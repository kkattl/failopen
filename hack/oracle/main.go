// Command oracle measures ground truth for a scenario: it probes every
// (source, target) pair on a live cluster, records which source address each
// target actually saw, computes what NetworkPolicy DECLARES for the intended
// and for the observed source (policy-assistant's matcher), and repeats the
// probes with policies removed to tell "blocked by policy" from "dead path".
//
// It writes <out>/<profile>/snapshot.json and reachability.json in the
// format of internal/scenario. See hack/scenarios/run.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

type config struct {
	kubeconfig      string
	manifests       string
	out             string
	externalIP      string
	probeTimeout    time.Duration
	settle          time.Duration
	keep            bool
	extContainer    string
	parallelism     int
	profile         string
	serviceAttempts int
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "summary" {
		if err := summary(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "oracle:", err)
			os.Exit(1)
		}
		return
	}
	var cfg config
	flag.StringVar(&cfg.kubeconfig, "kubeconfig", "", "path to kubeconfig")
	flag.StringVar(&cfg.manifests, "manifests", "", "scenario manifests.yaml (defines which namespaces are the scenario)")
	flag.StringVar(&cfg.out, "out", "", "scenario directory; results go to <out>/<profile>/")
	flag.StringVar(&cfg.profile, "profile", "", "lab profile name (hack/lab/profiles); defaults to the detected CNI")
	flag.StringVar(&cfg.externalIP, "external-ip", "203.0.113.10", "source IP of 'external' probes as seen by the cluster")
	flag.DurationVar(&cfg.probeTimeout, "probe-timeout", 2*time.Second, "per-connection timeout")
	flag.DurationVar(&cfg.settle, "settle", 60*time.Second, "max wait for the CNI to converge after changing policies")
	flag.StringVar(&cfg.extContainer, "external-container", "", "docker container to source 'external' probes from (hack/lab/external.sh); empty = dial from this host")
	flag.IntVar(&cfg.parallelism, "parallelism", 2, "concurrent connects inside one source pod (memory: they share the pod's cgroup)")
	flag.IntVar(&cfg.serviceAttempts, "service-attempts", 4, "attempts per ClusterIP/NodePort target: one attempt only exercises one backend")
	flag.BoolVar(&cfg.keep, "keep", false, "keep the failopen-oracle namespace after the run")
	flag.Parse()
	if cfg.manifests == "" || cfg.out == "" {
		fmt.Fprintln(os.Stderr, "usage: oracle --manifests <file> --out <scenario dir> --profile <p> [--kubeconfig <file>]\n       oracle summary <scenarios dir>")
		os.Exit(2)
	}
	if err := run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config) error {
	namespaces, err := scenarioNamespaces(cfg.manifests)
	if err != nil {
		return fmt.Errorf("read manifests: %w", err)
	}
	logf("scenario namespaces: %v", namespaces)

	k, err := newKube(cfg.kubeconfig)
	if err != nil {
		return err
	}
	if err := k.waitScenarioReady(ctx, namespaces, 5*time.Minute); err != nil {
		return err
	}

	c, err := collector.NewK8sCollector(cfg.kubeconfig)
	if err != nil {
		return err
	}
	snap, err := c.Collect(ctx)
	if err != nil {
		return err
	}
	snap = filterSnapshot(snap, namespaces)
	logf("CNI: %s (enforces: %t)", snap.CNI.Name, snap.CNI.EnforcesPolicy)

	agents, err := k.setupOracle(ctx)
	if err != nil {
		return fmt.Errorf("setup oracle namespace: %w", err)
	}
	if !cfg.keep {
		defer k.teardownOracle(context.Background())
	}

	sources := buildSources(snap, agents)
	targets := buildTargets(snap)
	ports := identityPorts(snap)
	logf("%d sources x %d targets", len(sources), len(targets))

	if err := k.injectProbes(ctx, sources, ports); err != nil {
		return fmt.Errorf("inject probe containers: %w", err)
	}

	p := &prober{kube: k, timeout: cfg.probeTimeout, extContainer: cfg.extContainer, parallelism: max(1, cfg.parallelism)}
	attempts := func(t target) int {
		if t.isService() {
			return max(1, cfg.serviceAttempts)
		}
		return 1
	}
	connectPlan := func() map[int][]job {
		plan := map[int][]job{}
		for si, src := range sources {
			for ti, t := range targets {
				if !applicable(src, t) {
					continue
				}
				for a := range attempts(t) {
					plan[si] = append(plan[si], job{key: jobKey("c", ti, a), addr: t.Address})
				}
			}
		}
		return plan
	}

	logf("probing with policies in place...")
	effRaw := p.run(ctx, sources, connectPlan())
	canary, haveCanary := pickCanary(sources, targets, effRaw)

	logf("removing policies for the baseline run...")
	restore, err := k.removePolicies(ctx, namespaces)
	if err != nil {
		return err
	}
	restored := false
	defer func() {
		if !restored {
			_ = restore(context.Background())
		}
	}()
	p.waitCanary(ctx, sources, targets, canary, haveCanary, true, cfg.settle)

	shadows, dropShadows, err := k.createShadows(ctx, targets)
	if err != nil {
		return err
	}
	basePlan := connectPlan()
	for si, src := range sources {
		for ti, t := range targets {
			if !applicable(src, t) {
				continue
			}
			if addr := identityAddress(t, ports, shadows); addr != "" {
				for a := range attempts(t) {
					basePlan[si] = append(basePlan[si], job{key: jobKey("i", ti, a), addr: addr, identity: true})
				}
			}
		}
	}
	logf("probing baseline + observed sources...")
	baseRaw := p.run(ctx, sources, basePlan)
	dropShadows(context.Background())

	logf("restoring policies...")
	if err := restore(ctx); err != nil {
		return fmt.Errorf("restore policies (re-apply manifests!): %w", err)
	}
	restored = true
	p.waitCanary(ctx, sources, targets, canary, haveCanary, false, cfg.settle)

	// A failed exec turns every probe of that source into "error", which
	// would silently classify as unreachable. Refuse to write such results.
	if len(p.failures) > 0 {
		return fmt.Errorf("probing failed from %d source(s): %v", len(p.failures), p.failures)
	}

	if cfg.profile == "" {
		cfg.profile = snap.CNI.Name
	}
	reach := &scenario.Reachability{
		Profile:    cfg.profile,
		CNI:        snap.CNI.Name,
		Provenance: k.provenance(ctx, cfg, snap, agents.outsider.Spec.NodeName),
	}
	dc := newDeclaredCalc(snap, cfg.externalIP, agents.outsider)
	for si, src := range sources {
		for ti, t := range targets {
			if !applicable(src, t) {
				continue
			}
			n := attempts(t)
			eff, hits := collect(effRaw[si], ti, n, "c", baseRaw[si]) // hits judged against baseline
			base, _ := collect(baseRaw[si], ti, n, "c", nil)
			observed := observedIPs(baseRaw[si], ti, n)

			declared := dc.intended(src, t)
			b := basisFor(src, t, observed)
			if t.ETPLocal && !scenario.BaselineReachable(base) {
				if local, _ := t.backendNodes(t.Node); local == 0 {
					b = scenario.BasisETPLocal
				}
			}
			reach.Probes = append(reach.Probes, scenario.Probe{
				Source:           src.Name,
				SourceKind:       src.Kind,
				Target:           t.Name,
				TargetKind:       t.Kind,
				Address:          t.Address,
				Declared:         declared,
				Basis:            b,
				Effective:        eff,
				Baseline:         base,
				Verdict:          scenario.Classify(declared, b, eff, base),
				Attempts:         n,
				Hits:             fmt.Sprintf("%d/%d", hits, n),
				ObservedSources:  observed,
				DeclaredObserved: dc.observed(observed, t),
			})
		}
	}

	dir := filepath.Join(cfg.out, cfg.profile)
	if err := writeResults(dir, snap, reach); err != nil {
		return err
	}
	printSummary(reach)
	logf("wrote %s", dir)
	return nil
}

func jobKey(kind string, target, attempt int) string {
	return kind + "/" + strconv.Itoa(target) + "/" + strconv.Itoa(attempt)
}

// rank orders outcomes so the "best" one over attempts represents a target.
var rank = map[string]int{
	scenario.EffectiveOpen: 3, scenario.EffectiveRefused: 2,
	scenario.EffectiveTimeout: 1, scenario.EffectiveError: 0,
}

// collect folds n connect attempts into the best outcome, plus how many
// attempts were reachable (judged against the same attempt's baseline).
func collect(raw map[string]string, ti, n int, kind string, baseRaw map[string]string) (string, int) {
	best, hits := scenario.EffectiveError, 0
	for a := range n {
		got := classifyOutput(raw[jobKey(kind, ti, a)])
		if rank[got] > rank[best] {
			best = got
		}
		base := scenario.EffectiveOpen
		if baseRaw != nil {
			base = classifyOutput(baseRaw[jobKey(kind, ti, a)])
		}
		if scenario.Reachable(got, base) {
			hits++
		}
	}
	return best, hits
}

func observedIPs(raw map[string]string, ti, n int) []string {
	var ips []string
	for a := range n {
		if ip, ok := parseClientIP(raw[jobKey("i", ti, a)]); ok {
			ips = append(ips, ip)
		}
	}
	slices.Sort(ips)
	return slices.Compact(ips)
}

// canary is a (source, pod-ip target) pair that policy blocked: it flips to
// reachable once the CNI has dropped the policies, and back once restored.
type canary struct{ src, tgt int }

func pickCanary(sources []source, targets []target, eff map[int]map[string]string) (canary, bool) {
	for si, src := range sources {
		if src.Kind != scenario.SourcePod && src.Kind != scenario.SourceOutsider {
			continue
		}
		for ti, t := range targets {
			if t.Kind == scenario.TargetPodIP && applicable(src, t) &&
				classifyOutput(eff[si][jobKey("c", ti, 0)]) == scenario.EffectiveTimeout {
				return canary{si, ti}, true
			}
		}
	}
	return canary{}, false
}

// waitCanary replaces a blind sleep: poll the canary until it is reachable
// (policies gone) or blocked (policies back), up to limit.
func (p *prober) waitCanary(ctx context.Context, sources []source, targets []target, c canary, ok, wantReachable bool, limit time.Duration) {
	if !ok {
		logf("no canary pair (nothing was blocked); waiting %s", limit/6)
		time.Sleep(limit / 6)
		return
	}
	src, t := sources[c.src], targets[c.tgt]
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, limit, true, func(ctx context.Context) (bool, error) {
		raw := p.runFrom(ctx, src, []job{{key: "k", addr: t.Address}})
		got := classifyOutput(raw["k"])
		return (got == scenario.EffectiveOpen || got == scenario.EffectiveRefused) == wantReachable, nil
	})
	if err != nil {
		logf("canary %s -> %s did not converge within %s (want reachable=%t)", src.Name, t.Address, limit, wantReachable)
	}
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[oracle] "+format+"\n", args...)
}
