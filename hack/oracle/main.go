// Command oracle measures ground truth for a scenario: it probes every
// (source, target) pair on a live cluster, computes what NetworkPolicy
// DECLARES for the same pair (policy-assistant's matcher), and repeats the
// probes with policies removed to tell "blocked by policy" from "dead path".
//
// It writes <out>/<cni>/snapshot.json and <out>/<cni>/reachability.json in
// the format of internal/scenario. See hack/scenarios/run.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

type config struct {
	kubeconfig   string
	manifests    string
	out          string
	externalIP   string
	probeTimeout time.Duration
	settle       time.Duration
	keep         bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.kubeconfig, "kubeconfig", "", "path to kubeconfig")
	flag.StringVar(&cfg.manifests, "manifests", "", "scenario manifests.yaml (defines which namespaces are the scenario)")
	flag.StringVar(&cfg.out, "out", "", "scenario directory; results go to <out>/<cni>/")
	flag.StringVar(&cfg.externalIP, "external-ip", "203.0.113.10", "source IP of 'external' probes as seen by the cluster (kind: docker network gateway)")
	flag.DurationVar(&cfg.probeTimeout, "probe-timeout", 2*time.Second, "per-connection timeout")
	flag.DurationVar(&cfg.settle, "settle", 5*time.Second, "wait after changing policies, for the CNI to converge")
	flag.BoolVar(&cfg.keep, "keep", false, "keep the failopen-oracle namespace after the run")
	flag.Parse()
	if cfg.manifests == "" || cfg.out == "" {
		fmt.Fprintln(os.Stderr, "usage: oracle --manifests <file> --out <scenario dir> [--kubeconfig <file>]")
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
	logf("%d sources x %d targets", len(sources), len(targets))

	if err := k.injectProbes(ctx, sources); err != nil {
		return fmt.Errorf("inject probe containers: %w", err)
	}

	p := &prober{kube: k, timeout: cfg.probeTimeout}
	logf("probing with policies in place...")
	effective := p.probeAll(ctx, sources, targets)

	logf("removing policies for the baseline run...")
	restore, err := k.removePolicies(ctx, namespaces)
	if err != nil {
		return err
	}
	time.Sleep(cfg.settle)
	baseline := p.probeAll(ctx, sources, targets)
	logf("restoring policies...")
	if err := restore(ctx); err != nil {
		return fmt.Errorf("restore policies (re-apply manifests!): %w", err)
	}

	// A failed exec turns every probe of that source into "error", which
	// would silently classify as unreachable. Refuse to write such results.
	if len(p.failures) > 0 {
		return fmt.Errorf("probing failed from %d source(s): %v", len(p.failures), p.failures)
	}

	dc := newDeclaredCalc(snap, cfg.externalIP)
	reach := &scenario.Reachability{CNI: snap.CNI.Name}
	for si, src := range sources {
		for ti, tgt := range targets {
			if !applicable(src, tgt) {
				continue
			}
			key := pair{si, ti}
			declared := dc.verdict(src, tgt)
			reach.Probes = append(reach.Probes, scenario.Probe{
				Source:     src.Name,
				SourceKind: src.Kind,
				Target:     tgt.Name,
				TargetKind: tgt.Kind,
				Address:    tgt.Address,
				Declared:   declared,
				Effective:  effective[key],
				Baseline:   baseline[key],
				Verdict:    scenario.Classify(declared, effective[key], baseline[key]),
			})
		}
	}

	dir := filepath.Join(cfg.out, snap.CNI.Name)
	if err := writeResults(dir, snap, reach); err != nil {
		return err
	}
	printSummary(reach)
	logf("wrote %s", dir)
	return nil
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[oracle] "+format+"\n", args...)
}
