// Experiment 1: detector accuracy against MEASURED reachability, without
// labels in between. For every scenario × CNI in the corpus, the oracle's
// bypass probes are grouped into divergences and matched with failopen's
// findings on the snapshot of the same cluster.
//
//	go run ./hack/experiments/exp1 [--scenarios testdata/scenarios]
//
// Units:
//   - divergence: measured bypasses grouped by (target, basis), pods of one
//     workload (Deployment, DaemonSet, ...) being one target; on a CNI that
//     measurably enforces nothing, the whole run is ONE divergence, "policies
//     not enforced" — the hundreds of bypasses are one fact, not hundreds.
//   - finding: one failopen finding.
//
// A finding is a TP if some divergence it explains was measured, else FP.
// A divergence is covered if some finding explains it, else it is an FN.
// cni explains the "not enforced" divergence; ipblock-node-ips explains
// source-rewriting (undefined-snat) bypasses to its Service or workload;
// hostnetwork-under-policy explains bypasses to its hostNetwork workload.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/kkattl/failopen/internal/detector"
	"github.com/kkattl/failopen/internal/scenario"
)

var holdout = map[string]bool{"iot-voltgrid": true, "saas-formcraft-etp-cluster": true}

type divergence struct {
	Scenario, Profile string
	Target, Basis     string // Target "*" for "policies not enforced"
	Sources           []string
	Observed          []string
	Covered           bool
}

type finding struct {
	Scenario, Profile string
	F                 detector.Finding
	TP                bool
}

// tally is TP/FP over findings and covered/missed over divergences.
type tally struct{ TP, FP, Covered, FN int }

func (t tally) precision() string { return ratio(t.TP, t.TP+t.FP) }
func (t tally) recall() string    { return ratio(t.Covered, t.Covered+t.FN) }

func (t tally) f1() string {
	if t.TP+t.FP == 0 || t.Covered+t.FN == 0 {
		return "-"
	}
	p := float64(t.TP) / float64(t.TP+t.FP)
	r := float64(t.Covered) / float64(t.Covered+t.FN)
	if p+r == 0 {
		return "0.00"
	}
	return fmt.Sprintf("%.2f", 2*p*r/(p+r))
}

func ratio(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f (%d/%d)", float64(a)/float64(b), a, b)
}

func main() {
	root := flag.String("scenarios", "testdata/scenarios", "scenario corpus")
	flag.Parse()

	cases, err := scenario.LoadAll(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var divs []*divergence
	var finds []*finding
	overblocks := map[string]int{} // profile -> overblock groups (fail-closed; out of scope)
	for _, c := range cases {
		for _, r := range c.Runs {
			fs := detector.Run(r.Snapshot)
			ds := divergences(c.Name, r)
			for i := range fs {
				f := &finding{Scenario: c.Name, Profile: r.Profile, F: fs[i]}
				for _, d := range ds {
					if explains(fs[i], d) {
						f.TP, d.Covered = true, true
					}
				}
				finds = append(finds, f)
			}
			divs = append(divs, ds...)
			overblocks[r.Profile] += overblockGroups(r)
		}
	}

	// Per detector × CNI. A divergence belongs to the detector whose class
	// it is: "not enforced" → cni, undefined-snat → ipblock-node-ips;
	// everything else has no detector (yet) and only counts in "all".
	byKey := map[[2]string]*tally{}
	get := func(det, prof string) *tally {
		k := [2]string{det, prof}
		if byKey[k] == nil {
			byKey[k] = &tally{}
		}
		return byKey[k]
	}
	for _, f := range finds {
		for _, k := range []string{f.Profile, "ALL", split(f.Scenario)} {
			for _, d := range []string{f.F.Detector, "all"} {
				t := get(d, k)
				if f.TP {
					t.TP++
				} else {
					t.FP++
				}
			}
		}
	}
	for _, d := range divs {
		for _, k := range []string{d.Profile, "ALL", split(d.Scenario)} {
			dets := []string{"all"}
			if c := classOf(d); c != "" {
				dets = append(dets, c)
			}
			for _, det := range dets {
				t := get(det, k)
				if d.Covered {
					t.Covered++
				} else {
					t.FN++
				}
			}
		}
	}

	profiles := []string{}
	seen := map[string]bool{}
	for _, d := range divs {
		if !seen[d.Profile] {
			seen[d.Profile] = true
			profiles = append(profiles, d.Profile)
		}
	}
	for _, f := range finds {
		if !seen[f.Profile] {
			seen[f.Profile] = true
			profiles = append(profiles, f.Profile)
		}
	}
	sort.Strings(profiles)
	profiles = append(profiles, "ALL", "dev", "hold-out")

	fmt.Println("## Detector × CNI (findings vs measured divergences)")
	fmt.Println()
	fmt.Println("| Detector | CNI / split | TP | FP | covered | FN | Precision | Recall | F1 |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|")
	for _, det := range []string{"cni", "ipblock-node-ips", "hostnetwork-under-policy", "all"} {
		for _, p := range profiles {
			t := get(det, p)
			fmt.Printf("| %s | %s | %d | %d | %d | %d | %s | %s | %s |\n", det, p, t.TP, t.FP, t.Covered, t.FN, t.precision(), t.recall(), t.f1())
		}
	}

	fmt.Println()
	fmt.Println("## Per scenario × CNI")
	fmt.Println()
	fmt.Println("| Scenario | CNI | divergences | covered | findings | TP | FP |")
	fmt.Println("|---|---|---|---|---|---|---|")
	type sk struct{ s, p string }
	rows := map[sk]*[5]int{}
	keys := []sk{}
	row := func(k sk) *[5]int {
		if rows[k] == nil {
			rows[k] = &[5]int{}
			keys = append(keys, k)
		}
		return rows[k]
	}
	for _, c := range cases {
		for _, r := range c.Runs {
			row(sk{c.Name, r.Profile})
		}
	}
	for _, d := range divs {
		x := row(sk{d.Scenario, d.Profile})
		x[0]++
		if d.Covered {
			x[1]++
		}
	}
	for _, f := range finds {
		x := row(sk{f.Scenario, f.Profile})
		x[2]++
		if f.TP {
			x[3]++
		} else {
			x[4]++
		}
	}
	for _, k := range keys {
		x := rows[k]
		name := k.s
		if holdout[name] {
			name += " (hold-out)"
		}
		fmt.Printf("| %s | %s | %d | %d | %d | %d | %d |\n", name, k.p, x[0], x[1], x[2], x[3], x[4])
	}

	fmt.Println()
	fmt.Println("## False positives")
	fmt.Println()
	n := 0
	for _, f := range finds {
		if !f.TP {
			n++
			fmt.Printf("- %s / %s: `%s` %s (%s) — %s\n", f.Scenario, f.Profile, f.F.Detector, f.F.Subject, f.F.Severity, f.F.Effective)
		}
	}
	if n == 0 {
		fmt.Println("none")
	}

	fmt.Println()
	fmt.Println("## False negatives (measured divergences no finding explains)")
	fmt.Println()
	n = 0
	for _, d := range divs {
		if d.Covered {
			continue
		}
		n++
		ho := ""
		if holdout[d.Scenario] {
			ho = " (hold-out)"
		}
		obs := ""
		if len(d.Observed) > 0 {
			obs = "; target saw " + strings.Join(first(d.Observed, 4), ", ")
		}
		fmt.Printf("- %s%s / %s: `%s` [%s] from %d source(s): %s%s\n", d.Scenario, ho, d.Profile, d.Target, d.Basis, len(d.Sources), strings.Join(first(d.Sources, 4), ", "), obs)
	}
	if n == 0 {
		fmt.Println("none")
	}

	fmt.Println()
	fmt.Println("## Overblock groups (declared allow, measured dropped; fail-closed, out of failopen's scope)")
	fmt.Println()
	for _, p := range profiles[:len(profiles)-3] {
		fmt.Printf("- %s: %d\n", p, overblocks[p])
	}
}

// split: the corpus was used to develop the detectors, except the hold-out.
func split(scenarioName string) string {
	if holdout[scenarioName] {
		return "hold-out"
	}
	return "dev"
}

// divergences groups a run's bypass probes.
func divergences(name string, r scenario.Run) []*divergence {
	probes := r.Reachability.Probes
	if unenforced(r) {
		var srcs []string
		for _, p := range probes {
			if p.Verdict == scenario.VerdictBypass {
				srcs = append(srcs, p.Source+" -> "+p.Target)
			}
		}
		if len(srcs) == 0 {
			return nil
		}
		return []*divergence{{Scenario: name, Profile: r.Profile, Target: "*", Basis: "not-enforced", Sources: srcs}}
	}
	workloads := map[string]string{} // "ns/pod" -> "ns/workload"
	for i := range r.Snapshot.Pods {
		pod := &r.Snapshot.Pods[i]
		workloads[pod.Namespace+"/"+pod.Name] = pod.Namespace + "/" + workloadName(pod)
	}
	groups := map[string]*divergence{}
	var order []string
	for _, p := range probes {
		if p.Verdict != scenario.VerdictBypass {
			continue
		}
		target := p.Target
		if w, ok := workloads[target]; ok {
			target = w
		}
		k := target + "|" + p.Basis
		d := groups[k]
		if d == nil {
			d = &divergence{Scenario: name, Profile: r.Profile, Target: target, Basis: p.Basis}
			groups[k] = d
			order = append(order, k)
		}
		d.Sources = appendUniq(d.Sources, p.Source+" ("+p.TargetKind+")")
		for _, o := range p.ObservedSources {
			d.Observed = appendUniq(d.Observed, o)
		}
	}
	sort.Strings(order)
	out := make([]*divergence, 0, len(order))
	for _, k := range order {
		out = append(out, groups[k])
	}
	return out
}

// unenforced: the share of policy-denied probes that were blocked, as in
// internal/score — measured when there is enough data, else the snapshot's claim.
func unenforced(r scenario.Run) bool {
	blocked, denied := 0, 0
	for _, p := range r.Reachability.Probes {
		if p.Basis == scenario.BasisPolicy && p.Declared == scenario.DeclaredDeny && scenario.BaselineReachable(p.Baseline) {
			denied++
			if !scenario.Reachable(p.Effective, p.Baseline) {
				blocked++
			}
		}
	}
	if denied >= 10 {
		return float64(blocked)/float64(denied) < 0.1
	}
	return !r.Snapshot.CNI.EnforcesPolicy
}

func overblockGroups(r scenario.Run) int {
	seen := map[string]bool{}
	for _, p := range r.Reachability.Probes {
		if p.Verdict == scenario.VerdictOverblock {
			seen[p.Target+"|"+p.Basis] = true
		}
	}
	return len(seen)
}

func classOf(d *divergence) string {
	switch d.Basis {
	case "not-enforced":
		return "cni"
	case scenario.BasisSNAT:
		return "ipblock-node-ips"
	case scenario.BasisUndefined:
		return "hostnetwork-under-policy"
	}
	return ""
}

func explains(f detector.Finding, d *divergence) bool {
	switch f.Detector {
	case "cni":
		return d.Basis == "not-enforced"
	case "ipblock-node-ips":
		return d.Basis == scenario.BasisSNAT && targetMatches(d.Target, f.Object)
	case "hostnetwork-under-policy":
		return d.Basis == scenario.BasisUndefined && targetMatches(d.Target, f.Object)
	}
	return false
}

// targetMatches: divergence targets are "ns/workload" or "ns/svc/name".
func targetMatches(target string, o detector.ObjectRef) bool {
	ns, rest, ok := strings.Cut(target, "/")
	if !ok || ns != o.Namespace {
		return false
	}
	if svc, isSvc := strings.CutPrefix(rest, "svc/"); isSvc {
		return o.Kind == "Service" && svc == o.Name
	}
	return o.Kind == "Workload" && rest == o.Name
}

// workloadName mirrors the detector's: the controller's name, with a
// ReplicaSet's pod-template hash stripped.
func workloadName(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if i := strings.LastIndex(o.Name, "-"); i > 0 {
				return o.Name[:i]
			}
		}
		return o.Name
	}
	return p.Name
}

func appendUniq(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func first(ss []string, n int) []string {
	if len(ss) > n {
		return append(ss[:n:n], fmt.Sprintf("… +%d", len(ss)-n))
	}
	return ss
}
