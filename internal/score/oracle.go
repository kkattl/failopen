package score

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kkattl/failopen/internal/scenario"
)

// Reconciliation of labels with what the oracle measured. Labels and the
// oracle are independent opinions; every disagreement is either a
// labelling error or an oracle bug, and goes to a human.

type Disagreement struct {
	Scenario, Profile string
	Kind              string // "label-unsupported", "label-contradicted", "unlabeled-divergence"
	Label             *Label
	What              string
}

// Reconcile checks the labels of implemented classes against a run's
// probes, and lists measured bypass groups that no label mentions.
func Reconcile(c scenario.Case, r scenario.Run, lf *LabelFile) []Disagreement {
	var out []Disagreement
	add := func(kind string, l *Label, format string, args ...any) {
		out = append(out, Disagreement{Scenario: c.Name, Profile: r.Profile, Kind: kind, Label: l, What: fmt.Sprintf(format, args...)})
	}
	probes := r.Reachability.Probes

	// On a CNI that measurably enforces nothing, every divergence is that
	// one cluster-level fact (the cni-not-enforcing finding); per-target
	// bypasses and per-class checks would just restate it hundreds of times.
	// Too few policy-denied probes to measure it: trust the collector's
	// claim, which TestEnforcementClaim checks wherever there is enough data.
	blocked, denied := enforcement(probes)
	unenforced := !r.Snapshot.CNI.EnforcesPolicy
	if denied >= 10 {
		unenforced = float64(blocked)/float64(denied) < 0.1
	}

	if lf != nil {
		for i := range lf.Findings {
			l := &lf.Findings[i]
			if !l.AppliesTo(r.Profile) || l.Label == May {
				continue
			}
			switch l.Class {
			case "cni-not-enforcing":
				blocked, denied := enforcement(probes)
				if denied < 10 {
					continue
				}
				share := float64(blocked) / float64(denied)
				if l.Label == Must && share > 0.1 {
					add("label-contradicted", l, "label says the CNI doesn't enforce; oracle measured %d/%d policy-denied probes blocked", blocked, denied)
				}
				if l.Label == MustNot && share < 0.9 {
					add("label-contradicted", l, "label says the CNI enforces; oracle measured only %d/%d blocked", blocked, denied)
				}
			case "ipblock-admits-node-ips":
				if unenforced {
					continue
				}
				hits := snatBypasses(probes, l.Subject)
				if l.Label == Must && len(hits) == 0 {
					add("label-unsupported", l, "no SNAT bypass measured to %s/%s", l.Subject.Namespace, l.Subject.Name)
				}
				if l.Label == MustNot && len(hits) > 0 {
					add("label-contradicted", l, "oracle measured SNAT bypass: %s", strings.Join(hits, "; "))
				}
			}
		}
	}

	if unenforced {
		return out
	}

	// Measured divergences nobody labelled: group bypasses by (target, basis).
	groups := map[string][]string{}
	for _, p := range probes {
		if p.Verdict != scenario.VerdictBypass {
			continue
		}
		k := p.Target + " [" + p.Basis + "]"
		groups[k] = append(groups[k], p.Source)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		target := strings.SplitN(k, " ", 2)[0]
		if lf != nil && mentioned(target, lf) {
			continue
		}
		add("unlabeled-divergence", nil, "%s from %d source(s): %s", k, len(groups[k]), strings.Join(first(groups[k], 3), ", "))
	}
	return out
}

func enforcement(probes []scenario.Probe) (blocked, denied int) {
	for _, p := range probes {
		if p.Basis == scenario.BasisPolicy && p.Declared == scenario.DeclaredDeny && scenario.BaselineReachable(p.Baseline) {
			denied++
			if !scenario.Reachable(p.Effective, p.Baseline) {
				blocked++
			}
		}
	}
	return blocked, denied
}

// snatBypasses: bypass probes through source rewriting to the subject.
func snatBypasses(probes []scenario.Probe, s Subject) []string {
	var out []string
	for _, p := range probes {
		if p.Verdict == scenario.VerdictBypass && p.Basis == scenario.BasisSNAT && targetMatches(p.Target, s) {
			out = append(out, fmt.Sprintf("%s -> %s (%s, saw %v)", p.Source, p.Address, p.TargetKind, p.ObservedSources))
		}
	}
	return first(out, 3)
}

// targetMatches: probe targets are "ns/pod-name" or "ns/svc/name".
func targetMatches(target string, s Subject) bool {
	ns, rest, ok := strings.Cut(target, "/")
	if !ok || ns != s.Namespace {
		return false
	}
	if svc, isSvc := strings.CutPrefix(rest, "svc/"); isSvc {
		return svc == s.Name
	}
	return rest == s.Name || strings.HasPrefix(rest, s.Name+"-")
}

// mentioned: some label (any class, any value) is about the target, or
// about its namespace as a whole.
func mentioned(target string, lf *LabelFile) bool {
	ns, _, _ := strings.Cut(target, "/")
	for _, l := range lf.Findings {
		if targetMatches(target, l.Subject) || (l.Subject.Kind == "Namespace" && l.Subject.Name == ns) {
			return true
		}
	}
	return false
}

func first(ss []string, n int) []string {
	if len(ss) > n {
		return append(ss[:n:n], fmt.Sprintf("… +%d", len(ss)-n))
	}
	return ss
}
