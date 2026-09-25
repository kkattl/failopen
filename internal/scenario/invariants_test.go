package scenario

import (
	"strings"
	"testing"
)

const corpus = "../../testdata/scenarios"

// TestKnownAnswer: scenarios named known-open* have no policies, so any
// bypass or overblock is an oracle bug, not a finding.
func TestKnownAnswer(t *testing.T) {
	cases, err := LoadAll(corpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if !strings.HasPrefix(c.Name, "known-open") {
			continue
		}
		for _, r := range c.Runs {
			for _, p := range r.Reachability.Probes {
				if p.Verdict == VerdictBypass || p.Verdict == VerdictOverblock {
					t.Errorf("%s/%s: %s -> %s %s: verdict %s on a policy-free scenario",
						c.Name, r.Profile, p.Source, p.TargetKind, p.Address, p.Verdict)
				}
			}
		}
	}
}

// TestEnforcementClaim cross-checks the collector's EnforcesPolicy against
// measurement: of the probes plain policy says to deny (and that work
// without policies), an enforcing CNI must block nearly all, a
// non-enforcing one nearly none.
func TestEnforcementClaim(t *testing.T) {
	cases, err := LoadAll(corpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		for _, r := range c.Runs {
			denied, blocked := 0, 0
			for _, p := range r.Reachability.Probes {
				if p.Basis == BasisPolicy && p.Declared == DeclaredDeny && BaselineReachable(p.Baseline) {
					denied++
					if !Reachable(p.Effective, p.Baseline) {
						blocked++
					}
				}
			}
			if denied < 10 {
				continue // too few to judge
			}
			share := float64(blocked) / float64(denied)
			claim := r.Snapshot.CNI.EnforcesPolicy
			if claim && share < 0.9 || !claim && share > 0.1 {
				t.Errorf("%s/%s: collector says %s enforces=%t, measured %d/%d policy-denied probes blocked",
					c.Name, r.Profile, r.Snapshot.CNI.Name, claim, blocked, denied)
			}
		}
	}
}
