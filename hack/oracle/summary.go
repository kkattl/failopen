package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/kkattl/failopen/internal/scenario"
)

// summary prints a profile x scenario table of verdicts for the corpus.
//
// BYPASS and OVERBLOCK are split by basis: pol = plain policy semantics,
// snat = the target saw a rewritten source, hn = hostNetwork target
// (undefined by the spec). UNREACH is split into dead paths and NodePorts
// that are dead by design (externalTrafficPolicy: Local, no local backend).
//
// NP-ENF n/N: of N probes where plain policy semantics say deny and the path
// works without policies, n were blocked. ~N/N for an enforcing CNI, ~0 for
// flannel; it cross-checks the collector's EnforcesPolicy claim.
func summary(root string) error {
	cases, err := scenario.LoadAll(root)
	if err != nil {
		return err
	}
	type row struct {
		profile, scenario string
		run               scenario.Run
	}
	var rows []row
	for _, c := range cases {
		for _, r := range c.Runs {
			rows = append(rows, row{r.Profile, c.Name, r})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].profile != rows[j].profile {
			return rows[i].profile < rows[j].profile
		}
		return rows[i].scenario < rows[j].scenario
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tSCENARIO\tCNI\tPROBES\tMATCH\tBYPASS pol/snat/hn\tSPEC-EXC\tOVERBLOCK pol/snat\tUNREACH dead/etp\tUNKNOWN\tNP-ENF")
	for _, r := range rows {
		c := map[string]int{}
		denied, blocked := 0, 0
		for _, p := range r.run.Reachability.Probes {
			c[p.Verdict]++
			c[p.Verdict+"/"+p.Basis]++
			if p.Basis == scenario.BasisPolicy && p.Declared == scenario.DeclaredDeny && scenario.BaselineReachable(p.Baseline) {
				denied++
				if !scenario.Reachable(p.Effective, p.Baseline) {
					blocked++
				}
			}
		}
		v := func(verdict, basis string) int { return c[verdict+"/"+basis] }
		cni := r.run.Snapshot.CNI
		enforces := "enf"
		if !cni.EnforcesPolicy {
			enforces = "no-enf"
		}
		fmt.Fprintf(w, "%s\t%s\t%s (%s)\t%d\t%d\t%d/%d/%d\t%d\t%d/%d\t%d/%d\t%d\t%d/%d\n",
			r.profile, r.scenario, cni.Name, enforces, len(r.run.Reachability.Probes),
			c[scenario.VerdictMatch],
			v(scenario.VerdictBypass, scenario.BasisPolicy), v(scenario.VerdictBypass, scenario.BasisSNAT), v(scenario.VerdictBypass, scenario.BasisUndefined),
			c[scenario.VerdictSpecException],
			v(scenario.VerdictOverblock, scenario.BasisPolicy), v(scenario.VerdictOverblock, scenario.BasisSNAT),
			c[scenario.VerdictUnreachable]-v(scenario.VerdictUnreachable, scenario.BasisETPLocal), v(scenario.VerdictUnreachable, scenario.BasisETPLocal),
			c[scenario.VerdictUnknown],
			blocked, denied)
	}
	return w.Flush()
}
