package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kkattl/failopen/internal/scenario"
)

// reclassify re-derives outcomes and verdicts of an already measured corpus
// after a change in how outcomes are interpreted (scenario.AtTarget,
// scenario.Classify). Measurements are not repeated: only their reading
// changes, and every changed probe is printed.
func reclassify(root string) error {
	cases, err := scenario.LoadAll(root)
	if err != nil {
		return err
	}
	for _, c := range cases {
		for _, r := range c.Runs {
			changed := 0
			for i := range r.Reachability.Probes {
				p := &r.Reachability.Probes[i]
				eff := scenario.AtTarget(p.TargetKind, p.Effective)
				base := scenario.AtTarget(p.TargetKind, p.Baseline)
				verdict := scenario.Classify(p.Declared, p.Basis, eff, base)
				if eff == p.Effective && base == p.Baseline && verdict == p.Verdict {
					continue
				}
				changed++
				fmt.Printf("%s/%s: %s -> %s (%s): %s/%s %s -> %s/%s %s\n", c.Name, r.Profile, p.Source, p.Target, p.TargetKind,
					p.Effective, p.Baseline, p.Verdict, eff, base, verdict)
				p.Effective, p.Baseline, p.Verdict = eff, base, verdict
			}
			if changed == 0 {
				continue
			}
			data, err := json.MarshalIndent(r.Reachability, "", "  ")
			if err != nil {
				return err
			}
			path := filepath.Join(c.Dir, r.Profile, "reachability.json")
			if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "%s: %d probe(s) reclassified\n", path, changed)
		}
	}
	return nil
}
