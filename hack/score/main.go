// Command score measures failopen's detectors against the blind labels on
// every measured run of the scenario corpus, and reconciles the labels with
// the oracle's measurements.
//
//	go run ./hack/score              # dev set (hold-out excluded)
//	go run ./hack/score --holdout    # include the hold-out: do this once, at the end
package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"text/tabwriter"

	"github.com/kkattl/failopen/internal/scenario"
	"github.com/kkattl/failopen/internal/score"
)

func main() {
	labelsDir := flag.String("labels", "labeling", "directory with <scenario>.expected.yaml")
	scenariosDir := flag.String("scenarios", "testdata/scenarios", "scenario corpus")
	holdout := flag.Bool("holdout", false, "include hold-out scenarios (only once, at the end)")
	flag.Parse()
	if err := run(*labelsDir, *scenariosDir, *holdout); err != nil {
		fmt.Fprintln(os.Stderr, "score:", err)
		os.Exit(1)
	}
}

func run(labelsDir, scenariosDir string, holdout bool) error {
	labels, err := score.LoadLabels(labelsDir, scenariosDir)
	if err != nil {
		return err
	}
	cases, err := scenario.LoadAll(scenariosDir)
	if err != nil {
		return err
	}

	var runs []score.Run
	var disagreements []score.Disagreement
	skipped := 0
	for _, c := range cases {
		if !holdout && slices.Contains(score.Holdout, c.Name) {
			skipped++
			continue
		}
		for _, r := range c.Runs {
			runs = append(runs, score.ScoreRun(c, r, labels[c.Name]))
			disagreements = append(disagreements, score.Reconcile(c, r, labels[c.Name])...)
		}
	}
	if skipped > 0 {
		fmt.Printf("(hold-out excluded: %v — use --holdout once, at the end)\n\n", score.Holdout)
	}

	printTable(runs)
	printDetails(runs)
	printGaps(runs)
	printDisagreements(disagreements)
	return nil
}

func printTable(runs []score.Run) {
	type agg struct{ tp, fn, fp, fpu, may, sev int }
	byProfile := map[string]*agg{}
	total := &agg{}
	for _, r := range runs {
		a := byProfile[r.Profile]
		if a == nil {
			a = &agg{}
			byProfile[r.Profile] = a
		}
		for _, x := range []*agg{a, total} {
			x.tp += r.Count(score.TruePositive)
			x.fn += r.Count(score.FalseNegative)
			x.fp += r.Count(score.FalsePositive)
			x.fpu += r.Count(score.Unlabeled)
			x.may += r.Count(score.MayHit)
			for _, it := range r.Items {
				if it.SeverityMismatch {
					x.sev++
				}
			}
		}
	}
	profiles := make([]string, 0, len(byProfile))
	for p := range byProfile {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tTP\tFN\tFP must-not\tFP unlabeled\tmay\tsev-mismatch\tPRECISION\tRECALL")
	line := func(name string, a *agg) {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", name, a.tp, a.fn, a.fp, a.fpu, a.may, a.sev,
			ratio(a.tp, a.tp+a.fp+a.fpu), ratio(a.tp, a.tp+a.fn))
	}
	for _, p := range profiles {
		line(p, byProfile[p])
	}
	line("TOTAL", total)
	w.Flush()
	fmt.Println()
}

func printDetails(runs []score.Run) {
	fmt.Println("Misses, false positives, severity mismatches:")
	n := 0
	for _, r := range runs {
		for _, it := range r.Items {
			var msg string
			switch {
			case it.Outcome == score.FalseNegative:
				msg = fmt.Sprintf("FN  %s %s/%s/%s — %s", it.Label.Class, it.Label.Subject.Kind, it.Label.Subject.Namespace, it.Label.Subject.Name, it.Label.ID)
			case it.Outcome == score.FalsePositive:
				msg = fmt.Sprintf("FP  %s %s — hits must-not %s", it.Finding.Detector, it.Finding.Subject, it.Label.ID)
			case it.Outcome == score.Unlabeled:
				msg = fmt.Sprintf("FP? %s %s — no label mentions it (%s)", it.Finding.Detector, it.Finding.Subject, it.Finding.Severity)
			case it.SeverityMismatch:
				msg = fmt.Sprintf("SEV %s %s — detector %s, label %s (%s)", it.Finding.Detector, it.Finding.Subject, it.Finding.Severity, it.Label.Severity, it.Label.ID)
			default:
				continue
			}
			fmt.Printf("  %-9s %-30s %s\n", r.Profile, r.Scenario, msg)
			n++
		}
	}
	if n == 0 {
		fmt.Println("  none")
	}
	fmt.Println()
}

func printGaps(runs []score.Run) {
	seen := map[string]bool{}
	byClass := map[string]int{}
	for _, r := range runs {
		for _, it := range r.Items {
			if it.Outcome != score.NotImplemented {
				continue
			}
			k := r.Scenario + "/" + it.Label.ID
			if !seen[k] {
				seen[k] = true
				byClass[it.Label.Class]++
			}
		}
	}
	fmt.Println("Coverage gaps (must labels of classes without a detector yet):")
	if len(byClass) == 0 {
		fmt.Println("  none")
	}
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		fmt.Printf("  %-28s %d\n", c, byClass[c])
	}
	fmt.Println()
}

func printDisagreements(ds []score.Disagreement) {
	fmt.Println("Labels vs oracle (each is a labelling error or an oracle bug — log the verdict):")
	if len(ds) == 0 {
		fmt.Println("  none")
	}
	for _, d := range ds {
		id := ""
		if d.Label != nil {
			id = d.Label.ID + " "
		}
		fmt.Printf("  %-9s %-30s %-21s %s%s\n", d.Profile, d.Scenario, d.Kind, id, d.What)
	}
}

func ratio(a, b int) string {
	if b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f (%d/%d)", float64(a)/float64(b), a, b)
}
