package score

import (
	"strings"

	"github.com/kkattl/failopen/internal/detector"
	"github.com/kkattl/failopen/internal/scenario"
)

// DetectorClass maps implemented detectors to label classes. Labels of any
// other class are coverage gaps, not misses.
var DetectorClass = map[string]string{
	"cni":              "cni-not-enforcing",
	"ipblock-node-ips": "ipblock-admits-node-ips",
}

// Holdout scenarios are scored only on request, once, at the end — they
// must not be looked at while tuning detectors (testdata/scenarios/README).
var Holdout = []string{"iot-voltgrid", "saas-formcraft-etp-cluster"}

type Outcome string

const (
	TruePositive   Outcome = "TP"
	FalseNegative  Outcome = "FN"
	FalsePositive  Outcome = "FP"         // finding on a must-not label
	Unlabeled      Outcome = "FP-unlabel" // finding no label mentions: counts as FP
	MayHit         Outcome = "may"        // finding on a may label: neutral
	NotImplemented Outcome = "gap"        // must label of a class with no detector yet
)

type Item struct {
	Outcome Outcome
	Label   *Label
	Finding *detector.Finding
	// SeverityMismatch: a TP whose severity differs from the label's.
	SeverityMismatch bool
}

type Run struct {
	Scenario, Profile string
	Items             []Item
}

func (r Run) Count(o Outcome) int {
	n := 0
	for _, it := range r.Items {
		if it.Outcome == o {
			n++
		}
	}
	return n
}

// ScoreRun runs every detector on the run's snapshot and matches findings
// against the labels that apply to the run's profile.
func ScoreRun(c scenario.Case, r scenario.Run, lf *LabelFile) Run {
	out := Run{Scenario: c.Name, Profile: r.Profile}
	findings := detector.Run(r.Snapshot)

	var applicable []*Label
	if lf != nil {
		for i := range lf.Findings {
			if lf.Findings[i].AppliesTo(r.Profile) {
				applicable = append(applicable, &lf.Findings[i])
			}
		}
	}
	satisfied := map[*Label]bool{}
	for i := range findings {
		f := &findings[i]
		l := bestMatch(f, applicable)
		it := Item{Finding: f, Label: l}
		switch {
		case l == nil:
			it.Outcome = Unlabeled
		case l.Label == Must:
			it.Outcome = TruePositive
			it.SeverityMismatch = l.Severity != "" && l.Severity != string(f.Severity)
			satisfied[l] = true
		case l.Label == May:
			it.Outcome = MayHit
		default:
			it.Outcome = FalsePositive
		}
		out.Items = append(out.Items, it)
	}
	for _, l := range applicable {
		if l.Label != Must || satisfied[l] {
			continue
		}
		o := FalseNegative
		if !implemented(l.Class) {
			o = NotImplemented
		}
		out.Items = append(out.Items, Item{Outcome: o, Label: l})
	}
	return out
}

// bestMatch picks the label a finding corresponds to: same class and
// subject; must beats may beats must-not.
func bestMatch(f *detector.Finding, labels []*Label) *Label {
	rank := map[string]int{Must: 3, May: 2, MustNot: 1}
	var best *Label
	for _, l := range labels {
		if l.Class != DetectorClass[f.Detector] || !subjectMatches(f.Object, l.Subject) {
			continue
		}
		if best == nil || rank[l.Label] > rank[best.Label] {
			best = l
		}
	}
	return best
}

// subjectMatches compares a finding's object with a label's subject.
// Ports are ignored: labels name the pod port, findings the node port.
// Pods and workloads are one thing to a human ("the node-agent").
func subjectMatches(o detector.ObjectRef, s Subject) bool {
	if o.Kind == "Cluster" || s.Kind == "Cluster" {
		return o.Kind == s.Kind
	}
	if o.Namespace != s.Namespace {
		return false
	}
	switch {
	case o.Kind == "Service" || s.Kind == "Service":
		return o.Kind == s.Kind && o.Name == s.Name
	default: // Workload / Pod / DaemonSet / Deployment ...
		return o.Name == s.Name || strings.HasPrefix(o.Name, s.Name+"-") || strings.HasPrefix(s.Name, o.Name+"-")
	}
}

func implemented(class string) bool {
	for _, c := range DetectorClass {
		if c == class {
			return true
		}
	}
	return false
}
