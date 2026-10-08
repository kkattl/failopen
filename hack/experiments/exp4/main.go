// Experiment 4 (offline half): how failopen's verdicts move when what it
// knows about the network changes. Every corpus snapshot is audited as
// captured and under transformations that hide or flip one input:
//
//	no-podcidr   the pod CIDR is unknown (CNI.PodCIDRs dropped)
//	unknown-cni  the CNI is not recognised (name "unknown", enforcement unknown)
//	etp-flip     externalTrafficPolicy Local <-> Cluster on every NodePort/LB
//
// The claim under test: missing knowledge lowers severity, never raises it,
// and never invents findings. Each finding is matched by (detector, subject).
//
//	go run ./hack/experiments/exp4 [--scenarios testdata/scenarios]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/detector"
	"github.com/kkattl/failopen/internal/scenario"
)

type transform struct {
	name string
	fn   func(*collector.Snapshot)
}

var transforms = []transform{
	{"no-podcidr", func(s *collector.Snapshot) { s.CNI.PodCIDRs = nil; s.CNI.PodCIDRSource = "" }},
	{"unknown-cni", func(s *collector.Snapshot) {
		s.CNI = collector.CNIInfo{Name: "unknown", PodCIDRs: s.CNI.PodCIDRs, PodCIDRSource: s.CNI.PodCIDRSource}
	}},
	{"etp-flip", func(s *collector.Snapshot) {
		for i := range s.Services {
			svc := &s.Services[i]
			if svc.Spec.Type != corev1.ServiceTypeNodePort && svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
				continue
			}
			if svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
				svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
			} else {
				svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
			}
		}
	}},
}

var rank = map[detector.Severity]int{detector.SeverityInfo: 0, detector.SeverityWarning: 1, detector.SeverityCritical: 2}

func main() {
	root := flag.String("scenarios", "testdata/scenarios", "scenario corpus")
	flag.Parse()
	cases, err := scenario.LoadAll(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	type counts struct{ same, lowered, raised, dropped, addedWarning, addedCritical int }
	total := map[string]*counts{}
	var changes []string
	for _, t := range transforms {
		total[t.name] = &counts{}
	}

	for _, c := range cases {
		for _, r := range c.Runs {
			base := index(detector.Run(r.Snapshot))
			for _, t := range transforms {
				s := clone(r.Snapshot)
				t.fn(s)
				after := index(detector.Run(s))
				n := total[t.name]
				for k, b := range base {
					a, ok := after[k]
					switch {
					case !ok:
						n.dropped++
						changes = append(changes, fmt.Sprintf("| %s | %s / %s | %s | %s → dropped |", t.name, c.Name, r.Profile, k, b))
					case rank[a] < rank[b]:
						n.lowered++
						changes = append(changes, fmt.Sprintf("| %s | %s / %s | %s | %s → %s |", t.name, c.Name, r.Profile, k, b, a))
					case rank[a] > rank[b]:
						n.raised++
						changes = append(changes, fmt.Sprintf("| %s | %s / %s | %s | %s → **%s** |", t.name, c.Name, r.Profile, k, b, a))
					default:
						n.same++
					}
				}
				for k, a := range after {
					if _, ok := base[k]; !ok {
						if a == detector.SeverityCritical {
							n.addedCritical++
						} else {
							n.addedWarning++
						}
						changes = append(changes, fmt.Sprintf("| %s | %s / %s | %s | none → %s |", t.name, c.Name, r.Profile, k, a))
					}
				}
			}
		}
	}

	fmt.Println("## Verdict changes per transformation (all scenario × CNI snapshots)")
	fmt.Println()
	fmt.Println("| Transformation | unchanged | severity lowered | severity raised | finding dropped | added: warning | added: critical |")
	fmt.Println("|---|---|---|---|---|---|---|")
	for _, t := range transforms {
		n := total[t.name]
		fmt.Printf("| %s | %d | %d | %d | %d | %d | %d |\n", t.name, n.same, n.lowered, n.raised, n.dropped, n.addedWarning, n.addedCritical)
	}
	fmt.Println()
	fmt.Println("## Every change")
	fmt.Println()
	fmt.Println("| Transformation | Scenario / CNI | Finding | Severity |")
	fmt.Println("|---|---|---|---|")
	for _, l := range changes {
		fmt.Println(l)
	}
}

func index(fs []detector.Finding) map[string]detector.Severity {
	m := map[string]detector.Severity{}
	for _, f := range fs {
		m[f.Detector+" "+strings.TrimSpace(f.Subject)] = f.Severity
	}
	return m
}

func clone(s *collector.Snapshot) *collector.Snapshot {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	var out collector.Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return &out
}
