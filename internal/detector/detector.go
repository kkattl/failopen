// Package detector turns a collector.Snapshot into findings: places where
// what NetworkPolicy DECLARES differs from what the network lets through.
// Every detector is a pure function of the Snapshot, so it is tested with
// hand-built fixtures and against the measured scenario corpus.
package detector

import (
	"regexp"
	"sort"

	"github.com/kkattl/failopen/internal/collector"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

var severityRank = map[Severity]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}

// ObjectRef is what a finding is about, in machine-readable form.
type ObjectRef struct {
	Kind      string // "Cluster", "Service", "Workload", "Namespace", ...
	Namespace string
	Name      string
}

type Finding struct {
	Detector  string // "cni", "ipblock-node-ips"
	Object    ObjectRef
	Severity  Severity
	Namespace string   // "" for cluster-scope findings
	Subject   string   // "ecom-edge/svc/edge-proxy:30080"
	Declared  string   // "ALLOW only 172.18.0.0/16 (edge-proxy-ingress)"
	Effective string   // "ALLOW from any pod via NodePort 30080"
	Detail    string   // one or two sentences for a human
	Assumes   []string // what must hold for the finding to be true
	Verify    string   // a command that demonstrates it on the live cluster
}

type Detector interface {
	Name() string
	Detect(s *collector.Snapshot) []Finding
}

// All is the registry: a plain slice, no magic.
func All() []Detector {
	return []Detector{
		&CNIEnforcement{},
		&IPBlockNodeIPs{},
	}
}

// Run executes every detector and returns findings sorted critical-first,
// then by namespace and subject.
func Run(s *collector.Snapshot) []Finding {
	var out []Finding
	for _, d := range All() {
		out = append(out, d.Detect(s)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Subject < b.Subject
	})
	return out
}

// systemNamespaces hold the cluster's own plumbing (CNI, kube-proxy, DNS),
// where host networking and NodePorts are legitimate; detectors skip them.
var systemNamespaces = regexp.MustCompile(`^(kube-.*|calico-.*|tigera-operator|cilium.*|local-path-storage)$`)

func isSystemNamespace(ns string) bool { return systemNamespaces.MatchString(ns) }
