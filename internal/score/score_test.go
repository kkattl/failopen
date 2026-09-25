package score

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/detector"
	"github.com/kkattl/failopen/internal/scenario"
)

func TestSubjectMatches(t *testing.T) {
	svc := detector.ObjectRef{Kind: "Service", Namespace: "edge", Name: "gw"}
	wl := detector.ObjectRef{Kind: "Workload", Namespace: "iot", Name: "ingest-gateway"}
	for _, tt := range []struct {
		o    detector.ObjectRef
		s    Subject
		want bool
	}{
		{svc, Subject{Kind: "Service", Namespace: "edge", Name: "gw", Port: 8080}, true},
		{svc, Subject{Kind: "Service", Namespace: "edge", Name: "other"}, false},
		{svc, Subject{Kind: "Service", Namespace: "other", Name: "gw"}, false},
		{svc, Subject{Kind: "Workload", Namespace: "edge", Name: "gw"}, false},
		{wl, Subject{Kind: "Pod", Namespace: "iot", Name: "ingest-gateway-7c9d"}, true},
		{wl, Subject{Kind: "Workload", Namespace: "iot", Name: "ingest-gateway"}, true},
		{detector.ObjectRef{Kind: "Cluster"}, Subject{Kind: "Cluster"}, true},
		{detector.ObjectRef{Kind: "Cluster"}, Subject{Kind: "Namespace", Name: "x"}, false},
	} {
		if got := subjectMatches(tt.o, tt.s); got != tt.want {
			t.Errorf("subjectMatches(%+v, %+v) = %t", tt.o, tt.s, got)
		}
	}
}

// A flannel run with policies: the cni detector fires once.
func flannelRun() (scenario.Case, scenario.Run) {
	snap := &collector.Snapshot{
		CNI:             collector.CNIInfo{Name: "flannel"},
		NetworkPolicies: []networkingv1.NetworkPolicy{{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "deny"}}},
	}
	return scenario.Case{Name: "shop"}, scenario.Run{Profile: "flannel", Snapshot: snap, Reachability: &scenario.Reachability{}}
}

func TestScoreRun(t *testing.T) {
	c, r := flannelRun()
	cluster := Subject{Kind: "Cluster"}
	edge := Subject{Kind: "Service", Namespace: "shop", Name: "gw"}
	tests := []struct {
		name   string
		labels []Label
		want   map[Outcome]int
	}{
		{"must hit", []Label{{Class: "cni-not-enforcing", Subject: cluster, AppliesToCNI: []string{"flannel"}, Label: Must, Severity: "critical"}},
			map[Outcome]int{TruePositive: 1}},
		{"must-not hit", []Label{{Class: "cni-not-enforcing", Subject: cluster, AppliesToCNI: []string{"any"}, Label: MustNot}},
			map[Outcome]int{FalsePositive: 1}},
		{"label for another profile", []Label{{Class: "cni-not-enforcing", Subject: cluster, AppliesToCNI: []string{"calico"}, Label: Must}},
			map[Outcome]int{Unlabeled: 1}},
		{"may is neutral", []Label{{Class: "cni-not-enforcing", Subject: cluster, AppliesToCNI: []string{"any"}, Label: May}},
			map[Outcome]int{MayHit: 1}},
		{"missed must of an implemented class", []Label{
			{Class: "cni-not-enforcing", Subject: cluster, AppliesToCNI: []string{"any"}, Label: Must},
			{Class: "ipblock-admits-node-ips", Subject: edge, AppliesToCNI: []string{"any"}, Label: Must}},
			map[Outcome]int{TruePositive: 1, FalseNegative: 1}},
		{"must of an unimplemented class is a gap", []Label{
			{Class: "node-exception-segment", Subject: Subject{Kind: "Namespace", Name: "shop"}, AppliesToCNI: []string{"any"}, Label: Must}},
			map[Outcome]int{Unlabeled: 1, NotImplemented: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScoreRun(c, r, &LabelFile{Findings: tt.labels})
			for o, n := range tt.want {
				if got.Count(o) != n {
					t.Errorf("%s = %d, want %d (items %+v)", o, got.Count(o), n, got.Items)
				}
			}
			if len(got.Items) != sum(tt.want) {
				t.Errorf("%d items, want %d", len(got.Items), sum(tt.want))
			}
		})
	}
}

func TestSeverityMismatch(t *testing.T) {
	c, r := flannelRun()
	got := ScoreRun(c, r, &LabelFile{Findings: []Label{{Class: "cni-not-enforcing", Subject: Subject{Kind: "Cluster"},
		AppliesToCNI: []string{"any"}, Label: Must, Severity: "warning"}}})
	if got.Count(TruePositive) != 1 || !got.Items[0].SeverityMismatch {
		t.Errorf("want a TP flagged as severity mismatch, got %+v", got.Items)
	}
}

func sum(m map[Outcome]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Q6: a mutant inherits the base's labels except those about the object the
// mutation changed, and except those it labels itself.
func TestMutationInheritance(t *testing.T) {
	dir := t.TempDir()
	base := `apiVersion: v1
kind: Service
metadata: {name: gw, namespace: edge}
spec: {externalTrafficPolicy: Local}
---
apiVersion: v1
kind: Service
metadata: {name: api, namespace: app}
spec: {}
`
	write(t, filepath.Join(dir, "sc/shop/manifests.yaml"), base)
	write(t, filepath.Join(dir, "sc/shop-etp/manifests.yaml"), strings.Replace(base, "Local", "Cluster", 1))
	write(t, filepath.Join(dir, "lab/shop.expected.yaml"), `scenario: shop
findings:
  - {id: f1, class: other, subject: {kind: Service, namespace: edge, name: gw}, applies_to_cni: [any], label: must-not}
  - {id: f2, class: other, subject: {kind: Service, namespace: app, name: api}, applies_to_cni: [any], label: must-not}
  - {id: f3, class: cni-not-enforcing, subject: {kind: Cluster}, applies_to_cni: [flannel], label: must}
  - {id: f4, class: other, subject: {kind: Service, namespace: kube-system, name: kube-dns}, applies_to_cni: [any], label: must-not}
`)
	write(t, filepath.Join(dir, "lab/shop-etp.expected.yaml"), `scenario: shop-etp
findings:
  - {id: f1, class: cni-not-enforcing, subject: {kind: Cluster}, applies_to_cni: [flannel], label: may}
`)
	labels, err := LoadLabels(filepath.Join(dir, "lab"), filepath.Join(dir, "sc"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(labels["shop"].Findings); n != 3 {
		t.Errorf("base: %d labels, want 3 (system-namespace label dropped)", n)
	}
	var ids []string
	for _, l := range labels["shop-etp"].Findings {
		ids = append(ids, l.ID)
	}
	// f1 (edge/gw) is the mutated object: not inherited. f3 is labelled by
	// the mutant itself: not inherited. f2 is inherited.
	if len(ids) != 2 || ids[0] != "f1" || ids[1] != "shop:f2" {
		t.Errorf("mutant labels = %v, want [f1 shop:f2]", ids)
	}
}

func TestReconcile(t *testing.T) {
	c, r := flannelRun()
	r.Profile = "calico"
	r.Snapshot.CNI = collector.CNIInfo{Name: "calico", EnforcesPolicy: true}
	r.Reachability.Probes = []scenario.Probe{
		{Source: "outsider", Target: "edge/svc/gw", TargetKind: scenario.TargetNodePort, Address: "172.18.0.2:30080",
			Declared: scenario.DeclaredDeny, Basis: scenario.BasisSNAT, Verdict: scenario.VerdictBypass, ObservedSources: []string{"172.18.0.3"}},
		{Source: "outsider", Target: "db/postgres-0", TargetKind: scenario.TargetPodIP,
			Declared: scenario.DeclaredDeny, Basis: scenario.BasisPolicy, Verdict: scenario.VerdictBypass},
	}
	lf := &LabelFile{Findings: []Label{
		{Class: "ipblock-admits-node-ips", Subject: Subject{Kind: "Service", Namespace: "edge", Name: "gw"}, AppliesToCNI: []string{"calico"}, Label: MustNot},
		{Class: "ipblock-admits-node-ips", Subject: Subject{Kind: "Service", Namespace: "edge", Name: "other"}, AppliesToCNI: []string{"calico"}, Label: Must},
	}}
	got := map[string]int{}
	for _, d := range Reconcile(c, r, lf) {
		got[d.Kind]++
	}
	want := map[string]int{"label-contradicted": 1, "label-unsupported": 1, "unlabeled-divergence": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

// On a CNI that enforces nothing, per-target divergences are all explained
// by the cluster-level fact and aren't listed.
func TestReconcileUnenforcedCNI(t *testing.T) {
	c, r := flannelRun()
	for i := 0; i < 12; i++ {
		r.Reachability.Probes = append(r.Reachability.Probes, scenario.Probe{
			Source: "a", Target: "shop/web-1", Basis: scenario.BasisPolicy, Declared: scenario.DeclaredDeny,
			Baseline: scenario.EffectiveOpen, Effective: scenario.EffectiveOpen, Verdict: scenario.VerdictBypass})
	}
	lf := &LabelFile{Findings: []Label{
		{Class: "ipblock-admits-node-ips", Subject: Subject{Kind: "Service", Namespace: "shop", Name: "web"}, AppliesToCNI: []string{"any"}, Label: MustNot},
	}}
	if got := Reconcile(c, r, lf); len(got) != 0 {
		t.Errorf("got %d disagreements on an unenforced CNI, want 0: %+v", len(got), got)
	}
}
