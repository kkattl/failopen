package detector

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kkattl/failopen/internal/collector"
)

func policies(nsNames ...string) []networkingv1.NetworkPolicy {
	var out []networkingv1.NetworkPolicy
	for i, ns := range nsNames {
		out = append(out, networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "p" + string(rune('a'+i))}})
	}
	return out
}

func TestCNIEnforcement(t *testing.T) {
	tests := []struct {
		name     string
		cni      collector.CNIInfo
		policies []networkingv1.NetworkPolicy
		want     []Severity
	}{
		{"flannel with policies", collector.CNIInfo{Name: "flannel"}, policies("payments", "payments", "shop"), []Severity{SeverityCritical}},
		{"flannel without policies", collector.CNIInfo{Name: "flannel"}, nil, nil},
		{"flannel with only system policies", collector.CNIInfo{Name: "flannel"}, policies("kube-system"), nil},
		{"calico with policies", collector.CNIInfo{Name: "calico", EnforcesPolicy: true}, policies("payments"), nil},
		{"unknown CNI with policies", collector.CNIInfo{Name: "unknown"}, policies("payments"), []Severity{SeverityWarning}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (&CNIEnforcement{}).Detect(&collector.Snapshot{CNI: tt.cni, NetworkPolicies: tt.policies})
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings %+v, want %v", len(got), got, tt.want)
			}
			for i := range got {
				if got[i].Severity != tt.want[i] {
					t.Errorf("finding %d severity %s, want %s", i, got[i].Severity, tt.want[i])
				}
			}
		})
	}
	got := (&CNIEnforcement{}).Detect(&collector.Snapshot{CNI: collector.CNIInfo{Name: "flannel"}, NetworkPolicies: policies("payments", "payments", "shop")})
	if want := "3 NetworkPolicies across 2 namespaces"; got[0].Declared != want {
		t.Errorf("Declared = %q, want %q", got[0].Declared, want)
	}
}
