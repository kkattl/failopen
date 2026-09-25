package detector

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/kkattl/failopen/internal/collector"
)

// Fixture shaped like the corpus lab: nodes 172.18.0.2-3, pods 192.168/16,
// external clients 10.250.0.0/24.
func edgeSnapshot(ingress []networkingv1.NetworkPolicyIngressRule, podCIDRs ...string) *collector.Snapshot {
	node := func(name, ip string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}}}
	}
	return &collector.Snapshot{
		CNI:   collector.CNIInfo{Name: "calico", EnforcesPolicy: true, PodCIDRs: podCIDRs},
		Nodes: []corev1.Node{node("n1", "172.18.0.2"), node("n2", "172.18.0.3")},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "gw-abc-1", Namespace: "edge", Labels: map[string]string{"app": "gw"},
				OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "gw-abc", Controller: ptr.To(true)}}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c",
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}},
			Status: corev1.PodStatus{HostIP: "172.18.0.2", PodIP: "192.168.1.5"},
		}},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "edge"},
			Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, Selector: map[string]string{"app": "gw"},
				ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
				Ports:                 []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("http"), NodePort: 30080}}},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{
			{ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: "edge"},
				Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "gw-ingress", Namespace: "edge"},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "gw"}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress:     ingress,
				}},
		},
	}
}

func from(port *intstr.IntOrString, peers ...networkingv1.NetworkPolicyPeer) []networkingv1.NetworkPolicyIngressRule {
	r := networkingv1.NetworkPolicyIngressRule{From: peers}
	if port != nil {
		r.Ports = []networkingv1.NetworkPolicyPort{{Port: port}}
	}
	return []networkingv1.NetworkPolicyIngressRule{r}
}

func block(cidr string, except ...string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr, Except: except}}
}

func TestIPBlockNodeIPs(t *testing.T) {
	p8080 := ptr.To(intstr.FromInt32(8080))
	pHTTP := ptr.To(intstr.FromString("http"))
	p9090 := ptr.To(intstr.FromInt32(9090))
	pods := "192.168.0.0/16"
	tests := []struct {
		name string
		snap *collector.Snapshot
		want []Severity
	}{
		// saas/health: "internet but not pods" — node IPs are inside, pods are
		// out. Internet-facing, so a warning (labelling decision Q1).
		{"anything but pods", edgeSnapshot(from(p8080, block("0.0.0.0/0", pods)), pods), []Severity{SeverityWarning}},
		// ecommerce original: a closed allowlist (the F5 range) that overlaps
		// the node network. Critical.
		{"external range overlapping nodes", edgeSnapshot(from(pHTTP, block("172.18.0.0/16")), pods), []Severity{SeverityCritical}},
		// fintech: 0.0.0.0/0 admits pods on purpose; SNAT changes nothing.
		{"everything incl. pods", edgeSnapshot(from(p8080, block("0.0.0.0/0")), pods), nil},
		// ecommerce fixed: external range doesn't contain node IPs.
		{"external range not overlapping nodes", edgeSnapshot(from(p8080, block("10.250.0.0/24")), pods), nil},
		// iot: a /32 that isn't a node.
		{"single external host", edgeSnapshot(from(p8080, block("10.250.0.10/32")), pods), nil},
		{"rule for another port", edgeSnapshot(from(p9090, block("0.0.0.0/0", pods)), pods), nil},
		{"another rule admits all pods", edgeSnapshot(append(from(p8080, block("0.0.0.0/0", pods)),
			from(nil, networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}})...), pods), nil},
		{"rule without from admits everyone", edgeSnapshot(append(from(p8080, block("0.0.0.0/0", pods)),
			networkingv1.NetworkPolicyIngressRule{}), pods), nil},
		{"pod CIDR unknown degrades to warning", edgeSnapshot(from(p8080, block("0.0.0.0/0", pods))), []Severity{SeverityWarning}},
		{"node IPs excepted explicitly", edgeSnapshot(from(p8080, block("0.0.0.0/0", pods, "172.18.0.0/16")), pods), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (&IPBlockNodeIPs{}).Detect(tt.snap)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings %+v, want %v", len(got), got, tt.want)
			}
			for i := range got {
				if got[i].Severity != tt.want[i] {
					t.Errorf("severity %s, want %s", got[i].Severity, tt.want[i])
				}
			}
		})
	}
}

// Cilium doesn't match ipBlocks against cluster identities, so the SNAT'd
// traffic never passes the rule: no bypass, no finding.
func TestIPBlockNodeIPsNotOnCilium(t *testing.T) {
	s := edgeSnapshot(from(nil, block("172.18.0.0/16")), "192.168.0.0/16")
	s.CNI = collector.CNIInfo{Name: "cilium", EnforcesPolicy: true, PodCIDRs: []string{"192.168.0.0/16"}}
	if got := (&IPBlockNodeIPs{}).Detect(s); len(got) != 0 {
		t.Errorf("got %+v on cilium, want none", got)
	}
}

func TestIPBlockNodeIPsNotWhenNothingIsEnforced(t *testing.T) {
	s := edgeSnapshot(from(nil, block("172.18.0.0/16")), "192.168.0.0/16")
	s.CNI = collector.CNIInfo{Name: "flannel", PodCIDRs: []string{"192.168.0.0/16"}}
	if got := (&IPBlockNodeIPs{}).Detect(s); len(got) != 0 {
		t.Errorf("got %+v on flannel, want none (the cni detector covers it)", got)
	}
}

func TestIPBlockNodeIPsFindingText(t *testing.T) {
	got := (&IPBlockNodeIPs{}).Detect(edgeSnapshot(from(nil, block("0.0.0.0/0", "192.168.0.0/16")), "192.168.0.0/16"))
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	f := got[0]
	for field, want := range map[string]string{
		f.Subject:   "edge/svc/gw:30080",
		f.Declared:  "ALLOW only 0.0.0.0/0 except 192.168.0.0/16 (gw-ingress)",
		f.Effective: "ALLOW from any pod via NodePort 30080 (SNAT to node IP)",
	} {
		if field != want {
			t.Errorf("got %q, want %q", field, want)
		}
	}
	if f.Verify == "" || len(f.Assumes) == 0 {
		t.Error("finding must say what it assumes and how to verify it")
	}
}

func TestHostPortExposureNamedByWorkload(t *testing.T) {
	s := edgeSnapshot(from(nil, block("172.16.0.0/12")), "192.168.0.0/16")
	s.Services = nil
	s.Pods[0].Spec.Containers[0].Ports[0].HostPort = 8883
	got := (&IPBlockNodeIPs{}).Detect(s)
	if len(got) != 1 || got[0].Subject != "edge/gw:8883" {
		t.Fatalf("got %+v, want one finding on edge/gw:8883", got)
	}
}
