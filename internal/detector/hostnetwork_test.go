package detector

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kkattl/failopen/internal/collector"
)

// hostNetSnapshot: the shape of demo-payments — a hostNetwork pod in a
// namespace with a default-deny, plus the given extra ingress rules on it.
func hostNetSnapshot(hostNetwork bool, ingress ...networkingv1.NetworkPolicyIngressRule) *collector.Snapshot {
	pols := []networkingv1.NetworkPolicy{
		{ObjectMeta: metav1.ObjectMeta{Name: "default-deny-all", Namespace: "payments"},
			Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}},
	}
	if len(ingress) > 0 {
		pols = append(pols, networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "probe-ingress", Namespace: "payments"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "host-probe"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress:     ingress,
			}})
	}
	return &collector.Snapshot{
		CNI: collector.CNIInfo{Name: "calico", EnforcesPolicy: true},
		Pods: []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: "host-probe", Namespace: "payments", Labels: map[string]string{"app": "host-probe"}},
			Spec: corev1.PodSpec{HostNetwork: hostNetwork, Containers: []corev1.Container{{Name: "c",
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}},
			Status: corev1.PodStatus{HostIP: "172.18.0.2", PodIP: "172.18.0.2"},
		}},
		NetworkPolicies: pols,
	}
}

func TestHostNetworkUnderDefaultDeny(t *testing.T) {
	got := (&HostNetworkUnderPolicy{}).Detect(hostNetSnapshot(true))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Severity != SeverityCritical || f.Subject != "payments/host-probe" || f.Declared != "DENY all ingress (default-deny-all)" {
		t.Errorf("got %+v", f)
	}
	if f.Verify == "" || len(f.Assumes) == 0 {
		t.Error("finding must say what it assumes and how to verify it")
	}
}

func TestHostNetworkNotForOrdinaryPods(t *testing.T) {
	if got := (&HostNetworkUnderPolicy{}).Detect(hostNetSnapshot(false)); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
}

// A policy that opens the port to everyone declares nothing to bypass.
func TestHostNetworkNotWhenPortOpenToAll(t *testing.T) {
	port := intstr.FromInt32(8080)
	s := hostNetSnapshot(true, networkingv1.NetworkPolicyIngressRule{Ports: []networkingv1.NetworkPolicyPort{{Port: &port}}})
	if got := (&HostNetworkUnderPolicy{}).Detect(s); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
}

// Restricted to some peers is still restricted.
func TestHostNetworkRestrictedToPeers(t *testing.T) {
	s := hostNetSnapshot(true, from(nil, block("10.250.0.0/24"))...)
	got := (&HostNetworkUnderPolicy{}).Detect(s)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
}

// No policy in the namespace selects it: nothing is declared (demo-payments'
// monitoring/node-agent, labelled must-not).
func TestHostNetworkNotWithoutPolicy(t *testing.T) {
	s := hostNetSnapshot(true)
	s.NetworkPolicies = nil
	if got := (&HostNetworkUnderPolicy{}).Detect(s); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
}

// 0.0.0.0/0 with no excepts admits nodes, external clients and pods alike.
func TestHostNetworkNotWhenOpenInternet(t *testing.T) {
	s := hostNetSnapshot(true, from(nil, block("0.0.0.0/0"))...)
	if got := (&HostNetworkUnderPolicy{}).Detect(s); len(got) != 0 {
		t.Errorf("got %+v, want none", got)
	}
}

// namespaceSelector: {} admits every pod, but not nodes or external
// clients: the policy still restricts, and is still not applied.
func TestHostNetworkAllPodsIsStillRestricted(t *testing.T) {
	allPods := networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}}
	s := hostNetSnapshot(true, from(nil, allPods)...)
	if got := (&HostNetworkUnderPolicy{}).Detect(s); len(got) != 1 {
		t.Errorf("got %d findings, want 1", len(got))
	}
}

// Only the restricted ports are reported.
func TestHostNetworkReportsRestrictedPortsOnly(t *testing.T) {
	port := intstr.FromInt32(8080)
	s := hostNetSnapshot(true, networkingv1.NetworkPolicyIngressRule{Ports: []networkingv1.NetworkPolicyPort{{Port: &port}}})
	c := &s.Pods[0].Spec.Containers[0]
	c.Ports = append(c.Ports, corev1.ContainerPort{Name: "admin", ContainerPort: 9000})
	got := (&HostNetworkUnderPolicy{}).Detect(s)
	if len(got) != 1 || got[0].Effective != "ALLOW on the node IP, port 9000 — policy not applied (hostNetwork pod)" {
		t.Errorf("got %+v, want one finding on port 9000 only", got)
	}
}

func TestHostNetworkSkipsSystemNamespaces(t *testing.T) {
	s := hostNetSnapshot(true)
	for _, ns := range []string{"kube-system", "calico-system", "cilium"} {
		s.Pods[0].Namespace, s.NetworkPolicies[0].Namespace = ns, ns
		if got := (&HostNetworkUnderPolicy{}).Detect(s); len(got) != 0 {
			t.Errorf("%s: got %+v, want none (cluster plumbing)", ns, got)
		}
	}
}

func TestHostNetworkNotWhenNothingIsEnforced(t *testing.T) {
	s := hostNetSnapshot(true)
	s.CNI = collector.CNIInfo{Name: "flannel"}
	if got := (&HostNetworkUnderPolicy{}).Detect(s); len(got) != 0 {
		t.Errorf("got %+v on flannel, want none (the cni detector covers it)", got)
	}
}

// An unrecognised CNI may enforce policies: the finding stays, downgraded.
func TestHostNetworkWarningOnUnknownCNI(t *testing.T) {
	s := hostNetSnapshot(true)
	s.CNI = collector.CNIInfo{Name: "unknown"}
	got := (&HostNetworkUnderPolicy{}).Detect(s)
	if len(got) != 1 || got[0].Severity != SeverityWarning {
		t.Fatalf("got %+v, want one warning", got)
	}
	if a := got[0].Assumes[len(got[0].Assumes)-1]; a != "CNI not recognised: assumes it enforces NetworkPolicy at all" {
		t.Errorf("last assumption = %q, want the unknown-CNI caveat", a)
	}
}
