package collector

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ds(name string) appsv1.DaemonSet {
	return dsIn("kube-system", name)
}

func dsIn(namespace, name string) appsv1.DaemonSet {
	return appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
}

func TestClassifyCNI(t *testing.T) {
	tests := []struct {
		name         string
		daemonSets   []appsv1.DaemonSet
		wantName     string
		wantEnforces bool
	}{
		{
			name:         "calico enforces policy",
			daemonSets:   []appsv1.DaemonSet{ds("calico-node")},
			wantName:     "calico",
			wantEnforces: true,
		},
		{
			name:         "flannel does not enforce policy",
			daemonSets:   []appsv1.DaemonSet{ds("kube-flannel-ds")},
			wantName:     "flannel",
			wantEnforces: false,
		},
		{
			name:         "cilium enforces policy",
			daemonSets:   []appsv1.DaemonSet{ds("cilium")},
			wantName:     "cilium",
			wantEnforces: true,
		},
		{
			name:         "flannel from official manifest (kube-flannel namespace)",
			daemonSets:   []appsv1.DaemonSet{dsIn("kube-flannel", "kube-flannel-ds")},
			wantName:     "flannel",
			wantEnforces: false,
		},
		{
			name:         "operator-installed calico (calico-system namespace)",
			daemonSets:   []appsv1.DaemonSet{dsIn("calico-system", "calico-node")},
			wantName:     "calico",
			wantEnforces: true,
		},
		{
			name:         "canal enforces policy",
			daemonSets:   []appsv1.DaemonSet{ds("canal")},
			wantName:     "canal",
			wantEnforces: true,
		},
		{
			name:         "kindnet enforces policy",
			daemonSets:   []appsv1.DaemonSet{ds("kindnet")},
			wantName:     "kindnet",
			wantEnforces: true,
		},
		{
			name:         "enforcing CNI wins over flannel regardless of order",
			daemonSets:   []appsv1.DaemonSet{dsIn("kube-flannel", "kube-flannel-ds"), ds("calico-node")},
			wantName:     "calico",
			wantEnforces: true,
		},
		{
			name:         "no known CNI is unknown",
			daemonSets:   []appsv1.DaemonSet{ds("kube-proxy")},
			wantName:     "unknown",
			wantEnforces: false,
		},
		{
			name:         "empty cluster is unknown",
			daemonSets:   nil,
			wantName:     "unknown",
			wantEnforces: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCNI(tt.daemonSets)
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.EnforcesPolicy != tt.wantEnforces {
				t.Errorf("EnforcesPolicy = %t, want %t", got.EnforcesPolicy, tt.wantEnforces)
			}
		})
	}
}

func k3sNode(args string) corev1.Node {
	return corev1.Node{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		annotationK3sNodeArgs:    args,
		annotationFlannelBackend: "vxlan",
	}}}
}

func TestClassifyEmbeddedCNI(t *testing.T) {
	tests := []struct {
		name         string
		nodes        []corev1.Node
		wantName     string
		wantEnforces bool
	}{
		{"k3s default enforces", []corev1.Node{k3sNode(`["server"]`), k3sNode(`["agent"]`)}, "k3s", true},
		{"k3s with netpol disabled", []corev1.Node{k3sNode(`["server","--disable-network-policy"]`)}, "k3s", false},
		{"plain nodes are unknown", []corev1.Node{{}}, "unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyEmbeddedCNI(tt.nodes)
			if got.Name != tt.wantName || got.EnforcesPolicy != tt.wantEnforces {
				t.Errorf("got %+v, want %s enforces=%t", got, tt.wantName, tt.wantEnforces)
			}
		})
	}
}
