package collector

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ds(name string) appsv1.DaemonSet {
	return appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system"},
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
