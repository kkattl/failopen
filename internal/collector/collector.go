package collector

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// Snapshot is a complete view of cluster state at collection time.
// Detectors operate ONLY on a Snapshot, never on the API directly.
// This makes every detector a pure function that can be unit-tested
// by hand-building a Snapshot from fixtures — no cluster required.
type Snapshot struct {
	Pods            []corev1.Pod                 `json:"pods"`
	Services        []corev1.Service             `json:"services"`
	NetworkPolicies []networkingv1.NetworkPolicy `json:"networkPolicies"`
	Namespaces      []corev1.Namespace           `json:"namespaces"`
	Nodes           []corev1.Node                `json:"nodes"`
	CNI             CNIInfo                      `json:"cni"`
}

// CNIInfo describes which CNI is installed and whether it actually
// enforces NetworkPolicies (flannel, for example, does not).
type CNIInfo struct {
	Name           string `json:"name"` // "calico" | "flannel" | "cilium" | "canal" | "unknown"
	EnforcesPolicy bool   `json:"enforcesPolicy"`
}

// Collector gathers a Snapshot from the cluster.
type Collector interface {
	Collect(ctx context.Context) (*Snapshot, error)
}
