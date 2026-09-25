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
	Pods            []corev1.Pod
	Services        []corev1.Service
	NetworkPolicies []networkingv1.NetworkPolicy
	Namespaces      []corev1.Namespace
	Nodes           []corev1.Node
	CNI             CNIInfo
}

// CNIInfo describes which CNI is installed and whether it actually
// enforces NetworkPolicies (flannel, for example, does not).
type CNIInfo struct {
	Name           string // "calico" | "flannel" | "cilium" | "unknown"
	EnforcesPolicy bool
}

// Collector gathers a Snapshot from the cluster.
type Collector interface {
	Collect(ctx context.Context) (*Snapshot, error)
}
