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

	// Pod network as configured in the CNI itself. Needed to reason about
	// ipBlocks: does "0.0.0.0/0 except <pod CIDR>" still admit node IPs?
	PodCIDRs      []string `json:"podCIDRs,omitempty"`
	Encapsulation string   `json:"encapsulation,omitempty"` // Encap* constant
	PodCIDRSource string   `json:"podCIDRSource,omitempty"` // Source* constant: where PodCIDRs came from
}

// Encapsulation of pod-to-pod traffic between nodes. It decides the source
// IP of node-originated traffic to remote pods (e.g. the tunl0 address with
// IPIP), and therefore whether ipBlocks on node IPs match it.
const (
	EncapIPIP      = "ipip"
	EncapVXLAN     = "vxlan"
	EncapGeneve    = "geneve"
	EncapWireGuard = "wireguard"
	EncapNone      = "none" // native routing / host-gw / BGP without overlay
)

// Where PodCIDRs came from, most to least trustworthy.
const (
	SourceCalicoIPPool = "calico-ippool"
	SourceFlannelConf  = "flannel-config"
	SourceCiliumConf   = "cilium-config"
	// SourceNodePodCIDR is a fallback only: Calico IPAM ignores
	// Node.spec.podCIDR and allocates from its IPPools instead.
	SourceNodePodCIDR = "node-podcidr"
)

// Collector gathers a Snapshot from the cluster.
type Collector interface {
	Collect(ctx context.Context) (*Snapshot, error)
}
