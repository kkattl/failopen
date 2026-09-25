package collector

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var calicoIPPools = schema.GroupVersionResource{Group: "crd.projectcalico.org", Version: "v1", Resource: "ippools"}

// detectPodNetwork fills the pod-network fields of cni. Best effort: missing
// CRDs, ConfigMaps or RBAC permissions fall through to the next source and,
// finally, to Node.spec.podCIDR. It never fails the collection.
func (c *k8sCollector) detectPodNetwork(ctx context.Context, cni *CNIInfo, nodes []corev1.Node) {
	switch cni.Name {
	case "calico", "canal":
		if list, err := c.dynamic.Resource(calicoIPPools).List(ctx, metav1.ListOptions{}); err == nil && len(list.Items) > 0 {
			cni.PodCIDRs, cni.Encapsulation = parseCalicoIPPools(list.Items)
			cni.PodCIDRSource = SourceCalicoIPPool
			return
		}
	case "flannel":
		if cm := c.firstConfigMap(ctx, "kube-flannel-cfg", "kube-flannel", "kube-system"); cm != nil {
			if cidrs, encap, ok := parseFlannelNetConf(cm.Data["net-conf.json"]); ok {
				cni.PodCIDRs, cni.Encapsulation, cni.PodCIDRSource = cidrs, encap, SourceFlannelConf
				return
			}
		}
	case "cilium":
		if cm := c.firstConfigMap(ctx, "cilium-config", "kube-system", "cilium"); cm != nil {
			if cidrs, encap, ok := parseCiliumConfig(cm.Data); ok {
				cni.PodCIDRs, cni.Encapsulation, cni.PodCIDRSource = cidrs, encap, SourceCiliumConf
				return
			}
		}
	case "k3s":
		// k3s' embedded flannel does honour Node.spec.podCIDR, and records
		// its backend on every node.
		for _, n := range nodes {
			if b, ok := n.Annotations[annotationFlannelBackend]; ok {
				cni.Encapsulation = flannelEncap(b)
				break
			}
		}
	}
	if cidrs := nodePodCIDRs(nodes); len(cidrs) > 0 {
		cni.PodCIDRs, cni.PodCIDRSource = cidrs, SourceNodePodCIDR
	}
}

func (c *k8sCollector) firstConfigMap(ctx context.Context, name string, namespaces ...string) *corev1.ConfigMap {
	for _, ns := range namespaces {
		if cm, err := c.client.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{}); err == nil {
			return cm
		}
	}
	return nil
}

// parseCalicoIPPools returns enabled pool CIDRs and the overlay in use.
// Pools may differ; any IPIP pool makes the answer "ipip", then VXLAN.
func parseCalicoIPPools(pools []unstructured.Unstructured) ([]string, string) {
	var cidrs []string
	encap := EncapNone
	for _, p := range pools {
		if disabled, _, _ := unstructured.NestedBool(p.Object, "spec", "disabled"); disabled {
			continue
		}
		cidr, _, _ := unstructured.NestedString(p.Object, "spec", "cidr")
		if cidr == "" {
			continue
		}
		cidrs = append(cidrs, cidr)
		ipip, _, _ := unstructured.NestedString(p.Object, "spec", "ipipMode")
		vxlan, _, _ := unstructured.NestedString(p.Object, "spec", "vxlanMode")
		switch {
		case ipip != "" && ipip != "Never":
			encap = EncapIPIP
		case vxlan != "" && vxlan != "Never" && encap != EncapIPIP:
			encap = EncapVXLAN
		}
	}
	sort.Strings(cidrs)
	return cidrs, encap
}

// parseFlannelNetConf reads flannel's net-conf.json.
func parseFlannelNetConf(raw string) ([]string, string, bool) {
	var conf struct {
		Network     string
		IPv6Network string
		Backend     struct{ Type string }
	}
	if err := json.Unmarshal([]byte(raw), &conf); err != nil || conf.Network == "" {
		return nil, "", false
	}
	cidrs := []string{conf.Network}
	if conf.IPv6Network != "" {
		cidrs = append(cidrs, conf.IPv6Network)
	}
	return cidrs, flannelEncap(conf.Backend.Type), true
}

// flannelEncap maps a flannel backend type to an Encap* constant.
func flannelEncap(backend string) string {
	switch strings.ToLower(backend) {
	case "host-gw":
		return EncapNone
	case "ipip":
		return EncapIPIP
	case "wireguard", "wireguard-native":
		return EncapWireGuard
	default: // "vxlan", and flannel's default when unset
		return EncapVXLAN
	}
}

// parseCiliumConfig reads the cilium-config ConfigMap. Only cluster-pool
// IPAM stores the CIDR here; other IPAM modes fall back to node podCIDRs.
func parseCiliumConfig(data map[string]string) ([]string, string, bool) {
	cidrs := strings.Fields(data["cluster-pool-ipv4-cidr"])
	if len(cidrs) == 0 {
		return nil, "", false
	}
	encap := EncapVXLAN // cilium's default tunnel
	switch {
	case data["routing-mode"] == "native", data["tunnel"] == "disabled":
		encap = EncapNone
	case data["tunnel-protocol"] == "geneve", data["tunnel"] == "geneve":
		encap = EncapGeneve
	}
	if data["enable-wireguard"] == "true" {
		encap = EncapWireGuard
	}
	return cidrs, encap, true
}

func nodePodCIDRs(nodes []corev1.Node) []string {
	set := map[string]bool{}
	for _, n := range nodes {
		for _, c := range n.Spec.PodCIDRs {
			set[c] = true
		}
		if n.Spec.PodCIDR != "" {
			set[n.Spec.PodCIDR] = true
		}
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
