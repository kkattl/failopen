package collector

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func pool(cidr, ipip, vxlan string, disabled bool) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{"cidr": cidr, "ipipMode": ipip, "vxlanMode": vxlan, "disabled": disabled},
	}}
}

func TestParseCalicoIPPools(t *testing.T) {
	tests := []struct {
		name      string
		pools     []unstructured.Unstructured
		wantCIDRs []string
		wantEncap string
	}{
		{"default manifest", []unstructured.Unstructured{pool("192.168.0.0/16", "Always", "Never", false)},
			[]string{"192.168.0.0/16"}, EncapIPIP},
		{"vxlan", []unstructured.Unstructured{pool("10.244.0.0/16", "Never", "CrossSubnet", false)},
			[]string{"10.244.0.0/16"}, EncapVXLAN},
		{"bgp no overlay", []unstructured.Unstructured{pool("10.0.0.0/16", "Never", "Never", false)},
			[]string{"10.0.0.0/16"}, EncapNone},
		{"disabled pool ignored", []unstructured.Unstructured{
			pool("10.1.0.0/16", "Never", "Never", false), pool("10.2.0.0/16", "Always", "Never", true)},
			[]string{"10.1.0.0/16"}, EncapNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidrs, encap := parseCalicoIPPools(tt.pools)
			if !reflect.DeepEqual(cidrs, tt.wantCIDRs) || encap != tt.wantEncap {
				t.Errorf("got %v %s, want %v %s", cidrs, encap, tt.wantCIDRs, tt.wantEncap)
			}
		})
	}
}

func TestParseFlannelNetConf(t *testing.T) {
	tests := []struct {
		raw       string
		wantOK    bool
		wantEncap string
	}{
		{`{"Network": "10.244.0.0/16", "Backend": {"Type": "vxlan"}}`, true, EncapVXLAN},
		{`{"Network": "10.244.0.0/16", "Backend": {"Type": "host-gw"}}`, true, EncapNone},
		{`{"Network": "10.244.0.0/16"}`, true, EncapVXLAN},
		{`not json`, false, ""},
		{`{"Backend": {"Type": "vxlan"}}`, false, ""},
	}
	for _, tt := range tests {
		cidrs, encap, ok := parseFlannelNetConf(tt.raw)
		if ok != tt.wantOK || encap != tt.wantEncap || (ok && cidrs[0] != "10.244.0.0/16") {
			t.Errorf("parseFlannelNetConf(%s) = %v %s %t", tt.raw, cidrs, encap, ok)
		}
	}
}

func TestParseCiliumConfig(t *testing.T) {
	tests := []struct {
		data      map[string]string
		wantOK    bool
		wantEncap string
	}{
		{map[string]string{"cluster-pool-ipv4-cidr": "10.0.0.0/8"}, true, EncapVXLAN},
		{map[string]string{"cluster-pool-ipv4-cidr": "10.0.0.0/8", "routing-mode": "native"}, true, EncapNone},
		{map[string]string{"cluster-pool-ipv4-cidr": "10.0.0.0/8", "tunnel-protocol": "geneve"}, true, EncapGeneve},
		{map[string]string{"ipam": "kubernetes"}, false, ""},
	}
	for _, tt := range tests {
		_, encap, ok := parseCiliumConfig(tt.data)
		if ok != tt.wantOK || encap != tt.wantEncap {
			t.Errorf("parseCiliumConfig(%v) = %s %t", tt.data, encap, ok)
		}
	}
}

func TestNodePodCIDRs(t *testing.T) {
	nodes := []corev1.Node{
		{Spec: corev1.NodeSpec{PodCIDR: "10.244.1.0/24", PodCIDRs: []string{"10.244.1.0/24"}}},
		{Spec: corev1.NodeSpec{PodCIDR: "10.244.0.0/24"}},
	}
	if got, want := nodePodCIDRs(nodes), []string{"10.244.0.0/24", "10.244.1.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
