package main

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/network-policy-api/policy-assistant/pkg/matcher"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

// declaredCalc answers "what does NetworkPolicy say about this connection?"
// using policy-assistant's matcher — i.e. pure API semantics, no CNI.
//
// Source identity:
//   - ordinary pods and the outsider: namespace + labels + pod IP
//   - hostNetwork pods and nodes: the node IP only. They share the node's
//     network namespace, so the only identity a policy can match is an
//     ipBlock on the node address.
//   - external: --external-ip
type declaredCalc struct {
	policy     *matcher.Policy
	nsLabels   map[string]map[string]string
	externalIP string
}

func newDeclaredCalc(s *collector.Snapshot, externalIP string) *declaredCalc {
	var nps []*networkingv1.NetworkPolicy
	for i := range s.NetworkPolicies {
		nps = append(nps, &s.NetworkPolicies[i])
	}
	nsLabels := map[string]map[string]string{
		oracleNS: {"kubernetes.io/metadata.name": oracleNS},
	}
	for _, ns := range s.Namespaces {
		nsLabels[ns.Name] = ns.Labels
	}
	return &declaredCalc{
		policy:     matcher.BuildNetworkPolicies(true, nps),
		nsLabels:   nsLabels,
		externalIP: externalIP,
	}
}

func (d *declaredCalc) podPeer(p *corev1.Pod, ip string) *matcher.TrafficPeer {
	return &matcher.TrafficPeer{
		Internal: &matcher.InternalPeer{
			Namespace:       p.Namespace,
			PodLabels:       p.Labels,
			NamespaceLabels: d.nsLabels[p.Namespace],
		},
		IP: ip,
	}
}

func (d *declaredCalc) sourcePeer(s source) *matcher.TrafficPeer {
	switch s.Kind {
	case scenario.SourcePod, scenario.SourceOutsider:
		return d.podPeer(s.Pod, s.IP)
	case scenario.SourceExternal:
		return &matcher.TrafficPeer{IP: d.externalIP}
	default: // hostNetwork pod, node
		return &matcher.TrafficPeer{IP: s.IP}
	}
}

// verdict aggregates over all backends that could serve the target.
func (d *declaredCalc) verdict(s source, t target) string {
	if len(t.Backends) == 0 {
		return scenario.DeclaredNA
	}
	allowed, denied := 0, 0
	src := d.sourcePeer(s)
	for _, b := range t.Backends {
		ip := b.Pod.Status.PodIP
		if b.Pod.Spec.HostNetwork {
			ip = b.Pod.Status.HostIP
		}
		r := d.policy.IsTrafficAllowed(&matcher.Traffic{
			Source:           src,
			Destination:      d.podPeer(b.Pod, ip),
			ResolvedPort:     b.Port,
			ResolvedPortName: b.PortName,
			Protocol:         corev1.ProtocolTCP,
		})
		if r.IsAllowed() {
			allowed++
		} else {
			denied++
		}
	}
	switch {
	case denied == 0:
		return scenario.DeclaredAllow
	case allowed == 0:
		return scenario.DeclaredDeny
	default:
		return scenario.DeclaredMixed
	}
}
