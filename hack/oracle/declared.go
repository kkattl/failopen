package main

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/network-policy-api/policy-assistant/pkg/matcher"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

// declaredCalc answers "what does NetworkPolicy say about this connection?"
// using policy-assistant's matcher — i.e. pure API semantics, no CNI.
//
// Intended source identity:
//   - ordinary pods and the outsider: namespace + labels + pod IP
//   - hostNetwork pods and nodes: the node IP only. They share the node's
//     network namespace, so the only identity a policy can match is an
//     ipBlock on the node address.
//   - external: --external-ip
//
// Observed identity: whatever address the target reported in /clientip —
// a pod IP maps back to that pod's labels, anything else is IP-only.
type declaredCalc struct {
	policy     *matcher.Policy
	nsLabels   map[string]map[string]string
	podsByIP   map[string]*corev1.Pod
	externalIP string
}

func newDeclaredCalc(s *collector.Snapshot, externalIP string, extra ...*corev1.Pod) *declaredCalc {
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
	podsByIP := map[string]*corev1.Pod{}
	add := func(p *corev1.Pod) {
		if p != nil && !p.Spec.HostNetwork && p.Status.PodIP != "" {
			podsByIP[p.Status.PodIP] = p
		}
	}
	for i := range s.Pods {
		add(&s.Pods[i])
	}
	for _, p := range extra {
		add(p)
	}
	return &declaredCalc{
		policy:     matcher.BuildNetworkPolicies(true, nps),
		nsLabels:   nsLabels,
		podsByIP:   podsByIP,
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

func (d *declaredCalc) intendedPeer(s source) *matcher.TrafficPeer {
	switch s.Kind {
	case scenario.SourcePod, scenario.SourceOutsider:
		return d.podPeer(s.Pod, s.IP)
	case scenario.SourceExternal:
		return &matcher.TrafficPeer{IP: d.externalIP}
	default: // hostNetwork pod, node
		return &matcher.TrafficPeer{IP: s.IP}
	}
}

func (d *declaredCalc) observedPeer(ip string) *matcher.TrafficPeer {
	if p, ok := d.podsByIP[ip]; ok {
		return d.podPeer(p, ip)
	}
	return &matcher.TrafficPeer{IP: ip}
}

// intended is the declared verdict for the source the connection started from.
func (d *declaredCalc) intended(s source, t target) string {
	return d.verdictFor(d.intendedPeer(s), t)
}

// observed is the declared verdict for the source addresses the target saw;
// "" when nothing was observed.
func (d *declaredCalc) observed(ips []string, t target) string {
	var verdicts []string
	for _, ip := range ips {
		verdicts = append(verdicts, d.verdictFor(d.observedPeer(ip), t))
	}
	return aggregate(verdicts)
}

// verdictFor aggregates over all backends that could serve the target.
func (d *declaredCalc) verdictFor(src *matcher.TrafficPeer, t target) string {
	if len(t.Backends) == 0 {
		return scenario.DeclaredNA
	}
	var verdicts []string
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
			verdicts = append(verdicts, scenario.DeclaredAllow)
		} else {
			verdicts = append(verdicts, scenario.DeclaredDeny)
		}
	}
	return aggregate(verdicts)
}

func aggregate(verdicts []string) string {
	if len(verdicts) == 0 {
		return ""
	}
	slices.Sort(verdicts)
	verdicts = slices.Compact(verdicts)
	if len(verdicts) == 1 {
		return verdicts[0]
	}
	if slices.Contains(verdicts, scenario.DeclaredNA) {
		return scenario.DeclaredNA
	}
	return scenario.DeclaredMixed
}

func nodeish(s source) bool {
	return s.Kind == scenario.SourceNode || s.Kind == scenario.SourceHostNetwork
}

// basisFor decides which rule governs the expectation (scenario.Basis*),
// from the source addresses the target actually observed.
//
//   - hostNetwork target: behaviour is undefined by the spec.
//   - node / hostNetwork source reaching a pod on ITS OWN node: the spec's
//     "traffic to and from the node where a Pod is running is always
//     allowed". Their packets always carry one of their node's addresses,
//     so what decides is where the backend runs. A Service with backends
//     both on and off the node takes different paths per attempt: mixed.
//     Not for a NodePort on ANOTHER node: that node DNATs and forwards, so
//     the packet arrives from it, not from the source's node.
//   - otherwise: the source arrived unchanged -> plain policy; it arrived as
//     something else (masquerade, natOutgoing, tunnel address) -> SNAT.
//
// With nothing observed (hostPort, or no /clientip answer) it falls back to
// the modelled identity: unchanged source.
func basisFor(s source, t target, observed []string) string {
	if t.Kind == scenario.TargetHostNetwork {
		return scenario.BasisUndefined
	}
	if nodeish(s) && (t.Kind != scenario.TargetNodePort || t.Node == s.Pod.Spec.NodeName) {
		local, total := t.backendNodes(s.Pod.Spec.NodeName)
		switch {
		case total > 0 && local == total:
			return scenario.BasisSpecException
		case local > 0:
			return scenario.BasisMixedPath
		}
	}
	if len(observed) == 0 {
		return scenario.BasisPolicy
	}
	var bases []string
	for _, ip := range observed {
		if ip == s.IP {
			bases = append(bases, scenario.BasisPolicy)
		} else {
			bases = append(bases, scenario.BasisSNAT)
		}
	}
	slices.Sort(bases)
	if bases = slices.Compact(bases); len(bases) == 1 {
		return bases[0]
	}
	return scenario.BasisMixedPath
}
