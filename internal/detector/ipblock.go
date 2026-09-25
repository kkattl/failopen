package detector

import (
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kkattl/failopen/internal/collector"
)

// IPBlockNodeIPs finds pods exposed at the node level (NodePort /
// LoadBalancer backends, hostPorts) whose ingress policy admits node IPs
// through an ipBlock while NOT admitting pods.
//
// The intent of such a rule is "only these external clients" or "anything
// but pods". But pod traffic heading for a NodePort or hostPort is
// source-NATed to a node address on the way — kube-proxy masquerade
// (externalTrafficPolicy: Cluster) or the CNI's outgoing NAT — and the
// Kubernetes docs leave it undefined whether that happens before or after
// policy evaluation. When it happens before, the packet arrives as a node IP
// and the rule meant to keep pods out lets every pod in.
type IPBlockNodeIPs struct{}

func (*IPBlockNodeIPs) Name() string { return "ipblock-node-ips" }

// exposure is one way a pod is reachable at a node address.
type exposure struct {
	object   ObjectRef
	subject  string // what a human fixes: the Service, or the workload
	how      string // "NodePort 30080", "hostPort 8883"
	pod      *corev1.Pod
	podPort  int32
	portName string
	nodePort string // for the verify command: "<nodeIP>:<port>"
}

func (*IPBlockNodeIPs) Detect(s *collector.Snapshot) []Finding {
	// Cilium applies CIDR rules to the "world" identity only: SNAT'd pod
	// traffic arrives as a cluster identity and the ipBlock never admits it.
	// Measured on the corpus: no SNAT bypass on cilium in any scenario (the
	// same rules over-block instead — a different finding, not this one).
	if s.CNI.Name == "cilium" {
		return nil
	}
	// Policies that aren't enforced at all can't be bypassed; the cni
	// detector already says everything there is to say.
	if !s.CNI.EnforcesPolicy {
		return nil
	}
	nodeIPs := internalIPs(s.Nodes)
	if len(nodeIPs) == 0 {
		return nil
	}
	podCIDRs := parsePrefixes(s.CNI.PodCIDRs)

	var out []Finding
	seen := map[string]bool{}
	for _, e := range exposures(s) {
		if seen[e.subject] {
			continue
		}
		pol, block, ok := admittingBlock(s, e, nodeIPs, podCIDRs)
		if !ok {
			continue
		}
		seen[e.subject] = true
		out = append(out, finding(s, e, pol, block, nodeIPs, podCIDRs))
	}
	return out
}

func finding(s *collector.Snapshot, e exposure, pol *networkingv1.NetworkPolicy, block *networkingv1.IPBlock, nodeIPs, podCIDRs []netip.Prefix) Finding {
	allowed := block.CIDR
	if len(block.Except) > 0 {
		allowed += " except " + strings.Join(block.Except, ",")
	}
	f := Finding{
		Detector:  "ipblock-node-ips",
		Object:    e.object,
		Severity:  SeverityCritical,
		Namespace: e.pod.Namespace,
		Subject:   e.subject,
		Declared:  fmt.Sprintf("ALLOW only %s (%s)", allowed, pol.Name),
		Effective: fmt.Sprintf("ALLOW from any pod via %s (SNAT to node IP)", e.how),
		Detail: fmt.Sprintf("Pod traffic to the %s is source-NATed to a node IP, and node IPs fall inside %s, "+
			"so the rule meant to keep pods out lets them in.", e.how, allowed),
		Assumes: []string{
			"pod -> node-IP traffic is SNAT'd to a node address before policy evaluation " +
				"(kube-proxy masquerade with externalTrafficPolicy: Cluster, or CNI outgoing NAT) — undefined by the spec, CNI-dependent",
			fmt.Sprintf("CNI %s; the source pod has egress to node IPs", s.CNI.Name),
		},
		Verify: fmt.Sprintf("kubectl run fo-verify -n <ns-without-egress-policy> --rm -i --restart=Never "+
			"--image=registry.k8s.io/e2e-test-images/agnhost:2.53 -- connect %s --timeout=3s", e.nodePort),
	}
	switch {
	case len(podCIDRs) == 0:
		f.Severity = SeverityWarning
		f.Assumes = append(f.Assumes, "pod CIDR unknown: could not confirm the rule excludes pods")
	case internetWide(block):
		// "Anything but pods" in front of an internet-facing pod: pods could
		// usually reach it through the public load balancer anyway, so the
		// gap is real but rarely the path an attacker needs.
		f.Severity = SeverityWarning
	}
	// Otherwise a narrow range ("only the F5 SNAT pool") that happens to
	// cover the nodes: the stated intent is a closed allowlist, and every
	// pod in the cluster falls inside it. Critical.
	return f
}

// internetWide: the block starts from the whole address space (0.0.0.0/0,
// ::/0), i.e. an internet-facing allow with carve-outs.
func internetWide(b *networkingv1.IPBlock) bool {
	p, err := netip.ParsePrefix(b.CIDR)
	return err == nil && p.Bits() == 0
}

// admittingBlock returns the policy and ipBlock through which node IPs are
// admitted to e's pod and port, provided that pods as such are NOT admitted
// (if a rule already lets every pod in, SNAT changes nothing).
func admittingBlock(s *collector.Snapshot, e exposure, nodeIPs, podCIDRs []netip.Prefix) (*networkingv1.NetworkPolicy, *networkingv1.IPBlock, bool) {
	var hitPol *networkingv1.NetworkPolicy
	var hitBlock *networkingv1.IPBlock
	selected := false
	for i := range s.NetworkPolicies {
		np := &s.NetworkPolicies[i]
		if np.Namespace != e.pod.Namespace || !hasIngress(np) || !selects(&np.Spec.PodSelector, e.pod) {
			continue
		}
		selected = true
		for _, rule := range np.Spec.Ingress {
			if !portMatches(rule.Ports, e.podPort, e.portName) {
				continue
			}
			if len(rule.From) == 0 {
				return nil, nil, false // everyone allowed on this port
			}
			for _, peer := range rule.From {
				if peer.IPBlock == nil {
					if allPods(peer) {
						return nil, nil, false
					}
					continue
				}
				if len(podCIDRs) > 0 && admitsAll(peer.IPBlock, podCIDRs) {
					return nil, nil, false // pods admitted on purpose
				}
				if hitBlock == nil && admitsAny(peer.IPBlock, nodeIPs) {
					hitPol, hitBlock = np, peer.IPBlock
				}
			}
		}
	}
	if !selected || hitBlock == nil {
		return nil, nil, false
	}
	return hitPol, hitBlock, true
}

func exposures(s *collector.Snapshot) []exposure {
	var out []exposure
	for i := range s.Services {
		svc := &s.Services[i]
		if isSystemNamespace(svc.Namespace) || len(svc.Spec.Selector) == 0 ||
			(svc.Spec.Type != corev1.ServiceTypeNodePort && svc.Spec.Type != corev1.ServiceTypeLoadBalancer) {
			continue
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		for _, sp := range svc.Spec.Ports {
			if sp.NodePort == 0 || !isTCP(sp.Protocol) {
				continue
			}
			for j := range s.Pods {
				p := &s.Pods[j]
				if p.Namespace != svc.Namespace || p.Spec.HostNetwork || !sel.Matches(labels.Set(p.Labels)) {
					continue
				}
				port, name, ok := resolveTargetPort(p, sp)
				if !ok {
					continue
				}
				out = append(out, exposure{
					object:  ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
					subject: fmt.Sprintf("%s/svc/%s:%d", svc.Namespace, svc.Name, sp.NodePort),
					how:     fmt.Sprintf("NodePort %d", sp.NodePort),
					pod:     p, podPort: port, portName: name,
					nodePort: fmt.Sprintf("%s:%d", p.Status.HostIP, sp.NodePort),
				})
			}
		}
	}
	for j := range s.Pods {
		p := &s.Pods[j]
		if isSystemNamespace(p.Namespace) || p.Spec.HostNetwork {
			continue
		}
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.HostPort == 0 || !isTCP(cp.Protocol) {
					continue
				}
				out = append(out, exposure{
					object:  ObjectRef{Kind: "Workload", Namespace: p.Namespace, Name: workloadName(p)},
					subject: fmt.Sprintf("%s/%s:%d", p.Namespace, workloadName(p), cp.HostPort),
					how:     fmt.Sprintf("hostPort %d", cp.HostPort),
					pod:     p, podPort: cp.ContainerPort, portName: cp.Name,
					nodePort: fmt.Sprintf("%s:%d", p.Status.HostIP, cp.HostPort),
				})
			}
		}
	}
	return out
}

// --- helpers ---

func hasIngress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PolicyTypes) == 0 {
		return true // defaults to Ingress
	}
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			return true
		}
	}
	return false
}

func selects(sel *metav1.LabelSelector, p *corev1.Pod) bool {
	s, err := metav1.LabelSelectorAsSelector(sel)
	return err == nil && s.Matches(labels.Set(p.Labels))
}

// allPods: a peer that admits every pod in every namespace.
func allPods(peer networkingv1.NetworkPolicyPeer) bool {
	empty := func(s *metav1.LabelSelector) bool {
		return s != nil && len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0
	}
	return empty(peer.NamespaceSelector) && (peer.PodSelector == nil || empty(peer.PodSelector))
}

func portMatches(ports []networkingv1.NetworkPolicyPort, port int32, name string) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p.Protocol != nil && *p.Protocol != corev1.ProtocolTCP {
			continue
		}
		switch {
		case p.Port == nil:
			return true
		case p.Port.StrVal != "":
			if name != "" && p.Port.StrVal == name {
				return true
			}
		case p.EndPort != nil:
			if port >= p.Port.IntVal && port <= *p.EndPort {
				return true
			}
		case p.Port.IntVal == port:
			return true
		}
	}
	return false
}

// admitsAny: some address in addrs is inside cidr and outside every except.
func admitsAny(b *networkingv1.IPBlock, addrs []netip.Prefix) bool {
	cidr, err := netip.ParsePrefix(b.CIDR)
	if err != nil {
		return false
	}
	excepts := parsePrefixes(b.Except)
	for _, a := range addrs {
		if !cidr.Contains(a.Addr()) {
			continue
		}
		excluded := false
		for _, e := range excepts {
			if e.Contains(a.Addr()) {
				excluded = true
				break
			}
		}
		if !excluded {
			return true
		}
	}
	return false
}

// admitsAll: every range in nets lies inside cidr and overlaps no except.
func admitsAll(b *networkingv1.IPBlock, nets []netip.Prefix) bool {
	cidr, err := netip.ParsePrefix(b.CIDR)
	if err != nil {
		return false
	}
	for _, n := range nets {
		if !cidr.Contains(n.Addr()) || n.Bits() < cidr.Bits() {
			return false
		}
		for _, e := range parsePrefixes(b.Except) {
			if e.Overlaps(n) {
				return false
			}
		}
	}
	return true
}

func internalIPs(nodes []corev1.Node) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range nodes {
		for _, a := range n.Status.Addresses {
			if a.Type != corev1.NodeInternalIP {
				continue
			}
			if ip, err := netip.ParseAddr(a.Address); err == nil {
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}
	return out
}

func parsePrefixes(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// resolveTargetPort maps a Service port to the pod's port number and name.
func resolveTargetPort(p *corev1.Pod, sp corev1.ServicePort) (int32, string, bool) {
	tp := sp.TargetPort
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			if (tp.StrVal != "" && cp.Name == tp.StrVal) || (tp.StrVal == "" && cp.ContainerPort == tp.IntVal) {
				return cp.ContainerPort, cp.Name, true
			}
		}
	}
	switch {
	case tp.StrVal != "":
		return 0, "", false // named port not on this pod
	case tp.IntVal == 0:
		return sp.Port, "", true
	default:
		return tp.IntVal, "", true
	}
}

// workloadName names a pod by its controller: DaemonSet/StatefulSet name,
// or the Deployment behind a ReplicaSet ("web-5fdfd7d849" -> "web").
func workloadName(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if i := strings.LastIndex(o.Name, "-"); i > 0 {
				return o.Name[:i]
			}
		}
		return o.Name
	}
	return p.Name
}

func isTCP(p corev1.Protocol) bool { return p == "" || p == corev1.ProtocolTCP }
