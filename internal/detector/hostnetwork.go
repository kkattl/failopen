package detector

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/kkattl/failopen/internal/collector"
)

// HostNetworkUnderPolicy finds hostNetwork pods selected by an ingress
// NetworkPolicy that restricts them.
//
// A hostNetwork pod has no interface of its own: it listens on the node's
// addresses, in the node's network namespace. CNIs enforce NetworkPolicy on
// pod interfaces, so the policy has nothing to attach to — the Kubernetes
// docs call NetworkPolicy behaviour for hostNetwork pods "undefined".
// Measured on Calico and Cilium: every node, every hostNetwork pod, external
// clients and any pod whose own egress allows it reach the pod's ports,
// whatever the policy says.
type HostNetworkUnderPolicy struct{}

func (*HostNetworkUnderPolicy) Name() string { return "hostnetwork-under-policy" }

func (*HostNetworkUnderPolicy) Detect(s *collector.Snapshot) []Finding {
	// Nothing is enforced at all: the cni detector covers it.
	if !s.CNI.EnforcesPolicy && s.CNI.Name != "unknown" {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for i := range s.Pods {
		p := &s.Pods[i]
		if !p.Spec.HostNetwork || isSystemNamespace(p.Namespace) {
			continue
		}
		subject := p.Namespace + "/" + workloadName(p)
		if seen[subject] {
			continue
		}
		pols := ingressPoliciesFor(s, p)
		if len(pols) == 0 {
			continue
		}
		ports := restrictedPorts(p, pols)
		if ports == nil {
			continue // some rule admits everyone on every port it listens on
		}
		seen[subject] = true
		out = append(out, hostNetworkFinding(s, p, subject, pols, ports))
	}
	return out
}

func hostNetworkFinding(s *collector.Snapshot, p *corev1.Pod, subject string, pols []*networkingv1.NetworkPolicy, ports []string) Finding {
	names := make([]string, len(pols))
	denyAll := false
	for i, np := range pols {
		names[i] = np.Name
		if len(np.Spec.Ingress) == 0 {
			denyAll = true
		}
	}
	declared := fmt.Sprintf("ingress restricted (%s)", strings.Join(names, ", "))
	if denyAll {
		declared = fmt.Sprintf("DENY all ingress (%s)", strings.Join(names, ", "))
	}
	on := "port " + strings.Join(ports, ", ")
	if len(ports) == 0 {
		on = "every port it listens on"
	}
	f := Finding{
		Detector:  "hostnetwork-under-policy",
		Object:    ObjectRef{Kind: "Workload", Namespace: p.Namespace, Name: workloadName(p)},
		Severity:  SeverityCritical,
		Namespace: p.Namespace,
		Subject:   subject,
		Declared:  declared,
		Effective: fmt.Sprintf("ALLOW on the node IP, %s — policy not applied (hostNetwork pod)", on),
		Detail: "The pod uses the node's network namespace, so it has no interface for the CNI to enforce the policy on: " +
			"nodes, hostNetwork pods, external clients and any pod whose own egress allows it reach it.",
		Assumes: []string{
			"the CNI doesn't apply pod NetworkPolicy to the host network namespace — undefined by the spec; " +
				"measured on Calico and Cilium (host-level policy such as Calico HostEndpoints or Cilium host firewall is not read)",
			fmt.Sprintf("CNI %s", s.CNI.Name),
		},
		Verify: fmt.Sprintf("kubectl run fo-verify -n <ns-without-egress-policy> --rm -i --restart=Never "+
			"--image=registry.k8s.io/e2e-test-images/agnhost:2.53 -- connect %s:%s --timeout=3s", p.Status.HostIP, firstOr(ports, "<port>")),
	}
	if s.CNI.Name == "unknown" {
		f.Severity = SeverityWarning
		f.Assumes = append(f.Assumes, "CNI not recognised: assumes it enforces NetworkPolicy at all")
	}
	return f
}

// ingressPoliciesFor: the pod's namespace's policies that select it for ingress.
func ingressPoliciesFor(s *collector.Snapshot, p *corev1.Pod) []*networkingv1.NetworkPolicy {
	var out []*networkingv1.NetworkPolicy
	for i := range s.NetworkPolicies {
		np := &s.NetworkPolicies[i]
		if np.Namespace == p.Namespace && hasIngress(np) && selects(&np.Spec.PodSelector, p) {
			out = append(out, np)
		}
	}
	return out
}

// restrictedPorts lists the pod's TCP ports that the policies don't open to
// everyone; nil if every port is open to everyone. A pod that declares no
// ports gets an empty, non-nil list unless some rule opens all ports.
//
// "Everyone" is what reaches a node address: nodes, external clients and
// pods. A rule with no peers admits them all, and so does 0.0.0.0/0 with no
// excepts. namespaceSelector: {} admits every pod but no node or external
// client, so the port stays restricted — and the bypass real.
func restrictedPorts(p *corev1.Pod, pols []*networkingv1.NetworkPolicy) []string {
	openToAll := func(port int32, name string) bool {
		for _, np := range pols {
			for _, rule := range np.Spec.Ingress {
				if !portMatches(rule.Ports, port, name) {
					continue
				}
				if len(rule.From) == 0 {
					return true
				}
				for _, peer := range rule.From {
					if peer.IPBlock != nil && internetWide(peer.IPBlock) && len(peer.IPBlock.Except) == 0 {
						return true
					}
				}
			}
		}
		return false
	}
	var ports []string
	declared := false
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			if !isTCP(cp.Protocol) {
				continue
			}
			declared = true
			if !openToAll(cp.ContainerPort, cp.Name) {
				ports = append(ports, fmt.Sprint(cp.ContainerPort))
			}
		}
	}
	if declared {
		sort.Strings(ports)
		return ports // nil when every declared port is open to everyone
	}
	if openToAll(0, "") {
		return nil
	}
	return []string{}
}

func firstOr(ss []string, def string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return def
}
