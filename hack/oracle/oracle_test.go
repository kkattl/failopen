package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

// Fixture: two nodes; "shop" namespace under default-deny ingress except an
// ipBlock "0.0.0.0/0 except 10.0.0.0/8" (internet, but not pods) on web.
//
//	node-a 172.18.0.2: web-1 (10.0.1.5, :8080), client (10.0.1.9)
//	node-b 172.18.0.3: web-2 (10.0.2.5, :8080), hostnet (hostNetwork, :9100)
//	svc web: NodePort 30080 -> targetPort "http"
func fixture() *collector.Snapshot {
	pod := func(name, node, ip string, hostNet bool, lbl map[string]string, ports ...corev1.ContainerPort) corev1.Pod {
		p := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", UID: types.UID(name), Labels: lbl},
			Spec: corev1.PodSpec{NodeName: node, HostNetwork: hostNet,
				Containers: []corev1.Container{{Name: "c", Ports: ports}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip, HostIP: map[string]string{"node-a": "172.18.0.2", "node-b": "172.18.0.3"}[node]},
		}
		if hostNet {
			p.Status.PodIP = p.Status.HostIP
		}
		return p
	}
	http := corev1.ContainerPort{Name: "http", ContainerPort: 8080}
	node := func(name, ip string) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}}}
	}
	return &collector.Snapshot{
		Nodes: []corev1.Node{node("node-a", "172.18.0.2"), node("node-b", "172.18.0.3")},
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "shop",
			Labels: map[string]string{"kubernetes.io/metadata.name": "shop"}}}},
		Pods: []corev1.Pod{
			pod("web-1", "node-a", "10.0.1.5", false, map[string]string{"app": "web"}, http),
			pod("web-2", "node-b", "10.0.2.5", false, map[string]string{"app": "web"}, http),
			pod("client", "node-a", "10.0.1.9", false, map[string]string{"app": "client"}),
			pod("hostnet", "node-b", "", true, map[string]string{"app": "agent"}, corev1.ContainerPort{ContainerPort: 9100}),
		},
		Services: []corev1.Service{{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop", UID: "svc-web"},
			Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeNodePort, ClusterIP: "10.96.0.10",
				Selector: map[string]string{"app": "web"},
				Ports:    []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromString("http"), NodePort: 30080}}},
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "web-from-internet", Namespace: "shop"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8"}},
				}}}},
			},
		}},
	}
}

func findTarget(t *testing.T, ts []target, kind, addr string) target {
	t.Helper()
	for _, x := range ts {
		if x.Kind == kind && x.Address == addr {
			return x
		}
	}
	t.Fatalf("no %s target %s in %d targets", kind, addr, len(ts))
	return target{}
}

func podSource(s *collector.Snapshot, name string) source {
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Name == name {
			if p.Spec.HostNetwork {
				return source{Name: "shop/" + name, Kind: scenario.SourceHostNetwork, Pod: p, IP: p.Status.HostIP}
			}
			return source{Name: "shop/" + name, Kind: scenario.SourcePod, Pod: p, IP: p.Status.PodIP}
		}
	}
	panic(name)
}

func nodeSource(name, ip string) source {
	return source{Name: "node/" + name, Kind: scenario.SourceNode, IP: ip,
		Pod: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("agent-" + name)}, Spec: corev1.PodSpec{NodeName: name}}}
}

func TestBuildTargets(t *testing.T) {
	ts := buildTargets(fixture())
	findTarget(t, ts, scenario.TargetPodIP, "10.0.1.5:8080")
	findTarget(t, ts, scenario.TargetPodIP, "10.0.2.5:8080")
	findTarget(t, ts, scenario.TargetHostNetwork, "172.18.0.3:9100")
	c := findTarget(t, ts, scenario.TargetClusterIP, "10.96.0.10:80")
	if len(c.Backends) != 2 || c.Backends[0].Port != 8080 || c.Backends[0].PortName != "http" {
		t.Errorf("clusterip backends = %+v, want both web pods on named port http/8080", c.Backends)
	}
	np := findTarget(t, ts, scenario.TargetNodePort, "172.18.0.3:30080")
	if np.Node != "node-b" || np.ServicePort != 80 {
		t.Errorf("nodeport target = node %q port %d", np.Node, np.ServicePort)
	}
}

func TestApplicable(t *testing.T) {
	s := fixture()
	ts := buildTargets(s)
	web1 := podSource(s, "web-1")
	if applicable(web1, findTarget(t, ts, scenario.TargetPodIP, "10.0.1.5:8080")) {
		t.Error("a pod probing itself must be skipped")
	}
	if applicable(web1, findTarget(t, ts, scenario.TargetClusterIP, "10.96.0.10:80")) {
		t.Error("hairpin through a Service to yourself must be skipped")
	}
	ext := source{Kind: scenario.SourceExternal}
	if applicable(ext, findTarget(t, ts, scenario.TargetClusterIP, "10.96.0.10:80")) {
		t.Error("external must not probe cluster-internal addresses")
	}
	if !applicable(ext, findTarget(t, ts, scenario.TargetNodePort, "172.18.0.2:30080")) {
		t.Error("external must probe NodePorts")
	}
}

func TestResolveTargetPort(t *testing.T) {
	p := &fixture().Pods[0]
	for _, tt := range []struct {
		tp       intstr.IntOrString
		wantPort int
		wantOK   bool
	}{
		{intstr.FromString("http"), 8080, true},
		{intstr.FromString("nope"), 0, false},
		{intstr.FromInt32(9000), 9000, true}, // numeric, not declared: still valid
		{intstr.IntOrString{}, 80, true},     // unset: defaults to port
	} {
		port, _, ok := resolveTargetPort(p, corev1.ServicePort{Port: 80, TargetPort: tt.tp})
		if port != tt.wantPort || ok != tt.wantOK {
			t.Errorf("targetPort %v: got %d %t, want %d %t", tt.tp, port, ok, tt.wantPort, tt.wantOK)
		}
	}
}

func TestBasisFor(t *testing.T) {
	s := fixture()
	ts := buildTargets(s)
	web1IP := findTarget(t, ts, scenario.TargetPodIP, "10.0.1.5:8080")
	svc := findTarget(t, ts, scenario.TargetClusterIP, "10.96.0.10:80")
	npB := findTarget(t, ts, scenario.TargetNodePort, "172.18.0.3:30080")
	hn := findTarget(t, ts, scenario.TargetHostNetwork, "172.18.0.3:9100")
	client := podSource(s, "client")
	nodeA := nodeSource("node-a", "172.18.0.2")
	nodeB := nodeSource("node-b", "172.18.0.3")

	tests := []struct {
		name     string
		src      source
		tgt      target
		observed []string
		want     string
	}{
		{"hostNetwork target is undefined", client, hn, []string{"10.0.1.9"}, scenario.BasisUndefined},
		{"pod arrives unchanged", client, web1IP, []string{"10.0.1.9"}, scenario.BasisPolicy},
		{"pod via NodePort arrives as a node IP", client, npB, []string{"172.18.0.2"}, scenario.BasisSNAT},
		{"node to a pod on its own node", nodeA, web1IP, []string{"172.18.0.2"}, scenario.BasisSpecException},
		{"node to a remote pod via tunnel address", nodeB, web1IP, []string{"10.0.2.1"}, scenario.BasisSNAT},
		{"node to a remote pod, node IP preserved", nodeB, web1IP, []string{"172.18.0.3"}, scenario.BasisPolicy},
		{"node to its own NodePort, backend local (web-1 not on node-b) -> mixed", nodeB, npB, []string{"172.18.0.3", "10.0.2.1"}, scenario.BasisMixedPath},
		{"node to ANOTHER node's NodePort arrives from that node", nodeA, npB, []string{"10.0.2.1"}, scenario.BasisSNAT},
		{"node to a Service with one local, one remote backend", nodeA, svc, []string{"172.18.0.2", "10.0.1.1"}, scenario.BasisMixedPath},
		{"attempts saw both unchanged and rewritten", client, svc, []string{"10.0.1.9", "172.18.0.2"}, scenario.BasisMixedPath},
		{"nothing observed falls back to policy", client, npB, nil, scenario.BasisPolicy},
	}
	for _, tt := range tests {
		if got := basisFor(tt.src, tt.tgt, tt.observed); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

// The SNAT class end to end: "internet but not pods" admits a pod whose
// traffic was rewritten to a node IP.
func TestDeclaredIntendedVsObserved(t *testing.T) {
	s := fixture()
	ts := buildTargets(s)
	dc := newDeclaredCalc(s, "203.0.113.10")
	client := podSource(s, "client")
	np := findTarget(t, ts, scenario.TargetNodePort, "172.18.0.3:30080")

	if got := dc.intended(client, np); got != scenario.DeclaredDeny {
		t.Errorf("intended: pod 10.0.1.9 is inside the excepted 10/8: got %s, want deny", got)
	}
	if got := dc.observed([]string{"172.18.0.2"}, np); got != scenario.DeclaredAllow {
		t.Errorf("observed: node IP is outside the except: got %s, want allow", got)
	}
	ext := source{Kind: scenario.SourceExternal}
	if got := dc.intended(ext, np); got != scenario.DeclaredAllow {
		t.Errorf("external client: got %s, want allow", got)
	}
	// An observed pod IP maps back to the pod's labels.
	if got := dc.observed([]string{"10.0.1.9"}, np); got != scenario.DeclaredDeny {
		t.Errorf("observed pod IP: got %s, want deny", got)
	}
	if got := aggregate([]string{scenario.DeclaredAllow, scenario.DeclaredDeny}); got != scenario.DeclaredMixed {
		t.Errorf("aggregate allow+deny = %s, want mixed", got)
	}
}

func TestIdentityAddress(t *testing.T) {
	s := fixture()
	ts := buildTargets(s)
	ports := identityPorts(s)
	shadows := map[types.UID]shadow{"svc-web": {clusterIP: "10.96.0.99", nodePorts: map[int32]int32{80: 31999}}}
	for _, tt := range []struct {
		kind, addr, want string
	}{
		{scenario.TargetPodIP, "10.0.1.5:8080", "10.0.1.5:39999"},
		{scenario.TargetHostNetwork, "172.18.0.3:9100", "172.18.0.3:39000"},
		{scenario.TargetClusterIP, "10.96.0.10:80", "10.96.0.99:80"},
		{scenario.TargetNodePort, "172.18.0.2:30080", "172.18.0.2:31999"},
	} {
		if got := identityAddress(findTarget(t, ts, tt.kind, tt.addr), ports, shadows); got != tt.want {
			t.Errorf("%s %s: identity address %s, want %s", tt.kind, tt.addr, got, tt.want)
		}
	}
}

func TestParseClientIP(t *testing.T) {
	for in, want := range map[string]string{"10.0.1.9:43210": "10.0.1.9", "FAIL": "", "": "", "garbage": ""} {
		got, ok := parseClientIP(in)
		if got != want || ok != (want != "") {
			t.Errorf("parseClientIP(%q) = %q %t", in, got, ok)
		}
	}
}

func TestClassifyOutput(t *testing.T) {
	for in, want := range map[string]string{
		"OPEN": scenario.EffectiveOpen, "REFUSED": scenario.EffectiveRefused,
		"TIMEOUT": scenario.EffectiveTimeout, "DNS": scenario.EffectiveError, "": scenario.EffectiveError,
	} {
		if got := classifyOutput(in); got != want {
			t.Errorf("classifyOutput(%q) = %s, want %s", in, got, want)
		}
	}
}
