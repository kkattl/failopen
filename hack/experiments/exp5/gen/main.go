// Command gen writes a deterministic synthetic cluster snapshot of N pods for
// the performance experiment (Experiment 5). Objects are modelled on the
// measured calico snapshots in testdata/scenarios and scale with N:
//
//	namespaces       ~N/50   (plus kube-system, calico-system)
//	services         ~N/5    (one per app: ~88% ClusterIP, ~10% NodePort, ~2% LoadBalancer)
//	NetworkPolicies  ~N/10   (default-deny, DNS egress, podSelector / namespaceSelector
//	                          allows, ipBlock rules: 0.0.0.0/0-except-podCIDR,
//	                          ranges covering the node IPs, external-only ranges,
//	                          ranges admitting the pod CIDR)
//	nodes            ~N/30   (InternalIP in 10.0.0.0/16)
//	hostPort pods    ~1% of app pods
//	hostNetwork pods 3 per 10 team namespaces (a node agent under default-deny),
//	                 plus calico-node per node (system, skipped by detectors)
//
//	go run ./hack/experiments/exp5/gen -pods 1000 -seed 1 -o snap-1000.json
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kkattl/failopen/internal/collector"
)

const (
	podCIDR    = "10.112.0.0/12" // calico IPPool; big enough for 50k+ pods
	nodeSubnet = "10.0.0.0/16"   // node InternalIPs live here
)

type gen struct {
	rng *rand.Rand
	ts  metav1.Time
	rv  int
}

func (g *gen) uid() types.UID {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(g.rng.IntN(256))
	}
	return types.UID(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

func (g *gen) hex(n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[g.rng.IntN(16)]
	}
	return string(b)
}

func (g *gen) meta(name, ns string, lbls map[string]string) metav1.ObjectMeta {
	g.rv++
	return metav1.ObjectMeta{
		Name: name, Namespace: ns, UID: g.uid(),
		ResourceVersion:   fmt.Sprint(g.rv),
		CreationTimestamp: g.ts,
		Labels:            lbls,
	}
}

type app struct {
	name, ns, team string
	replicas       int
	svcType        corev1.ServiceType
	hostPort       bool
	namedTarget    bool
}

func main() {
	pods := flag.Int("pods", 1000, "number of pods")
	seed := flag.Uint64("seed", 1, "random seed")
	out := flag.String("o", "-", "output file (- for stdout)")
	flag.Parse()

	s := generate(*pods, *seed)
	w := os.Stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	if err := collector.WriteJSON(bw, s); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := bw.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "gen: %d pods, %d services, %d policies, %d namespaces, %d nodes\n",
		len(s.Pods), len(s.Services), len(s.NetworkPolicies), len(s.Namespaces), len(s.Nodes))
}

func generate(nPods int, seed uint64) *collector.Snapshot {
	g := &gen{rng: rand.New(rand.NewPCG(seed, 0x5eed)), ts: metav1.NewTime(time.Date(2026, 9, 24, 14, 0, 0, 0, time.UTC))}
	s := &collector.Snapshot{CNI: collector.CNIInfo{
		Name: "calico", EnforcesPolicy: true, PodCIDRs: []string{podCIDR},
		Encapsulation: collector.EncapIPIP, PodCIDRSource: collector.SourceCalicoIPPool,
	}}

	// --- nodes ---
	nNodes := max(3, nPods/30)
	for i := range nNodes {
		name := fmt.Sprintf("node-%04d", i)
		ip := fmt.Sprintf("10.0.%d.%d", (i+2)/250, (i+2)%250+1)
		cap := corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("16"),
			corev1.ResourceMemory: resource.MustParse("65842428Ki"),
			corev1.ResourcePods:   resource.MustParse("110"),
		}
		s.Nodes = append(s.Nodes, corev1.Node{
			ObjectMeta: func() metav1.ObjectMeta {
				m := g.meta(name, "", map[string]string{
					"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux",
					"kubernetes.io/hostname":      name,
					"topology.kubernetes.io/zone": fmt.Sprintf("zone-%c", 'a'+i%3),
					"pool":                        []string{"general", "general", "edge", "data"}[i%4],
				})
				m.Annotations = map[string]string{
					"projectcalico.org/IPv4Address":        ip + "/16",
					"projectcalico.org/IPv4IPIPTunnelAddr": fmt.Sprintf("10.%d.%d.0", 112+i/256, i%256),
				}
				return m
			}(),
			Spec: corev1.NodeSpec{PodCIDR: fmt.Sprintf("10.%d.%d.0/24", 112+i/256, i%256)},
			Status: corev1.NodeStatus{
				Capacity: cap, Allocatable: cap,
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: ip},
					{Type: corev1.NodeHostName, Address: name},
				},
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionFalse, Reason: "CalicoIsUp", LastTransitionTime: g.ts, LastHeartbeatTime: g.ts},
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady", LastTransitionTime: g.ts, LastHeartbeatTime: g.ts},
				},
				NodeInfo: corev1.NodeSystemInfo{KubeletVersion: "v1.37.0", ContainerRuntimeVersion: "containerd://2.1.4", OperatingSystem: "linux", Architecture: "amd64"},
			},
		})
	}
	nodeIP := func(i int) string { return s.Nodes[i%nNodes].Status.Addresses[0].Address }

	podSeq := 0
	podIP := func() string {
		podSeq++
		return fmt.Sprintf("10.%d.%d.%d", 112+podSeq/65536, (podSeq/256)%256, podSeq%256)
	}

	// --- system namespaces: calico-node per node (hostNetwork), coredns ---
	for _, ns := range []string{"kube-system", "calico-system"} {
		s.Namespaces = append(s.Namespaces, corev1.Namespace{
			ObjectMeta: g.meta(ns, "", map[string]string{"kubernetes.io/metadata.name": ns}),
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		})
	}
	for i := range nNodes {
		p := g.pod("calico-node", "calico-system", map[string]string{"k8s-app": "calico-node"}, "DaemonSet", "calico-node", nodeIP(i), s.Nodes[i].Name, nodeIP(i), 9099, "", 0)
		p.Spec.HostNetwork = true
		s.Pods = append(s.Pods, p)
	}
	for i := range 2 {
		s.Pods = append(s.Pods, g.pod("coredns", "kube-system", map[string]string{"k8s-app": "kube-dns"}, "ReplicaSet", "coredns-668d6bf9bc", nodeIP(i), s.Nodes[i].Name, podIP(), 53, "dns-tcp", 0))
	}
	s.Services = append(s.Services, corev1.Service{
		ObjectMeta: g.meta("kube-dns", "kube-system", map[string]string{"k8s-app": "kube-dns"}),
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.96.0.10", Selector: map[string]string{"k8s-app": "kube-dns"},
			Ports: []corev1.ServicePort{
				{Name: "dns", Protocol: corev1.ProtocolUDP, Port: 53, TargetPort: intstr.FromInt32(53)},
				{Name: "dns-tcp", Protocol: corev1.ProtocolTCP, Port: 53, TargetPort: intstr.FromInt32(53)},
			},
		},
	})

	// --- application namespaces and apps ---
	appPods := max(nPods-len(s.Pods), 10)
	nNS := max(2, nPods/50)
	nApps := max(nNS, appPods/5) // => services ~N/5
	apps := make([][]app, nNS)
	for a := range nApps {
		ns := a % nNS
		x := app{
			name: fmt.Sprintf("svc-%05d", a), ns: fmt.Sprintf("team-%04d", ns), team: fmt.Sprintf("t%d", ns%40),
			replicas: 5, svcType: corev1.ServiceTypeClusterIP, namedTarget: g.rng.IntN(2) == 0,
		}
		switch r := g.rng.IntN(100); {
		case r < 2:
			x.svcType = corev1.ServiceTypeLoadBalancer
		case r < 12:
			x.svcType = corev1.ServiceTypeNodePort
		}
		apps[ns] = append(apps[ns], x)
	}
	// Spread exactly appPods pods over the apps, 1..9 replicas, mean 5.
	left := appPods
	for ns := range apps {
		for i := range apps[ns] {
			apps[ns][i].replicas = 1
			left--
		}
	}
	for left > 0 {
		ns := g.rng.IntN(nNS)
		i := g.rng.IntN(len(apps[ns]))
		if apps[ns][i].replicas < 9 {
			apps[ns][i].replicas++
			left--
		}
	}
	// ~1% of app pods carry a hostPort: mark some apps (their pods all have it).
	hostPodsWanted := appPods / 100
	for hostPodsWanted > 0 {
		ns := g.rng.IntN(nNS)
		i := g.rng.IntN(len(apps[ns]))
		if !apps[ns][i].hostPort {
			apps[ns][i].hostPort = true
			hostPodsWanted -= apps[ns][i].replicas
		}
	}

	npSeq := 0
	nPolicies := max(1, nPods/10)
	nodePortSeq := 30000
	for ns := range apps {
		nsName := fmt.Sprintf("team-%04d", ns)
		s.Namespaces = append(s.Namespaces, corev1.Namespace{
			ObjectMeta: g.meta(nsName, "", map[string]string{
				"kubernetes.io/metadata.name": nsName, "team": fmt.Sprintf("t%d", ns%40),
				"env": []string{"prod", "staging", "dev"}[ns%3], "pod-security.kubernetes.io/enforce": "restricted",
			}),
			Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		})
		for _, a := range apps[ns] {
			hash := g.hex(10)
			lbls := map[string]string{"app": a.name, "team": a.team, "tier": []string{"frontend", "backend", "data"}[g.rng.IntN(3)], "pod-template-hash": hash}
			for r := range a.replicas {
				ni := g.rng.IntN(nNodes)
				hp := int32(0)
				if a.hostPort {
					hp = 9100
				}
				p := g.pod(a.name, nsName, copyMap(lbls), "ReplicaSet", a.name+"-"+hash, nodeIP(ni), s.Nodes[ni].Name, podIP(), 8080, "http", hp)
				_ = r
				s.Pods = append(s.Pods, p)
			}
			svc := corev1.Service{
				ObjectMeta: g.meta(a.name, nsName, map[string]string{"app": a.name}),
				Spec: corev1.ServiceSpec{
					Type: a.svcType, Selector: map[string]string{"app": a.name},
					ClusterIP: fmt.Sprintf("10.96.%d.%d", (len(s.Services)/250)%256, len(s.Services)%250+1),
					Ports: []corev1.ServicePort{
						{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt32(8080)},
						{Name: "metrics", Protocol: corev1.ProtocolTCP, Port: 9090, TargetPort: intstr.FromInt32(9090)},
					},
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			}
			if a.namedTarget {
				svc.Spec.Ports[0].TargetPort = intstr.FromString("http")
			}
			if a.svcType != corev1.ServiceTypeClusterIP {
				svc.Spec.Ports[0].NodePort = int32(nodePortSeq)
				nodePortSeq = 30000 + (nodePortSeq-30000+1)%2768
				svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyCluster
			}
			if a.svcType == corev1.ServiceTypeLoadBalancer {
				svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: fmt.Sprintf("203.0.113.%d", g.rng.IntN(254)+1)}}
			}
			s.Services = append(s.Services, svc)
		}

		// Policies: ~5 per namespace => ~N/10 in total.
		quota := nPolicies / nNS
		if ns < nPolicies%nNS {
			quota++
		}
		add := func(np networkingv1.NetworkPolicy) bool {
			if quota == 0 {
				return false
			}
			quota--
			npSeq++
			s.NetworkPolicies = append(s.NetworkPolicies, np)
			return true
		}
		add(g.policy("default-deny-ingress", nsName, metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, nil, nil))
		add(g.policy("allow-dns-egress", nsName, metav1.LabelSelector{}, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, nil,
			[]networkingv1.NetworkPolicyEgressRule{{
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(53, corev1.ProtocolUDP), tcpPort(53, corev1.ProtocolTCP)},
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				}},
			}}))
		// Exposed apps (NodePort / LB / hostPort) first: they get the ipBlock rules.
		ordered := make([]app, 0, len(apps[ns]))
		for _, a := range apps[ns] {
			if a.svcType != corev1.ServiceTypeClusterIP || a.hostPort {
				ordered = append(ordered, a)
			}
		}
		for _, a := range apps[ns] {
			if a.svcType == corev1.ServiceTypeClusterIP && !a.hostPort {
				ordered = append(ordered, a)
			}
		}
		for _, a := range ordered {
			sel := metav1.LabelSelector{MatchLabels: map[string]string{"app": a.name}}
			var from []networkingv1.NetworkPolicyPeer
			ports := []networkingv1.NetworkPolicyPort{tcpPort(8080, corev1.ProtocolTCP)}
			if a.hostPort {
				ports = append(ports, tcpPort(9100, corev1.ProtocolTCP))
			}
			exposed := a.svcType != corev1.ServiceTypeClusterIP || a.hostPort
			kind := g.rng.IntN(100)
			switch {
			case exposed && kind < 35: // closed allowlist that covers the nodes: critical
				from = []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: []string{"10.0.0.0/16", "10.0.0.0/20", "10.0.0.0/17"}[g.rng.IntN(3)]}}}
			case exposed && kind < 65: // "anything but pods": warning
				from = []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: []string{podCIDR}}}}
			case exposed && kind < 80: // external-only range, no node IPs: no finding
				from = []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "198.51.100.0/24"}}}
			case exposed && kind < 90: // admits the pod CIDR on purpose: no finding
				from = []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}}}
			case kind < 50: // same-namespace podSelector allow
				from = []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
				}}}}
			default: // cross-namespace allow by team label
				from = []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": a.team}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
				}}
			}
			ok := add(g.policy(a.name+"-ingress", nsName, sel, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				[]networkingv1.NetworkPolicyIngressRule{{Ports: ports, From: from}}, nil))
			if !ok {
				break
			}
		}
	}
	// Distribute any policy quota left over (namespaces with few apps) to the
	// largest namespaces as extra monitoring allows, so the total stays ~N/10.
	for i := 0; len(s.NetworkPolicies) < nPolicies; i++ {
		nsName := fmt.Sprintf("team-%04d", i%nNS)
		s.NetworkPolicies = append(s.NetworkPolicies, g.policy(fmt.Sprintf("allow-prometheus-%d", i), nsName, metav1.LabelSelector{},
			[]networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			[]networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{tcpPort(9090, corev1.ProtocolTCP)},
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "monitoring"}},
				}},
			}}, nil))
	}

	// --- non-system hostNetwork agents: one 3-node DaemonSet in every 10th
	// team namespace, under that namespace's default-deny, so that
	// hostnetwork-under-policy has real work (system hostNetwork pods above
	// are skipped by it).
	for ns := 0; ns < nNS; ns += 10 {
		nsName := fmt.Sprintf("team-%04d", ns)
		for i := range min(3, nNodes) {
			n := (ns + i) % nNodes
			p := g.pod("node-agent", nsName, map[string]string{"app": "node-agent"}, "DaemonSet", "node-agent", nodeIP(n), s.Nodes[n].Name, nodeIP(n), 9100, "metrics", 0)
			p.Spec.HostNetwork = true
			s.Pods = append(s.Pods, p)
		}
	}
	return s
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func tcpPort(p int32, proto corev1.Protocol) networkingv1.NetworkPolicyPort {
	pr := proto
	port := intstr.FromInt32(p)
	return networkingv1.NetworkPolicyPort{Protocol: &pr, Port: &port}
}

func (g *gen) policy(name, ns string, sel metav1.LabelSelector, types []networkingv1.PolicyType,
	in []networkingv1.NetworkPolicyIngressRule, eg []networkingv1.NetworkPolicyEgressRule) networkingv1.NetworkPolicy {
	m := g.meta(name, ns, nil)
	m.Generation = 1
	return networkingv1.NetworkPolicy{
		ObjectMeta: m,
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: sel, PolicyTypes: types, Ingress: in, Egress: eg},
	}
}

// pod builds a pod shaped like the measured lab pods (agnhost, probes,
// security context, full status), so JSON size per pod is realistic.
func (g *gen) pod(app, ns string, lbls map[string]string, ownerKind, ownerName, hostIP, nodeName, ip string, port int32, portName string, hostPort int32) corev1.Pod {
	name := ownerName + "-" + g.hex(5)
	m := g.meta(name, ns, lbls)
	m.GenerateName = ownerName + "-"
	m.Generation = 1
	m.Annotations = map[string]string{
		"cni.projectcalico.org/containerID": g.hex(64),
		"cni.projectcalico.org/podIP":       ip + "/32",
		"cni.projectcalico.org/podIPs":      ip + "/32",
	}
	t := true
	m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: ownerKind, Name: ownerName, UID: g.uid(), Controller: &t, BlockOwnerDeletion: &t}}
	probe := func(period int32) *corev1.Probe {
		return &corev1.Probe{
			ProbeHandler:   corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(port), Scheme: corev1.URISchemeHTTP}},
			TimeoutSeconds: 1, PeriodSeconds: period, SuccessThreshold: 1, FailureThreshold: 3,
		}
	}
	ports := []corev1.ContainerPort{{Name: portName, ContainerPort: port, Protocol: corev1.ProtocolTCP}}
	if hostPort != 0 {
		ports = append(ports, corev1.ContainerPort{Name: "node-metrics", ContainerPort: 9100, HostPort: hostPort, Protocol: corev1.ProtocolTCP})
	}
	if portName == "http" {
		ports = append(ports, corev1.ContainerPort{Name: "metrics", ContainerPort: 9090, Protocol: corev1.ProtocolTCP})
	}
	res := corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")},
		Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
	}
	f := false
	nonRoot := true
	uid := int64(65534)
	grace := int64(30)
	img := "registry.k8s.io/e2e-test-images/agnhost:2.53"
	cond := func(t corev1.PodConditionType) corev1.PodCondition {
		return corev1.PodCondition{Type: t, Status: corev1.ConditionTrue, LastTransitionTime: g.ts, ObservedGeneration: 1}
	}
	return corev1.Pod{
		ObjectMeta: m,
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app", Image: img, Args: []string{"netexec", fmt.Sprintf("--http-port=%d", port)},
				Ports: ports, Resources: res, LivenessProbe: probe(10), ReadinessProbe: probe(5),
				TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: corev1.TerminationMessageReadFile,
				ImagePullPolicy: corev1.PullIfNotPresent,
				SecurityContext: &corev1.SecurityContext{
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					ReadOnlyRootFilesystem:   &nonRoot,
					AllowPrivilegeEscalation: &f,
				},
			}},
			RestartPolicy: corev1.RestartPolicyAlways, TerminationGracePeriodSeconds: &grace,
			DNSPolicy: corev1.DNSClusterFirst, ServiceAccountName: "default", AutomountServiceAccountToken: &f,
			NodeName: nodeName, SchedulerName: "default-scheduler",
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: &uid, RunAsGroup: &uid, RunAsNonRoot: &nonRoot,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Tolerations: []corev1.Toleration{
				{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
				{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
			},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{cond(corev1.PodInitialized), cond(corev1.PodReady), cond(corev1.ContainersReady), cond(corev1.PodScheduled)},
			HostIP:     hostIP, HostIPs: []corev1.HostIP{{IP: hostIP}},
			PodIP: ip, PodIPs: []corev1.PodIP{{IP: ip}},
			StartTime: &g.ts,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", Ready: true, Image: img,
				State:       corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: g.ts}},
				ImageID:     "registry.k8s.io/e2e-test-images/agnhost@sha256:" + g.hex(64),
				ContainerID: "containerd://" + g.hex(64),
			}},
			QOSClass: corev1.PodQOSBurstable,
		},
	}
}
