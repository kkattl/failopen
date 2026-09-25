package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

// systemNamespaces are kept in the snapshot next to the scenario's own
// namespaces: detectors must see realistic CNI/kube-system noise.
var systemNamespaces = regexp.MustCompile(`^(kube-.*|calico-.*|tigera-operator|cilium.*|local-path-storage)$`)

// source is a connection initiator.
type source struct {
	Name      string
	Kind      string
	Pod       *corev1.Pod // nil for external
	Container string      // exec target; empty for external
	IP        string      // identity for declared-verdict purposes
}

// target is an address to connect to, plus the pods that end up serving it.
type target struct {
	Name     string
	Kind     string
	Address  string
	Owner    *corev1.Pod // pod behind pod-ip/hostport/hostnetwork targets
	Backends []backend
}

type backend struct {
	Pod      *corev1.Pod
	Port     int
	PortName string
}

type pair struct{ src, tgt int }

func scenarioNamespaces(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := k8syaml.NewYAMLOrJSONDecoder(f, 4096)
	set := map[string]bool{}
	for {
		var obj struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := dec.Decode(&obj); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		switch {
		case obj.Kind == "Namespace":
			set[obj.Metadata.Name] = true
		case obj.Metadata.Namespace != "":
			set[obj.Metadata.Namespace] = true
		}
	}
	var out []string
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no namespaces found; scenario objects must set metadata.namespace")
	}
	return out, nil
}

// filterSnapshot drops namespaces that belong neither to this scenario nor
// to the system (leftovers of other scenarios, the oracle itself).
func filterSnapshot(s *collector.Snapshot, scenarioNS []string) *collector.Snapshot {
	keep := func(ns string) bool { return slices.Contains(scenarioNS, ns) || systemNamespaces.MatchString(ns) }
	out := &collector.Snapshot{Nodes: s.Nodes, CNI: s.CNI}
	for _, p := range s.Pods {
		if keep(p.Namespace) {
			out.Pods = append(out.Pods, p)
		}
	}
	for _, svc := range s.Services {
		if keep(svc.Namespace) {
			out.Services = append(out.Services, svc)
		}
	}
	for _, np := range s.NetworkPolicies {
		if keep(np.Namespace) {
			out.NetworkPolicies = append(out.NetworkPolicies, np)
		}
	}
	for _, ns := range s.Namespaces {
		if keep(ns.Name) {
			out.Namespaces = append(out.Namespaces, ns)
		}
	}
	return out
}

func isScenarioPod(p *corev1.Pod) bool {
	return !systemNamespaces.MatchString(p.Namespace) && p.Status.Phase == corev1.PodRunning
}

func buildSources(s *collector.Snapshot, agents oracleAgents) []source {
	var out []source
	for i := range s.Pods {
		p := &s.Pods[i]
		if !isScenarioPod(p) {
			continue
		}
		src := source{Name: p.Namespace + "/" + p.Name, Kind: scenario.SourcePod, Pod: p, Container: probeContainer, IP: p.Status.PodIP}
		if p.Spec.HostNetwork {
			src.Kind = scenario.SourceHostNetwork
			src.IP = p.Status.HostIP
		}
		out = append(out, src)
	}
	for _, a := range agents.nodes {
		out = append(out, source{Name: "node/" + a.Spec.NodeName, Kind: scenario.SourceNode, Pod: a, Container: "agnhost", IP: a.Status.HostIP})
	}
	out = append(out, source{Name: "outsider", Kind: scenario.SourceOutsider, Pod: agents.outsider, Container: "agnhost", IP: agents.outsider.Status.PodIP})
	out = append(out, source{Name: "external", Kind: scenario.SourceExternal})
	return out
}

func buildTargets(s *collector.Snapshot) []target {
	var out []target
	seen := map[string]bool{}
	add := func(t target) {
		if !seen[t.Address] {
			seen[t.Address] = true
			out = append(out, t)
		}
	}
	podTargets := func(p *corev1.Pod, port int, name string) {
		b := []backend{{Pod: p, Port: port, PortName: name}}
		id := p.Namespace + "/" + p.Name
		if p.Spec.HostNetwork {
			add(target{Name: id, Kind: scenario.TargetHostNetwork, Address: hostPort(p.Status.HostIP, port), Owner: p, Backends: b})
			return
		}
		add(target{Name: id, Kind: scenario.TargetPodIP, Address: hostPort(p.Status.PodIP, port), Owner: p, Backends: b})
	}

	for i := range s.Pods {
		p := &s.Pods[i]
		if !isScenarioPod(p) {
			continue
		}
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if !isTCP(cp.Protocol) {
					continue
				}
				podTargets(p, int(cp.ContainerPort), cp.Name)
				if cp.HostPort > 0 && !p.Spec.HostNetwork {
					add(target{Name: p.Namespace + "/" + p.Name, Kind: scenario.TargetHostPort,
						Address: hostPort(p.Status.HostIP, int(cp.HostPort)), Owner: p,
						Backends: []backend{{Pod: p, Port: int(cp.ContainerPort), PortName: cp.Name}}})
				}
			}
		}
	}

	var nodeIPs []string
	for _, n := range s.Nodes {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP {
				nodeIPs = append(nodeIPs, a.Address)
			}
		}
	}

	for _, svc := range s.Services {
		if systemNamespaces.MatchString(svc.Namespace) || len(svc.Spec.Selector) == 0 {
			continue // selector-less: no backends we can reason about
		}
		sel := labels.SelectorFromSet(svc.Spec.Selector)
		name := svc.Namespace + "/svc/" + svc.Name
		for _, sp := range svc.Spec.Ports {
			if !isTCP(sp.Protocol) {
				continue
			}
			var backends []backend
			for i := range s.Pods {
				p := &s.Pods[i]
				if p.Namespace != svc.Namespace || !isScenarioPod(p) || !sel.Matches(labels.Set(p.Labels)) {
					continue
				}
				port, portName, ok := resolveTargetPort(p, sp)
				if !ok {
					continue
				}
				backends = append(backends, backend{Pod: p, Port: port, PortName: portName})
				podTargets(p, port, portName) // pods may not declare containerPorts
			}
			if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != corev1.ClusterIPNone {
				add(target{Name: name, Kind: scenario.TargetClusterIP, Address: hostPort(svc.Spec.ClusterIP, int(sp.Port)), Backends: backends})
			}
			if sp.NodePort > 0 {
				for _, ip := range nodeIPs {
					add(target{Name: name, Kind: scenario.TargetNodePort, Address: hostPort(ip, int(sp.NodePort)), Backends: backends})
				}
			}
		}
	}
	return out
}

// resolveTargetPort maps a service port to a numeric pod port.
func resolveTargetPort(p *corev1.Pod, sp corev1.ServicePort) (int, string, bool) {
	tp := sp.TargetPort
	if tp.IntVal == 0 && tp.StrVal == "" {
		return int(sp.Port), "", true
	}
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			if (tp.StrVal != "" && cp.Name == tp.StrVal) || (tp.StrVal == "" && int(cp.ContainerPort) == int(tp.IntVal)) {
				return int(cp.ContainerPort), cp.Name, true
			}
		}
	}
	if tp.StrVal != "" {
		return 0, "", false // named port not found on this pod
	}
	return int(tp.IntVal), "", true
}

// applicable filters out meaningless pairs: self-connections, and
// cluster-internal addresses from outside the cluster.
func applicable(s source, t target) bool {
	if s.Kind == scenario.SourceExternal {
		return t.Kind == scenario.TargetNodePort || t.Kind == scenario.TargetHostPort || t.Kind == scenario.TargetHostNetwork
	}
	if s.Pod == nil {
		return true
	}
	if t.Owner != nil && t.Owner.UID == s.Pod.UID {
		return false
	}
	for _, b := range t.Backends {
		if b.Pod.UID == s.Pod.UID {
			return false // hairpin through a service to yourself
		}
	}
	return true
}

func isTCP(p corev1.Protocol) bool { return p == "" || p == corev1.ProtocolTCP }

func hostPort(ip string, port int) string { return ip + ":" + strconv.Itoa(port) }

func writeResults(dir string, snap *collector.Snapshot, reach *scenario.Reachability) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return err
	}
	defer f.Close()
	if err := collector.WriteJSON(f, snap); err != nil {
		return err
	}
	data, err := json.MarshalIndent(reach, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "reachability.json"), append(data, '\n'), 0o644)
}

func printSummary(r *scenario.Reachability) {
	counts := map[string]int{}
	for _, p := range r.Probes {
		counts[p.Verdict]++
	}
	fmt.Printf("\n%s: %d probes — match %d, bypass %d, overblock %d, unreachable %d, unknown %d\n",
		r.CNI, len(r.Probes), counts[scenario.VerdictMatch], counts[scenario.VerdictBypass],
		counts[scenario.VerdictOverblock], counts[scenario.VerdictUnreachable], counts[scenario.VerdictUnknown])
	for _, verdict := range []string{scenario.VerdictBypass, scenario.VerdictOverblock} {
		for _, p := range r.Probes {
			if p.Verdict == verdict {
				fmt.Printf("  %-9s %-40s -> %-40s %-11s %s (declared %s, got %s)\n",
					verdict, p.Source, p.Target, p.TargetKind, p.Address, p.Declared, p.Effective)
			}
		}
	}
}
