package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// k8sCollector is the client-go backed implementation of Collector.
type k8sCollector struct {
	client  kubernetes.Interface
	dynamic dynamic.Interface // CNI CRDs (Calico IPPools)
}

// NewK8sCollector builds a client using the standard kubeconfig chain:
// --kubeconfig (explicitPath) → $KUBECONFIG → ~/.kube/config → in-cluster.
func NewK8sCollector(explicitPath string) (Collector, error) {
	config, err := buildConfig(explicitPath)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	return &k8sCollector{client: client, dynamic: dyn}, nil
}

// buildConfig resolves the kubeconfig, falling back to in-cluster config
// when running as a pod inside the cluster.
func buildConfig(explicitPath string) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if explicitPath != "" {
		rules.ExplicitPath = explicitPath
	}
	cfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules,
		&clientcmd.ConfigOverrides{},
	)
	restCfg, err := cfg.ClientConfig()
	if err == nil {
		return restCfg, nil
	}
	// An explicit --kubeconfig that fails to load is a user error; don't
	// mask it with an unrelated in-cluster message.
	if explicitPath != "" {
		return nil, err
	}
	// Fallback: in-cluster config (when the tool runs as a pod itself).
	if inCluster, icErr := rest.InClusterConfig(); icErr == nil {
		return inCluster, nil
	}
	return nil, err
}

// Collect performs the List calls and determines the CNI.
func (c *k8sCollector) Collect(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{}

	pods, err := c.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	s.Pods = pods.Items

	svcs, err := c.client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	s.Services = svcs.Items

	nps, err := c.client.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}
	s.NetworkPolicies = nps.Items

	nss, err := c.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	s.Namespaces = nss.Items

	nodes, err := c.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	s.Nodes = nodes.Items

	cni, err := c.detectCNI(ctx)
	if err != nil {
		return nil, fmt.Errorf("detect cni: %w", err)
	}
	if cni.Name == "unknown" {
		cni = classifyEmbeddedCNI(s.Nodes)
	}
	c.detectPodNetwork(ctx, &cni, s.Nodes)
	s.CNI = cni

	return s, nil
}

// detectCNI applies the v1 heuristic: inspect DaemonSet names across all
// namespaces. Modern installs don't live in kube-system: the official flannel
// manifest uses "kube-flannel", tigera-operator puts calico-node in
// "calico-system".
func (c *k8sCollector) detectCNI(ctx context.Context) (CNIInfo, error) {
	dsList, err := c.client.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return CNIInfo{}, err
	}
	return classifyCNI(dsList.Items), nil
}

// cniRules maps DaemonSet names to a CNI, in priority order. Enforcing CNIs
// come first: if a cluster runs both calico and flannel DaemonSets (e.g. a
// half-finished migration), policy IS enforced and we must not report flannel.
var cniRules = []struct {
	dsNames []string
	info    CNIInfo
}{
	{[]string{"cilium"}, CNIInfo{Name: "cilium", EnforcesPolicy: true}},
	{[]string{"calico-node"}, CNIInfo{Name: "calico", EnforcesPolicy: true}},
	// Canal = flannel networking + calico policy enforcement.
	{[]string{"canal"}, CNIInfo{Name: "canal", EnforcesPolicy: true}},
	// kind's default CNI; enforces NetworkPolicy since it bundled
	// kube-network-policies (kind v0.24+). Older kindnet did not.
	{[]string{"kindnet"}, CNIInfo{Name: "kindnet", EnforcesPolicy: true}},
	{[]string{"kube-flannel-ds", "kube-flannel"}, CNIInfo{Name: "flannel", EnforcesPolicy: false}},
}

// classifyCNI is a pure function mapping a set of DaemonSets to a CNI.
// Kept separate from detectCNI so it can be tested without a cluster
// using fake DaemonSets. The result does not depend on DaemonSet order.
func classifyCNI(daemonSets []appsv1.DaemonSet) CNIInfo {
	present := make(map[string]bool, len(daemonSets))
	for _, ds := range daemonSets {
		present[ds.Name] = true
	}
	for _, rule := range cniRules {
		for _, name := range rule.dsNames {
			if present[name] {
				return rule.info
			}
		}
	}
	return CNIInfo{Name: "unknown", EnforcesPolicy: false}
}

// Node annotations left by distributions that embed the CNI in their own
// binary, so there is no CNI DaemonSet to find.
const (
	annotationK3sNodeArgs      = "k3s.io/node-args"
	annotationFlannelBackend   = "flannel.alpha.coreos.com/backend-type"
	k3sDisableNetworkPolicyArg = "--disable-network-policy"
)

// classifyEmbeddedCNI recognises k3s: flannel for networking plus an
// embedded kube-router NetworkPolicy controller, which is on unless a
// server was started with --disable-network-policy.
func classifyEmbeddedCNI(nodes []corev1.Node) CNIInfo {
	k3s, enforces := false, true
	for _, n := range nodes {
		args, ok := n.Annotations[annotationK3sNodeArgs]
		if !ok {
			continue
		}
		k3s = true
		var argv []string
		if err := json.Unmarshal([]byte(args), &argv); err == nil && slices.Contains(argv, k3sDisableNetworkPolicyArg) {
			enforces = false
		}
	}
	if !k3s {
		return CNIInfo{Name: "unknown", EnforcesPolicy: false}
	}
	return CNIInfo{Name: "k3s", EnforcesPolicy: enforces}
}
