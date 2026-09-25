package collector

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// k8sCollector is the client-go backed implementation of Collector.
type k8sCollector struct {
	client kubernetes.Interface
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
	return &k8sCollector{client: client}, nil
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
	// Fallback: in-cluster config (when the tool runs as a pod itself).
	return rest.InClusterConfig()
}

// Collect performs the five List calls and determines the CNI.
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
	s.CNI = cni

	return s, nil
}

// detectCNI applies the v1 heuristic: inspect DaemonSet names in kube-system.
func (c *k8sCollector) detectCNI(ctx context.Context) (CNIInfo, error) {
	dsList, err := c.client.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return CNIInfo{}, err
	}
	return classifyCNI(dsList.Items), nil
}

// classifyCNI is a pure function mapping a set of DaemonSets to a CNI.
// Kept separate from detectCNI so it can be tested without a cluster
// using fake DaemonSets.
func classifyCNI(daemonSets []appsv1.DaemonSet) CNIInfo {
	for _, ds := range daemonSets {
		switch ds.Name {
		case "calico-node":
			return CNIInfo{Name: "calico", EnforcesPolicy: true}
		case "cilium":
			return CNIInfo{Name: "cilium", EnforcesPolicy: true}
		case "kube-flannel-ds", "kube-flannel":
			return CNIInfo{Name: "flannel", EnforcesPolicy: false}
		}
	}
	return CNIInfo{Name: "unknown", EnforcesPolicy: false}
}
