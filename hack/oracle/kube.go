package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"
)

const (
	oracleNS     = "failopen-oracle"
	agnhostImage = "registry.k8s.io/e2e-test-images/agnhost:2.53"
)

// probeContainer is this run's ephemeral container name. Unique per run:
// ephemeral containers can't be restarted or removed, so a container that
// died in an earlier run (e.g. OOM) must not be reused.
var probeContainer = "failopen-oracle-" + strconv.FormatInt(time.Now().Unix(), 36)

type kube struct {
	cs  kubernetes.Interface
	cfg *rest.Config
}

type oracleAgents struct {
	nodes    []*corev1.Pod // hostNetwork agent per node
	outsider *corev1.Pod
}

func newKube(kubeconfig string) (*kube, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}
	cfg.QPS, cfg.Burst = 50, 100
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &kube{cs: cs, cfg: cfg}, nil
}

// waitScenarioReady waits until every scenario pod is Ready (or finished).
func (k *kube) waitScenarioReady(ctx context.Context, namespaces []string, timeout time.Duration) error {
	var notReady []string
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		notReady = nil
		for _, ns := range namespaces {
			pods, err := k.cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				return false, err
			}
			for _, p := range pods.Items {
				if p.Status.Phase == corev1.PodSucceeded {
					continue
				}
				if !podReady(&p) {
					notReady = append(notReady, ns+"/"+p.Name)
				}
			}
		}
		return len(notReady) == 0, nil
	})
	if err != nil {
		return fmt.Errorf("scenario pods not ready: %v: %w", notReady, err)
	}
	return nil
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func agnhostContainer(args ...string) corev1.Container {
	return corev1.Container{Name: "agnhost", Image: agnhostImage, Args: args}
}

// setupOracle creates the oracle namespace: a hostNetwork agent on every
// node (the "node" source) and an unlabelled pod (the "outsider" source).
func (k *kube) setupOracle(ctx context.Context) (oracleAgents, error) {
	var agents oracleAgents
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: oracleNS,
		Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}}}
	if _, err := k.cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return agents, err
	}
	agentLabels := map[string]string{"app": "node-agent"}
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: oracleNS},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: agentLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: agentLabels},
				Spec: corev1.PodSpec{
					HostNetwork: true,
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
					Containers:  []corev1.Container{agnhostContainer("pause")},
				},
			},
		},
	}
	if _, err := k.cs.AppsV1().DaemonSets(oracleNS).Create(ctx, ds, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return agents, err
	}
	outsider := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "outsider", Namespace: oracleNS},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{agnhostContainer("pause")}},
	}
	if _, err := k.cs.CoreV1().Pods(oracleNS).Create(ctx, outsider, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return agents, err
	}

	nodes, err := k.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return agents, err
	}
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		pods, err := k.cs.CoreV1().Pods(oracleNS).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		agents = oracleAgents{}
		for i := range pods.Items {
			p := &pods.Items[i]
			if !podReady(p) {
				return false, nil
			}
			if p.Name == "outsider" {
				agents.outsider = p
			} else {
				agents.nodes = append(agents.nodes, p)
			}
		}
		return agents.outsider != nil && len(agents.nodes) == len(nodes.Items), nil
	})
	if err != nil {
		return agents, fmt.Errorf("oracle pods not ready: %w", err)
	}
	return agents, nil
}

func (k *kube) teardownOracle(ctx context.Context) {
	_ = k.cs.CoreV1().Namespaces().Delete(ctx, oracleNS, metav1.DeleteOptions{})
}

// injectProbes adds an agnhost ephemeral container to every scenario pod
// source, so probes originate from the pod's real network identity.
// The security context satisfies the "restricted" Pod Security profile.
func (k *kube) injectProbes(ctx context.Context, sources []source) error {
	for _, s := range sources {
		if s.Pod == nil || s.Container != probeContainer {
			continue
		}
		pod, err := k.cs.CoreV1().Pods(s.Pod.Namespace).Get(ctx, s.Pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(pod.Spec.EphemeralContainers, func(c corev1.EphemeralContainer) bool { return c.Name == probeContainer }) {
			pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, corev1.EphemeralContainer{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  probeContainer,
					Image: agnhostImage,
					Args:  []string{"pause"},
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             ptr.To(true),
						RunAsUser:                ptr.To[int64](65534),
						AllowPrivilegeEscalation: ptr.To(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
				},
			})
			if _, err := k.cs.CoreV1().Pods(pod.Namespace).UpdateEphemeralContainers(ctx, pod.Name, pod, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("%s/%s: %w", pod.Namespace, pod.Name, err)
			}
		}
	}
	for _, s := range sources {
		if s.Pod == nil || s.Container != probeContainer {
			continue
		}
		err := wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
			pod, err := k.cs.CoreV1().Pods(s.Pod.Namespace).Get(ctx, s.Pod.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			for _, st := range pod.Status.EphemeralContainerStatuses {
				if st.Name == probeContainer && st.State.Running != nil {
					return true, nil
				}
			}
			return false, nil
		})
		if err != nil {
			return fmt.Errorf("%s: probe container not running: %w", s.Name, err)
		}
	}
	return nil
}

// removePolicies deletes the scenario's NetworkPolicies and returns a
// function that recreates them.
func (k *kube) removePolicies(ctx context.Context, namespaces []string) (func(context.Context) error, error) {
	var saved []networkingv1.NetworkPolicy
	for _, ns := range namespaces {
		list, err := k.cs.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		saved = append(saved, list.Items...)
	}
	for _, np := range saved {
		if err := k.cs.NetworkingV1().NetworkPolicies(np.Namespace).Delete(ctx, np.Name, metav1.DeleteOptions{}); err != nil {
			return nil, err
		}
	}
	return func(ctx context.Context) error {
		for _, np := range saved {
			np.ObjectMeta = metav1.ObjectMeta{Name: np.Name, Namespace: np.Namespace, Labels: np.Labels, Annotations: np.Annotations}
			if _, err := k.cs.NetworkingV1().NetworkPolicies(np.Namespace).Create(ctx, &np, metav1.CreateOptions{}); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// exec runs a command in a pod container and returns stdout.
func (k *kube) exec(ctx context.Context, pod *corev1.Pod, container string, cmd []string) (string, error) {
	req := k.cs.CoreV1().RESTClient().Post().Resource("pods").
		Namespace(pod.Namespace).Name(pod.Name).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: container, Command: cmd, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	ws, err := remotecommand.NewWebSocketExecutor(k.cfg, "GET", req.URL().String())
	if err != nil {
		return "", err
	}
	spdy, err := remotecommand.NewSPDYExecutor(k.cfg, "POST", req.URL())
	if err != nil {
		return "", err
	}
	ex, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	if err := ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}); err != nil {
		return stdout.String(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}
