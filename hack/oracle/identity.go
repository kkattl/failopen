package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/scenario"
)

// Observed-source measurement.
//
// The probe container injected into every scenario pod runs
// `agnhost netexec`, whose /clientip endpoint answers with the source address
// the pod actually saw. In the baseline run (policies removed) every source
// fetches /clientip over the same path as its real probe: the pod IP
// directly, or a "shadow" copy of the Service that differs only in
// targetPort. That turns guesses about SNAT/tunnel addresses into data.

const (
	// identityPort is where pod-network pods serve /clientip; they have
	// their own network namespace, so one port fits all.
	identityPort = 39999
	// hostNetwork pods share the node's namespace: each gets its own port.
	hostNetIdentityBase = 39000
	shadowPrefix        = "fo-id-"
	shadowLabel         = "failopen.io/oracle-shadow"
)

// identityPorts assigns every scenario pod the port its probe container
// serves /clientip on.
func identityPorts(s *collector.Snapshot) map[types.UID]int {
	ports := map[types.UID]int{}
	var hostNet []*corev1.Pod
	for i := range s.Pods {
		p := &s.Pods[i]
		if !isScenarioPod(p) {
			continue
		}
		if p.Spec.HostNetwork {
			hostNet = append(hostNet, p)
			continue
		}
		ports[p.UID] = identityPort
	}
	sort.Slice(hostNet, func(i, j int) bool {
		return hostNet[i].Namespace+hostNet[i].Name < hostNet[j].Namespace+hostNet[j].Name
	})
	for i, p := range hostNet {
		ports[p.UID] = hostNetIdentityBase + i
	}
	return ports
}

// shadow is the identity twin of a Service.
type shadow struct {
	clusterIP string
	nodePorts map[int32]int32 // original spec.ports[].port -> shadow nodePort
}

// createShadows clones every targeted Service with targetPort = identityPort
// (same selector, type and externalTrafficPolicy) and waits for endpoints.
// The returned func deletes them.
func (k *kube) createShadows(ctx context.Context, targets []target) (map[types.UID]shadow, func(context.Context), error) {
	svcs := map[types.UID]*corev1.Service{}
	for _, t := range targets {
		if t.Service != nil {
			svcs[t.Service.UID] = t.Service
		}
	}
	shadows := map[types.UID]shadow{}
	var created []*corev1.Service
	cleanup := func(ctx context.Context) {
		for _, s := range created {
			_ = k.cs.CoreV1().Services(s.Namespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
		}
	}

	for uid, orig := range svcs {
		sh := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      truncate(shadowPrefix+orig.Name, 63),
				Namespace: orig.Namespace,
				Labels:    map[string]string{shadowLabel: "true"},
			},
			Spec: corev1.ServiceSpec{Selector: orig.Spec.Selector, Type: corev1.ServiceTypeClusterIP},
		}
		if orig.Spec.Type == corev1.ServiceTypeNodePort || orig.Spec.Type == corev1.ServiceTypeLoadBalancer {
			sh.Spec.Type = corev1.ServiceTypeNodePort
			sh.Spec.ExternalTrafficPolicy = orig.Spec.ExternalTrafficPolicy
		}
		for _, p := range orig.Spec.Ports {
			if isTCP(p.Protocol) {
				sh.Spec.Ports = append(sh.Spec.Ports, corev1.ServicePort{
					Name: p.Name, Port: p.Port, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(identityPort),
				})
			}
		}
		got, err := k.cs.CoreV1().Services(sh.Namespace).Create(ctx, sh, metav1.CreateOptions{})
		if err != nil {
			cleanup(ctx)
			return nil, nil, fmt.Errorf("shadow for %s/%s: %w", orig.Namespace, orig.Name, err)
		}
		created = append(created, got)
		s := shadow{clusterIP: got.Spec.ClusterIP, nodePorts: map[int32]int32{}}
		for _, p := range got.Spec.Ports {
			s.nodePorts[p.Port] = p.NodePort
		}
		shadows[uid] = s
	}

	for _, s := range created {
		err := wait.PollUntilContextTimeout(ctx, time.Second, time.Minute, true, func(ctx context.Context) (bool, error) {
			slices, err := k.cs.DiscoveryV1().EndpointSlices(s.Namespace).List(ctx, metav1.ListOptions{
				LabelSelector: discoveryv1.LabelServiceName + "=" + s.Name,
			})
			if err != nil {
				return false, err
			}
			for _, sl := range slices.Items {
				for _, ep := range sl.Endpoints {
					if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
						return true, nil
					}
				}
			}
			return false, nil
		})
		if err != nil {
			logf("shadow %s/%s has no ready endpoints; observed sources will be missing for it", s.Namespace, s.Name)
		}
	}
	return shadows, cleanup, nil
}

// identityAddress is where a source fetches /clientip to learn what the
// target sees; "" if the path can't be observed (hostPort: we can't add a
// hostPort to a running pod).
func identityAddress(t target, ports map[types.UID]int, shadows map[types.UID]shadow) string {
	switch t.Kind {
	case scenario.TargetPodIP:
		if p, ok := ports[t.Owner.UID]; ok {
			return hostPort(t.Owner.Status.PodIP, p)
		}
	case scenario.TargetHostNetwork:
		if p, ok := ports[t.Owner.UID]; ok {
			return hostPort(t.Owner.Status.HostIP, p)
		}
	case scenario.TargetClusterIP:
		if s, ok := shadows[t.Service.UID]; ok && s.clusterIP != "" {
			return hostPort(s.clusterIP, int(t.ServicePort))
		}
	case scenario.TargetNodePort:
		if s, ok := shadows[t.Service.UID]; ok && s.nodePorts[t.ServicePort] > 0 {
			host, _, _ := cutHostPort(t.Address)
			return hostPort(host, int(s.nodePorts[t.ServicePort]))
		}
	}
	return ""
}

func cutHostPort(addr string) (string, int, bool) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			p, err := strconv.Atoi(addr[i+1:])
			return addr[:i], p, err == nil
		}
	}
	return addr, 0, false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
