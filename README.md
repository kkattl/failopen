# failopen

**Your NetworkPolicy says DENY. failopen shows what gets through anyway.**

NetworkPolicy describes segmentation at the Kubernetes API level. Underneath
is a real network — kube-proxy NAT, CNI quirks, host networking — and the
Kubernetes docs leave several of those interactions *undefined*. failopen
reads your cluster (read-only, like `kubectl get`) and reports where the
policy you wrote does not mean what it looks like it means.

```
failopen audit — 1 finding (1 critical)

  ✗ saas-edge/svc/gateway:31480   ALLOW only 0.0.0.0/0 except 192.168.0.0/16 (gateway-ingress) → ALLOW from any pod via NodePort 31480 (SNAT to node IP)
      Pod traffic to the NodePort 31480 is source-NATed to a node IP, and node IPs fall inside
      0.0.0.0/0 except 192.168.0.0/16, so the rule meant to keep pods out lets them in.
      assumes: pod -> node-IP traffic is SNAT'd to a node address before policy evaluation ...
      verify:  kubectl run fo-verify -n <ns-without-egress-policy> --rm -i --restart=Never ...

Snapshot: 9 namespaces · 36 pods · 10 services · 28 policies · CNI calico (enforces: true)
```

> **Status:** pre-release, working towards v0.1. Output and flags may change.

## What it detects

| Detector | Severity | What it means |
|---|---|---|
| `cni` | critical | NetworkPolicies exist, but the CNI doesn't implement them (e.g. flannel). Every policy is decoration. |
| `ipblock-node-ips` | critical | A pod exposed through a NodePort/LoadBalancer or hostPort has an ingress `ipBlock` that admits node IPs but not pods ("internet, but not pods", or an external range overlapping the nodes). Pod traffic to that port gets SNAT'd to a node IP and passes the rule meant to keep pods out. |

Every finding says what it **assumes** (CNI, NAT behaviour) and gives a
**verify** command that demonstrates it on your cluster. If failopen can't
confirm an assumption — unknown CNI, unknown pod CIDR — the finding is
downgraded, never inflated.

## Usage

```bash
go install github.com/kkattl/failopen/cmd/failopen@latest

failopen audit                           # current kubeconfig context
failopen audit --kubeconfig ~/.kube/prod
failopen snapshot > cluster.json         # save a snapshot...
failopen audit --snapshot cluster.json   # ...and audit it offline
```

**Exit codes** (CI-friendly):

| Code | Meaning |
|---|---|
| 0 | no critical findings |
| 1 | critical findings |
| 2 | the audit could not run (bad flags, cluster unreachable, …) |

**Access:** read-only `list` on pods, services, networkpolicies, namespaces,
nodes, daemonsets; optionally Calico `ippools` and the flannel/Cilium
ConfigMaps to learn the pod CIDR. No agents, no CRDs, nothing written to the
cluster.

## How we know the findings are real

Detectors are static, but they are checked against **measured** behaviour.
`hack/oracle` deploys realistic scenarios on production-shaped
[kind](https://kind.sigs.k8s.io/) clusters (node pools, taints, zones) with
different CNIs, probes every source → target pair from real pod identities,
records the source address each target actually saw, and compares it with
what NetworkPolicy declares (via
[policy-assistant](https://github.com/kubernetes-sigs/network-policy-api)).
The results live in `testdata/scenarios/` — see its README for the method
and its threats to validity.

```bash
make matrix PROFILES="calico cilium flannel"   # measure the corpus (hours)
make corpus-summary                            # verdicts per profile x scenario
```

## Limitations

- Findings rest on assumptions about NAT and CNI behaviour that the
  Kubernetes spec leaves undefined; they are stated per finding.
- Measured on kind with iptables kube-proxy: Calico (IPIP), Cilium
  (VXLAN, kube-proxy kept), flannel. Cloud CNIs (AWS VPC CNI, GKE Dataplane
  V2) and kube-proxy replacements are not measured yet.
- IPv4/TCP only. CNI-specific policy CRDs (Calico GlobalNetworkPolicy,
  Cilium CCNP, AdminNetworkPolicy) are not read yet.

## License

Apache 2.0
