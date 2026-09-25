# fintech-paylane-hostnet-agent

**Mutation of [`fintech-paylane`](../fintech-paylane/) — exactly one change:** the `fintech-ops/node-agent` DaemonSet (node-exporter + fluent-bit, tolerates every taint) runs with `hostNetwork: true`, as the upstream node-exporter chart does. The original author avoided it on purpose.

Everything else, including the original author's design notes below, is unchanged.

---

## Original scenario

Files:

- `manifests.yaml`: everything, built-in kinds only.
- `smoke.sh <kubeconfig>`: checks readiness, placement, every allowed flow and 22 flows that must be denied.

```
kubectl --kubeconfig $KC apply -f manifests.yaml
./smoke.sh $KC
kubectl --kubeconfig $KC delete -f manifests.yaml --wait=true
```

## Architecture

```
 internet ──► corporate edge LB ──► <edge node IP>:30880 (NodePort, externalTrafficPolicy=Local)
                                         │
 ┌─ fintech-edge ─── pool=edge ──────────▼───────────┐
 │  edge-proxy (nginx-unprivileged, 1 replica)       │
 └───────────────────────────────┬───────────────────┘
                                 │ :8080
 ┌─ fintech-app ─── pool=general ▼─────────────────────────────────────┐
 │  checkout-api (x2, zone-spread) ──:6379──► redis                    │
 │  admin-panel (x1, no ingress; staff access via kubectl port-forward) │
 └──────────┬─────────────────────────────┬────────────────────────────┘
            │ :8080                       │ :8080
 ┌─ fintech-cde ─── pool=restricted (PCI CDE) ─────────────────────────┐
 │  payments-core (x2, zone-a + zone-b)                                │
 │     ├──:8080──► ledger ──:5432──► postgres (StatefulSet, 1Gi PVC)    │
 │     └──:8080──► card-gateway (x2) ──:443──► card networks (internet) │
 └─────────────────────────────────────────────────────────────────────┘
 ┌─ fintech-ops ───────────────────────────────────────────────────────┐
 │  node-agent DaemonSet on ALL 7 nodes: node-exporter + fluent-bit     │
 │     fluent-bit ──:443──► log vendor (internet)                       │
 │  prometheus (pool=general) ──:9100──► node-agent (DNS SD, headless)  │
 └─────────────────────────────────────────────────────────────────────┘
 all pods ──:53──► kube-system/kube-dns
```

### Namespaces = security zones

| Namespace | PCI scope | Pod Security | Contents |
|---|---|---|---|
| `fintech-edge` | connected-to | restricted | edge reverse proxy |
| `fintech-app` | connected-to (it calls the CDE) | restricted | checkout-api, redis, admin-panel |
| `fintech-cde` | **CDE** | restricted | payments-core, card-gateway, ledger, postgres |
| `fintech-ops` | security-impacting | privileged (warn: baseline) | node agent, prometheus |

Each namespace carries a `paylane.io/pci-scope` label.

### Placement decisions

- **CDE on `pool=restricted`.** The four CDE workloads use `nodeSelector: pool=restricted` and tolerate `dedicated=restricted`. The toleration lets them onto the tainted nodes, and the selector keeps them off every other node. payments-core and card-gateway run 2 replicas each, spread across zone-a and zone-b (`DoNotSchedule`), with a PDB of `minAvailable: 1`. No non-CDE application pod can land on these nodes, because only the CDE tolerates the taint. The one exception is the per-node ops agent (see below).
- **edge-proxy on `pool=edge`.** It tolerates `dedicated=edge`. It is exposed as a NodePort (30880) with `externalTrafficPolicy: Local`, so only a node that runs an edge-proxy pod answers: in practice, just the edge node. General and restricted nodes drop the traffic (smoke.sh checks this), and the client source IP is preserved for logs and rate limiting. I chose NodePort over `hostPort` because hostPort breaks the `restricted` Pod Security level. No ingress controller is needed for one upstream, and a plain nginx reverse proxy has no cluster RBAC.
- **checkout-api, redis, admin-panel, prometheus on `pool=general`.** checkout-api runs 2 replicas spread across zones.
- **node-agent on every node.** It tolerates everything (`operator: Exists`), so it also lands on edge, restricted and control-plane nodes. That covers "metrics and logs from every node".
- **Pod budget: 19 of 20.** The DaemonSet costs 7 pods. With separate node-exporter and fluent-bit DaemonSets we would need 14 pods, plus at least 8 application pods, which is 22. So I put both agents in one DaemonSet pod as two containers. Multi-replica Deployments use `maxSurge: 0` so a rollout never goes above the cap.

### Hardening

- The pods in edge, app and cde pass PSA `restricted`: non-root, all capabilities dropped, read-only root filesystem, RuntimeDefault seccomp and no privilege escalation.
- `automountServiceAccountToken: false` everywhere. No workload needs the Kubernetes API, and egress to the apiserver is blocked anyway.
- No Roles, no ClusterRoles, no cluster-scoped objects apart from the 4 namespaces.
- The node-agent is **not** `hostNetwork` (see "hostNetwork bypass" below). Its host mounts (`/proc`, `/sys`, `/`, `/var/log`) are read-only. node-exporter runs as nobody. fluent-bit runs as uid 0 because it needs to read root-owned container logs, but it has no capabilities.
- Secrets for postgres, redis and the log-vendor token are Kubernetes Secrets. In production they would come from an external secret store, and etcd encryption at rest would be enabled.

## Network policy model

Every namespace has a `default-deny-all` policy covering **Ingress and Egress**. It also has an `allow-dns-egress` policy that permits only kube-system/kube-dns on 53/UDP and 53/TCP. Each workload then gets one policy that lists its exact ingress sources and egress destinations. Cross-namespace peers always pair a `namespaceSelector` (`kubernetes.io/metadata.name`) with a `podSelector`, so a label copied onto a pod in another namespace cannot impersonate a peer. Internet egress uses `0.0.0.0/0` minus RFC1918, CGNAT, link-local and loopback. That way a "443 to the internet" rule cannot reach pods, nodes, the kubelet or the apiserver. The policies come first in `manifests.yaml`, so no pod ever starts unprotected.

### Intended flows

| # | Source | Destination:port | Decision | Why |
|---|---|---|---|---|
| 1 | Internet (via edge LB) | edge node:30880 → edge-proxy:8080 | **allow** | Public merchant API entry point |
| 2 | edge-proxy | checkout-api:8080 | **allow** | The proxy has exactly one upstream |
| 3 | checkout-api | redis:6379 | **allow** | Idempotency keys and rate limiting |
| 4 | checkout-api | payments-core:8080 | **allow** | Authorize/capture: the **only** way from outside into the CDE |
| 5 | admin-panel | payments-core:8080 | **allow** | Support lookups and refunds go through the CDE's API, never to the DB |
| 6 | payments-core | ledger:8080 | **allow** | Book the double-entry postings |
| 7 | payments-core | card-gateway:8080 | **allow** | Card network calls |
| 8 | ledger | postgres:5432 | **allow** | Ledger is the only DB client |
| 9 | card-gateway | internet:443 (non-private) | **allow** | The only component allowed to talk to the card networks. In production, narrow this to the networks' published CIDRs or an egress proxy |
| 10 | node-agent (fluent-bit) | internet:443 (non-private) | **allow** | Log shipping to the vendor |
| 11 | prometheus | node-agent:9100 | **allow** | Node metrics scrape |
| 12 | all fintech pods | kube-dns:53 UDP/TCP | **allow** | Service discovery |
| 13 | Internet | general/restricted node:30880 | deny | externalTrafficPolicy=Local; only the edge pool is internet-facing |
| 14 | edge-proxy | anything except checkout-api | deny | Default deny |
| 15 | checkout-api / admin-panel | ledger, postgres, card-gateway | deny | The CDE has one entry point (payments-core) |
| 16 | admin-panel | redis, checkout-api | deny | No lateral movement inside the app zone |
| 17 | payments-core, ledger, checkout-api, … | internet | deny | Only card-gateway (and the log shipper) may leave the cluster |
| 18 | card-gateway | internet:80 or other ports | deny | 443 only |
| 19 | payments-core, card-gateway | postgres:5432 | deny | Only ledger talks to the DB |
| 20 | card-gateway ↔ ledger | any | deny | Both are leaves; only payments-core calls them |
| 21 | any CDE pod | fintech-app / fintech-edge / fintech-ops | deny | The CDE never initiates connections out of the CDE (except card networks) |
| 22 | CDE pods | node IPs (kubelet 10250), kube-apiserver | deny | No control-plane or node access |
| 23 | prometheus / node-agent | any CDE pod | deny | Monitoring must not become a path into the CDE |
| 24 | anything but prometheus | node-agent:9100 | deny | Metrics are not public |
| 25 | anything | redis, postgres, prometheus egress except the above | deny | redis and postgres have `egress: []`: they never initiate connections |

`smoke.sh` tests flows 1–9, 11 and 12 directly, plus a sample of the denies (13, 15–24). Flow 10 is configured but cannot succeed in the lab, because the vendor hostname is a placeholder.

## Known gaps, compromises and residual risks (tell the auditor)

1. **hostNetwork traffic bypasses NetworkPolicy on the same node (verified).** With Calico's default configuration, traffic from the node's own network namespace to a local pod is allowed. That is also how the kubelet probes get through default-deny. I tested it: a `hostNetwork` pod on the node running `postgres-0` **connected** to postgres:5432 despite the policy. The same probe from a different node was blocked. So any host-network workload on a restricted node sits inside the CDE segment. That includes kube-system DaemonSets and any other team's workload that tolerates `dedicated=restricted`, a taint that is also meant for PHI workloads. Mitigations, which need cluster-admin and are out of scope here:
   - Calico `GlobalNetworkPolicy` / host endpoint policy (CRDs, not allowed for this deliverable).
   - A dedicated PCI-only node pool, or a ValidatingAdmissionPolicy that forbids `hostNetwork` and the `dedicated=restricted` toleration outside `fintech-cde`.
   - Our own node-agent is deliberately not host-network for this reason.
2. **`fintech-ops` is PSA `privileged`.** The node agent needs hostPath, so anyone who can create pods in `fintech-ops` could create a host-network or privileged pod on a CDE node (see 1). Restrict pod-create RBAC in `fintech-ops` to the platform team and treat that namespace as in-scope for PCI.
3. **The node agent runs on the CDE nodes**, so it is an in-scope system component: read-only host mounts, egress only to the log vendor on 443, ingress only from prometheus on 9100. Because it is not host-network, node-exporter's *network-interface* metrics describe the pod's own netns, not the node's. CPU, memory, disk and filesystem metrics are node-level. This trade-off is deliberate.
4. **Log shipping target is a placeholder** (`logs.log-vendor.example:443`). fluent-bit tails `/var/log/containers/*.log` on every node and retries. The lab run confirmed it reads the logs and fails only on DNS for the fake host. There is no Kubernetes metadata enrichment, because the `kubernetes` filter needs a ClusterRole. The node name is added as a field, and pod, namespace and container come from the file name.
5. **Prometheus has no remote_write or alerting yet.** It is reachable only through `kubectl port-forward`. Add an egress rule when a metrics backend is chosen.
6. **Single points of failure** forced by the 20-pod cap and the pool sizes:
   - edge-proxy: there is only one edge node.
   - redis: a cache. Losing it degrades idempotency; it loses no money.
   - ledger: 1 replica.
   - postgres: a single instance on a node-local PVC (local-path), so it is pinned to one restricted node and zone. For production, use managed Postgres or a replicated operator-based cluster with backups and PITR.
7. **No TLS inside the cluster and no TLS on the edge listener** in the lab. For PCI (Req. 4), terminate TLS at the corporate edge LB or at edge-proxy, and add mTLS between checkout-api → payments-core → card-gateway. Egress to card networks and the vendor is TLS by protocol.
8. **admin-panel has no network ingress.** Staff reach it through an authenticated `kubectl port-forward`, or later through an internal-only LB with SSO. It is intentionally not on the public edge path.
9. **Node-level policy for the NodePort.** The NodePort is still bound on every node. Only `externalTrafficPolicy: Local` makes the non-edge nodes drop the traffic. A firewall at the corporate edge should only forward to edge-pool IPs anyway.
10. The images use floating minor tags for the lab. In production, pin them by digest and pull through a scanned registry mirror.
