# Voltgrid telemetry platform: lab deployment

Files:
- `manifests.yaml`: everything, built-in kinds only. Apply with `kubectl apply -f manifests.yaml`.
- `smoke.sh [kubeconfig]`: checks readiness, every intended flow, and the flows that must be denied or not exposed. Run it from a host on the "plant network". In the kind lab that is the docker host, `172.18.0.1`.

## Architecture

```
 plant network (sensors, engineers)            ── routed only to pool=edge node IPs ──
        │ TCP 8883 (fixed IP:port)        │ TCP 8080 (browser)
        ▼                                 ▼
┌─ iot-edge (device-facing tier, pool=edge) ──────────────────────────────┐
│ ingest-gateway DS  hostPort 8883 ─┐     dashboard-proxy DS (nginx)      │
│   :9000 internal consumer API     │       hostPort 8080                 │
└───────────▲───────────────────────┼──────────────┼──────────────────────┘
            │ 9000                  │ 8080 (auth)  │ 3000
┌─ iot-app (application tier, pool=general) ───────▼──────────────────────┐
│ stream-processor x2   device-registry x2   dashboard   alerting ──► paging provider :443
└──────┬───────────────────────┬───────────────┬───────────┬──────────────┘
       │ 8428                  │ 5432          │ 8428      │ 8428
┌─ iot-data (data tier, pool=general, no egress) ─────────────────────────┐
│ tsdb (StatefulSet+PVC)        registry-db postgres (StatefulSet+PVC)     │
└──────────────────────────────────────────────────────────────────────────┘
┌─ iot-ops (every node) ──────────────────────────────────────────────────┐
│ node-agent DS (tolerates all taints): hw-diag :9200 + node-exporter :9100│
│ prometheus (pool=general) ── DNS-SD scrape of every node-agent pod       │
└──────────────────────────────────────────────────────────────────────────┘
```

Each tier has its own namespace, so policies select peers by `kubernetes.io/metadata.name` plus `app.kubernetes.io/name`. Pod Security Admission is `restricted` for iot-app and iot-data. iot-edge needs hostPort and iot-ops needs read-only hostPath, so those two namespaces are `privileged`, with `warn`/`audit` set to restricted. Every container still runs non-root, with `readOnlyRootFilesystem`, all capabilities dropped, the RuntimeDefault seccomp profile, no service-account token, and small requests and limits.

## Placement decisions

| Workload | Kind / replicas | Where | Why |
|---|---|---|---|
| ingest-gateway | DaemonSet on `pool=edge` (tolerates `dedicated=edge`) | edge node, **hostPort 8883** | Sensors can't use DNS or follow redirects, and the plant network is routed only to edge node IPs. A NodePort can't be 8883 (range 30000-32767) and would open the port on every node, including restricted ones. A hostNetwork pod would bypass NetworkPolicy. hostPort keeps the pod on the pod network, so NetworkPolicy still applies and the sensor source IP is preserved (smoke test checks this). A DaemonSet means any edge node added later serves 8883 automatically. |
| dashboard-proxy (nginx) | DaemonSet on `pool=edge` | edge node, hostPort 8080 | No LB or ingress controller exists, and engineers only reach edge IPs. It is a thin proxy, so the dashboard itself and its tsdb access stay off the exposed node. |
| stream-processor, device-registry | Deployment x2, zone topology spread, PDB minAvailable 1 | pool=general | Stateless and on the critical ingest path. |
| alerting, dashboard | Deployment x1 | pool=general | Stateless. Can scale out if needed. |
| tsdb, registry-db | StatefulSet x1 + PVC (local-path) | pool=general | Data tier. Never on the edge node (see "host traffic" below). |
| node-agent (hw-diag + node-exporter) | DaemonSet, `tolerations: [{operator: Exists}]` | **all 7 nodes** incl. edge, restricted, control-plane | "Every node" requirement. Pod network, not hostNetwork, so the endpoints are not published on the plant-facing edge IP and stay under NetworkPolicy. |
| prometheus | Deployment x1 | pool=general | Collects node metrics. Discovers node-agent pods through a headless Service (DNS SD), so it needs no RBAC or API-server access. |
| (restricted pool) | nothing except node-agent | | Reserved for regulated workloads. Nothing here is regulated, so only the mandatory per-node agent runs there. |

Pod budget: 18 of 20 (7 node-agent + 11 app pods). The remaining 2 leave room for a `maxSurge: 1` rollout.

## Network flows

Every `iot-*` namespace starts with `default-deny-all` (Ingress **and** Egress). The only allowed traffic is listed below. The smoke test checks every ALLOW row and D1-D9 (D6 only for tsdb, since the postgres image has no agnhost. D10 is not tested because we may not create pods outside iot-*). The NetworkPolicies come before any workload in the file, so no pod ever runs unsegmented.

"Plant" = `172.18.0.1/32` in the lab (see caveat 1).

| # | Source | Destination:port | Verdict | Why |
|---|---|---|---|---|
| 1 | plant sensors | edge-node-IP:8883 → ingest-gateway | ALLOW | Telemetry ingest (hostPort). |
| 2 | plant engineers | edge-node-IP:8080 → dashboard-proxy | ALLOW | Dashboard UI entry point. |
| 3 | dashboard-proxy | dashboard:3000 | ALLOW | Reverse proxy. |
| 4 | ingest-gateway | device-registry:8080 | ALLOW | Per-device authentication. |
| 5 | stream-processor | ingest-gateway:9000 | ALLOW | Consumes telemetry. The internal port is not published on the node. |
| 6 | stream-processor | tsdb:8428 | ALLOW | Writes enriched data. |
| 7 | device-registry | registry-db:5432 | ALLOW | Registry storage. |
| 8 | alerting | tsdb:8428 | ALLOW | Evaluates alert rules. |
| 9 | alerting | public internet :443 (except 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8) | ALLOW | Paging provider. Cannot use this rule to reach anything internal, including the API server. |
| 10 | dashboard | tsdb:8428 | ALLOW | Read-only queries. |
| 11 | prometheus | node-agent:9100, :9200 on every node | ALLOW | Node metrics and hw-diag status. |
| 12 | pods that resolve names (edge, app, prometheus) | kube-dns:53 UDP/TCP | ALLOW | DNS. tsdb, registry-db and node-agent get no DNS because they initiate nothing. |
| D1 | ingest-gateway, dashboard-proxy (device-facing) | tsdb, registry-db | **DENY** | Device-facing tier must never reach the data tier directly. |
| D2 | ingest-gateway | anything except device-registry:8080 (internet, API server, dashboard, other ports) | **DENY** | A compromised gateway can only reach the auth API. |
| D3 | stream-processor, alerting, dashboard | registry-db | **DENY** | Only device-registry owns the registry DB. |
| D4 | device-registry | tsdb | **DENY** | Not needed. |
| D5 | alerting ↔ other app services | | **DENY** | No lateral movement within a tier. |
| D6 | tsdb, registry-db | any egress | **DENY** | Data stores initiate nothing (no exfiltration path). |
| D7 | node-agent (vendor hw-diag) | any egress | **DENY** | The third-party agent sits on every node, including the plant-facing one. No phone-home, no lateral movement. |
| D8 | any cluster pod | edge-node-IP:8883 / :8080 | **DENY** | The plant CIDR does not cover pod or node IPs. |
| D9 | plant | edge-node-IP:9000/9100/9200, general-node-IP:8883 | not exposed | Only 8883 and 8080 are published, and only on edge nodes. |
| D10 | everything else (other namespaces, other teams) | any iot-* pod | **DENY** | default-deny ingress. |

## Caveats, compromises, things to know

1. **Plant CIDR is a lab parameter.** The policies use `172.18.0.1/32` (the docker bridge that plays the plant network). In production, put the real sensor and engineer subnets there. They **must not overlap node IPs**: Calico `natOutgoing` masquerades pod→node-IP traffic to the source node's IP, so an ipBlock covering node IPs would let every pod in the cluster reach 8883/8080. Smoke check D8 guards against this.
2. **Single edge node = single point of failure for ingest.** Sensors have a fixed IP:port list, and only one edge node exists. Fixing this needs a second edge node (or a VIP from the infra team). hostPort also rules out a surge rollout on that node, so a gateway update has a short outage (`maxUnavailable: 1`). Sensors are expected to reconnect and buffer.
3. **hostPort / hostPath need `privileged` PSA** in iot-edge and iot-ops, because baseline forbids both. The proper guardrail (a ValidatingAdmissionPolicy that allows only hostPort 8883/8080 and read-only hostPath) is cluster-scoped, so it's out of scope here.
4. **hw-diag and node-exporter share one pod** per node. Two DaemonSets on 7 nodes would be 14 pods and break the 20-pod budget. They are still separate containers with their own security contexts. If the real vendor agent needs `hostNetwork` or privileges, that has to be reviewed: a hostNetwork endpoint is outside NetworkPolicy and would be published on the plant-facing edge IP.
5. **node-exporter runs in the pod network**, so its network-interface metrics are the pod's. CPU, memory, filesystem and hardware metrics come from host `/proc`, `/sys` and `/`. This is a deliberate trade-off to keep the plant-facing edge node from exposing :9100.
6. **Host traffic:** Calico always allows traffic from a node to pods on that same node (kubelet probes rely on it). This is one reason the data tier is pinned to `pool=general` and must never share the edge node.
7. The stand-ins use HTTP. Production needs TLS on 8883 (MQTT over TLS) and on the dashboard proxy, plus postgres credentials from a secret manager (the Secret in the file holds a lab-only value). tsdb and registry-db are single replicas. HA postgres would need an operator, which isn't allowed. Prometheus uses emptyDir storage with 2-day retention.
8. No PriorityClass was created (cluster-scoped). In production the node-agent should run at a node-critical priority.

## Smoke result (lab, kind 1.37 + Calico)

`./smoke.sh ../lab-kubeconfig` gave **51 passed, 0 failed**: 18/18 pods Ready, node-agent on 7/7 nodes, all intended flows OK, all 22 deny checks dropped by policy (TIMEOUT), and the 4 "not exposed" checks confirmed.
