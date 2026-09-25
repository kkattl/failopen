# Carewell patient-records platform: lab deployment

Files:
- `manifests.yaml`: everything, built-in kinds only. `kubectl apply -f manifests.yaml`
- `smoke.sh <kubeconfig>`: checks that the allowed flows work and the forbidden ones are blocked. It exits non-zero on any failure.

## Architecture

```
 corporate edge LB ──► edge node IP:<nodePort>  (only the pool=edge node answers)
                         │
               [health-edge] edge-proxy (nginx)             pool=edge
                         │ :8080
               [health-web]  portal x2                      pool=general
                    │ :8080                 │ :8080
                    ▼                       ▼
 [health-phi]  records-api x2        [health-notify] notifications ──► public email/SMS APIs :443/:587
   pool=restricted │                      pool=general
         ┌─────────┼──────────────┐
         ▼ :5432   ▼ :8080        ▼ :8080
     records-db   imaging      audit-log         (all PVC-backed, pool=restricted)
         ▲ :5432 (streaming replication, role "replicator" only)
         │
 [health-reporting] reporting-replica (hot standby) ◄──:5432── reporting CronJob (02:15 UTC)
                                                     pool=restricted

 [health-ops] log-shipper DaemonSet (fluent-bit): every node, including control plane ──► SIEM :24224/TLS
              backup-agent DaemonSet: pool=restricted (every node that stores data) ──► vendor :443
```

### Namespaces as trust zones

| Namespace | Contents | Pod Security |
|---|---|---|
| `health-edge` | nginx reverse proxy, the only component the internet can reach | restricted |
| `health-web` | portal | restricted |
| `health-notify` | notifications. It is kept apart so it can never be grouped with PHI by mistake | restricted |
| `health-phi` | records-api, records-db, imaging, audit-log | restricted |
| `health-reporting` | reporting-replica (a full PHI copy) and the reporting CronJob | restricted |
| `health-ops` | node agents that need read-only `hostPath` | privileged enforce, baseline audit/warn |

## Placement decisions

- **PHI on `pool=restricted`.** This covers records-api, records-db, imaging, audit-log, reporting-replica and the reporting job. Each one has a `nodeSelector` and a toleration. A toleration alone would only *permit* the restricted nodes, so the nodeSelector is what forces the pods there. records-api is spread across zone-a and zone-b. The replica prefers a different node from the primary.
- The **reporting replica counts as PHI**. A streaming replica of records-db holds the same data. De-identification happens inside the reporting job, so the job's input is PHI as well. For that reason both the replica and the job run on restricted nodes, under default-deny.
- **Portal and notifications run on `pool=general`.** Portal uses a zone spread and a PodDisruptionBudget. Neither of them tolerates the restricted or edge taints.
- **Only the edge proxy runs on `pool=edge`.** It is published with a `NodePort` Service set to `externalTrafficPolicy: Local`:
  - Every node opens the NodePort. With `Local`, only a node that runs an edge-proxy pod forwards the traffic, and that is the edge node. The restricted and general nodes drop it (smoke.sh checks this).
  - `Local` keeps the client source IP, so the edge NetworkPolicy can match on it.
  - `hostPort` was ruled out because it would require the privileged Pod Security level for the internet-facing namespace. `hostNetwork` was ruled out because it bypasses NetworkPolicy.
  - The nodePort number is auto-allocated. Port 31480 was already taken by another team on this shared cluster, so fixed ports are fragile here. The edge LB must be pointed at `.spec.ports[0].nodePort`.
- **log-shipper** tolerates every taint (`operator: Exists`), so it runs on all 7 nodes, including edge, restricted and the control plane. It reads `/var/log/containers` and the kubelet/containerd journal read-only.
- **backup-agent** runs on `pool=restricted`. By design every PersistentVolume of the platform lives there, because every stateful workload is pinned to that pool, so "nodes that store data" means `pool=restricted`. smoke.sh checks this invariant. It mounts `/var/local-path-provisioner` read-only.
- **Hardening.** Every workload runs as non-root, except the two node agents, which need root plus `DAC_READ_SEARCH` to read root-owned logs and 0700 postgres data. All workloads have a read-only root filesystem, `drop: [ALL]`, the RuntimeDefault seccomp profile and `automountServiceAccountToken: false`. None of them uses the Kubernetes API. Resource requests are small and memory limits are set.
- **Pod budget.** 19 pods run steadily: 1 edge-proxy, 2 portal, 1 notifications, 2 records-api, 1 records-db, 1 imaging, 1 audit-log, 1 replica, 7 log-shipper, 2 backup-agent. The CronJob uses the 20th slot at night. smoke.sh uses that same slot and runs its test jobs one at a time.

## Network flows

Every namespace has `default-deny-all` for both Ingress and Egress. On top of that there is DNS egress to `kube-system/k8s-app=kube-dns:53`, except in health-ops, whose agents use fixed IPs. Every allow rule pins the source or destination by namespace **and** pod label.

### Allowed

| # | Source | Destination:port | Why |
|---|---|---|---|
| A1 | Internet / edge LB (any IP except the pod CIDR 192.168.0.0/16) | edge-proxy:8080 (via edge node NodePort) | Public entry point |
| A2 | edge-proxy | portal:8080 | Reverse proxy. The portal is the only upstream |
| A3 | portal | records-api:8080 | All PHI reads and writes go through records-api |
| A4 | portal | notifications:8080 | Schedule appointment reminders, with minimum necessary data and no PHI |
| A5 | notifications | public internet :443, :587 (RFC1918, CGNAT, link-local and loopback excluded) | Email/SMS provider APIs |
| A6 | records-api | records-db:5432 | PHI storage |
| A7 | records-api | imaging:8080 | Medical images |
| A8 | records-api | audit-log:8080 | Audit trail for every PHI access |
| A9 | reporting-replica | records-db:5432 | Streaming replication. pg_hba also limits this to the `replicator` role with REPLICATION |
| A10 | reporting (CronJob) | reporting-replica:5432 | Read-only `reporting` role (`pg_read_all_data`) on a hot standby |
| A11 | log-shipper | SIEM collector 203.0.113.10/32:24224 (forward over TLS) | Node and container logs go to the SIEM |
| A12 | backup-agent | backup vendor 198.51.100.0/24:443 | Off-site backup |
| A13 | all pods in the app namespaces | kube-dns:53 UDP/TCP | Name resolution |

### Denied (a sample; everything not listed above is denied)

| Source → destination | Why |
|---|---|
| anything → any node except the edge node on the edge NodePort | Only the edge pool is internet-facing |
| edge-proxy → records-api / records-db / notifications | A compromised edge must reach nothing but the portal |
| portal → records-db / imaging / audit-log / reporting-replica | No bypass of records-api (auth and auditing live there) |
| portal → internet | No egress need |
| notifications → any PHI service or replica, notifications → portal | Notifications must never touch PHI |
| records-api / imaging / audit-log / records-db / replica → internet | Stops PHI exfiltration |
| records-api → notifications / replica | Not needed. PHI must not flow into non-PHI services |
| imaging ↔ audit-log, imaging/audit-log → records-db | No lateral movement inside the PHI zone |
| records-db → anything | A database never initiates connections |
| reporting → records-db | Reporting reads the replica only |
| backup-agent / log-shipper → any pod | The agents sit on the same nodes as PHI but get no network path to it |
| any other namespace (other teams) → any `health-*` pod | Default deny. The only ingress rule that is not selector-based is A1, and it applies only to edge-proxy |

## Smoke test result

`./smoke.sh <kubeconfig>` gave **55 passed, 0 failed**. It checks:
- readiness of every pod
- DaemonSet coverage: 7 of 7 nodes for the log-shipper, 2 of 2 data nodes for the backup agent
- that every PHI pod is placed on `pool=restricted`
- the north-south path from the host to the edge NodePort, plus a NodePort check against each of the other five nodes
- 9 allowed east-west flows, and that the replica is `streaming`
- a real run of the CronJob, which reports `replica_in_recovery=true`
- 30 denied flows, including a Job that runs with the reporting job's exact labels and ServiceAccount and tries to reach records-db

## Compromises and known limitations

1. **Host → local pod traffic is not filtered.** Like most CNIs, Calico lets a node reach its own pods regardless of NetworkPolicy (kubelet probes depend on this). This was verified: from the restricted node's host network namespace, the PHI pods on that node answer, and those on the other node do not. So any `hostNetwork` pod that another team schedules onto a restricted node can reach our PHI pods, and NetworkPolicy cannot stop it. Mitigations are needed outside my scope:
   - admission policy that forbids hostNetwork on restricted nodes
   - a PHI-only node pool
   - mTLS and authentication between services (a real app must not trust the network alone)
2. **PHI shares nodes with PCI.** The restricted pool is shared with `fintech-cde` (PCI) and other teams' node agents. A dedicated PHI pool, or at least per-tenant taints, would be the production recommendation. Node labels and taints are outside my remit.
3. **Single edge node.** `edge-proxy` has 1 replica because the edge pool has one node. This is a single point of failure and needs a second edge node. TLS is not terminated in the lab: the proxy speaks HTTP on 8080. In production the LB or the proxy terminates TLS.
4. **The SIEM and the backup vendor are placeholders** (203.0.113.10 and 198.51.100.0/24, both TEST-NET ranges). fluent-bit is really tailing logs and retrying the forward, but delivery cannot be proven in the lab. The backup agent is an `agnhost pause` stand-in with the correct placement, mounts and egress policy. Both agents are business associates in HIPAA terms: application logs must not contain PHI, and the vendor needs a BAA.
5. **No Kubernetes metadata enrichment in fluent-bit.** That would need a ClusterRole, which is cluster-scoped and not allowed here. Records are tagged with the node name and the container log file name, which includes the namespace and pod.
6. **The notifications egress is broad** (all public IPs on 443/587). Built-in NetworkPolicy cannot express FQDNs. In production, route this through an egress proxy with an allowlist.
7. **Secrets are in the manifest** (lab passwords). In production they come from an external secret manager, with encryption at rest.
8. The apps are `agnhost netexec` stand-ins, so the portal and records-api do no real authentication or auditing. The postgres primary/replica setup is real, with streaming replication.
9. **The edge ipBlock admits node IPs**, so any host-network process can reach the public proxy, which is equivalent to internet access. The pod CIDR is excluded so that pods cannot use the public path as a pivot.
