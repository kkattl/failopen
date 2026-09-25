# ecommerce-northwind-overlap

**Mutation of [`ecommerce-northwind`](../ecommerce-northwind/) — exactly one change:** the edge-proxy ingress `ipBlock` is restored to the agent's original `172.18.0.0/16` — the docker network that stood in for the F5 SNAT pool. It overlaps the node IPs, as LB/VPC ranges often do in real clouds, so SNAT'd in-cluster traffic may match it.

Everything else, including the original author's design notes below, is unchanged.

---

## Original scenario

Files: `manifests.yaml` (everything, built-in kinds only), `smoke.sh` (checks that the store is up, that pods run on the right node pools, that the intended flows work and that forbidden flows are denied).

```
kubectl --kubeconfig <cfg> apply -f manifests.yaml
./smoke.sh <cfg>                      # exit 0 = all checks passed
kubectl --kubeconfig <cfg> delete -f manifests.yaml --wait=true
```

## Architecture

```
 Internet ─► F5 ─► <edge node IP>:30080 (NodePort, externalTrafficPolicy=Local)
                        │
                 ecom-edge/edge-proxy (nginx, DaemonSet on pool=edge)
                   │ /            │ /api/
                   ▼              ▼
          ecom-storefront/web ─► ecom-storefront/bff ──────────────┐
                   │              │        │          │            │
                   ▼              ▼        ▼          ▼            ▼
          ecom-shared/session-cache   ecom-catalog/  ecom-orders/  ecom-orders/checkout
                   ▲                  catalog-api    cart          (pool=restricted, PCI)
                   └──── cart            │   │        │   │           │   │    │
                                         ▼   ▼        ▼   └──► catalog-api  │
                                    search  catalog-db  orders-db ◄─────────┘    │
                                        └──► catalog-db  (restricted, PCI)  cart ◄┘
```

| Namespace | Owner | Workloads | Pool |
|---|---|---|---|
| `ecom-edge` | platform | `edge-proxy` (nginx-unprivileged), DaemonSet | edge |
| `ecom-storefront` | storefront | `web` ×2, `bff` ×2 | general |
| `ecom-catalog` | catalog | `catalog-api` ×2, `search` ×2, `catalog-db` (postgres) ×1 | general |
| `ecom-orders` | orders | `cart` ×2 (general), `checkout` ×2 and `orders-db` (postgres) ×1 (restricted) | general / restricted |
| `ecom-shared` | platform | `session-cache` (redis) ×1 | general |

16 pods in total (the limit is 20).

### Getting traffic in from the F5
The F5 can only target fixed ports on node IPs. It cannot reach pod IPs or follow endpoints that change. So:
- A `NodePort` Service `ecom-edge/edge-proxy` is pinned to port **30080** and uses **`externalTrafficPolicy: Local`**. Only nodes that run an edge-proxy pod answer on that port. That means only the edge pool, and `smoke.sh` checks that a general node does *not* serve traffic. There is no second hop from one node to another. The client/F5 source IP is kept, so NetworkPolicy can limit ingress to the F5 network.
- The F5 pool members are the **edge-pool node IPs, port 30080**. The F5 health monitor should target `GET /healthz`. This fits the "fixed port on node IP" requirement, and pod rescheduling never changes what the F5 sees.
- `edge-proxy` is a small nginx reverse proxy that we deploy ourselves, because no ingress controller is installed. `/` goes to `web`, and `/api/` goes to `bff`. It runs as a **DaemonSet on `pool=edge`** (with a toleration for the edge taint), so it grows with the edge pool. Its rollout uses `maxSurge: 1, maxUnavailable: 0`, so the single edge node is never left without a proxy during an update.
- Why not `hostPort` or `hostNetwork`: both break Pod Security `restricted`/`baseline`. `hostNetwork` also puts the pod outside NetworkPolicy.

### Placement decisions
- **general** (the default): all stateless services, `catalog-db` and `session-cache`. Every workload sets `nodeSelector: pool=general` explicitly. Replicated services use a zone `topologySpreadConstraint` (maxSkew 1), and each has a PDB with `minAvailable: 1`.
- **edge**: only the edge-proxy. No application code runs on the internet-facing node.
- **restricted**: `checkout` (handles payment/card data, so it is in PCI scope) and `orders-db` (stores orders and payment references). Both use a nodeSelector plus a toleration. The 2 checkout replicas are spread across zone-a and zone-b. `cart` is **not** in PCI scope, so it stays on general. That keeps the PCI footprint small.
- `catalog-db` holds catalog data only, not regulated data, so it runs on general.

### Hardening
- Pod Security Admission `enforce: restricted` on every namespace. All pods run as non-root with a read-only root filesystem, `drop: [ALL]` capabilities, a RuntimeDefault seccomp profile, and `automountServiceAccountToken: false` (none of the apps talk to the API server).
- CPU/memory requests and memory limits are set on every container. A `ResourceQuota` in each namespace caps pods and resources.
- Readiness and liveness probes on everything: HTTP `/healthz`, `pg_isready`, and a TCP check for redis.
- Redis requires a password (`--requirepass`) and has persistence turned off, since it is a session cache.

## Network policy model
- Every namespace has `default-deny-all` (Ingress **and** Egress) plus `allow-dns-egress` (to `kube-system/k8s-app=kube-dns` on port 53 UDP/TCP).
- Each allowed flow is opened **twice**: an egress rule on the source and an ingress rule on the destination. Neither team can open a flow on its own. The destination team decides who may call it.
- Rules match pods with `namespaceSelector` (`kubernetes.io/metadata.name`) **plus** `podSelector` (`app`) in the same peer. Allowing a namespace never allows every pod in it.
- There is no egress to the internet or to other cluster namespaces unless it is listed below.

### Intended flows

| # | Source | Destination:port | Decision | Why |
|---|---|---|---|---|
| 1 | F5 (172.18.0.0/16 in the lab) | edge-proxy:8080 via node:30080 | **allow** | The only public entry point |
| 2 | edge-proxy | web:8080 | **allow** | Serves the SSR storefront pages (`/`) |
| 3 | edge-proxy | bff:8080 | **allow** | Browser API calls (`/api/`) |
| 4 | web | bff:8080 | **allow** | SSR fetches data through the BFF |
| 5 | web | session-cache:6379 | **allow** | Storefront sessions |
| 6 | bff | session-cache:6379 | **allow** | Storefront sessions |
| 7 | bff | catalog-api:8080 | **allow** | Product listing and detail pages |
| 8 | bff | cart:8080 | **allow** | Cart operations |
| 9 | bff | checkout:8080 | **allow** | Placing orders |
| 10 | catalog-api | search:8080 | **allow** | Search queries (catalog-internal) |
| 11 | catalog-api | catalog-db:5432 | **allow** | Owning team's DB |
| 12 | search | catalog-db:5432 | **allow** | Index builds (owning team's DB) |
| 13 | cart | session-cache:6379 | **allow** | Anonymous cart linked to the session |
| 14 | cart | catalog-api:8080 | **allow** | Price and availability lookup |
| 15 | cart | orders-db:5432 | **allow** | Saved carts (owning team's DB) |
| 16 | checkout | cart:8080 | **allow** | Read the cart being checked out |
| 17 | checkout | catalog-api:8080 | **allow** | Re-check prices at order time |
| 18 | checkout | orders-db:5432 | **allow** | Write orders (owning team's DB) |
| 19 | all pods | kube-dns:53 | **allow** | Service discovery |
| – | edge-proxy | anything except web/bff | deny | The edge only exposes the storefront |
| – | web | catalog-api, cart, checkout, search | deny | The storefront reaches backends only through the BFF |
| – | anyone outside ecom-catalog | catalog-db:5432, search:8080 | deny | Databases belong to the owning team; search is internal |
| – | anyone outside ecom-orders | orders-db:5432 | deny | Owning team only (PCI) |
| – | catalog-api / search / checkout | session-cache:6379 | deny | Only storefront and cart use sessions |
| – | cart | checkout:8080 | deny | The call goes checkout → cart, never the other way |
| – | catalog team | orders team services | deny | Not an approved flow |
| – | anything in the store | internet | deny | No approved external dependencies yet |
| – | non-edge node:30080 | edge-proxy | not served | `externalTrafficPolicy: Local` |
| – | any other namespace in the cluster | any ecom pod | deny | Default-deny ingress |

## Verification (smoke.sh)
`smoke.sh` checks:
- all pods are Ready;
- each pod runs on the right pool;
- the F5 path works end to end: `curl <edge IP>:30080/` reaches `web`, and `/api/` reaches `bff`;
- a general node does not serve port 30080;
- all 17 app-level allow flows connect (`/agnhost connect`, or busybox `wget` from nginx);
- 18 forbidden flows fail, including DB access from other teams and internet egress.

Last run: **59 passed, 0 failed**.

## Lab compromises / what production would change
- **Database storage uses `emptyDir`.** Production would use StatefulSet `volumeClaimTemplates` on a replicated, encrypted storage class, or a managed Postgres, with backups and HA (a replica or operator). I didn't use PVCs here for two reasons. Dynamic PVs are cluster-scoped objects, which the lab rules forbid creating. `delete -f` also would not clean them up. Postgres and redis each run as a single replica.
- **Secrets are plain `Secret` manifests** with placeholder passwords. In production they come from the secret manager (Vault or External Secrets). Client services would also get their DB and redis credentials that way; the agnhost stand-ins don't need them.
- **TLS is not set up.** TLS is assumed to terminate on the F5. Production should re-encrypt F5 → edge-proxy and use mTLS between services (for example a mesh), which PCI requires for checkout.
- **The edge pool is a single node,** so the edge is a single point of failure. That is an infra-level gap: ask for ≥2 edge nodes in different zones and add all of them to the F5 pool. The DaemonSet picks new nodes up automatically.
- **The F5 source CIDR is `172.18.0.0/16`,** the kind docker network. Replace it with the F5 self-IP/SNAT range.
- **The shared `session-cache` has no per-tenant isolation.** Storefront and cart share one redis. Separate ACL users or key prefixes per team would be the next step.
- **Deny checks are mostly enforced on the source's egress side.** Every forbidden source here also lacks an egress rule. The destination ingress rules are present, but they are not tested in isolation, because doing that would need a test pod with open egress, meaning an extra, unapproved workload.
- Monitoring and logging flows (Prometheus scraping, log shipping) are not modelled. Each would need its own explicit ingress rule from the monitoring namespace.

