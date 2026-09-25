# Formcraft: Kubernetes lab deployment

Files:
- `manifests.yaml`: everything, built-in kinds only. Apply it with `kubectl apply -f`.
- `smoke.sh <kubeconfig>`: checks that the allowed flows work and the denied flows are blocked. It exits with a non-zero code on any failure.
- This README.

## Architecture

```
                 corporate edge LB
                        │  (forwards to edge node IP : 31480)
          ┌─────────────▼──────────────┐   pool=edge (tainted dedicated=edge)
          │ saas-edge / gateway (nginx)│   Host: <tenant>.formcraft.example
          └───┬──────────┬──────────┬──┘
              │8080      │8080      │8080
   ┌──────────▼───┐ ┌────▼───────┐ ┌▼─────────────┐   pool=general
   │saas-tenant-  │ │saas-tenant-│ │saas-tenant-  │
   │ acme         │ │ globex     │ │ initech      │   (identical stacks,
   │ app ─► db    │ │ app ─► db  │ │ app ─► db    │    no path between them)
   │ worker ─► db │ │ worker ─►db│ │ worker ─► db │
   └──┬───▲───┬───┘ └─...........┘ └..............┘
      │   │   │ worker ─► mailer:2525
 app ─► auth:8080     │
      │   └── billing ─► app:8080 (pull usage)
   ┌──▼───────────────▼──────────────┐
   │ saas-platform: auth(x2) billing mailer ─► internet SMTP 25/465/587
   └─────────────────────────────────┘
```

### Namespaces
| Namespace | Contents |
|---|---|
| `saas-edge` | `gateway`: nginx reverse proxy, routes by Host header |
| `saas-platform` | `auth` (2 replicas + PDB), `billing`, `mailer` |
| `saas-tenant-acme`, `saas-tenant-globex`, `saas-tenant-initech` | `app`, `worker`, `db` (postgres StatefulSet), a DB Secret and a ResourceQuota |

Each tenant has its own namespace. That makes the namespace the tenant boundary for NetworkPolicy, RBAC, quotas and Secrets. A tenant's DB credentials Secret exists only in that tenant's namespace.

### Placement decisions
- **gateway → `pool=edge`**, using a nodeSelector plus a toleration for `dedicated=edge:NoSchedule`. The corporate LB only forwards to edge node IPs, so the gateway has to run there. It's exposed with a NodePort Service (`31480`) that sets **`externalTrafficPolicy: Local`**. With that setting, only a node running a gateway pod (the edge node) answers on the port. The NodePort is still allocated on every node, but general and restricted nodes drop the traffic. The client source IP is also kept, which the ingress policy depends on. I chose this over `hostPort`/`hostNetwork` because both of those break the Pod Security `restricted` level. `hostNetwork` also takes the pod out of NetworkPolicy altogether.
- **All other workloads → `pool=general`** via an explicit nodeSelector. None of them tolerate the edge or restricted taints, so they never land on the internet-facing node or on the regulated pool.
- **Nothing on `pool=restricted`.** The brief doesn't classify any Formcraft data as PCI/PHI. If a tenant contract later requires it, that tenant's `db` (and probably its `app`/`worker`) would move there with a toleration and nodeSelector.
- **auth** has 2 replicas spread across zones and nodes, with a PDB (`minAvailable: 1`). Every tenant depends on it, so it gets HA first.
- There is one gateway replica, because the edge pool has only one node. This is a single point of failure, noted under compromises below.
- Pod count: 14 of the 20 allowed. All requests are small (10–20m CPU, 16–64Mi).

### Hardening (every pod)
- Pod Security Admission is set to `restricted` (enforce, audit and warn) on every namespace.
- Every pod runs as non-root with seccomp `RuntimeDefault`, drops all capabilities, has `allowPrivilegeEscalation: false` and a read-only root filesystem.
- `automountServiceAccountToken: false` and `enableServiceLinks: false` are set. No workload needs the Kubernetes API.
- Tenant ResourceQuota forbids NodePort and LoadBalancer Services, so a tenant namespace cannot open its own path in from outside.

## Network policy model

Each namespace has:
1. `default-deny-all`: an empty podSelector covering **both Ingress and Egress**, with no rules.
2. `allow-dns-egress`: UDP/TCP 53 to `kube-system` pods labelled `k8s-app=kube-dns` only.
3. One narrow allow policy per real flow. Wherever a flow crosses namespaces, **both ends** are allowed explicitly: an egress rule at the source and an ingress rule at the destination. Removing either one breaks the flow, so a single mistaken policy can't open a path on its own.

Cross-namespace peers are matched with `kubernetes.io/metadata.name`. The API server sets that label and it can't be spoofed. Each peer rule combines the namespace selector with a pod selector (`app.kubernetes.io/name`) in the same peer entry, which ANDs them. Same-namespace peers (app/worker → db) use a bare `podSelector`, so they match only inside that tenant's namespace.

### Intended flows

| # | Source | Destination : port | Verdict | Why |
|---|---|---|---|---|
| 1 | Outside the cluster (edge LB / internet) | `saas-edge/gateway` :8080 (via edge node :31480) | **ALLOW** | Public entry point. The ipBlock is `0.0.0.0/0` **except the pod CIDR 192.168.0.0/16**, so no pod can use the gateway to hop into a tenant. |
| 2 | `saas-edge/gateway` | `saas-tenant-*/app` :8080 | **ALLOW** | Routes `<tenant>.formcraft.example` to that tenant's app. Unknown hosts get 404, and there is no default tenant. |
| 3 | `saas-tenant-X/app` | `saas-tenant-X/db` :5432 | **ALLOW** | The app reads and writes its own tenant DB. |
| 4 | `saas-tenant-X/worker` | `saas-tenant-X/db` :5432 | **ALLOW** | Async jobs work on the tenant's own DB. |
| 5 | `saas-tenant-*/app` | `saas-platform/auth` :8080 | **ALLOW** | SSO and token validation. |
| 6 | `saas-tenant-*/worker` | `saas-platform/mailer` :2525 | **ALLOW** | Outbound email is relayed through the shared mailer. |
| 7 | `saas-platform/billing` | `saas-tenant-*/app` :8080 | **ALLOW** | Billing pulls usage. The connection is pull-only: billing initiates it and apps cannot reach billing. |
| 8 | `saas-platform/mailer` | Internet (non-RFC1918) TCP 25/465/587 | **ALLOW** | SMTP delivery. Private, CGNAT, link-local (metadata) and loopback ranges are excluded. |
| 9 | Every pod | kube-dns :53 UDP/TCP | **ALLOW** | Name resolution. |
| 10 | Tenant X (any pod) | Tenant Y (any pod, including db) | **DENY** | Contractual tenant isolation, blocked by X's egress **and** Y's ingress policy. |
| 11 | Tenant app/worker | edge node IP :31480, or the gateway pod directly | **DENY** | Stops a tenant from reaching another tenant "through the front door". Tenant pods have no egress except rows 3–6 and 9, and the gateway ingress excludes pod IPs. |
| 12 | Tenant app/worker | internet, Kubernetes API, node/kubelet IPs | **DENY** | No need. Also blocks exfiltration and escalation. |
| 13 | `saas-tenant-*/app` | `mailer` | **DENY** | Only workers send mail. |
| 14 | `saas-tenant-*/worker` | `auth`, own `app` | **DENY** | No such flow in the design. |
| 15 | `auth`, `mailer` | tenant pods | **DENY** | These shared services are called by tenants and never call them. That keeps them from becoming a bridge between tenants. |
| 16 | `billing` | tenant `db`, `auth`, anything else | **DENY** | Billing only needs the app usage endpoint. |
| 17 | `db` | anything (except DNS) | **DENY** | Databases never initiate connections. Ingress is from their own tenant's app and worker only. |
| 18 | Any other namespace in the cluster | anything in `saas-*` (except the public gateway) | **DENY** | Default-deny ingress everywhere. Peers are selected by namespace name, not by labels someone else could apply. |

Shared services and cross-tenant exposure: `billing` and `gateway` are the only components that can open connections to more than one tenant. Both are platform-owned, and neither runs tenant code. Tenant code can reach only `auth` and `mailer`, and neither of those can connect back into any tenant.

## Verification
`./smoke.sh <kubeconfig>` checks:
- Placement.
- North-south routing: curl to the edge node IP with each tenant's Host header returns the correct tenant's pod hostname, and an unknown host gets 404.
- Every allowed east-west flow (rows 3–7).
- All 6 ordered tenant pairs, for app and worker against both the Service DNS name and the raw pod IP, plus db→db.
- The side doors: NodePort hairpin, the gateway pod directly, kube API, kubelet, internet, and the shared services calling back into tenants.

Last run: **65 passed, 0 failed**.

## Compromises / lab-only shortcuts
- **Postgres storage is `emptyDir`.** A PVC would make the local-path provisioner create a cluster-scoped PersistentVolume, which is outside my allowed scope. Production would use a PVC on a replicated or backed-up StorageClass, or a managed DB.
- **The DB password is a placeholder `Secret` inside manifests.yaml.** Production would use an external secret store or sealed secrets, rotated per tenant.
- **There's one gateway replica on one edge node**, a single point of failure. The edge pool needs at least 2 nodes (ideally across zones) before this can be HA. There's also no TLS in the lab. Production would terminate TLS at the gateway with per-tenant certificates.
- **The pod CIDR (192.168.0.0/16) is hard-coded** in the gateway ingress `except` and the mailer egress `except`. It must match the cluster's IPPool.
- **NetworkPolicy is L3/L4 only.** It can't restrict billing to the usage endpoint on the app, or stop an app from asking auth for another tenant's tokens. Those checks have to be enforced by the app and auth (mTLS / tenant-scoped tokens).
- **The `NodePort` is still allocated on every node.** `externalTrafficPolicy: Local` makes non-edge nodes drop the traffic, but closing the port entirely would take host firewalling or `nodePortAddresses`. Both are cluster-level settings outside my namespaces.
- Tenants share general-pool nodes. Network isolation is enforced. Kernel-level isolation (separate node pools per tenant, or sandboxed runtimes) is out of scope here.
