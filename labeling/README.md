# Blind labels (`*.expected.yaml`)

What failopen **should** report for each scenario in `testdata/scenarios/`,
written by a human **before** looking at what the oracle measured. The labels
and the oracle are two independent opinions; where they disagree, one of them
is wrong — and that is how both get tested.

Templates are generated from the manifests only:
`hack/labeling/gen-templates.py` (never overwrites an existing file).

## Rules

1. **Look only at** `testdata/scenarios/<name>/manifests.yaml`, its
   `README.md`, the inventory at the top of the template and the Kubernetes
   docs. **Do not open** `testdata/scenarios/<name>/<profile>/*.json` until
   the file is done. If you already saw them, set `blind: false` — the
   label still counts, it's just weaker evidence.
2. **Label findings, not probes.** One entry per thing a person would fix:
   "Service X is reachable by every pod despite its ipBlock", not one entry
   per node or per source.
3. **Negatives matter as much.** Most agent-designed scenarios are clean;
   write `must-not` entries for things a naive detector would flag but
   shouldn't (e.g. a hostPort locked to one external /32, a broad
   `0.0.0.0/0` allow that already admits pods on purpose).
4. **Unsure → `may`.** A `may` entry never counts as a false positive or
   a miss; use it for arguable warnings.
5. **Hold-out** (proposed): `iot-voltgrid` and `saas-formcraft-etp-cluster`.
   Label them like the rest, but they are not used while tuning detectors.

## Fields

| Field | Values |
|---|---|
| `class` | see below |
| `subject` | `{kind, namespace, name, port}` — `kind`: `Cluster`, `Namespace`, `Service`, `Pod`, `Workload`, `NetworkPolicy` |
| `mechanism` | `cni` · `snat` · `hostnetwork` · `node-local` · `other` |
| `applies_to_cni` | `[any]` or a list: `calico`, `cilium`, `flannel` |
| `label` | `must` · `may` · `must-not` |
| `severity` | `critical` · `warning` · `info` (for `must`/`may`) |
| `rationale` | why — cite the spec/docs where the argument depends on them |
| `evidence` | leave empty; filled at reconciliation with oracle probe refs |

## Classes

**v0.1 (being implemented):**

- `cni-not-enforcing` — policies exist, the CNI ignores them. Subject:
  `{kind: Cluster}`. On a Calico/Cilium profile this is a `must-not`;
  on flannel a `must` (use `applies_to_cni`).
- `ipblock-admits-node-ips` — a pod reachable at the node level (NodePort /
  LoadBalancer backend, hostPort) whose ingress `ipBlock` admits node IPs
  while **not** admitting pods. Traffic from any pod that gets SNAT'd to a
  node IP on the way (kube-proxy masquerade, CNI natOutgoing) passes the
  rule meant to keep pods out. Subject: the Service (+port) or the Pod.

**v0.2 (label them anyway if you see them):**

- `hostnetwork-under-policy` — a NetworkPolicy selects a hostNetwork pod;
  behaviour is undefined by the spec and usually means "no effect".
- `node-exception-segment` — pods under a restrictive policy share nodes
  with non-system hostNetwork pods (e.g. a DaemonSet tolerating every
  taint); the spec always allows node-local traffic, so those agents sit
  inside the segment. Subject: the protected Namespace.
- `cilium-ipblock-cluster-addrs` — on Cilium, an `ipBlock` meant to cover
  pod/node addresses doesn't match them (Cilium applies CIDR rules to
  "world" only).

**Anything else** you think is wrong: `class: other` + a clear rationale.
These become candidates for future detectors.

## After labelling

Tell me which files are done. Reconciliation: I compare each label with the
oracle's divergence groups and the detectors' output, and every
disagreement goes to `labeling/disagreements.md` as either a labelling
error or an oracle/detector bug.
