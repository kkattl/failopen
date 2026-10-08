# Experiment 6: failopen changes nothing in the cluster

**Question.** Is failopen read-only in practice, and not only by design?

**Answer.** Yes. failopen ran under a ServiceAccount bound to a read-only
ClusterRole. The API server audit log shows that it made **12 requests,
all `list`, all answered 200, and 0 mutating requests**. Both `failopen
audit` and `failopen snapshot` completed with only the permissions listed
in the README.

Reproduce: `hack/experiments/exp6/run.sh`. It needs about 2 minutes and
creates and deletes the kind cluster `fo-exp6`.

## Method

1. A kind cluster (Kubernetes 1.37, kindnet) with API server auditing on.
   The audit policy is a single rule, `level: Metadata` for every request,
   so nothing is filtered out before the analysis.
2. Scenario `demo-payments` is deployed, so there is something to audit.
3. ServiceAccount `failopen` is bound to ClusterRole `failopen-readonly`
   ([rbac.yaml](rbac.yaml)). The role allows exactly the access the
   README documents:
   - `list` on pods, services, namespaces, nodes, networkpolicies,
     daemonsets and Calico ippools;
   - `get` on the two named ConfigMaps (flannel, Cilium).
4. `failopen audit` and `failopen snapshot` run with a kubeconfig that
   holds only that ServiceAccount's token.
5. Every audit event whose user is
   `system:serviceaccount:default:failopen` is extracted
   ([audit-failopen.jsonl](audit-failopen.jsonl)).

Running under a restricted identity makes the result stronger in two ways:

- **No help from permissions.** Any write attempt would have appeared in
  the log, as a 403. There are none.
- **No other permissions needed.** The tool doesn't quietly depend on
  anything beyond what the README documents.

## Results

| verb | resource | HTTP status | requests |
|---|---|---|---|
| list | apps/daemonsets | 200 | 2 |
| list | core/namespaces | 200 | 2 |
| list | core/nodes | 200 | 2 |
| list | core/pods | 200 | 2 |
| list | core/services | 200 | 2 |
| list | networking.k8s.io/networkpolicies | 200 | 2 |

Requests by verb: `list` 12. Mutating requests (`create`, `update`,
`patch`, `delete`, …): **0**. Two requests per resource: one from `audit`,
one from `snapshot`. No `watch`, and nothing outside the documented
resources.

## Limits

- **Only the kindnet path ran.** On kindnet the pod CIDR comes from
  `node.spec.podCIDR`. The Calico `ippools` list and the flannel and Cilium
  ConfigMap `get` were not exercised. They are read-only by construction:
  the collector calls only `List` and `Get`, which `grep -n
  'Create\|Update\|Patch\|Delete' internal/collector` confirms. The RBAC
  role grants them anyway.
- **Not tested: failure without the optional permissions.** If the
  optional permissions are missing, the collector skips those sources (pod
  CIDR unknown leads to downgraded findings, see experiment 4) instead of
  failing. This experiment granted them, so that behaviour was not
  exercised here.
