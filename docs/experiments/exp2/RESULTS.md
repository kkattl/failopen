# Experiment 2: is the CNI enforcement verdict right?

**Question.** The `cni` detector rests on a heuristic: which DaemonSets and
node annotations exist. Does its claim "policies are enforced / not
enforced" match what the network does?

**Answer.** Not at first. On the code as of commit `c6f9f7f`, the
heuristic was right on 7 of 10 distributions/CNIs:

- **2 wrong answers.** Old kindnet was reported as enforcing (a silent
  miss). flannel with kube-router as the policy engine was reported as
  **"NONE ENFORCED"**, a false critical with exit code 1.
- **1 undecided.** Antrea was not recognised, so failopen gave a warning,
  "enforcement unverified".

All three were fixed in the collector. On the fixed code the verdict is
right on **10 of 10**. The deny-all probe confirms each verdict from the
same node and from another node.

Reproduce: `hack/experiments/exp2/run.sh [variant...]`. Each variant needs
3–5 minutes and creates and deletes its own small cluster.
`PASS=<name> FAILOPEN=<binary>` keeps runs of different code versions
apart.

## Method

1. One small cluster per variant: 1 control plane + 2 workers (k3d: 1
   server + 2 agents).
2. In namespace `exp2`: an agnhost `netexec` server on worker A, a client
   on worker A (same node) and a client on worker B (cross-node).
3. **Baseline:** both clients must reach the server's pod IP. If not, the
   variant counts as `broken`, not as a result.
4. **Deny-all ingress** on the namespace. Both clients are polled for up to
   60 s, so the controller has time to program the dataplane.
   - **enforced:** both are blocked.
   - **not-enforced:** both still connect.
   - **partial:** anything else.
5. `failopen snapshot` and `failopen audit` run against the live cluster.
   The snapshot's `cni.enforcesPolicy` is the prediction.
   - **unknown CNI:** the prediction is "unknown", meaning warning, not a
     claim either way.

## Results

| Variant | CNI as deployed | Kubernetes | Measured | failopen @ c6f9f7f | failopen, fixed |
|---|---|---|---|---|---|
| kindnet | kindnetd v20260820 (kind v0.33) | 1.37.0 | enforced | kindnet, enforces ✔ | kindnet, enforces ✔ |
| kindnet-legacy | kindnetd v20240202 (kind v0.23) | 1.30.0 | **not enforced** | kindnet, enforces ✘ (silent) | kindnet, doesn't enforce ✔ (critical) |
| calico | Calico v3.28.0 | 1.37.0 | enforced | ✔ | ✔ |
| cilium | Cilium 1.20.2 | 1.37.0 | enforced | ✔ | ✔ |
| flannel | flannel v0.28.9 | 1.37.0 | not enforced | ✔ (critical) | ✔ (critical) |
| canal | Calico v3.28.0 + flannel v0.24.3 | 1.37.0 | enforced | ✔ | ✔ |
| antrea | Antrea v2.7.0 | 1.37.0 | enforced | unknown (warning) | antrea, enforces ✔ |
| k3s | k3s v1.35.5 (flannel + kube-router) | 1.35.5 | enforced | ✔ | ✔ |
| k3s-no-policy | k3s, `--disable-network-policy` | 1.35.5 | not enforced | ✔ (critical) | ✔ (critical) |
| flannel-kube-router | flannel v0.28.9 + kube-router v2.11.1 (firewall only) | 1.37.0 | enforced | flannel, **NONE ENFORCED** ✘ (false critical) | kube-router, enforces ✔ |
| **correct** | | | | **7 / 10** (+1 undecided) | **10 / 10** |

In every variant the same-node and cross-node probes agreed. No variant
was `partial` or `broken`. Raw output for each pass is in `pass1-c6f9f7f.tsv`,
`pass2-fixed.tsv` and `raw/<pass>/<variant>/`: DaemonSets, nodes, the
probe log, the snapshot and the audit output.

## What was wrong and how it was fixed

| Error | Cause | Fix (`internal/collector/k8s.go`) |
|---|---|---|
| Old kindnet reported as enforcing | kindnet has enforced NetworkPolicy only since kind v0.24.0, when it bundled kube-network-policies. The DaemonSet name is the same before and after. | `kindnetEnforces` reads the kindnetd image tag. kind tags it by build date (`vYYYYMMDD-…`), and it enforces from `v20240813`, the image of kind v0.24.0. Tags that can't be dated are assumed current. |
| flannel + kube-router reported as "NONE ENFORCED" | flannel was matched by DaemonSet name. The policy-only kube-router DaemonSet was not a known name. | New rule `kube-router` placed before flannel: an enforcing engine wins. It enforces unless `--run-firewall=false`. |
| Antrea not recognised | No rule for `antrea-agent`. | New rule `antrea-agent`, which enforces. |

Unit tests cover each case: `TestClassifyCNI`.

## Threats to validity

- **Same variants before and after.** The fixes were written after pass 1
  on these same variants. Pass 2 shows that the fixes work. It is not an
  independent test of the heuristic. A fresh hold-out of CNIs would be one:
  Weave, kube-ovn, AWS VPC CNI with its network policy agent, GKE Dataplane
  V2.
- **The heuristic is still a heuristic.** These cases would fool it:
  - a renamed DaemonSet;
  - a policy engine running as a Deployment or a host service;
  - an enforcing CNI configured not to enforce, such as Cilium with
    `policyEnforcementMode: never`.

  This is why every finding carries `assumes:` and `verify:`, and why the
  live deny-all probe of this experiment is the `verify` an operator
  should run.
- **Ingress only.** The probe checks ingress deny-all. An egress-only
  enforcement gap would not show up.
- **Single host.** All clusters ran in Docker on one host (kind / k3d).
