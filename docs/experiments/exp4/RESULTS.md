# Experiment 4: sensitivity to the network layer's configuration

**Question.** Do failopen's verdicts follow the network configuration they
depend on? And when failopen lacks knowledge, does severity go down rather
than up?

**Answer.**

1. **Missing knowledge never raises a verdict, and never produces a new
   critical.** Hiding the pod CIDR turns the one critical that depends on
   it into a warning. Hiding the CNI turns every verdict into a warning.
   Getting there took two fixes, both found by this experiment (see below).
2. **kube-proxy IPVS instead of iptables changes nothing that matters.**
   On 5 scenarios, 2,869 probes were re-measured on Calico. 0 differ in a
   bypass or overblock verdict, and failopen's findings are identical: 4
   TPs, 0 FPs, 0 FNs.
3. **`externalTrafficPolicy` changes reality on Cilium, but not
   failopen's verdict.** On Calico, both settings produce the same bypass,
   and failopen is right on both. On Cilium, `Cluster` opens a bypass that
   `Local` doesn't have, and failopen misses it. This is the one hold-out
   FN of experiment 1.

## 4a. Hiding or flipping inputs (offline, all 30 snapshots)

Numbers include all three detectors, `hostnetwork-under-policy` among them.
`go run ./hack/experiments/exp4` audits every corpus snapshot as captured,
and again under each transformation. It then matches findings by
(detector, subject). Full list of changes: [offline.md](offline.md).

| Transformation | unchanged | severity lowered | severity raised | finding dropped | added: warning | added: critical |
|---|---|---|---|---|---|---|
| `no-podcidr`: pod CIDR unknown | 16 | 1 | **0** | 0 | 0 | **0** |
| `unknown-cni`: CNI not recognised | 3 | 14 | **0** | 0 | 28 | **0** |
| `etp-flip`: `externalTrafficPolicy` Local ↔ Cluster | 17 | 0 | **0** | 0 | 0 | **0** |

**`no-podcidr`.** The critical in `ecommerce-northwind-overlap` becomes a
warning. Without the pod CIDR, failopen can't confirm that the rule
excludes pods, and the finding says so in `assumes:`.

**`unknown-cni`.** All 9 flannel criticals ("NONE ENFORCED") become one
warning per run, "enforcement unverified", because failopen can no longer
claim the CNI is flannel. The 28 added warnings are of three kinds:

- that same `cni` warning on Calico and Cilium snapshots (18);
- `ipblock-node-ips` warnings on Cilium and flannel snapshots (8), where
  the detector is normally switched off because the CNI is known.
- `hostnetwork-under-policy` warnings on flannel snapshots (2), for the
  same reason.

All three are what "we don't know" should look like: possible, unverified, not
critical. No exit code changes from 0 to 1.

**`etp-flip`.** No verdict moves. The detector doesn't read
`externalTrafficPolicy`, and on Calico that is right (see 4c).

### Two fixes this experiment forced

The first run of 4a contradicted the README's claim that failopen
downgrades findings when it can't confirm an assumption:

| Run 1 | Cause | Fix (`internal/detector/ipblock.go`) |
|---|---|---|
| `unknown-cni`: 3 `ipblock-node-ips` findings **dropped** (critical → nothing) | The detector returned early whenever the CNI didn't claim enforcement, and that included "unknown". | It is silent only when the CNI is known **not** to enforce. If the CNI is unknown, it reports a warning with `assumes: CNI not recognised`. Test: `TestIPBlockNodeIPsWarningOnUnknownCNI`. |
| `no-podcidr`: 2 **new** warnings on `fintech-edge/edge-proxy` (labelled `must-not`) | The detector decides whether a rule "already admits pods" by comparing it with the pod CIDR. `0.0.0.0/0` with no excepts admits every pod whatever the CIDR, but that case went through the same comparison. | `0.0.0.0/0` with no excepts counts as admitting pods without needing the CIDR. Test: `TestIPBlockNodeIPsNotForOpenInternetWithoutPodCIDR`. |

After the fixes, the corpus scores are unchanged (`make score`: 13/13,
0 FP).

## 4b. kube-proxy in IPVS mode (live, Calico)

New lab profile `calico-ipvs`: the same 7-node topology as Calico, with
kube-proxy `mode: ipvs`. The script checks the mode before measuring. Five
scenarios were measured with `hack/experiments/exp4/ipvs.sh`:

- `known-open`, the sanity check;
- the three scenarios with `ipblock-node-ips` findings;
- the eTP=Cluster mutation.

The results are in `ipvs/` and were not added to the corpus.

Probe by probe against the iptables measurement of the same scenarios
(`python3 hack/experiments/exp4/compare.py`):

| Scenario | probes | identical verdicts | differ: placement only | differ: bypass/overblock |
|---|---|---|---|---|
| known-open | 252 | 241 | 11 | 0 |
| ecommerce-northwind-overlap | 760 | 732 | 28 | 0 |
| saas-formcraft | 510 | 496 | 14 | 0 |
| saas-formcraft-etp-cluster | 510 | 484 | 26 | 0 |
| health-carewell | 837 | 817 | 20 | 0 |
| **total** | **2,869** | **2,770** | **99** | **0** |

All 99 differences come from where the scheduler placed pods in each run.
Pod placement decides three things:

- which node → pod pairs fall under the node-local spec exception
  (`spec-exception` ↔ `match`);
- which ClusterIPs have backends on several nodes (`unknown`);
- which NodePorts with `externalTrafficPolicy: Local` have a local backend
  (`unreachable` ↔ `match`).

None of these is a policy outcome.

failopen on the IPVS snapshots, scored against the IPVS measurement
(`go run ./hack/experiments/exp1 --scenarios docs/experiments/exp4/ipvs`,
[ipvs-accuracy.md](ipvs-accuracy.md)):

| | TP | FP | covered | FN |
|---|---|---|---|---|
| iptables (corpus) | 4 | 0 | 4 | 0 |
| IPVS | 4 | 0 | 4 | 0 |

The IPVS run used the oracle as of `c6f9f7f`, and was then re-read with
`oracle reclassify` (the node-refused fix from experiment 1). Re-reading
changed no probe.

## 4c. `externalTrafficPolicy` in the measurements

The corpus has a controlled pair: `saas-formcraft` (`gateway` NodePort
with `Local`) and its mutation `saas-formcraft-etp-cluster` (`Cluster`).
Nothing else differs. Probes from the `outsider` pod to the NodePort, on
all 7 nodes:

| CNI | eTP Local | eTP Cluster | failopen (both) |
|---|---|---|---|
| Calico | 1 bypass (via the backend's own node: IPIP tunnel address) | 1 bypass, same path; the other nodes now SNAT external clients → 6 **overblocks** for the external range | warning on both ✔ |
| Cilium | 0 bypass | **6 bypasses**, via every other node (the backend sees `cilium_host` addresses inside the pod CIDR) | silent on both: FN on Cluster |
| flannel | not enforced | not enforced | `cni` critical on both ✔ |

On Calico the bypass doesn't come from the eTP-controlled masquerade: the
Calico tunnel rewrites the source on the backend's own node. So ignoring
eTP is correct there. On Cilium, eTP decides the outcome, and a v0.2
detector has to read it.

## Threats to validity

- **IPVS was tested on Calico only.** Five scenarios, not the whole corpus.
- **Transformations are synthetic.** 4a hides inputs in snapshots. A real
  cluster that hides its pod CIDR may differ in other ways too.
- **The fixes and their test cases came from the same run.** They were
  checked against the full corpus afterwards, but not against an
  independent hold-out.
