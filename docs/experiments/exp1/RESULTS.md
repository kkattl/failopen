# Experiment 1: detector accuracy against measured reachability

**Question.** How often do failopen's static findings match what the
network actually does?

**Answer.** Every finding was confirmed by measurement: 13 of 13, with no
false positives, on 10 scenarios × 3 CNIs. The detectors explain 13 of the
18 measured divergences (recall 0.72). The 5 misses are classes failopen
has no detector for yet: hostNetwork pods under a policy (4), and one
Cilium behaviour that only the hold-out exposed (1).

> **Correction during the experiment.** A first count gave 13/20. Two of
> those "misses" were an oracle error, found by experiment 3's per-probe
> cross-check. On Cilium the lab's hostPorts were never mapped, so every
> client got an RST, with policies and without them. The RST came from the
> node, not from the pod, but the oracle read "RST in both runs" as
> "reachable". Fixed in `scenario.AtTarget`: an RST to a hostPort or
> NodePort is `node-refused`, which means unreachable. The stored corpus
> was re-read with `oracle reclassify`, with no new measurements: 65
> probes changed, all hostPort probes on Cilium (`iot-voltgrid`,
> `known-open`).

Reproduce: `go run ./hack/experiments/exp1` (full output: [raw.md](raw.md)).

## Method

- **Ground truth** is the oracle's measurement (`hack/oracle`), not the
  labels. For each scenario × CNI it probes every source → target pair from
  real pod identities, with policies in place and without them (the
  baseline). It records the source address each target saw, and compares
  the result with the policy verdict computed by policy-assistant.
- **Divergence** is the unit of truth. Bypass probes (policy says deny,
  traffic got through) are grouped by (target, basis). A target is a
  Service or a workload, and all pods of one Deployment or DaemonSet count
  as one target. If a CNI measurably enforces nothing (fewer than 10% of
  policy-denied probes are blocked), the whole run is **one** divergence,
  "policies not enforced". The hundreds of bypasses behind it are one fact
  that one person fixes.
- **Finding vs divergence.**
  - A finding is a **TP** if some divergence it explains was measured, and
    an **FP** if none was.
  - A divergence is **covered** if some finding explains it, and an **FN**
    if none does.
  - `cni` explains "not enforced".
  - `ipblock-node-ips` explains source-rewriting (`undefined-snat`)
    bypasses to its Service or workload.
- **Per-detector recall** counts only divergences of that detector's class.
  The `all` row counts every divergence, including classes that have no
  detector.
- **Spec exceptions are not counted.** The Kubernetes docs guarantee
  node-local traffic ("traffic to and from the node where a Pod is running
  is always allowed"), so it is a separate verdict, not a bypass.
- **Overblocks are reported but not scored.** These are cases where the
  policy allows traffic and the network drops it. They are fail-closed,
  outside failopen's scope.
- **Dev / hold-out split.** The detectors were developed on 8 scenarios.
  `iot-voltgrid` and `saas-formcraft-etp-cluster` were held out until the
  detectors were frozen.

Lab: kind clusters with 7 nodes (pools, taints, zones), with iptables
kube-proxy. The CNIs are Calico v3.28 (IPIP), Cilium 1.20.2 (VXLAN,
kube-proxy kept) and flannel v0.28.9.

## Results: detector × CNI

| Detector | CNI / split | TP | FP | covered | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cni | calico | 0 | 0 | 0 | 0 | – | – | – |
| cni | cilium | 0 | 0 | 0 | 0 | – | – | – |
| cni | flannel | 9 | 0 | 9 | 0 | 1.00 | 1.00 | 1.00 |
| ipblock-node-ips | calico | 4 | 0 | 4 | 0 | 1.00 | 1.00 | 1.00 |
| ipblock-node-ips | cilium | 0 | 0 | 0 | 1 | – | 0.00 | – |
| ipblock-node-ips | flannel | 0 | 0 | 0 | 0 | – | – | – |
| **all** | calico | 4 | 0 | 4 | 2 | 1.00 | 0.67 | 0.80 |
| **all** | cilium | 0 | 0 | 0 | 3 | – | 0.00 | – |
| **all** | flannel | 9 | 0 | 9 | 0 | 1.00 | 1.00 | 1.00 |
| **all** | dev | 10 | 0 | 10 | 4 | 1.00 | 0.71 | 0.83 |
| **all** | hold-out | 3 | 0 | 3 | 1 | 1.00 | 0.75 | 0.86 |
| **all** | **total** | **13** | **0** | **13** | **5** | **1.00** | **0.72** | **0.84** |

95% Wilson intervals, because the counts are small:

| Measure | Value | 95% interval |
|---|---|---|
| precision, total | 13/13 | 0.77–1.00 |
| recall, total | 13/18 | 0.49–0.88 |
| recall, dev | 10/14 | 0.45–0.88 |
| recall, hold-out | 3/4 | 0.30–0.95 |

What the cells mean:

- **Calico and Cilium rows of `cni`.** The `cni` detector stayed silent,
  which is correct: the oracle measured 100% enforcement on both. These are
  true negatives on 20 runs. The detector can't make an FP there, and the
  table can't show it.
- **Flannel row of `ipblock-node-ips`.** On flannel the detector stays
  silent on purpose, because nothing is enforced. The SNAT bypasses there
  fold into the single "not enforced" divergence, which `cni` covers.
- **Cilium row of `ipblock-node-ips`.** The detector is switched off on
  Cilium. The 0 TP / 0 FP on Cilium is that design decision, measured. On
  Cilium the same ipBlock rules **over-block** instead (26 overblock
  groups). The one SNAT FN is a different mechanism, explained below.

## False positives

None. Every finding corresponds to a measured bypass of the kind it
describes, on the Service or workload it names:

- **9 × `cni`**, one per scenario with policies on flannel.
- **4 × `ipblock-node-ips`** on Calico:
  - `ecommerce-northwind-overlap`: critical. The F5 range overlaps the
    nodes.
  - `health-carewell`, `saas-formcraft`, `saas-formcraft-etp-cluster`:
    warnings. Each is `0.0.0.0/0 except <pod CIDR>`.

## False negatives, with causes

| Scenario / CNI | Target | Basis | Cause | Detector that would catch it |
|---|---|---|---|---|
| demo-payments / calico, cilium | `payments/host-probe` | undefined-hostnetwork | A hostNetwork pod under a NetworkPolicy. The policy is not applied to the node network namespace, so every node and hostNetwork pod reaches it. The spec calls this *undefined*. | `hostnetwork-under-policy` (v0.2; already labelled, 2 `must`) |
| fintech-paylane-hostnet-agent / calico, cilium | `fintech-ops/node-agent` (DaemonSet) | undefined-hostnetwork | Same, for a DaemonSet. | same |
| saas-formcraft-etp-cluster / cilium (hold-out) | `saas-edge/svc/gateway` NodePort | undefined-snat | With `externalTrafficPolicy: Cluster`, Cilium forwards NodePort traffic between nodes. The backend sees the forwarding node's `cilium_host` address, which is in the pod CIDR (192.168.x). The rule that excludes pods then admits it. An outsider pod reaches the gateway through every node. | new: Cilium eTP=Cluster NodePort (v0.2) |

The Cilium mechanism was unknown when the detectors were frozen. The
hold-out found it, which is what it is for. It stays in the corpus as an
open FN and is not tuned away. The blind labels mark it `may`, so the
label-based score (`make score`) doesn't count it as a miss. This
measurement-based count does.

## Overblocks (not scored)

| CNI | Overblock groups |
|---|---|
| Calico | 15 |
| Cilium | 26 |
| flannel | 0 |

On Calico, the overblocks come mostly from `externalTrafficPolicy: Cluster`:
external clients are SNAT'd to a node IP, and an ipBlock for the external
range drops them. On Cilium, CIDR rules never match cluster identities.
These are availability problems, not security holes, and failopen
deliberately doesn't report them.

## Threats to validity

- **Small N.** There are 18 divergences and 13 findings, so the intervals
  above are wide. Precision 1.00 means "no FP in 13". The lower bound is
  0.77.
- **Dev-set optimism.** 10 of the 13 TPs come from scenarios the detectors
  were developed on. The hold-out has 3 TPs and 0 FPs, and recall 0.75.
- **Lab, not production.** kind on one host, iptables kube-proxy, IPv4/TCP
  only. Experiment 4 adds IPVS. Cloud CNIs are not measured.
- **Grouping choices.** The unit "divergence = (target, basis)" and the
  "not enforced = one divergence" rule move recall. Grouping by pod instead
  of workload makes recall much lower, because one DaemonSet becomes 7
  misses.
- **Lab artefact on Cilium.** hostPorts don't work in the Cilium profile:
  kube-proxy is kept and portmap isn't chained. So no hostPort result on
  Cilium says anything about policy. Those probes are now `unreachable`.
- **The oracle can be wrong.** It was, once, in this very experiment (see
  the correction above). It was caught only because a different tool
  computed declared connectivity independently.
- **Oracle independence.** The oracle and the detectors were written by
  the same team. They share no code: the oracle uses policy-assistant for
  policy semantics, and the detectors use their own. The blind labels are a
  third opinion, and they agree with the oracle with 0 disagreements
  (`make score`).
