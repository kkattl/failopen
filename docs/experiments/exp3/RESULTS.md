# Experiment 3: failopen vs Kubescape vs netpol-analyzer

**Question.** On the same 10 scenarios × 3 CNIs, where reachability was
*measured* by the oracle, which tool reports the places where declared
NetworkPolicy differs from effective network behaviour?

**Short answer.**

- **failopen** reports 13 of the 21 must-label instances, with no false
  positives. The 8 it misses are the two v0.2 classes that have no detector
  yet: `hostnetwork-under-policy` and `node-exception-segment`.
- **Kubescape** reports none of the 21 in the sense the labels mean. In
  exactly those 8 instances, its C-0041 (HostNetwork access) does flag the
  object behind the problem, so it gets **partial** credit where failopen is
  silent. Its C-0205 (CNI supports NetworkPolicy) could not be evaluated
  offline. On live clusters (section 6) it was right on 7 of 10 CNIs. It
  flags flannel, but it misses old kindnet and k3s with policies disabled,
  and it raises a false alarm on flannel + kube-router.
- **netpol-analyzer** reports none of them, which is what it was built for.
  It computes declared connectivity, and it does that well: it agrees with
  the oracle's *declared* verdict on 98.7% of compared probes. It said *deny*
  on all 4,732 measured bypass probes it was compared on.

The tools answer different questions, and the comparison should be read that
way. Kubescape C-0041 and C-0260 are posture checks ("is this risky?").
netpol-analyzer answers "what does the policy allow?". failopen answers
"where does the policy not hold?".

> **Note.** This experiment's per-probe check exposed an oracle error. The
> 14 `iot-voltgrid`/Cilium hostPort "bypasses" (row 186 below) were RSTs
> from the node: the lab's Cilium never mapped hostPorts. The corpus was
> re-read with the fixed rule (`scenario.AtTarget`, `oracle reclassify`),
> and those probes are now `unreachable`. The tables below predate that
> fix. The probe counts for `iot-voltgrid` and `known-open` on Cilium
> differ accordingly; no failopen result changes. See experiment 1.

> **Update: `hostnetwork-under-policy`.** Since this comparison, failopen
> has a third detector. It covers the 4 hostNetwork-pod-under-policy
> instances, which were among the 8 that only Kubescape C-0041 partly
> flagged. failopen now reports **17 of the 21** must instances, with 0 FPs.
> The 4 still missed are `node-exception-segment`, a hostNetwork agent
> co-located with a protected namespace. C-0041 still partly flags those.
>
> These 4 are development-set results: the detector was written after the
> instances were labelled and measured. The tables below are the original
> run.

Everything here is reproduced by `hack/experiments/exp3/run.sh`. Raw outputs
are in `raw/`, and the generated tables are in
[`raw/analysis.md`](raw/analysis.md).

## Method

| | |
|---|---|
| Corpus | `testdata/scenarios/*` — 10 scenarios × {calico, cilium, flannel} = 30 measured runs, 19,926 probes |
| Ground truth | `labeling/*.expected.yaml`, written blind. **must** = a real issue (21 label × CNI instances), **may** = arguable, **must-not** = a trap |
| Measured divergence | `reachability.json` probes with `verdict: bypass` (declared deny, effective open/refused) — 5,240 probes in 19 of the 30 runs |
| failopen | `failopen audit --snapshot <s>/<cni>/snapshot.json`, built from `git archive HEAD` (c6f9f7f), so uncommitted edits in the working tree are excluded; plus `hack/score --holdout` |
| Kubescape | `kubescape scan control C-0041,C-0205,C-0260 <file> --format json --keep-local --controls-version v2.0.38`, run on (a) each `manifests.yaml`, as a CI scan would, and (b) each snapshot converted into a Kubernetes `List` (`snapshot2list.py`), which is what a live scan *without the host sensor* would see, kube-system included. C-0205 was also run alone on (a) |
| netpol-analyzer | `k8snetpolicy list --dirpath <manifests + outsider.yaml> -o json`, plus `--explain` for the must-label subjects and `--exposure` for the ipBlock scenarios. `outsider.yaml` adds the oracle's probe source, an unlabelled pod in a namespace with no policies, so every probe can be compared |
| Probe-by-probe check | `analyze.py` maps every probe to netpol-analyzer peers (pod → owning workload; Service → backing workload and target port; node → node InternalIP; external → 10.250.0.10). It then compares netpol-analyzer's allow/deny with the oracle's *declared* and *effective* verdicts. 1,026 replica-to-replica probes were skipped, because netpol-analyzer lists no workload→itself edges |

### Tool versions (pinned in `run.sh`; full record in `raw/versions.txt`)

| Tool | Version |
|---|---|
| failopen | c6f9f7f (HEAD at the time of the run) |
| Kubescape | v4.0.15, `kubescape_4.0.15_linux_amd64`, sha256 `011569db…b244`; control library regolibrary **v2.0.38** |
| netpol-analyzer | v1.4.4 (`go install github.com/np-guard/netpol-analyzer/cmd/netpolicy@v1.4.4`) |
| Go | 1.27.1 |

## 1. Scenario overview

failopen output is per CNI. Kubescape on manifests is CNI-blind, so it shows
the same result for every CNI. netpol-analyzer is CNI-blind too.

| Scenario | Measured bypass (C / Ci / F probes) | failopen (C / Ci / F) | Kubescape C-0041 (manifests) | Kubescape C-0260 (manifests) | netpol-analyzer on the relevant subject |
|---|---|---|---|---|---|
| demo-payments | 11 / 11 / 99 | — / — / **cluster** | 2: `monitoring/Pod/node-agent`, `payments/Pod/host-probe` | 1: `monitoring/Pod/node-agent` | outsider → `host-probe`: **deny**; `node-agent` → `api-server`: **deny** (measured: open) |
| ecommerce-northwind | 0 / 0 / 522 | — / — / **cluster** | 0 | 0 | declared graph only |
| ecommerce-northwind-overlap | 1 / 0 / 499 | **edge-proxy:30080** / — / **cluster** | 0 | 0 | outsider → `edge-proxy`: **deny**; `172.18.0.0/16 → edge-proxy:8080`: allow |
| fintech-paylane | 0 / 0 / 830 | — / — / **cluster** | 0 | 0 | declared graph only |
| fintech-paylane-hostnet-agent | 210 / 210 / 810 | — / — / **cluster** | 1: `fintech-ops/DaemonSet/node-agent` | 0 | outsider → `node-agent:9100`: **deny** (measured: open) |
| health-carewell | 1 / 0 / 619 | **edge-proxy:30240** (warn) / — / **cluster** | 0 | 0 | outsider → `edge-proxy`: **deny** |
| iot-voltgrid | 0 / 14 / 683 | — / — / **cluster** | 0 | 0 | declared graph only |
| known-open | 0 / 0 / 0 | — / — / — | 1: `known-open/Pod/hostnet` | 4: `web`, `client`, `hostnet`, `hostport` | — |
| saas-formcraft | 1 / 0 / 321 | **gateway:31480** (warn) / — / **cluster** | 0 | 0 | outsider → `gateway`: **deny** |
| saas-formcraft-etp-cluster | 1 / 6 / 391 | **gateway:31480** (warn) / — / **cluster** | 0 | 0 | outsider → `gateway`: **deny** |

C-0205 was not evaluated in any scenario. With C-0041/C-0260 it is silently
dropped from the summary. Run alone, it stops with
`Error: no resources found to scan`. Its rule matches only
`hostdata.kubescape.cloud/v1beta0 CNIInfo` objects, which come from the
in-cluster host sensor. A hand-written `CNIInfo` YAML is also rejected by the
file scanner. Result: **not evaluable offline.** For the record, the rule in
regolibrary v2.0.38 fails when `"Flannel" in CNINames and not "Calico" in
CNINames`. So with a live cluster and the host sensor installed, it would
plausibly catch the 9 flannel instances. This was **not verified**.

**Kubescape on the measured clusters (snapshot → List, 30 runs).** Every run
adds the cluster's own hostNetwork pods: kube-proxy, calico-node / cilium /
cilium-envoy / kube-flannel, and the static control-plane pods. C-0041 then
reports 18 (Calico), 27 (Cilium) or 18 (flannel) system objects per run, and
C-0260 reports 22, 30 or 21. In the scenario namespaces the alerts are the
manifests' alerts multiplied by pod count. For example, node-agent produces 7
C-0041 alerts, one per DaemonSet pod. Totals: C-0041 has 30 alerts in scenario
namespaces and 630 in system namespaces; C-0260 has 18 and 730.

## 2. Must labels: detected by which tool?

There are 21 instances of (must label × CNI it applies to). Full table:
[`raw/analysis.md`](raw/analysis.md#must-labels--tool-one-row-per-label--cni-it-applies-to).

| Class (instances) | Measured | failopen | Kubescape | netpol-analyzer |
|---|---|---|---|---|
| `cni-not-enforcing`, flannel (9) | 99–830 bypass probes per run | **yes 9/9** | **no 0/9**: C-0205 not evaluable offline. C-0260 reports workloads *without* policy, which is the opposite of the problem | **no 0/9**: reports declared policy as if enforced. Said *deny* on every flannel bypass probe |
| `ipblock-admits-node-ips`, calico (4): overlap, carewell, formcraft, formcraft-etp | 1 bypass probe each, `undefined-snat` | **yes 4/4** | **no 0/4**: no control looks at ipBlock or SNAT | **no 0/4**: outsider → edge is *deny*. `--exposure` shows the edge open to `0.0.0.0-192.167.255.255` (overlap: `172.18.0.0/16`). A reader who knows the node CIDR could infer the hole, but the tool does not know node IPs or model SNAT |
| `hostnetwork-under-policy`, calico+cilium (4): demo `host-probe`, fintech `node-agent` | 11 / 210 bypass probes, `undefined-hostnetwork` | **no 0/4**: no detector (v0.2) | **partial 4/4**: C-0041 flags exactly these objects, for a different reason ("pod on host network"). It does not say that the policy selecting them has no effect | **no 0/4**: models the hostNetwork pod as an ordinary policy-protected pod (*deny*) |
| `node-exception-segment`, calico+cilium (4): demo `payments`, fintech `fintech-cde` | 6 / 30 `spec-exception` probes (open by spec) | **no 0/4**: no detector (v0.2) | **partial 4/4**: C-0041 flags the agent (`monitoring/node-agent`, `fintech-ops/node-agent`), not the namespace it reaches | **no 0/4**: node-local traffic not modelled (*deny*) |
| **Total (21)** | | **13 yes, 8 no** | **0 yes, 8 partial, 13 no** | **0 yes, 21 no** |

**Kubescape finds something failopen misses, and it matters.** In the 8
instances where failopen is silent, Kubescape C-0041 points at the right
object. Kubescape doesn't explain *why* it matters here (the namespace's
default-deny doesn't cover the pod or its node). It doesn't name the
protected namespace either. Still, a person following up on the C-0041 alert
would land on the real issue. Taken together, failopen's 13 and Kubescape's 8
partials cover all 21 instances.

failopen's own score (`hack/score --holdout`) is 13/13 TP with 0 FP. That
score leaves out the classes that have no detector, and the score tool lists
them as "coverage gaps: hostnetwork-under-policy 2, node-exception-segment 2"
per scenario. Counting every must instance, failopen's recall is **13/21 =
62%**.

## 3. Kubescape alerts without a measured divergence

Kubescape's controls are posture checks. "This pod uses the host network" and
"this workload has no NetworkPolicy" are statements about risk, not claims
that declared and effective behaviour diverge. An alert that matches no
divergence is therefore **not wrong**. It answers a different question. We
count such alerts separately and do not call them false positives.

**Manifests mode (9 alerts across 10 scenarios):**

| Alert | Matches a measured divergence or a must/may label? |
|---|---|
| C-0041 `payments/Pod/host-probe` | **yes**: must f1, 11 bypass probes on each CNI |
| C-0041 `fintech-ops/DaemonSet/node-agent` | **yes**: must f1 + f2 (and may f3/f4); 210/210/371 bypass probes as target |
| C-0041 `monitoring/Pod/node-agent` | **yes**: it is the agent of must f2 (node-exception-segment). The labels mark it must-not for `hostnetwork-under-policy` (no policy selects it), but C-0041 makes no claim about policy |
| C-0260 `monitoring/Pod/node-agent` | the object matches must f2, but the remedy C-0260 implies (add a NetworkPolicy) would not help a hostNetwork pod. Counted as corresponding |
| C-0041 `known-open/Pod/hostnet` | **no**: `known-open` has no policies, so nothing to diverge from (labels: must-not) |
| C-0260 `known-open/{Deployment/web, Pod/client, Pod/hostnet, Pod/hostport}` | **no**: correct statements (none has a policy), 0 measured divergences, by design of the scenario |

So in manifests mode **4 of 9 alerts correspond** to labelled, measured
issues, and **5 have no measured divergence**. All 5 are in `known-open`,
the oracle self-test with no policies, where each is still a correct posture
statement.

**Snapshot mode (what a live scan sees):** another **630 C-0041 and 730
C-0260 alerts** on system pods across the 30 runs, about 21–30 per run per
control. None corresponds to a divergence the oracle measured. The labels
explicitly rule kube-system hostNetwork DaemonSets out of
`node-exception-segment` (must-not, e.g. demo-payments f9 and fintech f11),
because they are cluster infrastructure. These alerts count as "without a
measured divergence", not as wrong.

## 4. netpol-analyzer: declared, verified probe by probe

| | Probes |
|---|---|
| compared (all 30 runs) | 18,900 |
| agrees with the oracle's **declared** verdict | **18,657 (98.7%)** |
| agrees with the **measured** result | 12,332 (65.3%) |
| measured **bypass** probes | 4,732. netpol-analyzer: **deny on 4,732, allow on 0** |
| `spec-exception` probes (node-local, open) | 549, all *deny* in netpol-analyzer |
| measured **overblock** probes | 298. netpol-analyzer: deny on 32, allow on 266 |

The question asked was whether netpol-analyzer shows "blocked" where the
oracle measured "bypass". Yes, it does so in every case, with no exceptions.
It cannot see SNAT, hostNetwork, node-local traffic or the CNI. That is a
statement about its scope, not a bug.

**The 243 disagreements with the oracle's *declared* verdict** all have one
cause: `fintech-edge/edge-proxy` admits `ipBlock: 0.0.0.0/0`, and the probe
source is a pod. The outsider, or node-agent modelled as a pod, gives 81
probes per CNI. The oracle (policy-assistant) reads 0.0.0.0/0 as covering pod
IPs. netpol-analyzer reads ipBlock as cluster-external only. The Kubernetes
docs leave this to the implementation. **On Cilium, netpol-analyzer's reading
matched the measurement:** the oracle recorded those flows as *overblock*,
because Cilium applies CIDR rules to "world" only. That accounts for the 32
overblocks it got right. The labels file this as `may
cilium-ipblock-cluster-addrs` (fintech f6/f7). failopen has no detector for
it, so here netpol-analyzer was right about Cilium's actual behaviour where
failopen says nothing. On Calico and flannel the same flows were open, and
there netpol-analyzer is wrong in the other direction. Neither tool flags the
ambiguity itself.

## 5. Where failopen is silent although the oracle measured a bypass

| Run | Bypass groups | Label | Why failopen is silent |
|---|---|---|---|
| demo-payments calico, cilium | `payments/host-probe` hostNetwork, 11 probes each | must f1, f2 | no `hostnetwork-under-policy` / `node-exception-segment` detector yet (v0.2) |
| fintech-paylane-hostnet-agent calico, cilium | `fintech-ops/node-agent` hostNetwork, 210 probes each | must f1, f2; may f3–f5 | same |
| saas-formcraft-etp-cluster cilium | `saas-edge/svc/gateway` NodePort, `undefined-snat`, 6 probes | **may** f2 `ipblock-admits-node-ips` | the ipBlock detector doesn't fire on Cilium. The labellers expected this path (masquerade to a host address → `reserved:host`) and left it to measurement. It *was* measured open. It is a real divergence failopen misses, though it is labelled `may` and so isn't scored as a miss |
| iot-voltgrid cilium | `iot-edge/{ingest-gateway, dashboard-proxy}` hostPort, `policy`, 7 probes each, effective `refused` | may f8 (other) | node → hostPort was refused (RST) instead of dropped: the packet reached the host but no app answered. A CNI-configuration artefact (no hostPort/portmap on this Cilium) rather than an exposure |

Neither Kubescape nor netpol-analyzer reports the last two rows.

failopen was silent on 17 runs. The 6 above had measured bypasses; the other
11 measured 0 bypasses (8 Calico/Cilium runs of the agent-designed
scenarios and all 3 `known-open` runs). All 13
runs where failopen did report something had measured bypasses: it made **no
report on a run with nothing to report**.

## 6. Kubescape C-0205 on live clusters

The offline scan could not evaluate C-0205, so it was run against live
clusters too. These are the 10 distributions and CNIs of experiment 2, on
the same cluster as the deny-all probe that serves as ground truth.

Kubescape v4 reads the CNI from the nodes only through its operator, so
the Kubescape operator 1.40.5 is installed first:

- the node-agent DaemonSet runs privileged and fills `CNIInfo` CRDs from
  `/etc/cni/net.d`;
- every other capability is switched off.

Then `kubescape scan control C-0205` runs. Reproduce:

```bash
PASS=kubescape-live AFTER_PROBE=hack/experiments/exp3/kubescape-live.sh \
  hack/experiments/exp2/run.sh
```

Results: [live-C-0205.tsv](live-C-0205.tsv), and per variant
`../exp2/raw/kubescape-live/<variant>/`.

The rule (regolibrary v2.0.38) fails only for "Flannel without Calico" and
"AWS CNI alone". A CNI the node-agent can't name passes.

| Variant | Measured | Kubescape C-0205 (CNI seen) | failopen @ c6f9f7f | failopen, fixed |
|---|---|---|---|---|
| kindnet (kind v0.33) | enforced | passed (Kindnet) ✔ | ✔ | ✔ |
| kindnet-legacy (kind v0.23) | **not enforced** | passed (Kindnet) **✘ miss** | ✘ miss | ✔ critical |
| calico | enforced | passed (Calico) ✔ | ✔ | ✔ |
| cilium | enforced | passed (Cilium) ✔ | ✔ | ✔ |
| flannel | not enforced | failed (Flannel) ✔ | ✔ critical | ✔ critical |
| canal | enforced | passed (Calico, Flannel) ✔ | ✔ | ✔ |
| antrea | enforced | passed (none recognised) ✔* | unknown → warning | ✔ |
| k3s (kube-router on) | enforced | passed (none recognised) ✔* | ✔ | ✔ |
| k3s `--disable-network-policy` | **not enforced** | passed (none recognised) **✘ miss** | ✔ critical | ✔ critical |
| flannel + kube-router | enforced | failed (Flannel) **✘ false alarm** | ✘ false critical | ✔ |
| **correct** | | **7/10** (2 of them by default*) | **7/10** + 1 warning | **10/10** |

\* passed because the node-agent named no CNI, and an unnamed CNI passes
by default.

**How to read this fairly.**

- **Against the same code version.** Before the experiment 2 fixes,
  failopen and Kubescape were both right on 7 of 10. They failed on the
  same two cases: old kindnet, and kube-router next to flannel. Both tools
  look only at *which CNI is installed*. failopen's 10/10 comes from fixes
  written on these same variants, so it is not an independent result (see
  experiment 2).
- **Where they really differ.**
  - **k3s with `--disable-network-policy`.** failopen reads the k3s
    server arguments from the node annotation and reports the critical.
    Kubescape sees no CNI config it knows and passes.
  - **An unknown CNI.** failopen says "unknown, enforcement unverified"
    (a warning). Kubescape passes silently. That pass is right for Antrea
    and k3s here, but only by default.
- **Cost of the check.**
  - **Kubescape** needs its operator in the cluster: a privileged
    DaemonSet plus CRDs, and write access to install them.
  - **failopen** needs `list` on six resource types (experiment 6).

## Threats to validity

- **Different questions.** Kubescape and netpol-analyzer were not designed
  to find declared ≠ effective. "Detected" here means "would a user of the
  tool learn about this problem". Partial credit is a judgement call, and the
  reasons are spelled out per row.
- **Kubescape scanned offline in sections 1–5.** C-0205 needs the
  in-cluster host sensor, so it was run live separately (section 6).
  There it fails on plain flannel, so a live scan would have caught the 9
  flannel instances of the corpus. It was run on the experiment-2
  clusters, not on the corpus scenarios. The snapshot
  mode approximates a live scan without the host sensor, but objects are
  Pods, not their controllers. Controller-level dedup in a live scan would
  report fewer C-0041/C-0260 rows than 630/730.
- **Only three Kubescape controls.** Other controls (e.g. C-0044 host ports,
  C-0054 cluster internal networking) were not run, as the task specified.
  More coverage may exist.
- **netpol-analyzer input.** It was given `manifests.yaml` plus the oracle's
  outsider pod. It doesn't see kube-system, so egress to kube-dns appears
  only in `--exposure`. The probe mapping (Service → workload → target port,
  hostPort → containerPort) is our code. 1,026 replica-to-replica probes were
  left out, and 0 probes were unmapped.
- **Same corpus, same author.** The scenarios and labels were made for
  failopen, so the corpus is biased toward the classes failopen targets. The
  scenarios are also kind-only, iptables kube-proxy, IPv4/TCP. The
  limitations listed in `testdata/scenarios/README.md` apply.
- **failopen version.** Built from HEAD c6f9f7f. Uncommitted detector edits
  in the working tree at run time (`internal/detector/ipblock.go`) are **not**
  included.
- **Label × CNI counting.** A label that applies to two CNIs counts twice.
  Counted per label instead, failopen finds 13 of 17 must labels. The 4
  misses are demo-payments f1/f2 and fintech-paylane-hostnet-agent f1/f2.
  Kubescape gets those 4 as partial, and netpol-analyzer finds 0 of 17.

## Reproduce

```sh
hack/experiments/exp3/run.sh          # ~2 min; needs network once for tool + control downloads
# FAILOPEN_REF=<commit> to pin failopen to another commit
```

Files: `hack/experiments/exp3/{run.sh, analyze.py, snapshot2list.py, outsider.yaml}`.
Raw outputs: `docs/experiments/exp3/raw/{failopen,kubescape/{manifests,snapshot},netpol}/`, plus `summary.json` and `analysis.md`.
