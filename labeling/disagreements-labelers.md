# Labeller disagreements (network / auditor / skeptic -> consensus)

Three blind labellers wrote `labeling/agents/<lens>/<scenario>.expected.yaml`. The merged result is
`labeling/<scenario>.expected.yaml`, where `agreed_by` names the labellers who support each label.
This file lists **only the places where the labellers were not unanimous**. A finding all three
labelled the same way, with the same CNI scope and severity, is not listed.

Legend: **M** = must, **m** = may, **X** = must-not, **—** = not labelled. Severity is shown as
`/crit`, `/warn` or `/info`. `fN` is the finding id in the consensus file.

Decision rules: majority 2 of 3. A finding only one labeller wrote is kept if it checks out against the
manifests and the docs, and is marked `single`. No majority, or a must vs must-not split, becomes `may`
and `needs-human`. Severity: majority, else the middle value. CNI scope: majority; entries are split
per CNI when the labellers diverge by CNI.

**Totals: 56 disagreement rows (plus 2 "not labelled" notes), 1 needs-human.** Most rows are single-labeller negatives (kept), CNI-scope wording
(`[any]` vs `[calico, cilium]`), or the recurring Cilium may/must-not split, which a measurement
settles. See the cross-cutting section.

Pattern that shows up in every scenario and is not repeated in each table:
- **Scope of node-exception / hostNetwork entries.** For `node-exception-segment` (all scenarios) and
  for `hostnetwork-under-policy` on demo-payments f1 and hostnet-agent f1, network wrote `[any]` and
  auditor and skeptic wrote `[calico, cilium]`. Decision: `[calico, cilium]` by majority. On flannel
  these entries are moot, because `cni-not-enforcing` already covers everything there.

---

## demo-payments

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f1 hostnetwork-under-policy host-probe:8080 | M/crit | M/crit | M/warn | M/crit | severity majority | no |
| f2 node-exception-segment payments | M/crit | M/crit | M/warn | M/crit | severity majority | no |
| f5 other api-nodeport:80 [cilium] (reserved:host after masquerade) | m/warn snat | m/warn snat | m/warn node-local | m/warn, mechanism snat | mechanism majority | no |
| f8 hostnetwork-under-policy monitoring/node-agent | — | — | X | X (single) | Checks out: no policy in `monitoring` selects it | no |
| f9 node-exception-segment kube-system/kube-proxy | — | — | X | X (single) | Consistent with the class definition. Subject not in the inventory (see cross-cutting Q4) | no |

## known-open

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f4 node-exception-segment known-open | X | — | X | X | 2 of 3 | no |
| f5 other hostport:30901 | — (see f6) | X (node-local) | X (other) | X, mechanism other | Same subject and verdict. Mechanism tie; `other` chosen | no |
| f6 ipblock-admits-node-ips hostport:30901 | X | — | — | X (single) | True by construction: there is no ipBlock | no |
| f7 other web-cluster:80 (NodePort ETP Cluster as such) | — | — | X | X (single) | No policy, so exposure is the declared state | no |
| f8 other web-local:80 | — | — | X | X (single) | Same reasoning | no |

## ecommerce-northwind

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f4 cilium-ipblock-cluster-addrs edge-proxy-ingress-from-f5 | X | — | X | X | 2 of 3. The ipBlock is external only | no |
| f5 other edge-proxy:8080 (NodePort ETP Local on non-edge nodes) | — | X | X | X | 2 of 3 | no |
| f7 kube-proxy node-exception | — | — | X | X (single) | See Q4 | no |
| f8 other ecom-storefront/web-ingress (split policies) | — | — | X | X (single) | Correct but low value | no |

## ecommerce-northwind-overlap

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f2 ipblock-admits-node-ips edge-proxy [cilium] | m/warn | m/warn | X | m/warn | 2 of 3. Settled by Cilium measurement (Q3) | no |
| f3 cilium-ipblock-cluster-addrs edge-proxy-ingress-from-f5 | m/info | — | m/info | m/info | 2 of 3 | no |
| f4 other edge-proxy-ingress-from-f5 [calico]: hostNetwork processes admitted | — | m/info | (said in rationale) | m/info (single) | Kept as may, since the traffic is strictly declared-allow. **Adjudicator moved the subject** from Service edge-proxy to the NetworkPolicy, so it does not collide with the must-not `other` entry f7 on the same Service | no |
| f7 other edge-proxy:8080 (NodePort ETP Local; lab client 10.250.0.10 denied as declared) | — | — | X (two entries) | X, merged into one | The skeptic's two must-not entries on the same class and subject were merged. The auditor labelled the NodePort half in the base scenario | no |
| f9 kube-proxy, f10 web-ingress | — | — | X | X (single) | As in the base scenario | no |

## fintech-paylane

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f5 hostnetwork-under-policy fintech-ops/node-agent | X | — | X | X | 2 of 3. The manifest says "Deliberately NOT hostNetwork" | no |
| f6 cilium-ipblock-cluster-addrs edge-proxy (0.0.0.0/0) | m/info | m/info | X | m/info | 2 of 3. The skeptic says the Cilium behaviour is closer to intent. Q3 | no |
| f7 other edge-proxy:8080 NodePort ETP Local | — | X | X | X | 2 of 3 | no |
| f8 other card-gateway:443 egress except-list | X | — | X | X | 2 of 3 | no |
| f9 other admin-panel (`ingress: []`, port-forward) | — | — | X | X (single) | port-forward is not subject to NetworkPolicy. Checks out | no |
| f10 kube-proxy | — | — | X | X (single) | Q4 | no |

## fintech-paylane-hostnet-agent

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f4 node-exception-segment fintech-edge | m/info | X | m/info | m/info | 2 of 3. The auditor's argument is strong: edge-proxy's only listener, 8080, already admits 0.0.0.0/0, so there may be nothing measurable. A may costs nothing | no |
| f5 other prometheus:9100 egress overblock | m/warn | m/info | m/info | m/info | Severity majority | no |
| **f7 cilium-ipblock-cluster-addrs edge-proxy** | m/info | — | X | **m/info** | **No majority** (1 may, 1 must-not, 1 silent). The auditor wrote may in the base scenario, and the fintech-paylane f6 decision was may 2-1 | **yes** |
| f8 other card-gateway:443 | X | — | X | X, **rationale corrected** | Both network and skeptic copied "same for fintech-ops/node-agent's egress rule" from the base scenario. That clause is wrong here: node-agent is now hostNetwork, so its egress rule is void (f1). The adjudicator removed it; the label stands | no |
| f9 other edge-proxy NodePort ETP Local | — | — | X | X (single) | The auditor labelled it in the base scenario | no |
| f10 admin-panel, f11 kube-proxy | — | — | X | X (single) | As in the base scenario. The node-local reach into admin-panel is covered by f3 | no |
| (not labelled) node-exception-segment fintech-ops | — | — | — | — | Nobody labelled it. The hostNetwork agent shares general nodes with prometheus (`ingress: []`). This is the same root cause, so it is a candidate for Q2 and not added | no |

## health-carewell

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f2 ipblock-admits-node-ips edge-proxy [cilium] | m/warn | m/warn | X | m/warn | 2 of 3. Q3 | no |
| f3 cilium-ipblock-cluster-addrs edge-proxy | m/info | m/info | X | m/info | 2 of 3. Q3 | no |
| f5 node-exception-segment health-reporting | (rationale) | (rationale) | — | X | Split out of "same for health-reporting" in the network and auditor rationales | no |
| f6 other notifications:443 egress | X | — | X | X | 2 of 3 | no |
| f7 other edge-proxy NodePort ETP Local | — | X | X | X | 2 of 3 | no |
| f8 hostnetwork-under-policy log-shipper | — | — | X | X (single) | Verified: not hostNetwork | no |
| f9 kube-proxy | — | — | X | X (single) | Q4 | no |

## iot-voltgrid

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f4 hostnetwork-under-policy iot-ops/node-agent | — | X | X | X | 2 of 3 | no |
| f5 hostnetwork-under-policy iot-edge/ingest-gateway:8883 | X | — | — | X (single) | Checks out: hostPort is not hostNetwork | no |
| f6 other ingest-gateway:9000 not published | — | X | X (in rationale) | X | 2 of 3 | no |
| f7 other ingest-gateway:8883 (hostPort is not a finding in itself) | — | — | X [any] | X **[calico, flannel]** | Single, kept. **Scope narrowed by the adjudicator** so it does not contradict f8 on Cilium | no |
| f8 other ingest-gateway:8883 [cilium] (hostPort without portmap chaining) | m/info | — | — | m/info (single) | Plausible and install-dependent. Q3 | no |
| f9 cilium-ipblock-cluster-addrs ingest-gateway (/32 external) | — | — | X | X (single) | An external /32 is exactly the world-only case | no |
| f10 other alerting:443, f11 kube-proxy | — | — | X | X (single) | Checks out / Q4 | no |

## saas-formcraft

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f2 ipblock-admits-node-ips gateway [cilium] | m/warn | m/warn | X | m/warn | 2 of 3. Q3 | no |
| f3 cilium-ipblock-cluster-addrs gateway-ingress-from-outside-cluster | m/info | m/info | X | m/info | 2 of 3. Q3 | no |
| f4–f6 node-exception-segment per tenant | X acme | X acme | X acme | X ×3 | All three wrote acme plus "same for globex and initech". **Split per tenant** by the adjudicator. Q2 | no |
| f7 other gateway NodePort ETP Local | — | X | X | X | 2 of 3 | no |
| f8 other mailer egress | X | — | X | X | 2 of 3 | no |
| f9 other billing-egress-to-tenant-apps, f10 kube-proxy | — | — | X | X (single) | Documented flow 7 / Q4 | no |

## saas-formcraft-etp-cluster

| finding | network | auditor | skeptic | decision | why | needs-human? |
|---|---|---|---|---|---|---|
| f2 ipblock-admits-node-ips gateway [cilium] | m/warn snat | m/warn snat | m/warn node-local | m/warn, snat | Mechanism majority. All three rely on the reserved:host exception, not the CIDR match (Q3) | no |
| f3 other gateway (ETP drift: every node forwards, client IP lost) [calico, cilium] | m/warn [any] | m/warn [calico,cilium] | m/info [calico] + m/info [cilium, overblock] | m/warn [calico, cilium] | Split by CNI (rule 5). Severity: warn, warn, info, so warn. The skeptic's Cilium overblock is folded into the rationale | no |
| f4 same, [flannel] | m/warn (via any) | — | — | m/info (single) | Kept as may. Mostly subsumed by cni-not-enforcing, so severity lowered to info | no |
| (absent) cilium-ipblock-cluster-addrs gateway | — | — | — | not labelled | Present as may 2-1 in the base scenario, but nobody labelled it here. Not added; Q3 | no |
| f5–f7 tenant node-exception | as base | as base | as base | X ×3 | Split per tenant | no |
| f8 mailer, f9 billing, f10 kube-proxy | X / — / — | — | X | X | 2 of 3 / single | no |

---

## Cross-cutting questions for the human

**Q1. Severity of SNAT findings when the exposed pod is a public, internet-facing proxy.**
All three labellers put `ipblock-admits-node-ips` on Calico at **warning** in overlap f1, carewell f1,
formcraft f1 and etp-cluster f1. Their reason: "the proxy is public anyway." In three of these the
author wrote an explicit guarantee that SNAT breaks:
- carewell: "pods cannot use the public path as a pivot"
- formcraft: "no pod can use the gateway to hop into a tenant"
- northwind: "any other namespace -> any ecom pod: deny"

What sits behind each proxy also differs: PHI records-api, every tenant app by Host header, or the
storefront. Policy decision needed: should severity follow (a) the exposed pod, which is public and
so gives warning, (b) what the pod forwards to, which is PHI or multi-tenant and so gives critical, or
(c) whether the author stated a pod-exclusion intent?

**Q2. Scope: per namespace or per DaemonSet when one root cause affects several segments.**
- In hostnet-agent, one hostNetwork DaemonSet produces fintech-cde (M/crit), fintech-app (m/warn),
  fintech-edge (m/info), and an unlabelled fintech-ops.
- The labellers kept per-namespace entries but said "a tool may fold it into one."
- Negatives were written "for acme, same for globex/initech" (formcraft, both variants) and "same for
  health-reporting" (carewell). The adjudicator split these per namespace.

Decide:
- Is the reportable unit `{kind: Namespace}` per affected segment, or `{kind: Workload}` for the
  offending DaemonSet with the segments listed inside?
- If per namespace, should the secondary segments be `must` or stay `may`?

**Q3. Cilium-dependent assumptions the labellers disagree on or cannot confirm.** These are settled by
measurement on the Cilium profile, not by argument.
1. `ipblock-admits-node-ips` with ETP Local on Cilium: does SNAT'd pod traffic arrive as
   `remote-node` and miss the CIDR peer? Labels: may, may, must-not in overlap f2, carewell f2 and
   formcraft f2.
2. `cilium-ipblock-cluster-addrs` on broad or node-covering ipBlocks. Is a safe-direction overblock
   worth reporting at all?
   - may, may, must-not: paylane f6, carewell f3, formcraft f3
   - may, —, may: overlap f3
   - may, —, must-not: hostnet-agent f7 (needs-human)
   - not labelled by anyone: etp-cluster
3. ETP Cluster plus iptables kube-proxy on Cilium: is a NodePort client masqueraded to a local host
   address classified as `reserved:host` and allowed past policy (allow-localhost)? All three say may
   in demo-payments f5 and etp-cluster f2. If this is measured true, both become must.
4. The node-local exception on Cilium (allow-localhost default) is assumed by all three for
   `node-exception-segment` must entries (demo-payments f2, hostnet-agent f2). It is unanimous, but
   still an assumption. Verify it.
5. hostPort on Cilium without portmap chaining or BPF hostPort. Plant flows may be dropped
   (iot-voltgrid f8, network only). This depends on the install.
6. Pod selectors that point at hostNetwork pods (prometheus -> node-agent, hostnet-agent f5): are they
   unmatched on Cilium, and also on Calico?
7. External clients entering a non-edge node with ETP Cluster: are they denied as `remote-node`
   (etp-cluster f3, skeptic)?

**Q4. Negatives on objects outside the scenario inventory.** The skeptic adds
`node-exception-segment X {kind: Workload, namespace: kube-system, name: kube-proxy}` to 9 scenarios.
It is correct in substance: system DaemonSets are excluded. However, the subject does not appear in
any manifest. Should synthetic, cluster-infrastructure negatives count in scoring, or be dropped?
They currently only guard against a detector flagging kube-system.

**Q5. Low-value `must-not` entries of class `other`.** Many single-labeller negatives say "this is
not a finding":
- NodePort ETP Local on non-edge nodes
- egress except-lists
- `ingress: []` with port-forward
- split ingress and egress policies

They are all correct, but they grow the negative set with things no planned detector would flag.
Keep them as guard rails, or limit `must-not` to things a naive detector in the v0.1/v0.2 classes
would plausibly flag?

**Q6. Should a finding carry across a mutation pair?** Several labellers labelled a finding in one
scenario of a pair and not in the other, although the mutation cannot affect it:
- the auditor's NodePort ETP Local negative in northwind and paylane, but not in overlap or
  hostnet-agent
- `cilium-ipblock-cluster-addrs` in formcraft, but not in etp-cluster

The adjudicator did not copy findings across the pair. Should the base scenario's labels be the
default for the mutant, apart from findings the mutation touches?

---

## Decisions (2026-09-24, project owner)

All six recommendations accepted:

- **Q1 — SNAT severity** follows the shape of the ipBlock: `0.0.0.0/0`-based
  ("internet, but not pods") → **warning**; a narrow external range that
  overlaps the nodes (closed allowlist, e.g. the F5 pool) → **critical**.
  Implemented in `internal/detector/ipblock.go`.
- **Q2 — scope:** one finding per root cause (the hostNetwork DaemonSet),
  listing the affected namespaces; severity from the most sensitive one.
  (v0.2 class.)
- **Q3 — Cilium assumptions:** settled by measurement, labels stay `may`.
- **Q4 — negatives on objects outside the manifests** (kube-proxy etc.):
  not scored; system namespaces are skipped by design.
- **Q5 — low-value must-nots:** kept, all scored.
- **Q6 — mutations inherit** the base scenario's labels except findings
  about the mutated object; done by the scoring tool, not by copying.
- **hostnet-agent f7:** stays `may` until Cilium is measured.
- **Applied:** `ecommerce-northwind-overlap` f1/f2 severity warning → critical (Q1).
