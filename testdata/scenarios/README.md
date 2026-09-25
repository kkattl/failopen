# Scenario corpus

Ground truth for failopen's detectors: realistic clusters whose reachability
was **measured** on real CNIs rather than assumed. Format: `internal/scenario`.
Produced by `make matrix` (lab: `hack/lab`, oracle: `hack/oracle`).

| Scenario | Origin | Role |
|---|---|---|
| `known-open` | hand-made | oracle self-test: no policies, must yield 0 bypass / 0 overblock |
| `demo-payments` | hand-made, holes planted | the `make demo` story |
| `fintech-paylane`, `ecommerce-northwind`, `saas-formcraft`, `iot-voltgrid`, `health-carewell` | designed by LLM agents from persona briefs, blind to failopen | mostly **negatives**: realistic noise for false-positive measurement |
| `*-overlap`, `*-etp-cluster`, `*-hostnet-agent` | single-change mutations of the above | **positives** with ground truth by construction |

## How to read a run

Each probe is (source, target) with a `verdict` and a `basis` explaining it:
`policy` (plain NetworkPolicy semantics), `spec-exception` (node-local
traffic, always allowed by the spec), `undefined-hostnetwork`,
`undefined-snat` (the target saw a rewritten source — `observedSources`),
`mixed-path` (attempts took paths with different bases), `etp-local` (dead
by design). Probe counts are combinatorial — score detectors per divergence
group (target workload, port, exposure path, mechanism, source class), not
per probe.

## Rules

- **Frozen.** Manifests change only through a new, named mutation; results
  only through `make matrix`. Every `reachability.json` carries provenance
  (oracle commit, matcher commit, manifest hash, CNI images).
- **Hold-out.** Proposed: `iot-voltgrid` and `saas-formcraft-etp-cluster` are
  not looked at while writing detectors; they're scored once at the end.
- **Labels are written blind.** `expected.yaml` is written from manifests and
  the spec before looking at the oracle output; disagreements go to a log —
  each is either a labelling error or an oracle bug.

## Threats to validity (accepted for now)

- **LLM monoculture.** Five agents, one model, converging designs (all used
  NodePort + `externalTrafficPolicy: Local` at the edge, none used
  hostNetwork). They smoke-tested on Calico until green, so the agent
  scenarios are "cleaned against Calico". Mitigation: mutations.
- **Shared cluster during design.** Agents ran concurrently and could see
  each other's namespaces.
- **Edited scenarios.** `ecommerce-northwind` and `iot-voltgrid` had their
  external `ipBlock` moved to the lab's external network (see their
  READMEs); the original is kept as `ecommerce-northwind-overlap`.
- **kind, not a cloud.** One topology, iptables kube-proxy, no cloud load
  balancer, no VPC-routable pod IPs, IPv4/TCP only. Pod CIDR is
  192.168.0.0/16 in every profile (scenarios hardcode it).
- **Not measured at all:** egress to node/metadata addresses, UDP/DNS,
  LoadBalancer `loadBalancerSourceRanges`, CNI-specific policy CRDs
  (Calico GNP, Cilium CCNP, ANP/BANP).
