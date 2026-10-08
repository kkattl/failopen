## Detector × CNI (findings vs measured divergences)

| Detector | CNI / split | TP | FP | covered | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cni | calico | 0 | 0 | 0 | 0 | - | - | - |
| cni | cilium | 0 | 0 | 0 | 0 | - | - | - |
| cni | flannel | 9 | 0 | 9 | 0 | 1.00 (9/9) | 1.00 (9/9) | 1.00 |
| cni | ALL | 9 | 0 | 9 | 0 | 1.00 (9/9) | 1.00 (9/9) | 1.00 |
| cni | dev | 7 | 0 | 7 | 0 | 1.00 (7/7) | 1.00 (7/7) | 1.00 |
| cni | hold-out | 2 | 0 | 2 | 0 | 1.00 (2/2) | 1.00 (2/2) | 1.00 |
| ipblock-node-ips | calico | 4 | 0 | 4 | 0 | 1.00 (4/4) | 1.00 (4/4) | 1.00 |
| ipblock-node-ips | cilium | 0 | 0 | 0 | 1 | - | 0.00 (0/1) | - |
| ipblock-node-ips | flannel | 0 | 0 | 0 | 0 | - | - | - |
| ipblock-node-ips | ALL | 4 | 0 | 4 | 1 | 1.00 (4/4) | 0.80 (4/5) | 0.89 |
| ipblock-node-ips | dev | 3 | 0 | 3 | 0 | 1.00 (3/3) | 1.00 (3/3) | 1.00 |
| ipblock-node-ips | hold-out | 1 | 0 | 1 | 1 | 1.00 (1/1) | 0.50 (1/2) | 0.67 |
| all | calico | 4 | 0 | 4 | 2 | 1.00 (4/4) | 0.67 (4/6) | 0.80 |
| all | cilium | 0 | 0 | 0 | 3 | - | 0.00 (0/3) | - |
| all | flannel | 9 | 0 | 9 | 0 | 1.00 (9/9) | 1.00 (9/9) | 1.00 |
| all | ALL | 13 | 0 | 13 | 5 | 1.00 (13/13) | 0.72 (13/18) | 0.84 |
| all | dev | 10 | 0 | 10 | 4 | 1.00 (10/10) | 0.71 (10/14) | 0.83 |
| all | hold-out | 3 | 0 | 3 | 1 | 1.00 (3/3) | 0.75 (3/4) | 0.86 |

## Per scenario × CNI

| Scenario | CNI | divergences | covered | findings | TP | FP |
|---|---|---|---|---|---|---|
| demo-payments | calico | 1 | 0 | 0 | 0 | 0 |
| demo-payments | cilium | 1 | 0 | 0 | 0 | 0 |
| demo-payments | flannel | 1 | 1 | 1 | 1 | 0 |
| ecommerce-northwind | calico | 0 | 0 | 0 | 0 | 0 |
| ecommerce-northwind | cilium | 0 | 0 | 0 | 0 | 0 |
| ecommerce-northwind | flannel | 1 | 1 | 1 | 1 | 0 |
| ecommerce-northwind-overlap | calico | 1 | 1 | 1 | 1 | 0 |
| ecommerce-northwind-overlap | cilium | 0 | 0 | 0 | 0 | 0 |
| ecommerce-northwind-overlap | flannel | 1 | 1 | 1 | 1 | 0 |
| fintech-paylane | calico | 0 | 0 | 0 | 0 | 0 |
| fintech-paylane | cilium | 0 | 0 | 0 | 0 | 0 |
| fintech-paylane | flannel | 1 | 1 | 1 | 1 | 0 |
| fintech-paylane-hostnet-agent | calico | 1 | 0 | 0 | 0 | 0 |
| fintech-paylane-hostnet-agent | cilium | 1 | 0 | 0 | 0 | 0 |
| fintech-paylane-hostnet-agent | flannel | 1 | 1 | 1 | 1 | 0 |
| health-carewell | calico | 1 | 1 | 1 | 1 | 0 |
| health-carewell | cilium | 0 | 0 | 0 | 0 | 0 |
| health-carewell | flannel | 1 | 1 | 1 | 1 | 0 |
| iot-voltgrid (hold-out) | calico | 0 | 0 | 0 | 0 | 0 |
| iot-voltgrid (hold-out) | cilium | 0 | 0 | 0 | 0 | 0 |
| iot-voltgrid (hold-out) | flannel | 1 | 1 | 1 | 1 | 0 |
| known-open | calico | 0 | 0 | 0 | 0 | 0 |
| known-open | cilium | 0 | 0 | 0 | 0 | 0 |
| known-open | flannel | 0 | 0 | 0 | 0 | 0 |
| saas-formcraft | calico | 1 | 1 | 1 | 1 | 0 |
| saas-formcraft | cilium | 0 | 0 | 0 | 0 | 0 |
| saas-formcraft | flannel | 1 | 1 | 1 | 1 | 0 |
| saas-formcraft-etp-cluster (hold-out) | calico | 1 | 1 | 1 | 1 | 0 |
| saas-formcraft-etp-cluster (hold-out) | cilium | 1 | 0 | 0 | 0 | 0 |
| saas-formcraft-etp-cluster (hold-out) | flannel | 1 | 1 | 1 | 1 | 0 |

## False positives

none

## False negatives (measured divergences no finding explains)

- demo-payments / calico: `payments/host-probe` [undefined-hostnetwork] from 11 source(s): monitoring/node-agent (hostnetwork), payments/api-server (hostnetwork), node/failopen-lab-calico-worker4 (hostnetwork), node/failopen-lab-calico-worker2 (hostnetwork), … +7; target saw 172.18.0.8, 172.18.0.6, 172.18.0.4, 172.18.0.2, … +4
- demo-payments / cilium: `payments/host-probe` [undefined-hostnetwork] from 11 source(s): monitoring/node-agent (hostnetwork), payments/api-server (hostnetwork), node/failopen-lab-cilium-worker3 (hostnetwork), node/failopen-lab-cilium-control-plane (hostnetwork), … +7; target saw 172.18.0.2, 172.18.0.6, 172.18.0.7, 172.18.0.4, … +4
- fintech-paylane-hostnet-agent / calico: `fintech-ops/node-agent` [undefined-hostnetwork] from 16 source(s): fintech-ops/node-agent-79j2k (hostnetwork), fintech-ops/node-agent-jz8jn (hostnetwork), fintech-ops/node-agent-pkkgx (hostnetwork), fintech-ops/node-agent-rrfkm (hostnetwork), … +12; target saw 172.18.0.7, 172.18.0.3, 172.18.0.2, 172.18.0.6, … +5
- fintech-paylane-hostnet-agent / cilium: `fintech-ops/node-agent` [undefined-hostnetwork] from 16 source(s): fintech-ops/node-agent-627q4 (hostnetwork), fintech-ops/node-agent-6fk72 (hostnetwork), fintech-ops/node-agent-6sqmt (hostnetwork), fintech-ops/node-agent-6v9pl (hostnetwork), … +12; target saw 172.18.0.8, 172.18.0.3, 172.18.0.5, 172.18.0.6, … +5
- saas-formcraft-etp-cluster (hold-out) / cilium: `saas-edge/svc/gateway` [undefined-snat] from 1 source(s): outsider (nodeport); target saw 192.168.0.130, 192.168.5.104, 192.168.1.230, 192.168.2.227, … +2

## Overblock groups (declared allow, measured dropped; fail-closed, out of failopen's scope)

- calico: 15
- cilium: 26
- flannel: 0
