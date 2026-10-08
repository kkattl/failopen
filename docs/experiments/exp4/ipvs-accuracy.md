## Detector × CNI (findings vs measured divergences)

| Detector | CNI / split | TP | FP | covered | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| cni | calico-ipvs | 0 | 0 | 0 | 0 | - | - | - |
| cni | ALL | 0 | 0 | 0 | 0 | - | - | - |
| cni | dev | 0 | 0 | 0 | 0 | - | - | - |
| cni | hold-out | 0 | 0 | 0 | 0 | - | - | - |
| ipblock-node-ips | calico-ipvs | 4 | 0 | 4 | 0 | 1.00 (4/4) | 1.00 (4/4) | 1.00 |
| ipblock-node-ips | ALL | 4 | 0 | 4 | 0 | 1.00 (4/4) | 1.00 (4/4) | 1.00 |
| ipblock-node-ips | dev | 3 | 0 | 3 | 0 | 1.00 (3/3) | 1.00 (3/3) | 1.00 |
| ipblock-node-ips | hold-out | 1 | 0 | 1 | 0 | 1.00 (1/1) | 1.00 (1/1) | 1.00 |
| hostnetwork-under-policy | calico-ipvs | 0 | 0 | 0 | 0 | - | - | - |
| hostnetwork-under-policy | ALL | 0 | 0 | 0 | 0 | - | - | - |
| hostnetwork-under-policy | dev | 0 | 0 | 0 | 0 | - | - | - |
| hostnetwork-under-policy | hold-out | 0 | 0 | 0 | 0 | - | - | - |
| all | calico-ipvs | 4 | 0 | 4 | 0 | 1.00 (4/4) | 1.00 (4/4) | 1.00 |
| all | ALL | 4 | 0 | 4 | 0 | 1.00 (4/4) | 1.00 (4/4) | 1.00 |
| all | dev | 3 | 0 | 3 | 0 | 1.00 (3/3) | 1.00 (3/3) | 1.00 |
| all | hold-out | 1 | 0 | 1 | 0 | 1.00 (1/1) | 1.00 (1/1) | 1.00 |

## Per scenario × CNI

| Scenario | CNI | divergences | covered | findings | TP | FP |
|---|---|---|---|---|---|---|
| ecommerce-northwind-overlap | calico-ipvs | 1 | 1 | 1 | 1 | 0 |
| health-carewell | calico-ipvs | 1 | 1 | 1 | 1 | 0 |
| known-open | calico-ipvs | 0 | 0 | 0 | 0 | 0 |
| saas-formcraft | calico-ipvs | 1 | 1 | 1 | 1 | 0 |
| saas-formcraft-etp-cluster (hold-out) | calico-ipvs | 1 | 1 | 1 | 1 | 0 |

## False positives

none

## False negatives (measured divergences no finding explains)

none

## Overblock groups (declared allow, measured dropped; fail-closed, out of failopen's scope)

- calico-ipvs: 8
