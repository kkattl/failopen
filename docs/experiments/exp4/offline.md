## Verdict changes per transformation (all scenario × CNI snapshots)

| Transformation | unchanged | severity lowered | severity raised | finding dropped | added: warning | added: critical |
|---|---|---|---|---|---|---|
| no-podcidr | 16 | 1 | 0 | 0 | 0 | 0 |
| unknown-cni | 3 | 14 | 0 | 0 | 28 | 0 |
| etp-flip | 17 | 0 | 0 | 0 | 0 | 0 |

## Every change

| Transformation | Scenario / CNI | Finding | Severity |
|---|---|---|---|
| unknown-cni | demo-payments / calico | hostnetwork-under-policy payments/host-probe | critical → warning |
| unknown-cni | demo-payments / calico | cni cluster | none → warning |
| unknown-cni | demo-payments / cilium | hostnetwork-under-policy payments/host-probe | critical → warning |
| unknown-cni | demo-payments / cilium | cni cluster | none → warning |
| unknown-cni | demo-payments / flannel | cni cluster | critical → warning |
| unknown-cni | demo-payments / flannel | hostnetwork-under-policy payments/host-probe | none → warning |
| unknown-cni | ecommerce-northwind / calico | cni cluster | none → warning |
| unknown-cni | ecommerce-northwind / cilium | cni cluster | none → warning |
| unknown-cni | ecommerce-northwind / flannel | cni cluster | critical → warning |
| no-podcidr | ecommerce-northwind-overlap / calico | ipblock-node-ips ecom-edge/svc/edge-proxy:30080 | critical → warning |
| unknown-cni | ecommerce-northwind-overlap / calico | ipblock-node-ips ecom-edge/svc/edge-proxy:30080 | critical → warning |
| unknown-cni | ecommerce-northwind-overlap / calico | cni cluster | none → warning |
| unknown-cni | ecommerce-northwind-overlap / cilium | ipblock-node-ips ecom-edge/svc/edge-proxy:30080 | none → warning |
| unknown-cni | ecommerce-northwind-overlap / cilium | cni cluster | none → warning |
| unknown-cni | ecommerce-northwind-overlap / flannel | cni cluster | critical → warning |
| unknown-cni | ecommerce-northwind-overlap / flannel | ipblock-node-ips ecom-edge/svc/edge-proxy:30080 | none → warning |
| unknown-cni | fintech-paylane / calico | cni cluster | none → warning |
| unknown-cni | fintech-paylane / cilium | cni cluster | none → warning |
| unknown-cni | fintech-paylane / flannel | cni cluster | critical → warning |
| unknown-cni | fintech-paylane-hostnet-agent / calico | hostnetwork-under-policy fintech-ops/node-agent | critical → warning |
| unknown-cni | fintech-paylane-hostnet-agent / calico | cni cluster | none → warning |
| unknown-cni | fintech-paylane-hostnet-agent / cilium | hostnetwork-under-policy fintech-ops/node-agent | critical → warning |
| unknown-cni | fintech-paylane-hostnet-agent / cilium | cni cluster | none → warning |
| unknown-cni | fintech-paylane-hostnet-agent / flannel | cni cluster | critical → warning |
| unknown-cni | fintech-paylane-hostnet-agent / flannel | hostnetwork-under-policy fintech-ops/node-agent | none → warning |
| unknown-cni | health-carewell / calico | cni cluster | none → warning |
| unknown-cni | health-carewell / cilium | cni cluster | none → warning |
| unknown-cni | health-carewell / cilium | ipblock-node-ips health-edge/svc/edge-proxy:32705 | none → warning |
| unknown-cni | health-carewell / flannel | cni cluster | critical → warning |
| unknown-cni | health-carewell / flannel | ipblock-node-ips health-edge/svc/edge-proxy:32227 | none → warning |
| unknown-cni | iot-voltgrid / calico | cni cluster | none → warning |
| unknown-cni | iot-voltgrid / cilium | cni cluster | none → warning |
| unknown-cni | iot-voltgrid / flannel | cni cluster | critical → warning |
| unknown-cni | saas-formcraft / calico | cni cluster | none → warning |
| unknown-cni | saas-formcraft / cilium | cni cluster | none → warning |
| unknown-cni | saas-formcraft / cilium | ipblock-node-ips saas-edge/svc/gateway:31480 | none → warning |
| unknown-cni | saas-formcraft / flannel | cni cluster | critical → warning |
| unknown-cni | saas-formcraft / flannel | ipblock-node-ips saas-edge/svc/gateway:31480 | none → warning |
| unknown-cni | saas-formcraft-etp-cluster / calico | cni cluster | none → warning |
| unknown-cni | saas-formcraft-etp-cluster / cilium | cni cluster | none → warning |
| unknown-cni | saas-formcraft-etp-cluster / cilium | ipblock-node-ips saas-edge/svc/gateway:31480 | none → warning |
| unknown-cni | saas-formcraft-etp-cluster / flannel | cni cluster | critical → warning |
| unknown-cni | saas-formcraft-etp-cluster / flannel | ipblock-node-ips saas-edge/svc/gateway:31480 | none → warning |
