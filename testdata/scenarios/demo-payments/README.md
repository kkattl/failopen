# demo-payments

The `make demo` scenario. A `payments` namespace under `default-deny-all`
(ingress) with three ways the declared isolation may not hold:

- `payments/host-probe` — hostNetwork pod inside the protected namespace.
- `monitoring/node-agent` — hostNetwork pod in another namespace, pinned to
  the node of `payments/api-server`.
- `payments/svc/api-nodeport` — NodePort in front of `api-server`.

Measured (see `<cni>/reachability.json`) rather than assumed.
