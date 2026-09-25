# known-open

Oracle self-test, not a realistic system. No NetworkPolicies at all, one of
every exposure path: pod IP, ClusterIP, NodePort with
`externalTrafficPolicy: Cluster` and `Local`, hostPort, hostNetwork.

Expected on every profile: `bypass = 0`, `overblock = 0` (everything is
declared allow). Enforced by `TestKnownAnswer` in `internal/scenario`.
