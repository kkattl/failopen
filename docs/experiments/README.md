# Evaluation

Six experiments on failopen. Each one has a script that reproduces it
(`hack/experiments/expN/`) and a write-up with method, raw data and
threats to validity (`expN/RESULTS.md`).

| # | Question | Result |
|---|---|---|
| [1](exp1/RESULTS.md) | Do findings match **measured** reachability? (10 scenarios × Calico / Cilium / flannel) | Precision **13/13** (95% CI 0.77–1.00), recall **13/18** (0.72). The 5 misses are classes with no detector yet: hostNetwork pods under a policy (4), and Cilium eTP=Cluster NodePort (1, found by the hold-out). |
| [2](exp2/RESULTS.md) | Is the CNI enforcement verdict right? (10 distributions/CNIs, live deny-all probe) | 7/10 on the code at `c6f9f7f`. The failures were old kindnet, Antrea, and flannel + kube-router (a false critical). After the fixes: **10/10**. |
| [3](exp3/RESULTS.md) | What do existing tools find on the same scenarios? (Kubescape C-0041/C-0205/C-0260, netpol-analyzer) | failopen 13/21 must-label instances, 0 FP. Kubescape partly flags the 8 failopen misses (C-0041 hostNetwork). netpol-analyzer computes declared connectivity correctly (98.7% agreement) and says *deny* on all 4,732 measured bypass probes. Live Kubescape C-0205 on the 10 CNIs of exp 2: 7/10. It misses old kindnet and k3s without policy, and raises a false alarm on flannel + kube-router. |
| [4](exp4/RESULTS.md) | Do verdicts follow the network configuration, and degrade safely when knowledge is missing? | Missing pod CIDR or CNI: 0 severities raised, 0 new criticals (after 2 fixes). IPVS vs iptables: 0 bypass/overblock differences in 2,869 probes, same findings. eTP matters on Cilium: 1 FN. |
| [5](exp5/RESULTS.md) | Is it fast enough for real clusters and CI? | 10,000 pods: 0.21 s. 50,000 pods: 1.2 s and 1.25 GB RSS. JSON decoding dominates. |
| [6](exp6/RESULTS.md) | Is it read-only in practice? (API server audit log) | 12 requests, all `list`, 0 mutating, under a read-only ServiceAccount. |

## What the experiments changed

The experiments found five defects, and each one was fixed. These numbers
are **after** those fixes. The write-ups give the before-and-after for
each.

| Found by | Defect | Fix |
|---|---|---|
| exp 2 | Old kindnet (kind < v0.24) reported as enforcing | kindnetd image tag date |
| exp 2 | flannel + kube-router reported as "NONE ENFORCED" | `kube-router` rule, placed before flannel |
| exp 2 | Antrea not recognised | `antrea-agent` rule |
| exp 4 | `ipblock-node-ips` dropped findings on an unknown CNI, instead of downgrading them | warning with `assumes:` |
| exp 4 | False warning on `0.0.0.0/0` when the pod CIDR is unknown | handled without the CIDR |
| exp 3 → 1 | **Oracle:** an RST from the node to an unmapped hostPort was read as "reachable" (Cilium lab) | `node-refused` outcome; corpus re-read with `oracle reclassify` |

## Not done

- **BGP (containerlab + FRR + Calico BGP).** failopen has no model of BGP
  route advertisement. It could not predict that result from static
  configuration, so the experiment would have measured the lab, not
  failopen. BGP is therefore not claimed anywhere.
- **Cloud CNIs and kube-proxy replacements** (AWS VPC CNI, GKE Dataplane
  V2, Cilium KPR) are not measured.

## Machine

All runs used one host: 8 cores, 30 GB RAM, Linux 7.0, Docker, kind
v0.33.0 (Kubernetes 1.37.0), k3d v5.9.0 (k3s v1.35.5). Pinned CNI
versions are listed in each write-up.
