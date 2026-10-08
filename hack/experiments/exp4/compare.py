#!/usr/bin/env python3
"""Probe-by-probe comparison of the corpus' Calico (iptables kube-proxy)
measurements with the IPVS re-measurement in docs/experiments/exp4/ipvs.

Probes are matched by (source, target, target kind) with node and pod
names normalised (cluster prefix, ReplicaSet/pod hashes). Differences are
classified: those involving a bypass/overblock verdict matter; the rest are
spec-exception/unknown swaps caused by pods landing on different nodes.
"""
import collections, json, re, sys

SCENARIOS = ["known-open", "ecommerce-northwind-overlap", "saas-formcraft",
             "saas-formcraft-etp-cluster", "health-carewell"]
MATTERS = {"bypass", "overblock"}


def norm(s):
    s = s.replace("failopen-lab-calico-ipvs", "N").replace("failopen-lab-calico", "N")
    s = re.sub(r"-[a-z0-9]{8,10}-[a-z0-9]{5}$", "", s)
    return re.sub(r"-[a-z0-9]{5}$", "", s)


def load(path):
    m = collections.defaultdict(list)
    for p in json.load(open(path))["probes"]:
        m[(norm(p["source"]), norm(p["target"]), p["targetKind"])].append(p["verdict"])
    return m


print("| Scenario | probes | identical verdicts | differ: placement only | differ: bypass/overblock |")
print("|---|---|---|---|---|")
total = collections.Counter()
for s in SCENARIOS:
    a = load(f"testdata/scenarios/{s}/calico/reachability.json")
    b = load(f"docs/experiments/exp4/ipvs/{s}/calico-ipvs/reachability.json")
    if set(a) != set(b):
        sys.exit(f"{s}: probe sets differ")
    c = collections.Counter()
    for k in a:
        va, vb = collections.Counter(a[k]), collections.Counter(b[k])
        n, same = len(a[k]), sum((va & vb).values())
        c["probes"] += n
        c["same"] += same
        if same < n:
            kind = "matters" if set((va - vb) + (vb - va)) & MATTERS else "placement"
            c[kind] += n - same
    total += c
    print(f"| {s} | {c['probes']} | {c['same']} | {c['placement']} | {c['matters']} |")
print(f"| **total** | {total['probes']} | {total['same']} | {total['placement']} | {total['matters']} |")
