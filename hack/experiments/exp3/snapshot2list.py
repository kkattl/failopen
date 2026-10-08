#!/usr/bin/env python3
"""Turn a failopen snapshot.json into a Kubernetes `List` (YAML) so that
Kubescape can scan the objects the live cluster actually had (kube-system,
CNI agents, every running Pod) without a live cluster.

Usage: snapshot2list.py <snapshot.json> <out.yaml>
"""
import json
import sys

import yaml

KINDS = {
    "namespaces": ("v1", "Namespace"),
    "nodes": ("v1", "Node"),
    "pods": ("v1", "Pod"),
    "services": ("v1", "Service"),
    "networkPolicies": ("networking.k8s.io/v1", "NetworkPolicy"),
}


def main(src, dst):
    snap = json.load(open(src))
    docs = []
    for key, (api, kind) in KINDS.items():
        for obj in snap.get(key) or []:
            obj = dict(obj)
            obj["apiVersion"] = api
            obj["kind"] = kind
            obj.pop("status", None) if kind == "Node" else None
            docs.append(obj)
    with open(dst, "w") as f:
        yaml.safe_dump_all(docs, f, sort_keys=False)


if __name__ == "__main__":
    main(*sys.argv[1:])
