#!/usr/bin/env python3
"""Generate blind-labelling templates: labeling/<scenario>.expected.yaml.

Reads ONLY testdata/scenarios/<name>/manifests.yaml (never the oracle
output) and writes an inventory of everything a labeller needs as comments,
plus an empty findings list. Existing files are never overwritten.
"""
import os
import sys

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
SCENARIOS = os.path.join(ROOT, "testdata", "scenarios")
OUT = os.path.join(ROOT, "labeling")

WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def pod_spec(obj):
    kind, spec = obj["kind"], obj.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        return spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    return spec.get("template", {}).get("spec", {})


def workload_line(obj):
    ps = pod_spec(obj)
    md = obj["metadata"]
    labels = (obj.get("spec", {}).get("template", {}).get("metadata", {}) or {}).get("labels") \
        if obj["kind"] != "Pod" else md.get("labels")
    flags = []
    if ps.get("hostNetwork"):
        flags.append("hostNetwork")
    ports = []
    for c in ps.get("containers", []):
        for p in c.get("ports", []) or []:
            s = str(p.get("containerPort"))
            if p.get("hostPort"):
                s += f"->hostPort {p['hostPort']}"
                flags.append("hostPort")
            ports.append(s)
    tol = ps.get("tolerations") or []
    if any(t.get("operator") == "Exists" and not t.get("key") for t in tol):
        flags.append("tolerates-everything")
    elif tol:
        flags.append("tolerates " + ",".join(sorted({str(t.get('value') or t.get('key')) for t in tol})))
    sel = ps.get("nodeSelector") or {}
    if sel:
        flags.append("nodeSelector " + ",".join(f"{k}={v}" for k, v in sel.items()))
    replicas = obj.get("spec", {}).get("replicas")
    rep = f" x{replicas}" if replicas else ""
    return (f"{obj['kind']} {md.get('namespace')}/{md['name']}{rep} labels={labels or {}} "
            f"ports=[{', '.join(ports)}] {' '.join(flags)}").rstrip()


def service_line(obj):
    md, spec = obj["metadata"], obj.get("spec") or {}
    t = spec.get("type", "ClusterIP")
    ports = []
    for p in spec.get("ports", []):
        s = f"{p.get('port')}->{p.get('targetPort', p.get('port'))}"
        if p.get("nodePort"):
            s += f" nodePort {p['nodePort']}"
        ports.append(s)
    extra = ""
    if t in ("NodePort", "LoadBalancer"):
        extra = f" externalTrafficPolicy={spec.get('externalTrafficPolicy', 'Cluster')}"
    sel = spec.get("selector") or "NONE (selector-less)"
    return f"Service {md.get('namespace')}/{md['name']} type={t}{extra} selector={sel} ports=[{', '.join(ports)}]"


def policy_line(obj):
    md, spec = obj["metadata"], obj.get("spec") or {}
    sel = spec.get("podSelector") or {}
    sel = sel.get("matchLabels") or sel.get("matchExpressions") or "ALL pods"
    types = spec.get("policyTypes") or ["Ingress"]
    blocks = []
    for direction in ("ingress", "egress"):
        for rule in spec.get(direction) or []:
            for peer in rule.get("from" if direction == "ingress" else "to") or []:
                if "ipBlock" in peer:
                    b = peer["ipBlock"]
                    ex = f" except {b['except']}" if b.get("except") else ""
                    ports = [f"{p.get('port')}" for p in rule.get("ports") or []] or ["all"]
                    blocks.append(f"{direction} ipBlock {b['cidr']}{ex} ports={','.join(ports)}")
    s = f"NetworkPolicy {md.get('namespace')}/{md['name']} selects={sel} types={types}"
    for b in blocks:
        s += f"\n#       {b}"
    return s


def inventory(path):
    with open(path) as f:
        docs = [d for d in yaml.safe_load_all(f) if d]
    ns = sorted(d["metadata"]["name"] for d in docs if d["kind"] == "Namespace")
    lines = ["# Namespaces: " + ", ".join(ns), "#", "# Workloads:"]
    lines += [f"#   {workload_line(d)}" for d in docs if d["kind"] in WORKLOADS]
    lines += ["#", "# Services:"]
    lines += [f"#   {service_line(d)}" for d in docs if d["kind"] == "Service"]
    lines += ["#", "# NetworkPolicies:"]
    lines += [f"#   {policy_line(d)}" for d in docs if d["kind"] == "NetworkPolicy"]
    return "\n".join(lines)


TEMPLATE = """\
# Blind labels for scenario: {name}
# Source: testdata/scenarios/{name}/manifests.yaml (+ README.md)
#
# Rules (labeling/README.md): label from the manifests and the Kubernetes
# docs ONLY. Do not open testdata/scenarios/{name}/*/reachability.json
# before this file is done. Lab facts you may use: pod CIDR 192.168.0.0/16,
# node IPs 172.18.0.0/16, external clients 10.250.0.0/24, pools
# general/edge/restricted (edge and restricted are tainted).
#
# ---------------------------------------------------------------- inventory
{inventory}
# --------------------------------------------------------------------------

scenario: {name}
labeler: ""          # your name/handle
labeled_at: ""       # YYYY-MM-DD
blind: true          # set false if you saw oracle output for this scenario first

findings: []
# One entry per finding a detector SHOULD (must), MAY (may) or must NOT
# (must-not) report. Example:
#
#  - id: f1
#    class: ipblock-admits-node-ips      # see labeling/README.md
#    subject: {{kind: Service, namespace: ns, name: svc, port: 80}}
#    mechanism: snat                     # snat | hostnetwork | node-local | cni
#    applies_to_cni: [any]               # or e.g. [calico, cilium]
#    label: must                         # must | may | must-not
#    severity: critical                  # critical | warning | info (for must/may)
#    rationale: >
#      Why, citing the spec/docs where it matters.
#    evidence: []                        # filled at reconciliation: oracle probe refs
"""


def main():
    os.makedirs(OUT, exist_ok=True)
    for name in sorted(os.listdir(SCENARIOS)):
        manifests = os.path.join(SCENARIOS, name, "manifests.yaml")
        if not os.path.isfile(manifests):
            continue
        out = os.path.join(OUT, f"{name}.expected.yaml")
        if os.path.exists(out):
            print(f"keep  {out}")
            continue
        with open(out, "w") as f:
            f.write(TEMPLATE.format(name=name, inventory=inventory(manifests)))
        print(f"wrote {out}")


if __name__ == "__main__":
    sys.exit(main())
