#!/usr/bin/env python3
"""Experiment 3 analysis: failopen vs Kubescape vs netpol-analyzer.

Reads the raw outputs written by run.sh, the blind labels and the oracle's
measurements, and prints Markdown tables (stdout) plus summary.json.

    analyze.py --raw docs/experiments/exp3/raw --scenarios testdata/scenarios --labels labeling
"""
import argparse
import collections
import glob
import ipaddress
import json
import os
import re

import yaml

CNIS = ["calico", "cilium", "flannel"]
EXTERNAL_IP = "10.250.0.10"           # hack/scenarios/run.sh --external-ip
OUTSIDER_PEER = "failopen-oracle/outsider[Pod]"
SYSTEM_NS = {"kube-system", "kube-flannel", "local-path-storage", "kube-public",
             "kube-node-lease", "failopen-oracle", "calico-system", "tigera-operator"}
REACHABLE = {"open", "refused"}       # hack/oracle: refused = the packet got through
# Non-system hostNetwork agents named by the node-exception-segment labels'
# rationale (labeling/*.expected.yaml).
SEGMENT_AGENT = {
    "demo-payments": ("monitoring", "node-agent"),
    "fintech-paylane-hostnet-agent": ("fintech-ops", "node-agent"),
}


# ------------------------------------------------------------------ inputs
def load_labels(d):
    out = {}
    for f in sorted(glob.glob(os.path.join(d, "*.expected.yaml"))):
        y = yaml.safe_load(open(f))
        out[y["scenario"]] = y["findings"]
    return out


def label_cnis(lbl):
    a = lbl.get("applies_to_cni") or ["any"]
    return CNIS if "any" in a else a


def manifest_workloads(path):
    """{(ns, name): kind} for pod-owning objects in manifests.yaml."""
    out = {}
    for d in yaml.safe_load_all(open(path)):
        if d and d.get("kind") in ("Pod", "Deployment", "DaemonSet", "StatefulSet",
                                   "ReplicaSet", "Job", "CronJob"):
            out[(d["metadata"].get("namespace", "default"), d["metadata"]["name"])] = d["kind"]
    return out


def owner_workload(pod):
    refs = pod["metadata"].get("ownerReferences") or []
    if not refs:
        return pod["metadata"]["name"]
    r = refs[0]
    if r["kind"] == "ReplicaSet":
        return r["name"].rsplit("-", 1)[0]
    return r["name"]


# ------------------------------------------------------------------ failopen
FO_SUBJECT = re.compile(r"^\s{2}[✗⚠ℹ!•]\s+(\S+)")


def failopen_findings(raw, s, c):
    txt = open(os.path.join(raw, "failopen", f"{s}.{c}.txt")).read()
    subj = [m.group(1) for line in txt.splitlines() if (m := FO_SUBJECT.match(line))]
    return subj


def failopen_detects(lbl, findings):
    cls, sub = lbl["class"], lbl["subject"]
    if cls == "cni-not-enforcing":
        return "cluster" in findings
    if cls == "ipblock-admits-node-ips":
        pre = f"{sub['namespace']}/svc/{sub['name']}:"
        return any(f.startswith(pre) for f in findings)
    # no detector for the other classes: does any finding name the subject?
    name = sub.get("name", "")
    return any(name and name in f for f in findings)


# ------------------------------------------------------------------ kubescape
def ks_resource(rid):
    # path=123/api=apps/v1/<ns>/<Kind>/<name>  (cluster-scoped: no ns)
    parts = rid.split("api=", 1)[-1].split("/")
    return parts[-3], parts[-2], parts[-1]


def kubescape(path):
    """{control: [(ns, kind, name)]} of failed resources, plus evaluated controls."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None
    d = json.load(open(path))
    evaluated = sorted((d.get("summaryDetails") or {}).get("controls") or {})
    failed = collections.defaultdict(list)
    for r in d.get("results") or []:
        for c in r.get("controls") or []:
            if (c.get("status") or {}).get("status") == "failed":
                failed[c["controlID"]].append(ks_resource(r["resourceID"]))
    for v in failed.values():
        v.sort()
    return {"evaluated": evaluated, "failed": dict(failed)}


def ks_log_error(path):
    try:
        for line in open(path):
            if line.startswith("Error:"):
                return line.strip()
    except FileNotFoundError:
        pass
    return ""


# ------------------------------------------------------------------ netpol-analyzer
def parse_conn(s):
    """'All Connections' | 'TCP 443,587' -> set of (proto, port) or 'ALL'."""
    if s == "All Connections":
        return "ALL"
    out, proto = set(), None
    for tok in s.split(","):
        tok = tok.strip()
        if " " in tok:
            proto, tok = tok.split(" ", 1)
        if "-" in tok:
            a, b = tok.split("-")
            out |= {(proto, p) for p in range(int(a), int(b) + 1)}
        else:
            out.add((proto, int(tok)))
    return out


def parse_peer(p):
    if p[0].isdigit():
        a, b = p.split("-")
        return ("ip", int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b)))
    return ("wl", p.split("[")[0])


class NetpolModel:
    def __init__(self, path):
        self.rules = []
        for e in json.load(open(path)) if os.path.getsize(path) else []:
            self.rules.append((parse_peer(e["src"]), parse_peer(e["dst"]), parse_conn(e["conn"])))

    def allowed(self, src, dst, port):
        """src: ('wl', 'ns/name') or ('ipaddr', '1.2.3.4'); dst: 'ns/name'."""
        for s, d, conn in self.rules:
            if d != ("wl", dst):
                continue
            if src[0] == "wl" and s != src:
                continue
            if src[0] == "ipaddr":
                ip = int(ipaddress.ip_address(src[1]))
                if s[0] != "ip" or not (s[1] <= ip <= s[2]):
                    continue
            if conn == "ALL" or ("TCP", port) in conn:
                return True
        return False


def netpol_crosscheck(scen_dir, s, c, model, workloads):
    """Compare netpol-analyzer's verdict with the oracle, probe by probe."""
    snap = json.load(open(os.path.join(scen_dir, s, c, "snapshot.json")))
    reach = json.load(open(os.path.join(scen_dir, s, c, "reachability.json")))
    pods = {f"{p['metadata']['namespace']}/{p['metadata']['name']}": p for p in snap["pods"]}
    nodes = {n["metadata"]["name"]: next(a["address"] for a in n["status"]["addresses"]
                                         if a["type"] == "InternalIP") for n in snap["nodes"]}
    svcs = {f"{x['metadata']['namespace']}/{x['metadata']['name']}": x for x in snap["services"]}

    def wl_of(podkey):
        p = pods.get(podkey)
        if not p:
            return None
        ns = p["metadata"]["namespace"]
        w = owner_workload(p)
        return f"{ns}/{w}" if (ns, w) in workloads else None

    def container_port(pod, port, by_host=False, name=None):
        for ct in pod["spec"]["containers"]:
            for cp in ct.get("ports") or []:
                if name is not None and cp.get("name") == name:
                    return cp["containerPort"]
                if by_host and cp.get("hostPort") == port:
                    return cp["containerPort"]
        return None if name is not None else port

    def source(p):
        k = p["sourceKind"]
        if k == "outsider":
            return ("wl", "failopen-oracle/outsider")
        if k == "pod":
            w = wl_of(p["source"])
            return ("wl", w) if w else None
        if k == "hostnetwork-pod":
            w = wl_of(p["source"])  # netpol-analyzer models it as an ordinary pod
            if w:
                return ("wl", w)
            pod = pods.get(p["source"])
            return ("ipaddr", pod["status"]["hostIP"]) if pod else None
        if k == "node":
            ip = nodes.get(p["source"].split("/", 1)[1])
            return ("ipaddr", ip) if ip else None
        if k == "external":
            return ("ipaddr", EXTERNAL_IP)
        return None

    def targets(p):
        """[(workload, tcp port)] the probe lands on."""
        host, port = p["address"].rsplit(":", 1)
        port = int(port)
        tk = p["targetKind"]
        if tk in ("pod-ip", "hostnetwork", "hostport"):
            pod = pods.get(p["target"])
            w = wl_of(p["target"])
            if not (pod and w):
                return []
            cp = container_port(pod, port, by_host=(tk == "hostport"))
            return [(w, cp)] if cp else []
        if tk in ("clusterip", "nodeport"):
            ns, _, name = p["target"].split("/")
            svc = svcs.get(f"{ns}/{name}")
            if not svc:
                return []
            key = "nodePort" if tk == "nodeport" else "port"
            sp = next((x for x in svc["spec"]["ports"] if x.get(key) == port), None)
            sel = svc["spec"].get("selector") or {}
            if not sp or not sel:
                return []
            out = set()
            for k, pod in pods.items():
                if pod["metadata"]["namespace"] != ns:
                    continue
                if all((pod["metadata"].get("labels") or {}).get(a) == b for a, b in sel.items()):
                    w = wl_of(k)
                    tp = sp.get("targetPort", sp["port"])
                    cp = container_port(pod, None, name=tp) if isinstance(tp, str) else tp
                    if w and cp:
                        out.add((w, cp))
            return sorted(out)
        return []

    res = collections.Counter()
    bypass_rows, dis = [], []
    for p in reach["probes"]:
        src, tg = source(p), targets(p)
        if not src or not tg:
            res["unmapped"] += 1
            continue
        if src[0] == "wl" and any(w == src[1] for w, _ in tg):
            res["same_workload"] += 1   # netpol-analyzer lists no workload->itself edges
            continue
        np_allow = any(model.allowed(src, w, port) for w, port in tg)
        eff = p["effective"] in REACHABLE
        res["mapped"] += 1
        if np_allow == (p["declared"] == "allow"):
            res["agree_declared"] += 1
        else:
            res["disagree_declared"] += 1
            dis.append((p["sourceKind"], re.sub(r"-[0-9a-f]{6,10}-[a-z0-9]{5}$|-[a-z0-9]{5}$", "", p["source"]),
                        p["targetKind"], p["target"].rsplit("-", 2)[0] if p["targetKind"] != "clusterip" and p["targetKind"] != "nodeport" else p["target"],
                        p["address"].rsplit(":", 1)[1], p["declared"], "allow" if np_allow else "deny"))
        res["agree_effective" if np_allow == eff else "disagree_effective"] += 1
        if np_allow != eff:
            res["diseff:" + p["verdict"]] += 1
        if p["verdict"] == "bypass":
            res["bypass_mapped"] += 1
            res["bypass_np_denied" if not np_allow else "bypass_np_allowed"] += 1
            bypass_rows.append((p["target"], p["targetKind"], p["basis"], p["sourceKind"],
                                "allow" if np_allow else "deny"))
        if p["verdict"] == "overblock":
            res["overblock_mapped"] += 1
            res["overblock_np_denied" if not np_allow else "overblock_np_allowed"] += 1
        if p["verdict"] == "spec-exception" and eff and not np_allow:
            res["specexc_np_denied"] += 1
    return res, dis


# ------------------------------------------------------------------ oracle
def bypass_groups(scen_dir, s, c):
    reach = json.load(open(os.path.join(scen_dir, s, c, "reachability.json")))
    snap = json.load(open(os.path.join(scen_dir, s, c, "snapshot.json")))
    owner = {f"{p['metadata']['namespace']}/{p['metadata']['name']}":
             f"{p['metadata']['namespace']}/{owner_workload(p)}" for p in snap["pods"]}
    g = collections.Counter()
    for p in reach["probes"]:
        if p["verdict"] == "bypass":
            tgt = owner.get(p["target"], p["target"])  # pod -> owning workload
            g[(tgt, p["targetKind"], p["basis"])] += 1
    total = len(reach["probes"])
    return g, total, collections.Counter(p["verdict"] for p in reach["probes"])


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--scenarios", required=True)
    ap.add_argument("--labels", required=True)
    a = ap.parse_args()

    labels = load_labels(a.labels)
    scenarios = sorted(os.path.basename(p.rstrip("/")) for p in glob.glob(os.path.join(a.scenarios, "*/")))
    summary = {"scenarios": {}, "must": [], "kubescape_alerts": [], "failopen_silent": []}
    P = print

    P("# Experiment 3 — generated tables\n")
    P("Generated by `hack/experiments/exp3/analyze.py`; do not edit by hand.\n")

    # ---------------- per scenario x CNI overview
    P("## Per scenario × CNI\n")
    P("| scenario | CNI | measured bypass (probes / groups) | failopen | Kubescape C-0041 (snapshot, scenario ns / system) | Kubescape C-0260 (snapshot, scenario ns / system) | netpol-analyzer on bypass probes (deny / mapped) |")
    P("|---|---|---|---|---|---|---|")
    np_models, np_totals = {}, collections.Counter()
    np_dis = collections.defaultdict(collections.Counter)
    for s in scenarios:
        workloads = manifest_workloads(os.path.join(a.scenarios, s, "manifests.yaml"))
        workloads[("failopen-oracle", "outsider")] = "Pod"
        np_models[s] = NetpolModel(os.path.join(a.raw, "netpol", f"{s}.list.json"))
        summary["scenarios"][s] = {}
        for c in CNIS:
            g, total, verdicts = bypass_groups(a.scenarios, s, c)
            fo = failopen_findings(a.raw, s, c)
            ks = kubescape(os.path.join(a.raw, "kubescape", "snapshot", f"{s}.{c}.json")) or {"failed": {}}
            def split(ctrl):
                objs = ks["failed"].get(ctrl, [])
                sysn = sum(1 for ns, _, _ in objs if ns in SYSTEM_NS)
                return len(objs) - sysn, sysn
            h, hs = split("C-0041")
            m, ms = split("C-0260")
            cc, rows = netpol_crosscheck(a.scenarios, s, c, np_models[s], workloads)
            np_totals.update(cc)
            for r in rows:
                np_dis[(s,) + r[:5] + (r[5], r[6])][c] += 1
            summary["scenarios"][s][c] = {
                "bypass_probes": sum(g.values()), "bypass_groups": len(g), "probes": total,
                "verdicts": dict(verdicts), "failopen": fo,
                "ks_snapshot_C0041": [h, hs], "ks_snapshot_C0260": [m, ms],
                "netpol": dict(cc),
            }
            P(f"| {s} | {c} | {sum(g.values())} / {len(g)} | {', '.join(fo) or '—'} | {h} / {hs} | {m} / {ms} | "
              f"{cc['bypass_np_denied']} / {cc['bypass_mapped']} |")
    P()

    # ---------------- Kubescape on manifests
    P("## Kubescape on manifests.yaml (offline, CNI-blind)\n")
    P("| scenario | C-0041 failed | C-0260 failed | C-0205 |")
    P("|---|---|---|---|")
    for s in scenarios:
        ks = kubescape(os.path.join(a.raw, "kubescape", "manifests", f"{s}.json"))
        err = ks_log_error(os.path.join(a.raw, "kubescape", "manifests", f"{s}.C-0205.log"))
        c205 = "not evaluated" if "C-0205" not in (ks or {}).get("evaluated", []) else "evaluated"
        if err:
            c205 += f" (alone: `{err}`)"
        f41 = ks["failed"].get("C-0041", []) if ks else []
        f260 = ks["failed"].get("C-0260", []) if ks else []
        fmt = lambda xs: f"{len(xs)}: " + ", ".join(f"{ns}/{k}/{n}" for ns, k, n in xs) if xs else "0"
        P(f"| {s} | {fmt(f41)} | {fmt(f260)} | {c205} |")
        summary["scenarios"][s]["ks_manifests"] = {"C-0041": f41, "C-0260": f260, "C-0205": c205}
    P()

    # ---------------- must labels: detected by each tool?
    P("## Must labels × tool (one row per label × CNI it applies to)\n")
    P("| scenario | label | class | subject | CNI | measured | failopen | Kubescape | netpol-analyzer |")
    P("|---|---|---|---|---|---|---|---|---|")
    det = collections.Counter()
    for s in scenarios:
        ksm = summary["scenarios"][s]["ks_manifests"]
        hostnet = {(ns, n) for ns, _, n in ksm["C-0041"]}
        for lbl in labels.get(s, []):
            if lbl["label"] != "must":
                continue
            sub = lbl["subject"]
            subj = "/".join(x for x in [sub.get("namespace"), sub.get("name")] if x) or sub["kind"]
            for c in label_cnis(lbl):
                sc = summary["scenarios"][s][c]
                fo = "yes" if failopen_detects(lbl, sc["failopen"]) else "no"
                cls = lbl["class"]
                if cls == "cni-not-enforcing":
                    ks_v = "no — C-0205 not evaluable offline"
                    np_v = f"no — reports declared policy as effective ({sc['netpol'].get('bypass_np_denied',0)}/{sc['netpol'].get('bypass_mapped',0)} bypass probes 'deny')"
                    meas = f"{sc['bypass_probes']} bypass probes"
                elif cls == "ipblock-admits-node-ips":
                    ks_v = "no — no control covers ipBlock/SNAT"
                    np_v = "no — outsider→target 'deny'; node-IP range 'allow'" if s == "ecommerce-northwind-overlap" else "no — outsider→target 'deny'"
                    meas = f"{sc['bypass_probes']} bypass probe(s), undefined-snat"
                elif cls == "hostnetwork-under-policy":
                    hit = (sub["namespace"], sub["name"]) in hostnet
                    ks_v = "partial — C-0041 flags the object as hostNetwork, not the policy gap" if hit else "no"
                    np_v = "no — models the hostNetwork pod as policy-protected ('deny')"
                    meas = f"{sc['bypass_probes']} bypass probes, undefined-hostnetwork"
                elif cls == "node-exception-segment":
                    agent = SEGMENT_AGENT.get(s)
                    hit = agent in hostnet
                    ks_v = (f"partial — C-0041 flags the agent {agent[0]}/{agent[1]}, not the namespace it reaches" if hit else "no")
                    np_v = "no — node-local traffic not modelled ('deny')"
                    meas = f"{sc['verdicts'].get('spec-exception',0)} spec-exception probes"
                else:
                    ks_v, np_v, meas = "?", "?", "?"
                det[("failopen", fo.split(' ')[0])] += 1
                det[("kubescape", ks_v.split(' ')[0])] += 1
                det[("netpol", np_v.split(' ')[0])] += 1
                summary["must"].append({"scenario": s, "id": lbl["id"], "class": cls, "cni": c,
                                        "failopen": fo, "kubescape": ks_v, "netpol": np_v})
                P(f"| {s} | {lbl['id']} | {cls} | {subj} | {c} | {meas} | {fo} | {ks_v} | {np_v} |")
    P()
    P("Totals (label × CNI instances): " + ", ".join(f"{k[0]} {k[1]}={v}" for k, v in sorted(det.items())) + "\n")
    summary["must_totals"] = {f"{k[0]}:{k[1]}": v for k, v in det.items()}

    # ---------------- Kubescape alerts vs measured divergence / labels
    P("## Kubescape alerts (manifests) against measured divergences and labels\n")
    P("An alert *corresponds* when its object is the target of a measured bypass on a "
      "policy-enforcing CNI (Calico/Cilium), or the subject/agent of a must/may label. "
      "Flannel bypasses are attributed to the cluster (cni-not-enforcing), not to objects.\n")
    P("| scenario | control | object | corresponds to | measured bypass as target (calico/cilium/flannel probes) |")
    P("|---|---|---|---|---|")
    corr = collections.Counter()
    for s in scenarios:
        ksm = summary["scenarios"][s]["ks_manifests"]
        mm = [l for l in labels.get(s, []) if l["label"] in ("must", "may")]
        mn = [l for l in labels.get(s, []) if l["label"] == "must-not"]
        groups = {c: bypass_groups(a.scenarios, s, c)[0] for c in CNIS}
        for ctrl in ("C-0041", "C-0260"):
            for ns, kind, name in ksm[ctrl]:
                hits = []
                for c in CNIS:
                    n = sum(v for (t, _, _), v in groups[c].items() if t == f"{ns}/{name}")
                    hits.append(n)
                why = []
                for l in mm:
                    sub = l["subject"]
                    if (sub.get("namespace"), sub.get("name")) == (ns, name):
                        why.append(f"{l['label']} {l['id']} {l['class']}")
                if SEGMENT_AGENT.get(s) == (ns, name):
                    why += [f"{l['label']} {l['id']} node-exception-segment (agent)" for l in mm
                            if l["class"] == "node-exception-segment"]
                neg = [f"must-not {l['id']} {l['class']}" for l in mn
                       if (l["subject"].get("namespace"), l["subject"].get("name")) == (ns, name)]
                enforcing_hit = hits[0] + hits[1] > 0
                status = "yes" if (why or enforcing_hit) else "no"
                corr[(ctrl, status)] += 1
                summary["kubescape_alerts"].append({"scenario": s, "control": ctrl, "object": f"{ns}/{kind}/{name}",
                                                    "corresponds": status, "labels": why, "must_not": neg,
                                                    "bypass_probes_as_target": hits})
                P(f"| {s} | {ctrl} | {ns}/{kind}/{name} | {'; '.join(why) or ('measured bypass' if enforcing_hit else '**none**')}"
                  f"{' (labels: ' + '; '.join(neg) + ')' if neg else ''} | {'/'.join(map(str, hits))} |")
    P()
    P("Totals: " + ", ".join(f"{k[0]} corresponds={k[1]}: {v}" for k, v in sorted(corr.items())) + "\n")
    summary["kubescape_alert_totals"] = {f"{k[0]}:{k[1]}": v for k, v in corr.items()}

    # ---------------- failopen silent where something was measured
    P("## Where failopen is silent but the oracle measured a bypass\n")
    P("| scenario | CNI | bypass groups (target, kind, basis: probes) | labels covering it |")
    P("|---|---|---|---|")
    for s in scenarios:
        for c in CNIS:
            sc = summary["scenarios"][s][c]
            if sc["failopen"] or not sc["bypass_probes"]:
                continue
            g, _, _ = bypass_groups(a.scenarios, s, c)
            gs = "; ".join(f"{t} {k} {b}: {n}" for (t, k, b), n in sorted(g.items()))
            cov = [f"{l['label']} {l['id']} {l['class']}" for l in labels.get(s, [])
                   if l["label"] in ("must", "may") and c in label_cnis(l)
                   and l["class"] != "cni-not-enforcing"]
            summary["failopen_silent"].append({"scenario": s, "cni": c, "groups": gs, "labels": cov})
            P(f"| {s} | {c} | {gs} | {'; '.join(cov) or '—'} |")
    P()

    # ---------------- netpol cross-check totals
    P("## netpol-analyzer vs oracle, probe by probe (all scenarios × CNIs)\n")
    t = np_totals
    P(f"- probes: {t['mapped'] + t['unmapped'] + t['same_workload']}; compared: {t['mapped']}; "
      f"skipped: {t['same_workload']} replica-to-replica of one workload (netpol-analyzer lists no "
      f"self edges), {t['unmapped']} unmapped")
    P(f"- agrees with the oracle's **declared** verdict: {t['agree_declared']} / {t['mapped']}"
      f" (disagrees: {t['disagree_declared']})")
    P(f"- agrees with the **measured** (effective) result: {t['agree_effective']} / {t['mapped']}"
      f" (disagrees: {t['disagree_effective']})")
    P("  - by oracle verdict: " + ", ".join(f"{k.split(':')[1]} {v}" for k, v in sorted(t.items()) if k.startswith("diseff:")))
    P(f"- measured bypass probes: {t['bypass_mapped']}; netpol-analyzer says *deny* on {t['bypass_np_denied']}, *allow* on {t['bypass_np_allowed']}")
    P(f"- measured overblock probes: {t['overblock_mapped']}; netpol-analyzer says *deny* on {t['overblock_np_denied']}, *allow* on {t['overblock_np_allowed']}")
    P(f"- spec-exception probes that were open but netpol-analyzer says *deny*: {t['specexc_np_denied']}\n")
    P("### Where netpol-analyzer and the oracle's *declared* verdict differ\n")
    P("| scenario | source kind | source | target kind | target | port | oracle declared | netpol-analyzer | probes calico/cilium/flannel |")
    P("|---|---|---|---|---|---|---|---|---|")
    for k, v in sorted(np_dis.items()):
        P("| " + " | ".join(map(str, k)) + f" | {v['calico']}/{v['cilium']}/{v['flannel']} |")
    P()
    summary["netpol_totals"] = dict(t)

    with open(os.path.join(a.raw, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1, default=list)


if __name__ == "__main__":
    main()
