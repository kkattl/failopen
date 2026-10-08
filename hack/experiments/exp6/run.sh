#!/usr/bin/env bash
# Experiment 6: failopen changes nothing in the cluster. A kind cluster with
# API server auditing on (every request, Metadata level); failopen runs as a
# ServiceAccount bound to a read-only ClusterRole, and every request it made
# is pulled from the audit log and tabulated by verb and resource.
#
# Usage: hack/experiments/exp6/run.sh        (KEEP=1 keeps the cluster)
#
# Results: docs/experiments/exp6/{RESULTS-table.md,audit-failopen.jsonl,rbac.yaml}
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$PWD
OUT=$ROOT/docs/experiments/exp6
CLUSTER=fo-exp6
KUBECONFIG=$ROOT/hack/.bin/kubeconfig-exp6
SA_KUBECONFIG=$ROOT/hack/.bin/kubeconfig-exp6-sa
WORK=$(mktemp -d)
mkdir -p "$OUT"
kctl() { kubectl --kubeconfig "$KUBECONFIG" "$@"; }

cleanup() {
  [[ ${KEEP:-} == 1 ]] || kind delete cluster --name "$CLUSTER"
  rm -rf "$WORK"
}
trap cleanup EXIT

cat >"$WORK/audit-policy.yaml" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Metadata
EOF

make build >/dev/null
kind create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $WORK/audit-policy.yaml
        containerPath: /etc/kubernetes/audit/policy.yaml
        readOnly: true
    kubeadmConfigPatches:
      - |
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-policy-file: /etc/kubernetes/audit/policy.yaml
            audit-log-path: /var/log/kubernetes/audit.log
          extraVolumes:
            - name: audit-policy
              hostPath: /etc/kubernetes/audit/policy.yaml
              mountPath: /etc/kubernetes/audit/policy.yaml
              readOnly: true
              pathType: File
            - name: audit-log
              hostPath: /var/log/kubernetes
              mountPath: /var/log/kubernetes
              pathType: DirectoryOrCreate
  - role: worker
EOF
kctl wait --for=condition=Ready nodes --all --timeout=300s >/dev/null

# Something to audit: one of the corpus scenarios.
kctl apply -f testdata/scenarios/demo-payments/manifests.yaml >/dev/null

# Exactly the access the README documents, nothing more.
cat >"$OUT/rbac.yaml" <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata: {name: failopen, namespace: default}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: failopen-readonly}
rules:
  - apiGroups: [""]
    resources: [pods, services, namespaces, nodes]
    verbs: [list]
  - apiGroups: [networking.k8s.io]
    resources: [networkpolicies]
    verbs: [list]
  - apiGroups: [apps]
    resources: [daemonsets]
    verbs: [list]
  - apiGroups: [crd.projectcalico.org]
    resources: [ippools]
    verbs: [list]
  - apiGroups: [""]
    resources: [configmaps]
    resourceNames: [kube-flannel-cfg, cilium-config]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: failopen-readonly}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: failopen-readonly}
subjects: [{kind: ServiceAccount, name: failopen, namespace: default}]
EOF
kctl apply -f "$OUT/rbac.yaml" >/dev/null
server=$(kctl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kctl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d >"$WORK/ca.crt"
kubectl config --kubeconfig "$SA_KUBECONFIG" set-cluster exp6 --server "$server" --certificate-authority "$WORK/ca.crt" --embed-certs >/dev/null
kubectl config --kubeconfig "$SA_KUBECONFIG" set-credentials failopen --token "$(kctl create token failopen --duration 1h)" >/dev/null
kubectl config --kubeconfig "$SA_KUBECONFIG" set-context exp6 --cluster exp6 --user failopen >/dev/null
kubectl config --kubeconfig "$SA_KUBECONFIG" use-context exp6 >/dev/null

# Let the scenario settle so the audit has the full picture, then run.
kctl wait --for=condition=Ready pod --all -A --timeout=180s >/dev/null || true
sleep 5
rc=0
bin/failopen audit --kubeconfig "$SA_KUBECONFIG" --color=never >"$OUT/audit-output.txt" || rc=$?
bin/failopen snapshot --kubeconfig "$SA_KUBECONFIG" >"$WORK/snapshot.json"
echo "failopen audit exit code: $rc" >>"$OUT/audit-output.txt"
sleep 5 # the audit backend flushes in batches

node=$CLUSTER-control-plane
docker exec "$node" cat /var/log/kubernetes/audit.log |
  python3 -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    if e.get("user", {}).get("username") == "system:serviceaccount:default:failopen":
        print(json.dumps({k: e.get(k) for k in ("stage", "verb", "requestURI", "userAgent", "responseStatus", "objectRef")}))
' >"$OUT/audit-failopen.jsonl"

python3 - "$OUT/audit-failopen.jsonl" >"$OUT/RESULTS-table.md" <<'EOF'
import collections, json, sys
rows = collections.Counter()
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e["stage"] != "ResponseComplete":
        continue
    o = e.get("objectRef") or {}
    res = (o.get("apiGroup") or "core") + "/" + o.get("resource", "?")
    rows[(e["verb"], res, e["responseStatus"]["code"])] += 1
print("| verb | resource | HTTP status | requests |")
print("|---|---|---|---|")
for (verb, res, code), n in sorted(rows.items()):
    print(f"| {verb} | {res} | {code} | {n} |")
verbs = collections.Counter(v for (v, _, _), n in rows.items() for _ in range(n))
mutating = sum(n for (v, _, _), n in rows.items() if v not in ("get", "list", "watch"))
print()
print(f"Requests by verb: {dict(verbs)}; mutating requests: {mutating}")
EOF
cat "$OUT/RESULTS-table.md"
