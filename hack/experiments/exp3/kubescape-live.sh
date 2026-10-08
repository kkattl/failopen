#!/usr/bin/env bash
# Kubescape C-0205 ("Ensure that the CNI in use supports Network Policies")
# against a LIVE cluster. Kubescape v4 reads the CNI from the nodes only
# through its operator's node-agent (CNIInfo CRDs), so the operator is
# installed first, with every capability off except what starts node-agent. Runs as experiment 2's AFTER_PROBE hook, so the same cluster
# has a measured ground truth (deny-all probe) and failopen's verdict:
#
#   PASS=kubescape-live AFTER_PROBE=hack/experiments/exp3/kubescape-live.sh \
#     hack/experiments/exp2/run.sh [variant...]
#
# Writes <raw dir>/kubescape-C-0205.json and appends a row to
# docs/experiments/exp3/live-C-0205.tsv.
set -euo pipefail
cd "$(dirname "$0")/../../.."
kubeconfig=${1:?kubeconfig} dir=${2:?raw dir}
KS=$PWD/hack/.bin/kubescape-4.0.15 # pinned and checksummed by hack/experiments/exp3/run.sh
REGOLIBRARY_VERSION=v2.0.38
OUT=docs/experiments/exp3/live-C-0205.tsv
export KS_CACHE_DIR=$PWD/hack/.bin/kscache # don't touch ~/.kubescape

OPERATOR_VERSION=1.40.5
HELM=$PWD/hack/.bin/helm

"$HELM" install kubescape kubescape-operator --repo https://kubescape.github.io/helm-charts/ \
  --version "$OPERATOR_VERSION" --kubeconfig "$kubeconfig" -n kubescape --create-namespace \
  --set clusterName="$(basename "$dir")" \
  --set capabilities.nodeProfileService=enable \
  --set capabilities.nodeSbomGeneration=disable --set capabilities.vulnerabilityScan=disable \
  --set capabilities.relevancy=disable --set capabilities.runtimeObservability=disable \
  --set capabilities.networkPolicyService=disable --set capabilities.networkEventsStreaming=disable \
  --set capabilities.admissionController=disable --set capabilities.httpDetection=disable \
  --set capabilities.seccompProfileService=disable --wait --timeout 8m >"$dir/kubescape-operator.log" 2>&1
# node-agent senses hosts on start: wait until every node it runs on has reported.
for _ in $(seq 60); do
  want=$(kubectl --kubeconfig "$kubeconfig" -n kubescape get ds node-agent -o jsonpath='{.status.desiredNumberScheduled}')
  have=$(kubectl --kubeconfig "$kubeconfig" get cniinfos --no-headers 2>/dev/null | wc -l)
  [[ $want -gt 0 && $have -ge $want ]] && break
  sleep 5
done
kubectl --kubeconfig "$kubeconfig" get cniinfos -o json >"$dir/kubescape-cniinfos.json"

[[ -f $OUT ]] || printf 'variant\tkubescape_C-0205\thost_sensor_CNINames\n' >"$OUT"
"$KS" scan control C-0205 --kubeconfig "$kubeconfig" --keep-local \
  --controls-version "$REGOLIBRARY_VERSION" --format json --output "$dir/kubescape-C-0205.json" \
  >"$dir/kubescape.log" 2>&1 || true
python3 - "$dir/kubescape-C-0205.json" "$(basename "$dir")" "$dir/kubescape-cniinfos.json" >>"$OUT" <<'PY'
import json, sys
path, variant, cni = sys.argv[1:]
try:
    r = json.load(open(path))
except Exception as e:
    print(f"{variant}\terror: {e}\t-"); sys.exit()
status = r["summaryDetails"]["controls"]["C-0205"]["status"]
names = set()
def walk(o):
    if isinstance(o, dict):
        if "CNINames" in o and isinstance(o["CNINames"], list):
            names.update(o["CNINames"])
        for v in o.values(): walk(v)
    elif isinstance(o, list):
        for v in o: walk(v)
walk(json.load(open(cni)))
print(f"{variant}\t{status}\t{','.join(sorted(names)) or '-'}")
PY
tail -1 "$OUT"
