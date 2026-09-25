#!/usr/bin/env bash
# Measure one scenario on the current cluster: apply -> oracle -> delete.
# Results land in <scenario>/<cni>/{snapshot,reachability}.json.
#
# Usage: hack/scenarios/run.sh testdata/scenarios/<name> [kubeconfig]
#        KEEP=1 hack/scenarios/run.sh ...   # leave the scenario deployed
set -euo pipefail
cd "$(dirname "$0")/../.."

dir=${1:?usage: $0 testdata/scenarios/<name> [kubeconfig]}
kubeconfig=${2:-hack/demo/kubeconfig}
K="kubectl --kubeconfig=$kubeconfig"

# "external" probes come from this machine; on kind the cluster sees the
# docker network gateway as their source IP.
external_ip=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | grep -m1 '\.' || echo 203.0.113.10)

$K apply -f "$dir/manifests.yaml"
cleanup() {
  [[ ${KEEP:-} == 1 ]] || $K delete -f "$dir/manifests.yaml" --wait=true --ignore-not-found
}
trap cleanup EXIT

bin/oracle --kubeconfig "$kubeconfig" --manifests "$dir/manifests.yaml" \
  --out "$dir" --external-ip "$external_ip"
