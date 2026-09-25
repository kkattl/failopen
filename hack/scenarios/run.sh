#!/usr/bin/env bash
# Measure one scenario on the current cluster: apply -> oracle -> delete.
# Results land in <scenario>/<cni>/{snapshot,reachability}.json.
#
# Usage: hack/scenarios/run.sh testdata/scenarios/<name> <kubeconfig> <profile>
#        KEEP=1 hack/scenarios/run.sh ...   # leave the scenario deployed
set -euo pipefail
cd "$(dirname "$0")/../.."

dir=${1:?usage: $0 testdata/scenarios/<name> <kubeconfig> <profile>}
kubeconfig=${2:?kubeconfig required}
profile=${3:?profile required (hack/lab/profiles)}
K="kubectl --kubeconfig=$kubeconfig"

# "External" probes come from a container outside the node network
# (see hack/lab/external.sh for why the docker gateway won't do).
cluster=$($K config current-context | sed -E 's/^(kind|k3d)-//')
hack/lab/external.sh ensure "$cluster"

$K apply -f "$dir/manifests.yaml"
cleanup() {
  [[ ${KEEP:-} == 1 ]] || $K delete -f "$dir/manifests.yaml" --wait=true --ignore-not-found
}
trap cleanup EXIT

bin/oracle --kubeconfig "$kubeconfig" --manifests "$dir/manifests.yaml" \
  --out "$dir" --external-ip 10.250.0.10 --external-container failopen-ext --profile "$profile"
