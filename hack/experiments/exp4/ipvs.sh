#!/usr/bin/env bash
# Experiment 4 (live half): the same scenarios on Calico with kube-proxy in
# IPVS mode instead of iptables. Measurements go to docs/experiments/exp4/ipvs/
# (a copy of the scenarios), not into the corpus.
#
# Usage: hack/experiments/exp4/ipvs.sh [scenario...]
# Then:  go run ./hack/experiments/exp1 --scenarios docs/experiments/exp4/ipvs
set -euo pipefail
cd "$(dirname "$0")/../../.."
OUT=docs/experiments/exp4/ipvs
SCENARIOS=("${@:-known-open ecommerce-northwind-overlap saas-formcraft saas-formcraft-etp-cluster health-carewell}")
read -r -a SCENARIOS <<<"${SCENARIOS[*]}"

make build >/dev/null
(cd hack/oracle && go build -o ../../bin/oracle .)
hack/lab/lab.sh up calico-ipvs
KUBECONFIG=$(hack/lab/lab.sh kubeconfig calico-ipvs)
mode=$(kubectl --kubeconfig "$KUBECONFIG" -n kube-system get cm kube-proxy -o jsonpath='{.data.config\.conf}' | grep -E '^mode:')
[[ $mode == *ipvs* ]] || { echo "kube-proxy is not in IPVS mode: $mode" >&2; exit 1; }

for s in "${SCENARIOS[@]}"; do
  mkdir -p "$OUT/$s"
  cp "testdata/scenarios/$s/manifests.yaml" "$OUT/$s/"
  hack/scenarios/run.sh "$OUT/$s" "$KUBECONFIG" calico-ipvs
done
