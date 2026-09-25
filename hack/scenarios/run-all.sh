#!/usr/bin/env bash
# Measure every scenario in testdata/scenarios on one cluster, sequentially
# (scenarios share the cluster; parallel runs would see each other).
#
# Usage: hack/scenarios/run-all.sh <kubeconfig> <profile> [scenario...]
set -uo pipefail
cd "$(dirname "$0")/../.."

kubeconfig=${1:?usage: $0 <kubeconfig> <profile> [scenario...]}
profile=${2:?profile required}
shift 2
scenarios=("$@")
if [[ ${#scenarios[@]} -eq 0 ]]; then
  for d in testdata/scenarios/*/; do scenarios+=("$(basename "$d")"); done
fi

failed=()
for s in "${scenarios[@]}"; do
  echo "=== $profile / $s"
  log=$(mktemp)
  if hack/scenarios/run.sh "testdata/scenarios/$s" "$kubeconfig" "$profile" >"$log" 2>&1; then
    grep -E '^[a-z0-9-]+: [0-9]+ probes' "$log"
  else
    failed+=("$s")
    grep -E '^(oracle:|\[oracle\].*failed)' "$log" || tail -5 "$log"
  fi
  rm -f "$log"
done

if [[ ${#failed[@]} -gt 0 ]]; then
  echo "FAILED: ${failed[*]}"
  exit 1
fi
