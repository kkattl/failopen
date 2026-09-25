#!/usr/bin/env bash
# The whole measurement in one command: for each lab profile, bring up the
# cluster, measure every scenario, tear the cluster down; then print the
# profile x scenario summary.
#
# Usage: hack/lab/matrix.sh [profile...]        (default: all profiles)
#        KEEP_CLUSTERS=1 hack/lab/matrix.sh ...  (don't tear down)
#        SCENARIOS="demo-payments saas-formcraft" hack/lab/matrix.sh ...
set -uo pipefail
cd "$(dirname "$0")/../.."

profiles=("$@")
[[ ${#profiles[@]} -gt 0 ]] || mapfile -t profiles < <(hack/lab/lab.sh profiles)
# shellcheck disable=SC2206
scenarios=(${SCENARIOS:-})

failed=()
for p in "${profiles[@]}"; do
  echo "##### profile $p"
  if ! hack/lab/lab.sh up "$p"; then
    failed+=("$p:lab")
    continue
  fi
  hack/scenarios/run-all.sh "$(hack/lab/lab.sh kubeconfig "$p")" "$p" "${scenarios[@]}" || failed+=("$p:scenarios")
  [[ ${KEEP_CLUSTERS:-} == 1 ]] || hack/lab/lab.sh down "$p"
done

bin/oracle summary testdata/scenarios
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "FAILED: ${failed[*]}"
  exit 1
fi
