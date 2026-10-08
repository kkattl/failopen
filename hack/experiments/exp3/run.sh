#!/usr/bin/env bash
# Experiment 3: failopen vs Kubescape vs netpol-analyzer on the scenario corpus.
#
# Offline only: every tool reads files (manifests.yaml, snapshot.json); no
# cluster is contacted. Tool binaries go to hack/.bin (gitignored).
# Network is needed once, to download the pinned tools and Kubescape's
# pinned control library.
#
#   hack/experiments/exp3/run.sh            # everything -> docs/experiments/exp3/raw
#
# Requirements: go, curl, python3 with PyYAML.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
HERE=hack/experiments/exp3
BIN="$ROOT/hack/.bin"
OUT="$ROOT/docs/experiments/exp3/raw"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- pinned tools
KUBESCAPE_VERSION=4.0.15
KUBESCAPE_SHA256=011569dbcde85afc96cf63262e4f967166b6680fd70a623e9065334b6767b244
REGOLIBRARY_VERSION=v2.0.38           # Kubescape --controls-version
NETPOL_ANALYZER_VERSION=v1.4.4        # github.com/np-guard/netpol-analyzer
CONTROLS=C-0041,C-0205,C-0260
CNIS=(calico cilium flannel)

mkdir -p "$BIN" "$OUT"/{failopen,kubescape/manifests,kubescape/snapshot,netpol}

KS="$BIN/kubescape-$KUBESCAPE_VERSION"
if [[ ! -x "$KS" ]]; then
  curl -sSfL -o "$KS.tmp" \
    "https://github.com/kubescape/kubescape/releases/download/v$KUBESCAPE_VERSION/kubescape_${KUBESCAPE_VERSION}_linux_amd64"
  echo "$KUBESCAPE_SHA256  $KS.tmp" | sha256sum -c -
  chmod +x "$KS.tmp" && mv "$KS.tmp" "$KS"
fi
NP="$BIN/netpolicy-$NETPOL_ANALYZER_VERSION"
if [[ ! -x "$NP" ]]; then
  (cd "$WORK" && GOBIN="$WORK/gobin" go install \
    "github.com/np-guard/netpol-analyzer/cmd/netpolicy@$NETPOL_ANALYZER_VERSION")
  mv "$WORK/gobin/netpolicy" "$NP"
fi
export KS_CACHE_DIR="$WORK/kscache"   # don't touch ~/.kubescape

{
  echo "date: $(date -u +%FT%TZ)"
  echo "failopen: $(git rev-parse --short "${FAILOPEN_REF:-HEAD}") (built from git archive; working-tree edits not included)"
  echo "kubescape: $KUBESCAPE_VERSION (sha256 $KUBESCAPE_SHA256), controls: regolibrary $REGOLIBRARY_VERSION"
  "$KS" version 2>&1 | sed 's/^/  /'
  echo "netpol-analyzer: $NETPOL_ANALYZER_VERSION ($(go version -m "$NP" | awk '/^\tmod/{print $2, $3}'))"
  echo "go: $(go version)"
} > "$OUT/versions.txt"

# ---------------------------------------------------------------- failopen
# Built from the committed tree (git archive, read-only), not the working
# tree, so that concurrent uncommitted edits don't leak into the results.
FAILOPEN_REF="${FAILOPEN_REF:-HEAD}"
FO_SRC="$WORK/failopen-src"
mkdir -p "$FO_SRC"
git archive "$FAILOPEN_REF" | tar -x -C "$FO_SRC"
(cd "$FO_SRC" && go build -o "$WORK/failopen" ./cmd/failopen)
SCENARIOS=()
for d in testdata/scenarios/*/; do SCENARIOS+=("$(basename "$d")"); done

for s in "${SCENARIOS[@]}"; do
  for c in "${CNIS[@]}"; do
    "$WORK/failopen" audit --snapshot "testdata/scenarios/$s/$c/snapshot.json" --color=never \
      > "$OUT/failopen/$s.$c.txt" 2>&1 || true   # exit 1 = critical findings
  done
done
(cd "$FO_SRC" && go run ./hack/score --labels "$ROOT/labeling" --scenarios "$ROOT/testdata/scenarios" --holdout) \
  > "$OUT/failopen/score-holdout.txt"

# ---------------------------------------------------------------- kubescape
ks_scan() { # <input> <out-prefix> <controls>
  "$KS" scan control "$3" "$1" --format json --output "$2.json" --keep-local \
    --controls-version "$REGOLIBRARY_VERSION" > "$2.log" 2>&1 || echo "exit=$?" >> "$2.log"
}
for s in "${SCENARIOS[@]}"; do
  # (a) the scenario manifests, as asked: what a CI/IaC scan would see
  ks_scan "testdata/scenarios/$s/manifests.yaml" "$OUT/kubescape/manifests/$s" "$CONTROLS"
  # C-0205 alone: shows whether it can be evaluated from files at all
  ks_scan "testdata/scenarios/$s/manifests.yaml" "$OUT/kubescape/manifests/$s.C-0205" C-0205
  # (b) the objects of the measured cluster (snapshot -> List): what a live
  #     scan without the host sensor would see, kube-system included
  for c in "${CNIS[@]}"; do
    python3 "$HERE/snapshot2list.py" "testdata/scenarios/$s/$c/snapshot.json" "$WORK/$s.$c.yaml"
    ks_scan "$WORK/$s.$c.yaml" "$OUT/kubescape/snapshot/$s.$c" "$CONTROLS"
  done
done

# ---------------------------------------------------------------- netpol-analyzer
# Input: the scenario manifests plus the oracle's "outsider" pod (an
# unlabelled pod in a namespace without policies), so its answer can be
# compared probe by probe with the oracle.
for s in "${SCENARIOS[@]}"; do
  mkdir -p "$WORK/np/$s"
  cp "testdata/scenarios/$s/manifests.yaml" "$HERE/outsider.yaml" "$WORK/np/$s/"
  "$NP" list --dirpath "$WORK/np/$s" -o json -f "$OUT/netpol/$s.list.json" > "$OUT/netpol/$s.log" 2>&1 || echo "exit=$?" >> "$OUT/netpol/$s.log"
  "$NP" list --dirpath "$WORK/np/$s" -o txt > "$OUT/netpol/$s.list.txt" 2>>"$OUT/netpol/$s.log" || true
done
# Explanations for the subjects of the must labels
explain() { # <scenario> <target workload> <peer> <tag>
  "$NP" list --dirpath "$WORK/np/$1" --focusworkload "$2" --focusworkload-peer "$3" --explain \
    > "$OUT/netpol/$1.explain.$4.txt" 2>&1 || true
}
explain ecommerce-northwind-overlap ecom-edge/edge-proxy failopen-oracle/outsider outsider-to-edge-proxy
explain health-carewell             health-edge/edge-proxy failopen-oracle/outsider outsider-to-edge-proxy
explain saas-formcraft              saas-edge/gateway failopen-oracle/outsider outsider-to-gateway
explain saas-formcraft-etp-cluster  saas-edge/gateway failopen-oracle/outsider outsider-to-gateway
explain demo-payments               payments/host-probe failopen-oracle/outsider outsider-to-host-probe
explain demo-payments               payments/api-server monitoring/node-agent node-agent-to-api-server
explain fintech-paylane-hostnet-agent fintech-ops/node-agent failopen-oracle/outsider outsider-to-node-agent
for s in ecommerce-northwind-overlap health-carewell saas-formcraft saas-formcraft-etp-cluster; do
  "$NP" list --dirpath "$WORK/np/$s" --exposure > "$OUT/netpol/$s.exposure.txt" 2>&1 || true
done

# ---------------------------------------------------------------- analysis
python3 "$HERE/analyze.py" --raw "$OUT" --scenarios testdata/scenarios --labels labeling \
  > "$OUT/analysis.md"
echo "done: $OUT"
