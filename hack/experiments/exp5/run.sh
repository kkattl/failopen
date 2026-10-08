#!/usr/bin/env bash
# Experiment 5 (performance): analysis time vs cluster size.
#
#   hack/experiments/exp5/run.sh                 # sizes 100 1000 10000 50000
#   SIZES="100 1000" RUNS=3 hack/experiments/exp5/run.sh
#
# For every size: generate a deterministic synthetic snapshot, time
# `failopen audit --snapshot X --color=never` end to end (RUNS runs: median,
# min, max), peak RSS via /usr/bin/time -v, file size, findings; then split
# the time into JSON load / detectors / rendering with the in-process bench.
# Runs are strictly sequential (one core busy at a time).
#
# Outputs: docs/experiments/exp5/results.csv, docs/experiments/exp5/scaling.png
# Snapshots go to hack/experiments/exp5/.data (gitignored; ~300 MB at 50k pods).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"
SIZES=${SIZES:-"100 1000 10000 50000"}
RUNS=${RUNS:-5}
SEED=${SEED:-1}
DATA=${DATA:-hack/experiments/exp5/.data}
OUT=docs/experiments/exp5
mkdir -p "$DATA" "$OUT"

make build >/dev/null
go build -o "$DATA/gen" ./hack/experiments/exp5/gen
go build -o "$DATA/bench" ./hack/experiments/exp5/bench

CSV=$OUT/results.csv
echo "pods,services,policies,namespaces,nodes,file_mb,wall_median_s,wall_min_s,wall_max_s,peak_rss_mb,load_ms,detect_ms,detect_ipblock_ms,detect_cni_ms,detect_hostnetwork_ms,render_ms,findings,critical,warning" >"$CSV"

for n in $SIZES; do
  snap=$DATA/snap-$n.json
  [ -s "$snap" ] || "$DATA/gen" -pods "$n" -seed "$SEED" -o "$snap"
  file_mb=$(awk -v b="$(stat -c %s "$snap")" 'BEGIN{printf "%.1f", b/1048576}')

  # Warm the page cache so the first timed run doesn't measure the disk.
  cat "$snap" >/dev/null

  walls=() rss_max=0
  for _ in $(seq "$RUNS"); do
    # exit 1 = critical findings present; that's a result, not an error.
    # Wall time from bash's microsecond clock (time -v only has 10 ms
    # resolution); time -v supplies the peak RSS.
    t0=$EPOCHREALTIME
    /usr/bin/time -v -o "$DATA/time.txt" bin/failopen audit --snapshot "$snap" --color=never >"$DATA/audit-$n.txt" || [ $? -eq 1 ]
    t1=$EPOCHREALTIME
    w=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.4f", b-a}')
    r=$(awk -F': ' '/Maximum resident set size/{print $2}' "$DATA/time.txt")
    walls+=("$w")
    if [ "$r" -gt "$rss_max" ]; then rss_max=$r; fi
  done
  read -r wmed wmin wmax < <(printf '%s\n' "${walls[@]}" | sort -g | awk '{a[NR]=$1} END{print a[int((NR+1)/2)], a[1], a[NR]}')
  rss_mb=$(awk -v k="$rss_max" 'BEGIN{printf "%.0f", k/1024}')

  b=$("$DATA/bench" -snapshot "$snap" -runs "$RUNS")
  j() { python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])" "$b" "$1"; }
  echo "$(j pods),$(j services),$(j policies),$(j namespaces),$(j nodes),$file_mb,$wmed,$wmin,$wmax,$rss_mb,$(j load_ms),$(j detect_ms),$(j detect_ipblock-node-ips_ms),$(j detect_cni_ms),$(j detect_hostnetwork-under-policy_ms),$(j render_ms),$(j findings),$(j critical),$(j warning)" >>"$CSV"
  echo "n=$n done: wall median ${wmed}s, rss ${rss_mb} MB, $b" >&2
done

column -s, -t "$CSV"
python3 hack/experiments/exp5/plot.py "$CSV" "$OUT/scaling.png"
