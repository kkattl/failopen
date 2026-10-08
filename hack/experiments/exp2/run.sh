#!/usr/bin/env bash
# Experiment 2: does failopen's CNI heuristic tell the truth about policy
# enforcement? For every variant: a small cluster (1 control plane + 2
# workers), a deny-all-ingress probe from the same node and from another
# node, and failopen's own verdict from a live snapshot.
#
# Usage: hack/experiments/exp2/run.sh [variant...]   (default: all)
#        hack/experiments/exp2/run.sh list
#
# Results: docs/experiments/exp2/$PASS.tsv, raw output per variant in
# docs/experiments/exp2/raw/$PASS/<variant>/. Each cluster is deleted afterwards
# unless KEEP=1.
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$PWD
BIN=$ROOT/hack/.bin
OUT=$ROOT/docs/experiments/exp2
# FAILOPEN: the binary under test (default: a fresh build of the tree);
# PASS: name of this run, one per code version: results in $PASS.tsv and raw/$PASS/.
FAILOPEN=${FAILOPEN:-}
PASS=${PASS:-results}
AGNHOST=registry.k8s.io/e2e-test-images/agnhost:2.53
LEGACY_KIND_VERSION=v0.23.0 # last kind whose kindnet did not enforce NetworkPolicy
ANTREA_VERSION=2.7.0
CANAL_VERSION=v3.28.0
KUBE_ROUTER_IMAGE=docker.io/cloudnativelabs/kube-router:v2.11.1

VARIANTS=(kindnet kindnet-legacy calico cilium flannel canal antrea k3s k3s-no-policy flannel-kube-router)

# --- helpers shared with hack/lab/lab.sh (profiles call kctl/fetch/tool) ---

kctl() { kubectl --kubeconfig "$KUBECONFIG" "$@"; }

fetch() {
  mkdir -p "$BIN/cache"
  local out
  out=$BIN/cache/$(basename "$1")
  [[ -s $out ]] || curl -fsSL -o "$out" "$1"
  echo "$out"
}

tool() {
  case $1 in
  helm)
    if [[ ! -x $BIN/helm ]]; then
      tar -xzf "$(fetch "https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz")" -C "$BIN" --strip-components=1 linux-amd64/helm
    fi
    echo "$BIN/helm"
    ;;
  k3d)
    if [[ ! -x $BIN/k3d ]]; then
      install -m 0755 "$(fetch "https://github.com/k3d-io/k3d/releases/download/v5.9.0/k3d-linux-amd64")" "$BIN/k3d"
    fi
    echo "$BIN/k3d"
    ;;
  kind-legacy)
    if [[ ! -x $BIN/kind-$LEGACY_KIND_VERSION ]]; then
      install -m 0755 "$(fetch "https://github.com/kubernetes-sigs/kind/releases/download/$LEGACY_KIND_VERSION/kind-linux-amd64")" "$BIN/kind-$LEGACY_KIND_VERSION"
    fi
    echo "$BIN/kind-$LEGACY_KIND_VERSION"
    ;;
  esac
}

# kind_up [kind-binary]: 1 control plane + 2 workers with $POD_SUBNET.
kind_up() {
  local kind=${1:-kind} net="  podSubnet: \"$POD_SUBNET\""
  [[ $DEFAULT_CNI == true ]] || net="$net
  disableDefaultCNI: true"
  "$kind" create cluster --name "$CLUSTER" --kubeconfig "$KUBECONFIG" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
$net
nodes:
  - role: control-plane
  - role: worker
  - role: worker
EOF
}

k3d_up() {
  "$BIN/k3d" cluster create "$CLUSTER" --servers 1 --agents 2 \
    --kubeconfig-update-default=false --kubeconfig-switch-context=false \
    --wait --timeout 300s --k3s-arg "--cluster-cidr=$POD_SUBNET@server:*" "$@"
  "$BIN/k3d" kubeconfig get "$CLUSTER" >"$KUBECONFIG"
}

# --- variants: each defines PROVIDER, sets up the cluster and the CNI ---

setup() {
  PROVIDER=kind POD_SUBNET=192.168.0.0/16 DEFAULT_CNI=false
  case $1 in
  kindnet)
    DEFAULT_CNI=true
    kind_up
    ;;
  kindnet-legacy)
    DEFAULT_CNI=true
    kind_up "$(tool kind-legacy)"
    ;;
  calico | cilium | flannel)
    # shellcheck source=/dev/null
    source "hack/lab/profiles/$1.sh"
    kind_up
    install
    ;;
  canal)
    POD_SUBNET=10.244.0.0/16 # canal.yaml's flannel net-conf default
    kind_up
    kctl apply -f "https://raw.githubusercontent.com/projectcalico/calico/$CANAL_VERSION/manifests/canal.yaml"
    kctl -n kube-system rollout status ds/canal --timeout=300s
    ;;
  antrea)
    kind_up
    "$(tool helm)" install antrea antrea --repo https://charts.antrea.io --version "$ANTREA_VERSION" \
      --kubeconfig "$KUBECONFIG" --namespace kube-system --set disableTXChecksumOffload=true
    kctl -n kube-system rollout status ds/antrea-agent --timeout=300s
    ;;
  k3s)
    PROVIDER=k3d
    tool k3d >/dev/null
    k3d_up
    ;;
  k3s-no-policy)
    PROVIDER=k3d
    tool k3d >/dev/null
    k3d_up --k3s-arg "--disable-network-policy@server:*"
    ;;
  flannel-kube-router)
    # flannel for networking + kube-router as a policy-only controller:
    # a real setup in which no "enforcing CNI" DaemonSet exists by name.
    # shellcheck source=/dev/null
    source hack/lab/profiles/flannel.sh
    kind_up
    install
    curl -fsSL https://raw.githubusercontent.com/cloudnativelabs/kube-router/master/daemonset/kube-router-firewall-daemonset.yaml |
      sed "s|image: docker.io/cloudnativelabs/kube-router$|image: $KUBE_ROUTER_IMAGE|" | kctl apply -f -
    kctl -n kube-system rollout status ds/kube-router --timeout=300s
    ;;
  *)
    echo "unknown variant: $1" >&2
    return 2
    ;;
  esac
  kctl wait --for=condition=Ready nodes --all --timeout=300s >/dev/null
}

teardown() {
  case $PROVIDER in
  kind) kind delete cluster --name "$CLUSTER" ;;
  k3d) "$BIN/k3d" cluster delete "$CLUSTER" ;;
  esac
  rm -f "$KUBECONFIG"
}

# --- the probe ---

# connect <client-pod> <addr>: 0 if a TCP connection succeeds.
connect() { kctl -n exp2 exec "$1" -- /agnhost connect "$2" --timeout=3s >/dev/null 2>&1; }

pod() { # pod <name> <node> <args...>
  local name=$1 node=$2
  shift 2
  kctl -n exp2 run "$name" --image "$AGNHOST" --restart=Never --labels "app=$name" \
    --overrides "{\"spec\":{\"nodeName\":\"$node\",\"tolerations\":[{\"operator\":\"Exists\"}]}}" -- "$@"
}

# probe: prints "<same-node> <cross-node>" outcomes with deny-all in place
# (blocked | open | broken = no baseline connectivity) as its LAST line.
probe() {
  local nodes a b ip same cross deadline
  # two workers: skip the control plane / k3s server
  mapfile -t nodes < <(kctl get nodes -o name -l '!node-role.kubernetes.io/control-plane' | sed 's|node/||' | sort)
  a=${nodes[0]} b=${nodes[1]}
  kctl create namespace exp2
  pod server "$a" netexec --http-port=8080
  pod client-same "$a" pause
  pod client-cross "$b" pause
  kctl -n exp2 wait --for=condition=Ready pod --all --timeout=180s >/dev/null
  ip=$(kctl -n exp2 get pod server -o jsonpath='{.status.podIP}'):8080

  for c in client-same client-cross; do
    connect "$c" "$ip" || { echo "baseline $c -> $ip failed" >&2; echo "broken broken"; return; }
  done

  kctl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all-ingress, namespace: exp2}
spec: {podSelector: {}, policyTypes: [Ingress]}
EOF
  # Controllers take a moment to program the dataplane: poll up to 60s.
  same=open cross=open
  deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    connect client-same "$ip" || same=blocked
    connect client-cross "$ip" || cross=blocked
    [[ $same == blocked && $cross == blocked ]] && break
    sleep 3
  done
  echo "$same $cross"
}

# run_variant runs in its own process (see "one" below) so that errexit
# works and the cluster is deleted whatever happens.
run_variant() {
  local v=$1 dir=$OUT/raw/$PASS/$1
  CLUSTER=fo-exp2-$v
  KUBECONFIG=$BIN/kubeconfig-exp2-$v
  rm -rf "$dir" && mkdir -p "$dir"
  exec > >(tee "$dir/run.log") 2>&1
  [[ ${KEEP:-} == 1 ]] || trap teardown EXIT
  setup "$v"
  kctl get ds -A -o wide >"$dir/daemonsets.txt"
  kctl get nodes -o wide >"$dir/nodes.txt"
  probe | tee "$dir/probe.log"
  read -r same cross < <(tail -1 "$dir/probe.log")
  # AFTER_PROBE: another tool to run against the same live cluster, e.g.
  # hack/experiments/exp3/kubescape-live.sh; called with <kubeconfig> <raw dir>.
  [[ -z ${AFTER_PROBE:-} ]] || "$AFTER_PROBE" "$KUBECONFIG" "$dir"
  {
    "$FAILOPEN" snapshot --kubeconfig "$KUBECONFIG" >"$dir/snapshot.json"
    rc=0
    "$FAILOPEN" audit --kubeconfig "$KUBECONFIG" --color=never >"$dir/audit.txt" || rc=$?
    read -r name enforces < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["cni"]; print(c.get("name"), str(c.get("enforcesPolicy", False)).lower())' "$dir/snapshot.json")
    if [[ $same == broken ]]; then
      actual=broken
    elif [[ $same == blocked && $cross == blocked ]]; then
      actual=enforced
    elif [[ $same == open && $cross == open ]]; then
      actual=not-enforced
    else
      actual=partial
    fi
    if [[ $name == unknown ]]; then
      predicted=unknown # a warning: "enforcement unverified", not a claim either way
      correct=undecided
    else
      predicted=$([[ $enforces == true ]] && echo enforced || echo not-enforced)
      correct=$([[ $actual == "$predicted" ]] && echo yes || echo NO)
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$name" "$enforces" "$same" "$cross" "$actual" "$predicted" "$correct" "$rc" |
      tee -a "$OUT/$PASS.tsv"
  }
}

case ${1:-} in
list) printf '%s\n' "${VARIANTS[@]}" ;;
one) run_variant "$2" ;;
*)
  if [[ -z $FAILOPEN ]]; then
    make build >/dev/null
    export FAILOPEN=$ROOT/bin/failopen
  fi
  mkdir -p "$OUT"
  [[ -f $OUT/$PASS.tsv ]] || printf 'variant\tdetected_cni\tclaims_enforces\tsame_node\tcross_node\tactual\tpredicted\tcorrect\taudit_exit\n' >"$OUT/$PASS.tsv"
  for v in "${@:-${VARIANTS[@]}}"; do
    "$0" one "$v" || echo "variant $v failed: see $OUT/raw/$PASS/$v/run.log" >&2
  done
  column -t -s $'\t' "$OUT/$PASS.tsv"
  ;;
esac
