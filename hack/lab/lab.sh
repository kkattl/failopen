#!/usr/bin/env bash
# Production-shaped lab clusters, one per CNI profile.
#
# Usage: hack/lab/lab.sh up <profile>        create cluster + CNI + external client
#        hack/lab/lab.sh down <profile>
#        hack/lab/lab.sh kubeconfig <profile>
#        hack/lab/lab.sh profiles
#
# Cluster "failopen-lab-<profile>", kubeconfig hack/lab/kubeconfig-<profile>.
# Topology (pools, taints, zones) is identical for every profile; only the
# provider (kind or k3d), networking and the CNI install differ.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
BIN=$ROOT/hack/.bin
HELM_VERSION=v4.3.0
K3D_VERSION=v5.9.0

profiles() { for f in hack/lab/profiles/*.sh; do basename "$f" .sh; done; }

load_profile() {
  PROFILE=${1:?profile required; one of: $(profiles | tr '\n' ' ')}
  [[ -f hack/lab/profiles/$PROFILE.sh ]] || { echo "unknown profile: $PROFILE" >&2; exit 2; }
  CLUSTER=failopen-lab-$PROFILE
  KUBECONFIG=$ROOT/hack/lab/kubeconfig-$PROFILE
  PROVIDER=kind
  # shellcheck source=/dev/null
  source "hack/lab/profiles/$PROFILE.sh"
}

kctl() { kubectl --kubeconfig "$KUBECONFIG" "$@"; }

# fetch <url>: download once into hack/.bin/cache, print the local path.
fetch() {
  mkdir -p "$BIN/cache"
  local out
  out=$BIN/cache/$(basename "$1")
  [[ -s $out ]] || curl -fsSL -o "$out" "$1"
  echo "$out"
}

# tool <name>: repo-local binaries, so the lab doesn't install anything system-wide.
tool() {
  case $1 in
  helm)
    if [[ ! -x $BIN/helm ]]; then
      tar -xzf "$(fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz")" -C "$BIN" --strip-components=1 linux-amd64/helm
    fi
    echo "$BIN/helm"
    ;;
  k3d)
    if [[ ! -x $BIN/k3d ]]; then
      install -m 0755 "$(fetch "https://github.com/k3d-io/k3d/releases/download/$K3D_VERSION/k3d-linux-amd64")" "$BIN/k3d"
    fi
    echo "$BIN/k3d"
    ;;
  esac
}

# --- provider: kind ---

kind_exists() { kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; }
kind_down() { kind delete cluster --name "$CLUSTER"; }

kind_create() {
  local net="  podSubnet: \"$POD_SUBNET\""
  [[ $DEFAULT_CNI == true ]] || net="  disableDefaultCNI: true
$net"
  awk -v name="$CLUSTER" -v net="$net" '
    /__NAME__/ { sub(/__NAME__/, name) }
    /^__NETWORKING__$/ { print net; next }
    { print }' hack/lab/kind-config.yaml |
    kind create cluster --config - --kubeconfig "$KUBECONFIG"
}

# --- provider: k3d (k3s in docker) ---

k3d_exists() { "$(tool k3d)" cluster list -o json | grep -q "\"name\":\"$CLUSTER\""; }
k3d_down() { "$(tool k3d)" cluster delete "$CLUSTER"; }

# Same topology as hack/lab/kind-config.yaml — keep the two in sync:
# agents 0-2 general (zones a/b/c), 3 edge (a), 4-5 restricted (a/b).
# Joins the "kind" docker network so hack/lab/external.sh works unchanged.
k3d_create() {
  local k3d
  k3d=$(tool k3d)
  "$k3d" cluster create "$CLUSTER" --network kind --servers 1 --agents 6 \
    --kubeconfig-update-default=false --kubeconfig-switch-context=false \
    --wait --timeout 300s ${K3D_EXTRA_ARGS:-} \
    --k3s-arg "--node-label=pool=general@agent:0,1,2" \
    --k3s-arg "--node-label=pool=edge@agent:3" \
    --k3s-arg "--node-label=pool=restricted@agent:4,5" \
    --k3s-arg "--node-label=topology.kubernetes.io/zone=zone-a@agent:0,3,4" \
    --k3s-arg "--node-label=topology.kubernetes.io/zone=zone-b@agent:1,5" \
    --k3s-arg "--node-label=topology.kubernetes.io/zone=zone-c@agent:2" \
    --k3s-arg "--node-taint=dedicated=edge:NoSchedule@agent:3" \
    --k3s-arg "--node-taint=dedicated=restricted:NoSchedule@agent:4,5"
  "$k3d" kubeconfig get "$CLUSTER" >"$KUBECONFIG"
}

case ${1:-} in
up)
  load_profile "${2:-}"
  if "${PROVIDER}_exists"; then
    echo "$CLUSTER already exists"
    # Scenarios hardcode the pod CIDR (ipBlock excepts): an old cluster built
    # with another subnet would silently change what they mean.
    cidr=$(kctl get nodes -o jsonpath='{.items[0].spec.podCIDR}')
    if [[ ${cidr%.*.*} != "${POD_SUBNET%.*.*}" ]]; then
      echo "$CLUSTER has pod CIDR $cidr, profile wants $POD_SUBNET: recreate it (hack/lab/lab.sh down $PROFILE)" >&2
      exit 1
    fi
  else
    "${PROVIDER}_create"
    install
  fi
  kctl wait --for=condition=Ready nodes --all --timeout=300s >/dev/null
  hack/lab/external.sh ensure "$CLUSTER"
  echo "lab $PROFILE ready: KUBECONFIG=$KUBECONFIG"
  ;;
down)
  load_profile "${2:-}"
  "${PROVIDER}_down"
  rm -f "$KUBECONFIG"
  ;;
kubeconfig)
  load_profile "${2:-}"
  echo "$KUBECONFIG"
  ;;
profiles)
  profiles
  ;;
*)
  echo "usage: $0 up|down|kubeconfig <profile> | profiles" >&2
  exit 2
  ;;
esac
