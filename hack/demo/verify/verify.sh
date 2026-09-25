#!/usr/bin/env bash
# Reachability matrix: which declared-DENY paths into payments are actually open?
# Usage: hack/demo/verify/verify.sh   (after `make demo`)
set -uo pipefail

cd "$(dirname "$0")/../../.."
CLUSTER=failopen-demo
K="kubectl --kubeconfig=hack/demo/kubeconfig"

$K apply -f hack/demo/verify/probes.yaml >/dev/null
$K wait --for=condition=Ready pod --all -n payments --timeout=180s >/dev/null
$K wait --for=condition=Ready pod/client -n verify-client --timeout=180s >/dev/null

node_ip() { $K get node "$1" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'; }
pod_ip()   { $K -n payments get pod "$1" -o jsonpath='{.status.podIP}'; }
pod_node() { $K -n payments get pod "$1" -o jsonpath='{.spec.nodeName}'; }

API_IP=$(pod_ip api-server)
API_NODE=$(pod_node api-server)
HP_NODE=$(pod_node hostport-probe)
HN_NODE=$(pod_node host-probe)
# A worker that does NOT host api-server — exercises the cross-node SNAT path.
OTHER_NODE=$($K get nodes -o name | sed 's|node/||' | grep -v control-plane | grep -vx "$API_NODE" | head -1)

# probe <source> <host> <port> -> OPEN|closed
probe() {
  local src=$1 host=$2 port=$3 out
  case $src in
    external)  out=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$host:$port/hostname") ;;
    pod)       out=$($K -n verify-client exec client -- /agnhost connect "$host:$port" --timeout=3s 2>&1 && echo 200) ;;
    node:*)    out=$(docker exec "${src#node:}" curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$host:$port/hostname") ;;
  esac
  [[ $out == *200* ]] && echo OPEN || echo closed
}

row() { # row <label> <host> <port>
  printf '%-48s' "$1"
  for src in external pod "node:$API_NODE" "node:$OTHER_NODE"; do
    printf '%-28s' "$(probe "$src" "$2" "$3")"
  done
  echo
}

echo "api-server on $API_NODE, other worker $OTHER_NODE; policy: default-deny-all (ingress)"
echo
printf '%-48s%-28s%-28s%-28s%-28s\n' TARGET external pod-other-ns "node($API_NODE)" "node($OTHER_NODE)"
row "pod IP direct (control)" "$API_IP" 80
row "NodePort on pod's node           :31080" "$(node_ip "$API_NODE")" 31080
row "NodePort on other worker         :31080" "$(node_ip "$OTHER_NODE")" 31080
row "NodePort on control-plane        :31080" "$(node_ip $CLUSTER-control-plane)" 31080
row "hostPort on pod's node           :30081" "$(node_ip "$HP_NODE")" 30081
row "hostNetwork pod                  :8080"  "$(node_ip "$HN_NODE")" 8080

echo
printf '%-48s' "HOLE #2: monitoring/node-agent (hostNetwork, same node) -> api-server"
$K -n monitoring exec node-agent -- /agnhost connect "$API_IP:80" --timeout=3s >/dev/null 2>&1 && echo "  OPEN" || echo "  closed"
