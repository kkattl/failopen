#!/usr/bin/env bash
# Paylane smoke test: verifies readiness, every intended flow (ALLOW) and a set of
# flows that must be blocked (DENY). Exit 0 only if every check matches expectation.
#
# Usage: KUBECONFIG=/path/to/kubeconfig ./smoke.sh      (or: ./smoke.sh /path/to/kubeconfig)
set -uo pipefail

KCFG="${1:-${KUBECONFIG:-}}"
[[ -n "$KCFG" ]] || { echo "usage: $0 <kubeconfig> (or set KUBECONFIG)"; exit 2; }
k() { kubectl --kubeconfig "$KCFG" "$@"; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$*"; }

APP=fintech-app; CDE=fintech-cde; EDGE=fintech-edge; OPS=fintech-ops
svc() { echo "$1.$2.svc.cluster.local"; }   # svc <name> <ns>
PUBLIC_IP=1.1.1.1                           # stand-in for "the internet / card networks"

# check <expect allow|deny> <ns> <deploy> <host:port> <description>
# Uses agnhost's TCP connect from inside the source pod.
check() {
  local expect=$1 ns=$2 src=$3 target=$4 desc=$5 rc
  k -n "$ns" exec "deploy/$src" -- /agnhost connect "$target" --timeout=3s >/dev/null 2>&1; rc=$?
  verdict "$expect" "$rc" "$src -> $target  ($desc)"
}
# Same for the prometheus pod (busybox nc, no agnhost).
check_nc() {
  local expect=$1 host=$2 port=$3 desc=$4 rc
  k -n "$OPS" exec deploy/prometheus -- nc -z -w 3 "$host" "$port" >/dev/null 2>&1; rc=$?
  verdict "$expect" "$rc" "prometheus -> $host:$port  ($desc)"
}
verdict() {
  local expect=$1 rc=$2 msg=$3
  if [[ $expect == allow && $rc -eq 0 ]] || [[ $expect == deny && $rc -ne 0 ]]; then
    ok "[$expect] $msg"
  else
    bad "[$expect] $msg  (exit=$rc)"
  fi
}

echo "== 1. Readiness"
for ns in $EDGE $APP $CDE $OPS; do
  if k -n "$ns" wait --for=condition=Ready pod --all --timeout=180s >/dev/null; then
    ok "all pods Ready in $ns"
  else
    bad "pods not Ready in $ns"; k -n "$ns" get pods
  fi
done
total=$(k get pods -A --no-headers 2>/dev/null | awk '$1 ~ /^fintech-/' | wc -l)
nodes=$(k get nodes --no-headers | wc -l)
agents=$(k -n $OPS get ds node-agent -o jsonpath='{.status.numberReady}')
[[ $total -le 20 ]] && ok "pod budget: $total <= 20" || bad "pod budget: $total > 20"
[[ $agents -eq $nodes ]] && ok "node-agent ready on every node ($agents/$nodes)" || bad "node-agent on $agents/$nodes nodes"

echo "== 2. Placement"
place() {  # place <ns> <label> <pool>
  local bad_nodes
  bad_nodes=$(k -n "$1" get pods -l "$2" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' |
    while read -r n; do [[ $(k get node "$n" -o jsonpath='{.metadata.labels.pool}') == "$3" ]] || echo "$n"; done)
  [[ -z $bad_nodes ]] && ok "$2 runs only on pool=$3" || bad "$2 on wrong nodes: $bad_nodes"
}
place $EDGE app=edge-proxy edge
for a in checkout-api redis admin-panel; do place $APP app=$a general; done
for a in payments-core card-gateway ledger postgres; do place $CDE app=$a restricted; done
# nothing outside the CDE (except the per-node agent) may run on restricted nodes
foreign=$(k get pods -A -o wide --no-headers | awk '$1 ~ /^fintech-/ && $1 != "fintech-cde" && $1 != "fintech-ops"' |
  while read -r ns name _ _ _ _ _ node _; do
    [[ $(k get node "$node" -o jsonpath='{.metadata.labels.pool}') == restricted ]] && echo "$ns/$name"; done)
[[ -z $foreign ]] && ok "no non-CDE app pods on restricted nodes" || bad "non-CDE pods on restricted nodes: $foreign"

echo "== 3. Internet ingress path (edge LB -> edge node:30880 -> edge-proxy -> checkout-api)"
node_ip() { k get nodes -l "pool=$1" -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}'; }
EDGE_IP=$(node_ip edge); GEN_IP=$(node_ip general); RES_IP=$(node_ip restricted)
body=$(curl -s -m 5 "http://$EDGE_IP:30880/hostname")
[[ $body == checkout-api-* ]] && ok "[allow] internet -> $EDGE_IP:30880 answered by $body" \
  || bad "[allow] internet -> edge node $EDGE_IP:30880 (got '$body')"
for ip in "$GEN_IP" "$RES_IP"; do
  if curl -s -m 4 -o /dev/null "http://$ip:30880/hostname"; then bad "[deny] internet -> non-edge node $ip:30880 answered"
  else ok "[deny] internet -> non-edge node $ip:30880 (externalTrafficPolicy=Local)"; fi
done

echo "== 4. Allowed flows"
check allow $APP checkout-api "$(svc redis $APP):6379"          "idempotency / rate limit"
check allow $APP checkout-api "$(svc payments-core $CDE):8080"  "authorize/capture"
check allow $APP admin-panel  "$(svc payments-core $CDE):8080"  "support lookups/refunds"
check allow $CDE payments-core "$(svc ledger $CDE):8080"        "bookkeeping"
check allow $CDE payments-core "$(svc card-gateway $CDE):8080"  "card network calls"
check allow $CDE ledger       "$(svc postgres $CDE):5432"        "ledger DB"
check allow $CDE card-gateway "$PUBLIC_IP:443"                   "card networks (public 443)"
check_nc allow "node-agent.$OPS.svc.cluster.local" 9100          "node metrics scrape"
for _ in $(seq 1 15); do   # first scrape can take up to one scrape_interval (30s)
  up=$(k -n $OPS exec deploy/prometheus -- wget -qO- 'http://localhost:9090/api/v1/query?query=sum(up{job="node"})' |
    sed -n 's/.*"value":\[[^,]*,"\([0-9]*\)".*/\1/p')
  [[ $up == "$nodes" ]] && break; sleep 5
done
[[ $up == "$nodes" ]] && ok "[allow] prometheus scrapes node metrics from all $nodes nodes" \
  || bad "[allow] prometheus up targets = '$up', nodes = $nodes"

echo "== 5. Denied flows"
# non-CDE -> CDE, anything but the one entry point
check deny $APP checkout-api "$(svc postgres $CDE):5432"         "app must not reach CDE DB"
check deny $APP checkout-api "$(svc ledger $CDE):8080"           "only via payments-core"
check deny $APP checkout-api "$(svc card-gateway $CDE):8080"     "only payments-core talks to gateway"
check deny $APP admin-panel  "$(svc postgres $CDE):5432"         "back-office must not touch DB"
check deny $APP admin-panel  "$(svc ledger $CDE):8080"           "back-office only via payments-core"
check deny $APP admin-panel  "$(svc redis $APP):6379"            "redis is checkout-api only"
check deny $APP admin-panel  "$(svc checkout-api $APP):8080"     "no lateral app->app"
# egress to internet from everything except card-gateway
check deny $APP checkout-api "$PUBLIC_IP:443"                    "no internet egress"
check deny $CDE payments-core "$PUBLIC_IP:443"                   "only card-gateway may leave the cluster"
check deny $CDE ledger       "$PUBLIC_IP:443"                    "no internet egress"
check deny $CDE card-gateway "$PUBLIC_IP:80"                     "gateway egress is 443 only"
# inside the CDE: least privilege, and CDE never initiates to non-CDE
check deny $CDE payments-core "$(svc postgres $CDE):5432"        "DB only reachable from ledger"
check deny $CDE card-gateway "$(svc postgres $CDE):5432"         "DB only reachable from ledger"
check deny $CDE card-gateway "$(svc ledger $CDE):8080"           "gateway is a leaf"
check deny $CDE ledger       "$(svc card-gateway $CDE):8080"     "ledger is a leaf"
check deny $CDE payments-core "$(svc checkout-api $APP):8080"    "CDE does not call out to app zone"
check deny $CDE payments-core "$(svc redis $APP):6379"           "CDE does not call out to app zone"
check deny $CDE card-gateway "$RES_IP:10250"                     "no node/kubelet access (private ranges excluded)"
check deny $CDE payments-core "10.96.0.1:443"                    "no kube-apiserver access"
# ops/monitoring zone must not become a path into the CDE
check_nc deny "$(svc postgres $CDE)" 5432                        "monitoring must not reach CDE DB"
check_nc deny "$(svc payments-core $CDE)" 8080                   "monitoring must not reach CDE apps"
check deny $APP checkout-api "node-agent.$OPS.svc.cluster.local:9100" "metrics only for prometheus"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
