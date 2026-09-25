#!/usr/bin/env bash
# Smoke test for the Voltgrid telemetry platform.
# Proves every intended flow works and that a set of must-never-happen flows are denied.
#
# Usage: KUBECONFIG=/path/to/kubeconfig ./smoke.sh      (or: ./smoke.sh /path/to/kubeconfig)
# The machine running this script plays the "plant network" (in kind: the docker bridge
# gateway 172.18.0.1, which is the plant CIDR configured in the NetworkPolicies).
set -uo pipefail

KCFG="${1:-${KUBECONFIG:-$(dirname "$0")/../lab-kubeconfig}}"
k() { kubectl --kubeconfig "$KCFG" "$@"; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s  -- %s\n' "$1" "$2"; }

# exec_connect <ns> <pod> <container> <host:port>  -> prints agnhost output, returns its rc
exec_connect() {
  k -n "$1" exec "$2" -c "$3" -- /agnhost connect "$4" --timeout=3s 2>&1
}
expect_allow() { # <desc> <ns> <pod> <container> <target>
  local out; out=$(exec_connect "$2" "$3" "$4" "$5"); local rc=$?
  if [ $rc -eq 0 ]; then ok "ALLOW $1"; else bad "ALLOW $1" "rc=$rc ${out//$'\n'/ }"; fi
}
expect_deny() {  # <desc> <ns> <pod> <container> <target>  (must be dropped => TIMEOUT)
  local out; out=$(exec_connect "$2" "$3" "$4" "$5"); local rc=$?
  if [ $rc -ne 0 ] && grep -q TIMEOUT <<<"$out"; then ok "DENY  $1"
  elif [ $rc -ne 0 ]; then bad "DENY  $1" "failed but not by policy drop: ${out//$'\n'/ }"
  else bad "DENY  $1" "connection SUCCEEDED"; fi
}
pod()     { k -n "$1" get pod -l "app.kubernetes.io/name=$2" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'; }
svcip()   { k -n "$1" get svc "$2" -o jsonpath='{.spec.clusterIP}'; }

echo "== Readiness"
if k wait --for=condition=Ready pod -A -l app.kubernetes.io/part-of=voltgrid-telemetry --timeout=180s >/dev/null; then
  ok "all voltgrid pods Ready ($(k get pods -A -l app.kubernetes.io/part-of=voltgrid-telemetry --no-headers | wc -l) pods)"
else bad "all voltgrid pods Ready" "$(k get pods -A -l app.kubernetes.io/part-of=voltgrid-telemetry --no-headers | grep -v Running)"; fi

NODES=$(k get nodes --no-headers | wc -l)
AGENTS=$(k -n iot-ops get ds node-agent -o jsonpath='{.status.numberReady}')
[ "$AGENTS" = "$NODES" ] && ok "node-agent Ready on every node ($AGENTS/$NODES)" || bad "node-agent on every node" "$AGENTS/$NODES"

IG=$(pod iot-edge ingest-gateway); DP=$(pod iot-edge dashboard-proxy)
SP=$(pod iot-app stream-processor); DR=$(pod iot-app device-registry)
AL=$(pod iot-app alerting); DB=$(pod iot-app dashboard)
TS=$(pod iot-data tsdb); PR=$(pod iot-ops prometheus)
EDGE_NODE=$(k -n iot-edge get pod "$IG" -o jsonpath='{.spec.nodeName}')
EDGE_IP=$(k get node "$EDGE_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
GEN_IP=$(k get nodes -l pool=general -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
DIAG_EDGE=$(k -n iot-ops get pod -l app.kubernetes.io/name=node-agent --field-selector spec.nodeName="$EDGE_NODE" -o jsonpath='{.items[0].metadata.name}')
DIAG_EDGE_IP=$(k -n iot-ops get pod "$DIAG_EDGE" -o jsonpath='{.status.podIP}')
TSDB=$(svcip iot-data tsdb); PGDB=$(svcip iot-data registry-db)
REG=$(svcip iot-app device-registry); DASH=$(svcip iot-app dashboard)
APISERVER=$(svcip default kubernetes)

echo "== Plant network (this host) -> edge node $EDGE_NODE ($EDGE_IP)"
out=$(curl -s -m 5 "http://$EDGE_IP:8883/clientip")
[[ "$out" == 172.18.0.1:* ]] && ok "ALLOW sensor -> $EDGE_IP:8883 ingest-gateway (source IP preserved: $out)" || bad "ALLOW sensor -> $EDGE_IP:8883" "got '$out'"
out=$(curl -s -m 5 "http://$EDGE_IP:8080/hostname")
[[ "$out" == dashboard-* ]] && ok "ALLOW engineer -> $EDGE_IP:8080 dashboard-proxy -> dashboard ($out)" || bad "ALLOW engineer -> dashboard via proxy" "got '$out'"
for p in 9000 9100 9200; do
  curl -s -m 3 -o /dev/null "http://$EDGE_IP:$p/" && bad "NOT EXPOSED plant -> $EDGE_IP:$p" "reachable" || ok "NOT EXPOSED plant -> $EDGE_IP:$p (internal/ops port not on edge node IP)"
done
curl -s -m 3 -o /dev/null "http://$GEN_IP:8883/" && bad "NOT EXPOSED plant -> general node $GEN_IP:8883" "reachable" || ok "NOT EXPOSED plant -> general node $GEN_IP:8883 (ingest only on edge pool)"

echo "== Intended in-cluster flows"
expect_allow "ingest-gateway -> device-registry:8080"         iot-edge "$IG" device-listener device-registry.iot-app.svc.cluster.local:8080
expect_allow "stream-processor -> ingest-gateway:9000"        iot-app  "$SP" stream-processor ingest-gateway.iot-edge.svc.cluster.local:9000
expect_allow "stream-processor -> tsdb:8428"                  iot-app  "$SP" stream-processor tsdb.iot-data.svc.cluster.local:8428
expect_allow "device-registry -> registry-db:5432"            iot-app  "$DR" device-registry registry-db.iot-data.svc.cluster.local:5432
expect_allow "alerting -> tsdb:8428"                          iot-app  "$AL" alerting tsdb.iot-data.svc.cluster.local:8428
expect_allow "dashboard -> tsdb:8428"                         iot-app  "$DB" dashboard tsdb.iot-data.svc.cluster.local:8428
if curl -s -m 5 -o /dev/null https://events.pagerduty.com; then
  expect_allow "alerting -> paging provider events.pagerduty.com:443" iot-app "$AL" alerting events.pagerduty.com:443
else echo "  SKIP  alerting -> paging provider (lab has no internet)"; fi

echo "== Node metrics + hw-diag status collected from every node (prometheus -> node-agent)"
for ip in $(k -n iot-ops get pod -l app.kubernetes.io/name=node-agent -o jsonpath='{range .items[*]}{.status.podIP}{" "}{.spec.nodeName}{"\n"}{end}' | tr ' ' '|'); do
  pip=${ip%%|*}; node=${ip##*|}
  up=""
  for _ in $(seq 1 12); do
    up=$(k -n iot-ops exec "$PR" -- wget -qO- "http://localhost:9090/api/v1/query?query=up%7Binstance%3D%22$pip:9100%22%7D" | grep -o '"value":\[[^]]*\]' | grep -o '"[01]"')
    [ "$up" = '"1"' ] && break; sleep 5
  done
  [ "$up" = '"1"' ] && ok "prometheus scrapes node-exporter on $node ($pip)" || bad "prometheus scrapes $node" "up=$up"
  k -n iot-ops exec "$PR" -- nc -z -w 3 "$pip" 9200 && ok "ALLOW prometheus -> hw-diag status on $node" || bad "ALLOW prometheus -> hw-diag on $node" "unreachable"
done

echo "== Must be DENIED"
# device-facing tier must never reach the data tier directly (or anything but device-registry)
expect_deny "ingest-gateway -> tsdb:8428 (device tier -> data tier)"          iot-edge "$IG" device-listener "$TSDB:8428"
expect_deny "ingest-gateway -> registry-db:5432 (device tier -> data tier)"   iot-edge "$IG" device-listener "$PGDB:5432"
expect_deny "ingest-gateway -> dashboard:3000"                                iot-edge "$IG" device-listener "$DASH:3000"
expect_deny "ingest-gateway -> hw-diag on edge node :9200"                    iot-edge "$IG" device-listener "$DIAG_EDGE_IP:9200"
expect_deny "ingest-gateway -> internet 1.1.1.1:443"                          iot-edge "$IG" device-listener 1.1.1.1:443
expect_deny "ingest-gateway -> kube-apiserver"                                iot-edge "$IG" device-listener "$APISERVER:443"
expect_deny "ingest-gateway -> device-registry on non-API port 8081"          iot-edge "$IG" device-listener "$REG:8081"
# app tier: each service only reaches its own dependencies
expect_deny "stream-processor -> registry-db:5432"                            iot-app "$SP" stream-processor "$PGDB:5432"
expect_deny "dashboard -> registry-db:5432"                                   iot-app "$DB" dashboard "$PGDB:5432"
expect_deny "alerting -> registry-db:5432"                                    iot-app "$AL" alerting "$PGDB:5432"
expect_deny "alerting -> device-registry:8080 (lateral)"                      iot-app "$AL" alerting "$REG:8080"
expect_deny "alerting -> kube-apiserver (internal range excluded from :443)"  iot-app "$AL" alerting "$APISERVER:443"
expect_deny "device-registry -> tsdb:8428"                                    iot-app "$DR" device-registry "$TSDB:8428"
expect_deny "dashboard -> internet 1.1.1.1:443"                               iot-app "$DB" dashboard 1.1.1.1:443
# cluster pods must not reach the sensor port through the edge node IP (plant CIDR must not cover nodes)
expect_deny "dashboard (pod) -> edge node $EDGE_IP:8883 hostPort"             iot-app "$DB" dashboard "$EDGE_IP:8883"
# data tier has no egress at all
expect_deny "tsdb -> internet 1.1.1.1:443 (data tier egress)"                 iot-data "$TS" tsdb 1.1.1.1:443
expect_deny "tsdb -> registry-db:5432"                                        iot-data "$TS" tsdb "$PGDB:5432"
# vendor diagnostics agent on the plant-facing edge node: no egress
expect_deny "hw-diag@edge -> tsdb:8428"                                       iot-ops "$DIAG_EDGE" hw-diag "$TSDB:8428"
expect_deny "hw-diag@edge -> registry-db:5432"                                iot-ops "$DIAG_EDGE" hw-diag "$PGDB:5432"
expect_deny "hw-diag@edge -> internet 1.1.1.1:443 (vendor phone-home)"        iot-ops "$DIAG_EDGE" hw-diag 1.1.1.1:443
# dashboard-proxy (nginx, no agnhost): use busybox nc
if k -n iot-edge exec "$DP" -- nc -z -w 3 "$TSDB" 8428 2>/dev/null; then bad "DENY  dashboard-proxy -> tsdb:8428" "connection SUCCEEDED"
else ok "DENY  dashboard-proxy -> tsdb:8428 (device tier -> data tier)"; fi
if k -n iot-edge exec "$DP" -- nc -z -w 3 "$REG" 8080 2>/dev/null; then bad "DENY  dashboard-proxy -> device-registry:8080" "connection SUCCEEDED"
else ok "DENY  dashboard-proxy -> device-registry:8080"; fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
