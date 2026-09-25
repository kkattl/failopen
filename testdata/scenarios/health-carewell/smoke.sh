#!/usr/bin/env bash
# Carewell lab smoke test: proves the intended flows work and that a set of
# flows that must be denied are denied. Exit 0 = all checks passed.
#
# Usage: KUBECONFIG=/path/to/kubeconfig ./smoke.sh     (or pass it as $1)
set -uo pipefail

KCFG="${1:-${KUBECONFIG:-}}"
[ -n "$KCFG" ] || { echo "usage: $0 <kubeconfig>  (or set KUBECONFIG)"; exit 2; }
k() { kubectl --kubeconfig "$KCFG" "$@"; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

# DNS names
SVC=svc.cluster.local
PORTAL=portal.health-web.$SVC:8080
NOTIFY=notifications.health-notify.$SVC:8080
API=records-api.health-phi.$SVC:8080
DB=records-db.health-phi.$SVC:5432
IMG=imaging.health-phi.$SVC:8080
AUDIT=audit-log.health-phi.$SVC:8080
REPLICA=reporting-replica.health-reporting.$SVC:5432
EXTERNAL=1.1.1.1:443

pod() { k -n "$1" get pods -l "app.kubernetes.io/name=$2" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'; }

# agnhost-based pods: /agnhost connect ; nginx/postgres pods: busybox nc
probe() { # ns app target -> exit code of connect attempt
  local ns=$1 app=$2 target=$3 p; p=$(pod "$ns" "$app")
  case $app in
    edge-proxy|records-db|reporting-replica)
      k -n "$ns" exec "$p" -- nc -z -w 3 "${target%:*}" "${target##*:}" >/dev/null 2>&1 ;;
    *)
      k -n "$ns" exec "$p" -- /agnhost connect "$target" --timeout=3s >/dev/null 2>&1 ;;
  esac
}
allow() { if probe "$1" "$2" "$3"; then ok "ALLOW $1/$2 -> $3"; else bad "ALLOW $1/$2 -> $3 (expected connect)"; fi; }
deny()  { if probe "$1" "$2" "$3"; then bad "DENY  $1/$2 -> $3 (connected!)"; else ok "DENY  $1/$2 -> $3"; fi; }

echo "== 0. readiness"
for ns in health-edge health-web health-notify health-phi health-reporting health-ops; do
  if k -n "$ns" wait pod --all --for=condition=Ready --timeout=180s >/dev/null 2>&1; then ok "all pods Ready in $ns"; else bad "pods not Ready in $ns"; fi
done
NODES=$(k get nodes --no-headers | wc -l)
LS=$(k -n health-ops get ds log-shipper -o jsonpath='{.status.numberReady}')
[ "$LS" = "$NODES" ] && ok "log-shipper on every node ($LS/$NODES)" || bad "log-shipper on $LS/$NODES nodes"
RN=$(k get nodes -l pool=restricted --no-headers | wc -l)
BA=$(k -n health-ops get ds backup-agent -o jsonpath='{.status.numberReady}')
[ "$BA" = "$RN" ] && ok "backup-agent on every data node ($BA/$RN)" || bad "backup-agent on $BA/$RN data nodes"
# every PVC-backed pod must sit on a node covered by the backup agent
BAD_PLACEMENT=$(k get pods -n health-phi -o json | jq -r '.items[]|.spec.nodeName' | sort -u | while read -r n; do
  [ "$(k get node "$n" -o jsonpath='{.metadata.labels.pool}')" = restricted ] || echo "$n"; done)
BAD_PLACEMENT+=$(k get pods -n health-reporting -o json | jq -r '.items[]|.spec.nodeName' | sort -u | while read -r n; do
  [ "$(k get node "$n" -o jsonpath='{.metadata.labels.pool}')" = restricted ] || echo "$n"; done)
[ -z "$BAD_PLACEMENT" ] && ok "all PHI pods on pool=restricted" || bad "PHI pods on non-restricted nodes: $BAD_PLACEMENT"

echo "== 1. north-south: edge LB -> edge node NodePort"
NP=$(k -n health-edge get svc edge-proxy -o jsonpath='{.spec.ports[0].nodePort}')
EDGE_IP=$(k get nodes -l pool=edge -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
if out=$(curl -fsS -m 5 "http://$EDGE_IP:$NP/hostname"); then ok "ALLOW internet -> edge $EDGE_IP:$NP -> portal (served by $out)"; else bad "ALLOW internet -> edge $EDGE_IP:$NP"; fi
for sel in pool=restricted pool=general; do
  for ip in $(k get nodes -l "$sel" -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{" "}{end}'); do
    if curl -fsS -m 3 -o /dev/null "http://$ip:$NP/" 2>/dev/null; then bad "DENY  internet -> $sel node $ip:$NP (portal exposed!)"; else ok "DENY  internet -> $sel node $ip:$NP (externalTrafficPolicy=Local)"; fi
  done
done

echo "== 2. intended east-west flows"
allow health-edge  edge-proxy  "$PORTAL"
allow health-web   portal      "$API"
allow health-web   portal      "$NOTIFY"
allow health-notify notifications "$EXTERNAL"   # public email/SMS provider APIs
allow health-phi   records-api "$DB"
allow health-phi   records-api "$IMG"
allow health-phi   records-api "$AUDIT"
allow health-reporting reporting-replica "$DB"
STREAM=$(k -n health-reporting exec reporting-replica-0 -- psql -U records -d records -tAc "select status from pg_stat_wal_receiver" 2>/dev/null)
[ "$STREAM" = streaming ] && ok "reporting-replica is streaming from records-db" || bad "reporting-replica not streaming ($STREAM)"

# nightly job, run on demand from the real CronJob template
J=smoke-reporting-$RANDOM
k -n health-reporting create job "$J" --from=cronjob/reporting >/dev/null
if k -n health-reporting wait job "$J" --for=condition=Complete --timeout=120s >/dev/null 2>&1; then
  ok "ALLOW reporting (CronJob) -> $REPLICA : $(k -n health-reporting logs job/"$J" 2>/dev/null)"
else bad "ALLOW reporting (CronJob) -> $REPLICA"; fi
k -n health-reporting delete job "$J" --wait=true >/dev/null

echo "== 3. flows that must be denied"
# edge compromise must not reach anything but the portal
deny health-edge edge-proxy "$API"
deny health-edge edge-proxy "$DB"
deny health-edge edge-proxy "$NOTIFY"
# portal may only use records-api; no direct PHI store access
deny health-web portal "$DB"
deny health-web portal "$IMG"
deny health-web portal "$AUDIT"
deny health-web portal "$REPLICA"
deny health-web portal "$EXTERNAL"
# notifications never touches PHI
deny health-notify notifications "$API"
deny health-notify notifications "$DB"
deny health-notify notifications "$IMG"
deny health-notify notifications "$AUDIT"
deny health-notify notifications "$REPLICA"
deny health-notify notifications "$PORTAL"
# PHI zone: no lateral movement, no exfiltration
deny health-phi records-api "$EXTERNAL"
deny health-phi records-api "$NOTIFY"
deny health-phi records-api "$REPLICA"
deny health-phi imaging "$AUDIT"
deny health-phi imaging "$DB"
deny health-phi imaging "$EXTERNAL"
deny health-phi audit-log "$DB"
deny health-phi audit-log "$EXTERNAL"
deny health-phi records-db "$EXTERNAL"
deny health-phi records-db "$REPLICA"
# replica can replicate, nothing else
deny health-reporting reporting-replica "$API"
deny health-reporting reporting-replica "$EXTERNAL"
# node agents co-located with PHI on restricted nodes cannot reach PHI services
deny health-ops backup-agent "$DB"
deny health-ops backup-agent "$API"
deny health-ops backup-agent "$REPLICA"

# reporting must never read records-db directly: run a job with the exact
# reporting pod identity (labels/SA/placement from the CronJob) that tries.
J=smoke-reporting-deny-$RANDOM
k -n health-reporting get cronjob reporting -o json | jq --arg n "$J" --arg host "${DB%:*}" '
  {apiVersion:"batch/v1",kind:"Job",metadata:{name:$n,namespace:"health-reporting"},
   spec:(.spec.jobTemplate.spec | .backoffLimit=0 | .ttlSecondsAfterFinished=60
     | .template.spec.containers[0].command=["nc","-z","-w","3",$host,"5432"])}' | k apply -f - >/dev/null
if k -n health-reporting wait job "$J" --for=condition=Failed --timeout=60s >/dev/null 2>&1; then
  ok "DENY  health-reporting/reporting -> $DB"
else bad "DENY  health-reporting/reporting -> $DB (job did not fail)"; fi
k -n health-reporting delete job "$J" --wait=true >/dev/null

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
