#!/usr/bin/env bash
# Formcraft smoke test: proves intended flows work and forbidden flows are blocked.
# Usage: KUBECONFIG=/path/to/kubeconfig ./smoke.sh   (or: ./smoke.sh /path/to/kubeconfig)
set -uo pipefail

KCFG="${1:-${KUBECONFIG:-}}"
[ -n "$KCFG" ] || { echo "usage: $0 <kubeconfig> (or set KUBECONFIG)"; exit 2; }
k() { kubectl --kubeconfig "$KCFG" "$@"; }

TENANTS=(acme globex initech)
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$*"; }

pod() { # pod <namespace> <app.kubernetes.io/name>
  k -n "$1" get pod -l "app.kubernetes.io/name=$2" --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}'
}
podip() { k -n "$1" get pod -l "app.kubernetes.io/name=$2" -o jsonpath='{.items[0].status.podIP}'; }

# agnhost connect from <ns>/<component> to <host:port>; returns 0 if the TCP connection succeeded
try() { k -n "$1" exec "$(pod "$1" "$2")" -c "$2" -- /agnhost connect "$3" --timeout=3s >/dev/null 2>&1; }

allow() { # allow <src-ns> <src-comp> <dst> <description>
  if try "$1" "$2" "$3"; then ok "ALLOW $4 ($1/$2 -> $3)"; else bad "expected ALLOW but blocked: $4 ($1/$2 -> $3)"; fi
}
deny() {
  if try "$1" "$2" "$3"; then bad "expected DENY but CONNECTED: $4 ($1/$2 -> $3)"; else ok "DENY  $4 ($1/$2 -> $3)"; fi
}

echo "== Preflight: all pods Ready"
for ns in saas-edge saas-platform "${TENANTS[@]/#/saas-tenant-}"; do
  if k -n "$ns" wait --for=condition=Ready pod --all --timeout=120s >/dev/null; then ok "$ns pods Ready"; else bad "$ns pods not Ready"; fi
done

EDGE_NODE=$(k -n saas-edge get pod -l app.kubernetes.io/name=gateway -o jsonpath='{.items[0].spec.nodeName}')
EDGE_IP=$(k get node "$EDGE_NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
NODEPORT=$(k -n saas-edge get svc gateway -o jsonpath='{.spec.ports[0].nodePort}')
GW_IP=$(podip saas-edge gateway)
KUBE_API=$(k -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}')

echo "== Placement"
pool=$(k get node "$EDGE_NODE" -o jsonpath='{.metadata.labels.pool}')
[ "$pool" = edge ] && ok "gateway runs on edge pool ($EDGE_NODE)" || bad "gateway on pool '$pool'"
misplaced=0
for ns in saas-platform "${TENANTS[@]/#/saas-tenant-}"; do
  for n in $(k -n "$ns" get pod -o jsonpath='{.items[*].spec.nodeName}'); do
    p=$(k get node "$n" -o jsonpath='{.metadata.labels.pool}')
    [ "$p" = general ] || { bad "$ns pod on non-general node $n ($p)"; misplaced=1; }
  done
done
[ "$misplaced" = 0 ] && ok "platform + tenant pods all on general pool"

echo "== North-south: external client -> edge node -> gateway -> tenant app (Host routing)"
for t in "${TENANTS[@]}"; do
  expected=$(pod "saas-tenant-$t" app)
  got=$(curl -s --max-time 5 -H "Host: $t.formcraft.example" "http://$EDGE_IP:$NODEPORT/hostname" || true)
  [ "$got" = "$expected" ] && ok "$t.formcraft.example -> saas-tenant-$t/app ($got)" \
                           || bad "$t.formcraft.example routed to '$got', expected '$expected'"
done
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Host: evil.example" "http://$EDGE_IP:$NODEPORT/hostname" || true)
[ "$code" = 404 ] && ok "unknown Host header -> 404 (no default tenant)" || bad "unknown Host returned $code"

echo "== Intended east-west flows (must be ALLOWED)"
for t in "${TENANTS[@]}"; do
  ns="saas-tenant-$t"
  allow "$ns" app    "db.$ns.svc.cluster.local:5432"                  "$t app -> own db"
  allow "$ns" worker "db.$ns.svc.cluster.local:5432"                  "$t worker -> own db"
  allow "$ns" app    "auth.saas-platform.svc.cluster.local:8080"      "$t app -> auth"
  allow "$ns" worker "mailer.saas-platform.svc.cluster.local:2525"    "$t worker -> mailer"
  allow saas-platform billing "app.$ns.svc.cluster.local:8080"        "billing -> $t app"
done

echo "== Tenant isolation (must be DENIED, every ordered tenant pair)"
for a in "${TENANTS[@]}"; do for b in "${TENANTS[@]}"; do
  [ "$a" = "$b" ] && continue
  sa="saas-tenant-$a"; sb="saas-tenant-$b"
  deny "$sa" app    "app.$sb.svc.cluster.local:8080"   "$a app -> $b app (Service)"
  deny "$sa" app    "$(podip "$sb" db):5432"            "$a app -> $b db (pod IP)"
  deny "$sa" worker "db.$sb.svc.cluster.local:5432"    "$a worker -> $b db (Service)"
  deny "$sa" worker "$(podip "$sb" app):8080"           "$a worker -> $b app (pod IP)"
done; done
# db pods are postgres (no agnhost): use pg_isready from acme's db to globex's db
if k -n saas-tenant-acme exec db-0 -- pg_isready -t 3 -h "$(podip saas-tenant-globex db)" >/dev/null 2>&1; then
  bad "expected DENY but CONNECTED: acme db -> globex db"
else ok "DENY  acme db -> globex db (pg_isready)"; fi

echo "== Least privilege / side doors (must be DENIED)"
deny saas-tenant-acme app    "$(podip saas-tenant-globex app):8080"      "acme app -> globex app bypassing Service"
deny saas-tenant-acme app    "$EDGE_IP:$NODEPORT"                        "acme app -> edge NodePort hairpin (reach globex via front door)"
deny saas-tenant-acme app    "$GW_IP:8080"                               "acme app -> gateway pod directly"
deny saas-tenant-acme app    "mailer.saas-platform.svc.cluster.local:2525" "app -> mailer (only workers send mail)"
deny saas-tenant-acme worker "auth.saas-platform.svc.cluster.local:8080" "worker -> auth (only apps call auth)"
deny saas-tenant-acme worker "app.saas-tenant-acme.svc.cluster.local:8080" "worker -> own app (no such flow)"
deny saas-tenant-acme app    "$KUBE_API:443"                             "tenant app -> Kubernetes API"
ACME_NODE_IP=$(k get node "$(k -n saas-tenant-acme get pod -l app.kubernetes.io/name=app -o jsonpath='{.items[0].spec.nodeName}')" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
deny saas-tenant-acme app    "$ACME_NODE_IP:10250"                       "tenant app -> kubelet on its own node"
deny saas-tenant-acme app    "1.1.1.1:443"                               "tenant app -> internet"
deny saas-platform billing   "db.saas-tenant-acme.svc.cluster.local:5432" "billing -> tenant db"
deny saas-platform auth      "app.saas-tenant-acme.svc.cluster.local:8080" "auth -> tenant app (auth is called, never calls)"
deny saas-platform mailer    "app.saas-tenant-acme.svc.cluster.local:8080" "mailer -> tenant app"
deny saas-platform mailer    "1.1.1.1:443"                               "mailer -> internet on non-SMTP port"
deny saas-platform billing   "auth.saas-platform.svc.cluster.local:8080" "billing -> auth"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
