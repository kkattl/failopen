#!/usr/bin/env bash
# Smoke test for the Northwind online store.
# Usage: KUBECONFIG=/path/to/kubeconfig ./smoke.sh   (or pass the path as $1)
# Exit 0 = every check passed. Needs kubectl, and curl from a host on the
# node network (stands in for the F5).
set -uo pipefail

KCFG="${1:-${KUBECONFIG:-$(dirname "$0")/../lab-kubeconfig}}"
k() { kubectl --kubeconfig "$KCFG" "$@"; }
NODEPORT=30080
PASS=0; FAIL=0

ok()   { printf '  PASS  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }

# expect <allow|deny> <ns> <workload> <host:port> ; source runs agnhost
expect() {
  local want=$1 ns=$2 src=$3 dst=$4 rc
  k -n "$ns" exec "$src" -c app -- /agnhost connect "$dst" --timeout=3s >/dev/null 2>&1; rc=$?
  local label="$ns/${src#*/} -> $dst"
  if [[ $want == allow ]]; then
    [[ $rc -eq 0 ]] && ok "ALLOW $label" || bad "ALLOW $label (rc=$rc)"
  else
    [[ $rc -ne 0 ]] && ok "DENY  $label" || bad "DENY  $label (connected!)"
  fi
}

# edge-proxy is nginx (no agnhost): use busybox wget
expect_edge() {
  local want=$1 url=$2 rc
  k -n ecom-edge exec ds/edge-proxy -- wget -q -T 3 -O /dev/null "$url" >/dev/null 2>&1; rc=$?
  if [[ $want == allow ]]; then
    [[ $rc -eq 0 ]] && ok "ALLOW ecom-edge/edge-proxy -> $url" || bad "ALLOW ecom-edge/edge-proxy -> $url (rc=$rc)"
  else
    [[ $rc -ne 0 ]] && ok "DENY  ecom-edge/edge-proxy -> $url" || bad "DENY  ecom-edge/edge-proxy -> $url (connected!)"
  fi
}

WEB=web.ecom-storefront:8080
BFF=bff.ecom-storefront:8080
CAT=catalog-api.ecom-catalog:8080
SEARCH=search.ecom-catalog:8080
CATDB=catalog-db.ecom-catalog:5432
CART=cart.ecom-orders:8080
CHECKOUT=checkout.ecom-orders:8080
ORDDB=orders-db.ecom-orders:5432
CACHE=session-cache.ecom-shared:6379

echo "== 0. readiness"
for ns in ecom-edge ecom-storefront ecom-catalog ecom-orders ecom-shared; do
  if k -n "$ns" wait --for=condition=Ready pod --all --timeout=180s >/dev/null 2>&1; then
    ok "all pods Ready in $ns"
  else
    bad "pods not Ready in $ns"
  fi
done

echo "== 1. placement"
pool_of() { k get node "$1" -o jsonpath='{.metadata.labels.pool}'; }
while read -r ns name node app; do
  pool=$(pool_of "$node")
  case $app in
    edge-proxy)          want=edge ;;
    checkout|orders-db)  want=restricted ;;
    *)                   want=general ;;
  esac
  [[ $pool == "$want" ]] && ok "$ns/$name on pool=$pool" || bad "$ns/$name on pool=$pool (want $want)"
done < <(k get pods -A -l app -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.spec.nodeName} {.metadata.labels.app}{"\n"}{end}' | grep '^ecom-')

echo "== 2. F5 path: edge node IP:$NODEPORT (from this host)"
EDGE_IPS=$(k get nodes -l pool=edge -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{" "}{end}')
OTHER_IP=$(k get nodes -l pool=general -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
for ip in $EDGE_IPS; do
  body=$(curl -s -m 5 "http://$ip:$NODEPORT/hostname") && [[ $body == web-* ]] \
    && ok "F5 -> $ip:$NODEPORT/ served by $body" || bad "F5 -> $ip:$NODEPORT/ (got '$body')"
  body=$(curl -s -m 5 "http://$ip:$NODEPORT/api/hostname") && [[ $body == bff-* ]] \
    && ok "F5 -> $ip:$NODEPORT/api/ served by $body" || bad "F5 -> $ip:$NODEPORT/api/ (got '$body')"
done
# externalTrafficPolicy=Local: non-edge nodes must not serve the store
if curl -s -m 4 -o /dev/null "http://$OTHER_IP:$NODEPORT/healthz"; then
  bad "general node $OTHER_IP:$NODEPORT answers (should not)"
else
  ok "general node $OTHER_IP:$NODEPORT does not serve traffic"
fi

echo "== 3. intended flows (must be ALLOWED)"
expect_edge allow "http://$WEB/healthz"
expect_edge allow "http://$BFF/healthz"
expect allow ecom-storefront deploy/web  $BFF
expect allow ecom-storefront deploy/web  $CACHE
expect allow ecom-storefront deploy/bff  $CAT
expect allow ecom-storefront deploy/bff  $CART
expect allow ecom-storefront deploy/bff  $CHECKOUT
expect allow ecom-storefront deploy/bff  $CACHE
expect allow ecom-catalog    deploy/catalog-api $SEARCH
expect allow ecom-catalog    deploy/catalog-api $CATDB
expect allow ecom-catalog    deploy/search $CATDB
expect allow ecom-orders     deploy/cart $ORDDB
expect allow ecom-orders     deploy/cart $CAT
expect allow ecom-orders     deploy/cart $CACHE
expect allow ecom-orders     deploy/checkout $ORDDB
expect allow ecom-orders     deploy/checkout $CART
expect allow ecom-orders     deploy/checkout $CAT

echo "== 4. forbidden flows (must be DENIED)"
expect_edge deny "http://$CAT/healthz"          # edge may only reach storefront
expect_edge deny "http://$CHECKOUT/healthz"
expect deny ecom-storefront deploy/web $CAT       # web goes through bff
expect deny ecom-storefront deploy/web $CATDB     # no DB access from storefront
expect deny ecom-storefront deploy/web $ORDDB
expect deny ecom-storefront deploy/bff $CATDB
expect deny ecom-storefront deploy/bff $ORDDB
expect deny ecom-storefront deploy/bff $SEARCH    # search is catalog-internal
expect deny ecom-catalog    deploy/catalog-api $ORDDB   # other team's DB
expect deny ecom-catalog    deploy/catalog-api $CART
expect deny ecom-catalog    deploy/catalog-api $CACHE
expect deny ecom-catalog    deploy/search $CACHE
expect deny ecom-orders     deploy/cart $CATDB          # other team's DB
expect deny ecom-orders     deploy/cart $CHECKOUT
expect deny ecom-orders     deploy/checkout $CATDB
expect deny ecom-orders     deploy/checkout $CACHE
expect deny ecom-orders     deploy/checkout $WEB
expect deny ecom-storefront deploy/web "1.1.1.1:443"    # no internet egress

echo
echo "RESULT: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
