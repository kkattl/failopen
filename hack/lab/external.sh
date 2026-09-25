#!/usr/bin/env bash
# "External" client for lab clusters: a container on the kind docker network
# that sources traffic from 10.250.0.10 — an address OUTSIDE the node
# network. Without it, "external" traffic comes from the docker gateway
# (172.18.0.1), which sits inside the node subnet: any ipBlock meant for an
# external range then also matches node IPs and SNAT'd pod traffic, and the
# lab manufactures bypasses that production wouldn't have.
#
# Scenario contract: the external world (F5, plant network, internet
# clients) is 10.250.0.0/24; the client is 10.250.0.10.
#
# Usage: hack/lab/external.sh ensure <cluster-name>   (kind or k3d)
#        hack/lab/external.sh down
set -euo pipefail

NAME=failopen-ext
EXT_IP=10.250.0.10
IMAGE=registry.k8s.io/e2e-test-images/agnhost:2.53

case ${1:-} in
ensure)
  cluster=${2:?usage: $0 ensure <cluster-name>}
  if ! docker inspect "$NAME" >/dev/null 2>&1; then
    docker run -d --name "$NAME" --network kind --cap-add NET_ADMIN --restart unless-stopped \
      --entrypoint /agnhost "$IMAGE" pause >/dev/null
  elif [[ $(docker inspect -f '{{.State.Running}}' "$NAME") != true ]]; then
    docker start "$NAME" >/dev/null # e.g. after a host reboot; its address config is gone too
  fi
  kind_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$NAME")
  kind_net=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | grep -m1 '\.')
  docker exec "$NAME" sh -c "ip addr add $EXT_IP/32 dev eth0 2>/dev/null || true
    ip route replace $kind_net dev eth0 src $EXT_IP"
  if kind get clusters 2>/dev/null | grep -qx "$cluster"; then
    nodes=$(kind get nodes --name "$cluster")
  else # k3d: node containers carry the cluster label; skip its API load balancer
    nodes=$(docker ps --filter "label=k3d.cluster=$cluster" --format '{{.Names}}' | grep -v -- '-serverlb$')
  fi
  [[ -n $nodes ]] || { echo "no nodes found for cluster $cluster" >&2; exit 1; }
  for node in $nodes; do
    docker exec "$node" ip route replace "$EXT_IP/32" via "$kind_ip"
  done
  echo "$NAME: $EXT_IP via $kind_ip, routed from cluster $cluster"
  ;;
down)
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  ;;
*)
  echo "usage: $0 ensure <cluster-name> | down" >&2
  exit 2
  ;;
esac
