# kindnet, kind's built-in CNI; enforces NetworkPolicy via
# kube-network-policies (nftables).
POD_SUBNET=192.168.0.0/16 # same in every profile: scenarios hardcode it in ipBlock excepts
DEFAULT_CNI=true

install() {
  kctl -n kube-system rollout status ds/kindnet --timeout=300s
}
