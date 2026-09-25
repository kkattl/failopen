# Flannel, VXLAN. Does NOT enforce NetworkPolicy: every policy is decoration.
POD_SUBNET=192.168.0.0/16 # same in every profile: scenarios hardcode it in ipBlock excepts
DEFAULT_CNI=false
FLANNEL_VERSION=v0.28.9
CNI_PLUGINS_VERSION=v1.9.1

install() {
  # flannel delegates to the "bridge" plugin, which kind node images lack.
  local tgz; tgz=$(fetch "https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-$CNI_PLUGINS_VERSION.tgz")
  for node in $(kind get nodes --name "$CLUSTER"); do
    docker exec -i "$node" tar -xz -C /opt/cni/bin ./bridge <"$tgz"
  done
  # The manifest hardcodes 10.244.0.0/16 in net-conf.json.
  sed "s|10.244.0.0/16|$POD_SUBNET|" "$(fetch "https://github.com/flannel-io/flannel/releases/download/$FLANNEL_VERSION/kube-flannel.yml")" |
    kctl apply -f -
  kctl -n kube-flannel rollout status ds/kube-flannel-ds --timeout=300s
}
