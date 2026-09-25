# Calico, iptables dataplane, IPIP overlay (the manifest default).
POD_SUBNET=192.168.0.0/16
DEFAULT_CNI=false

install() {
  kctl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
  kctl -n kube-system rollout status ds/calico-node --timeout=300s
}
