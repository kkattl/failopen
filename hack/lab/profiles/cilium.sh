# Cilium, eBPF dataplane, VXLAN overlay, kube-proxy kept (no KPR) so that
# Service/NodePort handling stays comparable with the other profiles.
POD_SUBNET=192.168.0.0/16 # same in every profile: scenarios hardcode it in ipBlock excepts
DEFAULT_CNI=false
CILIUM_VERSION=1.20.2

install() {
  "$(tool helm)" install cilium cilium --repo https://helm.cilium.io --version "$CILIUM_VERSION" \
    --kubeconfig "$KUBECONFIG" --namespace kube-system \
    --set ipam.mode=kubernetes --set kubeProxyReplacement=false
  kctl -n kube-system rollout status ds/cilium --timeout=600s
}
