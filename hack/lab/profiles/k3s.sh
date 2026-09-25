# k3s (via k3d): a different distribution, not just a different CNI.
# Flannel (VXLAN) and a kube-router NetworkPolicy controller are embedded in
# the k3s binary — no CNI DaemonSet exists. Defaults kept on purpose
# (traefik, servicelb): that's what real k3s clusters run.
PROVIDER=k3d
POD_SUBNET=192.168.0.0/16 # same in every profile: scenarios hardcode it in ipBlock excepts
K3D_EXTRA_ARGS="--k3s-arg --cluster-cidr=$POD_SUBNET@server:*"

install() {
  kctl -n kube-system rollout status deploy/coredns --timeout=300s
}
