# Calico as in the calico profile, with kube-proxy in IPVS mode instead of
# iptables: a different NodePort/masquerade implementation under the same CNI.
# Needs the ip_vs kernel modules on the host:
#   sudo modprobe -a ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh nf_conntrack
# shellcheck source=/dev/null
source hack/lab/profiles/calico.sh
KUBE_PROXY_MODE=ipvs
