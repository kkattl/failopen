package detector

import (
	"fmt"

	"github.com/kkattl/failopen/internal/collector"
)

// CNIEnforcement: NetworkPolicies exist but the CNI doesn't implement them —
// every policy in the cluster is decoration.
type CNIEnforcement struct{}

func (*CNIEnforcement) Name() string { return "cni" }

func (*CNIEnforcement) Detect(s *collector.Snapshot) []Finding {
	namespaces := map[string]bool{}
	n := 0
	for _, np := range s.NetworkPolicies {
		if isSystemNamespace(np.Namespace) {
			continue
		}
		n++
		namespaces[np.Namespace] = true
	}
	if n == 0 {
		return nil
	}
	declared := fmt.Sprintf("%d NetworkPolicies across %d namespaces", n, len(namespaces))
	switch {
	case s.CNI.Name == "unknown":
		return []Finding{{
			Detector:  "cni",
			Severity:  SeverityWarning,
			Subject:   "cluster",
			Declared:  declared,
			Effective: "UNKNOWN — CNI not recognised, enforcement unverified",
			Detail: "failopen could not identify the CNI (no known DaemonSet or node annotations), " +
				"so it cannot tell whether these policies are enforced at all.",
			Verify: "kubectl get daemonsets -A -o wide",
		}}
	case !s.CNI.EnforcesPolicy:
		return []Finding{{
			Detector:  "cni",
			Severity:  SeverityCritical,
			Subject:   "cluster",
			Declared:  declared,
			Effective: fmt.Sprintf("NONE ENFORCED — CNI %q does not implement NetworkPolicy", s.CNI.Name),
			Detail: "The API server accepts NetworkPolicy objects whatever the CNI; " +
				"only the network plugin enforces them, and this one doesn't. Every policy here is decoration.",
			Assumes: []string{fmt.Sprintf("CNI detected as %s and no separate policy engine installed", s.CNI.Name)},
			Verify:  "kubectl get daemonsets -A -o wide   # no calico/cilium/kube-router/antrea policy agent",
		}}
	}
	return nil
}
