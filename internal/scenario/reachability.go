// Package scenario defines the on-disk test corpus: realistic clusters whose
// reachability was MEASURED on a real CNI, so detectors are tested against
// ground truth rather than against our assumptions about the network.
//
// Layout:
//
//	testdata/scenarios/<name>/
//	├── manifests.yaml        what was deployed
//	├── README.md             what the system is (optional)
//	└── <cni>/                one directory per CNI the oracle ran on
//	    ├── snapshot.json     collector.Snapshot captured from that cluster
//	    └── reachability.json measured probes (written by hack/oracle)
package scenario

// Source kinds: who initiates the connection.
const (
	SourcePod         = "pod"             // ordinary pod, identity = its labels
	SourceHostNetwork = "hostnetwork-pod" // pod in the node netns, identity = node IP
	SourceNode        = "node"            // the node itself (oracle agent)
	SourceOutsider    = "outsider"        // unlabelled pod in an unrelated namespace
	SourceExternal    = "external"        // outside the cluster, reaches node IPs only
)

// Target kinds: which address the connection was aimed at.
const (
	TargetPodIP       = "pod-ip"
	TargetHostNetwork = "hostnetwork" // node IP : containerPort of a hostNetwork pod
	TargetHostPort    = "hostport"
	TargetClusterIP   = "clusterip"
	TargetNodePort    = "nodeport"
)

// Declared verdicts, as computed from NetworkPolicy semantics.
const (
	DeclaredAllow = "allow"
	DeclaredDeny  = "deny"
	DeclaredMixed = "mixed" // service backends disagree
	DeclaredNA    = "n/a"   // no backend pods (e.g. selector-less service)
)

// Effective outcomes, as measured with `agnhost connect`.
const (
	EffectiveOpen    = "open"    // TCP handshake succeeded
	EffectiveRefused = "refused" // RST: packet reached the pod, port closed
	EffectiveTimeout = "timeout" // dropped (policy) or no route
	EffectiveError   = "error"   // DNS/other; treat as unreachable
)

// Verdicts: declared vs effective.
const (
	VerdictMatch       = "match"
	VerdictBypass      = "bypass"      // declared deny, packets got through
	VerdictOverblock   = "overblock"   // declared allow, packets dropped
	VerdictUnreachable = "unreachable" // path is dead even without policies
	VerdictUnknown     = "unknown"     // declared is n/a or mixed
)

// Reachability is the oracle's measurement of one scenario on one CNI.
type Reachability struct {
	CNI    string  `json:"cni"`
	Probes []Probe `json:"probes"`
}

// Probe is one (source, target) connection attempt.
type Probe struct {
	Source     string `json:"source"`     // "payments/api-server", "node/worker2", "external"
	SourceKind string `json:"sourceKind"` // Source* constant
	Target     string `json:"target"`     // "payments/api-server", "payments/svc/api-nodeport"
	TargetKind string `json:"targetKind"` // Target* constant
	Address    string `json:"address"`    // "172.18.0.2:31080"
	Declared   string `json:"declared"`   // Declared* constant
	Effective  string `json:"effective"`  // Effective* with policies in place
	Baseline   string `json:"baseline"`   // Effective* with policies removed
	Verdict    string `json:"verdict"`    // Verdict* constant
}

// Reachable reports whether a measured outcome means packets got through.
// REFUSED counts: the RST came from the destination, so policy let it in.
func Reachable(effective string) bool {
	return effective == EffectiveOpen || effective == EffectiveRefused
}

// Classify derives the verdict from declared, effective and baseline.
func Classify(declared, effective, baseline string) string {
	if !Reachable(baseline) {
		return VerdictUnreachable
	}
	switch declared {
	case DeclaredAllow:
		if Reachable(effective) {
			return VerdictMatch
		}
		return VerdictOverblock
	case DeclaredDeny:
		if Reachable(effective) {
			return VerdictBypass
		}
		return VerdictMatch
	default:
		return VerdictUnknown
	}
}
