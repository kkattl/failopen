// Package scenario defines the on-disk test corpus: realistic clusters whose
// reachability was MEASURED on a real CNI, so detectors are tested against
// ground truth rather than against our assumptions about the network.
//
// Layout:
//
//	testdata/scenarios/<name>/
//	├── manifests.yaml        what was deployed
//	├── README.md             what the system is (optional)
//	└── <profile>/            one directory per lab profile (hack/lab/profiles)
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

// Basis: which rule the expectation for a probe comes from. The Kubernetes
// NetworkPolicy docs carve out behaviour that no policy can change; mixing
// it with plain policy semantics would inflate "bypass" counts.
const (
	// BasisPolicy: plain NetworkPolicy semantics decide.
	BasisPolicy = "policy"
	// BasisSpecException: "traffic to and from the node where a Pod is
	// running is always allowed, regardless of the IP address of the Pod or
	// the node". Applies to node and hostNetwork sources hitting pods on
	// their own node.
	BasisSpecException = "spec-exception"
	// BasisUndefined: the target is a hostNetwork pod — "NetworkPolicy
	// behaviour for hostNetwork pods is undefined". The policy still states
	// the administrator's intent, so reachability here is reported as a
	// bypass, but the basis explains it's CNI-dependent, not a CNI bug.
	BasisUndefined = "undefined-hostnetwork"
	// BasisSNAT: the target saw a different source address than the one the
	// connection started from (kube-proxy masquerade, CNI natOutgoing,
	// tunnel address). The docs: "it is not defined whether this happens
	// before or after NetworkPolicy processing". The verdict still compares
	// against the INTENDED source; this basis explains why it diverged.
	BasisSNAT = "undefined-snat"
	// BasisMixedPath: repeated attempts took different paths (e.g. a
	// Service whose backends sit on different nodes) with different bases.
	// One probe can't stand for all of them; the verdict is "unknown".
	BasisMixedPath = "mixed-path"
	// BasisETPLocal: a NodePort with externalTrafficPolicy: Local on a node
	// without a local backend — dead by design, not by policy.
	BasisETPLocal = "etp-local"
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
	// VerdictSpecException: reachable although policy says deny, because the
	// spec guarantees node-local traffic. Not a CNI bug, still a surprise
	// to most administrators.
	VerdictSpecException = "spec-exception"
)

// Reachability is the oracle's measurement of one scenario on one CNI.
type Reachability struct {
	Profile    string      `json:"profile"` // lab profile, e.g. "calico", "cilium"
	CNI        string      `json:"cni"`     // CNI as detected by the collector
	Provenance *Provenance `json:"provenance,omitempty"`
	Probes     []Probe     `json:"probes"`
}

// Provenance pins down what produced a measurement, so results from
// different oracle versions or cluster builds are never silently compared.
type Provenance struct {
	Timestamp        string   `json:"timestamp"`
	OracleCommit     string   `json:"oracleCommit"`    // "-dirty" suffix if the tree had changes
	PolicyAssistant  string   `json:"policyAssistant"` // matcher commit
	ManifestSHA256   string   `json:"manifestSha256"`
	KubeletVersion   string   `json:"kubeletVersion"`
	ContainerRuntime string   `json:"containerRuntime"`
	CNIImages        []string `json:"cniImages"` // DaemonSet images in system namespaces
	OutsiderNode     string   `json:"outsiderNode"`
	ProbeTimeout     string   `json:"probeTimeout"`
	ServiceAttempts  int      `json:"serviceAttempts"`
}

// Probe is one (source, target) connection attempt.
type Probe struct {
	Source     string `json:"source"`     // "payments/api-server", "node/worker2", "external"
	SourceKind string `json:"sourceKind"` // Source* constant
	Target     string `json:"target"`     // "payments/api-server", "payments/svc/api-nodeport"
	TargetKind string `json:"targetKind"` // Target* constant
	Address    string `json:"address"`    // "172.18.0.2:31080"
	Declared   string `json:"declared"`   // Declared*: policy text, for the INTENDED source
	Basis      string `json:"basis"`      // Basis* constant
	Effective  string `json:"effective"`  // best Effective* over attempts, policies in place
	Baseline   string `json:"baseline"`   // best Effective* over attempts, policies removed
	Verdict    string `json:"verdict"`    // Verdict* constant

	// Attempts > 1 for load-balanced targets; Hits is how many of them got
	// through with policies in place ("2/4" = depends on backend choice).
	Attempts int    `json:"attempts"`
	Hits     string `json:"hits"`
	// ObservedSources are the source addresses the target reported seeing
	// (baseline run); empty if the target could not report them.
	ObservedSources []string `json:"observedSources,omitempty"`
	// DeclaredObserved is the policy verdict for the observed sources; it
	// differs from Declared exactly when source rewriting changes the answer.
	DeclaredObserved string `json:"declaredObserved,omitempty"`
}

// BaselineReachable reports whether the path works at all (policies removed).
func BaselineReachable(baseline string) bool {
	return baseline == EffectiveOpen || baseline == EffectiveRefused
}

// Reachable reports whether packets got through with policies in place.
// REFUSED only counts if the baseline was REFUSED too (nothing listens, the
// RST came from the pod). OPEN in baseline but REFUSED now means something
// in between rejected it — kube-proxy for endpoint-less Services, a CNI
// configured to REJECT instead of DROP — which is blocked, not reachable.
func Reachable(effective, baseline string) bool {
	switch effective {
	case EffectiveOpen:
		return true
	case EffectiveRefused:
		return baseline == EffectiveRefused
	default:
		return false
	}
}

// Classify derives the verdict from the intended-source declared verdict,
// the basis, and the measured outcomes.
func Classify(declared, basis, effective, baseline string) string {
	if !BaselineReachable(baseline) {
		return VerdictUnreachable
	}
	if basis == BasisMixedPath {
		return VerdictUnknown
	}
	reach := Reachable(effective, baseline)
	if basis == BasisSpecException && declared == DeclaredDeny && reach {
		return VerdictSpecException
	}
	switch declared {
	case DeclaredAllow:
		if reach {
			return VerdictMatch
		}
		return VerdictOverblock
	case DeclaredDeny:
		if reach {
			return VerdictBypass
		}
		return VerdictMatch
	default:
		return VerdictUnknown
	}
}
