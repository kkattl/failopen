package collector

import (
	"encoding/json"
	"fmt"
	"io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// lastApplied is dropped on export: it duplicates the whole object.
const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// WriteJSON serialises a Snapshot for offline use: the scenario test corpus
// and bug reports ("send me your snapshot"). Bookkeeping metadata that no
// detector reads (managedFields, last-applied) is stripped in place.
func WriteJSON(w io.Writer, s *Snapshot) error {
	for i := range s.Pods {
		stripMeta(&s.Pods[i].ObjectMeta)
	}
	for i := range s.Services {
		stripMeta(&s.Services[i].ObjectMeta)
	}
	for i := range s.NetworkPolicies {
		stripMeta(&s.NetworkPolicies[i].ObjectMeta)
	}
	for i := range s.Namespaces {
		stripMeta(&s.Namespaces[i].ObjectMeta)
	}
	for i := range s.Nodes {
		stripMeta(&s.Nodes[i].ObjectMeta)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// ReadJSON loads a Snapshot written by WriteJSON.
func ReadJSON(r io.Reader) (*Snapshot, error) {
	var s Snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &s, nil
}

func stripMeta(m *metav1.ObjectMeta) {
	m.ManagedFields = nil
	delete(m.Annotations, lastApplied)
}
