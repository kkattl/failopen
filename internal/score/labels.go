// Package score measures detectors against blind human/agent labels
// (labeling/*.expected.yaml) on every measured run of the scenario corpus,
// and reconciles those labels with what the oracle measured.
package score

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

// Label values.
const (
	Must    = "must"
	May     = "may"
	MustNot = "must-not"
)

type Subject struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Port      int    `json:"port"`
}

type Label struct {
	ID           string   `json:"id"`
	Class        string   `json:"class"`
	Subject      Subject  `json:"subject"`
	Mechanism    string   `json:"mechanism"`
	AppliesToCNI []string `json:"applies_to_cni"`
	Label        string   `json:"label"`
	Severity     string   `json:"severity"`
	Rationale    string   `json:"rationale"`

	// Inherited is set for labels carried over from a mutation's base
	// scenario (decision Q6); InheritedFrom names it.
	InheritedFrom string `json:"-"`
}

type LabelFile struct {
	Scenario string  `json:"scenario"`
	Labeler  string  `json:"labeler"`
	Blind    bool    `json:"blind"`
	Findings []Label `json:"findings"`
}

// AppliesTo reports whether the label is meant for a lab profile.
func (l Label) AppliesTo(profile string) bool {
	return slices.Contains(l.AppliesToCNI, "any") || slices.Contains(l.AppliesToCNI, profile)
}

// systemNamespaces: labels about them aren't scored (decision Q4) —
// detectors skip system namespaces by design.
var systemNamespaces = regexp.MustCompile(`^(kube-.*|calico-.*|tigera-operator|cilium.*|local-path-storage)$`)

// LoadLabels reads labeling/<scenario>.expected.yaml for every scenario and
// applies mutation inheritance: a scenario named "<base>-<suffix>" whose
// base is labelled inherits the base's labels, except (a) those whose
// subject is an object the mutation changed and (b) those the mutant
// labels itself (same class + subject).
func LoadLabels(labelDir, scenarioDir string) (map[string]*LabelFile, error) {
	files, err := filepath.Glob(filepath.Join(labelDir, "*.expected.yaml"))
	if err != nil {
		return nil, err
	}
	out := map[string]*LabelFile{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var lf LabelFile
		if err := yaml.Unmarshal(data, &lf); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		lf.Findings = slices.DeleteFunc(lf.Findings, func(l Label) bool {
			return systemNamespaces.MatchString(l.Subject.Namespace)
		})
		out[lf.Scenario] = &lf
	}
	for name, lf := range out {
		base := baseOf(name, out)
		if base == "" {
			continue
		}
		mutated, err := mutatedObjects(filepath.Join(scenarioDir, base, "manifests.yaml"),
			filepath.Join(scenarioDir, name, "manifests.yaml"))
		if err != nil {
			return nil, fmt.Errorf("diff %s vs %s: %w", base, name, err)
		}
		own := map[string]bool{}
		for _, l := range lf.Findings {
			own[l.Class+"|"+subjectKey(l.Subject)] = true
		}
		for _, l := range out[base].Findings {
			if own[l.Class+"|"+subjectKey(l.Subject)] || mutated[l.Subject.Namespace+"/"+l.Subject.Name] {
				continue
			}
			l.ID = base + ":" + l.ID
			l.InheritedFrom = base
			lf.Findings = append(lf.Findings, l)
		}
	}
	return out, nil
}

func subjectKey(s Subject) string {
	return strings.ToLower(s.Kind) + "/" + s.Namespace + "/" + s.Name
}

// baseOf: the longest labelled scenario name that prefixes name + "-".
func baseOf(name string, labelled map[string]*LabelFile) string {
	best := ""
	for other := range labelled {
		if other != name && strings.HasPrefix(name, other+"-") && len(other) > len(best) {
			best = other
		}
	}
	return best
}

// mutatedObjects returns "namespace/name" of every object that differs
// between two manifest files (added, removed or changed).
func mutatedObjects(basePath, mutantPath string) (map[string]bool, error) {
	a, err := objects(basePath)
	if err != nil {
		return nil, err
	}
	b, err := objects(mutantPath)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for k, v := range b {
		if a[k] != v {
			out[k] = true
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			out[k] = true
		}
	}
	return out, nil
}

// objects maps "namespace/name" to the object's canonical JSON.
func objects(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	out := map[string]string{}
	for {
		var obj map[string]any
		if err := dec.Decode(&obj); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if obj == nil {
			continue
		}
		md, _ := obj["metadata"].(map[string]any)
		ns, _ := md["namespace"].(string)
		name, _ := md["name"].(string)
		canon, err := json.Marshal(obj) // map keys are sorted: deterministic
		if err != nil {
			return nil, err
		}
		out[ns+"/"+name] = string(canon)
	}
	return out, nil
}
