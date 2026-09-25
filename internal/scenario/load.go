package scenario

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/kkattl/failopen/internal/collector"
)

// Case is one scenario directory.
type Case struct {
	Name string
	Dir  string
	Runs []Run // one per CNI, sorted by CNI name
}

// Run is a scenario measured on one CNI.
type Run struct {
	CNI          string
	Snapshot     *collector.Snapshot
	Reachability *Reachability
}

// Bypasses returns the probes where policy said deny but traffic got through.
func (r *Run) Bypasses() []Probe {
	var out []Probe
	for _, p := range r.Reachability.Probes {
		if p.Verdict == VerdictBypass {
			out = append(out, p)
		}
	}
	return out
}

// LoadAll reads every scenario under root (e.g. testdata/scenarios).
func LoadAll(root string) ([]Case, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := Load(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, nil
}

// Load reads one scenario directory. A CNI subdirectory must contain both
// snapshot.json and reachability.json.
func Load(dir string) (Case, error) {
	c := Case{Name: filepath.Base(dir), Dir: dir}
	if _, err := os.Stat(filepath.Join(dir, "manifests.yaml")); err != nil {
		return c, fmt.Errorf("scenario %s: %w", c.Name, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return c, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		run, err := loadRun(filepath.Join(dir, e.Name()))
		if err != nil {
			return c, fmt.Errorf("scenario %s/%s: %w", c.Name, e.Name(), err)
		}
		c.Runs = append(c.Runs, run)
	}
	sort.Slice(c.Runs, func(i, j int) bool { return c.Runs[i].CNI < c.Runs[j].CNI })
	return c, nil
}

func loadRun(dir string) (Run, error) {
	run := Run{CNI: filepath.Base(dir)}

	f, err := os.Open(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return run, err
	}
	defer f.Close()
	if run.Snapshot, err = collector.ReadJSON(f); err != nil {
		return run, err
	}

	data, err := os.ReadFile(filepath.Join(dir, "reachability.json"))
	if err != nil {
		return run, err
	}
	run.Reachability = &Reachability{}
	if err := json.Unmarshal(data, run.Reachability); err != nil {
		return run, fmt.Errorf("decode reachability: %w", err)
	}
	if run.Snapshot.CNI.Name != run.CNI || run.Reachability.CNI != run.CNI {
		return run, fmt.Errorf("directory says CNI %q, snapshot %q, reachability %q",
			run.CNI, run.Snapshot.CNI.Name, run.Reachability.CNI)
	}
	return run, nil
}
