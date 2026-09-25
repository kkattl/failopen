package scenario

import "testing"

// TestCorpusLoads keeps testdata/scenarios well-formed: every measured run
// must parse and agree on its CNI.
func TestCorpusLoads(t *testing.T) {
	cases, err := LoadAll("../../testdata/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		for _, r := range c.Runs {
			if len(r.Reachability.Probes) == 0 {
				t.Errorf("%s/%s: no probes", c.Name, r.CNI)
			}
		}
	}
}
