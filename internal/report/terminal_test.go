package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/detector"
)

func TestTerminal(t *testing.T) {
	findings := []detector.Finding{
		{Severity: detector.SeverityCritical, Subject: "cluster", Declared: "3 NetworkPolicies across 2 namespaces",
			Effective: "NONE ENFORCED", Detail: "decoration", Verify: "kubectl get ds -A"},
		{Severity: detector.SeverityWarning, Subject: "edge/svc/gw:30080", Declared: "ALLOW only 0.0.0.0/0",
			Effective: "ALLOW from any pod", Assumes: []string{"SNAT"}},
	}
	var buf bytes.Buffer
	Terminal(&buf, findings, &collector.Snapshot{CNI: collector.CNIInfo{Name: "flannel"}}, false)
	out := buf.String()
	for _, want := range []string{
		"failopen audit — 2 findings (1 critical, 1 warning)",
		"  ✗ cluster             3 NetworkPolicies across 2 namespaces → NONE ENFORCED",
		"  ⚠ edge/svc/gw:30080   ALLOW only 0.0.0.0/0 → ALLOW from any pod",
		"      assumes: SNAT",
		"      verify:  kubectl get ds -A",
		"CNI flannel (enforces: false)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\033[") {
		t.Error("color=false must not emit ANSI codes")
	}
}
