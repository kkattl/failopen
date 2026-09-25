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
	Terminal(&buf, findings, &collector.Snapshot{CNI: collector.CNIInfo{Name: "flannel"}}, Options{Width: 200})
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

func TestTerminalStacksLongFindings(t *testing.T) {
	f := detector.Finding{Severity: detector.SeverityCritical, Subject: "ecom-edge/svc/edge-proxy:30080",
		Declared:  "ALLOW only 172.18.0.0/16 (edge-proxy-ingress-from-f5)",
		Effective: "ALLOW from any pod via NodePort 30080 (SNAT to node IP)",
		Detail:    strings.Repeat("word ", 40),
		Verify:    "kubectl run fo-verify --rm -i --restart=Never --image=registry.k8s.io/e2e-test-images/agnhost:2.53 -- connect 172.18.0.6:30080",
	}
	var buf bytes.Buffer
	Terminal(&buf, []detector.Finding{f}, &collector.Snapshot{}, Options{Width: 80})
	out := buf.String()
	for _, want := range []string{
		"  ✗ ecom-edge/svc/edge-proxy:30080\n",
		"      declared:  ALLOW only 172.18.0.0/16 (edge-proxy-ingress-from-f5)\n",
		"      effective: ALLOW from any pod via NodePort 30080 (SNAT to node IP)\n",
		"      verify:  " + f.Verify + "\n", // never wrapped
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "      word") && len(line) > 80 {
			t.Errorf("detail line exceeds width: %q", line)
		}
	}
}
