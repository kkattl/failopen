package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/detector"
)

const (
	red    = "\033[31m"
	yellow = "\033[33m"
	gray   = "\033[90m"
	bold   = "\033[1m"
	reset  = "\033[0m"
)

var icons = map[detector.Severity]struct{ glyph, color string }{
	detector.SeverityCritical: {"✗", red},
	detector.SeverityWarning:  {"⚠", yellow},
	detector.SeverityInfo:     {"ℹ", gray},
}

// UseColor: color only for a terminal, and never with NO_COLOR set.
func UseColor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// Terminal renders findings as
//
//	✗ subject   DECLARED → EFFECTIVE
//	    detail
//	    assumes: ...
//	    verify:  ...
//
// followed by a one-line snapshot summary.
func Terminal(w io.Writer, findings []detector.Finding, s *collector.Snapshot, color bool) {
	paint := func(c, text string) string {
		if !color {
			return text
		}
		return c + text + reset
	}

	counts := map[detector.Severity]int{}
	width := 0
	for _, f := range findings {
		counts[f.Severity]++
		width = max(width, len(f.Subject))
	}
	var parts []string
	for _, sev := range []detector.Severity{detector.SeverityCritical, detector.SeverityWarning, detector.SeverityInfo} {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	header := "failopen audit — " + plural(len(findings), "finding", "findings")
	if len(parts) > 0 {
		header += " (" + strings.Join(parts, ", ") + ")"
	}
	fmt.Fprintln(w, paint(bold, header))
	fmt.Fprintln(w)

	for _, f := range findings {
		icon := icons[f.Severity]
		// Pad before coloring: ANSI codes would throw alignment off.
		subject := f.Subject + strings.Repeat(" ", width-len(f.Subject))
		fmt.Fprintf(w, "  %s %s   %s → %s\n", paint(icon.color, icon.glyph), paint(bold, subject), f.Declared, paint(icon.color, f.Effective))
		if f.Detail != "" {
			fmt.Fprintf(w, "      %s\n", f.Detail)
		}
		for _, a := range f.Assumes {
			fmt.Fprintf(w, "      %s\n", paint(gray, "assumes: "+a))
		}
		if f.Verify != "" {
			fmt.Fprintf(w, "      %s\n", paint(gray, "verify:  "+f.Verify))
		}
		fmt.Fprintln(w)
	}
	if len(findings) == 0 {
		fmt.Fprintln(w, "  no divergence found between declared policy and the network")
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, paint(gray, snapshotLine(s)))
}

func snapshotLine(s *collector.Snapshot) string {
	return fmt.Sprintf("Snapshot: %d namespaces · %d pods · %d services · %s · CNI %s (enforces: %t)",
		len(s.Namespaces), len(s.Pods), len(s.Services),
		plural(len(s.NetworkPolicies), "policy", "policies"), s.CNI.Name, s.CNI.EnforcesPolicy)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
