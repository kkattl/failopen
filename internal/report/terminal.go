package report

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

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

// Options control rendering.
type Options struct {
	Color bool
	Width int // wrap width; <= 0 means 100
}

// Width returns $COLUMNS if set and sane, else 100.
func Width() int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n >= 60 {
		return n
	}
	return 100
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
// or, when the first line doesn't fit the width,
//
//	✗ subject
//	    declared:  DECLARED
//	    effective: EFFECTIVE
//	    ...
//
// followed by a one-line snapshot summary. verify: is never wrapped, so it
// stays copy-pasteable.
func Terminal(w io.Writer, findings []detector.Finding, s *collector.Snapshot, opt Options) {
	width := opt.Width
	if width <= 0 {
		width = 100
	}
	color := opt.Color
	paint := func(c, text string) string {
		if !color {
			return text
		}
		return c + text + reset
	}

	counts := map[detector.Severity]int{}
	subjectWidth := 0
	for _, f := range findings {
		counts[f.Severity]++
		subjectWidth = max(subjectWidth, len(f.Subject))
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

	const indent = "      "
	for _, f := range findings {
		icon := icons[f.Severity]
		// Pad before coloring: ANSI codes would throw alignment off.
		subject := f.Subject + strings.Repeat(" ", subjectWidth-len(f.Subject))
		oneLine := 4 + len(subject) + 3 + utf8.RuneCountInString(f.Declared) + 3 + utf8.RuneCountInString(f.Effective)
		if oneLine <= width {
			fmt.Fprintf(w, "  %s %s   %s → %s\n", paint(icon.color, icon.glyph), paint(bold, subject), f.Declared, paint(icon.color, f.Effective))
		} else {
			fmt.Fprintf(w, "  %s %s\n", paint(icon.color, icon.glyph), paint(bold, f.Subject))
			fmt.Fprintf(w, "%sdeclared:  %s\n", indent, f.Declared)
			fmt.Fprintf(w, "%seffective: %s\n", indent, paint(icon.color, f.Effective))
		}
		for _, line := range wrap(f.Detail, width-len(indent)) {
			fmt.Fprintf(w, "%s%s\n", indent, line)
		}
		for _, a := range f.Assumes {
			for i, line := range wrap("assumes: "+a, width-len(indent)-9) {
				if i > 0 {
					line = "         " + line
				}
				fmt.Fprintf(w, "%s%s\n", indent, paint(gray, line))
			}
		}
		if f.Verify != "" {
			fmt.Fprintf(w, "%s%s\n", indent, paint(gray, "verify:  "+f.Verify))
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

// wrap splits text into lines of at most width runes, on spaces.
func wrap(text string, width int) []string {
	if text == "" {
		return nil
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	return append(lines, line)
}
