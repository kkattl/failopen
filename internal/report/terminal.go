package report

import (
	"fmt"
	"io"

	"github.com/kkattl/failopen/internal/collector"
)

// Terminal renders a Snapshot as plain text to the given writer.
// For M0 this is just counts; colored diff output comes in M1.
func Terminal(w io.Writer, s *collector.Snapshot) {
	fmt.Fprintln(w, "failopen — cluster snapshot")
	fmt.Fprintln(w, "===========================")
	fmt.Fprintf(w, "Namespaces:       %d\n", len(s.Namespaces))
	fmt.Fprintf(w, "Nodes:            %d\n", len(s.Nodes))
	fmt.Fprintf(w, "Pods:             %d\n", len(s.Pods))
	fmt.Fprintf(w, "Services:         %d\n", len(s.Services))
	fmt.Fprintf(w, "NetworkPolicies:  %d\n", len(s.NetworkPolicies))
	fmt.Fprintf(w, "CNI:              %s (enforces policy: %t)\n",
		s.CNI.Name, s.CNI.EnforcesPolicy)
}
