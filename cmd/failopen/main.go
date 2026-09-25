package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/kkattl/failopen/internal/cli"
)

// Exit codes (CI contract, documented in README):
//
//	0 — audit ran, no critical findings
//	1 — audit ran, critical findings present
//	2 — audit could not run (bad flags, cluster unreachable, ...)
func main() {
	err := cli.Execute()
	switch {
	case err == nil:
		os.Exit(0)
	case errors.Is(err, cli.ErrCriticalFindings):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
