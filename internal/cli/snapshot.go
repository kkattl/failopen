package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kkattl/failopen/internal/collector"
)

// snapshotCmd dumps the raw Snapshot as JSON. Hidden: it's a debugging and
// test-corpus tool, not part of the user-facing audit workflow.
var snapshotCmd = &cobra.Command{
	Use:    "snapshot",
	Short:  "Dump the collected cluster snapshot as JSON",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := collector.NewK8sCollector(kubeconfigPath)
		if err != nil {
			return fmt.Errorf("init collector: %w", err)
		}
		snap, err := c.Collect(context.Background())
		if err != nil {
			return fmt.Errorf("collect snapshot: %w", err)
		}
		return collector.WriteJSON(os.Stdout, snap)
	},
}

func init() {
	rootCmd.AddCommand(snapshotCmd)
}
