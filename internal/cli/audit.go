package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/report"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Collect a cluster snapshot and report it",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := collector.NewK8sCollector(kubeconfigPath)
		if err != nil {
			return fmt.Errorf("init collector: %w", err)
		}

		snap, err := c.Collect(context.Background())
		if err != nil {
			return fmt.Errorf("collect snapshot: %w", err)
		}

		// M0: terminal only. JSON output lands in M2.
		report.Terminal(os.Stdout, snap)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
