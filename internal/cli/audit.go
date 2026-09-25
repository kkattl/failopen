package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kkattl/failopen/internal/collector"
	"github.com/kkattl/failopen/internal/detector"
	"github.com/kkattl/failopen/internal/report"
)

var snapshotPath string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Find where NetworkPolicy says DENY but the network lets traffic through",
	Long: `Collects a read-only snapshot of the cluster (or reads one with --snapshot),
runs every detector and prints the findings.

Exit codes: 0 no critical findings, 1 critical findings, 2 the audit could not run.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		snap, err := loadSnapshot(cmd.Context())
		if err != nil {
			return err
		}
		findings := detector.Run(snap)
		color := colorMode == "always" || colorMode == "auto" && report.UseColor(os.Stdout)
		report.Terminal(os.Stdout, findings, snap, report.Options{Color: color, Width: report.Width()})
		for _, f := range findings {
			if f.Severity == detector.SeverityCritical {
				return ErrCriticalFindings
			}
		}
		return nil
	},
}

// loadSnapshot reads --snapshot (offline, e.g. `failopen snapshot` output or
// the scenario corpus) or collects from the cluster.
func loadSnapshot(ctx context.Context) (*collector.Snapshot, error) {
	if snapshotPath != "" {
		f, err := os.Open(snapshotPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return collector.ReadJSON(f)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c, err := collector.NewK8sCollector(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("init collector: %w", err)
	}
	snap, err := c.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("collect snapshot: %w", err)
	}
	return snap, nil
}

func init() {
	auditCmd.Flags().StringVar(&snapshotPath, "snapshot", "", "audit a saved snapshot (JSON from `failopen snapshot`) instead of the live cluster")
	rootCmd.AddCommand(auditCmd)
}
