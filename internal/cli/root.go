package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// ErrCriticalFindings is returned by audit when it completed successfully
// but found critical issues. main maps it to exit code 1, distinct from
// runtime errors (exit code 2), so CI can tell "holes found" from "broken run".
var ErrCriticalFindings = errors.New("critical findings")

// Global flags shared across subcommands.
var (
	kubeconfigPath string
	outputFormat   string
)

// rootCmd is the base command; subcommands attach to it in init().
var rootCmd = &cobra.Command{
	Use:   "failopen",
	Short: "failopen reveals the gap between declared and effective network segmentation",
	Long: `failopen inspects a Kubernetes cluster and reveals where NetworkPolicy
(what is declared) diverges from what the underlying network actually allows
(what is effective): hostNetwork pods, NodePort, CNIs that don't enforce policy.`,
	// main owns error printing and exit codes; don't dump usage on runtime errors.
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return validateOutputFormat(outputFormat)
	},
}

func validateOutputFormat(f string) error {
	switch f {
	case "terminal":
		return nil
	case "json":
		return errors.New("--output json is not implemented yet (planned for M2)")
	default:
		return fmt.Errorf("unknown --output %q (supported: terminal)", f)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "",
		"path to kubeconfig (defaults to $KUBECONFIG, then ~/.kube/config)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "terminal",
		"output format: terminal (json comes in M2)")
}

// Execute runs the root command. Called from main.
func Execute() error {
	return rootCmd.Execute()
}
