package cli

import (
	"github.com/spf13/cobra"
)

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
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "",
		"path to kubeconfig (defaults to $KUBECONFIG, then ~/.kube/config)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "terminal",
		"output format: terminal|json (json comes in M2)")
}

// Execute runs the root command. Called from main.
func Execute() error {
	return rootCmd.Execute()
}
