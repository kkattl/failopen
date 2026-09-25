package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags in M3; hardcoded for now.
var version = "v0.0.1-dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the failopen version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
