package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time: -ldflags "-X github.com/kkattl/failopen/internal/cli.version=..."
// (see Makefile); "dev" for plain `go build`.
var version = "dev"

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
