package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "0.1.0-dev"
var Commit = "unknown"
var Date = "unknown"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "◈ Print Plexar version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("◈ plexar %s (commit: %s, built: %s)\n", Version, Commit, Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
