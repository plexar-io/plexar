package main

import (
	"os"

	"github.com/plexar-io/plexar/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
