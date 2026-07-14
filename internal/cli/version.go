package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is the binary version string. It is overridable at build time via:
//
//	go build -ldflags "-X github.com/Ubermm/cryptoscan/internal/cli.version=v1.2.3"
var version = "v0.1.0-dev"

// newVersionCmd prints the cryptoscan version and exits.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the cryptoscan version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "cryptoscan %s\n", version)
			return nil
		},
	}
}
