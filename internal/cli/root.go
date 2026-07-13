// Package cli wires up the cobra command tree for the cryptoscan binary.
//
// Commands are built by constructor functions (newRootCmd, newVersionCmd, ...)
// rather than package-level init() side effects, so the tree is explicit and
// testable.
package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// errNotImplemented is returned by phase-stub subcommands. It is used to
// signal an exit code of 2 without printing a Go stack or usage text.
var errNotImplemented = errors.New("not implemented yet")

// newRootCmd constructs the top-level cryptoscan command with all subcommands
// registered.
func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cryptoscan",
		Short: "Open source cryptographic estate scanner",
		Long: "cryptoscan discovers cryptographic assets (certificates, TLS " +
			"configurations, keys, crypto API usage) and produces a " +
			"Cryptographic Bill of Materials (CBOM) plus a PQC-readiness report.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// Root with no subcommand prints help rather than erroring.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		newVersionCmd(),
		newFsCmd(),
		newProbeCmd(),
		newGraphCmd(),
	)

	return cmd
}

// Execute builds the root command, runs it, and returns a process exit code.
//
//	0 = success
//	1 = generic error
//	2 = subcommand not implemented (phase stub)
func Execute() int {
	root := newRootCmd()
	err := root.Execute()
	if err == nil {
		return 0
	}
	if errors.Is(err, errNotImplemented) {
		fmt.Fprintln(root.ErrOrStderr(), err)
		return 2
	}
	fmt.Fprintln(root.ErrOrStderr(), "cryptoscan:", err)
	return 1
}
