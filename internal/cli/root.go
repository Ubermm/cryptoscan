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

// errThresholdBreached is the sentinel returned by a scan command when its
// `--fail-on` policy gate trips. The command has ALREADY written the breach
// summary to stderr by the time it returns this, so Execute maps it straight to
// the dedicated exit code 4 WITHOUT printing the generic "cryptoscan: ..."
// prefix (which would double-report the failure).
var errThresholdBreached = errors.New("policy threshold breached")

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
//	1 = generic / operational / usage error
//	2 = subcommand not implemented (phase stub)
//	4 = a `--fail-on` policy threshold was breached (fs/probe)
func Execute() int {
	root := newRootCmd()
	err := root.Execute()
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errThresholdBreached):
		// The command already wrote the breach summary to stderr; emit nothing
		// more, just the dedicated exit code.
		return 4
	case errors.Is(err, errNotImplemented):
		fmt.Fprintln(root.ErrOrStderr(), err)
		return 2
	default:
		fmt.Fprintln(root.ErrOrStderr(), "cryptoscan:", err)
		return 1
	}
}
