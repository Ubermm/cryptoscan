package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newPhaseStub builds a subcommand that reports it is not implemented and
// causes the process to exit 2 (via errNotImplemented). It exists so the CLI
// surface is visible from Phase 0 while scanners land in later phases.
func newPhaseStub(use, short string, phase int) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("%s: %w (phase %d)", use, errNotImplemented, phase)
		},
	}
}

// newGraphCmd emits the cryptographic asset graph / CBOM (Phase 3).
func newGraphCmd() *cobra.Command {
	return newPhaseStub("graph", "Emit the cryptographic asset graph and CBOM", 3)
}
