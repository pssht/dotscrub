package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install git pre-commit hook",
	Long: `Install a git pre-commit hook that runs dotscrub on staged files.

This prevents accidentally committing secrets to version control.

This is a planned feature and not yet implemented.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("install-hook command not yet implemented")
	},
}
