package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var fixCmd = &cobra.Command{
	Use:   "fix [paths...]",
	Short: "Automatically fix secrets by moving them to environment variables",
	Long: `Fix hardcoded secrets by replacing them with environment variable references.

This command will:
  1. Detect hardcoded secrets in MCP configs and other agent files
  2. Generate unique environment variable names (e.g., MCP_GITHUB_TOKEN)
  3. Update the config files to reference ${VAR} instead
  4. Print instructions for setting the environment variables

This is a planned feature and not yet implemented.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("fix command not yet implemented")
	},
}
