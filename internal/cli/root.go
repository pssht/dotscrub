package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version string
	commit  string
	date    string
)

func SetVersion(v, c, d string) {
	version = v
	commit = c
	date = d
}

var rootCmd = &cobra.Command{
	Use:   "dotscrub",
	Short: "Local secret scanner for AI agent files",
	Long: `dotscrub is a 100% local secret scanner for AI-agent configuration files.

It scans MCP configs, agent rules, memory files, and JSONL transcripts
for hardcoded secrets and credentials, helping you keep your AI agent
setup secure.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(installHookCmd)
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("dotscrub %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
	},
}
