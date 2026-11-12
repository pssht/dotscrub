package cli

import (
	"fmt"
	"os"

	"github.com/pssht/dotscrub/internal/atlas"
	"github.com/pssht/dotscrub/internal/reporter"
	"github.com/pssht/dotscrub/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan paths for secrets in AI agent files",
	Long: `Scan specified paths for hardcoded secrets in AI agent configuration files.

If no paths are provided, scans the current directory.

Examples:
  dotscrub scan                    # Scan current directory
  dotscrub scan --home             # Scan common agent config locations
  dotscrub scan --staged           # Scan git staged files only
  dotscrub scan ~/.cursor          # Scan specific path
`,
	RunE: runScan,
}

var (
	scanHome    bool
	scanStaged  bool
	scanFormat  string
	scanOutput  string
	scanVerbose bool
)

func init() {
	scanCmd.Flags().BoolVar(&scanHome, "home", false, "Scan known agent config locations in home directory")
	scanCmd.Flags().BoolVar(&scanStaged, "staged", false, "Scan only git staged files")
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "text", "Output format: text, json, sarif")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Write output to file instead of stdout")
	scanCmd.Flags().BoolVarP(&scanVerbose, "verbose", "v", false, "Verbose output")
}

func runScan(cmd *cobra.Command, args []string) error {
	var paths []string

	if scanHome {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("getting home directory: %w", err)
		}
		
		atl := atlas.New()
		locations, err := atl.GetAgentLocations(homeDir)
		if err != nil {
			return fmt.Errorf("getting agent locations: %w", err)
		}
		
		for _, loc := range locations {
			if _, err := os.Stat(loc); err == nil {
				paths = append(paths, loc)
			}
		}
		
		if len(paths) == 0 {
			fmt.Fprintln(os.Stderr, "No agent config files found in home directory")
			return nil
		}
	} else if scanStaged {
		return fmt.Errorf("--staged mode not yet implemented (requires git integration)")
	} else if len(args) > 0 {
		paths = args
	} else {
		paths = []string{"."}
	}

	s := scanner.New()
	findings, err := s.ScanPaths(paths)
	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	var rep reporter.Reporter
	switch scanFormat {
	case "text":
		rep = reporter.NewText(scanVerbose)
	case "json":
		rep = reporter.NewJSON()
	case "sarif":
		rep = reporter.NewSARIF()
	default:
		return fmt.Errorf("unknown format: %s", scanFormat)
	}

	output := os.Stdout
	if scanOutput != "" {
		f, err := os.Create(scanOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	if err := rep.Report(output, findings); err != nil {
		return fmt.Errorf("reporting: %w", err)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}

	return nil
}
