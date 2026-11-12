package reporter

import (
	"fmt"
	"io"

	"github.com/pssht/dotscrub/internal/scanner"
)

type Text struct {
	verbose bool
}

func NewText(verbose bool) *Text {
	return &Text{verbose: verbose}
}

func (t *Text) Report(w io.Writer, findings []scanner.Finding) error {
	if len(findings) == 0 {
		fmt.Fprintln(w, "✓ No secrets found")
		return nil
	}

	fmt.Fprintf(w, "Found %d potential secret(s):\n\n", len(findings))

	for _, f := range findings {
		fmt.Fprintf(w, "  [%s] %s\n", severityColor(f.Severity), f.RuleDesc)
		fmt.Fprintf(w, "    File: %s\n", f.File)
		
		if f.KeyPath != "" {
			fmt.Fprintf(w, "    Path: %s\n", f.KeyPath)
		}
		if f.Line > 0 {
			fmt.Fprintf(w, "    Line: %d\n", f.Line)
		}
		
		if t.verbose {
			fmt.Fprintf(w, "    Rule: %s\n", f.RuleID)
			fmt.Fprintf(w, "    Value: %s\n", f.SecretValue)
		}
		
		fmt.Fprintln(w)
	}

	return nil
}

func severityColor(severity string) string {
	switch severity {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return severity
	}
}
