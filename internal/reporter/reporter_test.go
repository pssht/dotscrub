package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/pssht/dotscrub/internal/scanner"
)

func TestText_Report(t *testing.T) {
	finding := scanner.Finding{
		File:       "/test/file.json",
		Line:       10,
		KeyPath:    "api.token",
		RuleID:     "github-token",
		RuleDesc:   "GitHub Token",
		Severity:   "critical",
		SecretHash: "abc123def456",
	}
	findings := []scanner.Finding{finding}

	t.Run("normal output", func(t *testing.T) {
		var buf bytes.Buffer
		r := NewText(false)
		
		err := r.Report(&buf, findings)
		if err != nil {
			t.Fatalf("Report() error = %v", err)
		}

		output := buf.String()
		if output == "" {
			t.Error("expected output, got empty string")
		}
		
		t.Logf("Output:\n%s", output)
	})

	t.Run("verbose output", func(t *testing.T) {
		var buf bytes.Buffer
		r := NewText(true)
		
		err := r.Report(&buf, findings)
		if err != nil {
			t.Fatalf("Report() error = %v", err)
		}

		output := buf.String()
		if output == "" {
			t.Error("expected output, got empty string")
		}
	})

	t.Run("no findings", func(t *testing.T) {
		var buf bytes.Buffer
		r := NewText(false)
		
		err := r.Report(&buf, []scanner.Finding{})
		if err != nil {
			t.Fatalf("Report() error = %v", err)
		}

		output := buf.String()
		if output == "" {
			t.Error("expected output for no findings, got empty string")
		}
	})
}

func TestJSON_Report(t *testing.T) {
	finding := scanner.Finding{
		File:       "/test/file.json",
		KeyPath:    "api.token",
		RuleID:     "github-token",
		RuleDesc:   "GitHub Token",
		Severity:   "critical",
		SecretHash: "abc123def456",
	}
	findings := []scanner.Finding{finding}

	var buf bytes.Buffer
	r := NewJSON()
	
	err := r.Report(&buf, findings)
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if output["count"] != float64(1) {
		t.Errorf("expected count=1, got %v", output["count"])
	}
}

func TestSARIF_Report(t *testing.T) {
	finding := scanner.Finding{
		File:       "/test/file.json",
		Line:       10,
		RuleID:     "github-token",
		RuleDesc:   "GitHub Token",
		Severity:   "critical",
		SecretHash: "abc123def456",
	}
	findings := []scanner.Finding{finding}

	var buf bytes.Buffer
	r := NewSARIF()
	
	err := r.Report(&buf, findings)
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("failed to parse SARIF output: %v", err)
	}

	if output["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", output["version"])
	}

	runs, ok := output["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("expected runs array in SARIF output")
	}
}
