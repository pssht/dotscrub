package reporter

import (
	"encoding/json"
	"io"

	"github.com/pssht/dotscrub/internal/scanner"
)

type SARIF struct{}

func NewSARIF() *SARIF {
	return &SARIF{}
}

type sarifReport struct {
	Version string      `json:"version"`
	Schema  string      `json:"$schema"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	DefaultLevel     string          `json:"defaultConfiguration"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func (s *SARIF) Report(w io.Writer, findings []scanner.Finding) error {
	rules := make(map[string]bool)
	var sarifRules []sarifRule
	
	for _, f := range findings {
		if !rules[f.RuleID] {
			rules[f.RuleID] = true
			sarifRules = append(sarifRules, sarifRule{
				ID: f.RuleID,
				ShortDescription: sarifMessage{
					Text: f.RuleDesc,
				},
				FullDescription: sarifMessage{
					Text: f.RuleDesc,
				},
				DefaultLevel: mapSeverity(f.Severity),
			})
		}
	}

	var results []sarifResult
	for _, f := range findings {
		result := sarifResult{
			RuleID: f.RuleID,
			Level:  mapSeverity(f.Severity),
			Message: sarifMessage{
				Text: f.RuleDesc + " detected",
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.File,
						},
						Region: sarifRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "dotscrub",
						InformationURI: "https://github.com/pssht/dotscrub",
						Version:        "0.1.0",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func mapSeverity(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}
