package reporter

import (
	"encoding/json"
	"io"

	"github.com/pssht/dotscrub/internal/scanner"
)

type JSON struct{}

func NewJSON() *JSON {
	return &JSON{}
}

type jsonOutput struct {
	Findings []scanner.Finding `json:"findings"`
	Count    int               `json:"count"`
}

func (j *JSON) Report(w io.Writer, findings []scanner.Finding) error {
	output := jsonOutput{
		Findings: findings,
		Count:    len(findings),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
