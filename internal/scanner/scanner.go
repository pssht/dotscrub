package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type Finding struct {
	File        string
	Line        int
	Column      int
	KeyPath     string
	RuleID      string
	RuleDesc    string
	Severity    string
	SecretValue string
}

type Scanner struct {
	rules []Rule
}

type Rule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	Severity    string
}

func New() *Scanner {
	return &Scanner{
		rules: defaultRules(),
	}
}

func defaultRules() []Rule {
	return []Rule{
		{
			ID:          "generic-api-key",
			Description: "Generic API Key",
			Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?`),
			Severity:    "high",
		},
		{
			ID:          "bearer-token",
			Description: "Bearer Token",
			Pattern:     regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})`),
			Severity:    "high",
		},
		{
			ID:          "github-token",
			Description: "GitHub Token",
			Pattern:     regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}`),
			Severity:    "critical",
		},
		{
			ID:          "slack-token",
			Description: "Slack Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`),
			Severity:    "critical",
		},
		{
			ID:          "aws-access-key",
			Description: "AWS Access Key",
			Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Severity:    "critical",
		},
		{
			ID:          "private-key",
			Description: "Private Key",
			Pattern:     regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
			Severity:    "critical",
		},
		{
			ID:          "generic-secret",
			Description: "Generic Secret",
			Pattern:     regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})["']`),
			Severity:    "medium",
		},
	}
}

func (s *Scanner) ScanPaths(paths []string) ([]Finding, error) {
	var findings []Finding

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}

		if info.IsDir() {
			err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					name := d.Name()
					if name == ".git" || name == "node_modules" || name == "vendor" {
						return fs.SkipDir
					}
					return nil
				}

				if shouldScan(p) {
					f, err := s.scanFile(p)
					if err != nil {
						return fmt.Errorf("scanning %s: %w", p, err)
					}
					findings = append(findings, f...)
				}

				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			f, err := s.scanFile(path)
			if err != nil {
				return nil, err
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

func shouldScan(path string) bool {
	ext := filepath.Ext(path)

	agentFiles := []string{
		"mcp.json",
		"claude_desktop_config.json",
		".claude",
		"config.toml",
		".cursorrules",
		".aiderignore",
	}

	for _, af := range agentFiles {
		if strings.Contains(path, af) {
			return true
		}
	}

	agentExts := []string{".json", ".yaml", ".yml", ".toml", ".jsonl"}
	for _, ae := range agentExts {
		if ext == ae {
			return true
		}
	}

	return false
}

func (s *Scanner) scanFile(path string) ([]Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []Finding

	ext := filepath.Ext(path)
	switch ext {
	case ".json", ".jsonl":
		findings = append(findings, s.scanJSON(path, content)...)
	case ".yaml", ".yml":
		findings = append(findings, s.scanYAML(path, content)...)
	case ".toml":
		findings = append(findings, s.scanTOML(path, content)...)
	default:
		findings = append(findings, s.scanText(path, content)...)
	}

	return findings, nil
}

func (s *Scanner) scanJSON(path string, content []byte) []Finding {
	var findings []Finding
	
	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return s.scanText(path, content)
	}

	s.scanValue(path, "", data, &findings)
	return findings
}

func (s *Scanner) scanYAML(path string, content []byte) []Finding {
	var findings []Finding
	
	var data map[string]interface{}
	if err := yaml.Unmarshal(content, &data); err != nil {
		return s.scanText(path, content)
	}

	s.scanValue(path, "", data, &findings)
	return findings
}

func (s *Scanner) scanTOML(path string, content []byte) []Finding {
	var findings []Finding
	
	var data map[string]interface{}
	if err := toml.Unmarshal(content, &data); err != nil {
		return s.scanText(path, content)
	}

	s.scanValue(path, "", data, &findings)
	return findings
}

func (s *Scanner) scanValue(path, keyPath string, value interface{}, findings *[]Finding) {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, val := range v {
			newPath := k
			if keyPath != "" {
				newPath = keyPath + "." + k
			}
			s.scanValue(path, newPath, val, findings)
		}
	case []interface{}:
		for i, val := range v {
			newPath := fmt.Sprintf("%s[%d]", keyPath, i)
			s.scanValue(path, newPath, val, findings)
		}
	case string:
		for _, rule := range s.rules {
			if rule.Pattern.MatchString(v) {
				*findings = append(*findings, Finding{
					File:        path,
					KeyPath:     keyPath,
					RuleID:      rule.ID,
					RuleDesc:    rule.Description,
					Severity:    rule.Severity,
					SecretValue: maskSecret(v),
				})
			}
		}
	}
}

func (s *Scanner) scanText(path string, content []byte) []Finding {
	var findings []Finding
	
	lines := strings.Split(string(content), "\n")
	for lineNum, line := range lines {
		for _, rule := range s.rules {
			if rule.Pattern.MatchString(line) {
				matches := rule.Pattern.FindStringSubmatch(line)
				secret := line
				if len(matches) > 0 {
					secret = matches[0]
				}
				
				findings = append(findings, Finding{
					File:        path,
					Line:        lineNum + 1,
					RuleID:      rule.ID,
					RuleDesc:    rule.Description,
					Severity:    rule.Severity,
					SecretValue: maskSecret(secret),
				})
			}
		}
	}
	
	return findings
}

func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return "***"
	}
	
	visible := 4
	if len(secret) < 12 {
		visible = 2
	}
	
	maskLen := len(secret) - visible
	if maskLen > 20 {
		maskLen = 20
	}
	
	prefix := secret[:visible]
	return prefix + strings.Repeat("*", maskLen)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
