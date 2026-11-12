package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"gopkg.in/yaml.v3"
)

type Finding struct {
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	KeyPath     string `json:"key_path,omitempty"`
	RuleID      string `json:"rule_id"`
	RuleDesc    string `json:"rule_desc"`
	Severity    string `json:"severity"`
	SecretHash  string `json:"secret_hash"`
	secretValue string
}

type Scanner struct {
	detector     *detect.Detector
	agentRules   []AgentRule
	alwaysMasked bool
}

type AgentRule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	Severity    string
	KeyHints    []string
}

func New() *Scanner {
	var cfg config.Config
	var vip config.ViperConfig
	
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(config.DefaultConfig)); err == nil {
		if err := v.Unmarshal(&vip); err == nil {
			cfg, _ = vip.Translate()
		}
	}

	detector := detect.NewDetector(cfg)

	return &Scanner{
		detector:     detector,
		agentRules:   getAgentSpecificRules(),
		alwaysMasked: true,
	}
}

func getAgentSpecificRules() []AgentRule {
	return []AgentRule{
		{
			ID:          "mcp-env-literal",
			Description: "MCP environment variable with literal secret value",
			Pattern:     regexp.MustCompile(`(?i)["']([a-zA-Z0-9_\-\.]{20,})["']`),
			Severity:    "high",
			KeyHints:    []string{"env", "environment", "GITHUB_TOKEN", "SLACK_TOKEN", "API_KEY"},
		},
		{
			ID:          "authorization-header-token",
			Description: "Authorization or Bearer header with token",
			Pattern:     regexp.MustCompile(`(?i)(bearer|token)\s+([a-zA-Z0-9_\-\.]{20,})`),
			Severity:    "critical",
			KeyHints:    []string{"authorization", "bearer", "auth", "token"},
		},
		{
			ID:          "credentials-in-url",
			Description: "Credentials embedded in URL",
			Pattern:     regexp.MustCompile(`(?i)(https?|postgresql|mysql|mongodb)://[^:@\s]+:[^@\s]+@[^\s]+`),
			Severity:    "critical",
			KeyHints:    []string{"url", "connection", "database", "endpoint"},
		},
		{
			ID:          "saved-permission-token",
			Description: "Saved permission entry containing token",
			Pattern:     regexp.MustCompile(`(?i)(access_token|refresh_token|session_token)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{20,})`),
			Severity:    "high",
			KeyHints:    []string{"permissions", "access", "refresh", "session"},
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
		findings = append(findings, s.scanStructured(path, content, "json")...)
	case ".yaml", ".yml":
		findings = append(findings, s.scanStructured(path, content, "yaml")...)
	case ".toml":
		findings = append(findings, s.scanStructured(path, content, "toml")...)
	default:
		findings = append(findings, s.scanText(path, content)...)
	}

	findings = append(findings, s.scanWithGitleaks(path, content)...)

	return deduplicateFindings(findings), nil
}

func (s *Scanner) scanStructured(path string, content []byte, format string) []Finding {
	var findings []Finding
	var data map[string]interface{}

	switch format {
	case "json":
		if err := json.Unmarshal(content, &data); err != nil {
			return s.scanText(path, content)
		}
	case "yaml":
		if err := yaml.Unmarshal(content, &data); err != nil {
			return s.scanText(path, content)
		}
	case "toml":
		if err := toml.Unmarshal(content, &data); err != nil {
			return s.scanText(path, content)
		}
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
		if len(v) < 8 {
			return
		}

		for _, rule := range s.agentRules {
			if !s.shouldApplyRule(rule, keyPath, v) {
				continue
			}

			if rule.Pattern.MatchString(v) {
				*findings = append(*findings, Finding{
					File:        path,
					KeyPath:     keyPath,
					RuleID:      rule.ID,
					RuleDesc:    rule.Description,
					Severity:    rule.Severity,
					SecretHash:  hashSecret(v),
					secretValue: v,
				})
			}
		}
	}
}

func (s *Scanner) shouldApplyRule(rule AgentRule, keyPath, value string) bool {
	if len(rule.KeyHints) == 0 {
		return true
	}

	lowerKeyPath := strings.ToLower(keyPath)
	lowerValue := strings.ToLower(value)

	for _, hint := range rule.KeyHints {
		lowerHint := strings.ToLower(hint)
		if strings.Contains(lowerKeyPath, lowerHint) {
			return true
		}
		if strings.Contains(lowerValue, lowerHint) {
			return true
		}
	}

	return false
}

func (s *Scanner) scanText(path string, content []byte) []Finding {
	var findings []Finding

	lines := strings.Split(string(content), "\n")
	for lineNum, line := range lines {
		for _, rule := range s.agentRules {
			if rule.Pattern.MatchString(line) {
				matches := rule.Pattern.FindStringSubmatch(line)
				secret := line
				if len(matches) > 0 {
					secret = matches[0]
					if len(matches) > 1 {
						for i := len(matches) - 1; i >= 1; i-- {
							if len(matches[i]) >= 20 {
								secret = matches[i]
								break
							}
						}
					}
				}

				findings = append(findings, Finding{
					File:        path,
					Line:        lineNum + 1,
					RuleID:      rule.ID,
					RuleDesc:    rule.Description,
					Severity:    rule.Severity,
					SecretHash:  hashSecret(secret),
					secretValue: secret,
				})
			}
		}
	}

	return findings
}

func (s *Scanner) scanWithGitleaks(path string, content []byte) []Finding {
	fragment := detect.Fragment{
		Raw:      string(content),
		FilePath: path,
	}

	gitleaksFindings := s.detector.Detect(fragment)
	
	var findings []Finding
	for _, gf := range gitleaksFindings {
		findings = append(findings, Finding{
			File:        path,
			Line:        gf.StartLine,
			Column:      gf.StartColumn,
			RuleID:      gf.RuleID,
			RuleDesc:    gf.Description,
			Severity:    mapGitleaksSeverity(gf),
			SecretHash:  hashSecret(gf.Secret),
			secretValue: gf.Secret,
		})
	}

	return findings
}

func mapGitleaksSeverity(finding report.Finding) string {
	switch finding.RuleID {
	case "github-pat", "github-oauth", "github-app-token", "github-fine-grained-pat":
		return "critical"
	case "slack-access-token", "slack-webhook-url":
		return "critical"
	case "aws-access-token":
		return "critical"
	case "private-key":
		return "critical"
	default:
		return "high"
	}
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])[:16]
}

func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding

	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%s", f.File, f.KeyPath, f.SecretHash)
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}

func (f *Finding) MaskedSecret() string {
	if f.secretValue == "" {
		return "***"
	}

	secret := f.secretValue
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
