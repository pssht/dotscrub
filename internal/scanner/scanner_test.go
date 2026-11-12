package scanner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScanner_ScanPaths(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantMinimum  int
	}{
		{
			name:        "mcp.json with secrets",
			path:        "../../testdata/.cursor/mcp.json",
			wantMinimum: 1,
		},
		{
			name:        "settings.yaml with secrets",
			path:        "../../testdata/settings.yaml",
			wantMinimum: 1,
		},
		{
			name:        "clean.json no secrets",
			path:        "../../testdata/clean.json",
			wantMinimum: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			
			absPath, err := filepath.Abs(tt.path)
			if err != nil {
				t.Fatalf("failed to get absolute path: %v", err)
			}

			findings, err := s.ScanPaths([]string{absPath})
			if err != nil {
				t.Fatalf("ScanPaths() error = %v", err)
			}

			if tt.wantMinimum == 0 {
				if len(findings) != 0 {
					t.Errorf("got %d findings in clean file, want 0", len(findings))
				}
			} else {
				if len(findings) < tt.wantMinimum {
					t.Errorf("got %d findings, want at least %d", len(findings), tt.wantMinimum)
				}
			}
			
			for i, f := range findings {
				t.Logf("  finding %d: %s (%s) at %s", i, f.RuleID, f.RuleDesc, f.KeyPath)
			}
		})
	}
}

func TestScanner_ScanDirectory(t *testing.T) {
	s := New()
	
	testdataPath, err := filepath.Abs("../../testdata")
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	findings, err := s.ScanPaths([]string{testdataPath})
	if err != nil {
		t.Fatalf("ScanPaths() error = %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected to find secrets in testdata directory, but found none")
	}

	t.Logf("Found %d total secrets across all test files", len(findings))
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{
			name:   "short secret",
			secret: "abc123",
		},
		{
			name:   "long secret",
			secret: "ghp_1234567890123456789012345678901234",
		},
		{
			name:   "medium secret",
			secret: "sk-test-123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{secretValue: tt.secret}
			got := f.MaskedSecret()
			if len(got) < 3 {
				t.Errorf("MaskedSecret() = %v, too short", got)
			}
			if !strings.Contains(got, "*") {
				t.Errorf("MaskedSecret() = %v, should contain asterisks", got)
			}
			t.Logf("MaskedSecret(%q) = %q", tt.secret, got)
		})
	}
}

func TestHashSecret(t *testing.T) {
	secret := "ghp_1234567890123456789012345678901234"
	hash1 := hashSecret(secret)
	hash2 := hashSecret(secret)
	
	if hash1 != hash2 {
		t.Errorf("hashSecret should be deterministic: %s != %s", hash1, hash2)
	}
	
	if len(hash1) != 16 {
		t.Errorf("hash should be 16 chars, got %d", len(hash1))
	}
	
	differentSecret := "ghp_9876543210987654321098765432109876"
	hash3 := hashSecret(differentSecret)
	if hash1 == hash3 {
		t.Errorf("different secrets should have different hashes")
	}
}
