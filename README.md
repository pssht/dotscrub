# dotscrub

[![CI](https://github.com/pssht/dotscrub/workflows/CI/badge.svg)](https://github.com/pssht/dotscrub/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Status: Pre-Alpha** - This project is under active development. APIs and features may change.

**dotscrub** is a 100% local secret scanner for AI agent configuration files. Part of the [Pssht](https://github.com/pssht) family of open-source security tools for local AI agents.

## What is dotscrub?

dotscrub scans your AI agent configuration files for hardcoded secrets and credentials:

- **MCP configs**: `.cursor/mcp.json`, `claude_desktop_config.json`, `.claude/settings.json`
- **Agent rules and memory files**: `.cursorrules`, agent memory stores
- **Codex configs**: `config.toml` and similar
- **Transcript files**: JSONL conversation logs

It runs entirely locally—no data leaves your machine.

## Installation

### Using go install

```bash
go install github.com/pssht/dotscrub/cmd/dotscrub@latest
```

### From source

```bash
git clone https://github.com/pssht/dotscrub.git
cd dotscrub
go build -o dotscrub ./cmd/dotscrub
```

## Usage

### Basic scanning

```bash
# Scan current directory
dotscrub scan

# Scan specific paths
dotscrub scan ~/.cursor ~/.config/Claude

# Scan known agent config locations in home directory
dotscrub scan --home

# Output formats
dotscrub scan --format json
dotscrub scan --format sarif -o results.sarif
```

### Pre-commit hook (planned)

```bash
dotscrub install-hook
```

### Fix mode (planned)

```bash
dotscrub fix ~/.cursor/mcp.json
```

This will move secrets to environment variables and update configs to use `${VAR}` references.

## GitHub Action

Use dotscrub in your CI/CD pipeline:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan-secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pssht/dotscrub@main
        with:
          paths: '.cursor .config'
          format: 'sarif'
          upload-sarif: true
```

## Output Formats

### Text (default)

```
Found 2 potential secret(s):

  [CRITICAL] GitHub Token
    File: .cursor/mcp.json
    Path: mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN
```

### JSON

```json
{
  "findings": [
    {
      "File": ".cursor/mcp.json",
      "KeyPath": "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN",
      "RuleID": "github-token",
      "RuleDesc": "GitHub Token",
      "Severity": "critical"
    }
  ],
  "count": 1
}
```

### SARIF 2.1.0

Compatible with GitHub Advanced Security and other security platforms.

## Roadmap

- [x] Core scanning engine with common patterns
- [x] JSON/YAML/TOML parsing with key path tracking
- [x] Multiple output formats (text, JSON, SARIF)
- [x] GitHub Action
- [ ] Fix mode: move secrets to environment variables
- [ ] Git pre-commit hook integration
- [ ] Scan only staged files (`--staged`)
- [ ] Custom rule definitions
- [ ] Integration with gitleaks rules
- [ ] Always-masked secret output
- [ ] Configuration file support

## Development

```bash
# Run tests
go test ./...

# Build
go build ./cmd/dotscrub

# Run linter
golangci-lint run

# Run on test fixtures
go run ./cmd/dotscrub scan testdata/
```

## Project Structure

```
dotscrub/
├── cmd/dotscrub/          # CLI entrypoint
├── internal/
│   ├── atlas/             # Agent file location atlas
│   ├── cli/               # Command implementations
│   ├── scanner/           # Core scanning logic
│   └── reporter/          # Output formatters
├── atlas/                 # Agent location definitions
│   └── agents.yaml
├── testdata/              # Test fixtures (fake secrets only!)
└── .github/
    └── workflows/         # CI/CD
```

## Security

See [SECURITY.md](SECURITY.md) for security policy and reporting vulnerabilities.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important**: Agent-authored PRs are welcome but must be clearly disclosed in the PR description and reviewed by a human maintainer.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## About Pssht

dotscrub is part of the **Pssht** project—a family of open-source security tools designed for local AI agents. All Pssht tools run locally and prioritize privacy.

## Acknowledgments

Inspired by tools like [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), and the security practices of the AI agent community.
