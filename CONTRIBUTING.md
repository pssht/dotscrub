# Contributing to dotscrub

Thank you for your interest in contributing to dotscrub! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
- Check the [existing issues](https://github.com/pssht/dotscrub/issues) to avoid duplicates
- Ensure you're using the latest version

When filing a bug report, include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Go version)
- Relevant logs or error messages

### Suggesting Features

Feature requests are welcome! Please:
- Check existing issues first
- Explain the use case clearly
- Describe the expected behavior
- Consider implementation approaches

### Pull Requests

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Write code** following our standards:
   - Clear, readable code with meaningful names
   - Comments for non-obvious logic (not obvious code)
   - Tests for new functionality
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   go test ./...
   go vet ./...
   golangci-lint run
   ```

4. **Commit with clear messages**:
   ```
   Add support for custom rule definitions
   
   - Implement YAML-based rule configuration
   - Add validation for rule patterns
   - Include tests for rule loading
   ```

5. **Push and create PR**:
   - Reference related issues
   - Describe what changed and why
   - Include before/after examples if relevant

## Automated Tool Contributions

Contributions generated with the assistance of automated tools are welcome, provided they meet the same quality standards as any other contribution and are reviewed by a human maintainer before merge.

## Development Setup

### Prerequisites

- Go 1.22 or later
- golangci-lint (for linting)
- git

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/dotscrub.git
cd dotscrub

# Install dependencies
go mod download

# Build
go build ./cmd/dotscrub

# Run tests
go test ./...

# Run the tool
./dotscrub scan testdata/
```

### Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Specific package
go test ./internal/scanner -v

# Race detector
go test -race ./...
```

### Code Style

We follow standard Go conventions:
- Use `gofmt` for formatting
- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use `golangci-lint` for static analysis
- Prefer readability over cleverness

### Test Fixtures

**CRITICAL**: Never commit real secrets!

All test fixtures must use **obviously fake credentials**:

```json
{
  "token": "ghp_FAKE1234567890fakefaketoken1234567"
}
```

This avoids triggering GitHub's secret scanning on push.

## Project Structure

- `cmd/dotscrub/` - CLI entrypoint
- `internal/cli/` - Command implementations
- `internal/scanner/` - Core scanning logic
- `internal/atlas/` - Agent config location database
- `internal/reporter/` - Output formatters (text, JSON, SARIF)
- `atlas/` - YAML definitions of agent config paths
- `testdata/` - Test fixtures (fake secrets only!)

## Adding New Features

### Adding a New Detection Rule

1. Add pattern to `internal/scanner/scanner.go`:
   ```go
   {
       ID:          "my-new-secret",
       Description: "My Service Token",
       Pattern:     regexp.MustCompile(`pattern-here`),
       Severity:    "high",
   }
   ```

2. Add test fixture to `testdata/`
3. Add test case in `internal/scanner/scanner_test.go`

### Adding a New Output Format

1. Implement `Reporter` interface in `internal/reporter/`
2. Register in `internal/cli/scan.go`
3. Add tests in `internal/reporter/reporter_test.go`
4. Update documentation

## Release Process

(For maintainers)

1. Update version and changelog
2. Tag release: `git tag -a v0.1.0 -m "Release v0.1.0"`
3. Push tag: `git push origin v0.1.0`
4. GitHub Actions builds and creates release via goreleaser

## Questions?

- Open a [discussion](https://github.com/pssht/dotscrub/discussions)
- File an [issue](https://github.com/pssht/dotscrub/issues)

Thank you for contributing to making AI agent security better!
