# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in dotscrub, please report it privately to:

📧 **security@pssht.dev** (when available) or via GitHub's private vulnerability reporting feature.

### What to Include

Please provide:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We will acknowledge your report within 48 hours and provide a detailed response within 7 days.

## Security Considerations

### Local-First Design

dotscrub is designed to run **100% locally**:

- No data is sent to remote servers
- All scanning happens on your machine
- No telemetry or usage tracking

### Test Fixtures

Our test fixtures use **obviously fake secrets** to avoid triggering secret scanners:

```json
{
  "token": "ghp_FAKE1234567890fakefaketoken1234567"
}
```

This is intentional and safe.

### False Positives

dotscrub may flag:
- Test credentials
- Example configurations
- Already-revoked tokens

Review findings carefully. When scanning for CI/CD, consider:
- Using `--format sarif` for integration with security platforms
- Excluding test directories if needed
- Documenting known false positives

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x: (pre-release)  |

## Security Best Practices

When using dotscrub:

1. **Run regularly**: Integrate into CI/CD and pre-commit hooks
2. **Scan before commit**: Use `dotscrub scan --staged`
3. **Review findings**: Not all detections are real secrets
4. **Use environment variables**: Store secrets in environment, not config files
5. **Rotate exposed secrets**: If a secret is committed, rotate it immediately

## Scope

### In Scope

- Vulnerabilities in dotscrub itself
- False negatives (secrets not detected)
- Security improvements to detection rules

### Out of Scope

- Reports of secrets in **your** repositories (rotate them yourself)
- Feature requests (use GitHub Discussions)
- Support questions (use GitHub Issues)

## Disclosure Policy

- We follow **coordinated disclosure**
- We will work with you to understand and address the issue
- We will credit reporters (unless you prefer anonymity)
- We aim to release fixes within 30 days

## Security Updates

Security updates will be:
- Released as soon as practical
- Announced via GitHub Security Advisories
- Documented in release notes

## Questions?

For security-related questions that are not vulnerabilities, please:
- Open a [Discussion](https://github.com/pssht/dotscrub/discussions)
- Tag with `security` label

Thank you for helping keep dotscrub and its users secure! 🛡️
