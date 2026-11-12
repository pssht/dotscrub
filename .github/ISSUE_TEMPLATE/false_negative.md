---
name: False Negative (Secret Not Detected)
about: Report a secret pattern that dotscrub should detect but doesn't
title: '[FALSE NEGATIVE] '
labels: security, enhancement
assignees: ''
---

## Secret Type

What type of secret is not being detected?
- [ ] API Key
- [ ] Token
- [ ] Password
- [ ] Private Key
- [ ] Other: ___________

## Service/Platform

Which service is this secret for? (e.g., GitHub, AWS, OpenAI, Slack)

## Pattern Example

Provide a **fake/example** pattern that should be detected:

```
# DO NOT include real secrets!
Example: sk-proj-abc123...
```

## Why It's Important

Why should dotscrub detect this pattern? Is it commonly found in AI agent configs?

## Suggested Detection Rule

If you know the pattern/regex that would catch this, share it:

```regex
your-pattern-here
```

## Additional Context

- How common is this secret type in AI agent configurations?
- Are there any false positive risks?
- Links to documentation about the secret format
