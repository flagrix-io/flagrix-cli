# Security Policy

## Supported versions

Only the latest published version of Flagrix CLI and MCP server is actively supported with security updates.

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Use GitHub's private vulnerability reporting form:

https://github.com/flagrix-io/flagrix-cli/security/advisories/new

If GitHub reporting is unavailable, email [security@flagrix.io](mailto:security@flagrix.io).

Please include, where possible:

- The affected package, component, and version
- A clear description of the vulnerability and its security impact
- Reproduction steps or a minimal proof of concept
- Any relevant logs, screenshots, or suggested remediation

Do not include secrets, personal data, or malicious payloads that are not required to reproduce the issue.

We aim to acknowledge reports within 3 business days and provide an initial assessment within 7 business days. Please allow reasonable time for investigation and remediation before public disclosure. We will coordinate disclosure and credit with the reporter when appropriate.

## Security scope

Examples of security issues include:

- Scanner bypasses that can produce an unsafe low-risk verdict for malicious code
- Token, private-repository, or scanned-content exposure
- Command injection, arbitrary code execution, or unsafe file handling
- Compromise of published packages, releases, or detection-rule distribution
- Vulnerabilities in the CLI, MCP server, scanner engine, or rule update path

False positives, missed detections without a security exploit, documentation problems, and ordinary rule improvements can be reported through public GitHub issues.

## Bug bounties

Flagrix does not currently operate a paid bug-bounty program.
