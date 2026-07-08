# flagrix

Scan GitHub repositories and profiles for malware **before you clone** — from the
terminal, CI, or an AI agent. The same commit-pinned verdict as the
[Flagrix browser extension](https://flagrix.io), made callable.

```bash
npx flagrix scan https://github.com/some-org/coding-assignment
```

```
  some-org/coding-assignment @ 3f9c2a1
  HIGH RISK — Do not clone  security score 12/100
  3 files scanned · 10 dependencies · 2 issues

  CRITICAL Data exfiltration patterns detected: Keylogger Pattern
    assignment.js:14
      14  document.addEventListener("keydown", (e) => send(e.key))
```

Built after real fake-recruiter campaigns ("coding assignment" repos that steal
wallets, SSH keys, and browser sessions) started targeting developers.

## Commands

```bash
flagrix scan <url | owner/repo>   # scan a repository (--ref <branch|sha>)
flagrix scan-user <username>      # score a GitHub profile for scam signals
flagrix mcp                       # MCP server (stdio) for AI agents
```

## Exit codes

| code | meaning |
|---|---|
| 0 | low risk |
| 1 | scan failed |
| 2 | medium risk — review before proceeding |
| 3 | high risk — do not clone |

`--json` (automatic when stdout is piped) emits the full result. The verdict is
**pinned to the scanned commit** (`commitSha` in the JSON): every file is read at
that SHA, so a push mid-scan or after the verdict can't silently invalidate it.

## AI agents

```bash
claude mcp add flagrix -- npx -y flagrix mcp
```

Tools: `scan_github_repo`, `scan_github_user`. A Claude Code hook that gates every
`git clone` on a scan ships in [hooks/](hooks/) — see
[docs/agent-gating.md](docs/agent-gating.md).

## Tokens & rate limits

Unauthenticated scans use GitHub's 60 req/h budget (a scan issues one request per
scanned file, up to ~50). Set `GITHUB_TOKEN` (or `FLAGRIX_GITHUB_TOKEN`, or
`--token`) to raise it to 5,000/h and to scan private repositories.

## Privacy

Fully local. No telemetry, no accounts, no Flagrix backend — the only network
calls go to the GitHub/npm APIs and the public
[detection-rules](https://github.com/flagrix-io/flagrix-detection-rules)
repository (signature refresh, cached 6 h, with a bundled offline snapshot).

## How it works

Scanning logic lives in [@flagrix/scanner-core](https://github.com/flagrix-io/flagrix-scanner-core)
(MIT), signatures in [flagrix-detection-rules](https://github.com/flagrix-io/flagrix-detection-rules)
(MIT) — the same engine and rules the browser extension uses. Verdicts are risk
assessments, not definitive fraud determinations; always verify through official
channels.

## AI Disclosure

This project leverages Claude AI for boilerplate generation, test-suite expansion,
and optimization. All AI-generated code is strictly reviewed, refactored, and
verified by human maintainers before merging.

## License

MIT — see [LICENSE](LICENSE).
