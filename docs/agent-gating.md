# Gating agents with Flagrix

Two ways to put Flagrix between an AI agent and untrusted code: the **MCP server**
(the agent decides to scan, or is instructed to) and the **Claude Code hook**
(every `git clone` is gated, no cooperation needed).

## Exit codes (the contract)

| code | meaning |
|---|---|
| 0 | low risk |
| 1 | scan failed (network, auth, bad target) |
| 2 | medium risk — review before proceeding |
| 3 | high risk — do not clone |

`--json` (or any piped stdout) emits the full scan result, including `commitSha` —
the verdict applies to that commit, not to whatever the branch points at later.

## MCP server

```bash
claude mcp add flagrix -- npx -y flagrix mcp
```

Tools exposed: `scan_github_repo {target, ref?}` and `scan_github_user {username}`.
Set `GITHUB_TOKEN` in the environment to raise rate limits / scan private repos.

Suggested agent instruction (CLAUDE.md or system prompt):

> Before cloning or installing any repository you did not author, call the
> `scan_github_repo` tool and follow its guidance. Do not proceed on MEDIUM or
> HIGH verdicts without explicit human approval.

## Claude Code clone gate (hook)

Copies of the hook script ship inside the npm package (`hooks/flagrix-clone-gate.sh`).

`~/.claude/settings.json` (or a project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$(npm root -g)/flagrix/hooks/flagrix-clone-gate.sh\""
          }
        ]
      }
    ]
  }
}
```

Install the package globally first (`npm i -g flagrix`), or vendor the script into
your repo and point the hook at it. The hook only reacts to `git clone` /
`gh repo clone` commands targeting github.com; everything else passes through.

## CI

```yaml
- name: Gate on Flagrix scan
  run: npx -y flagrix scan ${{ github.event.pull_request.head.repo.html_url }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

A non-zero exit fails the job (2/3 = risk verdicts, 1 = scan error).
