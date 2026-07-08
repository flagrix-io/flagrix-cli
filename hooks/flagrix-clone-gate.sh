#!/usr/bin/env bash
# Flagrix clone gate — Claude Code PreToolUse hook for the Bash tool.
#
# Scans any GitHub repo about to be cloned; blocks the clone (hook exit 2)
# when Flagrix rates it MEDIUM or HIGH risk. See docs/agent-gating.md for the
# settings.json wiring.
set -euo pipefail

payload="$(cat)"

# Extract a github.com repo URL from a `git clone`/`gh repo clone` command.
url="$(node -e '
  let input = ""
  process.stdin.on("data", (d) => (input += d))
  process.stdin.on("end", () => {
    try {
      const cmd = JSON.parse(input)?.tool_input?.command ?? ""
      if (!/\b(git\s+clone|gh\s+repo\s+clone)\b/.test(cmd)) return
      const m =
        cmd.match(/https?:\/\/github\.com\/[\w.-]+\/[\w.-]+/) ||
        cmd.match(/git@github\.com:[\w.-]+\/[\w.-]+/) ||
        cmd.match(/\bclone\s+([\w.-]+\/[\w.-]+)(?:\s|$)/)?.slice(1)
      if (m) process.stdout.write(String(Array.isArray(m) ? m[0] : m))
    } catch {}
  })
' <<< "$payload")"

# Not a GitHub clone — allow.
[ -z "$url" ] && exit 0

if npx -y flagrix scan "$url" --json > /dev/null 2>&1; then
  exit 0 # low risk
else
  code=$?
  case "$code" in
    2) echo "Flagrix: MEDIUM risk — review https://github.com/flagrix-io/flagrix-cli#exit-codes before cloning $url" >&2 ;;
    3) echo "Flagrix: HIGH risk — do NOT clone $url (malicious patterns detected). Run: npx flagrix scan $url" >&2 ;;
    *) echo "Flagrix: scan of $url failed (exit $code) — blocking out of caution. Run: npx flagrix scan $url" >&2 ;;
  esac
  exit 2 # exit 2 = block the tool call in Claude Code
fi
