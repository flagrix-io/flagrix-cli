#!/usr/bin/env bash
# Flagrix clone gate — Claude Code PreToolUse hook for the Bash tool.
#
# Scans any GitHub repo about to be cloned; blocks the clone (hook exit 2)
# when Flagrix rates it MEDIUM or HIGH risk, or when the scan could not read
# enough of the repository to give a verdict (exit 4). A `--branch`/`-b` on the
# clone is scanned as that ref; otherwise the repository's default branch is.
# See docs/agent-gating.md for the settings.json wiring.
set -euo pipefail

payload="$(cat)"

# Extract a github.com repo URL — and the branch, if one is given — from a
# `git clone`/`gh repo clone` command. Prints "<url>\t<branch>" (branch may be
# empty), or nothing when the command is not a GitHub clone.
parsed="$(node -e '
  let input = ""
  process.stdin.on("data", (d) => (input += d))
  process.stdin.on("end", () => {
    try {
      const cmd = JSON.parse(input)?.tool_input?.command ?? ""
      // git takes global options before the subcommand (`git -C /tmp clone …`,
      // `git -c http.proxy=… clone …`, `git --git-dir=… clone …`), so allow any
      // run of them between `git` and `clone`.
      const VALUE = String.raw`(?:"[^"]*"|\x27[^\x27]*\x27|\S+)`
      const GIT_OPTS =
        String.raw`(?:\s+(?:-[Cc]\s+|--(?:git-dir|work-tree|namespace|exec-path|config-env)\s+)` +
        VALUE +
        String.raw`|\s+--?[\w-]+(?:=` + VALUE + String.raw`)?)*`
      const clone = cmd.match(
        new RegExp(String.raw`\bgit` + GIT_OPTS + String.raw`\s+clone\b|\bgh\s+repo\s+clone\b`)
      )
      if (!clone) return
      const m =
        cmd.match(/https?:\/\/github\.com\/[\w.-]+\/[\w.-]+/) ||
        cmd.match(/git@github\.com:[\w.-]+\/[\w.-]+/) ||
        cmd.match(/\bclone\s+([\w.-]+\/[\w.-]+)(?:\s|$)/)?.slice(1)
      if (!m) return
      // Only the clone itself counts: `git checkout -b x && git clone …` must
      // not pick up the checkout branch. `gh repo clone o/r -- -b x` passes
      // the flag through to git, so it is covered too.
      const segment = cmd.slice(clone.index).split(/&&|\|\||[;|\n]/)[0]
      const b = segment.match(/(?:^|\s)(?:--branch(?:=|\s+)|-b\s*)("[^"]+"|\x27[^\x27]+\x27|[^\s"\x27]+)/)
      const branch = b ? b[1].replace(/^["\x27]|["\x27]$/g, "") : ""
      process.stdout.write(String(Array.isArray(m) ? m[0] : m) + "\t" + branch)
    } catch {}
  })
' <<< "$payload")"

# Not a GitHub clone — allow.
[ -z "$parsed" ] && exit 0

url="${parsed%%$'\t'*}"
ref="${parsed#*$'\t'}"

args=(scan "$url" --json)
target="$url"
if [ -n "$ref" ]; then
  args+=(--ref "$ref")
  target="$url (branch $ref)"
fi

if npx -y flagrix "${args[@]}" > /dev/null 2>&1; then
  exit 0 # low risk
else
  code=$?
  rerun="npx flagrix scan $url${ref:+ --ref $ref}"
  case "$code" in
    2) echo "Flagrix: MEDIUM risk — review https://github.com/flagrix-io/flagrix-cli#exit-codes before cloning $target" >&2 ;;
    3) echo "Flagrix: HIGH risk — do NOT clone $target (malicious patterns detected). Run: $rerun" >&2 ;;
    4) echo "Flagrix: scan of $target was incomplete — not enough was read to give a verdict (usually GitHub's 60 req/h limit; set GITHUB_TOKEN). Run: $rerun" >&2 ;;
    *) echo "Flagrix: scan of $target failed (exit $code) — blocking out of caution. Run: $rerun" >&2 ;;
  esac
  exit 2 # exit 2 = block the tool call in Claude Code
fi
