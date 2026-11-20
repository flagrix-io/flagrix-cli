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

## How much gets read

A scan reads one file per GitHub request, up to ~200 files, and says so:

```
  3 files scanned · 10 dependencies · 2 issues · read file by file
```

`--tarball` reads the whole commit in one request instead (`/tarball/{sha}`),
which trades the 200-file cap for a 16MB budget of source:

| facebook/react @ e04279e | file by file | one snapshot |
| --- | --- | --- |
| files read | 226 | 4,373 |
| GitHub requests | 231 | 6 |
| wall clock | 14.4s | 8.7s |

The request count is the part that matters without a token: GitHub allows 60
requests an hour unauthenticated, so a per-file scan of any real repository
runs out part way through and exits 4, while a snapshot read finishes.

**It is off by default**, because of what the extra coverage reaches. The
file cap spends its budget on files that run on install and on ordinary
source; 4,000 files also means test fixtures and vendored bundles, where the
rules have not been measured. Across the 50 pinned repositories in
[benchmark/](benchmark/), reading snapshots moves 10 verdicts off "low":
pnpm/pnpm 0.090 → 1.000, socket.io 0.255 → 0.708, npm/cli 0.090 → 0.617 and
electron 0.240 → 0.640 all land on "high — do not clone", on
`POSTINSTALL_SCRIPT` findings in pnpm's and npm's own lifecycle-script test
fixtures and `OBFUSCATED_CODE` in checked-in minified bundles. Live, not just
offline: `flagrix scan pnpm/pnpm --ref 0dd21df` reads 227 files and answers
LOW, 91/100; with `--tarball` it reads 2,502 and answers HIGH, 0/100. Turn it
on when the wider coverage is worth reading those findings by hand.

Either way the result names the reader that produced it, in the human output
and as `coverage.readMode` (`"tarball"`, `"per-file"`, or `"unknown"` from an
engine older than 0.8.0) in the JSON. Two scans of one commit can score
differently depending on which ran, so the mode is part of the verdict rather
than a detail. When `--tarball` is asked for and GitHub will not serve the
archive, the scan falls back to reading file by file, keeps its verdict, and
says why (`coverage.readFallbackReason`: `too-large`, `unavailable` or
`unreadable`).

## Exit codes

| code | meaning |
|---|---|
| 0 | low risk |
| 1 | scan failed |
| 2 | medium risk — review before proceeding |
| 3 | high risk — do not clone |
| 4 | scan incomplete — not enough of the repository was read to give a verdict |

`--json` (automatic when stdout is piped) emits the full result. The verdict is
**pinned to the scanned commit** (`commitSha` in the JSON): every file is read at
that SHA, so a push mid-scan or after the verdict can't silently invalidate it.

### Incomplete scans (exit 4)

A repository scan is one tree request plus up to ~200 file reads, and GitHub
allows 60 requests an hour without a token. When the budget runs out part way
through, the rest of the repository is never looked at — so a "low risk, no
findings" result over 30 of 180 files is the absence of looking, not a clean
bill of health. (`--tarball` spends one request instead of ~200 — see
[How much gets read](#how-much-gets-read).)

The result says so (`scanSummary.complete: false`, with
`scanSummary.incompleteReason` of `"rate-limit"` or `"fetch-errors"`), the
human output withholds the verdict and the score, and the exit code is **4**
instead of 0. In CI the exit code is the decision and nobody reads stdout, so
a gate on `flagrix scan` stops here as it does on any non-zero code. Findings
are the other way round: evidence found is evidence however little else was
read, so a medium or high verdict keeps its own code and the coverage note
reads "there may be more".

In `--json` output, read `verdict` and `coverage` rather than `riskLevel`:

```json
{
  "verdict": "incomplete",
  "coverage": {
    "complete": false,
    "unreliableClear": true,
    "filesRead": 30,
    "filesUnread": 150,
    "reason": "rate-limit",
    "readMode": "per-file"
  },
  "riskLevel": "low",
  "safeToClone": false,
  ...
}
```

- `verdict` is `"low"`, `"medium"`, `"high"`, or `"incomplete"` when a low
  result rests on files that were never read. It matches the exit code
  (0 / 2 / 3 / 4).
- `coverage.unreliableClear` is true exactly when `verdict` is `"incomplete"`;
  `coverage.complete` is false on any partial scan, including a medium or high
  one. `reason` is present only when coverage is incomplete.
- `riskLevel`, `riskScore` and the rest of the engine's result are unchanged,
  so existing consumers keep working — but `riskLevel` is the engine's reading
  of the files it did see, so on an incomplete scan it can still say `"low"`.
- `safeToClone` is kept for compatibility and is now `false` whenever
  `verdict` is `"incomplete"` (in 0.4.0 and earlier it could be `true` there). Gate on
  `verdict` or the exit code instead.
- `coverage.readMode` is which reader ran, and `coverage.readFallbackReason`
  is present only when a requested snapshot read did not happen.

The MCP tool's JSON block carries the same fields.

Set a token to make this rare: `GITHUB_TOKEN` raises the budget to 5,000/h.

## AI agents

```bash
claude mcp add flagrix -- npx -y flagrix mcp
```

Tools: `scan_github_repo` (`target`, `ref`, `tarball`), `scan_github_user`. A Claude Code hook that gates every
`git clone` on a scan ships in [hooks/](hooks/) — see
[docs/agent-gating.md](docs/agent-gating.md).

## Tokens & rate limits

Unauthenticated scans use GitHub's 60 req/h budget (a scan issues one request per
scanned file, up to ~200, or a single request with `--tarball`). Set
`GITHUB_TOKEN` (or `FLAGRIX_GITHUB_TOKEN`, or `--token`) to raise it to 5,000/h
and to scan private repositories. A scan that runs out of budget reports partial
coverage and exits 4 — see [Incomplete scans](#incomplete-scans-exit-4).

## Privacy

Fully local. No telemetry, no accounts, no Flagrix backend — the only network
calls go to the GitHub/npm APIs and the public
[detection-rules](https://github.com/flagrix-io/flagrix-detection-rules)
repository (signature refresh, cached 6 h, with a bundled offline snapshot).

Dependencies are also checked against the OSV malicious-package feed
(`osv-malicious.json` from the same repository: every npm/PyPI package the
OpenSSF malicious-packages project has confirmed malicious). The feed is
downloaded and matched locally, so dependency names never leave your machine.
It is cached 6 h and revalidated with its ETag. Set `FLAGRIX_OSV_FEED=0` to
skip it (the curated list in the signatures still applies).

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
