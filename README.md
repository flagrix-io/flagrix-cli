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

A scan reads the whole commit in one request (`/tarball/{sha}`), up to a 16MB
budget of source, and says so:

```
  4373 files scanned · 12 dependencies · 0 issues · read as one snapshot
```

`--no-tarball` reads one file per request instead, up to ~200 files:

| facebook/react @ e04279e | one snapshot (default) | `--no-tarball` |
| --- | --- | --- |
| files read | 4,373 | 226 |
| GitHub requests | 6 | 231 |
| wall clock | 8.7s | 14.4s |

The request count is the part that matters without a token: GitHub allows 60
requests an hour unauthenticated, so a per-file scan of any real repository
runs out part way through and exits 4, while a snapshot read finishes.

The wider read reaches test fixtures and vendored bundles, which the file cap
used to skip. Across the 50 pinned repositories in [benchmark/](benchmark/),
every one reads "low" as a snapshot, and the release gate runs the whole
corpus with both readers. `--tarball` is still accepted; it asks for the
default.

Either way the result names the reader that produced it, in the human output
and as `coverage.readMode` (`"tarball"`, `"per-file"`, or `"unknown"` from an
engine older than 0.8.0) in the JSON. Two scans of one commit can score
differently depending on which ran, so the mode is part of the verdict rather
than a detail. When GitHub will not serve the archive, the scan falls back to reading file by file, keeps its verdict, and
says why (`coverage.readFallbackReason`: `too-large`, `unavailable` or
`unreadable`).

## Exit codes

| code | meaning |
|---|---|
| 0 | low risk |
| 1 | scan failed |
| 2 | medium risk — review before proceeding |
| 3 | high risk — do not clone or install |
| 4 | scan incomplete — not enough of the repository was read to give a verdict |

When every finding behind a medium or high verdict runs on install (an
install hook, or a malicious or typosquatted dependency), the verdict reads
"Review before installing" / "Do not install" instead of naming the clone:
that code runs on `npm install`, not on `git clone`. The exit code is the same.

`--json` (automatic when stdout is piped) emits the full result. The verdict is
**pinned to the scanned commit** (`commitSha` in the JSON): every file is read at
that SHA, so a push mid-scan or after the verdict can't silently invalidate it.

### Incomplete scans (exit 4)

A per-file scan (`--no-tarball`, or the fallback when GitHub will not serve
the archive) is one tree request plus up to ~200 file reads, and GitHub
allows 60 requests an hour without a token. When the budget runs out part way
through, the rest of the repository is never looked at — so a "low risk, no
findings" result over 30 of 180 files is the absence of looking, not a clean
bill of health. The default snapshot read spends one request on the
contents instead, so it rarely gets here — see
[How much gets read](#how-much-gets-read).

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

Tools: `scan_github_repo` (`target`, `ref`, `tarball` — default `true`, `false`
reads file by file), `scan_github_user`. A Claude Code hook that gates every
`git clone` on a scan ships in [hooks/](hooks/) — see
[docs/agent-gating.md](docs/agent-gating.md).

## Tokens & rate limits

Unauthenticated scans use GitHub's 60 req/h budget (a scan reads the commit's contents in a
single request, or one request per scanned file, up to ~200, with
`--no-tarball`). Set
`GITHUB_TOKEN` (or `FLAGRIX_GITHUB_TOKEN`, or `--token`) to raise it to 5,000/h
and to scan private repositories. A scan that runs out of budget reports partial
coverage and exits 4 — see [Incomplete scans](#incomplete-scans-exit-4).

## Privacy

Fully local. No telemetry, no accounts, no Flagrix backend — the only network
calls go to:

- the GitHub API (`api.github.com`), for the file tree, file contents and
  profile data;
- `codeload.github.com`, for the archive of the commit being scanned (the
  default snapshot read; the API's `/tarball/{sha}` redirects there — not
  contacted with `--no-tarball`);
- npm's public download-count API (`api.npmjs.org`), for typosquat checks;
- the public
  [detection-rules](https://github.com/flagrix-io/flagrix-detection-rules)
  repository (signature refresh, cached 6 h, with a bundled offline snapshot).

Dependencies are also checked against the OSV malicious-package feed
(`osv-malicious.json` from the same repository: every npm/PyPI package the
OpenSSF malicious-packages project has confirmed malicious). The feed is
downloaded and matched locally, so the OSV check sends no dependency names
anywhere. It is cached 6 h and revalidated with its ETag. Set
`FLAGRIX_OSV_FEED=0` to skip it (the curated list in the signatures still
applies).

The one place a dependency name leaves your machine is the typosquat check: a
name within an edit or two of one of 15 popular npm packages (lodash, express,
react…) is looked up on npm's download-count API, so a well-used package isn't
reported as a typosquat.

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
