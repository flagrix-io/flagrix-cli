# Flagrix benchmark

This benchmark evaluates the same `@flagrix/scanner-core` engine used by the
CLI and browser extension. It never clones repositories, installs packages, or
executes sample code.

## Safety model

- Critical fixtures are inert source strings served through an in-memory mock
  of the GitHub API. They are parsed by the scanner but never written or run.
  The reverse-shell fixture includes both socket and shell-process behavior;
  the AWS fixture uses a non-documentation dummy so reserved AWS examples stay
  valid negative controls.
- Malicious-package fixtures contain only inert dependency manifests derived
  from 25 non-withdrawn OpenSSF OSV reports pinned by repository commit and
  report blob SHA. Package archives and package source are never downloaded.
- Public repositories are read from immutable GitHub blobs at a 40-character
  commit SHA. The harness batches text-blob reads through GitHub GraphQL while
  preserving the scanner's exact selected-file contents and REST-shaped input.
- Moving branches are rejected by the runner. `benchmark:pin` resolves them to
  SHAs and writes `corpus.lock.json` before evaluation.
- Live malware archives are out of scope for this public/safe harness. A future
  private corpus can use independently labeled package metadata or source that
  has been unpacked in a disposable, network-disabled analysis environment.

## Commands

```bash
# Deterministic, offline baseline of the ten claimed critical behaviors
npm run benchmark -- --corpus critical-fixture

# Pin every GitHub target without cloning it
FLAGRIX_GITHUB_TOKEN=... npm run benchmark:pin

# Explicitly advance public repositories to their current heads
FLAGRIX_GITHUB_TOKEN=... npm run benchmark:pin -- --refresh

# Run all pinned samples (resume skips completed rows)
FLAGRIX_GITHUB_TOKEN=... npm run benchmark -- --resume

# Fail the process unless every gate passed and every sample completed
FLAGRIX_GITHUB_TOKEN=... npm run benchmark -- --enforce-gates

# Read each GitHub sample file by file instead of as one snapshot (the default)
node --import ./benchmark/offline/gitmock.mjs benchmark/run.mjs --no-tarball
```

Without `--enforce-gates` the runner reports and exits 0, red gates included,
which is what makes it usable interactively. CI passes the flag. It also fails
a run that did not finish: a run that dies partway — usually an exhausted
GitHub quota, which the runner breaks out of rather than throwing — leaves the
samples it never reached out of the metrics, so its gates are computed from a
partial read and can come back green having proved nothing. On a full run an
unevaluated (`null`) gate is a failure too; on a `--corpus` or `--sample` run
it is expected, so only `false` fails there.

The token should be a fine-grained, read-only GitHub PAT. Do not pass it via
`--token`, because command-line arguments can appear in process listings. If
`FLAGRIX_GITHUB_TOKEN` is absent, the scripts securely reuse `gh auth token`,
so an interactive `gh auth login -h github.com` is the easiest local setup.

Outputs are written to `benchmark/results/`, named after the reader the run
asked for (`tarball` or `per-file`), so the two modes never overwrite or
`--resume` from each other:

- `latest-tarball.json` / `latest-per-file.json`: complete structured run and
  aggregate metrics
- `latest-tarball.csv` / `latest-per-file.csv`: flat, spreadsheet-friendly
  sample results
- `<timestamp>-<reader>.json`: a copy of each finished run

Ad-hoc outputs are gitignored; only the canonical snapshots
(`pre-fix-baseline.*`, `post-fix-final.*`) are tracked. To update a canonical
snapshot, copy `latest-tarball.json`/`latest-tarball.csv` (the default
reader) over it and commit.

**Refresh `post-fix-final.*` with every engine release.** A stale snapshot is
not a harmless stale file: it is the only record of what the corpus is
*supposed* to produce, so while it lags there is nothing to compare a run
against. Scanner-core 0.7.0 shipped verdicts of HIGH (unsafe to clone) on
evanw/esbuild and MEDIUM on reduxjs/redux, and the drift went unnoticed for a
month because this snapshot predated the release.

## Where the benchmark runs

| run | corpora | token | gate |
| --- | --- | --- | --- |
| `ci.yml` → `benchmark-fixtures`, every PR | the three in-memory fixture corpora | none | blocks the PR |
| `benchmark.yml`, nightly + manual | all 114 samples | `FLAGRIX_GITHUB_TOKEN` | opens a failed run |
| `release.yml`, on a `v*` tag | all 114 samples | `FLAGRIX_GITHUB_TOKEN` | blocks the publish |

The fixture corpora are inert in-memory samples behind a mocked GitHub API, so
they are fast and need no network — but they cannot catch a false positive that
only appears on a real project, which is what 0.7.0's regression was. That is
why the public corpus gates the release as well as running nightly.

Nightly is not redundant with the release gate: detection rules ship from
flagrix-detection-rules on their own cadence and reach the scanner without a
commit here, so a rule can introduce a false positive that no pull request
touches.

**A full run costs roughly a whole hourly GitHub quota** — about 5,000 REST
requests for 114 samples. That limit is *per user*, not per token, so a local
full run and a CI run in the same hour starve each other. The v0.6.1 release
failed exactly this way: a local verification run minutes earlier left the
release gate to stop at sample 59 of 114. Do not run the full corpus locally
while a release or the nightly is in flight; the fixture corpora are free and
cost nothing to run any time.

### Offline mirror (no GitHub token)

`offline/mirror.py` shallow-fetches every pinned commit (trees plus only the
blobs any scanner version could select) into `offline/git/`, and
`offline/gitmock.mjs` serves the scanner's GitHub REST calls from it — the
tree, the file contents, and the commit tarball:

```bash
python3 benchmark/offline/mirror.py
node --import ./benchmark/offline/gitmock.mjs benchmark/run.mjs
```

The offline run matches the API-backed run. Verified 2026-11-19 against engine
0.7.1, over all 114 samples:

| | result |
| --- | --- |
| files scanned | 9,656 offline vs 9,656 API — identical on every sample |
| verdicts differing | 0 |
| findings only in the offline run | 0 |
| findings only in the API run | 10, all `TYPOSQUAT_PACKAGE` |

The one divergence is structural and harmless: npm download lookups return a
fixed 1M/week here, so the typosquat check — which only fires below 100k weekly
downloads — never fires offline. It changes no verdict.

**This is what CI runs.** A full API-backed run costs roughly a whole hourly
GitHub quota, and that limit is per user rather than per token, so the nightly,
a release and anyone running it locally used to starve each other; the v0.6.1
release died exactly that way. The offline path makes that impossible rather
than merely documented, and needs no token at all.

The mirror holds **every scannable blob**, uncapped. It deliberately has no
selection of its own: it once took the first 320 blobs in tree order while the
scanner sorted by `sourcePriority` and took the top 200, and after 0.7.0 began
reading build scripts first the two diverged badly — `noisy-node` scanned 225
files through the API and 34 from the mirror. A superset has nothing to drift.

Fonts and configs are uncapped too. The per-file path magic-checks at most 10
fonts, but scanner-core's snapshot path (flagrix-io/flagrix-scanner-core#15)
checks every font as the archive streams and gives configs a 4MB byte budget
instead of a count. A font the mirror lacks is missing from the synthesized
tarball, falls through to a per-file read that 404s offline, and becomes
`fetch-failed` — eslint has 33 fonts, rust 14, next.js 50 — so the mirror
fetches all of them.

`tree.json` records a fingerprint of every rule that decides which blobs are
fetched (`SELECTION_POLICY`, `PRIORITY`, `SCANNABLE`, `CONFIG`, `FONTS`), and a
mismatch re-fetches. Without it the cache short-circuited on `tree.json` merely
existing, so widening the patterns to follow the engine changed nothing and
reported `cached` for every repo. `--fingerprint` prints it, which is what the
CI cache key uses.

Rebuilding the whole mirror takes a few minutes and about 400MB.

## Corpus semantics

`reference-clean` means a project selected as a false-alarm reference at one
specific commit. It is not a claim that the project is vulnerability-free or
benign forever. Any High/Critical finding requires manual review and a note in
the result workbook before it is classified as a false positive.

`known-malicious-metadata` measures **signature coverage, not generalizing
recall**: every OSV package in the corpus is also present in the bundled
signature snapshot, so the 100% detection rate proves the dependency-matching
pipeline works end-to-end against independently labeled samples — it does not
predict detection of malware absent from the rules list. Detection of unseen
malicious *behavior* is exercised separately by the critical fixtures, which
match behavioral rules rather than package names.

`emerging-threat-fixture` covers 2025–2026 developer-targeted attacks that
live outside ordinary source files: VS Code `folderOpen` task files, fake font
loaders, Shai-Hulud/CHAINDROP `preinstall` droppers and `.claude` hooks, MCP
configs, agent-instruction injection, GlassWorm invisible-Unicode payloads,
blockchain dead drops, and ClickFix READMEs. Each fixture cites the public
report it was modeled on. Matching benign look-alikes (watch tasks, project
hooks, installer one-liners, `npx` MCP servers, real fonts, read-only RPC
calls, ordinary CI) are in `reference-fixture`.

Launch-gate defaults:

- 100% of critical fixtures detected in the expected category
- at least 90% of emerging-threat fixtures detected in the expected category
- at least 90% independently labeled malicious samples detected
- zero Critical findings in reference-clean samples
- no more than 5% reference-clean samples with a High verdict

### Which reader the samples are read with

scanner-core 0.8.0 can read a commit as one archive instead of one request per
file, and the two see different amounts of a large repository: 4,373 of
facebook/react's files against 226. A verdict therefore belongs to a reader,
and the runner records which one produced each row (`read_mode` in the CSV,
`readMode` per result, `readModes` in the metrics).

The default follows `READ_WHOLE_SNAPSHOT_BY_DEFAULT` in
`src/commands/shared.ts`, read out of the source at startup rather than copied
here, so the corpus always measures the reader the CLI ships.
That is the snapshot reader: `READ_WHOLE_SNAPSHOT_BY_DEFAULT` is `true` since
scanner-core 0.8.2 and rules 2026.11.23.001 brought every pinned repository
back to "low" when read whole. `--no-tarball` measures the per-file reader,
`--tarball` asks for the default explicitly. The release and nightly
workflows run both, each with `--enforce-gates`, for as long as the CLI
supports both.

A sixth gate, `everyGitHubSampleReadAsRequested`, fails a run in which any
GitHub sample was read by a reader other than the one asked for. It exists
because the first version of this mock answered `/tarball/` with its 404
catch-all: every sample fell back to the per-file path and the five gates came
back green, measuring a reader that was no longer the one under test. A silent
fallback halves the file count on a large repository, so it has to be a
failure rather than a note. `readFallbacks` in the metrics says why.

Fixtures stay on the per-file path — their file list is served from memory and
has no archive to offer, and a fixture is a handful of files, so both readers
see all of them. The archive parse is scanner-core's own test subject; what
these 50 GitHub samples measure is the coverage it produces.

Two differences from a live archive, both from how the mirror is built: files
it never fetched (images and other binaries, which no scanner variant selects)
are absent, and the tree sizes it records cover only the blobs it holds, so
the engine's 150MB tree-byte gate sees a smaller repository than GitHub would
serve. A sample where that gate decides the matter has to be measured against
the API.

Measured 2026-11-20, engine 0.8.0, rules 2026.11.20.001, all 114 samples:

| | file by file | one snapshot |
| --- | --- | --- |
| files scanned (50 GitHub samples) | 9,581 | 70,253 |
| verdicts off "low" | 0 | 10 |
| critical findings on reference-clean | 0 | 14 |
| gates | 6 green | `zeroCriticalReferenceFindings` and `referenceHighVerdictsAtMost5Percent` red |

The ten are pnpm (0.090 → 1.000), socket.io (0.255 → 0.708), npm/cli (0.090 →
0.617) and electron (0.240 → 0.640) on high, and next, playwright, node, bun,
cpython and ansible on medium. The critical findings are all
`POSTINSTALL_SCRIPT` on nested `package.json` files, most of them pnpm's and
npm's own test fixtures for lifecycle scripts; the bulk of the rest is
`OBFUSCATED_CODE` and the `OBF_*` family on checked-in minified bundles under
paths like `next/src/compiled/`. That is why the CLI reads file by file by
default: this run is the measurement that has to come back clean before the
default moves.
