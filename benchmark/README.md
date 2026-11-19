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

Outputs are written to `benchmark/results/`:

- `latest.json`: complete structured run and aggregate metrics
- `latest.csv`: flat, spreadsheet-friendly sample results

Ad-hoc outputs are gitignored; only the canonical snapshots
(`pre-fix-baseline.*`, `post-fix-final.*`) are tracked. To update a canonical
snapshot, copy `latest.json`/`latest.csv` over it and commit.

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

### Offline mirror (no GitHub token)

`offline/mirror.py` shallow-fetches every pinned commit (trees plus only the
blobs any scanner version could select) into `offline/git/`, and
`offline/gitmock.mjs` serves the scanner's GitHub REST calls from it:

```bash
python3 benchmark/offline/mirror.py
node --import ./benchmark/offline/gitmock.mjs benchmark/run.mjs
```

Results match the API-backed run sample-for-sample (verified against
the 2026-07-13 `post-fix-final.json`: 0 of 90 samples differ). npm download lookups return a
fixed 1M/week in this mode, so typosquat warnings never fire on reference repos.

**That equivalence no longer holds, and the offline mirror is not wired into
CI because of it.** `mirror.py` keeps its own copy of scanner-core's config
file patterns to decide which blobs to fetch, and that copy predates 0.7.0: it
has no Dockerfile/Containerfile, compose, `.devcontainer`, `.claude/commands`,
`.claude/agents`, `.claude/skills` or `.github/instructions` entry. So the
mirror does not contain files the current scanner reads, and an offline run
silently scans less than an API-backed one. Re-verify the equivalence after
bringing that list back in step with `CONFIG_FILE_PATTERNS`.

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
