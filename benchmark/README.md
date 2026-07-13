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
```

The token should be a fine-grained, read-only GitHub PAT. Do not pass it via
`--token`, because command-line arguments can appear in process listings. If
`FLAGRIX_GITHUB_TOKEN` is absent, the scripts securely reuse `gh auth token`,
so an interactive `gh auth login -h github.com` is the easiest local setup.

Outputs are written to `benchmark/results/`:

- `latest.json`: complete structured run and aggregate metrics
- `latest.csv`: flat, spreadsheet-friendly sample results

## Corpus semantics

`reference-clean` means a project selected as a false-alarm reference at one
specific commit. It is not a claim that the project is vulnerability-free or
benign forever. Any High/Critical finding requires manual review and a note in
the result workbook before it is classified as a false positive.

Launch-gate defaults:

- 100% of critical fixtures detected in the expected category
- at least 90% independently labeled malicious samples detected
- zero Critical findings in reference-clean samples
- no more than 5% reference-clean samples with a High verdict
