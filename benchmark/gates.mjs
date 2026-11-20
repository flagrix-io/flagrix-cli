/**
 * Turning a benchmark report into a pass/fail verdict for CI.
 *
 * Kept apart from run.mjs, which performs a run on import, so the decision can
 * be tested against recorded reports — including the one where scanner-core
 * 0.7.0 called evanw/esbuild high-risk and unsafe to clone.
 *
 * The contract is the six `gates`, which are the thresholds this benchmark
 * declares, plus the run having actually finished. Individual samples missing
 * their expected verdict is a finer-grained signal than that contract: it is
 * reported, loudly, but it does not fail the build. Treating it as a failure
 * would mean CI blocking on every accepted false alarm, and the corpus already
 * has a process for those (manual review recorded in reference-review.json).
 */

/**
 * `{ problems, warnings }` — a non-empty `problems` means the run failed.
 *
 * `requireEveryGate` is false for a `--corpus` / `--sample` / `--limit` run,
 * which cannot evaluate the gates belonging to the corpora it left out.
 */
export function gateReport(metrics, { requireEveryGate } = { requireEveryGate: true }) {
  const problems = []
  const warnings = []

  // Completeness is half the check, and the half that is easy to lose. A run
  // that dies partway — usually an exhausted GitHub quota, which run.mjs
  // breaks out of rather than throwing — leaves every sample it never reached
  // out of the metrics, so the gates it does report are computed from
  // whatever it managed to read. One such run has been observed reporting
  // four green gates without ever reaching the repository whose regression
  // prompted all of this.
  if (metrics.samplesCompleted < metrics.samplesDefined) {
    // Say which kind of shortfall it is. A sample that errored was reached
    // and failed; one that was never attempted means the run abandoned the
    // rest of the corpus, which is what an exhausted GitHub quota looks like
    // — and the corpora at the end of the list never get a gate at all.
    const attempted = metrics.samplesAttempted ?? metrics.samplesCompleted
    const unattempted = metrics.samplesDefined - attempted
    const errored = attempted - metrics.samplesCompleted
    const detail = [
      errored > 0 ? `${errored} errored` : null,
      unattempted > 0 ? `${unattempted} never attempted` : null,
    ]
      .filter(Boolean)
      .join(", ")
    problems.push(
      `only ${metrics.samplesCompleted} of ${metrics.samplesDefined} samples completed` +
        ` (${detail}) — the gates below were computed from a partial run`
    )
  }

  for (const [name, value] of Object.entries(metrics.gates ?? {})) {
    if (value === false) problems.push(`gate failed: ${name}`)
    // A gate that could not be evaluated is a skipped check, not a passed one.
    else if (value === null && requireEveryGate) {
      problems.push(`gate not evaluated: ${name}`)
    }
  }

  if (metrics.samplesPassed < metrics.samplesCompleted) {
    const missed = metrics.samplesCompleted - metrics.samplesPassed
    warnings.push(
      `${missed} completed sample(s) missed their expected verdict` +
        " — review them, and record any accepted false alarm in reference-review.json"
    )
  }

  return { problems, warnings }
}
