import type { GitHubScanResult, RiskLevel } from "@flagrix/scanner-core"

/**
 * What a scan actually managed to read.
 *
 * A file that was never read cannot clear a repository, so a scan that ran
 * short of its own file list has not earned a verdict of "low risk" — that
 * would be the absence of looking, dressed up as the absence of malware.
 * Findings are the other way round: evidence found is evidence, however
 * little else was read, so a medium/high verdict still stands on its own.
 */
export interface Coverage {
  /** False only when the engine itself reported partial coverage. */
  complete: boolean
  /** A "low" that rests on files which were never read — not a clean bill of health. */
  unreliableClear: boolean
  filesRead: number
  filesUnread: number
  reason?: "rate-limit" | "fetch-errors"
}

export function coverageOf(result: GitHubScanResult): Coverage {
  const summary = result.scanSummary
  // `!== false`, not `=== true`: scanner-core < 0.6.0 has no such field, and a
  // missing field is "unknown", never "incomplete".
  const complete = summary.complete !== false
  const filesUnread = (summary.skippedFiles ?? []).filter(
    (file) => file.reason === "rate-limited" || file.reason === "fetch-failed"
  ).length

  return {
    complete,
    unreliableClear: !complete && result.riskLevel === "low",
    filesRead: summary.filesScanned,
    filesUnread,
    reason: summary.incompleteReason
  }
}

/**
 * The decision a gate should act on: the risk level, or "incomplete" when a
 * low verdict rests on files that were never read (the case that exits 4).
 */
export type Verdict = RiskLevel | "incomplete"

/**
 * A repository result as `--json` and the MCP tool emit it: the engine's
 * result plus the CLI's own coverage verdict, so the JSON says what the exit
 * code and the human output say.
 */
export type ScanReport = GitHubScanResult & { verdict: Verdict; coverage: Coverage }

/**
 * Every engine field is kept so existing consumers don't break, with one
 * correction: `safeToClone` is forced to false when the clear is unreliable.
 * The engine sets it from findings alone, and a scan that ran out of budget
 * has no findings to block on — that is exactly the result it must not pass.
 * `riskLevel` stays as the engine's reading of the files it did see; gates
 * should branch on `verdict` (or the exit code), not on `riskLevel`.
 */
export function scanReport(result: GitHubScanResult): ScanReport {
  const coverage = coverageOf(result)
  return {
    verdict: coverage.unreliableClear ? "incomplete" : result.riskLevel,
    coverage,
    ...result,
    safeToClone: result.safeToClone && !coverage.unreliableClear
  }
}

/**
 * One or two sentences naming what was missed and why — empty when coverage
 * is whole. Written for both the human output and the MCP tool text, so it
 * stays free of colour codes and markup. `findingCount` is how many findings
 * the scan did report: an incomplete low can still carry low-weight findings,
 * and then "nothing was found" would contradict the list printed with it.
 */
export function describeCoverage(coverage: Coverage, findingCount: number): string {
  if (coverage.complete) return ""

  const read = `${coverage.filesRead} ${coverage.filesRead === 1 ? "file" : "files"} read`
  const counts = coverage.filesUnread > 0 ? `${read}, ${coverage.filesUnread} left unread` : read
  // On a low verdict the gap is the whole story; on medium/high it means the
  // findings are a floor, not a ceiling.
  const consequence = !coverage.unreliableClear
    ? "There may be more than what is reported here."
    : findingCount > 0
      ? "What was read turned up only low-weight findings — that says nothing about the files left unread."
      : "Nothing was found in what was read — that is not the same as nothing being there."

  if (coverage.reason === "rate-limit") {
    return (
      `Stopped early — GitHub rate limit: ${counts}. Unauthenticated scans share ` +
      `60 API requests an hour and one scan can need up to 200, so the rest of ` +
      `the repository was never looked at. A token raises the limit to 5,000/hour ` +
      `(--token, or GITHUB_TOKEN / FLAGRIX_GITHUB_TOKEN). ${consequence}`
    )
  }
  return (
    `Scan incomplete — some files could not be read: ${counts}. GitHub did not ` +
    `return the rest, so this rests on partial evidence; re-scanning usually ` +
    `clears it up. ${consequence}`
  )
}
