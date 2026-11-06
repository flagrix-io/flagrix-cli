import type { GitHubScanResult } from "@flagrix/scanner-core"

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
 * One or two sentences naming what was missed and why — empty when coverage
 * is whole. Written for both the human output and the MCP tool text, so it
 * stays free of colour codes and markup.
 */
export function describeCoverage(coverage: Coverage): string {
  if (coverage.complete) return ""

  const read = `${coverage.filesRead} ${coverage.filesRead === 1 ? "file" : "files"} read`
  const counts = coverage.filesUnread > 0 ? `${read}, ${coverage.filesUnread} left unread` : read
  // On a low verdict the gap is the whole story; on medium/high it means the
  // findings are a floor, not a ceiling.
  const consequence = coverage.unreliableClear
    ? "Nothing was found in what was read — that is not the same as nothing being there."
    : "There may be more than what is reported here."

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
