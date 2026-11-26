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
  /**
   * Which reader produced the evidence. `"tarball"` read the whole commit in
   * one request under a byte budget; `"per-file"` spent one request per file
   * under a file cap, so it read far less of a large repository. `"unknown"`
   * is an engine that predates the field.
   *
   * Reported because it decides what the verdict rests on: the same commit
   * scanned both ways can score differently, and without this the two results
   * are indistinguishable.
   */
  readMode: "tarball" | "per-file" | "unknown"
  /** Why a requested whole-snapshot read did not happen. */
  readFallbackReason?: "too-large" | "unavailable" | "unreadable"
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
    reason: summary.incompleteReason,
    // Same reasoning as `complete` above: scanner-core < 0.8.0 reports no read
    // mode, and a missing field is "unknown" rather than an assumed path.
    readMode: summary.readMode ?? "unknown",
    readFallbackReason: summary.readFallbackReason
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
 * code and the human output say, and the version of the detection rules the
 * scan ran with — two scans of one commit under different rules can disagree,
 * and without it the results are indistinguishable.
 */
export type ScanReport = GitHubScanResult & { verdict: Verdict; coverage: Coverage; rulesVersion?: string }

/**
 * Every engine field is kept so existing consumers don't break, with one
 * correction: `safeToClone` is forced to false when the clear is unreliable.
 * The engine sets it from findings alone, and a scan that ran out of budget
 * has no findings to block on — that is exactly the result it must not pass.
 * `riskLevel` stays as the engine's reading of the files it did see; gates
 * should branch on `verdict` (or the exit code), not on `riskLevel`.
 */
export function scanReport(result: GitHubScanResult, rulesVersion?: string): ScanReport {
  const coverage = coverageOf(result)
  return {
    verdict: coverage.unreliableClear ? "incomplete" : result.riskLevel,
    coverage,
    ...(rulesVersion ? { rulesVersion } : {}),
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

/**
 * A short phrase for the counts line, naming where the files came from. Empty
 * for an engine that reports no read mode, so nothing is claimed about it.
 */
export function readModeLabel(coverage: Coverage): string {
  if (coverage.readMode === "tarball") return "read as one snapshot"
  if (coverage.readMode === "per-file") return "read file by file"
  return ""
}

const FALLBACK_CAUSE = {
  "too-large": "the repository is too large to download as one archive",
  unavailable: "GitHub would not serve the archive — refused, rate-limited, or unreachable",
  unreadable: "the archive did not parse as a gzipped tar"
} as const

/**
 * One sentence when a whole-snapshot read was asked for and did not happen —
 * empty otherwise, including when none was asked for. The fallback is not a
 * failure (the per-file path ran and the verdict stands), but it is a
 * different and smaller body of evidence than the one that was requested, and
 * silently serving that is how two scans of one commit disagree.
 */
export function describeReadFallback(coverage: Coverage): string {
  if (!coverage.readFallbackReason) return ""
  return (
    `Read file by file: ${FALLBACK_CAUSE[coverage.readFallbackReason]}. A per-file ` +
    `read spends one request per file against a file cap, so on a large ` +
    `repository it covers less than the one-request snapshot would have.`
  )
}
