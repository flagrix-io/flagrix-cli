import type { GitHubScanResult, GitHubUserScanResult } from "@flagrix/scanner-core"

import { coverageOf, describeCoverage, describeReadFallback, readModeLabel } from "./coverage.js"
import { INSTALL_TIME_NOTE, verdictIsInstallTime } from "./install-time.js"

const useColor = process.stdout.isTTY && !process.env.NO_COLOR

const paint = (code: string) => (s: string) => (useColor ? `[${code}m${s}[0m` : s)
const bold = paint("1")
const dim = paint("2")
const red = paint("31")
const yellow = paint("33")
const green = paint("32")

const VERDICTS = {
  low: { label: "LOW RISK", verdict: "No blocking findings", color: green },
  medium: { label: "MEDIUM RISK", verdict: "Review before cloning", color: yellow },
  high: { label: "HIGH RISK", verdict: "Do not clone", color: red }
} as const

/** The same verdicts when every finding behind them runs on install. */
const INSTALL_VERDICTS = {
  medium: "Review before installing",
  high: "Do not install"
} as const

/** Soft-wrap a prose note into the indented column the result lines use. */
function wrapNote(text: string, indent: string, width = 78): string[] {
  const lines: string[] = []
  let line = ""
  for (const word of text.split(" ")) {
    if (line && (indent + line + " " + word).length > width) {
      lines.push(indent + line)
      line = word
    } else {
      line = line ? `${line} ${word}` : word
    }
  }
  if (line) lines.push(indent + line)
  return lines
}

/** Higher = safer, mirroring the extension's score presentation. */
export function securityScore(riskScore: number): number {
  return 100 - Math.round(riskScore * 100)
}

export function renderRepoResult(result: GitHubScanResult): string {
  const v = VERDICTS[result.riskLevel]
  const installTime = verdictIsInstallTime(result)
  const verdict = installTime && result.riskLevel !== "low" ? INSTALL_VERDICTS[result.riskLevel] : v.verdict
  const coverage = coverageOf(result)
  const slug = `${result.repo.owner}/${result.repo.repo}`
  const sha = result.commitSha?.slice(0, 7)
  const lines: string[] = []

  lines.push("")
  lines.push(`  ${bold(slug)}${sha ? dim(` @ ${sha}`) : ""}`)
  if (coverage.unreliableClear) {
    // Withhold the clean verdict and the score: both would read as a clean
    // bill of health for files that were never opened.
    lines.push(
      `  ${yellow(bold("SCAN INCOMPLETE — no verdict"))}  ${dim("not enough of this repository was read to give a verdict")}`
    )
  } else {
    lines.push(
      `  ${v.color(bold(`${v.label} — ${verdict}`))}  ${dim(`security score ${securityScore(result.riskScore)}/100`)}`
    )
    if (installTime) for (const line of wrapNote(INSTALL_TIME_NOTE, "  ")) lines.push(dim(line))
  }
  // The read mode sits on the counts line because it is what makes the file
  // count mean something: 4,373 files read as one snapshot and 200 read one
  // request at a time are not the same evidence, and the verdict follows the
  // difference.
  const readMode = readModeLabel(coverage)
  lines.push(
    dim(
      `  ${result.scanSummary.filesScanned} files scanned · ${result.scanSummary.dependenciesChecked} dependencies · ${result.findings.length} issue${result.findings.length === 1 ? "" : "s"}${readMode ? ` · ${readMode}` : ""}`
    )
  )

  // Asked for the snapshot, got the per-file path: say so unprompted, because
  // the coverage on offer was not the coverage delivered.
  const fallback = describeReadFallback(coverage)
  if (fallback) {
    lines.push("")
    for (const line of wrapNote(fallback, "  ")) lines.push(dim(line))
  }

  // Stated whenever coverage fell short — on a high-risk verdict too, where it
  // means "and there may be more than this".
  if (!coverage.complete) {
    lines.push("")
    for (const line of wrapNote(describeCoverage(coverage, result.findings.length), "  ")) lines.push(yellow(line))
  }

  for (const f of result.findings) {
    lines.push("")
    lines.push(`  ${bold(f.severity.toUpperCase())} ${f.description}`)
    const file = f.file || f.files?.[0]
    if (file) {
      const anchor = f.evidence?.[0] ? `:${f.evidence[0].line}` : ""
      lines.push(dim(`    ${file}${anchor}`))
    }
    for (const e of f.evidence ?? []) {
      lines.push(dim(`      ${String(e.line).padStart(4)}  ${e.code}`))
    }
  }

  if (result.commitSha) {
    lines.push("")
    lines.push(dim(`  Verdict applies to commit ${result.commitSha} — re-scan after new pushes.`))
  }
  lines.push(dim(`  ${result.disclaimer}`))
  lines.push("")
  return lines.join("\n")
}

export function renderUserResult(result: GitHubUserScanResult): string {
  const v = VERDICTS[result.riskLevel]
  const lines: string[] = []

  lines.push("")
  lines.push(`  ${bold(result.username)}  ${dim(result.profileUrl)}`)
  lines.push(
    `  ${v.color(bold(v.label))}  ${dim(`security score ${securityScore(result.riskScore)}/100`)}`
  )
  lines.push(
    dim(
      `  ${result.accountAgeDays} days old · ${result.followers} followers · ${result.publicRepos} public repos`
    )
  )
  for (const f of result.riskFactors) {
    lines.push(`  ${bold("RISK")}  ${f.description} ${dim(`(+${Math.round(f.weight * 100)}%)`)}`)
  }
  for (const t of result.trustSignals) {
    lines.push(`  ${bold("TRUST")} ${t.description} ${dim(`(${Math.round(t.weight * 100)}%)`)}`)
  }
  lines.push("")
  lines.push(`  ${result.recommendation}`)
  lines.push("")
  return lines.join("\n")
}
