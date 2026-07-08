import type { GitHubScanResult, GitHubUserScanResult } from "@flagrix/scanner-core"

const useColor = process.stdout.isTTY && !process.env.NO_COLOR

const paint = (code: string) => (s: string) => (useColor ? `[${code}m${s}[0m` : s)
const bold = paint("1")
const dim = paint("2")
const red = paint("31")
const yellow = paint("33")
const green = paint("32")

const VERDICTS = {
  low: { label: "LOW RISK", verdict: "Safe to clone", color: green },
  medium: { label: "MEDIUM RISK", verdict: "Review before cloning", color: yellow },
  high: { label: "HIGH RISK", verdict: "Do not clone", color: red }
} as const

/** Higher = safer, mirroring the extension's score presentation. */
export function securityScore(riskScore: number): number {
  return 100 - Math.round(riskScore * 100)
}

export function renderRepoResult(result: GitHubScanResult): string {
  const v = VERDICTS[result.riskLevel]
  const slug = `${result.repo.owner}/${result.repo.repo}`
  const sha = result.commitSha?.slice(0, 7)
  const lines: string[] = []

  lines.push("")
  lines.push(`  ${bold(slug)}${sha ? dim(` @ ${sha}`) : ""}`)
  lines.push(
    `  ${v.color(bold(`${v.label} — ${v.verdict}`))}  ${dim(`security score ${securityScore(result.riskScore)}/100`)}`
  )
  lines.push(
    dim(
      `  ${result.scanSummary.filesScanned} files scanned · ${result.scanSummary.dependenciesChecked} dependencies · ${result.findings.length} issue${result.findings.length === 1 ? "" : "s"}`
    )
  )

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
