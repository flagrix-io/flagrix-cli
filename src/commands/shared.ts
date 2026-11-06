import type { GitHubScanResult, RiskLevel } from "@flagrix/scanner-core"

import { coverageOf } from "../lib/coverage.js"

/**
 * The exit-code contract (documented in --help and README):
 *   0 low · 1 scan failed · 2 medium · 3 high · 4 scan incomplete
 * Gates should treat anything non-zero as "do not proceed".
 */
export const EXIT = { LOW: 0, ERROR: 1, MEDIUM: 2, HIGH: 3, INCOMPLETE: 4 } as const

export function exitCodeFor(level: RiskLevel): number {
  return level === "high" ? EXIT.HIGH : level === "medium" ? EXIT.MEDIUM : EXIT.LOW
}

/**
 * The exit code for a repository scan, which is `exitCodeFor` plus coverage.
 *
 * In CI the exit code *is* the decision and nobody reads stdout, so a "low"
 * reached by running out of GitHub budget half way through must not exit 0:
 * "we could not look" is a different fact from "we looked and found nothing".
 * It exits 4 instead — non-zero, which correct gates already stop on.
 * A medium or high result keeps its own code: the findings stand regardless
 * of what else went unread.
 */
export function exitCodeForScan(result: GitHubScanResult): number {
  return coverageOf(result).unreliableClear ? EXIT.INCOMPLETE : exitCodeFor(result.riskLevel)
}

export function resolveToken(flag?: string): string | undefined {
  return flag || process.env.FLAGRIX_GITHUB_TOKEN || process.env.GITHUB_TOKEN || undefined
}

/** JSON when asked — or automatically when stdout is piped (agents, hooks, CI). */
export function wantJson(flag?: boolean): boolean {
  return flag ?? !process.stdout.isTTY
}
