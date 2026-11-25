import type { GitHubScanResult, RiskLevel } from "@flagrix/scanner-core"

import { coverageOf } from "../lib/coverage.js"

/**
 * The exit-code contract (documented in --help and README):
 *   0 low · 1 scan failed · 2 medium · 3 high · 4 scan incomplete
 * Gates should treat anything non-zero as "do not proceed".
 */
export const EXIT = { LOW: 0, ERROR: 1, MEDIUM: 2, HIGH: 3, INCOMPLETE: 4 } as const

// Kept in step with package.json by tests/version.test.ts — `npm version`
// does not reach into source, and the built CLI would otherwise report the
// previous release. Lives here rather than in cli.ts because `flagrix mcp`
// advertises the same number to its client, and cli.ts runs a scan on import.
export const VERSION = "0.9.0"

/**
 * Whether a scan reads the whole commit in one request (scanner-core's
 * `tarball` option) unless told otherwise.
 *
 * On. Reading the snapshot is better on every axis the CLI cares about:
 * facebook/react goes from 226 files in 14.4s to 4,373 in 8.7s, and the scan
 * spends 6 GitHub requests instead of 231, which is the difference between an
 * unauthenticated scan finishing and running out of the hourly 60 part way
 * through. Node has no permission to ask for, unlike the extension.
 *
 * It was opt-in until the rules had been measured on what the wider coverage
 * reaches: test fixtures and vendored bundles. On scanner-core 0.8.1 and rules
 * 2026.11.20.001, reading the 50 pinned repositories as snapshots moved 10
 * verdicts off "low" (pnpm and socket.io to "high") and failed two release
 * gates. scanner-core 0.8.2 rates install hooks by what they can do and only
 * counts a credential read as exfiltration when it leaves for another origin,
 * and rules 2026.11.23.001 skip matches in comments; with both, every
 * repository in the corpus reads low as a snapshot and all six gates pass in
 * both modes.
 *
 * `--no-tarball` (or `tarball: false` on the MCP tool) still reads file by
 * file, every result says which reader ran, and the release gate runs the
 * benchmark in both modes for as long as both are supported.
 */
export const READ_WHOLE_SNAPSHOT_BY_DEFAULT = true

/**
 * The reader `flagrix scan` asks for, from its flags. `--no-tarball` reads
 * file by file; `--tarball` asks for what is now the default and stays
 * accepted so scripts written for 0.7 keep working. Unset leaves the choice to
 * READ_WHOLE_SNAPSHOT_BY_DEFAULT.
 */
export function tarballFromFlags(flags: { tarball?: boolean; "no-tarball"?: boolean }): boolean | undefined {
  if (flags["no-tarball"]) return false
  if (flags.tarball) return true
  return undefined
}

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
