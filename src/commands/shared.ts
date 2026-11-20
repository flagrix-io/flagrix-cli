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
export const VERSION = "0.7.0"

/**
 * Whether a scan reads the whole commit in one request (scanner-core's
 * `tarball` option) unless told otherwise.
 *
 * Off, and the reason is the corpus rather than the mechanism. Reading the
 * snapshot is better on every axis the CLI cares about: facebook/react goes
 * from 226 files in 14.4s to 4,373 in 8.7s, and the scan spends 6 GitHub
 * requests instead of 231, which is the difference between an unauthenticated
 * scan finishing and running out of the hourly 60 part way through. Node has
 * no permission to ask for, unlike the extension.
 *
 * What stops it is what the extra coverage reaches. The 200-file cap spends
 * its budget on the files that run on install and on ordinary source; a byte
 * cap wide enough for 4,000 files also reads the deprioritised tail — test
 * fixtures and vendored bundles — and the rules were never measured there.
 * Over the 50 pinned repositories, read as snapshots:
 *
 *   - 10 verdicts move off "low": pnpm 0.090 → 1.000, socket.io 0.255 →
 *     0.708, npm/cli 0.090 → 0.617 and electron 0.240 → 0.640 all land on
 *     "high — do not clone".
 *   - 14 critical findings on repositories labelled clean, all
 *     POSTINSTALL_SCRIPT on nested package.json files that are pnpm's and
 *     npm's own test fixtures for lifecycle scripts.
 *   - 95 OBFUSCATED_CODE and 104 further OBF_* findings, mostly on minified
 *     bundles checked in under paths like next/src/compiled/.
 *
 * Two release gates fail on that run (zeroCriticalReferenceFindings and
 * referenceHighVerdictsAtMost5Percent) — the same pair that caught 0.7.0.
 * Confirmed against the live API, not just the offline mirror: `flagrix scan
 * pnpm/pnpm --ref 0dd21df` reads 227 files and answers LOW, 91/100, and with
 * `--tarball` reads 2,502 and answers HIGH, 0/100, do not clone.
 *
 * So the reader is opt-in (`--tarball`, or `tarball: true` on the MCP tool)
 * and every result says which one ran. Flipping this is one line plus a green
 * `npm run benchmark -- --tarball --enforce-gates`, which is the measurement
 * that has to come back clean first.
 */
export const READ_WHOLE_SNAPSHOT_BY_DEFAULT = false

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
