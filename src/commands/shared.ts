import type { RiskLevel } from "@flagrix/scanner-core"

/**
 * The exit-code contract (documented in --help and README):
 *   0 low · 1 scan failed · 2 medium · 3 high
 * Gates should treat anything non-zero as "do not proceed".
 */
export const EXIT = { LOW: 0, ERROR: 1, MEDIUM: 2, HIGH: 3 } as const

export function exitCodeFor(level: RiskLevel): number {
  return level === "high" ? EXIT.HIGH : level === "medium" ? EXIT.MEDIUM : EXIT.LOW
}

export function resolveToken(flag?: string): string | undefined {
  return flag || process.env.FLAGRIX_GITHUB_TOKEN || process.env.GITHUB_TOKEN || undefined
}

/** JSON when asked — or automatically when stdout is piped (agents, hooks, CI). */
export function wantJson(flag?: boolean): boolean {
  return flag ?? !process.stdout.isTTY
}
