import type { GitHubFinding, GitHubScanResult } from "@flagrix/scanner-core"

/**
 * Whether a verdict is about installing the project rather than cloning it.
 *
 * An install hook runs on `npm install`, and a malicious or typosquatted
 * dependency arrives with it; neither runs on `git clone`. Telling someone
 * "do not clone" about a repository whose only problem is its preinstall
 * script names the wrong step. "Do not clone" stays for everything else,
 * including what runs the moment an editor or agent opens the folder (VS Code
 * folderOpen tasks, devcontainer commands, agent hooks).
 *
 * Mirrored in flagrix-extension src/lib/install-time.ts; keep the two in step.
 */

const INSTALL_TIME_TYPES: ReadonlySet<GitHubFinding["type"]> = new Set([
  "POSTINSTALL_SCRIPT",
  "SUSPICIOUS_DEPENDENCY",
  "TYPOSQUAT_PACKAGE"
])

/** Detection rules that match package.json install hooks. */
const INSTALL_HOOK_RULE = /^SUPPLY_CHAIN_(?:PRE|POST)?INSTALL_/

const VERDICT_SEVERITIES: ReadonlySet<GitHubFinding["severity"]> = new Set(["critical", "high", "medium"])

export function runsOnInstall(finding: GitHubFinding): boolean {
  return INSTALL_TIME_TYPES.has(finding.type) || INSTALL_HOOK_RULE.test(finding.pattern ?? "")
}

/**
 * True when a medium or high verdict rests only on install-time findings:
 * every clone-blocking finding of medium severity or above runs on install.
 */
export function verdictIsInstallTime(result: Pick<GitHubScanResult, "riskLevel" | "findings">): boolean {
  if (result.riskLevel === "low") return false
  const drivers = result.findings.filter(
    (finding) => finding.cloneBlocking !== false && VERDICT_SEVERITIES.has(finding.severity)
  )
  return drivers.length > 0 && drivers.every(runsOnInstall)
}

export const INSTALL_TIME_NOTE =
  "The findings behind this verdict run when the project is installed (an install hook or a dependency), not on git clone."
