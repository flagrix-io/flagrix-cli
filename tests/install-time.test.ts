import type { GitHubFinding, GitHubScanResult } from "@flagrix/scanner-core"
import { describe, expect, it } from "vitest"

import { repoScanResponse } from "../src/commands/mcp.js"
import { runsOnInstall, verdictIsInstallTime } from "../src/lib/install-time.js"
import { renderRepoResult } from "../src/lib/render.js"

const HOOK: GitHubFinding = {
  severity: "critical",
  type: "MALWARE_SIGNATURE",
  pattern: "SUPPLY_CHAIN_PREINSTALL_SETUP_DROPPER",
  file: "package.json",
  description: "preinstall runs setup.js, which is not in the repository"
}
const BAD_DEP: GitHubFinding = {
  severity: "high",
  type: "SUSPICIOUS_DEPENDENCY",
  package: "evil-pkg",
  description: "Known malicious package: evil-pkg"
}
const KEYLOGGER: GitHubFinding = {
  severity: "critical",
  type: "DATA_EXFILTRATION",
  file: "src/evil.js",
  description: "Keylogger Pattern"
}
const TASK: GitHubFinding = {
  severity: "critical",
  type: "MALWARE_SIGNATURE",
  pattern: "VSCODE_TASK_AUTORUN",
  file: ".vscode/tasks.json",
  description: "Task runs on folder open"
}
const ADVISORY: GitHubFinding = {
  severity: "high",
  type: "INSECURE_CONFIGURATION",
  cloneBlocking: false,
  description: "Privileged container"
}
const LOW_NOISE: GitHubFinding = {
  severity: "low",
  type: "SUSPICIOUS_URL",
  file: "README.md",
  description: "Shortened link"
}

function result(riskLevel: GitHubScanResult["riskLevel"], findings: GitHubFinding[]): GitHubScanResult {
  return {
    riskLevel,
    riskScore: riskLevel === "high" ? 0.9 : riskLevel === "medium" ? 0.4 : 0.05,
    safeToClone: riskLevel === "low",
    findings,
    disclaimer: "",
    repo: { owner: "acme", repo: "thing" },
    commitSha: "a".repeat(40),
    scanSummary: { filesScanned: 3, dependenciesChecked: 1, skippedFiles: [], complete: true }
  } as unknown as GitHubScanResult
}

describe("install-time verdicts", () => {
  it("knows which findings run on install", () => {
    expect(runsOnInstall(HOOK)).toBe(true)
    expect(runsOnInstall(BAD_DEP)).toBe(true)
    expect(runsOnInstall({ ...KEYLOGGER, type: "POSTINSTALL_SCRIPT" })).toBe(true)
    expect(runsOnInstall({ ...TASK, pattern: "SUPPLY_CHAIN_INSTALL_DOWNLOAD" })).toBe(true)
    expect(runsOnInstall(KEYLOGGER)).toBe(false)
    // Runs when an editor opens the folder: that one is about the clone.
    expect(runsOnInstall(TASK)).toBe(false)
  })

  it("an install-only verdict says install; advisories and low noise do not change that", () => {
    expect(verdictIsInstallTime(result("high", [HOOK, BAD_DEP, ADVISORY, LOW_NOISE]))).toBe(true)
  })

  it("any finding that does not run on install keeps the clone wording", () => {
    expect(verdictIsInstallTime(result("high", [HOOK, KEYLOGGER]))).toBe(false)
    expect(verdictIsInstallTime(result("high", [HOOK, TASK]))).toBe(false)
    expect(verdictIsInstallTime(result("medium", [LOW_NOISE]))).toBe(false)
    expect(verdictIsInstallTime(result("low", [HOOK]))).toBe(false)
  })

  it("the human output names the install", () => {
    const high = renderRepoResult(result("high", [HOOK]))
    expect(high).toContain("HIGH RISK — Do not install")
    expect(high).not.toContain("Do not clone")
    expect(high).toContain("not on git clone")

    expect(renderRepoResult(result("medium", [BAD_DEP]))).toContain("MEDIUM RISK — Review before installing")

    const mixed = renderRepoResult(result("high", [HOOK, KEYLOGGER]))
    expect(mixed).toContain("HIGH RISK — Do not clone")
    expect(mixed).not.toContain("not on git clone")
  })

  it("the MCP text names the install first and still says not to execute", () => {
    const text = repoScanResponse(result("high", [HOOK])).content[0]!.text
    expect(text).toContain("do NOT install this project or its dependencies")
    expect(text).toContain("Treat the repository as malicious")
    expect(text).toContain("not on git clone")

    const mixed = repoScanResponse(result("high", [HOOK, KEYLOGGER])).content[0]!.text
    expect(mixed).toContain("do NOT clone, install, or execute this code")
  })
})
