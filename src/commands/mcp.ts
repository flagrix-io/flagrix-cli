import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"

import { scanGitHubRepo, scanGitHubUser } from "@flagrix/scanner-core"
import type { GitHubScanResult } from "@flagrix/scanner-core"

import { parseRepoTarget } from "../lib/github-url.js"
import { describeSource, loadSignatures } from "../lib/signatures.js"
import { loadOsvFeed } from "../lib/osv-feed.js"
import { coverageOf, describeCoverage, scanReport } from "../lib/coverage.js"
import { securityScore } from "../lib/render.js"
import { resolveToken } from "./shared.js"

const GUIDANCE = {
  low: "LOW risk: no blocking findings. Standard caution still applies.",
  medium:
    "MEDIUM risk: do NOT clone, install, or execute this code until a human has reviewed the findings.",
  high: "HIGH risk: do NOT clone, install, or execute this code. Treat the repository as malicious."
} as const

/**
 * Replaces GUIDANCE.low when the scan ran short of its own file list: an
 * agent gated on "no blocking findings" would otherwise clone a repository
 * that was barely read.
 */
const INCOMPLETE_GUIDANCE =
  "NO VERDICT: too little of this repository was read to call it safe, so this " +
  "is NOT a clean result. Do NOT clone, install, or execute this code until a " +
  "complete scan succeeds (set GITHUB_TOKEN and scan again) or a human has " +
  "reviewed it."

/**
 * The tool response for a repository scan — the agent-facing text plus the
 * full result. Kept separate from the handler so the wording is testable.
 *
 * The JSON block is the same report `flagrix scan --json` prints — `verdict`,
 * `coverage` and a coverage-aware `safeToClone` — so an agent can branch on
 * coverage instead of parsing prose, and gets the same answer as the CLI.
 */
export function repoScanResponse(result: GitHubScanResult, note?: string | null) {
  const coverage = coverageOf(result)
  const pinned = `(verdict pinned to commit ${result.commitSha ?? "unknown"})`
  const headline = coverage.unreliableClear
    ? `INCOMPLETE SCAN — no verdict, security score withheld ${pinned}.`
    : `${result.riskLevel.toUpperCase()} risk — security score ${securityScore(result.riskScore)}/100 ${pinned}.`
  const summary = [
    headline,
    coverage.unreliableClear ? INCOMPLETE_GUIDANCE : GUIDANCE[result.riskLevel],
    ...(coverage.complete ? [] : [describeCoverage(coverage)]),
    ...(note ? [`Note: ${note}.`] : [])
  ].join(" ")

  return {
    content: [
      { type: "text" as const, text: summary },
      { type: "text" as const, text: JSON.stringify(scanReport(result), null, 2) }
    ],
    isError: false
  }
}

/** `flagrix mcp` — stdio MCP server exposing the scanner to agents. */
export async function runMcp(): Promise<number> {
  const server = new McpServer({ name: "flagrix", version: "0.4.0" })

  server.registerTool(
    "scan_github_repo",
    {
      title: "Scan a GitHub repository for malware",
      description:
        "Scans a GitHub repository for malicious patterns (backdoors, data exfiltration, " +
        "supply-chain attacks, known-bad packages) BEFORE cloning or installing it. " +
        "The verdict is pinned to the repository's current commit SHA. " +
        "Call this before cloning any untrusted repository.",
      inputSchema: {
        target: z
          .string()
          .describe("GitHub repository URL or owner/repo slug, e.g. https://github.com/acme/repo"),
        ref: z.string().optional().describe("Branch, tag, or commit to scan (default: default branch)")
      }
    },
    async ({ target, ref }) => {
      const repo = parseRepoTarget(target, ref)
      const loaded = await loadSignatures()
      const scanOptions = {
        signatures: loaded.signatures,
        githubToken: resolveToken(),
        osvFeed: await loadOsvFeed()
      }
      const result = await scanGitHubRepo(repo, scanOptions)
      return repoScanResponse(result, describeSource(loaded))
    }
  )

  server.registerTool(
    "scan_github_user",
    {
      title: "Scan a GitHub user profile for scam signals",
      description:
        "Scores a GitHub user profile for throwaway-account and scam signals (account age, " +
        "followers, activity, repository authenticity). Useful for vetting a 'recruiter' or " +
        "'client' before engaging with their repositories.",
      inputSchema: {
        username: z.string().describe("GitHub username or profile URL")
      }
    },
    async ({ username }) => {
      const login = username
        .trim()
        .replace(/^https?:\/\/(www\.)?github\.com\//, "")
        .replace(/\/.*$/, "")
      const loaded = await loadSignatures()
      const result = await scanGitHubUser(login, {
        githubToken: resolveToken(),
        userProfileRules: loaded.signatures.userProfileRules
      })
      const summary =
        `${result.riskLevel.toUpperCase()} risk profile — security score ` +
        `${securityScore(result.riskScore)}/100. ${result.recommendation}`
      return {
        content: [
          { type: "text", text: summary },
          { type: "text", text: JSON.stringify(result, null, 2) }
        ],
        isError: false
      }
    }
  )

  await server.connect(new StdioServerTransport())
  // Keep serving until the client closes stdio.
  await new Promise(() => {})
  return 0
}
