import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"

import { scanGitHubRepo, scanGitHubUser } from "@flagrix/scanner-core"

import { parseRepoTarget } from "../lib/github-url.js"
import { describeSource, loadSignatures } from "../lib/signatures.js"
import { securityScore } from "../lib/render.js"
import { resolveToken } from "./shared.js"

const GUIDANCE = {
  low: "LOW risk: no blocking findings. Standard caution still applies.",
  medium:
    "MEDIUM risk: do NOT clone, install, or execute this code until a human has reviewed the findings.",
  high: "HIGH risk: do NOT clone, install, or execute this code. Treat the repository as malicious."
} as const

/** `flagrix mcp` — stdio MCP server exposing the scanner to agents. */
export async function runMcp(): Promise<number> {
  const server = new McpServer({ name: "flagrix", version: "0.1.0" })

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
      const result = await scanGitHubRepo(repo, {
        signatures: loaded.signatures,
        githubToken: resolveToken()
      })
      const note = describeSource(loaded)
      const summary = [
        `${result.riskLevel.toUpperCase()} risk — security score ${securityScore(result.riskScore)}/100 ` +
          `(verdict pinned to commit ${result.commitSha ?? "unknown"}).`,
        GUIDANCE[result.riskLevel],
        ...(note ? [`Note: ${note}.`] : [])
      ].join(" ")
      return {
        content: [
          { type: "text", text: summary },
          { type: "text", text: JSON.stringify(result, null, 2) }
        ],
        isError: false
      }
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
