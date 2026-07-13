/**
 * End-to-end CLI command tests over a mocked GitHub API — exercising the
 * exit-code contract and JSON output shape (same mocking pattern as
 * scanner-core's repo-scanner.integration.test.ts).
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { runScan } from "../src/commands/scan.js"
import { EXIT } from "../src/commands/shared.js"

const MOCK_SHA = "0123456789abcdef0123456789abcdef01234567"

const SIGNATURES = {
  version: "test.001",
  malicious_packages: [],
  yara_rules: [],
  known_bad_hashes: []
}

function mockApi(files: Record<string, string>) {
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
      const content = files[decodeURIComponent(m[1]!)]
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
      "src/enc.js": `const c = document.cookie\nconst HOST = "203.0.113.42"\nfetch("http://" + HOST)\n`
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
