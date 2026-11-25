/**
 * Which rules set a scan runs with: cache, remote or the snapshot bundled with
 * the release, and never one older than that snapshot.
 *
 * The case that prompted this: a 0.8.3 run cached rules 2026.11.23.001, and a
 * 0.9.0 scan inside the 6 h refresh window used that copy instead of the
 * 2026.11.25.001 snapshot it shipped with, so the git-hook rules new in that
 * release never ran.
 */
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { compareRulesVersions, describeSource, loadSignatures } from "../src/lib/signatures.js"

const SNAPSHOT_VERSION = JSON.parse(
  readFileSync(join(import.meta.dirname, "..", "assets", "signatures-snapshot.json"), "utf8")
).version as string

/** What 0.8.3 left in ~/.cache on 2026-11-25 — older than any later snapshot. */
const OLDER = "2026.11.23.001"
/** Newer than any snapshot this repository will ship. */
const NEWER = "9999.12.31.001"

const rules = (version: string) => ({ version, malicious_packages: [], yara_rules: [], known_bad_hashes: [] })

let cacheDir: string
const cacheFile = () => join(cacheDir, "flagrix", "signatures.json")

function writeCache(version: string, ageMs: number) {
  mkdirSync(join(cacheDir, "flagrix"), { recursive: true })
  writeFileSync(
    cacheFile(),
    JSON.stringify({ fetchedAt: new Date(Date.now() - ageMs).toISOString(), data: rules(version) })
  )
}
const cachedVersion = () => JSON.parse(readFileSync(cacheFile(), "utf8")).data.version as string

const MINUTE = 60 * 1000
const FRESH = 10 * MINUTE
const STALE = 7 * 60 * MINUTE

/** A rules endpoint that serves `version`, or is unreachable when null. */
function remote(version: string | null) {
  const fetchMock = vi.fn(async () => {
    if (version === null) throw new Error("offline")
    return new Response(JSON.stringify(rules(version)), { status: 200 })
  })
  global.fetch = fetchMock as unknown as typeof fetch
  return fetchMock
}

beforeEach(() => {
  cacheDir = mkdtempSync(join(tmpdir(), "flagrix-sig-test-"))
  process.env.FLAGRIX_CACHE_DIR = cacheDir
})

afterEach(() => {
  vi.restoreAllMocks()
  delete process.env.FLAGRIX_CACHE_DIR
})

describe("compareRulesVersions", () => {
  it("orders date-like versions", () => {
    expect(compareRulesVersions("2026.11.23.001", "2026.11.25.001")).toBeLessThan(0)
    expect(compareRulesVersions("2026.11.25.002", "2026.11.25.001")).toBeGreaterThan(0)
    expect(compareRulesVersions("2026.12.01.001", "2026.11.30.009")).toBeGreaterThan(0)
    expect(compareRulesVersions("2026.11.25.001", "2026.11.25.001")).toBe(0)
  })

  it("compares segments as numbers, not as text", () => {
    expect(compareRulesVersions("2026.11.25.1000", "2026.11.25.999")).toBeGreaterThan(0)
  })

  it("treats a missing version as the oldest", () => {
    expect(compareRulesVersions("", "2026.11.25.001")).toBeLessThan(0)
    expect(compareRulesVersions("2026.11.25.001", "")).toBeGreaterThan(0)
  })
})

describe("loadSignatures — the bundled snapshot is the floor", () => {
  it("older fresh cache, newer snapshot, offline → bundled snapshot, and says why", async () => {
    writeCache(OLDER, FRESH)
    const fetchMock = remote(null)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("bundled-snapshot")
    expect(loaded.signatures.version).toBe(SNAPSHOT_VERSION)
    expect(loaded.superseded).toEqual({ source: "stale-cache", version: OLDER })
    // The older cache is no longer trusted for 6 h: it is refreshed at once.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(describeSource(loaded)).toBe(
      `cached signatures v${OLDER} are older than this release — using bundled snapshot v${SNAPSHOT_VERSION}`
    )
  })

  it("older fresh cache, newer remote → refreshes and uses the remote rules", async () => {
    writeCache(OLDER, FRESH)
    remote(NEWER)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("remote")
    expect(loaded.signatures.version).toBe(NEWER)
    expect(cachedVersion()).toBe(NEWER)
    expect(describeSource(loaded)).toBeNull()
  })

  it("newer fresh cache, older snapshot → cache, without a network call", async () => {
    writeCache(NEWER, FRESH)
    const fetchMock = remote(OLDER)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("cache")
    expect(loaded.signatures.version).toBe(NEWER)
    expect(loaded.superseded).toBeUndefined()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("cache of the same version as the snapshot → cache", async () => {
    writeCache(SNAPSHOT_VERSION, FRESH)
    const fetchMock = remote(null)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("cache")
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("newer stale cache, offline → stale cache", async () => {
    writeCache(NEWER, STALE)
    remote(null)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("stale-cache")
    expect(loaded.signatures.version).toBe(NEWER)
  })

  it("no cache, offline → bundled snapshot", async () => {
    remote(null)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("bundled-snapshot")
    expect(loaded.signatures.version).toBe(SNAPSHOT_VERSION)
    expect(loaded.superseded).toBeUndefined()
    expect(describeSource(loaded)).toContain("signature source unreachable")
  })

  it("no cache, newer remote → remote, and caches it", async () => {
    remote(NEWER)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("remote")
    expect(loaded.signatures.version).toBe(NEWER)
    expect(cachedVersion()).toBe(NEWER)
  })

  it("no cache, older remote → bundled snapshot", async () => {
    remote(OLDER)

    const loaded = await loadSignatures()

    expect(loaded.source).toBe("bundled-snapshot")
    expect(loaded.signatures.version).toBe(SNAPSHOT_VERSION)
    expect(loaded.superseded).toEqual({ source: "remote", version: OLDER })
    expect(describeSource(loaded)).toContain(`downloaded signatures v${OLDER} are older than this release`)
  })
})
