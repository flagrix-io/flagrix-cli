import { mkdir, readFile, writeFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

import type { SignatureDatabase } from "@flagrix/scanner-core"

/** Public signature source — same URL the browser extension updates from. */
const DEFAULT_SIGNATURES_URL =
  "https://raw.githubusercontent.com/flagrix-io/flagrix-detection-rules/main/signatures.json"

const CACHE_TTL_MS = 6 * 60 * 60 * 1000 // match the extension's refresh interval

// Bundled dist/cli.js sits one level below the package root; the source file
// (dev, tests) sits two levels below — probe both.
const SNAPSHOT_CANDIDATES = ["../assets", "../../assets"].map((dir) =>
  fileURLToPath(new URL(`${dir}/signatures-snapshot.json`, import.meta.url))
)

interface CacheFile {
  fetchedAt: string
  data: unknown
}

export type SignatureSource = "remote" | "cache" | "stale-cache" | "bundled-snapshot"

export interface LoadedSignatures {
  signatures: SignatureDatabase
  /** Where they came from — surfaced on stderr so scans are auditable. */
  source: SignatureSource
  /**
   * Set when the bundled snapshot was used because the cached or downloaded
   * rules were older than it: which set was passed over, and its version.
   */
  superseded?: { source: Exclude<SignatureSource, "bundled-snapshot">; version: string }
}

function signaturesUrl(): string {
  return process.env.FLAGRIX_SIGNATURES_URL || DEFAULT_SIGNATURES_URL
}

function cacheFilePath(): string {
  const base =
    process.env.FLAGRIX_CACHE_DIR ||
    process.env.XDG_CACHE_HOME ||
    join(homedir(), ".cache")
  return join(base, "flagrix", "signatures.json")
}

/** Accept both snake_case (published signatures.json) and camelCase fields. */
function normalize(data: any): SignatureDatabase {
  return {
    version: data.version || `remote-${Date.now()}`,
    lastUpdated: new Date(),
    maliciousPackages: data.malicious_packages || data.maliciousPackages || [],
    yaraRules: data.yara_rules || data.yaraRules || [],
    knownBadHashes: data.known_bad_hashes || data.knownBadHashes || [],
    userProfileRules: data.user_profile_rules || data.userProfileRules || undefined
  }
}

async function readCache(): Promise<CacheFile | null> {
  try {
    return JSON.parse(await readFile(cacheFilePath(), "utf8")) as CacheFile
  } catch {
    return null
  }
}

async function writeCache(data: unknown): Promise<void> {
  try {
    const path = cacheFilePath()
    await mkdir(join(path, ".."), { recursive: true })
    await writeFile(path, JSON.stringify({ fetchedAt: new Date().toISOString(), data }))
  } catch {
    // A read-only or exotic environment shouldn't break scanning.
  }
}

async function fetchRemote(): Promise<unknown | null> {
  try {
    const response = await fetch(signaturesUrl())
    if (!response.ok) return null
    return await response.json()
  } catch {
    return null
  }
}

async function readSnapshot(): Promise<unknown | null> {
  for (const path of SNAPSHOT_CANDIDATES) {
    try {
      return JSON.parse(await readFile(path, "utf8"))
    } catch {
      // try the next location
    }
  }
  return null
}

/** The `version` a rules file declares, or "" when it declares none. */
function versionOf(data: any): string {
  return typeof data?.version === "string" ? data.version : ""
}

/**
 * Order two rules versions. Published versions are dates with a counter
 * (`2026.11.25.001`), so dot-separated segments compare as numbers when both
 * are digits and as strings otherwise. A missing version is older than any
 * declared one: a set that does not say what it is cannot show it is newer.
 */
export function compareRulesVersions(a: string, b: string): number {
  if (!a || !b) return a ? 1 : b ? -1 : 0
  const left = a.split(".")
  const right = b.split(".")
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i]
    const y = right[i]
    if (x === undefined) return -1
    if (y === undefined) return 1
    if (/^\d+$/.test(x) && /^\d+$/.test(y)) {
      const diff = Number(x) - Number(y)
      if (diff !== 0) return diff < 0 ? -1 : 1
    } else if (x !== y) {
      return x < y ? -1 : 1
    }
  }
  return 0
}

/**
 * The cached or downloaded rules, unless the snapshot bundled with this
 * release is newer. A ~/.cache copy written by an older CLI is younger than
 * the 6 h refresh but can predate rules this release ships with; using it
 * would scan without them.
 */
function newest(
  data: unknown,
  source: Exclude<SignatureSource, "bundled-snapshot">,
  snapshot: unknown | null
): LoadedSignatures {
  if (snapshot && compareRulesVersions(versionOf(data), versionOf(snapshot)) < 0) {
    return {
      signatures: normalize(snapshot),
      source: "bundled-snapshot",
      superseded: { source, version: versionOf(data) || "unknown" }
    }
  }
  return { signatures: normalize(data), source }
}

/**
 * Load detection signatures: fresh cache → remote (refreshing the cache) →
 * stale cache → snapshot bundled with the package at release time — and in
 * every case, the bundled snapshot instead when it is the newer set.
 *
 * A fresh cache older than the snapshot is treated as due for refresh: the
 * remote rules are usually newer still, and the snapshot covers the offline
 * case.
 */
export async function loadSignatures(): Promise<LoadedSignatures> {
  const [cached, snapshot] = await Promise.all([readCache(), readSnapshot()])
  const cacheIsCurrent =
    !snapshot || (cached !== null && compareRulesVersions(versionOf(cached.data), versionOf(snapshot)) >= 0)
  if (cached && cacheIsCurrent && Date.now() - new Date(cached.fetchedAt).getTime() < CACHE_TTL_MS) {
    return { signatures: normalize(cached.data), source: "cache" }
  }

  const remote = await fetchRemote()
  if (remote) {
    await writeCache(remote)
    return newest(remote, "remote", snapshot)
  }

  if (cached) return newest(cached.data, "stale-cache", snapshot)

  if (snapshot) return { signatures: normalize(snapshot), source: "bundled-snapshot" }
  throw new Error("no signatures available (network, cache, and bundled snapshot all failed)")
}

export function describeSource(loaded: LoadedSignatures): string | null {
  switch (loaded.source) {
    case "stale-cache":
      return `signature update unavailable — using cached signatures v${loaded.signatures.version}`
    case "bundled-snapshot":
      if (loaded.superseded) {
        const older = loaded.superseded.source === "remote" ? "downloaded" : "cached"
        return `${older} signatures v${loaded.superseded.version} are older than this release — using bundled snapshot v${loaded.signatures.version}`
      }
      return `signature source unreachable — using bundled snapshot v${loaded.signatures.version} (may be outdated)`
    default:
      return null
  }
}
