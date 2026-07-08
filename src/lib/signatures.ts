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

export interface LoadedSignatures {
  signatures: SignatureDatabase
  /** Where they came from — surfaced on stderr so scans are auditable. */
  source: "remote" | "cache" | "stale-cache" | "bundled-snapshot"
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

/**
 * Load detection signatures: fresh cache → remote (refreshing the cache) →
 * stale cache → snapshot bundled with the package at release time.
 */
export async function loadSignatures(): Promise<LoadedSignatures> {
  const cached = await readCache()
  if (cached && Date.now() - new Date(cached.fetchedAt).getTime() < CACHE_TTL_MS) {
    return { signatures: normalize(cached.data), source: "cache" }
  }

  const remote = await fetchRemote()
  if (remote) {
    await writeCache(remote)
    return { signatures: normalize(remote), source: "remote" }
  }

  if (cached) {
    return { signatures: normalize(cached.data), source: "stale-cache" }
  }

  for (const path of SNAPSHOT_CANDIDATES) {
    try {
      const snapshot = JSON.parse(await readFile(path, "utf8"))
      return { signatures: normalize(snapshot), source: "bundled-snapshot" }
    } catch {
      // try the next location
    }
  }
  throw new Error("no signatures available (network, cache, and bundled snapshot all failed)")
}

export function describeSource(loaded: LoadedSignatures): string | null {
  switch (loaded.source) {
    case "stale-cache":
      return `signature update unavailable — using cached signatures v${loaded.signatures.version}`
    case "bundled-snapshot":
      return `signature source unreachable — using bundled snapshot v${loaded.signatures.version} (may be outdated)`
    default:
      return null
  }
}
