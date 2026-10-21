import { mkdir, readFile, writeFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"

/**
 * OSV malicious-package feed (osv-malicious.json from flagrix-detection-rules):
 * every npm/PyPI package the OpenSSF malicious-packages project has confirmed
 * malicious. scanner-core >= 0.5 matches it locally against a repo's declared
 * dependencies. It is optional: when it can't be loaded, scans fall back to
 * the curated list in signatures.json.
 */
export interface OsvFeed {
  schemaVersion: number
  updated?: string
  npm: { all: string[]; versions: Record<string, string[]> }
  pypi: { all: string[]; versions: Record<string, string[]> }
}

const DEFAULT_OSV_FEED_URL =
  "https://raw.githubusercontent.com/flagrix-io/flagrix-detection-rules/main/osv-malicious.json"

const CACHE_TTL_MS = 6 * 60 * 60 * 1000 // same cadence as signatures

interface CacheFile {
  fetchedAt: string
  etag?: string
  data: unknown
}

function feedUrl(): string {
  return process.env.FLAGRIX_OSV_FEED_URL || DEFAULT_OSV_FEED_URL
}

function cacheFilePath(): string {
  const base =
    process.env.FLAGRIX_CACHE_DIR ||
    process.env.XDG_CACHE_HOME ||
    join(homedir(), ".cache")
  return join(base, "flagrix", "osv-malicious.json")
}

function isFeed(data: any): data is OsvFeed {
  return (
    data?.schemaVersion === 1 &&
    Array.isArray(data.npm?.all) &&
    typeof data.npm?.versions === "object" &&
    Array.isArray(data.pypi?.all) &&
    typeof data.pypi?.versions === "object"
  )
}

async function readCache(): Promise<CacheFile | null> {
  try {
    return JSON.parse(await readFile(cacheFilePath(), "utf8")) as CacheFile
  } catch {
    return null
  }
}

async function writeCache(entry: CacheFile): Promise<void> {
  try {
    const path = cacheFilePath()
    await mkdir(join(path, ".."), { recursive: true })
    await writeFile(path, JSON.stringify(entry))
  } catch {
    // A read-only or exotic environment shouldn't break scanning.
  }
}

/**
 * Fresh cache → remote (conditional on the cached ETag, so an unchanged
 * 5.6 MB feed isn't downloaded again) → stale cache → none.
 * FLAGRIX_OSV_FEED=0 turns it off.
 */
export async function loadOsvFeed(): Promise<OsvFeed | undefined> {
  if (process.env.FLAGRIX_OSV_FEED === "0") return undefined

  const cached = await readCache()
  const cachedFeed = cached && isFeed(cached.data) ? cached.data : undefined
  if (cachedFeed && Date.now() - new Date(cached!.fetchedAt).getTime() < CACHE_TTL_MS) {
    return cachedFeed
  }

  try {
    const response = await fetch(feedUrl(), {
      headers: cachedFeed && cached?.etag ? { "If-None-Match": cached.etag } : {}
    })
    if (response.status === 304 && cachedFeed) {
      await writeCache({ ...cached!, fetchedAt: new Date().toISOString() })
      return cachedFeed
    }
    if (response.ok) {
      const data: unknown = await response.json()
      if (isFeed(data)) {
        await writeCache({
          fetchedAt: new Date().toISOString(),
          etag: response.headers.get("etag") ?? undefined,
          data
        })
        return data
      }
    }
  } catch {
    // Offline: fall through to the stale cache.
  }
  return cachedFeed
}
