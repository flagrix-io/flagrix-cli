import { mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { loadOsvFeed } from "../src/lib/osv-feed.js"

const FEED = {
  schemaVersion: 1,
  updated: "2026-10-21T05:30:04Z",
  npm: { all: ["evil-pkg"], versions: { fsevents: [">=1.0.0 <1.2.11"] } },
  pypi: { all: ["foo-bar"], versions: {} }
}

let cacheDir: string

beforeEach(() => {
  cacheDir = mkdtempSync(join(tmpdir(), "flagrix-osv-"))
  process.env.FLAGRIX_CACHE_DIR = cacheDir
})

afterEach(() => {
  vi.restoreAllMocks()
  delete process.env.FLAGRIX_CACHE_DIR
  delete process.env.FLAGRIX_OSV_FEED
})

const serve = (handler: (init?: RequestInit) => Response) => {
  const fetchMock = vi.fn(async (_input: unknown, init?: RequestInit) => handler(init))
  global.fetch = fetchMock as unknown as typeof fetch
  return fetchMock
}

describe("loadOsvFeed", () => {
  it("fetches the feed and caches it with its ETag", async () => {
    serve(() => new Response(JSON.stringify(FEED), { status: 200, headers: { etag: '"abc"' } }))
    expect(await loadOsvFeed()).toEqual(FEED)
    const cache = JSON.parse(readFileSync(join(cacheDir, "flagrix", "osv-malicious.json"), "utf8"))
    expect(cache.etag).toBe('"abc"')
  })

  it("serves a fresh cache without a request", async () => {
    serve(() => new Response(JSON.stringify(FEED), { status: 200 }))
    await loadOsvFeed()
    const fetchMock = serve(() => { throw new Error("should not fetch") })
    expect(await loadOsvFeed()).toEqual(FEED)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("revalidates a stale cache with If-None-Match and keeps it on 304", async () => {
    serve(() => new Response(JSON.stringify(FEED), { status: 200, headers: { etag: '"abc"' } }))
    await loadOsvFeed()
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7 * 60 * 60 * 1000)
    const fetchMock = serve(() => new Response(null, { status: 304 }))
    expect(await loadOsvFeed()).toEqual(FEED)
    const headers = fetchMock.mock.calls[0]![1]!.headers as Record<string, string>
    expect(headers["If-None-Match"]).toBe('"abc"')
  })

  it("falls back to the stale cache offline, and to nothing without one", async () => {
    serve(() => { throw new Error("offline") })
    expect(await loadOsvFeed()).toBeUndefined()
    serve(() => new Response(JSON.stringify(FEED), { status: 200 }))
    await loadOsvFeed()
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7 * 60 * 60 * 1000)
    serve(() => { throw new Error("offline") })
    expect(await loadOsvFeed()).toEqual(FEED)
  })

  it("rejects malformed data and honours FLAGRIX_OSV_FEED=0", async () => {
    serve(() => new Response(JSON.stringify({ npm: [] }), { status: 200 }))
    expect(await loadOsvFeed()).toBeUndefined()
    process.env.FLAGRIX_OSV_FEED = "0"
    const fetchMock = serve(() => new Response(JSON.stringify(FEED), { status: 200 }))
    expect(await loadOsvFeed()).toBeUndefined()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
