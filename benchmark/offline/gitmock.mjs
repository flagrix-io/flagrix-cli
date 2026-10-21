// Preload for flagrix-cli/benchmark/run.mjs: serve the GitHub REST calls the
// scanner makes from local shallow mirrors (bench/git/<owner>_<repo>), so the
// pinned reference corpus runs without a GitHub token. GraphQL prefetch is
// answered 503 so run.mjs falls back to the (mocked) REST contents path.
// npm download lookups return 1M/week (container cannot reach api.npmjs.org).
import { execFileSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "git")
const realFetch = globalThis.fetch
const warned = new Set()
const json = (body, status = 200) => new Response(JSON.stringify(body), { status })

globalThis.fetch = async (input, init) => {
  const url = String(input)
  if (url.startsWith("https://api.github.com/graphql")) return json({ message: "mock: no graphql" }, 503)
  if (url.includes("api.npmjs.org/downloads/")) return json({ downloads: 1_000_000 })
  const m = url.match(/^https:\/\/api\.github\.com\/repos\/([^/]+)\/([^/]+)\/(.*)$/)
  if (!m) return realFetch(input, init)
  const dir = join(ROOT, `${m[1]}_${m[2]}`)
  if (!existsSync(join(dir, "tree.json"))) return json({ message: `mock: no mirror for ${m[1]}/${m[2]}` }, 404)
  const rest = m[3]
  let r
  if ((r = rest.match(/^commits\/([0-9a-f]{40})$/i))) return json({ sha: r[1] })
  if (rest.startsWith("git/trees/")) return new Response(readFileSync(join(dir, "tree.json")), { status: 200 })
  if ((r = rest.match(/^contents\/(.+?)\?ref=([0-9a-f]{40})$/i))) {
    const path = decodeURIComponent(r[1])
    try {
      // Offline means offline: a blob missing from the blobless mirror must
      // not trigger a lazy fetch from github.com (that can hang for minutes).
      const blob = execFileSync("git", ["-C", dir, "cat-file", "blob", `${r[2]}:${path}`], {
        maxBuffer: 64 << 20,
        env: { ...process.env, GIT_NO_LAZY_FETCH: "1" },
        stdio: ["ignore", "pipe", "ignore"],
      })
      return json({ content: blob.toString("base64") })
    } catch {
      if (!warned.has(`${dir}:${path}`)) {
        warned.add(`${dir}:${path}`)
        console.error(`gitmock: ${m[1]}/${m[2]}:${path} is not in the mirror (re-run mirror.py)`)
      }
      return json({ message: "Not Found" }, 404)
    }
  }
  return json({ message: `mock: unhandled ${rest}` }, 404)
}
