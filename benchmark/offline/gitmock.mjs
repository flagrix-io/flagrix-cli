// Preload for flagrix-cli/benchmark/run.mjs: serve the GitHub REST calls the
// scanner makes from local shallow mirrors (bench/git/<owner>_<repo>), so the
// pinned reference corpus runs without a GitHub token. GraphQL prefetch is
// answered 503 so run.mjs falls back to the (mocked) REST contents path.
// npm download lookups return 1M/week (container cannot reach api.npmjs.org).
import { execFileSync } from "node:child_process"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { gzipSync } from "node:zlib"

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
  if ((r = rest.match(/^tarball\/([0-9a-f]{40})$/i))) {
    const archive = tarball(dir, m[2], r[1])
    if (!archive) return json({ message: "mock: tarball unavailable" }, 404)
    return new Response(archive, {
      status: 200,
      headers: { "content-type": "application/x-gzip", "content-length": String(archive.length) },
    })
  }
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

// ── tarball ─────────────────────────────────────────────────────────────────
// `GET /repos/{owner}/{repo}/tarball/{sha}` as scanner-core >= 0.8 asks for
// it, synthesised from the mirror. Without this the request fell through to
// the catch-all 404, so the scan fell back to the per-file path and the
// corpus measured a reader the release no longer uses — green gates for code
// nobody ran. The mirror already holds every blob any scanner variant could
// select (mirror.py fetches all of them, uncapped), so the archive carries
// the same bytes the real one would for every file the scan can want.
//
// Two differences from GitHub's archive, both harmless here: files the mirror
// never fetched (images, binaries — never selected) are absent, and the
// tree sizes it records cover only the blobs it holds, so the engine's
// tree-byte gate sees a smaller repo than the live one would. A sample big
// enough for that gate to decide the matter would have to be measured
// against the API.
const TAR_BLOCK = 512
const tarballs = new Map()

/** NUL-terminated, NUL-padded header field. */
function field(text, length) {
  const out = Buffer.alloc(length)
  out.write(text, "utf8") // never called with more than length - 1 bytes
  return out
}

/** `0000644\0`-style octal field. */
function octal(value, length) {
  return field(value.toString(8).padStart(length - 1, "0"), length)
}

function header(name, size, typeFlag) {
  const block = Buffer.alloc(TAR_BLOCK)
  field(name, 100).copy(block, 0)
  octal(0o644, 8).copy(block, 100)
  octal(0, 8).copy(block, 108)
  octal(0, 8).copy(block, 116)
  octal(size, 12).copy(block, 124)
  octal(0, 12).copy(block, 136)
  block.write("        ", 148, "ascii") // checksum computed over spaces
  block.write(typeFlag, 156, "ascii")
  block.write("ustar\0", 257, "ascii")
  block.write("00", 263, "ascii")
  let sum = 0
  for (const byte of block) sum += byte
  field(sum.toString(8).padStart(6, "0") + "\0 ", 8).copy(block, 148)
  return block
}

/** `<len> path=<name>\n`, where len counts its own digits. */
function paxRecord(name) {
  const tail = ` path=${name}\n`
  let len = tail.length + 1
  while (String(len).length + tail.length !== len) len = String(len).length + tail.length
  return Buffer.from(String(len) + tail, "utf8")
}

function padding(size) {
  return Buffer.alloc((TAR_BLOCK - (size % TAR_BLOCK)) % TAR_BLOCK)
}

/**
 * One entry, as `git archive` writes it: a pax extended header carrying the
 * path when it does not fit the 100-byte name field, then the file itself.
 * The reader takes the path from the record, so the 'x' entry's own name and
 * the truncated name on the entry that follows it are both ignored.
 */
function entry(name, body) {
  const blocks = []
  const long = Buffer.byteLength(name) >= 100
  if (long) {
    const record = paxRecord(name)
    blocks.push(header("PaxHeaders/path", record.length, "x"), record, padding(record.length))
  }
  const short = long ? "truncated-name" : name
  blocks.push(header(short, body.length, "0"), body, padding(body.length))
  return blocks
}

/** Every blob the mirror holds, keyed by path, in one `cat-file --batch`. */
function readBlobs(dir, entries) {
  const blobs = entries.filter((e) => e.type === "blob" && e.size !== undefined)
  if (blobs.length === 0) return []
  const out = execFileSync("git", ["-C", dir, "cat-file", "--batch"], {
    input: blobs.map((e) => e.sha).join("\n") + "\n",
    maxBuffer: 1 << 30,
    env: { ...process.env, GIT_NO_LAZY_FETCH: "1" },
    stdio: ["pipe", "pipe", "ignore"],
  })
  const files = []
  let at = 0
  for (const blob of blobs) {
    const eol = out.indexOf(0x0a, at)
    if (eol === -1) break
    const parts = out.toString("ascii", at, eol).split(" ")
    at = eol + 1
    if (parts[1] !== "blob") continue // "missing": not in this mirror
    const size = Number(parts[2])
    files.push([blob.path, out.subarray(at, at + size)])
    at += size + 1 // the batch writes a newline after each body
  }
  return files
}

function tarball(dir, repo, sha) {
  const key = `${dir}:${sha}`
  if (tarballs.has(key)) return tarballs.get(key)
  let archive = null
  try {
    const tree = JSON.parse(readFileSync(join(dir, "tree.json"), "utf8"))
    // `git archive` wraps the tree in one `<repo>-<sha>/` directory, which the
    // reader strips; paths must match the tree's underneath it.
    const root = `${repo}-${sha.slice(0, 7)}`
    const blocks = []
    for (const [path, body] of readBlobs(dir, tree.tree)) {
      blocks.push(...entry(`${root}/${path}`, body))
    }
    blocks.push(Buffer.alloc(TAR_BLOCK * 2)) // end of archive
    archive = gzipSync(Buffer.concat(blocks), { level: 1 })
  } catch (error) {
    console.error(`gitmock: could not build a tarball for ${repo} (${error.message})`)
  }
  tarballs.set(key, archive)
  return archive
}
