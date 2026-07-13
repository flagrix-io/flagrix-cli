import { createHash } from "node:crypto"
import { execFileSync } from "node:child_process"
import { readFile, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

import { expandCorpus } from "./samples.mjs"

const benchmarkDir = dirname(fileURLToPath(import.meta.url))
const sourcePath = join(benchmarkDir, "corpus.json")
const outputPath = join(benchmarkDir, "corpus.lock.json")
const refresh = process.argv.includes("--refresh")
function resolveGithubToken() {
  if (process.env.FLAGRIX_GITHUB_TOKEN) return process.env.FLAGRIX_GITHUB_TOKEN
  try {
    return execFileSync("gh", ["auth", "token"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || undefined
  } catch {
    return undefined
  }
}

const token = resolveGithubToken()

function headers() {
  const value = {
    Accept: "application/vnd.github+json",
    "User-Agent": "Flagrix-Benchmark",
    "X-GitHub-Api-Version": "2022-11-28",
  }
  if (token) value.Authorization = `Bearer ${token}`
  return value
}

async function githubJson(url) {
  const response = await fetch(url, { headers: headers() })
  if (!response.ok) {
    const remaining = response.headers.get("x-ratelimit-remaining")
    const reset = response.headers.get("x-ratelimit-reset")
    throw new Error(
      `GitHub ${response.status} for ${url} (remaining=${remaining ?? "?"}, reset=${reset ?? "?"})`
    )
  }
  return response.json()
}

async function resolveHead(repo) {
  const metadata = await githubJson(`https://api.github.com/repos/${repo}`)
  const commit = await githubJson(
    `https://api.github.com/repos/${repo}/commits/${encodeURIComponent(metadata.default_branch)}`
  )
  if (!/^[0-9a-f]{40}$/i.test(commit.sha)) throw new Error(`Invalid commit SHA for ${repo}`)
  return { sha: commit.sha, defaultBranch: metadata.default_branch }
}

async function main() {
  let previousByRepo = new Map()
  if (!refresh) {
    try {
      const previous = JSON.parse(await readFile(outputPath, "utf8"))
      previousByRepo = new Map(previous.samples
        .filter((sample) => sample.target.kind === "github")
        .map((sample) => [sample.target.repo, sample]))
    } catch {
      // No lock exists yet.
    }
  }
  const sourceText = await readFile(sourcePath, "utf8")
  const corpus = JSON.parse(sourceText)
  const additionsText = await readFile(join(benchmarkDir, "github-projects.json"), "utf8")
  const additions = JSON.parse(additionsText)
  const osvText = await readFile(join(benchmarkDir, "osv-malicious-packages.json"), "utf8")
  const osv = JSON.parse(osvText)
  expandCorpus(corpus, additions, osv)
  for (const sample of corpus.samples) {
    if (sample.target.kind !== "github") continue
    if (/^[0-9a-f]{40}$/i.test(sample.target.ref ?? "")) continue
    const previous = previousByRepo.get(sample.target.repo)
    if (/^[0-9a-f]{40}$/i.test(previous?.target.ref ?? "")) {
      sample.target.ref = previous.target.ref
      sample.immutableRef = previous.immutableRef
      sample.defaultBranchAtPin = previous.defaultBranchAtPin
      console.error(`preserved ${sample.target.repo}@${sample.target.ref.slice(0, 12)}`)
      continue
    }
    const pinned = await resolveHead(sample.target.repo)
    sample.target.ref = pinned.sha
    sample.immutableRef = pinned.sha
    sample.defaultBranchAtPin = pinned.defaultBranch
    console.error(`pinned ${sample.target.repo}@${pinned.sha.slice(0, 12)}`)
  }
  corpus.pinnedAt = new Date().toISOString()
  corpus.sourceCorpusSha256 = createHash("sha256")
    .update(sourceText)
    .update(additionsText)
    .update(osvText)
    .digest("hex")
  await writeFile(outputPath, JSON.stringify(corpus, null, 2) + "\n")
  console.log(outputPath)
}

main().catch((error) => {
  console.error(`benchmark:pin: ${error instanceof Error ? error.message : error}`)
  process.exitCode = 1
})
