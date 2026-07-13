import { createHash } from "node:crypto"
import { execFileSync } from "node:child_process"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

import { scanGitHubRepo } from "@flagrix/scanner-core"

import { expandCorpus } from "./samples.mjs"

const benchmarkDir = dirname(fileURLToPath(import.meta.url))
const projectDir = join(benchmarkDir, "..")
const resultsDir = join(benchmarkDir, "results")
const LOCKED_CORPUS = join(benchmarkDir, "corpus.lock.json")
const SOURCE_CORPUS = join(benchmarkDir, "corpus.json")
const SHA_PATTERN = /^[0-9a-f]{40}$/i
const VERDICT_RANK = { low: 0, medium: 1, high: 2 }
const GITHUB_GRAPHQL_BATCH_SIZE = 50
const NPM_PREFETCH_CONCURRENCY = 12
// Mirror of the file-selection rules in @flagrix/scanner-core's repo-scanner
// (PRIORITY_FILES / SCANNABLE_EXTENSIONS / MAX_FILES_TO_SCAN /
// MAX_FILE_SIZE_BYTES) — used only to decide which blobs the GraphQL prefetch
// warms. Drift is safe for correctness: files the scanner wants but the
// prefetch skipped fall through to plain REST fetches; extra prefetched files
// are ignored. Re-sync when bumping the scanner-core dependency.
const GITHUB_MAX_FILES = 200
const GITHUB_MAX_FILE_SIZE = 1024 * 1024
const GITHUB_PRIORITY_FILES = [
  "package.json", "package-lock.json", "requirements.txt", "setup.py", "Pipfile",
  ".npmrc", ".yarnrc", "Makefile",
]
const GITHUB_SCANNABLE_EXTENSIONS = [
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".php",
  ".go", ".sh", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".html", ".htm",
]

function parseArgs(argv) {
  const options = { corpus: null, sample: null, resume: false, limit: null }
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]
    if (arg === "--corpus") options.corpus = argv[++index]
    else if (arg === "--sample") options.sample = argv[++index]
    else if (arg === "--resume") options.resume = true
    else if (arg === "--limit") {
      options.limit = Number.parseInt(argv[++index], 10)
      if (!Number.isInteger(options.limit) || options.limit < 1) {
        throw new Error("--limit must be a positive integer")
      }
    }
    else if (arg === "--help" || arg === "-h") options.help = true
    else throw new Error(`Unknown argument: ${arg}`)
  }
  return options
}

function help() {
  return `Flagrix benchmark

Usage:
  npm run benchmark -- [--corpus <name>] [--sample <sample-id>] [--resume] [--limit <count>]

The runner never clones repositories or executes fixture code. GitHub samples
must be pinned in benchmark/corpus.lock.json before they can run. Results are
checkpointed after every sample, so an interrupted run can safely use --resume.`
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"))
}

async function loadCorpus() {
  try {
    return { corpus: await readJson(LOCKED_CORPUS), path: LOCKED_CORPUS }
  } catch {
    const corpus = await readJson(SOURCE_CORPUS)
    const additions = await readJson(join(benchmarkDir, "github-projects.json"))
    const osv = await readJson(join(benchmarkDir, "osv-malicious-packages.json"))
    return { corpus: expandCorpus(corpus, additions, osv), path: SOURCE_CORPUS }
  }
}

function normalizeSignatures(data) {
  return {
    version: data.version,
    lastUpdated: new Date(data.lastUpdated ?? 0),
    maliciousPackages: data.maliciousPackages ?? data.malicious_packages ?? [],
    yaraRules: data.yaraRules ?? data.yara_rules ?? [],
    knownBadHashes: data.knownBadHashes ?? data.known_bad_hashes ?? [],
    userProfileRules: data.userProfileRules ?? data.user_profile_rules,
  }
}

function resolveGithubToken() {
  if (process.env.FLAGRIX_GITHUB_TOKEN) return process.env.FLAGRIX_GITHUB_TOKEN
  try {
    return execFileSync("gh", ["auth", "token"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || undefined
  } catch {
    return undefined
  }
}

function fixtureSha(sample) {
  return createHash("sha256")
    .update(JSON.stringify(sample.target.files))
    .digest("hex")
    .slice(0, 40)
}

function fixtureFetch(files, commitSha) {
  return async (input) => {
    const url = String(input)
    if (url.includes("api.npmjs.org")) {
      return new Response(JSON.stringify({ downloads: 0 }), { status: 200 })
    }
    if (/\/commits\/[^/]+$/.test(url)) {
      return new Response(JSON.stringify({ sha: commitSha }), { status: 200 })
    }
    if (url.includes("/git/trees/")) {
      return new Response(JSON.stringify({
        sha: commitSha,
        truncated: false,
        tree: Object.entries(files).map(([path, content]) => ({
          path,
          type: "blob",
          sha: createHash("sha1").update(content).digest("hex"),
          size: Buffer.byteLength(content),
          url: path,
        })),
      }), { status: 200 })
    }
    const contentMatch = url.match(/\/contents\/(.+?)\?ref=/)
    if (contentMatch) {
      const path = decodeURIComponent(contentMatch[1])
      if (!(path in files)) return new Response("{}", { status: 404 })
      return new Response(JSON.stringify({
        content: Buffer.from(files[path], "utf8").toString("base64"),
      }), { status: 200 })
    }
    return new Response("{}", { status: 404 })
  }
}

/**
 * Preserve the scanner's exact API responses while overlapping its otherwise
 * sequential content reads. The bounded pool is benchmark-only: it changes
 * elapsed time, not the pinned tree, selected files, detector inputs, or score.
 */
function githubPrefetchFetch(baseFetch) {
  const contentCache = new Map()
  const npmQueue = []
  let npmActive = 0
  let scheduled = false

  function levenshteinDistance(a, b) {
    const rows = Array.from({ length: a.length + 1 }, (_, row) =>
      Array.from({ length: b.length + 1 }, (_, column) =>
        row === 0 ? column : column === 0 ? row : 0
      )
    )
    for (let row = 1; row <= a.length; row++) {
      for (let column = 1; column <= b.length; column++) {
        rows[row][column] = a[row - 1] === b[column - 1]
          ? rows[row - 1][column - 1]
          : 1 + Math.min(rows[row - 1][column - 1], rows[row - 1][column], rows[row][column - 1])
      }
    }
    return rows[a.length][b.length]
  }

  function mayNeedNpmLookup(name) {
    if (name.startsWith("@")) return false
    const popular = [
      "lodash", "express", "react", "axios", "moment", "webpack", "babel",
      "typescript", "eslint", "prettier", "jest", "mocha", "bcrypt", "crypto", "request",
    ]
    return popular.some((candidate) =>
      name !== candidate && Math.abs(name.length - candidate.length) <= 3 &&
      levenshteinDistance(name, candidate) <= 2
    )
  }

  function pumpNpmQueue() {
    while (npmActive < NPM_PREFETCH_CONCURRENCY && npmQueue.length > 0) {
      const task = npmQueue.shift()
      npmActive++
      baseFetch(task.url, { signal: AbortSignal.timeout(5000) })
        .then(task.resolve, task.reject)
        .finally(() => {
          npmActive--
          pumpNpmQueue()
        })
    }
  }

  function scheduleNpmLookups(content) {
    try {
      const manifest = JSON.parse(content)
      const dependencies = { ...manifest.dependencies, ...manifest.devDependencies }
      for (const name of Object.keys(dependencies)) {
        if (!mayNeedNpmLookup(name)) continue
        const url = `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`
        if (contentCache.has(url)) continue
        let resolve
        let reject
        const response = new Promise((onResolve, onReject) => {
          resolve = onResolve
          reject = onReject
        })
        contentCache.set(url, response)
        npmQueue.push({ url, resolve, reject })
      }
      pumpNpmQueue()
    } catch {
      // Invalid manifests are ignored by the scanner too.
    }
  }

  function schedule(tree, owner, repo, commitSha, init) {
    const files = []
    for (const item of tree.tree ?? []) {
      if (item.type !== "blob") continue
      const eligible = GITHUB_PRIORITY_FILES.some((name) => item.path.endsWith(name)) ||
        GITHUB_SCANNABLE_EXTENSIONS.some((extension) => item.path.endsWith(extension))
      if (!eligible || (item.size !== undefined && item.size > GITHUB_MAX_FILE_SIZE)) continue
      if (files.length >= GITHUB_MAX_FILES) break
      files.push(item)
    }

    const tasks = files.map((file) => {
      const url = `https://api.github.com/repos/${owner}/${repo}/contents/${file.path}?ref=${commitSha}`
      let resolve
      let reject
      const response = new Promise((onResolve, onReject) => {
        resolve = onResolve
        reject = onReject
      })
      contentCache.set(url, response)
      return { file, url, resolve, reject }
    })

    async function fetchBatch(batch) {
      const declarations = batch.map((_, index) => `$expr${index}:String!`).join(",")
      const fields = batch.map((_, index) =>
        `b${index}:object(expression:$expr${index}){... on Blob{text isBinary isTruncated}}`
      ).join(" ")
      const variables = { owner, repo }
      batch.forEach((task, index) => {
        variables[`expr${index}`] = `${commitSha}:${task.file.path}`
      })

      try {
        const response = await baseFetch("https://api.github.com/graphql", {
          ...init,
          method: "POST",
          body: JSON.stringify({
            query: `query($owner:String!,$repo:String!,${declarations}){repository(owner:$owner,name:$repo){${fields}}}`,
            variables,
          }),
        })
        if (!response.ok) throw new Error(`GitHub GraphQL ${response.status}`)
        const payload = await response.json()
        if (payload.errors) throw new Error(payload.errors.map((error) => error.message).join("; "))
        if (process.env.FLAGRIX_BENCHMARK_DEBUG) {
          console.error(`graphql-prefetch ${owner}/${repo}: ${batch.length} blobs`)
        }

        await Promise.all(batch.map(async (task, index) => {
          const blob = payload.data?.repository?.[`b${index}`]
          try {
            if (!blob || blob.isBinary || blob.isTruncated || typeof blob.text !== "string") {
              task.resolve(await baseFetch(task.url, init))
              return
            }
            if (task.file.path.endsWith("package.json")) scheduleNpmLookups(blob.text)
            task.resolve(new Response(JSON.stringify({
              content: Buffer.from(blob.text, "utf8").toString("base64"),
            }), { status: 200 }))
          } catch (error) {
            task.reject(error)
          }
        }))
      } catch (error) {
        if (process.env.FLAGRIX_BENCHMARK_DEBUG) {
          console.error(`graphql-prefetch fallback ${owner}/${repo}: ${error instanceof Error ? error.message : error}`)
        }
        await Promise.all(batch.map(async (task) => {
          try {
            task.resolve(await baseFetch(task.url, init))
          } catch (error) {
            task.reject(error)
          }
        }))
      }
    }

    for (let offset = 0; offset < tasks.length; offset += GITHUB_GRAPHQL_BATCH_SIZE) {
      void fetchBatch(tasks.slice(offset, offset + GITHUB_GRAPHQL_BATCH_SIZE))
    }
  }

  return async (input, init) => {
    const url = String(input)
    const cached = contentCache.get(url)
    if (cached) return cached

    const response = await baseFetch(input, init)
    const treeMatch = url.match(
      /api\.github\.com\/repos\/([^/]+)\/([^/]+)\/git\/trees\/([0-9a-f]{40})\?recursive=1/i
    )
    if (!scheduled && response.ok && treeMatch) {
      scheduled = true
      const tree = await response.clone().json()
      schedule(tree, treeMatch[1], treeMatch[2], treeMatch[3], init)
    }
    return response
  }
}

function findingRule(finding) {
  return finding.pattern || finding.type
}

function evaluate(sample, result) {
  const triggered = [...new Set(result.findings.map(findingRule))]
  const expected = sample.expectedDetectionCategories ?? []
  const categoryDetected = expected.length === 0
    ? true
    : expected.every((category) =>
      result.findings.some((finding) => finding.pattern === category || finding.type === category)
    )

  const verdictPass = sample.minimumExpectedVerdict
    ? VERDICT_RANK[result.riskLevel] >= VERDICT_RANK[sample.minimumExpectedVerdict]
    : sample.maximumExpectedVerdict
      ? VERDICT_RANK[result.riskLevel] <= VERDICT_RANK[sample.maximumExpectedVerdict]
      : true

  const isReference = sample.label === "reference-clean"
  const reviewRequired = isReference && result.findings.some(
    (finding) => finding.severity === "high" || finding.severity === "critical"
  )

  return {
    categoryDetected,
    verdictPass,
    testPassed: categoryDetected && verdictPass,
    triggered,
    falsePositiveNotes: reviewRequired
      ? "Manual review required; this result is not yet classified as a false positive."
      : "",
  }
}

function flattenFinding(finding) {
  return {
    severity: finding.severity,
    confidence: finding.confidence ?? "unspecified",
    type: finding.type,
    rule: findingRule(finding),
    file: finding.file ?? "",
    line: finding.line ?? finding.evidence?.[0]?.line ?? null,
    description: finding.description,
  }
}

async function runSample(sample, signatures, token) {
  const started = Date.now()
  let result
  let immutableRef = sample.immutableRef

  if (sample.target.kind === "fixture") {
    const commitSha = fixtureSha(sample)
    const originalFetch = global.fetch
    try {
      global.fetch = fixtureFetch(sample.target.files, commitSha)
      result = await scanGitHubRepo({
        owner: "flagrix-benchmark",
        repo: sample.sampleId,
        branch: commitSha,
        url: `fixture://${sample.sampleId}`,
      }, { signatures })
    } finally {
      global.fetch = originalFetch
    }
    immutableRef = `${sample.immutableRef}:${commitSha}`
  } else {
    const ref = sample.target.ref ?? sample.immutableRef
    if (!SHA_PATTERN.test(ref ?? "")) {
      return {
        sampleId: sample.sampleId,
        corpus: sample.corpus,
        label: sample.label,
        labelSource: sample.labelSource,
        sourceUrl: sample.sourceUrl,
        immutableRef: ref ?? "",
        expectedDetectionCategories: sample.expectedDetectionCategories ?? [],
        minimumExpectedVerdict: sample.minimumExpectedVerdict ?? "",
        maximumExpectedVerdict: sample.maximumExpectedVerdict ?? "",
        status: "skipped-unpinned",
        testPassed: null,
        error: "GitHub target is not locked to a 40-character commit SHA.",
        durationMs: Date.now() - started,
      }
    }
    const [owner, repo] = sample.target.repo.split("/")
    const originalFetch = global.fetch
    try {
      global.fetch = githubPrefetchFetch(originalFetch)
      result = await scanGitHubRepo({
        owner,
        repo,
        branch: ref,
        url: `https://github.com/${sample.target.repo}`,
      }, { signatures, githubToken: token })
    } finally {
      global.fetch = originalFetch
    }
    immutableRef = result.commitSha ?? ref
  }

  const evaluation = evaluate(sample, result)
  return {
    sampleId: sample.sampleId,
    corpus: sample.corpus,
    label: sample.label,
    labelSource: sample.labelSource,
    sourceUrl: sample.sourceUrl,
    immutableRef,
    expectedDetectionCategories: sample.expectedDetectionCategories ?? [],
    minimumExpectedVerdict: sample.minimumExpectedVerdict ?? "",
    maximumExpectedVerdict: sample.maximumExpectedVerdict ?? "",
    status: "completed",
    testPassed: evaluation.testPassed,
    categoryDetected: evaluation.categoryDetected,
    verdictPass: evaluation.verdictPass,
    actualVerdict: result.riskLevel,
    actualScore: result.riskScore,
    safeToClone: result.safeToClone,
    rulesTriggered: evaluation.triggered,
    falsePositiveNotes: evaluation.falsePositiveNotes,
    findings: result.findings.map(flattenFinding),
    filesScanned: result.scanSummary.filesScanned,
    filesSkipped: result.scanSummary.skippedCount,
    treeTruncated: result.scanSummary.treeTruncated,
    durationMs: Date.now() - started,
    error: "",
  }
}

function gate(value, evaluated) {
  return evaluated ? value : null
}

function calculateMetrics(results) {
  const completed = results.filter((row) => row.status === "completed")
  const critical = completed.filter((row) => row.corpus === "critical-fixture")
  const malicious = completed.filter((row) => row.corpus === "real-malicious")
  const references = completed.filter((row) => row.label === "reference-clean")
  const criticalReferenceFindings = references.filter((row) =>
    row.findings.some((finding) => finding.severity === "critical")
  ).length
  const actionableReferenceFindings = references.filter((row) =>
    row.findings.some((finding) => finding.severity === "high" || finding.severity === "critical")
  ).length
  const highReferenceVerdicts = references.filter((row) => row.actualVerdict === "high").length

  const criticalDetected = critical.filter((row) => row.categoryDetected).length
  const maliciousDetected = malicious.filter((row) => row.categoryDetected).length
  return {
    samplesDefined: results.length,
    samplesCompleted: completed.length,
    samplesPassed: completed.filter((row) => row.testPassed).length,
    criticalFixturesDetected: criticalDetected,
    criticalFixturesTotal: critical.length,
    criticalFixtureDetectionRate: critical.length ? criticalDetected / critical.length : null,
    maliciousSamplesDetected: maliciousDetected,
    maliciousSamplesTotal: malicious.length,
    maliciousDetectionRate: malicious.length ? maliciousDetected / malicious.length : null,
    referenceSamplesTotal: references.length,
    referenceHighVerdicts: highReferenceVerdicts,
    referenceHighVerdictRate: references.length ? highReferenceVerdicts / references.length : null,
    referenceSamplesWithHighOrCriticalFindings: actionableReferenceFindings,
    referenceCriticalFindings: criticalReferenceFindings,
    gates: {
      criticalFixtures100Percent: gate(criticalDetected === critical.length, critical.length > 0),
      maliciousDetectionAtLeast90Percent: gate(
        maliciousDetected / malicious.length >= 0.9,
        malicious.length > 0
      ),
      zeroCriticalReferenceFindings: gate(criticalReferenceFindings === 0, references.length > 0),
      referenceHighVerdictsAtMost5Percent: gate(
        highReferenceVerdicts / references.length <= 0.05,
        references.length > 0
      ),
    },
  }
}

function csvCell(value) {
  const text = Array.isArray(value) ? value.join(" | ") : String(value ?? "")
  return `"${text.replaceAll('"', '""')}"`
}

function toCsv(results, metadata) {
  const headers = [
    "sample_id", "corpus", "label", "label_source", "source_url", "immutable_ref",
    "expected_detection_category", "minimum_expected_verdict", "maximum_expected_verdict",
    "status", "test_passed", "category_detected", "verdict_pass", "actual_verdict",
    "actual_score", "safe_to_clone", "rules_triggered", "finding_severities",
    "finding_confidences", "false_positive_notes", "files_scanned", "files_skipped",
    "tree_truncated", "duration_ms", "engine_version", "engine_commit_sha",
    "detection_rules_version", "error",
  ]
  const rows = results.map((row) => [
    row.sampleId, row.corpus, row.label, row.labelSource, row.sourceUrl, row.immutableRef,
    row.expectedDetectionCategories, row.minimumExpectedVerdict, row.maximumExpectedVerdict,
    row.status, row.testPassed, row.categoryDetected, row.verdictPass, row.actualVerdict,
    row.actualScore, row.safeToClone, row.rulesTriggered ?? [],
    row.findings?.map((finding) => finding.severity) ?? [],
    row.findings?.map((finding) => finding.confidence) ?? [], row.falsePositiveNotes,
    row.filesScanned, row.filesSkipped, row.treeTruncated, row.durationMs,
    metadata.engineVersion, metadata.engineCommitSha, metadata.rulesVersion,
    row.error,
  ])
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n") + "\n"
}

async function writeCheckpoint(results, metadata) {
  const report = { metadata, metrics: calculateMetrics(results), results }
  await Promise.all([
    writeFile(join(resultsDir, "latest.json"), JSON.stringify(report, null, 2) + "\n"),
    writeFile(join(resultsDir, "latest.csv"), toCsv(results, metadata)),
  ])
  return report
}

async function main() {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    console.log(help())
    return
  }

  // The engine is whatever `npm install` resolved for @flagrix/scanner-core —
  // the same import the runner executes. Metadata must describe that artifact,
  // not a sibling checkout that may be dirty or on a different commit.
  const [{ corpus, path: corpusPath }, rawSignatures, corePackage, cliPackage] = await Promise.all([
    loadCorpus(),
    readJson(join(projectDir, "assets", "signatures-snapshot.json")),
    readJson(join(projectDir, "node_modules", "@flagrix/scanner-core", "package.json")),
    readJson(join(projectDir, "package.json")),
  ])
  const signatures = normalizeSignatures(rawSignatures)
  const metadata = {
    benchmarkVersion: corpus.benchmarkVersion,
    runAt: new Date().toISOString(),
    corpusPath,
    cliVersion: cliPackage.version,
    engineVersion: corePackage.version,
    // npm strips gitHead from some publishes; null means "as published on the
    // registry at engineVersion", which is already immutable.
    engineCommitSha: corePackage.gitHead ?? null,
    engineDirty: false,
    rulesVersion: signatures.version,
  }

  let samples = corpus.samples
  if (options.corpus) samples = samples.filter((sample) => sample.corpus === options.corpus)
  if (options.sample) samples = samples.filter((sample) => sample.sampleId === options.sample)
  if (samples.length === 0) throw new Error("No benchmark samples matched the selection.")

  await mkdir(resultsDir, { recursive: true })
  let previous = new Map()
  if (options.resume) {
    try {
      const prior = await readJson(join(resultsDir, "latest.json"))
      previous = new Map(prior.results.map((row) => [row.sampleId, row]))
    } catch {
      // No prior run to resume.
    }
  }

  const results = []
  const githubToken = resolveGithubToken()
  let newlyAttempted = 0
  for (const sample of samples) {
    if (previous.get(sample.sampleId)?.status === "completed") {
      results.push(previous.get(sample.sampleId))
      console.error(`resume ${sample.sampleId}`)
      continue
    }
    if (options.limit !== null && newlyAttempted >= options.limit) break
    newlyAttempted++
    try {
      const row = await runSample(sample, signatures, githubToken)
      results.push(row)
      console.error(`${row.status} ${sample.sampleId}${row.actualVerdict ? ` → ${row.actualVerdict}` : ""}`)
    } catch (error) {
      results.push({
        sampleId: sample.sampleId,
        corpus: sample.corpus,
        label: sample.label,
        labelSource: sample.labelSource,
        sourceUrl: sample.sourceUrl,
        immutableRef: sample.immutableRef ?? sample.target.ref ?? "",
        expectedDetectionCategories: sample.expectedDetectionCategories ?? [],
        minimumExpectedVerdict: sample.minimumExpectedVerdict ?? "",
        maximumExpectedVerdict: sample.maximumExpectedVerdict ?? "",
        status: "error",
        testPassed: false,
        error: error instanceof Error ? error.message : String(error),
      })
      console.error(`error ${sample.sampleId}: ${error instanceof Error ? error.message : error}`)
      await writeCheckpoint(results, metadata)
      if (/rate limit/i.test(error instanceof Error ? error.message : String(error))) break
      continue
    }
    await writeCheckpoint(results, metadata)
  }

  const report = await writeCheckpoint(results, metadata)
  const timestamp = metadata.runAt.replaceAll(":", "-").replaceAll(".", "-")
  await writeFile(join(resultsDir, `${timestamp}.json`), JSON.stringify(report, null, 2) + "\n")
  console.log(JSON.stringify({ metadata, metrics: report.metrics }, null, 2))
}

main().catch((error) => {
  console.error(`benchmark: ${error instanceof Error ? error.message : error}`)
  process.exitCode = 1
})
