import { scanGitHubRepo } from "@flagrix/scanner-core"

import { parseRepoTarget } from "../lib/github-url.js"
import { describeSource, loadSignatures } from "../lib/signatures.js"
import { loadOsvFeed } from "../lib/osv-feed.js"
import { renderRepoResult } from "../lib/render.js"
import { scanReport } from "../lib/coverage.js"
import { EXIT, exitCodeForScan, resolveToken, wantJson } from "./shared.js"

export interface ScanOptions {
  ref?: string
  json?: boolean
  token?: string
}

/** `flagrix scan <url|owner/repo>` — returns the process exit code. */
export async function runScan(target: string, options: ScanOptions): Promise<number> {
  let repo
  try {
    repo = parseRepoTarget(target, options.ref)
  } catch (error) {
    console.error(`flagrix: ${(error as Error).message}`)
    return EXIT.ERROR
  }

  try {
    const loaded = await loadSignatures()
    const note = describeSource(loaded)
    if (note) console.error(`flagrix: ${note}`)

    // Passed as a variable: `osvFeed` is a scanner-core >= 0.5 option, and
    // older engines simply ignore it.
    const scanOptions = {
      signatures: loaded.signatures,
      githubToken: resolveToken(options.token),
      osvFeed: await loadOsvFeed()
    }
    const result = await scanGitHubRepo(repo, scanOptions)

    if (wantJson(options.json)) {
      console.log(JSON.stringify(scanReport(result), null, 2))
    } else {
      console.log(renderRepoResult(result))
    }
    return exitCodeForScan(result)
  } catch (error) {
    console.error(`flagrix: scan failed — ${(error as Error).message}`)
    return EXIT.ERROR
  }
}
