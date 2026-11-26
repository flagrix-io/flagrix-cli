import { scanGitHubRepo } from "@flagrix/scanner-core"

import { parseRepoTarget } from "../lib/github-url.js"
import { describeSource, loadSignatures } from "../lib/signatures.js"
import { loadOsvFeed } from "../lib/osv-feed.js"
import { renderRepoResult } from "../lib/render.js"
import { scanReport } from "../lib/coverage.js"
import {
  EXIT,
  READ_WHOLE_SNAPSHOT_BY_DEFAULT,
  exitCodeForScan,
  resolveToken,
  wantJson
} from "./shared.js"

export interface ScanOptions {
  ref?: string
  json?: boolean
  token?: string
  /** Read the whole commit in one request; unset takes the default. */
  tarball?: boolean
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
      osvFeed: await loadOsvFeed(),
      // A scanner-core >= 0.8 option; older engines ignore it and report no
      // read mode, which the coverage report calls "unknown".
      tarball: options.tarball ?? READ_WHOLE_SNAPSHOT_BY_DEFAULT
    }
    const result = await scanGitHubRepo(repo, scanOptions)

    if (wantJson(options.json)) {
      console.log(JSON.stringify(scanReport(result, loaded.signatures.version), null, 2))
    } else {
      console.log(renderRepoResult(result, loaded.signatures.version))
    }
    return exitCodeForScan(result)
  } catch (error) {
    console.error(`flagrix: scan failed — ${(error as Error).message}`)
    return EXIT.ERROR
  }
}
