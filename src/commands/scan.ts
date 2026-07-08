import { scanGitHubRepo } from "@flagrix/scanner-core"

import { parseRepoTarget } from "../lib/github-url.js"
import { describeSource, loadSignatures } from "../lib/signatures.js"
import { renderRepoResult } from "../lib/render.js"
import { EXIT, exitCodeFor, resolveToken, wantJson } from "./shared.js"

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

    const result = await scanGitHubRepo(repo, {
      signatures: loaded.signatures,
      githubToken: resolveToken(options.token)
    })

    if (wantJson(options.json)) {
      console.log(JSON.stringify(result, null, 2))
    } else {
      console.log(renderRepoResult(result))
    }
    return exitCodeFor(result.riskLevel)
  } catch (error) {
    console.error(`flagrix: scan failed — ${(error as Error).message}`)
    return EXIT.ERROR
  }
}
