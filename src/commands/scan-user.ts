import { scanGitHubUser } from "@flagrix/scanner-core"

import { describeSource, loadSignatures } from "../lib/signatures.js"
import { renderUserResult } from "../lib/render.js"
import { EXIT, exitCodeFor, resolveToken, wantJson } from "./shared.js"

export interface ScanUserOptions {
  json?: boolean
  token?: string
}

/** `flagrix scan-user <login>` — returns the process exit code. */
export async function runScanUser(login: string, options: ScanUserOptions): Promise<number> {
  const username = login.trim().replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\/.*$/, "")
  if (!/^[A-Za-z0-9-]+$/.test(username)) {
    console.error(`flagrix: not a GitHub username: "${login}"`)
    return EXIT.ERROR
  }

  try {
    const loaded = await loadSignatures()
    const note = describeSource(loaded)
    if (note) console.error(`flagrix: ${note}`)

    const result = await scanGitHubUser(username, {
      githubToken: resolveToken(options.token),
      userProfileRules: loaded.signatures.userProfileRules
    })

    if (wantJson(options.json)) {
      console.log(JSON.stringify(result, null, 2))
    } else {
      console.log(renderUserResult(result))
    }
    return exitCodeFor(result.riskLevel)
  } catch (error) {
    console.error(`flagrix: profile scan failed — ${(error as Error).message}`)
    return EXIT.ERROR
  }
}
