import type { GitHubRepoInfo } from "@flagrix/scanner-core"

/**
 * Parse the ways people (and agents) refer to a GitHub repo:
 *   owner/repo
 *   https://github.com/owner/repo[.git][/tree/<ref>[/path]][?query]
 *   git@github.com:owner/repo[.git]
 *
 * An explicit `ref` argument wins over a /tree/<ref> segment. An empty branch
 * tells scanner-core to resolve the default branch (then pin its head SHA).
 */
export function parseRepoTarget(input: string, ref?: string): GitHubRepoInfo {
  const raw = input.trim()
  let owner = ""
  let repo = ""
  let branch = ref ?? ""

  const ssh = raw.match(/^git@github\.com:([^/]+)\/(.+?)(?:\.git)?$/)
  const slug = raw.match(/^([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?$/)

  if (ssh) {
    owner = ssh[1]!
    repo = ssh[2]!
  } else if (slug) {
    owner = slug[1]!
    repo = slug[2]!
  } else {
    let url: URL
    try {
      url = new URL(raw.includes("://") ? raw : `https://${raw}`)
    } catch {
      throw new Error(`Not a GitHub repository reference: "${input}"`)
    }
    if (url.hostname !== "github.com" && url.hostname !== "www.github.com") {
      throw new Error(`Only github.com repositories are supported (got ${url.hostname})`)
    }
    const parts = url.pathname.split("/").filter(Boolean)
    if (parts.length < 2) {
      throw new Error(`URL is missing owner/repo: "${input}"`)
    }
    owner = parts[0]!
    repo = parts[1]!.replace(/\.git$/, "")
    if (!ref && parts[2] === "tree" && parts[3]) {
      branch = decodeURIComponent(parts[3])
    }
  }

  if (!owner || !repo) {
    throw new Error(`Not a GitHub repository reference: "${input}"`)
  }

  return {
    owner,
    repo,
    branch,
    url: `https://github.com/${owner}/${repo}`
  }
}
