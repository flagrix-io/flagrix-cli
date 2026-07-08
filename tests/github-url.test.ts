import { describe, expect, it } from "vitest"

import { parseRepoTarget } from "../src/lib/github-url.js"

describe("parseRepoTarget", () => {
  it("parses owner/repo slugs", () => {
    expect(parseRepoTarget("acme/repo")).toMatchObject({ owner: "acme", repo: "repo", branch: "" })
  })

  it("parses https URLs, with and without .git", () => {
    expect(parseRepoTarget("https://github.com/acme/repo")).toMatchObject({ owner: "acme", repo: "repo" })
    expect(parseRepoTarget("https://github.com/acme/repo.git")).toMatchObject({ owner: "acme", repo: "repo" })
  })

  it("takes the ref from /tree/<ref> URLs", () => {
    expect(parseRepoTarget("https://github.com/acme/repo/tree/dev/src")).toMatchObject({
      owner: "acme",
      repo: "repo",
      branch: "dev"
    })
  })

  it("prefers an explicit ref over the URL's", () => {
    expect(parseRepoTarget("https://github.com/acme/repo/tree/dev", "main").branch).toBe("main")
  })

  it("parses ssh remotes", () => {
    expect(parseRepoTarget("git@github.com:acme/repo.git")).toMatchObject({ owner: "acme", repo: "repo" })
  })

  it("parses bare github.com URLs without scheme", () => {
    expect(parseRepoTarget("github.com/acme/repo")).toMatchObject({ owner: "acme", repo: "repo" })
  })

  it("rejects non-GitHub hosts", () => {
    expect(() => parseRepoTarget("https://gitlab.com/acme/repo")).toThrow(/github\.com/)
  })

  it("rejects garbage", () => {
    expect(() => parseRepoTarget("not a repo")).toThrow(/Not a GitHub repository/)
  })

  it("normalizes the canonical url", () => {
    expect(parseRepoTarget("git@github.com:acme/repo.git").url).toBe("https://github.com/acme/repo")
  })
})
