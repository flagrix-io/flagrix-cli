/**
 * `--version` must agree with the package, and `server.json` with both.
 *
 * None of the three is derived from the others: `npm version` updates
 * package.json and the lock, the CLI carries its own literal, and the MCP
 * registry has two more copies in server.json. Release CI checks the tag
 * against package.json and server.json, but nothing checked the literal the
 * CLI actually prints, so a release could — and nearly did — publish 0.6.1
 * while `flagrix --version` said 0.6.0.
 */

import { readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

const root = join(import.meta.dirname, "..")
const read = (name: string) => readFileSync(join(root, name), "utf8")
const packageVersion = JSON.parse(read("package.json")).version as string

describe("version consistency", () => {
  it("has a plain semver version in package.json", () => {
    expect(packageVersion).toMatch(/^\d+\.\d+\.\d+(?:-[\w.]+)?$/)
  })

  it("prints the package version from --version", () => {
    const literal = read("src/cli.ts").match(/^const VERSION = "([^"]+)"$/m)?.[1]
    expect(literal, "src/cli.ts must declare `const VERSION = \"x.y.z\"`").toBeDefined()
    expect(literal).toBe(packageVersion)
  })

  it("advertises the package version to the MCP registry", () => {
    const server = JSON.parse(read("server.json"))
    expect(server.version).toBe(packageVersion)
    expect(server.packages[0].version).toBe(packageVersion)
  })
})
