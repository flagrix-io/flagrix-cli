/**
 * `--version` must agree with the package, and `server.json` with both.
 *
 * None of the three is derived from the others: `npm version` updates
 * package.json and the lock, the CLI carries its own literal, and the MCP
 * registry has two more copies in server.json. Release CI checks the tag
 * against package.json and server.json, but nothing checked the literal the
 * CLI actually prints, so a release could — and nearly did — publish 0.6.1
 * while `flagrix --version` said 0.6.0.
 *
 * The MCP server advertises its version to the client over the wire, where
 * nothing checks it at all: it sat at 0.5.1 through four releases. It reads
 * the same literal now, and the last test here keeps it that way.
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
    const literal = read("src/commands/shared.ts").match(/^export const VERSION = "([^"]+)"$/m)?.[1]
    expect(
      literal,
      'src/commands/shared.ts must declare `export const VERSION = "x.y.z"`'
    ).toBeDefined()
    expect(literal).toBe(packageVersion)
  })

  it("advertises that same version over MCP", () => {
    // A second literal here is a number nobody reads until a client reports
    // the wrong one, so the source must name the constant.
    expect(read("src/commands/mcp.ts")).toContain('new McpServer({ name: "flagrix", version: VERSION })')
  })

  it("advertises the package version to the MCP registry", () => {
    const server = JSON.parse(read("server.json"))
    expect(server.version).toBe(packageVersion)
    expect(server.packages[0].version).toBe(packageVersion)
  })
})
