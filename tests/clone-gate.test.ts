/**
 * The Claude Code clone gate (hooks/flagrix-clone-gate.sh), run as Claude Code
 * runs it: the tool-call JSON on stdin, the exit code as the decision. `npx` is
 * replaced by a stub on PATH that records its arguments and exits with the
 * code a scan would, so no network or real scan is involved.
 */
import { spawnSync } from "node:child_process"
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, expect, it } from "vitest"

const HOOK = resolve(__dirname, "../hooks/flagrix-clone-gate.sh")

function runHook(command: string, scanExit = 0) {
  const dir = mkdtempSync(join(tmpdir(), "flagrix-hook-"))
  const argsFile = join(dir, "args")
  const npx = join(dir, "npx")
  writeFileSync(npx, `#!/usr/bin/env bash\nprintf '%s\\n' "$@" > "${argsFile}"\nexit ${scanExit}\n`)
  chmodSync(npx, 0o755)

  const res = spawnSync("bash", [HOOK], {
    input: JSON.stringify({ tool_name: "Bash", tool_input: { command } }),
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
    encoding: "utf8"
  })
  const npxArgs = existsSync(argsFile) ? readFileSync(argsFile, "utf8").trim().split("\n") : null
  return { code: res.status, stderr: res.stderr, npxArgs }
}

describe("clone gate hook", () => {
  it("scans the default branch when no branch is given", () => {
    const r = runHook("git clone https://github.com/acme/tool")
    expect(r.code).toBe(0)
    expect(r.npxArgs).toEqual(["-y", "flagrix", "scan", "https://github.com/acme/tool", "--json"])
  })

  it.each([
    ["git clone --branch release https://github.com/acme/tool", "release"],
    ["git clone --branch=release https://github.com/acme/tool", "release"],
    ["git clone -b release https://github.com/acme/tool", "release"],
    ["git clone https://github.com/acme/tool -b release/2.x --depth 1", "release/2.x"],
    ['git clone -b "v1.2.0" git@github.com:acme/tool.git', "v1.2.0"],
    ["gh repo clone acme/tool -- --branch release", "release"]
  ])("scans the branch being cloned: %s", (command, branch) => {
    const r = runHook(command)
    expect(r.npxArgs).toContain("--ref")
    expect(r.npxArgs![r.npxArgs!.indexOf("--ref") + 1]).toBe(branch)
  })

  it("ignores a -b that belongs to another command in the same line", () => {
    const r = runHook("git checkout -b wip && git clone https://github.com/acme/tool")
    expect(r.npxArgs).not.toContain("--ref")
  })

  it("does not mistake --bare for a branch flag", () => {
    const r = runHook("git clone --bare https://github.com/acme/tool")
    expect(r.npxArgs).not.toContain("--ref")
  })

  it("blocks on high risk and names the branch that was scanned", () => {
    const r = runHook("git clone -b release https://github.com/acme/tool", 3)
    expect(r.code).toBe(2)
    expect(r.stderr).toContain("HIGH risk")
    expect(r.stderr).toContain("(branch release)")
    expect(r.stderr).toContain("--ref release")
  })

  it("blocks on an incomplete scan (exit 4)", () => {
    const r = runHook("git clone https://github.com/acme/tool", 4)
    expect(r.code).toBe(2)
    expect(r.stderr).toContain("not enough was read to give a verdict")
  })

  it("lets non-clone commands through without scanning", () => {
    const r = runHook("git status")
    expect(r.code).toBe(0)
    expect(r.npxArgs).toBeNull()
  })
})
