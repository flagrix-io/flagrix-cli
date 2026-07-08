import { parseArgs } from "node:util"

import { runScan } from "./commands/scan.js"
import { runScanUser } from "./commands/scan-user.js"
import { EXIT } from "./commands/shared.js"

const VERSION = "0.1.0"

const HELP = `flagrix — scan GitHub repos and profiles for malware before you clone

Usage:
  flagrix scan <url | owner/repo> [--ref <branch|sha>] [--json] [--token <pat>]
  flagrix scan-user <username> [--json] [--token <pat>]
  flagrix mcp                       start the MCP server (stdio) for agents

Options:
  --ref <ref>       branch, tag, or commit to scan (default: default branch)
  --json            machine-readable output (automatic when stdout is piped)
  --token <pat>     GitHub token (or FLAGRIX_GITHUB_TOKEN / GITHUB_TOKEN env)
  -h, --help        show this help
  -v, --version     show version

Exit codes:
  0  low risk        2  medium risk — review before proceeding
  1  scan failed     3  high risk — do not clone

The verdict is pinned to the scanned commit SHA (in the JSON output as
"commitSha"). Scanning is fully local: the only network calls go to the
GitHub/npm APIs and the public detection-rules repository. No telemetry.
Docs: https://github.com/flagrix-io/flagrix-cli`

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      ref: { type: "string" },
      json: { type: "boolean" },
      token: { type: "string" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" }
    }
  })

  if (values.version) {
    console.log(VERSION)
    return EXIT.LOW
  }

  const [command, target] = positionals

  if (values.help || !command) {
    console.log(HELP)
    return values.help ? EXIT.LOW : EXIT.ERROR
  }

  switch (command) {
    case "scan":
      if (!target) {
        console.error("flagrix: scan requires a repository URL or owner/repo\n")
        console.error(HELP)
        return EXIT.ERROR
      }
      return runScan(target, { ref: values.ref, json: values.json, token: values.token })

    case "scan-user":
      if (!target) {
        console.error("flagrix: scan-user requires a GitHub username\n")
        console.error(HELP)
        return EXIT.ERROR
      }
      return runScanUser(target, { json: values.json, token: values.token })

    case "mcp": {
      // Lazy import keeps `flagrix scan` startup free of the MCP SDK.
      const { runMcp } = await import("./commands/mcp.js")
      return runMcp()
    }

    default:
      console.error(`flagrix: unknown command "${command}"\n`)
      console.error(HELP)
      return EXIT.ERROR
  }
}

main().then(
  (code) => {
    process.exitCode = code
  },
  (error) => {
    console.error(`flagrix: ${(error as Error).message}`)
    process.exitCode = EXIT.ERROR
  }
)
