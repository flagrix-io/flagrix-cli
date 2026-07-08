import { defineConfig } from "tsup"

export default defineConfig({
  entry: ["src/cli.ts"],
  format: "esm",
  target: "node18",
  platform: "node",
  clean: true,
  // scanner-core is a devDependency (bundled in), so the published package
  // carries only the MCP SDK + zod as runtime deps — fast `npx` cold start
  // and no coupling to the core's npm release cadence.
  banner: { js: "#!/usr/bin/env node" }
})
