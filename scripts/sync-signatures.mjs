/**
 * Refresh the bundled signature snapshot (offline fallback) from the public
 * detection-rules repo. Runs automatically before publish (prepublishOnly).
 */
import { writeFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"

const URL_ = "https://raw.githubusercontent.com/flagrix-io/flagrix-detection-rules/main/signatures.json"
const OUT = fileURLToPath(new URL("../assets/signatures-snapshot.json", import.meta.url))

const response = await fetch(URL_)
if (!response.ok) {
  console.error(`sync-signatures: fetch failed (${response.status}) — keeping existing snapshot`)
  process.exit(0)
}
const body = await response.text()
JSON.parse(body) // validate before overwriting
await writeFile(OUT, body)
console.log(`sync-signatures: snapshot updated (${(body.length / 1024).toFixed(1)} kB)`)
