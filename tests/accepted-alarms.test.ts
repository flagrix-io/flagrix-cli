/**
 * Findings a human reviewed and accepted stop failing the gate — but only
 * that exact finding, at the ref it was reviewed at.
 *
 * `reference-review.json` existed as prose nobody read while the gate's own
 * message told you to record alarms in it. This is the part that reads it,
 * so the pairing has to stay narrow: a different rule, a different file or a
 * bumped pin must all still fail.
 */

import { readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

const root = join(import.meta.dirname, "..")
const review = JSON.parse(readFileSync(join(root, "benchmark", "reference-review.json"), "utf8"))
const runner = readFileSync(join(root, "benchmark", "run.mjs"), "utf8")

describe("accepted alarms", () => {
  it("records pnpm's preinstall with a rule, a file and a ref", () => {
    const entries = review.accepted?.["reference-pnpm-pnpm"]
    expect(entries).toHaveLength(1)
    expect(entries[0]).toMatchObject({
      pattern: "SUPPLY_CHAIN_PREINSTALL_SETUP_DROPPER",
      file: "pnpm11/pnpm/artifacts/exe/package.json",
    })
    expect(entries[0].ref).toMatch(/^[0-9a-f]{40}$/)
    expect(String(entries[0].why).length).toBeGreaterThan(20)
  })

  it("pins every entry to the ref the corpus actually uses", () => {
    const lock = JSON.parse(readFileSync(join(root, "benchmark", "corpus.lock.json"), "utf8"))
    for (const [sampleId, entries] of Object.entries(review.accepted ?? {})) {
      const sample = lock.samples.find((s: { sampleId: string }) => s.sampleId === sampleId)
      expect(sample, `accepted entry for unknown sample: ${sampleId}`).toBeDefined()
      for (const entry of entries as { ref: string }[]) {
        expect(
          entry.ref,
          `accepted entry for ${sampleId} is pinned to a ref the corpus no longer uses`
        ).toBe(sample.immutableRef ?? sample.target?.ref)
      }
    }
  })

  it("matches on rule, file and ref together", () => {
    // All three are compared, so a rule that starts firing on another file,
    // or the same finding after a pin bump, is not covered by the entry.
    for (const field of ["entry.pattern === (finding.rule ?? findingRule(finding))", "entry.file === finding.file", "entry.ref === row.immutableRef"]) {
      expect(runner, `acceptance must compare ${field}`).toContain(field)
    }
  })

  it("counts only unaccepted findings toward the critical gate", () => {
    expect(runner).toContain(
      `(finding) => finding.severity === "critical" && !acceptedFinding(accepted, row, finding)`
    )
  })
})
