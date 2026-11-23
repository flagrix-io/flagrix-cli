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
// @ts-expect-error — plain .mjs module without type declarations
import { acceptedFinding } from "../benchmark/accepted.mjs"

const root = join(import.meta.dirname, "..")
const review = JSON.parse(readFileSync(join(root, "benchmark", "reference-review.json"), "utf8"))
const runner = readFileSync(join(root, "benchmark", "run.mjs"), "utf8")

describe("accepted alarms", () => {
  // An inline entry, so the matching stays covered whether or not the real
  // review file holds any accepted findings at the moment.
  const REF = "0123456789abcdef0123456789abcdef01234567"
  const accepted = {
    "reference-example": [{
      pattern: "SUPPLY_CHAIN_PREINSTALL_SETUP_DROPPER",
      file: "packages/exe/package.json",
      severity: "critical",
      ref: REF,
      why: "preinstall links the platform binary; no network, no process spawn.",
    }],
  }
  const row = { sampleId: "reference-example", immutableRef: REF }
  const finding = {
    severity: "critical",
    rule: "SUPPLY_CHAIN_PREINSTALL_SETUP_DROPPER",
    file: "packages/exe/package.json",
  }

  it("accepts the exact finding an entry names", () => {
    expect(acceptedFinding(accepted, row, finding)).toBe(true)
    // An unflattened finding carries its rule on `pattern`.
    const raw = { severity: "critical", pattern: finding.rule, type: "MALWARE_SIGNATURE", file: finding.file }
    expect(acceptedFinding(accepted, row, raw)).toBe(true)
  })

  it("does not accept a different rule, file, ref or sample", () => {
    expect(acceptedFinding(accepted, row, { ...finding, rule: "SUPPLY_CHAIN_INSTALL_HOOK_DOWNLOADER" })).toBe(false)
    expect(acceptedFinding(accepted, row, { ...finding, file: "package.json" })).toBe(false)
    expect(acceptedFinding(accepted, { ...row, immutableRef: "f".repeat(40) }, finding)).toBe(false)
    expect(acceptedFinding(accepted, { ...row, sampleId: "reference-other" }, finding)).toBe(false)
    expect(acceptedFinding({}, row, finding)).toBe(false)
  })

  it("records every real entry with a rule, a file, a ref and a reason", () => {
    for (const entries of Object.values(review.accepted ?? {})) {
      for (const entry of entries as Record<string, unknown>[]) {
        expect(typeof entry.pattern).toBe("string")
        expect(typeof entry.file).toBe("string")
        expect(entry.ref).toMatch(/^[0-9a-f]{40}$/)
        expect(String(entry.why).length).toBeGreaterThan(20)
      }
    }
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

  it("counts only unaccepted findings toward the critical gate", () => {
    expect(runner).toContain(
      `(finding) => finding.severity === "critical" && !acceptedFinding(accepted, row, finding)`
    )
  })
})
