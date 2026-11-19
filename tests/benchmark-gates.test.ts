/**
 * The benchmark's pass/fail decision, driven by three real recorded runs.
 *
 * Context: `npm run benchmark` used to exit 0 whatever the gates said, so the
 * benchmark could not be wired into CI as a gate — and scanner-core 0.7.0 was
 * published calling evanw/esbuild high-risk and unsafe to clone, with every
 * unit test green. These fixtures are the actual reports from that episode.
 */

import { readFileSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"
// @ts-expect-error — plain ESM helper shared with benchmark/run.mjs
import { gateReport } from "../benchmark/gates.mjs"

/** Read with fs rather than import, which would need a JSON import attribute. */
function fixture(name: string) {
  const path = join(import.meta.dirname, "fixtures", name)
  return JSON.parse(readFileSync(path, "utf8")) as {
    metrics: {
      samplesDefined: number
      samplesCompleted: number
      samplesPassed: number
      gates: Record<string, boolean | null>
    }
  }
}

const green = fixture("benchmark-green-0.7.1.json")
const partial = fixture("benchmark-partial-run.json")
const regression = fixture("benchmark-regression-0.7.0.json")

const full = { requireEveryGate: true }
const scoped = { requireEveryGate: false }

describe("benchmark gate decision", () => {
  it("passes the run where both false positives are fixed", () => {
    const { problems, warnings } = gateReport(green.metrics, full)
    expect(problems).toEqual([])
    // 112 of 114: the two Docusaurus samples still miss their expected
    // verdict. That is reported but must not block, or CI would refuse to
    // ship a release that is strictly better than what is published.
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toMatch(/2 completed sample\(s\) missed/)
  })

  it("fails the published 0.7.0 regression", () => {
    const { problems, warnings } = gateReport(regression.metrics, full)
    expect(problems).toContain("gate failed: zeroCriticalReferenceFindings")
    // 111 of 114 passed: esbuild plus the two Docusaurus samples.
    expect(warnings[0]).toMatch(/3 completed sample\(s\) missed/)
  })

  it("fails a run that stopped early, even with every evaluated gate green", () => {
    // This is the trap the completeness check exists for. The run below was
    // cut short by an exhausted GitHub quota; it never reached esbuild, so
    // the gate that should have caught 0.7.0 reported green.
    expect(partial.metrics.gates.zeroCriticalReferenceFindings).toBe(true)
    expect(
      Object.values(partial.metrics.gates).every((gate) => gate === true || gate === null)
    ).toBe(true)

    const { problems } = gateReport(partial.metrics, full)
    expect(problems.some((p: string) => /samples completed/.test(p))).toBe(true)
  })

  it("treats an unevaluated gate as skipped on a scoped run, failed on a full one", () => {
    const oneCorpus = {
      samplesDefined: 10,
      samplesCompleted: 10,
      samplesPassed: 10,
      gates: { criticalFixtures100Percent: true, maliciousDetectionAtLeast90Percent: null },
    }
    // `--corpus critical-fixture` cannot evaluate the malicious-package gate.
    expect(gateReport(oneCorpus, scoped).problems).toEqual([])
    expect(gateReport(oneCorpus, full).problems).toContain(
      "gate not evaluated: maliciousDetectionAtLeast90Percent"
    )
  })

  it("names every reason rather than stopping at the first", () => {
    const { problems } = gateReport(
      {
        samplesDefined: 114,
        samplesCompleted: 100,
        samplesPassed: 90,
        gates: { a: false, b: null, c: true },
      },
      full
    )
    expect(problems).toEqual([
      "only 100 of 114 samples completed — the gates below were computed from a partial run",
      "gate failed: a",
      "gate not evaluated: b",
    ])
  })
})
