/**
 * The rule id a finding is reported under: its data-driven rule when it has
 * one, its built-in type otherwise.
 */
export function findingRule(finding) {
  return finding.pattern || finding.type
}

/**
 * Findings a human reviewed and accepted, from benchmark/reference-review.json.
 *
 * An entry names one finding on one sample: its rule, its file, and the ref it
 * was reviewed at. A finding that differs in any of those is not covered, and
 * an entry whose ref no longer matches the corpus is ignored — so bumping a
 * pin re-opens the question rather than carrying the acceptance forward
 * silently. Nothing here lowers a verdict; it only stops a reviewed finding
 * from failing the gate twice.
 */
export function acceptedFinding(accepted, row, finding) {
  const entries = accepted[row.sampleId]
  if (!Array.isArray(entries)) return false
  return entries.some(
    (entry) =>
      // Rows here are already flattened, where the rule id lives on `rule`.
      entry.pattern === (finding.rule ?? findingRule(finding)) &&
      entry.file === finding.file &&
      entry.ref === row.immutableRef
  )
}
