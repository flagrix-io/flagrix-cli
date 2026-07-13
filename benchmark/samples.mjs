/**
 * Shared corpus-sample constructors for run.mjs and pin-corpus.mjs.
 * Both scripts must expand the source corpus identically, or the runner would
 * evaluate samples the pinner never locked (and vice versa).
 */

export function projectSample(project) {
  const prefix = project.corpus === "noisy-legitimate" ? "noisy" : "reference"
  const slug = project.repo.toLowerCase().replaceAll("/", "-").replaceAll(".", "-")
  return {
    sampleId: `${prefix}-${slug}`,
    corpus: project.corpus,
    label: "reference-clean",
    labelSource: "Expanded commit-pinned reference corpus",
    sourceUrl: `https://github.com/${project.repo}`,
    immutableRef: null,
    maximumExpectedVerdict: "low",
    expectedDetectionCategories: [],
    target: { kind: "github", repo: project.repo, ref: null },
  }
}

export function osvSample(source, entry) {
  const reportPath = `osv/malicious/${source.ecosystem}/${entry.name}/${entry.reportId}.json`
  return {
    sampleId: `malicious-osv-${entry.reportId.toLowerCase()}`,
    corpus: "real-malicious",
    label: "known-malicious-metadata",
    labelSource: `OpenSSF OSV ${entry.reportId}; report blob ${entry.reportBlobSha}`,
    sourceUrl: `https://github.com/${source.repository}/blob/${source.commit}/${reportPath}`,
    immutableRef: `osv:${source.commit}:${entry.reportBlobSha}`,
    expectedDetectionCategories: ["SUSPICIOUS_DEPENDENCY"],
    minimumExpectedVerdict: "high",
    target: {
      kind: "fixture",
      files: {
        "package.json": JSON.stringify({
          name: `flagrix-inert-${entry.reportId.toLowerCase()}`,
          private: true,
          dependencies: { [entry.name]: entry.version },
        }) + "\n",
      },
    },
  }
}

/** Append the github-projects and OSV samples to the source corpus in place. */
export function expandCorpus(corpus, additions, osv) {
  corpus.samples.push(...additions.projects.map(projectSample))
  corpus.samples.push(...osv.packages.map((entry) => osvSample(osv.source, entry)))
  return corpus
}
