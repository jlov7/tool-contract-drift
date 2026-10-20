# Changelog

## October 2026 Experimental Candidate

- Add a complete-inventory descriptor-review Action with separate change/finding outputs and counts-only job summaries by default. The legacy root Action and SARIF remain findings-only.
- Add grouped Markdown reports, text diffs and complete expandable values, plus explicit counts/paths disclosure projections. Full reports remain local unless the caller shares them.
- Distinguish change/finding gate failures (exit 1) from input, processing or output failures (exit 2). Protect input files from report-output aliases and use generic non-disclosing error diagnostics.
- Add independent structural checks with pinned development-only DeepDiff and JSON Patch libraries: 400 seeded pairs, path agreement, reconstruction, inversion and permutation checks. Retain library equality disagreements explicitly; no exhaustive correctness claim.
- Add `tool-descriptor-review` and `review_descriptor_pair`: complete structural tool-object changes alongside incomplete policy labels.
- Add a reproducible 20-transition released-version case study and pinned independent `mcpdiff@0.1.0` comparison. Findings are descriptive observations, not accuracy or human-benefit evidence.
- Keep the July paper and all-synthetic regression corpus as separate historical background. Preserve the historical CLI and policy bytes.

## 0.1.0a0

- Adds a pre-review implementation-neutral vocabulary for tool-descriptor reapproval decisions.
- Adds explicit, manifest-verified corpus selection with no implicit default or private/public fallback.
- Ships `public-reproduction-53`: a separate manifest-bound identity with 53 project-authored synthetic fixture pairs, comprising 28 regression cases retained byte-for-byte from the private corpus's synthetic rows and 25 newly authored quiet controls, with 22 holds, 31 quiet controls, 25 finding instances, and zero source-derived descriptor bytes; it is not a private-corpus subset.
- Keeps `private-canonical-65` as private checkout evidence and refuses to select it from installed/public artifacts.
- Normalizes MCP annotation defaults and distinguishes explicit restatement, safer explicit annotation, and actual escalation.
- Preserves version-aware MCP/Apps descriptor fields and demotes unsupported schema-containment cases to manual review.
- Adds Markdown, JSON, SARIF, Python API, CLI, capture, and composite Action surfaces.
- Reports configured-policy and oasdiff-adapter parity as shared-policy carrier portability and standalone-carrier pivot pressure, not independent accuracy evidence.
- Adds deterministic public-export, exact byte manifest, fresh-extraction verification, structured feedback forms, and negative-evidence response policy.

This prerelease does not claim external reviewer evidence, scored sealed cases, benchmark status, vulnerability detection, live GitHub SARIF evidence, protocol endorsement, production readiness, ethics approval, legal clearance, or a DOI.
