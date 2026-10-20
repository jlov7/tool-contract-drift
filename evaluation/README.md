# What a Quiet MCP Diff Does Not Tell You

Local experiment and reference utility, 18 October 2026. Jason M. Lovell. [ORCID](https://orcid.org/0009-0001-6300-9155).

A descriptor can change without triggering a policy finding. This experiment compares structural changes with two classifiers on saved descriptors from released MCP packages. It accompanies a small experimental review utility, not a security product. Existing tools cover much of this problem; the contribution is a reproducible case study and reference workflow, not a new diff algorithm.

## What Was Measured

We selected five named npm packages before looking at their descriptor differences: the official filesystem, memory and sequential-thinking servers, Playwright MCP, and Context7 MCP. For each package, we selected the five most recently *published* stable versions before **2026-10-18 00:00:00 UTC**, an exclusive cutoff. This excludes releases later on October 18. All four adjacent publication transitions were included, including unchanged ones. A move from calendar versions to `1.0.0` is therefore included, not treated as a downgrade or filtered away.

The packages represent three publisher families, not five independent projects. Selection was purposive, not random or representative. Current transitive dependencies were frozen in `pnpm-lock.yaml`; these are not necessarily the dependency resolutions used on each original publication date.

Each version was launched twice, using pinned local entry points and a non-secret environment allowlist. Only protocol setup and paginated `tools/list` were requested. No tool was called, no browser launched, and no account or production data was supplied. Lifecycle scripts were disabled during installation. OpenTelemetry was disabled. These precautions are not a general sandbox for arbitrary untrusted packages: reproduction launches third-party JavaScript, so inspect it and use an appropriately isolated environment.

The same original acquisition went to each analysis path:

- A complete structural comparison of name-keyed raw tool objects. It ignores tool-array order and acquisition metadata outside `tools`. Object keys are canonicalized; arrays inside a tool remain ordered and atomic. Added or removed objects count as one changed path, so path counts are not comparable to classifier finding counts.
- The unchanged historical policy implementation from the July baseline, with the existing MCP-to-descriptor adapter. Its ten heuristic rules produce policy findings, not a complete diff.
- Independently implemented `mcpdiff@0.1.0`, using its offline `diff --format json` command and empty configuration. We passed original raw tool objects, bypassing its separate live-capture projection. We retained its all-changes output, not only its breaking changes. No code or predicates were shared with it.

The new `tool-descriptor-review` command was then tested on the same acquisitions. This is a repair/regression check on observed data, not an untouched holdout. The structural comparator and repaired utility are both project-authored; their agreement is not independent validation. It is a separate command so the research-frozen historical CLI and policy bytes remain unchanged.

Code, analysis and local review were AI-assisted using Codex. Separate model review passes found input-validation and evidence-preservation defects that were repaired. Those passes were not human peer review.

## Results

| Observation | Result |
|---|---:|
| Version captures | 25/25 successful |
| Server launches | 50; all repeated tool sets identical |
| Adjacent transitions retained | 20/20 |
| Structurally changed / unchanged transitions | 14 / 6 |
| Structural changed paths | 85 |
| Historical policy finding instances | 20 |
| Changed transitions with no historical policy findings | 7/14 |
| Pinned comparator finding instances | 53 |
| Changed transitions with no pinned comparator findings | 2/14 |
| New review inventory matches the frozen structural paths | 20/20 transitions |

These are descriptive counts from this sample, **not false-negative rates**. There are no independent labels for required approval, maliciousness, compatibility or reviewer usefulness. A changed field can be benign; a classifier may intentionally ignore it. More findings are not necessarily better.

### Three Cases Worth Inspecting

**Nested text can be quiet.** Context7 `4.3.0` to `4.4.0` changed `/tools/query-docs/inputSchema/properties/libraryId/description`. The edit refreshed an example version string. Both classifiers were quiet. The new review output shows the edit without calling it an attack. This is a benign demonstration of a visibility boundary, not an exploit or a vulnerability report.

**An unresolved schema question is not an attack.** Filesystem `2026.8.31` to `1.0.0` changed 28 schema-dialect paths across 14 tools. The historical policy emitted 14 `schema_containment_unresolved` review findings; the pinned comparator emitted none. That difference does not establish which behavior is more useful. We did not independently adjudicate dialect compatibility or measure the cost of those holds.

**One label must not hide other changes.** Playwright `0.0.80` to `0.0.81` added two tools and changed seven nested parameter descriptions. The historical policy emitted one `risky_tool_added` finding. The pinned comparator reported the two additions. A reviewer still needs visibility into the other edits. The new command retains all nine structural paths alongside the existing finding.

Raw acquisitions and full findings are not redistributed here because they contain third-party descriptions. Public receipts contain package identities, integrity pins, hashes, counts, field paths and classifier identifiers. Reproduction retrieves packages from their publishers. Package license metadata is inventory, not a legal determination.

## Use the Utility

Python 3.11 or later; no runtime dependencies.

```bash
uv run python -m tool_contract_drift.review_cli \
  --before examples/before_descriptor.json \
  --after examples/after_descriptor.json \
  --format json
```

Inputs may be raw `tools/list` result objects or normalized descriptors emitted by the historical capture command. The installed console entry point is `tool-descriptor-review`; the module command above also works from a checkout. `changes` is the full tool-object inventory; `policy_findings` is a separate, incomplete interpretation. Every change remains visible even when another change on the same tool triggers a finding. No per-path semantic coverage is claimed. Reports contain descriptor values, so do not upload them without checking for confidential or third-party content.

`--fail-on change` exits 1 for any structural change. `--fail-on findings` exits 1 only for policy findings. Default exit 0 means the command completed, not that the pair is safe or unchanged. `status` explicitly reports `changed` or `unchanged`. The legacy `lint` command remains findings-only, including its SARIF and Action path; do not use a quiet legacy report as approval.

The historical public `capture` command is a legacy stdio client pinned to the 2025 handshake. It has not been qualified as a general current-protocol acquisition tool. The experiment's capture runner is separate, bounded, and exercised only on the packages here. Use an appropriate maintained MCP client for other acquisition needs; this utility deliberately focuses on saved tool objects.

## Reproduce

Requirements: uv, Node.js and pnpm. The recorded run used the exact runtime versions in `practical_results.json` and pnpm's frozen lockfile. npm access is required to install packages. Review the runner before launching third-party servers.

```bash
uv run python scripts/prepare_practical_evaluation.py \
  --restore-runtime --runtime-dir artifacts/practical-reproduction/runtime
pnpm --dir artifacts/practical-reproduction/runtime install \
  --frozen-lockfile --ignore-scripts \
  --store-dir ../pnpm-store --config.verify-store-integrity=true
uv run python scripts/run_practical_evaluation.py \
  --work artifacts/practical-reproduction \
  --output artifacts/practical-reproduction/reproduced-results.json
uv run python scripts/check_practical_review.py \
  --work artifacts/practical-reproduction \
  --output artifacts/practical-reproduction/reproduced-review.json
```

Use a fresh work directory for each reproduction. Both runners refuse to overwrite an existing receipt, and acquisition refuses existing capture/comparison directories. `practical_protocol.json` and `practical_sample.json` freeze selection, tarball integrity, and the initial policy commit. `practical_results.json` is the original comparison receipt. `review_results.json` binds the repaired review module to the regression check. A reproduction must compare capture hashes, paths, classifications and counts; runtime-version fields can differ. The checker rejects a capture identity different from the frozen receipt. Different current server behavior or nondeterminism is a result to investigate, not a reason to quietly replace these receipts.

The recorded baseline commit is a private custody identifier, not a reachable commit in the clean distribution history. The unchanged baseline implementation is included here; its byte hash is recorded in the receipts.

## What This Does Not Establish

There was no human review experiment, independent approval adjudication, production deployment, behavioral tool test, attack-success evaluation, ecosystem prevalence estimate, or evidence that this utility saves time. The observed nested-text example was benign. Hashes bind observations but do not prove that the observations or interpretations are correct.

A conventional recursive JSON diff could implement the structural visibility lesson. This is a reference workflow and case study, not a claim of a new diff algorithm. For broader MCP capture and compatibility checks, consider existing projects rather than adopting this solely for that purpose.

The July white paper describes the earlier policy and proposed evaluation. Its 53-case all-synthetic public regression corpus and 65-case private research corpus are distinct from these 20 released-version transitions. No historical result has been promoted into an accuracy claim.

## Related Work and Feedback

[mcpdiff](https://github.com/samlader/mcpdiff) is the directly executed independent comparator. [Cisco's MCP Contract Toolkit](https://github.com/cisco-open/mcptoolkit-contract) provides adjacent capture, diff and rule-based compatibility functionality; it was inspected as related work, not executed in this comparison. [MCP Drift Lab](https://github.com/zelinsky-alexander/mcp-drift-lab) examines client lifecycle/consent behavior. The [MCP tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) defines the descriptor surface, including untrusted annotations. None of these projects endorses this artifact.

Useful feedback is a reproducible pair, an incorrectly omitted change path, a misleading policy label, or evidence that an existing tool makes this workflow unnecessary. Public feedback can guide iteration. It does not retroactively turn these observations into blinded study evidence.
