# Saved-Descriptor Review Contract

The review command compares accepted saved tool objects. It does not execute tools
or decide whether a change is safe, compatible or approved. The structural inventory
and the historical policy findings are separate outputs. The comparison engine and
the original released-version observations remain unchanged by the reporting and CI
features described here.

## CLI Reports

```bash
uv run python -m tool_contract_drift.review_cli \
  --before examples/before_quiet_change.json \
  --after examples/after_quiet_change.json \
  --format json --output artifacts/review.json \
  --summary-output artifacts/summary.md --fail-on change
```

One comparison supplies both reports. The primary report defaults to full
disclosure. The optional secondary Markdown report defaults to counts. Both are
written before a change/finding gate returns exit 1. JSON remains the machine
format; Markdown groups every structural entry by tool, operation and path, with
findings in a separate section. Long string replacements have a text diff and
expandable complete before/after JSON. No change entry or full value is truncated.

The full JSON schema remains `tool-descriptor-review-v1`. Paths address a name-keyed
tool map, not positions in the input `tools` array. They are not directly executable
JSON Patch instructions against the original snapshot. Inner arrays are ordered
and atomic; object-key order, outer tool order and metadata outside `tools` are
excluded from identity. This is not a complete behavioral or protocol-context diff.

Input files are limited to 10 MB each. Reports must not alias either input or each
other, including existing hard links. Individual file writes use temporary files
and atomic replacement. Multiple output files are not a joint transaction: a later
output failure can leave an earlier complete file. Exit 2 means the invocation
failed, not that any existing artifact is current or approved. Pre-existing reports
are not deleted on failure. Never substitute a stale report for a failed comparison.

| Result | Exit |
|---|---:|
| Successful comparison, default `--fail-on none` | 0 |
| Successful comparison with the selected change/finding gate triggered | 1 |
| Invalid input/settings, processing or report-writing failure | 2 |

`--fail-on change` uses the structural inventory. `--fail-on findings` uses policy
findings. Both gate meanings are independent of the disclosure level. An unchanged
report or no findings is not approval. Descriptor and file failures use a generic
JSON diagnostic with a request ID instead of printing descriptor validation details.
Argument syntax errors report usage. The Python API can
raise detailed exceptions; treat those as potentially sensitive when debugging.

## Disclosure Levels

`--disclosure` controls the primary report. `--summary-disclosure` controls the
optional secondary Markdown report. Both accept `full`, `counts` and `paths`.

`counts` and `paths` use `tool-descriptor-review-summary-v1`:

- `schema_version` and `disclosure` identify the projection.
- `status`, `change_count` and `policy_finding_count` describe this comparison.
- `operation_counts` contains counts for `add`, `remove` and `replace`.
- `boundary` is fixed explanatory text, never copied from input metadata.
- Only `paths` includes `changes`, each with `tool_name`, `path` and `op`.

These are allowlisted projections, not regex redactions. They omit values,
snapshot hashes, fixture identifiers and finding details. No hashes of individual
secret values are substituted. `paths` deliberately reveals identifiers, which
can be confidential. `counts` still reveals aggregate structure and comparison
status. Neither is anonymization, differential privacy, an independent attestation
or sufficient evidence for approval. File names and the destination audience are
chosen by the caller, not inferred from descriptor contents.

The Python projection is
`tool_contract_drift.review_privacy.minimize_review_report(report, disclosure)`.
It validates status/count consistency and operations, uses fixed errors and returns
fresh summary containers. For Markdown, pass its result to
`tool_contract_drift.review_render.render_review_markdown`. A hand-authored object
with a summary schema name is not a substitute for the privacy projection.

Full Markdown escapes names, paths, values and finding text as data, including
fences, HTML, Unicode direction/control characters and unpaired surrogates. It is
still a full-disclosure report. Escaping content does not make sharing it lawful
or appropriate. Review confidential and third-party text before redistribution.

## GitHub Action

`actions/descriptor-review/action.yml` is separate from the legacy root Action.
It requires a checkout accessible to the workflow, Python 3.11 or later, and Bash.
It has no runtime Python dependencies beyond the installed project. Hosted checks
exercise Linux with Python 3.11 and 3.12; other runner platforms are not qualified
by those checks.

| Input | Default | Meaning |
|---|---|---|
| `before`, `after` | Required | Saved snapshot file paths |
| `report` | `artifacts/descriptor-review.json` | Local full JSON report, including values |
| `summary` | `artifacts/descriptor-review.md` | Local Markdown summary |
| `summary-disclosure` | `counts` | Explicitly choose `paths` or `full` to expose more |
| `post-summary` | `"true"` | Set `"false"` to avoid appending to the job summary |
| `fail-on` | `none` | Report-only, structural-change gate or findings gate |

After a successful comparison, outputs are `status`, `change-count`,
`policy-finding-count`, `report-path` and `summary-path`. They are written even if
the selected change/finding gate subsequently fails. Invalid inputs or processing
failures do not emit comparison outputs. A failed installation is also an Action
failure, not a comparison result.

Inputs travel through environment variables, not interpolated shell commands.
The adapter rejects multiline path/output-protocol injection and destinations
that alias input, report or GitHub output/summary files. It writes no descriptor
values to stdout. Job summaries use [GitHub's summary file](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#adding-a-job-summary)
and outputs use the [composite Action output contract](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax#outputs-for-composite-actions).

The Action retains the full report locally and does not upload it automatically.
If another workflow step uploads that file, prints it or selects a broader summary
disclosure, that is a separate disclosure decision. A counts-only job summary
does not constrain other steps, runner access or later artifact uploads.

The root `action.yml`, legacy `lint` and SARIF remain findings-only. Their quiet
output must not be interpreted as an unchanged descriptor. No SARIF completeness
or live code-scanning upload claim is added by the new Action.

## Evidence Boundary

Tests cover disclosure canaries, malformed input, gate/output separation, report
alias protection, hostile Markdown/control characters and complete entry retention.
[Independent structural checks](../evaluation/structural_correctness.md) use pinned
development-only libraries for expected paths and reversible operations on bounded
generated inputs. The hosted workflow also exercises an unlabeled change gate and
an invalid-input Action invocation, checking their actual step outcomes and outputs.

These checks support specific software contracts. They do not establish exhaustive
correctness, reviewer time savings, independent approval labels, attack detection,
runtime behavior, production readiness or a general privacy guarantee.
