# Agent Tool Contract Drift

Review saved MCP tool-object changes, including edits a policy classifier leaves unlabeled.

A tool's parameter description can change while a compatibility or risk report stays quiet. That silence may be intentional, but it is not evidence that the descriptor is unchanged. Agent Tool Contract Drift keeps the structural changes and the policy findings separate, so you can inspect both.

This is a small experimental utility and [released-version case study](evaluation/README.md). It does not decide whether a change is safe or needs approval. Python 3.11 or later, MIT license, no third-party Python runtime dependencies.

## Try It

From a checkout, with [uv](https://docs.astral.sh/uv/):

```bash
uv run python -m tool_contract_drift.review_cli \
  --before examples/before_quiet_change.json \
  --after examples/after_quiet_change.json --format json
```

The example changes one parameter description, from "Document title to look up." to "Document title or reference number to look up." The policy classifier emits nothing. The review still contains the edit:

```json
{
  "status": "changed",
  "change_count": 1,
  "changed_without_policy_findings": true,
  "changes": [
    {
      "tool_name": "lookup_document",
      "path": "/tools/lookup_document/inputSchema/properties/query/description",
      "op": "replace",
      "before": "Document title to look up.",
      "after": "Document title or reference number to look up."
    }
  ],
  "policy_findings": []
}
```

This is an excerpt of the JSON report; the full output also includes its schema version, snapshot hashes and interpretation boundary. It is a benign wording change, not a demonstrated attack. The example is covered by a regression test.

The installed console command is `tool-descriptor-review`. The [second example pair](examples/before_descriptor.json) produces four changed paths and three policy findings.

## Two Outputs, Different Jobs

| Output | What it tells you | What it does not tell you |
|---|---|---|
| `changes` | Structural edits within accepted tool objects, including unknown fields | Whether an edit matters, is malicious or needs approval |
| `policy_findings` | Findings from the historical heuristic policy | Complete coverage of changes, compatibility or safety |

Inputs are JSON objects containing a `tools` array, with unique nonempty tool names and an object-valued `inputSchema` or `input_schema`. Raw MCP tool objects and the historical CLI's normalized descriptors are accepted. Unsupported or ambiguous inputs can fail validation; accepting an input does not certify protocol conformance.

Tools are matched by name. Object-key order and outer tool-array order are ignored. Arrays inside a tool remain ordered and are reported as one changed value. Missing fields differ from JSON `null`. Acquisition metadata outside `tools` is not compared.

Paths address a name-keyed tool map, not the original array positions; they are not executable JSON Patch instructions. Snapshot hashes bind this representation, not server authenticity, authorization context or runtime behavior.

## Use in Automation

To stop on any structural edit, including edits with no policy findings:

```bash
uv run python -m tool_contract_drift.review_cli \
  --before examples/before_quiet_change.json \
  --after examples/after_quiet_change.json \
  --format json --output artifacts/descriptor-review.json \
  --fail-on change
```

This example writes the report and exits 1 because the descriptor changed.

| Setting | Successful comparison exit behavior |
|---|---|
| Default / `--fail-on none` | 0, whether changed or unchanged |
| `--fail-on change` | 1 if any structural change exists; otherwise 0 |
| `--fail-on findings` | 1 if policy findings exist; otherwise 0 |

Input and processing errors also exit nonzero. A nonzero exit alone does not distinguish a change from an error; inspect the report and stderr. Completion is not approval.

Reports contain descriptor values, tool names and field paths. Check for confidential and third-party content before sharing them. Markdown output currently wraps the JSON report rather than providing a separate change-focused renderer.

**The legacy `lint`, SARIF and composite Action paths remain findings-only.** Use the review command above for the structural inventory. A quiet legacy report must not be treated as an unchanged descriptor or approval.

## Case Study

The [October 2026 case study](evaluation/README.md) compares all 20 adjacent publication transitions from 25 pinned released versions of five named npm packages across three publisher families. Each version was launched twice; all repeated tool sets matched. No tools were called.

| Observation | Result |
|---|---:|
| Changed / unchanged transitions | 14 / 6 |
| Changed transitions with no historical policy findings | 7 / 14 |
| Changed transitions with no findings from pinned `mcpdiff@0.1.0` | 2 / 14 |

The independently implemented comparator received the same raw acquisitions. These are descriptive counts, not false-negative rates: the sample has no independent approval, maliciousness or usefulness labels. A classifier can reasonably leave a benign edit unlabeled. The pinned comparison does not describe every current version of that tool.

The new command preserves the structural inventory on those same observations. This is a regression check, not a held-out evaluation. A conventional JSON diff can provide structural visibility; no new diff algorithm or reviewer benefit is claimed. The case study includes a benign nested-description edit and explains the limits of the comparison.

Raw acquisitions are not redistributed because they contain third-party descriptions. The case study provides integrity pins, hashes, field paths and reproduction instructions. Reproduction launches third-party packages and needs an appropriately isolated environment; the runner is not a general sandbox.

## When to Use Something Else

The structural diff is conventional. Before adopting another tool, check whether your existing one already gives you the inventory and workflow you need.

| Project | Adjacent capabilities described in its documentation |
|---|---|
| [mcpdiff](https://github.com/samlader/mcpdiff) | Live capture, saved snapshots and Git inputs, configurable checks, compatibility and changelog output |
| [Cisco MCP Contract Toolkit](https://github.com/cisco-open/mcptoolkit-contract) | Capability dumps, comparison, breaking-change checks, changelogs and documentation generation |
| [agent-tool-drift](https://github.com/fykong/agent-tool-drift) | Source and manifest inputs, MCP snapshots, policy configuration and HTML reports |

This is a documentation-based scope comparison, not a current-version execution benchmark. Only the pinned `mcpdiff@0.1.0` comparator was executed in the case study. No endorsement is implied. This project's reason to exist is an inspectable reference workflow that keeps change visibility separate from policy interpretation, with a reproducible example of why that distinction matters.

## Limits

This release focuses on saved tool objects. It does not execute tools, verify authorization, find vulnerabilities or certify protocol conformance. The legacy `lint`, SARIF and Action paths remain findings-only. The historical public `capture` command uses the 2025 stdio handshake and has not been qualified as a general current-protocol capture tool.

There is no external reviewer result, scored sealed evaluation, ethics approval claim, live GitHub SARIF upload evidence, DOI, protocol endorsement or production-readiness claim. Code, analysis and local model review were AI-assisted; model review is not human peer review.

## Inspect and Reproduce

Start with the [case study](evaluation/README.md), [review implementation](tool_contract_drift/review.py) or [policy specification](docs/policy_spec.md). The [July white paper](paper/agent-tool-contract-drift.pdf) is frozen historical policy/methods background, not the current case study or a validated research result.

<details>
<summary>Synthetic corpus and configured-policy evidence</summary>

This public source export contains the manifest-verified `public-reproduction-53` corpus:

- 53 descriptor pairs;
- 53 project-authored synthetic records: 28 regression cases retained byte-for-byte from the private corpus's project-authored synthetic rows plus 25 newly authored quiet controls;
- 22 hold fixtures and 31 quiet/control fixtures;
- 25 emitted finding instances under `tool-contract-drift-v1`.

No source-derived descriptor bytes are part of this corpus. It provides synthetic regression checks, not real-source findings, prevalence evidence or independent performance evidence. Released-version observations are separate; their raw acquisitions are not redistributed.

The separate research/coordinator corpus is `private-canonical-65`: 65 pairs, 30 finding instances, 26 fixtures with holds, and 39 quiet/control fixtures. `public-reproduction-53` is a separate manifest-bound identity, not a subset of that corpus: it retains the 28 project-authored synthetic private-corpus rows byte-for-byte and adds 25 new synthetic controls, while excluding all 37 source-derived rows. It is not an independent external reproduction. The public export cannot select the private corpus and must fail instead of silently substituting these 53 cases.

Configured-policy and oasdiff-adapter parity on the private corpus are shared-policy carrier results. They show transportability and substitute pressure, not independent comparator accuracy or evidence that a standalone detector is novel.

</details>

<details>
<summary>Verify source bytes and distribution history</summary>

### Verify the Source

Verify a fresh checkout before running commands that generate environments, caches or reports:

```bash
command -v pdftotext
uv run --no-project python -B scripts/verify_public_export.py .
uv run --no-project python -B scripts/verify_public_history.py .
```

The file verifier rejects extra or modified files, including generated files. Use a fresh checkout for an exact-byte recheck. The history verifier applies to a Git checkout, not an archive extraction.

If using a separately supplied source archive and sidecars, verify them before extraction:

```bash
python3 scripts/verify_public_archive.py \
  dist/public-export/tool-contract-drift-0.1.0a0-public-source.tar.gz \
  --build-record dist/public-export/tool-contract-drift-0.1.0a0-public-source.build.json \
  --manifest dist/public-export/tool-contract-drift-0.1.0a0-public-source.manifest.json \
  --checksum dist/public-export/tool-contract-drift-0.1.0a0-public-source.tar.gz.sha256 \
  --extract-to /tmp/tool-contract-drift-public
```

From the verified extraction root, run the file verifier above, without the Git history command. It checks every allowlisted byte against `PUBLIC_EXPORT_MANIFEST.json`, scans the PDF's reader-visible text, and recomputes the synthetic corpus identity, composition, count, finding set, Markdown and SARIF. Builder-recorded study-visibility and case-separation assertions are included, but their private inputs are excluded and cannot be independently rechecked from this export.

The manifest records build-tool versions and a declared oasdiff pin for separate private adapter evidence. The public 53-case command exercises a thin shared-semantics mapper, not native oasdiff. These byte and regression checks do not establish research validity. Release metadata records private staging separately from public publication; neither implies external validation.

</details>

<details>
<summary>Run synthetic regression checks and package audits</summary>

### Reproduce the Public Result

```bash
uv sync --locked
uv run python tool_contract_drift_cli.py validate-fixtures \
  --corpus public-reproduction-53 \
  --format json \
  --output public-fixture-validation.json
uv run python tool_contract_drift_cli.py lint \
  --corpus public-reproduction-53 \
  --format json \
  --output public-linter-report.json
```

The lint report must identify `public-reproduction-53`, 53 fixtures, and 25 total findings. These are regression-harness counts, not benchmark performance or ecosystem rates.

Reproduce the public carrier-pressure result:

```bash
uv run python tool_contract_drift_cli.py configured-baselines \
  --corpus public-reproduction-53 \
  --output public-configured-carriers.md \
  --json public-configured-carriers.json
```

The configured policy and thin oasdiff-style mapper must each map all 53 public cases under the authored policy. This is shared-policy transport parity, not an independent comparison or a zero-error performance claim.

Run the public distribution tests:

```bash
uv run python -m unittest discover -s public_tests -v
```

Build and inspect the Python artifacts:

```bash
uv build
python3 scripts/verify_built_distributions.py --dist dist
```

The wheel and source distribution contain the installed runtime, packaged public corpus and documented CLI/API behavior. They do not include the private checkout's full repository test suite or fixture tree. The CI workflow installs each artifact into a clean environment, reproduces the 53-case/25-finding result, checks shared-policy carrier parity, and verifies that the private corpus selector fails closed. Inspect the workflow run for the exact commit rather than treating this description as a test result.

### Legacy SARIF Output

```bash
uv run python tool_contract_drift_cli.py lint \
  --before examples/before_descriptor.json \
  --after examples/after_descriptor.json \
  --format sarif \
  --output tool-contract-drift.sarif
```

SARIF severity is a reapproval-triage signal, not a vulnerability severity.

## Policy and API

- `policy/tool-contract-drift-v1.json` is the versioned policy vocabulary.
- `docs/policy_spec.md` describes the rule intent and evidence boundary.
- `tool_contract_drift` exposes the alpha Python API.
- `action.yml` is the composite Action surface; use a local checkout until a real public repository and tag exist.

</details>

## Feedback

Use the structured issue forms for reproduction failures, label disputes, descriptor pairs, carrier alternatives, and provenance/licensing concerns. Read `docs/community_feedback_guide.md` and `docs/contributor_response_policy.md` first.

Counterexamples and negative results are welcome. If a submitted case is inspected or used to tune the policy, it is development evidence and will not be scored as held out in the same release.

## Citation

Jason M. Lovell, [ORCID 0009-0001-6300-9155](https://orcid.org/0009-0001-6300-9155). Use [CITATION.cff](CITATION.cff) and cite the exact commit or archive SHA-256. Add a DOI only after a resolving archival record exists and its artifact hash matches this export.

## License

Project code and all 53 public descriptor pairs are project-authored and MIT-licensed. `THIRD_PARTY_NOTICES.md` explains the separate metadata-only inventory retained for the private research corpus; it is not a permission claim for third-party descriptor bytes.

---

<sub>This is a personal research and development project. It is not affiliated with, endorsed by, or sponsored by my employer. Any views expressed are my own.</sub>
