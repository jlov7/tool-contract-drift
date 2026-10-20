# Agent Tool Contract Drift

Agent Tool Contract Drift is an experimental utility for reviewing saved MCP tool descriptors. It shows structural changes alongside supplemental policy findings, so a quiet classifier does not hide an edit. It does not decide whether a change is safe or needs approval.

## Try It

Python 3.11 or later and [uv](https://docs.astral.sh/uv/) are required for this checkout command. The runtime has no third-party Python dependencies.

```bash
uv run python -m tool_contract_drift.review_cli \
  --before examples/before_descriptor.json \
  --after examples/after_descriptor.json --format json
```

The example produces four changed paths and three policy findings. The installed console command is `tool-descriptor-review`.

`changes` inventories structural tool-object changes; `policy_findings` is an incomplete heuristic interpretation. Every change remains visible even when the same tool triggers a finding. Object-key order and tool-array order are ignored; arrays inside a tool remain ordered and are reported as a single changed value. Acquisition metadata outside `tools` is not compared.

`--fail-on change` exits 1 for any structural change. `--fail-on findings` exits 1 only for policy findings. Default exit 0 indicates completion, not approval or a lack of changes. Reports contain descriptor values: check for confidential and third-party content before sharing them.

## Case Study

The [October 2026 case study](evaluation/README.md) compares 20 adjacent transitions from 25 pinned released package versions across three publisher families. Fourteen transitions changed descriptors; seven produced no historical policy findings. An independently implemented pinned comparator, [mcpdiff](https://github.com/samlader/mcpdiff), was quiet on two changed transitions. Neither count is a false-negative rate: the sample has no independent labels for approval, maliciousness or usefulness.

The new command preserves the structural inventory on those same observations. This is a regression check, not a held-out evaluation. A conventional JSON diff can provide structural visibility; no new diff algorithm or reviewer benefit is claimed. The case study includes a benign nested-description edit and explains the limits of the comparison.

The [July white paper](paper/agent-tool-contract-drift.pdf) is frozen historical policy/methods background, not a validated result or the current case study. Existing tools cover much of this area, including the adjacent [Cisco MCP Contract Toolkit](https://github.com/cisco-open/mcptoolkit-contract). Their scope and classifications differ, and neither project endorses this one.

## Limits

This release focuses on saved tool objects. It does not execute tools, verify authorization, find vulnerabilities or certify protocol conformance. The legacy `lint`, SARIF and Action paths remain findings-only. The historical public `capture` command uses the 2025 stdio handshake and has not been qualified as a general current-protocol capture tool.

There is no external reviewer result, scored sealed evaluation, ethics approval claim, live GitHub SARIF upload evidence, DOI, protocol endorsement or production-readiness claim. Code, analysis and local model review were AI-assisted; model review is not human peer review.

## Public Evidence Boundary

This public source export contains the manifest-verified `public-reproduction-53` corpus:

- 53 descriptor pairs;
- 53 project-authored synthetic records: 28 regression cases retained byte-for-byte from the private corpus's project-authored synthetic rows plus 25 newly authored quiet controls;
- 22 hold fixtures and 31 quiet/control fixtures;
- 25 emitted finding instances under `tool-contract-drift-v1`.

No source-derived descriptor bytes are part of this corpus. It provides synthetic regression checks, not real-source findings, prevalence evidence or independent performance evidence. Released-version observations are separate; their raw acquisitions are not redistributed.

The separate research/coordinator corpus is `private-canonical-65`: 65 pairs, 30 finding instances, 26 fixtures with holds, and 39 quiet/control fixtures. `public-reproduction-53` is a separate manifest-bound identity, not a subset of that corpus: it retains the 28 project-authored synthetic private-corpus rows byte-for-byte and adds 25 new synthetic controls, while excluding all 37 source-derived rows. It is not an independent external reproduction. The public export cannot select the private corpus and must fail instead of silently substituting these 53 cases.

Configured-policy and oasdiff-adapter parity on the private corpus are shared-policy carrier results. They show transportability and substitute pressure, not independent comparator accuracy or evidence that a standalone detector is novel.

## Verify the Source

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

## Reproduce the Public Result

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

## Descriptor-Pair Use

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

## Feedback

Use the structured issue forms for reproduction failures, label disputes, descriptor pairs, carrier alternatives, and provenance/licensing concerns. Read `docs/community_feedback_guide.md` and `docs/contributor_response_policy.md` first.

Counterexamples and negative results are welcome. If a submitted case is inspected or used to tune the policy, it is development evidence and will not be scored as held out in the same release.

## Citation

Use `CITATION.cff` and cite the exact commit or archive SHA-256. Add a DOI only after a resolving archival record exists and its artifact hash matches this export.

## License

Project code and all 53 public descriptor pairs are project-authored and MIT-licensed. `THIRD_PARTY_NOTICES.md` explains the separate metadata-only inventory retained for the private research corpus; it is not a permission claim for third-party descriptor bytes.
