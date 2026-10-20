# Reproduction and source verification

The [released-version case study](../evaluation/README.md) and the synthetic policy
corpus answer different questions. Neither establishes detection accuracy or human
review benefit. This guide covers byte verification, synthetic regression checks
and package audits; the case study has its own acquisition recipe.

## Verify a fresh checkout

Run these checks before generating environments, caches or reports inside the
checkout. They require `pdftotext` from Poppler and Python 3.11 or later:

```bash
command -v pdftotext
PYTHONDONTWRITEBYTECODE=1 uv run --no-project python -B scripts/verify_public_export.py .
PYTHONDONTWRITEBYTECODE=1 uv run --no-project python -B scripts/verify_public_history.py .
```

The file verifier checks every shipped byte against `PUBLIC_EXPORT_MANIFEST.json`,
including file modes and the PDF's reader-visible text. It rejects extra or changed
files, including generated files. Use another fresh checkout for a later exact-byte
check. The history verifier requires a Git checkout, not an extracted archive.

The verifier also recomputes synthetic corpus identity, composition, counts,
findings, Markdown and SARIF. Private-study visibility and case-separation checks
are builder-recorded assertions: their inputs are excluded, so the public export
cannot independently recheck those assertions. These checks establish byte and
regression consistency, not research validity or independent attestation.

The manifest's `external_publication_authorized: false` means the builder grants
no publication permission. It does not describe separate owner approval or live
repository visibility. The study-sequence record describes an unlaunched study,
not the publication state of this utility.

### Separately supplied archives

GitHub's automatic source downloads are not the custom archive below. If an
archive and its sidecars are separately supplied, verify them before extraction:

```bash
uv run --no-project python -B scripts/verify_public_archive.py \
  dist/public-export/tool-contract-drift-0.1.0a0-public-source.tar.gz \
  --build-record dist/public-export/tool-contract-drift-0.1.0a0-public-source.build.json \
  --manifest dist/public-export/tool-contract-drift-0.1.0a0-public-source.manifest.json \
  --checksum dist/public-export/tool-contract-drift-0.1.0a0-public-source.tar.gz.sha256 \
  --extract-to artifacts/verified-public-source
```

Run the file verifier from the verified extraction root, without the history
command. The manifest records build-tool versions and a declared oasdiff pin for
separate private adapter evidence; that pin does not mean the public synthetic
command executes native oasdiff. Hosting metadata is a dated snapshot, not live
GitHub state. Repository availability is separate from a release, DOI or validation.

## Synthetic policy corpus

`public-reproduction-53` contains 53 project-authored synthetic descriptor pairs:
28 regression cases retained byte-for-byte from the private corpus's synthetic
rows, plus 25 newly authored quiet controls. Under `tool-contract-drift-v1`, it
produces 22 hold fixtures, 31 quiet/control fixtures and 25 finding instances.

The separate `private-canonical-65` corpus has 65 pairs, 26 holds, 39 quiet/control
fixtures and 30 findings. The public corpus excludes all 37 source-derived rows
and adds new controls. It is a separate manifest-bound identity, not a private-
corpus subset or an independent external reproduction. Public and installed
artifacts reject the private selector rather than silently substituting data.

No source-derived descriptor bytes are included in the public corpus. These are
synthetic regression checks, not real-source findings, prevalence estimates or
independent performance evidence. The released-version observations are separate;
their raw acquisitions are not redistributed.

```bash
uv sync --locked
uv run python tool_contract_drift_cli.py validate-fixtures \
  --corpus public-reproduction-53 --format json \
  --output artifacts/public-fixture-validation.json
uv run python tool_contract_drift_cli.py lint \
  --corpus public-reproduction-53 --format json \
  --output artifacts/public-linter-report.json
uv run python tool_contract_drift_cli.py configured-baselines \
  --corpus public-reproduction-53 \
  --output artifacts/public-configured-carriers.md \
  --json artifacts/public-configured-carriers.json
```

The lint report must identify 53 fixtures and 25 findings under
`public-reproduction-53`. The configured policy and thin oasdiff-style mapper each
map all 53 cases under the authored policy. These paths reuse or map the same
semantics. Their agreement shows portability and substitute pressure, not
independent comparator accuracy or a zero-error performance result.

## Tests and packages

```bash
uv run --locked python -m unittest discover -s public_tests -v
uv build
uv run --no-project python -B scripts/verify_built_distributions.py --dist dist
```

Wheel and source-distribution audits check exact member sets and source-controlled
bytes. CI installs each artifact into a clean environment, reproduces the public
corpus result and shared-policy parity, and rejects the private corpus selector.
Inspect the workflow result at the exact commit; this description is not a test
result. Packages contain the installed runtime and public corpus, not the private
checkout's full tests or source-derived fixtures.

The [structural correctness checks](../evaluation/structural_correctness.md) use
pinned development-only libraries. They provide bounded software evidence. There
is no external reviewer result, scored sealed evaluation, ethics approval claim,
live GitHub SARIF upload evidence, DOI, protocol endorsement or production-
readiness result.

## File roles

| Location | Purpose |
|---|---|
| `tool_contract_drift/`, `tool_contract_drift_cli.py` | Runtime, alpha Python API and historical CLI |
| `actions/descriptor-review/`, `action.yml` | Complete-inventory and legacy findings-only Actions, respectively |
| `examples/`, `docs/descriptor_review.md` | Runnable pairs, rendered report and reporting/privacy contract |
| `evaluation/` | Pinned case-study protocol, results, dependency lock and correctness-check method |
| `public_tests/`, `.github/workflows/` | Software regressions and hosted verification |
| `policy/`, `tool_contract_drift/policy/` | Inspectable policy plus the copy needed by installed packages |
| `tool_contract_drift/fixtures/` | Synthetic corpus inputs; empty historical files remain part of its hash identity |
| `reports/` | Regenerated synthetic Markdown and SARIF results |
| `paper/` | Frozen July methods paper, source, bibliography audit and source/PDF hash binding |
| `scripts/`, `release/`, `PUBLIC_EXPORT_MANIFEST.json` | Reproduction, byte/history/package verification and artifact metadata |
| `tool_contract_drift/data/` | Corpus/packaging contracts and metadata-only provenance inventory, not third-party payloads |
| `.github/ISSUE_TEMPLATE/`, contribution/security documents | Feedback, provenance and safe disclosure routes |

## Legacy SARIF

```bash
uv run python tool_contract_drift_cli.py lint \
  --before examples/before_descriptor.json \
  --after examples/after_descriptor.json \
  --format sarif --output artifacts/tool-contract-drift.sarif
```

SARIF severity is a reapproval-triage signal, not a vulnerability severity. Legacy
`lint`, root Action and SARIF output remain findings-only. A quiet result does not
mean the tool objects are unchanged. The [policy specification](policy_spec.md)
describes rule intent; the [review contract](descriptor_review.md) describes the
complete structural inventory and its limits.
