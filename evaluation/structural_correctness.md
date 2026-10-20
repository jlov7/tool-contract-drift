# Independent Structural Correctness Checks

The test module calls only the public `review_descriptor_pair` API. It imports no
production canonicalization or diff helpers and does not use the practical
evaluation comparator, corpus, runner or receipts. [DeepDiff 9.1.0](https://zepworks.com/deepdiff/9.1.0/)
and [jsonpatch 1.36](https://github.com/stefankoegl/python-json-patch) are pinned
development-only dependencies, not runtime dependencies. Missing
dependencies fail test import; no checks are skipped.

## Method

Raw tools become `{"tools": {name: tool}}`. DeepDiff tree view supplies expected
operation/path sets with `threshold_to_diff_deeper=0`,
`ignore_private_variables=False` and `ignore_order=False`. It handles dictionary
traversal, whole object/tool additions and removals, scalar values and type
changes. The adapter uses structured tree paths, not parsed path strings.

Two explicit leaf conventions are adjudicated. Arrays inside tools are ordered
and atomic, so a custom DeepDiff operator compares their canonical JSON bytes
and emits one replacement without descending. Floating signed zero also uses
JSON bytes. The operator does not traverse dictionaries or implement recursive
diffing. Type-sensitive serialization distinguishes Boolean/number, integer/float
spellings (`1` versus `1.0`), and `0.0` versus `-0.0`; object keys are sorted and
Unicode is escaped without normalization. Nonfinite numbers and non-JSON Python
objects are outside the generated domain.

Raw DeepDiff is not an unqualified JSON-byte oracle: the pinned version reports
no difference for `0.0`/`-0.0`, `[True]`/`[1]`, `[1]`/`[1.0]` and
`[0.0]`/`[-0.0]`. Dedicated tests retain each raw-library disagreement, assert the
distinct serialized values and check the explicit leaf adjudication. Scalars
`True`/`1` and `1`/`1.0` are detected as type changes. These conventions are part
of the tested contract, not evidence that raw DeepDiff agrees on every input.

Beyond operation/path-set agreement, every report is converted to jsonpatch
operations and applied to the name-keyed representation. The reconstructed
target and reverse-operation restoration must match type-sensitive canonical
JSON bytes exactly. Reported old/new values are checked at their pointers,
duplicate operations fail, hashes are recomputed independently, and insertion-
order-sensitive source snapshots must remain unchanged. These are **test
representation pointers**, not JSON Patch paths into raw `tools/list` arrays.

## Bounds and Cases

The generator produces 400 pairs (100 each for seeds `7`, `101`, `20261020`,
`8675309`). Each descriptor has at most three valid named tools, three arbitrary
extension fields per tool, and JSON containers at most three levels deep within
each extension, with at most three children per container. Scalars come from a
fixed finite pool. Each serialized descriptor is capped by assertion at 32 KiB.
Every fifth pair has independently generated sides; other pairs mutate extension
fields on retained tools. Both input schema aliases are exercised.

Explicit cases cover escaped names/keys, empty keys, private-looking keys,
Unicode, null versus missing, numeric conventions, atomic arrays and reordering,
whole additions/removals, and simultaneous labeled/unlabeled changes on one tool.
Twenty object-key/outer-tool permutations check identity, changed-path stability
and hash consistency; inner array order is preserved during those permutations.

## Reproduction and Limits

From the public export with the development dependencies installed:

```bash
uv run python -m unittest discover -s public_tests -p test_descriptor_review_oracle.py
```

This is bounded synthetic structural evidence, not proof for all inputs. Shared
contract choices and JSON serialization remain possible common-mode errors.
The checks do not establish security, semantic compatibility, policy completeness,
human usefulness or runtime tool behavior. No frozen evaluation result is changed.
