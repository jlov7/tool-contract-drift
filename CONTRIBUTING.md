# Contributing

Contributions should preserve the no-overclaim boundary.

## Propose a Change

This repository is a curated source export. Submit an issue, minimal reproduction
or proposed patch. Maintainers integrate accepted changes into the canonical
source, then regenerate the export and its byte manifest. Do not refresh manifest
hashes or private-evidence attestations to make a patch pass.

An ordinary edit intentionally fails the exact-byte CI gate until that regeneration
happens. CI then stops before the public tests; that does not mean those tests
failed. Contributors can run them locally:

```bash
uv run --locked python -m unittest discover -s public_tests -v
```

The code remains MIT-licensed. This release process does not restrict modifying
or forking it. Full descriptor reports can contain sensitive or third-party text;
check proposed attachments before sharing them.

## Rules and Fixtures

Before proposing a new rule or fixture:

1. Add a regression test.
2. Explain the descriptor-review risk.
3. Include a control case where possible.
4. State whether the fixture is synthetic, public commit-backed, or reviewer-labeled.
5. Avoid claims of standards, security, or production validation unless the evidence supports them.
