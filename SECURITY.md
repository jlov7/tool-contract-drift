# Security Policy

This project is an experimental descriptor-review utility and research harness, not a security scanner.

Do not rely on Agent Tool Contract Drift findings as proof that an MCP/App tool is safe or unsafe. The linter only classifies static descriptor drift and does not execute tools, verify authorization, inspect server code, or validate runtime behavior.

## Supported Scope

In scope:

- bugs in the CLI, action, packaging, or generated SARIF that could mislead users about what was analyzed;
- accidental disclosure of private reviewer mapping, identity, or response data;
- repository or release-process issues that could cause overclaiming, unsafe publication, or confusing security-scanner framing.

Out of scope:

- claims that a third-party MCP/App tool is vulnerable solely because this policy emitted a review label;
- requests for production security certification;
- reports that require executing unknown third-party tools without a separate reproduction agreement.

## Reporting

No private reporting route is currently configured and verified. Do not submit sensitive reports through public issues. A redacted, non-sensitive reproduction may include the commit hash, command, minimal input descriptors and observed output. Keep secrets, private reviewer identities and payment/contact details out of reports.

## SARIF Boundary

SARIF output is for code-scanning-style triage and review workflow integration. It is not a vulnerability report. A SARIF `error` level means the policy marked descriptor drift as high-priority for review; it does not prove exploitability, unsafe runtime behavior, or authorization failure.

## Reviewer Data

Reviewer identities, contact channels, attribution decisions, returned-file hashes and conflict/exposure notes must stay out of public reports unless the reviewer explicitly opts in. The public distribution includes no study recruitment or consent package; do not solicit study participation through its issue forms.
