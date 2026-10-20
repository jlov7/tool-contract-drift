# Agent Tool Contract Drift Descriptor Drift Policy Specification

Status: implementation-neutral policy draft. The Python linter is the reference implementation, but this policy is intended to be portable to adapters, rulesets, or review workflows.

## Scope

Agent Tool Contract Drift evaluates static before/after MCP/App-style tool descriptors. It does not execute tools, inspect server code, verify authorization, or decide whether a tool is safe.

The policy input is a descriptor pair:

```json
{
  "before": {"tools": []},
  "after": {"tools": []}
}
```

Each tool is keyed by `name` and may include:

- `description`
- `input_schema`
- `output_schema`
- `output_template`
- `annotations`
- `auth.scopes`
- `security_schemes`
- `execution`
- `icons`
- `_meta`

## Policy Output

Each finding has:

- `fixture_id` or descriptor-pair id;
- `tool_name`;
- `risk`;
- `severity`;
- `reason`;
- evidence strings;
- generic baseline labels;
- `reapproval_required = true`.

Severity is a review triage hint, not a vulnerability rating.

## Labels

| Label | Severity | Trigger Intent | Review Question |
|---|---|---|---|
| `readonly_to_destructive` | high | A previously read-only tool moves toward write/destructive behavior through annotations, risky scopes, or side-effect text. | Does prior approval still apply if the tool can now mutate state or cause side effects? |
| `destructive_hint_escalation` | high | Effective `destructiveHint` changes from `false` to `true` after applying MCP defaults. | Does the tool need renewed review because destructive behavior is now explicit? |
| `destructive_hint_downgrade` | medium | An explicit `destructiveHint: true` changes to `false` while effective `readOnlyHint` remains `false`. | Is the descriptor changing destructive semantics without becoming read-only? |
| `description_injection_drift` | high | A tool description gains agent-instruction, prompt-injection, exfiltration, or hidden-instruction text. | Could the changed descriptor steer the model or reviewer outside the approved tool contract? |
| `auth_scope_expansion` | high | New auth scopes introduce write, delete, admin, payment, deploy, secret, or sensitive read capability. | Does the agent receive materially broader authority? |
| `closed_world_to_open_world_input` | medium | Input bounds loosen through supported local checks such as enum/const removal, required-field weakening, open object expansion, sound local `allOf` weakening, or `openWorldHint` escalation. | Can the agent now act over a broader or less predictable input space? |
| `schema_containment_unresolved` | medium | `$ref`, boolean schemas, non-monotonic combiners, or unsupported applicators prevent a sound local containment result. | Does a complete JSON Schema evaluation show widening, narrowing, or a mixed change? |
| `sensitive_output_template_drift` | high | Output template references change while sensitive output fields are added, or the new template reference names an existing sensitive field. | Is sensitive data now exposed in a different UI/resource boundary? |
| `sensitive_output_schema_expansion` | high | Output schema adds sensitive fields without an output-template change. | Did the descriptor add sensitive output without making the presentation boundary obvious? |
| `risky_tool_added` | high | A newly added tool has risky name, description, destructive annotation, or risky auth scopes. | Should a new tool with side-effect/admin/payment/secret behavior be approved before use? |

## Generic Baseline Labels

Agent Tool Contract Drift records generic labels only as comparison context:

- `tool_added`
- `tool_removed`
- `description_changed`
- `input_schema_changed`
- `output_schema_changed`
- `output_template_changed`
- `annotations_changed`
- `annotation_explicit_restatement`
- `annotation_safer_explicit`
- `annotation_actual_escalation`
- `annotation_mixed_semantics`
- `auth_changed`
- `security_schemes_changed`
- `execution_changed`
- `icons_changed`
- `metadata_changed`
- `extensions_changed`

Generic labels show what changed. Agent Tool Contract Drift labels state why a change may need agent-facing review.

## Output Template Boundary

Agent Tool Contract Drift does not fetch or execute output templates. The current `sensitive_output_template_drift` rule inspects descriptor-level `output_template` references and output-schema field names only. A hit means the descriptor changed the declared presentation/resource boundary in a way that appears sensitive enough to require review; it is not proof that a UI template actually renders the field. External reviewers or maintainers should inspect template contents before promoting this label beyond a reapproval heuristic.

## Rule Intent

### Read-only to destructive

Emit `readonly_to_destructive` when the old descriptor had `annotations.readOnlyHint: true` and the new descriptor gains one of:

- `annotations.destructiveHint: true`;
- `annotations.readOnlyHint: false`;
- a risky new auth scope;
- new side-effecting text.

### MCP annotation defaults and explicit declarations

The policy applies the MCP defaults before deciding whether annotation semantics changed: absent `readOnlyHint` is `false`, absent `destructiveHint` is `true`, absent `idempotentHint` is `false`, and absent `openWorldHint` is `true`.

Consequently, absent to explicit `readOnlyHint: false` and absent to explicit `destructiveHint: true` are restatements, not new-risk findings. Explicit `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, or `openWorldHint: false` declarations are safer directions. The generic baseline records these cases as `annotation_explicit_restatement` or `annotation_safer_explicit`; it uses `annotation_actual_escalation` only when an effective value becomes riskier, and `annotation_mixed_semantics` when directions differ.

The former `side_effect_annotation_added` and `missing_readonly_side_effect_annotation` heuristics are disabled and are not members of the versioned policy. Descriptor under-specification may still be raised for manual review, but it is not emitted as a machine finding in this release.

### Destructive hint escalation or downgrade

Emit `destructive_hint_escalation` when effective `destructiveHint` changes from `false` to `true` after applying MCP defaults. Adding explicit `destructiveHint: true` where the field was absent is therefore quiet apart from its generic restatement label.

Emit `destructive_hint_downgrade` when explicitly declared `destructiveHint` changes from `true` to `false` while the new descriptor's effective `readOnlyHint` is `false`. This rule does not inspect the tool name or description.

### Description injection drift

Emit `description_injection_drift` when a new or changed tool description introduces prompt-injection or agent-instruction text such as requests to ignore prior instructions, hidden/developer/system prompt language, exfiltration language, or direct instructions about how the assistant, agent, model, or LLM must behave.

Do not emit this label for ordinary documentation, usage copy, or product-description changes that do not instruct the agent or model.

### Auth scope expansion

Emit `auth_scope_expansion` when newly added scopes:

- widen a read-only scope to a broader provider scope;
- contain risky markers such as write, delete, admin, modify, send, deploy, payment, refund, charge, secret, credential, password, or token;
- grant read access to sensitive material such as secrets or payment credentials.

Read-only scopes for non-sensitive nouns should remain quiet.

### Closed-world to open-world input

Emit `closed_world_to_open_world_input` when a schema becomes less bounded through:

- `additionalProperties: false` becoming absent or non-false;
- `enum` removal;
- `const` removal;
- required-field weakening;
- sound local `allOf` weakening within the supported subset;
- nested object/array loosening;
- addition of a new open object property to a closed object;
- `annotations.openWorldHint` changing from `false` to `true`.

Changes involving `$ref`, `$dynamicRef`, boolean schemas, `oneOf`, `anyOf`, `not`, conditional/applicator keywords, or other unsupported containment cases emit `schema_containment_unresolved` for manual review. The policy does not infer containment from branch count alone.

### Sensitive output drift

Sensitive output names include token, secret, password, credential, and payment, excluding token usage counters such as `token_count`.

Emit `sensitive_output_template_drift` when the template reference changes and sensitive-looking output-schema fields are added or newly mentioned in that reference. This does not establish that a UI renders those fields.

Emit `sensitive_output_schema_expansion` when sensitive output fields are added while the output template does not change.

### Risky tool added

Emit `risky_tool_added` when a new tool has:

- `destructiveHint: true`;
- risky auth scopes;
- risky name or description markers such as charge, delete, deploy, payment, refund, secret, send, write, or run shell.

## Portability Contract

A compatible implementation should:

- preserve label names and severities unless it documents a versioned policy change;
- include enough evidence for a reviewer to understand the label;
- emit machine-readable output suitable for CI or review tooling;
- keep generic-diff labels separate from Agent Tool Contract Drift labels;
- state that labels are review/reapproval signals, not vulnerability findings.

## Versioning

This draft describes the versioned policy artifact in `policy/tool-contract-drift-v1.json` and the default behavior of `tool-contract-drift` `0.1.0a0`.

The CLI can print the machine-readable policy:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tool_contract_drift_cli.py explain-rules --format json
```

Repository-specific config can pin the policy version, enable or disable rules, override severity, suppress reviewed findings, and set SARIF metadata. See `policy/example-config.json`.

Schema and conformance artifacts:

- `policy/schema/tool-contract-drift-policy.schema.json`
- `policy/schema/tool-contract-drift-config.schema.json`
- `tool_contract_drift/fixtures/schema/tool-descriptor-fixture.schema.json`

The private research checkout's additional conformance guide is not included in this distribution.

Future versions should record:

- added or removed labels;
- changed severity defaults;
- changed sensitive/risky marker lists;
- corpus count changes;
- known compatibility breaks for generated reports or SARIF rule IDs.
