# Agent Tool Contract Drift Report

Corpus identity: `public-reproduction-53`; fixtures: 53; boundary: fully synthetic public-package reproduction corpus; the separate source-metadata inventory contains no source-derived descriptor bytes and grants no permission.

| Fixture | Tool | Risk | Severity | Generic Baseline Labels | Reason |
|---|---|---|---|---|---|
| fixture-001-readonly-to-destructive | search_docs | readonly_to_destructive | high | description_changed, auth_changed, annotations_changed, annotation_actual_escalation | Tool moved from read-only semantics toward destructive or write-capable behavior. |
| fixture-001-readonly-to-destructive | search_docs | destructive_hint_escalation | high | description_changed, auth_changed, annotations_changed, annotation_actual_escalation | Existing tool changed from explicitly non-destructive to destructive. |
| fixture-001-readonly-to-destructive | search_docs | auth_scope_expansion | high | description_changed, auth_changed, annotations_changed, annotation_actual_escalation | New auth scopes increase write, delete, admin, payment, deploy, or secret capability. |
| fixture-002-auth-scope-expansion | crm_lookup | readonly_to_destructive | high | description_changed, auth_changed | Tool moved from read-only semantics toward destructive or write-capable behavior. |
| fixture-002-auth-scope-expansion | crm_lookup | auth_scope_expansion | high | description_changed, auth_changed | New auth scopes increase write, delete, admin, payment, deploy, or secret capability. |
| fixture-003-closed-to-open-world | deploy_preview | closed_world_to_open_world_input | medium | description_changed, input_schema_changed | Input schema or open-world annotation loosened bounds on the agent action space. |
| fixture-004-sensitive-output-template-drift | list_invoices | sensitive_output_template_drift | high | description_changed, output_template_changed, output_schema_changed | Output template changed while sensitive output fields appeared or became rendered. |
| fixture-005-risky-tool-count-expansion | run_shell | risky_tool_added | high | tool_added | New tool introduces write, admin, shell, deploy, payment, or destructive capability. |
| adversarial-001-sensitive-readonly-disclosure-not-destructive | list_invoices | sensitive_output_template_drift | high | description_changed, output_template_changed, output_schema_changed | Output template changed while sensitive output fields appeared or became rendered. |
| adversarial-002-nested-enum-removal | deploy_preview | closed_world_to_open_world_input | medium | input_schema_changed | Input schema or open-world annotation loosened bounds on the agent action space. |
| adversarial-003-additional-properties-removed | update_record | closed_world_to_open_world_input | medium | input_schema_changed | Input schema or open-world annotation loosened bounds on the agent action space. |
| adversarial-004-array-item-enum-removal | process_actions | closed_world_to_open_world_input | medium | input_schema_changed | Input schema or open-world annotation loosened bounds on the agent action space. |
| adversarial-005-open-world-hint-escalation | fetch_url | closed_world_to_open_world_input | medium | annotations_changed, annotation_actual_escalation | Input schema or open-world annotation loosened bounds on the agent action space. |
| adversarial-006-provider-modify-scope | gmail_search | auth_scope_expansion | high | auth_changed | New auth scopes increase write, delete, admin, payment, deploy, or secret capability. |
| adversarial-009-name-only-risky-tool-added | delete_document | risky_tool_added | high | tool_added | New tool introduces write, admin, shell, deploy, payment, or destructive capability. |
| adversarial-010-readonly-description-becomes-delete-with-stale-readonly | invoice_lookup | readonly_to_destructive | high | description_changed | Tool moved from read-only semantics toward destructive or write-capable behavior. |
| adversarial-011-provider-broad-drive-scope-expansion | drive_search | auth_scope_expansion | high | auth_changed | New auth scopes increase write, delete, admin, payment, deploy, or secret capability. |
| adversarial-014-nested-sensitive-output-template-drift | session_status | sensitive_output_template_drift | high | output_template_changed, output_schema_changed | Output template changed while sensitive output fields appeared or became rendered. |
| adversarial-015-sensitive-template-existing-field-rendered | oauth_session | sensitive_output_template_drift | high | output_template_changed | Output template changed while sensitive output fields appeared or became rendered. |
| adversarial-016-new-open-object-property-expansion | update_export | closed_world_to_open_world_input | medium | input_schema_changed | Input schema or open-world annotation loosened bounds on the agent action space. |
| adversarial-017-bounded-optional-property-control | read_export | closed_world_to_open_world_input | medium | input_schema_changed | Input schema or open-world annotation loosened bounds on the agent action space. |
| adversarial-018-sensitive-readonly-scope-expansion | vault_secret_read | auth_scope_expansion | high | description_changed, auth_changed | New auth scopes increase write, delete, admin, payment, deploy, or secret capability. |
| adversarial-019-sensitive-output-schema-expansion-no-template-change | payment_session | sensitive_output_schema_expansion | high | output_schema_changed | Output schema added sensitive fields without an output-template change to make the disclosure boundary obvious. |
| adversarial-020-money-movement-tool-added | charge_card | risky_tool_added | high | tool_added | New tool introduces write, admin, shell, deploy, payment, or destructive capability. |
| adversarial-021-destructive-hint-downgrade-with-delete-text | delete_export_jobs | destructive_hint_downgrade | medium | annotations_changed, annotation_safer_explicit | Existing non-read-only tool changed from the destructive default or an explicit destructive hint to non-destructive. |

## Summary

- Total findings: 25
- High severity: 17
- Medium severity: 8
- Reapproval required: 25
