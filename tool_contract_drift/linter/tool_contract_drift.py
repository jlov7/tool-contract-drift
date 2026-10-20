from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RISKY_SCOPE_MARKERS = (
    "act_as",
    "admin",
    "cancel",
    "charge",
    "delete",
    "deploy",
    "execute sql",
    "impersonate",
    "manage",
    "modify",
    "pay",
    "payment",
    "post",
    "refund",
    "secret",
    "send",
    "transfer",
    "write",
)
RISKY_DESCRIPTION_MARKERS = (
    "charge",
    "delete",
    "deploy",
    "execute sql",
    "pay",
    "payment",
    "refund",
    "run shell",
    "secret",
    "send",
    "transfer",
    "write",
)
SIDE_EFFECT_TEXT_MARKERS = (
    "activate",
    "charge",
    "connect",
    "create",
    "deactivate",
    "delete",
    "deregister",
    "execute sql",
    "import",
    "pay",
    "publish",
    "refund",
    "register",
    "remove",
    "send",
    "sign",
    "start",
    "stop",
    "submit",
    "sync",
    "transfer",
    "update",
    "upload",
    "write",
)
SENSITIVE_OUTPUT_MARKERS = ("token", "secret", "secrets", "password", "credential", "payment")
DESCRIPTION_INJECTION_MARKERS = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the user's instructions",
    "disregard previous instructions",
    "disregard the user's instructions",
    "system prompt",
    "developer message",
    "hidden instructions",
    "do not reveal",
    "exfiltrate",
)
DESCRIPTION_INJECTION_PATTERNS = (
    re.compile(r"\b(assistant|agent|model|llm)\b.{0,80}\b(must|should|always|never)\b", re.IGNORECASE),
    re.compile(r"\b(must|should|always|never)\b.{0,80}\b(assistant|agent|model|llm)\b", re.IGNORECASE),
)
TOOL_ANNOTATION_DEFAULTS = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}
SAFER_TOOL_ANNOTATION_VALUES = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
SCHEMA_MANUAL_REVIEW_KEYWORDS = frozenset(
    {
        "$dynamicRef",
        "$ref",
        "contains",
        "dependentRequired",
        "dependentSchemas",
        "else",
        "if",
        "maxContains",
        "minContains",
        "not",
        "patternProperties",
        "prefixItems",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
SCHEMA_MANUAL_CHANGE_KEYWORDS = frozenset(
    {
        "$schema",
        "format",
        "maxProperties",
        "minProperties",
        "multipleOf",
        "type",
        "uniqueItems",
    }
)
WORD_BOUNDARY_MARKERS = frozenset(
    {
        "activate",
        "admin",
        "cancel",
        "charge",
        "connect",
        "create",
        "deactivate",
        "delete",
        "deploy",
        "deregister",
        "execute sql",
        "import",
        "impersonate",
        "manage",
        "modify",
        "pay",
        "payment",
        "post",
        "publish",
        "refund",
        "register",
        "remove",
        "send",
        "sign",
        "secrets",
        "start",
        "stop",
        "submit",
        "sync",
        "transfer",
        "update",
        "upload",
        "write",
        "token",
        "secret",
        "password",
        "credential",
    }
)


@dataclass(frozen=True)
class GenericDiff:
    fixture_id: str
    tool_name: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class RiskFinding:
    fixture_id: str
    tool_name: str
    risk: str
    severity: str
    reason: str
    evidence: tuple[str, ...]
    generic_baseline_labels: tuple[str, ...]
    reapproval_required: bool = True


def load_fixtures(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text())


def generic_diff_baseline(fixture: dict[str, Any]) -> list[GenericDiff]:
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    diffs: list[GenericDiff] = []
    for name in sorted(set(before) | set(after)):
        labels: list[str] = []
        if name not in before:
            labels.append("tool_added")
        elif name not in after:
            labels.append("tool_removed")
        else:
            old = before[name]
            new = after[name]
            if old.get("description") != new.get("description"):
                labels.append("description_changed")
            if old.get("input_schema") != new.get("input_schema"):
                labels.append("input_schema_changed")
            if old.get("auth") != new.get("auth"):
                labels.append("auth_changed")
            if old.get("output_template") != new.get("output_template"):
                labels.append("output_template_changed")
            if old.get("output_schema") != new.get("output_schema"):
                labels.append("output_schema_changed")
            if old.get("annotations") != new.get("annotations"):
                labels.append("annotations_changed")
                annotation_change = _annotation_change_classification(old, new)
                if annotation_change:
                    labels.append(annotation_change)
            if old.get("security_schemes") != new.get("security_schemes"):
                labels.append("security_schemes_changed")
            if old.get("execution") != new.get("execution"):
                labels.append("execution_changed")
            if old.get("icons") != new.get("icons"):
                labels.append("icons_changed")
            if old.get("_meta") != new.get("_meta"):
                labels.append("metadata_changed")
            if old.get("extensions") != new.get("extensions"):
                labels.append("extensions_changed")
        if labels:
            diffs.append(GenericDiff(fixture["id"], name, tuple(labels)))
    return diffs


def lint_fixture(fixture: dict[str, Any]) -> list[RiskFinding]:
    baseline = {item.tool_name: item.labels for item in generic_diff_baseline(fixture)}
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    findings: list[RiskFinding] = []
    for name in sorted(set(before) | set(after)):
        if name not in before:
            findings.extend(_lint_added_tool(fixture["id"], name, after[name], baseline.get(name, ())))
            continue
        if name not in after:
            continue
        findings.extend(_lint_changed_tool(fixture["id"], name, before[name], after[name], baseline.get(name, ())))
    return findings


def lint_fixtures(fixtures: list[dict[str, Any]]) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for fixture in fixtures:
        findings.extend(lint_fixture(fixture))
    return findings


def summarize(findings: list[RiskFinding]) -> dict[str, int]:
    summary = {"total_findings": len(findings), "high": 0, "medium": 0, "reapproval_required": 0}
    for finding in findings:
        summary[finding.severity] += 1
        if finding.reapproval_required:
            summary["reapproval_required"] += 1
    return summary


def render_markdown(findings: list[RiskFinding]) -> str:
    lines = [
        "# Agent Tool Contract Drift Report",
        "",
        "| Fixture | Tool | Risk | Severity | Generic Baseline Labels | Reason |",
        "|---|---|---|---|---|---|",
    ]
    for item in findings:
        labels = ", ".join(item.generic_baseline_labels) if item.generic_baseline_labels else "-"
        lines.append(
            f"| {item.fixture_id} | {item.tool_name} | {item.risk} | {item.severity} | "
            f"{labels} | {item.reason} |"
        )
    summary = summarize(findings)
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Total findings: {summary['total_findings']}",
            f"- High severity: {summary['high']}",
            f"- Medium severity: {summary['medium']}",
            f"- Reapproval required: {summary['reapproval_required']}",
        ]
    )
    return "\n".join(lines) + "\n"


def _lint_added_tool(fixture_id: str, name: str, tool: dict[str, Any], baseline_labels: tuple[str, ...]) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    if _has_description_injection_text(tool) or _has_tool_description_injection_text({}, tool):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "description_injection_drift",
                "high",
                "Tool description contains agent-instruction or prompt-injection text that can alter review and approval semantics.",
                (_describe_tool(tool),),
                baseline_labels,
            )
        )
    if _is_risky_tool(tool):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "risky_tool_added",
                "high",
                "New tool introduces write, admin, shell, deploy, payment, or destructive capability.",
                (_describe_tool(tool),),
                baseline_labels,
            )
        )
    return findings


def _lint_changed_tool(
    fixture_id: str,
    name: str,
    old: dict[str, Any],
    new: dict[str, Any],
    baseline_labels: tuple[str, ...],
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    if _became_destructive(old, new):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "readonly_to_destructive",
                "high",
                "Tool moved from read-only semantics toward destructive or write-capable behavior.",
                (_describe_tool(old), _describe_tool(new)),
                baseline_labels,
            )
        )
    if _destructive_hint_escalated(old, new):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "destructive_hint_escalation",
                "high",
                "Existing tool changed from explicitly non-destructive to destructive.",
                (_describe_tool(old), _describe_tool(new)),
                baseline_labels,
            )
        )
    if _destructive_hint_downgraded(old, new):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "destructive_hint_downgrade",
                "medium",
                "Existing non-read-only tool changed from the destructive default or an explicit destructive hint to non-destructive.",
                (_describe_tool(old), _describe_tool(new)),
                baseline_labels,
            )
        )
    if _has_tool_description_injection_text(old, new):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "description_injection_drift",
                "high",
                "Tool description gained agent-instruction or prompt-injection text that can alter review and approval semantics.",
                (_describe_tool(old), _describe_tool(new)),
                baseline_labels,
            )
        )
    new_scopes = sorted(_scopes(new) - _scopes(old))
    risky_scopes = [scope for scope in new_scopes if _is_risky_scope(scope, _scopes(old))]
    if risky_scopes:
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "auth_scope_expansion",
                "high",
                "New auth scopes increase write, delete, admin, payment, deploy, or secret capability.",
                tuple(risky_scopes),
                baseline_labels,
            )
        )
    old_input_schema = old.get("input_schema", {})
    new_input_schema = new.get("input_schema", {})
    if _closed_world_became_open(old_input_schema, new_input_schema) or _open_world_hint_escalated(old, new):
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "closed_world_to_open_world_input",
                "medium",
                "Input schema or open-world annotation loosened bounds on the agent action space.",
                ("input_schema/openWorldHint",),
                baseline_labels,
            )
        )
    schema_review_reasons = _schema_containment_review_reasons(old_input_schema, new_input_schema)
    if schema_review_reasons:
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "schema_containment_unresolved",
                "medium",
                "Input-schema containment cannot be established safely for this change; manual review is required.",
                schema_review_reasons,
                baseline_labels,
            )
        )
    sensitive_outputs = _sensitive_output_template_fields(old, new)
    if old.get("output_template") != new.get("output_template") and sensitive_outputs:
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "sensitive_output_template_drift",
                "high",
                "Output template changed while sensitive output fields appeared or became rendered.",
                tuple(sensitive_outputs),
                baseline_labels,
            )
        )
    sensitive_schema_outputs = _new_sensitive_output_fields(old, new)
    if old.get("output_template") == new.get("output_template") and sensitive_schema_outputs:
        findings.append(
            RiskFinding(
                fixture_id,
                name,
                "sensitive_output_schema_expansion",
                "high",
                "Output schema added sensitive fields without an output-template change to make the disclosure boundary obvious.",
                tuple(sensitive_schema_outputs),
                baseline_labels,
            )
        )
    return findings


def _tool_map(descriptor: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {tool["name"]: tool for tool in descriptor.get("tools", [])}


def _scopes(tool: dict[str, Any]) -> set[str]:
    return set(tool.get("auth", {}).get("scopes", []))


def _became_destructive(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_annotations = _effective_tool_annotations(old)
    new_annotations = _effective_tool_annotations(new)
    was_readonly = old_annotations["readOnlyHint"] is True
    became_write_annotated = (
        new_annotations["readOnlyHint"] is False
        or (
            old_annotations["destructiveHint"] is False
            and new_annotations["destructiveHint"] is True
            and new_annotations["readOnlyHint"] is False
        )
    )
    gained_risky_scope = any(_is_risky_scope(scope, _scopes(old)) for scope in _scopes(new) - _scopes(old))
    gained_side_effect_text = _has_side_effect_text(new) and not _has_side_effect_text(old)
    return was_readonly and (became_write_annotated or gained_risky_scope or gained_side_effect_text)


def _side_effect_annotation_added(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_annotations = old.get("annotations", {})
    new_annotations = new.get("annotations", {})
    old_had_side_effect_hint = "readOnlyHint" in old_annotations or "destructiveHint" in old_annotations
    new_added_side_effect_hint = any(
        key in new_annotations and key not in old_annotations for key in ("readOnlyHint", "destructiveHint")
    )
    return (
        not old_had_side_effect_hint
        and new_added_side_effect_hint
        and _annotation_change_classification(old, new) == "annotation_actual_escalation"
    )


def _destructive_hint_escalated(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_annotations = _effective_tool_annotations(old)
    new_annotations = _effective_tool_annotations(new)
    return old_annotations["destructiveHint"] is False and new_annotations["destructiveHint"] is True


def _destructive_hint_downgraded(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_raw = old.get("annotations", {}) if isinstance(old.get("annotations", {}), dict) else {}
    new_raw = new.get("annotations", {}) if isinstance(new.get("annotations", {}), dict) else {}
    new_annotations = _effective_tool_annotations(new)
    return (
        old_raw.get("destructiveHint") is True
        and new_raw.get("destructiveHint") is False
        and new_annotations["readOnlyHint"] is False
    )


def _open_world_hint_escalated(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_annotations = _effective_tool_annotations(old)
    new_annotations = _effective_tool_annotations(new)
    return old_annotations["openWorldHint"] is False and new_annotations["openWorldHint"] is True


def _missing_readonly_side_effect_annotation(old: dict[str, Any], new: dict[str, Any]) -> bool:
    del old, new
    return False


def _effective_tool_annotations(tool: dict[str, Any]) -> dict[str, bool]:
    annotations = tool.get("annotations", {})
    if not isinstance(annotations, dict):
        annotations = {}
    return {
        key: annotations.get(key, default) if isinstance(annotations.get(key, default), bool) else default
        for key, default in TOOL_ANNOTATION_DEFAULTS.items()
    }


def _annotation_change_classification(old: dict[str, Any], new: dict[str, Any]) -> str | None:
    old_raw = old.get("annotations", {}) if isinstance(old.get("annotations", {}), dict) else {}
    new_raw = new.get("annotations", {}) if isinstance(new.get("annotations", {}), dict) else {}
    changed_hint_keys = {
        key
        for key in TOOL_ANNOTATION_DEFAULTS
        if old_raw.get(key, TOOL_ANNOTATION_DEFAULTS[key]) != new_raw.get(key, TOOL_ANNOTATION_DEFAULTS[key])
        or (key in old_raw) != (key in new_raw)
    }
    if not changed_hint_keys:
        return None
    old_effective = _effective_tool_annotations(old)
    new_effective = _effective_tool_annotations(new)
    changed_effective_keys = {key for key in TOOL_ANNOTATION_DEFAULTS if old_effective[key] != new_effective[key]}
    if not changed_effective_keys:
        return "annotation_explicit_restatement"

    directions = {
        "safer" if new_effective[key] == SAFER_TOOL_ANNOTATION_VALUES[key] else "riskier"
        for key in changed_effective_keys
    }
    if directions == {"safer"}:
        return "annotation_safer_explicit"
    if directions == {"riskier"}:
        return "annotation_actual_escalation"
    return "annotation_mixed_semantics"


def _is_risky_tool(tool: dict[str, Any]) -> bool:
    if tool.get("annotations", {}).get("destructiveHint") is True:
        return True
    if any(_is_risky_scope(scope, set()) for scope in _scopes(tool)):
        return True
    return _contains_any(f"{tool.get('name', '')} {tool.get('description', '')}", RISKY_DESCRIPTION_MARKERS)


def _closed_world_became_open(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> bool:
    if not isinstance(old_schema, dict) or not isinstance(new_schema, dict):
        return False
    if old_schema.get("additionalProperties") is False and new_schema.get("additionalProperties", True) is not False:
        return True
    if "enum" in old_schema and "enum" not in new_schema:
        return True
    if _enum_weakened(old_schema.get("enum"), new_schema.get("enum")):
        return True
    if "const" in old_schema and "const" not in new_schema:
        return True
    if "pattern" in old_schema and "pattern" not in new_schema:
        return True
    if _schema_bounds_weakened(old_schema, new_schema):
        return True
    old_required = set(old_schema.get("required", []))
    new_required = set(new_schema.get("required", []))
    if old_required and not old_required.issubset(new_required):
        return True
    if _closed_world_combiner_weakened(old_schema, new_schema):
        return True

    old_props = old_schema.get("properties", {}) if isinstance(old_schema.get("properties", {}), dict) else {}
    new_props = new_schema.get("properties", {}) if isinstance(new_schema.get("properties", {}), dict) else {}
    for name, old_prop in old_props.items():
        if name in new_props and _closed_world_became_open(old_prop, new_props[name]):
            return True
    if old_schema.get("additionalProperties") is False:
        new_required = set(new_schema.get("required", []))
        for name in new_props:
            if name not in old_props and name not in new_required:
                return True
    old_items = old_schema.get("items")
    new_items = new_schema.get("items")
    if isinstance(old_items, dict) and isinstance(new_items, dict):
        return _closed_world_became_open(old_items, new_items)
    return False


def _schema_bounds_weakened(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> bool:
    for key in ("maxLength", "maxItems", "maximum", "exclusiveMaximum"):
        if key in old_schema and _upper_bound_weakened(old_schema.get(key), new_schema.get(key)):
            return True
    for key in ("minLength", "minItems", "minimum", "exclusiveMinimum"):
        if key in old_schema and _lower_bound_weakened(old_schema.get(key), new_schema.get(key)):
            return True
    return False


def _enum_weakened(old_enum: Any, new_enum: Any) -> bool:
    if not isinstance(old_enum, list) or not isinstance(new_enum, list):
        return False
    old_values = {json.dumps(value, sort_keys=True) for value in old_enum}
    new_values = {json.dumps(value, sort_keys=True) for value in new_enum}
    return bool(old_values) and old_values < new_values


def _upper_bound_weakened(old_value: Any, new_value: Any) -> bool:
    if not isinstance(old_value, (int, float)):
        return False
    if not isinstance(new_value, (int, float)):
        return True
    return new_value > old_value


def _lower_bound_weakened(old_value: Any, new_value: Any) -> bool:
    if not isinstance(old_value, (int, float)):
        return False
    if not isinstance(new_value, (int, float)):
        return True
    return new_value < old_value


def _schema_admits_open_input(schema: Any) -> bool:
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == "object":
        if schema.get("additionalProperties", True) is not False:
            return True
        props = schema.get("properties", {})
        if isinstance(props, dict):
            return any(_schema_admits_open_input(prop) for prop in props.values())
    items = schema.get("items")
    if isinstance(items, dict) and _schema_admits_open_input(items):
        return True
    for key in ("oneOf", "anyOf"):
        options = schema.get(key)
        if isinstance(options, list) and any(_schema_admits_open_input(option) for option in options):
            return True
    options = schema.get("allOf")
    if isinstance(options, list) and options and all(_schema_admits_open_input(option) for option in options):
        return True
    return False


def _closed_world_combiner_weakened(old_schema: dict[str, Any], new_schema: dict[str, Any]) -> bool:
    old_options = old_schema.get("allOf")
    new_options = new_schema.get("allOf")
    if old_options and not new_options:
        return True
    if not isinstance(old_options, list) or not isinstance(new_options, list):
        return False
    old_values = {_canonical_json(option) for option in old_options}
    new_values = {_canonical_json(option) for option in new_options}
    return bool(new_values) and new_values < old_values


def _schema_containment_review_reasons(old_schema: Any, new_schema: Any) -> tuple[str, ...]:
    if old_schema == new_schema:
        return ()
    reasons: set[str] = set()
    _collect_schema_review_reasons(old_schema, new_schema, "$", reasons)
    return tuple(sorted(reasons))


def _collect_schema_review_reasons(old_schema: Any, new_schema: Any, path: str, reasons: set[str]) -> None:
    if old_schema == new_schema:
        return
    if isinstance(old_schema, bool) or isinstance(new_schema, bool):
        reasons.add(f"{path}: boolean-schema containment changed")
        return
    if not isinstance(old_schema, dict) or not isinstance(new_schema, dict):
        reasons.add(f"{path}: schema shape changed outside the supported object subset")
        return

    present_manual_keywords = sorted((set(old_schema) | set(new_schema)) & SCHEMA_MANUAL_REVIEW_KEYWORDS)
    for key in present_manual_keywords:
        if old_schema.get(key) != new_schema.get(key) or key in {"$ref", "$dynamicRef"}:
            reasons.add(f"{path}: {key} requires reference/applicator-aware containment review")
    for key in sorted(SCHEMA_MANUAL_CHANGE_KEYWORDS):
        if old_schema.get(key) != new_schema.get(key):
            reasons.add(f"{path}: {key} containment is outside the proven local subset")

    _collect_combiner_review_reason(old_schema, new_schema, path, "allOf", reasons)
    _collect_combiner_review_reason(old_schema, new_schema, path, "anyOf", reasons)
    _collect_combiner_review_reason(old_schema, new_schema, path, "oneOf", reasons)

    old_properties = old_schema.get("properties", {})
    new_properties = new_schema.get("properties", {})
    if isinstance(old_properties, dict) and isinstance(new_properties, dict):
        removed_properties = sorted(set(old_properties) - set(new_properties))
        if removed_properties and old_schema.get("additionalProperties", True) is not False:
            reasons.add(f"{path}.properties: removed constrained properties require manual containment review")
        for name in sorted(set(old_properties) & set(new_properties)):
            _collect_schema_review_reasons(
                old_properties[name],
                new_properties[name],
                f"{path}.properties.{name}",
                reasons,
            )

    old_items = old_schema.get("items")
    new_items = new_schema.get("items")
    if old_items is not None or new_items is not None:
        if isinstance(old_items, dict) and isinstance(new_items, dict):
            _collect_schema_review_reasons(old_items, new_items, f"{path}.items", reasons)
        elif old_items != new_items:
            reasons.add(f"{path}.items: tuple/boolean or missing-item containment requires manual review")

    old_additional = old_schema.get("additionalProperties")
    new_additional = new_schema.get("additionalProperties")
    if (isinstance(old_additional, dict) or isinstance(new_additional, dict)) and old_additional != new_additional:
        reasons.add(f"{path}.additionalProperties: schema-valued containment requires manual review")


def _collect_combiner_review_reason(
    old_schema: dict[str, Any],
    new_schema: dict[str, Any],
    path: str,
    key: str,
    reasons: set[str],
) -> None:
    old_options = old_schema.get(key)
    new_options = new_schema.get(key)
    if old_options == new_options:
        return
    if key == "allOf" and isinstance(old_options, list) and isinstance(new_options, list):
        old_values = {_canonical_json(option) for option in old_options}
        new_values = {_canonical_json(option) for option in new_options}
        if old_values <= new_values or new_values < old_values:
            return
    if key == "allOf" and old_options and not new_options:
        return
    reasons.add(f"{path}.{key}: branch-count or branch-content comparison is not a containment proof")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sensitive_output_template_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    new_fields = set(_sensitive_output_fields(new.get("output_schema", {})))
    rendered_existing = {
        field
        for field in new_fields
        if _template_mentions_field(new.get("output_template", ""), field)
        and not _template_mentions_field(old.get("output_template", ""), field)
    }
    return sorted(set(_new_sensitive_output_fields(old, new)) | rendered_existing)


def _new_sensitive_output_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    old_fields = set(_sensitive_output_fields(old.get("output_schema", {})))
    new_fields = set(_sensitive_output_fields(new.get("output_schema", {})))
    return sorted(new_fields - old_fields)


def _sensitive_output_fields(schema: Any, prefix: str = "") -> list[str]:
    if not isinstance(schema, dict):
        return []
    fields: list[str] = []
    props = schema.get("properties", {})
    if isinstance(props, dict):
        for name, prop in props.items():
            path = f"{prefix}.{name}" if prefix else name
            if _is_sensitive_output_name(name):
                fields.append(path)
            fields.extend(_sensitive_output_fields(prop, path))
    items = schema.get("items")
    if isinstance(items, dict):
        fields.extend(_sensitive_output_fields(items, f"{prefix}[]" if prefix else "[]"))
    for key in ("oneOf", "anyOf", "allOf"):
        options = schema.get(key)
        if isinstance(options, list):
            for option in options:
                fields.extend(_sensitive_output_fields(option, prefix))
    return fields


def _is_sensitive_output_name(name: str) -> bool:
    lower = name.lower()
    if re.search(r"(?<![a-z0-9])tokens?[_-]?(count|used|usage)(?![a-z0-9])", lower):
        return False
    return _contains_any(lower, SENSITIVE_OUTPUT_MARKERS)


def _template_mentions_field(template: str, field_path: str) -> bool:
    if not template:
        return False
    field_name = field_path.split(".")[-1]
    return field_name.lower() in template.lower()


def _has_side_effect_text(tool: dict[str, Any]) -> bool:
    return _contains_any(f"{tool.get('name', '')} {tool.get('description', '')}", SIDE_EFFECT_TEXT_MARKERS)


def _has_tool_description_injection_text(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return _has_description_injection_text(new) and not _has_description_injection_text(old)


def _has_description_injection_text(tool: dict[str, Any]) -> bool:
    description = str(tool.get("description", ""))
    if _contains_any(description, DESCRIPTION_INJECTION_MARKERS):
        return True
    return any(pattern.search(description) for pattern in DESCRIPTION_INJECTION_PATTERNS)


def _is_risky_scope(scope: str, old_scopes: set[str]) -> bool:
    lower = scope.lower()
    if _scope_is_readonly(lower):
        return _contains_any(lower, SENSITIVE_OUTPUT_MARKERS)
    if any(_readonly_scope_widened(old_scope.lower(), lower) for old_scope in old_scopes):
        return True
    return _contains_any(lower, RISKY_SCOPE_MARKERS)


def _scope_is_readonly(scope: str) -> bool:
    return any(part in {"readonly", "read_only", "read"} for part in re.split(r"[^a-z0-9_]+", scope))


def _readonly_scope_widened(old_scope: str, new_scope: str) -> bool:
    if not _scope_is_readonly(old_scope):
        return False
    readonly_prefixes = (
        old_scope.removesuffix(".readonly"),
        old_scope.removesuffix(".read_only"),
        old_scope.removesuffix(".read"),
    )
    return any(prefix and new_scope == prefix for prefix in readonly_prefixes)


def _contains_any(value: str, markers: tuple[str, ...]) -> bool:
    lower = value.lower()
    return any(_contains_marker(lower, marker) for marker in markers)


def _strip_temporal_read_markers(value: str) -> str:
    return re.sub(r"\b(start|stop)\s+(date|time|timestamp)\b", " ", value, flags=re.IGNORECASE)


def _contains_marker(lower_value: str, marker: str) -> bool:
    marker = marker.lower()
    if marker in {"execute sql", "run shell"}:
        return marker in re.sub(r"[_\-\s]+", " ", lower_value)
    if marker in WORD_BOUNDARY_MARKERS:
        return re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", lower_value) is not None
    return marker in lower_value


def _describe_tool(tool: dict[str, Any]) -> str:
    scopes = ",".join(sorted(_scopes(tool))) or "no-scopes"
    annotations = tool.get("annotations", {})
    return f"scopes={scopes}; annotations={annotations}; description={tool.get('description', '')}"


def main() -> None:
    fixtures = load_fixtures(Path("fixtures/tool_descriptor_fixtures.json"))
    print(render_markdown(lint_fixtures(fixtures)), end="")


if __name__ == "__main__":
    main()
