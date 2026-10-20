from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tool_contract_drift.corpora import (
    SUPPORTED_CORPUS_IDS,
    canonical_fixture_source,
    custom_fixture_paths,
    select_corpus,
)
from tool_contract_drift.linter.tool_contract_drift import (
    _became_destructive,
    _closed_world_became_open,
    _destructive_hint_escalated,
    _destructive_hint_downgraded,
    _has_tool_description_injection_text,
    _is_risky_tool,
    _missing_readonly_side_effect_annotation,
    _new_sensitive_output_fields,
    _open_world_hint_escalated,
    _scope_is_readonly,
    _scopes,
    _sensitive_output_template_fields,
    _side_effect_annotation_added,
    _tool_map,
    lint_fixture,
    load_fixtures,
)
from tool_contract_drift.adapters import oasdiff as oasdiff_adapter


descriptor_to_openapi = oasdiff_adapter.project_descriptor_to_openapi


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_FILES = (
    "tool_descriptor_fixtures.json",
    "real_public_descriptor_changes.json",
    "heldout_public_descriptor_changes.json",
    "second_heldout_public_descriptor_changes.json",
    "third_heldout_public_descriptor_changes.json",
    "ordinary_public_descriptor_controls.json",
    "adversarial_descriptor_cases.json",
)
RISK_FIELD_NAMES = (
    "name",
    "description",
    "auth",
    "annotations",
    "input_schema",
    "output_schema",
    "output_template",
)
PRIVATE_HASH_ALLOWLIST_PATH = ROOT.parent / "policy" / "hash_allowlist_quiet_changes.json"
PACKAGED_HASH_ALLOWLIST_PATH = ROOT / "policy" / "hash_allowlist_quiet_changes.json"
HASH_ALLOWLIST_PATH = (
    PRIVATE_HASH_ALLOWLIST_PATH if PRIVATE_HASH_ALLOWLIST_PATH.is_file() else PACKAGED_HASH_ALLOWLIST_PATH
)


@dataclass(frozen=True)
class ConfiguredSubstituteResult:
    fixture_id: str
    source_file: str
    candidate_risks: tuple[str, ...]
    candidate_finding_keys: tuple[str, ...]
    configured_spectral_risks: tuple[str, ...]
    configured_spectral_finding_keys: tuple[str, ...]
    oasdiff_mapper_risks: tuple[str, ...]
    oasdiff_mapper_finding_keys: tuple[str, ...]
    exact_descriptor_hash_labels: tuple[str, ...]
    risk_field_hash_labels: tuple[str, ...]
    hash_allowlist_decision: str


@dataclass(frozen=True)
class BaselineMetrics:
    baseline: str
    tp_fixtures: int
    fp_fixtures: int
    fn_fixtures: int
    tn_fixtures: int
    fixture_exact_matches: str
    semantic_label_fn: str
    finding_instance_exact_matches: str
    finding_instance_fn: str
    absorbs_candidate: str


def load_all_fixture_records(paths: list[Path]) -> list[tuple[str, dict[str, Any]]]:
    if not paths:
        raise ValueError("Fixture paths are required; select a named corpus explicitly before running evidence code.")
    records: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        for fixture in load_fixtures(path):
            records.append((canonical_fixture_source(path), fixture))
    return records


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def configured_spectral_equivalent_risks(before_openapi: dict[str, Any], after_openapi: dict[str, Any]) -> tuple[str, ...]:
    fixture = {
        "id": "configured-spectral-equivalent",
        "before": openapi_to_descriptor(before_openapi),
        "after": openapi_to_descriptor(after_openapi),
    }
    return policy_risks(fixture)


def oasdiff_risk_mapper_risks(
    oasdiff_json: dict[str, Any],
    before_openapi: dict[str, Any],
    after_openapi: dict[str, Any],
) -> tuple[str, ...]:
    fixture = {
        "id": "oasdiff-risk-mapper",
        "before": openapi_to_descriptor(before_openapi),
        "after": openapi_to_descriptor(after_openapi),
    }
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    labels_by_tool = oasdiff_change_labels(oasdiff_json, before_openapi, after_openapi)
    risks: set[str] = set()
    for name, labels in labels_by_tool.items():
        old = before.get(name, {})
        new = after.get(name, {})
        label_set = set(labels)
        if "tool_added" in label_set:
            if _is_risky_tool(new):
                risks.add("risky_tool_added")
            if _missing_readonly_side_effect_annotation({}, new):
                risks.add("missing_readonly_side_effect_annotation")
        if "annotations_changed" in label_set:
            if _side_effect_annotation_added(old, new):
                risks.add("side_effect_annotation_added")
            if _destructive_hint_escalated(old, new):
                risks.add("destructive_hint_escalation")
            if _destructive_hint_downgraded(old, new):
                risks.add("destructive_hint_downgrade")
            if _open_world_hint_escalated(old, new):
                risks.add("closed_world_to_open_world_input")
            if _missing_readonly_side_effect_annotation(old, new):
                risks.add("missing_readonly_side_effect_annotation")
        if "auth_changed" in label_set:
            if risky_scope_expansion(old, new):
                risks.add("auth_scope_expansion")
            if _became_destructive(old, new):
                risks.add("readonly_to_destructive")
        if "description_changed" in label_set and _became_destructive(old, new):
            risks.add("readonly_to_destructive")
        if "description_changed" in label_set and _has_tool_description_injection_text(old, new):
            risks.add("description_injection_drift")
        if "input_schema_changed" in label_set and _closed_world_became_open(
            old.get("input_schema", {}), new.get("input_schema", {})
        ):
            risks.add("closed_world_to_open_world_input")
        if "output_template_changed" in label_set and _sensitive_output_template_fields(old, new):
            risks.add("sensitive_output_template_drift")
        if (
            "output_schema_changed" in label_set
            and "output_template_changed" not in label_set
            and _new_sensitive_output_fields(old, new)
        ):
            risks.add("sensitive_output_schema_expansion")
    return tuple(sorted(risks))


def oasdiff_risk_mapper_finding_keys(
    oasdiff_json: dict[str, Any],
    before_openapi: dict[str, Any],
    after_openapi: dict[str, Any],
) -> tuple[str, ...]:
    fixture = {
        "id": "oasdiff-risk-mapper",
        "before": openapi_to_descriptor(before_openapi),
        "after": openapi_to_descriptor(after_openapi),
    }
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    labels_by_tool = oasdiff_change_labels(oasdiff_json, before_openapi, after_openapi)
    keys: set[str] = set()
    for name, labels in labels_by_tool.items():
        old = before.get(name, {})
        new = after.get(name, {})
        label_set = set(labels)
        if "tool_added" in label_set:
            if _is_risky_tool(new):
                keys.add(finding_key(name, "risky_tool_added", "high"))
            if _missing_readonly_side_effect_annotation({}, new):
                keys.add(finding_key(name, "missing_readonly_side_effect_annotation", "medium"))
        if "annotations_changed" in label_set:
            if _side_effect_annotation_added(old, new):
                severity = "high" if new.get("annotations", {}).get("destructiveHint") is True else "medium"
                keys.add(finding_key(name, "side_effect_annotation_added", severity))
            if _destructive_hint_escalated(old, new):
                keys.add(finding_key(name, "destructive_hint_escalation", "high"))
            if _destructive_hint_downgraded(old, new):
                keys.add(finding_key(name, "destructive_hint_downgrade", "medium"))
            if _open_world_hint_escalated(old, new):
                keys.add(finding_key(name, "closed_world_to_open_world_input", "medium"))
            if _missing_readonly_side_effect_annotation(old, new):
                keys.add(finding_key(name, "missing_readonly_side_effect_annotation", "medium"))
        if "auth_changed" in label_set:
            if risky_scope_expansion(old, new):
                keys.add(finding_key(name, "auth_scope_expansion", "high"))
            if _became_destructive(old, new):
                keys.add(finding_key(name, "readonly_to_destructive", "high"))
        if "description_changed" in label_set and _became_destructive(old, new):
            keys.add(finding_key(name, "readonly_to_destructive", "high"))
        if "description_changed" in label_set and _has_tool_description_injection_text(old, new):
            keys.add(finding_key(name, "description_injection_drift", "high"))
        if "input_schema_changed" in label_set and _closed_world_became_open(
            old.get("input_schema", {}), new.get("input_schema", {})
        ):
            keys.add(finding_key(name, "closed_world_to_open_world_input", "medium"))
        if "output_template_changed" in label_set and _sensitive_output_template_fields(old, new):
            keys.add(finding_key(name, "sensitive_output_template_drift", "high"))
        if (
            "output_schema_changed" in label_set
            and "output_template_changed" not in label_set
            and _new_sensitive_output_fields(old, new)
        ):
            keys.add(finding_key(name, "sensitive_output_schema_expansion", "high"))
    return tuple(sorted(keys))


def policy_risks(fixture: dict[str, Any]) -> tuple[str, ...]:
    risks: set[str] = set()
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    for name in sorted(set(before) | set(after)):
        if name not in before:
            if _is_risky_tool(after[name]):
                risks.add("risky_tool_added")
            if _missing_readonly_side_effect_annotation({}, after[name]):
                risks.add("missing_readonly_side_effect_annotation")
            continue
        if name not in after:
            continue
        old = before[name]
        new = after[name]
        if _became_destructive(old, new):
            risks.add("readonly_to_destructive")
        if _side_effect_annotation_added(old, new):
            risks.add("side_effect_annotation_added")
        if _missing_readonly_side_effect_annotation(old, new):
            risks.add("missing_readonly_side_effect_annotation")
        if _destructive_hint_escalated(old, new):
            risks.add("destructive_hint_escalation")
        if _destructive_hint_downgraded(old, new):
            risks.add("destructive_hint_downgrade")
        if _has_tool_description_injection_text(old, new):
            risks.add("description_injection_drift")
        if risky_scope_expansion(old, new):
            risks.add("auth_scope_expansion")
        if _closed_world_became_open(old.get("input_schema", {}), new.get("input_schema", {})) or _open_world_hint_escalated(
            old, new
        ):
            risks.add("closed_world_to_open_world_input")
        if _sensitive_output_template_fields(old, new) and old.get("output_template") != new.get("output_template"):
            risks.add("sensitive_output_template_drift")
        if _new_sensitive_output_fields(old, new) and old.get("output_template") == new.get("output_template"):
            risks.add("sensitive_output_schema_expansion")
    return tuple(sorted(risks))


def policy_finding_keys(fixture: dict[str, Any]) -> tuple[str, ...]:
    return tuple(sorted(finding_key(item.tool_name, item.risk, item.severity) for item in lint_fixture(fixture)))


def finding_key(tool_name: str, risk: str, severity: str) -> str:
    return f"{tool_name}:{risk}:{severity}"


def risky_scope_expansion(old: dict[str, Any], new: dict[str, Any]) -> bool:
    old_scopes = _scopes(old)
    for scope in _scopes(new) - old_scopes:
        lower = scope.lower()
        if _scope_is_readonly(lower):
            if not any(marker in lower for marker in ("credential", "password", "payment", "secret", "token")):
                continue
            return True
        if any(readonly_scope_widened(old_scope.lower(), lower) for old_scope in old_scopes):
            return True
        if any(marker in lower for marker in ("act_as", "cancel", "delete", "deploy", "impersonate", "manage", "modify", "payment", "post", "secret", "send", "write")):
            return True
        if "admin" in lower and not _scope_is_readonly(lower):
            return True
    return False


def readonly_scope_widened(old_scope: str, new_scope: str) -> bool:
    if not _scope_is_readonly(old_scope):
        return False
    return new_scope in {
        old_scope.removesuffix(".readonly"),
        old_scope.removesuffix(".read_only"),
        old_scope.removesuffix(".read"),
    }


def openapi_to_descriptor(openapi: dict[str, Any]) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    for path, methods in sorted(openapi.get("paths", {}).items()):
        operation = methods.get("post") or {}
        request_schema = (
            operation.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        response_schema = (
            operation.get("responses", {})
            .get("200", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        tool: dict[str, Any] = {
            "name": operation.get("x-mcp-tool-name") or operation.get("summary") or path.removeprefix("/tools/"),
            "description": operation.get("description", ""),
        }
        if request_schema:
            tool["input_schema"] = request_schema
        if response_schema:
            tool["output_schema"] = response_schema
        if operation.get("x-mcp-auth"):
            tool["auth"] = operation["x-mcp-auth"]
        if operation.get("x-mcp-annotations"):
            tool["annotations"] = operation["x-mcp-annotations"]
        if "x-mcp-output-template" in operation:
            tool["output_template"] = operation["x-mcp-output-template"]
        tools.append(tool)
    return {"tools": tools}


def projected_oasdiff_json(before_openapi: dict[str, Any], after_openapi: dict[str, Any]) -> dict[str, Any]:
    before_ops = openapi_operations_by_tool(before_openapi)
    after_ops = openapi_operations_by_tool(after_openapi)
    changed_operations: dict[str, list[str]] = {}
    for name in sorted(set(before_ops) | set(after_ops)):
        if name not in before_ops:
            changed_operations[name] = ["tool_added"]
            continue
        if name not in after_ops:
            changed_operations[name] = ["tool_removed"]
            continue
        old = before_ops[name]
        new = after_ops[name]
        labels: list[str] = []
        if old.get("description") != new.get("description"):
            labels.append("description_changed")
        if openapi_request_schema(old) != openapi_request_schema(new):
            labels.append("input_schema_changed")
        if old.get("x-mcp-auth") != new.get("x-mcp-auth"):
            labels.append("auth_changed")
        if old.get("x-mcp-output-template") != new.get("x-mcp-output-template"):
            labels.append("output_template_changed")
        if openapi_response_schema(old) != openapi_response_schema(new):
            labels.append("output_schema_changed")
        if old.get("x-mcp-annotations") != new.get("x-mcp-annotations"):
            labels.append("annotations_changed")
        if labels:
            changed_operations[name] = labels
    return {"changed_operations": changed_operations}


def oasdiff_change_labels(
    oasdiff_json: dict[str, Any],
    before_openapi: dict[str, Any],
    after_openapi: dict[str, Any],
) -> dict[str, tuple[str, ...]]:
    if isinstance(oasdiff_json.get("changed_operations"), dict):
        return {
            str(name): tuple(str(label) for label in labels)
            for name, labels in oasdiff_json["changed_operations"].items()
        }
    labels_by_tool: dict[str, set[str]] = {}
    tool_by_path = path_to_tool_name(before_openapi) | path_to_tool_name(after_openapi)
    paths = oasdiff_json.get("paths", {})
    for path in paths.get("added", []):
        labels_by_tool.setdefault(tool_by_path.get(path, path), set()).add("tool_added")
    for path in paths.get("deleted", []):
        labels_by_tool.setdefault(tool_by_path.get(path, path), set()).add("tool_removed")
    modified = paths.get("modified", {})
    if isinstance(modified, dict):
        for path, change in modified.items():
            tool_name = tool_by_path.get(path, path)
            labels = labels_by_tool.setdefault(tool_name, set())
            encoded_change = json.dumps(change, sort_keys=True)
            if "x-mcp-annotations" in encoded_change:
                labels.add("annotations_changed")
            if "x-mcp-auth" in encoded_change:
                labels.add("auth_changed")
            if "x-mcp-output-template" in encoded_change:
                labels.add("output_template_changed")
            if "requestBody" in encoded_change:
                labels.add("input_schema_changed")
            if "responses" in encoded_change:
                labels.add("output_schema_changed")
            if "\"description\"" in encoded_change:
                labels.add("description_changed")
    return {name: tuple(sorted(labels)) for name, labels in labels_by_tool.items()}


def openapi_operations_by_tool(openapi: dict[str, Any]) -> dict[str, dict[str, Any]]:
    operations: dict[str, dict[str, Any]] = {}
    for methods in openapi.get("paths", {}).values():
        operation = methods.get("post") or {}
        name = operation.get("x-mcp-tool-name") or operation.get("summary")
        if name:
            operations[str(name)] = operation
    return operations


def path_to_tool_name(openapi: dict[str, Any]) -> dict[str, str]:
    names: dict[str, str] = {}
    for path, methods in openapi.get("paths", {}).items():
        operation = methods.get("post") or {}
        names[path] = operation.get("x-mcp-tool-name") or operation.get("summary") or path.removeprefix("/tools/")
    return names


def openapi_request_schema(operation: dict[str, Any]) -> dict[str, Any]:
    return operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})


def openapi_response_schema(operation: dict[str, Any]) -> dict[str, Any]:
    return (
        operation.get("responses", {})
        .get("200", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )


openapi_to_descriptor = oasdiff_adapter.openapi_to_descriptor
projected_oasdiff_json = oasdiff_adapter.projected_oasdiff_json
oasdiff_change_labels = oasdiff_adapter.oasdiff_change_labels
openapi_operations_by_tool = oasdiff_adapter.openapi_operations_by_tool
path_to_tool_name = oasdiff_adapter.path_to_tool_name
openapi_request_schema = oasdiff_adapter.openapi_request_schema
openapi_response_schema = oasdiff_adapter.openapi_response_schema
oasdiff_risk_mapper_risks = oasdiff_adapter.map_oasdiff_json_to_risks
oasdiff_risk_mapper_finding_keys = oasdiff_adapter.map_oasdiff_json_to_finding_keys
risky_scope_expansion = oasdiff_adapter.risky_scope_expansion
readonly_scope_widened = oasdiff_adapter.readonly_scope_widened


def descriptor_hash_policy_labels(fixture: dict[str, Any], mode: str) -> tuple[str, ...]:
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    labels: set[str] = set()
    for name in sorted(set(before) | set(after)):
        if name not in before:
            labels.add("unapproved_tool")
        elif name not in after:
            labels.add("tool_removed")
        else:
            old_hash = descriptor_hash(before[name] if mode == "exact" else risk_field_descriptor(before[name]))
            new_hash = descriptor_hash(after[name] if mode == "exact" else risk_field_descriptor(after[name]))
            if old_hash != new_hash:
                labels.add("descriptor_hash_mismatch")
    return tuple(sorted(labels))


def hash_allowlist_decision(fixture: dict[str, Any], source_file: str) -> str:
    transitions = risk_field_hash_transitions(fixture)
    if not transitions:
        return "allowed_change"
    allowlist = load_hash_allowlist(hash_allowlist_path_for_source(source_file))
    for transition in transitions:
        key = (
            fixture["id"],
            source_file,
            transition["tool_name"],
            transition["before_risk_field_sha256"],
            transition["after_risk_field_sha256"],
        )
        if key not in allowlist:
            return "reapproval_required"
    return "allowed_change"


def risk_field_hash_transitions(fixture: dict[str, Any]) -> list[dict[str, str | None]]:
    before = _tool_map(fixture["before"])
    after = _tool_map(fixture["after"])
    transitions = []
    for name in sorted(set(before) | set(after)):
        before_hash = descriptor_hash(risk_field_descriptor(before[name])) if name in before else None
        after_hash = descriptor_hash(risk_field_descriptor(after[name])) if name in after else None
        if before_hash != after_hash:
            transitions.append(
                {
                    "tool_name": name,
                    "before_risk_field_sha256": before_hash,
                    "after_risk_field_sha256": after_hash,
                }
            )
    return transitions


def hash_allowlist_path_for_source(source_file: str) -> Path:
    if source_file.startswith("tool_contract_drift/fixtures/"):
        return PACKAGED_HASH_ALLOWLIST_PATH
    if source_file.startswith("fixtures/"):
        return PRIVATE_HASH_ALLOWLIST_PATH
    return HASH_ALLOWLIST_PATH


def load_hash_allowlist(
    path: Path = HASH_ALLOWLIST_PATH,
) -> set[tuple[str, str, str, str | None, str | None]]:
    payload = json.loads(path.read_text())
    return {
        (
            entry["fixture_id"],
            entry["source_file"],
            entry["tool_name"],
            entry["before_risk_field_sha256"],
            entry["after_risk_field_sha256"],
        )
        for entry in payload["entries"]
    }


def risk_field_descriptor(tool: dict[str, Any]) -> dict[str, Any]:
    return {name: tool[name] for name in RISK_FIELD_NAMES if name in tool}


def descriptor_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()


def run_bakeoff(paths: list[Path]) -> list[ConfiguredSubstituteResult]:
    results = []
    for source_file, fixture in load_all_fixture_records(paths):
        before_openapi = descriptor_to_openapi(fixture["before"], f"{fixture['id']} before")
        after_openapi = descriptor_to_openapi(fixture["after"], f"{fixture['id']} after")
        candidate_risks = tuple(sorted({finding.risk for finding in lint_fixture(fixture)}))
        candidate_finding_keys = policy_finding_keys(fixture)
        spectral_fixture = {
            "id": "configured-spectral-equivalent",
            "before": openapi_to_descriptor(before_openapi),
            "after": openapi_to_descriptor(after_openapi),
        }
        projected_oasdiff = projected_oasdiff_json(before_openapi, after_openapi)
        results.append(
            ConfiguredSubstituteResult(
                fixture_id=fixture["id"],
                source_file=source_file,
                candidate_risks=candidate_risks,
                candidate_finding_keys=candidate_finding_keys,
                configured_spectral_risks=configured_spectral_equivalent_risks(before_openapi, after_openapi),
                configured_spectral_finding_keys=policy_finding_keys(spectral_fixture),
                oasdiff_mapper_risks=oasdiff_risk_mapper_risks(
                    projected_oasdiff,
                    before_openapi,
                    after_openapi,
                ),
                oasdiff_mapper_finding_keys=oasdiff_risk_mapper_finding_keys(
                    projected_oasdiff,
                    before_openapi,
                    after_openapi,
                ),
                exact_descriptor_hash_labels=descriptor_hash_policy_labels(fixture, "exact"),
                risk_field_hash_labels=descriptor_hash_policy_labels(fixture, "risk"),
                hash_allowlist_decision=hash_allowlist_decision(fixture, source_file),
            )
        )
    return results


def summarize_bakeoff(results: list[ConfiguredSubstituteResult]) -> dict[str, Any]:
    metrics = baseline_metrics(results)
    return {
        "fixture_count": len(results),
        "candidate_hold_fixture_count": sum(bool(item.candidate_risks) for item in results),
        "quiet_fixture_count": sum(not item.candidate_risks for item in results),
        "baseline_metrics": [asdict(item) for item in metrics],
        "configured_spectral_exact_matches": exact_match_count(results, "configured_spectral_risks"),
        "oasdiff_mapper_exact_matches": exact_match_count(results, "oasdiff_mapper_risks"),
        "candidate_finding_instance_count": sum(len(item.candidate_finding_keys) for item in results),
        "configured_spectral_instance_exact_matches": exact_match_count(results, "configured_spectral_finding_keys", "candidate_finding_keys"),
        "oasdiff_mapper_instance_exact_matches": exact_match_count(results, "oasdiff_mapper_finding_keys", "candidate_finding_keys"),
        "configured_spectral_instance_fn": semantic_label_fn_count(results, "configured_spectral_finding_keys", "candidate_finding_keys"),
        "oasdiff_mapper_instance_fn": semantic_label_fn_count(results, "oasdiff_mapper_finding_keys", "candidate_finding_keys"),
        "exact_descriptor_hash_reapproval_fixture_count": sum(bool(item.exact_descriptor_hash_labels) for item in results),
        "risk_field_hash_reapproval_fixture_count": sum(bool(item.risk_field_hash_labels) for item in results),
    }


def baseline_metrics(results: list[ConfiguredSubstituteResult]) -> list[BaselineMetrics]:
    return [
        risk_metrics(
            "Configured Spectral-equivalent",
            results,
            lambda item: bool(item.configured_spectral_risks),
            exact_matches=exact_match_count(results, "configured_spectral_risks"),
            semantic_label_fn=semantic_label_fn_count(results, "configured_spectral_risks"),
            instance_exact_matches=exact_match_count(results, "configured_spectral_finding_keys", "candidate_finding_keys"),
            instance_fn=semantic_label_fn_count(results, "configured_spectral_finding_keys", "candidate_finding_keys"),
            absorbs="Yes, for current corpus as policy rules"
            if exact_match_count(results, "configured_spectral_risks") == len(results)
            else "No, misses current semantic labels",
        ),
        risk_metrics(
            "oasdiff risk mapper",
            results,
            lambda item: bool(item.oasdiff_mapper_risks),
            exact_matches=exact_match_count(results, "oasdiff_mapper_risks"),
            semantic_label_fn=semantic_label_fn_count(results, "oasdiff_mapper_risks"),
            instance_exact_matches=exact_match_count(results, "oasdiff_mapper_finding_keys", "candidate_finding_keys"),
            instance_fn=semantic_label_fn_count(results, "oasdiff_mapper_finding_keys", "candidate_finding_keys"),
            absorbs="Yes, if mapper remains this thin"
            if exact_match_count(results, "oasdiff_mapper_risks") == len(results)
            else "No, mapper misses current semantic labels",
        ),
        risk_metrics(
            "Exact descriptor hash",
            results,
            lambda item: bool(item.exact_descriptor_hash_labels),
            exact_matches=decision_match_count(results, lambda item: bool(item.exact_descriptor_hash_labels)),
            semantic_label_fn="n/a",
            instance_exact_matches="n/a",
            instance_fn="n/a",
            absorbs="No, too blunt",
            decision_only=True,
        ),
        risk_metrics(
            "Risk-field hash",
            results,
            lambda item: bool(item.risk_field_hash_labels),
            exact_matches=decision_match_count(results, lambda item: bool(item.risk_field_hash_labels)),
            semantic_label_fn="n/a",
            instance_exact_matches="n/a",
            instance_fn="n/a",
            absorbs="No, too blunt",
            decision_only=True,
        ),
        risk_metrics(
            "Risk-field hash + allowlist",
            results,
            lambda item: item.hash_allowlist_decision == "reapproval_required",
            exact_matches=decision_match_count(
                results, lambda item: item.hash_allowlist_decision == "reapproval_required"
            ),
            semantic_label_fn="n/a",
            instance_exact_matches="n/a",
            instance_fn="n/a",
            absorbs="Partial, no semantic labels",
            decision_only=True,
        ),
    ]


def risk_metrics(
    baseline: str,
    results: list[ConfiguredSubstituteResult],
    predicts_hold: Any,
    exact_matches: int,
    semantic_label_fn: int | str,
    instance_exact_matches: int | str,
    instance_fn: int | str,
    absorbs: str,
    decision_only: bool = False,
) -> BaselineMetrics:
    tp = fp = fn = tn = 0
    for item in results:
        expected = bool(item.candidate_risks)
        predicted = bool(predicts_hold(item))
        if expected and predicted:
            tp += 1
        elif not expected and predicted:
            fp += 1
        elif expected and not predicted:
            fn += 1
        else:
            tn += 1
    suffix = " decision-only" if decision_only else ""
    return BaselineMetrics(
        baseline=baseline,
        tp_fixtures=tp,
        fp_fixtures=fp,
        fn_fixtures=fn,
        tn_fixtures=tn,
        fixture_exact_matches=f"{exact_matches}/{len(results)}{suffix}",
        semantic_label_fn=str(semantic_label_fn),
        finding_instance_exact_matches=(
            str(instance_exact_matches) if isinstance(instance_exact_matches, str) else f"{instance_exact_matches}/{len(results)}"
        ),
        finding_instance_fn=str(instance_fn),
        absorbs_candidate=absorbs,
    )


def exact_match_count(results: list[ConfiguredSubstituteResult], attr: str, expected_attr: str = "candidate_risks") -> int:
    return sum(getattr(item, attr) == getattr(item, expected_attr) for item in results)


def semantic_label_fn_count(
    results: list[ConfiguredSubstituteResult],
    attr: str,
    expected_attr: str = "candidate_risks",
) -> int:
    return sum(bool(getattr(item, expected_attr)) and getattr(item, attr) != getattr(item, expected_attr) for item in results)


def decision_match_count(results: list[ConfiguredSubstituteResult], predicts_hold: Any) -> int:
    return sum(bool(item.candidate_risks) == bool(predicts_hold(item)) for item in results)


def render_markdown(results: list[ConfiguredSubstituteResult]) -> str:
    summary = summarize_bakeoff(results)
    lines = [
        "# Agent Tool Contract Drift Configured Substitute Baseline Bakeoff",
        "",
        "Status: adversarial configured-baseline comparison. This tests whether Agent Tool Contract Drift's current value can be absorbed by small policy layers on existing diff/governance surfaces.",
        "",
        "## Summary",
        "",
        f"- Fixture pairs: {summary['fixture_count']}",
        f"- Agent Tool Contract Drift hold fixtures: {summary['candidate_hold_fixture_count']}",
        f"- Quiet/control fixtures: {summary['quiet_fixture_count']}",
        f"- Agent Tool Contract Drift finding instances: {summary['candidate_finding_instance_count']}",
        f"- Configured Spectral-equivalent instance exact matches: {summary['configured_spectral_instance_exact_matches']}/{summary['fixture_count']}",
        f"- oasdiff mapper instance exact matches: {summary['oasdiff_mapper_instance_exact_matches']}/{summary['fixture_count']}",
        "",
        "| Baseline | TP Fixtures | FP Fixtures | FN Fixtures | TN Fixtures | Fixture Exact Matches | Semantic Label FN | Instance Exact Matches | Instance FN | Absorbs Agent Tool Contract Drift? |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for metric in baseline_metrics(results):
        lines.append(
            f"| {metric.baseline} | {metric.tp_fixtures} | {metric.fp_fixtures} | {metric.fn_fixtures} | "
            f"{metric.tn_fixtures} | {metric.fixture_exact_matches} | {metric.semantic_label_fn} | "
            f"{metric.finding_instance_exact_matches} | {metric.finding_instance_fn} | "
            f"{metric.absorbs_candidate} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A configured policy over the projected OpenAPI `x-mcp-*` surface can reproduce Agent Tool Contract Drift on the current corpus. That narrows the standalone-tool claim: the durable contribution is the descriptor-risk policy, corpus, reproducible harness, and reviewer packet unless reviewers prefer a separate linter.",
            "",
            "The hash policies are intentionally blunt. Exact and risk-field hashes force review on quiet controls, while `policy/hash_allowlist_quiet_changes.json` can match current hold/control decisions only by explicitly encoding curated quiet risk-field hash transitions and without preserving semantic labels.",
            "",
            "## Fixture Results",
            "",
            "| Fixture | Source | Agent Tool Contract Drift Risks | Spectral-equivalent Risks | oasdiff Mapper Risks | Exact Hash | Risk-Field Hash | Hash Allowlist Decision |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for item in results:
        lines.append(
            f"| {item.fixture_id} | `{item.source_file}` | {labels(item.candidate_risks)} | "
            f"{labels(item.configured_spectral_risks)} | {labels(item.oasdiff_mapper_risks)} | "
            f"{labels(item.exact_descriptor_hash_labels)} | {labels(item.risk_field_hash_labels)} | "
            f"{item.hash_allowlist_decision} |"
        )
    return "\n".join(lines) + "\n"


def labels(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "-"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    parser.add_argument("--corpus", choices=SUPPORTED_CORPUS_IDS)
    parser.add_argument("--output", default=str(ROOT / "reports" / "configured_substitute_bakeoff.md"))
    parser.add_argument("--json", default=str(ROOT / "reports" / "configured_substitute_bakeoff.json"))
    args = parser.parse_args()

    if bool(args.fixture) == bool(args.corpus):
        raise SystemExit("Choose exactly one of --fixture or --corpus.")
    fixture_paths = (
        list(custom_fixture_paths(args.fixture)) if args.fixture else list(select_corpus(args.corpus).fixture_paths)
    )
    results = run_bakeoff(fixture_paths)
    write_text(Path(args.output), render_markdown(results))
    write_text(
        Path(args.json),
        json.dumps(
            {
                "summary": summarize_bakeoff(results),
                "results": [asdict(item) for item in results],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    print(f"Wrote {args.output}")
    print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()
