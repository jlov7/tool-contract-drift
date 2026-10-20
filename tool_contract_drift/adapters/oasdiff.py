from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tool_contract_drift.linter.tool_contract_drift import (
    _became_destructive,
    _closed_world_became_open,
    _destructive_hint_downgraded,
    _destructive_hint_escalated,
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
)


@dataclass(frozen=True)
class OasdiffAdapterRun:
    adapter_risks: tuple[str, ...]
    oasdiff_status: str
    oasdiff_exit_code: int | None
    oasdiff_changed: bool
    oasdiff_available: bool
    stdout_excerpt: str
    stderr_excerpt: str


def project_descriptor_to_openapi(descriptor: dict[str, Any], title: str) -> dict[str, Any]:
    """Project an MCP/App-style descriptor into the OpenAPI carrier used by the adapter."""
    paths: dict[str, Any] = {}
    for tool in descriptor.get("tools", []):
        extensions: dict[str, Any] = {
            "x-mcp-tool-name": tool["name"],
            "x-mcp-annotations": tool.get("annotations", {}),
            "x-mcp-auth": tool.get("auth", {}),
        }
        if "output_template" in tool:
            extensions["x-mcp-output-template"] = tool["output_template"]

        paths[operation_path(tool["name"])] = {
            "post": {
                "operationId": operation_id(tool["name"]),
                "tags": ["mcp-tool"],
                "summary": tool["name"],
                "description": tool.get("description") or f"MCP tool {tool['name']}.",
                "requestBody": {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": normalized_schema(tool.get("input_schema")),
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "MCP tool result.",
                        "content": {
                            "application/json": {
                                "schema": normalized_schema(tool.get("output_schema")),
                            }
                        },
                    }
                },
                **extensions,
            }
        }

    return {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": "0.0.0",
            "description": "Generated projection of MCP/App tool descriptors for Agent Tool Contract Drift oasdiff adapter evidence.",
            "contact": {"name": "Agent Tool Contract Drift oasdiff adapter"},
        },
        "servers": [{"url": "https://example.invalid"}],
        "tags": [{"name": "mcp-tool", "description": "Generated MCP/App tool operation."}],
        "paths": paths,
    }


def operation_path(tool_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", tool_name).strip("-")
    return f"/tools/{cleaned or 'tool'}"


def operation_id(tool_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", tool_name).strip("_")
    if not cleaned:
        return "tool"
    if cleaned[0].isdigit():
        return f"tool_{cleaned}"
    return cleaned


def normalized_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    if schema:
        return schema
    return {"type": "object", "additionalProperties": True}


def parse_oasdiff_json(text: str) -> dict[str, Any] | None:
    """Parse `oasdiff diff -f json` output into a dictionary shape."""
    if not text.strip() or text.strip() == "null":
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else {}


def map_oasdiff_json_to_risks(
    oasdiff_json: dict[str, Any],
    before_openapi: dict[str, Any],
    after_openapi: dict[str, Any],
) -> tuple[str, ...]:
    """Map structured oasdiff evidence back to Agent Tool Contract Drift semantic labels."""
    before = _tool_map(openapi_to_descriptor(before_openapi))
    after = _tool_map(openapi_to_descriptor(after_openapi))
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


def map_oasdiff_json_to_finding_keys(
    oasdiff_json: dict[str, Any],
    before_openapi: dict[str, Any],
    after_openapi: dict[str, Any],
) -> tuple[str, ...]:
    """Map structured oasdiff evidence to stable Agent Tool Contract Drift tool/risk/severity keys."""
    before = _tool_map(openapi_to_descriptor(before_openapi))
    after = _tool_map(openapi_to_descriptor(after_openapi))
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
            if '"description"' in encoded_change:
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
        if any(
            marker in lower
            for marker in (
                "act_as",
                "cancel",
                "delete",
                "deploy",
                "impersonate",
                "manage",
                "modify",
                "payment",
                "post",
                "secret",
                "send",
                "write",
            )
        ):
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


def run_oasdiff_descriptor_pair(
    before: dict[str, Any],
    after: dict[str, Any],
    fixture_id: str = "descriptor-pair",
    oasdiff_command: str | None = None,
) -> OasdiffAdapterRun:
    """Run real oasdiff over one descriptor pair and map the JSON diff to Agent Tool Contract Drift labels."""
    command = oasdiff_command or find_oasdiff_command()
    if command is None:
        return OasdiffAdapterRun(
            adapter_risks=(),
            oasdiff_status="not_found",
            oasdiff_exit_code=None,
            oasdiff_changed=False,
            oasdiff_available=False,
            stdout_excerpt="",
            stderr_excerpt="oasdiff command not found",
        )

    before_openapi = project_descriptor_to_openapi(before, f"{fixture_id} before")
    after_openapi = project_descriptor_to_openapi(after, f"{fixture_id} after")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        before_path = tmp_root / "before_openapi.json"
        after_path = tmp_root / "after_openapi.json"
        before_path.write_text(json.dumps(before_openapi, indent=2, sort_keys=True) + "\n")
        after_path.write_text(json.dumps(after_openapi, indent=2, sort_keys=True) + "\n")
        try:
            completed = subprocess.run(
                [command, "diff", str(before_path), str(after_path), "-f", "json"],
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )
        except FileNotFoundError:
            return OasdiffAdapterRun(
                adapter_risks=(),
                oasdiff_status="not_found",
                oasdiff_exit_code=None,
                oasdiff_changed=False,
                oasdiff_available=False,
                stdout_excerpt="",
                stderr_excerpt="oasdiff command not found",
            )
    parsed = parse_oasdiff_json(completed.stdout)
    risks = map_oasdiff_json_to_risks(parsed, before_openapi, after_openapi) if parsed is not None else ()
    return OasdiffAdapterRun(
        adapter_risks=risks,
        oasdiff_status="ok" if completed.returncode == 0 else "error",
        oasdiff_exit_code=completed.returncode,
        oasdiff_changed=parsed not in ({}, None),
        oasdiff_available=True,
        stdout_excerpt=excerpt(completed.stdout),
        stderr_excerpt=excerpt(completed.stderr),
    )


def find_oasdiff_command() -> str | None:
    from_path = shutil.which("oasdiff")
    if from_path:
        return from_path
    direct = Path.home() / "go" / "bin" / "oasdiff"
    if direct.exists():
        return str(direct)
    return None


def excerpt(value: str, limit: int = 200_000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"
