"""Complete tool-object changes alongside the historical, incomplete policy labels."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from typing import Any

from tool_contract_drift.linter.tool_contract_drift import lint_fixture


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _tools(descriptor: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(descriptor, dict) or not isinstance(descriptor.get("tools"), list):
        raise ValueError("Expected an object containing a tools array.")
    result = {}
    for tool in descriptor["tools"]:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
            raise ValueError("Each tool must have a nonempty string name.")
        name = tool["name"]
        if name in result:
            raise ValueError(f"Duplicate tool name: {name!r}")
        if ("inputSchema" in tool) == ("input_schema" in tool):
            raise ValueError(f"Tool {name!r} must have exactly one inputSchema or input_schema.")
        schema = tool.get("inputSchema", tool.get("input_schema"))
        if not isinstance(schema, dict):
            raise ValueError(f"Tool {name!r} input schema must be an object.")
        for field in ("description", "title", "output_template"):
            if field in tool and not isinstance(tool[field], str):
                raise ValueError(f"Tool {name!r} {field} must be a string.")
        for field in ("annotations", "auth", "_meta", "execution", "outputSchema", "output_schema"):
            if field in tool and not isinstance(tool[field], dict):
                raise ValueError(f"Tool {name!r} {field} must be an object.")
        scopes = tool.get("auth", {}).get("scopes", [])
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            raise ValueError(f"Tool {name!r} auth.scopes must be an array of strings.")
        if "icons" in tool and not isinstance(tool["icons"], list):
            raise ValueError(f"Tool {name!r} icons must be an array.")
        result[name] = tool
    _canonical(result)
    return result


def _pointer(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _changes(before: Any, after: Any, path: str, name: str) -> list[dict[str, Any]]:
    if type(before) is type(after) and isinstance(before, dict):
        changes = []
        for key in sorted(before.keys() | after.keys()):
            child = path + "/" + _pointer(key)
            if key not in before:
                changes.append({"tool_name": name, "path": child, "op": "add", "after": after[key]})
            elif key not in after:
                changes.append({"tool_name": name, "path": child, "op": "remove", "before": before[key]})
            else:
                changes.extend(_changes(before[key], after[key], child, name))
        return changes
    # Arrays are atomic and order-sensitive. Missing and JSON null remain distinct.
    if _canonical(before) == _canonical(after):
        return []
    return [{"tool_name": name, "path": path, "op": "replace", "before": before, "after": after}]


def review_descriptor_pair(before: dict[str, Any], after: dict[str, Any], fixture_id: str = "descriptor-pair") -> dict[str, Any]:
    """Compare every tool field without interpreting absence of labels as approval.

    Accepts raw MCP tools/list results or the CLI's normalized descriptor format.
    Paths address a name-keyed tool map, not array positions. Acquisition metadata
    outside tools is intentionally excluded; array order inside tools is retained.
    """
    from tool_contract_drift_cli import normalize_mcp_tool

    left, right = _tools(before), _tools(after)
    changes = []
    for name in sorted(left.keys() | right.keys()):
        path = "/tools/" + _pointer(name)
        if name not in left:
            changes.append({"tool_name": name, "path": path, "op": "add", "after": right[name]})
        elif name not in right:
            changes.append({"tool_name": name, "path": path, "op": "remove", "before": left[name]})
        else:
            changes.extend(_changes(left[name], right[name], path, name))
    fixture = {"id": fixture_id}
    for phase, tools in (("before", left), ("after", right)):
        try:
            fixture[phase] = {"tools": [normalize_mcp_tool(tool) if "inputSchema" in tool else tool for tool in tools.values()]}
        except SystemExit as error:
            raise ValueError(str(error)) from error
    findings = [asdict(finding) for finding in lint_fixture(fixture)]
    return {
        "schema_version": "tool-descriptor-review-v1",
        "status": "changed" if changes else "unchanged",
        "before_sha256": hashlib.sha256(_canonical(left)).hexdigest(),
        "after_sha256": hashlib.sha256(_canonical(right)).hexdigest(),
        "change_count": len(changes), "changes": changes,
        "policy_findings": findings,
        "changed_without_policy_findings": bool(changes) and not findings,
        "boundary": "Every change remains for review. Policy findings are incomplete heuristics, not coverage of individual paths, an approval decision, or evidence of runtime safety.",
    }
