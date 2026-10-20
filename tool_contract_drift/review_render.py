"""Dependency-free Markdown rendering for descriptor reviews and privacy summaries."""
from __future__ import annotations

from difflib import unified_diff
import json
import re


def _json(value: object) -> str:
    # ASCII JSON also makes controls, bidi marks and unpaired surrogates visible.
    text = json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False)
    for char in "<>&":
        text = text.replace(char, f"\\u{ord(char):04x}")
    return text


def _ticks(text: str, minimum: int) -> str:
    return "`" * max(minimum, 1 + max((len(run) for run in re.findall(r"`+", text)), default=0))


def _inline(value: object) -> str:
    text = _json(value)
    ticks = _ticks(text, 1)
    return f"{ticks} {text} {ticks}"


def _block(text: str, language: str = "json") -> str:
    fence = _ticks(text, 3)
    return f"{fence}{language}\n{text}\n{fence}"


def _group_changes(changes: list[dict], include_values: bool) -> list[str]:
    tools = {}
    for change in changes:
        tools.setdefault(change["tool_name"], {}).setdefault(change["op"], []).append(change)
    lines = []
    for name, operations in tools.items():
        lines.append(f"### Tool: {_inline(name)}")
        for op in ("add", "remove", "replace"):
            entries = operations.get(op, [])
            if not entries:
                continue
            lines.append(f"#### {op.title()} ({len(entries)})")
            for change in entries:
                lines.append(f"##### Path: {_inline(change['path'])}")
                if not include_values:
                    continue
                for key in ("before", "after"):
                    if key not in change:
                        lines.append(f"{key.title()}: missing (key not present).")
                values = {key: change[key] for key in ("before", "after") if key in change}
                full_values = _block(_json(values))
                before, after = change.get("before"), change.get("after")
                if isinstance(before, str) and isinstance(after, str) and (
                    "\n" in before or "\n" in after or max(len(before), len(after)) > 240
                ):
                    # Escape each source line before diffing; only generated layout is raw.
                    diff = "\n".join(unified_diff(
                        [_json(line)[1:-1] for line in before.split("\n")],
                        [_json(line)[1:-1] for line in after.split("\n")],
                        fromfile="before", tofile="after", lineterm="",
                    ))
                    lines.append("Text diff (unchanged context omitted; full values available in JSON below).")
                    lines.append(_block(diff, "diff"))
                    lines.append("<details><summary>Full values (JSON)</summary>\n\n" + full_values + "\n\n</details>")
                else:
                    lines.append(full_values)
    return lines


def render_review_markdown(report: dict) -> str:
    """Render a tool-descriptor-review-v1 report or its minimized summary.

    Summaries are projected onto their disclosure fields, never backfilled with
    values or findings. Boundary wording is supplied by the report producer.
    """
    schema = report["schema_version"]
    if schema not in ("tool-descriptor-review-v1", "tool-descriptor-review-summary-v1"):
        raise ValueError("Unsupported review schema.")
    summary = schema == "tool-descriptor-review-summary-v1"
    disclosure = report["disclosure"] if summary else "full"
    if disclosure not in ("full", "counts", "paths") or (summary and disclosure == "full"):
        raise ValueError("Unsupported review disclosure.")
    finding_count = report["policy_finding_count"] if summary else len(report["policy_findings"])
    lines = [
        "# Tool Descriptor Review",
        f"Disclosure: {disclosure}.",
        f"Status: {_inline(report['status'])}.",
        f"Structural changes: {_inline(report['change_count'])}.",
        f"Policy findings: {_inline(finding_count)}.",
        "## Review Boundary",
        _inline(report["boundary"]),
        "Unchanged or no policy findings does not imply approval or runtime safety.",
    ]
    if summary:
        lines.extend(["## Operation Counts", _block(_json({
            op: report["operation_counts"][op] for op in ("add", "remove", "replace")
        }))])
    else:
        metadata = _block(_json({
            key: report[key] for key in (
                "schema_version", "status", "before_sha256", "after_sha256",
                "change_count", "changed_without_policy_findings", "boundary",
            )
        }))
        lines.append("<details><summary>Snapshot identity and report metadata</summary>\n\n" + metadata + "\n\n</details>")
    lines.append("## Structural Changes")
    if report["status"] == "unchanged":
        lines.append("No structural changes.")
    if disclosure == "counts":
        lines.append("Change details withheld: tool names, paths and values are not disclosed.")
    else:
        if disclosure == "paths":
            lines.append("Values withheld; only tool names, operations and paths are disclosed.")
        lines.extend(_group_changes(report["changes"], include_values=not summary))
    lines.append("## Policy Findings (Separate Heuristics)")
    if finding_count == 0:
        lines.append("No policy findings reported. This is not approval.")
    elif summary:
        lines.append("Policy finding details withheld; only the count is disclosed.")
    else:
        lines.append("Findings do not label or cover every structural edit; all changes above remain for review.")
        for index, finding in enumerate(report["policy_findings"], 1):
            lines.extend([f"### Finding {index}", _block(_json(finding))])
    return "\n\n".join(lines) + "\n"
