"""Allowlisted disclosure projections for complete descriptor review reports."""
from __future__ import annotations


REVIEW_SUMMARY_BOUNDARY = (
    "Counts disclose aggregate structure. Paths disclosure explicitly includes tool "
    "names and paths and is not anonymization. This summary is not approval evidence "
    "or evidence of runtime safety."
)


def minimize_review_report(report: dict, disclosure: str = "counts") -> dict:
    """Return fresh summary containers, exposing identifiers only in paths mode."""
    if disclosure not in ("counts", "paths"):
        raise ValueError("Invalid disclosure mode.")
    if not isinstance(report, dict):
        raise ValueError("Invalid review report.")
    changes = report.get("changes")
    findings = report.get("policy_findings")
    if not isinstance(changes, list) or not isinstance(findings, list):
        raise ValueError("Invalid review report.")
    status = "changed" if changes else "unchanged"
    if (
        report.get("status") != status
        or type(report.get("change_count")) is not int
        or report["change_count"] != len(changes)
    ):
        raise ValueError("Invalid review report.")

    operation_counts = {"add": 0, "remove": 0, "replace": 0}
    projected_changes = []
    for change in changes:
        if (
            not isinstance(change, dict)
            or not isinstance(change.get("tool_name"), str)
            or not isinstance(change.get("path"), str)
            or not isinstance(change.get("op"), str)
            or change["op"] not in operation_counts
        ):
            raise ValueError("Invalid review report.")
        op = change["op"]
        operation_counts[op] += 1
        if disclosure == "paths":
            projected_changes.append({
                "tool_name": change["tool_name"], "path": change["path"], "op": op,
            })

    summary = {
        "schema_version": "tool-descriptor-review-summary-v1",
        "disclosure": disclosure,
        "status": status,
        "change_count": len(changes),
        "policy_finding_count": len(findings),
        "operation_counts": operation_counts,
        "boundary": REVIEW_SUMMARY_BOUNDARY,
    }
    if disclosure == "paths":
        summary["changes"] = projected_changes
    return summary
