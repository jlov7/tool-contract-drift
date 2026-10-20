"""GitHub Action adapter: retain complete evidence, disclose counts by default."""
from __future__ import annotations

import json
import os
from pathlib import Path

from tool_contract_drift.review_cli import _validate_destinations, main as review_main, report_error
from tool_contract_drift.review_privacy import minimize_review_report


def main() -> int:
    before = os.environ.get("TCD_REVIEW_BEFORE", "")
    after = os.environ.get("TCD_REVIEW_AFTER", "")
    report_path = os.environ.get("TCD_REVIEW_REPORT", "artifacts/descriptor-review.json")
    summary_path = os.environ.get("TCD_REVIEW_SUMMARY", "artifacts/descriptor-review.md")
    disclosure = os.environ.get("TCD_REVIEW_DISCLOSURE", "counts")
    fail_on = os.environ.get("TCD_REVIEW_FAIL_ON", "none")
    post_summary = os.environ.get("TCD_REVIEW_POST_SUMMARY", "true")
    github_output = os.environ.get("GITHUB_OUTPUT", "")
    github_summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    paths = [before, after, report_path, summary_path, github_output]
    if post_summary == "true":
        paths.append(github_summary)
    if (disclosure not in ("counts", "paths", "full")
            or fail_on not in ("none", "change", "findings")
            or post_summary not in ("true", "false")
            or any(not path or any(char in path for char in "\r\n\0") for path in paths)):
        return report_error()
    try:
        inputs = [Path(before), Path(after)]
        destinations = [Path(path) for path in paths[2:]]
        _validate_destinations(inputs, destinations)
        status = review_main([
            "--before=" + before, "--after=" + after,
            "--format=json", "--output=" + report_path,
            "--summary-output=" + summary_path, "--summary-disclosure=" + disclosure,
            "--fail-on", fail_on,
        ])
        if status not in (0, 1):
            return status
        counts = minimize_review_report(json.loads(Path(report_path).read_text()))
        if post_summary == "true":
            _validate_destinations(inputs, destinations)
            with Path(github_summary).open("a", encoding="utf-8") as output:
                output.write(Path(summary_path).read_text(encoding="utf-8"))
        fields = {
            "status": counts["status"], "change-count": counts["change_count"],
            "policy-finding-count": counts["policy_finding_count"],
            "report-path": report_path, "summary-path": summary_path,
        }
        _validate_destinations(inputs, destinations)
        with Path(github_output).open("a", encoding="utf-8") as output:
            output.writelines(f"{key}={value}\n" for key, value in fields.items())
        return status
    except (OSError, ValueError, TypeError, RecursionError):
        return report_error()


if __name__ == "__main__":
    raise SystemExit(main())
