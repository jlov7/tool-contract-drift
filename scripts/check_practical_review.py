"""Check the new review path against the frozen original structural inventory."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tool_contract_drift import review_descriptor_pair


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, default=ROOT / "artifacts/practical-evaluation")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation/review_results.json")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Review receipt already exists; choose a new --output path.")
    result_path = ROOT / "evaluation/practical_results.json"
    results = json.loads(result_path.read_text())
    sample = json.loads((ROOT / "evaluation/practical_sample.json").read_text())
    aliases = {(record["package"], record["version"]): record["alias"] for record in sample["releases"]}
    capture_hashes = {capture["alias"]: capture["tool_set_sha256"][0] for capture in results["captures"] if capture["status"] == "stable"}
    rows = []
    for row in results["transitions"]:
        if row["status"] != "compared":
            rows.append({"package": row["package"], "before": row["before"], "after": row["after"], "status": "not-evaluated"})
            continue
        snapshots = [json.loads((args.work / "captures" / aliases[(row["package"], row[phase])] / "0.json").read_text()) for phase in ("before", "after")]
        report = review_descriptor_pair(*snapshots)
        for phase in ("before", "after"):
            if report[phase + "_sha256"] != capture_hashes[aliases[(row["package"], row[phase])]]:
                raise ValueError("Acquisition hash differs from the frozen capture receipt.")
        expected_paths = ["/tools" + path for path in row["structural_paths"]]
        observed_paths = [change["path"] for change in report["changes"]]
        if expected_paths != observed_paths or len(report["policy_findings"]) != row["baseline_finding_count"]:
            raise ValueError(f"Review differs from frozen inventory: {row['package']} {row['before']} -> {row['after']}")
        rows.append({"package": row["package"], "before": row["before"], "after": row["after"], "status": report["status"],
            "change_count": report["change_count"], "before_sha256": report["before_sha256"], "after_sha256": report["after_sha256"],
            "policy_finding_count": len(report["policy_findings"]), "changed_without_policy_findings": report["changed_without_policy_findings"]})
    receipt = {
        "schema_version": "practical-review-check-v1",
        "original_results_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "review_module_sha256": hashlib.sha256((ROOT / "tool_contract_drift/review.py").read_bytes()).hexdigest(),
        "linter_module_sha256": hashlib.sha256((ROOT / "tool_contract_drift/linter/tool_contract_drift.py").read_bytes()).hexdigest(),
        "python": platform.python_version(), "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        "transitions": rows,
        "boundary": "Software regression against the same observed sample, not a new holdout, semantic adjudication, accuracy comparison, or evidence of reviewer benefit.",
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
