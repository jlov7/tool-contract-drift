"""Check the new review path against the frozen original structural inventory."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tool_contract_drift import review_descriptor_pair
from scripts.run_practical_evaluation import digest, tool_map


def verified_captures(work: Path, original: list[dict], reproduced: list[dict], repeat_count: int) -> dict:
    by_alias = {capture["alias"]: capture for capture in reproduced}
    if len(by_alias) != len(reproduced) or set(by_alias) != {capture["alias"] for capture in original}:
        raise ValueError("Reproduced capture set differs from the frozen receipt.")
    snapshots = {}
    for expected in original:
        alias = expected["alias"]
        current = by_alias[alias]
        hashes = expected["tool_set_sha256"]
        if (expected["status"] != "stable" or current["status"] != "stable"
                or len(hashes) != repeat_count or len(set(hashes)) != 1
                or current["tool_set_sha256"] != hashes):
            raise ValueError(f"Capture is not stable at the frozen identity: {alias}")
        for repetition, expected_hash in enumerate(hashes):
            snapshot = json.loads((work / "captures" / alias / f"{repetition}.json").read_text())
            if digest(tool_map(snapshot)) != expected_hash:
                raise ValueError(f"Capture identity differs from the frozen receipt: {alias}/{repetition}")
            if repetition == 0:
                snapshots[alias] = snapshot
    return snapshots


def verify_inventory(report: dict, row: dict) -> None:
    expected_paths = ["/tools" + path for path in row["structural_paths"]]
    observed_paths = [change["path"] for change in report["changes"]]
    observed_rules = Counter(finding["risk"] for finding in report["policy_findings"])
    if (expected_paths != observed_paths
            or len(report["policy_findings"]) != row["baseline_finding_count"]
            or observed_rules != row["baseline_rules"]):
        raise ValueError(f"Review differs from frozen inventory: {row['package']} {row['before']} -> {row['after']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, default=ROOT / "artifacts/practical-evaluation")
    parser.add_argument("--acquisition-results", type=Path, required=True, help="Results written by run_practical_evaluation.py for this work directory.")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation/review_results.json")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Review receipt already exists; choose a new --output path.")
    result_path = ROOT / "evaluation/practical_results.json"
    results = json.loads(result_path.read_text())
    sample = json.loads((ROOT / "evaluation/practical_sample.json").read_text())
    acquisition = json.loads(args.acquisition_results.read_text())
    sample_hash = hashlib.sha256((ROOT / "evaluation/practical_sample.json").read_bytes()).hexdigest()
    if results["sample_sha256"] != sample_hash or acquisition["sample_sha256"] != sample_hash:
        raise ValueError("Acquisition sample differs from the frozen sample.")
    protocol = json.loads((ROOT / "evaluation/practical_protocol.json").read_text())
    captures = verified_captures(args.work, results["captures"], acquisition["captures"], protocol["capture"]["repeat_count"])
    aliases = {(record["package"], record["version"]): record["alias"] for record in sample["releases"]}
    capture_hashes = {capture["alias"]: capture["tool_set_sha256"][0] for capture in results["captures"] if capture["status"] == "stable"}
    rows = []
    for row in results["transitions"]:
        if row["status"] != "compared":
            rows.append({"package": row["package"], "before": row["before"], "after": row["after"], "status": "not-evaluated"})
            continue
        snapshots = [captures[aliases[(row["package"], row[phase])]] for phase in ("before", "after")]
        report = review_descriptor_pair(*snapshots)
        for phase in ("before", "after"):
            if report[phase + "_sha256"] != capture_hashes[aliases[(row["package"], row[phase])]]:
                raise ValueError("Acquisition hash differs from the frozen capture receipt.")
        verify_inventory(report, row)
        rows.append({"package": row["package"], "before": row["before"], "after": row["after"], "status": report["status"],
            "change_count": report["change_count"], "before_sha256": report["before_sha256"], "after_sha256": report["after_sha256"],
            "policy_finding_count": len(report["policy_findings"]),
            "policy_rules": dict(sorted(Counter(finding["risk"] for finding in report["policy_findings"]).items())),
            "changed_without_policy_findings": report["changed_without_policy_findings"]})
    receipt = {
        "schema_version": "practical-review-check-v2",
        "original_results_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "acquisition_results_sha256": hashlib.sha256(args.acquisition_results.read_bytes()).hexdigest(),
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
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
