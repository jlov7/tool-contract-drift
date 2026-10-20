from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANARY = "PRIVATE_DESCRIPTOR_CANARY_7612"


class ReviewCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.before = self.directory / "before.json"
        self.after = self.directory / "after.json"
        snapshot = {"tools": [{"name": "lookup", "inputSchema": {}, "custom": "old"}]}
        self.before.write_text(json.dumps(snapshot))
        snapshot["tools"][0]["custom"] = CANARY
        self.after.write_text(json.dumps(snapshot))

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-B", "-m", "tool_contract_drift.review_cli",
             "--before", str(self.before), "--after", str(self.after), *arguments],
            cwd=ROOT, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=10,
        )

    def test_counts_projection_has_no_values_identifiers_or_hashes(self):
        result = self.run_cli("--format", "json", "--disclosure", "counts", "--id", CANARY)
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual("counts", report["disclosure"])
        self.assertEqual(1, report["change_count"])
        self.assertEqual(0, report["policy_finding_count"])
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertNotIn("lookup", result.stdout)
        self.assertNotIn("sha256", result.stdout)

    def test_paths_projection_is_explicitly_identifier_disclosing(self):
        result = self.run_cli("--format", "json", "--disclosure", "paths")
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([{"tool_name": "lookup", "path": "/tools/lookup/custom", "op": "replace"}], report["changes"])
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        self.assertNotIn("before_sha256", report)

    def test_full_json_stays_full_and_default_gate_is_report_only(self):
        result = self.run_cli("--format", "json")
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual("tool-descriptor-review-v1", report["schema_version"])
        self.assertEqual(CANARY, report["changes"][0]["after"])
        self.assertIn("before_sha256", report)

    def test_summary_is_counts_only_by_default_and_from_the_same_comparison(self):
        primary, summary = self.directory / "full.json", self.directory / "summary.md"
        result = self.run_cli("--format", "json", "--output", str(primary), "--summary-output", str(summary), "--fail-on", "change")
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)
        self.assertEqual(1, json.loads(primary.read_text())["change_count"])
        self.assertIn(CANARY, primary.read_text())
        self.assertNotIn(CANARY, summary.read_text() + result.stderr)
        self.assertNotIn("lookup", summary.read_text())
        self.assertTrue(summary.read_text().startswith("# "))

    def test_full_summary_requires_explicit_disclosure(self):
        summary = self.directory / "summary.md"
        result = self.run_cli("--disclosure", "counts", "--summary-output", str(summary), "--summary-disclosure", "full")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn(CANARY, result.stdout)
        self.assertIn(CANARY, summary.read_text())

    def test_invalid_input_has_distinct_exit_and_no_sensitive_error_content(self):
        self.after.write_text(json.dumps({"tools": [{"name": CANARY, "inputSchema": False}]}))
        for disclosure in ("full", "counts", "paths"):
            with self.subTest(disclosure=disclosure):
                result = self.run_cli("--format", "json", "--disclosure", disclosure)
                self.assertEqual(2, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertNotIn(CANARY, result.stderr)
                error = json.loads(result.stderr)
                self.assertIn("request_id", error)
                self.assertEqual("descriptor_review_failed", error["error"])

    def test_duplicate_json_keys_do_not_leak_field_names_in_errors(self):
        self.after.write_text('{"tools": [], "' + CANARY + '": 1, "' + CANARY + '": 2}')
        result = self.run_cli("--disclosure", "counts")
        self.assertEqual(2, result.returncode)
        self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_input_cannot_be_overwritten_by_either_report(self):
        original = self.before.read_bytes()
        for flag in ("--output", "--summary-output"):
            with self.subTest(flag=flag):
                result = self.run_cli(flag, str(self.before))
                self.assertEqual(2, result.returncode)
                self.assertEqual(original, self.before.read_bytes())

    def test_input_alias_cannot_be_overwritten(self):
        alias = self.directory / "alias.json"
        alias.hardlink_to(self.before)
        result = self.run_cli("--output", str(alias))
        self.assertEqual(2, result.returncode)
        self.assertEqual(self.before.read_bytes(), alias.read_bytes())

    def test_primary_and_summary_destinations_must_differ(self):
        output = self.directory / "same.json"
        result = self.run_cli("--output", str(output), "--summary-output", str(output))
        self.assertEqual(2, result.returncode)
        self.assertFalse(output.exists())

    def test_absent_case_alias_cannot_replace_primary_report(self):
        probe = self.directory / "case-probe"
        probe.write_text("")
        if not (self.directory / "CASE-PROBE").exists():
            self.skipTest("requires a case-insensitive filesystem")
        for primary_disclosure, summary_disclosure in (("full", "counts"), ("counts", "full")):
            with self.subTest(primary=primary_disclosure):
                primary = self.directory / (primary_disclosure + "-REVIEW.json")
                summary = self.directory / (primary_disclosure + "-review.json")
                result = self.run_cli(
                    "--format", "json", "--output", str(primary),
                    "--disclosure", primary_disclosure, "--summary-output", str(summary),
                    "--summary-disclosure", summary_disclosure,
                )
                self.assertEqual(2, result.returncode, result.stderr)
                report = json.loads(primary.read_text())
                self.assertEqual(1, report["change_count"])
                self.assertEqual(primary_disclosure == "full", CANARY in primary.read_text())
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_output_failure_is_not_a_change_gate_failure(self):
        result = self.run_cli("--output", str(self.directory))
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)

    def test_symlink_loops_use_generic_error_exit_not_gate_exit(self):
        loop = self.directory / (CANARY + "-loop")
        loop.symlink_to(loop.name)
        for flag in ("--output", "--summary-output", "--before"):
            with self.subTest(flag=flag):
                arguments = [flag, str(loop)]
                if flag != "--output":
                    arguments.extend(["--output", str(self.directory / "report.json")])
                result = self.run_cli(*arguments)
                self.assertEqual(2, result.returncode)
                self.assertEqual("descriptor_review_failed", json.loads(result.stderr)["error"])
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_gate_meaning_is_independent_of_disclosure(self):
        for disclosure in ("full", "counts", "paths"):
            with self.subTest(disclosure=disclosure):
                self.assertEqual(1, self.run_cli("--disclosure", disclosure, "--fail-on", "change").returncode)
                self.assertEqual(0, self.run_cli("--disclosure", disclosure, "--fail-on", "findings").returncode)
        self.after.write_bytes(self.before.read_bytes())
        self.assertEqual(0, self.run_cli("--fail-on", "change").returncode)


if __name__ == "__main__":
    unittest.main()
