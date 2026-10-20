from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CANARY = "PRIVATE_ACTION_CANARY_3819"


class ReviewActionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.before, self.after = self.root / "before.json", self.root / "after.json"
        snapshot = {"tools": [{"name": "lookup", "inputSchema": {}, "custom": "old", "annotations": {"readOnlyHint": True}}]}
        self.before.write_text(json.dumps(snapshot))
        snapshot["tools"][0]["custom"] = CANARY
        self.after.write_text(json.dumps(snapshot))
        self.report, self.summary = self.root / "review.json", self.root / "review.md"
        self.outputs, self.job_summary = self.root / "outputs", self.root / "job-summary"
        self.environment = {
            "TCD_REVIEW_BEFORE": str(self.before), "TCD_REVIEW_AFTER": str(self.after),
            "TCD_REVIEW_REPORT": str(self.report), "TCD_REVIEW_SUMMARY": str(self.summary),
            "GITHUB_OUTPUT": str(self.outputs), "GITHUB_STEP_SUMMARY": str(self.job_summary),
        }

    def run_action(self, **settings):
        environment = {key: value for key, value in os.environ.items() if not key.startswith("TCD_REVIEW_")}
        environment.update(self.environment)
        environment.update(settings)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-B", "-m", "tool_contract_drift.review_action"],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10,
        )

    def output_fields(self):
        return dict(line.split("=", 1) for line in self.outputs.read_text().splitlines())

    def test_quiet_change_is_retained_and_gated_with_counts_only_job_summary(self):
        result = self.run_action(TCD_REVIEW_FAIL_ON="change")
        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual(1, report["change_count"])
        self.assertEqual([], report["policy_findings"])
        self.assertEqual(CANARY, report["changes"][0]["after"])
        self.assertEqual({"status": "changed", "change-count": "1", "policy-finding-count": "0",
                          "report-path": str(self.report), "summary-path": str(self.summary)}, self.output_fields())
        self.assertEqual(self.summary.read_bytes(), self.job_summary.read_bytes())
        self.assertNotIn(CANARY, self.job_summary.read_text() + result.stdout + result.stderr)
        self.assertNotIn("lookup", self.job_summary.read_text())

    def test_labeled_change_does_not_hide_unlabeled_change(self):
        after = json.loads(self.after.read_text())
        after["tools"][0]["annotations"]["readOnlyHint"] = False
        self.after.write_text(json.dumps(after))
        result = self.run_action(TCD_REVIEW_FAIL_ON="findings")
        self.assertEqual(1, result.returncode, result.stderr)
        report = json.loads(self.report.read_text())
        self.assertEqual(2, report["change_count"])
        self.assertTrue(report["policy_findings"])
        self.assertIn("/tools/lookup/custom", [change["path"] for change in report["changes"]])

    def test_report_only_and_unchanged_results_are_distinct(self):
        self.assertEqual(0, self.run_action().returncode)
        self.assertEqual("changed", self.output_fields()["status"])
        self.after.write_bytes(self.before.read_bytes())
        self.outputs.write_text("")
        result = self.run_action(TCD_REVIEW_FAIL_ON="change", TCD_REVIEW_POST_SUMMARY="false")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("unchanged", self.output_fields()["status"])
        self.assertEqual("0", self.output_fields()["change-count"])

    def test_invalid_input_never_publishes_a_successful_comparison(self):
        self.after.write_text(json.dumps({"tools": [{"name": CANARY, "inputSchema": False}]}))
        result = self.run_action()
        self.assertEqual(2, result.returncode)
        self.assertFalse(self.outputs.exists())
        self.assertFalse(self.job_summary.exists())
        self.assertFalse(self.report.exists())
        self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_invalid_input_does_not_publish_stale_existing_reports(self):
        self.report.write_text('{"status": "unchanged", "old": true}')
        self.summary.write_text("Previous comparison, not current evidence.")
        self.after.write_text("not JSON")
        result = self.run_action()
        self.assertEqual(2, result.returncode)
        self.assertFalse(self.outputs.exists())
        self.assertFalse(self.job_summary.exists())
        self.assertEqual({"status": "unchanged", "old": True}, json.loads(self.report.read_text()))
        self.assertEqual("Previous comparison, not current evidence.", self.summary.read_text())

    def test_sensitive_summary_disclosure_requires_explicit_opt_in(self):
        result = self.run_action(TCD_REVIEW_DISCLOSURE="paths")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("lookup", self.job_summary.read_text())
        self.assertNotIn(CANARY, self.job_summary.read_text())
        result = self.run_action(TCD_REVIEW_DISCLOSURE="full")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(CANARY, self.summary.read_text())

    def test_posting_can_be_disabled_without_losing_local_reports(self):
        result = self.run_action(TCD_REVIEW_POST_SUMMARY="false")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(self.job_summary.exists())
        self.assertTrue(self.report.exists())
        self.assertTrue(self.summary.exists())

    def test_paths_are_data_not_shell_commands(self):
        output = self.root / "report $(touch ATTACKED); 'literal'.json"
        result = self.run_action(TCD_REVIEW_REPORT=str(output))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(output.exists())
        self.assertFalse((ROOT / "ATTACKED").exists())

    def test_runner_rejects_invalid_controls_and_multiline_output_injection(self):
        for key, value in (
            ("TCD_REVIEW_FAIL_ON", "approve"), ("TCD_REVIEW_DISCLOSURE", CANARY),
            ("TCD_REVIEW_POST_SUMMARY", "yes"), ("TCD_REVIEW_REPORT", "file\nstatus=unchanged"),
            ("TCD_REVIEW_BEFORE", ""), ("GITHUB_OUTPUT", ""),
        ):
            with self.subTest(key=key):
                result = self.run_action(**{key: value})
                self.assertEqual(2, result.returncode)
                self.assertFalse(self.outputs.exists())
                self.assertFalse(self.job_summary.exists())
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_github_files_must_not_alias_reports_or_inputs(self):
        original = self.before.read_bytes()
        for settings in ({"GITHUB_OUTPUT": str(self.report)}, {"GITHUB_OUTPUT": str(self.before)}, {"GITHUB_STEP_SUMMARY": str(self.summary)}):
            with self.subTest(settings=settings):
                result = self.run_action(**settings)
                self.assertEqual(2, result.returncode)
                self.assertEqual(original, self.before.read_bytes())
                self.assertFalse(self.report.exists())

    def test_absent_case_aliases_cannot_corrupt_reports_or_github_files(self):
        probe = self.root / "case-probe"
        probe.write_text("")
        if not (self.root / "CASE-PROBE").exists():
            self.skipTest("requires a case-insensitive filesystem")
        for index, (key, target) in enumerate((
            ("TCD_REVIEW_SUMMARY", self.report),
            ("GITHUB_OUTPUT", self.report),
            ("GITHUB_STEP_SUMMARY", self.summary),
            ("GITHUB_OUTPUT", self.job_summary),
        )):
            with self.subTest(key=key, target=target.name):
                directory = self.root / str(index)
                directory.mkdir()
                paths = {name: str(directory / path.name) for name, path in (
                    ("TCD_REVIEW_REPORT", self.report), ("TCD_REVIEW_SUMMARY", self.summary),
                    ("GITHUB_OUTPUT", self.outputs), ("GITHUB_STEP_SUMMARY", self.job_summary),
                )}
                paths[key] = str(directory / target.name.upper())
                result = self.run_action(**paths)
                self.assertEqual(2, result.returncode, result.stderr)
                report = json.loads((directory / self.report.name).read_text())
                self.assertEqual(1, report["change_count"])
                self.assertNotIn(CANARY, result.stdout + result.stderr)
                if key == "GITHUB_OUTPUT" and target == self.job_summary:
                    self.assertNotIn("status=", (directory / target.name).read_text())
                elif key == "GITHUB_OUTPUT":
                    self.assertNotIn("status=", (directory / self.report.name).read_text())

    def test_action_python_commands_ignore_checkout_and_pythonpath_shadows(self):
        action = (ROOT / "actions/descriptor-review/action.yml").read_text()
        commands = [shlex.split(line.strip()[5:]) for line in action.splitlines() if line.strip().startswith("run: ")]
        self.assertEqual(2, len(commands))
        for command in commands:
            self.assertIn("-I", command[:command.index("-m")])
        legacy = (ROOT / "action.yml").read_text()
        legacy_install = next(shlex.split(line.strip()[5:]) for line in legacy.splitlines()
                              if line.strip().startswith("run: "))
        self.assertIn("-I", legacy_install[:legacy_install.index("-m")])
        self.assertIn("cmd=(python -I -B -m tool_contract_drift_cli lint ", legacy)
        (self.root / "pip.py").write_text("raise SystemExit('CHECKOUT_SHADOW_EXECUTED')\n")
        prefix = commands[0][1:commands[0].index("pip") + 1]
        result = subprocess.run(
            [sys.executable, *prefix, "--version"], cwd=self.root,
            env={**os.environ, "PYTHONPATH": str(self.root)},
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode:
            # uv test environments need not include pip; never fall back to the checkout.
            self.assertEqual(f"{sys.executable}: No module named pip", result.stderr.strip())
        self.assertNotIn("CHECKOUT_SHADOW_EXECUTED", result.stdout + result.stderr)

    def test_symlink_loops_cannot_leak_paths_or_masquerade_as_gate_failure(self):
        loop = self.root / (CANARY + "-loop")
        loop.symlink_to(loop.name)
        for key in ("TCD_REVIEW_REPORT", "TCD_REVIEW_BEFORE", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY"):
            with self.subTest(key=key):
                result = self.run_action(**{key: str(loop)})
                self.assertEqual(2, result.returncode)
                self.assertEqual("descriptor_review_failed", json.loads(result.stderr)["error"])
                self.assertNotIn(CANARY, result.stdout + result.stderr)
                self.assertFalse(self.outputs.exists())
                self.assertFalse(self.job_summary.exists())


if __name__ == "__main__":
    unittest.main()
