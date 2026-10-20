from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from scripts.prepare_practical_evaluation import select_versions
from scripts.check_practical_review import verified_captures, verify_inventory
from scripts.run_practical_evaluation import acquire, changed_paths, digest, launch_environment, run, tool_map


class PracticalEvaluationTests(unittest.TestCase):
    def test_selection_uses_publication_time_not_semantic_version(self):
        metadata = {"name": "test", "versions": dict.fromkeys(("9.0.0", "1.0.0", "2.0.0", "3.0.0-rc.1")), "time": {
            "9.0.0": "2026-10-16T23:00:00Z", "1.0.0": "2026-10-17T01:00:00+01:00", "2.0.0": "2026-10-18T00:00:00Z", "3.0.0-rc.1": "2026-10-17T10:00:00Z"}}
        self.assertEqual(select_versions(metadata, "2026-10-18T00:00:00Z", 2), ["9.0.0", "1.0.0"])

    def test_structural_inventory_preserves_types_and_arrays(self):
        self.assertEqual(changed_paths({"a/b": None}, {}), ["/a~1b"])
        self.assertEqual(changed_paths([True], [1]), ["/"])
        self.assertEqual(changed_paths([1, 2], [2, 1]), ["/"])
        with self.assertRaises(ValueError):
            tool_map({"tools": [{"name": "a"}, {"name": "a"}]})

    def test_environment_does_not_inherit_credentials_or_home(self):
        environment = launch_environment(Path("work"))
        self.assertNotIn("HOME", environment)
        self.assertNotIn("CONTEXT7_API_KEY", environment)
        self.assertEqual(environment["OTEL_SDK_DISABLED"], "true")

    def test_capture_pages_and_rejects_repeated_cursor(self):
        server = '''import json, sys
for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request: continue
    if request["method"] == "initialize": result = {"protocolVersion": "2025-11-25"}
    elif "cursor" not in request["params"]: result = {"tools": [{"name": "a", "inputSchema": {}}], "nextCursor": "page2"}
    else: result = {"tools": [{"name": "b", "inputSchema": {}}]}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
'''
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            result = asyncio.run(acquire([sys.executable, "-u", "-c", server], work, {"timeout_seconds": 2, "max_pages": 3}, False))
            self.assertEqual([tool["name"] for tool in result["tools"]], ["a", "b"])
            broken = server.replace('{"tools": [{"name": "b", "inputSchema": {}}]}', '{"tools": [], "nextCursor": "page2"}')
            with self.assertRaisesRegex(ValueError, "repeated-cursor"):
                asyncio.run(acquire([sys.executable, "-u", "-c", broken], work, {"timeout_seconds": 2, "max_pages": 3}, False))

    def test_capture_timeout_terminates_server(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(TimeoutError):
            asyncio.run(acquire([sys.executable, "-u", "-c", "import time; time.sleep(10)"], Path(temporary), {"timeout_seconds": 0.05, "max_pages": 3}, False))

    def test_acquisition_rejects_an_existing_work_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / "captures").mkdir()
            with self.assertRaisesRegex(ValueError, "fresh --work"):
                asyncio.run(run(SimpleNamespace(work=work)))


class PracticalReviewVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.capture = self.work / "captures" / "example"
        self.capture.mkdir(parents=True)
        self.snapshot = {"tools": [{"name": "lookup", "inputSchema": {}}]}
        for repetition in range(2):
            (self.capture / f"{repetition}.json").write_text(json.dumps(self.snapshot))
        self.original = [{"alias": "example", "status": "stable", "tool_set_sha256": [digest(tool_map(self.snapshot))] * 2}]
        self.reproduced = copy.deepcopy(self.original)

    def test_both_repetitions_match_the_frozen_identity(self):
        snapshots = verified_captures(self.work, self.original, self.reproduced, 2)
        self.assertEqual(snapshots, {"example": self.snapshot})

    def test_missing_second_capture_fails(self):
        (self.capture / "1.json").unlink()
        with self.assertRaises(FileNotFoundError):
            verified_captures(self.work, self.original, self.reproduced, 2)

    def test_divergent_second_capture_fails_even_with_stable_receipt(self):
        self.snapshot["tools"][0]["title"] = "Changed on the second launch"
        (self.capture / "1.json").write_text(json.dumps(self.snapshot))
        with self.assertRaisesRegex(ValueError, "Capture identity"):
            verified_captures(self.work, self.original, self.reproduced, 2)

    def test_failed_reproduction_cannot_pass_with_matching_files(self):
        self.reproduced[0]["status"] = "failed-or-unstable"
        with self.assertRaisesRegex(ValueError, "stable"):
            verified_captures(self.work, self.original, self.reproduced, 2)

    def test_missing_duplicate_or_different_capture_receipts_fail(self):
        for captures in ([], self.reproduced * 2, [{**self.reproduced[0], "tool_set_sha256": ["different"] * 2}]):
            with self.subTest(captures=captures), self.assertRaises(ValueError):
                verified_captures(self.work, self.original, captures, 2)

    def test_rule_histogram_must_match_not_only_the_count(self):
        report = {"changes": [{"path": "/tools/lookup/title"}], "policy_findings": [{"risk": "risky_tool_added"}]}
        row = {"package": "example", "before": "1", "after": "2", "structural_paths": ["/lookup/title"],
               "baseline_finding_count": 1, "baseline_rules": {"risky_tool_added": 1}}
        verify_inventory(report, row)
        report["policy_findings"][0]["risk"] = "schema_containment_unresolved"
        with self.assertRaisesRegex(ValueError, "frozen inventory"):
            verify_inventory(report, row)


if __name__ == "__main__":
    unittest.main()
