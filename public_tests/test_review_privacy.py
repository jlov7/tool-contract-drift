from __future__ import annotations

import copy
import json
import unittest

from tool_contract_drift import review_descriptor_pair
from tool_contract_drift.review_privacy import minimize_review_report


CANARY = "PRIVATE_CANARY_7d9c"
SUMMARY_KEYS = {
    "schema_version", "disclosure", "status", "change_count",
    "policy_finding_count", "operation_counts", "boundary",
}
BOUNDARY = (
    "Counts disclose aggregate structure. Paths disclosure explicitly includes tool "
    "names and paths and is not anonymization. This summary is not approval evidence "
    "or evidence of runtime safety."
)


class ReviewPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "schema_version": CANARY + "_schema",
            "status": "changed",
            "before_sha256": CANARY + "_before_hash",
            "after_sha256": CANARY + "_after_hash",
            "change_count": 3,
            "changes": [
                {
                    "tool_name": CANARY + "_tool_" + op,
                    "path": "/tools/" + CANARY + "/" + op,
                    "op": op,
                    "before": {CANARY + "_key": [CANARY + "_before_value"]},
                    "after": [CANARY + "_after_value"],
                    "label": CANARY + "_label",
                    "reason": CANARY + "_reason",
                    "evidence": {"message": CANARY + "_evidence"},
                    "extra": CANARY + "_change_extra",
                }
                for op in ("add", "remove", "replace")
            ],
            "policy_findings": [{
                "fixture_id": CANARY + "_fixture",
                "tool_name": CANARY + "_finding_tool",
                "path": CANARY + "_finding_path",
                "label": CANARY + "_finding_label",
                "risk": CANARY + "_risk",
                "message": CANARY + "_message",
                "evidence": {"before": CANARY + "_finding_value"},
            }],
            "changed_without_policy_findings": False,
            "boundary": CANARY + "_boundary",
            "context": {"custom": CANARY + "_context"},
            "fixture_id": CANARY + "_input_id",
            "extra": CANARY + "_report_extra",
        }

    def assert_invalid(self, report, disclosure="counts"):
        with self.assertRaises(ValueError) as caught:
            minimize_review_report(report, disclosure)
        self.assertIn(str(caught.exception), (
            "Invalid review report.", "Invalid disclosure mode.",
        ))
        self.assertNotIn(CANARY, str(caught.exception))

    def test_counts_exact_allowlist_excludes_canaries_and_preserves_source(self):
        original = copy.deepcopy(self.report)
        result = minimize_review_report(self.report)
        self.assertEqual(set(result), SUMMARY_KEYS)
        self.assertEqual(result, {
            "schema_version": "tool-descriptor-review-summary-v1",
            "disclosure": "counts", "status": "changed", "change_count": 3,
            "policy_finding_count": 1,
            "operation_counts": {"add": 1, "remove": 1, "replace": 1},
            "boundary": BOUNDARY,
        })
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertEqual(self.report, original)

    def test_paths_exact_allowlist_exposes_only_opted_in_identifiers(self):
        original = copy.deepcopy(self.report)
        result = minimize_review_report(self.report, "paths")
        expected_changes = [
            {key: change[key] for key in ("tool_name", "path", "op")}
            for change in self.report["changes"]
        ]
        self.assertEqual(set(result), SUMMARY_KEYS | {"changes"})
        self.assertEqual(result, {
            **minimize_review_report(self.report),
            "disclosure": "paths", "changes": expected_changes,
        })
        for change in result["changes"]:
            self.assertEqual(set(change), {"tool_name", "path", "op"})
        without_identifiers = copy.deepcopy(result)
        without_identifiers.pop("changes")
        self.assertNotIn(CANARY, json.dumps(without_identifiers))
        self.assertEqual(self.report, original)

    def test_returned_containers_share_no_source_references(self):
        original = copy.deepcopy(self.report)
        result = minimize_review_report(self.report, "paths")
        self.assertIsNot(result, self.report)
        self.assertIsNot(result["changes"], self.report["changes"])
        for projected, source in zip(result["changes"], self.report["changes"]):
            self.assertIsNot(projected, source)
        result["changes"][0]["tool_name"] = "edited"
        result["changes"].append({})
        result["operation_counts"]["add"] = 99
        self.assertEqual(self.report, original)
        self.report["changes"][1]["path"] = "edited source"
        self.assertEqual(result["changes"][1]["path"], original["changes"][1]["path"])
        self.assertEqual(minimize_review_report(original)["operation_counts"]["add"], 1)

    def test_real_full_reports_with_and_without_changes(self):
        before = {"tools": [{"name": "lookup", "inputSchema": {}}]}
        after = copy.deepcopy(before)
        after["tools"][0]["title"] = CANARY
        for descriptor, status, count in ((before, "unchanged", 0), (after, "changed", 1)):
            for mode in ("counts", "paths"):
                with self.subTest(status=status, mode=mode):
                    report = review_descriptor_pair(before, descriptor, CANARY)
                    result = minimize_review_report(report, mode)
                    self.assertEqual(result["status"], status)
                    self.assertEqual(result["change_count"], count)
                    self.assertEqual(result["operation_counts"], {"add": count, "remove": 0, "replace": 0})
                    self.assertEqual(set(result), SUMMARY_KEYS | ({"changes"} if mode == "paths" else set()))
                    self.assertNotIn(CANARY, json.dumps(result))
                    if mode == "paths":
                        self.assertEqual(result["changes"], [{"tool_name": "lookup", "path": "/tools/lookup/title", "op": "add"}] if count else [])

    def test_repeated_operations_and_arbitrary_findings_are_counted(self):
        self.report["changes"] = [copy.deepcopy(self.report["changes"][0]) for _ in range(3)]
        self.report["policy_findings"] = [CANARY, None, [CANARY], {CANARY: CANARY}]
        result = minimize_review_report(self.report)
        self.assertEqual(result["operation_counts"], {"add": 3, "remove": 0, "replace": 0})
        self.assertEqual(result["policy_finding_count"], 4)
        self.assertNotIn(CANARY, json.dumps(result))

    def test_invalid_modes_are_rejected_without_disclosing_input(self):
        for mode in ("full", CANARY, "", None, [], {}, 1):
            with self.subTest(mode=mode):
                self.assert_invalid(self.report, mode)

    def test_invalid_top_level_types_and_missing_fields(self):
        for mode in ("counts", "paths"):
            for report in (None, CANARY, [], 1, {}):
                with self.subTest(mode=mode, report=report):
                    self.assert_invalid(report, mode)
            for field in ("status", "change_count", "changes", "policy_findings"):
                with self.subTest(mode=mode, field=field):
                    report = copy.deepcopy(self.report)
                    del report[field]
                    self.assert_invalid(report, mode)

    def test_changes_and_findings_must_be_lists(self):
        for mode in ("counts", "paths"):
            for field in ("changes", "policy_findings"):
                for value in (None, CANARY, {}, (), 3):
                    with self.subTest(mode=mode, field=field, value=value):
                        report = copy.deepcopy(self.report)
                        report[field] = value
                        self.assert_invalid(report, mode)

    def test_status_and_count_must_match_actual_changes(self):
        for mode in ("counts", "paths"):
            for field, values in (
                ("status", (CANARY, "unchanged", "CHANGED", None, [], {})),
                ("change_count", (CANARY, -1, 0, 2, 4, 3.0, True, None, [])),
            ):
                for value in values:
                    with self.subTest(mode=mode, field=field, value=value):
                        report = copy.deepcopy(self.report)
                        report[field] = value
                        self.assert_invalid(report, mode)
            report = copy.deepcopy(self.report)
            report.update(changes=[], change_count=0)
            self.assert_invalid(report, mode)
            report.update(changes=[self.report["changes"][0]], change_count=True)
            self.assert_invalid(report, mode)
            report.update(changes=[], status="unchanged", change_count=False)
            self.assert_invalid(report, mode)

    def test_invalid_changes_identifiers_and_operations_have_generic_errors(self):
        for mode in ("counts", "paths"):
            for value in (None, CANARY, [], 1):
                with self.subTest(mode=mode, change=value):
                    report = copy.deepcopy(self.report)
                    report["changes"][0] = value
                    self.assert_invalid(report, mode)
            for field, values in (
                ("op", (CANARY, "move", "copy", "test", "ADD", None, [], {}, 1)),
                ("tool_name", (None, [CANARY], {CANARY: CANARY}, 1)),
                ("path", (None, [CANARY], {CANARY: CANARY}, 1)),
            ):
                for value in values:
                    with self.subTest(mode=mode, field=field, value=value):
                        report = copy.deepcopy(self.report)
                        report["changes"][0][field] = value
                        self.assert_invalid(report, mode)
                report = copy.deepcopy(self.report)
                del report["changes"][0][field]
                self.assert_invalid(report, mode)


if __name__ == "__main__":
    unittest.main()
