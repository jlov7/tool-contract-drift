from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import unittest

from tool_contract_drift import review_descriptor_pair
from tool_contract_drift.review_render import render_review_markdown


def json_blocks(markdown):
    return [json.loads(match[1]) for match in re.findall(
        r"^(`{3,})json\n(.*?)\n\1$", markdown, re.MULTILINE | re.DOTALL,
    )]


class ReviewRenderTests(unittest.TestCase):
    def setUp(self):
        self.before = {"tools": [{"name": "lookup", "inputSchema": {}, "annotations": {"readOnlyHint": True}}]}
        self.after = copy.deepcopy(self.before)

    def test_committed_quiet_example_matches_the_renderer(self):
        root = Path(__file__).resolve().parents[1]
        before = json.loads((root / "examples/before_quiet_change.json").read_text())
        after = json.loads((root / "examples/after_quiet_change.json").read_text())
        rendered = render_review_markdown(review_descriptor_pair(before, after))
        self.assertEqual(rendered, (root / "examples/quiet_change_review.md").read_text())

    def test_groups_every_entry_by_tool_operation_and_path_without_mutating(self):
        self.before["tools"][0].update({"old": [1, False, None], "custom": True})
        self.after["tools"][0].update({"new": {"nested": [1, 2]}, "custom": 1})
        self.after["tools"].append({"name": "other", "inputSchema": {}, "title": "Added"})
        report = review_descriptor_pair(self.before, self.after)
        snapshot = copy.deepcopy(report)
        text = render_review_markdown(report)
        blocks = json_blocks(text)
        self.assertEqual(report, snapshot)
        self.assertEqual(text, render_review_markdown(report))
        self.assertEqual(text.count("### Tool:"), 2)
        self.assertEqual(text.count("##### Path:"), report["change_count"])
        self.assertEqual(blocks[0], {
            key: value for key, value in report.items() if key not in ("changes", "policy_findings")
        })
        self.assertEqual(len(blocks), 1 + report["change_count"] + len(report["policy_findings"]))
        for change in report["changes"]:
            self.assertIn(json.dumps(change["path"]), text)
            self.assertIn({key: change[key] for key in ("before", "after") if key in change}, blocks)
        self.assertLess(text.index("#### Add"), text.index("#### Remove"))
        self.assertLess(text.index("#### Remove"), text.index("#### Replace"))

    def test_findings_never_hide_unlabeled_changes_on_the_same_tool(self):
        self.after["tools"][0]["annotations"]["readOnlyHint"] = False
        self.after["tools"][0]["title"] = "Unlabeled title"
        report = review_descriptor_pair(self.before, self.after)
        self.assertTrue(report["policy_findings"])
        snapshot = copy.deepcopy(report)
        text = render_review_markdown(report)
        self.assertEqual(report, snapshot)
        self.assertIn("Unlabeled title", text)
        self.assertEqual(text.count("##### Path:"), 2)
        self.assertIn("all changes above remain for review", text)
        # Findings contain tuples in memory; JSON faithfully represents them as arrays.
        finding_blocks = json_blocks(text)[1 + report["change_count"]:]
        self.assertEqual(
            json.dumps(report["policy_findings"], sort_keys=True),
            json.dumps(finding_blocks, sort_keys=True),
        )
        self.assertGreater(text.index("## Policy Findings"), text.index("##### Path:"))

    def test_added_removed_tools_preserve_whole_objects_and_escaped_names(self):
        added = {"name": "a/b~c", "inputSchema": {}, "custom": {"null": None, "array": [False, 1]}}
        report = review_descriptor_pair(self.before, {"tools": [added]})
        text = render_review_markdown(report)
        self.assertEqual(text.count("##### Path:"), 2)
        self.assertIn('### Tool: ` "a/b~c" `', text)
        self.assertIn('##### Path: ` "/tools/a~1b~0c" `', text)
        self.assertEqual(json_blocks(text)[1:], [
            {"after": added}, {"before": self.before["tools"][0]},
        ])

    def test_null_is_distinct_from_missing_for_add_remove_and_replace(self):
        self.before["tools"][0].update({"removed": None, "replaced": None})
        self.after["tools"][0].update({"added": None, "replaced": False})
        text = render_review_markdown(review_descriptor_pair(self.before, self.after))
        self.assertEqual(text.count("Before: missing (key not present)."), 1)
        self.assertEqual(text.count("After: missing (key not present)."), 1)
        for values in ({"after": None}, {"before": None}, {"before": None, "after": False}):
            self.assertIn(values, json_blocks(text))

    def test_multiline_diff_and_long_values_are_complete_and_safely_fenced(self):
        before = "\n".join(f"line {index}" for index in range(100)) + "\n``````\nend\n"
        after = before.replace("line 50\n", "changed 50\n") + "x" * 12000
        self.before["tools"][0]["description"] = before
        self.after["tools"][0]["description"] = after
        text = render_review_markdown(review_descriptor_pair(self.before, self.after))
        self.assertIn({"before": before, "after": after}, json_blocks(text))
        self.assertIn("unchanged context omitted; full values available in JSON", text)
        self.assertIn("-line 50\n+changed 50", text)
        self.assertIn("```````diff\n", text)
        self.assertIn("x" * 12000, text)
        self.assertLess(text.index("```````diff\n"), text.index("<details><summary>Full values (JSON)</summary>"))
        self.assertIn("<details><summary>Full values (JSON)</summary>\n\n```````json\n", text)
        self.assertIn("\n```````\n\n</details>", text)

    def test_long_single_line_replacement_uses_diff_first_and_complete_collapsed_json(self):
        before, after = "old" * 1000, "new" * 1000
        self.before["tools"][0]["description"] = before
        self.after["tools"][0]["description"] = after
        text = render_review_markdown(review_descriptor_pair(self.before, self.after))
        self.assertLess(text.index("```diff\n"), text.index("<details><summary>Full values (JSON)</summary>"))
        self.assertIn({"before": before, "after": after}, json_blocks(text))

    def test_short_text_and_nontext_values_remain_immediate_json(self):
        self.before["tools"][0]["title"] = "Before"
        self.after["tools"][0].update({"title": "After", "custom": [1, False, None]})
        text = render_review_markdown(review_descriptor_pair(self.before, self.after))
        self.assertNotIn("<summary>Full values (JSON)</summary>", text)
        self.assertNotIn("```diff\n", text)
        self.assertIn({"before": "Before", "after": "After"}, json_blocks(text))
        self.assertIn({"after": [1, False, None]}, json_blocks(text))

    def test_long_paths_and_many_entries_are_not_truncated(self):
        key = "segment/with~escape" * 1000
        self.after["tools"][0][key] = {"nested": list(range(100))}
        self.after["tools"][0].update({f"entry{index}": index for index in range(150)})
        report = review_descriptor_pair(self.before, self.after)
        text = render_review_markdown(report)
        self.assertEqual(text.count("##### Path:"), 151)
        for change in report["changes"]:
            self.assertIn(json.dumps(change["path"]), text)
            self.assertIn({"after": change["after"]}, json_blocks(text))

    def test_hostile_names_paths_values_findings_and_boundary_are_inert_utf8(self):
        hostile = '![](<https://evil.invalid>) [click](javascript:alert(1)) ` ```\n# injected\n<script>&</script>\r\x00\x1b[2J\x7f\x85\u2028\u2029\u202e\ud800|\udfff'
        tool = {"name": hostile, "inputSchema": {}}
        report = review_descriptor_pair({"tools": [tool]}, {"tools": [dict(tool, custom=hostile)]})
        report["policy_findings"] = [{"tool_name": hostile, "reason": hostile}]
        report["boundary"] = hostile
        text = render_review_markdown(report)
        text.encode("utf-8", errors="strict")
        self.assertNotIn("<script>", text)
        self.assertNotIn("\n# injected", text)
        self.assertFalse(any(ord(char) < 32 and char != "\n" for char in text))
        self.assertTrue(all(ord(char) < 127 for char in text))
        self.assertIn("\\r\\u0000\\u001b", text)
        self.assertIn("\\u2028\\u2029", text)
        self.assertIn("\\ud800", text)
        self.assertIn("\\udfff", text)
        self.assertIn({"after": hostile}, json_blocks(text))
        self.assertIn(report["policy_findings"][0], json_blocks(text))
        tool_heading = next(line for line in text.splitlines() if line.startswith("### Tool:"))
        self.assertTrue(tool_heading.startswith('### Tool: ```` "'))
        self.assertTrue(tool_heading.endswith('" ````'))

    def test_diff_escapes_unicode_separators_surrogates_and_terminal_controls(self):
        before = "old\u2028\u2029\ud800\n<script>\r\x00\x1b\udfff\n```"
        after = before.replace("old", "new")
        self.before["tools"][0]["description"] = before
        self.after["tools"][0]["description"] = after
        text = render_review_markdown(review_descriptor_pair(self.before, self.after))
        text.encode("utf-8", errors="strict")
        self.assertTrue(all(char == "\n" or 32 <= ord(char) < 127 for char in text))
        self.assertNotIn("<script>", text)
        self.assertIn("-old\\u2028\\u2029\\ud800\n+new\\u2028\\u2029\\ud800", text)
        self.assertIn("\\r\\u0000\\u001b\\udfff", text)
        self.assertIn({"before": before, "after": after}, json_blocks(text))

    def summary(self, disclosure="counts", status="changed", findings=2):
        result = {
            "schema_version": "tool-descriptor-review-summary-v1", "disclosure": disclosure,
            "status": status, "change_count": 3 if status == "changed" else 0,
            "policy_finding_count": findings,
            "operation_counts": {op: 1 if status == "changed" else 0 for op in ("add", "remove", "replace")},
            "boundary": "Summary only. Details withheld; no approval or runtime safety conclusion.",
        }
        if disclosure == "paths":
            result["changes"] = [
                {"tool_name": "lookup", "path": f"/tools/lookup/{op}", "op": op}
                for op in ("add", "remove", "replace")
            ] if status == "changed" else []
        return result

    def test_counts_summary_needs_no_changes_names_paths_values_or_hashes(self):
        report = self.summary()
        text = render_review_markdown(report)
        self.assertIn({"add": 1, "remove": 1, "replace": 1}, json_blocks(text))
        self.assertIn("only the count is disclosed", text)
        self.assertNotIn("### Tool:", text)
        self.assertNotIn("Report Metadata", text)
        report.update({"changes": [{"tool_name": "PRIVATE_NAME", "path": "/PRIVATE_PATH", "after": "PRIVATE_VALUE"}],
                       "policy_findings": [{"reason": "PRIVATE_FINDING"}], "before_sha256": "PRIVATE_HASH"})
        self.assertEqual(text, render_review_markdown(report))

    def test_paths_summary_shows_only_names_operations_paths_never_values_or_findings(self):
        report = self.summary("paths")
        text = render_review_markdown(report)
        self.assertEqual(text.count("##### Path:"), 3)
        self.assertNotIn("missing", text)
        self.assertNotIn("Report Metadata", text)
        for change in report["changes"]:
            self.assertIn(json.dumps(change["path"]), text)
            change.update({"before": "PRIVATE_VALUE", "after": "PRIVATE_VALUE", "extra": "PRIVATE_EXTRA"})
        report.update({"policy_findings": [{"reason": "PRIVATE_FINDING"}], "after_sha256": "PRIVATE_HASH"})
        self.assertEqual(text, render_review_markdown(report))

    def test_paths_summary_escapes_hostile_names_without_synthesizing_details(self):
        report = self.summary("paths")
        report["changes"][0].update({"tool_name": "```\n<script>\r\ud800", "path": "![x](https://evil.invalid)\x1b"})
        text = render_review_markdown(report)
        text.encode("utf-8", errors="strict")
        self.assertNotIn("<script>", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("### Finding 1", text)
        self.assertNotIn("Before:", text)
        self.assertNotIn("After:", text)

    def test_unchanged_and_no_findings_are_explicit_never_approval(self):
        full = review_descriptor_pair(self.before, self.before)
        for report in (full, self.summary(status="unchanged", findings=0), self.summary("paths", "unchanged", 0)):
            with self.subTest(schema=report["schema_version"], disclosure=report.get("disclosure")):
                text = render_review_markdown(report)
                self.assertIn("No structural changes.", text)
                self.assertIn("No policy findings reported. This is not approval.", text)
                self.assertIn("does not imply approval or runtime safety", text)
        self.after["tools"][0]["title"] = "Quiet edit"
        text = render_review_markdown(review_descriptor_pair(self.before, self.after))
        self.assertIn("Quiet edit", text)
        self.assertIn("This is not approval.", text)
        self.assertNotIn("No structural changes.", text)

    def test_unknown_schema_and_disclosure_fail_without_echoing_input(self):
        for updates in ({"schema_version": "PRIVATE"}, {"disclosure": "PRIVATE"}, {"disclosure": "full"}):
            report = self.summary()
            report.update(updates)
            with self.subTest(updates=updates), self.assertRaisesRegex(ValueError, "^Unsupported review (schema|disclosure)\\.$"):
                render_review_markdown(report)


if __name__ == "__main__":
    unittest.main()
