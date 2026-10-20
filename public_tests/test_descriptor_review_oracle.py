"""Independent structural paths and executable, reversible report operations."""
from __future__ import annotations

import copy
import hashlib
import json
import random
import unittest

from deepdiff import DeepDiff
from deepdiff.operator import BaseOperator
import jsonpatch

from tool_contract_drift import review_descriptor_pair


SEEDS = (7, 101, 20261020, 8675309)
CASES_PER_SEED = 100
MAX_DEPTH = 3
MAX_CHILDREN = 3
MAX_TOOLS = 3
MAX_DESCRIPTOR_BYTES = 32768
KEYS = ("", "a/b~c", "__private", "quote'\"\\", "\u96ea", "0", "plain")
NAMES = ("lookup", "a/b~c", "\u96ea", "quote'\"\\", "__private")
SCALARS = (None, False, True, 0, 1, -1, 2**64, 0.0, -0.0, 1.0, 1e-12,
           1e100, "", "null", "\u96ea\U0001f680", "a/b~c")


def json_bytes(value):
    """Type-sensitive JSON spelling, not Python's True == 1 == 1.0 equality."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


class AtomicJsonLeaves(BaseOperator):
    """Declare atomic ordered arrays and adjudicate DeepDiff's signed-zero edge."""

    def match(self, level):
        left, right = level.t1, level.t2
        return (isinstance(left, list) and isinstance(right, list)) or (
            type(left) is float and type(right) is float and left == right == 0.0
        )

    def give_up_diffing(self, level, diff_instance):
        if json_bytes(level.t1) != json_bytes(level.t2):
            diff_instance.custom_report_result("values_changed", level)
        return True


def name_keyed(descriptor):
    return {"tools": {tool["name"]: tool for tool in descriptor["tools"]}}


def expected_operations(left, right):
    # DeepDiff owns object traversal, membership, type changes and scalar diffing.
    diff = DeepDiff(left, right, view="tree", threshold_to_diff_deeper=0,
                    ignore_private_variables=False, ignore_order=False,
                    custom_operators=[AtomicJsonLeaves()])
    operations = {"dictionary_item_added": "add", "dictionary_item_removed": "remove",
                  "type_changes": "replace", "values_changed": "replace"}
    unexpected = set(diff) - operations.keys()
    if unexpected:
        raise AssertionError(f"Unadjudicated DeepDiff categories: {unexpected}")
    return {
        (operations[category], jsonpatch.JsonPointer.from_parts(
            node.path(output_format="list")).path)
        for category, nodes in diff.items() for node in nodes
    }


def tool(name="lookup", **fields):
    return {"name": name, "inputSchema": {"type": "object", "properties": {}}, **fields}


def random_json(rng, depth=MAX_DEPTH):
    kind = rng.randrange(3) if depth else 0
    if kind == 0:
        return rng.choice(SCALARS)
    if kind == 1:
        return [random_json(rng, depth - 1) for _ in range(rng.randrange(MAX_CHILDREN + 1))]
    return {key: random_json(rng, depth - 1)
            for key in rng.sample(KEYS, rng.randrange(MAX_CHILDREN + 1))}


def random_descriptor(rng):
    tools = []
    for name in rng.sample(NAMES, rng.randrange(MAX_TOOLS + 1)):
        item = tool(name)
        if rng.choice((False, True)):
            item["input_schema"] = item.pop("inputSchema")
        item.update({key: random_json(rng)
                     for key in rng.sample(KEYS, rng.randrange(1, MAX_CHILDREN + 1))})
        tools.append(item)
    return {"tools": tools}


def permute_objects(value, rng):
    if isinstance(value, dict):
        return {key: permute_objects(value[key], rng)
                for key in rng.sample(list(value), len(value))}
    if isinstance(value, list):
        return [permute_objects(item, rng) for item in value]
    return value


class DescriptorReviewOracleTests(unittest.TestCase):
    def assert_pair(self, before, after):
        # Preserve insertion order too, so review cannot silently rewrite a source.
        snapshots = [json.dumps(value, allow_nan=False) for value in (before, after)]
        left, right = name_keyed(before), name_keyed(after)
        expected = expected_operations(left, right)
        report = review_descriptor_pair(before, after)
        actual = {(change["op"], change["path"]) for change in report["changes"]}
        self.assertEqual(expected, actual)
        self.assertEqual(len(actual), len(report["changes"]), "duplicate operations")
        self.assertEqual(len(expected), report["change_count"])
        self.assertEqual("changed" if expected else "unchanged", report["status"])
        for phase, value in (("before", left), ("after", right)):
            self.assertEqual(hashlib.sha256(json_bytes(value["tools"])).hexdigest(),
                             report[f"{phase}_sha256"])

        forward, inverse = [], []
        for change in report["changes"]:
            op, path = change["op"], change["path"]
            pointer = jsonpatch.JsonPointer(path)
            self.assertEqual(change["tool_name"], pointer.parts[1])
            if op != "add":
                self.assertEqual(json_bytes(pointer.resolve(left)), json_bytes(change["before"]))
            if op != "remove":
                self.assertEqual(json_bytes(pointer.resolve(right)), json_bytes(change["after"]))
            forward.append({"op": op, "path": path,
                            **({"value": copy.deepcopy(change["after"])} if op != "remove" else {})})
            inverse.append({"op": {"add": "remove", "remove": "add", "replace": "replace"}[op],
                            "path": path,
                            **({"value": copy.deepcopy(change["before"])} if op != "add" else {})})
        rebuilt = jsonpatch.JsonPatch(forward).apply(left, in_place=False)
        self.assertEqual(json_bytes(right), json_bytes(rebuilt))
        restored = jsonpatch.JsonPatch(list(reversed(inverse))).apply(rebuilt, in_place=False)
        self.assertEqual(json_bytes(left), json_bytes(restored))
        self.assertEqual(snapshots, [json.dumps(value, allow_nan=False) for value in (before, after)])
        return report

    def test_escaped_paths_and_whole_object_additions_removals(self):
        name = "a/b~\u96ea"
        before = {"tools": [tool(name, extension={"": None, "__private": 1,
                                                  "old": {"deep": [1, 2]}}), tool("removed")]}
        after = {"tools": [tool(name, extension={"": False, "__private": 2,
                                                 "new/~": {"deep": [2, 1]}, "quote'\"\\": "\u96ea"}),
                           tool("added/~")]}
        report = self.assert_pair(before, after)
        self.assertEqual({
            ("remove", "/tools/removed"), ("add", "/tools/added~1~0"),
            ("replace", "/tools/a~1b~0\u96ea/extension/"),
            ("replace", "/tools/a~1b~0\u96ea/extension/__private"),
            ("remove", "/tools/a~1b~0\u96ea/extension/old"),
            ("add", "/tools/a~1b~0\u96ea/extension/new~1~0"),
            ("add", "/tools/a~1b~0\u96ea/extension/quote'\"\\"),
        }, {(c["op"], c["path"]) for c in report["changes"]})
        self.assert_pair(after, before)

    def test_types_null_and_ordered_atomic_arrays(self):
        cases = ((True, 1), (False, 0), (1, 1.0), (0.0, -0.0), (None, 0),
                 ({"nested": 1}, []), ([], [None]), ([True], [1]), ([1], [1.0]),
                 ([0.0], [-0.0]), ([1, 2], [2, 1]),
                 ([{"nested": [1, 2]}, None], [{"nested": [2, 1]}, None]),
                 ("\u00e9", "e\u0301"))
        for left, right in cases:
            with self.subTest(left=left, right=right):
                report = self.assert_pair({"tools": [tool(extension=left)]},
                                          {"tools": [tool(extension=right)]})
                self.assertEqual([("replace", "/tools/lookup/extension")],
                                 [(c["op"], c["path"]) for c in report["changes"]])
        missing, null = {"tools": [tool()]}, {"tools": [tool(extension=None)]}
        self.assertEqual("add", self.assert_pair(missing, null)["changes"][0]["op"])
        self.assertEqual("remove", self.assert_pair(null, missing)["changes"][0]["op"])

    def test_raw_deepdiff_disagreements_remain_explicit(self):
        # Do not present raw DeepDiff equality as JSON-byte equivalence.
        for left, right in ((0.0, -0.0), ([True], [1]), ([1], [1.0]), ([0.0], [-0.0])):
            with self.subTest(left=left, right=right):
                raw = DeepDiff({"extension": left}, {"extension": right}, view="tree",
                               threshold_to_diff_deeper=0, ignore_private_variables=False,
                               ignore_order=False)
                self.assertEqual({}, raw, "Reinvestigate the pinned-library edge if this changes")
                self.assertNotEqual(json_bytes(left), json_bytes(right))
                self.assertEqual({("replace", "/extension")},
                                 expected_operations({"extension": left}, {"extension": right}))

    def test_same_tool_labeled_and_unlabeled_changes_survive(self):
        before = {"tools": [tool(annotations={"readOnlyHint": True}, extension="old")]}
        after = {"tools": [tool(annotations={"readOnlyHint": False}, extension="new")]}
        report = self.assert_pair(before, after)
        self.assertTrue(report["policy_findings"])
        self.assertEqual({"/tools/lookup/annotations/readOnlyHint", "/tools/lookup/extension"},
                         {c["path"] for c in report["changes"]})

    def test_object_keys_and_outer_tool_permutations_preserve_identity_and_hashes(self):
        rng = random.Random(101)
        before = {"tools": [tool(name, extension={"z": [{"b": True, "a": 1.0}], "a": None})
                            for name in NAMES]}
        after = copy.deepcopy(before)
        after["tools"][0]["extension"]["a"] = "changed"
        baseline = self.assert_pair(before, after)
        for _ in range(20):
            left, right = (permute_objects(value, rng) for value in (before, after))
            rng.shuffle(left["tools"])
            rng.shuffle(right["tools"])
            right["capturedAt"] = "excluded acquisition metadata"
            identity = self.assert_pair(before, left)
            self.assertEqual("unchanged", identity["status"])
            self.assertEqual(identity["before_sha256"], identity["after_sha256"])
            report = self.assert_pair(left, right)
            for field in ("before_sha256", "after_sha256", "changes"):
                self.assertEqual(json_bytes(baseline[field]), json_bytes(report[field]))
        reverse = self.assert_pair(after, before)
        self.assertEqual(baseline["before_sha256"], reverse["after_sha256"])
        self.assertEqual(baseline["after_sha256"], reverse["before_sha256"])

    def test_bounded_seeded_pairs(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for case in range(CASES_PER_SEED):
                with self.subTest(seed=seed, case=case):
                    before = random_descriptor(rng)
                    after = random_descriptor(rng) if case % 5 == 0 else copy.deepcopy(before)
                    if case % 5:
                        for item in after["tools"]:
                            keys = [key for key in item if key in KEYS]
                            key = rng.choice(keys)
                            if rng.random() < 0.2:
                                del item[key]
                            else:
                                item[key] = random_json(rng)
                    for descriptor in (before, after):
                        self.assertLessEqual(len(json_bytes(descriptor)), MAX_DESCRIPTOR_BYTES)
                    self.assert_pair(before, after)


if __name__ == "__main__":
    unittest.main()
