from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

from scripts.prepare_practical_evaluation import select_versions
from scripts.run_practical_evaluation import acquire, changed_paths, launch_environment, run, tool_map


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


if __name__ == "__main__":
    unittest.main()
