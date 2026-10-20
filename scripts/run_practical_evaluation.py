"""Capture pinned local MCP packages, then compare identical saved acquisitions.

Raw third-party descriptors and full findings stay in the ignored work directory.
The durable receipt contains only hashes, counts, field paths and rule identifiers.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tool_contract_drift.linter.tool_contract_drift import lint_fixture
from tool_contract_drift_cli import normalize_mcp_tool


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def tool_map(snapshot: dict) -> dict:
    tools = snapshot["tools"]
    result = {}
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
            raise ValueError("invalid-tool-name")
        if tool["name"] in result:
            raise ValueError("duplicate-tool-name")
        result[tool["name"]] = tool
    return result


def changed_paths(before: object, after: object, path: str = "") -> list[str]:
    if type(before) is not type(after):
        return [path or "/"]
    if isinstance(before, dict):
        paths = []
        for key in sorted(before.keys() | after.keys()):
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before or key not in after:
                paths.append(child)
            else:
                paths.extend(changed_paths(before[key], after[key], child))
        return paths
    # Arrays are atomic and order-sensitive; schema arrays are not assumed sets.
    return [] if encoded(before) == encoded(after) else [path or "/"]


def launch_environment(work: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8", "NO_COLOR": "1", "NODE_NO_WARNINGS": "1",
        "OTEL_SDK_DISABLED": "true", "DO_NOT_TRACK": "1",
        "DISABLE_THOUGHT_LOGGING": "true", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
        "MEMORY_FILE_PATH": str(work / "unused-memory.json"),
    }


async def drain(stream: asyncio.StreamReader) -> bytes:
    hasher = hashlib.sha256()
    total = 0
    while chunk := await stream.read(65536):
        total += len(chunk)
        if total > 20_000_000:
            raise ValueError("stderr-limit")
        hasher.update(chunk)
    return hasher.digest()


async def acquire(command: list[str], work: Path, protocol: dict, modern: bool) -> dict:
    process = await asyncio.create_subprocess_exec(
        *command, cwd=work, env=launch_environment(work),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, limit=8_000_000,
    )
    stderr_task = asyncio.create_task(drain(process.stderr))
    request_id = 0

    async def send(message: dict) -> None:
        process.stdin.write(encoded(message) + b"\n")
        await process.stdin.drain()

    async def request(method: str, params: dict) -> dict:
        nonlocal request_id
        request_id += 1
        if modern:
            params = {**params, "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "descriptor-review-evaluation", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }}
        await send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        total = 0
        while True:
            line = await process.stdout.readline()
            if not line:
                raise ValueError("server-eof")
            total += len(line)
            if total > 20_000_000:
                raise ValueError("response-limit")
            message = json.loads(line)
            if message.get("id") == request_id and "method" not in message:
                if "error" in message:
                    raise ValueError("rpc-error-" + str(message["error"].get("code")))
                return message["result"]
            if "id" in message and "method" in message:
                await send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Not supported"}})

    try:
        async with asyncio.timeout(protocol["timeout_seconds"]):
            if not modern:
                await request("initialize", {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "descriptor-review-evaluation", "version": "1"},
                })
                await send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            tools, seen, cursor = [], set(), None
            for _ in range(protocol["max_pages"]):
                result = await request("tools/list", {} if cursor is None else {"cursor": cursor})
                if not isinstance(result.get("tools"), list):
                    raise ValueError("invalid-tools-list")
                tools.extend(result["tools"])
                if len(tools) > 2500:
                    raise ValueError("tool-count-limit")
                cursor = result.get("nextCursor")
                if cursor is None:
                    snapshot = {"tools": tools}
                    tool_map(snapshot)
                    return snapshot
                if not isinstance(cursor, str) or cursor in seen:
                    raise ValueError("invalid-or-repeated-cursor")
                seen.add(cursor)
            raise ValueError("page-limit")
    finally:
        if process.returncode is None:
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except TimeoutError:
            process.kill()
            await process.wait()
        stderr_task.cancel()
        await asyncio.gather(stderr_task, return_exceptions=True)


async def capture_release(release: dict, work: Path, protocol: dict, semaphore: asyncio.Semaphore) -> dict:
    alias = release["alias"]
    local = work / "captures" / alias
    local.mkdir(parents=True, exist_ok=True)
    node = shutil.which("node")
    bin_record = release["bin"]
    entry = next(iter(bin_record.values())) if isinstance(bin_record, dict) else bin_record
    command = [node, str(work / "runtime/node_modules" / alias / entry)]
    if release["package"] == "@modelcontextprotocol/server-filesystem":
        empty_root = local / "empty-root"
        empty_root.mkdir(exist_ok=True)
        command.append(str(empty_root))
    attempts, snapshots = [], []
    async with semaphore:
        for repetition in range(protocol["repeat_count"]):
            for modern in (False, True):
                try:
                    snapshot = await acquire(command, local, protocol, modern)
                except (ValueError, TimeoutError, OSError, KeyError, TypeError) as error:
                    # Failure details can contain source text; keep them private.
                    (local / f"failure-{repetition}-{modern}.txt").write_text(repr(error))
                    attempts.append({"repeat": repetition, "mode": "stateless" if modern else "initialize", "status": type(error).__name__})
                    continue
                (local / f"{repetition}.json").write_bytes(encoded(snapshot) + b"\n")
                snapshots.append(snapshot)
                attempts.append({"repeat": repetition, "mode": "stateless" if modern else "initialize", "status": "captured"})
                break
    hashes = [digest(tool_map(snapshot)) for snapshot in snapshots]
    stable = len(hashes) == protocol["repeat_count"] and len(set(hashes)) == 1
    return {
        "alias": alias, "attempts": attempts, "status": "stable" if stable else "failed-or-unstable",
        "tool_count": len(snapshots[0]["tools"]) if snapshots else None,
        "tool_set_sha256": hashes,
    }


async def compare(before: dict, after: dict, work: Path, node: str) -> dict:
    left = work / "captures" / before["alias"] / "0.json"
    right = work / "captures" / after["alias"] / "0.json"
    process = await asyncio.create_subprocess_exec(
        node, str(work / "runtime/node_modules/independent-comparator/dist/cli.js"),
        "diff", str(left), str(right), "--format", "json",
        cwd=work, env=launch_environment(work),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise
    pair_id = before["alias"] + "--" + after["alias"]
    (work / "comparisons" / f"{pair_id}-mcpdiff.json").write_bytes(stdout)
    if process.returncode not in (0, 1):
        (work / "comparisons" / f"{pair_id}-stderr.txt").write_bytes(stderr)
        raise ValueError("comparator-failed")
    return json.loads(stdout)


async def run(args: argparse.Namespace) -> dict:
    work = args.work.resolve()
    if (work / "captures").exists() or (work / "comparisons").exists():
        raise ValueError("Acquisition work already exists; choose a fresh --work directory.")
    sample_path = ROOT / "evaluation/practical_sample.json"
    sample = json.loads(sample_path.read_text())
    protocol_path = ROOT / "evaluation/practical_protocol.json"
    protocol = json.loads(protocol_path.read_text())
    if hashlib.sha256(protocol_path.read_bytes()).hexdigest() != sample["protocol_sha256"]:
        raise ValueError("Protocol changed after sample freeze")
    if not shutil.which("node"):
        raise ValueError("node-not-installed")
    (work / "comparisons").mkdir(parents=True, exist_ok=True)
    # Stop comparator config discovery here, before any user-level directory.
    (work / ".mcpdiff.json").write_text("{}\n")
    semaphore = asyncio.Semaphore(4)
    captures = await asyncio.gather(*[
        capture_release(release, work, protocol["capture"], semaphore)
        for release in sample["releases"]
    ])
    by_alias = {capture["alias"]: capture for capture in captures}
    pairs = []
    for before, after in zip(sample["releases"], sample["releases"][1:]):
        if before["package"] != after["package"]:
            continue
        row = {"package": before["package"], "before": before["version"], "after": after["version"]}
        if any(by_alias[release["alias"]]["status"] != "stable" for release in (before, after)):
            pairs.append({**row, "status": "capture-failed-or-unstable"})
            continue
        raw = [json.loads((work / "captures" / release["alias"] / "0.json").read_text()) for release in (before, after)]
        maps = [tool_map(snapshot) for snapshot in raw]
        paths = changed_paths(*maps)
        fixture = {"id": before["alias"] + "--" + after["alias"], **{
            phase: {"tools": [normalize_mcp_tool(tool) for tool in snapshot["tools"]]}
            for phase, snapshot in zip(("before", "after"), raw)
        }}
        findings = lint_fixture(fixture)
        (work / "comparisons" / f"{fixture['id']}-lint.json").write_text(json.dumps([asdict(finding) for finding in findings], indent=2))
        comparator = await compare(before, after, work, shutil.which("node"))
        changes = comparator["changes"]
        pairs.append({**row, "status": "compared", "structural_paths": paths,
            "baseline_finding_count": len(findings),
            "baseline_rules": dict(sorted(Counter(finding.risk for finding in findings).items())),
            "comparator_changes": [{key: change[key] for key in ("path", "ruleId", "breaking", "drift") if key in change} for change in changes],
            "comparator_output_sha256": hashlib.sha256(encoded(comparator)).hexdigest(),
        })
    return {
        "schema_version": "practical-review-results-v1", "baseline_commit": sample["baseline_commit"],
        "sample_sha256": hashlib.sha256(sample_path.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "linter_sha256": hashlib.sha256((ROOT / "tool_contract_drift/linter/tool_contract_drift.py").read_bytes()).hexdigest(),
        "runtime": {"python": platform.python_version(), "node": subprocess.check_output(["node", "--version"], text=True).strip(), "pnpm": subprocess.check_output(["pnpm", "--version"], text=True).strip()},
        "lock_sha256": hashlib.sha256((work / "runtime/pnpm-lock.yaml").read_bytes()).hexdigest(),
        "captures": captures, "transitions": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, default=ROOT / "artifacts/practical-evaluation")
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation/practical_results.json")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Results already exist; preserve the original receipt.")
    result = asyncio.run(run(args))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
