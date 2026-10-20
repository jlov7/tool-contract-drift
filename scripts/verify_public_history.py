from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


FORBIDDEN_HISTORY_PATTERNS = (
    re.compile(b"public-" + b"redistributable-" + b"53", re.IGNORECASE),
    re.compile(b"public-" + b"blocker-excluded-" + b"53", re.IGNORECASE),
    re.compile(rb"redistribution[- ]cleared", re.IGNORECASE),
    re.compile(rb"ar-?031", re.IGNORECASE),
    re.compile(b"/Users/" + b"jasonlovell/", re.IGNORECASE),
    re.compile(rb"https://github\.com/jasonlovell/tool-contract-drift", re.IGNORECASE),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    re.compile(rb"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN)\s*=", re.IGNORECASE),
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit the recreated public repository tree and reachable Git history."
    )
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--initial-recreation", action="store_true")
    parser.add_argument("--require-no-remotes", action="store_true")
    args = parser.parse_args()

    issues = verify_history(
        args.root.resolve(),
        initial_recreation=args.initial_recreation,
        require_no_remotes=args.require_no_remotes,
    )
    if issues:
        print("Public Git history verification failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1
    print("Public Git history verified: tracked tree is manifest-exact and no hidden prior history is reachable.")
    return 0


def verify_history(
    root: Path,
    *,
    initial_recreation: bool,
    require_no_remotes: bool,
) -> list[str]:
    issues: list[str] = []
    manifest_path = root / "PUBLIC_EXPORT_MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [f"public export manifest could not be read: {exc}"]
    expected = {record["path"] for record in manifest.get("files", [])}
    expected.add("PUBLIC_EXPORT_MANIFEST.json")

    if run_git(root, "rev-parse", "--is-inside-work-tree", check=False).stdout.strip() != "true":
        return ["public root is not a Git worktree"]
    status = run_git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status.stdout:
        issues.append("public worktree is not clean")

    tracked_rows = run_git(root, "ls-files", "-s").stdout.splitlines()
    tracked: set[str] = set()
    for row in tracked_rows:
        try:
            metadata, path = row.split("\t", 1)
            mode, _object_id, stage = metadata.split()
        except ValueError:
            issues.append(f"malformed Git index row: {row}")
            continue
        tracked.add(path)
        if stage != "0":
            issues.append(f"non-zero Git index stage: {path}")
        expected_mode = "100755" if path.startswith("scripts/") and path.endswith(".py") else "100644"
        if mode != expected_mode:
            issues.append(f"tracked mode differs for {path}: {mode} != {expected_mode}")
    if tracked != expected:
        issues.append(
            "tracked file set differs from public manifest: "
            f"missing={sorted(expected - tracked)}, extra={sorted(tracked - expected)}"
        )

    commits = [line for line in run_git(root, "rev-list", "--all").stdout.splitlines() if line]
    if not commits:
        issues.append("public repository has no reachable commit")
    if initial_recreation and len(commits) != 1:
        issues.append(f"initial recreated public repository must have one commit, observed {len(commits)}")
    if initial_recreation and commits:
        head = run_git(root, "rev-list", "--parents", "-n", "1", "HEAD").stdout.split()
        if len(head) != 1:
            issues.append("initial recreated public commit is not a root commit")

    reachable_paths: set[str] = set()
    reachable_blobs: dict[str, bytes] = {}
    for row in run_git(root, "rev-list", "--objects", "--all").stdout.splitlines():
        if " " not in row:
            continue
        _object_id, path = row.split(" ", 1)
        if path:
            object_type = run_git(root, "cat-file", "-t", _object_id).stdout.strip()
            if object_type == "blob":
                reachable_paths.add(path)
                if _object_id not in reachable_blobs:
                    reachable_blobs[_object_id] = subprocess.run(
                        ["git", "cat-file", "blob", _object_id],
                        cwd=root,
                        check=True,
                        capture_output=True,
                    ).stdout
    if not reachable_paths <= expected:
        issues.append(
            "reachable history contains paths outside the exact public surface: "
            f"{sorted(reachable_paths - expected)}"
        )
    for object_id, data in reachable_blobs.items():
        matched = [pattern.pattern.decode("ascii") for pattern in FORBIDDEN_HISTORY_PATTERNS if pattern.search(data)]
        if matched:
            issues.append(f"reachable blob {object_id} contains forbidden private/stale markers: {matched}")

    unreachable = run_git(
        root,
        "fsck",
        "--no-reflogs",
        "--unreachable",
        "--no-progress",
        check=False,
    )
    residue = "\n".join(
        line for line in (unreachable.stdout + unreachable.stderr).splitlines()
        if "unreachable" in line or "dangling" in line
    )
    if residue:
        issues.append("Git object database contains unreachable or dangling residue")

    if require_no_remotes:
        remotes = run_git(root, "remote").stdout.splitlines()
        if remotes:
            issues.append(f"recreated local public repository unexpectedly has remotes: {sorted(remotes)}")
    return issues


def run_git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=check,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
