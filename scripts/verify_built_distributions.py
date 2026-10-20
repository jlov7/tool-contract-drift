from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cff",
    ".in",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".sarif",
    ".tex",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
TEXT_NAMES = {"LICENSE", "METADATA", "PKG-INFO", "RECORD", "WHEEL"}
DENIED_PREFIXES = (
    ".codex/",
    "coordinator/",
    "fixtures/",
    "provenance/",
    "reports/reviewer_",
    "reports/sealed_",
    "tests/",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify exact wheel and source-distribution byte boundaries.")
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()

    metadata = load_json(ROOT / "release/public_release_metadata.json")
    contract = load_json(ROOT / "tool_contract_drift/data/release_contract.json")
    manifest_path = ROOT / "PUBLIC_EXPORT_MANIFEST.json"
    if not manifest_path.is_file():
        print(
            "Built distribution verification failed:\n"
            "- PUBLIC_EXPORT_MANIFEST.json is missing; build publishable artifacts only from a verified public extraction."
        )
        return 1
    manifest = load_json(manifest_path)
    expected = {
        "wheel": args.dist / metadata["artifact_names"]["wheel"],
        "sdist": args.dist / metadata["artifact_names"]["sdist"],
    }
    issues: list[str] = []
    issues.extend(verify_source_manifest_binding(manifest, ROOT))
    hashes: dict[str, str] = {}
    for kind, path in expected.items():
        if not path.is_file():
            issues.append(f"{kind} is missing: {path.name}")
            continue
        data = path.read_bytes()
        hashes[kind] = hashlib.sha256(data).hexdigest()
        try:
            members = read_wheel(data) if kind == "wheel" else read_sdist(data)
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            issues.append(f"{kind} could not be read: {exc}")
            continue
        issues.extend(verify_members(kind, members, contract, source_root=ROOT))

    if issues:
        print("Built distribution verification failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1
    print(
        "Built distributions verified: "
        f"wheel={hashes['wheel']}; sdist={hashes['sdist']}; "
        f"corpus={contract['corpora']['public_reproduction']['id']}; "
        f"public_file_set={manifest['file_set_sha256']}."
    )
    return 0


def read_wheel(data: bytes) -> dict[PurePosixPath, bytes]:
    members: dict[PurePosixPath, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            path = checked_path(info.filename)
            if path in members:
                raise ValueError(f"duplicate wheel member: {path}")
            members[path] = archive.read(info)
    return members


def read_sdist(data: bytes) -> dict[PurePosixPath, bytes]:
    raw: dict[PurePosixPath, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        roots: set[str] = set()
        for member in archive.getmembers():
            path = checked_path(member.name)
            roots.add(path.parts[0])
            if member.isdir():
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise ValueError(f"unsafe sdist member type: {path}")
            if path in raw:
                raise ValueError(f"duplicate sdist member: {path}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"unreadable sdist member: {path}")
            raw[path] = stream.read()
    if len(roots) != 1:
        raise ValueError(f"sdist has multiple roots: {sorted(roots)}")
    root = next(iter(roots))
    return {PurePosixPath(*path.parts[1:]): value for path, value in raw.items() if path.parts[0] == root}


def checked_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe archive path: {value}")
    return path


def verify_members(
    kind: str,
    members: dict[PurePosixPath, bytes],
    contract: dict[str, Any],
    *,
    source_root: Path = ROOT,
) -> list[str]:
    issues: list[str] = []
    names = {path.as_posix() for path in members}
    expected_sources = expected_source_members(kind, source_root)
    generated_required, generated_allowed = generated_member_contract(kind, members, source_root)
    expected_names = set(expected_sources) | generated_allowed
    missing = (set(expected_sources) | generated_required) - set(members)
    extra = set(members) - expected_names
    if missing:
        issues.append(f"{kind} omits exact distribution members: {sorted(str(path) for path in missing)}")
    if extra:
        issues.append(f"{kind} includes uncontracted members: {sorted(str(path) for path in extra)}")
    for member_path, source_path in sorted(
        expected_sources.items(), key=lambda item: item[0].as_posix()
    ):
        if member_path in members and members[member_path] != source_path.read_bytes():
            issues.append(f"{kind} source-controlled bytes differ: {member_path}")
    for name in sorted(names):
        path = PurePosixPath(name)
        if any(name == prefix.rstrip("/") or name.startswith(prefix) for prefix in DENIED_PREFIXES):
            issues.append(f"{kind} includes denied path: {name}")
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            issues.append(f"{kind} includes cache bytecode: {name}")

    public_identity = contract["corpora"]["public_reproduction"]
    expected_fixture_names = set(public_identity["fixture_files"])
    observed_fixture_names = {
        path.name
        for path in members
        if path.parent == PurePosixPath("tool_contract_drift/fixtures") and path.suffix == ".json"
    }
    if observed_fixture_names != expected_fixture_names:
        issues.append(
            f"{kind} fixture member set differs: "
            f"missing={sorted(expected_fixture_names - observed_fixture_names)}, "
            f"extra={sorted(observed_fixture_names - expected_fixture_names)}"
        )
    for name in sorted(expected_fixture_names):
        member_path = PurePosixPath("tool_contract_drift/fixtures") / name
        source = source_root / member_path
        if member_path not in members:
            continue
        if members[member_path] != source.read_bytes():
            issues.append(f"{kind} fixture bytes differ: {member_path}")

    contract_path = PurePosixPath("tool_contract_drift/data/release_contract.json")
    if members.get(contract_path) != (source_root / contract_path).read_bytes():
        issues.append(f"{kind} release contract bytes differ")
    source_inventory_path = PurePosixPath("tool_contract_drift/data/source_metadata_inventory.json")
    source_inventory_bytes = members.get(source_inventory_path)
    if source_inventory_bytes is None:
        issues.append(f"{kind} omits source metadata inventory")
    else:
        try:
            source_inventory = json.loads(source_inventory_bytes)
        except json.JSONDecodeError as exc:
            issues.append(f"{kind} source metadata inventory is invalid JSON: {exc}")
        else:
            if source_inventory.get("status") != "metadata_only_not_public_cases_not_permission":
                issues.append(f"{kind} source metadata inventory loses its non-permission boundary")
            forbidden_inventory_fields = {"after", "before", "descriptor", "source_excerpt", "tools"}
            for index, record in enumerate(source_inventory.get("records", [])):
                leaked_fields = sorted(forbidden_inventory_fields & set(record))
                if leaked_fields:
                    issues.append(
                        f"{kind} source metadata inventory record {index} includes descriptor-byte fields: {leaked_fields}"
                    )
    notice_paths = [path for path in members if path.name == "THIRD_PARTY_NOTICES.md"]
    if not notice_paths:
        issues.append(f"{kind} omits THIRD_PARTY_NOTICES.md")
    for notice_path in notice_paths:
        if members[notice_path] != (source_root / "THIRD_PARTY_NOTICES.md").read_bytes():
            issues.append(f"{kind} notice bytes differ: {notice_path}")

    blocked_ids = set(contract["redistribution"]["blocked_fixture_ids"])
    forbidden_patterns = (
        re.compile("public-" + "redistributable-" + "53", re.IGNORECASE),
        re.compile("public-" + "blocker-excluded-" + "53", re.IGNORECASE),
        re.compile("redistribution" + "[- ]" + "cleared", re.IGNORECASE),
        re.compile("ar" + "-?" + "031", re.IGNORECASE),
        re.compile("(?:private|unreleased)[ -]+(?:pre-review[ -]+)?manuscript", re.IGNORECASE),
        re.compile("study" + "-synth-", re.IGNORECASE),
        re.compile("review" + "-pack", re.IGNORECASE),
        re.compile("score" + "-review", re.IGNORECASE),
    )
    for path, data in members.items():
        if path.suffix not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            issues.append(f"{kind} has non-UTF-8 text member: {path}")
            continue
        for pattern in forbidden_patterns:
            if pattern.search(path.as_posix()) or pattern.search(text):
                issues.append(f"{kind} includes forbidden marker {pattern.pattern!r}: {path}")
        if path not in {contract_path, source_inventory_path}:
            leaked = sorted(fixture_id for fixture_id in blocked_ids if fixture_id in text)
            if leaked:
                issues.append(f"{kind} includes blocked fixture IDs outside the release contract: {path}: {leaked}")
    if kind == "wheel":
        issues.extend(verify_wheel_record(members))
    return issues


def expected_source_members(kind: str, source_root: Path) -> dict[PurePosixPath, Path]:
    package_paths: set[Path] = set()
    package_root = source_root / "tool_contract_drift"
    package_paths.update(package_root.rglob("*.py"))
    for relative_pattern in (
        "data/*.json",
        "fixtures/*.json",
        "fixtures/schema/*.json",
        "policy/*.json",
        "policy/schema/*.json",
    ):
        package_paths.update(package_root.glob(relative_pattern))
    package_paths.add(source_root / "tool_contract_drift_cli.py")

    if kind == "sdist":
        for name in (
            "CHANGELOG.md",
            "CITATION.cff",
            "CONTRIBUTING.md",
            "LICENSE",
            "MANIFEST.in",
            "README.md",
            "SECURITY.md",
            "THIRD_PARTY_NOTICES.md",
            "action.yml",
            "pyproject.toml",
            "uv.lock",
        ):
            package_paths.add(source_root / name)
        package_paths.update((source_root / "examples").glob("*.json"))
    missing = sorted(path for path in package_paths if not path.is_file())
    if missing:
        raise ValueError(f"distribution source contract has missing files: {missing}")
    return {
        PurePosixPath(path.relative_to(source_root).as_posix()): path
        for path in package_paths
    }


def verify_source_manifest_binding(
    manifest: dict[str, Any],
    source_root: Path,
) -> list[str]:
    issues: list[str] = []
    if manifest.get("schema_version") != "tool-contract-drift-public-export-manifest-v1":
        return ["public export manifest has an unsupported schema"]
    records = {
        PurePosixPath(record["path"]): record
        for record in manifest.get("files", [])
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    sources = expected_source_members("wheel", source_root) | expected_source_members("sdist", source_root)
    for path, source in sources.items():
        record = records.get(path)
        if record is None:
            issues.append(f"distribution source is absent from public manifest: {path}")
            continue
        data = source.read_bytes()
        if record.get("sha256") != hashlib.sha256(data).hexdigest():
            issues.append(f"distribution source hash differs from public manifest: {path}")
        if record.get("size_bytes") != len(data):
            issues.append(f"distribution source size differs from public manifest: {path}")
    return issues


def generated_member_contract(
    kind: str,
    members: dict[PurePosixPath, bytes],
    source_root: Path,
) -> tuple[set[PurePosixPath], set[PurePosixPath]]:
    if kind == "sdist":
        egg_info = PurePosixPath("tool_contract_drift.egg-info")
        generated = {
            PurePosixPath("PKG-INFO"),
            PurePosixPath("setup.cfg"),
            egg_info / "PKG-INFO",
            egg_info / "SOURCES.txt",
            egg_info / "dependency_links.txt",
            egg_info / "entry_points.txt",
            egg_info / "top_level.txt",
        }
        return generated, generated

    roots = {
        path.parts[0]
        for path in members
        if path.parts and path.parts[0].endswith(".dist-info")
    }
    metadata = load_json(source_root / "release/public_release_metadata.json")
    match = re.fullmatch(r"(.+)-py3-none-any\.whl", metadata["artifact_names"]["wheel"])
    if match is None:
        return {PurePosixPath("<canonical-wheel-filename-required>")}, set()
    expected_root = match.group(1) + ".dist-info"
    if roots != {expected_root}:
        return {PurePosixPath(expected_root) / "<exact-dist-info-directory-required>"}, set()
    dist_info = PurePosixPath(expected_root)
    required = {
        dist_info / "METADATA",
        dist_info / "WHEEL",
        dist_info / "entry_points.txt",
        dist_info / "top_level.txt",
        dist_info / "RECORD",
        dist_info / "licenses/LICENSE",
        dist_info / "licenses/THIRD_PARTY_NOTICES.md",
    }
    return required, required


def verify_wheel_record(members: dict[PurePosixPath, bytes]) -> list[str]:
    issues: list[str] = []
    record_paths = [path for path in members if path.name == "RECORD" and path.parent.name.endswith(".dist-info")]
    if len(record_paths) != 1:
        return [f"wheel must contain exactly one RECORD, observed {len(record_paths)}"]
    record_path = record_paths[0]
    try:
        rows = list(csv.reader(io.StringIO(members[record_path].decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        return [f"wheel RECORD could not be parsed: {exc}"]
    observed: set[PurePosixPath] = set()
    for row in rows:
        if len(row) != 3:
            issues.append("wheel RECORD has a malformed row")
            continue
        try:
            path = checked_path(row[0])
        except ValueError as exc:
            issues.append(f"wheel RECORD contains {exc}")
            continue
        if path in observed:
            issues.append(f"wheel RECORD duplicates {path}")
            continue
        observed.add(path)
        if path == record_path:
            if row[1] or row[2]:
                issues.append("wheel RECORD self-row must have empty hash and size")
            continue
        data = members.get(path)
        if data is None:
            issues.append(f"wheel RECORD names a missing member: {path}")
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if row[1] != f"sha256={digest}" or row[2] != str(len(data)):
            issues.append(f"wheel RECORD hash or size differs: {path}")
    if observed != set(members):
        issues.append(
            "wheel RECORD member set differs: "
            f"missing={sorted(str(path) for path in set(members) - observed)}, "
            f"extra={sorted(str(path) for path in observed - set(members))}"
        )
    return issues


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


if __name__ == "__main__":
    raise SystemExit(main())
