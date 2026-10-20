from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


MAX_ARCHIVE_BYTES = 50_000_000
MAX_MEMBER_BYTES = 20_000_000
MAX_MEMBER_COUNT = 512
MAX_TOTAL_FILE_BYTES = 100_000_000
MANIFEST_NAME = PurePosixPath("PUBLIC_EXPORT_MANIFEST.json")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a deterministic public source archive before optional extraction."
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("--build-record", type=Path)
    parser.add_argument("--checksum", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--extract-to", type=Path)
    args = parser.parse_args()

    archive_bytes = args.archive.read_bytes()
    build_record = load_json(args.build_record) if args.build_record else None
    checksum = args.checksum.read_text() if args.checksum else None
    manifest_sidecar = args.manifest.read_bytes() if args.manifest else None
    result, issues = inspect_archive(
        archive_bytes,
        archive_name=args.archive.name,
        build_record=build_record,
        checksum=checksum,
        manifest_sidecar=manifest_sidecar,
    )
    if issues:
        print("Public archive verification failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1
    if args.extract_to:
        extract_verified(result, args.extract_to)
        print(f"Safely extracted verified archive to {args.extract_to.resolve()}")
    print(
        "Public archive verified before extraction: "
        f"sha256={hashlib.sha256(archive_bytes).hexdigest()}; "
        f"files={len(result['files'])}; root={result['root']}."
    )
    return 0


def inspect_archive(
    archive_bytes: bytes,
    *,
    archive_name: str,
    build_record: dict[str, Any] | None = None,
    checksum: str | None = None,
    manifest_sidecar: bytes | None = None,
) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    result: dict[str, Any] = {"directories": set(), "files": {}, "members": {}}
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        return result, [f"compressed archive exceeds {MAX_ARCHIVE_BYTES} bytes"]

    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    issues.extend(verify_sidecars(archive_name, archive_bytes, archive_sha256, build_record, checksum))

    roots: set[str] = set()
    seen: set[PurePosixPath] = set()
    total_file_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r|gz") as archive:
            for index, member in enumerate(archive, start=1):
                if index > MAX_MEMBER_COUNT:
                    issues.append(f"archive exceeds {MAX_MEMBER_COUNT} members")
                    break
                try:
                    path = checked_archive_path(member.name)
                except ValueError as exc:
                    issues.append(str(exc))
                    break
                if path in seen:
                    issues.append(f"duplicate archive member: {path}")
                    break
                seen.add(path)
                roots.add(path.parts[0])
                if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
                    issues.append(f"non-normalized ownership: {path}")
                result["members"][path] = member
                if member.isdir():
                    result["directories"].add(path)
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    issues.append(f"unsafe archive member type: {path}")
                    break
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    issues.append(f"unsafe archive member size: {path} ({member.size})")
                    break
                total_file_bytes += member.size
                if total_file_bytes > MAX_TOTAL_FILE_BYTES:
                    issues.append(f"archive expands beyond {MAX_TOTAL_FILE_BYTES} file bytes")
                    break
                stream = archive.extractfile(member)
                if stream is None:
                    issues.append(f"unreadable archive member: {path}")
                    break
                data = stream.read(MAX_MEMBER_BYTES + 1)
                if len(data) != member.size:
                    issues.append(f"archive member size/read mismatch: {path}")
                    break
                result["files"][path] = data
    except (OSError, tarfile.TarError, EOFError) as exc:
        issues.append(f"archive could not be read safely: {exc}")

    if len(roots) != 1:
        issues.append(f"archive must have exactly one root: {sorted(roots)}")
        return result, issues
    root = next(iter(roots))
    result["root"] = root
    manifest_path = PurePosixPath(root) / MANIFEST_NAME
    manifest_bytes = result["files"].get(manifest_path)
    if manifest_bytes is None:
        issues.append("archive omits PUBLIC_EXPORT_MANIFEST.json")
        return result, issues
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        issues.append(f"public export manifest is invalid JSON: {exc}")
        return result, issues
    result["manifest"] = manifest
    issues.extend(
        verify_manifested_members(
            root,
            result["files"],
            result["directories"],
            result["members"],
            manifest,
        )
    )
    if build_record is not None:
        expected_manifest_hash = build_record.get("internal_manifest_sha256")
        if expected_manifest_hash != hashlib.sha256(manifest_bytes).hexdigest():
            issues.append("build record does not bind the internal manifest bytes")
    if manifest_sidecar is not None and manifest_sidecar != manifest_bytes:
        issues.append("manifest sidecar differs from the internal manifest bytes")
    return result, issues


def verify_sidecars(
    archive_name: str,
    archive_bytes: bytes,
    archive_sha256: str,
    build_record: dict[str, Any] | None,
    checksum: str | None,
) -> list[str]:
    issues: list[str] = []
    if build_record is not None:
        if build_record.get("archive_file") != archive_name:
            issues.append("build record archive filename differs")
        if build_record.get("archive_sha256") != archive_sha256:
            issues.append("build record archive hash differs")
        if build_record.get("archive_size_bytes") != len(archive_bytes):
            issues.append("build record archive size differs")
        if build_record.get("publication_claimed") is not False:
            issues.append("build record must not claim publication")
        if build_record.get("external_actions_performed") is not False:
            issues.append("build record must not claim external actions")
    if checksum is not None:
        expected = f"{archive_sha256}  {archive_name}\n"
        if checksum != expected:
            issues.append("checksum sidecar differs from the exact archive hash and filename")
    return issues


def verify_manifested_members(
    root: str,
    files: dict[PurePosixPath, bytes],
    directories: set[PurePosixPath],
    members: dict[PurePosixPath, tarfile.TarInfo],
    manifest: dict[str, Any],
) -> list[str]:
    issues: list[str] = []
    if manifest.get("schema_version") != "tool-contract-drift-public-export-manifest-v1":
        issues.append("unsupported public export manifest schema")
    if manifest.get("archive_root") != root:
        issues.append("manifest archive root differs")
    source_date_epoch = manifest.get("toolchain", {}).get("source_date_epoch")
    if not isinstance(source_date_epoch, int) or source_date_epoch < 0:
        issues.append("manifest source-date epoch is invalid")
        source_date_epoch = None

    records = manifest.get("files")
    if not isinstance(records, list):
        return issues + ["manifest file records are missing"]
    expected: dict[PurePosixPath, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"mode", "path", "sha256", "size_bytes"}:
            issues.append("manifest contains a malformed file record")
            continue
        try:
            relative = checked_relative_path(record["path"])
        except (TypeError, ValueError) as exc:
            issues.append(f"manifest contains unsafe path: {exc}")
            continue
        if relative == MANIFEST_NAME or relative in expected:
            issues.append(f"manifest contains duplicate or self-referential path: {relative}")
            continue
        expected[relative] = record

    observed_relative = {
        PurePosixPath(*path.parts[1:])
        for path in files
        if path != PurePosixPath(root) / MANIFEST_NAME
    }
    if set(expected) != observed_relative:
        issues.append(
            "archive file set differs from manifest: "
            f"missing={sorted(str(path) for path in set(expected) - observed_relative)}, "
            f"extra={sorted(str(path) for path in observed_relative - set(expected))}"
        )
    for relative, record in expected.items():
        path = PurePosixPath(root) / relative
        data = files.get(path)
        if data is None:
            continue
        if record["size_bytes"] != len(data):
            issues.append(f"manifested size differs: {relative}")
        if record["sha256"] != hashlib.sha256(data).hexdigest():
            issues.append(f"manifested hash differs: {relative}")
        member = members[path]
        expected_mode = int(record["mode"], 8) if isinstance(record["mode"], str) else -1
        if member.mode != expected_mode:
            issues.append(f"manifested mode differs: {relative}")

    expected_dirs = {PurePosixPath(root)}
    for path in files:
        expected_dirs.update(parent for parent in path.parents if parent != PurePosixPath("."))
    if directories != expected_dirs:
        issues.append(
            "archive directory set differs: "
            f"missing={sorted(str(path) for path in expected_dirs - directories)}, "
            f"extra={sorted(str(path) for path in directories - expected_dirs)}"
        )
    for path, member in members.items():
        if source_date_epoch is not None and member.mtime != source_date_epoch:
            issues.append(f"non-normalized mtime: {path}")
        if member.isdir() and member.mode != 0o755:
            issues.append(f"unexpected directory mode: {path}")

    ordered_records = sorted(expected.values(), key=lambda item: item["path"])
    if records != ordered_records:
        issues.append("manifest file records are not in canonical path order")
    if manifest.get("file_set_sha256") != file_set_sha256(ordered_records):
        issues.append("manifest file-set hash differs")
    return issues


def extract_verified(result: dict[str, Any], destination: Path) -> None:
    destination = destination.resolve()
    root = destination / result["root"]
    if root.exists():
        raise SystemExit(f"Refusing to overwrite extraction root: {root}")
    root.mkdir(parents=True)
    for path in sorted(result["directories"], key=lambda item: len(item.parts)):
        relative = PurePosixPath(*path.parts[1:])
        target = root.joinpath(*relative.parts)
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(0o755)
    for path, data in sorted(result["files"].items(), key=lambda item: item[0].as_posix()):
        relative = PurePosixPath(*path.parts[1:])
        target = root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(target, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        target.chmod(result["members"][path].mode)


def checked_archive_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError(f"unsafe archive path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts or not path.parts:
        raise ValueError(f"unsafe archive path: {value!r}")
    return path


def checked_relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str):
        raise TypeError("path is not a string")
    return checked_archive_path(value)


def file_set_sha256(records: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record in records:
        digest.update(record["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(record["sha256"].encode("ascii"))
        digest.update(b"\0")
        digest.update(str(record["size_bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(record["mode"].encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
