from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "evaluation/practical_protocol.json"


def registry_metadata(registry: str, package: str) -> tuple[dict, str]:
    url = f"{registry}/{urllib.parse.quote(package, safe='')}"
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(20_000_001)
    if len(raw) > 20_000_000:
        raise ValueError(f"Registry metadata exceeds size limit: {package}")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def select_versions(metadata: dict, cutoff: str, count: int) -> list[str]:
    cutoff_time = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
    published = [
        (datetime.fromisoformat(timestamp.replace("Z", "+00:00")), version)
        for version, timestamp in metadata["time"].items()
        if re.fullmatch(r"\d+\.\d+\.\d+", version)
        and datetime.fromisoformat(timestamp.replace("Z", "+00:00")) < cutoff_time
        and version in metadata["versions"]
    ]
    selected = [version for _, version in sorted(published)[-count:]]
    if len(selected) != count:
        raise ValueError(f"Not enough stable releases for {metadata['name']}")
    return selected


def release_record(metadata: dict, version: str, alias: str) -> dict:
    release = metadata["versions"][version]
    distribution = release["dist"]
    if not distribution.get("integrity") or not distribution.get("tarball"):
        raise ValueError(f"Missing integrity or tarball for {metadata['name']}@{version}")
    return {
        "alias": alias,
        "package": metadata["name"],
        "version": version,
        "published_at": metadata["time"][version],
        "tarball": distribution["tarball"],
        "integrity": distribution["integrity"],
        "license_metadata": release.get("license"),
        "repository": release.get("repository"),
        "bin": release.get("bin"),
    }


def restore_runtime(manifest: dict, runtime: Path) -> None:
    dependencies = {
        record["alias"]: f"npm:{record['package']}@{record['version']}"
        for record in [*manifest["releases"], manifest["comparator"]]
    }
    runtime.mkdir(parents=True, exist_ok=True)
    (runtime / "package.json").write_text(json.dumps({
        "name": "tool-contract-drift-practical-evaluation", "private": True,
        "version": "0.0.0", "dependencies": dependencies,
    }, indent=2, sort_keys=True) + "\n")
    lock = ROOT / "evaluation/pnpm-lock.yaml"
    if lock.is_file():
        shutil.copyfile(lock, runtime / "pnpm-lock.yaml")


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze a date-selected MCP release comparison.")
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=ROOT / "evaluation/practical_sample.json")
    parser.add_argument("--restore-runtime", action="store_true", help="Use the frozen sample and lock; do not query the registry or change selection.")
    args = parser.parse_args()
    if args.restore_runtime:
        restore_runtime(json.loads(args.manifest.read_text()), args.runtime_dir)
        return 0
    if args.manifest.exists():
        raise SystemExit("Sample already exists; do not silently replace a frozen sample.")
    protocol = json.loads(PROTOCOL.read_text())
    package_records = []
    registry_hashes = {}
    for index, package in enumerate(protocol["packages"]):
        metadata, metadata_hash = registry_metadata(protocol["registry"], package)
        registry_hashes[package] = metadata_hash
        versions = select_versions(metadata, protocol["publication_cutoff"], protocol["versions_per_package"])
        for position, version in enumerate(versions):
            alias = f"server-{index}-{position}"
            package_records.append(release_record(metadata, version, alias))
    comparator = protocol["independent_comparator"]
    metadata, metadata_hash = registry_metadata(protocol["registry"], comparator["package"])
    registry_hashes[comparator["package"]] = metadata_hash
    comparator_record = release_record(metadata, comparator["version"], "independent-comparator")
    manifest = {
        "schema_version": protocol["schema_version"],
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "baseline_commit": protocol["baseline_commit"],
        "publication_cutoff": protocol["publication_cutoff"],
        "registry_response_sha256": registry_hashes,
        "releases": package_records,
        "comparator": comparator_record,
    }
    args.runtime_dir.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    restore_runtime(manifest, args.runtime_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
