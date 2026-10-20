from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


sys.dont_write_bytecode = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an extracted Agent Tool Contract Drift public export.")
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    issues = verify_export(root)
    if issues:
        print("Public export verification failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1
    manifest = load_json(root / "PUBLIC_EXPORT_MANIFEST.json")
    public = manifest["corpora"]["public"]
    print(
        "Public export verified: "
        f"{len(manifest['files'])} files; file-set {manifest['file_set_sha256']}; "
        f"{public['id']}={public['fixture_count']} fixtures/{public['finding_count']} findings."
    )
    return 0


def verify_export(root: Path) -> list[str]:
    issues: list[str] = []
    manifest_path = root / "PUBLIC_EXPORT_MANIFEST.json"
    policy_path = root / "release/public_export_policy.json"
    if not manifest_path.is_file():
        return ["PUBLIC_EXPORT_MANIFEST.json is missing."]
    if not policy_path.is_file():
        return ["release/public_export_policy.json is missing."]
    try:
        manifest = load_json(manifest_path)
        policy = load_json(policy_path)
    except (json.JSONDecodeError, OSError) as exc:
        return [f"manifest or policy could not be read: {exc}"]
    if manifest.get("schema_version") != "tool-contract-drift-public-export-manifest-v1":
        issues.append("unsupported public export manifest schema")
        return issues
    if policy.get("schema_version") != "tool-contract-drift-public-export-policy-v1":
        issues.append("unsupported public export policy schema")
        return issues
    if manifest.get("archive_root") != policy.get("archive_root"):
        issues.append("manifest and policy archive roots differ")
    if manifest.get("policy_sha256") != sha256_path(policy_path):
        issues.append("public export policy hash does not match the manifest")
    metadata_path = root / "release/public_release_metadata.json"
    if not metadata_path.is_file():
        issues.append("public release metadata is missing")
    elif manifest.get("release_metadata_sha256") != sha256_path(metadata_path):
        issues.append("public release metadata hash does not match the manifest")
    else:
        issues.extend(verify_release_metadata(metadata_path, policy))
    manifest_contract = policy.get("manifest_contract", {})
    if manifest.get("boundary") != manifest_contract.get("boundary"):
        issues.append("manifest evidence boundary differs from the public policy")
    if manifest.get("excluded_surfaces") != manifest_contract.get("excluded_surfaces"):
        issues.append("manifest excluded-surface list differs from the public policy")
    if manifest.get("publication_claims") != manifest_contract.get("publication_claims"):
        issues.append("manifest contains unsupported publication or validation claims")
    if manifest.get("status") != manifest_contract.get("status"):
        issues.append("manifest status differs from the local public-export status")
    if manifest.get("version") != policy.get("version"):
        issues.append("manifest version differs from the public policy")
    issues.extend(verify_paper_build_identity(root, manifest))
    visibility = manifest.get("active_study_visibility", {})
    if visibility.get("local_export_visibility_passed") is not True:
        issues.append("manifest does not record a passing active-study visibility gate")
    if visibility.get("external_publication_authorized") is not False:
        issues.append("manifest improperly authorizes external publication")
    declared_counts = visibility.get("declared_current_counts", {})
    observed_counts = visibility.get("observed_current_counts", {})
    for key in ("sent_count", "returned_count", "response_count"):
        if declared_counts.get(key) != observed_counts.get(key):
            issues.append(f"manifest active-study declared and observed {key} differ")
    if visibility.get("sequence_status") != "local_candidate_before_external_validation_and_approval":
        issues.append("manifest active-study sequence status is unsupported")
    study_separation = manifest.get("study_case_separation", {})
    if study_separation.get("local_export_case_separation_passed") is not True:
        issues.append("manifest does not record a passing frozen-study case-separation gate")
    if study_separation.get("id_overlap_count") != 0:
        issues.append("manifest records public/study fixture-ID overlap")
    if study_separation.get("content_overlap_count") != 0:
        issues.append("manifest records public/study descriptor-content overlap")

    records = manifest.get("files", [])
    record_paths = [record.get("path") for record in records]
    if len(record_paths) != len(set(record_paths)):
        issues.append("manifest has duplicate file paths")
    expected_paths = set(record_paths) | {policy["manifest_path"]}
    actual_paths: set[str] = set()
    ignored_prefixes = policy.get("verification_ignored_prefixes", [])
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if any(
            relative == prefix.rstrip("/") or relative.startswith(prefix)
            for prefix in ignored_prefixes
        ):
            continue
        if path.is_symlink():
            issues.append(f"symlink is forbidden: {relative}")
        if path.is_file():
            actual_paths.add(relative)
    for path in sorted(expected_paths - actual_paths):
        issues.append(f"manifested file is missing: {path}")
    for path in sorted(actual_paths - expected_paths):
        issues.append(f"unmanifested file is present: {path}")

    verified_records: list[dict[str, Any]] = []
    for record in records:
        path_value = record.get("path")
        if not isinstance(path_value, str):
            issues.append("manifest record has no string path")
            continue
        path = PurePosixPath(path_value)
        if path.is_absolute() or ".." in path.parts:
            issues.append(f"unsafe manifest path: {path_value}")
            continue
        if is_denied_public_path(path, policy):
            issues.append(f"manifest includes a denied public path: {path_value}")
            continue
        full_path = root / path
        if not full_path.is_file() or full_path.is_symlink():
            continue
        data = full_path.read_bytes()
        if len(data) > policy.get("max_file_size_bytes", 0):
            issues.append(f"file exceeds public size limit: {path_value}")
        observed_mode = f"{stat.S_IMODE(full_path.stat().st_mode):04o}"
        if observed_mode != record.get("mode"):
            issues.append(f"mode mismatch: {path_value}")
        if len(data) != record.get("size_bytes"):
            issues.append(f"size mismatch: {path_value}")
        if hashlib.sha256(data).hexdigest() != record.get("sha256"):
            issues.append(f"SHA-256 mismatch: {path_value}")
        verified_records.append(record)
    if len(verified_records) == len(records) and file_set_sha256(verified_records) != manifest.get("file_set_sha256"):
        issues.append("manifest file-set SHA-256 is inconsistent")

    toolchain = manifest.get("toolchain", {})
    for key in (
        "archive_builder",
        "pdftotext",
        "python_implementation",
        "python_requires",
        "python_runtime",
        "uv",
        "zlib_runtime",
    ):
        if not isinstance(toolchain.get(key), str) or not toolchain[key].strip():
            issues.append(f"manifest toolchain field is missing: {key}")
    oasdiff = toolchain.get("oasdiff", {})
    if not isinstance(oasdiff, dict) or any(
        not isinstance(oasdiff.get(key), str) or not oasdiff[key].strip()
        for key in ("module", "version")
    ):
        issues.append("manifest oasdiff toolchain identity is missing")
    if toolchain.get("archive_builder") != "python-stdlib-tarfile-ustar+gzip":
        issues.append("manifest archive-builder identity is unsupported")
    if toolchain.get("python_implementation") != "CPython":
        issues.append("manifest Python implementation is unsupported")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+].+)?", toolchain.get("python_runtime", "")):
        issues.append("manifest Python runtime version is malformed")
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+].+)?", toolchain.get("zlib_runtime", "")):
        issues.append("manifest zlib runtime version is malformed")
    if not re.match(r"^uv \d+\.\d+\.\d+", toolchain.get("uv", "")):
        issues.append("manifest uv version is malformed")
    if "pdftotext" not in toolchain.get("pdftotext", "").lower():
        issues.append("manifest pdftotext version is malformed")
    if not isinstance(toolchain.get("source_date_epoch"), int) or toolchain["source_date_epoch"] < 0:
        issues.append("manifest source-date epoch is malformed")
    try:
        pyproject = tomllib.loads((root / "pyproject.toml").read_text())
        if toolchain.get("python_requires") != pyproject["project"]["requires-python"]:
            issues.append("manifest Python requirement differs from pyproject")
    except (KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        issues.append(f"pyproject toolchain identity could not be read: {exc}")

    issues.extend(
        scan_files(
            root,
            [*records, {"path": policy["manifest_path"]}],
            policy,
        )
    )
    issues.extend(verify_corpus(root, manifest, policy))
    source_identity = manifest.get("source_identity", {})
    if source_identity != {
        "file_set_sha256": manifest.get("file_set_sha256"),
        "state": "selected_public_file_set",
    }:
        issues.append("manifest public source identity differs from the selected file set")
    return issues


def scan_files(root: Path, records: list[dict[str, Any]], policy: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    scans = policy["content_scans"]
    text_suffixes = set(scans["text_suffixes"])
    secret_patterns = [re.compile(pattern) for pattern in scans["secret_patterns"]]
    forbidden_patterns = mandatory_forbidden_patterns() + [
        re.compile(pattern) for pattern in scans["forbidden_regex_patterns"]
    ]
    for record in records:
        path = PurePosixPath(record["path"])
        full_path = root / path
        for pattern in forbidden_patterns:
            if pattern.search(path.as_posix()):
                issues.append(f"forbidden path {pattern.pattern!r}: {path}")
        if not full_path.is_file():
            continue
        if full_path.suffix == ".pdf":
            text, pdf_issue = extract_pdf_text(full_path)
            if pdf_issue:
                issues.append(pdf_issue)
                continue
        elif full_path.suffix in text_suffixes or full_path.name == "LICENSE":
            try:
                text = full_path.read_text()
            except UnicodeDecodeError:
                issues.append(f"non-UTF-8 text file: {path}")
                continue
        else:
            continue
        for pattern in forbidden_patterns:
            if pattern.search(text):
                issues.append(f"forbidden content {pattern.pattern!r}: {path}")
        for pattern in secret_patterns:
            if pattern.search(text):
                issues.append(f"secret-like content {pattern.pattern!r}: {path}")
    return issues


def verify_paper_build_identity(root: Path, manifest: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    identity_path = root / "paper/build_identity.json"
    try:
        identity = load_json(identity_path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"paper build identity could not be read: {exc}"]
    expected_paths = {
        "paper_source": "paper/agent-tool-contract-drift.tex",
        "pdf": "paper/agent-tool-contract-drift.pdf",
    }
    if identity.get("schema_version") != "tool-contract-drift-paper-build-identity-v1":
        issues.append("unsupported paper build-identity schema")
    for field, path in expected_paths.items():
        if identity.get(field) != path:
            issues.append(f"paper build identity has an unexpected {field} path")
            continue
        full_path = root / path
        if not full_path.is_file():
            issues.append(f"paper build-identity target is missing: {path}")
            continue
        if identity.get(f"{field}_sha256") != sha256_path(full_path):
            issues.append(f"paper build-identity hash differs: {path}")
    expected_manifest = {
        "pdf_sha256": identity.get("pdf_sha256"),
        "source_pdf_hashes_verified": True,
        "source_sha256": identity.get("paper_source_sha256"),
    }
    if manifest.get("paper_build_identity") != expected_manifest:
        issues.append("manifest paper build identity differs from shipped source/PDF hashes")
    return issues


def verify_release_metadata(path: Path, policy: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    try:
        metadata = load_json(path)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"public release metadata could not be read: {exc}"]
    if metadata.get("schema_version") != "tool-contract-drift-public-release-metadata-v1":
        issues.append("unsupported public release metadata schema")
    if metadata.get("version") != policy.get("version"):
        issues.append("public release metadata version differs")
    version = policy.get("version")
    expected_artifact_names = {
        "build_record": f"tool-contract-drift-{version}-public-source.build.json",
        "checksum": f"tool-contract-drift-{version}-public-source.tar.gz.sha256",
        "manifest": f"tool-contract-drift-{version}-public-source.manifest.json",
        "public_source_archive": f"tool-contract-drift-{version}-public-source.tar.gz",
        "sdist": f"tool_contract_drift-{version}.tar.gz",
        "wheel": f"tool_contract_drift-{version}-py3-none-any.whl",
    }
    if metadata.get("artifact_names") != expected_artifact_names:
        issues.append("public artifact filenames differ from the versioned release contract")
    for name in metadata.get("artifact_names", {}).values():
        artifact_path = PurePosixPath(str(name))
        if artifact_path.is_absolute() or len(artifact_path.parts) != 1 or artifact_path.name != name:
            issues.append(f"public artifact filename is unsafe: {name!r}")
    issues.extend(verify_publication_state(metadata))
    issues.extend(verify_publication_claims(
        metadata, policy.get("manifest_contract", {}).get("publication_claims", {}),
    ))
    zenodo = metadata.get("zenodo", {})
    for key in ("version_doi", "concept_doi", "github_release_url", "paper_or_preprint_identifier"):
        if zenodo.get(key) is not None:
            issues.append(f"public release metadata claims unresolved Zenodo field: {key}")
    return issues


def verify_publication_state(metadata: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    as_of = metadata.get("publication_state_as_of")
    try:
        if not isinstance(as_of, str) or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", as_of) is None:
            raise ValueError
        date.fromisoformat(as_of)
    except ValueError:
        issues.append("release metadata requires a valid YYYY-MM-DD hosting snapshot date")
    state = metadata.get("publication_state", {})
    created = state.get("github_repository_created")
    public = state.get("github_repository_public")
    expected = {
        "archive_created": False,
        "doi_created_or_reserved": False,
        "github_repository_created": created,
        "github_repository_public": public,
        "github_release_created": False,
        "public_post_made": False,
    }
    if ((created is not True and created is not False)
            or (public is not True and public is not False)
            or set(state) != set(expected)
            or any(state[key] is not value for key, value in expected.items())):
        issues.append("release metadata must distinguish source hosting from other publication events")
    if public is True and created is not True:
        issues.append("public source hosting requires an existing repository")
    status = "public_source_repository" if public is True else (
        "private_staging_not_published" if created is True else "prepared_locally_not_published"
    )
    if metadata.get("status") != status:
        issues.append("release metadata status differs from its repository state")
    github = metadata.get("github", {})
    if created is True:
        owner = github.get("owner")
        slug = github.get("repository_slug")
        if (
            not isinstance(owner, str)
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner)
            or not isinstance(slug, str)
            or not re.fullmatch(r"[a-z0-9-]+", slug)
            or github.get("repository_url") != f"https://github.com/{owner}/{slug}"
            or github.get("visibility") != ("public" if public is True else "private")
        ):
            issues.append("source hosting requires a matching owner, repository URL and visibility")
    elif any(github.get(key) is not None for key in ("owner", "repository_url", "visibility")):
        issues.append("local-only metadata must not claim an existing repository")
    return issues


def verify_publication_claims(metadata: dict[str, Any], claims: dict[str, Any]) -> list[str]:
    expected = {
        "archive_or_doi_exists": False,
        "external_validation": False,
        "public_github_repository_or_release_exists": metadata.get("publication_state", {}).get("github_repository_public") is True,
        "live_sarif_upload_verified": False,
        "protocol_or_vendor_endorsement": False,
    }
    if set(claims) != set(expected) or any(claims[key] is not value for key, value in expected.items()):
        return ["publication claims must match the hosting snapshot and deny unobserved releases or validation"]
    return []


def is_denied_public_path(path: PurePosixPath, policy: dict[str, Any]) -> bool:
    value = path.as_posix()
    return (
        any(
            value == prefix.rstrip("/") or value.startswith(prefix)
            for prefix in policy.get("deny_path_prefixes", [])
        )
        or any(part in policy.get("deny_path_components", []) for part in path.parts)
        or path.name in policy.get("deny_path_names", [])
        or path.suffix in policy.get("deny_path_suffixes", [])
    )


def mandatory_forbidden_patterns() -> list[re.Pattern[str]]:
    return [
        re.compile("public-" + "redistributable-" + "53"),
        re.compile("public-" + "blocker-excluded-" + "53"),
        re.compile("(?i)redistribution" + "[- ]" + "cleared"),
        re.compile("(?i)" + "ar" + "-?" + "031"),
        re.compile("(?i)(?:private|unreleased)[ -]+(?:pre-review[ -]+)?manuscript"),
    ]


def extract_pdf_text(path: Path) -> tuple[str, str | None]:
    if shutil.which("pdftotext") is None:
        return "", "pdftotext is required to audit reader-visible PDF text"
    completed = subprocess.run(
        ["pdftotext", str(path), "-"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return "", f"pdftotext failed for {path.name}: {completed.stderr.strip()}"
    return completed.stdout, None


def verify_corpus(root: Path, manifest: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    try:
        contract = load_json(root / "tool_contract_drift/data/release_contract.json")
        package_lock = load_json(root / "tool_contract_drift/data/public_fixtures.lock.json")
        source_inventory = load_json(root / "tool_contract_drift/data/source_metadata_inventory.json")
        package_allowlist = load_json(root / "tool_contract_drift/policy/hash_allowlist_quiet_changes.json")
        public_identity = contract["corpora"]["public_reproduction"]
        private_identity = contract["corpora"]["private_canonical"]
        payloads = {
            name: load_json(root / "tool_contract_drift/fixtures" / name)
            for name in public_identity["fixture_files"]
        }
    except (KeyError, OSError, json.JSONDecodeError) as exc:
        return [f"public corpus contract could not be read: {exc}"]
    fixtures = [record for payload in payloads.values() for record in payload]
    if "study" in contract.get("expected_counts", {}):
        issues.append("packaged release contract leaks private study planning counts")
    if manifest.get("toolchain", {}).get("oasdiff") != contract.get("toolchain", {}).get("oasdiff"):
        issues.append("manifest oasdiff declaration differs from the packaged release contract")
    fixture_count = len(fixtures)
    rendered = {
        name: render_json(payload).encode("utf-8")
        for name, payload in payloads.items()
    }
    digest = content_manifest_sha256(rendered)
    if fixture_count != public_identity["expected_fixture_count"]:
        issues.append("public fixture count differs from release contract")
    if digest != public_identity["content_manifest_sha256"]:
        issues.append("public corpus content manifest differs from release contract")

    blocked_ids = set(contract["redistribution"]["blocked_fixture_ids"])
    fixture_ids = {record["id"] for record in fixtures}
    if len(fixture_ids) != fixture_count:
        issues.append("public reproduction corpus has duplicate fixture IDs")
    try:
        composition = public_composition(fixtures)
    except ValueError as exc:
        issues.append(str(exc))
        composition = {}
    if composition != public_identity.get("composition"):
        issues.append("public reproduction composition differs from release contract")
    if fixture_ids & blocked_ids:
        issues.append(f"blocked fixture IDs are present: {sorted(fixture_ids & blocked_ids)}")
    allowlist_ids = {entry["fixture_id"] for entry in package_allowlist.get("entries", [])}
    if package_allowlist.get("entry_count") != len(package_allowlist.get("entries", [])):
        issues.append("packaged hash allowlist entry count is inconsistent")
    if not allowlist_ids <= fixture_ids:
        issues.append(f"packaged hash allowlist has non-public fixture IDs: {sorted(allowlist_ids - fixture_ids)}")
    if allowlist_ids & blocked_ids:
        issues.append(f"packaged hash allowlist has blocked fixture IDs: {sorted(allowlist_ids & blocked_ids)}")
    if package_allowlist.get("corpus_id") != public_identity["id"]:
        issues.append("packaged hash allowlist identifies a different corpus")
    if package_allowlist.get("corpus_manifest_sha256") != digest:
        issues.append("packaged hash allowlist identifies a different corpus manifest")
    for entry in package_allowlist.get("entries", []):
        source_file = str(entry.get("source_file", ""))
        try:
            source_path = checked_relative_path(source_file)
        except ValueError:
            issues.append(f"packaged hash allowlist has unsafe path: {source_file}")
            continue
        if not (root / source_path).is_file():
            issues.append(f"packaged hash allowlist path is absent: {source_file}")
    issues.extend(verify_empty_public_case_lock(package_lock))
    inventory_issues, inventory_count = verify_source_metadata_inventory(
        source_inventory,
        fixture_ids,
    )
    issues.extend(inventory_issues)

    sys.path.insert(0, str(root))
    try:
        from tool_contract_drift.corpora import (
            PRIVATE_CANONICAL_CORPUS_ID,
            PUBLIC_REPRODUCTION_CORPUS_ID,
            select_corpus,
        )
        from tool_contract_drift.baselines.configured_substitutes import (
            run_bakeoff,
            summarize_bakeoff,
        )
        from tool_contract_drift.linter.tool_contract_drift import lint_fixtures
        from tool_contract_drift.linter.tool_contract_drift import render_markdown
        from tool_contract_drift_cli import annotate_markdown_corpus, render_sarif

        selected = select_corpus(PUBLIC_REPRODUCTION_CORPUS_ID)
        if selected.expected_fixture_count != fixture_count:
            issues.append("public corpus selector count differs from packaged bytes")
        try:
            select_corpus(PRIVATE_CANONICAL_CORPUS_ID)
        except RuntimeError:
            pass
        else:
            issues.append("private corpus is selectable from the public export")
        findings = lint_fixtures(fixtures)
        finding_count = len(findings)
        carrier_summary = summarize_bakeoff(
            run_bakeoff(
                [
                    root / "tool_contract_drift/fixtures" / name
                    for name in public_identity["fixture_files"]
                ]
            )
        )
    except Exception as exc:
        issues.append(f"public corpus runtime verification failed: {exc}")
        finding_count = -1
        carrier_summary = {
            "configured_spectral_exact_matches": -1,
            "oasdiff_mapper_exact_matches": -1,
        }
        findings = []
    finally:
        if sys.path[0] == str(root):
            sys.path.pop(0)

    expected = policy["corpus_contract"]
    if fixture_count != expected["public_expected_fixture_count"]:
        issues.append("public fixture count differs from export policy")
    if finding_count != expected["public_expected_finding_count"]:
        issues.append("public finding count differs from export policy")
    if carrier_summary["configured_spectral_exact_matches"] != fixture_count:
        issues.append("configured-policy public carrier mapping differs")
    if carrier_summary["oasdiff_mapper_exact_matches"] != fixture_count:
        issues.append("oasdiff-style public carrier mapping differs")
    if len(blocked_ids) != expected["blocked_private_fixture_count"]:
        issues.append("blocked fixture count differs from export policy")
    if expected.get("private_corpus_selectable_surface_included") is not False:
        issues.append("export policy does not exclude the selectable private corpus surface")
    if expected.get("private_source_derived_fixture_bytes_included") is not False:
        issues.append("export policy does not exclude private source-derived fixture bytes")
    if (
        public_identity.get("composition", {}).get(
            "retained_from_private_canonical_synthetic_fixture_count"
        )
        != expected.get("retained_private_synthetic_fixture_count")
    ):
        issues.append("retained private synthetic fixture count differs from export policy")
    hold_fixture_count = len({finding.fixture_id for finding in findings})
    expected_public_counts = {
        "candidate_file_reference_count": 0,
        "finding_count": finding_count,
        "hold_fixture_count": hold_fixture_count,
        "public_fixture_count": 0,
        "quiet_fixture_count": fixture_count - hold_fixture_count,
        "source_lock_record_count": 0,
        "synthetic_fixture_count": fixture_count,
    }
    if contract.get("expected_counts", {}).get("public_package") != expected_public_counts:
        issues.append("public package counts differ from release contract")
    finding_set_sha256 = canonical_json_sha256(normalize_findings(findings))
    if public_identity.get("finding_set_sha256") != finding_set_sha256:
        issues.append("public finding-set hash differs from the release contract")
    observed_manifest = manifest.get("corpora", {})
    expected_manifest = {
        "private": {
            "corpus_selectable_surface_included": False,
            "expected_fixture_count": private_identity["expected_fixture_count"],
            "id": private_identity["id"],
            "redistribution_blocked_fixture_count": len(blocked_ids),
            "retained_synthetic_fixture_count": composition[
                "retained_from_private_canonical_synthetic_fixture_count"
            ],
            "source_derived_descriptor_bytes_included": False,
        },
        "public": {
            "composition": composition,
            "content_manifest_sha256": digest,
            "configured_policy_shared_semantics_exact_matches": carrier_summary[
                "configured_spectral_exact_matches"
            ],
            "finding_count": finding_count,
            "finding_set_sha256": finding_set_sha256,
            "fixture_count": fixture_count,
            "id": public_identity["id"],
            "independent_comparator_evidence": False,
            "metadata_only_private_source_record_count": inventory_count,
            "oasdiff_style_shared_semantics_exact_matches": carrier_summary["oasdiff_mapper_exact_matches"],
            "public_hash_allowlist_entry_count": package_allowlist["entry_count"],
            "public_provenance_case_record_count": 0,
            "source_derived_descriptor_byte_count": 0,
            "synthetic_fixture_count": fixture_count,
        },
    }
    if observed_manifest != expected_manifest:
        issues.append("manifest corpus summary differs from independently observed public bytes")
    try:
        sarif = load_json(root / "reports/current_linter_report.sarif")
        run = sarif["runs"][0]
        properties = run["tool"]["driver"]["properties"]
        if properties.get("corpus_id") != public_identity["id"]:
            issues.append("public SARIF corpus ID differs")
        if properties.get("corpus_manifest_sha256") != digest:
            issues.append("public SARIF corpus manifest differs")
        if len(run.get("results", [])) != finding_count:
            issues.append("public SARIF finding count differs")
        markdown = (root / "reports/current_linter_report.md").read_text()
        report_fixtures = []
        for name, payload in payloads.items():
            for fixture in payload:
                report_fixture = dict(fixture)
                report_fixture["_source_file"] = f"tool_contract_drift/fixtures/{name}"
                report_fixtures.append(report_fixture)
        corpus_metadata = {
            "content_manifest_sha256": digest,
            "evidence_boundary": (
                "fully synthetic public-package reproduction corpus; the separate source-metadata "
                "inventory contains no source-derived descriptor bytes and grants no permission"
            ),
            "fixture_count": fixture_count,
            "id": public_identity["id"],
        }
        expected_sarif = json.loads(
            render_sarif(
                report_fixtures,
                findings,
                {"_corpus": corpus_metadata, "policy_version": "tool-contract-drift-v1", "sarif": {}},
            )
        )
        if sarif != expected_sarif:
            issues.append("public SARIF does not represent the exact live public finding tuples")
        for result in run.get("results", []):
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            if not (root / uri).is_file() or uri not in {record["path"] for record in manifest.get("files", [])}:
                issues.append(f"public SARIF artifact URI is not manifested: {uri}")
        expected_markdown = annotate_markdown_corpus(render_markdown(findings), corpus_metadata)
        if markdown != expected_markdown:
            issues.append("public Markdown report does not represent the exact live public finding tuples")
    except (KeyError, OSError, json.JSONDecodeError) as exc:
        issues.append(f"public reports could not be verified: {exc}")
    return issues


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


def content_manifest_sha256(files: dict[str, bytes]) -> str:
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}
    payload = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def public_composition(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    source_identity_fields = {"commit", "repo", "source", "url"}
    sourced = sorted(
        record.get("id", "<missing-id>")
        for record in fixtures
        if any(record.get(field) for field in source_identity_fields)
    )
    if sourced:
        raise ValueError(f"public reproduction fixtures contain source-derived identity fields: {sourced}")
    new_controls = sorted(
        (
            record
            for record in fixtures
            if str(record.get("id", "")).startswith("public-synthetic-quiet-")
        ),
        key=lambda record: record["id"],
    )
    if any(record.get("expected_risks") for record in new_controls):
        raise ValueError("newly authored public synthetic controls are not all quiet controls")
    retained = [
        record
        for record in fixtures
        if not str(record.get("id", "")).startswith("public-synthetic-quiet-")
    ]
    return {
        "all_fixture_bytes_authored_for_this_project": True,
        "construction_version": "public-reproduction-corpus-v1",
        "newly_authored_synthetic_quiet_control_count": len(new_controls),
        "newly_authored_synthetic_quiet_control_ids_sha256": canonical_json_sha256(
            sorted(record["id"] for record in new_controls)
        ),
        "newly_authored_synthetic_quiet_control_records_sha256": canonical_json_sha256(
            new_controls
        ),
        "relationship_to_private_canonical": (
            "separate_manifest_identity_reuses_private_synthetic_records_not_a_private_corpus_subset"
        ),
        "retained_from_private_canonical_synthetic_fixture_count": len(retained),
        "retained_from_private_canonical_synthetic_fixture_ids_sha256": canonical_json_sha256(
            sorted(record["id"] for record in retained)
        ),
        "retained_from_private_canonical_synthetic_fixture_records_sha256": canonical_json_sha256(
            sorted(retained, key=lambda record: record["id"])
        ),
        "retained_from_private_canonical_descriptor_pairs_sha256": descriptor_pairs_sha256(retained),
        "source_derived_descriptor_byte_count": 0,
        "total_authored_synthetic_fixture_count": len(fixtures),
    }


def verify_empty_public_case_lock(package_lock: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if package_lock.get("schema_version") != "tool-contract-drift-public-fixtures-lock-v1":
        issues.append("public case-provenance lock has an unsupported schema")
    if package_lock.get("release_surface") != "fully-synthetic-public-package-no-source-derived-case-bytes":
        issues.append("public case-provenance lock has an unsupported release surface")
    if package_lock.get("records") != []:
        issues.append("fully synthetic public package has case-bound provenance records")
    if package_lock.get("source_metadata_inventory") != "tool_contract_drift/data/source_metadata_inventory.json":
        issues.append("public case-provenance lock does not identify the metadata-only source inventory")
    return issues


def verify_source_metadata_inventory(
    inventory: dict[str, Any],
    public_fixture_ids: set[str],
) -> tuple[list[str], int]:
    issues: list[str] = []
    if inventory.get("schema_version") != "source-metadata-inventory-v1":
        issues.append("source metadata inventory has an unsupported schema")
    if inventory.get("status") != "metadata_only_not_public_cases_not_permission":
        issues.append("source metadata inventory does not preserve its non-permission boundary")
    if not isinstance(inventory.get("boundary"), str) or not inventory["boundary"].strip():
        issues.append("source metadata inventory has no evidence boundary")
    records = inventory.get("records")
    if not isinstance(records, list):
        return issues + ["source metadata inventory records are not a list"], 0
    if inventory.get("record_count") != len(records):
        issues.append("source metadata inventory count is inconsistent")
    required_fields = {
        "commit",
        "extraction_status",
        "fixture_id",
        "fixture_sha256",
        "legal_review_status",
        "license_status",
        "redistribution_status",
        "repo",
        "source_resolution_status",
        "url",
    }
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != required_fields:
            issues.append("source metadata inventory has a malformed record")
            continue
        fixture_id = str(record["fixture_id"])
        if fixture_id in seen:
            issues.append(f"source metadata inventory duplicates {fixture_id}")
        seen.add(fixture_id)
        if fixture_id in public_fixture_ids:
            issues.append(f"source metadata inventory overlaps public case {fixture_id}")
        commit = str(record["commit"])
        digest = str(record["fixture_sha256"])
        repo = str(record["repo"])
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            issues.append(f"source metadata commit is invalid: {fixture_id}")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            issues.append(f"source metadata fixture hash is invalid: {fixture_id}")
        if record["url"] != f"https://github.com/{repo}/commit/{commit}":
            issues.append(f"source metadata URL is inconsistent: {fixture_id}")
        if record["license_status"] != "not_audited" or record["legal_review_status"] != "not_reviewed":
            issues.append(f"source metadata review boundary differs: {fixture_id}")
        if record["extraction_status"] != "manual_extraction_not_replayed":
            issues.append(f"source metadata extraction boundary differs: {fixture_id}")
        if record["redistribution_status"] not in {
            "permissive_license_metadata_inventory",
            "uncleared_metadata_inventory_public_release_blocker",
        }:
            issues.append(f"source metadata redistribution boundary differs: {fixture_id}")
    return issues, len(records)


def checked_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError(value)
    return path


def fixture_sha256(fixture: dict[str, Any]) -> str:
    public_fixture = {key: value for key, value in fixture.items() if not key.startswith("_")}
    payload = json.dumps(public_fixture, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_findings(findings: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "evidence": list(finding.evidence),
            "fixture_id": finding.fixture_id,
            "generic_baseline_labels": list(finding.generic_baseline_labels),
            "reapproval_required": finding.reapproval_required,
            "reason": finding.reason,
            "risk": finding.risk,
            "severity": finding.severity,
            "tool_name": finding.tool_name,
        }
        for finding in findings
    ]


def canonical_json_sha256(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def descriptor_pairs_sha256(records: list[dict[str, Any]]) -> str:
    pairs = [
        {"id": record["id"], "before": record["before"], "after": record["after"]}
        for record in sorted(records, key=lambda record: record["id"])
    ]
    return canonical_json_sha256(pairs)


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def render_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
