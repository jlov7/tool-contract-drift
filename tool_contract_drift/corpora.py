from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable


PRIVATE_CANONICAL_CORPUS_ID = "private-canonical-65"
PUBLIC_REPRODUCTION_CORPUS_ID = "public-reproduction-53"
SUPPORTED_CORPUS_IDS = (PRIVATE_CANONICAL_CORPUS_ID, PUBLIC_REPRODUCTION_CORPUS_ID)

PACKAGE_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_ROOT.parent
RELEASE_CONTRACT_RESOURCE = "data/release_contract.json"


@dataclass(frozen=True)
class CorpusSelection:
    id: str
    expected_fixture_count: int
    content_manifest_sha256: str
    fixture_paths: tuple[Path, ...]
    availability: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "expected_fixture_count": self.expected_fixture_count,
            "content_manifest_sha256": self.content_manifest_sha256,
            "availability": self.availability,
        }


def load_release_contract() -> dict[str, Any]:
    return json.loads(resources.files("tool_contract_drift").joinpath(RELEASE_CONTRACT_RESOURCE).read_text())


def select_corpus(corpus_id: str) -> CorpusSelection:
    contract = load_release_contract()
    identity = _identity_for_id(contract, corpus_id)
    names = tuple(identity["fixture_files"])
    if corpus_id == PRIVATE_CANONICAL_CORPUS_ID:
        fixture_root = SOURCE_ROOT / "fixtures"
        availability = "private-source-checkout"
        if not fixture_root.is_dir():
            raise RuntimeError(
                f"Corpus {corpus_id!r} is private checkout evidence and is unavailable in this installation. "
                f"Use {PUBLIC_REPRODUCTION_CORPUS_ID!r} or pass explicit fixture files without making a corpus claim."
            )
        paths = tuple(fixture_root / name for name in names)
    elif corpus_id == PUBLIC_REPRODUCTION_CORPUS_ID:
        fixture_root = resources.files("tool_contract_drift.fixtures")
        availability = "fully-synthetic-installed-public-package"
        paths = tuple(Path(str(fixture_root.joinpath(name))) for name in names)
    else:
        raise ValueError(f"Unknown corpus id {corpus_id!r}; expected one of {', '.join(SUPPORTED_CORPUS_IDS)}.")

    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise RuntimeError(f"Corpus {corpus_id!r} is incomplete; missing fixture files: {', '.join(missing)}")
    _verify_identity(identity, paths)
    return CorpusSelection(
        id=identity["id"],
        expected_fixture_count=identity["expected_fixture_count"],
        content_manifest_sha256=identity["content_manifest_sha256"],
        fixture_paths=paths,
        availability=availability,
    )


def custom_fixture_paths(paths: Iterable[str | Path]) -> tuple[Path, ...]:
    selected = tuple(Path(path) for path in paths)
    if not selected:
        raise ValueError("At least one explicit fixture path is required for a custom corpus.")
    missing = [str(path) for path in selected if not path.is_file()]
    if missing:
        raise RuntimeError(f"Custom fixture files are missing: {', '.join(missing)}")
    return selected


def canonical_fixture_source(path: str | Path) -> str:
    """Render fixture provenance without embedding checkout-specific absolute paths."""
    selected = Path(path)
    if not selected.is_absolute():
        return selected.as_posix()
    try:
        package_relative = selected.relative_to(PACKAGE_ROOT)
        return (Path("tool_contract_drift") / package_relative).as_posix()
    except ValueError:
        pass
    try:
        return selected.relative_to(SOURCE_ROOT).as_posix()
    except ValueError:
        pass
    return selected.name


def _identity_for_id(contract: dict[str, Any], corpus_id: str) -> dict[str, Any]:
    matches = [identity for identity in contract["corpora"].values() if identity["id"] == corpus_id]
    if len(matches) != 1:
        raise ValueError(f"Unknown corpus id {corpus_id!r}; expected one of {', '.join(SUPPORTED_CORPUS_IDS)}.")
    return matches[0]


def _verify_identity(identity: dict[str, Any], paths: tuple[Path, ...]) -> None:
    payloads = {path.name: json.loads(path.read_text()) for path in paths}
    fixture_count = sum(len(payload) for payload in payloads.values())
    if fixture_count != identity["expected_fixture_count"]:
        raise RuntimeError(
            f"Corpus {identity['id']!r} fixture-count mismatch: "
            f"expected {identity['expected_fixture_count']}, found {fixture_count}."
        )
    rendered = {
        name: (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        for name, payload in payloads.items()
    }
    digest = content_manifest_sha256(rendered)
    if digest != identity["content_manifest_sha256"]:
        raise RuntimeError(
            f"Corpus {identity['id']!r} manifest mismatch: "
            f"expected {identity['content_manifest_sha256']}, found {digest}."
        )


def content_manifest_sha256(files: dict[str, bytes]) -> str:
    file_hashes = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}
    manifest = json.dumps(file_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(manifest).hexdigest()
