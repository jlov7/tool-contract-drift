from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tool_contract_drift.corpora import (
    PRIVATE_CANONICAL_CORPUS_ID,
    PUBLIC_REPRODUCTION_CORPUS_ID,
    load_release_contract,
    select_corpus,
)
from tool_contract_drift.linter.tool_contract_drift import lint_fixtures, load_fixtures
from scripts.verify_public_export import verify_publication_state


ROOT = Path(__file__).resolve().parents[1]


class PublicDistributionTests(unittest.TestCase):
    def test_public_source_availability_does_not_imply_other_publications(self) -> None:
        metadata = json.loads((ROOT / "release/public_release_metadata.json").read_text())
        metadata["status"] = "public_source_repository"
        metadata["publication_state"].update(github_repository_created=True, github_repository_public=True)
        metadata["github"]["visibility"] = "public"
        self.assertEqual([], verify_publication_state(metadata))
        for flag in ("github_release_created", "archive_created", "doi_created_or_reserved", "public_post_made"):
            with self.subTest(flag=flag):
                metadata["publication_state"][flag] = True
                self.assertTrue(verify_publication_state(metadata))
                metadata["publication_state"][flag] = False
        as_of = metadata.pop("publication_state_as_of")
        self.assertTrue(verify_publication_state(metadata))
        for invalid in (None, "not-a-date", "2026-02-30", "20261020"):
            with self.subTest(date=invalid):
                metadata["publication_state_as_of"] = invalid
                self.assertTrue(verify_publication_state(metadata))
        metadata["publication_state_as_of"] = as_of
        metadata["publication_state"]["github_repository_created"] = False
        self.assertTrue(verify_publication_state(metadata))

    def test_public_corpus_identity_and_result(self) -> None:
        selected = select_corpus(PUBLIC_REPRODUCTION_CORPUS_ID)
        fixtures = [fixture for path in selected.fixture_paths for fixture in load_fixtures(path)]

        self.assertEqual("fully-synthetic-installed-public-package", selected.availability)
        self.assertEqual(53, selected.expected_fixture_count)
        self.assertEqual(53, len(fixtures))
        self.assertEqual(25, len(lint_fixtures(fixtures)))

    def test_private_corpus_cannot_silently_fall_back_to_public_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch(
            "tool_contract_drift.corpora.SOURCE_ROOT",
            Path(tmp),
        ):
            with self.assertRaisesRegex(RuntimeError, "private checkout evidence"):
                select_corpus(PRIVATE_CANONICAL_CORPUS_ID)

    def test_public_corpus_is_fully_synthetic_and_metadata_inventory_is_separate(self) -> None:
        contract = load_release_contract()
        lock = json.loads((ROOT / "tool_contract_drift/data/public_fixtures.lock.json").read_text())
        inventory = json.loads(
            (ROOT / "tool_contract_drift/data/source_metadata_inventory.json").read_text()
        )
        allowlist = json.loads((ROOT / "tool_contract_drift/policy/hash_allowlist_quiet_changes.json").read_text())
        selected = select_corpus(PUBLIC_REPRODUCTION_CORPUS_ID)
        fixtures = [fixture for path in selected.fixture_paths for fixture in load_fixtures(path)]
        fixture_ids = {fixture["id"] for fixture in fixtures}
        blocked_ids = set(contract["redistribution"]["blocked_fixture_ids"])
        source_fields = {"commit", "repo", "source", "url"}

        self.assertEqual(set(), fixture_ids & blocked_ids)
        self.assertNotIn("study", contract.get("expected_counts", {}))
        self.assertEqual([], lock["records"])
        self.assertEqual(
            "fully-synthetic-public-package-no-source-derived-case-bytes",
            lock["release_surface"],
        )
        self.assertTrue(
            all(not any(fixture.get(field) for field in source_fields) for fixture in fixtures)
        )
        self.assertEqual(53, contract["corpora"]["public_reproduction"]["composition"]["total_authored_synthetic_fixture_count"])
        self.assertEqual(0, contract["corpora"]["public_reproduction"]["composition"]["source_derived_descriptor_byte_count"])
        self.assertEqual("metadata_only_not_public_cases_not_permission", inventory["status"])
        self.assertEqual(inventory["record_count"], len(inventory["records"]))
        self.assertEqual(set(), fixture_ids & {record["fixture_id"] for record in inventory["records"]})
        allowlist_ids = {entry["fixture_id"] for entry in allowlist["entries"]}
        self.assertEqual(allowlist["entry_count"], len(allowlist["entries"]))
        self.assertLessEqual(allowlist_ids, fixture_ids)
        self.assertEqual(set(), allowlist_ids & blocked_ids)
        self.assertTrue(
            all(
                (ROOT / entry["source_file"]).is_file()
                for entry in allowlist["entries"]
            )
        )

    def test_cli_requires_and_echoes_the_public_corpus_identity(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "tool_contract_drift_cli.py",
                "lint",
                "--corpus",
                PUBLIC_REPRODUCTION_CORPUS_ID,
                "--format",
                "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)

        self.assertEqual(PUBLIC_REPRODUCTION_CORPUS_ID, report["corpus"]["id"])
        self.assertEqual(53, report["corpus"]["fixture_count"])
        self.assertEqual(25, report["summary"]["total_findings"])

    def test_public_configured_carriers_use_the_public_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "configured.md"
            json_output = Path(tmp) / "configured.json"
            subprocess.run(
                [
                    sys.executable,
                    "tool_contract_drift_cli.py",
                    "configured-baselines",
                    "--corpus",
                    PUBLIC_REPRODUCTION_CORPUS_ID,
                    "--output",
                    str(output),
                    "--json",
                    str(json_output),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(json_output.read_text())

        self.assertEqual(PUBLIC_REPRODUCTION_CORPUS_ID, report["corpus"]["id"])
        self.assertEqual(53, report["summary"]["fixture_count"])
        self.assertEqual(53, report["summary"]["configured_spectral_exact_matches"])
        self.assertEqual(53, report["summary"]["oasdiff_mapper_exact_matches"])


if __name__ == "__main__":
    unittest.main()
