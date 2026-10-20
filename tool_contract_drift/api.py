from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

from tool_contract_drift.linter.tool_contract_drift import RiskFinding, lint_fixture


def load_policy(version: str = "tool-contract-drift-v1") -> dict[str, Any]:
    """Load a packaged Agent Tool Contract Drift policy document."""
    if version != "tool-contract-drift-v1":
        raise ValueError(f"Unsupported policy version: {version}")
    return json.loads(resources.files("tool_contract_drift.policy").joinpath("tool-contract-drift-v1.json").read_text())


def lint_descriptor_pair(
    before: dict[str, Any],
    after: dict[str, Any],
    fixture_id: str = "descriptor-pair",
) -> list[RiskFinding]:
    """Lint one before/after descriptor pair with the reference Agent Tool Contract Drift policy."""
    return lint_fixture({"id": fixture_id, "before": before, "after": after})


def lint_fixture_record(fixture: dict[str, Any]) -> list[RiskFinding]:
    """Lint a fixture-shaped record with the reference Agent Tool Contract Drift policy."""
    return lint_fixture(fixture)


def validate_fixture_records(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate fixture records with the same checks used by the CLI release gate."""
    from tool_contract_drift_cli import validate_fixture_records as _validate_fixture_records

    return _validate_fixture_records(fixtures)


def load_descriptor(path: str | Path) -> dict[str, Any]:
    """Load a descriptor JSON object from disk."""
    return json.loads(Path(path).read_text())
