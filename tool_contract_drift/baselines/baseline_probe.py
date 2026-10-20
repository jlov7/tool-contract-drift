from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tool_contract_drift.corpora import SUPPORTED_CORPUS_IDS, custom_fixture_paths, select_corpus

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tool_contract_drift.linter.tool_contract_drift import generic_diff_baseline, lint_fixture, load_fixtures


FIXTURE_FILES = (
    "tool_descriptor_fixtures.json",
    "real_public_descriptor_changes.json",
    "heldout_public_descriptor_changes.json",
    "second_heldout_public_descriptor_changes.json",
    "third_heldout_public_descriptor_changes.json",
    "ordinary_public_descriptor_controls.json",
    "adversarial_descriptor_cases.json",
)
AGENT_RISK_LABELS = (
    "readonly_to_destructive",
    "destructive_hint_escalation",
    "destructive_hint_downgrade",
    "description_injection_drift",
    "auth_scope_expansion",
    "closed_world_to_open_world_input",
    "schema_containment_unresolved",
    "sensitive_output_template_drift",
    "sensitive_output_schema_expansion",
    "risky_tool_added",
)


@dataclass(frozen=True)
class CommandResult:
    name: str
    command: str
    status: str
    exit_code: int | None
    stdout_excerpt: str
    stderr_excerpt: str


@dataclass(frozen=True)
class FixtureProbeResult:
    fixture_id: str
    source_file: str
    expected_candidate_risks: tuple[str, ...]
    candidate_finding_count: int
    generic_diff_labels: tuple[str, ...]
    hash_binding_labels: tuple[str, ...]
    oasdiff_status: str
    oasdiff_exit_code: int | None
    oasdiff_changed: bool
    oasdiff_agent_label_hits: tuple[str, ...]
    before_openapi: str
    after_openapi: str


def operation_path(tool_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", tool_name).strip("-")
    return f"/tools/{cleaned or 'tool'}"


def operation_id(tool_name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", tool_name).strip("_")
    if not cleaned:
        return "tool"
    if cleaned[0].isdigit():
        return f"tool_{cleaned}"
    return cleaned


def descriptor_to_openapi(descriptor: dict[str, Any], title: str) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for tool in descriptor.get("tools", []):
        extensions: dict[str, Any] = {
            "x-mcp-tool-name": tool["name"],
            "x-mcp-annotations": tool.get("annotations", {}),
            "x-mcp-auth": tool.get("auth", {}),
        }
        if "output_template" in tool:
            extensions["x-mcp-output-template"] = tool["output_template"]

        paths[operation_path(tool["name"])] = {
            "post": {
                "operationId": operation_id(tool["name"]),
                "tags": ["mcp-tool"],
                "summary": tool["name"],
                "description": tool.get("description") or f"MCP tool {tool['name']}.",
                "requestBody": {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": normalized_schema(tool.get("input_schema")),
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "MCP tool result.",
                        "content": {
                            "application/json": {
                                "schema": normalized_schema(tool.get("output_schema")),
                            }
                        },
                    }
                },
                **extensions,
            }
        }

    return {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": "0.0.0",
            "description": "Generated projection of MCP/App tool descriptors for generic OpenAPI baselines.",
            "contact": {"name": "Agent Tool Contract Drift baseline probe"},
        },
        "servers": [{"url": "https://example.invalid"}],
        "tags": [{"name": "mcp-tool", "description": "Generated MCP/App tool operation."}],
        "paths": paths,
    }


def normalized_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    if schema:
        return schema
    return {"type": "object", "additionalProperties": True}


def hash_binding_baseline(fixture: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    before = {tool["name"]: tool for tool in fixture["before"].get("tools", [])}
    after = {tool["name"]: tool for tool in fixture["after"].get("tools", [])}
    labels_by_tool: dict[str, tuple[str, ...]] = {}
    for name in sorted(set(before) | set(after)):
        labels: list[str] = []
        if name not in before:
            labels.append("unapproved_tool")
        elif name not in after:
            labels.append("tool_removed")
        else:
            before_hash = tool_description_hash(name, before[name].get("description", ""))
            after_hash = tool_description_hash(name, after[name].get("description", ""))
            if before_hash != after_hash:
                labels.append("description_hash_mismatch")
        if labels:
            labels_by_tool[name] = tuple(labels)
    return labels_by_tool


def tool_description_hash(tool_name: str, description: str) -> str:
    payload = json.dumps({"name": tool_name, "description": description}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_all_fixtures(paths: list[Path]) -> list[tuple[str, dict[str, Any]]]:
    if not paths:
        raise ValueError("Fixture paths are required; select a named corpus explicitly before running evidence code.")
    loaded: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        for fixture in load_fixtures(path):
            loaded.append((path.name, fixture))
    return loaded


def write_openapi_pair(fixture: dict[str, Any], fixture_dir: Path) -> tuple[Path, Path]:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    before_path = fixture_dir / "before_openapi.json"
    after_path = fixture_dir / "after_openapi.json"
    before_path.write_text(
        json.dumps(descriptor_to_openapi(fixture["before"], f"{fixture['id']} descriptor"), indent=2, sort_keys=True)
        + "\n"
    )
    after_path.write_text(
        json.dumps(descriptor_to_openapi(fixture["after"], f"{fixture['id']} descriptor"), indent=2, sort_keys=True)
        + "\n"
    )
    (fixture_dir / "before_descriptor.json").write_text(json.dumps(fixture["before"], indent=2, sort_keys=True) + "\n")
    (fixture_dir / "after_descriptor.json").write_text(json.dumps(fixture["after"], indent=2, sort_keys=True) + "\n")
    return before_path, after_path


def run_command(command: list[str], cwd: Path, timeout: int = 60) -> CommandResult:
    display_command = " ".join(display_command_args(command))
    display_name = Path(command[0]).name
    try:
        completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return CommandResult(display_name, display_command, "not_found", None, "", "command not found")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(display_name, display_command, "timeout", None, exc.stdout or "", exc.stderr or "")
    status = "ok" if completed.returncode == 0 else "nonzero"
    stdout = normalize_json_output(completed.stdout) if display_name == "oasdiff" else completed.stdout
    return CommandResult(
        display_name,
        display_command,
        status,
        completed.returncode,
        excerpt(sanitize_text(stdout)),
        excerpt(sanitize_text(completed.stderr)),
    )


def normalize_json_output(value: str) -> str:
    if not value.strip():
        return value
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    return json.dumps(sort_json_arrays(parsed), separators=(",", ":"))


def sort_json_arrays(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        return {key: sort_json_arrays(item, key) for key, item in value.items()}
    if isinstance(value, list):
        normalized = [sort_json_arrays(item, parent_key) for item in value]
        if parent_key == "added" and all(isinstance(item, str) for item in normalized):
            return sorted(normalized)
        return normalized
    return value


def sanitize_text(value: str) -> str:
    return value.replace(str(ROOT), ".").replace(str(Path.home()), "~")


def display_command_args(command: list[str]) -> list[str]:
    return [display_command_arg(arg) for arg in command]


def display_command_arg(arg: str) -> str:
    path = Path(arg)
    if path.is_absolute():
        try:
            return str(path.relative_to(ROOT))
        except ValueError:
            return path.name
    return arg


def excerpt(value: str, limit: int = 2000) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def agent_label_hits(text: str) -> tuple[str, ...]:
    return tuple(label for label in AGENT_RISK_LABELS if label in text)


def find_oasdiff() -> str | None:
    direct = Path.home() / "go" / "bin" / "oasdiff"
    if direct.exists():
        return str(direct)
    return shutil.which("oasdiff")


def probe_fixtures(
    artifact_dir: Path,
    fixture_paths: list[Path],
) -> tuple[list[FixtureProbeResult], list[CommandResult], dict[str, Any]]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / ".spectral.yaml").write_text('extends: ["spectral:oas"]\n')
    command_results: list[CommandResult] = []
    fixture_results: list[FixtureProbeResult] = []
    oasdiff = find_oasdiff()

    for source_file, fixture in load_all_fixtures(fixture_paths):
        fixture_dir = artifact_dir / fixture["id"]
        before_path, after_path = write_openapi_pair(fixture, fixture_dir)
        candidate_findings = lint_fixture(fixture)
        expected = tuple(sorted({finding.risk for finding in candidate_findings}))
        generic_labels = tuple(sorted({label for diff in generic_diff_baseline(fixture) for label in diff.labels}))
        hash_labels = tuple(sorted({label for labels in hash_binding_baseline(fixture).values() for label in labels}))

        oasdiff_status = "not_found"
        oasdiff_exit_code: int | None = None
        oasdiff_changed = False
        oasdiff_hits: tuple[str, ...] = ()
        if oasdiff:
            result = run_command([oasdiff, "diff", str(before_path), str(after_path), "-f", "json"], ROOT)
            command_results.append(result)
            oasdiff_status = result.status
            oasdiff_exit_code = result.exit_code
            combined = f"{result.stdout_excerpt}\n{result.stderr_excerpt}"
            oasdiff_changed = result.status == "ok" and combined not in ("", "null\n")
            oasdiff_hits = agent_label_hits(combined)

        fixture_results.append(
            FixtureProbeResult(
                fixture_id=fixture["id"],
                source_file=source_file,
                expected_candidate_risks=expected,
                candidate_finding_count=len(candidate_findings),
                generic_diff_labels=generic_labels,
                hash_binding_labels=hash_labels,
                oasdiff_status=oasdiff_status,
                oasdiff_exit_code=oasdiff_exit_code,
                oasdiff_changed=oasdiff_changed,
                oasdiff_agent_label_hits=oasdiff_hits,
                before_openapi=portable_path(before_path, REPO_ROOT),
                after_openapi=portable_path(after_path, REPO_ROOT),
            )
        )

    after_docs = sorted(str(path) for path in artifact_dir.glob("*/after_openapi.json"))
    spectral_result = run_command(
        [
            "npx",
            "-y",
            "-p",
            "@stoplight/spectral-cli",
            "-p",
            "@stoplight/spectral-rulesets",
            "spectral",
            "lint",
            "-f",
            "json",
            *after_docs,
        ],
        artifact_dir,
        timeout=120,
    )
    command_results.append(spectral_result)
    spectral_text = f"{spectral_result.stdout_excerpt}\n{spectral_result.stderr_excerpt}"

    metadata = {
        "spectral_status": spectral_result.status,
        "spectral_exit_code": spectral_result.exit_code,
        "spectral_agent_label_hits": agent_label_hits(spectral_text),
        "spectral_issue_count": count_json_list(spectral_result.stdout_excerpt),
        "spectral_issue_codes": json_issue_codes(spectral_result.stdout_excerpt),
    }
    return fixture_results, command_results, metadata


def count_json_list(text: str) -> int | None:
    try:
        parsed = json.loads(text) if text.strip() else []
    except json.JSONDecodeError:
        return None
    return len(parsed) if isinstance(parsed, list) else None


def json_issue_codes(text: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(text) if text.strip() else []
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    codes = sorted({str(item.get("code")) for item in parsed if isinstance(item, dict) and item.get("code")})
    return tuple(codes)


def collect_tool_orientation_commands() -> list[CommandResult]:
    return [
        run_command(["npx", "-y", "mcp-to-ai-sdk", "--help"], ROOT, timeout=60),
        run_command(["npx", "-y", "@modelcontextprotocol/inspector", "--help"], ROOT, timeout=60),
        run_command(["npx", "-y", "@stoplight/spectral-cli", "lint", "--help"], ROOT, timeout=60),
    ]


def portable_path(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def render_report(
    fixture_results: list[FixtureProbeResult],
    command_results: list[CommandResult],
    metadata: dict[str, Any],
) -> str:
    total_fixtures = len(fixture_results)
    candidate_hold_fixtures = sum(1 for item in fixture_results if item.expected_candidate_risks)
    candidate_risk_count = sum(len(item.expected_candidate_risks) for item in fixture_results)
    candidate_finding_count = sum(item.candidate_finding_count for item in fixture_results)
    generic_agent_hits = sorted(
        {
            label
            for item in fixture_results
            for label in item.generic_diff_labels
            if label in AGENT_RISK_LABELS
        }
    )
    hash_labels = sorted({label for item in fixture_results for label in item.hash_binding_labels})
    hash_agent_hits = sorted({label for label in hash_labels if label in AGENT_RISK_LABELS})
    oasdiff_changed = sum(1 for item in fixture_results if item.oasdiff_changed)
    oasdiff_agent_hits = sorted({label for item in fixture_results for label in item.oasdiff_agent_label_hits})

    lines = [
        "# Agent Tool Contract Drift Baseline Probe",
        "",
        "Status: partial executed baseline comparison. This is not promotion-grade external validation.",
        "",
        "## Corpus",
        "",
        f"- Fixture pairs: {total_fixtures}",
        f"- Fixture pairs with Agent Tool Contract Drift holds: {candidate_hold_fixtures}",
        f"- Fixture-level Agent Tool Contract Drift risk labels: {candidate_risk_count}",
        f"- Agent Tool Contract Drift finding instances: {candidate_finding_count}",
        "- Fixture groups: synthetic, first-pass public, historical heldout public regression, second historical heldout public regression, third historical heldout public regression, ordinary public controls, adversarial controls.",
        "",
        "## Executed Baseline Results",
        "",
        "| Baseline | What Was Executed | Result | Agent-Risk Labels Emitted | Boundary |",
        "|---|---|---|---|---|",
        (
            f"| Generic descriptor diff | In-repo `generic_diff_baseline` over all fixture pairs | "
            f"Generic labels only: {', '.join(sorted({label for item in fixture_results for label in item.generic_diff_labels})) or '-'} | "
            f"{', '.join(generic_agent_hits) or 'none'} | Labels changes, not reapproval semantics. |"
        ),
        (
            f"| ArkForge-equivalent hash binding | Simulated approved SHA-256 over `tool_name + description`, then compared runtime descriptors | "
            f"Hash labels only: {', '.join(hash_labels) or '-'} | "
            f"{', '.join(hash_agent_hits) or 'none'} | Catches description drift and unapproved tools, not annotation/auth/schema risk semantics. |"
        ),
        (
            f"| oasdiff | Generated OpenAPI 3.1 projection for every before/after pair; ran `oasdiff diff -f json` | "
            f"Detected OpenAPI changes on {oasdiff_changed}/{total_fixtures} pairs | "
            f"{', '.join(oasdiff_agent_hits) or 'none'} | OpenAPI diff surface, not MCP/App agent-risk classifier. |"
        ),
        (
            f"| Spectral | Generated OpenAPI 3.1 projections plus `spectral:oas` ruleset via `@stoplight/spectral-rulesets` | "
            f"status={metadata['spectral_status']}, exit={metadata['spectral_exit_code']}, issues={metadata['spectral_issue_count']}, codes={', '.join(metadata['spectral_issue_codes']) or '-'} | "
            f"{', '.join(metadata['spectral_agent_label_hits']) or 'none'} | API governance linting, no custom MCP risk rules. |"
        ),
        (
            "| MCP Inspector | CLI help inspected with `npx -y @modelcontextprotocol/inspector --help` | "
            "Requires stdio/SSE/HTTP server config or URL | none | Live-server inspector, not static before/after diff classifier. |"
        ),
        (
            "| Vercel mcp-to-ai-sdk | CLI help inspected with `npx -y mcp-to-ai-sdk --help` | "
            "Requires MCP URL or server path and generates wrappers | none | Static tool generation, not descriptor-drift reapproval classifier. |"
        ),
        "",
        "## Fixture-Level Probe",
        "",
        "| Fixture | Agent Tool Contract Drift Risks | Generic Diff Labels | Hash Binding Labels | oasdiff Changed | oasdiff Agent Labels |",
        "|---|---|---|---|---|---|",
    ]
    for item in fixture_results:
        lines.append(
            f"| {item.fixture_id} | {', '.join(item.expected_candidate_risks) or '-'} | "
            f"{', '.join(item.generic_diff_labels) or '-'} | "
            f"{', '.join(item.hash_binding_labels) or '-'} | {item.oasdiff_changed} | "
            f"{', '.join(item.oasdiff_agent_label_hits) or '-'} |"
        )

    lines.extend(
        [
            "",
            "## Command Evidence",
            "",
            "| Command | Status | Exit | Notes |",
            "|---|---|---|---|",
        ]
    )
    seen: set[str] = set()
    for result in command_results:
        key = result.command
        if key in seen:
            continue
        seen.add(key)
        notes = (result.stderr_excerpt or result.stdout_excerpt or "-").replace("\n", " ")
        if len(notes) > 220:
            notes = notes[:220] + "..."
        lines.append(f"| `{result.command}` | {result.status} | {result.exit_code} | {notes} |")

    lines.extend(
        [
            "",
            "## Decision",
            "",
            "The executable probe strengthens Agent Tool Contract Drift's non-overlap claim against generic descriptor diffing, hash-binding, oasdiff, and uncustomized Spectral/OpenAPI governance because none emitted the Agent Tool Contract Drift agent-risk or reapproval labels on the current corpus.",
            "",
            "It does not close the survivor gate. The ArkForge-equivalent hash-binding baseline was only a local simulation of the blog pattern, not ArkForge's hosted attestation service; enterprise manual review was not measured; MCP Inspector and Vercel mcp-to-ai-sdk were only help/fit checks because their CLIs require live MCP servers or wrapper-generation inputs; and no maintainer/tool-builder has reacted to the holds.",
            "",
            "Current decision: keep Agent Tool Contract Drift at 79 / CONDITIONAL_RESEARCH_QUEUE. The next gate is manual-review comparison, a larger ordinary-descriptor FP/FN corpus, and maintainer/tool-builder reaction.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    parser.add_argument("--corpus", choices=SUPPORTED_CORPUS_IDS)
    parser.add_argument("--artifact-dir", default=str(ROOT / "reports" / "baseline_probe_artifacts"))
    parser.add_argument("--report", default=str(ROOT / "reports" / "baseline_probe.md"))
    parser.add_argument("--json", default=str(ROOT / "reports" / "baseline_probe.json"))
    args = parser.parse_args()

    if bool(args.fixture) == bool(args.corpus):
        raise SystemExit("Choose exactly one of --fixture or --corpus.")
    fixture_paths = (
        list(custom_fixture_paths(args.fixture)) if args.fixture else list(select_corpus(args.corpus).fixture_paths)
    )
    artifact_dir = Path(args.artifact_dir)
    fixture_results, command_results, metadata = probe_fixtures(artifact_dir, fixture_paths)
    command_results.extend(collect_tool_orientation_commands())

    report = render_report(fixture_results, command_results, metadata)
    Path(args.report).write_text(report)
    Path(args.json).write_text(
        json.dumps(
            {
                "fixture_results": [asdict(item) for item in fixture_results],
                "commands": [asdict(item) for item in command_results],
                "metadata": metadata,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"Wrote {args.report}")
    print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()
