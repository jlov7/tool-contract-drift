from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import select
import shlex
import subprocess
import time
from collections import Counter
from dataclasses import asdict, replace
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from tool_contract_drift.corpora import (
    PRIVATE_CANONICAL_CORPUS_ID,
    PUBLIC_REPRODUCTION_CORPUS_ID,
    SUPPORTED_CORPUS_IDS,
    canonical_fixture_source,
    custom_fixture_paths,
    select_corpus,
)
from tool_contract_drift.linter.tool_contract_drift import (
    generic_diff_baseline,
    lint_fixtures,
    load_fixtures,
    render_markdown,
    summarize,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURE_FILES = (
    "tool_descriptor_fixtures.json",
    "real_public_descriptor_changes.json",
    "heldout_public_descriptor_changes.json",
    "second_heldout_public_descriptor_changes.json",
    "third_heldout_public_descriptor_changes.json",
    "ordinary_public_descriptor_controls.json",
    "adversarial_descriptor_cases.json",
)
SEVERITY_RANK = {"medium": 1, "high": 2}
DEFAULT_POLICY_VERSION = "tool-contract-drift-v1"
DEFAULT_INFORMATION_URI = ""
DEFAULT_MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_MCP_PROTOCOL_VERSIONS = frozenset({"2025-06-18", "2025-11-25"})
SARIF_BOUNDARY_TEXT = "Review signal only; not a vulnerability finding or proof of runtime safety."
POLICY_PACKAGE = "tool_contract_drift.policy"
POLICY_FILE = "tool-contract-drift-v1.json"
CONFIG_EXAMPLE_FILE = "example-config.json"
PROVENANCE_PACKAGE = "provenance"
PUBLIC_FIXTURE_LOCK_FILE = "public_fixtures.lock.json"
PUBLIC_FIXTURE_LOCK_RESOURCE = "data/public_fixtures.lock.json"
PUBLIC_FIXTURE_LOCK = ROOT / "provenance" / "public_fixtures.lock.json"


def private_canonical_fixture_paths() -> list[Path]:
    try:
        return list(select_corpus(PRIVATE_CANONICAL_CORPUS_ID).fixture_paths)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def packaged_fixture_paths() -> list[Path]:
    try:
        return list(select_corpus(PUBLIC_REPRODUCTION_CORPUS_ID).fixture_paths)
    except (ModuleNotFoundError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def fixture_paths(paths: list[str] | None, corpus_id: str | None = None) -> list[Path]:
    if paths and corpus_id:
        raise SystemExit("Choose either explicit --fixture paths or --corpus, not both.")
    if paths:
        try:
            return list(custom_fixture_paths(paths))
        except (RuntimeError, ValueError) as exc:
            raise SystemExit(str(exc)) from exc
    if not corpus_id:
        raise SystemExit(
            "Corpus selection is required. Pass explicit --fixture paths or --corpus "
            f"{{{','.join(SUPPORTED_CORPUS_IDS)}}}."
        )
    try:
        return list(select_corpus(corpus_id).fixture_paths)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def load_fixture_records(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        for fixture in load_fixtures(path):
            record = dict(fixture)
            record["_source_file"] = canonical_fixture_source(path)
            records.append(record)
    return records


def corpus_metadata(args: argparse.Namespace, fixture_count: int) -> dict[str, Any]:
    corpus_id = getattr(args, "corpus", None)
    if getattr(args, "builtin_corpus", False):
        corpus_id = PUBLIC_REPRODUCTION_CORPUS_ID
    if corpus_id:
        selection = select_corpus(corpus_id)
        return {
            **selection.as_dict(),
            "fixture_count": fixture_count,
            "evidence_boundary": (
                "private canonical research corpus; includes blocker-marked source records"
                if corpus_id == PRIVATE_CANONICAL_CORPUS_ID
                else (
                    "fully synthetic public-package reproduction corpus; the separate source-metadata "
                    "inventory contains no source-derived descriptor bytes and grants no permission"
                )
            ),
        }
    return {
        "id": "single-descriptor-pair" if getattr(args, "before", None) else "custom-explicit-fixtures",
        "expected_fixture_count": None,
        "content_manifest_sha256": None,
        "availability": "caller-supplied",
        "fixture_count": fixture_count,
        "evidence_boundary": "caller-supplied input; not a canonical corpus result",
    }


def annotate_markdown_corpus(markdown: str, metadata: dict[str, Any]) -> str:
    lines = markdown.splitlines()
    note = (
        f"Corpus identity: `{metadata['id']}`; fixtures: {metadata['fixture_count']}; "
        f"boundary: {metadata['evidence_boundary']}."
    )
    if lines:
        lines[1:1] = ["", note]
    return "\n".join(lines).rstrip() + "\n"


def descriptor_pair_record(before_path: str, after_path: str, fixture_id: str) -> dict[str, Any]:
    before = json.loads(Path(before_path).read_text())
    after = json.loads(Path(after_path).read_text())
    return {
        "id": fixture_id,
        "before": before,
        "after": after,
        "_source_file": f"{before_path} -> {after_path}",
        "_before_path": before_path,
        "_after_path": after_path,
    }


def source_type_for_fixture(fixture: dict[str, Any]) -> str:
    return "public_commit" if fixture.get("url") else "synthetic"


def split_for_source_file(source_file: str) -> str:
    if source_file == "fixtures/tool_descriptor_fixtures.json":
        return "dev_regression"
    if source_file in {
        "fixtures/heldout_public_descriptor_changes.json",
        "fixtures/second_heldout_public_descriptor_changes.json",
        "fixtures/third_heldout_public_descriptor_changes.json",
    }:
        return "historical_heldout_regression"
    if source_file == "fixtures/ordinary_public_descriptor_controls.json":
        return "ordinary_control_regression"
    if source_file == "fixtures/real_public_descriptor_changes.json":
        return "public_regression"
    if source_file == "fixtures/adversarial_descriptor_cases.json":
        return "adversarial_regression"
    return "custom"


def fixtures_for_lint(args: argparse.Namespace) -> list[dict[str, Any]]:
    selected_modes = sum(
        (
            bool(args.before or args.after),
            bool(args.fixture),
            bool(getattr(args, "corpus", None)),
            bool(getattr(args, "builtin_corpus", False)),
        )
    )
    if selected_modes > 1:
        raise SystemExit("Choose exactly one input mode: --before/--after, --fixture, --corpus, or --builtin-corpus.")
    if args.before or args.after:
        if not args.before or not args.after:
            raise SystemExit("--before and --after must be supplied together.")
        return [descriptor_pair_record(args.before, args.after, args.id)]
    if args.fixture or getattr(args, "corpus", None):
        return load_fixture_records(fixture_paths(args.fixture, getattr(args, "corpus", None)))
    if getattr(args, "builtin_corpus", False):
        return load_fixture_records(packaged_fixture_paths())
    raise SystemExit("lint requires --before/--after, --fixture, --corpus, or explicit --builtin-corpus.")


def fixtures_for_lint_legacy(args: argparse.Namespace) -> list[dict[str, Any]]:
    """Load fixtures for compatibility callers while requiring an explicit corpus identity."""
    if args.before or args.after:
        if not args.before or not args.after:
            raise SystemExit("--before and --after must be supplied together.")
        return [descriptor_pair_record(args.before, args.after, args.id)]
    return load_fixture_records(fixture_paths(args.fixture, getattr(args, "corpus", None)))


def finding_dicts(fixtures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [asdict(finding) for finding in lint_fixtures(fixtures)]


def generic_label_rows(fixture: dict[str, Any]) -> list[dict[str, Any]]:
    return [asdict(diff) for diff in generic_diff_baseline(fixture)]


def descriptor_diff(fixture: dict[str, Any], display_id: str | None = None) -> str:
    before = json.dumps(fixture["before"], indent=2, sort_keys=True).splitlines()
    after = json.dumps(fixture["after"], indent=2, sort_keys=True).splitlines()
    diff_id = display_id or fixture["id"]
    return "\n".join(
        difflib.unified_diff(
            before,
            after,
            fromfile=f"{diff_id}:before",
            tofile=f"{diff_id}:after",
            lineterm="",
        )
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def load_default_policy_document() -> dict[str, Any]:
    source_policy = ROOT / "policy" / POLICY_FILE
    if source_policy.exists():
        return json.loads(source_policy.read_text())
    try:
        return json.loads(resources.files(POLICY_PACKAGE).joinpath(POLICY_FILE).read_text())
    except ModuleNotFoundError:
        raise SystemExit("Built-in Agent Tool Contract Drift policy is unavailable.")


def known_policy_labels() -> set[str]:
    policy = load_default_policy_document()
    return {label["id"] for label in policy.get("labels", [])}


def load_lint_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {
            "policy_version": DEFAULT_POLICY_VERSION,
            "enabled_rules": None,
            "disabled_rules": [],
            "severity_overrides": {},
            "suppressions": [],
            "sarif": {},
            "_config_path": None,
        }
    config_path = Path(path)
    try:
        payload = json.loads(config_path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON config {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("Config must be a JSON object.")
    allowed_keys = {"policy_version", "enabled_rules", "disabled_rules", "severity_overrides", "suppressions", "sarif"}
    unknown_keys = sorted(set(payload) - allowed_keys)
    if unknown_keys:
        raise SystemExit(f"Unknown config field(s): {', '.join(unknown_keys)}")
    config = {
        "policy_version": payload.get("policy_version", DEFAULT_POLICY_VERSION),
        "enabled_rules": payload.get("enabled_rules"),
        "disabled_rules": payload.get("disabled_rules", []),
        "severity_overrides": payload.get("severity_overrides", {}),
        "suppressions": payload.get("suppressions", []),
        "sarif": payload.get("sarif", {}),
        "_config_path": str(config_path),
    }
    validate_lint_config(config)
    return config


def validate_lint_config(config: dict[str, Any]) -> None:
    labels = known_policy_labels()
    if config["policy_version"] != DEFAULT_POLICY_VERSION:
        raise SystemExit(f"Unsupported policy_version {config['policy_version']!r}; expected {DEFAULT_POLICY_VERSION!r}.")
    enabled = config["enabled_rules"]
    if enabled is not None and not isinstance(enabled, list):
        raise SystemExit("enabled_rules must be null or a list of rule ids.")
    if enabled is not None and any(not isinstance(rule, str) for rule in enabled):
        raise SystemExit("enabled_rules must contain only rule ids.")
    for field in ("disabled_rules", "suppressions"):
        if not isinstance(config[field], list):
            raise SystemExit(f"{field} must be a list.")
    if any(not isinstance(rule, str) for rule in config["disabled_rules"]):
        raise SystemExit("disabled_rules must contain only rule ids.")
    if not isinstance(config["severity_overrides"], dict):
        raise SystemExit("severity_overrides must be an object.")
    if not isinstance(config["sarif"], dict):
        raise SystemExit("sarif must be an object.")
    unknown_sarif = sorted(set(config["sarif"]) - {"information_uri", "semantic_version"})
    if unknown_sarif:
        raise SystemExit(f"Unknown sarif config field(s): {', '.join(unknown_sarif)}")
    configured_rules = set(config["disabled_rules"])
    if enabled is not None:
        configured_rules.update(enabled)
    configured_rules.update(config["severity_overrides"])
    for suppression in config["suppressions"]:
        if not isinstance(suppression, dict):
            raise SystemExit("Each suppression must be an object.")
        unknown_suppression = sorted(set(suppression) - {"fixture_id", "tool_name", "risk", "reason"})
        if unknown_suppression:
            raise SystemExit(f"Unknown suppression field(s): {', '.join(unknown_suppression)}")
        if not suppression.get("reason"):
            raise SystemExit("Each suppression must include a non-empty reason.")
        if "risk" in suppression:
            configured_rules.add(str(suppression["risk"]))
    unknown = sorted(rule for rule in configured_rules if rule not in labels)
    if unknown:
        raise SystemExit(f"Unknown rule id(s) in config: {', '.join(unknown)}")
    invalid_severities = sorted(
        rule for rule, severity in config["severity_overrides"].items() if severity not in SEVERITY_RANK
    )
    if invalid_severities:
        raise SystemExit(f"Invalid severity override for rule id(s): {', '.join(invalid_severities)}")


def apply_lint_config(findings: list[Any], config: dict[str, Any]) -> tuple[list[Any], dict[str, Any]]:
    enabled = set(config["enabled_rules"]) if config["enabled_rules"] is not None else None
    disabled = set(config["disabled_rules"])
    severity_overrides = config["severity_overrides"]
    filtered = []
    suppressed = 0
    for finding in findings:
        if enabled is not None and finding.risk not in enabled:
            continue
        if finding.risk in disabled:
            continue
        if is_suppressed(finding, config["suppressions"]):
            suppressed += 1
            continue
        severity = severity_overrides.get(finding.risk)
        filtered.append(replace(finding, severity=severity) if severity else finding)
    metadata = {
        "version": config["policy_version"],
        "config_path": config["_config_path"],
        "enabled_rules": sorted(enabled) if enabled is not None else None,
        "disabled_rules": sorted(disabled),
        "severity_overrides": dict(sorted(severity_overrides.items())),
        "suppressed_findings": suppressed,
    }
    return filtered, metadata


def is_suppressed(finding: Any, suppressions: list[dict[str, Any]]) -> bool:
    for suppression in suppressions:
        if suppression_matches(finding, suppression):
            return True
    return False


def suppression_matches(finding: Any, suppression: dict[str, Any]) -> bool:
    for key, attribute in (("risk", "risk"), ("fixture_id", "fixture_id"), ("tool_name", "tool_name")):
        value = suppression.get(key)
        if value is not None and str(value) != str(getattr(finding, attribute)):
            return False
    return any(key in suppression for key in ("risk", "fixture_id", "tool_name"))


def render_sarif(fixtures: list[dict[str, Any]], findings: list[Any], config: dict[str, Any] | None = None) -> str:
    config = config or {}
    sarif_config = config.get("sarif", {})
    policy_version = config.get("policy_version", DEFAULT_POLICY_VERSION)
    corpus = config.get("_corpus", {})
    information_uri = sarif_config.get("information_uri", DEFAULT_INFORMATION_URI)
    semantic_version = sarif_config.get("semantic_version", "0.1.0a0")
    fixture_lookup = {fixture["id"]: fixture for fixture in fixtures}
    rule_ids = sorted({finding.risk for finding in findings})
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": rule_id.replace("_", " ")},
            "fullDescription": {
                "text": f"Agent-facing tool descriptor drift label requiring review or reapproval. {SARIF_BOUNDARY_TEXT}"
            },
            "defaultConfiguration": {"level": "error" if "destructive" in rule_id or "auth" in rule_id else "warning"},
            "help": {
                "text": (
                    "Use this as a descriptor-review cue. Confirm actual tool behavior, authorization, "
                    f"and reviewer policy before acting. {SARIF_BOUNDARY_TEXT}"
                )
            },
        }
        for rule_id in rule_ids
    ]
    results = []
    for finding in findings:
        fixture = fixture_lookup.get(finding.fixture_id, {})
        uri = sarif_uri(fixture.get("_before_path") or fixture.get("_source_file") or f"{finding.fixture_id}.json")
        fingerprint = stable_fingerprint(
            finding.fixture_id,
            finding.tool_name,
            finding.risk,
            tuple(finding.evidence),
        )
        results.append(
            {
                "ruleId": finding.risk,
                "ruleIndex": rule_indexes[finding.risk],
                "level": "error" if finding.severity == "high" else "warning",
                "message": {
                    "text": (
                        f"{finding.tool_name}: {finding.reason} "
                        f"(fixture={finding.fixture_id}, severity={finding.severity}; {SARIF_BOUNDARY_TEXT})"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint,
                    "toolContractDrift/v1": fingerprint,
                },
                "properties": {
                    "fixture_id": finding.fixture_id,
                    "tool_name": finding.tool_name,
                    "severity": finding.severity,
                    "reapproval_required": finding.reapproval_required,
                    "generic_baseline_labels": list(finding.generic_baseline_labels),
                    "evidence": list(finding.evidence),
                },
            }
        )
    driver = {
        "name": "tool-contract-drift",
        "semanticVersion": semantic_version,
        "properties": {
            "policy_version": policy_version,
            "corpus_id": corpus.get("id", "custom-explicit-fixtures"),
            "corpus_manifest_sha256": corpus.get("content_manifest_sha256"),
        },
        "rules": rules,
    }
    if information_uri:
        driver["informationUri"] = information_uri
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "automationDetails": {"id": f"tool-contract-drift/{policy_version.removeprefix('tool-contract-drift-')}"},
                "tool": {
                    "driver": driver
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sarif_uri(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        for base in (Path.cwd(), ROOT):
            try:
                return str(path.relative_to(base))
            except ValueError:
                continue
    return value


def stable_fingerprint(fixture_id: str, tool_name: str, risk: str, evidence: tuple[str, ...]) -> str:
    payload = json.dumps(
        {
            "fixture_id": fixture_id,
            "tool_name": tool_name,
            "risk": risk,
            "evidence": evidence,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fail_on_findings(findings: list[Any], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    if fail_on == "any":
        return bool(findings)
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)


def run_lint(args: argparse.Namespace) -> int:
    fixtures = fixtures_for_lint(args)
    selected_corpus = corpus_metadata(args, len(fixtures))
    config = load_lint_config(args.config)
    config["_corpus"] = selected_corpus
    findings, policy_metadata = apply_lint_config(lint_fixtures(fixtures), config)
    if args.format == "json":
        payload = {
            "summary": summarize(findings),
            "fixture_count": len(fixtures),
            "corpus": selected_corpus,
            "policy": policy_metadata,
            "findings": [asdict(finding) for finding in findings],
        }
        output = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    elif args.format == "sarif":
        output = render_sarif(fixtures, findings, config)
    else:
        output = annotate_markdown_corpus(render_markdown(findings), selected_corpus)

    if args.output:
        write_text(Path(args.output), output)
    else:
        print(output, end="")
    return 1 if fail_on_findings(findings, args.fail_on) else 0


def normalize_mcp_tool(tool: dict[str, Any]) -> dict[str, Any]:
    if "name" not in tool:
        raise SystemExit("MCP tools/list returned a tool without a name.")
    if not isinstance(tool["name"], str) or not tool["name"]:
        raise SystemExit("MCP tools/list returned a tool with an invalid name.")
    if "inputSchema" not in tool and "input_schema" not in tool:
        raise SystemExit(f"MCP tool {tool['name']!r} omitted required inputSchema.")
    for key, expected_type in (("annotations", dict), ("icons", list), ("execution", dict), ("_meta", dict)):
        if key in tool and not isinstance(tool[key], expected_type):
            raise SystemExit(f"MCP tool {tool['name']!r} returned invalid {key}.")
    normalized: dict[str, Any] = {
        "name": tool["name"],
        "description": tool.get("description", ""),
    }
    if "title" in tool:
        normalized["title"] = tool["title"]
    if "inputSchema" in tool:
        normalized["input_schema"] = tool["inputSchema"]
    elif "input_schema" in tool:
        normalized["input_schema"] = tool["input_schema"]
    if "outputSchema" in tool:
        normalized["output_schema"] = tool["outputSchema"]
    elif "output_schema" in tool:
        normalized["output_schema"] = tool["output_schema"]
    if "annotations" in tool:
        normalized["annotations"] = tool["annotations"]
    for key in ("icons", "execution", "_meta"):
        if key in tool:
            normalized[key] = tool[key]

    security_schemes = _mcp_security_schemes(tool)
    if security_schemes is not None:
        normalized["security_schemes"] = security_schemes

    auth = tool.get("auth") if isinstance(tool.get("auth"), dict) else {}
    scopes = sorted(set(_security_scheme_scopes(security_schemes)) | set(auth.get("scopes", [])))
    if auth or scopes:
        normalized["auth"] = dict(auth)
        if scopes:
            normalized["auth"]["scopes"] = scopes

    output_template = _mcp_output_template(tool)
    if output_template is not None:
        normalized["output_template"] = output_template

    known_fields = {
        "_meta",
        "annotations",
        "auth",
        "description",
        "execution",
        "icons",
        "inputSchema",
        "input_schema",
        "name",
        "outputSchema",
        "output_schema",
        "output_template",
        "securitySchemes",
        "title",
    }
    extensions = {key: value for key, value in tool.items() if key not in known_fields}
    if extensions:
        normalized["extensions"] = extensions
    return normalized


def _mcp_security_schemes(tool: dict[str, Any]) -> list[dict[str, Any]] | None:
    direct = tool.get("securitySchemes")
    meta = tool.get("_meta") if isinstance(tool.get("_meta"), dict) else {}
    mirrored = meta.get("securitySchemes")
    if "securitySchemes" in tool and not isinstance(direct, list):
        raise SystemExit(f"MCP tool {tool['name']!r} returned invalid securitySchemes.")
    if "securitySchemes" in meta and not isinstance(mirrored, list):
        raise SystemExit(f"MCP tool {tool['name']!r} returned invalid _meta.securitySchemes.")
    if isinstance(direct, list):
        if any(not isinstance(scheme, dict) for scheme in direct):
            raise SystemExit(f"MCP tool {tool['name']!r} returned a non-object security scheme.")
        return direct
    if isinstance(mirrored, list):
        if any(not isinstance(scheme, dict) for scheme in mirrored):
            raise SystemExit(f"MCP tool {tool['name']!r} returned a non-object _meta security scheme.")
        return mirrored
    return None


def _security_scheme_scopes(security_schemes: list[dict[str, Any]] | None) -> list[str]:
    scopes: set[str] = set()
    for scheme in security_schemes or []:
        if not isinstance(scheme, dict):
            continue
        values = scheme.get("scopes", [])
        if isinstance(values, list):
            scopes.update(value for value in values if isinstance(value, str))
    return sorted(scopes)


def _mcp_output_template(tool: dict[str, Any]) -> str | None:
    meta = tool.get("_meta") if isinstance(tool.get("_meta"), dict) else {}
    ui = meta.get("ui") if isinstance(meta.get("ui"), dict) else {}
    standard = ui.get("resourceUri")
    compatibility_alias = meta.get("openai/outputTemplate")
    legacy = tool.get("output_template")
    for value in (standard, compatibility_alias, legacy):
        if isinstance(value, str) and value:
            return value
    return None


def mcp_request(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    return payload


def write_mcp_message(proc: subprocess.Popen[str], payload: dict[str, Any]) -> None:
    if proc.stdin is None:
        raise SystemExit("MCP server stdin is unavailable.")
    proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def read_mcp_response(proc: subprocess.Popen[str], expected_id: int, timeout_seconds: float) -> dict[str, Any]:
    if proc.stdout is None:
        raise SystemExit("MCP server stdout is unavailable.")
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SystemExit(f"Timed out waiting for MCP response id {expected_id}.")
        ready, _, _ = select.select([proc.stdout], [], [], remaining)
        if not ready:
            continue
        line = proc.stdout.readline()
        if line == "":
            raise SystemExit(f"MCP server exited before response id {expected_id}.")
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"MCP server wrote non-JSON stdout line: {line.strip()}") from exc
        if payload.get("id") != expected_id:
            continue
        if "error" in payload:
            raise SystemExit(f"MCP request {expected_id} failed: {payload['error']}")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise SystemExit(f"MCP response {expected_id} did not contain an object result.")
        return payload


def capture_mcp_stdio_tools(command: str, protocol_version: str, timeout_seconds: float) -> dict[str, Any]:
    if protocol_version not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        supported = ", ".join(sorted(SUPPORTED_MCP_PROTOCOL_VERSIONS))
        raise SystemExit(f"Unsupported requested MCP protocol version {protocol_version!r}; supported: {supported}.")
    argv = shlex.split(command)
    if not argv:
        raise SystemExit("--stdio must contain a command to launch.")
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        initialize = mcp_request(
            1,
            "initialize",
            {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "tool-contract-drift-capture", "version": "0.1.0a0"},
            },
        )
        write_mcp_message(proc, initialize)
        init_response = read_mcp_response(proc, 1, timeout_seconds)
        negotiated_version = init_response["result"].get("protocolVersion")
        if negotiated_version not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_MCP_PROTOCOL_VERSIONS))
            raise SystemExit(
                f"MCP server negotiated unsupported protocol version {negotiated_version!r}; supported: {supported}."
            )
        write_mcp_message(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        request_id = 2
        while True:
            params = {"cursor": cursor} if cursor else None
            write_mcp_message(proc, mcp_request(request_id, "tools/list", params))
            response = read_mcp_response(proc, request_id, timeout_seconds)
            result = response["result"]
            page_tools = result.get("tools", [])
            if not isinstance(page_tools, list):
                raise SystemExit("MCP tools/list result.tools must be a list.")
            tools.extend(normalize_mcp_tool(tool) for tool in page_tools)
            next_cursor = result.get("nextCursor")
            if not next_cursor:
                break
            if not isinstance(next_cursor, str):
                raise SystemExit("MCP tools/list nextCursor must be a string when present.")
            cursor = next_cursor
            request_id += 1
        return {
            "schema_version": "tool-contract-drift-descriptor-v2",
            "source": {
                "transport": "mcp_stdio",
                "command": command,
                "protocol_version_requested": protocol_version,
                "protocol_version_negotiated": negotiated_version,
                "server_info": init_response["result"].get("serverInfo", {}),
            },
            "tools": tools,
        }
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


def run_capture(args: argparse.Namespace) -> int:
    descriptor = capture_mcp_stdio_tools(args.stdio, args.protocol_version, args.timeout)
    output = json.dumps(descriptor, indent=2, sort_keys=True) + "\n"
    if args.output:
        write_text(Path(args.output), output)
    else:
        print(output, end="")
    return 0


def corpus_manifest(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    for fixture in fixtures:
        findings = lint_fixtures([fixture])
        generic_rows = generic_diff_baseline(fixture)
        rows.append(
            {
                "fixture_id": fixture["id"],
                "source_file": fixture.get("_source_file", ""),
                "source": fixture.get("source", ""),
                "url": fixture.get("url", ""),
                "source_type": source_type_for_fixture(fixture),
                "corpus_split": split_for_source_file(fixture.get("_source_file", "")),
                "before_tool_count": len(fixture["before"].get("tools", [])),
                "after_tool_count": len(fixture["after"].get("tools", [])),
                "generic_label_count": sum(len(row.labels) for row in generic_rows),
                "candidate_finding_count": len(findings),
                "candidate_risks": sorted({finding.risk for finding in findings}),
                "expected_risks": fixture.get("expected_risks", []),
                "label_status": fixture.get("label_status", ""),
                "label_rationale": fixture.get("label_rationale", ""),
                "control_or_quiet_case": not findings,
            }
        )
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        group = row["source_file"]
        item = grouped.setdefault(
            group,
            {
                "source_file": group,
                "fixture_count": 0,
                "hold_fixture_count": 0,
                "quiet_fixture_count": 0,
                "finding_count": 0,
            },
        )
        item["fixture_count"] += 1
        item["finding_count"] += row["candidate_finding_count"]
        if row["candidate_finding_count"]:
            item["hold_fixture_count"] += 1
        else:
            item["quiet_fixture_count"] += 1
    return {
        "summary": {
            "fixture_count": len(rows),
            "hold_fixture_count": sum(1 for row in rows if row["candidate_finding_count"]),
            "quiet_fixture_count": sum(1 for row in rows if not row["candidate_finding_count"]),
            "finding_count": sum(row["candidate_finding_count"] for row in rows),
            "public_commit_backed_fixture_count": sum(1 for row in rows if row["url"]),
        },
        "groups": list(grouped.values()),
        "fixtures": rows,
        "limitations": [
            "Fixture set is intentionally small and curated.",
            "Rules were iterated after inspecting failures, so this is not an unbiased benchmark.",
            "Manual reviewer lift is not established until external responses are scored.",
            "Configured policy tools may absorb some value; this manifest records current evidence only.",
        ],
    }


def render_corpus_manifest_markdown(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    lines = [
        "# Agent Tool Contract Drift Corpus Manifest",
        "",
        "Status: evidence manifest for the current local corpus. This is not an unbiased benchmark release.",
        "",
        "## Summary",
        "",
        f"- Fixture pairs: {summary['fixture_count']}",
        f"- Fixtures with Agent Tool Contract Drift holds: {summary['hold_fixture_count']}",
        f"- Quiet/control fixtures: {summary['quiet_fixture_count']}",
        f"- Agent Tool Contract Drift finding instances: {summary['finding_count']}",
        f"- Public commit-backed fixtures: {summary['public_commit_backed_fixture_count']}",
        "",
        "## Fixture Groups",
        "",
        "| Source File | Fixtures | Hold Fixtures | Quiet Fixtures | Findings |",
        "|---|---:|---:|---:|---:|",
    ]
    for group in manifest["groups"]:
        lines.append(
            f"| `{group['source_file']}` | {group['fixture_count']} | {group['hold_fixture_count']} | "
            f"{group['quiet_fixture_count']} | {group['finding_count']} |"
        )
    lines.extend(
        [
            "",
            "## Fixtures",
            "",
            "| Fixture | Source File | Split | Source Type | Source | URL | Expected Risks | Agent Tool Contract Drift Risks | Findings | Quiet |",
            "|---|---|---|---|---|---|---|---|---:|---|",
        ]
    )
    for row in manifest["fixtures"]:
        risks = ", ".join(row["candidate_risks"]) or "-"
        expected = ", ".join(row["expected_risks"]) or "-"
        url = row["url"] or "-"
        source = row["source"] or "-"
        lines.append(
            f"| {row['fixture_id']} | `{row['source_file']}` | {row['corpus_split']} | {row['source_type']} | "
            f"{source} | {url} | {expected} | {risks} | "
            f"{row['candidate_finding_count']} | {row['control_or_quiet_case']} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in manifest["limitations"])
    return "\n".join(lines) + "\n"


def run_corpus_manifest(args: argparse.Namespace) -> int:
    fixtures = load_fixture_records(fixture_paths(args.fixture, args.corpus))
    manifest = corpus_manifest(fixtures)
    manifest["corpus"] = corpus_metadata(args, len(fixtures))
    if args.output:
        write_text(Path(args.output), annotate_markdown_corpus(render_corpus_manifest_markdown(manifest), manifest["corpus"]))
    if args.json:
        write_text(Path(args.json), json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if not args.output and not args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def run_configured_baselines(args: argparse.Namespace) -> int:
    from tool_contract_drift.baselines.configured_substitutes import render_markdown as render_configured_markdown
    from tool_contract_drift.baselines.configured_substitutes import run_bakeoff, summarize_bakeoff

    paths = fixture_paths(args.fixture, args.corpus)
    results = run_bakeoff(paths)
    selected_corpus = corpus_metadata(args, len(results))
    payload = {
        "corpus": selected_corpus,
        "summary": summarize_bakeoff(results),
        "results": [asdict(item) for item in results],
    }
    if args.output:
        write_text(
            Path(args.output),
            annotate_markdown_corpus(render_configured_markdown(results), selected_corpus),
        )
    if args.json:
        write_text(
            Path(args.json),
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
    if not args.output and not args.json:
        print(json.dumps(payload, indent=2))
    return 0


def run_oasdiff_adapter(args: argparse.Namespace) -> int:
    from tool_contract_drift.baselines.baseline_probe import descriptor_to_openapi
    from tool_contract_drift.baselines.baseline_probe import run_command
    from tool_contract_drift.baselines.configured_substitutes import oasdiff_risk_mapper_finding_keys, policy_finding_keys
    from tool_contract_drift.adapters.oasdiff import find_oasdiff_command
    from tool_contract_drift.adapters.oasdiff import run_oasdiff_descriptor_pair
    from tool_contract_drift.adapters.oasdiff import parse_oasdiff_json
    from tool_contract_drift.baselines.oasdiff_adapter_probe import OasdiffAdapterResult
    from tool_contract_drift.baselines.oasdiff_adapter_probe import oasdiff_version_metadata
    from tool_contract_drift.baselines.oasdiff_adapter_probe import render_markdown as render_oasdiff_adapter_markdown
    from tool_contract_drift.baselines.oasdiff_adapter_probe import run_adapter_probe, summarize_results

    if args.before or args.after:
        if not args.before or not args.after:
            raise SystemExit("--before and --after must be supplied together.")
        oasdiff = find_oasdiff_command()
        version_result = run_command([oasdiff, "--version"], ROOT) if oasdiff else None
        fixture = descriptor_pair_record(args.before, args.after, args.id)
        candidate_risks = tuple(sorted({finding.risk for finding in lint_fixtures([fixture])}))
        candidate_finding_keys = policy_finding_keys(fixture)
        before_openapi = descriptor_to_openapi(fixture["before"], f"{args.id} before")
        after_openapi = descriptor_to_openapi(fixture["after"], f"{args.id} after")
        adapter_run = run_oasdiff_descriptor_pair(fixture["before"], fixture["after"], args.id, oasdiff)
        parsed_oasdiff = parse_oasdiff_json(adapter_run.stdout_excerpt)
        adapter_finding_keys = (
            oasdiff_risk_mapper_finding_keys(parsed_oasdiff, before_openapi, after_openapi)
            if parsed_oasdiff is not None
            else ()
        )
        results = [
            OasdiffAdapterResult(
                fixture_id=args.id,
                source_file=fixture["_source_file"],
                candidate_risks=candidate_risks,
                candidate_finding_keys=candidate_finding_keys,
                adapter_risks=adapter_run.adapter_risks,
                adapter_finding_keys=adapter_finding_keys,
                exact_match=adapter_run.adapter_risks == candidate_risks,
                instance_exact_match=adapter_finding_keys == candidate_finding_keys,
                oasdiff_status=adapter_run.oasdiff_status,
                oasdiff_exit_code=adapter_run.oasdiff_exit_code,
                oasdiff_changed=adapter_run.oasdiff_changed,
                stderr_excerpt=adapter_run.stderr_excerpt,
            )
        ]
        metadata = {
            "oasdiff_available": adapter_run.oasdiff_available,
            "oasdiff_command": "oasdiff" if adapter_run.oasdiff_available else "",
            **oasdiff_version_metadata(oasdiff, version_result),
        }
    else:
        paths = fixture_paths(args.fixture, args.corpus)
        results, metadata = run_adapter_probe(paths)
    selected_corpus = corpus_metadata(args, len(results))
    payload = {
        "corpus": selected_corpus,
        "summary": summarize_results(results, metadata),
        "results": [asdict(item) for item in results],
    }
    if args.output:
        write_text(
            Path(args.output),
            annotate_markdown_corpus(render_oasdiff_adapter_markdown(results, metadata), selected_corpus),
        )
    if args.json:
        write_text(Path(args.json), json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if not args.output and not args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def validate_fixture_records(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    labels = known_policy_labels()
    issues: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for fixture in fixtures:
        fixture_id = fixture.get("id", "")
        source_file = fixture.get("_source_file", "")
        if not isinstance(fixture_id, str) or not fixture_id:
            issues.append(validation_issue("error", source_file, fixture_id, "id", "Fixture id must be a non-empty string."))
            fixture_id = "<missing>"
        if fixture_id in seen_ids:
            issues.append(validation_issue("error", source_file, fixture_id, "id", "Fixture id must be unique across loaded files."))
        seen_ids.add(fixture_id)
        for side in ("before", "after"):
            validate_descriptor(fixture, side, issues)
        expected = fixture.get("expected_risks")
        if not isinstance(expected, list) or any(not isinstance(item, str) for item in expected):
            issues.append(validation_issue("error", source_file, fixture_id, "expected_risks", "Expected risks must be a list of strings."))
        else:
            unknown = sorted(set(expected) - labels)
            if unknown:
                issues.append(
                    validation_issue(
                        "error",
                        source_file,
                        fixture_id,
                        "expected_risks",
                        f"Unknown expected risk label(s): {', '.join(unknown)}.",
                    )
                )
            if expected != sorted(expected):
                issues.append(validation_issue("warning", source_file, fixture_id, "expected_risks", "Expected risks should be sorted for stable diffs."))
        for field in ("label_status", "label_rationale"):
            if not isinstance(fixture.get(field), str) or not fixture.get(field, "").strip():
                issues.append(validation_issue("error", source_file, fixture_id, field, f"{field} must be a non-empty string."))
        if fixture.get("url") and not fixture.get("source"):
            issues.append(validation_issue("error", source_file, fixture_id, "source", "Public URL fixtures must include source."))
        if fixture.get("source") and "@" in str(fixture.get("source")) and fixture.get("url"):
            commit = str(fixture["source"]).rsplit("@", 1)[1]
            if commit and commit not in str(fixture["url"]):
                issues.append(validation_issue("warning", source_file, fixture_id, "url", "URL does not contain the source commit id."))
    errors = [issue for issue in issues if issue["severity"] == "error"]
    warnings = [issue for issue in issues if issue["severity"] == "warning"]
    return {
        "summary": {
            "fixture_count": len(fixtures),
            "error_count": len(errors),
            "warning_count": len(warnings),
            "public_commit_fixture_count": sum(1 for fixture in fixtures if fixture.get("url")),
            "synthetic_fixture_count": sum(1 for fixture in fixtures if not fixture.get("url")),
        },
        "issues": issues,
    }


def validate_descriptor(fixture: dict[str, Any], side: str, issues: list[dict[str, Any]]) -> None:
    fixture_id = fixture.get("id", "")
    source_file = fixture.get("_source_file", "")
    descriptor = fixture.get(side)
    if not isinstance(descriptor, dict):
        issues.append(validation_issue("error", source_file, fixture_id, side, f"{side} descriptor must be an object."))
        return
    tools = descriptor.get("tools")
    if not isinstance(tools, list):
        issues.append(validation_issue("error", source_file, fixture_id, f"{side}.tools", "Descriptor tools must be a list."))
        return
    names = []
    for index, tool in enumerate(tools):
        path = f"{side}.tools[{index}]"
        if not isinstance(tool, dict):
            issues.append(validation_issue("error", source_file, fixture_id, path, "Tool must be an object."))
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            issues.append(validation_issue("error", source_file, fixture_id, f"{path}.name", "Tool name must be a non-empty string."))
        else:
            names.append(name)
        for field in ("input_schema", "output_schema", "annotations", "auth"):
            if field in tool and not isinstance(tool[field], dict):
                issues.append(validation_issue("error", source_file, fixture_id, f"{path}.{field}", f"{field} must be an object when present."))
        if "description" in tool and not isinstance(tool["description"], str):
            issues.append(validation_issue("error", source_file, fixture_id, f"{path}.description", "description must be a string when present."))
        if "output_template" in tool and not isinstance(tool["output_template"], str):
            issues.append(validation_issue("error", source_file, fixture_id, f"{path}.output_template", "output_template must be a string when present."))
        scopes = tool.get("auth", {}).get("scopes", []) if isinstance(tool.get("auth", {}), dict) else []
        if scopes and (not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes)):
            issues.append(validation_issue("error", source_file, fixture_id, f"{path}.auth.scopes", "auth.scopes must be a list of strings."))
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        issues.append(validation_issue("error", source_file, fixture_id, f"{side}.tools", f"Duplicate tool name(s): {', '.join(duplicates)}."))


def validation_issue(severity: str, source_file: str, fixture_id: str, field: str, message: str) -> dict[str, str]:
    return {
        "severity": severity,
        "source_file": source_file,
        "fixture_id": fixture_id,
        "field": field,
        "message": message,
    }


def render_validation_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Agent Tool Contract Drift Fixture Validation",
        "",
        f"- Fixtures: {summary['fixture_count']}",
        f"- Errors: {summary['error_count']}",
        f"- Warnings: {summary['warning_count']}",
        f"- Public commit fixtures: {summary['public_commit_fixture_count']}",
        f"- Synthetic fixtures: {summary['synthetic_fixture_count']}",
        "",
        "## Issues",
        "",
    ]
    if not result["issues"]:
        lines.append("- -")
    else:
        for issue in result["issues"]:
            lines.append(
                f"- {issue['severity']}: `{issue['source_file']}` `{issue['fixture_id']}` "
                f"`{issue['field']}` - {issue['message']}"
            )
    return "\n".join(lines) + "\n"


def run_validate_fixtures(args: argparse.Namespace) -> int:
    fixtures = load_fixture_records(fixture_paths(args.fixture, args.corpus))
    result = validate_fixture_records(fixtures)
    result["corpus"] = corpus_metadata(args, len(fixtures))
    output = (
        json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else annotate_markdown_corpus(render_validation_markdown(result), result["corpus"])
    )
    if args.output:
        write_text(Path(args.output), output)
    else:
        print(output, end="")
    return 1 if result["summary"]["error_count"] else 0


def run_init_config(args: argparse.Namespace) -> int:
    target = Path(args.output)
    if target.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing config: {target}. Pass --force to replace it.")
    source = ROOT / "policy" / CONFIG_EXAMPLE_FILE
    if source.exists():
        config_text = source.read_text()
    else:
        config_text = resources.files(POLICY_PACKAGE).joinpath(CONFIG_EXAMPLE_FILE).read_text()
    write_text(target, config_text)
    print(f"Wrote {target}")
    return 0


def public_provenance_audit(fixtures: list[dict[str, Any]], check_urls: bool = False) -> dict[str, Any]:
    source_lock = load_public_fixture_source_lock()
    locked_ids = set(source_lock)
    fixture_ids = {fixture["id"] for fixture in fixtures if fixture.get("url")}
    source_lock_issues: list[dict[str, str]] = []
    records = []
    for fixture in fixtures:
        if not fixture.get("url"):
            continue
        source = str(fixture.get("source", ""))
        repo, commit = parse_source_ref(source)
        url_status = check_url(fixture["url"]) if check_urls else {"status": "not_checked", "http_status": None}
        lock_record = source_lock.get(fixture["id"])
        lock_status = "matched"
        if lock_record is None:
            lock_status = "missing"
            source_lock_issues.append(
                {"fixture_id": fixture["id"], "field": "source_lock", "message": "Missing source-lock record."}
            )
            lock_record = {}
        else:
            source_file = canonical_fixture_source_file(fixture.get("_source_file", ""))
            expected = {
                "source_file": source_file,
                "repo": repo,
                "commit": commit,
                "url": fixture["url"],
                "fixture_sha256": fixture_sha256(fixture),
            }
            for field, expected_value in expected.items():
                if lock_record.get(field) != expected_value:
                    lock_status = "mismatch"
                    source_lock_issues.append(
                        {
                            "fixture_id": fixture["id"],
                            "field": field,
                            "message": f"Expected {expected_value!r}, found {lock_record.get(field)!r}.",
                        }
                    )
        candidate_files = lock_record.get("candidate_files", [])
        records.append(
            {
                "fixture_id": fixture["id"],
                "source_file": canonical_fixture_source_file(fixture.get("_source_file", "")),
                "source_type": "public_commit",
                "repo": repo,
                "commit": commit,
                "url": fixture["url"],
                "url_status": url_status["status"],
                "http_status": url_status["http_status"],
                "corpus_split": split_for_source_file(fixture.get("_source_file", "")),
                "expected_risks": fixture.get("expected_risks", []),
                "label_status": fixture.get("label_status", ""),
                "fixture_sha256": fixture_sha256(fixture),
                "source_lock_status": lock_status,
                "source_resolution_status": lock_record.get("source_resolution_status", "missing_lock"),
                "selected_source_files": lock_record.get("selected_source_files", []),
                "candidate_file_count": len(candidate_files),
                "candidate_files": candidate_files,
                "exception_reason": lock_record.get("exception_reason", ""),
                "extraction_method": "manual descriptor-pair extraction into normalized Agent Tool Contract Drift fixture shape",
                "normalized_from": "public commit diff and local descriptor review notes",
                "extraction_status": lock_record.get("extraction_status", "manual_extraction_not_replayed"),
                "extraction_note": lock_record.get(
                    "extraction_note",
                    "Agent Tool Contract Drift fixture was normalized manually; descriptor extraction has not been replayed.",
                ),
                "license": lock_record.get("license_status", "not_audited"),
                "license_status": lock_record.get("license_status", "not_audited"),
                "license_note": lock_record.get("license_note", "Repository license posture is not audited."),
                "verified_at": None,
            }
        )
    for fixture_id in sorted(locked_ids - fixture_ids):
        source_lock_issues.append({"fixture_id": fixture_id, "field": "source_lock", "message": "Extra source-lock record."})
    status_counts = Counter(record["url_status"] for record in records)
    lock_status_counts = Counter(record["source_lock_status"] for record in records)
    resolution_status_counts = Counter(record["source_resolution_status"] for record in records)
    return {
        "summary": {
            "public_fixture_count": len(records),
            "unique_public_url_count": len({record["url"] for record in records}),
            "url_status_counts": dict(sorted(status_counts.items())),
            "source_lock_record_count": len(source_lock),
            "source_lock_status_counts": dict(sorted(lock_status_counts.items())),
            "source_resolution_status_counts": dict(sorted(resolution_status_counts.items())),
            "candidate_file_reference_count": sum(record["candidate_file_count"] for record in records),
            "records_with_candidate_files": sum(1 for record in records if record["candidate_file_count"] > 0),
            "source_lock_issue_count": len(source_lock_issues),
            "check_urls": check_urls,
        },
        "records": records,
        "source_lock_issues": source_lock_issues,
        "limitations": [
            "This audit records fixture provenance metadata; it does not certify upstream runtime behavior.",
            "Candidate files come from GitHub commit metadata; selected-field source replay exists for 10 fixtures, 16 retained derived descriptors have source-full static descriptor replay, 9 restricted source-full records are hash-only demotions, 1 source-full/current-fixture static match exists, current-fixture full descriptor replay remains 0, and license posture remains unaudited.",
            "License posture is not independently audited in the current corpus.",
            "Labels remain local regression-oracle expectations until external reviewers adjudicate them.",
        ],
    }


def canonical_fixture_source_file(source_file: str) -> str:
    path = Path(source_file)
    parts = path.parts
    for index, part in enumerate(parts):
        if part == "tool_contract_drift" and index + 2 < len(parts) and parts[index + 1] == "fixtures":
            return str(Path("fixtures") / parts[index + 2])
    return source_file


def load_public_fixture_source_lock() -> dict[str, dict[str, Any]]:
    if PUBLIC_FIXTURE_LOCK.exists():
        payload = json.loads(PUBLIC_FIXTURE_LOCK.read_text())
    else:
        try:
            payload = json.loads(
                resources.files("tool_contract_drift").joinpath(PUBLIC_FIXTURE_LOCK_RESOURCE).read_text()
            )
        except (ModuleNotFoundError, FileNotFoundError) as exc:
            raise SystemExit("Built-in public fixture provenance lock is unavailable.") from exc
    return {record["fixture_id"]: record for record in payload.get("records", [])}


def parse_source_ref(source: str) -> tuple[str, str]:
    if "@" not in source:
        return source, ""
    repo, commit = source.rsplit("@", 1)
    return repo, commit


def fixture_sha256(fixture: dict[str, Any]) -> str:
    public_fixture = {key: value for key, value in fixture.items() if not key.startswith("_")}
    payload = json.dumps(public_fixture, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def check_url(url: str) -> dict[str, Any]:
    request = Request(url, method="GET", headers={"User-Agent": "tool-contract-drift-provenance-audit/0.1"})
    try:
        with urlopen(request, timeout=15) as response:
            return {"status": "ok", "http_status": response.status}
    except HTTPError as exc:
        return {"status": "http_error", "http_status": exc.code}
    except URLError:
        return {"status": "url_error", "http_status": None}
    except TimeoutError:
        return {"status": "timeout", "http_status": None}


def render_public_provenance_markdown(audit: dict[str, Any]) -> str:
    summary = audit["summary"]
    lines = [
        "# Agent Tool Contract Drift Public Provenance Audit",
        "",
        "Status: deterministic provenance metadata for public commit-backed fixtures. This is not an independent upstream audit.",
        "",
        "## Summary",
        "",
        f"- Public fixture records: {summary['public_fixture_count']}",
        f"- Unique public URLs: {summary['unique_public_url_count']}",
        f"- URL checks enabled: {summary['check_urls']}",
        f"- URL status counts: {json.dumps(summary['url_status_counts'], sort_keys=True)}",
        f"- Source-lock records: {summary['source_lock_record_count']}",
        f"- Source-lock status counts: {json.dumps(summary['source_lock_status_counts'], sort_keys=True)}",
        f"- Source resolution status counts: {json.dumps(summary['source_resolution_status_counts'], sort_keys=True)}",
        f"- Candidate changed-file references: {summary['candidate_file_reference_count']}",
        f"- Source-lock issues: {summary['source_lock_issue_count']}",
        "",
        "## Records",
        "",
        "| Fixture | Repo | Commit | Split | URL Status | Source Lock | Resolution | Candidate Files | License | Expected Risks | Fixture SHA-256 |",
        "|---|---|---|---|---|---|---|---:|---|---|---|",
    ]
    for record in audit["records"]:
        risks = ", ".join(record["expected_risks"]) or "-"
        lines.append(
            f"| {record['fixture_id']} | {record['repo']} | `{record['commit']}` | {record['corpus_split']} | "
            f"{record['url_status']} | {record['source_lock_status']} | {record['source_resolution_status']} | "
            f"{record['candidate_file_count']} | {record['license_status']} | {risks} | `{record['fixture_sha256']}` |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in audit["limitations"])
    return "\n".join(lines) + "\n"


def run_public_provenance_audit(args: argparse.Namespace) -> int:
    fixtures = load_fixture_records(fixture_paths(args.fixture, args.corpus))
    audit = public_provenance_audit(fixtures, args.check_urls)
    audit["corpus"] = corpus_metadata(args, len(fixtures))
    if args.output:
        write_text(
            Path(args.output),
            annotate_markdown_corpus(render_public_provenance_markdown(audit), audit["corpus"]),
        )
    if args.json:
        write_text(Path(args.json), json.dumps(audit, indent=2, sort_keys=True) + "\n")
    if not args.output and not args.json:
        print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


def corpus_quality(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    labels = sorted(known_policy_labels())
    public_labels = {risk for fixture in fixtures if fixture.get("url") for risk in fixture.get("expected_risks", [])}
    synthetic_labels = {risk for fixture in fixtures if not fixture.get("url") for risk in fixture.get("expected_risks", [])}
    split_counts: dict[str, dict[str, int]] = {}
    source_type_counts: Counter[str] = Counter()
    for fixture in fixtures:
        split = split_for_source_file(fixture.get("_source_file", ""))
        source_type = source_type_for_fixture(fixture)
        source_type_counts[source_type] += 1
        row = split_counts.setdefault(split, {"fixtures": 0, "hold_fixtures": 0, "quiet_fixtures": 0, "findings": 0})
        row["fixtures"] += 1
        finding_count = len(lint_fixtures([fixture]))
        row["findings"] += finding_count
        if finding_count:
            row["hold_fixtures"] += 1
        else:
            row["quiet_fixtures"] += 1
    return {
        "summary": {
            "fixture_count": len(fixtures),
            "public_commit_fixture_count": source_type_counts["public_commit"],
            "synthetic_fixture_count": source_type_counts["synthetic"],
            "synthetic_only_labels": sorted(set(labels) - public_labels),
            "public_covered_labels": sorted(public_labels),
            "synthetic_covered_labels": sorted(synthetic_labels),
        },
        "splits": dict(sorted(split_counts.items())),
        "limitations": [
            "Historical heldout groups are now regression fixtures, not sealed evaluation data.",
            "Synthetic-only labels should not be presented as public prevalence evidence.",
            "No adjudicated gold-label layer exists until independent non-participant adjudicators complete and hash-freeze the gold-label template before reviewer outreach.",
        ],
    }


def render_corpus_quality_markdown(quality: dict[str, Any]) -> str:
    summary = quality["summary"]
    lines = [
        "# Agent Tool Contract Drift Corpus Quality Report",
        "",
        "Status: corpus quality summary for the current regression harness. This is not a benchmark scorecard.",
        "",
        "## Summary",
        "",
        f"- Fixture pairs: {summary['fixture_count']}",
        f"- Public commit-backed fixtures: {summary['public_commit_fixture_count']}",
        f"- Synthetic fixtures: {summary['synthetic_fixture_count']}",
        f"- Public-covered labels: {', '.join(summary['public_covered_labels']) or '-'}",
        f"- Synthetic-covered labels: {', '.join(summary['synthetic_covered_labels']) or '-'}",
        f"- Synthetic-only labels: {', '.join(summary['synthetic_only_labels']) or '-'}",
        "",
        "## Splits",
        "",
        "| Split | Fixtures | Hold Fixtures | Quiet Fixtures | Findings |",
        "|---|---:|---:|---:|---:|",
    ]
    for split, row in quality["splits"].items():
        lines.append(f"| {split} | {row['fixtures']} | {row['hold_fixtures']} | {row['quiet_fixtures']} | {row['findings']} |")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in quality["limitations"])
    return "\n".join(lines) + "\n"


def run_corpus_quality(args: argparse.Namespace) -> int:
    fixtures = load_fixture_records(fixture_paths(args.fixture, args.corpus))
    quality = corpus_quality(fixtures)
    quality["corpus"] = corpus_metadata(args, len(fixtures))
    if args.output:
        write_text(
            Path(args.output),
            annotate_markdown_corpus(render_corpus_quality_markdown(quality), quality["corpus"]),
        )
    if args.json:
        write_text(Path(args.json), json.dumps(quality, indent=2, sort_keys=True) + "\n")
    if not args.output and not args.json:
        print(json.dumps(quality, indent=2, sort_keys=True))
    return 0


def render_policy_markdown(policy: dict[str, Any]) -> str:
    lines = [
        "# Agent Tool Contract Drift Policy",
        "",
        f"- Policy version: {policy['policy_version']}",
        f"- Status: {policy['status']}",
        "",
        "## Labels",
        "",
        "| Label | Default Severity | Review Question |",
        "|---|---|---|",
    ]
    for label in policy["labels"]:
        lines.append(f"| `{label['id']}` | {label['default_severity']} | {label['review_question']} |")
    lines.extend(
        [
            "",
            "## Generic Baseline Labels",
            "",
            *[f"- `{label}`" for label in policy["generic_baseline_labels"]],
            "",
            "## Output Contract",
            "",
            *[f"- `{field}`" for field in policy["output_contract"]],
        ]
    )
    return "\n".join(lines) + "\n"


def run_explain_rules(args: argparse.Namespace) -> int:
    policy = load_default_policy_document()
    if args.format == "json":
        output = json.dumps(policy, indent=2, sort_keys=True) + "\n"
    else:
        output = render_policy_markdown(policy)
    if args.output:
        write_text(Path(args.output), output)
    else:
        print(output, end="")
    return 0


def add_corpus_selection_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--corpus",
        choices=SUPPORTED_CORPUS_IDS,
        help="Named, manifest-verified corpus. Required when --fixture is not supplied.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent Tool Contract Drift agent tool contract drift utilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  tool-contract-drift lint --before before.json --after after.json --format sarif --output tool-contract-drift.sarif
  tool-contract-drift capture --stdio "python server.py" --output after-descriptor.json
  tool-contract-drift init-config --output tool-contract-drift-config.json
  tool-contract-drift validate-fixtures --format json
  tool-contract-drift public-provenance-audit
  tool-contract-drift corpus-quality
""",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    lint_parser = subparsers.add_parser("lint", help="Run Agent Tool Contract Drift labels over descriptor fixture pairs.")
    lint_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(lint_parser)
    lint_parser.add_argument("--before", help="Before descriptor JSON for a single descriptor-pair run.")
    lint_parser.add_argument("--after", help="After descriptor JSON for a single descriptor-pair run.")
    lint_parser.add_argument("--id", default="descriptor-pair", help="Fixture id for --before/--after runs.")
    lint_parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown")
    lint_parser.add_argument("--output", help="Optional output file.")
    lint_parser.add_argument("--fail-on", choices=("none", "any", "medium", "high"), default="none")
    lint_parser.add_argument("--config", help="Optional Agent Tool Contract Drift lint config JSON path.")
    lint_parser.add_argument(
        "--builtin-corpus",
        action="store_true",
        help=f"Compatibility alias for --corpus {PUBLIC_REPRODUCTION_CORPUS_ID}.",
    )
    lint_parser.set_defaults(func=run_lint)

    capture_parser = subparsers.add_parser(
        "capture",
        help="Capture a descriptor snapshot from a stdio MCP server by calling initialize and tools/list.",
    )
    capture_parser.add_argument("--stdio", required=True, help="Command used to launch a stdio MCP server.")
    capture_parser.add_argument("--output", help="Optional descriptor JSON output file.")
    capture_parser.add_argument("--protocol-version", default=DEFAULT_MCP_PROTOCOL_VERSION)
    capture_parser.add_argument("--timeout", type=float, default=10.0, help="Seconds to wait for each MCP response.")
    capture_parser.set_defaults(func=run_capture)

    corpus_parser = subparsers.add_parser("corpus-manifest", help="Generate a corpus provenance and label manifest.")
    corpus_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(corpus_parser)
    corpus_parser.add_argument("--output", default="reports/corpus_manifest.md")
    corpus_parser.add_argument("--json", default="reports/corpus_manifest.json")
    corpus_parser.set_defaults(func=run_corpus_manifest)

    configured_parser = subparsers.add_parser("configured-baselines", help="Run configured substitute baseline bakeoff.")
    configured_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(configured_parser)
    configured_parser.add_argument("--output", default="reports/configured_substitute_bakeoff.md")
    configured_parser.add_argument("--json", default="reports/configured_substitute_bakeoff.json")
    configured_parser.set_defaults(func=run_configured_baselines)

    oasdiff_parser = subparsers.add_parser("oasdiff-adapter", help="Run real oasdiff JSON through the Agent Tool Contract Drift adapter.")
    oasdiff_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(oasdiff_parser)
    oasdiff_parser.add_argument("--before", help="Before descriptor JSON for a single descriptor-pair adapter run.")
    oasdiff_parser.add_argument("--after", help="After descriptor JSON for a single descriptor-pair adapter run.")
    oasdiff_parser.add_argument("--id", default="descriptor-pair", help="Fixture id for --before/--after runs.")
    oasdiff_parser.add_argument("--output", default="reports/oasdiff_adapter_probe.md")
    oasdiff_parser.add_argument("--json", default="reports/oasdiff_adapter_probe.json")
    oasdiff_parser.set_defaults(func=run_oasdiff_adapter)

    explain_parser = subparsers.add_parser("explain-rules", help="Print the built-in Agent Tool Contract Drift policy labels.")
    explain_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    explain_parser.add_argument("--output", help="Optional output file.")
    explain_parser.set_defaults(func=run_explain_rules)

    validate_parser = subparsers.add_parser("validate-fixtures", help="Validate Agent Tool Contract Drift fixture structure and labels.")
    validate_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(validate_parser)
    validate_parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    validate_parser.add_argument("--output", help="Optional output file.")
    validate_parser.set_defaults(func=run_validate_fixtures)

    init_config_parser = subparsers.add_parser("init-config", help="Write an example Agent Tool Contract Drift config file.")
    init_config_parser.add_argument("--output", default="tool-contract-drift-config.json")
    init_config_parser.add_argument("--force", action="store_true", help="Overwrite an existing output file.")
    init_config_parser.set_defaults(func=run_init_config)

    provenance_parser = subparsers.add_parser("public-provenance-audit", help="Generate public fixture provenance metadata.")
    provenance_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(provenance_parser)
    provenance_parser.add_argument("--output", default="reports/public_provenance_audit.md")
    provenance_parser.add_argument("--json", default="reports/public_provenance_audit.json")
    provenance_parser.add_argument("--check-urls", action="store_true", help="Perform live URL checks. Not used by deterministic release gates.")
    provenance_parser.set_defaults(func=run_public_provenance_audit)

    quality_parser = subparsers.add_parser("corpus-quality", help="Generate corpus split and label-coverage quality report.")
    quality_parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    add_corpus_selection_argument(quality_parser)
    quality_parser.add_argument("--output", default="reports/corpus_quality.md")
    quality_parser.add_argument("--json", default="reports/corpus_quality.json")
    quality_parser.set_defaults(func=run_corpus_quality)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
