from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tool_contract_drift.corpora import SUPPORTED_CORPUS_IDS, custom_fixture_paths, select_corpus

ROOT = Path(__file__).resolve().parents[1]
RELEASE_CONTRACT = ROOT / "data/release_contract.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tool_contract_drift.baselines.baseline_probe import run_command
from tool_contract_drift.baselines.configured_substitutes import (
    load_all_fixture_records,
    policy_finding_keys,
)
from tool_contract_drift.linter.tool_contract_drift import lint_fixture
from tool_contract_drift.adapters.oasdiff import (
    find_oasdiff_command,
    map_oasdiff_json_to_finding_keys,
    parse_oasdiff_json,
    project_descriptor_to_openapi,
    run_oasdiff_descriptor_pair,
)


@dataclass(frozen=True)
class OasdiffAdapterResult:
    fixture_id: str
    source_file: str
    candidate_risks: tuple[str, ...]
    candidate_finding_keys: tuple[str, ...]
    adapter_risks: tuple[str, ...]
    adapter_finding_keys: tuple[str, ...]
    exact_match: bool
    instance_exact_match: bool
    oasdiff_status: str
    oasdiff_exit_code: int | None
    oasdiff_changed: bool
    stderr_excerpt: str


def run_adapter_probe(paths: list[Path]) -> tuple[list[OasdiffAdapterResult], dict[str, Any]]:
    if not paths:
        raise ValueError("Fixture paths are required; select a named corpus explicitly before running evidence code.")
    oasdiff = find_oasdiff_command()
    version = run_command([oasdiff, "--version"], ROOT) if oasdiff else None
    version_metadata = oasdiff_version_metadata(oasdiff, version)
    results: list[OasdiffAdapterResult] = []
    for source_file, fixture in load_all_fixture_records(paths):
        candidate_risks = tuple(sorted({finding.risk for finding in lint_fixture(fixture)}))
        candidate_finding_keys = policy_finding_keys(fixture)
        before_openapi = project_descriptor_to_openapi(fixture["before"], f"{fixture['id']} before")
        after_openapi = project_descriptor_to_openapi(fixture["after"], f"{fixture['id']} after")
        adapter_run = run_oasdiff_descriptor_pair(fixture["before"], fixture["after"], fixture["id"], oasdiff)
        parsed_oasdiff = parse_oasdiff_json(adapter_run.stdout_excerpt)
        adapter_finding_keys = (
            map_oasdiff_json_to_finding_keys(parsed_oasdiff, before_openapi, after_openapi)
            if parsed_oasdiff is not None
            else ()
        )
        results.append(
            OasdiffAdapterResult(
                fixture_id=fixture["id"],
                source_file=source_file,
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
        )
    return results, {
        "oasdiff_available": oasdiff is not None,
        "oasdiff_command": "oasdiff" if oasdiff else "",
        **version_metadata,
    }


def oasdiff_version_metadata(oasdiff_command: str | None, version_result: Any | None) -> dict[str, str]:
    contract = json.loads(RELEASE_CONTRACT.read_text())
    expected = contract["toolchain"]["oasdiff"]
    raw_version = version_result.stdout_excerpt if version_result else ""
    raw_status = version_result.status if version_result else "not_found"
    module_path = ""
    module_version = ""
    module_status = "not_checked" if oasdiff_command else "not_found"
    if oasdiff_command:
        module_result = run_command(["go", "version", "-m", oasdiff_command], ROOT)
        module_status = module_result.status
        module_path, module_version = parse_go_module_version(module_result.stdout_excerpt)
    if module_path == "github.com/oasdiff/oasdiff" and module_version:
        return {
            "oasdiff_version": f"{module_path} {module_version}",
            "oasdiff_version_status": "module_version_identified",
            "oasdiff_version_raw": raw_version,
            "oasdiff_version_raw_status": raw_status,
            "oasdiff_module_path": module_path,
            "oasdiff_module_version": module_version,
            "oasdiff_module_status": module_status,
            "oasdiff_expected_module_path": expected["module"],
            "oasdiff_expected_module_version": expected["version"],
            "oasdiff_pin_status": (
                "match"
                if module_path == expected["module"] and module_version == expected["version"]
                else "mismatch"
            ),
        }
    if raw_version and raw_version.strip() == "oasdiff version main":
        attribution_status = "raw_version_unidentifiable"
    else:
        attribution_status = raw_status
    return {
        "oasdiff_version": raw_version,
        "oasdiff_version_status": attribution_status,
        "oasdiff_version_raw": raw_version,
        "oasdiff_version_raw_status": raw_status,
        "oasdiff_module_path": module_path,
        "oasdiff_module_version": module_version,
        "oasdiff_module_status": module_status,
        "oasdiff_expected_module_path": expected["module"],
        "oasdiff_expected_module_version": expected["version"],
        "oasdiff_pin_status": "mismatch",
    }


def parse_go_module_version(text: str) -> tuple[str, str]:
    for line in text.splitlines():
        match = re.match(r"\s*mod\s+(\S+)\s+(\S+)", line)
        if match:
            return match.group(1), match.group(2)
    return "", ""


def summarize_results(results: list[OasdiffAdapterResult], metadata: dict[str, Any]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for item in results:
        expected = bool(item.candidate_risks)
        predicted = bool(item.adapter_risks)
        if expected and predicted:
            tp += 1
        elif not expected and predicted:
            fp += 1
        elif expected and not predicted:
            fn += 1
        else:
            tn += 1
    return {
        **metadata,
        "fixture_count": len(results),
        "candidate_hold_fixture_count": sum(bool(item.candidate_risks) for item in results),
        "quiet_fixture_count": sum(not item.candidate_risks for item in results),
        "adapter_hold_fixture_count": sum(bool(item.adapter_risks) for item in results),
        "exact_match_count": sum(item.exact_match for item in results),
        "candidate_finding_instance_count": sum(len(item.candidate_finding_keys) for item in results),
        "instance_exact_match_count": sum(item.instance_exact_match for item in results),
        "missing_finding_instance_count": sum(
            len(set(item.candidate_finding_keys) - set(item.adapter_finding_keys)) for item in results
        ),
        "extra_finding_instance_count": sum(
            len(set(item.adapter_finding_keys) - set(item.candidate_finding_keys)) for item in results
        ),
        "semantic_label_fn_count": sum(bool(item.candidate_risks) and item.adapter_risks != item.candidate_risks for item in results),
        "semantic_instance_fn_count": sum(
            bool(item.candidate_finding_keys) and item.adapter_finding_keys != item.candidate_finding_keys
            for item in results
        ),
        "tp_fixtures": tp,
        "fp_fixtures": fp,
        "fn_fixtures": fn,
        "tn_fixtures": tn,
        "non_ok_status_count": sum(item.oasdiff_status != "ok" for item in results),
    }


def render_markdown(results: list[OasdiffAdapterResult], metadata: dict[str, Any]) -> str:
    summary = summarize_results(results, metadata)
    lines = [
        "# Agent Tool Contract Drift oasdiff Adapter Probe",
        "",
        "Status: executable substitute-adapter probe. This is not external reviewer validation.",
        "",
        "## Summary",
        "",
        f"- oasdiff available: {summary['oasdiff_available']}",
        f"- oasdiff version: {summary['oasdiff_version'] or '-'}",
        f"- oasdiff raw version: {summary['oasdiff_version_raw'] or '-'}",
        f"- oasdiff version attribution: {summary['oasdiff_version_status']}",
        f"- Authoritative oasdiff pin: {summary['oasdiff_expected_module_path']} {summary['oasdiff_expected_module_version']}",
        f"- oasdiff pin status: {summary['oasdiff_pin_status']}",
        f"- Fixture pairs: {summary['fixture_count']}",
        f"- Agent Tool Contract Drift hold fixtures: {summary['candidate_hold_fixture_count']}",
        f"- Quiet/control fixtures: {summary['quiet_fixture_count']}",
        f"- Adapter hold fixtures: {summary['adapter_hold_fixture_count']}",
        f"- Exact semantic-label matches: {summary['exact_match_count']}/{summary['fixture_count']}",
        f"- Agent Tool Contract Drift finding instances: {summary['candidate_finding_instance_count']}",
        f"- Finding-instance exact fixture matches: {summary['instance_exact_match_count']}/{summary['fixture_count']}",
        f"- Missing/extra finding instances: {summary['missing_finding_instance_count']}/{summary['extra_finding_instance_count']}",
        f"- Semantic-label false negatives: {summary['semantic_label_fn_count']}",
        f"- Semantic-instance false negatives: {summary['semantic_instance_fn_count']}",
        f"- TP/FP/FN/TN fixtures: {summary['tp_fixtures']}/{summary['fp_fixtures']}/{summary['fn_fixtures']}/{summary['tn_fixtures']}",
        f"- Non-OK oasdiff statuses: {summary['non_ok_status_count']}",
        "",
        "## Interpretation",
        "",
        "This probe runs real `oasdiff diff -f json` output through the Agent Tool Contract Drift risk mapper over the generated OpenAPI `x-mcp-*` projection.",
        "A full match means the current semantic labels can be transported through an oasdiff adapter on this corpus; it does not prove oasdiff independently contains those semantics.",
        "",
        "## Fixture Results",
        "",
        "| Fixture | Source | Agent Tool Contract Drift Risks | Adapter Risks | Exact Match | oasdiff Status | Changed |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in results:
        lines.append(
            f"| {item.fixture_id} | `{item.source_file}` | {labels(item.candidate_risks)} | "
            f"{labels(item.adapter_risks)} | {item.exact_match} | {item.oasdiff_status} | {item.oasdiff_changed} |"
        )
    return "\n".join(lines) + "\n"


def labels(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "-"


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", action="append", help="Explicit custom fixture JSON path.")
    parser.add_argument("--corpus", choices=SUPPORTED_CORPUS_IDS)
    parser.add_argument("--output", default=str(ROOT / "reports" / "oasdiff_adapter_probe.md"))
    parser.add_argument("--json", default=str(ROOT / "reports" / "oasdiff_adapter_probe.json"))
    args = parser.parse_args()

    if bool(args.fixture) == bool(args.corpus):
        raise SystemExit("Choose exactly one of --fixture or --corpus.")
    paths = list(custom_fixture_paths(args.fixture)) if args.fixture else list(select_corpus(args.corpus).fixture_paths)
    results, metadata = run_adapter_probe(paths)
    write_text(Path(args.output), render_markdown(results, metadata))
    write_text(
        Path(args.json),
        json.dumps(
            {"summary": summarize_results(results, metadata), "results": [asdict(item) for item in results]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    print(f"Wrote {args.output}")
    print(f"Wrote {args.json}")


if __name__ == "__main__":
    main()
