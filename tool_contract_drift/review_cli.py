from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

from tool_contract_drift.review import review_descriptor_pair
from tool_contract_drift.review_privacy import minimize_review_report
from tool_contract_drift.review_render import render_review_markdown


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _render(report: dict, output_format: str, disclosure: str) -> str:
    visible = report if disclosure == "full" else minimize_review_report(report, disclosure)
    if output_format == "markdown":
        return render_review_markdown(visible)
    return json.dumps(visible, indent=2, sort_keys=True) + "\n"


def _validate_destinations(inputs: list[Path], outputs: list[Path]) -> None:
    for index, output in enumerate(outputs):
        if output.is_dir():
            raise ValueError("Invalid report destination.")
        for other in inputs + outputs[:index]:
            try:
                aliases = output.resolve() == other.resolve() or (
                    output.exists() and other.exists() and output.samefile(other)
                )
            except RuntimeError:
                raise ValueError("Invalid report destination.") from None
            if aliases:
                raise ValueError("Report destinations must not alias inputs or each other.")


def _write_report(destination: Path, text: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=".descriptor-review-",
            dir=destination.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def report_error() -> int:
    # Descriptor validation exceptions can contain private names or values.
    sys.stderr.write(json.dumps({"error": "descriptor_review_failed", "request_id": uuid.uuid4().hex}) + "\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show every tool-object change alongside incomplete policy labels.")
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--id", default="descriptor-pair")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output")
    parser.add_argument("--disclosure", choices=("full", "counts", "paths"), default="full")
    parser.add_argument("--summary-output", help="Optional separate Markdown report from the same comparison.")
    parser.add_argument("--summary-disclosure", choices=("counts", "paths", "full"), default="counts")
    parser.add_argument("--fail-on", choices=("none", "change", "findings"), default="none")
    args = parser.parse_args(argv)
    try:
        inputs = [Path(filename) for filename in (args.before, args.after)]
        destinations = [Path(filename) for filename in (args.output, args.summary_output) if filename]
        _validate_destinations(inputs, destinations)
        descriptors = []
        for filename in inputs:
            with filename.open("rb") as source:
                raw = source.read(10_000_001)
            if len(raw) > 10_000_000:
                raise ValueError("Descriptor exceeds the 10 MB review input limit.")
            descriptors.append(json.loads(raw, object_pairs_hook=unique_object))
        report = review_descriptor_pair(*descriptors, fixture_id=args.id)
        output = _render(report, args.format, args.disclosure)
        summary = _render(report, "markdown", args.summary_disclosure) if args.summary_output else None
        if args.output:
            _write_report(Path(args.output), output)
        if args.summary_output:
            _write_report(Path(args.summary_output), summary)
        if not args.output:
            sys.stdout.write(output)
    except (OSError, ValueError, TypeError, RecursionError):
        return report_error()
    return int((args.fail_on == "change" and bool(report["changes"])) or (args.fail_on == "findings" and bool(report["policy_findings"])))


if __name__ == "__main__":
    raise SystemExit(main())
