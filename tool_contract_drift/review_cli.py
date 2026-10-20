from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from tool_contract_drift.review import review_descriptor_pair


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Show every tool-object change alongside incomplete policy labels.")
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--id", default="descriptor-pair")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output")
    parser.add_argument("--fail-on", choices=("none", "change", "findings"), default="none")
    args = parser.parse_args()
    try:
        descriptors = []
        for filename in (args.before, args.after):
            with Path(filename).open("rb") as source:
                raw = source.read(10_000_001)
            if len(raw) > 10_000_000:
                raise ValueError("Descriptor exceeds the 10 MB review input limit.")
            descriptors.append(json.loads(raw, object_pairs_hook=unique_object))
        report = review_descriptor_pair(*descriptors, fixture_id=args.id)
    except (OSError, ValueError, TypeError, RecursionError) as error:
        raise SystemExit(f"Cannot review descriptor pair: {error}") from error
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.format == "markdown":
        fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", output)), default=0) + 1)
        output = "# Tool Descriptor Review\n\n" + report["boundary"] + "\n\n" + fence + "json\n" + output + fence + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output)
    else:
        sys.stdout.write(output)
    return int((args.fail_on == "change" and bool(report["changes"])) or (args.fail_on == "findings" and bool(report["policy_findings"])))


if __name__ == "__main__":
    raise SystemExit(main())
