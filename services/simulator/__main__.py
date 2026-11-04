"""Opt-in local JSON/JSONL export: python -m services.simulator --help."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

from .generator import DEFAULT_REFERENCE_TIME, SCENARIOS, generate_events


def _utc_time(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        raise argparse.ArgumentTypeError("reference time must be UTC ISO 8601 with Z or +00:00")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError("reference time must be a valid calendar date") from None


def _local_path(value: str) -> Path:
    # Do not let an explicitly supplied UNC path or URL initiate remote I/O.
    if not value.strip() or value.replace("\\", "/").startswith("//") or "://" in value:
        raise argparse.ArgumentTypeError("output must be a local file path, not a URL or UNC path")
    return Path(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic authentication events offline.")
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--reference-time", type=_utc_time, default=DEFAULT_REFERENCE_TIME,
                        help="UTC ISO 8601 end time (default: 2026-11-04T12:00:00Z)")
    parser.add_argument("--count", type=int, help="normal: 2-10000; burst: 5-10000; unfamiliar: 2")
    parser.add_argument("--output", type=_local_path, required=True, help="explicit local output file")
    parser.add_argument("--format", choices=("json", "jsonl"), default="json")
    parser.add_argument("--overwrite", action="store_true", help="allow replacing an existing file")
    args = parser.parse_args(argv)
    try:
        events = generate_events(args.scenario, seed=args.seed,
                                 reference_time=args.reference_time, count=args.count)
        if args.format == "json":
            content = json.dumps(events, indent=2, sort_keys=True) + "\n"
        else:
            content = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        # Exclusive creation provides overwrite protection without a check/open race.
        with args.output.open("w" if args.overwrite else "x", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    except FileExistsError:
        parser.error("output already exists; use --overwrite to replace it")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
