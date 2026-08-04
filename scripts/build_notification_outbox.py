#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.outbox import build_outbox  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("outbox", type=Path)
    parser.add_argument("--kind", choices=("immediate", "review", "watch"), default="immediate")
    parser.add_argument("--exclude-report", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    existing = json.loads(args.outbox.read_text(encoding="utf-8")) if args.outbox.exists() else None
    excluded: set[str] = set()
    if args.exclude_report and args.exclude_report.exists():
        exclusion_report = json.loads(args.exclude_report.read_text(encoding="utf-8"))
        excluded = {
            f"{item.get('repo')}#{item.get('num')}"
            for item in exclusion_report.get("candidate_details") or []
            if isinstance(item, dict) and item.get("repo") and item.get("num") is not None
        }
    outbox = build_outbox(
        report,
        existing,
        kind=args.kind,
        exclude_candidate_keys=excluded,
    )
    atomic_write_json(args.outbox, outbox)
    print(
        json.dumps(
            {
                "outbox_events": len(outbox["events"]),
                "new_outbox_events": outbox["newEventCount"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
