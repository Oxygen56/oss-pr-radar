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
    parser.add_argument(
        "--kind", choices=("immediate", "review", "watch"), default="immediate"
    )
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    existing = (
        json.loads(args.outbox.read_text(encoding="utf-8"))
        if args.outbox.exists()
        else None
    )
    outbox = build_outbox(report, existing, kind=args.kind)
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
