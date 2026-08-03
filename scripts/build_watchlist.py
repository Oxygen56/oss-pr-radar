#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.util import atomic_write_json  # noqa: E402
from oss_pr_radar.watch import build_watchlist  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("watchlist", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    existing = (
        json.loads(args.watchlist.read_text(encoding="utf-8")) if args.watchlist.exists() else None
    )
    value = build_watchlist(report, existing)
    atomic_write_json(args.watchlist, value)
    print(json.dumps({"watching": len(value["items"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
