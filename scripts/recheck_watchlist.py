#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.github_client import GitHubClient  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402
from oss_pr_radar.watch import recheck_watchlist  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("watchlist", type=Path)
    parser.add_argument("pending_rechecks", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    if not args.watchlist.exists():
        atomic_write_json(args.pending_rechecks, {})
        atomic_write_json(
            args.report,
            {"scan_ok": True, "candidate_details": [], "updates": [], "pending_rechecks": {}},
        )
        return 0
    watchlist = json.loads(args.watchlist.read_text(encoding="utf-8"))
    inventory = {
        item.strip().casefold()
        for item in os.environ.get("RADAR_HARDWARE", "4090,5090,a100,v100").split(",")
        if item.strip()
    }
    updated, report = recheck_watchlist(
        watchlist,
        GitHubClient(),
        limit=args.limit,
        current_actor=os.environ.get("GITHUB_ACTOR", "Oxygen56"),
        hardware_inventory=inventory,
    )
    atomic_write_json(args.watchlist, updated)
    atomic_write_json(args.pending_rechecks, report["pending_rechecks"])
    atomic_write_json(args.report, report)
    print(json.dumps({"updates": len(report["updates"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
