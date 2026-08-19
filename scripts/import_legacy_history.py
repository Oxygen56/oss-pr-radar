#!/usr/bin/env python3
"""Import legacy history into an explicit managed Ledger rehearsal copy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.legacy_migration import import_legacy_history  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--production-ledger", type=Path)
    parser.add_argument("--war-room-db", type=Path)
    parser.add_argument("--reports-dir", type=Path)
    args = parser.parse_args()
    result = import_legacy_history(
        args.target,
        production_ledger=args.production_ledger,
        war_room_db=args.war_room_db,
        reports_dir=args.reports_dir,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
