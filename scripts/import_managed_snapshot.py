#!/usr/bin/env python3
"""Atomically restore a redacted managed lifecycle checkpoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_snapshot import import_snapshot  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snapshot", type=Path, default=ROOT / "state" / "managed_lifecycle.snapshot.json.gz"
    )
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            import_snapshot(args.ledger, args.snapshot, allow_missing=args.allow_missing),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
