#!/usr/bin/env python3
"""Create the redacted managed lifecycle checkpoint used by state_branch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_snapshot import export_snapshot  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "state" / "managed_lifecycle.snapshot.json.gz"
    )
    args = parser.parse_args()
    print(json.dumps(export_snapshot(args.ledger, args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
