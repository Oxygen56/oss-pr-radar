#!/usr/bin/env python3
"""Project a previously collected GitHub follow-up snapshot into Managed Ledger."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_adapter import ManagedAdapter  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    args = parser.parse_args()
    state = json.loads(args.state.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    result = ManagedAdapter(ROOT, args.ledger).record_followup(state, report)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
