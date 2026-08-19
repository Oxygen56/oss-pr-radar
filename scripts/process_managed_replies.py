#!/usr/bin/env python3
"""Reconcile observed reply receipts and leave queued replies pending without a sender."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_adapter import ManagedAdapter  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    parser.add_argument("--receipts", type=Path)
    args = parser.parse_args()
    receipts = {}
    if args.receipts and args.receipts.exists():
        value = json.loads(args.receipts.read_text(encoding="utf-8"))
        receipts = value if isinstance(value, dict) else {}
    result = ManagedAdapter(ROOT, args.ledger).process_reply_outbox(
        sender=None, receipts=receipts
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
