#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.outbox import merge_receipts  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("current", type=Path)
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    current = json.loads(args.current.read_text(encoding="utf-8"))
    merged = merge_receipts(current, receipt)
    atomic_write_json(args.current, merged)
    print(json.dumps({"merged_receipts": len(receipt.get("events") or [])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
