#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.publication import broker_publication_request  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    args = parser.parse_args()
    result = broker_publication_request(RadarLedger(args.ledger), args.request_id)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("granted") or result.get("pending") else 2


if __name__ == "__main__":
    raise SystemExit(main())
