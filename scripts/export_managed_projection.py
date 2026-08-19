#!/usr/bin/env python3
"""Export the read-only four-bucket Ledger projection for War Room consumers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_lifecycle import export_projection  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-copy", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export_projection(args.db_copy), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
