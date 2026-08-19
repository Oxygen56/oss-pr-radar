#!/usr/bin/env python3
"""Migrate or roll back a managed Ledger on a database copy only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_lifecycle import (  # noqa: E402
    migrate_copy,
    rollback_schema,
    schema_status,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--rollback", action="store_true")
    args = parser.parse_args()
    if args.rollback:
        result = rollback_schema(args.target)
    else:
        result = migrate_copy(args.source, args.target)
    result["schema"] = schema_status(args.target)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
