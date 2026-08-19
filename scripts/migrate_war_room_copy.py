#!/usr/bin/env python3
"""Prepare or roll back an explicit War Room database copy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.war_room_migration import prepare_copy, rollback_copy  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--rollback-manifest", type=Path)
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args()
    if args.rollback_manifest:
        result = rollback_copy(
            args.target, json.loads(args.rollback_manifest.read_text(encoding="utf-8"))
        )
    else:
        if args.source is None:
            parser.error("--source is required unless --rollback-manifest is used")
        result = prepare_copy(args.source, args.target, source_commit=args.source_commit)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
