#!/usr/bin/env python3
"""Preflight or copy-clean the one known ``a/b#1`` synthetic ledger graph."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.synthetic_ledger_cleanup import (  # noqa: E402
    SyntheticLedgerCleanupError,
    copy_and_clean_known_synthetic_graph,
    preflight_known_synthetic_graph,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the fixed a/b#1 synthetic graph read-only by default. "
            "--execute-copy creates and cleans a new database; the source is never modified."
        )
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument(
        "--execute-copy",
        type=Path,
        help="explicit new output path; must not already exist",
    )
    args = parser.parse_args()
    try:
        if args.execute_copy is None:
            result = preflight_known_synthetic_graph(args.source)
        else:
            result = copy_and_clean_known_synthetic_graph(args.source, args.execute_copy)
    except (OSError, sqlite3.Error, SyntheticLedgerCleanupError) as exc:
        print(
            json.dumps(
                {"ok": False, "error": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
