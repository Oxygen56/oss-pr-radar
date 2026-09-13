#!/usr/bin/env python3
"""Export verified public PR admissions or merge signed controller feedback."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.publication_feedback import FILENAME, apply_feedback, build_feedback  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("export", "apply"))
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    parser.add_argument("--feedback", type=Path, default=ROOT / "state" / FILENAME)
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    if args.operation == "export":
        value = build_feedback(args.ledger)
        atomic_write_json(args.feedback, value)
        result = {"ok": True, "admissions": len(value["entries"])}
    elif not args.feedback.exists() and args.allow_missing:
        result = {"ok": True, "admissions": 0, "added": 0, "duplicates": 0, "missing": True}
    else:
        result = apply_feedback(args.ledger, json.loads(args.feedback.read_text(encoding="utf-8")))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
