#!/usr/bin/env python3
"""Read-only reconciliation report for scheduled Radar command receipts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.automation_run_receipt import (  # noqa: E402
    audit_automation_runs,
    load_automation_run_receipts,
)
from oss_pr_radar.util import sha256_json  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--receipt-path", type=Path)
    parser.add_argument("--automation-id")
    parser.add_argument("--window-start")
    parser.add_argument("--window-end")
    parser.add_argument("--expected-interval-minutes", type=float)
    parser.add_argument("--grace-minutes", type=float, default=10)
    args = parser.parse_args(argv)
    try:
        records, source_issues = load_automation_run_receipts(
            args.runtime_root,
            path=args.receipt_path,
        )
        result = audit_automation_runs(
            records,
            source_issues=source_issues,
            automation_id=args.automation_id,
            window_start=args.window_start,
            window_end=args.window_end,
            expected_interval_minutes=args.expected_interval_minutes,
            grace_minutes=args.grace_minutes,
            expected_runtime_root_digest=sha256_json(str(args.runtime_root.absolute())),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        result = {
            "schema": "oss-pr-radar.automation-run-audit.v1",
            "ok": False,
            "error": f"{type(exc).__name__}:{str(exc)[:400]}",
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
