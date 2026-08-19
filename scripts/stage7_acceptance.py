#!/usr/bin/env python3
"""Run read-only Stage 7 deployment acceptance checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.runtime import write_json  # noqa: E402
from oss_pr_radar.stage7_acceptance import check, shareable_acceptance_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--managed-counts-evidence", type=Path)
    parser.add_argument("--automation-snapshot", type=Path)
    parser.add_argument(
        "--preflight", action="store_true", help="check all gates before workers are loaded"
    )
    parser.add_argument(
        "--private", action="store_true", help="emit restricted operational details"
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.managed_counts_evidence is None or args.automation_snapshot is None:
        parser.error(
            "production-strict acceptance requires --managed-counts-evidence and --automation-snapshot"
        )
    result = check(
        args.runtime_root,
        managed_counts_evidence=args.managed_counts_evidence,
        automation_snapshot=args.automation_snapshot,
        require_workers_loaded=not args.preflight,
    )
    output = result if args.private else shareable_acceptance_report(result)
    if args.out:
        write_json(args.out, output)
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
