#!/usr/bin/env python3
"""Run one deterministic OSS PR Radar desktop controller cycle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.controller import (  # noqa: E402
    DEFAULT_PROJECT_ID,
    compact_controller_result,
    run_locked_controller_cycle,
    write_controller_report,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID)
    parser.add_argument("--no-notify", action="store_true")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    result = run_locked_controller_cycle(
        args.root,
        notify=not args.no_notify,
        project_id=args.project_id,
    )
    report_path = write_controller_report(args.root, result)
    output = result if args.full else compact_controller_result(result, report_path=report_path)
    print(json.dumps(output, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
