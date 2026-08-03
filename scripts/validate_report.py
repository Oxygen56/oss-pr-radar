#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.contracts import ContractError, validate_report  # noqa: E402


def main() -> int:
    path = Path(sys.argv[1])
    report = json.loads(path.read_text(encoding="utf-8"))
    try:
        validation = validate_report(report, require_v2=True)
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    print(
        json.dumps(
            {
                "scan_ok": True,
                "schema_version": report.get("schema_version"),
                "run_id": report.get("run_id"),
                "report_digest": validation.digest,
                "candidates": validation.candidate_count,
                "auto_spawn_candidates": validation.auto_dispatch_count,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
