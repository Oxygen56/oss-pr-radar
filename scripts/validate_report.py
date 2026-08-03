#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    path = Path(sys.argv[1])
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("scan_ok") is not True:
        raise SystemExit(f"scan failed: {report.get('scan_error')}")
    details = report.get("candidate_details")
    if not isinstance(details, list):
        raise SystemExit("candidate_details is missing")
    for candidate in details:
        if "_llm_context" in candidate:
            raise SystemExit("untrusted LLM context leaked into report")
        review = candidate.get("llm_review") or {}
        if review.get("status") != "ok":
            candidate["auto_spawn"] = False
    print(
        json.dumps(
            {
                "scan_ok": True,
                "candidates": len(details),
                "auto_spawn_candidates": sum(
                    bool(item.get("auto_spawn")) for item in details
                ),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
