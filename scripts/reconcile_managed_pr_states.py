#!/usr/bin/env python3
"""Apply an exact read-only GitHub PR state snapshot to a managed copy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_lifecycle import reconcile_managed_pr_states  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-copy", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--observed-at")
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    observations = payload.get("observations", payload) if isinstance(payload, dict) else payload
    if not isinstance(observations, list):
        raise ValueError("input must be a JSON array or an object with observations")
    result = reconcile_managed_pr_states(
        args.db_copy,
        observations,
        observed_at=args.observed_at,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
