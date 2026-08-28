#!/usr/bin/env python3
"""Run the one serialized slow worker for network and publication effects."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.local_publication import (  # noqa: E402
    SLOW_WORKER_LABEL,
    slow_advance_once,
    worker_log_paths,
)
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.runtime import rotate_log  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        require_operational_authorization(args.root)
    except RuntimeError as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "blocked": "operational authorization required",
                    "error": str(exc)[:400],
                }
            )
        )
        return 1
    stdout_path, stderr_path = worker_log_paths(SLOW_WORKER_LABEL, home=Path.home())
    rotate_log(stdout_path)
    rotate_log(stderr_path)
    result = slow_advance_once(args.root)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
