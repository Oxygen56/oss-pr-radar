#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.publication import broker_publication_request  # noqa: E402
from oss_pr_radar.release_binding import bind_runtime, runtime_ledger_path  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, default=None)
    args = parser.parse_args()
    runtime_root = args.runtime_root.resolve()
    expected_ledger = runtime_ledger_path(runtime_root).resolve()
    if args.ledger is None:
        args.ledger = expected_ledger
    elif args.ledger.resolve() != expected_ledger:
        print(json.dumps({"ok": False, "error": "ledger must be the runtime ledger"}))
        return 2
    try:
        bind_runtime(runtime_root, code_root=ROOT)
        require_operational_authorization(runtime_root)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)[:300]}))
        return 2
    result = broker_publication_request(
        RadarLedger(args.ledger),
        args.request_id,
        review_state_root=runtime_root,
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
