#!/usr/bin/env python3
"""Run one deterministic daily War Room cycle from an explicit runtime root."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.daily_war_room import run_daily_cycle  # noqa: E402
from oss_pr_radar.notifier import FeishuClient  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.release_binding import bind_runtime  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--send", action="store_true")
    args = parser.parse_args()
    binding = bind_runtime(args.runtime_root, code_root=ROOT)
    try:
        require_operational_authorization(args.runtime_root)
    except RuntimeError as exc:
        raise SystemExit(f"blocked: operational authorization required ({exc})") from exc
    sender = None
    if args.send:
        app_id = os.environ.get("FEISHU_APP_ID")
        app_secret = os.environ.get("FEISHU_APP_SECRET")
        chat_id = os.environ.get("FEISHU_CHAT_ID")
        if not app_id or not app_secret or not chat_id:
            raise SystemExit("authenticated Feishu credentials are required for --send")
        client = FeishuClient(app_id, app_secret, chat_id)

        def sender(event: dict) -> str:
            response = client.send_card(event["card"], idempotency_key=event["idempotencyKey"])
            return str((response.get("data") or {}).get("message_id") or "")

    result = run_daily_cycle(args.runtime_root, ledger=args.ledger, send=args.send, sender=sender)
    result["release"] = {
        "releaseId": binding.release_id,
        "path": str(binding.code_root),
        "manifestSha256": binding.release.get("manifestSha256"),
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
