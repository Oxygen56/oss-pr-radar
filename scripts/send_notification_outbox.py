#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.notifier import FeishuClient, NotificationError  # noqa: E402
from oss_pr_radar.outbox import validate_outbox  # noqa: E402
from oss_pr_radar.util import atomic_write_json, iso_z, sha256_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    outbox = json.loads(args.input.read_text(encoding="utf-8"))
    validate_outbox(outbox)
    app_id = os.environ.get("FEISHU_APP_ID")
    app_secret = os.environ.get("FEISHU_APP_SECRET")
    chat_id = os.environ.get("FEISHU_CHAT_ID")
    if not app_id or not app_secret or not chat_id:
        raise SystemExit("Feishu credentials are not configured")
    client = FeishuClient(app_id, app_secret, chat_id)
    sent = 0
    failed = 0
    for event in outbox.get("events") or []:
        if event.get("status") == "SENT":
            continue
        event["attempts"] = int(event.get("attempts") or 0) + 1
        event["lastAttemptAt"] = iso_z(datetime.now(UTC))
        try:
            response = client.send_card(event["card"], idempotency_key=event["idempotencyKey"])
            event["status"] = "SENT"
            event["sentAt"] = iso_z(datetime.now(UTC))
            event["messageId"] = str((response.get("data") or {}).get("message_id") or "")
            event.pop("lastError", None)
            sent += 1
        except NotificationError as exc:
            event["status"] = "FAILED"
            event["lastError"] = str(exc)[:200]
            failed += 1
    outbox["digest"] = sha256_json({key: value for key, value in outbox.items() if key != "digest"})
    atomic_write_json(args.output, outbox)
    print(json.dumps({"sent": sent, "failed": failed}))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
