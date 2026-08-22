#!/usr/bin/env python3
"""Send only the authenticated War Room Feishu projection."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.notifier import FeishuClient, NotificationError  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402
from oss_pr_radar.war_room_delivery import (  # noqa: E402
    build_receipt_document,
    sign_delivery_receipt,
)
from oss_pr_radar.war_room_messages import build_outbox, validate_outboxes  # noqa: E402
from oss_pr_radar.war_room_projection import validate_projection  # noqa: E402


def validate(value: dict) -> None:
    if value.get("schema") != "oss-pr-radar.war-room-outbox.v1":
        raise ValueError("unsupported War Room outbox")
    if value.get("channel") != "feishu":
        raise ValueError("only Feishu War Room outbox may be sent")
    if set(value) != {"schema", "channel", "sourceArtifactDigest", "events"}:
        raise ValueError("War Room delivery input must be a canonical queue")
    events = value.get("events")
    if not isinstance(events, list):
        raise ValueError("War Room events are missing")
    for event in events:
        if event.get("status") != "PENDING":
            raise ValueError("War Room sender accepts PENDING events only")
        if set(event) != {
            "eventId",
            "candidateKey",
            "taskId",
            "actionKind",
            "notificationDigest",
            "title",
            "reason",
            "nextAction",
            "status",
            "idempotencyKey",
            "card",
            "attemptId",
        }:
            raise ValueError("War Room queue event is not canonical")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    outbox = json.loads(args.input.read_text(encoding="utf-8"))
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    validate_projection(artifact)
    validate(outbox)
    if outbox.get("sourceArtifactDigest") != artifact.get("artifactDigest"):
        raise ValueError("War Room outbox is not bound to the supplied artifact")
    expected = build_outbox(artifact, channel="feishu")
    validate_outboxes(
        artifact,
        {"feishu": outbox, "codex": build_outbox(artifact, channel="codex")},
    )
    if [event.get("candidateKey") for event in outbox.get("events") or []] != [
        event.get("candidateKey") for event in expected.get("events") or []
    ]:
        raise ValueError("War Room outbox candidates changed after export")
    pending = outbox.get("events") or []
    receipts = []
    app_id = os.environ.get("FEISHU_APP_ID")
    app_secret = os.environ.get("FEISHU_APP_SECRET")
    chat_id = os.environ.get("FEISHU_CHAT_ID")
    client = (
        FeishuClient(app_id, app_secret, chat_id) if app_id and app_secret and chat_id else None
    )
    for event in pending:
        if client is None:
            receipts.append(
                sign_delivery_receipt(
                    artifact_digest=artifact["artifactDigest"],
                    event=event,
                    status="FAILED",
                    error="Feishu credentials are not configured",
                )
            )
            continue
        try:
            response = client.send_card(event["card"], idempotency_key=event["idempotencyKey"])
            message_id = str((response.get("data") or {}).get("message_id") or "").strip()
            if not message_id:
                receipts.append(
                    sign_delivery_receipt(
                        artifact_digest=artifact["artifactDigest"],
                        event=event,
                        status="FAILED",
                        error="Feishu response missing message_id; reconciliation required",
                        reconciliation_required=True,
                    )
                )
            else:
                receipts.append(
                    sign_delivery_receipt(
                        artifact_digest=artifact["artifactDigest"],
                        event=event,
                        status="SENT",
                        message_id=message_id,
                    )
                )
        except NotificationError as exc:
            receipts.append(
                sign_delivery_receipt(
                    artifact_digest=artifact["artifactDigest"],
                    event=event,
                    status="FAILED",
                    error=str(exc),
                    reconciliation_required=True,
                )
            )
        except Exception as exc:  # keep ambiguous post-send failures fail-closed
            receipts.append(
                sign_delivery_receipt(
                    artifact_digest=artifact["artifactDigest"],
                    event=event,
                    status="FAILED",
                    error=f"send failed: {exc}",
                    reconciliation_required=True,
                )
            )
    receipt = build_receipt_document(artifact_digest=artifact["artifactDigest"], receipts=receipts)
    atomic_write_json(args.output, receipt)
    failed = sum(event.get("status") == "FAILED" for event in receipts)
    print(json.dumps({"sent": len(receipts) - failed, "failed": failed}))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
