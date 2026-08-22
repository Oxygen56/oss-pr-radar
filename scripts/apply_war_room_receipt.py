#!/usr/bin/env python3
"""Apply authenticated USER_DECISION delivery results to managed and scanner state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_adapter import ManagedAdapter  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402
from oss_pr_radar.war_room_delivery import validate_receipt_document  # noqa: E402


def _read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def apply(
    *,
    ledger_path: Path,
    outbox: dict,
    receipt: dict,
    seen_path: Path,
) -> dict[str, int]:
    if (
        outbox.get("schema") != "oss-pr-radar.war-room-outbox.v1"
        or outbox.get("channel") != "feishu"
    ):
        raise ValueError("unsupported War Room outbox")
    events = {
        str(event.get("eventId")): event
        for event in outbox.get("events") or []
        if isinstance(event, dict) and event.get("eventId")
    }
    if len(events) != len(outbox.get("events") or []):
        raise ValueError("War Room outbox events are invalid")
    artifact_digest = str(outbox.get("sourceArtifactDigest") or "")
    validate_receipt_document(receipt, artifact_digest=artifact_digest, events=events)

    seen = _read(seen_path) if seen_path.exists() else {}
    adapter = ManagedAdapter(ROOT, ledger_path)
    applied = 0
    seen_updated = 0
    for delivered in receipt.get("events") or []:
        event = events[delivered["eventId"]]
        if event.get("actionKind") != "USER_DECISION":
            continue
        notification_digest = str(event.get("notificationDigest") or "")
        adapter.record_user_decision_delivery(
            candidate_key=str(event["candidateKey"]),
            notification_digest=notification_digest,
            channel=str(outbox["channel"]),
            status=str(delivered["status"]),
            receipt_id=str(delivered["receiptId"]),
            source_artifact_digest=artifact_digest,
            reconciliation_required=delivered.get("reconciliationRequired") is True,
            message_id=str(delivered.get("messageId") or ""),
            error=str(delivered.get("error") or ""),
        )
        applied += 1
        entry = seen.get(event["candidateKey"])
        if not isinstance(entry, dict) or entry.get("notification_digest") != notification_digest:
            continue
        updated = dict(entry)
        if delivered["status"] == "SENT":
            updated.update({"notified": True, "status": "notified"})
            updated.pop("send_error", None)
            updated.pop("reconciliation_required", None)
        else:
            updated.update(
                {
                    "notified": False,
                    "status": "send_failed",
                    "send_error": str(delivered.get("error") or "")[:240],
                    "reconciliation_required": delivered.get("reconciliationRequired") is True,
                }
            )
        seen[event["candidateKey"]] = updated
        seen_updated += 1
    if seen_updated:
        atomic_write_json(seen_path, seen)
    return {"applied": applied, "seenUpdated": seen_updated}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", type=Path)
    parser.add_argument("outbox", type=Path)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("seen", type=Path)
    args = parser.parse_args()
    result = apply(
        ledger_path=args.ledger,
        outbox=_read(args.outbox),
        receipt=_read(args.receipt),
        seen_path=args.seen,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
