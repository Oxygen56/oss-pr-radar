#!/usr/bin/env python3
"""Apply Codex USER_DECISION delivery feedback from the controller state branch."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_adapter import ManagedAdapter  # noqa: E402
from oss_pr_radar.util import sha256_json  # noqa: E402
from oss_pr_radar.war_room_messages import canonical_event_digest  # noqa: E402

FEEDBACK_SCHEMA = "oss-pr-radar.codex-decision-feedback.v1"
OUTBOX_SCHEMA = "oss-pr-radar.war-room-outbox.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def _skip(result: dict[str, Any], event_id: str, reason: str) -> None:
    result["skipped"] += 1
    result["skippedEvents"].append({"eventId": event_id, "reason": reason})


def _current_events(outbox: dict[str, Any] | None) -> tuple[str, dict[str, dict[str, Any]]]:
    if outbox is None:
        return "", {}
    if outbox.get("schema") != OUTBOX_SCHEMA or outbox.get("channel") != "codex":
        raise ValueError("unsupported Codex War Room outbox")
    source_digest = str(outbox.get("sourceArtifactDigest") or "")
    if not SHA256_RE.fullmatch(source_digest):
        raise ValueError("Codex War Room outbox artifact digest is invalid")
    raw_events = outbox.get("events")
    if not isinstance(raw_events, list):
        raise ValueError("Codex War Room outbox events are invalid")
    events: dict[str, dict[str, Any]] = {}
    for event in raw_events:
        if not isinstance(event, dict) or not SHA256_RE.fullmatch(str(event.get("eventId") or "")):
            raise ValueError("Codex War Room outbox events are invalid")
        event_id = str(event["eventId"])
        if event_id in events:
            raise ValueError("Codex War Room outbox contains duplicate events")
        events[event_id] = event
    return source_digest, events


def _valid_timestamp(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def apply(
    *,
    ledger_path: Path,
    feedback: dict[str, Any],
    outbox: dict[str, Any] | None,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Apply current, exactly bound Codex receipts and skip stale feedback."""

    if feedback.get("schema") != FEEDBACK_SCHEMA:
        raise ValueError("unsupported controller decision feedback")
    feedback_events = feedback.get("events")
    if not isinstance(feedback_events, dict):
        raise ValueError("controller decision feedback events are invalid")

    source_digest, current_events = _current_events(outbox)
    result: dict[str, Any] = {
        "ok": True,
        "applied": 0,
        "duplicates": 0,
        "skipped": 0,
        "skippedEvents": [],
    }
    adapter = ManagedAdapter(root, ledger_path)
    for mapped_event_id in sorted(feedback_events):
        event_id = str(mapped_event_id)
        delivered = feedback_events[mapped_event_id]
        if not isinstance(delivered, dict) or str(delivered.get("eventId") or "") != event_id:
            _skip(result, event_id, "invalid_feedback_event")
            continue
        if not source_digest:
            _skip(result, event_id, "current_outbox_missing")
            continue
        if str(delivered.get("sourceArtifactDigest") or "") != source_digest:
            _skip(result, event_id, "stale_source_artifact")
            continue
        current = current_events.get(event_id)
        if current is None:
            _skip(result, event_id, "event_not_in_current_outbox")
            continue
        candidate_key = str(delivered.get("candidateKey") or "")
        notification_digest = str(delivered.get("notificationDigest") or "")
        if any(
            (
                current.get("actionKind") != "USER_DECISION",
                candidate_key != str(current.get("candidateKey") or ""),
                notification_digest != str(current.get("notificationDigest") or ""),
                not SHA256_RE.fullmatch(notification_digest),
                delivered.get("canonicalEventDigest") != canonical_event_digest(current),
            )
        ):
            _skip(result, event_id, "event_binding_mismatch")
            continue
        status = str(delivered.get("status") or "")
        receipt_id = str(delivered.get("receiptId") or "")
        delivery_id = str(delivered.get("deliveryId") or "")
        analyzed = str(delivered.get("analyzed") or "")
        expected_receipt_id = sha256_json(
            {
                "channel": "codex",
                "eventId": event_id,
                "candidateKey": candidate_key,
                "notificationDigest": notification_digest,
                "deliveryId": delivery_id,
                "status": "SENT",
            }
        )
        if any(
            (
                status != "SENT",
                not SHA256_RE.fullmatch(delivery_id),
                receipt_id != expected_receipt_id,
                not _valid_timestamp(analyzed),
            )
        ):
            _skip(result, event_id, "invalid_delivery_receipt")
            continue
        try:
            recorded = adapter.record_user_decision_delivery(
                candidate_key=candidate_key,
                notification_digest=notification_digest,
                channel="codex",
                status="SENT",
                receipt_id=receipt_id,
                source_artifact_digest=source_digest,
                message_id=delivery_id,
            )
        except ValueError:
            _skip(result, event_id, "managed_opportunity_mismatch")
            continue
        result["applied"] += 1
        if recorded.get("eventCreated") is False:
            result["duplicates"] += 1
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger",
        type=Path,
        default=ROOT / "state" / "radar_ledger.sqlite3",
    )
    parser.add_argument(
        "--feedback",
        type=Path,
        default=ROOT / "state" / "controller_decision_feedback.json",
    )
    parser.add_argument(
        "--outbox",
        type=Path,
        default=ROOT / "state" / "war_room_codex_outbox.json",
    )
    args = parser.parse_args()
    if not args.feedback.exists():
        result = {
            "ok": True,
            "applied": 0,
            "duplicates": 0,
            "skipped": 0,
            "skippedEvents": [],
        }
    else:
        result = apply(
            ledger_path=args.ledger,
            feedback=_read(args.feedback),
            outbox=_read(args.outbox) if args.outbox.exists() else None,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
