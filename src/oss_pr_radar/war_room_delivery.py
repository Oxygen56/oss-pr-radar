"""Authenticated War Room delivery transitions."""

from __future__ import annotations

from typing import Any

from .managed_security import sign_current, verify_current
from .util import sha256_json
from .war_room_messages import canonical_event_digest

DELIVERY_RECEIPT_SCHEMA = "oss-pr-radar.war-room-delivery-receipt.v1"
DELIVERY_CONTEXT = "war-room-delivery-v1"
DELIVERY_STATUSES = {"SENT", "FAILED"}
MAX_ERROR_LENGTH = 240


def _error(value: Any) -> str:
    return str(value or "").strip()[:MAX_ERROR_LENGTH]


def _payload(
    *,
    artifact_digest: str,
    event: dict[str, Any],
    status: str,
    message_id: str = "",
    error: str = "",
    reconciliation_required: bool = False,
) -> dict[str, Any]:
    if status not in DELIVERY_STATUSES:
        raise ValueError("delivery receipt status is invalid")
    if not artifact_digest or not event.get("eventId"):
        raise ValueError("delivery receipt identity is missing")
    if not event.get("taskId") or not event.get("attemptId"):
        raise ValueError("delivery receipt task or attempt is missing")
    message_id = str(message_id or "").strip()
    error = _error(error)
    if status == "SENT" and not message_id:
        raise ValueError("SENT delivery receipt requires a message ID")
    if status == "FAILED" and (message_id or not error):
        raise ValueError("FAILED delivery receipt requires an error and no message ID")
    return {
        "schema": DELIVERY_RECEIPT_SCHEMA,
        "artifactDigest": artifact_digest,
        "eventId": event["eventId"],
        "idempotencyKey": event["idempotencyKey"],
        "candidateKey": event["candidateKey"],
        "taskId": event["taskId"],
        "attemptId": event["attemptId"],
        "canonicalEventDigest": canonical_event_digest(event),
        "channel": "feishu",
        "status": status,
        "messageId": message_id,
        "error": error,
        "reconciliationRequired": bool(reconciliation_required),
    }


def sign_delivery_receipt(
    *,
    artifact_digest: str,
    event: dict[str, Any],
    status: str,
    message_id: str = "",
    error: str = "",
    reconciliation_required: bool = False,
) -> dict[str, Any]:
    payload = _payload(
        artifact_digest=artifact_digest,
        event=event,
        status=status,
        message_id=message_id,
        error=error,
        reconciliation_required=reconciliation_required,
    )
    auth = sign_current(payload, context=DELIVERY_CONTEXT)
    if not auth.get("keyId") or not auth.get("signature"):
        raise ValueError("current signing key is required for delivery receipt")
    return {
        **payload,
        **auth,
        "receiptId": sha256_json(payload),
    }


def verify_delivery_receipt(
    receipt: dict[str, Any], *, artifact_digest: str, event: dict[str, Any]
) -> None:
    if not isinstance(receipt, dict):
        raise ValueError("delivery receipt must be an object")
    if receipt.get("schema") != DELIVERY_RECEIPT_SCHEMA:
        raise ValueError("unsupported delivery receipt")
    expected = _payload(
        artifact_digest=artifact_digest,
        event=event,
        status=receipt.get("status"),
        message_id=receipt.get("messageId", ""),
        error=receipt.get("error", ""),
        reconciliation_required=receipt.get("reconciliationRequired", False),
    )
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError("delivery receipt binding changed")
    if receipt.get("receiptId") != sha256_json(expected):
        raise ValueError("delivery receipt ID is invalid")
    if not verify_current(
        expected,
        context=DELIVERY_CONTEXT,
        key_id=receipt.get("keyId"),
        signature=receipt.get("signature"),
    ):
        raise ValueError("delivery receipt signature is invalid or stale")


def build_receipt_document(*, artifact_digest: str, receipts: list[dict[str, Any]]) -> dict[str, Any]:
    event_ids = [receipt.get("eventId") for receipt in receipts]
    if any(not event_id for event_id in event_ids) or len(event_ids) != len(set(event_ids)):
        raise ValueError("delivery receipt contains duplicate or missing events")
    result = {
        "schema": DELIVERY_RECEIPT_SCHEMA,
        "channel": "feishu",
        "sourceArtifactDigest": artifact_digest,
        "events": receipts,
    }
    result["digest"] = sha256_json(result)
    return result


def validate_receipt_document(
    receipt: dict[str, Any], *, artifact_digest: str, events: dict[str, dict[str, Any]]
) -> None:
    if receipt.get("schema") != DELIVERY_RECEIPT_SCHEMA or receipt.get("channel") != "feishu":
        raise ValueError("unsupported War Room delivery receipt")
    if receipt.get("sourceArtifactDigest") != artifact_digest:
        raise ValueError("delivery receipt artifact binding changed")
    unsigned = {key: value for key, value in receipt.items() if key != "digest"}
    if receipt.get("digest") != sha256_json(unsigned):
        raise ValueError("delivery receipt document digest is invalid")
    received = receipt.get("events")
    if not isinstance(received, list):
        raise ValueError("delivery receipt events are invalid")
    ids = [event.get("eventId") for event in received if isinstance(event, dict)]
    if len(ids) != len(received) or len(ids) != len(set(ids)):
        raise ValueError("delivery receipt contains duplicate or missing events")
    if set(ids) - set(events):
        raise ValueError("delivery receipt contains an unknown event")
    for event in received:
        verify_delivery_receipt(event, artifact_digest=artifact_digest, event=events[event["eventId"]])
