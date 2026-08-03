"""Durable notification outbox with deterministic idempotency keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .notifier import candidate_card
from .util import iso_z, parse_time, sha256_json

OUTBOX_VERSION = "notification_outbox_v1"


def build_outbox(
    report: dict[str, Any],
    existing: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
    kind: str = "immediate",
) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    keep_after = current - timedelta(days=7)
    retained: dict[str, dict[str, Any]] = {}
    if isinstance(existing, dict) and existing.get("version") == OUTBOX_VERSION:
        for event in existing.get("events") or []:
            if not isinstance(event, dict):
                continue
            try:
                if parse_time(str(event["createdAt"])) >= keep_after:
                    retained[str(event["eventId"])] = event
            except (KeyError, TypeError, ValueError):
                continue
    candidates = [
        item
        for item in report.get("candidate_details") or []
        if isinstance(item, dict)
        and (
            bool(item.get("auto_spawn"))
            if kind == "immediate"
            else not bool(item.get("auto_spawn"))
        )
    ]
    new_count = 0
    if candidates:
        basis = {
            "kind": kind,
            "candidates": [
                {
                    "key": f"{item['repo']}#{item['num']}",
                    "digest": item.get("notification_digest")
                    or item.get("evidence_digest"),
                    "category": item.get("category"),
                }
                for item in candidates
            ],
        }
        event_id = sha256_json(basis)
        if event_id not in retained:
            retained[event_id] = {
                "eventId": event_id,
                "idempotencyKey": event_id[:50],
                "kind": kind,
                "status": "PENDING",
                "attempts": 0,
                "createdAt": iso_z(current),
                "runId": report.get("run_id"),
                "candidateKeys": [item["key"] for item in basis["candidates"]],
                "card": candidate_card(
                    candidates,
                    title=(
                        "OSS PR Radar: 可立即执行"
                        if kind == "immediate"
                        else "OSS PR Radar: 需要确认"
                        if kind == "review"
                        else "OSS PR Radar: 状态更新"
                    ),
                ),
            }
            new_count = 1
    result = {
        "version": OUTBOX_VERSION,
        "generatedAt": iso_z(current),
        "events": sorted(retained.values(), key=lambda item: item["createdAt"]),
        "newEventCount": new_count,
    }
    result["digest"] = sha256_json(
        {key: value for key, value in result.items() if key != "digest"}
    )
    return result


def validate_outbox(outbox: dict[str, Any]) -> None:
    if outbox.get("version") != OUTBOX_VERSION:
        raise ValueError("unsupported notification outbox")
    expected = sha256_json(
        {key: value for key, value in outbox.items() if key != "digest"}
    )
    if outbox.get("digest") != expected:
        raise ValueError("notification outbox digest mismatch")


def merge_receipts(
    current: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    validate_outbox(current)
    validate_outbox(receipt)
    receipt_by_id = {
        item.get("eventId"): item
        for item in receipt.get("events") or []
        if isinstance(item, dict) and item.get("eventId")
    }
    merged = dict(current)
    merged["events"] = [
        receipt_by_id.get(item.get("eventId"), item)
        for item in current.get("events") or []
        if isinstance(item, dict)
    ]
    merged["digest"] = sha256_json(
        {key: value for key, value in merged.items() if key != "digest"}
    )
    return merged
