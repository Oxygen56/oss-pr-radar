"""Deterministic daily War Room cycle over one managed projection."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .release_binding import runtime_ledger_path
from .runtime import read_disk_pressure_gate_health
from .util import atomic_write_json, sha256_json
from .war_room_delivery import sign_delivery_receipt, verify_delivery_receipt
from .war_room_messages import build_outbox, canonical_event_digest, validate_outboxes
from .war_room_projection import build_views, export_projection, validate_views

DAILY_CYCLE_SCHEMA = "oss-pr-radar.daily-war-room-cycle.v1"
DELIVERY_STATE_SCHEMA = "oss-pr-radar.daily-war-room-delivery-state.v1"


def ledger_path(runtime_root: Path) -> Path:
    return runtime_ledger_path(runtime_root)


def _load_delivery_state(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != DELIVERY_STATE_SCHEMA:
        raise ValueError("daily War Room delivery state is invalid")
    entries = value.get("events")
    if not isinstance(entries, dict):
        raise ValueError("daily War Room delivery state events are invalid")
    result: dict[str, dict[str, Any]] = {}
    for event_id, record in entries.items():
        if not isinstance(record, dict):
            raise ValueError("daily War Room delivery state record is invalid")
        event = record.get("event")
        receipt = record.get("receipt")
        artifact_digest = record.get("artifactDigest")
        if not isinstance(event, dict) or not isinstance(receipt, dict) or not artifact_digest:
            raise ValueError("daily War Room delivery state record is incomplete")
        verify_delivery_receipt(receipt, artifact_digest=artifact_digest, event=event)
        if event.get("eventId") != event_id:
            raise ValueError("daily War Room delivery state identity changed")
        result[event_id] = record
    return result


def _write_delivery_state(path: Path, entries: dict[str, dict[str, Any]]) -> None:
    atomic_write_json(
        path,
        {
            "schema": DELIVERY_STATE_SCHEMA,
            "events": entries,
            "digest": sha256_json(entries),
        },
    )


def run_daily_cycle(
    runtime_root: Path,
    *,
    ledger: Path | None = None,
    send: bool = False,
    sender: Callable[[dict[str, Any]], str] | None = None,
    automation_run_id: str | None = None,
) -> dict[str, Any]:
    """Write the shared artifact/views/outboxes and optionally send new events.

    Delivery identity is derived from candidate content, not the global
    projection digest.  An unrelated candidate changing therefore does not
    resend an already authenticated event.
    """

    runtime_root = runtime_root.resolve()
    runtime_ledger = ledger_path(runtime_root).resolve()
    if send and ledger is not None:
        raise ValueError("--send may only use the runtime current-ledger pointer")
    ledger = runtime_ledger if send else (ledger or runtime_ledger).resolve()
    if send and ledger != runtime_ledger:
        raise ValueError("--send ledger is not the runtime current-ledger target")
    report_root = runtime_root / "reports" / "war-room" / "daily"
    state_path = runtime_root / "state" / "war-room-delivery-state.json"
    report_root.mkdir(parents=True, exist_ok=True)
    artifact = export_projection(ledger, report_root / "projection.json")
    views = build_views(artifact)
    validate_views(views)
    atomic_write_json(report_root / "views.json", views)
    feishu = build_outbox(artifact, channel="feishu")
    codex = build_outbox(artifact, channel="codex")
    validate_outboxes(artifact, {"feishu": feishu, "codex": codex})
    atomic_write_json(report_root / "outbox-feishu.json", feishu)
    atomic_write_json(report_root / "outbox-codex.json", codex)

    entries = _load_delivery_state(state_path)
    pending: list[dict[str, Any]] = []
    for event in feishu["events"]:
        old = entries.get(event["eventId"])
        if old and old.get("receipt", {}).get("status") == "SENT":
            if canonical_event_digest(old["event"]) == canonical_event_digest(event):
                continue
        pending.append(event)

    sent = 0
    failed = 0
    delivery_gate_blocked: dict[str, Any] | None = None
    if send:
        # This is the authoritative effect-time check.  Entry points may have
        # performed an earlier check before constructing credentials, but a
        # caller cannot supply or cache that authorization across projection
        # work and then send after the gate changes.
        gate_health = read_disk_pressure_gate_health(runtime_root)
        if (
            not isinstance(gate_health, dict)
            or gate_health.get("ok") is not True
            or gate_health.get("blocked") is not False
        ):
            cycle = {
                "schema": DAILY_CYCLE_SCHEMA,
                "ok": False,
                "cycleId": sha256_json(
                    {
                        "artifact": artifact["artifactDigest"],
                        "pending": [event["eventId"] for event in pending],
                    }
                ),
                "artifactDigest": artifact["artifactDigest"],
                "ledger": str(ledger),
                "buckets": {key: len(value) for key, value in artifact["buckets"].items()},
                "actionableCount": len(feishu["events"]),
                "newActionableCount": len(pending),
                "sent": 0,
                "failed": 0,
                "sendRequested": True,
                "blocked": "disk pressure gate blocked",
                "error": str(
                    gate_health.get("reason")
                    if isinstance(gate_health, dict)
                    else "DISK_PRESSURE_GATE_UNAVAILABLE"
                ),
                "diskPressureGate": gate_health,
                "publicReplies": "DRAFT_UNLESS_MANAGED_GATE_AUTHORIZES",
                "sharedChannelArtifact": True,
            }
            if automation_run_id:
                cycle["automationRunId"] = automation_run_id
            atomic_write_json(report_root / "cycle.json", cycle)
            return cycle
        if sender is None:
            raise ValueError("--send requires an authenticated sender")
        for event in pending:
            effect_gate_health = read_disk_pressure_gate_health(runtime_root)
            if (
                not isinstance(effect_gate_health, dict)
                or effect_gate_health.get("ok") is not True
                or effect_gate_health.get("blocked") is not False
            ):
                delivery_gate_blocked = effect_gate_health
                break
            try:
                message_id = str(sender(event)).strip()
                if not message_id:
                    raise ValueError("sender returned an empty message ID")
                receipt = sign_delivery_receipt(
                    artifact_digest=artifact["artifactDigest"],
                    event=event,
                    status="SENT",
                    message_id=message_id,
                )
                sent += 1
            except Exception as exc:
                receipt = sign_delivery_receipt(
                    artifact_digest=artifact["artifactDigest"],
                    event=event,
                    status="FAILED",
                    error=str(exc),
                    reconciliation_required=True,
                )
                failed += 1
            entries[event["eventId"]] = {
                "artifactDigest": artifact["artifactDigest"],
                "event": event,
                "receipt": receipt,
            }
        _write_delivery_state(state_path, entries)

    cycle = {
        "schema": DAILY_CYCLE_SCHEMA,
        "ok": failed == 0 and delivery_gate_blocked is None,
        "cycleId": sha256_json(
            {"artifact": artifact["artifactDigest"], "pending": [e["eventId"] for e in pending]}
        ),
        "artifactDigest": artifact["artifactDigest"],
        "ledger": str(ledger),
        "buckets": {key: len(value) for key, value in artifact["buckets"].items()},
        "actionableCount": len(feishu["events"]),
        "newActionableCount": len(pending),
        "sent": sent,
        "failed": failed,
        "sendRequested": send,
        "publicReplies": "DRAFT_UNLESS_MANAGED_GATE_AUTHORIZES",
        "sharedChannelArtifact": True,
    }
    if delivery_gate_blocked is not None:
        cycle.update(
            {
                "blocked": "disk pressure gate blocked",
                "error": str(
                    delivery_gate_blocked.get("reason") or "DISK_PRESSURE_GATE_UNAVAILABLE"
                ),
                "diskPressureGate": delivery_gate_blocked,
            }
        )
    if automation_run_id:
        cycle["automationRunId"] = automation_run_id
    atomic_write_json(report_root / "cycle.json", cycle)
    return cycle
