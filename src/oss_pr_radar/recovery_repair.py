"""Safe, durable repair of historical event-lane outcome recoveries.

This module only changes local SQLite state.  It never creates an outcome and
never talks to GitHub.  A historical recovery is rearmed at most once by this
mechanism, with the old receipt retained as provenance.  A later, genuinely
completed machine outcome can instead supersede the stale chain.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .agentscope_events import EventLane

_REARM_SCHEMA = "oss-pr-radar-model-compatibility-rearm-v1"
_MAX_REARM_HISTORY = 4
_TERMINAL_STATUSES = {"completed", "failed", "interrupted"}
_OUTCOME_STATES = {"no_action", "claimed_or_pr", "design_wait"}


def event_artifact_path(
    root: Path,
    directory: str,
    event_id: str,
    *,
    attempt: int = 1,
    is_recovery: bool = False,
    generation: object = None,
) -> Path:
    """Return an evidence path that cannot collide across recovery generations.

    The first implementation keyed every recovery receipt only by event id.
    Re-arming an exhausted row then found the old terminal receipt before a
    new bridge turn could be created.  A generation is deliberately part of
    the filename, while the old generation remains on disk as evidence.
    ``attempt`` is retained for the within-generation retry identity.
    """
    identity = str(event_id)
    if is_recovery:
        normalized_generation = str(generation or "").strip()
        if normalized_generation and normalized_generation not in {"0", "none"}:
            identity += f":generation:{normalized_generation}"
        if int(attempt) > 1:
            identity += f":attempt:{int(attempt)}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return Path(root) / "state" / directory / f"{digest}.json"


def _object(raw: object) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    try:
        value = json.loads(str(raw or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return dict(value) if isinstance(value, dict) else {}


def _time(value: object) -> float | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).timestamp()


def _stamp(now: float) -> str:
    return datetime.fromtimestamp(now, UTC).isoformat().replace("+00:00", "Z")


def _root_id(event: dict[str, Any]) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return str(
        event.get("rootEventId")
        or payload.get("rootEventId")
        or event.get("eventIdSource")
        or payload.get("eventId")
        or ""
    )


def _recovery_id(namespace: str, root_event_id: str) -> str:
    digest = hashlib.sha256(str(root_event_id).encode("utf-8")).hexdigest()
    return f"outcome-reconcile:{namespace}:{digest}"


def _event_time(event: dict[str, Any]) -> float | None:
    """Prefer the GitHub observation time, then fall back to ingestion time."""
    for key in ("updatedAt", "updated_at", "createdAt", "created_at"):
        value = _time(event.get(key))
        if value is not None:
            return value
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    for key in ("updated_at", "updatedAt", "created_at", "createdAt"):
        value = _time(issue.get(key))
        if value is not None:
            return value
    return None


def _valid_outcome(
    receipt: dict[str, Any], event_id: str, event_key: str, namespace: str
) -> bool:
    """Accept only a completed wrapper and the exact namespaced outcome."""
    if str(receipt.get("turnStatus") or "") != "completed":
        return False
    outcome = receipt.get("outcome")
    if not isinstance(outcome, dict) or outcome.get("error"):
        return False
    if (
        outcome.get("schemaVersion") != f"{namespace}_event_outcome_v1"
        or str(outcome.get("eventId") or "") != str(event_id)
        or str(outcome.get("publicKey") or "") != str(event_key)
    ):
        return False
    state = str(outcome.get("state") or "")
    if state not in _OUTCOME_STATES:
        return False
    expected = {"schemaVersion", "eventId", "publicKey", "state"}
    if state == "design_wait":
        expected.update({"waitStartedAt", "waitUntil"})
    if set(outcome) != expected:
        return False
    if state == "design_wait":
        started = _time(outcome.get("waitStartedAt"))
        until = _time(outcome.get("waitUntil"))
        if started is None or until is None or until < started or until - started > 24 * 60 * 60:
            return False
    return True


def _is_recovery(event_id: str, event: dict[str, Any], namespace: str) -> bool:
    return (
        event.get("kind") == "outcome_reconcile"
        and str(event_id).startswith(f"outcome-reconcile:{namespace}:")
    )


def _lineage_valid(
    event_id: str,
    event: dict[str, Any],
    root_id: str,
    root: dict[str, Any],
    key: str,
    namespace: str,
) -> bool:
    if event_id != _recovery_id(namespace, root_id):
        return False
    if not re.fullmatch(r"[^:#/]+/[^:#/]+#[1-9][0-9]*", key):
        return False
    number = key.rsplit("#", 1)[1]
    repo = key.rsplit("#", 1)[0]
    root_kind = str(root.get("kind") or "")
    if root_kind not in {"issue_update", "pr_update"}:
        return False
    if (
        str(root.get("eventId") or "") != root_id
        or str(root.get("repo") or "") != repo
        or str(root.get("number") or "") != number
        or str(root.get("eventKey") or key) != key
        or not root_id.startswith(f"github:{repo}:{number}:{root_kind}:")
    ):
        return False
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return bool(
        str(event.get("rootEventId") or "") == root_id
        and str(event.get("eventIdSource") or "") == root_id
        and str(event.get("eventKey") or "") == key
        and str(payload.get("eventId") or "") == root_id
        and str(payload.get("rootEventId") or "") == root_id
        and str(payload.get("publicKey") or "") == key
    )


def _later_valid_turn(
    db: Any,
    *,
    key: str,
    root_id: str,
    root: dict[str, Any],
    root_created: float,
    namespace: str,
) -> dict[str, Any] | None:
    root_time = _event_time(root)
    rows = db.execute(
        "SELECT t.event_id,t.turn_id,t.status,t.created_at,t.receipt_json,e.payload_json "
        "FROM event_lane_turns t LEFT JOIN event_lane_events e USING(event_id) "
        "WHERE t.event_key=? AND t.event_id<>? ORDER BY t.created_at",
        (key, root_id),
    ).fetchall()
    for row in rows:
        event_id = str(row["event_id"])
        receipt = _object(row["receipt_json"])
        if not _valid_outcome(receipt, event_id, key, namespace):
            continue
        event = _object(row["payload_json"])
        if _is_recovery(event_id, event, namespace):
            # A valid recovery for the same historical chain is handled by
            # the normal migration path, not treated as a newer observation.
            if _root_id(event) == root_id:
                continue
        candidate_time = _event_time(event)
        if root_time is not None and candidate_time is not None:
            if candidate_time < root_time:
                continue
            if candidate_time == root_time and float(row["created_at"] or 0) <= root_created:
                continue
        elif float(row["created_at"] or 0) <= root_created:
            continue
        return dict(row)
    return None


def _repair_marker(event: dict[str, Any]) -> dict[str, Any] | None:
    marker = event.get("historicalModelRepair")
    if not isinstance(marker, dict):
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        marker = payload.get("historicalModelRepair")
    if not isinstance(marker, dict) or marker.get("schemaVersion") != _REARM_SCHEMA:
        return None
    if marker.get("state") not in {"rearmed", "eligible"}:
        return None
    if not marker.get("originalPayloadSha256") or not marker.get("originalReceiptSha256"):
        return None
    return dict(marker)


def _live_receipt(receipt: dict[str, Any]) -> bool:
    # Import lazily so the repair module remains usable with old test doubles.
    from .agentscope_events import _receipt_has_live_bridge

    return _receipt_has_live_bridge(receipt)


def rearm_historical_recoveries(
    lane: EventLane,
    *,
    namespace: str,
    now: float | None = None,
    max_automatic_rearms: int = 1,
) -> dict[str, int]:
    """Atomically rearm eligible historical model-failure recoveries.

    No outcome is invented.  If a later valid outcome already covers a root,
    the stale chain is explicitly marked superseded instead.
    """
    current = time.time() if now is None else float(now)
    stamp = _stamp(current)
    stats = {"candidates": 0, "rearmed": 0, "superseded": 0, "skipped": 0}
    with lane.writer() as db:
        rows = db.execute(
            "SELECT e.event_id,e.status,e.attempts,e.created_at,e.payload_json,"
            "t.status AS turn_status,t.thread_id,t.turn_id,t.receipt_json "
            "FROM event_lane_events e JOIN event_lane_turns t USING(event_id) "
            "WHERE e.status='needs_reconcile' AND e.attempts>=? "
            "AND t.status='needs_reconcile'",
            (lane.max_attempts,),
        ).fetchall()
        records: dict[str, dict[str, Any]] = {}
        for row in rows:
            event = _object(row["payload_json"])
            event_id = str(row["event_id"])
            records[event_id] = {"row": row, "event": event, "receipt": _object(row["receipt_json"])}
        for event_id, record in records.items():
            row = record["row"]
            event = record["event"]
            receipt = record["receipt"]
            if not _is_recovery(event_id, event, namespace):
                continue
            marker = _repair_marker(event)
            if marker is None:
                continue
            stats["candidates"] += 1
            raw_rearm_count = marker.get("automaticRearmCount")
            if raw_rearm_count is None:
                # The first repair release wrote only ``state=rearmed``.  It
                # was a manual compatibility marker, not a completed run of
                # this bounded automatic mechanism, so give it one honest
                # automatic opportunity and record the distinction below.
                rearm_count = 0
            else:
                try:
                    rearm_count = int(raw_rearm_count)
                except (TypeError, ValueError, OverflowError):
                    stats["skipped"] += 1
                    continue
            if rearm_count >= max_automatic_rearms:
                stats["skipped"] += 1
                continue
            root_id = _root_id(event)
            key = str(event.get("eventKey") or "")
            root_row = db.execute(
                "SELECT status,created_at,payload_json FROM event_lane_events WHERE event_id=?",
                (root_id,),
            ).fetchone()
            root_turn = db.execute(
                "SELECT status,thread_id,turn_id,receipt_json FROM event_lane_turns WHERE event_id=?",
                (root_id,),
            ).fetchone()
            if root_row is None or root_turn is None:
                stats["skipped"] += 1
                continue
            root = _object(root_row["payload_json"])
            root_receipt = _object(root_turn["receipt_json"])
            if not _lineage_valid(event_id, event, root_id, root, key, namespace):
                stats["skipped"] += 1
                continue
            if str(root_row["status"] or "") not in {"delivered", "needs_reconcile"}:
                stats["skipped"] += 1
                continue
            if str(root_turn["status"] or "") != "needs_reconcile":
                stats["skipped"] += 1
                continue
            if _valid_outcome(receipt, event_id, key, namespace) or _valid_outcome(
                root_receipt, root_id, key, namespace
            ):
                stats["skipped"] += 1
                continue
            if _live_receipt(receipt) or _live_receipt(root_receipt):
                stats["skipped"] += 1
                continue
            terminal = str(receipt.get("turnStatus") or "")
            reason = str(receipt.get("terminalReason") or event.get("terminalReason") or "")
            if terminal not in _TERMINAL_STATUSES and not reason:
                stats["skipped"] += 1
                continue
            newer = _later_valid_turn(
                db,
                key=key,
                root_id=root_id,
                root=root,
                root_created=float(root_row["created_at"] or 0),
                namespace=namespace,
            )
            if newer is not None:
                target = {
                    "eventId": str(newer["event_id"]),
                    "turnId": str(newer["turn_id"] or ""),
                    "at": stamp,
                }
                _supersede_chain(db, records, event_id, root_id, target, stamp)
                stats["superseded"] += 1
                continue
            history = marker.get("rearmHistory")
            if not isinstance(history, list):
                history = []
            history = [item for item in history if isinstance(item, dict)][-(_MAX_REARM_HISTORY - 1) :]
            history.append(
                {
                    "at": stamp,
                    "fromAttempts": int(row["attempts"] or 0),
                    "fromTurnId": str(row["turn_id"] or ""),
                    "fromTerminalReason": reason[:160],
                }
            )
            marker.update(
                {
                    "state": "rearmed",
                    "automaticRearmCount": rearm_count + 1,
                    "lastAutomaticRearmAt": stamp,
                    "rearmHistory": history,
                }
            )
            repaired = dict(event)
            repaired["historicalModelRepair"] = marker
            # Advance the evidence generation before resetting attempts.  The
            # old fixed-name receipt is intentionally retained, but it must
            # never be mistaken for the new bridge turn.
            try:
                previous_generation = int(event.get("recoveryGeneration") or 0)
            except (TypeError, ValueError, OverflowError):
                previous_generation = 0
            repaired["recoveryGeneration"] = previous_generation + 1
            marker["lastArtifactGeneration"] = previous_generation + 1
            repaired.pop("terminalReason", None)
            repaired.pop("recoveryExhausted", None)
            repaired.pop("recoveryAttempts", None)
            repaired.pop("retryNotBefore", None)
            changed = db.execute(
                "UPDATE event_lane_events SET status='pending',attempts=0,payload_json=?,"
                "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                "WHERE event_id=? AND status='needs_reconcile' AND attempts=?",
                (json.dumps(repaired, sort_keys=True), event_id, int(row["attempts"] or 0)),
            )
            if changed.rowcount != 1:
                raise RuntimeError("historical recovery changed during rearm")
            stats["rearmed"] += 1
    return stats


def _supersede_chain(
    db: Any,
    records: dict[str, dict[str, Any]],
    recovery_id: str,
    root_id: str,
    target: dict[str, str],
    stamp: str,
) -> None:
    """Mark stale local rows covered by a real later result, preserving receipts."""
    for event_id, record in records.items():
        event = record["event"]
        if event_id != recovery_id and _root_id(event) != root_id:
            continue
        row = record["row"]
        marker = _repair_marker(event) or {}
        marker.update(
            {
                "state": "superseded",
                "supersededAt": stamp,
                "supersededByValidOutcome": target,
            }
        )
        repaired = dict(event)
        repaired["historicalModelRepair"] = marker
        repaired["terminalReason"] = "historical_recovery_superseded_by_valid_outcome"
        changed = db.execute(
            "UPDATE event_lane_events SET status='coalesced',payload_json=?,delivered_at=?,"
            "lease_until=NULL,lease_owner=NULL,lease_token=NULL "
            "WHERE event_id=? AND status='needs_reconcile' AND attempts=?",
            (json.dumps(repaired, sort_keys=True), time.time(), event_id, int(row["attempts"] or 0)),
        )
        if changed.rowcount:
            db.execute(
                "UPDATE event_lane_turns SET status='superseded' WHERE event_id=? "
                "AND status='needs_reconcile'",
                (event_id,),
            )
    root_row = db.execute(
        "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
        (root_id,),
    ).fetchone()
    root_turn = db.execute(
        "SELECT status FROM event_lane_turns WHERE event_id=?", (root_id,)
    ).fetchone()
    if root_row is not None and root_turn is not None:
        if str(root_row["status"] or "") in {"delivered", "needs_reconcile"} and str(
            root_turn["status"] or ""
        ) == "needs_reconcile":
            root = _object(root_row["payload_json"])
            root["terminalReason"] = "historical_recovery_superseded_by_valid_outcome"
            root["supersededByValidOutcome"] = target
            db.execute(
                "UPDATE event_lane_events SET status='coalesced',payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=?",
                (json.dumps(root, sort_keys=True), time.time(), root_id),
            )
            db.execute(
                "UPDATE event_lane_turns SET status='superseded' WHERE event_id=? AND status='needs_reconcile'",
                (root_id,),
            )


def migrate_completed_recovery_chains(
    lane: EventLane, *, namespace: str, now: float | None = None
) -> dict[str, int]:
    """Close local ancestors only after a strict completed recovery outcome."""
    stamp = _stamp(time.time() if now is None else float(now))
    changed_events = 0
    changed_turns = 0
    with lane.writer() as db:
        rows = db.execute(
            "SELECT e.event_id,e.status,e.payload_json,t.status AS turn_status,t.receipt_json "
            "FROM event_lane_events e JOIN event_lane_turns t USING(event_id) "
            "WHERE e.status='delivered' AND t.status='completed'"
        ).fetchall()
        for row in rows:
            event_id = str(row["event_id"])
            event = _object(row["payload_json"])
            if not _is_recovery(event_id, event, namespace):
                continue
            key = str(event.get("eventKey") or "")
            root_id = _root_id(event)
            root_row = db.execute(
                "SELECT status,payload_json FROM event_lane_events WHERE event_id=?", (root_id,)
            ).fetchone()
            root_turn = db.execute(
                "SELECT status FROM event_lane_turns WHERE event_id=?", (root_id,)
            ).fetchone()
            if root_row is None or root_turn is None or not _valid_outcome(
                _object(row["receipt_json"]), event_id, key, namespace
            ):
                continue
            if str(root_row["status"] or "") not in {"delivered", "needs_reconcile"} or str(
                root_turn["status"] or ""
            ) != "needs_reconcile":
                continue
            root = _object(root_row["payload_json"])
            if not root or str(root.get("eventKey") or key) != key:
                continue
            root["terminalReason"] = "outcome_recovery_completed"
            root["recoveryResolvedBy"] = {"eventId": event_id, "at": stamp}
            event_changed = db.execute(
                "UPDATE event_lane_events SET status='coalesced',payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=? AND status=?",
                (json.dumps(root, sort_keys=True), time.time(), root_id, str(root_row["status"])),
            )
            turn_changed = db.execute(
                "UPDATE event_lane_turns SET status='superseded' WHERE event_id=? AND status='needs_reconcile'",
                (root_id,),
            )
            changed_events += event_changed.rowcount
            changed_turns += turn_changed.rowcount
    return {"eventsChanged": changed_events, "turnsChanged": changed_turns}
