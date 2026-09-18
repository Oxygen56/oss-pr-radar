#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import (  # noqa: E402
    EventLane,
    GitHubIssuePoller,
    PollResult,
    advance_model_fallback,
    dispatch_once,
    github_event_effective_time,
)
from oss_pr_radar.claims import detect_claims  # noqa: E402
from oss_pr_radar.local_publication import run_bridge  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.recovery_repair import (  # noqa: E402
    event_artifact_path,
    migrate_unmarked_transient_model_recoveries,
    rearm_historical_recoveries,
)
from scripts.migrate_event_recovery_chains import (  # noqa: E402
    _declared_lineage_ids,
    _event_source,
    migrate_recovery_chains,
)


def _is_agentscope_record(value: dict) -> bool:
    repo = str(value.get("repo") or value.get("repository") or "").casefold()
    if repo == REPO.casefold():
        return True
    for key in ("key", "opportunityKey", "opportunity_key"):
        if str(value.get(key) or "").casefold().startswith(f"{REPO.casefold()}#"):
            return True
    for key in ("issueUrl", "issue_url", "prUrl", "pr_url"):
        if f"github.com/{REPO.casefold()}/" in str(value.get(key) or "").casefold():
            return True
    return False


EVENT_LANE_MANIFEST = "event-lane-manifest.json"
EVENT_LANE_DIGEST = "event-lane-manifest.sha256"
REPO = "agentscope-ai/agentscope"
CENTRAL_CWD = Path("/Users/oxygen/Documents/github/agentscope")
RECOVERY_EVENT_NAMESPACE = "agentscope"
EVENT_RECEIPT_DIR = "agentscope_event_receipts"
EVENT_OUTCOME_DIR = "agentscope_event_outcomes"
EXHAUSTED_EVIDENCE_RECHECK_SECONDS = 15 * 60
EXTERNAL_CLAIM_WATCH_SECONDS = 24 * 60 * 60
TRANSIENT_MODEL_RETRY_DELAY_SECONDS = 5 * 60
EVENT_MODEL_CANDIDATES = ("gpt-6-astra", "gpt-5.6-terra", "gpt-5.6-luna")
LEGACY_UNRECORDED_MODEL = "legacy-unrecorded"
_CONDITIONAL_EXTERNAL_CLAIM_RE = re.compile(
    r"(?:"
    r"\b(?:if|unless)\b.{0,160}\b(?:i(?:['’]?d|['’]?ll| am| will| would)|we)\b"
    r"|\bif\b.{0,160}\b(?:no one|nobody|not(?: already)?|still available|unclaimed)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_NEGATED_EXTERNAL_CLAIM_RE = re.compile(
    r"\b(?:i|we)\b.{0,20}\b(?:can't|cannot|can not|won['’]?t|will not|would not|do not|don't|never)\b",
    re.IGNORECASE | re.DOTALL,
)
_OPERATIONAL_AUTHORIZATION_GAP_ERRORS = frozenset(
    {
        f"operational authorization required: {reason}"
        for reason in (
            "operational authorization is missing or not a regular file",
            "operational authorization has not been activated",
            "operational authorization release binding mismatch",
            "operational authorization ledger pointer is invalid",
            "operational authorization ledger binding mismatch",
            "operational authorization is not yet valid",
            "operational authorization worker binding is invalid",
        )
    }
)
_WORKER_BINDING_AUTH_ERROR = (
    "operational authorization required: operational authorization worker binding is invalid"
)


def _transient_model_error(value: object) -> bool:
    """Allow only known, retryable Codex model-capacity/config errors."""
    if isinstance(value, dict):
        try:
            text = json.dumps(value, sort_keys=True)
        except (TypeError, ValueError):
            text = str(value)
    else:
        text = str(value or "")
    folded = text.casefold()
    return (
        "selected model is at capacity" in folded
        or "model is at capacity" in folded
        or "model is not supported when using codex with a chatgpt account" in folded
        or "usagelimitexceeded" in folded
        or "you've hit your usage limit" in folded
        or "serveroverloaded" in folded
        or "stream disconnected before completion" in folded
    )


def _event_model(event: dict) -> str:
    """Choose the first candidate not durably recorded as a capacity failure."""
    fallback = event.get("modelFallback") if isinstance(event.get("modelFallback"), dict) else {}
    history = fallback.get("history") if isinstance(fallback, dict) else []
    history = history if isinstance(history, list) else []
    attempted = {
        str(item.get("model") or "")
        for item in history
        if isinstance(item, dict) and str(item.get("model") or "") in EVENT_MODEL_CANDIDATES
    }
    for model in EVENT_MODEL_CANDIDATES:
        if model not in attempted:
            return model
    # The lane will terminalize this stale/invalid state before another turn
    # can start.  Returning the final candidate keeps the caller total.
    return EVENT_MODEL_CANDIDATES[-1]


def _record_transient_model_failure(
    lane: EventLane,
    *,
    event: dict,
    model: str,
    error: object,
) -> str:
    """Persist one capacity failure; no branch refunds its consumed attempt."""
    return lane.record_transient_model_failure(
        str(event.get("eventId") or ""),
        model=model,
        candidates=EVENT_MODEL_CANDIDATES,
        error=error,
        lease_token=str(event.get("leaseToken") or "") or None,
        retry_not_before=datetime.now(UTC).timestamp() + TRANSIENT_MODEL_RETRY_DELAY_SECONDS,
    )


def _is_operational_authorization_gap(value: object) -> bool:
    """Recognize only the exact pre-turn envelope for this bridge operation."""
    if isinstance(value, dict):
        return (
            set(value) == {"ok", "error", "turnStarted"}
            and value.get("ok") is False
            and value.get("turnStarted") is False
            and value.get("error") in _OPERATIONAL_AUTHORIZATION_GAP_ERRORS
        )
    if not isinstance(value, RuntimeError):
        return False
    prefix = "agentscope-event-create: "
    text = str(value)
    if not text.startswith(prefix):
        return False
    try:
        envelope = json.loads(text[len(prefix) :].strip())
    except json.JSONDecodeError:
        return False
    return (
        isinstance(envelope, dict)
        and set(envelope) == {"ok", "error"}
        and envelope.get("ok") is False
        and envelope.get("error") in _OPERATIONAL_AUTHORIZATION_GAP_ERRORS
    )


def _is_exact_exhausted_worker_binding_receipt(value: object) -> bool:
    """Match only the historical pre-turn failure shape produced by this lane."""
    if not isinstance(value, dict) or set(value) != {"error", "terminalReason"}:
        return False
    if value.get("terminalReason") != "handler_start_exception":
        return False
    error = value.get("error")
    prefix = "RuntimeError:agentscope-event-create: "
    if not isinstance(error, str) or not error.startswith(prefix):
        return False
    try:
        envelope = json.loads(error[len(prefix) :])
    except json.JSONDecodeError:
        return False
    return (
        isinstance(envelope, dict)
        and set(envelope) == {"ok", "error"}
        and envelope.get("ok") is False
        and envelope.get("error") == _WORKER_BINDING_AUTH_ERROR
    )


def _is_exact_exhausted_desktop_writer_receipt(
    value: object, *, event_id: str, event_key: str
) -> bool:
    """Match only an exhausted pre-turn desktop-writer collision.

    A collision is safe to retry only when the bridge proves that no turn was
    started.  Keep this deliberately narrower than a generic retryable error:
    the receipt must be the worker's complete, known envelope and must still
    be bound to the same lane event.
    """
    if not isinstance(value, dict) or set(value) != {
        "error",
        "eventId",
        "eventKey",
        "model",
        "ok",
        "retryable",
        "terminalReason",
        "turnId",
        "turnStarted",
        "workerPid",
    }:
        return False
    return bool(
        value.get("ok") is False
        and value.get("retryable") is True
        and value.get("turnStarted") is False
        and value.get("turnId") is None
        and value.get("terminalReason") == "handler_start_retryable"
        and value.get("eventId") == event_id
        and value.get("eventKey") == event_key
        and isinstance(value.get("model"), str)
        and value.get("model")
        and isinstance(value.get("workerPid"), int)
        and value.get("workerPid") > 0
        and isinstance(value.get("error"), str)
        and value["error"].startswith("RuntimeError:DESKTOP_ACTIVE_WRITER:")
    )


def _recovery_source_event_id(event: dict) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return str(
        event.get("rootEventId")
        or payload.get("rootEventId")
        or event.get("eventIdSource")
        or payload.get("eventId")
        or ""
    )


def _repair_exhausted_worker_binding_failures(root: Path, lane: EventLane) -> dict[str, object]:
    """Repair exact exhausted rows whose attempts were consumed by an auth gap.

    Authorization is verified before opening the lane writer.  The writer then
    re-reads and conditionally mutates every row in one transaction.  Row state
    is the idempotency boundary, so a leased row can be repaired on a later run
    after it expires without relying on a global completion marker.
    """
    try:
        authorization = require_operational_authorization(root)
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "authorization_unavailable",
            "requeued": 0,
            "coalesced": 0,
            "error": f"{type(exc).__name__}:{str(exc)[:300]}",
        }
    if authorization.get("state") != "ACTIVE":
        return {
            "status": "authorization_unavailable",
            "requeued": 0,
            "coalesced": 0,
            "error": "operational authorization is not active",
        }
    binding = {
        "releaseId": str(authorization.get("releaseId") or ""),
        "releaseHead": str(authorization.get("releaseHead") or ""),
        "releaseManifestSha256": str(authorization.get("releaseManifestSha256") or ""),
        "ledgerTarget": str(authorization.get("ledgerTarget") or ""),
    }
    if not all(binding.values()):
        return {
            "status": "authorization_unavailable",
            "requeued": 0,
            "coalesced": 0,
            "error": "operational authorization repair binding is incomplete",
        }

    with lane.writer() as db:
        try:
            current_authorization = require_operational_authorization(root)
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                "status": "authorization_changed",
                "requeued": 0,
                "coalesced": 0,
                "error": f"{type(exc).__name__}:{str(exc)[:300]}",
            }
        if any(current_authorization.get(key) != value for key, value in binding.items()):
            return {
                "status": "authorization_changed",
                "requeued": 0,
                "coalesced": 0,
                "error": "operational authorization binding changed before repair",
            }
        rows = db.execute(
            "SELECT e.event_id,e.status,e.attempts,e.payload_json,e.delivered_at,"
            "e.lease_owner,e.lease_token,t.status AS turn_status,t.thread_id,t.turn_id,"
            "t.receipt_json FROM event_lane_events e "
            "LEFT JOIN event_lane_turns t USING(event_id)"
        ).fetchall()
        records: dict[str, dict[str, object]] = {}
        for row in rows:
            try:
                event = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                event = {}
            try:
                receipt = json.loads(row["receipt_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                receipt = {}
            event_id = str(row["event_id"])
            is_recovery = event_id.startswith("outcome-reconcile:") or (
                isinstance(event, dict) and event.get("kind") == "outcome_reconcile"
            )
            eligible = bool(
                isinstance(event, dict)
                and str(row["status"] or "") in {"pending", "needs_reconcile"}
                and int(row["attempts"] or 0) >= lane.max_attempts
                and str(row["turn_status"] or "") == "needs_reconcile"
                and not str(row["thread_id"] or "")
                and not str(row["turn_id"] or "")
                and (
                    _is_exact_exhausted_worker_binding_receipt(receipt)
                    or _is_exact_exhausted_desktop_writer_receipt(
                        receipt,
                        event_id=event_id,
                        event_key=str(event.get("eventKey") or ""),
                    )
                )
            )
            records[event_id] = {
                "row": row,
                "event": event if isinstance(event, dict) else {},
                "eligible": eligible,
                "isRecovery": is_recovery,
            }

        def root_event_id(event_id: str) -> str:
            current = str(event_id)
            visited: set[str] = set()
            while current and current not in visited:
                visited.add(current)
                record = records.get(current)
                if record is None or not record["isRecovery"]:
                    return current
                source = _recovery_source_event_id(record["event"])
                if not source:
                    return current
                current = source
            return current or str(event_id)

        recovery_by_root: dict[str, list[str]] = {}
        for event_id, record in records.items():
            if record["isRecovery"]:
                recovery_by_root.setdefault(root_event_id(event_id), []).append(event_id)

        now = datetime.now(UTC).timestamp()
        requeued = 0
        coalesced = 0
        repaired_roots: set[str] = set()
        coalesced_recoveries: set[str] = set()

        def requeue(event_id: str) -> None:
            nonlocal requeued
            record = records[event_id]
            row = record["row"]
            event = dict(record["event"])
            for key in ("terminalReason", "recoveryExhausted", "recoveryAttempts"):
                event.pop(key, None)
            event["authorizationGapRepair"] = {
                "schemaVersion": "event_lane_worker_binding_auth_gap_repair_v1",
                "state": "requeued",
                **binding,
            }
            changed = db.execute(
                "UPDATE event_lane_events SET status='pending',attempts=0,payload_json=?,"
                "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                "WHERE event_id=? AND status=? AND attempts=? AND payload_json=?",
                (
                    json.dumps(event, sort_keys=True),
                    event_id,
                    str(row["status"]),
                    int(row["attempts"] or 0),
                    str(row["payload_json"]),
                ),
            )
            removed = db.execute(
                "DELETE FROM event_lane_turns WHERE event_id=? AND status='needs_reconcile' "
                "AND thread_id='' AND (turn_id IS NULL OR turn_id='') AND receipt_json=?",
                (event_id, str(row["receipt_json"])),
            )
            if changed.rowcount != 1 or removed.rowcount != 1:
                raise RuntimeError("authorization gap repair row changed during requeue")
            requeued += 1

        def coalesce(recovery_id: str, root_id: str) -> None:
            nonlocal coalesced
            record = records[recovery_id]
            row = record["row"]
            event = dict(record["event"])
            event["terminalReason"] = "prestart_authorization_gap_superseded"
            event["authorizationGapRepair"] = {
                "schemaVersion": "event_lane_worker_binding_auth_gap_repair_v1",
                "state": "superseded",
                "rootEventId": root_id,
                **binding,
            }
            changed = db.execute(
                "UPDATE event_lane_events SET status='coalesced',payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                "WHERE event_id=? AND status=? AND attempts=? AND payload_json=?",
                (
                    json.dumps(event, sort_keys=True),
                    now,
                    recovery_id,
                    str(row["status"]),
                    int(row["attempts"] or 0),
                    str(row["payload_json"]),
                ),
            )
            superseded = db.execute(
                "UPDATE event_lane_turns SET status='superseded' WHERE event_id=? "
                "AND status='needs_reconcile' AND thread_id='' "
                "AND (turn_id IS NULL OR turn_id='') AND receipt_json=?",
                (recovery_id, str(row["receipt_json"])),
            )
            if changed.rowcount != 1 or superseded.rowcount != 1:
                raise RuntimeError("authorization gap recovery changed during coalescing")
            coalesced += 1

        for event_id, record in records.items():
            if record["isRecovery"] or not record["eligible"]:
                continue
            linked = [
                recovery_id
                for recovery_id in recovery_by_root.get(event_id, [])
                if str(records[recovery_id]["row"]["status"] or "") != "coalesced"
            ]
            if any(not records[recovery_id]["eligible"] for recovery_id in linked):
                continue
            requeue(event_id)
            repaired_roots.add(event_id)
            for recovery_id in linked:
                coalesce(recovery_id, event_id)
                coalesced_recoveries.add(recovery_id)

        for event_id, record in records.items():
            if (
                not record["isRecovery"]
                or not record["eligible"]
                or event_id in coalesced_recoveries
            ):
                continue
            root_id = root_event_id(event_id)
            if root_id in repaired_roots:
                continue
            root_record = records.get(root_id)
            if root_record is not None and root_record["eligible"]:
                # The root was deliberately left untouched because another
                # linked recovery did not satisfy the exact pre-turn proof.
                continue
            requeue(event_id)

    return {"status": "applied", "requeued": requeued, "coalesced": coalesced}


def _revive_superseded_auth_gap_recovery(lane: EventLane, event: dict) -> bool:
    """Reuse the stable recovery identity if the retried root later truly needs it."""
    event_id = str(event.get("eventId") or "")
    root_id = _recovery_source_event_id(event)
    if not event_id or not root_id:
        return False
    with lane.writer() as db:
        row = db.execute(
            "SELECT e.status,e.payload_json,t.status AS turn_status,t.thread_id,t.turn_id "
            "FROM event_lane_events e LEFT JOIN event_lane_turns t USING(event_id) "
            "WHERE e.event_id=?",
            (event_id,),
        ).fetchone()
        if row is None:
            return False
        try:
            existing = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        repair = existing.get("authorizationGapRepair") if isinstance(existing, dict) else None
        if (
            str(row["status"] or "") != "coalesced"
            or str(row["turn_status"] or "") != "superseded"
            or str(row["thread_id"] or "")
            or str(row["turn_id"] or "")
            or not isinstance(repair, dict)
            or repair.get("state") != "superseded"
            or repair.get("rootEventId") != root_id
        ):
            return False
        changed = db.execute(
            "UPDATE event_lane_events SET status='pending',attempts=0,payload_json=?,"
            "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
            "WHERE event_id=? AND status='coalesced' AND payload_json=?",
            (json.dumps(event, sort_keys=True), event_id, str(row["payload_json"])),
        )
        removed = db.execute(
            "DELETE FROM event_lane_turns WHERE event_id=? AND status='superseded' "
            "AND thread_id='' AND (turn_id IS NULL OR turn_id='')",
            (event_id,),
        )
        if changed.rowcount != 1 or removed.rowcount != 1:
            raise RuntimeError("superseded authorization recovery changed during revival")
        return True


def _outcome_recovery_event_id(root_event_id: str) -> str:
    """Return one fixed-length recovery identity for an original event."""
    digest = hashlib.sha256(str(root_event_id).encode("utf-8")).hexdigest()
    return f"outcome-reconcile:{RECOVERY_EVENT_NAMESPACE}:{digest}"


def _valid_exhausted_recovery_lineage(
    recovery_event_id: str,
    recovery_event: dict,
    root_event: dict,
    root_event_id: str,
    event_key: str,
) -> bool:
    """Accept settlement only for the exact stable root/recovery pair."""

    key_prefix, separator, key_number = str(event_key).rpartition("#")
    if separator != "#" or key_prefix != REPO or not re.fullmatch(r"[1-9][0-9]*", key_number):
        return False
    root_kind = str(root_event.get("kind") or "")
    root_prefix = f"github:{REPO}:{key_number}:{root_kind}:"
    if str(recovery_event_id) != _outcome_recovery_event_id(root_event_id):
        return False
    if (
        not root_event_id.startswith("github:")
        or "outcome-reconcile:" in root_event_id
        or not root_event_id.startswith(root_prefix)
        or str(root_event.get("eventId") or "") != root_event_id
        or str(root_event.get("repo") or "") != REPO
        or str(root_event.get("number") or "") != key_number
        or str(root_event.get("eventKey") or "") != event_key
        or root_kind not in {"issue_update", "pr_update"}
    ):
        return False
    if (
        str(recovery_event.get("eventId") or "") != str(recovery_event_id)
        or recovery_event.get("kind") != "outcome_reconcile"
        or str(recovery_event.get("eventKey") or "") != event_key
        or str(recovery_event.get("rootEventId") or "") != root_event_id
        or str(recovery_event.get("eventIdSource") or "") != root_event_id
    ):
        return False
    payload = recovery_event.get("payload")
    if not isinstance(payload, dict):
        return False
    return (
        str(payload.get("eventId") or "") == root_event_id
        and str(payload.get("publicKey") or "") == event_key
        and str(payload.get("rootEventId") or "") == root_event_id
    )


def _valid_machine_outcome(event_id: str, event_key: str, outcome: dict) -> bool:
    """Accept only the exact restricted terminal receipt for this event."""
    if outcome.get("error"):
        return False
    if outcome.get("schemaVersion") != "agentscope_event_outcome_v1":
        return False
    if str(outcome.get("eventId") or "") != str(event_id):
        return False
    if str(outcome.get("publicKey") or "") != str(event_key):
        return False
    state = str(outcome.get("state") or "")
    if state not in {"no_action", "claimed_or_pr", "design_wait"}:
        return False
    expected_keys = {"schemaVersion", "eventId", "publicKey", "state"}
    if state == "design_wait":
        expected_keys.update({"waitStartedAt", "waitUntil"})
    if set(outcome) != expected_keys:
        return False
    if state == "design_wait":
        try:
            started = datetime.fromisoformat(str(outcome["waitStartedAt"]).replace("Z", "+00:00"))
            until = datetime.fromisoformat(str(outcome["waitUntil"]).replace("Z", "+00:00"))
            if started.tzinfo is None or until.tzinfo is None:
                return False
        except (KeyError, TypeError, ValueError):
            return False
        try:
            invalid_window = until < started or until - started > timedelta(hours=24)
        except TypeError:
            return False
        if invalid_window:
            return False
    return True


def _enqueue_unresolved_outcome_recoveries(lane: EventLane) -> dict[str, int]:
    """Create one stable, read-only recovery event for each unresolved root."""
    with lane.connect() as db:
        all_event_rows = db.execute(
            "SELECT e.event_id,e.status,e.payload_json,t.status AS turn_status "
            "FROM event_lane_events e LEFT JOIN event_lane_turns t USING(event_id)"
        ).fetchall()
        rows = db.execute(
            "SELECT e.event_id,e.payload_json,e.status AS event_status,"
            "t.status AS turn_status,t.receipt_json "
            "FROM event_lane_events e LEFT JOIN event_lane_turns t USING(event_id) "
            "WHERE e.status='needs_reconcile' OR "
            "(e.status='delivered' AND t.status='needs_reconcile') "
            "ORDER BY e.created_at,e.event_id"
        ).fetchall()
    all_events: dict[str, dict] = {}
    recovery_events: set[str] = set()
    unresolved_recoveries: set[str] = set()
    for row in all_event_rows:
        try:
            value = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            value = {}
        event_id = str(row["event_id"])
        all_events[event_id] = value if isinstance(value, dict) else {}
        if event_id.startswith("outcome-reconcile:") or value.get("kind") == "outcome_reconcile":
            recovery_events.add(event_id)
            if not (
                str(row["status"] or "") in {"coalesced", "watch_only"}
                and str(row["turn_status"] or "") in {"", "superseded", "watch_only"}
            ):
                unresolved_recoveries.add(event_id)

    blocked_roots: set[str] = set()
    ordinary_ids = set(all_events) - recovery_events
    for recovery_id in unresolved_recoveries:
        pending = [recovery_id]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current in visited or current not in recovery_events:
                continue
            visited.add(current)
            current_event = all_events[current]
            source = _event_source(
                current,
                current_event,
                namespace=RECOVERY_EVENT_NAMESPACE,
            )
            declared = _declared_lineage_ids(current_event)
            if source:
                declared.add(source)
            for candidate in declared:
                if candidate in recovery_events:
                    pending.append(candidate)
                elif candidate in ordinary_ids:
                    blocked_roots.add(candidate)
    candidates = 0
    inserted = 0
    existing = 0
    skipped = 0
    for row in rows:
        try:
            event = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            skipped += 1
            continue
        if (
            str(row["event_id"]).startswith("outcome-reconcile:")
            or event.get("kind") == "outcome_reconcile"
        ):
            continue
        event_key = str(
            event.get("eventKey")
            or event.get("targetKey")
            or (
                f"{event.get('repo')}#{event.get('number')}"
                if event.get("repo") and event.get("number") is not None
                else ""
            )
        )
        if not event_key.casefold().startswith(f"{REPO.casefold()}#") or event_key.endswith("#"):
            skipped += 1
            continue
        root_event_id = str(row["event_id"])
        candidates += 1
        if root_event_id in blocked_roots:
            existing += 1
            continue
        try:
            receipt = json.loads(row["receipt_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            receipt = {}
        reason = str(
            event.get("terminalReason") or receipt.get("terminalReason") or "legacy_needs_reconcile"
        )
        recovery = {
            "eventId": _outcome_recovery_event_id(root_event_id),
            "kind": "outcome_reconcile",
            "eventKey": event_key,
            "rootEventId": root_event_id,
            "eventIdSource": root_event_id,
            "payload": {
                "eventId": root_event_id,
                "rootEventId": root_event_id,
                "publicKey": event_key,
                "reason": reason,
            },
        }
        if lane.append(recovery, priority=250) or _revive_superseded_auth_gap_recovery(
            lane, recovery
        ):
            inserted += 1
        else:
            existing += 1
    return {
        "candidates": candidates,
        "inserted": inserted,
        "existing": existing,
        "skipped": skipped,
    }


def _comment_claim_evidence(
    comments: list[dict],
    *,
    not_before: datetime | None = None,
) -> dict[str, str] | None:
    """Return a normalized claim signal, excluding bots and old comments."""

    for comment in comments:
        if not isinstance(comment, dict):
            continue
        created_at = str(comment.get("created_at") or comment.get("createdAt") or "")
        created = _parse_time(created_at)
        if created is None or (not_before is not None and created < not_before):
            continue
        author = comment.get("user") if isinstance(comment.get("user"), dict) else {}
        user_type = str(author.get("type") or author.get("userType") or "").casefold()
        if user_type == "bot":
            continue
        normalized = {
            "body": comment.get("body"),
            "user": author,
            "author_association": comment.get("author_association")
            or comment.get("authorAssociation"),
            "created_at": created_at,
        }
        signals = detect_claims([normalized], current_actor="oxygen56")
        if not signals:
            continue
        signal = signals[0]
        login = str(author.get("login") or signal.author or "")
        if not login or login.casefold().endswith("[bot]"):
            continue
        body = str(comment.get("body") or "").strip()
        if not body or _NEGATED_EXTERNAL_CLAIM_RE.search(body):
            continue
        claim_kind = str(signal.kind)
        if _CONDITIONAL_EXTERNAL_CLAIM_RE.search(body):
            claim_kind = "conditional_claim"
        return {
            "kind": "external_claim_comment",
            "claimKind": claim_kind,
            "commentId": str(comment.get("id") or "")[:80],
            "author": login[:120],
            "authorType": user_type[:40],
            "authorAssociation": str(signal.association or "NONE")[:40],
            "createdAt": created_at[:80],
            "excerpt": " ".join(body.split())[:240],
            "commentUrl": str(comment.get("html_url") or comment.get("url") or "")[:400],
        }
    return None


def _external_no_action_evidence(
    issue: dict,
    comments: list[dict],
    *,
    root_event: dict | None = None,
) -> dict[str, str] | None:
    """Return conservative public evidence for a watch-only closeout."""

    state = str(issue.get("state") or "open").casefold()
    repository = issue.get("repository") if isinstance(issue.get("repository"), dict) else {}
    repo = str(repository.get("full_name") or REPO)
    number = issue.get("number")
    if state == "closed":
        return {
            "kind": "issue_closed",
            "repo": repo,
            "number": str(number or ""),
            "issueState": state,
            "issueUrl": str(issue.get("html_url") or "")[:400],
        }
    assignees = issue.get("assignees") if isinstance(issue.get("assignees"), list) else []
    assignee = issue.get("assignee") if isinstance(issue.get("assignee"), dict) else None
    names = [
        value
        for value in ([assignee] if assignee else []) + assignees
        if isinstance(value, dict) and str(value.get("login") or "")
    ]
    external = [value for value in names if str(value.get("login") or "").casefold() != "oxygen56"]
    # An assignment or claim only supersedes an issue event.  A PR watch event
    # must continue to observe the user's own PR even if an issue has an
    # unrelated assignee or comment.
    root_kind = str((root_event or {}).get("kind") or "issue_update")
    if external and root_kind == "issue_update":
        value = external[0]
        return {
            "kind": "issue_assigned_external",
            "repo": repo,
            "number": str(number or ""),
            "issueState": state,
            "assignee": str(value.get("login") or "")[:120],
            "issueUrl": str(issue.get("html_url") or "")[:400],
        }
    not_before = None
    if root_event:
        not_before = _parse_time(
            str(root_event.get("updatedAt") or root_event.get("createdAt") or "")
        )
    claim = _comment_claim_evidence(comments, not_before=not_before)
    if claim and root_kind == "issue_update":
        claim.update(
            {
                "repo": repo,
                "number": str(number or ""),
                "issueState": state,
                "issueUrl": str(issue.get("html_url") or "")[:400],
            }
        )
        return claim
    return None


def _live_exhausted_recovery_evidence(
    root: Path,
    event: dict,
    *,
    transport=None,
) -> dict[str, str] | None:
    """Read current issue state and look for a deterministic no-action proof.

    This helper performs GET-only requests and intentionally returns no proof
    when GitHub is unavailable or the issue remains genuinely actionable.
    """

    repo = str(event.get("repo") or REPO)
    number = _pr_number(event)
    if repo != REPO or number is None:
        return None
    state_path = root / "state" / "agentscope-poll.json"
    state = _load_json(state_path)
    try:
        poller = (
            GitHubIssuePoller(state_path, transport=transport)
            if transport
            else GitHubIssuePoller(state_path)
        )
        headers = poller._headers(state, conditional=False, require_auth=transport is None)
        base = f"https://api.github.com/repos/{repo}/issues/{number}"
        status, _response_headers, issue = poller.transport(base, headers)
        if status != 200 or not isinstance(issue, dict):
            return None
        comments_url = f"{base}/comments?per_page=100&page=1&sort=created&direction=desc"
        comment_status, _comment_headers, comments = poller.transport(comments_url, headers)
        if comment_status != 200 or not isinstance(comments, list):
            comments = []
        issue = dict(issue)
        if not issue.get("number"):
            issue["number"] = number
        issue["repository"] = {"full_name": repo}
        return _external_no_action_evidence(issue, comments, root_event=event)
    except Exception:  # noqa: BLE001 - an unavailable proof must fail closed
        return None


def _settle_exhausted_outcome_recoveries(
    root: Path,
    lane: EventLane,
    *,
    transport=None,
    now: float | None = None,
) -> dict[str, int]:
    """Settle only exhausted chains whose current public state proves no-op."""

    try:
        current = time.time() if now is None else float(now)
    except (TypeError, ValueError, OverflowError):
        return {"candidates": 0, "settled": 0, "alreadyApplied": 0, "skipped": 0}
    if not (current == current and abs(current) != float("inf")):
        return {"candidates": 0, "settled": 0, "alreadyApplied": 0, "skipped": 0}
    with lane.connect() as db:
        rows = db.execute(
            "SELECT e.event_id,e.payload_json,e.status,e.attempts,t.status AS turn_status,"
            "t.receipt_json,s.value_json AS audit_json FROM event_lane_events e "
            "LEFT JOIN event_lane_turns t USING(event_id) "
            "LEFT JOIN event_lane_state s ON s.key=('outcome-recovery-evidence:' || e.event_id) "
            "WHERE (e.status='needs_reconcile' OR "
            "(e.status='delivered' AND t.status='needs_reconcile')) "
            "AND (e.event_id LIKE 'outcome-reconcile:%' OR "
            "(json_valid(e.payload_json) AND "
            "json_extract(e.payload_json,'$.kind')='outcome_reconcile')) "
            "AND e.attempts>=? "
            # Prefer chains that have never been checked, then rotate older
            # audits ahead of recently checked rows so a blocked early row
            # cannot starve later recoveries indefinitely.
            "ORDER BY CASE WHEN s.value_json IS NULL OR NOT json_valid(s.value_json) THEN 0 ELSE 1 END,"
            "CASE WHEN json_valid(s.value_json) THEN json_extract(s.value_json,'$.lastCheckedAt') END,"
            "e.created_at,e.event_id LIMIT 8",
            (lane.max_attempts,),
        ).fetchall()
    candidates = 0
    settled = 0
    already_applied = 0
    skipped = 0
    for row in rows:
        try:
            event = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            skipped += 1
            continue
        if not isinstance(event, dict) or event.get("kind") != "outcome_reconcile":
            skipped += 1
            continue
        root_event_id = _recovery_source_event_id(event)
        event_key = str(event.get("eventKey") or "")
        if not root_event_id or not event_key:
            skipped += 1
            continue
        with lane.connect() as db:
            root_row = db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?",
                (root_event_id,),
            ).fetchone()
        if root_row is None:
            skipped += 1
            continue
        try:
            root_event = json.loads(root_row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            root_event = {}
        if not isinstance(root_event, dict):
            skipped += 1
            continue
        if not _valid_exhausted_recovery_lineage(
            str(row["event_id"]), event, root_event, root_event_id, event_key
        ):
            skipped += 1
            continue
        candidates += 1
        audit_key = f"outcome-recovery-evidence:{row['event_id']}"
        audit = lane.state_value(audit_key)
        last_checked = _parse_time(
            str(audit.get("lastCheckedAt") or "") if isinstance(audit, dict) else ""
        )
        if (
            last_checked is not None
            and current - last_checked.timestamp() < EXHAUSTED_EVIDENCE_RECHECK_SECONDS
        ):
            skipped += 1
            continue
        lane.set_state_value(
            audit_key,
            {
                "schemaVersion": "agentscope_event_recovery_audit_v1",
                "lastCheckedAt": datetime.fromtimestamp(current, UTC)
                .isoformat()
                .replace("+00:00", "Z"),
            },
        )
        evidence = _live_exhausted_recovery_evidence(root, root_event, transport=transport)
        if not evidence:
            skipped += 1
            continue
        result = lane.settle_exhausted_recovery_no_action(
            str(row["event_id"]),
            root_event_id=root_event_id,
            event_key=event_key,
            reason=str(evidence.get("kind") or "external_state_superseded"),
            evidence=evidence,
            now=current,
            watch_seconds=EXTERNAL_CLAIM_WATCH_SECONDS,
        )
        if result.get("status") == "applied":
            settled += 1
        elif result.get("status") == "already_applied":
            already_applied += 1
        else:
            skipped += 1
    return {
        "candidates": candidates,
        "settled": settled,
        "alreadyApplied": already_applied,
        "skipped": skipped,
    }


def _central_handler_busy(lane: EventLane) -> bool:
    """Do not spend an event attempt while the one central task is occupied."""
    with lane.connect() as db:
        return (
            db.execute(
                "SELECT 1 FROM event_lane_turns WHERE status IN ('reserved','started') LIMIT 1"
            ).fetchone()
            is not None
        )


def _event_artifact_path(
    root: Path,
    directory: str,
    event_id: str,
    *,
    attempt: int = 1,
    is_recovery: bool = False,
    generation: object = None,
) -> Path:
    """Keep every terminal recovery attempt in a distinct evidence file."""
    return event_artifact_path(
        root,
        directory,
        event_id,
        attempt=attempt,
        is_recovery=is_recovery,
        generation=generation,
    )


def _recovery_generation(event: dict[str, object]) -> object:
    """Read a durable rearm generation, preserving legacy path semantics."""
    value = event.get("recoveryGeneration")
    if value is None and isinstance(event.get("payload"), dict):
        value = event["payload"].get("recoveryGeneration")
    return value


def _outcome_recovery_lineage(lane: EventLane, event_id: str) -> tuple[str, bool]:
    """Resolve the original event across both stable and legacy recovery rows."""
    current = str(event_id)
    visited: set[str] = set()
    is_recovery = False
    with lane.connect() as db:
        while current and current not in visited:
            visited.add(current)
            row = db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?",
                (current,),
            ).fetchone()
            if row is None:
                return current, is_recovery
            try:
                event = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                return current, is_recovery
            if event.get("kind") != "outcome_reconcile":
                return current, is_recovery
            is_recovery = True
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            root_event_id = str(event.get("rootEventId") or payload.get("rootEventId") or "")
            if root_event_id:
                return root_event_id, True
            source_event_id = str(event.get("eventIdSource") or payload.get("eventId") or "")
            if not source_event_id:
                return current, True
            current = source_event_id
    return current or str(event_id), is_recovery


def _retry_or_exhaust_outcome_recovery(
    lane: EventLane,
    *,
    event_id: str,
    root_event_id: str,
    outcome: dict,
    transient_error: object = None,
    used_model: object = None,
) -> str:
    """Reuse one recovery row until its existing EventLane budget is spent."""
    now = datetime.now(UTC).timestamp()
    if _transient_model_error(transient_error):
        with lane.connect() as db:
            row = db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?", (str(event_id),)
            ).fetchone()
        if row is None:
            return "missing"
        try:
            event = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            event = {"eventId": str(event_id), "kind": "outcome_reconcile"}
        recorded_model = str(used_model or "").strip() or LEGACY_UNRECORDED_MODEL
        outcome = lane.record_transient_model_failure(
            str(event_id),
            model=recorded_model,
            candidates=EVENT_MODEL_CANDIDATES,
            error=transient_error,
            retry_not_before=now + TRANSIENT_MODEL_RETRY_DELAY_SECONDS,
        )
        return "transient_retry" if outcome == "retry" else outcome
    with lane.writer() as db:
        row = db.execute(
            "SELECT attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (str(event_id),),
        ).fetchone()
        if row is None:
            return "missing"
        try:
            event = json.loads(row["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            event = {"eventId": str(event_id), "kind": "outcome_reconcile"}
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        payload.update(
            {
                "outcome": outcome,
                "reason": "invalid_or_missing_outcome",
            }
        )
        stable_identity = str(event_id) == _outcome_recovery_event_id(root_event_id)
        if stable_identity:
            event["rootEventId"] = str(root_event_id)
            event["eventIdSource"] = str(root_event_id)
            payload["eventId"] = str(root_event_id)
            payload["rootEventId"] = str(root_event_id)
        event["payload"] = payload
        attempts = int(row["attempts"] or 0)
        if attempts < lane.max_attempts:
            event.pop("terminalReason", None)
            event.pop("recoveryExhausted", None)
            db.execute(
                "UPDATE event_lane_events SET status='pending',payload_json=?,"
                "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                "WHERE event_id=?",
                (json.dumps(event, sort_keys=True), str(event_id)),
            )
            return "retry"

        event["terminalReason"] = "outcome_recovery_attempts_exhausted"
        event["recoveryExhausted"] = True
        event["recoveryAttempts"] = attempts
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',payload_json=?,"
            "delivered_at=?,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
            "WHERE event_id=?",
            (json.dumps(event, sort_keys=True), now, str(event_id)),
        )
        turn = db.execute(
            "SELECT event_key,turn_id,receipt_json FROM event_lane_turns WHERE event_id=?",
            (str(event_id),),
        ).fetchone()
        if turn is not None:
            try:
                receipt = json.loads(turn["receipt_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                receipt = {}
            receipt.update(
                {
                    "terminalReason": "outcome_recovery_attempts_exhausted",
                    "rootEventId": str(root_event_id),
                    "recoveryAttempts": attempts,
                }
            )
            receipt_json = json.dumps(receipt, sort_keys=True)
            db.execute(
                "UPDATE event_lane_turns SET status='needs_reconcile',receipt_json=? "
                "WHERE event_id=?",
                (receipt_json, str(event_id)),
            )
            db.execute(
                "UPDATE event_lane_threads SET status='needs_reconcile',receipt_json=? "
                "WHERE event_key=? AND turn_id=?",
                (receipt_json, str(turn["event_key"]), str(turn["turn_id"] or "")),
            )
        return "exhausted"


def _active_task_config(root: Path, repo: str) -> dict[str, str]:
    """Read and verify the immutable release manifest; never use runtime root."""
    del root
    manifest_path = ROOT / EVENT_LANE_MANIFEST
    digest_path = ROOT / EVENT_LANE_DIGEST
    if any(path.is_symlink() or not path.is_file() for path in (manifest_path, digest_path)):
        raise RuntimeError(f"event-lane manifest is unavailable for {repo}")
    try:
        manifest_bytes = manifest_path.read_bytes()
        actual_digest = hashlib.sha256(manifest_bytes).hexdigest()
        expected_digest = digest_path.read_text(encoding="utf-8").strip().split()[0]
        value = json.loads(manifest_bytes.decode("utf-8"))
    except (IndexError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("event-lane manifest is invalid") from exc
    if actual_digest != expected_digest:
        raise RuntimeError("event-lane manifest digest mismatch")
    if not isinstance(value, dict) or value.get("schemaVersion") != "oss-pr-radar-event-lane-v1":
        raise RuntimeError("event-lane manifest schema is invalid")
    repositories = value.get("repositories")
    entry = repositories.get(repo) if isinstance(repositories, dict) else None
    thread_id = str(entry.get("activeThreadId") or "") if isinstance(entry, dict) else ""
    if not thread_id:
        raise RuntimeError(f"central active task thread is not configured for {repo}")
    configured_cwd = (
        Path(str(entry.get("cwd") or "")).resolve() if isinstance(entry, dict) else Path("/")
    )
    if configured_cwd != CENTRAL_CWD or not CENTRAL_CWD.is_dir():
        raise RuntimeError("central task cwd is not the safe repository")
    return {"threadId": thread_id, "cwd": str(CENTRAL_CWD)}


def _pr_number(event: dict) -> int | None:
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    raw = issue.get("number") or event.get("number")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _resolve_event_target(root: Path, event: dict) -> dict[str, object]:
    """Classify an event without consulting shared task ownership state."""
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    if event.get("kind") == "outcome_reconcile":
        return {
            "key": str(event.get("eventKey") or payload.get("publicKey") or ""),
            "kind": "outcome_reconcile",
            "mapped": False,
        }
    repo = str(event.get("repo") or "")
    number = _pr_number(event)
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    is_pr = bool(event.get("kind") == "pr_update" or issue.get("pull_request"))
    key = f"{repo}#{number}"
    if not is_pr:
        return {"key": key, "kind": "issue", "mapped": False}
    pr_url = str(issue.get("html_url") or issue.get("pull_request", {}).get("html_url") or "")
    # Own-PR filtering happens in GitHubIssuePoller before this point.  The
    # event lane never maps a PR back to a shared Radar opportunity/thread.
    return {"key": f"{repo}#{number}", "kind": "pr_watch", "mapped": False, "prUrl": pr_url}


def _quarantine_event(root: Path, lane: EventLane, event: dict, *, reason: str) -> None:
    """Persist a private reconciliation handoff and stop this event lease."""
    handoff = root / "state" / "agentscope-event-handoffs.jsonl"
    handoff.parent.mkdir(parents=True, exist_ok=True)
    with handoff.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event": event, "reason": reason}, sort_keys=True) + "\n")
    lane.terminalize_event(str(event.get("eventId") or ""), reason=reason)


def issue_handler_delivery(
    root: Path, lane: EventLane, event: dict, *, target: dict[str, object] | None = None
) -> None:
    """Start/resume the detached bridge worker and receipt its turn before ack."""
    target = target or _resolve_event_target(root, event)
    event_repo = str(event.get("repo") or "")
    if event_repo != REPO and not (event.get("kind") == "outcome_reconcile" and not event_repo):
        _quarantine_event(root, lane, event, reason="foreign_repository_event")
        return
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    key = str(
        target.get("key")
        or event.get("eventKey")
        or payload.get("publicKey")
        or f"{event.get('repo')}#{event.get('number')}"
    )
    if not key.casefold().startswith(f"{REPO.casefold()}#") or key.endswith("#"):
        _quarantine_event(root, lane, event, reason="foreign_repository_event")
        return
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    public_status = lane.public_status(key)
    if str(issue.get("state") or "open").casefold() != "open" and public_status not in {
        "active",
        "watch_only",
    }:
        # A closed ordinary issue is a no-op closeout, not a new public task.
        return
    if str(issue.get("state") or "open").casefold() != "open" and target.get("kind") == "issue":
        target = dict(target)
        target["kind"] = "issue_closeout"
    event_id = str(event["eventId"])
    model = _event_model(event)
    lane.expire_handler_turns()
    existing_turn = lane.handler_turn(event_id)
    if existing_turn and str(existing_turn.get("status") or "") == "started":
        # A delayed retry for the same event is idempotent.
        return
    if existing_turn and str(existing_turn.get("status") or "") == "reserved":
        raise RuntimeError("event_turn_reserved")
    central_thread = None
    central_cwd = None
    try:
        central = _active_task_config(root, REPO)
        central_thread = central["threadId"]
        central_cwd = central["cwd"]
    except RuntimeError as exc:
        _quarantine_event(root, lane, event, reason=str(exc))
        return
    binding = {"thread_id": central_thread}
    recovery_attempt = int(event.get("attempts") or 1)
    is_recovery = event.get("kind") == "outcome_reconcile"
    recovery_generation = _recovery_generation(event) if is_recovery else 0
    client_message_id = f"oss-pr-radar:agentscope-event:{event_id}"
    if is_recovery:
        if recovery_generation not in (None, "", 0, "0"):
            client_message_id += f":generation:{recovery_generation}"
        if recovery_attempt > 1:
            client_message_id += f":attempt:{recovery_attempt}"
    reservation = lane.try_reserve_handler_turn_if_idle(
        key,
        event_id,
        client_message_id,
        lease_token=str(event.get("leaseToken") or ""),
        recovery_retry=is_recovery,
    )
    if reservation.get("status") == "busy":
        return
    if reservation.get("status") != "reserved":
        raise RuntimeError(f"handler_reservation_{reservation.get('reason') or 'conflict'}")
    if target.get("kind") in {"pr_followup", "pr_watch"}:
        prompt = (
            f"Observe AgentScope PR event {event['eventId']} for {target.get('prUrl') or key} in the configured central task. "
            "Review maintainer comments, review state, conflicts, and CI without resuming any legacy task context; "
            "never claim a new issue or create a duplicate PR. "
            "Before terminal completion, write one machine outcome: no_action, claimed_or_pr, or design_wait with publicKey and wait timestamps."
        )
    elif target.get("kind") == "outcome_reconcile":
        prompt = (
            f"Recover the invalid AgentScope event outcome for {key} in the existing thread. "
            "This recovery is strictly read-only: do not claim work, create or change a PR, comment, "
            "label, assign, push, rerun workflows, or perform any other GitHub or external mutation. "
            "Only inspect existing state and write the private outcome file. Verify the actual terminal "
            "state and write a valid outcome JSON for this exact event/public key using the restricted "
            "schema before completion."
        )
    elif target.get("kind") == "issue_closeout":
        prompt = (
            f"Reconcile the closed AgentScope issue event {event['eventId']} for {key} in its existing thread. "
            "Do not claim new work or create a PR. Record the terminal closeout and write one valid machine outcome."
        )
    else:
        prompt = (
            f"Handle AgentScope issue event {event['eventId']} for {event.get('issue', {}).get('html_url') or key}. "
            "First verify it is an open code issue, unassigned, unclaimed, without duplicate PR or maintainer-reserved design. "
            "Only one complete PR is allowed; do not make partial fixes, claims, CLA/AI/legal declarations, force pushes, or destructive changes. "
            "Respect a maximum of three active Oxygen56 tasks and stop in watch-only state when maintainer input is needed for 24 hours. "
            "If eligible, reproduce the behavior, implement the complete issue, run target validation, and prepare the authorized PR. "
            "Before terminal completion, write exactly one machine outcome: no_action, claimed_or_pr, or design_wait with publicKey and wait timestamps."
        )
    receipt = _event_artifact_path(
        root,
        EVENT_RECEIPT_DIR,
        event_id,
        attempt=recovery_attempt,
        is_recovery=is_recovery,
        generation=recovery_generation,
    )
    outcome_path = _event_artifact_path(
        root,
        EVENT_OUTCOME_DIR,
        event_id,
        attempt=recovery_attempt,
        is_recovery=is_recovery,
        generation=recovery_generation,
    )
    outcome_instruction = (
        f" Write the terminal outcome JSON to {outcome_path}: schemaVersion=agentscope_event_outcome_v1, "
        f"eventId={event_id}, publicKey={key}, state one of no_action/claimed_or_pr/design_wait; "
        "design_wait must include waitStartedAt and waitUntil no more than 24 hours apart."
    )
    prompt += outcome_instruction
    try:
        result = run_bridge(
            root,
            "agentscope-event-create",
            timeout=75,
            code_root=ROOT,
            inactive_release=True,
            extra_args=[
                "--event-id",
                event_id,
                "--event-key",
                key,
                "--model",
                model,
                "--thread-id",
                str(binding.get("thread_id") or "") if binding else "",
                "--client-user-message-id",
                client_message_id,
                "--cwd",
                str(central_cwd),
                "--prompt",
                prompt,
                "--receipt",
                str(receipt),
                "--outcome-receipt",
                str(outcome_path),
                "--design-wait-until",
                str(event.get("designWaitUntil") or ""),
                "--design-wait-started-at",
                str(event.get("designWaitStartedAt") or event.get("updatedAt") or ""),
            ],
        )
    except Exception as exc:
        if _is_operational_authorization_gap(exc):
            lane.defer_prestart_authorization_gap(
                event_id,
                lease_token=str(event.get("leaseToken") or ""),
            )
            raise
        if _transient_model_error(exc):
            lane.release_handler_reservation(
                event_id,
                {"model": model, "error": f"{type(exc).__name__}:{str(exc)[:300]}"},
                reason="transient_model_failure",
            )
            state = _record_transient_model_failure(lane, event=event, model=model, error=exc)
            raise RuntimeError(
                f"AgentScope event worker recorded transient model failure ({state}): {str(exc)[:300]}"
            ) from exc
        lane.release_handler_reservation(
            event_id,
            {"error": f"{type(exc).__name__}:{str(exc)[:300]}"},
            reason="handler_start_exception",
        )
        lane.defer_event(
            event_id,
            lease_token=str(event.get("leaseToken") or ""),
        )
        raise
    if central_thread and str(result.get("threadId") or central_thread) != central_thread:
        lane.release_handler_reservation(
            event_id,
            result,
            reason="central_task_thread_receipt_mismatch",
        )
        _quarantine_event(root, lane, event, reason="central_task_thread_receipt_mismatch")
        return
    if result.get("turnId"):
        received_thread = str(result.get("threadId") or central_thread or "")
        lane.bind_handler_turn(
            key,
            event_id,
            received_thread,
            str(result["turnId"]),
            result,
            status="started",
        )
        if result.get("designWait") or result.get("status") == "watch_only":
            lane.mark_design_wait(event_id)
        return
    if not result.get("ok") or not result.get("turnId"):
        if (
            not result.get("turnId")
            and result.get("turnStarted") is False
            and _is_operational_authorization_gap(result)
        ):
            lane.defer_prestart_authorization_gap(
                event_id,
                lease_token=str(event.get("leaseToken") or ""),
            )
            raise RuntimeError(
                f"AgentScope event authorization deferred before turn creation: {result}"
            )
        if _transient_model_error(result):
            lane.release_handler_reservation(
                event_id,
                result | {"model": str(result.get("model") or model)},
                reason="transient_model_failure",
            )
            state = _record_transient_model_failure(
                lane,
                event=event,
                model=str(result.get("model") or model),
                error=result,
            )
            raise RuntimeError(
                f"AgentScope event worker recorded transient model failure ({state})"
            )
        lane.release_handler_reservation(
            event_id,
            result,
            reason="handler_start_retryable" if result.get("retryable") else "handler_start_failed",
        )
        lane.defer_event(
            event_id,
            lease_token=str(event.get("leaseToken") or ""),
        )
        if result.get("retryable"):
            handoff = root / "state" / "agentscope-event-handoffs.jsonl"
            handoff.parent.mkdir(parents=True, exist_ok=True)
            with handoff.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"event": event, "result": result}, sort_keys=True) + "\n")
        raise RuntimeError(f"AgentScope event worker receipt unavailable: {result}")


def reconcile_detached_receipts(root: Path, lane: EventLane) -> int:
    """Copy terminal state from detached worker receipts into the lane ledger."""
    updated = 0
    with lane.connect() as db:
        rows = db.execute(
            "SELECT t.event_id,t.event_key,t.thread_id,t.turn_id,t.receipt_json,"
            "e.attempts,e.payload_json AS event_payload_json FROM event_lane_turns t "
            "JOIN event_lane_events e ON e.event_id=t.event_id "
            "WHERE t.status IN ('reserved','started')"
        ).fetchall()
    for row in rows:
        event = {}
        try:
            event = json.loads(row["event_payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        receipt = _event_artifact_path(
            root,
            EVENT_RECEIPT_DIR,
            str(row["event_id"]),
            attempt=int(row["attempts"] or 1),
            is_recovery=event.get("kind") == "outcome_reconcile",
            generation=(
                _recovery_generation(event) if event.get("kind") == "outcome_reconcile" else 0
            ),
        )
        try:
            value = json.loads(receipt.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            # A terminal receipt must be an object.  Leave malformed files in
            # place for inspection instead of crashing the whole reconciler.
            continue
        # The detached worker's final file intentionally contains only the
        # public turn result.  Carry the launch PID and retry history from the
        # durable reservation so a just-finished process cannot be mistaken
        # for a dead one during the recovery reset race.
        existing_receipt = {}
        try:
            existing_receipt = json.loads(row["receipt_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            existing_receipt = {}
        if not isinstance(existing_receipt, dict):
            existing_receipt = {}
        for field in ("workerPid", "pid", "processId", "launchPid"):
            if field not in value and field in existing_receipt:
                value[field] = existing_receipt[field]
        launch = receipt.with_suffix(".launch.json")
        launch_state = _load_json(launch)
        if "workerPid" not in value and launch_state.get("pid"):
            value["workerPid"] = launch_state.get("pid")
        terminal = str(value.get("turnStatus") or "")
        if terminal not in {"completed", "failed", "interrupted"}:
            continue
        if value.get("terminalError") is None and value.get("error") is not None:
            value["terminalError"] = value.get("error")
        lane.bind_handler_turn(
            str(row["event_key"]),
            str(row["event_id"]),
            str(row["thread_id"]),
            str(row["turn_id"]),
            value,
            status=terminal,
        )
        if value.get("designWait") or value.get("status") == "watch_only":
            lane.mark_design_wait(str(row["event_id"]))
        outcome = value.get("outcome") if isinstance(value.get("outcome"), dict) else {}
        outcome_state = str(outcome.get("state") or "")
        if terminal != "completed" or not _valid_machine_outcome(
            str(row["event_id"]), str(row["event_key"]), outcome
        ):
            root_event_id, is_recovery = _outcome_recovery_lineage(lane, str(row["event_id"]))
            lane.register_public_work(
                str(row["event_key"]), status="active", source="outcome-invalid"
            )
            lane.bind_handler_turn(
                str(row["event_key"]),
                str(row["event_id"]),
                str(row["thread_id"]),
                str(row["turn_id"]),
                value,
                status="needs_reconcile",
            )
            if is_recovery:
                _retry_or_exhaust_outcome_recovery(
                    lane,
                    event_id=str(row["event_id"]),
                    root_event_id=root_event_id,
                    outcome=outcome,
                    transient_error=value.get("terminalError"),
                    used_model=value.get("model"),
                )
            else:
                recovery = {
                    "eventId": _outcome_recovery_event_id(root_event_id),
                    "kind": "outcome_reconcile",
                    "eventKey": str(row["event_key"]),
                    "rootEventId": root_event_id,
                    "eventIdSource": str(row["event_id"]),
                    "payload": {
                        "eventId": root_event_id,
                        "rootEventId": root_event_id,
                        "publicKey": str(row["event_key"]),
                        "outcome": outcome,
                        "reason": "invalid_or_missing_outcome",
                    },
                }
                if value.get("terminalError") is not None:
                    recovery["terminalError"] = value["terminalError"]
                if isinstance(event.get("modelFallback"), dict):
                    recovery["modelFallback"] = dict(event["modelFallback"])
                if _transient_model_error(value.get("terminalError")):
                    failed_model = str(value.get("model") or "").strip() or LEGACY_UNRECORDED_MODEL
                    recovery, fallback_state = advance_model_fallback(
                        recovery,
                        model=failed_model,
                        candidates=EVENT_MODEL_CANDIDATES,
                        error=value.get("terminalError"),
                    )
                    if fallback_state == "exhausted":
                        recovery["terminalReason"] = "model_capacity_retries_exhausted"
                appended = lane.append(recovery, priority=250)
                if (
                    appended
                    and recovery.get("terminalReason") == "model_capacity_retries_exhausted"
                ):
                    lane.terminalize_event(
                        str(recovery["eventId"]),
                        reason="model_capacity_retries_exhausted",
                    )
                elif not appended:
                    _revive_superseded_auth_gap_recovery(lane, recovery)
        elif outcome_state == "design_wait":
            lane.mark_design_wait(str(row["event_id"]))
            until = outcome.get("waitUntil")
            try:
                watch_until = datetime.fromisoformat(str(until).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError):
                watch_until = None
            lane.register_public_work(
                str(row["event_key"]),
                status="design_wait",
                watch_until=watch_until,
                source="turn-outcome",
            )
        elif outcome_state == "claimed_or_pr":
            lane.register_public_work(str(row["event_key"]), status="active", source="turn-outcome")
        elif outcome_state == "no_action":
            lane.clear_public_work(str(row["event_key"]))
        updated += 1
    return updated


def production_queue_snapshot(root: Path) -> dict:
    """Compatibility hook; queue ownership remains outside this listener."""
    del root
    return {}


def bridge_delivery(root: Path, lane: EventLane, event: dict) -> None:
    """Deliver only GitHub observations; the central controller owns queue work."""
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    queue_kinds = {"intents", "prFollowups", "followups", "slowWorkRequests"}
    if event.get("kind") in queue_kinds:
        lane.terminalize_event(
            str(event.get("eventId") or ""),
            status="coalesced",
            reason="retired_shared_queue_mirror",
        )
        return
    target = _resolve_event_target(root, event)
    if event.get("kind") == "outcome_reconcile":
        target = {
            "key": str(event.get("eventKey") or payload.get("publicKey") or ""),
            "kind": "outcome_reconcile",
            "mapped": False,
        }
        issue_handler_delivery(root, lane, event, target=target)
        return
    issue_handler_delivery(root, lane, event, target=target)


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _save_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _sync_public_work_seed(root: Path, lane: EventLane) -> int:
    state = _load_json(root / "state" / "agentscope-public-work.json")
    records = state.get("items") if isinstance(state.get("items"), list) else []
    digest = hashlib.sha256(json.dumps(records, sort_keys=True).encode("utf-8")).hexdigest()
    if lane.state_value("public_work_seed_digest") is not None:
        return 0
    synced = 0
    for value in records:
        if not isinstance(value, dict) or not _is_agentscope_record(value):
            continue
        key = str(value.get("key") or value.get("opportunityKey") or "")
        if not key:
            continue
        status = str(value.get("status") or "active")
        until = value.get("watchUntil") or value.get("designWaitUntil")
        try:
            watch_until = (
                datetime.fromisoformat(str(until).replace("Z", "+00:00")).timestamp()
                if until
                else None
            )
        except ValueError:
            watch_until = None
        if status in {"active", "design_wait"}:
            lane.register_public_work(
                key, status=status, watch_until=watch_until, source="runtime-seed"
            )
        elif status in {"watch_only", "completed", "no_action"}:
            lane.clear_public_work(key)
        synced += 1
    lane.set_state_value(
        "public_work_seed_digest", {"digest": digest, "importedAt": datetime.now(UTC).isoformat()}
    )
    return synced


BOOTSTRAP_BOUNDARY_STATE_KEY = "github_event_bootstrap_boundary_v1"


def _bootstrap_boundary(root: Path, lane: EventLane) -> tuple[datetime | None, dict[str, object]]:
    """Apply the durable listener activation boundary once.

    The boundary is configuration, not a guessed overlap window. Existing
    GitHub rows at or before it are audited as baseline; queue rows are never
    touched. A changed boundary after first application fails closed.
    """
    seed = _load_json(root / "state" / "agentscope-public-work.json")
    raw = seed.get("baselineThrough")
    if not raw:
        return None, {"applied": False, "terminalized": []}
    boundary = _parse_time(str(raw))
    if boundary is None:
        raise RuntimeError("invalid public-work baselineThrough")
    canonical = boundary.isoformat().replace("+00:00", "Z")
    existing = lane.state_value(BOOTSTRAP_BOUNDARY_STATE_KEY)
    if existing is not None:
        if not isinstance(existing, dict):
            raise RuntimeError("invalid persisted GitHub event bootstrap state")
        if str(existing.get("baselineThrough") or "") != canonical:
            raise RuntimeError("public-work baselineThrough changed after bootstrap")
        return boundary, {"applied": False, "terminalized": existing.get("terminalized") or []}
    terminalized = lane.terminalize_github_events_before(boundary)
    audit = {
        "schemaVersion": "agentscope_event_bootstrap_v1",
        "baselineThrough": canonical,
        "appliedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "terminalized": terminalized,
    }
    lane.set_state_value(BOOTSTRAP_BOUNDARY_STATE_KEY, audit)
    return boundary, {"applied": True, "terminalized": terminalized}


def _event_updated_at(event: dict) -> datetime | None:
    return github_event_effective_time(event)


def _is_bootstrap_baseline(event: dict, boundary: datetime | None) -> bool:
    """Suppress only timestamped GitHub events at/before the boundary."""
    if boundary is None or not str(event.get("eventId") or "").startswith("github:"):
        return False
    updated = _event_updated_at(event)
    return updated is not None and updated <= boundary


def run_once(
    root: Path,
    *,
    deliver=None,
    queue: dict | None = None,
    now: datetime | None = None,
    reconcile_interval_seconds: int = 3600,
) -> dict:
    state = root / "state"
    lane = EventLane(state / "agentscope-events.sqlite3")
    production_delivery = deliver is None
    seed_items = _sync_public_work_seed(root, lane)
    bootstrap_boundary, bootstrap = _bootstrap_boundary(root, lane)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    # Normalize old, model-less capacity failures before detached receipts can
    # be interpreted under the current Astra-first fallback policy.
    transient_model_migration = migrate_unmarked_transient_model_recoveries(
        lane,
        namespace=RECOVERY_EVENT_NAMESPACE,
        now=current.timestamp(),
    )
    receipts_reconciled = reconcile_detached_receipts(root, lane)
    expired = lane.expire_claims(now=current.timestamp())
    turns_expired = lane.expire_handler_turns(now=current.timestamp())
    recovery_migration = migrate_recovery_chains(
        lane.path,
        namespace=RECOVERY_EVENT_NAMESPACE,
        apply=True,
    )
    historical_repair = rearm_historical_recoveries(
        lane,
        namespace=RECOVERY_EVENT_NAMESPACE,
        now=current.timestamp(),
    )
    authorization_gap_repair = _repair_exhausted_worker_binding_failures(root, lane)
    poll = GitHubIssuePoller(state / "agentscope-poll.json")
    had_poll_state = (state / "agentscope-poll.json").exists()
    try:
        result = poll.poll(now=current)
    except TypeError:
        # Keep test/in-process adapters written against the original poll().
        try:
            result = poll.poll()
        except Exception as exc:  # noqa: BLE001 - isolate transient transport failures
            if not GitHubIssuePoller._recoverable_poll_error(exc):
                raise
            result = PollResult("degraded", error=f"{type(exc).__name__}:{str(exc)[:400]}")
    except Exception as exc:  # noqa: BLE001 - isolate transient transport failures
        if not GitHubIssuePoller._recoverable_poll_error(exc):
            raise
        result = PollResult("degraded", error=f"{type(exc).__name__}:{str(exc)[:400]}")
    poll_status = str(getattr(result, "status", "unknown") or "unknown")
    poll_error = getattr(result, "error", None)
    reconciliation = _load_json(state / "agentscope-reconcile.json")
    last_full = reconciliation.get("lastCompletedAt")
    last_full_dt = None
    if last_full:
        try:
            last_full_dt = datetime.fromisoformat(str(last_full).replace("Z", "+00:00")).astimezone(
                UTC
            )
        except ValueError:
            last_full_dt = None
    full_result = None
    if (
        poll_status != "degraded"
        and had_poll_state
        and (
            last_full_dt is None
            or current - last_full_dt >= timedelta(seconds=max(1, reconcile_interval_seconds))
        )
    ):
        try:
            full_result = poll.full_reconcile(now=current)
        except Exception as exc:  # noqa: BLE001 - isolate transient transport failures
            if not GitHubIssuePoller._recoverable_poll_error(exc):
                raise
            full_result = PollResult("degraded", error=f"{type(exc).__name__}:{str(exc)[:400]}")
        if str(getattr(full_result, "status", "unknown") or "unknown") != "degraded":
            _save_json(
                state / "agentscope-reconcile.json",
                {
                    "schemaVersion": "agentscope_reconcile_v1",
                    "lastCompletedAt": current.isoformat().replace("+00:00", "Z"),
                },
            )
    # Queue work belongs exclusively to the shared Radar controller.  Older
    # event releases mirrored that queue; retire those rows once rather than
    # draining them or starting issue-specific tasks.
    queue_result = {"imported": 0, "woken": 0}
    legacy_queue_retired = lane.retire_queue_events()
    # Reviews/CI and PR changes outrank issue discovery.  The worker does not
    # make a claim here; claim eligibility remains the existing bridge policy.
    inserted = 0
    events = list(getattr(result, "events", ()) or ())
    if full_result is not None:
        if str(getattr(full_result, "status", "unknown") or "unknown") != "degraded":
            events.extend(getattr(full_result, "events", ()) or ())
    for event in events:
        if _is_bootstrap_baseline(event, bootstrap_boundary):
            baseline_record = lane.record_baseline_event(event)
            if baseline_record not in bootstrap["terminalized"]:
                bootstrap["terminalized"].append(baseline_record)
            continue
        event_key = str(event.get("eventKey") or event.get("targetKey") or "")
        if not event_key and event.get("repo") and event.get("number") is not None:
            event_key = f"{event['repo']}#{event['number']}"
        design_wait = bool(event.get("designWait") and event.get("designWaitUntil"))
        watch_reply = lane.public_status(event_key) == "watch_only" if event_key else False
        priority = (
            250
            if watch_reply
            else (200 if design_wait else (100 if event.get("kind") == "pr_update" else 10))
        )
        inserted += int(lane.append(event, priority=priority))
        if design_wait:
            target = _resolve_event_target(root, event)
            if target.get("key"):
                wait_until = str(event.get("designWaitUntil"))
                lane.register_public_work(
                    str(target["key"]),
                    status="design_wait",
                    watch_until=datetime.fromisoformat(
                        str(wait_until).replace("Z", "+00:00")
                    ).timestamp(),
                    source="github-maintainer-reply",
                )
    if bootstrap_boundary is not None and bootstrap["terminalized"]:
        audit = lane.state_value(BOOTSTRAP_BOUNDARY_STATE_KEY)
        if not isinstance(audit, dict):
            raise RuntimeError("invalid persisted GitHub event bootstrap state")
        audit["terminalized"] = bootstrap["terminalized"]
        lane.set_state_value(BOOTSTRAP_BOUNDARY_STATE_KEY, audit)
    pr_snapshots_coalesced = lane.coalesce_pending_pr_updates(now=current.timestamp())
    issue_snapshots_coalesced = lane.coalesce_pending_issue_updates(now=current.timestamp())
    recovery_settlement = _settle_exhausted_outcome_recoveries(
        root,
        lane,
        now=current.timestamp(),
    )
    recovery_queue = _enqueue_unresolved_outcome_recoveries(lane)
    drained = {"claimed": 0, "delivered": 0, "pending": lane.pending()}
    central_task_busy = production_delivery and _central_handler_busy(lane)
    if deliver is None:

        def deliver(event):
            bridge_delivery(root, lane, event)

    if lane.pending() > 0 and not central_task_busy:
        # One central task can own only one running turn.  Claiming a batch
        # made the later rows spend retry attempts merely because the first
        # row was still running.
        drained = dispatch_once(lane, deliver, limit=1 if production_delivery else 3)
    return {
        "ok": True,
        "status": poll_status,
        "pollStatus": poll_status,
        "pollDegraded": poll_status == "degraded",
        "pollError": str(poll_error)[:400] if poll_error else None,
        "eventsSeen": len(events),
        "eventsInserted": inserted,
        "prSnapshotsCoalesced": pr_snapshots_coalesced,
        "issueSnapshotsCoalesced": issue_snapshots_coalesced,
        "codexWake": bool(drained["delivered"]),
        "drain": drained,
        "receiptsReconciled": receipts_reconciled,
        "queueImported": queue_result["imported"],
        "queueWoken": queue_result["woken"],
        "legacyQueueRetired": legacy_queue_retired,
        "claimsExpired": expired,
        "turnsExpired": turns_expired,
        "recoveryMigration": recovery_migration,
        "transientModelMigration": transient_model_migration,
        "historicalRecoveryRepair": historical_repair,
        "recoveryQueue": recovery_queue,
        "recoverySettlement": recovery_settlement,
        "authorizationGapRepair": authorization_gap_repair,
        "centralTaskBusy": central_task_busy,
        "fullReconciliation": bool(full_result is not None),
        "fullReconciliationDegraded": bool(
            full_result is not None
            and str(getattr(full_result, "status", "unknown") or "unknown") == "degraded"
        ),
        "fullReconciliationEvents": (
            len(getattr(full_result, "events", ()) or ())
            if full_result is not None
            and str(getattr(full_result, "status", "unknown") or "unknown") != "degraded"
            else 0
        ),
        "publicWorkSeedItems": seed_items,
        "bootstrapBoundary": bootstrap_boundary.isoformat().replace("+00:00", "Z")
        if bootstrap_boundary
        else None,
        "bootstrapApplied": bool(bootstrap["applied"]),
        "bootstrapTerminalized": len(bootstrap["terminalized"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_once(args.root)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
