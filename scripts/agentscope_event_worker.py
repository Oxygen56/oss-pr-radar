#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import (  # noqa: E402
    EventLane,
    GitHubIssuePoller,
    dispatch_once,
    github_event_effective_time,
)
from oss_pr_radar.local_publication import run_bridge  # noqa: E402
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
        )
    }
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


def _outcome_recovery_event_id(root_event_id: str) -> str:
    """Return one fixed-length recovery identity for an original event."""
    digest = hashlib.sha256(str(root_event_id).encode("utf-8")).hexdigest()
    return f"outcome-reconcile:{RECOVERY_EVENT_NAMESPACE}:{digest}"


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
                str(row["status"] or "") == "coalesced"
                and str(row["turn_status"] or "") in {"", "superseded"}
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
        if lane.append(recovery, priority=250):
            inserted += 1
        else:
            existing += 1
    return {
        "candidates": candidates,
        "inserted": inserted,
        "existing": existing,
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
) -> Path:
    """Keep every terminal recovery attempt in a distinct evidence file."""
    identity = str(event_id)
    if is_recovery and int(attempt) > 1:
        identity = f"{identity}:attempt:{int(attempt)}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return root / "state" / directory / f"{digest}.json"


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
) -> str:
    """Reuse one recovery row until its existing EventLane budget is spent."""
    now = datetime.now(UTC).timestamp()
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
    client_message_id = f"oss-pr-radar:agentscope-event:{event_id}"
    if is_recovery and recovery_attempt > 1:
        client_message_id += f":attempt:{recovery_attempt}"
    reservation = lane.try_reserve_handler_turn_if_idle(
        key,
        event_id,
        client_message_id,
        lease_token=str(event.get("leaseToken") or ""),
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
    )
    outcome_path = _event_artifact_path(
        root,
        EVENT_OUTCOME_DIR,
        event_id,
        attempt=recovery_attempt,
        is_recovery=is_recovery,
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
        )
        try:
            value = json.loads(receipt.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            continue
        terminal = str(value.get("turnStatus") or "")
        if terminal not in {"completed", "failed", "interrupted"}:
            continue
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
                )
            else:
                lane.append(
                    {
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
                    },
                    priority=250,
                )
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
    receipts_reconciled = reconcile_detached_receipts(root, lane)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    expired = lane.expire_claims(now=current.timestamp())
    turns_expired = lane.expire_handler_turns(now=current.timestamp())
    recovery_migration = migrate_recovery_chains(
        lane.path,
        namespace=RECOVERY_EVENT_NAMESPACE,
        apply=True,
    )
    recovery_queue = _enqueue_unresolved_outcome_recoveries(lane)
    poll = GitHubIssuePoller(state / "agentscope-poll.json")
    had_poll_state = (state / "agentscope-poll.json").exists()
    try:
        result = poll.poll(now=current)
    except TypeError:
        # Keep test/in-process adapters written against the original poll().
        result = poll.poll()
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
    if had_poll_state and (
        last_full_dt is None
        or current - last_full_dt >= timedelta(seconds=max(1, reconcile_interval_seconds))
    ):
        full_result = poll.full_reconcile(now=current)
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
    events = list(result.events)
    if full_result is not None:
        events.extend(full_result.events)
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
        "status": result.status,
        "eventsSeen": len(events),
        "eventsInserted": inserted,
        "prSnapshotsCoalesced": pr_snapshots_coalesced,
        "codexWake": bool(drained["delivered"]),
        "drain": drained,
        "receiptsReconciled": receipts_reconciled,
        "queueImported": queue_result["imported"],
        "queueWoken": queue_result["woken"],
        "legacyQueueRetired": legacy_queue_retired,
        "claimsExpired": expired,
        "turnsExpired": turns_expired,
        "recoveryMigration": recovery_migration,
        "recoveryQueue": recovery_queue,
        "centralTaskBusy": central_task_busy,
        "fullReconciliation": bool(full_result is not None),
        "fullReconciliationEvents": len(full_result.events) if full_result is not None else 0,
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
