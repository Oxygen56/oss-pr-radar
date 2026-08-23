#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once  # noqa: E402
from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.local_publication import run_bridge  # noqa: E402


def issue_handler_delivery(root: Path, lane: EventLane, event: dict) -> None:
    """Start/resume the detached bridge worker and receipt its turn before ack."""
    key = f"{event.get('repo')}#{event.get('number')}"
    binding = lane.handler_thread(key)
    if binding is None:
        with lane.connect() as db:
            active = db.execute(
                "SELECT count(*) FROM event_lane_threads WHERE status IN ('started','reserved')"
            ).fetchone()[0]
        if int(active) >= 3:
            raise RuntimeError("AgentScope handler capacity is full")
    event_id = str(event["eventId"])
    client_message_id = f"oss-pr-radar:agentscope-event:{event_id}"
    lane.reserve_handler_turn(key, event_id, client_message_id)
    prompt = (
        f"Handle AgentScope issue event {event['eventId']} for {event.get('issue', {}).get('html_url') or key}. "
        "First verify it is an open code issue, unassigned, unclaimed, without duplicate PR or maintainer-reserved design. "
        "Only one complete PR is allowed; do not make partial fixes, claims, CLA/AI/legal declarations, force pushes, or destructive changes. "
        "Respect a maximum of three active Oxygen56 tasks and stop in watch-only state when maintainer input is needed for 24 hours. "
        "If eligible, reproduce the behavior, implement the complete issue, run target validation, and prepare the authorized PR."
    )
    receipt = root / "state" / "agentscope_event_receipts" / (
        hashlib.sha256(event_id.encode("utf-8")).hexdigest() + ".json"
    )
    result = run_bridge(
        root,
        "agentscope-event-create",
        timeout=75,
        extra_args=[
            "--event-id", event_id,
            "--event-key", key,
            "--thread-id", str(binding.get("thread_id") or "") if binding else "",
            "--client-user-message-id", client_message_id,
            "--cwd", str(root),
            "--prompt", prompt,
            "--receipt", str(receipt),
        ],
    )
    if result.get("pending") and result.get("turnId"):
        pending_thread = str(result.get("threadId") or (binding or {}).get("thread_id") or "")
        lane.bind_handler_turn(
            key, event_id, pending_thread, str(result["turnId"]), result, status="started"
        )
        return
    if not result.get("ok") or not result.get("turnId"):
        if result.get("retryable"):
            handoff = root / "state" / "agentscope-event-handoffs.jsonl"
            handoff.parent.mkdir(parents=True, exist_ok=True)
            with handoff.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"event": event, "result": result}, sort_keys=True) + "\n")
        raise RuntimeError(f"AgentScope event worker receipt unavailable: {result}")
    lane.bind_handler_turn(
        key,
        event_id,
        str(result["threadId"]),
        str(result["turnId"]),
        result,
        status="started",
    )


def reconcile_detached_receipts(root: Path, lane: EventLane) -> int:
    """Copy terminal state from detached worker receipts into the lane ledger."""
    updated = 0
    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,event_key,thread_id,turn_id,receipt_json FROM event_lane_turns "
            "WHERE status IN ('reserved','started')"
        ).fetchall()
    for row in rows:
        receipt = root / "state" / "agentscope_event_receipts" / (
            hashlib.sha256(str(row["event_id"]).encode("utf-8")).hexdigest() + ".json"
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
        updated += 1
    return updated


def bridge_delivery(root: Path, lane: EventLane, event: dict) -> None:
    """Use the existing serialized drain, whose bridge performs App Server turns."""
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    key = (
        f"{event.get('repo')}#{event.get('number')}"
        if event.get("number") is not None
        else str(payload.get("key") or payload.get("opportunityKey") or payload.get("taskId") or "")
    )
    ledger = RadarLedger(root / "state" / "radar_ledger.sqlite3")
    mapped = any(item.get("key") == key for item in ledger.pending())
    mapped = mapped or any(item.get("key") == key for item in ledger.pr_followup_candidates())
    mapped = mapped or any(item.get("key") == key for item in ledger.implementation_followup_candidates())
    if not mapped and event.get("kind") not in {"intents", "prFollowups", "followups", "slowWorkRequests"}:
        issue_handler_delivery(root, lane, event)
        return
    result = run_bridge(root, "drain-once", timeout=300)
    if not result.get("ok") or result.get("busy"):
        raise RuntimeError(f"event drain not committed: {result}")
    if result.get("key") != key and event.get("kind") not in {
        "intents", "prFollowups", "followups", "slowWorkRequests"
    }:
        raise RuntimeError("event drain did not consume this event")
    if result.get("action") not in {
        "issue_task_dispatched",
        "pr_followup_dispatched",
        "implementation_followup_dispatched",
        "publication_feedback_dispatched",
        "recovery_dispatched",
    }:
        raise RuntimeError("event drain produced no task receipt for this event")
    delivery = result.get("delivery") or {}
    if delivery.get("requiresReconciliation") or delivery.get("requiresDesktopHandoff"):
        handoff = root / "state" / "agentscope-event-handoff.jsonl"
        handoff.parent.mkdir(parents=True, exist_ok=True)
        with handoff.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "result": result}, sort_keys=True) + "\n")
        raise RuntimeError("event drain requires durable handoff/reconciliation")


def run_once(root: Path, *, deliver=None, queue: dict | None = None) -> dict:
    state = root / "state"
    lane = EventLane(state / "agentscope-events.sqlite3")
    receipts_reconciled = reconcile_detached_receipts(root, lane)
    poll = GitHubIssuePoller(state / "agentscope-poll.json")
    result = poll.poll()
    queue_result = lane.import_queue(queue or {}) if queue else {"imported": 0, "woken": 0}
    # Reviews/CI and PR changes outrank issue discovery.  The worker does not
    # make a claim here; claim eligibility remains the existing bridge policy.
    inserted = 0
    for event in result.events:
        priority = 100 if event.get("kind") == "pr_update" else 10
        inserted += int(lane.append(event, priority=priority))
    drained = {"claimed": 0, "delivered": 0, "pending": lane.pending()}
    if deliver is None:
        def deliver(event):
            bridge_delivery(root, lane, event)
    if result.events or queue_result["imported"]:
        drained = dispatch_once(lane, deliver)
    return {
        "ok": True,
        "status": result.status,
        "eventsSeen": len(result.events),
        "eventsInserted": inserted,
        "codexWake": bool(drained["delivered"]),
        "drain": drained,
        "receiptsReconciled": receipts_reconciled,
        "queueImported": queue_result["imported"],
        "queueWoken": queue_result["woken"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        queue_path = args.root / "state" / "agentscope-event-queue.json"
        try:
            queue = json.loads(queue_path.read_text(encoding="utf-8"))
            queue = queue if isinstance(queue, dict) else None
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            queue = None
        result = run_once(args.root, queue=queue)
        if queue is not None and result.get("queueImported", 0) >= 0:
            queue_path.unlink(missing_ok=True)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
