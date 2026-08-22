#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once  # noqa: E402
from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.local_publication import run_bridge  # noqa: E402


def bridge_delivery(root: Path, event: dict) -> None:
    """Use the existing serialized drain, whose bridge performs App Server turns."""
    key = f"{event.get('repo')}#{event.get('number')}"
    ledger = RadarLedger(root / "state" / "radar_ledger.sqlite3")
    mapped = any(item.get("key") == key for item in ledger.pending())
    mapped = mapped or any(item.get("key") == key for item in ledger.pr_followup_candidates())
    mapped = mapped or any(item.get("key") == key for item in ledger.implementation_followup_candidates())
    if not mapped:
        raise RuntimeError("event has no existing ledger task/thread mapping")
    result = run_bridge(root, "drain-once", timeout=300)
    if not result.get("ok") or result.get("busy"):
        raise RuntimeError(f"event drain not committed: {result}")
    if result.get("key") != key:
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


def run_once(root: Path, *, deliver=None) -> dict:
    state = root / "state"
    lane = EventLane(state / "agentscope-events.sqlite3")
    poll = GitHubIssuePoller(state / "agentscope-poll.json")
    result = poll.poll()
    # Reviews/CI and PR changes outrank issue discovery.  The worker does not
    # make a claim here; claim eligibility remains the existing bridge policy.
    inserted = lane.append_many(
        result.events,
        priority=100 if any(event.get("kind") == "pr_update" for event in result.events) else 10,
    )
    drained = {"claimed": 0, "delivered": 0, "pending": lane.pending()}
    if deliver is None:
        def deliver(event):
            bridge_delivery(root, event)
    if result.events:
        drained = dispatch_once(lane, deliver)
    return {
        "ok": True,
        "status": result.status,
        "eventsSeen": len(result.events),
        "eventsInserted": inserted,
        "codexWake": bool(drained["delivered"]),
        "drain": drained,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run_once(args.root), ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
