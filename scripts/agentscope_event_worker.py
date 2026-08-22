#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import json
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once  # noqa: E402
from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.local_publication import run_bridge  # noqa: E402

HANDLER_CWD = Path("/Users/oxygen/Documents/github")
HANDLER_TIMEOUT_SECONDS = 45 * 60


def _rpc_response(process: subprocess.Popen[str], request_id: int, *, timeout: float) -> dict:
    if process.stdout is None:
        raise RuntimeError("App Server stdout unavailable")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stdout], [], [], min(1.0, deadline - time.monotonic()))
        if not ready:
            if process.poll() is not None:
                raise RuntimeError("App Server exited before JSON-RPC receipt")
            continue
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("App Server closed before JSON-RPC receipt")
        message = json.loads(line)
        if message.get("id") == request_id:
            if message.get("error"):
                raise RuntimeError(f"App Server JSON-RPC error: {message['error']}")
            return message
    raise TimeoutError(f"App Server response {request_id} timed out")


def issue_handler_delivery(root: Path, lane: EventLane, event: dict) -> None:
    """Start/resume the dedicated issue handler and persist its turn receipt."""
    key = f"{event.get('repo')}#{event.get('number')}"
    binding = lane.handler_thread(key)
    if binding and binding.get("status") == "completed" and binding.get("receipt_json"):
        return
    if binding is None:
        with lane.connect() as db:
            active = db.execute("SELECT count(*) FROM event_lane_threads WHERE status='started'").fetchone()[0]
        if int(active) >= 3:
            raise RuntimeError("AgentScope handler capacity is full")
    executable = shutil.which("codex") or "/opt/homebrew/bin/codex"
    if not Path(executable).exists():
        raise RuntimeError("codex executable is unavailable")
    prompt = (
        f"Handle AgentScope issue event {event['eventId']} for {event.get('issue', {}).get('html_url') or key}. "
        "First verify it is an open code issue, unassigned, unclaimed, without duplicate PR or maintainer-reserved design. "
        "Only one complete PR is allowed; do not make partial fixes, claims, CLA/AI/legal declarations, force pushes, or destructive changes. "
        "Respect a maximum of three active Oxygen56 tasks and stop in watch-only state when maintainer input is needed for 24 hours. "
        "If eligible, reproduce the behavior, implement the complete issue, run target validation, and prepare the authorized PR."
    )
    process = subprocess.Popen([executable, "app-server", "--disable", "recommended_plugins", "--disable", "remote_plugin", "--stdio"], cwd=HANDLER_CWD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
    try:
        assert process.stdin and process.stdout
        requests = [{"id": 1, "method": "initialize", "params": {"clientInfo": {"name": "oss-pr-radar-agentscope", "version": "1"}, "capabilities": {"experimentalApi": True}}}]
        if binding:
            requests.append({"id": 2, "method": "thread/resume", "params": {"threadId": binding["thread_id"]}})
            thread_id = str(binding["thread_id"])
        else:
            requests.append({"id": 2, "method": "thread/start", "params": {"cwd": str(root), "sandbox": "danger-full-access", "approvalPolicy": "never", "threadSource": "appServer"}})
            thread_id = ""
        for request in requests:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()
            message = _rpc_response(process, request["id"], timeout=30)
            if request["id"] == 2 and not binding:
                thread_id = str(((message.get("result") or {}).get("thread") or {}).get("id") or "")
        if not thread_id:
            raise RuntimeError("App Server did not return a thread receipt")
        process.stdin.write(json.dumps({"id": 3, "method": "turn/start", "params": {"threadId": thread_id, "clientUserMessageId": event["eventId"], "input": [{"type": "text", "text": prompt}]}}) + "\n")
        process.stdin.flush()
        turn_id = ""
        message = _rpc_response(process, 3, timeout=30)
        turn_id = str(((message.get("result") or {}).get("turn") or {}).get("id") or "")
        if not turn_id:
            raise RuntimeError("App Server did not return a turn receipt")
        # Do not acknowledge merely because turn/start was accepted.  Keep the
        # app-server owner alive until a terminal notification is observed.
        terminal = None
        deadline = time.monotonic() + HANDLER_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if process.stdout is None:
                break
            ready, _, _ = select.select([process.stdout], [], [], min(1.0, deadline - time.monotonic()))
            if not ready:
                continue
            line = process.stdout.readline()
            if not line:
                break
            notification = json.loads(line)
            params = notification.get("params") or {}
            turn = params.get("turn") or params.get("turnStatus") or {}
            observed_id = str(turn.get("id") or turn.get("turnId") or "")
            status = str(turn.get("status") or params.get("status") or "")
            if observed_id == turn_id and status in {"completed", "failed", "interrupted", "cancelled"}:
                terminal = status
                break
        if terminal is None:
            lane.bind_handler_thread(key, thread_id, turn_id, {"eventId": event["eventId"], "threadId": thread_id, "turnId": turn_id, "status": "timeout"}, status="failed")
            raise TimeoutError("App Server turn did not reach a terminal receipt")
        lane.bind_handler_thread(key, thread_id, turn_id, {"eventId": event["eventId"], "threadId": thread_id, "turnId": turn_id, "status": terminal}, status=terminal)
        if terminal != "completed":
            raise RuntimeError(f"App Server turn ended {terminal}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def bridge_delivery(root: Path, lane: EventLane, event: dict) -> None:
    """Use the existing serialized drain, whose bridge performs App Server turns."""
    key = f"{event.get('repo')}#{event.get('number')}"
    ledger = RadarLedger(root / "state" / "radar_ledger.sqlite3")
    mapped = any(item.get("key") == key for item in ledger.pending())
    mapped = mapped or any(item.get("key") == key for item in ledger.pr_followup_candidates())
    mapped = mapped or any(item.get("key") == key for item in ledger.implementation_followup_candidates())
    if not mapped:
        issue_handler_delivery(root, lane, event)
        return
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
            bridge_delivery(root, lane, event)
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
