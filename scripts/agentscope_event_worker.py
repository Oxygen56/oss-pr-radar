#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once  # noqa: E402
from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.local_publication import run_bridge  # noqa: E402
from oss_pr_radar.release_binding import runtime_ledger_path  # noqa: E402


def _is_agentscope_record(value: dict) -> bool:
    repo = str(value.get("repo") or value.get("repository") or "").casefold()
    if repo == "agentscope-ai/agentscope":
        return True
    for key in ("key", "opportunityKey", "opportunity_key"):
        if str(value.get(key) or "").casefold().startswith("agentscope-ai/agentscope#"):
            return True
    for key in ("issueUrl", "issue_url", "prUrl", "pr_url"):
        if "github.com/agentscope-ai/agentscope/" in str(value.get(key) or "").casefold():
            return True
    return False


def _public_active_keys(root: Path, store: RadarLedger, lane: EventLane) -> set[str]:
    """Count durable public work, including ledger work without a live thread."""
    active: set[str] = set()
    for value in store.pr_followup_candidates() + store.implementation_followup_candidates():
        if _is_agentscope_record(value):
            key = str(value.get("key") or value.get("opportunityKey") or "")
            if key:
                active.add(key)
    try:
        with store.connect() as db:
            rows = db.execute(
                "SELECT p.opportunity_key AS key FROM pr_followups p "
                "JOIN opportunities o ON o.key=p.opportunity_key WHERE o.repo=? "
                "AND o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')",
                ("agentscope-ai/agentscope",),
            ).fetchall()
        active.update(str(row["key"]) for row in rows if row["key"])
    except Exception:
        pass
    active.update(lane.active_work_keys())
    return active


def _pr_number(event: dict) -> int | None:
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    raw = issue.get("number") or event.get("number")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _resolve_event_target(root: Path, event: dict) -> dict[str, object]:
    """Resolve a GitHub PR to its opportunity before selecting a handler."""
    repo = str(event.get("repo") or "")
    number = _pr_number(event)
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    is_pr = bool(event.get("kind") == "pr_update" or issue.get("pull_request"))
    if not is_pr:
        return {"key": f"{repo}#{number}", "kind": "issue", "mapped": False}
    pr_url = str(issue.get("html_url") or issue.get("pull_request", {}).get("html_url") or "")
    ledger = RadarLedger(runtime_ledger_path(root))
    candidates = ledger.pr_followup_candidates()
    candidates += ledger.unresolved_pr_followups()
    try:
        with ledger.connect() as db:
            rows = db.execute(
                "SELECT p.opportunity_key AS key,p.pr_url AS pr_url,"
                "(SELECT i.thread_id FROM intents i WHERE i.opportunity_key=p.opportunity_key "
                "AND i.thread_id IS NOT NULL ORDER BY i.updated_at DESC,i.intent_id DESC LIMIT 1) AS thread_id,"
                "(SELECT i.worktree_path FROM intents i WHERE i.opportunity_key=p.opportunity_key "
                "AND i.thread_id IS NOT NULL ORDER BY i.updated_at DESC,i.intent_id DESC LIMIT 1) AS worktree_path "
                "FROM pr_followups p JOIN opportunities o ON o.key=p.opportunity_key WHERE o.repo=?",
                (repo,),
            ).fetchall()
        candidates += [dict(row) for row in rows]
    except Exception:
        pass
    for candidate in candidates:
        candidate_url = str(candidate.get("prUrl") or candidate.get("pr_url") or "")
        parsed = urlparse(candidate_url)
        candidate_number = parsed.path.rstrip("/").split("/")[-1] if parsed.path else ""
        if number is not None and candidate_number == str(number):
            return {"key": str(candidate.get("key") or ""), "kind": "pr_followup", "mapped": True,
                    "candidate": candidate, "threadId": candidate.get("thread_id") or candidate.get("threadId"),
                    "worktreePath": candidate.get("worktree_path") or candidate.get("worktreePath"), "prUrl": candidate_url}
        if pr_url and candidate_url and pr_url.rstrip("/") == candidate_url.rstrip("/"):
            return {"key": str(candidate.get("key") or ""), "kind": "pr_followup", "mapped": True,
                    "candidate": candidate, "threadId": candidate.get("thread_id") or candidate.get("threadId"),
                    "worktreePath": candidate.get("worktree_path") or candidate.get("worktreePath"), "prUrl": candidate_url}
    # An Oxygen56 PR without a Ledger mapping remains a review/CI watch item;
    # it is never downgraded into a new issue claim.
    return {"key": f"{repo}#{number}", "kind": "pr_watch", "mapped": False, "prUrl": pr_url}


def issue_handler_delivery(root: Path, lane: EventLane, event: dict, *, target: dict[str, object] | None = None) -> None:
    """Start/resume the detached bridge worker and receipt its turn before ack."""
    target = target or _resolve_event_target(root, event)
    key = str(target.get("key") or f"{event.get('repo')}#{event.get('number')}")
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    public_status = lane.public_status(key)
    if str(issue.get("state") or "open").casefold() != "open" and public_status not in {"active", "watch_only"}:
        # A closed ordinary issue is a no-op closeout, not a new public task.
        return
    if str(issue.get("state") or "open").casefold() != "open" and target.get("kind") == "issue":
        target = dict(target)
        target["kind"] = "issue_closeout"
    binding = lane.handler_thread(key)
    if binding is None and target.get("threadId"):
        binding = {"thread_id": str(target["threadId"])}
    binding_active = binding and str(binding.get("status") or "") in {"reserved", "started"}
    if not binding_active:
        active = _public_active_keys(root, RadarLedger(runtime_ledger_path(root)), lane)
        if key not in active and len(active) >= 3:
            raise RuntimeError("AgentScope handler capacity is full")
    event_id = str(event["eventId"])
    client_message_id = f"oss-pr-radar:agentscope-event:{event_id}"
    lane.reserve_handler_turn(key, event_id, client_message_id)
    if target.get("kind") == "pr_followup":
        prompt = (
            f"Handle AgentScope PR follow-up event {event['eventId']} for {target.get('prUrl') or key}. "
            "Resume the mapped opportunity's existing thread. Review maintainer comments, review state, conflicts, and CI; "
            "repair or complete the existing PR only, never claim a new issue or create a duplicate PR. "
            "Before terminal completion, write one machine outcome: no_action, claimed_or_pr, or design_wait with publicKey and wait timestamps."
        )
    elif target.get("kind") == "outcome_reconcile":
        prompt = (
            f"Recover the invalid AgentScope event outcome for {key} in the existing thread. "
            "Do not claim new work or create a PR. Verify the actual terminal state and write a valid outcome JSON "
            "for this exact event/public key using the restricted schema before completion."
        )
    elif target.get("kind") == "pr_watch":
        prompt = (
            f"Watch AgentScope PR event {event['eventId']} for {event.get('issue', {}).get('html_url') or key}. "
            "This is an unmapped Oxygen56 PR review/CI/conflict observation. Do not claim an issue, reserve an opportunity, "
            "or create a new PR; record only actionable maintainer or CI follow-up. "
            "Before terminal completion, write one machine outcome: no_action, claimed_or_pr, or design_wait with publicKey and wait timestamps."
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
    receipt = root / "state" / "agentscope_event_receipts" / (
        hashlib.sha256(event_id.encode("utf-8")).hexdigest() + ".json"
    )
    outcome_path = root / "state" / "agentscope_event_outcomes" / (
        hashlib.sha256(event_id.encode("utf-8")).hexdigest() + ".json"
    )
    outcome_instruction = (
        f" Write the terminal outcome JSON to {outcome_path}: schemaVersion=agentscope_event_outcome_v1, "
        f"eventId={event_id}, publicKey={key}, state one of no_action/claimed_or_pr/design_wait; "
        "design_wait must include waitStartedAt and waitUntil no more than 24 hours apart."
    )
    prompt += outcome_instruction
    result = run_bridge(
        root,
        "agentscope-event-create",
        timeout=75,
        code_root=ROOT,
        inactive_release=True,
        extra_args=[
            "--event-id", event_id,
            "--event-key", key,
            "--thread-id", str(binding.get("thread_id") or "") if binding else "",
            "--client-user-message-id", client_message_id,
            "--cwd", str(target.get("worktreePath") or root),
            "--prompt", prompt,
            "--receipt", str(receipt),
            "--outcome-receipt", str(outcome_path),
            "--design-wait-until", str(event.get("designWaitUntil") or ""),
            "--design-wait-started-at", str(event.get("designWaitStartedAt") or event.get("updatedAt") or ""),
        ],
    )
    if result.get("pending") and result.get("turnId"):
        pending_thread = str(result.get("threadId") or (binding or {}).get("thread_id") or "")
        lane.bind_handler_turn(
            key, event_id, pending_thread, str(result["turnId"]), result, status="started"
        )
        if result.get("designWait") or result.get("status") == "watch_only":
            lane.mark_design_wait(event_id)
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
    if result.get("designWait") or result.get("status") == "watch_only":
        lane.mark_design_wait(event_id)


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
        if value.get("designWait") or value.get("status") == "watch_only":
            lane.mark_design_wait(str(row["event_id"]))
        outcome = value.get("outcome") if isinstance(value.get("outcome"), dict) else {}
        outcome_state = str(outcome.get("state") or "")
        if outcome.get("error") or not outcome_state:
            lane.register_public_work(str(row["event_key"]), status="active", source="outcome-invalid")
            lane.bind_handler_turn(
                str(row["event_key"]), str(row["event_id"]), str(row["thread_id"]),
                str(row["turn_id"]), value, status="needs_reconcile",
            )
            lane.append({
                "eventId": f"outcome-reconcile:{row['event_id']}:{hashlib.sha256(json.dumps(outcome, sort_keys=True).encode()).hexdigest()[:16]}",
                "kind": "outcome_reconcile", "eventKey": str(row["event_key"]),
                "eventIdSource": str(row["event_id"]), "payload": {
                    "eventId": str(row["event_id"]), "publicKey": str(row["event_key"]),
                    "outcome": outcome, "reason": "invalid_or_missing_outcome",
                },
            }, priority=250)
        elif outcome_state == "design_wait":
            lane.mark_design_wait(str(row["event_id"]))
            until = outcome.get("waitUntil")
            try:
                watch_until = datetime.fromisoformat(str(until).replace("Z", "+00:00")).timestamp()
            except (TypeError, ValueError):
                watch_until = None
            lane.register_public_work(str(row["event_key"]), status="design_wait", watch_until=watch_until, source="turn-outcome")
        elif outcome_state == "claimed_or_pr":
            lane.register_public_work(str(row["event_key"]), status="active", source="turn-outcome")
        elif outcome_state == "no_action":
            lane.clear_public_work(str(row["event_key"]))
        updated += 1
    return updated


def production_queue_snapshot(root: Path) -> dict:
    """Read existing local durable work without invoking the shared workers."""
    try:
        ledger_path = runtime_ledger_path(root)
        if not ledger_path.exists():
            return {}
        store = RadarLedger(ledger_path)
        intents = [item for item in store.pending() if _is_agentscope_record(item)]
        pr_followups = [item for item in store.pr_followup_candidates() if _is_agentscope_record(item)]
        followups = [item for item in store.implementation_followup_candidates() if _is_agentscope_record(item)]
        queue: dict = {
            "intents": intents,
            "prFollowups": pr_followups,
            "followups": followups,
        }
        slow_path = root / "state" / "slow-work-request.json"
        try:
            slow = json.loads(slow_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            slow = {}
        if isinstance(slow, dict) and slow.get("reasons") and _is_agentscope_record(slow):
            queue["slowWorkRequests"] = [slow]
        return queue
    except (OSError, RuntimeError, ValueError, TypeError):
        return {}


def bridge_delivery(root: Path, lane: EventLane, event: dict) -> None:
    """Use the existing serialized drain, whose bridge performs App Server turns."""
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    queue_kinds = {"intents", "prFollowups", "followups", "slowWorkRequests"}
    task_id = ""
    if event.get("kind") in queue_kinds:
        key = str(event.get("targetKey") or payload.get("key") or payload.get("opportunityKey") or "")
        task_id = str(event.get("taskId") or payload.get("taskId") or payload.get("intentId") or "")
        target = {"key": key, "kind": "queue", "mapped": True, "taskId": task_id}
    else:
        target = _resolve_event_target(root, event)
        key = str(target.get("key") or "")
    mapped = bool(target.get("mapped"))
    if event.get("kind") == "outcome_reconcile":
        target = {"key": str(event.get("eventKey") or payload.get("publicKey") or ""),
                  "kind": "outcome_reconcile", "mapped": False}
        issue_handler_delivery(root, lane, event, target=target)
        return
    if event.get("kind") == "pr_update" or (not mapped and event.get("kind") not in queue_kinds):
        issue_handler_delivery(root, lane, event, target=target)
        return
    result = run_bridge(root, "drain-once", timeout=300)
    if not result.get("ok") or result.get("busy"):
        raise RuntimeError(f"event drain not committed: {result}")
    if key and result.get("key") != key:
        raise RuntimeError(f"event drain consumed {result.get('key')!r}, expected {key!r}")
    if not key and task_id and str(result.get("taskId") or result.get("intentId") or "") != task_id:
        raise RuntimeError("event drain did not consume this queue task")
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
            watch_until = datetime.fromisoformat(str(until).replace("Z", "+00:00")).timestamp() if until else None
        except ValueError:
            watch_until = None
        if status in {"active", "design_wait"}:
            lane.register_public_work(key, status=status, watch_until=watch_until, source="runtime-seed")
        elif status in {"watch_only", "completed", "no_action"}:
            lane.clear_public_work(key)
        synced += 1
    lane.set_state_value("public_work_seed_digest", {"digest": digest, "importedAt": datetime.now(UTC).isoformat()})
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
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    raw = event.get("updatedAt") or issue.get("updated_at")
    return _parse_time(str(raw or ""))


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
    seed_items = _sync_public_work_seed(root, lane)
    bootstrap_boundary, bootstrap = _bootstrap_boundary(root, lane)
    receipts_reconciled = reconcile_detached_receipts(root, lane)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    expired = lane.expire_claims(now=current.timestamp())
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
            last_full_dt = datetime.fromisoformat(str(last_full).replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            last_full_dt = None
    full_result = None
    if had_poll_state and (last_full_dt is None or current - last_full_dt >= timedelta(seconds=max(1, reconcile_interval_seconds))):
        full_result = poll.full_reconcile(now=current)
        _save_json(state / "agentscope-reconcile.json", {
            "schemaVersion": "agentscope_reconcile_v1",
            "lastCompletedAt": current.isoformat().replace("+00:00", "Z"),
        })
    queue_payload = queue if queue is not None else production_queue_snapshot(root)
    queue_result = (
        lane.import_queue(queue_payload)
        if queue_payload
        else {"imported": 0, "woken": 0}
    )
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
        priority = 250 if watch_reply else (200 if design_wait else (100 if event.get("kind") == "pr_update" else 10))
        inserted += int(lane.append(event, priority=priority))
        if design_wait:
            target = _resolve_event_target(root, event)
            if target.get("key"):
                wait_until = str(event.get("designWaitUntil"))
                lane.register_public_work(
                    str(target["key"]), status="design_wait",
                    watch_until=datetime.fromisoformat(str(wait_until).replace("Z", "+00:00")).timestamp(),
                    source="github-maintainer-reply",
                )
    if bootstrap_boundary is not None and bootstrap["terminalized"]:
        audit = lane.state_value(BOOTSTRAP_BOUNDARY_STATE_KEY)
        if not isinstance(audit, dict):
            raise RuntimeError("invalid persisted GitHub event bootstrap state")
        audit["terminalized"] = bootstrap["terminalized"]
        lane.set_state_value(BOOTSTRAP_BOUNDARY_STATE_KEY, audit)
    drained = {"claimed": 0, "delivered": 0, "pending": lane.pending()}
    if deliver is None:
        def deliver(event):
            bridge_delivery(root, lane, event)
    if lane.pending() > 0:
        drained = dispatch_once(lane, deliver)
    return {
        "ok": True,
        "status": result.status,
        "eventsSeen": len(events),
        "eventsInserted": inserted,
        "codexWake": bool(drained["delivered"]),
        "drain": drained,
        "receiptsReconciled": receipts_reconciled,
        "queueImported": queue_result["imported"],
        "queueWoken": queue_result["woken"],
        "claimsExpired": expired,
        "fullReconciliation": bool(full_result is not None),
        "fullReconciliationEvents": len(full_result.events) if full_result is not None else 0,
        "publicWorkSeedItems": seed_items,
        "bootstrapBoundary": bootstrap_boundary.isoformat().replace("+00:00", "Z") if bootstrap_boundary else None,
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
