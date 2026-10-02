from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

import pytest

from oss_pr_radar.agentscope_events import (
    EventLane,
    GitHubIssuePoller,
    _event_bridge_process_alive,
    _github_event_id,
    _github_event_identity,
    dispatch_once,
)
from scripts import migrate_event_recovery_chains as recovery_migration

CENTRAL_THREAD = "01a0399e-f694-7213-98e6-9d7c4808dfa2"


def _configure_manifest(worker, root: Path, monkeypatch) -> None:
    central_cwd = root / "agentscope"
    central_cwd.mkdir(exist_ok=True)
    monkeypatch.setattr(worker, "CENTRAL_CWD", central_cwd.resolve())
    value = {
        "schemaVersion": "oss-pr-radar-event-lane-v1",
        "repositories": {
            "agentscope-ai/agentscope": {
                "activeThreadId": CENTRAL_THREAD,
                "cwd": str(worker.CENTRAL_CWD),
            },
        },
    }
    data = json.dumps(value, sort_keys=True, indent=2).encode("utf-8")
    (root / worker.EVENT_LANE_MANIFEST).write_bytes(data)
    (root / worker.EVENT_LANE_DIGEST).write_text(
        f"{hashlib.sha256(data).hexdigest()}  {worker.EVENT_LANE_MANIFEST}\n", encoding="utf-8"
    )
    monkeypatch.setattr(worker, "ROOT", root)


def _event_worker_module():
    path = Path(__file__).parents[1] / "scripts" / "agentscope_event_worker.py"
    spec = importlib.util.spec_from_file_location("agentscope_event_worker", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_poll_health_persists_failures_without_advancing_watermark(tmp_path):
    failed = False

    def transport(url, headers):
        nonlocal failed
        if "direction=desc" in url:
            if not failed:
                return 200, {"ETag": "gate"}, [_issue(1, "2026-08-22T00:00:00Z")]
            raise urllib.error.URLError("TLS handshake failed")
        return 200, {}, []

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport)
    first = poller.poll(now=datetime(2026, 8, 22, tzinfo=UTC))
    state_path = tmp_path / "poll.json"
    baseline = json.loads(state_path.read_text())
    failed = True
    second = poller.poll(now=datetime(2026, 8, 22, 0, 0, 1, tzinfo=UTC))
    state = json.loads(state_path.read_text())
    assert first.status == "baseline"
    assert second.status == "degraded"
    assert state["watermark"] == baseline["watermark"]
    assert state["lastSuccessAt"] == "2026-08-22T00:00:00Z"
    assert state["consecutiveFailures"] == 1
    assert state["pollHealthStatus"] == "recovering"
    assert state["failureWindowFailures"] == 1
    for second_offset in (2, 3):
        assert (
            poller.poll(now=datetime(2026, 8, 22, 0, 0, second_offset, tzinfo=UTC)).status
            == "degraded"
        )
    state = json.loads(state_path.read_text())
    assert state["consecutiveFailures"] == 3
    assert state["pollHealthStatus"] == "degraded"
    assert state["watermark"] == baseline["watermark"]

    failed = False
    recovered = poller.poll(now=datetime(2026, 8, 22, 0, 0, 4, tzinfo=UTC))
    state = json.loads(state_path.read_text())
    assert recovered.status == "ok"
    assert state["consecutiveFailures"] == 0
    assert state["pollHealthStatus"] == "healthy"


def test_poll_logic_error_is_not_hidden_but_failure_is_recorded(tmp_path):
    def transport(_url, _headers):
        raise AssertionError("fixture bug")

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport)
    with pytest.raises(AssertionError, match="fixture bug"):
        poller.poll(now=datetime(2026, 8, 22, tzinfo=UTC))
    state = json.loads((tmp_path / "poll.json").read_text())
    assert state["consecutiveFailures"] == 1
    assert state["lastError"].startswith("AssertionError:")


def _authorization_bridge_error(operation: str, reason: str, **extra) -> RuntimeError:
    envelope = {
        "ok": False,
        "error": f"operational authorization required: {reason}",
    }
    envelope.update(extra)
    return RuntimeError(f"{operation}: {json.dumps(envelope, sort_keys=True)}")


def test_event_worker_starts_from_an_unrelated_working_directory(tmp_path):
    script = Path(__file__).parents[1] / "scripts" / "agentscope_event_worker.py"
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--root" in result.stdout


def test_operational_authorization_gap_classifier_is_cutover_only():
    worker = _event_worker_module()
    planned = (
        "operational authorization is missing or not a regular file",
        "operational authorization has not been activated",
        "operational authorization release binding mismatch",
        "operational authorization ledger pointer is invalid",
        "operational authorization ledger binding mismatch",
        "operational authorization is not yet valid",
        "operational authorization worker binding is invalid",
    )
    permanent = (
        "operational authorization schema is invalid",
        "operational authorization permissions are unsafe",
        "operational authorization authentication failed",
    )
    for reason in planned:
        assert worker._is_operational_authorization_gap(
            _authorization_bridge_error("agentscope-event-create", reason)
        )
    for reason in permanent:
        assert not worker._is_operational_authorization_gap(
            _authorization_bridge_error("agentscope-event-create", reason)
        )
    allowed_error = f"operational authorization required: {planned[0]}"
    assert worker._is_operational_authorization_gap(
        {"ok": False, "error": allowed_error, "turnStarted": False}
    )
    assert not worker._is_operational_authorization_gap({"ok": False, "error": allowed_error})
    assert not worker._is_operational_authorization_gap(
        {"ok": False, "error": allowed_error, "turnStarted": True}
    )
    assert not worker._is_operational_authorization_gap(
        {
            "ok": False,
            "error": allowed_error,
            "turnStarted": False,
            "turnId": "remote-turn",
        }
    )
    assert not worker._is_operational_authorization_gap(
        {
            "ok": False,
            "error": allowed_error,
            "turnStarted": False,
            "threadId": "remote-thread",
        }
    )
    assert not worker._is_operational_authorization_gap(
        _authorization_bridge_error("nanobot-event-create", planned[0])
    )
    assert not worker._is_operational_authorization_gap(
        _authorization_bridge_error("agentscope-event-create", planned[0], turnStarted=False)
    )
    assert not worker._is_operational_authorization_gap(
        RuntimeError(f"agentscope-event-create: operational authorization required: {planned[0]}")
    )


def _issue(number: int, updated: str, *, pr: bool = False) -> dict:
    value = {
        "number": number,
        "updated_at": updated,
        "title": f"item {number}",
        "labels": [{"name": "bug"}],
    }
    if pr:
        value["pull_request"] = {"url": "https://example.test/pr"}
    return value


def test_poller_304_is_empty_and_sends_conditional_headers(tmp_path):
    calls = []

    def transport(url, headers):
        calls.append((url, headers))
        if len(calls) == 1:
            return 200, {"ETag": '"v1"'}, [_issue(1, "2026-08-22T00:00:00Z")]
        return 304, {"ETag": '"v1"'}, None

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport)
    baseline = poller.poll(now=datetime(2026, 8, 22, tzinfo=UTC))
    second = poller.poll(now=datetime(2026, 8, 22, 0, 1, tzinfo=UTC))
    assert baseline.status == "baseline"
    assert second.status == "not_modified" and not second.events
    assert calls[1][1]["If-None-Match"] == '"v1"'


def test_poller_paginates_with_overlap_and_dedupes_at_lane(tmp_path):
    calls = []

    def transport(url, headers):
        calls.append(url)
        if "direction=desc" in url:
            return 200, {"ETag": "gate"}, [_issue(3, "2026-08-22T00:02:00Z")]
        if "page=1" in url:
            return (
                200,
                {},
                [
                    _issue(1, "2026-08-22T00:00:00Z"),
                    _issue(2, "2026-08-22T00:01:00Z"),
                    _issue(3, "2026-08-22T00:02:00Z"),
                ],
            )
        return 200, {}, [_issue(3, "2026-08-22T00:02:00Z")]

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport, per_page=3)
    assert poller.poll().status == "baseline"
    result = poller.poll()
    lane = EventLane(tmp_path / "events.db")
    assert len(result.events) == 4 and len(calls) == 4
    assert lane.append_many(result.events) == 3
    assert lane.append(result.events[0]) is False


def test_crash_retry_and_priority(tmp_path):
    lane = EventLane(tmp_path / "events.db", lease_seconds=5)
    lane.append({"eventId": "low", "kind": "issue"}, priority=1, now=0)
    lane.append({"eventId": "high", "kind": "review"}, priority=100, now=0)
    seen = []

    def deliver(event):
        seen.append(event["eventId"])
        if event["eventId"] == "high" and seen.count("high") == 1:
            raise RuntimeError("crash")

    assert dispatch_once(lane, deliver, limit=2, now=0)["delivered"] == 1
    assert dispatch_once(lane, deliver, limit=2, now=6)["delivered"] == 1
    assert seen[:2] == ["high", "low"]
    assert seen[2] == "high"


def test_queue_import_includes_followups_and_wakes_once(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    wakes = []
    result = lane.import_queue(
        {
            "intents": [{"intentId": "i1", "threadId": "t1"}],
            "prFollowups": [{"taskId": "i1", "kind": "review"}],
            "slowWorkRequests": [{"taskId": "i2"}],
        },
        wake=wakes.append,
    )
    assert result == {"imported": 3, "woken": 2}
    assert {item["taskId"] for item in wakes} == {"i1", "i2"}


def test_ttl_marks_stale_pending_watch_only(tmp_path):
    lane = EventLane(tmp_path / "events.db", ttl_seconds=10)
    lane.append({"eventId": "old", "designWait": True}, now=0)
    assert lane.expire_claims(now=11) == 1
    assert lane.pending() == 0


def test_lease_owner_and_token_condition_ack(tmp_path):
    lane = EventLane(tmp_path / "events.db", lease_seconds=5)
    lane.append({"eventId": "e1"}, now=0)
    claimed = lane.claim(owner="worker-a", now=0)
    assert claimed[0]["leaseOwner"] == "worker-a"
    assert lane.ack("e1", lease_token=claimed[0]["leaseToken"], owner="worker-b") is False
    assert lane.pending() == 1
    assert lane.ack("e1", lease_token=claimed[0]["leaseToken"], owner="worker-a") is True
    assert lane.pending() == 0


def test_prestart_authorization_gap_refund_is_token_bound(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    lane.append({"eventId": "auth-gap", "eventKey": "agentscope-ai/agentscope#1"})
    claimed = lane.claim(owner="worker-a")[0]
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "auth-gap", "client:auth-gap")

    assert (
        lane.defer_prestart_authorization_gap(
            "auth-gap", lease_token="wrong-token", owner="worker-a"
        )
        is False
    )
    assert (
        lane.defer_prestart_authorization_gap(
            "auth-gap", lease_token=claimed["leaseToken"], owner="worker-a"
        )
        is True
    )

    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,lease_token FROM event_lane_events WHERE event_id='auth-gap'"
        ).fetchone()
    assert dict(row) == {"status": "pending", "attempts": 0, "lease_token": None}
    assert lane.handler_turn("auth-gap") is None

    lane.append({"eventId": "zero-attempt", "eventKey": "agentscope-ai/agentscope#2"})
    lane.reserve_handler_turn("agentscope-ai/agentscope#2", "zero-attempt", "client:zero-attempt")
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='leased',lease_owner='worker-a',"
            "lease_token='zero-token' WHERE event_id='zero-attempt'"
        )
    assert (
        lane.defer_prestart_authorization_gap(
            "zero-attempt", lease_token="zero-token", owner="worker-a"
        )
        is False
    )
    with lane.connect() as db:
        zero = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id='zero-attempt'"
        ).fetchone()
    assert dict(zero) == {"status": "leased", "attempts": 0}
    assert lane.handler_turn("zero-attempt")["status"] == "reserved"

    lane.append({"eventId": "started-turn", "eventKey": "agentscope-ai/agentscope#3"})
    started = next(
        item for item in lane.claim(owner="worker-a") if item["eventId"] == "started-turn"
    )
    lane.reserve_handler_turn("agentscope-ai/agentscope#3", "started-turn", "client:started-turn")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#3",
        "started-turn",
        "thread-started",
        "turn-started",
        {"turnStarted": True},
    )
    assert (
        lane.defer_prestart_authorization_gap(
            "started-turn", lease_token=started["leaseToken"], owner="worker-a"
        )
        is False
    )
    with lane.connect() as db:
        started_row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id='started-turn'"
        ).fetchone()
    assert dict(started_row) == {"status": "leased", "attempts": 1}
    assert lane.handler_turn("started-turn")["status"] == "started"


def test_atomic_handler_gate_serializes_two_claimed_events(tmp_path):
    path = tmp_path / "events.db"
    lane = EventLane(path)
    for number in (1, 2):
        lane.append(
            {
                "eventId": f"race-{number}",
                "eventKey": f"agentscope-ai/agentscope#{number}",
            }
        )
    claimed = lane.claim(limit=2, owner="worker-a")
    barrier = Barrier(2)

    def reserve(event):
        connection = EventLane(path)
        barrier.wait(timeout=5)
        result = connection.try_reserve_handler_turn_if_idle(
            str(event["eventKey"]),
            str(event["eventId"]),
            f"client:{event['eventId']}",
            lease_token=str(event["leaseToken"]),
            owner="worker-a",
        )
        return str(event["eventId"]), str(result["status"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = dict(executor.map(reserve, claimed))

    assert sorted(outcomes.values()) == ["busy", "reserved"]
    reserved_event = next(event_id for event_id, status in outcomes.items() if status == "reserved")
    busy_event = next(event_id for event_id, status in outcomes.items() if status == "busy")
    with lane.connect() as db:
        rows = {
            str(row["event_id"]): dict(row)
            for row in db.execute(
                "SELECT event_id,status,attempts,lease_owner,lease_token "
                "FROM event_lane_events WHERE event_id IN ('race-1','race-2')"
            ).fetchall()
        }
        turns = db.execute(
            "SELECT event_id,status FROM event_lane_turns WHERE status IN ('reserved','started')"
        ).fetchall()
        reconcile_count = db.execute(
            "SELECT count(*) FROM event_lane_turns WHERE status='needs_reconcile'"
        ).fetchone()[0]
    assert rows[reserved_event]["status"] == "leased"
    assert rows[reserved_event]["attempts"] == 1
    assert rows[reserved_event]["lease_owner"] == "worker-a"
    assert rows[reserved_event]["lease_token"]
    assert rows[busy_event] == {
        "event_id": busy_event,
        "status": "pending",
        "attempts": 0,
        "lease_owner": None,
        "lease_token": None,
    }
    assert [dict(turn) for turn in turns] == [{"event_id": reserved_event, "status": "reserved"}]
    assert reconcile_count == 0


def test_atomic_handler_gate_resets_empty_reconcile_and_rejects_bad_lease(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    lane.append(
        {
            "eventId": "resettable",
            "eventKey": "agentscope-ai/agentscope#1",
        }
    )
    reset_claim = lane.claim(limit=1, owner="worker-a")[0]
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "resettable", "client:old")
    assert lane.release_handler_reservation("resettable", {"error": "pre-turn"}, reason="pre-turn")

    reset = lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#1",
        "resettable",
        "client:new",
        lease_token=str(reset_claim["leaseToken"]),
        owner="worker-a",
    )

    assert reset["status"] == "reserved"
    turn = lane.handler_turn("resettable")
    assert turn is not None
    assert turn["status"] == "reserved"
    assert turn["client_user_message_id"] == "client:new"
    assert turn["thread_id"] == ""
    assert turn["turn_id"] is None
    assert json.loads(turn["receipt_json"]) == {}

    lane.append(
        {
            "eventId": "bad-lease",
            "eventKey": "agentscope-ai/agentscope#2",
        }
    )
    bad_claim = lane.claim(limit=1, owner="worker-a")[0]
    assert lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#2",
        "bad-lease",
        "client:bad",
        lease_token="wrong-token",
        owner="worker-a",
    ) == {"status": "conflict", "reason": "lease_mismatch"}
    assert lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#2",
        "bad-lease",
        "client:bad",
        lease_token=str(bad_claim["leaseToken"]),
        owner="worker-b",
    ) == {"status": "conflict", "reason": "lease_mismatch"}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,lease_owner,lease_token FROM event_lane_events "
            "WHERE event_id='bad-lease'"
        ).fetchone()
    assert dict(row) == {
        "status": "leased",
        "attempts": 1,
        "lease_owner": "worker-a",
        "lease_token": bad_claim["leaseToken"],
    }
    assert lane.handler_turn("bad-lease") is None


def test_atomic_handler_gate_preserves_reconcile_receipts_on_busy_or_conflict(
    tmp_path,
):
    lane = EventLane(tmp_path / "events.db")
    lane.reserve_handler_turn("agentscope-ai/agentscope#99", "active", "client:active")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#99",
        "active",
        "thread-active",
        "turn-active",
        {"turnStarted": True},
        status="started",
    )
    lane.append(
        {
            "eventId": "empty-reconcile",
            "eventKey": "agentscope-ai/agentscope#1",
        }
    )
    empty_claim = lane.claim(limit=1, owner="worker-a")[0]
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "empty-reconcile", "client:old")
    assert lane.release_handler_reservation(
        "empty-reconcile", {"marker": "keep"}, reason="pre-turn"
    )
    before_empty = lane.handler_turn("empty-reconcile")

    busy = lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#1",
        "empty-reconcile",
        "client:new",
        lease_token=str(empty_claim["leaseToken"]),
        owner="worker-a",
    )

    assert busy == {"status": "busy", "activeEventId": "active"}
    with lane.connect() as db:
        empty_event = db.execute(
            "SELECT status,attempts,lease_owner,lease_token FROM event_lane_events "
            "WHERE event_id='empty-reconcile'"
        ).fetchone()
    assert dict(empty_event) == {
        "status": "pending",
        "attempts": 0,
        "lease_owner": None,
        "lease_token": None,
    }
    assert lane.handler_turn("empty-reconcile") == before_empty

    lane.append(
        {
            "eventId": "remote-reconcile",
            "eventKey": "agentscope-ai/agentscope#2",
        },
        priority=100,
    )
    remote_claim = lane.claim(limit=1, owner="worker-a")[0]
    lane.reserve_handler_turn("agentscope-ai/agentscope#2", "remote-reconcile", "client:remote")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#2",
        "remote-reconcile",
        "thread-remote",
        "turn-remote",
        {"marker": "remote"},
        status="needs_reconcile",
    )
    before_remote = lane.handler_turn("remote-reconcile")

    conflict = lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#2",
        "remote-reconcile",
        "client:replacement",
        lease_token=str(remote_claim["leaseToken"]),
        owner="worker-a",
    )

    assert conflict == {"status": "conflict", "reason": "turn_conflict"}
    with lane.connect() as db:
        remote_event = db.execute(
            "SELECT status,attempts,lease_owner,lease_token FROM event_lane_events "
            "WHERE event_id='remote-reconcile'"
        ).fetchone()
    assert dict(remote_event) == {
        "status": "leased",
        "attempts": 1,
        "lease_owner": "worker-a",
        "lease_token": remote_claim["leaseToken"],
    }
    assert lane.handler_turn("remote-reconcile") == before_remote


def _prepare_bound_recovery_retry(lane: EventLane, *, receipt: dict) -> tuple[str, dict]:
    """Create one leased recovery event with an already-bound old turn."""
    event_id = "outcome-reconcile:agentscope:retry-bound"
    event_key = "agentscope-ai/agentscope#1"
    lane.append(
        {
            "eventId": event_id,
            "eventKey": event_key,
            "kind": "outcome_reconcile",
            "rootEventId": "root-retry-bound",
            "payload": {"eventId": "root-retry-bound", "publicKey": event_key},
        },
        priority=250,
    )
    claimed = lane.claim(limit=1, owner="worker-a")[0]
    lane.reserve_handler_turn(event_key, event_id, "client:old")
    lane.bind_handler_turn(
        event_key,
        event_id,
        "thread-old",
        "turn-old",
        receipt,
        status="needs_reconcile",
    )
    return event_id, claimed


def test_recovery_retry_resets_dead_bound_turn_and_preserves_bounded_history(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    event_id, claimed = _prepare_bound_recovery_retry(
        lane,
        receipt={
            "turnStatus": "completed",
            "workerPid": 1_000_000_000,
            "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
        },
    )

    result = lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#1",
        event_id,
        "client:new",
        lease_token=str(claimed["leaseToken"]),
        owner="worker-a",
        recovery_retry=True,
    )

    assert result["status"] == "reserved"
    turn = lane.handler_turn(event_id)
    assert turn is not None
    assert turn["thread_id"] == ""
    assert turn["turn_id"] is None
    reset_receipt = json.loads(turn["receipt_json"])
    assert reset_receipt["retryOfTurnId"] == "turn-old"
    assert reset_receipt["receiptHistory"][0]["receipt"]["turnStatus"] == "completed"

    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        event_id,
        "thread-new",
        "turn-new",
        {"turnStatus": "completed", "outcome": {"error": "again"}},
        status="completed",
    )
    rebound = lane.handler_turn(event_id)
    assert rebound is not None
    assert (
        json.loads(rebound["receipt_json"])["receiptHistory"][0]["receipt"]["workerPid"]
        == 1_000_000_000
    )
    thread = lane.handler_thread("agentscope-ai/agentscope#1")
    assert thread is not None
    assert (
        json.loads(thread["receipt_json"])["receiptHistory"][0]["receipt"]["turnStatus"]
        == "completed"
    )


def test_recovery_retry_does_not_clear_live_or_valid_bound_turn(tmp_path, monkeypatch):
    lane = EventLane(tmp_path / "events.db")
    event_id, claimed = _prepare_bound_recovery_retry(
        lane,
        receipt={
            "turnStatus": "completed",
            "workerPid": 1234,
            "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
        },
    )
    monkeypatch.setattr(
        "oss_pr_radar.agentscope_events._event_bridge_process_alive", lambda _pid: True
    )
    live = lane.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#1",
        event_id,
        "client:new",
        lease_token=str(claimed["leaseToken"]),
        owner="worker-a",
        recovery_retry=True,
    )
    assert live == {
        "status": "busy",
        "activeEventId": event_id,
        "reason": "recovery_process_active",
    }
    assert lane.handler_turn(event_id)["turn_id"] == "turn-old"
    with lane.connect() as db:
        live_event = db.execute(
            "SELECT status,attempts,lease_token FROM event_lane_events WHERE event_id=?",
            (event_id,),
        ).fetchone()
    assert dict(live_event) == {"status": "pending", "attempts": 0, "lease_token": None}

    monkeypatch.setattr(
        "oss_pr_radar.agentscope_events._event_bridge_process_alive", lambda _pid: False
    )
    lane2 = EventLane(tmp_path / "events-valid.db")
    event_id2, claimed2 = _prepare_bound_recovery_retry(
        lane2,
        receipt={
            "turnStatus": "completed",
            "workerPid": 1_000_000_000,
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": "outcome-reconcile:agentscope:retry-bound",
                "publicKey": "agentscope-ai/agentscope#1",
                "state": "no_action",
            },
        },
    )
    valid = lane2.try_reserve_handler_turn_if_idle(
        "agentscope-ai/agentscope#1",
        event_id2,
        "client:new",
        lease_token=str(claimed2["leaseToken"]),
        owner="worker-a",
        recovery_retry=True,
    )
    assert valid == {"status": "conflict", "reason": "turn_conflict"}
    assert lane2.handler_turn(event_id2)["turn_id"] == "turn-old"


def test_reconcile_carries_launch_pid_into_terminal_receipt(tmp_path, monkeypatch):
    worker = _event_worker_module()
    monkeypatch.setattr(
        "oss_pr_radar.agentscope_events._event_bridge_process_alive", lambda _pid: False
    )
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_id = worker._outcome_recovery_event_id("root-for-pid")
    event_key = "agentscope-ai/agentscope#1"
    lane.append(
        {
            "eventId": event_id,
            "eventKey": event_key,
            "kind": "outcome_reconcile",
            "rootEventId": "root-for-pid",
            "eventIdSource": "root-for-pid",
            "payload": {"eventId": "root-for-pid", "publicKey": event_key},
        },
        priority=250,
    )
    claimed = lane.claim(limit=1)[0]
    lane.reserve_handler_turn(event_key, event_id, "client:pid")
    lane.bind_handler_turn(
        event_key,
        event_id,
        "thread-old",
        "turn-old",
        {"turnStarted": True, "workerPid": 4321},
        status="started",
    )
    assert lane.ack(event_id, lease_token=str(claimed["leaseToken"]))
    receipt = worker._event_artifact_path(
        tmp_path,
        worker.EVENT_RECEIPT_DIR,
        event_id,
        attempt=1,
        is_recovery=True,
    )
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(
        json.dumps(
            {
                "turnStatus": "completed",
                "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
            }
        )
    )

    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    stored = json.loads(lane.handler_turn(event_id)["receipt_json"])
    assert stored["workerPid"] == 4321
    retry_claim = lane.claim(limit=1)[0]
    retry = lane.try_reserve_handler_turn_if_idle(
        event_key,
        event_id,
        "client:pid:retry",
        lease_token=str(retry_claim["leaseToken"]),
        recovery_retry=True,
    )
    assert retry["status"] == "reserved"
    assert lane.handler_turn(event_id)["turn_id"] is None


def test_github_identity_ignores_metadata_drift_and_tracks_material_revisions(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    details = {
        "pull": {
            "head": {"sha": "sha-1"},
            "state": "open",
            "draft": False,
            "updated_at": "2026-08-24T00:00:00Z",
            "mergeable_state": "clean",
        },
        "reviews": [
            {
                "id": 1,
                "state": "COMMENTED",
                "submitted_at": "2026-08-24T00:00:00Z",
                "commit_id": "sha-1",
                "body": "review",
            }
        ],
        "comments": [
            {
                "id": 2,
                "created_at": "2026-08-24T00:00:00Z",
                "updated_at": "2026-08-24T00:00:00Z",
                "body": "comment",
                "user": {"login": "reviewer"},
            }
        ],
        "checks": {
            "check_runs": [
                {
                    "id": 3,
                    "name": "ci",
                    "head_sha": "sha-1",
                    "status": "queued",
                    "conclusion": None,
                    "started_at": "2026-08-24T00:00:00Z",
                    "completed_at": None,
                    "app": {"slug": "github-actions", "owner": {"followers": 1}},
                }
            ]
        },
    }
    first = _github_event(2397, "2026-08-24T00:00:00Z") | {
        "eventId": "github:agentscope-ai/agentscope:2397:pr_update:legacy-a",
        "prDetails": details,
    }
    metadata_drift = first | {
        "eventId": "github:agentscope-ai/agentscope:2397:pr_update:legacy-b",
        "prDetails": {
            **details,
            "checks": {
                "check_runs": [
                    {
                        **details["checks"]["check_runs"][0],
                        "app": {
                            "slug": "github-actions",
                            "owner": {"followers": 999},
                            "permissions": {"checks": "write"},
                        },
                    }
                ]
            },
        },
    }
    material_change = first | {
        "eventId": "github:agentscope-ai/agentscope:2397:pr_update:legacy-c",
        "prDetails": {
            **details,
            "checks": {
                "check_runs": [
                    {
                        **details["checks"]["check_runs"][0],
                        "status": "completed",
                        "conclusion": "success",
                    }
                ]
            },
        },
    }
    changed = _github_event(2397, "2026-08-24T00:01:00Z")
    changed["prDetails"] = details
    assert lane.append(first) is True
    assert lane.append(metadata_drift) is False
    assert lane.append(material_change) is True
    assert lane.append(changed) is True
    seen = []
    assert dispatch_once(lane, seen.append, limit=3)["delivered"] == 1
    assert [event["eventId"] for event in seen] == [changed["eventId"]]


def test_plain_issue_has_no_material_suffix_and_stable_legacy_identity():
    event = _github_event(2398, "2026-08-24T00:00:00Z")
    event["eventId"] = _github_event_id(event)
    assert (
        event["eventId"] == "github:agentscope-ai/agentscope:2398:issue_update:2026-08-24T00:00:00Z"
    )
    assert _github_event_identity(event) == (
        "agentscope-ai/agentscope",
        "2398",
        "issue_update",
        "2026-08-24T00:00:00Z",
        "",
    )


def test_active_pull_events_use_canonical_material_projection(tmp_path):
    poller = GitHubIssuePoller(
        tmp_path / "poll.json", transport=lambda _url, _headers: (200, {}, [])
    )
    details = {
        "pull": {
            "head": {
                "sha": "sha-1",
                "ref": "feature",
                "user": {"login": "Oxygen56", "repo": {"stargazers_count": 1}},
            },
            "state": "open",
            "draft": False,
            "updated_at": "2026-08-24T00:00:00Z",
            "mergeable_state": "clean",
        },
        "reviews": [
            {
                "id": 1,
                "state": "COMMENTED",
                "submitted_at": "2026-08-24T00:00:00Z",
                "commit_id": "sha-1",
                "body": "review",
            }
        ],
        "comments": [
            {
                "id": 2,
                "created_at": "2026-08-24T00:00:00Z",
                "updated_at": "2026-08-24T00:00:00Z",
                "body": "comment",
                "user": {"login": "reviewer"},
            }
        ],
        "checks": {
            "check_runs": [
                {
                    "id": 3,
                    "name": "ci",
                    "head_sha": "sha-1",
                    "status": "queued",
                    "conclusion": None,
                    "started_at": "2026-08-24T00:00:00Z",
                    "completed_at": None,
                    "app": {
                        "slug": "github-actions",
                        "owner": {"permissions": {"checks": "write"}, "stargazers_count": 1},
                    },
                }
            ]
        },
    }
    poller._enrich_pull_request = lambda item, _state: item

    def item(value, updated="2026-08-24T00:00:00Z"):
        return {
            "number": 2397,
            "updated_at": updated,
            "title": "implementation",
            "state": "open",
            "user": {"login": "Oxygen56"},
            "pull_request": {"url": "https://example.test/pr"},
            "agentscopeDetails": value,
        }

    baseline = poller._active_pull_events([item(details)], {})[0]["eventId"]
    metadata = copy.deepcopy(details)
    metadata["pull"]["head"]["repo"] = {
        "stargazers_count": 999,
        "owner": {"permissions": {"admin": True}},
    }
    metadata["checks"]["check_runs"][0]["app"]["owner"]["stargazers_count"] = 999
    assert poller._active_pull_events([item(metadata)], {})[0]["eventId"] == baseline
    for key in ("reviews", "comments", "checks"):
        changed = copy.deepcopy(details)
        if key == "checks":
            changed[key]["check_runs"][0].update({"status": "completed", "conclusion": "success"})
        else:
            changed[key][0]["body"] = "changed"
        assert poller._active_pull_events([item(changed)], {})[0]["eventId"] != baseline
    assert poller._active_pull_events([item(details)], {})[0]["eventId"] == baseline
    assert (
        poller._active_pull_events([item(details, "2026-08-24T00:01:00Z")], {})[0]["eventId"]
        != baseline
    )


def test_same_event_is_idempotent_but_new_event_resumes_same_thread(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    first = lane.reserve_handler_turn("agentscope-ai/agentscope#1", "e1", "client:e1")
    again = lane.reserve_handler_turn("agentscope-ai/agentscope#1", "e1", "client:e1")
    assert first["event_id"] == again["event_id"] == "e1"
    lane.bind_handler_turn("agentscope-ai/agentscope#1", "e1", "thread-1", "turn-1", {"ok": True})
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "e2", "client:e2")
    lane.bind_handler_turn("agentscope-ai/agentscope#1", "e2", "thread-1", "turn-2", {"ok": True})
    assert lane.handler_turn("e1")["turn_id"] == "turn-1"
    assert lane.handler_turn("e2")["thread_id"] == "thread-1"


def test_handoff_drain_uses_atomic_claim_file(tmp_path, monkeypatch):
    lane = EventLane(tmp_path / "events.db")
    handoff = tmp_path / "handoff.jsonl"
    original = lane.append

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    import sqlite3

    monkeypatch.setattr(lane, "append", locked)
    assert lane.append_or_handoff({"eventId": "e1"}, handoff_path=handoff) == "handoff"
    monkeypatch.setattr(lane, "append", original)
    assert lane.drain_handoff(handoff) == 1
    assert not handoff.exists()


def test_active_oxygen_pr_details_are_polled_even_when_issue_gate_is_304(tmp_path):
    item = {
        "number": 9,
        "updated_at": "2026-08-22T00:00:00Z",
        "title": "implementation",
        "state": "open",
        "user": {"login": "Oxygen56"},
        "pull_request": {"url": "https://api.github.com/repos/agentscope-ai/agentscope/pulls/9"},
        "labels": [],
    }
    calls = []

    def transport(url, headers):
        calls.append(url)
        if len(calls) == 1:
            return 200, {"ETag": "gate"}, [item]
        if "/issues?" in url and "direction=desc" in url:
            return 304, {"ETag": "gate"}, None
        if url.endswith("/pulls/9"):
            return 200, {}, {"head": {"sha": "sha9"}, "mergeable_state": "clean"}
        if "/check-runs" in url:
            return 200, {}, {"check_runs": [{"name": "ci", "status": "completed"}]}
        return 200, {}, []

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport)
    assert poller.poll().status == "baseline"
    result = poller.poll()
    assert result.status == "ok"
    assert result.events[0]["prDetails"]["checks"]["check_runs"]


def test_production_queue_snapshot_imports_pr_followup_once(tmp_path, monkeypatch):
    worker = _event_worker_module()
    monkeypatch.setattr(
        worker,
        "production_queue_snapshot",
        lambda _root: {
            "prFollowups": [{"taskId": "task-1", "key": "agentscope-ai/agentscope#9"}],
        },
    )
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": (), "status": "not_modified"})(),
    )
    delivered = []
    first = worker.run_once(tmp_path, deliver=delivered.append)
    second = worker.run_once(tmp_path, deliver=delivered.append)
    assert first["queueImported"] == 0
    assert first["drain"]["delivered"] == 0
    assert first["legacyQueueRetired"] == 0
    assert second["queueImported"] == 0
    assert delivered == []


def test_run_once_migrates_legacy_model_failures_before_receipt_reconciliation(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    order = []
    migrate = worker.migrate_unmarked_transient_model_recoveries
    reconcile = worker.reconcile_detached_receipts

    def tracked_migration(*args, **kwargs):
        order.append("migration")
        return migrate(*args, **kwargs)

    def tracked_reconciliation(*args, **kwargs):
        order.append("reconciliation")
        return reconcile(*args, **kwargs)

    monkeypatch.setattr(worker, "migrate_unmarked_transient_model_recoveries", tracked_migration)
    monkeypatch.setattr(worker, "reconcile_detached_receipts", tracked_reconciliation)
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": (), "status": "not_modified"})(),
    )

    worker.run_once(tmp_path, deliver=lambda _event: None)

    assert order[:2] == ["migration", "reconciliation"]


def test_queue_identity_is_stable_and_legacy_rows_retire_once(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    first = {
        "intents": [
            {"intentId": "intent-2413", "key": "agentscope-ai/agentscope#2413", "title": "old"}
        ]
    }
    changed = {
        "intents": [
            {
                "intentId": "intent-2413",
                "key": "agentscope-ai/agentscope#2413",
                "title": "new",
                "status": "CREATING",
            }
        ]
    }
    assert lane.import_queue(first)["imported"] == 1
    assert lane.import_queue(changed)["imported"] == 0
    lane.append(
        {
            "eventId": "queue:legacy-payload-digest",
            "kind": "intents",
            "taskId": "legacy",
            "payload": {"intentId": "legacy", "title": "mutable"},
        }
    )
    assert lane.retire_queue_events(now=10) == 2
    assert lane.retire_queue_events(now=11) == 0
    with lane.connect() as db:
        rows = list(db.execute("SELECT status,payload_json FROM event_lane_events"))
    assert {row["status"] for row in rows} == {"coalesced"}
    assert all(
        json.loads(row["payload_json"])["terminalReason"] == "retired_shared_queue_mirror"
        for row in rows
    )


def test_concurrent_legacy_queue_event_is_coalesced_before_dispatch_ack(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "queue:late",
        "kind": "prFollowups",
        "taskId": "late",
        "payload": {"status": "CREATING"},
    }
    lane.append(event)
    result = dispatch_once(lane, lambda item: worker.bridge_delivery(tmp_path, lane, item), limit=1)
    assert result["delivered"] == 0
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id='queue:late'"
        ).fetchone()
    assert row["status"] == "coalesced"
    assert json.loads(row["payload_json"])["terminalReason"] == "retired_shared_queue_mirror"


def _write_bootstrap_seed(root: Path, boundary: str) -> None:
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "agentscope-public-work.json").write_text(
        json.dumps({"baselineThrough": boundary, "items": []}) + "\n", encoding="utf-8"
    )


def _github_event(number: int, updated: str) -> dict:
    return {
        "eventId": f"github:agentscope-ai/agentscope:{number}:issue_update:{updated}",
        "repo": "agentscope-ai/agentscope",
        "number": number,
        "kind": "issue_update",
        "updatedAt": updated,
        "issue": {
            "number": number,
            "updated_at": updated,
            "state": "open",
            "labels": [{"name": "bug"}],
        },
    }


def _pr_event(number: int, updated: str, check_runs: list[dict]) -> dict:
    event = _github_event(number, updated)
    event.update(
        {
            "kind": "pr_update",
            "eventKey": f"agentscope-ai/agentscope#{number}",
            "prDetails": {
                "pull": {
                    "head": {"sha": "head-1", "ref": "fix", "user": {"login": "Oxygen56"}},
                    "state": "open",
                    "draft": False,
                    "updated_at": updated,
                    "comments": 0,
                    "review_comments": 0,
                },
                "reviews": [],
                "comments": [],
                "checks": {"check_runs": check_runs},
            },
        }
    )
    event["issue"]["pull_request"] = {
        "html_url": f"https://github.com/agentscope-ai/agentscope/pull/{number}"
    }
    event["eventId"] = _github_event_id(event)
    return event


def test_pr_ci_progress_uses_phases_and_keeps_only_latest_unstarted_snapshot(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    queued = [
        {"id": 1, "name": "unit", "head_sha": "head-1", "status": "queued", "conclusion": None},
        {"id": 2, "name": "lint", "head_sha": "head-1", "status": "queued", "conclusion": None},
    ]
    progress = [
        {
            "id": 1,
            "name": "unit",
            "head_sha": "head-1",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "id": 2,
            "name": "lint",
            "head_sha": "head-1",
            "status": "in_progress",
            "conclusion": None,
        },
    ]
    success = [
        {
            "id": 1,
            "name": "unit",
            "head_sha": "head-1",
            "status": "completed",
            "conclusion": "success",
        },
        {
            "id": 2,
            "name": "lint",
            "head_sha": "head-1",
            "status": "completed",
            "conclusion": "success",
        },
    ]
    first = _pr_event(2500, "2026-08-28T13:50:56Z", queued)
    active_progress = _pr_event(2500, "2026-08-28T13:50:56Z", progress)
    final = _pr_event(2500, "2026-08-28T13:50:56Z", success)

    assert first["eventId"] == active_progress["eventId"]
    assert final["eventId"] != first["eventId"]
    assert lane.append(first, priority=200, now=1) is True
    assert lane.append(active_progress, priority=200, now=2) is False
    assert lane.append(final, priority=200, now=3) is True

    with lane.connect() as db:
        rows = db.execute(
            "SELECT status,payload_json FROM event_lane_events ORDER BY created_at"
        ).fetchall()
    assert [row["status"] for row in rows] == ["coalesced", "pending"]
    pending_payload = json.loads(rows[-1]["payload_json"])
    assert pending_payload["prDetails"]["checks"]["check_runs"] == success
    assert pending_payload["wakeGeneration"] == 2
    assert json.loads(rows[0]["payload_json"])["supersededByEventId"] == pending_payload["eventId"]


def test_pr_wake_generation_preserves_phase_reentry(tmp_path):
    active = [{"id": 1, "name": "unit", "status": "in_progress", "conclusion": None}]
    failure = [{"id": 1, "name": "unit", "status": "completed", "conclusion": "failure"}]
    success = [{"id": 1, "name": "unit", "status": "completed", "conclusion": "success"}]
    for name, phases in (
        ("active-failure-active", (active, failure, active)),
        ("success-active-success", (success, active, success)),
    ):
        lane = EventLane(tmp_path / f"{name}.db")
        events = [_pr_event(2500, "2026-08-28T13:50:56Z", checks) for checks in phases]
        assert events[0]["eventId"] == events[2]["eventId"]
        assert [
            lane.append(event, priority=200, now=index) for index, event in enumerate(events, 1)
        ] == [True, True, True]
        with lane.connect() as db:
            rows = db.execute(
                "SELECT status,payload_json FROM event_lane_events ORDER BY rowid"
            ).fetchall()
        payloads = [json.loads(row["payload_json"]) for row in rows]
        assert [row["status"] for row in rows] == ["coalesced", "coalesced", "pending"]
        assert [payload["wakeGeneration"] for payload in payloads] == [1, 2, 3]
        assert payloads[-1]["prDetails"]["checks"]["check_runs"] == phases[-1]


def test_pr_wake_ignores_mergeability_flap_but_keeps_explicit_conflict(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    checks = [{"id": 1, "name": "unit", "status": "in_progress", "conclusion": None}]
    unknown = _pr_event(2500, "2026-08-28T13:50:56Z", checks)
    unknown["prDetails"]["pull"].update(
        {"mergeable_state": "unknown", "mergeable": None, "rebaseable": None}
    )
    unknown["eventId"] = _github_event_id(unknown)
    clean = copy.deepcopy(unknown)
    clean["prDetails"]["pull"].update(
        {"mergeable_state": "clean", "mergeable": True, "rebaseable": True}
    )
    clean["eventId"] = _github_event_id(clean)
    conflict = copy.deepcopy(clean)
    conflict["prDetails"]["pull"]["mergeable_state"] = "dirty"
    conflict["eventId"] = _github_event_id(conflict)

    assert unknown["eventId"] == clean["eventId"]
    assert conflict["eventId"] != clean["eventId"]
    assert lane.append(unknown, priority=200, now=1)
    assert lane.append(clean, priority=200, now=2) is False
    assert lane.append(conflict, priority=200, now=3)


def test_pr_snapshot_coalescing_never_touches_started_turn_or_other_pr(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    active = _pr_event(
        2500,
        "2026-08-28T13:50:56Z",
        [{"id": 1, "name": "unit", "status": "in_progress", "conclusion": None}],
    )
    final = _pr_event(
        2500,
        "2026-08-28T13:50:56Z",
        [{"id": 1, "name": "unit", "status": "completed", "conclusion": "success"}],
    )
    other = _pr_event(
        2501,
        "2026-08-28T13:50:56Z",
        [{"id": 3, "name": "unit", "status": "completed", "conclusion": "success"}],
    )
    assert lane.append(active, priority=200, now=1)
    claimed = lane.claim(limit=1, owner="event-lane", now=1)[0]
    lane.reserve_handler_turn(active["eventKey"], claimed["eventId"], "client:active")
    lane.bind_handler_turn(
        active["eventKey"],
        claimed["eventId"],
        "thread-active",
        "turn-active",
        {"ok": True},
        status="started",
    )
    assert lane.append(final, priority=200, now=2)
    assert lane.append(other, priority=200, now=3)
    assert lane.coalesce_pending_pr_updates(now=4) == 0

    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status FROM event_lane_events ORDER BY created_at"
        ).fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (claimed["eventId"], "leased"),
        (f"{final['eventId']}:g2", "pending"),
        (f"{other['eventId']}:g1", "pending"),
    ]


def test_pr_snapshot_sweep_coalesces_preexisting_legacy_backlog(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    older = _pr_event(
        2500,
        "2026-08-28T13:50:56Z",
        [{"id": 1, "name": "unit", "status": "in_progress", "conclusion": None}],
    )
    newer = _pr_event(
        2500,
        "2026-08-28T13:50:56Z",
        [{"id": 1, "name": "unit", "status": "completed", "conclusion": "success"}],
    )
    older["eventId"] = "github:legacy:older"
    newer["eventId"] = "github:legacy:newer"
    with lane.writer() as db:
        db.execute(
            "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) VALUES(?,?,200,?)",
            (older["eventId"], json.dumps(older, sort_keys=True), 1),
        )
        db.execute(
            "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) VALUES(?,?,200,?)",
            (newer["eventId"], json.dumps(newer, sort_keys=True), 1),
        )

    assert lane.coalesce_pending_pr_updates(now=2) == 1
    with lane.connect() as db:
        rows = db.execute(
            "SELECT status,payload_json FROM event_lane_events ORDER BY rowid"
        ).fetchall()
    assert [row["status"] for row in rows] == ["coalesced", "pending"]
    assert json.loads(rows[0]["payload_json"])["supersededByEventId"] == newer["eventId"]


def test_pr_snapshot_sweep_uses_newer_started_turn_as_authority(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    older = _pr_event(
        2500,
        "2026-08-28T13:50:56Z",
        [{"id": 1, "name": "unit", "status": "in_progress", "conclusion": None}],
    )
    newer = _pr_event(
        2500,
        "2026-08-28T13:50:56Z",
        [{"id": 1, "name": "unit", "status": "completed", "conclusion": "success"}],
    )
    older["eventId"] = "github:legacy:older"
    newer["eventId"] = "github:legacy:newer"
    with lane.writer() as db:
        db.execute(
            "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) VALUES(?,?,100,?)",
            (older["eventId"], json.dumps(older, sort_keys=True), 1),
        )
        db.execute(
            "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) VALUES(?,?,200,?)",
            (newer["eventId"], json.dumps(newer, sort_keys=True), 2),
        )
    claimed = lane.claim(limit=1, owner="event-lane", now=2)[0]
    assert claimed["eventId"] == newer["eventId"]
    lane.reserve_handler_turn(newer["eventKey"], newer["eventId"], "client:newer")
    lane.bind_handler_turn(
        newer["eventKey"],
        newer["eventId"],
        "thread-newer",
        "turn-newer",
        {"ok": True},
        status="started",
    )

    assert lane.coalesce_pending_pr_updates(now=3) == 1
    with lane.connect() as db:
        rows = db.execute("SELECT event_id,status FROM event_lane_events ORDER BY rowid").fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (older["eventId"], "coalesced"),
        (newer["eventId"], "leased"),
    ]


def test_issue_updates_keep_only_latest_unstarted_snapshot(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    older = _github_event(2500, "2026-08-28T13:50:56Z")
    newer = _github_event(2500, "2026-08-28T13:51:56Z")

    assert lane.append(older, priority=10, now=1)
    assert lane.append(newer, priority=10, now=2)

    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status,payload_json FROM event_lane_events ORDER BY rowid"
        ).fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (older["eventId"], "coalesced"),
        (newer["eventId"], "pending"),
    ]
    superseded = json.loads(rows[0]["payload_json"])
    assert superseded["terminalReason"] == "superseded_by_newer_issue_snapshot"
    assert superseded["supersededByEventId"] == newer["eventId"]


def test_issue_updates_keep_newer_effective_snapshot_when_older_arrives_late(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    newer = _github_event(2500, "2026-08-28T13:51:56Z")
    older = _github_event(2500, "2026-08-28T13:50:56Z")

    assert lane.append(newer, priority=10, now=1)
    assert lane.append(older, priority=10, now=2)

    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status,payload_json FROM event_lane_events ORDER BY rowid"
        ).fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (newer["eventId"], "pending"),
        (older["eventId"], "coalesced"),
    ]
    superseded = json.loads(rows[1]["payload_json"])
    assert superseded["supersededByEventId"] == newer["eventId"]

    delivered = []
    assert dispatch_once(lane, delivered.append, limit=3)["delivered"] == 1
    assert [event["eventId"] for event in delivered] == [newer["eventId"]]


def test_issue_update_handoff_cannot_replace_newer_effective_snapshot(tmp_path, monkeypatch):
    import sqlite3

    lane = EventLane(tmp_path / "events.db")
    handoff = tmp_path / "handoff.jsonl"
    newer = _github_event(2500, "2026-08-28T13:51:56Z")
    older = _github_event(2500, "2026-08-28T13:50:56Z")
    assert lane.append(newer, priority=10, now=1)
    original = lane.append

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(lane, "append", locked)
    assert lane.append_or_handoff(older, priority=10, handoff_path=handoff) == "handoff"
    monkeypatch.setattr(lane, "append", original)
    assert lane.drain_handoff(handoff) == 1

    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status,payload_json FROM event_lane_events ORDER BY rowid"
        ).fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (newer["eventId"], "pending"),
        (older["eventId"], "coalesced"),
    ]
    assert json.loads(rows[1]["payload_json"])["supersededByEventId"] == newer["eventId"]


def test_existing_issue_replay_does_not_force_older_snapshot_as_authority(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    older = _github_event(2500, "2026-08-28T13:50:56Z")
    newer = _github_event(2500, "2026-08-28T13:51:56Z")
    for event in (older, newer):
        event["eventKey"] = f"{event['repo']}#{event['number']}"
    with lane.writer() as db:
        for event, created_at in ((older, 1), (newer, 2)):
            db.execute(
                "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) "
                "VALUES(?,?,10,?)",
                (event["eventId"], json.dumps(event, sort_keys=True), created_at),
            )

    assert lane.append(older, priority=10, now=3) is False

    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status,payload_json FROM event_lane_events ORDER BY rowid"
        ).fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (older["eventId"], "coalesced"),
        (newer["eventId"], "pending"),
    ]
    assert json.loads(rows[0]["payload_json"])["supersededByEventId"] == newer["eventId"]


def test_issue_snapshot_sweep_preserves_started_turn_and_other_issue(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    older = _github_event(2500, "2026-08-28T13:50:56Z")
    newer = _github_event(2500, "2026-08-28T13:51:56Z")
    other = _github_event(2501, "2026-08-28T13:51:56Z")
    for event in (older, newer, other):
        event["eventKey"] = f"{event['repo']}#{event['number']}"
    with lane.writer() as db:
        snapshots = ((older, 10, 1), (newer, 20, 2), (other, 10, 3))
        for event, priority, created_at in snapshots:
            db.execute(
                "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) "
                "VALUES(?,?,?,?)",
                (event["eventId"], json.dumps(event, sort_keys=True), priority, created_at),
            )
    claimed = lane.claim(limit=1, owner="event-lane", now=3)[0]
    assert claimed["eventId"] == newer["eventId"]
    lane.reserve_handler_turn(newer["eventKey"], newer["eventId"], "client:newer")
    lane.bind_handler_turn(
        newer["eventKey"],
        newer["eventId"],
        "thread-newer",
        "turn-newer",
        {"ok": True},
        status="started",
    )

    assert lane.coalesce_pending_issue_updates(now=4) == 1
    with lane.connect() as db:
        rows = db.execute("SELECT event_id,status FROM event_lane_events ORDER BY rowid").fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (older["eventId"], "coalesced"),
        (newer["eventId"], "leased"),
        (other["eventId"], "pending"),
    ]


def test_worker_sweeps_preexisting_pending_issue_snapshots(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _write_bootstrap_seed(tmp_path, "2026-08-27T00:00:00Z")
    older = _github_event(2500, "2026-08-28T13:50:56Z")
    newer = _github_event(2500, "2026-08-28T13:51:56Z")
    for event in (older, newer):
        event["eventKey"] = f"{event['repo']}#{event['number']}"
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    with lane.writer() as db:
        for event, created_at in ((older, 1), (newer, 2)):
            db.execute(
                "INSERT INTO event_lane_events(event_id,payload_json,priority,created_at) "
                "VALUES(?,?,10,?)",
                (event["eventId"], json.dumps(event, sort_keys=True), created_at),
            )
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self, **_kwargs: type("Poll", (), {"events": (), "status": "ok"})(),
    )
    delivered = []

    result = worker.run_once(
        tmp_path,
        deliver=delivered.append,
        now=datetime(2026, 8, 28, 14, tzinfo=UTC),
    )

    assert result["issueSnapshotsCoalesced"] == 1
    assert [event["eventId"] for event in delivered] == [newer["eventId"]]
    with lane.connect() as db:
        rows = db.execute("SELECT event_id,status FROM event_lane_events ORDER BY rowid").fetchall()
    assert [(row["event_id"], row["status"]) for row in rows] == [
        (older["eventId"], "coalesced"),
        (newer["eventId"], "delivered"),
    ]


def test_aged_issue_outranks_pr_but_not_recovery(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    issue = _github_event(2502, "2026-08-28T13:00:00Z")
    pr = _pr_event(
        2500,
        "2026-08-28T13:05:00Z",
        [{"id": 1, "name": "unit", "status": "in_progress", "conclusion": None}],
    )
    recovery = {"eventId": "outcome-reconcile:root", "kind": "outcome_reconcile"}
    assert lane.append(issue, priority=10, now=0)
    assert lane.append(pr, priority=200, now=100)
    assert lane.append(recovery, priority=250, now=200)

    first = lane.claim(limit=1, owner="event-lane", now=301)[0]
    assert first["eventId"] == recovery["eventId"]
    assert lane.ack(
        first["eventId"],
        owner="event-lane",
        lease_token=first["leaseToken"],
    )
    second = lane.claim(limit=1, owner="event-lane", now=301)[0]
    assert second["eventId"] == issue["eventId"]


def test_recovery_strictly_outranks_watch_reply_at_same_priority(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    watch = {"eventId": "watch", "kind": "watch_reply", "eventKey": "repo#1"}
    recovery = {
        "eventId": "outcome-reconcile:root",
        "kind": "outcome_reconcile",
        "eventKey": "repo#2",
    }
    assert lane.append(watch, priority=250, now=0)
    assert lane.append(recovery, priority=250, now=1)
    claimed = lane.claim(limit=1, owner="event-lane", now=1)[0]
    assert claimed["eventId"] == recovery["eventId"]


def test_bootstrap_suppresses_stale_catchup_without_wake_or_pending(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:49:07Z"
    _write_bootstrap_seed(tmp_path, boundary)
    stale = _github_event(2364, "2026-08-22T17:08:35Z")
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": (stale,), "status": "ok"})(),
    )
    delivered = []
    result = worker.run_once(tmp_path, deliver=delivered.append)
    assert result["eventsInserted"] == 0
    assert result["codexWake"] is False
    assert result["drain"]["pending"] == 0
    assert delivered == []
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT status FROM event_lane_events WHERE event_id=?", (stale["eventId"],)
            ).fetchone()[0]
            == "baseline"
        )


def test_bootstrap_terminalizes_existing_leased_stale_event(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:49:07Z"
    _write_bootstrap_seed(tmp_path, boundary)
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    stale = _github_event(2364, "2026-08-22T17:08:35Z")
    lane.append(stale, now=1)
    assert lane.claim(owner="old-listener", now=1)
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": (), "status": "not_modified"})(),
    )
    result = worker.run_once(
        tmp_path,
        deliver=lambda _event: (_ for _ in ()).throw(AssertionError("stale event delivered")),
    )
    assert result["bootstrapApplied"] is True
    assert result["bootstrapTerminalized"] == 1
    assert result["drain"]["pending"] == 0
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT status FROM event_lane_events WHERE event_id=?", (stale["eventId"],)
            ).fetchone()[0]
            == "baseline"
        )


def test_post_bootstrap_event_dispatches_once(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:49:07Z"
    _write_bootstrap_seed(tmp_path, boundary)
    fresh = _github_event(2400, "2026-08-23T12:49:08Z")
    polls = iter(
        [
            type("Poll", (), {"events": (fresh,), "status": "ok"})(),
            type("Poll", (), {"events": (), "status": "not_modified"})(),
        ]
    )
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: next(polls))
    delivered = []
    first = worker.run_once(tmp_path, deliver=delivered.append)
    second = worker.run_once(tmp_path, deliver=delivered.append)
    assert first["eventsInserted"] == 1 and first["drain"]["delivered"] == 1
    assert second["eventsInserted"] == 0 and second["codexWake"] is False
    assert [event["eventId"] for event in delivered] == [fresh["eventId"]]


def test_material_time_after_boundary_is_dispatchable_even_with_old_issue_updated_at(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:00:00Z"
    _write_bootstrap_seed(tmp_path, boundary)
    events = []
    for number, details in (
        (2501, {"reviews": [{"id": 1, "submitted_at": "2026-08-23T12:01:00Z"}]}),
        (2502, {"comments": [{"id": 2, "updated_at": "2026-08-23T12:02:00Z"}]}),
        (
            2503,
            {
                "checks": {
                    "check_runs": [
                        {
                            "id": 3,
                            "started_at": "2026-08-23T12:03:00Z",
                            "completed_at": "2026-08-23T12:04:00Z",
                        }
                    ]
                }
            },
        ),
    ):
        event = _github_event(number, "2026-08-23T11:00:00Z")
        event["prDetails"] = details
        events.append(event)
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": tuple(events), "status": "ok"})(),
    )
    delivered = []
    result = worker.run_once(tmp_path, deliver=delivered.append)
    assert result["eventsInserted"] == 3
    assert result["drain"]["delivered"] == 3
    assert result["drain"]["pending"] == 0
    assert [event["eventId"] for event in delivered] == [event["eventId"] for event in events]


def test_production_worker_claims_only_one_central_turn_per_cycle(tmp_path, monkeypatch):
    worker = _event_worker_module()
    events = tuple(_github_event(number, f"2026-08-23T12:0{number}:00Z") for number in (1, 2, 3))
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": events, "status": "ok"})(),
    )
    delivered = []
    monkeypatch.setattr(
        worker,
        "bridge_delivery",
        lambda _root, _lane, event: delivered.append(event["eventId"]),
    )

    result = worker.run_once(tmp_path)

    assert result["eventsInserted"] == 3
    assert result["drain"] == {"claimed": 1, "delivered": 1, "pending": 2}
    assert delivered == [events[0]["eventId"]]


def test_busy_central_task_does_not_spend_pending_attempts_across_cycles(tmp_path, monkeypatch):
    worker = _event_worker_module()
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": (), "status": "not_modified"})(),
    )
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    lane.append(
        {
            "eventId": "active-event",
            "eventKey": "agentscope-ai/agentscope#1",
            "kind": "issue_update",
        }
    )
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "active-event", "client:active")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        "active-event",
        CENTRAL_THREAD,
        "turn-active",
        {"turnStarted": True, "workerPid": os.getpid()},
        status="started",
    )
    with lane.writer() as db:
        db.execute("UPDATE event_lane_events SET status='delivered' WHERE event_id='active-event'")
    lane.append(
        {
            "eventId": "waiting-event",
            "eventKey": "agentscope-ai/agentscope#2",
            "kind": "issue_update",
        }
    )
    monkeypatch.setattr(
        worker,
        "bridge_delivery",
        lambda *_args: (_ for _ in ()).throw(AssertionError("busy task dispatched")),
    )

    results = [worker.run_once(tmp_path) for _ in range(4)]

    assert all(result["centralTaskBusy"] is True for result in results)
    assert all(result["drain"]["claimed"] == 0 for result in results)
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id='waiting-event'"
        ).fetchone()
    assert row["status"] == "pending"
    assert row["attempts"] == 0
    assert lane.handler_turn("waiting-event") is None
    assert lane.expire_claims() == 0
    assert lane.active_handler_thread(CENTRAL_THREAD) is not None


def test_material_times_at_or_before_boundary_are_baseline(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:00:00Z"
    _write_bootstrap_seed(tmp_path, boundary)
    stale = _github_event(2504, "2026-08-23T11:00:00Z")
    stale["prDetails"] = {
        "checks": {
            "check_runs": [
                {
                    "id": 4,
                    "started_at": "2026-08-23T11:30:00Z",
                    "completed_at": "2026-08-23T11:59:59Z",
                }
            ]
        }
    }
    monkeypatch.setattr(
        worker.GitHubIssuePoller,
        "poll",
        lambda _self: type("Poll", (), {"events": (stale,), "status": "ok"})(),
    )
    delivered = []
    result = worker.run_once(tmp_path, deliver=delivered.append)
    assert result["eventsInserted"] == 0
    assert result["codexWake"] is False
    assert result["drain"]["pending"] == 0
    assert delivered == []


def test_unmapped_event_uses_explicit_independent_release_bridge(tmp_path, monkeypatch):
    worker = _event_worker_module()
    calls = []

    def fake_bridge(root, operation, **kwargs):
        calls.append((root, operation, kwargs))
        return {
            "ok": True,
            "threadId": CENTRAL_THREAD,
            "turnId": "turn-new",
            "turnStarted": True,
        }

    monkeypatch.setattr(worker, "run_bridge", fake_bridge)
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "github:agentscope-ai/agentscope:10:issue_update:now",
        "repo": "agentscope-ai/agentscope",
        "number": 10,
        "issue": {"html_url": "https://github.com/agentscope-ai/agentscope/issues/10"},
    }
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane.append(event)
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(tmp_path, lane, claimed)
    assert calls[0][1] == "agentscope-event-create"
    assert calls[0][2]["inactive_release"] is True
    assert calls[0][2]["code_root"] == worker.ROOT
    extra = calls[0][2]["extra_args"]
    assert extra[extra.index("--model") + 1] == "gpt-6-astra"
    assert extra[extra.index("--thread-id") + 1] == CENTRAL_THREAD
    assert lane.handler_thread("agentscope-ai/agentscope#10")["thread_id"] == CENTRAL_THREAD
    assert all(operation != "drain-once" for _, operation, _ in calls)


def test_remote_turn_id_is_bound_and_acked_without_duplicate_retry(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda *_args, **_kwargs: {
            "ok": False,
            "error": (
                "operational authorization required: "
                "operational authorization release binding mismatch"
            ),
            "turnStarted": False,
            "threadId": CENTRAL_THREAD,
            "turnId": "turn-1",
        },
    )
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "central-mismatch",
        "repo": "agentscope-ai/agentscope",
        "number": 11,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/11",
        },
    }
    lane.append(event)
    result = dispatch_once(
        lane,
        lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
        limit=1,
    )
    assert result == {"claimed": 1, "delivered": 1, "pending": 0}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?",
            ("central-mismatch",),
        ).fetchone()
    assert dict(row) == {"status": "delivered", "attempts": 1}
    turn = lane.handler_turn("central-mismatch")
    assert turn["status"] == "started"
    assert turn["thread_id"] == CENTRAL_THREAD
    assert turn["turn_id"] == "turn-1"


def test_wrong_central_thread_with_turn_id_remains_quarantined(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda *_args, **_kwargs: {
            "ok": False,
            "error": (
                "operational authorization required: "
                "operational authorization release binding mismatch"
            ),
            "turnStarted": False,
            "threadId": "wrong-central-thread",
            "turnId": "wrong-thread-turn",
        },
    )
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "central-mismatch-with-turn",
        "repo": "agentscope-ai/agentscope",
        "number": 12,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/12",
        },
    }
    lane.append(event)

    result = dispatch_once(
        lane,
        lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
        limit=1,
    )

    assert result == {"claimed": 1, "delivered": 0, "pending": 0}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()
    assert row["status"] == "needs_reconcile"
    assert row["attempts"] == 1
    assert "central_task_thread_receipt_mismatch" in row["payload_json"]
    turn = lane.handler_turn(event["eventId"])
    assert turn["status"] == "needs_reconcile"
    assert turn["turn_id"] is None
    assert lane.handler_thread("agentscope-ai/agentscope#12") is None


def test_stale_handler_turn_is_terminalized_and_releases_central_slot(tmp_path):
    central = CENTRAL_THREAD
    lane = EventLane(tmp_path / "events.db", turn_timeout_seconds=10)
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "stale-event", "client:stale")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1", "stale-event", central, "turn-stale", {}, status="started"
    )
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id='stale-event'")
    assert lane.expire_handler_turns(now=11) == 1
    assert lane.active_handler_thread(central) is None
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,receipt_json FROM event_lane_turns WHERE event_id='stale-event'"
        ).fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["receipt_json"])["terminalReason"] == "handler_turn_timeout"


def test_stale_prestart_reservation_returns_event_to_pending(tmp_path):
    lane = EventLane(tmp_path / "events.db", turn_timeout_seconds=10)
    event = {
        "eventId": "reserved-event",
        "repo": "agentscope-ai/agentscope",
        "number": 1,
    }
    lane.append(event)
    lane.claim(now=0)
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#1",
        event["eventId"],
        "client:reserved",
    )
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id='reserved-event'")
    assert lane.expire_handler_turns(now=11) == 1
    with lane.connect() as db:
        event_row = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id='reserved-event'"
        ).fetchone()
        turn_row = db.execute(
            "SELECT status,receipt_json FROM event_lane_turns WHERE event_id='reserved-event'"
        ).fetchone()
    assert event_row["status"] == "pending"
    assert turn_row["status"] == "needs_reconcile"
    assert (
        json.loads(turn_row["receipt_json"])["terminalReason"]
        == "handler_reservation_timeout_retry"
    )


def test_active_long_bridge_turn_is_not_reclaimed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "oss_pr_radar.agentscope_events._event_bridge_process_alive",
        lambda pid: int(pid) == os.getpid(),
    )
    lane = EventLane(tmp_path / "events.db", turn_timeout_seconds=10)
    lane.reserve_handler_turn("agentscope-ai/agentscope#2", "long-event", "client:long")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#2",
        "long-event",
        CENTRAL_THREAD,
        "turn-long",
        {"turnStarted": True, "workerPid": os.getpid()},
        status="started",
    )
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id='long-event'")
    assert lane.expire_handler_turns(now=11) == 0
    assert lane.active_handler_thread(CENTRAL_THREAD)["event_id"] == "long-event"


def test_reused_pid_from_unrelated_process_is_not_trusted(monkeypatch):
    monkeypatch.setattr("oss_pr_radar.agentscope_events.os.kill", lambda *_args: None)

    class Result:
        returncode = 0
        stdout = "python -m pytest tests/test_agentscope_events.py"

    monkeypatch.setattr(
        "oss_pr_radar.agentscope_events.subprocess.run",
        lambda *_args, **_kwargs: Result(),
    )
    assert _event_bridge_process_alive(os.getpid()) is False


def test_dead_started_bridge_turn_is_reclaimed(tmp_path):
    lane = EventLane(tmp_path / "events.db", turn_timeout_seconds=10)
    lane.reserve_handler_turn("agentscope-ai/agentscope#3", "dead-event", "client:dead")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#3",
        "dead-event",
        CENTRAL_THREAD,
        "turn-dead",
        {"turnStarted": True, "workerPid": 1_000_000_000},
        status="started",
    )
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id='dead-event'")
    assert lane.expire_handler_turns(now=11) == 1
    assert lane.active_handler_thread(CENTRAL_THREAD) is None


def test_started_bridge_without_pid_is_reclaimed(tmp_path):
    lane = EventLane(tmp_path / "events.db", turn_timeout_seconds=10)
    lane.reserve_handler_turn("agentscope-ai/agentscope#4", "pidless-event", "client:pidless")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#4",
        "pidless-event",
        CENTRAL_THREAD,
        "turn-pidless",
        {"turnStarted": True},
        status="started",
    )
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id='pidless-event'")
    assert lane.expire_handler_turns(now=11) == 1
    assert lane.active_handler_thread(CENTRAL_THREAD) is None


def test_busy_central_wakeup_remains_pending_until_turn_is_free(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane = EventLane(tmp_path / "events.db")
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "active-event", "client:active")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        "active-event",
        CENTRAL_THREAD,
        "turn-active",
        {},
        status="started",
    )
    event = {
        "eventId": "queued-behind-central",
        "repo": "agentscope-ai/agentscope",
        "number": 2,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/2",
        },
    }
    lane.append(event)
    for _cycle in range(4):
        result = dispatch_once(
            lane,
            lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
            limit=1,
        )
        assert result == {"claimed": 1, "delivered": 0, "pending": 1}
        with lane.connect() as db:
            row = db.execute(
                "SELECT status,attempts FROM event_lane_events WHERE event_id=?",
                (event["eventId"],),
            ).fetchone()
        assert dict(row) == {"status": "pending", "attempts": 0}
        assert lane.handler_turn(event["eventId"]) is None
        assert lane.expire_claims() == 0
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        "active-event",
        CENTRAL_THREAD,
        "turn-active",
        {},
        status="needs_reconcile",
    )
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda *_args, **_kwargs: {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-next"},
    )
    result = dispatch_once(
        lane, lambda item: worker.issue_handler_delivery(tmp_path, lane, item), limit=1
    )
    assert result["delivered"] == 1


def test_same_key_busy_race_refunds_four_claims_without_reconcile(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane = EventLane(tmp_path / "events.db")
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "active", "client:active")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        "active",
        CENTRAL_THREAD,
        "turn-active",
        {},
        status="started",
    )
    event = {
        "eventId": "same-key-review",
        "repo": "agentscope-ai/agentscope",
        "number": 1,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/1",
        },
    }
    lane.append(event)

    for _cycle in range(4):
        claimed = lane.claim(limit=1)[0]
        worker.issue_handler_delivery(tmp_path, lane, claimed)
        with lane.connect() as db:
            row = db.execute(
                "SELECT status,attempts FROM event_lane_events WHERE event_id=?",
                (event["eventId"],),
            ).fetchone()
        assert dict(row) == {"status": "pending", "attempts": 0}
        assert lane.handler_turn(event["eventId"]) is None


def test_busy_refund_wrong_token_fails_closed(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane = EventLane(tmp_path / "events.db")
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", "active", "client:active")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        "active",
        CENTRAL_THREAD,
        "turn-active",
        {},
        status="started",
    )
    event = {
        "eventId": "busy-stale-token",
        "repo": "agentscope-ai/agentscope",
        "number": 2,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/2",
        },
    }
    lane.append(event)
    claimed = lane.claim(limit=1)[0]
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET lease_token='replacement-token' WHERE event_id=?",
            (event["eventId"],),
        )

    with pytest.raises(RuntimeError, match="handler_reservation_lease_mismatch"):
        worker.issue_handler_delivery(tmp_path, lane, claimed)

    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,lease_token FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()
    assert dict(row) == {
        "status": "leased",
        "attempts": 1,
        "lease_token": "replacement-token",
    }
    assert lane.handler_turn(event["eventId"]) is None


def test_retryable_start_failure_releases_reservation_and_retries(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    event = {
        "eventId": "retryable-start",
        "repo": "agentscope-ai/agentscope",
        "number": 5,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/5",
        },
    }
    lane = EventLane(tmp_path / "events.db")
    lane.append(event)
    results = iter(
        [
            {"ok": False, "retryable": True, "turnStarted": False},
            {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-retry"},
        ]
    )
    monkeypatch.setattr(worker, "run_bridge", lambda *_args, **_kwargs: next(results))

    first = dispatch_once(
        lane,
        lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
        limit=1,
    )
    assert first["claimed"] == 1
    assert first["delivered"] == 0
    assert first["pending"] == 1
    assert lane.handler_turn(event["eventId"])["status"] == "needs_reconcile"
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT attempts FROM event_lane_events WHERE event_id=?",
                (event["eventId"],),
            ).fetchone()[0]
            == 1
        )

    second = dispatch_once(
        lane,
        lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
        limit=1,
    )
    assert second["delivered"] == 1
    turn = lane.handler_turn(event["eventId"])
    assert turn["status"] == "started"
    assert turn["thread_id"] == CENTRAL_THREAD


def test_transient_model_failover_is_bounded_outside_the_lease_attempt_budget(tmp_path):
    lane = EventLane(tmp_path / "events.db", max_attempts=3)
    event = {
        "eventId": "model-fallback",
        "eventKey": "agentscope-ai/agentscope#5",
        "repo": "agentscope-ai/agentscope",
        "number": 5,
        "kind": "issue_update",
    }
    lane.append(event)
    models = ("gpt-6-astra", "gpt-5.6-terra", "gpt-5.6-luna")
    for index, model in enumerate(models):
        claimed = lane.claim(limit=1)[0]
        assert claimed["attempts"] == 1
        outcome = lane.record_transient_model_failure(
            event["eventId"],
            model=model,
            candidates=models,
            error={"code": "serverOverloaded"},
            lease_token=claimed["leaseToken"],
            retry_not_before=0,
        )
        assert outcome == ("exhausted" if index == len(models) - 1 else "retry")
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert (row["status"], row["attempts"]) == ("needs_reconcile", 0)
    assert payload["terminalReason"] == "model_capacity_retries_exhausted"
    assert [item["model"] for item in payload["modelFallback"]["history"]] == list(models)
    assert lane.claim(limit=1) == []


def test_model_fallback_keeps_prior_non_model_attempts_and_can_try_all_models(tmp_path):
    lane = EventLane(tmp_path / "events.db", max_attempts=3)
    event = {
        "eventId": "model-fallback-after-start-failures",
        "eventKey": "agentscope-ai/agentscope#6",
        "repo": "agentscope-ai/agentscope",
        "number": 6,
        "kind": "issue_update",
    }
    lane.append(event)
    for expected_attempt in (1, 2):
        claimed = lane.claim(limit=1)[0]
        assert claimed["attempts"] == expected_attempt
        assert lane.defer_event(event["eventId"], lease_token=claimed["leaseToken"])

    models = ("gpt-6-astra", "gpt-5.6-terra", "gpt-5.6-luna")
    for index, model in enumerate(models):
        claimed = lane.claim(limit=1)[0]
        assert claimed["attempts"] == 3
        state = lane.record_transient_model_failure(
            event["eventId"],
            model=model,
            candidates=models,
            error={"code": "serverOverloaded"},
            lease_token=claimed["leaseToken"],
            retry_not_before=0,
        )
        assert state == ("exhausted" if index == len(models) - 1 else "retry")

    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert (row["status"], row["attempts"]) == ("needs_reconcile", 2)
    assert [item["model"] for item in payload["modelFallback"]["history"]] == list(models)
    assert lane.claim(limit=1) == []


def test_transient_model_classifier_accepts_server_overloaded_code():
    worker = _event_worker_module()
    assert worker.EVENT_MODEL_CANDIDATES == (
        "gpt-6-astra",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    )
    assert worker._transient_model_error({"code": "serverOverloaded"})
    assert worker._transient_model_error("stream disconnected before completion")
    assert worker._transient_model_error(
        {
            "codexErrorInfo": "usageLimitExceeded",
            "message": "You've hit your usage limit. Try again later.",
        }
    )


def test_operational_authorization_gap_refunds_attempt_without_reconcile(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    event = {
        "eventId": "authorization-gap",
        "repo": "agentscope-ai/agentscope",
        "number": 6,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/6",
        },
    }
    lane = EventLane(tmp_path / "events.db")
    lane.append(event)
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            _authorization_bridge_error(
                "agentscope-event-create",
                "operational authorization has not been activated",
            )
        ),
    )

    for _cycle in range(4):
        result = dispatch_once(
            lane,
            lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
            limit=1,
        )
        assert result == {"claimed": 1, "delivered": 0, "pending": 1}
        with lane.connect() as db:
            row = db.execute(
                "SELECT status,attempts FROM event_lane_events WHERE event_id=?",
                (event["eventId"],),
            ).fetchone()
        assert dict(row) == {"status": "pending", "attempts": 0}
        assert lane.handler_turn(event["eventId"]) is None

    assert lane.expire_claims() == 0
    recovery = worker._enqueue_unresolved_outcome_recoveries(lane)
    assert recovery["inserted"] == 0
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM event_lane_events WHERE event_id LIKE 'outcome-reconcile:%'"
            ).fetchone()[0]
            == 0
        )


def test_authorization_gap_refund_rejection_preserves_lease_and_reservation(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    event = {
        "eventId": "authorization-gap-stale-token",
        "repo": "agentscope-ai/agentscope",
        "number": 8,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/8",
        },
    }
    lane = EventLane(tmp_path / "events.db")
    lane.append(event)
    claimed = lane.claim(limit=1)[0]

    def stale_lease_then_fail(*_args, **_kwargs):
        with lane.writer() as db:
            db.execute(
                "UPDATE event_lane_events SET lease_token='replacement-token' WHERE event_id=?",
                (event["eventId"],),
            )
        raise _authorization_bridge_error(
            "agentscope-event-create",
            "operational authorization release binding mismatch",
        )

    monkeypatch.setattr(worker, "run_bridge", stale_lease_then_fail)

    with pytest.raises(RuntimeError, match="agentscope-event-create"):
        worker.issue_handler_delivery(tmp_path, lane, claimed)

    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,lease_token FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()
    assert dict(row) == {
        "status": "leased",
        "attempts": 1,
        "lease_token": "replacement-token",
    }
    assert lane.handler_turn(event["eventId"])["status"] == "reserved"


def _active_authorization() -> dict[str, str]:
    return {
        "state": "ACTIVE",
        "releaseId": "release-4-workers",
        "releaseHead": "a" * 40,
        "releaseManifestSha256": "b" * 64,
        "ledgerTarget": "ledger-releases/ledger.sqlite3",
    }


def _exhaust_with_worker_binding_error(worker, lane: EventLane, event_id: str, key: str) -> None:
    lane.reserve_handler_turn(key, event_id, f"client:{event_id}")
    error = _authorization_bridge_error(
        "agentscope-event-create",
        "operational authorization worker binding is invalid",
    )
    assert lane.release_handler_reservation(
        event_id,
        {"error": f"RuntimeError:{error}\n"},
        reason="handler_start_exception",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=? WHERE event_id=?",
            (lane.max_attempts, event_id),
        )


def _exhaust_with_desktop_writer_collision(
    worker, lane: EventLane, event_id: str, key: str
) -> None:
    lane.reserve_handler_turn(key, event_id, f"client:{event_id}")
    assert lane.release_handler_reservation(
        event_id,
        {
            "error": "RuntimeError:DESKTOP_ACTIVE_WRITER:thread central already has an active writer",
            "eventId": event_id,
            "eventKey": key,
            "model": "gpt-6-astra",
            "ok": False,
            "retryable": True,
            "terminalReason": "handler_start_retryable",
            "turnId": None,
            "turnStarted": False,
            "workerPid": 123,
        },
        reason="handler_start_retryable",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=? WHERE event_id=?",
            (lane.max_attempts, event_id),
        )


def test_worker_binding_auth_gap_repair_requeues_root_and_coalesces_recovery(tmp_path, monkeypatch):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#42"
    root_id = "github:agentscope-ai/agentscope:42:issue_update:auth-gap"
    recovery_id = worker._outcome_recovery_event_id(root_id)
    root = {
        "eventId": root_id,
        "eventKey": key,
        "repo": "agentscope-ai/agentscope",
        "number": 42,
        "kind": "issue_update",
        "terminalReason": "lease_attempts_exhausted",
    }
    recovery = {
        "eventId": recovery_id,
        "eventKey": key,
        "kind": "outcome_reconcile",
        "rootEventId": root_id,
        "eventIdSource": root_id,
        "payload": {"eventId": root_id, "rootEventId": root_id, "publicKey": key},
    }
    assert lane.append(root)
    assert lane.append(recovery, priority=250)
    _exhaust_with_worker_binding_error(worker, lane, root_id, key)
    _exhaust_with_worker_binding_error(worker, lane, recovery_id, key)
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )

    first = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)
    second = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)

    assert first == {"status": "applied", "requeued": 1, "coalesced": 1}
    assert second == {"status": "applied", "requeued": 0, "coalesced": 0}
    with lane.connect() as db:
        root_row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (root_id,),
        ).fetchone()
        recovery_row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
        recovery_turn = db.execute(
            "SELECT status,thread_id,turn_id FROM event_lane_turns WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    assert root_row["status"] == "pending" and root_row["attempts"] == 0
    assert lane.handler_turn(root_id) is None
    assert json.loads(root_row["payload_json"])["authorizationGapRepair"]["state"] == "requeued"
    assert recovery_row["status"] == "coalesced" and recovery_row["attempts"] == 3
    assert dict(recovery_turn) == {"status": "superseded", "thread_id": "", "turn_id": None}
    assert (
        json.loads(recovery_row["payload_json"])["authorizationGapRepair"]["state"] == "superseded"
    )
    assert worker._enqueue_unresolved_outcome_recoveries(lane)["inserted"] == 0

    assert worker._revive_superseded_auth_gap_recovery(lane, recovery) is True
    assert worker._revive_superseded_auth_gap_recovery(lane, recovery) is False
    with lane.connect() as db:
        revived = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
    assert dict(revived) == {"status": "pending", "attempts": 0}
    assert lane.handler_turn(recovery_id) is None


def test_prestart_desktop_writer_collision_requeues_only_proved_root_and_coalesces_recovery(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#2044"
    root_id = "github:agentscope-ai/agentscope:2044:issue_update:collision"
    recovery_id = worker._outcome_recovery_event_id(root_id)
    assert lane.append({"eventId": root_id, "eventKey": key, "kind": "issue_update"})
    assert lane.append(
        {
            "eventId": recovery_id,
            "eventKey": key,
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
            "payload": {"eventId": root_id, "rootEventId": root_id, "publicKey": key},
        },
        priority=250,
    )
    _exhaust_with_desktop_writer_collision(worker, lane, root_id, key)
    _exhaust_with_desktop_writer_collision(worker, lane, recovery_id, key)
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )

    assert worker._repair_exhausted_worker_binding_failures(tmp_path, lane) == {
        "status": "applied",
        "requeued": 1,
        "coalesced": 1,
    }
    with lane.connect() as db:
        root_row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (root_id,)
        ).fetchone()
        recovery_row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
    assert dict(root_row) == {"status": "pending", "attempts": 0}
    assert dict(recovery_row) == {"status": "coalesced", "attempts": 3}


def test_prestart_desktop_writer_collision_repair_rejects_mismatched_event_binding(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#2044"
    event_id = "collision-with-mismatched-receipt"
    assert lane.append({"eventId": event_id, "eventKey": key, "kind": "issue_update"})
    _exhaust_with_desktop_writer_collision(worker, lane, event_id, key)
    with lane.writer() as db:
        row = db.execute(
            "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (event_id,)
        ).fetchone()
        receipt = json.loads(row["receipt_json"])
        receipt["eventId"] = "different-event"
        db.execute(
            "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
            (json.dumps(receipt, sort_keys=True), event_id),
        )
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )

    assert worker._repair_exhausted_worker_binding_failures(tmp_path, lane) == {
        "status": "applied",
        "requeued": 0,
        "coalesced": 0,
    }
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (event_id,)
        ).fetchone()
    assert dict(row) == {"status": "needs_reconcile", "attempts": 3}


def test_worker_binding_auth_gap_repair_retries_after_exhausted_lease_expires(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#leased-auth-gap"
    event_id = "leased-auth-gap"
    assert lane.append({"eventId": event_id, "eventKey": key, "kind": "issue_update"})
    _exhaust_with_worker_binding_error(worker, lane, event_id, key)
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='leased',lease_until=?,lease_owner=?,"
            "lease_token=? WHERE event_id=?",
            (10.0, "old-worker", "old-lease", event_id),
        )
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )

    before_expiry = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)
    assert before_expiry == {"status": "applied", "requeued": 0, "coalesced": 0}
    with lane.connect() as db:
        leased = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (event_id,)
        ).fetchone()
    assert dict(leased) == {"status": "leased", "attempts": lane.max_attempts}

    assert lane.expire_claims(now=11.0) == 1
    after_expiry = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)

    assert after_expiry == {"status": "applied", "requeued": 1, "coalesced": 0}
    with lane.connect() as db:
        repaired = db.execute(
            "SELECT status,attempts,lease_owner,lease_token FROM event_lane_events "
            "WHERE event_id=?",
            (event_id,),
        ).fetchone()
    assert dict(repaired) == {
        "status": "pending",
        "attempts": 0,
        "lease_owner": None,
        "lease_token": None,
    }
    assert lane.handler_turn(event_id) is None


def test_worker_binding_auth_gap_repair_requeues_recovery_only_and_fails_closed(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#43"
    root_id = "root-with-real-turn"
    recovery_id = worker._outcome_recovery_event_id(root_id)
    assert lane.append({"eventId": root_id, "eventKey": key, "kind": "issue_update"})
    lane.reserve_handler_turn(key, root_id, "client:real")
    lane.bind_handler_turn(key, root_id, "thread-real", "turn-real", {}, status="needs_reconcile")
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=? WHERE event_id=?",
            (lane.max_attempts, root_id),
        )
    assert lane.append(
        {
            "eventId": recovery_id,
            "eventKey": key,
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
            "payload": {"rootEventId": root_id, "publicKey": key},
        },
        priority=250,
    )
    _exhaust_with_worker_binding_error(worker, lane, recovery_id, key)
    other_id = "other-error"
    assert lane.append({"eventId": other_id, "eventKey": key, "kind": "issue_update"})
    lane.reserve_handler_turn(key, other_id, "client:other")
    assert lane.release_handler_reservation(
        other_id,
        {"error": "RuntimeError:unrelated"},
        reason="handler_start_exception",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=? WHERE event_id=?",
            (lane.max_attempts, other_id),
        )
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )

    result = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)

    assert result == {"status": "applied", "requeued": 1, "coalesced": 0}
    with lane.connect() as db:
        root_row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (root_id,)
        ).fetchone()
        recovery_row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
        other_row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (other_id,)
        ).fetchone()
    assert dict(root_row) == {"status": "needs_reconcile", "attempts": 3}
    assert dict(recovery_row) == {"status": "pending", "attempts": 0}
    assert dict(other_row) == {"status": "needs_reconcile", "attempts": 3}
    assert lane.handler_turn(root_id)["turn_id"] == "turn-real"
    assert lane.handler_turn(other_id)["status"] == "needs_reconcile"


def test_worker_binding_auth_gap_repair_requires_verified_active_authorization(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#44"
    event_id = "auth-not-verified"
    assert lane.append({"eventId": event_id, "eventKey": key, "kind": "issue_update"})
    _exhaust_with_worker_binding_error(worker, lane, event_id, key)
    monkeypatch.setattr(
        worker,
        "require_operational_authorization",
        lambda _root: (_ for _ in ()).throw(RuntimeError("authentication failed")),
    )

    result = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)

    assert result["status"] == "authorization_unavailable"
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (event_id,)
        ).fetchone()
    assert dict(row) == {"status": "needs_reconcile", "attempts": 3}
    assert lane.handler_turn(event_id)["status"] == "needs_reconcile"


def test_worker_binding_auth_gap_repair_keeps_mixed_recovery_chain_fail_closed(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#45"
    root_id = "mixed-root"
    exact_recovery = worker._outcome_recovery_event_id(root_id)
    other_recovery = "outcome-reconcile:agentscope:mixed-other"
    assert lane.append({"eventId": root_id, "eventKey": key, "kind": "issue_update"})
    assert lane.append(
        {
            "eventId": exact_recovery,
            "eventKey": key,
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
        },
        priority=250,
    )
    assert lane.append(
        {
            "eventId": other_recovery,
            "eventKey": key,
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
        },
        priority=250,
    )
    _exhaust_with_worker_binding_error(worker, lane, root_id, key)
    _exhaust_with_worker_binding_error(worker, lane, exact_recovery, key)
    lane.reserve_handler_turn(key, other_recovery, "client:other-recovery")
    assert lane.release_handler_reservation(
        other_recovery,
        {"error": "RuntimeError:other failure"},
        reason="handler_start_exception",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=? WHERE event_id=?",
            (lane.max_attempts, other_recovery),
        )
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )

    result = worker._repair_exhausted_worker_binding_failures(tmp_path, lane)

    assert result == {"status": "applied", "requeued": 0, "coalesced": 0}
    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status,attempts FROM event_lane_events ORDER BY event_id"
        ).fetchall()
    assert all(row["status"] == "needs_reconcile" and row["attempts"] == 3 for row in rows)


def test_permanent_authorization_failure_keeps_retry_budget_semantics(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    event = {
        "eventId": "authorization-invalid",
        "repo": "agentscope-ai/agentscope",
        "number": 7,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/7",
        },
    }
    lane = EventLane(tmp_path / "events.db")
    lane.append(event)
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            _authorization_bridge_error(
                "agentscope-event-create",
                "operational authorization authentication failed",
            )
        ),
    )

    result = dispatch_once(
        lane,
        lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
        limit=1,
    )

    assert result == {"claimed": 1, "delivered": 0, "pending": 1}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()
    assert dict(row) == {"status": "pending", "attempts": 1}
    assert lane.handler_turn(event["eventId"])["status"] == "needs_reconcile"


def test_runtime_root_manifest_and_foreign_event_fail_closed(tmp_path, monkeypatch):
    worker = _event_worker_module()
    release_root = tmp_path / "release"
    release_root.mkdir()
    _configure_manifest(worker, release_root, monkeypatch)
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    (runtime_root / worker.EVENT_LANE_MANIFEST).write_text(
        json.dumps({"repositories": {}}), encoding="utf-8"
    )
    lane = EventLane(runtime_root / "events.db")
    calls = []
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda _root, _operation, **kwargs: (
            calls.append(kwargs) or {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-safe"}
        ),
    )
    foreign = {
        "eventId": "foreign-event",
        "repo": "other/project",
        "number": 1,
        "issue": {"state": "open", "html_url": "https://github.com/other/project/issues/1"},
    }
    lane.append(foreign)
    worker.issue_handler_delivery(runtime_root, lane, foreign)
    assert calls == []
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id='foreign-event'"
        ).fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["payload_json"])["terminalReason"] == "foreign_repository_event"
    normal = {
        "eventId": "runtime-root-event",
        "repo": "agentscope-ai/agentscope",
        "number": 2,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/2",
        },
    }
    lane.append(normal)
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(runtime_root, lane, claimed)
    extra = calls[-1]["extra_args"]
    assert extra[extra.index("--cwd") + 1] == str(worker.CENTRAL_CWD)
    (release_root / worker.EVENT_LANE_MANIFEST).write_text("{}", encoding="utf-8")
    mutated = {
        "eventId": "mutated-release-manifest",
        "repo": "agentscope-ai/agentscope",
        "number": 3,
        "issue": {
            "state": "open",
            "html_url": "https://github.com/agentscope-ai/agentscope/issues/3",
        },
    }
    lane.append(mutated)
    worker.issue_handler_delivery(runtime_root, lane, mutated)
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id='mutated-release-manifest'"
        ).fetchone()
    assert row["status"] == "needs_reconcile"
    assert (
        json.loads(row["payload_json"])["terminalReason"] == "event-lane manifest digest mismatch"
    )


def test_pr_detail_failure_does_not_emit_shrunken_snapshot(tmp_path):
    item = {
        "number": 12,
        "updated_at": "2026-08-22T00:00:00Z",
        "title": "implementation",
        "state": "open",
        "user": {"login": "Oxygen56"},
        "pull_request": {"url": "https://api.github.com/repos/agentscope-ai/agentscope/pulls/12"},
        "labels": [],
    }
    fail_details = True

    def transport(url, headers):
        if "direction=desc" in url and "issues?" in url:
            if headers.get("If-None-Match"):
                return 304, {"ETag": "gate"}, None
            return 200, {"ETag": "gate"}, [item]
        if fail_details:
            return 503, {}, None
        if url.endswith("/pulls/12"):
            return 200, {}, {"head": {"sha": "sha12"}}
        if "/check-runs" in url:
            return 200, {}, {"check_runs": []}
        return 200, {}, []

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport)
    assert poller.poll().status == "baseline"
    assert not poller.poll().events
    fail_details = False
    result = poller.poll()
    assert len(result.events) == 1
    assert set(result.events[0]["prDetails"]) == {"pull", "reviews", "comments", "checks"}


def test_full_reconcile_first_pass_is_baseline_and_second_pass_is_idempotent(tmp_path):
    changed = False

    def transport(url, headers):
        if "direction=desc" in url:
            return 200, {"ETag": "gate"}, [_issue(1, "2026-08-22T00:00:00Z")]
        title = "changed" if changed else "item 1"
        return 200, {}, [_issue(1, "2026-08-22T00:00:00Z") | {"title": title}]

    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=transport)
    poller.poll()
    first = poller.full_reconcile()
    assert not first.events
    second = poller.full_reconcile()
    assert not second.events
    changed = True
    third = poller.full_reconcile()
    assert len(third.events) == 1


def test_pr_event_ignores_old_shared_followup_binding(tmp_path, monkeypatch):
    worker = _event_worker_module()
    old_context = tmp_path / "old-task" / ".oss-pr-radar" / "task-context.json"
    old_context.parent.mkdir(parents=True)
    old_context.write_text(
        json.dumps(
            {
                "threadId": "thread-2385",
                "key": "agentscope-ai/agentscope#2385",
                "prFollowup": {"prUrl": "https://github.com/agentscope-ai/agentscope/pull/2397"},
            }
        ),
        encoding="utf-8",
    )
    event = {
        "repo": "agentscope-ai/agentscope",
        "number": 2397,
        "kind": "pr_update",
        "issue": {
            "number": 2397,
            "pull_request": {"html_url": "https://github.com/agentscope-ai/agentscope/pull/2397"},
        },
    }

    def unexpected_ledger(*_args, **_kwargs):
        raise AssertionError("ordinary PR target resolution must not read the shared ledger")

    monkeypatch.setattr(worker, "RadarLedger", unexpected_ledger)
    target = worker._resolve_event_target(tmp_path, event)
    assert target["kind"] == "pr_watch"
    assert target["key"] == "agentscope-ai/agentscope#2397"
    assert "threadId" not in target


def test_pr_event_wakes_central_thread_despite_old_binding(tmp_path, monkeypatch):
    worker = _event_worker_module()
    central = CENTRAL_THREAD
    _configure_manifest(worker, tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda root, operation, **kwargs: (
            calls.append((root, operation, kwargs))
            or {"ok": True, "threadId": central, "turnId": "turn-central"}
        ),
    )
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "pr-central-wake",
        "repo": "agentscope-ai/agentscope",
        "number": 2397,
        "kind": "pr_update",
        "issue": {
            "state": "open",
            "pull_request": {"html_url": "https://github.com/agentscope-ai/agentscope/pull/2397"},
        },
    }
    lane.append(event)
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(
        tmp_path,
        lane,
        claimed,
        target=worker._resolve_event_target(tmp_path, claimed),
    )
    extra = calls[0][2]["extra_args"]
    assert extra[extra.index("--thread-id") + 1] == central
    assert lane.handler_thread("agentscope-ai/agentscope#2397")["thread_id"] == central


def test_public_work_seed_is_imported_once_and_outcome_can_replace_it(tmp_path):
    worker = _event_worker_module()
    seed = tmp_path / "state" / "agentscope-public-work.json"
    seed.parent.mkdir()
    seed.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "key": "agentscope-ai/agentscope#2364",
                        "status": "design_wait",
                        "designWaitUntil": "2099-01-01T00:00:00Z",
                    }
                ]
            }
        )
    )
    lane = EventLane(tmp_path / "state" / "events.db")
    assert worker._sync_public_work_seed(tmp_path, lane) == 1
    assert lane.public_status("agentscope-ai/agentscope#2364") == "design_wait"
    seed.write_text(
        json.dumps({"items": [{"key": "agentscope-ai/agentscope#2364", "status": "active"}]})
    )
    assert worker._sync_public_work_seed(tmp_path, lane) == 0
    lane.register_public_work("agentscope-ai/agentscope#2364", status="watch_only")
    assert lane.public_status("agentscope-ai/agentscope#2364") == "watch_only"


def test_invalid_outcome_creates_durable_recovery_event(tmp_path, monkeypatch):
    worker = _event_worker_module()
    central = CENTRAL_THREAD
    _configure_manifest(worker, tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda root, operation, **kwargs: (
            calls.append((root, operation, kwargs))
            or {"ok": True, "threadId": central, "turnId": "turn-recovery"}
        ),
    )
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_id = "event-invalid"
    lane.append({"eventId": event_id, "repo": "agentscope-ai/agentscope", "number": 1})
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", event_id, "client:event-invalid")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1", event_id, "thread-1", "turn-1", {}, status="started"
    )
    receipt = (
        tmp_path
        / "state"
        / "agentscope_event_receipts"
        / (hashlib.sha256(event_id.encode()).hexdigest() + ".json")
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text(
        json.dumps(
            {
                "ok": True,
                "turnStatus": "completed",
                "threadId": "thread-1",
                "turnId": "turn-1",
                "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
            }
        )
    )
    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    with lane.connect() as db:
        row = db.execute(
            "SELECT event_id,payload_json FROM event_lane_events "
            "WHERE event_id LIKE 'outcome-reconcile:%'"
        ).fetchone()
    recovery_event = json.loads(row["payload_json"])
    recovery_id = worker._outcome_recovery_event_id(event_id)
    assert row["event_id"] == recovery_id
    assert recovery_event["kind"] == "outcome_reconcile"
    assert recovery_event["rootEventId"] == event_id
    assert len(recovery_id) < 120
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(tmp_path, lane, claimed)
    extra = calls[0][2]["extra_args"]
    assert extra[extra.index("--thread-id") + 1] == central
    prompt = extra[extra.index("--prompt") + 1]
    assert "strictly read-only" in prompt
    for forbidden_write in ("comment", "label", "assign", "push", "rerun workflows"):
        assert forbidden_write in prompt
    assert "Only inspect existing state and write the private outcome file" in prompt
    assert lane.handler_thread("agentscope-ai/agentscope#1")["thread_id"] == central
    with lane.connect() as db:
        status = db.execute(
            "SELECT status FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()["status"]
    assert status != "delivered"


def test_unresolved_root_gets_one_stable_read_only_recovery_event(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    root_event_id = "github:agentscope-ai/agentscope:2448:issue_update:failed"
    event_key = "agentscope-ai/agentscope#2448"
    lane.append(
        {
            "eventId": root_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2448,
            "kind": "issue_update",
            "terminalReason": "handler_start_exception",
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
            (root_event_id,),
        )
    for status in ("baseline", "watch_only", "coalesced", "pending", "leased"):
        ignored_id = f"ignored-{status}"
        lane.append(
            {
                "eventId": ignored_id,
                "eventKey": f"agentscope-ai/agentscope#{len(status)}",
                "kind": "issue_update",
            }
        )
        lane.reserve_handler_turn(
            f"agentscope-ai/agentscope#{len(status)}",
            ignored_id,
            f"client:{status}",
        )
        lane.bind_handler_turn(
            f"agentscope-ai/agentscope#{len(status)}",
            ignored_id,
            "",
            "",
            {"terminalReason": "handler_turn_timeout"},
            status="needs_reconcile",
        )
        with lane.writer() as db:
            db.execute(
                "UPDATE event_lane_events SET status=? WHERE event_id=?",
                (status, ignored_id),
            )

    first = worker._enqueue_unresolved_outcome_recoveries(lane)
    second = worker._enqueue_unresolved_outcome_recoveries(lane)
    recovery_id = worker._outcome_recovery_event_id(root_event_id)
    assert first == {"candidates": 1, "inserted": 1, "existing": 0, "skipped": 0}
    assert second == {"candidates": 1, "inserted": 0, "existing": 1, "skipped": 0}
    with lane.connect() as db:
        row = db.execute(
            "SELECT priority,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    recovery = json.loads(row["payload_json"])
    assert row["priority"] == 250
    assert recovery["rootEventId"] == root_event_id
    assert recovery["eventIdSource"] == root_event_id
    assert recovery["eventKey"] == event_key
    assert recovery["payload"]["reason"] == "handler_start_exception"


def test_existing_unresolved_legacy_recovery_blocks_a_duplicate_stable_recovery(
    tmp_path,
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    root_event_id = "github:agentscope-ai/agentscope:1:issue_update:legacy"
    event_key = "agentscope-ai/agentscope#1"
    legacy_id = "outcome-reconcile:agentscope:legacy-pending"
    assert lane.append(
        {
            "eventId": root_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    assert lane.append(
        {
            "eventId": legacy_id,
            "eventKey": event_key,
            "kind": "outcome_reconcile",
            "eventIdSource": root_event_id,
            "payload": {"eventId": root_event_id, "publicKey": event_key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root_event_id,),
        )
        db.execute(
            "UPDATE event_lane_events SET status='pending',attempts=2 WHERE event_id=?",
            (legacy_id,),
        )

    result = worker._enqueue_unresolved_outcome_recoveries(lane)

    assert result == {"candidates": 1, "inserted": 0, "existing": 1, "skipped": 0}
    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,attempts FROM event_lane_events "
            "WHERE event_id LIKE 'outcome-reconcile:%'"
        ).fetchall()
    assert [(row["event_id"], row["attempts"]) for row in rows] == [(legacy_id, 2)]


@pytest.mark.parametrize(
    ("recovery_id", "kind"),
    [
        ("outcome-reconcile:agentscope:missing-kind", "issue_update"),
        ("recovery-without-prefix", "outcome_reconcile"),
    ],
)
def test_malformed_recovery_like_sibling_blocks_duplicate_enqueue(
    tmp_path,
    recovery_id,
    kind,
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    root = "github:agentscope-ai/agentscope:1:issue_update:root"
    key = "agentscope-ai/agentscope#1"
    assert lane.append(
        {
            "eventId": root,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    assert lane.append(
        {
            "eventId": recovery_id,
            "eventKey": key,
            "kind": kind,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id IN (?,?)",
            (root, recovery_id),
        )

    result = worker._enqueue_unresolved_outcome_recoveries(lane)

    assert result == {"candidates": 1, "inserted": 0, "existing": 1, "skipped": 0}
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM event_lane_events WHERE event_id=?",
                (worker._outcome_recovery_event_id(root),),
            ).fetchone()[0]
            == 0
        )


def test_structurally_invalid_terminal_outcome_retries_recovery(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_key = "agentscope-ai/agentscope#1"
    root_event_id = "root-invalid-schema"
    recovery_id = worker._outcome_recovery_event_id(root_event_id)
    lane.append(
        {
            "eventId": recovery_id,
            "kind": "outcome_reconcile",
            "eventKey": event_key,
            "rootEventId": root_event_id,
            "eventIdSource": root_event_id,
            "payload": {"eventId": root_event_id, "publicKey": event_key},
        },
        priority=250,
    )
    claimed = lane.claim(limit=1)[0]
    lane.reserve_handler_turn(event_key, recovery_id, "client:recovery")
    lane.bind_handler_turn(event_key, recovery_id, "thread-1", "turn-1", {}, status="started")
    lane.ack(recovery_id, lease_token=claimed["leaseToken"])
    receipt = worker._event_artifact_path(
        tmp_path,
        worker.EVENT_RECEIPT_DIR,
        recovery_id,
        attempt=1,
        is_recovery=True,
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text(
        json.dumps(
            {
                "turnStatus": "completed",
                "outcome": {
                    "eventId": recovery_id,
                    "publicKey": event_key,
                    "state": "no_action",
                },
            }
        )
    )

    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    assert row["status"] == "pending"
    assert row["attempts"] == 1


def test_legacy_recovery_retry_preserves_legacy_identity_and_can_migrate(
    tmp_path,
):
    worker = _event_worker_module()
    database = tmp_path / "state" / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root_event_id = "legacy-root"
    event_key = "agentscope-ai/agentscope#1"
    legacy_recovery_id = "outcome-reconcile:agentscope:legacy-retry"
    assert lane.append(
        {
            "eventId": root_event_id,
            "eventKey": event_key,
            "kind": "issue_update",
        }
    )
    assert lane.append(
        {
            "eventId": legacy_recovery_id,
            "eventKey": event_key,
            "kind": "outcome_reconcile",
            "eventIdSource": root_event_id,
            "payload": {
                "eventId": root_event_id,
                "publicKey": event_key,
            },
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root_event_id,),
        )

    assert (
        worker._retry_or_exhaust_outcome_recovery(
            lane,
            event_id=legacy_recovery_id,
            root_event_id=root_event_id,
            outcome={"error": "invalid"},
        )
        == "retry"
    )
    with lane.connect() as db:
        payload = json.loads(
            db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?",
                (legacy_recovery_id,),
            ).fetchone()[0]
        )
    assert payload["eventIdSource"] == root_event_id
    assert payload["payload"]["eventId"] == root_event_id
    assert "rootEventId" not in payload
    assert "rootEventId" not in payload["payload"]

    lane.reserve_handler_turn(event_key, legacy_recovery_id, "client:legacy")
    lane.bind_handler_turn(
        event_key,
        legacy_recovery_id,
        "thread-legacy",
        "turn-legacy",
        {
            "turnStatus": "completed",
            "eventId": legacy_recovery_id,
            "eventKey": event_key,
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": legacy_recovery_id,
                "publicKey": event_key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id=?",
            (legacy_recovery_id,),
        )
    preview = recovery_migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["eventsToCoalesce"] == 1


@pytest.mark.parametrize("terminal", ["failed", "interrupted"])
def test_noncompleted_turn_cannot_publish_a_structurally_valid_outcome(tmp_path, terminal):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_id = f"root-{terminal}"
    event_key = "agentscope-ai/agentscope#1"
    lane.append(
        {
            "eventId": event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    claimed = lane.claim(limit=1)[0]
    lane.reserve_handler_turn(event_key, event_id, f"client:{terminal}")
    lane.bind_handler_turn(
        event_key, event_id, "thread-1", f"turn-{terminal}", {}, status="started"
    )
    lane.ack(event_id, lease_token=claimed["leaseToken"])
    receipt = worker._event_artifact_path(tmp_path, worker.EVENT_RECEIPT_DIR, event_id)
    receipt.parent.mkdir(parents=True)
    receipt.write_text(
        json.dumps(
            {
                "turnStatus": terminal,
                "outcome": {
                    "schemaVersion": "agentscope_event_outcome_v1",
                    "eventId": event_id,
                    "publicKey": event_key,
                    "state": "no_action",
                },
            }
        )
    )

    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    assert lane.handler_turn(event_id)["status"] == "needs_reconcile"
    with lane.connect() as db:
        recovery_count = db.execute(
            "SELECT count(*) FROM event_lane_events WHERE event_id=?",
            (worker._outcome_recovery_event_id(event_id),),
        ).fetchone()[0]
    assert recovery_count == 1


@pytest.mark.parametrize(
    ("receipt_model", "recorded_model", "next_model"),
    [
        ("gpt-6-astra", "gpt-6-astra", "gpt-5.6-terra"),
        (None, "legacy-unrecorded", "gpt-6-astra"),
    ],
)
def test_capacity_failed_root_recovery_uses_only_the_recorded_model(
    tmp_path, monkeypatch, receipt_model, recorded_model, next_model
):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_id = "root-capacity"
    event_key = "agentscope-ai/agentscope#1"
    lane.append(
        {
            "eventId": event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    claimed = lane.claim(limit=1)[0]
    lane.reserve_handler_turn(event_key, event_id, "client:capacity")
    lane.bind_handler_turn(event_key, event_id, "thread-1", "turn-capacity", {}, status="started")
    assert lane.ack(event_id, lease_token=claimed["leaseToken"])
    receipt = worker._event_artifact_path(tmp_path, worker.EVENT_RECEIPT_DIR, event_id)
    receipt.parent.mkdir(parents=True)
    receipt_value = {
        "turnStatus": "failed",
        "terminalError": {"code": "serverOverloaded"},
        "outcome": {
            "schemaVersion": "agentscope_event_outcome_v1",
            "eventId": event_id,
            "publicKey": event_key,
            "state": "no_action",
        },
    }
    if receipt_model is not None:
        receipt_value["model"] = receipt_model
    receipt.write_text(json.dumps(receipt_value))

    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    recovery_id = worker._outcome_recovery_event_id(event_id)
    with lane.connect() as db:
        payload = json.loads(
            db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?", (recovery_id,)
            ).fetchone()[0]
        )
    assert [item["model"] for item in payload["modelFallback"]["history"]] == [recorded_model]
    calls = []
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda _root, _operation, **kwargs: (
            calls.append(kwargs)
            or {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-recovery"}
        ),
    )
    recovery = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(tmp_path, lane, recovery)
    extra = calls[0]["extra_args"]
    assert extra[extra.index("--model") + 1] == next_model


def test_legacy_capacity_receipt_without_model_retries_recovery_with_astra(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    root_event_id = "github:agentscope-ai/agentscope:2:issue_update:legacy-capacity"
    recovery_id = worker._outcome_recovery_event_id(root_event_id)
    event_key = "agentscope-ai/agentscope#2"
    lane.append(
        {
            "eventId": root_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2,
            "kind": "issue_update",
        }
    )
    lane.append(
        {
            "eventId": recovery_id,
            "eventKey": event_key,
            "kind": "outcome_reconcile",
            "rootEventId": root_event_id,
            "eventIdSource": root_event_id,
            "payload": {
                "eventId": root_event_id,
                "rootEventId": root_event_id,
                "publicKey": event_key,
            },
        },
        priority=250,
    )
    claimed = lane.claim(limit=1)[0]
    assert claimed["eventId"] == recovery_id
    lane.reserve_handler_turn(event_key, recovery_id, "client:legacy-capacity")
    lane.bind_handler_turn(
        event_key,
        recovery_id,
        "thread-legacy",
        "turn-legacy-capacity",
        {},
        status="started",
    )
    assert lane.ack(recovery_id, lease_token=claimed["leaseToken"])
    receipt = worker._event_artifact_path(
        tmp_path,
        worker.EVENT_RECEIPT_DIR,
        recovery_id,
        attempt=1,
        is_recovery=True,
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text(
        json.dumps(
            {
                "turnStatus": "failed",
                "terminalError": {"code": "serverOverloaded"},
                "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
            }
        )
    )

    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert (row["status"], row["attempts"]) == ("pending", 0)
    assert [item["model"] for item in payload["modelFallback"]["history"]] == [
        worker.LEGACY_UNRECORDED_MODEL
    ]
    assert payload["modelFallback"]["nextIndex"] == 0
    assert worker._event_model(payload) == "gpt-6-astra"


def test_invalid_recovery_reuses_one_event_and_exhausts_existing_attempt_budget(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(
        tmp_path / "state" / "agentscope-events.sqlite3",
        max_attempts=3,
    )
    event_key = "agentscope-ai/agentscope#1"
    root_event_id = "event-invalid-" + ("x" * 2048)
    lane.append(
        {
            "eventId": root_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
        }
    )
    claimed = lane.claim(owner="event-lane")[0]
    lane.reserve_handler_turn(event_key, root_event_id, "client:root")
    lane.bind_handler_turn(event_key, root_event_id, "thread-1", "turn-root", {}, status="started")
    assert lane.ack(
        root_event_id,
        lease_token=str(claimed["leaseToken"]),
        owner="event-lane",
    )
    receipt_dir = tmp_path / "state" / "agentscope_event_receipts"
    receipt_dir.mkdir(parents=True)
    invalid_outcome = {"error": "OUTCOME_MISSING_OR_INVALID"}
    root_receipt = receipt_dir / (hashlib.sha256(root_event_id.encode()).hexdigest() + ".json")
    root_receipt.write_text(
        json.dumps(
            {
                "ok": True,
                "turnStatus": "completed",
                "threadId": "thread-1",
                "turnId": "turn-root",
                "outcome": invalid_outcome,
            }
        )
    )
    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1

    recovery_id = worker._outcome_recovery_event_id(root_event_id)
    assert len(recovery_id) < 120
    recovery_receipts = []
    for attempt in range(1, lane.max_attempts + 1):
        recovery = lane.claim(owner="event-lane")[0]
        assert recovery["eventId"] == recovery_id
        assert recovery["attempts"] == attempt
        lane.reserve_handler_turn(event_key, recovery_id, f"client:recovery:{attempt}")
        lane.bind_handler_turn(
            event_key,
            recovery_id,
            "thread-1",
            f"turn-recovery-{attempt}",
            {},
            status="started",
        )
        assert lane.ack(
            recovery_id,
            lease_token=str(recovery["leaseToken"]),
            owner="event-lane",
        )
        recovery_receipt = worker._event_artifact_path(
            tmp_path,
            worker.EVENT_RECEIPT_DIR,
            recovery_id,
            attempt=attempt,
            is_recovery=True,
        )
        recovery_receipts.append(recovery_receipt)
        recovery_receipt.parent.mkdir(parents=True, exist_ok=True)
        recovery_receipt.write_text(
            json.dumps(
                {
                    "ok": True,
                    "turnStatus": "completed",
                    "threadId": "thread-1",
                    "turnId": f"turn-recovery-{attempt}",
                    "outcome": invalid_outcome,
                }
            )
        )
        assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
        with lane.connect() as db:
            row = db.execute(
                "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
                (recovery_id,),
            ).fetchone()
            recovery_count = db.execute(
                "SELECT count(*) FROM event_lane_events WHERE event_id LIKE 'outcome-reconcile:%'"
            ).fetchone()[0]
        assert row["attempts"] == attempt
        assert recovery_count == 1
        if attempt < lane.max_attempts:
            assert row["status"] == "pending"
        else:
            payload = json.loads(row["payload_json"])
            assert row["status"] == "needs_reconcile"
            assert payload["terminalReason"] == "outcome_recovery_attempts_exhausted"
            assert payload["recoveryExhausted"] is True

    assert lane.claim(owner="event-lane") == []
    assert len(set(recovery_receipts)) == lane.max_attempts
    assert all(path.is_file() for path in recovery_receipts)


def test_recovery_retry_uses_distinct_bridge_identity_and_evidence_paths(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        worker,
        "run_bridge",
        lambda _root, _operation, **kwargs: (
            calls.append(kwargs)
            or {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-recovery-2"}
        ),
    )
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    root_event_id = "event-invalid"
    recovery_id = worker._outcome_recovery_event_id(root_event_id)
    event = {
        "eventId": recovery_id,
        "eventKey": "agentscope-ai/agentscope#1",
        "kind": "outcome_reconcile",
        "rootEventId": root_event_id,
        "attempts": 2,
    }
    lane.append(event, priority=250)
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET attempts=1 WHERE event_id=?",
            (recovery_id,),
        )
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(tmp_path, lane, claimed)
    extra = calls[0]["extra_args"]
    client_id = extra[extra.index("--client-user-message-id") + 1]
    receipt = Path(extra[extra.index("--receipt") + 1])
    outcome = Path(extra[extra.index("--outcome-receipt") + 1])
    assert client_id.endswith(":attempt:2")
    assert receipt == worker._event_artifact_path(
        tmp_path,
        worker.EVENT_RECEIPT_DIR,
        recovery_id,
        attempt=2,
        is_recovery=True,
    )
    assert outcome == worker._event_artifact_path(
        tmp_path,
        worker.EVENT_OUTCOME_DIR,
        recovery_id,
        attempt=2,
        is_recovery=True,
    )
    assert receipt != worker._event_artifact_path(
        tmp_path,
        worker.EVENT_RECEIPT_DIR,
        recovery_id,
        attempt=1,
        is_recovery=True,
    )


def _make_exhausted_outcome_chain(worker, lane, key="agentscope-ai/agentscope#1"):
    number = int(key.rsplit("#", 1)[1])
    root_id = f"github:agentscope-ai/agentscope:{number}:issue_update:failed"
    recovery_id = worker._outcome_recovery_event_id(root_id)
    lane.append(
        {
            "eventId": root_id,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": number,
            "kind": "issue_update",
        }
    )
    lane.append(
        {
            "eventId": recovery_id,
            "eventKey": key,
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
            "eventIdSource": root_id,
            "payload": {"eventId": root_id, "rootEventId": root_id, "publicKey": key},
        },
        priority=250,
    )
    for event_id in (root_id, recovery_id):
        lane.reserve_handler_turn(key, event_id, f"client:{event_id}")
        lane.bind_handler_turn(
            key,
            event_id,
            "thread-1",
            f"turn-{event_id}",
            {"turnStatus": "failed", "turnStarted": True},
            status="needs_reconcile",
        )
        with lane.writer() as db:
            db.execute(
                "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
                (event_id,),
            )
    lane.register_public_work(key, status="active", source="outcome-invalid")
    return root_id, recovery_id


def _make_controller_rejected_prestart_chain(worker, root, monkeypatch):
    from oss_pr_radar.ledger import RadarLedger

    state = root / "state"
    state.mkdir(mode=0o700)
    ledger_dir = state / "ledger-releases"
    ledger_dir.mkdir(mode=0o700)
    store = RadarLedger(ledger_dir / "ledger.sqlite3")
    (state / "current-ledger").symlink_to("ledger-releases/ledger.sqlite3")
    key = "agentscope-ai/agentscope#1"
    store.enqueue(
        {
            "intentId": "rejected-intent",
            "key": key,
            "repo": "agentscope-ai/agentscope",
            "issueNumber": 1,
            "issueUrl": "https://github.com/agentscope-ai/agentscope/issues/1",
            "title": "Rejected duplicate",
            "issuedAt": "2026-10-01T00:00:00Z",
            "expiresAt": "2026-10-03T00:00:00Z",
        }
    )
    store.record_stage(key, "AUDIT_NO_GO", reason="STRONG_EXISTING_PR")
    with store.connect() as db:
        db.execute(
            "INSERT INTO task_quarantines(opportunity_key,reason,dedupe_key,payload_json,"
            "status,created_at) VALUES(?,?,?,?,?,?)",
            (
                key,
                "TASK_CONTEXT_BLOCKED",
                "original-gate",
                '{"original":true}',
                "ACTIVE",
                "2026-10-01T00:00:00Z",
            ),
        )
    lane = EventLane(state / "agentscope-events.sqlite3")
    root_id = "github:agentscope-ai/agentscope:1:issue_update:2026-10-02T00:35:36Z"
    recovery_id = worker._outcome_recovery_event_id(root_id)
    root_event = {
        "eventId": root_id,
        "eventKey": key,
        "repo": "agentscope-ai/agentscope",
        "number": 1,
        "kind": "issue_update",
        "updatedAt": "2026-10-02T00:35:36Z",
    }
    recovery = {
        "eventId": recovery_id,
        "eventKey": key,
        "kind": "outcome_reconcile",
        "rootEventId": root_id,
        "eventIdSource": root_id,
        "payload": {"eventId": root_id, "rootEventId": root_id, "publicKey": key},
    }
    paths = []
    for event in (root_event, recovery):
        event_id = event["eventId"]
        lane.append(event)
        lane.reserve_handler_turn(key, event_id, f"client:{event_id}")
        lane.release_handler_reservation(
            event_id,
            {"error": "RuntimeError:agentscope-event-create: Traceback (truncated)"},
            reason="handler_start_exception",
        )
        with lane.writer() as db:
            db.execute(
                "UPDATE event_lane_events SET status='needs_reconcile',attempts=? WHERE event_id=?",
                (lane.max_attempts, event_id),
            )
        path = worker._event_artifact_path(
            root,
            worker.EVENT_RECEIPT_DIR,
            event_id,
            attempt=lane.max_attempts,
            is_recovery=event_id == recovery_id,
        )
        path.parent.mkdir(mode=0o700, exist_ok=True)
        receipt = {
            "eventId": event_id,
            "eventKey": key,
            "model": "gpt-6-astra",
            "ok": False,
            "retryable": False,
            "turnStarted": False,
            "turnId": None,
            "error": f"PermissionError:task action blocked by active quarantine: {key}",
        }
        for target, value in (
            (path, receipt),
            (
                path.with_suffix(".request.json"),
                {
                    "eventId": event_id,
                    "eventKey": key,
                    "model": "gpt-6-astra",
                    "threadId": CENTRAL_THREAD,
                    "prompt": "Original request must remain intact",
                },
            ),
            (path.with_suffix(".launch.json"), {"pid": 99999999, "model": "gpt-6-astra"}),
        ):
            target.write_text(json.dumps(value), encoding="utf-8")
            target.chmod(0o600)
            paths.append(target)
    monkeypatch.setattr(
        worker, "require_operational_authorization", lambda _root: _active_authorization()
    )
    monkeypatch.setattr(
        worker.GitHubIssuePoller, "poll", lambda _self, **_kw: worker.PollResult("not_modified")
    )
    monkeypatch.setattr(worker, "_live_exhausted_recovery_evidence", lambda *_a, **_kw: None)
    return lane, store, root_id, recovery_id, paths


def test_run_once_watches_exact_controller_rejected_prestart_chain_without_rewriting_evidence(
    tmp_path,
    monkeypatch,
):
    worker = _event_worker_module()
    lane, store, root_id, recovery_id, paths = _make_controller_rejected_prestart_chain(
        worker,
        tmp_path,
        monkeypatch,
    )
    raw = {path: path.read_bytes() for path in paths}
    with lane.connect() as db:
        before_events = {
            r["event_id"]: dict(r) for r in db.execute("SELECT * FROM event_lane_events")
        }
        before_turns = {
            r["event_id"]: dict(r) for r in db.execute("SELECT * FROM event_lane_turns")
        }
    with store.connect() as db:
        before_main = {
            table: [dict(r) for r in db.execute(f"SELECT * FROM {table}")]
            for table in ("opportunities", "intents", "task_quarantines", "events")
        }
    delivered = []
    first = worker.run_once(tmp_path, deliver=delivered.append)
    second = worker.run_once(tmp_path, deliver=delivered.append)
    assert first["recoverySettlement"]["settled"] == 1
    assert second["recoverySettlement"]["settled"] == 0
    assert delivered == []
    with lane.connect() as db:
        after_events = {
            r["event_id"]: dict(r) for r in db.execute("SELECT * FROM event_lane_events")
        }
        after_turns = {r["event_id"]: dict(r) for r in db.execute("SELECT * FROM event_lane_turns")}
    assert after_events[root_id] == before_events[root_id] | {"status": "watch_only"}
    assert after_events[recovery_id] == before_events[recovery_id] | {"status": "coalesced"}
    assert after_turns[root_id] == before_turns[root_id] | {"status": "watch_only"}
    assert after_turns[recovery_id] == before_turns[recovery_id] | {"status": "superseded"}
    assert {path: path.read_bytes() for path in paths} == raw
    with store.connect() as db:
        after_main = {
            table: [dict(r) for r in db.execute(f"SELECT * FROM {table}")] for table in before_main
        }
    assert after_main == before_main
    marker = lane.state_value(f"controller-prestart-rejection:{root_id}")
    assert marker["reason"] == "controller_prestart_rejected"
    assert marker["controllerBinding"]["stage"] == "AUDIT_NO_GO"
    assert "outcome" not in marker
    # The closeout belongs to the original identity only. A genuinely later
    # public revision still enters the ordinary observation/delivery path.
    newer_id = "github:agentscope-ai/agentscope:1:issue_update:2026-10-02T04:00:00Z"
    lane.append(
        {
            "eventId": newer_id,
            "eventKey": "agentscope-ai/agentscope#1",
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
            "updatedAt": "2026-10-02T04:00:00Z",
        }
    )
    worker.run_once(tmp_path, deliver=delivered.append)
    assert [event["eventId"] for event in delivered] == [newer_id]


@pytest.mark.parametrize(
    "mismatch",
    [
        "foreign_receipt",
        "different_error",
        "retryable",
        "started",
        "lane_turn",
        "live_pid",
        "not_exhausted",
        "not_rejected",
        "no_quarantine",
        "auth_unavailable",
    ],
)
def test_prestart_rejection_settlement_preserves_unproved_chain(tmp_path, monkeypatch, mismatch):
    worker = _event_worker_module()
    lane, store, root_id, recovery_id, paths = _make_controller_rejected_prestart_chain(
        worker,
        tmp_path,
        monkeypatch,
    )
    if mismatch in {"foreign_receipt", "different_error", "retryable", "started"}:
        receipt = json.loads(paths[0].read_bytes())
        field, value = {
            "foreign_receipt": ("eventId", "foreign-event"),
            "different_error": ("error", "PermissionError:unrelated"),
            "retryable": ("retryable", True),
            "started": ("turnStarted", True),
        }[mismatch]
        receipt[field] = value
        paths[0].write_text(json.dumps(receipt), encoding="utf-8")
    elif mismatch in {"lane_turn", "not_exhausted"}:
        with lane.writer() as db:
            if mismatch == "lane_turn":
                db.execute(
                    "UPDATE event_lane_turns SET turn_id='real-turn' WHERE event_id=?", (root_id,)
                )
            else:
                db.execute("UPDATE event_lane_events SET attempts=2 WHERE event_id=?", (root_id,))
    elif mismatch == "live_pid":
        monkeypatch.setattr(worker, "_receipt_has_live_bridge", lambda _value: True)
    elif mismatch in {"not_rejected", "no_quarantine"}:
        with store.connect() as db:
            if mismatch == "not_rejected":
                db.execute("UPDATE intents SET status='DISPATCHED'")
            else:
                db.execute("UPDATE task_quarantines SET status='CLEARED'")
    else:

        def unavailable(_root):
            raise RuntimeError("operational authorization expired")

        monkeypatch.setattr(worker, "require_operational_authorization", unavailable)
    with lane.connect() as db:
        before = {
            table: [dict(r) for r in db.execute(f"SELECT * FROM {table}")]
            for table in ("event_lane_events", "event_lane_turns")
        }
    assert worker._settle_exhausted_outcome_recoveries(tmp_path, lane)["settled"] == 0
    with lane.connect() as db:
        after = {table: [dict(r) for r in db.execute(f"SELECT * FROM {table}")] for table in before}
    assert after == before
    assert lane.state_value(f"controller-prestart-rejection:{root_id}") is None


def test_exhausted_recovery_settles_only_after_external_claim_evidence(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)

    def transport(url, _headers):
        if "/comments" in url:
            return (
                200,
                {},
                [
                    {
                        "id": 17,
                        "user": {"login": "another-contributor"},
                        "created_at": "2026-09-01T00:00:00Z",
                        "body": "I'd like to take this issue and submit a PR shortly.",
                    }
                ],
            )
        return 200, {}, {"state": "open", "assignee": None, "assignees": []}

    result = worker._settle_exhausted_outcome_recoveries(
        tmp_path, lane, transport=transport, now=100.0
    )
    assert result == {"candidates": 1, "settled": 1, "alreadyApplied": 0, "skipped": 0}
    with lane.connect() as db:
        rows = db.execute(
            "SELECT event_id,status,payload_json FROM event_lane_events ORDER BY event_id"
        ).fetchall()
        turns = db.execute(
            "SELECT event_id,status,receipt_json FROM event_lane_turns ORDER BY event_id"
        ).fetchall()
    statuses = {row["event_id"]: row["status"] for row in rows}
    assert statuses[recovery_id] == "coalesced"
    assert statuses[root_id] == "watch_only"
    turn_statuses = {row["event_id"]: row["status"] for row in turns}
    assert turn_statuses[recovery_id] == "superseded"
    assert turn_statuses[root_id] == "watch_only"
    assert all(
        json.loads(row["payload_json"]).get("operatorResolution", {}).get("state") == "watch_only"
        for row in rows
    )
    assert lane.public_status("agentscope-ai/agentscope#1") == "watch_only"
    assert worker._settle_exhausted_outcome_recoveries(
        tmp_path, lane, transport=transport, now=101.0
    ) == {"candidates": 0, "settled": 0, "alreadyApplied": 0, "skipped": 0}
    assert root_id and recovery_id


def test_exhausted_recovery_stays_blocked_without_strong_public_evidence(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    _make_exhausted_outcome_chain(worker, lane)

    def transport(url, _headers):
        if "/comments" in url:
            return 200, {}, [{"id": 18, "user": {"login": "reviewer"}, "body": "Thanks!"}]
        return 200, {}, {"state": "open", "assignee": None, "assignees": []}

    result = worker._settle_exhausted_outcome_recoveries(tmp_path, lane, transport=transport)
    assert result == {"candidates": 1, "settled": 0, "alreadyApplied": 0, "skipped": 1}
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT status FROM event_lane_events WHERE event_id LIKE 'outcome-reconcile:%'"
            ).fetchone()[0]
            == "needs_reconcile"
        )


def test_exhausted_recovery_does_not_supersede_live_turn(tmp_path, monkeypatch):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    _root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)
    events_module = importlib.import_module("oss_pr_radar.agentscope_events")
    monkeypatch.setattr(events_module, "_event_bridge_process_alive", lambda _pid: True)
    with lane.writer() as db:
        row = db.execute(
            "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (recovery_id,)
        ).fetchone()
        receipt = json.loads(row[0])
        receipt["workerPid"] = 1234
        db.execute(
            "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
            (json.dumps(receipt), recovery_id),
        )

    result = worker._settle_exhausted_outcome_recoveries(
        tmp_path,
        lane,
        transport=lambda url, _headers: (
            (
                200,
                {},
                [{"id": 1, "user": {"login": "other"}, "body": "I will take this issue."}],
            )
            if "/comments" in url
            else (200, {}, {"state": "open", "assignee": None, "assignees": []})
        ),
    )
    assert result["settled"] == 0
    assert lane.handler_turn(recovery_id)["status"] == "needs_reconcile"


def test_exhausted_recovery_rejects_forged_lineage_and_untrusted_reason(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)
    evidence = {
        "kind": "external_claim_comment",
        "repo": "agentscope-ai/agentscope",
        "number": "1",
        "issueState": "open",
        "commentId": "17",
        "author": "other",
        "createdAt": "2026-09-01T00:00:00Z",
        "excerpt": "I will take this issue.",
    }
    assert (
        lane.settle_exhausted_recovery_no_action(
            recovery_id,
            root_event_id=root_id,
            event_key="agentscope-ai/agentscope#1",
            reason="not-a-public-reason",
            evidence=evidence,
        )["status"]
        == "invalid"
    )
    forged_id = "outcome-reconcile:agentscope:forged"
    lane.append(
        {
            "eventId": forged_id,
            "eventKey": "agentscope-ai/agentscope#1",
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
            "eventIdSource": root_id,
            "payload": {"eventId": root_id, "publicKey": "agentscope-ai/agentscope#1"},
        },
        priority=250,
    )
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", forged_id, "client:forged")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        forged_id,
        "thread-1",
        "turn-forged",
        {"turnStatus": "failed"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
            (forged_id,),
        )

    result = worker._settle_exhausted_outcome_recoveries(
        tmp_path,
        lane,
        transport=lambda url, _headers: (
            (
                200,
                {},
                [
                    {
                        "id": 17,
                        "user": {"login": "other"},
                        "created_at": "2026-09-01T00:00:00Z",
                        "body": "I'd like to take this issue.",
                    }
                ],
            )
            if "/comments" in url
            else (200, {}, {"state": "open", "assignee": None, "assignees": []})
        ),
        now=100.0,
    )
    assert result["settled"] == 1
    assert lane.handler_turn(forged_id)["status"] == "needs_reconcile"


def test_exhausted_recovery_requires_attempt_budget_not_a_forged_marker(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)
    with lane.writer() as db:
        row = db.execute(
            "SELECT payload_json FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
        payload = json.loads(row[0])
        payload["recoveryExhausted"] = True
        db.execute(
            "UPDATE event_lane_events SET attempts=0,payload_json=? WHERE event_id=?",
            (json.dumps(payload), recovery_id),
        )
    evidence = {
        "kind": "external_claim_comment",
        "repo": "agentscope-ai/agentscope",
        "number": "1",
        "issueState": "open",
        "commentId": "17",
        "author": "other",
        "createdAt": "2026-09-01T00:00:00Z",
        "claimKind": "active_claim",
        "excerpt": "I will take this issue.",
    }
    assert (
        lane.settle_exhausted_recovery_no_action(
            recovery_id,
            root_event_id=root_id,
            event_key="agentscope-ai/agentscope#1",
            reason="external_claim_comment",
            evidence=evidence,
        )["status"]
        == "not_eligible"
    )


def test_exhausted_recovery_accepts_completed_turn_with_invalid_outcome(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)
    with lane.writer() as db:
        for event_id in (root_id, recovery_id):
            row = db.execute(
                "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (event_id,)
            ).fetchone()
            receipt = json.loads(row[0])
            receipt["turnStatus"] = "completed"
            receipt["outcome"] = {"error": "OUTCOME_MISSING_OR_INVALID"}
            db.execute(
                "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
                (json.dumps(receipt), event_id),
            )
    result = worker._settle_exhausted_outcome_recoveries(
        tmp_path,
        lane,
        transport=lambda url, _headers: (
            (
                200,
                {},
                [
                    {
                        "id": 17,
                        "user": {"login": "other"},
                        "created_at": "2026-09-02T00:00:00Z",
                        "body": "I will take this issue.",
                    }
                ],
            )
            if "/comments" in url
            else (200, {}, {"state": "open", "assignee": None, "assignees": []})
        ),
        now=100.0,
    )
    assert result["settled"] == 1


def test_exhausted_recovery_rejects_valid_machine_outcome(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)
    key = "agentscope-ai/agentscope#1"
    with lane.writer() as db:
        for event_id in (root_id, recovery_id):
            row = db.execute(
                "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (event_id,)
            ).fetchone()
            receipt = json.loads(row[0])
            receipt["turnStatus"] = "completed"
            receipt["outcome"] = {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": event_id,
                "publicKey": key,
                "state": "no_action",
            }
            db.execute(
                "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
                (json.dumps(receipt), event_id),
            )
    evidence = {
        "kind": "external_claim_comment",
        "repo": "agentscope-ai/agentscope",
        "number": "1",
        "issueState": "open",
        "commentId": "17",
        "author": "other",
        "createdAt": "2026-09-01T00:00:00Z",
        "claimKind": "active_claim",
        "excerpt": "I will take this issue.",
    }
    assert (
        lane.settle_exhausted_recovery_no_action(
            recovery_id,
            root_event_id=root_id,
            event_key=key,
            reason="external_claim_comment",
            evidence=evidence,
        )["status"]
        == "terminal_receipt_missing"
    )


def test_exhausted_recovery_does_not_close_pr_watch_for_issue_claim(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    key = "agentscope-ai/agentscope#2463"
    root_id = "github:agentscope-ai/agentscope:2463:pr_update:2026-09-01T00:00:00Z"
    recovery_id = worker._outcome_recovery_event_id(root_id)
    lane.append(
        {
            "eventId": root_id,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 2463,
            "kind": "pr_update",
            "updatedAt": "2026-09-01T00:00:00Z",
        }
    )
    lane.append(
        {
            "eventId": recovery_id,
            "eventKey": key,
            "kind": "outcome_reconcile",
            "rootEventId": root_id,
            "eventIdSource": root_id,
            "payload": {
                "eventId": root_id,
                "rootEventId": root_id,
                "publicKey": key,
            },
        },
        priority=250,
    )
    for event_id in (root_id, recovery_id):
        lane.reserve_handler_turn(key, event_id, f"client:{event_id}")
        lane.bind_handler_turn(
            key,
            event_id,
            "thread-1",
            f"turn-{event_id}",
            {"turnStatus": "failed", "turnStarted": True},
            status="needs_reconcile",
        )
        with lane.writer() as db:
            db.execute(
                "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
                (event_id,),
            )
    lane.register_public_work(key, status="active", source="outcome-invalid")
    result = worker._settle_exhausted_outcome_recoveries(
        tmp_path,
        lane,
        transport=lambda url, _headers: (
            (
                200,
                {},
                [
                    {
                        "id": 17,
                        "user": {"login": "other"},
                        "created_at": "2026-09-02T00:00:00Z",
                        "body": "I'd like to take this issue.",
                    }
                ],
            )
            if "/comments" in url
            else (200, {}, {"state": "open", "assignee": None, "assignees": []})
        ),
        now=100.0,
    )
    assert result["settled"] == 0
    assert lane.public_status(key) == "active"


def test_exhausted_recovery_preserves_newer_public_work(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    root_id, recovery_id = _make_exhausted_outcome_chain(worker, lane)
    key = "agentscope-ai/agentscope#1"
    newer_id = "newer-turn"
    lane.append(
        {
            "eventId": newer_id,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    lane.reserve_handler_turn(key, newer_id, "client:newer")
    lane.bind_handler_turn(
        key,
        newer_id,
        "thread-newer",
        "turn-newer",
        {"turnStatus": "failed"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_turns SET created_at=9999999999 WHERE event_id=?", (newer_id,)
        )

    result = worker._settle_exhausted_outcome_recoveries(
        tmp_path,
        lane,
        transport=lambda url, _headers: (
            (
                200,
                {},
                [
                    {
                        "id": 17,
                        "user": {"login": "other"},
                        "created_at": "2026-09-01T00:00:00Z",
                        "body": "I'd like to take this issue.",
                    }
                ],
            )
            if "/comments" in url
            else (200, {}, {"state": "open", "assignee": None, "assignees": []})
        ),
        now=100.0,
    )
    assert result["settled"] == 1
    with lane.connect() as db:
        public = db.execute(
            "SELECT status,source FROM event_lane_public_work WHERE event_key=?", (key,)
        ).fetchone()
    assert dict(public) == {"status": "active", "source": "outcome-invalid"}


def test_exhausted_recovery_evidence_audit_is_rate_limited(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    _make_exhausted_outcome_chain(worker, lane)
    calls = []

    def transport(url, _headers):
        calls.append(url)
        if "/comments" in url:
            return 200, {}, [{"id": 1, "user": {"login": "reviewer"}, "body": "Thanks"}]
        return 200, {}, {"state": "open", "assignee": None, "assignees": []}

    first = worker._settle_exhausted_outcome_recoveries(
        tmp_path, lane, transport=transport, now=100.0
    )
    second = worker._settle_exhausted_outcome_recoveries(
        tmp_path, lane, transport=transport, now=101.0
    )
    assert first["skipped"] == 1 and second["skipped"] == 1
    assert len(calls) == 2


def test_external_claim_evidence_ignores_bots_and_old_comments():
    worker = _event_worker_module()
    root = {"kind": "issue_update", "updatedAt": "2026-09-01T12:00:00Z"}
    comments = [
        {
            "id": 1,
            "user": {"login": "helper", "type": "Bot"},
            "created_at": "2026-09-02T00:00:00Z",
            "body": "I will take this issue.",
        },
        {
            "id": 2,
            "user": {"login": "other"},
            "created_at": "2026-09-01T11:00:00Z",
            "body": "I'd like to take this issue.",
        },
    ]
    assert (
        worker._external_no_action_evidence(
            {"state": "open", "number": 1}, comments, root_event=root
        )
        is None
    )
    comments.append(
        {
            "id": 3,
            "user": {"login": "other"},
            "created_at": "2026-09-01T13:00:00Z",
            "body": "I'd like to take this issue if nobody else is working on it.",
        }
    )
    evidence = worker._external_no_action_evidence(
        {"state": "open", "number": 1}, comments, root_event=root
    )
    assert evidence and evidence["claimKind"] == "conditional_claim"
    comments.insert(
        0,
        {
            "id": 4,
            "user": {"login": "decliner"},
            "created_at": "2026-09-01T14:00:00Z",
            "body": "I will not take this issue.",
        },
    )
    evidence = worker._external_no_action_evidence(
        {"state": "open", "number": 1}, comments, root_event=root
    )
    assert evidence and evidence["commentId"] == "3"


def test_delivered_recovery_turn_timeout_returns_to_bounded_retry(tmp_path):
    lane = EventLane(tmp_path / "events.db", turn_timeout_seconds=10)
    event = {
        "eventId": "outcome-reconcile:agentscope:timeout",
        "eventKey": "agentscope-ai/agentscope#1",
        "kind": "outcome_reconcile",
        "payload": {"eventId": "root", "publicKey": "agentscope-ai/agentscope#1"},
    }
    lane.append(event)
    claimed = lane.claim(now=0)[0]
    lane.reserve_handler_turn(event["eventKey"], event["eventId"], "client:timeout")
    lane.bind_handler_turn(
        event["eventKey"],
        event["eventId"],
        "thread-1",
        "turn-1",
        {"turnStarted": True},
        status="started",
    )
    assert lane.ack(event["eventId"], lease_token=claimed["leaseToken"])
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id=?", (event["eventId"],))
    assert lane.expire_handler_turns(now=11) == 1
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts FROM event_lane_events WHERE event_id=?", (event["eventId"],)
        ).fetchone()
    assert dict(row) == {"status": "pending", "attempts": 1}


def test_foreign_pr_is_not_an_event_source_and_closed_issue_is_noop(tmp_path):
    worker = _event_worker_module()
    foreign = _issue(77, "2026-08-23T00:00:00Z", pr=True) | {
        "state": "open",
        "user": {"login": "another-contributor"},
        "comments": 99,
        "mergeable_state": "blocked",
    }
    own_closed = _issue(78, "2026-08-23T00:00:00Z", pr=True) | {
        "state": "closed",
        "user": {"login": "Oxygen56"},
    }
    assert worker.GitHubIssuePoller._is_relevant(foreign) is False
    assert worker.GitHubIssuePoller._is_relevant(own_closed) is True
    lane = EventLane(tmp_path / "events.db")
    called = []
    worker.run_bridge = lambda *_args, **_kwargs: called.append(True)
    worker.issue_handler_delivery(
        tmp_path,
        lane,
        {
            "eventId": "closed-ordinary",
            "repo": "agentscope-ai/agentscope",
            "number": 79,
            "issue": {
                "number": 79,
                "state": "closed",
                "html_url": "https://github.com/agentscope-ai/agentscope/issues/79",
            },
        },
    )
    assert called == []


def test_outcome_reconcile_with_foreign_public_key_is_quarantined(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "foreign-outcome",
        "kind": "outcome_reconcile",
        "eventKey": "other/project#1",
        "payload": {"publicKey": "other/project#1"},
    }
    lane.append(event)
    worker.issue_handler_delivery(tmp_path, lane, event)
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id='foreign-outcome'"
        ).fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["payload_json"])["terminalReason"] == "foreign_repository_event"
