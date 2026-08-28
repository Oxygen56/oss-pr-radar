from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
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
    value = {
        "schemaVersion": "oss-pr-radar-event-lane-v1",
        "repositories": {
            "agentscope-ai/agentscope": {
                "activeThreadId": CENTRAL_THREAD,
                "cwd": "/Users/oxygen/Documents/github/agentscope",
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
    assert not worker._is_operational_authorization_gap(
        {"ok": False, "error": allowed_error}
    )
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
        _authorization_bridge_error(
            "agentscope-event-create", planned[0], turnStarted=False
        )
    )
    assert not worker._is_operational_authorization_gap(
        RuntimeError(
            f"agentscope-event-create: operational authorization required: {planned[0]}"
        )
    )


def _issue(number: int, updated: str, *, pr: bool = False) -> dict:
    value = {"number": number, "updated_at": updated, "title": f"item {number}", "labels": [{"name": "bug"}]}
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
            return 200, {}, [_issue(1, "2026-08-22T00:00:00Z"), _issue(2, "2026-08-22T00:01:00Z"), _issue(3, "2026-08-22T00:02:00Z")]
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
    result = lane.import_queue({
        "intents": [{"intentId": "i1", "threadId": "t1"}],
        "prFollowups": [{"taskId": "i1", "kind": "review"}],
        "slowWorkRequests": [{"taskId": "i2"}],
    }, wake=wakes.append)
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
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#1", "auth-gap", "client:auth-gap"
    )

    assert lane.defer_prestart_authorization_gap(
        "auth-gap", lease_token="wrong-token", owner="worker-a"
    ) is False
    assert lane.defer_prestart_authorization_gap(
        "auth-gap", lease_token=claimed["leaseToken"], owner="worker-a"
    ) is True

    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,lease_token FROM event_lane_events "
            "WHERE event_id='auth-gap'"
        ).fetchone()
    assert dict(row) == {"status": "pending", "attempts": 0, "lease_token": None}
    assert lane.handler_turn("auth-gap") is None

    lane.append({"eventId": "zero-attempt", "eventKey": "agentscope-ai/agentscope#2"})
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#2", "zero-attempt", "client:zero-attempt"
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='leased',lease_owner='worker-a',"
            "lease_token='zero-token' WHERE event_id='zero-attempt'"
        )
    assert lane.defer_prestart_authorization_gap(
        "zero-attempt", lease_token="zero-token", owner="worker-a"
    ) is False
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
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#3", "started-turn", "client:started-turn"
    )
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#3",
        "started-turn",
        "thread-started",
        "turn-started",
        {"turnStarted": True},
    )
    assert lane.defer_prestart_authorization_gap(
        "started-turn", lease_token=started["leaseToken"], owner="worker-a"
    ) is False
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
            "SELECT event_id,status FROM event_lane_turns "
            "WHERE status IN ('reserved','started')"
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
    assert [dict(turn) for turn in turns] == [
        {"event_id": reserved_event, "status": "reserved"}
    ]
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
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#1", "resettable", "client:old"
    )
    assert lane.release_handler_reservation(
        "resettable", {"error": "pre-turn"}, reason="pre-turn"
    )

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
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#99", "active", "client:active"
    )
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
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#1", "empty-reconcile", "client:old"
    )
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
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#2", "remote-reconcile", "client:remote"
    )
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


def test_github_identity_ignores_metadata_drift_and_tracks_material_revisions(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    details = {
        "pull": {"head": {"sha": "sha-1"}, "state": "open", "draft": False, "updated_at": "2026-08-24T00:00:00Z", "mergeable_state": "clean"},
        "reviews": [{"id": 1, "state": "COMMENTED", "submitted_at": "2026-08-24T00:00:00Z", "commit_id": "sha-1", "body": "review"}],
        "comments": [{"id": 2, "created_at": "2026-08-24T00:00:00Z", "updated_at": "2026-08-24T00:00:00Z", "body": "comment", "user": {"login": "reviewer"}}],
        "checks": {"check_runs": [{"id": 3, "name": "ci", "head_sha": "sha-1", "status": "queued", "conclusion": None, "started_at": "2026-08-24T00:00:00Z", "completed_at": None, "app": {"slug": "github-actions", "owner": {"followers": 1}}}]},
    }
    first = _github_event(2397, "2026-08-24T00:00:00Z") | {
        "eventId": "github:agentscope-ai/agentscope:2397:pr_update:legacy-a",
        "prDetails": details,
    }
    metadata_drift = first | {
        "eventId": "github:agentscope-ai/agentscope:2397:pr_update:legacy-b",
        "prDetails": {**details, "checks": {"check_runs": [{**details["checks"]["check_runs"][0], "app": {"slug": "github-actions", "owner": {"followers": 999}, "permissions": {"checks": "write"}}}]}},
    }
    material_change = first | {
        "eventId": "github:agentscope-ai/agentscope:2397:pr_update:legacy-c",
        "prDetails": {**details, "checks": {"check_runs": [{**details["checks"]["check_runs"][0], "status": "completed", "conclusion": "success"}]}},
    }
    changed = _github_event(2397, "2026-08-24T00:01:00Z")
    changed["prDetails"] = details
    assert lane.append(first) is True
    assert lane.append(metadata_drift) is False
    assert lane.append(material_change) is True
    assert lane.append(changed) is True
    seen = []
    assert dispatch_once(lane, seen.append, limit=3)["delivered"] == 3
    assert [event["eventId"] for event in seen] == [first["eventId"], material_change["eventId"], changed["eventId"]]


def test_plain_issue_has_no_material_suffix_and_stable_legacy_identity():
    event = _github_event(2398, "2026-08-24T00:00:00Z")
    event["eventId"] = _github_event_id(event)
    assert event["eventId"] == "github:agentscope-ai/agentscope:2398:issue_update:2026-08-24T00:00:00Z"
    assert _github_event_identity(event) == (
        "agentscope-ai/agentscope", "2398", "issue_update", "2026-08-24T00:00:00Z", ""
    )


def test_active_pull_events_use_canonical_material_projection(tmp_path):
    poller = GitHubIssuePoller(tmp_path / "poll.json", transport=lambda _url, _headers: (200, {}, []))
    details = {
        "pull": {"head": {"sha": "sha-1", "ref": "feature", "user": {"login": "Oxygen56", "repo": {"stargazers_count": 1}}}, "state": "open", "draft": False, "updated_at": "2026-08-24T00:00:00Z", "mergeable_state": "clean"},
        "reviews": [{"id": 1, "state": "COMMENTED", "submitted_at": "2026-08-24T00:00:00Z", "commit_id": "sha-1", "body": "review"}],
        "comments": [{"id": 2, "created_at": "2026-08-24T00:00:00Z", "updated_at": "2026-08-24T00:00:00Z", "body": "comment", "user": {"login": "reviewer"}}],
        "checks": {"check_runs": [{"id": 3, "name": "ci", "head_sha": "sha-1", "status": "queued", "conclusion": None, "started_at": "2026-08-24T00:00:00Z", "completed_at": None, "app": {"slug": "github-actions", "owner": {"permissions": {"checks": "write"}, "stargazers_count": 1}}}]},
    }
    poller._enrich_pull_request = lambda item, _state: item

    def item(value, updated="2026-08-24T00:00:00Z"):
        return {"number": 2397, "updated_at": updated, "title": "implementation", "state": "open", "user": {"login": "Oxygen56"}, "pull_request": {"url": "https://example.test/pr"}, "agentscopeDetails": value}

    baseline = poller._active_pull_events([item(details)], {})[0]["eventId"]
    metadata = copy.deepcopy(details)
    metadata["pull"]["head"]["repo"] = {"stargazers_count": 999, "owner": {"permissions": {"admin": True}}}
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
    assert poller._active_pull_events([item(details, "2026-08-24T00:01:00Z")], {})[0]["eventId"] != baseline


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
    monkeypatch.setattr(worker, "production_queue_snapshot", lambda _root: {
        "prFollowups": [{"taskId": "task-1", "key": "agentscope-ai/agentscope#9"}],
    })
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


def test_queue_identity_is_stable_and_legacy_rows_retire_once(tmp_path):
    lane = EventLane(tmp_path / "events.db")
    first = {"intents": [{"intentId": "intent-2413", "key": "agentscope-ai/agentscope#2413", "title": "old"}]}
    changed = {"intents": [{"intentId": "intent-2413", "key": "agentscope-ai/agentscope#2413", "title": "new", "status": "CREATING"}]}
    assert lane.import_queue(first)["imported"] == 1
    assert lane.import_queue(changed)["imported"] == 0
    lane.append({
        "eventId": "queue:legacy-payload-digest",
        "kind": "intents",
        "taskId": "legacy",
        "payload": {"intentId": "legacy", "title": "mutable"},
    })
    assert lane.retire_queue_events(now=10) == 2
    assert lane.retire_queue_events(now=11) == 0
    with lane.connect() as db:
        rows = list(db.execute("SELECT status,payload_json FROM event_lane_events"))
    assert {row["status"] for row in rows} == {"coalesced"}
    assert all(json.loads(row["payload_json"])["terminalReason"] == "retired_shared_queue_mirror" for row in rows)


def test_concurrent_legacy_queue_event_is_coalesced_before_dispatch_ack(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "events.db")
    event = {"eventId": "queue:late", "kind": "prFollowups", "taskId": "late", "payload": {"status": "CREATING"}}
    lane.append(event)
    result = dispatch_once(lane, lambda item: worker.bridge_delivery(tmp_path, lane, item), limit=1)
    assert result["delivered"] == 0
    with lane.connect() as db:
        row = db.execute("SELECT status,payload_json FROM event_lane_events WHERE event_id='queue:late'").fetchone()
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
        "issue": {"number": number, "updated_at": updated, "state": "open", "labels": [{"name": "bug"}]},
    }


def test_bootstrap_suppresses_stale_catchup_without_wake_or_pending(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:49:07Z"
    _write_bootstrap_seed(tmp_path, boundary)
    stale = _github_event(2364, "2026-08-22T17:08:35Z")
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: type("Poll", (), {
        "events": (stale,), "status": "ok"
    })())
    delivered = []
    result = worker.run_once(tmp_path, deliver=delivered.append)
    assert result["eventsInserted"] == 0
    assert result["codexWake"] is False
    assert result["drain"]["pending"] == 0
    assert delivered == []
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    with lane.connect() as db:
        assert db.execute("SELECT status FROM event_lane_events WHERE event_id=?", (stale["eventId"],)).fetchone()[0] == "baseline"


def test_bootstrap_terminalizes_existing_leased_stale_event(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:49:07Z"
    _write_bootstrap_seed(tmp_path, boundary)
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    stale = _github_event(2364, "2026-08-22T17:08:35Z")
    lane.append(stale, now=1)
    assert lane.claim(owner="old-listener", now=1)
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: type("Poll", (), {
        "events": (), "status": "not_modified"
    })())
    result = worker.run_once(tmp_path, deliver=lambda _event: (_ for _ in ()).throw(AssertionError("stale event delivered")))
    assert result["bootstrapApplied"] is True
    assert result["bootstrapTerminalized"] == 1
    assert result["drain"]["pending"] == 0
    with lane.connect() as db:
        assert db.execute("SELECT status FROM event_lane_events WHERE event_id=?", (stale["eventId"],)).fetchone()[0] == "baseline"


def test_post_bootstrap_event_dispatches_once(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:49:07Z"
    _write_bootstrap_seed(tmp_path, boundary)
    fresh = _github_event(2400, "2026-08-23T12:49:08Z")
    polls = iter([type("Poll", (), {"events": (fresh,), "status": "ok"})(),
                  type("Poll", (), {"events": (), "status": "not_modified"})()])
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: next(polls))
    delivered = []
    first = worker.run_once(tmp_path, deliver=delivered.append)
    second = worker.run_once(tmp_path, deliver=delivered.append)
    assert first["eventsInserted"] == 1 and first["drain"]["delivered"] == 1
    assert second["eventsInserted"] == 0 and second["codexWake"] is False
    assert [event["eventId"] for event in delivered] == [fresh["eventId"]]


def test_material_time_after_boundary_is_dispatchable_even_with_old_issue_updated_at(tmp_path, monkeypatch):
    worker = _event_worker_module()
    boundary = "2026-08-23T12:00:00Z"
    _write_bootstrap_seed(tmp_path, boundary)
    events = []
    for number, details in (
        (2501, {"reviews": [{"id": 1, "submitted_at": "2026-08-23T12:01:00Z"}]}),
        (2502, {"comments": [{"id": 2, "updated_at": "2026-08-23T12:02:00Z"}]}),
        (2503, {"checks": {"check_runs": [{"id": 3, "started_at": "2026-08-23T12:03:00Z", "completed_at": "2026-08-23T12:04:00Z"}]}}),
    ):
        event = _github_event(number, "2026-08-23T11:00:00Z")
        event["prDetails"] = details
        events.append(event)
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: type("Poll", (), {
        "events": tuple(events), "status": "ok"
    })())
    delivered = []
    result = worker.run_once(tmp_path, deliver=delivered.append)
    assert result["eventsInserted"] == 3
    assert result["drain"]["delivered"] == 3
    assert result["drain"]["pending"] == 0
    assert [event["eventId"] for event in delivered] == [event["eventId"] for event in events]


def test_production_worker_claims_only_one_central_turn_per_cycle(tmp_path, monkeypatch):
    worker = _event_worker_module()
    events = tuple(
        _github_event(number, f"2026-08-23T12:0{number}:00Z")
        for number in (1, 2, 3)
    )
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: type(
        "Poll", (), {"events": events, "status": "ok"}
    )())
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


def test_busy_central_task_does_not_spend_pending_attempts_across_cycles(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: type(
        "Poll", (), {"events": (), "status": "not_modified"}
    )())
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    lane.append({
        "eventId": "active-event",
        "eventKey": "agentscope-ai/agentscope#1",
        "kind": "issue_update",
    })
    lane.reserve_handler_turn(
        "agentscope-ai/agentscope#1", "active-event", "client:active"
    )
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#1",
        "active-event",
        CENTRAL_THREAD,
        "turn-active",
        {"turnStarted": True, "workerPid": os.getpid()},
        status="started",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id='active-event'"
        )
    lane.append({
        "eventId": "waiting-event",
        "eventKey": "agentscope-ai/agentscope#2",
        "kind": "issue_update",
    })
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
    stale["prDetails"] = {"checks": {"check_runs": [{"id": 4, "started_at": "2026-08-23T11:30:00Z", "completed_at": "2026-08-23T11:59:59Z"}]}}
    monkeypatch.setattr(worker.GitHubIssuePoller, "poll", lambda _self: type("Poll", (), {
        "events": (stale,), "status": "ok"
    })())
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
        "issue": {"state": "open", "html_url": "https://github.com/agentscope-ai/agentscope/issues/11"},
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
    lane.bind_handler_turn("agentscope-ai/agentscope#1", "stale-event", central, "turn-stale", {}, status="started")
    with lane.writer() as db:
        db.execute("UPDATE event_lane_turns SET created_at=0 WHERE event_id='stale-event'")
    assert lane.expire_handler_turns(now=11) == 1
    assert lane.active_handler_thread(central) is None
    with lane.connect() as db:
        row = db.execute("SELECT status,receipt_json FROM event_lane_turns WHERE event_id='stale-event'").fetchone()
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
        db.execute(
            "UPDATE event_lane_turns SET created_at=0 WHERE event_id='reserved-event'"
        )
    assert lane.expire_handler_turns(now=11) == 1
    with lane.connect() as db:
        event_row = db.execute(
            "SELECT status,payload_json FROM event_lane_events "
            "WHERE event_id='reserved-event'"
        ).fetchone()
        turn_row = db.execute(
            "SELECT status,receipt_json FROM event_lane_turns "
            "WHERE event_id='reserved-event'"
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
        "agentscope-ai/agentscope#2", "long-event", CENTRAL_THREAD, "turn-long",
        {"turnStarted": True, "workerPid": os.getpid()}, status="started"
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
    lane.bind_handler_turn("agentscope-ai/agentscope#1", "active-event", CENTRAL_THREAD, "turn-active", {}, status="started")
    event = {
        "eventId": "queued-behind-central", "repo": "agentscope-ai/agentscope", "number": 2,
        "issue": {"state": "open", "html_url": "https://github.com/agentscope-ai/agentscope/issues/2"},
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
    lane.bind_handler_turn("agentscope-ai/agentscope#1", "active-event", CENTRAL_THREAD, "turn-active", {}, status="needs_reconcile")
    monkeypatch.setattr(worker, "run_bridge", lambda *_args, **_kwargs: {
        "ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-next"
    })
    result = dispatch_once(lane, lambda item: worker.issue_handler_delivery(tmp_path, lane, item), limit=1)
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


def test_retryable_start_failure_releases_reservation_and_retries(
    tmp_path, monkeypatch
):
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
        assert db.execute(
            "SELECT attempts FROM event_lane_events WHERE event_id=?",
            (event["eventId"],),
        ).fetchone()[0] == 1

    second = dispatch_once(
        lane,
        lambda item: worker.issue_handler_delivery(tmp_path, lane, item),
        limit=1,
    )
    assert second["delivered"] == 1
    turn = lane.handler_turn(event["eventId"])
    assert turn["status"] == "started"
    assert turn["thread_id"] == CENTRAL_THREAD


def test_operational_authorization_gap_refunds_attempt_without_reconcile(
    tmp_path, monkeypatch
):
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
        assert db.execute(
            "SELECT count(*) FROM event_lane_events "
            "WHERE event_id LIKE 'outcome-reconcile:%'"
        ).fetchone()[0] == 0


def test_authorization_gap_refund_rejection_preserves_lease_and_reservation(
    tmp_path, monkeypatch
):
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
                "UPDATE event_lane_events SET lease_token='replacement-token' "
                "WHERE event_id=?",
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


def test_permanent_authorization_failure_keeps_retry_budget_semantics(
    tmp_path, monkeypatch
):
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
    (runtime_root / worker.EVENT_LANE_MANIFEST).write_text(json.dumps({"repositories": {}}), encoding="utf-8")
    lane = EventLane(runtime_root / "events.db")
    calls = []
    monkeypatch.setattr(worker, "run_bridge", lambda _root, _operation, **kwargs: (
        calls.append(kwargs) or {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-safe"}
    ))
    foreign = {
        "eventId": "foreign-event", "repo": "other/project", "number": 1,
        "issue": {"state": "open", "html_url": "https://github.com/other/project/issues/1"},
    }
    lane.append(foreign)
    worker.issue_handler_delivery(runtime_root, lane, foreign)
    assert calls == []
    with lane.connect() as db:
        row = db.execute("SELECT status,payload_json FROM event_lane_events WHERE event_id='foreign-event'").fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["payload_json"])["terminalReason"] == "foreign_repository_event"
    normal = {
        "eventId": "runtime-root-event", "repo": "agentscope-ai/agentscope", "number": 2,
        "issue": {"state": "open", "html_url": "https://github.com/agentscope-ai/agentscope/issues/2"},
    }
    lane.append(normal)
    claimed = lane.claim(limit=1)[0]
    worker.issue_handler_delivery(runtime_root, lane, claimed)
    extra = calls[-1]["extra_args"]
    assert extra[extra.index("--cwd") + 1] == "/Users/oxygen/Documents/github/agentscope"
    (release_root / worker.EVENT_LANE_MANIFEST).write_text("{}", encoding="utf-8")
    mutated = {
        "eventId": "mutated-release-manifest", "repo": "agentscope-ai/agentscope", "number": 3,
        "issue": {"state": "open", "html_url": "https://github.com/agentscope-ai/agentscope/issues/3"},
    }
    lane.append(mutated)
    worker.issue_handler_delivery(runtime_root, lane, mutated)
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id='mutated-release-manifest'"
        ).fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["payload_json"])["terminalReason"] == "event-lane manifest digest mismatch"


def test_pr_detail_failure_does_not_emit_shrunken_snapshot(tmp_path):
    item = {
        "number": 12, "updated_at": "2026-08-22T00:00:00Z", "title": "implementation",
        "state": "open", "user": {"login": "Oxygen56"},
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
    old_context.write_text(json.dumps({
        "threadId": "thread-2385", "key": "agentscope-ai/agentscope#2385",
        "prFollowup": {"prUrl": "https://github.com/agentscope-ai/agentscope/pull/2397"},
    }), encoding="utf-8")
    event = {
        "repo": "agentscope-ai/agentscope", "number": 2397, "kind": "pr_update",
        "issue": {"number": 2397, "pull_request": {"html_url": "https://github.com/agentscope-ai/agentscope/pull/2397"}},
    }
    assert not hasattr(worker, "RadarLedger")
    target = worker._resolve_event_target(tmp_path, event)
    assert target["kind"] == "pr_watch"
    assert target["key"] == "agentscope-ai/agentscope#2397"
    assert "threadId" not in target


def test_pr_event_wakes_central_thread_despite_old_binding(tmp_path, monkeypatch):
    worker = _event_worker_module()
    central = CENTRAL_THREAD
    _configure_manifest(worker, tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(worker, "run_bridge", lambda root, operation, **kwargs: (
        calls.append((root, operation, kwargs)) or {"ok": True, "threadId": central, "turnId": "turn-central"}
    ))
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "pr-central-wake", "repo": "agentscope-ai/agentscope", "number": 2397,
        "kind": "pr_update", "issue": {"state": "open", "pull_request": {
            "html_url": "https://github.com/agentscope-ai/agentscope/pull/2397"
        }},
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
    seed.write_text(json.dumps({"items": [{"key": "agentscope-ai/agentscope#2364", "status": "design_wait", "designWaitUntil": "2099-01-01T00:00:00Z"}]}))
    lane = EventLane(tmp_path / "state" / "events.db")
    assert worker._sync_public_work_seed(tmp_path, lane) == 1
    assert lane.public_status("agentscope-ai/agentscope#2364") == "design_wait"
    seed.write_text(json.dumps({"items": [{"key": "agentscope-ai/agentscope#2364", "status": "active"}]}))
    assert worker._sync_public_work_seed(tmp_path, lane) == 0
    lane.register_public_work("agentscope-ai/agentscope#2364", status="watch_only")
    assert lane.public_status("agentscope-ai/agentscope#2364") == "watch_only"


def test_invalid_outcome_creates_durable_recovery_event(tmp_path, monkeypatch):
    worker = _event_worker_module()
    central = CENTRAL_THREAD
    _configure_manifest(worker, tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(worker, "run_bridge", lambda root, operation, **kwargs: (
        calls.append((root, operation, kwargs)) or {"ok": True, "threadId": central, "turnId": "turn-recovery"}
    ))
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_id = "event-invalid"
    lane.append({"eventId": event_id, "repo": "agentscope-ai/agentscope", "number": 1})
    lane.reserve_handler_turn("agentscope-ai/agentscope#1", event_id, "client:event-invalid")
    lane.bind_handler_turn("agentscope-ai/agentscope#1", event_id, "thread-1", "turn-1", {}, status="started")
    receipt = tmp_path / "state" / "agentscope_event_receipts" / (hashlib.sha256(event_id.encode()).hexdigest() + ".json")
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({"ok": True, "turnStatus": "completed", "threadId": "thread-1", "turnId": "turn-1", "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"}}))
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
    lane.append({
        "eventId": root_event_id,
        "eventKey": event_key,
        "repo": "agentscope-ai/agentscope",
        "number": 2448,
        "kind": "issue_update",
        "terminalReason": "handler_start_exception",
    })
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 "
            "WHERE event_id=?",
            (root_event_id,),
        )
    for status in ("baseline", "watch_only", "coalesced", "pending", "leased"):
        ignored_id = f"ignored-{status}"
        lane.append({
            "eventId": ignored_id,
            "eventKey": f"agentscope-ai/agentscope#{len(status)}",
            "kind": "issue_update",
        })
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
    assert lane.append({
        "eventId": root_event_id,
        "eventKey": event_key,
        "repo": "agentscope-ai/agentscope",
        "number": 1,
        "kind": "issue_update",
    })
    assert lane.append({
        "eventId": legacy_id,
        "eventKey": event_key,
        "kind": "outcome_reconcile",
        "eventIdSource": root_event_id,
        "payload": {"eventId": root_event_id, "publicKey": event_key},
    })
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
    assert [(row["event_id"], row["attempts"]) for row in rows] == [
        (legacy_id, 2)
    ]


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
    assert lane.append({
        "eventId": root,
        "eventKey": key,
        "repo": "agentscope-ai/agentscope",
        "number": 1,
        "kind": "issue_update",
    })
    assert lane.append({
        "eventId": recovery_id,
        "eventKey": key,
        "kind": kind,
        "eventIdSource": root,
        "payload": {"eventId": root, "publicKey": key},
    })
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' "
            "WHERE event_id IN (?,?)",
            (root, recovery_id),
        )

    result = worker._enqueue_unresolved_outcome_recoveries(lane)

    assert result == {"candidates": 1, "inserted": 0, "existing": 1, "skipped": 0}
    with lane.connect() as db:
        assert db.execute(
            "SELECT count(*) FROM event_lane_events WHERE event_id=?",
            (worker._outcome_recovery_event_id(root),),
        ).fetchone()[0] == 0


def test_structurally_invalid_terminal_outcome_retries_recovery(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_key = "agentscope-ai/agentscope#1"
    root_event_id = "root-invalid-schema"
    recovery_id = worker._outcome_recovery_event_id(root_event_id)
    lane.append({
        "eventId": recovery_id,
        "kind": "outcome_reconcile",
        "eventKey": event_key,
        "rootEventId": root_event_id,
        "eventIdSource": root_event_id,
        "payload": {"eventId": root_event_id, "publicKey": event_key},
    }, priority=250)
    claimed = lane.claim(limit=1)[0]
    lane.reserve_handler_turn(event_key, recovery_id, "client:recovery")
    lane.bind_handler_turn(
        event_key, recovery_id, "thread-1", "turn-1", {}, status="started"
    )
    lane.ack(recovery_id, lease_token=claimed["leaseToken"])
    receipt = worker._event_artifact_path(
        tmp_path,
        worker.EVENT_RECEIPT_DIR,
        recovery_id,
        attempt=1,
        is_recovery=True,
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({
        "turnStatus": "completed",
        "outcome": {
            "eventId": recovery_id,
            "publicKey": event_key,
            "state": "no_action",
        },
    }))

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
    assert lane.append({
        "eventId": root_event_id,
        "eventKey": event_key,
        "kind": "issue_update",
    })
    assert lane.append({
        "eventId": legacy_recovery_id,
        "eventKey": event_key,
        "kind": "outcome_reconcile",
        "eventIdSource": root_event_id,
        "payload": {
            "eventId": root_event_id,
            "publicKey": event_key,
        },
    })
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root_event_id,),
        )

    assert worker._retry_or_exhaust_outcome_recovery(
        lane,
        event_id=legacy_recovery_id,
        root_event_id=root_event_id,
        outcome={"error": "invalid"},
    ) == "retry"
    with lane.connect() as db:
        payload = json.loads(db.execute(
            "SELECT payload_json FROM event_lane_events WHERE event_id=?",
            (legacy_recovery_id,),
        ).fetchone()[0])
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
    preview = recovery_migration.migrate_recovery_chains(
        database, namespace="agentscope"
    )
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["eventsToCoalesce"] == 1


@pytest.mark.parametrize("terminal", ["failed", "interrupted"])
def test_noncompleted_turn_cannot_publish_a_structurally_valid_outcome(
    tmp_path, terminal
):
    worker = _event_worker_module()
    lane = EventLane(tmp_path / "state" / "agentscope-events.sqlite3")
    event_id = f"root-{terminal}"
    event_key = "agentscope-ai/agentscope#1"
    lane.append({
        "eventId": event_id,
        "eventKey": event_key,
        "repo": "agentscope-ai/agentscope",
        "number": 1,
        "kind": "issue_update",
    })
    claimed = lane.claim(limit=1)[0]
    lane.reserve_handler_turn(event_key, event_id, f"client:{terminal}")
    lane.bind_handler_turn(
        event_key, event_id, "thread-1", f"turn-{terminal}", {}, status="started"
    )
    lane.ack(event_id, lease_token=claimed["leaseToken"])
    receipt = worker._event_artifact_path(
        tmp_path, worker.EVENT_RECEIPT_DIR, event_id
    )
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({
        "turnStatus": terminal,
        "outcome": {
            "schemaVersion": "agentscope_event_outcome_v1",
            "eventId": event_id,
            "publicKey": event_key,
            "state": "no_action",
        },
    }))

    assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
    assert lane.handler_turn(event_id)["status"] == "needs_reconcile"
    with lane.connect() as db:
        recovery_count = db.execute(
            "SELECT count(*) FROM event_lane_events "
            "WHERE event_id=?",
            (worker._outcome_recovery_event_id(event_id),),
        ).fetchone()[0]
    assert recovery_count == 1


def test_invalid_recovery_reuses_one_event_and_exhausts_existing_attempt_budget(tmp_path):
    worker = _event_worker_module()
    lane = EventLane(
        tmp_path / "state" / "agentscope-events.sqlite3",
        max_attempts=3,
    )
    event_key = "agentscope-ai/agentscope#1"
    root_event_id = "event-invalid-" + ("x" * 2048)
    lane.append({
        "eventId": root_event_id,
        "eventKey": event_key,
        "repo": "agentscope-ai/agentscope",
        "number": 1,
    })
    claimed = lane.claim(owner="event-lane")[0]
    lane.reserve_handler_turn(event_key, root_event_id, "client:root")
    lane.bind_handler_turn(
        event_key, root_event_id, "thread-1", "turn-root", {}, status="started"
    )
    assert lane.ack(
        root_event_id,
        lease_token=str(claimed["leaseToken"]),
        owner="event-lane",
    )
    receipt_dir = tmp_path / "state" / "agentscope_event_receipts"
    receipt_dir.mkdir(parents=True)
    invalid_outcome = {"error": "OUTCOME_MISSING_OR_INVALID"}
    root_receipt = receipt_dir / (
        hashlib.sha256(root_event_id.encode()).hexdigest() + ".json"
    )
    root_receipt.write_text(json.dumps({
        "ok": True,
        "turnStatus": "completed",
        "threadId": "thread-1",
        "turnId": "turn-root",
        "outcome": invalid_outcome,
    }))
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
        recovery_receipt.write_text(json.dumps({
            "ok": True,
            "turnStatus": "completed",
            "threadId": "thread-1",
            "turnId": f"turn-recovery-{attempt}",
            "outcome": invalid_outcome,
        }))
        assert worker.reconcile_detached_receipts(tmp_path, lane) == 1
        with lane.connect() as db:
            row = db.execute(
                "SELECT status,attempts,payload_json FROM event_lane_events "
                "WHERE event_id=?",
                (recovery_id,),
            ).fetchone()
            recovery_count = db.execute(
                "SELECT count(*) FROM event_lane_events "
                "WHERE event_id LIKE 'outcome-reconcile:%'"
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


def test_recovery_retry_uses_distinct_bridge_identity_and_evidence_paths(
    tmp_path, monkeypatch
):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(worker, "run_bridge", lambda _root, _operation, **kwargs: (
        calls.append(kwargs)
        or {"ok": True, "threadId": CENTRAL_THREAD, "turnId": "turn-recovery-2"}
    ))
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


def test_foreign_pr_is_not_an_event_source_and_closed_issue_is_noop(tmp_path):
    worker = _event_worker_module()
    foreign = _issue(77, "2026-08-23T00:00:00Z", pr=True) | {
        "state": "open", "user": {"login": "another-contributor"},
        "comments": 99, "mergeable_state": "blocked",
    }
    own_closed = _issue(78, "2026-08-23T00:00:00Z", pr=True) | {
        "state": "closed", "user": {"login": "Oxygen56"},
    }
    assert worker.GitHubIssuePoller._is_relevant(foreign) is False
    assert worker.GitHubIssuePoller._is_relevant(own_closed) is True
    lane = EventLane(tmp_path / "events.db")
    called = []
    worker.run_bridge = lambda *_args, **_kwargs: called.append(True)
    worker.issue_handler_delivery(tmp_path, lane, {
        "eventId": "closed-ordinary", "repo": "agentscope-ai/agentscope", "number": 79,
        "issue": {"number": 79, "state": "closed", "html_url": "https://github.com/agentscope-ai/agentscope/issues/79"},
    })
    assert called == []


def test_outcome_reconcile_with_foreign_public_key_is_quarantined(tmp_path, monkeypatch):
    worker = _event_worker_module()
    _configure_manifest(worker, tmp_path, monkeypatch)
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "foreign-outcome", "kind": "outcome_reconcile",
        "eventKey": "other/project#1", "payload": {"publicKey": "other/project#1"},
    }
    lane.append(event)
    worker.issue_handler_delivery(tmp_path, lane, event)
    with lane.connect() as db:
        row = db.execute("SELECT status,payload_json FROM event_lane_events WHERE event_id='foreign-outcome'").fetchone()
    assert row["status"] == "needs_reconcile"
    assert json.loads(row["payload_json"])["terminalReason"] == "foreign_repository_event"
