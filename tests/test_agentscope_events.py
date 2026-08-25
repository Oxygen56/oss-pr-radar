from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

from oss_pr_radar.agentscope_events import (
    EventLane,
    GitHubIssuePoller,
    _github_event_id,
    _github_event_identity,
    dispatch_once,
)


def _event_worker_module():
    path = Path(__file__).parents[1] / "scripts" / "agentscope_event_worker.py"
    spec = importlib.util.spec_from_file_location("agentscope_event_worker", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


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
                "threadId": "01a032a7-5288-70a0-9faf-0b1d1e8161f0",
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
    (tmp_path / worker.EVENT_LANE_MANIFEST).write_text(json.dumps({
        "schemaVersion": "oss-pr-radar-event-lane-v1",
        "repositories": {"agentscope-ai/agentscope": {
            "activeThreadId": "01a032a7-5288-70a0-9faf-0b1d1e8161f0"
        }},
    }), encoding="utf-8")
    worker.issue_handler_delivery(tmp_path, lane, event)
    assert calls[0][1] == "agentscope-event-create"
    assert calls[0][2]["inactive_release"] is True
    assert calls[0][2]["code_root"] == worker.ROOT
    extra = calls[0][2]["extra_args"]
    assert extra[extra.index("--thread-id") + 1] == "01a032a7-5288-70a0-9faf-0b1d1e8161f0"
    assert lane.handler_thread("agentscope-ai/agentscope#10")["thread_id"] == "01a032a7-5288-70a0-9faf-0b1d1e8161f0"
    assert all(operation != "drain-once" for _, operation, _ in calls)


def test_central_thread_receipt_mismatch_is_quarantined_without_success(tmp_path, monkeypatch):
    worker = _event_worker_module()
    manifest = {
        "schemaVersion": "oss-pr-radar-event-lane-v1",
        "repositories": {"agentscope-ai/agentscope": {
            "activeThreadId": "01a032a7-5288-70a0-9faf-0b1d1e8161f0"
        }},
    }
    (tmp_path / worker.EVENT_LANE_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(worker, "run_bridge", lambda *_args, **_kwargs: {
        "ok": True, "threadId": "issue-specific-thread", "turnId": "turn-1"
    })
    lane = EventLane(tmp_path / "events.db")
    event = {
        "eventId": "central-mismatch",
        "repo": "agentscope-ai/agentscope",
        "number": 11,
        "issue": {"state": "open", "html_url": "https://github.com/agentscope-ai/agentscope/issues/11"},
    }
    lane.append(event)
    lane.claim(now=0)
    worker.issue_handler_delivery(tmp_path, lane, event)
    with lane.connect() as db:
        row = db.execute("SELECT status,payload_json FROM event_lane_events WHERE event_id=?", ("central-mismatch",)).fetchone()
    assert row["status"] == "needs_reconcile"
    assert "central_task_thread_receipt_mismatch" in row["payload_json"]
    assert lane.handler_thread("agentscope-ai/agentscope#11") is None


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


def test_pr_number_maps_to_underlying_opportunity_even_when_followup_not_required(tmp_path, monkeypatch):
    worker = _event_worker_module()

    class FakeDb:
        def execute(self, _query, _params):
            class Rows:
                def fetchall(self):
                    return [{"key": "agentscope-ai/agentscope#2385", "pr_url": "https://github.com/agentscope-ai/agentscope/pull/2397", "thread_id": "thread-2385"}]

            return Rows()

    class FakeStore:
        def __init__(self, _path):
            pass

        def pr_followup_candidates(self):
            return []

        def unresolved_pr_followups(self):
            return []

        def connect(self):
            class Context:
                def __enter__(self):
                    return FakeDb()

                def __exit__(self, *_args):
                    return False

            return Context()

    monkeypatch.setattr(worker, "RadarLedger", FakeStore)
    target = worker._resolve_event_target(tmp_path, {
        "repo": "agentscope-ai/agentscope", "number": 2397, "kind": "pr_update",
        "issue": {"number": 2397, "pull_request": {"html_url": "https://github.com/agentscope-ai/agentscope/pull/2397"}},
    })
    assert target["kind"] == "pr_followup"
    assert target["key"] == "agentscope-ai/agentscope#2385"
    assert target["threadId"] == "thread-2385"


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


def test_invalid_outcome_creates_durable_recovery_event(tmp_path):
    worker = _event_worker_module()
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
        row = db.execute("SELECT payload_json FROM event_lane_events WHERE event_id LIKE 'outcome-reconcile:%'").fetchone()
    assert json.loads(row["payload_json"])["kind"] == "outcome_reconcile"
    recovery_event = {
        "eventId": "outcome-reconcile:event-invalid",
        "eventKey": "agentscope-ai/agentscope#1",
        "kind": "outcome_reconcile",
    }
    lane.append(recovery_event)
    worker.issue_handler_delivery(tmp_path, lane, recovery_event)
    assert (tmp_path / "state" / "agentscope-event-handoffs.jsonl").exists()
    with lane.connect() as db:
        status = db.execute(
            "SELECT status FROM event_lane_events WHERE event_id=?",
            ("outcome-reconcile:event-invalid",),
        ).fetchone()["status"]
    assert status == "needs_reconcile"


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
