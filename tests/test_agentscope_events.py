from __future__ import annotations

import importlib.util
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once


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
    assert first["queueImported"] == 1
    assert first["drain"]["delivered"] == 1
    assert second["queueImported"] == 0
    assert len(delivered) == 1


def test_unmapped_event_uses_explicit_independent_release_bridge(tmp_path, monkeypatch):
    worker = _event_worker_module()
    calls = []

    def fake_bridge(root, operation, **kwargs):
        calls.append((root, operation, kwargs))
        return {
            "ok": True,
            "threadId": "thread-new",
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
    worker.issue_handler_delivery(tmp_path, lane, event)
    assert calls[0][1] == "agentscope-event-create"
    assert calls[0][2]["inactive_release"] is True
    assert calls[0][2]["code_root"] == worker.ROOT
    assert lane.handler_thread("agentscope-ai/agentscope#10")["thread_id"] == "thread-new"


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
    delivered = []
    assert dispatch_once(lane, delivered.append, limit=1)["delivered"] == 1
    assert delivered[0]["kind"] == "outcome_reconcile"
