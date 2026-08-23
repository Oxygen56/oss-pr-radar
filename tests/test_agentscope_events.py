from __future__ import annotations

from datetime import UTC, datetime

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once


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
