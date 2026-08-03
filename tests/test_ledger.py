from datetime import UTC, datetime, timedelta

import pytest

from oss_pr_radar.ledger import LedgerError, RadarLedger
from oss_pr_radar.metrics import QUALITY_FIELDS, assess_submit_ready, rolling_quality
from oss_pr_radar.util import iso_z


def intent(**updates):
    now = datetime.now(UTC)
    value = {
        "intentId": "intent-1",
        "key": "a/b#1",
        "repo": "a/b",
        "issueNumber": 1,
        "issueUrl": "https://github.com/a/b/issues/1",
        "title": "Bug",
        "mode": "canary",
        "score": 9,
        "snapshotId": "snapshot",
        "decisionDigest": "decision",
        "issuedAt": iso_z(now),
        "expiresAt": iso_z(now + timedelta(hours=1)),
    }
    value.update(updates)
    return value


def test_lease_is_exclusive_and_commit_is_idempotent(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    assert store.enqueue(intent()) is True
    assert store.enqueue(intent()) is False
    assert store.claim("intent-1", "worker-a")
    assert store.claim("intent-1", "worker-b") is None
    store.commit_dispatch(
        "intent-1",
        owner="worker-a",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree",
    )
    store.commit_dispatch(
        "intent-1",
        owner="worker-a",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree",
    )


def test_canary_wip_limit_is_transactional_and_released_by_outcome(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.enqueue(
        intent(
            intentId="intent-2",
            key="a/b#2",
            issueNumber=2,
            issueUrl="https://github.com/a/b/issues/2",
        )
    )
    assert store.claim("intent-1", "worker-a", max_active=1)
    assert store.claim("intent-2", "worker-b", max_active=1) is None
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    assert store.claim("intent-2", "worker-b", max_active=1)


def test_enqueue_starts_submit_ready_denominator(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    store = RadarLedger(path)
    store.enqueue(intent())
    metrics = rolling_quality(path)
    assert metrics["selected"] == 1
    assert metrics["submitReady"] == 0


def test_same_issue_cannot_create_a_second_live_task(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    assert store.enqueue(intent()) is True
    assert store.enqueue(intent(intentId="intent-2", decisionDigest="new")) is False


def test_expired_pending_intent_does_not_block_a_fresh_snapshot(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent(expiresAt="2020-01-01T00:00:00Z"))
    assert store.enqueue(intent(intentId="intent-2", decisionDigest="new")) is True


def test_title_state_advances_from_go_to_fix_ready(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-04 05:25",
    )
    assert store.title_candidates() == []
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    candidate = store.title_candidates()[0]
    assert candidate["titleState"] == "FIX_READY"
    store.commit_title(
        thread_id="thread-1",
        state="FIX_READY",
        nonce=candidate["titleNonce"],
    )
    assert store.title_candidates() == []


def test_only_audit_no_go_threads_are_cleanup_candidates(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree",
    )
    assert store.cleanup_candidates() == []


def test_stalled_dispatch_gets_one_write_ahead_recovery(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
    )
    old = iso_z(datetime.now(UTC) - timedelta(hours=3))
    with store.connect() as connection:
        connection.execute(
            "UPDATE events SET created_at=? WHERE event_type='DISPATCHED'",
            (old,),
        )

    candidate = store.recovery_candidates(min_age_minutes=90)[0]
    assert candidate["threadId"] == "thread-1"
    store.reserve_recovery(
        thread_id="thread-1", nonce=candidate["recoveryNonce"]
    )
    assert store.recovery_candidates(min_age_minutes=90) == []
    assert store.unresolved_recoveries()[0]["threadId"] == "thread-1"

    store.commit_recovery(
        thread_id="thread-1", nonce=candidate["recoveryNonce"]
    )
    assert store.unresolved_recoveries() == []
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="DUPLICATE")
    candidate = store.cleanup_candidates()[0]
    assert candidate["threadId"] == "thread-1"
    store.commit_cleanup(
        thread_id="thread-1", nonce=candidate["cleanupNonce"]
    )
    assert store.cleanup_candidates() == []


def test_expired_intent_cannot_be_claimed(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent(expiresAt="2020-01-01T00:00:00Z"))
    assert store.claim("intent-1", "worker") is None


def test_submit_ready_requires_every_quality_gate(tmp_path):
    evidence = {field: True for field in QUALITY_FIELDS}
    assert assess_submit_ready(evidence).ready is True
    evidence["regression_test_verified"] = False
    assert assess_submit_ready(evidence).missing == ("regression_test_verified",)

    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.record_stage("a/b#1", "QUALIFIED", evidence={})
    store.record_stage("a/b#1", "FIX_READY", evidence={field: True for field in QUALITY_FIELDS})
    metrics = rolling_quality(tmp_path / "ledger.sqlite3")
    assert metrics["submitReadyRate"] == 1.0


def test_commit_without_lease_is_rejected(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    with pytest.raises(LedgerError):
        store.commit_dispatch(
            "intent-1",
            owner="worker",
            thread_id="thread",
            project_id="github",
            worktree_path="/tmp/worktree",
        )
