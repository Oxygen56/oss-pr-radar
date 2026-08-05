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
    assert store.claim("intent-1", "worker-a") is None
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


def test_same_signed_intent_renews_pending_expiry(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    initial = intent(expiresAt=iso_z(datetime.now(UTC) + timedelta(minutes=5)))
    renewed_expiry = iso_z(datetime.now(UTC) + timedelta(hours=2))
    assert store.enqueue(initial) is True

    assert store.enqueue(intent(expiresAt=renewed_expiry)) is False

    pending = store.pending()
    assert len(pending) == 1
    assert pending[0]["expiresAt"] == renewed_expiry


def test_same_signed_intent_reopens_an_expired_lease(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "old-controller")
    with store.connect() as connection:
        connection.execute(
            """UPDATE intents SET expires_at=?,lease_until=?
               WHERE intent_id='intent-1'""",
            (
                iso_z(datetime.now(UTC) - timedelta(minutes=2)),
                iso_z(datetime.now(UTC) - timedelta(minutes=1)),
            ),
        )

    renewed_expiry = iso_z(datetime.now(UTC) + timedelta(hours=2))
    assert store.enqueue(intent(expiresAt=renewed_expiry)) is False

    pending = store.pending()
    assert len(pending) == 1
    assert pending[0]["ledgerStatus"] == "PENDING"
    assert pending[0]["expiresAt"] == renewed_expiry


def test_latest_signed_queue_supersedes_withdrawn_uncommitted_intent(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "old-controller")

    assert store.reconcile_pending(set()) == ["intent-1"]
    assert store.pending() == []
    with pytest.raises(LedgerError, match="not leased"):
        store.commit_dispatch(
            "intent-1",
            owner="old-controller",
            thread_id="thread-1",
            project_id="repo-project",
            worktree_path="/tmp/worktree",
        )
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


def test_no_go_requires_title_sync_before_cleanup(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-04 18:47",
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="STRONG_EXISTING_PR")

    assert store.cleanup_candidates() == []
    candidate = store.title_candidates()[0]
    assert candidate["titleState"] == "AUDIT_NO_GO"
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=candidate["titleNonce"],
    )
    assert store.title_candidates() == []
    assert store.cleanup_candidates()[0]["threadId"] == "thread-1"


def test_no_go_revokes_task_context_publication_authorization(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            autoSubmitAuthorized=True,
            publicSubmissionAllowed=True,
            authorizationSource="signed_live_revalidation_required",
            publicationMode="canary",
        )
    )
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
    )

    authorized = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert authorized is not None
    assert authorized["autoSubmitAuthorized"] is True
    assert authorized["publicSubmissionAllowed"] is True

    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="POLICY_BLOCKED")
    revoked = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert revoked is not None
    assert revoked["intentStatus"] == "REJECTED"
    assert revoked["autoSubmitAuthorized"] is False
    assert revoked["publicSubmissionAllowed"] is False
    assert revoked["authorizationSource"] == "revoked_terminal_no_go"


def test_same_no_go_decision_is_not_requeued_until_evidence_changes(tmp_path):
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
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="MAINTAINER_APPROVAL_REQUIRED")

    assert store.enqueue(intent(intentId="intent-2")) is False
    assert store.enqueue(intent(intentId="intent-3", decisionDigest="new-decision")) is True


def test_orphan_dispatch_can_reconcile_an_expired_async_handoff(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    candidate = store.orphaned_handoffs()[0]
    with store.connect() as connection:
        connection.execute("UPDATE intents SET status='EXPIRED' WHERE intent_id='intent-1'")

    store.commit_orphan_dispatch(
        "intent-1",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-04 18:47",
        lease_started_at=candidate["leaseStartedAt"],
    )
    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context is not None
    assert context["intentStatus"] == "DISPATCHED"


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
    store.reserve_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])
    assert store.recovery_candidates(min_age_minutes=90) == []
    assert store.unresolved_recoveries()[0]["threadId"] == "thread-1"

    store.commit_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])
    assert store.unresolved_recoveries() == []
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="DUPLICATE")
    title_candidate = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=title_candidate["titleNonce"],
    )
    candidate = store.cleanup_candidates()[0]
    assert candidate["threadId"] == "thread-1"
    store.commit_cleanup(thread_id="thread-1", nonce=candidate["cleanupNonce"])
    assert store.cleanup_candidates() == []


def test_expired_intent_cannot_be_claimed(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent(expiresAt="2020-01-01T00:00:00Z"))
    assert store.claim("intent-1", "worker") is None


def test_pending_intent_alerts_after_one_controller_cycle(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        intent(
            issuedAt=iso_z(now - timedelta(minutes=80)),
            expiresAt=iso_z(now + timedelta(hours=1)),
        )
    )

    pending = store.pending()[0]
    alerts = store.pending_alerts(min_age_minutes=70)

    assert pending["pendingAgeMinutes"] >= 79
    assert alerts[0]["alertCode"] == "DISPATCH_PENDING_OVER_ONE_CYCLE"


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
