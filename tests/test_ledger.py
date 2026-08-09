import json
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
        "issueUpdatedAt": iso_z(now),
        "policyDigest": "policy-digest",
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


def test_clean_unresolved_dispatch_can_be_reset_for_retry(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree",
    )

    result = store.reset_dispatch_for_retry(
        thread_id="thread-1", reason="INVALID_EXECUTION_ENVIRONMENT"
    )

    assert result["intentId"] == "intent-1"
    pending = store.pending()[0]
    assert pending["ledgerStatus"] == "PENDING"
    assert store.active_dispatch_count() == 0


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


def test_creating_state_survives_expired_lease_and_blocks_duplicate(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    creation = store.reserve_creation("intent-1", owner="controller")
    store.bind_creation_client(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        client_thread_id="client-1",
    )
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET lease_until=?,expires_at=? WHERE intent_id='intent-1'",
            (
                iso_z(datetime.now(UTC) - timedelta(hours=1)),
                iso_z(datetime.now(UTC) - timedelta(minutes=30)),
            ),
        )

    assert store.enqueue(intent(intentId="intent-2", decisionDigest="new")) is False
    assert store.claim("intent-1", "controller") is None
    assert store.active_dispatch_count() == 1
    assert store.has_live_handoff(issue_url="https://github.com/a/b/issues/1") is True
    pending = store.pending()
    assert pending[0]["ledgerStatus"] == "CREATING"
    assert pending[0]["clientThreadId"] == "client-1"
    assert store.pending_alerts() == []
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET creation_started_at=? WHERE intent_id='intent-1'",
            (iso_z(datetime.now(UTC) - timedelta(hours=2)),),
        )
    assert store.pending_alerts()[0]["alertCode"] == "TASK_CREATION_PENDING"


def test_late_created_thread_can_commit_after_lease_expiry(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    creation = store.reserve_creation("intent-1", owner="controller")
    store.bind_creation_client(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        client_thread_id="client-1",
    )
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET lease_until=? WHERE intent_id='intent-1'",
            (iso_z(datetime.now(UTC) - timedelta(hours=1)),),
        )

    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-late",
        project_id="github",
        worktree_path="/tmp/worktree",
    )

    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-late",
    )
    assert context is not None
    assert context["intentStatus"] == "DISPATCHED"


def test_creation_can_only_be_cancelled_before_client_id_is_bound(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    creation = store.reserve_creation("intent-1", owner="controller")
    store.cancel_creation(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        reason="create_thread_rejected_before_dispatch",
    )
    assert store.pending()[0]["ledgerStatus"] == "PENDING"

    store.claim("intent-1", "controller")
    creation = store.reserve_creation("intent-1", owner="controller")
    store.bind_creation_client(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        client_thread_id="client-1",
    )
    with pytest.raises(LedgerError, match="cannot be cancelled"):
        store.cancel_creation(
            "intent-1",
            owner="controller",
            creation_token=creation["creationToken"],
            reason="timeout",
        )


def test_stale_bound_creation_can_be_abandoned_and_renewed(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    creation = store.reserve_creation("intent-1", owner="controller")
    store.bind_creation_client(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        client_thread_id="client-1",
    )
    with pytest.raises(LedgerError, match="not old enough"):
        store.abandon_creation(
            "intent-1",
            owner="controller",
            creation_token=creation["creationToken"],
            client_thread_id="client-1",
            reason="ASYNC_CREATION_NOT_MATERIALIZED",
        )
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET creation_started_at=? WHERE intent_id='intent-1'",
            (iso_z(datetime.now(UTC) - timedelta(hours=2)),),
        )

    store.abandon_creation(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        client_thread_id="client-1",
        reason="ASYNC_CREATION_NOT_MATERIALIZED",
    )

    with store.connect() as connection:
        row = connection.execute(
            """SELECT i.status,i.client_thread_id,i.creation_token,o.stage
               FROM intents i JOIN opportunities o ON o.key=i.opportunity_key
               WHERE i.intent_id='intent-1'"""
        ).fetchone()
    assert dict(row) == {
        "status": "SUPERSEDED",
        "client_thread_id": None,
        "creation_token": None,
        "stage": "AUDIT_PASS",
    }
    renewed_expiry = iso_z(datetime.now(UTC) + timedelta(hours=2))
    assert store.enqueue(intent(expiresAt=renewed_expiry)) is False
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


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
    with store.connect() as connection:
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            0
        ]
    assert stage == "AUDIT_PASS"
    with pytest.raises(LedgerError, match="not leased"):
        store.commit_dispatch(
            "intent-1",
            owner="old-controller",
            thread_id="thread-1",
            project_id="repo-project",
            worktree_path="/tmp/worktree",
        )
    assert store.enqueue(intent(intentId="intent-2", decisionDigest="new")) is True


def test_failed_preparation_can_release_an_exclusive_lease(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    assert store.claim("intent-1", "controller") is not None

    assert store.release_claim("intent-1", owner="other", reason="wrong owner") is False
    assert store.release_claim("intent-1", owner="controller", reason="clone timeout") is True

    pending = store.pending()
    assert len(pending) == 1
    assert pending[0]["ledgerStatus"] == "PENDING"
    with store.connect() as connection:
        event = connection.execute(
            "SELECT payload_json FROM events WHERE event_type='LEASE_RELEASED'"
        ).fetchone()
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            "stage"
        ]
    assert json.loads(event["payload_json"])["reason"] == "clone timeout"
    assert stage == "AUDIT_PASS"


def test_initialization_repairs_historical_lease_without_active_intent(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    store = RadarLedger(path)
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    with store.connect() as connection:
        connection.execute(
            """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,lease_until=NULL
               WHERE intent_id='intent-1'"""
        )
    store = RadarLedger(path)

    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage FROM opportunities WHERE key='a/b#1'"
        ).fetchone()
        repair = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='a/b#1' AND event_type='LEDGER_STAGE_REPAIRED'"""
        ).fetchone()

    assert opportunity["stage"] == "AUDIT_PASS"
    assert json.loads(repair["payload_json"]) == {"from": "LEASED", "to": "AUDIT_PASS"}


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


def test_validation_pending_is_non_terminal_and_not_archivable(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            autoSubmitAuthorized=True,
            publicSubmissionAllowed=True,
            authorizationSource="signed_live_revalidation_required",
            publicationMode="active",
        )
    )
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-09 05:25",
    )

    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"missing": ["relevant_tests_green"]},
    )

    candidate = store.title_candidates()[0]
    assert candidate["titleState"] == "VALIDATION_PENDING"
    assert store.cleanup_candidates() == []
    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert context["stage"] == "VALIDATION_PENDING"
    assert context["intentStatus"] == "COMPLETED"
    assert context["autoSubmitAuthorized"] is True


def test_post_publication_no_go_audit_does_not_downgrade_lifecycle(tmp_path):
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
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": "https://example.test/pr/1"})
    candidate = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="PR_OPEN",
        nonce=candidate["titleNonce"],
    )

    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ISSUE_CLOSED")

    assert store.title_candidates() == []
    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage,terminal_reason FROM opportunities WHERE key='a/b#1'"
        ).fetchone()
        ignored = connection.execute(
            "SELECT payload_json FROM events WHERE opportunity_key='a/b#1' "
            "AND event_type='POST_PUBLICATION_AUDIT_NO_GO'"
        ).fetchone()
    assert dict(opportunity) == {"stage": "PR_OPEN", "terminal_reason": None}
    assert json.loads(ignored["payload_json"])["reason"] == "ISSUE_CLOSED"


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


def test_archived_prior_thread_does_not_hide_later_no_go_thread(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree-1",
        title_time="08-04 18:47",
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="WRONG_REPO")
    first_title = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=first_title["titleNonce"],
    )
    first_cleanup = store.cleanup_candidates()[0]
    store.commit_cleanup(thread_id="thread-1", nonce=first_cleanup["cleanupNonce"])

    store.enqueue(
        intent(
            intentId="intent-2",
            decisionDigest="decision-2",
            issueUpdatedAt=iso_z(datetime.now(UTC) + timedelta(minutes=1)),
        )
    )
    store.claim("intent-2", "worker")
    store.commit_dispatch(
        "intent-2",
        owner="worker",
        thread_id="thread-2",
        project_id="repo-project",
        worktree_path="/tmp/worktree-2",
        title_time="08-05 20:35",
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="WRONG_REPO")

    second_title = store.title_candidates()
    assert [item["threadId"] for item in second_title] == ["thread-2"]
    store.commit_title(
        thread_id="thread-2",
        state="AUDIT_NO_GO",
        nonce=second_title[0]["titleNonce"],
    )
    assert [item["threadId"] for item in store.cleanup_candidates()] == ["thread-2"]


def test_archived_thread_is_not_retitle_candidate_when_issue_is_released_again(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree-1",
        title_time="08-04 18:47",
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="SECURITY_SENSITIVE")
    first_title = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=first_title["titleNonce"],
    )
    first_cleanup = store.cleanup_candidates()[0]
    store.commit_cleanup(thread_id="thread-1", nonce=first_cleanup["cleanupNonce"])

    store.enqueue(
        intent(
            intentId="intent-2",
            decisionDigest="decision-2",
            issueUpdatedAt=iso_z(datetime.now(UTC) + timedelta(minutes=1)),
        )
    )
    store.claim("intent-2", "worker")

    assert store.title_candidates() == []
    assert store.restore_candidates() == []


def test_archived_task_is_restored_when_lifecycle_recovers(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-09 21:30",
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="VALIDATION_INCOMPLETE")
    title = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=title["titleNonce"],
    )
    cleanup = store.cleanup_candidates()[0]
    store.commit_cleanup(thread_id="thread-1", nonce=cleanup["cleanupNonce"])

    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": "https://example.test/pr/1"})

    assert store.title_candidates() == []
    restore = store.restore_candidates()[0]
    assert restore["threadId"] == "thread-1"
    assert restore["stage"] == "PR_OPEN"
    store.commit_restore(thread_id="thread-1", nonce=restore["restoreNonce"])
    assert store.restore_candidates() == []
    recovered_title = store.title_candidates()[0]
    assert recovered_title["titleState"] == "PR_OPEN"


def test_restored_task_can_be_archived_again_after_a_new_no_go(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-09 21:30",
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="VALIDATION_INCOMPLETE")
    first_title = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=first_title["titleNonce"],
    )
    first_cleanup = store.cleanup_candidates()[0]
    store.commit_cleanup(thread_id="thread-1", nonce=first_cleanup["cleanupNonce"])

    store.record_stage("a/b#1", "VALIDATION_PENDING")
    restore = store.restore_candidates()[0]
    store.commit_restore(thread_id="thread-1", nonce=restore["restoreNonce"])
    pending_title = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="VALIDATION_PENDING",
        nonce=pending_title["titleNonce"],
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ISSUE_CLOSED")
    second_title = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="AUDIT_NO_GO",
        nonce=second_title["titleNonce"],
    )
    second_cleanup = store.cleanup_candidates()[0]
    store.commit_cleanup(thread_id="thread-1", nonce=second_cleanup["cleanupNonce"])

    assert store.cleanup_candidates() == []
    with store.connect() as connection:
        archived_count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE opportunity_key='a/b#1' "
            "AND event_type='THREAD_ARCHIVED'"
        ).fetchone()[0]
    assert archived_count == 2


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
    assert (
        store.enqueue(
            intent(
                intentId="intent-3",
                decisionDigest="new-decision",
                issueUpdatedAt=iso_z(datetime.now(UTC) + timedelta(minutes=1)),
            )
        )
        is True
    )
    with store.connect() as connection:
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            "stage"
        ]
    assert stage == "QUALIFIED"


def test_same_issue_snapshot_is_not_requeued_after_no_go(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    first = intent()
    store.enqueue(first)
    store.claim("intent-1", "worker")
    store.record_stage(
        "a/b#1",
        "AUDIT_PASS",
        evidence={"liveAudit": {"evidence": {"issue": {"updated_at": first["issueUpdatedAt"]}}}},
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="NOT_ACTIONABLE")

    assert (
        store.enqueue(
            intent(
                intentId="intent-2",
                decisionDigest="changed",
                issueUpdatedAt=first["issueUpdatedAt"],
            )
        )
        is False
    )
    assert store.pending() == []


def test_changed_issue_snapshot_can_reopen_no_go(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    first = intent()
    store.enqueue(first)
    store.claim("intent-1", "worker")
    store.record_stage(
        "a/b#1",
        "AUDIT_PASS",
        evidence={"liveAudit": {"evidence": {"issue": {"updated_at": first["issueUpdatedAt"]}}}},
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="NOT_ACTIONABLE")

    assert store.enqueue(
        intent(
            intentId="intent-2",
            decisionDigest="changed",
            issueUpdatedAt=iso_z(datetime.now(UTC) + timedelta(minutes=1)),
        )
    )
    with store.connect() as connection:
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            "stage"
        ]
    assert stage == "QUALIFIED"


def test_changed_policy_can_reopen_no_go_without_issue_update(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    first = intent()
    store.enqueue(first)
    store.claim("intent-1", "worker")
    store.record_stage(
        "a/b#1",
        "AUDIT_PASS",
        evidence={"liveAudit": {"evidence": {"issue": {"updated_at": first["issueUpdatedAt"]}}}},
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="POLICY_BLOCKED")

    assert store.enqueue(
        intent(
            intentId="intent-2",
            decisionDigest="changed",
            issueUpdatedAt=first["issueUpdatedAt"],
            policyDigest="changed-policy-digest",
        )
    )


def test_intent_issued_before_no_go_cannot_revive_terminal_opportunity(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    stale = intent(intentId="intent-stale", decisionDigest="changed")
    store.enqueue(intent())
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="NOT_ACTIONABLE")

    assert store.enqueue(stale) is False
    assert store.pending() == []
    with store.connect() as connection:
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE event_type='STALE_INTENT_IGNORED'"""
        ).fetchone()
    assert json.loads(event["payload_json"])["intentId"] == "intent-stale"


def test_terminal_reconciliation_rejects_active_stale_intent(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    stale = intent(intentId="intent-stale", decisionDigest="changed")
    store.enqueue(intent())
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="NOT_ACTIONABLE")
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO intents
               (intent_id,opportunity_key,intent_digest,status,issued_at,expires_at,
                payload_json,updated_at)
               VALUES (?,?,?,'PENDING',?,?,?,?)""",
            (
                stale["intentId"],
                stale["key"],
                stale["decisionDigest"],
                stale["issuedAt"],
                stale["expiresAt"],
                json.dumps(stale),
                stale["issuedAt"],
            ),
        )

    assert store.reconcile_terminal_intents() == ["intent-stale"]
    assert store.pending() == []


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


def test_validation_deferred_result_is_not_an_empty_thread_recovery(tmp_path):
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
    assert store.recovery_candidates(min_age_minutes=90)

    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )

    assert store.recovery_candidates(min_age_minutes=90) == []


def test_validation_followup_is_write_ahead_and_rearms_for_a_new_result(tmp_path):
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
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-1",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")

    candidate = store.validation_followup_candidates()[0]
    assert candidate["threadId"] == "thread-1"
    assert candidate["resultDigest"] == "result-digest-1"
    assert candidate["missing"] == ["relevant_tests_green"]

    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    assert store.validation_followup_candidates() == []
    assert store.unresolved_validation_followups()[0]["resultDigest"] == "result-digest-1"

    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    assert store.unresolved_validation_followups() == []
    old = iso_z(datetime.now(UTC) - timedelta(hours=3))
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_SENT'""",
            (old,),
        )
    assert store.stale_validation_followups(min_age_minutes=90)[0]["threadId"] == "thread-1"

    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-2",
        missing=["reproduction_verified"],
    )
    rearmed = store.validation_followup_candidates()[0]
    assert rearmed["resultDigest"] == "result-digest-2"
    assert rearmed["missing"] == ["reproduction_verified"]
    assert store.stale_validation_followups(min_age_minutes=90) == []

    assert store.validation_followup_was_sent(thread_id="thread-1") is True
    assert store.validation_followup_was_sent(thread_id="missing-thread") is False


def test_expired_intent_cannot_be_claimed(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent(expiresAt="2020-01-01T00:00:00Z"))
    assert store.claim("intent-1", "worker") is None


def test_plain_pending_backlog_is_not_reported_as_dispatch_failure(tmp_path):
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
    assert alerts == []


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


def test_pr_followup_is_bound_to_existing_task_and_sent_once(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            autoSubmitAuthorized=True,
            publicSubmissionAllowed=True,
            authorizationSource="signed_live_revalidation_required",
            publicationMode="canary",
        )
    )
    store.claim("intent-1", "controller")
    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree",
    )
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": "https://github.com/a/b/pull/9"})
    now = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/1-runtime','/tmp/worktree',
                       'evidence','CONSUMED','{}',?,?)""",
            ("a" * 40, now, now),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/1-runtime','CONSUMED',?,'https://github.com/a/b/pull/9','{}',?,?)""",
            ("a" * 40, iso_z(datetime.now(UTC) + timedelta(hours=1)), now, now),
        )
    state = {
        "version": "pr_followup_v3",
        "generatedAt": now,
        "items": [
            {
                "url": "https://github.com/a/b/pull/9",
                "headSha": "b" * 40,
                "actionDigest": "action",
                "taskActionDigest": "task-action",
                "taskFollowupRequired": True,
                "taskActions": ["当前分支检查失败"],
                "evidence": {"actionableCheckNames": ["Ruff"]},
                "checkedAt": now,
            }
        ],
    }

    imported = store.import_pr_followups(state)
    candidate = store.pr_followup_candidates()[0]
    assert imported == {"matched": 1, "inserted": 1, "updated": 0}
    assert candidate["threadId"] == "thread-1"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "prFollowup"
        ]["headSha"]
        == "b" * 40
    )

    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    assert store.pr_followup_candidates() == []
    assert store.unresolved_pr_followups()
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    assert store.unresolved_pr_followups() == []

    store.import_pr_followups(state)
    assert store.pr_followup_candidates() == []

    state["items"][0]["headSha"] = "c" * 40
    state["items"][0]["checkedAt"] = iso_z(datetime.now(UTC) + timedelta(minutes=1))
    store.import_pr_followups(state)
    assert store.pr_followup_candidates() == []

    previous_wake = candidate["wakeDigest"]
    store.record_stage("a/b#1", "FIX_READY", evidence={field: True for field in QUALITY_FIELDS})
    update = store.create_publication_request(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        commit_sha="d" * 40,
        branch="fix/1-runtime",
        worktree_path="/tmp/worktree",
        evidence_digest="update-evidence",
        evidence_path="/tmp/worktree/.oss-pr-radar/result.json",
        publication={
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: runtime",
            "bodyPath": "/tmp/worktree/.oss-pr-radar/pr-body.md",
        },
    )
    assert update["request"]["publicationKind"] == "PR_UPDATE"
    permit = store.grant_publication_request(
        update["request_id"],
        issue_url="https://github.com/a/b/issues/1",
        commit_sha="d" * 40,
        branch="fix/1-runtime",
        evidence={"verified": True},
    )
    assert permit["status"] == "ACTIVE"

    store.block_publication_request(update["request_id"], "EXISTING_PR_HEAD_DRIFT")

    with store.connect() as connection:
        expired = connection.execute(
            "SELECT status FROM publication_permits WHERE request_id=?",
            (update["request_id"],),
        ).fetchone()
    assert expired["status"] == "EXPIRED"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "PR_OPEN"
    )
    assert store.active_pr_followup("a/b#1") is None
    store.import_pr_followups(state)
    rearmed = store.pr_followup_candidates()[0]
    assert rearmed["wakeDigest"] != previous_wake


def test_post_push_confirmation_recovers_legacy_head_drift_failure(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    request_id = "request-update"
    permit_id = "permit-update"
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,'GRANTED',?,?,?)""",
            (
                request_id,
                "a/b#1",
                "thread-1",
                "b" * 40,
                "fix/1-runtime",
                "/tmp/worktree",
                "evidence",
                json.dumps({"publicationKind": "PR_UPDATE", "commitSha": "b" * 40}),
                now,
                now,
            ),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                evidence_json,created_at,updated_at)
               VALUES (?,?,?,?,?,'ACTIVE',?,'{}',?,?)""",
            (
                permit_id,
                request_id,
                "https://github.com/a/b/issues/1",
                "b" * 40,
                "fix/1-runtime",
                iso_z(datetime.now(UTC) + timedelta(minutes=10)),
                now,
                now,
            ),
        )
    push = store.publication_effect(
        permit_id=permit_id,
        action="push",
        request_digest="push-request",
    )
    store.complete_publication_effect(
        push["effect_id"],
        status="SUCCEEDED",
        result={"ok": True, "remoteSha": "b" * 40},
    )
    confirmation = store.publication_effect(
        permit_id=permit_id,
        action="create_pr",
        request_digest="confirmation-request",
    )
    store.complete_publication_effect(
        confirmation["effect_id"],
        status="FAILED",
        result={
            "ok": False,
            "reason": "LIVE_RECHECK_FAILED",
            "detail": "EXISTING_PR_HEAD_DRIFT",
        },
    )
    store.block_publication_request(request_id, "EXISTING_PR_HEAD_DRIFT")

    assert [item["request_id"] for item in store.publication_work_items()] == [request_id]
    recovered = store.prepare_post_push_reconciliation(request_id)

    assert recovered["permit_id"] == permit_id
    assert store.publication_request(request_id)["status"] == "GRANTED"
    effect = store.publication_effect_by_request(
        permit_id=permit_id,
        action="create_pr",
        request_digest="confirmation-request",
    )
    assert effect["status"] == "RECONCILE_REQUIRED"

    store.succeed_pull_request_effect(
        effect_id=effect["effect_id"],
        permit_id=permit_id,
        pr_url="https://github.com/a/b/pull/9",
        result={"ok": True, "prUrl": "https://github.com/a/b/pull/9"},
    )
    consumed = store.publication_request(request_id)
    assert consumed["status"] == "CONSUMED"
    assert consumed["reason"] is None
