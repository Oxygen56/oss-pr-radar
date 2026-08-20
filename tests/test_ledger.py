import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.ledger import LedgerError, RadarLedger
from oss_pr_radar.metrics import QUALITY_FIELDS, assess_submit_ready, rolling_quality
from oss_pr_radar.util import iso_z, parse_time, sha256_json

pytestmark = pytest.mark.usefixtures("current_signing_key")


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


def legal_publication_probe(
    tmp_path: Path,
    *,
    commit_message: str = "fix: runtime",
    owner_repo: str = "a/b",
    issue_number: int = 1,
    task_id: str = "intent-1",
):
    from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES, run_reproduction_probe

    worktree = tmp_path / f"publication-worktree-{task_id}"
    worktree.mkdir()

    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=worktree, check=True, capture_output=True, text=True
        )
        return completed.stdout.strip()

    git("init")
    git("config", "user.name", "Test Contributor")
    git("config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    git("add", "runtime.py")
    git("commit", "-m", "chore: baseline")
    base_sha = git("rev-parse", "HEAD")
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    git("add", "runtime.py")
    git("commit", "-m", commit_message)
    head_sha = git("rev-parse", "HEAD")
    branch = git("symbolic-ref", "--short", "HEAD")
    checkout = tmp_path / f"publication-probe-{task_id}"
    profile_id = "test-ledger-publication"
    issue_url = f"https://github.com/{owner_repo}/issues/{issue_number}"
    unsigned = {
        "taskId": task_id,
        "issueUrl": issue_url,
        "selectedBaseSha": base_sha,
        "headSha": head_sha,
        "commitSha": head_sha,
        "codePaths": ["runtime.py"],
    }
    result_digest = sha256_json(unsigned)
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    git("worktree", "add", "--detach", str(checkout), base_sha)
    receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo=owner_repo,
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
        profile_id=profile_id,
        issue_url=unsigned["issueUrl"],
        task_id=task_id,
        thread_id=task_id,
        head_sha=head_sha,
        commit_sha=head_sha,
        result_digest=result_digest,
    )
    TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    git("worktree", "remove", "--force", str(checkout))
    evidence_path = worktree / ".oss-pr-radar" / "result.json"
    evidence_path.parent.mkdir()
    evidence_path.write_text(
        json.dumps(unsigned | {"reproductionReceipt": receipt}), encoding="utf-8"
    )
    return worktree, base_sha, head_sha, branch, receipt, result_digest, evidence_path


def published_task_context(**updates):
    now = iso_z(datetime.now(UTC))
    value = {
        "key": "a/b#1",
        "stage": "PR_OPEN",
        "issueUrl": "https://github.com/a/b/issues/1",
        "intentId": "recovered-intent",
        "threadId": "thread-recovered",
        "worktreePath": "/tmp/recovered-worktree",
        "intentStatus": "COMPLETED",
        "track": "agent_ai_infra",
        "algorithmEvidence": None,
        "autoSubmitAuthorized": True,
        "publicSubmissionAllowed": True,
        "authorizationSource": "signed_live_revalidation_required",
        "publicationMode": "canary",
        "contextDigest": "context-digest",
        "resultPath": "/tmp/recovered-worktree/.oss-pr-radar/result.json",
        "liveAuditRecordedAt": now,
        "liveAudit": {
            "capturedAt": now,
            "evidence": {
                "digest": "evidence-digest",
                "issue": {
                    "state": "open",
                    "title": "Recovered runtime bug",
                    "updated_at": now,
                },
                "policy": {"digest": "policy-digest"},
            },
        },
        "publicationReceipt": {
            "status": "PR_OPEN",
            "prUrl": "https://github.com/a/b/pull/9",
            "commitSha": "a" * 40,
            "branch": "fix/recovered-runtime",
            "requestedAt": now,
            "updatedAt": now,
        },
    }
    value.update(updates)
    return value


def insert_publication_preflight(
    store: RadarLedger,
    *,
    effect_status: str = "ATTEMPTED",
    effect_result: dict | None = None,
) -> None:
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    expires_at = iso_z(datetime.now(UTC) + timedelta(minutes=10))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/runtime','/tmp/worktree',
                       'evidence','GRANTED','{}',?,?)""",
            ("b" * 40, now, now),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/runtime','ACTIVE',?,'{}',?,?)""",
            ("b" * 40, expires_at, now, now),
        )
        connection.execute(
            """INSERT INTO publication_effects
               (effect_id,permit_id,action,request_digest,status,result_json,created_at,updated_at)
               VALUES ('effect-1','permit-1','push','digest',?,?,?,?)""",
            (effect_status, json.dumps(effect_result or {}), now, now),
        )


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


def test_pending_prioritizes_publishable_normal_work(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        intent(
            intentId="private-old",
            key="a/b#1",
            issuedAt=iso_z(now - timedelta(minutes=10)),
            expiresAt=iso_z(now + timedelta(hours=1)),
            score=12,
            publicSubmissionAllowed=False,
            submissionPolicy="ai_disclosure_conflict",
        )
    )
    store.enqueue(
        intent(
            intentId="publishable-new",
            key="a/b#2",
            issueNumber=2,
            issueUrl="https://github.com/a/b/issues/2",
            issuedAt=iso_z(now),
            expiresAt=iso_z(now + timedelta(hours=1)),
            score=9,
            publicSubmissionAllowed=True,
            submissionPolicy="normal",
        )
    )

    assert [item["intentId"] for item in store.pending()] == [
        "publishable-new",
        "private-old",
    ]


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


def test_filter_miss_metrics_accept_current_machine_readable_failure_classes(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    store = RadarLedger(path)
    store.enqueue(intent())
    store.record_stage("a/b#1", "AUDIT_NO_GO", evidence={}, reason="STRONG_EXISTING_PR")

    metrics = rolling_quality(path)

    assert metrics["filterMisses"] == 1
    assert metrics["filterMissRate"] == 1.0
    assert metrics["failureClassCounts"] == {"STRONG_EXISTING_PR": 1}


def test_same_issue_cannot_create_a_second_live_task(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    assert store.enqueue(intent()) is True
    assert store.enqueue(intent(intentId="intent-2", decisionDigest="new")) is False


def test_verified_task_context_rebuilds_publication_and_suppresses_duplicate(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    assert store.enqueue(intent(intentId="new-intent", decisionDigest="new")) is True

    restored = store.restore_task_context(published_task_context())

    assert restored == {
        "key": "a/b#1",
        "stage": "PR_OPEN",
        "intentRestored": True,
        "publicationRestored": True,
    }
    assert store.pending() == []
    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-recovered",
    )
    assert context is not None
    assert context["stage"] == "PR_OPEN"
    assert context["publicationReceipt"]["prUrl"] == "https://github.com/a/b/pull/9"
    assert store.enqueue(intent(intentId="new-intent", decisionDigest="new")) is False
    assert store.pending() == []
    assert store.enqueue(intent(intentId="later-intent", decisionDigest="later")) is False

    imported = store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": iso_z(datetime.now(UTC)),
            "items": [
                {
                    "url": "https://github.com/a/b/pull/9",
                    "headSha": "a" * 40,
                    "actionDigest": "action",
                    "taskActionDigest": "task-action",
                    "checkedAt": iso_z(datetime.now(UTC)),
                    "taskActions": ["current branch check failed"],
                    "taskFollowupRequired": True,
                    "evidence": {"baseIntegrationRequired": True},
                }
            ],
        }
    )
    assert imported == {
        "matched": 1,
        "inserted": 1,
        "updated": 0,
        "staleHeadSuppressed": 0,
    }
    candidate = store.pr_followup_candidates()[0]
    assert candidate["threadId"] == "thread-recovered"
    store.record_followup_result(
        "a/b#1",
        wake_digest=candidate["wakeDigest"],
        result_digest="result",
        stage="PR_OPEN",
    )
    assert store.pr_followup_candidates() == []


def test_pr_followup_import_suppresses_stale_head_but_accepts_later_external_head(
    tmp_path,
):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    published_time = datetime.now(UTC)
    context = published_task_context()
    context["publicationReceipt"]["requestedAt"] = iso_z(published_time - timedelta(minutes=1))
    context["publicationReceipt"]["updatedAt"] = iso_z(published_time)
    store.restore_task_context(context)
    stale_checked_at = iso_z(published_time - timedelta(seconds=1))
    state = {
        "version": "pr_followup_v3",
        "generatedAt": stale_checked_at,
        "items": [
            {
                "url": "https://github.com/a/b/pull/9",
                "headSha": "b" * 40,
                "actionDigest": "stale-action",
                "taskActionDigest": "stale-task-action",
                "checkedAt": stale_checked_at,
                "taskActions": ["old head check failed"],
                "taskFollowupRequired": True,
                "evidence": {"actionableCheckNames": ["Old check"]},
            }
        ],
    }

    stale = store.import_pr_followups(state)

    assert stale == {
        "matched": 1,
        "inserted": 0,
        "updated": 0,
        "staleHeadSuppressed": 1,
    }
    assert store.pr_followup_candidates() == []
    with store.connect() as connection:
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='a/b#1'
                 AND event_type='PR_FOLLOWUP_STALE_HEAD_SUPPRESSED'"""
        ).fetchone()
    assert json.loads(event["payload_json"])["currentCommitSha"] == "a" * 40

    fresh_checked_at = iso_z(published_time + timedelta(seconds=1))
    state["generatedAt"] = fresh_checked_at
    state["items"][0].update(
        {
            "headSha": "c" * 40,
            "actionDigest": "fresh-action",
            "taskActionDigest": "fresh-task-action",
            "checkedAt": fresh_checked_at,
        }
    )
    fresh = store.import_pr_followups(state)

    assert fresh == {
        "matched": 1,
        "inserted": 1,
        "updated": 0,
        "staleHeadSuppressed": 0,
    }
    assert store.pr_followup_candidates()[0]["headSha"] == "c" * 40


def test_task_context_recovery_is_idempotent(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    context = published_task_context()

    first = store.restore_task_context(context)
    store.record_stage("a/b#1", "FIX_READY", evidence={"followup": True})
    second = store.restore_task_context(context)

    assert first["intentRestored"] is True
    assert first["publicationRestored"] is True
    assert second["intentRestored"] is False
    assert second["publicationRestored"] is False
    assert second["stage"] == "FIX_READY"
    current = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-recovered",
    )
    assert current is not None
    assert current["stage"] == "FIX_READY"
    with store.connect() as connection:
        recovered_events = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key='a/b#1' AND event_type='TASK_CONTEXT_RECOVERED'"""
        ).fetchone()[0]
    assert recovered_events == 1


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


def test_stale_unbound_creation_can_be_abandoned(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "controller")
    creation = store.reserve_creation("intent-1", owner="controller")
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET creation_started_at=? WHERE intent_id='intent-1'",
            (iso_z(datetime.now(UTC) - timedelta(hours=2)),),
        )

    store.abandon_creation(
        "intent-1",
        owner="controller",
        creation_token=creation["creationToken"],
        client_thread_id=None,
        reason="CREATION_NOT_MATERIALIZED",
    )

    with store.connect() as connection:
        row = connection.execute(
            "SELECT status,client_thread_id,creation_token FROM intents WHERE intent_id='intent-1'"
        ).fetchone()
    assert dict(row) == {
        "status": "SUPERSEDED",
        "client_thread_id": None,
        "creation_token": None,
    }


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


def test_synced_title_can_be_invalidated_after_desktop_drift(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-09 19:30",
    )

    assert store.title_candidates() == []
    assert (
        store.invalidate_title_sync(
            thread_id="thread-1",
            state="GO",
            actual_title_digest="a" * 64,
        )
        is True
    )
    candidate = store.title_candidates()[0]
    assert candidate["titleState"] == "GO"
    store.commit_title(thread_id="thread-1", state="GO", nonce=candidate["titleNonce"])
    assert store.title_candidates() == []


def test_title_nonce_ignores_unrelated_opportunity_timestamp_churn(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-09 19:30",
    )
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    candidate = store.title_candidates()[0]

    with store.connect() as connection:
        connection.execute(
            "UPDATE opportunities SET updated_at=? WHERE key=?",
            ("2099-01-01T00:00:00Z", "a/b#1"),
        )

    current = store.title_candidates()[0]
    assert current["titleNonce"] == candidate["titleNonce"]
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


def test_policy_migration_reopens_only_matching_undispatched_terminal(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    original = intent()
    store.enqueue(original)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="AI_DISCLOSURE_REQUIRES_USER")

    store.reopen_false_terminal(
        "a/b#1",
        expected_reason="AI_DISCLOSURE_REQUIRES_USER",
        migration_reason="PRIVATE_DISCLOSURE_DISPATCH_ENABLED",
    )

    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage,terminal_reason FROM opportunities WHERE key='a/b#1'"
        ).fetchone()
        status = connection.execute(
            "SELECT status FROM intents WHERE intent_id='intent-1'"
        ).fetchone()["status"]
    assert dict(opportunity) == {"stage": "QUALIFIED", "terminal_reason": None}
    assert status == "EXPIRED"

    refreshed = original | {
        "expiresAt": iso_z(datetime.now(UTC) + timedelta(hours=2)),
        "submissionPolicy": "REQUIRE_USER_DISCLOSURE_APPROVAL",
    }
    assert store.enqueue(refreshed) is False
    assert store.pending()[0]["submissionPolicy"] == "REQUIRE_USER_DISCLOSURE_APPROVAL"

    with pytest.raises(LedgerError, match="authorization is stale"):
        store.reopen_false_terminal(
            "a/b#1",
            expected_reason="AI_DISCLOSURE_REQUIRES_USER",
            migration_reason="PRIVATE_DISCLOSURE_DISPATCH_ENABLED",
        )


def test_task_context_recovers_disclosure_policy_from_live_audit(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent(autoSubmitAuthorized=False, publicSubmissionAllowed=False))
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
    )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {"policy": {"ai_disclosure": True}},
            }
        },
        dedupe_key="disclosure-audit",
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert context["submissionPolicy"] == "ai_disclosure_conflict"
    assert context["publicSubmissionAllowed"] is False


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


def test_desktop_archive_drift_can_be_reconciled_without_archive_event(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
        title_time="08-16 19:30",
    )

    assert store.restore_candidates() == []
    binding = store.restorable_task_bindings()[0]
    assert binding["lifecycleState"] is None

    store.commit_restore(thread_id="thread-1", nonce=binding["restoreNonce"])

    with store.connect() as connection:
        restored = connection.execute(
            """SELECT payload_json FROM events
               WHERE event_type='THREAD_RESTORED'"""
        ).fetchone()
    assert json.loads(restored["payload_json"])["threadId"] == "thread-1"


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
    assert candidate["recoveryKind"] == "DISPATCHED_TASK"
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


def test_recent_dispatch_can_be_authorized_for_terminal_error_recovery(tmp_path):
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

    assert store.recovery_candidates(min_age_minutes=90) == []
    candidate = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])

    assert store.unresolved_recoveries()[0]["threadId"] == "thread-1"


def test_unknown_recovery_delivery_can_be_abandoned_and_rearmed(tmp_path):
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
    first = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=first["recoveryNonce"])
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='THREAD_RECOVERY_RESERVED'""",
            (iso_z(datetime.now(UTC) - timedelta(minutes=10)),),
        )

    store.abandon_recovery_delivery(
        thread_id="thread-1",
        nonce=first["recoveryNonce"],
        reason="TARGET_TURN_NOT_MATERIALIZED",
        min_age_minutes=5,
    )

    assert store.unresolved_recoveries() == []
    rearmed = store.recovery_candidates(min_age_minutes=0)[0]
    assert rearmed["recoveryNonce"] != first["recoveryNonce"]
    with pytest.raises(LedgerError, match="stale or invalid"):
        store.reserve_recovery(thread_id="thread-1", nonce=first["recoveryNonce"])
    store.reserve_recovery(thread_id="thread-1", nonce=rearmed["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=rearmed["recoveryNonce"])
    assert store.unresolved_recoveries() == []


def test_sent_pr_followup_without_a_result_gets_recovery(tmp_path):
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
    published_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    now = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/1-runtime','/tmp/worktree',
                       'evidence','CONSUMED','{}',?,?)""",
            ("a" * 40, published_at, published_at),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/1-runtime','CONSUMED',?,'https://github.com/a/b/pull/9','{}',?,?)""",
            (
                "a" * 40,
                iso_z(datetime.now(UTC) + timedelta(hours=1)),
                published_at,
                published_at,
            ),
        )
    store.import_pr_followups(
        {
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
    )
    followup = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=followup["wakeDigest"])
    store.commit_pr_followup(thread_id="thread-1", wake_digest=followup["wakeDigest"])
    old = iso_z(datetime.now(UTC) - timedelta(hours=3))
    with store.connect() as connection:
        connection.execute(
            "UPDATE events SET created_at=? WHERE event_type='PR_FOLLOWUP_SENT'",
            (old,),
        )

    candidate = store.recovery_candidates(min_age_minutes=90)[0]

    assert candidate["threadId"] == "thread-1"
    assert candidate["recoveryKind"] == "PR_FOLLOWUP_RESULT"
    assert candidate["followupDigest"] == followup["wakeDigest"]
    store.reserve_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])
    assert store.recovery_candidates(min_age_minutes=90) == []

    store.commit_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])
    assert store.unresolved_recoveries() == []


def test_pr_followup_result_prevents_recovery(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.restore_task_context(published_task_context())
    old = iso_z(datetime.now(UTC) - timedelta(hours=3))
    wake_digest = "followup-wake"
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES ('a/b#1','PR_FOLLOWUP_SENT',?,? ,?)""",
            (
                wake_digest,
                json.dumps(
                    {
                        "threadId": "thread-recovered",
                        "prUrl": "https://github.com/a/b/pull/9",
                    }
                ),
                old,
            ),
        )
    assert store.recovery_candidates(min_age_minutes=90)

    store.record_followup_result(
        "a/b#1", wake_digest=wake_digest, result_digest="result", stage="PR_OPEN"
    )

    assert store.recovery_candidates(min_age_minutes=90) == []


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


def test_interrupted_validation_followup_can_enter_controlled_recovery(tmp_path):
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
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest")

    candidate = store.recovery_candidates(min_age_minutes=0)[0]

    assert candidate["threadId"] == "thread-1"
    assert candidate["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert candidate["followupDigest"] == "result-digest"
    store.reserve_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])
    assert store.unresolved_recoveries()[0]["threadId"] == "thread-1"

    store.record_task_result_ingested(
        "a/b#1", digest="new-result-digest", stage="VALIDATION_PENDING"
    )

    assert store.recovery_candidates(min_age_minutes=0) == []
    assert store.unresolved_recoveries() == []


def test_repeatedly_interrupted_recovery_is_terminal_and_releases_wip(tmp_path):
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
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest")
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_SENT'""",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )

    pending = store.sent_recoveries_without_result()

    assert pending[0]["threadId"] == "thread-1"
    assert store.stale_validation_followups(min_age_minutes=90)[0]["threadId"] == "thread-1"
    store.exhaust_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    assert store.sent_recoveries_without_result() == []
    assert store.recovery_candidates(min_age_minutes=0) == []
    assert store.stale_validation_followups(min_age_minutes=90) == []
    assert store.active_task_count() == 0
    assert store.validation_no_progress()[0]["reason"] == "RECOVERY_RETRY_EXHAUSTED"
    assert store.rearm_validation_no_progress_for_review(
        key="a/b#1",
        result_digest="result-digest",
        review_marker="dependency-prefetch",
        reason="DEPENDENCY_PREFETCH_AVAILABLE",
    )
    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest"

    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="new-result-digest",
        missing=["independent_review_passed"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="new-result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="new-result-digest")

    rearmed = store.recovery_candidates(min_age_minutes=0)

    assert rearmed[0]["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert rearmed[0]["followupDigest"] == "new-result-digest"


def test_reconcile_backfills_exhausted_validation_recovery_no_progress(tmp_path):
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
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest")
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.exhaust_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    with store.connect() as connection:
        connection.execute(
            """DELETE FROM events
               WHERE opportunity_key='a/b#1'
                 AND event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                 AND dedupe_key='result-digest'"""
        )

    assert store.validation_no_progress() == []
    assert store.reconcile_validation_no_progress() == 1
    assert store.validation_no_progress()[0]["reason"] == "RECOVERY_RETRY_EXHAUSTED"


def test_completed_task_can_enter_controlled_validation(tmp_path):
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
    store.record_stage("a/b#1", "PR_OPEN")

    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="completed-result",
        missing=["fresh_state_verified"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")

    assert store.validation_followup_candidates()[0]["resultDigest"] == "completed-result"


def test_validation_reservation_excludes_its_own_intent_inside_transaction(tmp_path):
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
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")

    with pytest.raises(LedgerError, match="does not match the task"):
        store.reserve_validation_followup(
            thread_id="thread-1",
            result_digest="result-digest",
            max_active=1,
            exclude_intent_id="another-intent",
        )
    reserved = store.reserve_validation_followup(
        thread_id="thread-1",
        result_digest="result-digest",
        max_active=1,
        exclude_intent_id="intent-1",
    )

    assert reserved["intentId"] == "intent-1"


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
    assert store.validation_no_progress() == []
    assert store.stale_validation_followups(min_age_minutes=90) == []

    assert store.validation_followup_was_sent(thread_id="thread-1") is True
    assert store.validation_followup_was_sent(thread_id="missing-thread") is False


def test_validation_followup_unknown_delivery_can_be_safely_abandoned(tmp_path):
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
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_RESERVED'""",
            (iso_z(datetime.now(UTC) - timedelta(hours=2)),),
        )

    store.abandon_validation_followup_delivery(
        thread_id="thread-1",
        result_digest="result-digest-1",
        reason="TARGET_TURN_NOT_MATERIALIZED",
        min_age_minutes=90,
    )

    assert store.unresolved_validation_followups() == []
    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest-1"

    retry = store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")

    assert retry["attempt"] == 2
    assert store.unresolved_validation_followups()[0]["resultDigest"] == "result-digest-1"
    with store.connect() as connection:
        reservations = connection.execute(
            """SELECT COUNT(*) AS total,COUNT(DISTINCT dedupe_key) AS distinct_total
               FROM events WHERE event_type='VALIDATION_FOLLOWUP_RESERVED'"""
        ).fetchone()
    assert reservations["total"] == 2
    assert reservations["distinct_total"] == 2


def test_validation_followup_stops_when_a_new_result_has_the_same_gap(tmp_path):
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
        missing=["relevant_tests_green", "regression_test_verified"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")

    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-2",
        missing=["regression_test_verified", "relevant_tests_green"],
    )

    assert store.validation_followup_candidates() == []
    blocked = store.validation_no_progress()
    assert blocked[0]["resultDigest"] == "result-digest-2"
    assert blocked[0]["previousResultDigest"] == "result-digest-1"
    assert blocked[0]["missing"] == [
        "regression_test_verified",
        "relevant_tests_green",
    ]
    assert blocked[0]["reason"] == "UNCHANGED_VALIDATION_GAP"
    assert store.reconcile_validation_no_progress() == 0

    assert (
        store.rearm_validation_no_progress_for_review(
            key="a/b#1",
            result_digest="result-digest-2",
            review_marker="review-fail-digest",
            reason="CONTROLLER_REVIEW_FEEDBACK_AVAILABLE",
        )
        is True
    )
    assert store.validation_no_progress() == []
    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest-2"
    assert (
        store.rearm_validation_no_progress_for_review(
            key="a/b#1",
            result_digest="result-digest-2",
            review_marker="review-fail-digest",
            reason="CONTROLLER_REVIEW_FEEDBACK_AVAILABLE",
        )
        is False
    )


def test_validation_followup_continues_when_check_evidence_changes(tmp_path):
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
        progress_marker="dependencies-missing",
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")

    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-2",
        missing=["relevant_tests_green"],
        progress_marker="focused-test-failure",
    )

    assert store.validation_no_progress() == []
    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest-2"


def test_validation_dependency_prefetch_rearm_is_one_shot_across_result_digests(tmp_path):
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
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-2",
        missing=["relevant_tests_green"],
    )
    assert store.rearm_validation_no_progress_for_review(
        key="a/b#1",
        result_digest="result-digest-2",
        review_marker="same-prefetch-plan",
        reason="DEPENDENCY_PREFETCH_AVAILABLE",
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-2")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-2")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-3",
        missing=["relevant_tests_green"],
    )

    assert (
        store.rearm_validation_no_progress_for_review(
            key="a/b#1",
            result_digest="result-digest-3",
            review_marker="same-prefetch-plan",
            reason="DEPENDENCY_PREFETCH_AVAILABLE",
        )
        is False
    )
    assert store.validation_no_progress()[0]["resultDigest"] == "result-digest-3"


def test_validation_rearm_requires_changed_evidence_across_result_digests(tmp_path):
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
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-2",
        missing=["relevant_tests_green"],
    )
    assert store.rearm_validation_no_progress_for_review(
        key="a/b#1",
        result_digest="result-digest-2",
        review_marker="same-review-evidence",
        reason="CONTROLLER_REVIEW_FEEDBACK_AVAILABLE",
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-2")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-2")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-3",
        missing=["relevant_tests_green"],
    )

    assert (
        store.rearm_validation_no_progress_for_review(
            key="a/b#1",
            result_digest="result-digest-3",
            review_marker="same-review-evidence",
            reason="CONTROLLER_REVIEW_FEEDBACK_AVAILABLE",
        )
        is False
    )
    assert store.validation_no_progress()[0]["resultDigest"] == "result-digest-3"
    assert store.rearm_validation_no_progress_for_review(
        key="a/b#1",
        result_digest="result-digest-3",
        review_marker="changed-review-evidence",
        reason="CONTROLLER_REVIEW_FEEDBACK_AVAILABLE",
    )
    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest-3"


def test_first_validation_result_is_not_mistaken_for_no_progress(tmp_path):
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

    assert store.reconcile_validation_no_progress() == 0
    assert store.validation_no_progress() == []
    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest-1"


@pytest.mark.parametrize(
    ("publication_status", "expected_candidates"),
    [("PENDING", 0), ("GRANTED", 0), ("CONSUMED", 1), ("BLOCKED", 1)],
)
def test_task_result_candidate_is_blocked_only_by_active_publication(
    tmp_path, publication_status, expected_candidates
):
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
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    now = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,reason,permit_id,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "request-1",
                "a/b#1",
                "thread-1",
                "a" * 40,
                "fix/test",
                "/tmp/worktree",
                "evidence",
                publication_status,
                None,
                None,
                "{}",
                now,
                now,
            ),
        )

    assert len(store.task_result_candidates()) == expected_candidates


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
    published_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    now = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/1-runtime','/tmp/worktree',
                       'evidence','CONSUMED','{}',?,?)""",
            ("a" * 40, published_at, published_at),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/1-runtime','CONSUMED',?,'https://github.com/a/b/pull/9','{}',?,?)""",
            (
                "a" * 40,
                iso_z(datetime.now(UTC) + timedelta(hours=1)),
                published_at,
                published_at,
            ),
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
    assert imported == {
        "matched": 1,
        "inserted": 1,
        "updated": 0,
        "staleHeadSuppressed": 0,
    }
    assert candidate["threadId"] == "thread-1"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "prFollowup"
        ]["headSha"]
        == "b" * 40
    )

    original_wake = candidate["wakeDigest"]
    assert store.suspend_pr_followups(
        source_generated_at=now,
        reason="CLOUD_PR_FOLLOWUP_STATE_STALE",
    ) == ["a/b#1"]
    assert store.pr_followup_candidates() == []
    store.import_pr_followups(state)
    candidate = store.pr_followup_candidates()[0]
    assert candidate["wakeDigest"] != original_wake

    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha="d" * 40,
    )
    assert store.pr_followup_candidates() == []
    assert store.unresolved_pr_followups()
    bound = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
        "prFollowup"
    ]
    assert bound["headSha"] == "b" * 40
    assert bound["preparedHeadSha"] == "d" * 40
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='PR_FOLLOWUP_RESERVED' AND dedupe_key=?""",
            (
                iso_z(datetime.now(UTC) - timedelta(hours=2)),
                candidate["wakeDigest"],
            ),
        )
    replacement = store.abandon_pr_followup_delivery(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        reason="TARGET_TURN_NOT_MATERIALIZED",
    )
    assert store.unresolved_pr_followups() == []
    candidate = store.pr_followup_candidates()[0]
    assert candidate["wakeDigest"] == replacement["replacementWakeDigest"]
    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha="d" * 40,
    )
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    assert store.unresolved_pr_followups() == []

    store.import_pr_followups(state)
    assert store.pr_followup_candidates() == []

    state["items"][0]["headSha"] = "c" * 40
    state["items"][0]["checkedAt"] = iso_z(datetime.now(UTC) + timedelta(minutes=1))
    store.import_pr_followups(state)
    assert store.pr_followup_candidates() == []
    still_bound = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )["prFollowup"]
    assert still_bound["headSha"] == "b" * 40
    assert still_bound["preparedHeadSha"] == "d" * 40

    previous_wake = candidate["wakeDigest"]
    store.record_stage("a/b#1", "FIX_READY", evidence={field: True for field in QUALITY_FIELDS})
    worktree, base_sha, head_sha, branch, probe_receipt, result_digest, evidence_path = (
        legal_publication_probe(tmp_path)
    )
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET worktree_path=? WHERE intent_id='intent-1'",
            (str(worktree),),
        )
    update = store.create_publication_request(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        commit_sha=head_sha,
        branch="fix/1-runtime",
        worktree_path=str(worktree),
        evidence_digest="update-evidence",
        evidence_path=str(evidence_path),
        publication={
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: runtime",
            "bodyPath": str(worktree / ".oss-pr-radar" / "pr-body.md"),
        },
        probe_receipt=probe_receipt,
        result_digest=result_digest,
        head_sha=head_sha,
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
    )
    assert update["request"]["publicationKind"] == "PR_UPDATE"
    permit = store.grant_publication_request(
        update["request_id"],
        issue_url="https://github.com/a/b/issues/1",
        commit_sha=head_sha,
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
    with pytest.raises(LedgerError, match="authenticated reproduction is required"):
        store.publication_effect(
            permit_id=permit_id,
            action="push",
            request_digest="push-request",
        )
    assert store.publication_request(request_id)["status"] == "BLOCKED"
    assert store.publication_request(request_id)["reason"] == "BLOCKED_REPRODUCTION_REQUIRED"
    assert store.publication_work_items() == []


def test_interrupted_push_effect_can_retry_after_confirmed_noop(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    old = iso_z(datetime.now(UTC) - timedelta(minutes=10))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/runtime','/tmp/worktree',
                       'evidence','GRANTED','{}',?,?)""",
            ("b" * 40, old, old),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/runtime','EXPIRED',?,'{}',?,?)""",
            ("b" * 40, old, old, old),
        )
        connection.execute(
            """INSERT INTO publication_effects
               (effect_id,permit_id,action,request_digest,status,result_json,created_at,updated_at)
               VALUES ('effect-1','permit-1','push','digest','ATTEMPTED','{}',?,?)""",
            (old, old),
        )

    assert store.prepare_ambiguous_publication_effect("request-1", action="push") is None
    with store.connect() as connection:
        status = connection.execute(
            "SELECT status FROM publication_effects WHERE effect_id='effect-1'"
        ).fetchone()["status"]
    assert status == "BLOCKED"
    assert store.publication_request("request-1")["status"] == "BLOCKED"


def test_transient_pr_creation_effect_can_refresh_and_retry_after_confirmed_noop(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    old = iso_z(datetime.now(UTC) - timedelta(minutes=10))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/runtime','/tmp/worktree',
                       'evidence','GRANTED',?,?,?)""",
            (
                "b" * 40,
                json.dumps({"publicationKind": "PR_CREATE"}),
                old,
                old,
            ),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/runtime','EXPIRED',?,'{}',?,?)""",
            ("b" * 40, old, old, old),
        )
        connection.execute(
            """INSERT INTO publication_effects
               (effect_id,permit_id,action,request_digest,status,result_json,created_at,updated_at)
               VALUES ('push-1','permit-1','push','push-digest','SUCCEEDED','{}',?,?)""",
            (old, old),
        )
        connection.execute(
            """INSERT INTO publication_effects
               (effect_id,permit_id,action,request_digest,status,result_json,created_at,updated_at)
               VALUES ('create-1','permit-1','create_pr','create-digest',
                       'RECONCILE_REQUIRED',?, ?, ?)""",
            (
                json.dumps(
                    {
                        "ok": False,
                        "reason": "PR_CREATION_NOT_RECONCILED",
                        "detail": "HTTP 503: service unavailable",
                    }
                ),
                old,
                old,
            ),
        )

    permit = store.prepare_post_push_reconciliation("request-1")

    assert permit["status"] == "ACTIVE"
    assert parse_time(permit["expires_at"]) > datetime.now(UTC)
    with pytest.raises(LedgerError, match="authenticated reproduction is required"):
        store.retry_publication_effect_after_noop(
            effect_id="create-1",
            permit_id="permit-1",
            evidence={"exactHeadPrAbsent": True},
        )


def test_deferred_publication_preflight_is_rearmed_without_ambiguous_effect(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    insert_publication_preflight(store)

    store.resolve_publication_preflight(
        "effect-1",
        disposition="DEFER",
        reason="LIVE_EVIDENCE_INCOMPLETE",
    )

    request = store.publication_request("request-1")
    assert request["status"] == "PENDING"
    assert request["reason"] == "LIVE_EVIDENCE_INCOMPLETE"
    with store.connect() as connection:
        permit = connection.execute(
            "SELECT status FROM publication_permits WHERE permit_id='permit-1'"
        ).fetchone()
        effect = connection.execute(
            "SELECT 1 FROM publication_effects WHERE effect_id='effect-1'"
        ).fetchone()
    assert permit["status"] == "EXPIRED"
    assert effect is None


def test_legacy_failed_live_recheck_is_recovered_for_retry(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    insert_publication_preflight(
        store,
        effect_status="FAILED",
        effect_result={
            "ok": False,
            "reason": "LIVE_RECHECK_FAILED",
            "detail": "LIVE_EVIDENCE_INCOMPLETE",
        },
    )

    recovered = store.recover_failed_publication_preflight(
        "request-1",
        action="push",
        transient_reasons={"LIVE_EVIDENCE_INCOMPLETE"},
    )

    assert recovered is True
    assert store.publication_request("request-1")["status"] == "PENDING"
    with store.connect() as connection:
        permit = connection.execute(
            "SELECT status FROM publication_permits WHERE permit_id='permit-1'"
        ).fetchone()
        effect = connection.execute(
            "SELECT 1 FROM publication_effects WHERE effect_id='effect-1'"
        ).fetchone()
    assert permit["status"] == "EXPIRED"
    assert effect is None


def test_publication_feedback_is_reserved_retried_and_sent_once(tmp_path):
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
    pr_url = "https://github.com/a/b/pull/9"
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": pr_url}, dedupe_key=pr_url)

    candidate = store.publication_feedback_candidates()[0]
    reserved = store.reserve_publication_feedback(
        thread_id=candidate["threadId"],
        pr_url=candidate["prUrl"],
    )

    assert store.publication_feedback_candidates() == []
    assert (
        store.unresolved_publication_feedback()[0]["reservationNonce"]
        == reserved["reservationNonce"]
    )
    with pytest.raises(LedgerError, match="stale or already reserved"):
        store.reserve_publication_feedback(thread_id="thread-1", pr_url=pr_url)

    store.abandon_publication_feedback(
        thread_id="thread-1",
        reservation_nonce=reserved["reservationNonce"],
        reason="VISIBLE_STATUS_DELIVERY_INCOMPLETE",
        min_age_minutes=0,
    )
    retry = store.reserve_publication_feedback(thread_id="thread-1", pr_url=pr_url)
    assert retry["reservationNonce"] != reserved["reservationNonce"]

    store.commit_publication_feedback(
        thread_id="thread-1",
        reservation_nonce=retry["reservationNonce"],
    )
    assert store.publication_feedback_candidates() == []
    assert store.unresolved_publication_feedback() == []


def test_pr_followup_task_drift_rebinds_wake_and_invalidates_preparation(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent(autoSubmitAuthorized=True, publicSubmissionAllowed=True))
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
    old_wake = "e" * 64
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO pr_followups
               (opportunity_key,pr_url,head_sha,action_digest,task_action_digest,wake_digest,
                actions_json,evidence_json,followup_required,checked_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "a/b#1",
                "https://github.com/a/b/pull/9",
                "b" * 40,
                "action",
                "task-action",
                old_wake,
                json.dumps(["当前分支检查失败"]),
                json.dumps({"actionableCheckNames": ["Ruff"]}),
                1,
                now,
                now,
            ),
        )
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?)""",
            (
                "a/b#1",
                "PR_FOLLOWUP_RESERVED",
                old_wake,
                json.dumps({"threadId": "thread-1", "prUrl": "https://github.com/a/b/pull/9"}),
                now,
            ),
        )
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?)""",
            (
                "a/b#1",
                "PR_FOLLOWUP_PREPARATION_BOUND",
                old_wake,
                json.dumps({"threadId": "thread-1", "snapshot": {}}),
                now,
            ),
        )

    rebound = store.rearm_pr_followup_after_task_drift(
        "a/b#1",
        expected_prepared_head_sha="c" * 40,
        observed_head_sha="d" * 40,
    )

    assert rebound["previousWakeDigest"] == old_wake
    assert rebound["replacementWakeDigest"] != old_wake
    assert store.active_pr_followup_preparation("a/b#1", thread_id="thread-1") is None
    assert store.pr_followup_candidates()[0]["wakeDigest"] == rebound["replacementWakeDigest"]
    repeated = store.rearm_pr_followup_after_task_drift(
        "a/b#1",
        expected_prepared_head_sha="c" * 40,
        observed_head_sha="d" * 40,
    )
    assert repeated == {**rebound, "created": False}
    assert store.pr_followup_rebind_status("a/b#1")["observedHeadSha"] == "d" * 40


def test_task_quarantine_blocks_pending_publication_until_cleared(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        connection.execute(
            """INSERT INTO opportunities
               (key,repo,issue_number,issue_url,title,stage,first_seen,updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                "a/b#1",
                "a/b",
                1,
                "https://github.com/a/b/issues/1",
                "Bug",
                "FIX_READY",
                now,
                now,
            ),
        )
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "request-1",
                "a/b#1",
                "thread-1",
                "a" * 40,
                "fix/runtime",
                str(tmp_path / "worktree"),
                "evidence",
                "PENDING",
                json.dumps({"opportunityKey": "a/b#1"}),
                now,
                now,
            ),
        )
        from oss_pr_radar.task_quarantine import record

        record(
            connection,
            opportunity_key="a/b#1",
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-1",
            payload={"requiresExplicitMigration": True},
            created_at=now,
        )

    assert store.active_task_quarantine("a/b#1") is not None
    assert store.publication_work_items() == []

    store.clear_task_quarantine(
        "a/b#1",
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        evidence={"revalidated": True, "migrationId": "m-1"},
    )
    assert store.active_task_quarantine("a/b#1") is None
    assert [item["request_id"] for item in store.publication_work_items()] == ["request-1"]
