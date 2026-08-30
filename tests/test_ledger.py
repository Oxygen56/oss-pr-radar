import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from oss_pr_radar.ledger import (
    LedgerError,
    RadarLedger,
    bind_dispatched_recovery_prompt,
)
from oss_pr_radar.metrics import QUALITY_FIELDS, assess_submit_ready, rolling_quality
from oss_pr_radar.util import iso_z, parse_time, sha256_json, sha256_text

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


def repository_path_receipt(base_sha: str, code_paths: list[str]) -> dict[str, Any]:
    from oss_pr_radar.repo_probe import run_repo_probe

    class RepositoryClient:
        def repository(self, repo):
            assert repo == "a/b"
            return {"default_branch": "main"}

        def branch(self, repo, branch):
            assert (repo, branch) == ("a/b", "main")
            return {"commit": {"sha": base_sha}}

        def repository_tree(self, repo, ref):
            assert (repo, ref) == ("a/b", base_sha)
            return [{"path": path, "type": "blob"} for path in code_paths]

    return run_repo_probe(
        RepositoryClient(),
        repo="a/b",
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=code_paths,
    )


def refreshed_repository_path_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    from oss_pr_radar.repo_probe import _signed_receipt

    now = datetime.now(UTC) + timedelta(seconds=1)
    payload = {
        key: value
        for key, value in receipt.items()
        if key not in {"keyId", "signature", "receiptDigest", "observedAt", "expiresAt"}
    }
    payload["observedAt"] = iso_z(now)
    payload["expiresAt"] = iso_z(now + timedelta(minutes=30))
    payload["receiptDigest"] = sha256_json(payload)
    return _signed_receipt(payload)


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


def publication_request_fixture(tmp_path: Path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    worktree, base_sha, head_sha, branch, probe_receipt, result_digest, evidence_path = (
        legal_publication_probe(tmp_path)
    )
    store.enqueue(
        intent(
            mode="canary",
            publicationMode="canary",
            publicSubmissionAllowed=True,
            autoSubmitAuthorized=True,
            authorizationSource="signed_live_revalidation_required",
            worktree=str(worktree),
            llmReview={
                "status": "ok",
                "decision": "NEW_CLEAN_CANDIDATE",
                "semanticSignal": "NO_OBJECTION",
                "confidence": 0.9,
            },
        )
    )
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="project-1",
        worktree_path=str(worktree),
    )
    store.record_stage("a/b#1", "FIX_READY", evidence={field: True for field in QUALITY_FIELDS})
    args = {
        "issue_url": "https://github.com/a/b/issues/1",
        "thread_id": "thread-1",
        "commit_sha": head_sha,
        "branch": branch,
        "worktree_path": str(worktree),
        "evidence_digest": "evidence-digest",
        "evidence_path": str(evidence_path),
        "publication": {
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: runtime",
            "bodyPath": str(worktree / ".oss-pr-radar" / "pr-body.md"),
        },
        "probe_receipt": probe_receipt,
        "result_digest": result_digest,
        "head_sha": head_sha,
        "selected_base_sha": base_sha,
        "code_paths": ["runtime.py"],
    }
    return store, args


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
        "category": "NEW_CLEAN_CANDIDATE",
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
    assert context["category"] == "NEW_CLEAN_CANDIDATE"
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


@pytest.mark.parametrize("update_status", ["PENDING", "BLOCKED"])
def test_task_context_keeps_consumed_pr_until_update_is_consumed(tmp_path, update_status):
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
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": "https://github.com/a/b/pull/9"})
    published_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    update_at = iso_z(datetime.now(UTC) - timedelta(minutes=1))
    old_commit = "a" * 40
    new_commit = "b" * 40
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-create','a/b#1','thread-1',?,'fix/runtime','/tmp/worktree',
                       'evidence-create','CONSUMED','{}',?,?)""",
            (old_commit, published_at, published_at),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-create','request-create','https://github.com/a/b/issues/1',?,
                       'fix/runtime','CONSUMED',?,'https://github.com/a/b/pull/9','{}',?,?)""",
            (
                old_commit,
                iso_z(datetime.now(UTC) + timedelta(hours=1)),
                published_at,
                published_at,
            ),
        )
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,reason,request_json,created_at,updated_at)
               VALUES ('request-update','a/b#1','thread-1',?,'fix/runtime','/tmp/worktree',
                       'evidence-update',?,?,'{"publicationKind":"PR_UPDATE"}',?,?)""",
            (
                new_commit,
                update_status,
                "ACTIVE_OR_CONDITIONAL_CLAIM" if update_status == "BLOCKED" else None,
                update_at,
                update_at,
            ),
        )

    pending_context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )

    assert pending_context is not None
    assert pending_context["publicationReceipt"] == {
        "status": "PR_OPEN",
        "prUrl": "https://github.com/a/b/pull/9",
        "commitSha": old_commit,
        "branch": "fix/runtime",
        "requestedAt": published_at,
        "updatedAt": published_at,
    }

    consumed_at = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """UPDATE publication_requests
               SET status='CONSUMED',reason=NULL,permit_id='permit-update',updated_at=?
               WHERE request_id='request-update'""",
            (consumed_at,),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-update','request-update','https://github.com/a/b/issues/1',?,
                       'fix/runtime','CONSUMED',?,'https://github.com/a/b/pull/9','{}',?,?)""",
            (
                new_commit,
                iso_z(datetime.now(UTC) + timedelta(hours=1)),
                update_at,
                consumed_at,
            ),
        )

    consumed_context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )

    assert consumed_context is not None
    assert consumed_context["publicationReceipt"] == {
        "status": "PR_OPEN",
        "prUrl": "https://github.com/a/b/pull/9",
        "commitSha": new_commit,
        "branch": "fix/runtime",
        "requestedAt": update_at,
        "updatedAt": consumed_at,
    }


@pytest.mark.parametrize("request_status", ["PENDING", "BLOCKED"])
def test_task_context_without_consumed_pr_projects_current_request(tmp_path, request_status):
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
    requested_at = iso_z(datetime.now(UTC))
    commit_sha = "b" * 40
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,reason,request_json,created_at,updated_at)
               VALUES ('request-update','a/b#1','thread-1',?,'fix/runtime','/tmp/worktree',
                       'evidence-update',?,?,'{"publicationKind":"PR_UPDATE"}',?,?)""",
            (
                commit_sha,
                request_status,
                "ACTIVE_OR_CONDITIONAL_CLAIM" if request_status == "BLOCKED" else None,
                requested_at,
                requested_at,
            ),
        )

    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )

    assert context is not None
    assert context["publicationReceipt"] == {
        "status": request_status,
        "prUrl": None,
        "commitSha": commit_sha,
        "branch": "fix/runtime",
        "requestedAt": requested_at,
        "updatedAt": requested_at,
    }


def test_published_context_recovery_ignores_expired_prepublication_freshness(tmp_path):
    old = iso_z(datetime.now(UTC) - timedelta(hours=2))
    context = published_task_context(liveAuditRecordedAt=old)
    context["liveAudit"]["capturedAt"] = old
    context["liveAudit"]["evidence"]["issue"]["updated_at"] = old
    context["publicationReceipt"]["requestedAt"] = old
    context["publicationReceipt"]["updatedAt"] = old
    path = tmp_path / "ledger.sqlite3"

    store = RadarLedger(path)
    restored = store.restore_task_context(context)

    assert restored["publicationRestored"] is True
    with store.connect() as connection:
        request = connection.execute("SELECT status,reason FROM publication_requests").fetchone()
        permit = connection.execute("SELECT status,pr_url FROM publication_permits").fetchone()
    assert dict(request) == {"status": "CONSUMED", "reason": None}
    assert dict(permit) == {
        "status": "CONSUMED",
        "pr_url": "https://github.com/a/b/pull/9",
    }

    reopened = RadarLedger(path)
    assert (
        reopened.publication_request(
            sha256_text("task-context-recovery|a/b#1|https://github.com/a/b/pull/9|" + "a" * 40)
        )["status"]
        == "CONSUMED"
    )


def test_terminal_publication_self_heals_and_cannot_be_blocked(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    store = RadarLedger(path)
    insert_publication_preflight(store)
    old = iso_z(datetime.now(UTC) - timedelta(hours=2))
    pr_url = "https://github.com/a/b/pull/9"
    with store.connect() as connection:
        connection.execute(
            """UPDATE publication_requests
               SET status='BLOCKED',reason='BLOCKED_REPRODUCTION_REQUIRED',updated_at=?
               WHERE request_id='request-1'""",
            (old,),
        )
        connection.execute(
            """UPDATE publication_permits
               SET status='CONSUMED',pr_url=?,updated_at=?
               WHERE permit_id='permit-1'""",
            (pr_url, old),
        )
        connection.execute(
            """UPDATE publication_effects
               SET effect_id=?,action='create_pr',status='SUCCEEDED',result_json=?,updated_at=?
               WHERE effect_id='effect-1'""",
            (
                sha256_text("permit-1|create_pr|digest"),
                json.dumps({"ok": True, "prUrl": pr_url}),
                old,
            ),
        )
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES ('a/b#1','PR_OPEN',?,?,?)""",
            (pr_url, json.dumps({"permitId": "permit-1", "prUrl": pr_url}), old),
        )
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-2','a/b#1','thread-1',?,'fix/runtime-2','/tmp/worktree',
                       'evidence-2','GRANTED','{}',?,?)""",
            ("c" * 40, old, old),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                evidence_json,created_at,updated_at)
               VALUES ('permit-2','request-2','https://github.com/a/b/issues/1',?,
                       'fix/runtime-2','ACTIVE',?,'{}',?,?)""",
            ("c" * 40, old, old, old),
        )

    reopened = RadarLedger(path)
    assert reopened.publication_request("request-1")["status"] == "CONSUMED"
    assert reopened.publication_request("request-1")["reason"] is None
    assert reopened.publication_request("request-2")["status"] == "BLOCKED"
    assert reopened.publication_request("request-2")["reason"] == "BLOCKED_REPRODUCTION_REQUIRED"

    assert (
        reopened.publication_permit(
            issue_url="https://github.com/a/b/issues/1",
            commit_sha="b" * 40,
            branch="fix/runtime",
        )
        is None
    )
    assert reopened.publication_permit_by_id("permit-1") is None
    terminal_permit = reopened.publication_permit_for_effect("permit-1", action="create_pr")
    assert terminal_permit is not None
    assert terminal_permit["status"] == "CONSUMED"
    terminal_effect = reopened.publication_effect_by_request(
        permit_id="permit-1", action="create_pr", request_digest="digest"
    )
    assert terminal_effect is not None
    assert terminal_effect["status"] == "SUCCEEDED"
    assert (
        reopened.publication_effect(
            permit_id="permit-1", action="create_pr", request_digest="digest"
        )["created"]
        is False
    )
    with reopened.connect() as connection:
        permit_status = connection.execute(
            "SELECT status FROM publication_permits WHERE permit_id='permit-1'"
        ).fetchone()[0]
    assert permit_status == "CONSUMED"

    reopened.block_publication_request(
        "request-1", "BLOCKED_REPRODUCTION_REQUIRED", evidence={"probeFresh": False}
    )

    assert reopened.publication_request("request-1")["status"] == "CONSUMED"
    assert reopened.publication_request("request-1")["reason"] is None


def test_published_terminal_missing_worktree_gate_requires_followup_result(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.restore_task_context(published_task_context())
    store.record_task_result_ingested("a/b#1", digest="result", stage="PR_OPEN")
    store.import_pr_followups(
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
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(
        thread_id="thread-recovered",
        wake_digest=candidate["wakeDigest"],
    )
    store.commit_pr_followup(
        thread_id="thread-recovered",
        wake_digest=candidate["wakeDigest"],
    )

    assert not store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )

    store.record_followup_result(
        "a/b#1",
        wake_digest=candidate["wakeDigest"],
        result_digest="followup-result",
        stage="PR_OPEN",
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def _published_terminal_with_validation_followup(
    tmp_path: Path,
    *,
    result_digest: str = "validation-result",
    thread_id: str = "thread-recovered",
) -> tuple[RadarLedger, dict[str, Any]]:
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.restore_task_context(
        published_task_context(
            threadId=thread_id,
            worktreePath=f"/tmp/{thread_id}-worktree",
            resultPath=f"/tmp/{thread_id}-worktree/.oss-pr-radar/result.json",
        )
    )
    store.record_task_result_ingested("a/b#1", digest="published-result", stage="CI_GREEN")
    assert store.published_task_result_is_terminal("a/b#1", thread_id=thread_id)
    store.record_validation_deferred(
        "a/b#1",
        thread_id=thread_id,
        result_digest=result_digest,
        missing=["independent_review_passed"],
    )
    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"resultDigest": result_digest},
        dedupe_key=f"validation:{result_digest}",
    )
    reservation = store.reserve_validation_followup(
        thread_id=thread_id,
        result_digest=result_digest,
    )
    store.record_stage(
        "a/b#1",
        "CI_GREEN",
        evidence={"prUrl": "https://github.com/a/b/pull/9"},
        dedupe_key=f"ci-green:{result_digest}",
    )
    return store, reservation


def _insert_validation_event(
    store: RadarLedger,
    *,
    event_type: str,
    dedupe_key: str,
    payload: dict[str, Any],
) -> None:
    with store.connect() as connection:
        store._event(
            connection,
            "a/b#1",
            event_type,
            dedupe_key,
            payload,
            iso_z(datetime.now(UTC)),
        )


def test_published_terminal_missing_worktree_gate_blocks_unfinished_validation_reservation(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)

    assert not store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_blocks_unfinished_validation_sent(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    store.commit_validation_followup(
        thread_id="thread-recovered",
        result_digest="validation-result",
    )

    assert not store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_allows_cancelled_validation_reservation(
    tmp_path,
):
    store, reservation = _published_terminal_with_validation_followup(tmp_path)

    store.cancel_validation_followup_reservation(
        thread_id="thread-recovered",
        result_digest="validation-result",
        reservation_digest=reservation["reservationDigest"],
        reason="VALIDATION_RESULT_CHANGED_AFTER_RESERVE",
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_allows_abandoned_validation_reservation(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    with store.connect() as connection:
        connection.execute(
            "UPDATE events SET created_at=? WHERE event_type='VALIDATION_FOLLOWUP_RESERVED'",
            (iso_z(datetime.now(UTC) - timedelta(hours=2)),),
        )

    store.abandon_validation_followup_delivery(
        thread_id="thread-recovered",
        result_digest="validation-result",
        reason="TARGET_TURN_NOT_MATERIALIZED",
        min_age_minutes=90,
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_allows_ingested_validation_result(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    store.commit_validation_followup(
        thread_id="thread-recovered",
        result_digest="validation-result",
    )

    store.record_task_result_ingested(
        "a/b#1",
        digest="post-validation-result",
        stage="CI_GREEN",
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_allows_no_progress_validation_result(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"resultDigest": "validation-result"},
        dedupe_key="validation:recovery",
    )
    store.commit_validation_followup(
        thread_id="thread-recovered",
        result_digest="validation-result",
    )
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-recovered", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-recovered", nonce=recovery["recoveryNonce"])
    store.exhaust_recovery(thread_id="thread-recovered", nonce=recovery["recoveryNonce"])
    store.record_stage(
        "a/b#1",
        "CI_GREEN",
        evidence={"prUrl": "https://github.com/a/b/pull/9"},
        dedupe_key="ci-green:no-progress",
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_keeps_rearmed_validation_scoped(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    _insert_validation_event(
        store,
        event_type="VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
        dedupe_key="review-1",
        payload={
            "threadId": "thread-recovered",
            "resultDigest": "other-validation-result",
            "reviewMarker": "other",
            "reason": "DEPENDENCY_PREFETCH_AVAILABLE",
        },
    )

    assert not store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )

    _insert_validation_event(
        store,
        event_type="VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
        dedupe_key="review-2",
        payload={
            "threadId": "thread-recovered",
            "resultDigest": "validation-result",
            "reviewMarker": "dependency-prefetch",
            "reason": "DEPENDENCY_PREFETCH_AVAILABLE",
        },
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_scopes_validation_by_thread(
    tmp_path,
):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.restore_task_context(published_task_context())
    store.record_task_result_ingested("a/b#1", digest="published-result", stage="CI_GREEN")
    _insert_validation_event(
        store,
        event_type="VALIDATION_FOLLOWUP_RESERVED",
        dedupe_key="other-reservation",
        payload={
            "threadId": "other-thread",
            "resultDigest": "validation-result",
            "missing": ["independent_review_passed"],
            "reservationDigest": "other-reservation",
        },
    )

    assert store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_does_not_use_wrong_thread_closure(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    _insert_validation_event(
        store,
        event_type="VALIDATION_FOLLOWUP_NO_PROGRESS",
        dedupe_key="validation-result",
        payload={
            "threadId": "other-thread",
            "resultDigest": "validation-result",
            "previousResultDigest": "validation-result",
            "missing": ["independent_review_passed"],
            "reason": "UNCHANGED_VALIDATION_GAP",
        },
    )
    _insert_validation_event(
        store,
        event_type="VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
        dedupe_key="other-thread-review",
        payload={
            "threadId": "other-thread",
            "resultDigest": "validation-result",
            "reviewMarker": "dependency-prefetch",
            "reason": "DEPENDENCY_PREFETCH_AVAILABLE",
        },
    )

    assert not store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


def test_published_terminal_missing_worktree_gate_does_not_use_wrong_digest_closure(
    tmp_path,
):
    store, _reservation = _published_terminal_with_validation_followup(tmp_path)
    _insert_validation_event(
        store,
        event_type="VALIDATION_FOLLOWUP_NO_PROGRESS",
        dedupe_key="other-validation-result",
        payload={
            "threadId": "thread-recovered",
            "resultDigest": "other-validation-result",
            "previousResultDigest": "other-validation-result",
            "missing": ["independent_review_passed"],
            "reason": "UNCHANGED_VALIDATION_GAP",
        },
    )

    assert not store.published_task_result_is_terminal(
        "a/b#1",
        thread_id="thread-recovered",
    )


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
    assert second["stage"] == "PR_OPEN"
    current = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-recovered",
    )
    assert current is not None
    assert current["stage"] == "PR_OPEN"
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


@pytest.mark.parametrize(
    "published_stage",
    ["PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED", "MERGED", "CLOSED"],
)
def test_published_stage_preserves_validation_as_a_substate(tmp_path, published_stage):
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
    if published_stage != "PR_OPEN":
        store.record_stage(
            "a/b#1", published_stage, evidence={"prUrl": "https://example.test/pr/1"}
        )

    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"missing": ["relevant_tests_green"]},
        dedupe_key="validation-result-1",
    )

    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage,terminal_reason FROM opportunities WHERE key='a/b#1'"
        ).fetchone()
        preserved = connection.execute(
            """SELECT payload_json FROM events WHERE opportunity_key='a/b#1'
               AND event_type='POST_PUBLICATION_STAGE_PRESERVED'
               AND dedupe_key='validation-result-1'"""
        ).fetchone()
    assert dict(opportunity) == {"stage": published_stage, "terminal_reason": None}
    payload = json.loads(preserved["payload_json"])
    assert payload["preservedStage"] == published_stage
    assert payload["requestedStage"] == "VALIDATION_PENDING"


def test_replayed_stage_receipt_cannot_undo_later_result(tmp_path):
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
    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"missing": ["independent_review_passed"]},
        dedupe_key="older-result",
    )
    store.record_stage(
        "a/b#1",
        "FIX_READY",
        evidence={field: True for field in QUALITY_FIELDS},
        dedupe_key="reviewed-result",
    )

    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"missing": ["independent_review_passed"]},
        dedupe_key="older-result",
    )

    with store.connect() as connection:
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            "stage"
        ]
        replay_count = connection.execute(
            """SELECT COUNT(*) FROM events WHERE opportunity_key='a/b#1'
               AND event_type='VALIDATION_PENDING' AND dedupe_key='older-result'"""
        ).fetchone()[0]
    assert stage == "FIX_READY"
    assert replay_count == 1


@pytest.mark.parametrize("terminal_stage", ["MERGED", "CLOSED"])
def test_terminal_publication_ignores_stale_validation_quality(tmp_path, terminal_stage):
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
    initial_quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("a/b#1", "FIX_READY", evidence=initial_quality)
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": "https://example.test/pr/1"})
    store.record_stage("a/b#1", terminal_stage, evidence={"prUrl": "https://example.test/pr/1"})
    with store.connect() as connection:
        before = dict(
            connection.execute(
                """SELECT submit_ready_at,quality_json,updated_at FROM outcomes
                   WHERE opportunity_key='a/b#1'"""
            ).fetchone()
        )

    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"missing": ["relevant_tests_green"]},
        dedupe_key="terminal-validation",
    )
    store.record_stage(
        "a/b#1",
        "FIX_READY",
        evidence={field: False for field in QUALITY_FIELDS},
        dedupe_key="terminal-fix-ready",
    )

    with store.connect() as connection:
        opportunity_stage = connection.execute(
            "SELECT stage FROM opportunities WHERE key='a/b#1'"
        ).fetchone()["stage"]
        after = dict(
            connection.execute(
                """SELECT submit_ready_at,quality_json,updated_at FROM outcomes
                   WHERE opportunity_key='a/b#1'"""
            ).fetchone()
        )
    assert opportunity_stage == terminal_stage
    assert after == before


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


def test_state_drift_invalidates_exact_intent_and_allows_fresh_same_digest(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    original = intent(selectedBaseSha="old-base")
    assert store.enqueue(original) is True

    invalidated = store.invalidate_state_drift_intent(
        "a/b#1",
        intent_id="intent-1",
        evidence={
            "issue": {"updated_at": original["issueUpdatedAt"]},
            "selectedBaseSha": "old-base",
            "liveBaseSha": "new-base",
            "evidenceDigest": "live-evidence",
        },
    )

    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage,terminal_reason FROM opportunities WHERE key='a/b#1'"
        ).fetchone()
        old_status = connection.execute(
            "SELECT status FROM intents WHERE intent_id='intent-1'"
        ).fetchone()["status"]
        no_go_events = connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='AUDIT_NO_GO'"
        ).fetchone()[0]
    assert dict(opportunity) == {"stage": "QUALIFIED", "terminal_reason": None}
    assert old_status == "REJECTED"
    assert no_go_events == 0
    assert invalidated["staleBaseSha"] == "old-base"
    assert invalidated["liveBaseSha"] == "new-base"
    assert store.terminal_feedback() == []
    assert store.scanner_recheck_feedback()[0]["intent_id"] == "intent-1"

    replay = original | {"expiresAt": iso_z(datetime.now(UTC) + timedelta(hours=2))}
    assert store.enqueue(replay) is False
    fresh = original | {
        "intentId": "intent-2",
        "issuedAt": iso_z(datetime.now(UTC) + timedelta(seconds=1)),
        "expiresAt": iso_z(datetime.now(UTC) + timedelta(hours=2)),
    }
    assert store.enqueue(fresh) is True
    assert [item["intentId"] for item in store.pending()] == ["intent-2"]

    repeated = store.invalidate_state_drift_intent(
        "a/b#1", intent_id="intent-1", evidence={"liveBaseSha": "ignored"}
    )
    assert repeated["changed"] is False
    assert repeated["recordedAt"] == invalidated["recordedAt"]


def test_state_drift_invalidation_rejects_creating_and_thread_bound_intents(tmp_path):
    creating = RadarLedger(tmp_path / "creating.sqlite3")
    creating.enqueue(intent())
    creating.claim("intent-1", "worker")
    creating.reserve_creation("intent-1", owner="worker")

    with pytest.raises(LedgerError, match="no longer invalidatable"):
        creating.invalidate_state_drift_intent("a/b#1", intent_id="intent-1")
    with creating.connect() as connection:
        assert (
            connection.execute("SELECT status FROM intents WHERE intent_id='intent-1'").fetchone()[
                "status"
            ]
            == "CREATING"
        )
        assert (
            connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
                "stage"
            ]
            == "CREATING"
        )

    bound = RadarLedger(tmp_path / "bound.sqlite3")
    bound.enqueue(intent())
    bound.claim("intent-1", "worker")
    bound.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree",
    )

    with pytest.raises(LedgerError, match="thread-bound"):
        bound.invalidate_state_drift_intent("a/b#1", intent_id="intent-1")
    with bound.connect() as connection:
        assert (
            connection.execute("SELECT status FROM intents WHERE intent_id='intent-1'").fetchone()[
                "status"
            ]
            == "DISPATCHED"
        )


def test_historical_state_drift_migration_is_bounded_and_idempotent(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    original = intent(selectedBaseSha="old-base")
    store.enqueue(original)
    store.record_stage(
        "a/b#1",
        "AUDIT_NO_GO",
        reason="STATE_DRIFT",
        evidence={
            "evidence": {
                "issue": {"updated_at": original["issueUpdatedAt"]},
                "selectedBaseSha": "old-base",
                "liveBaseSha": "new-base",
            }
        },
    )

    migrated = store.invalidate_state_drift_intent(
        "a/b#1", intent_id="intent-1", historical_terminal=True
    )
    repeated = store.invalidate_state_drift_intent(
        "a/b#1", intent_id="intent-1", historical_terminal=True
    )

    assert migrated["changed"] is True
    assert repeated["changed"] is False
    assert repeated["recordedAt"] == migrated["recordedAt"]
    assert store.terminal_feedback() == []
    assert store.scanner_recheck_feedback()[0]["live_base_sha"] == "new-base"


def test_historical_state_drift_migration_rejects_published_opportunity(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.record_stage("a/b#1", "PR_OPEN", evidence={})

    with pytest.raises(LedgerError, match="published"):
        store.invalidate_state_drift_intent("a/b#1", intent_id="intent-1", historical_terminal=True)


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


def test_task_context_prefers_live_audit_verified_paths_over_scanner_plan(tmp_path):
    from oss_pr_radar.repo_probe import _signed_receipt

    base_sha = "a" * 40
    current_receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    expired_payload = {
        key: value
        for key, value in current_receipt.items()
        if key not in {"keyId", "signature", "receiptDigest"}
    }
    expired_payload["observedAt"] = iso_z(datetime.now(UTC) - timedelta(hours=2))
    expired_payload["expiresAt"] = iso_z(datetime.now(UTC) - timedelta(hours=1))
    expired_payload["receiptDigest"] = sha256_json(expired_payload)
    receipt = _signed_receipt(expired_payload)
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py", "runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py", "runtime.py"],
            },
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
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {
                    "issue": {"state": "open"},
                    "repoProbeReceipt": receipt,
                }
            }
        },
        dedupe_key="verified-path-audit",
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert context["codePaths"] == ["src/runtime.py"]
    with pytest.raises(LedgerError, match="does not match the result context"):
        store.audited_probe_code_paths(
            intent_id="intent-1",
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            worktree_path="/tmp/worktree",
            expected_base_sha="b" * 40,
        )


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("signature", "not authenticated"),
        ("base", "not authenticated"),
        ("null", "receipt is invalid"),
    ],
)
def test_task_context_rejects_unauthenticated_live_audit_paths(tmp_path, tamper, message):
    base_sha = "a" * 40
    receipt = repository_path_receipt(
        "b" * 40 if tamper == "base" else base_sha, ["src/runtime.py"]
    )
    if tamper == "signature":
        receipt = dict(receipt) | {"signature": "0" * 64}
    elif tamper == "null":
        receipt = None
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py", "runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py", "runtime.py"],
            },
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
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {
                    "issue": {"state": "open"},
                    "repoProbeReceipt": receipt,
                }
            }
        },
        dedupe_key=f"invalid-path-audit-{tamper}",
    )

    with pytest.raises(LedgerError, match=message):
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")


def test_task_context_binds_audit_paths_to_exact_intent(tmp_path):
    base_sha = "a" * 40
    receipt_1 = repository_path_receipt(base_sha, ["src/one.py"])
    receipt_2 = repository_path_receipt(base_sha, ["src/two.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            probeReceiptDigest=receipt_1["receiptDigest"],
            codePaths=["one.py"],
            preTaskEvidence={"baseSha": base_sha, "codePathsPlan": ["one.py"]},
        )
    )
    store.claim("intent-1", "worker-1")
    store.commit_dispatch(
        "intent-1",
        owner="worker-1",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree-1",
    )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {
                    "issue": {"state": "open"},
                    "repoProbeReceipt": receipt_1,
                }
            }
        },
        dedupe_key="intent-1:first-audit",
    )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {
                    "issue": {"state": "open"},
                    "policy": {"status": "refreshed"},
                }
            }
        },
        dedupe_key="intent-1:policy-refresh",
    )
    second_intent = intent(
        intentId="intent-2",
        decisionDigest="decision-2",
        selectedBaseSha=base_sha,
        probeReceiptDigest=receipt_2["receiptDigest"],
        codePaths=["two.py"],
        preTaskEvidence={"baseSha": base_sha, "codePathsPlan": ["two.py"]},
    )
    # A live opportunity cannot normally have two active intents.  Preserve a
    # historical second dispatch directly so this regression fixture exercises
    # audit selection after an intent rollover.
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO intents
               (intent_id,opportunity_key,intent_digest,status,issued_at,expires_at,
                thread_id,project_id,worktree_path,payload_json,updated_at)
               VALUES (?,?,?,'DISPATCHED',?,?,?,?,?,?,?)""",
            (
                "intent-2",
                "a/b#1",
                "decision-2",
                second_intent["issuedAt"],
                second_intent["expiresAt"],
                "thread-2",
                "repo-project",
                "/tmp/worktree-2",
                json.dumps(second_intent, sort_keys=True),
                iso_z(datetime.now(UTC)),
            ),
        )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {
                    "issue": {"state": "open"},
                    "repoProbeReceipt": receipt_2,
                }
            }
        },
        dedupe_key="intent-2:newer-audit",
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert context["codePaths"] == ["src/one.py"]
    assert context["liveAudit"]["evidence"]["policy"] == {"status": "refreshed"}


def test_audited_probe_paths_reject_receipt_bound_to_another_intent(tmp_path):
    base_sha = "a" * 40
    receipt = repository_path_receipt(base_sha, ["src/other.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/controller.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/controller.py"],
            },
        )
    )
    store.claim("intent-1", "worker-1")
    store.commit_dispatch(
        "intent-1",
        owner="worker-1",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree-1",
    )
    second_intent = intent(
        intentId="intent-2",
        decisionDigest="decision-2",
        selectedBaseSha=base_sha,
        codePaths=["src/other.py"],
        preTaskEvidence={"baseSha": base_sha, "codePathsPlan": ["src/other.py"]},
    )
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO intents
               (intent_id,opportunity_key,intent_digest,status,issued_at,expires_at,
                thread_id,project_id,worktree_path,payload_json,updated_at)
               VALUES (?,?,?,'DISPATCHED',?,?,?,?,?,?,?)""",
            (
                "intent-2",
                "a/b#1",
                "decision-2",
                second_intent["issuedAt"],
                second_intent["expiresAt"],
                "thread-2",
                "repo-project",
                "/tmp/worktree-2",
                json.dumps(second_intent, sort_keys=True),
                iso_z(datetime.now(UTC)),
            ),
        )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "liveAudit": {
                "evidence": {
                    "issue": {"state": "open"},
                    "repoProbeReceipt": receipt,
                }
            }
        },
        dedupe_key="intent-2:repository-probe",
    )

    with pytest.raises(LedgerError, match="not bound to the task intent"):
        store.audited_probe_code_paths(
            intent_id="intent-1",
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            worktree_path="/tmp/worktree-1",
            expected_base_sha=base_sha,
        )


def test_live_audit_binding_reuses_canonical_receipt_across_timestamp_refresh(tmp_path):
    base_sha = "a" * 40
    first_receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    refreshed_receipt = refreshed_repository_path_receipt(first_receipt)
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py"],
            },
        )
    )
    first = store.record_live_audit_pass_and_bind_probe(
        "intent-1",
        evidence={
            "evidenceDigest": "audit-evidence",
            "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
            "liveAudit": {"evidence": {"repoProbeReceipt": first_receipt}},
        },
    )
    second = store.record_live_audit_pass_and_bind_probe(
        "intent-1",
        evidence={
            "evidenceDigest": "audit-evidence",
            "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
            "liveAudit": {"evidence": {"repoProbeReceipt": refreshed_receipt}},
        },
    )

    with store.connect() as connection:
        event_count = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key='a/b#1' AND event_type='AUDIT_PASS'
                 AND dedupe_key LIKE '%:live-audit-v2'"""
        ).fetchone()[0]
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
    assert event_count == 1
    assert first["receiptDigest"] == first_receipt["receiptDigest"]
    assert second["receiptDigest"] == first_receipt["receiptDigest"]
    assert payload["probeReceiptDigest"] == first_receipt["receiptDigest"]


def test_live_audit_binding_does_not_reuse_changed_paths(tmp_path):
    base_sha = "a" * 40
    first_receipt = repository_path_receipt(base_sha, ["src/one.py"])
    second_receipt = repository_path_receipt(base_sha, ["src/two.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/one.py"],
            preTaskEvidence={"baseSha": base_sha, "codePathsPlan": ["src/one.py"]},
        )
    )
    store.record_live_audit_pass_and_bind_probe(
        "intent-1",
        evidence={
            "evidenceDigest": "audit-evidence",
            "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
            "liveAudit": {"evidence": {"repoProbeReceipt": first_receipt}},
        },
    )
    result = store.record_live_audit_pass_and_bind_probe(
        "intent-1",
        evidence={
            "evidenceDigest": "audit-evidence",
            "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
            "liveAudit": {"evidence": {"repoProbeReceipt": second_receipt}},
        },
    )

    with store.connect() as connection:
        event_count = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key='a/b#1' AND event_type='AUDIT_PASS'
                 AND dedupe_key LIKE '%:live-audit-v2'"""
        ).fetchone()[0]
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
    assert event_count == 2
    assert result["receiptDigest"] == second_receipt["receiptDigest"]
    assert payload["codePaths"] == ["src/two.py"]


def test_live_audit_binding_rolls_back_event_and_intent_together(tmp_path, monkeypatch):
    base_sha = "a" * 40
    receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py"],
            },
        )
    )
    original_event = store._event

    def interrupted_event(*args, **kwargs):
        original_event(*args, **kwargs)
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(store, "_event", interrupted_event)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        store.record_live_audit_pass_and_bind_probe(
            "intent-1",
            evidence={
                "evidenceDigest": "audit-evidence",
                "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
                "liveAudit": {"evidence": {"repoProbeReceipt": receipt}},
            },
        )

    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='AUDIT_PASS'"
            ).fetchone()[0]
            == 0
        )
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            0
        ]
    assert "probeReceiptDigest" not in payload
    assert stage == "QUALIFIED"


def test_live_audit_binding_key_rotation_creates_new_canonical_event(tmp_path, monkeypatch):
    base_sha = "a" * 40
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "old-signing-key")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "old-key")
    first_receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py"],
            },
        )
    )
    store.record_live_audit_pass_and_bind_probe(
        "intent-1",
        evidence={
            "evidenceDigest": "audit-evidence",
            "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
            "liveAudit": {"evidence": {"repoProbeReceipt": first_receipt}},
        },
    )

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "new-signing-key")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "new-key")
    second_receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    result = store.record_live_audit_pass_and_bind_probe(
        "intent-1",
        evidence={
            "evidenceDigest": "audit-evidence",
            "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
            "liveAudit": {"evidence": {"repoProbeReceipt": second_receipt}},
        },
    )

    with store.connect() as connection:
        event_count = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key='a/b#1' AND event_type='AUDIT_PASS'
                 AND dedupe_key LIKE '%:live-audit-v2'"""
        ).fetchone()[0]
    assert event_count == 2
    assert result["receiptDigest"] == second_receipt["receiptDigest"]


def test_live_audit_binding_refuses_an_active_lease(tmp_path):
    base_sha = "a" * 40
    receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py"],
            },
        )
    )
    assert store.claim("intent-1", "worker") is not None

    with pytest.raises(LedgerError, match="intent is not claimable"):
        store.record_live_audit_pass_and_bind_probe(
            "intent-1",
            evidence={
                "evidenceDigest": "audit-evidence",
                "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
                "liveAudit": {"evidence": {"repoProbeReceipt": receipt}},
            },
        )


def test_live_audit_binding_refuses_reproduction_receipt_authority(tmp_path):
    worktree, base_sha, _, _, receipt, _, _ = legal_publication_probe(tmp_path)
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["runtime.py"],
            preTaskEvidence={"baseSha": base_sha, "codePathsPlan": ["runtime.py"]},
            worktree=str(worktree),
        )
    )

    with pytest.raises(LedgerError, match="must be PATHS_VERIFIED"):
        store.record_live_audit_pass_and_bind_probe(
            "intent-1",
            evidence={
                "evidenceDigest": "audit-evidence",
                "authorization": {"status": "ALLOW", "evidence_digest": "audit-evidence"},
                "liveAudit": {"evidence": {"repoProbeReceipt": receipt}},
            },
        )


def test_historical_probe_binding_reconciles_only_exact_semantics(tmp_path):
    base_sha = "a" * 40
    canonical_receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    refreshed_receipt = refreshed_repository_path_receipt(canonical_receipt)
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py"],
            },
        )
    )
    store.record_stage(
        "a/b#1",
        "AUDIT_PASS",
        evidence={"liveAudit": {"evidence": {"repoProbeReceipt": canonical_receipt}}},
        dedupe_key="intent-1:audit-evidence:live-audit-v1",
    )
    store.update_intent_probe_metadata(
        "intent-1",
        probe_level="PATHS_VERIFIED",
        task_stage="REPRODUCTION_REQUIRED",
        receipt_digest=refreshed_receipt["receiptDigest"],
        code_paths=["src/runtime.py"],
    )
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
    )

    assert (
        store.reconcile_intent_probe_audit_binding(
            intent_id="intent-1",
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            worktree_path="/tmp/worktree",
            expected_base_sha=base_sha,
        )
        is True
    )
    assert store.audited_probe_code_paths(
        intent_id="intent-1",
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        worktree_path="/tmp/worktree",
        expected_base_sha=base_sha,
    ) == ["src/runtime.py"]


def test_historical_probe_binding_preserves_unprefixed_exact_digest(tmp_path):
    base_sha = "a" * 40
    receipt = repository_path_receipt(base_sha, ["src/runtime.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/runtime.py"],
            probeLevel="PATHS_VERIFIED",
            taskStage="REPRODUCTION_REQUIRED",
            probeReceiptDigest=receipt["receiptDigest"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/runtime.py"],
            },
        )
    )
    store.record_stage(
        "a/b#1",
        "AUDIT_PASS",
        evidence={"liveAudit": {"evidence": {"repoProbeReceipt": receipt}}},
        dedupe_key="legacy-unprefixed-audit",
    )
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
    )

    assert (
        store.reconcile_intent_probe_audit_binding(
            intent_id="intent-1",
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            worktree_path="/tmp/worktree",
            expected_base_sha=base_sha,
        )
        is False
    )


def test_historical_probe_binding_refuses_different_paths(tmp_path):
    base_sha = "a" * 40
    old_receipt = repository_path_receipt(base_sha, ["src/old.py"])
    current_receipt = repository_path_receipt(base_sha, ["src/current.py"])
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent(
            selectedBaseSha=base_sha,
            codePaths=["src/current.py"],
            probeLevel="PATHS_VERIFIED",
            taskStage="REPRODUCTION_REQUIRED",
            probeReceiptDigest=current_receipt["receiptDigest"],
            preTaskEvidence={
                "baseSha": base_sha,
                "codePathsPlan": ["src/current.py"],
            },
        )
    )
    store.record_stage(
        "a/b#1",
        "AUDIT_PASS",
        evidence={"liveAudit": {"evidence": {"repoProbeReceipt": old_receipt}}},
        dedupe_key="intent-1:audit-evidence:live-audit-v1",
    )
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/worktree",
    )

    with pytest.raises(LedgerError, match="receipt digest is unavailable"):
        store.reconcile_intent_probe_audit_binding(
            intent_id="intent-1",
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            worktree_path="/tmp/worktree",
            expected_base_sha=base_sha,
        )


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


def test_exhausted_dispatched_recovery_is_queryable_and_releases_wip(tmp_path):
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
    assert store.active_task_count() == 1
    assert store.exhausted_recovery_blockers() == []

    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.exhaust_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])

    blocker = store.exhausted_recovery_blockers()[0]
    assert blocker["key"] == "a/b#1"
    assert blocker["intentId"] == "intent-1"
    assert blocker["threadId"] == "thread-1"
    assert blocker["recoveryKind"] == "DISPATCHED_TASK"
    assert blocker["reason"] == "RECOVERY_RETRY_EXHAUSTED"
    assert blocker["occupiesTaskSlot"] is False
    assert store.active_task_count() == 0

    store.enqueue(
        intent(
            intentId="intent-2",
            key="c/d#2",
            repo="c/d",
            issueNumber=2,
            issueUrl="https://github.com/c/d/issues/2",
        )
    )
    assert store.claim("intent-2", "worker", max_active=1) is not None


def test_reviewed_implementation_recovery_is_parked_rearmable_and_auditable(tmp_path, monkeypatch):
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
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "IMPLEMENTATION_FOLLOWUP_SENT",
            "result-digest",
            {
                "threadId": "thread-1",
                "resultDigest": "result-digest",
                "attemptDigest": "result-digest",
            },
            iso_z(datetime.now(UTC)),
        )
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    assert recovery["recoveryKind"] == "IMPLEMENTATION_FOLLOWUP_RESULT"
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.exhaust_recovery(
        thread_id="thread-1",
        nonce=recovery["recoveryNonce"],
        retry_count=2,
        terminal_error={
            "status": "failed",
            "code": "cyber_policy",
            "turnId": "turn-2",
            "message": "blocked by policy",
        },
    )

    blocker = store.exhausted_recovery_blockers()[0]
    assert blocker["retryCount"] == 2
    assert blocker["terminalError"]["code"] == "cyber_policy"
    assert blocker["terminalError"]["turnId"] == "turn-2"
    assert store.active_task_count() == 0
    assert store.recovery_candidates(min_age_minutes=0) == []

    # A foreign acknowledgement on the same opportunity must not hide this nonce.
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED",
            "foreign-nonce",
            {
                "threadId": "thread-1",
                "recoveryNonce": "foreign-nonce",
                "reason": "OPERATOR_REVIEWED_OTHER_RECOVERY",
            },
            iso_z(datetime.now(UTC)),
        )
    assert [item["recoveryNonce"] for item in store.exhausted_recovery_blockers()] == [
        recovery["recoveryNonce"]
    ]
    with pytest.raises(LedgerError, match="active exhausted recovery not found"):
        store.acknowledge_exhausted_recovery(
            thread_id="wrong-thread",
            nonce=recovery["recoveryNonce"],
            reason="OPERATOR_REVIEWED_EXTERNAL_POLICY_BLOCK",
        )

    acknowledged = store.acknowledge_exhausted_recovery(
        thread_id="thread-1",
        nonce=recovery["recoveryNonce"],
        reason="OPERATOR_REVIEWED_EXTERNAL_POLICY_BLOCK",
    )

    assert acknowledged["key"] == "a/b#1"
    assert store.exhausted_recovery_blockers() == []
    assert store.active_task_count() == 0
    parked = store.acknowledged_exhausted_recoveries()
    assert len(parked) == 1
    assert parked[0]["recoveryNonce"] == recovery["recoveryNonce"]
    assert parked[0]["terminalError"]["code"] == "cyber_policy"
    with pytest.raises(LedgerError, match="parked exhausted recovery not found"):
        store.rearm_acknowledged_recovery(
            thread_id="thread-1",
            nonce="wrong-nonce",
            reason="EXECUTION_ENVIRONMENT_CHANGED",
        )
    repeated_ack = store.acknowledge_exhausted_recovery(
        thread_id="thread-1",
        nonce=recovery["recoveryNonce"],
        reason="OPERATOR_REVIEWED_EXTERNAL_POLICY_BLOCK",
    )
    assert repeated_ack["alreadyAcknowledged"] is True
    with pytest.raises(LedgerError, match="another reason"):
        store.acknowledge_exhausted_recovery(
            thread_id="thread-1",
            nonce=recovery["recoveryNonce"],
            reason="OPERATOR_REVIEWED_DIFFERENT_REASON",
        )

    rearmed = store.rearm_acknowledged_recovery(
        thread_id="thread-1",
        nonce=recovery["recoveryNonce"],
        reason="EXECUTION_ENVIRONMENT_CHANGED",
    )
    assert rearmed["key"] == "a/b#1"
    repeated_rearm = store.rearm_acknowledged_recovery(
        thread_id="thread-1",
        nonce=recovery["recoveryNonce"],
        reason="EXECUTION_ENVIRONMENT_CHANGED",
    )
    assert repeated_rearm["alreadyRearmed"] is True
    with pytest.raises(LedgerError, match="another reason"):
        store.rearm_acknowledged_recovery(
            thread_id="thread-1",
            nonce=recovery["recoveryNonce"],
            reason="DIFFERENT_EXECUTION_ENVIRONMENT_CHANGE",
        )
    assert store.acknowledged_exhausted_recoveries() == []
    assert store.exhausted_recovery_blockers() == []
    assert store.active_task_count() == 1
    resumed = store.recovery_candidates(min_age_minutes=0)[0]
    assert resumed["recoveryKind"] == "IMPLEMENTATION_FOLLOWUP_RESULT"
    assert resumed["followupDigest"] == "result-digest"
    assert resumed["rearmedFromExhausted"]["exhaustedNonce"] == recovery["recoveryNonce"]

    store.reserve_recovery(thread_id="thread-1", nonce=resumed["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=resumed["recoveryNonce"])
    store.exhaust_recovery(
        thread_id="thread-1",
        nonce=resumed["recoveryNonce"],
        retry_count=3,
        terminal_error={"status": "failed", "code": "cyber_policy"},
    )

    second_blocker = store.exhausted_recovery_blockers()
    assert len(second_blocker) == 1
    assert second_blocker[0]["recoveryNonce"] == resumed["recoveryNonce"]
    assert store.active_task_count() == 0
    assert store.acknowledged_exhausted_recoveries() == []

    store.acknowledge_exhausted_recovery(
        thread_id="thread-1",
        nonce=resumed["recoveryNonce"],
        reason="OPERATOR_REVIEWED_REPEATED_POLICY_BLOCK",
    )
    store.rearm_acknowledged_recovery(
        thread_id="thread-1",
        nonce=resumed["recoveryNonce"],
        reason="EXECUTION_ENVIRONMENT_CHANGED_AGAIN",
    )
    fresh = store.recovery_candidates(min_age_minutes=0)[0]
    assert fresh["recoveryNonce"] != resumed["recoveryNonce"]
    monkeypatch.setattr(store, "recovery_candidates", lambda **_kwargs: [resumed])

    with pytest.raises(LedgerError, match="stale or invalid"):
        store.reserve_recovery(thread_id="thread-1", nonce=resumed["recoveryNonce"])
    assert store.unresolved_recoveries() == []


def test_implementation_recovery_reservation_rechecks_new_result_in_transaction(
    tmp_path, monkeypatch
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
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "IMPLEMENTATION_FOLLOWUP_SENT",
            "result-digest",
            {
                "threadId": "thread-1",
                "resultDigest": "result-digest",
                "attemptDigest": "result-digest",
            },
            iso_z(datetime.now(UTC)),
        )
    stale = store.recovery_candidates(min_age_minutes=0)[0]
    store.record_task_result_ingested(
        "a/b#1", digest="new-result", stage="FIX_READY", thread_id="thread-1"
    )
    monkeypatch.setattr(store, "recovery_candidates", lambda **_kwargs: [stale])

    with pytest.raises(LedgerError, match="stale or invalid"):
        store.reserve_recovery(thread_id="thread-1", nonce=stale["recoveryNonce"])

    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE opportunity_key='a/b#1'
                     AND event_type='THREAD_RECOVERY_RESERVED'"""
            ).fetchone()[0]
            == 0
        )


def test_new_result_clears_exhausted_dispatched_recovery_blocker(tmp_path):
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
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.exhaust_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    assert store.active_task_count() == 0

    store.record_task_result_ingested(
        "a/b#1",
        digest="new-result-digest",
        stage="IMPLEMENTATION_READY",
        task_id="intent-1",
        thread_id="thread-1",
    )

    assert store.exhausted_recovery_blockers() == []
    assert store.active_task_count() == 1
    with pytest.raises(LedgerError, match="active exhausted recovery not found"):
        store.acknowledge_exhausted_recovery(
            thread_id="thread-1",
            nonce=recovery["recoveryNonce"],
            reason="OPERATOR_REVIEWED_EXTERNAL_POLICY_BLOCK",
        )


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


def test_terminal_stage_retires_unsent_recovery_reservation(tmp_path):
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
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    assert store.unresolved_recoveries()[0]["threadId"] == "thread-1"

    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="WRONG_REPO")

    assert store.unresolved_recoveries() == []


def test_terminal_stage_retires_sent_recovery_without_result(tmp_path):
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
    recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=recovery["recoveryNonce"])
    assert store.sent_recoveries_without_result()[0]["threadId"] == "thread-1"

    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="WRONG_REPO")

    assert store.sent_recoveries_without_result() == []


def test_new_prompt_rearms_a_legacy_exhausted_dispatch_recovery_once(tmp_path):
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
    legacy = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=legacy["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=legacy["recoveryNonce"])
    store.exhaust_recovery(thread_id="thread-1", nonce=legacy["recoveryNonce"])

    assert store.recovery_candidates(min_age_minutes=0) == []
    raw = store.recovery_candidates(
        min_age_minutes=0,
        include_exhausted_dispatched=True,
    )[0]
    prompt_version = "issue-bound-recovery-v1"
    prompt_digest = "a" * 64
    rearmed = bind_dispatched_recovery_prompt(
        raw,
        prompt_version=prompt_version,
        prompt_digest=prompt_digest,
    )

    assert rearmed is not None
    assert rearmed["recoveryNonce"] != legacy["recoveryNonce"]
    assert rearmed["rearmedFromExhausted"] == {
        "eventId": raw["exhaustedRecoveries"][0]["eventId"],
        "exhaustedNonce": legacy["recoveryNonce"],
    }
    store.reserve_recovery(
        thread_id="thread-1",
        nonce=rearmed["recoveryNonce"],
        recovery_prompt_version=prompt_version,
        recovery_prompt_digest=prompt_digest,
    )
    reservation = store.unresolved_recoveries()[0]["reservation"]
    assert reservation["recoveryPromptVersion"] == prompt_version
    assert reservation["recoveryPromptDigest"] == prompt_digest
    assert reservation["rearmedFromExhausted"] == rearmed["rearmedFromExhausted"]
    store.commit_recovery(thread_id="thread-1", nonce=rearmed["recoveryNonce"])
    store.abandon_recovery_delivery(
        thread_id="thread-1",
        nonce=rearmed["recoveryNonce"],
        reason="TERMINAL_RECOVERY_TURN_INTERRUPTED",
        min_age_minutes=0,
    )
    retry_raw = store.recovery_candidates(
        min_age_minutes=0,
        include_exhausted_dispatched=True,
    )[0]
    retry = bind_dispatched_recovery_prompt(
        retry_raw,
        prompt_version=prompt_version,
        prompt_digest=prompt_digest,
    )
    assert retry is not None
    assert retry["recoveryChainDigest"] == rearmed["recoveryChainDigest"]
    assert retry["recoveryNonce"] != rearmed["recoveryNonce"]
    store.reserve_recovery(
        thread_id="thread-1",
        nonce=retry["recoveryNonce"],
        recovery_prompt_version=prompt_version,
        recovery_prompt_digest=prompt_digest,
    )
    store.commit_recovery(thread_id="thread-1", nonce=retry["recoveryNonce"])
    assert store.sent_recoveries_without_result()[0]["retryCount"] == 1
    store.exhaust_recovery(thread_id="thread-1", nonce=retry["recoveryNonce"])

    exhausted_again = store.recovery_candidates(
        min_age_minutes=0,
        include_exhausted_dispatched=True,
    )[0]
    assert (
        bind_dispatched_recovery_prompt(
            exhausted_again,
            prompt_version=prompt_version,
            prompt_digest=prompt_digest,
        )
        is None
    )
    changed_prompt = bind_dispatched_recovery_prompt(
        exhausted_again,
        prompt_version=prompt_version,
        prompt_digest="b" * 64,
    )
    assert changed_prompt is None
    with pytest.raises(LedgerError, match="stale or invalid"):
        store.reserve_recovery(
            thread_id="thread-1",
            nonce=retry["recoveryNonce"],
            recovery_prompt_version="issue-bound-recovery-v2",
            recovery_prompt_digest="b" * 64,
        )


def test_recovery_retry_count_is_scoped_to_the_current_recovery_chain(tmp_path):
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
    now = iso_z(datetime.now(UTC))

    def sent_recovery(
        nonce: str,
        kind: str,
        followup_digest: str | None,
        recovery_chain_digest: str | None = None,
    ) -> None:
        with store.transaction() as connection:
            store._event(
                connection,
                "a/b#1",
                "THREAD_RECOVERY_RESERVED",
                nonce,
                {
                    "threadId": "thread-1",
                    "recoveryNonce": nonce,
                    "recoveryKind": kind,
                    "followupDigest": followup_digest,
                    "recoveryChainDigest": recovery_chain_digest,
                },
                now,
            )
            store._event(
                connection,
                "a/b#1",
                "THREAD_RECOVERY_SENT",
                nonce,
                {"threadId": "thread-1", "recoveryNonce": nonce},
                now,
            )

    def interrupt(nonce: str) -> None:
        with store.transaction() as connection:
            store._event(
                connection,
                "a/b#1",
                "THREAD_RECOVERY_DELIVERY_ABANDONED",
                f"abandoned-{nonce}",
                {
                    "threadId": "thread-1",
                    "recoveryNonce": nonce,
                    "reservationDigest": nonce,
                    "reason": "TERMINAL_RECOVERY_TURN_INTERRUPTED",
                },
                now,
            )

    sent_recovery("dispatch-1", "DISPATCHED_TASK", None)
    interrupt("dispatch-1")
    sent_recovery("dispatch-bound-1", "DISPATCHED_TASK", None, "new-chain")
    interrupt("dispatch-bound-1")
    sent_recovery("dispatch-bound-2", "DISPATCHED_TASK", None, "new-chain")
    sent_recovery("validation-1", "VALIDATION_FOLLOWUP_RESULT", "result-1")
    interrupt("validation-1")
    sent_recovery("validation-2", "VALIDATION_FOLLOWUP_RESULT", "result-1")
    sent_recovery("pr-1", "PR_FOLLOWUP_RESULT", "wake-1")

    pending = {
        item["reservationDigest"]: item["retryCount"]
        for item in store.sent_recoveries_without_result()
    }

    assert pending == {"dispatch-bound-2": 1, "validation-2": 1, "pr-1": 0}


def test_exhaust_recovery_rolls_back_abandonment_when_terminal_write_fails(monkeypatch, tmp_path):
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
    raw = store.recovery_candidates(
        min_age_minutes=0,
        include_exhausted_dispatched=True,
    )[0]
    bound = bind_dispatched_recovery_prompt(
        raw,
        prompt_version="issue-bound-recovery-v1",
        prompt_digest="a" * 64,
    )
    assert bound is not None
    store.reserve_recovery(
        thread_id="thread-1",
        nonce=bound["recoveryNonce"],
        recovery_prompt_version=bound["recoveryPromptVersion"],
        recovery_prompt_digest=bound["recoveryPromptDigest"],
    )
    store.commit_recovery(thread_id="thread-1", nonce=bound["recoveryNonce"])
    original_event = store._event

    def fail_terminal_event(connection, key, event_type, dedupe_key, payload, created_at):
        if event_type == "THREAD_RECOVERY_RETRY_EXHAUSTED":
            raise RuntimeError("injected terminal write failure")
        return original_event(connection, key, event_type, dedupe_key, payload, created_at)

    monkeypatch.setattr(store, "_event", fail_terminal_event)
    with pytest.raises(RuntimeError, match="injected terminal write failure"):
        store.exhaust_recovery(thread_id="thread-1", nonce=bound["recoveryNonce"])

    with store.connect() as connection:
        rolled_back = connection.execute(
            """SELECT event_type,COUNT(*) FROM events
               WHERE event_type IN (
                 'THREAD_RECOVERY_DELIVERY_ABANDONED',
                 'THREAD_RECOVERY_RETRY_EXHAUSTED'
               ) GROUP BY event_type"""
        ).fetchall()
    assert rolled_back == []
    assert store.sent_recoveries_without_result()[0]["reservationDigest"] == bound["recoveryNonce"]

    monkeypatch.setattr(store, "_event", original_event)
    store.exhaust_recovery(thread_id="thread-1", nonce=bound["recoveryNonce"])
    with store.connect() as connection:
        committed = dict(
            connection.execute(
                """SELECT event_type,COUNT(*) FROM events
                   WHERE event_type IN (
                     'THREAD_RECOVERY_DELIVERY_ABANDONED',
                     'THREAD_RECOVERY_RETRY_EXHAUSTED'
                   ) GROUP BY event_type"""
            ).fetchall()
        )
    assert committed == {
        "THREAD_RECOVERY_DELIVERY_ABANDONED": 1,
        "THREAD_RECOVERY_RETRY_EXHAUSTED": 1,
    }
    assert store.sent_recoveries_without_result() == []


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


def test_active_quarantine_hides_validation_and_recovery_until_cleared(tmp_path):
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

    assert store.validation_followup_candidates()[0]["resultDigest"] == "result-digest"
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest")
    with store.connect() as connection:
        connection.execute(
            "UPDATE events SET created_at=? WHERE event_type='VALIDATION_FOLLOWUP_SENT'",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )
    assert store.stale_validation_followups(min_age_minutes=90)
    assert store.recovery_candidates(min_age_minutes=0)
    assert store.recovery_candidates(min_age_minutes=0)

    from oss_pr_radar.task_quarantine import record

    with store.connect() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-1",
            payload={"requiresExplicitMigration": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    assert store.validation_followup_candidates() == []
    assert store.stale_validation_followups(min_age_minutes=90) == []
    assert store.recovery_candidates(min_age_minutes=0) == []
    assert store.quarantined_validation_followups()[0]["reason"] == (
        "LEGACY_RESULT_REQUIRES_MIGRATION"
    )

    with store.connect() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="PR_FOLLOWUP_REBIND_REQUIRED",
            dedupe_key="rebind-1",
            payload={"requiresRebind": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    quarantined = store.quarantined_validation_followups()
    assert len(quarantined) == 1
    assert quarantined[0]["reason"] == "PR_FOLLOWUP_REBIND_REQUIRED"

    store.clear_task_quarantine(
        "a/b#1",
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        evidence={"revalidated": True, "migrationId": "m-1"},
    )
    store.clear_task_quarantine(
        "a/b#1",
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        evidence={"revalidated": True, "migrationId": "m-1"},
    )
    assert store.stale_validation_followups(min_age_minutes=90)
    assert store.recovery_candidates(min_age_minutes=0)


def test_active_quarantine_releases_validation_wip_but_keeps_unresolved_delivery(tmp_path):
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
    with store.connect() as connection:
        assert (
            connection.execute("SELECT status FROM intents WHERE intent_id='intent-1'").fetchone()[
                "status"
            ]
            == "COMPLETED"
        )
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    assert store.active_task_count() == 1
    assert store.unresolved_validation_followups()

    from oss_pr_radar.task_quarantine import record

    with store.connect() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="PR_FOLLOWUP_REBIND_REQUIRED",
            dedupe_key="rebind-1",
            payload={"requiresRebind": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    assert store.active_task_count() == 0
    assert store.unresolved_validation_followups()

    store.clear_task_quarantine(
        "a/b#1",
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        evidence={"revalidated": True, "replacement": "r-1"},
    )
    assert store.active_task_count() == 1
    assert store.unresolved_validation_followups()


def test_active_quarantine_keeps_a_dispatched_writer_in_wip(tmp_path):
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
    assert store.active_task_count() == 1

    from oss_pr_radar.task_quarantine import record

    with store.connect() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-1",
            payload={"requiresExplicitMigration": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    assert store.active_task_count() == 1

    with store.connect() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="PR_FOLLOWUP_REBIND_REQUIRED",
            dedupe_key="rebind-1",
            payload={"requiresRebind": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    assert store.active_task_count() == 1


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
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_SENT'""",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )

    candidate = store.recovery_candidates(min_age_minutes=0)[0]

    assert candidate["threadId"] == "thread-1"
    assert candidate["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert candidate["followupDigest"] == "result-digest"
    assert store.stale_validation_followups(min_age_minutes=0)[0]["resultDigest"] == (
        "result-digest"
    )
    store.reserve_recovery(thread_id="thread-1", nonce=candidate["recoveryNonce"])
    assert store.unresolved_recoveries()[0]["threadId"] == "thread-1"

    store.record_task_result_ingested(
        "a/b#1",
        digest="new-result-digest",
        stage="VALIDATION_PENDING",
        task_id="intent-1",
        thread_id="thread-1",
    )

    assert store.recovery_candidates(min_age_minutes=0) == []
    assert store.unresolved_recoveries() == []
    assert store.stale_validation_followups(min_age_minutes=0) == []


def test_published_result_binding_retires_followup_when_legacy_ingest_was_earlier(tmp_path):
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
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.record_task_result_ingested("a/b#1", digest="result-digest", stage="PR_OPEN")
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest")
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_SENT'""",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )
    assert store.stale_validation_followups(min_age_minutes=90)

    store.record_published_task_result_backfilled(
        "a/b#1",
        task_id="intent-1",
        thread_id="thread-1",
        digest="new-published-result-digest",
        stage="PR_OPEN",
        pr_url="https://github.com/a/b/pull/9",
        head_sha="a" * 40,
    )

    assert store.stale_validation_followups(min_age_minutes=90) == []
    assert store.recovery_candidates(min_age_minutes=0) == []


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


def test_stale_validation_followup_requires_result_from_same_thread(tmp_path):
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
        result_digest="validation-result",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.reserve_validation_followup(thread_id="thread-1", result_digest="validation-result")
    store.commit_validation_followup(thread_id="thread-1", result_digest="validation-result")
    with store.connect() as connection:
        connection.execute(
            "UPDATE events SET created_at=? WHERE event_type='VALIDATION_FOLLOWUP_SENT'",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )
    assert store.stale_validation_followups(min_age_minutes=90)
    assert store.recovery_candidates(min_age_minutes=0)

    store.record_task_result_ingested(
        "a/b#1", digest="other-thread-result", stage="PR_OPEN", thread_id="thread-2"
    )
    assert store.stale_validation_followups(min_age_minutes=90)
    assert store.recovery_candidates(min_age_minutes=0)

    store.record_task_result_ingested("a/b#1", digest="unattributed-result", stage="PR_OPEN")
    assert store.stale_validation_followups(min_age_minutes=90)
    assert store.recovery_candidates(min_age_minutes=0)

    store.record_task_result_ingested(
        "a/b#1", digest="same-thread-result", stage="PR_OPEN", thread_id="thread-1"
    )
    assert store.stale_validation_followups(min_age_minutes=90) == []
    assert store.recovery_candidates(min_age_minutes=0) == []


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


def test_validation_result_change_uses_immediate_cancel_without_relaxing_abandonment(
    tmp_path,
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
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-1",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    reservation = store.reserve_validation_followup(
        thread_id="thread-1", result_digest="result-digest-1"
    )

    with pytest.raises(LedgerError, match="not old enough"):
        store.abandon_validation_followup_delivery(
            thread_id="thread-1",
            result_digest="result-digest-1",
            reason="TARGET_TURN_NOT_MATERIALIZED",
            min_age_minutes=0,
        )

    store.cancel_validation_followup_reservation(
        thread_id="thread-1",
        result_digest="result-digest-1",
        reservation_digest=reservation["reservationDigest"],
        reason="VALIDATION_RESULT_CHANGED_AFTER_RESERVE",
    )
    assert store.unresolved_validation_followups() == []
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT 1 FROM events
               WHERE event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'"""
            ).fetchone()
            is not None
        )
        assert (
            connection.execute(
                """SELECT 1 FROM events
               WHERE event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'"""
            ).fetchone()
            is None
        )
    with pytest.raises(LedgerError, match="not cancellable"):
        store.cancel_validation_followup_reservation(
            thread_id="thread-1",
            result_digest="result-digest-1",
            reservation_digest=reservation["reservationDigest"],
            reason="VALIDATION_RESULT_CHANGED_AFTER_RESERVE",
        )


def test_validation_delivery_binding_is_idempotent_and_blocks_started_or_old_cancel(
    tmp_path,
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
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-1",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    first = store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    binding = store.authorize_task_turn_delivery(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="result-digest-1",
        reservation_digest=first["reservationDigest"],
        snapshot_id=first["reservationDigest"],
        snapshot_path=f"validation-inputs/{first['reservationDigest']}.json",
        snapshot_digest="snapshot-digest-1",
        worktree_input_path=(f".oss-pr-radar/validation-inputs/{first['reservationDigest']}.json"),
        worktree_input_digest="snapshot-digest-1",
    )
    assert (
        store.authorize_task_turn_delivery(
            delivery_kind="validation-followup",
            thread_id="thread-1",
            delivery_token="result-digest-1",
            reservation_digest=first["reservationDigest"],
            snapshot_id=first["reservationDigest"],
            snapshot_path=f"validation-inputs/{first['reservationDigest']}.json",
            snapshot_digest="snapshot-digest-1",
            worktree_input_path=(
                f".oss-pr-radar/validation-inputs/{first['reservationDigest']}.json"
            ),
            worktree_input_digest="snapshot-digest-1",
        )
        == binding
    )
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
               WHERE event_type='TASK_TURN_DELIVERY_STARTED'"""
            ).fetchone()[0]
            == 1
        )
    with pytest.raises(LedgerError, match="not cancellable"):
        store.cancel_validation_followup_reservation(
            thread_id="thread-1",
            result_digest="result-digest-1",
            reservation_digest=first["reservationDigest"],
            reason="RESULT_CHANGED",
        )

    store.commit_validation_followup(
        thread_id="thread-1",
        result_digest="result-digest-1",
        reservation_digest=first["reservationDigest"],
    )
    assert store.unresolved_validation_followups() == []


def test_validation_delivery_retry_binds_a_new_reservation_after_started_abandonment(
    tmp_path,
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
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-1",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    first = store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    first_binding = store.authorize_task_turn_delivery(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="result-digest-1",
        reservation_digest=first["reservationDigest"],
        snapshot_id=first["reservationDigest"],
        snapshot_path=f"validation-inputs/{first['reservationDigest']}.json",
        snapshot_digest="snapshot-digest-1",
        worktree_input_path=(f".oss-pr-radar/validation-inputs/{first['reservationDigest']}.json"),
        worktree_input_digest="snapshot-digest-1",
    )
    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_RESERVED'
                 AND dedupe_key=?""",
            (iso_z(datetime.now(UTC) - timedelta(minutes=2)), first["reservationDigest"]),
        )
    store.abandon_validation_followup_delivery(
        thread_id="thread-1",
        result_digest="result-digest-1",
        reason="TARGET_TURN_OUTCOME_UNKNOWN",
        min_age_minutes=1,
    )

    second = store.reserve_validation_followup(
        thread_id="thread-1", result_digest="result-digest-1"
    )
    assert second["reservationDigest"] != first["reservationDigest"]
    second_binding = store.authorize_task_turn_delivery(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="result-digest-1",
        reservation_digest=second["reservationDigest"],
        snapshot_id=second["reservationDigest"],
        snapshot_path=f"validation-inputs/{second['reservationDigest']}.json",
        snapshot_digest="snapshot-digest-2",
        worktree_input_path=(f".oss-pr-radar/validation-inputs/{second['reservationDigest']}.json"),
        worktree_input_digest="snapshot-digest-2",
    )
    assert second_binding["reservationDigest"] == second["reservationDigest"]
    assert first_binding["reservationDigest"] != second_binding["reservationDigest"]
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
               WHERE event_type='TASK_TURN_DELIVERY_STARTED'"""
            ).fetchone()[0]
            == 2
        )


def test_validation_delivery_same_reservation_concurrent_start_is_idempotent(tmp_path):
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
    reservation = store.reserve_validation_followup(
        thread_id="thread-1", result_digest="result-digest-1"
    )
    kwargs = {
        "delivery_kind": "validation-followup",
        "thread_id": "thread-1",
        "delivery_token": "result-digest-1",
        "reservation_digest": reservation["reservationDigest"],
        "snapshot_id": reservation["reservationDigest"],
        "snapshot_path": f"validation-inputs/{reservation['reservationDigest']}.json",
        "snapshot_digest": "snapshot-digest-1",
        "worktree_input_path": (
            f".oss-pr-radar/validation-inputs/{reservation['reservationDigest']}.json"
        ),
        "worktree_input_digest": "snapshot-digest-1",
    }
    with ThreadPoolExecutor(max_workers=4) as executor:
        bindings = list(
            executor.map(lambda _: store.authorize_task_turn_delivery(**kwargs), range(4))
        )

    assert all(binding == bindings[0] for binding in bindings)
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
               WHERE event_type='TASK_TURN_DELIVERY_STARTED'"""
            ).fetchone()[0]
            == 1
        )


def test_validation_delivery_rejects_worktree_input_path_escape(tmp_path):
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
    reservation = store.reserve_validation_followup(
        thread_id="thread-1", result_digest="result-digest-1"
    )

    with pytest.raises(LedgerError, match="validation task-turn worktree input binding is invalid"):
        store.authorize_task_turn_delivery(
            delivery_kind="validation-followup",
            thread_id="thread-1",
            delivery_token="result-digest-1",
            reservation_digest=reservation["reservationDigest"],
            snapshot_id=reservation["reservationDigest"],
            snapshot_path=(f"validation-inputs/{reservation['reservationDigest']}.json"),
            snapshot_digest="snapshot-digest-1",
            worktree_input_path="../result.json",
            worktree_input_digest="snapshot-digest-1",
        )
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
               WHERE event_type='TASK_TURN_DELIVERY_STARTED'"""
            ).fetchone()[0]
            == 0
        )


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


def test_local_receipt_candidates_skip_plain_completed_published_history(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="repo-project",
        worktree_path="/tmp/missing-worktree",
    )
    store.record_stage("a/b#1", "CI_GREEN", evidence={"prUrl": "https://github.com/a/b/pull/9"})

    assert [item["key"] for item in store.task_result_candidates()] == ["a/b#1"]
    assert store.local_receipt_candidates() == []


def test_local_receipt_candidates_keep_unfinished_pr_followup_until_result_ingested(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.restore_task_context(published_task_context())
    wake_digest = "followup-wake"
    old = iso_z(datetime.now(UTC) - timedelta(minutes=5))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES ('a/b#1','PR_FOLLOWUP_SENT',?,?,?)""",
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

    assert [item["key"] for item in store.local_receipt_candidates()] == ["a/b#1"]

    store.record_followup_result(
        "a/b#1", wake_digest=wake_digest, result_digest="result", stage="PR_OPEN"
    )

    assert store.local_receipt_candidates() == []


def test_local_receipt_candidates_keep_unfinished_validation_followup(tmp_path):
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

    assert [item["key"] for item in store.local_receipt_candidates()] == ["a/b#1"]


def test_local_receipt_candidates_exclude_active_quarantine_without_changing_audit_scope(
    tmp_path,
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
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": "https://github.com/a/b/pull/9"})
    assert [item["key"] for item in store.task_result_candidates()] == ["a/b#1"]
    assert store.local_receipt_candidates() == []

    store.record_shared_context_quarantine(
        key="a/b#1",
        reason="SHARED_CONTEXT_LAYOUT_CONFLICT",
        dedupe_key="layout-conflict",
        payload={"issueUrl": "https://github.com/a/b/issues/1"},
        created_at=iso_z(datetime.now(UTC)),
    )

    assert store.local_receipt_candidates() == []


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


def _make_pr_followup_candidate(
    store: RadarLedger,
    *,
    key: str = "a/b#1",
    issue_url: str = "https://github.com/a/b/issues/1",
    pr_url: str = "https://github.com/a/b/pull/9",
    intent_id: str = "intent-1",
    thread_id: str = "thread-1",
    worktree_path: str = "/tmp/worktree",
    head_sha: str = "b" * 40,
) -> str:
    store.enqueue(
        intent(
            intentId=intent_id,
            key=key,
            repo=key.split("#", 1)[0],
            issueNumber=int(key.rsplit("#", 1)[1]),
            issueUrl=issue_url,
            autoSubmitAuthorized=True,
            publicSubmissionAllowed=True,
            authorizationSource="signed_live_revalidation_required",
            publicationMode="canary",
        )
    )
    store.claim(intent_id, "controller")
    store.commit_dispatch(
        intent_id,
        owner="controller",
        thread_id=thread_id,
        project_id="github",
        worktree_path=worktree_path,
    )
    store.record_stage(key, "PR_OPEN", evidence={"prUrl": pr_url})
    published_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,'CONSUMED','{}',?,?)""",
            (
                f"request-{intent_id}",
                key,
                thread_id,
                "a" * 40,
                f"fix/{intent_id}",
                worktree_path,
                f"evidence-{intent_id}",
                published_at,
                published_at,
            ),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES (?,?,?,?,?,'CONSUMED',?,?,'{}',?,?)""",
            (
                f"permit-{intent_id}",
                f"request-{intent_id}",
                issue_url,
                "a" * 40,
                f"fix/{intent_id}",
                iso_z(datetime.now(UTC) + timedelta(hours=1)),
                pr_url,
                published_at,
                published_at,
            ),
        )
    imported = store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": iso_z(datetime.now(UTC)),
            "items": [
                {
                    "url": pr_url,
                    "headSha": head_sha,
                    "actionDigest": f"action-{intent_id}",
                    "taskActionDigest": f"task-action-{intent_id}",
                    "taskFollowupRequired": True,
                    "taskActions": ["current branch check failed"],
                    "evidence": {"actionableCheckNames": ["Ruff"]},
                    "checkedAt": iso_z(datetime.now(UTC)),
                }
            ],
        }
    )
    assert imported["inserted"] == 1
    return key


def _insert_pr_update_request(
    store: RadarLedger,
    *,
    status: str,
    commit_sha: str,
) -> None:
    now = iso_z(datetime.now(UTC))
    permit_id = "permit-update" if status in {"GRANTED", "CONSUMED"} else None
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,permit_id,request_json,created_at,updated_at)
               VALUES ('request-update','a/b#1','thread-1',?,'fix/intent-1','/tmp/worktree',
                       'evidence-update',?,?,?,?,?)""",
            (
                commit_sha,
                status,
                permit_id,
                json.dumps({"publicationKind": "PR_UPDATE", "commitSha": commit_sha}),
                now,
                now,
            ),
        )
        if permit_id is not None:
            connection.execute(
                """INSERT INTO publication_permits
                   (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                    evidence_json,created_at,updated_at)
                   VALUES (?,'request-update','https://github.com/a/b/issues/1',?,
                           'fix/intent-1',?,?,?,'{}',?,?)""",
                (
                    permit_id,
                    commit_sha,
                    "CONSUMED" if status == "CONSUMED" else "ACTIVE",
                    iso_z(datetime.now(UTC) + timedelta(hours=1)),
                    "https://github.com/a/b/pull/9" if status == "CONSUMED" else None,
                    now,
                    now,
                ),
            )


@pytest.mark.parametrize("request_status", ["PENDING", "GRANTED", "BLOCKED"])
def test_pr_followup_candidates_wait_for_different_head_update(tmp_path, request_status):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    _make_pr_followup_candidate(store, head_sha="b" * 40)
    _insert_pr_update_request(store, status=request_status, commit_sha="c" * 40)

    assert store.pr_followup_candidates() == []


@pytest.mark.parametrize("request_status", ["PENDING", "GRANTED", "BLOCKED"])
def test_pr_followup_candidates_allow_same_head_update(tmp_path, request_status):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store, head_sha="b" * 40)
    _insert_pr_update_request(store, status=request_status, commit_sha="b" * 40)

    assert [candidate["key"] for candidate in store.pr_followup_candidates()] == [key]


def test_pr_followup_candidates_allow_consumed_different_head_update(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store, head_sha="b" * 40)
    _insert_pr_update_request(store, status="CONSUMED", commit_sha="c" * 40)

    assert [candidate["key"] for candidate in store.pr_followup_candidates()] == [key]


def test_pr_followup_candidates_exclude_active_task_quarantine(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store)
    assert [candidate["key"] for candidate in store.pr_followup_candidates()] == [key]

    from oss_pr_radar.task_quarantine import record

    now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        record(
            connection,
            opportunity_key=key,
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-result",
            payload={"requiresMigration": True},
            created_at=now,
        )

    assert store.pr_followup_candidates() == []
    with pytest.raises(LedgerError):
        store.reserve_pr_followup(thread_id="thread-1", wake_digest="missing")


def test_pr_followup_candidates_keep_quarantine_exclusion_idempotent(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store)

    from oss_pr_radar.task_quarantine import record

    now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        first = record(
            connection,
            opportunity_key=key,
            reason="SHARED_CONTEXT_LAYOUT_CONFLICT",
            dedupe_key="rebind",
            payload={"observedHeadSha": "c" * 40},
            created_at=now,
        )
        repeated = record(
            connection,
            opportunity_key=key,
            reason="SHARED_CONTEXT_LAYOUT_CONFLICT",
            dedupe_key="rebind",
            payload={"observedHeadSha": "c" * 40},
            created_at=now,
        )
        newer = record(
            connection,
            opportunity_key=key,
            reason="SHARED_CONTEXT_LAYOUT_CONFLICT",
            dedupe_key="rebind|generation=2",
            payload={"observedHeadSha": "d" * 40},
            created_at=now,
        )

    assert first["created"] is True
    assert repeated["created"] is False
    assert newer["created"] is True
    assert store.pr_followup_candidates() == []

    store.clear_task_quarantine(
        key,
        reason="SHARED_CONTEXT_LAYOUT_CONFLICT",
        evidence={"revalidated": True, "rebindId": "rebuilt"},
    )
    assert [candidate["key"] for candidate in store.pr_followup_candidates()] == [key]


def test_pr_followup_candidates_keep_unquarantined_followups(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    first = _make_pr_followup_candidate(store)
    second = _make_pr_followup_candidate(
        store,
        key="c/d#2",
        issue_url="https://github.com/c/d/issues/2",
        pr_url="https://github.com/c/d/pull/10",
        intent_id="intent-2",
        thread_id="thread-2",
        worktree_path="/tmp/worktree-2",
        head_sha="c" * 40,
    )

    from oss_pr_radar.task_quarantine import record

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key=first,
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-result",
            payload={"requiresMigration": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    assert [candidate["key"] for candidate in store.pr_followup_candidates()] == [second]


def test_pr_followup_rebind_gate_does_not_bypass_other_quarantine(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store)
    rebound = store.rearm_pr_followup_after_task_drift(
        key,
        expected_prepared_head_sha="c" * 40,
        observed_head_sha="d" * 40,
    )
    assert store.pr_followup_candidates()[0]["wakeDigest"] == rebound["replacementWakeDigest"]

    from oss_pr_radar.task_quarantine import record

    now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        record(
            connection,
            opportunity_key=key,
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-result",
            payload={"requiresMigration": True},
            created_at=now,
        )
    assert store.pr_followup_candidates() == []


def test_pr_followup_rebind_gate_does_not_bypass_stale_rebind_quarantine(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store)
    rebound = store.rearm_pr_followup_after_task_drift(
        key,
        expected_prepared_head_sha="c" * 40,
        observed_head_sha="d" * 40,
    )
    assert store.pr_followup_candidates()[0]["wakeDigest"] == rebound["replacementWakeDigest"]

    from oss_pr_radar.task_quarantine import record

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key=key,
            reason="PR_FOLLOWUP_REBIND_REQUIRED",
            dedupe_key="stale-rebind",
            payload={"replacementWakeDigest": "f" * 64},
            created_at=iso_z(datetime.now(UTC)),
        )

    assert store.pr_followup_candidates() == []


def test_reserve_pr_followup_rechecks_quarantine_after_candidate_read(
    tmp_path,
):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store)
    candidate = store.pr_followup_candidates()[0]

    from oss_pr_radar.task_quarantine import record

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key=key,
            reason="LEGACY_RESULT_REQUIRES_MIGRATION",
            dedupe_key="legacy-result",
            payload={"requiresMigration": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    with pytest.raises(LedgerError, match="stale or invalid"):
        store.reserve_pr_followup(
            thread_id=candidate["threadId"], wake_digest=candidate["wakeDigest"]
        )

    _assert_no_pr_followup_reservation(store, key)


@pytest.mark.parametrize(
    "mutation",
    ["stage", "permit", "wake", "disabled"],
)
def test_reserve_pr_followup_rechecks_candidate_state_after_candidate_read(tmp_path, mutation):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    key = _make_pr_followup_candidate(store)
    candidate = store.pr_followup_candidates()[0]
    replacement_wake = "c" * 64

    with store.transaction() as connection:
        if mutation == "stage":
            connection.execute(
                "UPDATE opportunities SET stage='AUDIT_NO_GO' WHERE key=?",
                (key,),
            )
        elif mutation == "permit":
            connection.execute(
                """UPDATE publication_permits
                   SET status='BLOCKED',updated_at=?
                   WHERE request_id='request-intent-1'""",
                (iso_z(datetime.now(UTC)),),
            )
        elif mutation == "wake":
            connection.execute(
                """UPDATE pr_followups SET wake_digest=?,updated_at=?
                   WHERE opportunity_key=?""",
                (replacement_wake, iso_z(datetime.now(UTC)), key),
            )
        elif mutation == "disabled":
            connection.execute(
                """UPDATE pr_followups SET followup_required=0,updated_at=?
                   WHERE opportunity_key=?""",
                (iso_z(datetime.now(UTC)), key),
            )
        else:  # pragma: no cover - defensive for future parametrization edits
            raise AssertionError(mutation)

    with pytest.raises(LedgerError, match="stale or invalid"):
        store.reserve_pr_followup(
            thread_id=candidate["threadId"], wake_digest=candidate["wakeDigest"]
        )

    _assert_no_pr_followup_reservation(store, key)


def _assert_no_pr_followup_reservation(store: RadarLedger, key: str) -> None:
    with store.connect() as connection:
        reserved = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key=? AND event_type='PR_FOLLOWUP_RESERVED'""",
            (key,),
        ).fetchone()[0]
    assert reserved == 0


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
    store.complete_pr_followup_reservation(
        thread_id="thread-1", wake_digest=candidate["wakeDigest"]
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
    store.complete_pr_followup_reservation(
        thread_id="thread-1", wake_digest=candidate["wakeDigest"]
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
    assert store.pr_followup_candidates() == []
    receipt = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )["publicationReceipt"]
    assert receipt["status"] == "PR_OPEN"
    assert receipt["prUrl"] == "https://github.com/a/b/pull/9"
    assert receipt["commitSha"] == "a" * 40


def test_existing_publication_request_without_snapshot_upgrades_idempotently(tmp_path):
    store, args = publication_request_fixture(tmp_path)

    legacy = store.create_publication_request(**args)
    assert legacy["request"]["evidenceRawBase64"] is None

    upgraded = store.create_publication_request(**args, evidence_raw_base64="e30=")

    assert upgraded["request_id"] == legacy["request_id"]
    assert upgraded["status"] == legacy["status"]
    assert upgraded["reason"] == legacy["reason"]
    stored = store.publication_request(legacy["request_id"])
    assert stored["request"]["evidenceRawBase64"] == "e30="

    returned = store.create_publication_request(**args, evidence_raw_base64="eyJvdGhlciI6dHJ1ZX0=")

    assert returned["request"]["evidenceRawBase64"] == "e30="
    assert store.publication_request(legacy["request_id"])["request"]["evidenceRawBase64"] == "e30="


def test_existing_publication_request_without_snapshot_rejects_binding_drift(tmp_path):
    store, args = publication_request_fixture(tmp_path)
    legacy = store.create_publication_request(**args)
    tampered = dict(legacy["request"])
    tampered.pop("evidenceRawBase64", None)
    tampered["branch"] = "fix/other-branch"
    with store.connect() as connection:
        connection.execute(
            "UPDATE publication_requests SET request_json=? WHERE request_id=?",
            (json.dumps(tampered, sort_keys=True), legacy["request_id"]),
        )

    with pytest.raises(LedgerError, match="snapshot upgrade binding mismatch"):
        store.create_publication_request(**args, evidence_raw_base64="e30=")

    stored = store.publication_request(legacy["request_id"])
    assert "evidenceRawBase64" not in stored["request"]


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


@pytest.mark.parametrize(
    "operation", ["recover", "ambiguous", "retry", "post_push", "retry_blocked"]
)
def test_publication_recovery_entries_fail_closed_on_active_quarantine(tmp_path, operation):
    store = RadarLedger(tmp_path / f"{operation}.sqlite3")
    insert_publication_preflight(store)
    now = iso_z(datetime.now(UTC) - timedelta(minutes=10))
    with store.connect() as connection:
        if operation == "recover":
            connection.execute(
                "UPDATE publication_effects SET status='FAILED',result_json=? WHERE effect_id='effect-1'",
                (
                    json.dumps(
                        {"reason": "LIVE_RECHECK_FAILED", "detail": "LIVE_EVIDENCE_INCOMPLETE"}
                    ),
                ),
            )
        elif operation == "ambiguous":
            connection.execute(
                "UPDATE publication_effects SET updated_at=? WHERE effect_id='effect-1'",
                (now,),
            )
        elif operation == "retry":
            connection.execute(
                "UPDATE publication_effects SET status='RECONCILE_REQUIRED' WHERE effect_id='effect-1'"
            )
        elif operation == "post_push":
            connection.execute(
                "UPDATE publication_requests SET request_json=? WHERE request_id='request-1'",
                (json.dumps({"publicationKind": "PR_CREATE"}),),
            )
        else:
            connection.execute(
                "UPDATE publication_requests SET status='BLOCKED',reason='RETRY_ME' WHERE request_id='request-1'"
            )
        from oss_pr_radar.task_quarantine import record

        record(
            connection,
            opportunity_key="a/b#1",
            reason="ACTIVE_TASK_QUARANTINE",
            dedupe_key=operation,
            payload={"test": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    if operation == "ambiguous":
        assert (
            store.prepare_ambiguous_publication_effect(
                "request-1", action="push", min_age_minutes=0
            )
            is None
        )
        assert store.publication_request("request-1")["status"] == "BLOCKED"
    else:
        with pytest.raises(PermissionError, match="active task quarantine"):
            if operation == "recover":
                store.recover_failed_publication_preflight(
                    "request-1",
                    action="push",
                    transient_reasons={"LIVE_EVIDENCE_INCOMPLETE"},
                )
            elif operation == "retry":
                store.retry_publication_effect_after_noop(
                    effect_id="effect-1",
                    permit_id="permit-1",
                    evidence={"exactHeadPrAbsent": True},
                )
            elif operation == "post_push":
                store.prepare_post_push_reconciliation("request-1")
            else:
                store.retry_blocked_publication_request("request-1", expected_reason="RETRY_ME")

    with store.connect() as connection:
        assert connection.execute(
            "SELECT status FROM publication_effects WHERE effect_id='effect-1'"
        ).fetchone()["status"] in {"ATTEMPTED", "FAILED", "RECONCILE_REQUIRED", "BLOCKED"}


def test_preflight_resolution_remains_safe_shrink_under_active_quarantine(tmp_path):
    store = RadarLedger(tmp_path / "resolution.sqlite3")
    insert_publication_preflight(store)
    with store.connect() as connection:
        from oss_pr_radar.task_quarantine import record

        record(
            connection,
            opportunity_key="a/b#1",
            reason="ACTIVE_TASK_QUARANTINE",
            dedupe_key="resolution",
            payload={"test": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    store.resolve_publication_preflight(
        "effect-1", disposition="BLOCK", reason="LIVE_EVIDENCE_INCOMPLETE"
    )
    assert store.publication_request("request-1")["status"] == "BLOCKED"


def test_publication_work_items_keeps_durable_receipt_reconciliation_visible_under_quarantine(
    tmp_path,
):
    store = RadarLedger(tmp_path / "receipt-visible.sqlite3")
    insert_publication_preflight(store)
    pr_url = "https://github.com/a/b/pull/1"
    with store.connect() as connection:
        now = iso_z(datetime.now(UTC))
        connection.execute(
            "UPDATE publication_requests SET status='CONSUMED' WHERE request_id='request-1'"
        )
        connection.execute(
            "UPDATE publication_permits SET status='CONSUMED',pr_url=? WHERE permit_id='permit-1'",
            (pr_url,),
        )
        connection.execute(
            """INSERT INTO publication_effects
               (effect_id,permit_id,action,request_digest,status,result_json,created_at,updated_at)
               VALUES ('create-1','permit-1','create_pr','create-digest','SUCCEEDED',?,?,?)""",
            (json.dumps({"ok": True, "prUrl": pr_url, "headSha": "b" * 40}), now, now),
        )
        from oss_pr_radar.task_quarantine import record

        record(
            connection,
            opportunity_key="a/b#1",
            reason="ACTIVE_TASK_QUARANTINE",
            dedupe_key="receipt-visible",
            payload={"test": True},
            created_at=now,
        )

    items = store.publication_work_items()
    assert len(items) == 1
    assert items[0]["externalPublicationReceipt"]["prUrl"] == pr_url


def test_publication_work_items_skip_opportunity_that_is_no_longer_submit_ready(tmp_path):
    store = RadarLedger(tmp_path / "stale-stage.sqlite3")
    insert_publication_preflight(store)
    with store.connect() as connection:
        connection.execute("UPDATE opportunities SET stage='VALIDATION_PENDING' WHERE key='a/b#1'")

    assert store.publication_work_items() == []


def test_publication_safe_shrink_is_allowed_under_active_quarantine(tmp_path):
    store = RadarLedger(tmp_path / "safe-shrink.sqlite3")
    insert_publication_preflight(store)
    with store.connect() as connection:
        connection.execute(
            "UPDATE publication_requests SET status='PENDING' WHERE request_id='request-1'"
        )
        from oss_pr_radar.task_quarantine import record

        record(
            connection,
            opportunity_key="a/b#1",
            reason="ACTIVE_TASK_QUARANTINE",
            dedupe_key="safe-shrink",
            payload={"test": True},
            created_at=iso_z(datetime.now(UTC)),
        )

    store.defer_publication_request("request-1", "LIVE_EVIDENCE_INCOMPLETE")
    assert store.publication_request("request-1")["status"] == "PENDING"
    assert store.publication_request("request-1")["reason"] == "LIVE_EVIDENCE_INCOMPLETE"
    store.block_publication_request("request-1", "BLOCKED_FOR_REVIEW")
    assert store.publication_request("request-1")["status"] == "BLOCKED"


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


def test_exact_task_quarantine_clear_requires_one_matching_active_gate(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    from oss_pr_radar.task_quarantine import record

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="SHARED_CONTEXT_INVALID",
            dedupe_key="invalid-1",
            payload={"error": "published task result authentication is invalid"},
            created_at=now,
        )

    assert store.single_active_task_quarantine("a/b#1") == {
        "reason": "SHARED_CONTEXT_INVALID",
        "dedupeKey": "invalid-1",
        "payload": {"error": "published task result authentication is invalid"},
        "createdAt": now,
    }

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="PR_FOLLOWUP_REBIND_REQUIRED",
            dedupe_key="rebind-1",
            payload={"requiresRebind": True},
            created_at=now,
        )

    assert store.single_active_task_quarantine("a/b#1") is None
    with pytest.raises(LedgerError, match="sole active gate"):
        store.clear_task_quarantine_exact(
            "a/b#1",
            reason="SHARED_CONTEXT_INVALID",
            dedupe_key="invalid-1",
            evidence={"revalidated": True},
        )
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM task_quarantines WHERE opportunity_key=? AND status='ACTIVE'",
                ("a/b#1",),
            ).fetchone()[0]
            == 2
        )


def test_exact_task_quarantine_clear_clears_only_the_bound_row(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    from oss_pr_radar.task_quarantine import record

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="SHARED_CONTEXT_INVALID",
            dedupe_key="invalid-1",
            payload={"error": "published task result authentication is invalid"},
            created_at=now,
        )

    store.clear_task_quarantine_exact(
        "a/b#1",
        reason="SHARED_CONTEXT_INVALID",
        dedupe_key="invalid-1",
        evidence={"revalidated": True, "resultDigest": "result-1"},
    )

    assert store.single_active_task_quarantine("a/b#1") is None
    with store.connect() as connection:
        row = connection.execute(
            "SELECT status,clear_payload_json FROM task_quarantines WHERE opportunity_key=?",
            ("a/b#1",),
        ).fetchone()
    assert row["status"] == "CLEARED"
    assert json.loads(row["clear_payload_json"]) == {
        "resultDigest": "result-1",
        "revalidated": True,
    }


def _record_batch_task_quarantines(store: RadarLedger, *, now: str) -> None:
    from oss_pr_radar.task_quarantine import record

    with store.transaction() as connection:
        record(
            connection,
            opportunity_key="a/b#1",
            reason="SHARED_CONTEXT_INVALID",
            dedupe_key="invalid-1",
            payload={"error": "published task result authentication is invalid"},
            created_at=now,
        )
        record(
            connection,
            opportunity_key="a/b#1",
            reason="PR_FOLLOWUP_REBIND_REQUIRED",
            dedupe_key="rebind-1",
            payload={"requiresRebind": True},
            created_at=now,
        )


def test_active_task_quarantines_returns_every_payload_bound_gate(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)

    assert store.active_task_quarantines("a/b#1") == [
        {
            "reason": "SHARED_CONTEXT_INVALID",
            "dedupeKey": "invalid-1",
            "payload": {"error": "published task result authentication is invalid"},
            "payloadDigest": sha256_json(
                {"error": "published task result authentication is invalid"}
            ),
            "createdAt": now,
        },
        {
            "reason": "PR_FOLLOWUP_REBIND_REQUIRED",
            "dedupeKey": "rebind-1",
            "payload": {"requiresRebind": True},
            "payloadDigest": sha256_json({"requiresRebind": True}),
            "createdAt": now,
        },
    ]


def test_exact_task_quarantine_member_clear_preserves_unrelated_active_gate(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)
    payload_digest = sha256_json({"error": "published task result authentication is invalid"})

    store.clear_task_quarantine_member_exact(
        "a/b#1",
        reason="SHARED_CONTEXT_INVALID",
        dedupe_key="invalid-1",
        payload_digest=payload_digest,
        evidence={"revalidated": True, "repair": "exact-member-test"},
    )

    assert store.active_task_quarantines("a/b#1") == [
        {
            "reason": "PR_FOLLOWUP_REBIND_REQUIRED",
            "dedupeKey": "rebind-1",
            "payload": {"requiresRebind": True},
            "payloadDigest": sha256_json({"requiresRebind": True}),
            "createdAt": now,
        }
    ]
    with store.connect() as connection:
        cleared = connection.execute(
            """SELECT status,clear_payload_json FROM task_quarantines
               WHERE opportunity_key='a/b#1' AND dedupe_key='invalid-1'"""
        ).fetchone()
    assert cleared["status"] == "CLEARED"
    assert json.loads(cleared["clear_payload_json"]) == {
        "repair": "exact-member-test",
        "revalidated": True,
    }


def test_exact_task_quarantine_member_clear_rejects_payload_drift(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)

    with pytest.raises(LedgerError, match="member changed"):
        store.clear_task_quarantine_member_exact(
            "a/b#1",
            reason="SHARED_CONTEXT_INVALID",
            dedupe_key="invalid-1",
            payload_digest="f" * 64,
            evidence={"revalidated": True},
        )

    assert len(store.active_task_quarantines("a/b#1")) == 2


def test_radar_event_backfill_replays_only_the_exact_cleared_gate(tmp_path):
    from oss_pr_radar.task_quarantine import backfill_from_radar_events

    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "PR_FOLLOWUP_REBIND_REQUIRED",
            "rebind-1",
            {"slot": 1},
            now,
        )
        store._event(
            connection,
            "a/b#1",
            "PR_FOLLOWUP_REBIND_REQUIRED",
            "rebind-2",
            {"slot": 2},
            now,
        )
        store._event(
            connection,
            "a/b#1",
            "LEGACY_RESULT_REQUIRES_MIGRATION",
            "legacy-1",
            {"legacy": True},
            now,
        )
        store._event(
            connection,
            "a/b#1",
            "TASK_QUARANTINE_CLEARED",
            "clear-rebind-1",
            {
                "reason": "PR_FOLLOWUP_REBIND_REQUIRED",
                "dedupeKey": "rebind-1",
                "revalidated": True,
            },
            now,
        )
        connection.execute("DELETE FROM task_quarantines")
    guard_root = tmp_path / "radar-action-guards"
    guard_root.mkdir(mode=0o700)
    with store.connect() as connection:
        backfill_from_radar_events(
            connection,
            action_guard_root=guard_root,
        )

    assert {
        (gate["reason"], gate["dedupeKey"]) for gate in store.active_task_quarantines("a/b#1")
    } == {
        ("PR_FOLLOWUP_REBIND_REQUIRED", "rebind-2"),
        ("LEGACY_RESULT_REQUIRES_MIGRATION", "legacy-1"),
    }


def test_managed_event_backfill_replays_only_the_exact_cleared_gate(tmp_path):
    from oss_pr_radar.managed_lifecycle import ManagedLedger
    from oss_pr_radar.task_quarantine import backfill_from_managed_events

    store = RadarLedger(tmp_path / "ledger.sqlite3")
    ManagedLedger(store.path, ensure_schema=True)
    now = iso_z(datetime.now(UTC))
    events = [
        ("PR_FOLLOWUP_REBIND_REQUIRED", "rebind-1", {"slot": 1}),
        ("PR_FOLLOWUP_REBIND_REQUIRED", "rebind-2", {"slot": 2}),
        ("LEGACY_RESULT_REQUIRES_MIGRATION", "legacy-1", {"legacy": True}),
        (
            "TASK_QUARANTINE_CLEARED",
            "clear-rebind-1",
            {
                "reason": "PR_FOLLOWUP_REBIND_REQUIRED",
                "dedupeKey": "rebind-1",
                "revalidated": True,
            },
        ),
    ]
    guard_root = tmp_path / "managed-action-guards"
    guard_root.mkdir(mode=0o700)
    with store.connect() as connection:
        for event_type, idempotency_key, payload in events:
            connection.execute(
                """INSERT INTO managed_lifecycle_events
                   (opportunity_key,event_type,state,idempotency_key,
                    idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    "a/b#1",
                    event_type,
                    "READY",
                    idempotency_key,
                    sha256_text(idempotency_key),
                    "test",
                    "{}",
                    now,
                    json.dumps(payload, sort_keys=True),
                ),
            )
        connection.execute("DELETE FROM task_quarantines")
        backfill_from_managed_events(
            connection,
            action_guard_root=guard_root,
        )

    assert {
        (gate["reason"], gate["dedupeKey"]) for gate in store.active_task_quarantines("a/b#1")
    } == {
        ("PR_FOLLOWUP_REBIND_REQUIRED", "rebind-2"),
        ("LEGACY_RESULT_REQUIRES_MIGRATION", "legacy-1"),
    }


def test_exact_task_quarantine_batch_clear_keeps_blocked_publications_unchanged(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)
    with store.transaction() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,reason,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "request-1",
                "a/b#1",
                "thread-1",
                "a" * 40,
                "fix/runtime",
                str(tmp_path / "worktree"),
                "evidence",
                "BLOCKED",
                "BLOCKED_REPRODUCTION_REQUIRED",
                json.dumps({"opportunityKey": "a/b#1"}),
                now,
                now,
            ),
        )
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,reason,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "request-2",
                "a/b#1",
                "thread-2",
                "b" * 40,
                "fix/unrelated",
                str(tmp_path / "other-worktree"),
                "other-evidence",
                "BLOCKED",
                "BLOCKED_REPRODUCTION_REQUIRED",
                json.dumps({"opportunityKey": "a/b#1"}),
                now,
                now,
            ),
        )

    gates = store.active_task_quarantines("a/b#1")
    store.clear_task_quarantines_exact(
        "a/b#1",
        gates=gates,
        evidence={"revalidated": True, "resultDigest": "result-1"},
    )

    assert store.active_task_quarantines("a/b#1") == []
    with store.connect() as connection:
        requests = connection.execute(
            """SELECT request_id,commit_sha,status,reason,updated_at
               FROM publication_requests WHERE opportunity_key='a/b#1'
               ORDER BY request_id"""
        ).fetchall()
        events = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='a/b#1' AND event_type='TASK_QUARANTINE_CLEARED'
               ORDER BY id"""
        ).fetchall()
    assert [tuple(row) for row in requests] == [
        (
            "request-1",
            "a" * 40,
            "BLOCKED",
            "BLOCKED_REPRODUCTION_REQUIRED",
            now,
        ),
        (
            "request-2",
            "b" * 40,
            "BLOCKED",
            "BLOCKED_REPRODUCTION_REQUIRED",
            now,
        ),
    ]
    assert [json.loads(row["payload_json"])["dedupeKey"] for row in events] == [
        "invalid-1",
        "rebind-1",
    ]
    assert all(json.loads(row["payload_json"])["revalidated"] is True for row in events)


@pytest.mark.parametrize("change", ["empty", "duplicate", "missing", "extra"])
def test_exact_task_quarantine_batch_clear_rejects_inexact_gate_sets(tmp_path, change):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)
    gates = store.active_task_quarantines("a/b#1")
    if change == "empty":
        changed = []
    elif change == "duplicate":
        changed = [gates[0], gates[0]]
    elif change == "missing":
        changed = gates[:1]
    else:
        changed = gates + [
            {
                "reason": "EXTRA_GATE",
                "dedupeKey": "extra-1",
                "payloadDigest": "f" * 64,
            }
        ]

    with pytest.raises(LedgerError, match="gate set"):
        store.clear_task_quarantines_exact(
            "a/b#1",
            gates=changed,
            evidence={"revalidated": True},
        )
    assert len(store.active_task_quarantines("a/b#1")) == 2


def test_exact_task_quarantine_batch_clear_rejects_payload_drift(tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)
    gates = store.active_task_quarantines("a/b#1")
    with store.transaction() as connection:
        connection.execute(
            """UPDATE task_quarantines SET payload_json=?
               WHERE opportunity_key='a/b#1' AND dedupe_key='invalid-1'""",
            (json.dumps({"error": "changed"}),),
        )

    with pytest.raises(LedgerError, match="active gate set changed"):
        store.clear_task_quarantines_exact(
            "a/b#1",
            gates=gates,
            evidence={"revalidated": True},
        )
    assert len(store.active_task_quarantines("a/b#1")) == 2


def test_exact_task_quarantine_batch_clear_rolls_back_every_write(tmp_path, monkeypatch):
    import oss_pr_radar.ledger as ledger_module

    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(intent())
    now = iso_z(datetime.now(UTC))
    _record_batch_task_quarantines(store, now=now)
    gates = store.active_task_quarantines("a/b#1")
    original_clear = ledger_module.clear_quarantine_exact
    attempts = 0

    def fail_second_clear(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            return 0
        return original_clear(*args, **kwargs)

    monkeypatch.setattr(ledger_module, "clear_quarantine_exact", fail_second_clear)
    with pytest.raises(LedgerError, match="batch was not cleared"):
        store.clear_task_quarantines_exact(
            "a/b#1",
            gates=gates,
            evidence={"revalidated": True},
        )

    assert len(store.active_task_quarantines("a/b#1")) == 2
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE opportunity_key='a/b#1'
                     AND event_type='TASK_QUARANTINE_CLEARED'"""
            ).fetchone()[0]
            == 0
        )


def _task_result_tombstone_ledger(tmp_path: Path) -> RadarLedger:
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
    return store


def _record_tombstone_preparation(
    store: RadarLedger,
    *,
    wake_digest: str,
    prepared_head_sha: str,
    thread_id: str = "thread-1",
) -> dict[str, Any]:
    snapshot = {
        "prUrl": "https://github.com/a/b/pull/9",
        "headSha": "9" * 40,
        "preparedHeadSha": prepared_head_sha,
        "actionDigest": "published-authority-action",
        "taskActionDigest": "published-authority-task-action",
        "wakeDigest": wake_digest,
        "actions": ["review follow-up"],
        "evidence": {"actionableCheckNames": ["test"]},
        "checkedAt": iso_z(datetime.now(UTC)),
    }
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "PR_FOLLOWUP_PREPARATION_BOUND",
            wake_digest,
            {"threadId": thread_id, "snapshot": snapshot},
            iso_z(datetime.now(UTC)),
        )
    return snapshot


def _ledger_tombstone_receipt(*, snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "code-path-tombstone-v1",
        "wakeDigest": snapshot["wakeDigest"],
        "preparedHeadSha": snapshot["preparedHeadSha"],
        "prUrl": snapshot["prUrl"],
        "actionDigest": snapshot["actionDigest"],
        "taskActionDigest": snapshot["taskActionDigest"],
        "checkedAt": snapshot["checkedAt"],
        "receiptDigest": sha256_json(snapshot),
    }


@pytest.mark.parametrize(
    "missing_field",
    [
        "followup_wake_digest",
        "code_path_tombstone_receipt",
        "continuation_head_sha",
        "pr_followup_snapshot",
    ],
)
def test_task_result_tombstone_binding_fields_are_all_or_none(tmp_path, missing_field):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="2" * 40,
    )
    binding = {
        "followup_wake_digest": snapshot["wakeDigest"],
        "code_path_tombstone_receipt": _ledger_tombstone_receipt(snapshot=snapshot),
        "continuation_head_sha": "3" * 40,
        "pr_followup_snapshot": snapshot,
    }
    binding.pop(missing_field)

    with pytest.raises(ValueError, match="tombstone continuation"):
        store.record_task_result_ingested(
            "a/b#1",
            digest="result-1",
            stage="FIX_READY",
            task_id="intent-1",
            thread_id="thread-1",
            **binding,
        )

    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='TASK_RESULT_INGESTED'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("mismatch", ["receipt", "snapshot"])
def test_task_result_tombstone_binding_rejects_wake_mismatch(tmp_path, mismatch):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="3" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    if mismatch == "receipt":
        receipt = dict(receipt) | {"wakeDigest": "2" * 64}
    else:
        snapshot = dict(snapshot) | {"wakeDigest": "2" * 64}

    with pytest.raises(ValueError, match="tombstone continuation"):
        store.record_task_result_ingested(
            "a/b#1",
            digest="result-1",
            stage="FIX_READY",
            task_id="intent-1",
            thread_id="thread-1",
            followup_wake_digest="1" * 64,
            code_path_tombstone_receipt=receipt,
            continuation_head_sha="5" * 40,
            pr_followup_snapshot=snapshot,
        )


def test_task_context_ignores_tombstone_continuation_for_different_result_digest(tmp_path):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="3" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    store.record_task_result_ingested(
        "a/b#1",
        digest="result-1",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
    )
    mismatched_continuation = {
        "taskId": "intent-1",
        "threadId": "thread-1",
        "stage": "FIX_READY",
        "resultDigest": "result-2",
        "followupWakeDigest": snapshot["wakeDigest"],
        "codePathTombstoneReceipt": receipt,
        "continuationHeadSha": "5" * 40,
        "prFollowupSnapshot": snapshot,
    }
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND",
            sha256_json(mismatched_continuation),
            mismatched_continuation,
            iso_z(datetime.now(UTC)),
        )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert "codePathTombstoneReceipt" not in context
    assert "codePathTombstoneContinuationHeadSha" not in context
    assert context["prFollowup"] is None


def test_existing_task_result_digest_can_be_upgraded_with_exact_tombstone_continuation(
    tmp_path,
):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="4" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    store.record_task_result_ingested(
        "a/b#1",
        digest="result-1",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
    )
    store.record_task_result_ingested(
        "a/b#1",
        digest="result-1",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=receipt,
        continuation_head_sha="5" * 40,
        pr_followup_snapshot=snapshot,
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert "codePathTombstoneReceipt" not in context
    assert "edit_files" not in context["allowedActions"]
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='TASK_RESULT_INGESTED'"
            ).fetchone()[0]
            == 1
        )
        continuation = json.loads(
            connection.execute(
                "SELECT payload_json FROM events "
                "WHERE event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'"
            ).fetchone()[0]
        )
    assert continuation["continuationHeadSha"] == "5" * 40


def test_task_context_accepts_latest_exact_tombstone_round_for_same_wake(tmp_path):
    store = _task_result_tombstone_ledger(tmp_path)
    wake_digest = "1" * 64
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest=wake_digest,
        prepared_head_sha="4" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    store.record_task_result_ingested(
        "a/b#1",
        digest="result-1",
        stage="VALIDATION_PENDING",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=wake_digest,
        code_path_tombstone_receipt=receipt,
        continuation_head_sha="5" * 40,
        pr_followup_snapshot=snapshot,
    )
    store.record_followup_result(
        "a/b#1",
        wake_digest=wake_digest,
        result_digest="result-1",
        stage="VALIDATION_PENDING",
    )
    store.record_task_result_ingested(
        "a/b#1",
        digest="result-2",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=wake_digest,
        code_path_tombstone_receipt=receipt,
        continuation_head_sha="6" * 40,
        pr_followup_snapshot=snapshot,
    )
    store.record_followup_result(
        "a/b#1",
        wake_digest=wake_digest,
        result_digest="result-2",
        stage="FIX_READY",
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert "codePathTombstoneReceipt" not in context
    with store.connect() as connection:
        continuation = json.loads(
            connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()[0]
        )
    assert continuation["resultDigest"] == "result-2"
    assert continuation["continuationHeadSha"] == "6" * 40


def test_task_context_tombstone_binding_is_thread_latest_and_yields_to_active_preparation(
    tmp_path,
):
    store = _task_result_tombstone_ledger(tmp_path)
    old_wake = "1" * 64
    old_result = "result-1"
    receipt_head = "4" * 40
    old_snapshot = _record_tombstone_preparation(
        store,
        wake_digest=old_wake,
        prepared_head_sha=receipt_head,
    )
    receipt = _ledger_tombstone_receipt(snapshot=old_snapshot)
    store.record_task_result_ingested(
        "a/b#1",
        digest=old_result,
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=old_wake,
        code_path_tombstone_receipt=receipt,
        continuation_head_sha="5" * 40,
        pr_followup_snapshot=old_snapshot,
    )
    store.record_followup_result(
        "a/b#1",
        wake_digest=old_wake,
        result_digest=old_result,
        stage="FIX_READY",
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert "codePathTombstoneReceipt" not in context
    assert "edit_files" not in context["allowedActions"]

    store.record_task_result_ingested(
        "a/b#1",
        digest="other-thread-result",
        stage="FIX_READY",
        task_id="intent-2",
        thread_id="thread-2",
    )
    same_thread_context = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert "codePathTombstoneReceipt" not in same_thread_context

    active_wake = "6" * 64
    active_head = "7" * 40
    _record_tombstone_preparation(
        store,
        wake_digest=active_wake,
        prepared_head_sha=active_head,
    )
    active_context = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert active_context["prFollowup"]["wakeDigest"] == active_wake
    assert active_context["prFollowup"]["preparedHeadSha"] == active_head
    assert "codePathTombstoneReceipt" not in active_context
    assert "codePathTombstoneContinuationHeadSha" not in active_context

    store.record_task_result_ingested(
        "a/b#1",
        digest="result-without-receipt",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
    )
    store.record_followup_result(
        "a/b#1",
        wake_digest=active_wake,
        result_digest="result-without-receipt",
        stage="FIX_READY",
    )
    cleared_context = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert cleared_context["prFollowup"] is None
    assert "codePathTombstoneReceipt" not in cleared_context
    assert "codePathTombstoneContinuationHeadSha" not in cleared_context


def _signed_recovered_tombstone_bundle(
    tmp_path: Path,
    *,
    task_id: str,
    thread_id: str,
    worktree_path: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    from oss_pr_radar.repo_probe import (
        attest_code_path_tombstones,
        attest_task_reproduction_result,
    )

    checkout = tmp_path / f"signed-recovery-{task_id}"
    checkout.mkdir()

    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=checkout, check=True, capture_output=True, text=True
        )
        return completed.stdout.strip()

    git("init")
    git("config", "user.name", "Test Contributor")
    git("config", "user.email", "test@example.com")
    (checkout / "deleted.py").write_text("deleted = True\n", encoding="utf-8")
    (checkout / "present.py").write_text("present = True\n", encoding="utf-8")
    git("add", "deleted.py", "present.py")
    git("commit", "-m", "test: signed recovery base")
    base_sha = git("rev-parse", "HEAD")
    code_paths = ["deleted.py", "present.py"]
    result_digest = sha256_json(
        {
            "taskId": task_id,
            "threadId": thread_id,
            "baseSha": base_sha,
            "codePaths": code_paths,
        }
    )
    reproduction_receipt = attest_task_reproduction_result(
        checkout_path=checkout,
        repo="a/b",
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=code_paths,
        issue_url="https://github.com/a/b/issues/1",
        task_id=task_id,
        thread_id=thread_id,
        head_sha=base_sha,
        commit_sha=base_sha,
        result_digest=result_digest,
        result={
            "reproductionVerified": True,
            "evidence": {"summary": "The regression is reproduced."},
            "tests": [{"command": "python3 present.py", "exitCode": 0}],
        },
    )
    snapshot = {
        "prUrl": "https://github.com/a/b/pull/9",
        "headSha": "8" * 40,
        "preparedHeadSha": "9" * 40,
        "actionDigest": "signed-recovery-action",
        "taskActionDigest": "signed-recovery-task-action",
        "wakeDigest": "7" * 64,
        "actions": ["review follow-up"],
        "evidence": {"actionableCheckNames": ["test"]},
        "checkedAt": iso_z(datetime.now(UTC)),
    }
    tombstone_receipt = attest_code_path_tombstones(
        source_receipt_digest=str(reproduction_receipt["receiptDigest"]),
        base_sha=base_sha,
        key="a/b#1",
        issue_url="https://github.com/a/b/issues/1",
        intent_id=task_id,
        thread_id=thread_id,
        worktree_path_fingerprint=sha256_text(str(Path(worktree_path).resolve())),
        pr_url=snapshot["prUrl"],
        wake_digest=snapshot["wakeDigest"],
        action_digest=snapshot["actionDigest"],
        task_action_digest=snapshot["taskActionDigest"],
        checked_at=snapshot["checkedAt"],
        prepared_head_sha=snapshot["preparedHeadSha"],
        code_paths=code_paths,
        present_paths=["present.py"],
        tombstone_paths=["deleted.py"],
    )
    return reproduction_receipt, tombstone_receipt, snapshot


def _recovered_tombstone_context(
    *,
    worktree_path: str,
    reproduction_receipt: dict[str, Any],
    tombstone_receipt: dict[str, Any],
    snapshot: dict[str, Any],
    context_digest: str,
    **updates: Any,
) -> dict[str, Any]:
    prepared_head_sha = str(tombstone_receipt["preparedHeadSha"])
    current_result_digest = sha256_json(
        {
            "contextDigest": context_digest,
            "preparedHeadSha": prepared_head_sha,
            "wakeDigest": snapshot["wakeDigest"],
        }
    )
    value = published_task_context(
        intentId="intent-1",
        threadId="thread-1",
        worktreePath=worktree_path,
        selectedBaseSha=reproduction_receipt["baseSha"],
        codePaths=list(reproduction_receipt["codePaths"]),
        probeReceiptDigest=reproduction_receipt["receiptDigest"],
        resultDigest=current_result_digest,
        headSha=prepared_head_sha,
        commitSha=prepared_head_sha,
        reproductionReceipt=reproduction_receipt,
        codePathTombstoneReceipt=tombstone_receipt,
        prFollowup=snapshot,
        contextDigest=context_digest,
    )
    value.update(updates)
    return value


def _resign_recovered_tombstone(
    *,
    reproduction_receipt: dict[str, Any],
    snapshot: dict[str, Any],
    worktree_path: str,
    prepared_head_sha: str,
    wake_digest: str,
    checked_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    from oss_pr_radar.repo_probe import attest_code_path_tombstones

    refreshed_snapshot = dict(snapshot) | {
        "preparedHeadSha": prepared_head_sha,
        "wakeDigest": wake_digest,
        "actionDigest": f"refreshed-action-{wake_digest[:8]}",
        "taskActionDigest": f"refreshed-task-action-{wake_digest[:8]}",
        "checkedAt": checked_at,
    }
    refreshed_receipt = attest_code_path_tombstones(
        source_receipt_digest=str(reproduction_receipt["receiptDigest"]),
        base_sha=str(reproduction_receipt["baseSha"]),
        key="a/b#1",
        issue_url="https://github.com/a/b/issues/1",
        intent_id="intent-1",
        thread_id="thread-1",
        worktree_path_fingerprint=sha256_text(str(Path(worktree_path).resolve())),
        pr_url=str(refreshed_snapshot["prUrl"]),
        wake_digest=str(refreshed_snapshot["wakeDigest"]),
        action_digest=str(refreshed_snapshot["actionDigest"]),
        task_action_digest=str(refreshed_snapshot["taskActionDigest"]),
        checked_at=str(refreshed_snapshot["checkedAt"]),
        prepared_head_sha=str(refreshed_snapshot["preparedHeadSha"]),
        code_paths=list(reproduction_receipt["codePaths"]),
        present_paths=["present.py"],
        tombstone_paths=["deleted.py"],
    )
    return refreshed_receipt, refreshed_snapshot


def _bind_managed_reproduction_receipt(
    store: RadarLedger,
    *,
    worktree_path: str,
    reproduction_receipt: dict[str, Any],
) -> None:
    from oss_pr_radar.managed_lifecycle import ManagedLedger

    managed = ManagedLedger(store.path, ensure_schema=True)
    managed.upsert_opportunity(
        opportunity_key="a/b#1",
        owner="a",
        repo="b",
        issue_number=1,
        issue_url="https://github.com/a/b/issues/1",
        state="SYSTEM_PROCESSING",
        source="test-context-authority",
        provenance={"fixture": True},
        metadata={
            "selectedBaseSha": reproduction_receipt["baseSha"],
            "codePaths": reproduction_receipt["codePaths"],
        },
    )
    managed.bind_task(
        task_id="intent-1",
        opportunity_key="a/b#1",
        thread_id="thread-1",
        worktree_path=worktree_path,
        state="REPRODUCTION_REQUIRED",
        provenance={
            "selectedBaseSha": reproduction_receipt["baseSha"],
            "codePaths": reproduction_receipt["codePaths"],
            "headSha": reproduction_receipt["headSha"],
            "commitSha": reproduction_receipt["commitSha"],
            "resultDigest": reproduction_receipt["resultDigest"],
        },
    )
    managed.transition_task_to_implementation(
        task_id="intent-1",
        receipt_digest=reproduction_receipt["receiptDigest"],
        receipt=reproduction_receipt,
    )


def test_restore_existing_legacy_intent_atomically_adds_verified_recovery_receipt(tmp_path):
    store = RadarLedger(tmp_path / "restore-existing.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    old_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="old-context",
        autoSubmitAuthorized=False,
        publicSubmissionAllowed=False,
        resultDigest=reproduction_receipt["resultDigest"],
        headSha=reproduction_receipt["headSha"],
        commitSha=reproduction_receipt["commitSha"],
    )
    old_context.pop("reproductionReceipt")
    old_context.pop("codePathTombstoneReceipt")
    old_context.pop("prFollowup")
    old_context.pop("resultDigest")
    old_context.pop("headSha")
    old_context.pop("commitSha")
    store.restore_task_context(old_context)

    upgraded_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="new-context",
        autoSubmitAuthorized=True,
        publicSubmissionAllowed=True,
    )
    restored = store.restore_task_context(upgraded_context)
    store.restore_task_context(upgraded_context)

    assert restored["intentRestored"] is False
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
    assert payload["recoveredReproductionReceipt"] == reproduction_receipt
    assert payload["probeReceiptDigest"] == reproduction_receipt["receiptDigest"]
    assert payload["selectedBaseSha"] == reproduction_receipt["baseSha"]
    assert payload["codePaths"] == reproduction_receipt["codePaths"]
    assert payload["resultDigest"] == upgraded_context["resultDigest"]
    assert payload["headSha"] == upgraded_context["headSha"]
    assert payload["commitSha"] == upgraded_context["commitSha"]
    assert payload["resultDigest"] != reproduction_receipt["resultDigest"]
    assert payload["headSha"] != reproduction_receipt["headSha"]
    assert payload["autoSubmitAuthorized"] is False
    assert payload["publicSubmissionAllowed"] is False

    store.record_task_result_ingested(
        "a/b#1",
        digest=reproduction_receipt["resultDigest"],
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=tombstone_receipt,
        continuation_head_sha="6" * 40,
        pr_followup_snapshot=snapshot,
    )
    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert task["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in task["allowedActions"]
    assert task["reproductionReceipt"] == reproduction_receipt


@pytest.mark.parametrize(
    ("field", "conflicting_value"),
    [
        ("codePaths", ["other.py"]),
        ("selectedBaseSha", "e" * 40),
        ("probeReceiptDigest", "f" * 64),
    ],
)
def test_restore_existing_intent_rejects_conflicting_recovery_bundle_atomically(
    tmp_path,
    field,
    conflicting_value,
):
    store = RadarLedger(tmp_path / "restore-conflict.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    old_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="old-conflicting-context",
        **{field: conflicting_value},
    )
    old_context.pop("reproductionReceipt")
    old_context.pop("codePathTombstoneReceipt")
    old_context.pop("prFollowup")
    store.restore_task_context(old_context)
    with store.connect() as connection:
        before_payload = connection.execute(
            "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
        ).fetchone()[0]
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    with pytest.raises(LedgerError, match=rf"conflicts with intent {field}"):
        store.restore_task_context(
            _recovered_tombstone_context(
                worktree_path=worktree_path,
                reproduction_receipt=reproduction_receipt,
                tombstone_receipt=tombstone_receipt,
                snapshot=snapshot,
                context_digest="new-conflicting-context",
            )
        )

    with store.connect() as connection:
        after_payload = connection.execute(
            "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
        ).fetchone()[0]
        after_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert after_payload == before_payload
    assert after_events == before_events


@pytest.mark.parametrize(
    "updates",
    [
        {"resultDigest": "not-a-result-digest"},
        {"headSha": "e" * 40},
        {"commitSha": "e" * 40},
    ],
)
def test_restore_tombstone_context_rejects_unbound_current_result_tuple(tmp_path, updates):
    store = RadarLedger(tmp_path / "restore-current-tuple.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="invalid-current-tuple",
        **updates,
    )

    with pytest.raises(LedgerError, match="tombstone authority"):
        store.restore_task_context(context)

    with store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


@pytest.mark.parametrize(
    "intent_status",
    [
        "PENDING",
        "LEASED",
        "CREATING",
        "REJECTED",
        "SUPERSEDED",
        "EXPIRED",
        "SHADOW_OBSERVED",
    ],
)
def test_inactive_intent_cannot_recover_tombstone_edit_authority(tmp_path, intent_status):
    store = RadarLedger(tmp_path / f"inactive-{intent_status}.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest=f"inactive-{intent_status}",
        )
    )
    with store.transaction() as connection:
        connection.execute(
            "UPDATE intents SET status=? WHERE intent_id='intent-1'", (intent_status,)
        )

    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert task["intentStatus"] == intent_status
    assert task["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in task["allowedActions"]
    assert task["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in task
    assert "codePathTombstoneContinuationHeadSha" not in task


def test_managed_receipt_cannot_bypass_corrupt_tombstone_continuation(tmp_path):
    from oss_pr_radar.managed_lifecycle import ManagedLedger

    store = RadarLedger(tmp_path / "managed-corrupt-tombstone.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest="managed-signed-context",
        )
    )
    managed = ManagedLedger(store.path, ensure_schema=True)
    managed.upsert_opportunity(
        opportunity_key="a/b#1",
        owner="a",
        repo="b",
        issue_number=1,
        issue_url="https://github.com/a/b/issues/1",
        state="SYSTEM_PROCESSING",
        source="test-managed-corrupt-continuation",
        provenance={"fixture": True},
        metadata={
            "selectedBaseSha": reproduction_receipt["baseSha"],
            "codePaths": reproduction_receipt["codePaths"],
        },
    )
    managed.bind_task(
        task_id="intent-1",
        opportunity_key="a/b#1",
        thread_id="thread-1",
        worktree_path=worktree_path,
        state="REPRODUCTION_REQUIRED",
        provenance={
            "selectedBaseSha": reproduction_receipt["baseSha"],
            "codePaths": reproduction_receipt["codePaths"],
            "headSha": reproduction_receipt["headSha"],
            "commitSha": reproduction_receipt["commitSha"],
            "resultDigest": reproduction_receipt["resultDigest"],
        },
    )
    managed.transition_task_to_implementation(
        task_id="intent-1",
        receipt_digest=reproduction_receipt["receiptDigest"],
        receipt=reproduction_receipt,
    )
    corrupt_receipt = dict(tombstone_receipt) | {"signature": "corrupt-signature"}
    store.record_task_result_ingested(
        "a/b#1",
        digest="f" * 64,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=corrupt_receipt,
        continuation_head_sha="6" * 40,
        pr_followup_snapshot=snapshot,
    )

    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert task["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in task["allowedActions"]
    assert task["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in task
    assert "codePathTombstoneContinuationHeadSha" not in task
    assert "codePathTombstoneReceipt" not in task
    assert "codePathTombstoneContinuationHeadSha" not in task


def test_audit_no_go_cannot_recover_tombstone_edit_authority_for_completed_intent(tmp_path):
    store = RadarLedger(tmp_path / "inactive-audit-no-go.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest="inactive-audit-no-go",
        )
    )
    with store.transaction() as connection:
        connection.execute("UPDATE intents SET status='COMPLETED' WHERE intent_id='intent-1'")
        connection.execute("UPDATE opportunities SET stage='AUDIT_NO_GO' WHERE key='a/b#1'")

    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert task["intentStatus"] == "COMPLETED"
    assert task["stage"] == "AUDIT_NO_GO"
    assert task["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in task["allowedActions"]
    assert task["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in task


def test_same_digest_continuation_exactly_binds_legacy_threadless_result(tmp_path):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="4" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    store.record_task_result_ingested("a/b#1", digest="legacy-result", stage="FIX_READY")
    store.record_task_result_ingested(
        "a/b#1",
        digest="legacy-result",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=receipt,
        continuation_head_sha="5" * 40,
        pr_followup_snapshot=snapshot,
    )

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert "codePathTombstoneReceipt" not in context
    with store.connect() as connection:
        result_row = connection.execute(
            """SELECT id FROM events WHERE event_type='TASK_RESULT_INGESTED'
               AND dedupe_key='legacy-result'"""
        ).fetchone()
        continuation = json.loads(
            connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'"""
            ).fetchone()[0]
        )
    assert continuation["sourceResultEventId"] == result_row["id"]
    assert continuation["taskId"] == "intent-1"
    assert continuation["threadId"] == "thread-1"


def test_legacy_threadless_result_rejects_nonexistent_intent_binding(tmp_path):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="4" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    store.record_task_result_ingested("a/b#1", digest="legacy-result", stage="FIX_READY")

    with pytest.raises(ValueError, match="continuation identity"):
        store.record_task_result_ingested(
            "a/b#1",
            digest="legacy-result",
            stage="FIX_READY",
            task_id="other-intent",
            thread_id="thread-1",
            followup_wake_digest=snapshot["wakeDigest"],
            code_path_tombstone_receipt=receipt,
            continuation_head_sha="5" * 40,
            pr_followup_snapshot=snapshot,
        )

    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'"""
            ).fetchone()[0]
            == 0
        )


def test_unbound_newer_result_does_not_clear_exact_threadless_result_binding(tmp_path):
    store = _task_result_tombstone_ledger(tmp_path)
    snapshot = _record_tombstone_preparation(
        store,
        wake_digest="1" * 64,
        prepared_head_sha="4" * 40,
    )
    receipt = _ledger_tombstone_receipt(snapshot=snapshot)
    store.record_task_result_ingested("a/b#1", digest="legacy-result", stage="FIX_READY")
    store.record_task_result_ingested(
        "a/b#1",
        digest="legacy-result",
        stage="FIX_READY",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=receipt,
        continuation_head_sha="5" * 40,
        pr_followup_snapshot=snapshot,
    )
    store.record_task_result_ingested("a/b#1", digest="unbound-newer", stage="FIX_READY")

    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert "codePathTombstoneReceipt" not in context
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'"""
            ).fetchone()[0]
            == 1
        )

    store.record_task_result_ingested(
        "a/b#1",
        digest="wrong-intent-newer",
        stage="FIX_READY",
        task_id="other-intent",
        thread_id="thread-1",
    )
    still_bound = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert "codePathTombstoneReceipt" not in still_bound

    store.record_task_result_ingested(
        "a/b#1",
        digest="task-bound-newer",
        stage="FIX_READY",
        task_id="intent-1",
    )
    cleared = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert "codePathTombstoneReceipt" not in cleared


def test_recovered_receipt_projection_rejects_corrupt_tombstone_signature(tmp_path):
    store = RadarLedger(tmp_path / "corrupt-tombstone.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest="signed-context",
        )
    )
    corrupt_receipt = dict(tombstone_receipt) | {"signature": "corrupt-signature"}
    store.record_task_result_ingested(
        "a/b#1",
        digest=reproduction_receipt["resultDigest"],
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=corrupt_receipt,
        continuation_head_sha="6" * 40,
        pr_followup_snapshot=snapshot,
    )

    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert task["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in task["allowedActions"]
    assert task["reproductionReceipt"] is None


def test_active_new_preparation_cannot_reuse_old_recovered_tombstone_authority(tmp_path):
    store = RadarLedger(tmp_path / "active-preparation.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest="signed-context",
        )
    )
    active_snapshot = _record_tombstone_preparation(
        store,
        wake_digest="a" * 64,
        prepared_head_sha="b" * 40,
    )

    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert task["prFollowup"]["wakeDigest"] == active_snapshot["wakeDigest"]
    assert task["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in task["allowedActions"]
    assert task["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in task


def test_native_existing_intent_can_recover_exact_signed_tombstone_authority(tmp_path):
    store = _task_result_tombstone_ledger(tmp_path)
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path="/tmp/worktree",
    )

    restored = store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path="/tmp/worktree",
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest="native-existing-context",
        )
    )

    assert restored["intentRestored"] is False
    task = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")
    assert task["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in task["allowedActions"]
    assert task["reproductionReceipt"] == reproduction_receipt
    assert task["codePathTombstoneReceipt"] == tombstone_receipt


@pytest.mark.parametrize("stage", ["VALIDATION_PENDING", "FIX_READY"])
def test_empty_ledger_context_recovery_projects_tombstone_until_new_result(
    tmp_path,
    stage,
):
    store = RadarLedger(tmp_path / f"context-continuation-{stage}.sqlite3")
    worktree_path = str(tmp_path / f"managed-worktree-{stage}")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest=f"{stage.lower()}-context",
            stage=stage,
        )
    )

    recovered = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert recovered["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in recovered["allowedActions"]
    assert recovered["codePathTombstoneReceipt"] == tombstone_receipt
    assert recovered["codePathTombstoneContinuationHeadSha"] == snapshot["preparedHeadSha"]
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'"""
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='TASK_RESULT_INGESTED'"
            ).fetchone()[0]
            == 0
        )

    store.record_task_result_ingested(
        "a/b#1",
        digest="new-result-without-tombstone",
        stage=stage,
        task_id="intent-1",
        thread_id="thread-1",
    )
    superseded = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert superseded["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in superseded["allowedActions"]
    assert "codePathTombstoneReceipt" not in superseded


def test_newer_context_revokes_old_tombstone_authority_and_blocks_replay(tmp_path):
    from oss_pr_radar.managed_lifecycle import ManagedLedger
    from oss_pr_radar.repo_probe import attest_code_path_tombstones

    store = RadarLedger(tmp_path / "context-authority-revocation.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="authorized-context-a",
    )
    store.restore_task_context(
        authorized_context,
        source_updated_at="2026-08-30T01:00:00Z",
    )

    managed = ManagedLedger(store.path, ensure_schema=True)
    managed.upsert_opportunity(
        opportunity_key="a/b#1",
        owner="a",
        repo="b",
        issue_number=1,
        issue_url="https://github.com/a/b/issues/1",
        state="SYSTEM_PROCESSING",
        source="test-context-authority-revocation",
        provenance={"fixture": True},
        metadata={
            "selectedBaseSha": reproduction_receipt["baseSha"],
            "codePaths": reproduction_receipt["codePaths"],
        },
    )
    managed.bind_task(
        task_id="intent-1",
        opportunity_key="a/b#1",
        thread_id="thread-1",
        worktree_path=worktree_path,
        state="REPRODUCTION_REQUIRED",
        provenance={
            "selectedBaseSha": reproduction_receipt["baseSha"],
            "codePaths": reproduction_receipt["codePaths"],
            "headSha": reproduction_receipt["headSha"],
            "commitSha": reproduction_receipt["commitSha"],
            "resultDigest": reproduction_receipt["resultDigest"],
        },
    )
    managed.transition_task_to_implementation(
        task_id="intent-1",
        receipt_digest=reproduction_receipt["receiptDigest"],
        receipt=reproduction_receipt,
    )

    revoked_context = dict(authorized_context) | {
        "contextDigest": "revoked-context-b",
        "taskStage": "REPRODUCTION_REQUIRED",
        "probeLevel": "UNVERIFIED",
    }
    for field in (
        "reproductionReceipt",
        "codePathTombstoneReceipt",
        "prFollowup",
        "resultDigest",
        "headSha",
        "commitSha",
    ):
        revoked_context.pop(field, None)
    store.restore_task_context(
        revoked_context,
        source_updated_at="2026-08-30T01:01:00Z",
    )

    revoked = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert revoked["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in revoked["allowedActions"]
    assert revoked["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in revoked
    assert "codePathTombstoneContinuationHeadSha" not in revoked
    with store.connect() as connection:
        revoked_payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        before_replay = connection.execute(
            "SELECT event_type,dedupe_key,payload_json FROM events ORDER BY id"
        ).fetchall()
        latest_marker = json.loads(
            connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()[0]
        )
    assert "recoveredReproductionReceipt" not in revoked_payload
    assert latest_marker["hasContinuation"] is False
    assert latest_marker["revokedContinuationDedupeKey"]

    replay = store.restore_task_context(
        authorized_context,
        source_updated_at="2026-08-30T01:02:00Z",
    )
    assert replay["supersededContextMirror"] is True
    with store.connect() as connection:
        after_replay = connection.execute(
            "SELECT event_type,dedupe_key,payload_json FROM events ORDER BY id"
        ).fetchall()
        replayed_payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
    assert after_replay == before_replay
    assert replayed_payload == revoked_payload
    still_revoked = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert still_revoked["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in still_revoked["allowedActions"]

    new_snapshot = dict(snapshot) | {
        "preparedHeadSha": "c" * 40,
        "wakeDigest": "d" * 64,
        "actionDigest": "new-signed-recovery-action",
        "taskActionDigest": "new-signed-recovery-task-action",
        "checkedAt": "2026-08-30T01:03:00Z",
    }
    new_tombstone_receipt = attest_code_path_tombstones(
        source_receipt_digest=str(reproduction_receipt["receiptDigest"]),
        base_sha=str(reproduction_receipt["baseSha"]),
        key="a/b#1",
        issue_url="https://github.com/a/b/issues/1",
        intent_id="intent-1",
        thread_id="thread-1",
        worktree_path_fingerprint=sha256_text(str(Path(worktree_path).resolve())),
        pr_url=str(new_snapshot["prUrl"]),
        wake_digest=str(new_snapshot["wakeDigest"]),
        action_digest=str(new_snapshot["actionDigest"]),
        task_action_digest=str(new_snapshot["taskActionDigest"]),
        checked_at=str(new_snapshot["checkedAt"]),
        prepared_head_sha=str(new_snapshot["preparedHeadSha"]),
        code_paths=list(reproduction_receipt["codePaths"]),
        present_paths=["present.py"],
        tombstone_paths=["deleted.py"],
    )
    new_authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=new_tombstone_receipt,
        snapshot=new_snapshot,
        context_digest="new-authorized-context-c",
    )
    restored = store.restore_task_context(
        new_authorized_context,
        source_updated_at="2026-08-30T01:04:00Z",
    )
    assert restored.get("supersededContextMirror") is not True
    reauthorized = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert reauthorized["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in reauthorized["allowedActions"]
    assert reauthorized["reproductionReceipt"] == reproduction_receipt
    assert reauthorized["codePathTombstoneReceipt"] == new_tombstone_receipt
    with store.connect() as connection:
        active_marker = json.loads(
            connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()[0]
        )
        active_continuation = connection.execute(
            """SELECT dedupe_key FROM events
               WHERE event_type='TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
               ORDER BY id DESC LIMIT 1"""
        ).fetchone()
    assert active_marker["hasContinuation"] is True
    assert active_marker["continuationDedupeKey"] == active_continuation["dedupe_key"]


def test_equal_source_time_cannot_replace_context_authority(tmp_path):
    store = RadarLedger(tmp_path / "equal-context-authority-time.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="equal-time-authority-a",
    )
    store.restore_task_context(
        authorized_context,
        source_updated_at="2026-08-30T02:00:00Z",
    )
    conflicting_context = dict(authorized_context) | {"contextDigest": "equal-time-authority-b"}

    rejected = store.restore_task_context(
        conflicting_context,
        source_updated_at="2026-08-30T02:00:00Z",
    )

    assert rejected["supersededContextMirror"] is True
    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context["taskStage"] == "IMPLEMENTATION_READY"
    assert context["codePathTombstoneReceipt"] == tombstone_receipt


def test_same_context_refresh_advances_replay_watermark(tmp_path):
    store = RadarLedger(tmp_path / "context-authority-watermark.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="watermark-authority-a",
    )
    store.restore_task_context(
        authorized_context,
        source_updated_at="2026-08-30T03:00:00Z",
    )
    refreshed = store.restore_task_context(
        authorized_context,
        source_updated_at="2026-08-30T03:02:00Z",
    )
    assert refreshed["duplicateContextMirror"] is True
    assert refreshed["authorityWatermarkAdvanced"] is True

    unseen_stale_context = dict(authorized_context) | {"contextDigest": "unseen-stale-authority-d"}
    rejected = store.restore_task_context(
        unseen_stale_context,
        source_updated_at="2026-08-30T03:01:00Z",
    )

    assert rejected["supersededContextMirror"] is True
    current = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert current["taskStage"] == "IMPLEMENTATION_READY"
    assert current["codePathTombstoneReceipt"] == tombstone_receipt
    with store.connect() as connection:
        latest_marker = json.loads(
            connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                   ORDER BY id DESC LIMIT 1"""
            ).fetchone()[0]
        )
    assert latest_marker["authorityObservedAt"] == "2026-08-30T03:02:00Z"
    assert latest_marker["authorityTransition"] is False


@pytest.mark.parametrize("record_new_preparation", [False, True])
def test_fresh_context_authority_cannot_resurrect_older_preparation(
    tmp_path,
    record_new_preparation,
):
    store = _task_result_tombstone_ledger(tmp_path)
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path="/tmp/worktree",
    )
    _record_tombstone_preparation(
        store,
        wake_digest=snapshot["wakeDigest"],
        prepared_head_sha=snapshot["preparedHeadSha"],
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path="/tmp/worktree",
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="preparation-authority-a",
    )
    store.restore_task_context(
        authorized_context,
        source_updated_at="2026-08-30T04:00:00Z",
    )
    revoked_context = dict(authorized_context) | {
        "contextDigest": "preparation-revocation-b",
        "taskStage": "REPRODUCTION_REQUIRED",
        "probeLevel": "UNVERIFIED",
    }
    for field in (
        "reproductionReceipt",
        "codePathTombstoneReceipt",
        "prFollowup",
        "resultDigest",
        "headSha",
        "commitSha",
    ):
        revoked_context.pop(field, None)
    store.restore_task_context(
        revoked_context,
        source_updated_at="2026-08-30T04:01:00Z",
    )
    new_tombstone_receipt, new_snapshot = _resign_recovered_tombstone(
        reproduction_receipt=reproduction_receipt,
        snapshot=snapshot,
        worktree_path="/tmp/worktree",
        prepared_head_sha="c" * 40,
        wake_digest="d" * 64,
        checked_at="2026-08-30T04:02:00Z",
    )
    if record_new_preparation:
        _record_tombstone_preparation(
            store,
            wake_digest=new_snapshot["wakeDigest"],
            prepared_head_sha=new_snapshot["preparedHeadSha"],
        )
    fresh_context = _recovered_tombstone_context(
        worktree_path="/tmp/worktree",
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=new_tombstone_receipt,
        snapshot=new_snapshot,
        context_digest="preparation-authority-c",
    )
    store.restore_task_context(
        fresh_context,
        source_updated_at="2026-08-30T04:03:00Z",
    )

    current = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert current["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in current["allowedActions"]
    assert current["prFollowup"]["wakeDigest"] == new_snapshot["wakeDigest"]
    assert current["codePathTombstoneReceipt"] == new_tombstone_receipt


@pytest.mark.parametrize("old_result_has_continuation", [False, True])
@pytest.mark.parametrize(
    "revocation_offset_seconds",
    [0, 10],
    ids=["equal-time-fails-closed", "newer-revocation"],
)
def test_newer_context_revocation_beats_older_task_result_authority(
    tmp_path,
    old_result_has_continuation,
    revocation_offset_seconds,
):
    store = RadarLedger(tmp_path / "context-result-authority.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="result-authority-a",
    )
    store.restore_task_context(authorized_context)
    _bind_managed_reproduction_receipt(
        store,
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
    )
    old_result_digest = "a" * 64 if old_result_has_continuation else "b" * 64
    old_result_args: dict[str, Any] = {}
    if old_result_has_continuation:
        old_result_args = {
            "followup_wake_digest": snapshot["wakeDigest"],
            "code_path_tombstone_receipt": tombstone_receipt,
            "continuation_head_sha": snapshot["preparedHeadSha"],
            "pr_followup_snapshot": snapshot,
        }
    store.record_task_result_ingested(
        "a/b#1",
        digest=old_result_digest,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        **old_result_args,
    )
    with store.connect() as connection:
        old_result_created_at = parse_time(
            connection.execute(
                """SELECT created_at FROM events
                   WHERE event_type='TASK_RESULT_INGESTED' AND dedupe_key=?""",
                (old_result_digest,),
            ).fetchone()[0]
        )
    revocation_time = iso_z(old_result_created_at + timedelta(seconds=revocation_offset_seconds))
    revoked_context = dict(authorized_context) | {
        "contextDigest": "result-revocation-b",
        # These unsigned projection fields must not preserve authority after
        # the signed receipt/continuation has disappeared.
        "taskStage": "IMPLEMENTATION_READY",
        "probeLevel": "REPRODUCED_VALIDATED",
    }
    for field in (
        "reproductionReceipt",
        "codePathTombstoneReceipt",
        "prFollowup",
        "resultDigest",
        "headSha",
        "commitSha",
    ):
        revoked_context.pop(field, None)
    store.restore_task_context(
        revoked_context,
        source_updated_at=revocation_time,
    )

    revoked = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert revoked["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in revoked["allowedActions"]
    assert revoked["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in revoked

    fresh_result_digest = "c" * 64
    store.record_task_result_ingested(
        "a/b#1",
        digest=fresh_result_digest,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=tombstone_receipt,
        continuation_head_sha=snapshot["preparedHeadSha"],
        pr_followup_snapshot=snapshot,
    )
    fresh_result_time = iso_z(parse_time(revocation_time) + timedelta(seconds=10))
    with store.transaction() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='TASK_RESULT_INGESTED' AND dedupe_key=?""",
            (fresh_result_time, fresh_result_digest),
        )
        marker_row = connection.execute(
            """SELECT id,payload_json FROM events
               WHERE event_type='TASK_RESULT_AUTHORITY_BOUND'
                 AND json_extract(payload_json,'$.resultDigest')=?""",
            (fresh_result_digest,),
        ).fetchone()
        marker = json.loads(marker_row["payload_json"])
        marker["authorityObservedAt"] = fresh_result_time
        connection.execute(
            """UPDATE events SET created_at=?,dedupe_key=?,payload_json=? WHERE id=?""",
            (
                fresh_result_time,
                sha256_json(marker),
                json.dumps(marker, sort_keys=True, separators=(",", ":")),
                marker_row["id"],
            ),
        )

    reauthorized = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert reauthorized["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in reauthorized["allowedActions"]
    assert reauthorized["codePathTombstoneReceipt"] == tombstone_receipt


@pytest.mark.parametrize("authority_history", ["revoked", "legacy-unmarked"])
def test_fresh_signed_context_preserves_prior_result_revocation_watermark(
    tmp_path,
    authority_history,
):
    store = RadarLedger(tmp_path / f"fresh-context-{authority_history}.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="result-lineage-authority-a",
    )
    store.restore_task_context(authorized_context)
    store.record_task_result_ingested(
        "a/b#1",
        digest="1" * 64,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=tombstone_receipt,
        continuation_head_sha=snapshot["preparedHeadSha"],
        pr_followup_snapshot=snapshot,
    )
    with store.connect() as connection:
        result_created_at = parse_time(
            connection.execute(
                """SELECT created_at FROM events
                   WHERE event_type='TASK_RESULT_INGESTED' AND dedupe_key=?""",
                ("1" * 64,),
            ).fetchone()[0]
        )

    if authority_history == "revoked":
        revoked_context = dict(authorized_context) | {
            "contextDigest": "result-lineage-revocation-b",
            "taskStage": "REPRODUCTION_REQUIRED",
            "probeLevel": "UNVERIFIED",
        }
        for field in (
            "reproductionReceipt",
            "codePathTombstoneReceipt",
            "prFollowup",
            "resultDigest",
            "headSha",
            "commitSha",
        ):
            revoked_context.pop(field, None)
        store.restore_task_context(
            revoked_context,
            source_updated_at=iso_z(result_created_at + timedelta(seconds=10)),
        )
    else:
        with store.transaction() as connection:
            connection.execute(
                """DELETE FROM events WHERE event_type IN (
                     'TASK_CONTEXT_AUTHORITY_BOUND',
                     'TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND',
                     'TASK_RESULT_AUTHORITY_BOUND'
                   )"""
            )

    new_tombstone_receipt, new_snapshot = _resign_recovered_tombstone(
        reproduction_receipt=reproduction_receipt,
        snapshot=snapshot,
        worktree_path=worktree_path,
        prepared_head_sha="2" * 40,
        wake_digest="3" * 64,
        checked_at=iso_z(result_created_at + timedelta(seconds=15)),
    )
    fresh_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=new_tombstone_receipt,
        snapshot=new_snapshot,
        context_digest="result-lineage-authority-c",
    )
    store.restore_task_context(
        fresh_context,
        source_updated_at=iso_z(result_created_at + timedelta(seconds=20)),
    )

    current = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert current["taskStage"] == "IMPLEMENTATION_READY"
    assert "edit_files" in current["allowedActions"]
    assert current["prFollowup"]["wakeDigest"] == new_snapshot["wakeDigest"]
    assert current["codePathTombstoneReceipt"] == new_tombstone_receipt
    assert current["codePathTombstoneContinuationHeadSha"] == new_snapshot["preparedHeadSha"]


def test_legacy_unmarked_context_continuation_fails_closed_even_with_task_result(tmp_path):
    store = RadarLedger(tmp_path / "legacy-unmarked-context-authority.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    legacy_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="legacy-unmarked-authority",
    )
    store.restore_task_context(legacy_context)
    _bind_managed_reproduction_receipt(
        store,
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
    )
    store.record_task_result_ingested(
        "a/b#1",
        digest="e" * 64,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=tombstone_receipt,
        continuation_head_sha=snapshot["preparedHeadSha"],
        pr_followup_snapshot=snapshot,
    )
    with store.transaction() as connection:
        connection.execute(
            """DELETE FROM events WHERE event_type IN (
                 'TASK_CONTEXT_AUTHORITY_BOUND',
                 'TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND',
                 'TASK_RESULT_AUTHORITY_BOUND'
               )"""
        )

    current = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert current["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in current["allowedActions"]
    assert current["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in current
    with store.connect() as connection:
        events_before_result_replay = connection.execute("SELECT COUNT(*) FROM events").fetchone()[
            0
        ]
    store.record_task_result_ingested(
        "a/b#1",
        digest="e" * 64,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=tombstone_receipt,
        continuation_head_sha=snapshot["preparedHeadSha"],
        pr_followup_snapshot=snapshot,
    )
    with store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == (
            events_before_result_replay
        )
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='TASK_RESULT_AUTHORITY_BOUND'"""
            ).fetchone()[0]
            == 0
        )
        payload_before_replay = connection.execute(
            "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
        ).fetchone()[0]
        events_before_replay = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    replay = store.restore_task_context(
        legacy_context,
        source_updated_at=iso_z(datetime.now(UTC) + timedelta(hours=1)),
    )

    assert replay["supersededContextMirror"] is True
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
            == payload_before_replay
        )
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == (
            events_before_replay
        )
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='TASK_CONTEXT_AUTHORITY_BOUND'"""
            ).fetchone()[0]
            == 0
        )
    still_closed = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert still_closed["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in still_closed["allowedActions"]


def test_existing_result_cannot_gain_tombstone_authority_by_replay(tmp_path):
    store = RadarLedger(tmp_path / "result-continuation-replay.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    authorized_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="result-continuation-replay-a",
    )
    store.restore_task_context(authorized_context)
    _bind_managed_reproduction_receipt(
        store,
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
    )
    result_digest = "f" * 64
    store.record_task_result_ingested(
        "a/b#1",
        digest=result_digest,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
    )

    result_only = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert result_only["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in result_only["allowedActions"]

    store.record_task_result_ingested(
        "a/b#1",
        digest=result_digest,
        stage="PR_OPEN",
        task_id="intent-1",
        thread_id="thread-1",
        followup_wake_digest=snapshot["wakeDigest"],
        code_path_tombstone_receipt=tombstone_receipt,
        continuation_head_sha=snapshot["preparedHeadSha"],
        pr_followup_snapshot=snapshot,
    )

    replayed = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert replayed["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in replayed["allowedActions"]
    assert "codePathTombstoneReceipt" not in replayed
    with store.connect() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM events
                   WHERE event_type='TASK_RESULT_AUTHORITY_BOUND'"""
            ).fetchone()[0]
            == 0
        )


def test_late_context_recovery_cannot_override_existing_result_without_tombstone(tmp_path):
    store = RadarLedger(tmp_path / "newer-context-continuation.sqlite3")
    worktree_path = str(tmp_path / "managed-worktree")
    reproduction_receipt, tombstone_receipt, snapshot = _signed_recovered_tombstone_bundle(
        tmp_path,
        task_id="intent-1",
        thread_id="thread-1",
        worktree_path=worktree_path,
    )
    legacy_context = _recovered_tombstone_context(
        worktree_path=worktree_path,
        reproduction_receipt=reproduction_receipt,
        tombstone_receipt=tombstone_receipt,
        snapshot=snapshot,
        context_digest="legacy-context",
        stage="VALIDATION_PENDING",
    )
    legacy_context.pop("reproductionReceipt")
    legacy_context.pop("codePathTombstoneReceipt")
    legacy_context.pop("prFollowup")
    store.restore_task_context(legacy_context)
    store.record_task_result_ingested(
        "a/b#1",
        digest="older-result-without-tombstone",
        stage="VALIDATION_PENDING",
        task_id="intent-1",
        thread_id="thread-1",
    )

    store.restore_task_context(
        _recovered_tombstone_context(
            worktree_path=worktree_path,
            reproduction_receipt=reproduction_receipt,
            tombstone_receipt=tombstone_receipt,
            snapshot=snapshot,
            context_digest="newer-context",
            stage="VALIDATION_PENDING",
        )
    )

    recovered = store.task_context(
        issue_url="https://github.com/a/b/issues/1", thread_id="thread-1"
    )
    assert recovered["taskStage"] == "REPRODUCTION_REQUIRED"
    assert "edit_files" not in recovered["allowedActions"]
    assert recovered["reproductionReceipt"] is None
    assert "codePathTombstoneReceipt" not in recovered
    assert "codePathTombstoneContinuationHeadSha" not in recovered
