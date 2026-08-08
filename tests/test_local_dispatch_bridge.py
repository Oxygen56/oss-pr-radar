from __future__ import annotations

import importlib.util
import json
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.metrics import QUALITY_FIELDS
from oss_pr_radar.util import iso_z

SCRIPT = Path(__file__).parents[1] / "scripts" / "local_dispatch_bridge.py"
SPEC = importlib.util.spec_from_file_location("local_dispatch_bridge", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def run_git(path: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def registered_store(tmp_path: Path) -> tuple[RadarLedger, Path]:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
            "autoSubmitAuthorized": True,
            "publicSubmissionAllowed": True,
            "authorizationSource": "signed_live_revalidation_required",
            "publicationMode": "canary",
        }
    )
    store.claim("intent-1", "controller")
    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-1",
        project_id="github",
        worktree_path=str(worktree),
        title_time="08-05 16:00",
    )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "authorization": {"status": "ALLOW"},
            "evidenceDigest": "live-evidence",
            "liveAudit": {
                "capturedAt": iso_z(now),
                "evidence": {"digest": "live-evidence", "issue": {"state": "open"}},
            },
        },
        dedupe_key="test-live-evidence",
    )
    return store, worktree


def test_compact_title_matches_desktop_limit():
    value = "08-04 02:16 repo/project#42 " + "x" * 100
    result = MODULE.compact_title(value)
    assert len(result) == 59
    assert result.endswith("…")


def test_lifecycle_title_keeps_timestamp_and_value_prefix():
    result = MODULE.lifecycle_title(
        "FIX_READY", "08-04 05:25", "repo/project#42", "Runtime correctness"
    )
    assert result.startswith("[有价值·本地修复就绪] 08-04 05:25 repo/project#42")
    assert len(result) <= 59


def test_no_go_title_is_visibly_marked_before_archive():
    result = MODULE.lifecycle_title(
        "AUDIT_NO_GO", "08-04 18:47", "repo/project#42", "Duplicate work"
    )
    assert result.startswith("[无价值] 08-04 18:47 repo/project#42")


def test_canonical_prompt_unwraps_delegation():
    prompt = "[$gh-issue-pr](/tmp/SKILL.md)\nhttps://github.com/a/b/issues/1"
    wrapped = f"<codex_delegation><source_thread_id>x</source_thread_id><input>{prompt}</input></codex_delegation>"
    assert MODULE.canonical_prompt(wrapped) == prompt


def test_pr_lifecycle_prefers_merge_review_and_green_checks():
    assert MODULE.pr_lifecycle_stage({"state": "MERGED"}) == "MERGED"
    assert (
        MODULE.pr_lifecycle_stage({"state": "OPEN", "reviewDecision": "APPROVED"})
        == "MAINTAINER_ACCEPTED"
    )
    assert (
        MODULE.pr_lifecycle_stage(
            {
                "state": "OPEN",
                "statusCheckRollup": [
                    {"conclusion": "SUCCESS"},
                    {"conclusion": "SKIPPED"},
                ],
            }
        )
        == "CI_GREEN"
    )


def test_task_context_waits_for_live_handoff_receipt(monkeypatch, tmp_path):
    expected = {"threadId": "thread-1", "worktreePath": str(tmp_path)}

    class Store:
        calls = 0

        def task_context(self, **_kwargs):
            self.calls += 1
            return expected if self.calls == 2 else None

        def has_live_handoff(self, **_kwargs):
            return True

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "orphan_list",
        lambda _args: {"ok": True, "candidates": [], "blocked": [], "unmatched": []},
    )
    monkeypatch.setattr(MODULE, "sleep", lambda _seconds: None)

    result = MODULE.task_context(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            issue_url="https://github.com/a/b/issues/1",
            thread_id=None,
            worktree=str(tmp_path),
            wait_seconds=1,
        )
    )

    assert result == {"ok": True, "task": expected, "pendingHandoff": False}


def test_workspace_task_context_is_private_and_git_ignored(tmp_path):
    store, worktree = registered_store(tmp_path)

    path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["schemaVersion"] == "radar-task-context-v1"
    assert value["threadId"] == "thread-1"
    assert value["externalLedgerAccessAllowed"] is False
    assert value["planHubRequired"] is False
    assert value["networkPolicy"] == "controller_snapshot_only"
    assert value["childMayRequestApproval"] is False
    assert value["childMayWriteGitMetadata"] is False
    assert value["controllerOwnsCommit"] is True
    assert value["liveAudit"]["evidence"]["digest"] == "live-evidence"
    assert run_git(worktree, "status", "--porcelain") == ""

    store.record_stage("a/b#1", "FIX_READY", evidence={})
    refreshed = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )
    assert refreshed["stage"] == "FIX_READY"
    assert refreshed["contextDigest"] == value["contextDigest"]

    request = store.create_publication_request(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        commit_sha="a" * 40,
        branch="fix-runtime",
        worktree_path=str(worktree),
        evidence_digest="evidence",
        evidence_path=str(worktree / ".oss-pr-radar" / "result.json"),
        publication={
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: runtime",
            "bodyPath": str(worktree / ".oss-pr-radar" / "pr-body.md"),
        },
    )
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url="https://github.com/a/b/issues/1",
        commit_sha="a" * 40,
        branch="fix-runtime",
        evidence={},
    )
    store.consume_publication_permit(permit["permit_id"], "https://github.com/a/b/pull/2")
    published = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )

    assert published["stage"] == "PR_OPEN"
    assert published["publicationReceipt"]["status"] == "PR_OPEN"
    assert published["publicationReceipt"]["prUrl"] == "https://github.com/a/b/pull/2"
    assert published["contextDigest"] == value["contextDigest"]
    assert store.task_context_candidates()[0]["threadId"] == "thread-1"


def test_private_task_dispatch_is_not_limited_by_publication_canary(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)

    def candidate_intent(number: int):
        return {
            "intentId": f"intent-{number}",
            "key": f"a/b#{number}",
            "repo": "a/b",
            "issueNumber": number,
            "issueUrl": f"https://github.com/a/b/issues/{number}",
            "title": f"Runtime bug {number}",
            "mode": "canary",
            "category": "NEW_CLEAN_CANDIDATE",
            "scanGate": "ALLOW_TO_WORK",
            "autoSpawn": True,
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": f"decision-{number}",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }

    store.enqueue(candidate_intent(1))
    store.enqueue(candidate_intent(2))
    store.record_stage(
        "a/b#2",
        "AUDIT_PASS",
        evidence={"evidenceDigest": "evidence-2"},
        dedupe_key="intent-2:evidence-2",
    )
    store.claim("intent-1", "controller")
    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree-1",
    )

    evidence = SimpleNamespace(
        digest="evidence-2",
        as_dict=lambda: {"digest": "evidence-2", "complete": True},
    )
    verdict = SimpleNamespace(
        status="ALLOW",
        reason_code="ALLOW",
        as_dict=lambda: {"status": "ALLOW", "reasonCode": "ALLOW"},
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))
    monkeypatch.delenv("RADAR_MAX_ACTIVE_TASKS", raising=False)

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-2",
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )

    assert result["claimed"] is True
    with store.connect() as connection:
        audit = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='a/b#2' AND event_type='AUDIT_PASS'
               ORDER BY id DESC LIMIT 1"""
        ).fetchone()
    assert json.loads(audit["payload_json"])["liveAudit"]["evidence"]["digest"] == ("evidence-2")


def test_dispatch_notification_receipt_is_per_created_thread(tmp_path):
    store, _worktree = registered_store(tmp_path)

    assert [item["threadId"] for item in store.dispatch_notification_candidates()] == ["thread-1"]
    store.commit_dispatch_notification(thread_id="thread-1", idempotency_key="notification-1")
    assert store.dispatch_notification_candidates() == []


def test_prepare_failure_releases_claim(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    evidence = SimpleNamespace(
        digest="evidence",
        as_dict=lambda: {"digest": "evidence", "complete": True},
    )
    verdict = SimpleNamespace(
        status="ALLOW",
        reason_code="ALLOW",
        as_dict=lambda: {"status": "ALLOW", "reasonCode": "ALLOW"},
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))
    monkeypatch.setattr(
        MODULE,
        "source_repo",
        lambda _repo: (_ for _ in ()).throw(RuntimeError("clone timeout")),
    )

    with pytest.raises(RuntimeError, match="clone timeout"):
        MODULE.claim_intent(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                intent_id="intent-1",
                owner="controller",
                lease_minutes=15,
                prepare=True,
            )
        )

    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_claim_release_returns_unstarted_lease_to_pending(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    store.claim("intent-1", "controller")
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.release_claim(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            reason="CONTROLLER_DID_NOT_START_CREATION",
        )
    )

    assert result == {"ok": True, "intentId": "intent-1", "released": True}
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_new_repo_clone_is_shallow_and_atomic(monkeypatch, tmp_path):
    commands = []
    prewarmed = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        clone_target = Path(args[-1])
        clone_target.mkdir(parents=True)
        (clone_target / ".git").mkdir()
        return ""

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "prewarm_source_repo", prewarmed.append)

    path = MODULE.source_repo("example/large-repo")

    clone = commands[0][0]
    assert clone[:2] == ["git", "clone"]
    assert "--depth=1" in clone
    assert "--single-branch" in clone
    assert "--no-tags" in clone
    assert commands[0][2] == 180
    assert path == (tmp_path / "large-repo").resolve()
    assert prewarmed == [path]
    assert not list(tmp_path.glob(".large-repo.radar-clone-*"))


def test_existing_repo_fetches_and_prewarms_default_snapshot(monkeypatch, tmp_path):
    repo = tmp_path / "large-repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    commands = []
    prewarmed = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        if args == ["git", "remote", "get-url", "origin"]:
            return "https://github.com/example/large-repo.git"
        return ""

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "prewarm_source_repo", prewarmed.append)

    path = MODULE.source_repo("example/large-repo")

    assert commands[1][0] == [
        "git",
        "fetch",
        "--prune",
        "--no-tags",
        "--filter=blob:none",
        "origin",
    ]
    assert prewarmed == [path]


def test_prewarm_source_repo_refreshes_index_and_hydrates_only_default_snapshot(
    monkeypatch, tmp_path
):
    commands = []
    quiet_commands = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        if args[:3] == ["git", "symbolic-ref", "--quiet"]:
            return "refs/remotes/origin/main"
        return ""

    def fake_quiet_command(args, *, cwd, timeout=300):
        quiet_commands.append((args, cwd, timeout))

    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "quiet_command", fake_quiet_command)

    MODULE.prewarm_source_repo(tmp_path)

    assert commands[0][0] == [
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    ]
    assert quiet_commands == [
        (
            [
                "git",
                "archive",
                "--format=tar",
                "refs/remotes/origin/main",
            ],
            tmp_path,
            600,
        )
    ]


def test_retry_dispatch_requires_archived_clean_resultless_task(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", str(worktree), 1))
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.retry_dispatch(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            reason="INVALID_EXECUTION_ENVIRONMENT",
        )
    )

    assert result["retried"]["intentId"] == "intent-1"
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_retry_dispatch_accepts_worktree_removed_by_archival(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", str(worktree), 1))
    shutil.rmtree(worktree)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.retry_dispatch(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            reason="INVALID_EXECUTION_ENVIRONMENT",
        )
    )

    assert result["retried"]["intentId"] == "intent-1"
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_controller_ingests_workspace_no_go_without_child_ledger_access(tmp_path):
    store, worktree = registered_store(tmp_path)
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "STRONG_EXISTING_PR",
                "evidence": {"existingPr": "https://github.com/a/b/pull/2"},
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == [
        {"key": "a/b#1", "stage": "AUDIT_NO_GO", "reason": "STRONG_EXISTING_PR"}
    ]
    task = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert task is not None
    assert task["stage"] == "AUDIT_NO_GO"
    assert task["autoSubmitAuthorized"] is False


def _controller_commit_result(
    tmp_path: Path,
    *,
    policy_verified: bool = True,
    missing_quality: tuple[str, ...] = (),
    publication_blocked_reason: str | None = None,
    dco_required: bool = False,
) -> tuple[RadarLedger, Path, Path]:
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    source.write_text("value = 2\n", encoding="utf-8")
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    body_path = worktree / ".oss-pr-radar" / "pr-body.md"
    body_path.write_text("Fixes #1\n\nCorrect the runtime boundary.\n", encoding="utf-8")
    result_path = Path(context["resultPath"])
    quality = {field: True for field in QUALITY_FIELDS}
    quality["policy_verified"] = policy_verified
    for field in missing_quality:
        quality[field] = False
    result = {
        "schemaVersion": "radar-task-result-v1",
        "contextDigest": context["contextDigest"],
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "stage": "FIX_READY",
        "handoffMode": "controller_commit_required",
        "commitSha": None,
        "branch": "fix/1-runtime-boundary",
        "commitMessage": "fix: preserve runtime boundary",
        "changedFiles": ["runtime.py"],
        "tests": [{"command": "pytest tests/runtime", "exitCode": 0}],
        "quality": quality,
        "dcoRequired": dco_required,
        "publication": {
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: preserve runtime boundary",
            "bodyFile": str(body_path.resolve()),
        },
    }
    if publication_blocked_reason:
        result["publicationBlockedReason"] = publication_blocked_reason
    result_path.write_text(json.dumps(result), encoding="utf-8")
    return store, worktree, result_path


def test_controller_commits_validated_child_patch_and_requests_publication(tmp_path):
    store, worktree, result_path = _controller_commit_result(tmp_path)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(result["publicationRequests"]) == 1
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert finalized["commitSha"] == run_git(worktree, "rev-parse", "HEAD")
    assert finalized["branch"] == "fix/1-runtime-boundary"
    assert run_git(worktree, "status", "--porcelain") == ""
    assert run_git(worktree, "show", "--pretty=format:", "--name-only", "HEAD") == "runtime.py"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "FIX_READY"
    )


def test_controller_keeps_ai_disclosure_fix_local_and_signs_dco(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
        publication_blocked_reason="AI_DISCLOSURE_REQUIRED",
        dco_required=True,
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["publicationRequests"] == []
    assert result["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "FIX_READY",
            "publicationBlockedReason": "AI_DISCLOSURE_REQUIRED",
        }
    ]
    assert "Signed-off-by: Test Contributor <test@example.com>" in run_git(
        worktree, "show", "-s", "--format=%B", "HEAD"
    )
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert store.publication_work_items() == []


def test_controller_defers_blocked_local_fix_with_incomplete_validation(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
        publication_blocked_reason="AI_DISCLOSURE_REQUIRED",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["validationDeferred"] == [
        {
            "key": "a/b#1",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
            "missing": ["regression_test_verified", "relevant_tests_green"],
        }
    ]
    assert result["publicationRequests"] == []
    assert result["ingested"] == []
    with store.connect() as connection:
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE event_type='TASK_RESULT_VALIDATION_DEFERRED'
                 AND dedupe_key='thread-1'"""
        ).fetchone()
    assert json.loads(event["payload_json"])["missing"] == [
        "regression_test_verified",
        "relevant_tests_green",
    ]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "DISPATCHED"
    )


def test_controller_defers_unvalidated_publishable_fix_without_agent_failure(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=(
            "regression_test_verified",
            "relevant_tests_green",
            "independent_review_passed",
        ),
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == []
    assert result["publicationRequests"] == []
    assert result["validationDeferred"] == [
        {
            "key": "a/b#1",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
            "missing": [
                "regression_test_verified",
                "relevant_tests_green",
                "independent_review_passed",
            ],
        }
    ]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert finalized["commitSha"] == run_git(worktree, "rev-parse", "HEAD")
    assert store.publication_work_items() == []
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "DISPATCHED"
    )


def test_privileged_controller_runs_granted_publication_queue(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    class Store:
        def publication_work_items(self):
            return [
                {
                    "request_id": "request-1",
                    "request": {
                        "requestId": "request-1",
                        "opportunityKey": "a/b#1",
                        "issueUrl": "https://github.com/a/b/issues/1",
                        "commitSha": "a" * 40,
                        "branch": "fix-runtime",
                        "worktreePath": str(worktree),
                        "publication": {
                            "headOwner": "Oxygen56",
                            "baseBranch": "main",
                            "title": "fix: runtime",
                            "bodyPath": str(worktree / "body.md"),
                        },
                    },
                }
            ]

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args: {"granted": True, "permit": {"permit_id": "permit-1"}},
    )
    monkeypatch.setattr(MODULE, "ensure_fork_remote", lambda *_args: "radar-fork")
    calls = []

    def executor(operation, arguments, *, ledger_path):
        calls.append((operation, arguments, ledger_path))
        if operation == "push":
            return {"ok": True, "reconciled": False}
        return {"ok": True, "prUrl": "https://github.com/a/b/pull/2"}

    monkeypatch.setattr(MODULE, "_executor", executor)
    ledger_path = tmp_path / "ledger.sqlite3"

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=ledger_path))

    assert result["ok"] is True
    assert result["published"][0]["prUrl"] == "https://github.com/a/b/pull/2"
    assert [call[0] for call in calls] == ["push", "create-pr"]
    assert all(call[2] == ledger_path for call in calls)


def test_task_context_self_reconciles_exact_async_handoff(monkeypatch, tmp_path):
    issue_url = "https://github.com/a/b/issues/1"
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    class Store:
        reconciled = False
        commit_args = None

        def task_context(self, **_kwargs):
            if self.reconciled:
                return {"threadId": "thread-1", "worktreePath": str(worktree)}
            return None

        def commit_orphan_dispatch(self, intent_id, **kwargs):
            self.reconciled = True
            self.commit_args = (intent_id, kwargs)

        def has_live_handoff(self, **_kwargs):
            return True

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "orphan_list",
        lambda _args: {
            "ok": True,
            "blocked": [],
            "unmatched": [],
            "candidates": [
                {
                    "intentId": "intent-1",
                    "threadId": "thread-1",
                    "issueUrl": issue_url,
                    "repo": "a/b",
                    "cwd": str(worktree),
                    "titleTime": "08-04 18:47",
                    "leaseStartedAt": "2026-08-04T10:47:08Z",
                }
            ],
        },
    )

    result = MODULE.task_context(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            issue_url=issue_url,
            thread_id=None,
            worktree=str(worktree),
            wait_seconds=1,
        )
    )

    assert result["ok"] is True
    assert store.commit_args[0] == "intent-1"
    assert store.commit_args[1]["title_synced_state"] is None


def test_orphan_list_recovers_unique_async_worktree_task(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    cwd = worktree_root / "abcd" / "repo"
    cwd.mkdir(parents=True)
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                str(cwd),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                "https://github.com/a/b.git",
                0,
                int(now.timestamp()),
                int(now.timestamp() * 1000),
            ),
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "LEASED",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(minutes=1)),
                    "leaseUntil": iso_z(now + timedelta(minutes=29)),
                    "expiresAt": iso_z(now + timedelta(hours=1)),
                    "repo": "a/b",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["blocked"] == []
    assert result["candidates"][0]["threadId"] == "thread-1"
    assert result["candidates"][0]["desiredTitle"].startswith("[有价值·GO]")


def test_orphan_list_does_not_report_expired_lease_as_active(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "LEASED",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(minutes=31)),
                    "leaseUntil": iso_z(now - timedelta(minutes=1)),
                    "expiresAt": iso_z(now + timedelta(hours=1)),
                    "repo": "a/b",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {"ok": True, "candidates": [], "blocked": [], "unmatched": []}


def test_orphan_list_keeps_bound_async_creation_after_lease_expiry(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["candidates"] == []
    unmatched = result["unmatched"][0]
    expected = {
        "intentId": "intent-1",
        "key": "a/b#1",
        "leaseStartedAt": iso_z(now - timedelta(hours=2)),
        "creationStartedAt": iso_z(now - timedelta(hours=2)),
        "clientThreadId": "client-1",
        "creationPending": True,
        "abandonable": True,
    }
    assert {key: unmatched[key] for key in expected} == expected
    assert unmatched["creationAgeMinutes"] >= 119
    assert unmatched["abandonNonce"]


def test_creation_abandon_requires_a_stale_unmatched_bound_request(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        abandoned = None

        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

        def abandon_creation(self, intent_id, **kwargs):
            self.abandoned = (intent_id, kwargs)

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)
    probe = MODULE.orphan_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=70)
    )
    nonce = probe["unmatched"][0]["abandonNonce"]

    result = MODULE.creation_abandon(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            client_thread_id="client-1",
            abandon_nonce=nonce,
            reason="ASYNC_CREATION_NOT_MATERIALIZED",
            min_age_minutes=70,
        )
    )

    assert result["abandoned"] is True
    assert store.abandoned == (
        "intent-1",
        {
            "owner": "controller",
            "creation_token": "token-1",
            "client_thread_id": "client-1",
            "reason": "ASYNC_CREATION_NOT_MATERIALIZED",
            "min_age_minutes": 70,
        },
    )


def test_orphan_list_matches_late_thread_for_creating_intent(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    cwd = worktree_root / "late" / "repo"
    cwd.mkdir(parents=True)
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-late",
                str(cwd),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                "https://github.com/a/b.git",
                0,
                int(now.timestamp()),
                int(now.timestamp() * 1000),
            ),
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["blocked"] == []
    assert result["unmatched"] == []
    assert result["candidates"][0]["threadId"] == "thread-late"
