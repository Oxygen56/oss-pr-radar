from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_pr_radar.ledger import LedgerError, RadarLedger
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


def registered_store(tmp_path: Path, worktree: Path | None = None) -> tuple[RadarLedger, Path]:
    worktree = worktree or tmp_path / "worktree"
    worktree.mkdir(parents=True)
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


def test_validation_pending_title_remains_visibly_valuable():
    result = MODULE.lifecycle_title(
        "VALIDATION_PENDING", "08-09 05:25", "repo/project#42", "Runtime correctness"
    )
    assert result.startswith("[有价值·待验证] 08-09 05:25 repo/project#42")


def test_no_go_title_is_visibly_marked_before_archive():
    result = MODULE.lifecycle_title(
        "AUDIT_NO_GO", "08-04 18:47", "repo/project#42", "Duplicate work"
    )
    assert result.startswith("[无价值] 08-04 18:47 repo/project#42")


def test_title_list_detects_desktop_title_drift(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "PR_OPEN", evidence={})
    pending = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="PR_OPEN",
        nonce=pending["titleNonce"],
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, title TEXT, archived INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", "<codex_delegation>...", 0),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    result = MODULE.title_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert len(result["titles"]) == 1
    assert result["titles"][0]["threadId"] == "thread-1"
    assert result["titles"][0]["desiredTitle"].startswith("[有价值·PR已开] 08-05 16:00 a/b#1")
    with store.connect() as connection:
        drift = connection.execute(
            "SELECT payload_json FROM events WHERE event_type='THREAD_TITLE_DRIFTED'"
        ).fetchone()
    assert drift is not None
    assert "<codex_delegation>" not in drift["payload_json"]


def test_title_reconcile_applies_and_receipts_desktop_title(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "PR_OPEN", evidence={})
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, title TEXT, archived INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", "<codex_delegation>...", 0),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    def apply_titles(candidates):
        with sqlite3.connect(thread_db) as connection:
            for candidate in candidates:
                connection.execute(
                    "UPDATE threads SET title=? WHERE id=?",
                    (candidate["desiredTitle"], candidate["threadId"]),
                )
        return {str(candidate["threadId"]): None for candidate in candidates}

    monkeypatch.setattr(MODULE, "_set_desktop_thread_titles", apply_titles)

    result = MODULE.title_reconcile(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["errors"] == []
    assert result["renamed"][0]["threadId"] == "thread-1"
    assert MODULE.title_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")) == {
        "ok": True,
        "titles": [],
    }


def test_canonical_prompt_unwraps_delegation():
    prompt = "[$gh-issue-pr](/tmp/SKILL.md)\nhttps://github.com/a/b/issues/1"
    wrapped = f"<codex_delegation><source_thread_id>x</source_thread_id><input>{prompt}</input></codex_delegation>"
    assert MODULE.canonical_prompt(wrapped) == prompt


def test_terminal_feedback_is_published_only_for_unchanged_issues(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()
    feedback_path = state / "controller_terminal_feedback.json"
    calls = []

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2020-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(
        MODULE,
        "command",
        lambda args, **_kwargs: calls.append(args) or "",
    )

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    saved = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert result["published"] == 1
    assert result["stateChanged"] is True
    assert result["publishAttempts"] == 1
    assert saved["a/b#1"]["status"] == "controller_terminal"
    assert saved["a/b#1"]["terminal_reason"] == "ALREADY_FIXED"
    assert [call[2] for call in calls] == ["restore", "publish"]
    assert all("controller-feedback" in call for call in calls)


def test_terminal_feedback_reloads_and_merges_after_concurrent_publish(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()
    feedback_path = state / "controller_terminal_feedback.json"
    calls = []
    delays = []
    restore_count = 0
    publish_count = 0

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2020-01-01T00:00:00Z", "state": "open"}

    def concurrent_command(args, **_kwargs):
        nonlocal restore_count, publish_count
        calls.append(args)
        if args[2] == "restore":
            restore_count += 1
            if restore_count >= 2:
                feedback_path.write_text(
                    json.dumps(
                        {
                            "x/y#2": {
                                "status": "controller_terminal",
                                "terminal_reason": "CONCURRENT_RESULT",
                            }
                        }
                    ),
                    encoding="utf-8",
                )
        elif args[2] == "publish":
            publish_count += 1
            if publish_count <= 4:
                raise RuntimeError("state branch changed since restore")
        return ""

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", concurrent_command)
    monkeypatch.setattr(MODULE, "sleep", delays.append)

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    saved = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert result["published"] == 1
    assert result["stateChanged"] is True
    assert result["publishAttempts"] == 5
    assert set(saved) == {"a/b#1", "x/y#2"}
    assert [call[2] for call in calls] == ["restore", "publish"] * 5
    assert delays == [2, 4, 8, 8]


def test_terminal_feedback_does_not_republish_unchanged_state(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()
    feedback_path = state / "controller_terminal_feedback.json"
    feedback_path.write_text(
        json.dumps(
            {
                "a/b#1": {
                    "analyzed": "2020-01-01T00:00:00Z",
                    "status": "controller_terminal",
                    "controller_stage": "AUDIT_NO_GO",
                    "terminal_reason": "ALREADY_FIXED",
                    "issue_updated": "2020-01-01T00:00:00Z",
                    "scanner_version": MODULE.SCANNER_DECISION_REVISION,
                    "decision_contract_digest": MODULE.decision_contract_digest(),
                }
            }
        ),
        encoding="utf-8",
    )
    calls = []

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2020-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", lambda args, **_kwargs: calls.append(args) or "")

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    saved = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert result["published"] == 1
    assert result["stateChanged"] is False
    assert result["publishAttempts"] == 1
    assert saved["a/b#1"]["analyzed"] == "2020-01-01T00:00:00Z"
    assert [call[2] for call in calls] == ["restore"]


def test_terminal_feedback_defers_when_issue_changed_after_dispatch(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2099-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", lambda *_args, **_kwargs: "")

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["published"] == 0
    assert result["deferred"] == [{"key": "a/b#1", "reason": "issue_updated_after_local_snapshot"}]
    assert not (state / "controller_terminal_feedback.json").exists()


def test_terminal_feedback_uses_latest_terminal_recheck_time(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="INITIAL_NO_GO")
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET issued_at='2020-01-01T00:00:00Z' WHERE opportunity_key='a/b#1'"
        )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="UNCHANGED_AFTER_RECHECK")
    state = tmp_path / "state"
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2021-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", lambda *_args, **_kwargs: "")

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["published"] == 1
    assert result["deferred"] == []


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


@pytest.mark.parametrize("current", ["VALIDATION_PENDING", "FIX_READY"])
def test_remote_open_state_does_not_replace_local_pr_action_stage(current):
    assert MODULE.should_apply_pr_lifecycle_stage(current, "PR_OPEN") is False
    assert MODULE.should_apply_pr_lifecycle_stage(current, "CI_GREEN") is False
    assert MODULE.should_apply_pr_lifecycle_stage(current, "MAINTAINER_ACCEPTED") is False


@pytest.mark.parametrize("current", ["VALIDATION_PENDING", "FIX_READY"])
@pytest.mark.parametrize("remote", ["MERGED", "CLOSED"])
def test_remote_terminal_state_replaces_local_pr_action_stage(current, remote):
    assert MODULE.should_apply_pr_lifecycle_stage(current, remote) is True


def test_remote_pr_lifecycle_only_advances_published_stage():
    assert MODULE.should_apply_pr_lifecycle_stage("PR_OPEN", "CI_GREEN") is True
    assert MODULE.should_apply_pr_lifecycle_stage("CI_GREEN", "MAINTAINER_ACCEPTED") is True
    assert MODULE.should_apply_pr_lifecycle_stage("MAINTAINER_ACCEPTED", "PR_OPEN") is False


def test_refresh_pull_requests_preserves_local_validation_stage(monkeypatch, tmp_path):
    recorded = []

    class Store:
        def tracked_pull_requests(self):
            return [
                {
                    "key": "a/b#1",
                    "pr_url": "https://github.com/a/b/pull/9",
                    "stage": "VALIDATION_PENDING",
                }
            ]

        def record_stage(self, *args, **kwargs):
            recorded.append((args, kwargs))

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE,
        "command",
        lambda *_args, **_kwargs: json.dumps({"state": "OPEN", "statusCheckRollup": []}),
    )

    result = MODULE.refresh_pull_requests(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {"ok": True, "updates": [], "errors": []}
    assert recorded == []


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
    assert value["titleTime"] == "08-05 16:00"
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


def test_managed_workspace_context_is_mirrored_for_github_project_bootstrap(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path, worktree=worktree)

    path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    local = json.loads(path.read_text(encoding="utf-8"))
    bootstrap_path = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    bootstrap = json.loads(bootstrap_path.read_text(encoding="utf-8"))
    assert local == bootstrap
    assert local["workspaceMode"] == "github_project_managed_worktree"
    assert local["taskProjectRoot"] == str(project_root.resolve())
    assert local["bootstrapContextPath"] == str(bootstrap_path)
    assert local["worktreePath"] == str(worktree.resolve())


def test_shared_context_recovery_rebuilds_a_lost_local_ledger(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 1
    assert result["errors"] == []
    assert result["restored"][0]["stage"] == "FIX_READY"
    context = recovered.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context is not None
    assert context["intentStatus"] == "COMPLETED"
    assert context["stage"] == "FIX_READY"
    assert re.fullmatch(r"\d{2}-\d{2} \d{2}:\d{2}", context["titleTime"])


def test_shared_context_recovery_verifies_an_existing_dispatched_task(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    verified = MODULE.recover_shared_task_contexts(store)

    assert verified["verified"] == 1
    assert verified["errors"] == []
    assert verified["restored"] == [
        {
            "key": "a/b#1",
            "stage": "DISPATCHED",
            "intentRestored": False,
            "publicationRestored": False,
            "resultReceiptRestored": False,
        }
    ]


def test_shared_context_recovery_accepts_a_superseded_dispatched_mirror(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    verified = MODULE.recover_shared_task_contexts(store)

    assert verified["verified"] == 1
    assert verified["errors"] == []
    assert verified["restored"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "intentRestored": False,
            "publicationRestored": False,
            "supersededActiveMirror": True,
            "resultReceiptRestored": False,
        }
    ]


def test_shared_context_recovery_accepts_a_terminal_no_go_over_dispatched_mirror(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", evidence={}, reason="DUPLICATE")

    verified = MODULE.recover_shared_task_contexts(store)

    assert verified["verified"] == 1
    assert verified["errors"] == []
    assert verified["restored"] == [
        {
            "key": "a/b#1",
            "stage": "AUDIT_NO_GO",
            "intentRestored": False,
            "publicationRestored": False,
            "supersededActiveMirror": True,
            "resultReceiptRestored": False,
        }
    ]


def test_shared_context_recovery_does_not_rebuild_a_dispatched_task(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 0
    assert result["restored"] == []
    assert result["errors"][0]["error"] == "active task context disagrees with the ledger"


def test_shared_context_recovery_fails_closed_when_mirrors_disagree(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    value = json.loads(context_path.read_text(encoding="utf-8"))
    value["stage"] = "FIX_READY"
    MODULE._atomic_json(context_path, value)

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 0
    assert result["restored"] == []
    assert result["errors"][0]["error"] == "shared and worktree task context mirrors disagree"


def test_shared_context_recovery_marks_clean_published_result_as_consumed(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    store.record_stage("a/b#1", "FIX_READY", evidence={})
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
                "stage": "FIX_READY",
                "changedFiles": ["runtime.py"],
                "quality": {key: True for key in QUALITY_FIELDS},
                "publication": {
                    "headOwner": "Oxygen56",
                    "baseBranch": "main",
                    "title": "fix: runtime",
                    "bodyFile": str(worktree / ".oss-pr-radar" / "pr-body.md"),
                },
            }
        ),
        encoding="utf-8",
    )
    request = store.create_publication_request(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        commit_sha=head_sha,
        branch="fix-runtime",
        worktree_path=str(worktree),
        evidence_digest="evidence",
        evidence_path=str(result_path),
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
        commit_sha=head_sha,
        branch="fix-runtime",
        evidence={},
    )
    store.consume_publication_permit(permit["permit_id"], "https://github.com/a/b/pull/2")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    recovered_path = tmp_path / "recovered.sqlite3"
    recovered = RadarLedger(recovered_path)
    recovery = MODULE.recover_shared_task_contexts(recovered)
    ingestion = MODULE.ingest_task_results(SimpleNamespace(ledger=recovered_path))

    assert recovery["resultReceiptsRestored"] == 1
    assert recovery["restored"][0]["resultReceiptRestored"] is True
    assert ingestion["ok"] is True
    assert ingestion["ingested"] == []
    assert ingestion["publicationRequests"] == []
    with recovered.connect() as connection:
        followup_results = connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='PR_FOLLOWUP_RESULT_INGESTED'"
        ).fetchone()[0]
    assert followup_results == 0


def test_clean_pr_followup_result_restores_its_wake_receipt(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    MODULE._exclude_private_task_dir(worktree)
    private = worktree / ".oss-pr-radar"
    private.mkdir()
    result_path = private / "result.json"
    context = {
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "resultPath": str(result_path),
        "contextDigest": "context",
        "stage": "PR_OPEN",
        "publicationReceipt": {
            "prUrl": "https://github.com/a/b/pull/2",
            "commitSha": head_sha,
        },
        "prFollowup": {"wakeDigest": "wake"},
    }
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": "context",
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "followupDigest": "wake",
                "evidence": {"reviewed": True},
            }
        ),
        encoding="utf-8",
    )

    recovered = MODULE._recoverable_published_result(context)

    assert recovered is not None
    assert recovered["stage"] == "PR_OPEN"
    assert recovered["wakeDigest"] == "wake"

    context["contextDigest"] = "new-context"
    context["prFollowup"] = {"wakeDigest": "new-wake"}
    assert MODULE._recoverable_published_result(context) is None

    stale_fix = json.loads(result_path.read_text(encoding="utf-8"))
    stale_fix["stage"] = "FIX_READY"
    stale_fix.pop("followupDigest")
    result_path.write_text(json.dumps(stale_fix), encoding="utf-8")
    recovered_fix = MODULE._recoverable_published_result(context)
    assert recovered_fix is not None
    assert recovered_fix["stage"] == "FIX_READY"


def test_context_recovery_ignores_already_ingested_result_from_older_context(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    private = worktree / ".oss-pr-radar"
    private.mkdir()
    result_path = private / "result.json"
    context = {
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "resultPath": str(result_path),
        "contextDigest": "new-context",
        "stage": "PR_OPEN",
        "publicationReceipt": {
            "prUrl": "https://github.com/a/b/pull/2",
            "commitSha": head_sha,
        },
    }
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": "old-context",
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "followupDigest": "old-wake",
            }
        ),
        encoding="utf-8",
    )
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
            "category": "NEW_CLEAN_CANDIDATE",
            "scanGate": "ALLOW_TO_WORK",
            "autoSpawn": True,
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    digest = hashlib.sha256(result_path.read_bytes()).hexdigest()
    store.record_task_result_ingested("a/b#1", digest=digest, stage="PR_OPEN")

    assert MODULE._recoverable_published_result(context, store=store) is None


def test_prepare_managed_worktree_is_isolated_under_github_project(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    run_git(source, "init")
    run_git(source, "config", "user.name", "Test Contributor")
    run_git(source, "config", "user.email", "test@example.com")
    (source / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(source, "add", "runtime.py")
    run_git(source, "commit", "-m", "baseline")
    run_git(source, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)

    worktree = MODULE.prepare_managed_worktree(
        source,
        intent_id="intent-1",
        repo="a/b",
    )

    assert MODULE._is_managed_worktree(worktree) is True
    assert (worktree / "runtime.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert MODULE._worktree_belongs_to_source(worktree, source) is True
    assert run_git(worktree, "status", "--porcelain") == ""


def test_worktree_membership_uses_common_repository_for_linked_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    run_git(source, "init")
    run_git(source, "config", "user.name", "Test Contributor")
    run_git(source, "config", "user.email", "test@example.com")
    (source / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(source, "add", "runtime.py")
    run_git(source, "commit", "-m", "baseline")
    linked = tmp_path / "linked"
    run_git(source, "worktree", "add", "--detach", str(linked), "HEAD")

    assert MODULE._worktree_belongs_to_source(source, linked) is True


def test_commit_receipt_binds_github_project_thread_to_managed_worktree(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    source.mkdir()
    run_git(source, "init")
    run_git(source, "config", "user.name", "Test Contributor")
    run_git(source, "config", "user.email", "test@example.com")
    (source / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(source, "add", "runtime.py")
    run_git(source, "commit", "-m", "baseline")
    run_git(source, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.prepare_managed_worktree(
        source,
        intent_id="intent-1",
        repo="a/b",
    )
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
        dedupe_key="live-evidence",
    )
    title_time = "08-08 16:20"
    title = MODULE.lifecycle_title("GO", title_time, "a/b#1", "Runtime bug")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?)",
            (
                "thread-1",
                str(project_root),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                None,
                0,
            ),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    def apply_titles(candidates):
        assert candidates[0]["desiredTitle"] == title
        with sqlite3.connect(thread_db) as connection:
            connection.execute(
                "UPDATE threads SET title=? WHERE id=?",
                (candidates[0]["desiredTitle"], candidates[0]["threadId"]),
            )
        return {"thread-1": None}

    monkeypatch.setattr(MODULE, "_set_desktop_thread_titles", apply_titles)

    result = MODULE.commit_receipt(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            thread_id="thread-1",
            project_id="github-project",
            cwd=str(project_root),
            worktree=str(worktree),
            source_repo=str(source),
            title_time=title_time,
        )
    )

    assert result["workspaceMode"] == "github_project_managed_worktree"
    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context is not None
    assert context["worktreePath"] == str(worktree)
    assert MODULE.shared_context_path("https://github.com/a/b/issues/1").exists()


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


def test_claim_hold_does_not_terminalize_candidate(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent := {
            "intentId": "intent-hold",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(datetime.now(UTC)),
            "expiresAt": iso_z(datetime.now(UTC) + timedelta(hours=1)),
        }
    )
    evidence = SimpleNamespace(digest="evidence", as_dict=lambda: {"digest": "evidence"})
    verdict = SimpleNamespace(
        status="HOLD",
        reason_code="MAINTAINER_REVIEW_PENDING",
        as_dict=lambda: {
            "status": "HOLD",
            "reasonCode": "MAINTAINER_REVIEW_PENDING",
        },
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id=intent["intentId"],
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )

    assert result["authorized"] is False
    assert result["held"] is True
    assert store.pending()[0]["ledgerStatus"] == "PENDING"
    with store.connect() as connection:
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            "stage"
        ]
    assert stage == "QUALIFIED"


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


def test_prepare_claim_returns_single_project_root_and_isolated_worktree(monkeypatch, tmp_path):
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
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))
    monkeypatch.setattr(MODULE, "source_repo", lambda _repo: source)
    monkeypatch.setattr(MODULE, "prepare_managed_worktree", lambda *_args, **_kwargs: worktree)

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            lease_minutes=15,
            prepare=True,
            task_project_id="github-project",
        )
    )

    assert result["sourceRepoPath"] == str(source)
    assert result["taskProjectPath"] == str(project_root.resolve())
    assert result["worktreePath"] == str(worktree)
    assert result["leaseOwner"] == "controller"
    assert result["createThreadRequest"] == {
        "prompt": (
            "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)\n"
            "https://github.com/a/b/issues/1"
        ),
        "target": {
            "type": "project",
            "projectId": "github-project",
            "environment": {"type": "local"},
        },
    }
    assert "projectId" not in result["createThreadRequest"]


def test_creation_start_infers_active_lease_owner(monkeypatch, tmp_path):
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
    assert store.claim("intent-1", "controller") is not None
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.creation_start(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner=None,
        )
    )

    assert result["ok"] is True
    assert result["intentId"] == "intent-1"
    assert result["creationToken"]
    assert store.current_lease_owner("intent-1") == "controller"


def test_creation_start_does_not_override_explicit_wrong_owner(monkeypatch, tmp_path):
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
    assert store.claim("intent-1", "controller") is not None
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    with pytest.raises(LedgerError, match="not leased by this owner"):
        MODULE.creation_start(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                intent_id="intent-1",
                owner="mistyped-controller",
            )
        )


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
            owner=None,
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


def test_existing_repo_ignores_linked_worktree_candidates(monkeypatch, tmp_path):
    linked = tmp_path / "a-linked"
    linked.mkdir()
    (linked / ".git").write_text("gitdir: /tmp/common/worktrees/a-linked\n")
    repo = tmp_path / "b-main"
    repo.mkdir()
    (repo / ".git").mkdir()
    commands = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        if args == ["git", "remote", "get-url", "origin"]:
            assert cwd == repo
            return "https://github.com/example/large-repo.git"
        return ""

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "prewarm_source_repo", lambda _path: None)

    path = MODULE.source_repo("example/large-repo")

    assert path == repo.resolve()
    assert all(cwd != linked for _args, cwd, _timeout, _stdin in commands)


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


def test_recovery_accepts_github_project_thread_with_managed_worktree(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(project_root),
                None,
                1,
                None,
            ),
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["blocked"] == []
    assert result["recoverable"][0]["threadId"] == "thread-1"


def test_pr_followup_list_defers_recently_active_threads(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, updated_at INTEGER)")
        connection.executemany(
            "INSERT INTO threads VALUES (?,?)",
            [
                ("thread-active", int(datetime.now(UTC).timestamp())),
                (
                    "thread-idle",
                    int((datetime.now(UTC) - timedelta(hours=2)).timestamp()),
                ),
            ],
        )

    class Store:
        def pr_followup_candidates(self):
            return [
                {"key": "a/b#1", "threadId": "thread-active"},
                {"key": "a/b#2", "threadId": "thread-idle"},
            ]

        def unresolved_pr_followups(self):
            return []

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert [item["threadId"] for item in result["candidates"]] == ["thread-idle"]
    assert [item["threadId"] for item in result["activeDeferred"]] == ["thread-active"]
    assert result["activeDeferred"][0]["reason"] == "thread_recently_active"


def test_pr_followup_abandons_only_when_no_target_turn_materialized(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    reserved_at = iso_z(now - timedelta(hours=2))
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, updated_at INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?)",
            ("thread-1", int((now - timedelta(hours=3)).timestamp())),
        )

    class Store:
        abandoned = None

        def pr_followup_candidates(self):
            return []

        def unresolved_pr_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "thread_id": "thread-1",
                    "pr_url": "https://github.com/a/b/pull/2",
                    "wake_digest": "a" * 64,
                    "created_at": reserved_at,
                }
            ]

        def abandon_pr_followup_delivery(self, **kwargs):
            self.abandoned = kwargs
            return {"replacementWakeDigest": "b" * 64}

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    args = SimpleNamespace(
        ledger=tmp_path / "ledger.sqlite3",
        min_age_minutes=90,
    )
    probe = MODULE.pr_followup_list(args)
    unresolved = probe["unresolved"][0]

    result = MODULE.pr_followup_abandon(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            wake_digest="a" * 64,
            abandon_nonce=unresolved["abandonNonce"],
            reason="TARGET_TURN_NOT_MATERIALIZED",
            min_age_minutes=90,
        )
    )

    assert result["abandoned"] is True
    assert result["replacementWakeDigest"] == "b" * 64
    assert store.abandoned == {
        "thread_id": "thread-1",
        "wake_digest": "a" * 64,
        "reason": "TARGET_TURN_NOT_MATERIALIZED",
        "min_age_minutes": 90,
    }


def test_pr_followup_keeps_unknown_delivery_when_target_thread_updated(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, updated_at INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?)",
            ("thread-1", int((now - timedelta(minutes=30)).timestamp())),
        )

    class Store:
        def pr_followup_candidates(self):
            return []

        def unresolved_pr_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "thread_id": "thread-1",
                    "pr_url": "https://github.com/a/b/pull/2",
                    "wake_digest": "a" * 64,
                    "created_at": iso_z(now - timedelta(hours=2)),
                }
            ]

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["unresolved"][0]["targetTurnMaterialized"] is True
    assert result["unresolved"][0]["abandonable"] is False


def test_recovery_skips_a_recently_active_thread(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(project_root),
                None,
                int(datetime.now(UTC).timestamp()),
                None,
            ),
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["blocked"] == []
    assert result["recoverable"] == []


def test_recovery_immediately_surfaces_a_recent_terminal_desktop_error(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        "\n".join(
            [
                json.dumps({"type": "turn_context", "payload": {"turn_id": "turn-1"}}),
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": "turn-1",
                            "error": {
                                "codex_error_info": "cyber_policy",
                                "message": "try rephrasing",
                            },
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(project_root),
                None,
                int(datetime.now(UTC).timestamp()),
                str(rollout),
            ),
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["blocked"] == []
    assert result["recoverable"][0]["immediateRecovery"] is True
    assert result["recoverable"][0]["terminalError"]["code"] == "cyber_policy"


def test_latest_terminal_error_ignores_a_failure_before_a_new_turn(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "error": {"codex_error_info": "internal_error"},
                        },
                    }
                ),
                json.dumps({"type": "turn_context", "payload": {"turn_id": "turn-2"}}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert MODULE.latest_terminal_thread_error(str(rollout)) is None


def test_recovery_reserve_rephrases_a_benign_policy_false_positive(monkeypatch, tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "error": {"codex_error_info": "cyber_policy"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?)", ("thread-1", str(rollout)))

    class Store:
        def reserve_recovery(self, **_kwargs):
            return {
                "threadId": "thread-1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "recoveryNonce": "nonce",
            }

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            recovery_nonce="nonce",
        )
    )

    assert result["prompt"] == MODULE.BENIGN_POLICY_RECOVERY_PROMPT
    assert result["terminalError"]["code"] == "cyber_policy"


def test_cleanup_commit_removes_managed_bootstrap_context(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    bootstrap = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text("{}\n", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?)", ("thread-1", 1))

    class Store:
        committed = False

        def cleanup_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                    "cleanupNonce": "nonce",
                }
            ]

        def commit_cleanup(self, **_kwargs):
            self.committed = True

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    MODULE.cleanup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            cleanup_nonce="nonce",
        )
    )

    assert store.committed is True
    assert not bootstrap.exists()


def test_restore_list_and_commit_require_actual_unarchive(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", 1, "[无价值] task"))

    class Store:
        committed = False

        def restore_candidates(self):
            if self.committed:
                return []
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": "/tmp/worktree",
                    "restoreNonce": "nonce",
                }
            ]

        def commit_restore(self, **_kwargs):
            self.committed = True

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    pending = MODULE.restore_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert pending["restore"][0]["threadId"] == "thread-1"
    assert store.committed is False

    with sqlite3.connect(thread_db) as connection:
        connection.execute("UPDATE threads SET archived=0 WHERE id='thread-1'")
    result = MODULE.restore_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            restore_nonce="nonce",
        )
    )

    assert result["ok"] is True
    assert store.committed is True


def test_restore_list_reconciles_already_unarchived_task(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", 0, "task"))

    class Store:
        committed = False

        def restore_candidates(self):
            if self.committed:
                return []
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "restoreNonce": "nonce",
                }
            ]

        def commit_restore(self, **_kwargs):
            self.committed = True

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.restore_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["restore"] == []
    assert result["reconciled"][0]["threadId"] == "thread-1"
    assert store.committed is True


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


def _published_followup_store(
    tmp_path: Path,
) -> tuple[RadarLedger, Path, str, str]:
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(worktree, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(
        worktree,
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    )
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    pr_url = "https://github.com/a/b/pull/9"
    now = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/1-runtime',?,
                       'evidence','CONSUMED','{}',?,?)""",
            (head_sha, str(worktree), now, now),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/1-runtime','CONSUMED',?,?, '{}',?,?)""",
            (head_sha, iso_z(datetime.now(UTC) + timedelta(hours=1)), pr_url, now, now),
        )
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": pr_url})
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": now,
            "items": [
                {
                    "url": pr_url,
                    "headSha": head_sha,
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
    return store, worktree, head_sha, pr_url


def test_pr_followup_reserve_refreshes_context_and_uses_canonical_prompt(monkeypatch, tmp_path):
    store, worktree, _head_sha, pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    prepared = []

    def prepare(value):
        prepared.append(value)
        return {"preparedHeadSha": "b" * 40}

    monkeypatch.setattr(MODULE, "_prepare_pr_followup", prepare)

    result = MODULE.pr_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            wake_digest=candidate["wakeDigest"],
        )
    )

    assert prepared == [candidate]
    assert result["prUrl"] == pr_url
    assert result["prompt"] == MODULE.issue_prompt("https://github.com/a/b/issues/1")
    assert result["prompt"].splitlines() == [
        "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)",
        "https://github.com/a/b/issues/1",
    ]
    context = json.loads(Path(result["contextPath"]).read_text(encoding="utf-8"))
    assert context["prFollowup"]["wakeDigest"] == candidate["wakeDigest"]
    assert context["prFollowup"]["preparedHeadSha"] == "b" * 40
    assert context["publicationReceipt"]["prUrl"] == pr_url
    refreshed = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )
    assert refreshed["prFollowup"]["preparedHeadSha"] == "b" * 40
    assert refreshed["contextDigest"] == context["contextDigest"]
    assert store.pr_followup_candidates() == []


def test_pr_followup_reserve_binds_controller_verified_conflict_files(tmp_path):
    store, worktree, head_sha, pr_url = _published_followup_store(tmp_path)
    now = iso_z(datetime.now(UTC))
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": now,
            "items": [
                {
                    "url": pr_url,
                    "headSha": head_sha,
                    "actionDigest": "conflict-action",
                    "taskActionDigest": "conflict-task-action",
                    "taskFollowupRequired": True,
                    "taskActions": ["分支存在合并冲突"],
                    "evidence": {
                        "mergeConflict": True,
                        "baseRefName": "main",
                        "baseSha": "a" * 40,
                        "mergeConflictPreparationVersion": "conflict_files_v1",
                    },
                    "checkedAt": now,
                }
            ],
        }
    )
    candidate = store.pr_followup_candidates()[0]

    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=head_sha,
        prepared_base_sha="b" * 40,
        merge_conflict_files=["src/two.py", "src/one.py"],
    )
    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert context["prFollowup"]["preparedHeadSha"] == head_sha
    assert context["prFollowup"]["evidence"]["baseAdvancedFromSha"] == "a" * 40
    assert context["prFollowup"]["evidence"]["baseSha"] == "b" * 40
    assert context["prFollowup"]["evidence"]["mergeConflictFiles"] == [
        "src/one.py",
        "src/two.py",
    ]
    assert worktree.is_dir()
    assert store.unresolved_pr_followups()


def test_context_sync_recovers_legacy_prepared_followup_binding(tmp_path):
    store, worktree, previous_head, _pr_url = _published_followup_store(tmp_path)
    run_git(worktree, "switch", "main")
    (worktree / "base.py").write_text("base = True\n", encoding="utf-8")
    run_git(worktree, "add", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    prepared_base = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    run_git(worktree, "merge", "--no-ff", "--no-commit", prepared_base)
    run_git(worktree, "commit", "-m", "merge: refresh upstream branch for CI validation")
    prepared_head = run_git(worktree, "rev-parse", "HEAD")
    with store.connect() as connection:
        row = connection.execute(
            "SELECT evidence_json FROM pr_followups WHERE opportunity_key='a/b#1'"
        ).fetchone()
        evidence = json.loads(row["evidence_json"])
        evidence.update({"baseIntegrationRequired": True, "baseSha": "f" * 40})
        connection.execute(
            "UPDATE pr_followups SET evidence_json=? WHERE opportunity_key='a/b#1'",
            (json.dumps(evidence),),
        )
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    next_checked_at = iso_z(datetime.now(UTC) + timedelta(minutes=1))
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": next_checked_at,
            "items": [
                {
                    "url": "https://github.com/a/b/pull/9",
                    "headSha": previous_head,
                    "actionDigest": "new-action",
                    "taskActionDigest": "new-task-action",
                    "taskFollowupRequired": True,
                    "taskActions": ["存在未解决审查线程"],
                    "evidence": {
                        "baseIntegrationRequired": True,
                        "baseSha": "f" * 40,
                    },
                    "checkedAt": next_checked_at,
                }
            ],
        }
    )
    legacy_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
    assert "preparedHeadSha" not in legacy["prFollowup"]
    assert legacy["prFollowup"]["wakeDigest"] != candidate["wakeDigest"]
    Path(legacy["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": legacy["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "followupDigest": legacy["prFollowup"]["wakeDigest"],
                "evidence": {"verified": True},
            }
        ),
        encoding="utf-8",
    )

    recovered, errors = MODULE._recover_unbound_pr_followup_preparations(store)
    refreshed_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    refreshed = json.loads(refreshed_path.read_text(encoding="utf-8"))

    assert errors == []
    assert recovered[0]["preparedHeadSha"] == prepared_head
    assert refreshed["prFollowup"]["headSha"] == previous_head
    assert refreshed["prFollowup"]["preparedHeadSha"] == prepared_head
    assert refreshed["prFollowup"]["evidence"]["baseSha"] == prepared_base
    assert refreshed["contextDigest"] != legacy["contextDigest"]
    assert refreshed["prFollowup"]["wakeDigest"] == candidate["wakeDigest"]
    preparation = store.active_pr_followup_preparation("a/b#1", thread_id="thread-1")
    assert preparation["legacyCompatibility"] == {
        "contextDigest": legacy["contextDigest"],
        "wakeDigest": legacy["prFollowup"]["wakeDigest"],
    }
    assert store.pr_followup_candidates() == []

    ingested = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert ingested["ok"] is True
    assert ingested["ingested"] == [{"key": "a/b#1", "stage": "PR_OPEN"}]
    assert store.active_pr_followup_preparation("a/b#1", thread_id="thread-1") is None
    assert store.pr_followup_candidates()[0]["wakeDigest"] == legacy["prFollowup"]["wakeDigest"]


def test_context_sync_closes_legacy_reservation_superseded_by_later_result(tmp_path):
    store, worktree, head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=head_sha,
    )
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.record_followup_result(
        "a/b#1",
        wake_digest="f" * 64,
        result_digest="later-result",
        stage="PR_OPEN",
    )

    synced = MODULE.sync_task_contexts(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert synced["ok"] is True
    assert synced["prFollowupsSuperseded"] == [
        {
            "key": "a/b#1",
            "wakeDigest": candidate["wakeDigest"],
            "supersededBy": "f" * 64,
        }
    ]
    assert store.active_pr_followup_preparation("a/b#1", thread_id="thread-1") is None
    assert (worktree / ".oss-pr-radar" / "task-context.json").is_file()


def test_ingest_skips_consumed_result_after_followup_context_refresh(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    original_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    original = json.loads(original_path.read_text(encoding="utf-8"))
    result_path = Path(original["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": original["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "FIX_READY",
            }
        ),
        encoding="utf-8",
    )
    digest = hashlib.sha256(result_path.read_bytes()).hexdigest()
    store.record_task_result_ingested("a/b#1", digest=digest, stage="FIX_READY")
    refreshed_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
        prepared_followup_head="b" * 40,
    )
    refreshed = json.loads(refreshed_path.read_text(encoding="utf-8"))
    assert refreshed["contextDigest"] != original["contextDigest"]

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == []
    assert result["publicationRequests"] == []
    assert result["errors"] == []


def test_ingest_skips_blocked_fix_after_context_refresh(tmp_path):
    store, _worktree, result_path = _controller_commit_result(tmp_path)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    request_id = first["publicationRequests"][0]["requestId"]
    store.block_publication_request(request_id, "SUBMIT_READY_EVIDENCE_INCOMPLETE")
    context_path = result_path.parent / "task-context.json"
    refreshed = json.loads(context_path.read_text(encoding="utf-8"))
    refreshed["contextDigest"] = "refreshed-context"
    context_path.write_text(json.dumps(refreshed), encoding="utf-8")

    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert repeated["ok"] is True
    assert repeated["ingested"] == []
    assert repeated["publicationRequests"] == []
    assert repeated["errors"] == []


def test_prepare_pr_followup_accepts_fast_forwarded_base(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    remote = tmp_path / "remote.git"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    baseline = run_git(worktree, "rev-parse", "HEAD")
    run_git(remote.parent, "init", "--bare", str(remote))
    run_git(worktree, "remote", "add", "origin", str(remote))
    run_git(worktree, "push", "origin", f"{baseline}:refs/heads/main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    source.write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    live_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", "HEAD:refs/heads/fix/1-runtime")
    run_git(remote, "update-ref", "refs/pull/9/head", live_head)
    run_git(worktree, "switch", "--detach", baseline)
    source.write_text("value = 3\n", encoding="utf-8")
    (worktree / "base.py").write_text("base = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    live_base = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", f"{live_base}:refs/heads/main")
    run_git(worktree, "update-ref", "refs/remotes/origin/main", baseline)
    run_git(worktree, "switch", "--detach", baseline)
    run_git(worktree, "branch", "-f", "fix/1-runtime", baseline)
    monkeypatch.setattr(MODULE, "_upstream_remote", lambda *_args: "origin")

    prepared = MODULE._prepare_pr_followup(
        {
            "prUrl": "https://github.com/a/b/pull/9",
            "worktreePath": str(worktree),
            "branch": "fix/1-runtime",
            "headSha": live_head,
            "evidence": {
                "mergeConflict": True,
                "baseRefName": "main",
                "baseSha": baseline,
            },
        }
    )

    assert prepared == {
        "preparedHeadSha": live_head,
        "preparedBaseSha": live_base,
        "mergeConflictFiles": ["runtime.py"],
    }
    assert run_git(worktree, "rev-parse", "HEAD") == live_head
    assert run_git(worktree, "branch", "--show-current") == "fix/1-runtime"
    assert run_git(worktree, "rev-parse", "refs/remotes/origin/main") == live_base
    assert run_git(worktree, "status", "--porcelain") == ""


def test_prepare_conflicted_pr_followup_requires_signed_base_snapshot(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    monkeypatch.setattr(MODULE, "_upstream_remote", lambda *_args: "origin")

    with pytest.raises(RuntimeError, match="lacks base snapshot"):
        MODULE._prepare_pr_followup(
            {
                "prUrl": "https://github.com/a/b/pull/9",
                "worktreePath": str(worktree),
                "branch": "fix/1-runtime",
                "headSha": "a" * 40,
                "evidence": {"mergeConflict": True},
            }
        )


def test_prepare_pr_followup_creates_local_base_integration_commit(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    remote = tmp_path / "remote.git"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    baseline = run_git(worktree, "rev-parse", "HEAD")
    run_git(remote.parent, "init", "--bare", str(remote))
    run_git(worktree, "remote", "add", "origin", str(remote))
    run_git(worktree, "push", "origin", f"{baseline}:refs/heads/main")

    run_git(worktree, "switch", "-c", "fix/1-runtime")
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    live_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", "HEAD:refs/heads/fix/1-runtime")
    run_git(remote, "update-ref", "refs/pull/9/head", live_head)

    run_git(worktree, "switch", "--detach", baseline)
    (worktree / "base.py").write_text("base = 2\n", encoding="utf-8")
    run_git(worktree, "add", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    live_base = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", f"{live_base}:refs/heads/main")
    run_git(worktree, "switch", "fix/1-runtime")
    monkeypatch.setattr(MODULE, "_upstream_remote", lambda *_args: "origin")

    preparation = MODULE._prepare_pr_followup(
        {
            "prUrl": "https://github.com/a/b/pull/9",
            "worktreePath": str(worktree),
            "branch": "fix/1-runtime",
            "headSha": live_head,
            "evidence": {
                "mergeConflict": False,
                "baseIntegrationRequired": True,
                "baseRefName": "main",
                "baseSha": live_base,
            },
        }
    )

    prepared = preparation["preparedHeadSha"]
    assert preparation["preparedBaseSha"] == live_base
    assert prepared == run_git(worktree, "rev-parse", "HEAD")
    assert prepared != live_head
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        live_head,
        live_base,
    ]
    assert "Signed-off-by: Test Contributor <test@example.com>" in run_git(
        worktree, "show", "-s", "--format=%B", "HEAD"
    )
    assert run_git(worktree, "status", "--porcelain") == ""


def test_controller_ingests_followup_fix_as_update_to_exact_existing_pr(tmp_path):
    store, worktree, previous_head, pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    body_path = worktree / ".oss-pr-radar" / "pr-body.md"
    body_path.write_text("Fixes #1\n\nCorrect the runtime boundary.\n", encoding="utf-8")
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "followupDigest": candidate["wakeDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "FIX_READY",
                "handoffMode": "controller_commit_required",
                "commitSha": None,
                "branch": "fix/1-runtime",
                "commitMessage": "fix: preserve runtime boundary",
                "changedFiles": ["runtime.py"],
                "tests": [{"command": "pytest tests/runtime", "exitCode": 0}],
                "quality": {field: True for field in QUALITY_FIELDS},
                "publication": {
                    "headOwner": "Oxygen56",
                    "baseBranch": "main",
                    "title": "fix: preserve runtime boundary",
                    "bodyFile": str(body_path.resolve()),
                },
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(result["publicationRequests"]) == 1
    request = store.publication_work_items()[0]["request"]
    assert request["publicationKind"] == "PR_UPDATE"
    assert request["existingPrUrl"] == pr_url
    assert request["previousCommitSha"] == previous_head
    assert request["commitSha"] == run_git(worktree, "rev-parse", "HEAD")
    assert request["commitSha"] != previous_head
    assert store.task_result_digest_seen(
        "a/b#1", hashlib.sha256(result_path.read_bytes()).hexdigest()
    )


def test_followup_commit_preserves_prepared_base_integration_diff(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    baseline = run_git(worktree, "rev-parse", "HEAD")

    run_git(worktree, "switch", "-c", "fix/1-runtime")
    (worktree / "feature.py").write_text("feature = True\n", encoding="utf-8")
    run_git(worktree, "add", "feature.py")
    run_git(worktree, "commit", "-m", "fix: feature")
    previous_head = run_git(worktree, "rev-parse", "HEAD")

    run_git(worktree, "switch", "main")
    (worktree / "base.py").write_text("base = 2\n", encoding="utf-8")
    run_git(worktree, "add", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    run_git(worktree, "merge", "--no-ff", "--no-commit", base_sha)
    run_git(worktree, "commit", "--signoff", "-m", "merge: refresh upstream branch")
    prepared_head = run_git(worktree, "rev-parse", "HEAD")

    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    result_path = tmp_path / "result.json"
    value = {
        "handoffMode": "controller_commit_required",
        "commitSha": None,
        "branch": "fix/1-runtime",
        "commitMessage": "fix: adapt runtime to current base",
        "changedFiles": ["runtime.py"],
        "publication": {"baseBranch": "main"},
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")

    finalized, _raw = MODULE._finalize_controller_commit(
        candidate={"worktreePath": str(worktree)},
        context={
            "stage": "PR_OPEN",
            "prFollowup": {
                "headSha": previous_head,
                "preparedHeadSha": prepared_head,
                "evidence": {
                    "baseIntegrationRequired": True,
                    "baseSha": base_sha,
                },
            },
        },
        value=value,
        result_path=result_path,
    )

    assert finalized["controllerCommitChangedFiles"] == ["runtime.py"]
    assert finalized["changedFiles"] == ["base.py", "runtime.py"]
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        prepared_head
    ]
    assert run_git(worktree, "merge-base", baseline, "HEAD") == baseline


def _controller_commit_result(
    tmp_path: Path,
    *,
    policy_verified: bool = True,
    controller_policy_complete: bool = False,
    missing_quality: tuple[str, ...] = (),
    publication_blocked_reason: str | None = None,
    dco_required: bool = False,
    base_branch: str = "main",
) -> tuple[RadarLedger, Path, Path]:
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(worktree, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(
        worktree,
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    )
    source.write_text("value = 2\n", encoding="utf-8")
    if controller_policy_complete:
        store.record_audit_snapshot(
            "a/b#1",
            evidence={
                "authorization": {"status": "ALLOW"},
                "evidenceDigest": "c" * 64,
                "liveAudit": {
                    "capturedAt": iso_z(datetime.now(UTC)),
                    "evidence": {
                        "digest": "c" * 64,
                        "repo": "a/b",
                        "issue": {"number": 1, "state": "open"},
                        "completeness": {"repositoryPolicy": "COMPLETE"},
                        "policy": {
                            "status": "NORMAL",
                            "digest": "d" * 64,
                            "ai_disclosure": False,
                            "ai_prohibited": False,
                        },
                    },
                },
            },
            dedupe_key="controller-policy-complete",
        )
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
            "baseBranch": base_branch,
            "title": "fix: preserve runtime boundary",
            "bodyFile": str(body_path.resolve()),
        },
    }
    if publication_blocked_reason:
        result["publicationBlockedReason"] = publication_blocked_reason
    result_path.write_text(json.dumps(result), encoding="utf-8")
    return store, worktree, result_path


def test_controller_normalizes_child_base_to_prepared_default_branch(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        base_branch="release-1.12.0",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["publication"]["baseBranch"] == "main"
    with store.connect() as connection:
        request = connection.execute(
            "SELECT request_json FROM publication_requests WHERE opportunity_key='a/b#1'"
        ).fetchone()
    assert json.loads(request["request_json"])["publication"]["baseBranch"] == "main"


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


def test_controller_policy_snapshot_satisfies_child_policy_quality(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
        controller_policy_complete=True,
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert len(result["publicationRequests"]) == 1
    assert result["validationDeferred"] == []
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["quality"]["policy_verified"] is True
    assert finalized["controllerPolicyVerification"] == {
        "source": "controller_live_audit",
        "capturedAt": finalized["controllerPolicyVerification"]["capturedAt"],
        "policyDigest": "d" * 64,
        "policyStatus": "NORMAL",
    }
    assert finalized["controllerPolicyVerification"]["capturedAt"]


def test_controller_policy_snapshot_recovers_an_existing_blocked_fix(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
        controller_policy_complete=True,
    )
    controller_verification = MODULE._controller_policy_verification
    monkeypatch.setattr(MODULE, "_controller_policy_verification", lambda _context: None)

    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )["candidates"][0]
    MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
        )
    )
    blocked = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    monkeypatch.setattr(MODULE, "_controller_policy_verification", controller_verification)
    context_path = result_path.parent / "task-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["contextDigest"] = "refreshed-controller-context"
    context_path.write_text(json.dumps(context), encoding="utf-8")

    recovered = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first["validationDeferred"][0]["missing"] == ["policy_verified"]
    assert blocked["ingested"][0]["publicationBlockedReason"] == (
        "REPOSITORY_POLICY_EVIDENCE_REQUIRED"
    )
    assert len(recovered["publicationRequests"]) == 1
    assert recovered["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert json.loads(result_path.read_text(encoding="utf-8"))["quality"]["policy_verified"] is True
    request_id = recovered["publicationRequests"][0]["requestId"]
    request = store.publication_request(request_id)
    assert request is not None
    assert request["request"]["quality"]["policy_verified"] is True


def test_repaired_quality_rearms_same_blocked_publication_request(tmp_path):
    store, worktree, result_path = _controller_commit_result(tmp_path)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    request_id = first["publicationRequests"][0]["requestId"]
    request = store.publication_request(request_id)
    assert request is not None
    stale_quality = dict(request["request"]["quality"])
    stale_quality["policy_verified"] = False
    stale_request = dict(request["request"])
    stale_request["quality"] = stale_quality
    with store.connect() as connection:
        connection.execute(
            """UPDATE outcomes SET quality_json=? WHERE opportunity_key='a/b#1'""",
            (json.dumps(stale_quality),),
        )
        connection.execute(
            """UPDATE publication_requests
               SET status='BLOCKED',reason='SUBMIT_READY_EVIDENCE_INCOMPLETE',request_json=?
               WHERE request_id=?""",
            (json.dumps(stale_request), request_id),
        )
    store.record_stage(
        "a/b#1",
        "FIX_READY",
        evidence=request["request"]["quality"],
        dedupe_key="quality-repaired",
    )

    repaired = MODULE.request_publication(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=result_path,
    )

    assert repaired["request_id"] == request_id
    assert repaired["status"] == "PENDING"
    assert repaired["request"]["quality"]["policy_verified"] is True
    assert store.publication_request(request_id)["reason"] is None


def test_existing_policy_block_with_refreshed_context_stays_idempotent(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )["candidates"][0]
    MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
        )
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = result_path.parent / "task-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["contextDigest"] = "refreshed-context"
    context_path.write_text(json.dumps(context), encoding="utf-8")

    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert repeated == {
        "ok": True,
        "ingested": [],
        "publicationRequests": [],
        "validationDeferred": [],
        "errors": [],
    }


def test_controller_creates_two_parent_commit_for_conflicted_pr_followup(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 'original'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    source.write_text("value = 'pull-request'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: preserve runtime")
    previous_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "main")
    source.write_text("value = 'upstream'\n", encoding="utf-8")
    (worktree / "base.py").write_text("base = True\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py", "base.py")
    run_git(worktree, "commit", "-m", "refactor: update runtime")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")

    result_path = tmp_path / "result.json"
    value = {
        "handoffMode": "controller_merge_required",
        "commitSha": None,
        "branch": "fix/1-runtime",
        "commitMessage": "merge: refresh runtime branch",
        "changedFiles": ["runtime.py"],
        "mergeBaseSha": base_sha,
        "resolutionSourceCommit": previous_head,
        "publication": {"baseBranch": "main"},
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")
    finalized, _raw = MODULE._finalize_controller_commit(
        candidate={"worktreePath": str(worktree)},
        context={
            "prFollowup": {
                "headSha": previous_head,
                "evidence": {
                    "mergeConflict": True,
                    "baseRefName": "main",
                    "baseSha": base_sha,
                },
            }
        },
        value=value,
        result_path=result_path,
    )

    assert finalized["handoffMode"] == "controller_merge_complete"
    assert finalized["mergeResolutionFiles"] == ["runtime.py"]
    assert finalized["controllerCommitChangedFiles"] == ["runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py"]
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        previous_head,
        base_sha,
    ]
    assert source.read_text(encoding="utf-8") == "value = 'pull-request'\n"
    assert run_git(worktree, "status", "--porcelain") == ""


def test_controller_merge_rejects_incomplete_conflict_file_set(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    for name in ("one.py", "two.py"):
        (worktree / name).write_text("value = 'original'\n", encoding="utf-8")
    run_git(worktree, "add", "one.py", "two.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    for name in ("one.py", "two.py"):
        (worktree / name).write_text("value = 'pull-request'\n", encoding="utf-8")
    run_git(worktree, "add", "one.py", "two.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    previous_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "main")
    for name in ("one.py", "two.py"):
        (worktree / name).write_text("value = 'upstream'\n", encoding="utf-8")
    run_git(worktree, "add", "one.py", "two.py")
    run_git(worktree, "commit", "-m", "refactor: runtime")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    value = {
        "handoffMode": "controller_merge_required",
        "branch": "fix/1-runtime",
        "commitMessage": "merge: refresh runtime branch",
        "changedFiles": ["one.py"],
        "mergeBaseSha": base_sha,
        "resolutionSourceCommit": previous_head,
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(RuntimeError, match="conflict set mismatch"):
        MODULE._finalize_controller_commit(
            candidate={"worktreePath": str(worktree)},
            context={
                "prFollowup": {
                    "headSha": previous_head,
                    "evidence": {"mergeConflict": True, "baseSha": base_sha},
                }
            },
            value=value,
            result_path=result_path,
        )

    assert run_git(worktree, "rev-parse", "HEAD") == previous_head
    assert run_git(worktree, "status", "--porcelain") == ""


def test_controller_merge_preserves_child_prepared_resolution(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 'original'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    source.write_text("value = 'pull-request'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    previous_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "main")
    source.write_text("value = 'upstream'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "refactor: runtime")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    source.write_text("value = 'combined-resolution'\n", encoding="utf-8")
    value = {
        "handoffMode": "controller_merge_required",
        "branch": "fix/1-runtime",
        "commitMessage": "merge: refresh runtime branch",
        "changedFiles": ["runtime.py"],
        "mergeBaseSha": base_sha,
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(value), encoding="utf-8")

    MODULE._finalize_controller_commit(
        candidate={"worktreePath": str(worktree)},
        context={
            "prFollowup": {
                "headSha": previous_head,
                "evidence": {"mergeConflict": True, "baseSha": base_sha},
            }
        },
        value=value,
        result_path=result_path,
    )

    assert source.read_text(encoding="utf-8") == "value = 'combined-resolution'\n"
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        previous_head,
        base_sha,
    ]


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


def test_controller_stops_policy_only_validation_after_one_followup(tmp_path):
    store, _worktree, _result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
    )

    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert first["validationDeferred"][0]["missing"] == ["policy_verified"]
    candidate = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )["candidates"][0]
    MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
        )
    )

    reconciled = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert reconciled["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "FIX_READY",
            "publicationBlockedReason": "REPOSITORY_POLICY_EVIDENCE_REQUIRED",
        }
    ]
    assert reconciled["publicationRequests"] == []
    assert (
        MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))[
            "candidates"
        ]
        == []
    )


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
    assert result["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
        }
    ]
    with store.connect() as connection:
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE event_type='TASK_RESULT_VALIDATION_DEFERRED'"""
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
        == "VALIDATION_PENDING"
    )
    assert store.task_result_candidates()[0]["stage"] == "VALIDATION_PENDING"
    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert repeated["ingested"] == []

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert listed["ok"] is True
    assert listed["unresolved"] == []
    assert listed["stale"] == []
    assert listed["errors"] == []
    assert listed["candidates"][0]["threadId"] == "thread-1"
    assert listed["candidates"][0]["missing"] == [
        "regression_test_verified",
        "relevant_tests_green",
    ]
    assert listed["candidates"][0]["prefetchRequired"] is False
    assert listed["candidates"][0]["prefetchMode"] == "none"
    assert listed["candidates"][0]["nextOperation"] == "validation-followup-reserve"
    assert "prefetchCommands" not in listed["candidates"][0]

    digest = listed["candidates"][0]["resultDigest"]
    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
            prefetch_complete=False,
        )
    )
    assert reserved["ok"] is True
    assert "regression_test_verified" in reserved["prompt"]
    assert (
        MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))[
            "unresolved"
        ][0]["resultDigest"]
        == digest
    )

    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
        )
    )
    final_list = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )
    assert final_list["candidates"] == []
    assert final_list["unresolved"] == []
    assert final_list["stale"] == []

    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_SENT'""",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )
    stalled = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )
    assert stalled["ok"] is False
    assert stalled["stale"][0]["threadId"] == "thread-1"


def test_validation_followup_list_reconciles_and_reports_unchanged_gap(tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-1",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?)""",
            (
                "a/b#1",
                "TASK_RESULT_VALIDATION_DEFERRED",
                "result-digest-2",
                json.dumps(
                    {
                        "threadId": "thread-1",
                        "resultDigest": "result-digest-2",
                        "missing": ["relevant_tests_green"],
                    }
                ),
                iso_z(datetime.now(UTC)),
            ),
        )

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["ok"] is True
    assert listed["candidates"] == []
    assert listed["unresolved"] == []
    assert listed["stale"] == []
    assert listed["errors"] == []
    assert listed["reconciledNoProgress"] == 1
    assert listed["blockedNoProgress"][0]["key"] == "a/b#1"
    assert listed["blockedNoProgress"][0]["resultDigest"] == "result-digest-2"
    assert listed["blockedNoProgress"][0]["previousResultDigest"] == "result-digest-1"
    assert listed["blockedNoProgress"][0]["missing"] == ["relevant_tests_green"]


def test_validation_followup_abandons_only_when_no_target_turn_materialized(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    reserved_at = iso_z(now - timedelta(hours=2))
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, updated_at INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?)",
            ("thread-1", int((now - timedelta(hours=3)).timestamp())),
        )

    class Store:
        abandoned = None

        def reconcile_validation_no_progress(self):
            return 0

        def validation_followup_candidates(self):
            return []

        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "missing": ["relevant_tests_green"],
                    "reservedAt": reserved_at,
                }
            ]

        def stale_validation_followups(self, **_kwargs):
            return []

        def validation_no_progress(self):
            return []

        def abandon_validation_followup_delivery(self, **kwargs):
            self.abandoned = kwargs

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    args = SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    unresolved = MODULE.validation_followup_list(args)["unresolved"][0]

    result = MODULE.validation_followup_abandon(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest="a" * 64,
            abandon_nonce=unresolved["abandonNonce"],
            reason="TARGET_TURN_NOT_MATERIALIZED",
            min_age_minutes=90,
        )
    )

    assert result["abandoned"] is True
    assert store.abandoned == {
        "thread_id": "thread-1",
        "result_digest": "a" * 64,
        "reason": "TARGET_TURN_NOT_MATERIALIZED",
        "min_age_minutes": 90,
    }


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
    assert result["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
        }
    ]
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
        == "VALIDATION_PENDING"
    )
    assert store.task_result_candidates()[0]["stage"] == "VALIDATION_PENDING"
    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert repeated["ingested"] == []

    completed = json.loads(result_path.read_text(encoding="utf-8"))
    for field in (
        "regression_test_verified",
        "relevant_tests_green",
        "independent_review_passed",
    ):
        completed["quality"][field] = True
    result_path.write_text(json.dumps(completed), encoding="utf-8")

    advanced = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert advanced["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(advanced["publicationRequests"]) == 1
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "FIX_READY"
    )


def test_validation_followup_uses_cumulative_files_for_first_publication(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )

    deferred = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert deferred["validationDeferred"]
    original_head = run_git(worktree, "rev-parse", "HEAD")

    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["stage"] == "VALIDATION_PENDING"
    (worktree / "test_runtime.py").write_text(
        "def test_runtime():\n    assert True\n", encoding="utf-8"
    )
    followup = json.loads(result_path.read_text(encoding="utf-8"))
    followup.update(
        {
            "contextDigest": context["contextDigest"],
            "handoffMode": "controller_commit_required",
            "commitSha": None,
            "commitMessage": "test: cover runtime boundary",
            "changedFiles": ["test_runtime.py"],
            "quality": {field: True for field in QUALITY_FIELDS},
        }
    )
    followup.pop("controllerCommitChangedFiles", None)
    result_path.write_text(json.dumps(followup), encoding="utf-8")

    advanced = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert advanced["ok"] is True
    assert advanced["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(advanced["publicationRequests"]) == 1
    assert run_git(worktree, "rev-parse", "HEAD") != original_head
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["controllerCommitChangedFiles"] == ["test_runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py", "test_runtime.py"]

    finalized_after_sync, _raw = MODULE._finalize_controller_commit(
        candidate={"worktreePath": str(worktree)},
        context=context | {"stage": "PR_OPEN"},
        value=finalized,
        result_path=result_path,
    )
    assert finalized_after_sync["changedFiles"] == ["runtime.py", "test_runtime.py"]
    assert run_git(worktree, "show", "--pretty=format:", "--name-only", "HEAD") == (
        "test_runtime.py"
    )


def test_validation_followup_normalizes_existing_complete_handoff(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    (worktree / "test_runtime.py").write_text(
        "def test_runtime():\n    assert True\n", encoding="utf-8"
    )
    run_git(worktree, "add", "test_runtime.py")
    run_git(worktree, "commit", "-m", "test: cover runtime boundary")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value.update(
        {
            "handoffMode": "controller_commit_complete",
            "commitSha": run_git(worktree, "rev-parse", "HEAD"),
            "changedFiles": ["test_runtime.py"],
        }
    )
    value.pop("controllerCommitChangedFiles", None)
    result_path.write_text(json.dumps(value), encoding="utf-8")

    finalized, _raw = MODULE._finalize_controller_commit(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=value,
        result_path=result_path,
    )

    assert finalized["controllerCommitChangedFiles"] == ["test_runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py", "test_runtime.py"]


def test_validation_prefetch_plan_is_lockfile_scoped(tmp_path):
    worktree = tmp_path / "worktree"
    result_dir = worktree / ".oss-pr-radar"
    go_module = worktree / "gateway"
    ui_root = worktree / "ui"
    result_dir.mkdir(parents=True)
    go_module.mkdir()
    ui_root.mkdir()
    (worktree / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
    (worktree / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (worktree / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    (go_module / "go.mod").write_text("module example.com/gateway\n", encoding="utf-8")
    (go_module / "router.go").write_text("package gateway\n", encoding="utf-8")
    (ui_root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (ui_root / "package.json").write_text("{}\n", encoding="utf-8")
    (ui_root / "app.tsx").write_text("export default 1;\n", encoding="utf-8")
    result = {
        "changedFiles": ["gateway/router.go", "ui/app.tsx"],
        "tests": [
            {
                "command": "CARGO_NET_OFFLINE=true cargo test -p router",
                "exitCode": 101,
                "summary": "offline cache lacks locked dependency",
            },
            {
                "command": "GOPROXY=off go test ./...",
                "exitCode": 1,
                "summary": "module lookup disabled by GOPROXY=off",
            },
            {
                "command": "npm run test",
                "exitCode": 127,
                "summary": "Vitest was unavailable because node_modules is absent",
            },
            {
                "command": "python3 -m pytest tests/test_router.py",
                "exitCode": 1,
                "summary": "pytest is not installed in the prepared environment",
            },
        ],
    }
    raw = json.dumps(result).encode()
    result_path = result_dir / "result.json"
    result_path.write_bytes(raw)

    commands = MODULE._validation_prefetch_commands(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert commands == [
        {
            "kind": "cargo_locked_fetch",
            "cwd": str(worktree.resolve()),
            "argv": ["cargo", "fetch", "--locked"],
        },
        {
            "kind": "go_locked_download",
            "cwd": str(go_module.resolve()),
            "argv": ["go", "mod", "download"],
        },
        {
            "kind": "uv_locked_sync",
            "cwd": str(worktree.resolve()),
            "argv": ["uv", "sync", "--frozen", "--no-install-project"],
        },
        {
            "kind": "npm_locked_install",
            "cwd": str(ui_root.resolve()),
            "argv": [
                "npm",
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
        },
    ]


def test_validation_followup_blocks_missing_python_dependencies_without_lockfile(
    tmp_path,
):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["tests"] = [
        {
            "command": "python3 -m pytest test_runtime.py",
            "exitCode": 1,
            "summary": "Collection blocked: NumPy is not installed and torch is missing.",
        }
    ]
    raw = json.dumps(value).encode()
    result_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["candidates"] == []
    assert listed["environmentBlocked"][0]["key"] == "a/b#1"
    assert listed["environmentBlocked"][0]["reason"] == "DEPENDENCY_ENVIRONMENT_UNAVAILABLE"


def test_validation_prefetch_execution_enforces_command_and_worktree_boundaries(
    monkeypatch, tmp_path
):
    worktree = tmp_path / "worktree"
    package = worktree / "ui"
    package.mkdir(parents=True)
    calls = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        calls.append((args, cwd, timeout, stdin))
        return ""

    monkeypatch.setattr(MODULE, "command", fake_command)
    candidate = {"worktreePath": str(worktree)}
    commands = [
        {
            "kind": "npm_locked_install",
            "cwd": str(package),
            "argv": [
                "npm",
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
        }
    ]

    completed = MODULE._execute_validation_prefetch(candidate, commands)

    assert calls == [
        (
            commands[0]["argv"],
            package.resolve(),
            MODULE.VALIDATION_PREFETCH_TIMEOUTS["npm_locked_install"],
            None,
        )
    ]
    assert completed[0]["kind"] == "npm_locked_install"
    assert completed[0]["cwd"] == str(package.resolve())

    with pytest.raises(RuntimeError, match="not allowlisted"):
        MODULE._execute_validation_prefetch(
            candidate,
            [
                {
                    "kind": "npm_locked_install",
                    "cwd": str(package),
                    "argv": ["npm", "install"],
                }
            ],
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(RuntimeError, match="escapes"):
        MODULE._execute_validation_prefetch(
            candidate,
            [
                {
                    "kind": "cargo_locked_fetch",
                    "cwd": str(outside),
                    "argv": ["cargo", "fetch", "--locked"],
                }
            ],
        )


def test_validation_followup_reserve_runs_prefetch_inside_bridge(monkeypatch, tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    ui_root = worktree / "ui"
    ui_root.mkdir()
    (ui_root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (ui_root / "package.json").write_text("{}\n", encoding="utf-8")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["changedFiles"] = ["runtime.py", "ui/app.tsx"]
    value["tests"] = [
        {
            "command": "npm run test",
            "exitCode": 127,
            "summary": "Vitest was unavailable because node_modules is absent",
        }
    ]
    raw = json.dumps(value).encode()
    result_path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["regression_test_verified", "relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})
    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))[
        "candidates"
    ][0]
    assert listed["prefetchRequired"] is True
    assert listed["prefetchMode"] == "bridge_managed"
    assert "prefetchCommands" not in listed
    executed = []

    def fake_execute(candidate, commands):
        executed.extend(commands)
        return [{"kind": commands[0]["kind"], "cwd": commands[0]["cwd"], "durationMs": 1}]

    monkeypatch.setattr(MODULE, "_execute_validation_prefetch", fake_execute)

    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
            prefetch_complete=False,
        )
    )

    assert [item["kind"] for item in executed] == ["npm_locked_install"]
    assert reserved["prefetch"][0]["kind"] == "npm_locked_install"
    assert "已经按锁文件预取缺失依赖" in reserved["prompt"]


def test_validation_prefetch_failure_does_not_reserve_followup(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    raw = result_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    def fail_prefetch(candidate, commands):
        raise RuntimeError("prefetch failed")

    monkeypatch.setattr(MODULE, "_execute_validation_prefetch", fail_prefetch)

    with pytest.raises(RuntimeError, match="prefetch failed"):
        MODULE.validation_followup_reserve(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id="thread-1",
                result_digest=digest,
                prefetch_complete=True,
            )
        )

    assert store.validation_followup_candidates()[0]["resultDigest"] == digest
    assert store.unresolved_validation_followups() == []


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

        def prepare_ambiguous_publication_effect(self, _request_id, *, action):
            assert action == "push"
            return None

        def prepare_post_push_reconciliation(self, _request_id):
            return None

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


def test_publication_queue_reconciles_interrupted_push_before_pr_confirmation(
    monkeypatch, tmp_path
):
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
                        "commitSha": "b" * 40,
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

        def prepare_ambiguous_publication_effect(self, _request_id, *, action):
            assert action == "push"
            return {"pending": False, "permit": {"permit_id": "permit-1"}}

        def prepare_post_push_reconciliation(self, _request_id):
            return {"permit_id": "permit-1"}

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "ensure_fork_remote", lambda *_args: "radar-fork")
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args: pytest.fail("reconciliation must not request a new permit first"),
    )
    calls = []

    def executor(operation, arguments, *, ledger_path):
        calls.append(operation)
        if operation == "push":
            return {"ok": True, "reconciled": True}
        return {"ok": True, "prUrl": "https://github.com/a/b/pull/2"}

    monkeypatch.setattr(MODULE, "_executor", executor)

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert calls == ["push", "create-pr"]


def test_publication_queue_returns_immediately_when_another_executor_holds_lock(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        MODULE.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(BlockingIOError()),
    )

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {
        "ok": True,
        "busy": True,
        "published": [],
        "pending": [],
        "blocked": [],
        "errors": [],
    }


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


def test_duplicate_task_list_only_returns_stale_unbound_raw_tasks(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    project_root = tmp_path / "github"
    project_root.mkdir()
    thread_db = tmp_path / "threads.sqlite3"
    prompt = MODULE.issue_prompt("https://github.com/a/b/issues/1")
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                archived INTEGER, created_at INTEGER, updated_at INTEGER,
                thread_source TEXT
            )"""
        )
        rows = [
            ("canonical", str(project_root), "[有价值]", prompt, 0, -300, -60, "app"),
            ("duplicate", str(project_root), "<codex_delegation>raw", prompt, 0, -240, -60, "app"),
            ("recent", str(project_root), "<codex_delegation>raw", prompt, 0, -20, -5, "app"),
            ("archived", str(project_root), "<codex_delegation>raw", prompt, 1, -240, -60, "app"),
            (
                "helper",
                str(project_root),
                "<codex_delegation>raw",
                prompt,
                0,
                -240,
                -60,
                "subagent",
            ),
        ]
        for row in rows:
            connection.execute(
                "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
                row[:5]
                + (
                    int((now + timedelta(minutes=row[5])).timestamp()),
                    int((now + timedelta(minutes=row[6])).timestamp()),
                    row[7],
                ),
            )

    class Store:
        def task_context_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "canonical",
                }
            ]

        def bound_thread_ids(self):
            return {"canonical"}

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)

    result = MODULE.duplicate_task_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=30)
    )

    assert [item["threadId"] for item in result["duplicates"]] == ["duplicate"]
    assert result["duplicates"][0]["canonicalThreadId"] == "canonical"
    assert result["duplicates"][0]["desiredTitle"].startswith("[无价值·重复任务]")

    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "UPDATE threads SET title=? WHERE id=?",
            (result["duplicates"][0]["desiredTitle"], "duplicate"),
        )
    after_rename = MODULE.duplicate_task_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=30)
    )
    assert [item["threadId"] for item in after_rename["duplicates"]] == ["duplicate"]


def test_orphan_list_recovers_thread_created_in_github_project(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    project_root = tmp_path / "github"
    project_root.mkdir()
    thread_db = tmp_path / "threads.sqlite3"
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
                str(project_root),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                None,
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
                    "leaseStartedAt": iso_z(now - timedelta(minutes=1)),
                    "leaseUntil": iso_z(now + timedelta(minutes=29)),
                    "expiresAt": iso_z(now + timedelta(hours=1)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(minutes=1)),
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    candidate = result["candidates"][0]
    assert candidate["threadId"] == "thread-1"
    assert candidate["workspaceMode"] == "github_project_managed_worktree"
    assert candidate["cwd"] == str(project_root)
    assert candidate["worktreePath"] == str(MODULE.managed_worktree_path("intent-1", "a/b"))


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


def test_creation_abandon_accepts_a_stale_unbound_request(monkeypatch, tmp_path):
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
                    "clientThreadId": None,
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
    candidate = probe["unmatched"][0]

    result = MODULE.creation_abandon(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            client_thread_id=None,
            abandon_nonce=candidate["abandonNonce"],
            reason="CREATION_NOT_MATERIALIZED",
            min_age_minutes=70,
        )
    )

    assert result["abandoned"] is True
    assert store.abandoned[1]["client_thread_id"] is None


def test_orphan_list_blocks_archived_matching_thread(monkeypatch, tmp_path):
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
                "thread-archived",
                str(cwd),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                "https://github.com/a/b.git",
                1,
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
                    "clientThreadId": None,
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=70)
    )

    assert result["unmatched"] == []
    assert result["blocked"] == [
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "reason": "matching_thread_archived",
            "threadIds": ["thread-archived"],
        }
    ]


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
