from __future__ import annotations

import importlib.util
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from oss_pr_radar.util import iso_z

SCRIPT = Path(__file__).parents[1] / "scripts" / "local_dispatch_bridge.py"
SPEC = importlib.util.spec_from_file_location("local_dispatch_bridge", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


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
