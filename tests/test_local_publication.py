import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from oss_pr_radar.local_publication import (
    advance_once,
    compact_advance_result,
    launch_agent_spec,
    run_bridge,
)


def test_run_bridge_terminates_the_process_group_on_timeout(monkeypatch, tmp_path):
    calls = []

    class Process:
        pid = 4321
        returncode = None

        def __init__(self):
            self.communications = 0

        def communicate(self, timeout=None):
            self.communications += 1
            if self.communications == 1:
                raise subprocess.TimeoutExpired(["bridge"], timeout)
            return "", ""

        def wait(self, timeout=None):
            self.returncode = -signal.SIGTERM
            return self.returncode

    process = Process()

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return process

    killed = []
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(os, "killpg", lambda pid, sig: killed.append((pid, sig)))

    with pytest.raises(subprocess.TimeoutExpired):
        run_bridge(tmp_path, "drain-once", timeout=1)

    assert calls[0][1]["start_new_session"] is True
    assert killed == [(4321, signal.SIGTERM)]


def test_fast_publication_runs_ingestion_and_publication_in_order(tmp_path):
    calls = []
    responses = {
        "context-recover": {"ok": True, "verified": 1, "errors": []},
        "ingest-results": {
            "ok": True,
            "ingested": [{"key": "a/b#1", "stage": "FIX_READY"}],
            "publicationRequests": [{"requestId": "request-1", "status": "PENDING"}],
            "errors": [],
        },
        "independent-review-run": {"ok": True, "updated": [], "errors": []},
        "title-reconcile": {
            "ok": True,
            "renamed": [{"key": "a/b#1", "threadId": "thread-1"}],
            "errors": [],
        },
        "cleanup-reconcile": {
            "ok": True,
            "archived": [{"key": "a/b#2", "threadId": "thread-2"}],
            "errors": [],
        },
        "publication-run": {
            "ok": True,
            "published": [{"key": "a/b#1", "prUrl": "https://github.com/a/b/pull/2"}],
            "pending": [],
            "blocked": [],
            "errors": [],
        },
        "context-sync": {
            "ok": True,
            "written": [{"key": "a/b#1", "path": "/tmp/task-context.json"}],
            "errors": [],
        },
        "recovery-list": {"ok": True, "recoverable": []},
        "drain-once": {
            "ok": True,
            "action": "issue_task_dispatched",
            "key": "a/b#3",
            "threadId": "thread-3",
        },
    }

    def runner(root: Path, operation: str):
        calls.append((root, operation))
        return responses[operation]

    result = advance_once(tmp_path, runner=runner)

    assert [operation for _, operation in calls] == [
        "context-recover",
        "ingest-results",
        "independent-review-run",
        "title-reconcile",
        "cleanup-reconcile",
        "publication-run",
        "context-sync",
        "recovery-list",
        "drain-once",
    ]
    assert result["ok"] is True
    assert result["activity"] is True
    assert result["titlesRenamed"][0]["threadId"] == "thread-1"
    assert result["threadsArchived"][0]["threadId"] == "thread-2"
    assert result["published"][0]["prUrl"] == "https://github.com/a/b/pull/2"
    assert result["contextsSynced"][0]["key"] == "a/b#1"
    assert result["drain"]["threadId"] == "thread-3"


def test_terminalized_live_audit_is_published_before_cycle_finishes(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [{"key": "a/b#1", "stage": "AUDIT_NO_GO"}],
                "publicationRequests": [],
                "errors": [],
            }
        if operation == "drain-once":
            return {
                "ok": True,
                "action": "none",
                "terminalized": [{"key": "a/b#2", "reason": "STRONG_EXISTING_PR"}],
            }
        if operation == "publish-terminal-feedback":
            return {"ok": True, "published": 1, "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-2:] == ["drain-once", "publish-terminal-feedback"]
    assert result["ok"] is True
    assert result["terminalFeedback"]["published"] == 1


def test_fast_publication_is_quiet_when_no_result_or_request_exists(tmp_path):
    def runner(_root: Path, operation: str):
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["activity"] is False


def test_fast_publication_retries_an_old_negative_turn_receipt(tmp_path):
    receipt_root = tmp_path / "state" / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    receipt = receipt_root / "failed.json"
    receipt.write_text(
        json.dumps({"ok": False, "turnStarted": False, "error": "resume failed"}),
        encoding="utf-8",
    )
    old = time.time() - 120
    os.utime(receipt, (old, old))
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        if operation == "drain-once":
            return {"ok": True, "action": "validation_followup_dispatched", "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-1] == "drain-once"
    assert result["ok"] is True
    assert result["activity"] is True


def test_fast_publication_retries_a_terminal_interrupted_receipt(tmp_path):
    receipt_root = tmp_path / "state" / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    receipt = receipt_root / "interrupted.json"
    receipt.write_text(json.dumps({"ok": True, "turnStatus": "interrupted"}), encoding="utf-8")
    old = time.time() - 120
    os.utime(receipt, (old, old))
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        if operation == "drain-once":
            return {"ok": True, "action": "recovery_dispatched", "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-1] == "drain-once"
    assert result["activity"] is True


def test_fast_publication_drains_an_immediately_recoverable_interrupted_turn(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        if operation == "recovery-list":
            return {
                "ok": True,
                "recoverable": [{"key": "a/b#1", "threadId": "thread-1"}],
            }
        if operation == "drain-once":
            return {"ok": True, "action": "recovery_dispatched", "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-2:] == ["recovery-list", "drain-once"]
    assert result["recoverable"][0]["threadId"] == "thread-1"
    assert result["activity"] is True


def test_fast_publication_surfaces_title_reconciliation_failure(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [{"key": "a/b#1", "stage": "AUDIT_NO_GO"}],
                "publicationRequests": [],
                "errors": [],
            }
        if operation == "title-reconcile":
            return {"ok": False, "renamed": [], "errors": [{"error": "rename failed"}]}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls == [
        "context-recover",
        "ingest-results",
        "independent-review-run",
        "title-reconcile",
        "cleanup-reconcile",
        "publication-run",
    ]
    assert result["ok"] is False
    assert result["errors"] == [{"error": "rename failed"}]


def test_missing_historical_worktree_does_not_stop_fast_publication(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {
                "ok": True,
                "verified": 0,
                "unavailable": [{"key": "old/repo#1"}],
                "errors": [],
            }
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls == [
        "context-recover",
        "ingest-results",
        "independent-review-run",
        "title-reconcile",
        "cleanup-reconcile",
        "publication-run",
        "recovery-list",
    ]
    assert result["ok"] is True
    assert result["activity"] is False
    assert result["contextsUnavailable"] == [{"key": "old/repo#1"}]


def test_independent_review_update_is_reingested_before_publication(tmp_path):
    calls = []
    ingestion_count = 0

    def runner(_root: Path, operation: str):
        nonlocal ingestion_count
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            ingestion_count += 1
            if ingestion_count == 1:
                return {
                    "ok": True,
                    "ingested": [],
                    "publicationRequests": [],
                    "validationDeferred": [],
                    "errors": [],
                }
            return {
                "ok": True,
                "ingested": [{"key": "a/b#1", "stage": "FIX_READY"}],
                "publicationRequests": [{"requestId": "request-1", "status": "PENDING"}],
                "validationDeferred": [],
                "errors": [],
            }
        if operation == "independent-review-run":
            return {
                "ok": True,
                "updated": [{"key": "a/b#1", "verdict": "PASS"}],
                "errors": [],
            }
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[:4] == [
        "context-recover",
        "ingest-results",
        "independent-review-run",
        "ingest-results",
    ]
    assert result["publicationRequests"] == [{"requestId": "request-1", "status": "PENDING"}]
    assert result["independentReview"]["updated"][0]["verdict"] == "PASS"


def test_review_update_is_reingested_even_when_an_older_candidate_is_invalid(tmp_path):
    calls = []
    ingestion_count = 0

    def runner(_root: Path, operation: str):
        nonlocal ingestion_count
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            ingestion_count += 1
            return {
                "ok": True,
                "ingested": (
                    [{"key": "a/b#2", "stage": "FIX_READY"}] if ingestion_count == 2 else []
                ),
                "publicationRequests": [],
                "validationDeferred": [],
                "errors": [],
            }
        if operation == "independent-review-run":
            return {
                "ok": False,
                "updated": [{"key": "a/b#2", "verdict": "PASS"}],
                "errors": [{"key": "a/b#1", "error": "invalid old result"}],
            }
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[:4] == [
        "context-recover",
        "ingest-results",
        "independent-review-run",
        "ingest-results",
    ]
    assert result["resultsIngested"] == [{"key": "a/b#2", "stage": "FIX_READY"}]
    assert result["ok"] is False
    assert result["errors"] == [{"key": "a/b#1", "error": "invalid old result"}]


def test_incomplete_validation_is_healthy_and_quiet(tmp_path):
    deferred = {
        "key": "a/b#1",
        "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
        "missing": ["relevant_tests_green"],
    }

    def runner(_root: Path, operation: str):
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [],
                "publicationRequests": [],
                "validationDeferred": [deferred],
                "errors": [],
            }
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["activity"] is False
    assert result["validationDeferred"] == [deferred]


def test_recovery_failure_stops_ingestion_and_publication(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        return {"ok": False, "errors": [{"error": "context mismatch"}]}

    result = advance_once(tmp_path, runner=runner)

    assert calls == ["context-recover"]
    assert result["ok"] is False
    assert result["published"] == []
    assert result["errors"] == [{"error": "context mismatch"}]


def test_ingestion_failure_stops_publication(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        return {"ok": False, "errors": [{"error": "invalid result"}]}

    result = advance_once(tmp_path, runner=runner)

    assert calls == ["context-recover", "ingest-results"]
    assert result["ok"] is False
    assert result["published"] == []
    assert result["errors"] == [{"error": "invalid result"}]


def test_launch_agent_uses_local_venv_and_contains_no_credentials(tmp_path):
    root = tmp_path / "radar"
    python = root / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.touch()
    home = tmp_path / "home"

    spec = launch_agent_spec(root, interval_seconds=5, home=home)

    assert spec["StartInterval"] == 15
    assert spec["ProgramArguments"][0:2] == ["/usr/bin/env", "-i"]
    assert str(python) in spec["ProgramArguments"]
    assert any(
        "/Applications/ChatGPT.app/Contents/Resources" in argument
        for argument in spec["ProgramArguments"]
    )
    assert spec["WorkingDirectory"] == str(root.resolve())
    assert "FEISHU" not in str(spec)
    assert "DEEPSEEK" not in str(spec)


def test_compact_result_keeps_counts_and_omits_large_payloads():
    result = {
        "ok": False,
        "activity": True,
        "resultsIngested": [{"key": "a/b#1", "evidence": "x" * 10_000}],
        "publicationRequests": [{"requestId": "request-1"}],
        "validationDeferred": [],
        "independentReview": {
            "busy": True,
            "updated": [{"key": "a/b#1", "details": "y" * 10_000}],
        },
        "blocked": [{"key": "a/b#2", "details": "z" * 10_000}],
        "contextsUnavailable": [{"key": f"old/repo#{index}"} for index in range(20)],
        "contextsUnavailableCount": 20,
        "drain": {"ok": True, "action": "none"},
        "errors": [{"key": "a/b#3", "error": "stale result"}],
    }

    compact = compact_advance_result(result)

    assert compact["counts"] == {
        "resultsIngested": 1,
        "publicationRequests": 1,
        "validationDeferred": 0,
        "reviewsUpdated": 1,
        "titlesRenamed": 0,
        "threadsArchived": 0,
        "published": 0,
        "publicationBlocked": 1,
        "errors": 1,
    }
    assert compact["reviewBusy"] is True
    assert compact["contextsUnavailableCount"] == 20
    assert "contextsUnavailable" not in compact
    assert len(json.dumps(compact)) < 1_000
