import json
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

import pytest
from test_ledger import insert_publication_preflight, legal_publication_probe

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.local_publication import (
    advance_once,
    compact_advance_result,
    fast_advance_once,
    fast_bridge,
    launch_agent_spec,
    queue_import_launch_agent_spec,
    queue_import_once,
    retryable_delivery_pending,
    run_bridge,
    slow_advance_once,
    slow_launch_agent_spec,
    sync_cloud_queue_if_due,
    worker_log_paths,
)
from oss_pr_radar.runtime import RuntimeLockBusy

pytestmark = pytest.mark.usefixtures("current_signing_key")


def test_fast_bridge_deadline_covers_bounded_cold_start(monkeypatch, tmp_path):
    observed = {}

    def bridge(_root, operation, **kwargs):
        observed.update(operation=operation, **kwargs)
        return {"ok": True}

    monkeypatch.setattr("oss_pr_radar.local_publication.run_bridge", bridge)

    result = fast_bridge(
        tmp_path,
        "local-receipt-enqueue",
        code_root=Path(__file__).parents[1],
        allow_unreleased_code=True,
    )

    assert result == {"ok": True}
    assert observed["operation"] == "local-receipt-enqueue"
    assert observed["timeout"] == 60


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
        run_bridge(
            tmp_path,
            "drain-once",
            timeout=1,
            code_root=Path(__file__).parents[1],
            allow_unreleased_code=True,
        )

    assert calls[0][1]["start_new_session"] is True
    assert killed == [(4321, signal.SIGTERM)]


@pytest.mark.parametrize("response", [{}, {"ok": None}, {"ok": "true"}, {"ok": 1}])
def test_run_bridge_requires_explicit_boolean_success(monkeypatch, tmp_path, response):
    class Process:
        pid = 4321
        returncode = 0

        def communicate(self, timeout=None):
            return json.dumps(response), ""

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: Process())

    with pytest.raises(RuntimeError, match="boolean ok"):
        run_bridge(
            tmp_path,
            "list",
            code_root=Path(__file__).parents[1],
            allow_unreleased_code=True,
        )


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
        "publication-feedback-list": {
            "ok": True,
            "candidates": [],
            "unresolved": [],
            "reconciled": [],
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
        "publication-feedback-list",
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


def test_implementation_context_is_synced_before_followup_drain(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 1, "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [{"key": "a/b#1", "stage": "IMPLEMENTATION_READY"}],
                "publicationRequests": [],
                "validationDeferred": [],
                "errors": [],
            }
        if operation == "context-sync":
            return {
                "ok": True,
                "written": [{"key": "a/b#1", "path": "/tmp/task-context.json"}],
                "errors": [],
            }
        if operation == "drain-once":
            return {
                "ok": True,
                "action": "implementation_followup_dispatched",
                "key": "a/b#1",
                "threadId": "thread-1",
            }
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "errors": []}
        if operation == "recovery-list":
            return {"ok": True, "recoverable": [], "errors": []}
        return {
            "ok": True,
            "updated": [],
            "renamed": [],
            "archived": [],
            "published": [],
            "pending": [],
            "blocked": [],
            "errors": [],
        }

    result = advance_once(tmp_path, runner=runner)

    assert calls.index("context-sync") < calls.index("drain-once")
    assert result["ok"] is True
    assert result["contextsSynced"][0]["key"] == "a/b#1"
    assert result["drain"]["action"] == "implementation_followup_dispatched"


def test_advance_once_keeps_legacy_task_quarantine_out_of_global_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.sync_cloud_queue_if_due",
        lambda *args, **kwargs: {"ok": True, "errors": [], "pending": []},
    )

    def runner(_root: Path, operation: str):
        if operation == "context-recover":
            return {"ok": True, "unavailable": [{"key": "old#1"}], "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [],
                "publicationRequests": [],
                "validationDeferred": [],
                "quarantined": [
                    {
                        "key": "a/b#1",
                        "reason": "LEGACY_RESULT_REQUIRES_MIGRATION",
                    }
                ],
                "errors": [],
            }
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["errors"] == []
    assert result["quarantined"] == [{"key": "a/b#1", "reason": "LEGACY_RESULT_REQUIRES_MIGRATION"}]
    assert result["contextsUnavailableCount"] == 1


def test_advance_once_does_not_report_recorded_quarantine_as_activity(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.sync_cloud_queue_if_due",
        lambda *args, **kwargs: {"ok": True, "errors": [], "pending": []},
    )

    def runner(_root: Path, operation: str):
        if operation == "context-recover":
            return {"ok": True, "unavailable": [], "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [],
                "publicationRequests": [],
                "validationDeferred": [],
                "quarantined": [
                    {
                        "key": "a/b#1",
                        "reason": "LEGACY_RESULT_REQUIRES_MIGRATION",
                        "new": False,
                    }
                ],
                "errors": [],
            }
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["activity"] is False
    assert result["quarantined"][0]["new"] is False


def test_slow_cycle_is_successful_with_task_local_context_quarantine(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.sync_cloud_queue_if_due",
        lambda *args, **kwargs: {"ok": True, "errors": [], "pending": []},
    )

    def runner(_root: Path, operation: str):
        if operation == "reproduction-probe":
            return {"ok": True, "count": 0, "errors": []}
        if operation == "context-recover":
            return {
                "ok": True,
                "verified": 39,
                "unavailable": [],
                "quarantined": [
                    {"key": "a/b#1", "reason": "SHARED_CONTEXT_DIGEST_MISMATCH", "new": False}
                ],
                "errors": [],
            }
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [],
                "publicationRequests": [],
                "validationDeferred": [],
                "quarantined": [],
                "errors": [],
            }
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "errors": []}
        if operation == "recovery-list":
            return {"ok": True, "recoverable": [], "errors": []}
        return {
            "ok": True,
            "updated": [],
            "renamed": [],
            "archived": [],
            "published": [],
            "pending": [],
            "blocked": [],
            "errors": [],
        }

    result = slow_advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["activity"] is False
    assert result["slowWorkerDiagnostic"]["worker"] == "slow"
    assert result["slowWorkerDiagnostic"]["contextRecovery"]["quarantined"] == 1
    assert result["slowWorkerDiagnostic"]["reproductionProbe"]["ok"] is True


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


def test_ingested_terminal_result_is_published_without_drain_terminalization(tmp_path):
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
            return {"ok": True, "action": "none", "terminalized": []}
        if operation == "publish-terminal-feedback":
            return {"ok": True, "published": 1, "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-2:] == ["drain-once", "publish-terminal-feedback"]
    assert result["ok"] is True
    assert result["terminalFeedback"]["published"] == 1


def test_scanner_recheck_from_drain_is_published_before_cycle_finishes(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [{"key": "a/b#1", "stage": "QUALIFIED"}],
                "publicationRequests": [],
                "errors": [],
            }
        if operation == "drain-once":
            return {
                "ok": True,
                "action": "none",
                "terminalized": [],
                "scannerRechecks": [{"key": "a/b#1", "reason": "STATE_DRIFT"}],
            }
        if operation == "publish-terminal-feedback":
            return {"ok": True, "published": 1, "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-2:] == ["drain-once", "publish-terminal-feedback"]
    assert result["ok"] is True
    assert result["activity"] is True
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


def test_fast_publication_drains_pending_visible_pr_feedback(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        if operation == "publication-feedback-list":
            return {
                "ok": True,
                "candidates": [{"key": "a/b#1", "threadId": "thread-1"}],
                "unresolved": [],
                "reconciled": [],
            }
        if operation == "drain-once":
            return {
                "ok": True,
                "action": "publication_feedback_dispatched",
                "key": "a/b#1",
                "threadId": "thread-1",
            }
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert calls[-2:] == ["recovery-list", "drain-once"]
    assert result["drain"]["action"] == "publication_feedback_dispatched"
    assert result["activity"] is True


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
    receipt.write_text(
        json.dumps({"ok": True, "turnId": "turn-1", "turnStatus": "interrupted"}),
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
        "publication-feedback-list",
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
        "publication-feedback-list",
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


def test_review_update_continues_when_an_older_candidate_is_invalid(tmp_path):
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
    assert result["ok"] is True
    assert result["errors"] == []
    assert result["workBlocked"] == [
        {
            "key": "a/b#1",
            "reason": "INDEPENDENT_REVIEW_FAILED",
            "error": "invalid old result",
        }
    ]


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


def test_one_evidence_block_does_not_stop_the_rest_of_the_slow_cycle(tmp_path):
    calls = []
    blocked = {
        "key": "a/b#1",
        "reason": "REPRODUCTION_RECEIPT_INVALID",
        "alreadyRecorded": False,
    }

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [{"key": "a/b#2", "stage": "FIX_READY"}],
                "publicationRequests": [{"requestId": "request-2"}],
                "validationDeferred": [],
                "workBlocked": [blocked],
                "errors": [],
            }
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["workBlocked"] == [blocked]
    assert result["resultsIngested"] == [{"key": "a/b#2", "stage": "FIX_READY"}]
    assert "independent-review-run" in calls
    assert "publication-run" in calls


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
    assert spec["ProgramArguments"][-2:] == ["--mode", "fast"]
    assert "ProcessType" not in spec
    assert "LowPriorityIO" not in spec
    assert "FEISHU" not in str(spec)
    assert "DEEPSEEK" not in str(spec)


def test_fast_cycle_restricts_operations_and_enqueues_slow_work(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}

    result = fast_advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert calls == ["local-receipt-enqueue"]
    request = json.loads((tmp_path / "state" / "slow-work-request.json").read_text())
    assert request["reasons"] == ["local_ingest"]


def test_fast_cycle_does_not_call_network_or_publication_operations(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )

    def runner(_root: Path, operation: str):
        if operation != "local-receipt-enqueue":
            raise AssertionError(operation)
        return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}

    assert fast_advance_once(tmp_path, runner=runner)["ok"] is True


def test_fast_cycle_injected_bridge_does_not_execute_git(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )

    calls = []

    def runner(root: Path, operation: str):
        calls.append((root, operation))
        assert operation == "local-receipt-enqueue"
        queue = root / "state" / "local-receipt-queue.json"
        queue.parent.mkdir(parents=True, exist_ok=True)
        queue.write_text("{}\n", encoding="utf-8")
        return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}

    result = fast_advance_once(
        tmp_path,
        runner=runner,
    )

    assert result["ok"] is True
    assert calls == [(tmp_path.resolve(), "local-receipt-enqueue")]
    assert (tmp_path / "state" / "local-receipt-queue.json").exists()


def test_queue_importer_is_independent_and_only_imports_signed_queue(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        return {"ok": True, "verified": 2, "inserted": 1}

    result = queue_import_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert calls == ["queue-import"]
    state = json.loads((tmp_path / "state" / "queue-import-state.json").read_text())
    assert state["inserted"] == 1


def test_slow_worker_persists_backoff_after_network_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )

    def runner(_root: Path, operation: str):
        if operation == "context-recover":
            return {"ok": False, "errors": [{"error": "CLONE_TIMEOUT"}]}
        raise AssertionError(operation)

    first = slow_advance_once(tmp_path, runner=runner)
    second = slow_advance_once(tmp_path, runner=runner)

    assert first["ok"] is False
    assert second["deferred"] is True
    backoff = json.loads((tmp_path / "state" / "slow-worker-backoff.json").read_text())
    assert backoff["failureCount"] == 1
    assert backoff["backoffSeconds"] == 60
    health = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    slow = health["workers"]["slow"]
    assert slow["lastExitCode"] == 1
    assert slow["consecutiveFailures"] == 1
    assert slow["consecutiveSuccesses"] == 0


@pytest.mark.parametrize(
    ("in_flight", "reason"),
    [
        (False, "PERSISTED_BACKOFF"),
        (True, "PERSISTED_INFLIGHT_BACKOFF"),
    ],
)
def test_slow_worker_persisted_backoff_does_not_manufacture_success_health(
    tmp_path, in_flight, reason
):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    retry_at = time.time() + 3600
    (state_dir / "slow-worker-backoff.json").write_text(
        json.dumps(
            {
                "schemaVersion": "slow_backoff_v1",
                "failureCount": 1,
                "nextAttemptAt": 0 if in_flight else retry_at,
                "retryAfter": retry_at,
                "inFlight": in_flight,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def must_not_run(_root: Path, _operation: str):
        raise AssertionError("persisted backoff should not run slow work")

    result = slow_advance_once(tmp_path, runner=must_not_run)

    assert result["ok"] is True
    assert result["deferred"] is True
    assert result["reason"] == reason
    assert not (state_dir / "runtime-health.json").exists()


def test_slow_worker_marks_runtime_inflight_and_clears_it_on_success(monkeypatch, tmp_path):
    observed = {}
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )

    def runner(_root: Path, operation: str):
        if operation == "reproduction-probe":
            health = json.loads(
                (tmp_path / "state" / "runtime-health.json").read_text(encoding="utf-8")
            )
            observed.update(health["workers"]["slow"])
            return {"ok": True, "errors": []}
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "unavailable": [], "quarantined": [], "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [],
                "publicationRequests": [],
                "validationDeferred": [],
                "ignored": [],
                "errors": [],
            }
        if operation == "independent-review-run":
            return {"ok": True, "updated": [], "errors": []}
        if operation == "title-reconcile":
            return {"ok": True, "renamed": [], "errors": []}
        if operation == "cleanup-reconcile":
            return {"ok": True, "archived": [], "errors": []}
        if operation == "publication-run":
            return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}
        if operation == "sync":
            return {"ok": True, "verified": 0, "inserted": 0, "superseded": 0}
        if operation == "list":
            return {"ok": True, "pending": []}
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "reconciled": []}
        if operation == "recovery-list":
            return {"ok": True, "recoverable": []}
        raise AssertionError(operation)

    result = slow_advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert observed["inFlight"] is True
    assert observed["attemptStartedAt"]
    assert observed["workerPid"] == os.getpid()
    assert observed["workerPidAlive"] is True
    health = json.loads((tmp_path / "state" / "runtime-health.json").read_text(encoding="utf-8"))
    slow = health["workers"]["slow"]
    assert slow["inFlight"] is False
    assert slow["attemptStartedAt"] is None
    assert slow["workerPid"] is None
    assert slow["workerPidAlive"] is False


def test_slow_worker_marks_terminal_missing_worktree_skip_as_success(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "reproduction-probe":
            return {"ok": True, "errors": []}
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "unavailable": [], "errors": []}
        if operation == "ingest-results":
            return {
                "ok": True,
                "ingested": [],
                "publicationRequests": [],
                "validationDeferred": [],
                "ignored": [
                    {
                        "key": "a/b#1",
                        "reason": "PUBLISHED_TERMINAL_WORKTREE_MISSING",
                    }
                ],
                "errors": [],
            }
        if operation == "independent-review-run":
            return {"ok": True, "updated": [], "errors": []}
        if operation == "title-reconcile":
            return {"ok": True, "renamed": [], "errors": []}
        if operation == "cleanup-reconcile":
            return {"ok": True, "archived": [], "errors": []}
        if operation == "publication-run":
            return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}
        if operation == "sync":
            return {"ok": True, "verified": 0, "inserted": 0, "superseded": 0}
        if operation == "list":
            return {"ok": True, "pending": []}
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "reconciled": []}
        if operation == "recovery-list":
            return {"ok": True, "recoverable": []}
        raise AssertionError(operation)

    first = slow_advance_once(tmp_path, runner=runner)
    second = slow_advance_once(tmp_path, runner=runner)

    assert first["ok"] is True
    assert second["ok"] is True
    health = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    slow = health["workers"]["slow"]
    assert slow["lastExitCode"] == 0
    assert slow["consecutiveFailures"] == 0
    assert slow["consecutiveSuccesses"] == 2
    assert calls.count("ingest-results") == 2


def test_slow_worker_lock_busy_does_not_manufacture_success_health(monkeypatch, tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    def busy_lock(*_args, **_kwargs):
        raise RuntimeLockBusy("slow worker is already running")

    monkeypatch.setattr("oss_pr_radar.local_publication.exclusive_lock", busy_lock)

    def must_not_run(_root: Path, _operation: str):
        raise AssertionError("lock busy should not run slow work")

    result = slow_advance_once(tmp_path, runner=must_not_run)

    assert result == {"ok": True, "busy": True, "errors": []}
    assert not (state_dir / "runtime-health.json").exists()


def test_slow_worker_persists_exception_failure_before_restart(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )
    calls = []

    def failing_runner(_root: Path, operation: str):
        calls.append(operation)
        raise RuntimeError("clone timeout")

    first = slow_advance_once(tmp_path, runner=failing_runner)
    second = slow_advance_once(tmp_path, runner=failing_runner)

    assert first["ok"] is False
    assert second["deferred"] is True
    assert calls == ["reproduction-probe"]
    backoff = json.loads((tmp_path / "state" / "slow-worker-backoff.json").read_text())
    assert backoff["inFlight"] is False
    assert backoff["retryAfter"] > time.time()
    operations = [
        json.loads(line)
        for line in (tmp_path / "state" / "runtime-operations" / "operations.ndjson")
        .read_text()
        .splitlines()
    ]
    assert [item["status"] for item in operations if item["operation"] == "slow-cycle"] == [
        "started",
        "failure",
    ]


def test_slow_worker_crash_leaves_restart_backoff(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )

    def interrupted_runner(_root: Path, _operation: str):
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        slow_advance_once(tmp_path, runner=interrupted_runner)

    called = False

    def must_not_run(_root: Path, _operation: str):
        nonlocal called
        called = True
        raise AssertionError("restart retried before durable backoff expired")

    result = slow_advance_once(tmp_path, runner=must_not_run)
    assert result["deferred"] is True
    assert called is False
    backoff = json.loads((tmp_path / "state" / "slow-worker-backoff.json").read_text())
    assert backoff["inFlight"] is False
    assert backoff["lastError"].startswith("KeyboardInterrupt")


def test_blocked_slow_worker_does_not_block_fast_receipt_registration(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )
    slow_started = threading.Event()
    release_slow = threading.Event()
    slow_calls = []

    ledger = RadarLedger(tmp_path / "state" / "radar_ledger.sqlite3")
    insert_publication_preflight(ledger)
    worktree, base_sha, head_sha, branch, probe_receipt, result_digest, evidence_path = (
        legal_publication_probe(tmp_path)
    )
    request_payload = {
        "requestId": "request-1",
        "opportunityKey": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "taskId": "intent-1",
        "commitSha": head_sha,
        "headSha": head_sha,
        "selectedBaseSha": base_sha,
        "codePaths": ["runtime.py"],
        "preTaskEvidence": {"baseSha": base_sha, "codePathsPlan": ["runtime.py"]},
        "resultDigest": result_digest,
        "reproductionReceipt": probe_receipt,
        "publicationKind": "PR_CREATE",
    }
    with ledger.connect() as connection:
        connection.execute(
            "UPDATE publication_requests SET commit_sha=?,branch=?,worktree_path=?,request_json=? WHERE request_id='request-1'",
            (head_sha, branch, str(worktree), json.dumps(request_payload, sort_keys=True)),
        )
        connection.execute(
            "UPDATE publication_permits SET commit_sha=?,branch=? WHERE permit_id='permit-1'",
            (head_sha, branch),
        )

    def slow_runner(_root: Path, operation: str):
        slow_calls.append(operation)
        if len(slow_calls) == 1:
            slow_started.set()
            assert release_slow.wait(timeout=3)
        if operation == "context-recover":
            first = ledger.publication_effect(
                permit_id="permit-1", action="create_pr", request_digest="same-effect"
            )
            second = ledger.publication_effect(
                permit_id="permit-1", action="create_pr", request_digest="same-effect"
            )
            assert first["created"] is True
            assert second["created"] is False
        return {"ok": True}

    slow_result = {}

    def run_slow():
        slow_result.update(slow_advance_once(tmp_path, runner=slow_runner))

    thread = threading.Thread(target=run_slow)
    thread.start()
    assert slow_started.wait(timeout=3)

    fast_started = time.monotonic()
    fast_result = fast_advance_once(
        tmp_path,
        runner=lambda _root, _operation: {"ok": True, "queued": []},
    )
    fast_elapsed = time.monotonic() - fast_started
    assert fast_result["ok"] is True
    assert fast_elapsed < 1.0

    release_slow.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert slow_result["ok"] is True
    with ledger.connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM publication_effects WHERE action='create_pr'"
        ).fetchone()[0]
    assert count == 1


def test_worker_specs_are_separate_and_use_expected_intervals(tmp_path):
    home = tmp_path / "home"
    fast = launch_agent_spec(tmp_path / "radar", interval_seconds=20, home=home)
    slow = slow_launch_agent_spec(tmp_path / "radar", home=home)
    queue = queue_import_launch_agent_spec(tmp_path / "radar", home=home)

    assert fast["Label"] != slow["Label"]
    assert slow["StartInterval"] == 60
    assert queue["StartInterval"] == 300
    assert "ProcessType" not in slow
    assert "LowPriorityIO" not in slow
    assert "ProcessType" not in queue
    assert "LowPriorityIO" not in queue
    assert slow["ProgramArguments"][-2:] == ["--root", str((tmp_path / "radar").resolve())]
    assert "queue_importer.py" in queue["ProgramArguments"][-3]
    assert worker_log_paths(fast["Label"], home=home) == (
        Path(fast["StandardOutPath"]),
        Path(fast["StandardErrorPath"]),
    )
    assert worker_log_paths(slow["Label"], home=home) == (
        Path(slow["StandardOutPath"]),
        Path(slow["StandardErrorPath"]),
    )
    assert worker_log_paths(queue["Label"], home=home) == (
        Path(queue["StandardOutPath"]),
        Path(queue["StandardErrorPath"]),
    )
    assert Path(slow["StandardOutPath"]).name == "local-publication-slow.log"
    assert Path(queue["StandardOutPath"]).name == "queue-importer.log"


def test_due_cloud_queue_sync_imports_and_lists_pending_work(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        if operation == "sync":
            return {"ok": True, "verified": 2, "inserted": 1, "superseded": 0}
        return {"ok": True, "pending": [{"key": "a/b#1"}]}

    result = sync_cloud_queue_if_due(
        tmp_path,
        runner=runner,
        interval_seconds=300,
        now=1_000,
    )

    assert calls == ["sync", "list"]
    assert result["ok"] is True
    assert result["inserted"] == 1
    assert result["pending"] == [{"key": "a/b#1"}]


def test_synced_actionable_pr_followup_is_exposed_to_the_serial_drain(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        responses = {
            "context-recover": {"ok": True, "errors": [], "unavailable": []},
            "ingest-results": {"ok": True},
            "independent-review-run": {"ok": True, "updated": []},
            "title-reconcile": {"ok": True},
            "cleanup-reconcile": {"ok": True},
            "publication-run": {"ok": True},
            "sync": {
                "ok": True,
                "verified": 0,
                "inserted": 0,
                "prFollowup": {
                    "status": "imported",
                    "matched": 1,
                    "inserted": 1,
                    "updated": 0,
                },
            },
            "list": {"ok": True, "pending": []},
            "pr-followup-list": {
                "ok": True,
                "candidates": [{"key": "ai-dynamo/dynamo#13691"}],
                "unresolved": [],
            },
            "publication-feedback-list": {"ok": True},
            "recovery-list": {"ok": True, "recoverable": []},
            "drain-once": {
                "ok": True,
                "action": "pr_followup_dispatched",
                "key": "ai-dynamo/dynamo#13691",
            },
        }
        return responses[operation]

    result = advance_once(
        tmp_path,
        runner=runner,
        queue_sync_interval_seconds=300,
    )

    assert result["ok"] is True
    assert result["queueSync"]["prFollowupCandidates"] == [{"key": "ai-dynamo/dynamo#13691"}]
    assert result["drain"]["action"] == "pr_followup_dispatched"
    assert calls.index("pr-followup-list") < calls.index("drain-once")


def test_replayed_pr_followup_without_a_candidate_does_not_retrigger_drain(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        responses = {
            "context-recover": {"ok": True, "errors": [], "unavailable": []},
            "ingest-results": {"ok": True},
            "independent-review-run": {"ok": True, "updated": []},
            "title-reconcile": {"ok": True},
            "cleanup-reconcile": {"ok": True},
            "publication-run": {"ok": True},
            "sync": {
                "ok": True,
                "verified": 0,
                "inserted": 0,
                "prFollowup": {
                    "status": "imported",
                    "matched": 1,
                    "inserted": 0,
                    "updated": 1,
                },
            },
            "list": {"ok": True, "pending": []},
            "pr-followup-list": {"ok": True, "candidates": [], "unresolved": []},
            "publication-feedback-list": {"ok": True},
            "recovery-list": {"ok": True, "recoverable": []},
        }
        return responses[operation]

    result = advance_once(
        tmp_path,
        runner=runner,
        queue_sync_interval_seconds=300,
    )

    assert result["ok"] is True
    assert result["drain"]["action"] == "not_triggered"
    assert "drain-once" not in calls


def test_slow_cycle_polls_cloud_pr_followups_every_five_minutes(monkeypatch, tmp_path):
    observed = []

    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: {"level": "ok"}
    )

    def sync(_root, *, runner, interval_seconds, now=None):
        observed.append(interval_seconds)
        return {"ok": True, "attempted": False, "pending": [], "errors": []}

    monkeypatch.setattr("oss_pr_radar.local_publication.sync_cloud_queue_if_due", sync)

    def runner(_root: Path, operation: str):
        if operation == "reproduction-probe":
            return {"ok": True, "count": 0, "errors": []}
        if operation == "context-recover":
            return {"ok": True, "verified": 0, "unavailable": [], "errors": []}
        if operation == "ingest-results":
            return {"ok": True, "ingested": [], "publicationRequests": [], "errors": []}
        if operation == "publication-feedback-list":
            return {"ok": True, "candidates": [], "unresolved": [], "errors": []}
        if operation == "recovery-list":
            return {"ok": True, "recoverable": [], "errors": []}
        return {"ok": True, "published": [], "pending": [], "blocked": [], "errors": []}

    result = slow_advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert observed == [300]


def test_cloud_queue_sync_is_throttled_after_an_attempt(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        return {"ok": True, "verified": 0, "inserted": 0, "pending": []}

    first = sync_cloud_queue_if_due(
        tmp_path,
        runner=runner,
        interval_seconds=300,
        now=1_000,
    )
    second = sync_cloud_queue_if_due(
        tmp_path,
        runner=runner,
        interval_seconds=300,
        now=1_100,
    )

    assert first["attempted"] is True
    assert second == {"ok": True, "attempted": False, "pending": [], "errors": []}
    assert calls == ["sync", "list"]


def test_synced_pending_work_triggers_the_existing_serial_drain(tmp_path):
    calls = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        responses = {
            "context-recover": {"ok": True, "errors": [], "unavailable": []},
            "ingest-results": {"ok": True},
            "independent-review-run": {"ok": True, "updated": []},
            "title-reconcile": {"ok": True},
            "cleanup-reconcile": {"ok": True},
            "publication-run": {"ok": True},
            "sync": {"ok": True, "verified": 1, "inserted": 1},
            "list": {"ok": True, "pending": [{"key": "a/b#1"}]},
            "publication-feedback-list": {"ok": True},
            "recovery-list": {"ok": True, "recoverable": []},
            "drain-once": {
                "ok": True,
                "action": "issue_task_dispatched",
                "key": "a/b#1",
            },
        }
        return responses[operation]

    result = advance_once(
        tmp_path,
        runner=runner,
        queue_sync_interval_seconds=300,
    )

    assert result["ok"] is True
    assert result["queueSync"]["inserted"] == 1
    assert result["drain"]["action"] == "issue_task_dispatched"
    assert calls.index("sync") < calls.index("drain-once")


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
        "workBlocked": 0,
        "reviewsUpdated": 1,
        "titlesRenamed": 0,
        "threadsArchived": 0,
        "published": 0,
        "publicationFeedbackPending": 0,
        "publicationFeedbackReconciled": 0,
        "publicationBlocked": 1,
        "errors": 1,
    }
    assert compact["reviewBusy"] is True
    assert compact["contextsUnavailableCount"] == 20
    assert "contextsUnavailable" not in compact
    assert len(json.dumps(compact)) < 1_000


@pytest.mark.parametrize(
    "receipt",
    [
        {"ok": False, "turnStarted": False, "turnId": "turn-1", "error": "conflict"},
        {
            "ok": False,
            "turnStarted": False,
            "turnId": None,
            "turnStatus": "completed",
            "error": "conflict",
        },
        {"ok": "true", "turnStarted": False, "turnId": None, "error": "malformed"},
    ],
)
def test_retryable_delivery_pending_rejects_contradictory_receipts(tmp_path, receipt):
    receipt_path = tmp_path / "state" / "task_turn_receipts" / "receipt.json"
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    assert retryable_delivery_pending(tmp_path, min_age_seconds=0) is False
