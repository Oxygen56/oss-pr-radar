from __future__ import annotations

import fcntl
from pathlib import Path

import pytest

from oss_pr_radar.controller import (
    _managed_runtime_has_local_state,
    compact_controller_result,
    controller_cycle,
    run_locked_controller_cycle,
    write_controller_report,
)
from oss_pr_radar.managed_lifecycle import ManagedLedger, migrate_schema

pytestmark = pytest.mark.usefixtures("current_signing_key")
DEV_CODE_ROOT = Path(__file__).parents[1]


def healthy_response(stage: str) -> dict:
    if stage in {"workflowHealth", "finalWorkflowHealth"}:
        return {
            "operationalHealthy": True,
            "githubNaturalScheduleHealthy": True,
            "effectiveScan": {"recentActive": False},
        }
    if stage == "drain":
        return {"ok": True, "action": "issue_task_dispatched", "key": "a/b#1"}
    if stage == "finalQueue":
        return {"ok": True, "pending": []}
    if stage == "quality":
        return {
            "ok": True,
            "submitReadyRate": 0.5,
            "filterMissRate": 0.1,
            "hardGateEscapes": 0,
        }
    return {"ok": True}


def test_controller_cycle_runs_one_ordered_sync_and_drain(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=runner,
        notify=False,
        project_id="github",
    )

    assert result["ok"] is True
    assert calls.count("queueSync") == 1
    assert calls.count("drain") == 1
    assert calls.index("resultIngestion") < calls.index("drain")
    assert calls.index("resultIngestion") < calls.index("independentReview")
    assert calls.index("restoreReconcile") < calls.index("drain")
    assert result["summary"]["drainAction"] == "issue_task_dispatched"


def test_controller_does_not_restore_redacted_snapshot_over_live_task_binding(tmp_path):
    database = tmp_path / "radar.sqlite3"
    migrate_schema(database)
    managed = ManagedLedger(database)
    managed.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    managed.bind_task(
        task_id="task-1",
        opportunity_key="owner/repo#1",
        thread_id="thread-private",
        worktree_path="/private/worktree",
        source="test",
    )

    assert _managed_runtime_has_local_state(database) is True
    task = managed.read_task("task-1")
    assert task["thread_id"] == "thread-private"
    assert task["worktree_path"] == "/private/worktree"


def test_controller_reingests_an_independently_reviewed_result(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "independentReview":
            return {"ok": True, "updated": [{"key": "a/b#1", "verdict": "PASS"}]}
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path, code_root=DEV_CODE_ROOT, allow_unreleased_code=True, runner=runner, notify=False
    )

    assert result["ok"] is True
    assert calls.index("independentReview") < calls.index("resultIngestionAfterReview")
    assert calls.index("resultIngestionAfterReview") < calls.index("publication")


def test_controller_cycle_fails_closed_when_context_recovery_fails(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "contextRecovery":
            return {"ok": False, "errors": [{"error": "context mismatch"}]}
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path, code_root=DEV_CODE_ROOT, allow_unreleased_code=True, runner=runner, notify=False
    )

    assert result["ok"] is False
    assert "drain" not in calls
    assert "publication" not in calls
    assert any(item["stage"] == "contextRecovery" for item in result["failures"])


def test_controller_cycle_skips_sync_while_remote_scan_is_active(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "workflowHealth":
            return {
                "operationalHealthy": True,
                "githubNaturalScheduleHealthy": True,
                "effectiveScan": {"recentActive": True},
            }
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path, code_root=DEV_CODE_ROOT, allow_unreleased_code=True, runner=runner, notify=False
    )

    assert result["ok"] is True
    assert "queueSync" not in calls
    assert result["stages"]["queueSync"]["reason"] == "remote_scan_active"


def test_controller_cycle_lock_suppresses_overlap(tmp_path):
    lock_path = tmp_path / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir()
    lock_path.touch()
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run_locked_controller_cycle(tmp_path, notify=False)

    assert result["busy"] is True
    assert result["summary"]["action"] == "controller_already_running"


def test_controller_output_is_compact_and_full_evidence_stays_in_report(tmp_path):
    result = {
        "ok": True,
        "checkedAt": "2026-08-15T00:00:00Z",
        "summary": {"drainAction": "none"},
        "failures": [],
        "finalBlockers": [],
        "stages": {
            "contextRecovery": {"unavailable": [{"body": "x" * 10000}]},
            "finalValidationFollowups": {
                "environmentBlocked": [{"key": "a/b#1"}],
                "blockedNoProgress": [],
            },
            "finalPrFollowups": {"quarantined": [{"key": "a/b#2"}]},
            "finalTitles": {"titles": [{"key": "a/b#3"}]},
            "publication": {"blocked": []},
            "terminalFeedbackBeforeSync": {"deferred": []},
        },
    }

    report = write_controller_report(tmp_path, result)
    compact = compact_controller_result(result, report_path=report)

    assert report.is_file()
    assert compact["warnings"]["unavailableWorktrees"] == 1
    assert compact["warnings"]["validationEnvironmentBlocked"] == 1
    assert compact["warnings"]["prFollowupQuarantined"] == 1
    assert compact["warnings"]["titleUpdatesPending"] == 1
    assert "stages" not in compact
    assert len(str(compact)) < 1000


def test_pending_title_update_and_quarantine_are_not_controller_blockers():
    from oss_pr_radar.controller import _final_blockers

    blockers = _final_blockers(
        {
            "finalTitles": {"titles": [{"threadId": "thread-1"}], "blocked": []},
            "finalPrFollowups": {
                "quarantined": [{"key": "a/b#1"}],
                "blocked": [],
                "unresolved": [],
                "restoreRequired": [],
            },
        }
    )

    assert blockers == []


def test_compact_controller_result_exposes_one_desktop_handoff():
    handoff = {
        "deliveryKind": "validation-followup",
        "threadId": "thread-1",
        "deliveryToken": "digest-1",
        "prompt": "系统续跑：继续验证同一个修复，你无需操作。",
    }
    result = {
        "ok": False,
        "checkedAt": "2026-08-17T00:00:00Z",
        "summary": {"drainAction": "none"},
        "failures": [],
        "finalBlockers": [{"stage": "finalValidationFollowups", "queue": "unresolved", "count": 1}],
        "stages": {
            "finalValidationFollowups": {
                "unresolved": [{"desktopHandoff": handoff}],
            }
        },
    }

    compact = compact_controller_result(result)

    assert compact["desktopHandoff"] == handoff
