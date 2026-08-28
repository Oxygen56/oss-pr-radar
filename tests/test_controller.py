from __future__ import annotations

import fcntl
import hashlib
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.controller import (
    CONTROLLER_LOCK_MARKER_SCHEMA,
    _controller_command_digest,
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
    if stage == "finalEventLaneHealth":
        return {
            "healthy": True,
            "lanes": {
                "agentscope": {"healthy": True},
                "nanobot": {"healthy": True},
            },
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
    assert calls.count("codexDecisionSessions") == 1
    assert calls.count("drain") == 1
    assert calls.index("queueSync") < calls.index("codexDecisionSessions")
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


def test_controller_stops_immediately_when_disk_guard_is_active(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "localAgentStatus":
            return {
                "ok": False,
                "workers": [
                    {
                        "ok": False,
                        "runtimeHealth": {"disk": {"level": "stop"}},
                    }
                ],
            }
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=runner,
        notify=False,
    )

    assert result["ok"] is False
    assert calls == ["localAgentEnsure", "localAgentStatus"]
    assert result["finalBlockers"] == [
        {"stage": "finalLocalAgentStatus", "queue": "disk_stop", "count": 1}
    ]
    compact = compact_controller_result(result)
    assert compact["warnings"]["diskThresholdStop"] == 1
    assert compact["finalBlockers"] == result["finalBlockers"]


def test_controller_finishes_terminal_publication_lifecycle_in_same_cycle(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "publication":
            return {
                "ok": True,
                "blocked": [
                    {
                        "requestId": "request-1",
                        "reason": "STRONG_EXISTING_PR",
                        "terminalized": True,
                    }
                ],
            }
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path, code_root=DEV_CODE_ROOT, allow_unreleased_code=True, runner=runner, notify=False
    )

    assert result["ok"] is True
    ordered = [
        "publication",
        "contextSync",
        "terminalFeedbackAfterPublication",
        "titleReconcileAfterPublication",
        "cleanupReconcileAfterPublication",
        "drain",
    ]
    assert [calls.index(stage) for stage in ordered] == sorted(
        calls.index(stage) for stage in ordered
    )


def test_controller_skips_post_publication_cleanup_without_terminal_block(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "publication":
            return {
                "ok": True,
                "blocked": [
                    {
                        "requestId": "request-1",
                        "reason": "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED",
                    }
                ],
            }
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path, code_root=DEV_CODE_ROOT, allow_unreleased_code=True, runner=runner, notify=False
    )

    assert result["ok"] is True
    assert "terminalFeedbackAfterPublication" not in calls
    assert "titleReconcileAfterPublication" not in calls
    assert "cleanupReconcileAfterPublication" not in calls
    assert result["stages"]["terminalFeedbackAfterPublication"]["skipped"] is True
    assert result["stages"]["titleReconcileAfterPublication"]["skipped"] is True
    assert result["stages"]["cleanupReconcileAfterPublication"]["skipped"] is True


def test_controller_publishes_state_drift_recheck_after_drain(tmp_path):
    calls: list[str] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        calls.append(stage)
        if stage == "drain":
            return {
                "ok": True,
                "action": "none",
                "terminalized": [],
                "scannerRechecks": [{"key": "a/b#1", "reason": "STATE_DRIFT"}],
            }
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path, code_root=DEV_CODE_ROOT, allow_unreleased_code=True, runner=runner, notify=False
    )

    assert result["ok"] is True
    assert calls.index("drain") < calls.index("terminalFeedbackAfterDrain")


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


def test_controller_repairs_after_one_missed_hour_without_tightening_final_health(tmp_path):
    health_commands: dict[str, list[str]] = {}

    def runner(_root, stage, argv, _allowed, _timeout):
        if stage in {"workflowHealth", "finalWorkflowHealth"}:
            health_commands[stage] = list(argv)
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=runner,
        notify=False,
    )

    assert result["ok"] is True
    repair = health_commands["workflowHealth"]
    assert repair[repair.index("--max-effective-age-minutes") + 1] == "90"
    assert "--repair" in repair
    final = health_commands["finalWorkflowHealth"]
    assert final[final.index("--max-effective-age-minutes") + 1] == "110"
    assert "--repair" not in final


def test_controller_allows_initial_local_health_to_recover_within_cycle(tmp_path):
    def runner(_root, stage, _argv, _allowed, _timeout):
        if stage == "localAgentStatus":
            return {"ok": False, "workers": [{"label": "fast", "ok": False}]}
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=runner,
        notify=False,
    )

    assert result["ok"] is True
    assert result["failures"] == []
    assert result["finalBlockers"] == []
    assert result["summary"]["localAgentHealthy"] is True


def test_controller_fails_closed_when_final_local_health_is_unhealthy(tmp_path):
    def runner(_root, stage, _argv, _allowed, _timeout):
        if stage == "finalLocalAgentStatus":
            return {"ok": False, "workers": [{"label": "slow", "ok": False}]}
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=runner,
        notify=False,
    )

    assert result["ok"] is False
    assert result["failures"] == []
    assert result["finalBlockers"] == [
        {"stage": "finalLocalAgentStatus", "queue": "unhealthy", "count": 1}
    ]
    assert result["summary"]["localAgentHealthy"] is False


def test_controller_fails_closed_when_final_local_health_omits_ok(tmp_path):
    def runner(_root, stage, _argv, _allowed, _timeout):
        if stage == "finalLocalAgentStatus":
            return {}
        return healthy_response(stage)

    result = controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=runner,
        notify=False,
    )

    assert result["ok"] is False
    assert result["failures"] == []
    assert result["finalBlockers"] == [
        {"stage": "finalLocalAgentStatus", "queue": "unhealthy", "count": 1}
    ]


def test_controller_cycle_lock_suppresses_overlap(tmp_path):
    lock_path = tmp_path / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir()
    lock_path.touch()
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run_locked_controller_cycle(tmp_path, notify=False)

    assert result["busy"] is True
    assert result["summary"]["action"] == "controller_already_running"


def test_controller_cycle_can_join_existing_run_after_tool_context_loss(tmp_path):
    acquired = threading.Event()
    completed: list[dict] = []

    def runner(_root, stage, _argv, _allowed, _timeout):
        if not acquired.is_set():
            acquired.set()
            time.sleep(0.2)
        return healthy_response(stage)

    def existing_run():
        completed.append(
            run_locked_controller_cycle(
                tmp_path,
                code_root=DEV_CODE_ROOT,
                allow_unreleased_code=True,
                runner=runner,
                notify=False,
                report_on_complete=True,
            )
        )

    thread = threading.Thread(target=existing_run)
    thread.start()
    assert acquired.wait(timeout=1)
    joined: list[dict] = []

    def join_existing():
        joined.append(
            run_locked_controller_cycle(
                tmp_path,
                code_root=DEV_CODE_ROOT,
                allow_unreleased_code=True,
                notify=False,
                wait_existing=True,
                report_on_complete=True,
                busy_timeout_seconds=1,
                runner=lambda *_args: (_ for _ in ()).throw(
                    AssertionError("a joiner must not start a duplicate controller cycle")
                ),
            )
        )

    second_joiner = threading.Thread(target=join_existing)
    second_joiner.start()
    join_existing()
    thread.join(timeout=1)
    second_joiner.join(timeout=1)

    assert not thread.is_alive()
    assert not second_joiner.is_alive()
    assert joined == [completed[0], completed[0]]

    replay = run_locked_controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        notify=False,
        wait_existing=True,
        report_on_complete=True,
        runner=lambda *_args: (_ for _ in ()).throw(
            AssertionError("a lost completed result must not start a duplicate controller cycle")
        ),
    )
    assert replay == completed[0]


def test_controller_cycle_recovers_report_written_before_completion_marker(tmp_path):
    command_digest = _controller_command_digest(
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        notify=False,
        project_id="github",
    )
    now = datetime.now(UTC)
    started_at = (now - timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
    checked_at = (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    run_id = "recovered-run"
    result = {
        "ok": True,
        "checkedAt": checked_at,
        "controllerRunId": run_id,
        "summary": {"action": "completed-before-marker"},
        "failures": [],
        "finalBlockers": [],
    }
    write_controller_report(tmp_path, result)
    lock_path = tmp_path / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir(exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "schema": CONTROLLER_LOCK_MARKER_SCHEMA,
                "state": "RUNNING",
                "runId": run_id,
                "commandDigest": command_digest,
                "startedAt": started_at,
            }
        ),
        encoding="utf-8",
    )

    recovered = run_locked_controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        notify=False,
        project_id="github",
        wait_existing=True,
        report_on_complete=True,
        runner=lambda *_args: (_ for _ in ()).throw(
            AssertionError("a fully written result must not start a replacement cycle")
        ),
    )

    assert recovered == result
    marker = json.loads(lock_path.read_text(encoding="utf-8"))
    assert marker["state"] == "COMPLETED"
    assert marker["runId"] == run_id


def test_controller_cycle_does_not_reuse_an_ancient_running_marker(tmp_path):
    command_digest = _controller_command_digest(
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        notify=False,
        project_id="github",
    )
    old_run_id = "ancient-run"
    write_controller_report(
        tmp_path,
        {
            "ok": True,
            "checkedAt": "2020-01-01T00:00:01Z",
            "controllerRunId": old_run_id,
            "summary": {"action": "ancient"},
        },
    )
    lock_path = tmp_path / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir(exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "schema": CONTROLLER_LOCK_MARKER_SCHEMA,
                "state": "RUNNING",
                "runId": old_run_id,
                "commandDigest": command_digest,
                "startedAt": "2020-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    fresh = run_locked_controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        runner=lambda _root, stage, _argv, _allowed, _timeout: healthy_response(stage),
        notify=False,
        project_id="github",
        wait_existing=True,
        report_on_complete=True,
    )

    assert fresh["controllerRunId"] != old_run_id
    assert fresh["summary"].get("action") != "ancient"


def test_controller_cycle_join_gets_current_runtime_failure_not_old_report(tmp_path, monkeypatch):
    write_controller_report(
        tmp_path,
        {
            "ok": True,
            "checkedAt": "2026-08-27T00:00:00Z",
            "summary": {"action": "stale"},
        },
    )
    acquired = threading.Event()
    completed: list[dict] = []

    def failing_cycle(*_args, **_kwargs):
        acquired.set()
        time.sleep(0.05)
        raise RuntimeError("operational authorization expired")

    monkeypatch.setattr("oss_pr_radar.controller.controller_cycle", failing_cycle)

    def existing_run():
        completed.append(
            run_locked_controller_cycle(
                tmp_path,
                code_root=DEV_CODE_ROOT,
                allow_unreleased_code=True,
                notify=False,
                report_on_complete=True,
            )
        )

    thread = threading.Thread(target=existing_run)
    thread.start()
    assert acquired.wait(timeout=1)
    joined = run_locked_controller_cycle(
        tmp_path,
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        notify=False,
        wait_existing=True,
        report_on_complete=True,
        busy_timeout_seconds=1,
        runner=lambda *_args: (_ for _ in ()).throw(
            AssertionError("a joiner must not execute a replacement cycle")
        ),
    )
    thread.join(timeout=1)

    assert joined == completed[0]
    assert joined["ok"] is False
    assert "expired" in joined["error"]
    assert joined.get("summary") != {"action": "stale"}


def test_controller_cycle_join_ignores_expired_completed_marker_during_new_run(
    tmp_path, monkeypatch
):
    command_digest = _controller_command_digest(
        code_root=DEV_CODE_ROOT,
        allow_unreleased_code=True,
        notify=False,
        project_id="github",
    )
    old_run_id = "expired-completed-run"
    old_checked_at = (datetime.now(UTC) - timedelta(minutes=11)).isoformat().replace("+00:00", "Z")
    old_result = {
        "ok": True,
        "checkedAt": old_checked_at,
        "controllerRunId": old_run_id,
        "summary": {"action": "expired"},
        "failures": [],
        "finalBlockers": [],
    }
    report_path = write_controller_report(tmp_path, old_result)
    lock_path = tmp_path / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir(exist_ok=True)
    lock_path.write_text(
        json.dumps(
            {
                "schema": CONTROLLER_LOCK_MARKER_SCHEMA,
                "state": "COMPLETED",
                "runId": old_run_id,
                "commandDigest": command_digest,
                "startedAt": old_checked_at,
                "completedAt": old_checked_at,
                "reportCheckedAt": old_checked_at,
                "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )

    producer_paused = threading.Event()
    release_producer = threading.Event()
    from oss_pr_radar.controller import _completed_controller_result

    original_completed = _completed_controller_result
    paused_once = False

    def pause_expired_reuse_check(*args, **kwargs):
        nonlocal paused_once
        if threading.current_thread().name == "producer" and not paused_once:
            paused_once = True
            producer_paused.set()
            assert release_producer.wait(timeout=2)
        return original_completed(*args, **kwargs)

    monkeypatch.setattr(
        "oss_pr_radar.controller._completed_controller_result", pause_expired_reuse_check
    )
    results: list[dict] = []

    def run_cycle():
        results.append(
            run_locked_controller_cycle(
                tmp_path,
                code_root=DEV_CODE_ROOT,
                allow_unreleased_code=True,
                runner=lambda _root, stage, _argv, _allowed, _timeout: healthy_response(stage),
                notify=False,
                project_id="github",
                wait_existing=True,
                report_on_complete=True,
                busy_timeout_seconds=2,
            )
        )

    producer = threading.Thread(target=run_cycle, name="producer")
    producer.start()
    assert producer_paused.wait(timeout=1)
    joiner = threading.Thread(target=run_cycle, name="joiner")
    joiner.start()
    time.sleep(0.05)
    release_producer.set()
    producer.join(timeout=3)
    joiner.join(timeout=3)

    assert not producer.is_alive()
    assert not joiner.is_alive()
    assert len(results) == 2
    assert results[0]["controllerRunId"] == results[1]["controllerRunId"]
    assert results[0]["controllerRunId"] != old_run_id
    assert results[0]["summary"].get("action") != "expired"


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
            "finalRecovery": {"parkedRecovery": [{"key": "a/b#4"}]},
            "finalLocalAgentStatus": {
                "workers": [
                    {
                        "runtimeHealth": {"warnings": ["DISK_WARNING_THRESHOLD"]},
                        "workerRuntimeHealth": {"healthy": True},
                    }
                ]
            },
        },
    }

    report = write_controller_report(tmp_path, result)
    compact = compact_controller_result(result, report_path=report)

    assert report.is_file()
    assert compact["warnings"]["unavailableWorktrees"] == 1
    assert compact["warnings"]["validationEnvironmentBlocked"] == 1
    assert compact["warnings"]["prFollowupQuarantined"] == 1
    assert compact["warnings"]["titleUpdatesPending"] == 1
    assert compact["warnings"]["parkedRecovery"] == 1
    assert compact["warnings"]["diskThresholdWarning"] == 1
    assert compact["warnings"]["diskThresholdStop"] == 0
    assert "stages" not in compact
    assert "startupBlocker" not in compact
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


def test_controller_blockers_include_execution_failures_and_exhausted_recovery():
    from oss_pr_radar.controller import _final_blockers

    blockers = _final_blockers(
        {
            "resultIngestion": {
                "ok": False,
                "errors": [{"key": "a/b#1"}],
                "workBlocked": [{"key": "a/b#3"}],
            },
            "finalRecovery": {
                "blocked": [],
                "unresolved": [],
                "recoveryRetryExhausted": [{"key": "a/b#2"}],
            },
            "finalLocalAgentStatus": {
                "ok": False,
                "workers": [{"label": "slow", "ok": False}],
            },
            "finalEventLaneHealth": {
                "healthy": False,
                "lanes": {
                    "agentscope": {"healthy": False},
                    "nanobot": {"healthy": True},
                },
            },
        }
    )

    assert blockers == [
        {"stage": "resultIngestion", "queue": "errors", "count": 1},
        {"stage": "resultIngestion", "queue": "workBlocked", "count": 1},
        {
            "stage": "finalRecovery",
            "queue": "recoveryRetryExhausted",
            "count": 1,
        },
        {"stage": "finalLocalAgentStatus", "queue": "unhealthy", "count": 1},
        {"stage": "finalEventLaneHealth", "queue": "unhealthy", "count": 1},
    ]


def test_controller_health_checks_fail_closed_on_invalid_results():
    from oss_pr_radar.controller import _final_blockers

    assert _final_blockers(
        {
            "finalWorkflowHealth": {"ok": False, "error": "invalid JSON"},
            "finalEventLaneHealth": {"ok": False, "error": "command failed"},
        }
    ) == [
        {"stage": "finalWorkflowHealth", "queue": "unhealthy", "count": 1},
        {"stage": "finalEventLaneHealth", "queue": "unhealthy", "count": 1},
    ]


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
    assert "startupBlocker" not in compact


def test_compact_controller_result_exposes_safe_release_binding_mismatch():
    result = {
        "ok": False,
        "blocked": "operational authorization required",
        "error": (
            "explicit code root is not the active immutable release: /private/sensitive/release"
        ),
    }

    compact = compact_controller_result(result)

    assert compact["startupBlocker"] == {
        "errorCode": "RELEASE_BINDING_MISMATCH",
        "message": "自动任务绑定的版本已不是当前运行版本；本轮未执行。",
    }
    assert "error" not in compact
    assert "blocked" not in compact
    assert "/private/sensitive/release" not in str(compact)
