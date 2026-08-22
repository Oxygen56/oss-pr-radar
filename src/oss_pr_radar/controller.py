"""Deterministic hourly controller for the local Radar control plane."""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .managed_adapter import GitHubAbsenceQueries, ManagedAdapter
from .managed_snapshot import export_snapshot, import_snapshot
from .operational_auth import require_operational_authorization
from .release_binding import bind_runtime, runtime_ledger_path, runtime_python

DEFAULT_PROJECT_ID = "5e41d21c-cba3-4be0-9a02-7eef35b67625"
Runner = Callable[[Path, str, Sequence[str], set[int], int], dict[str, Any]]


def _managed_runtime_has_local_state(path: Path) -> bool:
    """Return true when importing a redacted snapshot would erase local bindings."""

    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with sqlite3.connect(path) as connection:
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            required = {
                "managed_opportunities",
                "managed_tasks",
                "managed_prs",
                "managed_lifecycle_events",
            }
            if not required.issubset(tables):
                return False
            return any(
                connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
                for table in required
            )
    except sqlite3.Error:
        return False


def run_json_command(
    root: Path,
    _stage: str,
    argv: Sequence[str],
    allowed_codes: set[int],
    timeout: int,
) -> dict[str, Any]:
    completed = subprocess.run(
        list(argv),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode not in allowed_codes:
        detail = completed.stderr or completed.stdout or "controller command failed"
        raise RuntimeError(f"exit={completed.returncode}: {detail[:600]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("controller command returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("controller command returned a non-object")
    return value


def controller_cycle(
    root: Path,
    *,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
    runner: Runner = run_json_command,
    notify: bool = True,
    project_id: str = DEFAULT_PROJECT_ID,
) -> dict[str, Any]:
    """Run one ordered control-plane cycle and return one authoritative result."""

    root = root.resolve()
    binding = bind_runtime(
        root,
        code_root=code_root,
        allow_unreleased_code=allow_unreleased_code,
    )
    if not allow_unreleased_code:
        require_operational_authorization(root)
    managed_path = runtime_ledger_path(root)
    managed_snapshot_path = root / "state" / "managed_lifecycle.snapshot.json.gz"
    if _managed_runtime_has_local_state(managed_path):
        managed_restore = {"ok": True, "restored": False, "reason": "local_state_active"}
    else:
        managed_restore = import_snapshot(managed_path, managed_snapshot_path, allow_missing=True)
    managed_adapter = ManagedAdapter(root)
    managed_adapter.ensure()
    python = str(runtime_python(root))
    bridge_script = str(binding.script("scripts/local_dispatch_bridge.py"))
    stages: dict[str, dict[str, Any]] = {}
    stages["managedRestore"] = managed_restore
    failures: list[dict[str, str]] = []

    def run_stage(
        name: str,
        argv: Sequence[str],
        *,
        allowed_codes: set[int] | None = None,
        timeout: int = 900,
        require_ok: bool = True,
    ) -> dict[str, Any]:
        try:
            value = runner(root, name, argv, allowed_codes or {0}, timeout)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            value = {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}
        stages[name] = value
        if require_ok and value.get("ok") is False:
            failures.append(
                {
                    "stage": name,
                    "reason": str(value.get("error") or value.get("errors") or "stage failed")[
                        :400
                    ],
                }
            )
        return value

    def bridge(
        name: str,
        operation: str,
        *arguments: str,
        require_ok: bool = True,
        timeout: int = 900,
    ) -> dict[str, Any]:
        return run_stage(
            name,
            [python, bridge_script, "--runtime-root", str(root), operation, *arguments],
            require_ok=require_ok,
            timeout=timeout,
        )

    install_script = str(binding.script("scripts/install_local_publication_workers.py"))
    health_script = str(binding.script("scripts/check_workflow_health.py"))
    run_stage("localAgentEnsure", [python, install_script, "--runtime-root", str(root), "--ensure"])
    run_stage(
        "localAgentStatus",
        [python, install_script, "--runtime-root", str(root), "--status"],
        allowed_codes={0, 1},
    )
    health = run_stage(
        "workflowHealth",
        [
            python,
            health_script,
            "--runtime-root",
            str(root),
            "--code-root",
            str(binding.code_root),
            "--max-effective-age-minutes",
            "110",
            "--repair",
        ],
        allowed_codes={0, 2},
        require_ok=False,
    )
    remote_scan_active = bool((health.get("effectiveScan") or {}).get("recentActive"))

    bridge(
        "orphanReconcile",
        "orphan-reconcile",
        "--project-id",
        project_id,
        require_ok=True,
    )
    bridge("terminalFeedbackBeforeSync", "publish-terminal-feedback")
    if health.get("operationalHealthy") and not remote_scan_active:
        bridge("queueSync", "sync", timeout=1200)
    else:
        stages["queueSync"] = {
            "ok": True,
            "skipped": True,
            "reason": ("remote_scan_active" if remote_scan_active else "workflow_not_operational"),
        }
    bridge(
        "codexDecisionSessions",
        "codex-decision-dispatch",
        "--project-id",
        project_id,
        timeout=900,
    )
    bridge("refreshPullRequests", "refresh-prs")

    recovery = bridge("contextRecovery", "context-recover")
    lifecycle_ready = recovery.get("ok") is not False and not recovery.get("errors")
    if lifecycle_ready:
        bridge("resultIngestion", "ingest-results")
        independent_review = bridge(
            "independentReview",
            "independent-review-run",
            timeout=1800,
        )
        if independent_review.get("updated"):
            bridge("resultIngestionAfterReview", "ingest-results")
        else:
            stages["resultIngestionAfterReview"] = {"ok": True, "skipped": True}
        bridge("contextSyncBeforeCleanup", "context-sync")
        bridge("restoreReconcile", "restore-reconcile")
        bridge("titleReconcile", "title-reconcile")
        bridge("cleanupReconcile", "cleanup-reconcile")
        bridge(
            "duplicateTaskReconcile",
            "duplicate-task-reconcile",
            "--min-age-minutes",
            "30",
        )
        bridge("publication", "publication-run", timeout=1800)
        bridge("contextSync", "context-sync")
        drain = bridge(
            "drain",
            "drain-once",
            "--project-id",
            project_id,
            "--owner",
            "hourly-controller",
            timeout=1800,
        )
        if drain.get("terminalized"):
            bridge("terminalFeedbackAfterDrain", "publish-terminal-feedback")
        else:
            stages["terminalFeedbackAfterDrain"] = {"ok": True, "skipped": True}
        notification_args = ["--notify"] if notify else []
        bridge("dispatchNotifications", "dispatch-notifications", *notification_args)
    else:
        stages["lifecycle"] = {
            "ok": False,
            "skipped": True,
            "reason": "task_context_recovery_failed",
        }
        failures.append({"stage": "lifecycle", "reason": "task_context_recovery_failed"})

    alert_args = ["--min-age-minutes", "70"] + (["--notify"] if notify else [])
    bridge("alerts", "alerts", *alert_args)

    for name, operation, arguments in (
        ("finalContextRecovery", "context-recover", ()),
        ("finalOrphans", "orphan-list", ()),
        ("finalPrFollowups", "pr-followup-list", ()),
        ("finalValidationFollowups", "validation-followup-list", ()),
        ("finalRecovery", "recovery-list", ("--min-age-minutes", "90")),
        ("finalRestore", "restore-list", ()),
        ("finalTitles", "title-list", ()),
        ("finalCleanup", "cleanup-list", ()),
        ("finalDuplicates", "duplicate-task-list", ("--min-age-minutes", "30")),
        ("finalQueue", "list", ()),
        ("quality", "metrics", ("--days", "30")),
    ):
        bridge(name, operation, *arguments, require_ok=False)

    run_stage(
        "finalWorkflowHealth",
        [
            python,
            health_script,
            "--runtime-root",
            str(root),
            "--code-root",
            str(binding.code_root),
            "--max-effective-age-minutes",
            "110",
        ],
        allowed_codes={0, 2},
        require_ok=False,
    )
    run_stage(
        "finalLocalAgentStatus",
        [python, install_script, "--runtime-root", str(root), "--status"],
        allowed_codes={0, 1},
    )

    final_blockers = _final_blockers(stages)
    stages["absenceReconcile"] = managed_adapter.reconcile_pending_absences(GitHubAbsenceQueries())
    reply_flow = managed_adapter.process_reply_outbox(sender=None, receipts={})
    stages["replyQueue"] = {"ok": True, "stage": "queue_public_reply"}
    stages["replyDispatch"] = reply_flow["dispatch"]
    stages["replyReconcile"] = reply_flow["reconcile"]
    stages["managedProjection"] = managed_adapter.ledger.war_room_projection()
    stages["managedPersistence"] = export_snapshot(managed_path, managed_snapshot_path)
    return {
        "ok": not failures and not final_blockers,
        "checkedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "stages": stages,
        "failures": failures,
        "finalBlockers": final_blockers,
        "summary": _compact_summary(stages),
    }


def _final_blockers(stages: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    checks = {
        "finalOrphans": ("blocked",),
        "finalPrFollowups": ("blocked", "unresolved", "restoreRequired"),
        "finalValidationFollowups": ("unresolved", "stale", "errors"),
        "finalRecovery": ("blocked", "unresolved"),
        "finalRestore": ("restore", "blocked"),
        "finalTitles": ("blocked",),
        "finalCleanup": ("cleanup", "blocked"),
        "finalDuplicates": ("duplicates",),
    }
    for stage, keys in checks.items():
        value = stages.get(stage) or {}
        for key in keys:
            items = value.get(key) or []
            if items:
                blockers.append({"stage": stage, "queue": key, "count": len(items)})
    return blockers


def _compact_summary(stages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    drain = stages.get("drain") or {}
    queue = stages.get("finalQueue") or {}
    quality = stages.get("quality") or {}
    health = stages.get("finalWorkflowHealth") or stages.get("workflowHealth") or {}
    decision_sessions = stages.get("codexDecisionSessions") or {}
    return {
        "localAgentHealthy": bool((stages.get("finalLocalAgentStatus") or {}).get("ok")),
        "operationalHealthy": bool(health.get("operationalHealthy")),
        "githubNaturalScheduleHealthy": bool(health.get("githubNaturalScheduleHealthy")),
        "drainAction": drain.get("action"),
        "drainKey": drain.get("key"),
        "decisionSessionsCreated": len(decision_sessions.get("created") or []),
        "decisionSessionsExisting": len(decision_sessions.get("existing") or []),
        "pendingCount": len(queue.get("pending") or []),
        "submitReadyRate": quality.get("submitReadyRate"),
        "filterMissRate": quality.get("filterMissRate"),
        "hardGateEscapes": quality.get("hardGateEscapes"),
    }


def run_locked_controller_cycle(
    root: Path,
    *,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
    runner: Runner = run_json_command,
    notify: bool = True,
    project_id: str = DEFAULT_PROJECT_ID,
) -> dict[str, Any]:
    lock_path = root.resolve() / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"ok": True, "busy": True, "summary": {"action": "controller_already_running"}}
        return controller_cycle(
            root,
            code_root=code_root,
            allow_unreleased_code=allow_unreleased_code,
            runner=runner,
            notify=notify,
            project_id=project_id,
        )


def write_controller_report(root: Path, result: dict[str, Any]) -> Path:
    report_path = root.resolve() / "reports" / "latest_controller_cycle.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = report_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, report_path)
    return report_path


def compact_controller_result(
    result: dict[str, Any], *, report_path: Path | None = None
) -> dict[str, Any]:
    if result.get("busy"):
        return result
    stages = result.get("stages") or {}
    recovery = stages.get("finalContextRecovery") or stages.get("contextRecovery") or {}
    validation = stages.get("finalValidationFollowups") or {}
    pr_followups = stages.get("finalPrFollowups") or {}
    titles = stages.get("finalTitles") or {}
    publication = stages.get("publication") or {}
    feedback = stages.get("terminalFeedbackBeforeSync") or {}
    desktop_handoff = _pending_desktop_handoff(stages)
    compact = {
        "ok": result.get("ok"),
        "checkedAt": result.get("checkedAt"),
        "summary": result.get("summary") or {},
        "failures": result.get("failures") or [],
        "finalBlockers": result.get("finalBlockers") or [],
        "warnings": {
            "unavailableWorktrees": len(recovery.get("unavailable") or []),
            "validationEnvironmentBlocked": len(validation.get("environmentBlocked") or []),
            "validationNoProgress": len(validation.get("blockedNoProgress") or []),
            "prFollowupQuarantined": len(pr_followups.get("quarantined") or []),
            "titleUpdatesPending": len(titles.get("titles") or []),
            "publicationBlocked": len(publication.get("blocked") or []),
            "terminalFeedbackDeferred": len(feedback.get("deferred") or []),
        },
    }
    if desktop_handoff is not None:
        compact["desktopHandoff"] = desktop_handoff
    startup_blocker = _safe_startup_blocker(result)
    if startup_blocker is not None:
        compact["startupBlocker"] = startup_blocker
    if report_path is not None:
        compact["reportPath"] = str(report_path)
    return compact


def _safe_startup_blocker(result: dict[str, Any]) -> dict[str, str] | None:
    """Return a stable, non-sensitive summary for pre-cycle failures."""

    if result.get("ok") is not False or result.get("stages"):
        return None
    error = str(result.get("error") or "")
    blocked = str(result.get("blocked") or "")
    if "explicit code root is not the active immutable release" in error:
        return {
            "errorCode": "RELEASE_BINDING_MISMATCH",
            "message": "自动任务绑定的版本已不是当前运行版本；本轮未执行。",
        }
    if (
        "operational authorization" in error.lower()
        or "operational authorization" in blocked.lower()
    ):
        return {
            "errorCode": "OPERATIONAL_AUTHORIZATION_REQUIRED",
            "message": "当前运行版本尚未完成授权；本轮未执行。",
        }
    if error or blocked:
        return {
            "errorCode": "CONTROLLER_START_FAILED",
            "message": "控制器启动失败；本轮未执行。",
        }
    return None


def _pending_desktop_handoff(stages: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    drain_handoff = ((stages.get("drain") or {}).get("delivery") or {}).get("desktopHandoff")
    if (
        isinstance(drain_handoff, dict)
        and drain_handoff.get("threadId")
        and drain_handoff.get("prompt")
    ):
        return drain_handoff
    for stage_name in ("finalPrFollowups", "finalValidationFollowups", "finalRecovery"):
        stage = stages.get(stage_name) or {}
        for item in stage.get("unresolved") or []:
            handoff = item.get("desktopHandoff")
            if isinstance(handoff, dict) and handoff.get("threadId") and handoff.get("prompt"):
                return handoff
    return None
