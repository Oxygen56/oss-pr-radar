"""Deterministic hourly controller for the local Radar control plane."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_PROJECT_ID = "5e41d21c-cba3-4be0-9a02-7eef35b67625"
Runner = Callable[[Path, str, Sequence[str], set[int], int], dict[str, Any]]


def _python(root: Path) -> Path:
    candidate = root / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else Path(sys.executable)


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
    runner: Runner = run_json_command,
    notify: bool = True,
    project_id: str = DEFAULT_PROJECT_ID,
) -> dict[str, Any]:
    """Run one ordered control-plane cycle and return one authoritative result."""

    root = root.resolve()
    python = str(_python(root))
    bridge_script = str(root / "scripts" / "local_dispatch_bridge.py")
    stages: dict[str, dict[str, Any]] = {}
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
            [python, bridge_script, operation, *arguments],
            require_ok=require_ok,
            timeout=timeout,
        )

    install_script = str(root / "scripts" / "install_local_publication_agent.py")
    health_script = str(root / "scripts" / "check_workflow_health.py")
    run_stage("localAgentInstall", [python, install_script])
    run_stage(
        "localAgentStatus",
        [python, install_script, "--status"],
        allowed_codes={0, 1},
    )
    health = run_stage(
        "workflowHealth",
        [python, health_script, "--max-effective-age-minutes", "110", "--repair"],
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
    bridge("refreshPullRequests", "refresh-prs")

    recovery = bridge("contextRecovery", "context-recover")
    lifecycle_ready = recovery.get("ok") is not False and not recovery.get("errors")
    if lifecycle_ready:
        bridge("resultIngestion", "ingest-results")
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
        [python, health_script, "--max-effective-age-minutes", "110"],
        allowed_codes={0, 2},
        require_ok=False,
    )
    run_stage(
        "finalLocalAgentStatus",
        [python, install_script, "--status"],
        allowed_codes={0, 1},
    )

    final_blockers = _final_blockers(stages)
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
        "finalTitles": ("titles", "blocked"),
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
    return {
        "localAgentHealthy": bool((stages.get("finalLocalAgentStatus") or {}).get("ok")),
        "operationalHealthy": bool(health.get("operationalHealthy")),
        "githubNaturalScheduleHealthy": bool(health.get("githubNaturalScheduleHealthy")),
        "drainAction": drain.get("action"),
        "drainKey": drain.get("key"),
        "pendingCount": len(queue.get("pending") or []),
        "submitReadyRate": quality.get("submitReadyRate"),
        "filterMissRate": quality.get("filterMissRate"),
        "hardGateEscapes": quality.get("hardGateEscapes"),
    }


def run_locked_controller_cycle(
    root: Path,
    *,
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
        return controller_cycle(root, runner=runner, notify=notify, project_id=project_id)


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
    recovery = stages.get("contextRecovery") or {}
    validation = stages.get("finalValidationFollowups") or {}
    publication = stages.get("publication") or {}
    feedback = stages.get("terminalFeedbackBeforeSync") or {}
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
            "publicationBlocked": len(publication.get("blocked") or []),
            "terminalFeedbackDeferred": len(feedback.get("deferred") or []),
        },
    }
    if report_path is not None:
        compact["reportPath"] = str(report_path)
    return compact
