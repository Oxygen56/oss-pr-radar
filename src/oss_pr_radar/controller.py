"""Deterministic hourly controller for the local Radar control plane."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .managed_adapter import GitHubAbsenceQueries, ManagedAdapter
from .managed_snapshot import export_snapshot, import_snapshot
from .operational_auth import require_operational_authorization
from .release_binding import bind_runtime, runtime_ledger_path, runtime_python

DEFAULT_PROJECT_ID = "5e41d21c-cba3-4be0-9a02-7eef35b67625"
CONTROLLER_REPAIR_AGE_MINUTES = 90
CONTROLLER_LOCK_MARKER_SCHEMA = "oss-pr-radar.controller-lock.v1"
CONTROLLER_COMPLETED_REUSE_SECONDS = 300
CONTROLLER_ABANDONED_RECOVERY_SECONDS = 900
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
        if require_ok and value.get("ok") is not True:
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
    event_lane_health_script = str(binding.script("scripts/event_lane_health.py"))
    run_stage("localAgentEnsure", [python, install_script, "--runtime-root", str(root), "--ensure"])
    run_stage(
        "localAgentStatus",
        [python, install_script, "--runtime-root", str(root), "--status"],
        allowed_codes={0, 1},
        require_ok=False,
    )
    if _local_agent_disk_stop(stages["localAgentStatus"]):
        stages["finalLocalAgentStatus"] = stages["localAgentStatus"]
        final_blockers = _final_blockers(stages)
        return {
            "ok": False,
            "checkedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "stages": stages,
            "failures": [],
            "finalBlockers": final_blockers,
            "summary": _compact_summary(stages),
        }
    run_stage(
        "eventLaneEnsure",
        [python, event_lane_health_script, "--root", str(root), "--repair"],
        allowed_codes={0, 2},
        timeout=150,
        require_ok=False,
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
            str(CONTROLLER_REPAIR_AGE_MINUTES),
            "--repair",
        ],
        allowed_codes={0, 2},
        require_ok=False,
    )
    remote_scan_active = (health.get("effectiveScan") or {}).get("recentActive") is True

    bridge(
        "orphanReconcile",
        "orphan-reconcile",
        "--project-id",
        project_id,
        require_ok=True,
    )
    bridge("terminalFeedbackBeforeSync", "publish-terminal-feedback")
    if health.get("operationalHealthy") is True and not remote_scan_active:
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
    lifecycle_ready = recovery.get("ok") is True and not recovery.get("errors")
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
        publication = bridge("publication", "publication-run", timeout=1800)
        bridge("contextSync", "context-sync")
        publication_terminalized = any(
            isinstance(item, dict) and item.get("terminalized") is True
            for item in (publication.get("blocked") or [])
        )
        if publication_terminalized:
            bridge("terminalFeedbackAfterPublication", "publish-terminal-feedback")
            bridge("titleReconcileAfterPublication", "title-reconcile")
            bridge("cleanupReconcileAfterPublication", "cleanup-reconcile")
        else:
            stages["terminalFeedbackAfterPublication"] = {"ok": True, "skipped": True}
            stages["titleReconcileAfterPublication"] = {"ok": True, "skipped": True}
            stages["cleanupReconcileAfterPublication"] = {"ok": True, "skipped": True}
        drain = bridge(
            "drain",
            "drain-once",
            "--project-id",
            project_id,
            "--owner",
            "hourly-controller",
            timeout=1800,
        )
        if drain.get("terminalized") or drain.get("scannerRechecks"):
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
        require_ok=False,
    )
    run_stage(
        "finalEventLaneHealth",
        [python, event_lane_health_script, "--root", str(root)],
        allowed_codes={0, 2},
        require_ok=False,
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


def _local_agent_disk_stop(status: dict[str, Any]) -> bool:
    for worker in status.get("workers") or []:
        if not isinstance(worker, dict):
            continue
        health = worker.get("runtimeHealth")
        if isinstance(health, dict) and (health.get("disk") or {}).get("level") == "stop":
            return True
    return False


def _final_blockers(stages: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    checks = {
        "resultIngestion": ("errors", "workBlocked"),
        "resultIngestionAfterReview": ("errors", "workBlocked"),
        "independentReview": ("candidateErrors", "retryExhausted"),
        "finalOrphans": ("blocked",),
        "finalPrFollowups": ("blocked", "unresolved", "restoreRequired"),
        "finalValidationFollowups": ("unresolved", "stale", "errors"),
        "finalRecovery": ("blocked", "unresolved", "recoveryRetryExhausted"),
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
    local_status = stages.get("finalLocalAgentStatus") or {}
    if "finalLocalAgentStatus" in stages and local_status.get("ok") is not True:
        unhealthy = [
            worker
            for worker in (local_status.get("workers") or [])
            if isinstance(worker, dict) and worker.get("ok") is not True
        ]
        blockers.append(
            {
                "stage": "finalLocalAgentStatus",
                "queue": ("disk_stop" if _local_agent_disk_stop(local_status) else "unhealthy"),
                "count": max(1, len(unhealthy)),
            }
        )
    workflow_health = stages.get("finalWorkflowHealth") or {}
    if "finalWorkflowHealth" in stages and workflow_health.get("operationalHealthy") is not True:
        blockers.append(
            {
                "stage": "finalWorkflowHealth",
                "queue": "unhealthy",
                "count": 1,
            }
        )
    event_lane_health = stages.get("finalEventLaneHealth") or {}
    if "finalEventLaneHealth" in stages and event_lane_health.get("healthy") is not True:
        unhealthy_lanes = [
            lane
            for lane in (event_lane_health.get("lanes") or {}).values()
            if isinstance(lane, dict) and lane.get("healthy") is not True
        ]
        blockers.append(
            {
                "stage": "finalEventLaneHealth",
                "queue": "unhealthy",
                "count": max(1, len(unhealthy_lanes)),
            }
        )
    event_lane_ensure = stages.get("eventLaneEnsure") or {}
    if "eventLaneEnsure" in stages and event_lane_ensure.get("ok") is not True:
        blockers.append(
            {
                "stage": "eventLaneEnsure",
                "queue": "reconcile_failed",
                "count": 1,
            }
        )
    return blockers


def _compact_summary(stages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    drain = stages.get("drain") or {}
    queue = stages.get("finalQueue") or {}
    quality = stages.get("quality") or {}
    health = stages.get("finalWorkflowHealth") or stages.get("workflowHealth") or {}
    decision_sessions = stages.get("codexDecisionSessions") or {}
    result_ingestion = stages.get("resultIngestion") or {}
    post_review_ingestion = stages.get("resultIngestionAfterReview") or {}
    local_status = stages.get("finalLocalAgentStatus") or {}
    return {
        "localAgentHealthy": (stages.get("finalLocalAgentStatus") or {}).get("ok") is True,
        "localWorkerStates": _compact_local_worker_states(local_status),
        "eventLanesHealthy": (stages.get("finalEventLaneHealth") or {}).get("healthy") is True,
        "operationalHealthy": health.get("operationalHealthy") is True,
        "githubNaturalScheduleHealthy": health.get("githubNaturalScheduleHealthy") is True,
        "drainAction": drain.get("action"),
        "drainKey": drain.get("key"),
        "decisionSessionsCreated": len(decision_sessions.get("created") or []),
        "decisionSessionsExisting": len(decision_sessions.get("existing") or []),
        "workBlockedCount": len(result_ingestion.get("workBlocked") or [])
        + len(post_review_ingestion.get("workBlocked") or []),
        "pendingCount": len(queue.get("pending") or []),
        "submitReadyRate": quality.get("submitReadyRate"),
        "filterMissRate": quality.get("filterMissRate"),
        "hardGateEscapes": quality.get("hardGateEscapes"),
    }


def _compact_local_worker_states(status: dict[str, Any]) -> list[dict[str, Any]]:
    """Expose final worker freshness evidence in the heartbeat JSON."""

    states: list[dict[str, Any]] = []
    for worker in status.get("workers") or []:
        if not isinstance(worker, dict):
            continue
        runtime = worker.get("workerRuntimeHealth")
        runtime = runtime if isinstance(runtime, dict) else {}
        process = worker.get("process")
        process = process if isinstance(process, dict) else {}
        states.append(
            {
                "label": str(worker.get("label") or ""),
                "ok": worker.get("ok") is True,
                "runtimeHealthy": runtime.get("healthy") is True,
                "inFlight": runtime.get("inFlight") is True,
                "workerPidAlive": runtime.get("workerPidAlive"),
                "processAlive": process.get("alive"),
                "lastSuccessAt": runtime.get("lastSuccessAt")
                or runtime.get("queueImportSuccessAt"),
                "lastExitCode": runtime.get("lastExitCode")
                if runtime.get("lastExitCode") is not None
                else runtime.get("queueLastExitCode"),
            }
        )
    return states


def run_locked_controller_cycle(
    root: Path,
    *,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
    runner: Runner = run_json_command,
    notify: bool = True,
    project_id: str = DEFAULT_PROJECT_ID,
    wait_existing: bool = False,
    busy_timeout_seconds: float | None = None,
    report_on_complete: bool = False,
) -> dict[str, Any]:
    if wait_existing and not report_on_complete:
        raise ValueError("joining a controller cycle requires durable reporting")
    root = root.resolve()
    lock_path = root / "state" / "controller-cycle.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        joined_existing = False
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if not wait_existing:
                return {
                    "ok": True,
                    "busy": True,
                    "summary": {"action": "controller_already_running"},
                }
            deadline = (
                None if busy_timeout_seconds is None else time.monotonic() + busy_timeout_seconds
            )
            while True:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if deadline is not None and time.monotonic() >= deadline:
                        return {
                            "ok": False,
                            "summary": {"action": "controller_existing_run_timeout"},
                            "failures": [
                                {
                                    "stage": "controllerLock",
                                    "error": "existing controller run did not finish",
                                }
                            ],
                            "finalBlockers": [
                                {"stage": "controllerLock", "queue": "timeout", "count": 1}
                            ],
                        }
                    time.sleep(0.25)
            joined_existing = True
        # Resolve the active release only after acquiring the shared lock. A
        # stable automation command uses ``current-release``; this pins the
        # cycle to one immutable release and prevents an old fixed-release
        # invocation from reusing a completion marker from another release.
        binding = None
        binding_error: Exception | None = None
        try:
            binding = bind_runtime(
                root,
                code_root=code_root,
                allow_unreleased_code=allow_unreleased_code,
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            binding_error = exc
            if not report_on_complete:
                raise
        bound_code_root = binding.code_root if binding is not None else code_root
        command_digest = _controller_command_digest(
            code_root=bound_code_root,
            allow_unreleased_code=allow_unreleased_code,
            notify=notify,
            project_id=project_id,
        )
        # A failed release preflight must not reuse an old marker. Continue to
        # the durable failure-reporting path below instead.
        can_reuse_marker = binding_error is None
        if joined_existing and not can_reuse_marker:
            # The waiter joined an existing process but the caller's release
            # path is stale/invalid. Do not return that process's result.
            pass
        elif joined_existing:
            completed_marker = _read_controller_lock_marker(lock)
            existing = _completed_controller_result(
                root,
                completed_marker,
                command_digest=command_digest,
                max_age_seconds=None,
            )
            if existing is None:
                recovered = _recover_finished_running_marker(
                    root,
                    completed_marker,
                    command_digest=command_digest,
                )
                if recovered is not None:
                    existing, repaired_marker = recovered
                    _write_controller_lock_marker(lock, repaired_marker)
            if existing is None:
                return {
                    "ok": False,
                    "summary": {"action": "controller_existing_result_missing"},
                    "failures": [
                        {"stage": "controllerLock", "error": "existing controller result missing"}
                    ],
                    "finalBlockers": [
                        {"stage": "controllerLock", "queue": "result_missing", "count": 1}
                    ],
                }
            return existing
        if wait_existing:
            if can_reuse_marker:
                previous_marker = _read_controller_lock_marker(lock)
                previous = _completed_controller_result(
                    root,
                    previous_marker,
                    command_digest=command_digest,
                    max_age_seconds=CONTROLLER_COMPLETED_REUSE_SECONDS,
                )
                if previous is not None:
                    return previous
                recovered = _recover_finished_running_marker(
                    root,
                    previous_marker,
                    command_digest=command_digest,
                )
                if recovered is not None:
                    result, completed_marker = recovered
                    _write_controller_lock_marker(lock, completed_marker)
                    return result
        started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        run_id = secrets.token_hex(16)
        if report_on_complete:
            _write_controller_lock_marker(
                lock,
                {
                    "schema": CONTROLLER_LOCK_MARKER_SCHEMA,
                    "state": "RUNNING",
                    "runId": run_id,
                    "commandDigest": command_digest,
                    "startedAt": started_at,
                },
            )
        if binding_error is not None:
            result = {
                "ok": False,
                "checkedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "blocked": "release binding required",
                "error": str(binding_error)[:400],
            }
        else:
            try:
                result = controller_cycle(
                    root,
                    code_root=bound_code_root,
                    allow_unreleased_code=allow_unreleased_code,
                    runner=runner,
                    notify=notify,
                    project_id=project_id,
                )
            except RuntimeError as exc:
                if not report_on_complete:
                    raise
                error = str(exc)[:400]
                blocked = (
                    "operational authorization required"
                    if "operational authorization" in error.lower()
                    else "controller startup failed"
                )
                result = {
                    "ok": False,
                    "checkedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "blocked": blocked,
                    "error": error,
                }
        if report_on_complete:
            result = {**result, "controllerRunId": run_id}
            report_path = write_controller_report(root, result)
            completed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            _write_controller_lock_marker(
                lock,
                {
                    "schema": CONTROLLER_LOCK_MARKER_SCHEMA,
                    "state": "COMPLETED",
                    "runId": run_id,
                    "commandDigest": command_digest,
                    "startedAt": started_at,
                    "completedAt": completed_at,
                    "reportCheckedAt": result.get("checkedAt"),
                    "reportSha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                },
            )
        return result


def _controller_command_digest(
    *,
    code_root: Path | None,
    allow_unreleased_code: bool,
    notify: bool,
    project_id: str,
) -> str:
    payload = {
        "codeRoot": str(code_root.resolve()) if code_root is not None else None,
        "allowUnreleasedCode": allow_unreleased_code,
        "notify": notify,
        "projectId": project_id,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _read_controller_lock_marker(lock) -> dict[str, Any] | None:
    lock.seek(0)
    try:
        value = json.loads(lock.read())
    except (json.JSONDecodeError, OSError):
        return None
    return value if isinstance(value, dict) else None


def _write_controller_lock_marker(lock, marker: dict[str, Any]) -> None:
    lock.seek(0)
    lock.truncate()
    lock.write(json.dumps(marker, sort_keys=True, separators=(",", ":")))
    lock.flush()
    os.fsync(lock.fileno())


def _completed_controller_result(
    root: Path,
    marker: object,
    *,
    command_digest: str,
    max_age_seconds: float | None,
) -> dict[str, Any] | None:
    if (
        not isinstance(marker, dict)
        or marker.get("schema") != CONTROLLER_LOCK_MARKER_SCHEMA
        or marker.get("state") != "COMPLETED"
        or marker.get("commandDigest") != command_digest
        or not isinstance(marker.get("runId"), str)
    ):
        return None
    try:
        started_at = _controller_timestamp(marker["startedAt"])
        completed_at = _controller_timestamp(marker["completedAt"])
        if completed_at < started_at:
            return None
        if max_age_seconds is not None:
            age = (datetime.now(UTC) - completed_at).total_seconds()
            if age < 0 or age > max_age_seconds:
                return None
        report_path = root.resolve() / "reports" / "latest_controller_cycle.json"
        raw = report_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != marker.get("reportSha256"):
            return None
        result = json.loads(raw)
        checked_at = _controller_timestamp(result["checkedAt"])
        if (
            result.get("controllerRunId") != marker.get("runId")
            or result.get("checkedAt") != marker.get("reportCheckedAt")
            or checked_at < started_at
            or checked_at > completed_at
        ):
            return None
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def _recover_finished_running_marker(
    root: Path,
    marker: object,
    *,
    command_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if (
        not isinstance(marker, dict)
        or marker.get("schema") != CONTROLLER_LOCK_MARKER_SCHEMA
        or marker.get("state") != "RUNNING"
        or marker.get("commandDigest") != command_digest
        or not isinstance(marker.get("runId"), str)
    ):
        return None
    try:
        started_at = _controller_timestamp(marker["startedAt"])
        report_path = root.resolve() / "reports" / "latest_controller_cycle.json"
        raw = report_path.read_bytes()
        result = json.loads(raw)
        checked_at = _controller_timestamp(result["checkedAt"])
        age = (datetime.now(UTC) - checked_at).total_seconds()
        if (
            result.get("controllerRunId") != marker.get("runId")
            or checked_at < started_at
            or age < 0
            or age > CONTROLLER_ABANDONED_RECOVERY_SECONDS
        ):
            return None
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    completed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    completed_marker = {
        **marker,
        "state": "COMPLETED",
        "completedAt": completed_at,
        "reportCheckedAt": result["checkedAt"],
        "reportSha256": hashlib.sha256(raw).hexdigest(),
    }
    return result, completed_marker


def _controller_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("controller timestamp is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("controller timestamp has no timezone")
    return parsed.astimezone(UTC)


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
    final_recovery = stages.get("finalRecovery") or {}
    local_status = stages.get("finalLocalAgentStatus") or {}
    local_warning_codes = {
        str(code)
        for worker in (local_status.get("workers") or [])
        if isinstance(worker, dict)
        for health_key in ("runtimeHealth", "workerRuntimeHealth")
        for code in (
            ((worker.get(health_key) or {}).get("warnings") or [])
            if isinstance(worker.get(health_key), dict)
            else []
        )
    }
    local_disk_stop = _local_agent_disk_stop(local_status)
    desktop_handoff = _pending_desktop_handoff(stages)
    summary = dict(result.get("summary") or {})
    if "finalLocalAgentStatus" in stages:
        # The final status stage is authoritative; do not preserve an optimistic
        # caller-supplied summary when the worker snapshot says otherwise.
        summary["localAgentHealthy"] = local_status.get("ok") is True
        summary["localWorkerStates"] = _compact_local_worker_states(local_status)
    else:
        summary.setdefault("localAgentHealthy", local_status.get("ok") is True)
        summary.setdefault("localWorkerStates", _compact_local_worker_states(local_status))
    compact = {
        "ok": result.get("ok"),
        "checkedAt": result.get("checkedAt"),
        "summary": summary,
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
            "parkedRecovery": len(final_recovery.get("parkedRecovery") or []),
            "diskThresholdWarning": int("DISK_WARNING_THRESHOLD" in local_warning_codes),
            "diskThresholdStop": int(local_disk_stop),
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
