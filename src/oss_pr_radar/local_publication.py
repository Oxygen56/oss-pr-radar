"""Fast local collection and publication for completed Radar tasks."""

from __future__ import annotations

import argparse
import errno
import json
import os
import plistlib
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from .operational_auth import require_operational_authorization
from .release_binding import bind_runtime, runtime_ledger_path, runtime_python
from .runtime import (
    RuntimeLockBusy,
    append_operation,
    disk_snapshot,
    exclusive_lock,
    read_json,
    record_cycle,
    rotate_log,
    utc_now,
    write_json,
)
from .runtime_audit import active_release_evidence

LAUNCH_AGENT_LABEL = "com.oss-pr-radar.local-publication"
SLOW_WORKER_LABEL = "com.oss-pr-radar.local-publication-slow"
SERVICE_PATH = (
    "/Applications/ChatGPT.app/Contents/Resources:"
    "/Applications/Codex.app/Contents/Resources:"
    "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:"
    "/usr/sbin:/sbin:/Library/Apple/usr/bin"
)
SENSITIVE_ENVIRONMENT_KEYS = {
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "FEISHU_APP_ID",
    "FEISHU_APP_SECRET",
    "MODEL_API_KEY",
    "OPENAI_API_KEY",
}
QUEUE_SYNC_STATE = "local_queue_sync.json"
FAST_WORK_LOCK = "fast-worker.lock"
SLOW_WORK_LOCK = "slow-worker.lock"
SLOW_REQUEST_STATE = "slow-work-request.json"
SLOW_BACKOFF_STATE = "slow-worker-backoff.json"
MAX_FAST_OPERATION_SECONDS = 15


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)


def run_bridge(
    root: Path,
    operation: str,
    *,
    timeout: int = 900,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
) -> dict[str, Any]:
    binding = bind_runtime(
        root,
        code_root=code_root,
        allow_unreleased_code=allow_unreleased_code,
    )
    argv = [
        str(runtime_python(root)),
        str(binding.script("scripts/local_dispatch_bridge.py")),
        "--runtime-root",
        str(root.resolve()),
        "--ledger",
        str(runtime_ledger_path(root)),
        operation,
    ]
    process = subprocess.Popen(
        argv,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(
            argv,
            timeout,
            output=stdout,
            stderr=stderr,
        ) from exc
    completed = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    if completed.returncode != 0:
        detail = completed.stderr or completed.stdout or "local bridge failed"
        raise RuntimeError(f"{operation}: {detail[:800]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{operation}: local bridge returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{operation}: local bridge returned a non-object")
    return value


def retryable_delivery_pending(root: Path, *, min_age_seconds: int = 60) -> bool:
    """Detect a durable no-turn receipt that is old enough to re-arm."""

    receipt_root = root / "state" / "task_turn_receipts"
    now = time.time()
    for path in receipt_root.glob("*.json"):
        if path.name.endswith(".launch.json"):
            continue
        try:
            if now - path.stat().st_mtime < min_age_seconds:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if value.get("ok") is False and value.get("turnStarted") is False:
            return True
        if value.get("turnStatus") in {"failed", "interrupted"}:
            return True
    return False


def _queue_sync_state_path(root: Path) -> Path:
    return root / "state" / QUEUE_SYNC_STATE


def _write_queue_sync_state(root: Path, value: dict[str, Any]) -> None:
    path = _queue_sync_state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def sync_cloud_queue_if_due(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]],
    interval_seconds: int | None,
    now: float | None = None,
) -> dict[str, Any]:
    """Import signed cloud work without depending on a Codex heartbeat turn."""

    if interval_seconds is None or interval_seconds <= 0:
        return {"ok": True, "attempted": False, "pending": [], "errors": []}
    current = time.time() if now is None else now
    state_path = _queue_sync_state_path(root)
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        state = {}
    last_attempt = float(state.get("attemptedAtEpoch") or 0)
    if current - last_attempt < max(60, int(interval_seconds)):
        return {"ok": True, "attempted": False, "pending": [], "errors": []}

    # Record before network I/O so a crash cannot create a 20-second retry storm.
    _write_queue_sync_state(
        root,
        {
            "attemptedAtEpoch": current,
            "completedAtEpoch": None,
            "ok": None,
        },
    )
    errors: list[dict[str, str]] = []
    try:
        sync = runner(root, "sync")
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        sync = {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}
    if sync.get("ok") is False:
        errors.append(
            {"error": str(sync.get("error") or sync.get("errors") or "queue sync failed")[:400]}
        )

    listing: dict[str, Any] = {"ok": True, "pending": []}
    if not errors:
        try:
            listing = runner(root, "list")
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            listing = {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}
        if listing.get("ok") is False:
            errors.append(
                {
                    "error": str(
                        listing.get("error") or listing.get("errors") or "queue list failed"
                    )[:400]
                }
            )

    result = {
        "ok": not errors,
        "attempted": True,
        "verified": int(sync.get("verified") or 0),
        "inserted": int(sync.get("inserted") or 0),
        "superseded": int(sync.get("superseded") or 0),
        "pending": list(listing.get("pending") or []),
        "errors": errors,
    }
    _write_queue_sync_state(
        root,
        {
            "attemptedAtEpoch": current,
            "completedAtEpoch": time.time() if now is None else now,
            "ok": result["ok"],
            "verified": result["verified"],
            "inserted": result["inserted"],
            "pendingCount": len(result["pending"]),
            "errors": errors[:5],
        },
    )
    return result


def _enqueue_slow_work(root: Path, *, reason: str) -> None:
    path = root / "state" / SLOW_REQUEST_STATE
    previous = read_json(path, {})
    previous = previous if isinstance(previous, dict) else {}
    reasons = list(previous.get("reasons") or [])
    if reason not in reasons:
        reasons.append(reason)
    write_json(
        path,
        {
            "schemaVersion": "slow_work_request_v1",
            "requestedAt": utc_now(),
            "reasons": reasons[-20:],
        },
    )


def fast_bridge(
    root: Path,
    operation: str,
    *,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
) -> dict[str, Any]:
    """Run only the local ingest operations permitted in the rapid cycle."""

    if operation != "local-receipt-enqueue":
        raise RuntimeError(f"fast cycle rejected non-local operation: {operation}")
    return run_bridge(
        root,
        operation,
        timeout=MAX_FAST_OPERATION_SECONDS,
        code_root=code_root,
        allow_unreleased_code=allow_unreleased_code,
    )


def queue_bridge(
    root: Path,
    operation: str,
    *,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
) -> dict[str, Any]:
    if operation != "queue-import":
        raise RuntimeError(f"queue importer rejected operation: {operation}")
    return run_bridge(
        root,
        operation,
        timeout=300,
        code_root=code_root,
        allow_unreleased_code=allow_unreleased_code,
    )


def fast_advance_once(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]] = fast_bridge,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
) -> dict[str, Any]:
    """Ingest local receipts and enqueue slow work without network side effects."""

    root = root.resolve()
    if runner is fast_bridge and (code_root is not None or allow_unreleased_code):
        runner = lambda current_root, operation: fast_bridge(  # noqa: E731
            current_root,
            operation,
            code_root=code_root,
            allow_unreleased_code=allow_unreleased_code,
        )
    started = time.time()
    try:
        with exclusive_lock(root / "state" / FAST_WORK_LOCK):
            disk = disk_snapshot(root)
            if disk["level"] == "stop":
                record_cycle(
                    root,
                    worker="fast",
                    ok=False,
                    exit_code=78,
                    started_at=started,
                    error_code="DISK_STOP_THRESHOLD",
                    disk=disk,
                )
                return {
                    "ok": False,
                    "activity": False,
                    "errors": [{"error": "DISK_STOP_THRESHOLD"}],
                    "slowWorkQueued": False,
                }
            ingestion = runner(root, "local-receipt-enqueue")
            errors = list(ingestion.get("errors") or []) + list(ingestion.get("rejected") or [])
            _enqueue_slow_work(root, reason="local_ingest")
            result = {
                "ok": not errors
                and ingestion.get("ok") is not False,
                "activity": bool(ingestion.get("queued") or errors),
                "receiptsQueued": list(ingestion.get("queued") or []),
                "errors": errors,
                "slowWorkQueued": True,
            }
            record_cycle(
                root,
                worker="fast",
                ok=bool(result["ok"]),
                exit_code=0 if result["ok"] else 1,
                started_at=started,
                error_code="LOCAL_INGEST_FAILED" if not result["ok"] else None,
                disk=disk,
            )
            return result
    except RuntimeLockBusy:
        return {"ok": True, "busy": True, "activity": False, "errors": []}
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        record_cycle(
            root,
            worker="fast",
            ok=False,
            exit_code=1,
            started_at=started,
            error_code=type(exc).__name__,
        )
        return {
            "ok": False,
            "activity": True,
            "errors": [{"error": f"{type(exc).__name__}:{str(exc)[:400]}"}],
            "slowWorkQueued": False,
        }


def queue_import_once(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]] = queue_bridge,
) -> dict[str, Any]:
    """Run the independent five-minute signed queue importer."""

    root = root.resolve()
    started = time.time()
    try:
        with exclusive_lock(root / "state" / "queue-import.lock"):
            disk = disk_snapshot(root)
            if disk["level"] == "stop":
                result = {"ok": False, "error": "DISK_STOP_THRESHOLD"}
            else:
                result = runner(root, "queue-import")
            if result.get("ok"):
                write_json(
                    root / "state" / "queue-import-state.json",
                    {
                        "schemaVersion": "queue_import_v1",
                        "lastAttemptAt": utc_now(),
                        "lastSuccessAt": utc_now(),
                        "ok": True,
                        "verified": int(result.get("verified") or 0),
                        "inserted": int(result.get("inserted") or 0),
                    },
                )
            record_cycle(
                root,
                worker="queue-importer",
                ok=bool(result.get("ok")),
                exit_code=0 if result.get("ok") else 1,
                started_at=started,
                error_code=None if result.get("ok") else str(result.get("error") or "QUEUE_IMPORT_FAILED"),
                success_field="queueImportSuccessAt",
                exit_field="queueLastExitCode",
                failure_field="queueConsecutiveFailures",
                disk=disk,
            )
            return result
    except RuntimeLockBusy:
        return {"ok": True, "busy": True, "errors": []}
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        record_cycle(
            root,
            worker="queue-importer",
            ok=False,
            exit_code=1,
            started_at=started,
            error_code=type(exc).__name__,
            success_field="queueImportSuccessAt",
            exit_field="queueLastExitCode",
            failure_field="queueConsecutiveFailures",
        )
        return {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}


def slow_advance_once(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]] = run_bridge,
) -> dict[str, Any]:
    """Run the single durable slow worker with persisted exponential backoff."""

    root = root.resolve()
    backoff_path = root / "state" / SLOW_BACKOFF_STATE
    started = time.time()
    try:
        with exclusive_lock(root / "state" / SLOW_WORK_LOCK):
            now = time.time()
            backoff = read_json(backoff_path, {})
            backoff = backoff if isinstance(backoff, dict) else {}
            retry_at = float(backoff.get("retryAfter") or backoff.get("nextAttemptAt") or 0)
            if backoff.get("inFlight") and now < retry_at:
                return {
                    "ok": True,
                    "deferred": True,
                    "reason": "PERSISTED_INFLIGHT_BACKOFF",
                    "retryAt": retry_at,
                }
            if now < float(backoff.get("nextAttemptAt") or 0):
                return {
                    "ok": True,
                    "deferred": True,
                    "reason": "PERSISTED_BACKOFF",
                    "retryAt": float(backoff["nextAttemptAt"]),
                }
            disk = disk_snapshot(root)
            failures = int(backoff.get("failureCount") or 0)
            delay = min(3600, 60 * (2**min(failures, 5)))
            retry_after = now + delay
            operation_id = f"{os.getpid()}-{time.time_ns()}"
            write_json(
                backoff_path,
                {
                    "schemaVersion": "slow_backoff_v1",
                    "failureCount": failures,
                    "backoffSeconds": delay,
                    "nextAttemptAt": retry_after,
                    "retryAfter": retry_after,
                    "attemptStartedAt": utc_now(),
                    "inFlight": True,
                    "operationId": operation_id,
                },
            )
            append_operation(
                root,
                {
                    "operationId": operation_id,
                    "worker": "slow",
                    "operation": "slow-cycle",
                    "status": "started",
                    "retryAfter": retry_after,
                    "inFlight": True,
                },
            )
            try:
                if disk["level"] == "stop":
                    result = {"ok": False, "errors": [{"error": "DISK_STOP_THRESHOLD"}]}
                else:
                    reproduction = runner(root, "reproduction-probe")
                    result = advance_once(root, runner=runner, queue_sync_interval_seconds=None)
                    result["reproductionProbe"] = reproduction
            except BaseException as exc:
                failure_retry = time.time() + delay
                error_code = (
                    errno.errorcode.get(exc.errno, type(exc).__name__)
                    if isinstance(exc, OSError)
                    else type(exc).__name__
                )
                write_json(
                    backoff_path,
                    {
                        "schemaVersion": "slow_backoff_v1",
                        "failureCount": failures + 1,
                        "backoffSeconds": delay,
                        "nextAttemptAt": failure_retry,
                        "retryAfter": failure_retry,
                        "attemptStartedAt": backoff.get("attemptStartedAt"),
                        "lastAttemptAt": utc_now(),
                        "inFlight": False,
                        "lastError": f"{error_code}:{str(exc)[:240]}",
                        "operationId": operation_id,
                    },
                )
                append_operation(
                    root,
                    {
                        "operationId": operation_id,
                        "worker": "slow",
                        "operation": "slow-cycle",
                        "status": "failure",
                        "errorCode": error_code,
                        "retryAfter": failure_retry,
                        "inFlight": False,
                    },
                )
                record_cycle(
                    root,
                    worker="slow",
                    ok=False,
                    exit_code=130 if isinstance(exc, KeyboardInterrupt) else 1,
                    started_at=started,
                    error_code=error_code,
                    disk=disk,
                )
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                return {"ok": False, "errors": [{"error": str(exc)[:400]}]}
            ok = bool(result.get("ok"))
            completed_retry = time.time() if ok else time.time() + delay
            write_json(
                backoff_path,
                {
                    "schemaVersion": "slow_backoff_v1",
                    "failureCount": 0 if ok else failures + 1,
                    "backoffSeconds": 0 if ok else delay,
                    "nextAttemptAt": completed_retry,
                    "retryAfter": completed_retry,
                    "attemptStartedAt": backoff.get("attemptStartedAt"),
                    "lastAttemptAt": utc_now(),
                    "inFlight": False,
                    "operationId": backoff.get("operationId"),
                },
            )
            record_cycle(
                root,
                worker="slow",
                ok=ok,
                exit_code=0 if ok else 1,
                started_at=started,
                error_code=None if ok else "SLOW_WORKER_FAILED",
                disk=disk,
            )
            append_operation(
                root,
                {
                    "worker": "slow",
                    "operation": "slow-cycle",
                    "status": "success" if ok else "failure",
                    "exitCode": 0 if ok else 1,
                    "retryAfter": completed_retry,
                    "inFlight": False,
                    "operationId": backoff.get("operationId"),
                },
            )
            return result
    except RuntimeLockBusy:
        return {"ok": True, "busy": True, "errors": []}


def advance_once(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]] = run_bridge,
    queue_sync_interval_seconds: int | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    recovery = runner(root, "context-recover")
    recovery_errors = list(recovery.get("errors") or [])
    recovery_unavailable = list(recovery.get("unavailable") or [])
    public_unavailable = recovery_unavailable[:5]
    if recovery.get("ok") is False or recovery_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": [],
            "publicationRequests": [],
            "validationDeferred": [],
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": recovery_errors
            or [{"error": "task context recovery failed before result ingestion"}],
        }
    ingestion = runner(root, "ingest-results")
    ingestion_errors = list(ingestion.get("errors") or [])
    if ingestion.get("ok") is False or ingestion_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": list(ingestion.get("ingested") or []),
            "publicationRequests": list(ingestion.get("publicationRequests") or []),
            "validationDeferred": list(ingestion.get("validationDeferred") or []),
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": ingestion_errors
            or [{"error": "task result ingestion failed before publication"}],
        }
    independent_review = runner(root, "independent-review-run")
    review_errors = list(independent_review.get("errors") or [])
    review_updated = bool(independent_review.get("updated"))
    if (independent_review.get("ok") is False or review_errors) and not review_updated:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": list(ingestion.get("ingested") or []),
            "publicationRequests": list(ingestion.get("publicationRequests") or []),
            "validationDeferred": list(ingestion.get("validationDeferred") or []),
            "independentReview": independent_review,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": review_errors or [{"error": "independent review failed before publication"}],
        }
    post_review_ingestion = (
        runner(root, "ingest-results")
        if review_updated
        else {"ok": True, "ingested": [], "publicationRequests": [], "validationDeferred": []}
    )
    post_review_errors = list(post_review_ingestion.get("errors") or [])
    if post_review_ingestion.get("ok") is False or post_review_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": [
                *list(ingestion.get("ingested") or []),
                *list(post_review_ingestion.get("ingested") or []),
            ],
            "publicationRequests": [
                *list(ingestion.get("publicationRequests") or []),
                *list(post_review_ingestion.get("publicationRequests") or []),
            ],
            "validationDeferred": [
                *list(ingestion.get("validationDeferred") or []),
                *list(post_review_ingestion.get("validationDeferred") or []),
            ],
            "independentReview": independent_review,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": post_review_errors
            or [{"error": "task result ingestion failed after independent review"}],
        }
    ingested = [
        *list(ingestion.get("ingested") or []),
        *list(post_review_ingestion.get("ingested") or []),
    ]
    title_reconciliation = runner(root, "title-reconcile")
    cleanup_reconciliation = runner(root, "cleanup-reconcile")
    publication = runner(root, "publication-run")
    published = list(publication.get("published") or [])
    context_sync = (
        runner(root, "context-sync") if published else {"ok": True, "written": [], "errors": []}
    )
    queue_sync = sync_cloud_queue_if_due(
        root,
        runner=runner,
        interval_seconds=queue_sync_interval_seconds,
    )
    publication_feedback = runner(root, "publication-feedback-list")

    errors = [
        *review_errors,
        *list(title_reconciliation.get("errors") or []),
        *list(cleanup_reconciliation.get("errors") or []),
        *list(publication.get("errors") or []),
        *list(context_sync.get("errors") or []),
    ]
    requests = [
        *list(ingestion.get("publicationRequests") or []),
        *list(post_review_ingestion.get("publicationRequests") or []),
    ]
    validation_deferred = [
        *list(ingestion.get("validationDeferred") or []),
        *list(post_review_ingestion.get("validationDeferred") or []),
    ]
    blocked = list(publication.get("blocked") or [])
    pending = list(publication.get("pending") or [])
    renamed = list(title_reconciliation.get("renamed") or [])
    archived = list(cleanup_reconciliation.get("archived") or [])
    drain = {"ok": True, "action": "not_triggered"}
    terminal_feedback = {"ok": True, "published": 0, "errors": []}
    lifecycle_healthy = bool(
        not errors
        and title_reconciliation.get("ok") is not False
        and cleanup_reconciliation.get("ok") is not False
        and publication.get("ok") is not False
        and context_sync.get("ok") is not False
        and publication_feedback.get("ok") is not False
    )
    recovery = (
        runner(root, "recovery-list") if lifecycle_healthy else {"ok": False, "recoverable": []}
    )
    recoverable = list(recovery.get("recoverable") or []) if recovery.get("ok") else []
    should_drain = bool(
        ingested
        or validation_deferred
        or archived
        or published
        or publication_feedback.get("candidates")
        or publication_feedback.get("unresolved")
        or recoverable
        or retryable_delivery_pending(root)
        or queue_sync.get("pending")
    )
    if should_drain and lifecycle_healthy:
        drain = runner(root, "drain-once")
        errors.extend(list(drain.get("errors") or []))
        if drain.get("terminalized"):
            terminal_feedback = runner(root, "publish-terminal-feedback")
            errors.extend(list(terminal_feedback.get("errors") or []))
    drain_activity = bool(
        drain.get("action")
        and drain.get("action") not in {"none", "not_triggered", "drain_already_running"}
    )
    activity = bool(
        ingested
        or requests
        or renamed
        or archived
        or published
        or publication_feedback.get("reconciled")
        or blocked
        or errors
        or drain_activity
        or queue_sync.get("inserted")
        or queue_sync.get("superseded")
        or queue_sync.get("errors")
    )
    errors.extend(list(queue_sync.get("errors") or []))
    return {
        "ok": not errors
        and title_reconciliation.get("ok") is not False
        and cleanup_reconciliation.get("ok") is not False
        and publication.get("ok") is not False
        and context_sync.get("ok") is not False
        and publication_feedback.get("ok") is not False
        and drain.get("ok") is not False
        and terminal_feedback.get("ok") is not False,
        "activity": activity,
        "resultsIngested": ingested,
        "publicationRequests": requests,
        "validationDeferred": validation_deferred,
        "independentReview": independent_review,
        "titlesRenamed": renamed,
        "threadsArchived": archived,
        "published": published,
        "contextsSynced": list(context_sync.get("written") or []),
        "publicationFeedback": publication_feedback,
        "queueSync": queue_sync,
        "recoverable": recoverable,
        "drain": drain,
        "terminalFeedback": terminal_feedback,
        "pending": pending,
        "blocked": blocked,
        "contextsUnavailable": public_unavailable,
        "contextsUnavailableCount": len(recovery_unavailable),
        "errors": errors,
    }


def compact_advance_result(result: dict[str, Any]) -> dict[str, Any]:
    """Keep the LaunchAgent log useful without repeating full controller state."""

    review = result.get("independentReview")
    review = review if isinstance(review, dict) else {}
    drain = result.get("drain")
    drain = drain if isinstance(drain, dict) else {}
    queue_sync = result.get("queueSync")
    queue_sync = queue_sync if isinstance(queue_sync, dict) else {}
    return {
        "ok": result.get("ok"),
        "activity": result.get("activity"),
        "counts": {
            "resultsIngested": len(result.get("resultsIngested") or []),
            "publicationRequests": len(result.get("publicationRequests") or []),
            "validationDeferred": len(result.get("validationDeferred") or []),
            "reviewsUpdated": len(review.get("updated") or []),
            "titlesRenamed": len(result.get("titlesRenamed") or []),
            "threadsArchived": len(result.get("threadsArchived") or []),
            "published": len(result.get("published") or []),
            "publicationFeedbackPending": len(
                (result.get("publicationFeedback") or {}).get("candidates") or []
            ),
            "publicationFeedbackReconciled": len(
                (result.get("publicationFeedback") or {}).get("reconciled") or []
            ),
            "publicationBlocked": len(result.get("blocked") or []),
            "errors": len(result.get("errors") or []),
        },
        "reviewBusy": bool(review.get("busy")),
        "drain": {
            "ok": drain.get("ok"),
            "action": drain.get("action"),
            "key": drain.get("key"),
        },
        "queueSync": {
            "attempted": bool(queue_sync.get("attempted")),
            "verified": int(queue_sync.get("verified") or 0),
            "inserted": int(queue_sync.get("inserted") or 0),
            "pending": len(queue_sync.get("pending") or []),
        },
        "contextsUnavailableCount": int(result.get("contextsUnavailableCount") or 0),
        "errors": list(result.get("errors") or [])[:5],
    }


def launch_agent_spec(
    root: Path,
    *,
    interval_seconds: int,
    home: Path,
    queue_sync_interval_seconds: int = 300,
    runtime_root: Path | None = None,
) -> dict[str, Any]:
    code_root = root.resolve()
    runtime_root = (runtime_root or root).resolve()
    interval = max(15, min(int(interval_seconds), 300))
    log_dir = home / "Library" / "Logs" / "oss-pr-radar"
    return {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [
            "/usr/bin/env",
            "-i",
            f"HOME={home}",
            f"USER={home.name}",
            f"LOGNAME={home.name}",
            "LANG=en_US.UTF-8",
            f"PATH={SERVICE_PATH}",
            str(runtime_python(runtime_root)),
            str(code_root / "scripts" / "local_publication_agent.py"),
            "--root",
            str(runtime_root),
            "--mode",
            "fast",
        ],
        "WorkingDirectory": str(runtime_root),
        "RunAtLoad": True,
        "StartInterval": interval,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "StandardOutPath": str(log_dir / "publication-agent.log"),
        "StandardErrorPath": str(log_dir / "publication-agent.error.log"),
    }


def _worker_spec(
    code_root: Path,
    *,
    label: str,
    script: str,
    interval_seconds: int,
    home: Path,
    runtime_root: Path | None = None,
) -> dict[str, Any]:
    code_root = code_root.resolve()
    runtime_root = (runtime_root or code_root).resolve()
    log_dir = home / "Library" / "Logs" / "oss-pr-radar"
    return {
        "Label": label,
        "ProgramArguments": [
            "/usr/bin/env",
            "-i",
            f"HOME={home}",
            f"USER={home.name}",
            f"LOGNAME={home.name}",
            "LANG=en_US.UTF-8",
            f"PATH={SERVICE_PATH}",
            str(runtime_python(runtime_root)),
            str(code_root / "scripts" / script),
            "--root",
            str(runtime_root),
        ],
        "WorkingDirectory": str(runtime_root),
        "RunAtLoad": True,
        "StartInterval": max(60, int(interval_seconds)),
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "StandardOutPath": str(log_dir / f"{label.rsplit('.', 1)[-1]}.log"),
        "StandardErrorPath": str(log_dir / f"{label.rsplit('.', 1)[-1]}.error.log"),
    }


def slow_launch_agent_spec(
    root: Path,
    *,
    home: Path,
    interval_seconds: int = 60,
    runtime_root: Path | None = None,
) -> dict[str, Any]:
    return _worker_spec(
        root,
        label=SLOW_WORKER_LABEL,
        script="slow_publication_worker.py",
        interval_seconds=interval_seconds,
        home=home,
        runtime_root=runtime_root,
    )


def queue_import_launch_agent_spec(
    root: Path,
    *,
    home: Path,
    interval_seconds: int = 300,
    runtime_root: Path | None = None,
) -> dict[str, Any]:
    return _worker_spec(
        root,
        label="com.oss-pr-radar.queue-importer",
        script="queue_importer.py",
        interval_seconds=interval_seconds,
        home=home,
        runtime_root=runtime_root,
    )


def worker_specs(
    root: Path,
    *,
    home: Path,
    runtime_root: Path | None = None,
) -> list[dict[str, Any]]:
    code_root = root.resolve()
    runtime_root = (runtime_root or root).resolve()
    evidence = active_release_evidence(runtime_root)
    if evidence.get("valid") is not True:
        raise RuntimeError(f"active release is invalid: {evidence.get('error', 'unknown error')}")
    if Path(str(evidence["path"])).resolve() != code_root:
        raise RuntimeError("worker code root is not the active immutable release")
    return [
        launch_agent_spec(
            code_root,
            interval_seconds=20,
            home=home,
            runtime_root=runtime_root,
        ),
        slow_launch_agent_spec(code_root, home=home, runtime_root=runtime_root),
        queue_import_launch_agent_spec(code_root, home=home, runtime_root=runtime_root),
    ]


def write_launch_agent(path: Path, spec: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML, sort_keys=True))


def main() -> int:
    for key in SENSITIVE_ENVIRONMENT_KEYS:
        os.environ.pop(key, None)
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[2])
    parser.add_argument("--queue-sync-interval-seconds", type=int, default=300)
    parser.add_argument("--mode", choices=("full", "fast", "slow"), default="full")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        require_operational_authorization(args.root)
    except RuntimeError as exc:
        print(json.dumps({"ok": False, "blocked": "operational authorization required", "error": str(exc)[:400]}))
        return 1
    log_dir = Path.home() / "Library" / "Logs" / "oss-pr-radar"
    rotate_log(log_dir / "publication-agent.log")
    rotate_log(log_dir / "publication-agent.error.log")
    try:
        if args.mode == "fast":
            result = fast_advance_once(args.root)
        elif args.mode == "slow":
            result = slow_advance_once(args.root)
        else:
            result = advance_once(
                args.root,
                queue_sync_interval_seconds=args.queue_sync_interval_seconds,
            )
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result = {"ok": False, "activity": True, "errors": [{"error": str(exc)[:800]}]}
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    elif result.get("activity") or not result.get("ok"):
        print(json.dumps(compact_advance_result(result), ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
