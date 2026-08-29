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
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .operational_auth import require_operational_authorization
from .release_binding import bind_runtime, runtime_ledger_path, runtime_python
from .runtime import (
    RuntimeLockBusy,
    append_operation,
    disk_pressure_gate,
    disk_restart_safe,
    disk_snapshot,
    exclusive_lock,
    pid_probe,
    read_json,
    record_cycle,
    rotate_log,
    update_worker_observation,
    utc_now,
    write_json,
)
from .runtime_audit import active_release_evidence
from .runtime_retention import maybe_reclaim_runtime_storage

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
SLOW_CLOUD_SYNC_INTERVAL_SECONDS = 300
# The bridge runs in a fresh Python process.  Its deadline therefore includes
# interpreter and native-extension startup, which can exceed 15 seconds under
# ordinary host load before the local-only operation even opens the ledger.
# Keep the bound below the fast-worker health freshness window while allowing
# enough time for that cold start.
MAX_FAST_OPERATION_SECONDS = 60
TERMINAL_FEEDBACK_STAGES = {"AUDIT_NO_GO", "MERGED", "CLOSED"}
PR_FOLLOWUP_REBIND_REQUIRED = "PR_FOLLOWUP_REBIND_REQUIRED"


def _record_identity(value: Any) -> str:
    """Return the stable identity used when combining repeated bridge results.

    A slow cycle may ingest once before independent review and once after it.
    The ledger treats the second observation as the same event, but the bridge
    responses are separate lists.  Prefer an explicit result/event digest (or
    idempotency key) when available; older bridge payloads do not expose one,
    so their canonical JSON is a safe compatibility fallback.
    """

    if isinstance(value, dict):
        for key in (
            "resultDigest",
            "result_digest",
            "eventDigest",
            "event_digest",
            "digest",
            "eventId",
            "event_id",
            "idempotencyKey",
            "idempotency_key",
            "requestId",
            "request_id",
        ):
            candidate = value.get(key)
            if candidate not in (None, ""):
                target = value.get("key") or value.get("opportunityKey") or ""
                return f"{target}:{key}:{candidate}"
    try:
        return "json:" + json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError):
        return f"repr:{value!r}"


def _merge_unique_records(*groups: list[Any]) -> list[Any]:
    """Merge bridge record groups without counting one event twice.

    When the same identity appears in both ingestion passes, retain the later
    representation so a refreshed status is not replaced by the stale first
    observation while preserving the original ordering of identities.
    """

    merged: list[Any] = []
    positions: dict[str, int] = {}
    for group in groups:
        for value in group:
            identity = _record_identity(value)
            position = positions.get(identity)
            if position is None:
                positions[identity] = len(merged)
                merged.append(value)
            else:
                merged[position] = value
    return merged


def _has_rebind_recovery(*groups: list[Any]) -> bool:
    """Return whether result ingestion produced an actionable PR rebind.

    A rebind quarantine is actionable only after the bridge has successfully
    rearmed the follow-up and supplied a replacement wake digest.  Invalid
    rebind evidence is deliberately excluded, as are unrelated and already
    settled quarantines.  The bridge reports a repeated durable quarantine in
    ``quarantinedAlreadyRecorded``; callers pass both forms here so a failed
    drain is retried on the next slow cycle as well.
    """

    for group in groups:
        for item in group:
            if not isinstance(item, dict):
                continue
            if item.get("reason") != PR_FOLLOWUP_REBIND_REQUIRED:
                continue
            if item.get("rebindEligible", True) is False:
                continue
            replacement_digest = item.get("replacementWakeDigest")
            if isinstance(replacement_digest, str) and replacement_digest:
                return True
    return False


def _disk_gate(
    root: Path,
    *,
    worker: str,
    force_recheck: bool = False,
    observed_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the shared capacity gate through this module's snapshot seam."""

    # Passing the local alias keeps existing tests and callers able to inject
    # a deterministic snapshot without bypassing the shared gate.
    snapshot_fn = (
        (lambda _root: dict(observed_snapshot))
        if isinstance(observed_snapshot, dict)
        else disk_snapshot
    )
    return disk_pressure_gate(
        root,
        worker=worker,
        snapshot_fn=snapshot_fn,
        force_recheck=force_recheck,
    )


def _record_disk_gate_recovery(root: Path, *, worker: str) -> str | None:
    """Append one best-effort recovery marker after a gate is cleared."""

    try:
        append_operation(
            root,
            {
                "worker": worker,
                "operation": "disk-pressure-recovery",
                "status": "success",
                "exitCode": 0,
                "inFlight": False,
            },
        )
    except Exception as exc:
        return f"{type(exc).__name__}:{str(exc)[:240]}"
    return None


def _disk_gate_failure(
    root: Path,
    *,
    worker: str,
    started_at: float,
    gate: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a fail-closed worker result and claim the first stop record."""

    reason = str(gate.get("reason") or "DISK_PRESSURE_GATE_UNAVAILABLE")
    result: dict[str, Any] = {
        "ok": False,
        "activity": False,
        "reason": reason,
        "deferred": bool(gate.get("deferred")),
        "errors": [{"error": reason}],
        "diskPressureGate": {
            "active": bool(gate.get("gateActive")),
            "deferred": bool(gate.get("deferred")),
            "firstStop": bool(gate.get("firstStop")),
            "nextCheckAt": gate.get("nextCheckAt"),
        },
    }
    if gate.get("error"):
        result["diskPressureGate"]["error"] = str(gate["error"])[:240]
    if gate.get("recordStop") is True:
        try:
            record_extra = {}
            if extra and "storageMaintenance" in extra:
                record_extra["storageMaintenance"] = extra["storageMaintenance"]
            record_cycle(
                root,
                worker=worker,
                ok=False,
                exit_code=78,
                started_at=started_at,
                error_code=reason,
                disk=gate.get("snapshot"),
                **record_extra,
            )
        except Exception as exc:
            # The gate is already durable and claimed. Do not retry this
            # health write on every worker interval if the host is still full.
            result["diskPressureGate"]["recordError"] = f"{type(exc).__name__}:{str(exc)[:240]}"
    if extra:
        result.update(extra)
    return result


def _handle_disk_gate_recovery(
    root: Path,
    *,
    worker: str,
    gate: dict[str, Any],
) -> str | None:
    if gate.get("recordRecovery") is True:
        return _record_disk_gate_recovery(root, worker=worker)
    return None


def _legacy_disk_backoff_recoverable(
    root: Path,
    *,
    backoff: dict[str, Any],
    disk: dict[str, Any],
    now: float,
) -> bool:
    """Recognize only a future backoff produced by the former disk-stop bug."""

    if (
        not disk_restart_safe(disk)
        or backoff.get("schemaVersion") != "slow_backoff_v1"
        or backoff.get("inFlight") is not False
        or int(backoff.get("failureCount") or 0) <= 0
        or float(backoff.get("nextAttemptAt") or 0) <= now
        or backoff.get("lastError")
    ):
        return False
    health = read_json(root / "state" / "runtime-health.json", {})
    workers = health.get("workers") if isinstance(health, dict) else None
    slow = workers.get("slow") if isinstance(workers, dict) else None
    previous_disk = slow.get("disk") if isinstance(slow, dict) else None
    if (
        not isinstance(previous_disk, dict)
        or previous_disk.get("level") != "stop"
        or slow.get("lastErrorCode") != "SLOW_WORKER_FAILED"
        or slow.get("lastExitCode") != 1
    ):
        return False
    try:
        backoff_finished = datetime.fromisoformat(
            str(backoff["lastAttemptAt"]).replace("Z", "+00:00")
        ).timestamp()
        health_finished = datetime.fromisoformat(
            str(slow["lastFinishedAt"]).replace("Z", "+00:00")
        ).timestamp()
    except (KeyError, TypeError, ValueError):
        return False
    return abs(backoff_finished - health_finished) <= 2


def _slow_worker_diagnostic(
    root: Path,
    result: dict[str, Any] | None = None,
    reproduction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    release = active_release_evidence(root)
    value = result if isinstance(result, dict) else {}
    recovery = value.get("taskContextRecovery")
    recovery = recovery if isinstance(recovery, dict) else {}
    return {
        "worker": "slow",
        "release": {
            key: release.get(key)
            for key in ("valid", "releaseId", "commit", "manifestSha256", "policyDigest")
        },
        "contextRecovery": {
            "verified": int(recovery.get("verified") or 0),
            "unavailable": len(recovery.get("unavailable") or []),
            "quarantined": len(recovery.get("quarantined") or []),
            "errors": len(recovery.get("errors") or []),
        },
        "reproductionProbe": {
            "ok": reproduction.get("ok") if isinstance(reproduction, dict) else None,
            "errors": list(reproduction.get("errors") or [])[:3]
            if isinstance(reproduction, dict)
            else [],
        },
    }


def _record_slow_cycle(
    root: Path,
    *,
    ok: bool,
    exit_code: int,
    started_at: float,
    error_code: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Record a terminal slow cycle and clear its active-run marker."""

    extra.update(
        {
            "inFlight": False,
            "attemptStartedAt": None,
            "workerPid": None,
            "workerPidAlive": False,
        }
    )
    return record_cycle(
        root,
        worker="slow",
        ok=ok,
        exit_code=exit_code,
        started_at=started_at,
        error_code=error_code,
        **extra,
    )


def _stale_slow_inflight(
    root: Path,
    *,
    backoff: dict[str, Any],
) -> tuple[bool, str | None]:
    """Verify the owner of a persisted slow attempt before honoring it."""

    if backoff.get("inFlight") is not True:
        return False, None
    runtime = read_json(root / "state" / "runtime-health.json", {})
    workers = runtime.get("workers") if isinstance(runtime, dict) else None
    slow = workers.get("slow") if isinstance(workers, dict) else None
    slow = slow if isinstance(slow, dict) else {}
    try:
        recorded_pid = int(slow.get("workerPid") or 0)
    except (TypeError, ValueError):
        return False, None
    if recorded_pid <= 0:
        return False, None
    operation_id = str(backoff.get("operationId") or "")
    if operation_id and not operation_id.startswith(f"{recorded_pid}-"):
        return False, None
    evidence = pid_probe(recorded_pid, expected_fragment="slow_publication_worker.py")
    if evidence.get("alive") is True and evidence.get("versionMatched") is True:
        return False, None
    reason = "SLOW_WORKER_STALE_PID"
    detail = str(evidence.get("error") or "process identity mismatch")[:160]
    return True, f"{reason}:{recorded_pid}:{detail}"


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
    if not isinstance(value.get("ok"), bool):
        raise RuntimeError(f"{operation}: local bridge omitted a boolean ok result")
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
        if (
            value.get("ok") is False
            and value.get("turnStarted") is False
            and value.get("turnId") is None
            and value.get("turnStatus") in {None, ""}
            and isinstance(value.get("error"), str)
            and value["error"].strip()
        ):
            return True
        if (
            value.get("ok") is True
            and isinstance(value.get("turnId"), str)
            and value["turnId"]
            and value.get("turnStatus") in {"failed", "interrupted"}
        ):
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
    if sync.get("ok") is not True:
        errors.append(
            {"error": str(sync.get("error") or sync.get("errors") or "queue sync failed")[:400]}
        )

    listing: dict[str, Any] = {"ok": True, "pending": []}
    if not errors:
        try:
            listing = runner(root, "list")
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            listing = {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}
        if listing.get("ok") is not True:
            errors.append(
                {
                    "error": str(
                        listing.get("error") or listing.get("errors") or "queue list failed"
                    )[:400]
                }
            )

    followup_listing: dict[str, Any] = {
        "ok": True,
        "candidates": [],
        "unresolved": [],
    }
    followup_import = sync.get("prFollowup")
    if (
        not errors
        and isinstance(followup_import, dict)
        and followup_import.get("status") == "imported"
    ):
        try:
            followup_listing = runner(root, "pr-followup-list")
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            followup_listing = {
                "ok": False,
                "error": f"{type(exc).__name__}:{str(exc)[:400]}",
            }
        if followup_listing.get("ok") is not True:
            errors.append(
                {
                    "error": str(
                        followup_listing.get("error")
                        or followup_listing.get("errors")
                        or "PR follow-up list failed"
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
        "prFollowup": followup_import if isinstance(followup_import, dict) else {},
        "prFollowupCandidates": list(followup_listing.get("candidates") or []),
        "prFollowupUnresolved": list(followup_listing.get("unresolved") or []),
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
            disk_before = disk_snapshot(root)
            initial_stop_gate = None
            if disk_before.get("level") == "stop":
                # Persist the hard-stop episode before retention changes the
                # measurement.  A reclaim may recheck immediately, but it may
                # not turn a near-boundary warning into an implicit restart.
                initial_stop_gate = _disk_gate(
                    root,
                    worker="fast",
                    observed_snapshot=disk_before,
                )
            storage_maintenance = maybe_reclaim_runtime_storage(root, disk=disk_before)
            reclaimed = int(storage_maintenance.get("freedBytes") or 0) > 0
            gate = (
                _disk_gate(root, worker="fast", force_recheck=True)
                if reclaimed
                else (initial_stop_gate or _disk_gate(root, worker="fast"))
            )
            if (
                isinstance(initial_stop_gate, dict)
                and initial_stop_gate.get("recordStop") is True
                and gate.get("allowed") is not True
            ):
                gate = dict(gate)
                gate["recordStop"] = True
                gate["firstStop"] = True
                gate["snapshot"] = initial_stop_gate.get("snapshot")
            if gate.get("allowed") is not True:
                return _disk_gate_failure(
                    root,
                    worker="fast",
                    started_at=started,
                    gate=gate,
                    extra={
                        "slowWorkQueued": False,
                        "storageMaintenance": storage_maintenance,
                    },
                )
            recovery_error = _handle_disk_gate_recovery(root, worker="fast", gate=gate)
            disk = gate.get("snapshot")
            ingestion = runner(root, "local-receipt-enqueue")
            errors = list(ingestion.get("errors") or []) + list(ingestion.get("rejected") or [])
            _enqueue_slow_work(root, reason="local_ingest")
            result = {
                "ok": not errors and ingestion.get("ok") is True,
                "activity": bool(ingestion.get("queued") or errors),
                "receiptsQueued": list(ingestion.get("queued") or []),
                "errors": errors,
                "slowWorkQueued": True,
                "storageMaintenance": storage_maintenance,
            }
            record_cycle(
                root,
                worker="fast",
                ok=result["ok"] is True,
                exit_code=0 if result["ok"] is True else 1,
                started_at=started,
                error_code="LOCAL_INGEST_FAILED" if result["ok"] is not True else None,
                disk=disk,
                storageMaintenance=storage_maintenance,
            )
            if recovery_error:
                result.setdefault("errors", []).append({"error": recovery_error})
                result["ok"] = False
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
            gate = _disk_gate(root, worker="queue-importer")
            if gate.get("allowed") is not True:
                return _disk_gate_failure(
                    root,
                    worker="queue-importer",
                    started_at=started,
                    gate=gate,
                    extra={"error": str(gate.get("reason") or "DISK_PRESSURE_GATE_UNAVAILABLE")},
                )
            recovery_error = _handle_disk_gate_recovery(
                root,
                worker="queue-importer",
                gate=gate,
            )
            disk = gate.get("snapshot")
            result = runner(root, "queue-import")
            if result.get("ok") is True:
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
                ok=result.get("ok") is True,
                exit_code=0 if result.get("ok") is True else 1,
                started_at=started,
                error_code=None
                if result.get("ok") is True
                else str(result.get("error") or "QUEUE_IMPORT_FAILED"),
                success_field="queueImportSuccessAt",
                exit_field="queueLastExitCode",
                failure_field="queueConsecutiveFailures",
                disk=disk,
            )
            if recovery_error:
                result = dict(result)
                result.setdefault("errors", []).append({"error": recovery_error})
                result["ok"] = False
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
            gate = _disk_gate(root, worker="slow")
            if gate.get("allowed") is not True:
                result = _disk_gate_failure(
                    root,
                    worker="slow",
                    started_at=started,
                    gate=gate,
                    extra={"slowWorkerDiagnostic": _slow_worker_diagnostic(root)},
                )
                return result
            disk = gate.get("snapshot")
            recovery_error = _handle_disk_gate_recovery(root, worker="slow", gate=gate)
            recovered_legacy_disk_backoff = _legacy_disk_backoff_recoverable(
                root,
                backoff=backoff,
                disk=disk,
                now=now,
            )
            if recovered_legacy_disk_backoff:
                backoff = backoff | {
                    "failureCount": 0,
                    "backoffSeconds": 0,
                    "nextAttemptAt": now,
                    "retryAfter": now,
                }
                append_operation(
                    root,
                    {
                        "worker": "slow",
                        "operation": "slow-backoff-recovery",
                        "status": "success",
                        "reason": "LEGACY_DISK_STOP_BACKOFF",
                        "inFlight": False,
                    },
                )
            stale_inflight, stale_error = _stale_slow_inflight(root, backoff=backoff)
            if stale_inflight and stale_error:
                try:
                    failures = max(0, int(backoff.get("failureCount") or 0))
                except (TypeError, ValueError):
                    failures = 0
                delay = min(3600, 60 * (2 ** min(failures, 5)))
                failure_retry = now + delay
                operation_id = str(
                    backoff.get("operationId") or f"stale-{os.getpid()}-{time.time_ns()}"
                )
                write_json(
                    backoff_path,
                    {
                        "schemaVersion": "slow_backoff_v1",
                        "failureCount": failures + 1,
                        "backoffSeconds": delay,
                        "nextAttemptAt": failure_retry,
                        "retryAfter": failure_retry,
                        "attemptStartedAt": None,
                        "lastAttemptAt": utc_now(),
                        "inFlight": False,
                        "lastError": stale_error,
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
                        "errorCode": "SLOW_WORKER_STALE_PID",
                        "retryAfter": failure_retry,
                        "inFlight": False,
                    },
                )
                _record_slow_cycle(
                    root,
                    ok=False,
                    exit_code=1,
                    started_at=started,
                    error_code="SLOW_WORKER_STALE_PID",
                    disk=disk,
                )
                return {
                    "ok": False,
                    "errors": [{"error": stale_error}],
                    "slowWorkerDiagnostic": _slow_worker_diagnostic(root),
                }
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
            failures = int(backoff.get("failureCount") or 0)
            delay = min(3600, 60 * (2 ** min(failures, 5)))
            retry_after = now + delay
            operation_id = f"{os.getpid()}-{time.time_ns()}"
            attempt_started_at = utc_now()
            write_json(
                backoff_path,
                {
                    "schemaVersion": "slow_backoff_v1",
                    "failureCount": failures,
                    "backoffSeconds": delay,
                    "nextAttemptAt": retry_after,
                    "retryAfter": retry_after,
                    "attemptStartedAt": attempt_started_at,
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
            update_worker_observation(
                root,
                worker="slow",
                inFlight=True,
                attemptStartedAt=attempt_started_at,
                workerPid=os.getpid(),
                workerPidAlive=True,
            )
            try:
                reproduction = runner(root, "reproduction-probe")
                result = advance_once(
                    root,
                    runner=runner,
                    queue_sync_interval_seconds=SLOW_CLOUD_SYNC_INTERVAL_SECONDS,
                )
                result["reproductionProbe"] = reproduction
                result["slowWorkerDiagnostic"] = _slow_worker_diagnostic(root, result, reproduction)
                if recovered_legacy_disk_backoff:
                    result["legacyDiskBackoffRecovered"] = True
                if recovery_error:
                    result.setdefault("errors", []).append({"error": recovery_error})
                    result["ok"] = False
                if "slowWorkerDiagnostic" not in result:
                    result["slowWorkerDiagnostic"] = _slow_worker_diagnostic(root, result)
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
                _record_slow_cycle(
                    root,
                    ok=False,
                    exit_code=130 if isinstance(exc, KeyboardInterrupt) else 1,
                    started_at=started,
                    error_code=error_code,
                    disk=disk,
                )
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                return {
                    "ok": False,
                    "errors": [{"error": str(exc)[:400]}],
                    "slowWorkerDiagnostic": _slow_worker_diagnostic(root),
                }
            ok = result.get("ok") is True
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
            _record_slow_cycle(
                root,
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
    context_recovery = runner(root, "context-recover")
    recovery_errors = list(context_recovery.get("errors") or [])
    recovery_unavailable = list(context_recovery.get("unavailable") or [])
    recovery_quarantined = list(context_recovery.get("quarantined") or [])
    public_unavailable = recovery_unavailable[:5]
    public_quarantined = recovery_quarantined[:5]
    if context_recovery.get("ok") is not True or recovery_errors:
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
            "contextsQuarantined": public_quarantined,
            "contextsQuarantinedCount": len(recovery_quarantined),
            "errors": recovery_errors
            or [{"error": "task context recovery failed before result ingestion"}],
        }
    ingestion = runner(root, "ingest-results")
    ingestion_quarantined = list(ingestion.get("quarantined") or [])
    ingestion_quarantined_already_recorded = list(ingestion.get("quarantinedAlreadyRecorded") or [])
    ingestion_work_blocked = list(ingestion.get("workBlocked") or [])
    ingestion_errors = list(ingestion.get("errors") or [])
    if ingestion.get("ok") is not True or ingestion_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": _merge_unique_records(list(ingestion.get("ingested") or [])),
            "publicationRequests": _merge_unique_records(
                list(ingestion.get("publicationRequests") or [])
            ),
            "validationDeferred": _merge_unique_records(
                list(ingestion.get("validationDeferred") or [])
            ),
            "workBlocked": ingestion_work_blocked,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "contextsQuarantined": public_quarantined,
            "contextsQuarantinedCount": len(recovery_quarantined),
            "quarantined": ingestion_quarantined,
            "errors": ingestion_errors
            or [{"error": "task result ingestion failed before publication"}],
        }
    independent_review = runner(root, "independent-review-run")
    reported_review_errors = list(independent_review.get("errors") or [])
    review_candidate_errors = [
        *list(independent_review.get("candidateErrors") or []),
        *[item for item in reported_review_errors if isinstance(item, dict) and item.get("key")],
    ]
    review_errors = [item for item in reported_review_errors if item not in review_candidate_errors]
    review_retry_exhausted = list(independent_review.get("retryExhausted") or [])
    review_work_blocked = [
        {
            "key": str(item.get("key") or ""),
            "reason": "INDEPENDENT_REVIEW_FAILED",
            "error": str(item.get("error") or "")[:300],
        }
        for item in review_candidate_errors
        if isinstance(item, dict)
    ] + [
        {
            "key": str(item.get("key") or ""),
            "reason": str(item.get("reason") or "INDEPENDENT_REVIEW_RETRY_EXHAUSTED"),
            "attempts": int(item.get("attempts") or 0),
            "alreadyRecorded": True,
        }
        for item in review_retry_exhausted
        if isinstance(item, dict)
    ]
    review_updated = bool(independent_review.get("updated"))
    review_system_failed = bool(review_errors) or bool(
        independent_review.get("ok") is not True and not review_candidate_errors
    )
    if review_system_failed and not review_updated:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": _merge_unique_records(list(ingestion.get("ingested") or [])),
            "publicationRequests": _merge_unique_records(
                list(ingestion.get("publicationRequests") or [])
            ),
            "validationDeferred": _merge_unique_records(
                list(ingestion.get("validationDeferred") or [])
            ),
            "workBlocked": _merge_unique_records(ingestion_work_blocked, review_work_blocked),
            "independentReview": independent_review,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "contextsQuarantined": public_quarantined,
            "contextsQuarantinedCount": len(recovery_quarantined),
            "quarantined": _merge_unique_records(ingestion_quarantined),
            "errors": review_errors or [{"error": "independent review failed before publication"}],
        }
    post_review_ingestion = (
        runner(root, "ingest-results")
        if review_updated
        else {
            "ok": True,
            "ingested": [],
            "publicationRequests": [],
            "validationDeferred": [],
            "workBlocked": [],
        }
    )
    post_review_errors = list(post_review_ingestion.get("errors") or [])
    post_review_quarantined = list(post_review_ingestion.get("quarantined") or [])
    post_review_quarantined_already_recorded = list(
        post_review_ingestion.get("quarantinedAlreadyRecorded") or []
    )
    post_review_work_blocked = list(post_review_ingestion.get("workBlocked") or [])
    if post_review_ingestion.get("ok") is not True or post_review_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": _merge_unique_records(
                list(ingestion.get("ingested") or []),
                list(post_review_ingestion.get("ingested") or []),
            ),
            "publicationRequests": _merge_unique_records(
                list(ingestion.get("publicationRequests") or []),
                list(post_review_ingestion.get("publicationRequests") or []),
            ),
            "validationDeferred": _merge_unique_records(
                list(ingestion.get("validationDeferred") or []),
                list(post_review_ingestion.get("validationDeferred") or []),
            ),
            "workBlocked": _merge_unique_records(
                ingestion_work_blocked,
                review_work_blocked,
                post_review_work_blocked,
            ),
            "independentReview": independent_review,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "contextsQuarantined": public_quarantined,
            "contextsQuarantinedCount": len(recovery_quarantined),
            "quarantined": _merge_unique_records(ingestion_quarantined, post_review_quarantined),
            "errors": post_review_errors
            or [{"error": "task result ingestion failed after independent review"}],
        }
    ingested = _merge_unique_records(
        list(ingestion.get("ingested") or []),
        list(post_review_ingestion.get("ingested") or []),
    )
    terminal_feedback_needed = any(
        item.get("stage") in TERMINAL_FEEDBACK_STAGES for item in ingested
    )
    title_reconciliation = runner(root, "title-reconcile")
    cleanup_reconciliation = runner(root, "cleanup-reconcile")
    publication = runner(root, "publication-run")
    published = list(publication.get("published") or [])
    implementation_context_changed = any(
        item.get("stage") == "IMPLEMENTATION_READY" for item in ingested
    )
    context_sync = (
        runner(root, "context-sync")
        if published or implementation_context_changed
        else {"ok": True, "written": [], "errors": []}
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
    requests = _merge_unique_records(
        list(ingestion.get("publicationRequests") or []),
        list(post_review_ingestion.get("publicationRequests") or []),
    )
    validation_deferred = _merge_unique_records(
        list(ingestion.get("validationDeferred") or []),
        list(post_review_ingestion.get("validationDeferred") or []),
    )
    work_blocked = _merge_unique_records(
        ingestion_work_blocked,
        review_work_blocked,
        post_review_work_blocked,
    )
    quarantined = _merge_unique_records(ingestion_quarantined, post_review_quarantined)
    rebind_recovery = _has_rebind_recovery(
        ingestion_quarantined,
        ingestion_quarantined_already_recorded,
        post_review_quarantined,
        post_review_quarantined_already_recorded,
    )
    blocked = list(publication.get("blocked") or [])
    pending = list(publication.get("pending") or [])
    renamed = list(title_reconciliation.get("renamed") or [])
    archived = list(cleanup_reconciliation.get("archived") or [])
    drain = {"ok": True, "action": "not_triggered"}
    terminal_feedback = {"ok": True, "published": 0, "errors": []}
    lifecycle_healthy = bool(
        not errors
        and title_reconciliation.get("ok") is True
        and cleanup_reconciliation.get("ok") is True
        and publication.get("ok") is True
        and context_sync.get("ok") is True
        and publication_feedback.get("ok") is True
    )
    recovery = (
        runner(root, "recovery-list") if lifecycle_healthy else {"ok": False, "recoverable": []}
    )
    recoverable = list(recovery.get("recoverable") or []) if recovery.get("ok") is True else []
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
        or queue_sync.get("prFollowupCandidates")
        or queue_sync.get("prFollowupUnresolved")
        or rebind_recovery
    )
    if should_drain and lifecycle_healthy:
        drain = runner(root, "drain-once")
        errors.extend(list(drain.get("errors") or []))
        if drain.get("terminalized") or drain.get("scannerRechecks"):
            terminal_feedback_needed = True
    if terminal_feedback_needed and lifecycle_healthy:
        terminal_feedback = runner(root, "publish-terminal-feedback")
        errors.extend(list(terminal_feedback.get("errors") or []))
    drain_activity = bool(
        drain.get("action")
        and drain.get("action") not in {"none", "not_triggered", "drain_already_running"}
    )
    non_quarantine_blocked = any(item.get("reason") != "ACTIVE_TASK_QUARANTINE" for item in blocked)
    activity = bool(
        ingested
        or requests
        or renamed
        or archived
        or published
        or publication_feedback.get("reconciled")
        or any(not item.get("alreadyRecorded") for item in work_blocked)
        or non_quarantine_blocked
        or errors
        or drain_activity
        or queue_sync.get("inserted")
        or queue_sync.get("superseded")
        or queue_sync.get("prFollowupCandidates")
        or queue_sync.get("prFollowupUnresolved")
        or rebind_recovery
        or drain.get("scannerRechecks")
        or queue_sync.get("errors")
    )
    errors.extend(list(queue_sync.get("errors") or []))
    return {
        "ok": not errors
        and title_reconciliation.get("ok") is True
        and cleanup_reconciliation.get("ok") is True
        and publication.get("ok") is True
        and context_sync.get("ok") is True
        and publication_feedback.get("ok") is True
        and drain.get("ok") is True
        and terminal_feedback.get("ok") is True,
        "activity": activity,
        "resultsIngested": ingested,
        "publicationRequests": requests,
        "validationDeferred": validation_deferred,
        "workBlocked": work_blocked,
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
        "contextsQuarantined": public_quarantined,
        "contextsQuarantinedCount": len(recovery_quarantined),
        "taskContextRecovery": context_recovery,
        "quarantined": quarantined,
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
            "workBlocked": len(result.get("workBlocked") or []),
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
        "contextsQuarantinedCount": int(result.get("contextsQuarantinedCount") or 0),
        "slowWorkerDiagnostic": result.get("slowWorkerDiagnostic"),
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
    stdout_path, stderr_path = worker_log_paths(LAUNCH_AGENT_LABEL, home=home)
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
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
    }


def worker_log_paths(label: str, *, home: Path) -> tuple[Path, Path]:
    """Return the launchd output paths for one managed worker."""

    log_dir = home / "Library" / "Logs" / "oss-pr-radar"
    basename = "publication-agent" if label == LAUNCH_AGENT_LABEL else label.rsplit(".", 1)[-1]
    return log_dir / f"{basename}.log", log_dir / f"{basename}.error.log"


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
    stdout_path, stderr_path = worker_log_paths(label, home=home)
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
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
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
        print(
            json.dumps(
                {
                    "ok": False,
                    "blocked": "operational authorization required",
                    "error": str(exc)[:400],
                }
            )
        )
        return 1
    stdout_path, stderr_path = worker_log_paths(LAUNCH_AGENT_LABEL, home=Path.home())
    rotate_log(stdout_path)
    rotate_log(stderr_path)
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
    elif result.get("activity") or result.get("ok") is not True:
        print(json.dumps(compact_advance_result(result), ensure_ascii=False))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
