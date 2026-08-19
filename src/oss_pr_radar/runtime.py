"""Durable runtime safety primitives for the local Radar workers.

The runtime state is deliberately separate from the Radar Ledger. The Ledger
is the lifecycle authority; this module records whether the local execution
plane is able to process it safely.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

RUNTIME_STATE = "runtime-health.json"
QUEUE_STATE = "queue-import-state.json"
OPERATIONS_DIR = "runtime-operations"
RELEASE_POINTER = "current-release"
RELEASE_MANIFEST = "release-manifest.json"
RUNTIME_SCHEMA = "runtime_health_v1"
GIB = 1024**3
REQUIRED_WORKERS = ("fast", "slow", "queue-importer")


class RuntimeLockBusy(RuntimeError):
    """A mutually exclusive worker is already running."""


@dataclass(frozen=True)
class DiskThresholds:
    """Free-space limits that stop automation before ENOSPC."""

    warning_free_bytes: int = 32 * GIB
    stop_free_bytes: int = 16 * GIB
    warning_used_fraction: float = 0.90
    stop_used_fraction: float = 0.95


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _atomic_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def write_json(path: Path, value: object) -> None:
    """Atomically persist a small runtime control record."""

    _atomic_write(path, value)


def read_json(path: Path, default: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return default


def runtime_state_path(root: Path) -> Path:
    return root / "state" / RUNTIME_STATE


def runtime_state_lock_path(root: Path) -> Path:
    return root / "state" / "runtime-health.lock"


def queue_state_path(root: Path) -> Path:
    return root / "state" / QUEUE_STATE


def operation_log_path(root: Path) -> Path:
    return root / "state" / OPERATIONS_DIR / "operations.ndjson"


@contextmanager
def exclusive_lock(path: Path, *, blocking: bool = False) -> Iterator[None]:
    """Acquire a process lock, optionally waiting for a state writer."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            operation = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(handle.fileno(), operation)
        except BlockingIOError as exc:
            raise RuntimeLockBusy(str(path)) from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def append_operation(root: Path, record: dict[str, Any]) -> None:
    """Append a bounded, non-secret operation record with a durable flush."""

    path = operation_log_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    safe = {
        "at": utc_now(),
        "operationId": str(record.get("operationId") or f"{os.getpid()}-{time.time_ns()}"),
        "worker": str(record.get("worker") or "unknown"),
        "operation": str(record.get("operation") or "unknown"),
        "status": str(record.get("status") or "unknown"),
        "exitCode": record.get("exitCode"),
        "durationSeconds": record.get("durationSeconds"),
        "errorCode": str(record.get("errorCode") or "")[:120],
        "retryAfter": record.get("retryAfter"),
        "inFlight": bool(record.get("inFlight")),
    }
    with exclusive_lock(root / "state" / "runtime-operation.lock", blocking=True):
        rotate_log(path, max_bytes=50 * 1024 * 1024, backups=5)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(safe, ensure_ascii=True, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def rotate_log(path: Path, *, max_bytes: int = 50 * 1024 * 1024, backups: int = 3) -> list[str]:
    """Rotate one launchd log before a new one-shot process starts."""

    if max_bytes <= 0 or backups < 1 or not path.exists() or path.stat().st_size < max_bytes:
        return []
    rotated: list[str] = []
    for index in range(backups, 0, -1):
        current = path.with_name(f"{path.name}.{index}")
        if index == backups:
            current.unlink(missing_ok=True)
        else:
            previous = path.with_name(f"{path.name}.{index + 1}")
            if current.exists():
                current.replace(previous)
        rotated.append(str(current))
    path.replace(path.with_name(f"{path.name}.1"))
    return rotated


def disk_snapshot(path: Path, thresholds: DiskThresholds | None = None) -> dict[str, Any]:
    thresholds = thresholds or DiskThresholds()
    usage = shutil.disk_usage(path)
    used_fraction = 1.0 - (usage.free / usage.total if usage.total else 0.0)
    if usage.free <= thresholds.stop_free_bytes or used_fraction >= thresholds.stop_used_fraction:
        level = "stop"
    elif (
        usage.free <= thresholds.warning_free_bytes
        or used_fraction >= thresholds.warning_used_fraction
    ):
        level = "warning"
    else:
        level = "ok"
    return {
        "path": str(path),
        "totalBytes": usage.total,
        "freeBytes": usage.free,
        "usedFraction": round(used_fraction, 6),
        "level": level,
        "warningFreeBytes": thresholds.warning_free_bytes,
        "stopFreeBytes": thresholds.stop_free_bytes,
    }


def pid_probe(pid: int | None, *, expected_fragment: str | None = None) -> dict[str, Any]:
    if not pid or pid <= 0:
        return {"pid": pid, "alive": False, "versionMatched": False}
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return {
            "pid": pid,
            "alive": False,
            "versionMatched": False,
            "error": errno.errorcode.get(exc.errno or 0, type(exc).__name__),
        }
    command = ""
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        command = completed.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return {
        "pid": pid,
        "alive": True,
        "command": command[:500],
        "versionMatched": expected_fragment is None or expected_fragment in command,
    }


def _parse_epoch(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _worker_health(
    worker: str,
    state: dict[str, Any],
    *,
    now: float,
    max_success_age_seconds: int,
    max_queue_age_seconds: int,
    max_failures: int,
) -> dict[str, Any]:
    success_field = "queueImportSuccessAt" if worker == "queue-importer" else "lastSuccessAt"
    exit_field = "queueLastExitCode" if worker == "queue-importer" else "lastExitCode"
    failure_field = (
        "queueConsecutiveFailures" if worker == "queue-importer" else "consecutiveFailures"
    )
    success = _parse_epoch(state.get(success_field))
    issues: list[str] = []
    max_age = max_queue_age_seconds if worker == "queue-importer" else max_success_age_seconds
    if success is None or now - success > max_age:
        issues.append("RECENT_SUCCESS_MISSING_OR_STALE")
    if int(state.get(failure_field) or 0) >= max_failures:
        issues.append("CONSECUTIVE_FAILURES")
    if state.get(exit_field) not in {None, 0}:
        issues.append("LAST_EXIT_NONZERO")
    return {
        "worker": worker,
        "healthy": not issues,
        "issues": issues,
        "lastSuccessAt": state.get(success_field),
        "lastExitCode": state.get(exit_field),
        "consecutiveFailures": int(state.get(failure_field) or 0),
    }


def evaluate_health(
    state: dict[str, Any],
    *,
    now: float | None = None,
    max_success_age_seconds: int = 120,
    max_queue_age_seconds: int = 900,
    max_failures: int = 3,
    expected_release: str | None = None,
    expected_policy_digest: str | None = None,
    disk: dict[str, Any] | None = None,
    log_bytes: int | None = None,
    max_log_bytes: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    current = time.time() if now is None else now
    nested = isinstance(state.get("workers"), dict)
    worker_states = state.get("workers") if nested else {"runtime": state}
    workers: dict[str, dict[str, Any]] = {}
    issues: list[str] = []
    for worker in REQUIRED_WORKERS if nested else ("runtime",):
        worker_state = worker_states.get(worker)
        worker_state = worker_state if isinstance(worker_state, dict) else {}
        result = _worker_health(
            worker,
            worker_state,
            now=current,
            max_success_age_seconds=max_success_age_seconds,
            max_queue_age_seconds=max_queue_age_seconds,
            max_failures=max_failures,
        )
        workers[worker] = result
        issues.extend(
            f"{worker}:{issue}" if nested else issue for issue in result["issues"]
        )
    if not nested:
        queue_success = _parse_epoch(state.get("queueImportSuccessAt"))
        if queue_success is None or current - queue_success > max_queue_age_seconds:
            issues.append("QUEUE_IMPORT_STALE")
    deployment = state.get("deployment") if isinstance(state.get("deployment"), dict) else state
    pending_effects = int(deployment.get("pendingPublicationEffects") or 0)
    if pending_effects < 0:
        issues.append("PUBLICATION_EFFECTS_UNREADABLE")
    elif pending_effects > 0:
        issues.append("PUBLICATION_EFFECT_REQUIRES_RECONCILIATION")
    release_version = deployment.get("releaseVersion")
    policy_digest = deployment.get("policyDigest")
    if expected_release and release_version != expected_release:
        issues.append("RELEASE_VERSION_MISMATCH")
    if expected_policy_digest and policy_digest != expected_policy_digest:
        issues.append("POLICY_DIGEST_CHANGED")
    if deployment.get("deploymentDirty") is True or deployment.get("manifestVerified") is not True:
        issues.append("DIRTY_OR_UNVERIFIED_DEPLOYMENT")
    if disk and disk.get("level") == "stop":
        issues.append("DISK_STOP_THRESHOLD")
    elif disk and disk.get("level") == "warning":
        issues.append("DISK_WARNING_THRESHOLD")
    if log_bytes is not None and log_bytes > max_log_bytes:
        issues.append("LOG_LIMIT_EXCEEDED")
    return {
        "healthy": not issues,
        "issues": issues,
        "checkedAt": datetime.fromtimestamp(current, UTC).isoformat().replace("+00:00", "Z"),
        "workers": workers,
        "deployment": deployment,
        "disk": disk,
        "logBytes": log_bytes,
    }


def record_cycle(
    root: Path,
    *,
    worker: str,
    ok: bool,
    exit_code: int,
    started_at: float,
    error_code: str | None = None,
    release_version: str | None = None,
    policy_digest: str | None = None,
    success_field: str = "lastSuccessAt",
    exit_field: str = "lastExitCode",
    failure_field: str = "consecutiveFailures",
    **extra: Any,
) -> dict[str, Any]:
    path = runtime_state_path(root)
    with exclusive_lock(runtime_state_lock_path(root), blocking=True):
        current = read_json(path, {})
        state = dict(current) if isinstance(current, dict) else {}
        workers = state.get("workers") if isinstance(state.get("workers"), dict) else {}
        worker_state = dict(workers.get(worker) or {})
        failures = int(worker_state.get(failure_field) or 0)
        finished_at = utc_now()
        worker_state.update(
            {
                "lastStartedAt": datetime.fromtimestamp(started_at, UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "lastFinishedAt": finished_at,
                exit_field: exit_code,
                failure_field: 0 if ok else failures + 1,
                "consecutiveSuccesses": int(worker_state.get("consecutiveSuccesses") or 0) + 1
                if ok
                else 0,
                "lastErrorCode": None if ok else error_code,
            }
        )
        if ok:
            worker_state[success_field] = finished_at
        worker_state.update(extra)
        workers[worker] = worker_state
        state["schemaVersion"] = RUNTIME_SCHEMA
        state["workers"] = workers
        deployment = state.get("deployment") if isinstance(state.get("deployment"), dict) else {}
        if release_version is not None:
            deployment["releaseVersion"] = release_version
        if policy_digest is not None:
            deployment["policyDigest"] = policy_digest
        state["deployment"] = deployment
        aggregate = evaluate_health(state)
        state["aggregate"] = aggregate
        _atomic_write(path, state)
    append_operation(
        root,
        {
            "worker": worker,
            "operation": "cycle",
            "status": "success" if ok else "failure",
            "exitCode": exit_code,
            "durationSeconds": round(max(0.0, time.time() - started_at), 3),
            "errorCode": error_code,
        },
    )
    return state


def update_worker_observation(
    root: Path,
    *,
    worker: str,
    deployment: dict[str, Any] | None = None,
    **updates: Any,
) -> dict[str, Any]:
    """Atomically merge supervisor observations into one worker's state."""

    path = runtime_state_path(root)
    with exclusive_lock(runtime_state_lock_path(root), blocking=True):
        current = read_json(path, {})
        state = dict(current) if isinstance(current, dict) else {}
        workers = state.get("workers") if isinstance(state.get("workers"), dict) else {}
        worker_state = dict(workers.get(worker) or {})
        worker_state.update(updates)
        workers[worker] = worker_state
        state["schemaVersion"] = RUNTIME_SCHEMA
        state["workers"] = workers
        current_deployment = (
            dict(state.get("deployment"))
            if isinstance(state.get("deployment"), dict)
            else {}
        )
        if deployment:
            current_deployment.update(deployment)
        state["deployment"] = current_deployment
        state["aggregate"] = evaluate_health(state)
        _atomic_write(path, state)
        return state


def digest_policy(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def pending_publication_effects(ledger_path: Path) -> int:
    """Read unresolved publication effects without opening the production DB for writes."""

    if not ledger_path.exists():
        return 0
    try:
        connection = sqlite3.connect(f"file:{ledger_path}?mode=ro", uri=True, timeout=2)
        try:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='publication_effects'"
            ).fetchone()
            # Managed ledgers deliberately do not carry the legacy publication
            # effect table.  Its absence means there are no legacy effects to
            # drain; other database errors remain fail-closed below.
            if table is None:
                return 0
            row = connection.execute(
                "SELECT COUNT(*) FROM publication_effects WHERE status <> 'SUCCEEDED'"
            ).fetchone()
            return int(row[0] if row else 0)
        finally:
            connection.close()
    except sqlite3.Error:
        return -1
