"""Durable runtime safety primitives for the local Radar workers.

The runtime state is deliberately separate from the Radar Ledger. The Ledger
is the lifecycle authority; this module records whether the local execution
plane is able to process it safely.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .release_binding import (
    _path_from_directory_fd,
    open_directory_handle,
    validate_runtime_file,
    validate_runtime_layout,
)

RUNTIME_STATE = "runtime-health.json"
QUEUE_STATE = "queue-import-state.json"
OPERATIONS_DIR = "runtime-operations"
RELEASE_POINTER = "current-release"
RELEASE_MANIFEST = "release-manifest.json"
RELEASE_ACTIVATION_JOURNAL = "release-activation.json"
RUNTIME_SCHEMA = "runtime_health_v1"
GIB = 1024**3
REQUIRED_WORKERS = ("fast", "slow", "queue-importer")
SLOW_INFLIGHT_MAX_SECONDS = 1800


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


def _atomic_write(path: Path, value: object, *, directory_fd: int | None = None) -> None:
    _atomic_write_bytes(
        path,
        (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
        directory_fd=directory_fd,
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unlink_at(name: str, directory_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        pass


def _atomic_write_bytes(
    path: Path, payload: bytes, *, mode: int, directory_fd: int | None = None
) -> None:
    path = path.absolute()
    owns_directory = directory_fd is None
    if owns_directory:
        directory_fd, _ = open_directory_handle(
            path.parent, label="runtime state parent", required_mode=0o700
        )
    assert directory_fd is not None
    temporary_name = f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    descriptor = -1
    try:
        try:
            metadata = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise RuntimeError("runtime state file is unsafe")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        if owns_directory:
            os.close(directory_fd)


def _atomic_pointer_write(pointer: Path, target: Path, *, directory_fd: int | None = None) -> None:
    pointer = pointer.absolute()
    owns_directory = directory_fd is None
    if owns_directory:
        directory_fd, _ = open_directory_handle(pointer.parent, label="release pointer parent")
    assert directory_fd is not None
    try:
        target = Path(os.path.realpath(str(target)))
        target_metadata = os.lstat(target)
        if stat.S_ISLNK(target_metadata.st_mode) or not stat.S_ISDIR(target_metadata.st_mode):
            raise RuntimeError("release pointer target is unsafe")
        if (
            pointer.name == RELEASE_POINTER
            and target.parent != (pointer.parent / "releases").absolute()
        ):
            raise RuntimeError("release pointer target escapes releases")
        try:
            pointer_metadata = os.stat(pointer.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pointer_metadata = None
        if pointer_metadata is not None and not stat.S_ISLNK(pointer_metadata.st_mode):
            raise RuntimeError("release pointer must be a symlink")
        temporary_name = f".{pointer.name}.{os.getpid()}.{time.time_ns()}.tmp"
        try:
            os.symlink(str(target), temporary_name, dir_fd=directory_fd)
            os.replace(
                temporary_name,
                pointer.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
    finally:
        if owns_directory:
            os.close(directory_fd)


def _restore_pointer_target(pointer_name: str, target: str, directory_fd: int) -> None:
    """Restore a previously validated pointer using only its held parent fd."""

    temporary_name = f".{pointer_name}.{os.getpid()}.{time.time_ns()}.tmp"
    try:
        os.symlink(target, temporary_name, dir_fd=directory_fd)
        os.replace(temporary_name, pointer_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: object) -> None:
    """Atomically persist a small runtime control record."""

    _atomic_write(path, value)


def read_json(path: Path, default: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return default


def runtime_state_path(root: Path) -> Path:
    root, _releases, state = validate_runtime_layout(root, create_state=True)
    return state / RUNTIME_STATE


def runtime_state_lock_path(root: Path) -> Path:
    root, _releases, state = validate_runtime_layout(root, create_state=True)
    return state / "runtime-health.lock"


def release_activation_journal_path(root: Path) -> Path:
    root, _releases, state = validate_runtime_layout(root, create_state=True)
    return state / RELEASE_ACTIVATION_JOURNAL


def _strict_runtime_state(path: Path, *, directory_fd: int | None = None) -> dict[str, Any]:
    if directory_fd is not None:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return {}
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise RuntimeError("runtime state is unsafe")
            with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
                descriptor = -1
                value = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("runtime health state is unreadable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(value, dict):
            raise RuntimeError("runtime health state is not an object")
        return value
    if not path.absolute().exists():
        return {}
    validate_runtime_file(path, label="runtime state")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime health state is unreadable") from exc
    if not isinstance(value, dict):
        raise RuntimeError("runtime health state is not an object")
    return value


def _read_private_state_at(name: str, directory_fd: int) -> tuple[bytes, int] | None:
    """Read one state file through a stable directory fd without following links."""

    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RuntimeError("runtime health state is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read(), stat.S_IMODE(metadata.st_mode)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _deployment_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    release_id = manifest.get("releaseId")
    policy_digest = manifest.get("policyDigest")
    if not isinstance(release_id, str) or not release_id:
        raise RuntimeError("release identity is missing a releaseId")
    if not isinstance(policy_digest, str) or not policy_digest:
        raise RuntimeError("release identity is missing a policyDigest")
    return {
        "releaseVersion": release_id,
        "policyDigest": policy_digest,
        "manifestVerified": True,
        "deploymentDirty": False,
    }


def _pointer_target(pointer: Path, *, directory_fd: int | None = None) -> str | None:
    if directory_fd is not None:
        try:
            metadata = os.stat(pointer.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError("release pointer must be a symlink")
        raw_target = os.readlink(pointer.name, dir_fd=directory_fd)
        target = Path(raw_target)
        if not target.is_absolute():
            target = pointer.parent / target
        return str(Path(os.path.realpath(str(target))))
    try:
        metadata = os.lstat(pointer)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(metadata.st_mode):
        raise RuntimeError("release pointer must be a symlink")
    return str(pointer.resolve())


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("release directory identity is not a directory")
    return metadata.st_dev, metadata.st_ino


def _require_directory_identity(path: Path, descriptor: int, *, label: str) -> None:
    expected = _directory_identity(descriptor)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{label} changed during activation") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected
    ):
        raise RuntimeError(f"{label} changed during activation")


def _validated_release_target(root: Path, value: str | Path) -> Path:
    """Validate a journal/pointer target without following an external path."""

    root, releases, _state = validate_runtime_layout(root, create_state=True)
    target = Path(os.path.realpath(str(value)))
    if target.parent != releases:
        raise RuntimeError("release activation target escapes runtime releases")
    metadata = os.lstat(target)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("release activation target must be a real directory")
    return target


def _restore_runtime_state(
    path: Path, payload: bytes | None, mode: int | None, *, directory_fd: int | None = None
) -> None:
    if payload is None:
        if directory_fd is not None:
            _unlink_at(path.name, directory_fd)
            os.fsync(directory_fd)
        else:
            path.unlink(missing_ok=True)
            _fsync_directory(path.parent)
        return
    _atomic_write_bytes(path, payload, mode=mode or 0o600, directory_fd=directory_fd)


def _recover_release_activation_unlocked(
    root: Path, *, state_directory_fd: int | None = None, root_directory_fd: int | None = None
) -> str | None:
    journal_path = release_activation_journal_path(root)
    if state_directory_fd is not None:
        try:
            os.stat(journal_path.name, dir_fd=state_directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
    elif not journal_path.exists():
        return None
    journal = _strict_runtime_state(journal_path, directory_fd=state_directory_fd)
    pointer = root / RELEASE_POINTER
    state_path = runtime_state_path(root)
    new_target = str(journal.get("newTarget") or "")
    old_target = journal.get("oldTarget")
    new_identity = journal.get("newDeployment")
    new_target_path = _validated_release_target(root, new_target)
    old_target_path = (
        _validated_release_target(root, str(old_target)) if old_target is not None else None
    )
    current_state = _strict_runtime_state(state_path, directory_fd=state_directory_fd)
    current_deployment = current_state.get("deployment")
    current_target = _pointer_target(pointer, directory_fd=root_directory_fd)
    committed = (
        current_target == str(new_target_path)
        and isinstance(current_deployment, dict)
        and all(current_deployment.get(key) == value for key, value in new_identity.items())
    )
    if committed:
        if state_directory_fd is not None:
            _unlink_at(journal_path.name, state_directory_fd)
            os.fsync(state_directory_fd)
        else:
            journal_path.unlink(missing_ok=True)
            _fsync_directory(journal_path.parent)
        return "committed"

    if old_target:
        _atomic_pointer_write(pointer, old_target_path, directory_fd=root_directory_fd)
    else:
        if root_directory_fd is not None:
            _unlink_at(pointer.name, root_directory_fd)
            os.fsync(root_directory_fd)
        else:
            pointer.unlink(missing_ok=True)
            _fsync_directory(pointer.parent)
    encoded = journal.get("oldStateBytes")
    old_payload = base64.b64decode(encoded) if isinstance(encoded, str) else None
    _restore_runtime_state(
        state_path, old_payload, journal.get("oldStateMode"), directory_fd=state_directory_fd
    )
    if state_directory_fd is not None:
        _unlink_at(journal_path.name, state_directory_fd)
        os.fsync(state_directory_fd)
    else:
        journal_path.unlink(missing_ok=True)
        _fsync_directory(journal_path.parent)
    return "rolled_back"


def recover_release_activation(root: Path) -> str | None:
    """Finish or roll back an interrupted release/health transaction."""

    root = root.absolute()
    validate_runtime_layout(root, create_state=True)
    root_fd, _ = open_directory_handle(root, label="runtime root")
    state_fd, _ = open_directory_handle(root / "state", label="runtime state", required_mode=0o700)
    try:
        with exclusive_lock(runtime_state_lock_path(root), blocking=True, directory_fd=state_fd):
            return _recover_release_activation_unlocked(
                root, state_directory_fd=state_fd, root_directory_fd=root_fd
            )
    finally:
        os.close(state_fd)
        os.close(root_fd)


def activate_release_pointer(
    root: Path,
    release: Path,
    manifest: dict[str, Any],
    *,
    expected_release_identity: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Atomically bind the active release pointer to its runtime identity.

    The journal makes a crash between pointer replacement and health-state
    replacement recoverable. A failed write restores both previous files; a
    pending journal causes strict readers to remain fail-closed until the next
    activation call repairs it.
    """

    root = root.absolute()
    root, releases, _state = validate_runtime_layout(root, create_state=True)
    release = Path(os.path.realpath(str(release)))
    if release.parent != releases:
        raise RuntimeError("release activation escapes the runtime releases directory")
    release_metadata = os.lstat(release)
    if stat.S_ISLNK(release_metadata.st_mode) or not stat.S_ISDIR(release_metadata.st_mode):
        raise RuntimeError("release activation target must be a real directory")
    identity = _deployment_identity(manifest)
    root_fd = release_fd = state_fd = -1
    old_release_fd: int | None = None
    try:
        root_fd, root = open_directory_handle(root, label="runtime root")
        _require_directory_identity(root, root_fd, label="runtime root")
        releases = root / "releases"
        release = releases / release.name
        release_fd, release = open_directory_handle(release, label="release")
        state_fd, state = open_directory_handle(
            root / "state", label="runtime state", required_mode=0o700
        )
        pointer = root / RELEASE_POINTER
        state_path = state / RUNTIME_STATE
        journal_path = state / RELEASE_ACTIVATION_JOURNAL
        with exclusive_lock(state / "runtime-health.lock", blocking=True, directory_fd=state_fd):
            _require_directory_identity(root, root_fd, label="runtime root")
            _require_directory_identity(state, state_fd, label="runtime state")
            if (
                expected_release_identity is not None
                and _directory_identity(release_fd) != expected_release_identity
            ):
                raise RuntimeError("release activation target changed")
            _require_directory_identity(release, release_fd, label="release")
            _recover_release_activation_unlocked(
                root, state_directory_fd=state_fd, root_directory_fd=root_fd
            )
            _require_directory_identity(root, root_fd, label="runtime root")
            old_target = _pointer_target(pointer, directory_fd=root_fd)
            if old_target is not None:
                old_target = str(_validated_release_target(root, old_target))
            old_target_value = old_target
            old_target_bound = Path(old_target) if old_target is not None else None
            if old_target_bound is not None:
                old_release_fd, old_target_bound = open_directory_handle(
                    old_target_bound, label="previous release"
                )
            old_state = _read_private_state_at(state_path.name, state_fd)
            old_state_payload = old_state[0] if old_state is not None else None
            old_state_mode = old_state[1] if old_state is not None else None
            journal = {
                "schema": "oss-pr-radar.release-activation.v1",
                "oldTarget": old_target_value,
                "newTarget": str(release),
                "oldStateBytes": base64.b64encode(old_state_payload).decode("ascii")
                if old_state_payload is not None
                else None,
                "oldStateMode": old_state_mode,
                "newDeployment": identity,
                "phase": "prepared",
            }
            journal_written = False
            try:
                _atomic_write(journal_path, journal, directory_fd=state_fd)
                journal_written = True
                _require_directory_identity(root, root_fd, label="runtime root")
                _require_directory_identity(state, state_fd, label="runtime state")
                _atomic_pointer_write(pointer, release, directory_fd=root_fd)
                _require_directory_identity(root, root_fd, label="runtime root")
                _require_directory_identity(release, release_fd, label="release")
                if _pointer_target(pointer, directory_fd=root_fd) != str(release):
                    raise RuntimeError("release pointer changed during activation")
                journal["phase"] = "pointer-active"
                _atomic_write(journal_path, journal, directory_fd=state_fd)
                health = _strict_runtime_state(state_path, directory_fd=state_fd)
                deployment = health.get("deployment")
                deployment = dict(deployment) if isinstance(deployment, dict) else {}
                deployment.update(identity)
                health["schemaVersion"] = RUNTIME_SCHEMA
                health["deployment"] = deployment
                _atomic_write(state_path, health, directory_fd=state_fd)
                _strict_runtime_state(state_path, directory_fd=state_fd)
                journal["phase"] = "health-active"
                _atomic_write(journal_path, journal, directory_fd=state_fd)
                _require_directory_identity(root, root_fd, label="runtime root")
                _require_directory_identity(state, state_fd, label="runtime state")
                _require_directory_identity(release, release_fd, label="release")
                _unlink_at(journal_path.name, state_fd)
                os.fsync(state_fd)
            except Exception:
                if journal_written:
                    if old_target_value is not None:
                        restore_target = old_target_value
                        if old_release_fd is not None:
                            restore_target = str(
                                _path_from_directory_fd(old_release_fd, label="previous release")
                            )
                        _restore_pointer_target(pointer.name, restore_target, root_fd)
                    else:
                        _unlink_at(pointer.name, root_fd)
                        os.fsync(root_fd)
                    _restore_runtime_state(
                        state_path, old_state_payload, old_state_mode, directory_fd=state_fd
                    )
                    _unlink_at(journal_path.name, state_fd)
                    os.fsync(state_fd)
                raise
        return identity
    finally:
        if old_release_fd is not None:
            os.close(old_release_fd)
        if release_fd >= 0:
            os.close(release_fd)
        if state_fd >= 0:
            os.close(state_fd)
        if root_fd >= 0:
            os.close(root_fd)


def queue_state_path(root: Path) -> Path:
    return root / "state" / QUEUE_STATE


def operation_log_path(root: Path) -> Path:
    return root / "state" / OPERATIONS_DIR / "operations.ndjson"


@contextmanager
def exclusive_lock(
    path: Path, *, blocking: bool = False, directory_fd: int | None = None
) -> Iterator[None]:
    """Acquire a process lock, optionally waiting for a state writer."""

    path = path.absolute()
    owns_directory = directory_fd is None
    if owns_directory:
        directory_fd, _ = open_directory_handle(
            path.parent, label="runtime lock parent", create=True, required_mode=0o700
        )
    assert directory_fd is not None
    try:
        try:
            metadata = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and (
            stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
        ):
            raise RuntimeError("runtime lock must be a regular file")
        descriptor = -1
        for attempt in range(20):
            try:
                descriptor = os.open(
                    path.name,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                break
            except FileNotFoundError:
                if attempt == 19:
                    raise
                time.sleep(0.001)
    except Exception:
        if owns_directory:
            os.close(directory_fd)
        raise
    os.fchmod(descriptor, 0o600)
    try:
        with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
            try:
                operation = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
                fcntl.flock(handle.fileno(), operation)
            except BlockingIOError as exc:
                raise RuntimeLockBusy(str(path)) from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        if owns_directory:
            os.close(directory_fd)


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
    max_inflight_seconds: int,
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
    in_flight = worker == "slow" and state.get("inFlight") is True
    attempt_started = _parse_epoch(state.get("attemptStartedAt"))
    worker_pid_alive = False
    if in_flight and state.get("workerPidAlive") is True:
        recorded_pid = state.get("workerPid")
        try:
            recorded_pid = int(recorded_pid)
        except (TypeError, ValueError):
            recorded_pid = None
        if (
            isinstance(recorded_pid, int)
            and not isinstance(recorded_pid, bool)
            and recorded_pid > 0
        ):
            pid_evidence = pid_probe(
                recorded_pid,
                expected_fragment="slow_publication_worker.py",
            )
            worker_pid_alive = (
                pid_evidence.get("alive") is True and pid_evidence.get("versionMatched") is True
            )
    if in_flight:
        if not worker_pid_alive:
            issues.append("INFLIGHT_PID_NOT_ALIVE")
        elif attempt_started is None or now - attempt_started > max_inflight_seconds:
            issues.append("INFLIGHT_TIMEOUT")
    elif success is None or now - success > max_age:
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
        "inFlight": bool(state.get("inFlight")) if worker == "slow" else False,
        "attemptStartedAt": state.get("attemptStartedAt") if worker == "slow" else None,
        "workerPid": state.get("workerPid") if worker == "slow" else None,
        "workerPidAlive": worker_pid_alive if worker == "slow" else None,
    }


def evaluate_health(
    state: dict[str, Any],
    *,
    now: float | None = None,
    max_success_age_seconds: int = 120,
    max_queue_age_seconds: int = 900,
    max_inflight_seconds: int = SLOW_INFLIGHT_MAX_SECONDS,
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
    warnings: list[str] = []
    for worker in REQUIRED_WORKERS if nested else ("runtime",):
        worker_state = worker_states.get(worker)
        worker_state = worker_state if isinstance(worker_state, dict) else {}
        result = _worker_health(
            worker,
            worker_state,
            now=current,
            max_success_age_seconds=max_success_age_seconds,
            max_queue_age_seconds=max_queue_age_seconds,
            max_inflight_seconds=max_inflight_seconds,
            max_failures=max_failures,
        )
        workers[worker] = result
        issues.extend(f"{worker}:{issue}" if nested else issue for issue in result["issues"])
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
        warnings.append("DISK_WARNING_THRESHOLD")
    if log_bytes is not None and log_bytes > max_log_bytes:
        issues.append("LOG_LIMIT_EXCEEDED")
    return {
        "healthy": not issues,
        "issues": issues,
        "warnings": warnings,
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
    state_fd, _ = open_directory_handle(path.parent, label="runtime state", required_mode=0o700)
    try:
        with exclusive_lock(
            path.parent / "runtime-health.lock", blocking=True, directory_fd=state_fd
        ):
            current = _strict_runtime_state(path, directory_fd=state_fd)
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
            deployment = (
                state.get("deployment") if isinstance(state.get("deployment"), dict) else {}
            )
            if release_version is not None:
                deployment["releaseVersion"] = release_version
            if policy_digest is not None:
                deployment["policyDigest"] = policy_digest
            state["deployment"] = deployment
            aggregate = evaluate_health(state)
            state["aggregate"] = aggregate
            _atomic_write(path, state, directory_fd=state_fd)
    finally:
        os.close(state_fd)
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
    state_fd, _ = open_directory_handle(path.parent, label="runtime state", required_mode=0o700)
    try:
        with exclusive_lock(
            path.parent / "runtime-health.lock", blocking=True, directory_fd=state_fd
        ):
            current = _strict_runtime_state(path, directory_fd=state_fd)
            state = dict(current) if isinstance(current, dict) else {}
            workers = state.get("workers") if isinstance(state.get("workers"), dict) else {}
            worker_state = dict(workers.get(worker) or {})
            worker_state.update(updates)
            workers[worker] = worker_state
            state["schemaVersion"] = RUNTIME_SCHEMA
            state["workers"] = workers
            current_deployment = (
                dict(state.get("deployment")) if isinstance(state.get("deployment"), dict) else {}
            )
            if deployment:
                current_deployment.update(deployment)
            state["deployment"] = current_deployment
            state["aggregate"] = evaluate_health(state)
            _atomic_write(path, state, directory_fd=state_fd)
            return state
    finally:
        os.close(state_fd)


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
