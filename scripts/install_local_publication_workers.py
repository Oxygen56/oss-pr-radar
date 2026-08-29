#!/usr/bin/env python3
"""Install the fast, slow, and signed-queue worker LaunchAgents together."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

FIXED_WORKER_LABELS = (
    "com.oss-pr-radar.local-publication",
    "com.oss-pr-radar.local-publication-slow",
    "com.oss-pr-radar.queue-importer",
)

from oss_pr_radar.launch_config import parse_launchctl_config  # noqa: E402
from oss_pr_radar.local_publication import SLOW_WORK_LOCK, worker_specs  # noqa: E402
from oss_pr_radar.operational_auth import (  # noqa: E402
    authorization_path,
    consume_worker_staging_authorization,
    finalize_operational_authorization,
    require_operational_authorization,
    require_worker_staging_authorization,
    revoke_operational_authorization,
    staged_worker_receipt_path,
    worker_spec_digest,
    worker_staging_transaction_lock,
)
from oss_pr_radar.release_binding import runtime_ledger_path  # noqa: E402
from oss_pr_radar.runtime import (  # noqa: E402
    REQUIRED_WORKERS,
    RuntimeLockBusy,
    disk_snapshot,
    evaluate_health,
    exclusive_lock,
    pending_publication_effects,
    pid_probe,
    read_disk_pressure_gate_health,
    read_json,
)
from oss_pr_radar.runtime_audit import active_release_evidence  # noqa: E402


def launchctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["launchctl", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


@dataclass(frozen=True)
class PlistSnapshot:
    service: str
    path: Path
    exists: bool
    data: bytes | None
    mode: int | None
    loaded: bool


def _checked_launchctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    result = launchctl(*arguments, check=True)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            ["launchctl", *arguments],
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


def _loaded(service: str) -> bool:
    return launchctl("print", service, check=False).returncode == 0


def _snapshot_plist(service: str, path: Path) -> PlistSnapshot:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return PlistSnapshot(service, path, False, None, None, _loaded(service))
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"LaunchAgent plist is not a regular file: {path}")
    return PlistSnapshot(
        service,
        path,
        True,
        path.read_bytes(),
        stat.S_IMODE(metadata.st_mode),
        _loaded(service),
    )


def _validate_specs(specs: list[dict[str, object]]) -> None:
    if len(specs) != 3:
        raise RuntimeError(f"expected three worker specs, got {len(specs)}")
    labels: set[str] = set()
    required = {
        "Label",
        "ProgramArguments",
        "WorkingDirectory",
        "StandardOutPath",
        "StandardErrorPath",
    }
    for spec in specs:
        if not isinstance(spec, dict) or not required.issubset(spec):
            raise RuntimeError("worker spec is incomplete")
        label = spec["Label"]
        if not isinstance(label, str) or not label or "/" in label or label in labels:
            raise RuntimeError("worker spec labels are invalid or duplicated")
        if not isinstance(spec["ProgramArguments"], list) or not spec["ProgramArguments"]:
            raise RuntimeError(f"worker spec arguments are invalid: {label}")
        labels.add(label)


def _atomic_replace(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    open_descriptor: int | None = descriptor
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            open_descriptor = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if open_descriptor is not None:
            os.close(open_descriptor)
        temporary.unlink(missing_ok=True)


def _write_plist_atomically(path: Path, spec: dict[str, object], mode: int) -> None:
    _atomic_replace(path, plistlib.dumps(spec, fmt=plistlib.FMT_XML, sort_keys=True), mode)


def _snapshot_workers(
    specs: list[dict[str, object]], *, home: Path, domain: str
) -> list[PlistSnapshot]:
    snapshots = []
    paths: set[Path] = set()
    services: set[str] = set()
    for spec in specs:
        label = str(spec["Label"])
        service = f"{domain}/{label}"
        path = home / "Library" / "LaunchAgents" / f"{label}.plist"
        if path in paths or service in services:
            raise RuntimeError("worker plist targets are duplicated")
        paths.add(path)
        services.add(service)
        snapshots.append(_snapshot_plist(service, path))
    return snapshots


def _restore_snapshot(snapshot: PlistSnapshot) -> None:
    if snapshot.exists:
        assert snapshot.data is not None and snapshot.mode is not None
        _atomic_replace(snapshot.path, snapshot.data, snapshot.mode)
    else:
        snapshot.path.unlink(missing_ok=True)


def _rollback(snapshots: list[PlistSnapshot], touched: list[str], *, domain: str) -> list[str]:
    errors: list[str] = []
    touched_services = set(touched)
    touched_snapshots = [snapshot for snapshot in snapshots if snapshot.service in touched_services]
    for service in reversed(touched):
        try:
            launchctl("bootout", service, check=False)
        except Exception as exc:  # best effort: continue restoring every target
            errors.append(f"bootout {service}: {type(exc).__name__}:{exc}")
    for snapshot in touched_snapshots:
        try:
            _restore_snapshot(snapshot)
        except Exception as exc:
            errors.append(f"restore {snapshot.path}: {type(exc).__name__}:{exc}")
    for snapshot in touched_snapshots:
        if not snapshot.loaded:
            continue
        try:
            _checked_launchctl("bootstrap", domain, str(snapshot.path))
        except Exception as exc:
            errors.append(f"reload {snapshot.service}: {type(exc).__name__}:{exc}")
    for snapshot in touched_snapshots:
        try:
            if _loaded(snapshot.service) != snapshot.loaded:
                expected = "loaded" if snapshot.loaded else "unloaded"
                errors.append(f"restore {snapshot.service}: service not {expected}")
        except Exception as exc:
            errors.append(f"verify {snapshot.service}: {type(exc).__name__}:{exc}")
    return errors


def _config_matches(path: Path, expected: dict[str, object]) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        actual = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException):
        return False
    return isinstance(actual, dict) and actual == expected


def _launchctl_config_matches(service: str, expected: dict[str, object]) -> bool:
    """Require launchd's loaded command to match the immutable worker spec."""

    result = launchctl("print", service, check=False)
    if result.returncode != 0:
        return False
    actual = parse_launchctl_config(result.stdout or "")
    return actual.get("ProgramArguments") == [
        str(item) for item in expected["ProgramArguments"]
    ] and actual.get("WorkingDirectory") == str(expected["WorkingDirectory"])


def service_status(
    service: str,
    plist_path: Path,
    expected: dict,
    *,
    disk: dict | None = None,
    disk_pressure_gate: dict | None = None,
) -> dict:
    """Read one worker status without changing launchd or the managed ledger."""

    result = launchctl("print", service, check=False)
    output = result.stdout or result.stderr or ""
    runs = re.search(r"\bruns = (\d+)", output)
    last_exit = re.search(r"\blast exit code = (-?\d+)", output)
    pid_match = re.search(r"\bpid = (\d+)", output)
    error_path = Path(str(expected["StandardErrorPath"]))
    error_bytes = error_path.stat().st_size if error_path.exists() else 0
    loaded = result.returncode == 0
    config_current = _config_matches(plist_path, expected)
    last_exit_code = int(last_exit.group(1)) if last_exit else None
    pid = int(pid_match.group(1)) if pid_match else None
    root = Path(str(expected["WorkingDirectory"]))
    process = pid_probe(pid, expected_fragment=str(root))
    worker = {
        FIXED_WORKER_LABELS[0]: "fast",
        FIXED_WORKER_LABELS[1]: "slow",
        FIXED_WORKER_LABELS[2]: "queue-importer",
    }.get(str(expected.get("Label")), "fast")
    release = active_release_evidence(root)
    # Status is deliberately observational: evaluate the complete persisted
    # worker state in memory and never update runtime-health.json or the ledger.
    persisted = read_json(root / "state" / "runtime-health.json", {})
    persisted = persisted if isinstance(persisted, dict) else {}
    runtime_state = dict(persisted)
    deployment = (
        dict(persisted.get("deployment")) if isinstance(persisted.get("deployment"), dict) else {}
    )
    deployment.update(
        {
            "manifestVerified": release.get("valid") is True,
            "deploymentDirty": release.get("valid") is not True,
            "releaseVersion": release.get("releaseId"),
            "policyDigest": release.get("policyDigest"),
            "pendingPublicationEffects": pending_publication_effects(runtime_ledger_path(root)),
        }
    )
    runtime_state["deployment"] = deployment
    backoff = read_json(root / "state" / "slow-worker-backoff.json", {})
    backoff = backoff if isinstance(backoff, dict) else {}
    try:
        backoff_failures = max(0, int(backoff.get("failureCount") or 0))
    except (TypeError, ValueError):
        backoff_failures = 0
    if backoff_failures:
        workers = (
            dict(runtime_state.get("workers"))
            if isinstance(runtime_state.get("workers"), dict)
            else {}
        )
        slow_state = dict(workers.get("slow") or {})
        slow_state["consecutiveFailures"] = max(
            int(slow_state.get("consecutiveFailures") or 0), backoff_failures
        )
        if slow_state.get("lastExitCode") in {None, 0}:
            slow_state["lastExitCode"] = 1
        workers["slow"] = slow_state
        runtime_state["workers"] = workers
    if disk_pressure_gate is None:
        disk = disk_snapshot(root)
        disk_pressure_gate = read_disk_pressure_gate_health(
            root, snapshot_fn=lambda _root: dict(disk)
        )
    elif disk is None and isinstance(disk_pressure_gate.get("snapshot"), dict):
        disk = dict(disk_pressure_gate["snapshot"])
    log_bytes = sum(
        path.stat().st_size
        for path in (
            Path(str(expected["StandardOutPath"])),
            Path(str(expected["StandardErrorPath"])),
        )
        if path.exists()
    )
    health = evaluate_health(
        runtime_state,
        expected_release=release.get("releaseId") if release.get("valid") else None,
        expected_policy_digest=release.get("policyDigest") if release.get("valid") else None,
        disk=disk,
        disk_pressure_gate=disk_pressure_gate,
        log_bytes=log_bytes,
    )
    if pid is not None and not process["alive"]:
        health["issues"].append("PID_NOT_ALIVE")
        health["healthy"] = False
    if pid is not None and not process["versionMatched"]:
        health["issues"].append("PROCESS_VERSION_MISMATCH")
        health["healthy"] = False
    worker_health = (health.get("workers") or {}).get(worker) or {}
    shared_issues = [
        issue
        for issue in health.get("issues") or []
        if not any(issue.startswith(f"{required}:") for required in REQUIRED_WORKERS)
    ]
    return {
        "ok": (
            loaded
            and config_current
            and worker_health.get("healthy") is True
            and not shared_issues
            and last_exit_code in {None, 0}
            and (pid is None or process["alive"] is True)
            and (pid is None or process["versionMatched"] is True)
        ),
        "installed": loaded,
        "configCurrent": config_current,
        "runs": int(runs.group(1)) if runs else 0,
        "lastExitCode": last_exit_code,
        "errorLogBytes": error_bytes,
        "pid": pid,
        "process": process,
        "runtimeHealth": health,
        "workerRuntimeHealth": worker_health,
        "label": str(expected.get("Label")),
    }


def install_workers(
    specs: list[dict[str, object]], *, home: Path, domain: str
) -> dict[str, object]:
    """Install every worker as one rollback-capable transaction."""

    _validate_specs(specs)
    snapshots = _snapshot_workers(specs, home=home, domain=domain)
    touched: list[str] = []
    try:
        for spec in specs:
            Path(str(spec["StandardOutPath"])).parent.mkdir(parents=True, exist_ok=True)
            Path(str(spec["StandardErrorPath"])).parent.mkdir(parents=True, exist_ok=True)
        for spec, snapshot in zip(specs, snapshots, strict=True):
            touched.append(snapshot.service)
            if snapshot.loaded:
                _checked_launchctl("bootout", snapshot.service)
            mode = snapshot.mode if snapshot.mode is not None else 0o600
            _write_plist_atomically(snapshot.path, spec, mode)
            _checked_launchctl("bootstrap", domain, str(snapshot.path))
            _checked_launchctl("kickstart", "-k", snapshot.service)
        for spec, snapshot in zip(specs, snapshots, strict=True):
            if not _config_matches(snapshot.path, spec) or not _loaded(snapshot.service):
                raise RuntimeError(f"worker validation failed: {snapshot.service}")
    except Exception as exc:
        rollback_errors = _rollback(snapshots, touched, domain=domain)
        detail = f"{type(exc).__name__}:{exc}"
        if rollback_errors:
            detail += "; rollback=" + ", ".join(rollback_errors)
        raise RuntimeError(f"worker installation rolled back: {detail}") from exc
    return {
        "ok": True,
        "workers": [{"label": str(spec["Label"]), "installed": True} for spec in specs],
    }


def stage_workers(
    specs: list[dict[str, object]],
    *,
    home: Path,
    domain: str,
    allow_unload: bool = False,
    replace_complete_unloaded: bool = False,
) -> dict[str, object]:
    """Write exact release plists and leave every worker unloaded."""

    _validate_specs(specs)
    if allow_unload and replace_complete_unloaded:
        raise RuntimeError("worker staging replacement modes are mutually exclusive")
    snapshots = _snapshot_workers(specs, home=home, domain=domain)
    if not allow_unload:
        if any(snapshot.loaded for snapshot in snapshots):
            raise RuntimeError("stage refuses to unload a loaded worker")
        present = [snapshot.exists for snapshot in snapshots]
        if any(present) and not all(present):
            raise RuntimeError("partial staged worker configuration refuses recovery")
        if all(present):
            if any(snapshot.mode != 0o600 for snapshot in snapshots):
                raise RuntimeError("unsafe staged worker configuration refuses recovery")
            conflicting = any(
                not _config_matches(snapshot.path, spec)
                for snapshot, spec in zip(snapshots, specs, strict=True)
            )
            if conflicting and not replace_complete_unloaded:
                raise RuntimeError("conflicting staged worker configuration refuses recovery")
            if not conflicting:
                return {
                    "ok": True,
                    "staged": True,
                    "loaded": False,
                    "changed": False,
                    "workers": [{"label": str(spec["Label"]), "staged": True} for spec in specs],
                }
    touched: list[str] = []
    try:
        for spec, snapshot in zip(specs, snapshots, strict=True):
            touched.append(snapshot.service)
            if snapshot.loaded and allow_unload:
                _checked_launchctl("bootout", snapshot.service)
            mode = snapshot.mode if snapshot.mode is not None else 0o600
            _write_plist_atomically(snapshot.path, spec, mode)
        for spec, snapshot in zip(specs, snapshots, strict=True):
            if not _config_matches(snapshot.path, spec) or _loaded(snapshot.service):
                raise RuntimeError(f"worker staging validation failed: {snapshot.service}")
    except Exception as exc:
        rollback_errors = _rollback(snapshots, touched, domain=domain)
        detail = f"{type(exc).__name__}:{exc}"
        if rollback_errors:
            detail += "; rollback=" + ", ".join(rollback_errors)
        raise RuntimeError(f"worker staging rolled back: {detail}") from exc
    return {
        "ok": True,
        "staged": True,
        "loaded": False,
        "changed": True,
        "workers": [{"label": str(spec["Label"]), "staged": True} for spec in specs],
    }


def _staging_records(
    specs: list[dict[str, object]], *, home: Path, domain: str
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    launch_dir = (home / "Library" / "LaunchAgents").resolve()
    digest = worker_spec_digest(specs)
    for spec in specs:
        label = str(spec["Label"])
        path = launch_dir / f"{label}.plist"
        service = f"{domain}/{label}"
        observation = launchctl("print", service, check=False)
        if observation.returncode == 0:
            raise RuntimeError(f"worker is loaded during stage observation: {label}")
        metadata = path.lstat()
        raw = path.read_bytes()
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        records.append(
            {
                "worker": label,
                "label": label,
                "plistPath": str(path),
                "plistSha256": hashlib.sha256(raw).hexdigest(),
                "mode": "0o%03o" % (metadata.st_mode & 0o777),
                "ownerUid": metadata.st_uid,
                "regular": stat.S_ISREG(metadata.st_mode),
                "symlink": stat.S_ISLNK(metadata.st_mode),
                "loaded": observation.returncode == 0,
                "pid": None,
                "specDigest": digest,
                "observedAt": now,
            }
        )
    return records


def activate_staged_workers(
    specs: list[dict[str, object]],
    *,
    home: Path,
    domain: str,
    runtime_root: Path,
    require_stage_receipt: bool = True,
) -> dict[str, object]:
    """Load workers only after the current operational authorization verifies."""

    authorization = require_operational_authorization(
        runtime_root, require_staged_receipt=require_stage_receipt
    )
    _validate_specs(specs)
    snapshots = _snapshot_workers(specs, home=home, domain=domain)
    if authorization.get("workerConfigDigest") != worker_spec_digest(specs):
        raise RuntimeError("operational authorization worker spec mismatch")
    # A first activation must start from three observed unloaded services.
    # A matching plist is not evidence that launchd is running that plist:
    # launchd may still have an older cached service under the same label.
    # Steady-state --ensure is the only path allowed to handle loaded workers.
    if require_stage_receipt and any(snapshot.loaded for snapshot in snapshots):
        raise RuntimeError("workers must be explicitly unloaded before first activation")
    if any(
        snapshot.loaded or not _config_matches(snapshot.path, spec)
        for snapshot, spec in zip(snapshots, specs, strict=True)
    ):
        raise RuntimeError("workers must be staged and unloaded before activation")
    touched: list[str] = []
    try:
        # The bridge performs its own authorization check before any worker
        # operation, including reproduction-probe.  Promote the staged proof
        # before bootstrap so the first process cannot observe STAGED auth.
        if require_stage_receipt:
            finalize_operational_authorization(runtime_root)
        for _spec, snapshot in zip(specs, snapshots, strict=True):
            touched.append(snapshot.service)
            _checked_launchctl("bootstrap", domain, str(snapshot.path))
            _checked_launchctl("kickstart", "-k", snapshot.service)
        if any(
            not _loaded(snapshot.service) or not _launchctl_config_matches(snapshot.service, spec)
            for snapshot, spec in zip(snapshots, specs, strict=True)
        ):
            raise RuntimeError("worker activation validation failed")
    except Exception as exc:
        rollback_errors = _rollback(snapshots, touched, domain=domain)
        if require_stage_receipt:
            try:
                revoke_operational_authorization(runtime_root)
            except Exception as revoke_exc:
                rollback_errors.append(
                    f"revoke authorization: {type(revoke_exc).__name__}:{revoke_exc}"
                )
        detail = f"{type(exc).__name__}:{exc}"
        if rollback_errors:
            detail += "; rollback=" + ", ".join(rollback_errors)
        raise RuntimeError(f"worker activation rolled back: {detail}") from exc
    return {
        "ok": True,
        "activated": True,
        "loaded": True,
        "workers": [{"label": str(spec["Label"]), "activated": True} for spec in specs],
    }


def ensure_workers(
    specs: list[dict[str, object]], *, home: Path, domain: str, runtime_root: Path
) -> dict[str, object]:
    """Keep correctly loaded workers running, or repair them under authorization."""

    require_operational_authorization(runtime_root)
    _validate_specs(specs)
    snapshots = _snapshot_workers(specs, home=home, domain=domain)
    if all(
        snapshot.loaded
        and _config_matches(snapshot.path, spec)
        and _launchctl_config_matches(snapshot.service, spec)
        for snapshot, spec in zip(snapshots, specs, strict=True)
    ):
        return {
            "ok": True,
            "ensured": True,
            "loaded": True,
            "changed": False,
            "workers": [{"label": str(spec["Label"]), "ensured": True} for spec in specs],
        }
    if all(
        _config_matches(snapshot.path, spec)
        for snapshot, spec in zip(snapshots, specs, strict=True)
    ):
        return activate_staged_workers(
            specs, home=home, domain=domain, runtime_root=runtime_root, require_stage_receipt=False
        )
    stage_workers(specs, home=home, domain=domain, allow_unload=True)
    return activate_staged_workers(
        specs, home=home, domain=domain, runtime_root=runtime_root, require_stage_receipt=False
    )


def _snapshot_file_matches(snapshot: PlistSnapshot) -> bool:
    if not snapshot.exists:
        return not snapshot.path.exists() and not snapshot.path.is_symlink()
    try:
        metadata = snapshot.path.lstat()
        return (
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == snapshot.mode
            and snapshot.path.read_bytes() == snapshot.data
        )
    except OSError:
        return False


def _rollback_uninstall(snapshots: list[PlistSnapshot], *, domain: str) -> list[str]:
    errors: list[str] = []
    for snapshot in snapshots:
        try:
            _restore_snapshot(snapshot)
        except Exception as exc:
            errors.append(f"restore {snapshot.path}: {type(exc).__name__}:{exc}")
    for snapshot in snapshots:
        try:
            loaded = _loaded(snapshot.service)
            if snapshot.loaded and not loaded:
                _checked_launchctl("bootstrap", domain, str(snapshot.path))
            elif not snapshot.loaded and loaded:
                _checked_launchctl("bootout", snapshot.service)
        except Exception as exc:
            errors.append(f"restore {snapshot.service}: {type(exc).__name__}:{exc}")
    for snapshot in snapshots:
        if not _snapshot_file_matches(snapshot):
            errors.append(f"verify {snapshot.path}: plist state mismatch")
        try:
            if _loaded(snapshot.service) != snapshot.loaded:
                expected = "loaded" if snapshot.loaded else "unloaded"
                errors.append(f"verify {snapshot.service}: service not {expected}")
        except Exception as exc:
            errors.append(f"verify {snapshot.service}: {type(exc).__name__}:{exc}")
    return errors


def _uninstall_snapshots(snapshots: list[PlistSnapshot], *, domain: str) -> dict[str, object]:
    try:
        # First quiesce and verify the complete worker set.  Deleting even one
        # plist before all three services are down would invalidate the active
        # authorization and make an ordinary retry impossible.
        for snapshot in snapshots:
            if snapshot.loaded:
                _checked_launchctl("bootout", snapshot.service)
            if _loaded(snapshot.service):
                raise RuntimeError(f"worker remained loaded: {snapshot.service}")
        for snapshot in snapshots:
            snapshot.path.unlink(missing_ok=True)
        for snapshot in snapshots:
            if snapshot.path.exists() or snapshot.path.is_symlink():
                raise RuntimeError(f"worker plist remained installed: {snapshot.path}")
            if _loaded(snapshot.service):
                raise RuntimeError(f"worker reloaded during uninstall: {snapshot.service}")
    except Exception as exc:
        rollback_errors = _rollback_uninstall(snapshots, domain=domain)
        detail = f"{type(exc).__name__}:{exc}"
        if rollback_errors:
            raise RuntimeError(
                "worker uninstall rollback incomplete: "
                + detail
                + "; rollback="
                + ", ".join(rollback_errors)
            ) from exc
        raise RuntimeError(f"worker uninstall rolled back: {detail}") from exc

    return {
        "ok": True,
        "workers": [{"label": snapshot.path.stem, "installed": False} for snapshot in snapshots],
        "errors": [],
    }


def _require_slow_worker_quiescent(*, runtime_root: Path, domain: str) -> None:
    """Refuse to stop services while the durable slow cycle may still be running."""

    runtime = read_json(runtime_root / "state" / "runtime-health.json", {})
    workers = runtime.get("workers") if isinstance(runtime, dict) else None
    slow_health = workers.get("slow") if isinstance(workers, dict) else None
    backoff = read_json(runtime_root / "state" / "slow-worker-backoff.json", {})
    in_flight = (isinstance(slow_health, dict) and slow_health.get("inFlight") is True) or (
        isinstance(backoff, dict) and backoff.get("inFlight") is True
    )
    if in_flight:
        raise RuntimeError("worker uninstall refused: slow worker is in flight")

    service = f"{domain}/{FIXED_WORKER_LABELS[1]}"
    observation = launchctl("print", service, check=False)
    if observation.returncode != 0:
        return
    output = "\n".join(part for part in (observation.stdout, observation.stderr) if part)
    match = re.search(r"\bpid = (\d+)", output)
    if match is None:
        return
    pid = int(match.group(1))
    process = pid_probe(pid)
    if process.get("alive") is True:
        raise RuntimeError(f"worker uninstall refused: slow worker process is alive: {pid}")
    if process.get("error") not in {None, "ESRCH"}:
        raise RuntimeError(
            f"worker uninstall refused: slow worker process state is uncertain: {pid}"
        )


def uninstall_workers(
    specs: list[dict[str, object]], *, home: Path, domain: str, runtime_root: Path
) -> dict[str, object]:
    """Remove all workers transactionally after proving the slow lane is idle."""

    _validate_specs(specs)
    runtime_root = runtime_root.resolve()
    try:
        with exclusive_lock(runtime_root / "state" / SLOW_WORK_LOCK):
            _require_slow_worker_quiescent(runtime_root=runtime_root, domain=domain)
            snapshots = _snapshot_workers(specs, home=home, domain=domain)
            return _uninstall_snapshots(snapshots, domain=domain)
    except RuntimeLockBusy as exc:
        raise RuntimeError("worker uninstall refused: slow worker lock is busy") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--stage", action="store_true")
    mode.add_argument("--activate", action="store_true")
    mode.add_argument("--ensure", action="store_true")
    args = parser.parse_args()
    home = Path.home()
    domain = f"gui/{os.getuid()}"
    try:
        if args.runtime_root is None:
            raise RuntimeError("--runtime-root is required for status/install")
        runtime_root = args.runtime_root.resolve()
        release = active_release_evidence(runtime_root)
        if release.get("valid") is not True:
            raise RuntimeError(f"active release rejected: {release.get('error', 'unknown error')}")
        specs = worker_specs(
            Path(str(release["path"])),
            home=home,
            runtime_root=runtime_root,
        )
        _validate_specs(specs)
        if args.status:
            disk_pressure_gate = read_disk_pressure_gate_health(
                runtime_root, snapshot_fn=lambda root: disk_snapshot(root)
            )
            shared_disk = (
                dict(disk_pressure_gate["snapshot"])
                if isinstance(disk_pressure_gate.get("snapshot"), dict)
                else None
            )
            statuses: list[dict[str, object]] = []
            for spec in specs:
                label = str(spec["Label"])
                plist_path = home / "Library" / "LaunchAgents" / f"{label}.plist"
                status = service_status(
                    f"{domain}/{label}",
                    plist_path,
                    spec,
                    disk=shared_disk,
                    disk_pressure_gate=disk_pressure_gate,
                )
                status["label"] = label
                statuses.append(status)
            print(
                json.dumps(
                    {
                        "ok": (
                            disk_pressure_gate.get("ok") is True
                            and disk_pressure_gate.get("blocked") is False
                            and all(status.get("ok") is True for status in statuses)
                        ),
                        "diskPressureGate": disk_pressure_gate,
                        "workers": statuses,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.uninstall:
            require_operational_authorization(runtime_root)
            result = uninstall_workers(specs, home=home, domain=domain, runtime_root=runtime_root)
        elif args.stage:
            if (
                authorization_path(runtime_root).exists()
                or authorization_path(runtime_root).is_symlink()
            ):
                raise RuntimeError("--stage refuses to modify an already authorized runtime")
            with worker_staging_transaction_lock(runtime_root):
                receipt_path = staged_worker_receipt_path(runtime_root)
                replace_complete_unloaded = False
                if not receipt_path.exists():
                    require_worker_staging_authorization(
                        runtime_root, specs=specs, home=home, _lock_held=True
                    )
                    # Only a newly verified, release-bound staging permit may
                    # replace a complete unloaded trio from the prior release.
                    # Receipt recovery must validate its existing files first.
                    replace_complete_unloaded = True
                initial = _snapshot_workers(specs, home=home, domain=domain)
                changed = False
                try:
                    result = stage_workers(
                        specs,
                        home=home,
                        domain=domain,
                        replace_complete_unloaded=replace_complete_unloaded,
                    )
                    changed = result.get("changed") is True
                    receipt = consume_worker_staging_authorization(
                        runtime_root,
                        specs=specs,
                        worker_records=_staging_records(specs, home=home, domain=domain),
                        _lock_held=True,
                    )
                except Exception as exc:
                    # The signed receipt is the durable commit point. Before
                    # it exists, restore both newly created files and any
                    # complete unloaded prior-release trio replaced here.
                    if changed and not receipt_path.exists():
                        rollback_errors = _rollback(
                            initial,
                            [snapshot.service for snapshot in initial],
                            domain=domain,
                        )
                        if rollback_errors:
                            raise RuntimeError(
                                "worker staging receipt failed; rollback incomplete: "
                                + ", ".join(rollback_errors)
                            ) from exc
                    raise
            result["receipt"] = {
                "schema": receipt["schema"],
                "state": receipt["state"],
                "path": str(staged_worker_receipt_path(runtime_root)),
                "workerSpecDigest": receipt["workerSpecDigest"],
            }
        elif args.ensure:
            result = ensure_workers(specs, home=home, domain=domain, runtime_root=runtime_root)
        else:
            result = activate_staged_workers(
                specs, home=home, domain=domain, runtime_root=runtime_root
            )
        result["uninstalled"] = args.uninstall
        print(json.dumps(result, sort_keys=True))
        return 0 if result["ok"] is True else 1
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:800]}"},
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
