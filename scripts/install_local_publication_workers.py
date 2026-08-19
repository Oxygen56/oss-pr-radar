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
from oss_pr_radar.local_publication import worker_specs  # noqa: E402
from oss_pr_radar.operational_auth import (  # noqa: E402
    authorization_path,
    consume_worker_staging_authorization,
    finalize_operational_authorization,
    require_operational_authorization,
    require_worker_staging_authorization,
    staged_worker_receipt_path,
    worker_spec_digest,
    worker_staging_transaction_lock,
)
from oss_pr_radar.release_binding import runtime_ledger_path  # noqa: E402
from oss_pr_radar.runtime import (  # noqa: E402
    disk_snapshot,
    evaluate_health,
    pending_publication_effects,
    pid_probe,
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


def _rollback(
    snapshots: list[PlistSnapshot], touched: list[str], *, domain: str
) -> list[str]:
    errors: list[str] = []
    touched_services = set(touched)
    touched_snapshots = [
        snapshot for snapshot in snapshots if snapshot.service in touched_services
    ]
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
    return (
        actual.get("ProgramArguments") == [str(item) for item in expected["ProgramArguments"]]
        and actual.get("WorkingDirectory") == str(expected["WorkingDirectory"])
    )


def service_status(service: str, plist_path: Path, expected: dict) -> dict:
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
    # Status is deliberately observational: build the health input in memory
    # and never update runtime-health.json or the managed ledger.
    runtime_state = {
        "workers": {
            worker: {
                "lastExitCode": last_exit_code,
                "pid": pid,
                "pidAlive": process["alive"],
                "processVersionMatched": process["versionMatched"],
            }
        },
        "deployment": {
            "manifestVerified": release.get("valid") is True,
            "deploymentDirty": release.get("valid") is not True,
            "releaseVersion": release.get("releaseId"),
            "policyDigest": release.get("policyDigest"),
            "pendingPublicationEffects": pending_publication_effects(runtime_ledger_path(root)),
        },
    }
    disk = disk_snapshot(root)
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
        log_bytes=log_bytes,
    )
    if pid is not None and not process["alive"]:
        health["issues"].append("PID_NOT_ALIVE")
        health["healthy"] = False
    if pid is not None and not process["versionMatched"]:
        health["issues"].append("PROCESS_VERSION_MISMATCH")
        health["healthy"] = False
    return {
        "ok": loaded and config_current and health["healthy"],
        "installed": loaded,
        "configCurrent": config_current,
        "runs": int(runs.group(1)) if runs else 0,
        "lastExitCode": last_exit_code,
        "errorLogBytes": error_bytes,
        "pid": pid,
        "process": process,
        "runtimeHealth": health,
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
    specs: list[dict[str, object]], *, home: Path, domain: str, allow_unload: bool = False
) -> dict[str, object]:
    """Write exact release plists and leave every worker unloaded."""

    _validate_specs(specs)
    snapshots = _snapshot_workers(specs, home=home, domain=domain)
    if not allow_unload:
        if any(snapshot.loaded for snapshot in snapshots):
            raise RuntimeError("stage refuses to unload a loaded worker")
        present = [snapshot.exists for snapshot in snapshots]
        if any(present) and not all(present):
            raise RuntimeError("partial staged worker configuration refuses recovery")
        if all(present):
            if any(
                snapshot.mode != 0o600 or not _config_matches(snapshot.path, spec)
                for snapshot, spec in zip(snapshots, specs, strict=True)
            ):
                raise RuntimeError("conflicting staged worker configuration refuses recovery")
            return {
                "ok": True,
                "staged": True,
                "loaded": False,
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
        "workers": [{"label": str(spec["Label"]), "staged": True} for spec in specs],
    }


def _staging_records(specs: list[dict[str, object]], *, home: Path, domain: str) -> list[dict[str, object]]:
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
    specs: list[dict[str, object]], *, home: Path, domain: str, runtime_root: Path,
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
    if all(
        snapshot.loaded
        and _config_matches(snapshot.path, spec)
        and _launchctl_config_matches(snapshot.service, spec)
        for snapshot, spec in zip(snapshots, specs, strict=True)
    ):
        if require_stage_receipt:
            finalize_operational_authorization(runtime_root)
        return {
            "ok": True,
            "activated": True,
            "loaded": True,
            "workers": [{"label": str(spec["Label"]), "activated": True} for spec in specs],
        }
    if any(snapshot.loaded or not _config_matches(snapshot.path, spec) for snapshot, spec in zip(snapshots, specs, strict=True)):
        raise RuntimeError("workers must be staged and unloaded before activation")
    touched: list[str] = []
    try:
        for _spec, snapshot in zip(specs, snapshots, strict=True):
            touched.append(snapshot.service)
            _checked_launchctl("bootstrap", domain, str(snapshot.path))
            _checked_launchctl("kickstart", "-k", snapshot.service)
        if any(not _loaded(snapshot.service) for snapshot in snapshots):
            raise RuntimeError("worker activation validation failed")
        if require_stage_receipt:
            finalize_operational_authorization(runtime_root)
    except Exception as exc:
        rollback_errors = _rollback(snapshots, touched, domain=domain)
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
    if all(_config_matches(snapshot.path, spec) for snapshot, spec in zip(snapshots, specs, strict=True)):
        return activate_staged_workers(
            specs, home=home, domain=domain, runtime_root=runtime_root, require_stage_receipt=False
        )
    stage_workers(specs, home=home, domain=domain, allow_unload=True)
    return activate_staged_workers(
        specs, home=home, domain=domain, runtime_root=runtime_root, require_stage_receipt=False
    )


def _uninstall_labels(
    labels: tuple[str, ...], *, home: Path, domain: str
) -> dict[str, object]:
    errors: list[str] = []
    for label in labels:
        service = f"{domain}/{label}"
        path = home / "Library" / "LaunchAgents" / f"{label}.plist"
        try:
            launchctl("bootout", service, check=False)
        except Exception as exc:
            errors.append(f"bootout {service}: {type(exc).__name__}:{exc}")
            continue
        try:
            if _loaded(service):
                errors.append(f"bootout {service}: service remained loaded")
                continue
        except Exception as exc:
            errors.append(f"verify {service}: {type(exc).__name__}:{exc}")
            continue
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(f"remove {path}: {type(exc).__name__}:{exc}")
    return {
        "ok": not errors,
        "workers": [{"label": label, "installed": False} for label in labels],
        "errors": errors,
    }


def uninstall_workers(
    specs: list[dict[str, object]], *, home: Path, domain: str
) -> dict[str, object]:
    """Remove every worker, continuing through individual bootout failures."""

    _validate_specs(specs)
    return _uninstall_labels(tuple(str(spec["Label"]) for spec in specs), home=home, domain=domain)


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
            statuses: list[dict[str, object]] = []
            for spec in specs:
                label = str(spec["Label"])
                plist_path = home / "Library" / "LaunchAgents" / f"{label}.plist"
                status = service_status(f"{domain}/{label}", plist_path, spec)
                status["label"] = label
                statuses.append(status)
            print(json.dumps({"ok": True, "workers": statuses}, sort_keys=True))
            return 0
        if args.uninstall:
            require_operational_authorization(runtime_root)
            result = uninstall_workers(specs, home=home, domain=domain)
        elif args.stage:
            if authorization_path(runtime_root).exists() or authorization_path(runtime_root).is_symlink():
                raise RuntimeError("--stage refuses to modify an already authorized runtime")
            with worker_staging_transaction_lock(runtime_root):
                if not staged_worker_receipt_path(runtime_root).exists():
                    require_worker_staging_authorization(
                        runtime_root, specs=specs, home=home, _lock_held=True
                    )
                initial = _snapshot_workers(specs, home=home, domain=domain)
                try:
                    result = stage_workers(specs, home=home, domain=domain)
                    receipt = consume_worker_staging_authorization(
                        runtime_root,
                        specs=specs,
                        worker_records=_staging_records(specs, home=home, domain=domain),
                        _lock_held=True,
                    )
                except Exception:
                    # Only remove files created by this transaction. A receipt
                    # is the durable crash-recovery boundary and must win over
                    # cleanup after receipt creation.
                    if not staged_worker_receipt_path(runtime_root).exists():
                        for snapshot, spec in zip(initial, specs, strict=True):
                            if not snapshot.exists and not _loaded(snapshot.service) and _config_matches(snapshot.path, spec):
                                snapshot.path.unlink(missing_ok=True)
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
        return 0 if result["ok"] else 1
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
