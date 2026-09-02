#!/usr/bin/env python3
"""Atomically pause or resume all GitHub publication during local maintenance."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic, sleep

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.outbound_pause import (  # noqa: E402
    OUTBOUND_PAUSE_FILENAME,
    OUTBOUND_PAUSE_SCHEMA,
    active_outbound_pause,
    outbound_effect_lock,
)
from oss_pr_radar.release_binding import active_release, runtime_ledger_path  # noqa: E402
from oss_pr_radar.runtime import (  # noqa: E402
    disk_restart_safe,
    disk_snapshot,
    read_disk_pressure_gate_health,
)
from oss_pr_radar.util import iso_z  # noqa: E402

SCHEMA = OUTBOUND_PAUSE_SCHEMA
FILENAME = OUTBOUND_PAUSE_FILENAME
DEFAULT_REPO = "Oxygen56/oss-pr-radar"
DEFAULT_WORKFLOW = "radar.yml"
_OUTBOUND_LOCK_FD: int | None = None


def _run_gh(arguments: list[str], *, timeout: int = 45) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        pass_fds=(_OUTBOUND_LOCK_FD,) if _OUTBOUND_LOCK_FD is not None else (),
    )


def _workflow_state(repo: str, workflow: str) -> str:
    completed = _run_gh(["api", f"repos/{repo}/actions/workflows/{workflow}", "--jq", ".state"])
    if completed.returncode != 0:
        raise RuntimeError(
            f"workflow state lookup failed: {(completed.stderr or completed.stdout)[:240]}"
        )
    state = completed.stdout.strip()
    if not state:
        raise RuntimeError("workflow state lookup returned an empty state")
    return state


def _set_workflow_enabled(repo: str, workflow: str, *, enabled: bool) -> None:
    operation = "enable" if enabled else "disable"
    completed = _run_gh(["workflow", operation, workflow, "--repo", repo])
    if completed.returncode != 0:
        raise RuntimeError(
            f"workflow {operation} failed: {(completed.stderr or completed.stdout)[:240]}"
        )


def _active_workflow_runs(repo: str, workflow: str) -> list[dict[str, object]]:
    completed = _run_gh(["api", f"repos/{repo}/actions/workflows/{workflow}/runs?per_page=100"])
    if completed.returncode != 0:
        raise RuntimeError(
            f"workflow run lookup failed: {(completed.stderr or completed.stdout)[:240]}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("workflow run lookup returned invalid JSON") from exc
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        raise RuntimeError("workflow run lookup returned an invalid run list")
    return [
        item
        for item in runs
        if isinstance(item, dict) and str(item.get("status") or "") != "completed"
    ]


def _wait_workflow_idle(repo: str, workflow: str, *, wait_seconds: int) -> None:
    deadline = monotonic() + max(1, wait_seconds)
    consecutive_idle = 0
    while True:
        active = _active_workflow_runs(repo, workflow)
        if not active:
            consecutive_idle += 1
            if consecutive_idle >= 2:
                return
        else:
            consecutive_idle = 0
        if monotonic() >= deadline:
            identifiers = [str(item.get("id") or "unknown") for item in active[:5]]
            raise RuntimeError(f"workflow did not become idle: {','.join(identifiers)}")
        sleep(2 if not active else 5)


def _read_raw_pause(path: Path) -> dict[str, object] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("publication pause record is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("publication pause record permissions are unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("publication pause record is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != SCHEMA
        or value.get("paused") is not True
    ):
        raise RuntimeError("publication pause record schema is invalid")
    return value


def _write_pause(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fchmod(handle.fileno(), 0o600)
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_pause_after_failed_resume(
    *,
    path: Path,
    value: dict[str, object],
    repo: str,
    workflow: str,
    cause: BaseException,
) -> None:
    """Restore the remote and local ACTIVE pause or report explicit uncertainty."""

    try:
        _set_workflow_enabled(repo, workflow, enabled=False)
        rollback_state = _workflow_state(repo, workflow)
        if rollback_state == "active":
            raise RuntimeError("workflow remained active after rollback")
        _wait_workflow_idle(repo, workflow, wait_seconds=1800)
        value["pauseState"] = "ACTIVE"
        value["workflowStateAfterPause"] = rollback_state
        value["workflowIdleConfirmedAt"] = iso_z(datetime.now(UTC))
        value.pop("resumeStartedAt", None)
        _write_pause(path, value)
    except (OSError, RuntimeError, subprocess.SubprocessError) as rollback:
        raise RuntimeError(
            "REMOTE_STATE_UNCERTAIN: resume failed and pause rollback "
            f"could not be verified: {str(rollback)[:240]}"
        ) from cause


def pause(
    runtime_root: Path,
    *,
    minutes: int,
    reason: str,
    repo: str = DEFAULT_REPO,
    workflow: str = DEFAULT_WORKFLOW,
    wait_seconds: int = 1800,
) -> dict[str, object]:
    global _OUTBOUND_LOCK_FD
    runtime_root = runtime_root.resolve()
    ledger_path = runtime_ledger_path(runtime_root)
    path = runtime_root / "state" / FILENAME
    with outbound_effect_lock(ledger_path) as effect_lock:
        _OUTBOUND_LOCK_FD = effect_lock.fileno()
        try:
            previous = _read_raw_pause(path)
            release, manifest = active_release(runtime_root)
            state_before = _workflow_state(repo, workflow)
            workflow_was_active = bool(
                previous.get("workflowWasActive")
                if previous is not None and "workflowWasActive" in previous
                else state_before == "active"
            )
            now = datetime.now(UTC)
            value: dict[str, object] = {
                "schemaVersion": SCHEMA,
                "paused": True,
                "pauseState": "PAUSING",
                "reason": reason,
                "createdAt": str((previous or {}).get("createdAt") or iso_z(now)),
                "expiresAt": iso_z(now + timedelta(minutes=max(1, min(minutes, 240)))),
                "releaseId": manifest["releaseId"],
                "releasePath": str(release),
                "workflowRepo": repo,
                "workflowFile": workflow,
                "workflowWasActive": workflow_was_active,
                "workflowStateBeforePause": str(
                    (previous or {}).get("workflowStateBeforePause") or state_before
                ),
                "workflowStateAfterPause": state_before,
                "workflowIdleConfirmedAt": None,
            }
            # Persist recovery intent before changing remote state.  If this process
            # dies later, local writers fail closed and a retry can finish the pause.
            _write_pause(path, value)
            if state_before == "active":
                _set_workflow_enabled(repo, workflow, enabled=False)
            state_after = _workflow_state(repo, workflow)
            if state_after == "active":
                raise RuntimeError("workflow remained active after pause request")
            value["workflowStateAfterPause"] = state_after
            _write_pause(path, value)
            _wait_workflow_idle(repo, workflow, wait_seconds=wait_seconds)
            value["pauseState"] = "ACTIVE"
            value["workflowIdleConfirmedAt"] = iso_z(datetime.now(UTC))
            _write_pause(path, value)
        finally:
            _OUTBOUND_LOCK_FD = None
    return {"ok": True, "paused": True, "path": str(path), **value}


def resume(runtime_root: Path) -> dict[str, object]:
    global _OUTBOUND_LOCK_FD
    runtime_root = runtime_root.resolve()
    ledger_path = runtime_ledger_path(runtime_root)
    path = runtime_root / "state" / FILENAME
    durability_confirmed = True
    durability_warning = None
    with outbound_effect_lock(ledger_path) as effect_lock:
        _OUTBOUND_LOCK_FD = effect_lock.fileno()
        try:
            value = _read_raw_pause(path)
            if value is None:
                return {"ok": True, "paused": False, "removed": False, "path": str(path)}
            validated = active_outbound_pause(runtime_root)
            assert validated is not None
            disk_pressure_gate = read_disk_pressure_gate_health(
                runtime_root, snapshot_fn=lambda root: disk_snapshot(root)
            )
            if (
                disk_pressure_gate.get("ok") is not True
                or disk_pressure_gate.get("blocked") is not False
            ):
                raise RuntimeError("publication resume requires a clear disk pressure gate")
            disk = disk_pressure_gate.get("snapshot")
            if not isinstance(disk, dict) or not disk_restart_safe(disk):
                raise RuntimeError("publication resume requires restart-safe disk capacity")
            value = dict(value) | {"pauseState": validated["pauseState"]}
            repo = str(value.get("workflowRepo") or DEFAULT_REPO)
            workflow = str(value.get("workflowFile") or DEFAULT_WORKFLOW)
            value["pauseState"] = "RESUMING"
            value["resumeStartedAt"] = iso_z(datetime.now(UTC))
            _write_pause(path, value)
            enabled = False
            if value.get("workflowWasActive") is True:
                enable_attempted = False
                try:
                    enable_attempted = True
                    _set_workflow_enabled(repo, workflow, enabled=True)
                    enabled = True
                    if _workflow_state(repo, workflow) != "active":
                        raise RuntimeError("workflow did not become active during resume")
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    if enable_attempted:
                        _restore_pause_after_failed_resume(
                            path=path,
                            value=value,
                            repo=repo,
                            workflow=workflow,
                            cause=exc,
                        )
                    raise
            try:
                path.unlink()
            except OSError as exc:
                if enabled:
                    _restore_pause_after_failed_resume(
                        path=path,
                        value=value,
                        repo=repo,
                        workflow=workflow,
                        cause=exc,
                    )
                else:
                    value["pauseState"] = "ACTIVE"
                    value.pop("resumeStartedAt", None)
                    _write_pause(path, value)
                raise
            try:
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            except OSError as exc:
                # unlink is the resume linearization point.  A later fsync
                # failure can only make a crash restore the fail-closed record;
                # rolling the live remote state back here would be less safe.
                durability_confirmed = False
                durability_warning = f"pause removal durability not confirmed: {str(exc)[:240]}"
        finally:
            _OUTBOUND_LOCK_FD = None
    result: dict[str, object] = {
        "ok": True,
        "paused": False,
        "removed": True,
        "durabilityConfirmed": durability_confirmed,
        "path": str(path),
    }
    if durability_warning:
        result["warning"] = durability_warning
    return result


def status(runtime_root: Path) -> dict[str, object]:
    runtime_root = runtime_root.resolve()
    with outbound_effect_lock(runtime_ledger_path(runtime_root)):
        return _status_unlocked(runtime_root)


def _status_unlocked(runtime_root: Path) -> dict[str, object]:
    path = runtime_root / "state" / FILENAME
    value = active_outbound_pause(runtime_root)
    if value is None:
        return {
            "ok": True,
            "paused": False,
            "globallyPaused": False,
            "path": str(path),
        }
    repo = str(value.get("workflowRepo") or DEFAULT_REPO)
    workflow = str(value.get("workflowFile") or DEFAULT_WORKFLOW)
    try:
        workflow_state = _workflow_state(repo, workflow)
        active_runs = _active_workflow_runs(repo, workflow)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        return {
            "ok": False,
            "paused": True,
            "globallyPaused": False,
            "remoteStateVerified": False,
            "error": f"REMOTE_STATE_UNCERTAIN:{str(exc)[:240]}",
            "path": str(path),
            **value,
        }
    globally_paused = bool(
        value.get("pauseState") == "ACTIVE"
        and workflow_state != "active"
        and not active_runs
        and value.get("workflowIdleConfirmedAt")
    )
    return {
        "ok": globally_paused,
        "paused": True,
        "globallyPaused": globally_paused,
        "remoteStateVerified": True,
        "workflowCurrentState": workflow_state,
        "activeWorkflowRunIds": [str(item.get("id") or "") for item in active_runs],
        "path": str(path),
        **value,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--minutes", type=int, default=60)
    parser.add_argument("--reason", default="MAINTENANCE")
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW)
    parser.add_argument("--wait-seconds", type=int, default=1800)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    result = (
        status(args.runtime_root)
        if args.status
        else (
            resume(args.runtime_root)
            if args.resume
            else pause(
                args.runtime_root,
                minutes=args.minutes,
                reason=args.reason,
                repo=args.repo,
                workflow=args.workflow,
                wait_seconds=args.wait_seconds,
            )
        )
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
