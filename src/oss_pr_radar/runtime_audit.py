"""Read-only runtime audit and fault replay helpers."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .release_binding import active_release, runtime_ledger_path
from .runtime import REQUIRED_WORKERS, disk_snapshot, evaluate_health, pid_probe, read_json

WORKER_LABELS = {
    "fast": "com.oss-pr-radar.local-publication",
    "slow": "com.oss-pr-radar.local-publication-slow",
    "queue-importer": "com.oss-pr-radar.queue-importer",
}
LEGACY_LABELS = (
    "com.oss-pr-radar.local-publication-agent",
    "com.oss-pr-radar.local-publication-worker",
    "com.oss-pr-radar.local-dispatch-bridge",
    "com.oss-pr-radar.local-publication-legacy",
)


def active_release_evidence(root: Path) -> dict[str, Any]:
    """Verify the active immutable release without consulting runtime state."""

    try:
        release, manifest = active_release(root)
        return {
            "valid": True,
            "path": str(release),
            "releaseId": release.name,
            "commit": manifest.get("commit"),
            "manifestSha256": manifest.get("manifestSha256"),
            "policyDigest": manifest.get("policyDigest"),
        }
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        return {"valid": False, "error": f"{type(exc).__name__}:{str(exc)[:300]}"}


def parse_launchctl_output(output: str, *, expected_label: str | None = None) -> dict[str, Any]:
    pid = re.search(r"\bpid = (\d+)", output)
    last_exit = re.search(r"\blast exit code = (-?\d+)", output)
    state = re.search(r"\bstate = ([^\s]+)", output)
    observed_label = re.search(r"\b(?:label|service) = ([^\s]+)", output)
    result = {
        "pid": int(pid.group(1)) if pid else None,
        "lastExitCode": int(last_exit.group(1)) if last_exit else None,
        "state": state.group(1) if state else "unknown",
    }
    if expected_label is not None:
        result["labelMatched"] = observed_label is None or observed_label.group(1) == expected_label
        result["observedLabel"] = observed_label.group(1) if observed_label else expected_label
    return result


def process_probe(
    pid: int | None,
    *,
    expected_release: str | None,
    expected_runtime: Path,
) -> dict[str, Any]:
    """Probe the OS process and its cwd; runtime-health is never consulted."""

    evidence = pid_probe(pid, expected_fragment=expected_release)
    working_directory: str | None = None
    if pid and evidence.get("alive"):
        proc_cwd = Path(f"/proc/{pid}/cwd")
        try:
            if proc_cwd.exists():
                working_directory = str(proc_cwd.resolve())
        except OSError:
            working_directory = None
        if working_directory is None:
            try:
                completed = subprocess.run(
                    ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                for line in completed.stdout.splitlines():
                    if line.startswith("n"):
                        working_directory = line[1:]
                        break
            except (OSError, subprocess.SubprocessError):
                pass
    expected_runtime = str(expected_runtime.resolve())
    evidence["workingDirectory"] = working_directory
    evidence["workingDirectoryMatched"] = working_directory == expected_runtime
    evidence["releaseIdentityMatched"] = bool(evidence.get("versionMatched"))
    return evidence


def _read_operation_journal(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted((root / "state" / "runtime-operations").glob("*.ndjson")):
        try:
            for line in path.read_text(encoding="utf-8").splitlines()[-500:]:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    entries.append({"errorCode": "RUNTIME_JOURNAL_INVALID", "path": str(path)})
                    continue
                if isinstance(value, dict):
                    entries.append(value)
        except OSError:
            entries.append({"errorCode": "RUNTIME_JOURNAL_UNREADABLE", "path": str(path)})
    return entries[-1000:]


def _sqlite_evidence(path: Path, *, slow_alive: bool | None) -> dict[str, Any]:
    if not path.exists():
        return {"available": False, "integrity": "MISSING", "effects": []}
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        try:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            try:
                rows = connection.execute(
                    """SELECT effect_id,action,status,updated_at,result_json
                       FROM publication_effects WHERE status <> 'SUCCEEDED'
                       ORDER BY updated_at DESC LIMIT 50"""
                ).fetchall()
            except sqlite3.Error:
                rows = []
            effects = [
                {
                    "effectId": row[0],
                    "action": row[1],
                    "status": row[2],
                    "updatedAt": row[3],
                    "result": row[4],
                    "processCrashed": slow_alive is False,
                }
                for row in rows
            ]
            return {
                "available": True,
                "integrity": integrity,
                "effects": effects,
                "unresolvedCount": len(effects),
            }
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return {
            "available": True,
            "integrity": "ERROR",
            "integrityError": f"{type(exc).__name__}:{str(exc)[:240]}",
            "effects": [],
        }


def _isolated_ref_evidence(root: Path) -> dict[str, Any]:
    shared_fetch_head = root / ".git" / "FETCH_HEAD"
    try:
        completed = subprocess.run(
            ["git", "for-each-ref", "--format=%(refname)", "refs/oss-pr-radar/state"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        refs = [line for line in completed.stdout.splitlines() if line]
    except (OSError, subprocess.SubprocessError):
        refs = []
    return {
        "isolatedRefs": refs,
        "sharedFetchHeadExists": shared_fetch_head.exists(),
        "sharedWriteDetected": False,
    }


def _runtime_journal(
    root: Path,
    operations: list[dict[str, Any]],
    *,
    slow_alive: bool | None,
) -> dict[str, Any]:
    persisted = read_json(root / "state" / "runtime-journal.json", {})
    if isinstance(persisted, dict) and persisted.get("inFlight"):
        return dict(persisted) | {
            "state": persisted.get("state") or "BEGIN",
            "processCrashed": slow_alive is False,
        }
    backoff = read_json(root / "state" / "slow-worker-backoff.json", {})
    backoff = backoff if isinstance(backoff, dict) else {}
    if backoff.get("inFlight") is False:
        return {"state": "IDLE", "inFlight": False, "processCrashed": False}
    started = {
        str(item.get("operationId")): item
        for item in operations
        if item.get("status") == "started" and item.get("operationId")
    }
    completed = {
        str(item.get("operationId"))
        for item in operations
        if item.get("status") in {"success", "failure"} and item.get("operationId")
    }
    in_flight = bool(backoff.get("inFlight")) or any(
        operation_id not in completed for operation_id in started
    )
    if not in_flight:
        return {"state": "IDLE", "inFlight": False, "processCrashed": False}
    return {
        "state": "BEGIN",
        "inFlight": True,
        "processCrashed": slow_alive is False,
        "operationIds": sorted(started),
        "retryAfter": backoff.get("retryAfter"),
    }


def _raw_worker_success(runtime_worker: dict[str, Any], worker: str) -> bool:
    success_value = runtime_worker.get("lastSuccessAt") or runtime_worker.get(
        "queueImportSuccessAt"
    )
    exit_value = runtime_worker.get("queueLastExitCode") if worker == "queue-importer" else None
    if exit_value is None:
        exit_value = runtime_worker.get("lastExitCode")
    return exit_value == 0 and isinstance(success_value, str)


def audit_snapshot(snapshot: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    state = snapshot.get("state") if isinstance(snapshot.get("state"), dict) else {}
    release = snapshot.get("release") if isinstance(snapshot.get("release"), dict) else {}
    expected_release = release.get("releaseId") if release.get("valid") else None
    expected_policy_digest = release.get("policyDigest") if release.get("valid") else None
    health = evaluate_health(
        state,
        now=now,
        expected_release=expected_release,
        expected_policy_digest=expected_policy_digest,
        disk=snapshot.get("disk"),
        log_bytes=snapshot.get("logBytes"),
    )
    faults = list(health["issues"])
    if release.get("valid") is not True:
        faults.append("ACTIVE_RELEASE_INVALID")
    process = snapshot.get("process") if isinstance(snapshot.get("process"), dict) else {}
    launchctl = snapshot.get("launchctl") if isinstance(snapshot.get("launchctl"), dict) else {}
    if process.get("alive") and (
        launchctl.get("lastExitCode") not in {None, 0}
        or state.get("lastExitCode") not in {None, 0}
        or any(
            isinstance(item, dict) and item.get("lastExitCode") not in {None, 0}
            for item in (state.get("workers") or {}).values()
        )
    ):
        faults.append("PID_ALIVE_WITH_NONZERO_EXIT")
    if launchctl.get("lastExitCode") not in {None, 0}:
        faults.append("LAUNCHCTL_LAST_EXIT_NONZERO")
    if process.get("pid") and process.get("alive") is False:
        faults.append("PID_NOT_ALIVE")
    if process.get("pid") and process.get("versionMatched") is False:
        faults.append("PROCESS_VERSION_MISMATCH")
    worker_processes = snapshot.get("workerProcesses")
    if not isinstance(worker_processes, dict):
        faults.append("WORKER_PROCESS_EVIDENCE_MISSING")
        worker_processes = {}
    for worker in REQUIRED_WORKERS:
        evidence = worker_processes.get(worker)
        if not isinstance(evidence, dict):
            faults.append(f"{worker.upper()}_PROCESS_EVIDENCE_MISSING")
            continue
        label = evidence.get("label")
        launch = evidence.get("launchctl") if isinstance(evidence.get("launchctl"), dict) else {}
        actual = evidence.get("process") if isinstance(evidence.get("process"), dict) else {}
        runtime_workers = state.get("workers") if isinstance(state.get("workers"), dict) else {}
        runtime_worker = runtime_workers.get(worker) if isinstance(runtime_workers, dict) else {}
        runtime_worker = runtime_worker if isinstance(runtime_worker, dict) else {}
        evaluated_workers = health.get("workers") if isinstance(health.get("workers"), dict) else {}
        evaluated_worker = (
            evaluated_workers.get(worker) if isinstance(evaluated_workers, dict) else {}
        )
        evaluated_worker = evaluated_worker if isinstance(evaluated_worker, dict) else {}
        clean_short_lived_success = (
            launch.get("pid") is None
            and evaluated_worker.get("healthy") is True
            and evaluated_worker.get("lastExitCode") == 0
            and isinstance(evaluated_worker.get("lastSuccessAt"), str)
        )
        if label != WORKER_LABELS[worker]:
            faults.append(f"{worker.upper()}_LABEL_MISMATCH")
        if launch.get("pid") is None:
            if not clean_short_lived_success:
                faults.append(f"{worker.upper()}_PID_NOT_ALIVE")
        elif actual.get("alive") is not True:
            faults.append(f"{worker.upper()}_PID_NOT_ALIVE")
        if launch.get("lastExitCode") not in {None, 0}:
            faults.append(f"{worker.upper()}_LAST_EXIT_NONZERO")
        if launch.get("labelMatched") is False:
            faults.append(f"{worker.upper()}_LABEL_MISMATCH")
        if launch.get("pid") is not None:
            if (
                actual.get("versionMatched") is not True
                or actual.get("releaseIdentityMatched") is not True
            ):
                faults.append(f"{worker.upper()}_RELEASE_MISMATCH")
            if actual.get("workingDirectoryMatched") is not True:
                faults.append(f"{worker.upper()}_WORKDIR_MISMATCH")
        if evidence.get("stalePidConflict"):
            faults.append("STALE_PID_CONFLICT")
    operations = snapshot.get("operations") or []
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        code = str(operation.get("errorCode") or "")
        if "timeout" in code.casefold() or code in {"CLONE_TIMEOUT", "FETCH_TIMEOUT"}:
            faults.append("CLONE_OR_FETCH_TIMEOUT")
    fetch_head = snapshot.get("fetchHead")
    if isinstance(fetch_head, dict) and (
        fetch_head.get("cleared") or fetch_head.get("sharedWriteDetected")
    ):
        faults.append("SHARED_FETCH_HEAD_CLEARED_OR_USED")
    locks = snapshot.get("locks") if isinstance(snapshot.get("locks"), dict) else {}
    if locks.get("importerControllerConcurrent") or locks.get("owners", 0) > 1:
        faults.append("CONCURRENT_IMPORTER_CONTROLLER")
    journal = snapshot.get("journal") if isinstance(snapshot.get("journal"), dict) else {}
    if journal.get("state") in {"BEGIN", "CREATING", "started"} and journal.get("processCrashed"):
        faults.append("JOURNAL_AFTER_CRASH")
    effect = snapshot.get("publicationEffect")
    if isinstance(effect, dict) and effect.get("status") in {"CREATING", "ATTEMPTED"}:
        faults.append("PUBLICATION_EFFECT_REQUIRES_RECONCILIATION")
        if effect.get("processCrashed"):
            faults.append("CREATING_PUBLICATION_EFFECT_AFTER_CRASH")
    worker_errors = [
        item.get("lastErrorCode")
        for item in (state.get("workers") or {}).values()
        if isinstance(item, dict)
    ]
    if (
        snapshot.get("sqliteInterrupted")
        or state.get("lastErrorCode") == "SQLITE_INTERRUPT"
        or "SQLITE_INTERRUPT" in worker_errors
    ):
        faults.append("SQLITE_INTERRUPTED")
    if snapshot.get("lastErrno") == "ENOSPC":
        faults.append("ENOSPC")
    sqlite = snapshot.get("sqlite") if isinstance(snapshot.get("sqlite"), dict) else {}
    if sqlite.get("integrity") not in {None, "ok"}:
        faults.append("SQLITE_INTEGRITY_FAILURE")
    if snapshot.get("sqliteInterrupted"):
        faults.append("SQLITE_INTERRUPTED")
    return {
        "ok": not faults,
        "faults": sorted(set(faults)),
        "health": health,
        "auditScope": "read_only_runtime_and_fault_replay",
    }


def collect_snapshot(
    root: Path,
    *,
    launchctl_output: str = "",
    launchctl_runner: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    state = read_json(root / "state" / "runtime-health.json", {})
    state = state if isinstance(state, dict) else {}
    release = active_release_evidence(root)
    state_workers = state.get("workers") if isinstance(state.get("workers"), dict) else {}
    operations = _read_operation_journal(root)
    worker_processes: dict[str, dict[str, Any]] = {}
    launchctl_by_worker: dict[str, dict[str, Any]] = {}
    for worker in REQUIRED_WORKERS:
        label = WORKER_LABELS[worker]
        if launchctl_runner is not None:
            output = launchctl_runner(label)
        elif worker == "fast" and launchctl_output:
            output = launchctl_output
        else:
            output = launchctl_print(label)
        launch = parse_launchctl_output(output, expected_label=label)
        runtime_worker = state_workers.get(worker) if isinstance(state_workers, dict) else {}
        runtime_worker = runtime_worker if isinstance(runtime_worker, dict) else {}
        actual = process_probe(
            launch.get("pid"),
            expected_release=release.get("path") if release.get("valid") else None,
            expected_runtime=root,
        )
        worker_processes[worker] = {
            "label": label,
            "launchctl": launch,
            "process": actual,
            "stalePidConflict": bool(
                runtime_worker.get("pid") is not None
                and runtime_worker.get("pid") != launch.get("pid")
            ),
        }
        launchctl_by_worker[worker] = launch | {"label": label}
    slow_launch = worker_processes.get("slow", {}).get("launchctl", {})
    slow_runtime = state_workers.get("slow") if isinstance(state_workers, dict) else {}
    slow_runtime = slow_runtime if isinstance(slow_runtime, dict) else {}
    if slow_runtime.get("inFlight") is True:
        observed_workers = dict(state_workers)
        observed_slow = dict(slow_runtime)
        recorded_pid = slow_runtime.get("workerPid")
        current_pid = slow_launch.get("pid")
        observed_slow["workerPidAlive"] = (
            slow_runtime.get("workerPidAlive") is True
            and recorded_pid == current_pid
            and recorded_pid is not None
            and worker_processes.get("slow", {}).get("process", {}).get("alive") is True
        )
        observed_workers["slow"] = observed_slow
        state = dict(state)
        state["workers"] = observed_workers
    if slow_launch.get("pid") is None and _raw_worker_success(slow_runtime, "slow"):
        slow_alive = None
    else:
        slow_alive = worker_processes.get("slow", {}).get("process", {}).get("alive")
    sqlite = _sqlite_evidence(
        runtime_ledger_path(root),
        slow_alive=slow_alive,
    )
    marker = read_json(root / "state" / "sqlite-interrupted.json", {})
    marker = marker if isinstance(marker, dict) else {}
    error_codes = [str(item.get("errorCode") or "") for item in operations]
    last_errno = "ENOSPC" if any("ENOSPC" in code for code in error_codes) else None
    log_files = sorted((root / "state" / "runtime-operations").glob("*.ndjson"))
    log_bytes = sum(path.stat().st_size for path in log_files if path.exists())
    isolated_refs = _isolated_ref_evidence(root)
    isolated_refs["sharedWriteDetected"] = any(
        "FETCH_HEAD" in json.dumps(item, ensure_ascii=True) for item in operations
    )
    journal = _runtime_journal(root, operations, slow_alive=slow_alive)
    effects = sqlite.get("effects") or []
    publication_effect = effects[0] if effects else None
    if publication_effect is not None:
        publication_effect = dict(publication_effect)
        publication_effect["processCrashed"] = bool(
            publication_effect.get("processCrashed") or journal.get("processCrashed")
        )
    return {
        "state": state,
        "launchctl": launchctl_by_worker["fast"],
        "launchctlByWorker": launchctl_by_worker,
        "process": {
            "pid": worker_processes["fast"]["launchctl"].get("pid"),
            "alive": worker_processes["fast"]["process"].get("alive"),
            "versionMatched": worker_processes["fast"]["process"].get("versionMatched"),
        },
        "workerProcesses": worker_processes,
        "release": release,
        "operations": operations,
        "journal": journal,
        "publicationEffect": publication_effect,
        "publicationEffects": effects,
        "sqlite": sqlite,
        "sqliteInterrupted": bool(marker.get("interrupted"))
        or any("SQLITE_INTERRUPT" in code for code in error_codes),
        "lastErrno": last_errno,
        "fetchHead": isolated_refs,
        "logEvidence": {"files": [str(path) for path in log_files], "bytes": log_bytes},
        "disk": disk_snapshot(root),
        "logBytes": log_bytes,
    }


def launchctl_print(service: str) -> str:
    domain = service if service.startswith("gui/") else f"gui/{os.getuid()}/{service}"
    try:
        completed = subprocess.run(
            ["launchctl", "print", domain],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or completed.stderr
