#!/usr/bin/env python3
"""Read-only health evidence for independently released event-lane workers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.launch_config import parse_launchctl_config  # noqa: E402
from oss_pr_radar.operational_auth import (  # noqa: E402
    require_operational_authorization,
    worker_staging_transaction_lock,
)
from oss_pr_radar.release_binding import verify_release  # noqa: E402

LANES = {
    "agentscope": {
        "label": "com.oss-pr-radar.agentscope-events",
        "worker": "agentscope_event_worker.py",
        "repo": "agentscope-ai/agentscope",
    },
    "nanobot": {
        "label": "com.oss-pr-radar.nanobot-events",
        "worker": "nanobot_event_worker.py",
        "repo": "HKUDS/nanobot",
    },
}
ACTIVE_EVENT_STATUSES = {"pending", "leased", "needs_reconcile"}
ACTIVE_TURN_STATUSES = {"reserved", "started", "needs_reconcile"}
TURN_STALE_SECONDS = 20 * 60
POLL_SUCCESS_MAX_AGE_SECONDS = 5 * 60
POLL_FAILURE_WINDOW_SECONDS = 15 * 60
POLL_FAILURE_WINDOW_MAX_ATTEMPTS = 20
POLL_DEGRADED_CONSECUTIVE_FAILURES = 3
POLL_DEGRADED_MIN_WINDOW_ATTEMPTS = 3
POLL_DEGRADED_FAILURE_RATE = 0.5
POLL_SUCCESS_STALE_SECONDS = 15 * 60
POLL_OUTCOME_WINDOW = 20
EVENT_RECONCILE_SCHEMA = "oss-pr-radar.event-lane-reconcile.v1"
EVENT_RECONCILE_TIMEOUT_SECONDS = 90.0
EVENT_RECONCILE_POLL_INTERVAL_SECONDS = 5.0
EVENT_MANIFEST = "event-lane-manifest.json"
EVENT_MANIFEST_DIGEST = "event-lane-manifest.sha256"


def _launchctl(*arguments: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    """Run one launchctl operation through a narrow, testable seam."""

    return subprocess.run(
        ["launchctl", *arguments],
        capture_output=True,
        text=True,
        check=check,
        timeout=15,
    )


def _launch_status(label: str) -> dict[str, Any]:
    service = f"gui/{os.getuid()}/{label}"
    try:
        completed = _launchctl("print", service, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "service": service,
            "available": False,
            "lastExitCode": None,
            "error": f"launch_status_unavailable:{type(exc).__name__}",
        }
    output = (completed.stdout or "") + (completed.stderr or "")
    runs = re.search(r"\bruns = (\d+)", output)
    exit_code = re.search(r"\blast exit code = (-?\d+)", output)
    state = re.search(r"\bstate = ([^\n]+)", output)
    parsed = parse_launchctl_config(output)
    return {
        "service": service,
        "available": completed.returncode == 0,
        "state": state.group(1).strip() if state else None,
        "runs": int(runs.group(1)) if runs else None,
        "lastExitCode": int(exit_code.group(1)) if exit_code else None,
        "programArguments": parsed.get("ProgramArguments"),
        "workingDirectory": parsed.get("WorkingDirectory"),
    }


def _settle_launch_status(
    label: str,
    initial: dict[str, Any],
    *,
    attempts: int = 12,
    delay: float = 5.0,
    status_reader: Any | None = None,
    sleeper: Any | None = None,
) -> dict[str, Any]:
    """Wait for a replacement run before judging its predecessor's failed exit."""

    reader = status_reader or _launch_status
    wait = sleeper or time.sleep
    observed = initial
    for _ in range(max(0, attempts)):
        if not (
            observed.get("available")
            and observed.get("state") == "running"
            and observed.get("lastExitCode") != 0
        ):
            break
        wait(max(0.0, delay))
        observed = reader(label)
    return observed


def _launch_healthy(launch: dict[str, Any]) -> bool:
    return bool(launch.get("available") and launch.get("lastExitCode") == 0)


def _parse_poll_timestamp(value: object) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).timestamp()


def _read_poll_health(path: Path, *, now: float) -> dict[str, Any]:
    """Read durable poll evidence; launchd's predecessor exit is not enough."""
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file() and not path.is_symlink(),
        "available": False,
        "healthy": False,
        "status": "unknown",
        "issues": [],
    }
    if not result["exists"]:
        result["issues"].append("POLL_STATE_MISSING")
        return result
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        result["issues"].append(f"POLL_STATE_INVALID:{type(exc).__name__}")
        return result
    if not isinstance(value, dict):
        result["issues"].append("POLL_STATE_INVALID:object_required")
        return result
    result["available"] = True
    result["schemaVersion"] = value.get("schemaVersion")
    result["pollHealthSchema"] = value.get("pollHealthSchema")
    result["lastAttemptAt"] = value.get("lastAttemptAt")
    result["lastSuccessAt"] = value.get("lastSuccessAt")
    result["lastFailureAt"] = value.get("lastFailureAt")
    result["lastError"] = str(value.get("lastError") or "")[:400] or None
    attempt_at = _parse_poll_timestamp(value.get("lastAttemptAt"))
    success_at = _parse_poll_timestamp(value.get("lastSuccessAt"))
    result["lastAttemptAgeSeconds"] = max(0.0, now - attempt_at) if attempt_at is not None else None
    result["lastSuccessAgeSeconds"] = max(0.0, now - success_at) if success_at is not None else None
    if attempt_at is None:
        result["issues"].append("POLL_ATTEMPT_MISSING_OR_INVALID")
    if success_at is None:
        result["issues"].append("POLL_SUCCESS_MISSING_OR_INVALID")
    elif now - success_at > POLL_SUCCESS_MAX_AGE_SECONDS:
        result["issues"].append("POLL_SUCCESS_STALE")
    if attempt_at is not None and now - attempt_at > POLL_SUCCESS_MAX_AGE_SECONDS:
        result["issues"].append("POLL_ATTEMPT_STALE")

    try:
        consecutive = max(0, int(value.get("consecutiveFailures") or 0))
    except (TypeError, ValueError):
        consecutive = 0
        result["issues"].append("POLL_CONSECUTIVE_INVALID")
    result["consecutiveFailures"] = consecutive

    raw_window = value.get("failureWindow")
    window: list[dict[str, Any]] = []
    invalid_window = False
    if raw_window is not None and not isinstance(raw_window, list):
        invalid_window = True
    elif isinstance(raw_window, list):
        for entry in raw_window:
            if not isinstance(entry, dict) or not isinstance(entry.get("ok"), bool):
                invalid_window = True
                continue
            entry_at = _parse_poll_timestamp(entry.get("at"))
            if entry_at is None:
                invalid_window = True
                continue
            if entry_at > now or now - entry_at > POLL_FAILURE_WINDOW_SECONDS:
                continue
            window.append({"at": entry.get("at"), "ok": bool(entry["ok"])})
    if invalid_window:
        result["issues"].append("POLL_FAILURE_WINDOW_INVALID")
    window = window[-POLL_FAILURE_WINDOW_MAX_ATTEMPTS:]
    attempts = len(window)
    failures = sum(1 for entry in window if not entry["ok"])
    rate = round(failures / attempts, 3) if attempts else 0.0
    result.update(
        {
            "failureWindow": window,
            "failureWindowAttempts": attempts,
            "failureWindowFailures": failures,
            "failureRate": rate,
            "persistedFailureRate": value.get("failureRate"),
            "pollHealthStatus": str(value.get("pollHealthStatus") or "unknown"),
        }
    )
    degraded_evidence = consecutive >= POLL_DEGRADED_CONSECUTIVE_FAILURES or (
        attempts >= POLL_DEGRADED_MIN_WINDOW_ATTEMPTS and rate >= POLL_DEGRADED_FAILURE_RATE
    )
    status = result["pollHealthStatus"]
    if degraded_evidence or status == "degraded":
        result["status"] = "degraded"
        result["issues"].append("POLL_FAILURES_SUSTAINED")
    elif success_at is not None and attempt_at is not None:
        result["status"] = "recovering" if consecutive or status == "recovering" else "healthy"
    else:
        result["status"] = "unknown"
    # A recent successful poll keeps a single recoverable failure from making
    # the whole controller fatal. Missing/stale success or sustained failures
    # remain unhealthy even when launchd reports an old exit code of zero.
    result["healthy"] = bool(
        result["status"] in {"healthy", "recovering"}
        and success_at is not None
        and attempt_at is not None
        and now - success_at <= POLL_SUCCESS_MAX_AGE_SECONDS
        and now - attempt_at <= POLL_SUCCESS_MAX_AGE_SECONDS
        and not invalid_window
        and not degraded_evidence
    )
    return result


def _read_event_manifest(code_root: Path, *, namespace: str) -> dict[str, Any]:
    """Verify the lane-specific manifest and its sidecar digest.

    Event lanes are released independently.  Their Radar release manifests
    therefore have different ``releaseId`` and ``manifestSha256`` values.  A
    shared event-lane manifest is still verified *inside each release*; it is
    the trust boundary for the configured repository/thread mapping, not a
    reason to require the two executable releases to have the same identity.
    """

    manifest_path = code_root / EVENT_MANIFEST
    digest_path = code_root / EVENT_MANIFEST_DIGEST
    result: dict[str, Any] = {
        "path": str(manifest_path),
        "digestPath": str(digest_path),
        "ok": False,
        "sha256": None,
    }
    try:
        manifest_meta = manifest_path.lstat()
        digest_meta = digest_path.lstat()
    except OSError as exc:
        result["error"] = f"event_manifest_unavailable:{type(exc).__name__}"
        return result
    if (
        manifest_path.is_symlink()
        or digest_path.is_symlink()
        or not stat.S_ISREG(manifest_meta.st_mode)
        or not stat.S_ISREG(digest_meta.st_mode)
    ):
        result["error"] = "event_manifest_must_be_regular"
        return result
    try:
        manifest_bytes = manifest_path.read_bytes()
        expected = digest_path.read_text(encoding="utf-8").strip().split()[0]
        value = json.loads(manifest_bytes.decode("utf-8"))
    except (IndexError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        result["error"] = f"event_manifest_invalid:{type(exc).__name__}"
        return result
    actual = hashlib.sha256(manifest_bytes).hexdigest()
    if expected != actual or not re.fullmatch(r"[0-9a-f]{64}", expected):
        result["error"] = "event_manifest_digest_mismatch"
        result["sha256"] = actual
        return result
    repositories = value.get("repositories") if isinstance(value, dict) else None
    entry = (
        repositories.get(str(LANES[namespace]["repo"])) if isinstance(repositories, dict) else None
    )
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != "oss-pr-radar-event-lane-v1"
        or not isinstance(entry, dict)
        or not str(entry.get("activeThreadId") or "")
        or not str(entry.get("cwd") or "")
    ):
        result["error"] = "event_manifest_binding_invalid"
        result["sha256"] = actual
        return result
    result.update(
        {
            "ok": True,
            "sha256": actual,
            "schemaVersion": value.get("schemaVersion"),
            "repository": str(LANES[namespace]["repo"]),
            "activeThreadId": str(entry["activeThreadId"]),
            "cwd": str(entry["cwd"]),
        }
    )
    return result


def _plist_health(path: Path, *, root: Path, namespace: str) -> dict[str, Any]:
    lane = LANES[namespace]
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file() and not path.is_symlink(),
        "regular": False,
        "symlink": path.is_symlink(),
        "mode": None,
        "ownerUid": None,
        "bindingOk": False,
        "label": lane["label"],
        "worker": lane["worker"],
    }
    if not result["exists"]:
        return result
    try:
        metadata = path.lstat()
        result["regular"] = stat.S_ISREG(metadata.st_mode)
        result["mode"] = oct(stat.S_IMODE(metadata.st_mode))
        result["ownerUid"] = metadata.st_uid
        if not result["regular"] or result["symlink"]:
            result["error"] = "binding_invalid:plist_must_be_regular"
            return result
        value = plistlib.loads(path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError("plist object required")
        arguments = [str(item) for item in value.get("ProgramArguments") or []]
        code_root = Path(str(value.get("WorkingDirectory") or "")).absolute()
        manifest = verify_release(code_root)
    except (OSError, ValueError, plistlib.InvalidFileException, RuntimeError) as exc:
        result["error"] = f"binding_invalid:{type(exc).__name__}:{str(exc)[:160]}"
        return result
    try:
        root_index = arguments.index("--root") + 1
        runtime_argument = Path(arguments[root_index]).absolute()
    except (ValueError, IndexError):
        runtime_argument = None
    worker_path = code_root / "scripts" / str(lane["worker"])
    worker_argument = Path(arguments[1]).absolute() if len(arguments) > 1 else None
    release_id = str(manifest.get("releaseId") or "")
    event_manifest = _read_event_manifest(code_root, namespace=namespace)
    launch = _settle_launch_status(str(lane["label"]), _launch_status(str(lane["label"])))
    expected_arguments = arguments
    loaded_arguments = launch.get("programArguments")
    launch_config_ok = bool(
        launch.get("available")
        and loaded_arguments == expected_arguments
        and launch.get("workingDirectory") == str(code_root)
    )
    releases_root = (root / "releases").absolute()
    release_root_ok = code_root.parent == releases_root
    result.update(
        {
            "observedLabel": value.get("Label"),
            "releaseId": release_id or None,
            "releaseManifestSha256": manifest.get("manifestSha256"),
            "eventManifestSha256": event_manifest.get("sha256"),
            "eventManifest": event_manifest,
            "codeRoot": str(code_root),
            "runtimeRoot": str(runtime_argument) if runtime_argument else None,
            "releaseRootOk": release_root_ok,
            "launchConfigOk": launch_config_ok,
            "bindingOk": bool(
                value.get("Label") == lane["label"]
                and result["regular"]
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and metadata.st_uid == os.getuid()
                and release_root_ok
                and release_id == code_root.name
                and worker_path.is_file()
                and not worker_path.is_symlink()
                and worker_argument == worker_path
                and runtime_argument == root
                and event_manifest.get("ok") is True
            ),
            "launch": launch,
        }
    )
    return result


def _read_only_database(path: Path, *, namespace: str, now: float) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file() and not path.is_symlink(),
        "isolated": False,
        "integrityOk": False,
    }
    if not result["exists"]:
        return result
    try:
        uri = f"file:{path.absolute()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.row_factory = sqlite3.Row
            integrity = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            required = {
                "event_lane_events",
                "event_lane_threads",
                "event_lane_turns",
                "event_lane_public_work",
            }
            if not required.issubset(tables):
                raise sqlite3.DatabaseError("event lane schema is incomplete")
            events = connection.execute(
                "SELECT event_id,payload_json,status,attempts,created_at FROM event_lane_events"
            ).fetchall()
            turns = connection.execute(
                "SELECT event_id,event_key,status,created_at FROM event_lane_turns"
            ).fetchall()
            threads = connection.execute(
                "SELECT event_key,status FROM event_lane_threads"
            ).fetchall()
    except (OSError, sqlite3.Error) as exc:
        result["error"] = f"database_invalid:{type(exc).__name__}:{str(exc)[:160]}"
        return result

    repos: set[str] = set()
    malformed = 0
    recursive_history = 0
    active_recursive = 0
    active_events: list[sqlite3.Row] = []
    exhausted_recovery = 0
    for row in events:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            malformed += 1
            payload = {}
        repo = payload.get("repo")
        if repo:
            repos.add(str(repo))
        event_id = str(row["event_id"])
        recursion_depth = event_id.count("outcome-reconcile:")
        if recursion_depth > 1:
            recursive_history += 1
        if str(row["status"]) in ACTIVE_EVENT_STATUSES:
            active_events.append(row)
            if recursion_depth > 1:
                active_recursive += 1
            if recursion_depth and int(row["attempts"] or 0) >= 3:
                exhausted_recovery += 1
    active_turns = [row for row in turns if str(row["status"]) in ACTIVE_TURN_STATUSES]
    needs_reconcile_events = [row for row in events if str(row["status"]) == "needs_reconcile"]
    needs_reconcile_turns = [row for row in turns if str(row["status"]) == "needs_reconcile"]
    needs_reconcile_threads = [row for row in threads if str(row["status"]) == "needs_reconcile"]
    stale_turns = [
        row
        for row in active_turns
        if str(row["status"]) in {"reserved", "started"}
        and float(row["created_at"] or 0) <= now - TURN_STALE_SECONDS
    ]
    oldest_pending_age = max(
        (max(0, int(now - float(row["created_at"] or now))) for row in active_events),
        default=0,
    )
    stale_active_events = [
        row
        for row in active_events
        if str(row["status"]) in {"pending", "leased"}
        and float(row["created_at"] or 0) <= now - TURN_STALE_SECONDS
    ]
    expected_repo = str(LANES[namespace]["repo"])
    result.update(
        {
            "integrityOk": integrity == "ok",
            "isolated": repos.issubset({expected_repo})
            and path.name == f"{namespace}-events.sqlite3",
            "repos": sorted(repos),
            "eventCount": len(events),
            "activeEventCount": len(active_events),
            "activeTurnCount": len(active_turns),
            "needsReconcileCount": (
                len(needs_reconcile_events)
                + len(needs_reconcile_turns)
                + len(needs_reconcile_threads)
            ),
            "needsReconcileEvents": len(needs_reconcile_events),
            "needsReconcileTurns": len(needs_reconcile_turns),
            "needsReconcileThreads": len(needs_reconcile_threads),
            "staleTurnCount": len(stale_turns),
            "staleActiveEventCount": len(stale_active_events),
            "oldestPendingAgeSeconds": oldest_pending_age,
            "activeRecursiveRecoveryCount": active_recursive,
            "exhaustedRecoveryCount": exhausted_recovery,
            "historicalRecursiveRecoveryCount": recursive_history,
            "malformedPayloadCount": malformed,
        }
    )
    result["healthy"] = bool(
        result["integrityOk"]
        and result["isolated"]
        and not malformed
        and not stale_turns
        and not stale_active_events
        and not active_recursive
        and not exhausted_recovery
        and result["needsReconcileCount"] == 0
    )
    return result


def _poll_health(path: Path, *, now: float) -> dict[str, Any]:
    """Read durable poll outcomes and detect sustained transport failures.

    ``failureWindow`` is the current event-lane format.  The older
    ``recentPollOutcomes`` shape is accepted for one release so a mixed
    rollout remains observable; a state file with neither shape is unknown,
    never silently healthy.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        raw = None
    if isinstance(raw, dict) and "failureWindow" in raw:
        parsed = _read_poll_health(path, now=now)
        failures = int(parsed.get("failureWindowFailures") or 0)
        attempts = int(parsed.get("failureWindowAttempts") or 0)
        return {
            **parsed,
            "telemetryAvailable": bool(parsed.get("lastAttemptAt") or parsed.get("failureWindow")),
            "degraded": parsed.get("status") == "degraded",
            "recentOutcomeCount": attempts,
            "recentFailureCount": failures,
            "recentFailureRate": parsed.get("failureRate", 0.0),
            "successStale": "POLL_SUCCESS_STALE" in parsed.get("issues", []),
            "degradedReasons": parsed.get("issues", [])
            if parsed.get("status") == "degraded"
            else [],
        }
    # Compatibility with the first telemetry patch, which called the bounded
    # journal recentPollOutcomes.  It still requires a fresh successful sample.
    if isinstance(raw, dict) and isinstance(raw.get("recentPollOutcomes"), list):
        outcomes = [item for item in raw["recentPollOutcomes"] if isinstance(item, dict)][
            -POLL_OUTCOME_WINDOW:
        ]
        failures = [item for item in outcomes if item.get("ok") is False]
        try:
            consecutive = max(0, int(raw.get("consecutiveFailures") or 0))
        except (TypeError, ValueError, OverflowError):
            consecutive = 0
        last_success = _parse_iso_timestamp(raw.get("lastSuccessAt"))
        last_attempt = _parse_iso_timestamp(raw.get("lastAttemptAt"))
        stale = last_success is None or now - last_success > POLL_SUCCESS_STALE_SECONDS
        attempt_stale = last_attempt is None or now - last_attempt > POLL_SUCCESS_STALE_SECONDS
        rate = (len(failures) / len(outcomes)) if outcomes else 0.0
        degraded = bool(
            consecutive >= POLL_DEGRADED_CONSECUTIVE_FAILURES
            or (
                len(outcomes) >= POLL_DEGRADED_MIN_WINDOW_ATTEMPTS
                and rate >= POLL_DEGRADED_FAILURE_RATE
            )
            or stale
            or attempt_stale
        )
        reasons: list[str] = []
        if consecutive >= POLL_DEGRADED_CONSECUTIVE_FAILURES:
            reasons.append("consecutive_failures")
        if (
            len(outcomes) >= POLL_DEGRADED_MIN_WINDOW_ATTEMPTS
            and rate >= POLL_DEGRADED_FAILURE_RATE
        ):
            reasons.append("recent_failure_rate")
        if stale:
            reasons.append("last_success_stale")
        if attempt_stale:
            reasons.append("last_attempt_stale")
        return {
            "path": str(path),
            "telemetryAvailable": bool(raw.get("lastAttemptAt") or outcomes),
            "healthy": not degraded,
            "degraded": degraded,
            "status": "degraded" if degraded else ("recovering" if consecutive else "healthy"),
            "consecutiveFailures": consecutive,
            "lastAttemptAt": raw.get("lastAttemptAt"),
            "lastSuccessAt": raw.get("lastSuccessAt"),
            "recentOutcomeCount": len(outcomes),
            "recentFailureCount": len(failures),
            "recentFailureRate": round(rate, 4),
            "successStale": stale,
            "issues": (["POLL_SUCCESS_STALE"] if stale else [])
            + (["POLL_ATTEMPT_STALE"] if attempt_stale else []),
            "degradedReasons": reasons,
        }
    return {
        "path": str(path),
        "telemetryAvailable": False,
        "healthy": False,
        "degraded": False,
        "status": "unknown",
        "consecutiveFailures": 0,
        "recentOutcomeCount": 0,
        "recentFailureCount": 0,
        "recentFailureRate": 0.0,
        "successStale": True,
        "issues": ["POLL_STATE_MISSING_OR_LEGACY"],
        "degradedReasons": [],
    }


def _parse_iso_timestamp(value: object) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def audit(root: Path, *, home: Path | None = None, now: float | None = None) -> dict[str, Any]:
    root = root.absolute()
    home = (home or Path.home()).absolute()
    current = time.time() if now is None else now
    plists = {
        namespace: _plist_health(
            home / "Library" / "LaunchAgents" / f"{lane['label']}.plist",
            root=root,
            namespace=namespace,
        )
        for namespace, lane in LANES.items()
    }
    databases = {
        namespace: _read_only_database(
            root / "state" / f"{namespace}-events.sqlite3",
            namespace=namespace,
            now=current,
        )
        for namespace in LANES
    }
    poll_states = {
        namespace: _poll_health(root / "state" / f"{namespace}-poll.json", now=current)
        for namespace in LANES
    }
    try:
        authorization = require_operational_authorization(root)
        authorization_valid = isinstance(authorization, dict)
        authorization_error = None
    except Exception as exc:  # noqa: BLE001 - retain exact local gate failure
        authorization_valid = False
        authorization_error = f"{type(exc).__name__}:{str(exc)[:180]}"
    lane_health: dict[str, dict[str, Any]] = {}
    for namespace in LANES:
        plist = plists[namespace]
        database = databases[namespace]
        poll_state = poll_states[namespace]
        launch = plist.get("launch") or {}
        lane_health[namespace] = {
            "healthy": bool(
                plist.get("bindingOk")
                and plist.get("launchConfigOk")
                and _launch_healthy(launch)
                and database.get("healthy")
                and poll_state.get("healthy")
            ),
            "bindingOk": bool(plist.get("bindingOk")),
            "launchConfigOk": bool(plist.get("launchConfigOk")),
            "launchHealthy": _launch_healthy(launch),
            "databaseHealthy": bool(database.get("healthy")),
            "pollHealthy": bool(poll_state.get("healthy")),
            "pollTelemetryAvailable": bool(poll_state.get("telemetryAvailable")),
            "pollStatus": poll_state.get("status"),
            "pollError": poll_state.get("lastError"),
            "releaseId": plist.get("releaseId"),
            "releaseManifestSha256": plist.get("releaseManifestSha256"),
            "eventManifestSha256": plist.get("eventManifestSha256"),
        }
    healthy = authorization_valid and all(item.get("healthy") for item in lane_health.values())
    return {
        "schemaVersion": "oss-pr-radar.event-lane-health.v2",
        "checkedAt": datetime.fromtimestamp(current, UTC).isoformat().replace("+00:00", "Z"),
        "healthy": bool(healthy),
        "operationalAuthorizationValid": authorization_valid,
        "operationalAuthorizationError": authorization_error,
        "lanes": lane_health,
        "plists": plists,
        "databases": databases,
        "pollStates": poll_states,
    }


def _binding_fingerprint(snapshot: dict[str, Any]) -> dict[str, tuple[Any, ...]]:
    """Return only immutable lane binding fields for a TOCTOU check."""

    fingerprints: dict[str, tuple[Any, ...]] = {}
    for namespace in LANES:
        value = (snapshot.get("plists") or {}).get(namespace) or {}
        fingerprints[namespace] = (
            value.get("path"),
            value.get("codeRoot"),
            value.get("releaseId"),
            value.get("releaseManifestSha256"),
            value.get("eventManifestSha256"),
            value.get("runtimeRoot"),
            value.get("bindingOk"),
        )
    return fingerprints


def _reconcile_precondition_errors(snapshot: dict[str, Any]) -> list[str]:
    """Return reasons that make a repair unsafe instead of merely transient."""

    errors: list[str] = []
    if snapshot.get("operationalAuthorizationValid") is not True:
        errors.append("OPERATIONAL_AUTHORIZATION_REQUIRED")
    plists = snapshot.get("plists") if isinstance(snapshot.get("plists"), dict) else {}
    databases = snapshot.get("databases") if isinstance(snapshot.get("databases"), dict) else {}
    for namespace in LANES:
        plist = plists.get(namespace) if isinstance(plists.get(namespace), dict) else {}
        database = databases.get(namespace) if isinstance(databases.get(namespace), dict) else {}
        if plist.get("exists") is not True:
            errors.append(f"{namespace.upper()}_PLIST_MISSING")
        elif plist.get("bindingOk") is not True:
            errors.append(f"{namespace.upper()}_BINDING_INVALID")
        if database.get("healthy") is not True:
            errors.append(f"{namespace.upper()}_DATABASE_UNHEALTHY")
    return errors


def _lane_repair_actions(plist: dict[str, Any], poll: dict[str, Any]) -> list[str]:
    """Choose the smallest launchd action set for one already-validated lane."""

    launch = plist.get("launch") if isinstance(plist.get("launch"), dict) else {}
    if launch.get("available") is not True:
        return ["bootstrap", "kickstart"]
    if plist.get("launchConfigOk") is not True:
        return ["reload", "bootstrap", "kickstart"]
    if not _launch_healthy(launch) or poll.get("healthy") is not True:
        return ["kickstart"]
    return []


def _command_detail(result: subprocess.CompletedProcess[str]) -> str:
    detail = (result.stderr or result.stdout or "launchctl operation failed").strip()
    return detail[:240]


def _run_reconcile_action(
    namespace: str,
    action: str,
    *,
    plist_path: Path,
    launchctl_runner: Any,
) -> dict[str, Any]:
    """Execute one allowlisted launchd action and return private evidence."""

    label = str(LANES[namespace]["label"])
    service = f"gui/{os.getuid()}/{label}"
    domain = f"gui/{os.getuid()}"
    if action == "reload":
        bootout = launchctl_runner("bootout", service, check=False)
        if bootout.returncode != 0:
            return {
                "ok": False,
                "action": action,
                "error": f"LAUNCHCTL_BOOTOUT_FAILED:{_command_detail(bootout)}",
            }
        return {"ok": True, "action": action, "command": "bootout"}
    if action == "bootstrap":
        loaded = launchctl_runner("bootstrap", domain, str(plist_path), check=False)
        if loaded.returncode != 0:
            return {
                "ok": False,
                "action": action,
                "error": f"LAUNCHCTL_BOOTSTRAP_FAILED:{_command_detail(loaded)}",
            }
        return {"ok": True, "action": action, "command": "bootstrap"}
    if action == "kickstart":
        kicked = launchctl_runner("kickstart", "-k", service, check=False)
        if kicked.returncode != 0:
            return {
                "ok": False,
                "action": action,
                "error": f"LAUNCHCTL_KICKSTART_FAILED:{_command_detail(kicked)}",
            }
        return {"ok": True, "action": action, "command": "kickstart"}
    raise RuntimeError(f"unknown event-lane reconcile action: {action}")


def _fresh_poll(
    snapshot: dict[str, Any],
    *,
    namespaces: set[str],
    baseline_attempts: dict[str, float | None],
    now: float,
) -> bool:
    """Require a new durable attempt for each repaired lane and a green audit."""

    if snapshot.get("healthy") is not True:
        return False
    poll_states = snapshot.get("pollStates") if isinstance(snapshot.get("pollStates"), dict) else {}
    for namespace in namespaces:
        poll = poll_states.get(namespace) if isinstance(poll_states.get(namespace), dict) else {}
        attempt = _parse_poll_timestamp(poll.get("lastAttemptAt"))
        baseline = baseline_attempts.get(namespace)
        if attempt is None or (baseline is not None and attempt <= baseline):
            return False
        if now - attempt > POLL_SUCCESS_MAX_AGE_SECONDS:
            return False
    return True


def reconcile(
    root: Path,
    *,
    home: Path | None = None,
    now: float | None = None,
    timeout_seconds: float = EVENT_RECONCILE_TIMEOUT_SECONDS,
    poll_interval_seconds: float = EVENT_RECONCILE_POLL_INTERVAL_SECONDS,
    audit_reader: Any | None = None,
    launchctl_runner: Any | None = None,
    sleeper: Any | None = None,
    monotonic: Any | None = None,
) -> dict[str, Any]:
    """Idempotently re-load unhealthy event lanes without inventing bindings.

    Only an existing, regular plist whose code root and manifests pass the
    read-only audit may be acted on.  Missing or invalid cross-repository
    bindings are deliberately reported as blockers; the controller never
    guesses an installer path or silently rewrites a lane configuration.
    """

    root = root.absolute()
    home = (home or Path.home()).absolute()
    read_audit = audit_reader or audit
    run_launchctl = launchctl_runner or _launchctl
    wait = sleeper or time.sleep
    tick = monotonic or time.monotonic
    before = read_audit(root, home=home, now=now)
    result: dict[str, Any] = {
        "schemaVersion": EVENT_RECONCILE_SCHEMA,
        "checkedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "before": before,
        "actions": [],
        "errors": [],
        "freshPoll": False,
    }
    precondition_errors = _reconcile_precondition_errors(before)
    if precondition_errors:
        result.update({"ok": False, "action": "blocked", "errors": precondition_errors})
        return result
    try:
        # Validate the runtime layout before the transaction lock can create
        # or chmod anything under ``state``.  The locked re-check below closes
        # the race with a simultaneous release cutover.
        require_operational_authorization(root)
    except Exception as exc:  # noqa: BLE001 - repair must fail closed
        result.update(
            {
                "ok": False,
                "action": "blocked",
                "errors": [f"{type(exc).__name__}:{str(exc)[:240]}"],
            }
        )
        return result

    poll_states = before.get("pollStates") if isinstance(before.get("pollStates"), dict) else {}
    plans: dict[str, list[str]] = {}
    baseline_attempts: dict[str, float | None] = {}
    for namespace in LANES:
        plist = (before.get("plists") or {}).get(namespace) or {}
        poll = poll_states.get(namespace) if isinstance(poll_states.get(namespace), dict) else {}
        plans[namespace] = _lane_repair_actions(plist, poll)
        baseline_attempts[namespace] = _parse_poll_timestamp(poll.get("lastAttemptAt"))

    required = {namespace for namespace, actions in plans.items() if actions}
    if not required:
        result.update(
            {
                "ok": before.get("healthy") is True,
                "action": "noop",
                "after": before,
                "freshPoll": before.get("healthy") is True,
            }
        )
        return result

    repaired: set[str] = set()
    try:
        # Release cutover and worker staging use the same lock.  This keeps a
        # service from being reloaded against a release while its pointer is
        # being changed, without broadening the controller's lock scope.
        with worker_staging_transaction_lock(root):
            require_operational_authorization(root)
            locked = read_audit(root, home=home, now=now)
            if _reconcile_precondition_errors(locked):
                result["errors"] = _reconcile_precondition_errors(locked)
                result.update({"ok": False, "action": "blocked", "after": locked})
                return result
            if _binding_fingerprint(locked) != _binding_fingerprint(before):
                result.update(
                    {
                        "ok": False,
                        "action": "blocked",
                        "errors": ["EVENT_LANE_BINDING_CHANGED_DURING_RECONCILE"],
                        "after": locked,
                    }
                )
                return result
            locked_polls = (
                locked.get("pollStates") if isinstance(locked.get("pollStates"), dict) else {}
            )
            for namespace in sorted(required):
                plist = (locked.get("plists") or {}).get(namespace) or {}
                poll = (
                    locked_polls.get(namespace)
                    if isinstance(locked_polls.get(namespace), dict)
                    else {}
                )
                actions = _lane_repair_actions(plist, poll)
                if not actions:
                    continue
                repaired.add(namespace)
                plist_path = Path(str(plist.get("path") or ""))
                for action in actions:
                    if action == "reload":
                        outcome = _run_reconcile_action(
                            namespace,
                            "reload",
                            plist_path=plist_path,
                            launchctl_runner=run_launchctl,
                        )
                        result["actions"].append({"namespace": namespace, **outcome})
                        if outcome.get("ok") is not True:
                            result["errors"].append(str(outcome.get("error") or "reload failed"))
                            break
                        continue
                    outcome = _run_reconcile_action(
                        namespace,
                        action,
                        plist_path=plist_path,
                        launchctl_runner=run_launchctl,
                    )
                    result["actions"].append({"namespace": namespace, **outcome})
                    if outcome.get("ok") is not True:
                        result["errors"].append(str(outcome.get("error") or f"{action} failed"))
                        break
                if result["errors"]:
                    break
    except Exception as exc:  # noqa: BLE001 - the repair command must fail closed
        result["errors"].append(f"{type(exc).__name__}:{str(exc)[:240]}")
        result.update({"ok": False, "action": "failed"})
        return result

    if result["errors"]:
        result.update({"ok": False, "action": "failed"})
        return result

    try:
        deadline = tick() + max(0.0, float(timeout_seconds))
        after = read_audit(root, home=home, now=now)
        while True:
            current_now = time.time() if now is None else now
            if _fresh_poll(
                after,
                namespaces=repaired,
                baseline_attempts=baseline_attempts,
                now=current_now,
            ):
                result["freshPoll"] = True
                break
            if tick() >= deadline:
                break
            wait(max(0.0, float(poll_interval_seconds)))
            after = read_audit(root, home=home, now=now)
    except Exception as exc:  # noqa: BLE001 - repair must fail closed
        result["errors"].append(f"{type(exc).__name__}:{str(exc)[:240]}")
        result.update({"ok": False, "action": "failed"})
        return result
    result["after"] = after
    result["ok"] = bool(result["freshPoll"] and after.get("healthy") is True)
    result["action"] = "reconciled" if result["ok"] else "failed"
    if not result["ok"] and not result["errors"]:
        result["errors"] = ["EVENT_LANE_FRESH_POLL_TIMEOUT"]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--home", type=Path)
    parser.add_argument("--repair", action="store_true")
    args = parser.parse_args()
    result = (
        reconcile(args.root, home=args.home) if args.repair else audit(args.root, home=args.home)
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if (result.get("ok") if args.repair else result.get("healthy")) is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
