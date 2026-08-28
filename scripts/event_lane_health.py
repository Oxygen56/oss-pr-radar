#!/usr/bin/env python3
"""Read-only health evidence for independently released event-lane workers."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
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


def _launch_status(label: str) -> dict[str, Any]:
    service = f"gui/{os.getuid()}/{label}"
    try:
        completed = subprocess.run(
            ["launchctl", "print", service],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "service": service,
            "available": False,
            "lastExitCode": None,
            "error": f"launch_status_unavailable:{type(exc).__name__}",
        }
    output = completed.stdout + completed.stderr
    runs = re.search(r"\bruns = (\d+)", output)
    exit_code = re.search(r"\blast exit code = (-?\d+)", output)
    state = re.search(r"\bstate = ([^\n]+)", output)
    return {
        "service": service,
        "available": completed.returncode == 0,
        "state": state.group(1).strip() if state else None,
        "runs": int(runs.group(1)) if runs else None,
        "lastExitCode": int(exit_code.group(1)) if exit_code else None,
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


def _plist_health(path: Path, *, root: Path, namespace: str) -> dict[str, Any]:
    lane = LANES[namespace]
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file() and not path.is_symlink(),
        "bindingOk": False,
        "label": lane["label"],
        "worker": lane["worker"],
    }
    if not result["exists"]:
        return result
    try:
        value = plistlib.loads(path.read_bytes())
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
    launch = _settle_launch_status(str(lane["label"]), _launch_status(str(lane["label"])))
    result.update(
        {
            "observedLabel": value.get("Label"),
            "releaseId": release_id or None,
            "codeRoot": str(code_root),
            "runtimeRoot": str(runtime_argument) if runtime_argument else None,
            "bindingOk": bool(
                value.get("Label") == lane["label"]
                and release_id == code_root.name
                and worker_path.is_file()
                and worker_argument == worker_path
                and runtime_argument == root
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
                and _launch_healthy(launch)
                and database.get("healthy")
                and poll_state.get("healthy")
            ),
            "bindingOk": bool(plist.get("bindingOk")),
            "launchHealthy": _launch_healthy(launch),
            "databaseHealthy": bool(database.get("healthy")),
            "pollHealthy": bool(poll_state.get("healthy")),
            "pollTelemetryAvailable": bool(poll_state.get("telemetryAvailable")),
            "pollStatus": poll_state.get("status"),
            "pollError": poll_state.get("lastError"),
            "releaseId": plist.get("releaseId"),
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--home", type=Path)
    args = parser.parse_args()
    result = audit(args.root, home=args.home)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["healthy"] is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
