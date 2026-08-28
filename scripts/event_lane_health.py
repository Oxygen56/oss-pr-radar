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
        launch = plist.get("launch") or {}
        lane_health[namespace] = {
            "healthy": bool(
                plist.get("bindingOk") and _launch_healthy(launch) and database.get("healthy")
            ),
            "bindingOk": bool(plist.get("bindingOk")),
            "launchHealthy": _launch_healthy(launch),
            "databaseHealthy": bool(database.get("healthy")),
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
