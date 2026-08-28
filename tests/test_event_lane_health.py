from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "event_lane_health.py"
SPEC = importlib.util.spec_from_file_location("event_lane_health", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def event_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE event_lane_events (
            event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL, created_at REAL NOT NULL,
            delivered_at REAL, lease_owner TEXT, lease_token TEXT
        );
        CREATE TABLE event_lane_threads (
            event_key TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
            turn_id TEXT, status TEXT NOT NULL, receipt_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE event_lane_turns (
            event_id TEXT PRIMARY KEY, event_key TEXT NOT NULL,
            thread_id TEXT NOT NULL DEFAULT '', client_user_message_id TEXT NOT NULL,
            turn_id TEXT, status TEXT NOT NULL DEFAULT 'reserved',
            receipt_json TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL
        );
        CREATE TABLE event_lane_public_work (
            event_key TEXT PRIMARY KEY, status TEXT NOT NULL,
            watch_until REAL, source TEXT NOT NULL DEFAULT 'event-lane',
            updated_at REAL NOT NULL
        );
        """
    )
    return connection


def test_read_only_database_marks_active_recursive_recovery_unhealthy(tmp_path):
    path = tmp_path / "agentscope-events.sqlite3"
    with event_database(path) as connection:
        connection.execute(
            """INSERT INTO event_lane_events
               (event_id,payload_json,status,attempts,created_at)
               VALUES (?,?,?,?,?)""",
            (
                "outcome-reconcile:outcome-reconcile:root",
                json.dumps({"repo": "agentscope-ai/agentscope"}),
                "pending",
                2,
                900.0,
            ),
        )

    result = MODULE._read_only_database(path, namespace="agentscope", now=1000.0)

    assert result["integrityOk"] is True
    assert result["isolated"] is True
    assert result["activeRecursiveRecoveryCount"] == 1
    assert result["healthy"] is False


def test_completed_recursive_history_is_warning_only(tmp_path):
    path = tmp_path / "nanobot-events.sqlite3"
    with event_database(path) as connection:
        connection.execute(
            """INSERT INTO event_lane_events
               (event_id,payload_json,status,attempts,created_at,delivered_at)
               VALUES (?,?,?,?,?,?)""",
            (
                "outcome-reconcile:outcome-reconcile:root",
                json.dumps({"repo": "HKUDS/nanobot"}),
                "superseded",
                1,
                900.0,
                950.0,
            ),
        )

    result = MODULE._read_only_database(path, namespace="nanobot", now=1000.0)

    assert result["historicalRecursiveRecoveryCount"] == 1
    assert result["activeRecursiveRecoveryCount"] == 0
    assert result["healthy"] is True


def test_audit_allows_each_lane_to_use_its_own_verified_release(monkeypatch, tmp_path):
    observed_releases = {
        "agentscope": "agentscope-release",
        "nanobot": "nanobot-release",
    }

    def plist(_path, *, root, namespace):
        assert root == tmp_path
        return {
            "bindingOk": True,
            "releaseId": observed_releases[namespace],
            "launch": {"available": True, "lastExitCode": 0},
        }

    monkeypatch.setattr(MODULE, "_plist_health", plist)
    monkeypatch.setattr(
        MODULE,
        "_read_only_database",
        lambda _path, *, namespace, now: {
            "healthy": True,
            "namespace": namespace,
            "checkedAt": now,
        },
    )
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda _root: {"authorized": True},
    )

    result = MODULE.audit(tmp_path, home=tmp_path / "home", now=1000.0)

    assert result["healthy"] is True
    assert result["lanes"]["agentscope"]["releaseId"] == "agentscope-release"
    assert result["lanes"]["nanobot"]["releaseId"] == "nanobot-release"


def test_running_lane_waits_for_replacement_success():
    statuses = [{"available": True, "state": "not running", "lastExitCode": 0}]
    delays = []

    result = MODULE._settle_launch_status(
        "lane",
        {"available": True, "state": "running", "lastExitCode": 1},
        attempts=2,
        delay=0.25,
        status_reader=lambda _label: statuses.pop(0),
        sleeper=delays.append,
    )

    assert MODULE._launch_healthy(result) is True
    assert delays == [0.25]


def test_running_lane_stays_unhealthy_when_replacement_does_not_settle():
    running = {"available": True, "state": "running", "lastExitCode": 1}

    result = MODULE._settle_launch_status(
        "lane",
        running,
        attempts=2,
        delay=0,
        status_reader=lambda _label: running,
        sleeper=lambda _delay: None,
    )

    assert MODULE._launch_healthy(result) is False


def test_running_lane_keeps_replacement_failure_unhealthy():
    result = MODULE._settle_launch_status(
        "lane",
        {"available": True, "state": "running", "lastExitCode": 1},
        attempts=2,
        delay=0,
        status_reader=lambda _label: {
            "available": True,
            "state": "not running",
            "lastExitCode": 1,
        },
        sleeper=lambda _delay: None,
    )

    assert MODULE._launch_healthy(result) is False


def test_stopped_lane_keeps_previous_nonzero_exit_unhealthy():
    assert MODULE._launch_healthy(
        {"available": True, "state": "not running", "lastExitCode": 1}
    ) is False
