from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import plistlib
import sqlite3
import subprocess
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


def test_poll_health_degrades_after_three_consecutive_failures(tmp_path):
    path = tmp_path / "poll.json"
    path.write_text(
        json.dumps(
            {
                "lastAttemptAt": "1970-01-01T00:16:40Z",
                "lastSuccessAt": "1970-01-01T00:16:00Z",
                "consecutiveFailures": 3,
                "recentPollOutcomes": [
                    {"at": "1970-01-01T00:16:20Z", "ok": False},
                    {"at": "1970-01-01T00:16:30Z", "ok": False},
                    {"at": "1970-01-01T00:16:40Z", "ok": False},
                ],
            }
        )
    )
    result = MODULE._poll_health(path, now=1000.0)
    assert result["telemetryAvailable"] is True
    assert result["degraded"] is True
    assert "consecutive_failures" in result["degradedReasons"]


def test_poll_health_uses_window_rate_and_keeps_intermittent_failures_healthy(tmp_path):
    path = tmp_path / "poll.json"
    path.write_text(
        json.dumps(
            {
                "lastAttemptAt": "1970-01-01T00:16:40Z",
                "lastSuccessAt": "1970-01-01T00:16:39Z",
                "consecutiveFailures": 1,
                "recentPollOutcomes": [
                    {"at": "1970-01-01T00:16:38Z", "ok": True},
                    {"at": "1970-01-01T00:16:39Z", "ok": False},
                    {"at": "1970-01-01T00:16:40Z", "ok": True},
                ],
            }
        )
    )
    result = MODULE._poll_health(path, now=1000.0)
    assert result["healthy"] is True
    assert result["recentFailureRate"] < 0.5


def test_poll_health_degrades_when_success_is_stale(tmp_path):
    path = tmp_path / "poll.json"
    path.write_text(
        json.dumps(
            {
                "lastAttemptAt": "1970-01-01T00:00:01Z",
                "lastSuccessAt": "1970-01-01T00:00:00Z",
                "consecutiveFailures": 1,
                "recentPollOutcomes": [{"at": "1970-01-01T00:00:01Z", "ok": False}],
            }
        )
    )
    result = MODULE._poll_health(path, now=1000.0)
    assert result["degraded"] is True
    assert result["successStale"] is True


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
            "launchConfigOk": True,
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
    monkeypatch.setattr(
        MODULE,
        "_poll_health",
        lambda _path, *, now: {
            "healthy": True,
            "telemetryAvailable": True,
            "status": "healthy",
        },
    )

    result = MODULE.audit(tmp_path, home=tmp_path / "home", now=1000.0)

    assert result["healthy"] is True
    assert result["lanes"]["agentscope"]["releaseId"] == "agentscope-release"
    assert result["lanes"]["nanobot"]["releaseId"] == "nanobot-release"


def _reconcile_snapshot(tmp_path, *, agentscope=None, nanobot=None, healthy=True):
    def lane(namespace, override):
        value = {
            "path": str(tmp_path / f"{namespace}.plist"),
            "exists": True,
            "bindingOk": True,
            "launchConfigOk": True,
            "launch": {"available": True, "lastExitCode": 0},
        }
        if override:
            value.update(override)
        return value

    return {
        "healthy": healthy,
        "operationalAuthorizationValid": True,
        "plists": {
            "agentscope": lane("agentscope", agentscope),
            "nanobot": lane("nanobot", nanobot),
        },
        "databases": {
            "agentscope": {"healthy": True},
            "nanobot": {"healthy": True},
        },
        "pollStates": {
            "agentscope": {
                "healthy": True,
                "lastAttemptAt": "1970-01-01T00:15:00Z",
            },
            "nanobot": {
                "healthy": True,
                "lastAttemptAt": "1970-01-01T00:15:00Z",
            },
        },
    }


def test_reconcile_healthy_independent_lanes_is_idempotent_noop(monkeypatch, tmp_path):
    snapshot = _reconcile_snapshot(tmp_path)
    calls = []
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda _root: {"state": "ACTIVE"},
    )

    result = MODULE.reconcile(
        tmp_path,
        audit_reader=lambda *_args, **_kwargs: snapshot,
        launchctl_runner=lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert result["ok"] is True
    assert result["action"] == "noop"
    assert result["freshPoll"] is True
    assert calls == []


def test_reconcile_fails_closed_when_event_plist_is_missing(tmp_path):
    snapshot = _reconcile_snapshot(tmp_path, agentscope={"exists": False, "bindingOk": False})

    result = MODULE.reconcile(tmp_path, audit_reader=lambda *_args, **_kwargs: snapshot)

    assert result["ok"] is False
    assert result["action"] == "blocked"
    assert "AGENTSCOPE_PLIST_MISSING" in result["errors"]


def test_reconcile_fails_closed_when_event_binding_is_invalid(tmp_path):
    snapshot = _reconcile_snapshot(tmp_path, nanobot={"bindingOk": False})

    result = MODULE.reconcile(tmp_path, audit_reader=lambda *_args, **_kwargs: snapshot)

    assert result["ok"] is False
    assert result["action"] == "blocked"
    assert "NANOBOT_BINDING_INVALID" in result["errors"]


def test_plist_health_rejects_tampered_event_manifest(tmp_path, monkeypatch):
    root = tmp_path
    release = root / "releases" / "agent-release"
    release.mkdir(parents=True)
    worker = release / "scripts" / "agentscope_event_worker.py"
    worker.parent.mkdir()
    worker.write_text("worker", encoding="utf-8")
    manifest = release / "event-lane-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": "oss-pr-radar-event-lane-v1",
                "repositories": {
                    "agentscope-ai/agentscope": {
                        "activeThreadId": "thread-1",
                        "cwd": "/Users/oxygen/Documents/github/agentscope",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (release / "event-lane-manifest.sha256").write_text("0" * 64 + "\n", encoding="utf-8")
    monkeypatch.setattr(
        MODULE,
        "verify_release",
        lambda _release: {"releaseId": "agent-release", "manifestSha256": "release-digest"},
    )
    monkeypatch.setattr(
        MODULE,
        "_launch_status",
        lambda _label: {"available": False, "lastExitCode": None},
    )
    plist_path = root / "Library" / "LaunchAgents" / "com.oss-pr-radar.agentscope-events.plist"
    plist_path.parent.mkdir(parents=True)
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.oss-pr-radar.agentscope-events",
                "ProgramArguments": ["/usr/bin/python", str(worker), "--root", str(root)],
                "WorkingDirectory": str(release),
            }
        )
    )
    os.chmod(plist_path, 0o600)

    result = MODULE._plist_health(plist_path, root=root, namespace="agentscope")

    assert result["bindingOk"] is False
    assert result["eventManifest"]["error"] == "event_manifest_digest_mismatch"


def _valid_event_plist_fixture(tmp_path, monkeypatch):
    root = tmp_path
    release = root / "releases" / "agent-release"
    worker = release / "scripts" / "agentscope_event_worker.py"
    worker.parent.mkdir(parents=True)
    worker.write_text("worker", encoding="utf-8")
    manifest = release / "event-lane-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": "oss-pr-radar-event-lane-v1",
                "repositories": {
                    "agentscope-ai/agentscope": {
                        "activeThreadId": "thread-1",
                        "cwd": "/Users/oxygen/Documents/github/agentscope",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (release / "event-lane-manifest.sha256").write_text(
        hashlib.sha256(manifest.read_bytes()).hexdigest() + "\n", encoding="utf-8"
    )
    interpreter = root / ".venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_text("python", encoding="utf-8")
    os.chmod(interpreter, 0o755)
    monkeypatch.setattr(
        MODULE,
        "verify_release",
        lambda _release: {"releaseId": "agent-release", "manifestSha256": "release-digest"},
    )
    plist_path = root / "Library" / "LaunchAgents" / "com.oss-pr-radar.agentscope-events.plist"
    plist_path.parent.mkdir(parents=True)
    value = {
        "Label": "com.oss-pr-radar.agentscope-events",
        "ProgramArguments": [str(interpreter), str(worker), "--root", str(root)],
        "WorkingDirectory": str(release),
    }
    plist_path.write_bytes(plistlib.dumps(value))
    os.chmod(plist_path, 0o600)

    def launch_status(_label):
        return {
            "available": True,
            "lastExitCode": 0,
            "programArguments": value["ProgramArguments"],
            "workingDirectory": str(release),
            "plistPath": str(plist_path),
        }

    monkeypatch.setattr(MODULE, "_launch_status", launch_status)
    return root, release, worker, interpreter, plist_path, value


def test_plist_health_rejects_untrusted_interpreter_and_extra_arguments(tmp_path, monkeypatch):
    root, _release, worker, interpreter, plist_path, value = _valid_event_plist_fixture(
        tmp_path, monkeypatch
    )

    value["ProgramArguments"][0] = "/tmp/untrusted-python"
    plist_path.write_bytes(plistlib.dumps(value))
    wrong_interpreter = MODULE._plist_health(plist_path, root=root, namespace="agentscope")
    assert wrong_interpreter["programArgumentsOk"] is False
    assert wrong_interpreter["bindingOk"] is False

    value["ProgramArguments"] = [str(interpreter), str(worker), "--root", str(root)]
    value["ProgramArguments"].insert(2, "--unexpected")
    plist_path.write_bytes(plistlib.dumps(value))
    extra_argument = MODULE._plist_health(plist_path, root=root, namespace="agentscope")
    assert extra_argument["programArgumentsOk"] is False
    assert extra_argument["bindingOk"] is False


def test_plist_health_requires_loaded_plist_path_and_records_digest(tmp_path, monkeypatch):
    root, release, worker, interpreter, plist_path, value = _valid_event_plist_fixture(
        tmp_path, monkeypatch
    )
    raw = plist_path.read_bytes()
    result = MODULE._plist_health(plist_path, root=root, namespace="agentscope")

    assert result["bindingOk"] is True
    assert result["launchConfigOk"] is True
    assert result["launchPathOk"] is True
    assert result["plistSha256"] == hashlib.sha256(raw).hexdigest()
    assert result["expectedProgramArguments"] == [
        str(interpreter),
        str(worker),
        "--root",
        str(root),
    ]

    monkeypatch.setattr(
        MODULE,
        "_launch_status",
        lambda _label: {
            "available": True,
            "lastExitCode": 0,
            "programArguments": value["ProgramArguments"],
            "workingDirectory": str(release),
            "plistPath": str(root / "Library" / "LaunchAgents" / "other.plist"),
        },
    )
    wrong_loaded_path = MODULE._plist_health(plist_path, root=root, namespace="agentscope")
    assert wrong_loaded_path["bindingOk"] is True
    assert wrong_loaded_path["launchPathOk"] is False
    assert wrong_loaded_path["launchConfigOk"] is False


def test_launch_status_extracts_loaded_plist_path(monkeypatch):
    output = """gui/501/com.oss-pr-radar.agentscope-events = {
    path = /tmp/com.oss-pr-radar.agentscope-events.plist
    state = waiting
    program = /tmp/python
    arguments = {
        /tmp/python
        /tmp/worker.py
        --root
        /tmp/radar
    }
    working directory = /tmp/release
    last exit code = 0
}
"""
    monkeypatch.setattr(
        MODULE,
        "_launchctl",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, output, ""),
    )

    result = MODULE._launch_status("com.oss-pr-radar.agentscope-events")

    assert result["plistPath"] == "/tmp/com.oss-pr-radar.agentscope-events.plist"


def test_binding_fingerprint_covers_plist_and_loaded_launch_configuration(tmp_path):
    snapshot = _reconcile_snapshot(tmp_path)
    arguments = [
        str(tmp_path / ".venv" / "bin" / "python"),
        str(tmp_path / "releases" / "agent" / "scripts" / "agentscope_event_worker.py"),
        "--root",
        str(tmp_path),
    ]
    snapshot["plists"]["agentscope"].update(
        {
            "plistSha256": "plist-digest",
            "observedLabel": "com.oss-pr-radar.agentscope-events",
            "worker": "agentscope_event_worker.py",
            "programArguments": arguments,
            "expectedProgramArguments": arguments,
            "programArgumentsOk": True,
            "loadedPlistPath": str(tmp_path / "agentscope.plist"),
            "launchPathOk": True,
            "launch": {
                "available": True,
                "lastExitCode": 0,
                "plistPath": str(tmp_path / "agentscope.plist"),
                "programArguments": arguments,
                "workingDirectory": str(tmp_path / "releases" / "agent"),
            },
        }
    )
    baseline = MODULE._binding_fingerprint(snapshot)

    changed_plist = json.loads(json.dumps(snapshot))
    changed_plist["plists"]["agentscope"]["plistSha256"] = "changed"
    assert MODULE._binding_fingerprint(changed_plist) != baseline

    changed_launch = json.loads(json.dumps(snapshot))
    changed_launch["plists"]["agentscope"]["launch"]["programArguments"][0] = "/tmp/python"
    assert MODULE._binding_fingerprint(changed_launch) != baseline


def test_reconcile_bootstraps_unloaded_lane_and_requires_fresh_poll(monkeypatch, tmp_path):
    before = _reconcile_snapshot(
        tmp_path,
        agentscope={
            "launch": {"available": False, "lastExitCode": None},
            "launchConfigOk": False,
        },
        healthy=False,
    )
    locked = json.loads(json.dumps(before))
    after = _reconcile_snapshot(tmp_path, healthy=True)
    after["pollStates"]["agentscope"]["lastAttemptAt"] = "1970-01-01T00:16:00Z"
    snapshots = iter((before, locked, after))
    observed = []
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda _root: {"state": "ACTIVE"},
    )

    def launchctl(*args, **kwargs):
        observed.append((args, kwargs))
        return subprocess.CompletedProcess(["launchctl", *args], 0, "", "")

    result = MODULE.reconcile(
        tmp_path,
        now=1000.0,
        audit_reader=lambda *_args, **_kwargs: next(snapshots),
        launchctl_runner=launchctl,
        timeout_seconds=0,
    )

    assert result["ok"] is True
    assert result["action"] == "reconciled"
    assert result["freshPoll"] is True
    assert observed[0][0][0] == "bootstrap"
    assert observed[0][0][1].startswith("gui/")
    assert observed[1][0][0:2] == ("kickstart", "-k")


def test_poll_health_new_window_keeps_one_transient_failure_recoverable(tmp_path):
    path = tmp_path / "poll.json"
    path.write_text(
        json.dumps(
            {
                "pollHealthSchema": "event_poll_health_v1",
                "lastAttemptAt": "1970-01-01T00:16:40Z",
                "lastSuccessAt": "1970-01-01T00:16:39Z",
                "lastError": "URLError:temporary",
                "consecutiveFailures": 1,
                "pollHealthStatus": "recovering",
                "failureWindow": [
                    {"at": "1970-01-01T00:16:39Z", "ok": True},
                    {"at": "1970-01-01T00:16:40Z", "ok": False},
                ],
                "failureRate": 0.5,
            }
        )
    )
    result = MODULE._poll_health(path, now=1000.0)
    assert result["status"] == "recovering"
    assert result["healthy"] is True
    assert result["degraded"] is False
    assert result["failureWindowFailures"] == 1


def test_poll_health_new_window_marks_sustained_failures_degraded_even_exit_zero(tmp_path):
    path = tmp_path / "poll.json"
    path.write_text(
        json.dumps(
            {
                "pollHealthSchema": "event_poll_health_v1",
                "lastAttemptAt": "1970-01-01T00:16:40Z",
                "lastSuccessAt": "1970-01-01T00:16:37Z",
                "consecutiveFailures": 3,
                "pollHealthStatus": "degraded",
                "failureWindow": [
                    {"at": "1970-01-01T00:16:37Z", "ok": True},
                    {"at": "1970-01-01T00:16:38Z", "ok": False},
                    {"at": "1970-01-01T00:16:39Z", "ok": False},
                    {"at": "1970-01-01T00:16:40Z", "ok": False},
                ],
                "failureRate": 0.75,
            }
        )
    )
    result = MODULE._poll_health(path, now=1000.0)
    assert result["status"] == "degraded"
    assert result["healthy"] is False
    assert result["failureWindowFailures"] == 3


def test_poll_health_missing_telemetry_is_unknown_not_healthy(tmp_path):
    path = tmp_path / "poll.json"
    path.write_text(json.dumps({"watermark": "1970-01-01T00:16:00Z"}))
    result = MODULE._poll_health(path, now=1000.0)
    assert result["status"] == "unknown"
    assert result["healthy"] is False


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
    assert (
        MODULE._launch_healthy({"available": True, "state": "not running", "lastExitCode": 1})
        is False
    )
