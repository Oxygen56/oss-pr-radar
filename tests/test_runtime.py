from __future__ import annotations

import json
import math
import multiprocessing
import os
import time
from pathlib import Path

import pytest

from oss_pr_radar.runtime import (
    REQUIRED_WORKERS,
    DiskThresholds,
    RuntimeLockBusy,
    disk_restart_safe,
    disk_snapshot,
    evaluate_health,
    exclusive_lock,
    record_cycle,
    rotate_log,
)


def _iso(epoch: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def healthy_state(now: float) -> dict:
    return {
        "lastSuccessAt": _iso(now - 10),
        "queueImportSuccessAt": _iso(now - 100),
        "consecutiveFailures": 0,
        "lastExitCode": 0,
        "pendingPublicationEffects": 0,
        "manifestVerified": True,
        "deploymentDirty": False,
        "releaseVersion": "release-a",
        "policyDigest": "policy-a",
    }


def test_health_rejects_stale_success_and_consecutive_failures():
    now = time.time()
    state = healthy_state(now) | {
        "lastSuccessAt": _iso(now - 121),
        "consecutiveFailures": 3,
        "lastExitCode": 1,
    }

    result = evaluate_health(
        state,
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
    )

    assert result["healthy"] is False
    assert {
        "RECENT_SUCCESS_MISSING_OR_STALE",
        "CONSECUTIVE_FAILURES",
        "LAST_EXIT_NONZERO",
    } <= set(result["issues"])


def test_health_covers_queue_effect_disk_log_and_policy_boundaries():
    now = time.time()
    state = healthy_state(now) | {
        "queueImportSuccessAt": _iso(now - 901),
        "pendingPublicationEffects": 1,
        "deploymentDirty": True,
    }
    result = evaluate_health(
        state,
        now=now,
        expected_release="release-b",
        expected_policy_digest="policy-b",
        disk={"level": "stop", "freeBytes": 1},
        log_bytes=51 * 1024 * 1024,
    )

    assert result["healthy"] is False
    assert {
        "QUEUE_IMPORT_STALE",
        "PUBLICATION_EFFECT_REQUIRES_RECONCILIATION",
        "RELEASE_VERSION_MISMATCH",
        "POLICY_DIGEST_CHANGED",
        "DIRTY_OR_UNVERIFIED_DEPLOYMENT",
        "DISK_STOP_THRESHOLD",
        "LOG_LIMIT_EXCEEDED",
    } <= set(result["issues"])


def test_disk_warning_is_reported_without_marking_workers_unhealthy():
    now = time.time()

    result = evaluate_health(
        healthy_state(now),
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
        disk={"level": "warning", "freeBytes": 50 * 1024 * 1024 * 1024},
    )

    assert result["healthy"] is True
    assert result["issues"] == []
    assert result["warnings"] == ["DISK_WARNING_THRESHOLD"]


def test_health_keeps_persisted_disk_episode_unhealthy_during_live_warning():
    now = time.time()
    gate = {
        "ok": False,
        "blocked": True,
        "reason": "DISK_STOP_THRESHOLD",
        "active": True,
        "gateActive": True,
    }

    result = evaluate_health(
        healthy_state(now),
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
        disk={"level": "warning", "freeBytes": 50 * 1024**3, "usedFraction": 0.93},
        disk_pressure_gate=gate,
    )

    assert result["healthy"] is False
    assert "DISK_STOP_THRESHOLD" in result["issues"]
    assert result["diskPressureGate"] == gate


def test_lock_is_non_blocking_and_restart_safe(tmp_path: Path):
    lock_path = tmp_path / "state" / "controller.lock"
    with exclusive_lock(lock_path):
        with pytest.raises(RuntimeLockBusy):
            with exclusive_lock(lock_path):
                pass
    with exclusive_lock(lock_path):
        pass


def test_cycle_state_and_operation_log_are_durable(tmp_path: Path):
    record_cycle(
        tmp_path,
        worker="fast",
        ok=False,
        exit_code=1,
        started_at=time.time() - 2,
        error_code="SQLITE_INTERRUPT",
        release_version="release-a",
        policy_digest="policy-a",
    )
    record_cycle(
        tmp_path,
        worker="fast",
        ok=True,
        exit_code=0,
        started_at=time.time() - 1,
    )
    state = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    operations = (tmp_path / "state" / "runtime-operations" / "operations.ndjson").read_text()
    assert state["workers"]["fast"]["consecutiveFailures"] == 0
    assert state["workers"]["fast"]["lastExitCode"] == 0
    assert state["workers"]["fast"]["lastSuccessAt"]
    assert "lastExitCode" not in state
    assert "consecutiveFailures" not in state
    assert operations.count("\n") == 2
    assert "SQLITE_INTERRUPT" in operations


def _record_cycle_process(root: str, worker: str) -> None:
    record_cycle(
        Path(root),
        worker=worker,
        ok=True,
        exit_code=0,
        started_at=time.time(),
    )


def test_runtime_health_keeps_worker_state_and_aggregate_atomic(tmp_path: Path):
    processes = [
        multiprocessing.Process(target=_record_cycle_process, args=(str(tmp_path), worker))
        for worker in REQUIRED_WORKERS
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    state = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    assert set(state["workers"]) == set(REQUIRED_WORKERS)
    assert "worker" not in state
    assert "lastExitCode" not in state
    assert state["workers"]["fast"]["lastExitCode"] == 0
    assert state["workers"]["slow"]["lastExitCode"] == 0
    assert state["workers"]["queue-importer"]["lastExitCode"] == 0


def test_required_worker_failure_cannot_be_hidden_by_successful_worker():
    now = time.time()
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - 10),
                "lastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update({"lastExitCode": 1, "consecutiveFailures": 1})

    result = evaluate_health(
        state,
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
    )

    assert result["healthy"] is False
    assert result["workers"]["fast"]["healthy"] is True
    assert result["workers"]["slow"]["healthy"] is False
    assert "slow:LAST_EXIT_NONZERO" in result["issues"]


def test_health_does_not_mark_live_slow_cycle_stale_before_inflight_deadline(monkeypatch):
    now = time.time()
    monkeypatch.setattr(
        "oss_pr_radar.runtime.pid_probe",
        lambda pid, expected_fragment=None: {
            "pid": pid,
            "alive": pid == os.getpid(),
            "versionMatched": expected_fragment == "slow_publication_worker.py",
        },
    )
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - (600 if worker == "slow" else 10)),
                "queueImportSuccessAt": _iso(now - 100),
                "lastExitCode": 0,
                "queueLastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update(
        {
            "inFlight": True,
            "attemptStartedAt": _iso(now - 300),
            "workerPid": os.getpid(),
            "workerPidAlive": True,
        }
    )

    result = evaluate_health(
        state, now=now, expected_release="release-a", expected_policy_digest="policy-a"
    )

    assert result["healthy"] is True
    assert result["workers"]["slow"]["inFlight"] is True
    assert result["workers"]["slow"]["workerPidAlive"] is True
    assert "slow:RECENT_SUCCESS_MISSING_OR_STALE" not in result["issues"]


@pytest.mark.parametrize(
    ("worker_pid_alive", "attempt_age", "issue", "command_matches", "observed_alive"),
    [
        (False, 300, "INFLIGHT_PID_NOT_ALIVE", True, False),
        (True, 1801, "INFLIGHT_TIMEOUT", True, True),
        (True, 300, "INFLIGHT_PID_NOT_ALIVE", False, False),
    ],
)
def test_health_rejects_dead_or_overdue_slow_cycle(
    monkeypatch, worker_pid_alive, attempt_age, issue, command_matches, observed_alive
):
    now = time.time()
    monkeypatch.setattr(
        "oss_pr_radar.runtime.pid_probe",
        lambda pid, expected_fragment=None: {
            "pid": pid,
            "alive": pid == os.getpid(),
            "versionMatched": command_matches and expected_fragment == "slow_publication_worker.py",
        },
    )
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - 600),
                "lastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update(
        {
            "inFlight": True,
            "attemptStartedAt": _iso(now - attempt_age),
            "workerPid": os.getpid(),
            "workerPidAlive": worker_pid_alive,
        }
    )

    result = evaluate_health(
        state, now=now, expected_release="release-a", expected_policy_digest="policy-a"
    )

    assert result["healthy"] is False
    assert f"slow:{issue}" in result["issues"]
    assert result["workers"]["slow"]["workerPidAlive"] is observed_alive


def test_health_rejects_nonexistent_recorded_slow_pid():
    now = time.time()
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - (600 if worker == "slow" else 10)),
                "queueImportSuccessAt": _iso(now - 100),
                "lastExitCode": 0,
                "queueLastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update(
        {
            "inFlight": True,
            "attemptStartedAt": _iso(now - 300),
            "workerPid": 1_000_000_000,
            "workerPidAlive": True,
        }
    )

    result = evaluate_health(
        state, now=now, expected_release="release-a", expected_policy_digest="policy-a"
    )

    assert result["healthy"] is False
    assert "slow:INFLIGHT_PID_NOT_ALIVE" in result["issues"]
    assert result["workers"]["slow"]["workerPidAlive"] is False


def test_log_rotation_keeps_bounded_history(tmp_path: Path):
    path = tmp_path / "agent.log"
    path.write_bytes(b"x" * 10)
    path.with_name("agent.log.1").write_bytes(b"old")

    rotate_log(path, max_bytes=5, backups=2)

    assert not path.exists()
    assert path.with_name("agent.log.1").read_bytes() == b"x" * 10
    assert path.with_name("agent.log.2").read_bytes() == b"old"


def test_disk_snapshot_uses_free_space_and_capacity_limits(monkeypatch, tmp_path: Path):
    class Usage:
        total = 100
        used = 96
        free = 4

    monkeypatch.setattr("oss_pr_radar.runtime.shutil.disk_usage", lambda _path: Usage())
    result = disk_snapshot(
        tmp_path,
        DiskThresholds(
            warning_free_bytes=20,
            stop_free_bytes=5,
            warning_used_fraction=0.8,
            stop_used_fraction=0.95,
        ),
    )

    assert result["level"] == "stop"
    assert result["freeBytes"] == 4
    assert result["restartFreeBytes"] == 5 + 8 * 1024**3
    assert result["restartUsedFraction"] == 0.94


def test_disk_snapshot_keeps_unrounded_fraction_for_restart_decision(monkeypatch, tmp_path: Path):
    class Usage:
        total = 10_000_000
        used = 9_400_004
        free = 599_996

    thresholds = DiskThresholds(
        warning_free_bytes=0,
        stop_free_bytes=0,
        warning_used_fraction=0.90,
        stop_used_fraction=0.95,
        restart_free_margin_bytes=0,
        restart_used_fraction=0.94,
    )
    monkeypatch.setattr("oss_pr_radar.runtime.shutil.disk_usage", lambda _path: Usage())

    result = disk_snapshot(tmp_path, thresholds)

    assert result["usedFraction"] > 0.94
    assert result["usedFraction"] != 0.94
    assert disk_restart_safe(result, thresholds) is False


@pytest.mark.parametrize(
    ("snapshot", "expected"),
    [
        (
            {
                "level": "warning",
                "freeBytes": 24 * 1024**3,
                "usedFraction": 0.94,
            },
            True,
        ),
        (
            {
                "level": "warning",
                "freeBytes": 24 * 1024**3,
                "usedFraction": 0.940001,
            },
            False,
        ),
        (
            {
                "level": "warning",
                "freeBytes": 24 * 1024**3 - 1,
                "usedFraction": 0.93,
            },
            False,
        ),
        (
            {
                "level": "stop",
                "freeBytes": 100 * 1024**3,
                "usedFraction": 0.5,
            },
            False,
        ),
        (
            {
                "level": "ok",
                "freeBytes": 100 * 1024**3,
            },
            False,
        ),
        (
            {
                "level": "ok",
                "freeBytes": 100 * 1024**3,
                "usedFraction": float("nan"),
            },
            False,
        ),
        (
            {
                "level": "ok",
                "freeBytes": 100 * 1024**3,
                "usedFraction": -math.ulp(1.0),
            },
            False,
        ),
        (
            {
                "level": "stop",
                "freeBytes": 100 * 1024**3,
                "usedFraction": math.nextafter(1.0, math.inf),
            },
            False,
        ),
        (
            {
                "level": "ok",
                "freeBytes": -1,
                "usedFraction": 0.0,
            },
            False,
        ),
        (
            {
                "level": "ok",
                "freeBytes": True,
                "usedFraction": 0.0,
            },
            False,
        ),
        (
            {
                "level": "warning",
                "freeBytes": 24 * 1024**3,
                "usedFraction": math.nextafter(0.94, math.inf),
            },
            False,
        ),
        (
            {
                "level": "warning",
                "freeBytes": 24 * 1024**3,
                "usedFraction": 0.94,
                "stopFreeBytes": 1,
            },
            False,
        ),
    ],
)
def test_disk_restart_safe_requires_real_headroom(snapshot, expected):
    assert disk_restart_safe(snapshot) is expected
