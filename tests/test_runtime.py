from __future__ import annotations

import json
import multiprocessing
import time
from pathlib import Path

import pytest

from oss_pr_radar.runtime import (
    DiskThresholds,
    RuntimeLockBusy,
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
        for worker in ("fast", "slow", "queue-importer")
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    state = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    assert set(state["workers"]) == {"fast", "slow", "queue-importer"}
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
            for worker in ("fast", "slow", "queue-importer")
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
