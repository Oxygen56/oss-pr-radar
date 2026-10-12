from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from oss_pr_radar import runtime
from oss_pr_radar.local_publication import fast_advance_once, queue_import_once, slow_advance_once
from oss_pr_radar.runtime import (
    DISK_PRESSURE_GATE_SCHEMA,
    DiskThresholds,
    disk_pressure_gate,
    read_disk_pressure_gate_health,
)


def _stop_snapshot(_root: Path) -> dict:
    return {"level": "stop", "freeBytes": 1, "usedFraction": 0.96}


def _persisted_episode_seven() -> dict:
    return {
        "schemaVersion": DISK_PRESSURE_GATE_SCHEMA,
        "active": True,
        "episode": 7,
        "firstStoppedAt": "2026-08-29T06:24:55Z",
        "firstStoppedAtEpoch": 1_000.0,
        "nextCheckAt": "2026-08-29T06:29:55Z",
        "nextCheckAtEpoch": 1_300.0,
        "lastObservedAt": "2026-08-29T06:24:55Z",
        "lastObservedAtEpoch": 1_000.0,
        "lastSnapshot": {
            "path": "/Users/oxygen/Documents/github/oss-pr-radar",
            "totalBytes": 994_662_584_320,
            "freeBytes": 46_966_874_112,
            # Legacy releases persisted this display-rounded value.
            "usedFraction": 0.952781,
            "level": "stop",
            "warningFreeBytes": 32 * 1024**3,
            "stopFreeBytes": 16 * 1024**3,
            "stopUsedFraction": 0.95,
        },
        "stoppedBy": "fast",
        "stopReason": "DISK_STOP_THRESHOLD",
        "stopRecorded": True,
    }


def _persist_active_episode(root: Path, state: dict | None = None) -> Path:
    state_dir = root / "state"
    state_dir.mkdir(mode=0o700, exist_ok=True)
    path = state_dir / "disk-pressure-gate.json"
    path.write_text(json.dumps(state or _persisted_episode_seven()) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _concurrent_gate_worker(root: str, output) -> None:
    output.put(
        disk_pressure_gate(
            Path(root),
            worker="fast",
            snapshot_fn=_stop_snapshot,
            recheck_seconds=300,
            now=100,
        )
    )


@pytest.mark.parametrize(
    "snapshot",
    [
        {"level": "stop", "freeBytes": 0, "usedFraction": 1.0},
        {"level": "stop", "freeBytes": 1, "usedFraction": 0.96},
        {"level": "warning", "freeBytes": 24 * 1024**3 - 1, "usedFraction": 0.945},
    ],
)
def test_disk_pressure_gate_does_not_stop_at_old_capacity_boundaries(
    tmp_path: Path, snapshot: dict
):
    result = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: snapshot,
        thresholds=DiskThresholds(),
        now=100,
    )

    assert result["allowed"] is True
    assert result["blocked"] is False
    assert result["reason"] is None
    assert result["snapshot"] == snapshot
    assert result["gateActive"] is False
    assert result["firstStop"] is False
    assert result["recordStop"] is False
    assert result["recordRecovery"] is False
    assert result["recovered"] is False
    assert not (tmp_path / "state" / "disk-pressure-gate.json").exists()


def test_gate_clears_historical_active_episode_without_claiming_capacity_recovery(tmp_path: Path):
    path = _persist_active_episode(tmp_path)
    historical = json.loads(path.read_text())

    result = disk_pressure_gate(
        tmp_path,
        worker="fast",
        snapshot_fn=_stop_snapshot,
        now=1_001,
    )

    assert result["allowed"] is True
    assert result["gateActive"] is False
    assert result["deferred"] is False
    assert result["firstStop"] is False
    assert result["recordStop"] is False
    assert result["recovered"] is False
    assert result["recordRecovery"] is False
    state = json.loads(path.read_text())
    assert state["active"] is False
    assert state["clearedReason"] == "limits_removed"
    assert state["episode"] == historical["episode"]
    assert state["firstStoppedAt"] == historical["firstStoppedAt"]
    assert state["firstStoppedAtEpoch"] == historical["firstStoppedAtEpoch"]
    assert state["lastSnapshot"] == historical["lastSnapshot"]
    assert state["nextCheckAtEpoch"] is None
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["active"] is False


def test_historical_capacity_removal_is_serialized_and_not_repeated(tmp_path: Path):
    path = _persist_active_episode(tmp_path)
    context = multiprocessing.get_context("fork")
    output = context.Queue()
    processes = [
        context.Process(target=_concurrent_gate_worker, args=(str(tmp_path), output))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    results = [output.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert all(result["allowed"] is True for result in results)
    assert all(result["firstStop"] is False for result in results)
    assert sum(result["limitsRemoved"] is True for result in results) == 1
    assert all(result["recordRecovery"] is False for result in results)
    state = json.loads(path.read_text())
    assert state["active"] is False
    assert state["clearedReason"] == "limits_removed"
    assert state["episode"] == 7
    before = path.read_bytes()
    before_mtime = path.stat().st_mtime_ns
    again = disk_pressure_gate(tmp_path, snapshot_fn=_stop_snapshot, now=101)
    assert again["allowed"] is True
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == before_mtime


def test_removing_historical_capacity_limit_reports_actual_state_write_failure(
    monkeypatch, tmp_path
):
    path = _persist_active_episode(tmp_path)
    before = path.read_bytes()

    def fail_write(*_args, **_kwargs):
        raise OSError("No space left on device")

    monkeypatch.setattr(runtime, "_atomic_write", fail_write)
    result = disk_pressure_gate(tmp_path, snapshot_fn=_stop_snapshot, now=1_001)

    assert result["allowed"] is False
    assert result["reason"] == "RUNTIME_STATE_UNAVAILABLE"
    assert "No space left on device" in result["error"]
    assert result["recordStop"] is False
    assert result["recordRecovery"] is False
    assert path.read_bytes() == before
    assert json.loads(path.read_text())["active"] is True


def test_disk_pressure_gate_preserves_corrupt_state_and_exposes_the_error(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    path = state_dir / "disk-pressure-gate.json"
    path.write_text("{not-json\n", encoding="utf-8")
    path.chmod(0o600)
    before = path.read_bytes()

    result = disk_pressure_gate(tmp_path, snapshot_fn=_stop_snapshot, now=100)

    assert result["allowed"] is False
    assert result["reason"] == "RUNTIME_STATE_UNAVAILABLE"
    assert result["error"]
    assert result["recordStop"] is False
    assert path.read_bytes() == before


def test_gate_refuses_symlinked_state_file_without_touching_target(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    target = tmp_path / "external.json"
    target.write_text(json.dumps(_persisted_episode_seven()), encoding="utf-8")
    target.chmod(0o600)
    (state_dir / "disk-pressure-gate.json").symlink_to(target)
    before = target.read_bytes()

    result = disk_pressure_gate(tmp_path, snapshot_fn=_stop_snapshot, now=100)

    assert result["allowed"] is False
    assert result["reason"] == "RUNTIME_STATE_UNAVAILABLE"
    assert target.read_bytes() == before
    assert (state_dir / "disk-pressure-gate.json").is_symlink()


def test_gate_reports_actual_disk_measurement_failure_without_capacity_blocking(tmp_path: Path):
    def unreadable(_root):
        raise OSError("disk measurement unavailable")

    result = disk_pressure_gate(tmp_path, snapshot_fn=unreadable, now=100)

    assert result["allowed"] is True
    assert result["reason"] is None
    assert result["snapshot"]["level"] == "unavailable"
    assert "disk measurement unavailable" in result["snapshot"]["measurementError"]
    assert result["recordStop"] is False
    assert not (tmp_path / "state" / "disk-pressure-gate.json").exists()


def test_worker_entries_continue_under_old_capacity_stop_without_recovery_marker(
    monkeypatch, tmp_path
):
    path = _persist_active_episode(tmp_path)
    monkeypatch.setattr("oss_pr_radar.local_publication.disk_snapshot", _stop_snapshot)
    calls = []

    def runner(_root, operation):
        calls.append(operation)
        return {
            "ok": True,
            "queued": [],
            "rejected": [],
            "errors": [],
            "verified": 0,
            "inserted": 0,
        }

    fast = fast_advance_once(tmp_path, runner=runner)
    queue = queue_import_once(tmp_path, runner=runner)
    slow = slow_advance_once(tmp_path, runner=runner)

    assert fast["ok"] is True
    assert queue["ok"] is True
    assert slow["ok"] is True
    assert "local-receipt-enqueue" in calls
    assert "queue-import" in calls
    assert "publication-run" in calls
    assert json.loads(path.read_text())["clearedReason"] == "limits_removed"
    operations = (tmp_path / "state" / "runtime-operations" / "operations.ndjson").read_text()
    assert "disk-pressure-recovery" not in operations
    assert "DISK_STOP_THRESHOLD" not in operations


def test_read_capacity_health_exposes_history_without_blocking_or_mutating(tmp_path: Path):
    path = _persist_active_episode(tmp_path)
    before = path.read_bytes()
    before_mtime = path.stat().st_mtime_ns
    before_entries = sorted(item.name for item in path.parent.iterdir())

    health = read_disk_pressure_gate_health(tmp_path, snapshot_fn=_stop_snapshot)

    assert health["ok"] is True
    assert health["capacityLimitsEnabled"] is False
    assert health["blocked"] is False
    assert health["active"] is False
    assert health["gateActive"] is False
    assert health["historicalActive"] is True
    assert health["episode"] == 7
    assert health["snapshot"] == _stop_snapshot(tmp_path)
    assert health["restartSafe"] is None
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == before_mtime
    assert sorted(item.name for item in path.parent.iterdir()) == before_entries


def test_read_capacity_health_without_history_preserves_empty_state_directory(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    health = read_disk_pressure_gate_health(tmp_path, snapshot_fn=_stop_snapshot)

    assert health["ok"] is True
    assert health["capacityLimitsEnabled"] is False
    assert health["blocked"] is False
    assert health["active"] is False
    assert health["historicalActive"] is False
    assert health["snapshot"] == _stop_snapshot(tmp_path)
    assert health["restartSafe"] is None
    assert list(state_dir.iterdir()) == []


def test_read_capacity_health_reports_missing_runtime_directory_without_creating_it(tmp_path: Path):
    health = read_disk_pressure_gate_health(tmp_path, snapshot_fn=_stop_snapshot)

    assert health["ok"] is False
    assert health["reason"] == "RUNTIME_STATE_UNAVAILABLE"
    assert health["capacityLimitsEnabled"] is False
    assert not (tmp_path / "state").exists()


def test_read_capacity_health_keeps_actual_measurement_error_visible(tmp_path: Path):
    path = _persist_active_episode(tmp_path)
    before = path.read_bytes()

    def unreadable(_root):
        raise OSError("disk measurement unavailable")

    health = read_disk_pressure_gate_health(tmp_path, snapshot_fn=unreadable)

    assert health["ok"] is True
    assert health["blocked"] is False
    assert health["historicalActive"] is True
    assert health["snapshot"]["level"] == "unavailable"
    assert "disk measurement unavailable" in health["snapshot"]["measurementError"]
    assert path.read_bytes() == before
