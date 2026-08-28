from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from oss_pr_radar.local_publication import fast_advance_once, queue_import_once, slow_advance_once
from oss_pr_radar.runtime import DiskThresholds, disk_pressure_gate


def _stop_snapshot(_root: Path) -> dict:
    return {"level": "stop", "freeBytes": 1}


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


def test_disk_pressure_gate_persists_first_stop_and_defers_without_resnapshot(tmp_path: Path):
    calls: list[int] = []

    def snapshot(_root: Path) -> dict:
        calls.append(1)
        return {"level": "stop", "freeBytes": 1}

    first = disk_pressure_gate(
        tmp_path,
        worker="fast",
        snapshot_fn=snapshot,
        recheck_seconds=300,
        now=100,
    )
    second = disk_pressure_gate(
        tmp_path,
        worker="queue-importer",
        snapshot_fn=snapshot,
        recheck_seconds=300,
        now=101,
    )

    assert first["allowed"] is False
    assert first["firstStop"] is True
    assert first["recordStop"] is True
    assert second["allowed"] is False
    assert second["deferred"] is True
    assert second["recordStop"] is False
    assert calls == [1]

    state = json.loads((tmp_path / "state" / "disk-pressure-gate.json").read_text())
    assert state["active"] is True
    assert state["firstStoppedAtEpoch"] == 100.0
    assert state["nextCheckAtEpoch"] == 400.0
    assert state["stoppedBy"] == "fast"


@pytest.mark.parametrize(
    "snapshot",
    [
        {
            "level": "warning",
            "freeBytes": 15 * 1024**3,
            "usedFraction": 0.5,
            "stopFreeBytes": 16 * 1024**3,
            "stopUsedFraction": 0.95,
        },
        {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.95,
            "stopFreeBytes": 16 * 1024**3,
            "stopUsedFraction": 0.95,
        },
    ],
)
def test_disk_pressure_gate_honors_both_hard_stop_measurements(tmp_path: Path, snapshot: dict):
    result = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: snapshot,
        thresholds=DiskThresholds(),
        now=100,
    )

    assert result["allowed"] is False
    assert result["reason"] == "DISK_STOP_THRESHOLD"
    assert result["recordStop"] is True


def test_disk_pressure_gate_rechecks_then_clears_once(tmp_path: Path):
    snapshots = iter(
        [
            {"level": "stop", "freeBytes": 1},
            {"level": "stop", "freeBytes": 1},
            {"level": "warning", "freeBytes": 100 * 1024**3},
            {"level": "warning", "freeBytes": 100 * 1024**3},
        ]
    )
    calls: list[int] = []

    def snapshot(_root: Path) -> dict:
        calls.append(1)
        return next(snapshots)

    disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=100)
    deferred = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=101)
    still_stop = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=110)
    recovered = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=120)
    normal = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=121)

    assert deferred["deferred"] is True
    assert still_stop["allowed"] is False
    assert still_stop["recordStop"] is False
    assert recovered["allowed"] is True
    assert recovered["recovered"] is True
    assert recovered["recordRecovery"] is True
    assert normal["allowed"] is True
    assert normal["recovered"] is False
    assert calls == [1, 1, 1, 1]

    state = json.loads((tmp_path / "state" / "disk-pressure-gate.json").read_text())
    assert state["active"] is False
    assert state["clearedAtEpoch"] == 120.0
    assert state["nextCheckAtEpoch"] is None


def test_disk_pressure_gate_fails_closed_for_nan_snapshot(tmp_path: Path):
    for value in (float("nan"), float("inf"), float("-inf")):
        result = disk_pressure_gate(
            tmp_path,
            snapshot_fn=lambda _root, value=value: {
                "level": "ok",
                "usedFraction": value,
            },
            now=100,
        )

        assert result["allowed"] is False
        assert result["reason"] == "DISK_PRESSURE_GATE_UNAVAILABLE"
        assert result["recordStop"] is False
        assert not (tmp_path / "state" / "disk-pressure-gate.json").exists()


def test_disk_pressure_gate_fails_closed_for_corrupt_state(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_path = state_dir / "disk-pressure-gate.json"
    state_path.write_text("{not-json\n", encoding="utf-8")
    state_path.chmod(0o600)

    result = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: (_ for _ in ()).throw(AssertionError("must not sample")),
        now=100,
    )

    assert result["allowed"] is False
    assert result["reason"] == "DISK_PRESSURE_GATE_UNAVAILABLE"
    assert result["recordStop"] is False


def test_disk_pressure_gate_concurrent_first_stop_is_claimed_once(tmp_path: Path):
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

    assert sum(result["firstStop"] is True for result in results) == 1
    assert sum(result["recordStop"] is True for result in results) == 1
    state = json.loads((tmp_path / "state" / "disk-pressure-gate.json").read_text())
    assert state["active"] is True


def test_workers_share_one_stop_record_and_do_not_repeat_it(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot",
        lambda _root: {"level": "stop", "freeBytes": 1},
    )

    fast = fast_advance_once(
        tmp_path,
        runner=lambda _root, _operation: {"ok": True, "queued": [], "rejected": [], "errors": []},
    )
    queue = queue_import_once(
        tmp_path,
        runner=lambda _root, _operation: {"ok": True, "verified": 0, "inserted": 0},
    )
    slow = slow_advance_once(tmp_path, runner=lambda *_args: {"ok": True})

    assert fast["errors"] == [{"error": "DISK_STOP_THRESHOLD"}]
    assert queue["errors"] == [{"error": "DISK_STOP_THRESHOLD"}]
    assert slow["errors"] == [{"error": "DISK_STOP_THRESHOLD"}]
    operations = (tmp_path / "state" / "runtime-operations" / "operations.ndjson").read_text()
    assert operations.count("\n") == 1
