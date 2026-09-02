from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from oss_pr_radar.local_publication import fast_advance_once, queue_import_once, slow_advance_once
from oss_pr_radar.runtime import (
    DISK_PRESSURE_GATE_SCHEMA,
    DiskThresholds,
    disk_pressure_gate,
    read_disk_pressure_gate_health,
)


def _stop_snapshot(_root: Path) -> dict:
    return {"level": "stop", "freeBytes": 1, "usedFraction": 0.96}


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
        return {"level": "stop", "freeBytes": 1, "usedFraction": 0.96}

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
            "level": "stop",
            "freeBytes": 15 * 1024**3,
            "usedFraction": 0.5,
            "stopFreeBytes": 16 * 1024**3,
            "stopUsedFraction": 0.95,
        },
        {
            "level": "stop",
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


def test_disk_pressure_gate_persists_until_restart_margin_is_reached(tmp_path: Path):
    snapshots = iter(
        [
            {"level": "stop", "freeBytes": 1, "usedFraction": 0.96},
            {"level": "stop", "freeBytes": 1, "usedFraction": 0.96},
            {
                "level": "warning",
                "freeBytes": 100 * 1024**3,
                "usedFraction": 0.945,
            },
            {
                "level": "warning",
                "freeBytes": 100 * 1024**3,
                "usedFraction": 0.94,
            },
            {"level": "warning", "freeBytes": 100 * 1024**3, "usedFraction": 0.93},
        ]
    )
    calls: list[int] = []

    def snapshot(_root: Path) -> dict:
        calls.append(1)
        return next(snapshots)

    disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=100)
    deferred = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=101)
    still_stop = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=110)
    margin_pending = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=120)
    recovered = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=130)
    normal = disk_pressure_gate(tmp_path, snapshot_fn=snapshot, recheck_seconds=10, now=131)

    assert deferred["deferred"] is True
    assert still_stop["allowed"] is False
    assert still_stop["recordStop"] is False
    assert margin_pending["allowed"] is False
    assert margin_pending["gateActive"] is True
    assert margin_pending["recordRecovery"] is False
    assert recovered["allowed"] is True
    assert recovered["recovered"] is True
    assert recovered["recordRecovery"] is True
    assert normal["allowed"] is True
    assert normal["recovered"] is False
    assert calls == [1, 1, 1, 1, 1]

    state = json.loads((tmp_path / "state" / "disk-pressure-gate.json").read_text())
    assert state["active"] is False
    assert state["clearedAtEpoch"] == 130.0
    assert state["nextCheckAtEpoch"] is None


def test_disk_pressure_gate_force_recheck_cannot_bypass_restart_margin(tmp_path: Path):
    snapshots = iter(
        [
            {"level": "stop", "freeBytes": 1, "usedFraction": 0.96},
            {
                "level": "warning",
                "freeBytes": 100 * 1024**3,
                "usedFraction": 0.945,
            },
            {
                "level": "warning",
                "freeBytes": 100 * 1024**3,
                "usedFraction": 0.93,
            },
        ]
    )

    first = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: next(snapshots),
        recheck_seconds=300,
        now=100,
    )
    still_blocked = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: next(snapshots),
        recheck_seconds=300,
        now=101,
        force_recheck=True,
    )
    recovered = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: next(snapshots),
        recheck_seconds=300,
        now=102,
        force_recheck=True,
    )

    assert first["allowed"] is False
    assert still_blocked["allowed"] is False
    assert still_blocked["gateActive"] is True
    assert recovered["allowed"] is True
    assert recovered["recovered"] is True
    state = json.loads((tmp_path / "state" / "disk-pressure-gate.json").read_text())
    assert state["active"] is False


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
        lambda _root: {"level": "stop", "freeBytes": 1, "usedFraction": 0.96},
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


@pytest.mark.parametrize(
    "snapshot",
    [
        {"level": "ok"},
        {"level": "warning", "freeBytes": 100 * 1024**3},
        {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
            "stopUsedFraction": 0.99,
        },
    ],
)
def test_disk_pressure_gate_rejects_incomplete_or_forged_live_evidence(
    tmp_path: Path, snapshot: dict
):
    result = disk_pressure_gate(tmp_path, snapshot_fn=lambda _root: snapshot, now=100)

    assert result["allowed"] is False
    assert result["reason"] == "DISK_PRESSURE_GATE_UNAVAILABLE"
    assert not (tmp_path / "state" / "disk-pressure-gate.json").exists()


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


def test_read_disk_pressure_gate_health_is_read_only_and_exposes_active_episode(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    gate_path = state_dir / "disk-pressure-gate.json"
    gate_path.write_text(json.dumps(_persisted_episode_seven()) + "\n", encoding="utf-8")
    gate_path.chmod(0o600)
    before_bytes = gate_path.read_bytes()
    before_mtime = gate_path.stat().st_mtime_ns
    before_entries = sorted(path.name for path in state_dir.iterdir())

    health = read_disk_pressure_gate_health(
        tmp_path,
        snapshot_fn=lambda _root: {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
        },
    )

    assert health["ok"] is False
    assert health["blocked"] is True
    assert health["reason"] == "DISK_STOP_THRESHOLD"
    assert health["active"] is True
    assert health["episode"] == 7
    assert gate_path.read_bytes() == before_bytes
    assert gate_path.stat().st_mtime_ns == before_mtime
    assert sorted(path.name for path in state_dir.iterdir()) == before_entries


def test_read_disk_pressure_gate_health_reads_episode_after_live_sample(tmp_path: Path):
    safe_snapshot = {
        "level": "warning",
        "freeBytes": 100 * 1024**3,
        "usedFraction": 0.93,
    }

    def activate_during_sample(_root: Path) -> dict:
        result = disk_pressure_gate(
            tmp_path,
            worker="fast",
            snapshot_fn=_stop_snapshot,
            recheck_seconds=300,
            now=100,
        )
        assert result["gateActive"] is True
        return dict(safe_snapshot)

    health = read_disk_pressure_gate_health(tmp_path, snapshot_fn=activate_during_sample)

    assert health["snapshot"] == safe_snapshot
    assert health["restartSafe"] is True
    assert health["active"] is True
    assert health["blocked"] is True
    assert health["reason"] == "DISK_STOP_THRESHOLD"


def test_legacy_six_decimal_episode_can_clear_on_due_restart_safe_probe(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    gate_path = state_dir / "disk-pressure-gate.json"
    gate_path.write_text(json.dumps(_persisted_episode_seven()) + "\n", encoding="utf-8")
    gate_path.chmod(0o600)

    result = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
        },
        now=1_300,
    )

    assert result["allowed"] is True
    assert result["recovered"] is True
    state = json.loads(gate_path.read_text(encoding="utf-8"))
    assert state["active"] is False
    assert state["episode"] == 7


def test_legacy_level_selected_before_rounding_can_clear_after_upgrade(tmp_path: Path):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    gate_path = state_dir / "disk-pressure-gate.json"
    state = _persisted_episode_seven()
    state["lastSnapshot"] = {
        "path": "/legacy/runtime",
        "totalBytes": 1_000_000_000_000,
        "freeBytes": 50_000_400_000,
        # Exact byte-derived use is 0.9499996, so legacy disk_snapshot chose
        # warning before persisting the rounded value that old gate read as stop.
        "usedFraction": 0.95,
        "level": "warning",
        "warningFreeBytes": 32 * 1024**3,
        "stopFreeBytes": 16 * 1024**3,
        "stopUsedFraction": 0.95,
    }
    gate_path.write_text(json.dumps(state) + "\n", encoding="utf-8")
    gate_path.chmod(0o600)

    result = disk_pressure_gate(
        tmp_path,
        snapshot_fn=lambda _root: {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
        },
        now=1_300,
    )

    assert result["allowed"] is True
    assert result["recovered"] is True
    assert json.loads(gate_path.read_text(encoding="utf-8"))["active"] is False


def test_read_disk_pressure_gate_health_fails_closed_without_creating_state(tmp_path: Path):
    health = read_disk_pressure_gate_health(
        tmp_path,
        snapshot_fn=lambda _root: {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
        },
    )

    assert health["ok"] is False
    assert health["blocked"] is True
    assert health["reason"] == "DISK_PRESSURE_GATE_UNAVAILABLE"
    assert not (tmp_path / "state").exists()
