from __future__ import annotations

import importlib.util
import json
import os
import stat
import threading
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "set_publication_pause.py"
SPEC = importlib.util.spec_from_file_location("set_publication_pause", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def _runtime(monkeypatch, tmp_path):
    release = tmp_path / "releases" / "release-1"
    release.mkdir(parents=True)
    state = tmp_path / "state"
    state.mkdir()
    ledger = state / "radar_ledger.sqlite3"
    monkeypatch.setattr(MODULE, "runtime_ledger_path", lambda _root: ledger)
    monkeypatch.setattr(
        MODULE,
        "active_release",
        lambda _root: (release, {"releaseId": "release-1"}),
    )
    monkeypatch.setattr(
        MODULE,
        "disk_snapshot",
        lambda _root: {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.93,
        },
    )
    return release, state, ledger


def test_pause_record_write_is_durable_before_it_returns(monkeypatch, tmp_path):
    path = tmp_path / "state" / MODULE.FILENAME
    events = []
    original_fsync = os.fsync
    original_replace = os.replace

    def observed_fsync(fd):
        kind = "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
        events.append(f"fsync:{kind}")
        return original_fsync(fd)

    def observed_replace(source, target):
        events.append("replace")
        return original_replace(source, target)

    monkeypatch.setattr(MODULE.os, "fsync", observed_fsync)
    monkeypatch.setattr(MODULE.os, "replace", observed_replace)

    MODULE._write_pause(path, {"paused": True, "pauseState": "PAUSING"})

    assert events == ["fsync:file", "replace", "fsync:directory"]
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text(encoding="utf-8"))["pauseState"] == "PAUSING"


def test_pause_does_not_disable_remote_before_pausing_record_is_durable(monkeypatch, tmp_path):
    _release, _state, _ledger = _runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "active")
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda *_args, **_kwargs: actions.append("remote-disable"),
    )
    original_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("simulated PAUSING durability failure")
        return original_fsync(fd)

    monkeypatch.setattr(MODULE.os, "fsync", fail_directory_fsync)

    with pytest.raises(OSError, match="PAUSING durability failure"):
        MODULE.pause(tmp_path, minutes=30, reason="CUTOVER")

    assert actions == []


def test_resume_does_not_enable_remote_before_resuming_record_is_durable(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda *_args, **_kwargs: actions.append("remote-enable"),
    )
    original_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("simulated RESUMING durability failure")
        return original_fsync(fd)

    monkeypatch.setattr(MODULE.os, "fsync", fail_directory_fsync)

    with pytest.raises(OSError, match="RESUMING durability failure"):
        MODULE.resume(tmp_path)

    assert actions == []


def test_resume_keeps_pause_when_disk_restart_margin_is_missing(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    monkeypatch.setattr(
        MODULE,
        "disk_snapshot",
        lambda _root: {
            "level": "warning",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.945,
        },
    )
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda *_args, **_kwargs: actions.append("remote-enable"),
    )

    with pytest.raises(RuntimeError, match="restart-safe disk capacity"):
        MODULE.resume(tmp_path)

    assert actions == []
    assert json.loads(record_path.read_text(encoding="utf-8"))["pauseState"] == "ACTIVE"


def test_resume_keeps_pause_until_worker_clears_persisted_disk_episode(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    monkeypatch.setattr(
        MODULE,
        "read_disk_pressure_gate_health",
        lambda *_args, **_kwargs: {
            "ok": False,
            "blocked": True,
            "reason": "DISK_STOP_THRESHOLD",
            "active": True,
            "restartSafe": True,
            "snapshot": {
                "level": "warning",
                "freeBytes": 100 * 1024**3,
                "usedFraction": 0.93,
            },
        },
    )
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda *_args, **_kwargs: actions.append("remote-enable"),
    )

    with pytest.raises(RuntimeError, match="clear disk pressure gate"):
        MODULE.resume(tmp_path)

    assert actions == []
    assert json.loads(record_path.read_text(encoding="utf-8"))["pauseState"] == "ACTIVE"


def test_resume_rollback_is_uncertain_if_active_record_is_not_durable(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda _repo, _workflow, *, enabled: actions.append(enabled),
    )
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "disabled_manually")
    monkeypatch.setattr(MODULE, "_wait_workflow_idle", lambda *_args, **_kwargs: None)
    original_fsync = os.fsync
    directory_fsyncs = 0

    def fail_second_directory_fsync(fd):
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                raise OSError("simulated ACTIVE durability failure")
        return original_fsync(fd)

    monkeypatch.setattr(MODULE.os, "fsync", fail_second_directory_fsync)

    with pytest.raises(RuntimeError, match="REMOTE_STATE_UNCERTAIN"):
        MODULE.resume(tmp_path)

    assert actions == [True, False]


def test_pause_disables_remote_workflow_waits_for_idle_and_records_binding(monkeypatch, tmp_path):
    release, state, _ledger = _runtime(monkeypatch, tmp_path)
    states = iter(["active", "disabled_manually"])
    actions = []
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: next(states))
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda repo, workflow, *, enabled: actions.append((repo, workflow, enabled)),
    )
    monkeypatch.setattr(
        MODULE,
        "_wait_workflow_idle",
        lambda repo, workflow, *, wait_seconds: actions.append(
            (repo, workflow, "idle", wait_seconds)
        ),
    )

    result = MODULE.pause(
        tmp_path,
        minutes=30,
        reason="CUTOVER",
        wait_seconds=90,
    )

    record_path = state / MODULE.FILENAME
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert result["paused"] is True
    assert record["releaseId"] == "release-1"
    assert record["releasePath"] == str(release)
    assert record["pauseState"] == "ACTIVE"
    assert record["workflowWasActive"] is True
    assert record["workflowStateAfterPause"] == "disabled_manually"
    assert record_path.stat().st_mode & 0o777 == 0o600
    assert actions == [
        (MODULE.DEFAULT_REPO, MODULE.DEFAULT_WORKFLOW, False),
        (MODULE.DEFAULT_REPO, MODULE.DEFAULT_WORKFLOW, "idle", 90),
    ]


def test_pause_carries_remote_restore_intent_across_release_cutover(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record_path.write_text(
        json.dumps(
            {
                "schemaVersion": MODULE.SCHEMA,
                "paused": True,
                "createdAt": "2026-08-28T00:00:00Z",
                "workflowWasActive": True,
                "workflowStateBeforePause": "active",
            }
        ),
        encoding="utf-8",
    )
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "disabled_manually")
    monkeypatch.setattr(MODULE, "_set_workflow_enabled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(MODULE, "_wait_workflow_idle", lambda *_args, **_kwargs: None)

    MODULE.pause(tmp_path, minutes=30, reason="CUTOVER")

    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["createdAt"] == "2026-08-28T00:00:00Z"
    assert record["workflowWasActive"] is True
    assert record["workflowStateBeforePause"] == "active"


def test_pause_failure_keeps_a_durable_remote_restore_intent(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    states = iter(["active", "disabled_manually"])
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: next(states))
    monkeypatch.setattr(MODULE, "_set_workflow_enabled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        MODULE,
        "_wait_workflow_idle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("API unavailable")),
    )

    with pytest.raises(RuntimeError, match="API unavailable"):
        MODULE.pause(tmp_path, minutes=30, reason="CUTOVER")

    record = json.loads((state / MODULE.FILENAME).read_text(encoding="utf-8"))
    assert record["paused"] is True
    assert record["workflowWasActive"] is True
    assert record["workflowStateAfterPause"] == "disabled_manually"
    assert record["pauseState"] == "PAUSING"
    assert record["workflowIdleConfirmedAt"] is None


def test_pause_crash_before_remote_disable_is_explicitly_pausing(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "active")
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit(77)),
    )

    with pytest.raises(SystemExit) as crashed:
        MODULE.pause(tmp_path, minutes=30, reason="CUTOVER")

    assert crashed.value.code == 77
    record = json.loads((state / MODULE.FILENAME).read_text(encoding="utf-8"))
    assert record["pauseState"] == "PAUSING"
    assert record["workflowIdleConfirmedAt"] is None


def test_resume_reenables_only_a_workflow_that_pause_disabled(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(
        MODULE,
        "active_outbound_pause",
        lambda _root: record | {"pauseState": "ACTIVE"},
    )
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda repo, workflow, *, enabled: actions.append((repo, workflow, enabled)),
    )
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "active")

    result = MODULE.resume(tmp_path)

    assert result["removed"] is True
    assert not record_path.exists()
    assert actions == [(MODULE.DEFAULT_REPO, MODULE.DEFAULT_WORKFLOW, True)]


def test_resume_verification_failure_re_disables_workflow_and_keeps_pause(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(
        MODULE,
        "active_outbound_pause",
        lambda _root: record | {"pauseState": "ACTIVE"},
    )
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda _repo, _workflow, *, enabled: actions.append(enabled),
    )
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "disabled_manually")
    monkeypatch.setattr(MODULE, "_wait_workflow_idle", lambda *_args, **_kwargs: None)

    with pytest.raises(RuntimeError, match="did not become active"):
        MODULE.resume(tmp_path)

    assert record_path.exists()
    assert actions == [True, False]
    restored = json.loads(record_path.read_text(encoding="utf-8"))
    assert restored["pauseState"] == "ACTIVE"


def test_resume_crash_after_remote_enable_is_explicitly_resuming(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit(78)),
    )

    with pytest.raises(SystemExit) as crashed:
        MODULE.resume(tmp_path)

    assert crashed.value.code == 78
    remaining = json.loads(record_path.read_text(encoding="utf-8"))
    assert remaining["pauseState"] == "RESUMING"


def test_resume_unlink_failure_rolls_remote_back_and_restores_active_pause(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda _repo, _workflow, *, enabled: actions.append(enabled),
    )
    states = iter(["active", "disabled_manually"])
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: next(states))
    monkeypatch.setattr(MODULE, "_wait_workflow_idle", lambda *_args, **_kwargs: None)
    original_unlink = Path.unlink

    def fail_record_unlink(path, *args, **kwargs):
        if path == record_path:
            raise OSError("simulated unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_record_unlink)

    with pytest.raises(OSError, match="simulated unlink failure"):
        MODULE.resume(tmp_path)

    assert actions == [True, False]
    restored = json.loads(record_path.read_text(encoding="utf-8"))
    assert restored["pauseState"] == "ACTIVE"
    assert restored["workflowStateAfterPause"] == "disabled_manually"
    assert "resumeStartedAt" not in restored


def test_resume_directory_fsync_failure_reports_uncertain_durability_but_stays_resumed(
    monkeypatch, tmp_path
):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    actions = []
    monkeypatch.setattr(
        MODULE,
        "_set_workflow_enabled",
        lambda _repo, _workflow, *, enabled: actions.append(enabled),
    )
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "active")
    original_fsync = os.fsync
    directory_fsyncs = 0

    def fail_directory_fsync(fd):
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                raise OSError("simulated directory fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(MODULE.os, "fsync", fail_directory_fsync)

    result = MODULE.resume(tmp_path)

    assert result["removed"] is True
    assert result["durabilityConfirmed"] is False
    assert "durability not confirmed" in result["warning"]
    assert not record_path.exists()
    assert actions == [True]


def test_resume_rollback_failure_reports_remote_state_uncertain(monkeypatch, tmp_path):
    _release, state, _ledger = _runtime(monkeypatch, tmp_path)
    record_path = state / MODULE.FILENAME
    record = {
        "schemaVersion": MODULE.SCHEMA,
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowRepo": MODULE.DEFAULT_REPO,
        "workflowFile": MODULE.DEFAULT_WORKFLOW,
        "workflowWasActive": True,
    }
    record_path.write_text(json.dumps(record), encoding="utf-8")
    record_path.chmod(0o600)
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    actions = []

    def set_workflow(_repo, _workflow, *, enabled):
        actions.append(enabled)
        if not enabled:
            raise RuntimeError("simulated rollback failure")

    monkeypatch.setattr(MODULE, "_set_workflow_enabled", set_workflow)
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "active")
    original_unlink = Path.unlink

    def fail_record_unlink(path, *args, **kwargs):
        if path == record_path:
            raise OSError("simulated unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_record_unlink)

    with pytest.raises(RuntimeError, match="REMOTE_STATE_UNCERTAIN"):
        MODULE.resume(tmp_path)

    assert actions == [True, False]
    remaining = json.loads(record_path.read_text(encoding="utf-8"))
    assert remaining["pauseState"] == "RESUMING"


@pytest.mark.parametrize("pause_state", ["PAUSING", "RESUMING"])
def test_status_never_calls_an_intermediate_state_globally_paused(
    monkeypatch, tmp_path, pause_state
):
    record = {
        "paused": True,
        "pauseState": pause_state,
        "workflowIdleConfirmedAt": "2026-08-28T00:00:00Z",
    }
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    monkeypatch.setattr(MODULE, "_workflow_state", lambda *_args: "disabled_manually")
    monkeypatch.setattr(MODULE, "_active_workflow_runs", lambda *_args: [])

    result = MODULE.status(tmp_path)

    assert result["ok"] is False
    assert result["globallyPaused"] is False


def test_status_holds_the_outbound_lock_for_its_complete_remote_snapshot(monkeypatch, tmp_path):
    _release, _state, ledger = _runtime(monkeypatch, tmp_path)
    record = {
        "paused": True,
        "pauseState": "ACTIVE",
        "workflowIdleConfirmedAt": "2026-08-28T00:00:00Z",
    }
    monkeypatch.setattr(MODULE, "active_outbound_pause", lambda _root: record)
    remote_check_entered = threading.Event()
    allow_remote_check = threading.Event()
    competing_lock_acquired = threading.Event()
    result = {}

    def workflow_state(*_args):
        remote_check_entered.set()
        assert allow_remote_check.wait(2)
        return "disabled_manually"

    monkeypatch.setattr(MODULE, "_workflow_state", workflow_state)
    monkeypatch.setattr(MODULE, "_active_workflow_runs", lambda *_args: [])

    status_thread = threading.Thread(
        target=lambda: result.update(MODULE.status(tmp_path)), daemon=True
    )
    status_thread.start()
    assert remote_check_entered.wait(2)

    def competing_writer():
        with MODULE.outbound_effect_lock(ledger):
            competing_lock_acquired.set()

    writer_thread = threading.Thread(target=competing_writer, daemon=True)
    writer_thread.start()
    assert not competing_lock_acquired.wait(0.2)
    allow_remote_check.set()
    status_thread.join(2)
    writer_thread.join(2)

    assert result["globallyPaused"] is True
    assert competing_lock_acquired.is_set()
