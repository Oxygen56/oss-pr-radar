from __future__ import annotations

import os
import stat
import threading

import pytest

from oss_pr_radar.action_guard import (
    _open_private_child,
    ledger_action_guard_root,
    opportunity_action_guard,
)


def test_action_guard_handles_first_directory_creation_race(monkeypatch, tmp_path):
    real_mkdir = os.mkdir
    raced = False

    def mkdir(path, mode=0o777, *, dir_fd=None):
        nonlocal raced
        if path == "action-locks" and not raced:
            raced = True
            real_mkdir(path, mode, dir_fd=dir_fd)
            raise FileExistsError(path)
        return real_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", mkdir)
    with opportunity_action_guard(tmp_path, "example/project#1"):
        pass

    assert raced
    lock_dir = tmp_path / "action-locks"
    assert stat.S_IMODE(lock_dir.stat().st_mode) == 0o700
    locks = list(lock_dir.iterdir())
    assert len(locks) == 1
    assert len(locks[0].name) == len("op-") + 64 + len(".lock")
    assert stat.S_IMODE(locks[0].stat().st_mode) == 0o600


@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_action_guard_rejects_any_group_or_world_write_bit(tmp_path, mode):
    tmp_path.chmod(mode)
    with pytest.raises(RuntimeError, match="private"):
        with opportunity_action_guard(tmp_path, "example/project#1"):
            pass


def test_ledger_guard_fallback_accepts_safe_parent_but_rejects_symlink_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o755)
    assert ledger_action_guard_root(state / "ledger.sqlite3") == tmp_path

    state.rmdir()
    state.symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(RuntimeError, match="state directory"):
        ledger_action_guard_root(state / "ledger.sqlite3")


def test_open_private_child_rejects_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, tmp_path / "action-locks")
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(OSError):
            _open_private_child(parent_fd, "action-locks", create=True)
    finally:
        os.close(parent_fd)


def test_action_guard_serializes_gate_and_quarantine_activation(tmp_path):
    started = threading.Event()
    finished = threading.Event()

    def activate():
        started.set()
        with opportunity_action_guard(tmp_path, "example/project#1"):
            pass
        finished.set()

    with opportunity_action_guard(tmp_path, "example/project#1"):
        thread = threading.Thread(target=activate)
        thread.start()
        assert started.wait(2)
        assert not finished.is_set()
    thread.join(timeout=2)
    assert finished.is_set()


def test_action_guard_reentry_fails_fast_for_same_thread(tmp_path):
    with opportunity_action_guard(tmp_path, "example/project#1"):
        with pytest.raises(RuntimeError, match="re-entry"):
            with opportunity_action_guard(tmp_path, "example/project#1"):
                pass
