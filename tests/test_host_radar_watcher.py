from __future__ import annotations

import hashlib
import json
import os
import select
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import _watcher_missing_baseline_violation

from scripts.host_radar_watcher import (
    IN_ATTRIB,
    IN_IGNORED,
    IN_Q_OVERFLOW,
    IN_UNMOUNT,
    WATCHER_SCRIPT,
    _inotify_failure,
    _write_marker,
    parse_inotify_events,
)


def _inventory(root: Path) -> str:
    entries = []
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if name != "worktrees"]
        for name in dirs + files:
            path = current_path / name
            relative = path.relative_to(root)
            stat_result = path.lstat()
            if path.is_symlink():
                entries.append((str(relative), "symlink", os.readlink(path)))
            elif path.is_file():
                entries.append(
                    (
                        str(relative),
                        "file",
                        stat_result.st_mode & 0o777,
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                    )
                )
            else:
                entries.append((str(relative), "directory", stat_result.st_mode & 0o777))
    entries.sort()
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _start_watcher(tmp_path: Path, root: Path, baseline_exists: bool, pause=None, gate=None):
    flag = tmp_path / "flag"
    ready = tmp_path / "ready"
    args = [
        sys.executable,
        str(WATCHER_SCRIPT),
        str(root),
        _inventory(root) if baseline_exists else "missing",
        "1" if baseline_exists else "0",
        str(flag),
        str(ready),
        str(pause) if pause is not None else "",
        str(gate) if gate is not None else "",
    ]
    watcher = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    return watcher, flag, ready


def _wait_for_marker(path: Path, watcher: subprocess.Popen, label: str) -> None:
    deadline = time.monotonic() + 5
    while not path.exists() and time.monotonic() < deadline:
        if watcher.poll() is not None:
            stderr = watcher.communicate()[1].decode("utf-8", "replace")[-4000:]
            raise AssertionError(f"watcher exited before {label}: {stderr!r}")
        time.sleep(0.01)
    assert path.exists(), f"watcher did not produce {label}"


def _finish_watcher(watcher: subprocess.Popen, expected_codes=(-15, 2)) -> str:
    deadline = time.monotonic() + 5
    while watcher.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if watcher.poll() is None:
        watcher.terminate()
    _, stderr = watcher.communicate(timeout=2)
    assert watcher.returncode in expected_codes, (
        f"watcher exited unexpectedly: code={watcher.returncode}; "
        f"stderr={stderr.decode('utf-8', 'replace')[-4000:]!r}"
    )
    return stderr.decode("utf-8", "replace")


def test_marker_is_published_only_after_its_payload_is_complete(tmp_path, monkeypatch):
    marker = tmp_path / "flag"
    payload = b"complete marker payload"
    original_link = os.link
    observed_publish = False

    def checking_link(source, destination, *args, **kwargs):
        nonlocal observed_publish
        assert Path(source).read_bytes() == payload
        assert not Path(destination).exists()
        observed_publish = True
        return original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "link", checking_link)
    _write_marker(marker, payload)

    assert observed_publish
    assert marker.read_bytes() == payload
    assert marker.stat().st_mode & 0o777 == 0o600
    assert not tuple(tmp_path.glob(".flag.*.tmp"))


def test_missing_baseline_detects_empty_directory(tmp_path):
    root = tmp_path / "appeared"
    assert not _watcher_missing_baseline_violation(root, False)
    root.mkdir(mode=0o700)
    assert _watcher_missing_baseline_violation(root, False)
    assert not _watcher_missing_baseline_violation(root, True)


def test_missing_root_watcher_rejects_ancestor_symlink(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("secure directory traversal is unsupported on this platform")
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (real / "parent").mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    watcher, flag, ready = _start_watcher(tmp_path, alias / "parent" / "missing", False)
    _finish_watcher(watcher, expected_codes=(2,))
    assert flag.read_bytes() == b"missing-root path cannot be opened safely"
    assert not ready.exists()


def test_missing_root_watcher_rejects_ancestor_replacement_before_ready(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("secure directory traversal is unsupported on this platform")
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o700)
    (anchor / "parent").mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    pause = tmp_path / "registered"
    gate = tmp_path / "continue"
    watcher, flag, ready = _start_watcher(
        tmp_path, anchor / "parent" / "missing", False, pause=pause, gate=gate
    )
    try:
        _wait_for_marker(pause, watcher, "registration marker")
        anchor.rename(tmp_path / "anchor-old")
        anchor.symlink_to(external, target_is_directory=True)
        gate.touch(mode=0o600)
        _finish_watcher(watcher, expected_codes=(2,))
        assert flag.read_bytes() in {
            b"missing-root path changed before kqueue ready",
            b"missing-root path changed before inotify ready",
        }
        assert not ready.exists()
    finally:
        if watcher.poll() is None:
            watcher.terminate()
            watcher.wait(timeout=2)


def test_missing_root_watcher_detects_fast_create_delete(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "missing"
    watcher, flag, ready = _start_watcher(tmp_path, root, False)
    try:
        _wait_for_marker(ready, watcher, "ready marker")
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root.mkdir(mode=0o700)
            os.fsync(parent_fd)
            root.rmdir()
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        _wait_for_marker(flag, watcher, "transient event flag")
        assert not root.exists()
    finally:
        _finish_watcher(watcher)


def test_missing_root_watcher_detects_multiple_missing_levels(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "missing-one" / "missing-two"
    watcher, flag, ready = _start_watcher(tmp_path, root, False)
    try:
        _wait_for_marker(ready, watcher, "ready marker")
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            (parent / "missing-one").mkdir(mode=0o700)
            os.fsync(parent_fd)
            (parent / "missing-one").rmdir()
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        _wait_for_marker(flag, watcher, "transient event flag")
        assert not root.exists()
    finally:
        _finish_watcher(watcher)


def test_missing_root_watcher_detects_ready_after_parent_attrib_change(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    watcher, flag, ready = _start_watcher(tmp_path, parent / "missing", False)
    try:
        _wait_for_marker(ready, watcher, "ready marker")
        parent.chmod(0o750)
        _wait_for_marker(flag, watcher, "attribute event flag")
        assert flag.read_bytes() in {
            b"missing-root path changed after kqueue ready",
            b"inotify path event mask=0x00000004",
            b"inotify path event mask=0x40000004",
        }
    finally:
        _finish_watcher(watcher)


def test_inotify_event_parser_names_and_rejects_special_events():
    payload = b"".join(
        struct.pack("=iIII", index, mask, 0, 0)
        for index, mask in enumerate((IN_ATTRIB, IN_Q_OVERFLOW, IN_UNMOUNT, IN_IGNORED), 1)
    )
    events = parse_inotify_events(payload)
    assert [mask for _, mask, _, _ in events] == [IN_ATTRIB, IN_Q_OVERFLOW, IN_UNMOUNT, IN_IGNORED]
    assert _inotify_failure(IN_Q_OVERFLOW) == "inotify queue overflow"
    assert _inotify_failure(IN_UNMOUNT) == "inotify filesystem unmounted"
    assert _inotify_failure(IN_IGNORED) == "inotify watch was ignored"
    name_field = b"worktrees\0\0\0\0\0\0\0"
    named = struct.pack("=iIII", 7, 0, 0, len(name_field)) + name_field
    assert parse_inotify_events(named)[0][-1] == b"worktrees"
    assert _inotify_failure(IN_Q_OVERFLOW | 0x40000000) == "inotify queue overflow"
    for malformed in (
        struct.pack("=iIII", 1, IN_ATTRIB, 0, 2) + b"a\0",
        struct.pack("=iIII", 1, IN_ATTRIB, 0, 4) + b"abcd",
        struct.pack("=iIII", 1, IN_ATTRIB, 0, 8) + b"a\0\0x\0\0\0\0",
    ):
        with pytest.raises(ValueError):
            parse_inotify_events(malformed)
    with pytest.raises(ValueError, match="truncated"):
        parse_inotify_events(payload[:-1])


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux watcher contract")
def test_linux_existing_root_fails_closed_before_ready(tmp_path):
    root = tmp_path / "watched"
    root.mkdir(mode=0o700)
    watcher, flag, ready = _start_watcher(tmp_path, root, True)
    _finish_watcher(watcher, expected_codes=(2,))
    assert flag.read_bytes() == (
        b"Linux existing-root watcher unavailable: recursive inotify cannot safely "
        b"cover registration windows"
    )
    assert not ready.exists()


def test_existing_root_watcher_records_transient_write_after_final_state_is_restored(
    tmp_path,
):
    if (
        sys.platform.startswith("linux")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(select, "kqueue")
    ):
        pytest.skip("existing-root kqueue test is macOS-only")
    root = tmp_path / "watched"
    root.mkdir(mode=0o700)
    baseline = _inventory(root)
    watcher, flag, ready = _start_watcher(tmp_path, root, True)
    try:
        _wait_for_marker(ready, watcher, "ready marker")
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        transient = root / "transient.json"
        staged = root / "staged.json"
        try:
            fd = os.open(transient, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, b"temporary")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory_fd)
            os.rename(transient, staged)
            os.fsync(directory_fd)
            os.rename(staged, transient)
            os.fsync(directory_fd)
            os.unlink(transient)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _wait_for_marker(flag, watcher, "transient event flag")
        assert flag.read_bytes()
        assert _inventory(root) == baseline
    finally:
        _finish_watcher(watcher, expected_codes=(-15, 2))


def test_missing_root_named_worktrees_is_not_ignored(tmp_path):
    if not hasattr(select, "kqueue") and not sys.platform.startswith("linux"):
        pytest.skip("kernel missing-root watcher is unsupported on this platform")
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "worktrees"
    watcher, flag, ready = _start_watcher(tmp_path, root, False)
    try:
        _wait_for_marker(ready, watcher, "ready marker")
        root.mkdir(mode=0o700)
        root.rmdir()
        _wait_for_marker(flag, watcher, "missing worktrees event flag")
        assert not root.exists()
    finally:
        _finish_watcher(watcher)


def test_existing_root_watcher_records_file_modify_and_restore(tmp_path):
    if (
        sys.platform.startswith("linux")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(select, "kqueue")
    ):
        pytest.skip("existing-root kqueue test is macOS-only")
    root = tmp_path / "watched"
    root.mkdir(mode=0o700)
    target = root / "stable.txt"
    target.write_bytes(b"original")
    target.chmod(0o600)
    baseline = _inventory(root)
    watcher, flag, ready = _start_watcher(tmp_path, root, True)
    try:
        _wait_for_marker(ready, watcher, "ready marker")
        fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            os.write(fd, b"modified")
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, b"original")
            os.fsync(fd)
        finally:
            os.close(fd)
        _wait_for_marker(flag, watcher, "file modification flag")
        assert _inventory(root) == baseline
    finally:
        _finish_watcher(watcher, expected_codes=(-15, 2))
