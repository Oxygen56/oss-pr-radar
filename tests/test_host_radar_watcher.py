from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import _watcher_missing_baseline_violation


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


def test_missing_baseline_detects_empty_directory(tmp_path):
    root = tmp_path / "appeared"
    assert not _watcher_missing_baseline_violation(root, False)
    root.mkdir(mode=0o700)
    assert _watcher_missing_baseline_violation(root, False)
    assert not _watcher_missing_baseline_violation(root, True)


def test_kqueue_watcher_records_transient_write_after_final_state_is_restored(tmp_path):
    if not hasattr(select, "kqueue"):
        pytest.skip("kqueue transient-event proof is unsupported on this platform")
    root = tmp_path / "watched"
    root.mkdir(mode=0o700)
    flag = tmp_path / "flag"
    ready = tmp_path / "ready"
    baseline = _inventory(root)
    watcher = subprocess.Popen(
        [
            sys.executable,
            "-c",
            r"""
import hashlib
import json
import os
import select
import sys
from pathlib import Path

root = Path(sys.argv[1])
baseline = sys.argv[2]
flag = Path(sys.argv[3])
ready = Path(sys.argv[4])

def inventory(path):
    entries = []
    for current, dirs, files in os.walk(path, followlinks=False):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if name != "worktrees"]
        for name in dirs + files:
            item = current_path / name
            relative = item.relative_to(path)
            stat_result = item.lstat()
            entries.append((str(relative), stat_result.st_mode & 0o777))
    entries.sort()
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value)
        os.fsync(fd)
    finally:
        os.close(fd)

kq = select.kqueue()
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    kq.control([select.kevent(
        fd,
        filter=select.KQ_FILTER_VNODE,
        flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
        fflags=select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_DELETE,
    )], 0, 0)
    if inventory(root) != baseline:
        raise SystemExit("baseline changed before ready")
    write(ready, b"kqueue-active")
    while True:
        if kq.control(None, 1, 1):
            current = inventory(root)
            write(flag, f"baseline={baseline};current={current}".encode())
            raise SystemExit(2)
finally:
    os.close(fd)
    kq.close()
""",
            str(root),
            baseline,
            str(flag),
            str(ready),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            if watcher.poll() is not None:
                raise AssertionError(f"watcher exited before ready: {watcher.returncode}")
            time.sleep(0.01)
        assert ready.read_bytes() == b"kqueue-active"
        transient = root / "transient.json"
        transient.write_text("temporary", encoding="utf-8")
        transient.unlink()
        deadline = time.monotonic() + 5
        while not flag.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert flag.is_file()
        assert flag.read_text(encoding="utf-8").startswith(f"baseline={baseline};")
        assert _inventory(root) == baseline
    finally:
        if watcher.poll() is None:
            watcher.terminate()
        watcher.wait(timeout=2)
