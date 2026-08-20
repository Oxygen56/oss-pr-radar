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


_SECURE_CHAIN_PROBE = r"""
import os
import stat
import sys
import time
from pathlib import Path

path = Path(sys.argv[1])
flag = Path(sys.argv[2])
opened = Path(sys.argv[3])
gate = Path(sys.argv[4])

def mark(target, value):
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value)
        os.fsync(fd)
    finally:
        os.close(fd)

def open_chain(target):
    if not target.is_absolute() or target.parts[0] != os.sep:
        raise RuntimeError("path is not absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors = [os.open(os.sep, flags)]
    try:
        for component in target.parts[1:]:
            if component in ("", ".", ".."):
                raise RuntimeError("unsafe path component")
            descriptor = os.open(component, flags, dir_fd=descriptors[-1])
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise RuntimeError("path component is not a directory")
            descriptors.append(descriptor)
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise

try:
    descriptors = open_chain(path)
except BaseException as exc:
    mark(flag, f"rejected:{type(exc).__name__}".encode())
    raise SystemExit(2)

try:
    mark(opened, b"opened")
    while not gate.exists():
        time.sleep(0.001)
    try:
        fresh = open_chain(path)
    except BaseException:
        mark(flag, b"identity-mismatch")
        raise SystemExit(2)
    try:
        if len(fresh) != len(descriptors) or any(
            os.fstat(current).st_dev != os.fstat(original).st_dev
            or os.fstat(current).st_ino != os.fstat(original).st_ino
            for current, original in zip(fresh, descriptors)
        ):
            mark(flag, b"identity-mismatch")
            raise SystemExit(2)
    finally:
        for descriptor in fresh:
            os.close(descriptor)
finally:
    for descriptor in descriptors:
        os.close(descriptor)
"""


def _run_secure_chain_probe(path, flag, opened, gate):
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _SECURE_CHAIN_PROBE,
            str(path),
            str(flag),
            str(opened),
            str(gate),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        close_fds=True,
    )


def test_missing_root_watcher_rejects_ancestor_symlink(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("secure directory traversal is unsupported on this platform")
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    parent = real / "parent"
    parent.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    flag = tmp_path / "flag"
    opened = tmp_path / "opened"
    gate = tmp_path / "gate"
    watcher = _run_secure_chain_probe(alias / "parent", flag, opened, gate)
    _, stderr = watcher.communicate(timeout=5)
    assert watcher.returncode == 2, stderr.decode("utf-8", "replace")
    assert flag.read_bytes().startswith(b"rejected:")
    assert not opened.exists()


def test_missing_root_watcher_rechecks_ancestor_identity_after_open(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("secure directory traversal is unsupported on this platform")
    anchor = tmp_path / "anchor"
    anchor.mkdir(mode=0o700)
    parent = anchor / "parent"
    parent.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    path = anchor / "parent"
    flag = tmp_path / "flag"
    opened = tmp_path / "opened"
    gate = tmp_path / "gate"
    watcher = _run_secure_chain_probe(path, flag, opened, gate)
    try:
        deadline = time.monotonic() + 5
        while not opened.exists() and time.monotonic() < deadline:
            if watcher.poll() is not None:
                stderr = watcher.communicate()[1].decode("utf-8", "replace")
                raise AssertionError(f"probe exited before open: {stderr!r}")
            time.sleep(0.01)
        assert opened.is_file()
        anchor.rename(tmp_path / "anchor-old")
        anchor.symlink_to(external, target_is_directory=True)
        gate.touch(mode=0o600)
        _, stderr = watcher.communicate(timeout=5)
        assert watcher.returncode == 2, stderr.decode("utf-8", "replace")
        assert flag.read_bytes() == b"identity-mismatch"
    finally:
        if watcher.poll() is None:
            watcher.terminate()
            watcher.wait(timeout=2)


def test_missing_root_watcher_detects_fast_create_delete(tmp_path):
    if hasattr(select, "kqueue"):
        expected_ready = b"kqueue-missing-root-active"
        watcher_code = r"""
import os
import select
import sys
from pathlib import Path

parent = Path(sys.argv[1])
root = Path(sys.argv[2])
flag = Path(sys.argv[3])
ready = Path(sys.argv[4])

def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value)
        os.fsync(fd)
    finally:
        os.close(fd)

kq = select.kqueue()
fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    kq.control([select.kevent(
        fd,
        filter=select.KQ_FILTER_VNODE,
        flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
        fflags=(
            select.KQ_NOTE_WRITE
            | select.KQ_NOTE_EXTEND
            | select.KQ_NOTE_DELETE
            | select.KQ_NOTE_RENAME
            | select.KQ_NOTE_LINK
        ),
    )], 0, 0)
    if root.exists():
        write(flag, b"root existed before missing-root ready")
        raise SystemExit(2)
    write(ready, b"kqueue-missing-root-active")
    while True:
        events = kq.control(None, 1, 1)
        if events or root.exists():
            write(flag, b"missing root changed")
            raise SystemExit(2)
finally:
    os.close(fd)
    kq.close()
"""
    elif sys.platform.startswith("linux"):
        expected_ready = b"inotify-missing-root-active"
        watcher_code = r"""
import ctypes
import os
import sys
from pathlib import Path

parent = Path(sys.argv[1])
root = Path(sys.argv[2])
flag = Path(sys.argv[3])
ready = Path(sys.argv[4])

def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, value)
        os.fsync(fd)
    finally:
        os.close(fd)

libc = ctypes.CDLL(None, use_errno=True)
libc.inotify_init1.argtypes = [ctypes.c_int]
libc.inotify_init1.restype = ctypes.c_int
libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
libc.inotify_add_watch.restype = ctypes.c_int
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
notify_fd = libc.inotify_init1(os.O_CLOEXEC)
if notify_fd < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1 failed")
try:
    watch_mask = 0x00000100 | 0x00000200 | 0x00000040 | 0x00000080
    watch_descriptor = libc.inotify_add_watch(
        notify_fd,
        os.fsencode(f"/proc/self/fd/{parent_fd}"),
        watch_mask,
    )
    if watch_descriptor < 0:
        raise OSError(ctypes.get_errno(), "inotify_add_watch failed")
    if root.exists():
        write(flag, b"root existed before missing-root ready")
        raise SystemExit(2)
    write(ready, b"inotify-missing-root-active")
    while True:
        if os.read(notify_fd, 65536):
            write(flag, b"missing root changed")
            raise SystemExit(2)
finally:
    os.close(notify_fd)
    os.close(parent_fd)
"""
    else:
        pytest.skip("missing-root kernel event proof is unsupported on this platform")
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "missing"
    flag = tmp_path / "flag"
    ready = tmp_path / "ready"
    watcher = subprocess.Popen(
        [
            sys.executable,
            "-c",
            watcher_code,
            str(parent),
            str(root),
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
                stderr = watcher.communicate()[1].decode("utf-8", "replace")[-4000:]
                raise AssertionError(
                    f"missing-root watcher exited before ready: code={watcher.returncode}; "
                    f"stderr={stderr!r}"
                )
            time.sleep(0.01)
        assert ready.read_bytes() == expected_ready

        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root.mkdir(mode=0o700)
            os.fsync(parent_fd)
            root.rmdir()
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)

        deadline = time.monotonic() + 5
        while not flag.exists() and time.monotonic() < deadline:
            if watcher.poll() is not None:
                stderr = watcher.communicate()[1].decode("utf-8", "replace")[-4000:]
                raise AssertionError(
                    f"missing-root watcher exited before flag: code={watcher.returncode}; "
                    f"stderr={stderr!r}"
                )
            time.sleep(0.01)
        assert flag.is_file()
        assert not root.exists()
    finally:
        if watcher.poll() is None:
            watcher.terminate()
        _, stderr = watcher.communicate(timeout=2)
        assert watcher.returncode in (-15, 2), (
            f"missing-root watcher exited unexpectedly: code={watcher.returncode}; "
            f"stderr={stderr.decode('utf-8', 'replace')[-4000:]!r}"
        )


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
import time
from pathlib import Path

root = Path(sys.argv[1])
baseline = sys.argv[2]
flag = Path(sys.argv[3])
ready = Path(sys.argv[4])

def inventory(path):
    for _attempt in range(100):
        entries = []
        try:
            for current, dirs, files in os.walk(path, followlinks=False):
                current_path = Path(current)
                dirs[:] = [name for name in dirs if name != "worktrees"]
                for name in dirs + files:
                    item = current_path / name
                    relative = item.relative_to(path)
                    stat_result = item.lstat()
                    entries.append((str(relative), stat_result.st_mode & 0o777))
        except FileNotFoundError:
            time.sleep(0.001)
            continue
        entries.sort()
        return hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    raise RuntimeError("directory remained unstable while taking inventory")

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
        fflags=(
            select.KQ_NOTE_WRITE
            | select.KQ_NOTE_EXTEND
            | select.KQ_NOTE_DELETE
            | select.KQ_NOTE_RENAME
            | select.KQ_NOTE_LINK
        ),
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

        def stderr_after_exit():
            if watcher.stderr is None:
                return ""
            if watcher.poll() is None:
                return "watcher still running"
            return watcher.stderr.read().decode("utf-8", "replace")[-4000:]

        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        transient = root / "transient.json"
        staged = root / "staged.json"
        try:
            fd = os.open(
                transient,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
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
        deadline = time.monotonic() + 5
        while not flag.exists() and time.monotonic() < deadline:
            if watcher.poll() is not None:
                raise AssertionError(
                    f"watcher exited before flag: code={watcher.returncode}; "
                    f"stderr={stderr_after_exit()!r}"
                )
            time.sleep(0.01)
        if not flag.is_file():
            raise AssertionError(
                f"watcher did not record event: code={watcher.poll()}; "
                f"stderr={stderr_after_exit()!r}"
            )
        assert flag.read_text(encoding="utf-8").startswith(f"baseline={baseline};")
        assert _inventory(root) == baseline
    finally:
        if watcher.poll() is None:
            watcher.terminate()
        _, stderr = watcher.communicate(timeout=2)
        if watcher.returncode not in (0, -15, 2):
            raise AssertionError(
                f"watcher exited unexpectedly: code={watcher.returncode}; "
                f"stderr={stderr.decode('utf-8', 'replace')[-4000:]!r}"
            )
