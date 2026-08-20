from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _host_radar_inventory(root: Path) -> str:
    """Fingerprint host shared state without following worktree contents."""

    entries = []
    if root.exists():
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            relative_current = current_path.relative_to(root)
            if relative_current.parts and relative_current.parts[0] == "worktrees":
                dirs[:] = []
                continue
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
    payload = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _host_radar_shared_inventory(root: Path) -> str:
    """Fingerprint the shared task directories for transient-write detection."""

    entries = [(_host_radar_inventory(root),)]
    for name in ("task-contexts", "context-quarantine"):
        path = root / name
        entries.append((name, _host_radar_inventory(path)))
    return hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _watcher_missing_baseline_violation(root: Path, baseline_exists: bool) -> bool:
    """The missing-root watcher must treat an empty directory as a write."""

    return not baseline_exists and root.exists()


@pytest.fixture(scope="session", autouse=True)
def no_host_radar_private_writes(tmp_path_factory):
    """Make the full suite fail if it writes the live shared radar root."""

    root = Path.home() / "Documents" / "github" / ".oss-pr-radar"
    root_preexisting = root.exists()
    before = _host_radar_inventory(root)
    shared_before = _host_radar_shared_inventory(root)
    watcher_code = r"""
import hashlib
import json
import os
import select
import stat
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
baseline = sys.argv[2]
baseline_exists = sys.argv[3] == "1"
flag = Path(sys.argv[4])
ready = Path(sys.argv[5])

def inventory(path):
    entries = []
    if path.exists():
        for current, dirs, files in os.walk(path, followlinks=False):
            current_path = Path(current)
            relative_current = current_path.relative_to(path)
            if relative_current.parts and relative_current.parts[0] == "worktrees":
                dirs[:] = []
                continue
            dirs[:] = [name for name in dirs if name != "worktrees"]
            for name in dirs + files:
                item = current_path / name
                relative = item.relative_to(path)
                stat_result = item.lstat()
                if item.is_symlink():
                    entries.append((str(relative), "symlink", os.readlink(item)))
                elif item.is_file():
                    entries.append((str(relative), "file", stat_result.st_mode & 0o777, hashlib.sha256(item.read_bytes()).hexdigest()))
                else:
                    entries.append((str(relative), "directory", stat_result.st_mode & 0o777))
    entries.sort()
    payload = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def write_marker(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)

if not hasattr(select, "kqueue"):
    if sys.platform.startswith("linux") and not baseline_exists:
        import ctypes

        parent = root.parent
        while True:
            try:
                parent_stat = parent.lstat()
            except FileNotFoundError:
                if parent == parent.parent:
                    write_marker(flag, b"no existing parent is available for missing root")
                    raise SystemExit(2)
                parent = parent.parent
                continue
            if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
                write_marker(flag, b"missing root parent is unsafe")
                raise SystemExit(2)
            break

        parent_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            parent_fd_stat = os.fstat(parent_fd)
            if (
                not stat.S_ISDIR(parent_fd_stat.st_mode)
                or parent_fd_stat.st_uid != os.getuid()
                or parent_fd_stat.st_mode & 0o022
            ):
                write_marker(flag, b"missing root parent failed private directory checks")
                raise SystemExit(2)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_init1.restype = ctypes.c_int
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            libc.inotify_add_watch.restype = ctypes.c_int
            notify_fd = libc.inotify_init1(getattr(os, "O_CLOEXEC", 0))
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
                    write_marker(flag, b"host radar root appeared before missing-root ready")
                    raise SystemExit(2)
                write_marker(ready, b"inotify-missing-root-active")
                while True:
                    if os.read(notify_fd, 65536):
                        write_marker(flag, b"host radar root changed after missing-root ready")
                        raise SystemExit(2)
            finally:
                os.close(notify_fd)
        finally:
            os.close(parent_fd)

    if not baseline_exists:
        write_marker(flag, b"missing-root kernel event watcher is unsupported on this platform")
        raise SystemExit(2)
    write_marker(ready, b"unsupported:kqueue")
    while True:
        if inventory(root) != baseline:
            write_marker(flag, b"host radar state changed")
            raise SystemExit(2)
        time.sleep(0.05)

if not baseline_exists:
    parent = root.parent
    while True:
        try:
            parent_stat = parent.lstat()
        except FileNotFoundError:
            if parent == parent.parent:
                write_marker(flag, b"no existing parent is available for missing root")
                raise SystemExit(2)
            parent = parent.parent
            continue
        if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode):
            write_marker(flag, b"missing root parent is unsafe")
            raise SystemExit(2)
        break

    kqueue = select.kqueue()
    parent_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        parent_fd_stat = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_fd_stat.st_mode)
            or parent_fd_stat.st_uid != os.getuid()
            or parent_fd_stat.st_mode & 0o022
        ):
            write_marker(flag, b"missing root parent failed private directory checks")
            raise SystemExit(2)
        kqueue.control(
            [
                select.kevent(
                    parent_fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                    fflags=(
                        select.KQ_NOTE_WRITE
                        | select.KQ_NOTE_EXTEND
                        | select.KQ_NOTE_DELETE
                        | select.KQ_NOTE_RENAME
                        | select.KQ_NOTE_LINK
                    ),
                )
            ],
            0,
            0,
        )
        if root.exists():
            write_marker(flag, b"host radar root appeared before missing-root ready")
            raise SystemExit(2)
        write_marker(ready, b"kqueue-missing-root-active")
        while True:
            events = kqueue.control(None, 1, 0.5)
            if events or root.exists():
                write_marker(flag, b"host radar root changed after missing-root ready")
                raise SystemExit(2)
    finally:
        os.close(parent_fd)
        kqueue.close()

if root.is_symlink() or not root.is_dir():
    write_marker(flag, b"host radar root is unsafe before ready")
    raise SystemExit(2)

if inventory(root) != baseline:
    write_marker(flag, b"host radar state changed before ready")
    raise SystemExit(2)

kqueue = select.kqueue()
descriptors = []
try:
    paths = [root]
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        if current_path != root and current_path.relative_to(root).parts[:1] == ("worktrees",):
            dirs[:] = []
            continue
        dirs[:] = [name for name in dirs if name != "worktrees"]
        paths.extend(current_path / name for name in dirs + files)
    events = []
    for path in paths:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | (getattr(os, "O_DIRECTORY", 0) if path.is_dir() else 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except (FileNotFoundError, NotADirectoryError, OSError) as exc:
            raise RuntimeError(f"failed to open watched path {path}: {exc}") from exc
        descriptors.append(descriptor)
        events.append(
            select.kevent(
                descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                fflags=(
                    select.KQ_NOTE_WRITE
                    | select.KQ_NOTE_EXTEND
                    | select.KQ_NOTE_ATTRIB
                    | select.KQ_NOTE_DELETE
                    | select.KQ_NOTE_RENAME
                    | select.KQ_NOTE_LINK
                    | select.KQ_NOTE_REVOKE
                ),
            )
        )
    if events:
        kqueue.control(events, 0, 0)
    else:
        raise RuntimeError("kqueue watcher registered no paths")

    if inventory(root) != baseline:
        write_marker(flag, b"host radar state changed before ready")
        raise SystemExit(2)
    write_marker(ready, b"kqueue-active")

    while True:
        events = kqueue.control(None, 1, 0.5)
        if not events:
            continue
        current = inventory(root)
        write_marker(
            flag,
            f"host radar filesystem event; baseline={baseline}; current={current}".encode(
                "ascii"
            ),
        )
        raise SystemExit(2)
finally:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass
    kqueue.close()
"""
    watcher_dir = tmp_path_factory.mktemp("radar-host-watch") / "watch"
    watcher_dir.mkdir(mode=0o700)
    watcher_flag = watcher_dir / f"{os.getpid()}.flag"
    watcher_ready = watcher_dir / f"{os.getpid()}.ready"
    watcher_stderr_path = watcher_dir / f"{os.getpid()}.stderr"
    watcher_stderr = os.fdopen(
        os.open(
            watcher_stderr_path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL,
            0o600,
        ),
        "w+b",
    )
    watcher = subprocess.Popen(
        [
            sys.executable,
            "-c",
            watcher_code,
            str(root),
            before,
            "1" if root_preexisting else "0",
            str(watcher_flag),
            str(watcher_ready),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=watcher_stderr,
        close_fds=True,
    )
    try:
        ready_deadline = time.monotonic() + 5
        while not watcher_ready.exists() and time.monotonic() < ready_deadline:
            if watcher.poll() is not None:
                watcher_stderr.flush()
                watcher_stderr.seek(0)
                diagnostic = watcher_stderr.read()[-4000:].decode("utf-8", "replace")
                flag_diagnostic = (
                    watcher_flag.read_bytes()[-4000:] if watcher_flag.exists() else b""
                )
                raise AssertionError(
                    f"host watcher exited before ready: code={watcher.returncode}, "
                    f"stderr={diagnostic!r}, flag={flag_diagnostic!r}"
                )
            time.sleep(0.05)
        if not watcher_ready.exists():
            raise AssertionError("host watcher did not become ready")
        ready_value = watcher_ready.read_bytes()
        if ready_value != b"kqueue-active" and not ready_value.startswith(b"unsupported:"):
            raise AssertionError(f"host watcher did not activate kqueue: {ready_value!r}")
        yield
    finally:
        exit_code = watcher.poll()
        intentionally_terminated = False
        if exit_code is None:
            intentionally_terminated = True
            watcher.terminate()
        try:
            watcher.wait(timeout=2)
        except subprocess.TimeoutExpired:
            watcher.kill()
            watcher.wait(timeout=2)
        exit_code = watcher.returncode
        watcher_stderr.flush()
        watcher_stderr.seek(0)
        diagnostic = watcher_stderr.read()[-4000:].decode("utf-8", "replace")
        watcher_stderr.close()
        after = _host_radar_inventory(root)
        assert after == before, (
            f"tests modified the live .oss-pr-radar shared state: before={before} after={after}"
        )
        allowed_exit_codes = (None, 0, -15) if intentionally_terminated else (0,)
        assert exit_code in allowed_exit_codes, (
            f"host watcher exited unexpectedly: code={exit_code}, stderr={diagnostic!r}"
        )
        assert not watcher_flag.exists(), (
            "tests transiently modified the live shared radar state: "
            f"baseline={before} flag={watcher_flag.read_bytes()!r}"
            if watcher_flag.exists()
            else "tests transiently modified the live shared radar state"
        )
    assert _host_radar_shared_inventory(root) == shared_before


@pytest.fixture(autouse=True)
def hermetic_local_dispatch_bridge(monkeypatch, tmp_path_factory):
    """Keep local bridge tests out of the user's shared task directory."""

    from scripts import local_dispatch_bridge

    hermetic_root = tmp_path_factory.mktemp("radar-hermetic")
    home = hermetic_root / "home"
    private_env = {
        "HOME": home,
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_DATA_HOME": home / ".local" / "share",
        "XDG_STATE_HOME": home / ".local" / "state",
        "XDG_CACHE_HOME": home / ".cache",
        "CODEX_HOME": home / ".codex",
        "TMPDIR": hermetic_root / "tmp",
    }
    for path in private_env.values():
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    for name, path in private_env.items():
        monkeypatch.setenv(name, str(path))

    github_root = hermetic_root / "github_root"
    monkeypatch.setattr(local_dispatch_bridge, "GITHUB_ROOT", github_root)
    for module in list(sys.modules.values()):
        bridge = getattr(module, "BRIDGE", None)
        if getattr(bridge, "__file__", "").endswith("scripts/local_dispatch_bridge.py"):
            monkeypatch.setattr(bridge, "GITHUB_ROOT", github_root)
    private_root = github_root / local_dispatch_bridge.TASK_PRIVATE_DIR
    private_root.mkdir(parents=True, exist_ok=True)
    private_root.chmod(0o700)


@pytest.fixture(autouse=True)
def deterministic_test_signing_key(monkeypatch):
    """Keep signed test fixtures independent of the host shell environment."""

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 64)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "test-current")


@pytest.fixture
def current_signing_key(monkeypatch):
    """Explicit opt-in key for tests that create newly authorized evidence."""

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "managed-test-signing-key-0123456789abcdef")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "test-current")
