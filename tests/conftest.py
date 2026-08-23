from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.host_radar_watcher import WATCHER_SCRIPT

# Hashing and registering the existing shared tree can exceed five seconds
# under concurrent local CPU or filesystem load. The watcher still reports
# ready only after its fail-closed baseline and kernel watches are active.
HOST_WATCHER_READY_TIMEOUT_SECONDS = 30


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
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
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
    watcher_dir = tmp_path_factory.mktemp("radar-host-watch") / "watch"
    watcher_dir.mkdir(mode=0o700)
    watcher_flag = watcher_dir / f"{os.getpid()}.flag"
    watcher_ready = watcher_dir / f"{os.getpid()}.ready"
    watcher_stderr_path = watcher_dir / f"{os.getpid()}.stderr"
    watcher_stderr = os.fdopen(
        os.open(watcher_stderr_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600),
        "w+b",
    )
    watcher = subprocess.Popen(
        [
            sys.executable,
            str(WATCHER_SCRIPT),
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
        ready_deadline = time.monotonic() + HOST_WATCHER_READY_TIMEOUT_SECONDS
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
        valid_ready = {
            b"kqueue-active",
            b"kqueue-missing-root-active",
            b"inotify-missing-root-active",
            b"inotify-active",
        }
        if ready_value not in valid_ready:
            raise AssertionError(f"host watcher did not activate: {ready_value!r}")
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
