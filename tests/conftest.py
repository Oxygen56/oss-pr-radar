from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest


def _host_radar_inventory(root: Path) -> str:
    """Fingerprint host shared state without following worktree contents."""

    entries = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if relative.parts and relative.parts[0] == "worktrees":
                continue
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
    payload = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@pytest.fixture(scope="session", autouse=True)
def no_host_radar_private_writes():
    """Make the full suite fail if it writes the live shared radar root."""

    root = Path.home() / "Documents" / "github" / ".oss-pr-radar"
    before = _host_radar_inventory(root)
    yield
    after = _host_radar_inventory(root)
    assert after == before, "tests modified the live .oss-pr-radar shared state"


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
