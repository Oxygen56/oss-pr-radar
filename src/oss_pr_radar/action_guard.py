"""Cross-process opportunity guards for irreversible local and public actions."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_HELD_KEYS = threading.local()


def _open_private_child(parent_fd: int, name: str, *, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, flags, dir_fd=parent_fd)
    metadata = os.fstat(fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(fd)
        raise RuntimeError("action guard directory is not private")
    return fd


@contextmanager
def opportunity_action_guard(root: Path, opportunity_key: str) -> Iterator[None]:
    """Serialize one opportunity across processes and release on process exit.

    The lock name is a fixed-size SHA-256 encoding of the canonical key.  All
    path components are opened with no-follow semantics and the lock file is
    checked through its descriptor before flock is acquired.
    """

    if not opportunity_key or "\x00" in opportunity_key:
        raise ValueError("opportunity key is invalid")
    held_keys = getattr(_HELD_KEYS, "keys", set())
    if opportunity_key in held_keys:
        raise RuntimeError("opportunity action guard re-entry is not allowed")
    root = Path(root)
    root_metadata = os.lstat(root)
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise RuntimeError("action guard root is not a private directory")
    root_fd = os.open(
        root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    lock_dir_fd = -1
    lock_fd = -1
    try:
        root_after = os.fstat(root_fd)
        if (root_after.st_dev, root_after.st_ino) != (
            root_metadata.st_dev,
            root_metadata.st_ino,
        ):
            raise RuntimeError("action guard root changed while opening")
        lock_dir_fd = _open_private_child(root_fd, "action-locks", create=True)
        lock_name = f"op-{hashlib.sha256(opportunity_key.encode('utf-8')).hexdigest()}.lock"
        for attempt in range(5):
            try:
                lock_fd = os.open(
                    lock_name,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=lock_dir_fd,
                )
                break
            except FileNotFoundError:
                if attempt == 4:
                    raise
        lock_metadata = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != os.getuid()
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
        ):
            raise RuntimeError("action guard lock is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        held_keys.add(opportunity_key)
        _HELD_KEYS.keys = held_keys
        try:
            yield
        finally:
            held_keys.remove(opportunity_key)
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if lock_dir_fd >= 0:
            os.close(lock_dir_fd)
        os.close(root_fd)


def ledger_action_guard_root(ledger_path: Path) -> Path:
    """Return the private state directory used for one ledger's action locks."""

    state = Path(ledger_path).parent
    try:
        metadata = os.lstat(state)
    except OSError:
        return state
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("action guard state directory is unsafe")
    if metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700:
        return state
    # Some development fixtures place the ledger in a conventional 0755
    # `state` directory.  Use its already-private parent in that case; never
    # weaken the guard by accepting a public directory as the lock root.
    parent = state.parent
    parent_metadata = os.lstat(parent)
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise RuntimeError("action guard fallback root is not private")
    return parent
