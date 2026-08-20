"""Hermetic subprocess watcher used by the host-write protection fixture."""

from __future__ import annotations

import hashlib
import json
import os
import select
import stat
import struct
import sys
import time
from pathlib import Path

WATCHER_SCRIPT = Path(__file__).resolve()

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

_INOTIFY_EVENT = struct.Struct("=iIII")
_INOTIFY_SELF_EVENTS = IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF
_INOTIFY_PARENT_EVENTS = _INOTIFY_SELF_EVENTS | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
_INOTIFY_DIRECTORY_EVENTS = _INOTIFY_PARENT_EVENTS | IN_MODIFY | IN_CLOSE_WRITE
_INOTIFY_FILE_EVENTS = IN_MODIFY | IN_CLOSE_WRITE | _INOTIFY_SELF_EVENTS


def parse_inotify_events(payload: bytes) -> tuple[tuple[int, int, int, bytes], ...]:
    """Decode a complete inotify read and reject truncated records."""

    events = []
    offset = 0
    while offset < len(payload):
        if len(payload) - offset < _INOTIFY_EVENT.size:
            raise ValueError("truncated inotify event header")
        watch_descriptor, mask, cookie, name_length = _INOTIFY_EVENT.unpack_from(payload, offset)
        offset += _INOTIFY_EVENT.size
        if name_length and name_length % 4:
            raise ValueError("unaligned inotify event name")
        end = offset + name_length
        if end > len(payload):
            raise ValueError("truncated inotify event name")
        name_field = payload[offset:end]
        if name_length:
            nul = name_field.find(b"\0")
            if nul < 0:
                raise ValueError("inotify event name is not NUL-terminated")
            if any(name_field[nul:]):
                raise ValueError("inotify event name padding is not NUL")
            name = name_field[:nul]
        else:
            name = b""
        events.append((watch_descriptor, mask, cookie, name))
        offset = end
    return tuple(events)


def _inotify_failure(mask: int) -> str:
    if mask & IN_Q_OVERFLOW:
        return "inotify queue overflow"
    if mask & IN_UNMOUNT:
        return "inotify filesystem unmounted"
    if mask & IN_IGNORED:
        return "inotify watch was ignored"
    return f"inotify path event mask=0x{mask:08x}"


def _is_ignored_worktrees_event(mask: int, name: bytes) -> bool:
    return name == b"worktrees" and bool(mask & IN_ISDIR)


def _inotify_event_failure(
    watch_descriptor: int,
    mask: int,
    name: bytes,
    known_watch_descriptors: set[int],
    ignored_parent_descriptors: set[int] | frozenset[int],
) -> str | None:
    if mask & (IN_Q_OVERFLOW | IN_UNMOUNT | IN_IGNORED):
        return _inotify_failure(mask)
    if watch_descriptor not in known_watch_descriptors:
        return f"unknown inotify watch descriptor={watch_descriptor}"
    if watch_descriptor in ignored_parent_descriptors and _is_ignored_worktrees_event(mask, name):
        return None
    return _inotify_failure(mask)


def _inventory(path: Path) -> str:
    for _attempt in range(100):
        entries = []
        try:
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
                            entries.append(
                                (
                                    str(relative),
                                    "file",
                                    stat_result.st_mode & 0o777,
                                    hashlib.sha256(item.read_bytes()).hexdigest(),
                                )
                            )
                        else:
                            entries.append(
                                (str(relative), "directory", stat_result.st_mode & 0o777)
                            )
        except FileNotFoundError:
            time.sleep(0.001)
            continue
        entries.sort()
        return hashlib.sha256(
            json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    raise RuntimeError("directory remained unstable while taking inventory")


def _write_marker(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def _fail_closed(flag: Path, message: str) -> None:
    _write_marker(flag, message.encode("utf-8"))
    raise SystemExit(2)


def _open_existing_directory_chain(
    path: Path, flag: Path, *, report_failure: bool = True
) -> tuple[list[int], str | None]:
    def reject(message: str) -> None:
        if report_failure:
            _fail_closed(flag, message)
        raise OSError(message)

    if not path.is_absolute() or path.parts[0] != os.sep:
        reject("missing-root path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptors = [os.open(os.sep, flags)]
    try:
        for component in path.parts[1:]:
            if component in ("", ".", ".."):
                reject("missing-root path contains an unsafe component")
            try:
                descriptor = os.open(component, flags, dir_fd=descriptors[-1])
            except FileNotFoundError:
                final_stat = os.fstat(descriptors[-1])
                if final_stat.st_uid != os.getuid() or final_stat.st_mode & 0o022:
                    reject("missing-root parent failed private directory checks")
                return descriptors, component
            descriptor_stat = os.fstat(descriptor)
            if not stat.S_ISDIR(descriptor_stat.st_mode):
                reject("missing-root path component is not a directory")
            descriptors.append(descriptor)
        final_stat = os.fstat(descriptors[-1])
        if final_stat.st_uid != os.getuid() or final_stat.st_mode & 0o022:
            reject("missing-root parent failed private directory checks")
        return descriptors, None
    except BaseException:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _chain_matches(
    path: Path, expected_descriptors: list[int], expected_missing: str, flag: Path
) -> bool:
    try:
        current_descriptors, current_missing = _open_existing_directory_chain(
            path, flag, report_failure=False
        )
    except (OSError, SystemExit):
        return False
    try:
        return (
            current_missing == expected_missing
            and len(current_descriptors) == len(expected_descriptors)
            and all(
                os.fstat(current).st_dev == os.fstat(expected).st_dev
                and os.fstat(current).st_ino == os.fstat(expected).st_ino
                for current, expected in zip(current_descriptors, expected_descriptors, strict=True)
            )
        )
    finally:
        for descriptor in current_descriptors:
            os.close(descriptor)


def _target_is_missing(parent_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _wait_for_gate(gate: Path | None) -> None:
    if gate is None:
        return
    while not gate.exists():
        time.sleep(0.001)


def _safe_open_child(parent_descriptor: int, entry, flag: Path) -> tuple[int, bool]:
    entry_stat = entry.stat(follow_symlinks=False)
    if stat.S_ISLNK(entry_stat.st_mode):
        _fail_closed(flag, "existing-root watcher found a symlink")
    is_directory = stat.S_ISDIR(entry_stat.st_mode)
    if not is_directory and not stat.S_ISREG(entry_stat.st_mode):
        _fail_closed(flag, "existing-root watcher found a non-regular entry")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if is_directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(entry.name, flags, dir_fd=parent_descriptor)
    opened_stat = os.fstat(descriptor)
    if (
        opened_stat.st_dev != entry_stat.st_dev
        or opened_stat.st_ino != entry_stat.st_ino
        or opened_stat.st_mode != entry_stat.st_mode
        or opened_stat.st_uid != os.getuid()
        or opened_stat.st_mode & 0o022
    ):
        os.close(descriptor)
        _fail_closed(flag, "existing-root watcher found an unsafe replacement")
    return descriptor, is_directory


def _create_inotify(nonblocking: bool):
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int
    flags = getattr(os, "O_CLOEXEC", 0)
    if nonblocking:
        flags |= getattr(os, "O_NONBLOCK", 0)
    notify_fd = libc.inotify_init1(flags)
    if notify_fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1 failed")
    return libc, notify_fd


def _add_inotify_watch(libc, notify_fd: int, descriptor: int, mask: int, flag: Path) -> int:
    watch_descriptor = libc.inotify_add_watch(
        notify_fd,
        os.fsencode(f"/proc/self/fd/{descriptor}"),
        mask,
    )
    if watch_descriptor < 0:
        _fail_closed(flag, "inotify_add_watch failed")
    return watch_descriptor


def _drain_inotify(
    notify_fd: int,
    flag: Path,
    known_watch_descriptors: set[int],
    ignored_parent_descriptors: set[int] | frozenset[int],
) -> None:
    while True:
        try:
            payload = os.read(notify_fd, 65536)
        except BlockingIOError:
            return
        if not payload:
            _fail_closed(flag, "inotify stream closed")
        try:
            events = parse_inotify_events(payload)
        except ValueError as exc:
            _fail_closed(flag, f"malformed inotify event: {exc}")
        for watch_descriptor, mask, _, name in events:
            failure = _inotify_event_failure(
                watch_descriptor,
                mask,
                name,
                known_watch_descriptors,
                ignored_parent_descriptors,
            )
            if failure is not None:
                _fail_closed(flag, failure)


def _verify_existing_root_state(
    root: Path, expected_chain: list[int], baseline: str, flag: Path
) -> None:
    if not _chain_matches(root, expected_chain, None, flag):
        _fail_closed(flag, "existing-root path changed before inotify ready")
    try:
        current = _inventory(root)
    except (OSError, RuntimeError) as exc:
        _fail_closed(flag, f"existing-root inventory failed before inotify ready: {exc}")
    if current != baseline:
        _fail_closed(flag, "host radar state changed before inotify ready")


def _watch_existing_root_inotify(
    root: Path,
    baseline: str,
    flag: Path,
    ready: Path,
    pause: Path | None,
    gate: Path | None,
) -> None:
    try:
        chain_descriptors, missing_component = _open_existing_directory_chain(root, flag)
    except OSError:
        _fail_closed(flag, "existing-root watcher could not securely open root chain")
    if missing_component is not None:
        _fail_closed(flag, "existing-root target is missing")
    try:
        libc, notify_fd = _create_inotify(nonblocking=True)
    except OSError:
        for descriptor in chain_descriptors:
            os.close(descriptor)
        _fail_closed(flag, "inotify_init1 failed")
    descriptors = list(chain_descriptors)
    known_watch_descriptors = set()
    ignored_parent_descriptors = set()
    try:
        for index, descriptor in enumerate(chain_descriptors):
            watch_mask = (
                _INOTIFY_DIRECTORY_EVENTS
                if index == len(chain_descriptors) - 1
                else _INOTIFY_SELF_EVENTS
            )
            watch_descriptor = _add_inotify_watch(libc, notify_fd, descriptor, watch_mask, flag)
            known_watch_descriptors.add(watch_descriptor)
            if index == len(chain_descriptors) - 1:
                ignored_parent_descriptors.add(watch_descriptor)
        if pause is not None:
            _write_marker(pause, b"root-registered")
            _wait_for_gate(gate)
        pending_directories = [chain_descriptors[-1]]
        while pending_directories:
            parent_descriptor = pending_directories.pop()
            with os.scandir(f"/proc/self/fd/{parent_descriptor}") as entries:
                for entry in entries:
                    entry_stat = entry.stat(follow_symlinks=False)
                    if entry.name == "worktrees" and stat.S_ISDIR(entry_stat.st_mode):
                        continue
                    descriptor, is_directory = _safe_open_child(parent_descriptor, entry, flag)
                    descriptors.append(descriptor)
                    watch_mask = _INOTIFY_DIRECTORY_EVENTS if is_directory else _INOTIFY_FILE_EVENTS
                    watch_descriptor = _add_inotify_watch(
                        libc, notify_fd, descriptor, watch_mask, flag
                    )
                    known_watch_descriptors.add(watch_descriptor)
                    if is_directory:
                        ignored_parent_descriptors.add(watch_descriptor)
                        pending_directories.append(descriptor)
        _drain_inotify(notify_fd, flag, known_watch_descriptors, ignored_parent_descriptors)
        _verify_existing_root_state(root, chain_descriptors, baseline, flag)
        _drain_inotify(notify_fd, flag, known_watch_descriptors, ignored_parent_descriptors)
        _verify_existing_root_state(root, chain_descriptors, baseline, flag)
        _drain_inotify(notify_fd, flag, known_watch_descriptors, ignored_parent_descriptors)
        os.set_blocking(notify_fd, True)
        _write_marker(ready, b"inotify-active")
        while True:
            try:
                payload = os.read(notify_fd, 65536)
                if not payload:
                    _fail_closed(flag, "inotify stream closed")
                events = parse_inotify_events(payload)
            except ValueError as exc:
                _fail_closed(flag, f"malformed inotify event: {exc}")
            for watch_descriptor, mask, _, name in events:
                failure = _inotify_event_failure(
                    watch_descriptor,
                    mask,
                    name,
                    known_watch_descriptors,
                    ignored_parent_descriptors,
                )
                if failure is not None:
                    _fail_closed(flag, failure)
    finally:
        os.close(notify_fd)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _watch_missing_root(
    root: Path, flag: Path, ready: Path, pause: Path | None, gate: Path | None
) -> None:
    try:
        chain_descriptors, missing_component = _open_existing_directory_chain(root, flag)
    except OSError:
        _fail_closed(flag, "missing-root path cannot be opened safely")
    if missing_component is None:
        _fail_closed(flag, "missing-root target already exists")
    parent_descriptor = chain_descriptors[-1]
    try:
        if hasattr(select, "kqueue"):
            kqueue = select.kqueue()
            try:
                events = [
                    select.kevent(
                        descriptor,
                        filter=select.KQ_FILTER_VNODE,
                        flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                        fflags=(
                            select.KQ_NOTE_ATTRIB
                            | select.KQ_NOTE_DELETE
                            | select.KQ_NOTE_RENAME
                            | select.KQ_NOTE_REVOKE
                            | select.KQ_NOTE_LINK
                            | (select.KQ_NOTE_WRITE if descriptor == parent_descriptor else 0)
                        ),
                    )
                    for descriptor in chain_descriptors
                ]
                kqueue.control(events, 0, 0)
                if pause is not None:
                    _write_marker(pause, b"registered")
                    _wait_for_gate(gate)
                if not _chain_matches(
                    root, chain_descriptors, missing_component, flag
                ) or not _target_is_missing(parent_descriptor, missing_component):
                    _fail_closed(flag, "missing-root path changed before kqueue ready")
                _write_marker(ready, b"kqueue-missing-root-active")
                while True:
                    if kqueue.control(None, 1, 0.5):
                        _fail_closed(flag, "missing-root path changed after kqueue ready")
            finally:
                kqueue.close()
        elif sys.platform.startswith("linux"):
            libc, notify_fd = _create_inotify(nonblocking=False)
            known_watch_descriptors = set()
            try:
                for descriptor in chain_descriptors:
                    watch_mask = (
                        _INOTIFY_PARENT_EVENTS
                        if descriptor == parent_descriptor
                        else _INOTIFY_SELF_EVENTS
                    )
                    watch_descriptor = _add_inotify_watch(
                        libc, notify_fd, descriptor, watch_mask, flag
                    )
                    known_watch_descriptors.add(watch_descriptor)
                if pause is not None:
                    _write_marker(pause, b"registered")
                    _wait_for_gate(gate)
                if not _chain_matches(
                    root, chain_descriptors, missing_component, flag
                ) or not _target_is_missing(parent_descriptor, missing_component):
                    _fail_closed(flag, "missing-root path changed before inotify ready")
                _write_marker(ready, b"inotify-missing-root-active")
                while True:
                    try:
                        payload = os.read(notify_fd, 65536)
                        if not payload:
                            _fail_closed(flag, "inotify stream closed")
                        events = parse_inotify_events(payload)
                    except ValueError as exc:
                        _fail_closed(flag, f"malformed inotify event: {exc}")
                    for watch_descriptor, mask, _, name in events:
                        failure = _inotify_event_failure(
                            watch_descriptor, mask, name, known_watch_descriptors, frozenset()
                        )
                        if failure is not None:
                            _fail_closed(flag, failure)
            finally:
                os.close(notify_fd)
        else:
            _fail_closed(flag, "missing-root kernel event watcher is unsupported on this platform")
    finally:
        for descriptor in chain_descriptors:
            os.close(descriptor)


def _watch_existing_root(
    root: Path,
    baseline: str,
    flag: Path,
    ready: Path,
    pause: Path | None,
    gate: Path | None,
) -> None:
    if sys.platform.startswith("linux"):
        _watch_existing_root_inotify(root, baseline, flag, ready, pause, gate)
        return
    if not hasattr(select, "kqueue"):
        _fail_closed(flag, "existing-root kernel event watcher is unsupported on this platform")
    if root.is_symlink() or not root.is_dir():
        _fail_closed(flag, "host radar root is unsafe before ready")
    if _inventory(root) != baseline:
        _fail_closed(flag, "host radar state changed before ready")
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
        if not events:
            raise RuntimeError("kqueue watcher registered no paths")
        kqueue.control(events, 0, 0)
        if _inventory(root) != baseline:
            _fail_closed(flag, "host radar state changed before ready")
        _write_marker(ready, b"kqueue-active")
        while True:
            events = kqueue.control(None, 1, 0.5)
            if not events:
                continue
            current = _inventory(root)
            _write_marker(
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


def main(argv: list[str]) -> None:
    root = Path(argv[1])
    baseline = argv[2]
    baseline_exists = argv[3] == "1"
    flag = Path(argv[4])
    ready = Path(argv[5])
    pause = Path(argv[6]) if len(argv) > 6 and argv[6] else None
    gate = Path(argv[7]) if len(argv) > 7 and argv[7] else None
    if not baseline_exists:
        _watch_missing_root(root, flag, ready, pause, gate)
    else:
        _watch_existing_root(root, baseline, flag, ready, pause, gate)


if __name__ == "__main__":
    main(sys.argv)
