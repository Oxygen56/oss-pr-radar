"""Release-bound, fail-closed pause for all GitHub write effects."""

from __future__ import annotations

import fcntl
import json
import stat
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator, TextIO

from .release_binding import active_release
from .util import parse_time

OUTBOUND_PAUSE_SCHEMA = "oss-pr-radar.publication-pause.v1"
OUTBOUND_PAUSE_FILENAME = "publication-pause.json"
OUTBOUND_PAUSE_STATES = frozenset({"PAUSING", "ACTIVE", "RESUMING"})


class OutboundEffectLockBusy(RuntimeError):
    """Another GitHub write-capable operation currently owns the effect lock."""


def outbound_effect_lock_path(ledger_path: Path) -> Path:
    return ledger_path.resolve().with_suffix(".outbound.lock")


@contextmanager
def outbound_effect_lock(
    ledger_path: Path, *, blocking: bool = True
) -> Iterator[TextIO]:
    path = outbound_effect_lock_path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as lock:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(lock.fileno(), flags)
        except BlockingIOError as exc:
            raise OutboundEffectLockBusy("outbound effect lock is busy") from exc
        try:
            yield lock
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def active_outbound_pause(runtime_root: Path) -> dict[str, Any] | None:
    """Return a valid pause record; expiration is diagnostic and never resumes writes."""

    runtime_root = runtime_root.resolve()
    path = runtime_root / "state" / OUTBOUND_PAUSE_FILENAME
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("outbound pause record is not a regular file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError("outbound pause record permissions are unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("outbound pause record is invalid") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != OUTBOUND_PAUSE_SCHEMA:
        raise RuntimeError("outbound pause record schema is invalid")
    release, manifest = active_release(runtime_root)
    if (
        value.get("paused") is not True
        or value.get("releaseId") != manifest.get("releaseId")
        or value.get("releasePath") != str(release)
    ):
        raise RuntimeError("outbound pause record binding is invalid")
    try:
        review_after = parse_time(str(value.get("expiresAt") or ""))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("outbound pause review time is invalid") from exc
    pause_state = str(value.get("pauseState") or "")
    if not pause_state:
        pause_state = "ACTIVE" if value.get("workflowIdleConfirmedAt") else "PAUSING"
    if pause_state not in OUTBOUND_PAUSE_STATES:
        raise RuntimeError("outbound pause state is invalid")
    return dict(value) | {
        "pauseState": pause_state,
        "expired": review_after <= datetime.now(UTC),
    }


def require_outbound_effects_allowed(runtime_root: Path) -> None:
    pause = active_outbound_pause(runtime_root)
    if pause is not None:
        suffix = "_EXPIRED" if pause.get("expired") else ""
        raise PermissionError(f"GITHUB_OUTBOUND_PAUSED{suffix}")


@contextmanager
def outbound_effect_guard(
    runtime_root: Path, ledger_path: Path
) -> Iterator[TextIO]:
    """Serialize one real GitHub write and recheck pause after acquiring the lock."""

    with outbound_effect_lock(ledger_path) as lock:
        require_outbound_effects_allowed(runtime_root)
        yield lock
