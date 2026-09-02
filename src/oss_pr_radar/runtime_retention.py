"""Bounded, recoverable retention for Radar's generated rehearsal artifacts.

The local runtime intentionally treats the host disk as a hard safety boundary.  A
hard boundary is only useful if the runtime also has a bounded way to reclaim its
own temporary output.  This module owns that small piece of policy:

* only completed Stage 6 directories under ``reports/stage6`` are candidates;
* the active release, the newest few runs, and evidence referenced by the active
  cutover are never candidates;
* a candidate is first copied into a verified ``tar.gz`` archive, then removed;
* the archive and an operation record remain local, so a restore is possible;
* planning is read-only, while applying is an explicit operation (the worker
  caller has already passed its operational-authorization gate).

Keeping the policy narrow is deliberate.  Stage 7 preservation trees, ledgers,
event databases, and source releases are not disposable runtime output and are
therefore never traversed by the automatic path.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .operational_auth import require_operational_authorization
from .runtime import RuntimeLockBusy, disk_snapshot, exclusive_lock, utc_now
from .runtime_audit import active_release_evidence

RETENTION_SCHEMA = "oss-pr-radar.runtime-retention.v1"
RETENTION_STATE = "runtime-retention.json"
RETENTION_LOCK = "runtime-retention.lock"
ARCHIVE_RELATIVE_ROOT = Path("reports") / "stage6-archives"
CANDIDATE_RELATIVE_ROOT = Path("reports") / "stage6"

# A completed rehearsal older than one day is no longer part of the live worker
# path.  Keep the newest two regardless of age so a just-finished cutover always
# has a local rollback/reference point.
DEFAULT_MIN_AGE_SECONDS = 24 * 60 * 60
DEFAULT_KEEP_LATEST = 2
DEFAULT_MAX_CANDIDATES = 3
MIN_ARCHIVE_FREE_BYTES = 512 * 1024 * 1024
# Historical Stage 7 reports remain useful for audit, but they must not pin
# every raw rehearsal forever.  They are retained in a verified archive before
# the source directory is removed.  Evidence referenced by the currently
# active authorization is protected regardless of age.  Keep this constant for
# compatibility with operators that import the old policy value; age is no
# longer used as a liveness signal.
ACTIVE_EVIDENCE_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
DEFAULT_ARCHIVE_MIN_AGE_SECONDS = 7 * 24 * 60 * 60
DEFAULT_ARCHIVE_KEEP_LATEST = 3
DEFAULT_MAX_ARCHIVES = 20

# Only these authorization fields describe Stage 7 evidence files.  Other
# ``*Sha256`` fields bind release, ledger, worker, or receipt integrity and
# must not become accidental retention pins.
ACTIVE_EVIDENCE_DIGEST_FIELDS = frozenset(
    {
        "managedCountsEvidenceSha256",
        "automationSnapshotSha256",
    }
)


class RetentionError(RuntimeError):
    """A retention operation failed closed without deleting source data."""


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    """Return whether ``value`` is a canonical lower-case SHA-256 digest."""

    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _stable_sha256(path: Path, metadata: os.stat_result | None = None) -> str:
    """Hash one archive only if its identity and size stay stable while read."""

    before = metadata or path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise RetentionError("retention archive must be a regular file")
    digest = _sha256(path)
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise RetentionError("retention archive changed while being read")
    return digest


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise RetentionError("retention path escapes runtime root") from exc


def _managed_path(root: Path, relative: Path) -> Path:
    """Resolve one Radar-owned path without following a managed-root symlink.

    ``Path.resolve()`` alone is not sufficient here: if an operator or a
    concurrent process replaces ``reports/stage6-archives`` with a symlink,
    resolving first would silently move a later delete outside the runtime
    root.  Inspect every existing component lexically, then verify the final
    resolved path remains below the runtime root.
    """

    runtime_root = root.resolve()
    if relative.is_absolute() or ".." in relative.parts:
        raise RetentionError("retention path is not relative to runtime root")
    lexical = runtime_root / relative
    cursor = runtime_root
    parts = relative.parts
    for index, part in enumerate(parts):
        cursor = cursor / part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RetentionError("retention path cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RetentionError("managed retention root contains a symlink")
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise RetentionError("managed retention path has a non-directory parent")
    resolved = lexical.resolve(strict=False)
    try:
        resolved.relative_to(runtime_root)
    except ValueError as exc:
        raise RetentionError("retention path escapes runtime root") from exc
    return resolved


def _managed_state_root(root: Path) -> Path:
    """Return Radar's state directory, rejecting a file or symlink root."""

    state_root = _managed_path(root, Path("state"))
    if state_root.exists() and not state_root.is_dir():
        raise RetentionError("retention state root must be a directory")
    return state_root


def _directory_inventory(path: Path, root: Path) -> list[dict[str, Any]]:
    """Return a complete regular-file inventory and reject links/special files."""

    inventory: list[dict[str, Any]] = []
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RetentionError(f"candidate is unreadable: {path.name}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RetentionError("retention candidate must be a real directory")
    for child in sorted(path.rglob("*")):
        try:
            child_meta = child.lstat()
        except OSError as exc:
            raise RetentionError(f"candidate entry is unreadable: {child}") from exc
        if stat.S_ISLNK(child_meta.st_mode):
            raise RetentionError(f"candidate contains a symlink: {child.name}")
        if child.is_dir():
            continue
        if not stat.S_ISREG(child_meta.st_mode):
            raise RetentionError(f"candidate contains a non-regular file: {child.name}")
        inventory.append(
            {
                "path": _safe_relative(child, path),
                "bytes": int(child_meta.st_size),
                "sha256": _sha256(child),
                "mode": oct(stat.S_IMODE(child_meta.st_mode)),
            }
        )
    return inventory


def _tree_bytes(path: Path) -> int:
    total = 0
    for child in path.rglob("*"):
        try:
            metadata = child.lstat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            total += int(metadata.st_size)
    return total


def _latest_mtime(path: Path) -> float:
    latest = path.stat().st_mtime
    for child in path.rglob("*"):
        try:
            latest = max(latest, child.stat().st_mtime)
        except OSError:
            continue
    return latest


def _active_release_tokens(root: Path) -> set[str]:
    tokens: set[str] = set()
    evidence = active_release_evidence(root)
    release_id = evidence.get("releaseId")
    if isinstance(release_id, str) and release_id:
        tokens.add(release_id)
        tokens.add(release_id.split("-", 1)[0])
    # A release pointer can remain useful even if its manifest is temporarily
    # unreadable; protect the directory name independently.
    pointer = root / "current-release"
    try:
        target = pointer.resolve(strict=True)
    except OSError:
        target = None
    if target is not None:
        tokens.add(target.name)
        tokens.add(target.name.split("-", 1)[0])
    return {token for token in tokens if len(token) >= 8}


def _active_auth_evidence_digests(root: Path) -> set[str]:
    """Return Stage 7 evidence digests bound by current authorizations.

    Authorization records also contain hashes for release manifests, ledgers,
    worker plists, and receipts.  Those hashes describe the authorization's
    integrity boundary, not a raw Stage 6 directory, so only the two explicit
    Stage 7 evidence fields are considered here.
    """

    digests: set[str] = set()
    for name in (
        "operational-authorization.json",
        "worker-staging-authorization.json",
    ):
        path = _managed_path(root, Path("state") / name)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict) or value.get("state") not in {
            "ACTIVE",
            "STAGED",
            "CONSUMED",
        }:
            continue
        for key in ACTIVE_EVIDENCE_DIGEST_FIELDS:
            item = value.get(key)
            if isinstance(item, str) and len(item) == 64:
                try:
                    int(item, 16)
                except ValueError:
                    continue
                digests.add(item)
    return digests


def _active_stage7_evidence_sources(root: Path) -> list[Path]:
    """Return Stage 7 files whose bytes are bound by current authorization."""

    try:
        stage7 = _managed_path(root, Path("reports") / "stage7")
    except RetentionError:
        # Never delete evidence while the evidence root itself is ambiguous.
        raise
    active_digests = _active_auth_evidence_digests(root)
    if not active_digests:
        return []
    if not stage7.is_dir() or stage7.is_symlink():
        return []
    sources: list[Path] = []
    for path in stage7.rglob("*"):
        if not path.is_file() or path.is_symlink() or path.suffix not in {".json", ".gz"}:
            continue
        try:
            if _sha256(path) in active_digests:
                sources.append(path)
        except OSError as exc:
            # This file may be the only copy of an active signed input.
            raise RetentionError("active Stage 7 evidence is unreadable") from exc
    return sources


def _active_cutover_names(
    root: Path,
    candidate_names: set[str],
    *,
    now: float | None = None,
) -> set[str]:
    """Find names referenced by Stage 7 evidence bound to a live authorization.

    Stage 7 emits a historical snapshot on every cycle.  Recency is not a
    liveness signal: using it here pinned every raw rehearsal until the
    evidence-age window elapsed, precisely when disk pressure is most likely.
    Hash and inspect only files whose digest is present in the current staging
    or operational authorization.  Older reports remain auditable and can be
    recovered from the retention archive without becoming deletion pins.
    """

    if not candidate_names:
        return set()
    # ``now`` remains an API-compatible argument for callers that supplied the
    # former recency window; authorization digest binding is now the sole
    # liveness criterion.
    _ = now
    try:
        sources = _active_stage7_evidence_sources(root)
    except RetentionError:
        # An active authorization/evidence binding that cannot be inspected is
        # a live-state uncertainty; protect every candidate until repaired.
        return set(candidate_names)
    names: set[str] = set()
    for source in sources:
        try:
            if source.suffix == ".gz":
                with gzip.open(source, "rt", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            else:
                text = source.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return set(candidate_names)
        names.update(name for name in candidate_names if name in text)
    return names


def _candidate_report_dirs(root: Path) -> list[Path]:
    try:
        base = _managed_path(root, CANDIDATE_RELATIVE_ROOT)
    except RetentionError:
        return []
    if not base.is_dir() or base.is_symlink():
        return []
    return [
        path
        for path in sorted(base.iterdir(), key=lambda item: item.name)
        if path.is_dir() and not path.is_symlink()
    ]


def plan_runtime_retention(
    root: Path,
    *,
    now: float | None = None,
    min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
    keep_latest: int = DEFAULT_KEEP_LATEST,
    max_candidates: int | None = None,
    archive_min_age_seconds: int = DEFAULT_ARCHIVE_MIN_AGE_SECONDS,
    archive_keep_latest: int = DEFAULT_ARCHIVE_KEEP_LATEST,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
) -> dict[str, Any]:
    """Build a read-only plan for reclaiming completed Stage 6 directories."""

    root = root.resolve()
    if (
        min_age_seconds < 0
        or keep_latest < 0
        or archive_min_age_seconds < 0
        or archive_keep_latest < 0
        or max_archives < 1
    ):
        raise ValueError("retention limits must be non-negative")
    current = time.time() if now is None else float(now)
    all_dirs = _candidate_report_dirs(root)
    ordered = sorted(all_dirs, key=_latest_mtime, reverse=True)
    keep_names = {path.name for path in ordered[:keep_latest]}
    active_tokens = _active_release_tokens(root)
    preliminary: list[dict[str, Any]] = []
    for path in ordered:
        age = max(0.0, current - _latest_mtime(path))
        reasons: list[str] = []
        if path.name in keep_names:
            reasons.append("newest_runs")
        if any(token in path.name for token in active_tokens):
            reasons.append("active_release")
        if age < min_age_seconds:
            reasons.append("too_recent")
        envelope = path / "stage6-public-envelope.json"
        summary = path / "stage6-public-summary.json"
        if not envelope.is_file() or envelope.is_symlink() or not summary.is_file():
            reasons.append("incomplete_stage6_output")
        item = {
            "path": _safe_relative(path, root),
            "name": path.name,
            "bytes": _tree_bytes(path),
            "ageSeconds": int(age),
            "latestMtime": datetime.fromtimestamp(_latest_mtime(path), UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "reasons": reasons,
        }
        preliminary.append(item)
    # Only scan Stage 7 for directories that have already passed the cheap
    # safety checks above.  Historical reports without a current authorization
    # digest are intentionally ignored as deletion pins.
    reference_names = {str(item["name"]) for item in preliminary if not item["reasons"]}
    active_names = _active_cutover_names(root, reference_names, now=current)
    candidates: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    for item in preliminary:
        if item["name"] in active_names:
            item["reasons"].append("active_evidence_reference")
        (protected if item["reasons"] else candidates).append(item)
    if max_candidates is not None:
        if max_candidates < 0:
            raise ValueError("max_candidates must be non-negative")
        candidates = candidates[:max_candidates]
    return {
        "schema": RETENTION_SCHEMA,
        "generatedAt": utc_now(),
        "runtimeRootRelative": ".",
        "policy": {
            "candidateRoot": CANDIDATE_RELATIVE_ROOT.as_posix(),
            "archiveRoot": ARCHIVE_RELATIVE_ROOT.as_posix(),
            "minAgeSeconds": int(min_age_seconds),
            "keepLatest": int(keep_latest),
            "maxCandidates": max_candidates,
            "activeReleaseTokens": sorted(active_tokens),
            "archiveMinAgeSeconds": int(archive_min_age_seconds),
            "archiveKeepLatest": int(archive_keep_latest),
            "maxArchives": int(max_archives),
        },
        "candidates": candidates,
        "protected": protected,
        "disk": disk_snapshot(root),
    }


def _archive_inventory(archive: Path, candidate_name: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    root_seen = False
    try:
        stream = tarfile.open(archive, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise RetentionError("retention archive cannot be opened") from exc
    with stream:
        for member in stream.getmembers():
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RetentionError("retention archive contains an unsafe path")
            if member.name == candidate_name:
                if not member.isdir():
                    raise RetentionError("retention archive root is not a directory")
                root_seen = True
                continue
            if not member.name.startswith(candidate_name + "/"):
                raise RetentionError("retention archive contains an unexpected root")
            if member.issym() or member.islnk() or not member.isfile():
                if member.isdir():
                    continue
                raise RetentionError("retention archive contains a non-regular member")
            handle = stream.extractfile(member)
            if handle is None:
                raise RetentionError("retention archive member is unreadable")
            digest = hashlib.sha256()
            size = 0
            with handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
            files.append(
                {
                    "path": member.name[len(candidate_name) + 1 :],
                    "bytes": size,
                    "sha256": digest.hexdigest(),
                    "mode": oct(member.mode & 0o777),
                }
            )
    if not root_seen:
        raise RetentionError("retention archive root is missing")
    return sorted(files, key=lambda item: item["path"])


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        parent_metadata = path.parent.lstat()
    except OSError as exc:
        raise RetentionError("retention state parent is unavailable") from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise RetentionError("retention state parent is unsafe")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RetentionError("retention state path is unsafe")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(value, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _append_record(root: Path, record: dict[str, Any]) -> None:
    state_root = _managed_state_root(root)
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Recheck after creation so a concurrent replacement cannot turn the
    # journal write into an outside-runtime write.
    state_root = _managed_state_root(root)
    path = state_root / RETENTION_STATE
    existing: dict[str, Any] = {}
    if path.is_file() and not path.is_symlink():
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                existing = value
        except (OSError, json.JSONDecodeError):
            existing = {}
    records = list(existing.get("operations") or []) if isinstance(existing, dict) else []
    records.append(record)
    # Keep the journal bounded even if a disk-pressure loop is noisy.
    records = records[-1000:]
    _write_json_atomic(
        path,
        {
            "schema": RETENTION_SCHEMA,
            "updatedAt": utc_now(),
            "operations": records,
        },
    )


def _archive_candidate(root: Path, item: dict[str, Any], *, now: float) -> dict[str, Any]:
    candidate = _managed_path(root, Path(str(item["path"])))
    candidate_root = _managed_path(root, CANDIDATE_RELATIVE_ROOT)
    try:
        candidate.relative_to(candidate_root)
    except ValueError as exc:
        raise RetentionError("candidate is outside the managed Stage 6 root") from exc
    if not candidate.is_dir() or candidate.is_symlink():
        raise RetentionError("candidate disappeared or is not a directory")
    inventory = _directory_inventory(candidate, candidate_root)
    source_bytes = sum(int(entry["bytes"]) for entry in inventory)
    archive_root = _managed_path(root, ARCHIVE_RELATIVE_ROOT)
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive_root = _managed_path(root, ARCHIVE_RELATIVE_ROOT)
    stamp = datetime.fromtimestamp(now, UTC).strftime("%Y%m%dT%H%M%SZ")
    archive = archive_root / f"{candidate.name}-{stamp}.tar.gz"
    suffix = 0
    while archive.exists():
        suffix += 1
        archive = archive_root / f"{candidate.name}-{stamp}-{suffix}.tar.gz"
    # Refuse to start an archive when the host cannot afford a conservative
    # source-sized temporary write plus a small reserve.
    usage = shutil.disk_usage(root)
    if usage.free < source_bytes + MIN_ARCHIVE_FREE_BYTES:
        return {
            "path": item["path"],
            "status": "deferred_insufficient_space",
            "sourceBytes": source_bytes,
            "requiredFreeBytes": source_bytes + MIN_ARCHIVE_FREE_BYTES,
        }
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{archive.name}.", suffix=".tmp", dir=archive_root
    )
    os.close(fd)
    temporary = Path(temporary_name)
    archive_verified = False
    try:
        os.chmod(temporary, 0o600)
        with tarfile.open(temporary, mode="w:gz", dereference=False) as stream:
            stream.add(candidate, arcname=candidate.name, recursive=True)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, archive)
        os.chmod(archive, 0o600)
        archived_inventory = _archive_inventory(archive, candidate.name)
        expected = sorted(inventory, key=lambda entry: entry["path"])
        if archived_inventory != expected:
            archive.unlink(missing_ok=True)
            raise RetentionError("retention archive inventory verification failed")
        # Do not remove a directory that changed while it was being archived.
        # This is the only concurrency guard available to a maintenance pass
        # that runs beside the independent Stage 6 tooling.
        if _directory_inventory(candidate, candidate_root) != expected:
            archive.unlink(missing_ok=True)
            return {
                "path": item["path"],
                "status": "kept_source_changed",
                "sourceBytes": source_bytes,
            }
        archive_bytes = archive.stat().st_size
        if archive_bytes >= source_bytes:
            archive.unlink(missing_ok=True)
            return {
                "path": item["path"],
                "status": "kept_archive_not_smaller",
                "sourceBytes": source_bytes,
                "archiveBytes": archive_bytes,
            }
        # Everything used by the success record must be computed before source
        # removal.  Once the verified archive exists, an error must never
        # delete it as a rollback: it is the recovery copy.
        archive_relative = _safe_relative(archive, root)
        archive_sha256 = _sha256(archive)
        inventory_sha256 = hashlib.sha256(_canonical(expected).encode("utf-8")).hexdigest()
        archive_verified = True
        try:
            shutil.rmtree(candidate)
        except Exception as exc:  # noqa: BLE001 - preserve verified recovery copy
            return {
                "path": item["path"],
                "status": "failed_closed",
                "archive": archive_relative,
                "sourceBytes": source_bytes,
                "archiveBytes": archive_bytes,
                "archiveSha256": archive_sha256,
                "inventorySha256": inventory_sha256,
                "error": f"source delete failed: {type(exc).__name__}:{str(exc)[:180]}",
            }
        try:
            source_remains = candidate.exists()
        except Exception as exc:  # noqa: BLE001 - preserve verified recovery copy
            return {
                "path": item["path"],
                "status": "failed_closed",
                "archive": archive_relative,
                "sourceBytes": source_bytes,
                "archiveBytes": archive_bytes,
                "archiveSha256": archive_sha256,
                "inventorySha256": inventory_sha256,
                "error": f"source post-delete check failed: {type(exc).__name__}:{str(exc)[:180]}",
            }
        if source_remains:
            return {
                "path": item["path"],
                "status": "failed_closed",
                "archive": archive_relative,
                "sourceBytes": source_bytes,
                "archiveBytes": archive_bytes,
                "archiveSha256": archive_sha256,
                "inventorySha256": inventory_sha256,
                "error": "source remained after archive",
            }
        return {
            "path": item["path"],
            "status": "archived_and_removed",
            "archive": archive_relative,
            "sourceBytes": source_bytes,
            "archiveBytes": archive_bytes,
            "archiveSha256": archive_sha256,
            "freedBytes": source_bytes - archive_bytes,
            "inventorySha256": inventory_sha256,
        }
    except (OSError, tarfile.TarError) as exc:
        # Before verification, the archive is only a temporary copy and can
        # be rolled back.  After verification/source removal starts, it is the
        # recovery copy and must remain even if a later filesystem call fails.
        if not archive_verified:
            archive.unlink(missing_ok=True)
        raise RetentionError(f"retention archive failed: {type(exc).__name__}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _archive_records(root: Path) -> dict[str, dict[str, Any]]:
    try:
        path = _managed_path(root, Path("state") / RETENTION_STATE)
    except RetentionError:
        return {}
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    records = value.get("operations") if isinstance(value, dict) else None
    result: dict[str, dict[str, Any]] = {}
    for record in records or []:
        if not isinstance(record, dict):
            continue
        entries = [record]
        nested = record.get("operations")
        if isinstance(nested, list):
            entries.extend(item for item in nested if isinstance(item, dict))
        for entry in entries:
            if entry.get("status") != "archived_and_removed":
                continue
            archive = entry.get("archive")
            if isinstance(archive, str) and archive:
                result[archive] = entry
    return result


def _record_candidate_name(record: dict[str, Any]) -> str:
    value = record.get("path")
    if not isinstance(value, str) or not value:
        raise RetentionError("archive record candidate path is missing")
    relative = Path(value)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != value
        or relative.parent != CANDIDATE_RELATIVE_ROOT
    ):
        raise RetentionError("archive record candidate path is outside Stage 6")
    name = relative.name
    if not name or name in {".", ".."}:
        raise RetentionError("archive record candidate name is invalid")
    return name


def _record_nonnegative_int(record: dict[str, Any], field: str) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RetentionError(f"archive record {field} is invalid")
    return value


def _archive_is_referenced(
    root: Path,
    archive_relative: str,
    candidate_relative: str | None = None,
) -> bool:
    """Do not prune an archive named by currently authorized evidence.

    Historical Stage 7 reports remain immutable audit material, but their
    source-path strings are not a live ownership claim.  Once the source is
    represented by a verified archive, normal archive age/count policy may
    reclaim it unless the current authorization still binds the evidence.
    """

    archive_name = Path(archive_relative).name
    needles = {archive_name, archive_relative}
    if candidate_relative:
        needles.add(candidate_relative)
    try:
        sources = _active_stage7_evidence_sources(root)
    except RetentionError:
        return True
    for path in sources:
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            else:
                text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            # An unreadable evidence tree is an uncertainty at a destructive
            # boundary; keep the archive until an operator can inspect it.
            return True
        if any(needle in text for needle in needles):
            return True
    return False


def _prune_verified_archives(
    root: Path,
    *,
    now: float,
    min_age_seconds: int = DEFAULT_ARCHIVE_MIN_AGE_SECONDS,
    keep_latest: int = DEFAULT_ARCHIVE_KEEP_LATEST,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
) -> list[dict[str, Any]]:
    """Remove only our own, verified, old archives and report every decision."""

    if min_age_seconds < 0 or keep_latest < 0 or max_archives < 1:
        raise ValueError("archive retention limits are invalid")
    try:
        archive_root = _managed_path(root, ARCHIVE_RELATIVE_ROOT)
    except RetentionError as exc:
        return [
            {
                "archive": ARCHIVE_RELATIVE_ROOT.as_posix(),
                "status": "kept_unsafe_root",
                "error": str(exc)[:180],
            }
        ]
    if not archive_root.is_dir() or archive_root.is_symlink():
        return []
    records = _archive_records(root)
    archives = sorted(
        (
            path
            for path in archive_root.iterdir()
            if path.is_file() and not path.is_symlink() and path.name.endswith(".tar.gz")
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    protected = {path for path in archives[:keep_latest]}
    operations: list[dict[str, Any]] = []
    for index, archive in enumerate(archives):
        try:
            metadata = archive.lstat()
        except OSError:
            operations.append({"archive": str(archive), "status": "kept_unreadable"})
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
        ):
            operations.append(
                {
                    "archive": _safe_relative(archive, root),
                    "status": "kept_unsafe_permissions",
                }
            )
            continue
        relative = _safe_relative(archive, root)
        record = records.get(relative)
        age = max(0.0, now - archive.stat().st_mtime)
        if archive in protected:
            continue
        if record is None:
            # Never touch an archive that was not created and recorded by this
            # retention implementation.
            operations.append({"archive": relative, "status": "kept_unmanaged"})
            continue
        if age < min_age_seconds and index < max_archives:
            continue
        try:
            candidate_name = _record_candidate_name(record)
            candidate_relative = (CANDIDATE_RELATIVE_ROOT / candidate_name).as_posix()
            record_archive = record.get("archive")
            if record_archive != relative:
                raise RetentionError("archive record path does not match archive")
            archive_path = Path(relative)
            if (
                archive_path.is_absolute()
                or ".." in archive_path.parts
                or archive_path.as_posix() != relative
                or archive_path.parent != ARCHIVE_RELATIVE_ROOT
            ):
                raise RetentionError("archive record archive path is outside archive root")
            source_bytes = _record_nonnegative_int(record, "sourceBytes")
            archive_bytes_record = _record_nonnegative_int(record, "archiveBytes")
            freed_bytes = _record_nonnegative_int(record, "freedBytes")
            expected_digest = record.get("archiveSha256")
            expected_inventory_digest = record.get("inventorySha256")
            if not _is_sha256(expected_digest):
                raise RetentionError("archive digest is missing or invalid")
            if not _is_sha256(expected_inventory_digest):
                raise RetentionError("archive inventory digest is missing or invalid")
            if freed_bytes != source_bytes - archive_bytes_record:
                raise RetentionError("archive record byte accounting is invalid")
        except RetentionError:
            operations.append({"archive": relative, "status": "kept_invalid_record"})
            continue
        if _archive_is_referenced(root, relative, candidate_relative):
            operations.append({"archive": relative, "status": "kept_evidence_reference"})
            continue
        try:
            inventory = _archive_inventory(archive, candidate_name)
            inventory_digest = hashlib.sha256(_canonical(inventory).encode("utf-8")).hexdigest()
            if inventory_digest != expected_inventory_digest:
                raise RetentionError("archive inventory digest changed")
            metadata = archive.lstat()
            if archive_bytes_record != int(metadata.st_size):
                raise RetentionError("archive byte size changed")
            if expected_digest != _stable_sha256(archive, metadata):
                raise RetentionError("archive digest changed")
            if not inventory:
                raise RetentionError("archive inventory is empty")
        except (OSError, RetentionError, tarfile.TarError) as exc:
            operations.append(
                {
                    "archive": relative,
                    "status": "kept_unverified",
                    "error": f"{type(exc).__name__}:{str(exc)[:180]}",
                }
            )
            continue
        size = int(archive.stat().st_size)
        try:
            archive.unlink()
        except OSError as exc:
            operations.append(
                {
                    "archive": relative,
                    "status": "kept_unlink_failed",
                    "error": f"{type(exc).__name__}:{str(exc)[:180]}",
                }
            )
            continue
        operations.append(
            {
                "archive": relative,
                "status": "archive_pruned",
                "archiveBytes": size,
                "freedBytes": size,
            }
        )
    return operations


def _archive_retention_due(
    root: Path,
    *,
    now: float,
    min_age_seconds: int,
    keep_latest: int,
    max_archives: int,
) -> bool:
    """Cheap preflight used to avoid writing a no-op record every worker tick."""

    try:
        archive_root = _managed_path(root, ARCHIVE_RELATIVE_ROOT)
    except RetentionError:
        return False
    if not archive_root.is_dir() or archive_root.is_symlink():
        return False
    records = _archive_records(root)
    archives = sorted(
        (
            path
            for path in archive_root.iterdir()
            if path.is_file() and not path.is_symlink() and path.name.endswith(".tar.gz")
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for index, archive in enumerate(archives):
        if index < keep_latest:
            continue
        relative = _safe_relative(archive, root)
        if relative not in records:
            continue
        if now - archive.stat().st_mtime >= min_age_seconds or index >= max_archives:
            return True
    return False


def apply_runtime_retention(
    root: Path,
    *,
    plan: dict[str, Any] | None = None,
    now: float | None = None,
    min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
    keep_latest: int = DEFAULT_KEEP_LATEST,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    archive_min_age_seconds: int = DEFAULT_ARCHIVE_MIN_AGE_SECONDS,
    archive_keep_latest: int = DEFAULT_ARCHIVE_KEEP_LATEST,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
) -> dict[str, Any]:
    """Apply a bounded plan, failing closed before any source deletion."""

    root = root.resolve()
    if max_candidates < 0:
        raise ValueError("max_candidates must be non-negative")
    current = time.time() if now is None else float(now)
    selected = plan or plan_runtime_retention(
        root,
        now=current,
        min_age_seconds=min_age_seconds,
        keep_latest=keep_latest,
        max_candidates=max_candidates,
        archive_min_age_seconds=archive_min_age_seconds,
        archive_keep_latest=archive_keep_latest,
        max_archives=max_archives,
    )
    # Recompute eligibility at the destructive boundary.  A plan may have been
    # generated minutes earlier, after which a new release or Stage 7 evidence
    # could make one of its paths live.
    fresh = plan_runtime_retention(
        root,
        now=current,
        min_age_seconds=min_age_seconds,
        keep_latest=keep_latest,
        max_candidates=max_candidates,
        archive_min_age_seconds=archive_min_age_seconds,
        archive_keep_latest=archive_keep_latest,
        max_archives=max_archives,
    )
    fresh_by_path = {str(item.get("path")): item for item in fresh.get("candidates") or []}
    stale = [
        {"path": item.get("path"), "status": "skipped_stale_plan"}
        for item in list(selected.get("candidates") or [])
        if str(item.get("path")) not in fresh_by_path
    ]
    candidates = [
        fresh_by_path[str(item.get("path"))]
        for item in list(selected.get("candidates") or [])
        if str(item.get("path")) in fresh_by_path
    ]
    operations: list[dict[str, Any]] = stale
    for item in candidates[:max_candidates]:
        try:
            operation = _archive_candidate(root, item, now=current)
        except RetentionError as exc:
            operation = {
                "path": item.get("path"),
                "status": "failed_closed",
                "error": str(exc)[:240],
            }
        operations.append(operation)
        if operation.get("status") == "deferred_insufficient_space":
            break
    archive_operations = _prune_verified_archives(
        root,
        now=current,
        min_age_seconds=archive_min_age_seconds,
        keep_latest=archive_keep_latest,
        max_archives=max_archives,
    )
    operations.extend(archive_operations)
    result = {
        "schema": RETENTION_SCHEMA,
        "ok": not any(item.get("status") == "failed_closed" for item in operations),
        "generatedAt": utc_now(),
        "operations": operations,
        "freedBytes": sum(int(item.get("freedBytes") or 0) for item in operations),
        "candidatesConsidered": len(operations),
    }
    _append_record(root, result)
    return result


def maybe_reclaim_runtime_storage(
    root: Path,
    *,
    disk: dict[str, Any] | None = None,
    now: float | None = None,
    min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
    keep_latest: int = DEFAULT_KEEP_LATEST,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    archive_min_age_seconds: int = DEFAULT_ARCHIVE_MIN_AGE_SECONDS,
    archive_keep_latest: int = DEFAULT_ARCHIVE_KEEP_LATEST,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
) -> dict[str, Any]:
    """Reclaim old Stage 6 output only while disk pressure is active.

    The caller is a worker that has already passed the normal operational
    authorization check.  A separate non-blocking lock makes this safe against
    an operator running the maintenance command at the same time.
    """

    root = root.resolve()
    snapshot = disk if isinstance(disk, dict) else disk_snapshot(root)
    if snapshot.get("level") not in {"warning", "stop"}:
        return {"attempted": False, "reason": "disk_not_under_pressure", "disk": snapshot}
    try:
        lock_path = _managed_path(root, Path("state") / RETENTION_LOCK)
        with exclusive_lock(lock_path, blocking=False):
            # The fast worker reaches this helper before the normal bridge
            # operation, so recheck authorization while holding the
            # destructive-operation lock.  This closes the revoke/apply race.
            try:
                require_operational_authorization(root)
            except Exception as exc:  # noqa: BLE001 - retention fails closed
                return {
                    "attempted": False,
                    "ok": False,
                    "reason": "operational_authorization_required",
                    "error": f"{type(exc).__name__}:{str(exc)[:240]}",
                    "beforeDisk": snapshot,
                }
            plan = plan_runtime_retention(
                root,
                now=now,
                min_age_seconds=min_age_seconds,
                keep_latest=keep_latest,
                max_candidates=max_candidates,
                archive_min_age_seconds=archive_min_age_seconds,
                archive_keep_latest=archive_keep_latest,
                max_archives=max_archives,
            )
            if not plan.get("candidates"):
                if _archive_retention_due(
                    root,
                    now=time.time() if now is None else float(now),
                    min_age_seconds=archive_min_age_seconds,
                    keep_latest=archive_keep_latest,
                    max_archives=max_archives,
                ):
                    result = apply_runtime_retention(
                        root,
                        plan=plan,
                        now=now,
                        min_age_seconds=min_age_seconds,
                        keep_latest=keep_latest,
                        max_candidates=max_candidates,
                        archive_min_age_seconds=archive_min_age_seconds,
                        archive_keep_latest=archive_keep_latest,
                        max_archives=max_archives,
                    )
                    result["attempted"] = True
                    result["beforeDisk"] = snapshot
                    result["afterDisk"] = disk_snapshot(root)
                    return result
                return {
                    "attempted": False,
                    "ok": True,
                    "reason": "no_eligible_candidates",
                    "beforeDisk": snapshot,
                }
            result = apply_runtime_retention(
                root,
                plan=plan,
                now=now,
                min_age_seconds=min_age_seconds,
                keep_latest=keep_latest,
                max_candidates=max_candidates,
                archive_min_age_seconds=archive_min_age_seconds,
                archive_keep_latest=archive_keep_latest,
                max_archives=max_archives,
            )
            result["attempted"] = True
            result["beforeDisk"] = snapshot
            result["afterDisk"] = disk_snapshot(root)
            return result
    except (OSError, RetentionError, RuntimeLockBusy) as exc:
        if isinstance(exc, RuntimeLockBusy):
            return {
                "attempted": False,
                "ok": True,
                "reason": "retention_busy",
                "beforeDisk": snapshot,
            }
        return {
            "attempted": True,
            "ok": False,
            "reason": "retention_failed_closed",
            "error": f"{type(exc).__name__}:{str(exc)[:240]}",
            "beforeDisk": snapshot,
        }


def restore_runtime_archive(root: Path, archive: Path) -> dict[str, Any]:
    """Restore one verified archive into ``reports/stage6`` if the target is absent."""

    root = root.resolve()
    archive = archive.absolute()
    try:
        archive_relative = archive.relative_to(root)
    except ValueError as exc:
        raise RetentionError("restore archive is outside the runtime root") from exc
    # Resolve through the managed-path guard rather than following a caller
    # supplied symlink.  A symlink to an otherwise valid archive is still an
    # untrusted binding at this destructive restore boundary.
    archive = _managed_path(root, archive_relative)
    archive_root = _managed_path(root, ARCHIVE_RELATIVE_ROOT)
    try:
        archive.relative_to(archive_root)
    except ValueError as exc:
        raise RetentionError("restore archive is outside the managed archive root") from exc
    try:
        metadata = archive.lstat()
    except OSError as exc:
        raise RetentionError("restore archive is missing or unsafe") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
    ):
        raise RetentionError("restore archive is missing or unsafe")
    try:
        with tarfile.open(archive, mode="r:gz") as stream:
            members = stream.getmembers()
            if not members:
                raise RetentionError("restore archive is empty")
            roots = {Path(item.name).parts[0] for item in members if item.name}
            if len(roots) != 1:
                raise RetentionError("restore archive has multiple roots")
            candidate_name = next(iter(roots))
            if candidate_name in {"", ".", ".."} or "/" in candidate_name or "\\" in candidate_name:
                raise RetentionError("restore archive root is invalid")
            target_root = _managed_path(root, CANDIDATE_RELATIVE_ROOT)
            target_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            target_root = _managed_path(root, CANDIDATE_RELATIVE_ROOT)
            target = target_root / candidate_name
            if target.exists() or target.is_symlink():
                raise RetentionError("restore target already exists")
            for member in members:
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RetentionError("restore archive contains an unsafe path")
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    raise RetentionError("restore archive contains an unsafe member")
            temporary = Path(
                tempfile.mkdtemp(prefix=f".{candidate_name}.restore.", dir=target_root)
            )
            try:
                stream.extractall(temporary)
                extracted = temporary / candidate_name
                if not extracted.is_dir() or extracted.is_symlink():
                    raise RetentionError("restore archive root is invalid")
                os.replace(extracted, target)
            finally:
                shutil.rmtree(temporary, ignore_errors=True)
    except (OSError, tarfile.TarError) as exc:
        raise RetentionError(f"restore archive failed: {type(exc).__name__}") from exc
    return {"ok": True, "restored": _safe_relative(target, root)}
