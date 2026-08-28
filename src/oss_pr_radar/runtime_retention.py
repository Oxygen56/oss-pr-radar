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


def _safe_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise RetentionError("retention path escapes runtime root") from exc


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


def _active_cutover_names(root: Path, candidate_names: set[str]) -> set[str]:
    """Find report directory names mentioned by current signed evidence.

    Every Stage 7 JSON file is treated as an evidence reference.  This is a
    small, conservative set compared with the full runtime tree and prevents a
    retention pass from invalidating an older signed acceptance artifact.
    """

    names: set[str] = set()
    sources: list[Path] = []
    authorization = root / "state" / "operational-authorization.json"
    if authorization.is_file():
        sources.append(authorization)
    stage7 = root / "reports" / "stage7"
    if stage7.is_dir():
        sources.extend(
            path
            for path in stage7.rglob("*")
            if path.is_file() and not path.is_symlink() and path.suffix in {".json", ".gz"}
        )
    for source in sources:
        try:
            if source.suffix == ".gz":
                with gzip.open(source, "rt", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            else:
                text = source.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        names.update(name for name in candidate_names if name in text)
    return names


def _candidate_report_dirs(root: Path) -> list[Path]:
    base = root / CANDIDATE_RELATIVE_ROOT
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
) -> dict[str, Any]:
    """Build a read-only plan for reclaiming completed Stage 6 directories."""

    root = root.resolve()
    if min_age_seconds < 0 or keep_latest < 0:
        raise ValueError("retention limits must be non-negative")
    current = time.time() if now is None else float(now)
    all_dirs = _candidate_report_dirs(root)
    ordered = sorted(all_dirs, key=_latest_mtime, reverse=True)
    keep_names = {path.name for path in ordered[:keep_latest]}
    active_tokens = _active_release_tokens(root)
    active_names = _active_cutover_names(root, {path.name for path in all_dirs})
    candidates: list[dict[str, Any]] = []
    protected: list[dict[str, Any]] = []
    for path in ordered:
        age = max(0.0, current - _latest_mtime(path))
        reasons: list[str] = []
        if path.name in keep_names:
            reasons.append("newest_runs")
        if any(token in path.name for token in active_tokens):
            reasons.append("active_release")
        if path.name in active_names:
            reasons.append("active_evidence_reference")
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
        if reasons:
            protected.append(item)
        else:
            candidates.append(item)
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
        },
        "candidates": candidates,
        "protected": protected,
        "disk": disk_snapshot(root),
    }


def _archive_inventory(archive: Path, candidate_name: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
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
    return sorted(files, key=lambda item: item["path"])


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
    path = root / "state" / RETENTION_STATE
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
    records = records[-100:]
    _write_json_atomic(
        path,
        {
            "schema": RETENTION_SCHEMA,
            "updatedAt": utc_now(),
            "operations": records,
        },
    )


def _archive_candidate(root: Path, item: dict[str, Any], *, now: float) -> dict[str, Any]:
    candidate = (root / str(item["path"])).resolve()
    candidate_root = (root / CANDIDATE_RELATIVE_ROOT).resolve()
    try:
        candidate.relative_to(candidate_root)
    except ValueError as exc:
        raise RetentionError("candidate is outside the managed Stage 6 root") from exc
    if not candidate.is_dir() or candidate.is_symlink():
        raise RetentionError("candidate disappeared or is not a directory")
    inventory = _directory_inventory(candidate, candidate_root)
    source_bytes = sum(int(entry["bytes"]) for entry in inventory)
    archive_root = (root / ARCHIVE_RELATIVE_ROOT).resolve()
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
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
        shutil.rmtree(candidate)
        if candidate.exists():
            raise RetentionError("retention source remained after archive")
        return {
            "path": item["path"],
            "status": "archived_and_removed",
            "archive": _safe_relative(archive, root),
            "sourceBytes": source_bytes,
            "archiveBytes": archive_bytes,
            "freedBytes": source_bytes - archive_bytes,
            "inventorySha256": hashlib.sha256(_canonical(expected).encode("utf-8")).hexdigest(),
        }
    except (OSError, tarfile.TarError) as exc:
        archive.unlink(missing_ok=True)
        raise RetentionError(f"retention archive failed: {type(exc).__name__}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def apply_runtime_retention(
    root: Path,
    *,
    plan: dict[str, Any] | None = None,
    now: float | None = None,
    min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
    keep_latest: int = DEFAULT_KEEP_LATEST,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
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
    lock_path = root / "state" / RETENTION_LOCK
    try:
        with exclusive_lock(lock_path, blocking=False):
            plan = plan_runtime_retention(
                root,
                now=now,
                min_age_seconds=min_age_seconds,
                keep_latest=keep_latest,
                max_candidates=max_candidates,
            )
            if not plan.get("candidates"):
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
    archive = archive.resolve()
    archive_root = (root / ARCHIVE_RELATIVE_ROOT).resolve()
    try:
        archive.relative_to(archive_root)
    except ValueError as exc:
        raise RetentionError("restore archive is outside the managed archive root") from exc
    if not archive.is_file() or archive.is_symlink():
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
            target_root = root / CANDIDATE_RELATIVE_ROOT
            target = target_root / candidate_name
            if target.exists() or target.is_symlink():
                raise RetentionError("restore target already exists")
            target_root.mkdir(parents=True, exist_ok=True, mode=0o700)
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
