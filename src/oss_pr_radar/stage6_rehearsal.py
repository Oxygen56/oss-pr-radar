"""Small, independently testable controls for the Stage 6 rehearsal.

The rehearsal never replaces a production database.  It copies only after an
explicit quiescence proof and publishes only redacted, relative-path reports.
Raw database and API evidence stays in a separately classified recovery area.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from .managed_lifecycle import copy_database
from .util import canonical_json, iso_z, parse_time, utc_now

PUBLIC_SAFE = "PUBLIC_SAFE"
RESTRICTED_RECOVERY = "RESTRICTED_RECOVERY"
STAGE6_REHEARSAL_SCHEMA = "oss-pr-radar.stage6.rehearsal.v2"
STAGE6_ENVELOPE_SCHEMA = "oss-pr-radar.stage6.envelope.v1"
MIN_FREE_BYTES = int(1.5 * 1024**3)

_ABSOLUTE_PATH = re.compile(r"(?:/Users/|/private/|/tmp/|[A-Za-z]:[\\/])")
_TOKEN_LIKE = re.compile(
    r"(?i)(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{8,}|"
    r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:api[_-]?key|secret|token)\s*[:=]\s*[^\s,}\]]+)"
)
_OBSERVED_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
MAX_OBSERVED_AGE = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=5)


class QuiescenceError(RuntimeError):
    """The source changed while a copy was being made."""


def resolve_observation_time(
    snapshot: dict[str, Any] | None = None,
    *,
    explicit: str | None = None,
) -> str:
    """Return one strict, current-enough UTC time bound to a live snapshot."""

    snapshot = snapshot if isinstance(snapshot, dict) else {}
    generated = snapshot.get("generatedAt") or snapshot.get("observationTime")
    if generated is not None and not isinstance(generated, str):
        raise ValueError("live snapshot generation time must be a string")
    if explicit is not None and generated is not None and explicit != generated:
        raise ValueError("--observed-at must match the live snapshot generation time")
    selected = explicit or generated or iso_z(utc_now())
    if not isinstance(selected, str) or not _OBSERVED_AT.fullmatch(selected):
        raise ValueError("observed-at must be a strict UTC ISO timestamp ending in Z")
    parsed = parse_time(selected)
    now = utc_now()
    if parsed < now - MAX_OBSERVED_AGE:
        raise ValueError("observed-at is too old for a live reconciliation")
    if parsed > now + MAX_FUTURE_SKEW:
        raise ValueError("observed-at is in the future")
    if iso_z(parsed) != selected:
        raise ValueError("observed-at is not canonical UTC ISO")
    return selected


def require_free_space(root: Path, projected_bytes: int, *, minimum_bytes: int = MIN_FREE_BYTES) -> dict[str, int]:
    """Fail before creating rehearsal files if the safety reserve would be crossed."""

    usage = os.statvfs(root)
    free_bytes = usage.f_bavail * usage.f_frsize
    if free_bytes - max(0, projected_bytes) < minimum_bytes:
        raise OSError("insufficient free space for compact Stage 6 rehearsal")
    return {
        "freeBytes": free_bytes,
        "projectedBytes": max(0, projected_bytes),
        "minimumFreeBytes": minimum_bytes,
        "remainingAfterProjection": free_bytes - max(0, projected_bytes),
    }


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sqlite_content_digest(path: Path) -> tuple[str, dict[str, int]]:
    source = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        source.execute("PRAGMA query_only=ON")
        memory = sqlite3.connect(":memory:")
        try:
            source.backup(memory)
            tables = [
                str(row[0])
                for row in memory.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            counts = {
                table: int(memory.execute(f' SELECT COUNT(*) FROM "{table}"').fetchone()[0])
                for table in tables
            }
            digest = hashlib.sha256()
            for line in memory.iterdump():
                digest.update(line.encode("utf-8"))
                digest.update(b"\n")
            return digest.hexdigest(), counts
        finally:
            memory.close()
    finally:
        source.close()


def source_generation(path: Path) -> dict[str, Any]:
    """Return a content generation without exporting any row values."""

    digest, counts = _sqlite_content_digest(path)
    return {"contentDigest": digest, "tableCounts": counts, "generation": _digest(counts | {"digest": digest})}


def _require_quiescence_proof(token: str | None, lease: dict[str, Any] | None) -> dict[str, Any]:
    if isinstance(token, str) and token.strip():
        return {"mode": "explicit_token", "tokenDigest": _digest(token.strip())}
    if isinstance(lease, dict) and lease.get("valid") is True and lease.get("owner") and lease.get("expiresAt"):
        return {
            "mode": "writer_lease",
            "owner": str(lease["owner"]),
            "expiresAt": str(lease["expiresAt"]),
            "proofDigest": _digest({"owner": lease["owner"], "expiresAt": lease["expiresAt"]}),
        }
    raise QuiescenceError("an explicit quiesce token or valid writer lease is required")


def stable_sqlite_copy(
    source: Path,
    target: Path,
    *,
    quiesce_token: str | None = None,
    writer_lease: dict[str, Any] | None = None,
    max_attempts: int = 3,
    generation_hook: Any | None = None,
) -> dict[str, Any]:
    """Copy a SQLite source only when its generation is stable.

    The optional hook is test-only and runs after the physical copy, allowing a
    concurrent writer to be simulated without touching a real source database.
    """

    proof = _require_quiescence_proof(quiesce_token, writer_lease)
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    target.parent.mkdir(parents=True, exist_ok=True)
    target_mode_before = target.exists()
    attempts: list[dict[str, Any]] = []
    for attempt in range(1, max_attempts + 1):
        before = source_generation(source)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o600)
        try:
            copy_database(source, temporary)
            # The SQLite backup may leave data in a WAL sidecar.  Checkpoint
            # and close it before the atomic replace so the target is a
            # self-contained recovery file.
            checkpoint = sqlite3.connect(temporary)
            try:
                checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                checkpoint.execute("PRAGMA journal_mode=DELETE")
                checkpoint.commit()
            finally:
                checkpoint.close()
            for sidecar in (Path(f"{temporary}-wal"), Path(f"{temporary}-shm")):
                if sidecar.exists():
                    sidecar.unlink()
            if generation_hook is not None:
                generation_hook(attempt, source)
            after = source_generation(source)
            stable = before["generation"] == after["generation"]
            attempts.append({"attempt": attempt, "before": before, "after": after, "stable": stable})
            if stable:
                with temporary.open("rb") as handle:
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
                os.chmod(target, 0o600)
                directory_fd = os.open(target.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                return {"ok": True, "proof": proof, "attempts": attempts, "targetExisted": target_mode_before}
        finally:
            if temporary.exists():
                temporary.unlink()
    raise QuiescenceError(
        f"source generation did not stabilize after {max_attempts} attempts; target was not replaced"
    )


def redact_public(value: Any) -> Any:
    """Redact paths and token-like values recursively for PUBLIC_SAFE output."""

    if isinstance(value, dict):
        return {str(key): redact_public(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_public(child) for child in value]
    if isinstance(value, str):
        value = _ABSOLUTE_PATH.sub("<redacted-path>", value)
        return _TOKEN_LIKE.sub("<redacted-secret>", value)
    return value


def public_safe_scan(root: Path) -> dict[str, Any]:
    """Scan only PUBLIC_SAFE files; restricted recovery files are excluded."""

    violations: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or classify_artifact(path) != PUBLIC_SAFE:
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            violations.append({"path": str(path.relative_to(root)), "reason": "non_utf8_public_file"})
            continue
        if _ABSOLUTE_PATH.search(text):
            violations.append({"path": str(path.relative_to(root)), "reason": "absolute_path"})
        if _TOKEN_LIKE.search(text):
            violations.append({"path": str(path.relative_to(root)), "reason": "token_like_value"})
    return {"publicSafe": not violations, "violations": violations}


def classify_artifact(path: Path) -> str:
    name = path.name.casefold()
    if name.endswith((".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".patch")):
        return RESTRICTED_RECOVERY
    if "raw" in name or "live-open-prs" in name or "api-payload" in name:
        return RESTRICTED_RECOVERY
    return PUBLIC_SAFE


def artifact_manifest(root: Path, *, exclude_names: set[str] | None = None) -> dict[str, Any]:
    excluded = exclude_names or set()
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        relative = str(path.relative_to(root))
        files.append(
            {
                "path": relative,
                "classification": classify_artifact(path),
                "bytes": path.stat().st_size,
                "mode": oct(path.stat().st_mode & 0o777),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "ephemeralSidecar": path.name.endswith(("-wal", "-shm")),
            }
        )
    safe = public_safe_scan(root)
    return {
        "schema": STAGE6_REHEARSAL_SCHEMA,
        "rootRelativeOnly": True,
        "completeFileInventory": True,
        "files": files,
        "publicSafeScan": safe,
        "restrictedRecoveryExcludedFromPublicClaim": True,
    }


def secure_atomic_json(path: Path, value: object) -> None:
    """Create a 0600 JSON file atomically under a 0700 directory tree."""

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    raw = (canonical_json(redact_public(value)) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        temporary.write_bytes(raw)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def secure_atomic_private_json(path: Path, value: object) -> None:
    """Create an unredacted 0600 JSON file with a durable atomic replace."""

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    raw = (canonical_json(value) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        temporary.write_bytes(raw)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def secure_sqlite_target(path: Path) -> None:
    """Create an empty SQLite target with recovery-only permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    os.chmod(path, 0o600)


def write_detached_report_envelope(
    report: Path,
    envelope: Path,
    *,
    code_head: str,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    """Bind report bytes and HEAD in a separate, non-self-referential file."""

    if report.parent.resolve() != envelope.parent.resolve():
        raise ValueError("report and envelope must share a directory")
    expected_inventory = artifact_manifest(envelope.parent, exclude_names={envelope.name})
    if inventory != expected_inventory:
        raise ValueError("detached envelope inventory does not match the current artifact tree")
    payload = {
        "schema": STAGE6_ENVELOPE_SCHEMA,
        "codeHead": code_head,
        "report": {
            "path": report.name,
            "bytes": report.stat().st_size,
            "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        },
        "artifactManifest": inventory,
        "completeFileInventoryExceptEnvelope": True,
    }
    secure_atomic_json(envelope, payload)
    return payload


def validate_detached_report_envelope(report: Path, envelope: Path, *, code_head: str) -> None:
    """Verify the detached report and the complete non-envelope artifact tree."""

    import json

    if report.parent.resolve() != envelope.parent.resolve():
        raise ValueError("report and envelope must share a directory")
    if not report.is_file() or not envelope.is_file():
        raise ValueError("detached report or envelope is missing")
    payload = json.loads(envelope.read_text(encoding="utf-8"))
    if set(payload) != {
        "schema",
        "codeHead",
        "report",
        "artifactManifest",
        "completeFileInventoryExceptEnvelope",
    }:
        raise ValueError("detached report envelope fields are incomplete")
    if payload.get("schema") != STAGE6_ENVELOPE_SCHEMA or payload.get("codeHead") != code_head:
        raise ValueError("detached report envelope is not bound to this HEAD")
    if payload.get("completeFileInventoryExceptEnvelope") is not True:
        raise ValueError("detached report envelope is not a complete inventory")
    report_meta = payload.get("report")
    if (
        not isinstance(report_meta, dict)
        or set(report_meta) != {"path", "bytes", "sha256"}
        or report_meta.get("path") != report.name
        or Path(str(report_meta.get("path"))).is_absolute()
        or ".." in Path(str(report_meta.get("path"))).parts
    ):
        raise ValueError("detached report envelope names the wrong report")
    raw = report.read_bytes()
    if report_meta.get("bytes") != len(raw) or report_meta.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("detached report envelope does not match report bytes")
    inventory = payload.get("artifactManifest")
    if not isinstance(inventory, dict):
        raise ValueError("detached report envelope is missing artifactManifest")
    if inventory.get("rootRelativeOnly") is not True or inventory.get("completeFileInventory") is not True:
        raise ValueError("artifact manifest is not a complete relative inventory")
    files = inventory.get("files")
    if not isinstance(files, list):
        raise ValueError("artifact manifest files are invalid")
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "classification",
            "bytes",
            "mode",
            "sha256",
            "ephemeralSidecar",
        }:
            raise ValueError("artifact manifest file entry is invalid")
        relative = Path(str(item["path"]))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("artifact manifest contains an unsafe path")
        if relative.as_posix() in seen:
            raise ValueError("artifact manifest contains a duplicate path")
        seen.add(relative.as_posix())
        if item["classification"] not in {PUBLIC_SAFE, RESTRICTED_RECOVERY}:
            raise ValueError("artifact manifest classification is invalid")
        if item["mode"] != "0o600":
            raise ValueError("artifact manifest file mode is not restricted")
    expected = artifact_manifest(envelope.parent, exclude_names={envelope.name})
    if inventory != expected:
        raise ValueError("artifact manifest does not cover the current filesystem")
    if any(item["path"] == envelope.name for item in files):
        raise ValueError("detached envelope must be excluded from its own inventory")


def secure_permissions(root: Path) -> None:
    """Protect an existing evidence tree without deleting or rewriting content."""

    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_file():
            os.chmod(path, 0o600)
        elif path.is_dir():
            os.chmod(path, 0o700)
    if root.exists():
        os.chmod(root, 0o700)
