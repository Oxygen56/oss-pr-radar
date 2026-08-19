"""Reversible local Stage 7 ledger-pointer cutover protocol."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .managed_lifecycle import MANAGED_SCHEMA_VERSION
from .managed_security import sign_current, verify_current
from .operational_auth import revoke_operational_authorization
from .release_binding import bind_runtime, runtime_root_digest
from .runtime_audit import LEGACY_LABELS, WORKER_LABELS, collect_snapshot, launchctl_print
from .stage6_rehearsal import (
    require_free_space,
    resolve_observation_time,
    source_generation,
    stable_sqlite_copy,
)
from .util import canonical_json, sha256_json, utc_now

CUTOVER_SCHEMA = "oss-pr-radar.stage7-ledger-cutover.v1"
CUTOVER_CONTEXT = "stage7-cutover-v1"
POINTER_NAME = "current-ledger"
VERSIONS_DIR = "ledger-releases"
ROLLBACK_NONCE_SCHEMA = "oss-pr-radar.stage7-rollback-nonces.v1"
ROLLBACK_NONCE_FILE = "stage7-rollback-nonces.json"
STOP_EVIDENCE_SCHEMA = "oss-pr-radar.stage7-stop-evidence.v1"


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_inventory(paths: list[Path]) -> list[dict[str, Any]]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file())
    return [
        {
            "path": str(path),
            "bytes": path.stat().st_size,
            "mode": oct(path.stat().st_mode & 0o777),
            "sha256": _sha(path),
        }
        for path in sorted(files, key=lambda item: str(item))
    ]


def _validate_file_inventory(manifest: dict[str, Any], *, include_target: bool = True) -> None:
    """Re-check every signed file before a pointer-changing operation."""

    entries = manifest.get("fileInventory")
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("cutover file inventory is missing")
    expected: dict[str, dict[str, Any]] = {}
    target_name = Path(str(manifest.get("target") or "")).name
    skipped_target = False
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise RuntimeError("cutover file inventory entry is invalid")
        path = Path(item["path"]).resolve()
        if not include_target and path.name == target_name and not (
            isinstance(manifest.get("gitPreservation"), dict)
            and manifest["gitPreservation"].get("archivePath")
            and Path(str(manifest["gitPreservation"]["archivePath"])).resolve() in path.parents
        ):
            if skipped_target:
                raise RuntimeError("cutover file inventory contains a duplicate target")
            skipped_target = True
            continue
        path_key = str(path)
        if path_key in expected or path.is_symlink() or not path.is_file():
            raise RuntimeError("cutover file inventory contains a missing or duplicate file")
        actual = {
            "path": str(path),
            "bytes": path.stat().st_size,
            "mode": oct(path.stat().st_mode & 0o777),
            "sha256": _sha(path),
        }
        if actual != {
            "path": str(path),
            "bytes": int(item.get("bytes", -1)),
            "mode": str(item.get("mode")),
            "sha256": str(item.get("sha256")),
        }:
            raise RuntimeError("cutover file inventory does not match the current file")
        expected[str(path)] = actual
    preservation = manifest.get("gitPreservation")
    archive_value = preservation.get("archivePath") if isinstance(preservation, dict) else None
    if archive_value:
        archive = Path(str(archive_value)).resolve()
        actual_paths = {item["path"] for item in _file_inventory([archive])}
        signed_paths = {
            path for path in expected if Path(path) == archive or archive in Path(path).parents
        }
        if actual_paths != signed_paths:
            raise RuntimeError("cutover file inventory does not exactly cover preservation archive")
    if include_target:
        target_name = str(manifest.get("target") or "")
        if not any(Path(path).name == Path(target_name).name for path in expected):
            raise RuntimeError("cutover file inventory does not include the target ledger")


def _relative_state_path(state: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("cutover path must be relative")
    resolved = (state / relative).resolve()
    if state.resolve() not in resolved.parents:
        raise ValueError("cutover path escapes runtime state")
    return relative


def _sqlite_integrity(path: Path) -> str:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        connection.close()


def _managed_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError("cutover source database is missing")
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        try:
            versions = [
                int(row[0])
                for row in connection.execute(
                    "SELECT version FROM managed_schema_migrations ORDER BY version"
                ).fetchall()
            ]
        except sqlite3.OperationalError as exc:
            raise ValueError("cutover source is not a managed ledger") from exc
        current = versions[-1] if versions else 0
        if current != MANAGED_SCHEMA_VERSION:
            raise ValueError(
                f"cutover source schema {current} is not current managed schema {MANAGED_SCHEMA_VERSION}"
            )
        return {"current": current, "versions": versions}
    finally:
        connection.close()


def _private_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _git_preservation(repo: Path | None, archive: Path) -> dict[str, Any]:
    if repo is None:
        return {
            "available": False,
            "status": "",
            "archivePath": None,
            "trackedPatchPath": None,
            "trackedPatchSha256": None,
            "untrackedFiles": [],
        }
    repo = repo.resolve()
    archive.mkdir(parents=True, exist_ok=False)
    os.chmod(archive, 0o700)
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    top_level = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    baseline_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    origin_result = subprocess.run(
        ["git", "config", "--get", "remote.origin.url"],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    origin = origin_result.stdout.strip() or None
    patch_bytes = subprocess.run(
        ["git", "diff", "--binary", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    tracked_patch = archive / "tracked.patch"
    _private_bytes(tracked_patch, patch_bytes)
    raw_untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    untracked: list[dict[str, Any]] = []
    for encoded in raw_untracked.split(b"\0"):
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError("git preservation encountered an unsafe untracked path")
        source = repo / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError("git preservation only supports regular untracked files")
        raw = source.read_bytes()
        archive_relative = Path("untracked") / relative
        destination = archive / archive_relative
        _private_bytes(destination, raw)
        untracked.append(
            {
                "path": relative.as_posix(),
                "archivePath": archive_relative.as_posix(),
                "bytes": len(raw),
                "mode": oct(source.stat().st_mode & 0o777),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    metadata = {
        "schema": "oss-pr-radar.stage7-git-preservation.v1",
        "status": status,
        "repository": {
            "root": top_level,
            "baselineHead": baseline_head,
            "origin": origin,
            "status": status,
            "statusSha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        },
        "trackedPatch": {
            "path": "tracked.patch",
            "bytes": len(patch_bytes),
            "sha256": hashlib.sha256(patch_bytes).hexdigest(),
        },
        "untrackedFiles": sorted(untracked, key=lambda item: item["path"]),
    }
    _write(archive / "archive-manifest.json", metadata)
    _fsync_directory(archive)
    return {
        "available": True,
        "status": status,
        "archivePath": str(archive),
        "trackedPatchPath": str(tracked_patch),
        "trackedPatchSha256": metadata["trackedPatch"]["sha256"],
        "untrackedFiles": untracked,
        "trackedPatch": metadata["trackedPatch"],
        "repository": metadata["repository"],
    }


def _sign(manifest: dict[str, Any]) -> dict[str, Any]:
    unsigned = {key: value for key, value in manifest.items() if key not in {"manifestDigest", "keyId", "signature"}}
    digest = sha256_json(unsigned)
    key_id = os.environ.get("RADAR_DISPATCH_HMAC_KEY_ID", "dispatch-current")
    payload = {**unsigned, "manifestDigest": digest, "keyId": key_id}
    auth = sign_current(payload, context=CUTOVER_CONTEXT)
    if not auth.get("keyId") or not auth.get("signature"):
        raise PermissionError("current signing key is unavailable")
    return {**payload, "signature": auth["signature"]}


def _verify(manifest: dict[str, Any]) -> None:
    unsigned = {key: value for key, value in manifest.items() if key not in {"manifestDigest", "keyId", "signature"}}
    digest = sha256_json(unsigned)
    if manifest.get("manifestDigest") != digest:
        raise ValueError("cutover manifest digest mismatch")
    if not verify_current(
        {**unsigned, "manifestDigest": digest, "keyId": manifest.get("keyId")},
        context=CUTOVER_CONTEXT,
        key_id=manifest.get("keyId"),
        signature=manifest.get("signature"),
    ):
        raise ValueError("cutover manifest authentication failed")


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temporary = Path(temp_name)
    try:
        os.chmod(temporary, 0o600)
        temporary.write_bytes((canonical_json(value) + "\n").encode())
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rollback_nonce_state(state: Path) -> tuple[Path, dict[str, Any]]:
    path = state / ROLLBACK_NONCE_FILE
    if not path.exists():
        return path, {"schema": ROLLBACK_NONCE_SCHEMA, "nonces": []}
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != ROLLBACK_NONCE_SCHEMA or not isinstance(value.get("nonces"), list):
        raise ValueError("rollback nonce state is invalid")
    _verify(value)
    return path, value


def _consume_rollback_nonce(state: Path, nonce: str) -> None:
    if not nonce:
        raise ValueError("rollback manifest nonce is missing")
    path, value = _rollback_nonce_state(state)
    if nonce in value["nonces"]:
        raise RuntimeError("rollback nonce has already been consumed")
    value = _sign(
        {
            "schema": ROLLBACK_NONCE_SCHEMA,
            "nonces": sorted([*value["nonces"], nonce]),
        }
    )
    _write(path, value)


def _begin_rollback_nonce(state: Path, nonce: str, *, manifest_path: Path, digest: str) -> None:
    path, value = _rollback_nonce_state(state)
    if nonce in value["nonces"]:
        raise RuntimeError("rollback nonce has already been consumed")
    in_progress = value.get("inProgress") if isinstance(value.get("inProgress"), dict) else {}
    marker = {"manifestPath": str(manifest_path.resolve()), "manifestDigest": digest}
    if nonce in in_progress and in_progress[nonce] != marker:
        raise RuntimeError("rollback nonce is in progress for a different manifest")
    if nonce not in in_progress:
        _write(path, _sign({"schema": ROLLBACK_NONCE_SCHEMA, "nonces": sorted(value["nonces"]), "inProgress": {**in_progress, nonce: marker}}))


def _finish_rollback_nonce(state: Path, nonce: str) -> None:
    path, value = _rollback_nonce_state(state)
    in_progress = value.get("inProgress") if isinstance(value.get("inProgress"), dict) else {}
    if nonce not in in_progress:
        raise RuntimeError("rollback nonce is not in progress")
    marker = in_progress[nonce]
    completed = value.get("completed") if isinstance(value.get("completed"), dict) else {}
    _write(path, _sign({
        "schema": ROLLBACK_NONCE_SCHEMA,
        "nonces": sorted([*value["nonces"], nonce]),
        "inProgress": {key: item for key, item in in_progress.items() if key != nonce},
        "completed": {**completed, nonce: marker},
    }))


def _pointer_target(state: Path) -> tuple[str | None, str | None]:
    pointer = state / POINTER_NAME
    if not pointer.exists() and not pointer.is_symlink():
        return None, None
    target = pointer.resolve()
    if target.parent != (state / VERSIONS_DIR).resolve():
        raise RuntimeError("current ledger pointer escapes version directory")
    if not target.is_file():
        raise RuntimeError("current ledger pointer target is missing")
    return str(target.relative_to(state)), _sha(target)


def _service_stopped(evidence_path: Path) -> dict[str, Any]:
    try:
        value = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("service-stopped evidence is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema") != STOP_EVIDENCE_SCHEMA:
        raise ValueError("service-stopped evidence is not a signed Stage 7 record")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned,
        context="stage7-stop-evidence-v1",
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    ):
        raise ValueError("service-stopped evidence authentication failed")
    try:
        observed = datetime.fromisoformat(str(value["observedAt"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(value["expiresAt"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise ValueError("service-stopped evidence time is invalid") from exc
    now_value = utc_now()
    if observed > now_value + timedelta(minutes=1) or expires < now_value or expires - observed > timedelta(minutes=10):
        raise ValueError("service-stopped evidence is expired or outside its validity window")
    if value.get("allStopped") is not True:
        raise ValueError("service-stopped evidence must prove all workers are stopped")
    workers = value.get("workers")
    if not isinstance(workers, dict) or set(workers) != set(WORKER_LABELS):
        raise ValueError("service-stopped evidence has an incomplete worker key set")
    for worker, item in workers.items():
        if not isinstance(item, dict) or item.get("loaded") is True or item.get("pidAlive") is True:
            raise ValueError(f"service-stopped evidence reports an active worker: {worker}")
    legacy = value.get("legacy")
    if not isinstance(legacy, dict) or set(legacy) != set(LEGACY_LABELS) or any(
        not isinstance(item, dict) or item.get("loaded") is True for item in legacy.values()
    ):
        raise ValueError("service-stopped evidence has an incomplete or active legacy key set")
    return value


def _live_services_stopped(runtime_root: Path) -> dict[str, Any]:
    """Read current launchd/process state without trusting a prior evidence file."""

    snapshot = collect_snapshot(runtime_root)
    workers: dict[str, dict[str, Any]] = {}
    for worker, label in WORKER_LABELS.items():
        item = snapshot.get("workerProcesses", {}).get(worker, {})
        launch = item.get("launchctl") if isinstance(item.get("launchctl"), dict) else {}
        process = item.get("process") if isinstance(item.get("process"), dict) else {}
        raw = launchctl_print(label)
        loaded = bool(raw.strip()) and not any(
            marker in raw.casefold() for marker in ("could not find", "service not found", "no such process")
        )
        workers[worker] = {
            "label": label,
            "loaded": loaded,
            "pidAlive": process.get("alive") is True,
            "pid": launch.get("pid"),
        }
    legacy = {}
    for label in LEGACY_LABELS:
        raw = launchctl_print(label)
        legacy[label] = {
            "loaded": bool(raw.strip()) and not any(
                marker in raw.casefold() for marker in ("could not find", "service not found", "no such process")
            )
        }
    if any(item["loaded"] or item["pidAlive"] for item in workers.values()) or any(
        item["loaded"] for item in legacy.values()
    ):
        raise RuntimeError("workers or legacy services became active after stop evidence")
    return {"workers": workers, "legacy": legacy}


def build_stop_evidence(runtime_root: Path) -> dict[str, Any]:
    """Create short-lived stop evidence from live launchd/process observations."""

    binding = bind_runtime(runtime_root)
    live = _live_services_stopped(runtime_root)
    workers = live["workers"]
    legacy = live["legacy"]
    observed = datetime.now(UTC)
    unsigned = {
        "schema": STOP_EVIDENCE_SCHEMA,
        "runtimeRootDigest": runtime_root_digest(runtime_root),
        "releaseId": binding.release_id,
        "observedAt": observed.isoformat().replace("+00:00", "Z"),
        "expiresAt": (observed + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "allStopped": True,
        "workers": workers,
        "legacy": legacy,
    }
    auth = sign_current(unsigned, context="stage7-stop-evidence-v1")
    if not auth.get("keyId") or not auth.get("signature"):
        raise PermissionError("current signing key is unavailable")
    return {**unsigned, **auth}


def bootstrap(
    runtime_root: Path,
    legacy_source: Path,
    *,
    quiesce_token: str,
    service_stopped_evidence: Path,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Retain the pre-managed legacy DB and make it the rollback target.

    Bootstrap is deliberately separate from ``prepare``: it accepts a legacy
    schema, runs only before a pointer exists, and never creates a managed
    ledger.  A later prepare must copy a current managed ledger over this
    retained legacy version.
    """

    binding = bind_runtime(runtime_root)
    runtime_root = runtime_root.resolve()
    state = runtime_root / "state"
    state.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    if (state / POINTER_NAME).exists() or (state / POINTER_NAME).is_symlink():
        raise RuntimeError("legacy bootstrap is only allowed before current-ledger exists")
    evidence = _service_stopped(service_stopped_evidence)
    if evidence.get("runtimeRootDigest") != runtime_root_digest(runtime_root):
        raise ValueError("service-stopped evidence is bound to a different runtime root")
    if evidence.get("releaseId") != binding.release_id:
        raise ValueError("service-stopped evidence is bound to a different release")
    _live_services_stopped(runtime_root)
    generation = source_generation(legacy_source)
    nonce = hashlib.sha256(os.urandom(32)).hexdigest()
    versions = state / VERSIONS_DIR
    versions.mkdir(parents=True, exist_ok=True)
    os.chmod(versions, 0o700)
    require_free_space(runtime_root, legacy_source.stat().st_size + 2 * 1024 * 1024)
    target = versions / f"bootstrap-legacy-{generation['generation'][:24]}-{nonce[:16]}.sqlite3"
    copy = stable_sqlite_copy(
        legacy_source,
        target,
        quiesce_token=quiesce_token,
        max_attempts=max_attempts,
    )
    if _sqlite_integrity(target) != "ok":
        raise RuntimeError("bootstrapped legacy ledger integrity check failed")
    pointer = state / POINTER_NAME
    temporary = state / f".{POINTER_NAME}.{os.getpid()}.tmp"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(Path(VERSIONS_DIR) / target.name)
    temporary.replace(pointer)
    _fsync_directory(state)
    manifest = _sign(
        {
            "schema": CUTOVER_SCHEMA,
            "phase": "BOOTSTRAPPED",
            "kind": "LEGACY_BOOTSTRAP",
            "cutoverId": f"bootstrap-{nonce[:16]}",
            "nonce": nonce,
            "sourceGeneration": generation,
            "sourceSchema": {"managed": False},
            "serviceStoppedEvidence": {
                "sha256": sha256_json(evidence),
                "workers": sorted(str(item) for item in evidence["workers"]),
            },
            "target": str(target.relative_to(state)),
            "targetBytes": target.stat().st_size,
            "targetSha256": _sha(target),
            "targetIntegrity": _sqlite_integrity(target),
            "release": {
                "releaseId": binding.release_id,
                "manifestSha256": binding.release.get("manifestSha256"),
                "path": str(binding.code_root),
            },
            "copy": copy,
        }
    )
    manifest_path = runtime_root / "reports" / "stage7" / f"bootstrap-{nonce[:16]}.json"
    _write(manifest_path, manifest)
    return {"ok": True, "phase": "BOOTSTRAPPED", "manifestPath": str(manifest_path), "manifest": manifest}


def prepare(
    runtime_root: Path,
    source: Path,
    *,
    quiesce_token: str,
    production_repo: Path | None = None,
    max_attempts: int = 3,
    observed_at: str | None = None,
) -> dict[str, Any]:
    binding = bind_runtime(runtime_root)
    runtime_root = runtime_root.resolve()
    state = runtime_root / "state"
    schema = _managed_schema(source)
    before = source_generation(source)
    nonce = hashlib.sha256(os.urandom(32)).hexdigest()
    versions = state / VERSIONS_DIR
    versions.mkdir(parents=True, exist_ok=True)
    os.chmod(state, 0o700)
    os.chmod(versions, 0o700)
    previous_target, previous_digest = _pointer_target(state)
    if previous_target is None:
        raise RuntimeError("legacy bootstrap is required before managed prepare")
    copies = 2
    require_free_space(runtime_root, source.stat().st_size * copies + 2 * 1024 * 1024)
    target_name = f"{before['generation'][:24]}-{nonce[:16]}.sqlite3"
    target = versions / target_name
    copy = stable_sqlite_copy(source, target, quiesce_token=quiesce_token, max_attempts=max_attempts)
    if _sqlite_integrity(target) != "ok":
        raise RuntimeError("prepared ledger integrity check failed")
    observation_time = resolve_observation_time({}, explicit=observed_at)
    after = source_generation(source)
    if before["generation"] != after["generation"]:
        raise RuntimeError("source generation changed during cutover preparation")
    target_sha = _sha(target)
    cutover_id = f"{before['generation'][:16]}-{nonce[:16]}"
    git_evidence = _git_preservation(
        production_repo,
        runtime_root / "reports" / "stage7" / f"{cutover_id}.git-preservation",
    )
    inventory_paths = [target]
    if git_evidence.get("archivePath"):
        inventory_paths.append(Path(str(git_evidence["archivePath"])))
    manifest = _sign(
        {
            "schema": CUTOVER_SCHEMA,
            "phase": "PREPARED",
            "cutoverId": cutover_id,
            "nonce": nonce,
            "sourceGenerationBefore": before,
            "sourceGenerationAfter": after,
            "sourceSchema": schema,
            "observationTime": observation_time,
            "target": str(target.relative_to(state)),
            "targetBytes": target.stat().st_size,
            "targetSha256": target_sha,
            "targetIntegrity": _sqlite_integrity(target),
            "fileInventory": _file_inventory(inventory_paths),
            "previousTarget": previous_target,
            "previousTargetSha256": previous_digest,
            "release": {
                "releaseId": binding.release_id,
                "manifestSha256": binding.release.get("manifestSha256"),
                "path": str(binding.code_root),
            },
            "gitPreservation": git_evidence,
            "copy": copy,
        }
    )
    manifest_path = runtime_root / "reports" / "stage7" / f"{cutover_id}.json"
    _write(manifest_path, manifest)
    return {"ok": True, "phase": "PREPARED", "manifestPath": str(manifest_path), "manifest": manifest}


def activate(runtime_root: Path, manifest_path: Path) -> dict[str, Any]:
    binding = bind_runtime(runtime_root)
    runtime_root = runtime_root.resolve()
    state = runtime_root / "state"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _verify(manifest)
    if manifest.get("phase") != "PREPARED":
        raise ValueError("cutover manifest is not prepared")
    if manifest.get("release", {}).get("releaseId") != binding.release_id:
        raise RuntimeError("cutover manifest is bound to a different release")
    relative = _relative_state_path(state, str(manifest["target"]))
    target = state / relative
    if not target.is_file() or _sha(target) != manifest.get("targetSha256"):
        raise RuntimeError("prepared ledger bytes changed")
    _validate_file_inventory(manifest, include_target=True)
    revoke_operational_authorization(runtime_root)
    pointer = state / POINTER_NAME
    temporary = state / f".{POINTER_NAME}.{os.getpid()}.tmp"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(Path(VERSIONS_DIR) / target.name)
    temporary.replace(pointer)
    _fsync_directory(state)
    activated = {**manifest, "phase": "ACTIVATED"}
    _write(manifest_path, _sign({key: value for key, value in activated.items() if key not in {"manifestDigest", "keyId", "signature"}}))
    return {"ok": True, "phase": "ACTIVATED", "pointer": str(pointer), "target": str(target)}


def rollback(runtime_root: Path, manifest_path: Path) -> dict[str, Any]:
    binding = bind_runtime(runtime_root)
    runtime_root = runtime_root.resolve()
    state = runtime_root / "state"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _verify(manifest)
    if manifest.get("phase") != "ACTIVATED":
        raise ValueError("only an activated cutover can be rolled back")
    if manifest.get("release", {}).get("releaseId") != binding.release_id:
        raise RuntimeError("cutover manifest is bound to a different release")
    _validate_file_inventory(manifest, include_target=False)
    nonce = str(manifest.get("nonce") or "")
    _, nonce_state = _rollback_nonce_state(state)
    current, _ = _pointer_target(state)
    previous = manifest.get("previousTarget")
    if not previous:
        raise RuntimeError("no retained previous ledger pointer is available")
    previous_relative = _relative_state_path(state, previous)
    previous_path = state / previous_relative
    if not previous_path.is_file() or _sha(previous_path) != manifest.get("previousTargetSha256"):
        raise RuntimeError("retained previous ledger is unavailable or changed")
    revoke_operational_authorization(runtime_root)
    in_progress = nonce_state.get("inProgress") if isinstance(nonce_state.get("inProgress"), dict) else {}
    marker = in_progress.get(nonce)
    expected_marker = {
        "manifestPath": str(manifest_path.resolve()),
        "manifestDigest": str(manifest.get("manifestDigest") or ""),
    }
    if nonce in nonce_state["nonces"]:
        completed = nonce_state.get("completed") if isinstance(nonce_state.get("completed"), dict) else {}
        if current == previous and completed.get(nonce) == expected_marker:
            rolled = {**manifest, "phase": "ROLLED_BACK"}
            _write(manifest_path, _sign({key: value for key, value in rolled.items() if key not in {"manifestDigest", "keyId", "signature"}}))
            return {"ok": True, "phase": "ROLLED_BACK", "pointer": str(state / POINTER_NAME), "target": str(previous_path)}
        raise RuntimeError("rollback nonce has already been consumed")
    if current == previous and marker == expected_marker:
        _finish_rollback_nonce(state, nonce)
        rolled = {**manifest, "phase": "ROLLED_BACK"}
        _write(manifest_path, _sign({key: value for key, value in rolled.items() if key not in {"manifestDigest", "keyId", "signature"}}))
        return {"ok": True, "phase": "ROLLED_BACK", "pointer": str(state / POINTER_NAME), "target": str(previous_path)}
    if current != manifest.get("target"):
        raise RuntimeError("current pointer is not the cutover target")
    _begin_rollback_nonce(
        state,
        nonce,
        manifest_path=manifest_path,
        digest=str(manifest.get("manifestDigest") or ""),
    )
    temporary = state / f".{POINTER_NAME}.{os.getpid()}.tmp"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(previous_relative)
    temporary.replace(state / POINTER_NAME)
    _fsync_directory(state)
    _finish_rollback_nonce(state, nonce)
    rolled = {**manifest, "phase": "ROLLED_BACK"}
    _write(manifest_path, _sign({key: value for key, value in rolled.items() if key not in {"manifestDigest", "keyId", "signature"}}))
    return {"ok": True, "phase": "ROLLED_BACK", "pointer": str(state / POINTER_NAME), "target": str(previous_path)}


def _git_value(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _restore_preflight(
    repo: Path,
    repository: dict[str, Any],
    *,
    require_identity: bool,
    require_clean: bool = True,
    check_origin: bool = True,
) -> None:
    if not repo.is_dir() or (repo / ".git").exists() is False:
        raise RuntimeError("restore target is not a Git repository")
    top_level = Path(_git_value(repo, "rev-parse", "--show-toplevel")).resolve()
    expected_root = Path(str(repository.get("root"))).resolve()
    if require_identity and top_level != expected_root:
        raise RuntimeError("restore target repository identity does not match the preservation manifest")
    if _git_value(repo, "rev-parse", "HEAD") != repository.get("baselineHead"):
        raise RuntimeError("restore target HEAD does not match the preservation baseline")
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if require_clean and status:
        raise RuntimeError("restore target has unexpected changes")
    expected_origin = repository.get("origin")
    if check_origin and expected_origin:
        actual_origin = _git_value(repo, "config", "--get", "remote.origin.url")
        if actual_origin != expected_origin:
            raise RuntimeError("restore target origin does not match the preservation manifest")


def _preservation_metadata(
    preservation: dict[str, Any], archive: Path
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    try:
        metadata = json.loads((archive / "archive-manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("git preservation archive manifest is unreadable") from exc
    if metadata.get("schema") != "oss-pr-radar.stage7-git-preservation.v1":
        raise RuntimeError("git preservation archive manifest schema is invalid")
    repository = metadata.get("repository")
    tracked = metadata.get("trackedPatch")
    untracked = metadata.get("untrackedFiles")
    if not isinstance(repository, dict) or not isinstance(tracked, dict) or not isinstance(untracked, list):
        raise RuntimeError("git preservation archive manifest is incomplete")
    signed_repository = preservation.get("repository")
    signed_tracked = preservation.get("trackedPatch")
    signed_untracked = preservation.get("untrackedFiles")
    if signed_repository is not None and signed_repository != repository:
        raise RuntimeError("git preservation repository metadata has multiple inconsistent sources")
    if signed_tracked is not None and signed_tracked != tracked:
        raise RuntimeError("git preservation tracked patch metadata has multiple inconsistent sources")
    if signed_untracked is not None and signed_untracked != untracked:
        raise RuntimeError("git preservation untracked metadata has multiple inconsistent sources")
    if repository.get("statusSha256") != hashlib.sha256(str(repository.get("status", "")).encode()).hexdigest():
        raise RuntimeError("git preservation status digest is invalid")
    return repository, tracked, untracked


def _apply_preservation_to_repo(repo: Path, manifest: dict[str, Any], journal: Path) -> dict[str, Any]:
    preservation = manifest.get("gitPreservation")
    if not isinstance(preservation, dict) or preservation.get("available") is not True:
        raise RuntimeError("git preservation is unavailable")
    archive = Path(str(preservation["archivePath"])).resolve()
    repository, tracked_meta, untracked_files = _preservation_metadata(preservation, archive)
    tracked_patch = archive / str(tracked_meta["path"])
    expected_patch_bytes = tracked_meta.get("bytes")
    if (
        not isinstance(expected_patch_bytes, int)
        or expected_patch_bytes < 0
        or not tracked_patch.is_file()
        or tracked_patch.stat().st_size != expected_patch_bytes
        or _sha(tracked_patch) != tracked_meta.get("sha256")
    ):
        raise RuntimeError("tracked preservation patch is missing or changed")
    journal.parent.mkdir(parents=True, exist_ok=True)
    _write(journal, {"schema": "oss-pr-radar.stage7-restore.v1", "phase": "STAGED", "manifestDigest": manifest.get("manifestDigest"), "repo": str(repo.resolve())})
    if expected_patch_bytes:
        subprocess.run(["git", "apply", "--check", "--binary", str(tracked_patch)], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "apply", "--binary", str(tracked_patch)], cwd=repo, check=True, capture_output=True)
    _write(journal, {"schema": "oss-pr-radar.stage7-restore.v1", "phase": "TRACKED_APPLIED", "manifestDigest": manifest.get("manifestDigest"), "repo": str(repo.resolve())})
    for item in untracked_files:
        if not isinstance(item, dict):
            raise RuntimeError("untracked preservation entry is invalid")
        relative = Path(str(item.get("path")))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise RuntimeError("untracked preservation path is unsafe")
        source = archive / Path(str(item.get("archivePath")))
        destination = repo / relative
        if destination.exists() or destination.is_symlink() or not source.is_file():
            raise RuntimeError("restore would overwrite an unexpected file")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.restore.{os.getpid()}.tmp")
        _private_bytes(temporary, source.read_bytes())
        os.chmod(temporary, int(str(item["mode"]), 8))
        os.replace(temporary, destination)
        os.chmod(destination, int(str(item["mode"]), 8))
        if _sha(destination) != item.get("sha256") or destination.stat().st_size != item.get("bytes"):
            raise RuntimeError("restored untracked file does not match preservation evidence")
    _write(journal, {"schema": "oss-pr-radar.stage7-restore.v1", "phase": "VERIFYING", "manifestDigest": manifest.get("manifestDigest"), "repo": str(repo.resolve())})
    if tracked_patch.stat().st_size != expected_patch_bytes or _sha(tracked_patch) != tracked_meta.get("sha256"):
        raise RuntimeError("tracked preservation patch changed during restore")
    expected_status = str(repository.get("status") or "")
    actual_status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if actual_status != expected_status:
        raise RuntimeError("restored repository status does not match preservation evidence")
    for item in untracked_files:
        destination = repo / Path(str(item["path"]))
        if _sha(destination) != item.get("sha256") or destination.stat().st_size != item.get("bytes") or oct(destination.stat().st_mode & 0o777) != item.get("mode"):
            raise RuntimeError("restored untracked file integrity verification failed")
    journal.unlink(missing_ok=True)
    return {"ok": True, "phase": "VERIFIED", "repo": str(repo.resolve()), "status": actual_status}


def _rollback_failed_restore(
    repo: Path,
    repository: dict[str, Any],
    expected_status: str,
    untracked_files: list[dict[str, Any]],
    journal: Path,
) -> None:
    concurrent: list[str] = []
    for item in untracked_files:
        relative = Path(str(item.get("path")))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            concurrent.append(str(relative))
            continue
        destination = repo / relative
        for temporary in destination.parent.glob(f".{destination.name}.restore.*.tmp"):
            if temporary.is_symlink() or not temporary.is_file():
                concurrent.append(str(temporary.relative_to(repo)))
            else:
                temporary.unlink()
        if not destination.exists() and not destination.is_symlink():
            continue
        if destination.is_file() and not destination.is_symlink():
            try:
                matches = _sha(destination) == item.get("sha256") and oct(destination.stat().st_mode & 0o777) == item.get("mode")
            except OSError:
                matches = False
            if matches:
                destination.unlink()
            else:
                concurrent.append(str(relative))
        else:
            concurrent.append(str(relative))
    subprocess.run(["git", "reset", "--hard", str(repository["baselineHead"])], cwd=repo, check=True, capture_output=True)
    preservation_status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if concurrent or preservation_status != expected_status or _git_value(repo, "rev-parse", "HEAD") != repository["baselineHead"]:
        raise RuntimeError("restore failed and target rollback could not be verified")
    journal.unlink(missing_ok=True)


def _restore_status(repo: Path) -> str:
    return subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def restore_git_preservation(manifest_path: Path, repo: Path, *, mode: str) -> dict[str, Any]:
    """Rehearse in a local clone or apply only to an exact clean target repo."""

    if mode not in {"rehearse", "apply"}:
        raise ValueError("restore mode must be rehearse or apply")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _verify(manifest)
    _validate_file_inventory(manifest, include_target=False)
    preservation = manifest.get("gitPreservation")
    repository = preservation.get("repository") if isinstance(preservation, dict) else None
    if not isinstance(repository, dict):
        raise RuntimeError("git preservation repository identity is missing")
    source_repo = Path(str(repository["root"])).resolve()
    if mode == "apply":
        if repo.resolve() != source_repo:
            raise RuntimeError("apply restore requires the exact repository identity")
        _restore_preflight(repo, repository, require_identity=True, require_clean=True, check_origin=True)
        journal = repo.parent / f".{repo.name}.oss-pr-radar-restore.json"
        with tempfile.TemporaryDirectory(prefix="oss-pr-radar-restore-stage-", dir=repo.parent) as directory:
            staging = Path(directory) / "repo"
            subprocess.run(["git", "clone", "--local", "--no-hardlinks", str(repo), str(staging)], check=True, capture_output=True, text=True)
            _restore_preflight(staging, repository, require_identity=False, require_clean=True, check_origin=False)
            _apply_preservation_to_repo(staging, manifest, Path(directory) / "stage-journal.json")
            expected_status = _restore_status(repo)
            try:
                _apply_preservation_to_repo(repo, manifest, journal)
            except Exception:
                untracked = preservation.get("untrackedFiles") if isinstance(preservation.get("untrackedFiles"), list) else []
                _rollback_failed_restore(repo, repository, expected_status, untracked, journal)
                raise
        return {"ok": True, "phase": "VERIFIED", "mode": "apply", "repo": str(repo.resolve()), "status": str(repository.get("status") or "")}
    _restore_preflight(source_repo, repository, require_identity=True, require_clean=False)
    with tempfile.TemporaryDirectory(prefix="oss-pr-radar-restore-") as directory:
        clone = Path(directory) / "repo"
        subprocess.run(["git", "clone", "--local", "--no-hardlinks", str(source_repo), str(clone)], check=True, capture_output=True, text=True)
        _restore_preflight(clone, repository, require_identity=False, require_clean=True, check_origin=False)
        return _apply_preservation_to_repo(clone, manifest, Path(directory) / "restore-journal.json") | {"mode": "rehearse"}


def status(runtime_root: Path) -> dict[str, Any]:
    binding = bind_runtime(runtime_root)
    state = runtime_root.resolve() / "state"
    relative, digest = _pointer_target(state)
    manifests = sorted(str(path) for path in (runtime_root / "reports" / "stage7").glob("*.json"))
    return {
        "ok": True,
        "release": {"releaseId": binding.release_id, "manifestSha256": binding.release.get("manifestSha256")},
        "pointer": {"path": str(state / POINTER_NAME), "target": relative, "sha256": digest},
        "retainedLedgerVersions": sorted(str(path.relative_to(state)) for path in (state / VERSIONS_DIR).glob("*.sqlite3")),
        "manifests": manifests,
    }
