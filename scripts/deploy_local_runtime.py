#!/usr/bin/env python3
"""Build and activate immutable local Radar releases."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.independent_review import migrate_legacy_review_state  # noqa: E402
from oss_pr_radar.operational_auth import (  # noqa: E402
    revoke_operational_authorization,
    worker_staging_transaction_lock,
)
from oss_pr_radar.release_binding import (  # noqa: E402
    MANIFEST,
    PRESERVED_ROOTS,
    RELEASE_POINTER,
    RELEASES,
    active_release,
    validate_runtime_layout,
    verify_release,
)
from oss_pr_radar.runtime import activate_release_pointer  # noqa: E402

LOCAL_RUNTIME_IGNORE_PATTERNS = (
    "/current-release",
    "/releases/",
    "/reports/",
    "/state/",
    "/.venv/",
)
DURABLE_REVIEW_STATE_CAPABILITY = "durable-independent-review-state-v1"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def tracked_files(source: Path) -> set[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=source,
        check=True,
        capture_output=True,
    )
    files: set[Path] = set()
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("tracked path escapes the source repository")
        if relative.parts[0] in PRESERVED_ROOTS or relative.name == MANIFEST:
            continue
        files.add(relative)
    return files


def require_clean_source(source: Path) -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if status:
        raise RuntimeError("refusing deployment from a dirty source repository")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _git_info_exclude(target: Path) -> Path:
    """Return the target repository's private exclude file."""

    raw = subprocess.run(
        ["git", "rev-parse", "--git-path", "info/exclude"],
        cwd=target,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not raw:
        raise RuntimeError("Git did not provide an info/exclude path")
    path = Path(raw)
    if not path.is_absolute():
        path = target / path
    if path.is_symlink():
        raise RuntimeError("refusing to modify a symlinked Git info/exclude")
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _ensure_runtime_ignored(target: Path) -> Path:
    """Ignore deployment-owned runtime paths without touching tracked files."""

    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", RELEASE_POINTER, RELEASES],
        cwd=target,
        check=True,
        capture_output=True,
    ).stdout
    if tracked.rstrip(b"\0"):
        raise RuntimeError("target repository tracks a deployment-owned runtime path")

    exclude = _git_info_exclude(target)
    existing = exclude.read_bytes() if exclude.exists() else b""
    existing_lines = existing.decode("utf-8", errors="strict").splitlines()
    additions = [
        pattern for pattern in LOCAL_RUNTIME_IGNORE_PATTERNS if pattern not in existing_lines
    ]
    if not additions:
        return exclude

    separator = b"" if not existing or existing.endswith((b"\n", b"\r")) else b"\n"
    payload = existing + separator + "\n".join(additions).encode("utf-8") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{exclude.name}.", suffix=".tmp", dir=exclude.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, exclude)
    finally:
        temporary.unlink(missing_ok=True)
    return exclude


def _file_entry(source: Path, relative: Path) -> dict[str, object]:
    current = source
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise RuntimeError(f"tracked path component is a symlink: {relative}")
    path = source / relative
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"tracked runtime path is not a regular file: {relative}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"path": str(relative), "bytes": path.stat().st_size, "sha256": digest}


def _policy_digest(files: list[dict[str, object]]) -> str:
    policy_files = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in files
        if str(item.get("path") or "").startswith(("src/oss_pr_radar/", "scripts/"))
    ]
    return hashlib.sha256(_canonical(policy_files)).hexdigest()


def build_manifest(source: Path, files: set[Path], commit: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": "oss_pr_radar_release_v1",
        "commit": commit,
        "capabilities": [DURABLE_REVIEW_STATE_CAPABILITY],
        "files": [_file_entry(source, relative) for relative in sorted(files)],
    }
    payload["policyDigest"] = _policy_digest(payload["files"])
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload | {
        "manifestSha256": digest,
        "releaseId": f"{commit[:12]}-{digest[:12]}",
    }


def _release_identity(manifest: dict[str, object]) -> tuple[object, ...]:
    """Return the immutable identity to which runtime authorizations bind."""

    return tuple(
        manifest.get(field) for field in ("releaseId", "manifestSha256", "commit", "policyDigest")
    )


def _active_release_identity(target: Path) -> tuple[object, ...] | None:
    pointer = target / RELEASE_POINTER
    if not pointer.exists() and not pointer.is_symlink():
        return None
    _release, manifest = active_release(target)
    return _release_identity(manifest)


def activate_release(target: Path, release_id: str) -> dict[str, object]:
    """Verify and activate an existing immutable release for rollback."""

    target, releases, _state = validate_runtime_layout(target, create_state=True)
    release = releases / release_id
    if release.parent != releases:
        raise RuntimeError("release path escapes the runtime releases directory")
    manifest = verify_release(release)
    if manifest.get("releaseId") != release_id:
        raise RuntimeError("release directory does not match its manifest")
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, list) or DURABLE_REVIEW_STATE_CAPABILITY not in capabilities:
        raise RuntimeError(
            "release predates durable independent-review state and cannot be safely activated"
        )
    release_metadata = os.lstat(release)
    if not os.path.isdir(release) or os.path.islink(release):
        raise RuntimeError("release activation target must be a real directory")
    migrate_legacy_review_state(target)
    # The staging lock covers the complete identity check and pointer switch.
    # Revoke before changing the pointer so a failed activation cannot expose a
    # new release alongside credentials bound to the previous release.
    with worker_staging_transaction_lock(target):
        if _active_release_identity(target) != _release_identity(manifest):
            revoke_operational_authorization(target, _lock_held=True)
        activate_release_pointer(
            target,
            release,
            manifest,
            expected_release_identity=(release_metadata.st_dev, release_metadata.st_ino),
        )
    return manifest


def create_release(source: Path, target: Path) -> dict[str, object]:
    source = source.absolute()
    target = target.absolute()
    if source == target or source in target.parents or target in source.parents:
        raise RuntimeError("source and target repositories must be independent")
    if not (source / ".git").exists() or not (target / ".git").exists():
        raise RuntimeError("source and target must both be Git repositories")

    commit = require_clean_source(source)
    target, releases, _state = validate_runtime_layout(
        target, create_releases=True, create_state=True
    )
    files = tracked_files(source)
    manifest = build_manifest(source, files, commit)
    release = releases / str(manifest["releaseId"])
    reused = release.exists()
    if reused:
        verify_release(release)
    _ensure_runtime_ignored(target)
    validate_runtime_layout(target, create_releases=False, create_state=True)
    if not reused:
        temporary = release.parent / f".{release.name}.{os.getpid()}.tmp"
        shutil.rmtree(temporary, ignore_errors=True)
        temporary.mkdir(parents=True)
        for relative in sorted(files):
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)
        (temporary / MANIFEST).write_bytes(
            json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8")
            + b"\n"
        )
        os.chmod(temporary / MANIFEST, 0o600)
        verify_release(temporary, require_directory_identity=False)
        temporary.replace(release)
    activate_release(target, str(manifest["releaseId"]))
    return {
        "ok": True,
        "releaseId": manifest["releaseId"],
        "releasePath": str(release),
        "commit": commit,
        "manifestSha256": manifest["manifestSha256"],
        "reused": reused,
        "activePointer": str(target / RELEASE_POINTER),
        "preservedRoots": sorted(PRESERVED_ROOTS),
    }


def deploy(source: Path, target: Path) -> dict[str, object]:
    """Compatibility entry point: deploy now always means immutable release."""

    return create_release(source, target)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(deploy(args.source, args.target), sort_keys=True))


if __name__ == "__main__":
    main()
