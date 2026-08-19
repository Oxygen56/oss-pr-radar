"""Build-only helper for a thin non-git automation copy.

The helper is intentionally not called by the controller.  A caller must name
both source and target directories explicitly, and the manifest records the
source commit for later audit or rollback.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .managed_security import sign_current, verify_current_or_previous
from .util import canonical_json

DEPLOY_SCHEMA = "oss-pr-radar.war-room-copy.v1"
ENTRYPOINT = "war_room_entrypoint.py"
FORBIDDEN_ENTRYPOINT_MARKERS = (
    b"build_notification_outbox",
    b"send_notification_outbox",
    b"subprocess",
    b"FeishuClient",
)


def _source_commit(source: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True
    ).stdout.strip()


def _git(source: Path, *args: str, text: bool = False) -> bytes | str:
    result = subprocess.run(["git", *args], cwd=source, check=True, capture_output=True, text=text)
    return result.stdout if text else result.stdout


def _git_object(source: Path, commit: str, relative: Path) -> bytes:
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("deployment path traversal is forbidden")
    spec = f"{commit}:{relative.as_posix()}"
    kind = str(_git(source, "cat-file", "-t", spec, text=True)).strip()
    if kind != "blob":
        raise ValueError("deployment source entry must be a regular git blob")
    tree_entry = str(_git(source, "ls-tree", commit, "--", relative.as_posix(), text=True)).strip()
    mode = tree_entry.split(maxsplit=1)[0] if tree_entry else ""
    if mode != "100644":
        raise ValueError("deployment source entry must be a regular git blob")
    return bytes(_git(source, "show", spec))


def _manifest_unsigned(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in manifest.items()
        if key not in {"manifestDigest", "manifestKeyId", "manifestSignature"}
    }


def _manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(_manifest_unsigned(manifest)).encode()).hexdigest()


def _relative_files(target: Path) -> list[Path]:
    result: list[Path] = []
    for path in target.rglob("*"):
        if path.name == "war-room-copy-manifest.json":
            continue
        if path.is_symlink() or not path.is_file():
            if path.is_symlink() or not path.is_dir():
                raise ValueError("deployment copy contains a symlink or special file")
            continue
        result.append(path.relative_to(target))
    return sorted(result, key=lambda path: path.as_posix())


def verify_copy(target: Path, manifest: dict[str, Any]) -> None:
    if target.is_symlink():
        raise ValueError("deployment target must not be a symlink")
    target = target.resolve()
    if manifest.get("schema") != DEPLOY_SCHEMA:
        raise ValueError("invalid deployment manifest")
    source_commit = str(manifest.get("sourceCommit") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("deployment manifest source commit is invalid")
    if manifest.get("manifestDigest") != _manifest_digest(manifest):
        raise ValueError("deployment manifest digest mismatch")
    unsigned = {**_manifest_unsigned(manifest), "manifestDigest": manifest["manifestDigest"]}
    if not verify_current_or_previous(
        unsigned,
        context="war-room-copy-v1",
        key_id=manifest.get("manifestKeyId"),
        signature=manifest.get("manifestSignature"),
    ):
        raise ValueError("deployment manifest authentication failed")
    manifest_path = target / "war-room-copy-manifest.json"
    try:
        on_disk = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise ValueError("deployment manifest file is missing or invalid") from exc
    if on_disk != manifest:
        raise ValueError("deployment manifest file does not match authenticated manifest")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("deployment manifest file list is missing")
    expected_paths: list[Path] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("deployment manifest file entry is invalid")
        relative = Path(str(entry.get("path") or ""))
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or relative.as_posix() == "war-room-copy-manifest.json"
        ):
            raise ValueError("deployment manifest path traversal")
        expected_paths.append(relative)
    if len(set(expected_paths)) != len(expected_paths):
        raise ValueError("deployment manifest contains duplicate files")
    if sorted(expected_paths, key=lambda path: path.as_posix()) != _relative_files(target):
        raise ValueError("deployment copy file list does not match manifest")
    for entry, relative in zip(entries, expected_paths, strict=True):
        path = target / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("deployment copy entry is missing or symlinked")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry.get("sha256"):
            raise ValueError("deployment copy byte digest mismatch")


def build_copy(source: Path, target: Path, *, source_commit: str | None = None) -> dict[str, Any]:
    """Create an explicit non-git copy without activating or deploying it."""

    if source.is_symlink() or target.is_symlink():
        raise ValueError("deployment source and target must not be symlinks")
    source = source.resolve()
    target = target.resolve()
    if source == target:
        raise ValueError("deployment source and target must differ")
    status = str(_git(source, "status", "--porcelain", "--untracked-files=all", text=True))
    if status.strip():
        raise RuntimeError("deployment source worktree must be clean")
    head = _source_commit(source)
    commit = source_commit or head
    if commit != head:
        raise ValueError("deployment source commit does not match HEAD")
    relative_files = (Path("scripts") / ENTRYPOINT,)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        temporary.unlink()
        temporary.mkdir(parents=True)
        entries = []
        for relative in relative_files:
            content = _git_object(source, commit, relative)
            if any(marker in content for marker in FORBIDDEN_ENTRYPOINT_MARKERS):
                raise ValueError("thin copy entrypoint contains a legacy executor")
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            entries.append({"path": str(relative), "sha256": hashlib.sha256(content).hexdigest()})
        manifest = {
            "schema": DEPLOY_SCHEMA,
            "sourceCommit": commit,
            "files": entries,
        }
        manifest["manifestDigest"] = _manifest_digest(manifest)
        manifest_auth = sign_current(
            {**_manifest_unsigned(manifest), "manifestDigest": manifest["manifestDigest"]},
            context="war-room-copy-v1",
        )
        if not manifest_auth["keyId"] or not manifest_auth["signature"]:
            raise PermissionError("deployment manifest signing key is unavailable")
        manifest["manifestKeyId"] = manifest_auth["keyId"]
        manifest["manifestSignature"] = manifest_auth["signature"]
        (temporary / "war-room-copy-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)
        temporary = Path()
        verify_copy(target, manifest)
        return {"ok": True, "target": str(target), "sourceCommit": commit, "manifest": manifest}
    finally:
        if temporary != Path() and temporary.exists():
            shutil.rmtree(temporary)
