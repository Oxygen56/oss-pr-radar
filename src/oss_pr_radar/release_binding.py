"""Shared immutable-release and runtime-root binding primitives.

Deployed commands use this module from the active release itself.  Runtime
state is deliberately passed separately and is never used as a code search
path.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

RELEASE_POINTER = "current-release"
RELEASES = "releases"
MANIFEST = "release-manifest.json"
PRESERVED_ROOTS = {".git", ".venv", "reports", "state", RELEASES}
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _absolute(path: Path) -> Path:
    """Return a lexical absolute path without following symlinks."""

    return Path(path).absolute()


def _path_from_directory_fd(descriptor: int, *, label: str) -> Path:
    """Resolve a directory path from its opened identity, never its source name."""

    if hasattr(fcntl, "F_GETPATH"):
        buffer = b"\0" * 1024
        try:
            result = fcntl.fcntl(descriptor, fcntl.F_GETPATH, buffer)
        except (OSError, TypeError) as exc:
            raise RuntimeError(f"{label} identity cannot be resolved") from exc
        raw = result if isinstance(result, bytes) else bytes(buffer)
    else:
        try:
            raw = os.readlink(f"/proc/self/fd/{descriptor}").encode()
        except OSError as exc:
            raise RuntimeError(f"{label} identity cannot be resolved") from exc
    raw = raw.split(b"\0", 1)[0]
    if not raw:
        raise RuntimeError(f"{label} identity is empty")
    return Path(os.fsdecode(raw))


def open_directory_handle(
    path: Path, *, label: str, create: bool = False, required_mode: int | None = None
) -> tuple[int, Path]:
    """Open a validated directory and return its fd plus canonical path."""

    path = _absolute(path)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise RuntimeError(f"{label} is missing") from None
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"{label} must be a real directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.getuid():
            raise RuntimeError(f"{label} has unsafe ownership")
        if stat.S_IMODE(opened.st_mode) & 0o022:
            raise RuntimeError(f"{label} has unsafe permissions")
        if required_mode is not None and stat.S_IMODE(opened.st_mode) != required_mode:
            os.fchmod(descriptor, required_mode)
            opened = os.fstat(descriptor)
            if stat.S_IMODE(opened.st_mode) != required_mode:
                raise RuntimeError(f"{label} mode could not be secured")
        canonical = _path_from_directory_fd(descriptor, label=label)
        try:
            rebound = os.stat(canonical, follow_symlinks=False)
            current = os.lstat(path)
        except OSError as exc:
            raise RuntimeError(f"{label} changed during validation") from exc
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or (rebound.st_dev, rebound.st_ino) != (opened.st_dev, opened.st_ino)
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeError(f"{label} changed during validation")
        return descriptor, canonical
    except Exception:
        os.close(descriptor)
        raise


def _safe_directory(
    path: Path, *, label: str, create: bool = False, required_mode: int | None = None
) -> Path:
    descriptor, canonical = open_directory_handle(
        path, label=label, create=create, required_mode=required_mode
    )
    os.close(descriptor)
    return canonical


def validate_runtime_layout(
    runtime_root: Path, *, create_releases: bool = False, create_state: bool = False
) -> tuple[Path, Path, Path]:
    """Validate the runtime root and its two security-sensitive directories.

    This intentionally works on lexical paths and lstat metadata before any
    resolve call. A runtime root, releases directory, or state directory that
    is replaced with a symlink is therefore rejected instead of followed.
    """

    root = _safe_directory(runtime_root, label="runtime root")
    releases_path = _absolute(root / RELEASES)
    state_path = _absolute(root / "state")
    releases_missing = False
    try:
        os.lstat(releases_path)
    except FileNotFoundError:
        releases_missing = True
        releases = releases_path
    else:
        releases = _safe_directory(
            releases_path,
            label="runtime releases",
            create=create_releases,
            required_mode=0o700,
        )
    state_missing = False
    try:
        os.lstat(state_path)
    except FileNotFoundError:
        state_missing = True
        state = state_path
    else:
        state = _safe_directory(
            state_path, label="runtime state", create=create_state, required_mode=0o700
        )
    # Validate all pre-existing components before creating either missing one,
    # so a rejected sibling symlink leaves no deployment-owned side effect.
    if releases_missing:
        if not create_releases:
            releases = releases_path
        else:
            releases = _safe_directory(
                releases_path, label="runtime releases", create=True, required_mode=0o700
            )
    if state_missing:
        if not create_state:
            state = state_path
        else:
            state = _safe_directory(
                state_path, label="runtime state", create=True, required_mode=0o700
            )
    return root, releases, state


def validate_runtime_file(path: Path, *, label: str, mode: int = 0o600) -> Path:
    """Validate a private runtime file without following a symlink."""

    path = _absolute(path)
    _safe_directory(path.parent, label=f"{label} parent", required_mode=0o700)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        raise RuntimeError(f"{label} is missing") from None
    except OSError as exc:
        raise RuntimeError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"{label} must be a regular file")
    if metadata.st_uid != os.getuid():
        raise RuntimeError(f"{label} has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise RuntimeError(f"{label} must have mode {mode:o}")
    return path


def _validate_release_path(release: Path, *, label: str = "release") -> Path:
    release = _absolute(release)
    parent = _safe_directory(release.parent, label=f"{label} parent", required_mode=0o700)
    _safe_directory(release, label=label, required_mode=0o700)
    return parent / release.name


def _validate_release_relative_components(release: Path, relative: Path) -> None:
    current = release
    for component in relative.parts:
        current = current / component
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise RuntimeError(f"release path component is unavailable: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"release path component is a symlink: {relative}")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def runtime_root_digest(runtime_root: Path) -> str:
    """Stable binding digest shared by signed runtime evidence producers."""

    root = _safe_directory(runtime_root, label="runtime root")
    return hashlib.sha256(_canonical(str(root))).hexdigest()


def _safe_relative(value: object) -> Path:
    relative = Path(str(value))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeError("release manifest contains an unsafe path")
    if relative.parts[0] in PRESERVED_ROOTS or relative.name == MANIFEST:
        raise RuntimeError("release manifest contains a preserved path")
    return relative


def _policy_digest(files: list[dict[str, object]]) -> str:
    policy_files = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in files
        if str(item.get("path") or "").startswith(("src/oss_pr_radar/", "scripts/"))
    ]
    return hashlib.sha256(_canonical(policy_files)).hexdigest()


def verify_release(release: Path, *, require_directory_identity: bool = True) -> dict[str, object]:
    """Verify an immutable release without consulting runtime state."""

    release = _validate_release_path(release)
    manifest_path = release / MANIFEST
    try:
        manifest_metadata = os.lstat(manifest_path)
    except OSError as exc:
        raise RuntimeError("release manifest is unavailable") from exc
    if stat.S_ISLNK(manifest_metadata.st_mode) or not stat.S_ISREG(manifest_metadata.st_mode):
        raise RuntimeError("release manifest must be a regular file")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        raise RuntimeError("release manifest is invalid")
    expected_digest = hashlib.sha256(
        _canonical(
            {key: item for key, item in value.items() if key not in {"manifestSha256", "releaseId"}}
        )
    ).hexdigest()
    if value.get("manifestSha256") != expected_digest:
        raise RuntimeError("release manifest digest mismatch")
    for item in value["files"]:
        if not isinstance(item, dict):
            raise RuntimeError("release manifest file entry is invalid")
        relative = _safe_relative(item.get("path"))
        _validate_release_relative_components(release, relative)
        path = release / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"release file is missing: {relative}")
        if path.stat().st_size != int(item.get("bytes") or -1):
            raise RuntimeError(f"release file size changed: {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256"):
            raise RuntimeError(f"release file digest changed: {relative}")
    if value.get("policyDigest") != _policy_digest(value["files"]):
        raise RuntimeError("release policy digest mismatch")
    if not isinstance(value.get("commit"), str) or not _COMMIT_RE.fullmatch(value["commit"]):
        raise RuntimeError("release manifest commit is invalid")
    if require_directory_identity and value.get("releaseId") != release.name:
        raise RuntimeError("release directory does not match its manifest")
    return value


@dataclass(frozen=True)
class CodeIdentity:
    """The only accepted identity for versioned code execution."""

    root: Path
    commit: str
    kind: str


def _git_output(root: Path, *arguments: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *arguments], cwd=root, stderr=subprocess.STDOUT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("code root is neither a verified release nor a Git worktree") from exc


def resolve_code_identity(code_root: Path) -> CodeIdentity:
    """Resolve code identity without ever searching an ancestor repository."""

    root = code_root.resolve()
    manifest_path = root / MANIFEST
    if manifest_path.exists():
        manifest = verify_release(root)
        return CodeIdentity(root=root, commit=str(manifest["commit"]), kind="release")

    top_level = Path(_git_output(root, "rev-parse", "--show-toplevel")).resolve()
    if top_level != root:
        raise RuntimeError("development code root must be the exact Git top-level")
    status = _git_output(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise RuntimeError("development code root must be clean")
    commit = _git_output(root, "rev-parse", "HEAD")
    if not _COMMIT_RE.fullmatch(commit):
        raise RuntimeError("development Git HEAD is not a full commit SHA")
    return CodeIdentity(root=root, commit=commit, kind="development")


def require_stable_code_identity(code_root: Path, expected: CodeIdentity) -> CodeIdentity:
    """Re-verify code identity and fail if a long operation crossed a change."""

    actual = resolve_code_identity(code_root)
    if actual != expected:
        raise RuntimeError("code identity changed during Stage 6")
    return actual


def active_release(runtime_root: Path) -> tuple[Path, dict[str, object]]:
    runtime_root, releases, _state = validate_runtime_layout(runtime_root)
    releases = _safe_directory(releases, label="runtime releases")
    pointer = runtime_root / RELEASE_POINTER
    try:
        pointer_metadata = os.lstat(pointer)
    except OSError as exc:
        raise RuntimeError("active release pointer is missing") from exc
    if not stat.S_ISLNK(pointer_metadata.st_mode):
        raise RuntimeError("active release pointer is missing")
    release = pointer.resolve()
    if release.parent != releases:
        raise RuntimeError("active release escapes the release directory")
    _validate_release_path(release)
    return release, verify_release(release)


@dataclass(frozen=True)
class RuntimeBinding:
    runtime_root: Path
    code_root: Path
    release: dict[str, object]

    @property
    def release_id(self) -> str:
        return str(self.release["releaseId"])

    def script(self, relative: str) -> Path:
        path = (self.code_root / relative).resolve()
        if self.code_root not in path.parents or not path.is_file() or path.is_symlink():
            raise RuntimeError(f"release executable is unavailable: {relative}")
        return path


def bind_runtime(
    runtime_root: Path,
    *,
    code_root: Path | None = None,
    allow_unreleased_code: bool = False,
) -> RuntimeBinding:
    """Bind executable code to the exact active release.

    ``code_root`` is accepted for tests and development, but it must still be
    the active verified release.  There is intentionally no dirty-source
    fallback for deployed entrypoints.
    """

    runtime_root = _absolute(runtime_root)
    try:
        active, manifest = active_release(runtime_root)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        if not (allow_unreleased_code and code_root is not None):
            raise
        explicit = code_root.resolve()
        if (
            not explicit.is_dir()
            or not (explicit / "src").is_dir()
            or not (explicit / "scripts").is_dir()
        ):
            raise RuntimeError("explicit development code root is incomplete") from None
        return RuntimeBinding(
            runtime_root=runtime_root,
            code_root=explicit,
            release={
                "releaseId": "explicit-development-code-root",
                "manifestSha256": None,
                "policyDigest": None,
            },
        )
    if code_root is not None and code_root.resolve() != active:
        raise RuntimeError("explicit code root is not the active immutable release")
    return RuntimeBinding(runtime_root=runtime_root, code_root=active, release=manifest)


def runtime_python(runtime_root: Path) -> Path:
    candidate = runtime_root.resolve() / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else Path(sys.executable)


def runtime_ledger_path(runtime_root: Path) -> Path:
    runtime_root, _releases, state = validate_runtime_layout(runtime_root)
    pointer = state / "current-ledger"
    if pointer.is_symlink():
        return pointer.resolve()
    return state / "radar_ledger.sqlite3"
