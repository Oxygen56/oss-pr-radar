"""Shared immutable-release and runtime-root binding primitives.

Deployed commands use this module from the active release itself.  Runtime
state is deliberately passed separately and is never used as a code search
path.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

RELEASE_POINTER = "current-release"
RELEASES = "releases"
MANIFEST = "release-manifest.json"
PRESERVED_ROOTS = {".git", ".venv", "reports", "state", RELEASES}
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def runtime_root_digest(runtime_root: Path) -> str:
    """Stable binding digest shared by signed runtime evidence producers."""

    return hashlib.sha256(_canonical(str(runtime_root.resolve()))).hexdigest()


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

    release = release.resolve()
    manifest_path = release / MANIFEST
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        raise RuntimeError("release manifest is invalid")
    expected_digest = hashlib.sha256(
        _canonical(
            {
                key: item
                for key, item in value.items()
                if key not in {"manifestSha256", "releaseId"}
            }
        )
    ).hexdigest()
    if value.get("manifestSha256") != expected_digest:
        raise RuntimeError("release manifest digest mismatch")
    for item in value["files"]:
        if not isinstance(item, dict):
            raise RuntimeError("release manifest file entry is invalid")
        relative = _safe_relative(item.get("path"))
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
    runtime_root = runtime_root.resolve()
    pointer = runtime_root / RELEASE_POINTER
    if not pointer.is_symlink():
        raise RuntimeError("active release pointer is missing")
    release = pointer.resolve()
    if release.parent != (runtime_root / RELEASES).resolve():
        raise RuntimeError("active release escapes the release directory")
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

    runtime_root = runtime_root.resolve()
    try:
        active, manifest = active_release(runtime_root)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        if not (allow_unreleased_code and code_root is not None):
            raise
        explicit = code_root.resolve()
        if not explicit.is_dir() or not (explicit / "src").is_dir() or not (explicit / "scripts").is_dir():
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
    state = runtime_root.resolve() / "state"
    pointer = state / "current-ledger"
    if pointer.is_symlink():
        return pointer.resolve()
    return state / "radar_ledger.sqlite3"
