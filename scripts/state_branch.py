#!/usr/bin/env python3
"""Integrity-checked checkpoint storage on the dedicated radar-state branch."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_snapshot import validate_snapshot  # noqa: E402
from oss_pr_radar.outbound_pause import (  # noqa: E402
    outbound_effect_guard,
)
from oss_pr_radar.release_binding import runtime_ledger_path  # noqa: E402

FILES = {
    "seen.json": Path("state/seen.json"),
    "runtime.json": Path("state/runtime.json"),
    "llm_cache.json": Path("state/llm_cache.json"),
    "repo_cache.json": Path("state/repo_cache.json"),
    "dispatch_queue.json": Path("state/dispatch_queue.json"),
    "notification_outbox.json": Path("state/notification_outbox.json"),
    "war_room_codex_outbox.json": Path("state/war_room_codex_outbox.json"),
    "watchlist.json": Path("state/watchlist.json"),
    "health.json": Path("state/health.json"),
    "pending_rechecks.json": Path("state/pending_rechecks.json"),
    "pr_followup.json": Path("state/pr_followup.json"),
    "managed_lifecycle.snapshot.json.gz": Path("state/managed_lifecycle.snapshot.json.gz"),
}
MANIFEST = "state_manifest.json"
BASE_SHA = Path("state/base_sha.txt")
MANIFEST_VERSION = "radar_state_v2"
CONTROLLER_FEEDBACK_FILES = {
    "controller_terminal_feedback.json": Path("state/controller_terminal_feedback.json"),
    "controller_decision_feedback.json": Path("state/controller_decision_feedback.json"),
}
CONTROLLER_FEEDBACK_MANIFEST = "controller_feedback_manifest.json"
CONTROLLER_FEEDBACK_BASE_SHA = Path("state/controller_feedback_base_sha.txt")
CONTROLLER_FEEDBACK_MANIFEST_VERSION = "radar_controller_feedback_v1"
PROFILES = {
    "radar": {
        "branch": "radar-state",
        "files": FILES,
        "manifest": MANIFEST,
        "base_sha": BASE_SHA,
        "manifest_version": MANIFEST_VERSION,
    },
    "controller-feedback": {
        "branch": "radar-controller-feedback",
        "files": CONTROLLER_FEEDBACK_FILES,
        "manifest": CONTROLLER_FEEDBACK_MANIFEST,
        "base_sha": CONTROLLER_FEEDBACK_BASE_SHA,
        "manifest_version": CONTROLLER_FEEDBACK_MANIFEST_VERSION,
    },
}

_OUTBOUND_LOCK_FD: int | None = None


def isolated_state_ref(branch: str) -> str:
    if (
        not re.fullmatch(r"[A-Za-z0-9._/-]+", branch)
        or branch.startswith("/")
        or branch.endswith("/")
        or ".." in branch
    ):
        raise ValueError("invalid state branch name")
    return "refs/oss-pr-radar/state/" + branch.replace("/", "--")


def git(
    *args: str,
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
        env={**os.environ, **(env or {})},
        pass_fds=(_OUTBOUND_LOCK_FD,) if _OUTBOUND_LOCK_FD is not None else (),
    )


def git_bytes(
    *args: str, cwd: Path | None = None, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        capture_output=True,
        pass_fds=(_OUTBOUND_LOCK_FD,) if _OUTBOUND_LOCK_FD is not None else (),
    )


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode_state_json(remote_name: str, raw: bytes) -> object:
    if remote_name.endswith(".json.gz"):
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise RuntimeError(f"compressed state file is invalid: {remote_name}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"state file contains invalid JSON: {remote_name}") from exc


def _scan_snapshot(value: object, *, key: str = "") -> None:
    forbidden = {
        "threadid",
        "thread_id",
        "worktreepath",
        "worktree_path",
        "absolutepath",
        "absolute_path",
        "private_text",
        "token",
        "secret",
        "password",
        "api_key",
    }
    if key.casefold().replace("-", "_") in forbidden:
        raise RuntimeError(f"managed snapshot contains forbidden field: {key}")
    if isinstance(value, dict):
        for child_key, child in value.items():
            _scan_snapshot(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            _scan_snapshot(child, key=key)
    elif isinstance(value, str):
        if value.startswith(("/", "file://", "\\\\")):
            raise RuntimeError("managed snapshot contains an absolute path")
        if any(
            re.search(pattern, value)
            for pattern in (
                r"ghp_[A-Za-z0-9]{20,}",
                r"github_pat_[A-Za-z0-9_]{20,}",
                r"Bearer [A-Za-z0-9._~-]{20,}",
                r"sk-[A-Za-z0-9]{20,}",
            )
        ):
            raise RuntimeError("managed snapshot contains a token-like value")


def _validate_state_file(
    remote_name: str,
    raw: bytes,
    *,
    allow_legacy_managed_snapshot: bool = False,
) -> None:
    value = _decode_state_json(remote_name, raw)
    if remote_name.endswith("managed_lifecycle.snapshot.json.gz"):
        if not isinstance(value, dict):
            raise RuntimeError("managed lifecycle snapshot schema is invalid")
        try:
            validate_snapshot(value, allow_legacy=allow_legacy_managed_snapshot)
        except ValueError as exc:
            raise RuntimeError(f"managed lifecycle snapshot integrity is invalid: {exc}") from exc
        _scan_snapshot(value)
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        for name, value in os.environ.items():
            if (
                value
                and len(value) >= 8
                and any(
                    marker in name.casefold()
                    for marker in ("token", "secret", "password", "api_key")
                )
                and value in serialized
            ):
                raise RuntimeError(f"managed snapshot contains environment secret: {name}")


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(value)
        temporary = Path(handle.name)
    temporary.replace(path)


def fetch_state_ref(root: Path, branch: str) -> tuple[str, subprocess.CompletedProcess[str]]:
    """Fetch a branch into a private ref without touching shared FETCH_HEAD."""

    ref = isolated_state_ref(branch)
    git("update-ref", "-d", ref, cwd=root, check=False)
    result = git(
        "fetch",
        "--no-write-fetch-head",
        "origin",
        f"+refs/heads/{branch}:{ref}",
        cwd=root,
        check=False,
    )
    return ref, result


def restore(
    root: Path,
    branch: str,
    *,
    allow_missing: bool = False,
    files: dict[str, Path] = FILES,
    manifest_name: str = MANIFEST,
    base_sha_path: Path = BASE_SHA,
    manifest_version: str = MANIFEST_VERSION,
) -> None:
    ref, fetched = fetch_state_ref(root, branch)
    if fetched.returncode != 0:
        if allow_missing:
            for source in files.values():
                (root / source).unlink(missing_ok=True)
            atomic_write(root / base_sha_path, b"")
            return
        raise RuntimeError(f"state branch fetch failed: {fetched.stderr[:300]}")
    sha = git("rev-parse", ref, cwd=root).stdout.strip()
    manifest_result = git_bytes("show", f"{ref}:{manifest_name}", cwd=root, check=False)
    if manifest_result.returncode != 0:
        raise RuntimeError("state manifest is missing; migrate the state branch first")
    try:
        manifest = json.loads(manifest_result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("state manifest is invalid") from exc
    if manifest.get("version") != manifest_version:
        raise RuntimeError("unsupported state manifest")
    listed = manifest.get("files") or {}
    for remote_name, metadata in listed.items():
        if remote_name not in files or not isinstance(metadata, dict):
            raise RuntimeError(f"unexpected state file: {remote_name}")
        result = git_bytes("show", f"{ref}:{remote_name}", cwd=root, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"state file is missing: {remote_name}")
        raw = result.stdout
        if digest_bytes(raw) != metadata.get("sha256"):
            raise RuntimeError(f"state file digest mismatch: {remote_name}")
        _validate_state_file(remote_name, raw, allow_legacy_managed_snapshot=True)
        atomic_write(root / files[remote_name], raw)
    for remote_name, source in files.items():
        if remote_name not in listed:
            (root / source).unlink(missing_ok=True)
    atomic_write(root / base_sha_path, sha.encode("ascii"))


def build_manifest(
    root: Path,
    available: dict[str, Path],
    *,
    manifest_version: str = MANIFEST_VERSION,
    allow_legacy_managed_snapshot: bool = False,
) -> dict[str, object]:
    files = {}
    for remote_name, source in available.items():
        raw = source.read_bytes()
        _validate_state_file(
            remote_name,
            raw,
            allow_legacy_managed_snapshot=allow_legacy_managed_snapshot,
        )
        files[remote_name] = {"sha256": digest_bytes(raw), "bytes": len(raw)}
    return {
        "version": manifest_version,
        "generatedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "runId": os.environ.get("RADAR_RUN_ID") or os.environ.get("GITHUB_RUN_ID", ""),
        "sourceSha": os.environ.get("GITHUB_SHA", ""),
        "files": files,
    }


def publish(
    root: Path,
    branch: str,
    *,
    files: dict[str, Path] = FILES,
    manifest_name: str = MANIFEST,
    base_sha_path: Path = BASE_SHA,
    manifest_version: str = MANIFEST_VERSION,
) -> None:
    available = {
        remote_name: root / source
        for remote_name, source in files.items()
        if (root / source).exists()
    }
    if not available:
        raise RuntimeError("no state files are available to publish")
    expected = (
        (root / base_sha_path).read_text(encoding="utf-8").strip()
        if (root / base_sha_path).exists()
        else ""
    )
    ref, fetched = fetch_state_ref(root, branch)
    actual = ""
    if fetched.returncode == 0:
        actual = git("rev-parse", ref, cwd=root).stdout.strip()
        if expected and actual != expected:
            raise RuntimeError("state branch changed since restore")
    elif expected:
        raise RuntimeError("authenticated state branch fetch failed")
    manifest = build_manifest(root, available, manifest_version=manifest_version)
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="oss-pr-radar-state-index-") as raw:
        temporary = Path(raw)
        index_env = {"GIT_INDEX_FILE": str(temporary / "index")}
        git("read-tree", "--empty", cwd=root, env=index_env)
        for remote_name, source in available.items():
            blob = git("hash-object", "-w", str(source), cwd=root).stdout.strip()
            git(
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                blob,
                remote_name,
                cwd=root,
                env=index_env,
            )
        manifest_path = temporary / manifest_name
        atomic_write(manifest_path, manifest_bytes)
        manifest_blob = git("hash-object", "-w", str(manifest_path), cwd=root).stdout.strip()
        git(
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            manifest_blob,
            manifest_name,
            cwd=root,
            env=index_env,
        )
        tree = git("write-tree", cwd=root, env=index_env).stdout.strip()

    parent = ("-p", actual) if actual else ()
    commit = git(
        "-c",
        "user.name=github-actions[bot]",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit-tree",
        tree,
        *parent,
        "-m",
        "Update radar state",
        cwd=root,
    ).stdout.strip()
    lease = f"--force-with-lease=refs/heads/{branch}:{actual}"
    git("push", lease, "origin", f"{commit}:refs/heads/{branch}", cwd=root)


def migrate(
    root: Path,
    branch: str,
    *,
    files: dict[str, Path] = FILES,
    manifest_name: str = MANIFEST,
    manifest_version: str = MANIFEST_VERSION,
) -> None:
    """Add or repair the v2 manifest without changing state JSON bytes."""

    ref, fetched = fetch_state_ref(root, branch)
    if fetched.returncode != 0:
        raise RuntimeError(f"state branch fetch failed: {fetched.stderr[:300]}")
    actual = git("rev-parse", ref, cwd=root).stdout.strip()
    available_raw: dict[str, bytes] = {}
    for remote_name in files:
        result = git_bytes("show", f"{ref}:{remote_name}", cwd=root, check=False)
        if result.returncode == 0:
            _validate_state_file(
                remote_name,
                result.stdout,
                allow_legacy_managed_snapshot=True,
            )
            available_raw[remote_name] = result.stdout
    if not available_raw:
        raise RuntimeError("legacy state branch has no recognized JSON state")

    expected_files = {
        name: {"sha256": digest_bytes(raw), "bytes": len(raw)}
        for name, raw in available_raw.items()
    }
    existing = git_bytes("show", f"{ref}:{manifest_name}", cwd=root, check=False)
    if existing.returncode == 0:
        try:
            manifest = json.loads(existing.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("state branch manifest is invalid") from exc
        if manifest.get("version") != manifest_version:
            raise RuntimeError("state branch has an unsupported manifest")
        if manifest.get("files") == expected_files:
            return
    with tempfile.TemporaryDirectory(prefix="oss-pr-radar-state-migration-") as raw:
        work = Path(raw)
        git("init", cwd=work)
        git(
            "remote",
            "add",
            "origin",
            git("remote", "get-url", "origin", cwd=root).stdout.strip(),
            cwd=work,
        )
        work_ref, work_fetched = fetch_state_ref(work, branch)
        if work_fetched.returncode != 0:
            raise RuntimeError(f"state branch migration fetch failed: {work_fetched.stderr[:300]}")
        git("checkout", "-B", branch, work_ref, cwd=work)
        available: dict[str, Path] = {}
        for remote_name, raw in available_raw.items():
            source = work / remote_name
            atomic_write(source, raw)
            available[remote_name] = source
        manifest = build_manifest(
            work,
            available,
            manifest_version=manifest_version,
            allow_legacy_managed_snapshot=True,
        )
        (work / manifest_name).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        git("add", manifest_name, cwd=work)
        git(
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit",
            "-m",
            "Migrate radar state integrity manifest",
            cwd=work,
        )
        git(
            "push",
            f"--force-with-lease=refs/heads/{branch}:{actual}",
            "origin",
            f"HEAD:{branch}",
            cwd=work,
        )


def main() -> int:
    global _OUTBOUND_LOCK_FD
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("restore", "publish", "migrate"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", choices=tuple(PROFILES), default="radar")
    parser.add_argument("--branch", default=None)
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    profile = PROFILES[args.profile]
    branch = args.branch or str(profile["branch"])
    options = {
        "files": profile["files"],
        "manifest_name": profile["manifest"],
        "manifest_version": profile["manifest_version"],
    }
    if args.operation == "restore":
        restore(
            args.root,
            branch,
            allow_missing=args.allow_missing,
            base_sha_path=profile["base_sha"],
            **options,
        )
    else:
        def write_state() -> None:
            if args.operation == "publish":
                publish(args.root, branch, base_sha_path=profile["base_sha"], **options)
            else:
                migrate(args.root, branch, **options)

        try:
            ledger_path = runtime_ledger_path(args.root)
        except (OSError, RuntimeError, ValueError):
            ledger_path = args.root.resolve() / "state" / "radar_ledger.sqlite3"
        with outbound_effect_guard(args.root, ledger_path) as effect_lock:
            _OUTBOUND_LOCK_FD = effect_lock.fileno()
            try:
                write_state()
            finally:
                _OUTBOUND_LOCK_FD = None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
