#!/usr/bin/env python3
"""Integrity-checked checkpoint storage on the dedicated radar-state branch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

FILES = {
    "seen.json": Path("state/seen.json"),
    "runtime.json": Path("state/runtime.json"),
    "llm_cache.json": Path("state/llm_cache.json"),
    "dispatch_queue.json": Path("state/dispatch_queue.json"),
    "notification_outbox.json": Path("state/notification_outbox.json"),
    "watchlist.json": Path("state/watchlist.json"),
    "health.json": Path("state/health.json"),
    "pending_rechecks.json": Path("state/pending_rechecks.json"),
    "pr_followup.json": Path("state/pr_followup.json"),
}
MANIFEST = "state_manifest.json"
BASE_SHA = Path("state/base_sha.txt")
MANIFEST_VERSION = "radar_state_v2"


def git(
    *args: str, cwd: Path | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        text=True,
        capture_output=True,
    )


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(value)
        temporary = Path(handle.name)
    temporary.replace(path)


def restore(root: Path, branch: str, *, allow_missing: bool = False) -> None:
    fetched = git("fetch", "origin", branch, cwd=root, check=False)
    if fetched.returncode != 0:
        if allow_missing:
            atomic_write(root / BASE_SHA, b"")
            return
        raise RuntimeError(f"state branch fetch failed: {fetched.stderr[:300]}")
    sha = git("rev-parse", "FETCH_HEAD", cwd=root).stdout.strip()
    manifest_result = git("show", f"FETCH_HEAD:{MANIFEST}", cwd=root, check=False)
    if manifest_result.returncode != 0:
        raise RuntimeError("state manifest is missing; migrate the state branch first")
    try:
        manifest = json.loads(manifest_result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("state manifest is invalid") from exc
    if manifest.get("version") != MANIFEST_VERSION:
        raise RuntimeError("unsupported state manifest")
    listed = manifest.get("files") or {}
    for remote_name, metadata in listed.items():
        if remote_name not in FILES or not isinstance(metadata, dict):
            raise RuntimeError(f"unexpected state file: {remote_name}")
        result = git("show", f"FETCH_HEAD:{remote_name}", cwd=root, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"state file is missing: {remote_name}")
        raw = result.stdout.encode("utf-8")
        if digest_bytes(raw) != metadata.get("sha256"):
            raise RuntimeError(f"state file digest mismatch: {remote_name}")
        try:
            json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"state file contains invalid JSON: {remote_name}") from exc
        atomic_write(root / FILES[remote_name], raw)
    atomic_write(root / BASE_SHA, sha.encode("ascii"))


def build_manifest(root: Path, available: dict[str, Path]) -> dict[str, object]:
    files = {}
    for remote_name, source in available.items():
        raw = source.read_bytes()
        json.loads(raw)
        files[remote_name] = {"sha256": digest_bytes(raw), "bytes": len(raw)}
    return {
        "version": MANIFEST_VERSION,
        "generatedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "runId": os.environ.get("RADAR_RUN_ID")
        or os.environ.get("GITHUB_RUN_ID", ""),
        "sourceSha": os.environ.get("GITHUB_SHA", ""),
        "files": files,
    }


def publish(root: Path, branch: str) -> None:
    available = {
        remote_name: root / source
        for remote_name, source in FILES.items()
        if (root / source).exists()
    }
    if not available:
        raise RuntimeError("no state files are available to publish")
    expected = (root / BASE_SHA).read_text(encoding="utf-8").strip() if (root / BASE_SHA).exists() else ""
    manifest = build_manifest(root, available)
    with tempfile.TemporaryDirectory(prefix="oss-pr-radar-state-") as raw:
        work = Path(raw)
        git("init", cwd=work)
        git(
            "remote",
            "add",
            "origin",
            git("remote", "get-url", "origin", cwd=root).stdout.strip(),
            cwd=work,
        )
        auth = git(
            "config",
            "--local",
            "--get-regexp",
            r"^http\..*\.extraheader$",
            cwd=root,
            check=False,
        )
        for line in auth.stdout.splitlines():
            key, separator, value = line.partition(" ")
            if separator and key and value:
                git("config", "--local", key, value, cwd=work)
        fetched = git("fetch", "origin", branch, cwd=work, check=False)
        actual = ""
        if fetched.returncode == 0:
            actual = git("rev-parse", "FETCH_HEAD", cwd=work).stdout.strip()
            if expected and actual != expected:
                raise RuntimeError("state branch changed since restore")
            git("checkout", "-B", branch, "FETCH_HEAD", cwd=work)
        elif expected:
            raise RuntimeError("expected state branch no longer exists")
        else:
            git("checkout", "--orphan", branch, cwd=work)
        for remote_name, source in available.items():
            shutil.copy2(source, work / remote_name)
        (work / MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        git("add", *available.keys(), MANIFEST, cwd=work)
        if git("diff", "--cached", "--quiet", cwd=work, check=False).returncode == 0:
            return
        git(
            "-c",
            "user.name=github-actions[bot]",
            "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit",
            "-m",
            "Update radar state",
            cwd=work,
        )
        push = ["push", "origin", f"HEAD:{branch}"]
        if actual:
            push.insert(1, f"--force-with-lease=refs/heads/{branch}:{actual}")
        git(*push, cwd=work)


def migrate(root: Path, branch: str) -> None:
    """Add the v2 integrity manifest to a legacy state branch without rewriting state."""

    fetched = git("fetch", "origin", branch, cwd=root, check=False)
    if fetched.returncode != 0:
        raise RuntimeError(f"state branch fetch failed: {fetched.stderr[:300]}")
    actual = git("rev-parse", "FETCH_HEAD", cwd=root).stdout.strip()
    existing = git("show", f"FETCH_HEAD:{MANIFEST}", cwd=root, check=False)
    if existing.returncode == 0:
        manifest = json.loads(existing.stdout)
        if manifest.get("version") != MANIFEST_VERSION:
            raise RuntimeError("state branch has an unsupported manifest")
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
        git("fetch", "origin", branch, cwd=work)
        git("checkout", "-B", branch, "FETCH_HEAD", cwd=work)
        available: dict[str, Path] = {}
        for remote_name in FILES:
            source = work / remote_name
            if not source.exists():
                continue
            json.loads(source.read_text(encoding="utf-8"))
            available[remote_name] = source
        if not available:
            raise RuntimeError("legacy state branch has no recognized JSON state")
        manifest = build_manifest(work, available)
        (work / MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        git("add", MANIFEST, cwd=work)
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
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("restore", "publish", "migrate"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--branch", default="radar-state")
    parser.add_argument("--allow-missing", action="store_true")
    args = parser.parse_args()
    if args.operation == "restore":
        restore(args.root, args.branch, allow_missing=args.allow_missing)
    elif args.operation == "publish":
        publish(args.root, args.branch)
    else:
        migrate(args.root, args.branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
