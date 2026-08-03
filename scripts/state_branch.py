#!/usr/bin/env python3
"""Persist scanner state on a dedicated Git branch without polluting main."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

FILES = {
    "seen.json": Path("state/seen.json"),
    "runtime.json": Path("state/runtime.json"),
    "llm_cache.json": Path("state/llm_cache.json"),
}


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


def restore(root: Path, branch: str) -> None:
    fetched = git("fetch", "origin", branch, cwd=root, check=False)
    if fetched.returncode != 0:
        return
    for remote_name, destination in FILES.items():
        result = git("show", f"FETCH_HEAD:{remote_name}", cwd=root, check=False)
        if result.returncode == 0:
            target = root / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(result.stdout, encoding="utf-8")


def publish(root: Path, branch: str) -> None:
    available = {
        remote_name: root / source
        for remote_name, source in FILES.items()
        if (root / source).exists()
    }
    if not available:
        return
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
        fetched = git("fetch", "origin", branch, cwd=work, check=False)
        if fetched.returncode == 0:
            git("checkout", "-B", branch, "FETCH_HEAD", cwd=work)
        else:
            git("checkout", "--orphan", branch, cwd=work)
        for remote_name, source in available.items():
            shutil.copy2(source, work / remote_name)
        git("add", *available.keys(), cwd=work)
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
        git("push", "origin", f"HEAD:{branch}", cwd=work)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("restore", "publish"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--branch", default="radar-state")
    args = parser.parse_args()
    if args.operation == "restore":
        restore(args.root.resolve(), args.branch)
    else:
        publish(args.root.resolve(), args.branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
