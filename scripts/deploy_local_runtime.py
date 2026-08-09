#!/usr/bin/env python3
"""Deploy tracked controller code without touching durable local runtime state."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
MANIFEST = ".oss-pr-radar-runtime-manifest.json"
PRESERVED_ROOTS = {".git", ".venv", "reports", "state"}


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


def load_manifest(target: Path) -> set[Path]:
    path = target / MANIFEST
    if not path.exists():
        return set()
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        raise RuntimeError("runtime deployment manifest is invalid")
    files: set[Path] = set()
    for item in value["files"]:
        relative = Path(str(item))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise RuntimeError("runtime deployment manifest contains an unsafe path")
        if relative.parts[0] in PRESERVED_ROOTS or relative.name == MANIFEST:
            raise RuntimeError("runtime deployment manifest contains a preserved path")
        files.add(relative)
    return files


def write_manifest(target: Path, files: set[Path]) -> None:
    path = target / MANIFEST
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(
            {"version": "runtime_manifest_v1", "files": sorted(map(str, files))},
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def deploy(source: Path, target: Path) -> dict[str, object]:
    source = source.resolve()
    target = target.resolve()
    if source == target or source in target.parents or target in source.parents:
        raise RuntimeError("source and target repositories must be independent")
    if not (source / ".git").exists() or not (target / ".git").exists():
        raise RuntimeError("source and target must both be Git repositories")

    current = tracked_files(source)
    previous = load_manifest(target)
    removed: list[str] = []
    for relative in sorted(previous - current):
        destination = target / relative
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
            removed.append(str(relative))

    copied = 0
    for relative in sorted(current):
        source_path = source / relative
        destination = target / relative
        if source_path.is_symlink() or not source_path.is_file():
            raise RuntimeError(f"tracked runtime path is not a regular file: {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
        copied += 1
    write_manifest(target, current)
    return {
        "ok": True,
        "copied": copied,
        "removed": removed,
        "preservedRoots": sorted(PRESERVED_ROOTS),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(deploy(args.source, args.target), sort_keys=True))


if __name__ == "__main__":
    main()
