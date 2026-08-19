#!/usr/bin/env python3
"""Standalone read-only War Room projection launcher."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _policy_digest(files: list[dict]) -> str:
    selected = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in files
        if str(item.get("path") or "").startswith(("src/oss_pr_radar/", "scripts/"))
    ]
    return hashlib.sha256(_canonical(selected)).hexdigest()


def _verify_active_release(runtime_root: Path) -> tuple[Path, dict]:
    runtime_root = runtime_root.resolve()
    pointer = runtime_root / "current-release"
    if not pointer.is_symlink():
        raise RuntimeError("active release pointer is missing")
    release = pointer.resolve()
    if release.parent != (runtime_root / "releases").resolve():
        raise RuntimeError("active release escapes the release directory")
    manifest = json.loads((release / "release-manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise RuntimeError("active release manifest is invalid")
    unsigned = {
        key: value for key, value in manifest.items() if key not in {"manifestSha256", "releaseId"}
    }
    if manifest.get("manifestSha256") != hashlib.sha256(_canonical(unsigned)).hexdigest():
        raise RuntimeError("active release manifest digest mismatch")
    if manifest.get("releaseId") != release.name:
        raise RuntimeError("active release identity mismatch")
    for item in manifest["files"]:
        relative = Path(str(item.get("path") or ""))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise RuntimeError("active release contains an unsafe path")
        path = release / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("active release contains a missing executable")
        if path.stat().st_size != int(item.get("bytes") or -1):
            raise RuntimeError("active release file size changed")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256"):
            raise RuntimeError("active release file digest changed")
    if manifest.get("policyDigest") != _policy_digest(manifest["files"]):
        raise RuntimeError("active release policy digest mismatch")
    return release, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--ledger-copy", type=Path, required=True)
    args = parser.parse_args()
    release, manifest = _verify_active_release(args.runtime_root)
    sys.path.insert(0, str(release / "src"))
    from oss_pr_radar.war_room_projection import export_projection

    artifact = export_projection(args.ledger_copy.resolve(), source_commit=str(manifest["commit"]))
    print(json.dumps(artifact, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
