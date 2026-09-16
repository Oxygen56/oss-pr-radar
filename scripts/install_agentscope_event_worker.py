#!/usr/bin/env python3
"""Install the immutable-release AgentScope event poller at a 60s cadence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.local_publication import SERVICE_PATH  # noqa: E402

LABEL = "com.oss-pr-radar.agentscope-events"


def spec(
    runtime_root: Path,
    *,
    code_root: Path,
    manifest_sha256: str | None = None,
    home: Path | None = None,
) -> dict[str, object]:
    runtime_root = runtime_root.resolve()
    code_root = code_root.resolve()
    runtime_python = runtime_root / ".venv" / "bin" / "python"
    if not runtime_python.is_file():
        raise RuntimeError("runtime Python interpreter is unavailable")
    manifest = code_root / "release-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise RuntimeError("independent event release manifest is unavailable")
    if manifest_sha256:
        observed = hashlib.sha256(manifest.read_bytes()).hexdigest()
        if observed != manifest_sha256:
            raise RuntimeError("independent event release manifest digest mismatch")
    script = code_root / "scripts" / "agentscope_event_worker.py"
    if not script.is_file() or script.is_symlink():
        raise RuntimeError("event worker is not present in the immutable active release")
    home = (home or Path.home()).resolve()
    log = home / "Library" / "Logs" / "oss-pr-radar"
    return {
        "Label": LABEL,
        "ProgramArguments": [str(runtime_python), str(script), "--root", str(runtime_root)],
        "WorkingDirectory": str(code_root),
        "StartInterval": 60,
        "ThrottleInterval": 60,
        "RunAtLoad": True,
        "StandardOutPath": str(log / "agentscope-events.log"),
        "StandardErrorPath": str(log / "agentscope-events.error.log"),
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1", "PATH": SERVICE_PATH},
    }


def install(
    runtime_root: Path,
    *,
    code_root: Path,
    manifest_sha256: str | None = None,
    home: Path | None = None,
    load: bool = True,
) -> dict[str, object]:
    home = (home or Path.home()).resolve()
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True, exist_ok=True)
    logs = home / "Library" / "Logs" / "oss-pr-radar"
    logs.mkdir(parents=True, exist_ok=True)
    value = spec(runtime_root, code_root=code_root, manifest_sha256=manifest_sha256, home=home)
    path = launch_dir / f"{LABEL}.plist"
    temporary = path.with_suffix(".plist.tmp")
    temporary.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=False))
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or plistlib.loads(path.read_bytes()) != value
    ):
        raise RuntimeError("staged AgentScope event worker plist verification failed")
    service = f"gui/{os.getuid()}/{LABEL}"
    if load:
        subprocess.run(["launchctl", "bootout", service], check=False, capture_output=True)
        subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], check=True)
    return {"ok": True, "label": LABEL, "plist": str(path), "loaded": load, "spec": value}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--code-root", type=Path, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--print-spec", action="store_true")
    parser.add_argument(
        "--stage",
        action="store_true",
        help="write and validate the LaunchAgent plist without loading it",
    )
    args = parser.parse_args()
    try:
        result = (
            {
                "ok": True,
                "spec": spec(
                    args.runtime_root,
                    code_root=args.code_root,
                    manifest_sha256=args.manifest_sha256,
                ),
            }
            if args.print_spec
            else install(
                args.runtime_root,
                code_root=args.code_root,
                manifest_sha256=args.manifest_sha256,
                load=not args.stage,
            )
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
