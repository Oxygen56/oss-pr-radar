#!/usr/bin/env python3
"""Install the immutable-release AgentScope event poller at a 60s cadence."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.runtime_audit import active_release_evidence  # noqa: E402

LABEL = "com.oss-pr-radar.agentscope-events"


def spec(runtime_root: Path, *, home: Path | None = None) -> dict[str, object]:
    runtime_root = runtime_root.resolve()
    release = active_release_evidence(runtime_root)
    if release.get("valid") is not True:
        raise RuntimeError(f"active release rejected: {release.get('error', 'invalid')}")
    code_root = Path(str(release["path"])).resolve()
    script = code_root / "scripts" / "agentscope_event_worker.py"
    if not script.is_file() or script.is_symlink():
        raise RuntimeError("event worker is not present in the immutable active release")
    home = (home or Path.home()).resolve()
    log = home / "Library" / "Logs" / "oss-pr-radar"
    return {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, str(script), "--root", str(runtime_root)],
        "WorkingDirectory": str(code_root),
        "StartInterval": 60,
        "ThrottleInterval": 60,
        "RunAtLoad": True,
        "StandardOutPath": str(log / "agentscope-events.log"),
        "StandardErrorPath": str(log / "agentscope-events.error.log"),
        "EnvironmentVariables": {"PYTHONUNBUFFERED": "1", "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"},
    }


def install(runtime_root: Path, *, home: Path | None = None, load: bool = True) -> dict[str, object]:
    home = (home or Path.home()).resolve()
    launch_dir = home / "Library" / "LaunchAgents"
    launch_dir.mkdir(parents=True, exist_ok=True)
    logs = home / "Library" / "Logs" / "oss-pr-radar"
    logs.mkdir(parents=True, exist_ok=True)
    value = spec(runtime_root, home=home)
    path = launch_dir / f"{LABEL}.plist"
    temporary = path.with_suffix(".plist.tmp")
    temporary.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=False))
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    service = f"gui/{os.getuid()}/{LABEL}"
    if load:
        subprocess.run(["launchctl", "bootout", service], check=False, capture_output=True)
        subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)], check=True)
        subprocess.run(["launchctl", "kickstart", "-k", service], check=True)
    return {"ok": True, "label": LABEL, "plist": str(path), "loaded": load, "spec": value}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--print-spec", action="store_true")
    args = parser.parse_args()
    try:
        result = {"ok": True, "spec": spec(args.runtime_root)} if args.print_spec else install(args.runtime_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
