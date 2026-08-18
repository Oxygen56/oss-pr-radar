#!/usr/bin/env python3
"""Install or remove the macOS LaunchAgent for fast local publication."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.local_publication import (  # noqa: E402
    LAUNCH_AGENT_LABEL,
    launch_agent_spec,
    write_launch_agent,
)


def launchctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["launchctl", *arguments],
        check=check,
        capture_output=True,
        text=True,
    )


def read_plist(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException):
        return None
    return value if isinstance(value, dict) else None


def service_status(service: str, plist_path: Path, expected: dict) -> dict:
    result = launchctl("print", service, check=False)
    output = result.stdout or result.stderr or ""
    runs = re.search(r"\bruns = (\d+)", output)
    last_exit = re.search(r"\blast exit code = (-?\d+)", output)
    error_path = Path(expected["StandardErrorPath"])
    error_bytes = error_path.stat().st_size if error_path.exists() else 0
    loaded = result.returncode == 0
    config_current = read_plist(plist_path) == expected
    last_exit_code = int(last_exit.group(1)) if last_exit else None
    return {
        "ok": loaded and config_current and last_exit_code in {None, 0},
        "installed": loaded,
        "configCurrent": config_current,
        "runs": int(runs.group(1)) if runs else 0,
        "lastExitCode": last_exit_code,
        "errorLogBytes": error_bytes,
        "label": LAUNCH_AGENT_LABEL,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval-seconds", type=int, default=20)
    parser.add_argument("--queue-sync-interval-seconds", type=int, default=300)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()

    home = Path.home()
    domain = f"gui/{os.getuid()}"
    service = f"{domain}/{LAUNCH_AGENT_LABEL}"
    plist_path = home / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    spec = launch_agent_spec(
        ROOT,
        interval_seconds=args.interval_seconds,
        home=home,
        queue_sync_interval_seconds=args.queue_sync_interval_seconds,
    )

    if args.status:
        status = service_status(service, plist_path, spec)
        print(json.dumps(status))
        return 0 if status["ok"] else 1

    if args.uninstall:
        launchctl("bootout", service, check=False)
        plist_path.unlink(missing_ok=True)
        print(json.dumps({"ok": True, "installed": False, "label": LAUNCH_AGENT_LABEL}))
        return 0

    Path(spec["StandardOutPath"]).parent.mkdir(parents=True, exist_ok=True)
    current = service_status(service, plist_path, spec)
    changed = not current["installed"] or not current["configCurrent"]
    restarted = changed or current["lastExitCode"] not in {None, 0}
    if restarted:
        launchctl("bootout", service, check=False)
        write_launch_agent(plist_path, spec)
        launchctl("bootstrap", domain, str(plist_path))
        launchctl("kickstart", "-k", service)
    print(
        json.dumps(
            {
                "ok": True,
                "installed": True,
                "changed": changed,
                "restarted": restarted,
                "label": LAUNCH_AGENT_LABEL,
                "intervalSeconds": spec["StartInterval"],
                "queueSyncIntervalSeconds": args.queue_sync_interval_seconds,
                "plist": str(plist_path),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
