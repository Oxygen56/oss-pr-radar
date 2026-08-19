#!/usr/bin/env python3
"""Run a read-only audit of one local Radar runtime."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.runtime_audit import (  # noqa: E402
    audit_snapshot,
    collect_snapshot,
    launchctl_print,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--service", default="gui/%d/com.oss-pr-radar.local-publication")
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    if args.snapshot:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    else:
        service = args.service % __import__("os").getuid()
        snapshot = collect_snapshot(args.root, launchctl_output=launchctl_print(service))
    result = audit_snapshot(snapshot)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
