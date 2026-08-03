#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.followup import collect_followup  # noqa: E402
from oss_pr_radar.github_client import GitHubClient  # noqa: E402
from oss_pr_radar.util import atomic_write_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--author", default=os.environ.get("RADAR_GITHUB_ACTOR", "Oxygen56"))
    args = parser.parse_args()
    existing = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else None
    state, report = collect_followup(GitHubClient(), author=args.author, existing=existing)
    atomic_write_json(args.state, state)
    atomic_write_json(args.report, report)
    print(
        json.dumps(
            {
                "open_prs": len(state["items"]),
                "actionable_updates": len(report["updates"]),
                "errors": len(report["errors"]),
            }
        )
    )
    return 0 if report["scan_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
