#!/usr/bin/env python3
"""Run one AgentScope event-lane cycle; no model is started on an empty poll."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.agentscope_events import EventLane, GitHubIssuePoller, dispatch_once  # noqa: E402


def run_once(root: Path, *, deliver=None) -> dict:
    state = root / "state"
    lane = EventLane(state / "agentscope-events.sqlite3")
    poll = GitHubIssuePoller(state / "agentscope-poll.json")
    result = poll.poll()
    # Reviews/CI and PR changes outrank issue discovery.  The worker does not
    # make a claim here; claim eligibility remains the existing bridge policy.
    inserted = lane.append_many(
        result.events,
        priority=100 if any(event.get("kind") == "pr_update" for event in result.events) else 10,
    )
    drained = {"claimed": 0, "delivered": 0, "pending": lane.pending()}
    if deliver is not None and result.events:
        drained = dispatch_once(lane, deliver)
    return {
        "ok": True,
        "status": result.status,
        "eventsSeen": len(result.events),
        "eventsInserted": inserted,
        "codexWake": bool(drained["delivered"]),
        "drain": drained,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run_once(args.root), ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:400]}"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
