#!/usr/bin/env python3
"""Independent freshness watchdog for natural GitHub Actions scheduling."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.notifier import FeishuClient  # noqa: E402
from oss_pr_radar.util import parse_time, sha256_json  # noqa: E402


def runs(repo: str) -> list[dict]:
    completed = subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "GET",
            f"repos/{repo}/actions/workflows/radar.yml/runs",
            "-f",
            "per_page=20",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout)[:300])
    return json.loads(completed.stdout).get("workflow_runs") or []


def health(workflow_runs: list[dict], *, now: datetime | None = None) -> dict:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    scheduled = [item for item in workflow_runs if item.get("event") == "schedule"]
    successful = [item for item in scheduled if item.get("conclusion") == "success"]
    issues = []
    latest_schedule = scheduled[0] if scheduled else None
    latest_success = successful[0] if successful else None
    if not latest_schedule:
        issues.append("NO_NATURAL_SCHEDULE_RUN")
    elif parse_time(latest_schedule["created_at"]) < current - timedelta(hours=2, minutes=30):
        issues.append("NATURAL_SCHEDULE_STALE")
    if not latest_success:
        issues.append("NO_SUCCESSFUL_SCHEDULE_RUN")
    elif parse_time(latest_success["updated_at"]) < current - timedelta(hours=4):
        issues.append("SUCCESSFUL_SCHEDULE_STALE")
    if sum(item.get("conclusion") == "failure" for item in scheduled[:3]) >= 2:
        issues.append("REPEATED_SCHEDULE_FAILURE")
    return {
        "healthy": not issues,
        "issues": issues,
        "latestScheduleUrl": latest_schedule.get("html_url") if latest_schedule else None,
        "latestSuccessUrl": latest_success.get("html_url") if latest_success else None,
        "checkedAt": current.isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="Oxygen56/oss-pr-radar")
    parser.add_argument("--notify", action="store_true")
    args = parser.parse_args()
    result = health(runs(args.repo))
    if args.notify and not result["healthy"]:
        app_id = os.environ.get("FEISHU_APP_ID")
        app_secret = os.environ.get("FEISHU_APP_SECRET")
        chat_id = os.environ.get("FEISHU_CHAT_ID")
        if not app_id or not app_secret or not chat_id:
            raise SystemExit("Feishu credentials are not configured")
        client = FeishuClient(app_id, app_secret, chat_id)
        client.send_card(
            {
                "header": {
                    "title": {"tag": "plain_text", "content": "OSS PR Radar 调度异常"},
                    "template": "red",
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": "\n".join(result["issues"]),
                        },
                    }
                ],
            },
            idempotency_key=sha256_json(
                {"issues": result["issues"], "hour": result["checkedAt"][:13]}
            ),
        )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["healthy"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
