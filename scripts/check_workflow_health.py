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
from time import sleep

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.notifier import FeishuClient  # noqa: E402
from oss_pr_radar.util import parse_time, sha256_json  # noqa: E402


def runs(repo: str) -> list[dict]:
    last_error = "unknown GitHub API failure"
    for delay in (0.0, 1.0, 3.0):
        if delay:
            sleep(delay)
        try:
            completed = subprocess.run(
                [
                    "gh",
                    "api",
                    "-X",
                    "GET",
                    f"repos/{repo}/actions/workflows/radar.yml/runs",
                    "-f",
                    "per_page=100",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if completed.returncode == 0:
                return json.loads(completed.stdout).get("workflow_runs") or []
            last_error = (completed.stderr or completed.stdout or last_error)[:300]
        except (json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
            last_error = f"{type(exc).__name__}:{str(exc)[:240]}"
    raise RuntimeError(last_error)


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

    coverage_window = timedelta(hours=24)
    window_start = current - coverage_window
    run_times = [parse_time(item["created_at"]) for item in workflow_runs if item.get("created_at")]
    coverage_assessed = bool(run_times and min(run_times) <= window_start)
    successful_times = sorted(
        parse_time(item["created_at"])
        for item in successful
        if item.get("created_at") and parse_time(item["created_at"]) >= window_start
    )
    expected_runs = 24
    minimum_runs = 12
    coverage_ratio = min(1.0, len(successful_times) / expected_runs)
    gap_points = [window_start, *successful_times, current]
    max_gap_minutes = max(
        (
            int((right - left).total_seconds() // 60)
            for left, right in zip(gap_points, gap_points[1:], strict=False)
        ),
        default=None,
    )
    if coverage_assessed and len(successful_times) < minimum_runs:
        issues.append("NATURAL_SCHEDULE_COVERAGE_LOW")
    if coverage_assessed and max_gap_minutes is not None and max_gap_minutes > 150:
        issues.append("NATURAL_SCHEDULE_GAP_EXCESSIVE")
    return {
        "healthy": not issues,
        "issues": issues,
        "healthScope": "github_actions_schedule",
        "githubNaturalScheduleHealthy": not issues,
        "githubNaturalScheduleIssues": issues,
        # Compatibility fields for older controller prompts and reports.
        "naturalScheduleHealthy": not issues,
        "naturalScheduleIssues": issues,
        "latestScheduleUrl": latest_schedule.get("html_url") if latest_schedule else None,
        "latestSuccessUrl": latest_success.get("html_url") if latest_success else None,
        "naturalScheduleCoverage": {
            "assessed": coverage_assessed,
            "windowHours": 24,
            "successfulRuns": len(successful_times),
            "expectedRuns": expected_runs,
            "minimumRuns": minimum_runs,
            "coverageRatio": round(coverage_ratio, 3),
            "maxGapMinutes": max_gap_minutes,
        },
        "checkedAt": current.isoformat().replace("+00:00", "Z"),
    }


def effective_scan_freshness(
    workflow_runs: list[dict],
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(minutes=75),
    active_grace: timedelta = timedelta(minutes=50),
) -> dict:
    """Treat a recent fallback run as healthy and avoid duplicate repairs."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    relevant = [
        item for item in workflow_runs if item.get("event") in {"schedule", "workflow_dispatch"}
    ]
    successful = [item for item in relevant if item.get("conclusion") == "success"]
    active = [
        item
        for item in relevant
        if item.get("status") in {"queued", "in_progress", "waiting", "requested", "pending"}
        and item.get("created_at")
        and parse_time(item["created_at"]) >= current - active_grace
    ]
    latest_success = max(
        successful,
        key=lambda item: parse_time(item["updated_at"]),
        default=None,
    )
    latest_active = max(
        active,
        key=lambda item: parse_time(item["created_at"]),
        default=None,
    )
    success_fresh = bool(
        latest_success and parse_time(latest_success["updated_at"]) >= current - max_age
    )
    return {
        "fresh": success_fresh or latest_active is not None,
        "recentSuccess": success_fresh,
        "recentActive": latest_active is not None,
        "latestEffectiveUrl": ((latest_active or latest_success or {}).get("html_url")),
        "maxAgeMinutes": int(max_age.total_seconds() // 60),
    }


def dispatch_scan(repo: str, ref: str, *, window_hours: float = 2.0) -> None:
    completed = subprocess.run(
        [
            "gh",
            "workflow",
            "run",
            "radar.yml",
            "--repo",
            repo,
            "--ref",
            ref,
            "-f",
            f"window_hours={window_hours:g}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout)[:300])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="Oxygen56/oss-pr-radar")
    parser.add_argument("--notify", action="store_true")
    parser.add_argument("--repair", action="store_true")
    parser.add_argument("--dry-run-repair", action="store_true")
    parser.add_argument("--ref", default="main")
    parser.add_argument("--max-effective-age-minutes", type=int, default=75)
    args = parser.parse_args()
    workflow_runs = runs(args.repo)
    result = health(workflow_runs)
    effective = effective_scan_freshness(
        workflow_runs,
        max_age=timedelta(minutes=max(15, args.max_effective_age_minutes)),
    )
    repair_triggered = False
    repair_would_trigger = False
    repair_error = None
    if args.repair and not effective["fresh"]:
        repair_would_trigger = True
        if not args.dry_run_repair:
            try:
                dispatch_scan(args.repo, args.ref)
                repair_triggered = True
            except (RuntimeError, subprocess.SubprocessError) as exc:
                repair_error = f"{type(exc).__name__}:{str(exc)[:200]}"
    result["effectiveScan"] = effective
    result["repairTriggered"] = repair_triggered
    result["repairWouldTrigger"] = repair_would_trigger
    result["repairError"] = repair_error
    result["operationalHealthy"] = effective["fresh"] or repair_triggered
    if args.notify and (repair_would_trigger or repair_error):
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
                            "content": "\n".join(
                                result["issues"]
                                + (["FALLBACK_DISPATCH_TRIGGERED"] if repair_triggered else [])
                                + ([f"REPAIR_FAILED: {repair_error}"] if repair_error else [])
                            ),
                        },
                    }
                ],
            },
            idempotency_key=sha256_json(
                {"issues": result["issues"], "hour": result["checkedAt"][:13]}
            ),
        )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["operationalHealthy"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
