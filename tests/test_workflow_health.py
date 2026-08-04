from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_workflow_health.py"
SPEC = importlib.util.spec_from_file_location("check_workflow_health", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


NOW = datetime(2026, 8, 4, 2, tzinfo=UTC)


def test_missing_natural_schedule_is_unhealthy():
    result = MODULE.health([], now=NOW)
    assert result["healthy"] is False
    assert "NO_NATURAL_SCHEDULE_RUN" in result["issues"]


def test_recent_successful_schedule_is_healthy():
    result = MODULE.health(
        [
            {
                "event": "schedule",
                "conclusion": "success",
                "created_at": "2026-08-04T01:15:00Z",
                "updated_at": "2026-08-04T01:30:00Z",
                "html_url": "https://github.com/a/b/actions/runs/1",
            }
        ],
        now=NOW,
    )
    assert result["healthy"] is True


def test_recent_manual_success_keeps_effective_scan_fresh():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "created_at": "2026-08-04T01:20:00Z",
                "updated_at": "2026-08-04T01:35:00Z",
                "html_url": "https://github.com/a/b/actions/runs/2",
            }
        ],
        now=NOW,
    )
    assert result["fresh"] is True
    assert result["recentSuccess"] is True


def test_recent_active_run_suppresses_duplicate_repair():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "workflow_dispatch",
                "status": "in_progress",
                "conclusion": None,
                "created_at": "2026-08-04T01:45:00Z",
                "updated_at": "2026-08-04T01:45:00Z",
                "html_url": "https://github.com/a/b/actions/runs/3",
            }
        ],
        now=NOW,
    )
    assert result["fresh"] is True
    assert result["recentActive"] is True


def test_stale_success_requires_repair():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "schedule",
                "status": "completed",
                "conclusion": "success",
                "created_at": "2026-08-03T20:00:00Z",
                "updated_at": "2026-08-03T20:10:00Z",
                "html_url": "https://github.com/a/b/actions/runs/4",
            }
        ],
        now=NOW,
        max_age=timedelta(minutes=75),
    )
    assert result["fresh"] is False


def test_main_dispatches_one_fallback_for_stale_effective_scan(monkeypatch):
    stale_runs = [
        {
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2020-01-01T00:10:00Z",
            "html_url": "https://github.com/a/b/actions/runs/5",
        }
    ]
    dispatched = []
    monkeypatch.setattr(MODULE, "runs", lambda _repo: stale_runs)
    monkeypatch.setattr(
        MODULE,
        "dispatch_scan",
        lambda repo, ref: dispatched.append((repo, ref)),
    )
    monkeypatch.setattr(MODULE.sys, "argv", ["check_workflow_health.py", "--repair"])

    assert MODULE.main() == 0
    assert dispatched == [("Oxygen56/oss-pr-radar", "main")]
