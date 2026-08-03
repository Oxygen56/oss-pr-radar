from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
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
