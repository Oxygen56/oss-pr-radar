from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_workflow_health.py"
SPEC = importlib.util.spec_from_file_location("check_workflow_health", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


NOW = datetime(2026, 8, 4, 2, tzinfo=UTC)


def test_missing_natural_schedule_is_unhealthy():
    result = MODULE.health([], now=NOW)
    assert result["healthy"] is False
    assert result["healthScope"] == "github_actions_schedule"
    assert result["githubNaturalScheduleHealthy"] is False
    assert result["naturalScheduleHealthy"] is False
    assert "NO_NATURAL_SCHEDULE_RUN" in result["issues"]
    assert result["githubNaturalScheduleIssues"] == result["issues"]
    assert result["naturalScheduleIssues"] == result["issues"]


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
    assert result["githubNaturalScheduleHealthy"] is True
    assert result["naturalScheduleHealthy"] is True
    assert result["naturalScheduleCoverage"]["assessed"] is False


def test_sparse_natural_schedule_coverage_is_reported_without_hiding_freshness():
    runs = [
        {
            "event": "schedule",
            "conclusion": "success",
            "created_at": (NOW - timedelta(hours=offset)).isoformat(),
            "updated_at": (NOW - timedelta(hours=offset) + timedelta(minutes=10)).isoformat(),
            "html_url": f"https://github.com/a/b/actions/runs/{offset}",
        }
        for offset in range(1, 25, 3)
    ]
    runs.append(
        {
            "event": "workflow_dispatch",
            "conclusion": "success",
            "created_at": (NOW - timedelta(hours=25)).isoformat(),
            "updated_at": (NOW - timedelta(hours=25) + timedelta(minutes=10)).isoformat(),
            "html_url": "https://github.com/a/b/actions/runs/old",
        }
    )

    result = MODULE.health(runs, now=NOW, coverage_window_hours=24)

    assert result["githubNaturalScheduleHealthy"] is True
    assert result["issues"] == []
    assert result["githubNaturalScheduleWarnings"] == [
        "NATURAL_SCHEDULE_COVERAGE_LOW",
        "NATURAL_SCHEDULE_GAP_EXCESSIVE",
    ]
    assert result["naturalScheduleCoverage"] == {
        "assessed": True,
        "windowHours": 24,
        "successfulRuns": 8,
        "expectedRuns": 24,
        "minimumRuns": 12,
        "coverageRatio": 0.333,
        "maxGapMinutes": 180,
        "warnings": [
            "NATURAL_SCHEDULE_COVERAGE_LOW",
            "NATURAL_SCHEDULE_GAP_EXCESSIVE",
        ],
    }


def test_runs_retries_transient_github_api_failure(monkeypatch):
    attempts = []
    responses = [
        subprocess.CompletedProcess([], 1, stdout="", stderr="EOF"),
        subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps({"workflow_runs": [{"id": 1}]}),
            stderr="",
        ),
    ]

    def fake_run(*_args, **_kwargs):
        attempts.append(True)
        return responses.pop(0)

    delays = []
    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    monkeypatch.setattr(MODULE, "sleep", delays.append)

    assert MODULE.runs("example/project") == [{"id": 1}]
    assert len(attempts) == 2
    assert delays == [1.0]


def test_github_actions_billing_block_is_detected_from_job_annotation(monkeypatch):
    workflow_runs = [
        {
            "id": 42,
            "event": "schedule",
            "conclusion": "failure",
            "html_url": "https://github.com/a/b/actions/runs/42",
        }
    ]

    def fake_json(path):
        if path.endswith("/jobs"):
            return {
                "jobs": [
                    {
                        "conclusion": "failure",
                        "steps": [],
                        "runner_id": 0,
                        "check_run_url": "https://api.github.com/repos/a/b/check-runs/99",
                    }
                ]
            }
        assert path.endswith("/check-runs/99/annotations")
        return [
            {
                "message": (
                    "The job was not started because recent account payments have failed "
                    "or your spending limit needs to be increased."
                )
            }
        ]

    monkeypatch.setattr(MODULE, "github_json", fake_json)

    blocker = MODULE.github_actions_external_blocker("a/b", workflow_runs)

    assert blocker["code"] == "GITHUB_ACTIONS_BILLING_BLOCKED"
    assert blocker["runUrl"].endswith("/42")


def test_historical_billing_block_is_cleared_by_a_later_success(monkeypatch):
    workflow_runs = [
        {
            "id": 43,
            "event": "schedule",
            "conclusion": "success",
            "created_at": "2026-08-04T02:00:00Z",
            "updated_at": "2026-08-04T02:10:00Z",
            "html_url": "https://github.com/a/b/actions/runs/43",
        },
        {
            "id": 42,
            "event": "schedule",
            "conclusion": "failure",
            "created_at": "2026-08-04T01:00:00Z",
            "updated_at": "2026-08-04T01:01:00Z",
            "html_url": "https://github.com/a/b/actions/runs/42",
        },
    ]
    monkeypatch.setattr(
        MODULE,
        "github_json",
        lambda _path: (_ for _ in ()).throw(AssertionError("stale run must not be queried")),
    )

    assert MODULE.github_actions_external_blocker("a/b", workflow_runs) is None


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


def test_default_freshness_tolerates_normal_github_schedule_jitter():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "schedule",
                "status": "completed",
                "conclusion": "success",
                "created_at": (NOW - timedelta(minutes=72)).isoformat(),
                "updated_at": (NOW - timedelta(minutes=66)).isoformat(),
                "html_url": "https://github.com/a/b/actions/runs/repair-window",
            }
        ],
        now=NOW,
    )

    assert result["fresh"] is True
    assert result["maxAgeMinutes"] == 110


def test_default_freshness_expires_after_a_missed_hourly_scan():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "schedule",
                "status": "completed",
                "conclusion": "success",
                "created_at": (NOW - timedelta(minutes=125)).isoformat(),
                "updated_at": (NOW - timedelta(minutes=120)).isoformat(),
                "html_url": "https://github.com/a/b/actions/runs/missed-window",
            }
        ],
        now=NOW,
    )

    assert result["fresh"] is False
    assert result["maxAgeMinutes"] == 110


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
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "require_operational_authorization", lambda _root: None)
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", "--repair"],
    )

    assert MODULE.main() == 0
    assert dispatched == [("Oxygen56/oss-pr-radar", "main")]


def test_main_suppresses_futile_repair_when_actions_billing_is_blocked(monkeypatch, capsys):
    failed_runs = [
        {
            "id": 42,
            "event": "schedule",
            "status": "completed",
            "conclusion": "failure",
            "created_at": "2026-08-04T01:00:00Z",
            "updated_at": "2026-08-04T01:01:00Z",
            "html_url": "https://github.com/a/b/actions/runs/42",
        }
    ]
    dispatched = []
    monkeypatch.setattr(MODULE, "runs", lambda _repo: failed_runs)
    monkeypatch.setattr(
        MODULE,
        "github_actions_external_blocker",
        lambda *_args: {
            "code": "GITHUB_ACTIONS_BILLING_BLOCKED",
            "runUrl": "https://github.com/a/b/actions/runs/42",
            "message": "spending limit needs to be increased",
        },
    )
    monkeypatch.setattr(
        MODULE,
        "dispatch_scan",
        lambda repo, ref: dispatched.append((repo, ref)),
    )
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "require_operational_authorization", lambda _root: None)
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", "--repair"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert dispatched == []
    assert result["repairTriggered"] is False
    assert result["repairWouldTrigger"] is False
    assert result["repairSuppressedReason"] == "GITHUB_ACTIONS_BILLING_BLOCKED"


@pytest.mark.parametrize("flag", ["--repair", "--notify"])
def test_health_external_actions_require_authorization_before_github_or_feishu(
    monkeypatch, capsys, flag
):
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("missing authorization")),
    )
    monkeypatch.setattr(
        MODULE,
        "runs",
        lambda _repo: pytest.fail("GitHub must not be queried before authorization"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", flag],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "authorization" in result["error"]


def test_health_rejects_wrong_runtime_binding_before_github_or_feishu(monkeypatch, capsys):
    monkeypatch.setattr(
        MODULE,
        "bind_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("release mismatch")),
    )
    monkeypatch.setattr(
        MODULE,
        "runs",
        lambda _repo: pytest.fail("GitHub must not be queried for an invalid release"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", "--notify"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "runtime binding" in result["error"]


def test_health_help_has_no_auth_bypass_option():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "skip-auth" not in completed.stdout
    assert "allow-unreleased-code" not in completed.stdout
