from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.managed_lifecycle import ManagedLedger

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_workflow_health.py"
SPEC = importlib.util.spec_from_file_location("check_workflow_health", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


NOW = datetime(2026, 8, 4, 2, tzinfo=UTC)


def _healthy_managed_followup(_path):
    return {
        "assessed": True,
        "healthy": True,
        "issues": [],
        "openCount": 0,
        "coveredCount": 0,
    }


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
                "id": 1,
                "event": "schedule",
                "conclusion": "success",
                "created_at": "2026-08-04T01:15:00Z",
                "updated_at": "2026-08-04T01:30:00Z",
                "html_url": "https://github.com/a/b/actions/runs/1",
            }
        ],
        now=NOW,
        natural_full_chain_run_ids={1},
    )
    assert result["healthy"] is True
    assert result["githubNaturalScheduleHealthy"] is True
    assert result["naturalScheduleHealthy"] is True
    assert result["naturalScheduleCoverage"]["assessed"] is False


def test_sparse_natural_schedule_coverage_is_reported_without_hiding_freshness():
    runs = [
        {
            "id": offset,
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

    result = MODULE.health(
        runs,
        now=NOW,
        coverage_window_hours=24,
        natural_full_chain_run_ids={offset for offset in range(1, 25, 3)},
    )

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


def test_latest_failed_natural_schedule_is_not_masked_by_prior_success():
    runs = [
        {
            "id": 2,
            "event": "schedule",
            "conclusion": "failure",
            "created_at": "2026-08-04T01:50:00Z",
            "updated_at": "2026-08-04T01:55:00Z",
        },
        {
            "id": 1,
            "event": "schedule",
            "conclusion": "success",
            "created_at": "2026-08-04T01:15:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
            "html_url": "https://github.com/a/b/actions/runs/1",
        },
    ]

    result = MODULE.health(runs, now=NOW, natural_full_chain_run_ids={1})

    assert result["healthy"] is False
    assert "NATURAL_SCHEDULE_RUN_FAILED" in result["issues"]


def test_latest_unproven_natural_success_is_not_masked_by_prior_proven_success():
    runs = [
        {
            "id": 1,
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-08-04T01:15:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
        },
        {
            "id": 2,
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-08-04T01:50:00Z",
            "updated_at": "2026-08-04T01:55:00Z",
            "html_url": "https://github.com/a/b/actions/runs/2",
        },
    ]

    result = MODULE.health(runs, now=NOW, natural_full_chain_run_ids={1})

    assert result["healthy"] is False
    assert "NATURAL_SCHEDULE_FULL_CHAIN_UNPROVEN" in result["issues"]


def test_health_orders_schedule_rows_by_creation_time_before_selecting_latest():
    runs = [
        {
            "id": 1,
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-08-04T01:15:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
            "html_url": "https://github.com/a/b/actions/runs/1",
        },
        {
            "id": 2,
            "event": "schedule",
            "status": "completed",
            "conclusion": "failure",
            "created_at": "2026-08-04T01:50:00Z",
            "updated_at": "2026-08-04T01:55:00Z",
            "html_url": "https://github.com/a/b/actions/runs/2",
        },
    ]

    result = MODULE.health(runs, now=NOW, natural_full_chain_run_ids={1})

    assert result["latestScheduleUrl"].endswith("/2")
    assert "NATURAL_SCHEDULE_RUN_FAILED" in result["issues"]


def _managed_followup_ledger(
    tmp_path,
    *,
    open_count: int,
    covered_count: int,
    pr_observed_at: str = "2026-08-04T01:00:00Z",
    followup_observed_at: str = "2026-08-04T01:30:00Z",
) -> Path:
    path = tmp_path / "state" / "radar_ledger.sqlite3"
    ledger = ManagedLedger(path, ensure_schema=True)
    for number in range(1, open_count + 1):
        head_sha = f"{number:040x}"
        key = f"owner/repo#{number}"
        ledger.upsert_pr(
            pr_key=key,
            owner="owner",
            repo="repo",
            number=number,
            head_sha=head_sha,
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=False,
            source_kind="FOLLOWUP_OBSERVATION",
            source="github-followup",
            observed_at=pr_observed_at,
        )
        if number <= covered_count:
            ledger.record_ci_run(
                ci_key=f"followup:{key}:{head_sha}",
                pr_key=key,
                head_sha=head_sha,
                status="PASSED",
                checks={"source": "followup"},
                observed_at=followup_observed_at,
            )
    return path


def test_managed_followup_coverage_fails_when_legacy_40_of_67_are_present(tmp_path):
    path = _managed_followup_ledger(tmp_path, open_count=67, covered_count=40)

    result = MODULE.managed_followup_coverage(path, now=NOW)

    assert result["healthy"] is False
    assert result["openCount"] == 67
    assert result["coveredCount"] == 40
    assert len(result["missingKeys"]) == 27
    assert result["issues"] == ["MANAGED_PR_FOLLOWUP_MISSING"]


def test_managed_followup_coverage_fails_closed_when_ledger_is_unavailable(tmp_path):
    result = MODULE.managed_followup_coverage(tmp_path / "missing.sqlite3", now=NOW)

    assert result["assessed"] is False
    assert result["healthy"] is False
    assert result["issues"] == ["MANAGED_PR_FOLLOWUP_COVERAGE_UNAVAILABLE"]


def test_managed_followup_coverage_accepts_all_67_current_heads(tmp_path):
    path = _managed_followup_ledger(tmp_path, open_count=67, covered_count=67)

    result = MODULE.managed_followup_coverage(path, now=NOW)

    assert result["healthy"] is True
    assert result["openCount"] == result["coveredCount"] == 67
    assert result["issues"] == []


def test_managed_followup_coverage_excludes_terminal_pr_without_snapshot(tmp_path):
    path = _managed_followup_ledger(tmp_path, open_count=2, covered_count=1)
    ManagedLedger(path).upsert_pr(
        pr_key="owner/repo#2",
        owner="owner",
        repo="repo",
        number=2,
        head_sha=f"{2:040x}",
        pr_url="https://github.com/owner/repo/pull/2",
        state="MERGED",
        auto_created=False,
        source_kind="FOLLOWUP_OBSERVATION",
        source="github-authoritative-reconciliation",
        observed_at="2026-08-04T01:40:00Z",
    )

    result = MODULE.managed_followup_coverage(path, now=NOW)

    assert result["healthy"] is True
    assert result["openCount"] == result["coveredCount"] == 1
    assert result["missingKeys"] == []


def test_managed_followup_coverage_rejects_snapshot_before_latest_head(tmp_path):
    path = _managed_followup_ledger(tmp_path, open_count=1, covered_count=1)
    ManagedLedger(path).upsert_pr(
        pr_key="owner/repo#1",
        owner="owner",
        repo="repo",
        number=1,
        head_sha="f" * 40,
        pr_url="https://github.com/owner/repo/pull/1",
        state="OPEN",
        auto_created=False,
        source_kind="FOLLOWUP_OBSERVATION",
        source="publication",
        observed_at="2026-08-04T01:40:00Z",
    )

    result = MODULE.managed_followup_coverage(path, now=NOW)

    assert result["healthy"] is False
    assert result["headMismatchKeys"] == ["owner/repo#1"]
    assert result["issues"] == ["MANAGED_PR_FOLLOWUP_HEAD_STALE"]


def test_managed_followup_coverage_rejects_snapshot_before_latest_publication(tmp_path):
    path = _managed_followup_ledger(tmp_path, open_count=1, covered_count=1)
    ManagedLedger(path).upsert_pr(
        pr_key="owner/repo#1",
        owner="owner",
        repo="repo",
        number=1,
        head_sha=f"{1:040x}",
        pr_url="https://github.com/owner/repo/pull/1",
        state="OPEN",
        auto_created=False,
        source_kind="FOLLOWUP_OBSERVATION",
        source="publication",
        observed_at="2026-08-04T01:40:00Z",
    )

    result = MODULE.managed_followup_coverage(path, now=NOW)

    assert result["healthy"] is False
    assert result["predatesPublicationKeys"] == ["owner/repo#1"]
    assert result["issues"] == ["MANAGED_PR_FOLLOWUP_PREDATES_PUBLICATION"]


def test_managed_followup_coverage_does_not_require_refresh_after_same_head_reconciliation(
    tmp_path,
):
    path = _managed_followup_ledger(tmp_path, open_count=1, covered_count=1)
    ManagedLedger(path).upsert_pr(
        pr_key="owner/repo#1",
        owner="owner",
        repo="repo",
        number=1,
        head_sha=f"{1:040x}",
        pr_url="https://github.com/owner/repo/pull/1",
        state="OPEN",
        auto_created=False,
        source_kind="FOLLOWUP_OBSERVATION",
        source="github-authoritative-reconciliation",
        observed_at="2026-08-04T01:40:00Z",
    )

    result = MODULE.managed_followup_coverage(path, now=NOW)

    assert result["healthy"] is True
    assert result["coveredCount"] == 1


def test_main_fails_operational_health_for_40_of_67_managed_coverage(monkeypatch, capsys, tmp_path):
    current = datetime.now(UTC)
    _managed_followup_ledger(
        tmp_path,
        open_count=67,
        covered_count=40,
        pr_observed_at=(current - timedelta(minutes=40)).isoformat(),
        followup_observed_at=(current - timedelta(minutes=30)).isoformat(),
    )
    recent = {
        "id": 7,
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
        "updated_at": (datetime.now(UTC) - timedelta(minutes=20)).isoformat(),
        "html_url": "https://github.com/a/b/actions/runs/7",
    }
    monkeypatch.setattr(MODULE, "runs", lambda _repo: [recent])
    monkeypatch.setattr(
        MODULE,
        "workflow_component_health",
        lambda *_args: {
            "assessed": True,
            "healthy": True,
            "issues": [],
            "scanSucceeded": True,
            "runUpdatedAt": recent["updated_at"],
            "runUrl": recent["html_url"],
        },
    )
    monkeypatch.setattr(MODULE, "github_actions_external_blocker", lambda *_args: None)
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        MODULE,
        "runtime_managed_followup_coverage",
        lambda _root: MODULE.managed_followup_coverage(tmp_path / "state" / "radar_ledger.sqlite3"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", str(tmp_path)],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["operationalHealthy"] is False
    assert result["managedFollowupCoverage"]["coveredCount"] == 40
    assert "MANAGED_PR_FOLLOWUP_MISSING" in result["operationalIssues"]


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


def test_component_health_checks_each_required_job_below_green_run(monkeypatch):
    workflow_runs = [
        {
            "id": 7,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-08-04T01:20:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
            "html_url": "https://github.com/a/b/actions/runs/7",
        }
    ]
    monkeypatch.setattr(
        MODULE,
        "github_json",
        lambda path: (
            {
                "jobs": [
                    {"name": name, "conclusion": "success"}
                    for name in (
                        "watch",
                        "scan",
                        "pr-followup",
                        "build-state",
                        "persist-pending",
                        "notify",
                        "persist-receipt",
                    )
                ]
            }
            if path.endswith("/jobs?per_page=100")
            else pytest.fail(path)
        ),
    )

    result = MODULE.workflow_component_health("a/b", workflow_runs)

    assert result["healthy"] is True
    assert result["scanSucceeded"] is True
    assert result["issues"] == []


def test_component_health_requires_full_chain_proof_for_natural_run(monkeypatch):
    natural = {
        "id": 11,
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-08-04T01:20:00Z",
        "updated_at": "2026-08-04T01:30:00Z",
        "html_url": "https://github.com/a/b/actions/runs/11",
    }
    jobs = [
        {"name": name, "conclusion": "success"}
        for name in (*MODULE._NATURAL_REQUIRED_JOBS, MODULE._FULL_CHAIN_PROOF_JOB)
    ]
    monkeypatch.setattr(MODULE, "github_json", lambda _path: {"jobs": jobs})

    result = MODULE.workflow_component_health("a/b", [natural])

    assert result["healthy"] is True
    assert result["naturalFullChainProven"] is True
    assert result["scanSucceeded"] is True


def test_component_health_requires_watch_for_manual_fallback(monkeypatch):
    manual = {
        "id": 13,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-08-04T01:20:00Z",
        "updated_at": "2026-08-04T01:30:00Z",
    }
    jobs = [
        {"name": name, "conclusion": "success"}
        for name in (
            "scan",
            "pr-followup",
            "build-state",
            "persist-pending",
            "notify",
            "persist-receipt",
        )
    ]
    monkeypatch.setattr(MODULE, "github_json", lambda _path: {"jobs": jobs})

    result = MODULE.workflow_component_health("a/b", [manual])

    assert result["healthy"] is False
    assert result["issues"] == ["WATCH_DEGRADED"]


def test_duplicate_job_name_cannot_hide_a_failure(monkeypatch):
    natural = {
        "id": 14,
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-08-04T01:20:00Z",
        "updated_at": "2026-08-04T01:30:00Z",
    }
    jobs = [
        {"name": name, "conclusion": "success"}
        for name in (*MODULE._NATURAL_REQUIRED_JOBS, MODULE._FULL_CHAIN_PROOF_JOB)
    ]
    jobs.append({"name": "scan", "conclusion": "failure"})
    monkeypatch.setattr(MODULE, "github_json", lambda _path: {"jobs": jobs})

    result = MODULE.workflow_component_health("a/b", [natural])

    assert result["healthy"] is False
    assert result["jobs"]["scan"] == "failure"
    assert result["naturalFullChainProven"] is False


def test_component_health_rejects_natural_run_with_skipped_business_job(monkeypatch):
    natural = {
        "id": 12,
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-08-04T01:20:00Z",
        "updated_at": "2026-08-04T01:30:00Z",
        "html_url": "https://github.com/a/b/actions/runs/12",
    }
    jobs = [
        {"name": name, "conclusion": "success"}
        for name in (*MODULE._NATURAL_REQUIRED_JOBS, MODULE._FULL_CHAIN_PROOF_JOB)
    ]
    jobs[-2]["conclusion"] = "skipped"
    monkeypatch.setattr(MODULE, "github_json", lambda _path: {"jobs": jobs})

    result = MODULE.workflow_component_health("a/b", [natural])

    assert result["healthy"] is False
    assert result["naturalFullChainProven"] is False
    assert result["issues"] == ["NATURAL_FULL_CHAIN_DEGRADED"]


def test_proven_natural_ids_cover_only_jobs_api_verified_runs(monkeypatch):
    workflow_runs = [
        {"id": 21, "event": "schedule", "status": "completed", "conclusion": "success"},
        {"id": 20, "event": "schedule", "status": "completed", "conclusion": "success"},
    ]

    def fake_json(path):
        if "/21/" in path:
            names = (*MODULE._NATURAL_REQUIRED_JOBS, MODULE._FULL_CHAIN_PROOF_JOB)
        else:
            names = ("schedule-canary",)
        return {"jobs": [{"name": name, "conclusion": "success"} for name in names]}

    monkeypatch.setattr(MODULE, "github_json", fake_json)

    assert MODULE.proven_natural_schedule_run_ids("a/b", workflow_runs) == {21}


def test_proven_natural_ids_bound_jobs_queries_to_window_and_reuse_cache(monkeypatch):
    workflow_runs = [
        {
            "id": number,
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": (NOW - timedelta(minutes=30 * number)).isoformat(),
            "updated_at": (NOW - timedelta(minutes=30 * number - 5)).isoformat(),
        }
        for number in range(30)
    ]
    calls = []
    jobs = [
        {"name": name, "conclusion": "success"}
        for name in (*MODULE._NATURAL_REQUIRED_JOBS, MODULE._FULL_CHAIN_PROOF_JOB)
    ]

    def fake_json(path):
        calls.append(path)
        return {"jobs": jobs}

    monkeypatch.setattr(MODULE, "github_json", fake_json)
    cache = {}

    first = MODULE.proven_natural_schedule_run_ids(
        "a/b",
        workflow_runs,
        cache,
        now=NOW,
        coverage_window_hours=6,
    )
    second = MODULE.proven_natural_schedule_run_ids(
        "a/b",
        workflow_runs,
        cache,
        now=NOW,
        coverage_window_hours=6,
    )

    assert first == second
    assert len(calls) <= 6
    assert len(calls) == len(cache)


def test_component_health_ignores_schedule_canary_after_cancelled_dispatch(monkeypatch):
    workflow_runs = [
        {
            "id": 8,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "cancelled",
            "created_at": "2026-08-04T01:40:00Z",
            "updated_at": "2026-08-04T01:50:00Z",
            "html_url": "https://github.com/a/b/actions/runs/8",
        },
        {
            "id": 7,
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-08-04T01:20:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
            "html_url": "https://github.com/a/b/actions/runs/7",
        },
    ]
    monkeypatch.setattr(
        MODULE,
        "github_json",
        lambda path: {
            "jobs": [{"name": "schedule-canary", "conclusion": "success"}]
        }
        if path.endswith("/jobs?per_page=100")
        else pytest.fail(path),
    )

    result = MODULE.workflow_component_health("a/b", workflow_runs)

    assert result == {
        "assessed": False,
        "healthy": True,
        "issues": [],
        "scanSucceeded": None,
    }


def test_component_health_cancelled_run_does_not_hide_previous_failure(monkeypatch):
    workflow_runs = [
        {
            "id": 9,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "cancelled",
            "created_at": "2026-08-04T01:40:00Z",
            "updated_at": "2026-08-04T01:50:00Z",
            "html_url": "https://github.com/a/b/actions/runs/9",
        },
        {
            "id": 8,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "failure",
            "created_at": "2026-08-04T01:20:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
            "html_url": "https://github.com/a/b/actions/runs/8",
        },
    ]
    monkeypatch.setattr(
        MODULE,
        "github_json",
        lambda path: (
            {
                "jobs": [
                    {"name": "scan", "conclusion": "failure"},
                    {"name": "watch", "conclusion": "success"},
                    {"name": "pr-followup", "conclusion": "success"},
                    {"name": "build-state", "conclusion": "success"},
                    {"name": "persist-pending", "conclusion": "success"},
                    {"name": "notify", "conclusion": "success"},
                    {"name": "persist-receipt", "conclusion": "success"},
                ]
            }
            if path == "repos/a/b/actions/runs/8/jobs?per_page=100"
            else pytest.fail(path)
        ),
    )

    result = MODULE.workflow_component_health("a/b", workflow_runs)

    assert result["runId"] == 8
    assert result["healthy"] is False
    assert result["issues"] == ["SCAN_JOB_DEGRADED"]


def test_only_cancelled_run_provides_no_success_evidence():
    workflow_runs = [
        {
            "id": 9,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "cancelled",
            "created_at": "2026-08-04T01:40:00Z",
            "updated_at": "2026-08-04T01:50:00Z",
            "html_url": "https://github.com/a/b/actions/runs/9",
        }
    ]

    component = MODULE.workflow_component_health("a/b", workflow_runs)
    freshness = MODULE.effective_scan_freshness(
        workflow_runs,
        now=NOW,
        component_health=component,
    )
    schedule = MODULE.health(workflow_runs, now=NOW)

    assert component == {
        "assessed": False,
        "healthy": True,
        "issues": [],
        "scanSucceeded": None,
    }
    assert freshness["fresh"] is False
    assert schedule["healthy"] is False


def test_component_health_exposes_followup_failure_without_discarding_fresh_scan(
    monkeypatch,
):
    workflow_runs = [
        {
            "id": 8,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "failure",
            "created_at": "2026-08-04T01:20:00Z",
            "updated_at": "2026-08-04T01:30:00Z",
            "html_url": "https://github.com/a/b/actions/runs/8",
        }
    ]
    conclusions = {
        "scan": "success",
        "watch": "success",
        "pr-followup": "failure",
        "build-state": "success",
        "persist-pending": "success",
        "notify": "success",
        "persist-receipt": "success",
    }
    monkeypatch.setattr(
        MODULE,
        "github_json",
        lambda _path: {
            "jobs": [
                {"name": name, "conclusion": conclusion} for name, conclusion in conclusions.items()
            ]
        },
    )

    component = MODULE.workflow_component_health("a/b", workflow_runs)
    freshness = MODULE.effective_scan_freshness(
        workflow_runs,
        now=NOW,
        component_health=component,
    )

    assert component["healthy"] is False
    assert component["issues"] == ["PR_FOLLOWUP_DEGRADED"]
    assert freshness["fresh"] is True
    assert freshness["recentScanJobSuccess"] is True


def test_github_actions_billing_block_is_detected_from_job_annotation(monkeypatch):
    workflow_runs = [
        {
            "id": 42,
            "event": "workflow_dispatch",
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
            "event": "workflow_dispatch",
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


def test_unproven_natural_component_does_not_keep_effective_scan_fresh():
    natural = {
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "updated_at": (NOW - timedelta(minutes=4)).isoformat(),
        "html_url": "https://github.com/a/b/actions/runs/canary",
    }
    result = MODULE.effective_scan_freshness(
        [natural],
        now=NOW,
        component_health={
            "assessed": True,
            "scanSucceeded": True,
            "runEvent": "schedule",
            "naturalFullChainProven": False,
            "runUpdatedAt": natural["updated_at"],
        },
    )

    assert result["fresh"] is False
    assert result["recentScanJobSuccess"] is False


def test_late_schedule_canary_does_not_mask_a_stale_full_scan():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "schedule",
                "status": "completed",
                "conclusion": "success",
                "created_at": (NOW - timedelta(minutes=5)).isoformat(),
                "updated_at": (NOW - timedelta(minutes=4)).isoformat(),
                "html_url": "https://github.com/a/b/actions/runs/canary",
            },
            {
                "event": "workflow_dispatch",
                "status": "completed",
                "conclusion": "success",
                "created_at": (NOW - timedelta(hours=3)).isoformat(),
                "updated_at": (NOW - timedelta(hours=2, minutes=50)).isoformat(),
                "html_url": "https://github.com/a/b/actions/runs/full-scan",
            },
        ],
        now=NOW,
    )

    assert result["fresh"] is False
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


def test_stale_full_scan_is_not_fresh():
    result = MODULE.effective_scan_freshness(
        [
            {
                "event": "workflow_dispatch",
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


def test_main_reports_stale_scan_without_dispatching_a_repair(monkeypatch, capsys):
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
    monkeypatch.setattr(MODULE, "runs", lambda _repo: stale_runs)
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "runtime_managed_followup_coverage", _healthy_managed_followup)
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["effectiveScan"]["fresh"] is False
    assert result["repairTriggered"] is False
    assert result["repairWouldTrigger"] is False
    assert result["repairSuppressedReason"] == "REPAIR_OWNED_BY_SCHEDULER_WATCHDOG"
    assert not hasattr(MODULE, "dispatch_scan")


def test_dispatch_blocker_does_not_poison_natural_canary_health(monkeypatch, capsys):
    recent_runs = [
        {
            "event": "schedule",
            "status": "completed",
            "conclusion": "success",
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "html_url": "https://github.com/a/b/actions/runs/canary",
        },
        {
            "id": 42,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "failure",
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "html_url": "https://github.com/a/b/actions/runs/42",
        },
    ]
    monkeypatch.setattr(MODULE, "runs", lambda _repo: recent_runs)
    monkeypatch.setattr(
        MODULE,
        "workflow_component_health",
        lambda *_args: {
            "assessed": True,
            "healthy": False,
            "issues": ["WORKFLOW_COMPONENT_STATUS_UNAVAILABLE"],
            "scanSucceeded": None,
        },
    )
    monkeypatch.setattr(
        MODULE,
        "github_actions_external_blocker",
        lambda *_args: {
            "code": "GITHUB_ACTIONS_BILLING_BLOCKED",
            "runUrl": "https://github.com/a/b/actions/runs/42",
            "message": "spending limit needs to be increased",
        },
    )
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "runtime_managed_followup_coverage", _healthy_managed_followup)
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["githubNaturalScheduleHealthy"] is False
    assert "NATURAL_SCHEDULE_FULL_CHAIN_UNPROVEN" in result["githubNaturalScheduleIssues"]
    assert result["operationalHealthy"] is False
    assert "GITHUB_ACTIONS_BILLING_BLOCKED" in result["operationalIssues"]


def test_component_degradation_is_unhealthy_without_repeating_a_successful_scan(
    monkeypatch, capsys
):
    failed_run = {
        "id": 44,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
        "html_url": "https://github.com/a/b/actions/runs/44",
    }
    component = {
        "assessed": True,
        "healthy": False,
        "issues": ["PR_FOLLOWUP_DEGRADED"],
        "scanSucceeded": True,
        "runUpdatedAt": failed_run["updated_at"],
        "runUrl": failed_run["html_url"],
    }
    monkeypatch.setattr(MODULE, "runs", lambda _repo: [failed_run])
    monkeypatch.setattr(MODULE, "workflow_component_health", lambda *_args: component)
    monkeypatch.setattr(MODULE, "github_actions_external_blocker", lambda *_args: None)
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "runtime_managed_followup_coverage", _healthy_managed_followup)
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["effectiveScan"]["fresh"] is True
    assert result["repairWouldTrigger"] is False
    assert result["operationalHealthy"] is False
    assert "PR_FOLLOWUP_DEGRADED" in result["operationalIssues"]


def test_health_external_actions_require_authorization_before_github_or_feishu(monkeypatch, capsys):
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
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", "--notify"],
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


def test_notify_surfaces_a_stale_full_scan_even_when_canary_is_fresh(monkeypatch, capsys):
    canary = {
        "id": 7,
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": (datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
        "updated_at": (datetime.now(UTC) - timedelta(minutes=9)).isoformat(),
        "html_url": "https://github.com/a/b/actions/runs/canary",
    }
    sent = []

    class Client:
        def __init__(self, *_args):
            pass

        def send_card(self, card, *, idempotency_key):
            sent.append((card, idempotency_key))

    monkeypatch.setattr(MODULE, "runs", lambda _repo: [canary])
    monkeypatch.setattr(MODULE, "github_actions_external_blocker", lambda *_args: None)
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "require_operational_authorization", lambda _root: None)
    monkeypatch.setattr(MODULE, "runtime_managed_followup_coverage", _healthy_managed_followup)
    monkeypatch.setattr(MODULE, "FeishuClient", Client)
    for name in ("FEISHU_APP_ID", "FEISHU_APP_SECRET", "FEISHU_CHAT_ID"):
        monkeypatch.setenv(name, name.casefold())
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", "--notify"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["githubNaturalScheduleHealthy"] is False
    assert "NATURAL_SCHEDULE_FULL_CHAIN_UNPROVEN" in result["githubNaturalScheduleIssues"]
    assert result["effectiveScan"]["fresh"] is False
    assert "EFFECTIVE_SCAN_STALE" in result["operationalIssues"]
    assert len(sent) == 1
    assert "EFFECTIVE_SCAN_STALE" in json.dumps(sent[0][0])


def test_notify_includes_managed_followup_coverage_failure(monkeypatch, capsys):
    recent = {
        "id": 7,
        "event": "schedule",
        "status": "completed",
        "conclusion": "success",
        "created_at": (datetime.now(UTC) - timedelta(minutes=30)).isoformat(),
        "updated_at": (datetime.now(UTC) - timedelta(minutes=20)).isoformat(),
        "html_url": "https://github.com/a/b/actions/runs/7",
    }
    sent = []

    class Client:
        def __init__(self, *_args):
            pass

        def send_card(self, card, *, idempotency_key):
            sent.append((card, idempotency_key))

    monkeypatch.setattr(MODULE, "runs", lambda _repo: [recent])
    monkeypatch.setattr(
        MODULE,
        "workflow_component_health",
        lambda *_args: {
            "assessed": True,
            "healthy": True,
            "issues": [],
            "scanSucceeded": True,
            "runUpdatedAt": recent["updated_at"],
            "runUrl": recent["html_url"],
        },
    )
    monkeypatch.setattr(MODULE, "github_actions_external_blocker", lambda *_args: None)
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "require_operational_authorization", lambda _root: None)
    monkeypatch.setattr(
        MODULE,
        "runtime_managed_followup_coverage",
        lambda _root: {
            "assessed": True,
            "healthy": False,
            "issues": ["MANAGED_PR_FOLLOWUP_MISSING"],
            "openCount": 67,
            "coveredCount": 40,
        },
    )
    monkeypatch.setattr(MODULE, "FeishuClient", Client)
    for name in ("FEISHU_APP_ID", "FEISHU_APP_SECRET", "FEISHU_CHAT_ID"):
        monkeypatch.setenv(name, name.casefold())
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_workflow_health.py", "--runtime-root", "/tmp/radar-runtime", "--notify"],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["managedFollowupCoverage"]["healthy"] is False
    assert len(sent) == 1
    assert "MANAGED_PR_FOLLOWUP_MISSING" in json.dumps(sent[0][0])


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
    assert "--repair" not in completed.stdout
