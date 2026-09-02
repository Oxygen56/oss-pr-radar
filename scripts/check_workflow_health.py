#!/usr/bin/env python3
"""Read-only health checks for the schedule canary and full remote scans."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import sleep

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.notifier import FeishuClient  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.release_binding import bind_runtime, runtime_ledger_path  # noqa: E402
from oss_pr_radar.util import parse_time, sha256_json  # noqa: E402

_FULL_SCAN_EVENT = "workflow_dispatch"
_NATURAL_EVENT = "schedule"
_NATURAL_REQUIRED_JOBS = (
    "watch",
    "pr-followup",
    "scan",
    "build-state",
    "persist-pending",
    "notify",
    "persist-receipt",
)
_FULL_CHAIN_PROOF_JOB = "full-chain-proof"
_STATE_JOBS = {"build-state", "persist-pending", "persist-receipt"}
_MANAGED_FOLLOWUP_MAX_AGE = timedelta(minutes=150)


def github_json(path: str) -> object:
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
                    path,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if completed.returncode == 0:
                return json.loads(completed.stdout)
            last_error = (completed.stderr or completed.stdout or last_error)[:300]
        except (json.JSONDecodeError, OSError, subprocess.SubprocessError) as exc:
            last_error = f"{type(exc).__name__}:{str(exc)[:240]}"
    raise RuntimeError(last_error)


def runs(repo: str) -> list[dict]:
    value = github_json(f"repos/{repo}/actions/workflows/radar.yml/runs?per_page=100")
    if not isinstance(value, dict):
        return []
    return value.get("workflow_runs") or []


def _run_jobs(repo: str, run_id: int) -> list[dict] | None:
    """Return the jobs for a run, or ``None`` when the API response is unusable."""

    value = github_json(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")
    jobs = value.get("jobs") if isinstance(value, dict) else None
    return jobs if isinstance(jobs, list) else None


def _job_conclusions(jobs: list[dict]) -> dict[str, str]:
    return {
        str(job.get("name")): str(job.get("conclusion") or job.get("status") or "unknown")
        for job in jobs
        if isinstance(job, dict) and job.get("name")
    }


def _natural_chain_issues(conclusions: dict[str, str]) -> list[str]:
    """Require every business job and the terminal proof job to finish successfully."""

    issues: list[str] = []
    missing = [name for name in (*_NATURAL_REQUIRED_JOBS, _FULL_CHAIN_PROOF_JOB) if name not in conclusions]
    if missing:
        issues.append("NATURAL_FULL_CHAIN_PROOF_MISSING")
    failed = [
        name
        for name in (*_NATURAL_REQUIRED_JOBS, _FULL_CHAIN_PROOF_JOB)
        if conclusions.get(name) != "success"
    ]
    if failed:
        issues.append("NATURAL_FULL_CHAIN_DEGRADED")
    return issues


def workflow_component_health(repo: str, workflow_runs: list[dict]) -> dict:
    """Assess the latest completed full chain below its aggregate conclusion.

    A scheduled run is only evidence of a real scan when the Jobs API shows all
    business jobs and the terminal ``full-chain-proof`` job succeeded.  This
    deliberately rejects the historical schedule-canary-only runs.  Manual
    dispatch remains a valid full scan and does not need the natural proof job.
    """

    completed = [
        item
        for item in workflow_runs
        if item.get("event") in {_FULL_SCAN_EVENT, _NATURAL_EVENT}
        and item.get("status") == "completed"
        and item.get("conclusion") != "cancelled"
        and item.get("id")
        and (item.get("updated_at") or item.get("created_at"))
    ]
    ordered = sorted(
        completed,
        key=lambda item: parse_time(str(item.get("updated_at") or item.get("created_at"))),
        reverse=True,
    )
    if not ordered:
        return {
            "assessed": False,
            "healthy": True,
            "issues": [],
            "scanSucceeded": None,
        }
    for latest in ordered:
        run_id = int(latest["id"])
        base = {
            "assessed": True,
            "runId": run_id,
            "runUrl": latest.get("html_url"),
            "runEvent": latest.get("event"),
            "runUpdatedAt": latest.get("updated_at") or latest.get("created_at"),
        }
        try:
            jobs = _run_jobs(repo, run_id)
        except (RuntimeError, TypeError, ValueError) as exc:
            return {
                **base,
                "healthy": False,
                "issues": ["WORKFLOW_COMPONENT_STATUS_UNAVAILABLE"],
                "scanSucceeded": None,
                "error": f"{type(exc).__name__}:{str(exc)[:200]}",
            }
        if jobs is None:
            return {
                **base,
                "healthy": False,
                "issues": ["WORKFLOW_COMPONENT_STATUS_UNAVAILABLE"],
                "scanSucceeded": None,
            }
        conclusions = _job_conclusions(jobs)
        if latest.get("event") == _NATURAL_EVENT:
            natural_issues = _natural_chain_issues(conclusions)
            # A schedule-canary-only run is not a failed scan and must not hide
            # an older manual scan; it is simply not usable as scan evidence.
            if natural_issues:
                if (
                    "NATURAL_FULL_CHAIN_PROOF_MISSING" in natural_issues
                    and not any(name in conclusions for name in _NATURAL_REQUIRED_JOBS)
                ):
                    continue
                return {
                    **base,
                    "healthy": False,
                    "issues": natural_issues,
                    "scanSucceeded": conclusions.get("scan") == "success",
                    "jobs": conclusions,
                    "naturalFullChainProven": False,
                }
            return {
                **base,
                "healthy": True,
                "issues": [],
                "scanSucceeded": True,
                "jobs": conclusions,
                "naturalFullChainProven": True,
            }
        issues: list[str] = []
        scan_succeeded = conclusions.get("scan") == "success"
        if not scan_succeeded:
            issues.append("SCAN_JOB_DEGRADED")
        if conclusions.get("pr-followup") != "success":
            issues.append("PR_FOLLOWUP_DEGRADED")
        if any(conclusions.get(name) != "success" for name in _STATE_JOBS):
            issues.append("STATE_PERSISTENCE_DEGRADED")
        if conclusions.get("notify") != "success":
            issues.append("NOTIFICATION_DEGRADED")
        return {
            **base,
            "healthy": not issues,
            "issues": issues,
            "scanSucceeded": scan_succeeded,
            "jobs": conclusions,
            "naturalFullChainProven": False,
        }
    return {
        "assessed": False,
        "healthy": True,
        "issues": [],
        "scanSucceeded": None,
    }


def github_actions_external_blocker(repo: str, workflow_runs: list[dict]) -> dict | None:
    latest_success_at = max(
        (
            parse_time(str(item.get("updated_at") or item.get("created_at")))
            for item in workflow_runs
            if item.get("event") == _FULL_SCAN_EVENT
            and item.get("conclusion") == "success"
            and (item.get("updated_at") or item.get("created_at"))
        ),
        default=None,
    )
    failed = next(
        (
            item
            for item in workflow_runs
            if item.get("event") == _FULL_SCAN_EVENT
            and item.get("conclusion") == "failure"
            and item.get("id")
            and (
                latest_success_at is None
                or not (item.get("updated_at") or item.get("created_at"))
                or parse_time(str(item.get("updated_at") or item.get("created_at")))
                > latest_success_at
            )
        ),
        None,
    )
    if failed is None:
        return None
    try:
        jobs_value = github_json(f"repos/{repo}/actions/runs/{failed['id']}/jobs")
        jobs = jobs_value.get("jobs") or [] if isinstance(jobs_value, dict) else []
        for job in jobs:
            if (
                job.get("conclusion") != "failure"
                or job.get("steps")
                or job.get("runner_id") not in {0, None}
            ):
                continue
            check_url = str(job.get("check_run_url") or "")
            check_id = check_url.rsplit("/", 1)[-1]
            if not check_id.isdigit():
                continue
            annotations = github_json(f"repos/{repo}/check-runs/{check_id}/annotations")
            for annotation in annotations if isinstance(annotations, list) else []:
                message = str(annotation.get("message") or "")
                normalized = message.casefold()
                if "payments have failed" in normalized or "spending limit" in normalized:
                    return {
                        "code": "GITHUB_ACTIONS_BILLING_BLOCKED",
                        "runUrl": failed.get("html_url"),
                        "message": message,
                    }
    except (RuntimeError, TypeError, ValueError):
        return None
    return None


def health(
    workflow_runs: list[dict],
    *,
    now: datetime | None = None,
    coverage_window_hours: int = 12,
) -> dict:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    scheduled = [item for item in workflow_runs if item.get("event") == "schedule"]
    successful = [item for item in scheduled if item.get("conclusion") == "success"]
    issues: list[str] = []
    coverage_warnings: list[str] = []
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

    window_hours = max(6, min(int(coverage_window_hours), 24))
    coverage_window = timedelta(hours=window_hours)
    window_start = current - coverage_window
    run_times = [parse_time(item["created_at"]) for item in workflow_runs if item.get("created_at")]
    coverage_assessed = bool(run_times and min(run_times) <= window_start)
    successful_times = sorted(
        parse_time(item["created_at"])
        for item in successful
        if item.get("created_at") and parse_time(item["created_at"]) >= window_start
    )
    expected_runs = window_hours
    minimum_runs = max(3, window_hours // 2)
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
        coverage_warnings.append("NATURAL_SCHEDULE_COVERAGE_LOW")
    if coverage_assessed and max_gap_minutes is not None and max_gap_minutes > 150:
        coverage_warnings.append("NATURAL_SCHEDULE_GAP_EXCESSIVE")
    return {
        "healthy": not issues,
        "issues": issues,
        "healthScope": "github_actions_schedule",
        "githubNaturalScheduleHealthy": not issues,
        "githubNaturalScheduleIssues": issues,
        "githubNaturalScheduleWarnings": coverage_warnings,
        # Compatibility fields for older controller prompts and reports.
        "naturalScheduleHealthy": not issues,
        "naturalScheduleIssues": issues,
        "naturalScheduleWarnings": coverage_warnings,
        "latestScheduleUrl": latest_schedule.get("html_url") if latest_schedule else None,
        "latestSuccessUrl": latest_success.get("html_url") if latest_success else None,
        "naturalScheduleCoverage": {
            "assessed": coverage_assessed,
            "windowHours": window_hours,
            "successfulRuns": len(successful_times),
            "expectedRuns": expected_runs,
            "minimumRuns": minimum_runs,
            "coverageRatio": round(coverage_ratio, 3),
            "maxGapMinutes": max_gap_minutes,
            "warnings": coverage_warnings,
        },
        "checkedAt": current.isoformat().replace("+00:00", "Z"),
    }


def managed_followup_coverage(
    path: Path,
    *,
    now: datetime | None = None,
    max_age: timedelta = _MANAGED_FOLLOWUP_MAX_AGE,
) -> dict:
    """Require a current follow-up observation for every managed open PR head."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    if not path.is_file():
        return {
            "assessed": False,
            "healthy": False,
            "issues": ["MANAGED_PR_FOLLOWUP_COVERAGE_UNAVAILABLE"],
            "reason": "managed_ledger_unavailable",
            "openCount": 0,
            "coveredCount": 0,
        }
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if not {"managed_prs", "managed_ci_runs", "managed_lifecycle_events"} <= tables:
            return {
                "assessed": False,
                "healthy": False,
                "issues": ["MANAGED_PR_FOLLOWUP_COVERAGE_UNAVAILABLE"],
                "reason": "managed_schema_unavailable",
                "openCount": 0,
                "coveredCount": 0,
            }
        rows = connection.execute(
            """SELECT p.pr_key,p.pr_url,p.head_sha,p.observed_at AS pr_observed_at,
                      p.latest_source,
                      c.head_sha AS snapshot_head_sha,c.observed_at AS snapshot_observed_at,
                      (SELECT MAX(e.observed_at) FROM managed_lifecycle_events e
                       WHERE e.pr_key=p.pr_key
                         AND e.event_type='PUBLICATION_RECEIPT_OBSERVED')
                        AS publication_observed_at
               FROM managed_prs p
               LEFT JOIN managed_ci_runs c ON c.rowid=(
                   SELECT c2.rowid FROM managed_ci_runs c2
                   WHERE c2.pr_key=p.pr_key AND c2.ci_key LIKE 'followup:%'
                   ORDER BY c2.observed_at DESC,c2.rowid DESC LIMIT 1
               )
               WHERE p.state='OPEN' ORDER BY p.pr_key"""
        ).fetchall()
    finally:
        connection.close()

    missing: list[str] = []
    head_mismatches: list[str] = []
    predates_publication: list[str] = []
    stale: list[str] = []
    covered = 0
    cutoff = current - max_age
    for row in rows:
        key = str(row["pr_key"])
        snapshot_at = str(row["snapshot_observed_at"] or "")
        if not snapshot_at:
            missing.append(key)
            continue
        if str(row["snapshot_head_sha"] or "") != str(row["head_sha"] or ""):
            head_mismatches.append(key)
            continue
        try:
            snapshot_time = parse_time(snapshot_at)
        except (TypeError, ValueError):
            predates_publication.append(key)
            continue
        publication_at = str(row["publication_observed_at"] or "")
        if not publication_at and str(row["latest_source"] or "") == "publication":
            publication_at = str(row["pr_observed_at"] or "")
        if publication_at:
            try:
                if snapshot_time < parse_time(publication_at):
                    predates_publication.append(key)
                    continue
            except (TypeError, ValueError):
                predates_publication.append(key)
                continue
        if snapshot_time < cutoff:
            stale.append(key)
            continue
        covered += 1

    issues: list[str] = []
    if missing:
        issues.append("MANAGED_PR_FOLLOWUP_MISSING")
    if head_mismatches:
        issues.append("MANAGED_PR_FOLLOWUP_HEAD_STALE")
    if predates_publication:
        issues.append("MANAGED_PR_FOLLOWUP_PREDATES_PUBLICATION")
    if stale:
        issues.append("MANAGED_PR_FOLLOWUP_STALE")
    return {
        "assessed": True,
        "healthy": not issues,
        "issues": issues,
        "openCount": len(rows),
        "coveredCount": covered,
        "missingKeys": missing,
        "headMismatchKeys": head_mismatches,
        "predatesPublicationKeys": predates_publication,
        "staleKeys": stale,
        "maxAgeMinutes": int(max_age.total_seconds() // 60),
        "checkedAt": current.isoformat().replace("+00:00", "Z"),
    }


def runtime_managed_followup_coverage(runtime_root: Path) -> dict:
    """Resolve the immutable current ledger before checking local coverage."""

    return managed_followup_coverage(runtime_ledger_path(runtime_root))


def effective_scan_freshness(
    workflow_runs: list[dict],
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(minutes=110),
    active_grace: timedelta = timedelta(minutes=50),
    component_health: dict | None = None,
) -> dict:
    """Assess only full workflow-dispatch scans; schedule runs are canaries."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    relevant = [item for item in workflow_runs if item.get("event") == _FULL_SCAN_EVENT]
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
    component_success_fresh = False
    component_url = None
    if component_health and component_health.get("scanSucceeded") is True:
        component_updated_at = component_health.get("runUpdatedAt")
        if component_updated_at:
            component_success_fresh = parse_time(str(component_updated_at)) >= current - max_age
            component_url = component_health.get("runUrl")
    return {
        "fresh": success_fresh or component_success_fresh or latest_active is not None,
        "recentSuccess": success_fresh or component_success_fresh,
        "recentScanJobSuccess": component_success_fresh,
        "recentActive": latest_active is not None,
        "latestEffectiveUrl": (
            (latest_active or {}).get("html_url")
            or component_url
            or (latest_success or {}).get("html_url")
        ),
        "maxAgeMinutes": int(max_age.total_seconds() // 60),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="Oxygen56/oss-pr-radar")
    parser.add_argument("--runtime-root", type=Path, default=None)
    parser.add_argument("--code-root", type=Path, default=None)
    parser.add_argument("--notify", action="store_true")
    parser.add_argument("--max-effective-age-minutes", type=int, default=110)
    parser.add_argument("--coverage-window-hours", type=int, default=12)
    args = parser.parse_args()
    if args.runtime_root is not None:
        try:
            bind_runtime(args.runtime_root, code_root=args.code_root)
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": f"runtime binding required: {str(exc)[:300]}",
                    }
                )
            )
            return 2
    if args.notify:
        if args.runtime_root is None:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "--runtime-root is required for notify",
                    }
                )
            )
            return 2
        try:
            require_operational_authorization(args.runtime_root)
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": f"operational authorization required: {str(exc)[:300]}",
                    }
                )
            )
            return 2
    workflow_runs = runs(args.repo)
    result = health(workflow_runs, coverage_window_hours=args.coverage_window_hours)
    component_health = workflow_component_health(args.repo, workflow_runs)
    result["componentHealth"] = component_health
    external_blocker = github_actions_external_blocker(args.repo, workflow_runs)
    result["githubActionsExternalBlocker"] = external_blocker
    managed_coverage = (
        runtime_managed_followup_coverage(args.runtime_root)
        if args.runtime_root is not None
        else {
            "assessed": False,
            "healthy": True,
            "issues": [],
            "reason": "runtime_root_not_provided",
            "openCount": 0,
            "coveredCount": 0,
        }
    )
    result["managedFollowupCoverage"] = managed_coverage
    effective = effective_scan_freshness(
        workflow_runs,
        max_age=timedelta(minutes=max(15, args.max_effective_age_minutes)),
        component_health=component_health,
    )
    result["effectiveScan"] = effective
    # Compatibility fields remain read-only. The scheduler watchdog is the sole
    # owner of workflow-dispatch writes.
    result["repairTriggered"] = False
    result["repairReconciled"] = False
    result["repairWouldTrigger"] = False
    result["repairError"] = None
    result["repairSuppressedReason"] = "REPAIR_OWNED_BY_SCHEDULER_WATCHDOG"
    scan_health_issues = [] if effective["fresh"] else ["EFFECTIVE_SCAN_STALE"]
    result["operationalHealthy"] = bool(
        effective["fresh"]
        and component_health.get("healthy") is True
        and managed_coverage.get("healthy") is True
        and external_blocker is None
    )
    result["operationalIssues"] = list(
        dict.fromkeys(
            [
                *result["issues"],
                *scan_health_issues,
                *(component_health.get("issues") or []),
                *(managed_coverage.get("issues") or []),
                *([str(external_blocker["code"])] if external_blocker else []),
            ]
        )
    )
    if args.notify and (
        not effective["fresh"]
        or component_health.get("healthy") is not True
        or managed_coverage.get("healthy") is not True
        or external_blocker is not None
    ):
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
                            "content": "\n".join(result["operationalIssues"]),
                        },
                    }
                ],
            },
            idempotency_key=sha256_json(
                {"issues": result["operationalIssues"], "hour": result["checkedAt"][:13]}
            ),
        )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["operationalHealthy"] is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
