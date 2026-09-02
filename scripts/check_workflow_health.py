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
from oss_pr_radar.scheduler_watchdog import (  # noqa: E402
    BUSINESS_CHAIN_JOBS,
    eligible_slot,
    full_chain_evidence,
    normalize_job_conclusions,
    proven_watchdog_run_ids,
)
from oss_pr_radar.util import parse_time, sha256_json  # noqa: E402

_FULL_SCAN_EVENT = "workflow_dispatch"
_FULL_CHAIN_EVENTS = frozenset({"schedule", _FULL_SCAN_EVENT})
_MANAGED_FOLLOWUP_MAX_AGE = timedelta(minutes=150)
_ACTIVE_RUN_STATUSES = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})


def _run_id(value: dict) -> str | None:
    raw = value.get("id")
    if isinstance(raw, bool) or raw is None:
        return None
    encoded = str(raw)
    return encoded if encoded.isdigit() and int(encoded) > 0 else None


def _natural_full_chain_proven(
    run: dict,
    *,
    proven_run_ids: set[str] | frozenset[str] | None = None,
    allow_legacy_aggregate: bool = False,
) -> bool:
    """Return whether a schedule run has an explicit full-chain proof.

    ``proven_run_ids`` is supplied by the live jobs observer.  Without it,
    embedded evidence (used by fixtures and callers that already queried
    jobs) is honored.  A run-list-only schedule is deliberately unproven.
    The live ``main`` path passes a set,
    including an empty set when no schedule run was proven, so old canaries
    cannot leak into health or coverage.
    """

    if run.get("event") != "schedule":
        return False
    run_id = _run_id(run)
    if proven_run_ids is not None:
        return run_id is not None and run_id in {str(value) for value in proven_run_ids}
    evidence = full_chain_evidence(run)
    if evidence is True:
        return True
    # ``health()`` is also used by older local callers that only have the
    # workflow-runs response. Keep that call shape compatible when no
    # explicit proof set was requested. Production ``main`` always passes a
    # set (including an empty set), so unqueried schedules remain fail-closed.
    return (
        allow_legacy_aggregate
        and evidence is None
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    )


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


def workflow_component_health(repo: str, workflow_runs: list[dict]) -> dict:
    """Assess the latest completed run below its aggregate conclusion."""

    completed = [
        item
        for item in workflow_runs
        if item.get("event") in _FULL_CHAIN_EVENTS
        and item.get("status") == "completed"
        and item.get("conclusion") != "cancelled"
        and item.get("id")
        and (item.get("updated_at") or item.get("created_at"))
    ]
    latest = max(
        completed,
        key=lambda item: (
            parse_time(str(item.get("created_at") or item.get("updated_at"))),
            int(item["id"]),
        ),
        default=None,
    )
    if latest is None:
        return {
            "assessed": False,
            "healthy": True,
            "issues": [],
            "scanSucceeded": None,
        }

    run_id = int(latest["id"])
    base = {
        "assessed": True,
        "runId": run_id,
        "runUrl": latest.get("html_url"),
        "runEvent": latest.get("event"),
        "runUpdatedAt": latest.get("updated_at") or latest.get("created_at"),
    }
    try:
        jobs_value = github_json(f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")
    except (RuntimeError, TypeError, ValueError) as exc:
        return {
            **base,
            "healthy": False,
            "issues": ["WORKFLOW_COMPONENT_STATUS_UNAVAILABLE"],
            "scanSucceeded": None,
            "error": f"{type(exc).__name__}:{str(exc)[:200]}",
        }
    jobs = jobs_value.get("jobs") if isinstance(jobs_value, dict) else None
    if not isinstance(jobs, list):
        return {
            **base,
            "healthy": False,
            "issues": ["WORKFLOW_COMPONENT_STATUS_UNAVAILABLE"],
            "scanSucceeded": None,
        }
    conclusions = normalize_job_conclusions(jobs)
    issues: list[str] = []
    full_chain_proven = (
        full_chain_evidence(latest, jobs) if latest.get("event") == "schedule" else True
    )
    natural_full_chain_ids = (
        [str(run_id)]
        if latest.get("event") == "schedule" and full_chain_proven is True
        else []
    )
    if latest.get("event") == "schedule" and full_chain_proven is not True:
        # A successful aggregate schedule run with only ``schedule-canary``
        # is exactly the historical false-green case.  Do not fall back to an
        # older manual run when reporting the latest chain.
        issues.append("NATURAL_SCHEDULE_FULL_CHAIN_MISSING")
    scan_succeeded = conclusions.get("scan") == "success"
    if not scan_succeeded and "NATURAL_SCHEDULE_FULL_CHAIN_MISSING" not in issues:
        issues.append("SCAN_JOB_DEGRADED")
    if conclusions.get("pr-followup") != "success":
        issues.append("PR_FOLLOWUP_DEGRADED")
    if any(
        conclusions.get(name) != "success"
        for name in BUSINESS_CHAIN_JOBS - {"scan", "pr-followup", "notify"}
    ):
        issues.append("STATE_PERSISTENCE_DEGRADED")
    if conclusions.get("notify") != "success":
        issues.append("NOTIFICATION_DEGRADED")
    result = {
        **base,
        "healthy": not issues,
        "issues": issues,
        "scanSucceeded": scan_succeeded,
        "jobs": conclusions,
        "fullChainProven": full_chain_proven,
    }
    if latest.get("event") == "schedule":
        result["naturalFullChainRunIds"] = natural_full_chain_ids
    return result


def collect_natural_full_chain_run_ids(
    repo: str,
    workflow_runs: list[dict],
    *,
    now: datetime | None = None,
    window_hours: int = 12,
) -> set[str]:
    """Collect proof-backed native runs for the requested coverage window.

    The workflow-runs endpoint has no representation for skipped jobs.  This
    bounded jobs lookup is therefore the source of truth for each schedule
    slot; manual dispatch IDs are intentionally never returned here.
    """

    current = (now or datetime.now(UTC)).astimezone(UTC)
    hours = max(6, min(int(window_hours), 24))
    cutoff = current - timedelta(hours=hours)
    proven: set[str] = set()
    for run in workflow_runs:
        if run.get("event") != "schedule" or not run.get("id"):
            continue
        try:
            created = parse_time(str(run.get("created_at")))
        except (TypeError, ValueError):
            continue
        if created < cutoff:
            continue
        run_id = _run_id(run)
        if run_id is None:
            continue
        if run.get("status") in _ACTIVE_RUN_STATUSES:
            # In-flight native runs are transient observations, not proof.
            # Keep them out of the completed/proven set so coverage and
            # freshness cannot report an active run as a successful slot.
            # The watchdog separately returns a ``natural_active`` wait
            # result while the run is within the current slot grace window.
            continue
        embedded = run.get("jobs")
        if embedded is not None:
            evidence = full_chain_evidence(run, embedded)
        elif isinstance(run.get("_fullChainProven"), bool):
            evidence = bool(run["_fullChainProven"])
        else:
            try:
                jobs_value = github_json(
                    f"repos/{repo}/actions/runs/{int(run_id)}/jobs?per_page=100"
                )
                jobs = jobs_value.get("jobs") if isinstance(jobs_value, dict) else None
                evidence = full_chain_evidence(run, jobs)
            except (RuntimeError, TypeError, ValueError, OSError):
                evidence = False
        if evidence is True:
            proven.add(run_id)
    return proven


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
    watchdog_run_ids: set[str] | frozenset[str] | None = None,
    natural_full_chain_run_ids: set[str] | frozenset[str] | None = None,
) -> dict:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    scheduled = sorted(
        (item for item in workflow_runs if item.get("event") == "schedule"),
        key=lambda item: parse_time(str(item.get("created_at"))),
        reverse=True,
    )
    successful = [
        item
        for item in scheduled
        if item.get("status") == "completed" and item.get("conclusion") == "success"
    ]
    proven_natural_ids = (
        None
        if natural_full_chain_run_ids is None
        else {str(value) for value in natural_full_chain_run_ids}
    )
    full_chain_successful = [
        item
        for item in successful
        if _natural_full_chain_proven(
            item,
            proven_run_ids=proven_natural_ids,
            allow_legacy_aggregate=proven_natural_ids is None,
        )
    ]
    canary_issues: list[str] = []
    full_chain_issues: list[str] = []
    coverage_warnings: list[str] = []
    latest_schedule = scheduled[0] if scheduled else None
    latest_success = successful[0] if successful else None
    if not latest_schedule:
        canary_issues.append("NO_NATURAL_SCHEDULE_RUN")
    else:
        if parse_time(latest_schedule["created_at"]) < current - timedelta(hours=2, minutes=30):
            canary_issues.append("NATURAL_SCHEDULE_STALE")
        if not (
            latest_schedule.get("status") == "completed"
            and latest_schedule.get("conclusion") == "success"
        ):
            canary_issues.append("LATEST_NATURAL_SCHEDULE_NOT_SUCCESSFUL")
        elif not _natural_full_chain_proven(
            latest_schedule,
            proven_run_ids=proven_natural_ids,
            allow_legacy_aggregate=proven_natural_ids is None,
        ):
            # Keep the trigger canary fields separate, but never let a
            # successful canary-only run make the overall natural service
            # appear healthy once live proof was requested.
            full_chain_issues.append("NATURAL_SCHEDULE_FULL_CHAIN_MISSING")
    if not latest_success:
        canary_issues.append("NO_SUCCESSFUL_SCHEDULE_RUN")
    elif parse_time(latest_success["updated_at"]) < current - timedelta(hours=4):
        canary_issues.append("SUCCESSFUL_SCHEDULE_STALE")
    if sum(item.get("conclusion") == "failure" for item in scheduled[:3]) >= 2:
        canary_issues.append("REPEATED_SCHEDULE_FAILURE")

    window_hours = max(6, min(int(coverage_window_hours), 24))
    coverage_window = timedelta(hours=window_hours)
    window_start = current - coverage_window
    run_times = [parse_time(item["created_at"]) for item in workflow_runs if item.get("created_at")]
    coverage_assessed = bool(run_times and min(run_times) <= window_start)
    successful_times = sorted(
        parse_time(item["created_at"])
        for item in full_chain_successful
        if item.get("created_at") and parse_time(item["created_at"]) >= window_start
    )
    expected_runs = window_hours
    minimum_runs = expected_runs
    coverage_ratio = min(1.0, len(successful_times) / expected_runs)
    gap_points = [window_start, *successful_times, current]
    max_gap_minutes = max(
        (
            int((right - left).total_seconds() // 60)
            for left, right in zip(gap_points, gap_points[1:], strict=False)
        ),
        default=None,
    )
    if coverage_assessed and len(successful_times) < expected_runs:
        coverage_warnings.append("NATURAL_SCHEDULE_COVERAGE_LOW")
    if coverage_assessed and max_gap_minutes is not None and max_gap_minutes > 150:
        coverage_warnings.append("NATURAL_SCHEDULE_GAP_EXCESSIVE")
    coverage_healthy = None if not coverage_assessed else not coverage_warnings
    canary_healthy = not canary_issues
    issues = [
        *canary_issues,
        *full_chain_issues,
        *(coverage_warnings if coverage_assessed else []),
    ]
    full_coverage = full_slot_coverage(
        workflow_runs,
        now=current,
        coverage_window_hours=window_hours,
        watchdog_run_ids=watchdog_run_ids,
        natural_full_chain_run_ids=proven_natural_ids,
    )
    natural_healthy = canary_healthy and not full_chain_issues and coverage_healthy is not False
    return {
        "healthy": natural_healthy,
        "issues": issues,
        "healthScope": "github_actions_schedule_and_full_scan_slots",
        "githubNaturalScheduleHealthy": natural_healthy,
        "githubNaturalScheduleIssues": issues,
        "githubNaturalScheduleWarnings": coverage_warnings,
        "naturalScheduleCanaryHealthy": canary_healthy,
        "naturalScheduleCanary": {
            "healthy": canary_healthy,
            "issues": canary_issues,
            "latestRunFresh": latest_schedule is not None
            and "NATURAL_SCHEDULE_STALE" not in canary_issues,
            "latestSuccessfulRunFresh": latest_success is not None
            and "SUCCESSFUL_SCHEDULE_STALE" not in canary_issues,
            "latestRunUrl": latest_schedule.get("html_url") if latest_schedule else None,
            "latestSuccessUrl": latest_success.get("html_url") if latest_success else None,
            "sourceEvent": "schedule",
        },
        # Compatibility fields for older controller prompts and reports.
        "naturalScheduleHealthy": natural_healthy,
        "naturalScheduleIssues": issues,
        "naturalScheduleWarnings": coverage_warnings,
        "latestScheduleUrl": latest_schedule.get("html_url") if latest_schedule else None,
        "latestSuccessUrl": latest_success.get("html_url") if latest_success else None,
        "naturalScheduleCoverage": {
            "assessed": coverage_assessed,
            "healthy": coverage_healthy,
            "windowHours": window_hours,
            "successfulRuns": len(successful_times),
            "expectedRuns": expected_runs,
            "minimumRuns": minimum_runs,
            "coverageRatio": round(coverage_ratio, 3),
            "maxGapMinutes": max_gap_minutes,
            "warnings": coverage_warnings,
        },
        "naturalScheduleFullChain": {
            "latestRunProven": _natural_full_chain_proven(
                latest_schedule,
                proven_run_ids=proven_natural_ids,
                allow_legacy_aggregate=proven_natural_ids is None,
            )
            if latest_schedule
            else False,
            "provenRunIds": sorted(proven_natural_ids or []),
            "issues": full_chain_issues,
        },
        "fullSlotCoverage": full_coverage,
        "checkedAt": current.isoformat().replace("+00:00", "Z"),
    }


def full_slot_coverage(
    workflow_runs: list[dict],
    *,
    now: datetime | None = None,
    coverage_window_hours: int = 12,
    slot_minute: int = 17,
    grace_minutes: int = 13,
    watchdog_run_ids: set[str] | frozenset[str] | None = None,
    natural_full_chain_run_ids: set[str] | frozenset[str] | None = None,
) -> dict:
    """Measure hourly scans with attributable full-chain evidence.

    Native schedule runs count only when their terminal proof job was observed
    (or an embedded proof marker is present).  A workflow-dispatch run counts
    only when its exact ID is present in the durable watchdog claim state;
    arbitrary/manual dispatch IDs are deliberately ignored.
    """

    current = (now or datetime.now(UTC)).astimezone(UTC)
    window_hours = max(6, min(int(coverage_window_hours), 24))
    latest_slot = eligible_slot(current, minute=slot_minute, grace_minutes=grace_minutes)
    expected = [latest_slot - timedelta(hours=offset) for offset in reversed(range(window_hours))]
    expected_set = set(expected)
    proven_ids = None if watchdog_run_ids is None else {str(value) for value in watchdog_run_ids}
    natural_ids = (
        None
        if natural_full_chain_run_ids is None
        else {str(value) for value in natural_full_chain_run_ids}
    )
    run_times = [
        parse_time(str(item["created_at"])) for item in workflow_runs if item.get("created_at")
    ]
    # The oldest returned run only needs to reach the first slot's one-hour
    # attribution interval. This stays false for short synthetic/API history.
    assessed = bool(
        (proven_ids is not None or natural_ids is not None)
        and run_times
        and min(run_times) < expected[0] + timedelta(hours=1)
    )
    by_slot: dict[datetime, list[dict]] = {slot: [] for slot in expected}
    for item in workflow_runs:
        event = item.get("event")
        if event not in _FULL_CHAIN_EVENTS or not item.get("created_at"):
            continue
        item_id = str(item.get("id"))
        if event == _FULL_SCAN_EVENT:
            # A dispatch is valid only when the watchdog durably owns its
            # exact run ID.  ``natural_ids`` never authorizes this branch.
            if proven_ids is None or item_id not in proven_ids:
                continue
        else:
            if natural_ids is not None:
                if item_id not in natural_ids:
                    continue
            elif watchdog_run_ids is not None:
                # The caller explicitly supplied watchdog evidence but no
                # natural proof set: do not let a canary enter full coverage.
                continue
            elif not _natural_full_chain_proven(item):
                continue
        created = parse_time(str(item["created_at"])).astimezone(UTC)
        slot = eligible_slot(created, minute=slot_minute, grace_minutes=grace_minutes)
        if slot in expected_set:
            by_slot[slot].append(item)

    covered: list[str] = []
    active: list[str] = []
    failed: list[str] = []
    missing: list[str] = []
    for slot in expected:
        items = by_slot[slot]
        encoded = slot.isoformat().replace("+00:00", "Z")
        if any(
            item.get("status") == "completed" and item.get("conclusion") == "success"
            for item in items
        ):
            covered.append(encoded)
        elif any(item.get("status") in _ACTIVE_RUN_STATUSES for item in items):
            active.append(encoded)
        elif items:
            failed.append(encoded)
        else:
            missing.append(encoded)

    ratio = len(covered) / len(expected) if expected else 0.0
    coverage_healthy = None if not assessed else not active and not failed and not missing
    issues: list[str] = []
    if assessed and active:
        issues.append("FULL_SLOT_RUN_ACTIVE")
    if assessed and failed:
        issues.append("FULL_SLOT_RUN_FAILED")
    if assessed and missing:
        issues.append("FULL_SLOT_COVERAGE_MISSING")
    return {
        "assessed": assessed,
        "healthy": coverage_healthy,
        "sourceEvent": (
            "schedule+workflow_dispatch" if natural_ids is not None else _FULL_SCAN_EVENT
        ),
        "evidenceSource": (
            "scheduler_watchdog_exact_run_id_and_natural_full_chain_proof"
            if natural_ids is not None
            else "scheduler_watchdog_exact_run_id"
        ),
        "evidenceAvailable": proven_ids is not None or natural_ids is not None,
        "watchdogRunIds": sorted(proven_ids or []),
        "naturalFullChainRunIds": sorted(natural_ids or []),
        "windowHours": window_hours,
        "expectedSlots": len(expected),
        "coveredSlots": len(covered),
        "activeSlots": active,
        "failedSlots": failed,
        "missingSlots": missing,
        "coverageRatio": round(ratio, 3),
        "issues": issues,
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
    natural_full_chain_run_ids: set[str] | frozenset[str] | None = None,
    watchdog_run_ids: set[str] | frozenset[str] | None = None,
) -> dict:
    """Assess fresh full-chain scans from either trigger.

    Dispatch runs enter the completed/active set only when their exact ID is
    in the durable watchdog claim set (when that set is supplied);
    component health independently verifies their jobs.  Schedule runs enter
    the completed-success set only with the terminal proof job (or embedded
    evidence), while an active schedule is conservatively treated as in-flight
    so the watchdog/health loop does not start a duplicate repair.
    """

    current = (now or datetime.now(UTC)).astimezone(UTC)
    proven_natural_ids = (
        None
        if natural_full_chain_run_ids is None
        else {str(value) for value in natural_full_chain_run_ids}
    )
    proven_watchdog_ids = (
        None
        if watchdog_run_ids is None
        else {str(value) for value in watchdog_run_ids}
    )
    relevant = [
        item
        for item in workflow_runs
        if (
            item.get("event") == _FULL_SCAN_EVENT
            and (
                proven_watchdog_ids is None
                or str(item.get("id")) in proven_watchdog_ids
            )
        )
        or (
            item.get("event") == "schedule"
            and _natural_full_chain_proven(item, proven_run_ids=proven_natural_ids)
        )
    ]
    successful = [item for item in relevant if item.get("conclusion") == "success"]
    active = [
        item
        for item in workflow_runs
        if item.get("status") in {"queued", "in_progress", "waiting", "requested", "pending"}
        and item.get("created_at")
        and parse_time(item["created_at"]) >= current - active_grace
        and (
            (
                item.get("event") == _FULL_SCAN_EVENT
                and (
                    proven_watchdog_ids is None
                    or str(item.get("id")) in proven_watchdog_ids
                )
            )
            or item.get("event") == "schedule"
        )
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
    component_run_id = (
        str(component_health.get("runId")) if component_health and component_health.get("runId") else None
    )
    component_dispatch_proven = (
        component_health is None
        or component_health.get("runEvent") != _FULL_SCAN_EVENT
        or proven_watchdog_ids is None
        or component_run_id in proven_watchdog_ids
    )
    component_is_full_chain = (
        component_health is None
        or component_health.get("runEvent") != "schedule"
        or component_health.get("fullChainProven") is True
    )
    if (
        component_health
        and component_health.get("scanSucceeded") is True
        and component_is_full_chain
        and component_dispatch_proven
    ):
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
    watchdog_run_ids = (
        proven_watchdog_run_ids(args.runtime_root) if args.runtime_root is not None else None
    )
    component_health = workflow_component_health(args.repo, workflow_runs)
    natural_full_chain_run_ids = None
    if any(item.get("event") == "schedule" for item in workflow_runs):
        # Always collect the bounded window, even when a newer manual fallback
        # is the latest mixed run.  Otherwise the older natural full-chain
        # successes would be silently omitted (or old canaries over-counted).
        natural_full_chain_run_ids = collect_natural_full_chain_run_ids(
            args.repo,
            workflow_runs,
            window_hours=args.coverage_window_hours,
        )
    result = health(
        workflow_runs,
        coverage_window_hours=args.coverage_window_hours,
        watchdog_run_ids=watchdog_run_ids,
        natural_full_chain_run_ids=natural_full_chain_run_ids,
    )
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
        natural_full_chain_run_ids=natural_full_chain_run_ids,
        watchdog_run_ids=watchdog_run_ids,
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
    full_slot_coverage_health = result["fullSlotCoverage"]
    result["currentOperationalHealthy"] = bool(
        effective["fresh"]
        and component_health.get("healthy") is True
        and managed_coverage.get("healthy") is True
        and external_blocker is None
    )
    result["operationalHealthy"] = bool(
        result["currentOperationalHealthy"]
        and result["githubNaturalScheduleHealthy"] is True
        and full_slot_coverage_health.get("healthy") is not False
    )
    result["currentOperationalIssues"] = list(
        dict.fromkeys(
            [
                *scan_health_issues,
                *(component_health.get("issues") or []),
                *(managed_coverage.get("issues") or []),
                *([str(external_blocker["code"])] if external_blocker else []),
            ]
        )
    )
    result["operationalIssues"] = list(
        dict.fromkeys(
            [
                *result["currentOperationalIssues"],
                *(full_slot_coverage_health.get("issues") or []),
            ]
        )
    )
    result["healthIssues"] = list(dict.fromkeys([*result["issues"], *result["operationalIssues"]]))
    if args.notify and (
        result["healthy"] is not True
        or not effective["fresh"]
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
                            "content": "\n".join(result["healthIssues"]),
                        },
                    }
                ],
            },
            idempotency_key=sha256_json(
                {"issues": result["healthIssues"], "hour": result["checkedAt"][:13]}
            ),
        )
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["operationalHealthy"] is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
