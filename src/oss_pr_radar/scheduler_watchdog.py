"""Independent, slot-idempotent fallback for the hourly Radar workflow.

GitHub's native ``schedule`` event is the preferred full-chain path.  The
worker verifies the terminal proof job (and the required business jobs) before
counting a completed natural run; a canary-only historical run cannot suppress
the fallback.  After a bounded grace period it dispatches at most once for an
uncovered hourly slot.  A durable claim is committed before the external
request, so a timeout or process crash can be reconciled without issuing the
same fallback twice.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, ContextManager
from urllib.parse import urlsplit

from .github_client import GitHubClient
from .operational_auth import require_operational_authorization
from .outbound_pause import outbound_effect_guard
from .release_binding import runtime_ledger_path
from .runtime import RuntimeLockBusy, disk_pressure_gate, exclusive_lock, write_json
from .util import parse_time

WATCHDOG_SCHEMA = "oss-pr-radar.scheduler-watchdog.v1"
WATCHDOG_STATE = "scheduler-watchdog.json"
WATCHDOG_LOCK = "scheduler-watchdog.lock"
WATCHDOG_WORKER = "scheduler-watchdog"
WATCHDOG_LABEL = "com.oss-pr-radar.scheduler-watchdog"
ACTIVE_RUN_STATUSES = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})
LEGACY_CLAIM_STATES = frozenset({"CLAIMED", "REQUESTED", "UNCERTAIN"})
EXACT_TRACKING_STATES = frozenset({"BOUND", "RUNNING"})
RETRY_TRACKING_STATES = frozenset({"RETRY_CLAIMED", "RETRY_REQUESTED", "RETRY_UNCERTAIN"})
MAX_RETAINED_SLOTS = 48
MAX_FULL_WORKFLOW_RERUNS = 1
FULL_WORKFLOW_RERUN_PROTOCOL = "full-workflow-v1"
NATURAL_SCHEDULE_CADENCE_HOURS = 1.0
LEGACY_TIME_PRECISION = timedelta(seconds=2)
LEGACY_ATTRIBUTION_WINDOW = timedelta(seconds=30)

# ``schedule-canary`` is intentionally not part of this set.  The proof job
# starts on every current workflow invocation, while the remaining jobs prove
# that the business/state chain was actually materialized and completed.  A
# historical canary-only run therefore cannot masquerade as a full scan.
FULL_CHAIN_PROOF_JOB = "full-chain-proof"
BUSINESS_CHAIN_JOBS = frozenset(
    {
        "watch",
        "pr-followup",
        "scan",
        "build-state",
        "persist-pending",
        "notify",
        "persist-receipt",
    }
)
FULL_CHAIN_JOBS = BUSINESS_CHAIN_JOBS | {FULL_CHAIN_PROOF_JOB}

RunLister = Callable[[str, str], list[dict[str, Any]]]
JobsLister = Callable[[str, int], list[dict[str, Any]]]
DispatchReceipt = dict[str, Any]
DispatchRunner = Callable[
    [str, str, str, float, int | None],
    DispatchReceipt | None,
]
FailedJobRerunner = Callable[[str, int, int | None], None]
EffectGuardFactory = Callable[[Path, Path], ContextManager[Any]]
AuthorizationCheck = Callable[[Path], Any]
DispatchGate = Callable[[Path], dict[str, Any]]


def _iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def eligible_slot(
    now: datetime,
    *,
    minute: int = 17,
    grace_minutes: int = 13,
) -> datetime:
    """Return the latest hourly slot whose grace period has elapsed."""

    if now.tzinfo is None:
        raise ValueError("watchdog time must include a UTC offset")
    if not 0 <= minute <= 59:
        raise ValueError("slot minute must be between 0 and 59")
    if not 10 <= grace_minutes <= 15:
        raise ValueError("watchdog grace must be between 10 and 15 minutes")
    current = now.astimezone(UTC)
    slot = current.replace(minute=minute, second=0, microsecond=0)
    if current < slot + timedelta(minutes=grace_minutes):
        slot -= timedelta(hours=1)
    return slot


def fallback_key(repo: str, workflow: str, slot: datetime) -> str:
    material = f"scheduler-watchdog-v1\n{repo}\n{workflow}\n{_iso_z(slot)}\n"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _run_time(run: dict[str, Any]) -> datetime | None:
    raw = run.get("created_at") or run.get("run_started_at")
    if not raw:
        return None
    try:
        return parse_time(str(raw)).astimezone(UTC)
    except (TypeError, ValueError):
        return None


def normalize_job_conclusions(jobs: Any) -> dict[str, str]:
    """Normalize the small part of the Actions jobs response we need.

    GitHub returns both ``status`` and ``conclusion``.  A running job has no
    conclusion yet, so retaining the status lets the watchdog distinguish an
    active chain from a completed chain with a skipped/missing dependency.
    """

    if not isinstance(jobs, list):
        return {}
    result: dict[str, str] = {}
    for raw_job in jobs:
        if not isinstance(raw_job, dict) or not raw_job.get("name"):
            continue
        name = str(raw_job["name"])
        value = str(raw_job.get("conclusion") or raw_job.get("status") or "unknown")
        if name in result and result[name] != value:
            # Duplicate job names are ambiguous (for example, one matrix
            # copy succeeded while another was skipped).  Keep a sentinel so
            # every consumer fails closed instead of letting a later item
            # overwrite an earlier failure.
            result[name] = "__duplicate_non_deterministic__"
        elif name in result:
            result[name] = "__duplicate_non_deterministic__"
        else:
            result[name] = value
    return result


def full_chain_evidence(
    run: dict[str, Any],
    jobs: Any = None,
) -> bool | None:
    """Return whether a run is proven to be the current full workflow chain.

    ``workflow_dispatch`` must materialize all business/state jobs and its
    exact run ID is still required by the durable watchdog claim.  For
    ``schedule`` we additionally require the terminal proof job.  Completion
    requires every required job to succeed.

    ``None`` means no evidence was supplied and is intentionally not proof of
    a completed natural chain.  The production watchdog annotates API
    observations with an explicit value before making a dispatch decision.
    """

    event = run.get("event")
    if event not in {"schedule", "workflow_dispatch"}:
        return False

    # Only the namespaced marker written by this cycle is trusted.  Generic
    # user/run fields are attacker-controlled metadata and must not override
    # a jobs response supplied by the caller.
    if jobs is None:
        value = run.get("_fullChainProven")
        if isinstance(value, bool):
            return value
        jobs = run.get("jobs")
    if jobs is None:
        return None
    conclusions = normalize_job_conclusions(jobs)
    required = FULL_CHAIN_JOBS if event == "schedule" else BUSINESS_CHAIN_JOBS
    if event == "schedule" and FULL_CHAIN_PROOF_JOB not in conclusions:
        return False
    if str(run.get("status") or "") in ACTIVE_RUN_STATUSES:
        # Active native runs are handled by the transient wait path.  Do not
        # cache a positive completion proof that could be reused after the
        # same run transitions to a partial/failed terminal state.
        return None
    return required <= conclusions.keys() and all(
        conclusions[name] == "success" for name in required
    )


def _run_covers_slot(
    run: dict[str, Any],
    slot: datetime,
    *,
    ref: str,
    full_chain: bool | None = None,
) -> bool:
    if run.get("event") not in {"schedule", "workflow_dispatch"}:
        return False
    if run.get("head_branch") != ref:
        return False
    created = _run_time(run)
    if created is None or not slot <= created < slot + timedelta(hours=1):
        return False
    status = str(run.get("status") or "")
    conclusion = str(run.get("conclusion") or "")
    if run.get("event") == "schedule":
        evidence = full_chain
        if evidence is None:
            evidence = full_chain_evidence(run)
        if status in ACTIVE_RUN_STATUSES:
            return False
        if evidence is not True:
            return False
    # A watchdog dispatch receipt is already an exact, durable invocation
    # proof.  If this cycle additionally fetched jobs, honor a negative
    # result; otherwise retain compatibility with legacy run-list snapshots.
    elif run.get("_fullChainProven") is False:
        return False
    return status in ACTIVE_RUN_STATUSES or (status == "completed" and conclusion == "success")


def _run_id(run: dict[str, Any]) -> str | None:
    value = run.get("id")
    return str(value) if value is not None else None


def _run_attempt(run: dict[str, Any]) -> int | None:
    value = run.get("run_attempt")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _run_order_key(run: dict[str, Any]) -> tuple[datetime, int] | None:
    created = _run_time(run)
    run_id = _run_id(run)
    if created is None or run_id is None or not run_id.isdigit() or int(run_id) <= 0:
        return None
    return created, int(run_id)


def _entry_run_order_key(entry: dict[str, Any]) -> tuple[datetime, int] | None:
    run = entry.get("run")
    run = run if isinstance(run, dict) else {}
    raw_created = run.get("createdAt") or run.get("created_at")
    raw_run_id = entry.get("workflowRunId")
    if raw_run_id is None:
        raw_run_id = run.get("runId") or run.get("id")
    if isinstance(raw_run_id, bool) or not isinstance(raw_run_id, (int, str)):
        return None
    encoded_run_id = str(raw_run_id)
    if not encoded_run_id.isdigit() or int(encoded_run_id) <= 0 or not raw_created:
        return None
    try:
        created = parse_time(str(raw_created)).astimezone(UTC)
    except (TypeError, ValueError):
        return None
    return created, int(encoded_run_id)


def _full_run(
    run: dict[str, Any],
    *,
    ref: str,
    full_chain: bool | None = None,
) -> bool:
    if run.get("event") not in {"schedule", "workflow_dispatch"}:
        return False
    if run.get("head_branch") != ref or _run_order_key(run) is None:
        return False
    if run.get("event") == "schedule":
        evidence = full_chain
        if evidence is None:
            evidence = full_chain_evidence(run)
        if evidence is not True:
            return False
    elif run.get("_fullChainProven") is False:
        return False
    return True


def _latest_full_run(runs: list[dict[str, Any]], *, ref: str) -> dict[str, Any] | None:
    return max(
        (run for run in runs if _full_run(run, ref=ref)),
        key=lambda run: _run_order_key(run) or (datetime.min.replace(tzinfo=UTC), 0),
        default=None,
    )


def _covering_run(
    runs: list[dict[str, Any]],
    slot: datetime,
    *,
    ref: str,
    excluded_run_ids: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    candidates = [
        run
        for run in runs
        if _run_id(run) not in excluded_run_ids and _run_covers_slot(run, slot, ref=ref)
    ]
    return max(candidates, key=lambda item: _run_time(item) or slot, default=None)


def _active_natural_run(
    runs: list[dict[str, Any]],
    slot: datetime,
    *,
    ref: str,
) -> dict[str, Any] | None:
    """Find an in-flight native run for the eligible slot.

    This is deliberately separate from ``_covering_run``: active native runs
    are transient observations and must never be persisted as watchdog exact
    claims (which are reserved for workflow_dispatch receipts).
    """

    candidates = [
        run
        for run in runs
        if run.get("event") == "schedule"
        and run.get("head_branch") == ref
        and _run_time(run) is not None
        and slot <= (_run_time(run) or slot) < slot + timedelta(hours=1)
        and str(run.get("status") or "") in ACTIVE_RUN_STATUSES
    ]
    return max(candidates, key=lambda item: _run_time(item) or slot, default=None)


def _entry_run_id(entry: dict[str, Any]) -> str | None:
    exact = entry.get("workflowRunId")
    if exact is not None:
        return str(exact)
    run = entry.get("run")
    if not isinstance(run, dict):
        return None
    value = run.get("runId")
    return str(value) if value is not None else None


def _claim_backed(entry: dict[str, Any]) -> bool:
    return isinstance(entry.get("baselineRunIds"), list) and bool(entry.get("claimedAt"))


def _legacy_claim_started(entry: dict[str, Any]) -> datetime | None:
    try:
        return parse_time(str(entry["claimedAt"])).astimezone(UTC)
    except (KeyError, TypeError, ValueError):
        return None


def _legacy_claim_candidate(
    runs: list[dict[str, Any]],
    entry: dict[str, Any],
    *,
    ref: str,
    reserved_run_ids: set[str],
) -> dict[str, Any] | None:
    baseline = entry.get("baselineRunIds")
    claimed = _legacy_claim_started(entry)
    if not isinstance(baseline, list) or claimed is None:
        return None
    baseline_ids = {str(value) for value in baseline}
    candidates: list[dict[str, Any]] = []
    for run in runs:
        run_id = _run_id(run)
        created = _run_time(run)
        if (
            run_id is None
            or run_id in baseline_ids
            or run_id in reserved_run_ids
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != ref
            or created is None
            or created < claimed - LEGACY_TIME_PRECISION
            or created > claimed + LEGACY_ATTRIBUTION_WINDOW
        ):
            continue
        status = str(run.get("status") or "")
        if status in ACTIVE_RUN_STATUSES or status == "completed":
            candidates.append(run)
    return min(
        candidates,
        key=lambda item: (_run_time(item) or claimed, _run_id(item) or ""),
        default=None,
    )


def _assigned_run_ids(slots: dict[str, Any], *, except_key: str | None = None) -> frozenset[str]:
    assigned: set[str] = set()
    for key, raw_entry in slots.items():
        if key == except_key or not isinstance(raw_entry, dict):
            continue
        run_id = _entry_run_id(raw_entry)
        if run_id is not None:
            assigned.add(run_id)
    return frozenset(assigned)


def _remove_unclaimed_run_projection(
    slots: dict[str, Any],
    *,
    owner_key: str,
    run_id: str,
) -> None:
    for other_key, raw_other in list(slots.items()):
        if other_key == owner_key or not isinstance(raw_other, dict):
            continue
        if _entry_run_id(raw_other) != run_id:
            continue
        if _claim_backed(raw_other) or raw_other.get("workflowRunId") is not None:
            raise RuntimeError("scheduler watchdog run is assigned to multiple claims")
        del slots[other_key]


def _validate_exact_run(run: dict[str, Any], *, ref: str) -> None:
    if run.get("event") != "workflow_dispatch":
        raise RuntimeError("scheduler watchdog exact run event is invalid")
    if run.get("head_branch") != ref:
        raise RuntimeError("scheduler watchdog exact run ref is invalid")


def _run_state(run: dict[str, Any]) -> str:
    status = str(run.get("status") or "")
    conclusion = str(run.get("conclusion") or "")
    if status in ACTIVE_RUN_STATUSES:
        return "RUNNING"
    if status == "completed":
        return "COVERED" if conclusion == "success" else "FAILED"
    raise RuntimeError("scheduler watchdog run status is invalid")


def _bind_run(
    entry: dict[str, Any],
    run: dict[str, Any],
    *,
    observed_at: datetime,
    attribution_kind: str,
) -> dict[str, Any]:
    prior_state = str(entry.get("state") or "")
    run_attempt = _run_attempt(run)
    prior_run_attempt = entry.get("runAttempt")
    retry_base_attempt = entry.get("retryBaseRunAttempt")
    if prior_state in RETRY_TRACKING_STATES:
        if (
            not isinstance(retry_base_attempt, int)
            or run_attempt is None
            or run_attempt <= retry_base_attempt
        ):
            # The rerun request is write-ahead committed before the API call.
            # Until GitHub exposes a larger run_attempt, the completed failure
            # is still the pre-rerun observation and must not consume another
            # retry or be misreported as the recovery attempt's conclusion.
            entry.update(
                {
                    "run": _run_summary(run),
                    "lastReconciledAt": _iso_z(observed_at),
                    "reconcileCount": int(entry.get("reconcileCount") or 0) + 1,
                }
            )
            return entry
    if (
        prior_state == "FAILED"
        and isinstance(prior_run_attempt, int)
        and run_attempt is not None
        and run_attempt > prior_run_attempt
    ):
        # A same-ID rerun may be started outside this process between the
        # initial observation and the effect lock. Conservatively consume the
        # independent full-workflow budget too, preventing a duplicate rerun
        # request even though GitHub does not expose which rerun endpoint an
        # external actor used.
        legacy_attempts, full_attempts, total_attempts = _rerun_audit_counts(entry)
        if full_attempts < MAX_FULL_WORKFLOW_RERUNS:
            full_attempts += 1
            total_attempts += 1
            entry["fullWorkflowRerunBudgetSource"] = "external_same_run_attempt"
        entry.update(
            {
                "rerunAttempts": max(total_attempts, run_attempt - 1),
                "legacyFailedJobRerunAttempts": legacy_attempts,
                "fullWorkflowRerunAttempts": full_attempts,
                "fullWorkflowRerunProtocol": FULL_WORKFLOW_RERUN_PROTOCOL,
            }
        )
        entry["externallyObservedRerunAt"] = _iso_z(observed_at)
    state = _run_state(run)
    entry.update(
        {
            "state": state,
            "workflowRunId": run.get("id"),
            "workflowRunUrl": run.get("html_url"),
            "attributionKind": attribution_kind,
            "run": _run_summary(run),
            "lastReconciledAt": _iso_z(observed_at),
            "reconcileCount": int(entry.get("reconcileCount") or 0) + 1,
        }
    )
    if run_attempt is not None:
        entry["runAttempt"] = run_attempt
    if state == "COVERED":
        entry["coverageKind"] = "natural" if run.get("event") == "schedule" else "fallback"
        entry["coveredAt"] = _iso_z(observed_at)
        entry.pop("failedAt", None)
    elif state == "FAILED":
        entry["failedAt"] = _iso_z(observed_at)
        entry.pop("coverageKind", None)
        entry.pop("coveredAt", None)
    else:
        entry.pop("coverageKind", None)
        entry.pop("coveredAt", None)
        entry.pop("failedAt", None)
    return entry


def _reconciled_summary(key: str, entry: dict[str, Any]) -> dict[str, Any]:
    result = {
        "fallbackKey": key,
        "slotAt": entry.get("slotAt"),
        "state": entry.get("state"),
        "run": entry.get("run"),
    }
    if int(entry.get("rerunAttempts") or 0):
        result["rerunAttempts"] = int(entry["rerunAttempts"])
    if entry.get("state") == "SUPERSEDED":
        result["supersededByRun"] = entry.get("supersededByRun")
    return result


def _reconcile_exact_claims(
    slots: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    ref: str,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    runs_by_id = {run_id: run for run in runs if (run_id := _run_id(run)) is not None}
    reconciled: list[dict[str, Any]] = []
    for key, raw_entry in sorted(slots.items()):
        if not isinstance(raw_entry, dict):
            continue
        entry = dict(raw_entry)
        state = str(entry.get("state") or "")
        run_id = _entry_run_id(entry)
        if (
            run_id is None
            or entry.get("workflowRunId") is None
            or state
            not in EXACT_TRACKING_STATES | LEGACY_CLAIM_STATES | RETRY_TRACKING_STATES | {"FAILED"}
        ):
            continue
        run = runs_by_id.get(run_id)
        if run is None:
            if state in LEGACY_CLAIM_STATES:
                entry["state"] = "BOUND"
                entry["lastReconciledAt"] = _iso_z(observed_at)
                entry["reconcileCount"] = int(entry.get("reconcileCount") or 0) + 1
                slots[key] = entry
                reconciled.append(_reconciled_summary(key, entry))
            continue
        if run.get("event") != "workflow_dispatch":
            # A prior buggy release could have persisted an in-flight native
            # run as an exact claim.  It is not a valid watchdog receipt; drop
            # only that transient projection so the normal active/terminal
            # natural path below can decide without loosening exact-run
            # validation for manual dispatches.
            if state in EXACT_TRACKING_STATES | RETRY_TRACKING_STATES | LEGACY_CLAIM_STATES:
                del slots[key]
            continue
        _validate_exact_run(run, ref=ref)
        _remove_unclaimed_run_projection(slots, owner_key=key, run_id=run_id)
        prior_state = state
        prior_run = entry.get("run")
        entry = _bind_run(
            entry,
            run,
            observed_at=observed_at,
            attribution_kind=str(entry.get("attributionKind") or "exact_dispatch_receipt"),
        )
        slots[key] = entry
        if prior_state != entry["state"] or prior_run != entry["run"]:
            reconciled.append(_reconciled_summary(key, entry))
    return reconciled


def _reconcile_legacy_claims(
    slots: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    ref: str,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    """Migrate claims created before exact workflow run IDs were persisted."""

    reserved_run_ids = {
        run_id
        for raw_entry in slots.values()
        if isinstance(raw_entry, dict)
        and _claim_backed(raw_entry)
        and (run_id := _entry_run_id(raw_entry)) is not None
    }
    pending = sorted(
        (
            (key, dict(raw_entry))
            for key, raw_entry in slots.items()
            if isinstance(raw_entry, dict)
            and raw_entry.get("workflowRunId") is None
            and str(raw_entry.get("state") or "") in LEGACY_CLAIM_STATES
        ),
        key=lambda item: (str(item[1].get("claimedAt") or ""), item[0]),
    )
    reconciled: list[dict[str, Any]] = []
    for key, entry in pending:
        candidate = _legacy_claim_candidate(
            runs,
            entry,
            ref=ref,
            reserved_run_ids=reserved_run_ids,
        )
        if candidate is None:
            continue
        run_id = _run_id(candidate)
        if run_id is None:  # pragma: no cover - guarded by _legacy_claim_candidate
            continue
        _remove_unclaimed_run_projection(slots, owner_key=key, run_id=run_id)
        entry = _bind_run(
            entry,
            candidate,
            observed_at=observed_at,
            attribution_kind="legacy_baseline_migration",
        )
        slots[key] = entry
        reserved_run_ids.add(run_id)
        reconciled.append(_reconciled_summary(key, entry))
    return reconciled


def _supersede_failed_claims(
    slots: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    ref: str,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    """Terminalize failed claims covered by a logically newer successful full run."""

    successful_runs = [
        run
        for run in runs
        if _full_run(run, ref=ref)
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    ]
    latest_success = max(
        successful_runs,
        key=lambda run: _run_order_key(run) or (datetime.min.replace(tzinfo=UTC), 0),
        default=None,
    )
    if latest_success is None:
        return []
    success_key = _run_order_key(latest_success)
    if success_key is None:  # pragma: no cover - filtered above
        return []

    superseded: list[dict[str, Any]] = []
    for key, raw_entry in sorted(slots.items()):
        if (
            not isinstance(raw_entry, dict)
            or raw_entry.get("state") != "FAILED"
            or not _claim_backed(raw_entry)
        ):
            continue
        entry = dict(raw_entry)
        failed_key = _entry_run_order_key(entry)
        if failed_key is None or success_key <= failed_key:
            continue
        entry.update(
            {
                "state": "SUPERSEDED",
                "supersededAt": _iso_z(observed_at),
                "supersededReason": "LATER_SUCCESSFUL_FULL_RUN",
                "supersededByRun": _run_summary(latest_success),
            }
        )
        slots[key] = entry
        superseded.append(_reconciled_summary(key, entry))
    return superseded


def _reconcile_claims(
    slots: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    ref: str,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    reconciled = _reconcile_exact_claims(
        slots,
        runs,
        ref=ref,
        observed_at=observed_at,
    )
    reconciled.extend(
        _reconcile_legacy_claims(
            slots,
            runs,
            ref=ref,
            observed_at=observed_at,
        )
    )
    superseded = _supersede_failed_claims(
        slots,
        runs,
        ref=ref,
        observed_at=observed_at,
    )
    if superseded:
        superseded_keys = {item["fallbackKey"] for item in superseded}
        reconciled = [item for item in reconciled if item.get("fallbackKey") not in superseded_keys]
        reconciled.extend(superseded)
    return reconciled


def _recover_interrupted_retry_claims(
    slots: dict[str, Any],
    *,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    """Turn a crash-left retry claim into bounded uncertain tracking.

    ``RETRY_CLAIMED`` is persisted before the GitHub request.  Reissuing from
    that state could create a second recovery request, while leaving it as a
    claim forever obscures what happened.  On the next cycle we therefore
    preserve the consumed retry budget and track only the exact run ID until
    GitHub exposes a newer ``run_attempt``.
    """

    recovered: list[dict[str, Any]] = []
    for key, raw_entry in sorted(slots.items()):
        if not isinstance(raw_entry, dict) or raw_entry.get("state") != "RETRY_CLAIMED":
            continue
        entry = dict(raw_entry)
        entry.update(
            {
                "state": "RETRY_UNCERTAIN",
                "retryRecoveredAt": _iso_z(observed_at),
                "lastRetryError": "PROCESS_INTERRUPTED_AFTER_DURABLE_RETRY_CLAIM",
            }
        )
        slots[key] = entry
        recovered.append(_reconciled_summary(key, entry))
    return recovered


def _retryable_failed_claim_key(
    slots: dict[str, Any],
    *,
    exclude_key: str | None = None,
) -> str | None:
    # A newer slot, even while still tracking, makes every older failed claim
    # historical. Only when the newest durable slot itself is a retryable
    # failure may the worker replay its exact run ID.
    entries = [
        (str(entry.get("slotAt") or ""), key, entry)
        for key, entry in slots.items()
        if isinstance(entry, dict)
    ]
    if not entries:
        return None
    _, key, entry = max(entries, key=lambda item: (item[0], item[1]))
    if key == exclude_key or not _retryable_failed_claim(entry):
        return None
    return key


def _reconciled_only_covers_old_slots(
    reconciled: list[dict[str, Any]],
    *,
    current_key: str,
) -> bool:
    """Allow a one-cycle migration receipt only when every old claim finished."""

    return bool(reconciled) and all(
        item.get("fallbackKey") != current_key and item.get("state") == "COVERED"
        for item in reconciled
    )


def _result_for_reconciled(
    reconciled: list[dict[str, Any]],
    *,
    natural_healthy: bool,
    covered_action: str,
) -> dict[str, Any]:
    failed = next((item for item in reconciled if item["state"] == "FAILED"), None)
    tracking = next(
        (
            item
            for item in reconciled
            if item["state"] in EXACT_TRACKING_STATES | RETRY_TRACKING_STATES
        ),
        None,
    )
    superseded = next((item for item in reconciled if item["state"] == "SUPERSEDED"), None)
    primary = failed or tracking or superseded or reconciled[0]
    if failed is not None:
        action = "fallback_failed"
    elif tracking is not None:
        action = (
            "fallback_retry_tracking" if tracking["state"] in RETRY_TRACKING_STATES else "tracking"
        )
    elif superseded is not None:
        action = "fallback_superseded"
    else:
        action = covered_action
    result = {
        "ok": failed is None,
        "action": action,
        "slotAt": primary["slotAt"],
        "fallbackKey": primary["fallbackKey"],
        "claimState": primary["state"],
        "run": primary["run"],
        "reconciledClaims": reconciled,
        "githubNaturalScheduleHealthy": natural_healthy,
    }
    if primary["state"] == "COVERED":
        run = primary.get("run") if isinstance(primary.get("run"), dict) else {}
        result["coverageKind"] = "natural" if run.get("event") == "schedule" else "fallback"
    elif primary["state"] == "SUPERSEDED":
        result["supersededByRun"] = primary.get("supersededByRun")
    if int(primary.get("rerunAttempts") or 0):
        result["rerunAttempts"] = int(primary["rerunAttempts"])
    return result


def _result_for_existing_claim(
    entry: dict[str, Any],
    *,
    natural_healthy: bool,
) -> dict[str, Any]:
    state = str(entry.get("state") or "")
    if state in LEGACY_CLAIM_STATES:
        action = "reconciling"
        ok = True
    elif state in EXACT_TRACKING_STATES:
        action = "tracking"
        ok = True
    elif state in RETRY_TRACKING_STATES:
        action = "fallback_retry_tracking"
        ok = True
    elif state == "FAILED":
        action = "fallback_failed"
        ok = False
    elif state == "COVERED":
        action = "covered"
        ok = True
    elif state == "SUPERSEDED":
        action = "fallback_superseded"
        ok = True
    else:
        raise RuntimeError("scheduler watchdog claim state is invalid")
    result = {
        "ok": ok,
        "action": action,
        "slotAt": entry.get("slotAt"),
        "fallbackKey": entry.get("fallbackKey"),
        "claimState": state,
        "githubNaturalScheduleHealthy": natural_healthy,
    }
    if state in EXACT_TRACKING_STATES | RETRY_TRACKING_STATES | {
        "FAILED",
        "COVERED",
        "SUPERSEDED",
    }:
        result["run"] = entry.get("run")
    if int(entry.get("rerunAttempts") or 0):
        result["rerunAttempts"] = int(entry["rerunAttempts"])
    if state == "COVERED":
        run = entry.get("run") if isinstance(entry.get("run"), dict) else {}
        result["coverageKind"] = str(
            entry.get("coverageKind")
            or ("natural" if run.get("event") == "schedule" else "fallback")
        )
    elif state == "SUPERSEDED":
        result["supersededByRun"] = entry.get("supersededByRun")
    return result


def _result_for_natural_wait(
    run: dict[str, Any],
    *,
    slot: datetime,
    natural_healthy: bool,
) -> dict[str, Any]:
    """Return a transient in-flight natural observation.

    Native schedule runs are not durable watchdog claims.  Persisting one as
    ``RUNNING`` would make the next reconciliation route it through the exact
    dispatch validator and either fail or block the fallback forever.  The
    run is therefore reported for this cycle only; a later completed
    observation is bound as natural coverage, while a failed/partial run
    naturally falls through to fallback.
    """

    return {
        "ok": True,
        "action": "natural_active",
        "slotAt": _iso_z(slot),
        "run": _run_summary(run),
        "coverageKind": "natural",
        "githubNaturalScheduleHealthy": natural_healthy,
    }


def _latest_natural(
    runs: list[dict[str, Any]],
    *,
    ref: str | None = None,
) -> dict[str, Any] | None:
    scheduled = [
        run
        for run in runs
        if run.get("event") == "schedule"
        and _run_time(run)
        and (ref is None or run.get("head_branch") == ref)
    ]
    return max(
        scheduled,
        key=lambda item: _run_time(item) or datetime.min.replace(tzinfo=UTC),
        default=None,
    )


def _natural_schedule_health(
    run: dict[str, Any] | None,
    *,
    now: datetime,
    window_hours: float,
) -> tuple[bool, bool, bool, float]:
    """Return status, freshness, health, and the freshness window in hours.

    GitHub's natural scheduler is hourly, so a canary is never stale before
    one complete cadence has elapsed.  A larger scan window deliberately
    widens that tolerance, while a fallback ``workflow_dispatch`` can never
    enter this calculation because ``run`` comes only from ``_latest_natural``.
    """

    freshness_hours = max(NATURAL_SCHEDULE_CADENCE_HOURS, float(window_hours))
    successful = bool(
        run and run.get("status") == "completed" and run.get("conclusion") == "success"
    )
    created = _run_time(run) if run else None
    fresh = bool(created and now - timedelta(hours=freshness_hours) <= created <= now)
    # This tuple intentionally remains the trigger-canary contract: callers
    # that need full-chain health must consult ``full_chain_evidence``
    # separately.  A canary can be fresh/successful while its business graph
    # was skipped, and that distinction is surfaced in the state below.
    return successful, fresh, successful and fresh, freshness_hours


def _state_path(root: Path) -> Path:
    return root.resolve() / "state" / WATCHDOG_STATE


def _strict_state(root: Path) -> dict[str, Any]:
    path = _state_path(root)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"schemaVersion": WATCHDOG_SCHEMA, "slots": {}}
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeError("scheduler watchdog state is unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("scheduler watchdog state is unreadable") from exc
    if not isinstance(value, dict) or value.get("schemaVersion") != WATCHDOG_SCHEMA:
        raise RuntimeError("scheduler watchdog state schema is invalid")
    if not isinstance(value.get("slots"), dict):
        raise RuntimeError("scheduler watchdog slot state is invalid")
    return value


def proven_watchdog_run_ids(root: Path) -> frozenset[str]:
    """Return exact workflow run IDs backed by durable watchdog claims."""

    state = _strict_state(root.resolve())
    proven: set[str] = set()
    for raw_entry in (state.get("slots") or {}).values():
        if not isinstance(raw_entry, dict) or not _claim_backed(raw_entry):
            continue
        run_id = raw_entry.get("workflowRunId")
        if isinstance(run_id, bool) or not isinstance(run_id, (int, str)):
            continue
        encoded = str(run_id)
        if encoded.isdigit() and int(encoded) > 0:
            proven.add(encoded)
    return frozenset(proven)


def _write_state(root: Path, state: dict[str, Any]) -> None:
    slots = state.get("slots") if isinstance(state.get("slots"), dict) else {}
    ordered = sorted(
        slots.items(),
        key=lambda item: str((item[1] or {}).get("slotAt") or item[0]),
        reverse=True,
    )[:MAX_RETAINED_SLOTS]
    state["slots"] = dict(ordered)
    state["schemaVersion"] = WATCHDOG_SCHEMA
    write_json(_state_path(root), state)


def _default_list_runs(repo: str, workflow: str) -> list[dict[str, Any]]:
    value = GitHubClient().api(
        f"repos/{repo}/actions/workflows/{workflow}/runs",
        params={"per_page": 100},
    )
    if not isinstance(value, dict) or not isinstance(value.get("workflow_runs"), list):
        raise RuntimeError("GitHub workflow run response is invalid")
    return [item for item in value["workflow_runs"] if isinstance(item, dict)]


def _default_list_jobs(repo: str, run_id: int) -> list[dict[str, Any]]:
    value = GitHubClient().api(
        f"repos/{repo}/actions/runs/{run_id}/jobs",
        params={"per_page": 100},
    )
    if not isinstance(value, dict) or not isinstance(value.get("jobs"), list):
        raise RuntimeError("GitHub workflow jobs response is invalid")
    return [item for item in value["jobs"] if isinstance(item, dict)]


def _invoke_prepare_runs(
    prepare_runs: Callable[..., list[dict[str, Any]]] | None,
    raw_runs: list[dict[str, Any]],
    *,
    force_refresh: bool = False,
) -> list[dict[str, Any]]:
    """Call a preparation callback while retaining its old one-arg shape."""

    if prepare_runs is None:
        return raw_runs
    if force_refresh:
        try:
            parameters = inspect.signature(prepare_runs).parameters.values()
        except (TypeError, ValueError):
            parameters = ()
        supports_keyword = any(
            parameter.name == "force_refresh" or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )
        if supports_keyword:
            return prepare_runs(raw_runs, force_refresh=True)
    return prepare_runs(raw_runs)


def _annotate_schedule_runs(
    repo: str,
    runs: list[dict[str, Any]],
    *,
    ref: str,
    current: datetime,
    slot: datetime,
    list_jobs: JobsLister | None,
    job_cache: dict[tuple[str, str, str, str, str], tuple[bool | None, str]],
) -> list[dict[str, Any]]:
    """Attach one-cycle full-chain evidence to relevant native runs.

    The run-list endpoint does not expose skipped jobs.  Querying every old
    run would be needlessly expensive, so the watchdog proves the latest
    native run and any run that could cover the eligible slot.  The cache is
    shared with the lock-bound recheck, closing the duplicate-dispatch race
    without multiplying API calls.
    """

    if list_jobs is None:
        return runs
    scheduled = [
        run
        for run in runs
        if run.get("event") == "schedule" and run.get("head_branch") == ref and _run_time(run)
    ]
    if not scheduled:
        return runs
    latest = max(scheduled, key=lambda item: _run_time(item) or current)
    selected_ids = {_run_id(latest)}
    selected_ids.update(
        _run_id(run)
        for run in scheduled
        if _run_time(run) is not None
        and slot <= (_run_time(run) or slot) < slot + timedelta(hours=1)
    )
    selected_ids.discard(None)
    annotated: list[dict[str, Any]] = []
    for raw_run in runs:
        run = dict(raw_run)
        run_id = _run_id(run)
        if run.get("event") != "schedule":
            annotated.append(run)
            continue
        embedded_jobs = run.get("jobs")
        if embedded_jobs is not None:
            # Embedded jobs are already authoritative; do not discard them
            # merely because this run falls outside the bounded API query.
            run["_fullChainProven"] = full_chain_evidence(run, embedded_jobs)
            run["_fullChainEvidenceSource"] = "embedded_jobs"
            run["_fullChainEvidenceRequired"] = True
            annotated.append(run)
            continue
        if run_id not in selected_ids:
            # This run may still be present in the list response and must not
            # silently participate in ``_full_run``/supersession as if it had
            # the new proof job.  It is deliberately marked unproven until a
            # bounded jobs lookup covers it in a later cycle.
            run["_fullChainProven"] = False
            run["_fullChainEvidenceSource"] = "not_queried"
            run["_fullChainEvidenceRequired"] = True
            annotated.append(run)
            continue
        # Tests and callers may provide an embedded jobs response.  It is
        # already authoritative and avoids an unnecessary network request.
        cache_key = (
            run_id or "",
            str(run.get("status") or ""),
            str(run.get("conclusion") or ""),
            str(run.get("run_attempt") or ""),
            str(run.get("updated_at") or ""),
        )
        if cache_key in job_cache:
            evidence, source = job_cache[cache_key]
        else:
            try:
                evidence = full_chain_evidence(run, list_jobs(repo, int(run_id)))
                source = "jobs_api"
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                # Preserve an explicit unknown result.  Active native runs
                # still wait; completed runs fail closed and can be retried
                # by the next health/watchdog cycle after API recovery.
                evidence = None
                source = f"jobs_api_error:{type(exc).__name__}"
            job_cache[cache_key] = (evidence, source)
        run["_fullChainProven"] = evidence
        run["_fullChainEvidenceSource"] = source
        run["_fullChainEvidenceRequired"] = True
        annotated.append(run)
    return annotated


def _dispatch_receipt_value(
    value: dict[str, Any],
    *names: str,
) -> Any:
    present = [value[name] for name in names if name in value]
    if not present:
        raise RuntimeError(f"dispatch response is missing {names[0]}")
    if any(item != present[0] for item in present[1:]):
        raise RuntimeError(f"dispatch response has conflicting {names[0]}")
    return present[0]


def _validate_dispatch_url(
    value: Any,
    *,
    repo: str,
    run_id: int,
    api: bool,
) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise RuntimeError("dispatch response run URL is invalid")
    if any(character.isspace() for character in value):
        raise RuntimeError("dispatch response run URL is invalid")
    repo_parts = repo.split("/")
    if len(repo_parts) != 2 or not all(repo_parts):
        raise RuntimeError("dispatch repository is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("dispatch response run URL is invalid") from exc
    expected_host = "api.github.com" if api else "github.com"
    prefix = "/repos" if api else ""
    expected_path = f"{prefix}/{repo_parts[0]}/{repo_parts[1]}/actions/runs/{run_id}"
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.casefold() != expected_path.casefold()
    ):
        raise RuntimeError("dispatch response run URL is invalid")
    return value


def _normalize_dispatch_receipt(
    value: DispatchReceipt | None,
    *,
    repo: str,
) -> DispatchReceipt | None:
    # A 204 response is supported only for compatibility with older GitHub
    # servers/CLI behavior.  It falls back to the bounded legacy migration.
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuntimeError("dispatch response is not an object")
    run_id = _dispatch_receipt_value(value, "workflowRunId", "workflow_run_id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise RuntimeError("dispatch response workflow run ID is invalid")
    run_api_url = _validate_dispatch_url(
        _dispatch_receipt_value(value, "runApiUrl", "run_url"),
        repo=repo,
        run_id=run_id,
        api=True,
    )
    workflow_run_url = _validate_dispatch_url(
        _dispatch_receipt_value(value, "workflowRunUrl", "html_url"),
        repo=repo,
        run_id=run_id,
        api=False,
    )
    return {
        "workflowRunId": run_id,
        "runApiUrl": run_api_url,
        "workflowRunUrl": workflow_run_url,
    }


def _default_dispatch(
    repo: str,
    workflow: str,
    ref: str,
    window_hours: float,
    lock_fd: int | None,
) -> DispatchReceipt | None:
    arguments = [
        "gh",
        "api",
        "--method",
        "POST",
        f"repos/{repo}/actions/workflows/{workflow}/dispatches",
        "-H",
        "X-GitHub-Api-Version: 2026-03-10",
        "--input",
        "-",
    ]
    request_body = json.dumps(
        {
            "ref": ref,
            "inputs": {"window_hours": f"{window_hours:g}"},
            "return_run_details": True,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            input=request_body,
            timeout=30,
            pass_fds=(lock_fd,) if lock_fd is not None else (),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        # The server may have accepted the request before the client observed
        # the timeout.  The durable slot claim deliberately remains consumed.
        raise RuntimeError(f"dispatch outcome uncertain: {type(exc).__name__}:{exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "GitHub dispatch failed")[:300]
        raise RuntimeError(f"dispatch outcome uncertain: {detail}")
    raw = completed.stdout.strip()
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("dispatch outcome uncertain: invalid JSON response") from exc
    try:
        return _normalize_dispatch_receipt(value, repo=repo)
    except RuntimeError as exc:
        raise RuntimeError(f"dispatch outcome uncertain: {exc}") from exc


def _default_rerun_failed_jobs(repo: str, run_id: int, lock_fd: int | None) -> None:
    """Rerun the whole workflow inside the same run ID.

    A failed-jobs-only rerun reuses successful jobs and their artifacts from
    the previous attempt.  For a historical Radar run that leaves
    ``state/base_sha.txt`` bound to an old state-branch head, so a recovered
    publish deterministically fails after newer hourly runs advance the
    branch.  A full rerun preserves the exact run ID while rebuilding every
    state artifact from a fresh restore.
    """

    arguments = [
        "gh",
        "api",
        "--method",
        "POST",
        f"repos/{repo}/actions/runs/{run_id}/rerun",
        "-H",
        "X-GitHub-Api-Version: 2026-03-10",
    ]
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            pass_fds=(lock_fd,) if lock_fd is not None else (),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"rerun outcome uncertain: {type(exc).__name__}:{exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "GitHub rerun failed")[:300]
        raise RuntimeError(f"rerun outcome uncertain: {detail}")


def _default_dispatch_gate(root: Path) -> dict[str, Any]:
    return disk_pressure_gate(root, worker=WATCHDOG_WORKER)


def _run_summary(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "runId": run.get("id"),
        "event": run.get("event"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "runAttempt": run.get("run_attempt"),
        "createdAt": run.get("created_at"),
        "url": run.get("html_url"),
    }


def _nonnegative_count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _rerun_audit_counts(entry: dict[str, Any]) -> tuple[int, int, int]:
    """Return legacy, full-workflow, and total rerun audit counts.

    Records written before ``full-workflow-v1`` only contain
    ``rerunAttempts``.  Those attempts used GitHub's failed-jobs endpoint and
    therefore remain a separate legacy count rather than consuming the new
    full-workflow recovery budget.
    """

    total = _nonnegative_count(entry.get("rerunAttempts"))
    full = _nonnegative_count(entry.get("fullWorkflowRerunAttempts"))
    explicit_legacy = entry.get("legacyFailedJobRerunAttempts")
    if isinstance(explicit_legacy, int) and not isinstance(explicit_legacy, bool):
        legacy = max(0, explicit_legacy)
    else:
        legacy = max(0, total - full)
    return legacy, full, max(total, legacy + full)


def _retryable_failed_claim(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict) or entry.get("state") != "FAILED":
        return False
    run_id = entry.get("workflowRunId")
    run_attempt = entry.get("runAttempt")
    return bool(
        _claim_backed(entry)
        and isinstance(run_id, int)
        and not isinstance(run_id, bool)
        and run_id > 0
        and isinstance(run_attempt, int)
        and not isinstance(run_attempt, bool)
        and run_attempt > 0
        and _rerun_audit_counts(entry)[1] < MAX_FULL_WORKFLOW_RERUNS
    )


def _retry_failed_claim(
    root: Path,
    *,
    state: dict[str, Any],
    slots: dict[str, Any],
    claim_key: str,
    repo: str,
    workflow: str,
    ref: str,
    current: datetime,
    natural_healthy: bool,
    list_runs: RunLister,
    rerun_failed_jobs: FailedJobRerunner,
    effect_guard: EffectGuardFactory,
    authorization_check: AuthorizationCheck,
    dispatch_gate: DispatchGate,
    prepare_runs: Callable[..., list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Write-ahead claim one same-run full-workflow recovery attempt."""

    guard = effect_guard(root, runtime_ledger_path(root))
    with guard as effect_lock:
        authorization_check(root)
        gate = dispatch_gate(root)
        if gate.get("allowed") is not True:
            return {
                "ok": True,
                "action": "disk_gate_blocked",
                "slotAt": (slots.get(claim_key) or {}).get("slotAt"),
                "fallbackKey": claim_key,
                "diskPressureGate": gate,
                "githubNaturalScheduleHealthy": natural_healthy,
            }

        # Close the race with a user-initiated rerun before committing the
        # recovery effect. The exact run ID, not timestamps, owns the claim.
        refreshed = _invoke_prepare_runs(
            prepare_runs,
            list_runs(repo, workflow),
            force_refresh=True,
        )
        _reconcile_claims(slots, refreshed, ref=ref, observed_at=current)
        current_entry = slots.get(claim_key)
        current_entry = dict(current_entry) if isinstance(current_entry, dict) else None
        latest_full = _latest_full_run(refreshed, ref=ref)
        latest_full_id = _run_id(latest_full) if latest_full is not None else None
        if (
            not _retryable_failed_claim(current_entry)
            or _retryable_failed_claim_key(slots) != claim_key
            or latest_full_id != _entry_run_id(current_entry)
        ):
            state["slots"] = slots
            _write_state(root, state)
            if current_entry is None:
                raise RuntimeError("scheduler watchdog failed claim disappeared")
            return _result_for_existing_claim(
                current_entry,
                natural_healthy=natural_healthy,
            )

        run_id = int(current_entry["workflowRunId"])
        run_attempt = int(current_entry["runAttempt"])
        legacy_attempts, full_attempts, total_attempts = _rerun_audit_counts(current_entry)
        full_attempts += 1
        rerun_attempts = total_attempts + 1
        claimed_at = _iso_z(datetime.now(UTC))
        current_entry.update(
            {
                "state": "RETRY_CLAIMED",
                "rerunAttempts": rerun_attempts,
                "legacyFailedJobRerunAttempts": legacy_attempts,
                "fullWorkflowRerunAttempts": full_attempts,
                "fullWorkflowRerunProtocol": FULL_WORKFLOW_RERUN_PROTOCOL,
                "fullWorkflowRerunBudgetSource": "watchdog_request",
                "retryBaseRunAttempt": run_attempt,
                "retryClaimedAt": claimed_at,
            }
        )
        current_entry.pop("lastRetryError", None)
        slots[claim_key] = current_entry
        state["slots"] = slots
        state["lastFallbackRecoveryClaim"] = {
            "fallbackKey": claim_key,
            "slotAt": current_entry.get("slotAt"),
            "workflowRunId": run_id,
            "rerunAttempt": rerun_attempts,
            "fullWorkflowRerunAttempt": full_attempts,
            "fullWorkflowRerunProtocol": FULL_WORKFLOW_RERUN_PROTOCOL,
            "claimedAt": claimed_at,
        }
        # Commit before the API request. A crash or timeout can only reconcile
        # this same run ID; it can never create another workflow invocation.
        _write_state(root, state)
        lock_fd = effect_lock.fileno() if hasattr(effect_lock, "fileno") else None
        try:
            rerun_failed_jobs(repo, run_id, lock_fd)
        except Exception as exc:
            finished_at = _iso_z(datetime.now(UTC))
            current_entry.update(
                {
                    "state": "RETRY_UNCERTAIN",
                    "retryFinishedAt": finished_at,
                    "lastRetryError": f"{type(exc).__name__}:{str(exc)[:300]}",
                }
            )
            slots[claim_key] = current_entry
            state["slots"] = slots
            _write_state(root, state)
            return {
                "ok": False,
                "action": "fallback_retry_uncertain",
                "slotAt": current_entry.get("slotAt"),
                "fallbackKey": claim_key,
                "claimState": current_entry["state"],
                "run": current_entry.get("run"),
                "rerunAttempts": rerun_attempts,
                "error": current_entry["lastRetryError"],
                "githubNaturalScheduleHealthy": natural_healthy,
            }

        finished_at = _iso_z(datetime.now(UTC))
        current_entry.update(
            {
                "state": "RETRY_REQUESTED",
                "retryFinishedAt": finished_at,
            }
        )
        slots[claim_key] = current_entry
        state["slots"] = slots
        state["lastFallbackRecoveryRequest"] = {
            "fallbackKey": claim_key,
            "slotAt": current_entry.get("slotAt"),
            "workflowRunId": run_id,
            "rerunAttempt": rerun_attempts,
            "fullWorkflowRerunAttempt": full_attempts,
            "fullWorkflowRerunProtocol": FULL_WORKFLOW_RERUN_PROTOCOL,
            "requestedAt": finished_at,
        }
        _write_state(root, state)
        return {
            "ok": True,
            "action": "fallback_retry_requested",
            "slotAt": current_entry.get("slotAt"),
            "fallbackKey": claim_key,
            "claimState": current_entry["state"],
            "run": current_entry.get("run"),
            "rerunAttempts": rerun_attempts,
            "githubNaturalScheduleHealthy": natural_healthy,
        }


def watchdog_cycle(
    root: Path,
    *,
    repo: str = "Oxygen56/oss-pr-radar",
    workflow: str = "radar.yml",
    ref: str = "main",
    window_hours: float = 2.0,
    slot_minute: int = 17,
    grace_minutes: int = 13,
    now: datetime | None = None,
    list_runs: RunLister = _default_list_runs,
    list_jobs: JobsLister | None = None,
    dispatch: DispatchRunner = _default_dispatch,
    rerun_failed_jobs: FailedJobRerunner = _default_rerun_failed_jobs,
    effect_guard: EffectGuardFactory = outbound_effect_guard,
    authorization_check: AuthorizationCheck = require_operational_authorization,
    dispatch_gate: DispatchGate = _default_dispatch_gate,
) -> dict[str, Any]:
    """Observe one eligible slot and, if needed, consume one fallback claim."""

    root = root.resolve()
    current = (now or datetime.now(UTC)).astimezone(UTC)
    slot = eligible_slot(current, minute=slot_minute, grace_minutes=grace_minutes)
    slot_at = _iso_z(slot)
    claim_key = fallback_key(repo, workflow, slot)
    lock_path = root / "state" / WATCHDOG_LOCK
    if list_jobs is None and list_runs is _default_list_runs:
        list_jobs = _default_list_jobs
    job_cache: dict[tuple[str, str, str, str, str], tuple[bool | None, str]] = {}

    def prepare_runs(
        raw_runs: list[dict[str, Any]],
        *,
        force_refresh: bool = False,
    ) -> list[dict[str, Any]]:
        if force_refresh:
            # The jobs endpoint can settle after the workflow-run metadata
            # does (and a run may go from active to terminal between the two
            # reads).  Never let the shared pre-lock observation suppress a
            # fallback after the outbound-effect lock is acquired.
            job_cache.clear()
        return _annotate_schedule_runs(
            repo,
            raw_runs,
            ref=ref,
            current=current,
            slot=slot,
            list_jobs=list_jobs,
            job_cache=job_cache,
        )

    try:
        lock_context = exclusive_lock(lock_path, blocking=False)
        with lock_context:
            state = _strict_state(root)
            slots = dict(state.get("slots") or {})
            runs = prepare_runs(list_runs(repo, workflow))
            natural = _latest_natural(runs, ref=ref)
            natural_success, natural_fresh, natural_healthy, freshness_hours = (
                _natural_schedule_health(
                    natural,
                    now=current,
                    window_hours=window_hours,
                )
            )
            natural_full_chain = full_chain_evidence(natural) if natural else None
            natural_canary_healthy = natural_healthy
            natural_healthy = natural_canary_healthy and natural_full_chain is True
            state.update(
                {
                    "repo": repo,
                    "workflow": workflow,
                    "ref": ref,
                    "lastCheckedAt": _iso_z(current),
                    # Natural health is intentionally derived only from
                    # event=schedule and cannot be made green by this worker.
                    "latestNaturalSchedule": _run_summary(natural) if natural else None,
                    "naturalScheduleCanary": {
                        "observed": natural is not None,
                        "latestRun": _run_summary(natural) if natural else None,
                        "latestRunSuccessful": natural_success,
                        "latestRunFresh": natural_fresh,
                        "freshnessWindowHours": freshness_hours,
                        "freshnessCutoffAt": _iso_z(current - timedelta(hours=freshness_hours)),
                        "healthy": natural_canary_healthy,
                        "fullChainHealthy": natural_healthy,
                        "fullChainProven": natural_full_chain,
                        "fullChainEvidenceSource": (
                            natural.get("_fullChainEvidenceSource") if natural else None
                        ),
                        "sourceEvent": "schedule",
                    },
                    "naturalScheduleFullChain": {
                        "healthy": natural_healthy,
                        "proven": natural_full_chain is True,
                        "evidence": natural_full_chain,
                        "evidenceSource": (
                            natural.get("_fullChainEvidenceSource") if natural else None
                        ),
                        "sourceEvent": "schedule",
                    },
                }
            )
            reconciled = _reconcile_claims(
                slots,
                runs,
                ref=ref,
                observed_at=current,
            )
            reconciled.extend(
                _recover_interrupted_retry_claims(
                    slots,
                    observed_at=current,
                )
            )
            if reconciled:
                state["slots"] = slots
                _write_state(root, state)
                if _retryable_failed_claim_key(slots) == claim_key:
                    return _retry_failed_claim(
                        root,
                        state=state,
                        slots=slots,
                        claim_key=claim_key,
                        repo=repo,
                        workflow=workflow,
                        ref=ref,
                        current=current,
                        natural_healthy=natural_healthy,
                        list_runs=list_runs,
                        prepare_runs=prepare_runs,
                        rerun_failed_jobs=rerun_failed_jobs,
                        effect_guard=effect_guard,
                        authorization_check=authorization_check,
                        dispatch_gate=dispatch_gate,
                    )
                current_reconciled = [
                    item for item in reconciled if item.get("fallbackKey") == claim_key
                ]
                if current_reconciled:
                    if all(item.get("state") == "COVERED" for item in current_reconciled):
                        historical_retry_key = _retryable_failed_claim_key(
                            slots,
                            exclude_key=claim_key,
                        )
                        if historical_retry_key is not None:
                            return _retry_failed_claim(
                                root,
                                state=state,
                                slots=slots,
                                claim_key=historical_retry_key,
                                repo=repo,
                                workflow=workflow,
                                ref=ref,
                                current=current,
                                natural_healthy=natural_healthy,
                                list_runs=list_runs,
                                prepare_runs=prepare_runs,
                                rerun_failed_jobs=rerun_failed_jobs,
                                effect_guard=effect_guard,
                                authorization_check=authorization_check,
                                dispatch_gate=dispatch_gate,
                            )
                    return _result_for_reconciled(
                        current_reconciled,
                        natural_healthy=natural_healthy,
                        covered_action="covered",
                    )
                if _reconciled_only_covers_old_slots(
                    reconciled,
                    current_key=claim_key,
                ):
                    # Preserve a bounded migration receipt for successfully
                    # completed historical claims. Failed or still-tracking
                    # historical claims must not suppress the current slot.
                    return _result_for_reconciled(
                        reconciled,
                        natural_healthy=natural_healthy,
                        covered_action="covered",
                    )

            existing = slots.get(claim_key)
            existing = dict(existing) if isinstance(existing, dict) else None
            if existing is not None:
                if _retryable_failed_claim_key(slots) == claim_key:
                    return _retry_failed_claim(
                        root,
                        state=state,
                        slots=slots,
                        claim_key=claim_key,
                        repo=repo,
                        workflow=workflow,
                        ref=ref,
                        current=current,
                        natural_healthy=natural_healthy,
                        list_runs=list_runs,
                        prepare_runs=prepare_runs,
                        rerun_failed_jobs=rerun_failed_jobs,
                        effect_guard=effect_guard,
                        authorization_check=authorization_check,
                        dispatch_gate=dispatch_gate,
                    )
                existing_state = str(existing.get("state") or "")
                if existing_state in (
                    LEGACY_CLAIM_STATES | EXACT_TRACKING_STATES | RETRY_TRACKING_STATES
                ):
                    # Ambiguous requests are never repeated. Exact IDs are
                    # tracked by read-only observation; a completed failed run
                    # gets at most one separately claimed same-run recovery.
                    existing["lastReconciledAt"] = _iso_z(current)
                    existing["reconcileCount"] = int(existing.get("reconcileCount") or 0) + 1
                slots[claim_key] = existing
                state["slots"] = slots
                _write_state(root, state)
                if existing_state in {"COVERED"} | EXACT_TRACKING_STATES | LEGACY_CLAIM_STATES:
                    historical_retry_key = _retryable_failed_claim_key(
                        slots,
                        exclude_key=claim_key,
                    )
                    if historical_retry_key is not None:
                        return _retry_failed_claim(
                            root,
                            state=state,
                            slots=slots,
                            claim_key=historical_retry_key,
                            repo=repo,
                            workflow=workflow,
                            ref=ref,
                            current=current,
                            natural_healthy=natural_healthy,
                            list_runs=list_runs,
                            prepare_runs=prepare_runs,
                            rerun_failed_jobs=rerun_failed_jobs,
                            effect_guard=effect_guard,
                            authorization_check=authorization_check,
                            dispatch_gate=dispatch_gate,
                        )
                return _result_for_existing_claim(
                    existing,
                    natural_healthy=natural_healthy,
                )

            active_natural = _active_natural_run(runs, slot, ref=ref)
            if active_natural is not None:
                return _result_for_natural_wait(
                    active_natural,
                    slot=slot,
                    natural_healthy=natural_healthy,
                )
            covered = _covering_run(
                runs,
                slot,
                ref=ref,
                excluded_run_ids=_assigned_run_ids(slots, except_key=claim_key),
            )
            if covered is not None:
                if (
                    covered.get("event") == "schedule"
                    and str(covered.get("status") or "") in ACTIVE_RUN_STATUSES
                ):
                    return _result_for_natural_wait(
                        covered,
                        slot=slot,
                        natural_healthy=natural_healthy,
                    )
                entry = {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "firstObservedAt": _iso_z(current),
                }
                entry = _bind_run(
                    entry,
                    covered,
                    observed_at=current,
                    attribution_kind="temporal_slot_observation",
                )
                slots[claim_key] = entry
                state["slots"] = slots
                _write_state(root, state)
                historical_retry_key = _retryable_failed_claim_key(
                    slots,
                    exclude_key=claim_key,
                )
                if historical_retry_key is not None:
                    return _retry_failed_claim(
                        root,
                        state=state,
                        slots=slots,
                        claim_key=historical_retry_key,
                        repo=repo,
                        workflow=workflow,
                        ref=ref,
                        current=current,
                        natural_healthy=natural_healthy,
                        list_runs=list_runs,
                        prepare_runs=prepare_runs,
                        rerun_failed_jobs=rerun_failed_jobs,
                        effect_guard=effect_guard,
                        authorization_check=authorization_check,
                        dispatch_gate=dispatch_gate,
                    )
                return _result_for_reconciled(
                    [_reconciled_summary(claim_key, entry)],
                    natural_healthy=natural_healthy,
                    covered_action="covered",
                )

            guard = effect_guard(root, runtime_ledger_path(root))
            with guard as effect_lock:
                # Both gates are re-evaluated at the external-effect boundary;
                # the caller's earlier preflight cannot authorize a later
                # dispatch after a concurrent pause/revocation/disk transition.
                authorization_check(root)
                gate = dispatch_gate(root)
                if gate.get("allowed") is not True:
                    return {
                        "ok": True,
                        "action": "disk_gate_blocked",
                        "slotAt": slot_at,
                        "fallbackKey": claim_key,
                        "diskPressureGate": gate,
                        "githubNaturalScheduleHealthy": natural_healthy,
                    }
                # Close the race with a natural run or the controller after
                # obtaining the shared outbound-effect lock.
                refreshed = prepare_runs(
                    list_runs(repo, workflow),
                    force_refresh=True,
                )
                reconciled = _reconcile_claims(
                    slots,
                    refreshed,
                    ref=ref,
                    observed_at=current,
                )
                reconciled.extend(
                    _recover_interrupted_retry_claims(
                        slots,
                        observed_at=current,
                    )
                )
                if reconciled:
                    state["slots"] = slots
                    _write_state(root, state)
                    current_reconciled = [
                        item for item in reconciled if item.get("fallbackKey") == claim_key
                    ]
                    if current_reconciled:
                        return _result_for_reconciled(
                            current_reconciled,
                            natural_healthy=natural_healthy,
                            covered_action="covered_after_lock",
                        )
                    if _reconciled_only_covers_old_slots(
                        reconciled,
                        current_key=claim_key,
                    ):
                        return _result_for_reconciled(
                            reconciled,
                            natural_healthy=natural_healthy,
                            covered_action="covered_after_lock",
                        )
                active_natural = _active_natural_run(refreshed, slot, ref=ref)
                if active_natural is not None:
                    return _result_for_natural_wait(
                        active_natural,
                        slot=slot,
                        natural_healthy=natural_healthy,
                    )
                covered = _covering_run(
                    refreshed,
                    slot,
                    ref=ref,
                    excluded_run_ids=_assigned_run_ids(slots, except_key=claim_key),
                )
                if covered is not None:
                    if (
                        covered.get("event") == "schedule"
                        and str(covered.get("status") or "") in ACTIVE_RUN_STATUSES
                    ):
                        return _result_for_natural_wait(
                            covered,
                            slot=slot,
                            natural_healthy=natural_healthy,
                        )
                    entry = {
                        "fallbackKey": claim_key,
                        "slotAt": slot_at,
                        "firstObservedAt": _iso_z(current),
                    }
                    entry = _bind_run(
                        entry,
                        covered,
                        observed_at=current,
                        attribution_kind="temporal_slot_observation",
                    )
                    slots[claim_key] = entry
                    state["slots"] = slots
                    _write_state(root, state)
                    return _result_for_reconciled(
                        [_reconciled_summary(claim_key, entry)],
                        natural_healthy=natural_healthy,
                        covered_action="covered_after_lock",
                    )

                baseline_ids = sorted(
                    str(item.get("id")) for item in refreshed if item.get("id") is not None
                )
                claimed_at = datetime.now(UTC)
                entry = {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "firstObservedAt": _iso_z(current),
                    "state": "CLAIMED",
                    # Legacy recovery windows are measured from the durable
                    # pre-request commit, not from the cycle's earlier reads.
                    "claimedAt": _iso_z(claimed_at),
                    "baselineRunIds": baseline_ids,
                    "dispatchAttempts": 1,
                    "rerunAttempts": 0,
                    "legacyFailedJobRerunAttempts": 0,
                    "fullWorkflowRerunAttempts": 0,
                    "fullWorkflowRerunProtocol": FULL_WORKFLOW_RERUN_PROTOCOL,
                }
                slots[claim_key] = entry
                state["slots"] = slots
                state["lastFallbackClaim"] = {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "claimedAt": entry["claimedAt"],
                }
                # This fsynced write is the commit point and must precede the
                # network request.
                _write_state(root, state)
                lock_fd = effect_lock.fileno() if hasattr(effect_lock, "fileno") else None
                try:
                    receipt = _normalize_dispatch_receipt(
                        dispatch(repo, workflow, ref, window_hours, lock_fd),
                        repo=repo,
                    )
                except Exception as exc:
                    entry.update(
                        {
                            "state": "UNCERTAIN",
                            "dispatchFinishedAt": _iso_z(datetime.now(UTC)),
                            "lastError": f"{type(exc).__name__}:{str(exc)[:300]}",
                        }
                    )
                    slots[claim_key] = entry
                    state["slots"] = slots
                    _write_state(root, state)
                    return {
                        "ok": False,
                        "action": "dispatch_uncertain",
                        "slotAt": slot_at,
                        "fallbackKey": claim_key,
                        "error": entry["lastError"],
                        "githubNaturalScheduleHealthy": natural_healthy,
                    }

                dispatch_finished_at = _iso_z(datetime.now(UTC))
                entry.update(
                    {
                        "state": "BOUND" if receipt is not None else "REQUESTED",
                        "dispatchFinishedAt": dispatch_finished_at,
                        "attributionKind": (
                            "exact_dispatch_receipt"
                            if receipt is not None
                            else "legacy_no_run_details"
                        ),
                    }
                )
                if receipt is not None:
                    entry.update(receipt)
                    entry["run"] = {
                        "runId": receipt["workflowRunId"],
                        "event": "workflow_dispatch",
                        "status": None,
                        "conclusion": None,
                        "createdAt": None,
                        "url": receipt["workflowRunUrl"],
                    }
                slots[claim_key] = entry
                state["slots"] = slots
                state["lastFallbackRequest"] = {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "requestedAt": entry["dispatchFinishedAt"],
                }
                if receipt is not None:
                    state["lastFallbackRequest"].update(receipt)
                _write_state(root, state)
                result = {
                    "ok": True,
                    "action": "fallback_requested",
                    "slotAt": slot_at,
                    "fallbackKey": claim_key,
                    "claimState": entry["state"],
                    "githubNaturalScheduleHealthy": natural_healthy,
                }
                if receipt is not None:
                    result["run"] = entry["run"]
                return result
    except RuntimeLockBusy:
        return {
            "ok": True,
            "action": "busy",
            "slotAt": slot_at,
            "fallbackKey": claim_key,
            "githubNaturalScheduleHealthy": False,
        }
