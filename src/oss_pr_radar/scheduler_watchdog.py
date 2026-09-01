"""Independent, slot-idempotent fallback for the hourly Radar workflow.

GitHub's native ``schedule`` event remains the natural-schedule health signal.
This worker only protects the business scan cadence: after a bounded grace
period it dispatches at most once for an uncovered hourly slot.  A durable
claim is committed before the external request, so a timeout or process crash
can be reconciled without issuing the same fallback twice.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, ContextManager

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
PENDING_CLAIM_STATES = frozenset({"CLAIMED", "REQUESTED", "UNCERTAIN"})
MAX_RETAINED_SLOTS = 48
NATURAL_SCHEDULE_CADENCE_HOURS = 1.0
REQUEST_TIME_PRECISION = timedelta(seconds=2)

RunLister = Callable[[str, str], list[dict[str, Any]]]
DispatchRunner = Callable[[str, str, str, float, int | None], None]
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


def _run_covers_slot(run: dict[str, Any], slot: datetime, *, ref: str) -> bool:
    # event=schedule is a trigger canary only.  It never proves that the
    # workflow_dispatch business scan for this slot ran.
    if run.get("event") != "workflow_dispatch":
        return False
    if run.get("head_branch") not in {None, "", ref}:
        return False
    created = _run_time(run)
    if created is None or not slot <= created < slot + timedelta(hours=1):
        return False
    status = str(run.get("status") or "")
    conclusion = str(run.get("conclusion") or "")
    return status in ACTIVE_RUN_STATUSES or (status == "completed" and conclusion == "success")


def _run_id(run: dict[str, Any]) -> str | None:
    value = run.get("id")
    return str(value) if value is not None else None


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


def _entry_run_id(entry: dict[str, Any]) -> str | None:
    run = entry.get("run")
    if not isinstance(run, dict):
        return None
    value = run.get("runId")
    return str(value) if value is not None else None


def _claim_backed(entry: dict[str, Any]) -> bool:
    return isinstance(entry.get("baselineRunIds"), list) and bool(entry.get("claimedAt"))


def _claim_request_window(entry: dict[str, Any]) -> tuple[datetime, datetime] | None:
    try:
        claimed = parse_time(str(entry["claimedAt"])).astimezone(UTC)
    except (KeyError, TypeError, ValueError):
        return None
    raw_finished = entry.get("dispatchFinishedAt")
    if raw_finished:
        try:
            finished = parse_time(str(raw_finished)).astimezone(UTC)
        except (TypeError, ValueError):
            return None
        if finished + REQUEST_TIME_PRECISION < claimed:
            return None
    else:
        # A crash may leave the fsynced CLAIMED record behind while the
        # at-most-30-second dispatch request was already in flight.
        finished = claimed + timedelta(seconds=30)
    return claimed - REQUEST_TIME_PRECISION, finished + REQUEST_TIME_PRECISION


def _claim_candidate(
    runs: list[dict[str, Any]],
    entry: dict[str, Any],
    *,
    ref: str,
    reserved_run_ids: set[str],
) -> dict[str, Any] | None:
    baseline = entry.get("baselineRunIds")
    request_window = _claim_request_window(entry)
    if not isinstance(baseline, list) or request_window is None:
        return None
    baseline_ids = {str(value) for value in baseline}
    requested_after, requested_before = request_window
    candidates: list[dict[str, Any]] = []
    for run in runs:
        run_id = _run_id(run)
        created = _run_time(run)
        if (
            run_id is None
            or run_id in baseline_ids
            or run_id in reserved_run_ids
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") not in {None, "", ref}
            or created is None
            or not requested_after <= created <= requested_before
        ):
            continue
        status = str(run.get("status") or "")
        if status in ACTIVE_RUN_STATUSES or status == "completed":
            candidates.append(run)
    return min(
        candidates,
        key=lambda item: (_run_time(item) or requested_before, _run_id(item) or ""),
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


def _reconcile_pending_claims(
    slots: dict[str, Any],
    runs: list[dict[str, Any]],
    *,
    ref: str,
    observed_at: datetime,
) -> list[dict[str, Any]]:
    """Bind post-request runs to their durable claims before temporal slot matching."""

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
            and str(raw_entry.get("state") or "") in PENDING_CLAIM_STATES
        ),
        key=lambda item: (str(item[1].get("claimedAt") or ""), item[0]),
    )
    reconciled: list[dict[str, Any]] = []
    for key, entry in pending:
        candidate = _claim_candidate(
            runs,
            entry,
            ref=ref,
            reserved_run_ids=reserved_run_ids,
        )
        if candidate is None:
            continue
        run_id = _run_id(candidate)
        if run_id is None:  # pragma: no cover - guarded by _claim_candidate
            continue

        # Older releases could first attribute the same delayed run to the
        # next clock-hour slot.  A request-backed claim is authoritative, so
        # remove only those unclaimed temporal projections while preserving
        # every independently claimed assignment.
        for other_key, raw_other in list(slots.items()):
            if other_key == key or not isinstance(raw_other, dict):
                continue
            if _entry_run_id(raw_other) != run_id:
                continue
            if _claim_backed(raw_other):
                raise RuntimeError("scheduler watchdog run is assigned to multiple claims")
            del slots[other_key]

        status = str(candidate.get("status") or "")
        conclusion = str(candidate.get("conclusion") or "")
        covered = status in ACTIVE_RUN_STATUSES or (
            status == "completed" and conclusion == "success"
        )
        entry.update(
            {
                "state": "COVERED" if covered else "FAILED",
                "coverageKind": "fallback",
                "run": _run_summary(candidate),
                "lastReconciledAt": _iso_z(observed_at),
                "reconcileCount": int(entry.get("reconcileCount") or 0) + 1,
            }
        )
        if covered:
            entry["coveredAt"] = _iso_z(observed_at)
            entry.pop("failedAt", None)
        else:
            entry["failedAt"] = _iso_z(observed_at)
            entry.pop("coveredAt", None)
        slots[key] = entry
        reserved_run_ids.add(run_id)
        reconciled.append(
            {
                "fallbackKey": key,
                "slotAt": entry.get("slotAt"),
                "state": entry["state"],
                "run": entry["run"],
            }
        )
    return reconciled


def _latest_natural(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    scheduled = [run for run in runs if run.get("event") == "schedule" and _run_time(run)]
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


def _default_dispatch(
    repo: str,
    workflow: str,
    ref: str,
    window_hours: float,
    lock_fd: int | None,
) -> None:
    arguments = [
        "gh",
        "workflow",
        "run",
        workflow,
        "--repo",
        repo,
        "--ref",
        ref,
        "-f",
        f"window_hours={window_hours:g}",
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
        # The server may have accepted the request before the client observed
        # the timeout.  The durable slot claim deliberately remains consumed.
        raise RuntimeError(f"dispatch outcome uncertain: {type(exc).__name__}:{exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "GitHub dispatch failed")[:300]
        raise RuntimeError(f"dispatch outcome uncertain: {detail}")


def _default_dispatch_gate(root: Path) -> dict[str, Any]:
    return disk_pressure_gate(root, worker=WATCHDOG_WORKER)


def _run_summary(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "runId": run.get("id"),
        "event": run.get("event"),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "createdAt": run.get("created_at"),
        "url": run.get("html_url"),
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
    dispatch: DispatchRunner = _default_dispatch,
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
    try:
        lock_context = exclusive_lock(lock_path, blocking=False)
        with lock_context:
            state = _strict_state(root)
            slots = dict(state.get("slots") or {})
            runs = list_runs(repo, workflow)
            natural = _latest_natural(runs)
            natural_success, natural_fresh, natural_healthy, freshness_hours = (
                _natural_schedule_health(
                    natural,
                    now=current,
                    window_hours=window_hours,
                )
            )
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
                        "healthy": natural_healthy,
                        "sourceEvent": "schedule",
                    },
                }
            )
            reconciled = _reconcile_pending_claims(
                slots,
                runs,
                ref=ref,
                observed_at=current,
            )
            if reconciled:
                state["slots"] = slots
                _write_state(root, state)
                failed = next(
                    (item for item in reconciled if item["state"] == "FAILED"),
                    None,
                )
                primary = failed or reconciled[0]
                return {
                    "ok": failed is None,
                    "action": "fallback_failed" if failed is not None else "covered",
                    "slotAt": primary["slotAt"],
                    "fallbackKey": primary["fallbackKey"],
                    "coverageKind": "fallback",
                    "run": primary["run"],
                    "reconciledClaims": reconciled,
                    "githubNaturalScheduleHealthy": natural_healthy,
                }

            existing = slots.get(claim_key)
            existing = dict(existing) if isinstance(existing, dict) else None
            if existing is not None and str(existing.get("state") or "") in PENDING_CLAIM_STATES:
                # A durable request may only be completed by a run that is new
                # relative to its own baseline and falls in its request window.
                # Do not let an unrelated run from the same clock hour satisfy it.
                existing["lastReconciledAt"] = _iso_z(current)
                existing["reconcileCount"] = int(existing.get("reconcileCount") or 0) + 1
                slots[claim_key] = existing
                state["slots"] = slots
                _write_state(root, state)
                return {
                    "ok": True,
                    "action": "reconciling",
                    "slotAt": slot_at,
                    "fallbackKey": claim_key,
                    "claimState": existing.get("state"),
                    "githubNaturalScheduleHealthy": natural_healthy,
                }

            covered = _covering_run(
                runs,
                slot,
                ref=ref,
                excluded_run_ids=_assigned_run_ids(slots, except_key=claim_key),
            )
            if covered is not None:
                entry = existing or {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "firstObservedAt": _iso_z(current),
                }
                entry.update(
                    {
                        "state": "COVERED",
                        "coveredAt": _iso_z(current),
                        "coverageKind": "fallback",
                        "run": _run_summary(covered),
                    }
                )
                slots[claim_key] = entry
                state["slots"] = slots
                _write_state(root, state)
                return {
                    "ok": True,
                    "action": "covered",
                    "slotAt": slot_at,
                    "fallbackKey": claim_key,
                    "coverageKind": entry["coverageKind"],
                    "run": entry["run"],
                    "githubNaturalScheduleHealthy": natural_healthy,
                }

            if existing is not None:
                # Any prior claim is final for this fallback key.  In
                # particular, REQUESTED/UNCERTAIN is reconciled by reads only.
                existing["lastReconciledAt"] = _iso_z(current)
                existing["reconcileCount"] = int(existing.get("reconcileCount") or 0) + 1
                slots[claim_key] = existing
                state["slots"] = slots
                _write_state(root, state)
                return {
                    "ok": True,
                    "action": "reconciling",
                    "slotAt": slot_at,
                    "fallbackKey": claim_key,
                    "claimState": existing.get("state"),
                    "githubNaturalScheduleHealthy": natural_healthy,
                }

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
                refreshed = list_runs(repo, workflow)
                reconciled = _reconcile_pending_claims(
                    slots,
                    refreshed,
                    ref=ref,
                    observed_at=current,
                )
                if reconciled:
                    state["slots"] = slots
                    _write_state(root, state)
                    failed = next(
                        (item for item in reconciled if item["state"] == "FAILED"),
                        None,
                    )
                    primary = failed or reconciled[0]
                    return {
                        "ok": failed is None,
                        "action": "fallback_failed" if failed is not None else "covered_after_lock",
                        "slotAt": primary["slotAt"],
                        "fallbackKey": primary["fallbackKey"],
                        "coverageKind": "fallback",
                        "run": primary["run"],
                        "reconciledClaims": reconciled,
                        "githubNaturalScheduleHealthy": natural_healthy,
                    }
                covered = _covering_run(
                    refreshed,
                    slot,
                    ref=ref,
                    excluded_run_ids=_assigned_run_ids(slots, except_key=claim_key),
                )
                if covered is not None:
                    entry = {
                        "fallbackKey": claim_key,
                        "slotAt": slot_at,
                        "firstObservedAt": _iso_z(current),
                        "state": "COVERED",
                        "coveredAt": _iso_z(current),
                        "coverageKind": "fallback",
                        "run": _run_summary(covered),
                    }
                    slots[claim_key] = entry
                    state["slots"] = slots
                    _write_state(root, state)
                    return {
                        "ok": True,
                        "action": "covered_after_lock",
                        "slotAt": slot_at,
                        "fallbackKey": claim_key,
                        "coverageKind": entry["coverageKind"],
                        "run": entry["run"],
                        "githubNaturalScheduleHealthy": natural_healthy,
                    }

                baseline_ids = sorted(
                    str(item.get("id")) for item in refreshed if item.get("id") is not None
                )
                entry = {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "firstObservedAt": _iso_z(current),
                    "state": "CLAIMED",
                    "claimedAt": _iso_z(current),
                    "baselineRunIds": baseline_ids,
                    "dispatchAttempts": 1,
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
                    dispatch(repo, workflow, ref, window_hours, lock_fd)
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

                entry.update(
                    {
                        "state": "REQUESTED",
                        "dispatchFinishedAt": _iso_z(datetime.now(UTC)),
                    }
                )
                slots[claim_key] = entry
                state["slots"] = slots
                state["lastFallbackRequest"] = {
                    "fallbackKey": claim_key,
                    "slotAt": slot_at,
                    "requestedAt": entry["dispatchFinishedAt"],
                }
                _write_state(root, state)
                return {
                    "ok": True,
                    "action": "fallback_requested",
                    "slotAt": slot_at,
                    "fallbackKey": claim_key,
                    "githubNaturalScheduleHealthy": natural_healthy,
                }
    except RuntimeLockBusy:
        return {
            "ok": True,
            "action": "busy",
            "slotAt": slot_at,
            "fallbackKey": claim_key,
            "githubNaturalScheduleHealthy": False,
        }
