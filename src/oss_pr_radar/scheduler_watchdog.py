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
RELEVANT_EVENTS = frozenset({"schedule", "workflow_dispatch"})
MAX_RETAINED_SLOTS = 48

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
    if run.get("event") not in RELEVANT_EVENTS:
        return False
    if run.get("head_branch") not in {None, "", ref}:
        return False
    created = _run_time(run)
    if created is None or not slot <= created < slot + timedelta(hours=1):
        return False
    status = str(run.get("status") or "")
    conclusion = str(run.get("conclusion") or "")
    return status in ACTIVE_RUN_STATUSES or (status == "completed" and conclusion == "success")


def _covering_run(runs: list[dict[str, Any]], slot: datetime, *, ref: str) -> dict[str, Any] | None:
    candidates = [run for run in runs if _run_covers_slot(run, slot, ref=ref)]
    return max(candidates, key=lambda item: _run_time(item) or slot, default=None)


def _latest_natural(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    scheduled = [run for run in runs if run.get("event") == "schedule" and _run_time(run)]
    return max(
        scheduled,
        key=lambda item: _run_time(item) or datetime.min.replace(tzinfo=UTC),
        default=None,
    )


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
            state.update(
                {
                    "repo": repo,
                    "workflow": workflow,
                    "ref": ref,
                    "lastCheckedAt": _iso_z(current),
                    # Natural health is intentionally derived only from
                    # event=schedule and cannot be made green by this worker.
                    "latestNaturalSchedule": _run_summary(natural) if natural else None,
                }
            )
            existing = slots.get(claim_key)
            existing = dict(existing) if isinstance(existing, dict) else None
            covered = _covering_run(runs, slot, ref=ref)
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
                        "coverageKind": "natural"
                        if covered.get("event") == "schedule"
                        else "fallback",
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
                    "githubNaturalScheduleHealthy": covered.get("event") == "schedule"
                    and covered.get("conclusion") == "success",
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
                    "githubNaturalScheduleHealthy": False,
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
                        "githubNaturalScheduleHealthy": False,
                    }
                # Close the race with a natural run or the controller after
                # obtaining the shared outbound-effect lock.
                refreshed = list_runs(repo, workflow)
                covered = _covering_run(refreshed, slot, ref=ref)
                if covered is not None:
                    entry = {
                        "fallbackKey": claim_key,
                        "slotAt": slot_at,
                        "firstObservedAt": _iso_z(current),
                        "state": "COVERED",
                        "coveredAt": _iso_z(current),
                        "coverageKind": "natural"
                        if covered.get("event") == "schedule"
                        else "fallback",
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
                        "githubNaturalScheduleHealthy": covered.get("event") == "schedule"
                        and covered.get("conclusion") == "success",
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
                        "githubNaturalScheduleHealthy": False,
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
                    "githubNaturalScheduleHealthy": False,
                }
    except RuntimeLockBusy:
        return {
            "ok": True,
            "action": "busy",
            "slotAt": slot_at,
            "fallbackKey": claim_key,
            "githubNaturalScheduleHealthy": False,
        }
