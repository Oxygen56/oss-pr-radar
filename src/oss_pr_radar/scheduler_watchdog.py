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
MAX_RETAINED_SLOTS = 48
NATURAL_SCHEDULE_CADENCE_HOURS = 1.0
LEGACY_TIME_PRECISION = timedelta(seconds=2)
LEGACY_ATTRIBUTION_WINDOW = timedelta(seconds=30)

RunLister = Callable[[str, str], list[dict[str, Any]]]
DispatchReceipt = dict[str, Any]
DispatchRunner = Callable[
    [str, str, str, float, int | None],
    DispatchReceipt | None,
]
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
    if run.get("head_branch") != ref:
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
    if state == "COVERED":
        entry["coverageKind"] = "fallback"
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
    return {
        "fallbackKey": key,
        "slotAt": entry.get("slotAt"),
        "state": entry.get("state"),
        "run": entry.get("run"),
    }


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
            or state not in EXACT_TRACKING_STATES | LEGACY_CLAIM_STATES
        ):
            continue
        run = runs_by_id.get(run_id)
        if run is None:
            if state not in EXACT_TRACKING_STATES:
                entry["state"] = "BOUND"
                entry["lastReconciledAt"] = _iso_z(observed_at)
                entry["reconcileCount"] = int(entry.get("reconcileCount") or 0) + 1
                slots[key] = entry
                reconciled.append(_reconciled_summary(key, entry))
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
    return reconciled


def _result_for_reconciled(
    reconciled: list[dict[str, Any]],
    *,
    natural_healthy: bool,
    covered_action: str,
) -> dict[str, Any]:
    failed = next((item for item in reconciled if item["state"] == "FAILED"), None)
    tracking = next(
        (item for item in reconciled if item["state"] in EXACT_TRACKING_STATES),
        None,
    )
    primary = failed or tracking or reconciled[0]
    if failed is not None:
        action = "fallback_failed"
    elif tracking is not None:
        action = "tracking"
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
        result["coverageKind"] = "fallback"
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
    elif state == "FAILED":
        action = "fallback_failed"
        ok = False
    elif state == "COVERED":
        action = "covered"
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
    if state in EXACT_TRACKING_STATES | {"FAILED", "COVERED"}:
        result["run"] = entry.get("run")
    if state == "COVERED":
        result["coverageKind"] = "fallback"
    return result


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
            reconciled = _reconcile_claims(
                slots,
                runs,
                ref=ref,
                observed_at=current,
            )
            if reconciled:
                state["slots"] = slots
                _write_state(root, state)
                return _result_for_reconciled(
                    reconciled,
                    natural_healthy=natural_healthy,
                    covered_action="covered",
                )

            existing = slots.get(claim_key)
            existing = dict(existing) if isinstance(existing, dict) else None
            if existing is not None:
                existing_state = str(existing.get("state") or "")
                if existing_state in LEGACY_CLAIM_STATES | EXACT_TRACKING_STATES:
                    # Durable requests never retry. Exact IDs are tracked by
                    # read-only observation; legacy claims use bounded migration.
                    existing["lastReconciledAt"] = _iso_z(current)
                    existing["reconcileCount"] = int(existing.get("reconcileCount") or 0) + 1
                slots[claim_key] = existing
                state["slots"] = slots
                _write_state(root, state)
                return _result_for_existing_claim(
                    existing,
                    natural_healthy=natural_healthy,
                )

            covered = _covering_run(
                runs,
                slot,
                ref=ref,
                excluded_run_ids=_assigned_run_ids(slots, except_key=claim_key),
            )
            if covered is not None:
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
                refreshed = list_runs(repo, workflow)
                reconciled = _reconcile_claims(
                    slots,
                    refreshed,
                    ref=ref,
                    observed_at=current,
                )
                if reconciled:
                    state["slots"] = slots
                    _write_state(root, state)
                    return _result_for_reconciled(
                        reconciled,
                        natural_healthy=natural_healthy,
                        covered_action="covered_after_lock",
                    )
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
