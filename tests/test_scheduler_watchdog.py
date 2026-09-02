from __future__ import annotations

import json
import stat
import subprocess
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.scheduler_watchdog import (
    BUSINESS_CHAIN_JOBS,
    FULL_CHAIN_JOBS,
    WATCHDOG_SCHEMA,
    _default_dispatch,
    _default_rerun_failed_jobs,
    eligible_slot,
    fallback_key,
    full_chain_evidence,
    proven_watchdog_run_ids,
    watchdog_cycle,
)

NOW = datetime(2026, 8, 31, 3, 31, tzinfo=UTC)
SLOT = datetime(2026, 8, 31, 3, 17, tzinfo=UTC)


def _jobs(*, canary_only: bool = False, failed: set[str] | None = None) -> list[dict]:
    names = {"schedule-canary"} if canary_only else set(FULL_CHAIN_JOBS)
    failed = failed or set()
    return [
        {
            "name": name,
            "status": "completed",
            "conclusion": "failure" if name in failed else "success",
        }
        for name in sorted(names)
    ]


def _root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    ledger = state / "ledger.sqlite"
    ledger.touch()
    monkeypatch.setattr("oss_pr_radar.scheduler_watchdog.runtime_ledger_path", lambda _root: ledger)
    return tmp_path


def _guard(_root: Path, _ledger: Path):
    return nullcontext(None)


def _authorized(_root: Path):
    return {"state": "ACTIVE"}


def _disk_allowed(_root: Path):
    return {"allowed": True}


def _watchdog(root: Path, **kwargs):
    return watchdog_cycle(
        root,
        authorization_check=_authorized,
        dispatch_gate=_disk_allowed,
        **kwargs,
    )


def _run(
    *,
    event: str,
    run_id: int,
    created_at: str = "2026-08-31T03:20:00Z",
    status: str = "completed",
    conclusion: str | None = "success",
    head_branch: str | None = "main",
    run_attempt: int = 1,
    jobs: list[dict] | None = None,
) -> dict:
    result = {
        "id": run_id,
        "event": event,
        "created_at": created_at,
        "updated_at": created_at,
        "status": status,
        "conclusion": conclusion,
        "head_branch": head_branch,
        "run_attempt": run_attempt,
        "html_url": f"https://github.com/Oxygen56/oss-pr-radar/actions/runs/{run_id}",
    }
    if jobs is not None:
        result["jobs"] = jobs
    return result


def _receipt(run_id: int) -> dict:
    return {
        "workflowRunId": run_id,
        "runApiUrl": (f"https://api.github.com/repos/Oxygen56/oss-pr-radar/actions/runs/{run_id}"),
        "workflowRunUrl": (f"https://github.com/Oxygen56/oss-pr-radar/actions/runs/{run_id}"),
    }


def test_eligible_slot_waits_thirteen_minutes_and_recovers_latest_slot_after_sleep():
    assert eligible_slot(datetime(2026, 8, 31, 3, 29, tzinfo=UTC)) == datetime(
        2026, 8, 31, 2, 17, tzinfo=UTC
    )
    assert eligible_slot(NOW) == SLOT
    assert eligible_slot(datetime(2026, 9, 1, 8, 47, tzinfo=UTC)) == datetime(
        2026, 9, 1, 8, 17, tzinfo=UTC
    )


def test_natural_full_chain_covers_slot_without_fallback(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    dispatched = []
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [_run(event="schedule", run_id=7, jobs=_jobs())],
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    assert result["action"] == "covered"
    assert result["coverageKind"] == "natural"
    assert result["githubNaturalScheduleHealthy"] is True
    assert dispatched == []
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["naturalScheduleCanary"]["latestRunSuccessful"] is True
    assert state["naturalScheduleCanary"]["latestRunFresh"] is True
    assert state["naturalScheduleCanary"]["freshnessWindowHours"] == 2.0
    assert state["naturalScheduleCanary"]["healthy"] is True
    assert state["naturalScheduleCanary"]["fullChainHealthy"] is True
    assert state["naturalScheduleCanary"]["latestRun"]["event"] == "schedule"


def test_canary_only_schedule_falls_back_and_is_not_full_chain_healthy(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    dispatched = []
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            _run(event="schedule", run_id=6, jobs=_jobs(canary_only=True))
        ],
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    assert result["action"] == "fallback_requested"
    assert result["githubNaturalScheduleHealthy"] is False
    assert len(dispatched) == 1
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["naturalScheduleCanary"]["healthy"] is True
    assert state["naturalScheduleCanary"]["fullChainHealthy"] is False
    assert state["naturalScheduleFullChain"]["proven"] is False


def test_stale_successful_natural_run_is_unhealthy_and_does_not_suppress_fallback(
    tmp_path, monkeypatch
):
    root = _root(tmp_path, monkeypatch)
    dispatched = []
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            _run(
                event="schedule",
                run_id=70,
                created_at="2026-08-30T20:46:00Z",
            )
        ],
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    assert result["action"] == "fallback_requested"
    assert result["githubNaturalScheduleHealthy"] is False
    assert len(dispatched) == 1
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["naturalScheduleCanary"]["latestRunSuccessful"] is True
    assert state["naturalScheduleCanary"]["latestRunFresh"] is False
    assert state["naturalScheduleCanary"]["healthy"] is False


def test_larger_scan_window_widens_natural_canary_freshness_tolerance(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    result = _watchdog(
        root,
        now=NOW,
        window_hours=3.0,
        list_runs=lambda _repo, _workflow: [
            _run(
                event="schedule",
                run_id=71,
                created_at="2026-08-31T01:01:00Z",
                jobs=_jobs(),
            )
        ],
        dispatch=lambda *_args: None,
        effect_guard=_guard,
    )

    assert result["githubNaturalScheduleHealthy"] is True
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["naturalScheduleCanary"]["freshnessWindowHours"] == 3.0
    assert state["naturalScheduleCanary"]["latestRunFresh"] is True


def test_fresh_successful_dispatch_only_run_never_marks_natural_schedule_healthy(
    tmp_path, monkeypatch
):
    root = _root(tmp_path, monkeypatch)
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [_run(event="workflow_dispatch", run_id=72)],
        dispatch=lambda *_args: pytest.fail("covered slot must not dispatch"),
        effect_guard=_guard,
    )

    assert result["action"] == "covered"
    assert result["githubNaturalScheduleHealthy"] is False
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["naturalScheduleCanary"]["observed"] is False
    assert state["naturalScheduleCanary"]["latestRun"] is None
    assert state["naturalScheduleCanary"]["healthy"] is False


def test_active_natural_run_is_transient_wait_and_does_not_claim_slot(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    dispatched = []
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            _run(
                event="schedule",
                run_id=8,
                status="in_progress",
                conclusion=None,
            )
        ],
        dispatch=lambda *_args: dispatched.append(True),
        effect_guard=_guard,
    )

    assert result["action"] == "natural_active"
    assert result["githubNaturalScheduleHealthy"] is False
    assert dispatched == []
    # The transient wait is intentionally not persisted: native schedule runs
    # are never exact watchdog claims and therefore cannot poison the next
    # reconciliation cycle.
    assert not (root / "state" / "scheduler-watchdog.json").exists()


def test_active_natural_run_then_full_chain_success_is_covered_without_dispatch(
    tmp_path, monkeypatch
):
    root = _root(tmp_path, monkeypatch)
    active = _run(
        event="schedule",
        run_id=81,
        status="in_progress",
        conclusion=None,
    )
    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [active],
        dispatch=lambda *_args: pytest.fail("active native run must not dispatch"),
        effect_guard=_guard,
    )
    completed = active | {
        "status": "completed",
        "conclusion": "success",
        "updated_at": "2026-08-31T03:35:00Z",
        "jobs": _jobs(),
    }
    second = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [completed],
        dispatch=lambda *_args: pytest.fail("proven native run must cover slot"),
        effect_guard=_guard,
    )

    assert first["action"] == "natural_active"
    assert second["action"] == "covered"
    assert second["coverageKind"] == "natural"
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["slots"][second["fallbackKey"]]["coverageKind"] == "natural"


def test_active_natural_run_then_partial_terminal_run_falls_back(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    active = _run(
        event="schedule",
        run_id=82,
        status="in_progress",
        conclusion=None,
    )
    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [active],
        dispatch=lambda *_args: pytest.fail("active native run must not dispatch"),
        effect_guard=_guard,
    )
    partial = active | {
        "status": "completed",
        "conclusion": "success",
        "updated_at": "2026-08-31T03:35:00Z",
        "jobs": _jobs(failed={"scan"}),
    }
    dispatched = []
    second = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [partial],
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    assert first["action"] == "natural_active"
    assert second["action"] == "fallback_requested"
    assert len(dispatched) == 1


def test_full_chain_evidence_fails_closed_for_missing_or_duplicate_jobs():
    completed_schedule = _run(event="schedule", run_id=83)
    assert full_chain_evidence(completed_schedule, _jobs(canary_only=True)) is False
    missing = _jobs()
    missing.pop()
    assert full_chain_evidence(completed_schedule, missing) is False
    duplicate = _jobs()
    duplicate.append({"name": "scan", "status": "completed", "conclusion": "success"})
    assert full_chain_evidence(completed_schedule, duplicate) is False


def test_full_chain_evidence_accepts_business_dispatch_jobs_but_not_natural_without_proof():
    dispatch = _run(event="workflow_dispatch", run_id=84)
    assert (
        full_chain_evidence(
            dispatch,
            [{"name": name, "conclusion": "success"} for name in sorted(BUSINESS_CHAIN_JOBS)],
        )
        is True
    )
    natural = _run(event="schedule", run_id=85)
    assert full_chain_evidence(natural, _jobs(canary_only=True)) is False


def test_schedule_jobs_api_error_fails_closed_and_requests_fallback(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    queried = []
    dispatched = []

    def list_jobs(repo, run_id):
        queried.append((repo, run_id))
        raise RuntimeError("jobs endpoint unavailable")

    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [_run(event="schedule", run_id=86)],
        list_jobs=list_jobs,
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    assert result["action"] == "fallback_requested"
    assert queried
    assert all(run_id == 86 for _repo, run_id in queried)
    assert len(dispatched) == 1


def test_embedded_schedule_jobs_are_authoritative_without_jobs_api(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [_run(event="schedule", run_id=87, jobs=_jobs())],
        list_jobs=lambda *_args: pytest.fail("embedded jobs must not be queried"),
        dispatch=lambda *_args: pytest.fail("embedded full proof covers slot"),
        effect_guard=_guard,
    )

    assert result["action"] == "covered"
    assert result["coverageKind"] == "natural"


def test_lock_recheck_refreshes_same_run_jobs_evidence(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    run = _run(event="schedule", run_id=88)
    responses = [run, run]
    job_responses = [_jobs(canary_only=True), _jobs()]
    queried = []
    dispatched = []

    def list_jobs(repo, run_id):
        queried.append((repo, run_id))
        return job_responses.pop(0)

    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [responses.pop(0)],
        list_jobs=list_jobs,
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    # The first observation is a canary-only graph; the lock-bound refresh
    # sees the same run metadata but newly completed business jobs and must
    # cover the slot instead of dispatching a duplicate fallback.
    assert result["action"] == "covered_after_lock"
    assert result["coverageKind"] == "natural"
    assert dispatched == []
    assert len(queried) == 2


def test_publication_pause_does_not_consume_fallback_key(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)

    def paused(_root, _ledger):
        raise PermissionError("GITHUB_OUTBOUND_PAUSED")

    with pytest.raises(PermissionError, match="PAUSED"):
        _watchdog(
            root,
            now=NOW,
            list_runs=lambda _repo, _workflow: [],
            dispatch=lambda *_args: pytest.fail("paused worker must not dispatch"),
            effect_guard=paused,
        )

    assert not (root / "state" / "scheduler-watchdog.json").exists()


def test_fallback_claim_is_fsynced_before_dispatch_and_requested_once(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    observations = []

    def dispatch(*_args):
        state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
        key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
        observations.append(state["slots"][key]["state"])

    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [],
        dispatch=dispatch,
        effect_guard=_guard,
    )

    assert result["action"] == "fallback_requested"
    assert observations == ["CLAIMED"]
    state_path = root / "state" / "scheduler-watchdog.json"
    state = json.loads(state_path.read_text())
    assert state["schemaVersion"] == WATCHDOG_SCHEMA
    assert state["slots"][result["fallbackKey"]]["state"] == "REQUESTED"
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_timeout_consumes_same_fallback_key_and_later_cycles_only_reconcile(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    attempts = []

    def uncertain(*_args):
        attempts.append("attempt")
        raise RuntimeError("dispatch outcome uncertain: timeout")

    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [],
        dispatch=uncertain,
        effect_guard=_guard,
    )
    second = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [],
        dispatch=uncertain,
        effect_guard=_guard,
    )

    assert first["action"] == "dispatch_uncertain"
    assert second["action"] == "reconciling"
    assert second["fallbackKey"] == first["fallbackKey"]
    assert second["githubNaturalScheduleHealthy"] is False
    assert attempts == ["attempt"]


def test_delayed_dispatch_run_reconciles_claim_without_second_request(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    attempts = []
    responses = [[], [], [_run(event="workflow_dispatch", run_id=9)]]

    def list_runs(_repo, _workflow):
        return responses.pop(0)

    first = _watchdog(
        root,
        now=NOW,
        list_runs=list_runs,
        dispatch=lambda *_args: attempts.append("attempt"),
        effect_guard=_guard,
    )
    state_path = root / "state" / "scheduler-watchdog.json"
    state = json.loads(state_path.read_text())
    state["slots"][first["fallbackKey"]]["claimedAt"] = "2026-08-31T03:31:00Z"
    state["slots"][first["fallbackKey"]]["dispatchFinishedAt"] = "2026-08-31T03:31:01Z"
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    # Legacy records have no exact ID. A bounded claim-time migration still
    # accepts the observed production delay, including >2s after CLI return.
    responses[-1][0]["created_at"] = "2026-08-31T03:31:09Z"
    second = _watchdog(
        root,
        now=NOW,
        list_runs=list_runs,
        dispatch=lambda *_args: attempts.append("duplicate"),
        effect_guard=_guard,
    )

    assert first["action"] == "fallback_requested"
    assert second["action"] == "covered"
    assert second["coverageKind"] == "fallback"
    assert second["githubNaturalScheduleHealthy"] is False
    assert attempts == ["attempt"]


def test_exact_dispatch_id_tracks_running_then_success_without_time_attribution(
    tmp_path, monkeypatch
):
    root = _root(tmp_path, monkeypatch)
    attempts = []
    initial_responses = [[], []]

    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: initial_responses.pop(0),
        dispatch=lambda *_args: attempts.append("attempt") or _receipt(900),
        effect_guard=_guard,
    )

    state_path = root / "state" / "scheduler-watchdog.json"
    state = json.loads(state_path.read_text())
    state["slots"][first["fallbackKey"]]["dispatchFinishedAt"] = "2026-08-31T03:31:01Z"
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    queued = _run(
        event="workflow_dispatch",
        run_id=900,
        created_at="2026-08-31T03:31:04Z",
        status="queued",
        conclusion=None,
    )
    running = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [queued],
        dispatch=lambda *_args: attempts.append("duplicate"),
        effect_guard=_guard,
    )
    completed = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            queued | {"status": "completed", "conclusion": "success"}
        ],
        dispatch=lambda *_args: attempts.append("duplicate"),
        effect_guard=_guard,
    )

    assert first["action"] == "fallback_requested"
    assert first["claimState"] == "BOUND"
    assert first["run"]["runId"] == 900
    assert running["action"] == "tracking"
    assert running["claimState"] == "RUNNING"
    assert "coverageKind" not in running
    assert completed["action"] == "covered"
    assert completed["claimState"] == "COVERED"
    assert completed["coverageKind"] == "fallback"
    assert attempts == ["attempt"]
    state = json.loads(state_path.read_text())
    entry = state["slots"][first["fallbackKey"]]
    assert entry["workflowRunId"] == 900
    assert entry["state"] == "COVERED"


def test_exact_dispatch_id_retries_failed_jobs_once_and_completes_same_run(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    attempts = []
    initial_responses = [[], []]
    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: initial_responses.pop(0),
        dispatch=lambda *_args: attempts.append("attempt") or _receipt(901),
        effect_guard=_guard,
    )
    active = _run(
        event="workflow_dispatch",
        run_id=901,
        status="in_progress",
        conclusion=None,
    )
    running = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [active],
        dispatch=lambda *_args: attempts.append("duplicate"),
        effect_guard=_guard,
    )
    reruns = []
    failed = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            active | {"status": "completed", "conclusion": "failure"}
        ],
        dispatch=lambda *_args: attempts.append("duplicate"),
        rerun_failed_jobs=lambda repo, run_id, _lock_fd: reruns.append((repo, run_id)),
        effect_guard=_guard,
    )
    retry_running = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            active | {"run_attempt": 2, "status": "in_progress", "conclusion": None}
        ],
        dispatch=lambda *_args: attempts.append("duplicate"),
        rerun_failed_jobs=lambda *_args: pytest.fail("recovery must not be requested twice"),
        effect_guard=_guard,
    )
    recovered = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            active | {"run_attempt": 2, "status": "completed", "conclusion": "success"}
        ],
        dispatch=lambda *_args: attempts.append("duplicate"),
        rerun_failed_jobs=lambda *_args: pytest.fail("recovery must not be requested twice"),
        effect_guard=_guard,
    )

    assert first["claimState"] == "BOUND"
    assert running["claimState"] == "RUNNING"
    assert failed["action"] == "fallback_retry_requested"
    assert failed["ok"] is True
    assert failed["claimState"] == "RETRY_REQUESTED"
    assert failed["run"]["runId"] == 901
    assert failed["rerunAttempts"] == 1
    assert reruns == [("Oxygen56/oss-pr-radar", 901)]
    assert retry_running["action"] == "tracking"
    assert retry_running["claimState"] == "RUNNING"
    assert retry_running["run"]["runAttempt"] == 2
    assert recovered["action"] == "covered"
    assert recovered["claimState"] == "COVERED"
    assert recovered["run"]["runId"] == 901
    assert recovered["run"]["runAttempt"] == 2
    assert recovered["rerunAttempts"] == 1
    assert attempts == ["attempt"]


def test_failed_recovery_attempt_is_terminal_and_never_creates_second_invocation(
    tmp_path, monkeypatch
):
    root = _root(tmp_path, monkeypatch)
    initial_responses = [[], []]
    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: initial_responses.pop(0),
        dispatch=lambda *_args: _receipt(905),
        effect_guard=_guard,
    )
    initial_state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    initial_entry = initial_state["slots"][first["fallbackKey"]]
    assert initial_entry["fullWorkflowRerunProtocol"] == "full-workflow-v1"
    assert initial_entry["fullWorkflowRerunAttempts"] == 0
    assert initial_entry["legacyFailedJobRerunAttempts"] == 0
    failed_attempt_one = _run(
        event="workflow_dispatch",
        run_id=905,
        status="completed",
        conclusion="failure",
        run_attempt=1,
    )
    reruns = []
    requested = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed_attempt_one],
        dispatch=lambda *_args: pytest.fail("must not create a second workflow run"),
        rerun_failed_jobs=lambda _repo, run_id, _lock_fd: reruns.append(run_id),
        effect_guard=_guard,
    )
    failed_attempt_two = failed_attempt_one | {"run_attempt": 2}
    terminal = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed_attempt_two],
        dispatch=lambda *_args: pytest.fail("must not create a second workflow run"),
        rerun_failed_jobs=lambda *_args: pytest.fail("bounded recovery must run only once"),
        effect_guard=_guard,
    )
    repeated = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed_attempt_two],
        dispatch=lambda *_args: pytest.fail("must not create a second workflow run"),
        rerun_failed_jobs=lambda *_args: pytest.fail("bounded recovery must run only once"),
        effect_guard=_guard,
    )

    assert first["run"]["runId"] == 905
    assert requested["action"] == "fallback_retry_requested"
    assert reruns == [905]
    assert terminal["action"] == "fallback_failed"
    assert terminal["claimState"] == "FAILED"
    assert terminal["run"]["runAttempt"] == 2
    assert terminal["rerunAttempts"] == 1
    assert repeated["action"] == "fallback_failed"
    assert repeated["rerunAttempts"] == 1

    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    entry = state["slots"][first["fallbackKey"]]
    assert entry["fullWorkflowRerunProtocol"] == "full-workflow-v1"
    assert entry["fullWorkflowRerunAttempts"] == 1
    assert entry["legacyFailedJobRerunAttempts"] == 0


def test_legacy_failed_jobs_attempt_gets_one_independent_full_workflow_rerun(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    state_path = root / "state" / "scheduler-watchdog.json"
    failed_attempt_two = _run(
        event="workflow_dispatch",
        run_id=33514112897,
        status="completed",
        conclusion="failure",
        run_attempt=2,
    )
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    key: {
                        "fallbackKey": key,
                        "slotAt": SLOT.isoformat().replace("+00:00", "Z"),
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "baselineRunIds": [],
                        "dispatchAttempts": 1,
                        "state": "FAILED",
                        "workflowRunId": 33514112897,
                        "runAttempt": 2,
                        # Deployed v1 used this one attempt on
                        # rerun-failed-jobs and had no full-workflow budget.
                        "rerunAttempts": 1,
                        "run": {
                            "runId": 33514112897,
                            "event": "workflow_dispatch",
                            "status": "completed",
                            "conclusion": "failure",
                            "runAttempt": 2,
                            "createdAt": failed_attempt_two["created_at"],
                            "url": failed_attempt_two["html_url"],
                        },
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)
    reruns = []

    requested = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed_attempt_two],
        dispatch=lambda *_args: pytest.fail("the exact run must be reused"),
        rerun_failed_jobs=lambda _repo, run_id, _lock_fd: reruns.append(run_id),
        effect_guard=_guard,
    )

    assert requested["action"] == "fallback_retry_requested"
    assert reruns == [33514112897]
    state = json.loads(state_path.read_text())
    entry = state["slots"][key]
    assert entry["state"] == "RETRY_REQUESTED"
    assert entry["rerunAttempts"] == 2
    assert entry["legacyFailedJobRerunAttempts"] == 1
    assert entry["fullWorkflowRerunAttempts"] == 1
    assert entry["fullWorkflowRerunProtocol"] == "full-workflow-v1"

    tracking = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed_attempt_two],
        dispatch=lambda *_args: pytest.fail("the exact run must be reused"),
        rerun_failed_jobs=lambda *_args: pytest.fail("full rerun must not repeat"),
        effect_guard=_guard,
    )
    assert tracking["action"] == "fallback_retry_tracking"

    failed_attempt_three = failed_attempt_two | {"run_attempt": 3}
    terminal = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed_attempt_three],
        dispatch=lambda *_args: pytest.fail("the exact run must be reused"),
        rerun_failed_jobs=lambda *_args: pytest.fail("full rerun budget is exhausted"),
        effect_guard=_guard,
    )
    assert terminal["action"] == "fallback_failed"
    assert terminal["run"]["runAttempt"] == 3
    assert terminal["rerunAttempts"] == 2


def test_externally_observed_same_run_attempt_consumes_full_workflow_budget(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    state_path = root / "state" / "scheduler-watchdog.json"
    failed_attempt_two = _run(
        event="workflow_dispatch",
        run_id=33514112897,
        status="completed",
        conclusion="failure",
        run_attempt=2,
    )
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    key: {
                        "fallbackKey": key,
                        "slotAt": SLOT.isoformat().replace("+00:00", "Z"),
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "baselineRunIds": [],
                        "dispatchAttempts": 1,
                        "state": "FAILED",
                        "workflowRunId": 33514112897,
                        "runAttempt": 2,
                        "rerunAttempts": 1,
                        "run": {
                            "runId": 33514112897,
                            "event": "workflow_dispatch",
                            "status": "completed",
                            "conclusion": "failure",
                            "runAttempt": 2,
                            "createdAt": failed_attempt_two["created_at"],
                            "url": failed_attempt_two["html_url"],
                        },
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)
    attempt_three = failed_attempt_two | {
        "run_attempt": 3,
        "status": "in_progress",
        "conclusion": None,
    }

    tracking = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [attempt_three],
        dispatch=lambda *_args: pytest.fail("the exact run must be reused"),
        rerun_failed_jobs=lambda *_args: pytest.fail("observed rerun must not be duplicated"),
        effect_guard=_guard,
    )

    assert tracking["action"] == "tracking"
    state = json.loads(state_path.read_text())
    entry = state["slots"][key]
    assert entry["rerunAttempts"] == 2
    assert entry["legacyFailedJobRerunAttempts"] == 1
    assert entry["fullWorkflowRerunAttempts"] == 1
    assert entry["fullWorkflowRerunBudgetSource"] == "external_same_run_attempt"

    terminal = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            attempt_three | {"status": "completed", "conclusion": "failure"}
        ],
        dispatch=lambda *_args: pytest.fail("the exact run must be reused"),
        rerun_failed_jobs=lambda *_args: pytest.fail("observed rerun consumed the budget"),
        effect_guard=_guard,
    )
    assert terminal["action"] == "fallback_failed"
    assert terminal["rerunAttempts"] == 2


def test_observed_same_run_rerun_consumes_budget_without_duplicate_request(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    key: {
                        "fallbackKey": key,
                        "slotAt": SLOT.isoformat().replace("+00:00", "Z"),
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "baselineRunIds": [],
                        "dispatchAttempts": 1,
                        "state": "FAILED",
                        "workflowRunId": 907,
                        "runAttempt": 1,
                        "run": {
                            "runId": 907,
                            "event": "workflow_dispatch",
                            "status": "completed",
                            "conclusion": "failure",
                            "runAttempt": 1,
                            "createdAt": "2026-08-31T03:20:00Z",
                        },
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)
    externally_running = _run(
        event="workflow_dispatch",
        run_id=907,
        status="in_progress",
        conclusion=None,
        run_attempt=2,
    )

    tracking = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [externally_running],
        dispatch=lambda *_args: pytest.fail("the slot already owns an exact run"),
        rerun_failed_jobs=lambda *_args: pytest.fail("the observed rerun must not be duplicated"),
        effect_guard=_guard,
    )

    assert tracking["action"] == "tracking"
    assert tracking["run"]["runAttempt"] == 2
    assert tracking["rerunAttempts"] == 1

    terminal = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            externally_running | {"status": "completed", "conclusion": "failure"}
        ],
        dispatch=lambda *_args: pytest.fail("the slot already owns an exact run"),
        rerun_failed_jobs=lambda *_args: pytest.fail("the recovery budget is consumed"),
        effect_guard=_guard,
    )

    assert terminal["action"] == "fallback_failed"
    assert terminal["run"]["runAttempt"] == 2
    assert terminal["rerunAttempts"] == 1


def test_old_failed_claim_is_superseded_by_later_success_without_stale_rerun(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    current = NOW + timedelta(hours=1)
    current_slot = SLOT + timedelta(hours=1)
    old_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    current_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", current_slot)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    old_key: {
                        "fallbackKey": old_key,
                        "slotAt": SLOT.isoformat().replace("+00:00", "Z"),
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "baselineRunIds": [],
                        "dispatchAttempts": 1,
                        "state": "BOUND",
                        "workflowRunId": 33514112897,
                        "runAttempt": 1,
                        "run": _run(
                            event="workflow_dispatch",
                            run_id=33514112897,
                            status="in_progress",
                            conclusion=None,
                        ),
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)
    failed_old = _run(
        event="workflow_dispatch",
        run_id=33514112897,
        status="completed",
        conclusion="failure",
    )
    dispatched = []

    current_requested = _watchdog(
        root,
        now=current,
        list_runs=lambda _repo, _workflow: [failed_old],
        dispatch=lambda *_args: dispatched.append(33543998578) or _receipt(33543998578),
        rerun_failed_jobs=lambda *_args: pytest.fail(
            "the uncovered current slot has priority over historical recovery"
        ),
        effect_guard=_guard,
    )

    assert current_requested["action"] == "fallback_requested"
    assert current_requested["fallbackKey"] == current_key
    assert dispatched == [33543998578]
    state = json.loads(state_path.read_text())
    assert state["slots"][old_key]["state"] == "FAILED"
    assert state["slots"][current_key]["state"] == "BOUND"

    recovered_old = _watchdog(
        root,
        now=current,
        list_runs=lambda _repo, _workflow: [
            failed_old,
            _run(
                event="workflow_dispatch",
                run_id=33543998578,
                created_at="2026-08-31T04:31:00Z",
            ),
        ],
        dispatch=lambda *_args: pytest.fail("the current slot is already bound"),
        rerun_failed_jobs=lambda *_args: pytest.fail(
            "a later successful full run supersedes the stale failed claim"
        ),
        effect_guard=_guard,
    )

    assert recovered_old["action"] == "covered"
    assert recovered_old["fallbackKey"] == current_key
    assert recovered_old["run"]["runId"] == 33543998578
    state = json.loads(state_path.read_text())
    assert state["slots"][current_key]["state"] == "COVERED"
    assert state["slots"][old_key]["state"] == "SUPERSEDED"
    assert state["slots"][old_key]["supersededReason"] == "LATER_SUCCESSFUL_FULL_RUN"
    assert state["slots"][old_key]["supersededByRun"]["runId"] == 33543998578
    assert state["slots"][old_key].get("fullWorkflowRerunAttempts", 0) == 0


def test_only_latest_full_run_can_receive_a_recovery_rerun(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    old_slot = SLOT - timedelta(hours=1)
    old_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", old_slot)
    latest_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    old_failed = _run(
        event="workflow_dispatch",
        run_id=900,
        created_at="2026-08-31T02:31:00Z",
        status="completed",
        conclusion="failure",
    )
    latest_failed = _run(
        event="workflow_dispatch",
        run_id=901,
        created_at="2026-08-31T03:31:00Z",
        status="completed",
        conclusion="failure",
    )
    state_path = root / "state" / "scheduler-watchdog.json"
    entries = {}
    for key, slot, run in (
        (old_key, old_slot, old_failed),
        (latest_key, SLOT, latest_failed),
    ):
        entries[key] = {
            "fallbackKey": key,
            "slotAt": slot.isoformat().replace("+00:00", "Z"),
            "claimedAt": run["created_at"],
            "baselineRunIds": [],
            "dispatchAttempts": 1,
            "state": "FAILED",
            "workflowRunId": run["id"],
            "runAttempt": 1,
            "run": {
                "runId": run["id"],
                "event": run["event"],
                "status": run["status"],
                "conclusion": run["conclusion"],
                "runAttempt": run["run_attempt"],
                "createdAt": run["created_at"],
                "url": run["html_url"],
            },
        }
    state_path.write_text(json.dumps({"schemaVersion": WATCHDOG_SCHEMA, "slots": entries}))
    state_path.chmod(0o600)
    reruns = []

    requested = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [old_failed, latest_failed],
        dispatch=lambda *_args: pytest.fail("the latest slot already has an exact run"),
        rerun_failed_jobs=lambda _repo, run_id, _lock_fd: reruns.append(run_id),
        effect_guard=_guard,
    )

    assert requested["action"] == "fallback_retry_requested"
    assert requested["fallbackKey"] == latest_key
    assert reruns == [901]
    state = json.loads(state_path.read_text())
    assert state["slots"][old_key]["state"] == "FAILED"
    assert state["slots"][old_key].get("fullWorkflowRerunAttempts", 0) == 0

    terminal = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            old_failed,
            latest_failed | {"run_attempt": 2},
        ],
        dispatch=lambda *_args: pytest.fail("the latest slot already has an exact run"),
        rerun_failed_jobs=lambda *_args: pytest.fail(
            "an older failure must not inherit the latest run's exhausted recovery budget"
        ),
        effect_guard=_guard,
    )

    assert terminal["action"] == "fallback_failed"
    assert terminal["fallbackKey"] == latest_key
    state = json.loads(state_path.read_text())
    assert state["slots"][old_key]["state"] == "FAILED"
    assert state["slots"][old_key].get("fullWorkflowRerunAttempts", 0) == 0


def test_crash_left_retry_claim_becomes_uncertain_without_blocking_new_slot(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    current = NOW + timedelta(hours=1)
    old_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    old_key: {
                        "fallbackKey": old_key,
                        "slotAt": SLOT.isoformat().replace("+00:00", "Z"),
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "baselineRunIds": [],
                        "dispatchAttempts": 1,
                        "state": "RETRY_CLAIMED",
                        "workflowRunId": 903,
                        "runAttempt": 1,
                        "rerunAttempts": 1,
                        "retryBaseRunAttempt": 1,
                        "run": {
                            "runId": 903,
                            "event": "workflow_dispatch",
                            "status": "completed",
                            "conclusion": "failure",
                            "runAttempt": 1,
                            "createdAt": "2026-08-31T03:20:00Z",
                        },
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)
    dispatched = []

    result = _watchdog(
        root,
        now=current,
        list_runs=lambda _repo, _workflow: [
            _run(
                event="workflow_dispatch",
                run_id=903,
                status="completed",
                conclusion="failure",
            )
        ],
        dispatch=lambda *_args: dispatched.append(904) or _receipt(904),
        rerun_failed_jobs=lambda *_args: pytest.fail("an ambiguous rerun must never repeat"),
        effect_guard=_guard,
    )

    assert result["action"] == "fallback_requested"
    assert dispatched == [904]
    state = json.loads(state_path.read_text())
    assert state["slots"][old_key]["state"] == "RETRY_UNCERTAIN"
    assert state["slots"][old_key]["rerunAttempts"] == 1
    assert (
        state["slots"][old_key]["lastRetryError"] == "PROCESS_INTERRUPTED_AFTER_DURABLE_RETRY_CLAIM"
    )


def test_only_claim_backed_exact_ids_are_exported_as_watchdog_coverage(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    "claimed": {
                        "state": "COVERED",
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "baselineRunIds": [],
                        "workflowRunId": 901,
                    },
                    "manual-projection": {
                        "state": "COVERED",
                        "workflowRunId": 902,
                        "attributionKind": "temporal_slot_observation",
                    },
                    "claim-without-exact-id": {
                        "state": "REQUESTED",
                        "claimedAt": "2026-08-31T03:32:00Z",
                        "baselineRunIds": [],
                    },
                },
            }
        )
    )
    state_path.chmod(0o600)

    assert proven_watchdog_run_ids(root) == frozenset({"901"})


def test_uncertain_failed_job_rerun_is_reconciled_without_repeating_request(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    initial_responses = [[], []]
    _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: initial_responses.pop(0),
        dispatch=lambda *_args: _receipt(906),
        effect_guard=_guard,
    )
    failed = _run(
        event="workflow_dispatch",
        run_id=906,
        status="completed",
        conclusion="failure",
        run_attempt=1,
    )
    calls = []

    def uncertain(_repo, run_id, _lock_fd):
        calls.append(run_id)
        raise RuntimeError("timeout after request")

    requested = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed],
        dispatch=lambda *_args: pytest.fail("must not create a second workflow run"),
        rerun_failed_jobs=uncertain,
        effect_guard=_guard,
    )
    unchanged = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed],
        dispatch=lambda *_args: pytest.fail("must not create a second workflow run"),
        rerun_failed_jobs=lambda *_args: pytest.fail("uncertain request must not repeat"),
        effect_guard=_guard,
    )
    recovered = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [failed | {"run_attempt": 2, "conclusion": "success"}],
        dispatch=lambda *_args: pytest.fail("must not create a second workflow run"),
        rerun_failed_jobs=lambda *_args: pytest.fail("uncertain request must not repeat"),
        effect_guard=_guard,
    )

    assert requested["action"] == "fallback_retry_uncertain"
    assert requested["claimState"] == "RETRY_UNCERTAIN"
    assert calls == [906]
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    entry = state["slots"][requested["fallbackKey"]]
    assert entry["fullWorkflowRerunAttempts"] == 1
    assert entry["fullWorkflowRerunBudgetSource"] == "watchdog_request"
    assert unchanged["action"] == "fallback_retry_tracking"
    assert unchanged["claimState"] == "RETRY_UNCERTAIN"
    assert recovered["action"] == "covered"
    assert recovered["run"]["runId"] == 906
    assert recovered["run"]["runAttempt"] == 2


def test_default_retry_reruns_entire_workflow_to_refresh_state_restore_baseline(monkeypatch):
    observed = {}

    def fake_run(arguments, **kwargs):
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

    monkeypatch.setattr("oss_pr_radar.scheduler_watchdog.subprocess.run", fake_run)

    _default_rerun_failed_jobs("Oxygen56/oss-pr-radar", 12345, None)

    assert observed["arguments"] == [
        "gh",
        "api",
        "--method",
        "POST",
        "repos/Oxygen56/oss-pr-radar/actions/runs/12345/rerun",
        "-H",
        "X-GitHub-Api-Version: 2026-03-10",
    ]
    assert observed["kwargs"]["pass_fds"] == ()


def test_active_temporal_run_is_not_covered_until_it_completes(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    active = _run(
        event="workflow_dispatch",
        run_id=902,
        status="in_progress",
        conclusion=None,
    )
    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [active],
        dispatch=lambda *_args: pytest.fail("active slot is already protected"),
        effect_guard=_guard,
    )
    second = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            active | {"status": "completed", "conclusion": "success"}
        ],
        dispatch=lambda *_args: pytest.fail("tracked run must not dispatch again"),
        effect_guard=_guard,
    )

    assert first["action"] == "tracking"
    assert first["claimState"] == "RUNNING"
    assert "coverageKind" not in first
    assert second["action"] == "covered"
    assert second["claimState"] == "COVERED"


def test_exact_run_requires_the_requested_head_branch(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    initial_responses = [[], []]
    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: initial_responses.pop(0),
        dispatch=lambda *_args: _receipt(903),
        effect_guard=_guard,
    )

    with pytest.raises(RuntimeError, match="exact run ref"):
        _watchdog(
            root,
            now=NOW,
            list_runs=lambda _repo, _workflow: [
                _run(event="workflow_dispatch", run_id=903, head_branch=None)
            ],
            dispatch=lambda *_args: pytest.fail("invalid exact run must not retry"),
            effect_guard=_guard,
        )

    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    assert state["slots"][first["fallbackKey"]]["state"] == "BOUND"


def test_one_exact_run_id_cannot_be_bound_to_two_slots(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    current_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    old_slot = datetime(2026, 8, 31, 2, 17, tzinfo=UTC)
    old_key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", old_slot)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    current_key: {
                        "fallbackKey": current_key,
                        "slotAt": "2026-08-31T03:17:00Z",
                        "state": "BOUND",
                        "workflowRunId": 904,
                    },
                    old_key: {
                        "fallbackKey": old_key,
                        "slotAt": "2026-08-31T02:17:00Z",
                        "state": "BOUND",
                        "workflowRunId": 904,
                    },
                },
            }
        )
    )
    state_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="multiple claims"):
        _watchdog(
            root,
            now=NOW,
            list_runs=lambda _repo, _workflow: [_run(event="workflow_dispatch", run_id=904)],
            dispatch=lambda *_args: pytest.fail("duplicate binding must fail closed"),
            effect_guard=_guard,
        )


def test_cross_hour_claims_reconcile_before_temporal_slots_and_runs_are_not_reused(
    tmp_path, monkeypatch
):
    root = _root(tmp_path, monkeypatch)
    old_slot_a = datetime(2026, 8, 31, 4, 17, tzinfo=UTC)
    wrong_slot_a = datetime(2026, 8, 31, 5, 17, tzinfo=UTC)
    old_slot_b = datetime(2026, 9, 1, 0, 17, tzinfo=UTC)
    wrong_slot_b = datetime(2026, 9, 1, 1, 17, tzinfo=UTC)
    old_key_a = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", old_slot_a)
    wrong_key_a = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", wrong_slot_a)
    old_key_b = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", old_slot_b)
    wrong_key_b = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", wrong_slot_b)
    run_a = _run(
        event="workflow_dispatch",
        run_id=33360380108,
        created_at="2026-08-31T05:23:37Z",
    )
    run_b = _run(
        event="workflow_dispatch",
        run_id=33458844757,
        created_at="2026-09-01T01:27:57Z",
    )
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    old_key_a: {
                        "fallbackKey": old_key_a,
                        "slotAt": "2026-08-31T04:17:00Z",
                        "firstObservedAt": "2026-08-31T05:23:29.889424Z",
                        "claimedAt": "2026-08-31T05:23:29.889424Z",
                        "dispatchFinishedAt": "2026-08-31T05:23:37.463249Z",
                        "dispatchAttempts": 1,
                        "baselineRunIds": ["33351051712"],
                        "state": "REQUESTED",
                    },
                    wrong_key_a: {
                        "fallbackKey": wrong_key_a,
                        "slotAt": "2026-08-31T05:17:00Z",
                        "firstObservedAt": "2026-08-31T05:33:40.324246Z",
                        "state": "COVERED",
                        "coverageKind": "fallback",
                        "run": {
                            "runId": 33360380108,
                            "event": "workflow_dispatch",
                            "status": "completed",
                            "conclusion": "success",
                            "createdAt": "2026-08-31T05:23:37Z",
                        },
                    },
                    old_key_b: {
                        "fallbackKey": old_key_b,
                        "slotAt": "2026-09-01T00:17:00Z",
                        "firstObservedAt": "2026-09-01T01:27:48.032006Z",
                        "claimedAt": "2026-09-01T01:27:48.032006Z",
                        "dispatchFinishedAt": "2026-09-01T01:27:57.507629Z",
                        "dispatchAttempts": 1,
                        "baselineRunIds": ["33360380108", "33452336547"],
                        "state": "REQUESTED",
                    },
                    wrong_key_b: {
                        "fallbackKey": wrong_key_b,
                        "slotAt": "2026-09-01T01:17:00Z",
                        "firstObservedAt": "2026-09-01T01:32:57.670070Z",
                        "state": "COVERED",
                        "coverageKind": "fallback",
                        "run": {
                            "runId": 33458844757,
                            "event": "workflow_dispatch",
                            "status": "completed",
                            "conclusion": "success",
                            "createdAt": "2026-09-01T01:27:57Z",
                        },
                    },
                },
            }
        )
    )
    state_path.chmod(0o600)
    dispatched = []

    reconciled = _watchdog(
        root,
        now=datetime(2026, 9, 1, 1, 38, tzinfo=UTC),
        list_runs=lambda _repo, _workflow: [run_b, run_a],
        dispatch=lambda *_args: dispatched.append("unexpected"),
        effect_guard=_guard,
    )

    assert reconciled["action"] == "covered"
    assert len(reconciled["reconciledClaims"]) == 2
    assert dispatched == []
    state = json.loads(state_path.read_text())
    assert wrong_key_a not in state["slots"]
    assert wrong_key_b not in state["slots"]
    assert state["slots"][old_key_a]["state"] == "COVERED"
    assert state["slots"][old_key_a]["run"]["runId"] == 33360380108
    assert state["slots"][old_key_b]["state"] == "COVERED"
    assert state["slots"][old_key_b]["run"]["runId"] == 33458844757
    assigned = [
        entry.get("run", {}).get("runId")
        for entry in state["slots"].values()
        if isinstance(entry, dict)
    ]
    assert assigned.count(33360380108) == 1
    assert assigned.count(33458844757) == 1

    next_cycle = _watchdog(
        root,
        now=datetime(2026, 9, 1, 1, 38, tzinfo=UTC),
        list_runs=lambda _repo, _workflow: [run_b, run_a],
        dispatch=lambda *_args: dispatched.append("next-slot"),
        effect_guard=_guard,
    )

    assert next_cycle["action"] == "fallback_requested"
    assert next_cycle["fallbackKey"] == wrong_key_b
    assert dispatched == ["next-slot"]
    state = json.loads(state_path.read_text())
    assert state["slots"][wrong_key_b]["state"] == "REQUESTED"
    assert "run" not in state["slots"][wrong_key_b]


def test_pending_claim_ignores_baseline_and_out_of_request_window_runs(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    key: {
                        "fallbackKey": key,
                        "slotAt": "2026-08-31T03:17:00Z",
                        "firstObservedAt": "2026-08-31T03:31:00Z",
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "dispatchFinishedAt": "2026-08-31T03:31:05Z",
                        "dispatchAttempts": 1,
                        "baselineRunIds": ["80"],
                        "state": "REQUESTED",
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)

    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            _run(event="workflow_dispatch", run_id=80, created_at="2026-08-31T03:31:02Z"),
            _run(event="workflow_dispatch", run_id=81, created_at="2026-08-31T03:40:00Z"),
        ],
        dispatch=lambda *_args: pytest.fail("pending claim must remain read-only"),
        effect_guard=_guard,
    )

    assert result["action"] == "reconciling"
    state = json.loads(state_path.read_text())
    assert state["slots"][key]["state"] == "REQUESTED"
    assert "run" not in state["slots"][key]


@pytest.mark.parametrize("head_branch", [None, "", "feature"])
def test_legacy_claim_does_not_migrate_missing_or_wrong_branch(tmp_path, monkeypatch, head_branch):
    root = _root(tmp_path, monkeypatch)
    key = fallback_key("Oxygen56/oss-pr-radar", "radar.yml", SLOT)
    state_path = root / "state" / "scheduler-watchdog.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": WATCHDOG_SCHEMA,
                "slots": {
                    key: {
                        "fallbackKey": key,
                        "slotAt": "2026-08-31T03:17:00Z",
                        "firstObservedAt": "2026-08-31T03:31:00Z",
                        "claimedAt": "2026-08-31T03:31:00Z",
                        "dispatchFinishedAt": "2026-08-31T03:31:05Z",
                        "dispatchAttempts": 1,
                        "baselineRunIds": [],
                        "state": "REQUESTED",
                    }
                },
            }
        )
    )
    state_path.chmod(0o600)

    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [
            _run(
                event="workflow_dispatch",
                run_id=82,
                created_at="2026-08-31T03:31:09Z",
                head_branch=head_branch,
            )
        ],
        dispatch=lambda *_args: pytest.fail("untrusted branch must remain read-only"),
        effect_guard=_guard,
    )

    assert result["action"] == "reconciling"
    state = json.loads(state_path.read_text())
    assert state["slots"][key]["state"] == "REQUESTED"
    assert "workflowRunId" not in state["slots"][key]
    assert "run" not in state["slots"][key]


def test_late_natural_run_cannot_replace_fallback_evidence_or_trigger_again(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    attempts = []
    responses = [
        [],
        [],
        [
            _run(
                event="schedule",
                run_id=10,
                created_at="2026-08-31T03:49:00Z",
                jobs=_jobs(),
            )
        ],
    ]

    first = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: responses.pop(0),
        dispatch=lambda *_args: attempts.append("fallback"),
        effect_guard=_guard,
    )
    second = _watchdog(
        root,
        now=datetime(2026, 8, 31, 3, 50, tzinfo=UTC),
        list_runs=lambda _repo, _workflow: responses.pop(0),
        dispatch=lambda *_args: attempts.append("duplicate"),
        effect_guard=_guard,
    )

    assert first["action"] == "fallback_requested"
    assert second["action"] == "reconciling"
    assert second["fallbackKey"] == first["fallbackKey"]
    assert second["githubNaturalScheduleHealthy"] is True
    assert attempts == ["fallback"]
    state = json.loads((root / "state" / "scheduler-watchdog.json").read_text())
    slot = state["slots"][first["fallbackKey"]]
    assert slot["state"] == "REQUESTED"
    assert "coverageKind" not in slot
    assert state["naturalScheduleCanary"]["latestRun"]["runId"] == 10


def test_recheck_under_shared_effect_lock_closes_controller_race(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    responses = [[], [_run(event="workflow_dispatch", run_id=11)]]
    dispatched = []
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: responses.pop(0),
        dispatch=lambda *_args: dispatched.append(True),
        effect_guard=_guard,
    )

    assert result["action"] == "covered_after_lock"
    assert result["coverageKind"] == "fallback"
    assert dispatched == []


def test_default_dispatch_requests_and_validates_exact_run_details(monkeypatch):
    observed = {}
    response = {
        "workflow_run_id": 905,
        "run_url": ("https://api.github.com/repos/Oxygen56/oss-pr-radar/actions/runs/905"),
        "html_url": "https://github.com/Oxygen56/oss-pr-radar/actions/runs/905",
    }

    def run(arguments, **kwargs):
        observed["arguments"] = arguments
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            arguments,
            0,
            stdout=json.dumps(response),
            stderr="",
        )

    monkeypatch.setattr("oss_pr_radar.scheduler_watchdog.subprocess.run", run)
    receipt = _default_dispatch(
        "Oxygen56/oss-pr-radar",
        "radar.yml",
        "main",
        2.0,
        91,
    )

    assert receipt == _receipt(905)
    assert observed["arguments"] == [
        "gh",
        "api",
        "--method",
        "POST",
        "repos/Oxygen56/oss-pr-radar/actions/workflows/radar.yml/dispatches",
        "-H",
        "X-GitHub-Api-Version: 2026-03-10",
        "--input",
        "-",
    ]
    assert json.loads(observed["kwargs"]["input"]) == {
        "ref": "main",
        "inputs": {"window_hours": "2"},
        "return_run_details": True,
    }
    assert observed["kwargs"]["pass_fds"] == (91,)


def test_default_dispatch_supports_legacy_204_response(monkeypatch):
    monkeypatch.setattr(
        "oss_pr_radar.scheduler_watchdog.subprocess.run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(
            arguments,
            0,
            stdout="",
            stderr="",
        ),
    )

    assert (
        _default_dispatch(
            "Oxygen56/oss-pr-radar",
            "radar.yml",
            "main",
            2.0,
            None,
        )
        is None
    )


def test_default_dispatch_timeout_is_uncertain(monkeypatch):
    def timeout(arguments, **_kwargs):
        raise subprocess.TimeoutExpired(arguments, 30)

    monkeypatch.setattr("oss_pr_radar.scheduler_watchdog.subprocess.run", timeout)
    with pytest.raises(RuntimeError, match="outcome uncertain.*TimeoutExpired"):
        _default_dispatch(
            "Oxygen56/oss-pr-radar",
            "radar.yml",
            "main",
            2.0,
            None,
        )


def test_default_dispatch_rejects_mismatched_run_urls(monkeypatch):
    response = {
        "workflow_run_id": 906,
        "run_url": ("https://api.github.com/repos/other/repo/actions/runs/906"),
        "html_url": "https://github.com/Oxygen56/oss-pr-radar/actions/runs/906",
    }
    monkeypatch.setattr(
        "oss_pr_radar.scheduler_watchdog.subprocess.run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(
            arguments,
            0,
            stdout=json.dumps(response),
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="outcome uncertain.*URL is invalid"):
        _default_dispatch(
            "Oxygen56/oss-pr-radar",
            "radar.yml",
            "main",
            2.0,
            None,
        )


def test_unsafe_durable_state_fails_closed(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    path = root / "state" / "scheduler-watchdog.json"
    path.write_text('{"schemaVersion":"wrong","slots":{}}')
    path.chmod(0o600)
    with pytest.raises(RuntimeError, match="schema"):
        _watchdog(
            root,
            now=NOW,
            list_runs=lambda _repo, _workflow: [],
            dispatch=lambda *_args: None,
            effect_guard=_guard,
        )
