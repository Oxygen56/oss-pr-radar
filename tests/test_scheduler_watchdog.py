from __future__ import annotations

import json
import stat
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

import pytest

from oss_pr_radar.scheduler_watchdog import (
    WATCHDOG_SCHEMA,
    eligible_slot,
    fallback_key,
    watchdog_cycle,
)

NOW = datetime(2026, 8, 31, 3, 31, tzinfo=UTC)
SLOT = datetime(2026, 8, 31, 3, 17, tzinfo=UTC)


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
) -> dict:
    return {
        "id": run_id,
        "event": event,
        "created_at": created_at,
        "updated_at": created_at,
        "status": status,
        "conclusion": conclusion,
        "html_url": f"https://github.com/Oxygen56/oss-pr-radar/actions/runs/{run_id}",
    }


def test_eligible_slot_waits_thirteen_minutes_and_recovers_latest_slot_after_sleep():
    assert eligible_slot(datetime(2026, 8, 31, 3, 29, tzinfo=UTC)) == datetime(
        2026, 8, 31, 2, 17, tzinfo=UTC
    )
    assert eligible_slot(NOW) == SLOT
    assert eligible_slot(datetime(2026, 9, 1, 8, 47, tzinfo=UTC)) == datetime(
        2026, 9, 1, 8, 17, tzinfo=UTC
    )


def test_natural_run_covers_slot_without_dispatch_and_remains_natural_health(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
    dispatched = []
    result = _watchdog(
        root,
        now=NOW,
        list_runs=lambda _repo, _workflow: [_run(event="schedule", run_id=7)],
        dispatch=lambda *args: dispatched.append(args),
        effect_guard=_guard,
    )

    assert result["action"] == "covered"
    assert result["coverageKind"] == "natural"
    assert result["githubNaturalScheduleHealthy"] is True
    assert dispatched == []


def test_active_run_covers_slot_but_does_not_claim_natural_success(tmp_path, monkeypatch):
    root = _root(tmp_path, monkeypatch)
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
        dispatch=lambda *_args: pytest.fail("active run must prevent fallback"),
        effect_guard=_guard,
    )

    assert result["action"] == "covered"
    assert result["coverageKind"] == "natural"
    assert result["githubNaturalScheduleHealthy"] is False


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
