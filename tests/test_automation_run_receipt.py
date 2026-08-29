from __future__ import annotations

import importlib.util
import json
import stat
from pathlib import Path

from oss_pr_radar.automation_run_receipt import (
    audit_automation_runs,
    complete_automation_run,
    load_automation_run_receipts,
    start_automation_run,
    write_automation_audit_report,
)
from oss_pr_radar.util import sha256_json


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_receipt_log_is_append_only_and_reconciles_loaded_start(tmp_path: Path):
    started = start_automation_run(
        tmp_path,
        automation_id="test-automation",
        role="test-role",
        argv=["python", "cycle.py"],
        environment={
            "RADAR_AUTOMATION_ID": "test-automation",
            "RADAR_AUTOMATION_ROLE": "test-role",
            "RADAR_INVOCATION_ID": "invocation-1",
            "RADAR_TRIGGER_ID": "trigger-1",
            "RADAR_SCHEDULED_AT": "2026-08-29T09:00:00Z",
            "FEISHU_APP_SECRET": "must-not-be-recorded",
        },
        run_id="run-1",
        started_at="2026-08-29T09:00:01Z",
    )
    assert started["recordType"] == "STARTED"
    path = tmp_path / "state" / "automation-runs.ndjson"
    before = path.read_text(encoding="utf-8")
    assert "must-not-be-recorded" not in before

    records, source_issues = load_automation_run_receipts(tmp_path)
    assert source_issues == []
    assert records[0]["_line"] == 1
    completed = complete_automation_run(
        tmp_path,
        records[0],
        exit_code=0,
        final_json_text=json.dumps({"ok": True}, separators=(",", ":")) + "\n",
        external_effects={"summaryAvailable": True, "github": {"publishedCount": 0}},
        completed_at="2026-08-29T09:00:02Z",
    )
    assert completed["recordType"] == "COMPLETED"
    assert path.read_text(encoding="utf-8").startswith(before)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2

    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(
        records, source_issues=source_issues, automation_id="test-automation"
    )
    assert audit["ok"] is True
    assert audit["counts"]["closed"] == 1
    assert audit["schedulerEvidence"] == "present"


def test_audit_reports_missing_completion_and_exit_json_mismatch(tmp_path: Path):
    started = start_automation_run(
        tmp_path,
        automation_id="test-automation",
        role="test-role",
        argv=["cycle"],
        run_id="run-open",
        started_at="2026-08-29T09:00:00Z",
    )
    complete_automation_run(
        tmp_path,
        started,
        exit_code=0,
        final_json={"ok": False},
        external_effects={"summaryAvailable": True},
        completed_at="2026-08-29T09:00:01Z",
    )
    records, source_issues = load_automation_run_receipts(tmp_path)
    # Simulate a process crash after STARTED and an invalid successful result.
    records.append({**started, "runId": "run-crashed", "recordDigest": "bad"})
    audit = audit_automation_runs(
        records, source_issues=source_issues, automation_id="test-automation"
    )
    codes = {item["code"] for item in audit["issues"]}
    assert audit["ok"] is False
    assert "EXIT_FINAL_JSON_MISMATCH" in codes
    assert "MISSING_COMPLETED" in codes


def test_audit_does_not_accept_nonzero_run_without_final_json(tmp_path: Path):
    started = start_automation_run(
        tmp_path,
        automation_id="test-automation",
        role="test-role",
        argv=["cycle"],
        run_id="run-no-final",
        started_at="2026-08-29T09:00:00Z",
    )
    complete_automation_run(
        tmp_path,
        started,
        exit_code=1,
        external_effects={"summaryAvailable": True},
        completed_at="2026-08-29T09:00:01Z",
    )
    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(records, source_issues=source_issues)
    assert audit["ok"] is False
    assert any(item["code"] == "MISSING_FINAL_JSON" for item in audit["issues"])


def test_scheduler_gap_ignores_manual_run_and_normalizes_offsets(tmp_path: Path):
    entries = (
        ("natural-a", "2026-08-29T09:00:00Z", "2026-08-29T09:00:01Z"),
        ("manual", None, "2026-08-29T10:05:00Z"),
        ("natural-b", "2026-08-29T19:00:00+08:00", "2026-08-29T11:00:01Z"),
    )
    for run_id, scheduled_at, started_at in entries:
        environment = (
            {
                "RADAR_TRIGGER_ID": f"trigger-{run_id}",
                "RADAR_SCHEDULED_AT": scheduled_at,
                "RADAR_INVOCATION_ID": run_id,
            }
            if scheduled_at
            else {}
        )
        started = start_automation_run(
            tmp_path,
            automation_id="test-automation",
            role="test-role",
            argv=["cycle"],
            environment=environment,
            run_id=run_id,
            started_at=started_at,
        )
        complete_automation_run(
            tmp_path,
            started,
            exit_code=0,
            final_json={"ok": True},
            external_effects={"summaryAvailable": True},
            completed_at=started_at,
        )
    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(
        records,
        source_issues=source_issues,
        automation_id="test-automation",
        window_start="2026-08-29T09:00:00Z",
        window_end="2026-08-29T11:00:00Z",
        expected_interval_minutes=60,
        grace_minutes=5,
    )
    assert any(item["code"] == "MISSED_RUN_WINDOW" for item in audit["issues"])
    assert audit["schedulerEvidence"] == "partial"
    assert "manual" in audit["schedulerEvidenceMissingRunIds"]


def test_untrusted_scheduled_at_cannot_hide_missed_window(tmp_path: Path):
    """A manual timestamp must not fill a natural scheduler slot."""

    entries = (
        (
            "natural-a",
            {"RADAR_TRIGGER_ID": "trigger-a", "RADAR_SCHEDULED_AT": "2026-08-29T09:00:00Z"},
            "2026-08-29T09:00:01Z",
        ),
        # A caller can set only the timestamp.  It remains diagnostic and is
        # deliberately excluded from schedule reconciliation.
        ("manual", {"RADAR_SCHEDULED_AT": "2026-08-29T10:00:00Z"}, "2026-08-29T10:00:01Z"),
        (
            "natural-b",
            {"RADAR_TRIGGER_ID": "trigger-b", "RADAR_SCHEDULED_AT": "2026-08-29T11:00:00Z"},
            "2026-08-29T11:00:01Z",
        ),
    )
    for run_id, environment, started_at in entries:
        started = start_automation_run(
            tmp_path,
            automation_id="test-automation",
            role="test-role",
            argv=["cycle"],
            environment={**environment, "RADAR_INVOCATION_ID": run_id},
            run_id=run_id,
            started_at=started_at,
        )
        complete_automation_run(
            tmp_path,
            started,
            exit_code=0,
            final_json={"ok": True},
            external_effects={"summaryAvailable": True},
            completed_at=started_at,
        )

    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(
        records,
        source_issues=source_issues,
        automation_id="test-automation",
        window_start="2026-08-29T09:00:00Z",
        window_end="2026-08-29T11:00:00Z",
        expected_interval_minutes=60,
        grace_minutes=5,
    )
    missed = [item for item in audit["issues"] if item["code"] == "MISSED_RUN_WINDOW"]
    assert [item["scheduledAt"] for item in missed] == ["2026-08-29T10:00:00Z"]
    assert "manual" in audit["schedulerEvidenceMissingRunIds"]


def test_untrusted_scheduled_at_is_not_counted_as_duplicate(tmp_path: Path):
    """Duplicate checks must ignore timestamps without a scheduler envelope."""

    for run_id in ("manual-a", "manual-b"):
        started = start_automation_run(
            tmp_path,
            automation_id="test-automation",
            role="test-role",
            argv=["cycle"],
            environment={
                "RADAR_INVOCATION_ID": run_id,
                "RADAR_SCHEDULED_AT": "2026-08-29T10:00:00Z",
            },
            run_id=run_id,
            started_at="2026-08-29T10:00:01Z",
        )
        complete_automation_run(
            tmp_path,
            started,
            exit_code=0,
            final_json={"ok": True},
            external_effects={"summaryAvailable": True},
            completed_at="2026-08-29T10:00:02Z",
        )

    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(records, source_issues=source_issues)
    assert not any(item["code"] == "DUPLICATE_SCHEDULED_WINDOW" for item in audit["issues"])
    assert set(audit["schedulerEvidenceMissingRunIds"]) == {"manual-a", "manual-b"}


def test_mismatched_scheduler_identity_cannot_fill_a_schedule_slot(tmp_path: Path):
    """An envelope that relabels the command is not natural-schedule evidence."""

    entries = (
        (
            "natural-a",
            {"RADAR_TRIGGER_ID": "trigger-a", "RADAR_SCHEDULED_AT": "2026-08-29T09:00:00Z"},
        ),
        (
            "forged",
            {
                "RADAR_AUTOMATION_ID": "other-automation",
                "RADAR_TRIGGER_ID": "trigger-forged",
                "RADAR_SCHEDULED_AT": "2026-08-29T10:00:00Z",
            },
        ),
        (
            "natural-b",
            {"RADAR_TRIGGER_ID": "trigger-b", "RADAR_SCHEDULED_AT": "2026-08-29T11:00:00Z"},
        ),
    )
    for index, (run_id, environment) in enumerate(entries):
        started = start_automation_run(
            tmp_path,
            automation_id="test-automation",
            role="test-role",
            argv=["cycle"],
            environment={**environment, "RADAR_INVOCATION_ID": run_id},
            run_id=run_id,
            started_at=f"2026-08-29T{9 + index:02d}:00:01Z",
        )
        complete_automation_run(
            tmp_path,
            started,
            exit_code=0,
            final_json={"ok": True},
            external_effects={"summaryAvailable": True},
            completed_at=started["startedAt"],
        )

    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(
        records,
        source_issues=source_issues,
        automation_id="test-automation",
        window_start="2026-08-29T09:00:00Z",
        window_end="2026-08-29T11:00:00Z",
        expected_interval_minutes=60,
        grace_minutes=5,
    )
    missed = [item for item in audit["issues"] if item["code"] == "MISSED_RUN_WINDOW"]
    assert [item["scheduledAt"] for item in missed] == ["2026-08-29T10:00:00Z"]
    assert "forged" in audit["schedulerEvidenceMissingRunIds"]
    assert any(item["code"] == "TRIGGER_IDENTITY_MISMATCH" for item in audit["issues"])


def test_scheduler_environment_cannot_relabel_identity_or_runtime(tmp_path: Path):
    started = start_automation_run(
        tmp_path,
        automation_id="test-automation",
        role="test-role",
        argv=["cycle"],
        environment={
            "RADAR_AUTOMATION_ID": "forged",
            "RADAR_AUTOMATION_ROLE": "forged-role",
            "RADAR_TRIGGER_ID": "trigger-1",
            "RADAR_SCHEDULED_AT": "2026-08-29T09:00:00Z",
        },
        run_id="run-forged",
        started_at="2026-08-29T09:00:00Z",
    )
    assert started["automationId"] == "test-automation"
    assert started["role"] == "test-role"
    complete_automation_run(
        tmp_path,
        started,
        exit_code=0,
        final_json={"ok": True},
        external_effects={"summaryAvailable": True},
        completed_at="2026-08-29T09:00:01Z",
    )
    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(
        records,
        source_issues=source_issues,
        automation_id="test-automation",
        expected_runtime_root_digest=sha256_json(str(tmp_path.absolute())),
    )
    assert audit["ok"] is False
    assert any(item["code"] == "TRIGGER_IDENTITY_MISMATCH" for item in audit["issues"])
    assert not any(item["code"] == "RUNTIME_ROOT_MISMATCH" for item in audit["issues"])


def test_derived_audit_report_is_private_and_regenerable(tmp_path: Path):
    started = start_automation_run(
        tmp_path,
        automation_id="test-automation",
        role="test-role",
        argv=["cycle"],
        run_id="run-report",
        started_at="2026-08-29T09:00:00Z",
    )
    complete_automation_run(
        tmp_path,
        started,
        exit_code=0,
        final_json={"ok": True},
        external_effects={"summaryAvailable": True},
        completed_at="2026-08-29T09:00:01Z",
    )
    path, audit = write_automation_audit_report(
        tmp_path,
        automation_id="test-automation",
    )
    assert path == tmp_path / "state" / "automation-audit-test-automation.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text(encoding="utf-8"))["runStatus"] == "healthy"
    assert audit["receiptIntegrityOk"] is True


def test_audit_detects_duplicate_schedule_and_missed_window(tmp_path: Path):
    for run_id, invocation_id, scheduled_at in (
        ("run-a", "inv-a", "2026-08-29T09:00:00Z"),
        ("run-b", "inv-b", "2026-08-29T09:00:00Z"),
        ("run-c", "inv-c", "2026-08-29T11:00:00Z"),
    ):
        started = start_automation_run(
            tmp_path,
            automation_id="test-automation",
            role="test-role",
            argv=["cycle"],
            environment={
                "RADAR_TRIGGER_ID": f"trigger-{run_id}",
                "RADAR_SCHEDULED_AT": scheduled_at,
                "RADAR_INVOCATION_ID": invocation_id,
            },
            run_id=run_id,
            started_at=scheduled_at,
        )
        complete_automation_run(
            tmp_path,
            started,
            exit_code=1,
            final_json={"ok": False},
            external_effects={"summaryAvailable": True},
            completed_at=scheduled_at,
        )
    records, source_issues = load_automation_run_receipts(tmp_path)
    audit = audit_automation_runs(
        records,
        source_issues=source_issues,
        automation_id="test-automation",
        window_start="2026-08-29T09:00:00Z",
        window_end="2026-08-29T11:00:00Z",
        expected_interval_minutes=60,
        grace_minutes=5,
    )
    codes = {item["code"] for item in audit["issues"]}
    assert "DUPLICATE_SCHEDULED_WINDOW" in codes
    assert "MISSED_RUN_WINDOW" in codes


def test_controller_and_daily_entrypoints_write_blocked_receipts(
    tmp_path: Path, monkeypatch, capsys
):
    root = Path(__file__).parents[1]
    controller = _load_script("controller_cycle_receipt_test", root / "scripts/controller_cycle.py")
    daily = _load_script(
        "daily_war_room_cycle_receipt_test", root / "scripts/daily_war_room_cycle.py"
    )

    class Binding:
        release_id = "test-release"
        code_root = root
        release = {"manifestSha256": "digest"}

    monkeypatch.setattr(controller, "bind_runtime", lambda *_args, **_kwargs: Binding())
    monkeypatch.setattr(
        controller,
        "run_locked_controller_cycle",
        lambda *_args, **_kwargs: {"ok": True, "checkedAt": "2026-08-29T09:00:00Z", "stages": {}},
    )
    assert controller.main(["--root", str(tmp_path), "--code-root", str(root)]) == 0
    controller_output = json.loads(capsys.readouterr().out)
    assert controller_output["automationRunId"]
    records, issues = load_automation_run_receipts(tmp_path)
    assert len(records) == 2
    assert audit_automation_runs(records, source_issues=issues)["ok"] is True

    daily_root = tmp_path / "daily"
    daily_root.mkdir()
    monkeypatch.setattr(daily, "bind_runtime", lambda *_args, **_kwargs: Binding())
    monkeypatch.setattr(
        daily,
        "require_operational_authorization",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("missing auth")),
    )
    assert daily.main(["--runtime-root", str(daily_root)]) == 1
    daily_output = json.loads(capsys.readouterr().out)
    assert daily_output["ok"] is False
    assert daily_output["automationRunId"]
    records, issues = load_automation_run_receipts(daily_root)
    assert len(records) == 2
    daily_audit = audit_automation_runs(records, source_issues=issues)
    assert daily_audit["ok"] is False
    assert daily_audit["receiptIntegrityOk"] is True
    assert daily_audit["executionOk"] is False
    assert daily_audit["failedRuns"][0]["blockedReason"] == "operational authorization required"


def test_entrypoint_exception_is_closed_and_marks_effects_uncertain(
    tmp_path: Path, monkeypatch, capsys
):
    root = Path(__file__).parents[1]
    controller = _load_script(
        "controller_cycle_receipt_exception_test", root / "scripts/controller_cycle.py"
    )
    monkeypatch.setattr(
        controller,
        "run_locked_controller_cycle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert controller.main(["--root", str(tmp_path), "--code-root", str(root)]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is False
    records, issues = load_automation_run_receipts(tmp_path)
    completion = records[-1]
    assert completion["finalJsonPresent"] is True
    assert completion["finalJsonOk"] is False
    assert completion["externalEffects"]["summaryAvailable"] is False
    audit = audit_automation_runs(records, source_issues=issues)
    assert audit["ok"] is False
    assert any(item["code"] == "EXTERNAL_EFFECTS_UNCERTAIN" for item in audit["issues"])
