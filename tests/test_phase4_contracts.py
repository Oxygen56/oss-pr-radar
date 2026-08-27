from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import ManagedLedger

ROOT = Path(__file__).parents[1]


def test_scheduled_workflow_uses_only_the_versioned_war_room_actionable_path():
    workflow = (ROOT / ".github/workflows/radar.yml").read_text(encoding="utf-8")
    assert "export_war_room_projection.py" in workflow
    assert "send_war_room_outbox.py" in workflow
    assert "merge_war_room_receipt.py" in workflow
    assert "--artifact reports/war_room_projection.json" in workflow
    projection_step = workflow.split("- name: Export managed lifecycle and War Room projection", 1)[
        1
    ].split("\n      - name:", 1)[0]
    continuation = chr(92)
    assert "export_war_room_projection.py " + continuation in projection_step
    assert "--ledger-copy state/radar_ledger.sqlite3 " + continuation in projection_step
    assert "--feishu-outbox state/war_room_feishu_outbox.json" in workflow
    assert "export_managed_projection.py" not in workflow
    assert "--kind review" not in workflow
    assert "--artifact reports/war_room_projection.json" in workflow
    assert "build_notification_outbox.py" not in workflow
    assert "send_notification_outbox.py" not in workflow
    build_state = workflow.split("\n  build-state:\n", 1)[1].split("\n  persist-pending:\n", 1)[0]
    import_position = build_state.index("PYTHONPATH=src python scripts/import_managed_snapshot.py")
    dispatch_position = build_state.index("python scripts/build_dispatch_intents.py")
    export_position = build_state.index(
        "PYTHONPATH=src python scripts/export_managed_snapshot.py", dispatch_position
    )
    assert import_position < dispatch_position < export_position


def test_health_workflow_is_read_only_and_cannot_repair_or_notify():
    workflow = (ROOT / ".github/workflows/health.yml").read_text(encoding="utf-8")
    assert "Check natural schedule freshness (read-only)" in workflow
    assert "--max-effective-age-minutes 110" in workflow
    assert "--max-effective-age-minutes 65" not in workflow
    assert "--repair" not in workflow
    assert "--notify" not in workflow
    assert "FEISHU_APP_ID" not in workflow
    assert "FEISHU_APP_SECRET" not in workflow
    assert "actions: read" in workflow


def test_radar_scan_exports_authenticated_state_with_the_managed_key():
    workflow = (ROOT / ".github/workflows/radar.yml").read_text(encoding="utf-8")
    scan = workflow.split("\n  scan:\n", 1)[1].split("\n  build-state:\n", 1)[0]
    assert "RADAR_DISPATCH_HMAC_KEY: ${{ secrets.RADAR_DISPATCH_HMAC_KEY }}" in scan
    assert "scripts/export_managed_snapshot.py" in scan
    for job, next_job in (
        ("watch", "pr-followup"),
        ("pr-followup", "scan"),
        ("persist-pending", "notify"),
        ("persist-receipt", None),
    ):
        start = workflow.index(f"\n  {job}:\n")
        end = workflow.index(f"\n  {next_job}:\n", start) if next_job else len(workflow)
        section = workflow[start:end]
        assert "RADAR_DISPATCH_HMAC_KEY: ${{ secrets.RADAR_DISPATCH_HMAC_KEY }}" in section


def test_partial_failures_are_visible_without_skipping_durable_state():
    workflow = (ROOT / ".github/workflows/radar.yml").read_text(encoding="utf-8")
    assert "id: pr_followup_check" in workflow
    assert "if: steps.pr_followup_check.outcome == 'failure'" in workflow
    assert "PR_FOLLOWUP_DEGRADED" in workflow
    assert "id: war_room_send" in workflow
    assert "if: steps.war_room_send.outcome == 'failure'" in workflow
    assert "NOTIFICATION_DEGRADED" in workflow

    build_state_header = workflow.split("\n  build-state:\n", 1)[1].split(
        "\n    runs-on:", 1
    )[0]
    assert "needs.scan.result == 'success'" in build_state_header
    assert "needs.pr-followup.result == 'failure'" in build_state_header

    receipt_header = workflow.split("\n  persist-receipt:\n", 1)[1].split(
        "\n    runs-on:", 1
    )[0]
    assert "needs.notify.result == 'failure'" in receipt_header


def test_radar_scan_applies_controller_decision_feedback_before_scanning():
    workflow = (ROOT / ".github/workflows/radar.yml").read_text(encoding="utf-8")
    scan = workflow.split("\n  scan:\n", 1)[1].split("\n  build-state:\n", 1)[0]
    restore = scan.index("--profile controller-feedback")
    apply_feedback = scan.index("scripts/apply_controller_decision_feedback.py")
    scan_candidates = scan.index("python -m oss_pr_radar.scanner")
    assert restore < apply_feedback < scan_candidates


def test_radar_receipt_persistence_consumes_the_current_pending_state():
    workflow = (ROOT / ".github/workflows/radar.yml").read_text(encoding="utf-8")
    section = workflow.split("\n  persist-receipt:\n", 1)[1]
    assert "name: pending-state-${{ github.run_id }}" in section
    assert "path: pending-state" in section
    assert (
        "cp pending-state/state/war_room_feishu_outbox.json state/war_room_feishu_outbox.json"
        in section
    )
    assert "name: war-room-receipt-${{ github.run_id }}" in section
    assert "scripts/apply_war_room_receipt.py" in section
    assert (
        section.index("scripts/merge_war_room_receipt.py")
        < section.index("scripts/apply_war_room_receipt.py")
        < section.index("scripts/export_managed_snapshot.py")
    )


def test_war_room_sender_cannot_send_without_the_source_artifact():
    sender = (ROOT / "scripts/send_war_room_outbox.py").read_text(encoding="utf-8")
    assert "--artifact" in sender
    assert "sourceArtifactDigest" in sender
    assert "validate_projection" in sender


def test_workflow_exporter_multiline_script_smoke_creates_all_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    workflow = (ROOT / ".github/workflows/radar.yml").read_text(encoding="utf-8")
    block = workflow.split("- name: Export managed lifecycle and War Room projection", 1)[1].split(
        "\n      - name:", 1
    )[0]
    lines = block.splitlines()
    start = next(
        index for index, line in enumerate(lines) if "export_war_room_projection.py" in line
    )
    command = "\n".join(line.strip() for line in lines[start:] if line.strip())

    sandbox = tmp_path / "workflow"
    (sandbox / "state").mkdir(parents=True)
    shutil.copytree(ROOT / "scripts", sandbox / "scripts")
    (sandbox / "src").symlink_to(ROOT / "src", target_is_directory=True)
    ledger_path = sandbox / "state" / "radar_ledger.sqlite3"
    RadarLedger(ledger_path)
    ledger = ManagedLedger(ledger_path, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#7",
        owner="owner",
        repo="repo",
        issue_number=7,
        issue_url="https://github.com/owner/repo/issues/7",
        state="SYSTEM_PROCESSING",
        source="smoke",
        provenance={"title": "标题"},
        metadata={"title": "标题"},
    )
    ledger.bind_task(
        task_id="task-7",
        opportunity_key="owner/repo#7",
        thread_id="thread-7",
        worktree_path=None,
    )
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "s" * 32)
    ledger.authorize_task_creation(
        task_id="task-7",
        opportunity_key="owner/repo#7",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/7",
        intent_id="task-7",
    )
    environment = os.environ.copy()
    environment["GITHUB_SHA"] = "smoke-commit"
    environment["PATH"] = f"{Path(sys.executable).parent}:{environment.get('PATH', '')}"
    subprocess.run(
        ["bash", "-e", "-u", "-o", "pipefail", "-c", command],
        cwd=sandbox,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert (sandbox / "reports/war_room_projection.json").is_file()
    assert (sandbox / "reports/war_room_views.json").is_file()
    assert (sandbox / "state/war_room_feishu_outbox.json").is_file()
    assert (sandbox / "state/war_room_codex_outbox.json").is_file()
    projection = json.loads((sandbox / "reports/war_room_projection.json").read_text())
    assert projection["source"]["sourceCommit"] == "smoke-commit"
