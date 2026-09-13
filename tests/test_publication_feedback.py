from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_ledger import insert_succeeded_pr_creation, intent

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot
from oss_pr_radar.publication_feedback import (
    FILENAME,
    apply_feedback,
    build_feedback,
    merge_feedback,
    signed_feedback,
    validate_feedback,
)

pytestmark = pytest.mark.usefixtures("current_signing_key")
ROOT = Path(__file__).parents[1]
PR = "a/b#868"
URL = "https://github.com/a/b/pull/868"


def publication(database: Path) -> ManagedAdapter:
    store = RadarLedger(database)
    store.enqueue(intent())
    insert_succeeded_pr_creation(store, pr_url=URL, created=True, request_id="request-1")
    adapter = ManagedAdapter(database.parent, database)
    reservation = adapter.reserve_publication(
        request_id="request-1",
        repo="a/b",
        head_ref="fix/runtime",
        head_sha="b" * 40,
        opportunity_key="a/b#1",
    )
    adapter.ledger.record_publication_receipt_atomic(
        pr_key=PR,
        owner="a",
        repo="b",
        number=868,
        head_sha="b" * 40,
        pr_url=URL,
        auto_created=True,
        source_kind="MANAGED_PUBLICATION_RECEIPT",
        source="publication",
        reservation_key=reservation["reservationKey"],
        opportunity_key="a/b#1",
        event_idempotency_key=f"publication:request-1:{'b' * 40}",
        event_provenance={"requestId": "request-1"},
        receipt_observation=True,
    )
    return adapter


def command(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=cwd, check=True, capture_output=True, text=True, env=os.environ.copy()
    )


@pytest.fixture
def bridge():
    spec = importlib.util.spec_from_file_location(
        "publication_feedback_bridge", ROOT / "scripts/local_dispatch_bridge.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_export_feedback_branch_import_checkpoint_and_followup_entries(
    tmp_path, monkeypatch, bridge
):
    local = tmp_path / "local"
    local.mkdir(mode=0o700)
    (local / "state").mkdir(mode=0o700)
    database = local / "state" / "radar_ledger.sqlite3"
    publication(database)
    origin = tmp_path / "origin.git"
    command("git", "init", "--bare", str(origin))
    command("git", "init", str(local))
    command("git", "remote", "add", "origin", str(origin), cwd=local)

    exported = command(
        sys.executable,
        str(ROOT / "scripts/sync_publication_feedback.py"),
        "export",
        "--ledger",
        str(database),
        "--feedback",
        str(local / "state" / FILENAME),
    )
    assert json.loads(exported.stdout)["admissions"] == 1
    public_text = (local / "state" / FILENAME).read_text()
    assert "/tmp/worktree" not in public_text
    assert "thread-1" not in public_text
    assert "notice-evidence" not in public_text
    # Seed the existing channel, then exercise the controller's real publisher.
    (local / "state" / FILENAME).write_text(json.dumps(signed_feedback({})))
    terminal = local / "state" / "controller_terminal_feedback.json"
    decision = local / "state" / "controller_decision_feedback.json"
    terminal.write_text('{"keep/repo#4":{"status":"controller_terminal"}}')
    decision.write_text('{"entries":{"keep-decision":{}}}')
    command(
        sys.executable,
        str(ROOT / "scripts/state_branch.py"),
        "publish",
        "--root",
        str(local),
        "--profile",
        "controller-feedback",
    )
    monkeypatch.setattr(bridge, "STATE", local / "state")
    published = bridge.publish_publication_feedback(SimpleNamespace(ledger=database))
    assert published == {"ok": True, "admissions": 1, "stateChanged": True}
    assert (
        bridge.publish_publication_feedback(SimpleNamespace(ledger=database))["stateChanged"]
        is False
    )
    cloud = tmp_path / "cloud"
    command("git", "clone", str(origin), str(cloud))
    command(
        sys.executable,
        str(ROOT / "scripts/state_branch.py"),
        "restore",
        "--root",
        str(cloud),
        "--profile",
        "controller-feedback",
    )
    assert (cloud / "state" / terminal.name).read_bytes() == terminal.read_bytes()
    assert (cloud / "state" / decision.name).read_bytes() == decision.read_bytes()
    cloud_database = cloud / "state" / "radar_ledger.sqlite3"
    adapter = ManagedAdapter(cloud, cloud_database)
    adapter.ledger.upsert_opportunity(
        opportunity_key="scanner/new#17",
        owner="scanner",
        repo="new",
        issue_number=17,
        issue_url="https://github.com/scanner/new/issues/17",
        state="SYSTEM_PROCESSING",
        source="scanner",
        provenance={},
    )
    applied = command(
        sys.executable,
        str(ROOT / "scripts/sync_publication_feedback.py"),
        "apply",
        "--ledger",
        str(cloud_database),
        "--feedback",
        str(cloud / "state" / FILENAME),
    )
    assert json.loads(applied.stdout) == {"ok": True, "admissions": 1, "added": 1, "duplicates": 0}
    assert adapter.ledger.read_opportunity("scanner/new#17") is not None
    snapshot = cloud / "state" / "managed_lifecycle.snapshot.json.gz"
    export_snapshot(cloud_database, snapshot)
    restored = cloud / "restored.sqlite3"
    import_snapshot(restored, snapshot)
    value = json.loads(public_text)
    assert apply_feedback(restored, value) == {
        "ok": True,
        "admissions": 1,
        "added": 0,
        "duplicates": 1,
    }

    state, report = cloud / "followup.json", cloud / "report.json"
    state.write_text(
        json.dumps(
            {
                "items": [
                    {"key": PR, "headSha": "c" * 40, "prState": "OPEN", "ciStatus": "PASSED"},
                    {"key": "unknown/repo#7", "headSha": "d" * 40},
                ]
            }
        )
    )
    report.write_text('{"run_id":"isolation-test"}')
    followed = command(
        sys.executable,
        str(ROOT / "scripts/sync_managed_followup.py"),
        str(state),
        str(report),
        "--ledger",
        str(restored),
    )
    result = json.loads(followed.stdout)
    assert result["recorded"] == 1
    assert result["ignored"] == [{"key": "unknown/repo#7", "reason": "FOLLOWUP_KEY_NOT_MANAGED"}]
    # Replaying the original receipt cannot regress a newer PR observation.
    assert apply_feedback(restored, value)["duplicates"] == 1
    ledger = ManagedAdapter(cloud, restored).ledger
    with ledger._connection() as connection:
        assert (
            connection.execute("SELECT head_sha FROM managed_prs WHERE pr_key=?", (PR,)).fetchone()[
                0
            ]
            == "c" * 40
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM managed_publication_reservations").fetchone()[
                0
            ]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE event_type='PUBLICATION_RECEIPT_OBSERVED'"
            ).fetchone()[0]
            == 1
        )
    assert (
        ledger.published_pr_for_opportunity("a/b#1", pr_url=URL, publication_head_sha="b" * 40)[
            "pr_key"
        ]
        == PR
    )
    # Restored cloud admissions are not re-exported as local publication acts.
    assert build_feedback(restored)["entries"] == {}


def test_publisher_failed_restore_never_overwrites_feedback(tmp_path, monkeypatch, bridge):
    database = tmp_path / "local.sqlite3"
    publication(database)
    monkeypatch.setattr(bridge, "STATE", tmp_path / "state")
    calls = []

    def failed_restore(args, **kwargs):
        calls.append(args)
        assert args[2] == "restore"
        assert "--allow-missing" not in args
        raise RuntimeError("state branch fetch failed")

    monkeypatch.setattr(bridge, "command", failed_restore)
    with pytest.raises(RuntimeError, match="fetch failed"):
        bridge.publish_publication_feedback(SimpleNamespace(ledger=database))
    assert len(calls) == 1
    assert not (tmp_path / "state" / FILENAME).exists()


def test_publisher_respects_existing_publication_pause(tmp_path, monkeypatch, bridge):
    monkeypatch.setattr(
        bridge, "_active_publication_pause", lambda _root: {"reason": "maintenance"}
    )
    result = bridge.publish_publication_feedback(
        SimpleNamespace(ledger=tmp_path / "does-not-exist.sqlite3", runtime_root=tmp_path)
    )
    assert result == {"ok": True, "paused": True, "admissions": 0, "stateChanged": False}


@pytest.mark.parametrize("state", ["CLOSED", "MERGED"])
def test_replay_preserves_cloud_terminal_state_and_newer_head(tmp_path, state):
    local, cloud = tmp_path / "local.sqlite3", tmp_path / "cloud.sqlite3"
    publication(local)
    feedback = build_feedback(local)
    apply_feedback(cloud, feedback)
    ledger = ManagedAdapter(tmp_path, cloud).ledger
    with ledger._connection() as connection:
        connection.execute(
            "UPDATE managed_prs SET state=?, head_sha=? WHERE pr_key=?", (state, "c" * 40, PR)
        )
    snapshot = tmp_path / "checkpoint.json.gz"
    export_snapshot(cloud, snapshot)
    restored = tmp_path / "restored.sqlite3"
    import_snapshot(restored, snapshot)
    assert apply_feedback(restored, feedback)["duplicates"] == 1
    with ManagedAdapter(tmp_path, restored).ledger._connection() as connection:
        row = connection.execute(
            "SELECT state,head_sha FROM managed_prs WHERE pr_key=?", (PR,)
        ).fetchone()
        assert tuple(row) == (state, "c" * 40)


@pytest.mark.parametrize("mutation", ["effect", "event", "reservation", "permit", "pr"])
def test_export_refuses_incomplete_or_mismatched_durable_evidence(tmp_path, mutation):
    database = tmp_path / "local.sqlite3"
    adapter = publication(database)
    with adapter.ledger._connection() as connection:
        if mutation == "effect":
            connection.execute("UPDATE publication_effects SET status='FAILED'")
        elif mutation == "event":
            connection.execute("DROP TRIGGER managed_events_no_delete")
            connection.execute(
                "DELETE FROM managed_lifecycle_events WHERE event_type='PUBLICATION_RECEIPT_OBSERVED'"
            )
        elif mutation == "reservation":
            connection.execute(
                "UPDATE managed_publication_reservations SET head_sha=?", ("c" * 40,)
            )
        elif mutation == "permit":
            connection.execute(
                "UPDATE publication_permits SET pr_url='https://github.com/a/b/pull/9'"
            )
        else:
            connection.execute("UPDATE managed_prs SET origin_kind='FOLLOWUP_OBSERVATION'")
    with pytest.raises(ValueError, match="publication admission"):
        build_feedback(database)


def test_legacy_receipt_requires_exact_request_identity_without_reservation_payload(tmp_path):
    database = tmp_path / "local.sqlite3"
    adapter = publication(database)
    with adapter.ledger._connection() as connection:
        connection.execute("DROP TRIGGER managed_events_no_update")
        row = connection.execute(
            "SELECT event_id,payload_json FROM managed_lifecycle_events WHERE event_type='PUBLICATION_RECEIPT_OBSERVED'"
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload.pop("reservationKey")
        connection.execute(
            "UPDATE managed_lifecycle_events SET payload_json=? WHERE event_id=?",
            (json.dumps(payload), row["event_id"]),
        )
    assert len(build_feedback(database)["entries"]) == 1
    with adapter.ledger._connection() as connection:
        connection.execute("DROP TRIGGER IF EXISTS managed_events_no_update")
        connection.execute(
            "UPDATE managed_lifecycle_events SET provenance_json='{}' WHERE event_type='PUBLICATION_RECEIPT_OBSERVED'"
        )
    with pytest.raises(ValueError, match="successful GitHub evidence"):
        build_feedback(database)


def test_bad_signature_or_private_extra_field_never_creates_database(tmp_path):
    database = tmp_path / "local.sqlite3"
    publication(database)
    value = build_feedback(database)
    bad = deepcopy(value)
    next(iter(bad["entries"].values()))["prUrl"] = "https://github.com/a/b/pull/9"
    target = tmp_path / "target.sqlite3"
    with pytest.raises(ValueError, match="signature"):
        apply_feedback(target, bad)
    assert not target.exists()
    entries = deepcopy(value["entries"])
    next(iter(entries.values()))["worktreePath"] = "/private/worktree"
    with pytest.raises(ValueError, match="unexpected fields"):
        signed_feedback(entries)


def test_conflicting_signed_receipt_is_rejected_after_snapshot_restore(tmp_path):
    database = tmp_path / "local.sqlite3"
    publication(database)
    value = build_feedback(database)
    target = tmp_path / "target.sqlite3"
    apply_feedback(target, value)
    snapshot = tmp_path / "state.gz"
    export_snapshot(target, snapshot)
    restored = tmp_path / "restored.sqlite3"
    import_snapshot(restored, snapshot)
    entries = deepcopy(value["entries"])
    next(iter(entries.values()))["proofDigest"] = "e" * 64
    conflict = signed_feedback(entries)
    with pytest.raises(ValueError, match="conflicts"):
        apply_feedback(restored, conflict)
    with pytest.raises(ValueError, match="conflicts"):
        merge_feedback(value, conflict)
    assert validate_feedback(merge_feedback(value, value)) == value["entries"]


def test_workflow_applies_publication_admissions_before_followup_and_scan():
    workflow = (ROOT / ".github/workflows/radar.yml").read_text()
    scan = workflow.split("  scan:\n", 1)[1].split("  build-state:\n", 1)[0]
    build = workflow.split("  build-state:\n", 1)[1].split("  persist-pending:\n", 1)[0]
    apply = "scripts/sync_publication_feedback.py apply --allow-missing"
    assert (
        scan.index("--profile controller-feedback")
        < scan.index(apply)
        < scan.index("-m oss_pr_radar.scanner")
    )
    assert (
        build.index("scripts/import_managed_snapshot.py")
        < build.index(apply)
        < build.index("scripts/sync_managed_followup.py")
    )
