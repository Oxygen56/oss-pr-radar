from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    REPLY_TEMPLATE_ID,
    ManagedLedger,
    import_open_pr_observations,
    public_reply_policy_digest,
    verify_task_creation_authorization,
)
from oss_pr_radar.war_room_deploy import build_copy, verify_copy
from oss_pr_radar.war_room_messages import build_outbox, build_public_reply, validate_outboxes
from oss_pr_radar.war_room_migration import prepare_copy, rollback_copy
from oss_pr_radar.war_room_projection import (
    PROJECTION_BUCKETS,
    build_projection,
    build_views,
    export_projection,
    validate_projection,
)

ROOT = Path(__file__).parents[1]


def managed_db(tmp_path: Path) -> Path:
    path = tmp_path / "state" / "ledger.sqlite3"
    path.parent.mkdir(parents=True)
    RadarLedger(path)
    ManagedLedger(path, ensure_schema=True)
    return path


def add_opportunity(ledger: ManagedLedger, key: str, *, gate: bool = False) -> None:
    owner_repo, number = key.rsplit("#", 1)
    owner, repo = owner_repo.split("/", 1)
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner=owner,
        repo=repo,
        issue_number=int(number),
        issue_url=f"https://github.com/{owner_repo}/issues/{number}",
        state="DECISION_REQUIRED",
        source="test",
        provenance={"title": "标题"},
        metadata={"title": "标题", "preTaskGate": {"allowed": gate}, "notify": True},
        observed_at="2026-08-19T00:00:00Z",
    )


def test_four_buckets_are_exhaustive_and_missing_task_is_not_actionable(tmp_path: Path):
    path = managed_db(tmp_path)
    ledger = ManagedLedger(path)
    add_opportunity(ledger, "owner/repo#1")

    artifact = build_projection(path, source_commit="1533a21")

    assert tuple(artifact["buckets"]) == PROJECTION_BUCKETS
    assert len(artifact["items"]) == 1
    item = artifact["items"][0]
    assert item["actionable"] is False
    assert item["notified"] is False
    assert item["bucket"] == "DECISION_REQUIRED"
    validate_projection(artifact)
    assert build_outbox(artifact, channel="feishu")["events"] == []


def test_canonical_url_and_key_share_projection_authorization(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 32)
    path = managed_db(tmp_path)
    ledger = ManagedLedger(path)
    issue_url = "https://github.com/owner/repo/issues/7"
    ledger.upsert_opportunity(
        opportunity_key=issue_url,
        owner="owner",
        repo="repo",
        issue_number=7,
        issue_url=issue_url,
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={"title": "标题"},
        metadata={"title": "标题", "notify": True},
    )
    ledger.bind_task(
        task_id="task-7",
        opportunity_key=issue_url,
        thread_id="thread-7",
        worktree_path=None,
    )
    ledger.authorize_task_creation(
        task_id="task-7",
        opportunity_key=issue_url,
        repo="owner/repo",
        issue_url=issue_url,
        intent_id="task-7",
    )
    with ledger._connection() as connection:
        authorization = json.loads(
            connection.execute(
                "SELECT payload_json FROM managed_lifecycle_events "
                "WHERE event_type='TASK_CREATION_AUTHORIZED'"
            ).fetchone()[0]
        )["authorization"]
    assert verify_task_creation_authorization(
        authorization,
        task_id="task-7",
        opportunity_key=issue_url,
        repo="owner/repo",
        issue_url=issue_url,
    )
    assert verify_task_creation_authorization(
        authorization,
        task_id="task-7",
        opportunity_key="owner/repo#7",
        repo="owner/repo",
        issue_url=issue_url,
    )
    artifact = build_projection(path)
    assert artifact["items"][0]["candidateKey"] == "owner/repo#7"
    assert artifact["items"][0]["actionable"] is True
    assert artifact["items"][0]["creationGatePassed"] is True
    assert artifact["items"][0]["taskId"] == "task-7"
    assert build_outbox(artifact, channel="feishu")["events"][0]["candidateKey"] == "owner/repo#7"


def test_mature_notified_candidate_without_task_produces_no_external_send(tmp_path: Path):
    path = managed_db(tmp_path)
    ledger = ManagedLedger(path)
    add_opportunity(ledger, "owner/repo#8")
    artifact = export_projection(path)
    outbox = build_outbox(artifact, channel="feishu")
    assert outbox["events"] == []
    artifact_path = tmp_path / "projection.json"
    input_path = tmp_path / "outbox.json"
    output_path = tmp_path / "receipt.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    input_path.write_text(json.dumps(outbox), encoding="utf-8")
    environment = os.environ.copy()
    environment.pop("FEISHU_APP_ID", None)
    environment.pop("FEISHU_APP_SECRET", None)
    environment.pop("FEISHU_CHAT_ID", None)
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/send_war_room_outbox.py"),
            str(input_path),
            str(output_path),
            "--artifact",
            str(artifact_path),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(output_path.read_text(encoding="utf-8"))["events"] == []


def test_gate_bound_task_is_the_only_actionable_source_and_exports_are_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 32)
    path = managed_db(tmp_path)
    ledger = ManagedLedger(path)
    add_opportunity(ledger, "owner/repo#2", gate=True)
    ledger.bind_task(
        task_id="task-2",
        opportunity_key="owner/repo#2",
        thread_id="thread-2",
        worktree_path=None,
        provenance={"creationGate": {"allowed": True}},
        observed_at="2026-08-19T00:01:00Z",
    )
    ledger.authorize_task_creation(
        task_id="task-2",
        opportunity_key="owner/repo#2",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/2",
        intent_id="task-2",
    )
    first = export_projection(path, source_commit="1533a21")
    second = export_projection(path, source_commit="1533a21")
    assert first == second
    assert first["items"][0]["actionable"] is True
    views = build_views(first)
    outboxes = {channel: build_outbox(first, channel=channel) for channel in ("feishu", "codex")}
    validate_outboxes(first, outboxes)
    assert views["feishu"]["sourceArtifactDigest"] == views["codex"]["sourceArtifactDigest"]
    assert [event["candidateKey"] for event in outboxes["feishu"]["events"]] == ["owner/repo#2"]
    outboxes["codex"]["events"][0]["reason"] = "篡改后的内容"
    with pytest.raises(ValueError, match="event/card binding"):
        validate_outboxes(first, outboxes)


def test_sender_binding_rejects_card_event_and_idempotency_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 32)
    path = managed_db(tmp_path)
    ledger = ManagedLedger(path)
    add_opportunity(ledger, "owner/repo#2", gate=True)
    ledger.bind_task(
        task_id="task-2",
        opportunity_key="owner/repo#2",
        thread_id="thread-2",
        worktree_path=None,
    )
    ledger.authorize_task_creation(
        task_id="task-2",
        opportunity_key="owner/repo#2",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/2",
        intent_id="task-2",
    )
    artifact = export_projection(path)
    outbox = build_outbox(artifact, channel="feishu")
    for field, value in (
        ("eventId", "forged-event"),
        ("idempotencyKey", "forged-idempotency"),
    ):
        mutated = json.loads(json.dumps(outbox))
        mutated["events"][0][field] = value
        with pytest.raises(ValueError, match="event/card binding"):
            validate_outboxes(
                artifact,
                {"feishu": mutated, "codex": build_outbox(artifact, channel="codex")},
            )
    mutated = json.loads(json.dumps(outbox))
    mutated["events"][0]["card"]["elements"][0]["text"]["content"] = "path injection"
    with pytest.raises(ValueError, match="event/card binding"):
        validate_outboxes(
            artifact,
            {"feishu": mutated, "codex": build_outbox(artifact, channel="codex")},
        )


def test_forged_gate_metadata_and_identity_mismatch_never_become_actionable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 32)
    path = managed_db(tmp_path)
    ledger = ManagedLedger(path)
    add_opportunity(ledger, "owner/repo#3", gate=True)
    ledger.bind_task(
        task_id="task-3",
        opportunity_key="owner/repo#3",
        thread_id="thread-3",
        worktree_path=None,
        provenance={"creationGate": {"allowed": True}},
    )
    assert build_projection(path)["items"][0]["actionable"] is False
    with pytest.raises(ValueError, match="identity"):
        ledger.authorize_task_creation(
            task_id="task-3",
            opportunity_key="owner/repo#3",
            repo="owner/repo",
            issue_url="https://github.com/owner/repo/issues/999",
            intent_id="task-3",
        )
    assert build_projection(path)["items"][0]["actionable"] is False


def test_public_reply_defaults_to_draft_until_both_policy_and_evidence_are_proven():
    draft = build_public_reply(body="请确认", policy={"fullyAuthenticated": True})
    assert draft["mode"] == "DRAFT"
    allowed = build_public_reply(
        body="已按要求处理。",
        policy={
            "fullyAuthenticated": True,
            "maintainerAuthenticated": True,
            "deterministicMechanicalRequest": True,
            "policyDigest": public_reply_policy_digest(),
            "templateId": REPLY_TEMPLATE_ID,
        },
        evidence={
            "currentTaskEvidence": True,
            "currentChecksPassed": True,
            "validationCertificateValid": True,
            "headShaMatches": True,
        },
    )
    assert allowed["mode"] == "AUTO_REPLY_ALLOWED"


def test_copy_migration_is_atomic_and_rollback_preserves_existing_open_pr_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 32)
    source = managed_db(tmp_path / "source")
    import_open_pr_observations(
        source,
        [{"url": "https://github.com/owner/repo/pull/9", "headSha": "existing"}],
        source="test",
        observed_at="2026-08-19T00:00:00Z",
    )
    target = tmp_path / "copy" / "ledger.sqlite3"
    result = prepare_copy(source, target, source_commit="1533a21")
    assert result["legacyUnchanged"] is True
    assert result["existingOpenPrPreserved"] is True
    assert result["rollbackManifest"]["target"] == str(target.resolve())
    with ManagedLedger(target)._connection() as connection:
        row = connection.execute(
            "SELECT origin_kind FROM managed_prs WHERE pr_key='owner/repo#9'"
        ).fetchone()
        assert row[0] == "EXISTING_OPEN_PR"
    backup = Path(result["rollbackManifest"]["rollbackBackup"])
    consumption = Path(result["rollbackManifest"]["rollbackConsumptionPath"])
    assert not consumption.exists()
    backup_bytes = backup.read_bytes()
    backup.write_bytes(backup_bytes + b"tamper")
    with pytest.raises(RuntimeError, match="backup content digest"):
        rollback_copy(target, result["rollbackManifest"])
    backup.write_bytes(backup_bytes)
    rolled_back = rollback_copy(target, result["rollbackManifest"])
    assert consumption.is_file()
    consumption_record = json.loads(consumption.read_text(encoding="utf-8"))["records"][0]
    assert consumption_record["manifestDigest"] == result["rollbackManifest"]["manifestDigest"]
    assert consumption_record["rollbackNonce"] == result["rollbackManifest"]["rollbackNonce"]
    assert rolled_back["legacyPreserved"] is True
    assert rolled_back["existingPrHistoryPreserved"] is True
    with ManagedLedger(target)._connection() as connection:
        row = connection.execute(
            "SELECT origin_kind FROM managed_prs WHERE pr_key='owner/repo#9'"
        ).fetchone()
        assert row[0] == "EXISTING_OPEN_PR"
    with pytest.raises(RuntimeError, match="already been consumed"):
        rollback_copy(target, result["rollbackManifest"])
    with pytest.raises(ValueError, match="target"):
        rollback_copy(tmp_path / "wrong.sqlite3", result["rollbackManifest"])


def test_thin_copy_records_commit_without_activation(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "d" * 32)
    source = tmp_path / "source"
    (source / "scripts").mkdir(parents=True)
    (source / "scripts" / "war_room_entrypoint.py").write_text(
        "from oss_pr_radar.war_room_projection import export_projection\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "entry"], cwd=source, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True
    ).stdout.strip()
    target = tmp_path / "automation-copy"
    result = build_copy(source, target, source_commit=commit)
    assert result["sourceCommit"] == commit
    assert "export_projection" in (target / "scripts" / "war_room_entrypoint.py").read_text()
    manifest = json.loads((target / "war-room-copy-manifest.json").read_text())
    assert manifest["sourceCommit"] == commit
    forged_manifest = dict(manifest)
    forged_manifest["sourceCommit"] = "0" * 40
    with pytest.raises(ValueError, match="manifest digest"):
        verify_copy(target, forged_manifest)
    (target / "extra.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(ValueError, match="file list"):
        verify_copy(target, manifest)
    (target / "extra.txt").unlink()
    (target / "scripts" / "war_room_entrypoint.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="byte digest"):
        verify_copy(target, manifest)


def test_thin_copy_subprocess_uses_verified_release_from_non_repo_cwd(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "thin-stage7-key" * 4)
    source = tmp_path / "release-source"
    shutil.copytree(ROOT / "src", source / "src")
    shutil.copytree(
        ROOT / "scripts",
        source / "scripts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "release"], cwd=source, check=True)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=runtime, check=True)
    deploy_spec = importlib.util.spec_from_file_location(
        "stage7_deploy_for_war_room", ROOT / "scripts" / "deploy_local_runtime.py"
    )
    assert deploy_spec and deploy_spec.loader
    deploy = importlib.util.module_from_spec(deploy_spec)
    deploy_spec.loader.exec_module(deploy)
    deploy.deploy(source, runtime)
    ledger = managed_db(tmp_path / "ledger")
    copy = tmp_path / "thin-copy"
    build_copy(source, copy)
    poisoned = runtime / "scripts"
    poisoned.mkdir()
    (poisoned / "war_room_entrypoint.py").write_text(
        "raise SystemExit('poisoned')\n", encoding="utf-8"
    )
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [
            sys.executable,
            str(copy / "scripts" / "war_room_entrypoint.py"),
            "--runtime-root",
            str(runtime),
            "--ledger-copy",
            str(ledger),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["schema"] == "oss-pr-radar.war-room-projection.v1"


def test_thin_copy_rejects_dirty_source_and_tampering(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "d" * 32)
    source = tmp_path / "source"
    (source / "scripts").mkdir(parents=True)
    entry = source / "scripts" / "war_room_entrypoint.py"
    entry.write_text(
        "from oss_pr_radar.war_room_projection import export_projection\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "entry"], cwd=source, check=True)
    entry.write_text("dirty\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="clean"):
        build_copy(source, tmp_path / "dirty-target")
    entry.write_text(
        "from oss_pr_radar.war_room_projection import export_projection\n", encoding="utf-8"
    )
    subprocess.run(["git", "checkout", "--", "."], cwd=source, check=True)
    with pytest.raises(ValueError, match="does not match HEAD"):
        build_copy(source, tmp_path / "mismatch-target", source_commit="0" * 40)
    entry.unlink()
    (source / "scripts" / "real.py").write_text("entry\n", encoding="utf-8")
    entry.symlink_to("real.py")
    subprocess.run(["git", "add", "-A"], cwd=source, check=True)
    subprocess.run(["git", "commit", "-qm", "symlink"], cwd=source, check=True)
    with pytest.raises(ValueError, match="regular git blob"):
        build_copy(source, tmp_path / "symlink-target")
