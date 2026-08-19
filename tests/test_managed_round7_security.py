from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    PublicationAbsenceReconciler,
    _digest,
    migrate_v6_to_v7,
    schema_status,
)
from oss_pr_radar.managed_snapshot import (
    build_snapshot,
    export_snapshot,
    import_snapshot,
    inspect_snapshot,
)
from oss_pr_radar.util import canonical_json

pytestmark = pytest.mark.usefixtures("current_signing_key")


@pytest.fixture(autouse=True)
def disable_host_keychain(monkeypatch):
    monkeypatch.setattr("oss_pr_radar.managed_security._keychain_current_key", lambda: None)


def ledger_at(tmp_path: Path, name: str):
    database = tmp_path / name
    RadarLedger(database)
    return database, ManagedLedger(database, ensure_schema=True)


def write_snapshot(path: Path, snapshot: dict) -> None:
    path.write_bytes(gzip.compress(canonical_json(snapshot).encode("utf-8"), mtime=0))


def populated_source(tmp_path: Path, name: str = "source.sqlite3"):
    database, ledger = ledger_at(tmp_path, name)
    ledger.upsert_pr(
        pr_key="owner/repo#1",
        owner="owner",
        repo="repo",
        number=1,
        head_sha="head-1",
        pr_url="https://github.com/owner/repo/pull/1",
        state="OPEN",
        auto_created=True,
    )
    ledger.bind_task(
        task_id="task-1", opportunity_key="owner/repo#1", thread_id=None, worktree_path=None
    )
    ledger.record_result(
        task_id="task-1",
        result_digest="result-1",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#1",
        head_sha="head-1",
        commit_sha="commit-1",
        validation={"passed": True, "evidence": ["pytest:1"]},
        prior_head_sha="old-head",
        new_head_sha="head-1",
    )
    ledger.reserve_publication_slot(
        reservation_key="publication-1",
        request_id="request-1",
        repo="owner/repo",
        head_ref="feature/1",
        head_sha="head-1",
        idempotency_key="publication-1",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z")
    attestation = ledger.create_absence_attestation(
        reservation_key="publication-1",
        repo="owner/repo",
        head_ref="feature/1",
        head_sha="head-1",
        queries=[
            {"endpoint": "repos/owner/repo/branches/feature/1", "ok": True, "exists": False},
            {"endpoint": "repos/owner/repo/git/commits/head-1", "ok": True, "exists": False},
            {
                "endpoint": "repos/owner/repo/pulls?head=owner:feature/1&state=all",
                "ok": True,
                "exists": False,
            },
        ],
        local_effect={"endpoint": "local:publication_effects", "ok": True, "exists": False},
        observed_at="2026-08-19T00:02:00Z",
        nonce="nonce-1",
    )
    ledger.apply_absence_attestation(attestation, now="2026-08-19T00:02:01Z")
    return database, ledger


@pytest.mark.parametrize(
    "collection", ["prs", "results", "absenceAttestations", "attestationNonceConsumptions"]
)
def test_root_hmac_rejects_collection_deletion_after_content_digest_recompute(tmp_path, collection):
    source, _ = populated_source(tmp_path, f"source-{collection}.sqlite3")
    snapshot = build_snapshot(source)
    snapshot["rows"][collection].pop()
    snapshot["contentDigest"] = _digest(snapshot["rows"])
    forged = tmp_path / f"forged-{collection}.gz"
    write_snapshot(forged, snapshot)
    target, target_ledger = ledger_at(tmp_path, f"target-{collection}.sqlite3")
    target_ledger.record_event(event_type="SENTINEL", idempotency_key=f"sentinel:{collection}")
    before = target_ledger.projection()
    with pytest.raises(ValueError, match="root authentication"):
        import_snapshot(target, forged)
    assert target_ledger.projection() == before


def test_root_signature_required_unknown_key_and_previous_key_rotation(tmp_path, monkeypatch):
    source, _ = populated_source(tmp_path, "root-source.sqlite3")
    snapshot_path = tmp_path / "root.snapshot.gz"
    export_snapshot(source, snapshot_path)
    raw = json.loads(gzip.decompress(snapshot_path.read_bytes()))
    missing = dict(raw)
    missing.pop("rootSignature")
    missing_path = tmp_path / "missing-root.gz"
    write_snapshot(missing_path, missing)
    target, _ = ledger_at(tmp_path, "missing-root.sqlite3")
    with pytest.raises(ValueError, match="root authentication"):
        import_snapshot(target, missing_path)

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "round7-next-key-bbbbbbbb")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "round7-next")
    monkeypatch.setenv(
        "RADAR_DISPATCH_HMAC_KEY_PREVIOUS", "managed-test-signing-key-0123456789abcdef"
    )
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS_ID", "test-current")
    rotated_target, _ = ledger_at(tmp_path, "rotated-root.sqlite3")
    with pytest.raises(ValueError, match="root authentication"):
        import_snapshot(rotated_target, snapshot_path)
    assert inspect_snapshot(snapshot_path)["keyId"] == "test-current"

    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS")
    unknown_target, _ = ledger_at(tmp_path, "unknown-root.sqlite3")
    with pytest.raises(ValueError, match="root authentication"):
        import_snapshot(unknown_target, snapshot_path)


def test_restore_completely_replaces_consumption_and_managed_collections(tmp_path):
    source, source_ledger = populated_source(tmp_path, "replace-source.sqlite3")
    target, target_ledger = ledger_at(tmp_path, "replace-target.sqlite3")
    target_ledger.upsert_opportunity(
        opportunity_key="extra/repo#99",
        owner="extra",
        repo="repo",
        issue_number=99,
        issue_url="https://github.com/extra/repo/issues/99",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    snapshot = tmp_path / "replace.snapshot.gz"
    export_snapshot(source, snapshot)
    import_snapshot(target, snapshot)
    with (
        target_ledger._connection() as connection,
        source_ledger._connection() as source_connection,
    ):
        for table in (
            "managed_opportunities",
            "managed_prs",
            "managed_results",
            "managed_publication_absence_attestations",
            "attestation_nonce_consumptions",
        ):
            assert (
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                == source_connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_opportunities WHERE opportunity_key='extra/repo#99'"
            ).fetchone()[0]
            == 0
        )


def test_v6_to_v7_downgrades_authorization_and_requires_new_attestation(tmp_path):
    source, ledger = populated_source(tmp_path, "v6-source.sqlite3")
    with ledger._connection() as connection:
        connection.execute("DELETE FROM managed_schema_migrations WHERE version=7")
        connection.execute(
            "INSERT INTO managed_schema_migrations(version,applied_at,migration_digest) VALUES (6, '2026-08-19T00:00:00Z', 'legacy-v6')"
        )
    assert schema_status(source)["current"] == 6
    target = tmp_path / "v7-target.sqlite3"
    snapshot = tmp_path / "v7.snapshot.gz"
    result = migrate_v6_to_v7(source, target, snapshot_output=snapshot)
    assert result["toVersion"] == 7
    migrated = ManagedLedger(target)
    with migrated._connection() as connection:
        assert (
            connection.execute("SELECT state FROM managed_publication_reservations").fetchone()[0]
            == "CHECK_ABSENCE_REQUIRED"
        )
        validation = json.loads(
            connection.execute("SELECT validation_json FROM managed_results").fetchone()[0]
        )
        assert validation["authenticationStatus"] == "UNAUTHENTICATED"
        assert validation["authorizationState"] == "LEGACY_REAUTH_REQUIRED"
        assert (
            connection.execute(
                "SELECT authentication_status FROM managed_publication_absence_attestations"
            ).fetchone()[0]
            == "LEGACY_REAUTH_REQUIRED"
        )
        assert (
            connection.execute(
                "SELECT event_type,state FROM managed_lifecycle_events WHERE event_type='MANAGED_SCHEMA_MIGRATED'"
            ).fetchone()[1]
            == "LEGACY_REAUTH_REQUIRED"
        )
    with pytest.raises(PermissionError):
        migrated.apply_absence_attestation(
            {"authenticationStatus": "LEGACY_REAUTH_REQUIRED"}, now="2026-08-19T00:03:00Z"
        )

    restored = tmp_path / "v7-restored.sqlite3"
    RadarLedger(restored)
    import_snapshot(restored, snapshot)
    restored_ledger = ManagedLedger(restored)

    class AbsentGithub:
        def query_branch(self, repo, head_ref):
            return {"exists": False}

        def query_commit(self, repo, head_sha):
            return {"exists": False}

        def query_pull_request(self, repo, head_ref, head_sha):
            return {"exists": False}

    reauthorized = PublicationAbsenceReconciler(
        restored_ledger, AbsentGithub(), now="2026-08-19T00:03:00Z"
    ).reconcile(
        reservation_key="publication-1",
        repo="owner/repo",
        head_ref="feature/1",
        head_sha="head-1",
    )
    assert reauthorized["released"] is True


def test_v6_migration_missing_key_leaves_target_unchanged(tmp_path, monkeypatch):
    source, ledger = populated_source(tmp_path, "v6-no-key.sqlite3")
    with ledger._connection() as connection:
        connection.execute("DELETE FROM managed_schema_migrations WHERE version=7")
        connection.execute(
            "INSERT INTO managed_schema_migrations(version,applied_at,migration_digest) VALUES (6, '2026-08-19T00:00:00Z', 'legacy-v6')"
        )
    target, target_ledger = ledger_at(tmp_path, "v7-no-key-target.sqlite3")
    target_ledger.record_event(event_type="SENTINEL", idempotency_key="sentinel:v6")
    before = target_ledger.projection()
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY")
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS", raising=False)
    with pytest.raises(PermissionError, match="signing key"):
        migrate_v6_to_v7(source, target)
    assert target_ledger.projection() == before
