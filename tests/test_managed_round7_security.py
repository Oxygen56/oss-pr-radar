from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    MANAGED_SCHEMA_VERSION,
    ManagedLedger,
    PublicationAbsenceReconciler,
    _digest,
    migrate_v6_to_v7,
    schema_status,
)
from oss_pr_radar.managed_security import sign_current, stable_fingerprint
from oss_pr_radar.managed_snapshot import (
    LEGACY_MANAGED_SCHEMA_V7_DIGEST,
    LEGACY_MANAGED_SCHEMA_VERSION,
    LEGACY_SNAPSHOT_SCHEMA_VERSION,
    SNAPSHOT_AUTH_CONTEXT,
    SNAPSHOT_SCHEMA_VERSION,
    build_snapshot,
    decode_snapshot,
    export_snapshot,
    import_snapshot,
    inspect_snapshot,
    validate_snapshot,
)
from oss_pr_radar.util import canonical_json

pytestmark = pytest.mark.usefixtures("current_signing_key")

QUARANTINE_EVENT_TYPES = {
    "LEGACY_RESULT_REQUIRES_MIGRATION",
    "PUBLISHED_TASK_WORKTREE_MISSING",
    "PR_FOLLOWUP_REBIND_REQUIRED",
    "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID",
    "SHARED_CONTEXT_LAYOUT_CONFLICT",
    "TASK_QUARANTINE_CLEARED",
}


@pytest.fixture(autouse=True)
def disable_host_keychain(monkeypatch):
    monkeypatch.setattr("oss_pr_radar.managed_security._keychain_current_key", lambda: None)


def ledger_at(tmp_path: Path, name: str):
    database = tmp_path / name
    RadarLedger(database)
    return database, ManagedLedger(database, ensure_schema=True)


def write_snapshot(path: Path, snapshot: dict) -> None:
    path.write_bytes(gzip.compress(canonical_json(snapshot).encode("utf-8"), mtime=0))


def read_snapshot(path: Path) -> dict:
    return json.loads(gzip.decompress(path.read_bytes()))


def resign_snapshot(snapshot: dict) -> dict:
    snapshot.pop("rootSignature", None)
    snapshot.pop("keyId", None)
    auth = sign_current(snapshot, context=SNAPSHOT_AUTH_CONTEXT)
    assert auth["keyId"]
    snapshot["keyId"] = auth["keyId"]
    snapshot["rootSignature"] = sign_current(
        {key: value for key, value in snapshot.items() if key != "rootSignature"},
        context=SNAPSHOT_AUTH_CONTEXT,
    )["signature"]
    return snapshot


def legacy_v7_snapshot(source: Path) -> dict:
    snapshot = build_snapshot(source)
    snapshot["snapshotSchema"] = LEGACY_SNAPSHOT_SCHEMA_VERSION
    snapshot["managedSchemaVersion"] = LEGACY_MANAGED_SCHEMA_VERSION
    snapshot["managedSchemaDigest"] = LEGACY_MANAGED_SCHEMA_V7_DIGEST
    snapshot["rows"].pop("taskQuarantines", None)
    snapshot["contentDigest"] = _digest(snapshot["rows"])
    return resign_snapshot(snapshot)


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


def quarantine_snapshot_projection(snapshot: dict) -> dict:
    rows = snapshot["rows"]
    return {
        "taskQuarantines": rows["taskQuarantines"],
        "quarantineEvents": [
            {
                "opportunityKey": event["opportunityKey"],
                "eventType": event["eventType"],
                "idempotencyKey": event["idempotencyKey"],
                "idempotencyFingerprint": event["idempotencyFingerprint"],
                "payloadDigest": event["payloadDigest"],
            }
            for event in rows["events"]
            if event["eventType"] in QUARANTINE_EVENT_TYPES
        ],
    }


def assert_quarantine_snapshot_round_trips_without_drift(
    tmp_path: Path, source: Path, *, prefix: str
) -> None:
    snapshot_path = tmp_path / f"{prefix}-0.snapshot.gz"
    export_snapshot(source, snapshot_path)

    current_snapshot = snapshot_path
    baseline: dict | None = None
    baseline_snapshot: dict | None = None
    baseline_rows_digest: str | None = None
    for index in range(1, 5):
        target, _ = ledger_at(tmp_path, f"{prefix}-{index}.sqlite3")
        import_snapshot(target, current_snapshot)
        with ManagedLedger(target)._connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 1
        current_snapshot = tmp_path / f"{prefix}-{index}.snapshot.gz"
        export_snapshot(target, current_snapshot)
        snapshot = read_snapshot(current_snapshot)
        assert snapshot["contentDigest"] == _digest(snapshot["rows"])
        if baseline is None:
            baseline_snapshot = snapshot
            baseline = quarantine_snapshot_projection(snapshot)
            baseline_rows_digest = _digest(snapshot["rows"])
            assert len(baseline["taskQuarantines"]) == 1
            assert baseline["quarantineEvents"]
        else:
            assert baseline_snapshot is not None
            assert baseline_rows_digest is not None
            assert snapshot["contentDigest"] == baseline_snapshot["contentDigest"]
            assert _digest(snapshot["rows"]) == baseline_rows_digest
            assert quarantine_snapshot_projection(snapshot) == baseline
        with ManagedLedger(target)._connection() as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE event_type IN "
                f"({','.join('?' for _ in QUARANTINE_EVENT_TYPES)})",
                tuple(QUARANTINE_EVENT_TYPES),
            ).fetchone()[0] == len(baseline["quarantineEvents"])


def insert_task_quarantine_row(
    database: Path,
    *,
    opportunity_key: str,
    reason: str,
    dedupe_key: str,
    payload: dict,
    status: str = "ACTIVE",
    created_at: str = "2026-08-19T04:00:00Z",
    cleared_at: str | None = None,
    clear_payload: dict | None = None,
) -> None:
    with ManagedLedger(database)._connection() as connection:
        connection.execute(
            """INSERT INTO task_quarantines
               (opportunity_key,reason,dedupe_key,payload_json,status,created_at,cleared_at,clear_payload_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                opportunity_key,
                reason,
                dedupe_key,
                canonical_json(payload),
                status,
                created_at,
                cleared_at,
                canonical_json(clear_payload) if clear_payload is not None else None,
            ),
        )


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


def test_current_snapshot_exports_and_restores_task_quarantines_without_leaking_private_payload(
    tmp_path,
):
    source, ledger = populated_source(tmp_path, "quarantine-source.sqlite3")
    digest = "a" * 64
    replacement = "b" * 64
    reasons = [
        "PUBLISHED_TASK_WORKTREE_MISSING",
        "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID",
        "SHARED_CONTEXT_LAYOUT_CONFLICT",
        "LEGACY_RESULT_REQUIRES_MIGRATION",
        "PR_FOLLOWUP_REBIND_REQUIRED",
    ]
    for index in range(124):
        issue = index + 10
        key = f"owner/repo#{issue}"
        ledger.upsert_opportunity(
            opportunity_key=key,
            owner="owner",
            repo="repo",
            issue_number=issue,
            issue_url=f"https://github.com/owner/repo/issues/{issue}",
            state="SYSTEM_PROCESSING",
            source="test",
            provenance={},
        )
        ledger.record_task_quarantine(
            opportunity_key=key,
            reason=reasons[index % len(reasons)],
            dedupe_key=f"/Users/oxygen/private/worktree/{index}",
            payload={
                "wakeDigest": digest,
                "replacementWakeDigest": replacement,
                "reservationPending": index % 2 == 0,
                "artifactPath": f"/Users/oxygen/artifacts/{index}.json",
                "originalPath": f"/Users/oxygen/original/{index}.json",
                "worktreePath": f"/Users/oxygen/worktrees/{index}",
                "threadId": f"019f-private-{index}",
            },
            observed_at=f"2026-08-19T00:{index // 60:02d}:{index % 60:02d}Z",
        )

    snapshot_path = tmp_path / "quarantines.snapshot.gz"
    export_snapshot(source, snapshot_path)
    snapshot_text = gzip.decompress(snapshot_path.read_bytes()).decode("utf-8")
    assert "/Users/" not in snapshot_text
    assert "artifactPath" not in snapshot_text
    assert "originalPath" not in snapshot_text
    assert "worktreePath" not in snapshot_text
    assert "threadId" not in snapshot_text
    snapshot = json.loads(snapshot_text)
    validate_snapshot(snapshot)
    assert snapshot["snapshotSchema"] == SNAPSHOT_SCHEMA_VERSION
    assert snapshot["managedSchemaVersion"] == MANAGED_SCHEMA_VERSION
    assert len(snapshot["rows"]["taskQuarantines"]) == 124
    assert {
        "wakeDigest",
        "replacementWakeDigest",
        "reservationPending",
    } <= set(snapshot["rows"]["taskQuarantines"][0]["payload"])

    target, _ = ledger_at(tmp_path, "quarantine-target.sqlite3")
    import_snapshot(target, snapshot_path)
    with ManagedLedger(target)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 124


def test_task_quarantine_snapshot_import_is_additive_and_keeps_stable_dedupe_fingerprints(
    tmp_path,
):
    first, ledger = ledger_at(tmp_path, "quarantine-first.sqlite3")
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#77",
        owner="owner",
        repo="repo",
        issue_number=77,
        issue_url="https://github.com/owner/repo/issues/77",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    source_dedupe = "/Users/oxygen/private/rebind"
    fingerprint = stable_fingerprint(source_dedupe)
    ledger.record_task_quarantine(
        opportunity_key="owner/repo#77",
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        dedupe_key=source_dedupe,
        payload={"wakeDigest": "c" * 64, "reservationPending": True},
        observed_at="2026-08-19T01:00:00Z",
    )
    first_snapshot = tmp_path / "first.snapshot.gz"
    export_snapshot(first, first_snapshot)
    first_rows = json.loads(gzip.decompress(first_snapshot.read_bytes()))["rows"]["taskQuarantines"]
    assert first_rows[0]["dedupeFingerprint"] == fingerprint

    second, _ = ledger_at(tmp_path, "quarantine-second.sqlite3")
    import_snapshot(second, first_snapshot)
    second_snapshot = tmp_path / "second.snapshot.gz"
    export_snapshot(second, second_snapshot)
    second_rows = json.loads(gzip.decompress(second_snapshot.read_bytes()))["rows"][
        "taskQuarantines"
    ]
    assert second_rows[0]["dedupeFingerprint"] == fingerprint

    third, _ = ledger_at(tmp_path, "quarantine-third.sqlite3")
    import_snapshot(third, second_snapshot)
    import_snapshot(third, second_snapshot)
    with ManagedLedger(third)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 1


def test_active_task_quarantine_snapshot_round_trip_is_canonical(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-active-source.sqlite3")
    key = "owner/repo#79"
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=79,
        issue_url="https://github.com/owner/repo/issues/79",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        dedupe_key="/Users/oxygen/private/active-rebind",
        payload={
            "wakeDigest": "a" * 64,
            "replacementWakeDigest": "b" * 64,
            "reservationPending": True,
            "worktreePath": "/Users/oxygen/private/worktree",
            "threadId": "019f-private-active",
        },
        observed_at="2026-08-19T01:10:00Z",
    )

    assert_quarantine_snapshot_round_trips_without_drift(tmp_path, source, prefix="active")


def test_cleared_task_quarantine_snapshot_round_trip_is_canonical(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-cleared-roundtrip-source.sqlite3")
    key = "owner/repo#80"
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=80,
        issue_url="https://github.com/owner/repo/issues/80",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key="/Users/oxygen/private/legacy-result",
        payload={
            "wakeDigest": "c" * 64,
            "artifactPath": "/Users/oxygen/private/artifact.json",
            "originalPath": "/Users/oxygen/private/result.json",
        },
        observed_at="2026-08-19T01:20:00Z",
    )
    ledger.clear_task_quarantine(
        key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        evidence={
            "revalidated": True,
            "review": "ok",
            "artifactPath": "/Users/oxygen/private/clear.json",
        },
        observed_at="2026-08-19T01:21:00Z",
    )

    assert_quarantine_snapshot_round_trips_without_drift(tmp_path, source, prefix="cleared")


def test_task_quarantine_restore_export_over_existing_local_rows_is_idempotent(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-existing-local-source.sqlite3")
    active_key = "owner/repo#81"
    cleared_key = "owner/repo#82"
    for key, number in ((active_key, 81), (cleared_key, 82)):
        ledger.upsert_opportunity(
            opportunity_key=key,
            owner="owner",
            repo="repo",
            issue_number=number,
            issue_url=f"https://github.com/owner/repo/issues/{number}",
            state="SYSTEM_PROCESSING",
            source="test",
            provenance={},
        )
    ledger.record_task_quarantine(
        opportunity_key=active_key,
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        dedupe_key="/Users/oxygen/private/existing-active",
        payload={
            "wakeDigest": "a" * 64,
            "replacementWakeDigest": "b" * 64,
            "reservationPending": True,
            "worktreePath": "/Users/oxygen/private/worktree",
        },
        observed_at="2026-08-19T03:30:00Z",
    )
    ledger.record_task_quarantine(
        opportunity_key=cleared_key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key="/Users/oxygen/private/existing-cleared",
        payload={
            "wakeDigest": "c" * 64,
            "artifactPath": "/Users/oxygen/private/artifact.json",
        },
        observed_at="2026-08-19T03:31:00Z",
    )
    ledger.clear_task_quarantine(
        cleared_key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        evidence={
            "revalidated": True,
            "artifactPath": "/Users/oxygen/private/clear.json",
        },
        observed_at="2026-08-19T03:32:00Z",
    )

    current_snapshot = tmp_path / "existing-local-0.snapshot.gz"
    export_snapshot(source, current_snapshot)
    baseline_projection = None
    baseline_content_digest = None
    baseline_rows_digest = None
    baseline_quarantine_event_count = None
    for index in range(1, 4):
        import_snapshot(source, current_snapshot)
        with ManagedLedger(source)._connection() as connection:
            assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 2
        next_snapshot = tmp_path / f"existing-local-{index}.snapshot.gz"
        export_snapshot(source, next_snapshot)
        snapshot = read_snapshot(next_snapshot)
        projection = quarantine_snapshot_projection(snapshot)
        assert len(projection["taskQuarantines"]) == 2
        event_count = len(projection["quarantineEvents"])
        assert snapshot["contentDigest"] == _digest(snapshot["rows"])
        if baseline_projection is None:
            baseline_projection = projection
            baseline_content_digest = snapshot["contentDigest"]
            baseline_rows_digest = _digest(snapshot["rows"])
            baseline_quarantine_event_count = event_count
        else:
            assert projection == baseline_projection
            assert snapshot["contentDigest"] == baseline_content_digest
            assert _digest(snapshot["rows"]) == baseline_rows_digest
            assert event_count == baseline_quarantine_event_count
        current_snapshot = next_snapshot


def test_task_quarantine_export_rejects_conflicting_active_duplicate_identity(tmp_path):
    database, _ = ledger_at(tmp_path, "quarantine-export-active-conflict.sqlite3")
    key = "owner/repo#83"
    reason = "PR_FOLLOWUP_REBIND_REQUIRED"
    dedupe = "/Users/oxygen/private/export-active-conflict"
    fingerprint = stable_fingerprint(dedupe)
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key=dedupe,
        payload={"wakeDigest": "a" * 64, "reservationPending": True},
        created_at="2026-08-19T04:00:00Z",
    )
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key=f"snapshot:{fingerprint}",
        payload={"wakeDigest": "b" * 64, "reservationPending": True},
        created_at="2026-08-19T04:01:00Z",
    )

    with pytest.raises(ValueError, match="conflicting active task quarantine"):
        export_snapshot(database, tmp_path / "active-conflict.snapshot.gz")


def test_task_quarantine_export_rejects_conflicting_cleared_duplicate_identity(tmp_path):
    database, _ = ledger_at(tmp_path, "quarantine-export-cleared-conflict.sqlite3")
    key = "owner/repo#84"
    reason = "LEGACY_RESULT_REQUIRES_MIGRATION"
    dedupe = "/Users/oxygen/private/export-cleared-conflict"
    fingerprint = stable_fingerprint(dedupe)
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key=dedupe,
        payload={"payloadDigest": "a" * 64},
        status="CLEARED",
        created_at="2026-08-19T04:00:00Z",
        cleared_at="2026-08-19T04:02:00Z",
        clear_payload={"clearPayloadDigest": "b" * 64},
    )
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key=f"snapshot:{fingerprint}",
        payload={"payloadDigest": "a" * 64},
        status="CLEARED",
        created_at="2026-08-19T04:00:00Z",
        cleared_at="2026-08-19T04:03:00Z",
        clear_payload={"clearPayloadDigest": "c" * 64},
    )

    with pytest.raises(ValueError, match="conflicting cleared task quarantine"):
        export_snapshot(database, tmp_path / "cleared-conflict.snapshot.gz")


def test_task_quarantine_import_rejects_conflicting_active_local_row(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-import-active-source.sqlite3")
    key = "owner/repo#85"
    reason = "PR_FOLLOWUP_REBIND_REQUIRED"
    dedupe = "/Users/oxygen/private/import-active-conflict"
    fingerprint = stable_fingerprint(dedupe)
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason=reason,
        dedupe_key=dedupe,
        payload={"wakeDigest": "a" * 64, "reservationPending": True},
        observed_at="2026-08-19T04:00:00Z",
    )
    snapshot_path = tmp_path / "import-active-conflict.snapshot.gz"
    export_snapshot(source, snapshot_path)
    target, _ = ledger_at(tmp_path, "quarantine-import-active-target.sqlite3")
    insert_task_quarantine_row(
        target,
        opportunity_key=key,
        reason=reason,
        dedupe_key=f"snapshot:{fingerprint}",
        payload={"wakeDigest": "b" * 64, "reservationPending": True},
        created_at="2026-08-19T04:00:00Z",
    )

    with pytest.raises(ValueError, match="conflicts with local active"):
        import_snapshot(target, snapshot_path)


def test_task_quarantine_import_rejects_conflicting_cleared_local_row(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-import-cleared-source.sqlite3")
    key = "owner/repo#86"
    reason = "LEGACY_RESULT_REQUIRES_MIGRATION"
    dedupe = "/Users/oxygen/private/import-cleared-conflict"
    fingerprint = stable_fingerprint(dedupe)
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason=reason,
        dedupe_key=dedupe,
        payload={"wakeDigest": "c" * 64},
        observed_at="2026-08-19T04:10:00Z",
    )
    ledger.clear_task_quarantine(
        key,
        reason=reason,
        evidence={"revalidated": True, "review": "source"},
        observed_at="2026-08-19T04:11:00Z",
    )
    snapshot_path = tmp_path / "import-cleared-conflict.snapshot.gz"
    export_snapshot(source, snapshot_path)
    target, _ = ledger_at(tmp_path, "quarantine-import-cleared-target.sqlite3")
    insert_task_quarantine_row(
        target,
        opportunity_key=key,
        reason=reason,
        dedupe_key=f"snapshot:{fingerprint}",
        payload={"payloadDigest": "d" * 64},
        status="CLEARED",
        created_at="2026-08-19T04:10:00Z",
        cleared_at="2026-08-19T04:12:00Z",
        clear_payload={"clearPayloadDigest": "e" * 64},
    )

    with pytest.raises(ValueError, match="conflicts with local cleared"):
        import_snapshot(target, snapshot_path)


def test_task_quarantine_export_uses_active_payload_and_keeps_distinct_identities(
    tmp_path,
):
    database, ledger = ledger_at(tmp_path, "quarantine-active-payload-source.sqlite3")
    key = "owner/repo#87"
    reason = "PR_FOLLOWUP_REBIND_REQUIRED"
    dedupe = "/Users/oxygen/private/active-payload"
    fingerprint = stable_fingerprint(dedupe)
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key=dedupe,
        payload={"payloadDigest": "a" * 64},
        status="CLEARED",
        created_at="2026-08-19T04:20:00Z",
        cleared_at="2026-08-19T04:21:00Z",
        clear_payload={"clearPayloadDigest": "b" * 64},
    )
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key="/Users/oxygen/private/distinct-active-payload",
        payload={"wakeDigest": "1" * 64, "reservationPending": True},
        created_at="2026-08-19T04:22:00Z",
    )
    active_payload = {"wakeDigest": "f" * 64, "reservationPending": True}
    insert_task_quarantine_row(
        database,
        opportunity_key=key,
        reason=reason,
        dedupe_key=f"snapshot:{fingerprint}",
        payload=active_payload,
        created_at="2026-08-19T04:23:00Z",
    )

    active = ledger.active_task_quarantine(key)
    snapshot_path = tmp_path / "active-payload.snapshot.gz"
    export_snapshot(database, snapshot_path)
    rows = read_snapshot(snapshot_path)["rows"]["taskQuarantines"]

    assert len(rows) == 2
    active_row = next(row for row in rows if row["dedupeFingerprint"] == fingerprint)
    assert active["payload"] == active_payload
    assert active_row["payload"]["wakeDigest"] == active["payload"]["wakeDigest"]
    assert active_row["payload"]["reservationPending"] is True
    assert {row["dedupeFingerprint"] for row in rows} == {
        fingerprint,
        stable_fingerprint("/Users/oxygen/private/distinct-active-payload"),
    }


def test_task_quarantine_snapshot_cleared_rows_do_not_clear_local_active_rows(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-cleared-source.sqlite3")
    key = "owner/repo#88"
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=88,
        issue_url="https://github.com/owner/repo/issues/88",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    dedupe = "/Users/oxygen/private/cleared"
    fingerprint = stable_fingerprint(dedupe)
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key=dedupe,
        payload={"wakeDigest": "d" * 64},
        observed_at="2026-08-19T02:00:00Z",
    )
    ledger.clear_task_quarantine(
        key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        evidence={"revalidated": True, "review": "ok"},
        observed_at="2026-08-19T02:01:00Z",
    )
    snapshot_path = tmp_path / "cleared.snapshot.gz"
    export_snapshot(source, snapshot_path)

    target, target_ledger = ledger_at(tmp_path, "quarantine-cleared-target.sqlite3")
    target_ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=88,
        issue_url="https://github.com/owner/repo/issues/88",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    target_ledger.record_task_quarantine(
        opportunity_key=key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key=f"snapshot:{fingerprint}",
        payload={"wakeDigest": "e" * 64},
        observed_at="2026-08-19T03:00:00Z",
    )
    import_snapshot(target, snapshot_path)
    with ManagedLedger(target)._connection() as connection:
        rows = connection.execute(
            "SELECT status,payload_json FROM task_quarantines WHERE opportunity_key=?",
            (key,),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["status"] == "ACTIVE"
    assert json.loads(rows[0]["payload_json"])["wakeDigest"] == "e" * 64


def test_task_quarantine_snapshot_active_row_reisolates_local_cleared_row(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-active-source.sqlite3")
    key = "owner/repo#89"
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=89,
        issue_url="https://github.com/owner/repo/issues/89",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    dedupe = "/Users/oxygen/private/reactivated"
    fingerprint = stable_fingerprint(dedupe)
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        dedupe_key=dedupe,
        payload={"wakeDigest": "a" * 64, "reservationPending": True},
        observed_at="2026-08-19T03:10:00Z",
    )
    snapshot_path = tmp_path / "active-priority.snapshot.gz"
    export_snapshot(source, snapshot_path)

    target, _ = ledger_at(tmp_path, "quarantine-active-priority-target.sqlite3")
    with ManagedLedger(target)._connection() as connection:
        connection.execute(
            """INSERT INTO task_quarantines
               (opportunity_key,reason,dedupe_key,payload_json,status,created_at,cleared_at,clear_payload_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                key,
                "PR_FOLLOWUP_REBIND_REQUIRED",
                f"snapshot:{fingerprint}",
                canonical_json({"wakeDigest": "b" * 64}),
                "CLEARED",
                "2026-08-19T03:00:00Z",
                "2026-08-19T03:05:00Z",
                canonical_json({"revalidated": True}),
            ),
        )

    import_snapshot(target, snapshot_path)
    with ManagedLedger(target)._connection() as connection:
        row = connection.execute(
            "SELECT status,payload_json,cleared_at,clear_payload_json FROM task_quarantines "
            "WHERE opportunity_key=? AND reason=? AND dedupe_key=?",
            (key, "PR_FOLLOWUP_REBIND_REQUIRED", f"snapshot:{fingerprint}"),
        ).fetchone()
    assert row["status"] == "ACTIVE"
    assert json.loads(row["payload_json"])["wakeDigest"] == "a" * 64
    assert row["cleared_at"] is None
    assert row["clear_payload_json"] is None


def test_task_quarantine_snapshot_rejects_conflicting_cleared_when_both_sides_cleared(
    tmp_path,
):
    source, ledger = ledger_at(tmp_path, "quarantine-both-cleared-source.sqlite3")
    key = "owner/repo#90"
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=90,
        issue_url="https://github.com/owner/repo/issues/90",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    dedupe = "/Users/oxygen/private/both-cleared"
    fingerprint = stable_fingerprint(dedupe)
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key=dedupe,
        payload={"wakeDigest": "c" * 64},
        observed_at="2026-08-19T03:20:00Z",
    )
    ledger.clear_task_quarantine(
        key,
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        evidence={"revalidated": True},
        observed_at="2026-08-19T03:21:00Z",
    )
    snapshot_path = tmp_path / "both-cleared.snapshot.gz"
    export_snapshot(source, snapshot_path)

    target, _ = ledger_at(tmp_path, "quarantine-both-cleared-target.sqlite3")
    with ManagedLedger(target)._connection() as connection:
        connection.execute(
            """INSERT INTO task_quarantines
               (opportunity_key,reason,dedupe_key,payload_json,status,created_at,cleared_at,clear_payload_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                key,
                "LEGACY_RESULT_REQUIRES_MIGRATION",
                f"snapshot:{fingerprint}",
                canonical_json({"wakeDigest": "d" * 64}),
                "CLEARED",
                "2026-08-19T03:00:00Z",
                "2026-08-19T03:05:00Z",
                canonical_json({"clearPayloadDigest": "e" * 64}),
            ),
        )

    with pytest.raises(ValueError, match="conflicts with local cleared"):
        import_snapshot(target, snapshot_path)


def test_importing_legacy_v7_snapshot_upgrades_only_exact_old_shape(tmp_path):
    source, _ = populated_source(tmp_path, "legacy-v7-source.sqlite3")
    snapshot = legacy_v7_snapshot(source)
    validate_snapshot(snapshot, allow_legacy=True)
    with pytest.raises(ValueError, match="legacy"):
        validate_snapshot(snapshot)

    snapshot_path = tmp_path / "legacy-v7.snapshot.gz"
    write_snapshot(snapshot_path, snapshot)
    with pytest.raises(ValueError, match="legacy"):
        decode_snapshot(snapshot_path.read_bytes())
    target, _ = ledger_at(tmp_path, "legacy-v7-target.sqlite3")
    import_snapshot(target, snapshot_path)
    assert schema_status(target)["current"] == MANAGED_SCHEMA_VERSION
    with ManagedLedger(target)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 0

    extra = json.loads(gzip.decompress(snapshot_path.read_bytes()))
    extra["rows"]["unexpectedRows"] = []
    extra["contentDigest"] = _digest(extra["rows"])
    resign_snapshot(extra)
    extra_path = tmp_path / "legacy-extra.snapshot.gz"
    write_snapshot(extra_path, extra)
    with pytest.raises(ValueError, match="row shape"):
        import_snapshot(tmp_path / "legacy-extra-target.sqlite3", extra_path)

    wrong_digest = json.loads(gzip.decompress(snapshot_path.read_bytes()))
    wrong_digest["managedSchemaDigest"] = (
        "02ea3f38a042c2c48ad61089777d9cf0817190f413270b74010e64a5a860e360"
    )
    resign_snapshot(wrong_digest)
    wrong_digest_path = tmp_path / "legacy-wrong-digest.snapshot.gz"
    write_snapshot(wrong_digest_path, wrong_digest)
    with pytest.raises(ValueError, match="unsupported|mismatch"):
        import_snapshot(tmp_path / "legacy-wrong-digest.sqlite3", wrong_digest_path)


def test_current_snapshot_requires_exact_row_collections(tmp_path):
    source, _ = populated_source(tmp_path, "current-row-shape-source.sqlite3")
    snapshot = build_snapshot(source)

    extra = json.loads(json.dumps(snapshot))
    extra["rows"]["futureRows"] = []
    extra["contentDigest"] = _digest(extra["rows"])
    resign_snapshot(extra)
    with pytest.raises(ValueError, match="row shape"):
        validate_snapshot(extra)

    missing = json.loads(json.dumps(snapshot))
    missing["rows"].pop("taskQuarantines")
    missing["contentDigest"] = _digest(missing["rows"])
    resign_snapshot(missing)
    with pytest.raises(ValueError, match="row shape"):
        validate_snapshot(missing)


def test_snapshot_rejects_quarantine_shape_drift_and_duplicates(tmp_path):
    source, ledger = ledger_at(tmp_path, "quarantine-shape.sqlite3")
    key = "owner/repo#99"
    ledger.upsert_opportunity(
        opportunity_key=key,
        owner="owner",
        repo="repo",
        issue_number=99,
        issue_url="https://github.com/owner/repo/issues/99",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
    )
    ledger.record_task_quarantine(
        opportunity_key=key,
        reason="PR_FOLLOWUP_REBIND_REQUIRED",
        dedupe_key="dedupe-99",
        payload={"wakeDigest": "f" * 64},
        observed_at="2026-08-19T04:00:00Z",
    )
    snapshot = build_snapshot(source)

    extra_field = json.loads(json.dumps(snapshot))
    extra_field["rows"]["taskQuarantines"][0]["futureField"] = True
    extra_field["contentDigest"] = _digest(extra_field["rows"])
    resign_snapshot(extra_field)
    with pytest.raises(ValueError, match="row shape"):
        validate_snapshot(extra_field)

    bad_active = json.loads(json.dumps(snapshot))
    bad_active["rows"]["taskQuarantines"][0]["clearedAt"] = "2026-08-19T04:01:00Z"
    bad_active["contentDigest"] = _digest(bad_active["rows"])
    resign_snapshot(bad_active)
    with pytest.raises(ValueError, match="active quarantine clear fields"):
        validate_snapshot(bad_active)

    bad_time = json.loads(json.dumps(snapshot))
    bad_time["rows"]["taskQuarantines"][0]["createdAt"] = "2026-08-19T04:00:00"
    bad_time["contentDigest"] = _digest(bad_time["rows"])
    resign_snapshot(bad_time)
    with pytest.raises(ValueError, match="missing timezone"):
        validate_snapshot(bad_time)

    duplicate = json.loads(json.dumps(snapshot))
    duplicate["rows"]["taskQuarantines"].append(dict(duplicate["rows"]["taskQuarantines"][0]))
    duplicate["contentDigest"] = _digest(duplicate["rows"])
    resign_snapshot(duplicate)
    with pytest.raises(ValueError, match="duplicate quarantine"):
        validate_snapshot(duplicate)


def test_v6_to_current_downgrades_authorization_and_requires_new_attestation(tmp_path):
    source, ledger = populated_source(tmp_path, "v6-source.sqlite3")
    with ledger._connection() as connection:
        connection.execute("DELETE FROM managed_schema_migrations WHERE version>=7")
        connection.execute(
            "INSERT INTO managed_schema_migrations(version,applied_at,migration_digest) VALUES (6, '2026-08-19T00:00:00Z', 'legacy-v6')"
        )
    assert schema_status(source)["current"] == 6
    target = tmp_path / "current-target.sqlite3"
    snapshot = tmp_path / "current.snapshot.gz"
    result = migrate_v6_to_v7(source, target, snapshot_output=snapshot)
    assert result["toVersion"] == MANAGED_SCHEMA_VERSION
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
        connection.execute("DELETE FROM managed_schema_migrations WHERE version>=7")
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
