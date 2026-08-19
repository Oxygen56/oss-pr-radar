from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
from test_managed_round7_security import populated_source

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    _attestation_authenticated,
    migrate_v6_to_v7,
    validation_certificate,
    verify_validation_certificate,
    verify_validation_certificate_history,
)
from oss_pr_radar.managed_security import (
    sign_current,
    verify_current_or_previous,
)
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot, inspect_snapshot

pytestmark = pytest.mark.usefixtures("current_signing_key")


@pytest.fixture(autouse=True)
def disable_host_keychain(monkeypatch):
    monkeypatch.setattr("oss_pr_radar.managed_security._keychain_current_key", lambda: None)

CURRENT_ENV = "RADAR_DISPATCH_HMAC_KEY"
CURRENT_ID_ENV = "RADAR_DISPATCH_HMAC_KEY_ID"
PREVIOUS_ENV = "RADAR_DISPATCH_HMAC_KEY_PREVIOUS"
PREVIOUS_ID_ENV = "RADAR_DISPATCH_HMAC_KEY_PREVIOUS_ID"
ORIGINAL_KEY = "managed-test-signing-key-0123456789abcdef"
ORIGINAL_ID = "test-current"


def _reserve_and_expire(ledger: ManagedLedger, reservation_key: str) -> None:
    ledger.reserve_publication_slot(
        reservation_key=reservation_key,
        request_id=f"request:{reservation_key}",
        repo="owner/repo",
        head_ref=f"feature/{reservation_key}",
        head_sha=f"head:{reservation_key}",
        idempotency_key=reservation_key,
        lease_seconds=30,
        now="2026-08-19T01:00:00Z",
    )
    ledger.expire_publication_reservations(now="2026-08-19T01:01:00Z")


def _absence(ledger: ManagedLedger, reservation_key: str, *, nonce: str) -> dict:
    return ledger.create_absence_attestation(
        reservation_key=reservation_key,
        repo="owner/repo",
        head_ref=f"feature/{reservation_key}",
        head_sha=f"head:{reservation_key}",
        queries=[
            {
                "endpoint": f"repos/owner/repo/branches/feature/{reservation_key}",
                "ok": True,
                "exists": False,
            },
            {
                "endpoint": f"repos/owner/repo/git/commits/head:{reservation_key}",
                "ok": True,
                "exists": False,
            },
            {
                "endpoint": "repos/owner/repo/pulls?state=all",
                "ok": True,
                "exists": False,
            },
        ],
        local_effect={"endpoint": "local:publication_effects", "ok": True, "exists": False},
        observed_at="2026-08-19T01:02:00Z",
        nonce=nonce,
    )


def _mark_v6(database: Path) -> None:
    with ManagedLedger(database)._connection() as connection:
        connection.execute("DELETE FROM managed_schema_migrations WHERE version=7")
        connection.execute(
            "INSERT INTO managed_schema_migrations(version,applied_at,migration_digest) "
            "VALUES (6, '2026-08-19T00:00:00Z', 'legacy-v6')"
        )


def test_security_api_signs_current_only_and_verifies_previous(monkeypatch):
    payload = {"event": "historical"}
    monkeypatch.setenv(CURRENT_ENV, ORIGINAL_KEY)
    monkeypatch.setenv(CURRENT_ID_ENV, ORIGINAL_ID)
    monkeypatch.delenv(PREVIOUS_ENV, raising=False)
    historical = sign_current(payload, context="managed-snapshot-v1")
    assert historical["keyId"] == ORIGINAL_ID

    monkeypatch.setenv(CURRENT_ENV, "rotation-current-key-bbbbbbbb")
    monkeypatch.setenv(CURRENT_ID_ENV, "rotation-current")
    monkeypatch.setenv(PREVIOUS_ENV, ORIGINAL_KEY)
    monkeypatch.setenv(PREVIOUS_ID_ENV, ORIGINAL_ID)
    current = sign_current(payload, context="managed-snapshot-v1")
    assert current["keyId"] == "rotation-current"
    assert verify_current_or_previous(
        payload,
        context="managed-snapshot-v1",
        key_id=historical["keyId"],
        signature=historical["signature"],
    )

    monkeypatch.delenv(CURRENT_ENV)
    monkeypatch.delenv(CURRENT_ID_ENV)
    previous_only = sign_current(payload, context="managed-snapshot-v1")
    assert previous_only == {"keyId": None, "signature": None}
    assert verify_current_or_previous(
        payload,
        context="managed-snapshot-v1",
        key_id=historical["keyId"],
        signature=historical["signature"],
    )

    monkeypatch.delenv(PREVIOUS_ENV)
    monkeypatch.delenv(PREVIOUS_ID_ENV)
    assert not verify_current_or_previous(
        payload,
        context="managed-snapshot-v1",
        key_id=historical["keyId"],
        signature=historical["signature"],
    )


def test_snapshot_certificate_and_attestation_sign_current_with_previous_verify(
    tmp_path: Path, monkeypatch
):
    source, ledger = populated_source(tmp_path, "rotation-source.sqlite3")
    historical_snapshot = tmp_path / "historical.snapshot.gz"
    export_snapshot(source, historical_snapshot)
    historical_cert = validation_certificate(
        {"passed": True, "evidence": ["pytest:historical"]},
        result_key="task|owner/repo#1|head|historical",
        result_digest="historical",
    )
    _reserve_and_expire(ledger, "historical-attestation")
    historical_attestation = _absence(ledger, "historical-attestation", nonce="historical-nonce")
    assert historical_cert["keyId"] == ORIGINAL_ID
    assert historical_attestation["signerKeyId"] == ORIGINAL_ID

    monkeypatch.setenv(CURRENT_ENV, "rotation-current-key-bbbbbbbb")
    monkeypatch.setenv(CURRENT_ID_ENV, "rotation-current")
    monkeypatch.setenv(PREVIOUS_ENV, ORIGINAL_KEY)
    monkeypatch.setenv(PREVIOUS_ID_ENV, ORIGINAL_ID)

    current_cert = validation_certificate(
        {"passed": True, "evidence": ["pytest:current"]},
        result_key="task|owner/repo#1|head|current",
        result_digest="current",
    )
    assert current_cert["keyId"] == "rotation-current"
    assert verify_validation_certificate(historical_cert) is False
    assert verify_validation_certificate_history(historical_cert) is True

    _reserve_and_expire(ledger, "current-attestation")
    current_attestation = _absence(ledger, "current-attestation", nonce="current-nonce")
    assert current_attestation["signerKeyId"] == "rotation-current"
    assert _attestation_authenticated(historical_attestation)

    rotated_snapshot = tmp_path / "rotated.snapshot.gz"
    export_snapshot(source, rotated_snapshot)
    rotated = json.loads(gzip.decompress(rotated_snapshot.read_bytes()))
    assert rotated["keyId"] == "rotation-current"

    monkeypatch.delenv(CURRENT_ENV)
    monkeypatch.delenv(CURRENT_ID_ENV)
    previous_only_target = tmp_path / "previous-only.sqlite3"
    RadarLedger(previous_only_target)
    with pytest.raises(ValueError, match="root authentication"):
        import_snapshot(previous_only_target, historical_snapshot)
    assert inspect_snapshot(historical_snapshot)["keyId"] == ORIGINAL_ID
    assert verify_validation_certificate(historical_cert) is False
    assert verify_validation_certificate_history(historical_cert) is True
    with pytest.raises(PermissionError, match="snapshot signing key"):
        export_snapshot(source, tmp_path / "forbidden.snapshot.gz")
    with pytest.raises(PermissionError, match="certificate signing key"):
        validation_certificate(
            {"passed": True, "evidence": ["pytest:new"]},
            result_key="task|owner/repo#1|head|new",
            result_digest="new",
        )
    _reserve_and_expire(ledger, "previous-only-attestation")
    with pytest.raises(PermissionError, match="attestation signing key"):
        _absence(ledger, "previous-only-attestation", nonce="previous-only-nonce")

    monkeypatch.delenv(PREVIOUS_ENV)
    monkeypatch.delenv(PREVIOUS_ID_ENV)
    with pytest.raises(PermissionError, match="snapshot signing key"):
        export_snapshot(source, tmp_path / "no-key.snapshot.gz")
    _reserve_and_expire(ledger, "no-key-attestation")
    with pytest.raises(PermissionError, match="attestation signing key"):
        _absence(ledger, "no-key-attestation", nonce="no-key-nonce")


def test_v6_migration_signing_requires_current_and_uses_current_during_rotation(
    tmp_path: Path, monkeypatch
):
    source, _ = populated_source(tmp_path, "v6-rotation-source.sqlite3")
    _mark_v6(source)

    previous_only_target = tmp_path / "previous-only-target.sqlite3"
    RadarLedger(previous_only_target)
    previous_ledger = ManagedLedger(previous_only_target, ensure_schema=True)
    previous_ledger.record_event(event_type="SENTINEL", idempotency_key="sentinel:previous")
    before_previous = previous_ledger.projection()
    monkeypatch.delenv(CURRENT_ENV)
    monkeypatch.delenv(CURRENT_ID_ENV)
    monkeypatch.setenv(PREVIOUS_ENV, ORIGINAL_KEY)
    monkeypatch.setenv(PREVIOUS_ID_ENV, ORIGINAL_ID)
    with pytest.raises(PermissionError, match="current signing key"):
        migrate_v6_to_v7(source, previous_only_target)
    assert previous_ledger.projection() == before_previous

    no_key_target = tmp_path / "no-key-target.sqlite3"
    RadarLedger(no_key_target)
    no_key_ledger = ManagedLedger(no_key_target, ensure_schema=True)
    no_key_ledger.record_event(event_type="SENTINEL", idempotency_key="sentinel:none")
    before_no_key = no_key_ledger.projection()
    monkeypatch.delenv(PREVIOUS_ENV)
    monkeypatch.delenv(PREVIOUS_ID_ENV)
    with pytest.raises(PermissionError, match="current signing key"):
        migrate_v6_to_v7(source, no_key_target)
    assert no_key_ledger.projection() == before_no_key

    rotated_target = tmp_path / "rotated-target.sqlite3"
    rotated_snapshot = tmp_path / "rotated-v7.snapshot.gz"
    monkeypatch.setenv(CURRENT_ENV, "rotation-current-key-bbbbbbbb")
    monkeypatch.setenv(CURRENT_ID_ENV, "rotation-current")
    monkeypatch.setenv(PREVIOUS_ENV, ORIGINAL_KEY)
    monkeypatch.setenv(PREVIOUS_ID_ENV, ORIGINAL_ID)
    result = migrate_v6_to_v7(source, rotated_target, snapshot_output=rotated_snapshot)
    assert result["toVersion"] == 7
    rotated = json.loads(gzip.decompress(rotated_snapshot.read_bytes()))
    assert rotated["keyId"] == "rotation-current"
