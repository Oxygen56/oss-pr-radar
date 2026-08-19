from __future__ import annotations

import gzip
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_ledger import legal_publication_probe

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    PublicationAbsenceReconciler,
    _digest,
    validation_certificate,
    verify_validation_certificate,
    verify_validation_certificate_history,
)
from oss_pr_radar.managed_security import stable_fingerprint
from oss_pr_radar.managed_snapshot import (
    build_snapshot,
    export_snapshot,
    import_snapshot,
    validate_snapshot,
)
from oss_pr_radar.util import canonical_json

pytestmark = pytest.mark.usefixtures("current_signing_key")


@pytest.fixture(autouse=True)
def disable_host_keychain(monkeypatch):
    monkeypatch.setattr("oss_pr_radar.managed_security._keychain_current_key", lambda: None)


def make_ledger(tmp_path, name="ledger.sqlite3"):
    path = tmp_path / name
    RadarLedger(path)
    return path, ManagedLedger(path, ensure_schema=True)


class AbsentGithub:
    def __init__(self):
        self.calls = []

    def query_branch(self, repo, head_ref):
        self.calls.append(("branch", repo, head_ref))
        return {"exists": False, "result": "404"}

    def query_commit(self, repo, head_sha):
        self.calls.append(("commit", repo, head_sha))
        return {"exists": False, "result": "404"}

    def query_pull_request(self, repo, head_ref, head_sha):
        self.calls.append(("pr", repo, head_ref, head_sha))
        return {"exists": False, "result": "empty"}


def reserve_expired(ledger, *, reservation_key="publication:round5"):
    ledger.reserve_publication_slot(
        reservation_key=reservation_key,
        request_id=reservation_key,
        repo="owner/repo",
        head_ref="feature/round5",
        head_sha="head-round5",
        idempotency_key=reservation_key,
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    assert ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z") == 1


def test_slow_reconciler_signs_exact_absence_and_releases(tmp_path):
    _, ledger = make_ledger(tmp_path)
    reserve_expired(ledger)
    github = AbsentGithub()

    result = PublicationAbsenceReconciler(ledger, github, now="2026-08-19T00:02:00Z").reconcile(
        reservation_key="publication:round5",
        repo="owner/repo",
        head_ref="feature/round5",
        head_sha="head-round5",
    )

    assert result["released"] is True
    assert [call[0] for call in github.calls] == ["branch", "commit", "pr"]
    with ledger._connection() as connection:
        row = connection.execute(
            "SELECT * FROM managed_publication_absence_attestations"
        ).fetchone()
        assert row["signer_key_id"] == "test-current"
        assert row["signature"]


def test_absence_reconciler_uncertainty_and_false_bindings_fail_closed(tmp_path):
    _, ledger = make_ledger(tmp_path, "uncertain.sqlite3")
    reserve_expired(ledger, reservation_key="publication:uncertain")

    class FailingGithub(AbsentGithub):
        def query_commit(self, repo, head_sha):
            raise RuntimeError("rate limited")

    uncertain = PublicationAbsenceReconciler(
        ledger, FailingGithub(), now="2026-08-19T00:02:00Z"
    ).reconcile(
        reservation_key="publication:uncertain",
        repo="owner/repo",
        head_ref="feature/round5",
        head_sha="head-round5",
    )
    assert uncertain["state"] == "WAITING_EXTERNAL"

    with pytest.raises(ValueError, match="binding"):
        ledger.create_absence_attestation(
            reservation_key="publication:uncertain",
            repo="other/repo",
            head_ref="feature/round5",
            head_sha="head-round5",
            queries=[],
            local_effect={"ok": True, "exists": False},
            observed_at="2026-08-19T00:02:00Z",
        )


def test_attestation_wrong_endpoint_tamper_stale_and_replay_are_rejected(tmp_path):
    _, ledger = make_ledger(tmp_path, "attestation-adversarial.sqlite3")
    reserve_expired(ledger, reservation_key="publication:adversarial")
    queries = [
        {"endpoint": "wrong/branch", "ok": True, "exists": False},
        {
            "endpoint": "repos/owner/repo/git/commits/head-round5",
            "ok": True,
            "exists": False,
        },
        {
            "endpoint": "repos/owner/repo/pulls?head=owner:feature/round5&state=all",
            "ok": True,
            "exists": False,
        },
    ]
    attestation = ledger.create_absence_attestation(
        reservation_key="publication:adversarial",
        repo="owner/repo",
        head_ref="feature/round5",
        head_sha="head-round5",
        queries=queries,
        local_effect={"endpoint": "local:publication_effects", "ok": True, "exists": False},
        observed_at="2026-08-19T00:02:00Z",
    )
    with pytest.raises(PermissionError):
        ledger.apply_absence_attestation(attestation, now="2026-08-19T00:02:01Z")

    reserve_expired(ledger, reservation_key="publication:stale")
    stale = ledger.create_absence_attestation(
        reservation_key="publication:stale",
        repo="owner/repo",
        head_ref="feature/round5",
        head_sha="head-round5",
        queries=[
            {"endpoint": "repos/owner/repo/branches/feature/round5", "ok": True, "exists": False},
            {"endpoint": "repos/owner/repo/git/commits/head-round5", "ok": True, "exists": False},
            {
                "endpoint": "repos/owner/repo/pulls?head=owner:feature/round5&state=all",
                "ok": True,
                "exists": False,
            },
        ],
        local_effect={"endpoint": "local:publication_effects", "ok": True, "exists": False},
        observed_at="2026-08-19T00:02:00Z",
    )
    with pytest.raises(PermissionError, match="stale"):
        ledger.apply_absence_attestation(stale, now="2026-08-19T00:20:00Z")

    released = PublicationAbsenceReconciler(
        ledger, AbsentGithub(), now="2026-08-19T00:03:00Z"
    ).reconcile(
        reservation_key="publication:stale",
        repo="owner/repo",
        head_ref="feature/round5",
        head_sha="head-round5",
    )
    assert released["released"] is True
    with ledger._connection() as connection:
        stored = dict(
            connection.execute(
                "SELECT * FROM managed_publication_absence_attestations WHERE reservation_key=?",
                ("publication:stale",),
            ).fetchone()
        )
    replay = {
        "schema": "absence_attestation_v1",
        "attestationId": stored["attestation_id"],
        "reservationKey": stored["reservation_key"],
        "repo": stored["repo"],
        "headRef": stored["head_ref"],
        "headSha": stored["head_sha"],
        "queries": json.loads(stored["query_json"]),
        "localEffect": json.loads(stored["local_effect_json"]),
        "observedAt": stored["observed_at"],
        "policy": stored["policy_version"],
        "nonce": stored["nonce"],
        "createdAt": stored["created_at"],
        "contentDigest": stored["content_digest"],
        "signerKeyId": stored["signer_key_id"],
        "signature": stored["signature"],
        "authenticationStatus": stored["authentication_status"],
    }
    replayed = ledger.apply_absence_attestation(replay, now="2026-08-19T00:03:01Z")
    assert replayed["reason"] == "REPLAY_REJECTED"


def test_validation_certificate_context_key_rotation_and_missing_key(monkeypatch, tmp_path):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "round5-current-key-aaaaaaaa")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "round5-current")
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS", raising=False)
    cert = validation_certificate(
        {"passed": True, "evidence": ["pytest:round5"]},
        result_key="task|owner/repo#1|head|digest",
        result_digest="digest",
        commit_sha="commit",
        head_sha="head",
        ci_status="PASSED",
        observed_at="2026-08-19T00:00:00Z",
    )
    assert verify_validation_certificate(cert)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "round5-next-key-bbbbbbbb")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "round5-next")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS", "round5-current-key-aaaaaaaa")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS_ID", "round5-current")
    assert verify_validation_certificate(cert) is False
    assert verify_validation_certificate_history(cert) is True
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS")
    assert not verify_validation_certificate(cert)

    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY")
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY_ID")
    with pytest.raises(PermissionError, match="certificate signing key"):
        validation_certificate(
            {"passed": True, "evidence": ["pytest:unsigned"]},
            result_key="task|owner/repo#2|head|digest",
            result_digest="digest",
        )


def test_sensitive_idempotency_fingerprint_survives_snapshot_and_raw_replay(tmp_path):
    source, ledger = make_ledger(tmp_path, "source-sensitive.sqlite3")
    raw_key = "thread:private/worktree:/Users/oxygen/private/file:test.py"
    first = ledger.record_event(event_type="THREAD_OBSERVED", idempotency_key=raw_key)
    assert first["created"] is True
    snapshot = tmp_path / "managed.snapshot.gz"
    export_snapshot(source, snapshot)
    target, restored = make_ledger(tmp_path, "target-sensitive.sqlite3")
    import_snapshot(target, snapshot)
    replay = restored.record_event(event_type="THREAD_OBSERVED", idempotency_key=raw_key)
    assert replay["created"] is False
    with restored._connection() as connection:
        row = connection.execute("SELECT * FROM managed_lifecycle_events").fetchone()
        assert row["idempotency_fingerprint"] == stable_fingerprint(raw_key)
        assert (
            connection.execute("SELECT COUNT(*) FROM managed_lifecycle_events").fetchone()[0] == 1
        )
    assert raw_key not in snapshot.read_bytes().decode("latin1", errors="ignore")


def test_full_certified_reply_and_reservation_restore_is_authorized(tmp_path):
    source, ledger = make_ledger(tmp_path, "source-full.sqlite3")
    reservation = ledger.reserve_publication_slot(
        reservation_key="publication:full",
        request_id="request:full",
        repo="owner/repo",
        head_ref="feature/full",
        head_sha="head-full",
        idempotency_key="publication:full",
        now="2026-08-19T00:00:00Z",
    )
    assert reservation["allowed"] is True
    ledger.upsert_pr(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha="head-full",
        pr_url="https://github.com/owner/repo/pull/9",
        state="OPEN",
        auto_created=True,
        reservation_key="publication:full",
    )
    ledger.bind_task(
        task_id="task-full",
        opportunity_key="owner/repo#9",
        thread_id="task-full",
        worktree_path=None,
        state="REPRODUCTION_REQUIRED",
    )
    _worktree, _base_sha, _head_sha, _branch, probe_receipt, _probe_digest, _evidence = (
        legal_publication_probe(
            tmp_path,
            owner_repo="owner/repo",
            issue_number=9,
            task_id="task-full",
        )
    )
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#9",
        owner="owner",
        repo="repo",
        issue_number=9,
        issue_url="https://github.com/owner/repo/issues/9",
        state="SYSTEM_PROCESSING",
        source="test-legal-fixture",
        provenance={"fixture": True},
        metadata={"selectedBaseSha": probe_receipt["baseSha"], "codePaths": ["runtime.py"]},
    )
    ledger.bind_task(
        task_id="task-full",
        opportunity_key="owner/repo#9",
        thread_id="task-full",
        worktree_path=None,
        state="REPRODUCTION_REQUIRED",
        provenance={
            "codePaths": ["runtime.py"],
            "selectedBaseSha": probe_receipt["baseSha"],
            "headSha": probe_receipt["headSha"],
            "commitSha": probe_receipt["commitSha"],
            "resultDigest": probe_receipt["resultDigest"],
        },
    )
    ledger.transition_task_to_implementation(
        task_id="task-full", receipt_digest=probe_receipt["receiptDigest"], receipt=probe_receipt
    )
    result = ledger.record_result(
        task_id="task-full",
        result_digest="result-full",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#9",
        head_sha="head-full",
        commit_sha="commit-full",
        validation={"passed": True, "evidence": ["pytest:full"]},
        prior_head_sha="old-head",
        new_head_sha="head-full",
    )
    assert result["advanced"] is True
    ledger.record_ci_run(
        ci_key="ci-full", pr_key="owner/repo#9", head_sha="head-full", status="PASSED"
    )
    ledger.record_maintainer_event(
        event_key="event-full",
        pr_key="owner/repo#9",
        event_type="COMMENT",
        actor_login="maintainer",
        actor_type="User",
        author_association="OWNER",
        payload={"explicit_mechanical_request": True, "targetPrKey": "owner/repo#9"},
    )
    queued = ledger.queue_public_reply(
        pr_key="owner/repo#9",
        maintainer_event_key="event-full",
        result_digest="result-full",
        proposed_body="Fixed as requested.",
    )
    assert queued["mode"] == "AUTO_REPLY_ALLOWED"
    snapshot = tmp_path / "full.snapshot.gz"
    export_snapshot(source, snapshot)

    target, restored = make_ledger(tmp_path, "target-full.sqlite3")
    import_snapshot(target, snapshot)
    projection = restored.projection()
    assert projection["buckets"]["PORTFOLIO_READY"]
    assert projection["buckets"]["WAITING_EXTERNAL"] == []
    with restored._connection() as connection:
        reply = connection.execute("SELECT * FROM managed_public_replies").fetchone()
        delivery = connection.execute("SELECT * FROM managed_reply_deliveries").fetchone()
        reservation_row = connection.execute(
            "SELECT state,head_ref,head_sha FROM managed_publication_reservations WHERE reservation_key='publication:full'"
        ).fetchone()
        assert reply["body"] == "Fixed as requested."
        assert reply["body_digest"] == _digest(reply["body"])
        assert delivery["state"] == "QUEUED"
        assert tuple(reservation_row) == ("ACTIVE", "feature/full", "head-full")


def _absence_attestation(ledger, reservation_key, *, observed_at, nonce, query_ok=True):
    return ledger.create_absence_attestation(
        reservation_key=reservation_key,
        repo="owner/repo",
        head_ref="feature/nonce",
        head_sha="head-nonce",
        nonce=nonce,
        queries=[
            {
                "endpoint": "repos/owner/repo/branches/feature/nonce",
                "ok": query_ok,
                "exists": False,
            },
            {
                "endpoint": "repos/owner/repo/git/commits/head-nonce",
                "ok": query_ok,
                "exists": False,
            },
            {
                "endpoint": "repos/owner/repo/pulls?head=owner:feature/nonce&state=all",
                "ok": query_ok,
                "exists": False,
            },
        ],
        local_effect={"endpoint": "local:publication_effects", "ok": query_ok, "exists": False},
        observed_at=observed_at,
    )


def test_snapshot_rejects_unsigned_self_consistent_certificate(tmp_path):
    source, ledger = make_ledger(tmp_path, "forged-cert.sqlite3")
    ledger.bind_task(
        task_id="task-cert", opportunity_key="owner/repo#1", thread_id=None, worktree_path=None
    )
    ledger.record_result(
        task_id="task-cert",
        result_digest="result-cert",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#1",
        head_sha="head-cert",
        commit_sha="commit-cert",
        validation={"passed": True, "evidence": ["pytest:cert"]},
        prior_head_sha="old-cert",
        new_head_sha="head-cert",
    )
    snapshot = build_snapshot(source)
    result = snapshot["rows"]["results"][0]
    certificate = dict(result["validationCertificate"])
    certificate["keyId"] = None
    certificate["signature"] = None
    certificate["contentDigest"] = _digest(
        {
            key: value
            for key, value in certificate.items()
            if key not in {"contentDigest", "keyId", "signature"}
        }
    )
    result["validationCertificate"] = certificate
    snapshot["contentDigest"] = _digest(snapshot["rows"])
    with pytest.raises(ValueError, match="authentication"):
        validate_snapshot(snapshot)
    forged_path = tmp_path / "forged.snapshot.gz"
    forged_path.write_bytes(gzip.compress(canonical_json(snapshot).encode("utf-8"), mtime=0))
    target, _ = make_ledger(tmp_path, "forged-target.sqlite3")
    with pytest.raises(ValueError, match="authentication"):
        import_snapshot(target, forged_path)


def test_attestation_migration_removes_v6_single_reservation_constraint(tmp_path):
    _, ledger = make_ledger(tmp_path, "attestation-migration.sqlite3")
    with ledger._connection() as connection:
        connection.execute(
            "CREATE UNIQUE INDEX legacy_v6_attestation_reservation ON managed_publication_absence_attestations(reservation_key)"
        )
    from oss_pr_radar.managed_lifecycle import migrate_schema

    migrate_schema(ledger.path)
    ledger.reserve_publication_slot(
        reservation_key="publication:versions",
        request_id="request:versions",
        repo="owner/repo",
        head_ref="feature/nonce",
        head_sha="head-nonce",
        idempotency_key="publication:versions",
        now="2026-08-19T00:00:00Z",
    )
    _absence_attestation(
        ledger,
        "publication:versions",
        observed_at="2026-08-19T00:00:00Z",
        nonce="version-1",
    )
    _absence_attestation(
        ledger,
        "publication:versions",
        observed_at="2026-08-19T00:00:01Z",
        nonce="version-2",
    )
    with ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_publication_absence_attestations WHERE reservation_key='publication:versions'"
            ).fetchone()[0]
            == 2
        )


def test_snapshot_allows_explicit_unauthenticated_result_but_never_ready(tmp_path):
    source, ledger = make_ledger(tmp_path, "ordinary-result.sqlite3")
    ledger.bind_task(
        task_id="task-ordinary", opportunity_key="owner/repo#2", thread_id=None, worktree_path=None
    )
    ledger.record_result(
        task_id="task-ordinary",
        result_digest="queued-result",
        worker_state="skipped",
        result_type="task_no_go",
    )
    snapshot = build_snapshot(source)
    ordinary = snapshot["rows"]["results"][0]
    assert ordinary["validationCertificate"] is None
    assert ordinary["authenticationStatus"] == "UNAUTHENTICATED"
    validate_snapshot(snapshot)
    target, restored = make_ledger(tmp_path, "ordinary-restored.sqlite3")
    ordinary_path = tmp_path / "ordinary.snapshot.gz"
    export_snapshot(source, ordinary_path)
    import_snapshot(target, ordinary_path)
    assert restored.projection()["buckets"]["PORTFOLIO_READY"] == []


def test_nonce_consumption_is_atomic_and_cross_round_replay_is_rejected(tmp_path):
    source, ledger = make_ledger(tmp_path, "nonce-run1.sqlite3")
    ledger.reserve_publication_slot(
        reservation_key="publication:nonce",
        request_id="request:nonce",
        repo="owner/repo",
        head_ref="feature/nonce",
        head_sha="head-nonce",
        idempotency_key="publication:nonce",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z")
    attestation = _absence_attestation(
        ledger,
        "publication:nonce",
        observed_at="2026-08-19T00:02:00Z",
        nonce="nonce-fixed",
    )
    first = ledger.apply_absence_attestation(attestation, now="2026-08-19T00:02:01Z")
    assert first["released"] is True
    replay = ledger.apply_absence_attestation(attestation, now="2026-08-19T00:02:02Z")
    assert replay["reason"] == "REPLAY_REJECTED"
    with ledger._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM attestation_nonce_consumptions").fetchone()[0]
            == 1
        )

    snapshot = tmp_path / "nonce.snapshot.gz"
    export_snapshot(source, snapshot)
    target, restored = make_ledger(tmp_path, "nonce-run2.sqlite3")
    import_snapshot(target, snapshot)
    cross_round = restored.apply_absence_attestation(attestation, now="2026-08-19T00:02:03Z")
    assert cross_round["reason"] == "REPLAY_REJECTED"
    with restored._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM attestation_nonce_consumptions").fetchone()[0]
            == 1
        )


def test_nonce_consumption_waiting_tamper_rotation_and_concurrency(tmp_path, monkeypatch):
    _, ledger = make_ledger(tmp_path, "nonce-adversarial.sqlite3")
    ledger.reserve_publication_slot(
        reservation_key="publication:waiting",
        request_id="request:waiting",
        repo="owner/repo",
        head_ref="feature/nonce",
        head_sha="head-nonce",
        idempotency_key="publication:waiting",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z")
    waiting = _absence_attestation(
        ledger,
        "publication:waiting",
        observed_at="2026-08-19T00:02:00Z",
        nonce="nonce-waiting",
        query_ok=False,
    )
    waiting_result = ledger.apply_absence_attestation(waiting, now="2026-08-19T00:02:01Z")
    assert waiting_result["state"] == "WAITING_EXTERNAL"
    assert (
        ledger.apply_absence_attestation(waiting, now="2026-08-19T00:02:02Z")["reason"]
        == "REPLAY_REJECTED"
    )

    tampered = dict(waiting)
    tampered["contentDigest"] = "0" * 64
    with pytest.raises(PermissionError):
        ledger.apply_absence_attestation(tampered, now="2026-08-19T00:02:03Z")

    ledger.reserve_publication_slot(
        reservation_key="publication:rotation",
        request_id="request:rotation",
        repo="owner/repo",
        head_ref="feature/nonce",
        head_sha="head-nonce",
        idempotency_key="publication:rotation",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z")
    rotation_attestation = _absence_attestation(
        ledger,
        "publication:rotation",
        observed_at="2026-08-19T00:02:00Z",
        nonce="nonce-rotation",
    )
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "nonce-current-key-bbbbbbbb")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "nonce-current")
    monkeypatch.setenv(
        "RADAR_DISPATCH_HMAC_KEY_PREVIOUS", "managed-test-signing-key-0123456789abcdef"
    )
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS_ID", "test-current")
    with pytest.raises(PermissionError):
        ledger.apply_absence_attestation(rotation_attestation, now="2026-08-19T00:02:04Z")

    _, concurrent_ledger = make_ledger(tmp_path, "nonce-concurrent.sqlite3")
    concurrent_ledger.reserve_publication_slot(
        reservation_key="publication:concurrent",
        request_id="request:concurrent",
        repo="owner/repo",
        head_ref="feature/nonce",
        head_sha="head-nonce",
        idempotency_key="publication:concurrent",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    concurrent_ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z")
    concurrent_attestation = _absence_attestation(
        concurrent_ledger,
        "publication:concurrent",
        observed_at="2026-08-19T00:02:00Z",
        nonce="nonce-concurrent",
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _value: concurrent_ledger.apply_absence_attestation(
                    concurrent_attestation, now="2026-08-19T00:02:01Z"
                ),
                (1, 2),
            )
        )
    assert sum(result.get("released") is True for result in results) == 1
    assert sum(result.get("reason") == "REPLAY_REJECTED" for result in results) == 1
    with concurrent_ledger._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM attestation_nonce_consumptions").fetchone()[0]
            == 1
        )
