from __future__ import annotations

import gzip

import pytest
from test_ledger import legal_publication_probe

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    PublicationAbsenceReconciler,
    import_open_pr_observations,
)
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot

pytestmark = pytest.mark.usefixtures("current_signing_key")


def test_expired_reservation_requires_positive_absence_before_retry(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    ledger = ManagedLedger(database, ensure_schema=True)
    ledger.reserve_publication_slot(
        reservation_key="publication:crash",
        request_id="crash",
        repo="owner/repo",
        head_ref="feature/crash",
        head_sha="head-crash",
        idempotency_key="publication:crash",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    assert ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z") == 1
    assert (
        ledger.reserve_publication_slot(
            reservation_key="publication:crash",
            request_id="crash",
            repo="owner/repo",
            head_ref="feature/crash",
            head_sha="head-crash",
            idempotency_key="publication:crash",
            now="2026-08-19T00:01:01Z",
        )["state"]
        == "CHECK_ABSENCE_REQUIRED"
    )

    class FailingGithub:
        def query_branch(self, repo, head_ref):
            raise RuntimeError("query uncertain")

        def query_commit(self, repo, head_sha):
            return {"exists": False}

        def query_pull_request(self, repo, head_ref, head_sha):
            return {"exists": False}

    uncertain = PublicationAbsenceReconciler(
        ledger, FailingGithub(), now="2026-08-19T00:01:02Z"
    ).reconcile(
        reservation_key="publication:crash",
        repo="owner/repo",
        head_ref="feature/crash",
        head_sha="head-crash",
    )
    assert uncertain["released"] is False
    assert uncertain["state"] == "WAITING_EXTERNAL"

    class PresentGithub(FailingGithub):
        def query_branch(self, repo, head_ref):
            return {"exists": True}

    present = PublicationAbsenceReconciler(
        ledger, PresentGithub(), now="2026-08-19T00:01:02Z"
    ).reconcile(
        reservation_key="publication:crash",
        repo="owner/repo",
        head_ref="feature/crash",
        head_sha="head-crash",
    )
    assert present["released"] is False
    assert present["state"] == "RECONCILE_REQUIRED"

    class AbsentGithub:
        def query_branch(self, repo, head_ref):
            return {"exists": False}

        def query_commit(self, repo, head_sha):
            return {"exists": False}

        def query_pull_request(self, repo, head_ref, head_sha):
            return {"exists": False}

    absent = PublicationAbsenceReconciler(
        ledger, AbsentGithub(), now="2026-08-19T00:01:03Z"
    ).reconcile(
        reservation_key="publication:crash",
        repo="owner/repo",
        head_ref="feature/crash",
        head_sha="head-crash",
    )
    assert absent["released"] is True
    retry = ledger.reserve_publication_slot(
        reservation_key="publication:crash",
        request_id="crash",
        repo="owner/repo",
        head_ref="feature/crash",
        head_sha="head-crash",
        idempotency_key="publication:crash",
        now="2026-08-19T00:01:04Z",
    )
    assert retry["allowed"] is True


def test_existing_open_pr_origin_survives_followup_receipt_and_restore(tmp_path):
    database = tmp_path / "run1" / "state" / "radar_ledger.sqlite3"
    database.parent.mkdir(parents=True)
    RadarLedger(database)
    import_open_pr_observations(
        database,
        [{"url": "https://github.com/owner/repo/pull/9", "headSha": "existing-head"}],
        source="war-room-observation",
        observed_at="2026-08-19T00:00:00Z",
    )
    adapter = ManagedAdapter(database.parents[2], database)
    adapter.record_followup(
        {
            "items": [
                {
                    "key": "owner/repo#9",
                    "url": "https://github.com/owner/repo/pull/9",
                    "headSha": "followup-head",
                    "ciStatus": "PASSED",
                    "checkedAt": "2026-08-19T00:01:00Z",
                    "evidence": {"failingChecks": [], "requestedChanges": []},
                }
            ]
        },
        {"run_id": "followup-1"},
    )
    _worktree, base_sha, head_sha, _branch, probe_receipt, result_digest, _evidence_path = (
        legal_publication_probe(
            tmp_path,
            owner_repo="owner/repo",
            issue_number=9,
            task_id="existing-update",
        )
    )
    adapter.record_publication_receipt(
        request={
            "publicationKind": "PR_UPDATE",
            "requestId": "existing-update",
            "issueUrl": "https://github.com/owner/repo/issues/9",
            "taskId": "existing-update",
            "commitSha": head_sha,
            "headSha": head_sha,
            "selectedBaseSha": base_sha,
            "codePaths": ["runtime.py"],
            "preTaskEvidence": {"baseSha": base_sha, "codePathsPlan": ["runtime.py"]},
            "resultDigest": result_digest,
            "reproductionReceipt": probe_receipt,
        },
        receipt={
            "prUrl": "https://github.com/owner/repo/pull/9",
            "headSha": head_sha,
        },
    )
    with ManagedLedger(database)._connection() as connection:
        row = connection.execute("SELECT * FROM managed_prs WHERE pr_key='owner/repo#9'").fetchone()
        assert row["origin_kind"] == "EXISTING_OPEN_PR"
        assert row["auto_created"] == 0
        assert row["source_kind"] == "EXISTING_OPEN_PR"
        assert row["latest_source"] == "publication"

    snapshot = database.parent / "managed.snapshot.gz"
    export_snapshot(database, snapshot)
    assert "existing-head" in gzip.decompress(snapshot.read_bytes()).decode("utf-8")
    restored = tmp_path / "run2" / "state" / "radar_ledger.sqlite3"
    restored.parent.mkdir(parents=True)
    RadarLedger(restored)
    import_snapshot(restored, snapshot)
    with ManagedLedger(restored)._connection() as connection:
        row = connection.execute("SELECT * FROM managed_prs WHERE pr_key='owner/repo#9'").fetchone()
        assert row["origin_kind"] == "EXISTING_OPEN_PR"
        assert row["auto_created"] == 0
        assert row["source_kind"] == "EXISTING_OPEN_PR"
        assert row["latest_source"] == "publication"


def test_older_followup_cannot_overwrite_newer_authoritative_pr_head(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    ledger = ManagedLedger(database, ensure_schema=True)
    pr_url = "https://github.com/owner/repo/pull/9"
    current_head = "d" * 40
    stale_head = "8" * 40
    ledger.upsert_pr(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha=current_head,
        pr_url=pr_url,
        state="OPEN",
        auto_created=False,
        source_kind="EXISTING_OPEN_PR",
        source="github-authoritative-reconciliation",
        observed_at="2026-08-19T02:00:00Z",
    )

    ManagedAdapter(database.parent, database).record_followup(
        {
            "items": [
                {
                    "key": "owner/repo#9",
                    "url": pr_url,
                    "headSha": stale_head,
                    "ciStatus": "PASSED",
                    "checkedAt": "2026-08-19T01:00:00Z",
                    "evidence": {"failingChecks": [], "requestedChanges": []},
                }
            ]
        },
        {"run_id": "stale-followup"},
    )
    equal_time = ledger.upsert_pr(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha=stale_head,
        pr_url=pr_url,
        state="OPEN",
        auto_created=False,
        source_kind="FOLLOWUP_OBSERVATION",
        source="github-followup",
        observed_at="2026-08-19T02:00:00Z",
    )

    assert equal_time["head_sha"] == current_head
    assert equal_time["latest_source"] == "github-authoritative-reconciliation"
    assert equal_time["observed_at"] == "2026-08-19T02:00:00Z"

    newer = ledger.upsert_pr(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha="e" * 40,
        pr_url=pr_url,
        state="OPEN",
        auto_created=False,
        source_kind="FOLLOWUP_OBSERVATION",
        source="github-followup",
        observed_at="2026-08-19T03:00:00Z",
    )
    assert newer["head_sha"] == "e" * 40
    assert newer["latest_source"] == "github-followup"


def test_stale_publication_receipt_finalizes_without_reverting_pr_projection(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    ledger = ManagedLedger(database, ensure_schema=True)
    publication_head = "7" * 40
    current_head = "d" * 40
    pr_url = "https://github.com/owner/repo/pull/9"
    ledger.reserve_publication_slot(
        reservation_key="publication:request-9",
        request_id="request-9",
        repo="owner/repo",
        head_ref="fix/9",
        head_sha=publication_head,
        idempotency_key="publication:request-9",
        now="2026-08-19T00:00:00Z",
    )
    ledger.upsert_pr(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha=current_head,
        pr_url=pr_url,
        state="OPEN",
        auto_created=False,
        source_kind="EXISTING_OPEN_PR",
        source="github-authoritative-reconciliation",
        observed_at="2026-08-19T02:00:00Z",
    )

    row = ledger.record_publication_receipt_atomic(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha=publication_head,
        pr_url=pr_url,
        auto_created=False,
        source_kind="MANAGED_PUBLICATION_RECEIPT",
        source="publication",
        reservation_key="publication:request-9",
        event_idempotency_key="publication:request-9:receipt",
        now="2026-08-19T01:00:00Z",
    )

    assert row["head_sha"] == current_head
    assert row["latest_source"] == "github-authoritative-reconciliation"
    with ledger._connection() as connection:
        reservation = connection.execute(
            "SELECT state,head_sha,pr_key FROM managed_publication_reservations"
        ).fetchone()
        receipt_count = connection.execute(
            """SELECT COUNT(*) FROM managed_lifecycle_events
               WHERE event_type='PUBLICATION_RECEIPT_OBSERVED'"""
        ).fetchone()[0]
    assert dict(reservation) == {
        "state": "FINALIZED",
        "head_sha": publication_head,
        "pr_key": "owner/repo#9",
    }
    assert receipt_count == 1

    replayed = ledger.record_publication_receipt_atomic(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha=publication_head,
        pr_url=pr_url,
        auto_created=False,
        source_kind="MANAGED_PUBLICATION_RECEIPT",
        source="publication",
        reservation_key="publication:request-9",
        event_idempotency_key="publication:request-9:receipt",
        now="2026-08-19T03:00:00Z",
    )
    assert replayed["head_sha"] == current_head
    assert replayed["observed_at"] == "2026-08-19T02:00:00Z"
    assert replayed["latest_source"] == "github-authoritative-reconciliation"
    with ledger._connection() as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM managed_lifecycle_events
                   WHERE event_type='PUBLICATION_RECEIPT_OBSERVED'"""
            ).fetchone()[0]
            == 1
        )

    with pytest.raises(PermissionError, match="idempotency binding mismatch"):
        ledger.record_publication_receipt_atomic(
            pr_key="owner/repo#9",
            owner="owner",
            repo="repo",
            number=9,
            head_sha=publication_head,
            pr_url=f"{pr_url}/files",
            auto_created=False,
            source_kind="MANAGED_PUBLICATION_RECEIPT",
            source="publication",
            reservation_key="publication:request-9",
            event_idempotency_key="publication:request-9:receipt",
            now="2026-08-19T04:00:00Z",
        )
    with ledger._connection() as connection:
        unchanged = connection.execute(
            "SELECT head_sha,observed_at,latest_source FROM managed_prs WHERE pr_key='owner/repo#9'"
        ).fetchone()
        assert dict(unchanged) == {
            "head_sha": current_head,
            "observed_at": "2026-08-19T02:00:00Z",
            "latest_source": "github-authoritative-reconciliation",
        }


def test_active_publication_reservation_is_not_published_authority(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    ledger = ManagedLedger(database, ensure_schema=True)
    publication_head = "7" * 40
    pr_url = "https://github.com/owner/repo/pull/9"
    ledger.reserve_publication_slot(
        reservation_key="publication:request-9",
        request_id="request-9",
        repo="owner/repo",
        head_ref="fix/9",
        head_sha=publication_head,
        opportunity_key="owner/repo#1",
        idempotency_key="publication:request-9",
        now="2026-08-19T00:00:00Z",
    )
    ledger.upsert_pr(
        pr_key="owner/repo#9",
        owner="owner",
        repo="repo",
        number=9,
        head_sha=publication_head,
        pr_url=pr_url,
        state="OPEN",
        auto_created=False,
        reservation_key="publication:request-9",
        source_kind="MANAGED_PUBLICATION_RECEIPT",
        source="publication",
        observed_at="2026-08-19T00:01:00Z",
    )

    assert (
        ledger.published_pr_for_opportunity(
            "owner/repo#1",
            pr_url=pr_url,
            publication_head_sha=publication_head,
        )
        is None
    )
    assert (
        ledger.published_pr_authority_for_opportunity(
            "owner/repo#1",
            pr_url=pr_url,
            receipt_head_sha=publication_head,
        )
        is None
    )
