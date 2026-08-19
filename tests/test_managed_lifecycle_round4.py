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
