from __future__ import annotations

import json
import os
import sqlite3

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.legacy_migration import (
    compact_recursive_managed_history_copy,
    import_legacy_history,
)
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    import_open_pr_observations,
    reconcile_managed_pr_states,
)
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot
from oss_pr_radar.war_room_projection import build_projection


def _db(path, schema, rows):
    connection = sqlite3.connect(path)
    for statement in schema:
        connection.execute(statement)
    for table, values in rows.items():
        for value in values:
            columns = ",".join(value)
            placeholders = ",".join("?" for _ in value)
            connection.execute(
                f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(value.values())
            )
    connection.commit()
    connection.close()


def test_legacy_history_is_sanitized_and_idempotent(tmp_path, monkeypatch):
    production = tmp_path / "production.sqlite3"
    _db(
        production,
        [
            "CREATE TABLE opportunities (key TEXT PRIMARY KEY, repo TEXT, issue_number INTEGER, issue_url TEXT, title TEXT, stage TEXT, updated_at TEXT)",
            "CREATE TABLE outcomes (opportunity_key TEXT PRIMARY KEY, quality_json TEXT, updated_at TEXT)",
        ],
        {
            "opportunities": [
                {
                    "key": "owner/repo#7",
                    "repo": "owner/repo",
                    "issue_number": 7,
                    "issue_url": "https://github.com/owner/repo/issues/7",
                    "title": "Fix",
                    "stage": "FIX_READY",
                    "updated_at": "2026-08-19T00:00:00Z",
                }
            ],
            "outcomes": [
                {
                    "opportunity_key": "owner/repo#7",
                    "quality_json": '{"api_key":"sk-secret"}',
                    "updated_at": "",
                }
            ],
        },
    )
    war_room = tmp_path / "war-room.sqlite3"
    _db(
        war_room,
        ["CREATE TABLE opportunities (opportunity_key TEXT PRIMARY KEY, url TEXT, status TEXT)"],
        {
            "opportunities": [
                {
                    "opportunity_key": "owner/repo#7",
                    "url": "https://github.com/owner/repo/issues/7",
                    "status": "candidate",
                }
            ]
        },
    )
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "report.json").write_text(
        json.dumps({"worktreePath": "/Users/oxygen/private", "count": 1}), encoding="utf-8"
    )
    target = tmp_path / "managed.sqlite3"
    first = import_legacy_history(
        target, production_ledger=production, war_room_db=war_room, reports_dir=reports
    )
    second = import_legacy_history(
        target, production_ledger=production, war_room_db=war_room, reports_dir=reports
    )
    assert first["sources"]["production"]["opportunities"]["records"] == 1
    assert first["sources"]["warRoom"]["opportunities"]["records"] == 0
    assert first["sources"]["warRoom"]["opportunities"]["duplicates"] == 0
    assert second["managedHistoryEvents"] == first["managedHistoryEvents"]
    ledger = ManagedLedger(target)
    with ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_opportunities").fetchone()[0] == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE event_type IN ('LEGACY_RECORD_IMPORTED','LEGACY_REPORT_MANIFEST_IMPORTED')"
            ).fetchone()[0]
            == 4
        )
        payloads = [
            row[0]
            for row in connection.execute("SELECT payload_json FROM managed_lifecycle_events")
        ]
    encoded = "\n".join(payloads)
    assert "sk-secret" not in encoded
    assert "/Users/oxygen" not in encoded
    projection = build_projection(target, source_commit="stage6-test")
    assert projection["items"] == []
    assert set(projection["buckets"]) == {
        "DECISION_REQUIRED",
        "SYSTEM_PROCESSING",
        "WAITING_EXTERNAL",
        "PORTFOLIO_READY",
    }
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "legacy-migration-test-key-0123456789")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "legacy-migration-test")
    snapshot = tmp_path / "managed.snapshot.gz"
    restored = tmp_path / "restored.sqlite3"
    export_snapshot(target, snapshot)
    import_snapshot(restored, snapshot)
    assert (
        build_projection(restored, source_commit="stage6-test")["artifactDigest"]
        == projection["artifactDigest"]
    )


def test_managed_tables_are_not_reimported_as_legacy_history(tmp_path):
    source = tmp_path / "managed-source.sqlite3"
    _db(
        source,
        [
            "CREATE TABLE legacy_rows (id TEXT PRIMARY KEY, payload TEXT)",
            "CREATE TABLE managed_lifecycle_events (event_id INTEGER PRIMARY KEY, payload_json TEXT)",
            "CREATE TABLE managed_future_table (id TEXT PRIMARY KEY, payload TEXT)",
            "CREATE TABLE task_quarantines (id TEXT PRIMARY KEY, payload TEXT)",
            "CREATE TABLE attestation_nonce_consumptions (id TEXT PRIMARY KEY, payload TEXT)",
        ],
        {
            "legacy_rows": [{"id": "legacy-1", "payload": "legacy"}],
            "managed_lifecycle_events": [{"event_id": 1, "payload_json": "{}"}],
            "managed_future_table": [{"id": "managed-1", "payload": "managed"}],
            "task_quarantines": [{"id": "quarantine-1", "payload": "managed"}],
            "attestation_nonce_consumptions": [{"id": "nonce-1", "payload": "managed"}],
        },
    )
    target = tmp_path / "target.sqlite3"

    first = import_legacy_history(target, production_ledger=source)
    second = import_legacy_history(target, production_ledger=source)

    assert set(first["sources"]["production"]) == {"legacy_rows"}
    assert set(second["sources"]["production"]) == {"legacy_rows"}
    with ManagedLedger(target)._connection() as connection:
        rows = connection.execute(
            "SELECT event_type,provenance_json FROM managed_lifecycle_events ORDER BY event_id"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["event_type"] == "LEGACY_RECORD_IMPORTED"
    assert json.loads(rows[0]["provenance_json"])["table"] == "legacy_rows"


def test_recursive_managed_history_is_compacted_only_on_a_copy(tmp_path):
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "migrated.sqlite3"
    source.touch()
    ledger = ManagedLedger(target, ensure_schema=True)
    ledger.record_event(
        event_type="REAL_EVENT",
        idempotency_key="real-event",
        payload={"kept": True},
    )
    ledger.record_event(
        event_type="LEGACY_RECORD_IMPORTED",
        idempotency_key="true-legacy-event",
        provenance={"table": "events"},
        payload={"table": "events", "record": {"id": 1}},
    )
    ledger.record_event(
        event_type="LEGACY_RECORD_IMPORTED",
        idempotency_key="recursive-managed-event",
        provenance={"table": "managed_lifecycle_events"},
        payload={"table": "managed_lifecycle_events", "record": {"event_id": 1}},
    )
    ledger.record_event(
        event_type="LEGACY_RECORD_IMPORTED",
        idempotency_key="recursive-quarantine",
        provenance={"table": "task_quarantines"},
        payload={"table": "task_quarantines", "record": {"quarantine_id": 1}},
    )
    ledger.record_event(
        event_type="LEGACY_RECORD_IMPORTED",
        idempotency_key="recursive-nonce",
        provenance={"table": "attestation_nonce_consumptions"},
        payload={"table": "attestation_nonce_consumptions", "record": {"consumption_id": 1}},
    )
    with ledger._connection() as connection:
        connection.execute(
            """INSERT INTO task_quarantines
               (opportunity_key,reason,dedupe_key,payload_json,status,created_at)
               VALUES ('a/b#1','TEST','test-dedupe','{}','ACTIVE','2026-08-28T00:00:00Z')"""
        )

    result = compact_recursive_managed_history_copy(
        target,
        source=source,
        observed_at="2026-08-28T00:00:00Z",
    )

    assert result["removedEvents"] == 3
    assert result["tables"] == {
        "attestation_nonce_consumptions": 1,
        "managed_lifecycle_events": 1,
        "task_quarantines": 1,
    }
    assert result["auditEventCreated"] is True
    with ledger._connection() as connection:
        events = connection.execute(
            "SELECT event_type,idempotency_key FROM managed_lifecycle_events ORDER BY event_id"
        ).fetchall()
        assert [row["event_type"] for row in events] == [
            "REAL_EVENT",
            "LEGACY_RECORD_IMPORTED",
            "MANAGED_HISTORY_COMPACTED",
        ]
        quarantine = connection.execute(
            "SELECT opportunity_key,reason,dedupe_key,status FROM task_quarantines"
        ).fetchone()
        assert tuple(quarantine) == ("a/b#1", "TEST", "test-dedupe", "ACTIVE")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM managed_lifecycle_events WHERE idempotency_key='real-event'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE managed_lifecycle_events SET state='changed' "
                "WHERE idempotency_key='real-event'"
            )
    replay = compact_recursive_managed_history_copy(target, source=source)
    assert replay["removedEvents"] == 0
    with pytest.raises(ValueError, match="must be a copy"):
        compact_recursive_managed_history_copy(target, source=target)
    hard_link = tmp_path / "hard-link.sqlite3"
    os.link(target, hard_link)
    with pytest.raises(ValueError, match="must be a copy"):
        compact_recursive_managed_history_copy(target, source=hard_link)


def test_repeated_open_pr_observation_without_timestamp_is_stable(tmp_path):
    target = tmp_path / "managed.sqlite3"
    RadarLedger(target)
    observations = [{"url": "https://github.com/owner/repo/pull/9", "headSha": "head-9"}]
    first = import_open_pr_observations(target, observations)
    second = import_open_pr_observations(target, observations)
    assert first["after"]["digest"] == second["after"]["digest"]


def _api_observation(pr_key: str, state: str, head_sha: str | None) -> dict:
    owner_repo, number = pr_key.split("#")
    owner, repo = owner_repo.split("/")
    url = f"https://github.com/{owner}/{repo}/pull/{number}"
    return {
        "prKey": pr_key,
        "url": url,
        "headSha": head_sha,
        "state": state,
        "apiEvidence": {
            "authoritativeReadOnly": True,
            "endpoint": f"repos/{owner}/{repo}/pulls/{number}",
            "responseDigest": f"response-{number}-{state}",
            "fetchedAt": "2026-08-19T07:00:00Z",
            "state": state,
            "url": url,
            "headSha": head_sha,
        },
    }


def test_authoritative_reconciliation_closes_only_with_exact_evidence(tmp_path):
    target = tmp_path / "managed.sqlite3"
    RadarLedger(target)
    import_open_pr_observations(
        target,
        [
            {"url": "https://github.com/owner/repo/pull/1", "headSha": "head-1"},
            {"url": "https://github.com/owner/repo/pull/2", "headSha": "head-2"},
        ],
        observed_at="2026-08-19T06:59:59Z",
    )
    result = reconcile_managed_pr_states(
        target,
        [
            _api_observation("owner/repo#1", "OPEN", "head-1"),
            _api_observation("owner/repo#2", "MERGED", "head-2"),
        ],
    )
    assert result["total"] == 2
    assert result["stateCounts"] == {"OPEN": 1, "CLOSED": 0, "MERGED": 1}
    with ManagedLedger(target)._connection() as connection:
        event = connection.execute(
            "SELECT event_type,state FROM managed_lifecycle_events "
            "WHERE event_type='MANAGED_PR_STATE_RECONCILED' ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        assert tuple(event) == ("MANAGED_PR_STATE_RECONCILED", "MERGED")
    with pytest.raises(ValueError, match="reconciliation is incomplete"):
        reconcile_managed_pr_states(target, [_api_observation("owner/repo#1", "OPEN", "head-1")])
    with pytest.raises(ValueError, match="unexpected PR"):
        reconcile_managed_pr_states(
            target,
            [
                _api_observation("owner/repo#1", "OPEN", "head-1"),
                _api_observation("owner/repo#2", "MERGED", "head-2"),
                _api_observation("owner/repo#3", "OPEN", "head-3"),
            ],
        )
    with ManagedLedger(target)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_prs").fetchone()[0] == 2


def test_legacy_terminal_labels_cannot_authorize_projection(tmp_path):
    source = tmp_path / "legacy.sqlite3"
    _db(
        source,
        [
            "CREATE TABLE opportunities (key TEXT PRIMARY KEY, issue_url TEXT, stage TEXT, updated_at TEXT)",
        ],
        {
            "opportunities": [
                {
                    "key": "owner/repo#1",
                    "issue_url": "https://github.com/owner/repo/issues/1",
                    "stage": "FIX_READY",
                    "updated_at": "",
                },
                {
                    "key": "owner/repo#2",
                    "issue_url": "https://github.com/owner/repo/issues/2",
                    "stage": "PR_OPEN",
                    "updated_at": "",
                },
                {
                    "key": "owner/repo#3",
                    "issue_url": "https://github.com/owner/repo/issues/3",
                    "stage": "PORTFOLIO_READY",
                    "updated_at": "",
                },
            ]
        },
    )
    target = tmp_path / "managed.sqlite3"
    import_legacy_history(target, production_ledger=source)
    with ManagedLedger(target)._connection() as connection:
        states = [
            row[0]
            for row in connection.execute(
                "SELECT state FROM managed_opportunities ORDER BY opportunity_key"
            )
        ]
        task_count = connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0]
    assert states == ["SYSTEM_PROCESSING", "SYSTEM_PROCESSING", "SYSTEM_PROCESSING"]
    assert task_count == 0
    assert all(not item["actionable"] for item in build_projection(target)["items"])
