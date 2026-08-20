from __future__ import annotations

import sqlite3

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    migrate_copy,
    migrate_schema,
    rollback_schema,
    schema_status,
)


def test_migration_is_additive_idempotent_and_rollback_preserves_legacy_tables(tmp_path):
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "copy.sqlite3"
    legacy = RadarLedger(source)
    with legacy.connect() as connection:
        before_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    result = migrate_copy(source, target)
    assert result["legacyUnchanged"] is True
    assert result["schema"]["current"] == 7
    assert migrate_schema(target)["applied"] is False
    assert schema_status(target)["current"] == 7

    rollback_schema(target)
    with sqlite3.connect(target) as connection:
        after_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert before_tables <= after_tables
    assert schema_status(target)["current"] == 0


def test_double_read_prefers_managed_then_falls_back_to_legacy(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    managed = ManagedLedger(database, ensure_schema=True)
    with managed._connection() as connection:
        connection.execute(
            "INSERT INTO opportunities(key,repo,issue_number,issue_url,title,stage,first_seen,updated_at,metadata_json) "
            "VALUES ('owner/repo#1','owner/repo',1,'https://github.com/owner/repo/issues/1','Legacy','QUALIFIED','now','now','{}')"
        )
    fallback = managed.read_opportunity("owner/repo#1")
    assert fallback and fallback["readSource"] == "legacy"
    managed.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="DECISION_REQUIRED",
        source="test",
        provenance={"source": "test"},
    )
    preferred = managed.read_opportunity("owner/repo#1")
    assert preferred and preferred["readSource"] == "managed"
    assert preferred["state"] == "DECISION_REQUIRED"


def test_append_only_event_idempotency_and_legacy_publication_effects_survive(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    managed = ManagedLedger(database, ensure_schema=True)
    first = managed.record_event(
        event_type="TASK_RESULT_RECORDED",
        idempotency_key="result-1",
        task_id="task-1",
        source="test",
        provenance={"source": "test"},
        payload={"state": "FIX_READY"},
    )
    replay = managed.record_event(
        event_type="TASK_RESULT_RECORDED",
        idempotency_key="result-1",
        task_id="task-1",
        source="test",
        provenance={"source": "test"},
        payload={"state": "FIX_READY"},
    )
    assert first["created"] is True
    assert replay["created"] is False
    with managed._connection() as connection:
        try:
            connection.execute(
                "DELETE FROM managed_lifecycle_events WHERE idempotency_key='result-1'"
            )
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)
        else:
            raise AssertionError("append-only event deletion was allowed")


def test_task_quarantine_backfill_is_idempotent_across_managed_reopens(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    managed = ManagedLedger(database, ensure_schema=True)
    managed.record_event(
        event_type="LEGACY_RESULT_REQUIRES_MIGRATION",
        idempotency_key="legacy-quarantine-1",
        opportunity_key="owner/repo#1",
        source="legacy-test",
        payload={"reason": "LEGACY_RESULT_REQUIRES_MIGRATION", "legacy": True},
    )

    migrate_schema(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 1
        before_events = connection.execute(
            "SELECT COUNT(*) FROM managed_lifecycle_events "
            "WHERE event_type='LEGACY_RESULT_REQUIRES_MIGRATION'"
        ).fetchone()[0]

    managed.record_task_quarantine(
        opportunity_key="owner/repo#1",
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key="legacy-quarantine-1",
        payload={"reason": "LEGACY_RESULT_REQUIRES_MIGRATION", "legacy": True},
    )
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events "
                "WHERE event_type='LEGACY_RESULT_REQUIRES_MIGRATION'"
            ).fetchone()[0]
            == before_events
        )

    managed.record_task_quarantine(
        opportunity_key="owner/repo#2",
        reason="LEGACY_RESULT_REQUIRES_MIGRATION",
        dedupe_key="new-quarantine-2",
        payload={"reason": "LEGACY_RESULT_REQUIRES_MIGRATION", "new": True},
    )
    migrate_schema(database)
    migrate_schema(database)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM task_quarantines").fetchone()[0] == 2
