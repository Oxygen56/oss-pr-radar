"""Shared, transactional task-quarantine state.

Task quarantine is a publication safety fact, not merely an audit event.  Both
ledger implementations use this table so readers cannot accidentally consult
different event streams.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from .action_guard import opportunity_action_guard
from .util import canonical_json

QUARANTINE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS task_quarantines (
    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
    opportunity_key TEXT NOT NULL,
    reason TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('ACTIVE','CLEARED')),
    created_at TEXT NOT NULL,
    cleared_at TEXT,
    clear_payload_json TEXT,
    UNIQUE(opportunity_key, reason, dedupe_key)
);
CREATE INDEX IF NOT EXISTS task_quarantines_active_key
    ON task_quarantines(opportunity_key, status, quarantine_id);
"""


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS task_quarantines (
            quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
            opportunity_key TEXT NOT NULL,
            reason TEXT NOT NULL,
            dedupe_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('ACTIVE','CLEARED')),
            created_at TEXT NOT NULL,
            cleared_at TEXT,
            clear_payload_json TEXT,
            UNIQUE(opportunity_key, reason, dedupe_key)
        )"""
    )
    connection.execute(
        """CREATE INDEX IF NOT EXISTS task_quarantines_active_key
           ON task_quarantines(opportunity_key, status, quarantine_id)"""
    )


def backfill_from_radar_events(connection: sqlite3.Connection, *, action_guard_root: Path) -> None:
    """Shutdown/migration-only import guarded by every affected opportunity."""

    ensure_schema(connection)
    keys = connection.execute(
        """SELECT DISTINCT opportunity_key FROM events
           WHERE event_type IN ('LEGACY_RESULT_REQUIRES_MIGRATION',
                                'PR_FOLLOWUP_REBIND_REQUIRED')"""
    ).fetchall()
    with ExitStack() as guards:
        for row in sorted(keys, key=lambda value: str(value[0])):
            guards.enter_context(opportunity_action_guard(action_guard_root, str(row[0])))
        connection.execute(
            """INSERT OR IGNORE INTO task_quarantines
           (opportunity_key,reason,dedupe_key,payload_json,status,created_at)
           SELECT q.opportunity_key,q.event_type,q.dedupe_key,q.payload_json,'ACTIVE',q.created_at
           FROM events q
           WHERE q.event_type IN ('LEGACY_RESULT_REQUIRES_MIGRATION',
                                  'PR_FOLLOWUP_REBIND_REQUIRED')
             AND NOT EXISTS (
               SELECT 1 FROM task_quarantines t
               WHERE t.opportunity_key=q.opportunity_key
                 AND t.reason=q.event_type
                 AND t.payload_json=q.payload_json
             )
             AND NOT EXISTS (
               SELECT 1 FROM events c
               WHERE c.opportunity_key=q.opportunity_key
                 AND c.event_type='TASK_QUARANTINE_CLEARED'
                 AND c.id>q.id
             )"""
        )


def backfill_from_managed_events(
    connection: sqlite3.Connection, *, action_guard_root: Path
) -> None:
    """Shutdown/migration-only import guarded by every affected opportunity."""

    ensure_schema(connection)
    if (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_lifecycle_events'"
        ).fetchone()
        is None
    ):
        return
    keys = connection.execute(
        """SELECT DISTINCT opportunity_key FROM managed_lifecycle_events
           WHERE event_type IN ('LEGACY_RESULT_REQUIRES_MIGRATION',
                                'PR_FOLLOWUP_REBIND_REQUIRED')"""
    ).fetchall()
    with ExitStack() as guards:
        for row in sorted(keys, key=lambda value: str(value[0])):
            guards.enter_context(opportunity_action_guard(action_guard_root, str(row[0])))
        connection.execute(
            """INSERT OR IGNORE INTO task_quarantines
           (opportunity_key,reason,dedupe_key,payload_json,status,created_at)
           SELECT q.opportunity_key,q.event_type,q.idempotency_key,q.payload_json,'ACTIVE',q.observed_at
           FROM managed_lifecycle_events q
           WHERE q.event_type IN ('LEGACY_RESULT_REQUIRES_MIGRATION',
                                  'PR_FOLLOWUP_REBIND_REQUIRED')
             AND q.idempotency_key NOT LIKE 'task-quarantine:%'
             AND NOT EXISTS (
               SELECT 1 FROM task_quarantines t
               WHERE t.opportunity_key=q.opportunity_key
                 AND t.reason=q.event_type
                 AND t.payload_json=q.payload_json
             )
             AND NOT EXISTS (
               SELECT 1 FROM managed_lifecycle_events c
               WHERE c.opportunity_key=q.opportunity_key
                 AND c.event_type='TASK_QUARANTINE_CLEARED'
                 AND c.event_id>q.event_id
             )"""
        )


def record(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    reason: str,
    dedupe_key: str,
    payload: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    if not opportunity_key or not reason or not dedupe_key or not isinstance(payload, dict):
        raise ValueError("task quarantine fields are invalid")
    ensure_schema(connection)
    cursor = connection.execute(
        """INSERT OR IGNORE INTO task_quarantines
           (opportunity_key,reason,dedupe_key,payload_json,status,created_at)
           VALUES (?,?,?,?, 'ACTIVE', ?)""",
        (opportunity_key, reason, dedupe_key, canonical_json(payload), created_at),
    )
    row = connection.execute(
        """SELECT * FROM task_quarantines
           WHERE opportunity_key=? AND reason=? AND dedupe_key=?""",
        (opportunity_key, reason, dedupe_key),
    ).fetchone()
    if row is None:
        raise RuntimeError("task quarantine was not persisted")
    return dict(row) | {"created": cursor.rowcount == 1}


def active(
    connection: sqlite3.Connection, *, opportunity_key: str, reason: str | None = None
) -> dict[str, Any] | None:
    ensure_schema(connection)
    clauses = ["opportunity_key=?", "status='ACTIVE'"]
    params: list[Any] = [opportunity_key]
    if reason is not None:
        clauses.append("reason=?")
        params.append(reason)
    row = connection.execute(
        f"""SELECT * FROM task_quarantines WHERE {" AND ".join(clauses)}
            ORDER BY quarantine_id DESC LIMIT 1""",
        params,
    ).fetchone()
    return dict(row) if row else None


def require_clear(connection: sqlite3.Connection, *, opportunity_key: str, operation: str) -> None:
    """Fail closed for a publication mutation while a task quarantine is active."""

    row = active(connection, opportunity_key=opportunity_key)
    if row is not None:
        raise PermissionError(f"{operation} blocked by active task quarantine: {opportunity_key}")


def clear(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    reason: str,
    evidence: dict[str, Any],
    cleared_at: str,
) -> int:
    if not reason or not isinstance(evidence, dict) or evidence.get("revalidated") is not True:
        raise ValueError("task quarantine clear requires revalidated evidence")
    ensure_schema(connection)
    payload = canonical_json(evidence)
    cursor = connection.execute(
        """UPDATE task_quarantines
           SET status='CLEARED', cleared_at=?, clear_payload_json=?
           WHERE opportunity_key=? AND reason=? AND status='ACTIVE'""",
        (cleared_at, payload, opportunity_key, reason),
    )
    return int(cursor.rowcount)


def attach_artifact(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    reason: str,
    artifact: dict[str, Any],
) -> dict[str, Any]:
    """Bind recovery evidence to an active quarantine without changing its key."""

    if not isinstance(artifact, dict) or not artifact:
        raise ValueError("task quarantine artifact is invalid")
    ensure_schema(connection)
    row = connection.execute(
        """SELECT * FROM task_quarantines
           WHERE opportunity_key=? AND reason=? AND status='ACTIVE'
           ORDER BY quarantine_id DESC LIMIT 1""",
        (opportunity_key, reason),
    ).fetchone()
    if row is None:
        raise ValueError("active task quarantine is missing")
    current = payload(dict(row))
    for key, value in artifact.items():
        if key in current and current[key] != value:
            raise ValueError("task quarantine artifact binding changed")
    merged = current | artifact
    connection.execute(
        """UPDATE task_quarantines SET payload_json=? WHERE quarantine_id=?""",
        (canonical_json(merged), row["quarantine_id"]),
    )
    updated = connection.execute(
        "SELECT * FROM task_quarantines WHERE quarantine_id=?",
        (row["quarantine_id"],),
    ).fetchone()
    if updated is None:
        raise RuntimeError("task quarantine artifact was not persisted")
    return dict(updated)


def payload(row: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(str(row["payload_json"]))
    if not isinstance(value, dict):
        raise ValueError("task quarantine payload is invalid")
    return value
