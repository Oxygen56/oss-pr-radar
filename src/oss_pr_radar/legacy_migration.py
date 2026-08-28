"""Idempotent, read-only import of legacy Radar and War Room history.

The old databases remain the source of truth during rehearsal.  This module
only reads them and records a sanitized, provenance-bound history in the
managed Ledger copy.  Raw source copies and report hashes remain the audit
evidence; secrets and machine-local paths are never copied into the managed
history or its exported summaries.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .managed_lifecycle import MANAGED_TABLES, ManagedLedger, migrate_schema, parse_issue_reference
from .managed_security import stable_fingerprint
from .util import canonical_json

_SENSITIVE_KEY = re.compile(r"(?:secret|token|password|api[_-]?key|private[_-]?key|hmac)", re.I)
_LOCAL_PATH_KEY = re.compile(r"(?:worktree|checkout|absolute[_-]?path|local[_-]?path)", re.I)

_MANAGED_STORAGE_TABLES = frozenset(
    {*(table.casefold() for table in MANAGED_TABLES), "task_quarantines"}
)
_UNPREFIXED_MANAGED_STORAGE_TABLES = tuple(
    sorted(table for table in _MANAGED_STORAGE_TABLES if not table.startswith("managed_"))
)
_UNPREFIXED_MANAGED_STORAGE_SQL = ",".join(
    f"'{table}'" for table in _UNPREFIXED_MANAGED_STORAGE_TABLES
)


def _is_managed_storage_table(table: str) -> bool:
    normalized = table.casefold()
    return normalized.startswith("managed_") or normalized in _MANAGED_STORAGE_TABLES


def _managed_table_sql(json_column: str) -> str:
    value = (
        f"CASE WHEN json_valid({json_column}) "
        f"THEN lower(COALESCE(json_extract({json_column}, '$.table'), '')) ELSE '' END"
    )
    return (
        f"({value} LIKE 'managed\\_%' ESCAPE '\\' "
        f"OR {value} IN ({_UNPREFIXED_MANAGED_STORAGE_SQL}))"
    )


_RECURSIVE_MANAGED_HISTORY_PREDICATE = (
    "event_type='LEGACY_RECORD_IMPORTED' AND ("
    f"{_managed_table_sql('provenance_json')} OR {_managed_table_sql('payload_json')})"
)


def _safe_value(value: Any, *, key: str = "") -> Any:
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if _LOCAL_PATH_KEY.search(key):
        return "[LOCAL_PATH_REDACTED]"
    if isinstance(value, dict):
        return {str(k): _safe_value(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_value(item, key=key) for item in value]
    if isinstance(value, str):
        if value.startswith(("/", "\\")) or "/Users/" in value or "\\Users\\" in value:
            return "[LOCAL_PATH_REDACTED]"
        if value.startswith("sk-") or "sk-" in value:
            return "[REDACTED]"
    return value


def _safe_row(row: sqlite3.Row) -> dict[str, Any]:
    return {str(key): _safe_value(row[key], key=str(key)) for key in row.keys()}


def _row_key(table: str, row: sqlite3.Row, index: int) -> str:
    preferred = {
        "opportunities": ("key", "opportunity_key", "url"),
        "outcomes": ("opportunity_key",),
        "events": ("id", "dedupe_key"),
        "pr_followups": ("opportunity_key", "pr_url", "head_sha"),
        "opportunities_bridge": ("opportunity_key", "url"),
        "snapshots": ("run_id", "pr_key"),
        "decisions": ("run_id", "pr_key"),
        "actions": ("action_key",),
        "runs": ("run_id",),
    }.get(table, ())
    values = [str(row[name]) for name in preferred if name in row.keys() and row[name] is not None]
    return ":".join(values) if values else f"row-{index}"


def _tables(connection: sqlite3.Connection) -> list[str]:
    tables = [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    ]
    # A later rehearsal may use an already-managed Ledger as its production
    # source.  Those rows are already present in the copied target and must not
    # be wrapped again as LEGACY_RECORD_IMPORTED history.
    return [table for table in tables if not _is_managed_storage_table(table)]


def compact_recursive_managed_history_copy(
    target: Path,
    *,
    source: Path,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Remove recursively wrapped managed rows from one disposable migration copy.

    The active source is never modified.  The exact removed identities are
    summarized by a digest and one append-only repair event in the target.
    """

    target = target.resolve()
    source = source.resolve()
    if target == source or (
        target.exists() and source.exists() and os.path.samefile(target, source)
    ):
        raise ValueError("managed history compaction target must be a copy")
    if not target.is_file() or not source.is_file():
        raise FileNotFoundError("managed history compaction requires source and target files")
    migrate_schema(target)
    bytes_before = target.stat().st_size
    connection = sqlite3.connect(target, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        stable_counts_before = {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in _MANAGED_STORAGE_TABLES
            if table != "managed_lifecycle_events"
        }
        rows = connection.execute(
            f"""SELECT event_id,idempotency_fingerprint,
                       CASE WHEN json_valid(provenance_json)
                            THEN json_extract(provenance_json, '$.table') END AS provenance_table,
                       CASE WHEN json_valid(payload_json)
                            THEN json_extract(payload_json, '$.table') END AS payload_table,
                       length(payload_json) AS payload_bytes
                FROM managed_lifecycle_events
                WHERE {_RECURSIVE_MANAGED_HISTORY_PREDICATE}
                ORDER BY event_id"""
        ).fetchall()
        if not rows:
            return {
                "removedEvents": 0,
                "removedPayloadBytes": 0,
                "removedIdentityDigest": None,
                "tables": {},
                "auditEventCreated": False,
                "fileBytesBefore": bytes_before,
                "fileBytesAfter": bytes_before,
            }
        identities = []
        tables: dict[str, int] = {}
        payload_bytes = 0
        for row in rows:
            table = str(row["provenance_table"] or row["payload_table"] or "").casefold()
            identities.append(
                {
                    "eventId": int(row["event_id"]),
                    "idempotencyFingerprint": str(row["idempotency_fingerprint"]),
                    "table": table,
                }
            )
            tables[table] = tables.get(table, 0) + 1
            payload_bytes += int(row["payload_bytes"] or 0)
        identity_digest = hashlib.sha256(canonical_json(identities).encode("utf-8")).hexdigest()
        idempotency_key = f"managed-history-compaction:{identity_digest}"
        timestamp = observed_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
        payload = {
            "repair": "recursive-managed-history-v1",
            "removedEvents": len(rows),
            "removedPayloadBytes": payload_bytes,
            "removedIdentityDigest": identity_digest,
            "tables": dict(sorted(tables.items())),
        }
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TRIGGER IF EXISTS managed_events_no_delete")
        deleted = connection.execute(
            f"DELETE FROM managed_lifecycle_events WHERE {_RECURSIVE_MANAGED_HISTORY_PREDICATE}"
        ).rowcount
        if deleted != len(rows):
            raise RuntimeError("recursive managed history changed during compaction")
        connection.execute(
            """CREATE TRIGGER managed_events_no_delete
               BEFORE DELETE ON managed_lifecycle_events
               BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END"""
        )
        connection.execute(
            """INSERT INTO managed_lifecycle_events
               (opportunity_key,task_id,pr_key,event_type,state,idempotency_key,
                idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
               VALUES (NULL,NULL,NULL,?,?,?,?,?,?,?,?)""",
            (
                "MANAGED_HISTORY_COMPACTED",
                "DATA_REPAIRED",
                idempotency_key,
                stable_fingerprint(idempotency_key),
                "stage6-migration",
                canonical_json(
                    {
                        "originKind": "DATA_REPAIR",
                        "repair": "recursive-managed-history-v1",
                    }
                ),
                timestamp,
                canonical_json(payload),
            ),
        )
        stable_counts_after = {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in _MANAGED_STORAGE_TABLES
            if table != "managed_lifecycle_events"
        }
        if stable_counts_after != stable_counts_before:
            raise RuntimeError("managed history compaction changed authoritative projections")
        connection.execute("COMMIT")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("VACUUM")
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("managed history compaction integrity check failed")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {
        **payload,
        "auditEventCreated": True,
        "fileBytesBefore": bytes_before,
        "fileBytesAfter": target.stat().st_size,
    }


def _iter_rows(path: Path, table: str) -> Iterable[tuple[int, sqlite3.Row]]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        for index, row in enumerate(connection.execute(f'SELECT * FROM "{table}"')):
            yield index, row
    finally:
        connection.close()


def _ensure_issue(ledger: ManagedLedger, row: sqlite3.Row, *, source: str, table: str) -> bool:
    values = dict(row)
    reference = values.get("key") or values.get("opportunity_key") or values.get("url")
    if not isinstance(reference, str):
        return False
    try:
        identity = parse_issue_reference(reference)
    except ValueError:
        return False
    if ledger.opportunity_identity(identity["opportunityKey"]) is not None:
        return False
    safe_values = _safe_row(row)
    legacy_state = values.get("stage") or values.get("status") or ""
    title = safe_values.get("title") or safe_values.get("opportunity_json")
    metadata: dict[str, Any] = {
        "originKind": "LEGACY_HISTORY",
        "legacyTable": table,
        "legacyState": _safe_value(legacy_state, key="legacyState"),
        "authorization": "NON_AUTHORIZING_HISTORY_ONLY",
    }
    if title:
        metadata["title"] = str(title)[:500]
    ledger.upsert_opportunity(
        opportunity_key=identity["opportunityKey"],
        owner=identity["owner"],
        repo=identity["repo"],
        issue_number=identity["issueNumber"],
        issue_url=identity["issueUrl"],
        # Legacy labels are historical evidence only.  In particular, FIX_READY,
        # PR_OPEN and PORTFOLIO_READY must never authorize a new task or output.
        state="SYSTEM_PROCESSING",
        source=source,
        provenance={"originKind": "LEGACY_HISTORY", "legacyTable": table},
        observed_at=str(values.get("updated_at") or values.get("created_at") or "") or None,
        metadata=metadata,
    )
    return True


def _import_table(ledger: ManagedLedger, path: Path, table: str, *, source: str) -> dict[str, int]:
    imported = duplicates = 0
    for index, row in _iter_rows(path, table):
        row_key = _row_key(table, row, index)
        safe_row = _safe_row(row)
        digest = hashlib.sha256(canonical_json(safe_row).encode("utf-8")).hexdigest()
        if table in {"opportunities", "opportunities_bridge"} and _ensure_issue(
            ledger, row, source=source, table=table
        ):
            imported += 1
        opportunity_key = None
        for reference in (
            row["key"] if "key" in row.keys() else None,
            row["opportunity_key"] if "opportunity_key" in row.keys() else None,
            row["url"] if "url" in row.keys() else None,
            row["issue_url"] if "issue_url" in row.keys() else None,
        ):
            if isinstance(reference, str):
                try:
                    opportunity_key = parse_issue_reference(reference)["opportunityKey"]
                    break
                except ValueError:
                    pass
        result = ledger.record_event(
            event_type="LEGACY_RECORD_IMPORTED",
            idempotency_key=f"legacy:{source}:{table}:{row_key}",
            opportunity_key=opportunity_key,
            source="legacy-migration",
            provenance={
                "originKind": "LEGACY_HISTORY",
                "source": source,
                "table": table,
                "rowKey": row_key,
            },
            payload={
                "source": source,
                "table": table,
                "rowKey": row_key,
                "contentDigest": digest,
                "record": safe_row,
            },
            observed_at=str(row["updated_at"] if "updated_at" in row.keys() else "") or None,
        )
        if not result.get("created", True):
            duplicates += 1
    return {"records": imported, "events": imported + duplicates, "duplicates": duplicates}


def _import_report_manifest(ledger: ManagedLedger, reports_dir: Path | None) -> dict[str, int]:
    if reports_dir is None or not reports_dir.exists():
        return {"reports": 0, "duplicates": 0}
    imported = duplicates = 0
    for report in sorted(reports_dir.glob("*.json")):
        content = report.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        payload: dict[str, Any] = {
            "filename": report.name,
            "size": len(content),
            "sha256": digest,
        }
        try:
            parsed = json.loads(content.decode("utf-8"))
            if isinstance(parsed, dict):
                payload["topLevelKeys"] = sorted(str(key) for key in parsed)
                payload["safeSummary"] = {
                    key: _safe_value(parsed[key], key=key)
                    for key in ("count", "total", "run_id", "status", "generated_at")
                    if key in parsed
                }
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload["format"] = "non-json"
        result = ledger.record_event(
            event_type="LEGACY_REPORT_MANIFEST_IMPORTED",
            idempotency_key=f"legacy-report:{report.name}",
            source="legacy-migration",
            provenance={"originKind": "LEGACY_REPORT", "filename": report.name},
            payload=payload,
        )
        if result.get("created", True):
            imported += 1
        else:
            duplicates += 1
    return {"reports": imported, "duplicates": duplicates}


def import_legacy_history(
    target: Path,
    *,
    production_ledger: Path | None = None,
    war_room_db: Path | None = None,
    reports_dir: Path | None = None,
) -> dict[str, Any]:
    """Import legacy rows and report manifests without mutating any source."""

    migrate_schema(target)
    ledger = ManagedLedger(target)
    summary: dict[str, Any] = {"sources": {}, "managedSchema": 7}
    if production_ledger is not None:
        connection = sqlite3.connect(f"file:{production_ledger.resolve()}?mode=ro", uri=True)
        try:
            tables = _tables(connection)
        finally:
            connection.close()
        summary["sources"]["production"] = {
            table: _import_table(ledger, production_ledger, table, source="production")
            for table in tables
        }
    if war_room_db is not None:
        connection = sqlite3.connect(f"file:{war_room_db.resolve()}?mode=ro", uri=True)
        try:
            tables = _tables(connection)
        finally:
            connection.close()
        summary["sources"]["warRoom"] = {
            table: _import_table(
                ledger,
                war_room_db,
                table,
                source="war-room" if table != "opportunities" else "war-room-opportunities",
            )
            for table in tables
        }
    summary["reports"] = _import_report_manifest(ledger, reports_dir)
    with ledger._connection() as connection:
        summary["managedHistoryEvents"] = int(
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE event_type IN ('LEGACY_RECORD_IMPORTED','LEGACY_REPORT_MANIFEST_IMPORTED')"
            ).fetchone()[0]
        )
    return summary
