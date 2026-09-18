"""Fail-closed removal of the one known ``a/b#1`` synthetic ledger graph.

The production ledger is immutable input to this module.  Execution always
creates a new SQLite backup at an explicit, previously absent path and mutates
only that copy.  The hard-coded identities below intentionally make this a
one-time repair, not a general-purpose deletion facility.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

SCHEMA = "oss-pr-radar.synthetic-ledger-cleanup.a-b-1.v1"

OPPORTUNITY_KEY = "a/b#1"
REPOSITORY = "a/b"
ISSUE_URL = "https://github.com/a/b/issues/1"
INTENT_ID = "intent-1"
THREAD_ID = "thread-1"
WORKTREE_PATH = "/Users/oxygen/Documents/github/.oss-pr-radar/worktrees/intent-1-325142be9e/b"
REQUEST_ID = "9bd9e7f3fd3afcac04f3a48638611be421804f1091e7789b05a93b7988af5ec2"
PERMIT_ID = "04827eb20a4378a698a6dbd507c578a5d73ba7e0ce11c8828e0c84adf71ba074"
PR_URL = "https://github.com/a/b/pull/9"

EVENT_TYPES = {
    1081029: "AUDIT_SNAPSHOT",
    1081030: "TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND",
    1081031: "TASK_CONTEXT_AUTHORITY_BOUND",
    1081032: "PR_OPEN",
    1081033: "TASK_CONTEXT_RECOVERED",
    1081039: "SHARED_TASK_CONTEXT_QUARANTINED",
    1081795: "CLOSED",
    1083036: "TASK_CONTEXT_AUTHORITY_BOUND",
}
QUARANTINE_REASONS = {
    1: "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID",
    6634: "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID",
    53951: "SHARED_CONTEXT_LAYOUT_CONFLICT",
    53952: "SHARED_CONTEXT_LAYOUT_CONFLICT",
}
LIFECYCLE_EVENTS = {230882: "CODE_PATH_TOMBSTONE_ATTESTED"}

# Exact primary-key identities that may contain one of the synthetic markers.
# Any marker in any other row is an unexpected association and fails closed.
TARGET_IDENTITIES: dict[str, tuple[tuple[str, ...], frozenset[tuple[Any, ...]]]] = {
    "opportunities": (("key",), frozenset({(OPPORTUNITY_KEY,)})),
    "intents": (("intent_id",), frozenset({(INTENT_ID,)})),
    "events": (("id",), frozenset((event_id,) for event_id in EVENT_TYPES)),
    "outcomes": (("opportunity_key",), frozenset({(OPPORTUNITY_KEY,)})),
    "publication_requests": (("request_id",), frozenset({(REQUEST_ID,)})),
    "publication_permits": (("permit_id",), frozenset({(PERMIT_ID,)})),
    "task_quarantines": (
        ("quarantine_id",),
        frozenset((quarantine_id,) for quarantine_id in QUARANTINE_REASONS),
    ),
    "managed_lifecycle_events": (
        ("event_id",),
        frozenset((event_id,) for event_id in LIFECYCLE_EVENTS),
    ),
}

_STRONG_MARKERS = (
    OPPORTUNITY_KEY,
    ISSUE_URL,
    WORKTREE_PATH,
    REQUEST_ID,
    PERMIT_ID,
    PR_URL,
)
_EXACT_MARKERS = frozenset(
    {
        OPPORTUNITY_KEY,
        REPOSITORY,
        ISSUE_URL,
        INTENT_ID,
        THREAD_ID,
        WORKTREE_PATH,
        REQUEST_ID,
        PERMIT_ID,
        PR_URL,
    }
)


class SyntheticLedgerCleanupError(RuntimeError):
    """The source is not exactly the known synthetic graph."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$bytesBase64": base64.b64encode(value).decode("ascii")}
    return value


def _read_only(path: Path) -> sqlite3.Connection:
    uri = f"file:{quote(str(path.resolve()), safe='/')}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def _user_tables(connection: sqlite3.Connection) -> list[str]:
    return [
        str(row[0])
        for row in connection.execute(
            """SELECT name FROM sqlite_master
               WHERE type='table' AND name NOT LIKE 'sqlite_%'
               ORDER BY name"""
        ).fetchall()
    ]


def _table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')]


def _table_order(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    info = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    primary = [
        str(row[1]) for row in sorted((row for row in info if int(row[5])), key=lambda row: row[5])
    ]
    return tuple(primary or ["rowid"])


def _schema_digest(connection: sqlite3.Connection) -> str:
    rows = [
        [_jsonable(value) for value in row]
        for row in connection.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_autoindex_%'
               ORDER BY type,name,tbl_name,sql"""
        ).fetchall()
    ]
    return hashlib.sha256(_canonical(rows)).hexdigest()


def _row_identity(table: str, row: sqlite3.Row) -> tuple[Any, ...] | None:
    specification = TARGET_IDENTITIES.get(table)
    if specification is None:
        return None
    columns, _ = specification
    return tuple(row[column] for column in columns)


def _is_target_row(table: str, row: sqlite3.Row) -> bool:
    specification = TARGET_IDENTITIES.get(table)
    if specification is None:
        return False
    _, identities = specification
    return _row_identity(table, row) in identities


def _value_markers(value: Any) -> set[str]:
    if isinstance(value, str):
        found = {marker for marker in _STRONG_MARKERS if marker in value}
        if value in _EXACT_MARKERS:
            found.add(value)
        stripped = value.lstrip()
        if not stripped or stripped[0] not in "[{":
            return found
        try:
            decoded = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return found
        return found | _decoded_markers(decoded)
    return set()


def _decoded_markers(value: Any) -> set[str]:
    if isinstance(value, str):
        found = {marker for marker in _STRONG_MARKERS if marker in value}
        if value in _EXACT_MARKERS:
            found.add(value)
        return found
    if isinstance(value, list):
        found: set[str] = set()
        for item in value:
            found.update(_decoded_markers(item))
        return found
    if isinstance(value, dict):
        found = set()
        for key, item in value.items():
            found.update(_decoded_markers(key))
            found.update(_decoded_markers(item))
        return found
    return set()


def _json_object(row: sqlite3.Row, column: str) -> dict[str, Any]:
    try:
        value = json.loads(str(row[column]))
    except (TypeError, json.JSONDecodeError) as exc:
        raise SyntheticLedgerCleanupError(f"{column} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SyntheticLedgerCleanupError(f"{column} is not a JSON object")
    return value


def _path(value: dict[str, Any], *parts: str) -> Any:
    current: Any = value
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _require_fields(label: str, row: sqlite3.Row, expected: dict[str, Any]) -> None:
    actual = {field: row[field] for field in expected}
    if actual != expected:
        raise SyntheticLedgerCleanupError(
            f"{label} binding mismatch: expected {expected!r}, got {actual!r}"
        )


def _require_json_paths(
    label: str,
    payload: dict[str, Any],
    expected: dict[tuple[str, ...], Any],
) -> None:
    mismatches = {
        ".".join(path): {"expected": value, "actual": _path(payload, *path)}
        for path, value in expected.items()
        if _path(payload, *path) != value
    }
    if mismatches:
        raise SyntheticLedgerCleanupError(f"{label} JSON binding mismatch: {mismatches!r}")


def _validate_target_rows(rows: dict[str, dict[tuple[Any, ...], sqlite3.Row]]) -> None:
    opportunity = rows["opportunities"][(OPPORTUNITY_KEY,)]
    _require_fields(
        "opportunity",
        opportunity,
        {
            "key": OPPORTUNITY_KEY,
            "repo": REPOSITORY,
            "issue_number": 1,
            "issue_url": ISSUE_URL,
            "title": OPPORTUNITY_KEY,
            "stage": "CLOSED",
            "terminal_reason": "SYNTHETIC_TEST_CONTEXT_NOT_FOUND",
        },
    )

    intent = rows["intents"][(INTENT_ID,)]
    _require_fields(
        "intent",
        intent,
        {
            "intent_id": INTENT_ID,
            "opportunity_key": OPPORTUNITY_KEY,
            "status": "COMPLETED",
            "thread_id": THREAD_ID,
            "worktree_path": WORKTREE_PATH,
        },
    )
    _require_json_paths(
        "intent",
        _json_object(intent, "payload_json"),
        {
            ("key",): OPPORTUNITY_KEY,
            ("repo",): REPOSITORY,
            ("issueNumber",): 1,
            ("issueUrl",): ISSUE_URL,
            ("intentId",): INTENT_ID,
            ("recoveredFromTaskContext",): True,
        },
    )

    request = rows["publication_requests"][(REQUEST_ID,)]
    _require_fields(
        "publication request",
        request,
        {
            "request_id": REQUEST_ID,
            "opportunity_key": OPPORTUNITY_KEY,
            "thread_id": THREAD_ID,
            "worktree_path": WORKTREE_PATH,
            "status": "CONSUMED",
            "permit_id": PERMIT_ID,
        },
    )
    _require_json_paths(
        "publication request",
        _json_object(request, "request_json"),
        {
            ("requestId",): REQUEST_ID,
            ("opportunityKey",): OPPORTUNITY_KEY,
            ("issueUrl",): ISSUE_URL,
            ("intentId",): INTENT_ID,
            ("threadId",): THREAD_ID,
            ("worktreePath",): WORKTREE_PATH,
            ("recoveredFromTaskContext",): True,
        },
    )

    permit = rows["publication_permits"][(PERMIT_ID,)]
    _require_fields(
        "publication permit",
        permit,
        {
            "permit_id": PERMIT_ID,
            "request_id": REQUEST_ID,
            "issue_url": ISSUE_URL,
            "status": "CONSUMED",
            "pr_url": PR_URL,
        },
    )

    if rows["outcomes"][(OPPORTUNITY_KEY,)]["opportunity_key"] != OPPORTUNITY_KEY:
        raise SyntheticLedgerCleanupError("outcome binding mismatch")

    for event_id, event_type in EVENT_TYPES.items():
        row = rows["events"][(event_id,)]
        _require_fields(
            f"event {event_id}",
            row,
            {
                "id": event_id,
                "opportunity_key": OPPORTUNITY_KEY,
                "event_type": event_type,
            },
        )
        payload = _json_object(row, "payload_json")
        if event_id == 1081029:
            _require_json_paths(
                f"event {event_id}",
                payload,
                {
                    ("liveAudit", "evidence", "repoProbeReceipt", "repo"): REPOSITORY,
                    ("liveAudit", "evidence", "repoProbeReceipt", "issueUrl"): ISSUE_URL,
                    ("liveAudit", "evidence", "repoProbeReceipt", "taskId"): INTENT_ID,
                },
            )
        elif event_id == 1081030:
            _require_json_paths(
                f"event {event_id}",
                payload,
                {
                    ("codePathTombstoneReceipt", "key"): OPPORTUNITY_KEY,
                    ("codePathTombstoneReceipt", "issueUrl"): ISSUE_URL,
                    ("codePathTombstoneReceipt", "intentId"): INTENT_ID,
                    ("codePathTombstoneReceipt", "prUrl"): PR_URL,
                    ("taskId",): INTENT_ID,
                    ("threadId",): THREAD_ID,
                },
            )
        elif event_id in {1081031, 1083036}:
            _require_json_paths(
                f"event {event_id}",
                payload,
                {("taskId",): INTENT_ID, ("threadId",): THREAD_ID},
            )
        elif event_id == 1081032:
            _require_json_paths(
                f"event {event_id}",
                payload,
                {("permitId",): PERMIT_ID, ("prUrl",): PR_URL},
            )
        elif event_id in {1081033, 1081795}:
            _require_json_paths(
                f"event {event_id}",
                payload,
                {
                    ("intentId",): INTENT_ID,
                    ("threadId",): THREAD_ID,
                    ("worktreePath",): WORKTREE_PATH,
                },
            )
        elif event_id == 1081039:
            _require_json_paths(f"event {event_id}", payload, {("issueUrl",): ISSUE_URL})

    for quarantine_id, reason in QUARANTINE_REASONS.items():
        _require_fields(
            f"quarantine {quarantine_id}",
            rows["task_quarantines"][(quarantine_id,)],
            {
                "quarantine_id": quarantine_id,
                "opportunity_key": OPPORTUNITY_KEY,
                "reason": reason,
                "status": "ACTIVE",
            },
        )

    for event_id, event_type in LIFECYCLE_EVENTS.items():
        _require_fields(
            f"managed lifecycle event {event_id}",
            rows["managed_lifecycle_events"][(event_id,)],
            {
                "event_id": event_id,
                "opportunity_key": OPPORTUNITY_KEY,
                "task_id": INTENT_ID,
                "pr_key": None,
                "event_type": event_type,
            },
        )


def _scan_and_snapshot(
    connection: sqlite3.Connection,
) -> tuple[dict[str, dict[tuple[Any, ...], sqlite3.Row]], dict[str, Any]]:
    tables = _user_tables(connection)
    missing_tables = sorted(set(TARGET_IDENTITIES) - set(tables))
    if missing_tables:
        raise SyntheticLedgerCleanupError(f"required tables are missing: {missing_tables}")

    target_rows: dict[str, dict[tuple[Any, ...], sqlite3.Row]] = {
        table: {} for table in TARGET_IDENTITIES
    }
    unexpected: list[dict[str, Any]] = []
    table_summaries: dict[str, dict[str, Any]] = {}

    for table in tables:
        columns = _table_columns(connection, table)
        required = TARGET_IDENTITIES.get(table)
        if required is not None:
            missing_columns = sorted(set(required[0]) - set(columns))
            if missing_columns:
                raise SyntheticLedgerCleanupError(
                    f"required identity columns are missing from {table}: {missing_columns}"
                )
        select_columns = ",".join(f'"{column}"' for column in columns)
        order_columns = _table_order(connection, table)
        order_clause = ",".join(
            "rowid" if column == "rowid" else f'"{column}"' for column in order_columns
        )
        digest = hashlib.sha256()
        count = 0
        query = f'SELECT {select_columns} FROM "{table}" ORDER BY {order_clause}'
        for row in connection.execute(query):
            markers: set[str] = set()
            for value in row:
                markers.update(_value_markers(value))
            if _is_target_row(table, row):
                identity = _row_identity(table, row)
                assert identity is not None
                target_rows[table][identity] = row
                continue
            if markers:
                identity_columns = _table_order(connection, table)
                unexpected.append(
                    {
                        "table": table,
                        "identity": {
                            column: row[column]
                            for column in identity_columns
                            if column != "rowid" and column in row.keys()
                        },
                        "markers": sorted(markers),
                    }
                )
                if len(unexpected) >= 20:
                    break
            encoded = _canonical({column: _jsonable(row[column]) for column in columns})
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            count += 1
        if unexpected:
            break
        table_summaries[table] = {
            "rowCount": count,
            "contentDigest": digest.hexdigest(),
        }

    if unexpected:
        raise SyntheticLedgerCleanupError(
            "unexpected synthetic association outside the fixed deletion set: "
            + json.dumps(unexpected, ensure_ascii=False, sort_keys=True)
        )

    for table, (_, expected) in TARGET_IDENTITIES.items():
        actual = frozenset(target_rows[table])
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise SyntheticLedgerCleanupError(
                f"{table} target identity mismatch: missing={missing!r}, extra={extra!r}"
            )
    _validate_target_rows(target_rows)
    snapshot = {
        "tables": table_summaries,
        "overallDigest": hashlib.sha256(_canonical(table_summaries)).hexdigest(),
    }
    return target_rows, snapshot


def _integrity(connection: sqlite3.Connection) -> dict[str, Any]:
    foreign_key_rows = [list(row) for row in connection.execute("PRAGMA foreign_key_check")]
    integrity_rows = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
    if foreign_key_rows:
        raise SyntheticLedgerCleanupError(f"foreign key check failed: {foreign_key_rows[:20]!r}")
    if integrity_rows != ["ok"]:
        raise SyntheticLedgerCleanupError(f"integrity check failed: {integrity_rows!r}")
    return {"foreignKeyCheck": [], "integrityCheck": integrity_rows}


def _deletion_manifest() -> list[dict[str, Any]]:
    order = (
        "publication_permits",
        "publication_requests",
        "outcomes",
        "events",
        "task_quarantines",
        "managed_lifecycle_events",
        "intents",
        "opportunities",
    )
    result: list[dict[str, Any]] = []
    for table in order:
        columns, identities = TARGET_IDENTITIES[table]
        result.append(
            {
                "table": table,
                "primaryKeyColumns": list(columns),
                "primaryKeys": [list(identity) for identity in sorted(identities)],
                "rowCount": len(identities),
            }
        )
    return result


def preflight_known_synthetic_graph(source: Path) -> dict[str, Any]:
    """Read and validate the source without creating or changing any file."""

    source = source.resolve()
    if not source.is_file():
        raise SyntheticLedgerCleanupError("source ledger does not exist or is not a regular file")
    connection = _read_only(source)
    try:
        connection.execute("BEGIN")
        _, non_target = _scan_and_snapshot(connection)
        checks = _integrity(connection)
        schema_digest = _schema_digest(connection)
        trigger = connection.execute(
            """SELECT sql FROM sqlite_master
               WHERE type='trigger' AND name='managed_events_no_delete'"""
        ).fetchone()
        if trigger is None or not trigger[0]:
            raise SyntheticLedgerCleanupError("managed lifecycle delete guard is missing")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {
        "schema": SCHEMA,
        "mode": "preflight",
        "ok": True,
        "source": str(source),
        "plannedDeletion": _deletion_manifest(),
        "nonTarget": non_target,
        "schemaDigest": schema_digest,
        **checks,
    }


def _exclusive_backup(source: Path, output: Path) -> None:
    source = source.resolve()
    output = output.resolve()
    if source == output:
        raise SyntheticLedgerCleanupError("output must differ from the source ledger")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise SyntheticLedgerCleanupError(
            "output already exists; refusing to overwrite it"
        ) from exc
    os.close(descriptor)
    try:
        source_connection = _read_only(source)
        output_connection = sqlite3.connect(output, timeout=30, isolation_level=None)
        try:
            source_connection.backup(output_connection)
        finally:
            output_connection.close()
            source_connection.close()
        os.chmod(output, 0o600)
    except Exception:
        output.unlink(missing_ok=True)
        for suffix in ("-shm", "-wal", "-journal"):
            Path(str(output) + suffix).unlink(missing_ok=True)
        raise


def _delete_identity_rows(
    connection: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
    identities: Iterable[tuple[Any, ...]],
) -> int:
    deleted = 0
    where = " AND ".join(f'"{column}"=?' for column in columns)
    for identity in sorted(identities):
        cursor = connection.execute(f'DELETE FROM "{table}" WHERE {where}', identity)
        if cursor.rowcount != 1:
            raise SyntheticLedgerCleanupError(
                f"delete count mismatch for {table} {identity!r}: {cursor.rowcount}"
            )
        deleted += 1
    return deleted


def _assert_graph_absent(connection: sqlite3.Connection) -> None:
    residual: list[dict[str, Any]] = []
    for table, (columns, identities) in TARGET_IDENTITIES.items():
        where = " AND ".join(f'"{column}"=?' for column in columns)
        for identity in identities:
            count = int(
                connection.execute(
                    f'SELECT COUNT(*) FROM "{table}" WHERE {where}', identity
                ).fetchone()[0]
            )
            if count:
                residual.append({"table": table, "identity": list(identity), "count": count})
    if residual:
        raise SyntheticLedgerCleanupError(f"target graph was not fully removed: {residual!r}")

    for table in _user_tables(connection):
        columns = _table_columns(connection, table)
        select_columns = ",".join(f'"{column}"' for column in columns)
        for row in connection.execute(f'SELECT {select_columns} FROM "{table}"'):
            markers: set[str] = set()
            for value in row:
                markers.update(_value_markers(value))
            if markers:
                residual.append({"table": table, "markers": sorted(markers)})
                if len(residual) >= 20:
                    break
        if residual:
            break
    if residual:
        raise SyntheticLedgerCleanupError(
            "synthetic markers remain after deletion: "
            + json.dumps(residual, ensure_ascii=False, sort_keys=True)
        )


def _non_target_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    table_summaries: dict[str, dict[str, Any]] = {}
    for table in _user_tables(connection):
        columns = _table_columns(connection, table)
        select_columns = ",".join(f'"{column}"' for column in columns)
        order_columns = _table_order(connection, table)
        order_clause = ",".join(
            "rowid" if column == "rowid" else f'"{column}"' for column in order_columns
        )
        digest = hashlib.sha256()
        count = 0
        for row in connection.execute(
            f'SELECT {select_columns} FROM "{table}" ORDER BY {order_clause}'
        ):
            if _is_target_row(table, row):
                continue
            encoded = _canonical({column: _jsonable(row[column]) for column in columns})
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
            count += 1
        table_summaries[table] = {
            "rowCount": count,
            "contentDigest": digest.hexdigest(),
        }
    return {
        "tables": table_summaries,
        "overallDigest": hashlib.sha256(_canonical(table_summaries)).hexdigest(),
    }


def copy_and_clean_known_synthetic_graph(source: Path, output: Path) -> dict[str, Any]:
    """Copy ``source`` and remove the exact synthetic graph from ``output`` only."""

    source = source.resolve()
    output = output.resolve()
    if not source.is_file():
        raise SyntheticLedgerCleanupError("source ledger does not exist or is not a regular file")

    # The backup is intentionally the first operation in execution mode.  All
    # validation and deletion from this point forward targets the explicit copy.
    _exclusive_backup(source, output)
    before = preflight_known_synthetic_graph(output)

    connection = sqlite3.connect(output, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=DELETE")
    trigger_row = connection.execute(
        """SELECT sql FROM sqlite_master
           WHERE type='trigger' AND name='managed_events_no_delete'"""
    ).fetchone()
    if trigger_row is None or not trigger_row[0]:
        connection.close()
        raise SyntheticLedgerCleanupError("managed lifecycle delete guard is missing from copy")
    trigger_sql = str(trigger_row[0])
    deletion_counts: list[dict[str, Any]] = []
    try:
        connection.execute("BEGIN IMMEDIATE")
        for table in (
            "publication_permits",
            "publication_requests",
            "outcomes",
            "events",
            "task_quarantines",
        ):
            columns, identities = TARGET_IDENTITIES[table]
            deletion_counts.append(
                {
                    "table": table,
                    "rowCount": _delete_identity_rows(connection, table, columns, identities),
                }
            )

        # The managed event is append-only in normal operation.  The repair
        # temporarily removes only its delete guard inside the same transaction
        # and recreates the byte-identical trigger before any validation/commit.
        connection.execute("DROP TRIGGER managed_events_no_delete")
        table = "managed_lifecycle_events"
        columns, identities = TARGET_IDENTITIES[table]
        deletion_counts.append(
            {
                "table": table,
                "rowCount": _delete_identity_rows(connection, table, columns, identities),
            }
        )
        connection.execute(trigger_sql)

        for table in ("intents", "opportunities"):
            columns, identities = TARGET_IDENTITIES[table]
            deletion_counts.append(
                {
                    "table": table,
                    "rowCount": _delete_identity_rows(connection, table, columns, identities),
                }
            )

        _assert_graph_absent(connection)
        in_transaction_snapshot = _non_target_snapshot(connection)
        if in_transaction_snapshot != before["nonTarget"]:
            raise SyntheticLedgerCleanupError("non-target data changed during cleanup")
        if _schema_digest(connection) != before["schemaDigest"]:
            raise SyntheticLedgerCleanupError("database schema changed during cleanup")
        _integrity(connection)
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()

    verification = _read_only(output)
    try:
        verification.execute("BEGIN")
        _assert_graph_absent(verification)
        after_non_target = _non_target_snapshot(verification)
        checks = _integrity(verification)
        after_schema = _schema_digest(verification)
        verification.execute("COMMIT")
    except Exception:
        if verification.in_transaction:
            verification.execute("ROLLBACK")
        raise
    finally:
        verification.close()

    if after_non_target != before["nonTarget"]:
        raise SyntheticLedgerCleanupError("committed copy changed non-target data")
    if after_schema != before["schemaDigest"]:
        raise SyntheticLedgerCleanupError("committed copy changed database schema")

    descriptor = os.open(output, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(output, 0o600)
    return {
        "schema": SCHEMA,
        "mode": "execute-copy",
        "ok": True,
        "source": str(source),
        "output": str(output),
        "deleted": deletion_counts,
        "nonTargetBefore": before["nonTarget"],
        "nonTargetAfter": after_non_target,
        "nonTargetStable": True,
        "schemaDigestBefore": before["schemaDigest"],
        "schemaDigestAfter": after_schema,
        "schemaStable": True,
        **checks,
    }
