from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import migrate_schema
from oss_pr_radar.synthetic_ledger_cleanup import (
    EVENT_TYPES,
    INTENT_ID,
    ISSUE_URL,
    LIFECYCLE_EVENTS,
    OPPORTUNITY_KEY,
    PERMIT_ID,
    PR_URL,
    QUARANTINE_REASONS,
    REPOSITORY,
    REQUEST_ID,
    THREAD_ID,
    WORKTREE_PATH,
    SyntheticLedgerCleanupError,
    copy_and_clean_known_synthetic_graph,
    preflight_known_synthetic_graph,
)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_database(tmp_path: Path) -> Path:
    database = tmp_path / "source.sqlite3"
    RadarLedger(database)
    migrate_schema(database)
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        """INSERT INTO opportunities
           (key,repo,issue_number,issue_url,title,stage,first_seen,updated_at,
            snapshot_id,decision_digest,terminal_reason,metadata_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "real/repo#2",
            "real/repo",
            2,
            "https://github.com/real/repo/issues/2",
            "real issue",
            "QUALIFIED",
            "now",
            "now",
            None,
            None,
            None,
            "{}",
        ),
    )
    connection.execute(
        """INSERT INTO outcomes
           (opportunity_key,quality_json,updated_at) VALUES (?,?,?)""",
        ("real/repo#2", '{"real":true}', "now"),
    )
    connection.execute(
        """INSERT INTO managed_lifecycle_events
           (event_id,opportunity_key,task_id,pr_key,event_type,state,idempotency_key,
            idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            230881,
            "real/repo#2",
            "real-task",
            None,
            "REAL_EVENT",
            "OPEN",
            "real-event",
            "real-fingerprint",
            "test",
            "{}",
            "now",
            "{}",
        ),
    )

    connection.execute(
        """INSERT INTO opportunities
           (key,repo,issue_number,issue_url,title,stage,first_seen,updated_at,
            snapshot_id,decision_digest,terminal_reason,metadata_json)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            OPPORTUNITY_KEY,
            REPOSITORY,
            1,
            ISSUE_URL,
            OPPORTUNITY_KEY,
            "CLOSED",
            "synthetic-now",
            "synthetic-now",
            "decision",
            "decision",
            "SYNTHETIC_TEST_CONTEXT_NOT_FOUND",
            '{"recoveredFromTaskContext":true}',
        ),
    )
    intent_payload = {
        "key": OPPORTUNITY_KEY,
        "repo": REPOSITORY,
        "issueNumber": 1,
        "issueUrl": ISSUE_URL,
        "intentId": INTENT_ID,
        "recoveredFromTaskContext": True,
    }
    connection.execute(
        """INSERT INTO intents
           (intent_id,opportunity_key,intent_digest,status,issued_at,expires_at,
            thread_id,project_id,worktree_path,payload_json,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            INTENT_ID,
            OPPORTUNITY_KEY,
            "decision",
            "COMPLETED",
            "synthetic-now",
            "synthetic-later",
            THREAD_ID,
            "github",
            WORKTREE_PATH,
            _json(intent_payload),
            "synthetic-now",
        ),
    )
    event_payloads = {
        1081029: {
            "liveAudit": {
                "evidence": {
                    "repoProbeReceipt": {
                        "repo": REPOSITORY,
                        "issueUrl": ISSUE_URL,
                        "taskId": INTENT_ID,
                    }
                }
            }
        },
        1081030: {
            "codePathTombstoneReceipt": {
                "key": OPPORTUNITY_KEY,
                "issueUrl": ISSUE_URL,
                "intentId": INTENT_ID,
                "prUrl": PR_URL,
            },
            "taskId": INTENT_ID,
            "threadId": THREAD_ID,
        },
        1081031: {"taskId": INTENT_ID, "threadId": THREAD_ID},
        1081032: {"permitId": PERMIT_ID, "prUrl": PR_URL},
        1081033: {
            "intentId": INTENT_ID,
            "threadId": THREAD_ID,
            "worktreePath": WORKTREE_PATH,
        },
        1081039: {"issueUrl": ISSUE_URL},
        1081795: {
            "intentId": INTENT_ID,
            "threadId": THREAD_ID,
            "worktreePath": WORKTREE_PATH,
        },
        1083036: {"taskId": INTENT_ID, "threadId": THREAD_ID},
    }
    for event_id, event_type in EVENT_TYPES.items():
        connection.execute(
            """INSERT INTO events
               (id,opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?,?)""",
            (
                event_id,
                OPPORTUNITY_KEY,
                event_type,
                f"synthetic-{event_id}",
                _json(event_payloads[event_id]),
                "synthetic-now",
            ),
        )
    connection.execute(
        """INSERT INTO outcomes
           (opportunity_key,selected_at,submit_ready_at,quality_json,updated_at)
           VALUES (?,?,?,?,?)""",
        (OPPORTUNITY_KEY, "synthetic-now", "synthetic-now", "{}", "synthetic-now"),
    )
    request_payload = {
        "requestId": REQUEST_ID,
        "opportunityKey": OPPORTUNITY_KEY,
        "issueUrl": ISSUE_URL,
        "intentId": INTENT_ID,
        "threadId": THREAD_ID,
        "worktreePath": WORKTREE_PATH,
        "recoveredFromTaskContext": True,
    }
    connection.execute(
        """INSERT INTO publication_requests
           (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
            evidence_digest,status,permit_id,request_json,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            REQUEST_ID,
            OPPORTUNITY_KEY,
            THREAD_ID,
            "synthetic-sha",
            "fix/1-runtime-boundary",
            WORKTREE_PATH,
            "decision",
            "CONSUMED",
            PERMIT_ID,
            _json(request_payload),
            "synthetic-now",
            "synthetic-now",
        ),
    )
    connection.execute(
        """INSERT INTO publication_permits
           (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
            pr_url,evidence_json,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            PERMIT_ID,
            REQUEST_ID,
            ISSUE_URL,
            "synthetic-sha",
            "fix/1-runtime-boundary",
            "CONSUMED",
            "synthetic-now",
            PR_URL,
            "{}",
            "synthetic-now",
            "synthetic-now",
        ),
    )
    for quarantine_id, reason in QUARANTINE_REASONS.items():
        connection.execute(
            """INSERT INTO task_quarantines
               (quarantine_id,opportunity_key,reason,dedupe_key,payload_json,status,created_at)
               VALUES (?,?,?,?,?,'ACTIVE',?)""",
            (
                quarantine_id,
                OPPORTUNITY_KEY,
                reason,
                f"synthetic-quarantine-{quarantine_id}",
                _json({"issueUrl": ISSUE_URL}) if quarantine_id != 6634 else "{}",
                "synthetic-now",
            ),
        )
    for event_id, event_type in LIFECYCLE_EVENTS.items():
        connection.execute(
            """INSERT INTO managed_lifecycle_events
               (event_id,opportunity_key,task_id,pr_key,event_type,state,idempotency_key,
                idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id,
                OPPORTUNITY_KEY,
                INTENT_ID,
                None,
                event_type,
                "IMPLEMENTATION_READY",
                "synthetic-lifecycle",
                "synthetic-lifecycle-fingerprint",
                "task-context",
                "{}",
                "synthetic-now",
                "{}",
            ),
        )
    connection.commit()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    return database


def test_default_preflight_is_read_only_and_reports_exact_graph(tmp_path: Path) -> None:
    source = _fixture_database(tmp_path)
    before = _file_sha(source)

    result = preflight_known_synthetic_graph(source)

    assert result["ok"] is True
    assert result["mode"] == "preflight"
    assert _file_sha(source) == before
    deletion = {item["table"]: item["rowCount"] for item in result["plannedDeletion"]}
    assert deletion == {
        "publication_permits": 1,
        "publication_requests": 1,
        "outcomes": 1,
        "events": 8,
        "task_quarantines": 4,
        "managed_lifecycle_events": 1,
        "intents": 1,
        "opportunities": 1,
    }
    assert result["foreignKeyCheck"] == []
    assert result["integrityCheck"] == ["ok"]


def test_execute_cleans_only_new_copy_and_preserves_guard_and_non_target_data(
    tmp_path: Path,
) -> None:
    source = _fixture_database(tmp_path)
    output = tmp_path / "sanitized.sqlite3"
    source_before = _file_sha(source)

    result = copy_and_clean_known_synthetic_graph(source, output)

    assert _file_sha(source) == source_before
    assert output.is_file()
    assert output.stat().st_mode & 0o777 == 0o600
    assert result["nonTargetStable"] is True
    assert result["nonTargetBefore"] == result["nonTargetAfter"]
    assert result["schemaStable"] is True
    assert sum(item["rowCount"] for item in result["deleted"]) == 18

    connection = sqlite3.connect(output)
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM opportunities WHERE key=?", (OPPORTUNITY_KEY,)
        ).fetchone()[0]
        == 0
    )
    assert (
        connection.execute("SELECT COUNT(*) FROM opportunities WHERE key='real/repo#2'").fetchone()[
            0
        ]
        == 1
    )
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM outcomes WHERE opportunity_key='real/repo#2'"
        ).fetchone()[0]
        == 1
    )
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        connection.execute("DELETE FROM managed_lifecycle_events WHERE event_id=230881")
    connection.close()


def test_execute_refuses_to_overwrite_explicit_output(tmp_path: Path) -> None:
    source = _fixture_database(tmp_path)
    output = tmp_path / "existing.sqlite3"
    output.write_bytes(b"keep-me")

    with pytest.raises(SyntheticLedgerCleanupError, match="refusing to overwrite"):
        copy_and_clean_known_synthetic_graph(source, output)

    assert output.read_bytes() == b"keep-me"


def test_extra_association_fails_closed(tmp_path: Path) -> None:
    source = _fixture_database(tmp_path)
    with sqlite3.connect(source) as connection:
        connection.execute(
            """INSERT INTO publication_effects
               (effect_id,permit_id,action,request_digest,status,result_json,created_at,updated_at)
               VALUES ('unexpected-effect',?,'CREATE_PR','digest','DONE','{}','now','now')""",
            (PERMIT_ID,),
        )

    with pytest.raises(SyntheticLedgerCleanupError, match="unexpected synthetic association"):
        preflight_known_synthetic_graph(source)


def test_missing_or_cross_linked_expected_row_fails_closed(tmp_path: Path) -> None:
    missing = _fixture_database(tmp_path / "missing")
    with sqlite3.connect(missing) as connection:
        connection.execute("DELETE FROM task_quarantines WHERE quarantine_id=53952")
    with pytest.raises(SyntheticLedgerCleanupError, match="target identity mismatch"):
        preflight_known_synthetic_graph(missing)

    cross_linked = _fixture_database(tmp_path / "cross-linked")
    with sqlite3.connect(cross_linked) as connection:
        connection.execute("DROP TRIGGER managed_events_no_update")
        connection.execute(
            "UPDATE managed_lifecycle_events SET pr_key='real/repo#7' WHERE event_id=230882"
        )
        connection.execute(
            """CREATE TRIGGER managed_events_no_update
               BEFORE UPDATE ON managed_lifecycle_events
               BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END"""
        )
    with pytest.raises(SyntheticLedgerCleanupError, match="binding mismatch"):
        preflight_known_synthetic_graph(cross_linked)
