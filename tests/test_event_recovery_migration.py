from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from oss_pr_radar.agentscope_events import EventLane
from scripts import migrate_event_recovery_chains as migration


def _add_recovery(
    lane: EventLane,
    *,
    namespace: str,
    event_id: str,
    source_event_id: str,
    event_key: str,
    turn_status: str,
    valid_outcome: bool,
) -> None:
    event = {
        "eventId": event_id,
        "kind": "outcome_reconcile",
        "eventKey": event_key,
        "payload": {
            "eventId": source_event_id,
            "publicKey": event_key,
            "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
        },
    }
    if namespace == "agentscope":
        event["eventIdSource"] = source_event_id
    assert lane.append(event, priority=250)
    outcome = (
        {
            "schemaVersion": f"{namespace}_event_outcome_v1",
            "eventId": event_id,
            "publicKey": event_key,
            "state": "no_action",
        }
        if valid_outcome
        else {"error": "OUTCOME_MISSING_OR_INVALID"}
    )
    receipt = {
        "turnStatus": "completed" if valid_outcome else "failed",
        "outcome": outcome,
    }
    lane.reserve_handler_turn(event_key, event_id, f"client:{event_id}")
    lane.bind_handler_turn(
        event_key,
        event_id,
        "thread-1",
        f"turn:{event_id}",
        receipt,
        status=turn_status,
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered',attempts=1 WHERE event_id=?",
            (event_id,),
        )


def _add_stable_recovery(
    lane: EventLane,
    *,
    namespace: str,
    root_event_id: str,
    event_key: str,
) -> str:
    recovery_id = (
        f"outcome-reconcile:{namespace}:"
        + hashlib.sha256(root_event_id.encode("utf-8")).hexdigest()
    )
    assert lane.append(
        {
            "eventId": recovery_id,
            "kind": "outcome_reconcile",
            "eventKey": event_key,
            "rootEventId": root_event_id,
            "eventIdSource": root_event_id,
            "payload": {
                "rootEventId": root_event_id,
                "eventId": root_event_id,
                "publicKey": event_key,
            },
        },
        priority=250,
    )
    lane.reserve_handler_turn(event_key, recovery_id, f"client:{recovery_id}")
    lane.bind_handler_turn(
        event_key,
        recovery_id,
        "thread-1",
        f"turn:{recovery_id}",
        {
            "turnStatus": "completed",
            "eventId": recovery_id,
            "eventKey": event_key,
            "outcome": {
                "schemaVersion": f"{namespace}_event_outcome_v1",
                "eventId": recovery_id,
                "publicKey": event_key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered',attempts=1 WHERE event_id=?",
            (recovery_id,),
        )
    return recovery_id


@pytest.mark.parametrize("namespace", ["agentscope", "nanobot"])
def test_recovery_chain_migration_is_dry_run_evidence_preserving_and_idempotent(
    tmp_path: Path,
    namespace: str,
) -> None:
    database = tmp_path / f"{namespace}-events.sqlite3"
    lane = EventLane(database)
    event_key = (
        "agentscope-ai/agentscope#2441" if namespace == "agentscope" else "HKUDS/nanobot#5524"
    )
    root_event_id = f"{namespace}-root"
    root_event = {
        "eventId": root_event_id,
        "eventKey": event_key,
        "payload": {"originalEvidence": True},
    }
    assert lane.append(root_event)
    root_receipt = {
        "turnStatus": "completed",
        "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
    }
    lane.reserve_handler_turn(event_key, root_event_id, "client:root")
    lane.bind_handler_turn(
        event_key,
        root_event_id,
        "thread-1",
        "turn:root",
        root_receipt,
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered',attempts=1 WHERE event_id=?",
            (root_event_id,),
        )
    recovery_one = f"outcome-reconcile:{namespace}:legacy-1"
    recovery_two = f"outcome-reconcile:{namespace}:legacy-2"
    final_recovery = f"outcome-reconcile:{namespace}:legacy-final"
    _add_recovery(
        lane,
        namespace=namespace,
        event_id=recovery_one,
        source_event_id=root_event_id,
        event_key=event_key,
        turn_status="needs_reconcile",
        valid_outcome=False,
    )
    _add_recovery(
        lane,
        namespace=namespace,
        event_id=recovery_two,
        source_event_id=recovery_one,
        event_key=event_key,
        turn_status="needs_reconcile",
        valid_outcome=False,
    )
    _add_recovery(
        lane,
        namespace=namespace,
        event_id=final_recovery,
        source_event_id=recovery_two,
        event_key=event_key,
        turn_status="completed",
        valid_outcome=True,
    )

    uncovered = f"outcome-reconcile:{namespace}:uncovered"
    _add_recovery(
        lane,
        namespace=namespace,
        event_id=uncovered,
        source_event_id=f"{namespace}-uncovered-root",
        event_key=event_key,
        turn_status="completed",
        valid_outcome=False,
    )
    with lane.connect() as db:
        evidence_before = {
            row["event_id"]: (row["payload_json"], row["receipt_json"])
            for row in db.execute(
                "SELECT e.event_id,e.payload_json,t.receipt_json "
                "FROM event_lane_events e JOIN event_lane_turns t USING(event_id)"
            )
        }

    preview = migration.migrate_recovery_chains(
        database,
        namespace=namespace,
    )
    assert preview["mode"] == "dry-run"
    assert preview["eventsToCoalesce"] == 2
    assert preview["turnsToSupersede"] == 3
    assert preview["rootTurnsToSupersede"] == 1
    assert preview["changed"] == 0
    with lane.connect() as db:
        assert (
            db.execute(
                "SELECT status FROM event_lane_events WHERE event_id=?",
                (recovery_one,),
            ).fetchone()[0]
            == "delivered"
        )

    applied = migration.migrate_recovery_chains(
        database,
        namespace=namespace,
        apply=True,
    )
    assert applied["eventsChanged"] == 2
    assert applied["turnsChanged"] == 3
    assert applied["changed"] == 5
    with lane.connect() as db:
        event_statuses = dict(
            db.execute("SELECT event_id,status FROM event_lane_events").fetchall()
        )
        turn_statuses = dict(db.execute("SELECT event_id,status FROM event_lane_turns").fetchall())
        evidence_after = {
            row["event_id"]: (row["payload_json"], row["receipt_json"])
            for row in db.execute(
                "SELECT e.event_id,e.payload_json,t.receipt_json "
                "FROM event_lane_events e JOIN event_lane_turns t USING(event_id)"
            )
        }
    assert event_statuses[recovery_one] == "coalesced"
    assert event_statuses[recovery_two] == "coalesced"
    assert event_statuses[root_event_id] == "delivered"
    assert turn_statuses[root_event_id] == "superseded"
    assert turn_statuses[recovery_one] == "superseded"
    assert turn_statuses[recovery_two] == "superseded"
    assert event_statuses[final_recovery] == "delivered"
    assert turn_statuses[final_recovery] == "completed"
    assert event_statuses[uncovered] == "delivered"
    assert turn_statuses[uncovered] == "completed"
    assert evidence_after == evidence_before

    second = migration.migrate_recovery_chains(
        database,
        namespace=namespace,
        apply=True,
    )
    assert second["eventsToCoalesce"] == 0
    assert second["turnsToSupersede"] == 0
    assert second["rootTurnsToSupersede"] == 0
    assert second["changed"] == 0


def test_direct_valid_recovery_supersedes_only_needs_reconcile_root_turn(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    event_key = "agentscope-ai/agentscope#2405"
    root_event_id = "agentscope-direct-root"
    root_payload = {
        "eventId": root_event_id,
        "eventKey": event_key,
        "payload": {"originalEvidence": "preserve"},
    }
    assert lane.append(root_payload)
    lane.reserve_handler_turn(event_key, root_event_id, "client:root")
    lane.bind_handler_turn(
        event_key,
        root_event_id,
        "thread-1",
        "turn:root",
        {"turnStatus": "completed", "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"}},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered',attempts=1 WHERE event_id=?",
            (root_event_id,),
        )
    final_recovery = "outcome-reconcile:agentscope:direct-final"
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=final_recovery,
        source_event_id=root_event_id,
        event_key=event_key,
        turn_status="completed",
        valid_outcome=True,
    )
    with lane.connect() as db:
        original_payload_json = db.execute(
            "SELECT payload_json FROM event_lane_events WHERE event_id=?",
            (root_event_id,),
        ).fetchone()[0]

    preview = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
    )
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 1
    assert preview["rootTurnsToSupersede"] == 1

    applied = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        apply=True,
    )
    assert applied["eventsChanged"] == 0
    assert applied["turnsChanged"] == 1
    with lane.connect() as db:
        root_event = db.execute(
            "SELECT status,payload_json FROM event_lane_events WHERE event_id=?",
            (root_event_id,),
        ).fetchone()
        root_turn_status = db.execute(
            "SELECT status FROM event_lane_turns WHERE event_id=?",
            (root_event_id,),
        ).fetchone()[0]
        final_event_status = db.execute(
            "SELECT status FROM event_lane_events WHERE event_id=?",
            (final_recovery,),
        ).fetchone()[0]
        final_turn_status = db.execute(
            "SELECT status FROM event_lane_turns WHERE event_id=?",
            (final_recovery,),
        ).fetchone()[0]
    assert root_event["status"] == "delivered"
    assert root_event["payload_json"] == original_payload_json
    assert root_turn_status == "superseded"
    assert final_event_status == "delivered"
    assert final_turn_status == "completed"


def test_valid_recovery_coalesces_needs_reconcile_root_event_and_turn(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    event_key = "agentscope-ai/agentscope#2448"
    root_event_id = "agentscope-root-needs-reconcile"
    assert lane.append(
        {
            "eventId": root_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2448,
            "kind": "issue_update",
            "updatedAt": "2026-08-27T09:51:38Z",
        }
    )
    lane.reserve_handler_turn(event_key, root_event_id, "client:root")
    lane.bind_handler_turn(
        event_key,
        root_event_id,
        "thread-1",
        "turn:root",
        {"terminalReason": "handler_start_exception"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
            (root_event_id,),
        )
    final_recovery = "outcome-reconcile:agentscope:stable"
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=final_recovery,
        source_event_id=root_event_id,
        event_key=event_key,
        turn_status="completed",
        valid_outcome=True,
    )

    preview = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
    )
    assert preview["eventsToCoalesce"] == 1
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["turnsToSupersede"] == 1

    applied = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        apply=True,
    )
    assert applied["changed"] == 2
    with lane.connect() as db:
        root_status = db.execute(
            "SELECT status FROM event_lane_events WHERE event_id=?", (root_event_id,)
        ).fetchone()[0]
        turn_status = db.execute(
            "SELECT status FROM event_lane_turns WHERE event_id=?", (root_event_id,)
        ).fetchone()[0]
    assert root_status == "coalesced"
    assert turn_status == "superseded"


def test_ordinary_later_outcome_is_not_inferred_and_baseline_requires_explicit_plan(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    event_key = "agentscope-ai/agentscope#2397"
    old_event_id = "github:agentscope-ai/agentscope:2397:pr_update:old"
    assert lane.append(
        {
            "eventId": old_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2397,
            "kind": "pr_update",
            "updatedAt": "2026-08-25T15:16:46Z",
        },
        now=1,
    )
    with lane.connect() as db:
        old_event_id = db.execute(
            "SELECT event_id FROM event_lane_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()[0]
    lane.reserve_handler_turn("agentscope-ai/agentscope#2385", old_event_id, "client:misbound")
    lane.bind_handler_turn(
        "agentscope-ai/agentscope#2385",
        old_event_id,
        "",
        "",
        {"terminalReason": "handler_turn_timeout"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (old_event_id,),
        )

    final_event_id = "github:agentscope-ai/agentscope:2397:pr_update:new"
    assert lane.append(
        {
            "eventId": final_event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2397,
            "kind": "pr_update",
            "updatedAt": "2026-08-25T15:16:47Z",
        },
        now=2,
    )
    with lane.connect() as db:
        final_event_id = db.execute(
            "SELECT event_id FROM event_lane_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()[0]
    lane.reserve_handler_turn(event_key, final_event_id, "client:final")
    lane.bind_handler_turn(
        event_key,
        final_event_id,
        "thread-1",
        "turn:final",
        {
            "turnStatus": "completed",
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": final_event_id,
                "publicKey": event_key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id=?",
            (final_event_id,),
        )

    baseline_id = "github:agentscope-ai/agentscope:2364:issue_update:baseline"
    baseline_key = "agentscope-ai/agentscope#2364"
    assert lane.append(
        {
            "eventId": baseline_id,
            "eventKey": baseline_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2364,
            "kind": "issue_update",
            "updatedAt": "2026-08-22T17:08:35Z",
        },
        now=3,
    )
    lane.reserve_handler_turn(baseline_key, baseline_id, "client:baseline")
    lane.bind_handler_turn(
        baseline_key,
        baseline_id,
        "",
        "",
        {"terminalReason": "handler_turn_timeout"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='baseline' WHERE event_id=?",
            (baseline_id,),
        )

    implicit = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert implicit["eventsToCoalesce"] == 0
    assert implicit["turnsToSupersede"] == 0

    coverage = {
        "schemaVersion": "event-recovery-legacy-coverage-v1",
        "namespace": "agentscope",
        "baselineRoots": [
            {
                "rootEventId": baseline_id,
                "expectedEventKey": baseline_key,
                "expectedTurnEventKey": baseline_key,
            }
        ],
    }
    preview = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        legacy_coverage=coverage,
    )
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 1
    assert [item["coverageType"] for item in preview["chains"]] == ["bootstrap_baseline"]
    migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        apply=True,
        legacy_coverage=coverage,
    )
    with lane.connect() as db:
        statuses = dict(
            db.execute(
                "SELECT event_id,status FROM event_lane_events WHERE event_id IN (?,?)",
                (old_event_id, baseline_id),
            )
        )
        turn_statuses = dict(
            db.execute(
                "SELECT event_id,status FROM event_lane_turns WHERE event_id IN (?,?)",
                (old_event_id, baseline_id),
            )
        )
    assert statuses[old_event_id] == "needs_reconcile"
    assert statuses[baseline_id] == "baseline"
    assert turn_statuses[old_event_id] == "needs_reconcile"
    assert turn_statuses[baseline_id] == "superseded"

    second = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        apply=True,
        legacy_coverage=coverage,
    )
    assert second["changed"] == 0


def test_recovery_lineage_cannot_cross_public_keys(tmp_path: Path) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root_event_id = "root-key-a"
    assert lane.append(
        {
            "eventId": root_event_id,
            "eventKey": "agentscope-ai/agentscope#1",
            "kind": "issue_update",
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root_event_id,),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id="outcome-reconcile:agentscope:wrong-key",
        source_event_id=root_event_id,
        event_key="agentscope-ai/agentscope#2",
        turn_status="completed",
        valid_outcome=True,
    )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_stable_recovery_requires_one_consistent_declared_root(tmp_path: Path) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    event_key = "agentscope-ai/agentscope#1"
    root_a = "root-a"
    root_b = "root-b"
    assert lane.append(
        {
            "eventId": root_a,
            "eventKey": event_key,
            "kind": "issue_update",
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root_a,),
        )
    recovery_id = (
        "outcome-reconcile:agentscope:" + hashlib.sha256(root_a.encode("utf-8")).hexdigest()
    )
    assert lane.append(
        {
            "eventId": recovery_id,
            "kind": "outcome_reconcile",
            "eventKey": event_key,
            "rootEventId": root_a,
            "eventIdSource": root_b,
            "payload": {
                "rootEventId": root_a,
                "eventId": root_b,
                "publicKey": event_key,
            },
        }
    )
    lane.reserve_handler_turn(event_key, recovery_id, "client:recovery")
    lane.bind_handler_turn(
        event_key,
        recovery_id,
        "thread-1",
        "turn-1",
        {
            "turnStatus": "completed",
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": recovery_id,
                "publicKey": event_key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id=?",
            (recovery_id,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_conflicting_valid_recovery_siblings_and_active_turn_fail_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    event_key = "agentscope-ai/agentscope#1"
    root_event_id = "legacy-root"
    assert lane.append({"eventId": root_event_id, "eventKey": event_key})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root_event_id,),
        )
    for suffix in ("one", "two"):
        _add_recovery(
            lane,
            namespace="agentscope",
            event_id=f"outcome-reconcile:agentscope:{suffix}",
            source_event_id=root_event_id,
            event_key=event_key,
            turn_status="completed",
            valid_outcome=True,
        )
    ambiguous = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert ambiguous["eventsToCoalesce"] == 0
    assert ambiguous["turnsToSupersede"] == 0

    lane.reserve_handler_turn(event_key, "unrelated-active", "client:active")
    active = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert active["activeTurnCount"] == 1
    assert active["eventsToCoalesce"] == 0
    assert active["turnsToSupersede"] == 0


def test_baseline_plan_rejects_a_turn_that_really_started(tmp_path: Path) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    event_id = "github:agentscope-ai/agentscope:1:issue_update:baseline"
    event_key = "agentscope-ai/agentscope#1"
    assert lane.append(
        {
            "eventId": event_id,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    lane.reserve_handler_turn(event_key, event_id, "client:baseline")
    lane.bind_handler_turn(
        event_key,
        event_id,
        "",
        "",
        {"terminalReason": "handler_turn_timeout", "turnStarted": True},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='baseline' WHERE event_id=?",
            (event_id,),
        )
    coverage = {
        "schemaVersion": "event-recovery-legacy-coverage-v1",
        "namespace": "agentscope",
        "baselineRoots": [
            {
                "rootEventId": event_id,
                "expectedEventKey": event_key,
                "expectedTurnEventKey": event_key,
            }
        ],
    }

    with pytest.raises(ValueError, match="unsafe baseline coverage turn"):
        migration.migrate_recovery_chains(
            database,
            namespace="agentscope",
            legacy_coverage=coverage,
        )


def test_root_identity_mismatch_and_unresolved_sibling_block_recovery(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    bad_root = "github:agentscope-ai/agentscope:1:issue_update:bad"
    bad_key = "agentscope-ai/agentscope#2"
    assert lane.append(
        {
            "eventId": bad_root,
            "eventKey": bad_key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (bad_root,),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id="outcome-reconcile:agentscope:bad-root",
        source_event_id=bad_root,
        event_key=bad_key,
        turn_status="completed",
        valid_outcome=True,
    )
    bad_identity = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert bad_identity["eventsToCoalesce"] == 0

    root = "ordinary-root"
    key = "agentscope-ai/agentscope#3"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id="outcome-reconcile:agentscope:valid-leaf",
        source_event_id=root,
        event_key=key,
        turn_status="completed",
        valid_outcome=True,
    )
    sibling_id = "outcome-reconcile:agentscope:unresolved-sibling"
    assert lane.append(
        {
            "eventId": sibling_id,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (sibling_id,),
        )
    sibling_blocked = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert sibling_blocked["eventsToCoalesce"] == 0


def test_root_payload_event_id_must_match_database_identity(tmp_path: Path) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "github:agentscope-ai/agentscope:1:issue_update:identity"
    key = "agentscope-ai/agentscope#1"
    assert lane.append(
        {
            "eventId": root,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    with lane.writer() as db:
        payload = json.loads(
            db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?",
                (root,),
            ).fetchone()[0]
        )
        payload["eventId"] = "github:agentscope-ai/agentscope:2:issue_update:identity"
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',payload_json=? WHERE event_id=?",
            (json.dumps(payload), root),
        )
    _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_receipt_envelope_must_match_recovery_event(tmp_path: Path) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "receipt-root"
    key = "agentscope-ai/agentscope#1"
    recovery_id = "outcome-reconcile:agentscope:receipt"
    assert lane.append({"eventId": root, "eventKey": key})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    assert lane.append(
        {
            "eventId": recovery_id,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    lane.reserve_handler_turn(key, recovery_id, "client:receipt")
    lane.bind_handler_turn(
        key,
        recovery_id,
        "thread-1",
        "turn-1",
        {
            "turnStatus": "completed",
            "eventId": "different-event",
            "eventKey": key,
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": recovery_id,
                "publicKey": key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id=?",
            (recovery_id,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


@pytest.mark.parametrize("root_status", ["baseline", "watch_only"])
def test_recovery_cannot_implicitly_clear_baseline_or_watch_only_root(
    tmp_path: Path,
    root_status: str,
) -> None:
    database = tmp_path / f"{root_status}.sqlite3"
    lane = EventLane(database)
    root = f"root-{root_status}"
    key = "agentscope-ai/agentscope#1"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    lane.reserve_handler_turn(key, root, "client:root")
    lane.bind_handler_turn(
        key,
        root,
        "",
        "",
        {"terminalReason": "handler_turn_timeout"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status=? WHERE event_id=?",
            (root_status, root),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=f"outcome-reconcile:agentscope:{root_status}",
        source_event_id=root,
        event_key=key,
        turn_status="completed",
        valid_outcome=True,
    )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_sha256_stable_recovery_with_four_exact_root_fields_is_accepted(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "github:agentscope-ai/agentscope:1:issue_update:stable"
    key = "agentscope-ai/agentscope#1"
    assert lane.append(
        {
            "eventId": root,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    final_id = _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")

    assert preview["eventsToCoalesce"] == 1
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["chains"][0]["rootEventId"] == root
    assert preview["chains"][0]["finalEventId"] == final_id


def test_stable_shaped_id_without_all_root_declarations_fails_closed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "github:agentscope-ai/agentscope:1:issue_update:missing-root"
    key = "agentscope-ai/agentscope#1"
    assert lane.append(
        {
            "eventId": root,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 1,
            "kind": "issue_update",
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    recovery_id = "outcome-reconcile:agentscope:" + hashlib.sha256(root.encode("utf-8")).hexdigest()
    assert lane.append(
        {
            "eventId": recovery_id,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    lane.reserve_handler_turn(key, recovery_id, "client:missing-root")
    lane.bind_handler_turn(
        key,
        recovery_id,
        "thread-1",
        "turn-1",
        {
            "turnStatus": "completed",
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": recovery_id,
                "publicKey": key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id=?",
            (recovery_id,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_malformed_sibling_declaring_a_root_blocks_its_valid_recovery(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "ordinary-root"
    other = "ordinary-other-root"
    key = "agentscope-ai/agentscope#1"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    assert lane.append({"eventId": other, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id IN (?,?)",
            (root, other),
        )
    _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )
    malformed_id = "outcome-reconcile:agentscope:malformed-sibling"
    assert lane.append(
        {
            "eventId": malformed_id,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": other,
            "payload": {
                "rootEventId": root,
                "eventId": other,
                "publicKey": key,
            },
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (malformed_id,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_indirect_malformed_sibling_blocks_the_reachable_root(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "indirect-root"
    key = "agentscope-ai/agentscope#1"
    intermediate = "outcome-reconcile:agentscope:intermediate"
    final_id = "outcome-reconcile:agentscope:final"
    malformed = "outcome-reconcile:agentscope:malformed-indirect"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=intermediate,
        source_event_id=root,
        event_key=key,
        turn_status="needs_reconcile",
        valid_outcome=False,
    )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=final_id,
        source_event_id=intermediate,
        event_key=key,
        turn_status="completed",
        valid_outcome=True,
    )
    assert lane.append(
        {
            "eventId": malformed,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": intermediate,
            "payload": {"eventId": final_id, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (malformed,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


@pytest.mark.parametrize(
    ("sibling_id", "kind"),
    [
        ("outcome-reconcile:agentscope:missing-kind", "issue_update"),
        ("recovery-without-prefix", "outcome_reconcile"),
    ],
)
def test_recovery_like_sibling_requires_both_id_prefix_and_kind(
    tmp_path: Path,
    sibling_id: str,
    kind: str,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "recovery-shape-root"
    key = "agentscope-ai/agentscope#1"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )
    assert lane.append(
        {
            "eventId": sibling_id,
            "kind": kind,
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (sibling_id,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_resolved_malformed_sibling_does_not_permanently_block_root(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "resolved-malformed-root"
    key = "agentscope-ai/agentscope#1"
    malformed = "outcome-reconcile:agentscope:resolved-malformed"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )
    assert lane.append(
        {
            "eventId": malformed,
            "kind": "issue_update",
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='coalesced' WHERE event_id=?",
            (malformed,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["eventsToCoalesce"] == 1


def test_resolved_child_does_not_hide_an_authoritative_valid_leaf(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "resolved-child-root"
    key = "agentscope-ai/agentscope#1"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    final_id = _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )
    resolved_child = "outcome-reconcile:agentscope:resolved-child"
    assert lane.append(
        {
            "eventId": resolved_child,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": final_id,
            "payload": {"eventId": final_id, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='coalesced' WHERE event_id=?",
            (resolved_child,),
        )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["eventsToCoalesce"] == 1


def test_valid_leaf_can_traverse_a_fully_resolved_ancestor(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "resolved-ancestor-root"
    key = "agentscope-ai/agentscope#1"
    ancestor = "outcome-reconcile:agentscope:resolved-ancestor"
    final_id = "outcome-reconcile:agentscope:resolved-ancestor-final"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    assert lane.append(
        {
            "eventId": ancestor,
            "kind": "outcome_reconcile",
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='coalesced' WHERE event_id=?",
            (ancestor,),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=final_id,
        source_event_id=ancestor,
        event_key=key,
        turn_status="completed",
        valid_outcome=True,
    )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["rootEventsToCoalesce"] == 1
    assert preview["eventsToCoalesce"] == 1
    assert preview["chains"][0]["intermediateEventIds"] == []


@pytest.mark.parametrize(
    ("ancestor_id", "kind"),
    [
        ("outcome-reconcile:agentscope:bad-kind-ancestor", "issue_update"),
        ("kind-only-resolved-ancestor", "outcome_reconcile"),
    ],
)
def test_resolved_invalid_recovery_like_node_cannot_be_a_lineage_bridge(
    tmp_path: Path,
    ancestor_id: str,
    kind: str,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "invalid-resolved-ancestor-root"
    key = "agentscope-ai/agentscope#1"
    final_id = "outcome-reconcile:agentscope:valid-after-invalid"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    assert lane.append(
        {
            "eventId": ancestor_id,
            "kind": kind,
            "eventKey": key,
            "eventIdSource": root,
            "payload": {"eventId": root, "publicKey": key},
        }
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='coalesced' WHERE event_id=?",
            (ancestor_id,),
        )
    _add_recovery(
        lane,
        namespace="agentscope",
        event_id=final_id,
        source_event_id=ancestor_id,
        event_key=key,
        turn_status="completed",
        valid_outcome=True,
    )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("receipt_identity", ""),
        ("thread_identity", ""),
        ("extra_outcome_field", "unexpected"),
    ],
)
def test_terminal_recovery_requires_complete_exact_evidence(
    tmp_path: Path,
    mutation: str,
    value: str,
) -> None:
    database = tmp_path / f"{mutation}.sqlite3"
    lane = EventLane(database)
    root = f"root-{mutation}"
    key = "agentscope-ai/agentscope#1"
    assert lane.append({"eventId": root, "eventKey": key, "kind": "issue_update"})
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile' WHERE event_id=?",
            (root,),
        )
    recovery_id = _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=key,
    )
    with lane.writer() as db:
        if mutation == "receipt_identity":
            receipt = json.loads(
                db.execute(
                    "SELECT receipt_json FROM event_lane_turns WHERE event_id=?",
                    (recovery_id,),
                ).fetchone()[0]
            )
            receipt["eventId"] = value
            receipt["eventKey"] = value
            db.execute(
                "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
                (json.dumps(receipt), recovery_id),
            )
        elif mutation == "thread_identity":
            db.execute(
                "UPDATE event_lane_turns SET thread_id=?,turn_id=? WHERE event_id=?",
                (value, value, recovery_id),
            )
        else:
            receipt = json.loads(
                db.execute(
                    "SELECT receipt_json FROM event_lane_turns WHERE event_id=?",
                    (recovery_id,),
                ).fetchone()[0]
            )
            receipt["outcome"]["extra"] = value
            db.execute(
                "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
                (json.dumps(receipt), recovery_id),
            )

    preview = migration.migrate_recovery_chains(database, namespace="agentscope")
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 0


def test_exact_recovery_root_override_allows_only_declared_legacy_turn_key(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agentscope-events.sqlite3"
    lane = EventLane(database)
    root = "github:agentscope-ai/agentscope:2397:pr_update:legacy"
    event_key = "agentscope-ai/agentscope#2397"
    legacy_turn_key = "agentscope-ai/agentscope#2385"
    assert lane.append(
        {
            "eventId": root,
            "eventKey": event_key,
            "repo": "agentscope-ai/agentscope",
            "number": 2397,
            "kind": "pr_update",
        }
    )
    lane.reserve_handler_turn(legacy_turn_key, root, "client:legacy")
    lane.bind_handler_turn(
        legacy_turn_key,
        root,
        "thread-legacy",
        "turn-legacy",
        {"turnStatus": "completed", "outcome": {"error": "invalid"}},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered' WHERE event_id=?",
            (root,),
        )
    _add_stable_recovery(
        lane,
        namespace="agentscope",
        root_event_id=root,
        event_key=event_key,
    )
    assert (
        migration.migrate_recovery_chains(database, namespace="agentscope")["turnsToSupersede"] == 0
    )
    coverage = {
        "schemaVersion": "event-recovery-legacy-coverage-v1",
        "namespace": "agentscope",
        "baselineRoots": [],
        "recoveryRootOverrides": [
            {
                "rootEventId": root,
                "expectedEventKey": event_key,
                "expectedTurnEventKey": legacy_turn_key,
            }
        ],
    }

    preview = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        legacy_coverage=coverage,
    )
    assert preview["eventsToCoalesce"] == 0
    assert preview["turnsToSupersede"] == 1
    applied = migration.migrate_recovery_chains(
        database,
        namespace="agentscope",
        apply=True,
        legacy_coverage=coverage,
    )
    assert applied["changed"] == 1
    assert (
        migration.migrate_recovery_chains(
            database,
            namespace="agentscope",
            apply=True,
            legacy_coverage=coverage,
        )["changed"]
        == 0
    )
