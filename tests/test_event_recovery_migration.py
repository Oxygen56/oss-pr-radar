from __future__ import annotations

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


@pytest.mark.parametrize("namespace", ["agentscope", "nanobot"])
def test_recovery_chain_migration_is_dry_run_evidence_preserving_and_idempotent(
    tmp_path: Path,
    namespace: str,
) -> None:
    database = tmp_path / f"{namespace}-events.sqlite3"
    lane = EventLane(database)
    event_key = (
        "agentscope-ai/agentscope#2441"
        if namespace == "agentscope"
        else "HKUDS/nanobot#5524"
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
        assert db.execute(
            "SELECT status FROM event_lane_events WHERE event_id=?",
            (recovery_one,),
        ).fetchone()[0] == "delivered"

    applied = migration.migrate_recovery_chains(
        database,
        namespace=namespace,
        apply=True,
    )
    assert applied["eventsChanged"] == 2
    assert applied["turnsChanged"] == 3
    assert applied["changed"] == 5
    with lane.connect() as db:
        event_statuses = dict(db.execute(
            "SELECT event_id,status FROM event_lane_events"
        ).fetchall())
        turn_statuses = dict(db.execute(
            "SELECT event_id,status FROM event_lane_turns"
        ).fetchall())
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
