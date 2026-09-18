from __future__ import annotations

import hashlib
import json
from pathlib import Path

from oss_pr_radar.agentscope_events import EventLane
from oss_pr_radar.recovery_repair import (
    event_artifact_path,
    migrate_unmarked_transient_model_recoveries,
    rearm_historical_recoveries,
)


def _recovery_id(namespace: str, root_id: str) -> str:
    return f"outcome-reconcile:{namespace}:{hashlib.sha256(root_id.encode()).hexdigest()}"


def _seed_exhausted(
    tmp_path: Path,
    *,
    namespace: str,
    repo: str,
    number: int = 7,
) -> tuple[EventLane, str, str, str]:
    lane = EventLane(tmp_path / "state" / "events.sqlite3", max_attempts=3)
    key = f"{repo}#{number}"
    root_id = f"github:{repo}:{number}:issue_update:2026-09-01T00:00:00Z"
    recovery_id = _recovery_id(namespace, root_id)
    root = {
        "eventId": root_id,
        "eventKey": key,
        "repo": repo,
        "number": number,
        "kind": "issue_update",
        "updatedAt": "2026-09-01T00:00:00Z",
    }
    recovery = {
        "eventId": recovery_id,
        "eventIdSource": root_id,
        "eventKey": key,
        "kind": "outcome_reconcile",
        "rootEventId": root_id,
        "historicalModelRepair": {
            "schemaVersion": "oss-pr-radar-model-compatibility-rearm-v1",
            "state": "rearmed",
            "originalPayloadSha256": "a" * 64,
            "originalReceiptSha256": "b" * 64,
            "originalTurnId": "old-turn",
        },
        "payload": {
            "eventId": root_id,
            "rootEventId": root_id,
            "publicKey": key,
            "outcome": {"error": "OUTCOME_MISSING_OR_INVALID"},
        },
    }
    lane.append(root)
    lane.append(recovery, priority=250)
    lane.reserve_handler_turn(key, root_id, "client:root")
    lane.bind_handler_turn(
        key,
        root_id,
        "thread-old",
        "old-root-turn",
        {"turnStatus": "failed", "terminalReason": "model_not_supported"},
        status="needs_reconcile",
    )
    lane.reserve_handler_turn(key, recovery_id, "client:recovery")
    lane.bind_handler_turn(
        key,
        recovery_id,
        "thread-old",
        "old-recovery-turn",
        {"turnStatus": "failed", "terminalReason": "outcome_recovery_attempts_exhausted"},
        status="needs_reconcile",
    )
    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='delivered',delivered_at=1 WHERE event_id=?",
            (root_id,),
        )
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
            (recovery_id,),
        )
    return lane, key, root_id, recovery_id


def test_rearm_advances_artifact_generation_and_is_bounded(tmp_path: Path) -> None:
    lane, key, root_id, recovery_id = _seed_exhausted(
        tmp_path, namespace="agentscope", repo="agentscope-ai/agentscope"
    )
    old_path = event_artifact_path(
        tmp_path, "agentscope_event_receipts", recovery_id, is_recovery=True
    )
    old_path.parent.mkdir(parents=True)
    old_path.write_text('{"turnStatus":"failed"}\n', encoding="utf-8")

    first = rearm_historical_recoveries(
        lane, namespace="agentscope", now=1_700_000_000
    )
    assert first == {"candidates": 1, "rearmed": 1, "superseded": 0, "skipped": 0}
    with lane.connect() as db:
        event_row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    assert event_row["status"] == "pending"
    assert event_row["attempts"] == 0
    payload = json.loads(event_row["payload_json"])
    assert payload["recoveryGeneration"] == 1
    assert payload["historicalModelRepair"]["automaticRearmCount"] == 1
    assert old_path.is_file()
    assert event_artifact_path(
        tmp_path,
        "agentscope_event_receipts",
        recovery_id,
        is_recovery=True,
        generation=1,
    ) != old_path

    with lane.writer() as db:
        db.execute(
            "UPDATE event_lane_events SET status='needs_reconcile',attempts=3 WHERE event_id=?",
            (recovery_id,),
        )
    second = rearm_historical_recoveries(
        lane, namespace="agentscope", now=1_700_000_001
    )
    assert second["rearmed"] == 0
    assert second["skipped"] == 1


def test_unmarked_transient_recovery_migrates_once_to_astra(tmp_path: Path) -> None:
    lane, _key, _root_id, recovery_id = _seed_exhausted(
        tmp_path, namespace="agentscope", repo="agentscope-ai/agentscope", number=8
    )
    with lane.writer() as db:
        row = db.execute(
            "SELECT payload_json FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["transientModelRetry"] = {
            "schemaVersion": "oss_pr_radar_transient_model_retry_v1",
            "error": "selected model is at capacity",
        }
        db.execute(
            "UPDATE event_lane_events SET status='pending',attempts=0,payload_json=? WHERE event_id=?",
            (json.dumps(payload, sort_keys=True), recovery_id),
        )
        turn = db.execute(
            "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (recovery_id,)
        ).fetchone()
        receipt = json.loads(turn["receipt_json"])
        receipt["terminalError"] = {"code": "serverOverloaded"}
        db.execute(
            "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
            (json.dumps(receipt, sort_keys=True), recovery_id),
        )

    first = migrate_unmarked_transient_model_recoveries(
        lane, namespace="agentscope", now=1_700_000_000
    )
    assert first == {"candidates": 1, "migrated": 1, "skipped": 0}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert (row["status"], row["attempts"]) == ("pending", 0)
    assert payload["modelFallback"]["candidates"][0] == "gpt-6-astra"
    assert payload["modelFallback"]["nextIndex"] == 0
    assert payload["historicalModelRepair"]["automaticRearmCount"] == 1
    with lane.connect() as db:
        before_second = tuple(
            db.execute(
                "SELECT e.payload_json,t.receipt_json FROM event_lane_events e "
                "JOIN event_lane_turns t USING(event_id) WHERE e.event_id=?",
                (recovery_id,),
            ).fetchone()
        )
    assert migrate_unmarked_transient_model_recoveries(lane, namespace="agentscope") == {
        "candidates": 0,
        "migrated": 0,
        "skipped": 0,
    }
    with lane.connect() as db:
        after_second = tuple(
            db.execute(
                "SELECT e.payload_json,t.receipt_json FROM event_lane_events e "
                "JOIN event_lane_turns t USING(event_id) WHERE e.event_id=?",
                (recovery_id,),
            ).fetchone()
        )
    assert after_second == before_second


def test_usage_limit_recovery_migrates_to_bounded_model_fallback(tmp_path: Path) -> None:
    lane, _key, _root_id, recovery_id = _seed_exhausted(
        tmp_path, namespace="agentscope", repo="agentscope-ai/agentscope", number=19
    )
    with lane.writer() as db:
        row = db.execute(
            "SELECT payload_json FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["terminalError"] = {
            "codexErrorInfo": "usageLimitExceeded",
            "message": "You've hit your usage limit. Try again later.",
        }
        db.execute(
            "UPDATE event_lane_events SET payload_json=? WHERE event_id=?",
            (json.dumps(payload, sort_keys=True), recovery_id),
        )
        turn = db.execute(
            "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (recovery_id,)
        ).fetchone()
        receipt = json.loads(turn["receipt_json"])
        receipt["terminalError"] = payload["terminalError"]
        db.execute(
            "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
            (json.dumps(receipt, sort_keys=True), recovery_id),
        )

    result = migrate_unmarked_transient_model_recoveries(
        lane, namespace="agentscope", now=1_700_000_000
    )

    assert result == {"candidates": 1, "migrated": 1, "skipped": 0}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert (row["status"], row["attempts"]) == ("pending", 2)
    assert payload["modelFallback"] == {
        "schemaVersion": "oss_pr_radar_event_model_fallback_v1",
        "candidates": ["gpt-6-astra", "gpt-5.6-terra", "gpt-5.6-luna"],
        "nextIndex": 0,
        "history": [],
        "state": "pending",
    }


def test_unmarked_transient_migration_preserves_prior_non_model_attempts(
    tmp_path: Path,
) -> None:
    lane, _key, _root_id, recovery_id = _seed_exhausted(
        tmp_path, namespace="agentscope", repo="agentscope-ai/agentscope", number=18
    )
    with lane.writer() as db:
        row = db.execute(
            "SELECT payload_json FROM event_lane_events WHERE event_id=?", (recovery_id,)
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["transientModelRetry"] = {
            "schemaVersion": "oss_pr_radar_transient_model_retry_v1",
            "error": "selected model is at capacity",
        }
        db.execute(
            "UPDATE event_lane_events SET payload_json=? WHERE event_id=?",
            (json.dumps(payload, sort_keys=True), recovery_id),
        )
        turn = db.execute(
            "SELECT receipt_json FROM event_lane_turns WHERE event_id=?", (recovery_id,)
        ).fetchone()
        receipt = json.loads(turn["receipt_json"])
        receipt["terminalError"] = {"code": "serverOverloaded"}
        db.execute(
            "UPDATE event_lane_turns SET receipt_json=? WHERE event_id=?",
            (json.dumps(receipt, sort_keys=True), recovery_id),
        )

    result = migrate_unmarked_transient_model_recoveries(
        lane, namespace="agentscope", now=1_700_000_000
    )

    assert result == {"candidates": 1, "migrated": 1, "skipped": 0}
    with lane.connect() as db:
        row = db.execute(
            "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
            (recovery_id,),
        ).fetchone()
    payload = json.loads(row["payload_json"])
    assert (row["status"], row["attempts"]) == ("pending", 2)
    assert payload["historicalModelRepair"]["originalAttempts"] == 3
    assert payload["modelFallback"]["history"] == []
    assert payload["modelFallback"]["nextIndex"] == 0


def test_rearm_supersedes_chain_only_for_a_later_valid_completed_turn(tmp_path: Path) -> None:
    lane, key, root_id, recovery_id = _seed_exhausted(
        tmp_path, namespace="agentscope", repo="agentscope-ai/agentscope", number=9
    )
    later_id = "github:agentscope-ai/agentscope:9:issue_update:2026-09-02T00:00:00Z"
    lane.append(
        {
            "eventId": later_id,
            "eventKey": key,
            "repo": "agentscope-ai/agentscope",
            "number": 9,
            "kind": "issue_update",
            "updatedAt": "2026-09-02T00:00:00Z",
        }
    )
    lane.reserve_handler_turn(key, later_id, "client:later")
    lane.bind_handler_turn(
        key,
        later_id,
        "thread-later",
        "turn-later",
        {
            "turnStatus": "completed",
            "outcome": {
                "schemaVersion": "agentscope_event_outcome_v1",
                "eventId": later_id,
                "publicKey": key,
                "state": "no_action",
            },
        },
        status="completed",
    )
    result = rearm_historical_recoveries(
        lane, namespace="agentscope", now=1_700_000_000
    )
    assert result["superseded"] == 1
    with lane.connect() as db:
        states = {
            row["event_id"]: (row["status"], row["turn_status"])
            for row in db.execute(
                "SELECT e.event_id,e.status,t.status AS turn_status "
                "FROM event_lane_events e JOIN event_lane_turns t USING(event_id) "
                "WHERE e.event_id IN (?,?)",
                (root_id, recovery_id),
            )
        }
        recovery_payload = json.loads(
            db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?",
                (recovery_id,),
            ).fetchone()[0]
        )
    assert states[root_id] == ("coalesced", "superseded")
    assert states[recovery_id] == ("coalesced", "superseded")
    assert recovery_payload["historicalModelRepair"]["supersededByValidOutcome"]["turnId"] == "turn-later"
