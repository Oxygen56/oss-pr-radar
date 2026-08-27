#!/usr/bin/env python3
"""Coalesce covered legacy outcome-recovery ancestors without deleting evidence."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


def _json_object(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(str(raw or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _event_source(event: dict[str, Any]) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return str(event.get("eventIdSource") or payload.get("eventId") or "")


def _event_key(event: dict[str, Any]) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return str(event.get("eventKey") or payload.get("publicKey") or "")


def _valid_terminal_outcome(
    event_id: str,
    event: dict[str, Any],
    turn: dict[str, Any] | None,
    *,
    namespace: str,
) -> bool:
    if turn is None or str(turn.get("status") or "") != "completed":
        return False
    receipt = _json_object(turn.get("receipt_json"))
    if str(receipt.get("turnStatus") or "") != "completed":
        return False
    outcome = receipt.get("outcome") if isinstance(receipt.get("outcome"), dict) else {}
    if outcome.get("error"):
        return False
    if outcome.get("schemaVersion") != f"{namespace}_event_outcome_v1":
        return False
    if str(outcome.get("eventId") or "") != str(event_id):
        return False
    if str(outcome.get("publicKey") or "") != _event_key(event):
        return False
    state = str(outcome.get("state") or "")
    if state not in {"no_action", "claimed_or_pr", "design_wait"}:
        return False
    if state == "design_wait":
        try:
            started = datetime.fromisoformat(
                str(outcome["waitStartedAt"]).replace("Z", "+00:00")
            )
            until = datetime.fromisoformat(
                str(outcome["waitUntil"]).replace("Z", "+00:00")
            )
        except (KeyError, TypeError, ValueError):
            return False
        if until < started or until - started > timedelta(hours=24):
            return False
    return True


def _recovery_plan(db: sqlite3.Connection, *, namespace: str) -> dict[str, Any]:
    events: dict[str, dict[str, Any]] = {}
    event_statuses: dict[str, str] = {}
    created_at: dict[str, float] = {}
    for row in db.execute(
        "SELECT event_id,status,created_at,payload_json FROM event_lane_events"
    ):
        event_id = str(row["event_id"])
        event_statuses[event_id] = str(row["status"])
        if not event_id.startswith("outcome-reconcile:"):
            continue
        event = _json_object(row["payload_json"])
        if event.get("kind") != "outcome_reconcile":
            continue
        events[event_id] = event
        created_at[event_id] = float(row["created_at"] or 0)

    turns: dict[str, dict[str, Any]] = {}
    for row in db.execute(
        "SELECT event_id,status,receipt_json FROM event_lane_turns"
    ):
        turns[str(row["event_id"])] = dict(row)

    children: dict[str, set[str]] = {event_id: set() for event_id in events}
    for event_id, event in events.items():
        source = _event_source(event)
        if source in children:
            children[source].add(event_id)

    chains: list[dict[str, Any]] = []
    event_targets: dict[str, str] = {}
    turn_targets: dict[str, str] = {}
    final_ids = sorted(events, key=lambda value: (created_at[value], value), reverse=True)
    for final_event_id in final_ids:
        if children.get(final_event_id):
            continue
        final_event = events[final_event_id]
        if event_statuses.get(final_event_id) != "delivered":
            continue
        if not _valid_terminal_outcome(
            final_event_id,
            final_event,
            turns.get(final_event_id),
            namespace=namespace,
        ):
            continue
        ancestors: list[str] = []
        source = _event_source(final_event)
        visited = {final_event_id}
        while source in events and source not in visited:
            visited.add(source)
            ancestor = events[source]
            if _valid_terminal_outcome(
                source,
                ancestor,
                turns.get(source),
                namespace=namespace,
            ):
                ancestors = []
                break
            ancestors.append(source)
            source = _event_source(ancestor)
        root_event_id = source
        if (
            not root_event_id
            or root_event_id in events
            or root_event_id.startswith("outcome-reconcile:")
            or event_statuses.get(root_event_id) != "delivered"
        ):
            continue
        changed_events = [
            event_id
            for event_id in ancestors
            if event_statuses.get(event_id) != "coalesced"
        ]
        changed_turns = [
            event_id
            for event_id in ancestors
            if event_id in turns and str(turns[event_id].get("status") or "") != "superseded"
        ]
        root_turn = turns.get(root_event_id)
        root_turn_changed = bool(
            root_turn is not None
            and str(root_turn.get("status") or "") == "needs_reconcile"
        )
        if root_turn_changed:
            changed_turns.append(root_event_id)
        if not changed_events and not changed_turns:
            continue
        for event_id in changed_events:
            event_targets[event_id] = final_event_id
        for event_id in changed_turns:
            turn_targets[event_id] = final_event_id
        chains.append({
            "rootEventId": root_event_id,
            "rootTurnToSupersede": root_turn_changed,
            "finalEventId": final_event_id,
            "intermediateEventIds": list(reversed(ancestors)),
        })

    return {
        "chains": chains,
        "eventTargets": event_targets,
        "turnTargets": turn_targets,
        "eventsToCoalesce": len(event_targets),
        "turnsToSupersede": len(turn_targets),
        "rootTurnsToSupersede": sum(
            bool(chain["rootTurnToSupersede"]) for chain in chains
        ),
    }


def migrate_recovery_chains(
    database: Path,
    *,
    namespace: str,
    apply: bool = False,
) -> dict[str, Any]:
    """Plan or apply one bounded, repeatable migration transaction."""
    if not NAMESPACE_RE.fullmatch(namespace):
        raise ValueError("invalid event namespace")
    database = Path(database).resolve()
    if not database.is_file():
        raise FileNotFoundError(database)
    target = str(database) if apply else f"{database.as_uri()}?mode=ro"
    db = sqlite3.connect(target, uri=not apply, timeout=30, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=30000")
    try:
        if apply:
            db.execute("BEGIN IMMEDIATE")
        plan = _recovery_plan(db, namespace=namespace)
        changed_events = 0
        changed_turns = 0
        if apply:
            for event_id in sorted(plan["eventTargets"]):
                changed_events += db.execute(
                    "UPDATE event_lane_events SET status='coalesced' "
                    "WHERE event_id=? AND status!='coalesced'",
                    (event_id,),
                ).rowcount
            for event_id in sorted(plan["turnTargets"]):
                changed_turns += db.execute(
                    "UPDATE event_lane_turns SET status='superseded' "
                    "WHERE event_id=? AND status!='superseded'",
                    (event_id,),
                ).rowcount
            db.execute("COMMIT")
        return {
            "ok": True,
            "mode": "apply" if apply else "dry-run",
            "namespace": namespace,
            "database": str(database),
            "chains": plan["chains"],
            "eventsToCoalesce": plan["eventsToCoalesce"],
            "turnsToSupersede": plan["turnsToSupersede"],
            "rootTurnsToSupersede": plan["rootTurnsToSupersede"],
            "eventsChanged": changed_events,
            "turnsChanged": changed_turns,
            "changed": changed_events + changed_turns,
        }
    except Exception:
        if apply and db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        result = migrate_recovery_chains(
            args.database,
            namespace=str(args.namespace),
            apply=bool(args.apply),
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{exc}"}))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
