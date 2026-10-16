#!/usr/bin/env python3
"""Coalesce covered legacy outcome-recovery ancestors without deleting evidence."""

from __future__ import annotations

import argparse
import hashlib
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


def _event_source(
    event_id: str,
    event: dict[str, Any],
    *,
    namespace: str,
) -> str | None:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    declared_root = str(event.get("rootEventId") or "")
    source = str(event.get("eventIdSource") or "")
    payload_root = str(payload.get("rootEventId") or "")
    payload_source = str(payload.get("eventId") or "")
    stable_identity = (
        re.fullmatch(
            rf"outcome-reconcile:{re.escape(namespace)}:[0-9a-f]{{64}}",
            event_id,
        )
        is not None
    )
    if stable_identity and not declared_root:
        return None
    if declared_root:
        values = (declared_root, source, payload_root, payload_source)
        if not all(values) or len(set(values)) != 1:
            return None
        digest = hashlib.sha256(declared_root.encode("utf-8")).hexdigest()
        if event_id != f"outcome-reconcile:{namespace}:{digest}":
            return None
        return declared_root
    if payload_root:
        return None
    immediate = [value for value in (source, payload_source) if value]
    if not immediate or len(set(immediate)) != 1:
        return None
    return immediate[0]


def _declared_lineage_ids(event: dict[str, Any]) -> set[str]:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    return {
        str(value)
        for value in (
            event.get("rootEventId"),
            event.get("eventIdSource"),
            payload.get("rootEventId"),
            payload.get("eventId"),
        )
        if value
    }


def _event_key(event: dict[str, Any]) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    direct = str(event.get("eventKey") or "")
    nested = str(payload.get("publicKey") or "")
    if direct and nested and direct != nested:
        return ""
    return direct or nested


def _ordinary_event_identity_valid(event_id: str, event: dict[str, Any]) -> bool:
    if "eventId" in event and str(event.get("eventId") or "") != event_id:
        return False
    event_key = _event_key(event)
    if not event_key:
        return False
    repo = str(event.get("repo") or "")
    number = event.get("number")
    kind = str(event.get("kind") or "")
    if repo or number is not None:
        if not repo or number is None or event_key != f"{repo}#{number}":
            return False
    if event_id.startswith("github:"):
        if not repo or number is None or kind not in {"issue_update", "pr_update"}:
            return False
        if not event_id.startswith(f"github:{repo}:{number}:{kind}:"):
            return False
    return True


def _valid_terminal_outcome(
    event_id: str,
    event: dict[str, Any],
    turn: dict[str, Any] | None,
    *,
    namespace: str,
) -> bool:
    if turn is None or str(turn.get("status") or "") != "completed":
        return False
    if not str(turn.get("thread_id") or "") or not str(turn.get("turn_id") or ""):
        return False
    receipt = _json_object(turn.get("receipt_json"))
    if str(receipt.get("turnStatus") or "") != "completed":
        return False
    event_key = _event_key(event)
    if "eventId" in receipt and str(receipt.get("eventId") or "") != str(event_id):
        return False
    if "eventKey" in receipt and str(receipt.get("eventKey") or "") != event_key:
        return False
    outcome = receipt.get("outcome") if isinstance(receipt.get("outcome"), dict) else {}
    if outcome.get("error"):
        return False
    if outcome.get("schemaVersion") != f"{namespace}_event_outcome_v1":
        return False
    if str(outcome.get("eventId") or "") != str(event_id):
        return False
    if str(outcome.get("publicKey") or "") != event_key:
        return False
    state = str(outcome.get("state") or "")
    if state not in {"no_action", "claimed_or_pr", "design_wait"}:
        return False
    expected_keys = {"schemaVersion", "eventId", "publicKey", "state"}
    if state == "design_wait":
        expected_keys.update({"waitStartedAt", "waitUntil"})
    if set(outcome) != expected_keys:
        return False
    if state == "design_wait":
        try:
            started = datetime.fromisoformat(str(outcome["waitStartedAt"]).replace("Z", "+00:00"))
            until = datetime.fromisoformat(str(outcome["waitUntil"]).replace("Z", "+00:00"))
            if started.tzinfo is None or until.tzinfo is None:
                return False
        except (KeyError, TypeError, ValueError):
            return False
        try:
            invalid_window = until < started or until - started > timedelta(hours=24)
        except TypeError:
            return False
        if invalid_window:
            return False
    return True


def _coverage_contract(value: dict[str, Any] | None, *, namespace: str) -> dict[str, Any]:
    if value is None:
        return {"baselineRoots": [], "recoveryRootOverrides": []}
    if value.get("schemaVersion") != "event-recovery-legacy-coverage-v1":
        raise ValueError("invalid legacy coverage schema")
    if str(value.get("namespace") or "") != namespace:
        raise ValueError("legacy coverage namespace mismatch")
    baselines = value.get("baselineRoots")
    overrides = value.get("recoveryRootOverrides", [])
    if value.get("laterOutcomes") not in (None, []) or not isinstance(baselines, list):
        raise ValueError("invalid legacy coverage entries")
    if not isinstance(overrides, list):
        raise ValueError("invalid recovery root overrides")
    roots: set[str] = set()

    def normalize_entries(entries: list[Any], *, label: str) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError(f"{label} entries must be objects")
            root = str(item.get("rootEventId") or "")
            event_key = str(item.get("expectedEventKey") or "")
            turn_key = str(item.get("expectedTurnEventKey") or "")
            if not root or root in roots:
                raise ValueError(f"invalid or duplicate {label} root")
            if not event_key or not turn_key:
                raise ValueError(f"{label} keys are required")
            roots.add(root)
            normalized.append(
                {
                    "rootEventId": root,
                    "expectedEventKey": event_key,
                    "expectedTurnEventKey": turn_key,
                }
            )
        return normalized

    normalized_baselines = normalize_entries(baselines, label="baseline coverage")
    normalized_overrides = normalize_entries(overrides, label="recovery override")
    return {
        "baselineRoots": normalized_baselines,
        "recoveryRootOverrides": normalized_overrides,
    }


def _recovery_plan(
    db: sqlite3.Connection,
    *,
    namespace: str,
    legacy_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    coverage = _coverage_contract(legacy_coverage, namespace=namespace)
    all_events: dict[str, dict[str, Any]] = {}
    events: dict[str, dict[str, Any]] = {}
    invalid_recovery_kinds: set[str] = set()
    event_statuses: dict[str, str] = {}
    created_at: dict[str, float] = {}
    for row in db.execute("SELECT event_id,status,created_at,payload_json FROM event_lane_events"):
        event_id = str(row["event_id"])
        event_statuses[event_id] = str(row["status"])
        event = _json_object(row["payload_json"])
        all_events[event_id] = event
        created_at[event_id] = float(row["created_at"] or 0)
        prefixed = event_id.startswith("outcome-reconcile:")
        declared_kind = event.get("kind") == "outcome_reconcile"
        if not prefixed and not declared_kind:
            continue
        if not prefixed or not declared_kind:
            invalid_recovery_kinds.add(event_id)
        events[event_id] = event

    turns: dict[str, dict[str, Any]] = {}
    for row in db.execute(
        "SELECT event_id,event_key,thread_id,turn_id,status,receipt_json FROM event_lane_turns"
    ):
        turns[str(row["event_id"])] = dict(row)

    active_turn_count = sum(
        str(turn.get("status") or "") in {"reserved", "started"} for turn in turns.values()
    )

    def recovery_resolved(event_id: str) -> bool:
        turn = turns.get(event_id)
        return event_statuses.get(event_id) == "coalesced" and (
            turn is None or str(turn.get("status") or "") == "superseded"
        )

    recovery_overrides = {item["rootEventId"]: item for item in coverage["recoveryRootOverrides"]}
    for root_event_id, override in recovery_overrides.items():
        root_event = all_events.get(root_event_id)
        root_turn = turns.get(root_event_id)
        if (
            root_event is None
            or root_turn is None
            or not _ordinary_event_identity_valid(root_event_id, root_event)
            or _event_key(root_event) != override["expectedEventKey"]
            or str(root_turn.get("event_key") or "") != override["expectedTurnEventKey"]
            or event_statuses.get(root_event_id)
            not in {"delivered", "needs_reconcile", "coalesced"}
            or str(root_turn.get("status") or "") not in {"needs_reconcile", "superseded"}
        ):
            raise ValueError(f"invalid recovery root override: {root_event_id}")

    children: dict[str, set[str]] = {event_id: set() for event_id in events}
    for event_id, event in events.items():
        if recovery_resolved(event_id):
            continue
        source = _event_source(event_id, event, namespace=namespace)
        if source in children:
            children[source].add(event_id)

    def declared_ordinary_roots(start_event_id: str) -> set[str]:
        roots: set[str] = set()
        pending = [start_event_id]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current in visited or current not in events:
                continue
            visited.add(current)
            current_event = events[current]
            declared = _declared_lineage_ids(current_event)
            source = _event_source(current, current_event, namespace=namespace)
            if source:
                declared.add(source)
            for candidate in declared:
                if candidate in events:
                    pending.append(candidate)
                elif candidate in all_events:
                    roots.add(candidate)
        return roots

    root_members: dict[str, set[str]] = {}
    unsafe_roots: set[str] = set()
    for invalid_event_id in invalid_recovery_kinds:
        if not recovery_resolved(invalid_event_id):
            unsafe_roots.update(declared_ordinary_roots(invalid_event_id))
    for recovery_event_id, recovery_event in events.items():
        if recovery_resolved(recovery_event_id):
            continue
        current = recovery_event_id
        visited: set[str] = set()
        lineage_key = _event_key(recovery_event)
        root_event_id: str | None = None
        while current in events and current not in visited:
            visited.add(current)
            current_event = events[current]
            if not lineage_key or _event_key(current_event) != lineage_key:
                unsafe_roots.update(declared_ordinary_roots(current))
                current = ""
                break
            source = _event_source(current, current_event, namespace=namespace)
            if source is None:
                unsafe_roots.update(declared_ordinary_roots(current))
                current = ""
                break
            current = source
        if current and current not in events and current in all_events:
            root_event = all_events[current]
            if _event_key(root_event) == lineage_key and _ordinary_event_identity_valid(
                current, root_event
            ):
                root_event_id = current
            else:
                unsafe_roots.add(current)
        if root_event_id:
            root_members.setdefault(root_event_id, set()).add(recovery_event_id)

    proposals: list[dict[str, Any]] = []
    final_ids = sorted(events, key=lambda value: (created_at[value], value), reverse=True)
    for final_event_id in final_ids if active_turn_count == 0 else []:
        if final_event_id in invalid_recovery_kinds:
            continue
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
        final_event_key = _event_key(final_event)
        final_turn = turns.get(final_event_id)
        if (
            not final_event_key
            or final_turn is None
            or str(final_turn.get("event_key") or "") != final_event_key
        ):
            continue
        ancestors: list[str] = []
        source = _event_source(final_event_id, final_event, namespace=namespace)
        if source is None:
            continue
        visited = {final_event_id}
        lineage_valid = True
        while source in events and source not in visited:
            visited.add(source)
            ancestor = events[source]
            ancestor_turn = turns.get(source)
            ancestor_resolved = recovery_resolved(source)
            if (
                source in invalid_recovery_kinds
                or _event_key(ancestor) != final_event_key
                or (
                    not ancestor_resolved
                    and event_statuses.get(source) not in {"delivered", "needs_reconcile"}
                )
                or (
                    ancestor_turn is not None
                    and (
                        str(ancestor_turn.get("event_key") or "") != final_event_key
                        or str(ancestor_turn.get("status") or "") in {"reserved", "started"}
                    )
                )
            ):
                lineage_valid = False
                break
            next_source = _event_source(source, ancestor, namespace=namespace)
            if next_source is None:
                lineage_valid = False
                break
            if ancestor_resolved:
                source = next_source
                continue
            if _valid_terminal_outcome(
                source,
                ancestor,
                turns.get(source),
                namespace=namespace,
            ):
                ancestors = []
                break
            ancestors.append(source)
            source = next_source
        root_event_id = source
        root_event = all_events.get(root_event_id, {})
        root_status = event_statuses.get(root_event_id)
        root_turn = turns.get(root_event_id)
        root_override = recovery_overrides.get(root_event_id)
        expected_root_turn_key = (
            root_override["expectedTurnEventKey"] if root_override is not None else final_event_key
        )
        if (
            not lineage_valid
            or not root_event_id
            or root_event_id in events
            or root_event_id.startswith("outcome-reconcile:")
            or not (
                root_status == "needs_reconcile"
                or (
                    root_status == "delivered"
                    and root_turn is not None
                    and str(root_turn.get("status") or "") == "needs_reconcile"
                )
            )
            or _event_key(root_event) != final_event_key
            or (root_override is not None and root_override["expectedEventKey"] != final_event_key)
            or not _ordinary_event_identity_valid(root_event_id, root_event)
            or root_event_id in unsafe_roots
            or (
                root_turn is not None
                and (
                    str(root_turn.get("event_key") or "") != expected_root_turn_key
                    or str(root_turn.get("status") or "") in {"reserved", "started"}
                )
            )
        ):
            continue
        changed_events = [
            event_id for event_id in ancestors if event_statuses.get(event_id) != "coalesced"
        ]
        changed_turns = [
            event_id
            for event_id in ancestors
            if event_id in turns and str(turns[event_id].get("status") or "") != "superseded"
        ]
        root_turn_changed = bool(
            root_turn is not None and str(root_turn.get("status") or "") == "needs_reconcile"
        )
        root_event_changed = root_status == "needs_reconcile"
        if root_event_changed:
            changed_events.append(root_event_id)
        if root_turn_changed:
            changed_turns.append(root_event_id)
        if not changed_events and not changed_turns:
            continue
        chain_members = set(ancestors) | {final_event_id}
        unresolved_siblings = [
            event_id
            for event_id in root_members.get(root_event_id, set()) - chain_members
            if not recovery_resolved(event_id)
        ]
        if unresolved_siblings:
            continue
        proposals.append(
            {
                "coverageType": "outcome_recovery",
                "rootEventId": root_event_id,
                "rootEventToCoalesce": root_event_changed,
                "rootTurnToSupersede": root_turn_changed,
                "finalEventId": final_event_id,
                "intermediateEventIds": list(reversed(ancestors)),
                "changedEvents": changed_events,
                "changedTurns": changed_turns,
            }
        )

    # A legacy recursive implementation could create conflicting valid leaves.
    # Never guess which one is authoritative; stable recovery IDs make this
    # impossible for new rows.
    proposals_by_root: dict[str, list[dict[str, Any]]] = {}
    for proposal in proposals:
        proposals_by_root.setdefault(str(proposal["rootEventId"]), []).append(proposal)
    chains = [items[0] for items in proposals_by_root.values() if len(items) == 1]

    if legacy_coverage is not None and active_turn_count:
        raise RuntimeError("active handler turn prevents legacy coverage migration")

    for baseline in coverage["baselineRoots"]:
        root_event_id = baseline["rootEventId"]
        event = all_events.get(root_event_id)
        turn = turns.get(root_event_id)
        if event is None or turn is None or event.get("kind") == "outcome_reconcile":
            raise ValueError(f"invalid baseline coverage root: {root_event_id}")
        event_status = event_statuses.get(root_event_id)
        turn_status = str(turn.get("status") or "")
        receipt = _json_object(turn.get("receipt_json"))
        if (
            event_status != "baseline"
            or not _ordinary_event_identity_valid(root_event_id, event)
            or _event_key(event) != baseline["expectedEventKey"]
            or str(turn.get("event_key") or "") != baseline["expectedTurnEventKey"]
        ):
            raise ValueError(f"baseline coverage event is not baseline: {root_event_id}")
        if turn_status == "superseded":
            continue
        if (
            turn_status != "needs_reconcile"
            or str(turn.get("thread_id") or "")
            or str(turn.get("turn_id") or "")
            or receipt.get("turnStarted") is True
            or receipt.get("terminalReason") != "handler_turn_timeout"
        ):
            raise ValueError(f"unsafe baseline coverage turn: {root_event_id}")
        chains.append(
            {
                "coverageType": "bootstrap_baseline",
                "rootEventId": root_event_id,
                "rootEventToCoalesce": False,
                "rootTurnToSupersede": True,
                "finalEventId": root_event_id,
                "intermediateEventIds": [],
                "changedEvents": [],
                "changedTurns": [root_event_id],
            }
        )

    event_targets: dict[str, dict[str, str]] = {}
    turn_targets: dict[str, dict[str, str]] = {}
    for chain in chains:
        final_event_id = str(chain["finalEventId"])
        for event_id in chain.pop("changedEvents"):
            target = {
                "finalEventId": final_event_id,
                "expectedStatus": event_statuses[event_id],
            }
            if event_id in event_targets and event_targets[event_id] != target:
                raise RuntimeError(f"conflicting event coverage: {event_id}")
            event_targets[event_id] = target
        for event_id in chain.pop("changedTurns"):
            target = {
                "finalEventId": final_event_id,
                "expectedStatus": str(turns[event_id].get("status") or ""),
            }
            if event_id in turn_targets and turn_targets[event_id] != target:
                raise RuntimeError(f"conflicting turn coverage: {event_id}")
            turn_targets[event_id] = target

    return {
        "chains": chains,
        "eventTargets": event_targets,
        "turnTargets": turn_targets,
        "eventsToCoalesce": len(event_targets),
        "turnsToSupersede": len(turn_targets),
        "rootEventsToCoalesce": sum(bool(chain["rootEventToCoalesce"]) for chain in chains),
        "rootTurnsToSupersede": sum(bool(chain["rootTurnToSupersede"]) for chain in chains),
        "activeTurnCount": active_turn_count,
    }


def migrate_recovery_chains(
    database: Path,
    *,
    namespace: str,
    apply: bool = False,
    legacy_coverage: dict[str, Any] | None = None,
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
        plan = _recovery_plan(
            db,
            namespace=namespace,
            legacy_coverage=legacy_coverage,
        )
        changed_events = 0
        changed_turns = 0
        if apply:
            for event_id, target_status in sorted(plan["eventTargets"].items()):
                changed = db.execute(
                    "UPDATE event_lane_events SET status='coalesced' WHERE event_id=? AND status=?",
                    (event_id, target_status["expectedStatus"]),
                ).rowcount
                if changed != 1:
                    raise RuntimeError(f"event status changed during migration: {event_id}")
                changed_events += changed
            for event_id, target_status in sorted(plan["turnTargets"].items()):
                changed = db.execute(
                    "UPDATE event_lane_turns SET status='superseded' WHERE event_id=? AND status=?",
                    (event_id, target_status["expectedStatus"]),
                ).rowcount
                if changed != 1:
                    raise RuntimeError(f"turn status changed during migration: {event_id}")
                changed_turns += changed
            db.execute("COMMIT")
        return {
            "ok": True,
            "mode": "apply" if apply else "dry-run",
            "namespace": namespace,
            "database": str(database),
            "chains": plan["chains"],
            "eventsToCoalesce": plan["eventsToCoalesce"],
            "turnsToSupersede": plan["turnsToSupersede"],
            "rootEventsToCoalesce": plan["rootEventsToCoalesce"],
            "rootTurnsToSupersede": plan["rootTurnsToSupersede"],
            "activeTurnCount": plan["activeTurnCount"],
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
    parser.add_argument("--coverage-plan", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        legacy_coverage = None
        if args.coverage_plan is not None:
            if args.coverage_plan.is_symlink() or not args.coverage_plan.is_file():
                raise ValueError("legacy coverage plan is unavailable")
            legacy_coverage = json.loads(args.coverage_plan.read_text(encoding="utf-8"))
            if not isinstance(legacy_coverage, dict):
                raise ValueError("legacy coverage plan must be an object")
        result = migrate_recovery_chains(
            args.database,
            namespace=str(args.namespace),
            apply=bool(args.apply),
            legacy_coverage=legacy_coverage,
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}:{exc}"}))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
