"""Durable notification outbox with deterministic idempotency keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .notifier import candidate_card
from .util import iso_z, parse_time, sha256_json

OUTBOX_VERSION = "notification_outbox_v2"
LEGACY_OUTBOX_VERSION = "notification_outbox_v1"
EVENT_RETENTION_DAYS = 7
STATE_RETENTION_DAYS = 180


def _candidate_state(
    item: dict[str, Any], *, kind: str, scanner_version: str = ""
) -> dict[str, str]:
    value = {
        "key": f"{item['repo']}#{item['num']}",
        "digest": str(item.get("notification_digest") or item.get("evidence_digest") or ""),
        "category": str(item.get("category") or ""),
        "kind": kind,
        "scannerVersion": str(item.get("notification_scanner_version") or scanner_version or ""),
    }
    value["stateId"] = sha256_json(
        {key: item for key, item in value.items() if key != "scannerVersion"}
    )
    return value


def _state_index_key(kind: str, key: str) -> str:
    return f"{kind}|{key}"


def _valid_seen_at(value: Any, *, keep_after: datetime) -> str | None:
    try:
        parsed = parse_time(str(value))
    except (TypeError, ValueError):
        return None
    return iso_z(parsed) if parsed >= keep_after else None


def _state_index_entry(state: dict[str, Any], *, seen_at: str) -> dict[str, str]:
    return {
        "stateId": str(state.get("stateId") or ""),
        "digest": str(state.get("digest") or ""),
        "category": str(state.get("category") or ""),
        "kind": str(state.get("kind") or ""),
        "scannerVersion": str(state.get("scannerVersion") or ""),
        "seenAt": seen_at,
    }


def latest_candidate_notification_history(
    outbox: dict[str, Any],
    *,
    kinds: frozenset[str] = frozenset({"immediate", "review"}),
) -> dict[str, dict[str, str]]:
    """Return the latest durable notification identity for each issue."""

    validate_outbox(outbox)
    history: dict[str, dict[str, str]] = {}
    for event in outbox.get("events") or []:
        if not isinstance(event, dict) or event.get("status") not in {"PENDING", "SENT"}:
            continue
        event_kind = str(event.get("kind") or "")
        if event_kind not in kinds:
            continue
        for state in event.get("candidateStates") or []:
            if not isinstance(state, dict):
                continue
            key = str(state.get("key") or "")
            digest = str(state.get("digest") or "")
            if key and digest:
                history[key] = {
                    "notification_digest": digest,
                    "notification_scanner_version": str(state.get("scannerVersion") or ""),
                }
    index = outbox.get("candidateStateIndex")
    if isinstance(index, dict):
        for index_key, state in index.items():
            if not isinstance(index_key, str) or not isinstance(state, dict):
                continue
            kind, separator, key = index_key.partition("|")
            digest = str(state.get("digest") or "")
            if separator and kind in kinds and key and digest:
                history[key] = {
                    "notification_digest": digest,
                    "notification_scanner_version": str(state.get("scannerVersion") or ""),
                }
    return history


def build_outbox(
    report: dict[str, Any],
    existing: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
    kind: str = "immediate",
    exclude_candidate_keys: set[str] | None = None,
) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    keep_after = current - timedelta(days=EVENT_RETENTION_DAYS)
    keep_state_after = current - timedelta(days=STATE_RETENTION_DAYS)
    retained: dict[str, dict[str, Any]] = {}
    state_index: dict[str, dict[str, str | bool]] = {}
    if isinstance(existing, dict) and existing.get("version") in {
        OUTBOX_VERSION,
        LEGACY_OUTBOX_VERSION,
    }:
        existing_index = existing.get("candidateStateIndex")
        if isinstance(existing_index, dict):
            for index_key, entry in existing_index.items():
                if not isinstance(index_key, str) or not isinstance(entry, dict):
                    continue
                seen_at = _valid_seen_at(entry.get("seenAt"), keep_after=keep_state_after)
                state_id = entry.get("stateId")
                if seen_at and isinstance(state_id, str) and state_id:
                    state_index[index_key] = {
                        key: value
                        for key, value in _state_index_entry(entry, seen_at=seen_at).items()
                        if value
                    }
        for event in existing.get("events") or []:
            if not isinstance(event, dict):
                continue
            try:
                created_at = parse_time(str(event["createdAt"]))
                if created_at >= keep_after:
                    retained[str(event["eventId"])] = event
            except (KeyError, TypeError, ValueError):
                continue
            if created_at < keep_state_after:
                continue
            event_kind = str(event.get("kind") or "")
            seen_at = iso_z(created_at)
            states = event.get("candidateStates")
            if isinstance(states, list):
                for state in states:
                    if not isinstance(state, dict):
                        continue
                    key = str(state.get("key") or "")
                    state_id = str(state.get("stateId") or "")
                    if key and state_id:
                        state_index[_state_index_key(event_kind, key)] = _state_index_entry(
                            state,
                            seen_at=seen_at,
                        )
            else:
                for key in event.get("candidateKeys") or []:
                    if key:
                        state_index[_state_index_key(event_kind, str(key))] = {
                            "legacy": True,
                            "seenAt": seen_at,
                        }
    excluded = exclude_candidate_keys or set()
    candidates = [
        item
        for item in report.get("candidate_details") or []
        if isinstance(item, dict)
        and f"{item.get('repo')}#{item.get('num')}" not in excluded
        and (
            bool(item.get("auto_spawn"))
            if kind == "immediate"
            else not bool(item.get("auto_spawn"))
        )
        and (kind != "watch" or item.get("notify") is True)
    ]
    candidates.sort(key=lambda item: f"{item['repo']}#{item['num']}")
    candidate_states = [
        _candidate_state(
            item,
            kind=kind,
            scanner_version=str(report.get("scanner_version") or ""),
        )
        for item in candidates
    ]
    new_pairs: list[tuple[dict[str, Any], dict[str, str]]] = []
    for item, state in zip(candidates, candidate_states, strict=True):
        index_key = _state_index_key(kind, state["key"])
        previous = state_index.get(index_key)
        if not previous or (
            previous.get("stateId") != state["stateId"] and previous.get("legacy") is not True
        ):
            new_pairs.append((item, state))
        state_index[index_key] = _state_index_entry(state, seen_at=iso_z(current))
    candidates = [item for item, _state in new_pairs]
    candidate_states = [state for _item, state in new_pairs]
    new_count = 0
    if candidates:
        basis = {
            "kind": kind,
            "candidateStateIds": [state["stateId"] for state in candidate_states],
        }
        event_id = sha256_json(basis)
        if event_id not in retained:
            retained[event_id] = {
                "eventId": event_id,
                "idempotencyKey": event_id[:50],
                "kind": kind,
                "status": "PENDING",
                "attempts": 0,
                "createdAt": iso_z(current),
                "runId": report.get("run_id"),
                "candidateKeys": [state["key"] for state in candidate_states],
                "candidateStates": candidate_states,
                "card": candidate_card(
                    candidates,
                    title=(
                        "OSS PR Radar: 已进入自动派发队列"
                        if kind == "immediate"
                        else "OSS PR Radar: 需要确认"
                        if kind == "review"
                        else "OSS PR Radar: 状态更新"
                    ),
                ),
            }
            new_count = 1
    result = {
        "version": OUTBOX_VERSION,
        "generatedAt": iso_z(current),
        "events": sorted(retained.values(), key=lambda item: item["createdAt"]),
        "candidateStateIndex": dict(sorted(state_index.items())),
        "newEventCount": new_count,
    }
    result["digest"] = sha256_json({key: value for key, value in result.items() if key != "digest"})
    return result


def validate_outbox(outbox: dict[str, Any]) -> None:
    if outbox.get("version") != OUTBOX_VERSION:
        raise ValueError("unsupported notification outbox")
    expected = sha256_json({key: value for key, value in outbox.items() if key != "digest"})
    if outbox.get("digest") != expected:
        raise ValueError("notification outbox digest mismatch")


def merge_receipts(current: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    validate_outbox(current)
    validate_outbox(receipt)
    receipt_by_id = {
        item.get("eventId"): item
        for item in receipt.get("events") or []
        if isinstance(item, dict) and item.get("eventId")
    }
    merged = dict(current)
    merged["events"] = [
        receipt_by_id.get(item.get("eventId"), item)
        for item in current.get("events") or []
        if isinstance(item, dict)
    ]
    merged["digest"] = sha256_json({key: value for key, value in merged.items() if key != "digest"})
    return merged
