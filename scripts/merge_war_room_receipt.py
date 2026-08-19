#!/usr/bin/env python3
"""Merge a validated War Room Feishu receipt without accepting new events."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.util import atomic_write_json, sha256_json  # noqa: E402
from oss_pr_radar.war_room_delivery import (  # noqa: E402
    validate_receipt_document,
    verify_delivery_receipt,
)


def _read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("War Room receipt must be an object")
    return value


def merge(current: dict, receipt: dict) -> dict:
    if (
        current.get("schema") != "oss-pr-radar.war-room-outbox.v1"
        or current.get("channel") != "feishu"
    ):
        raise ValueError("unsupported War Room queue")
    current_events = {event.get("eventId"): event for event in current.get("events") or []}
    if any(
        event.get("status") not in {"PENDING", "SENT", "FAILED"}
        for event in current_events.values()
    ):
        raise ValueError("War Room persisted event status is invalid")
    for event in current_events.values():
        if event.get("status") != "PENDING":
            stored = event.get("deliveryReceipt")
            if not isinstance(stored, dict) or stored.get("status") != event.get("status"):
                raise ValueError("persisted War Room transition lacks a valid receipt")
            verify_delivery_receipt(
                stored,
                artifact_digest=current.get("sourceArtifactDigest", ""),
                event=event,
            )
    validate_receipt_document(
        receipt,
        artifact_digest=current.get("sourceArtifactDigest", ""),
        events=current_events,
    )
    receipt_events = {event.get("eventId"): event for event in receipt.get("events") or []}
    merged = dict(current)
    merged["events"] = []
    for event in current.get("events") or []:
        event_id = event.get("eventId")
        received = receipt_events.get(event_id)
        if received is not None:
            if event.get("status") == "PENDING":
                event_copy = dict(event)
                event_copy["status"] = received["status"]
                event_copy["deliveryReceipt"] = received
                merged["events"].append(event_copy)
            elif event.get("deliveryReceipt") == received:
                merged["events"].append(event)
            else:
                raise ValueError("conflicting War Room receipt or attempt")
        else:
            merged["events"].append(event)
    merged["digest"] = sha256_json({key: value for key, value in merged.items() if key != "digest"})
    return merged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("current", type=Path)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    atomic_write_json(args.output, merge(_read(args.current), _read(args.receipt)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
