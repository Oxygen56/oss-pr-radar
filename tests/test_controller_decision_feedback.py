from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.util import sha256_json
from oss_pr_radar.war_room_messages import build_outbox, canonical_event_digest
from oss_pr_radar.war_room_projection import export_projection

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "apply_controller_decision_feedback.py"
SPEC = importlib.util.spec_from_file_location("apply_controller_decision_feedback", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

DIGEST = "b" * 64


def _fixture(tmp_path: Path) -> tuple[Path, dict, dict]:
    ledger_path = tmp_path / "state" / "radar_ledger.sqlite3"
    ledger_path.parent.mkdir(parents=True)
    RadarLedger(ledger_path)
    ledger = ManagedLedger(ledger_path, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#8",
        owner="owner",
        repo="repo",
        issue_number=8,
        issue_url="https://github.com/owner/repo/issues/8",
        state="DECISION_REQUIRED",
        source="scanner",
        provenance={"title": "需要确认候选处理方向"},
        metadata={
            "title": "需要确认候选处理方向",
            "reviewRequired": True,
            "gateDecision": "HUMAN_REVIEW",
            "notificationDigest": DIGEST,
            "notificationStatus": "PENDING",
            "notified": False,
        },
        observed_at="2026-08-19T00:00:00Z",
    )
    outbox = build_outbox(export_projection(ledger_path), channel="codex")
    event = outbox["events"][0]
    delivery_id = "d" * 64
    receipt_id = sha256_json(
        {
            "channel": "codex",
            "eventId": event["eventId"],
            "candidateKey": event["candidateKey"],
            "notificationDigest": event["notificationDigest"],
            "deliveryId": delivery_id,
            "status": "SENT",
        }
    )
    feedback_event = {
        "eventId": event["eventId"],
        "candidateKey": event["candidateKey"],
        "notificationDigest": event["notificationDigest"],
        "sourceArtifactDigest": outbox["sourceArtifactDigest"],
        "canonicalEventDigest": canonical_event_digest(event),
        "status": "SENT",
        "receiptId": receipt_id,
        "deliveryId": delivery_id,
        "analyzed": "2026-08-23T00:00:00Z",
    }
    feedback = {
        "schema": MODULE.FEEDBACK_SCHEMA,
        "events": {event["eventId"]: feedback_event},
    }
    return ledger_path, outbox, feedback


def test_apply_codex_feedback_is_idempotent(tmp_path: Path):
    ledger_path, outbox, feedback = _fixture(tmp_path)

    first = MODULE.apply(
        ledger_path=ledger_path,
        outbox=outbox,
        feedback=feedback,
        root=tmp_path,
    )
    second = MODULE.apply(
        ledger_path=ledger_path,
        outbox=outbox,
        feedback=feedback,
        root=tmp_path,
    )

    assert first == {
        "ok": True,
        "applied": 1,
        "duplicates": 0,
        "skipped": 0,
        "skippedEvents": [],
    }
    assert second == {
        "ok": True,
        "applied": 1,
        "duplicates": 1,
        "skipped": 0,
        "skippedEvents": [],
    }
    projected = export_projection(ledger_path)
    assert projected["items"][0]["notificationStatusByChannel"] == {
        "feishu": "PENDING",
        "codex": "SENT",
    }
    assert build_outbox(projected, channel="codex")["events"] == []
    assert build_outbox(projected, channel="feishu")["events"][0]["candidateKey"] == (
        "owner/repo#8"
    )


def test_stale_and_mismatched_feedback_is_skipped(tmp_path: Path):
    ledger_path, outbox, feedback = _fixture(tmp_path)
    event_id = next(iter(feedback["events"]))
    stale = dict(feedback["events"][event_id])
    stale["sourceArtifactDigest"] = "a" * 64
    mismatched = dict(feedback["events"][event_id])
    mismatched["eventId"] = "different-event"
    feedback["events"] = {
        "stale-event": {**stale, "eventId": "stale-event"},
        event_id: mismatched,
    }

    result = MODULE.apply(
        ledger_path=ledger_path,
        outbox=outbox,
        feedback=feedback,
        root=tmp_path,
    )

    assert result["applied"] == 0
    assert result["skipped"] == 2
    assert result["skippedEvents"] == [
        {"eventId": event_id, "reason": "invalid_feedback_event"},
        {"eventId": "stale-event", "reason": "stale_source_artifact"},
    ]


def test_feedback_for_changed_managed_candidate_is_skipped(tmp_path: Path):
    ledger_path, outbox, feedback = _fixture(tmp_path)
    ledger = ManagedLedger(ledger_path)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#8",
        owner="owner",
        repo="repo",
        issue_number=8,
        issue_url="https://github.com/owner/repo/issues/8",
        state="DECISION_REQUIRED",
        source="scanner",
        provenance={"title": "候选已变化"},
        metadata={
            "title": "候选已变化",
            "reviewRequired": True,
            "gateDecision": "HUMAN_REVIEW",
            "notificationDigest": "c" * 64,
            "notificationStatus": "PENDING",
            "notified": False,
        },
        observed_at="2026-08-23T00:01:00Z",
    )

    result = MODULE.apply(
        ledger_path=ledger_path,
        outbox=outbox,
        feedback=feedback,
        root=tmp_path,
    )

    assert result["applied"] == 0
    assert result["skipped"] == 1
    assert result["skippedEvents"][0]["reason"] == "managed_opportunity_mismatch"
