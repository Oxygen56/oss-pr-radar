from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.util import sha256_json
from oss_pr_radar.war_room_delivery import (
    build_receipt_document,
    sign_delivery_receipt,
)
from oss_pr_radar.war_room_messages import (
    build_outbox,
    canonical_event_digest,
)
from oss_pr_radar.war_room_projection import export_projection

ROOT = Path(__file__).parents[1]
USER_DECISION_DIGEST = "b" * 64


def _load_script(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _artifact(tmp_path: Path) -> dict:
    os.environ.setdefault("RADAR_DISPATCH_HMAC_KEY", "delivery-fixture-key")
    ledger_path = tmp_path / "state" / "ledger.sqlite3"
    ledger_path.parent.mkdir(parents=True)
    RadarLedger(ledger_path)
    ledger = ManagedLedger(ledger_path, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#2",
        owner="owner",
        repo="repo",
        issue_number=2,
        issue_url="https://github.com/owner/repo/issues/2",
        state="DECISION_REQUIRED",
        source="test",
        provenance={"title": "标题"},
        metadata={"title": "标题", "preTaskGate": {"allowed": True}, "notify": True},
        observed_at="2026-08-19T00:00:00Z",
    )
    ledger.bind_task(
        task_id="task-2",
        opportunity_key="owner/repo#2",
        thread_id="thread-2",
        worktree_path=None,
    )
    ledger.authorize_task_creation(
        task_id="task-2",
        opportunity_key="owner/repo#2",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/2",
        intent_id="task-2",
    )
    return export_projection(ledger_path)


def _user_decision_artifact(tmp_path: Path) -> tuple[Path, dict]:
    os.environ.setdefault("RADAR_DISPATCH_HMAC_KEY", "delivery-fixture-key")
    ledger_path = tmp_path / "state" / "user-decision-ledger.sqlite3"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
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
            "notificationDigest": USER_DECISION_DIGEST,
            "notificationStatus": "PENDING",
            "notified": False,
        },
        observed_at="2026-08-19T00:00:00Z",
    )
    return ledger_path, export_projection(ledger_path)


def _review_candidate(*, repo: str, number: int, digest: str, title: str) -> dict:
    return {
        "repo": repo,
        "num": number,
        "url": f"https://github.com/{repo}/issues/{number}",
        "title": title,
        "score": 10,
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "notify": True,
        "maturity": "mature",
        "preTaskGate": {"allowed": True},
        "llm_review": {"status": "ok", "semanticSignal": "NO_OBJECTION"},
        "notification_digest": digest,
    }


def _write_inputs(tmp_path: Path, artifact: dict, queue: dict) -> tuple[Path, Path, Path]:
    artifact_path = tmp_path / "projection.json"
    input_path = tmp_path / "queue.json"
    output_path = tmp_path / "receipt.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    input_path.write_text(json.dumps(queue), encoding="utf-8")
    return artifact_path, input_path, output_path


@pytest.mark.parametrize("status", ["SENT", "FAILED"])
def test_sender_rejects_caller_supplied_terminal_queue_before_writing(tmp_path: Path, status: str):
    artifact = _artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    queue["events"][0]["status"] = status
    artifact_path, input_path, output_path = _write_inputs(tmp_path, artifact, queue)
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/send_war_room_outbox.py"),
            str(input_path),
            str(output_path),
            "--artifact",
            str(artifact_path),
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert not output_path.exists()


def test_status_is_not_part_of_canonical_event_digest(tmp_path: Path):
    artifact = _artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    event = queue["events"][0]
    sent = dict(event, status="SENT")
    assert canonical_event_digest(event) == canonical_event_digest(sent)
    altered_attempt = dict(event, attemptId="altered-attempt")
    assert canonical_event_digest(event) != canonical_event_digest(altered_attempt)


def test_sender_rejects_attempt_mutation_before_external_callback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-test-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    monkeypatch.setenv("FEISHU_APP_ID", "app")
    monkeypatch.setenv("FEISHU_APP_SECRET", "secret")
    monkeypatch.setenv("FEISHU_CHAT_ID", "chat")
    artifact = _artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    queue["events"][0]["attemptId"] = "altered-attempt"
    sender = _load_script(
        "send_war_room_outbox_attempt_mutation_test",
        ROOT / "scripts/send_war_room_outbox.py",
    )
    callback_count = 0

    class UnexpectedClient:
        def __init__(self, *_args):
            pass

        def send_card(self, _card, *, idempotency_key):
            nonlocal callback_count
            callback_count += 1
            return {"data": {"message_id": "must-not-send"}}

    monkeypatch.setattr(sender, "FeishuClient", UnexpectedClient)
    artifact_path, input_path, output_path = _write_inputs(tmp_path, artifact, queue)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "send_war_room_outbox.py",
            str(input_path),
            str(output_path),
            "--artifact",
            str(artifact_path),
        ],
    )
    with pytest.raises(ValueError, match="event/card binding"):
        sender.main()
    assert callback_count == 0
    assert not output_path.exists()


def test_legitimate_sender_receipt_merge_replay_and_conflict_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-test-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    monkeypatch.setenv("FEISHU_APP_ID", "app")
    monkeypatch.setenv("FEISHU_APP_SECRET", "secret")
    monkeypatch.setenv("FEISHU_CHAT_ID", "chat")
    artifact = _artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    sender = _load_script("send_war_room_outbox_test", ROOT / "scripts/send_war_room_outbox.py")

    class SuccessfulClient:
        def __init__(self, *_args):
            pass

        def send_card(self, _card, *, idempotency_key):
            assert idempotency_key
            return {"data": {"message_id": "om_legitimate"}}

    monkeypatch.setattr(sender, "FeishuClient", SuccessfulClient)
    artifact_path, input_path, output_path = _write_inputs(tmp_path, artifact, queue)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "send_war_room_outbox.py",
            str(input_path),
            str(output_path),
            "--artifact",
            str(artifact_path),
        ],
    )
    assert sender.main() == 0
    receipt = json.loads(output_path.read_text(encoding="utf-8"))
    assert receipt["events"][0]["status"] == "SENT"
    assert receipt["events"][0]["messageId"] == "om_legitimate"
    assert receipt["events"][0]["taskId"] == "task-2"
    assert receipt["events"][0]["attemptId"] == queue["events"][0]["attemptId"]

    merger = _load_script("merge_war_room_receipt_test", ROOT / "scripts/merge_war_room_receipt.py")
    merged = merger.merge(queue, receipt)
    assert merged["events"][0]["status"] == "SENT"
    assert merger.merge(merged, receipt) == merged

    conflicting = build_receipt_document(
        artifact_digest=artifact["artifactDigest"],
        receipts=[
            sign_delivery_receipt(
                artifact_digest=artifact["artifactDigest"],
                event=queue["events"][0],
                status="FAILED",
                error="later failure",
            )
        ],
    )
    with pytest.raises(ValueError, match="conflicting"):
        merger.merge(merged, conflicting)


def test_user_decision_sent_receipt_suppresses_replay_and_updates_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-user-decision-key" * 2)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    ledger_path, artifact = _user_decision_artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    event = queue["events"][0]
    receipt = build_receipt_document(
        artifact_digest=artifact["artifactDigest"],
        receipts=[
            sign_delivery_receipt(
                artifact_digest=artifact["artifactDigest"],
                event=event,
                status="SENT",
                message_id="om_user_decision",
            )
        ],
    )
    merger = _load_script(
        "merge_war_room_receipt_user_decision_sent_test",
        ROOT / "scripts/merge_war_room_receipt.py",
    )
    merged = merger.merge(queue, receipt)
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(
        json.dumps(
            {
                "owner/repo#8": {
                    "status": "queued_outbox",
                    "notified": False,
                    "notification_digest": USER_DECISION_DIGEST,
                }
            }
        ),
        encoding="utf-8",
    )
    applier = _load_script(
        "apply_war_room_receipt_user_decision_sent_test",
        ROOT / "scripts/apply_war_room_receipt.py",
    )

    first = applier.apply(
        ledger_path=ledger_path,
        outbox=merged,
        receipt=receipt,
        seen_path=seen_path,
    )
    second = applier.apply(
        ledger_path=ledger_path,
        outbox=merged,
        receipt=receipt,
        seen_path=seen_path,
    )

    assert first == {"applied": 1, "seenUpdated": 1}
    assert second == {"applied": 1, "seenUpdated": 1}
    seen = json.loads(seen_path.read_text(encoding="utf-8"))["owner/repo#8"]
    assert seen["status"] == "notified"
    assert seen["notified"] is True
    projected = export_projection(ledger_path)
    assert projected["items"][0]["notificationStatus"] == "SENT"
    assert projected["items"][0]["notificationStatusByChannel"] == {
        "feishu": "SENT",
        "codex": "PENDING",
    }
    assert build_outbox(projected, channel="feishu")["events"] == []
    assert build_outbox(projected, channel="codex")["events"][0]["candidateKey"] == ("owner/repo#8")


def test_feishu_sent_keeps_mastra_in_next_codex_round_with_second_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-two-round-key" * 2)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    ledger_path = tmp_path / "state" / "two-round-ledger.sqlite3"
    adapter = ManagedAdapter(tmp_path, ledger_path)
    mastra = _review_candidate(
        repo="mastra-ai/mastra",
        number=21961,
        digest="c" * 64,
        title="OM-managed Working Memory can overwrite stored memory",
    )
    first_report = {
        "run_id": "mastra-round",
        "now": "2026-08-22T16:39:41Z",
        "candidate_details": [mastra],
    }
    assert adapter.record_scan_report(first_report)["recorded"] == 1
    first_projection = export_projection(ledger_path)
    first_codex = build_outbox(first_projection, channel="codex")
    mastra_event = first_codex["events"][0]

    feishu = build_outbox(first_projection, channel="feishu")
    receipt = build_receipt_document(
        artifact_digest=first_projection["artifactDigest"],
        receipts=[
            sign_delivery_receipt(
                artifact_digest=first_projection["artifactDigest"],
                event=feishu["events"][0],
                status="SENT",
                message_id="om_mastra",
            )
        ],
    )
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(
        json.dumps(
            {
                "mastra-ai/mastra#21961": {
                    "status": "queued_outbox",
                    "notified": False,
                    "notification_digest": "c" * 64,
                }
            }
        ),
        encoding="utf-8",
    )
    applier = _load_script(
        "apply_war_room_receipt_two_round_test",
        ROOT / "scripts/apply_war_room_receipt.py",
    )
    assert applier.apply(
        ledger_path=ledger_path,
        outbox=feishu,
        receipt=receipt,
        seen_path=seen_path,
    ) == {"applied": 1, "seenUpdated": 1}

    compressor = _review_candidate(
        repo="vllm-project/llm-compressor",
        number=3071,
        digest="d" * 64,
        title="Qwen3-VL calibration fails during tracing",
    )
    second_report = {
        "run_id": "compressor-round",
        "now": "2026-08-22T16:48:36Z",
        "candidate_details": [mastra, compressor],
    }
    assert adapter.record_scan_report(second_report)["recorded"] == 2
    second_projection = export_projection(ledger_path)
    second_feishu = build_outbox(second_projection, channel="feishu")
    second_codex = build_outbox(second_projection, channel="codex")

    assert [event["candidateKey"] for event in second_feishu["events"]] == [
        "vllm-project/llm-compressor#3071"
    ]
    assert [event["candidateKey"] for event in second_codex["events"]] == [
        "mastra-ai/mastra#21961",
        "vllm-project/llm-compressor#3071",
    ]
    retained_mastra = second_codex["events"][0]
    assert retained_mastra["eventId"] == mastra_event["eventId"]
    assert canonical_event_digest(retained_mastra) == canonical_event_digest(mastra_event)


def test_scan_outcome_cannot_drop_pending_codex_user_decision(tmp_path: Path):
    ledger_path = tmp_path / "state" / "pending-codex-ledger.sqlite3"
    adapter = ManagedAdapter(tmp_path, ledger_path)
    candidate = _review_candidate(
        repo="deepset-ai/haystack",
        number=12436,
        digest="e" * 64,
        title="需要确认 AI 使用披露方式",
    )
    first_report = {
        "run_id": "decision-round",
        "now": "2026-08-23T00:00:00Z",
        "candidate_details": [candidate],
    }
    adapter.record_scan_report(first_report)
    first_projection = export_projection(ledger_path)
    first_event = build_outbox(first_projection, channel="codex")["events"][0]
    adapter.record_user_decision_delivery(
        candidate_key="deepset-ai/haystack#12436",
        notification_digest="e" * 64,
        channel="feishu",
        status="SENT",
        receipt_id="feishu-receipt",
        source_artifact_digest=first_projection["artifactDigest"],
        message_id="om_haystack",
    )

    second_report = {
        "run_id": "outcome-round",
        "now": "2026-08-23T01:00:00Z",
        "candidate_details": [],
        "issue_outcomes": {
            "deepset-ai/haystack#12436": {
                "status": "rejected",
                "reason": "seen_recently",
            }
        },
    }
    result = adapter.record_scan_report(second_report)
    second_projection = export_projection(ledger_path)
    second_item = second_projection["items"][0]
    second_event = build_outbox(second_projection, channel="codex")["events"][0]

    assert result["outcomesRecorded"] == 1
    assert second_item["actionKind"] == "USER_DECISION"
    assert second_item["taskId"] is None
    assert second_item["notificationStatusByChannel"] == {
        "feishu": "SENT",
        "codex": "PENDING",
    }
    assert second_event["eventId"] == first_event["eventId"]
    assert canonical_event_digest(second_event) == canonical_event_digest(first_event)

    revoking_report = {
        "run_id": "revoking-round",
        "now": "2026-08-23T02:00:00Z",
        "candidate_details": [],
        "issue_outcomes": {
            "deepset-ai/haystack#12436": {
                "status": "rejected",
                "reason": "score_low",
            }
        },
    }
    adapter.record_scan_report(revoking_report)
    assert export_projection(ledger_path)["items"] == []


def test_user_decision_failed_receipt_retries_same_event(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-user-decision-key" * 2)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    ledger_path, artifact = _user_decision_artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    event = queue["events"][0]
    receipt = build_receipt_document(
        artifact_digest=artifact["artifactDigest"],
        receipts=[
            sign_delivery_receipt(
                artifact_digest=artifact["artifactDigest"],
                event=event,
                status="FAILED",
                error="temporary transport failure",
            )
        ],
    )
    merger = _load_script(
        "merge_war_room_receipt_user_decision_failed_test",
        ROOT / "scripts/merge_war_room_receipt.py",
    )
    merged = merger.merge(queue, receipt)
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(
        json.dumps(
            {
                "owner/repo#8": {
                    "status": "queued_outbox",
                    "notified": False,
                    "notification_digest": USER_DECISION_DIGEST,
                }
            }
        ),
        encoding="utf-8",
    )
    applier = _load_script(
        "apply_war_room_receipt_user_decision_failed_test",
        ROOT / "scripts/apply_war_room_receipt.py",
    )
    applier.apply(
        ledger_path=ledger_path,
        outbox=merged,
        receipt=receipt,
        seen_path=seen_path,
    )

    seen = json.loads(seen_path.read_text(encoding="utf-8"))["owner/repo#8"]
    assert seen["status"] == "send_failed"
    retried = build_outbox(export_projection(ledger_path), channel="feishu")
    assert retried["events"][0]["eventId"] == event["eventId"]


def test_forged_receipts_missing_message_id_and_wrong_attempt_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-test-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    artifact = _artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    event = queue["events"][0]
    merger = _load_script(
        "merge_war_room_receipt_forged_test", ROOT / "scripts/merge_war_room_receipt.py"
    )

    forged_sent = {
        "schema": "oss-pr-radar.war-room-delivery-receipt.v1",
        "channel": "feishu",
        "sourceArtifactDigest": artifact["artifactDigest"],
        "events": [
            {
                "schema": "oss-pr-radar.war-room-delivery-receipt.v1",
                "artifactDigest": artifact["artifactDigest"],
                "eventId": event["eventId"],
                "idempotencyKey": event["idempotencyKey"],
                "candidateKey": event["candidateKey"],
                "taskId": event["taskId"],
                "attemptId": event["attemptId"],
                "canonicalEventDigest": canonical_event_digest(event),
                "channel": "feishu",
                "status": "SENT",
                "messageId": "",
                "error": "",
                "reconciliationRequired": False,
                "keyId": "delivery-current",
                "signature": "forged",
                "receiptId": "forged",
            }
        ],
    }
    forged_sent["digest"] = sha256_json(forged_sent)
    with pytest.raises(ValueError, match="message ID|signature"):
        merger.merge(queue, forged_sent)

    wrong_attempt_event = dict(event, attemptId="wrong-attempt")
    wrong_attempt = build_receipt_document(
        artifact_digest=artifact["artifactDigest"],
        receipts=[
            sign_delivery_receipt(
                artifact_digest=artifact["artifactDigest"],
                event=wrong_attempt_event,
                status="SENT",
                message_id="om_wrong_attempt",
            )
        ],
    )
    with pytest.raises(ValueError, match="binding"):
        merger.merge(queue, wrong_attempt)


def test_sender_turns_missing_message_id_into_authenticated_failed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "delivery-test-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "delivery-current")
    monkeypatch.setenv("FEISHU_APP_ID", "app")
    monkeypatch.setenv("FEISHU_APP_SECRET", "secret")
    monkeypatch.setenv("FEISHU_CHAT_ID", "chat")
    artifact = _artifact(tmp_path)
    queue = build_outbox(artifact, channel="feishu")
    sender = _load_script(
        "send_war_room_outbox_missing_id_test", ROOT / "scripts/send_war_room_outbox.py"
    )

    class MissingMessageClient:
        def __init__(self, *_args):
            pass

        def send_card(self, _card, *, idempotency_key):
            assert idempotency_key
            return {"data": {}}

    monkeypatch.setattr(sender, "FeishuClient", MissingMessageClient)
    artifact_path, input_path, output_path = _write_inputs(tmp_path, artifact, queue)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "send_war_room_outbox.py",
            str(input_path),
            str(output_path),
            "--artifact",
            str(artifact_path),
        ],
    )
    assert sender.main() == 1
    receipt = json.loads(output_path.read_text(encoding="utf-8"))
    event = receipt["events"][0]
    assert event["status"] == "FAILED"
    assert event["messageId"] == ""
    assert event["reconciliationRequired"] is True
    merger = _load_script(
        "merge_war_room_receipt_missing_id_test",
        ROOT / "scripts/merge_war_room_receipt.py",
    )
    merged = merger.merge(queue, receipt)
    assert merged["events"][0]["status"] == "FAILED"
