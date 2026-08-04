from datetime import UTC, datetime

import pytest

from oss_pr_radar.notifier import FeishuClient, candidate_card
from oss_pr_radar.outbox import build_outbox, validate_outbox

NOW = datetime(2026, 8, 4, tzinfo=UTC)


def candidate(**updates):
    value = {
        "repo": "a/b",
        "num": 1,
        "key": "a/b#1",
        "url": "https://github.com/a/b/issues/1",
        "title": "Runtime bug",
        "category": "NEW_CLEAN_CANDIDATE",
        "score": 9,
        "auto_spawn": True,
        "evidence_digest": "evidence",
        "why": "Runtime correctness",
        "test_path": "Regression test",
    }
    value.update(updates)
    return value


def test_outbox_is_idempotent_across_rebuilds():
    report = {"run_id": "run-1", "candidate_details": [candidate()]}
    first = build_outbox(report, now=NOW)
    second = build_outbox(report, first, now=NOW)
    assert first["newEventCount"] == 1
    assert second["newEventCount"] == 0
    assert len(second["events"]) == 1
    validate_outbox(second)


def test_review_and_immediate_are_separate():
    report = {"candidate_details": [candidate(), candidate(num=2, key="a/b#2", auto_spawn=False)]}
    immediate = build_outbox(report, now=NOW, kind="immediate")
    review = build_outbox(report, now=NOW, kind="review")
    assert immediate["events"][0]["candidateKeys"] == ["a/b#1"]
    assert review["events"][0]["candidateKeys"] == ["a/b#2"]


def test_excluded_candidate_is_not_added_twice():
    report = {"candidate_details": [candidate()]}
    outbox = build_outbox(report, now=NOW, exclude_candidate_keys={"a/b#1"})
    assert outbox["newEventCount"] == 0
    assert outbox["events"] == []


def test_outbox_digest_detects_tampering():
    outbox = build_outbox({"candidate_details": [candidate()]}, now=NOW)
    outbox["events"][0]["status"] = "SENT"
    with pytest.raises(ValueError):
        validate_outbox(outbox)


def test_feishu_uuid_is_sent(monkeypatch):
    calls = []
    client = FeishuClient("app", "secret", "chat")

    def fake_post(url, payload, token=None):
        calls.append((url, payload, token))
        if "tenant_access_token" in url:
            return {"tenant_access_token": "token"}
        return {"code": 0, "data": {"message_id": "m1"}}

    monkeypatch.setattr(client, "_post", fake_post)
    client.send_card({"elements": []}, idempotency_key="x" * 64)
    assert calls[1][1]["uuid"] == "x" * 50


def test_sparse_watch_card_omits_placeholder_noise():
    card = candidate_card(
        [
            {
                "repo": "a/b",
                "num": 3,
                "url": "https://github.com/a/b/issues/3",
                "title": "Maintainer confirmed the issue",
            }
        ],
        title="状态更新",
    )
    content = card["elements"][0]["text"]["content"]
    assert "None" not in content
    assert "尚未" not in content
    assert "等待证据" not in content
