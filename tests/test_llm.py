from __future__ import annotations

from pathlib import Path

from oss_pr_radar.llm import DeepSeekEvaluator


def candidate(**overrides):
    value = {
        "repo": "example/project",
        "num": 42,
        "title": "Streaming tool calls lose arguments",
        "track": "agent_ai_infra",
        "score": 8,
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "_llm_context": {"issue_body": "A reproducible runtime failure"},
    }
    value.update(overrides)
    return value


def evaluator(tmp_path: Path) -> DeepSeekEvaluator:
    return DeepSeekEvaluator(
        "secret",
        "deepseek-v4-flash",
        "https://example.invalid",
        tmp_path / "cache.json",
    )


def test_reject_removes_candidate(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {"decision": "REJECT", "score": 2, "confidence": 0.9},
    )
    assert instance.evaluate_candidates([candidate()]) == []
    assert instance.rejected_candidates["example/project#42"]["reason"] == "llm_reject"


def test_review_that_requires_no_code_is_rejected(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "WAIT_MAINTAINER",
            "score": 10,
            "confidence": 0.9,
            "why": ("A merged fix is on current main, so the candidate is no longer actionable."),
            "expected_changes": [
                "No new code changes expected; verify the merged fix and close the issue."
            ],
        },
    )

    assert instance.evaluate_candidates([candidate()]) == []
    assert instance.rejected_candidates["example/project#42"]["reason"] == "llm_no_code_action"


def test_llm_cannot_upgrade_human_review(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "NEW_CLEAN_CANDIDATE",
            "score": 9,
            "confidence": 0.9,
        },
    )
    result = instance.evaluate_candidates(
        [
            candidate(
                gate_decision="HUMAN_REVIEW",
                category="WAIT_MAINTAINER",
                auto_spawn=False,
            )
        ]
    )
    assert result[0]["gate_decision"] == "HUMAN_REVIEW"
    assert result[0]["auto_spawn"] is False


def test_disclosure_candidate_keeps_private_work_gate_when_review_wants_confirmation(
    tmp_path, monkeypatch
):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "WAIT_MAINTAINER",
            "score": 7,
            "confidence": 0.7,
        },
    )
    result = instance.evaluate_candidates(
        [
            candidate(
                gate_decision="ALLOW_PRIVATE_WORK",
                category="LOCAL_FIX_ONLY",
                submission_policy="ai_disclosure_conflict",
                public_submission_allowed=False,
            )
        ]
    )
    assert result[0]["gate_decision"] == "ALLOW_PRIVATE_WORK"
    assert result[0]["category"] == "LOCAL_FIX_ONLY"
    assert result[0]["auto_spawn"] is True


def test_api_failure_fails_closed(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)

    def fail(payload):
        raise TimeoutError

    monkeypatch.setattr(instance, "_request", fail)
    result = instance.evaluate_candidates([candidate()])
    assert result[0]["category"] == "WAIT_MAINTAINER"
    assert result[0]["auto_spawn"] is False
    assert result[0]["llm_review"]["status"] == "error"


def test_missing_key_never_auto_spawns(tmp_path):
    instance = DeepSeekEvaluator(
        None, "deepseek-v4-flash", "https://api.deepseek.com", tmp_path / "cache.json"
    )
    result = instance.evaluate_candidates([candidate()])
    assert result[0]["auto_spawn"] is False
    assert result[0]["llm_review"]["status"] == "not_configured"


def test_invalid_json_is_retried(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    calls = []

    def request_once(payload, attempt):
        calls.append(attempt)
        if attempt == 0:
            raise ValueError("bad json")
        return {"decision": "NEW_CLEAN_CANDIDATE", "score": 8}

    monkeypatch.setattr(instance, "_request_once", request_once)
    assert instance._request({})["score"] == 8
    assert calls == [0, 1]


def test_non_blocking_unknown_does_not_downgrade_clean_candidate(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "NEW_CLEAN_CANDIDATE",
            "score": 8,
            "confidence": 0.8,
            "unknowns": ["Maintainer may prefer different wording"],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["gate_decision"] == "ALLOW_TO_WORK"
    assert result[0]["auto_spawn"] is True
