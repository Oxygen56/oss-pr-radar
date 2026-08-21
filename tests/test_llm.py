from __future__ import annotations

from pathlib import Path

import pytest

from oss_pr_radar.llm import DeepSeekEvaluator, DeepSeekRequestError
from oss_pr_radar.opportunity import pre_task_gate


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


def strong_fallback_candidate(**overrides):
    value = candidate(
        score=10,
        submission_policy="normal",
        public_submission_allowed=True,
        hardware_compatible=True,
        actionability_evidence={
            "public_repro_signals": 2,
            "code_anchors": ["runtime.py", "frames.py"],
            "probe_ready": True,
            "needs_confirmation": False,
            "design_confirmation": False,
            "usage_confirmation": False,
            "maintainer_active_investigation": False,
            "maintainer_revalidation_requested": False,
        },
        open_pr_assessment={"status": "none", "prs": []},
        related_issue_assessment={"status": "none", "issues": []},
    )
    value.update(overrides)
    return value


def test_reject_removes_candidate(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "REJECT",
            "semanticSignal": "FILTER",
            "score": 2,
            "confidence": 0.9,
            "evidence_ids": ["candidate.open_pr_assessment"],
        },
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
            "semanticSignal": "NO_OBJECTION",
            "score": 9,
            "confidence": 0.9,
            "evidence_ids": ["issue_data.issue_body"],
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


def test_disclosure_candidate_waiting_on_design_does_not_spawn(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "WAIT_MAINTAINER",
            "wait_reason": "DESIGN_CONFIRMATION",
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
    assert result[0]["gate_decision"] == "RETRY_REQUIRED"
    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["auto_spawn"] is False


def test_disclosure_only_wait_keeps_private_work_gate(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "WAIT_MAINTAINER",
            "wait_reason": "DISCLOSURE_ONLY",
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
    assert result[0]["gate_decision"] == "RETRY_REQUIRED"
    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["auto_spawn"] is False


def test_api_failure_fails_closed(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)

    def fail(payload):
        raise TimeoutError

    monkeypatch.setattr(instance, "_request", fail)
    result = instance.evaluate_candidates([candidate()])
    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["gate_decision"] == "RETRY_REQUIRED"
    assert result[0]["auto_spawn"] is False
    assert result[0]["notify"] is False
    assert result[0]["llm_review"] == {
        "status": "retry",
        "model": "deepseek-v4-flash",
        "semanticSignal": "RETRY",
        "evidence": [],
        "error": "TimeoutError",
        "error_category": "timeout",
        "retryable": True,
    }


def test_service_failure_never_creates_a_deterministic_candidate(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)

    def fail(payload):
        raise DeepSeekRequestError("http_error", status_code=402, retryable=False)

    monkeypatch.setattr(instance, "_request", fail)
    result = instance.evaluate_candidates([strong_fallback_candidate()])

    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["gate_decision"] == "RETRY_REQUIRED"
    assert result[0]["auto_spawn"] is False
    assert result[0]["llm_review"]["semanticSignal"] == "RETRY"


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("track", "llm_algorithm"),
        ("submission_policy", "legal_confirmation"),
        ("score", 8),
        ("open_pr_assessment", {"status": "direct_open_pr", "prs": [{}]}),
        ("related_issue_assessment", {"status": "related_open_issue", "issues": [{}]}),
    ],
)
def test_service_failure_keeps_risky_candidates_in_retry(tmp_path, monkeypatch, override, value):
    instance = evaluator(tmp_path)

    def fail(payload):
        raise DeepSeekRequestError("http_error", status_code=402, retryable=False)

    monkeypatch.setattr(instance, "_request", fail)
    result = instance.evaluate_candidates([strong_fallback_candidate(**{override: value})])

    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["auto_spawn"] is False


def test_service_failure_never_bypasses_confirmation_flags(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    actionability = strong_fallback_candidate()["actionability_evidence"] | {
        "needs_confirmation": True
    }

    def fail(payload):
        raise DeepSeekRequestError("http_error", status_code=402, retryable=False)

    monkeypatch.setattr(instance, "_request", fail)
    result = instance.evaluate_candidates(
        [strong_fallback_candidate(actionability_evidence=actionability)]
    )

    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["auto_spawn"] is False


def test_malformed_model_response_never_uses_service_fallback(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)

    def fail(payload):
        raise ValueError("malformed response")

    monkeypatch.setattr(instance, "_request", fail)
    result = instance.evaluate_candidates([strong_fallback_candidate()])

    assert result[0]["category"] == "SEMANTIC_REVIEW_RETRY"
    assert result[0]["auto_spawn"] is False


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
            "semanticSignal": "NO_OBJECTION",
            "score": 8,
            "confidence": 0.8,
            "evidence_ids": ["issue_data.issue_body"],
            "unknowns": ["Maintainer may prefer different wording"],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["gate_decision"] == "ALLOW_TO_WORK"
    assert result[0]["auto_spawn"] is True


def test_evidence_only_response_does_not_invent_maintainer_wait(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "semanticSignal": "NO_OBJECTION",
            "score": 8,
            "confidence": 0.85,
            "evidence_ids": ["issue_data.issue_body"],
            "unknowns": ["The exact root cause still needs implementation work"],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["llm_review"]["decision"] == "NEW_CLEAN_CANDIDATE"
    assert result[0]["llm_review"]["semanticSignal"] == "NO_OBJECTION"
    assert result[0]["gate_decision"] == "ALLOW_TO_WORK"
    assert result[0]["auto_spawn"] is True
    second_pass = pre_task_gate(
        result[0],
        {
            "issue": {"state": "open", "assignees": []},
            "baseSha": "base-a",
            "policy": {"status": "normal"},
            "codePaths": ["src/runtime.py"],
            "reproductionPath": True,
            "validationPath": True,
            "matureRepository": True,
            "duplicate": {"status": "none"},
        },
    )
    assert second_pass["allowed"] is True
    assert second_pass["reasons"] == []


def test_routine_fix_choice_does_not_force_semantic_retry(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "WAIT_MAINTAINER",
            "wait_reason": "OTHER",
            "semanticSignal": "RETRY",
            "score": 8,
            "confidence": 0.85,
            "root_cause_clarity": "high",
            "why": "The failure and code path are reproduced.",
            "expected_changes": ["Skip zero-sized parameters in the reduction path"],
            "test_plan": ["Add a regression test for the supplied reproducer"],
            "evidence_ids": ["issue_data.issue_body"],
            "contradictions": [],
            "unknowns": [
                "The exact fix approach is not yet decided; maintainer approval is "
                "conditional on PR review."
            ],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["llm_review"]["semanticSignal"] == "NO_OBJECTION"
    assert result[0]["llm_review"]["routineUnknownsRecovered"] is True
    assert result[0]["gate_decision"] == "ALLOW_TO_WORK"
    assert result[0]["auto_spawn"] is True


def test_assignment_wait_reason_cannot_be_recovered_as_routine(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "decision": "WAIT_MAINTAINER",
            "wait_reason": "ASSIGNMENT",
            "semanticSignal": "RETRY",
            "score": 8,
            "confidence": 0.85,
            "root_cause_clarity": "high",
            "expected_changes": ["Implement the scoped fix"],
            "test_plan": ["Add the regression test"],
            "evidence_ids": ["repository.policy"],
            "contradictions": [],
            "unknowns": ["The exact implementation approach is not yet decided"],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["llm_review"]["semanticSignal"] == "RETRY"
    assert result[0]["llm_review"]["routineUnknownsRecovered"] is False
    assert result[0]["gate_decision"] == "RETRY_REQUIRED"
    assert result[0]["auto_spawn"] is False


def test_duplicate_coverage_unknown_still_requires_retry(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "semanticSignal": "RETRY",
            "score": 8,
            "confidence": 0.85,
            "root_cause_clarity": "high",
            "expected_changes": ["Adjust kernel selection"],
            "test_plan": ["Compare eager and graph outputs"],
            "evidence_ids": ["issue_data.issue_body"],
            "contradictions": [],
            "unknowns": ["Whether existing PR #4518 already fixes this root cause"],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["llm_review"]["semanticSignal"] == "RETRY"
    assert result[0]["llm_review"]["routineUnknownsRecovered"] is False
    assert result[0]["gate_decision"] == "RETRY_REQUIRED"
    assert result[0]["auto_spawn"] is False


def test_routine_phrase_cannot_hide_missing_reproduction(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "semanticSignal": "RETRY",
            "score": 8,
            "confidence": 0.85,
            "root_cause_clarity": "high",
            "expected_changes": ["Implement the scoped fix"],
            "test_plan": ["Add the regression test"],
            "evidence_ids": ["issue_data.issue_body"],
            "contradictions": [],
            "unknowns": [
                "The exact fix approach is not yet decided; reproduction evidence is missing"
            ],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["llm_review"]["semanticSignal"] == "RETRY"
    assert result[0]["llm_review"]["routineUnknownsRecovered"] is False
    assert result[0]["auto_spawn"] is False


def test_routine_phrase_cannot_hide_possible_pr_coverage(tmp_path, monkeypatch):
    instance = evaluator(tmp_path)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda payload: {
            "semanticSignal": "RETRY",
            "score": 8,
            "confidence": 0.85,
            "root_cause_clarity": "high",
            "expected_changes": ["Implement the scoped fix"],
            "test_plan": ["Add the regression test"],
            "evidence_ids": ["candidate.open_pr_assessment"],
            "contradictions": [],
            "unknowns": [
                "The exact implementation approach is not yet decided; "
                "PR #4518 may cover this root cause."
            ],
        },
    )

    result = instance.evaluate_candidates([candidate()])

    assert result[0]["llm_review"]["semanticSignal"] == "RETRY"
    assert result[0]["llm_review"]["routineUnknownsRecovered"] is False
    assert result[0]["auto_spawn"] is False
