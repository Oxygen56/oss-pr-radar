from datetime import UTC, datetime

from oss_pr_radar.scanner import (
    LLM_ALGORITHM_TRACK,
    Radar,
    is_dynamic_llm_algorithm_issue,
    llm_algorithm_evidence,
    select_inspection_bases,
)


def radar(tmp_path):
    return Radar(
        datetime(2026, 8, 5, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        notify=False,
    )


def test_algorithm_evidence_requires_mechanism_and_validation():
    text = (
        "GRPO computes ratio = exp(logprob - old_logprob) before advantage normalization. "
        "The gradient and training loss differ from the reference implementation. "
        "Steps to reproduce use a fixed seed and a deterministic batch in trainer/grpo.py."
    )
    evidence = llm_algorithm_evidence(
        "huggingface/trl", text, public_repro_signals=2, root_cause_signal=True
    )
    assert evidence["qualified"] is True
    assert evidence["mechanism_count"] >= 2
    assert evidence["score"] >= 7


def test_dynamic_algorithm_issue_is_detected():
    assert is_dynamic_llm_algorithm_issue(
        "DPO loss = -log sigmoid(beta * logprob_ratio) has an incorrect gradient. "
        "Expected numerical parity with the reference implementation; actual loss diverges. "
        "Minimal repro and regression test are in tests/test_dpo.py."
    )


def test_plain_zero_and_code_comparison_do_not_fake_algorithm_evidence():
    evidence = llm_algorithm_evidence(
        "BerriAI/litellm",
        "reasoning_tokens is always zero because thinking_tokens == 0 in usage.py. "
        "Steps to reproduce and a regression test are included.",
        public_repro_signals=2,
        root_cause_signal=True,
    )

    assert "distributed_training" not in evidence["mechanisms"]
    assert evidence["formula_signal"] is False
    assert evidence["qualified"] is False


def test_algorithm_repository_configuration_bug_is_rejected(tmp_path):
    base = {
        "repo": "huggingface/transformers",
        "num": 1,
        "title": "CLI config argument fails to load yaml",
        "url": "https://github.com/huggingface/transformers/issues/1",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "Steps to reproduce: install the package and pass --config config.yaml. "
            "Expected behavior: the CLI loads the configuration. Actual behavior: import error. "
            "The root cause is an argument parser default."
        ),
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar(tmp_path).score_issue(base, issue, [])

    assert candidate is None
    assert reason == "algorithm_operational_or_configuration_only"


def test_algorithm_issue_gets_independent_track_and_evidence(tmp_path):
    base = {
        "repo": "huggingface/trl",
        "num": 2,
        "title": "GRPO importance ratio uses the wrong advantage normalization",
        "url": "https://github.com/huggingface/trl/issues/2",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "Steps to reproduce: run trl/trainer/grpo_trainer.py with a fixed seed and batch. "
            "Expected result: ratio = exp(logprob - old_logprob) is multiplied by normalized "
            "advantage. Actual result: the clipping objective uses the unnormalized advantage. "
            "The root cause is the training loss reading the tensor before gradient normalization. "
            "A reference implementation and deterministic regression test show different loss values."
        ),
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar(tmp_path).score_issue(base, issue, [])

    assert reason is None
    assert candidate is not None
    assert candidate["track"] == LLM_ALGORITHM_TRACK
    assert candidate["algorithm_evidence"]["qualified"] is True
    assert "公式" in candidate["why"]


def test_algorithm_issues_have_a_reserved_inspection_lane():
    agents = [
        {
            "repo": "google/adk-python",
            "num": index,
            "title": "Streaming tool call fails",
            "labels": ["bug"],
            "created": f"2026-08-05T00:{index:02d}:00Z",
        }
        for index in range(30)
    ]
    algorithms = [
        {
            "repo": "huggingface/trl",
            "num": 100 + index,
            "title": "GRPO advantage and gradient loss mismatch",
            "labels": ["bug"],
            "created": f"2026-08-04T00:{index:02d}:00Z",
        }
        for index in range(15)
    ]

    selected, _ = select_inspection_bases([*agents, *algorithms], limit=30)

    assert sum(item["repo"] == "huggingface/trl" for item in selected) >= 12
