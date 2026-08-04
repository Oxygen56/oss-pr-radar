from datetime import UTC, datetime

from oss_pr_radar.scanner import (
    BUG_ACTIONABILITY_RE,
    Radar,
    is_dynamic_agent_infra_issue,
    requires_unavailable_hardware,
)


def test_dynamic_repo_requires_ai_specific_context():
    text = (
        "Inference, separated: the popup position changed at runtime. "
        "Retrieval Hint: large-over-small popup overlap."
    )
    assert not is_dynamic_agent_infra_issue(text)


def test_dynamic_repo_accepts_agent_or_inference_mechanism():
    assert is_dynamic_agent_infra_issue(
        "Streaming tool-call chunks lose the function-call id in the agent runtime."
    )
    assert is_dynamic_agent_infra_issue(
        "CUDA model inference batching corrupts the KV cache after a cancelled request."
    )


def test_is_not_honored_is_a_concrete_bug_signal():
    assert BUG_ACTIONABILITY_RE.search(
        "ModelSettings.parallel_tool_calls is not honored by the provider."
    )


def test_backend_context_does_not_turn_a_software_bug_into_hardware_only():
    assert not requires_unavailable_hardware(
        "[ROCm] Structured output is misclassified after reasoning",
        "bug, structured-output",
        (
            "This was reproduced while using ROCm, but it is not ROCm-specific. "
            "The root cause is the reasoning parser classifying a tool-call payload."
        ),
    )


def test_explicit_unavailable_hardware_requirement_is_preserved():
    assert requires_unavailable_hardware(
        "Kernel crash on MI300X",
        "bug, rocm",
        "The failure is only reproducible on MI300X and requires that accelerator.",
    )


def test_single_shared_scenario_slug_is_not_a_duplicate_issue(tmp_path):
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )
    radar.related_issue_cache["neomjs/neo"] = (
        [
            {
                "number": 16358,
                "html_url": "https://github.com/neomjs/neo/issues/16358",
                "title": "Large-over-small popup conversion intermittently misses park",
                "body": "The target-local popup can fail to materialize after park admission.",
            }
        ],
        None,
    )
    result = radar.assess_related_issues(
        "neomjs/neo",
        16472,
        "Large-over-small popup overlap escapes the partial-conversion window",
        "The setup score is above the expected geometric premise before assertions run.",
    )
    assert result["status"] == "none"
