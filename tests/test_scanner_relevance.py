from datetime import UTC, datetime

from oss_pr_radar.scanner import Radar, is_dynamic_agent_infra_issue


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
