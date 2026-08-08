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


def test_security_label_is_filtered_before_candidate_scoring(tmp_path):
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )
    base = {
        "repo": "OpenHands/OpenHands",
        "num": 16356,
        "title": "Tool output is retained longer than expected",
        "url": "https://github.com/OpenHands/OpenHands/issues/16356",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "Steps to reproduce: run the agent and inspect persisted tool output. "
            "Expected behavior: transient values are removed. Actual behavior: values remain."
        ),
        "labels": [{"name": "security"}, {"name": "secrets"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "security_disclosure_required"


def test_failure_tracker_requires_a_maintainer_split(tmp_path):
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )
    base = {
        "repo": "sgl-project/sglang",
        "num": 27937,
        "title": "[Failure Tracker] PR Test (AMD)",
        "url": "https://github.com/sgl-project/sglang/issues/27937",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "Steps to reproduce: inspect the linked jobs. Expected behavior: tests pass. "
            "Actual behavior: this tracker aggregates unrelated JIT, network, timeout, "
            "and runner failures with several possible root causes."
        ),
        "labels": [],
        "assignees": [],
        "user": {"login": "bot"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "rfc_or_roadmap_without_maintainer_split"


def test_environment_dump_does_not_make_commerce_issue_ai_infra(tmp_path):
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )
    base = {
        "repo": "woocommerce/woocommerce",
        "num": 47808,
        "title": "Attribute name showing as slug when using order again",
        "url": "https://github.com/woocommerce/woocommerce/issues/47808",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "Steps to reproduce: purchase a product and use Order Again. "
            "Expected behavior: the attribute name is shown. "
            "Actual behavior: the attribute slug is shown instead.\n"
            + ("Environment details. " * 300)
            + "WP Memory Limit: 512 MB; User Agents table enabled."
        ),
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "off_topic_dynamic_repo"


def test_managed_inference_incident_is_not_an_oss_pr_candidate(tmp_path):
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )
    base = {
        "repo": "livekit/agents",
        "num": 6675,
        "title": "Livekit inference timeouts since 14th july",
        "url": "https://github.com/livekit/agents/issues/6675",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "We see intermittent timeouts when using LiveKit Inference in production. "
            "Steps to reproduce: deploy a voice agent in LiveKit Cloud and inspect "
            "the private cloud.livekit.io/projects/example/sessions/example trace. "
            "Expected behavior: minimal timeouts. Actual behavior: requests stall. "
            "If I use a third-party provider directly via its SDK then it works fine."
        ),
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "managed_inference_service_incident"


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
