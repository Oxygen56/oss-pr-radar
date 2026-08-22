import copy
import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from oss_pr_radar import scanner
from oss_pr_radar.contracts import validate_report
from oss_pr_radar.outbox import build_outbox
from oss_pr_radar.policy import decision_contract_digest
from oss_pr_radar.scanner import (
    SCANNER_MIGRATION_RECHECK_STATUSES,
    SCANNER_VERSION,
    Radar,
    candidate_issue_outcome,
    candidate_notification_digest,
    canonical_issue_identity,
    controller_terminal_issue_outcomes,
    count_seen_rechecks,
    expire_stale_rechecks,
    merge_controller_terminal_feedback,
    select_inspection_bases,
    select_seen_rechecks,
    should_skip_seen,
)
from oss_pr_radar.util import atomic_write_json


def test_paginated_gh_flattens_every_page(monkeypatch):
    captured = {}

    def fake_gh(args, timeout=18):
        captured["args"] = args
        captured["timeout"] = timeout
        return [[{"id": 1}], [{"id": 2}]], None

    monkeypatch.setattr(scanner, "gh", fake_gh)
    rows, error = scanner.gh_paginated(["api", "repos/a/b/issues"], timeout=41)
    assert error is None
    assert rows == [{"id": 1}, {"id": 2}]
    assert captured["args"][-2:] == ["--paginate", "--slurp"]
    assert captured["timeout"] == 41


def test_probe_code_paths_excludes_symbol_only_anchors():
    assert scanner.probe_code_paths(
        ["`OD_NODE_BIN`", "`taskId`", "`pwsh`", "apps/daemon/src/server.ts"]
    ) == ["apps/daemon/src/server.ts"]


def test_semantic_review_retry_replaces_pre_llm_candidate_outcome():
    outcome = candidate_issue_outcome(
        {
            "repo": "a/b",
            "num": 1,
            "track": "agent_ai_infra",
            "category": "SEMANTIC_REVIEW_RETRY",
            "gate_decision": "RETRY_REQUIRED",
            "auto_spawn": False,
            "llm_review": {"status": "retry", "error_category": "timeout"},
        }
    )

    assert outcome == {
        "status": "deferred",
        "reason": "semantic_review_retry",
        "classification": "blocked_pre_task",
        "auto_spawn": False,
        "track": "agent_ai_infra",
        "category": "SEMANTIC_REVIEW_RETRY",
        "gate_decision": "RETRY_REQUIRED",
    }


def test_semantic_review_retry_with_successful_model_call_is_still_deferred():
    outcome = candidate_issue_outcome(
        {
            "repo": "a/b",
            "num": 1,
            "track": "llm_algorithm",
            "category": "SEMANTIC_REVIEW_RETRY",
            "gate_decision": "RETRY_REQUIRED",
            "auto_spawn": False,
            "llm_review": {"status": "ok", "semanticSignal": "RETRY"},
        }
    )

    assert outcome["status"] == "deferred"
    assert outcome["reason"] == "semantic_review_retry"


def test_old_budget_rechecks_expire_but_future_issue_updates_can_rearm():
    now = datetime(2026, 8, 15, tzinfo=UTC)
    seen = {
        "a/b#1": {
            "status": "inspection_budget_deferred",
            "first_deferred_at": (now - timedelta(hours=25)).isoformat(),
            "issue_updated": "2026-08-10T00:00:00Z",
        }
    }

    assert expire_stale_rechecks(seen, now) == 1
    assert seen["a/b#1"]["status"] == "deferred_expired"
    assert not should_skip_seen(seen["a/b#1"], "2026-08-15T01:00:00Z", now)


def test_gh_honors_full_timeout_without_proxy(monkeypatch):
    captured = {}
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(args, 0, stdout="[]", stderr="")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    data, error = scanner.gh(["api", "repos/a/b/pulls"], timeout=37)

    assert error is None
    assert data == []
    assert captured["timeout"] == 37


def test_single_page_collection_does_not_enable_pagination(monkeypatch):
    captured = {}

    def fake_gh(args, timeout=18):
        captured["args"] = args
        captured["timeout"] = timeout
        return [{"id": 1}], None

    monkeypatch.setattr(scanner, "gh", fake_gh)
    rows, error = scanner.gh_list_page(["api", "repos/a/b/pulls", "-f", "per_page=100"], timeout=29)

    assert error is None
    assert rows == [{"id": 1}]
    assert "--paginate" not in captured["args"]
    assert captured["timeout"] == 29


def test_missing_issue_is_terminal_but_transient_fetch_failure_requeues(monkeypatch, tmp_path):
    def run_with_error(error):
        instance = Radar(
            datetime.now(UTC),
            2,
            tmp_path / f"seen-{len(error)}.json",
            "",
            dry_run=True,
            notify=False,
        )
        monkeypatch.setattr(instance, "repo_quality", lambda *_args: (True, "ok"))

        def missing_issue(*_args):
            instance._last_issue_lookup_error = error
            return None

        monkeypatch.setattr(instance, "issue", missing_issue)
        key = "example/project#17"
        instance.shortlist(
            {
                key: {
                    "repo": "example/project",
                    "num": 17,
                    "title": "Tool result is lost",
                    "url": "https://github.com/example/project/issues/17",
                    "updated": "2026-08-05T00:00:00Z",
                    "labels": ["bug"],
                    "assignees": [],
                    "_explicit_recheck": True,
                }
            }
        )
        return instance, key

    missing, key = run_with_error("gh: Not Found (HTTP 404)")
    transient, transient_key = run_with_error("timeout")

    assert missing.issue_outcomes[key]["reason"] == "issue_not_found"
    assert missing.seen[key]["status"] == "issue_not_found"
    assert transient.issue_outcomes[transient_key]["reason"] == "issue_fetch_failed"
    assert transient.seen[transient_key]["status"] == "status_update"


def test_transferred_issue_uses_canonical_identity_for_every_followup(monkeypatch, tmp_path):
    instance = Radar(
        datetime(2026, 8, 22, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        notify=False,
    )
    base = {
        "repo": "langgenius/dify",
        "num": 40768,
        "title": "Persistent memory for agents",
        "url": "https://github.com/langgenius/dify/issues/40768",
        "updated": "2026-08-14T12:05:00Z",
        "labels": ["bug"],
        "assignees": [],
        "_explicit_recheck": True,
    }
    issue = {
        "number": 2885,
        "state": "open",
        "title": base["title"],
        "body": "A reproducible agent memory bug with src/plugin.py as the failing path.",
        "updated_at": base["updated"],
        "repository_url": "https://api.github.com/repos/langgenius/dify-plugins",
        "html_url": "https://github.com/langgenius/dify-plugins/issues/2885",
    }
    followups = []
    scored = {
        **base,
        "score": 10,
        "bucket": "immediate",
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "public_submission_allowed": True,
        "hardware_compatible": True,
        "risk": "Low",
        "next_step": "Reproduce locally.",
        "track": "agent_ai_infra",
        "actionability_evidence": {"code_anchors": ["src/plugin.py"], "probe_ready": True},
        "test_path": "Run the focused regression.",
    }

    monkeypatch.setattr(instance, "repo_quality", lambda *_args: (True, "ok"))
    monkeypatch.setattr(instance, "issue", lambda *_args: issue)
    monkeypatch.setattr(
        instance,
        "comments",
        lambda repo, number: followups.append(("comments", repo, number)) or [],
    )

    def score_issue(canonical_base, *_args):
        followups.append(("score", canonical_base["repo"], canonical_base["num"]))
        return scored | canonical_base, None

    monkeypatch.setattr(instance, "score_issue", score_issue)
    monkeypatch.setattr(
        instance,
        "submission_policy",
        lambda repo: followups.append(("policy", repo, 0)) or "normal",
    )
    monkeypatch.setattr(
        instance,
        "assess_related_issues",
        lambda repo, number, *_args: (
            followups.append(("related", repo, number)) or {"status": "none", "issues": []}
        ),
    )
    monkeypatch.setattr(
        instance,
        "assess_open_prs",
        lambda repo, number, *_args: (
            followups.append(("prs", repo, number)) or {"status": "none", "prs": []}
        ),
    )
    monkeypatch.setattr(
        instance,
        "default_branch_evidence",
        lambda repo: (
            followups.append(("base", repo, 0))
            or {"status": "ok", "defaultBranch": "main", "baseSha": "a" * 40}
        ),
    )

    candidates, _, inspected = instance.shortlist({"langgenius/dify#40768": base})

    assert inspected == 1
    assert candidates[0]["repo"] == "langgenius/dify-plugins"
    assert candidates[0]["num"] == 2885
    assert all(call[1] == "langgenius/dify-plugins" for call in followups)
    assert all(call[2] in {0, 2885} for call in followups)
    assert instance.issue_outcomes["langgenius/dify#40768"] == {
        "status": "rejected",
        "reason": "issue_transferred",
        "canonical_key": "langgenius/dify-plugins#2885",
    }
    assert instance.seen["langgenius/dify#40768"]["status"] == "issue_transferred"


def test_canonical_issue_identity_falls_back_to_html_url():
    assert canonical_issue_identity(
        "langgenius/dify",
        40768,
        {"html_url": "https://github.com/langgenius/dify-plugins/issues/2885"},
    ) == ("langgenius/dify-plugins", 2885)


def test_optional_discovery_retries_rate_limit(monkeypatch, tmp_path):
    calls = 0
    clock = [0.0]
    sleeps = []

    def fake_gh(_args, timeout=18):
        nonlocal calls
        calls += 1
        if calls == 1:
            return None, "API rate limit exceeded for installation"
        return {
            "items": [
                {
                    "number": 7,
                    "title": "Remote MCP state is process-local",
                    "html_url": "https://github.com/example/project/issues/7",
                    "repository_url": "https://api.github.com/repos/example/project",
                    "state": "open",
                    "labels": [{"name": "bug"}],
                    "assignees": [],
                }
            ]
        }, None

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(scanner, "gh", fake_gh)
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        sleep_fn=sleep,
        monotonic_fn=lambda: clock[0],
    )
    items = {}
    radar.add_search(items, "is:issue is:open label:bug MCP", 15, required=False)

    assert calls == 2
    assert 3.0 in sleeps
    assert radar.errors == []
    assert "example/project#7" in items


def test_searches_share_pacing_across_discovery_and_duplicate_audits(monkeypatch, tmp_path):
    clock = [0.0]
    sleeps = []

    def fake_gh(_args, timeout=18):
        return {"items": []}, None

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(scanner, "gh", fake_gh)
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        sleep_fn=sleep,
        monotonic_fn=lambda: clock[0],
    )

    radar.search_issues("is:issue MCP", 10)
    radar.search_issues("repo:example/project is:pr tool_call", 10)

    assert sleeps == [scanner.SEARCH_MIN_INTERVAL_SECONDS]


@pytest.mark.parametrize(
    ("policy", "related_status", "pr_status", "expected_reason"),
    [
        ("policy_unknown", "none", "none", "policy_lookup_failed"),
        ("normal", "lookup_failed", "none", "related_issue_lookup_failed"),
        ("normal", "none", "lookup_failed", "open_pr_lookup_failed"),
    ],
)
def test_critical_evidence_lookup_failure_is_silently_requeued(
    monkeypatch,
    tmp_path,
    policy,
    related_status,
    pr_status,
    expected_reason,
):
    seen_path = tmp_path / f"{expected_reason}.json"
    atomic_write_json(
        seen_path,
        {
            "example/project#19": {
                "status": "queued_outbox",
                "notification_digest": "prior-notification",
                "notification_scanner_version": "scanner-at-notification",
            }
        },
    )
    radar = Radar(
        datetime(2026, 8, 9, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    key = "example/project#19"
    base = {
        "repo": "example/project",
        "num": 19,
        "title": "Tool result disappears after resume",
        "url": "https://github.com/example/project/issues/19",
        "updated": "2026-08-09T00:00:00Z",
        "labels": ["bug"],
        "assignees": [],
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "updated_at": base["updated"],
        "body": "Steps to reproduce the tool result loss.",
    }
    scored = {
        **base,
        "score": 10,
        "bucket": "immediate",
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "public_submission_allowed": True,
        "hardware_compatible": True,
        "risk": "Low",
        "next_step": "Reproduce locally.",
    }
    monkeypatch.setattr(radar, "repo_quality", lambda *_args: (True, "ok"))
    monkeypatch.setattr(radar, "issue", lambda *_args: issue)
    monkeypatch.setattr(radar, "comments", lambda *_args: [])
    monkeypatch.setattr(radar, "score_issue", lambda *_args: (scored.copy(), None))
    monkeypatch.setattr(radar, "submission_policy", lambda *_args: policy)
    monkeypatch.setattr(
        radar,
        "assess_related_issues",
        lambda *_args: {"status": related_status, "issues": []},
    )
    monkeypatch.setattr(
        radar,
        "assess_open_prs",
        lambda *_args: {"status": pr_status, "prs": []},
    )

    candidates, _, _ = radar.shortlist({key: base})

    assert candidates == []
    assert radar.issue_outcomes[key] == {"status": "deferred", "reason": expected_reason}
    assert radar.seen[key]["status"] == "status_update"
    assert radar.seen[key]["requeue_reason"] == "critical_evidence_fetch_failure"
    assert radar.seen[key]["deferred_from_status"] == "queued_outbox"
    assert radar.seen[key]["notification_digest"] == "prior-notification"
    assert radar.seen[key]["notification_scanner_version"] == "scanner-at-notification"


def test_deadline_deferral_preserves_notification_identity(tmp_path):
    seen_path = tmp_path / "seen.json"
    atomic_write_json(
        seen_path,
        {
            "example/project#20": {
                "status": "queued_outbox",
                "notification_digest": "prior-notification",
                "notification_scanner_version": "scanner-at-notification",
            }
        },
    )
    radar = Radar(
        datetime(2026, 8, 9, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
        deep_inspection_deadline_seconds=0,
    )
    key = "example/project#20"
    base = {
        "repo": "example/project",
        "num": 20,
        "title": "Tool result disappears after resume",
        "url": "https://github.com/example/project/issues/20",
        "updated": "2026-08-09T00:00:00Z",
        "labels": ["bug"],
        "assignees": [],
    }

    candidates, _, _ = radar.shortlist({key: base})

    assert candidates == []
    assert radar.seen[key]["status"] == "inspection_budget_deferred"
    assert radar.seen[key]["deferred_from_status"] == "queued_outbox"
    assert radar.seen[key]["notification_digest"] == "prior-notification"
    assert radar.seen[key]["notification_scanner_version"] == "scanner-at-notification"


def test_notification_digest_ignores_llm_wording_and_age_churn():
    candidate = {
        "repo": "google/adk-python",
        "num": 6585,
        "title": "Remote stream ends before terminal state",
        "scanner_version": "scanner-v1",
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "submission_policy": "normal",
        "why": "First wording",
        "expected_changes": "First implementation prose",
        "llm_review": {"decision": "NEW_CLEAN_CANDIDATE", "confidence": 0.85},
        "open_pr_assessment": {
            "status": "none",
            "summary": "No related pull request",
            "prs": [{"number": 12, "state": "OPEN", "age_days": 20}],
        },
    }
    reworded = copy.deepcopy(candidate)
    reworded["why"] = "Equivalent second wording"
    reworded["expected_changes"] = "Equivalent implementation prose"
    reworded["llm_review"]["confidence"] = 0.8
    reworded["open_pr_assessment"]["prs"][0]["age_days"] = 21
    reworded["scanner_version"] = "scanner-v2"

    assert candidate_notification_digest(candidate) == candidate_notification_digest(reworded)
    assert candidate_notification_digest(
        candidate, bind_scanner_version=True
    ) != candidate_notification_digest(reworded, bind_scanner_version=True)

    reworded["open_pr_assessment"]["prs"][0]["state"] = "CLOSED"
    assert candidate_notification_digest(candidate) != candidate_notification_digest(reworded)


def test_conditional_claim_blocks_cloud_candidate(tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    base = {
        "repo": "example/project",
        "num": 1,
        "title": "Tool call streaming crashes",
        "url": "https://github.com/example/project/issues/1",
        "_explicit_recheck": True,
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": "Steps to reproduce: start a streaming tool call. Expected: completes. Actual: crashes.",
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }
    comments = [
        {
            "body": "Have anyone started this? If not then I can try this one.",
            "user": {"login": "contributor"},
            "author_association": "NONE",
        }
    ]
    candidate, reason = radar.score_issue(base, issue, comments)
    assert candidate is None
    assert reason == "someone_active"


def test_issue_author_ready_fix_branches_block_cloud_candidate(tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    base = {
        "repo": "example/project",
        "num": 1,
        "title": "Multi-output rollout corrupts trajectories",
        "url": "https://github.com/example/project/issues/1",
        "_explicit_recheck": True,
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "Three reproducible runtime bugs. I have fixes for all three, "
            "each on its own branch with a regression test, and can open PRs."
        ),
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "someone_active"


def test_contributor_confirmation_that_fix_is_on_current_main_is_terminal(tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    base = {
        "repo": "example/project",
        "num": 1,
        "title": "Large tool result is truncated",
        "url": "https://github.com/example/project/issues/1",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": "Large results are truncated because process.exit races stdout flush.",
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }
    comments = [
        {
            "body": "This looks fixed on current `main` by PR #123.",
            "user": {"login": "contributor"},
            "author_association": "CONTRIBUTOR",
        }
    ]

    candidate, reason = radar.score_issue(base, issue, comments)

    assert candidate is None
    assert reason == "resolved_upstream"


def test_issue_template_and_label_approval_gate_prevents_auto_spawn(tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    base = {
        "repo": "google/adk-python",
        "num": 2,
        "title": "Agent selection is ignored",
        "url": "https://github.com/google/adk-python/issues/2",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "PRs will be rejected if the linked issue does not have `status:approved`.\n"
            "Steps to reproduce: select one agent. Actual: all agents are modified.\n"
            "Root cause: discovery is used instead of the selected agent IDs."
        ),
        "labels": [{"name": "bug"}, {"name": "status:needs-review"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert reason is None
    assert candidate is not None
    assert candidate["category"] == "WAIT_MAINTAINER"
    assert candidate["gate_decision"] == "HUMAN_REVIEW"
    assert candidate["auto_spawn"] is False
    assert candidate["actionability_evidence"]["needs_confirmation"] is True


def test_help_wanted_does_not_turn_an_unsplit_rfc_into_a_clean_candidate(tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    base = {
        "repo": "example/project",
        "num": 388,
        "title": "[RFC]: Fail fast across every runtime path",
        "url": "https://github.com/example/project/issues/388",
        "_explicit_recheck": True,
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": (
            "This roadmap proposes a repository-wide policy. "
            "One possible anchor is runtime/config.py:42, but the implementation split "
            "has not been approved."
        ),
        "labels": [{"name": "bug"}, {"name": "help wanted"}],
        "assignees": [],
        "user": {"login": "maintainer"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "rfc_or_roadmap_without_maintainer_split"


def test_offer_to_send_small_pr_blocks_cloud_candidate(tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    base = {
        "repo": "example/project",
        "num": 1,
        "title": "Distributed attention truncates remainder tokens",
        "url": "https://github.com/example/project/issues/1",
        "_explicit_recheck": True,
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": "Non-divisible sequence lengths produce incorrect output.",
        "labels": [{"name": "bug"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }
    comments = [
        {
            "body": (
                "If you would take it, I am happy to send a small PR "
                "adding the assertion with a test."
            ),
            "user": {"login": "contributor"},
            "author_association": "NONE",
        }
    ]

    candidate, reason = radar.score_issue(base, issue, comments)

    assert candidate is None
    assert reason == "someone_active"


def test_comment_fetch_failure_is_exposed(monkeypatch, tmp_path):
    radar = Radar(
        datetime.now(UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
    )
    monkeypatch.setattr(scanner, "gh_paginated", lambda *args, **kwargs: (None, "timeout"))
    assert radar.comments("example/project", 1) == []
    assert radar._last_comments_lookup_error == "timeout"


def test_outbox_mode_marks_candidates_as_queued(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    candidate = {
        "repo": "example/project",
        "num": 7,
        "title": "Streaming tool-call chunks lose their id",
        "url": "https://github.com/example/project/issues/7",
        "score": 9,
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "labels": ["bug"],
        "issue_updated": "2026-08-04T00:00:00Z",
        "submission_policy": "normal",
        "public_submission_allowed": True,
        "actionability_evidence": {"public_repro_signals": 1},
        "open_pr_assessment": {"status": "none"},
        "related_issue_assessment": {"status": "none"},
    }

    class IdentityEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            return candidates

    monkeypatch.setattr(radar, "collect_items", lambda: {"example/project#7": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", IdentityEvaluator)

    result = radar.run(None)
    seen = json.loads(seen_path.read_text(encoding="utf-8"))
    assert result["notification_mode"] == "outbox"
    assert seen["example/project#7"]["status"] == "queued_outbox"
    assert seen["example/project#7"]["notification_digest"]
    assert seen["example/project#7"]["notification_scanner_version"] == SCANNER_VERSION


def test_semantic_regate_demotes_stale_auto_spawn_and_report_validates(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    report_path = tmp_path / "scan.json"
    candidate = {
        "repo": "example/project",
        "num": 7,
        "title": "Streaming tool-call chunks lose their id",
        "url": "https://github.com/example/project/issues/7",
        "score": 9,
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "notify": True,
        "maturity": "mature",
        "track": "agent_ai_infra",
        "labels": ["bug"],
        "issue_updated": "2026-08-04T00:00:00Z",
        "submission_policy": "normal",
        "public_submission_allowed": True,
        "actionability_evidence": {"public_repro_signals": 1},
        "open_pr_assessment": {"status": "none"},
        "related_issue_assessment": {"status": "none"},
        "llm_review": {
            "status": "ok",
            "semanticSignal": "NO_OBJECTION",
            "confidence": 0.95,
        },
        "preTaskEvidence": {
            "issue": {"state": "open", "assignees": []},
            "baseSha": "a" * 40,
            "issueDigest": "issue-digest",
            "policy": {"status": "normal"},
            "codePathsPlan": ["src/runtime.py"],
            "reproductionPathPlan": True,
            "validationPathPlan": True,
            "matureRepository": True,
            "duplicate": {"status": "none"},
        },
        "preTaskGate": {"allowed": True, "expected": {}},
    }

    class UncertainEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            candidates[0]["llm_review"] = {
                "status": "ok",
                "semanticSignal": "RETRY",
                "confidence": 0.9,
            }
            return candidates

    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(radar, "collect_items", lambda: {"example/project#7": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", UncertainEvaluator)

    radar.run(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate_report(report, require_v2=True)
    final = report["candidate_details"][0]
    assert final["preTaskGate"]["allowed"] is False
    assert final["auto_spawn"] is False
    assert final["notify"] is False
    assert final["maturity"] == "exploration"
    assert final["category"] == "WAIT_MAINTAINER"
    assert final["gate_decision"] == "HUMAN_REVIEW"


@pytest.mark.parametrize(
    "retry_review",
    [
        {"status": "retry", "semanticSignal": "RETRY", "error_category": "timeout"},
        {"status": "ok", "semanticSignal": "RETRY", "confidence": 0.9},
    ],
)
def test_bounded_algorithm_semantic_retry_validates_and_is_rechecked(
    monkeypatch, tmp_path, retry_review
):
    seen_path = tmp_path / "seen.json"
    report_path = tmp_path / "scan.json"
    candidate = {
        "repo": "example/project",
        "num": 8291,
        "title": "Algorithm dependency needs an implementation decision",
        "url": "https://github.com/example/project/issues/8291",
        "score": 9,
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "notify": True,
        "maturity": "mature",
        "track": "llm_algorithm",
        "labels": ["bug"],
        "issue_updated": "2026-08-04T00:00:00Z",
        "submission_policy": "normal",
        "public_submission_allowed": True,
        "actionability_evidence": {
            "needs_confirmation": True,
            "wait_reasons": ["DEPENDENCY", "OWNERSHIP_REVIEW"],
        },
        "algorithm_evidence": {
            "score": 5,
            "mechanism_count": 2,
            "qualified": False,
            "code_path_signal": True,
            "operational_only": False,
        },
        "open_pr_assessment": {"status": "human_review_required", "prs": []},
        "related_issue_assessment": {"status": "none"},
        "llm_review": {
            "status": "ok",
            "semanticSignal": "NO_OBJECTION",
            "confidence": 0.95,
        },
        "preTaskEvidence": {
            "issue": {"state": "open", "assignees": []},
            "baseSha": "a" * 40,
            "issueDigest": "issue-digest",
            "policy": {"status": "normal"},
            "codePathsPlan": ["src/runtime.py"],
            "reproductionPathPlan": True,
            "validationPathPlan": True,
            "matureRepository": True,
            "duplicate": {"status": "none"},
        },
        "preTaskGate": {"allowed": True, "expected": {}},
    }

    class RetryEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            candidates[0]["llm_review"] = dict(retry_review)
            candidates[0]["category"] = "SEMANTIC_REVIEW_RETRY"
            candidates[0]["gate_decision"] = "RETRY_REQUIRED"
            candidates[0]["auto_spawn"] = False
            candidates[0]["notify"] = False
            return candidates

    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(radar, "collect_items", lambda: {"example/project#8291": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", RetryEvaluator)

    result = radar.run(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validate_report(report, require_v2=True)
    final = report["candidate_details"][0]
    seen = json.loads(seen_path.read_text(encoding="utf-8"))

    assert final["category"] == "SEMANTIC_REVIEW_RETRY"
    assert final["gate_decision"] == "RETRY_REQUIRED"
    assert final["auto_spawn"] is False
    assert final["notify"] is False
    assert final["maturity"] == "exploration"
    assert final["preTaskGate"]["allowed"] is False
    assert final["preTaskGate"]["classification"] == "blocked_pre_task"
    assert result["auto_spawn_candidates"] == 0
    assert result["notification_candidate_count"] == 0
    assert result["issue_outcomes"]["example/project#8291"]["status"] == "deferred"
    assert seen["example/project#8291"]["status"] == "semantic_review_retry"
    assert select_seen_rechecks(seen)[0][0] == "example/project#8291"

    next_radar = Radar(
        datetime(2026, 8, 4, 1, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(next_radar, "add_repo_issues", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(next_radar, "add_search", lambda *_args, **_kwargs: None)
    items = next_radar.collect_items()
    assert items["example/project#8291"]["_explicit_recheck"] is True


def test_outbox_recovers_lost_deferred_notification_identity(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    outbox_path = tmp_path / "notification_outbox.json"
    candidate = {
        "repo": "example/project",
        "num": 7,
        "title": "Streaming tool-call chunks lose their id",
        "url": "https://github.com/example/project/issues/7",
        "score": 9,
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "labels": ["bug"],
        "issue_updated": "2026-08-04T00:00:00Z",
        "submission_policy": "needs_assignment",
        "public_submission_allowed": True,
        "actionability_evidence": {"public_repro_signals": 1},
        "open_pr_assessment": {"status": "none"},
        "related_issue_assessment": {"status": "none"},
    }
    notification_digest = candidate_notification_digest(candidate)
    outbox = build_outbox(
        {
            "run_id": "run-1",
            "scanner_version": SCANNER_VERSION,
            "candidate_details": [candidate | {"notification_digest": notification_digest}],
        },
        now=datetime(2026, 8, 4, tzinfo=UTC),
        kind="review",
    )
    atomic_write_json(outbox_path, outbox)
    atomic_write_json(
        seen_path,
        {
            "example/project#7": {
                "status": "inspection_budget_deferred",
                "deferred_from_status": "queued_outbox",
                "scanner_version": SCANNER_VERSION,
                "issue_updated": candidate["issue_updated"],
            }
        },
    )
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
        notification_outbox_path=outbox_path,
    )

    class IdentityEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            return candidates

    monkeypatch.setattr(radar, "collect_items", lambda: {"example/project#7": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", IdentityEvaluator)

    report_path = tmp_path / "scan.json"
    result = radar.run(report_path)
    seen = json.loads(seen_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    rebuilt_outbox = build_outbox(
        report,
        outbox,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
        kind="review",
    )

    assert result["notification_state_recovered"] == 1
    assert result["notification_candidate_count"] == 0
    assert result["notification_suppressed_count"] == 1
    assert seen["example/project#7"]["status"] == "queued_outbox"
    assert seen["example/project#7"]["notification_digest"] == notification_digest
    assert seen["example/project#7"]["notification_scanner_version"] == SCANNER_VERSION
    assert report["candidate_details"][0]["notification_digest"] == notification_digest
    assert rebuilt_outbox["newEventCount"] == 0


def test_legacy_version_bound_notification_is_migrated_without_resending(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    candidate = {
        "repo": "example/project",
        "num": 7,
        "title": "Streaming tool-call chunks lose their id",
        "url": "https://github.com/example/project/issues/7",
        "score": 9,
        "scanner_version": SCANNER_VERSION,
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "labels": ["bug"],
        "issue_updated": "2026-08-04T00:00:00Z",
        "submission_policy": "normal",
        "public_submission_allowed": True,
        "actionability_evidence": {"public_repro_signals": 1},
        "open_pr_assessment": {"status": "human_review_required", "prs": []},
        "related_issue_assessment": {"status": "none"},
    }
    legacy_candidate = candidate | {"scanner_version": "oss_pr_radar_v39_language_gates"}
    legacy_digest = candidate_notification_digest(
        legacy_candidate,
        bind_scanner_version=True,
    )
    seen_path.write_text(
        json.dumps(
            {
                "example/project#7": {
                    "analyzed": "2026-08-04T00:00:00Z",
                    "notified": False,
                    "status": "policy_migration_pending",
                    "deferred_from_status": "queued_outbox",
                    "notification_digest": legacy_digest,
                    "notification_scanner_version": "oss_pr_radar_v39_language_gates",
                    "scanner_version": "newer-state-contract",
                    "issue_updated": candidate["issue_updated"],
                }
            }
        ),
        encoding="utf-8",
    )
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )

    class IdentityEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            return candidates

    monkeypatch.setattr(radar, "collect_items", lambda: {"example/project#7": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", IdentityEvaluator)

    result = radar.run(None)
    seen = json.loads(seen_path.read_text(encoding="utf-8"))

    assert result["notification_candidate_count"] == 0
    assert result["notification_suppressed_count"] == 1
    assert seen["example/project#7"]["status"] == "queued_outbox"
    assert seen["example/project#7"]["notification_digest"] == candidate_notification_digest(
        candidate
    )
    assert seen["example/project#7"]["notification_scanner_version"] == SCANNER_VERSION
    assert "deferred_from_status" not in seen["example/project#7"]


def test_llm_rejection_is_persisted_as_terminal_seen_status(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    candidate = {
        "repo": "example/project",
        "num": 8,
        "title": "Provider timeout",
        "url": "https://github.com/example/project/issues/8",
        "issue_updated": "2026-08-04T00:00:00Z",
    }

    class RejectingEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            self.rejected_candidates = {
                "example/project#8": {
                    "reason": "llm_reject",
                    "candidate": candidates[0],
                    "review": {"decision": "REJECT", "score": 3},
                }
            }
            return []

    monkeypatch.setattr(radar, "collect_items", lambda: {"example/project#8": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", RejectingEvaluator)

    result = radar.run(None)
    seen = json.loads(seen_path.read_text(encoding="utf-8"))

    assert seen["example/project#8"]["status"] == "llm_reject"
    assert result["forced_recheck_results"] == {}
    assert result["rejection_summary"]["llm_reject"] == 1


def test_seen_deferred_items_are_tracked_as_forced_rechecks(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(
        json.dumps(
            {
                "example/project#9": {
                    "status": "inspection_budget_deferred",
                    "title": "Tool result disappears after resume",
                    "url": "https://github.com/example/project/issues/9",
                    "issue_updated": "2026-08-04T00:00:00Z",
                    "requeued_at": "2026-08-04T00:05:00Z",
                }
            }
        ),
        encoding="utf-8",
    )
    radar = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(radar, "add_repo_issues", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(radar, "add_search", lambda *_args, **_kwargs: None)

    items = radar.collect_items()
    assert items["example/project#9"]["_explicit_recheck"] is True
    assert "example/project#9" in radar.forced_recheck_keys


def test_changed_hardware_filter_rechecks_old_rejections():
    assert "hardware_unavailable" in SCANNER_MIGRATION_RECHECK_STATUSES


def test_dispatch_decision_change_rechecks_queued_candidate(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(
        json.dumps(
            {
                "example/project#11": {
                    "status": "queued_outbox",
                    "title": "Provider settings are overwritten",
                    "url": "https://github.com/example/project/issues/11",
                    "issue_updated": "2026-08-04T06:40:17Z",
                    "scanner_version": SCANNER_VERSION,
                    "decision_contract_digest": "previous-decision-contract",
                }
            }
        ),
        encoding="utf-8",
    )
    radar = Radar(
        datetime(2026, 8, 4, 7, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(radar, "add_repo_issues", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(radar, "add_search", lambda *_args, **_kwargs: None)

    items = radar.collect_items()

    assert decision_contract_digest() != "previous-decision-contract"
    assert items["example/project#11"]["_explicit_recheck"] is True
    assert "example/project#11" in radar.forced_recheck_keys


def test_migration_rechecks_prioritize_actionable_queue_over_newer_rejections(
    monkeypatch, tmp_path
):
    seen = {
        "example/project#11": {
            "status": "queued_outbox",
            "title": "Provider settings are overwritten",
            "url": "https://github.com/example/project/issues/11",
            "issue_updated": "2026-08-01T00:00:00Z",
            "scanner_version": "older",
        }
    }
    for index in range(12):
        seen[f"example/hardware#{index}"] = {
            "status": "hardware_unavailable",
            "title": f"Hardware issue {index}",
            "url": f"https://github.com/example/hardware/issues/{index}",
            "issue_updated": f"2026-08-08T{index:02d}:00:00Z",
            "scanner_version": "older",
        }
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(json.dumps(seen), encoding="utf-8")
    radar = Radar(
        datetime(2026, 8, 9, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(radar, "add_repo_issues", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(radar, "add_search", lambda *_args, **_kwargs: None)

    items = radar.collect_items()

    assert "example/project#11" in items
    assert "example/project#11" in radar.forced_recheck_keys
    assert len(radar.forced_recheck_keys) == scanner.MAX_SCANNER_MIGRATION_RECHECKS


def test_scanner_migration_reopens_repaired_relevance_rejections_only():
    assert "off_topic" in SCANNER_MIGRATION_RECHECK_STATUSES
    assert "trivial" in SCANNER_MIGRATION_RECHECK_STATUSES
    assert "no_bug_or_maintainer_actionability" in SCANNER_MIGRATION_RECHECK_STATUSES
    assert "algorithm_mechanism_evidence_low" in SCANNER_MIGRATION_RECHECK_STATUSES
    assert "frontend_interaction_issue" not in SCANNER_MIGRATION_RECHECK_STATUSES


def test_controller_terminal_feedback_survives_scanner_migration_until_issue_changes():
    old = {
        "status": "controller_terminal",
        "analyzed": "2026-08-09T00:00:00Z",
        "issue_updated": "2026-08-08T20:00:00Z",
        "scanner_version": "older",
        "decision_contract_digest": "older",
    }

    assert should_skip_seen(
        old,
        issue_updated="2026-08-08T20:00:00Z",
        now=datetime(2026, 8, 9, tzinfo=UTC),
        scanner_version=SCANNER_VERSION,
        decision_digest=decision_contract_digest(),
    )
    assert not should_skip_seen(
        old,
        issue_updated="2026-08-09T01:00:00Z",
        now=datetime(2026, 8, 9, tzinfo=UTC),
        scanner_version=SCANNER_VERSION,
        decision_digest=decision_contract_digest(),
    )


def test_stale_pending_recheck_cannot_reopen_unchanged_controller_terminal(monkeypatch, tmp_path):
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(
        json.dumps(
            {
                "example/project#1": {
                    "status": "controller_terminal",
                    "issue_updated": "2026-08-08T20:00:00Z",
                    "analyzed": "2026-08-09T00:00:00Z",
                },
                "example/project#2": {
                    "status": "controller_terminal",
                    "issue_updated": "2026-08-08T20:00:00Z",
                    "analyzed": "2026-08-09T00:00:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    radar = Radar(
        datetime(2026, 8, 9, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
        pending_rechecks={
            "example/project#1": {
                "issueTitle": "Unchanged terminal issue",
                "issueUrl": "https://github.com/example/project/issues/1",
                "issueUpdated": "2026-08-08T20:00:00Z",
            },
            "example/project#2": {
                "issueTitle": "Changed terminal issue",
                "issueUrl": "https://github.com/example/project/issues/2",
                "issueUpdated": "2026-08-09T01:00:00Z",
            },
        },
    )
    monkeypatch.setattr(radar, "add_repo_issues", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(radar, "add_search", lambda *_args, **_kwargs: None)

    items = radar.collect_items()

    assert "example/project#1" not in items
    assert "example/project#1" not in radar.forced_recheck_keys
    assert items["example/project#2"]["_explicit_recheck"] is True
    assert "example/project#2" in radar.forced_recheck_keys


def test_controller_terminal_feedback_does_not_override_newer_cloud_issue_revision():
    terminal = {
        "status": "controller_terminal",
        "issue_updated": "2026-08-08T20:00:00Z",
        "terminal_reason": "ALREADY_FIXED",
    }

    merged = merge_controller_terminal_feedback(
        {
            "a/b#1": {
                "status": "inspection_budget_deferred",
                "issue_updated": "2026-08-09T01:00:00Z",
            },
            "a/b#2": {
                "status": "inspection_budget_deferred",
                "issue_updated": "2026-08-08T20:00:00Z",
            },
        },
        {"a/b#1": terminal, "a/b#2": terminal},
    )

    assert merged["a/b#1"]["status"] == "inspection_budget_deferred"
    assert merged["a/b#2"]["status"] == "controller_terminal"


def test_controller_terminal_feedback_revokes_pending_dispatch_intents():
    outcomes = controller_terminal_issue_outcomes(
        {
            "a/b#1": {"status": "controller_terminal"},
            "a/b#2": {"status": "inspection_budget_deferred"},
        }
    )

    assert outcomes == {"a/b#1": {"status": "rejected", "reason": "controller_terminal"}}


def test_unselected_active_migrations_are_declassified_until_revalidated(monkeypatch, tmp_path):
    seen = {}
    for index in range(scanner.MAX_SCANNER_MIGRATION_RECHECKS + 3):
        seen[f"example/project#{index}"] = {
            "status": "queued_outbox",
            "title": f"Runtime issue {index}",
            "url": f"https://github.com/example/project/issues/{index}",
            "issue_updated": f"2026-08-{index + 1:02d}T00:00:00Z",
            "scanner_version": "older",
        }
    seen_path = tmp_path / "seen.json"
    seen_path.write_text(json.dumps(seen), encoding="utf-8")
    radar = Radar(
        datetime(2026, 8, 20, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
    )
    monkeypatch.setattr(radar, "add_repo_issues", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(radar, "add_search", lambda *_args, **_kwargs: None)

    radar.collect_items()

    pending = {
        key: value
        for key, value in radar.seen.items()
        if value.get("status") == "policy_migration_pending"
    }
    assert len(pending) == 3
    assert all(value["deferred_from_status"] == "queued_outbox" for value in pending.values())
    assert all(
        value["reason"] == "policy_migration_requires_revalidation" for value in pending.values()
    )
    selected = select_seen_rechecks(radar.seen)
    assert [key for key, _value in selected] == sorted(
        pending, key=lambda key: pending[key]["first_deferred_at"]
    )


def test_deferred_rechecks_have_capacity_in_addition_to_fresh_issues():
    bases = [
        {"repo": f"recheck/{index}", "num": index, "_explicit_recheck": True} for index in range(4)
    ] + [{"repo": f"fresh/{index}", "num": index} for index in range(5)]

    selected, deferred = select_inspection_bases(
        bases,
        limit=3,
        recheck_limit=2,
        per_repo_limit=1,
    )

    assert sum(bool(item.get("_explicit_recheck")) for item in selected) == 2
    assert sum(not item.get("_explicit_recheck") for item in selected) == 3
    assert len(deferred) == 4


def test_deferred_rechecks_and_fresh_issues_are_interleaved_before_deadline():
    bases = [
        {"repo": f"recheck/{index}", "num": index, "_explicit_recheck": True} for index in range(3)
    ] + [{"repo": f"fresh/{index}", "num": index} for index in range(3)]

    selected, _ = select_inspection_bases(
        bases,
        limit=3,
        recheck_limit=3,
        per_repo_limit=1,
    )

    assert [bool(item.get("_explicit_recheck")) for item in selected] == [
        True,
        False,
        True,
        False,
        True,
        False,
    ]


def test_seen_rechecks_prioritize_actionable_history_then_original_wait_time():
    seen = {
        "example/ordinary-new#1": {
            "status": "inspection_budget_deferred",
            "first_deferred_at": "2026-08-04T02:00:00Z",
            "requeued_at": "2026-08-04T02:00:00Z",
        },
        "example/actionable#2": {
            "status": "inspection_budget_deferred",
            "deferred_from_status": "queued_outbox",
            "first_deferred_at": "2026-08-04T03:00:00Z",
            "requeued_at": "2026-08-04T05:00:00Z",
        },
        "example/ordinary-old#3": {
            "status": "inspection_budget_deferred",
            "first_deferred_at": "2026-08-04T01:00:00Z",
            "requeued_at": "2026-08-04T06:00:00Z",
        },
    }

    selected = select_seen_rechecks(seen, limit=3)

    assert [key for key, _ in selected] == [
        "example/actionable#2",
        "example/ordinary-old#3",
        "example/ordinary-new#1",
    ]


def test_seen_recheck_count_reflects_final_durable_status():
    seen = {
        "example/deferred#1": {"status": "inspection_budget_deferred"},
        "example/overflow#2": {"status": "candidate_overflow"},
        "example/finished#3": {"status": "score_low"},
    }

    assert count_seen_rechecks(seen) == 2

    seen["example/deferred#1"]["status"] = "queued_outbox"
    assert count_seen_rechecks(seen) == 1


def test_repository_policy_cache_reuses_unchanged_blob_shas(monkeypatch, tmp_path):
    cache_path = tmp_path / "repo_cache.json"
    content_calls = []

    def fake_gh(args, timeout=18):
        endpoint = next(value for value in args if value.startswith("repos/"))
        if endpoint == "repos/example/project":
            return {"default_branch": "main"}, None
        if endpoint == "repos/example/project/git/trees/main":
            return {
                "truncated": False,
                "tree": [
                    {
                        "type": "blob",
                        "path": "CONTRIBUTING.md",
                        "sha": "policy-sha",
                    }
                ],
            }, None
        if endpoint == "repos/example/project/contents/CONTRIBUTING.md":
            content_calls.append(endpoint)
            return {
                "sha": "policy-sha",
                "content": "Q29udHJpYnV0aW9ucyBhcmUgd2VsY29tZS4=",
            }, None
        raise AssertionError(args)

    monkeypatch.setattr(scanner, "gh", fake_gh)
    first = Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        repo_cache_path=cache_path,
    )
    assert first.submission_policy("example/project") == "normal"
    atomic_write_json(cache_path, first.persistent_repo_cache)

    second = Radar(
        datetime(2026, 8, 4, 1, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        repo_cache_path=cache_path,
    )
    assert second.submission_policy("example/project") == "normal"
    assert content_calls == ["repos/example/project/contents/CONTRIBUTING.md"]


def test_litellm_custom_passthrough_route_enters_agent_infra_candidates(tmp_path):
    radar = Radar(datetime(2026, 8, 22, tzinfo=UTC), 2, tmp_path / "seen.json", "", dry_run=True)
    base = {
        "repo": "BerriAI/litellm",
        "num": 37925,
        "title": "Custom pass_through_endpoints prefixes can never work for file uploads",
        "url": "https://github.com/BerriAI/litellm/issues/37925",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": """A LiteLLM proxy fronts a non-default Anthropic-compatible host.
Steps to reproduce
1. Configure pass_through_endpoints at /claude-aws/v1/files.
2. Upload a file through that model gateway route.
Expected behavior: the configured target receives the request.
Actual behavior: the generic provider route wins because of route precedence and returns 422.
```bash
curl -X POST http://localhost:4000/claude-aws/v1/files -F file=@probe.txt
```
The handler in litellm/proxy/openai_files_endpoints/files_endpoints.py then derives the
custom_llm_provider from the URL segment, so another prefix never resolves correctly.
""",
        "labels": [{"name": "proxy"}, {"name": "llm translation"}],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert reason is None
    assert candidate is not None
    assert candidate["track"] == "agent_ai_infra"
    assert candidate["category"] == "NEW_CLEAN_CANDIDATE"
    assert candidate["auto_spawn"] is True


def test_active_dify_fix_beats_historical_chore_reference(tmp_path):
    radar = Radar(datetime(2026, 8, 22, tzinfo=UTC), 2, tmp_path / "seen.json", "", dry_run=True)
    base = {
        "repo": "langgenius/dify",
        "num": 41096,
        "title": "Change-email duplicate guards compare Account.email case-sensitively",
        "url": "https://github.com/langgenius/dify/issues/41096",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": """Registration started normalizing in #29978 (`chore: case insensitive email`),
but old mixed-case rows remain. Steps to reproduce:
1. Store Taken@Example.com.
2. Change another account to taken@example.com.
Expected behavior: EMAIL_IN_USE. Actual behavior: a duplicate row is written.
The checks in api/repositories/account_repository.py compare Account.email case-sensitively.
I have a fix with regression tests ready and will open a PR referencing this issue.
""",
        "labels": [],
        "assignees": [],
        "user": {"login": "reporter"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert candidate is None
    assert reason == "someone_active"


def test_deepspeed_policy_divergence_is_a_bounded_design_wait(tmp_path):
    radar = Radar(datetime(2026, 8, 22, tzinfo=UTC), 2, tmp_path / "seen.json", "", dry_run=True)
    base = {
        "repo": "deepspeedai/DeepSpeed",
        "num": 8290,
        "title": "HF tp_plan embedding_rowwise makes AutoTP reject the whole plan",
        "url": "https://github.com/deepspeedai/DeepSpeed/issues/8290",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": """deepspeed/module_inject/tp_plan_converter.py has a strict allowlist.
## Repro
```python
import torch
import deepspeed
from transformers import AutoModelForCausalLM, Qwen2Config
config = Qwen2Config(vocab_size=1000, hidden_size=128, num_attention_heads=4,
                     num_key_value_heads=4, tie_word_embeddings=True)
model = AutoModelForCausalLM.from_config(config)
engine = deepspeed.initialize(model=model, model_parameters=model.parameters(),
                              config={"tensor_parallel": {"autotp_size": 2}})
# ValueError: unsupported partition style embedding_rowwise
```
There is a policy divergence to resolve: DeepSpeed keeps the tied vocab projection
replicated, while transformers intends vocab-parallel tensor parallel sharding.
Options include preserving replication or supporting the new row-wise behavior.
""",
        "labels": [],
        "assignees": [],
        "author_association": "COLLABORATOR",
        "user": {"login": "collaborator"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert reason is None
    assert candidate is not None
    assert candidate["category"] == "WAIT_MAINTAINER"
    assert candidate["gate_decision"] == "HUMAN_REVIEW"
    assert candidate["auto_spawn"] is False
    assert candidate["algorithm_evidence"]["qualified"] is False
    assert candidate["actionability_evidence"]["probe_ready"] is True
    assert candidate["actionability_evidence"]["wait_reasons"] == ["DESIGN_CONFIRMATION"]


def test_deepspeed_followup_global_is_dependency_and_ownership_wait(tmp_path):
    radar = Radar(datetime(2026, 8, 22, tzinfo=UTC), 2, tmp_path / "seen.json", "", dry_run=True)
    base = {
        "repo": "deepspeedai/DeepSpeed",
        "num": 8291,
        "title": "Ulysses process-wide KV-head global breaks a second model",
        "url": "https://github.com/deepspeedai/DeepSpeed/issues/8291",
    }
    issue = {
        "state": "open",
        "title": base["title"],
        "body": """deepspeed/sequence/layer.py stores _ulysses_num_kv_heads process-wide.
The first sequence-parallel model locks the KV heads, so a second attention model with a
different head count silently corrupts the all-to-all shard layout and backward path.
#8241 deliberately left this global in place with its own TODO.
Suggested approach: mirror the per-model AutoTP fix in #8241 by threading the head count
through DistributedAttention and _SeqAllToAll ctx.
Regression test: run two DistributedAttention instances with different head counts through
forward and backward in the same process.
""",
        "labels": [],
        "assignees": [],
        "author_association": "COLLABORATOR",
        "user": {"login": "collaborator"},
    }

    candidate, reason = radar.score_issue(base, issue, [])

    assert reason is None
    assert candidate is not None
    assert candidate["category"] == "WAIT_MAINTAINER"
    assert candidate["gate_decision"] == "HUMAN_REVIEW"
    assert candidate["auto_spawn"] is False
    assert candidate["actionability_evidence"]["dependency_pr_numbers"] == [8241]
    assert candidate["actionability_evidence"]["wait_reasons"] == [
        "DEPENDENCY",
        "OWNERSHIP_REVIEW",
    ]
