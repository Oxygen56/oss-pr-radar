import copy
import json
import subprocess
from datetime import UTC, datetime

import pytest

from oss_pr_radar import scanner
from oss_pr_radar.policy import decision_contract_digest
from oss_pr_radar.scanner import (
    SCANNER_MIGRATION_RECHECK_STATUSES,
    SCANNER_VERSION,
    Radar,
    candidate_notification_digest,
    count_seen_rechecks,
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
    radar = Radar(
        datetime(2026, 8, 9, tzinfo=UTC),
        2,
        tmp_path / f"{expected_reason}.json",
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


def test_notification_digest_ignores_llm_wording_and_age_churn():
    candidate = {
        "repo": "google/adk-python",
        "num": 6585,
        "title": "Remote stream ends before terminal state",
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

    assert candidate_notification_digest(candidate) == candidate_notification_digest(reworded)

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


def test_scanner_migration_does_not_reopen_unrelated_terminal_rejections():
    assert "no_bug_or_maintainer_actionability" not in SCANNER_MIGRATION_RECHECK_STATUSES
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
