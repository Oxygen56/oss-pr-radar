import copy
import json
from datetime import UTC, datetime

from oss_pr_radar import scanner
from oss_pr_radar.policy import decision_contract_digest
from oss_pr_radar.scanner import (
    SCANNER_MIGRATION_RECHECK_STATUSES,
    SCANNER_VERSION,
    Radar,
    candidate_notification_digest,
    count_seen_rechecks,
    select_inspection_bases,
    select_seen_rechecks,
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
