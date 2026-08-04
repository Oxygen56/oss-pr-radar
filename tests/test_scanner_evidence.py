import json
from datetime import UTC, datetime

from oss_pr_radar import scanner
from oss_pr_radar.scanner import SCANNER_MIGRATION_RECHECK_STATUSES, Radar


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
