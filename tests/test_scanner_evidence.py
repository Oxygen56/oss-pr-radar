from datetime import UTC, datetime

from oss_pr_radar import scanner
from oss_pr_radar.scanner import Radar


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
