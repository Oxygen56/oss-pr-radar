from datetime import UTC, datetime

from oss_pr_radar.scanner import Radar


def radar(tmp_path):
    return Radar(
        datetime(2026, 8, 4, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "chat",
        dry_run=True,
        notify=False,
    )


def test_one_weak_direct_pr_remains_a_competition_opportunity(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 9}])
    monkeypatch.setattr(
        instance,
        "assess_single_pr",
        lambda *args: {
            "number": 9,
            "url": "https://github.com/a/b/pull/9",
            "references_issue": True,
            "issue_body_link": False,
            "technical_complete": False,
            "score": 12,
            "test_files": 0,
            "state": "OPEN",
            "is_draft": True,
            "gaps": ["缺少测试文件", "仍是 draft"],
            "strengths": ["明确关联 issue"],
        },
    )
    result = instance.assess_open_prs("a/b", 7, "Streaming bug")
    assert result["status"] == "weak_pr_competition_possible"


def test_merged_direct_pr_is_strong_coverage(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 9}])
    monkeypatch.setattr(
        instance,
        "assess_single_pr",
        lambda *args: {
            "number": 9,
            "url": "https://github.com/a/b/pull/9",
            "references_issue": True,
            "issue_body_link": False,
            "technical_complete": False,
            "score": 10,
            "test_files": 0,
            "state": "MERGED",
            "is_draft": False,
            "gaps": ["CI/check 信息不足"],
            "strengths": ["明确关联 issue"],
        },
    )
    result = instance.assess_open_prs("a/b", 7, "Streaming bug")
    assert result["status"] == "covered_strong"


def test_nontechnical_triage_failure_does_not_create_pr_competition(monkeypatch, tmp_path):
    instance = radar(tmp_path)
    monkeypatch.setattr(instance, "open_pr_hits", lambda *args: [{"number": 1726}])
    monkeypatch.setattr(
        instance,
        "pr_detail",
        lambda *args: {
            "number": 1726,
            "title": "fix(mcp): get_episodes returns recent episodes",
            "url": "https://github.com/getzep/graphiti/pull/1726",
            "body": (
                "Fixes #1062. The uuid-ordered query returns an arbitrary stable slice. "
                "This adds a recency query while preserving the pagination helper, and "
                "documents the compatibility boundary and regression coverage."
            ),
            "state": "OPEN",
            "isDraft": False,
            "updatedAt": "2026-08-03T21:55:35Z",
            "files": [
                {"path": "graphiti_core/nodes.py"},
                {"path": "tests/test_episode_recency_ordering.py"},
                {"path": "tests/test_node_int.py"},
            ],
            "additions": 396,
            "deletions": 7,
            "changedFiles": 6,
            "statusCheckRollup": [
                {"name": "ruff", "conclusion": "SUCCESS"},
                {
                    "name": "triage",
                    "workflowName": "PR Triage",
                    "conclusion": "FAILURE",
                },
            ],
            "reviewDecision": "REVIEW_REQUIRED",
            "comments": [],
            "closingIssuesReferences": [{"number": 1062}],
        },
    )

    result = instance.assess_open_prs(
        "getzep/graphiti",
        1062,
        "get_episodes returns stale old data",
        "get_episodes uses ORDER BY uuid DESC instead of recency",
    )

    assert result["status"] == "covered_strong"
    assert result["prs"][0]["ignored_nontechnical_failed_checks"] == ["triage"]
    assert "存在失败 CI/check" not in result["prs"][0]["gaps"]
