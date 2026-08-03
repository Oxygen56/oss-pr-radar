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
