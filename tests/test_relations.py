from oss_pr_radar.relations import assess_relations


def test_strong_exact_pr_requires_tests_and_green_checks():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming tool arguments disappear",
        pull_requests=[
            {
                "number": 9,
                "body": "Fixes #7",
                "title": "Fix streaming tool arguments",
                "files": [{"filename": "tests/test_streaming.py"}],
                "checks": [{"conclusion": "success"}],
                "draft": False,
            }
        ],
    )
    assert result[0].relation == "STRONG_EXACT_DUPLICATE"


def test_exact_draft_without_tests_is_weak():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming bug",
        pull_requests=[{"number": 9, "body": "Fixes #7", "title": "Fix", "draft": True}],
    )
    assert result[0].relation == "WEAK_OR_PARTIAL_EXACT"


def test_exact_merged_pr_blocks_even_without_test_metadata():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming bug",
        pull_requests=[
            {
                "number": 9,
                "body": "Fixes #7",
                "title": "Fix streaming",
                "state": "closed",
                "merged_at": "2026-08-01T00:00:00Z",
            }
        ],
    )
    assert result[0].relation == "STRONG_MERGED_COVERAGE"


def test_exact_closed_unmerged_pr_is_historical_not_active():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming bug",
        pull_requests=[
            {
                "number": 9,
                "body": "Fixes #7",
                "title": "Fix streaming",
                "state": "closed",
            }
        ],
    )
    assert result[0].relation == "HISTORICAL_CLOSED_EXACT"
