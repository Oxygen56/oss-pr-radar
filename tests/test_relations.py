from oss_pr_radar.relations import assess_relations


def test_active_exact_pr_blocks_regardless_of_review_quality():
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


def test_active_exact_draft_without_tests_is_still_duplicate():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming bug",
        pull_requests=[{"number": 9, "body": "Fixes #7", "title": "Fix", "draft": True}],
    )
    assert result[0].relation == "STRONG_EXACT_DUPLICATE"


def test_same_repo_reported_issue_with_matching_title_and_tests_is_exact():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="DSpark ragged CUDA graph request slot geometry mismatch",
        pull_requests=[
            {
                "number": 9,
                "body": "Reported in #7. Correct the request slot geometry at capture time.",
                "title": "Fix DSpark ragged CUDA graph request slot geometry",
                "files": [{"filename": "tests/test_ragged_cuda_graph.py"}],
                "state": "open",
                "updated_at": "2099-01-01T00:00:00Z",
                "_repo": "a/b",
                "_timeline_event": "cross-referenced",
            }
        ],
    )

    assert result[0].exact_link is True
    assert result[0].relation == "STRONG_EXACT_DUPLICATE"


def test_cross_repo_reported_issue_stays_reference_only_even_with_tests():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="DSpark ragged CUDA graph request slot geometry mismatch",
        pull_requests=[
            {
                "number": 9,
                "body": "Reported in a/b#7. Cover the downstream reproduction.",
                "title": "Fix DSpark ragged CUDA graph request slot geometry",
                "files": [{"filename": "tests/test_ragged_cuda_graph.py"}],
                "state": "open",
                "updated_at": "2099-01-01T00:00:00Z",
                "_repo": "downstream/e2e",
                "_timeline_event": "cross-referenced",
            }
        ],
    )

    assert result[0].exact_link is False
    assert result[0].relation == "REFERENCE_ONLY"


def test_stale_exact_pr_without_maintainer_signal_can_be_competitive():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming bug",
        pull_requests=[
            {
                "number": 9,
                "body": "Fixes #7",
                "title": "Fix",
                "draft": True,
                "updated_at": "2000-01-01T00:00:00Z",
            }
        ],
    )
    assert result[0].relation == "WEAK_OR_PARTIAL_EXACT"


def test_maintainer_owned_exact_pr_with_tests_blocks_even_when_ci_is_red():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming tool arguments disappear",
        pull_requests=[
            {
                "number": 9,
                "body": "Fixes #7 with focused regression coverage.",
                "title": "Fix streaming tool arguments",
                "files": [{"filename": "tests/test_streaming.py"}],
                "checks": [{"conclusion": "failure"}],
                "author_association": "COLLABORATOR",
                "draft": False,
            }
        ],
    )
    assert result[0].maintainer_owned is True
    assert result[0].relation == "STRONG_EXACT_DUPLICATE"


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


def test_reverse_cross_reference_to_older_merged_pr_does_not_claim_coverage():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Opus model rejects temperature",
        pull_requests=[
            {
                "number": 9,
                "body": "Adds Sonnet support and strips sampling parameters for Sonnet.",
                "title": "Add Sonnet model support",
                "state": "closed",
                "merged_at": "2026-07-01T00:00:00Z",
                "_linked_from_timeline": True,
                "_timeline_event": "cross-referenced",
            }
        ],
    )

    assert result[0].exact_link is False
    assert result[0].relation == "UNRELATED"


def test_development_sidebar_connection_is_an_exact_relation():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Streaming bug",
        pull_requests=[
            {
                "number": 9,
                "body": "Implements the requested change.",
                "title": "Fix streaming bug",
                "state": "open",
                "updated_at": "2099-01-01T00:00:00Z",
                "_linked_from_timeline": True,
                "_timeline_event": "connected",
            }
        ],
    )

    assert result[0].exact_link is True
    assert result[0].relation == "STRONG_EXACT_DUPLICATE"


def test_cross_repo_followup_reference_does_not_claim_upstream_coverage():
    result = assess_relations(
        repo="a/b",
        issue_number=7,
        issue_title="Web search returns unbounded page content",
        pull_requests=[
            {
                "number": 9,
                "body": (
                    "This limits an E2E test. The upstream fix is tracked in a/b#7; "
                    "this PR does not change the upstream component."
                ),
                "title": "Bound the E2E test iteration count",
                "state": "open",
                "updated_at": "2099-01-01T00:00:00Z",
                "_repo": "downstream/e2e",
            }
        ],
    )

    assert result[0].exact_link is False
    assert result[0].relation == "REFERENCE_ONLY"
