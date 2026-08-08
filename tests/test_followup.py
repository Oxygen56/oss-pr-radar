from datetime import UTC, datetime

from oss_pr_radar.followup import collect_followup
from oss_pr_radar.github_client import GitHubError


class Client:
    def open_pull_requests_by_author(self, author):
        return [
            {
                "number": 9,
                "repository_url": "https://api.github.com/repos/a/b",
            }
        ]

    def pull_request(self, repo, number):
        return {
            "number": number,
            "title": "Fix runtime",
            "html_url": "https://github.com/a/b/pull/9",
            "head": {"sha": "head"},
            "mergeable_state": "clean",
            "draft": False,
        }

    def pull_reviews(self, repo, number):
        return [
            {
                "state": "CHANGES_REQUESTED",
                "author_association": "MEMBER",
                "user": {"login": "maintainer"},
                "submitted_at": "2026-08-04T00:00:00Z",
            }
        ]

    def pull_review_threads(self, repo, number):
        return []

    def check_runs(self, repo, ref):
        return []

    def pull_files(self, repo, number):
        return [{"filename": "src/runtime.py"}]

    def check_annotations(self, repo, check_run_id):
        return []


def test_formal_maintainer_request_is_notified_once():
    state, report = collect_followup(
        Client(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )
    assert report["candidate_details"][0]["category"] == "PR_FOLLOWUP"
    assert report["workers"] == 1
    assert report["duration_seconds"] >= 0
    _, repeated = collect_followup(
        Client(),
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )
    assert repeated["candidate_details"] == []


def test_later_approval_clears_older_change_request():
    class ApprovedClient(Client):
        def pull_reviews(self, repo, number):
            return [
                {
                    "id": 1,
                    "state": "CHANGES_REQUESTED",
                    "author_association": "MEMBER",
                    "user": {"login": "maintainer"},
                    "submitted_at": "2026-08-03T00:00:00Z",
                },
                {
                    "id": 2,
                    "state": "APPROVED",
                    "author_association": "MEMBER",
                    "user": {"login": "maintainer"},
                    "submitted_at": "2026-08-04T00:00:00Z",
                },
            ]

    _, report = collect_followup(
        ApprovedClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )
    assert report["candidate_details"] == []


def test_transient_unknown_mergeability_does_not_repeat_failure_notification():
    class FailingClient(Client):
        mergeable_state = "blocked"

        def pull_request(self, repo, number):
            pull = super().pull_request(repo, number)
            pull["mergeable_state"] = self.mergeable_state
            return pull

        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 1,
                    "name": "tests",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": "https://example.test/checks/1",
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return [{"path": "src/runtime.py", "message": "failed"}]

    client = FailingClient()
    state, first = collect_followup(client, author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC))
    assert len(first["candidate_details"]) == 1

    client.mergeable_state = "unknown"
    repeated_state, repeated = collect_followup(
        client,
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert repeated["candidate_details"] == []
    assert repeated_state["items"][0]["mergeConflict"] is False
    assert repeated_state["items"][0]["actionDigest"] == state["items"][0]["actionDigest"]


def test_transient_unknown_mergeability_preserves_known_conflict():
    class ConflictedClient(Client):
        mergeable_state = "dirty"

        def pull_request(self, repo, number):
            pull = super().pull_request(repo, number)
            pull["mergeable_state"] = self.mergeable_state
            return pull

        def pull_reviews(self, repo, number):
            return []

    client = ConflictedClient()
    state, first = collect_followup(client, author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC))
    assert first["candidate_details"][0]["why"] == "分支存在合并冲突"

    client.mergeable_state = "unknown"
    repeated_state, repeated = collect_followup(
        client,
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert repeated["candidate_details"] == []
    assert repeated_state["items"][0]["mergeConflict"] is True
    assert repeated_state["items"][0]["actions"] == ["分支存在合并冲突"]


def test_state_schema_migration_does_not_repeat_unchanged_action():
    state, first = collect_followup(
        Client(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )
    assert len(first["candidate_details"]) == 1
    state["version"] = "pr_followup_v1"
    state["items"][0].pop("mergeConflict")
    state["items"][0]["actionDigest"] = "legacy-digest"

    migrated, repeated = collect_followup(
        Client(),
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert migrated["version"] == "pr_followup_v3"
    assert repeated["candidate_details"] == []


def test_initial_query_failure_preserves_state_and_emits_report():
    class FailingClient(Client):
        def open_pull_requests_by_author(self, author):
            raise GitHubError("temporary API failure")

    existing, _ = collect_followup(
        Client(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )
    state, report = collect_followup(
        FailingClient(),
        author="Oxygen56",
        existing=existing,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert report["scan_ok"] is False
    assert report["candidate_details"] == []
    assert report["errors"] == ["open_pull_requests:temporary API failure"]
    assert state["items"] == existing["items"]


def test_failed_check_only_wakes_task_when_evidence_matches_changed_file():
    class CheckClient(Client):
        details_url = "https://example.test/checks/11"

        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 11,
                    "name": "Ruff Style Check",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": self.details_url,
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return [
                {
                    "path": "src/runtime.py",
                    "start_line": 7,
                    "end_line": 7,
                    "annotation_level": "failure",
                    "message": "SIM117",
                }
            ]

    state, _ = collect_followup(
        CheckClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    item = state["items"][0]
    assert item["taskFollowupRequired"] is True
    assert item["taskActions"] == ["当前分支检查失败"]
    assert item["evidence"]["actionableCheckNames"] == ["Ruff Style Check"]

    rerun = CheckClient()
    rerun.details_url = "https://example.test/checks/12"
    rerun_state, rerun_report = collect_followup(
        rerun,
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )
    assert rerun_report["candidate_details"]
    assert rerun_state["items"][0]["taskActionDigest"] != item["taskActionDigest"]


def test_unrelated_test_failure_is_retained_without_notification_or_task_wake():
    class CheckClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 12,
                    "name": "Playwright Shard 47/70",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": "https://example.test/checks/12",
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return [{"path": "tests/unrelated.spec.ts", "message": "failed"}]

    state, report = collect_followup(
        CheckClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    assert report["candidate_details"] == []
    assert state["items"][0]["actions"] == ["CI 检查失败"]
    assert state["items"][0]["taskFollowupRequired"] is False
    assert state["items"][0]["taskActions"] == []


def test_unresolved_review_bot_thread_on_changed_file_wakes_original_task():
    class ReviewThreadClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 13,
                    "name": "Playwright Shard 47/70",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": "https://example.test/checks/13",
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return [{"path": "tests/unrelated.spec.ts", "message": "failed"}]

        def pull_review_threads(self, repo, number):
            return [
                {
                    "isResolved": False,
                    "isOutdated": False,
                    "path": "src/runtime.py",
                    "comments": {
                        "nodes": [
                            {
                                "author": {"login": "review-bot", "__typename": "Bot"},
                                "authorAssociation": "CONTRIBUTOR",
                                "body": "Add zero and negative boundary tests.",
                                "url": "https://github.com/a/b/pull/9#discussion_r1",
                                "createdAt": "2026-08-04T00:00:00Z",
                            }
                        ]
                    },
                }
            ]

    state, report = collect_followup(
        ReviewThreadClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    item = state["items"][0]
    assert item["taskFollowupRequired"] is True
    assert item["taskActions"] == ["存在未解决审查线程"]
    assert item["actions"] == ["CI 检查失败", "存在未解决审查线程"]
    assert item["evidence"]["unresolvedReviewThreads"][0]["reviewer"] == "review-bot"
    assert report["candidate_details"][0]["why"] == "存在未解决审查线程"
    assert report["candidate_details"][0]["evidence_digest"] == item["taskActionDigest"]

    class NewHeadClient(ReviewThreadClient):
        def pull_request(self, repo, number):
            pull = super().pull_request(repo, number)
            pull["head"] = {"sha": "new-head"}
            return pull

    new_state, repeated = collect_followup(
        NewHeadClient(),
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )
    assert repeated["candidate_details"] == []
    assert new_state["items"][0]["taskActionDigest"] == item["taskActionDigest"]


def test_author_reply_or_outdated_thread_does_not_wake_task():
    class AnsweredThreadClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def pull_review_threads(self, repo, number):
            return [
                {
                    "isResolved": False,
                    "isOutdated": False,
                    "path": "src/runtime.py",
                    "comments": {
                        "nodes": [
                            {
                                "author": {"login": "maintainer", "__typename": "User"},
                                "authorAssociation": "MEMBER",
                                "body": "Please add a boundary test.",
                                "url": "https://github.com/a/b/pull/9#discussion_r1",
                                "createdAt": "2026-08-04T00:00:00Z",
                            },
                            {
                                "author": {"login": "Oxygen56", "__typename": "User"},
                                "authorAssociation": "CONTRIBUTOR",
                                "body": "Addressed in the latest commit.",
                                "url": "https://github.com/a/b/pull/9#discussion_r2",
                                "createdAt": "2026-08-04T00:01:00Z",
                            },
                        ]
                    },
                },
                {
                    "isResolved": False,
                    "isOutdated": True,
                    "path": "src/runtime.py",
                    "comments": {
                        "nodes": [
                            {
                                "author": {"login": "review-bot", "__typename": "Bot"},
                                "authorAssociation": "CONTRIBUTOR",
                                "body": "Old suggestion.",
                                "url": "https://github.com/a/b/pull/9#discussion_r3",
                                "createdAt": "2026-08-03T00:00:00Z",
                            }
                        ]
                    },
                },
            ]

    state, report = collect_followup(
        AnsweredThreadClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    assert state["items"][0]["taskFollowupRequired"] is False
    assert report["candidate_details"] == []


def test_transient_review_thread_failure_preserves_previous_action_without_repeat():
    class ReviewThreadClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def pull_review_threads(self, repo, number):
            return [
                {
                    "isResolved": False,
                    "isOutdated": False,
                    "path": "src/runtime.py",
                    "comments": {
                        "nodes": [
                            {
                                "author": {"login": "review-bot", "__typename": "Bot"},
                                "authorAssociation": "CONTRIBUTOR",
                                "body": "Add boundary tests.",
                                "url": "https://github.com/a/b/pull/9#discussion_r1",
                                "createdAt": "2026-08-04T00:00:00Z",
                            }
                        ]
                    },
                }
            ]

    initial, _ = collect_followup(
        ReviewThreadClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    class FailingThreadClient(ReviewThreadClient):
        def pull_review_threads(self, repo, number):
            raise GitHubError("temporary GraphQL failure")

    repeated_state, report = collect_followup(
        FailingThreadClient(),
        author="Oxygen56",
        existing=initial,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert report["scan_ok"] is False
    assert report["candidate_details"] == []
    assert "temporary GraphQL failure" in report["errors"][0]
    assert repeated_state["items"][0]["taskFollowupRequired"] is True
    assert (
        repeated_state["items"][0]["evidence"]["unresolvedReviewThreads"]
        == initial["items"][0]["evidence"]["unresolvedReviewThreads"]
    )
