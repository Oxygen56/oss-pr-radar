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
            "base": {"ref": "main", "sha": "base"},
            "mergeable_state": "clean",
            "draft": False,
        }

    def branch(self, repo, branch):
        return {"name": branch, "commit": {"sha": getattr(self, "base_sha", "base")}}

    def pull_reviews(self, repo, number):
        return [
            {
                "state": "CHANGES_REQUESTED",
                "author_association": "MEMBER",
                "user": {"login": "maintainer"},
                "submitted_at": "2026-08-04T00:00:00Z",
            }
        ]

    def comments(self, repo, number):
        return []

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


def test_default_followup_covers_all_67_open_prs_without_legacy_limit():
    class ManyOpenPrsClient(Client):
        def open_pull_requests_by_author(self, author):
            return [
                {
                    "number": number,
                    "repository_url": "https://api.github.com/repos/a/b",
                }
                for number in range(1, 68)
            ]

        def pull_request(self, repo, number):
            value = super().pull_request(repo, number)
            return value | {
                "number": number,
                "html_url": f"https://github.com/a/b/pull/{number}",
                "head": {"sha": f"head-{number}"},
            }

        def pull_reviews(self, repo, number):
            return []

    state, report = collect_followup(
        ManyOpenPrsClient(),
        author="Oxygen56",
        now=datetime(2026, 8, 4, tzinfo=UTC),
    )

    assert len(state["items"]) == 67
    assert {item["number"] for item in state["items"]} == set(range(1, 68))
    assert report["scan_ok"] is True


def test_explicit_followup_limit_remains_available_for_non_formal_callers():
    class ManyOpenPrsClient(Client):
        def open_pull_requests_by_author(self, author):
            return [
                {
                    "number": number,
                    "repository_url": "https://api.github.com/repos/a/b",
                }
                for number in range(1, 68)
            ]

        def pull_request(self, repo, number):
            value = super().pull_request(repo, number)
            return value | {
                "number": number,
                "html_url": f"https://github.com/a/b/pull/{number}",
                "head": {"sha": f"head-{number}"},
            }

        def pull_reviews(self, repo, number):
            return []

    state, _report = collect_followup(
        ManyOpenPrsClient(),
        author="Oxygen56",
        limit=40,
        now=datetime(2026, 8, 4, tzinfo=UTC),
    )

    assert len(state["items"]) == 40


def test_draft_pr_wakes_original_task_once():
    class DraftClient(Client):
        def pull_request(self, repo, number):
            pull = super().pull_request(repo, number)
            pull["draft"] = True
            return pull

        def pull_reviews(self, repo, number):
            return []

    state, report = collect_followup(
        DraftClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    item = state["items"][0]
    assert item["draft"] is True
    assert item["taskFollowupRequired"] is True
    assert item["taskActions"] == ["PR 处于草稿状态"]
    assert report["candidate_details"][0]["why"] == "PR 处于草稿状态"

    _, repeated = collect_followup(
        DraftClient(),
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )
    assert repeated["candidate_details"] == []


def test_unanswered_top_level_maintainer_comment_wakes_until_author_replies():
    class CommentClient(Client):
        comment_values = [
            {
                "id": 101,
                "user": {"login": "maintainer", "type": "User"},
                "author_association": "MEMBER",
                "created_at": "2026-08-04T00:01:00Z",
                "html_url": "https://github.com/a/b/pull/9#issuecomment-101",
                "body": "Please keep the English estimate close to its previous behavior.",
            }
        ]

        def pull_reviews(self, repo, number):
            return []

        def comments(self, repo, number):
            return list(self.comment_values)

    client = CommentClient()
    state, report = collect_followup(
        client, author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    item = state["items"][0]
    assert item["taskActions"] == ["存在未回复的维护者评论"]
    comment = item["evidence"]["unansweredMaintainerComments"][0]
    assert comment["actorLogin"] == "maintainer"
    assert comment["eventType"] == "TOP_LEVEL_COMMENT"
    assert report["candidate_details"][0]["why"] == "存在未回复的维护者评论"

    client.comment_values.append(
        {
            "id": 102,
            "user": {"login": "Oxygen56", "type": "User"},
            "author_association": "CONTRIBUTOR",
            "created_at": "2026-08-04T00:02:00Z",
            "html_url": "https://github.com/a/b/pull/9#issuecomment-102",
            "body": "Addressed in the latest revision.",
        }
    )
    replied_state, replied_report = collect_followup(
        client,
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    replied_item = replied_state["items"][0]
    assert replied_item["taskFollowupRequired"] is False
    assert replied_item["evidence"]["unansweredMaintainerComments"] == []
    assert replied_report["candidate_details"] == []


def test_non_maintainer_top_level_comment_is_recorded_without_task_wake():
    class ExternalCommentClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def comments(self, repo, number):
            return [
                {
                    "id": 201,
                    "user": {"login": "external-contributor", "type": "User"},
                    "author_association": "NONE",
                    "created_at": "2026-08-04T00:01:00Z",
                    "html_url": "https://github.com/a/b/pull/9#issuecomment-201",
                    "body": "This estimate may be too aggressive for English text.",
                }
            ]

    state, report = collect_followup(
        ExternalCommentClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    item = state["items"][0]
    assert item["taskFollowupRequired"] is False
    assert item["evidence"]["unansweredMaintainerComments"] == []
    event = item["evidence"]["maintainerEvents"][0]
    assert event["actorLogin"] == "external-contributor"
    assert event["authorAssociation"] == "NONE"
    assert event["eventType"] == "TOP_LEVEL_COMMENT"
    assert report["candidate_details"] == []


def test_transient_top_level_comment_failure_preserves_previous_action_without_repeat():
    class MaintainerCommentClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def comments(self, repo, number):
            return [
                {
                    "id": 301,
                    "user": {"login": "maintainer", "type": "User"},
                    "author_association": "OWNER",
                    "created_at": "2026-08-04T00:01:00Z",
                    "html_url": "https://github.com/a/b/pull/9#issuecomment-301",
                    "body": "Please add the missing boundary case.",
                }
            ]

    initial, _ = collect_followup(
        MaintainerCommentClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    class FailingCommentClient(MaintainerCommentClient):
        def comments(self, repo, number):
            raise GitHubError("temporary comments failure")

    repeated_state, report = collect_followup(
        FailingCommentClient(),
        author="Oxygen56",
        existing=initial,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert report["scan_ok"] is False
    assert report["candidate_details"] == []
    assert "temporary comments failure" in report["errors"][0]
    assert repeated_state["items"][0]["taskFollowupRequired"] is True
    assert (
        repeated_state["items"][0]["evidence"]["unansweredMaintainerComments"]
        == initial["items"][0]["evidence"]["unansweredMaintainerComments"]
    )


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
    assert repeated_state["items"][0]["evidence"]["baseRefName"] == "main"
    assert repeated_state["items"][0]["evidence"]["baseSha"] == "base"
    assert (
        repeated_state["items"][0]["evidence"]["mergeConflictPreparationVersion"]
        == "conflict_files_v1"
    )


def test_new_base_head_rearms_an_existing_merge_conflict():
    class ConflictedClient(Client):
        base_sha = "base-1"

        def pull_request(self, repo, number):
            pull = super().pull_request(repo, number)
            pull["mergeable_state"] = "dirty"
            pull["base"] = {"ref": "main", "sha": self.base_sha}
            return pull

        def pull_reviews(self, repo, number):
            return []

    client = ConflictedClient()
    state, first = collect_followup(client, author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC))
    assert first["candidate_details"]

    client.base_sha = "base-2"
    updated, repeated = collect_followup(
        client,
        author="Oxygen56",
        existing=state,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert repeated["candidate_details"]
    assert updated["items"][0]["taskActionDigest"] != state["items"][0]["taskActionDigest"]


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


def test_single_pr_failure_preserves_its_previous_state():
    existing, _ = collect_followup(
        Client(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    class FailingClient(Client):
        def pull_files(self, repo, number):
            raise GitHubError("diff temporarily unavailable (HTTP 500)")

    state, report = collect_followup(
        FailingClient(),
        author="Oxygen56",
        existing=existing,
        now=datetime(2026, 8, 4, 1, tzinfo=UTC),
    )

    assert report["scan_ok"] is False
    assert report["candidate_details"] == []
    assert report["errors"] == ["a/b#9:diff temporarily unavailable (HTTP 500)"]
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


def test_unattributed_language_failure_wakes_task_and_requires_base_integration():
    class CheckClient(Client):
        def pull_request(self, repo, number):
            pull = super().pull_request(repo, number)
            pull["head"] = {"sha": "feature-head"}
            return pull

        def pull_reviews(self, repo, number):
            return []

        def pull_files(self, repo, number):
            return [{"filename": "lib/router/query.rs"}]

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 14,
                    "name": "rust-clippy (.)",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": "https://github.com/a/b/actions/runs/1/job/14",
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return [
                {
                    "path": ".github",
                    "annotation_level": "failure",
                    "message": "Process completed with exit code 101.",
                }
            ]

        def compare(self, repo, base, head):
            assert (repo, base, head) == ("a/b", "base", "feature-head")
            return {
                "status": "diverged",
                "merge_base_commit": {"sha": "old-base"},
            }

    state, report = collect_followup(
        CheckClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    item = state["items"][0]
    assert item["taskFollowupRequired"] is True
    assert item["taskActions"] == ["当前分支检查失败"]
    assert item["evidence"]["baseIntegrationRequired"] is True
    assert item["evidence"]["baseCompareStatus"] == "diverged"
    actionable = item["evidence"]["actionableCheckNames"]
    assert actionable == ["rust-clippy (.)"]
    assert report["candidate_details"][0]["why"] == "当前分支检查失败"


def test_aggregate_failure_does_not_wake_task_without_source_evidence():
    class CheckClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def pull_files(self, repo, number):
            return [{"filename": "lib/router/query.rs"}]

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 15,
                    "name": "pre-merge-status-check",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": "https://github.com/a/b/actions/runs/1/job/15",
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return [{"path": ".github", "message": "Process completed with exit code 1."}]

    state, report = collect_followup(
        CheckClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    assert state["items"][0]["taskFollowupRequired"] is False
    assert report["candidate_details"] == []


def test_unavailable_base_comparison_fails_safe_to_controller_ancestry_check():
    class CheckClient(Client):
        def pull_reviews(self, repo, number):
            return []

        def pull_files(self, repo, number):
            return [{"filename": "lib/router/query.rs"}]

        def check_runs(self, repo, ref):
            return [
                {
                    "id": 16,
                    "name": "cargo test",
                    "status": "completed",
                    "conclusion": "failure",
                }
            ]

        def check_annotations(self, repo, check_run_id):
            return []

        def compare(self, repo, base, head):
            raise GitHubError("comparison temporarily unavailable")

    state, report = collect_followup(
        CheckClient(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )

    evidence = state["items"][0]["evidence"]
    assert evidence["baseIntegrationRequired"] is True
    assert evidence["baseCompareError"] == "comparison temporarily unavailable"
    assert report["candidate_details"]


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
