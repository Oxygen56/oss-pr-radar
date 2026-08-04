from datetime import UTC, datetime

from oss_pr_radar.followup import collect_followup


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

    def check_runs(self, repo, ref):
        return []


def test_formal_maintainer_request_is_notified_once():
    state, report = collect_followup(
        Client(), author="Oxygen56", now=datetime(2026, 8, 4, tzinfo=UTC)
    )
    assert report["candidate_details"][0]["category"] == "PR_FOLLOWUP"
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
                    "name": "tests",
                    "status": "completed",
                    "conclusion": "failure",
                    "details_url": "https://example.test/checks/1",
                }
            ]

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

    assert migrated["version"] == "pr_followup_v2"
    assert repeated["candidate_details"] == []
