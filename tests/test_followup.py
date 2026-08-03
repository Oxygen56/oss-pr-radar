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
