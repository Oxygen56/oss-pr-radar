from datetime import UTC, datetime

from oss_pr_radar.watch import build_watchlist, recheck_watchlist

NOW = datetime(2026, 8, 4, tzinfo=UTC)


def held_candidate(**updates):
    value = {
        "repo": "a/b",
        "num": 1,
        "url": "https://github.com/a/b/issues/1",
        "title": "Runtime change",
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "evidence_digest": "old-evidence",
        "policy_digest": "old-policy",
    }
    value.update(updates)
    return value


class GreenLightClient:
    def issue(self, repo, number):
        return {
            "state": "open",
            "title": "Runtime change",
            "body": "Repro steps and root cause",
            "assignees": [],
            "updated_at": "2026-08-04T00:00:00Z",
        }

    def comments(self, repo, number):
        return [
            {
                "body": "Please open a PR for this",
                "user": {"login": "maintainer"},
                "author_association": "MEMBER",
                "created_at": "2026-08-04T00:00:00Z",
            }
        ]

    def timeline(self, repo, number):
        return []

    def repository(self, repo):
        return {"default_branch": "main"}

    def repository_tree(self, repo, ref):
        return [{"type": "blob", "path": "CONTRIBUTING.md", "sha": "sha"}]

    def file_text(self, repo, path, ref):
        return "Contributions are welcome."

    def related_open_prs(self, repo, number, **kwargs):
        return []


def test_actionable_candidate_is_removed_from_watchlist():
    existing = build_watchlist(
        {"candidate_details": [held_candidate()]}, now=NOW
    )
    updated = build_watchlist(
        {"candidate_details": [held_candidate(auto_spawn=True)]}, existing, now=NOW
    )
    assert updated["items"] == []


def test_maintainer_green_light_creates_forced_recheck():
    watchlist = build_watchlist(
        {"candidate_details": [held_candidate(policy_digest="different")]}, now=NOW
    )
    updated, report = recheck_watchlist(
        watchlist, GreenLightClient(), now=NOW
    )
    assert updated["items"][0]["status"] in {"POLICY_CHANGED", "RESCAN_REQUIRED"}
    assert report["pending_rechecks"]["a/b#1"]
