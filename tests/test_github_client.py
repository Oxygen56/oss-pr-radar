from oss_pr_radar.github_client import GitHubClient


def test_related_prs_keep_cross_repository_timeline_identity(monkeypatch):
    client = GitHubClient()
    monkeypatch.setattr(client, "api", lambda *_args, **_kwargs: [])
    timeline = [
        {
            "event": "cross-referenced",
            "source": {
                "issue": {
                    "number": 4342,
                    "html_url": ("https://github.com/OpenHands/software-agent-sdk/pull/4342"),
                }
            },
        }
    ]

    result = client.related_open_prs(
        "OpenHands/OpenHands",
        16270,
        issue_title="Browser tool fails",
        timeline=timeline,
    )

    assert result == [
        {
            "number": 4342,
            "html_url": "https://github.com/OpenHands/software-agent-sdk/pull/4342",
            "_linked_from_timeline": True,
            "_timeline_event": "cross-referenced",
            "_repo": "OpenHands/software-agent-sdk",
        }
    ]
