from oss_pr_radar.github_client import GitHubClient, GitHubError


def test_api_retries_plain_eof_and_then_succeeds():
    calls = []
    delays = []

    def runner(_args, _timeout):
        calls.append(True)
        if len(calls) == 1:
            raise GitHubError('Get "https://api.github.com/repos/a/b/issues/1": EOF')
        return '{"number":1}'

    client = GitHubClient(runner=runner, retry_delays=(0.01,), sleeper=delays.append)

    assert client.issue("a/b", 1)["number"] == 1
    assert len(calls) == 2
    assert delays == [0.01]


def test_api_does_not_retry_nontransient_permission_failure():
    calls = []

    def runner(_args, _timeout):
        calls.append(True)
        raise GitHubError("Resource not accessible by integration (HTTP 403)")

    client = GitHubClient(runner=runner, sleeper=lambda _delay: None)

    try:
        client.issue("a/b", 1)
    except GitHubError:
        pass
    else:
        raise AssertionError("expected GitHubError")
    assert len(calls) == 1


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


def test_pull_review_threads_uses_graphql_and_returns_nodes():
    calls = []

    def runner(args, timeout):
        calls.append((args, timeout))
        return '{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[{"isResolved":false}]}}}}}'

    client = GitHubClient(runner=runner)

    result = client.pull_review_threads("a/b", 9)

    assert result == [{"isResolved": False}]
    assert calls[0][0][:3] == ["gh", "api", "graphql"]
    assert "owner=a" in calls[0][0]
    assert "name=b" in calls[0][0]
    assert "number=9" in calls[0][0]


def test_branch_reads_the_live_branch_head(monkeypatch):
    calls = []
    client = GitHubClient()

    def api(endpoint, **_kwargs):
        calls.append(endpoint)
        return {"name": "release/next", "commit": {"sha": "a" * 40}}

    monkeypatch.setattr(client, "api", api)

    result = client.branch("a/b", "release/next")

    assert result["commit"]["sha"] == "a" * 40
    assert calls == ["repos/a/b/branches/release%2Fnext"]


def test_compare_reads_base_relationship(monkeypatch):
    calls = []
    client = GitHubClient()

    def api(endpoint, **_kwargs):
        calls.append(endpoint)
        return {"status": "diverged", "merge_base_commit": {"sha": "c" * 40}}

    monkeypatch.setattr(client, "api", api)

    result = client.compare("a/b", "release/next", "feature/head")

    assert result["status"] == "diverged"
    assert calls == ["repos/a/b/compare/release%2Fnext...feature%2Fhead"]


def test_check_runs_reads_every_paginated_page(monkeypatch):
    client = GitHubClient()
    calls = []

    def api(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        return [
            {"total_count": 101, "check_runs": [{"id": 1, "name": "gate"}]},
            {"total_count": 101, "check_runs": [{"id": 2, "name": "lint"}]},
        ]

    monkeypatch.setattr(client, "api", api)

    result = client.check_runs("a/b", "feature/head")

    assert result == [{"id": 1, "name": "gate"}, {"id": 2, "name": "lint"}]
    assert calls == [
        (
            "repos/a/b/commits/feature%2Fhead/check-runs",
            {
                "params": {"per_page": 100},
                "paginate": True,
                "accept": "application/vnd.github+json",
            },
        )
    ]
