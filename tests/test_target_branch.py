import pytest

from oss_pr_radar.github_client import GitHubError
from oss_pr_radar.target_branch import TargetBranchError, resolve_target_base


class Client:
    def __init__(self, *, default="dev", branches=None):
        self.default = default
        self.branches = branches or {default: "a" * 40}
        self.calls = []

    def repository(self, repo):
        self.calls.append(("repository", repo))
        return {"default_branch": self.default}

    def branch(self, repo, branch):
        self.calls.append(("branch", repo, branch))
        if branch not in self.branches:
            raise GitHubError("not found")
        return {"name": branch, "commit": {"sha": self.branches[branch]}}


def test_opencode_2_label_selects_v2_instead_of_default_branch():
    client = Client(branches={"dev": "a" * 40, "v2": "b" * 40})

    target = resolve_target_base(
        client,
        "anomalyco/opencode",
        {"labels": [{"name": "2.0"}]},
    )

    assert target == {
        "branch": "v2",
        "sha": "b" * 40,
        "source": "repository_label_rule",
        "defaultBranch": "dev",
        "label": "2.0",
    }
    assert ("branch", "anomalyco/opencode", "dev") not in client.calls


def test_unmapped_opencode_version_label_fails_closed():
    client = Client()

    with pytest.raises(TargetBranchError, match="no configured target branch"):
        resolve_target_base(
            client,
            "anomalyco/opencode",
            {"labels": [{"name": "3.0"}]},
        )


def test_ordinary_issue_uses_verified_repository_default_branch():
    client = Client(default="main", branches={"main": "c" * 40})

    target = resolve_target_base(client, "example/project", {"labels": [{"name": "bug"}]})

    assert target == {
        "branch": "main",
        "sha": "c" * 40,
        "source": "repository_default",
        "defaultBranch": "main",
    }
