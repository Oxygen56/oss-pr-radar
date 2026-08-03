from oss_pr_radar.repo_policy import discover_policy


class FakeClient:
    def __init__(self, files):
        self.files = files

    def repository(self, repo):
        return {"default_branch": "main"}

    def repository_tree(self, repo, ref):
        return [
            {"type": "blob", "path": path, "sha": f"sha-{index}"}
            for index, path in enumerate(self.files)
        ]

    def file_text(self, repo, path, ref):
        return self.files[path]


def test_plain_ai_product_language_is_not_a_disclosure_rule():
    policy = discover_policy(
        FakeClient(
            {
                "AGENTS.md": (
                    "This repository implements AI agents and LLM tool calling. "
                    "Run tests before opening a pull request."
                )
            }
        ),
        "example/project",
    )
    assert policy.status == "NORMAL"
    assert policy.ai_disclosure is False


def test_unedited_llm_boilerplate_quality_rule_is_not_total_ai_prohibition():
    policy = discover_policy(
        FakeClient(
            {
                "CONTRIBUTING.md": (
                    "Don't submit generated boilerplate. PRs that read like unedited "
                    "LLM output will be closed."
                )
            }
        ),
        "example/project",
    )
    assert policy.status == "NORMAL"
    assert policy.ai_prohibited is False


def test_explicit_ai_disclosure_is_held_for_user_review():
    policy = discover_policy(
        FakeClient(
            {"CONTRIBUTING.md": ("Contributors must disclose significant AI assistance in the PR.")}
        ),
        "example/project",
    )
    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True


def test_ai_prohibition_and_external_contribution_closure_are_distinct():
    prohibited = discover_policy(
        FakeClient({"AI_POLICY.md": "AI-generated contributions are not accepted."}),
        "example/project",
    )
    assert prohibited.ai_prohibited is True
    assert prohibited.unsolicited_pr_blocked is False

    closed = discover_policy(
        FakeClient({"CONTRIBUTING.md": "We are not accepting external pull requests."}),
        "example/project",
    )
    assert closed.status == "CONTRIBUTIONS_CLOSED"


def test_absence_of_repository_policy_is_not_an_unknown_fetch_failure():
    policy = discover_policy(FakeClient({"src/main.py": "pass"}), "example/project")
    assert policy.status == "NORMAL"
    assert policy.files == ()
