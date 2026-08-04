from oss_pr_radar.repo_policy import discover_policy, submission_policy_from_text


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


def test_issue_template_fields_do_not_become_pr_ai_disclosure_policy():
    policy = discover_policy(
        FakeClient(
            {
                ".github/ISSUE_TEMPLATE/bug_report.yaml": (
                    "validations:\n  required: true\n"
                    "attributes:\n  label: Models Used\n"
                    '  description: "Your STT/LLM/TTS setup"\n'
                ),
                "CONTRIBUTING.md": "Run tests before opening a pull request.",
            }
        ),
        "livekit/agents",
    )
    assert policy.status == "NORMAL"
    assert policy.ai_disclosure is False
    assert [item.path for item in policy.files] == ["CONTRIBUTING.md"]


def test_pr_template_ai_disclosure_policy_is_still_detected():
    policy = discover_policy(
        FakeClient(
            {
                ".github/PULL_REQUEST_TEMPLATE/ai.md": (
                    "AI-assisted contributions must disclose the coding assistant used."
                )
            }
        ),
        "example/project",
    )
    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True


def test_required_public_codex_branch_prefix_is_a_disclosure_conflict():
    policy = discover_policy(
        FakeClient(
            {
                "AGENTS.md": (
                    "New branches should use the `codex/` prefix, for example "
                    "`codex/fix-provider-endpoint`."
                )
            }
        ),
        "example/project",
    )

    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True


def test_post_pr_review_approval_is_not_a_pre_pr_assignment_gate():
    text = (
        "You can request that the issue be assigned to you.\n"
        "Create a PR against the main branch.\n"
        "Wait for feedback or approval of your changes from the code maintainers."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTING.md": text}),
        "microsoft/semantic-kernel",
    )

    assert policy.assignment_required is False
    assert submission_policy_from_text(text) == "normal"


def test_explicit_pre_pr_assignment_gate_is_shared_by_scanner_and_live_gate():
    text = (
        "The issue must be assigned before you start implementing it. "
        "Pull requests without assignment are automatically closed."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTING.md": text}),
        "example/project",
    )

    assert policy.assignment_required is True
    assert submission_policy_from_text(text) == "needs_assignment"


def test_issues_only_contributor_policy_blocks_before_dispatch():
    text = (
        "We accept issues, not pull requests. Design and implementation are done by "
        "the maintainers. If you've already built a fix locally, share the prompt "
        "you used to produce it, not the source code."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTORS.md": text}),
        "modelcontextprotocol/inspector",
    )

    assert policy.status == "CONTRIBUTIONS_CLOSED"
    assert policy.unsolicited_pr_blocked is True
    assert [item.path for item in policy.files] == ["CONTRIBUTORS.md"]
    assert submission_policy_from_text(text) == "contributions_closed"


def test_accepting_issues_and_pull_requests_remains_normal():
    text = (
        "We accept issues and pull requests. Do not send a diff by email; "
        "open a pull request instead."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTORS.md": text}),
        "example/project",
    )

    assert policy.status == "NORMAL"
    assert submission_policy_from_text(text) == "normal"
