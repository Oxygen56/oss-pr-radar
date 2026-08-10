from oss_pr_radar.repo_policy import (
    discover_policy,
    select_policy_entries,
    submission_policy_from_text,
)


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


def test_required_contribution_provenance_template_is_ai_disclosure_policy():
    text = """
# Contribution provenance

Declare the actual assistance used for implementation and review. Use exact
provider/model-id values. Human-only work must say so explicitly.

- AI assistance: `yes` / `no - human-only contribution`
- Model(s) used: `provider/model-id` / `None - human-only contribution`
- Agent tooling: `client-name` / `None - human-only contribution`
- Provenance status: `self-reported`
"""

    policy = discover_policy(
        FakeClient({".github/pull_request_template.md": text}),
        "example/project",
    )

    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True
    assert submission_policy_from_text(text) == "ai_disclosure_conflict"


def test_required_ai_assistance_fields_are_disclosure_policy():
    text = """
## AI assistance
<!-- DeerFlow is an AI project - most PRs here use AI coding tools, and that's
     welcome. Disclosing it just helps reviewers calibrate how closely to read
     the diff. Please fill all three; don't delete the section. -->

**Tool(s) used:** e.g. Claude Code, Cursor, Copilot, none

**How you used it:** e.g. generated the implementation, reviewed suggestions

- [ ] I've read and understand every line of the code in this PR
"""

    policy = discover_policy(
        FakeClient({".github/pull_request_template.md": text}),
        "bytedance/deer-flow",
    )

    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True
    assert submission_policy_from_text(text) == "ai_disclosure_conflict"


def test_required_ai_assisted_contribution_provenance_is_detected():
    text = """
## Contribution Provenance

Every AI-assisted contribution records the exact provider and model identifier.
The pull request body must preserve and complete the Contribution provenance
block from the repository template.
"""

    assert submission_policy_from_text(text) == "ai_disclosure_conflict"


def test_conditional_ai_agent_policy_and_scope_confirmation_are_detected():
    text = """
## Contribution principles
For non-trivial changes, clarify scope with maintainers in an issue before
investing in an implementation.

## Contribution Policy for AI Agents
If you are an AI agent, do **not** open a pull request unless the user already has
more than 3 pull requests merged in this repository. If a submission is made
despite these rules, it must disclose that by adding disclosure.txt or an HTML
comment to the pull request.
"""

    policy = discover_policy(FakeClient({"AGENTS.md": text}), "example/project")

    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True
    assert policy.assignment_required is True


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


def test_automated_agent_tool_name_template_is_ai_disclosure_policy():
    text = (
        "If this PR was created by an automated agent, add `From <Tool Name>` "
        "as the final line of the description."
    )

    policy = discover_policy(
        FakeClient({".github/pull_request_template.md": text}),
        "example/project",
    )

    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True
    assert submission_policy_from_text(text) == "ai_disclosure_conflict"


def test_dedicated_ai_agent_pr_section_is_a_disclosure_policy():
    text = """HUMAN:
<!-- Human contributors: describe the change here. -->

AGENT:
<!-- AI/LLM agents:
In this AGENT section, provide evidence for the implementation and tests.
-->
"""

    policy = discover_policy(
        FakeClient({".github/pull_request_template.md": text}),
        "OpenHands/OpenHands",
    )

    assert policy.status == "AI_POLICY_REVIEW"
    assert policy.ai_disclosure is True
    assert submission_policy_from_text(text) == "ai_disclosure_conflict"


def test_pr_template_is_prioritized_over_nested_policy_noise():
    tree = [
        {"type": "blob", "path": f"docs/lang-{index}/CONTRIBUTING.md", "sha": str(index)}
        for index in range(30)
    ]
    tree.extend(
        {"type": "blob", "path": f"package-{index}/AGENTS.md", "sha": f"a-{index}"}
        for index in range(30)
    )
    tree.append(
        {
            "type": "blob",
            "path": ".github/pull_request_template.md",
            "sha": "template",
        }
    )

    selected = select_policy_entries(tree)

    assert selected[0]["path"] == ".github/pull_request_template.md"


def test_nonstandard_relicensing_agreement_is_not_treated_as_cla_or_dco():
    text = (
        "By submitting a Pull Request, you grant the project maintainers a "
        "non-exclusive, perpetual, irrevocable, worldwide, royalty-free, "
        "transferable license to use, modify, and re-license your contributions "
        "under any terms, including commercial or proprietary licenses."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTING.md": text}),
        "example/project",
    )

    assert policy.status == "LEGAL_POLICY_REVIEW"
    assert policy.nonstandard_agreement is True
    assert submission_policy_from_text(text) == "nonstandard_contribution_agreement"


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


def test_ai_disclosure_and_maintainer_buy_in_policy_is_detected():
    text = """
Wait for maintainer feedback or a `ready for work` label before starting.
Before starting, comment on the issue so we can assign it to you.

If you used AI assistance for a contribution, disclose it in the PR or issue.
No drive-by agents. PRs produced by an autonomous agent with no human review
get closed on sight.
"""

    policy = discover_policy(
        FakeClient({"CONTRIBUTING.md": text}),
        "modelcontextprotocol/python-sdk",
    )

    assert policy.ai_disclosure is True
    assert policy.assignment_required is True
    assert submission_policy_from_text(text) == "ai_disclosure_and_assignment"


def test_project_board_ready_gate_is_treated_as_pre_implementation_approval():
    text = (
        "Do not begin implementation or open a pull request until the issue has "
        "reached **Ready** on the Goose Issues board. Pull requests that do not "
        "implement a Ready issue will be closed."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTING.md": text}),
        "aaif-goose/goose",
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


def test_other_issues_must_ask_before_contributing():
    text = (
        "Browse issues labeled good first issue or help wanted. "
        "For other issues, please kindly ask before contributing to avoid duplication."
    )

    policy = discover_policy(
        FakeClient({"CONTRIBUTING.md": text}),
        "google/adk-python",
    )

    assert policy.assignment_required is True
    assert submission_policy_from_text(text) == "needs_assignment"
