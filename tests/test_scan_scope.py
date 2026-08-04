from oss_pr_radar.scanner import (
    AGENT_INFRA_SCAN_REPOS,
    AGENT_PLATFORM_REPOS,
    AGENT_RUNTIME_REPOS,
    AGENT_TOOLING_REPOS,
)


def test_fixed_scope_covers_mature_agent_ecosystem_domains():
    assert len(AGENT_INFRA_SCAN_REPOS) >= 45
    assert {
        "google/adk-python",
        "OpenHands/OpenHands",
        "camel-ai/camel",
        "mastra-ai/mastra",
    } <= AGENT_RUNTIME_REPOS
    assert {
        "modelcontextprotocol/inspector",
        "browserbase/stagehand",
        "livekit/agents",
        "cline/cline",
    } <= AGENT_TOOLING_REPOS
    assert {
        "BerriAI/litellm",
        "langfuse/langfuse",
        "Arize-ai/phoenix",
        "promptfoo/promptfoo",
    } <= AGENT_PLATFORM_REPOS
