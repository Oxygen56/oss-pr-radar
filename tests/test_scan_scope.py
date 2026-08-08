from oss_pr_radar.scanner import (
    AGENT_INFRA_SCAN_REPOS,
    AGENT_PLATFORM_REPOS,
    AGENT_RUNTIME_REPOS,
    AGENT_TOOLING_REPOS,
    ALL_SCAN_REPOS,
    LLM_ALGORITHM_SCAN_REPOS,
    LLM_DISTRIBUTED_TRAINING_REPOS,
    LLM_EVALUATION_REPOS,
    LLM_MODELING_PEFT_REPOS,
    LLM_POST_TRAINING_REPOS,
    repo_rules,
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
    assert len(LLM_ALGORITHM_SCAN_REPOS) >= 19
    assert len(ALL_SCAN_REPOS) == len(set(AGENT_INFRA_SCAN_REPOS) | set(LLM_ALGORITHM_SCAN_REPOS))
    assert {"huggingface/trl", "verl-project/verl", "OpenRLHF/OpenRLHF"} <= (
        LLM_POST_TRAINING_REPOS
    )
    assert {"huggingface/peft", "huggingface/transformers"} <= LLM_MODELING_PEFT_REPOS
    assert {"NVIDIA/Megatron-LM", "pytorch/torchtitan"} <= LLM_DISTRIBUTED_TRAINING_REPOS
    assert {"EleutherAI/lm-evaluation-harness", "huggingface/lighteval"} <= (LLM_EVALUATION_REPOS)


def test_eliza_publication_requires_ai_disclosure():
    assert repo_rules("elizaOS/eliza") == "ai_disclosure_conflict"
