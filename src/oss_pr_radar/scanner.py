#!/usr/bin/env python3
"""OSS PR opportunity radar.

Reads GitHub via `gh`, sends Feishu notifications via bot env vars, and keeps a
local seen file so hourly overlapping windows do not repeat candidates.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .claims import detect_claims
from .contracts import CANDIDATE_SCHEMA, SCAN_SCHEMA, contract_digest
from .evidence import assess_hardware_requirements
from .llm import DeepSeekEvaluator
from .managed_adapter import ManagedAdapter
from .messages import add_chinese_explanations
from .opportunity import (
    allocate_capacity,
    classify_scan_outcome,
    pre_task_gate,
    rank_opportunity,
)
from .outbox import latest_candidate_notification_history
from .policy import SCANNER_DECISION_REVISION, decision_contract_digest
from .repo_policy import (
    POLICY_FILE_WORKERS,
    select_policy_entries,
    submission_policy_from_text,
)
from .scope import scope_digest
from .util import sha256_json

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_REPORTS = BASE_DIR / "reports"
DEFAULT_SEEN = DEFAULT_REPORTS / "oss_pr_radar_seen.json"
DEFAULT_STATE = DEFAULT_REPORTS / "pr_radar_runtime_state.json"
DEFAULT_REPO_CACHE = BASE_DIR / "state" / "repo_cache.json"
DEFAULT_CONTROLLER_FEEDBACK = BASE_DIR / "state" / "controller_terminal_feedback.json"
DEFAULT_NOTIFICATION_OUTBOX = BASE_DIR / "state" / "notification_outbox.json"
DEFAULT_CHAT_ID = os.environ.get("FEISHU_CHAT_ID", "")
PROFILE = "agent_ai_infra_v2"
AGENT_INFRA_TRACK = "agent_ai_infra"
LLM_ALGORITHM_TRACK = "llm_algorithm"
SCAN_TRACKS = (AGENT_INFRA_TRACK, LLM_ALGORITHM_TRACK)
SCANNER_VERSION = SCANNER_DECISION_REVISION
CONTROLLER_TERMINAL_STATUS = "controller_terminal"
MIN_ACTIONABLE_SCORE = 8
SEEN_RECHECK_HOURS = 24
SEARCH_MIN_INTERVAL_SECONDS = 1.5
SEARCH_RETRY_DELAYS_SECONDS = (3.0, 10.0, 30.0)
FEISHU_RETRY_DELAYS_SECONDS = (0.0, 1.0, 3.0)
SCAN_DEEP_INSPECTION_DEADLINE_SECONDS = 360.0
REPO_COLLECTION_WORKERS = 6
REPO_QUALITY_CACHE_HOURS = 6
MAX_ISSUES_TO_INSPECT = 30
RECHECK_INSPECTION_BUDGET = 24
MAX_SEEN_RECHECKS = RECHECK_INSPECTION_BUDGET
MAX_PENDING_RECHECKS = RECHECK_INSPECTION_BUDGET
OPPORTUNITY_CAPACITY = 10
MAX_SCANNER_MIGRATION_RECHECKS = 8
SEEN_RECHECK_STATUSES = frozenset(
    {
        "send_failed",
        "status_update",
        "inspection_budget_deferred",
        "candidate_overflow",
        "policy_migration_pending",
        "semantic_review_retry",
    }
)
SCANNER_MIGRATION_RECHECK_STATUSES = frozenset(
    {
        "hardware_unavailable",
        "notified",
        "queued_outbox",
    }
)
SCANNER_MIGRATION_RECHECK_PRIORITY = (
    "queued_outbox",
    "notified",
    "hardware_unavailable",
)
MAX_ISSUES_PER_REPO_PER_SCAN = 4
EXCLUDED_REPOS = {"openai/codex"}
UNAVAILABLE_HARDWARE_REPOS = {"vllm-project/vllm-ascend"}
EXCLUDED_REPO_QUERY = " ".join(f"-repo:{repo}" for repo in sorted(EXCLUDED_REPOS))

KNOWN_REPOS = [
    "deepseek-ai/DeepSeek-V3",
    "deepseek-ai/DeepEP",
    "deepseek-ai/3FS",
    "deepseek-ai/DeepSeek-R1",
    "deepseek-ai/DeepGEMM",
    "deepseek-ai/deepseek-harness",
    "vllm-project/vllm",
    "sgl-project/sglang",
    "lm-sys/FastChat",
    "langchain-ai/langgraph",
    "pydantic/pydantic-ai",
    "microsoft/autogen",
    "microsoft/agent-framework",
    "huggingface/smolagents",
    "run-llama/llama_index",
    "agno-agi/agno",
    "browser-use/browser-use",
    "bytedance/deer-flow",
    "crewAIInc/crewAI",
    "mem0ai/mem0",
    "OpenHands/OpenHands",
    "modelcontextprotocol/python-sdk",
    "modelcontextprotocol/typescript-sdk",
    "modelcontextprotocol/java-sdk",
    "modelcontextprotocol/csharp-sdk",
    "vercel/ai",
    "letta-ai/letta",
    "openai/openai-agents-python",
    "NVIDIA/TensorRT-LLM",
    "ray-project/ray",
    "bentoml/BentoML",
    "deepset-ai/haystack",
    "langchain-ai/langchain",
    "microsoft/semantic-kernel",
    "microsoft/markitdown",
    "lobehub/lobe-chat",
    "continuedev/continue",
    "qdrant/qdrant",
    "milvus-io/milvus",
    "weaviate/weaviate",
    "chroma-core/chroma",
    "apify/crawlee",
    "stanfordnlp/dspy",
    "microsoft/promptflow",
    "elastic/elasticsearch",
    "opensearch-project/OpenSearch",
    "PrefectHQ/fastmcp",
    "ai-dynamo/dynamo",
    "BerriAI/litellm",
    "google/adk-python",
    "google/adk-java",
    "google/adk-js",
    "strands-agents/harness-sdk",
    "camel-ai/camel",
    "langgenius/dify",
    "langflow-ai/langflow",
    "FlowiseAI/Flowise",
    "mastra-ai/mastra",
    "browserbase/stagehand",
    "livekit/agents",
    "pipecat-ai/pipecat",
    "ComposioHQ/composio",
    "langfuse/langfuse",
    "Arize-ai/phoenix",
    "promptfoo/promptfoo",
    "modelcontextprotocol/servers",
    "modelcontextprotocol/inspector",
    "NVIDIA/NeMo-Agent-Toolkit",
    "agentscope-ai/agentscope",
    "mcp-use/mcp-use",
    "aaif-goose/goose",
    "anomalyco/opencode",
    "cline/cline",
    "infiniflow/ragflow",
    "huggingface/trl",
    "huggingface/peft",
    "huggingface/transformers",
    "huggingface/accelerate",
    "huggingface/lighteval",
    "verl-project/verl",
    "OpenRLHF/OpenRLHF",
    "allenai/open-instruct",
    "Hiyouga/LLaMA-Factory",
    "modelscope/ms-swift",
    "modelscope/modelscope",
    "modelscope/ms-agent",
    "modelscope/evalscope",
    "modelscope/mcore-bridge",
    "QwenLM/Qwen-Agent",
    "QwenLM/qwen-code",
    "QwenLM/open-computer-use",
    "higress-group/higress",
    "alibaba/rtp-llm",
    "alibaba/tair-kvcache",
    "alibaba/ROLL",
    "alibaba/page-agent",
    "alibaba/spring-ai-alibaba",
    "bytedance/trae-agent",
    "bytedance/UI-TARS-desktop",
    "bytedance/SandboxFusion",
    "ByteDance-Seed/VeOmni",
    "TencentCloudADP/youtu-agent",
    "Tencent/WeKnora",
    "MoonshotAI/kimi-cli",
    "MoonshotAI/kimi-code",
    "MoonshotAI/kimi-agent-sdk",
    "MoonshotAI/checkpoint-engine",
    "MiniMax-AI/Mini-Agent",
    "MiniMax-AI/OpenRoom",
    "MiniMax-AI/MiniMax-MCP",
    "PaddlePaddle/FastDeploy",
    "PaddlePaddle/PaddleNLP",
    "deepseek-ai/FlashMLA",
    "axolotl-ai-cloud/axolotl",
    "Lightning-AI/litgpt",
    "NVIDIA/Megatron-LM",
    "deepspeedai/DeepSpeed",
    "pytorch/torchtitan",
    "bitsandbytes-foundation/bitsandbytes",
    "EleutherAI/lm-evaluation-harness",
    "Dao-AILab/flash-attention",
    "facebookresearch/xformers",
]

AGENT_RUNTIME_REPOS = {
    "deepseek-ai/deepseek-harness",
    "langchain-ai/langgraph",
    "pydantic/pydantic-ai",
    "microsoft/autogen",
    "microsoft/agent-framework",
    "huggingface/smolagents",
    "run-llama/llama_index",
    "agno-agi/agno",
    "browser-use/browser-use",
    "bytedance/deer-flow",
    "crewAIInc/crewAI",
    "mem0ai/mem0",
    "OpenHands/OpenHands",
    "letta-ai/letta",
    "deepset-ai/haystack",
    "stanfordnlp/dspy",
    "google/adk-python",
    "google/adk-java",
    "google/adk-js",
    "strands-agents/harness-sdk",
    "camel-ai/camel",
    "mastra-ai/mastra",
    "agentscope-ai/agentscope",
    "QwenLM/Qwen-Agent",
    "QwenLM/qwen-code",
    "bytedance/trae-agent",
    "bytedance/UI-TARS-desktop",
    "alibaba/page-agent",
    "alibaba/spring-ai-alibaba",
    "modelscope/ms-agent",
    "TencentCloudADP/youtu-agent",
    "MoonshotAI/kimi-cli",
    "MoonshotAI/kimi-code",
    "MoonshotAI/kimi-agent-sdk",
    "MiniMax-AI/Mini-Agent",
    "MiniMax-AI/OpenRoom",
}

AGENT_TOOLING_REPOS = {
    "modelcontextprotocol/python-sdk",
    "modelcontextprotocol/typescript-sdk",
    "modelcontextprotocol/java-sdk",
    "modelcontextprotocol/csharp-sdk",
    "modelcontextprotocol/servers",
    "modelcontextprotocol/inspector",
    "mcp-use/mcp-use",
    "openai/openai-agents-python",
    "microsoft/semantic-kernel",
    "PrefectHQ/fastmcp",
    "browserbase/stagehand",
    "livekit/agents",
    "pipecat-ai/pipecat",
    "ComposioHQ/composio",
    "continuedev/continue",
    "aaif-goose/goose",
    "anomalyco/opencode",
    "cline/cline",
    "QwenLM/open-computer-use",
    "bytedance/SandboxFusion",
    "MiniMax-AI/MiniMax-MCP",
}

AGENT_PLATFORM_REPOS = {
    "vercel/ai",
    "BerriAI/litellm",
    "langfuse/langfuse",
    "Arize-ai/phoenix",
    "promptfoo/promptfoo",
    "langgenius/dify",
    "langflow-ai/langflow",
    "FlowiseAI/Flowise",
    "infiniflow/ragflow",
    "NVIDIA/NeMo-Agent-Toolkit",
    "modelscope/modelscope",
    "higress-group/higress",
    "Tencent/WeKnora",
    "modelscope/evalscope",
}

INFERENCE_SERVING_REPOS = {
    "vllm-project/vllm",
    "sgl-project/sglang",
    "ai-dynamo/dynamo",
    "alibaba/rtp-llm",
    "alibaba/tair-kvcache",
    "MoonshotAI/checkpoint-engine",
    "PaddlePaddle/FastDeploy",
}

LLM_POST_TRAINING_REPOS = {
    "huggingface/trl",
    "verl-project/verl",
    "OpenRLHF/OpenRLHF",
    "allenai/open-instruct",
    "alibaba/ROLL",
}

LLM_MODELING_PEFT_REPOS = {
    "huggingface/transformers",
    "huggingface/peft",
    "Hiyouga/LLaMA-Factory",
    "modelscope/ms-swift",
    "axolotl-ai-cloud/axolotl",
    "Lightning-AI/litgpt",
    "Dao-AILab/flash-attention",
    "facebookresearch/xformers",
    "deepseek-ai/DeepSeek-V3",
    "deepseek-ai/DeepGEMM",
    "modelscope/mcore-bridge",
    "PaddlePaddle/PaddleNLP",
    "deepseek-ai/FlashMLA",
}

LLM_DISTRIBUTED_TRAINING_REPOS = {
    "NVIDIA/Megatron-LM",
    "deepspeedai/DeepSpeed",
    "pytorch/torchtitan",
    "huggingface/accelerate",
    "bitsandbytes-foundation/bitsandbytes",
    "deepseek-ai/DeepEP",
    "ByteDance-Seed/VeOmni",
}

LLM_EVALUATION_REPOS = {
    "EleutherAI/lm-evaluation-harness",
    "huggingface/lighteval",
}

LLM_ALGORITHM_PRIORITY_REPOS = (
    LLM_POST_TRAINING_REPOS
    | LLM_MODELING_PEFT_REPOS
    | LLM_DISTRIBUTED_TRAINING_REPOS
    | LLM_EVALUATION_REPOS
)

AGENT_INFRA_PRIORITY_REPOS = (
    AGENT_RUNTIME_REPOS | AGENT_TOOLING_REPOS | AGENT_PLATFORM_REPOS | INFERENCE_SERVING_REPOS
)

AGENT_INFRA_SCAN_REPOS = [repo for repo in KNOWN_REPOS if repo in AGENT_INFRA_PRIORITY_REPOS]
AGENT_INFRA_SCAN_REPOS = [
    repo for repo in AGENT_INFRA_SCAN_REPOS if repo.casefold() not in EXCLUDED_REPOS
]
LLM_ALGORITHM_SCAN_REPOS = [
    repo
    for repo in KNOWN_REPOS
    if repo in LLM_ALGORITHM_PRIORITY_REPOS and repo.casefold() not in EXCLUDED_REPOS
]
ALL_SCAN_REPOS = list(dict.fromkeys([*AGENT_INFRA_SCAN_REPOS, *LLM_ALGORITHM_SCAN_REPOS]))
SEARCH_REPO_CHUNK_SIZE = 4

AGENT_INFRA_TERMS = [
    '"tool call"',
    '"function call"',
    '"tool approval"',
    '"human in the loop"',
    '"agent runtime"',
    '"agent framework"',
    '"handoff"',
    '"checkpoint"',
    '"trace"',
    '"replay"',
    '"MCP"',
    '"structured output"',
    '"streaming" "tool"',
    '"agent" "state"',
    '"session" "agent"',
]

AGENT_INFRA_DISCOVERY_QUERIES = [
    '("tool call" OR "agent runtime" OR MCP OR "structured output")',
    '(inference OR "KV cache" OR scheduler OR "streaming tool")',
]

LLM_ALGORITHM_DISCOVERY_QUERIES = [
    '(GRPO OR DPO OR RLHF OR LoRA OR "reward model" OR distillation)',
    '("tensor parallel" OR FSDP OR MoE OR quantization OR "evaluation harness")',
]

BROAD_TERMS = AGENT_INFRA_TERMS + [
    '"tool call"',
    '"structured output"',
    '"MCP"',
    '"KV cache"',
    '"agent" "streaming"',
    '"inference" "regression"',
    '"reasoning" "streaming"',
]

SKIP_LABEL_RE = re.compile(
    r"\b(docs?|documentation|question|duplicate|invalid|wontfix|dependencies|"
    r"ci|test|flake|typo|good first issue|good-first-issue|easy|beginner|stale)\b",
    re.I,
)
WAIT_LABEL_RE = re.compile(
    r"\b(needs?[- ](?:confirmation|repro(?:duction)?|info(?:rmation)?|triage|review)|"
    r"awaiting[- ](?:response|confirmation|repro(?:duction)?|info(?:rmation)?)|"
    r"needs?\s*:\s*(?:design|product decision)|blocked|on hold)\b",
    re.I,
)
ISSUE_APPROVAL_GATE_RE = re.compile(
    r"\b(?:prs?|pull requests?)\s+(?:will be|are)\s+rejected\s+if\s+"
    r"(?:the\s+)?(?:linked\s+)?issue\s+does\s+not\s+have\s+"
    r"[`'\"]?status\s*:\s*approved|"
    r"(?:do not|don't)\s+open\s+(?:a\s+)?(?:pr|pull request)\s+until\s+"
    r"(?:the\s+)?issue\s+(?:is|has been)\s+approved\b",
    re.I,
)
HIGH_RE = re.compile(
    r"\b(agent|tool[- ]call|function[- ]call|structured output|mcp|memory|workflow|"
    r"human[- ]?in[- ]?the[- ]?loop|ag[- ]ui|interrupt|resume payload|deferred tool|"
    r"streaming|scheduler|kv cache|prefix cache|"
    r"cuda graph|distributed|parallel|routing|speculative|inference|serving|"
    r"throughput|latency|batch|token|reasoning|executor|runtime|eval|benchmark|"
    r"vector|retrieval|embedding|rerank|multimodal|audio|video|fps|mrope|rope)\b",
    re.I,
)
DYNAMIC_AGENT_INFRA_STRONG_RE = re.compile(
    r"\b(?:llm|large language model|model context protocol|mcp|tool[- ]call|"
    r"function[- ]call|structured output|ag[- ]ui|human[- ]in[- ]the[- ]loop|"
    r"agent runtime|agent framework|multi[- ]agent|kv cache|prefix cache|"
    r"speculative decoding|tensor parallel|pipeline parallel|context window|"
    r"tokenizer|transformer|attention kernel|language model)\b",
    re.I,
)
MODEL_RUNTIME_CONTEXT_RE = re.compile(
    r"\b(?:model|llm|token|transformer|attention|gpu|cuda|rocm|tensor|decoder|"
    r"generation|batching|quantization)\b",
    re.I,
)
RETRIEVAL_CONTEXT_RE = re.compile(
    r"\b(?:rag|vector|embedding|rerank|semantic search|vector database|"
    r"retrieval augmented)\b",
    re.I,
)
AGENT_CONTEXT_RE = re.compile(
    r"\b(?:tool|workflow|handoff|checkpoint|memory|planner|executor|session|"
    r"human[- ]in[- ]the[- ]loop)\b",
    re.I,
)
IMPACT_RE = re.compile(
    r"\b(crash|incorrect|corrupt|regression|hang|deadlock|oom|memory leak|"
    r"performance|latency|throughput|validation|data loss|security|production|"
    r"blocks|breaks|failing|fails)\b",
    re.I,
)
TRIVIAL_RE = re.compile(
    r"\b(typo|readme|docs only|documentation only|minor docs|comment only|"
    r"chore|dependency bump)\b",
    re.I,
)
ACTIVE_RE = re.compile(
    r"\b(i can take|i will take|i(?:'m| am) working|we(?:'re| are) working|"
    r"working on this|already working|opened a pr|draft pr|submitted pr|"
    r"my pr|assigned to me|fix is in progress|implementation is in progress|"
    r"happy to contribute|"
    r"happy to (?:send|submit|open|prepare|write) "
    r"(?:a |the )?(?:small |focused )?(?:fix|patch|pr|pull request)|"
    r"can contribute (?:a )?fix|contribute (?:a )?fix pr|"
    r"offer(?:ing)? (?:a )?fix pr|i(?:['’]d| would) like to submit|"
    r"i(?:['’]d| would) like to (?:take|claim|work on|investigate)|"
    r"can i (?:take|claim|work on)|"
    r"plan(?:ning)? to submit|submit (?:a )?fix|i will submit|"
    r"assign (?:this|it) to me|ready locally|"
    r"(?:fixed|implemented|addressed) in (?:pr\s*)?#\d+|"
    r"(?:reopen|reopening|restore) (?:pr\s*)?#\d+|"
    r"existing (?:repair|patch|fix) in (?:pr\s*)?#\d+|"
    r"(?:patch|fix)(?: plus (?:a )?regression test)? (?:is )?ready|"
    r"(?:have|prepared) (?:a )?(?:focused )?(?:patch(?:es)?|fix(?:es)?)|"
    r"take the implementation|have (?:a )?pr up|"
    r"(?:i(?:['’]ll| will)|we(?:['’]ll| will)).{0,100}(?:implement|prepare|open|submit|send|"
    r"add (?:a )?(?:regression )?test|put up).{0,80}(?:fix|patch|pr|pull request|test)?|"
    r"(?:i(?:'m| am)|we(?:'re| are)) implementing|"
    r"confirmed (?:the )?(?:same )?(?:root cause|bug).{0,120}(?:implement|fix|patch|test)|"
    r"i can (?:implement|prepare|open|send|have) (?:a )?(?:fix |patch |pr))\b",
    re.I,
)
RFC_RE = re.compile(
    r"\b(rfc|dep(?:\s*\((?:light|full)\))?|roadmap|tracking issue|failure tracker|"
    r"failure tracking|meta issue|epic|design proposal|"
    r"architecture proposal|architecture question|mapping check|migration plan|"
    r"umbrella issue|feature request|integration proposal|new integration|"
    r"p0\s*[-–]\s*p[1-9]|dep:draft)\b",
    re.I,
)
PROMOTIONAL_UPDATE_RE = re.compile(
    r"^(?:update|announcement)\s*:.*\b(?:now (?:has|supports?)|integration|platform)\b|"
    r"\b(?:introducing|announce(?:ment|d)?)\b.{0,100}\b(?:integration|platform|product)\b",
    re.I | re.S,
)
INTERNAL_AUTOMATION_ISSUE_RE = re.compile(
    r"^dependency validation failed\s*:|"
    r"\b(?:automated|scheduled|weekly)\s+(?:dependency|compatibility|range|upper[- ]bound)"
    r".{0,100}(?:validation|check|maintenance)\b",
    re.I | re.S,
)
BUG_ACTIONABILITY_RE = re.compile(
    r"\b(bug|regression|crash|exception|error|fail(?:s|ed|ure|ing)?|break(?:s|ing)?|broken|"
    r"incorrect|corrupt|hang(?:s|ed|ing)?|stall(?:s|ed|ing)?|freeze(?:s|frozen)?|"
    r"deadlock|oom|memory leak|garbled|mismatch|collapse(?:s|d)?|"
    r"unbounded|runaway|catastrophic|degrad(?:e|es|ed|ation)|slowdown|"
    r"discard(?:s|ed|ing)?|silent(?:ly)?|missing|never|livelock(?:s|ed|ing)?)\b|"
    r"\b(?:does not|doesn't|cannot|can't|fails? to|no way to)\b|"
    r"\b(?:is not|isn't|are not|aren't)\s+"
    r"(?:honou?red|forwarded|applied|respected|propagated|preserved|serialized|"
    r"handled|included|returned|closed)\b",
    re.I,
)
HELP_WANTED_RE = re.compile(r"\b(help wanted|contributions? welcome|good to implement)\b", re.I)
MAINTAINER_APPROVAL_RE = re.compile(
    r"\b(go ahead|please implement|contributions? welcome|help wanted|"
    r"happy to accept|sounds good|approved|please send a pr|feel free to open)\b",
    re.I,
)
PUBLIC_REPRO_RE = re.compile(
    r"(steps? to reproduce|repro(?:duction|ducer|ducible)?|minimal example|"
    r"expected (?:behavior|result|output)|actual (?:behavior|result|output)|"
    r"traceback|stack trace|"
    r"python\s+-m|pytest\s+|curl\s+|docker\s+run)",
    re.I,
)
ROOT_CAUSE_RE = re.compile(
    r"\b(root cause|caused by|regression from|bisect(?:ed)? to|"
    r"(?:combine\s+to\s+)?cause(?:s|d)?\s+this|overflow|race condition|"
    r"invariant violation|discard(?:s|ed|ing)?\s+(?:the|a|an)\s+"
    r"(?:event|chunk|token|request|response|state|value))\b",
    re.I,
)
PRIVATE_REPRO_RE = re.compile(
    r"\b(internal only|private repo|private link|intranet|内网|公司内部|"
    r"cannot share|can't share|not publicly available)\b",
    re.I,
)
RETRACTED_RE = re.compile(
    r"\b(i was wrong|my (?:assumption|analysis|premise) was wrong|mistaken|"
    r"false alarm|not actually a bug|works as intended|cannot reproduce|"
    r"can't reproduce|unable to reproduce|original report is invalid)\b",
    re.I,
)
RESOLVED_UPSTREAM_RE = re.compile(
    r"\b(already (?:been )?fixed|"
    r"(?:this (?:looks|appears) )?fixed (?:in|on) (?:current )?"
    r"[`'\"]?(?:main|master|nightly)[`'\"]?|"
    r"(?:this|that|it|pr\s*#?\d+)?\s*should (?:already )?have (?:resolved|fixed)(?: this)?|"
    r"resolved in (?:main|master)|landed in (?:main|master)|"
    r"(?:fully )?resolved by (?:pr\s*)?#\d+|"
    r"(?:the )?fix (?:has )?shipped in|"
    r"included in (?:the )?next release|will be in (?:the )?next release)\b",
    re.I,
)
WRONG_REPOSITORY_RE = re.compile(
    r"\b(?:(?:this|the) (?:issue|bug|failure) (?:is|appears to be) .{0,100}"
    r"(?:client|downstream|upstream)[- ]side (?:issue|bug)|"
    r"(?:not|isn't|is not) (?:an? )?(?:mcp |python )?"
    r"(?:sdk|framework|server|repository|repo) (?:issue|bug)|"
    r"(?:belongs|should be reported) (?:on|to|in) .{0,120}(?:tracker|repository|repo)|"
    r"(?:the )?(?:error|failure|bug|behavior) (?:is|comes|originates)\s+not from "
    r"(?:the )?.{0,100}(?:server|binary|repository|repo)|"
    r"definitively downstream of .{0,100}|"
    r"more (?:an? )?.{0,80} issue than (?:an? )?.{0,80} issue)\b",
    re.I | re.S,
)
UPSTREAM_ROOT_CAUSE_RE = re.compile(
    r"(?:root cause|bug)\s+(?:is\s+)?(?:not|isn't)\s+in\s+.{0,100}\b|"
    r"(?:real|actual|proper)\s+fix\s*(?::|is)?\s*(?:in\s+)?upstream\b|"
    r"\bfix\s+is\s+upstream\b",
    re.I | re.S,
)
EXTERNAL_MODEL_CAUSE_RE = re.compile(
    r"\b(model|provider|upstream)[- ]side (?:issue|bug|behavior)|"
    r"rather than (?:an? )?(?:framework|sdk|runtime|server) (?:issue|bug)|"
    r"framework correctly .{0,120} but the model\b|"
    r"(?:requested )?model .{0,120}(?:not supported by any provider|not (?:served|available) "
    r"(?:on|through|via) (?:the )?(?:router|provider))|"
    r"(?:router|provider).{0,120}(?:does not|doesn't|no longer) "
    r"(?:serve|support|offer).{0,80}(?:model|checkpoint)",
    re.I | re.S,
)
HOSTED_MODEL_QUALITY_RE = re.compile(
    r"(?::cloud|hosted (?:cloud )?model|cloud[- ]hosted model).{0,180}"
    r"(?:quality|degrad|worse|regress|hallucin|reasoning|output)|"
    r"(?:quality|degrad|worse|regress).{0,180}(?::cloud|hosted (?:cloud )?model)",
    re.I | re.S,
)
MANAGED_INFERENCE_INCIDENT_RE = re.compile(
    r"(?:livekit inference|managed inference|hosted inference|cloud inference)"
    r".{0,500}(?:timeouts?|outage|service unavailable|availability|provider incident|"
    r"private (?:trace|session)|cloud\.[a-z0-9.-]+/(?:projects|sessions))|"
    r"(?:timeouts?|outage|service unavailable|availability|provider incident)"
    r".{0,500}(?:livekit inference|managed inference|hosted inference|cloud inference)|"
    r"(?:third[- ]party provider|direct provider|provider api).{0,180}"
    r"(?:works?|fine|succeeds?).{0,260}(?:livekit inference|managed inference|"
    r"hosted inference|cloud inference)",
    re.I | re.S,
)
USAGE_AMBIGUITY_RE = re.compile(
    r"\b(?:invalid|unknown|unrecognized|unsupported|no such|command not found)\s+command\b|"
    r"\bcommand\s+(?:is\s+)?(?:invalid|unknown|unrecognized|not found)\b|"
    r"\bquestions?\s*:|"
    r"\bshould\s+[\w.-]+\s+be\s+set\b|"
    r"\bis\s+(?:the\s+)?[\w.-]+\s+(?:calculation|configuration|setting)\s+correct\b",
    re.I,
)
USAGE_QUESTION_RE = re.compile(
    r"\bhow (?:do|can|should|to)\b|\bis there (?:a|any) way\b|"
    r"\b(?:could|can) not find (?:it |anything )?in (?:the )?documentation\b|"
    r"\bdo not know how (?:to )?(?:configure|proceed|set up|use)\b|"
    r"\bthis is (?:mostly|mainly) about (?:updating )?documentation\b",
    re.I,
)
MODEL_ARTIFACT_FAILURE_RE = re.compile(
    r"(?:safetensors?|checkpoint|model (?:file|weight|artifact)).{0,180}"
    r"(?:incomplete|corrupt|download|checksum|invalid for input of size)|"
    r"(?:incomplete|corrupt|download|checksum|invalid for input of size).{0,180}"
    r"(?:safetensors?|checkpoint|model (?:file|weight|artifact))",
    re.I | re.S,
)
SECURITY_SENSITIVE_RE = re.compile(
    r"\b(?:security vulnerabilit(?:y|ies)|vulnerability disclosure|cve[- :#]?\d*|"
    r"remote code execution|arbitrary code execution|privilege escalation|"
    r"supply chain (?:attack|risk|vulnerability)|credential exfiltration|"
    r"sandbox escape|authentication bypass|command injection|"
    r"indirect prompt injection|unauthorized (?:code )?execution)\b",
    re.I,
)
SECURITY_LABEL_RE = re.compile(
    r"\b(?:security|secrets?|vulnerabilit(?:y|ies)|cve)\b",
    re.I,
)
LOW_IMPACT_SELF_ASSESSMENT_RE = re.compile(
    r"(?:^|\n)\s*(?:#{1,6}\s*)?impact\s*[:\-–—]?\s*(?:low|minor|negligible)\b|"
    r"(?:^|\n)\s*(?:#{1,6}\s*)?priority(?:\s+note)?\s*[:\-–—]?\s*"
    r"(?:\n\s*)?(?:low|minor|negligible)\b|"
    r"\b(?:nothing|no(?:thing)?)\s+(?:actually\s+)?breaks\b|"
    r"\b(?:happens|occurs|fires|runs)\s+(?:only\s+)?once\s+per\s+(?:thread|process|start|reload)\b",
    re.I | re.M,
)
EMPTY_TEMPLATE_VALUE_RE = re.compile(
    r"^\s*(?:_?no response_?|n/?a|none|[.\-–—])\s*$",
    re.I | re.M,
)
REACTIVATED_STALE_LABEL_RE = re.compile(r"\bunstale\b", re.I)
CONFIGURATION_CONTEXT_RE = re.compile(
    r"(?:--[a-z0-9][a-z0-9-]*|\bconfig(?:uration)?\b|\brequires?\b.{0,100}\benable\b)",
    re.I | re.S,
)
MAINTAINER_CONFIGURATION_GUIDANCE_RE = re.compile(
    r"\b(?:try|use|set|enable|add|pass|run)\s+(?:this|the following|these|--[a-z0-9])",
    re.I,
)
LLM_ALGORITHM_SIGNAL_PATTERNS = {
    "post_training_objective": re.compile(
        r"\b(?:RLHF|GRPO|DPO|PPO|RLOO|KTO|ORPO|SFT|reward model|policy gradient|"
        r"importance (?:sampling )?ratio|advantage(?:s| estimation)?|KL(?: divergence)?|"
        r"log[- ]?prob(?:ability|abilities|s)?|entropy bonus|clip(?:ped|ping)? objective|"
        r"knowledge distillation)\b",
        re.I,
    ),
    "parameter_efficient_finetuning": re.compile(
        r"\b(?:LoRA\+?|QLoRA|DoRA|AdaLoRA|IA3|prefix tuning|prompt tuning|adapter(?:s)?|"
        r"low[- ]rank|rank pattern|target modules?|merge(?:d|s|ing)? weights?)\b",
        re.I,
    ),
    "model_architecture": re.compile(
        r"\b(?:attention|self[- ]attention|cross[- ]attention|RoPE|rotary embedding|"
        r"position(?:al)? embedding|hidden states?|logits?|vocab(?:ulary)? projection|"
        r"KV heads?|GQA|MQA|MLP|activation function|normalization|RMSNorm|"
        r"mixture of experts|MoE|router logits?|expert routing)\b",
        re.I,
    ),
    "training_optimization": re.compile(
        r"\b(?:gradient(?:s| norm| clipping| accumulation)?|optimizer states?|AdamW?|"
        r"learning rate|weight decay|loss scaling|backprop(?:agation)?|autograd|"
        r"activation checkpoint(?:ing)?|sequence packing|loss function|training loss)\b",
        re.I,
    ),
    "distributed_training": re.compile(
        r"\b(?:FSDP2?|DeepSpeed|(?-i:ZeRO)[- ]?[123]?|tensor parallel(?:ism)?|"
        r"pipeline parallel(?:ism)?|context parallel(?:ism)?|sequence parallel(?:ism)?|"
        r"expert parallel(?:ism)?|data parallel(?:ism)?|distributed checkpoint(?:ing)?|"
        r"all[- ]reduce|reduce[- ]scatter|all[- ]gather|process group|shard(?:ed|ing)?)\b",
        re.I,
    ),
    "numerics_quantization": re.compile(
        r"\b(?:FP(?:4|8|16|32)|BF16|INT(?:4|8)|quantiz(?:e|ed|ation)|dequantiz(?:e|ation)|"
        r"QAT|GPTQ|AWQ|bitsandbytes|mixed precision|numerical (?:stability|parity)|"
        r"underflow|overflow|NaN|Inf|rounding|scaling factor)\b",
        re.I,
    ),
    "evaluation_method": re.compile(
        r"\b(?:evaluation harness|benchmark task|few[- ]shot|loglikelihood|perplexity|"
        r"exact match|pass@k|contamination|metric normalization|macro[- ]average|"
        r"micro[- ]average|bootstrap|confidence interval|statistical significance|"
        r"sampling variance|chat template)\b",
        re.I,
    ),
    "kernel_algorithm": re.compile(
        r"\b(?:FlashAttention|fused kernel|CUDA kernel|Triton kernel|GEMM|matmul|"
        r"memory[- ]efficient attention|block size|tile size|warp(?:s)?|occupancy|"
        r"kernel dispatch|autotun(?:e|er|ing))\b",
        re.I,
    ),
}
LLM_ALGORITHM_FORMULA_RE = re.compile(
    r"(?:\\(?:frac|sum|mathbb|mathcal|operatorname)|\$[^$]{3,}\$|"
    r"\b(?:loss|reward|advantage|logprob|ratio|gradient)\s*[=:])",
    re.I,
)
LLM_ALGORITHM_EXPERIMENT_RE = re.compile(
    r"\b(?:steps? to reproduce|minimal repro|expected (?:behavior|result|value|loss)|"
    r"actual (?:behavior|result|value|loss)|benchmark|ablation|baseline|loss curve|"
    r"accuracy|perplexity|numerical parity|reference implementation|unit test|"
    r"regression test|seed(?:ed)?|deterministic)\b",
    re.I,
)
LLM_ALGORITHM_CODE_PATH_RE = re.compile(
    r"(?:^|[\s`(])(?:[\w.-]+/)+(?:[\w.-]+\.(?:py|cu|cpp|cc|cuh|rs))\b|"
    r"\b(?:class|def|function|module|kernel)\s+[A-Za-z_][A-Za-z0-9_]*",
    re.I | re.M,
)
LLM_OPERATIONAL_ONLY_RE = re.compile(
    r"\b(?:install(?:ation|ing)?|setup|environment|dependency|requirements?|packaging|"
    r"docker(?:file)?|container image|command line|CLI|argument parser|config(?:uration)?|"
    r"yaml|readme|documentation|tutorial|example notebook|import error|module not found|"
    r"windows support|macos support|version bump|release note)\b",
    re.I,
)
MAINTAINER_ACTIVE_INVESTIGATION_RE = re.compile(
    r"(?:\b(?:i|we)\b.{0,100}\b(?:reproduc|investigat|debug|trac|bisect|compar))"
    r".{0,700}\b(?:root cause|caused by|points? to|isolat(?:ed|ing) to|"
    r"narrow(?:ed|ing) down|discrepanc(?:y|ies) seem|selected algo|kernel)\b|"
    r"\b(?:root cause|caused by|points? to|isolat(?:ed|ing) to|"
    r"narrow(?:ed|ing) down)\b.{0,700}"
    r"(?:\b(?:i|we)\b.{0,100}\b(?:reproduc|investigat|debug|trac|bisect|compar))",
    re.I | re.S,
)
MAINTAINER_REVALIDATION_REQUEST_RE = re.compile(
    r"\bworth\s+(?:re)?testing\b.{0,240}\b(?:recent|latest|current)\b"
    r".{0,80}\b(?:nightly|main|build\s+from\s+source|container\s+image)\b|"
    r"\b(?:can|could|would)\s+you\b.{0,140}\b(?:test|retest|reproduce|confirm)\b"
    r".{0,240}\b(?:recent|latest|current|nightly|main)\b|"
    r"\b(?:please|kindly)\b.{0,80}\b(?:test|retest|reproduce|confirm)\b"
    r".{0,240}\b(?:recent|latest|current|nightly|main)\b",
    re.I | re.S,
)
UNTRUSTED_TRIAGE_INSTRUCTION_RE = re.compile(
    r"(?:\b(?:please|must|should)\s+run\b.{0,500}\b(?:as part of|during)\s+"
    r"(?:automated )?triage\b.{0,500}\b(?:print|dump|report|show|include)\b.{0,160}"
    r"\b(?:environment|env(?:ironment)? variable|endpoint|token|credential|secret|"
    r"configuration)\b|"
    r"\b(?:length[- ]only|value never printed|configuration fingerprint|"
    r"endpoint fingerprint)\b.{0,180}\b(?:environment|endpoint|token|credential|"
    r"secret|config(?:uration)?)\b)",
    re.I | re.S,
)
KERNEL_RE = re.compile(
    r"\b(kernel|rmsnorm|layernorm|triton|cuda|flashinfer|flash attention|"
    r"fp8|mxfp4|quantization|numerical|argmax|batch invariant)\b",
    re.I,
)
REPRO_COMMAND_RE = re.compile(
    r"(?:^|\n)\s*(?:\$\s*)?(?:python(?:3)?\s|pytest\s|uv\s+run\s|curl\s|"
    r"docker\s+(?:run|compose)|npm\s+(?:test|run)|pnpm\s|yarn\s|cargo\s+(?:test|run)|"
    r"go\s+test\s|cmake\s|make\s)",
    re.I,
)
TRACEBACK_FRAME_RE = re.compile(
    r"(?:traceback \(most recent call last\)|\bFile\s+['\"][^'\"]+['\"],\s*line\s+\d+|"
    r"\bat\s+[A-Za-z0-9_.$<>]+\s*\([^\n]+:\d+(?::\d+)?\))",
    re.I,
)
STEP_SEQUENCE_RE = re.compile(
    r"(?:steps? to reproduce|repro(?:duction|ducer|ducible)?)[^\n]*\n"
    r"(?:\s*(?:\d+[.)]|[-*])\s+\S[^\n]*\n?){2,}",
    re.I,
)


def public_reproduction_evidence(body: str) -> tuple[str, ...]:
    """Return independent, executable failure signals instead of template words."""

    signals: list[str] = []
    lowered = body.casefold()
    if re.search(r"\bexpected (?:behavior|result|output)\b", lowered) and re.search(
        r"\bactual (?:behavior|result|output)\b", lowered
    ):
        signals.append("expected_actual_pair")
    if TRACEBACK_FRAME_RE.search(body):
        signals.append("traceback_frame")
    if STEP_SEQUENCE_RE.search(body):
        signals.append("ordered_steps")
    for block in re.findall(r"```[^\n]*\n(.*?)```", body, re.I | re.S):
        compact = re.sub(r"\s+", "", block)
        if len(compact) >= 24 and REPRO_COMMAND_RE.search(block):
            signals.append("executable_command")
            break
    if re.search(r"\bminimal (?:example|reproduction|reproducer)\b", body, re.I) and any(
        len(re.sub(r"\s+", "", block)) >= 80
        for block in re.findall(r"```[^\n]*\n(.*?)```", body, re.I | re.S)
    ):
        signals.append("minimal_example")
    return tuple(dict.fromkeys(signals))


def public_reproduction_signal_count(body: str) -> int:
    """Count independent executable signals, never headings or arbitrary code fences."""

    return len(public_reproduction_evidence(body))


def incomplete_template_value_count(body: str) -> int:
    """Count empty template placeholders only in prose, never in repro output."""
    prose = re.sub(r"```[^\n]*\n.*?```", "", body, flags=re.I | re.S)
    return len(EMPTY_TEMPLATE_VALUE_RE.findall(prose))


BOT_RE = re.compile(r"\b(bot|github-actions\[bot\]|stale\[bot\]|dependabot\[bot\])\b", re.I)
DESKTOP_PLATFORM_RE = re.compile(
    r"\b(windows|macos|desktop app|electron|microsoft store|chatgpt\.exe|gui)\b",
    re.I,
)
PERIPHERAL_INTEGRATION_RE = re.compile(
    r"\b(hid|usb|keyboard|mouse|serialport|device kit|accessory)\b",
    re.I,
)
FRONTEND_INTERACTION_RE = re.compile(
    r"\b(web\s*ui|webui|front[- ]?end|browser|chrome|edge|text\s*box|textarea|typing|"
    r"terminal|tui|viewport|scrollback|tool\s*card)\b",
    re.I,
)
FRONTEND_RENDERING_SYMPTOM_RE = re.compile(
    r"\b(laggy|sluggish|slow(?:ly)?|input lag|(?:re-?)?render(?:s|ing)?|repaint(?:s|ing)?|"
    r"flicker(?:ing)?|fullrender|"
    r"does(?:n['’]t| not) appear|chunk(?:ed)? text|letters?/words? appear)\b",
    re.I,
)
ISSUE_CODE_PATH_RE = re.compile(
    r"\b(?:[A-Za-z0-9_.-]+/)+(?:[A-Za-z0-9_.-]+\.(?:py|rs|ts|tsx|js|jsx|java|cs|cc|cpp|c|h|hpp))\b",
    re.I,
)
ISSUE_CODE_FILE_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_-]+\.(?:py|rs|ts|tsx|js|jsx|java|cs|cc|cpp|c|h|hpp))(?![A-Za-z0-9_.-])",
    re.I,
)
ISSUE_SYMBOL_RE = re.compile(
    r"(?:`[A-Za-z_][A-Za-z0-9_.:]{2,}`|"
    r"\b(?:class|function|method|module|operator|kernel|scheduler|parser|handler)\s+"
    r"[A-Za-z_][A-Za-z0-9_.:]{2,})",
    re.I,
)
GENERIC_CODE_BASENAMES = {
    "__init__.py",
    "api.py",
    "base.py",
    "cli.py",
    "client.py",
    "common.py",
    "config.py",
    "constants.py",
    "index.js",
    "index.ts",
    "main.py",
    "model.py",
    "server.py",
    "test.py",
    "types.ts",
    "utils.py",
}


def issue_code_anchors(text: str) -> tuple[str, ...]:
    anchors = [match.group(0) for match in ISSUE_CODE_PATH_RE.finditer(text)]
    anchors.extend(
        match.group(1)
        for match in ISSUE_CODE_FILE_RE.finditer(text)
        if match.group(1).casefold() not in GENERIC_CODE_BASENAMES
    )
    anchors.extend(match.group(0) for match in ISSUE_SYMBOL_RE.finditer(text))
    return tuple(dict.fromkeys(anchor[:160] for anchor in anchors))


RELATED_FAILURE_SIGNATURE_RE = re.compile(
    r"\b(?:nvcc|cicc|ptxas|clang|gcc|segmentation\s+fault|bus\s+error|"
    r"illegal\s+memory\s+access|core\s+dumped|signal\s+\d+)\b|"
    r"\b(?:exit|status|return)(?:\s+code)?\s*[=:]?\s*-?\d+\b",
    re.I,
)
API_DESIGN_RE = re.compile(
    r"\b(?:add|introduc(?:e|ing)|new|expose|public)\b.{0,80}"
    r"\b(?:public\s+)?(?:api|parameter|argument|option|constructor)\b|"
    r"\b(?:api|constructor)\b.{0,80}\b(?:change|design|proposal)\b|"
    r"\b(?:needs?|requires?)\s+(?:a\s+)?maintainer\s+"
    r"(?:design|scope|behavior)\s+(?:call|decision|confirmation)\b|"
    r"\bopen\s+design\s+questions?\b",
    re.I | re.S,
)
SEMANTIC_STOPWORDS = {
    "actual",
    "behavior",
    "breaking",
    "client",
    "completion",
    "crash",
    "default",
    "does",
    "effective",
    "error",
    "expected",
    "fails",
    "failed",
    "failure",
    "first",
    "fix",
    "hybrid",
    "ignore",
    "ignores",
    "issue",
    "model",
    "models",
    "openai",
    "python",
    "server",
    "serving",
    "states",
    "support",
    "using",
    "with",
}
SEMANTIC_TECHNICAL_TERMS = {
    "audience",
    "checkpoint",
    "conv",
    "conv_states",
    "credential",
    "cuda",
    "dtype",
    "index_put",
    "mamba",
    "nvfp4",
    "piecewise",
    "prefill",
    "scheduler",
    "scope",
    "streaming",
}
SEMANTIC_STRONG_TECHNICAL_TERMS = {
    "checkpoint",
    "conv_states",
    "cuda",
    "dtype",
    "index_put",
    "mamba",
    "nvfp4",
    "piecewise",
    "prefill",
    "scheduler",
}
TEST_FILE_RE = re.compile(
    r"(^|/)(tests?|specs?)(/|$)|(^|/)test_|(_test|\.test|\.spec)\.",
    re.I,
)
NON_TECHNICAL_CHECK_RE = re.compile(
    r"\b(?:cla(?:\s*assistant)?|(?:pull request|pr) triage|triage|labeler|"
    r"conventional commits?|semantic (?:pull request|pr)|pr title|title check|"
    r"preview deployment|deploy preview|vercel|netlify|cloudflare pages|"
    r"authorization|authorisation|permission|secret|policy gate)\b",
    re.I,
)


def check_label(check: dict[str, Any]) -> str:
    """Return all check metadata that can identify non-code status gates."""

    return " ".join(
        str(check.get(key) or "")
        for key in (
            "name",
            "workflowName",
            "detailsUrl",
            "targetUrl",
            "url",
        )
    )


def is_nontechnical_check(check: dict[str, Any]) -> bool:
    return bool(NON_TECHNICAL_CHECK_RE.search(check_label(check)))


def repo_is_excluded(repo: str) -> bool:
    return repo.casefold() in EXCLUDED_REPOS


def semantic_terms(text: str) -> set[str]:
    """Normalize prose and identifiers for conservative duplicate-PR matching."""

    raw = text.casefold()
    identifiers = {
        re.sub(r"[_./-]+", "_", token)
        for token in re.findall(r"[a-z][a-z0-9]*(?:[_./-][a-z0-9]+)+", raw)
    }
    if re.search(r"\bconv[\s_-]+states?\b", raw):
        identifiers.add("conv_states")
    normalized = re.sub(r"[_./-]+", " ", raw)
    words = {
        token
        for token in re.findall(r"[a-z0-9]{4,}", normalized)
        if token not in SEMANTIC_STOPWORDS and not token.isdigit()
    }
    return words | identifiers


def semantic_overlap_strength(left: str, right: str) -> tuple[int, bool]:
    left_terms = semantic_terms(left)
    right_terms = semantic_terms(right)
    overlap = left_terms & right_terms
    code_like = bool(
        overlap & SEMANTIC_TECHNICAL_TERMS
        or any("_" in term or any(char.isdigit() for char in term) for term in overlap)
    )
    return len(overlap), code_like


def semantic_distinctive_overlap(left: str, right: str) -> set[str]:
    overlap = semantic_terms(left) & semantic_terms(right)
    return {
        term
        for term in overlap
        if term in SEMANTIC_STRONG_TECHNICAL_TERMS
        or "_" in term
        or any(char.isdigit() for char in term)
    }


def issue_code_paths(text: str) -> set[str]:
    paths = {match.casefold().lstrip("./") for match in ISSUE_CODE_PATH_RE.findall(text)}
    paths.update(match.casefold() for match in ISSUE_CODE_FILE_RE.findall(text))
    return paths


def overlapping_issue_pr_paths(issue_context: str, file_paths: list[str]) -> list[str]:
    issue_paths = issue_code_paths(issue_context)
    overlaps: set[str] = set()
    for file_path in file_paths:
        normalized_file = file_path.casefold().lstrip("./")
        file_basename = normalized_file.rsplit("/", 1)[-1]
        for issue_path in issue_paths:
            issue_basename = issue_path.rsplit("/", 1)[-1]
            exact_or_suffix = (
                normalized_file == issue_path
                or normalized_file.endswith(f"/{issue_path}")
                or issue_path.endswith(f"/{normalized_file}")
            )
            distinctive_basename = (
                file_basename == issue_basename and file_basename not in GENERIC_CODE_BASENAMES
            )
            if exact_or_suffix or distinctive_basename:
                overlaps.add(file_path)
                break
    return sorted(overlaps)


def related_issue_stack_signatures(text: str) -> set[str]:
    signatures = {
        "failure:" + re.sub(r"\s+", "_", match.group(0).casefold())
        for match in RELATED_FAILURE_SIGNATURE_RE.finditer(text)
    }
    for raw_path in issue_code_paths(text):
        parts = raw_path.casefold().split("/")
        # Drop host-specific prefixes while retaining package/module identity.
        if "site-packages" in parts:
            parts = parts[parts.index("site-packages") + 1 :]
        signatures.add("path:" + "/".join(parts[-5:]))
    return signatures


def is_dependency_update_pr(hit: dict[str, Any]) -> bool:
    """Identify routine dependency bumps that should not create semantic collisions."""

    title = str(hit.get("title") or "").strip()
    user = hit.get("user") or hit.get("author") or {}
    author = (
        str(user.get("login") or user.get("name") or "") if isinstance(user, dict) else str(user)
    )
    return bool(
        re.search(r"^(?:build|chore)(?:\([^)]*deps?[^)]*\))?\s*:", title, re.I)
        or re.search(r"^bump\s+\S+.*\s+from\s+\S+\s+to\s+\S+", title, re.I)
        or re.search(r"(?:dependabot|renovate)", author, re.I)
    )


def issue_body_pr_link_relation(issue_context: str, repo: str, pr_num: int) -> str:
    """Classify an issue-body PR link as coverage, reference, or non-covering."""

    pattern = re.compile(
        rf"(?:https?://github\.com/{re.escape(repo)}/pull/{pr_num}\b|\bPR\s*#{pr_num}\b)",
        re.I,
    )
    matches = list(pattern.finditer(issue_context))
    if not matches:
        return "reference"

    for match in matches:
        snippet = issue_context[max(0, match.start() - 500) : match.end() + 500]
        if re.search(
            r"does(?:n['’]t| not)\s+(?:cover|address|fix|resolve)|"
            r"not\s+(?:cover(?:ing)?|address(?:ing)?|fix(?:ing)?|resolv(?:e|ing))|"
            r"different\s+(?:failure|scope|path|issue)|not\s+a\s+duplicate|"
            r"did\s+not\s+find\s+(?:one|a\s+(?:pr|pull request))\s+covering",
            snippet,
            re.I,
        ):
            return "non_covering"
        if re.search(
            rf"(?:fix(?:ed|es)?|implement(?:ed|s)?|address(?:ed|es)?|"
            rf"resolv(?:ed|es)?|cover(?:ed|s)?)\s*(?::|is\s+in|by|in)?\s*"
            rf"(?:\[?#?{pr_num}\]?|PR\s*#?{pr_num}|https?://github\.com/)",
            snippet,
            re.I,
        ):
            return "coverage"
        # Bug reports often describe the proposed repair first and then use
        # "Ref to <PR>" without adding a closing keyword to the PR itself.
        # Treat that link as coverage when it appears in an explicit repair
        # section; a non-covering disclaimer above still wins.
        if re.search(
            r"(?:how\s+to\s+fix|proposed\s+(?:fix|repair|solution)|"
            r"(?:first|second)\s+modification\s+approach|"
            r"fix\s+approach|solution)"
            r".{0,500}(?:ref(?:er(?:ence)?)?\s+to|see)\s*$",
            snippet[: match.start() - max(0, match.start() - 500)],
            re.I | re.S,
        ):
            return "coverage"
    return "reference"


def llm_algorithm_evidence(
    repo: str,
    text: str,
    *,
    public_repro_signals: int = 0,
    root_cause_signal: bool = False,
) -> dict[str, Any]:
    """Extract deterministic evidence that an issue exercises an LLM algorithm surface."""

    mechanisms: list[str] = []
    matched_terms: list[str] = []
    for mechanism, pattern in LLM_ALGORITHM_SIGNAL_PATTERNS.items():
        matches = {match.group(0).strip().lower() for match in pattern.finditer(text)}
        if matches:
            mechanisms.append(mechanism)
            matched_terms.extend(sorted(matches)[:3])
    formula_signal = bool(LLM_ALGORITHM_FORMULA_RE.search(text))
    experiment_signal = bool(LLM_ALGORITHM_EXPERIMENT_RE.search(text))
    code_path_signal = bool(LLM_ALGORITHM_CODE_PATH_RE.search(text))
    mechanism_count = len(mechanisms)
    score = min(
        10,
        min(6, mechanism_count * 2)
        + int(formula_signal)
        + int(experiment_signal)
        + int(code_path_signal)
        + int(root_cause_signal)
        + int(public_repro_signals >= 2),
    )
    single_mechanism_deep = bool(
        mechanism_count == 1
        and formula_signal
        and experiment_signal
        and root_cause_signal
        and code_path_signal
    )
    qualified = bool(score >= 7 and (mechanism_count >= 2 or single_mechanism_deep))
    operational_only = bool(
        LLM_OPERATIONAL_ONLY_RE.search(text)
        and mechanism_count <= 1
        and not (formula_signal and experiment_signal)
    )
    return {
        "score": score,
        "depth": "high" if score >= 9 else "medium" if qualified else "low",
        "mechanisms": mechanisms,
        "mechanism_count": mechanism_count,
        "matched_terms": sorted(set(matched_terms))[:12],
        "formula_signal": formula_signal,
        "experiment_signal": experiment_signal,
        "code_path_signal": code_path_signal,
        "operational_only": operational_only,
        "qualified": qualified and not operational_only,
        "curated_repo": repo in LLM_ALGORITHM_PRIORITY_REPOS,
    }


def issue_track(repo: str, text: str, evidence: dict[str, Any] | None = None) -> str:
    algorithm = evidence or llm_algorithm_evidence(repo, text)
    if repo in LLM_ALGORITHM_PRIORITY_REPOS or algorithm.get("qualified") is True:
        return LLM_ALGORITHM_TRACK
    return AGENT_INFRA_TRACK


def is_dynamic_llm_algorithm_issue(text: str) -> bool:
    return llm_algorithm_evidence("", text).get("qualified") is True


def is_algorithm_base(item: dict[str, Any]) -> bool:
    repo = str(item.get("repo") or "")
    if repo in LLM_ALGORITHM_PRIORITY_REPOS:
        return True
    text = f"{item.get('title') or ''}\n{item.get('body') or ''}"
    return is_dynamic_llm_algorithm_issue(text)


def base_priority(
    item: dict[str, Any],
) -> tuple[int, int, int, int, int, int, int, int, int, str, str]:
    labels = " ".join(item.get("labels", []))
    title = str(item.get("title") or "").replace("_", " ").replace("-", " ")
    context = f"{title}\n{item.get('body') or ''}"
    return (
        int(bool(item.get("_explicit_recheck"))),
        int(item.get("_recheck_priority") or 0),
        int(item.get("_prior_score") or 0),
        int(item.get("_defer_count") or 0),
        int(is_algorithm_base(item)),
        int(item.get("repo") in AGENT_INFRA_PRIORITY_REPOS),
        int(bool(re.search(r"\b(bug|regression|performance|refactor)\b", labels, re.I))),
        len(
            {
                match.group(0).lower()
                for match in re.finditer(
                    r"steps? to reproduce|repro(?:duction|ducible)?|expected behavior|"
                    r"actual behavior|traceback|stack trace|root cause|regression",
                    context,
                    re.I,
                )
            }
        ),
        len({match.group(0).lower() for match in HIGH_RE.finditer(title)}),
        item.get("created") or "",
        item.get("updated") or "",
    )


def select_inspection_bases(
    bases: list[dict[str, Any]],
    *,
    limit: int = MAX_ISSUES_TO_INSPECT,
    recheck_limit: int = RECHECK_INSPECTION_BUDGET,
    per_repo_limit: int = MAX_ISSUES_PER_REPO_PER_SCAN,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Give persisted rechecks their own budget without starving fresh issues."""
    selected_rechecks: list[dict[str, Any]] = []
    selected_regular: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    repo_counts: Counter[str] = Counter()

    rechecks = [base for base in bases if base.get("_explicit_recheck")]
    regular = [base for base in bases if not base.get("_explicit_recheck")]

    def reserve(
        pool: list[dict[str, Any]],
        capacity: int,
        selected: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        overflow: list[dict[str, Any]] = []
        accepted = 0
        for base in pool:
            repo = str(base.get("repo") or "")
            if accepted < capacity and repo_counts[repo] < per_repo_limit:
                selected.append(base)
                repo_counts[repo] += 1
                accepted += 1
            else:
                overflow.append(base)
        # Backfill unused capacity after repository diversity has had first pick.
        if accepted < capacity and overflow:
            extra = min(capacity - accepted, len(overflow))
            selected.extend(overflow[:extra])
            overflow = overflow[extra:]
        return overflow

    deferred.extend(reserve(rechecks, max(0, recheck_limit), selected_rechecks))
    algorithm_regular = [base for base in regular if is_algorithm_base(base)]
    agent_regular = [base for base in regular if not is_algorithm_base(base)]
    algorithm_capacity = min(12, max(0, limit))
    agent_capacity = max(0, limit - algorithm_capacity)
    algorithm_overflow = reserve(algorithm_regular, algorithm_capacity, selected_regular)
    agent_overflow = reserve(agent_regular, agent_capacity, selected_regular)
    remaining_capacity = max(0, limit - len(selected_regular))
    combined_overflow = sorted(
        [*algorithm_overflow, *agent_overflow], key=base_priority, reverse=True
    )
    deferred.extend(reserve(combined_overflow, remaining_capacity, selected_regular))

    # Network-heavy duplicate and policy checks can hit the wall-clock deadline
    # before both budgets are exhausted. Interleave durable rechecks with fresh
    # issues so neither class can consume the whole useful prefix of the run.
    selected: list[dict[str, Any]] = []
    for index in range(max(len(selected_rechecks), len(selected_regular))):
        if index < len(selected_rechecks):
            selected.append(selected_rechecks[index])
        if index < len(selected_regular):
            selected.append(selected_regular[index])
    return selected, deferred


def select_seen_rechecks(
    seen: dict[str, Any], limit: int = MAX_SEEN_RECHECKS
) -> list[tuple[str, dict[str, Any]]]:
    candidates = [
        (key, value)
        for key, value in seen.items()
        if isinstance(value, dict) and value.get("status") in SEEN_RECHECK_STATUSES
    ]
    candidates.sort(
        key=lambda pair: (
            0 if pair[1].get("deferred_from_status") in {"queued_outbox", "notified"} else 1,
            str(
                pair[1].get("first_deferred_at")
                or pair[1].get("requeued_at")
                or pair[1].get("analyzed")
                or ""
            ),
        )
    )
    return candidates[: max(0, limit)]


def expire_stale_rechecks(
    seen: dict[str, Any], now: datetime, *, max_age_hours: int = SEEN_RECHECK_HOURS
) -> int:
    """Retire old budget retries; a later issue update will naturally re-arm them."""

    expired = 0
    cutoff = now.astimezone(timezone.utc) - timedelta(hours=max(1, max_age_hours))
    for key, value in list(seen.items()):
        if not isinstance(value, dict) or value.get("status") not in SEEN_RECHECK_STATUSES:
            continue
        first_deferred = parse_github_time(
            value.get("first_deferred_at") or value.get("requeued_at") or value.get("analyzed"),
            now.astimezone(timezone.utc),
        )
        if first_deferred >= cutoff:
            continue
        seen[key] = value | {
            "status": "deferred_expired",
            "reason": "recheck_freshness_expired",
            "analyzed": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        expired += 1
    return expired


def count_seen_rechecks(seen: dict[str, Any]) -> int:
    return sum(
        isinstance(value, dict) and value.get("status") in SEEN_RECHECK_STATUSES
        for value in seen.values()
    )


def parse_github_time(value: str | None, default: datetime) -> datetime:
    if not value:
        return default
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return default


CODE_MARKERS = {
    "src",
    "python",
    "packages",
    "pkg",
    "lib",
    "server",
    "client",
    "csrc",
    "vllm",
    "sgl-kernel",
    "typescript",
    "java",
    "dotnet",
    "sdk",
    "llama_index",
    "autogen",
    "semantic-kernel",
}

RELATED_ISSUE_BEHAVIOR_TERMS = {
    "assignment",
    "authentication",
    "batch",
    "cache",
    "cancellation",
    "checkpoint",
    "concat",
    "cpu",
    "crash",
    "deadlock",
    "discovery",
    "endpoint",
    "hang",
    "idle",
    "latency",
    "leak",
    "memory",
    "oom",
    "parsing",
    "replay",
    "retry",
    "routing",
    "scheduler",
    "schema",
    "serialization",
    "shape",
    "shutdown",
    "streaming",
    "timeout",
    "tool",
    "trace",
    "wakeup",
}

RELATED_ISSUE_SIGNATURE_PAIRS = (
    frozenset(("cpu", "idle")),
    frozenset(("memory", "leak")),
    frozenset(("shutdown", "cancellation")),
    frozenset(("endpoint", "discovery")),
    frozenset(("batch", "shape")),
    frozenset(("tool", "streaming")),
    frozenset(("schema", "parsing")),
    frozenset(("retry", "timeout")),
    frozenset(("trace", "replay")),
    frozenset(("scheduler", "cache")),
)

RELATED_ISSUE_GENERIC_IDENTIFIERS = {
    "agent_run",
    "function_call",
    "run_sync",
    "structured_output",
    "tool_call",
}


def is_dynamic_agent_infra_issue(text: str) -> bool:
    """Require an AI-specific mechanism for repositories outside the curated set."""

    if DYNAMIC_AGENT_INFRA_STRONG_RE.search(text):
        return True
    if re.search(r"\b(?:inference|serving)\b", text, re.I) and MODEL_RUNTIME_CONTEXT_RE.search(
        text
    ):
        return True
    if re.search(r"\bretrieval\b", text, re.I) and RETRIEVAL_CONTEXT_RE.search(text):
        return True
    return bool(re.search(r"\bagents?\b", text, re.I) and AGENT_CONTEXT_RE.search(text))


def related_issue_behavior_terms(text: str) -> set[str]:
    words = set(re.findall(r"[a-z][a-z0-9_-]{2,}", text.casefold()))
    return words & RELATED_ISSUE_BEHAVIOR_TERMS


def gh(args: list[str], timeout: int = 18) -> tuple[Any | None, str | None]:
    started = time.monotonic()
    direct_env = os.environ.copy()
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        direct_env.pop(name, None)

    def invoke(env: dict[str, str], call_timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["gh", *args],
            text=True,
            capture_output=True,
            timeout=max(1.0, call_timeout),
            env=env,
        )

    proxy_configured = any(
        os.environ.get(name)
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        )
    )
    direct_timeout = float(timeout) if not proxy_configured else min(float(timeout), 10.0)
    try:
        proc = invoke(direct_env, direct_timeout)
    except subprocess.TimeoutExpired:
        if not proxy_configured:
            return None, "timeout"
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 1.0:
            return None, "timeout"
        try:
            proc = invoke(os.environ.copy(), remaining)
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as exc:  # pragma: no cover - operational fallback
            return None, str(exc)[:200]
    except Exception as exc:  # pragma: no cover - operational fallback
        return None, str(exc)[:200]

    error_text = (proc.stderr or proc.stdout or "").strip()
    connectivity_failure = bool(
        proc.returncode
        and re.search(
            r"tls handshake timeout|connection (?:refused|reset)|network is unreachable|"
            r"i/o timeout|context deadline exceeded|no route to host",
            error_text,
            re.I,
        )
    )
    if connectivity_failure and proxy_configured:
        remaining = timeout - (time.monotonic() - started)
        if remaining > 1.0:
            try:
                proc = invoke(os.environ.copy(), remaining)
            except subprocess.TimeoutExpired:
                return None, "timeout"
            except Exception as exc:  # pragma: no cover - operational fallback
                return None, str(exc)[:200]

    if proc.returncode:
        return None, (proc.stderr or proc.stdout or "").strip()[:250]
    try:
        return json.loads(proc.stdout or "{}"), None
    except json.JSONDecodeError as exc:
        return None, f"json_decode:{exc}"


def gh_paginated(
    args: list[str], timeout: int = 30
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Read every REST page and flatten the `gh api --slurp` response."""

    data, error = gh([*args, "--paginate", "--slurp"], timeout=timeout)
    if error:
        return None, error
    if not isinstance(data, list):
        return None, "invalid_paginated_response"
    pages = data if all(isinstance(page, list) for page in data) else [data]
    flattened: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, list):
            return None, "invalid_paginated_page"
        for item in page:
            if isinstance(item, dict):
                flattened.append(item)
    return flattened, None


def gh_list_page(
    args: list[str], timeout: int = 30
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Read one explicitly bounded REST page.

    Duplicate audits combine this recent page with exact timeline/body links and
    targeted search. Fetching every open issue or PR in a large repository can
    consume the whole scan budget without adding useful evidence.
    """

    data, error = gh(args, timeout=timeout)
    if error:
        return None, error
    if not isinstance(data, list):
        return None, "invalid_list_response"
    return [item for item in data if isinstance(item, dict)], None


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text()) if path.exists() else default
    except Exception:
        return default


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    tmp.replace(path)


def candidate_notification_digest(
    candidate: dict[str, Any], *, bind_scanner_version: bool = False
) -> str:
    """Hash material opportunity judgment while ignoring scan-time churn."""

    volatile = {
        "analyzed",
        "age_days",
        "evidence_digest",
        "expected_changes",
        "fetched_at",
        "issue_updated",
        "llm_review",
        "next_step",
        "notification_digest",
        "notification_scanner_version",
        "now",
        "policy_digest",
        "risk",
        "role_eta",
        "schema_version",
        "summary",
        "strengths",
        "gaps",
        "test_path",
        "updated",
        "updated_at",
        "why",
    }
    if not bind_scanner_version:
        volatile.add("scanner_version")

    def normalized(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: normalized(item) for key, item in sorted(value.items()) if key not in volatile
            }
        if isinstance(value, list):
            return [normalized(item) for item in value]
        return value

    payload = json.dumps(
        normalized(candidate),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def candidate_issue_outcome(candidate: dict[str, Any]) -> dict[str, Any]:
    if candidate.get("capacityDisposition") == "MATURE_BUDGET_DEFERRED":
        return {
            "status": "deferred",
            "reason": "mature_capacity_exhausted",
            "classification": "blocked_pre_task",
            "auto_spawn": False,
            "track": candidate.get("track"),
        }
    preflight = candidate.get("preTaskGate") or candidate.get("pre_task_gate") or {}
    if preflight and preflight.get("allowed") is not True:
        classification = preflight.get("classification") or classify_scan_outcome(
            "rejected", str(preflight.get("reason") or "")
        )
        return {
            "status": "deferred" if classification == "blocked_pre_task" else "rejected",
            "reason": preflight.get("reason") or "pre_task_gate_failed",
            "classification": classification,
            "auto_spawn": False,
            "track": candidate.get("track"),
            "category": candidate.get("category"),
            "gate_decision": candidate.get("gate_decision"),
        }
    review = candidate.get("llm_review") if isinstance(candidate.get("llm_review"), dict) else {}
    if review.get("status") in {"retry", "not_configured"}:
        return {
            "status": "deferred",
            "reason": "semantic_review_retry",
            "classification": "blocked_pre_task",
            "auto_spawn": False,
            "track": candidate.get("track"),
            "category": candidate.get("category"),
            "gate_decision": candidate.get("gate_decision"),
        }
    return {
        "status": "candidate",
        "auto_spawn": bool(candidate.get("auto_spawn")),
        "track": candidate.get("track"),
        "category": candidate.get("category"),
        "gate_decision": candidate.get("gate_decision"),
        "submission_policy": candidate.get("submission_policy"),
        "reason": (
            "maintainer_active_investigation"
            if (candidate.get("actionability_evidence") or {}).get(
                "maintainer_active_investigation"
            )
            else candidate.get("gate_decision")
        ),
    }


def demote_failed_pre_task_gate(candidate: dict[str, Any], gate: dict[str, Any]) -> None:
    """Remove dispatch eligibility after any failed deterministic gate."""

    if gate.get("allowed") is True:
        return
    candidate["auto_spawn"] = False
    candidate["notify"] = False
    candidate["maturity"] = "exploration"
    private_conflict = (
        candidate.get("gate_decision") == "ALLOW_PRIVATE_WORK"
        and candidate.get("submission_policy") == "ai_disclosure_conflict"
        and candidate.get("public_submission_allowed") is False
    )
    semantic_retry = (
        candidate.get("category") == "SEMANTIC_REVIEW_RETRY"
        or candidate.get("gate_decision") == "RETRY_REQUIRED"
    )
    if not private_conflict and not semantic_retry:
        candidate["category"] = "WAIT_MAINTAINER"
        candidate["gate_decision"] = "HUMAN_REVIEW"
    reasons = [str(reason) for reason in gate.get("reasons") or [] if str(reason)]
    if reasons:
        suffix = "；预审未通过：" + ", ".join(reasons[:4])
        risk = str(candidate.get("risk") or "")
        if suffix not in risk:
            candidate["risk"] = f"{risk}{suffix}"


def should_skip_seen(
    old: Any,
    issue_updated: str | None = None,
    now: datetime | None = None,
    scanner_version: str | None = None,
    decision_digest: str | None = None,
) -> bool:
    if not isinstance(old, dict):
        return False
    if old.get("status") == CONTROLLER_TERMINAL_STATUS:
        old_updated = old.get("issue_updated")
        if issue_updated and old_updated:
            return issue_updated == old_updated
        analyzed = parse_github_time(old.get("analyzed"), datetime.min.replace(tzinfo=timezone.utc))
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        return current - analyzed < timedelta(hours=SEEN_RECHECK_HOURS)
    if old.get("status") in {"send_failed", "status_update"}:
        return False
    if not (old.get("analyzed") or old.get("notified")):
        return False
    if scanner_version and old.get("scanner_version") != scanner_version:
        return False
    if decision_digest and old.get("decision_contract_digest") != decision_digest:
        return False

    old_updated = old.get("issue_updated")
    if issue_updated and old_updated:
        return issue_updated == old_updated

    analyzed = parse_github_time(old.get("analyzed"), datetime.min.replace(tzinfo=timezone.utc))
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return current - analyzed < timedelta(hours=SEEN_RECHECK_HOURS)


def merge_controller_terminal_feedback(
    seen: dict[str, Any], feedback: dict[str, Any]
) -> dict[str, Any]:
    """Overlay controller terminal judgments unless cloud state saw a newer issue revision."""

    merged = dict(seen)
    for key, value in feedback.items():
        if not isinstance(value, dict) or value.get("status") != CONTROLLER_TERMINAL_STATUS:
            continue
        current = merged.get(key) if isinstance(merged.get(key), dict) else {}
        current_updated = parse_github_time(
            current.get("issue_updated"), datetime.min.replace(tzinfo=timezone.utc)
        )
        feedback_updated = parse_github_time(
            value.get("issue_updated"), datetime.min.replace(tzinfo=timezone.utc)
        )
        if current_updated > feedback_updated:
            continue
        merged[key] = current | value
    return merged


def controller_terminal_issue_outcomes(seen: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Expose durable controller decisions so pending dispatch intents are revoked."""

    return {
        key: {"status": "rejected", "reason": "controller_terminal"}
        for key, value in seen.items()
        if isinstance(value, dict) and value.get("status") == CONTROLLER_TERMINAL_STATUS
    }


def requires_unavailable_hardware(title: str, labels_text: str, body: str) -> bool:
    """Skip only issues whose unavailable hardware is part of the actual scope."""
    return not assess_hardware_requirements(title, labels_text, body)["compatible"]


def is_desktop_peripheral_issue(title: str, labels_text: str, body: str) -> bool:
    """Keep desktop peripheral failures out of the Agent/AI Infra implementation queue."""

    scoped = f"{title}\n{labels_text}\n{body[:4000]}"
    return bool(DESKTOP_PLATFORM_RE.search(scoped) and PERIPHERAL_INTEGRATION_RE.search(scoped))


def is_frontend_interaction_issue(title: str, labels_text: str, body: str) -> bool:
    """Exclude browser/UI interaction bugs from the Agent/AI Infra implementation queue."""

    heading = re.sub(
        r"\bterminal\s+(?:state|outcome|status)\b",
        "",
        f"{title}\n{labels_text}",
        flags=re.I,
    )
    if FRONTEND_INTERACTION_RE.search(heading) and FRONTEND_RENDERING_SYMPTOM_RE.search(heading):
        return True
    prose = re.sub(r"```[^\n]*\n.*?```", "", body[:4000], flags=re.I | re.S)
    prose = re.sub(r"\bterminal\s+(?:state|outcome|status)\b", "", prose, flags=re.I)
    interaction_matches = list(FRONTEND_INTERACTION_RE.finditer(prose))
    symptom_matches = list(FRONTEND_RENDERING_SYMPTOM_RE.finditer(prose))
    return any(
        abs(interaction.start() - symptom.start()) <= 180
        for interaction in interaction_matches
        for symptom in symptom_matches
    )


def effective_window_hours(
    now: datetime,
    requested_hours: float,
    state: dict[str, Any],
    max_backfill_hours: float,
) -> tuple[float, str | None]:
    last_success = state.get("last_successful_scan") if isinstance(state, dict) else None
    if not last_success:
        return requested_hours, None
    parsed = parse_github_time(last_success, now)
    elapsed = max(0.0, (now - parsed).total_seconds() / 3600.0)
    return min(max_backfill_hours, max(requested_hours, elapsed + 1.0)), last_success


def repo_rules(repo: str) -> str:
    lower = repo.lower()
    if lower == "elizaos/eliza":
        return "ai_disclosure_conflict"
    if lower in {"langchain-ai/langgraph", "pydantic/pydantic-ai"}:
        return "needs_assignment"
    return "normal"


class Radar:
    def __init__(
        self,
        now: datetime,
        window_hours: float,
        seen_path: Path,
        chat_id: str,
        dry_run: bool = False,
        requested_window_hours: float | None = None,
        last_successful_scan: str | None = None,
        sleep_fn: Any = time.sleep,
        monotonic_fn: Any = time.monotonic,
        pending_rechecks: dict[str, Any] | None = None,
        deep_inspection_deadline_seconds: float = SCAN_DEEP_INSPECTION_DEADLINE_SECONDS,
        notify: bool = True,
        repo_cache_path: Path = DEFAULT_REPO_CACHE,
        controller_feedback_path: Path = DEFAULT_CONTROLLER_FEEDBACK,
        notification_outbox_path: Path = DEFAULT_NOTIFICATION_OUTBOX,
        managed_ledger_path: Path | None = None,
    ):
        self.now = now.astimezone(timezone.utc)
        self.since = self.now - timedelta(hours=window_hours)
        self.seen_path = seen_path
        self.chat_id = chat_id
        self.dry_run = dry_run
        self.window_hours = window_hours
        self.requested_window_hours = requested_window_hours or window_hours
        self.last_successful_scan = last_successful_scan
        seen = load_json(seen_path, {})
        feedback = load_json(controller_feedback_path, {})
        self.seen = merge_controller_terminal_feedback(
            seen if isinstance(seen, dict) else {},
            feedback if isinstance(feedback, dict) else {},
        )
        self.notification_history: dict[str, dict[str, Any]] = {}
        for key, entry in self.seen.items():
            if not isinstance(entry, dict) or not entry.get("notification_digest"):
                continue
            self.notification_history[key] = {
                "notification_digest": str(entry["notification_digest"]),
                "notification_scanner_version": str(
                    entry.get("notification_scanner_version") or entry.get("scanner_version") or ""
                ),
            }
        outbox = load_json(notification_outbox_path, {})
        try:
            durable_history = latest_candidate_notification_history(
                outbox if isinstance(outbox, dict) else {}
            )
        except ValueError:
            durable_history = {}
        for key, history in durable_history.items():
            if key in self.notification_history:
                continue
            scanner_version = str(history.get("notification_scanner_version") or "")
            if not scanner_version:
                seen_entry = self.seen.get(key)
                scanner_version = str(
                    (seen_entry or {}).get("notification_scanner_version")
                    or (seen_entry or {}).get("scanner_version")
                    or ""
                )
            self.notification_history[key] = {
                "notification_digest": str(history["notification_digest"]),
                "notification_scanner_version": scanner_version,
            }
        self.notification_state_recovered = 0
        self.managed_ledger_path = managed_ledger_path
        for key, history in self.notification_history.items():
            entry = self.seen.get(key)
            if not isinstance(entry, dict) or entry.get("notification_digest"):
                continue
            entry["notification_digest"] = history["notification_digest"]
            if history.get("notification_scanner_version"):
                entry["notification_scanner_version"] = history["notification_scanner_version"]
            self.notification_state_recovered += 1
        self.errors: list[str] = []
        self.repo_cache: dict[str, tuple[bool, str]] = {}
        self.policy_cache: dict[str, str] = {}
        self.repo_cache_path = repo_cache_path
        cached = load_json(repo_cache_path, {})
        self.persistent_repo_cache: dict[str, Any] = (
            cached if isinstance(cached, dict) and cached.get("version") == "repo_cache_v1" else {}
        )
        self.persistent_repo_cache.setdefault("version", "repo_cache_v1")
        self.persistent_repo_cache.setdefault("policies", {})
        self.persistent_repo_cache.setdefault("quality", {})
        self.related_issue_cache: dict[str, tuple[list[dict[str, Any]] | None, str | None]] = {}
        self.search_failed = False
        self.rate_limited = False
        self.sleep_fn = sleep_fn
        self.monotonic_fn = monotonic_fn
        self.scan_started_at = self.monotonic_fn()
        self.deep_inspection_deadline_seconds = max(0.0, float(deep_inspection_deadline_seconds))
        self.scan_deadline_reached = False
        self.pending_rechecks = pending_rechecks or {}
        self.notify = notify
        self.forced_recheck_keys: set[str] = set()
        self.issue_outcomes: dict[str, dict[str, Any]] = {}
        self._last_search_at: float | None = None
        self.rejection_summary: dict[str, int] = {}
        self.rejection_examples: dict[str, list[dict[str, Any]]] = {}
        self._last_comments_lookup_error: str | None = None
        self._last_issue_lookup_error: str | None = None
        self.queried_repos: set[str] = set()
        self.matched_repos: set[str] = set()
        self.qualified_repo_names: set[str] = set()
        self.inspected_repo_names: set[str] = set()
        self.collection_failures: dict[str, str] = {}
        self.deferred_rechecks_before = 0
        self.deferred_rechecks_attempted = 0
        self.deferred_rechecks_migration_selected = 0
        self.deferred_rechecks_expired = 0
        self.deferred_rechecks_remaining = 0
        self.base_head_cache: dict[str, dict[str, Any]] = {}
        self.exploration_candidates: list[dict[str, Any]] = []
        self.capacity_allocation: dict[str, Any] = {}

    def deep_inspection_deadline_reached(self) -> bool:
        reached = (
            self.monotonic_fn() - self.scan_started_at >= self.deep_inspection_deadline_seconds
        )
        self.scan_deadline_reached = self.scan_deadline_reached or reached
        return reached

    @property
    def analyzed(self) -> str:
        return self.now.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def since_str(self) -> str:
        return self.since.strftime("%Y-%m-%dT%H:%M:%SZ")

    def search_issues(
        self,
        query: str,
        per_page: int,
        timeout: int = 25,
    ) -> tuple[Any | None, str | None]:
        """Run a paced GitHub search so deep audits cannot burst into rate limits."""

        data: Any | None = None
        err: str | None = None
        for attempt in range(len(SEARCH_RETRY_DELAYS_SECONDS) + 1):
            if self._last_search_at is not None:
                elapsed = self.monotonic_fn() - self._last_search_at
                if elapsed < SEARCH_MIN_INTERVAL_SECONDS:
                    self.sleep_fn(SEARCH_MIN_INTERVAL_SECONDS - elapsed)
            data, err = gh(
                [
                    "api",
                    "-X",
                    "GET",
                    "search/issues",
                    "-f",
                    f"q={query}",
                    "-f",
                    "sort=updated",
                    "-f",
                    "order=desc",
                    "-f",
                    f"per_page={per_page}",
                ],
                timeout=timeout,
            )
            self._last_search_at = self.monotonic_fn()
            if not err:
                break
            is_rate_limit = "rate limit" in err.lower() or "abuse detection" in err.lower()
            if not is_rate_limit or attempt >= len(SEARCH_RETRY_DELAYS_SECONDS):
                break
            self.sleep_fn(SEARCH_RETRY_DELAYS_SECONDS[attempt])
        return data, err

    def add_search(
        self,
        items: dict[str, dict[str, Any]],
        query: str,
        per_page: int,
        required: bool = True,
    ) -> None:
        data, err = self.search_issues(query, per_page)
        if err:
            prefix = "search" if required else "discovery_degraded"
            self.errors.append(f"{prefix}:{err}:{query[:90]}")
            if required:
                self.search_failed = True
                if "secondary rate limit" in err.lower() or "rate limit" in err.lower():
                    self.rate_limited = True
            return
        for item in (data or {}).get("items", []):
            if item.get("pull_request") or item.get("state") != "open":
                continue
            repo_url = item.get("repository_url", "")
            repo = "/".join(repo_url.rsplit("/", 2)[-2:]) if repo_url else ""
            if not repo or repo_is_excluded(repo):
                continue
            self.matched_repos.add(repo)
            key = f"{repo}#{item.get('number')}"
            items.setdefault(
                key,
                {
                    "repo": repo,
                    "num": item.get("number"),
                    "title": item.get("title") or "",
                    "url": item.get("html_url") or "",
                    "updated": item.get("updated_at") or "",
                    "created": item.get("created_at") or "",
                    "labels": [label.get("name", "") for label in item.get("labels", [])],
                    "assignees": [a.get("login", "") for a in item.get("assignees", [])],
                    "body": item.get("body") or "",
                },
            )

    def add_repo_issues(
        self,
        repo: str,
        per_page: int = 100,
    ) -> tuple[dict[str, dict[str, Any]], str | None, bool]:
        if repo_is_excluded(repo):
            return {}, None, False
        found: dict[str, dict[str, Any]] = {}
        data: Any | None = None
        err: str | None = None
        retry_delays = (1.0, 3.0)
        for attempt in range(len(retry_delays) + 1):
            data, err = gh_paginated(
                [
                    "api",
                    "-X",
                    "GET",
                    f"repos/{repo}/issues",
                    "-f",
                    "state=open",
                    "-f",
                    f"since={self.since_str}",
                    "-f",
                    "sort=updated",
                    "-f",
                    "direction=desc",
                    "-f",
                    f"per_page={per_page}",
                ],
                timeout=30,
            )
            if not err:
                break
            if attempt < len(retry_delays):
                self.sleep_fn(retry_delays[attempt])
        if err or not isinstance(data, list):
            message = err or "invalid_response"
            rate_limited = "rate limit" in message.lower() or "abuse detection" in message.lower()
            return found, message, rate_limited

        for item in data:
            if item.get("pull_request") or item.get("state") != "open":
                continue
            key = f"{repo}#{item.get('number')}"
            found.setdefault(
                key,
                {
                    "repo": repo,
                    "num": item.get("number"),
                    "title": item.get("title") or "",
                    "url": item.get("html_url") or "",
                    "updated": item.get("updated_at") or "",
                    "created": item.get("created_at") or "",
                    "labels": [label.get("name", "") for label in item.get("labels", [])],
                    "assignees": [a.get("login", "") for a in item.get("assignees", [])],
                    "body": item.get("body") or "",
                },
            )
        return found, None, False

    def collect_items(self) -> dict[str, dict[str, Any]]:
        items: dict[str, dict[str, Any]] = {}
        base = (
            f"is:issue is:open archived:false no:assignee updated:>={self.since_str} "
            f"-label:stale {EXCLUDED_REPO_QUERY}"
        )
        # Repository issue feeds are independent. Bound concurrency so one slow
        # endpoint cannot make the whole hourly scan exceed the outer harness
        # timeout, while retaining the same fail-closed completeness contract.
        self.queried_repos.update(ALL_SCAN_REPOS)
        with ThreadPoolExecutor(max_workers=REPO_COLLECTION_WORKERS) as executor:
            futures = [executor.submit(self.add_repo_issues, repo) for repo in ALL_SCAN_REPOS]
            wait(futures)
            for repo, future in zip(ALL_SCAN_REPOS, futures, strict=True):
                try:
                    result = future.result()
                    if not result:
                        continue
                    repo_items, error, rate_limited = result
                    if error:
                        self.errors.append(f"repo_issues:{repo}:{error}")
                        self.collection_failures[repo] = error
                        self.search_failed = True
                        self.rate_limited = self.rate_limited or rate_limited
                        continue
                    if repo_items:
                        self.matched_repos.add(repo)
                    for key, item in repo_items.items():
                        items.setdefault(key, item)
                except Exception as exc:
                    message = f"{type(exc).__name__}:{str(exc)[:120]}"
                    self.errors.append(f"repo_issues_worker:{repo}:{message}")
                    self.collection_failures[repo] = message
                    self.search_failed = True
        discovery_index = int(self.now.timestamp() // 3600) % len(AGENT_INFRA_DISCOVERY_QUERIES)
        discovery_query = AGENT_INFRA_DISCOVERY_QUERIES[discovery_index]
        self.add_search(items, f"{base} label:bug {discovery_query}", 15, required=False)
        algorithm_index = int(self.now.timestamp() // 3600) % len(LLM_ALGORITHM_DISCOVERY_QUERIES)
        algorithm_query = LLM_ALGORITHM_DISCOVERY_QUERIES[algorithm_index]
        self.add_search(items, f"{base} label:bug {algorithm_query}", 15, required=False)
        self.deferred_rechecks_expired = expire_stale_rechecks(self.seen, self.now)
        rechecks = select_seen_rechecks(self.seen)
        self.deferred_rechecks_before = count_seen_rechecks(self.seen)
        recheck_keys = {key for key, _ in rechecks}
        self.forced_recheck_keys.update(recheck_keys)
        current_decision_digest = decision_contract_digest()
        migration_pool = [
            (key, value)
            for key, value in self.seen.items()
            if key not in recheck_keys
            and isinstance(value, dict)
            and (
                value.get("scanner_version") != SCANNER_VERSION
                or value.get("decision_contract_digest") != current_decision_digest
            )
            and value.get("status") in SCANNER_MIGRATION_RECHECK_STATUSES
        ]
        migration_rechecks = []
        for status in SCANNER_MIGRATION_RECHECK_PRIORITY:
            migration_rechecks.extend(
                sorted(
                    (pair for pair in migration_pool if pair[1].get("status") == status),
                    key=lambda pair: str(pair[1].get("issue_updated") or ""),
                    reverse=True,
                )
            )
        migration_rechecks = migration_rechecks[:MAX_SCANNER_MIGRATION_RECHECKS]
        selected_migration_keys = {key for key, _ in migration_rechecks}
        for key, previous in migration_pool:
            if key in selected_migration_keys or previous.get("status") not in {
                "queued_outbox",
                "notified",
            }:
                continue
            self.seen[key] = previous | {
                "status": "policy_migration_pending",
                "reason": "policy_migration_requires_revalidation",
                "deferred_from_status": previous.get("deferred_from_status")
                or previous.get("status"),
                "first_deferred_at": previous.get("first_deferred_at")
                or previous.get("issue_updated")
                or self.analyzed,
                "requeued_at": self.analyzed,
            }
        self.deferred_rechecks_migration_selected = len(migration_rechecks)
        self.forced_recheck_keys.update(key for key, _ in migration_rechecks)
        rechecks.extend(migration_rechecks)
        for key, entry in rechecks:
            repo, separator, number_text = key.rpartition("#")
            if not separator or not number_text.isdigit() or repo_is_excluded(repo):
                continue
            items.setdefault(
                key,
                {
                    "repo": repo,
                    "num": int(number_text),
                    "title": entry.get("title") or key,
                    "url": entry.get("url") or f"https://github.com/{repo}/issues/{number_text}",
                    "labels": [],
                    "assignees": [],
                    "updated": entry.get("issue_updated") or "",
                    "_explicit_recheck": True,
                    "_recheck_status": entry.get("status"),
                },
            )
            items[key]["_explicit_recheck"] = True
            items[key]["_recheck_status"] = entry.get("status")
            items[key]["_recheck_priority"] = (
                4
                if entry.get("deferred_from_status") in {"queued_outbox", "notified"}
                else (
                    2
                    if entry.get("status") in {"inspection_budget_deferred", "candidate_overflow"}
                    else 1
                )
            )
            items[key]["_prior_score"] = int(entry.get("score") or 0)
            items[key]["_defer_count"] = int(entry.get("defer_count") or 0)
            items[key]["_first_deferred_at"] = entry.get("first_deferred_at") or ""
            items[key]["expected_base_sha"] = entry.get("base_sha")
            prior_evidence = entry.get("pre_task_evidence") or {}
            items[key]["expected_issue_digest"] = prior_evidence.get("issueDigest")
            items[key]["expected_design_digest"] = prior_evidence.get("designDigest")
            items[key]["expected_assignee_digest"] = prior_evidence.get("assigneeDigest")
            items[key]["expected_duplicate_digest"] = prior_evidence.get("duplicateDigest")
        for key, entry in list(self.pending_rechecks.items())[:MAX_PENDING_RECHECKS]:
            repo, separator, number_text = key.rpartition("#")
            if not separator or not number_text.isdigit() or repo_is_excluded(repo):
                continue
            previous = self.seen.get(key)
            if (
                isinstance(previous, dict)
                and previous.get("status") == CONTROLLER_TERMINAL_STATUS
                and should_skip_seen(
                    previous,
                    entry.get("issueUpdated"),
                    self.now,
                    scanner_version=SCANNER_VERSION,
                    decision_digest=decision_contract_digest(),
                )
            ):
                continue
            self.forced_recheck_keys.add(key)
            items[key] = {
                "repo": repo,
                "num": int(number_text),
                "title": entry.get("issueTitle") or key,
                "url": entry.get("issueUrl") or f"https://github.com/{repo}/issues/{number_text}",
                "labels": [],
                "assignees": [],
                "updated": entry.get("issueUpdated") or "",
                "_explicit_recheck": True,
                "_recheck_status": "pending_queue",
                "_recheck_priority": 3,
            }
        return items

    def repo_quality(self, repo: str, known: bool) -> tuple[bool, str]:
        if repo in self.repo_cache:
            return self.repo_cache[repo]
        if known:
            self.repo_cache[repo] = (True, "curated_mature_repo")
            return self.repo_cache[repo]
        cached = (self.persistent_repo_cache.get("quality") or {}).get(repo)
        if isinstance(cached, dict):
            checked_at = parse_github_time(
                cached.get("checkedAt"), datetime.min.replace(tzinfo=timezone.utc)
            )
            if self.now - checked_at < timedelta(hours=REPO_QUALITY_CACHE_HOURS):
                value = cached.get("value")
                if (
                    isinstance(value, list)
                    and len(value) == 2
                    and isinstance(value[0], bool)
                    and isinstance(value[1], str)
                ):
                    self.repo_cache[repo] = (value[0], value[1])
                    return self.repo_cache[repo]
        meta, err = gh(
            [
                "repo",
                "view",
                repo,
                "--json",
                "stargazerCount,isArchived,isFork,description,nameWithOwner",
            ],
            timeout=15,
        )
        if err or not isinstance(meta, dict):
            self.repo_cache[repo] = (False, "repo_meta_failed")
            return self.repo_cache[repo]
        if meta.get("isArchived") or meta.get("isFork"):
            self.repo_cache[repo] = (False, "archived_or_fork")
            return self.repo_cache[repo]
        stars = int(meta.get("stargazerCount") or 0)
        if not known and stars < 500:
            self.repo_cache[repo] = (False, f"low_stars:{stars}")
            return self.repo_cache[repo]
        contents, contents_err = gh(["api", f"repos/{repo}/contents"], timeout=15)
        if contents_err or not isinstance(contents, list):
            self.repo_cache[repo] = (False, "repo_contents_failed")
            return self.repo_cache[repo]
        names = {
            str(entry.get("name") or "").casefold() for entry in contents if isinstance(entry, dict)
        }
        has_code = bool(names & CODE_MARKERS) or any(
            name
            in {
                "pyproject.toml",
                "package.json",
                "cargo.toml",
                "go.mod",
                "pom.xml",
                "build.gradle",
                "csproj",
                "cmakelists.txt",
            }
            for name in names
        )
        if not has_code:
            self.repo_cache[repo] = (False, "no_code_surface")
        else:
            self.repo_cache[repo] = (True, f"stars:{stars}")
        self.persistent_repo_cache["quality"][repo] = {
            "checkedAt": self.analyzed,
            "value": list(self.repo_cache[repo]),
        }
        return self.repo_cache[repo]

    def submission_policy(self, repo: str) -> str:
        static_rule = repo_rules(repo)
        if repo in self.policy_cache:
            return self.policy_cache[repo]

        metadata, metadata_err = gh(["api", f"repos/{repo}"], timeout=15)
        if metadata_err or not isinstance(metadata, dict):
            self.policy_cache[repo] = static_rule if static_rule != "normal" else "policy_unknown"
            return self.policy_cache[repo]
        ref = str(metadata.get("default_branch") or "HEAD")
        tree, tree_err = gh(
            [
                "api",
                "-X",
                "GET",
                f"repos/{repo}/git/trees/{quote(ref, safe='')}",
                "-f",
                "recursive=1",
            ],
            timeout=20,
        )
        if tree_err or not isinstance(tree, dict) or tree.get("truncated") is True:
            self.policy_cache[repo] = static_rule if static_rule != "normal" else "policy_unknown"
            return self.policy_cache[repo]
        raw_tree = tree.get("tree")
        if not isinstance(raw_tree, list):
            self.policy_cache[repo] = static_rule if static_rule != "normal" else "policy_unknown"
            return self.policy_cache[repo]
        entries = select_policy_entries([entry for entry in raw_tree if isinstance(entry, dict)])
        policy_paths = [str(entry["path"]) for entry in entries]
        primary_files = {str(entry["path"]): str(entry.get("sha") or "") for entry in entries}
        cache_entry = (self.persistent_repo_cache.get("policies") or {}).get(repo)
        if (
            isinstance(cache_entry, dict)
            and cache_entry.get("decisionDigest") == decision_contract_digest()
            and cache_entry.get("staticRule") == static_rule
            and cache_entry.get("primaryFiles") == primary_files
            and isinstance(cache_entry.get("result"), str)
        ):
            self.policy_cache[repo] = str(cache_entry["result"])
            return self.policy_cache[repo]

        def load_policy_text(path: str) -> str | None:
            payload, payload_err = gh(
                [
                    "api",
                    "-X",
                    "GET",
                    f"repos/{repo}/contents/{quote(path, safe='/')}",
                    "-f",
                    f"ref={ref}",
                ],
                timeout=15,
            )
            if payload_err or not isinstance(payload, dict):
                return None
            encoded = payload.get("content")
            if not encoded:
                return ""
            try:
                return base64.b64decode(encoded).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                return None

        policy_text: list[str] = []
        if policy_paths:
            with ThreadPoolExecutor(
                max_workers=min(POLICY_FILE_WORKERS, len(policy_paths))
            ) as executor:
                loaded_text = list(executor.map(load_policy_text, policy_paths))
            if any(text is None for text in loaded_text):
                self.policy_cache[repo] = "policy_unknown"
                return self.policy_cache[repo]
            policy_text = [text for text in loaded_text if text]

        combined = "\n".join(policy_text)
        result = submission_policy_from_text(combined, static_rule)
        self.policy_cache[repo] = result
        self.persistent_repo_cache["policies"][repo] = {
            "checkedAt": self.analyzed,
            "decisionDigest": decision_contract_digest(),
            "staticRule": static_rule,
            "primaryFiles": primary_files,
            "linkedFiles": {},
            "result": result,
        }
        return result

    def issue(self, repo: str, num: int) -> dict[str, Any] | None:
        data, err = gh(["api", f"repos/{repo}/issues/{num}"], timeout=15)
        self._last_issue_lookup_error = err
        if err:
            return None
        if not isinstance(data, dict):
            self._last_issue_lookup_error = "invalid_issue_response"
            return None
        return data

    def default_branch_evidence(self, repo: str) -> dict[str, Any]:
        """Pin the default branch commit used by the pre-task evidence gate."""

        if repo in self.base_head_cache:
            return self.base_head_cache[repo]
        metadata, metadata_err = gh(["api", f"repos/{repo}"], timeout=15)
        if metadata_err or not isinstance(metadata, dict):
            result = {"status": "lookup_failed", "reason": metadata_err or "repo_metadata_invalid"}
            self.base_head_cache[repo] = result
            return result
        branch = str(metadata.get("default_branch") or "")
        if not branch:
            result = {"status": "lookup_failed", "reason": "default_branch_missing"}
            self.base_head_cache[repo] = result
            return result
        branch_data, branch_err = gh(
            ["api", f"repos/{repo}/branches/{quote(branch, safe='')}"], timeout=15
        )
        commit = branch_data.get("commit") if isinstance(branch_data, dict) else {}
        base_sha = str(commit.get("sha") or "") if isinstance(commit, dict) else ""
        if branch_err or not base_sha:
            result = {
                "status": "lookup_failed",
                "reason": branch_err or "base_sha_missing",
                "defaultBranch": branch,
            }
        else:
            result = {
                "status": "ok",
                "defaultBranch": branch,
                "baseSha": base_sha,
                "evidenceDigest": sha256_json(
                    {"repo": repo, "defaultBranch": branch, "baseSha": base_sha}
                ),
            }
        self.base_head_cache[repo] = result
        return result

    def assess_related_issues(
        self,
        repo: str,
        num: int,
        title: str,
        issue_context: str,
    ) -> dict[str, Any]:
        if repo not in self.related_issue_cache:
            data, err = gh_list_page(
                [
                    "api",
                    "-X",
                    "GET",
                    f"repos/{repo}/issues",
                    "-f",
                    "state=open",
                    "-f",
                    "sort=updated",
                    "-f",
                    "direction=desc",
                    "-f",
                    "per_page=100",
                ],
                timeout=30,
            )
            self.related_issue_cache[repo] = (
                data if isinstance(data, list) and not err else None,
                err,
            )
        data, err = self.related_issue_cache[repo]
        if err or data is None:
            return {
                "status": "lookup_failed",
                "issues": [],
                "summary": f"相关 issue 审计失败：{err or 'invalid_response'}",
            }

        source_text = f"{title}\n{issue_context}"
        compiler_match = re.search(r"\b(nvcc|cicc|ptxas|clang|gcc)\b", source_text, re.I)
        failure_match = re.search(
            r"\b(segmentation\s+fault|bus\s+error|illegal\s+memory\s+access|core\s+dumped)\b",
            source_text,
            re.I,
        )
        related_items = list(data)
        if compiler_match and failure_match:
            query = (
                f'repo:{repo} is:issue is:open {compiler_match.group(1)} "{failure_match.group(1)}"'
            )
            search_data, search_err = self.search_issues(query, 20, timeout=20)
            if search_err or not isinstance(search_data, dict):
                return {
                    "status": "lookup_failed",
                    "issues": [],
                    "summary": f"相关 issue 精确搜索失败：{search_err or 'invalid_response'}",
                }
            by_number = {
                int(item.get("number") or 0): item
                for item in related_items
                if isinstance(item, dict) and item.get("number")
            }
            for item in search_data.get("items") or []:
                if isinstance(item, dict) and item.get("number"):
                    by_number[int(item["number"])] = item
            related_items = list(by_number.values())

        source_signals = related_issue_behavior_terms(source_text)
        source_title_signals = related_issue_behavior_terms(title)
        source_stack_signatures = related_issue_stack_signatures(source_text)
        overlaps: list[dict[str, Any]] = []
        for item in related_items:
            if not isinstance(item, dict) or item.get("pull_request"):
                continue
            if int(item.get("number") or 0) == num:
                continue
            other_text = f"{item.get('title') or ''}\n{item.get('body') or ''}"
            shared_signals = sorted(source_signals & related_issue_behavior_terms(other_text))
            title_shared_signals = sorted(
                source_title_signals & related_issue_behavior_terms(str(item.get("title") or ""))
            )
            semantic_overlap, _ = semantic_overlap_strength(source_text, other_text)
            title_overlap, title_code_like = semantic_overlap_strength(
                title, str(item.get("title") or "")
            )
            title_distinctive_overlap = (
                semantic_distinctive_overlap(title, str(item.get("title") or ""))
                - RELATED_ISSUE_GENERIC_IDENTIFIERS
            )
            shared_stack_signatures = sorted(
                source_stack_signatures & related_issue_stack_signatures(other_text)
            )
            shared_stack_paths = [
                signal for signal in shared_stack_signatures if signal.startswith("path:")
            ]
            shared_failures = [
                signal for signal in shared_stack_signatures if signal.startswith("failure:")
            ]
            shared_signal_set = set(shared_signals)
            has_signature_pair = bool(title_shared_signals) and any(
                pair <= shared_signal_set for pair in RELATED_ISSUE_SIGNATURE_PAIRS
            )
            # A single shared scenario slug (for example, ``large-over-small``)
            # is useful search context but is not enough to call two defects
            # duplicates. Require either multiple distinctive identifiers or a
            # shared behavioral mechanism in the titles.
            has_title_identity = bool(
                title_code_like
                and title_overlap >= 2
                and (
                    len(title_distinctive_overlap) >= 2
                    or (title_distinctive_overlap and title_shared_signals)
                )
            )
            has_stack_identity = bool(shared_stack_paths) and len(shared_failures) >= 2
            if semantic_overlap < 3 or not (
                has_signature_pair
                or len(title_shared_signals) >= 2
                or has_title_identity
                or has_stack_identity
            ):
                continue
            overlaps.append(
                {
                    "number": int(item.get("number") or 0),
                    "url": item.get("html_url") or "",
                    "title": item.get("title") or "",
                    "sharedBehaviorSignals": shared_signals,
                    "titleSharedBehaviorSignals": title_shared_signals,
                    "semanticOverlap": semantic_overlap,
                    "titleSemanticOverlap": title_overlap,
                    "sharedStackSignatures": shared_stack_signatures[:12],
                    "matchBasis": (
                        "stack_failure_signature"
                        if has_stack_identity
                        else "title_behavior_signature"
                    ),
                }
            )
        overlaps.sort(
            key=lambda item: (
                len(item["titleSharedBehaviorSignals"]),
                len(item["sharedBehaviorSignals"]),
                item["semanticOverlap"],
                len(item["sharedStackSignatures"]),
            ),
            reverse=True,
        )
        if overlaps:
            best = overlaps[0]
            return {
                "status": "potential_overlap",
                "issues": overlaps[:5],
                "best_url": best["url"],
                "summary": (
                    f"发现潜在重复 issue #{best['number']}，"
                    + (
                        "共享堆栈/失败签名："
                        if best["matchBasis"] == "stack_failure_signature"
                        else "共享行为信号："
                    )
                    + (
                        ", ".join(best["sharedStackSignatures"][:4])
                        if best["matchBasis"] == "stack_failure_signature"
                        else ", ".join(best["sharedBehaviorSignals"])
                    )
                ),
            }
        return {"status": "none", "issues": [], "summary": "未发现相关开放 issue"}

    def comments(self, repo: str, num: int) -> list[dict[str, Any]]:
        data, err = gh_paginated(
            [
                "api",
                "-X",
                "GET",
                f"repos/{repo}/issues/{num}/comments",
                "-f",
                "per_page=100",
            ],
            timeout=30,
        )
        self._last_comments_lookup_error = err
        return data if isinstance(data, list) and not err else []

    def events(self, repo: str, num: int) -> list[dict[str, Any]]:
        data, err = gh_paginated(
            [
                "api",
                "-X",
                "GET",
                f"repos/{repo}/issues/{num}/events",
                "-f",
                "per_page=100",
            ],
            timeout=30,
        )
        return data if isinstance(data, list) and not err else []

    def only_bot_refreshed(
        self, repo: str, num: int, issue: dict[str, Any], comments: list[dict[str, Any]]
    ) -> bool:
        try:
            created = datetime.fromisoformat((issue.get("created_at") or "").replace("Z", "+00:00"))
        except Exception:
            created = self.now
        if created >= self.since:
            return False

        for comment in comments:
            try:
                created_at = datetime.fromisoformat(
                    (comment.get("created_at") or "").replace("Z", "+00:00")
                )
            except Exception:
                continue
            user = (comment.get("user") or {}).get("login", "")
            if created_at >= self.since and not BOT_RE.search(user):
                return False

        for event in self.events(repo, num):
            try:
                event_at = datetime.fromisoformat(
                    (event.get("created_at") or "").replace("Z", "+00:00")
                )
            except Exception:
                continue
            actor = (event.get("actor") or {}).get("login", "")
            if (
                event_at >= self.since
                and not BOT_RE.search(actor)
                and event.get("event")
                in {
                    "reopened",
                    "commented",
                    "renamed",
                }
            ):
                return False
        return True

    def open_pr_hits(
        self,
        repo: str,
        num: int,
        title: str,
        issue_context: str = "",
    ) -> list[dict[str, Any]]:
        hits_by_url: dict[str, dict[str, Any]] = {}
        self._last_open_pr_lookup_errors = []

        escaped_repo = re.escape(repo)
        issue_body_linked_numbers = {
            int(match)
            for match in re.findall(
                rf"github\.com/{escaped_repo}/pull/(\d+)",
                issue_context,
                re.I,
            )
        }
        issue_body_link_relations = {
            pr_num: issue_body_pr_link_relation(issue_context, repo, pr_num)
            for pr_num in issue_body_linked_numbers
        }
        linked_numbers = set(issue_body_linked_numbers)
        linked_numbers.update(
            int(match)
            for match in re.findall(r"\b(?:pr|pull request)\s*#(\d+)\b", issue_context, re.I)
        )
        timeline, timeline_error = gh_paginated(
            [
                "api",
                "-X",
                "GET",
                f"repos/{repo}/issues/{num}/timeline",
                "-f",
                "per_page=100",
            ],
            timeout=30,
        )
        if timeline_error:
            self._last_open_pr_lookup_errors.append(f"timeline:{timeline_error}")
        for event in timeline if isinstance(timeline, list) else []:
            source_issue = (event.get("source") or {}).get("issue") or {}
            source_repo = (source_issue.get("repository") or {}).get("full_name") or ""
            source_url = source_issue.get("html_url") or ""
            source_match = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", source_url, re.I)
            if not source_repo and source_match:
                source_repo = source_match.group(1)
            same_repo = source_repo.casefold() == repo.casefold() or bool(
                re.search(rf"github\.com/{re.escape(repo)}/pull/\d+", source_url, re.I)
            )
            if same_repo and "pull_request" in source_issue and source_issue.get("number"):
                linked_numbers.add(int(source_issue["number"]))
            elif source_repo and source_match and "pull_request" in source_issue:
                source_text = f"{source_issue.get('title') or ''}\n{source_issue.get('body') or ''}"
                cross_repo_exact = str(event.get("event") or "").casefold() == "connected" or bool(
                    re.search(
                        rf"\b{re.escape(repo)}#{num}\b|"
                        rf"https://github\.com/{re.escape(repo)}/issues/{num}\b",
                        source_text,
                        re.I,
                    )
                )
                if cross_repo_exact:
                    hits_by_url[source_url] = source_issue | {
                        "number": int(source_match.group(2)),
                        "_repo": source_repo,
                        "_linked_from_issue": True,
                        "_timeline_event": str(event.get("event") or ""),
                    }
        linked_numbers.update(
            int(match)
            for groups in re.findall(
                r"\b(?:fixed|implemented|addressed|repaired|patch(?:ed)?|fix)"
                r"\s+(?:is\s+)?(?:in|by)\s+(?:pr\s*)?#(\d+)\b|"
                r"\b(?:reopen|reopening|restore)\s+(?:pr\s*)?#(\d+)\b|"
                r"\bexisting\s+(?:repair|patch|fix)\s+in\s+(?:pr\s*)?#(\d+)\b",
                issue_context,
                re.I,
            )
            for match in groups
            if match
        )
        for pr_num in list(linked_numbers)[:6]:
            detail, detail_error = gh(["api", f"repos/{repo}/pulls/{pr_num}"], timeout=15)
            if detail_error:
                self._last_open_pr_lookup_errors.append(f"linked_pr_{pr_num}:{detail_error}")
            if not isinstance(detail, dict):
                continue
            relation = issue_body_link_relations.get(pr_num)
            detail_text = f"{detail.get('title') or ''}\n{detail.get('body') or ''}"
            detail_direct = bool(
                re.search(
                    rf"\b(fix(e[sd])?|close[sd]?|resolve[sd]?)\s+#?{num}\b|#{num}\b",
                    detail_text,
                    re.I,
                )
            )
            if relation == "non_covering" and not detail_direct:
                continue
            url = detail.get("html_url")
            if url:
                hits_by_url[url] = {
                    **detail,
                    "number": pr_num,
                    "html_url": url,
                    "_linked_from_issue": (
                        pr_num not in issue_body_linked_numbers
                        or relation == "coverage"
                        or detail_direct
                    ),
                    "_issue_body_link": relation == "coverage",
                    "_issue_body_reference": pr_num in issue_body_linked_numbers,
                    "_issue_body_link_relation": relation,
                }

        data, list_error = gh_list_page(
            [
                "api",
                "-X",
                "GET",
                f"repos/{repo}/pulls",
                "-f",
                "state=open",
                "-f",
                "sort=updated",
                "-f",
                "direction=desc",
                "-f",
                "per_page=100",
            ],
            timeout=30,
        )
        if list_error:
            self._last_open_pr_lookup_errors.append(f"open_pr_list:{list_error}")
        for hit in data if isinstance(data, list) else []:
            hit_text = f"{hit.get('title') or ''}\n{hit.get('body') or ''}"
            direct = bool(
                re.search(
                    rf"\b(fix(e[sd])?|close[sd]?|resolve[sd]?)\s+#?{num}\b|#{num}\b",
                    hit_text,
                    re.I,
                )
            )
            if not direct and is_dependency_update_pr(hit):
                continue
            overlap_count, code_like_overlap = semantic_overlap_strength(title, hit_text)
            if not direct and not (overlap_count >= 3 and code_like_overlap):
                continue
            url = hit.get("html_url")
            if url:
                hits_by_url[url] = {
                    **hit,
                    "_semantic_overlap_count": overlap_count,
                    "_semantic_code_like": code_like_overlap,
                }

        title_semantic_terms = semantic_terms(title)
        technical_terms = [
            term
            for term in title_semantic_terms
            if term in SEMANTIC_TECHNICAL_TERMS
            or "_" in term
            or any(char.isdigit() for char in term)
        ]
        # High-velocity repositories can update more than 100 PRs between scans,
        # pushing a relevant PR out of the bounded recent inventory. A single
        # code-like identifier such as ``routing_groups`` is distinctive enough
        # for a supplemental GitHub search; all hits still pass the conservative
        # semantic-overlap check below before they are considered competition.
        if technical_terms:
            search_terms = sorted(
                technical_terms,
                key=lambda term: (
                    term not in SEMANTIC_STRONG_TECHNICAL_TERMS,
                    "_" not in term and not any(char.isdigit() for char in term),
                    term,
                ),
            )[:2]
            search_data, search_error = self.search_issues(
                f"repo:{repo} is:pr {' '.join(search_terms)}",
                20,
                timeout=20,
            )
            if search_error:
                self._last_open_pr_lookup_errors.append(f"semantic_search:{search_error}")
            for hit in (
                (search_data or {}).get("items", []) if isinstance(search_data, dict) else []
            ):
                hit_text = f"{hit.get('title') or ''}\n{hit.get('body') or ''}"
                direct = bool(
                    re.search(
                        rf"\b(fix(e[sd])?|close[sd]?|resolve[sd]?)\s+#?{num}\b|#{num}\b",
                        hit_text,
                        re.I,
                    )
                )
                if not direct and is_dependency_update_pr(hit):
                    continue
                overlap_count, code_like_overlap = semantic_overlap_strength(title, hit_text)
                if overlap_count < 3 or not code_like_overlap:
                    continue
                url = hit.get("html_url")
                if url:
                    hits_by_url[url] = {
                        **hit,
                        "_semantic_overlap_count": overlap_count,
                        "_semantic_code_like": code_like_overlap,
                    }

        return sorted(
            hits_by_url.values(),
            key=lambda hit: (
                bool(hit.get("_linked_from_issue")),
                int(hit.get("_semantic_overlap_count") or 0),
            ),
            reverse=True,
        )[:5]

    def pr_detail(self, repo: str, pr_num: int) -> dict[str, Any]:
        fields = (
            "number,title,url,body,state,isDraft,updatedAt,createdAt,closedAt,mergedAt,author,files,"
            "additions,deletions,changedFiles,statusCheckRollup,reviewDecision,"
            "latestReviews,comments,closingIssuesReferences"
        )
        data, err = gh(["pr", "view", str(pr_num), "--repo", repo, "--json", fields], timeout=25)
        if isinstance(data, dict) and not err:
            return data
        data, err = gh(["api", f"repos/{repo}/pulls/{pr_num}"], timeout=15)
        if not isinstance(data, dict) or err:
            return {}
        files, files_err = gh(
            ["api", f"repos/{repo}/pulls/{pr_num}/files", "-f", "per_page=100"],
            timeout=20,
        )
        normalized_files = (
            [
                {**entry, "path": entry.get("path") or entry.get("filename") or ""}
                for entry in files
                if isinstance(entry, dict)
            ]
            if isinstance(files, list) and not files_err
            else []
        )
        return {
            **data,
            "url": data.get("html_url") or data.get("url"),
            "isDraft": bool(data.get("draft")),
            "updatedAt": data.get("updated_at"),
            "createdAt": data.get("created_at"),
            "closedAt": data.get("closed_at"),
            "mergedAt": data.get("merged_at"),
            "changedFiles": data.get("changed_files"),
            "files": normalized_files,
            "comments": [],
            "statusCheckRollup": [],
            "closingIssuesReferences": [],
        }

    def assess_single_pr(
        self,
        repo: str,
        issue_num: int,
        issue_title: str,
        hit: dict[str, Any],
        issue_context: str = "",
    ) -> dict[str, Any]:
        pr_num = int(hit.get("number") or 0)
        pr_repo = str(hit.get("_repo") or repo)
        detail = self.pr_detail(pr_repo, pr_num) if pr_num else {}
        title = detail.get("title") or hit.get("title") or ""
        body = detail.get("body") or hit.get("body") or ""
        url = detail.get("url") or hit.get("html_url") or ""
        text = f"{title}\n{body}".lower()
        state = str(detail.get("state") or hit.get("state") or "").upper()
        merged = bool(detail.get("mergedAt") or detail.get("merged_at"))
        author_association = str(
            detail.get("authorAssociation")
            or detail.get("author_association")
            or hit.get("authorAssociation")
            or hit.get("author_association")
            or ""
        ).upper()
        maintainer_owned = author_association in {"OWNER", "MEMBER", "COLLABORATOR"}
        comments_value = detail.get("comments")
        comments = comments_value if isinstance(comments_value, list) else []
        comment_text = "\n".join(
            comment.get("body") or "" for comment in comments if isinstance(comment, dict)
        )
        rule_closed = bool(
            state == "CLOSED"
            and re.search(
                r"automatically closed.{0,300}(?:not assigned|must be assigned)|"
                r"assigned to (?:an?|the) (?:linked )?issue before opening|"
                r"missing-issue-link|require-issue-link",
                comment_text,
                re.I | re.S,
            )
        )
        files_value = detail.get("files")
        files = files_value if isinstance(files_value, list) else []
        file_paths = [entry.get("path", "") for entry in files if isinstance(entry, dict)]
        test_files = [path for path in file_paths if TEST_FILE_RE.search(path)]
        closing_value = detail.get("closingIssuesReferences")
        closing = closing_value if isinstance(closing_value, list) else []
        references_issue = any(
            ref.get("number") == issue_num for ref in closing if isinstance(ref, dict)
        )
        references_issue = (
            references_issue
            or bool(hit.get("_linked_from_issue"))
            or bool(
                re.search(
                    rf"\b(fix(e[sd])?|close[sd]?|resolve[sd]?)\s+#?{issue_num}\b|#{issue_num}\b",
                    text,
                    re.I,
                )
            )
        )
        issue_body_link = bool(hit.get("_issue_body_link"))
        issue_body_link_relation = str(hit.get("_issue_body_link_relation") or "")

        checks_value = detail.get("statusCheckRollup")
        checks = checks_value if isinstance(checks_value, list) else []
        technical_checks = [
            check
            for check in checks
            if isinstance(check, dict) and not is_nontechnical_check(check)
        ]
        check_states = [
            str(check.get("conclusion") or check.get("state") or check.get("status") or "").upper()
            for check in technical_checks
        ]
        failed_checks = [
            state for state in check_states if state in {"FAILURE", "FAILED", "ERROR", "TIMED_OUT"}
        ]
        successful_checks = [state for state in check_states if state in {"SUCCESS", "COMPLETED"}]
        ignored_failed_checks = [
            str(check.get("name") or check.get("workflowName") or "unnamed")
            for check in checks
            if isinstance(check, dict)
            and str(
                check.get("conclusion") or check.get("state") or check.get("status") or ""
            ).upper()
            in {"FAILURE", "FAILED", "ERROR", "TIMED_OUT"}
            and is_nontechnical_check(check)
        ]
        technical_failed_checks = [
            str(check.get("name") or check.get("workflowName") or "unnamed")
            for check in technical_checks
            if str(
                check.get("conclusion") or check.get("state") or check.get("status") or ""
            ).upper()
            in {"FAILURE", "FAILED", "ERROR", "TIMED_OUT"}
        ]
        updated = parse_github_time(detail.get("updatedAt") or hit.get("updated_at"), self.now)
        age_days = max(0, (self.now - updated).days)
        changed_files = int(detail.get("changedFiles") or len(file_paths) or 0)
        additions = int(detail.get("additions") or 0)
        deletions = int(detail.get("deletions") or 0)

        keyword_hits, code_like_overlap = semantic_overlap_strength(issue_title, text)
        distinctive_overlap = semantic_distinctive_overlap(issue_title, text)
        overlapping_paths = overlapping_issue_pr_paths(issue_context, file_paths)
        semantic_overlap = (bool(overlapping_paths) and keyword_hits >= 2) or (
            keyword_hits >= 3 and code_like_overlap and len(distinctive_overlap) >= 2
        )

        score = 0
        strengths: list[str] = []
        gaps: list[str] = []
        if references_issue:
            score += 25
            strengths.append("明确关联 issue")
        else:
            score -= 10
            gaps.append("未明确 closing/reference 目标 issue")
        if test_files:
            score += 20
            strengths.append(f"包含测试文件 {len(test_files)} 个")
        else:
            score -= 20
            gaps.append("缺少测试文件")
        if successful_checks and not failed_checks:
            score += 12
            strengths.append("已有成功 CI/check")
        elif failed_checks:
            # A red status is diagnostic evidence, not proof that a competing
            # implementation is warranted. Attribution requires logs and a
            # substantive implementation gap, neither of which a rollup state
            # establishes on its own.
            strengths.append("CI 失败待归因，不作为竞争依据")
        else:
            strengths.append("CI/check 信息不足，不作为竞争依据")
        if detail.get("reviewDecision") == "APPROVED":
            score += 18
            strengths.append("已有 review approval")
        elif detail.get("reviewDecision") == "CHANGES_REQUESTED":
            score -= 12
            gaps.append("已有 changes requested")
        if detail.get("isDraft"):
            score -= 10
            gaps.append("仍是 draft")
        if maintainer_owned:
            score += 18
            strengths.append("由仓库维护者或协作者提交")
        if age_days <= 7:
            score += 8
            strengths.append("近期仍活跃")
        elif age_days >= 30:
            score -= 20
            gaps.append("超过 30 天未更新")
        elif age_days >= 14:
            score -= 10
            gaps.append("超过 14 天未更新")
        if keyword_hits >= 2:
            score += 8
            strengths.append("标题/正文与 issue 关键词匹配")
        elif keyword_hits == 0:
            score -= 6
            gaps.append("与 issue 关键词匹配弱")
        if changed_files > 18 or additions + deletions > 900:
            score -= 12
            gaps.append("改动面偏大")
        if len(body.strip()) < 80:
            score -= 5
            gaps.append("PR 描述过短")
        if semantic_overlap:
            score += 8
            strengths.append("改动文件与 issue 代码路径重合")

        technical_complete = bool(references_issue and test_files and changed_files > 0)
        documented_root_cause = bool(
            re.search(r"(?im)^##+\s+(?:why|root cause|problem|motivation)\b", body)
            and re.search(
                r"(?im)^##+\s+(?:how to test|test plan|verification|validation)\b",
                body,
            )
        )
        root_cause_coverage = bool(
            detail.get("rootCauseCoverage") is True
            or (
                technical_complete
                and (semantic_overlap or issue_body_link or documented_root_cause)
            )
        )
        material_competition_gaps = []
        if not test_files:
            material_competition_gaps.append("缺少回归测试")
        if changed_files <= 0:
            material_competition_gaps.append("未发现实现改动")
        if detail.get("isDraft"):
            material_competition_gaps.append("仍是 draft")
        if age_days >= 30:
            material_competition_gaps.append("超过 30 天未更新")

        return {
            "number": pr_num,
            "url": url,
            "title": title,
            "score": score,
            "references_issue": references_issue,
            "issue_body_link": issue_body_link,
            "issue_body_link_relation": issue_body_link_relation,
            "semantic_overlap": semantic_overlap,
            "semantic_overlap_count": keyword_hits,
            "semantic_distinctive_overlap": sorted(distinctive_overlap),
            "overlapping_paths": overlapping_paths[:3],
            "test_files": len(test_files),
            "changed_files": changed_files,
            "additions": additions,
            "deletions": deletions,
            "age_days": age_days,
            "is_draft": bool(detail.get("isDraft")),
            "state": "MERGED" if merged else state,
            "rule_closed": rule_closed,
            "maintainer_owned": maintainer_owned,
            "author_association": author_association,
            "technical_complete": technical_complete,
            "root_cause_coverage": root_cause_coverage,
            "material_competition_gaps": material_competition_gaps,
            "ignored_nontechnical_failed_checks": ignored_failed_checks[:3],
            "technical_failed_checks": technical_failed_checks[:3],
            "ci_competition_weight": 0,
            "strengths": strengths[:4],
            "gaps": gaps[:5],
        }

    def assess_open_prs(
        self,
        repo: str,
        num: int,
        title: str,
        issue_context: str = "",
    ) -> dict[str, Any]:
        self._last_open_pr_lookup_errors = []
        hits = self.open_pr_hits(repo, num, title, issue_context)
        lookup_errors = list(getattr(self, "_last_open_pr_lookup_errors", []))
        if not hits:
            if lookup_errors:
                return {
                    "status": "lookup_failed",
                    "prs": [],
                    "summary": "open PR 检索不完整，禁止将未知当成无重复实现",
                    "errors": lookup_errors[:3],
                }
            return {"status": "none", "prs": [], "summary": "未发现相关 open PR"}

        assessments = [self.assess_single_pr(repo, num, title, hit, issue_context) for hit in hits]
        assessments = [item for item in assessments if item.get("url")]
        if not assessments:
            return {
                "status": "lookup_failed",
                "prs": [],
                "summary": "open PR 命中但无法读取有效详情",
                "errors": lookup_errors[:3],
            }

        direct_assessments = [item for item in assessments if item["references_issue"]]
        if not direct_assessments:
            if lookup_errors:
                return {
                    "status": "lookup_failed",
                    "prs": assessments[:3],
                    "summary": "open PR 检索不完整，需等待下轮重试后再判断碰撞",
                    "errors": lookup_errors[:3],
                }
            active_assessments = [
                item for item in assessments if item.get("state") in {None, "OPEN"}
            ]
            if not active_assessments:
                return {
                    "status": "none",
                    "prs": assessments[:3],
                    "summary": "未发现相关 open PR；仅发现未直接关联 issue 的历史 PR",
                }
            semantic_assessments = [
                item for item in active_assessments if item.get("semantic_overlap")
            ]
            if semantic_assessments:
                best = max(
                    semantic_assessments,
                    key=lambda item: (
                        item.get("semantic_overlap_count", 0),
                        item["score"],
                    ),
                )
                return {
                    "status": "semantic_overlap_requires_review",
                    "best_score": best["score"],
                    "best_url": best["url"],
                    "summary": (
                        f"发现 PR #{best['number']} 与 issue 代码路径和关键语义重合，"
                        "但未直接关联 issue；需人工比较，禁止自动创建重复任务"
                    ),
                    "prs": active_assessments[:3],
                }
            best = max(active_assessments, key=lambda item: item["score"])
            return {
                "status": "none",
                "best_score": best["score"],
                "best_url": best["url"],
                "keywordOverlapOnly": True,
                "summary": (
                    f"仅发现未直接关联、无代码路径或强机制重合的 PR #{best['number']}；"
                    "保留为搜索上下文，不阻止实现"
                ),
                "prs": active_assessments[:3],
            }

        best = max(
            direct_assessments,
            key=lambda item: (
                bool(item.get("issue_body_link")),
                bool(item.get("technical_complete") and item.get("rule_closed")),
                item.get("state") == "MERGED",
                item["score"],
            ),
        )
        active_direct = [
            item
            for item in direct_assessments
            if str(item.get("state") or "OPEN").upper() == "OPEN"
        ]
        merged_direct = [
            item for item in direct_assessments if str(item.get("state") or "").upper() == "MERGED"
        ]
        if merged_direct:
            best = max(merged_direct, key=lambda item: item["score"])
        elif active_direct:
            best = max(active_direct, key=lambda item: item["score"])

        # Direct association and recent activity are auxiliary signals. A PR
        # is strong only with root-cause coverage plus two independent proofs.
        def strong_pr(item: dict[str, Any]) -> bool:
            independent = sum(
                bool(value)
                for value in (
                    int(item.get("changed_files") or 0) > 0,
                    int(item.get("test_files") or 0) > 0,
                    item.get("maintainer_owned") is True
                    or item.get("reviewDecision") == "APPROVED",
                    item.get("semantic_overlap") is True,
                )
            )
            return item.get("root_cause_coverage") is True and independent >= 2

        strong = strong_pr(best)
        competition_saturated = len(active_direct) >= 2
        if competition_saturated:
            status = "competition_saturated"
            numbers = ", ".join(f"#{item['number']}" for item in active_direct[:5])
            summary = (
                f"已有 {len(active_direct)} 个活跃直接关联 PR（{numbers}）；"
                "竞争已饱和，不应再创建重复实现"
            )
        elif strong:
            status = "covered_strong"
            if active_direct:
                summary = (
                    f"已有活跃且直接关联 issue 的 PR #{best['number']}；"
                    "CI 状态只作诊断，不能据此自动创建竞争 PR"
                )
            else:
                summary = f"已有较强 PR：#{best['number']} score={best['score']}，{'; '.join(best['strengths'])}"
        elif active_direct and repo_rules(repo) != "needs_assignment":
            status = "weak_pr_competition_possible"
            summary = (
                f"已有直接关联但证据不完整的 PR #{best['number']}："
                f"{'; '.join(best.get('gaps') or ['缺少完整验证'])}；"
                "只有能补足根因、测试或关键路径覆盖时才值得竞争"
            )
        elif repo_rules(repo) == "needs_assignment":
            status = "human_review_required"
            summary = f"已有 PR 但强度不足，且仓库通常需要先分配/确认：#{best['number']} score={best['score']}"
        else:
            status = "human_review_required"
            summary = f"发现关键词相关 PR，但未确认直接覆盖：#{best['number']}；需人工核对"

        independent = {
            "codeChange": int(best.get("changed_files") or 0) > 0,
            "tests": int(best.get("test_files") or 0) > 0,
            "maintainerRecognition": bool(best.get("maintainer_owned"))
            or best.get("reviewDecision") == "APPROVED",
            "keyPathCoverage": bool(best.get("semantic_overlap")),
        }
        gaps = list(best.get("gaps") or [])
        if not best.get("root_cause_coverage"):
            gaps.append("缺少根因覆盖证据")

        return {
            "status": status,
            "best_score": best["score"],
            "best_url": best["url"],
            "summary": summary,
            "prs": assessments[:3],
            "components": {
                "rootCauseCoverage": bool(best.get("root_cause_coverage")),
                "independentEvidence": independent,
                "ciIsDiagnosticOnly": True,
            },
            "gaps": sorted(set(gaps))[:8],
        }

    def score_issue(
        self,
        base: dict[str, Any],
        issue: dict[str, Any],
        comments: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, str | None]:
        labels = [label.get("name", "") for label in issue.get("labels", [])]
        labels_text = " ".join(labels)
        title = issue.get("title") or base["title"]
        issue_kind_text = f"{title}\n{labels_text}"
        body = issue.get("body") or ""
        text = f"{title}\n{body}\n" + "\n".join(
            (comment.get("body") or "") for comment in comments[-8:]
        )
        topic_text = re.sub(r"[_-]+", " ", f"{title}\n{body}")
        scoring_text = re.sub(r"[_-]+", " ", text)
        maintainer_approved = any(
            (comment.get("author_association") or "").upper() in {"MEMBER", "OWNER", "COLLABORATOR"}
            and MAINTAINER_APPROVAL_RE.search(comment.get("body") or "")
            for comment in comments
        )
        recent_maintainer_approved = any(
            (comment.get("author_association") or "").upper() in {"MEMBER", "OWNER", "COLLABORATOR"}
            and MAINTAINER_APPROVAL_RE.search(comment.get("body") or "")
            and parse_github_time(comment.get("created_at"), self.now)
            >= self.now - timedelta(days=30)
            for comment in comments
        )
        maintainer_configuration_guidance = any(
            (comment.get("author_association") or "").upper() in {"MEMBER", "OWNER", "COLLABORATOR"}
            and MAINTAINER_CONFIGURATION_GUIDANCE_RE.search(comment.get("body") or "")
            and CONFIGURATION_CONTEXT_RE.search(comment.get("body") or "")
            for comment in comments
        ) and bool(CONFIGURATION_CONTEXT_RE.search(title + "\n" + body[:5000]))
        maintainer_active_investigation = any(
            (comment.get("author_association") or "").upper() in {"MEMBER", "OWNER", "COLLABORATOR"}
            and MAINTAINER_ACTIVE_INVESTIGATION_RE.search(comment.get("body") or "")
            and parse_github_time(comment.get("created_at"), self.now)
            >= self.now - timedelta(days=3)
            for comment in comments
        )
        maintainer_revalidation_requested = any(
            (comment.get("author_association") or "").upper() in {"MEMBER", "OWNER", "COLLABORATOR"}
            and MAINTAINER_REVALIDATION_REQUEST_RE.search(comment.get("body") or "")
            and parse_github_time(comment.get("created_at"), self.now)
            >= self.now - timedelta(days=7)
            for comment in comments
        )
        help_wanted = bool(HELP_WANTED_RE.search(labels_text))
        needs_confirmation = bool(
            WAIT_LABEL_RE.search(labels_text) or ISSUE_APPROVAL_GATE_RE.search(body)
        )
        repro_evidence = public_reproduction_evidence(body)
        public_repro_signals = len(repro_evidence)
        root_cause_signal = bool(ROOT_CAUSE_RE.search(title + "\n" + body))
        code_anchors = issue_code_anchors(text[:24000])
        probe_ready = bool(
            (public_repro_signals >= 2 and code_anchors)
            or (root_cause_signal and code_anchors)
            or ((maintainer_approved or help_wanted) and code_anchors)
        )
        algorithm_evidence = llm_algorithm_evidence(
            base["repo"],
            scoring_text,
            public_repro_signals=public_repro_signals,
            root_cause_signal=root_cause_signal,
        )
        track = issue_track(base["repo"], scoring_text, algorithm_evidence)
        design_confirmation = bool(
            re.search(r"\btriage\b", labels_text, re.I)
            or API_DESIGN_RE.search(title + "\n" + body[:3000])
        ) and not (maintainer_approved or help_wanted)
        usage_confirmation = bool(USAGE_AMBIGUITY_RE.search(title + "\n" + body[:3000])) and not (
            maintainer_approved or help_wanted
        )
        needs_confirmation = (
            needs_confirmation
            or design_confirmation
            or usage_confirmation
            or (maintainer_active_investigation and not (maintainer_approved or help_wanted))
            or (maintainer_revalidation_requested and not (maintainer_approved or help_wanted))
        )
        issue_author = ((issue.get("user") or {}).get("login") or "").lower()
        report_retracted = any(
            RETRACTED_RE.search(comment.get("body") or "")
            and (
                ((comment.get("user") or {}).get("login") or "").lower() == issue_author
                or (comment.get("author_association") or "").upper()
                in {"MEMBER", "OWNER", "COLLABORATOR"}
            )
            for comment in comments
        )
        resolved_upstream = any(
            RESOLVED_UPSTREAM_RE.search(comment.get("body") or "")
            and (comment.get("author_association") or "").upper()
            in {"MEMBER", "OWNER", "COLLABORATOR", "CONTRIBUTOR"}
            for comment in comments
        )
        wrong_repository = bool(WRONG_REPOSITORY_RE.search(title + "\n" + body[:5000])) or any(
            WRONG_REPOSITORY_RE.search(comment.get("body") or "")
            and (
                ((comment.get("user") or {}).get("login") or "").lower() == issue_author
                or (
                    (comment.get("author_association") or "").upper()
                    in {"MEMBER", "OWNER", "COLLABORATOR", "CONTRIBUTOR"}
                    and not BOT_RE.search(((comment.get("user") or {}).get("login") or ""))
                )
            )
            for comment in comments
        )

        if (issue.get("state") or "").lower() not in {"", "open"}:
            return None, "not_open"
        if issue.get("assignees"):
            return None, "assigned"
        if SKIP_LABEL_RE.search(labels_text):
            return None, "low_value_label"
        if TRIVIAL_RE.search(title + "\n" + body[:1500]):
            return None, "trivial"
        if SECURITY_SENSITIVE_RE.search(title + "\n" + body[:3000]) or SECURITY_LABEL_RE.search(
            labels_text
        ):
            return None, "security_disclosure_required"
        if LOW_IMPACT_SELF_ASSESSMENT_RE.search(body) and not (maintainer_approved or help_wanted):
            return None, "explicitly_low_impact"
        if incomplete_template_value_count(body) >= 2 and not (maintainer_approved or help_wanted):
            return None, "incomplete_issue_template"
        if REACTIVATED_STALE_LABEL_RE.search(labels_text) and not (
            recent_maintainer_approved or help_wanted
        ):
            return None, "reactivated_stale_without_recent_maintainer_confirmation"
        if maintainer_configuration_guidance and not (maintainer_approved or help_wanted):
            return None, "maintainer_configuration_guidance"
        if UNTRUSTED_TRIAGE_INSTRUCTION_RE.search(body):
            return None, "untrusted_triage_instruction"
        if base["repo"].casefold() == "microsoft/autogen" and not BUG_ACTIONABILITY_RE.search(
            title + "\n" + labels_text
        ):
            return None, "maintenance_mode_non_bug"
        if base["repo"].casefold() in UNAVAILABLE_HARDWARE_REPOS:
            return None, "hardware_unavailable_repo"
        if not base.get("_explicit_recheck") and self.only_bot_refreshed(
            base["repo"], base["num"], issue, comments
        ):
            return None, "bot_or_stale_refresh"
        claims = detect_claims(
            comments,
            current_actor=os.environ.get("RADAR_GITHUB_ACTOR", "Oxygen56"),
            issue=issue,
        )
        if ACTIVE_RE.search(body) or claims:
            return None, "someone_active"
        if RFC_RE.search(title + "\n" + labels_text + "\n" + body[:1200]) and not (
            maintainer_approved
        ):
            return None, "rfc_or_roadmap_without_maintainer_split"
        if PROMOTIONAL_UPDATE_RE.search(title + "\n" + body[:600]) and not (
            maintainer_approved or help_wanted
        ):
            return None, "promotional_or_external_integration"
        if INTERNAL_AUTOMATION_ISSUE_RE.search(title + "\n" + body[:1600]) and not (
            maintainer_approved or help_wanted
        ):
            return None, "automated_maintenance_issue"
        if (
            re.search(r"\b(feature|enhancement|proposal)\b", labels_text, re.I)
            and not BUG_ACTIONABILITY_RE.search(title)
            and not (maintainer_approved or help_wanted)
        ):
            return None, "feature_without_maintainer_approval"
        if not (
            BUG_ACTIONABILITY_RE.search(title + "\n" + labels_text)
            or maintainer_approved
            or help_wanted
        ):
            return None, "no_bug_or_maintainer_actionability"
        if PRIVATE_REPRO_RE.search(body):
            return None, "private_reproduction"
        if report_retracted:
            return None, "report_retracted"
        if resolved_upstream:
            return None, "resolved_upstream"
        if wrong_repository:
            return None, "wrong_repository_or_downstream_bug"
        if UPSTREAM_ROOT_CAUSE_RE.search(title + "\n" + body[:12000]) and not (
            maintainer_approved or help_wanted
        ):
            return None, "upstream_root_cause_without_maintainer_scope"
        if EXTERNAL_MODEL_CAUSE_RE.search(title + "\n" + body) or HOSTED_MODEL_QUALITY_RE.search(
            title + "\n" + body
        ):
            return None, "external_model_or_provider_issue"
        if MANAGED_INFERENCE_INCIDENT_RE.search(title + "\n" + body) and not (
            maintainer_approved or help_wanted
        ):
            return None, "managed_inference_service_incident"
        if USAGE_QUESTION_RE.search(title + "\n" + body[:4000]) and not root_cause_signal:
            return None, "usage_or_documentation_question"
        if MODEL_ARTIFACT_FAILURE_RE.search(title + "\n" + body[:8000]):
            return None, "external_model_artifact_failure"
        if requires_unavailable_hardware(title, labels_text, body):
            return None, "hardware_unavailable"
        if is_desktop_peripheral_issue(title, labels_text, body):
            return None, "desktop_peripheral_issue"
        if is_frontend_interaction_issue(title, labels_text, body):
            return None, "frontend_interaction_issue"
        if track == LLM_ALGORITHM_TRACK:
            if algorithm_evidence["operational_only"]:
                return None, "algorithm_operational_or_configuration_only"
            if not algorithm_evidence["qualified"]:
                return None, "algorithm_mechanism_evidence_low"
        if track != LLM_ALGORITHM_TRACK and not HIGH_RE.search(topic_text):
            return None, "off_topic"
        dynamic_topic_text = re.sub(r"[_-]+", " ", f"{title}\n{labels_text}\n{body[:4000]}")
        if base["repo"] not in set(KNOWN_REPOS) and not (
            is_dynamic_agent_infra_issue(dynamic_topic_text)
            or is_dynamic_llm_algorithm_issue(dynamic_topic_text)
        ):
            return None, "off_topic_dynamic_repo"
        if re.search(r"\b(bug|regression|performance)\b", issue_kind_text, re.I) and not (
            probe_ready
        ):
            return None, "probe_contract_incomplete"

        high_hits = len({match.group(0).lower() for match in HIGH_RE.finditer(scoring_text)})
        impact_hits = len({match.group(0).lower() for match in IMPACT_RE.finditer(scoring_text)})
        score = 0
        if high_hits >= 5 or len(body) > 1800:
            score += 3
            difficulty = "高"
        elif high_hits >= 2 or len(body) > 700:
            score += 2
            difficulty = "中"
        else:
            score += 1
            difficulty = "低"

        if impact_hits >= 2 or re.search(
            r"\b(bug|performance|regression)\b", issue_kind_text, re.I
        ):
            score += 3
            impact = "高"
        elif impact_hits >= 1 or re.search(r"\b(enhancement|feature)\b", issue_kind_text, re.I):
            score += 2
            impact = "中"
        else:
            score += 1
            impact = "低"

        if re.search(r"\b(bug|feature|performance|refactor|regression)\b", issue_kind_text, re.I):
            score += 2
        elif BUG_ACTIONABILITY_RE.search(title):
            # A precise failure mechanism in the title is equivalent evidence
            # to a missing bug label; many mature repositories triage labels later.
            score += 2
        elif re.search(r"\benhancement\b", issue_kind_text, re.I):
            score += 1
        score += 1
        if base["repo"] in AGENT_INFRA_PRIORITY_REPOS:
            score += 1
        if track == LLM_ALGORITHM_TRACK:
            score = max(score + 1, int(algorithm_evidence["score"]))
        if repo_rules(base["repo"]) == "needs_assignment":
            score -= 2
        if public_repro_signals >= 2:
            score += 1
        if root_cause_signal:
            score += 1
        if design_confirmation and public_repro_signals >= 1:
            # Explicit maintainer design gates are valuable review opportunities
            # even when the repository has not added a bug label yet. They can
            # only become WAIT_MAINTAINER, never an automatic implementation.
            score += 3
        if score < MIN_ACTIONABLE_SCORE:
            return None, "score_low"

        lower = text.lower()
        why: list[str] = []
        if re.search(r"\b(bug|regression|performance)\b", issue_kind_text, re.I):
            why.append("用户可见 bug/性能问题，合并动机明确")
        if any(
            term in lower
            for term in [
                "streaming",
                "tool call",
                "function call",
                "structured output",
                "mcp",
                "workflow",
                "agent",
                "kv cache",
                "inference",
                "serving",
                "retrieval",
                "embedding",
            ]
        ):
            why.append("命中 agent/inference/RAG 关键路径")
        if impact == "高":
            why.append("影响面高，适合做可复现修复")
        if not why:
            why.append("问题边界清楚且无人认领")

        title_lower = title.lower()
        expected = "先补失败用例，再沿相关 runtime/provider/scheduler 路径做最小修复。"
        test_path = (
            "用 issue 的公开最小复现先建立失败测试，再运行目标 package 的定向单测和静态检查。"
        )
        risk = "需确认是否已有 maintainer 设计偏好；避免扩大 API 行为变更。"
        role_eta = f"{difficulty}难度 / 预计 4-12 小时，适合作为 runtime/provider 修复型 PR。"
        if track == LLM_ALGORITHM_TRACK:
            mechanism_names = "、".join(algorithm_evidence["mechanisms"][:4])
            why = [f"命中可验证的 LLM 算法机制：{mechanism_names}"]
            if algorithm_evidence["formula_signal"]:
                why.append("包含公式/目标函数级证据，可形成算法正确性故事")
            if algorithm_evidence["experiment_signal"]:
                why.append("具备可比较实验或数值回归路径")
            mechanisms = set(algorithm_evidence["mechanisms"])
            if "post_training_objective" in mechanisms:
                expected = (
                    "固定 reward/logprob/advantage 等目标函数不变量，定位训练目标或采样路径根因，"
                    "以最小实现修正并补数值回归。"
                )
            elif "parameter_efficient_finetuning" in mechanisms:
                expected = (
                    "复现 adapter 参数选择、分组或合并差异，修正 PEFT 数学语义并补参数级回归测试。"
                )
            elif "distributed_training" in mechanisms:
                expected = (
                    "复现并行切分、同步或 checkpoint 不变量，修正分布式训练路径并补多 rank 回归。"
                )
            elif "evaluation_method" in mechanisms:
                expected = "固定样本、模板和指标定义，修正评测计算或聚合逻辑，并补基准兼容性回归。"
            elif "numerics_quantization" in mechanisms:
                expected = (
                    "建立高精度 reference，对比量化/混合精度误差，修正缩放或数值路径并补容差测试。"
                )
            else:
                expected = (
                    "建立 reference 输出和模型机制不变量，定位架构/优化实现偏差并补数值正确性回归。"
                )
            test_path = (
                "先用小模型、固定 seed 和合成 batch 建立 CPU/单卡 reference；"
                "再运行目标算法单测、数值容差检查，必要时补多卡或 GPU 对照实验。"
            )
            risk = "需区分数学语义错误与浮点/随机波动；测试必须固定基线、seed、容差和适用硬件。"
            role_eta = "高含金量算法工程 PR / 预计 8-24 小时，适合展示公式到实现再到实验的闭环。"
            difficulty = "高" if algorithm_evidence["depth"] == "high" else "中"
        elif KERNEL_RE.search(title):
            expected = "复现数值或批次不变量，定位 kernel 选择/块大小/数据布局根因，并补确定性正确性回归测试。"
            test_path = "先用 CPU/mock 或现有 kernel 单测固定输入输出不变量；具备匹配 GPU 时再补真实硬件复现。"
        elif "stream" in title_lower:
            expected = (
                "复现 streaming 事件序列，修正 chunk/finish/tool-call 状态传播，并补流式回归测试。"
            )
        elif re.search(r"\b(tool|function)[- ]call\b", title_lower):
            expected = "复现 tool-call 序列化/路由问题，修正转换层或 agent runtime 状态机，并补 provider/runtime 测试。"
        elif "structured output" in title_lower or "schema" in title_lower:
            expected = "复现 schema/structured-output 校验问题，修正 schema 生成或解析兼容性，并补模型无关单测。"
        elif "kv cache" in title_lower or "inference" in title_lower or "serving" in title_lower:
            expected = "用现有 serving 测试或最小 benchmark 复现，修正调度/cache 路径，并补性能或正确性回归。"

        rules = repo_rules(base["repo"])
        if rules == "ai_disclosure_conflict" and not needs_confirmation:
            bucket = "conflict"
            category = "LOCAL_FIX_ONLY"
        else:
            bucket = (
                "immediate" if rules == "normal" and not needs_confirmation else "needs_approval"
            )
            category = "NEW_CLEAN_CANDIDATE" if bucket == "immediate" else "WAIT_MAINTAINER"
        return {
            "repo": base["repo"],
            "num": base["num"],
            "title": title,
            "url": issue.get("html_url") or base["url"],
            "issue_updated": issue.get("updated_at") or base.get("updated") or "",
            "profile": PROFILE,
            "track": track,
            "scanner_version": SCANNER_VERSION,
            "category": category,
            "gate_decision": (
                "ALLOW_TO_WORK"
                if bucket == "immediate"
                else "ALLOW_PRIVATE_WORK"
                if bucket == "conflict"
                else "HUMAN_REVIEW"
            ),
            "score": score,
            "difficulty": difficulty,
            "impact": impact,
            "labels": labels[:6],
            "bucket": bucket,
            "auto_spawn": bucket == "immediate",
            "public_submission_allowed": bucket != "conflict",
            "hardware_compatible": True,
            "algorithm_evidence": algorithm_evidence if track == LLM_ALGORITHM_TRACK else None,
            "actionability_evidence": {
                "public_repro_signals": public_repro_signals,
                "reproduction_evidence": list(repro_evidence),
                "root_cause_signal": root_cause_signal,
                "code_anchors": list(code_anchors[:8]),
                "probe_ready": probe_ready,
                "maintainer_approved": maintainer_approved,
                "help_wanted": help_wanted,
                "needs_confirmation": needs_confirmation,
                "design_confirmation": design_confirmation,
                "usage_confirmation": usage_confirmation,
                "maintainer_active_investigation": maintainer_active_investigation,
                "maintainer_revalidation_requested": maintainer_revalidation_requested,
            },
            "why": "；".join(why[:3]),
            "expected_changes": expected,
            "test_path": test_path,
            "risk": risk,
            "next_step": (
                "阅读相关实现和测试，先本地复现，再决定是否开 PR。"
                if bucket == "immediate"
                else (
                    "仅准备本地修复和私有提交包，不执行任何公开 GitHub 动作。"
                    if bucket == "conflict"
                    else "先在 issue 下请求分配/确认方案，获批后再开 PR。"
                )
            ),
            "role_eta": role_eta,
            "open_pr_assessment": None,
            "related_issue_assessment": None,
        }, None

    def shortlist(self, items: dict[str, dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
        known = set(KNOWN_REPOS)
        bases: list[dict[str, Any]] = []
        rejection_counts: Counter[str] = Counter()
        rejection_examples: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        deadline_deferred_bases: list[dict[str, Any]] = []

        def reject(reason: str, base: dict[str, Any]) -> None:
            key = f"{base.get('repo')}#{base.get('num')}"
            self.issue_outcomes[key] = {"status": "rejected", "reason": reason}
            previous = self.seen.get(key)
            if (
                base.get("_explicit_recheck")
                and isinstance(previous, dict)
                and previous.get("status") in {"inspection_budget_deferred", "candidate_overflow"}
            ):
                retryable = reason.endswith("_failed")
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": "status_update" if retryable else "rejected",
                    "reason": reason,
                    "title": base.get("title") or key,
                    "url": base.get("url")
                    or f"https://github.com/{base.get('repo')}/issues/{base.get('num')}",
                    "issue_updated": base.get("updated") or base.get("issue_updated") or "",
                    **({"requeued_at": self.analyzed} if retryable else {}),
                }
            rejection_counts[reason] += 1
            if len(rejection_examples[reason]) < 2:
                rejection_examples[reason].append(
                    {
                        "repo": base.get("repo"),
                        "num": base.get("num"),
                        "title": base.get("title"),
                        "url": base.get("url"),
                    }
                )

        def defer(base: dict[str, Any], reason: str) -> None:
            key = f"{base['repo']}#{base['num']}"
            previous = self.seen.get(key) if isinstance(self.seen.get(key), dict) else {}
            self.issue_outcomes[key] = {"status": "deferred", "reason": reason}
            self.seen[key] = {
                "analyzed": self.analyzed,
                "requeued_at": self.analyzed,
                "first_deferred_at": previous.get("first_deferred_at")
                or previous.get("requeued_at")
                or self.analyzed,
                "defer_count": int(previous.get("defer_count") or 0) + 1,
                "deferred_from_status": previous.get("deferred_from_status")
                or previous.get("status"),
                "score": previous.get("score"),
                "status": (
                    "candidate_overflow"
                    if reason == "candidate_overflow"
                    else "inspection_budget_deferred"
                ),
                "reason": reason,
                "title": base.get("title") or key,
                "url": base.get("url") or f"https://github.com/{base['repo']}/issues/{base['num']}",
                "issue_updated": base.get("updated") or base.get("issue_updated") or "",
                **self.notification_history.get(key, {}),
            }

        def defer_evidence_lookup(base: dict[str, Any], issue: dict[str, Any], reason: str) -> None:
            key = f"{base['repo']}#{base['num']}"
            previous = self.seen.get(key) if isinstance(self.seen.get(key), dict) else {}
            reject(reason, base)
            self.issue_outcomes[key] = {"status": "deferred", "reason": reason}
            self.seen[key] = {
                "analyzed": self.analyzed,
                "status": "status_update",
                "reason": reason,
                "requeue_reason": "critical_evidence_fetch_failure",
                "requeued_at": self.analyzed,
                "first_deferred_at": previous.get("first_deferred_at")
                or previous.get("requeued_at")
                or self.analyzed,
                "defer_count": int(previous.get("defer_count") or 0) + 1,
                "deferred_from_status": previous.get("deferred_from_status")
                or previous.get("status"),
                "title": issue.get("title") or base.get("title") or key,
                "url": base.get("url") or f"https://github.com/{base['repo']}/issues/{base['num']}",
                "issue_updated": issue.get("updated_at")
                or base.get("updated")
                or base.get("issue_updated")
                or "",
                **self.notification_history.get(key, {}),
            }

        for base in items.values():
            if repo_is_excluded(base["repo"]):
                reject("excluded_repo", base)
                continue
            key = f"{base['repo']}#{base['num']}"
            if not base.get("_explicit_recheck") and should_skip_seen(
                self.seen.get(key),
                base.get("updated"),
                self.now,
                scanner_version=SCANNER_VERSION,
                decision_digest=decision_contract_digest(),
            ):
                reject("seen_recently", base)
                continue
            if base.get("assignees") or SKIP_LABEL_RE.search(" ".join(base.get("labels", []))):
                reject("prefilter_assigned_or_low_value_label", base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "issue_updated": base.get("updated") or "",
                    "status": "skip_prefilter",
                    "title": base["title"],
                }
                continue
            if self.deep_inspection_deadline_reached():
                deadline_deferred_bases.append(base)
                continue
            ok, reason = self.repo_quality(base["repo"], base["repo"] in known)
            if not ok:
                reject(f"repo_quality:{reason}", base)
                if reason in {"repo_meta_failed", "repo_contents_failed"}:
                    self.seen[key] = {
                        "analyzed": self.analyzed,
                        "status": "status_update",
                        "reason": reason,
                        "requeue_reason": "transient_repo_quality_failure",
                        "requeued_at": self.analyzed,
                        "title": base["title"],
                        "issue_updated": base.get("updated") or "",
                    }
                else:
                    self.seen[key] = {
                        "analyzed": self.analyzed,
                        "status": "skip_repo_quality",
                        "reason": reason,
                        "title": base["title"],
                        "issue_updated": base.get("updated") or "",
                    }
                continue
            bases.append(base)
            self.qualified_repo_names.add(str(base["repo"]))

        bases.sort(key=base_priority, reverse=True)
        inspection_bases, deferred_bases = select_inspection_bases(bases)
        self.deferred_rechecks_attempted = sum(
            bool(base.get("_explicit_recheck")) for base in inspection_bases
        )
        for base in deferred_bases:
            defer(base, "inspection_budget_deferred")
        for base in deadline_deferred_bases:
            defer(base, "scan_deadline_deferred")
        inspected = 0
        candidates: list[dict[str, Any]] = []
        for index, base in enumerate(inspection_bases):
            if self.deep_inspection_deadline_reached():
                for remaining in inspection_bases[index:]:
                    defer(remaining, "scan_deadline_deferred")
                deadline_deferred_bases.extend(inspection_bases[index:])
                break
            key = f"{base['repo']}#{base['num']}"
            self.inspected_repo_names.add(str(base["repo"]))
            issue = self.issue(base["repo"], base["num"])
            if not issue:
                issue_error = self._last_issue_lookup_error or "invalid_issue_response"
                issue_missing = bool(
                    re.search(r"\b(?:HTTP 404|HTTP 410|Not Found|Gone)\b", issue_error, re.I)
                )
                reason = "issue_not_found" if issue_missing else "issue_fetch_failed"
                reject(reason, base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": reason if issue_missing else "status_update",
                    "reason": reason,
                    "title": base.get("title") or key,
                    "url": base.get("url")
                    or f"https://github.com/{base['repo']}/issues/{base['num']}",
                    "issue_updated": base.get("updated") or base.get("issue_updated") or "",
                    **(
                        {}
                        if issue_missing
                        else {
                            "requeue_reason": "critical_evidence_fetch_failure",
                            "requeued_at": self.analyzed,
                        }
                    ),
                }
                continue
            if issue.get("state") != "open" or issue.get("pull_request"):
                reject("not_open_or_pull_request", base)
                continue
            comments = self.comments(base["repo"], base["num"])
            if self._last_comments_lookup_error:
                reject("comments_lookup_failed", base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": "status_update",
                    "reason": "comments_lookup_failed",
                    "requeue_reason": "critical_evidence_fetch_failure",
                    "requeued_at": self.analyzed,
                    "title": issue.get("title") or base["title"],
                    "issue_updated": issue.get("updated_at") or base.get("updated") or "",
                }
                continue
            inspected += 1
            scored, reason = self.score_issue(base, issue, comments)
            if not scored:
                reject(reason or "score_rejected", base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": reason,
                    "title": issue.get("title") or base["title"],
                    "issue_updated": issue.get("updated_at") or base.get("updated") or "",
                }
                continue
            policy = self.submission_policy(base["repo"])
            scored["submission_policy"] = policy
            if policy == "contributions_closed":
                reject("repository_not_accepting_code_contributions", base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": "repository_not_accepting_code_contributions",
                    "title": issue.get("title") or base["title"],
                    "issue_updated": issue.get("updated_at") or base.get("updated") or "",
                }
                continue
            if policy == "nonstandard_contribution_agreement":
                reject("nonstandard_contribution_agreement", base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": "nonstandard_contribution_agreement",
                    "title": issue.get("title") or base["title"],
                    "issue_updated": issue.get("updated_at") or base.get("updated") or "",
                }
                continue
            if policy == "ai_disclosure_conflict":
                scored["bucket"] = "conflict"
                scored["category"] = "LOCAL_FIX_ONLY"
                scored["gate_decision"] = "ALLOW_PRIVATE_WORK"
                # Private implementation is still useful. Publication remains
                # separately gated on user-approved disclosure wording.
                scored["auto_spawn"] = True
                scored["public_submission_allowed"] = False
                scored["risk"] = (
                    f"{scored['risk']}；仓库要求公开 AI 使用披露，自动公开动作被硬禁用。"
                )
                scored["next_step"] = (
                    "创建项目任务并完成本地复现、修复、测试和私有提交包；公开提交前等待用户确认披露措辞。"
                )
            if policy == "policy_unknown":
                defer_evidence_lookup(base, issue, "policy_lookup_failed")
                continue
            elif policy in {
                "needs_assignment",
                "ai_disclosure_and_assignment",
            }:
                scored["bucket"] = "needs_approval"
                scored["category"] = "WAIT_MAINTAINER"
                scored["gate_decision"] = "HUMAN_REVIEW"
                scored["auto_spawn"] = False
                scored["submission_policy"] = policy
                scored["next_step"] = (
                    "先请求维护者分配/确认方案，获批后再开 PR。"
                    if policy == "needs_assignment"
                    else (
                        "先等待维护者分配/确认方案；即使获批，公开 PR 的 AI 复核/披露确认仍必须由用户本人处理。"
                        if policy == "ai_disclosure_and_assignment"
                        else "仓库贡献政策读取失败；先人工确认 CONTRIBUTING/PR 模板后再行动。"
                    )
                )
                if policy == "ai_disclosure_and_assignment":
                    scored["public_submission_allowed"] = False
                    scored["risk"] = (
                        f"{scored['risk']}；仓库同时要求先分配，并要求用户本人完成 AI 代码复核/披露确认。"
                    )
            elif policy == "legal_confirmation":
                scored["risk"] = (
                    f"{scored['risk']}；DCO 将自动使用已配置 Git 身份 sign-off；"
                    "CLA 不阻止创建 PR，但协议接受仍需用户本人完成。"
                )
                scored["next_step"] = (
                    "按正常流程实现并验证；如要求 DCO 则自动 sign-off，PR 创建后报告 CLA 状态。"
                )
            issue_context = (
                (issue.get("body") or "")
                + "\n"
                + "\n".join((comment.get("body") or "") for comment in comments[-12:])
            )
            related_issue_assessment = self.assess_related_issues(
                base["repo"],
                base["num"],
                issue.get("title") or base["title"],
                issue_context,
            )
            scored["related_issue_assessment"] = related_issue_assessment
            if related_issue_assessment["status"] == "lookup_failed":
                defer_evidence_lookup(base, issue, "related_issue_lookup_failed")
                continue
            if related_issue_assessment["status"] != "none":
                scored["bucket"] = "needs_approval"
                scored["category"] = "WAIT_MAINTAINER"
                scored["gate_decision"] = "HUMAN_REVIEW"
                scored["auto_spawn"] = False
                scored["risk"] = f"{scored['risk']}；{related_issue_assessment['summary']}"
                scored["next_step"] = (
                    "先人工比较相关 issue 的根因、维护者归并方向和可提交代码路径；"
                    "确认不是重复后再进入实现。"
                    if related_issue_assessment["status"] == "potential_overlap"
                    else "相关 issue 审计失败；恢复审计并确认无重复后再进入实现。"
                )
            pr_assessment = self.assess_open_prs(
                base["repo"],
                base["num"],
                issue.get("title") or base["title"],
                issue_context,
            )
            # Persist a successful negative duplicate check as evidence. Omitting
            # status=none makes the downstream policy correctly treat the audit as
            # missing, which would hold every otherwise-clean candidate forever.
            scored["open_pr_assessment"] = pr_assessment
            if pr_assessment["status"] in {"covered_strong", "competition_saturated"}:
                rejection_reason = (
                    "open_pr_strong"
                    if pr_assessment["status"] == "covered_strong"
                    else "open_pr_competition_saturated"
                )
                reject(rejection_reason, base)
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": f"skip_{rejection_reason}",
                    "title": issue.get("title") or base["title"],
                    "pr": pr_assessment.get("best_url"),
                    "pr_assessment": pr_assessment.get("summary"),
                    "issue_updated": issue.get("updated_at") or base.get("updated") or "",
                }
                continue
            if pr_assessment["status"] == "lookup_failed":
                defer_evidence_lookup(base, issue, "open_pr_lookup_failed")
                continue
            elif pr_assessment["status"] == "weak_pr_competition_possible":
                scored["open_pr_assessment"] = pr_assessment
                if scored["bucket"] == "immediate":
                    scored["bucket"] = "competition"
                    scored["category"] = "PR_COMPETITION_OPPORTUNITY"
                    scored["gate_decision"] = "ALLOW_TO_WORK"
                    scored["auto_spawn"] = True
                    scored["why"] = (
                        f"{scored['why']}；已有 open PR 但证据/测试/活跃度不足，仍有竞争空间"
                    )
                    scored["risk"] = f"{scored['risk']}；需要先对比已有 PR，避免重复实现。"
                    scored["next_step"] = (
                        "先复现 issue，再逐项对比已有 PR 的缺口；只有能提供更小改动、更强测试或更完整边界覆盖时才开 PR。"
                    )
            elif pr_assessment["status"] == "human_review_required":
                scored["bucket"] = "needs_approval"
                scored["category"] = "WAIT_MAINTAINER"
                scored["gate_decision"] = "HUMAN_REVIEW"
                scored["auto_spawn"] = False
                scored["open_pr_assessment"] = pr_assessment
                scored["next_step"] = (
                    "已有 PR 但强度不足；先看维护者规则和 issue 讨论，必要时先请求确认方案或分配。"
                )
            elif pr_assessment["status"] == "semantic_overlap_requires_review":
                scored["open_pr_assessment"] = pr_assessment
                scored["bucket"] = "competition"
                scored["category"] = "PR_COMPETITION_OPPORTUNITY"
                scored["gate_decision"] = "HUMAN_REVIEW"
                scored["auto_spawn"] = False
                scored["why"] = f"{scored['why']}；已有 PR 与 issue 代码路径和关键语义重合"
                scored["risk"] = f"{scored['risk']}；现有 PR 可能已覆盖根因，需先比较实现边界。"
                scored["next_step"] = (
                    "先逐项对比已有 PR 的复现、根因、改动文件与测试；只有明确存在未覆盖路径时才继续。"
                )
            elif pr_assessment["status"] == "keyword_overlap_only":
                scored["open_pr_assessment"] = pr_assessment
                scored["bucket"] = "competition"
                scored["category"] = "PR_COMPETITION_OPPORTUNITY"
                scored["gate_decision"] = "HUMAN_REVIEW"
                scored["auto_spawn"] = False
                scored["why"] = f"{scored['why']}；存在未直接关联的关键词相似 PR"
                scored["risk"] = (
                    f"{scored['risk']}；存在未直接关联的关键词相似 PR，实施前需快速对比。"
                )
                scored["next_step"] = (
                    "先人工比较相似 PR 的根因、改动路径和测试；"
                    "确认没有覆盖后才能创建 issue 会话或实现。"
                )
            base_evidence = self.default_branch_evidence(base["repo"])
            actionability = scored.get("actionability_evidence") or {}
            issue_digest = sha256_json(
                {
                    "state": issue.get("state"),
                    "title": issue.get("title") or base.get("title"),
                    "body": issue.get("body") or "",
                    "updatedAt": issue.get("updated_at") or base.get("updated") or "",
                    "assignees": issue.get("assignees") or [],
                    "labels": issue.get("labels") or [],
                }
            )
            pre_task_evidence = {
                "schema": "pre_task_evidence_v1",
                "issue": {
                    "state": issue.get("state"),
                    "assignees": issue.get("assignees") or [],
                },
                "issueDigest": issue_digest,
                "baseSha": base_evidence.get("baseSha"),
                "defaultBranch": base_evidence.get("defaultBranch"),
                "baseLookupStatus": base_evidence.get("status"),
                "policy": {"status": policy},
                "assignmentRequired": policy
                in {"needs_assignment", "ai_disclosure_and_assignment"},
                "aiDisclosureConflict": policy
                in {"ai_disclosure_conflict", "ai_disclosure_and_assignment"},
                "codePathsPlan": actionability.get("code_anchors") or [],
                "reproductionPathPlan": bool(actionability.get("probe_ready")),
                "validationPathPlan": bool(scored.get("test_path")),
                "probeRequired": True,
                "matureRepository": base["repo"] in known
                or self.repo_quality(base["repo"], False)[0],
                "duplicate": pr_assessment,
                "duplicateStatus": pr_assessment.get("status"),
                "designDigest": sha256_json(
                    {
                        "needsConfirmation": actionability.get("needs_confirmation"),
                        "design": actionability.get("design_confirmation"),
                    }
                ),
                "assigneeDigest": sha256_json(issue.get("assignees") or []),
                "duplicateDigest": sha256_json(pr_assessment),
            }
            expected = {
                "baseSha": base.get("expected_base_sha") or base.get("expectedBaseSha"),
                "issueDigest": base.get("expected_issue_digest") or base.get("expectedIssueDigest"),
                "designDigest": base.get("expected_design_digest")
                or base.get("expectedDesignDigest"),
                "assigneeDigest": base.get("expected_assignee_digest")
                or base.get("expectedAssigneeDigest"),
                "duplicateDigest": base.get("expected_duplicate_digest")
                or base.get("expectedDuplicateDigest"),
            }
            scored["pre_task_evidence"] = pre_task_evidence
            scored["preTaskEvidence"] = pre_task_evidence
            scored["pre_task_gate"] = pre_task_gate(
                scored, pre_task_evidence, expected=expected, require_semantic=False
            )
            scored["preTaskGate"] = scored["pre_task_gate"]
            scored["ranking"] = rank_opportunity(
                scored,
                repository={"maturityScore": 8 if base["repo"] in known else 0},
            )
            demote_failed_pre_task_gate(scored, scored["pre_task_gate"])
            scored["_llm_context"] = {
                "issue_body": (issue.get("body") or "")[:16000],
                "recent_comments": [
                    {
                        "author": (comment.get("user") or {}).get("login")
                        or (comment.get("author") or {}).get("login")
                        or "unknown",
                        "association": comment.get("author_association")
                        or comment.get("authorAssociation")
                        or "",
                        "body": (comment.get("body") or "")[:4000],
                    }
                    for comment in comments[-8:]
                    if isinstance(comment, dict)
                ],
            }
            candidates.append(scored)
            self.issue_outcomes[key] = candidate_issue_outcome(scored)

        bucket_rank = {
            "immediate": 0,
            "competition": 1,
            "needs_approval": 2,
            "conflict": 3,
        }
        candidates.sort(
            key=lambda item: (
                bucket_rank.get(item["bucket"], 9),
                -item["score"],
                item["repo"],
            )
        )
        if deferred_bases:
            rejection_counts["inspection_budget_deferred"] += len(deferred_bases)
        if deadline_deferred_bases:
            rejection_counts["scan_deadline_deferred"] += len(deadline_deferred_bases)
        self.rejection_summary = dict(
            sorted(rejection_counts.items(), key=lambda row: (-row[1], row[0]))
        )
        self.rejection_examples = dict(rejection_examples)
        forced_candidates = [
            item
            for item in candidates
            if f"{item['repo']}#{item['num']}" in self.forced_recheck_keys
        ]
        regular_candidates = [
            item
            for item in candidates
            if f"{item['repo']}#{item['num']}" not in self.forced_recheck_keys
        ]
        algorithm_candidates = [
            item for item in regular_candidates if item.get("track") == LLM_ALGORITHM_TRACK
        ]
        agent_candidates = [
            item for item in regular_candidates if item.get("track") != LLM_ALGORITHM_TRACK
        ]
        selected_regular = [*algorithm_candidates[:3], *agent_candidates[:3]]
        selected_ids = {id(item) for item in selected_regular}
        remaining = [item for item in regular_candidates if id(item) not in selected_ids]
        selected_regular.extend(remaining[: max(0, 6 - len(selected_regular))])
        selected_ids = {id(item) for item in selected_regular}
        overflow_candidates = [item for item in regular_candidates if id(item) not in selected_ids]
        selected = [*forced_candidates, *selected_regular]
        selected.sort(
            key=lambda item: (
                bucket_rank.get(item["bucket"], 9),
                0 if item.get("track") == LLM_ALGORITHM_TRACK else 1,
                -item["score"],
                item["repo"],
            )
        )
        for candidate in overflow_candidates:
            defer(candidate, "candidate_overflow")
        if overflow_candidates:
            self.rejection_summary["candidate_overflow_deferred"] = len(overflow_candidates)
        self.deferred_rechecks_remaining = count_seen_rechecks(self.seen)
        return selected, len(bases), inspected

    def feishu_post(
        self, url: str, payload: dict[str, Any], token: str | None = None
    ) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        last_error: Exception | None = None
        for delay in FEISHU_RETRY_DELAYS_SECONDS:
            if delay:
                time.sleep(delay)
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json; charset=utf-8"},
            )
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req, timeout=18) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError:
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def card(self, candidates: list[dict[str, Any]]) -> dict[str, Any]:
        elements: list[dict[str, Any]] = []
        groups = [
            ("immediate", "🟢 可立即做"),
            ("competition", "🔵 已有 PR 但可竞争"),
            ("needs_approval", "🟡 需要先申请分配/维护者确认"),
            ("conflict", "⚠️ 规则冲突"),
        ]
        for bucket, title in groups:
            bucket_items = [candidate for candidate in candidates if candidate["bucket"] == bucket]
            if not bucket_items:
                continue
            elements.append({"tag": "div", "text": {"tag": "lark_md", "content": f"**{title}**"}})
            for candidate in bucket_items:
                content = (
                    f"**{candidate['repo']}#{candidate['num']}** "
                    f"[{candidate['title']}]({candidate['url']})\n"
                    f"赛道：{candidate.get('track', AGENT_INFRA_TRACK)} | "
                    f"类型：{candidate['category']} | Done-Gate：{candidate['gate_decision']}\n"
                    f"含金量分：{candidate['score']} | 难度：{candidate['difficulty']} | "
                    f"Impact：{candidate['impact']}\n"
                    f"为什么值得做：{candidate['why']}\n"
                    f"预计改动：{candidate['expected_changes']}\n"
                    f"复现/测试路径：{candidate['test_path']}\n"
                    f"风险：{candidate['risk']}\n"
                    f"下一步：{candidate['next_step']}\n"
                    f"建议角色和预计工时：{candidate['role_eta']}"
                )
                if candidate.get("open_pr_assessment"):
                    pr_assessment = candidate["open_pr_assessment"]
                    content += (
                        f"\n已有 PR 评估：{pr_assessment['summary']}\n"
                        f"最佳相关 PR：{pr_assessment.get('best_url')}"
                    )
                elements.append({"tag": "div", "text": {"tag": "lark_md", "content": content}})
                elements.append({"tag": "hr"})
        if elements and elements[-1].get("tag") == "hr":
            elements.pop()
        card = {
            "config": {"wide_screen_mode": True},
            "header": {
                "title": {"tag": "plain_text", "content": "OSS PR Opportunity Radar"},
                "template": "green",
            },
            "elements": elements,
        }
        json.loads(json.dumps(card, ensure_ascii=False))
        return card

    def send_feishu(self, candidates: list[dict[str, Any]]) -> tuple[bool, str | None]:
        if not candidates:
            return False, None
        if self.dry_run:
            return False, None
        app_id = os.environ.get("FEISHU_APP_ID")
        app_secret = os.environ.get("FEISHU_APP_SECRET")
        if not app_id or not app_secret:
            return False, "missing_feishu_env"
        try:
            token_resp = self.feishu_post(
                "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
                {"app_id": app_id, "app_secret": app_secret},
            )
            token = token_resp.get("tenant_access_token")
            if not token:
                return False, f"token_failed:{token_resp.get('code')}"
            resp = self.feishu_post(
                "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id",
                {
                    "receive_id": self.chat_id,
                    "msg_type": "interactive",
                    "content": json.dumps(self.card(candidates), ensure_ascii=False),
                },
                token,
            )
            if resp.get("code") == 0:
                return True, None
            text = "OSS PR Opportunity Radar\n" + "\n\n".join(
                f"{c['repo']}#{c['num']} {c['title']} {c['url']} score={c['score']}"
                for c in candidates
            )
            fallback = self.feishu_post(
                "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id",
                {
                    "receive_id": self.chat_id,
                    "msg_type": "text",
                    "content": json.dumps({"text": text}, ensure_ascii=False),
                },
                token,
            )
            if fallback.get("code") == 0:
                return True, None
            return False, f"send_failed:{resp.get('code')}/{fallback.get('code')}"
        except Exception as exc:  # pragma: no cover - operational fallback
            return False, f"{type(exc).__name__}:{str(exc)[:120]}"

    def run(self, scan_path: Path | None) -> dict[str, Any]:
        run_started = self.monotonic_fn()
        items = self.collect_items()
        collect_finished = self.monotonic_fn()
        shortlist_finished = collect_finished
        llm_finished = collect_finished
        if self.search_failed:
            candidates: list[dict[str, Any]] = []
            qualified_repos = 0
            inspected = 0
            sent = False
            send_error = (
                "github_secondary_rate_limit" if self.rate_limited else "github_search_incomplete"
            )
        else:
            candidates, qualified_repos, inspected = self.shortlist(items)
            shortlist_finished = self.monotonic_fn()
            evaluator = DeepSeekEvaluator.from_environment(BASE_DIR / "state" / "llm_cache.json")
            candidates = evaluator.evaluate_candidates(candidates)
            llm_finished = self.monotonic_fn()
            # The first pass pins deterministic evidence before semantic review.
            # Re-run the same gate after review so model uncertainty can only
            # remove eligibility, never manufacture it.
            for candidate in candidates:
                evidence = candidate.get("preTaskEvidence") or candidate.get("pre_task_evidence")
                previous_gate = candidate.get("preTaskGate") or candidate.get("pre_task_gate")
                if not isinstance(evidence, dict) or not isinstance(previous_gate, dict):
                    continue
                candidate["pre_task_gate"] = pre_task_gate(
                    candidate,
                    evidence,
                    expected=previous_gate.get("expected") or {},
                    require_semantic=True,
                )
                candidate["preTaskGate"] = candidate["pre_task_gate"]
                demote_failed_pre_task_gate(candidate, candidate["pre_task_gate"])
            phase3_candidates = any(
                isinstance(candidate, dict)
                and (
                    "preTaskGate" in candidate
                    or "pre_task_gate" in candidate
                    or "ranking" in candidate
                )
                for candidate in candidates
            )
            allocation = (
                allocate_capacity(
                    candidates,
                    capacity=int(
                        os.environ.get("RADAR_OPPORTUNITY_CAPACITY", OPPORTUNITY_CAPACITY)
                    ),
                    seed=str(self.analyzed),
                )
                if phase3_candidates
                else {
                    "schema": "opportunity_capacity_v1",
                    "seed": str(self.analyzed),
                    "capacity": 0,
                    "slots": {"mature": 0, "exploration": 0},
                    "mature": [],
                    "exploration": [],
                    "unused": {},
                    "selectedKeys": [],
                }
            )
            self.capacity_allocation = allocation
            selected_keys = set(allocation["selectedKeys"])
            selected_exploration = {
                f"{item.get('repo')}#{item.get('num')}" for item in allocation["exploration"]
            }
            for candidate in candidates if phase3_candidates else []:
                key = f"{candidate.get('repo')}#{candidate.get('num')}"
                if candidate.get("maturity") == "exploration":
                    candidate["capacityDisposition"] = (
                        "EXPLORATION_SELECTED"
                        if key in selected_exploration
                        else "EXPLORATION_UNUSED"
                    )
                    candidate["auto_spawn"] = False
                    candidate["notify"] = False
                elif key in selected_keys:
                    candidate["maturity"] = "mature"
                    candidate["capacityDisposition"] = "MATURE_SELECTED"
                else:
                    candidate["capacityDisposition"] = "MATURE_BUDGET_DEFERRED"
                    candidate["auto_spawn"] = False
                    candidate["notify"] = False
            for candidate in candidates:
                key = f"{candidate['repo']}#{candidate['num']}"
                self.issue_outcomes[key] = candidate_issue_outcome(candidate)
            for key, rejected in getattr(evaluator, "rejected_candidates", {}).items():
                candidate = rejected["candidate"]
                reason = rejected["reason"]
                review = rejected["review"]
                self.issue_outcomes[key] = {
                    "status": "rejected",
                    "reason": reason,
                    "classification": "scan_false_positive",
                }
                self.seen[key] = {
                    "analyzed": self.analyzed,
                    "status": reason,
                    "title": candidate.get("title") or key,
                    "url": candidate.get("url"),
                    "issue_updated": candidate.get("issue_updated") or "",
                    "llm_decision": review.get("decision"),
                    "llm_score": review.get("score"),
                }
                self.rejection_summary[reason] = int(self.rejection_summary.get(reason) or 0) + 1
            self.rejection_summary = dict(
                sorted(self.rejection_summary.items(), key=lambda row: (-row[1], row[0]))
            )
            notification_candidates = []
            for candidate in candidates:
                key = f"{candidate['repo']}#{candidate['num']}"
                if candidate.get("notify") is False:
                    review = candidate.get("llm_review") or {}
                    silent_status = (
                        "silent_exploration"
                        if candidate.get("maturity") == "exploration"
                        else "capacity_deferred"
                        if candidate.get("capacityDisposition") == "MATURE_BUDGET_DEFERRED"
                        else "semantic_review_retry"
                    )
                    self.seen[key] = {
                        "analyzed": self.analyzed,
                        "status": silent_status,
                        "reason": silent_status,
                        "requeued_at": self.analyzed,
                        "title": candidate.get("title") or key,
                        "url": candidate.get("url"),
                        "issue_updated": candidate.get("issue_updated") or "",
                        "llm_error_category": review.get("error_category") or review.get("status"),
                    }
                    continue
                digest = candidate_notification_digest(candidate)
                previous = self.seen.get(key)
                previous_digest = (
                    str(previous.get("notification_digest") or "")
                    if isinstance(previous, dict)
                    else ""
                )
                legacy_candidate = dict(candidate)
                if isinstance(previous, dict) and (
                    previous.get("notification_scanner_version") or previous.get("scanner_version")
                ):
                    legacy_candidate["scanner_version"] = (
                        previous.get("notification_scanner_version") or previous["scanner_version"]
                    )
                legacy_digest = candidate_notification_digest(
                    legacy_candidate,
                    bind_scanner_version=True,
                )
                candidate["notification_digest"] = digest
                candidate["notification_scanner_version"] = SCANNER_VERSION
                if (
                    isinstance(previous, dict)
                    and previous_digest
                    and previous_digest in {digest, legacy_digest}
                ):
                    origin_status = str(
                        previous.get("deferred_from_status") or previous.get("status") or ""
                    )
                    migrated = dict(previous)
                    migrated.update(
                        {
                            "analyzed": self.analyzed,
                            "status": (
                                origin_status
                                if origin_status in {"notified", "queued_outbox"}
                                else str(previous.get("status") or "notified")
                            ),
                            "score": candidate.get("score"),
                            "title": candidate.get("title"),
                            "url": candidate.get("url"),
                            "issue_updated": candidate.get("issue_updated") or "",
                            "notification_digest": digest,
                            "notification_scanner_version": SCANNER_VERSION,
                        }
                    )
                    for field in (
                        "defer_count",
                        "deferred_from_status",
                        "first_deferred_at",
                        "reason",
                        "requeue_reason",
                        "requeued_at",
                    ):
                        migrated.pop(field, None)
                    self.seen[key] = migrated
                    continue
                notification_candidates.append(candidate)
            sent, send_error = (
                self.send_feishu(notification_candidates) if self.notify else (False, None)
            )
        notify_finished = self.monotonic_fn()
        if self.search_failed:
            notification_candidates = []
        if sent:
            for candidate in notification_candidates:
                self.seen[f"{candidate['repo']}#{candidate['num']}"] = {
                    "analyzed": self.analyzed,
                    "notified": True,
                    "status": "notified",
                    "score": candidate["score"],
                    "title": candidate["title"],
                    "url": candidate["url"],
                    "issue_updated": candidate.get("issue_updated") or "",
                    "notification_digest": candidate["notification_digest"],
                    "notification_scanner_version": SCANNER_VERSION,
                }
        elif notification_candidates and send_error:
            for candidate in notification_candidates:
                self.seen[f"{candidate['repo']}#{candidate['num']}"] = {
                    "analyzed": self.analyzed,
                    "status": "send_failed",
                    "score": candidate["score"],
                    "title": candidate["title"],
                    "url": candidate["url"],
                    "issue_updated": candidate.get("issue_updated") or "",
                }
        elif not self.notify:
            for candidate in notification_candidates:
                self.seen[f"{candidate['repo']}#{candidate['num']}"] = {
                    "analyzed": self.analyzed,
                    "notified": False,
                    "status": "queued_outbox",
                    "score": candidate["score"],
                    "title": candidate["title"],
                    "url": candidate["url"],
                    "issue_updated": candidate.get("issue_updated") or "",
                    "notification_digest": candidate["notification_digest"],
                    "notification_scanner_version": SCANNER_VERSION,
                }

        for key, history in self.notification_history.items():
            entry = self.seen.get(key)
            if not isinstance(entry, dict) or entry.get("notification_digest"):
                continue
            entry["notification_digest"] = history["notification_digest"]
            if history.get("notification_scanner_version"):
                entry["notification_scanner_version"] = history["notification_scanner_version"]

        for candidate in candidates:
            evidence = candidate.get("preTaskEvidence") or candidate.get("pre_task_evidence")
            gate = candidate.get("preTaskGate") or candidate.get("pre_task_gate")
            if not isinstance(evidence, dict) or not isinstance(gate, dict):
                continue
            key = f"{candidate.get('repo')}#{candidate.get('num')}"
            entry = self.seen.setdefault(key, {})
            entry["pre_task_evidence"] = evidence
            entry["pre_task_gate"] = gate
            entry["base_sha"] = evidence.get("baseSha")
            entry["evidence_digest"] = gate.get("evidenceDigest")

        for entry in self.seen.values():
            if isinstance(entry, dict) and entry.get("analyzed") == self.analyzed:
                entry["scanner_version"] = SCANNER_VERSION
                entry["decision_contract_digest"] = decision_contract_digest()

        # LLM review and notification staging can resolve or create recheck states.
        # Report the durable state that is actually written, not the shortlist snapshot.
        self.deferred_rechecks_remaining = count_seen_rechecks(self.seen)
        atomic_write_json(self.seen_path, self.seen)
        self.persistent_repo_cache["updatedAt"] = self.analyzed
        atomic_write_json(self.repo_cache_path, self.persistent_repo_cache)
        self.issue_outcomes = controller_terminal_issue_outcomes(self.seen) | self.issue_outcomes
        auto_spawn_candidates = [
            candidate for candidate in candidates if candidate.get("auto_spawn")
        ]
        candidate_counts_by_track = dict(
            sorted(
                Counter(
                    str(candidate.get("track") or "unknown") for candidate in candidates
                ).items()
            )
        )
        auto_spawn_counts_by_track = dict(
            sorted(
                Counter(
                    str(candidate.get("track") or "unknown") for candidate in auto_spawn_candidates
                ).items()
            )
        )
        run_id = f"scan-{self.now.strftime('%Y%m%dT%H%M%SZ')}-{sha256_json({'since': self.since_str, 'items': sorted(items)})[:12]}"
        for candidate in candidates:
            candidate["schema_version"] = CANDIDATE_SCHEMA
            candidate["evidence_digest"] = sha256_json(
                {
                    "repo": candidate.get("repo"),
                    "num": candidate.get("num"),
                    "track": candidate.get("track"),
                    "issueUpdated": candidate.get("issue_updated"),
                    "labels": candidate.get("labels"),
                    "actionability": candidate.get("actionability_evidence"),
                    "algorithmEvidence": candidate.get("algorithm_evidence"),
                    "openPrAssessment": candidate.get("open_pr_assessment"),
                    "relatedIssueAssessment": candidate.get("related_issue_assessment"),
                }
            )
            candidate["policy_digest"] = sha256_json(
                {
                    "repo": candidate.get("repo"),
                    "submissionPolicy": candidate.get("submission_policy"),
                    "publicSubmissionAllowed": candidate.get("public_submission_allowed"),
                }
            )
        result = {
            "schema_version": SCAN_SCHEMA,
            "contract_digest": contract_digest(),
            "run_id": run_id,
            "profile": PROFILE,
            "tracks": list(SCAN_TRACKS),
            "scanner_version": SCANNER_VERSION,
            "now": self.analyzed,
            "since": self.since_str,
            "requested_window_hours": self.requested_window_hours,
            "effective_window_hours": self.window_hours,
            "last_successful_scan": self.last_successful_scan,
            "items": len(items),
            "scan_ok": not self.search_failed,
            "scan_error": None if not self.search_failed else send_error,
            "qualified_repos": qualified_repos,
            "inspected": inspected,
            "scan_deadline_reached": self.scan_deadline_reached,
            "deep_inspection_deadline_seconds": self.deep_inspection_deadline_seconds,
            "timings_seconds": {
                "collect": round(collect_finished - run_started, 3),
                "shortlist": round(shortlist_finished - collect_finished, 3),
                "llm": round(llm_finished - shortlist_finished, 3),
                "notify": round(notify_finished - llm_finished, 3),
                "total": round(notify_finished - run_started, 3),
            },
            "repository_activity": {
                "fixed_scope": sorted(ALL_SCAN_REPOS),
                "fixed_scope_by_domain": {
                    "agent_runtime": sorted(AGENT_RUNTIME_REPOS),
                    "agent_tooling": sorted(AGENT_TOOLING_REPOS),
                    "agent_platform": sorted(AGENT_PLATFORM_REPOS),
                    "inference_serving": sorted(INFERENCE_SERVING_REPOS),
                    "llm_post_training": sorted(LLM_POST_TRAINING_REPOS),
                    "llm_modeling_peft": sorted(LLM_MODELING_PEFT_REPOS),
                    "llm_distributed_training": sorted(LLM_DISTRIBUTED_TRAINING_REPOS),
                    "llm_evaluation": sorted(LLM_EVALUATION_REPOS),
                },
                "queried": sorted(self.queried_repos),
                "matched": sorted(self.matched_repos),
                "qualified": sorted(self.qualified_repo_names),
                "inspected": sorted(self.inspected_repo_names),
                "collection_failures": dict(sorted(self.collection_failures.items())),
                "dynamic_discovery_enabled": True,
                "scope_config_digest": scope_digest(),
            },
            "deferred_rechecks": {
                "queued_before": self.deferred_rechecks_before,
                "attempted": self.deferred_rechecks_attempted,
                "migration_selected": self.deferred_rechecks_migration_selected,
                "expired": self.deferred_rechecks_expired,
                "remaining": self.deferred_rechecks_remaining,
                "per_run_budget": RECHECK_INSPECTION_BUDGET,
                "cooldown_enabled": False,
            },
            "candidates": len(candidates),
            "sent": sent,
            "send_error": send_error,
            "notification_candidate_count": len(notification_candidates),
            "notification_suppressed_count": len(candidates) - len(notification_candidates),
            "notification_state_recovered": self.notification_state_recovered,
            "dry_run": self.dry_run,
            "notification_mode": "direct" if self.notify else "outbox",
            "auto_spawn_candidates": len(auto_spawn_candidates),
            "candidate_counts_by_track": candidate_counts_by_track,
            "auto_spawn_counts_by_track": auto_spawn_counts_by_track,
            "forced_recheck_results": {
                key: self.issue_outcomes.get(
                    key, {"status": "rejected", "reason": "inspection_budget_deferred"}
                )
                for key in sorted(self.forced_recheck_keys)
            },
            "issue_outcomes": self.issue_outcomes,
            "opportunity_budget": self.capacity_allocation,
            "silent_exploration": [
                {
                    "key": f"{item.get('repo')}#{item.get('num')}",
                    "maturity": item.get("maturity"),
                    "capacityDisposition": item.get("capacityDisposition"),
                    "ranking": item.get("ranking"),
                    "preTaskGate": item.get("preTaskGate"),
                }
                for item in candidates
                if item.get("maturity") == "exploration"
            ],
            "cohort_eligibility": {
                "horizonsDays": [14, 30, 60],
                "rightCensoredLabel": "censored",
                "selectionCount": len(allocation.get("mature") or []),
            },
            "rejection_summary": self.rejection_summary,
            "rejection_examples": self.rejection_examples,
            "titles": [
                (
                    c["repo"],
                    c["num"],
                    c["score"],
                    c.get("category"),
                    c.get("gate_decision"),
                )
                for c in candidates
            ],
            "auto_spawn_titles": [
                (
                    c["repo"],
                    c["num"],
                    c["score"],
                    c.get("category"),
                    c.get("gate_decision"),
                )
                for c in auto_spawn_candidates
            ],
        }
        report = {
            **result,
            "candidate_details": candidates,
            "errors": self.errors[:8],
        }
        report["snapshot_id"] = sha256_json(report)
        report["report_digest"] = sha256_json(report)
        managed = None
        if self.managed_ledger_path is not None:
            managed = ManagedAdapter(BASE_DIR, self.managed_ledger_path).record_scan_report(report)
        result["snapshot_id"] = report["snapshot_id"]
        result["report_digest"] = report["report_digest"]
        if managed is not None:
            result["managed_ledger"] = managed
        if scan_path:
            atomic_write_json(scan_path, report)
        return result


def parse_now(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--now", default=None)
    parser.add_argument("--window-hours", type=float, default=2.0)
    parser.add_argument("--seen", type=Path, default=DEFAULT_SEEN)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--pending-rechecks", type=Path, default=None)
    parser.add_argument("--repo-cache", type=Path, default=DEFAULT_REPO_CACHE)
    parser.add_argument("--controller-feedback", type=Path, default=DEFAULT_CONTROLLER_FEEDBACK)
    parser.add_argument("--max-backfill-hours", type=float, default=24.0)
    parser.add_argument("--chat-id", default=DEFAULT_CHAT_ID)
    parser.add_argument("--scan-out", type=Path, default=None)
    parser.add_argument("--ledger", type=Path, default=BASE_DIR / "state" / "radar_ledger.sqlite3")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-notify", action="store_true")
    args = parser.parse_args()

    now = parse_now(args.now)
    state = load_json(args.state, {})
    window_hours, last_success = effective_window_hours(
        now,
        args.window_hours,
        state,
        max(args.window_hours, args.max_backfill_hours),
    )
    radar = Radar(
        now,
        window_hours,
        args.seen,
        args.chat_id,
        dry_run=args.dry_run,
        requested_window_hours=args.window_hours,
        last_successful_scan=last_success,
        pending_rechecks=(load_json(args.pending_rechecks, {}) if args.pending_rechecks else {}),
        notify=not args.no_notify,
        repo_cache_path=args.repo_cache,
        controller_feedback_path=args.controller_feedback,
        managed_ledger_path=args.ledger,
    )
    result = radar.run(args.scan_out)
    next_state = dict(state) if isinstance(state, dict) else {}
    next_state.update(
        {
            "last_attempt": result["now"],
            "last_scan_ok": result["scan_ok"],
            "last_scan_error": result["scan_error"],
            "last_effective_window_hours": result["effective_window_hours"],
        }
    )
    if result["scan_ok"]:
        next_state["last_successful_scan"] = result["now"]
        next_state["last_successful_candidates"] = result["candidates"]
    atomic_write_json(args.state, next_state)
    print(json.dumps(add_chinese_explanations(result), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
