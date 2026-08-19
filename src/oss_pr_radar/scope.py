"""Maintained, identity-checked OSS contribution scope configuration."""

from __future__ import annotations

from typing import Any

from .util import sha256_json

SCOPE_SCHEMA = "oss_contribution_scope_v1"

# This is an allowlist of official owner/repository identities, not a ranking
# override. Repository maturity and evidence are evaluated on every scan.
SCOPE_ENTRIES: tuple[dict[str, Any], ...] = (
    {"repo": "deepseek-ai/deepseek-harness", "domains": ("agent_runtime",)},
    {"repo": "bytedance/deer-flow", "domains": ("agent_runtime",)},
    {"repo": "modelscope/modelscope", "domains": ("agent_platform",)},
    {"repo": "modelscope/ms-agent", "domains": ("agent_runtime",)},
    {"repo": "alibaba/rtp-llm", "domains": ("inference_serving",)},
    {"repo": "alibaba/ROLL", "domains": ("llm_post_training",)},
    {"repo": "Tencent/WeKnora", "domains": ("agent_platform",)},
    {"repo": "TencentCloudADP/youtu-agent", "domains": ("agent_runtime",)},
    {"repo": "MoonshotAI/kimi-cli", "domains": ("agent_runtime",)},
    {"repo": "MiniMax-AI/Mini-Agent", "domains": ("agent_runtime",)},
)


def scope_entries() -> list[dict[str, Any]]:
    entries = [dict(entry) | {"domains": list(entry["domains"])} for entry in SCOPE_ENTRIES]
    identities = [str(entry["repo"]) for entry in entries]
    if len(identities) != len(set(identities)):
        raise ValueError("scope contains duplicate repository identities")
    for identity in identities:
        owner, separator, repo = identity.partition("/")
        if not separator or not owner or not repo or " " in identity:
            raise ValueError(f"invalid official repository identity: {identity}")
    return entries


def scope_digest() -> str:
    return sha256_json({"schema": SCOPE_SCHEMA, "entries": scope_entries()})


def scope_identity_set() -> set[str]:
    return {str(entry["repo"]) for entry in scope_entries()}
