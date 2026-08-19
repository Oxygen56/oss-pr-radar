"""User-facing War Room messages and safe public-reply defaults."""

from __future__ import annotations

from typing import Any

from .managed_lifecycle import REPLY_TEMPLATE_ID, public_reply_policy_digest
from .util import sha256_json

REPLY_MODES = ("DRAFT", "AUTO_REPLY_ALLOWED")
EVENT_BINDING_FIELDS = (
    "eventId",
    "candidateKey",
    "taskId",
    "attemptId",
    "title",
    "reason",
    "nextAction",
    "idempotencyKey",
    "card",
)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def user_message(*, bucket: str, title: str, evidence_level: str | None = None) -> dict[str, str]:
    """Return plain Simplified Chinese presentation text."""

    messages = {
        "DECISION_REQUIRED": ("需要你确认下一步。", "请确认处理方向或补充必要信息。"),
        "SYSTEM_PROCESSING": ("系统正在处理已记录事项。", "等待系统完成当前处理。"),
        "WAITING_EXTERNAL": ("正在等待外部检查或维护者反馈。", "等待外部结果后再继续。"),
        "PORTFOLIO_READY": ("已有可复核的变更与检查结果。", "请复核结果，再决定是否进入后续流程。"),
    }
    reason, next_action = messages.get(
        bucket,
        ("事项状态已记录。", "请查看事项并决定下一步。"),
    )
    return {
        "title": _text(title) or "未命名事项",
        "reason": reason,
        "evidenceLevel": _text(evidence_level) or "已记录",
        "nextAction": next_action,
    }


def reply_decision(
    *,
    proposed_body: str,
    managed_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility helper; automatic replies require explicit managed proof."""

    policy = managed_policy if isinstance(managed_policy, dict) else {}
    allowed = all(
        (
            policy.get("authenticationStatus") == "AUTHENTICATED",
            policy.get("authorizationStatus") == "AUTHORIZED",
            policy.get("deterministicMechanicalRequest") is True,
            policy.get("requestType") == "mechanical",
            bool(_text(policy.get("requestDigest"))),
            bool(_text(policy.get("policyDigest"))),
            policy.get("templateId") in {"mechanical_change_v1", "standard_mechanical_v1"},
            bool(_text(proposed_body)),
        )
    )
    return {
        "mode": "AUTO_REPLY_ALLOWED" if allowed else "DRAFT",
        "body": _text(proposed_body),
        "reason": "已证明是经过认证的确定性机械请求。"
        if allowed
        else "尚未证明请求同时满足认证、授权和确定性要求。",
        "policyDigest": _text(policy.get("policyDigest")),
    }


def build_public_reply(
    *,
    body: str,
    policy: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return DRAFT unless the current managed policy and evidence agree."""

    policy = policy if isinstance(policy, dict) else {}
    evidence = evidence if isinstance(evidence, dict) else {}
    allowed = all(
        (
            policy.get("fullyAuthenticated") is True,
            policy.get("maintainerAuthenticated") is True,
            policy.get("deterministicMechanicalRequest") is True,
            policy.get("policyDigest") == public_reply_policy_digest(),
            policy.get("templateId") == REPLY_TEMPLATE_ID,
            evidence.get("currentTaskEvidence") is True,
            evidence.get("currentChecksPassed") is True,
            evidence.get("validationCertificateValid") is True,
            evidence.get("headShaMatches") is True,
            bool(_text(body)),
        )
    )
    mode = "AUTO_REPLY_ALLOWED" if allowed else "DRAFT"
    return {
        "mode": mode,
        "body": body,
        "reason": "已核实的确定性机械请求"
        if allowed
        else "默认需要人工确认，尚未形成可自动发送的授权",
        "bodyDigest": sha256_json(body),
        "actionable": allowed,
        "policyDigest": policy.get("policyDigest") if allowed else "",
    }


def validate_reply_mode(reply: dict[str, Any]) -> None:
    if reply.get("mode") not in REPLY_MODES:
        raise ValueError("unsupported public reply mode")
    if (
        reply.get("mode") == "AUTO_REPLY_ALLOWED"
        and reply.get("policyDigest") != public_reply_policy_digest()
    ):
        raise ValueError("automatic reply requires the current managed policy digest")


def build_outbox(artifact: dict[str, Any], *, channel: str) -> dict[str, Any]:
    """Build an idempotent channel outbox from one validated artifact."""

    from .war_room_projection import validate_projection

    validate_projection(artifact)
    if channel not in {"feishu", "codex"}:
        raise ValueError("channel must be feishu or codex")
    events = [
        {
            "eventId": sha256_json(
                {
                    "channel": channel,
                    "candidate": item["candidateKey"],
                    "taskId": item["taskId"],
                    "title": item["title"],
                    "reason": item["reason"],
                    "nextAction": item["nextAction"],
                }
            ),
            "candidateKey": item["candidateKey"],
            "taskId": item["taskId"],
            "title": item["title"],
            "reason": item["reason"],
            "nextAction": item["nextAction"],
            "status": "PENDING",
            "idempotencyKey": sha256_json(
                {
                    "channel": channel,
                    "candidate": item["candidateKey"],
                    "taskId": item["taskId"],
                    "title": item["title"],
                    "reason": item["reason"],
                    "nextAction": item["nextAction"],
                }
            )[:50],
            "card": {
                "config": {"wide_screen_mode": True},
                "header": {
                    "title": {"tag": "plain_text", "content": item["title"]},
                    "template": "green",
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": (
                                f"**事项**：{item['title']}\n"
                                f"**原因**：{item['reason']}\n"
                                f"**下一步**：{item['nextAction']}"
                            ),
                        },
                    }
                ],
            },
        }
        for item in artifact["items"]
        if item["actionable"]
    ]
    for event in events:
        event["attemptId"] = sha256_json(
            {
                "channel": channel,
                "event": event["eventId"],
            }
        )
    return {
        "schema": "oss-pr-radar.war-room-outbox.v1",
        "channel": channel,
        "sourceArtifactDigest": artifact["artifactDigest"],
        "events": events,
    }


def event_binding(event: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable event/card payload derived from the artifact."""

    return {key: event.get(key) for key in EVENT_BINDING_FIELDS}


def canonical_event_digest(event: dict[str, Any]) -> str:
    """Digest only immutable event/card data, never mutable delivery state."""

    return sha256_json(event_binding(event))


def validate_outboxes(artifact: dict[str, Any], outboxes: dict[str, dict[str, Any]]) -> None:
    for channel in ("feishu", "codex"):
        expected = [
            event_binding(event)
            for event in build_outbox(artifact, channel=channel)["events"]
        ]
        outbox = outboxes.get(channel)
        if (
            not isinstance(outbox, dict)
            or outbox.get("sourceArtifactDigest") != artifact["artifactDigest"]
        ):
            raise ValueError("both channel outboxes must reference the same artifact")
        actual = [event_binding(item) for item in outbox.get("events") or []]
        if actual != expected:
            raise ValueError("channel outbox event/card binding does not match artifact")
