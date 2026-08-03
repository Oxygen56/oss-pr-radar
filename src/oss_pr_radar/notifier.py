"""Idempotent Feishu notification transport and concise lifecycle cards."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class NotificationError(RuntimeError):
    pass


def candidate_card(candidates: list[dict[str, Any]], *, title: str) -> dict[str, Any]:
    elements: list[dict[str, Any]] = []
    for candidate in candidates:
        relation = candidate.get("open_pr_assessment") or {}
        evidence = candidate.get("actionability_evidence") or {}
        lines = [
            f"**[{candidate['repo']}#{candidate['num']}]({candidate['url']}) {candidate['title']}**",
            f"建议：{candidate.get('category')} | 分数：{candidate.get('score')}",
            f"价值：{candidate.get('why') or '等待证据'}",
            f"改动：{candidate.get('expected_changes') or '尚未定位'}",
            f"验证：{candidate.get('test_path') or '尚未给出'}",
            f"风险：{candidate.get('risk') or '尚未识别'}",
            f"竞争：{relation.get('summary') or '未发现直接覆盖'}",
            f"下一步：{candidate.get('next_step') or '按贡献规则复核'}",
            f"证据：复现信号 {evidence.get('public_repro_signals', 0)}，根因信号 {bool(evidence.get('root_cause_signal'))}",
        ]
        elements.append(
            {
                "tag": "div",
                "text": {"tag": "lark_md", "content": "\n".join(lines)},
            }
        )
        elements.append({"tag": "hr"})
    if elements:
        elements.pop()
    card = {
        "config": {"wide_screen_mode": True},
        "header": {
            "title": {"tag": "plain_text", "content": title},
            "template": "green" if any(item.get("auto_spawn") for item in candidates) else "yellow",
        },
        "elements": elements,
    }
    json.loads(json.dumps(card, ensure_ascii=False))
    return card


@dataclass
class FeishuClient:
    app_id: str
    app_secret: str
    chat_id: str
    timeout: float = 20.0

    def _post(
        self, url: str, payload: dict[str, Any], *, token: str | None = None
    ) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                value = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise NotificationError(type(exc).__name__) from exc
        if not isinstance(value, dict):
            raise NotificationError("invalid Feishu response")
        return value

    def token(self) -> str:
        value = self._post(
            "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
            {"app_id": self.app_id, "app_secret": self.app_secret},
        )
        token = value.get("tenant_access_token")
        if not token:
            raise NotificationError(f"Feishu token failed: {value.get('code')}")
        return str(token)

    def send_card(
        self, card: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        value = self._post(
            "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id",
            {
                "receive_id": self.chat_id,
                "msg_type": "interactive",
                "content": json.dumps(card, ensure_ascii=False),
                "uuid": idempotency_key[:50],
            },
            token=self.token(),
        )
        if value.get("code") != 0:
            raise NotificationError(f"Feishu send failed: {value.get('code')}")
        return value
