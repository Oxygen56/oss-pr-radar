#!/usr/bin/env python3
"""Verify, lease, prepare, and receipt local issue-task dispatches."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import html
import json
import os
import re
import selectors
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import tomllib
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic, sleep
from typing import Any, Callable

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.action_guard import (  # noqa: E402
    ledger_action_guard_root,
    opportunity_action_guard,
)
from oss_pr_radar.decision import authorize  # noqa: E402
from oss_pr_radar.dispatch import (  # noqa: E402
    DispatchSigner,
    SignatureError,
    canonical_prompt,
    superseded_scanner_revision_queue,
    verify_queue,
)
from oss_pr_radar.evidence import collect_evidence  # noqa: E402
from oss_pr_radar.github_client import GitHubClient, is_transient_github_error  # noqa: E402
from oss_pr_radar.independent_review import (  # noqa: E402
    controller_review_result,
    review_once,
)
from oss_pr_radar.ledger import (  # noqa: E402
    LedgerError,
    RadarLedger,
    bind_dispatched_recovery_prompt,
)
from oss_pr_radar.managed_adapter import (  # noqa: E402
    GitHubAbsenceQueries,
    ManagedAdapter,
)
from oss_pr_radar.managed_lifecycle import ManagedLedger  # noqa: E402
from oss_pr_radar.metrics import assess_submit_ready, rolling_quality  # noqa: E402
from oss_pr_radar.notifier import FeishuClient, NotificationError, candidate_card  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.opportunity import external_side_effect_allowed  # noqa: E402
from oss_pr_radar.policy import SCANNER_DECISION_REVISION, decision_contract_digest  # noqa: E402
from oss_pr_radar.publication import (  # noqa: E402
    broker_publication_request,
    public_branch_is_safe,
    public_text_is_safe,
    publication_evidence_from_request,
    request_publication,
)
from oss_pr_radar.release_binding import (  # noqa: E402
    bind_runtime,
    open_directory_handle,
    runtime_ledger_path,
    runtime_python,
)
from oss_pr_radar.repo_probe import (  # noqa: E402
    PATHS_VERIFIED,
    REPRODUCED_VALIDATED,
    attest_task_reproduction_result,
    rebind_probe_receipt,
    run_repo_probe,
    verify_probe_receipt,
)
from oss_pr_radar.target_branch import (  # noqa: E402
    TargetBranchError,
    resolve_target_base,
    validate_target_base,
)
from oss_pr_radar.util import (  # noqa: E402
    atomic_write_json,
    canonical_json,
    iso_z,
    parse_time,
    read_json,
    sha256_json,
)
from oss_pr_radar.war_room_messages import canonical_event_digest  # noqa: E402

STATE = ROOT / "state"
LEDGER_PATH = STATE / "radar_ledger.sqlite3"
THREAD_DB = Path.home() / ".codex" / "state_5.sqlite"
GITHUB_ROOT = Path.home() / "Documents" / "github"
WORKTREE_ROOT = Path.home() / ".codex" / "worktrees"
KEYCHAIN_SERVICE = "oss-pr-radar-dispatch"
DEFAULT_TASK_PROJECT_ID = os.environ.get(
    "RADAR_TASK_PROJECT_ID", "5e41d21c-cba3-4be0-9a02-7eef35b67625"
)
ISSUE_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
PULL_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$")
DELEGATED_INPUT = re.compile(r"<input>(.*?)</input>", re.DOTALL)
MAX_TITLE_CHARS = 59
TASK_PRIVATE_DIR = ".oss-pr-radar"
TASK_CONTEXT_SCHEMA = "radar-task-context-v1"
TASK_RESULT_SCHEMA = "radar-task-result-v1"
MAX_GITHUB_OWNER_CHARS = 39
MAX_GITHUB_REPOSITORY_CHARS = 100
MAX_GITHUB_ISSUE_NUMBER = 9_999_999_999
GITHUB_ID_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
ORPHAN_ABANDON_MIN_AGE_MINUTES = 70
PR_FOLLOWUP_ACTIVE_DEFERRAL_MINUTES = 30
PR_FOLLOWUP_ABANDON_MIN_AGE_MINUTES = 90
CLOUD_PR_FOLLOWUP_MAX_AGE_MINUTES = 150
APP_SERVER_WATCHDOG_INTERVAL_SECONDS = 5.0
APP_SERVER_WATCHDOG_STALE_SECONDS = 15.0
APP_SERVER_WATCHDOG_EXTERNAL_PROBE_SECONDS = 30.0
APP_SERVER_WATCHDOG_LIVE_PROBE_SECONDS = 60.0
APP_SERVER_WATCHDOG_LIVE_RETRY_SECONDS = 120.0
APP_SERVER_EVENT_DRAIN_SLICE_SECONDS = 1.0
APP_SERVER_TASK_TURN_MAX_SECONDS = 45 * 60.0
ROOT_THREAD_START_TIMEOUT_SECONDS = 60.0
ROOT_TURN_START_TIMEOUT_SECONDS = 45.0
ROOT_TASK_INDEX_WAIT_SECONDS = 30.0
ROOT_TASK_RECEIPT_MARGIN_SECONDS = 15.0
ROOT_TASK_RECEIPT_WAIT_SECONDS = (
    ROOT_THREAD_START_TIMEOUT_SECONDS
    + ROOT_TURN_START_TIMEOUT_SECONDS
    + ROOT_TASK_INDEX_WAIT_SECONDS
    + ROOT_TASK_RECEIPT_MARGIN_SECONDS
)
GITHUB_GIT_RETRY_DELAYS = (1.0, 3.0)
VALIDATION_PREFETCH_TIMEOUTS = {
    "cargo_locked_fetch": 300,
    "go_locked_download": 300,
    "uv_locked_sync": 600,
    "npm_locked_install": 600,
    "pnpm_locked_install": 600,
}
VALIDATION_POLICY_REVISION = "ci_delegation_v1"
TRANSIENT_PUBLICATION_AUDIT_REASONS = {
    "DCO_REVALIDATION_FAILED",
    "DEFAULT_BRANCH_UNKNOWN",
    "DIFF_REVALIDATION_FAILED",
    "EXISTING_PR_BASE_UNAVAILABLE",
    "EXISTING_PR_UNAVAILABLE",
    "LIVE_EVIDENCE_INCOMPLETE",
    "REPOSITORY_METADATA_UNAVAILABLE",
    "TARGET_BASE_UNAVAILABLE",
}
TERMINAL_PUBLICATION_BLOCK_REASONS = {
    "ACTIVE_OR_CONDITIONAL_CLAIM",
    "STRONG_EXISTING_PR",
}

PLAIN_LANGUAGE_STATUS_PROMPT = (
    "用户可见回复必须像普通进度通知，不要求用户理解 Git、CI 或项目内部实现。"
    "第一句按真实状态选择：处理中写‘正在处理，暂未创建 PR。’；修改和检查已完成写"
    "‘修改已完成，正在创建 PR。’；不值得继续写‘不建议创建 PR。’；必须等待外部决定写"
    "‘暂不创建 PR。’；只有拿到准确链接后才能写‘PR 已创建：<准确链接>’。"
    "随后最多四行，并固定使用‘这次在修’‘当前状态’‘下一步’，最后写用户是否需要操作。"
    "‘这次在修’用一句不超过三十个汉字的大白话说明用户会遇到什么，不能复述 issue 标题；"
    "‘当前状态’只说已确认、正在修改、本地检查已通过、修改已上传，或不值得继续；"
    "‘下一步’必须明确谁会做什么，例如‘系统会直接创建 PR’‘等待项目在线检查和维护者审阅’"
    "‘等待维护者确认后继续’或‘任务结束并自动归档’，不能只写‘继续处理’。"
    "没有用户专属操作时，最后单独写‘你无需操作。’"
    "不要在用户可见回复中提技能名或系统组件名，也不要使用‘外壳解析’‘直接执行边界’"
    "‘兼容输入’‘回归证据’‘远端环境’‘语义’等需要工程背景的表达。"
    "安全审查问题统一说‘发现一处可能引发错误执行的风险，正在修正’；"
    "本机不能完成的检查统一说‘项目的在线检查会继续完成’。"
    "不要罗列测试名称、测试数量、工具名称或构建产物；只说检查是否证明问题已修复、"
    "是否仍有真实失败。整轮默认不发送中间进度；只有运行超过十分钟且出现新的用户可感知结果时"
    "才允许发送一次。"
    "不要直播排查步骤、猜测、尝试过的方案或接下来准备查看什么。"
    "每次更新只说相对上次新增的用户可见变化，不重复播报未变状态。"
    "最终回复只回答五件事：PR 是否已创建、这次修什么、现在完成了什么、下一步由谁做、用户是否要操作。"
    "除非用户追问技术细节，不要展示内部字段名、真假值、阶段名、文件路径、提交哈希、"
    "分支名、命令行，或使用‘门禁’‘回执’‘结构化交接’‘自动复核’等内部术语。"
    "如果红色状态只是维护者尚未添加 CI 标签或批准运行，必须说‘等待维护者启动完整检查’，"
    "不得描述成代码测试失败。不要用‘问题’‘进展’‘还差’‘门禁’‘回执’‘发布队列’"
    "或其他内部汇报口吻。"
)
END_RESULT_TURN_PROMPT = (
    "写完有效结果后立即给出最终回复并结束本轮。不要等待或轮询系统复核、发布、"
    "在线检查、会话命名或归档；这些步骤只有在本轮结束后才能继续。"
)


def latest_agent_message(rollout_path: str | None, *, max_bytes: int = 2_000_000) -> str:
    """Return the newest visible assistant message from a task rollout."""

    if not rollout_path:
        return ""
    path = Path(rollout_path)
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            offset = max(0, size - max_bytes)
            handle.seek(offset)
            if offset:
                handle.readline()
            raw_lines = handle.readlines()
    except OSError:
        return ""

    latest = ""
    for raw in raw_lines:
        try:
            item = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        payload = item.get("payload") if isinstance(item, dict) else None
        if not isinstance(payload, dict):
            continue
        if item.get("type") == "event_msg" and payload.get("type") == "agent_message":
            message = payload.get("message")
            if isinstance(message, str) and message.strip():
                latest = message.strip()
            continue
        if (
            item.get("type") == "response_item"
            and payload.get("type") == "message"
            and payload.get("role") == "assistant"
        ):
            content = payload.get("content")
            if not isinstance(content, list):
                continue
            text = "".join(
                str(part.get("text") or "")
                for part in content
                if isinstance(part, dict) and part.get("type") == "output_text"
            ).strip()
            if text:
                latest = text
    return latest


def publication_feedback_prompt(*, pr_url: str, previous_message: str) -> str:
    """Build a no-work status turn after the controller has actually published a PR."""

    if not PULL_URL.fullmatch(pr_url):
        raise RuntimeError("publication feedback has an invalid PR URL")
    problem = "这个问题会影响正常使用。"
    match = re.search(
        r"(?m)^(?:-\s*)?(?:问题|这次在修|这次修复)：\s*(.+?)\s*$",
        previous_message,
    )
    if match:
        candidate = match.group(1).strip()
        if candidate and len(candidate) <= 30:
            problem = candidate
    reply = (
        f"PR 已创建：{pr_url}\n\n"
        f"这次修复：{problem}\n"
        "当前状态：修改已上传。\n"
        "下一步：等待项目在线检查和维护者审阅。\n"
        "你无需操作。"
    )
    return (
        "这是状态同步，不要读取文件、运行命令、修改内容或继续任务。"
        "请只原样回复下面内容，不要添加任何说明：\n\n"
        f"{reply}"
    )


def publication_feedback_materialized(rollout_path: str | None, pr_url: str) -> bool:
    """Require the visible assistant reply, not merely a started status turn."""

    if not PULL_URL.fullmatch(pr_url):
        return False
    message = latest_agent_message(rollout_path)
    first_line = message.splitlines()[0].strip() if message else ""
    return first_line == f"PR 已创建：{pr_url}"


def publication_feedback_link_visible(rollout_path: str | None, pr_url: str) -> bool:
    """Treat any already-visible exact PR link as sufficient for legacy reconciliation."""

    return bool(PULL_URL.fullmatch(pr_url) and pr_url in latest_agent_message(rollout_path))


class ValidationPrefetchError(RuntimeError):
    """A deterministic lockfile prefetch could not complete locally."""

    def __init__(self, failure: dict[str, Any]):
        super().__init__(str(failure.get("summary") or "validation prefetch failed"))
        self.failure = failure


class ValidationResultChanged(RuntimeError):
    """The queued validation result changed before it could be safely read."""

    def __init__(self, *, expected: str, observed: str):
        super().__init__("validation result changed after it was queued")
        self.expected = expected
        self.observed = observed


class MissingValidationResult(RuntimeError):
    """The validated task private directory exists but result.json does not."""


TITLE_PREFIXES = {
    "GO": "[有价值·处理中]",
    "AUDIT_NO_GO": "[无价值]",
    "VALIDATION_PENDING": "[有价值·检查中]",
    "FIX_READY": "[有价值·准备提交]",
    "PUBLICATION_REQUEST": "[有价值·准备提交]",
    "PR_OPEN": "[有价值·PR已开]",
    "MERGED": "[有价值·已合并]",
}
PR_STAGE_PRIORITY = {
    "PR_OPEN": 1,
    "CI_GREEN": 2,
    "MAINTAINER_ACCEPTED": 3,
    "MERGED": 4,
    "CLOSED": 4,
}
LOCAL_PR_ACTION_STAGES = {"VALIDATION_PENDING", "FIX_READY"}
TERMINAL_PR_STAGES = {"MERGED", "CLOSED"}
CONTROLLER_TERMINAL_STATUS = "controller_terminal"
CODEX_DECISION_BINDINGS_SCHEMA = "oss-pr-radar.codex-decision-bindings.v1"
CODEX_DECISION_FEEDBACK_SCHEMA = "oss-pr-radar.codex-decision-feedback.v1"
CODEX_DECISION_MAX_PER_CYCLE = 5
PUBLISHED_TASK_STAGES = {
    "PR_OPEN",
    "CI_GREEN",
    "MAINTAINER_ACCEPTED",
    "MERGED",
    "CLOSED",
}
LEGACY_RESULT_REQUIRES_MIGRATION = "LEGACY_RESULT_REQUIRES_MIGRATION"
PR_FOLLOWUP_REBIND_REQUIRED = "PR_FOLLOWUP_REBIND_REQUIRED"
IMMEDIATE_RECOVERY_ERROR_CODES = {
    "cyber_policy",
    "cyberPolicy",
    "internal_error",
    "internalServerError",
    "server_error",
    "serverOverloaded",
    "system_error",
    "unauthorized",
    "httpConnectionFailed",
    "responseStreamConnectionFailed",
    "responseStreamDisconnected",
    "responseTooManyFailedAttempts",
}
CODEX_USAGE_LIMIT_ERROR_CODE = "usage_limit_exceeded"
CODEX_USAGE_LIMIT_RESUME_RE = re.compile(r"\btry again at\s+(.+?)(?:\.|$)", re.IGNORECASE)


def benign_policy_recovery_prompt(issue_url: str) -> str:
    """Resume a false-positive policy interruption without inventing task details."""

    if not ISSUE_URL.fullmatch(issue_url):
        raise RuntimeError("policy recovery has an invalid issue URL")
    return (
        f"{issue_prompt(issue_url)}\n\n"
        "系统续跑：继续处理同一个开源软件 issue。读取当前任务上下文，保留现有工作树和"
        "已完成改动，从上次中断处继续完成离线测试、独立复核以及 Workspace Result "
        "Protocol 结构化交接；不要访问网络，不要执行公开操作。"
        + END_RESULT_TURN_PROMPT
        + PLAIN_LANGUAGE_STATUS_PROMPT
    )


VALIDATION_RECOVERY_PROMPT = (
    "系统续跑：继续验证同一个修复，你无需操作。不要创建新任务或重新实现。"
    "读取当前任务文件，只补仍缺少的验证；未完成的检查重新运行，不恢复旧进程。"
    "保持离线，不安装依赖，不请求权限，也不执行任何 GitHub 公开操作。"
    + END_RESULT_TURN_PROMPT
    + PLAIN_LANGUAGE_STATUS_PROMPT
)
DISPATCHED_RECOVERY_PROMPT_VERSION = "issue-bound-recovery-v1"


def _recovery_turn_prompt(candidate: dict[str, Any], terminal_error: dict[str, Any] | None) -> str:
    recovery_kind = str(
        candidate.get("recoveryKind")
        or (candidate.get("reservation") or {}).get("recoveryKind")
        or "DISPATCHED_TASK"
    )
    if recovery_kind == "VALIDATION_FOLLOWUP_RESULT":
        return VALIDATION_RECOVERY_PROMPT
    issue_url = str(candidate.get("issueUrl") or "")
    if not ISSUE_URL.fullmatch(issue_url):
        raise RuntimeError("task recovery has an invalid issue URL")
    if recovery_kind == "PR_FOLLOWUP_RESULT":
        return _pr_followup_prompt({"issueUrl": issue_url})
    if terminal_error and terminal_error.get("code") == "cyber_policy":
        return benign_policy_recovery_prompt(issue_url)
    return issue_prompt(issue_url)


def _dispatched_recovery_prompt_binding(prompt: str) -> tuple[str, str]:
    return (
        DISPATCHED_RECOVERY_PROMPT_VERSION,
        hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    )


def _verify_dispatched_recovery_prompt_binding(candidate: dict[str, Any], prompt: str) -> None:
    reservation = candidate.get("reservation") or {}
    expected_version = candidate.get("recoveryPromptVersion") or reservation.get(
        "recoveryPromptVersion"
    )
    expected_digest = candidate.get("recoveryPromptDigest") or reservation.get(
        "recoveryPromptDigest"
    )
    if expected_version is None and expected_digest is None:
        return
    version, digest = _dispatched_recovery_prompt_binding(prompt)
    if expected_version != version or expected_digest != digest:
        raise RuntimeError("recovery prompt binding mismatch")


issue_prompt = canonical_prompt


class TaskContextWorktreeUnavailable(RuntimeError):
    """A valid shared context whose controller-owned workspace no longer exists."""

    def __init__(
        self,
        context: dict[str, Any],
        reason: str = "TASK_WORKTREE_UNAVAILABLE",
    ):
        super().__init__(reason)
        self.context = context
        self.reason = reason


class PrFollowupSnapshotChanged(RuntimeError):
    """The live PR no longer matches the cloud snapshot being prepared."""

    def __init__(self, reason: str, **evidence: str):
        super().__init__(reason)
        self.reason = reason
        self.evidence = {key: value for key, value in evidence.items() if value}


def latest_thread_turn_state(rollout_path: str | None) -> dict[str, Any] | None:
    """Return the latest turn's terminal state without loading a large rollout."""

    if not rollout_path:
        return None
    path = Path(rollout_path)
    try:
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - 8 * 1024 * 1024))
            data = handle.read().decode("utf-8", errors="ignore")
    except OSError:
        return None
    for raw_line in reversed(data.splitlines()):
        if not any(
            marker in raw_line for marker in ('"task_complete"', '"turn_aborted"', '"turn_context"')
        ):
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if record.get("type") == "turn_context":
            return None
        payload = record.get("payload") or {}
        if record.get("type") != "event_msg":
            continue
        if payload.get("type") == "turn_aborted":
            return {
                "status": "interrupted",
                "code": "turn_interrupted",
                "message": str(payload.get("reason") or "interrupted")[:240],
                "turnId": str(payload.get("turn_id") or ""),
            }
        if payload.get("type") != "task_complete":
            continue
        error = payload.get("error")
        if not isinstance(error, dict):
            return {
                "status": "completed",
                "code": None,
                "message": "",
                "turnId": str(payload.get("turn_id") or ""),
            }
        error_info = error.get("codex_error_info")
        if isinstance(error_info, dict):
            code = str(next(iter(error_info), "system_error"))
        else:
            code = str(error_info or "system_error")
        return {
            "status": "failed",
            "code": code,
            "message": str(error.get("message") or "")[:240],
            "turnId": str(payload.get("turn_id") or ""),
        }
    return None


def _is_codex_usage_limit_state(turn_state: dict[str, Any] | None) -> bool:
    if not turn_state or turn_state.get("status") != "failed":
        return False
    code = str(turn_state.get("code") or "")
    message = str(turn_state.get("message") or "")
    return code == CODEX_USAGE_LIMIT_ERROR_CODE or "usage limit" in message.casefold()


def _codex_usage_limit_resume_after(message: str) -> str | None:
    match = CODEX_USAGE_LIMIT_RESUME_RE.search(message)
    return match.group(1).strip() if match else None


def _terminal_state_from_app_server_turn(turn: dict[str, Any]) -> dict[str, Any] | None:
    status = str(turn.get("status") or "")
    turn_id = str(turn.get("id") or "")
    if status == "completed":
        return {"status": "completed", "code": None, "message": "", "turnId": turn_id}
    if status == "interrupted":
        return {
            "status": "interrupted",
            "code": "turn_interrupted",
            "message": "interrupted",
            "turnId": turn_id,
        }
    if status != "failed":
        return None
    error = turn.get("error") if isinstance(turn.get("error"), dict) else {}
    error_info = error.get("codexErrorInfo") or error.get("codex_error_info")
    if isinstance(error_info, dict):
        code = str(next(iter(error_info), "system_error"))
    else:
        code = str(error_info or "system_error")
    return {
        "status": "failed",
        "code": code,
        "message": str(error.get("message") or "")[:240],
        "turnId": turn_id,
    }


def live_thread_turn_states(thread_ids: set[str]) -> dict[str, dict[str, Any]]:
    """Read terminal states from a separate app-server view of desktop tasks."""

    requested = sorted({str(item) for item in thread_ids if str(item)})
    executable = shutil.which("codex")
    if not requested or not executable:
        return {}
    try:
        process = subprocess.Popen(
            [
                executable,
                "app-server",
                "--disable",
                "recommended_plugins",
                "--disable",
                "remote_plugin",
                "--stdio",
            ],
            cwd=GITHUB_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except OSError:
        return {}
    try:
        if process.stdin is None or process.stdout is None:
            return {}
        request_threads = {index + 1: thread_id for index, thread_id in enumerate(requested)}
        requests = [
            {
                "id": 0,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "oss-pr-radar-watchdog", "version": "1.0"},
                    "capabilities": {"experimentalApi": True},
                },
            },
            *[
                {
                    "id": request_id,
                    "method": "thread/read",
                    "params": {"threadId": thread_id, "includeTurns": True},
                }
                for request_id, thread_id in request_threads.items()
            ],
        ]
        process.stdin.write(
            b"".join((json.dumps(item) + "\n").encode("utf-8") for item in requests)
        )
        process.stdin.flush()
        buffer = b""
        states: dict[str, dict[str, Any]] = {}
        pending = set(request_threads)
        deadline = monotonic() + 10
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while pending and monotonic() < deadline:
                ready = selector.select(max(0.0, deadline - monotonic()))
                if not ready:
                    break
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    try:
                        message = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    request_id = message.get("id")
                    if request_id not in pending:
                        continue
                    pending.remove(request_id)
                    if message.get("error"):
                        continue
                    thread = (message.get("result") or {}).get("thread") or {}
                    thread_id = request_threads[request_id]
                    if str(thread.get("id") or "") != thread_id:
                        continue
                    turns = [item for item in thread.get("turns") or [] if isinstance(item, dict)]
                    if not turns:
                        continue
                    state = _terminal_state_from_app_server_turn(turns[-1])
                    if state is not None:
                        states[thread_id] = state
        return states
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return {}
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def latest_terminal_thread_error(rollout_path: str | None) -> dict[str, Any] | None:
    """Return the latest turn's terminal failure for compatibility callers."""

    state = latest_thread_turn_state(rollout_path)
    if not state or state.get("status") not in {"failed", "interrupted"}:
        return None
    return state


def persisted_thread_turn_state(thread_id: str) -> dict[str, Any] | None:
    """Read a task terminal state without opening the task in another app-server."""

    try:
        connection = sqlite3.connect(THREAD_DB)
        row = connection.execute(
            "SELECT rollout_path FROM threads WHERE id=?", (thread_id,)
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        if "connection" in locals():
            connection.close()
    return latest_thread_turn_state(row[0] if row else None)


def thread_turn_materialized_after(rollout_path: str | None, reserved_at: str) -> tuple[bool, bool]:
    """Return whether a persisted turn started at or after a delivery reservation."""

    if not rollout_path:
        return False, False
    path = Path(rollout_path)
    try:
        threshold = parse_time(reserved_at)
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - 8 * 1024 * 1024))
            data = handle.read().decode("utf-8", errors="ignore")
    except (OSError, ValueError):
        return False, False
    for raw_line in data.splitlines():
        if '"turn_context"' not in raw_line:
            continue
        try:
            record = json.loads(raw_line)
            timestamp = record.get("timestamp")
            if (
                record.get("type") == "turn_context"
                and timestamp
                and parse_time(str(timestamp)) >= threshold
            ):
                return True, True
        except (json.JSONDecodeError, ValueError):
            continue
    return True, False


def thread_prompt_materialized_after(
    rollout_path: str | None, reserved_at: str, prompt: str
) -> tuple[bool, bool]:
    """Return whether the exact reserved prompt reached the target task."""

    if not rollout_path or not prompt:
        return False, False
    path = Path(rollout_path)
    try:
        threshold = parse_time(reserved_at)
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - 8 * 1024 * 1024))
            data = handle.read().decode("utf-8", errors="ignore")
    except (OSError, ValueError):
        return False, False
    expected_prompt = canonical_prompt(html.unescape(prompt)).strip()
    for raw_line in data.splitlines():
        try:
            record = json.loads(raw_line)
            timestamp = record.get("timestamp")
            if not timestamp or parse_time(str(timestamp)) < threshold:
                continue
            payload = record.get("payload") or {}
            texts: list[str] = []
            if (
                record.get("type") == "response_item"
                and payload.get("type") == "message"
                and payload.get("role") == "user"
            ):
                texts = [
                    str(item.get("text") or "")
                    for item in payload.get("content") or []
                    if isinstance(item, dict) and item.get("type") == "input_text"
                ]
            elif record.get("type") == "event_msg" and payload.get("type") == "user_message":
                texts = [str(payload.get("message") or "")]
            if any(
                canonical_prompt(html.unescape(text)).strip() == expected_prompt for text in texts
            ):
                return True, True
        except (json.JSONDecodeError, ValueError):
            continue
    return True, False


def _is_immediate_recovery(state: dict[str, Any] | None) -> bool:
    if not state:
        return False
    if state.get("status") == "interrupted":
        return True
    if state.get("status") != "failed":
        return False
    code = str(state.get("code") or "")
    if code in IMMEDIATE_RECOVERY_ERROR_CODES:
        return True
    message = str(state.get("message") or "").casefold()
    return code == "other" and any(
        marker in message
        for marker in (
            "403 forbidden",
            "access token could not be refreshed",
            "response stream",
            "connection failed",
        )
    )


def _ensure_private_task_root(*, create: bool) -> Path:
    """Create or validate the private shared root without following links."""

    github_fd, github_path = open_directory_handle(GITHUB_ROOT, label="GitHub root", create=create)
    private_fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            private_fd = os.open(TASK_PRIVATE_DIR, flags, dir_fd=github_fd)
        except FileNotFoundError:
            if not create:
                raise
            os.mkdir(TASK_PRIVATE_DIR, 0o700, dir_fd=github_fd)
            private_fd = os.open(TASK_PRIVATE_DIR, flags, dir_fd=github_fd)
        metadata = os.fstat(private_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RuntimeError("Radar private root is not a private directory")
        return github_path / TASK_PRIVATE_DIR
    finally:
        if private_fd >= 0:
            os.close(private_fd)
        os.close(github_fd)


def managed_worktree_root() -> Path:
    return _ensure_private_task_root(create=True) / "worktrees"


def shared_context_root() -> Path:
    return GITHUB_ROOT / TASK_PRIVATE_DIR / "task-contexts"


def shared_context_quarantine_root() -> Path:
    # Keep this lexical so open_directory_handle can reject a pre-existing
    # symlink instead of resolving it into an attacker-controlled directory.
    return GITHUB_ROOT / TASK_PRIVATE_DIR / "context-quarantine"


def managed_worktree_path(intent_id: str, repo: str) -> Path:
    safe_intent = re.sub(r"[^A-Za-z0-9._-]+", "-", intent_id).strip("-._")[:48]
    if not safe_intent:
        raise RuntimeError("intent id cannot form a managed worktree path")
    suffix = hashlib.sha256(intent_id.encode("utf-8")).hexdigest()[:10]
    repository = re.sub(r"[^A-Za-z0-9._-]+", "-", repo.rsplit("/", 1)[-1]).strip("-._")
    if not repository:
        raise RuntimeError("repository cannot form a managed worktree path")
    return managed_worktree_root() / f"{safe_intent}-{suffix}" / repository


def shared_context_path(issue_url: str) -> Path:
    return shared_context_root() / _canonical_shared_context_relative_path(issue_url)


def _legacy_shared_context_filename(issue_url: str) -> str:
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        raise RuntimeError("invalid issue URL")
    repo, number = match.groups()
    owner, repository = repo.split("/", 1)
    safe = "--".join(
        re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
        for value in (owner, repository, number)
    )
    return f"{safe}.json"


def _validated_context_identity(issue_url: str) -> tuple[str, str, str]:
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        raise RuntimeError("invalid issue URL")
    repo, number = match.groups()
    owner, repository = repo.split("/", 1)
    if (
        len(owner) > MAX_GITHUB_OWNER_CHARS
        or len(repository) > MAX_GITHUB_REPOSITORY_CHARS
        or not GITHUB_ID_SEGMENT.fullmatch(owner)
        or not GITHUB_ID_SEGMENT.fullmatch(repository)
    ):
        raise RuntimeError("GitHub repository identity exceeds v2 path limits")
    if not 1 <= int(number) <= MAX_GITHUB_ISSUE_NUMBER:
        raise RuntimeError("GitHub issue number exceeds v2 path limits")
    return owner, repository, number


def _context_segment_token(value: str) -> str:
    token = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
    if not token or len(token.encode("utf-8")) > 255:
        raise RuntimeError("context identity path segment exceeds filesystem limit")
    return token


def _decode_context_segment(token: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token) or len(token.encode("utf-8")) > 255:
        return None
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        value = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if _context_segment_token(value) != token:
        return None
    return value


def _canonical_shared_context_relative_path(issue_url: str) -> Path:
    owner, repository, number = _validated_context_identity(issue_url)
    return (
        Path("v2")
        / _context_segment_token(owner)
        / _context_segment_token(repository)
        / f"{number}.json"
    )


def _canonical_shared_context_filename(issue_url: str) -> str:
    """Return the bounded leaf name of the v2 path for compatibility callers."""

    return _canonical_shared_context_relative_path(issue_url).name


def _legacy_filename_is_unambiguous(filename: str) -> bool:
    match = re.fullmatch(r"(.+)--([1-9][0-9]*)\.json", filename)
    if match is None:
        return False
    owner_and_repo = match.group(1).split("--")
    return len(owner_and_repo) == 2 and all(
        re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in owner_and_repo
    )


def _legacy_filename_identity(filename: str) -> tuple[str, str, str] | None:
    if not _legacy_filename_is_unambiguous(filename):
        return None
    match = re.fullmatch(r"(.+)--([1-9][0-9]*)\.json", filename)
    if match is None:
        return None
    owner, repository = match.group(1).split("--")
    number = match.group(2)
    return owner, repository, number


def _shared_context_relative_path(path: Path) -> tuple[str, ...] | None:
    try:
        return tuple(path.relative_to(shared_context_root()).parts)
    except ValueError:
        return None


def _shared_context_path_identity(path: Path) -> tuple[str, str, str] | None:
    relative = _shared_context_relative_path(path)
    if relative is None:
        return None
    if len(relative) == 4 and relative[0] == "v2":
        owner = _decode_context_segment(relative[1])
        repository = _decode_context_segment(relative[2])
        match = re.fullmatch(r"([1-9][0-9]*)\.json", relative[3])
        if owner is None or repository is None or match is None:
            return None
        number = match.group(1)
        if (
            len(owner) > MAX_GITHUB_OWNER_CHARS
            or len(repository) > MAX_GITHUB_REPOSITORY_CHARS
            or not GITHUB_ID_SEGMENT.fullmatch(owner)
            or not GITHUB_ID_SEGMENT.fullmatch(repository)
            or int(number) > MAX_GITHUB_ISSUE_NUMBER
        ):
            return None
        return owner, repository, number
    if len(relative) == 1:
        return _legacy_filename_identity(relative[0])
    return None


def _shared_context_path_matches(path: Path, issue_url: str) -> bool:
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        return False
    repo, number = match.groups()
    owner, repository = repo.split("/", 1)
    expected = (owner, repository, number)
    identity = _shared_context_path_identity(path)
    return identity == expected and (
        path == shared_context_root() / _canonical_shared_context_relative_path(issue_url)
        or path == shared_context_root() / _legacy_shared_context_filename(issue_url)
    )


def _shared_context_filename_matches(filename: str, issue_url: str) -> bool:
    """Legacy compatibility wrapper for callers that only have a leaf name."""

    return filename == _legacy_shared_context_filename(issue_url)


def _open_shared_context_directory(*, create: bool) -> tuple[int, Path, list[int]]:
    """Open the private context root without following any path component."""

    github_fd, github_path = open_directory_handle(GITHUB_ROOT, label="GitHub root")
    handles = [github_fd]
    try:
        private_fd, private_path = _open_private_context_child(
            github_fd, github_path, TASK_PRIVATE_DIR, "Radar private root", create=create
        )
        handles.append(private_fd)
        context_fd, context_path = _open_private_context_child(
            private_fd,
            private_path,
            "task-contexts",
            "shared context root",
            create=create,
        )
        handles.append(context_fd)
        return context_fd, context_path, handles
    except Exception:
        for fd in reversed(handles):
            os.close(fd)
        raise


def _open_shared_context_quarantine_directory(*, create: bool) -> tuple[int, Path, list[int]]:
    """Open context-quarantine through the verified GitHub-root descriptor."""

    github_fd, github_path = open_directory_handle(GITHUB_ROOT, label="GitHub root", create=create)
    handles = [github_fd]
    try:
        private_fd, private_path = _open_private_context_child(
            github_fd, github_path, TASK_PRIVATE_DIR, "Radar private root", create=create
        )
        handles.append(private_fd)
        quarantine_fd, quarantine_path = _open_private_context_child(
            private_fd,
            private_path,
            "context-quarantine",
            "context quarantine root",
            create=create,
        )
        handles.append(quarantine_fd)
        return quarantine_fd, quarantine_path, handles
    except Exception:
        for fd in reversed(handles):
            os.close(fd)
        raise


def _open_private_context_child(
    parent_fd: int,
    parent_path: Path,
    name: str,
    label: str,
    *,
    create: bool,
) -> tuple[int, Path]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise RuntimeError(f"{label} name is invalid")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        fd = os.open(name, flags, dir_fd=parent_fd)
    metadata = os.fstat(fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(fd)
        raise RuntimeError(f"{label} is not a private directory")
    return fd, parent_path / name


def _open_shared_context_parent(issue_url: str, *, create: bool) -> tuple[int, Path, list[int]]:
    owner, repository, _number = _validated_context_identity(issue_url)
    context_fd, context_root, handles = _open_shared_context_directory(create=create)
    try:
        v2_fd, v2_path = _open_private_context_child(
            context_fd, context_root, "v2", "v2 context root", create=create
        )
        handles.append(v2_fd)
        owner_fd, owner_path = _open_private_context_child(
            v2_fd, v2_path, _context_segment_token(owner), "v2 owner directory", create=create
        )
        handles.append(owner_fd)
        repository_fd, repository_path = _open_private_context_child(
            owner_fd,
            owner_path,
            _context_segment_token(repository),
            "v2 repository directory",
            create=create,
        )
        handles.append(repository_fd)
        return repository_fd, repository_path, handles
    except Exception:
        for fd in reversed(handles):
            os.close(fd)
        raise


def _open_shared_context_parent_for_path(path: Path) -> tuple[int, Path, list[int], str]:
    relative = _shared_context_relative_path(path)
    if relative is None:
        raise RuntimeError("shared context path is outside the private root")
    context_fd, context_root, handles = _open_shared_context_directory(create=False)
    try:
        if len(relative) == 1:
            return context_fd, context_root, handles, relative[0]
        if len(relative) != 4 or relative[0] != "v2":
            raise RuntimeError("shared context path layout is invalid")
        v2_fd, v2_path = _open_private_context_child(
            context_fd, context_root, "v2", "v2 context root", create=False
        )
        handles.append(v2_fd)
        owner_fd, owner_path = _open_private_context_child(
            v2_fd, v2_path, relative[1], "v2 owner directory", create=False
        )
        handles.append(owner_fd)
        repository_fd, repository_path = _open_private_context_child(
            owner_fd, owner_path, relative[2], "v2 repository directory", create=False
        )
        handles.append(repository_fd)
        return repository_fd, repository_path, handles, relative[3]
    except Exception:
        for fd in reversed(handles):
            os.close(fd)
        raise


def _read_shared_context_file(path: Path) -> tuple[bytes, os.stat_result, Path]:
    parent_fd, parent_path, handles, leaf = _open_shared_context_parent_for_path(path)
    descriptor = -1
    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        first = os.fstat(descriptor)
        if (
            not stat.S_ISREG(first.st_mode)
            or first.st_uid != os.getuid()
            or stat.S_IMODE(first.st_mode) != 0o600
        ):
            raise RuntimeError("shared task context is not a private regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        second = os.fstat(descriptor)
        if (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns) != (
            second.st_dev,
            second.st_ino,
            second.st_size,
            second.st_mtime_ns,
            second.st_ctime_ns,
        ):
            raise RuntimeError("shared task context changed while reading")
        return b"".join(chunks), second, parent_path / leaf
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for fd in reversed(handles):
            os.close(fd)


def _list_shared_context_paths() -> list[Path]:
    """List legacy files and v2 files through private dirfds only."""

    context_fd, context_root, handles = _open_shared_context_directory(create=False)
    paths: list[Path] = []
    try:
        for name in sorted(os.listdir(context_fd)):
            if name.endswith(".json"):
                paths.append(context_root / name)
                continue
            if name != "v2":
                raise RuntimeError(f"unexpected shared context root entry: {name}")
            v2_fd, v2_path = _open_private_context_child(
                context_fd, context_root, name, "v2 context root", create=False
            )
            handles.append(v2_fd)
            for owner_token in sorted(os.listdir(v2_fd)):
                owner_fd, owner_path = _open_private_context_child(
                    v2_fd, v2_path, owner_token, "v2 owner directory", create=False
                )
                handles.append(owner_fd)
                for repository_token in sorted(os.listdir(owner_fd)):
                    repository_fd, repository_path = _open_private_context_child(
                        owner_fd,
                        owner_path,
                        repository_token,
                        "v2 repository directory",
                        create=False,
                    )
                    handles.append(repository_fd)
                    for leaf in sorted(os.listdir(repository_fd)):
                        paths.append(repository_path / leaf)
                    os.close(handles.pop())
                os.close(handles.pop())
            os.close(handles.pop())
        return paths
    finally:
        for fd in reversed(handles):
            os.close(fd)


class _SharedContextValidationError(RuntimeError):
    def __init__(self, message: str, *, raw: bytes, source_stat: os.stat_result, source_path: Path):
        super().__init__(message)
        self.raw = raw
        self.source_stat = source_stat
        self.source_path = source_path


def _deduplicate_shared_context_paths(
    paths: list[Path],
) -> tuple[list[Path], list[dict[str, str] | _SharedContextValidationError]]:
    """Prefer identical canonical v2 bytes; reject legacy/v2 conflicts."""

    grouped: dict[tuple[str, str, str], list[Path]] = {}
    unbound: list[Path] = []
    for path in paths:
        identity = _shared_context_path_identity(path)
        if identity is None:
            unbound.append(path)
        else:
            grouped.setdefault(identity, []).append(path)
    selected = list(unbound)
    conflicts: list[dict[str, str] | _SharedContextValidationError] = []
    for _identity, candidates in grouped.items():
        if len(candidates) == 1:
            selected.append(candidates[0])
            continue
        observations: list[tuple[Path, bytes, os.stat_result]] = []
        for path in candidates:
            try:
                raw, source_stat, secure_path = _read_shared_context_file(path)
            except (OSError, RuntimeError) as exc:
                conflicts.append(
                    {
                        "path": str(path),
                        "error": f"duplicate context cannot be read safely: {str(exc)[:240]}",
                    }
                )
                observations = []
                break
            observations.append((secure_path, raw, source_stat))
        if not observations:
            continue

        def comparable(raw: bytes) -> str | bytes:
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return raw
            if not isinstance(value, dict):
                return raw
            value = dict(value)
            # The two trusted layouts necessarily have different bootstrap
            # paths; all authenticated task content must otherwise agree.
            value.pop("bootstrapContextPath", None)
            return canonical_json(value)

        if len({comparable(raw) for _path, raw, _source_stat in observations}) != 1:
            for path, raw, source_stat in observations:
                conflicts.append(
                    _SharedContextValidationError(
                        "legacy and v2 context bytes conflict for one identity",
                        raw=raw,
                        source_stat=source_stat,
                        source_path=path,
                    )
                )
            continue
        canonical = [
            path
            for path, _raw, _source_stat in observations
            if _shared_context_relative_path(path)
            and _shared_context_relative_path(path)[0] == "v2"
        ]
        selected.append(canonical[0] if canonical else candidates[0])
    return sorted(selected), conflicts


def _is_within(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    resolved_root = root.resolve()
    return resolved != resolved_root and resolved_root in resolved.parents


def _is_managed_worktree(path: Path) -> bool:
    return _is_within(path, managed_worktree_root())


def _rebind_quarantine_location(candidate: dict[str, Any], expected: Path) -> tuple[Path, Path]:
    """Return the deterministic private directory and marker for one rebind."""

    identity = canonical_json(
        {
            "key": str(candidate.get("key") or ""),
            "repo": str(candidate.get("repo") or ""),
            "intentId": str(candidate.get("intentId") or ""),
            "worktreePath": str(expected),
        }
    )
    token = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    safe_key = re.sub(r"[^A-Za-z0-9._-]+", "-", str(candidate["key"])).strip("-._")
    parent = managed_worktree_root() / ".rebind-quarantine" / f"{safe_key}-{token}"
    return parent / expected.name, parent / "rebind-intent.json"


def _write_rebind_marker(path: Path, value: dict[str, Any]) -> None:
    """Persist the move intent before changing Git's worktree registry."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        payload = (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_rebind_marker(
    path: Path, *, candidate: dict[str, Any], expected: Path, destination: Path
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError("rebind intent marker is not private")
    try:
        marker = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("rebind intent marker is invalid") from exc
    expected_fields = {
        "schema": "oss-pr-radar.rebind-intent.v1",
        "candidateKey": str(candidate["key"]),
        "repo": str(candidate["repo"]),
        "intentId": str(candidate["intentId"]),
        "expectedWorktreePath": str(expected),
        "quarantinePath": str(destination),
    }
    if not isinstance(marker, dict) or any(
        marker.get(key) != value for key, value in expected_fields.items()
    ):
        raise RuntimeError("rebind intent marker binding is invalid")
    return marker


def _remove_rebind_marker(path: Path) -> None:
    try:
        path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        path.parent.rmdir()
    except FileNotFoundError:
        return
    except OSError:
        # The database binding is authoritative after it commits.  Leaving a
        # verified marker is safer than failing a successful rebind on cleanup.
        return


def command(
    args: list[str],
    cwd: Path | None = None,
    timeout: int = 300,
    stdin: str | None = None,
) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        input=stdin,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "command failed")[:800])
    return completed.stdout.strip()


def github_git_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
    before_retry: Callable[[], None] | None = None,
) -> str:
    """Retry bounded GitHub git transport failures without hiding hard errors."""

    for attempt in range(len(GITHUB_GIT_RETRY_DELAYS) + 1):
        try:
            return command(args, cwd=cwd, timeout=timeout)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            if attempt >= len(GITHUB_GIT_RETRY_DELAYS) or not is_transient_github_error(exc):
                raise
            if before_retry is not None:
                before_retry()
            sleep(GITHUB_GIT_RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def signing_key() -> str:
    value = os.environ.get("RADAR_DISPATCH_HMAC_KEY")
    if value:
        return value
    if sys.platform == "darwin":
        try:
            return command(
                ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
                timeout=15,
            )
        except RuntimeError:
            pass
    raise RuntimeError("dispatch signing key is not configured")


def normalize_origin(value: str) -> str:
    normalized = value.strip().removesuffix(".git")
    for prefix in (
        "https://github.com/",
        "git@github.com:",
        "ssh://git@github.com/",
    ):
        if normalized.lower().startswith(prefix):
            return normalized[len(prefix) :].strip("/").casefold()
    return ""


def compact_title(value: str) -> str:
    return value if len(value) <= MAX_TITLE_CHARS else value[: MAX_TITLE_CHARS - 1] + "…"


def lifecycle_title(state: str, title_time: str, key: str, title: str) -> str:
    prefix = TITLE_PREFIXES.get(state)
    if not prefix:
        raise RuntimeError("unsupported title state")
    return compact_title(f"{prefix} {title_time} {key} {title}")


def canonical_prompt(value: str) -> str:
    match = DELEGATED_INPUT.search(value)
    return (match.group(1) if match else value).strip()


def quiet_command(args: list[str], *, cwd: Path, timeout: int = 300) -> None:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or "command failed")[:800])


def _target_ref(path: Path, target_base: dict[str, Any] | None = None) -> str:
    if target_base is not None:
        target = validate_target_base(target_base)
        return f"refs/remotes/origin/{target['branch']}"
    return command(
        ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=path,
        timeout=15,
    )


def prewarm_source_repo(path: Path, target_base: dict[str, Any] | None = None) -> None:
    """Make the selected branch snapshot locally checkout-ready for Codex."""

    command(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=path,
        timeout=60,
    )
    selected_ref = _target_ref(path, target_base)
    quiet_command(
        ["git", "archive", "--format=tar", selected_ref],
        cwd=path,
        timeout=600,
    )


def fetch_default_branch(path: Path) -> None:
    """Refresh only the branch used to seed managed task worktrees."""

    default_ref = command(
        ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=path,
        timeout=15,
    )
    prefix = "refs/remotes/origin/"
    if not default_ref.startswith(prefix):
        raise RuntimeError("origin/HEAD does not target an origin branch")
    branch = default_ref.removeprefix(prefix)
    if not branch or branch == "HEAD":
        raise RuntimeError("origin/HEAD does not name a default branch")
    github_git_command(
        [
            "git",
            "fetch",
            "--no-write-fetch-head",
            "--no-tags",
            "--filter=blob:none",
            "origin",
            f"+refs/heads/{branch}:{default_ref}",
        ],
        cwd=path,
        timeout=180,
    )


def fetch_target_branch(
    path: Path,
    target_base: dict[str, Any] | None = None,
    *,
    depth_one: bool = False,
) -> None:
    """Refresh and verify the exact branch snapshot selected during live audit."""

    if target_base is None:
        fetch_default_branch(path)
        return
    target = validate_target_base(target_base)
    tracking_ref = f"refs/remotes/origin/{target['branch']}"
    fetch_args = ["git", "fetch"]
    if depth_one:
        fetch_args.append("--depth=1")
    fetch_args.extend(
        [
            "--no-tags",
            "--filter=blob:none",
            "origin",
            f"+refs/heads/{target['branch']}:{tracking_ref}",
        ]
    )
    github_git_command(fetch_args, cwd=path, timeout=180)
    fetched_sha = command(["git", "rev-parse", "--verify", tracking_ref], cwd=path)
    if fetched_sha.casefold() != target["sha"]:
        raise RuntimeError("target branch changed after live audit")


def source_repo(repo: str, *, target_base: dict[str, Any] | None = None) -> Path:
    GITHUB_ROOT.mkdir(parents=True, exist_ok=True)
    for path in sorted(GITHUB_ROOT.iterdir()):
        # A .git file marks a linked worktree. Using one as the reusable source
        # makes the reported source path disagree with the repository that owns
        # any newly-created worktree, and can also touch an unrelated task.
        if not path.is_dir() or not (path / ".git").is_dir():
            continue
        try:
            origin = command(["git", "remote", "get-url", "origin"], cwd=path, timeout=15)
        except RuntimeError:
            continue
        if normalize_origin(origin) == repo.casefold():
            fetch_target_branch(path, target_base)
            resolved = path.resolve()
            if target_base is None:
                prewarm_source_repo(resolved)
            else:
                prewarm_source_repo(resolved, target_base)
            return resolved
    destination = GITHUB_ROOT / repo.rsplit("/", 1)[1]
    if destination.exists():
        destination = GITHUB_ROOT / repo.replace("/", "--")
    clone_target = destination.with_name(f".{destination.name}.radar-clone-{os.getpid()}")
    try:
        clone_args = [
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "--filter=blob:none",
        ]
        if target_base is not None:
            clone_args.extend(["--branch", validate_target_base(target_base)["defaultBranch"]])
        clone_args.extend([f"https://github.com/{repo}.git", str(clone_target)])
        github_git_command(
            clone_args,
            timeout=180,
            before_retry=lambda: shutil.rmtree(clone_target, ignore_errors=True),
        )
        if destination.exists():
            shutil.rmtree(clone_target, ignore_errors=True)
            return source_repo(repo, target_base=target_base)
        clone_target.replace(destination)
    except Exception:
        shutil.rmtree(clone_target, ignore_errors=True)
        raise
    resolved = destination.resolve()
    if target_base is None:
        prewarm_source_repo(resolved)
    else:
        fetch_target_branch(resolved, target_base, depth_one=True)
        prewarm_source_repo(resolved, target_base)
    return resolved


def _worktree_belongs_to_source(worktree: Path, source: Path) -> bool:
    try:
        return git_path(
            "rev-parse", "--path-format=absolute", "--git-common-dir", cwd=worktree
        ) == git_path("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=source)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


def prepare_managed_worktree(
    source: Path,
    *,
    intent_id: str,
    repo: str,
    target_base: dict[str, Any] | None = None,
) -> Path:
    """Create an isolated source checkout inside the broad GitHub project."""

    worktree = managed_worktree_path(intent_id, repo)
    selected_ref = _target_ref(source, target_base)
    selected_sha = command(["git", "rev-parse", "--verify", selected_ref], cwd=source)
    if (
        target_base is not None
        and selected_sha.casefold() != validate_target_base(target_base)["sha"]
    ):
        raise RuntimeError("prepared target branch does not match live audit")
    if worktree.exists():
        if not _worktree_belongs_to_source(worktree, source):
            raise RuntimeError("managed worktree does not belong to source repository")
        if command(["git", "status", "--porcelain"], cwd=worktree):
            raise RuntimeError("managed worktree is not clean before dispatch")
        command(["git", "switch", "--detach", selected_sha], cwd=worktree, timeout=180)
    else:
        worktree.parent.mkdir(parents=True, exist_ok=True)
        try:
            command(
                ["git", "worktree", "add", "--detach", str(worktree), selected_sha],
                cwd=source,
                timeout=600,
            )
        except Exception:
            shutil.rmtree(worktree.parent, ignore_errors=True)
            raise
    if not _worktree_belongs_to_source(worktree, source):
        try:
            quiet_command(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=source,
                timeout=60,
            )
        except RuntimeError:
            shutil.rmtree(worktree.parent, ignore_errors=True)
        raise RuntimeError("managed worktree does not belong to source repository")
    _exclude_private_task_dir(worktree)
    return worktree.resolve()


def fetch_cloud_queue() -> dict[str, Any]:
    ref = "refs/radar/import/radar-state"
    command(
        ["git", "fetch", "--no-write-fetch-head", "origin", f"+radar-state:{ref}"],
        cwd=ROOT,
    )
    raw = command(["git", "show", f"{ref}:dispatch_queue.json"], cwd=ROOT)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("invalid cloud queue")
    return value


def fetch_cloud_codex_outbox() -> dict[str, Any] | None:
    """Read the durable Codex outbox only after checking the state manifest."""

    ref = "refs/radar/import/radar-state"
    fetched = subprocess.run(
        [
            "git",
            "fetch",
            "--no-write-fetch-head",
            "origin",
            f"+radar-state:{ref}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            (fetched.stderr or fetched.stdout or b"radar-state fetch failed")[:300].decode(
                "utf-8", errors="replace"
            )
        )

    def show(name: str, *, allow_missing: bool = False) -> bytes | None:
        completed = subprocess.run(
            ["git", "show", f"{ref}:{name}"],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        if completed.returncode == 0:
            return completed.stdout
        if allow_missing:
            return None
        raise RuntimeError(f"radar-state file is missing: {name}")

    manifest_raw = show("state_manifest.json")
    assert manifest_raw is not None
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("radar-state manifest is invalid") from exc
    if manifest.get("version") != "radar_state_v2":
        raise RuntimeError("radar-state manifest version is unsupported")
    metadata = (manifest.get("files") or {}).get("war_room_codex_outbox.json")
    raw = show("war_room_codex_outbox.json", allow_missing=True)
    if metadata is None and raw is None:
        return None
    if not isinstance(metadata, dict) or raw is None:
        raise RuntimeError("Codex decision outbox is not bound by the state manifest")
    if hashlib.sha256(raw).hexdigest() != metadata.get("sha256"):
        raise RuntimeError("Codex decision outbox digest does not match the state manifest")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Codex decision outbox is invalid") from exc
    _validate_codex_decision_outbox(value)
    return value


def _validate_codex_decision_outbox(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or value.get("schema") != "oss-pr-radar.war-room-outbox.v1"
        or value.get("channel") != "codex"
        or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sourceArtifactDigest") or ""))
    ):
        raise RuntimeError("Codex decision outbox envelope is invalid")
    events = value.get("events")
    if not isinstance(events, list):
        raise RuntimeError("Codex decision outbox events are invalid")
    event_ids: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            raise RuntimeError("Codex decision outbox event is invalid")
        if event.get("status") != "PENDING":
            raise RuntimeError("Codex decision outbox event status is invalid")
        action_kind = str(event.get("actionKind") or "")
        if action_kind not in {"USER_DECISION", "MANAGED_TASK"}:
            raise RuntimeError("Codex decision outbox action is invalid")
        identity = {
            "channel": "codex",
            "candidate": event.get("candidateKey"),
            "taskId": event.get("taskId"),
            "actionKind": action_kind,
            "notificationDigest": event.get("notificationDigest"),
        }
        expected_id = sha256_json(identity)
        event_id = str(event.get("eventId") or "")
        if (
            event_id != expected_id
            or event.get("idempotencyKey") != expected_id[:50]
            or event.get("attemptId") != sha256_json({"channel": "codex", "event": expected_id})
            or event_id in event_ids
        ):
            raise RuntimeError("Codex decision outbox event identity is invalid")
        if not all(
            isinstance(event.get(name), str) and str(event[name]).strip()
            for name in ("candidateKey", "title", "reason", "nextAction")
        ):
            raise RuntimeError("Codex decision outbox display fields are invalid")
        if action_kind == "USER_DECISION" and (
            event.get("taskId") is not None
            or not re.fullmatch(r"[0-9a-f]{64}", str(event.get("notificationDigest") or ""))
        ):
            raise RuntimeError("Codex user-decision binding is invalid")
        if action_kind == "MANAGED_TASK" and not event.get("taskId"):
            raise RuntimeError("Codex managed-task binding is invalid")
        event_ids.add(event_id)


def fetch_cloud_pr_followup() -> dict[str, Any]:
    raw = command(["git", "show", "refs/radar/import/radar-state:pr_followup.json"], cwd=ROOT)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("invalid cloud PR follow-up state")
    digest = str(value.get("digest") or "")
    expected = sha256_json({key: item for key, item in value.items() if key != "digest"})
    if not digest or digest != expected:
        raise RuntimeError("cloud PR follow-up state digest mismatch")
    return value


def _record_superseded_dispatch_queue(
    queue: dict[str, Any],
    stale: dict[str, Any],
    path: Path = LEDGER_PATH,
    *,
    import_scope: str,
) -> dict[str, Any]:
    superseded = ledger(path).supersede_intents_for_scanner_revision(
        scanner_version=str(stale["scannerVersion"]),
        decision_contract_digest=str(stale["decisionContractDigest"]),
        contract_digest=str(stale["contractDigest"]),
        queue_digest=str(stale["queueDigest"]),
    )
    event = ManagedAdapter(ROOT, path).ledger.record_event(
        event_type="DISPATCH_QUEUE_REJECTED",
        idempotency_key=f"dispatch-queue:stale-scanner:{stale['queueDigest']}",
        state="SUPERSEDED",
        source="dispatch",
        provenance={"queueDigest": stale["queueDigest"]},
        observed_at=iso_z(datetime.now(UTC)),
        payload=stale,
    )
    return {
        "ok": True,
        "mode": queue.get("mode"),
        "verified": 0,
        "inserted": 0,
        "superseded": len(superseded),
        "staleTerminalRejected": 0,
        "staleQueueRejected": 1,
        "staleQueue": stale,
        "staleLocalIntentsSuperseded": superseded,
        "auditEventCreated": bool(event.get("created")),
        "importScope": import_scope,
    }


def _classify_superseded_dispatch_queue(
    queue: dict[str, Any], signer: DispatchSigner, error: SignatureError
) -> dict[str, Any]:
    if str(error) != "stale scanner decision revision":
        raise error
    stale = superseded_scanner_revision_queue(queue, signer)
    if stale is None:
        raise error
    return stale


def ledger(path: Path = LEDGER_PATH) -> RadarLedger:
    return RadarLedger(path)


def _task_context_digest_payload(
    context: dict[str, Any],
    prepared_head: str | None,
    *,
    include_target_base: bool = True,
    include_prepared_head: bool = True,
) -> dict[str, Any]:
    live_audit = context.get("liveAudit")
    if not isinstance(live_audit, dict) or not isinstance(live_audit.get("evidence"), dict):
        raise RuntimeError("task context live audit is invalid")
    payload = {
        "schemaVersion": TASK_CONTEXT_SCHEMA,
        "key": context.get("key"),
        "issueUrl": context.get("issueUrl"),
        "intentId": context.get("intentId"),
        "track": context.get("track"),
        "algorithmEvidence": context.get("algorithmEvidence"),
        "liveAuditDigest": live_audit["evidence"].get("digest"),
        "threadId": context.get("threadId"),
        "worktreePath": context.get("worktreePath"),
    }
    if include_target_base:
        payload["targetBase"] = context.get("targetBase")
    if include_prepared_head:
        payload["prFollowupPreparedHeadSha"] = prepared_head
    return payload


def _legacy_task_context_digest_allowed(context: dict[str, Any]) -> bool:
    if str(context.get("stage") or "") not in PUBLISHED_TASK_STAGES:
        return False
    # A non-null target is already part of the authenticated context format.
    # Never downgrade it to the pre-target digest, even for published history.
    if "targetBase" in context and context.get("targetBase") is not None:
        return False
    receipt = context.get("publicationReceipt")
    if not isinstance(receipt, dict) or not receipt.get("prUrl"):
        return False
    issue_match = ISSUE_URL.fullmatch(str(context.get("issueUrl") or ""))
    pull_match = PULL_URL.fullmatch(str(receipt.get("prUrl") or ""))
    if issue_match is None or pull_match is None:
        return False
    if pull_match.group(1).casefold() != issue_match.group(1).casefold():
        return False
    return re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("commitSha") or "")) is not None


def _task_context_digest_candidates(context: dict[str, Any], prepared_head: str | None) -> set[str]:
    candidates: set[str] = set()
    if "targetBase" in context:
        if context.get("targetBase") is not None:
            validate_target_base(context["targetBase"])
        candidates.update(
            {
                sha256_json(_task_context_digest_payload(context, prepared_head)),
                sha256_json(
                    _task_context_digest_payload(
                        context,
                        prepared_head,
                        include_prepared_head=False,
                    )
                ),
            }
        )
    if _legacy_task_context_digest_allowed(context):
        candidates.update(
            {
                sha256_json(
                    _task_context_digest_payload(
                        context,
                        prepared_head,
                        include_target_base=False,
                    )
                ),
                sha256_json(
                    _task_context_digest_payload(
                        context,
                        prepared_head,
                        include_target_base=False,
                        include_prepared_head=False,
                    )
                ),
            }
        )
    return candidates


def _legacy_result_context_digest_migration_allowed(
    value: dict[str, Any], context: dict[str, Any], prepared_head: str | None
) -> bool:
    """Allow only the exact result digest produced before target binding.

    The context must either omit targetBase or carry the historical
    targetBase:null form, and its current digest must be the canonical
    target-bound value for that representation. This is a narrow in-memory
    migration for results written during the context-format transition; it
    does not authorize an arbitrary result/context mismatch.
    """

    if str(context.get("stage") or "") in PUBLISHED_TASK_STAGES:
        return False
    # The legacy result format predates target binding.  It is valid only for
    # the historical null/missing-target representation; a real target must
    # never be silently downgraded during result ingestion.
    if "targetBase" in context and context.get("targetBase") is not None:
        return False
    if "targetBase" in context:
        if context.get("contextDigest") != _task_context_digest(context, prepared_head):
            return False
    elif context.get("contextDigest") != sha256_json(
        _task_context_digest_payload(
            context,
            prepared_head,
            include_target_base=False,
        )
    ):
        return False
    legacy_digests = {
        sha256_json(
            _task_context_digest_payload(
                context,
                prepared_head,
                include_target_base=False,
            )
        )
    }
    if prepared_head is None:
        legacy_digests.add(
            sha256_json(
                _task_context_digest_payload(
                    context,
                    prepared_head,
                    include_target_base=False,
                    include_prepared_head=False,
                )
            )
        )
    return value.get("contextDigest") in legacy_digests


def _controller_parent_drift(
    value: dict[str, Any], context: dict[str, Any]
) -> dict[str, str] | None:
    """Return task-local rebind evidence for a stale prepared follow-up.

    This is deliberately read-only.  It does not switch branches or alter the
    result; the ledger rebind is the only controller-owned recovery action.
    """

    if value.get("handoffMode") != "controller_commit_required":
        return None
    followup = context.get("prFollowup")
    if not isinstance(followup, dict):
        return None
    expected = str(followup.get("preparedHeadSha") or followup.get("headSha") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        return None
    worktree = Path(str(context.get("worktreePath") or "")).resolve()
    try:
        observed = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    except (OSError, RuntimeError):
        return None
    if observed == expected:
        return None
    return {
        "expectedPreparedHeadSha": expected,
        "observedHeadSha": observed,
    }


def _parent_drift_rebind_is_valid(
    value: dict[str, Any],
    context: dict[str, Any],
    *,
    candidate: dict[str, Any],
    task_stage: str,
    prepared_head: str | None,
    current_wake_digest: str,
    legacy_compatible_result: bool,
) -> bool:
    """Validate the complete task contract before changing the ledger.

    Rebinding is a controller-owned recovery mutation.  It is intentionally
    stricter than merely noticing a stale parent: the result must still be a
    current, authenticated implementation handoff for this exact task.
    """

    if task_stage != "IMPLEMENTATION_READY":
        return False
    if context.get("taskStage") != task_stage:
        return False
    if value.get("stage") != "FIX_READY":
        return False
    if value.get("handoffMode") != "controller_commit_required":
        return False
    if value.get("key") != candidate.get("key"):
        return False
    try:
        valid_context_digests = _task_context_digest_candidates(context, prepared_head)
    except (RuntimeError, ValueError, TypeError):
        return False
    if value.get("contextDigest") not in valid_context_digests:
        return False
    if isinstance(context.get("prFollowup"), dict):
        if not current_wake_digest:
            return False
        if not (value.get("followupDigest") == current_wake_digest or legacy_compatible_result):
            return False
    try:
        return _controller_policy_verification(context) is not None
    except (RuntimeError, ValueError, TypeError):
        return False


def _legacy_result_requires_migration(
    value: dict[str, Any],
    context: dict[str, Any],
    candidate: dict[str, Any],
    prepared_head: str | None,
    *,
    followup_digest_valid: bool,
) -> dict[str, str] | None:
    """Recognize old implementation results without authorizing them.

    Missing task state is a format migration boundary, not a reason to run or
    publish the result.  Classification requires the same identity, digest,
    clean-checkout and commit evidence used by normal ingestion; anything less
    remains an ordinary validation error.
    """

    if context.get("taskStage") is not None or context.get("probeLevel") is not None:
        return None
    if str(value.get("stage") or "") != "FIX_READY":
        return None
    if not (
        value.get("commitSha")
        or value.get("handoffMode")
        or value.get("publication")
        or value.get("changedFiles")
    ):
        return None
    current_digest = value.get("contextDigest") == context.get("contextDigest")
    legacy_digest = _legacy_result_context_digest_migration_allowed(value, context, prepared_head)
    if not current_digest and not legacy_digest:
        return None
    commit_sha = str(value.get("commitSha") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        return None
    worktree = Path(str(candidate.get("worktreePath") or "")).resolve()
    try:
        if command(["git", "rev-parse", "--show-toplevel"], cwd=worktree) != str(worktree):
            return None
        if command(["git", "status", "--porcelain"], cwd=worktree):
            return None
        if command(["git", "rev-parse", "HEAD"], cwd=worktree) != commit_sha:
            return None
    except (OSError, RuntimeError):
        return None
    return {
        "legacyDigest": "true" if legacy_digest else "false",
        "commitSha": commit_sha,
        "followupDigestValid": "true" if followup_digest_valid else "false",
    }


def _verified_shared_task_context(path: Path) -> tuple[dict[str, Any], str]:
    raw, source_stat, secure_path = _read_shared_context_file(path)
    try:
        return _verified_shared_task_context_from_raw(secure_path, raw, source_stat)
    except TaskContextWorktreeUnavailable:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise _SharedContextValidationError(
            str(exc), raw=raw, source_stat=source_stat, source_path=secure_path
        ) from exc


def _verified_shared_task_context_from_raw(
    path: Path, raw: bytes, source_stat: os.stat_result
) -> tuple[dict[str, Any], str]:
    try:
        context = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("shared task context is not valid JSON") from exc
    if not isinstance(context, dict) or context.get("schemaVersion") != TASK_CONTEXT_SCHEMA:
        raise RuntimeError("shared task context schema is invalid")

    issue_url = str(context.get("issueUrl") or "")
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        raise RuntimeError("shared task context issue URL is invalid")
    repo, issue_number = match.groups()
    if context.get("key") != f"{repo}#{issue_number}":
        raise RuntimeError("shared task context key does not match issue URL")
    if not _shared_context_path_matches(path, issue_url):
        raise RuntimeError("shared task context path does not match issue identity")
    bootstrap_path = Path(str(context.get("bootstrapContextPath") or ""))
    if (
        bootstrap_path != path
        or not bootstrap_path.is_absolute()
        or any(part == ".." for part in bootstrap_path.parts)
        or not _shared_context_path_matches(bootstrap_path, issue_url)
    ):
        raise RuntimeError("shared task context bootstrap path is invalid")

    for key, expected in {
        "controllerOwnsLifecycle": True,
        "controllerOwnsPublication": True,
        "controllerOwnsCommit": True,
        "externalLedgerAccessAllowed": False,
        "childMayRequestApproval": False,
        "childMayWriteGitMetadata": False,
    }.items():
        if context.get(key) is not expected:
            raise RuntimeError(f"shared task context controller boundary is invalid: {key}")
    live_audit = context.get("liveAudit")
    if not isinstance(live_audit, dict) or not isinstance(live_audit.get("evidence"), dict):
        raise RuntimeError("shared task context live audit is missing")
    evidence = live_audit["evidence"]
    audit_repo = str(evidence.get("repo") or "")
    if audit_repo and audit_repo.casefold() != repo.casefold():
        raise RuntimeError("shared task context audit repository is invalid")
    issue_snapshot = evidence.get("issue")
    if not isinstance(issue_snapshot, dict):
        raise RuntimeError("shared task context issue snapshot is missing")
    snapshot_number = issue_snapshot.get("number") or evidence.get("issue_number")
    if snapshot_number is not None and str(snapshot_number) != issue_number:
        raise RuntimeError("shared task context issue snapshot identity is invalid")
    receipt = context.get("publicationReceipt")
    if isinstance(receipt, dict) and receipt.get("prUrl"):
        pull_match = PULL_URL.fullmatch(str(receipt["prUrl"]))
        if pull_match is None or pull_match.group(1).casefold() != repo.casefold():
            raise RuntimeError("shared task context pull request identity is invalid")
        commit_sha = str(receipt.get("commitSha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            raise RuntimeError("shared task context publication commit is invalid")
    followup = context.get("prFollowup")
    prepared_head = (
        str(followup.get("preparedHeadSha"))
        if isinstance(followup, dict) and followup.get("preparedHeadSha")
        else None
    )
    if context.get("contextDigest") not in _task_context_digest_candidates(context, prepared_head):
        raise RuntimeError("shared task context digest mismatch")

    # Missing historical workspaces must not block unrelated live queue items.
    # The shared envelope has passed identity, boundary, receipt, and digest
    # checks before availability is classified here.
    worktree = Path(str(context.get("worktreePath") or "")).resolve()
    if not worktree.is_dir() or not _is_managed_worktree(worktree):
        raise TaskContextWorktreeUnavailable(context)
    local_path = worktree / TASK_PRIVATE_DIR / "task-context.json"
    if local_path.is_symlink() or not local_path.is_file():
        # A recreated historical PR worktree can briefly exist before
        # context-sync restores its controller-owned mirror. Keep that task
        # unavailable without blocking unrelated result or publication work.
        raise TaskContextWorktreeUnavailable(
            context,
            reason="TASK_CONTEXT_MIRROR_UNAVAILABLE",
        )
    if local_path.stat().st_mode & 0o022:
        raise RuntimeError("worktree task context mirror is group or world writable")
    if local_path.read_bytes() != raw:
        raise RuntimeError("shared and worktree task context mirrors disagree")
    if Path(command(["git", "rev-parse", "--show-toplevel"], cwd=worktree)).resolve() != worktree:
        raise RuntimeError("shared task context worktree root is invalid")
    remotes = command(["git", "remote"], cwd=worktree).splitlines()
    if not any(
        normalize_origin(command(["git", "remote", "get-url", remote], cwd=worktree))
        == repo.casefold()
        for remote in remotes
    ):
        raise RuntimeError("shared task context worktree does not belong to issue repository")
    if isinstance(receipt, dict) and receipt.get("prUrl"):
        command(["git", "cat-file", "-e", f"{receipt['commitSha']}^{{commit}}"], cwd=worktree)
    if context.get("targetBase") is not None:
        target_base = validate_target_base(context["targetBase"])
        command(["git", "cat-file", "-e", f"{target_base['sha']}^{{commit}}"], cwd=worktree)
        command(
            ["git", "merge-base", "--is-ancestor", target_base["sha"], "HEAD"],
            cwd=worktree,
        )
    source_updated_at = iso_z(
        datetime.fromtimestamp(max(source_stat.st_mtime, local_path.stat().st_mtime), tz=UTC)
    )
    return context, source_updated_at


def _recoverable_published_result(
    context: dict[str, Any], *, store: RadarLedger | None = None
) -> dict[str, str] | None:
    """Identify a clean result already represented by a published task context."""

    if str(context.get("stage") or "") not in PUBLISHED_TASK_STAGES:
        return None
    receipt = context.get("publicationReceipt")
    if not isinstance(receipt, dict) or not receipt.get("prUrl"):
        return None

    worktree = _lexical_absolute(Path(str(context.get("worktreePath") or "")))
    result_path = _lexical_absolute(Path(str(context.get("resultPath") or "")))
    candidate = {"worktreePath": str(worktree)}
    expected_path = _task_result_path(candidate)
    if result_path != expected_path:
        raise RuntimeError("shared task context result path is invalid")
    result_data = _read_task_result_bytes_if_present(candidate)
    if result_data is None:
        return None
    _result_path, raw = result_data
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("published task result is not valid JSON") from exc
    expected = {
        "schemaVersion": TASK_RESULT_SCHEMA,
        "key": context.get("key"),
        "issueUrl": context.get("issueUrl"),
        "threadId": context.get("threadId"),
        "worktreePath": str(worktree),
    }
    if not isinstance(value, dict):
        raise RuntimeError("published task result must be an object")
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise RuntimeError(f"published task result mismatch: {key}")
    try:
        result_digest = _task_result_digest(value, raw)
    except RuntimeError as exc:
        raise RuntimeError("published task result authentication is invalid") from exc
    stage = str(value.get("stage") or "")
    if value.get("contextDigest") != context.get("contextDigest") and stage != "FIX_READY":
        # Context sync may refresh audit evidence long after this clean result
        # was published. The exact published checkout proves FIX_READY is old.
        followup = context.get("prFollowup")
        wake_digest = str(followup.get("wakeDigest") or "") if isinstance(followup, dict) else ""
        if wake_digest and value.get("followupDigest") != wake_digest:
            return None
        if store is not None and store.task_result_digest_seen(
            str(context.get("key") or ""), result_digest
        ):
            return None
        raise RuntimeError("published task result mismatch: contextDigest")

    commit_sha = str(receipt.get("commitSha") or "")
    if command(["git", "status", "--porcelain"], cwd=worktree):
        return None
    if command(["git", "rev-parse", "HEAD"], cwd=worktree) != commit_sha:
        return None
    recovered = {
        "key": str(context["key"]),
        "digest": result_digest,
        "stage": stage,
    }
    if stage == "FIX_READY":
        return recovered
    followup = context.get("prFollowup")
    wake_digest = str(followup.get("wakeDigest") or "") if isinstance(followup, dict) else ""
    if stage == "PR_OPEN" and wake_digest and value.get("followupDigest") == wake_digest:
        return recovered | {"wakeDigest": wake_digest}
    return None


def recover_shared_task_contexts(store: RadarLedger) -> dict[str, Any]:
    try:
        context_fd, root, handles = _open_shared_context_directory(create=False)
    except FileNotFoundError:
        return {
            "verified": 0,
            "restored": [],
            "resultReceiptsRestored": 0,
            "unavailable": [],
            "quarantined": [],
            "errors": [],
        }
    except (OSError, RuntimeError) as exc:
        return {
            "verified": 0,
            "restored": [],
            "resultReceiptsRestored": 0,
            "unavailable": [],
            "quarantined": [],
            "errors": [{"path": str(shared_context_root()), "error": str(exc)[:300]}],
        }
    for fd in reversed(handles):
        os.close(fd)
    try:
        paths = _list_shared_context_paths()
        paths, path_errors = _deduplicate_shared_context_paths(paths)
    except (OSError, RuntimeError) as exc:
        return {
            "verified": 0,
            "restored": [],
            "resultReceiptsRestored": 0,
            "unavailable": [],
            "quarantined": [],
            "errors": [{"path": str(root), "error": str(exc)[:300]}],
        }
    restored: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    result_receipts_restored = 0
    for item in path_errors:
        if isinstance(item, _SharedContextValidationError):
            try:
                quarantined_item = _quarantine_shared_context(
                    store,
                    item.source_path,
                    item,
                    raw=item.raw,
                    source_stat=item.source_stat,
                )
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as quarantine_exc:
                errors.append(
                    {
                        "path": str(item.source_path),
                        "error": f"context quarantine persistence failed: {str(quarantine_exc)[:240]}",
                    }
                )
            else:
                if quarantined_item is None:
                    errors.append(
                        {
                            "path": str(item.source_path),
                            "error": "shared task context identity is unavailable for quarantine",
                        }
                    )
                else:
                    quarantined.append(quarantined_item)
        else:
            errors.append(item)
    for path in paths:
        try:
            context, source_updated_at = _verified_shared_task_context(path)
            result_receipt = _recoverable_published_result(context, store=store)
            restored_context = store.restore_task_context(
                context, source_updated_at=source_updated_at
            )
            receipt_restored = False
            if result_receipt and not store.task_result_digest_seen(
                result_receipt["key"], result_receipt["digest"]
            ):
                store.record_task_result_ingested(
                    result_receipt["key"],
                    digest=result_receipt["digest"],
                    stage=result_receipt["stage"],
                )
                if result_receipt.get("wakeDigest"):
                    store.record_followup_result(
                        result_receipt["key"],
                        wake_digest=result_receipt["wakeDigest"],
                        result_digest=result_receipt["digest"],
                        stage=result_receipt["stage"],
                    )
                receipt_restored = True
                result_receipts_restored += 1
            restored.append(restored_context | {"resultReceiptRestored": receipt_restored})
        except TaskContextWorktreeUnavailable as exc:
            context = exc.context
            receipt = context.get("publicationReceipt")
            unavailable.append(
                {
                    "path": str(path),
                    "key": str(context.get("key") or ""),
                    "issueUrl": str(context.get("issueUrl") or ""),
                    "intentId": str(context.get("intentId") or ""),
                    "stage": str(context.get("stage") or ""),
                    "threadId": str(context.get("threadId") or ""),
                    "worktreePath": str(context.get("worktreePath") or ""),
                    "published": bool(isinstance(receipt, dict) and receipt.get("prUrl")),
                    "reason": exc.reason,
                }
            )
        except _SharedContextValidationError as exc:
            try:
                item = _quarantine_shared_context(
                    store,
                    exc.source_path,
                    exc,
                    raw=exc.raw,
                    source_stat=exc.source_stat,
                )
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as quarantine_exc:
                errors.append(
                    {
                        "path": str(exc.source_path),
                        "error": f"context quarantine persistence failed: {str(quarantine_exc)[:240]}",
                    }
                )
            else:
                if item is None:
                    errors.append(
                        {
                            "path": str(exc.source_path),
                            "error": "shared task context identity is unavailable for quarantine",
                        }
                    )
                else:
                    quarantined.append(item)
        except FileNotFoundError as exc:
            # Cleanup may remove a terminal task context after glob() has
            # enumerated it. Only treat that exact disappearance as benign;
            # malformed paths and other missing files remain errors.
            if not path.exists() and not path.is_symlink():
                continue
            errors.append({"path": str(path), "error": str(exc)[:300]})
        except (OSError, RuntimeError, ValueError) as exc:
            try:
                item = _quarantine_shared_context(store, path, exc)
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as quarantine_exc:
                errors.append(
                    {
                        "path": str(path),
                        "error": f"context quarantine persistence failed: {str(quarantine_exc)[:240]}",
                    }
                )
            else:
                if item is None:
                    errors.append(
                        {
                            "path": str(path),
                            "error": "shared task context identity is unavailable for quarantine",
                        }
                    )
                else:
                    quarantined.append(item)
    return {
        "verified": len(restored),
        "restored": restored,
        "resultReceiptsRestored": result_receipts_restored,
        "unavailable": unavailable,
        "quarantined": quarantined,
        "errors": errors,
    }


def recover_task_contexts(args: argparse.Namespace) -> dict[str, Any]:
    result = recover_shared_task_contexts(ledger(args.ledger))
    return {"ok": not result["errors"]} | result


def run_reproduction_probes(args: argparse.Namespace) -> dict[str, Any]:
    """Slow-worker entry point for controller-owned reproduction probes."""

    # This queue belongs to the migrated managed schema.  Do not use the
    # legacy RadarLedger helper here or implicitly run a migration in a worker.
    result = ManagedLedger(args.ledger, ensure_schema=False).run_pending_reproduction_probes(
        limit=10
    )
    return {"ok": True} | result


def sync_queue(path: Path = LEDGER_PATH) -> dict[str, Any]:
    queue = fetch_cloud_queue()
    signer = DispatchSigner(signing_key())
    stale_queue: dict[str, Any] | None = None
    stale_event: dict[str, Any] | None = None
    try:
        intents = verify_queue(queue, signer)
    except SignatureError as exc:
        stale_queue = _classify_superseded_dispatch_queue(queue, signer, exc)
        stale_event = _record_superseded_dispatch_queue(
            queue, stale_queue, path, import_scope="superseded_signed_queue_only"
        )
        intents = []
    else:
        ManagedAdapter(ROOT, path).record_dispatch_queue(queue)
    store = ledger(path)
    context_recovery = recover_shared_task_contexts(store)
    if context_recovery["errors"]:
        return {
            "ok": False,
            "mode": queue.get("mode"),
            "verified": len(intents),
            "inserted": 0,
            "superseded": 0,
            "staleTerminalRejected": 0,
            "missingWorkspacesSuperseded": [],
            "taskContextRecovery": context_recovery,
            "prFollowup": {"status": "deferred", "reason": "task_context_recovery_failed"},
        }
    quarantined_keys = {
        str(item.get("key") or "")
        for item in context_recovery.get("quarantined") or []
        if item.get("key")
    }
    safe_intents = [item for item in intents if str(item.get("key") or "") not in quarantined_keys]
    incoming_by_key = {str(item.get("key") or ""): item for item in safe_intents}
    workspace_superseded: list[dict[str, str]] = []
    for unavailable in context_recovery["unavailable"]:
        if unavailable.get("published"):
            continue
        replacement = incoming_by_key.get(str(unavailable.get("key") or ""))
        if not replacement:
            continue
        if store.supersede_missing_workspace(
            key=str(unavailable["key"]),
            intent_id=str(unavailable["intentId"]),
            worktree_path=str(unavailable["worktreePath"]),
            replacement_intent_id=str(replacement["intentId"]),
        ):
            workspace_superseded.append(
                {
                    "key": str(unavailable["key"]),
                    "intentId": str(unavailable["intentId"]),
                    "replacementIntentId": str(replacement["intentId"]),
                }
            )
    stale_terminal = store.reconcile_terminal_intents()
    if stale_queue is None:
        superseded = store.reconcile_pending(
            {str(item["intentId"]) for item in safe_intents if item.get("intentId")}
        )
        inserted = sum(store.enqueue(item) for item in safe_intents)
    else:
        superseded = list(stale_event.get("staleLocalIntentsSuperseded") or [])
        inserted = 0
    followup_import: dict[str, Any]
    try:
        followup = fetch_cloud_pr_followup()
        if followup.get("version") == "pr_followup_v3":
            generated_at = str(followup.get("generatedAt") or "")
            generated_time = parse_time(generated_at)
            age = datetime.now(UTC) - generated_time
            if age < -timedelta(minutes=5):
                raise RuntimeError("cloud PR follow-up state is from the future")
            age_minutes = max(0, int(age.total_seconds() // 60))
            if age > timedelta(minutes=CLOUD_PR_FOLLOWUP_MAX_AGE_MINUTES):
                suspended = store.suspend_pr_followups(
                    source_generated_at=generated_at,
                    reason="CLOUD_PR_FOLLOWUP_STATE_STALE",
                )
                followup_import = {
                    "status": "stale_suspended",
                    "generatedAt": generated_at,
                    "ageMinutes": age_minutes,
                    "suspended": suspended,
                }
            else:
                managed_followup = ManagedAdapter(ROOT, path).record_followup(
                    followup,
                    {"run_id": (f"cloud-pr-followup:{followup.get('digest') or generated_at}")},
                )
                followup_import = {
                    "status": "imported",
                    "generatedAt": generated_at,
                    "ageMinutes": age_minutes,
                    "managedRecorded": managed_followup.get("recorded", 0),
                } | store.import_pr_followups(followup)
        else:
            followup_import = {"status": "awaiting_v3", "version": followup.get("version")}
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        followup_import = {"status": "error", "error": str(exc)[:240]}
    return {
        "ok": followup_import.get("status") != "error",
        "mode": queue.get("mode"),
        "verified": len(intents),
        "inserted": inserted,
        "superseded": len(superseded),
        "staleTerminalRejected": len(stale_terminal),
        "staleQueueRejected": 1 if stale_queue is not None else 0,
        "staleQueue": stale_queue,
        "staleLocalIntentsSuperseded": superseded,
        "auditEventCreated": bool(stale_event and stale_event.get("auditEventCreated")),
        "missingWorkspacesSuperseded": workspace_superseded,
        "taskContextRecovery": context_recovery,
        "quarantined": context_recovery.get("quarantined", []),
        "prFollowup": followup_import,
    }


def import_signed_queue(path: Path = LEDGER_PATH) -> dict[str, Any]:
    """Import only signed dispatch intents into the local Ledger.

    This intentionally does not recover desktop contexts, inspect GitHub, or
    import PR follow-up projections. Those operations belong to the slow
    worker and must never extend the fast cycle or the queue importer.
    """

    queue = fetch_cloud_queue()
    signer = DispatchSigner(signing_key())
    try:
        intents = verify_queue(queue, signer)
    except SignatureError as exc:
        stale = _classify_superseded_dispatch_queue(queue, signer, exc)
        return _record_superseded_dispatch_queue(
            queue, stale, path, import_scope="superseded_signed_queue_only"
        )
    ManagedAdapter(ROOT, path).record_dispatch_queue(queue)
    store = ledger(path)
    stale_terminal = store.reconcile_terminal_intents()
    superseded = store.reconcile_pending(
        {str(item["intentId"]) for item in intents if item.get("intentId")}
    )
    inserted = sum(store.enqueue(item) for item in intents)
    return {
        "ok": True,
        "mode": queue.get("mode"),
        "verified": len(intents),
        "inserted": inserted,
        "superseded": len(superseded),
        "staleTerminalRejected": len(stale_terminal),
        "importScope": "signed_queue_and_write_intents_only",
    }


LOW_INFORMATION_COMMENT_RE = re.compile(
    r"\b(?:"
    r"(?:i|we)\s+(?:would\s+like\s+to|want\s+to|can|could)\s+(?:work\s+on|take|pick\s+up)"
    r"|can\s+(?:you\s+)?(?:please\s+)?assign"
    r"|(?:please\s+)?assign\s+(?:this\s+issue\s+)?to\s+me"
    r"|is\s+(?:this|it)\s+(?:still\s+)?(?:open|available|unassigned)"
    r"|any\s+updates?"
    r")\b",
    re.IGNORECASE,
)
COMMENT_TECHNICAL_MARKER_RE = re.compile(
    r"`|https?://|(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+|"
    r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b|"
    r"\b(?:stack\s*trace|traceback|exception|regression|test(?:ing)?|parser|handler|"
    r"endpoint|request|response|payload|implementation|code\s+path)\b",
    re.IGNORECASE,
)
GENERIC_TERMINAL_CODE_TERMS = {
    "api",
    "bug",
    "callback",
    "client",
    "code",
    "error",
    "fails",
    "hosted",
    "issue",
    "public",
    "repository",
    "server",
    "service",
}
TERMINAL_SOURCE_SUFFIXES = (
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".cc",
    ".cpp",
    ".c",
    ".h",
)
TERMINAL_NON_PRODUCT_PARTS = {
    ".github",
    "__tests__",
    "docs",
    "documentation",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "test",
    "tests",
}


def _is_low_information_comment(comment: dict[str, Any]) -> bool:
    body = " ".join(str(comment.get("body") or "").split())
    return bool(
        body
        and len(body) <= 180
        and LOW_INFORMATION_COMMENT_RE.search(body)
        and not COMMENT_TECHNICAL_MARKER_RE.search(body)
    )


def _issue_material_digest(issue: dict[str, Any]) -> str:
    def names(values: Any, key: str) -> list[str]:
        if not isinstance(values, list):
            return []
        normalized = []
        for value in values:
            if isinstance(value, dict):
                text = str(value.get(key) or "").strip()
            else:
                text = str(value or "").strip()
            if text:
                normalized.append(text.casefold())
        return sorted(set(normalized))

    return sha256_json(
        {
            "state": str(issue.get("state") or "").casefold(),
            "stateReason": str(issue.get("state_reason") or "").casefold(),
            "title": str(issue.get("title") or "").strip(),
            "body": str(issue.get("body") or "").replace("\r\n", "\n").rstrip(),
            "labels": names(issue.get("labels"), "name"),
            "assignees": names(issue.get("assignees"), "login"),
        }
    )


def _technical_comments_digest(comments: Any) -> str:
    material = []
    for comment in comments if isinstance(comments, list) else []:
        if not isinstance(comment, dict) or _is_low_information_comment(comment):
            continue
        user = comment.get("user") if isinstance(comment.get("user"), dict) else {}
        material.append(
            {
                "id": comment.get("id"),
                "author": str(user.get("login") or "").casefold(),
                "association": str(comment.get("author_association") or "").upper(),
                "body": str(comment.get("body") or "").replace("\r\n", "\n").rstrip(),
            }
        )
    material.sort(key=lambda value: (str(value.get("id") or ""), value["author"], value["body"]))
    return sha256_json(material)


def _terminal_audit_evidence(row: dict[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        payload = json.loads(str(row.get("terminal_audit_payload_json") or "{}"))
    except json.JSONDecodeError:
        return {}, ""
    live_audit = payload.get("liveAudit") if isinstance(payload, dict) else {}
    evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else {}
    if not isinstance(evidence, dict):
        return {}, ""
    try:
        terminal_payload = json.loads(str(row.get("terminal_payload_json") or "{}"))
    except json.JSONDecodeError:
        terminal_payload = {}
    summary = (
        str(terminal_payload.get("summary") or "") if isinstance(terminal_payload, dict) else ""
    )
    return evidence, summary


def _terminal_code_terms(issue: dict[str, Any], summary: str) -> set[str]:
    text = "\n".join(
        (str(issue.get("title") or ""), str(issue.get("body") or ""), str(summary or ""))
    )
    quoted = re.findall(r"`([A-Za-z][A-Za-z0-9_.:/-]{2,})`", text)
    identifiers = re.findall(r"\b[A-Za-z][A-Za-z0-9]*(?:[_./-][A-Za-z0-9]+)+\b", text)
    branded = re.findall(r"\b(?:[A-Z]{2,}[A-Za-z0-9]*|[A-Z][a-z]+[A-Z][A-Za-z0-9]*)\b", text)
    return {
        value.casefold().strip("./")
        for value in (*quoted, *identifiers, *branded)
        if len(value.strip("./")) >= 4
        and value.casefold().strip("./") not in GENERIC_TERMINAL_CODE_TERMS
    }


def _terminal_product_code_path(path: str) -> bool:
    normalized = path.casefold().lstrip("./")
    return normalized.endswith(TERMINAL_SOURCE_SUFFIXES) and not any(
        part in TERMINAL_NON_PRODUCT_PARTS for part in normalized.split("/")[:-1]
    )


def _terminal_path_matches(path: str, *, code_paths: set[str], terms: set[str]) -> bool:
    normalized = path.casefold().lstrip("./")
    if not _terminal_product_code_path(normalized):
        return False
    if any(
        normalized == candidate
        or normalized.endswith(f"/{candidate}")
        or candidate.endswith(f"/{normalized}")
        for candidate in code_paths
        if _terminal_product_code_path(candidate)
    ):
        return True
    return any(term in normalized for term in terms)


def _relevant_terminal_code_changed(
    github: GitHubClient,
    *,
    repo: str,
    evidence: dict[str, Any],
    baseline_issue: dict[str, Any],
    summary: str,
    live_sha: str = "",
) -> bool | None:
    baseline_sha = str(
        evidence.get("liveBaseSha")
        or evidence.get("live_base_sha")
        or evidence.get("selectedBaseSha")
        or evidence.get("selected_base_sha")
        or ""
    )
    default_branch = str(evidence.get("defaultBranch") or evidence.get("default_branch") or "")
    if not baseline_sha or not default_branch:
        return None
    if not live_sha:
        branch = github.branch(repo, default_branch)
        commit = branch.get("commit") if isinstance(branch, dict) else {}
        live_sha = str(commit.get("sha") or "") if isinstance(commit, dict) else ""
    if not live_sha:
        return None
    if live_sha == baseline_sha:
        return False
    comparison = github.compare(repo, baseline_sha, live_sha)
    if not isinstance(comparison, dict):
        return None
    if str(comparison.get("status") or "").casefold() == "identical":
        return False
    files = comparison.get("files")
    if not isinstance(files, list):
        return None
    probe = evidence.get("repoProbeReceipt") or evidence.get("repo_probe_receipt") or {}
    raw_paths = probe.get("codePaths") or probe.get("code_paths") or []
    code_paths = {str(path).casefold().lstrip("./") for path in raw_paths if str(path).strip()}
    # The terminal task summary identifies the code surface that was actually
    # investigated. Fall back to the broader issue text only for older results
    # that did not preserve those technical identifiers.
    terms = _terminal_code_terms({}, summary) or _terminal_code_terms(baseline_issue, "")
    for value in files:
        if not isinstance(value, dict):
            return None
        filename = str(value.get("filename") or "").casefold().lstrip("./")
        if _terminal_path_matches(filename, code_paths=code_paths, terms=terms):
            return True
        if not _terminal_product_code_path(filename):
            continue
        changed_text = f"{filename}\n{value.get('patch') or ''}".casefold()
        if any(term in changed_text for term in terms):
            return True
    if len(files) >= 300:
        try:
            baseline_tree = {
                str(item.get("path") or "").casefold().lstrip("./"): item.get("sha")
                for item in github.repository_tree(repo, baseline_sha)
                if item.get("type") == "blob" and str(item.get("path") or "")
            }
            live_tree = {
                str(item.get("path") or "").casefold().lstrip("./"): item.get("sha")
                for item in github.repository_tree(repo, live_sha)
                if item.get("type") == "blob" and str(item.get("path") or "")
            }
        except (OSError, RuntimeError, ValueError):
            return None
        for filename in baseline_tree.keys() | live_tree.keys():
            if baseline_tree.get(filename) == live_tree.get(filename):
                continue
            if _terminal_path_matches(filename, code_paths=code_paths, terms=terms):
                return True
    return False


def _wrong_repo_terminal_materially_changed(
    github: GitHubClient,
    *,
    row: dict[str, Any],
    issue: dict[str, Any],
    comments: list[dict[str, Any]] | None = None,
    live_sha: str = "",
) -> bool | None:
    evidence, summary = _terminal_audit_evidence(row)
    baseline_issue = evidence.get("issue") if isinstance(evidence.get("issue"), dict) else None
    baseline_comments = evidence.get("comments")
    if baseline_issue is None or not isinstance(baseline_comments, list):
        return None
    if _issue_material_digest(baseline_issue) != _issue_material_digest(issue):
        return True
    current_comments = (
        comments
        if comments is not None
        else github.comments(str(row["repo"]), int(row["issue_number"]))
    )
    if _technical_comments_digest(baseline_comments) != _technical_comments_digest(
        current_comments
    ):
        return True
    return _relevant_terminal_code_changed(
        github,
        repo=str(row["repo"]),
        evidence=evidence,
        baseline_issue=baseline_issue,
        summary=summary,
        live_sha=live_sha,
    )


def _historical_wrong_repo_feedback(
    store: RadarLedger, opportunity_key: str
) -> dict[str, Any] | None:
    for row in store.terminal_feedback():
        if row.get("key") == opportunity_key and row.get("terminal_reason") == "WRONG_REPO":
            return row
    return None


def publish_terminal_feedback(args: argparse.Namespace) -> dict[str, Any]:
    """Publish local terminal judgments into the integrity-checked cloud state."""

    store = ledger(args.ledger)
    rows = store.terminal_feedback()
    recheck_rows = store.scanner_recheck_feedback()
    if not rows and not recheck_rows:
        return {
            "ok": True,
            "published": 0,
            "scannerRechecks": [],
            "stateChanged": False,
            "publishAttempts": 0,
            "deferred": [],
            "warnings": [],
            "errors": [],
        }

    github = GitHubClient() if rows else None
    analyzed = iso_z(datetime.now(UTC))
    published: list[dict[str, Any]] = []
    scanner_rechecks: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    updates: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row["key"])
        try:
            assert github is not None
            issue = github.issue(str(row["repo"]), int(row["issue_number"]))
            issue_updated = str(issue.get("updated_at") or "")
            terminal_recorded_at = str(
                row.get("terminal_recorded_at") or row.get("latest_intent_issued_at") or ""
            )
            terminal_issue_updated_at = str(row.get("terminal_issue_updated_at") or "")
            if not issue_updated or not terminal_recorded_at:
                deferred.append({"key": key, "reason": "missing_issue_snapshot_time"})
                continue
            if terminal_issue_updated_at:
                issue_changed = issue_updated != terminal_issue_updated_at
            else:
                issue_changed = parse_time(issue_updated) > parse_time(terminal_recorded_at)
            if issue_changed:
                material_change = None
                if str(row.get("terminal_reason") or "") == "WRONG_REPO":
                    material_change = _wrong_repo_terminal_materially_changed(
                        github,
                        row=row,
                        issue=issue,
                    )
                if material_change is not False:
                    deferred.append(
                        {
                            "key": key,
                            "reason": (
                                "material_terminal_evidence_changed"
                                if material_change is True
                                else "issue_updated_after_local_snapshot"
                            ),
                        }
                    )
                    continue
            updates[key] = {
                "analyzed": analyzed,
                "status": CONTROLLER_TERMINAL_STATUS,
                "controller_stage": row["stage"],
                "terminal_reason": row.get("terminal_reason") or row["stage"],
                "issue_updated": issue_updated,
                "scanner_version": SCANNER_DECISION_REVISION,
                "decision_contract_digest": decision_contract_digest(),
            }
            published.append({"key": key, "stage": row["stage"]})
        except (KeyError, OSError, RuntimeError, ValueError) as exc:
            message = str(exc)[:240]
            if is_transient_github_error(exc):
                deferred.append({"key": key, "reason": "github_temporarily_unavailable"})
                warnings.append({"key": key, "warning": message})
            else:
                errors.append({"key": key, "error": message})

    for row in recheck_rows:
        key = str(row["key"])
        issue_updated = str(row.get("issue_updated_at") or "")
        recorded_at = str(row.get("recheck_recorded_at") or "")
        if not issue_updated or not recorded_at:
            deferred.append({"key": key, "reason": "missing_state_drift_snapshot_time"})
            continue
        updates[key] = {
            "analyzed": recorded_at,
            "status": "state_drift",
            "controller_stage": None,
            "terminal_reason": None,
            "issue_updated": issue_updated,
            "scanner_version": SCANNER_DECISION_REVISION,
            "decision_contract_digest": decision_contract_digest(),
            "source_intent_id": row.get("intent_id"),
            "stale_base_sha": row.get("stale_base_sha"),
            "live_base_sha": row.get("live_base_sha"),
        }
        scanner_rechecks.append({"key": key, "intentId": row.get("intent_id")})
        published.append({"key": key, "stage": "STATE_DRIFT_RECHECK_REQUIRED"})

    state_changed = False
    publish_attempts = 0
    if updates:
        state_changed, publish_attempts = _publish_controller_feedback_updates(updates)
    return {
        "ok": not errors,
        "published": len(published),
        "scannerRechecks": scanner_rechecks,
        "stateChanged": state_changed,
        "publishAttempts": publish_attempts,
        "deferred": deferred,
        "warnings": warnings,
        "errors": errors,
    }


def _publish_controller_feedback_updates(
    updates: dict[str, dict[str, Any]], max_attempts: int = 5
) -> tuple[bool, int]:
    """Merge controller updates without weakening the state branch stale-write guard."""

    state_script = ROOT / "scripts" / "state_branch.py"
    feedback_path = STATE / "controller_terminal_feedback.json"
    for attempt in range(1, max_attempts + 1):
        command(
            [
                sys.executable,
                str(state_script),
                "restore",
                "--profile",
                "controller-feedback",
                "--allow-missing",
            ],
            cwd=STATE.parent,
            timeout=90,
        )
        feedback = read_json(feedback_path, missing={})
        if not isinstance(feedback, dict):
            raise RuntimeError("controller terminal feedback is invalid")

        changed = False
        for key, update in updates.items():
            previous = feedback.get(key) if isinstance(feedback.get(key), dict) else {}
            semantic_update = {name: value for name, value in update.items() if name != "analyzed"}
            if previous and all(
                previous.get(name) == value for name, value in semantic_update.items()
            ):
                continue
            feedback[key] = previous | update
            changed = True

        if not changed:
            return False, attempt

        atomic_write_json(feedback_path, feedback)
        try:
            command(
                [
                    sys.executable,
                    str(state_script),
                    "publish",
                    "--profile",
                    "controller-feedback",
                ],
                cwd=STATE.parent,
                timeout=90,
            )
            return True, attempt
        except RuntimeError as exc:
            if "state branch changed since restore" not in str(exc) or attempt == max_attempts:
                raise
            sleep(min(2**attempt, 8))
    raise RuntimeError("controller terminal feedback publish attempts exhausted")


def _publish_controller_decision_feedback_updates(
    updates: dict[str, dict[str, Any]], max_attempts: int = 5
) -> tuple[bool, int]:
    """Merge durable Codex-session receipts into the controller feedback branch."""

    state_script = ROOT / "scripts" / "state_branch.py"
    feedback_path = STATE / "controller_decision_feedback.json"
    for attempt in range(1, max_attempts + 1):
        command(
            [
                sys.executable,
                str(state_script),
                "restore",
                "--profile",
                "controller-feedback",
                "--allow-missing",
            ],
            cwd=STATE.parent,
            timeout=90,
        )
        feedback = read_json(
            feedback_path,
            missing={"schema": CODEX_DECISION_FEEDBACK_SCHEMA, "events": {}},
        )
        if (
            not isinstance(feedback, dict)
            or feedback.get("schema") != CODEX_DECISION_FEEDBACK_SCHEMA
            or not isinstance(feedback.get("events"), dict)
        ):
            raise RuntimeError("controller Codex decision feedback is invalid")
        events = dict(feedback["events"])
        changed = False
        for event_id, update in updates.items():
            previous = events.get(event_id) if isinstance(events.get(event_id), dict) else {}
            semantic_update = {name: value for name, value in update.items() if name != "analyzed"}
            if previous and all(
                previous.get(name) == value for name, value in semantic_update.items()
            ):
                continue
            events[event_id] = previous | update
            changed = True
        if not changed:
            return False, attempt
        atomic_write_json(
            feedback_path,
            {"schema": CODEX_DECISION_FEEDBACK_SCHEMA, "events": events},
        )
        try:
            command(
                [
                    sys.executable,
                    str(state_script),
                    "publish",
                    "--profile",
                    "controller-feedback",
                ],
                cwd=STATE.parent,
                timeout=90,
            )
            return True, attempt
        except RuntimeError as exc:
            if "state branch changed since restore" not in str(exc) or attempt == max_attempts:
                raise
            sleep(min(2**attempt, 8))
    raise RuntimeError("controller Codex decision feedback publish attempts exhausted")


def list_pending(path: Path = LEDGER_PATH) -> dict[str, Any]:
    values = ledger(path).pending()
    return {
        "ok": True,
        "pending": [
            {
                "intentId": item["intentId"],
                "key": item["key"],
                "repo": item["repo"],
                "issueUrl": item["issueUrl"],
                "title": item["title"],
                "mode": item["mode"],
                "expiresAt": item["expiresAt"],
                "ledgerStatus": item["ledgerStatus"],
                "pendingSince": item["pendingSince"],
                "pendingAgeMinutes": item["pendingAgeMinutes"],
                "leaseStale": item["leaseStale"],
                "clientThreadId": item.get("clientThreadId"),
                "creationStartedAt": item.get("creationStartedAt"),
                "creationAgeMinutes": item.get("creationAgeMinutes"),
            }
            for item in values
        ],
        "alerts": [
            {
                "intentId": item["intentId"],
                "key": item["key"],
                "issueUrl": item["issueUrl"],
                "pendingAgeMinutes": item["pendingAgeMinutes"],
                "alertCode": item["alertCode"],
            }
            for item in ledger(path).pending_alerts()
        ],
    }


def dispatch_alerts(args: argparse.Namespace) -> dict[str, Any]:
    alerts = [
        item
        for item in ledger(args.ledger).pending_alerts(min_age_minutes=args.min_age_minutes)
        if external_side_effect_allowed(item)
    ]
    public = [
        {
            "intentId": item["intentId"],
            "key": item["key"],
            "issueUrl": item["issueUrl"],
            "pendingAgeMinutes": item["pendingAgeMinutes"],
            "alertCode": item["alertCode"],
        }
        for item in alerts
    ]
    notified = False
    error = None
    if args.notify and public:
        app_id = os.environ.get("FEISHU_APP_ID")
        app_secret = os.environ.get("FEISHU_APP_SECRET")
        chat_id = os.environ.get("FEISHU_CHAT_ID")
        if not app_id or not app_secret or not chat_id:
            error = "feishu_credentials_not_configured"
        else:
            card = {
                "header": {
                    "title": {"tag": "plain_text", "content": "OSS PR Radar 派发异常"},
                    "template": "red",
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": "\n".join(
                                f"**[{item['key']}]({item['issueUrl']})**："
                                f"{item['alertCode']}，已持续 "
                                f"{item['pendingAgeMinutes']} 分钟"
                                for item in public
                            ),
                        },
                    }
                ],
            }
            try:
                FeishuClient(app_id, app_secret, chat_id).send_card(
                    card,
                    idempotency_key=sha256_json(
                        {
                            "alerts": [[item["intentId"], item["alertCode"]] for item in public],
                            "hour": datetime.now().astimezone().strftime("%Y-%m-%dT%H"),
                        }
                    ),
                )
                notified = True
            except NotificationError as exc:
                error = str(exc)[:200]
    return {
        "ok": not error,
        "alerts": public,
        "notified": notified,
        "error": error,
    }


def dispatch_notifications(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidates = [
        item
        for item in store.dispatch_notification_candidates()
        if external_side_effect_allowed(item)
    ]
    if not candidates or not args.notify:
        return {"ok": True, "pending": candidates, "notified": [], "errors": []}
    app_id = os.environ.get("FEISHU_APP_ID")
    app_secret = os.environ.get("FEISHU_APP_SECRET")
    chat_id = os.environ.get("FEISHU_CHAT_ID")
    if not app_id or not app_secret or not chat_id:
        return {
            "ok": False,
            "pending": candidates,
            "notified": [],
            "errors": [{"error": "feishu_credentials_not_configured"}],
        }
    client = FeishuClient(app_id, app_secret, chat_id)
    notified: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for item in candidates:
        idempotency_key = sha256_json(
            {
                "kind": "codex_thread_created_v1",
                "threadId": item["threadId"],
            }
        )
        card = candidate_card(
            [
                {
                    "repo": item["repo"],
                    "num": item["issueNumber"],
                    "url": item["issueUrl"],
                    "title": item["title"],
                    "category": "CODEX_TASK_CREATED",
                    "auto_spawn": True,
                    "next_step": "Codex 会话已创建，正在本地审计与实现",
                }
            ],
            title="OSS PR Radar：Codex 会话已创建",
        )
        try:
            client.send_card(card, idempotency_key=idempotency_key)
            store.commit_dispatch_notification(
                thread_id=item["threadId"],
                idempotency_key=idempotency_key,
            )
            notified.append({"key": item["key"], "threadId": item["threadId"]})
        except (NotificationError, RuntimeError) as exc:
            errors.append({"key": item["key"], "error": str(exc)[:200]})
    return {
        "ok": not errors,
        "pending": candidates,
        "notified": notified,
        "errors": errors,
    }


def _candidate(intent: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo": intent["repo"],
        "num": intent["issueNumber"],
        "url": intent["issueUrl"],
        "title": intent["title"],
        "track": intent.get("track"),
        "category": intent["category"],
        "gate_decision": intent.get("scanGate"),
        "auto_spawn": intent.get("autoSpawn") is True,
        "submission_policy": intent.get("submissionPolicy") or "normal",
        "public_submission_allowed": intent.get("publicSubmissionAllowed") is True,
        "llm_review": intent.get("llmReview") or {},
        "actionability_evidence": intent.get("actionabilityEvidence") or {},
        "algorithm_evidence": intent.get("algorithmEvidence"),
        "maturity": intent.get("maturity") or "mature",
        "notify": intent.get("notify") is not False,
    }


def _hardware_inventory() -> set[str]:
    return {
        item.strip().casefold()
        for item in os.environ.get("RADAR_HARDWARE", "4090,5090,a100,v100").split(",")
        if item.strip()
    }


def _resolve_repo_code_paths(
    client: GitHubClient,
    *,
    repo: str,
    ref: str,
    code_paths: list[str],
) -> list[str]:
    normalized = [str(path).strip().strip("`").lstrip("./") for path in code_paths]
    normalized = [path for path in normalized if path]
    if not normalized:
        return []
    try:
        tree_paths = {
            str(item.get("path") or "")
            for item in client.repository_tree(repo, ref)
            if item.get("type") == "blob" and str(item.get("path") or "")
        }
    except Exception:
        return normalized

    resolved: set[str] = set()
    code_search_terms: list[str] = []
    source_suffixes = (
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".cc",
        ".cpp",
        ".c",
        ".h",
    )
    for path in normalized:
        if path in tree_paths:
            resolved.add(path)
            continue
        if "/" in path:
            suffix_matches = {
                candidate for candidate in tree_paths if candidate.endswith(f"/{path}")
            }
            if len(suffix_matches) == 1:
                resolved.update(suffix_matches)
            continue
        if "." not in path:
            snake_stem = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", path)
            snake_stem = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", snake_stem).casefold()
            stem_matches = {
                candidate
                for candidate in tree_paths
                if candidate.casefold().endswith(source_suffixes)
                and candidate.rsplit("/", 1)[-1].rsplit(".", 1)[0].replace("-", "_").casefold()
                == snake_stem
            }
            if len(stem_matches) == 1:
                resolved.update(stem_matches)
                continue
            code_search_terms.append(path)
            continue
        basename_matches = {
            candidate for candidate in tree_paths if candidate.rsplit("/", 1)[-1] == path
        }
        if len(basename_matches) == 1:
            resolved.update(basename_matches)
            continue
        if not path.casefold().endswith(source_suffixes):
            code_search_terms.append(path.rsplit(".", 1)[-1])

    for term in dict.fromkeys(code_search_terms):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{3,}", term):
            continue
        try:
            search = client.api(
                "search/code",
                params={"q": f"{term} repo:{repo}", "per_page": 20},
            )
        except Exception:
            continue
        items = search.get("items") if isinstance(search, dict) else search
        matches = {
            str(item.get("path") or "")
            for item in (items or [])
            if isinstance(item, dict) and str(item.get("path") or "") in tree_paths
        }
        source_matches = sorted(
            path
            for path in matches
            if path.startswith(("src/", "lib/", "packages/", "python/", "vllm/", "sglang/"))
        )
        resolved.update((source_matches or sorted(matches))[:5])
    return sorted(resolved)


def _audit_intent(intent: dict[str, Any]) -> tuple[Any, Any]:
    match = ISSUE_URL.match(str(intent.get("issueUrl") or ""))
    if not match:
        raise RuntimeError("invalid issue URL")
    repo, number = match.groups()
    client = GitHubClient()
    evidence = collect_evidence(
        client,
        repo,
        int(number),
        current_actor=os.environ.get("GITHUB_ACTOR", "Oxygen56"),
        hardware_inventory=_hardware_inventory(),
    )
    pre_task = (
        intent.get("preTaskEvidence") if isinstance(intent.get("preTaskEvidence"), dict) else {}
    )
    default_branch = str(intent.get("defaultBranch") or pre_task.get("defaultBranch") or "")
    selected_base = str(intent.get("selectedBaseSha") or pre_task.get("baseSha") or "")
    expected_digest = str(intent.get("preTaskEvidenceDigest") or intent.get("evidenceDigest") or "")
    base_status = "OK"
    actual_branch = ""
    actual_base = ""
    try:
        repository = client.repository(repo)
        actual_branch = str(repository.get("default_branch") or "")
        branch = client.branch(repo, actual_branch) if actual_branch else {}
        actual_base = str((branch.get("commit") or {}).get("sha") or "")
        if not default_branch or not selected_base or not expected_digest:
            base_status = "MISSING_SELECTED_BASE_EVIDENCE"
        elif actual_branch != default_branch or actual_base != selected_base:
            base_status = "STATE_DRIFT"
    except Exception as exc:
        base_status = f"LIVE_BASE_LOOKUP_FAILED:{type(exc).__name__}"
    code_paths = [
        str(path)
        for path in (pre_task.get("codePathsPlan") or pre_task.get("codePaths") or [])
        if str(path).strip()
    ]
    if base_status == "OK":
        code_paths = _resolve_repo_code_paths(
            client,
            repo=repo,
            ref=selected_base,
            code_paths=code_paths,
        )
    preliminary_verdict = authorize(_candidate(intent), evidence)
    if base_status == "OK" and preliminary_verdict.status != "ALLOW":
        evidence = replace(
            evidence,
            default_branch=default_branch,
            selected_base_sha=selected_base,
            live_base_sha=actual_base,
            repo_probe_receipt={
                "schema": "repo_probe_receipt_v1",
                "repo": repo,
                "baseSha": selected_base,
                "codePaths": code_paths,
                "status": "NOT_RUN",
                "probeLevel": "UNVERIFIED",
                "reason": preliminary_verdict.reason_code,
            },
        )
        return evidence, preliminary_verdict
    probe = (
        run_repo_probe(
            client,
            repo=repo,
            default_branch=default_branch,
            selected_base_sha=selected_base,
            code_paths=code_paths,
            probe_profile=intent.get("probeProfile") or pre_task.get("probeProfile"),
        )
        if base_status == "OK"
        else {
            "schema": "repo_probe_receipt_v1",
            "repo": repo,
            "baseSha": selected_base,
            "codePaths": code_paths,
            "status": "NOT_RUN",
            "reason": base_status,
        }
    )
    evidence = replace(
        evidence,
        default_branch=default_branch,
        selected_base_sha=selected_base,
        live_base_sha=actual_base,
        repo_probe_receipt=probe,
        probe_level=str(probe.get("probeLevel") or "UNVERIFIED"),
    )
    verdict = authorize(_candidate(intent), evidence)
    if base_status != "OK":
        verdict = replace(
            verdict,
            status="BLOCK" if base_status == "STATE_DRIFT" else "HOLD",
            reason_code=base_status,
        )
    elif verdict.status == "ALLOW":
        paths_verified = verify_probe_receipt(
            probe,
            repo=repo,
            base_sha=selected_base,
            code_paths=code_paths,
            required_level=PATHS_VERIFIED,
        )
        reproduced = verify_probe_receipt(
            probe,
            repo=repo,
            base_sha=selected_base,
            code_paths=code_paths,
            required_level=REPRODUCED_VALIDATED,
        )
        confidence = float((intent.get("llmReview") or {}).get("confidence") or 0.0)
        visible_reproduction_task = (
            intent.get("maturity", "mature") == "mature"
            and intent.get("notify") is not False
            and intent.get("autoSpawn") is True
            and confidence >= 0.7
        )
        if not paths_verified:
            verdict = replace(
                verdict,
                status="HOLD",
                reason_code="REPO_PATHS_REQUIRED" if code_paths else "REPO_PATHS_UNRESOLVED",
            )
        elif not reproduced and not visible_reproduction_task:
            verdict = replace(
                verdict,
                status="HOLD",
                reason_code="REPRODUCTION_REQUIRED_NOT_VISIBLE",
            )
    return evidence, verdict


def _resolve_intent_target_base(intent: dict[str, Any], evidence: Any) -> dict[str, str]:
    evidence_value = evidence.as_dict()
    issue = evidence_value.get("issue")
    repo = str(evidence_value.get("repo") or intent.get("repo") or "")
    if not isinstance(issue, dict) or not repo:
        raise TargetBranchError("live audit does not contain repository issue metadata")
    return resolve_target_base(GitHubClient(), repo, issue)


def _audit_payload(
    evidence: Any,
    verdict: Any,
    target_base: dict[str, str] | None = None,
) -> dict[str, Any]:
    payload = {
        "authorization": verdict.as_dict(),
        "evidenceDigest": evidence.digest,
        "probeLevel": getattr(evidence, "probe_level", "UNVERIFIED"),
        "liveAudit": {
            "capturedAt": iso_z(datetime.now(UTC)),
            "evidence": evidence.as_dict(),
        },
    }
    if target_base is not None:
        payload["targetBase"] = validate_target_base(target_base)
    return payload


def _private_task_limit() -> int | None:
    raw = os.environ.get("RADAR_MAX_ACTIVE_TASKS", "5").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("RADAR_MAX_ACTIVE_TASKS must be an integer") from exc
    if value < 0 or value > 64:
        raise RuntimeError("RADAR_MAX_ACTIVE_TASKS must be between 0 and 64")
    return value or None


def _active_task_count(store: Any, *, exclude_intent_id: str | None = None) -> int:
    counter = getattr(store, "active_task_count", None)
    if callable(counter):
        return int(counter(exclude_intent_id=exclude_intent_id))
    fallback = getattr(store, "active_dispatch_count", None)
    return int(fallback(exclude_intent_id=exclude_intent_id)) if callable(fallback) else 0


def _global_task_wip(
    store: Any, *, exclude_intent_id: str | None = None
) -> tuple[bool, int, int | None]:
    limit = _private_task_limit()
    active = _active_task_count(store, exclude_intent_id=exclude_intent_id)
    return limit is not None and active >= limit, active, limit


def _thread_bound_issue_tasks(store: Any) -> list[dict[str, Any]]:
    loader = getattr(store, "active_task_threads", None)
    if callable(loader):
        return list(loader())
    candidates = getattr(store, "task_context_candidates", None)
    if not callable(candidates):
        return []
    return [
        item
        for item in candidates()
        if item.get("intentStatus") == "DISPATCHED" and item.get("threadId")
    ]


def _codex_auth_refreshed_after(thread_updated_at: int) -> bool:
    """Return whether Codex credentials changed after a failed task turn.

    A usage-limit failure is a snapshot of the account state at that turn.  Once
    credentials are refreshed, keeping the old failure as a global pause would
    prevent the normal recovery path from ever testing the refreshed account.
    """

    codex_home = Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))
    try:
        metadata = (codex_home / "auth.json").stat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_mtime > thread_updated_at


def _codex_usage_limit_pause(store: Any) -> dict[str, Any] | None:
    tasks = _thread_bound_issue_tasks(store)
    thread_ids = sorted({str(item.get("threadId") or "") for item in tasks if item.get("threadId")})
    if not thread_ids or not THREAD_DB.is_file():
        return None

    placeholders = ",".join("?" for _ in thread_ids)
    rows: dict[str, tuple[int, str, int, str | None]] = {}
    try:
        connection = sqlite3.connect(THREAD_DB)
        values = connection.execute(
            f"SELECT id,archived,title,updated_at,rollout_path FROM threads "
            f"WHERE id IN ({placeholders})",
            thread_ids,
        ).fetchall()
        rows = {
            str(row[0]): (int(row[1] or 0), str(row[2] or ""), int(row[3] or 0), row[4])
            for row in values
        }
    except sqlite3.Error:
        return None
    finally:
        if "connection" in locals():
            connection.close()

    live_probe: set[str] = set()
    persisted_states: dict[str, dict[str, Any] | None] = {}
    for thread_id in thread_ids:
        row = rows.get(thread_id)
        if row is None or row[0] != 0:
            continue
        state = latest_thread_turn_state(row[3])
        persisted_states[thread_id] = state
        if state is None:
            live_probe.add(thread_id)
    live_states = live_thread_turn_states(live_probe)

    tasks_by_thread = {str(item.get("threadId") or ""): item for item in tasks}
    blocked: list[dict[str, Any]] = []
    resume_after: str | None = None
    for thread_id in thread_ids:
        row = rows.get(thread_id)
        if row is None or row[0] != 0:
            continue
        state = persisted_states.get(thread_id) or live_states.get(thread_id)
        if not _is_codex_usage_limit_state(state):
            continue
        if _codex_auth_refreshed_after(row[2]):
            continue
        message = str((state or {}).get("message") or "")
        resume_after = resume_after or _codex_usage_limit_resume_after(message)
        task = tasks_by_thread.get(thread_id) or {}
        blocked.append(
            {
                "key": task.get("key"),
                "threadId": thread_id,
                "reason": "codex_usage_limit_exceeded",
                "resumeAfter": _codex_usage_limit_resume_after(message),
                "turnId": (state or {}).get("turnId"),
                "threadUpdatedAt": row[2],
                "currentTitle": row[1],
            }
        )

    if not blocked:
        return None
    return {
        "reason": "codex_usage_limit_exceeded",
        "resumeAfter": resume_after,
        "activeTaskCount": _active_task_count(store),
        "tasks": blocked,
    }


def independent_review_run(args: argparse.Namespace) -> dict[str, Any]:
    """Run one serialized review independently of task lifecycle bookkeeping."""

    schema_path = ROOT / "schemas" / "independent_review.schema.json"
    if not schema_path.is_file():
        return {
            "ok": True,
            "unavailable": True,
            "reason": "independent_review_schema_unavailable",
            "updated": [],
            "skipped": [],
            "errors": [],
        }
    return review_once(ROOT, args.ledger)


def _higher_priority_existing_work(
    args: argparse.Namespace,
    *,
    intent_key: str,
) -> list[dict[str, str]]:
    """Keep scarce task capacity on work already closest to a useful outcome."""

    priorities: list[dict[str, str]] = []
    pr_state = pr_followup_list(argparse.Namespace(ledger=args.ledger))
    for item in [
        *pr_state["candidates"],
        *pr_state["restoreRequired"],
        *pr_state["unresolved"],
    ]:
        if item.get("key") != intent_key:
            priorities.append({"kind": "pr_followup", "key": str(item.get("key") or "")})

    validation_state = validation_followup_list(
        argparse.Namespace(ledger=args.ledger, min_age_minutes=90)
    )
    for item in [*validation_state["candidates"], *validation_state["unresolved"]]:
        if item.get("key") != intent_key:
            priorities.append({"kind": "validation_followup", "key": str(item.get("key") or "")})
    for item in validation_state.get("controllerReviewPending") or []:
        if item.get("key") != intent_key:
            priorities.append({"kind": "independent_review", "key": str(item.get("key") or "")})

    recovery_state = recovery_list(argparse.Namespace(ledger=args.ledger, min_age_minutes=90))
    for item in [*recovery_state["recoverable"], *recovery_state["unresolved"]]:
        if item.get("key") != intent_key:
            priorities.append({"kind": "recovery", "key": str(item.get("key") or "")})
    return priorities


def claim_intent(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    pending = {item["intentId"]: item for item in store.pending()}
    intent = pending.get(args.intent_id)
    if not intent:
        raise RuntimeError("intent is not pending")
    if not external_side_effect_allowed(intent):
        ManagedAdapter(ROOT, args.ledger).record_preflight_outcome(
            intent=intent,
            result_type="blocked_pre_task",
            reason="SILENT_EXPLORATION_NOT_DISPATCHABLE",
        )
        return {
            "ok": True,
            "authorized": False,
            "held": True,
            "claimed": False,
            "reason": "SILENT_EXPLORATION_NOT_DISPATCHABLE",
        }
    max_active = _private_task_limit()
    if (
        intent.get("mode") != "shadow"
        and max_active is not None
        and _active_task_count(store, exclude_intent_id=intent["intentId"]) >= max_active
    ):
        return {
            "ok": True,
            "authorized": False,
            "auditDeferred": True,
            "held": True,
            "claimed": False,
            "reason": "task_wip_limit",
        }
    if intent.get("mode") != "shadow":
        priority_work = _higher_priority_existing_work(args, intent_key=str(intent["key"]))
        if priority_work:
            return {
                "ok": True,
                "authorized": False,
                "auditDeferred": True,
                "held": True,
                "claimed": False,
                "reason": "higher_priority_existing_work",
                "priorityWork": priority_work,
            }
    evidence, verdict = _audit_intent(intent)
    historical_wrong_repo = _historical_wrong_repo_feedback(store, str(intent["key"]))
    if historical_wrong_repo is not None and verdict.status == "ALLOW":
        current_evidence = evidence.as_dict()
        current_issue = (
            current_evidence.get("issue")
            if isinstance(current_evidence.get("issue"), dict)
            else None
        )
        current_comments = current_evidence.get("comments")
        material_change = None
        if current_issue is not None and isinstance(current_comments, list):
            try:
                material_change = _wrong_repo_terminal_materially_changed(
                    GitHubClient(),
                    row=historical_wrong_repo,
                    issue=current_issue,
                    comments=current_comments,
                    live_sha=str(
                        current_evidence.get("liveBaseSha")
                        or current_evidence.get("live_base_sha")
                        or ""
                    ),
                )
            except (OSError, RuntimeError, ValueError):
                material_change = None
        if material_change is None:
            ManagedAdapter(ROOT, args.ledger).record_preflight_outcome(
                intent=intent,
                result_type="blocked_pre_task",
                reason="WRONG_REPO_RECHECK_INCOMPLETE",
                evidence=_audit_payload(evidence, verdict),
            )
            return {
                "ok": True,
                "authorized": False,
                "auditDeferred": True,
                "held": True,
                "claimed": False,
                "reason": "WRONG_REPO_RECHECK_INCOMPLETE",
            }
        if material_change is False:
            terminal_verdict = replace(verdict, status="BLOCK", reason_code="WRONG_REPO")
            ManagedAdapter(ROOT, args.ledger).record_preflight_outcome(
                intent=intent,
                result_type="task_no_go",
                reason="WRONG_REPO",
                evidence=_audit_payload(evidence, terminal_verdict),
            )
            store.record_stage(
                intent["key"],
                "AUDIT_NO_GO",
                evidence={
                    "authorization": terminal_verdict.as_dict(),
                    "evidence": current_evidence,
                    "historicalWrongRepoRevalidated": True,
                },
                reason="WRONG_REPO",
                dedupe_key=f"{intent['intentId']}:{evidence.digest}:wrong-repo-recheck",
            )
            return {
                "ok": True,
                "authorized": False,
                "claimed": False,
                "decision": terminal_verdict.as_dict(),
            }
    if verdict.status == "BLOCK":
        ManagedAdapter(ROOT, args.ledger).record_preflight_outcome(
            intent=intent,
            result_type=("state_drift" if verdict.reason_code == "STATE_DRIFT" else "task_no_go"),
            reason=verdict.reason_code,
            evidence=_audit_payload(evidence, verdict),
        )
        if verdict.reason_code == "STATE_DRIFT":
            recheck = store.invalidate_state_drift_intent(
                intent["key"],
                intent_id=intent["intentId"],
                evidence=evidence.as_dict(),
            )
            return {
                "ok": True,
                "authorized": False,
                "claimed": False,
                "recheckRequired": True,
                "scannerRecheck": recheck,
                "decision": verdict.as_dict(),
            }
        store.record_stage(
            intent["key"],
            "AUDIT_NO_GO",
            evidence={
                "authorization": verdict.as_dict(),
                "evidence": evidence.as_dict(),
            },
            reason=verdict.reason_code,
            dedupe_key=f"{intent['intentId']}:{evidence.digest}",
        )
        return {"ok": True, "authorized": False, "decision": verdict.as_dict()}
    if verdict.status != "ALLOW":
        ManagedAdapter(ROOT, args.ledger).record_preflight_outcome(
            intent=intent,
            result_type="blocked_pre_task",
            reason=verdict.reason_code,
            evidence=_audit_payload(evidence, verdict),
        )
        return {
            "ok": True,
            "authorized": False,
            "held": True,
            "decision": verdict.as_dict(),
        }
    try:
        target_base = _resolve_intent_target_base(intent, evidence)
    except TargetBranchError as exc:
        ManagedAdapter(ROOT, args.ledger).record_preflight_outcome(
            intent=intent,
            result_type="blocked_pre_task",
            reason="TARGET_BASE_UNRESOLVED",
            evidence=_audit_payload(evidence, verdict),
        )
        return {
            "ok": True,
            "authorized": False,
            "held": True,
            "claimed": False,
            "reason": "TARGET_BASE_UNRESOLVED",
            "error": str(exc)[:240],
            "decision": verdict.as_dict(),
        }
    store.record_stage(
        intent["key"],
        "AUDIT_PASS",
        evidence=_audit_payload(evidence, verdict, target_base),
        dedupe_key=f"{intent['intentId']}:{evidence.digest}:live-audit-v1",
    )
    probe = getattr(evidence, "repo_probe_receipt", None) or {}
    probe_level = str(probe.get("probeLevel") or "UNVERIFIED")
    task_stage = (
        "IMPLEMENTATION_READY" if probe_level == REPRODUCED_VALIDATED else "REPRODUCTION_REQUIRED"
    )
    store.update_intent_probe_metadata(
        intent["intentId"],
        probe_level=probe_level,
        task_stage=task_stage,
        receipt_digest=str(probe.get("receiptDigest") or ""),
        code_paths=list(probe.get("codePaths") or []),
    )
    if intent.get("mode") == "shadow":
        store.observe_shadow(
            intent["intentId"],
            evidence={
                "authorization": verdict.as_dict(),
                "evidenceDigest": evidence.digest,
            },
        )
        return {
            "ok": True,
            "authorized": True,
            "shadow": True,
            "decision": verdict.as_dict(),
        }
    claimed = store.claim(
        intent["intentId"],
        args.owner,
        lease_minutes=args.lease_minutes,
        max_active=max_active,
    )
    if not claimed:
        wip_limited = (
            max_active is not None
            and _active_task_count(store, exclude_intent_id=intent["intentId"]) >= max_active
        )
        return {
            "ok": True,
            "authorized": True,
            "claimed": False,
            "reason": "task_wip_limit" if wip_limited else "lease_unavailable",
        }
    result: dict[str, Any] = {
        "ok": True,
        "authorized": True,
        "claimed": True,
        "intentId": intent["intentId"],
        "leaseOwner": args.owner,
        "key": intent["key"],
        "prompt": issue_prompt(intent["issueUrl"]),
        "decision": verdict.as_dict(),
        "probeLevel": probe_level,
        "taskStage": task_stage,
        "reproductionRequired": task_stage == "REPRODUCTION_REQUIRED",
        "implementationAuthorized": task_stage == "IMPLEMENTATION_READY",
        "publicationAuthorized": False,
        "targetBase": target_base,
    }
    if args.prepare:
        try:
            path = source_repo(str(intent["repo"]), target_base=target_base)
            worktree = prepare_managed_worktree(
                path,
                intent_id=str(intent["intentId"]),
                repo=str(intent["repo"]),
                target_base=target_base,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            store.release_claim(
                intent["intentId"],
                owner=args.owner,
                reason=f"{type(exc).__name__}:{str(exc)[:240]}",
            )
            raise
        title_time = datetime.now().astimezone().strftime("%m-%d %H:%M")
        result["sourceRepoPath"] = str(path)
        result["taskProjectPath"] = str(GITHUB_ROOT.resolve())
        result["worktreePath"] = str(worktree)
        result["titleTime"] = title_time
        result["desiredTitle"] = lifecycle_title("GO", title_time, intent["key"], intent["title"])
        task_project_id = getattr(args, "task_project_id", None)
        if task_project_id:
            result["createThreadRequest"] = {
                "prompt": result["prompt"],
                "target": {
                    "type": "project",
                    "projectId": task_project_id,
                    "environment": {"type": "local"},
                },
            }
    return result


def _active_owner(store: RadarLedger, args: argparse.Namespace) -> str:
    return getattr(args, "owner", None) or store.current_lease_owner(args.intent_id)


def release_claim(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    released = store.release_claim(
        args.intent_id,
        owner=_active_owner(store, args),
        reason=args.reason,
    )
    if not released:
        raise RuntimeError("claim release authorization is stale or invalid")
    return {"ok": True, "intentId": args.intent_id, "released": True}


def reopen_false_terminal(args: argparse.Namespace) -> dict[str, Any]:
    allowed = {"AI_DISCLOSURE_REQUIRES_USER"}
    if args.expected_reason not in allowed:
        raise RuntimeError("terminal reason is not eligible for policy migration")
    store = ledger(args.ledger)
    store.reopen_false_terminal(
        args.key,
        expected_reason=args.expected_reason,
        migration_reason=args.migration_reason,
    )
    published, attempts = _publish_controller_feedback_updates(
        {
            args.key: {
                "status": "policy_migration_pending",
                "terminal_reason": args.migration_reason,
                "scanner_version": SCANNER_DECISION_REVISION,
                "analyzed": iso_z(datetime.now(UTC)),
            }
        }
    )
    return {
        "ok": True,
        "key": args.key,
        "stateChanged": published,
        "publishAttempts": attempts,
    }


def reopen_state_drift(args: argparse.Namespace) -> dict[str, Any]:
    """Reopen one historical pre-thread STATE_DRIFT misclassified as terminal."""

    store = ledger(args.ledger)
    recheck = store.invalidate_state_drift_intent(
        args.key,
        intent_id=args.intent_id,
        historical_terminal=True,
    )
    published, attempts = _publish_controller_feedback_updates(
        {
            args.key: {
                "analyzed": recheck["recordedAt"],
                "status": "state_drift",
                "controller_stage": None,
                "terminal_reason": None,
                "issue_updated": recheck.get("issueUpdatedAt"),
                "scanner_version": SCANNER_DECISION_REVISION,
                "decision_contract_digest": decision_contract_digest(),
                "source_intent_id": args.intent_id,
                "stale_base_sha": recheck.get("staleBaseSha"),
                "live_base_sha": recheck.get("liveBaseSha"),
            }
        }
    )
    return {
        "ok": True,
        "key": args.key,
        "intentId": args.intent_id,
        "recheckRequired": True,
        "ledgerChanged": recheck["changed"],
        "stateChanged": published,
        "publishAttempts": attempts,
    }


def git_path(*args: str, cwd: Path) -> Path:
    return Path(command(["git", *args], cwd=cwd)).resolve()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _atomic_private_json(
    path: Path, value: dict[str, Any], *, directory_fd: int | None = None
) -> None:
    """Persist private quarantine evidence with exact raw bytes embedded."""

    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    owns_directory = directory_fd is None
    if owns_directory:
        directory_fd, _ = open_directory_handle(
            path.parent, label="context quarantine", create=True
        )
    assert directory_fd is not None
    temporary_name = f".context-quarantine-{os.getpid()}-{time.time_ns()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        if owns_directory:
            os.close(directory_fd)


def _atomic_shared_context_json(issue_url: str, value: dict[str, Any]) -> Path:
    context_fd, context_parent, handles = _open_shared_context_parent(issue_url, create=True)
    path = context_parent / _canonical_shared_context_relative_path(issue_url).name
    try:
        _atomic_private_json(path, value, directory_fd=context_fd)
        return path
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _shared_context_quarantine_reason(exc: BaseException) -> str:
    message = str(exc)
    if "legacy and v2 context bytes conflict" in message:
        return "SHARED_CONTEXT_LAYOUT_CONFLICT"
    if "digest mismatch" in message:
        return "SHARED_CONTEXT_DIGEST_MISMATCH"
    if "bootstrap path" in message:
        return "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID"
    return "SHARED_CONTEXT_INVALID"


def _shared_context_identity_from_filename(path: Path, raw: bytes) -> tuple[str, str] | None:
    """Derive identity from trusted bytes and a one-to-one filename binding."""

    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    issue_url = str(value.get("issueUrl") or "")
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None or not _shared_context_path_matches(path, issue_url):
        return None
    repo, issue_number = match.groups()
    if value.get("key") != f"{repo}#{issue_number}":
        return None
    return f"{repo}#{issue_number}", issue_url


def _ensure_context_quarantine_artifact(
    artifact_path: Path,
    *,
    key: str,
    issue_url: str,
    reason: str,
    source_path: Path,
    raw: bytes,
    source_digest: str,
    source_mode: int,
    error: str,
) -> dict[str, Any]:
    """Create once, then only verify a quarantine artifact under a file lock."""

    if artifact_path.parent != shared_context_quarantine_root():
        raise RuntimeError("context quarantine artifact path is outside the private root")
    parent_fd, _parent_path, handles = _open_shared_context_quarantine_directory(create=True)
    lock_name = ".context-quarantine.lock"
    lock_fd = -1
    try:
        for attempt in range(20):
            try:
                lock_fd = os.open(
                    lock_name,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                break
            except FileNotFoundError:
                if attempt == 19:
                    raise
                time.sleep(0.001)
    except Exception:
        for fd in reversed(handles):
            os.close(fd)
        raise
    try:
        lock_stat = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.getuid()
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
        ):
            raise RuntimeError("context quarantine lock is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            artifact_stat = os.stat(artifact_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            artifact_stat = None
        if artifact_stat is not None:
            if (
                stat.S_ISLNK(artifact_stat.st_mode)
                or not stat.S_ISREG(artifact_stat.st_mode)
                or artifact_stat.st_uid != os.getuid()
                or stat.S_IMODE(artifact_stat.st_mode) != 0o600
            ):
                raise RuntimeError("shared context quarantine artifact is not a regular file")
            artifact_fd = -1
            try:
                artifact_fd = os.open(
                    artifact_path.name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                first = os.fstat(artifact_fd)
                if (
                    not stat.S_ISREG(first.st_mode)
                    or first.st_uid != os.getuid()
                    or stat.S_IMODE(first.st_mode) != 0o600
                ):
                    raise RuntimeError("shared context quarantine artifact is unsafe")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(artifact_fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                second = os.fstat(artifact_fd)
                if (
                    first.st_dev,
                    first.st_ino,
                    first.st_size,
                    first.st_mtime_ns,
                    first.st_ctime_ns,
                ) != (
                    second.st_dev,
                    second.st_ino,
                    second.st_size,
                    second.st_mtime_ns,
                    second.st_ctime_ns,
                ):
                    raise RuntimeError("shared context quarantine artifact changed while reading")
                artifact = json.loads(b"".join(chunks).decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as artifact_exc:
                raise RuntimeError(
                    "shared context quarantine artifact is invalid"
                ) from artifact_exc
            finally:
                if artifact_fd >= 0:
                    os.close(artifact_fd)
            if not isinstance(artifact, dict):
                raise RuntimeError("shared context quarantine artifact is invalid")
            if any(
                artifact.get(name) != expected
                for name, expected in {
                    "schemaVersion": "shared-context-quarantine-v1",
                    "key": key,
                    "issueUrl": issue_url,
                    "reason": reason,
                    "originalPath": str(source_path),
                    "originalBytesSha256": source_digest,
                }.items()
            ):
                raise RuntimeError("shared context quarantine artifact binding changed")
            try:
                encoded_original = base64.b64decode(
                    str(artifact.get("originalBytesBase64") or ""), validate=True
                )
            except (ValueError, TypeError) as artifact_exc:
                raise RuntimeError(
                    "shared context quarantine artifact bytes are invalid"
                ) from artifact_exc
            if encoded_original != raw:
                raise RuntimeError("shared context quarantine artifact bytes changed")
            if not isinstance(artifact.get("observedAt"), str) or not artifact["observedAt"]:
                raise RuntimeError("shared context quarantine artifact timestamp is invalid")
            return artifact
        artifact = {
            "schemaVersion": "shared-context-quarantine-v1",
            "key": key,
            "issueUrl": issue_url,
            "reason": reason,
            "error": error,
            "originalPath": str(source_path),
            "originalMode": source_mode,
            "originalBytesSha256": source_digest,
            "originalBytesBase64": base64.b64encode(raw).decode("ascii"),
            "observedAt": iso_z(datetime.now(UTC)),
        }
        _atomic_private_json(artifact_path, artifact, directory_fd=parent_fd)
        return artifact
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
            for fd in reversed(handles):
                os.close(fd)


def _quarantine_shared_context(
    store: RadarLedger,
    path: Path,
    exc: BaseException,
    *,
    raw: bytes | None = None,
    source_stat: os.stat_result | None = None,
) -> dict[str, Any] | None:
    """Persist one untrusted context without allowing it into the queue."""

    if raw is None or source_stat is None:
        raw, source_stat, path = _read_shared_context_file(path)
    identity = _shared_context_identity_from_filename(path, raw)
    if identity is None:
        return None
    source_digest = hashlib.sha256(raw).hexdigest()
    key, issue_url = identity
    reason = _shared_context_quarantine_reason(exc)
    dedupe_key = hashlib.sha256(
        f"shared-context|{path}|{source_digest}|{reason}".encode("utf-8")
    ).hexdigest()
    if re.fullmatch(r"[A-Z0-9_]+", reason) is None:
        raise RuntimeError("shared context quarantine reason is unsafe")
    artifact_identity = sha256_json(
        {
            "key": key,
            "reason": reason,
            "originalPath": str(path),
            "originalBytesSha256": source_digest,
        }
    )
    artifact_path = shared_context_quarantine_root() / f"q-{artifact_identity}.json"
    with opportunity_action_guard(ledger_action_guard_root(store.path), key):
        artifact = _ensure_context_quarantine_artifact(
            artifact_path,
            key=key,
            issue_url=issue_url,
            reason=reason,
            source_path=path,
            raw=raw,
            source_digest=source_digest,
            source_mode=source_stat.st_mode & 0o777,
            error=str(exc)[:500],
        )
        persisted = store._record_shared_context_quarantine(
            key=key,
            reason=reason,
            dedupe_key=dedupe_key,
            payload={
                "issueUrl": issue_url,
                "originalPath": str(path),
                "originalBytesSha256": source_digest,
                "artifactPath": str(artifact_path),
                "error": str(exc)[:500],
            },
            created_at=artifact["observedAt"],
        )
    return {
        "key": key,
        "issueUrl": issue_url,
        "path": str(path),
        "reason": reason,
        "artifactPath": str(artifact_path),
        "originalBytesSha256": source_digest,
        "new": bool(persisted.get("created")),
    }


def _exclude_private_task_dir(worktree: Path) -> None:
    raw = command(["git", "rev-parse", "--git-path", "info/exclude"], cwd=worktree)
    exclude = Path(raw)
    if not exclude.is_absolute():
        exclude = (worktree / exclude).resolve()
    exclude.parent.mkdir(parents=True, exist_ok=True)
    existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
    rule = f"/{TASK_PRIVATE_DIR}/"
    if rule not in {line.strip() for line in existing.splitlines()}:
        with exclude.open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith("\n"):
                handle.write("\n")
            handle.write(rule + "\n")


def _task_context_digest(context: dict[str, Any], prepared_head: str | None) -> str:
    return sha256_json(_task_context_digest_payload(context, prepared_head))


def write_task_context(
    store: RadarLedger,
    *,
    issue_url: str,
    thread_id: str,
    cwd: Path,
    prepared_followup_head: str | None = None,
) -> Path:
    context = store.task_context(
        issue_url=issue_url,
        thread_id=thread_id,
        worktree_path=str(cwd.resolve()),
    )
    if context is None:
        raise RuntimeError("registered task context is unavailable")
    # Keep the binding explicit in the serialized context even when the
    # current ledger predates target-base storage and the value is null.
    context["targetBase"] = context.get("targetBase")
    live_audit = context.get("liveAudit")
    if not isinstance(live_audit, dict) or not isinstance(live_audit.get("evidence"), dict):
        raise RuntimeError("registered task context is missing controller live audit")
    followup = context.get("prFollowup")
    bound_prepared_head = (
        str(followup.get("preparedHeadSha"))
        if isinstance(followup, dict) and followup.get("preparedHeadSha")
        else None
    )
    if (
        prepared_followup_head is not None
        and bound_prepared_head is not None
        and prepared_followup_head != bound_prepared_head
    ):
        raise RuntimeError("prepared PR follow-up head disagrees with the ledger")
    effective_prepared_head = prepared_followup_head or bound_prepared_head
    if effective_prepared_head is not None:
        if not isinstance(followup, dict) or not re.fullmatch(
            r"[0-9a-f]{40}", effective_prepared_head
        ):
            raise RuntimeError("prepared PR follow-up head is invalid")
        context["prFollowup"] = dict(followup) | {
            "preparedHeadSha": effective_prepared_head,
        }
    if context.get("targetBase") is not None:
        target_base = validate_target_base(context["targetBase"])
        command(["git", "cat-file", "-e", f"{target_base['sha']}^{{commit}}"], cwd=cwd)
        if context.get("stage") == "DISPATCHED" and not isinstance(followup, dict):
            if command(["git", "rev-parse", "HEAD"], cwd=cwd).casefold() != target_base["sha"]:
                raise RuntimeError("new task worktree does not start at its audited target base")
        command(
            ["git", "merge-base", "--is-ancestor", target_base["sha"], "HEAD"],
            cwd=cwd,
        )
    _exclude_private_task_dir(cwd)
    private_dir = cwd / TASK_PRIVATE_DIR
    private_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    path = private_dir / "task-context.json"
    prior_context: dict[str, Any] = {}
    if path.is_file() and not path.is_symlink():
        try:
            prior_value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior_value = {}
        if isinstance(prior_value, dict):
            prior_context = prior_value
    managed = _is_managed_worktree(cwd)
    project_root = GITHUB_ROOT.resolve() if managed else cwd.resolve()
    raw_task_stage = str(context.get("taskStage") or "REPRODUCTION_REQUIRED")
    raw_probe_level = str(context.get("probeLevel") or "UNVERIFIED")
    managed_ledger = ManagedLedger(store.path, ensure_schema=True)
    managed_task = managed_ledger.read_task(str(context.get("intentId") or ""))
    managed_provenance: dict[str, Any] = {}
    if managed_task and managed_task.get("readSource") == "managed":
        try:
            managed_provenance = json.loads(managed_task.get("provenance_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            managed_provenance = {}
    verified_receipt = None
    issue_match = ISSUE_URL.fullmatch(issue_url)
    if issue_match is None:
        raise RuntimeError("issue URL is invalid")
    repo_identity = issue_match.group(1)
    if managed_task and managed_task.get("state") == "IMPLEMENTATION_READY":
        managed_receipt = managed_provenance.get("probeReceipt")
        if isinstance(managed_receipt, dict):
            verified_receipt = managed_ledger.implementation_authorization_receipt(
                task_id=str(context.get("intentId") or ""),
                thread_id=thread_id,
                worktree_path=str(cwd.resolve()),
                repo=repo_identity,
                issue_url=issue_url,
                receipt_digest=str(managed_receipt.get("receiptDigest") or ""),
            )
            if verified_receipt is not None:
                context["selectedBaseSha"] = verified_receipt["baseSha"]
                context["codePaths"] = verified_receipt["codePaths"]
                context["headSha"] = verified_receipt["headSha"]
                context["commitSha"] = verified_receipt["commitSha"]
                context["resultDigest"] = verified_receipt["resultDigest"]
    if verified_receipt is not None:
        context["reproductionReceipt"] = verified_receipt
        raw_task_stage = "IMPLEMENTATION_READY"
        raw_probe_level = REPRODUCED_VALIDATED
    else:
        raw_task_stage = "REPRODUCTION_REQUIRED"
        raw_probe_level = "UNVERIFIED"
    task_stage = raw_task_stage
    reproduction_only = task_stage == "REPRODUCTION_REQUIRED"
    allowed_actions = (
        ["read_issue", "read_repo", "run_reproduction_probe", "write_structured_result"]
        if reproduction_only
        else ["read_issue", "read_repo", "edit_files", "run_tests", "write_structured_result"]
    )
    payload = {
        "schemaVersion": TASK_CONTEXT_SCHEMA,
        **context,
        "resultPath": str((private_dir / "result.json").resolve()),
        "taskProjectRoot": str(project_root),
        "workspaceMode": "github_project_managed_worktree" if managed else "codex_worktree",
        "controllerOwnsLifecycle": True,
        "controllerOwnsPublication": True,
        "controllerOwnsCommit": True,
        "externalLedgerAccessAllowed": False,
        "planHubRequired": False,
        "networkPolicy": "controller_snapshot_only",
        "childMayRequestApproval": False,
        "childMayWriteGitMetadata": False,
        "taskStage": task_stage,
        "probeLevel": raw_probe_level,
        "allowedActions": allowed_actions,
        "taskMode": "reproduction_only" if reproduction_only else "implementation",
        "childMayEditFiles": not reproduction_only,
        "childMayCommit": False,
        "childMayPush": False,
        "childMayCreatePR": False,
        "childMayComment": False,
    }
    payload["contextDigest"] = _task_context_digest(context, effective_prepared_head)
    bootstrap_path = None
    if managed:
        context_fd, context_parent, context_handles = _open_shared_context_parent(
            issue_url, create=True
        )
        bootstrap_path = context_parent / _canonical_shared_context_relative_path(issue_url).name
        payload["bootstrapContextPath"] = str(bootstrap_path)
    try:
        _atomic_json(path, payload)
        if bootstrap_path is not None:
            _atomic_private_json(bootstrap_path, payload, directory_fd=context_fd)
    finally:
        if bootstrap_path is not None:
            for fd in reversed(context_handles):
                os.close(fd)
    prior_result_digest = prior_context.get("resultDigest")
    repaired_same_result = (
        not reproduction_only
        and prior_context.get("taskStage") == "REPRODUCTION_REQUIRED"
        and prior_context.get("childMayEditFiles") is False
        and prior_context.get("intentId") == payload.get("intentId")
        and prior_context.get("threadId") == payload.get("threadId")
        and bool(prior_context.get("worktreePath"))
        and Path(str(prior_context.get("worktreePath") or "")).resolve() == cwd.resolve()
        and (not prior_result_digest or prior_result_digest == payload.get("resultDigest"))
        and bool(payload.get("resultDigest"))
    )
    if repaired_same_result:
        store.record_implementation_context_repair(
            key=str(payload.get("key") or ""),
            task_id=str(payload.get("intentId") or ""),
            thread_id=thread_id,
            worktree_path=str(cwd.resolve()),
            result_digest=str(payload["resultDigest"]),
            context_digest=str(payload["contextDigest"]),
        )
    return path


def _managed_bind_legacy_intent(
    store: RadarLedger,
    path: Path,
    intent_id: str,
    *,
    worktree_path: str | None = None,
) -> None:
    with store.connect() as connection:
        row = connection.execute("SELECT * FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
    if row is None:
        raise RuntimeError("legacy intent disappeared before managed binding")
    intent = dict(row)
    issue_key = str(intent["opportunity_key"])
    thread_id = str(intent.get("client_thread_id") or intent.get("thread_id") or "")
    if not thread_id:
        raise RuntimeError("managed task binding requires the actual Codex thread id")
    adapter = ManagedAdapter(ROOT, path)
    payload = json.loads(intent["payload_json"])
    managed_intent = payload | {
        "intentId": intent_id,
        "key": issue_key,
        "issuedAt": intent.get("issued_at"),
        "preTaskEvidenceDigest": payload.get("preTaskEvidenceDigest"),
        "probeLevel": payload.get("probeLevel", "UNVERIFIED"),
        "taskStage": payload.get("taskStage", "REPRODUCTION_REQUIRED"),
    }
    try:
        adapter.bind_task_after_thread(
            intent=managed_intent,
            thread_id=thread_id,
            worktree_path=worktree_path or intent.get("worktree_path"),
        )
    except Exception as exc:
        adapter.ledger.record_event(
            event_type="TASK_BIND_RECONCILIATION_REQUIRED",
            idempotency_key=f"task-bind-reconcile:{intent_id}:{thread_id}",
            opportunity_key=issue_key,
            source="dispatch-thread-bind",
            provenance={"threadId": thread_id, "intentId": intent_id},
            payload={"error": f"{type(exc).__name__}:{str(exc)[:240]}"},
        )
        raise


def creation_start(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    result = store.reserve_creation(args.intent_id, owner=_active_owner(store, args))
    return {"ok": True} | result


def creation_bind(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    result = store.bind_creation_client(
        args.intent_id,
        owner=_active_owner(store, args),
        creation_token=args.creation_token,
        client_thread_id=args.client_thread_id,
    )
    _managed_bind_legacy_intent(store, args.ledger, args.intent_id)
    return {"ok": True} | result


def creation_cancel(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    store.cancel_creation(
        args.intent_id,
        owner=_active_owner(store, args),
        creation_token=args.creation_token,
        reason=args.reason,
    )
    return {"ok": True, "intentId": args.intent_id, "cancelled": True}


def creation_abandon(args: argparse.Namespace) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", args.reason):
        raise RuntimeError("abandon reason must be machine-readable")
    result = orphan_list(args)
    unmatched = {item["intentId"]: item for item in result["unmatched"]}
    candidate = unmatched.get(args.intent_id)
    if not candidate or not candidate.get("abandonable"):
        raise RuntimeError("creation is not safely abandonable")
    if candidate.get("abandonNonce") != args.abandon_nonce:
        raise RuntimeError("creation abandonment authorization is stale or invalid")
    if candidate.get("clientThreadId") != args.client_thread_id:
        raise RuntimeError("creation client thread id changed")
    store = ledger(args.ledger)
    handoffs = {item["intentId"]: item for item in store.orphaned_handoffs()}
    handoff = handoffs.get(args.intent_id)
    if not handoff or not handoff.get("creationToken"):
        raise RuntimeError("stored creation authorization is unavailable")
    store.abandon_creation(
        args.intent_id,
        owner=_active_owner(store, args),
        creation_token=handoff["creationToken"],
        client_thread_id=args.client_thread_id,
        reason=args.reason,
        min_age_minutes=args.min_age_minutes,
    )
    return {
        "ok": True,
        "intentId": args.intent_id,
        "clientThreadId": args.client_thread_id,
        "abandoned": True,
    }


def _app_server_terminal_turn(
    message: dict[str, Any],
    *,
    thread_id: str,
    turn_id: str,
    read_request_id: int | None = None,
) -> dict[str, Any] | None:
    """Extract the target turn once app-server reports a terminal state."""

    turn: dict[str, Any] | None = None
    if message.get("method") == "turn/completed":
        params = message.get("params") or {}
        if str(params.get("threadId") or "") != thread_id:
            return None
        candidate = params.get("turn")
        if isinstance(candidate, dict):
            turn = candidate
    elif read_request_id is not None and message.get("id") == read_request_id:
        thread = (message.get("result") or {}).get("thread") or {}
        if str(thread.get("id") or "") != thread_id:
            return None
        turns = thread.get("turns") or []
        turn = next(
            (
                candidate
                for candidate in turns
                if isinstance(candidate, dict) and str(candidate.get("id") or "") == turn_id
            ),
            None,
        )
    if not turn or str(turn.get("id") or "") != turn_id:
        return None
    status = str(turn.get("status") or "")
    if status not in {"completed", "interrupted", "failed"}:
        return None
    return {"turnId": turn_id, "status": status, "error": turn.get("error")}


def _wait_for_app_server_terminal_turn(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    buffer: bytes,
    *,
    thread_id: str,
    turn_id: str,
    next_request_id: int = 3,
) -> dict[str, Any] | None:
    """Keep an app-server owner alive while independently polling turn state."""

    if process.stdin is None or process.stdout is None:
        return None
    read_request_id: int | None = None
    read_requested_at: float | None = None
    watch_started_at = monotonic()
    next_read_at = watch_started_at + APP_SERVER_WATCHDOG_INTERVAL_SECONDS
    next_external_probe_at = watch_started_at + APP_SERVER_WATCHDOG_EXTERNAL_PROBE_SECONDS
    next_live_probe_at = watch_started_at + APP_SERVER_WATCHDOG_LIVE_PROBE_SECONDS
    task_deadline = watch_started_at + APP_SERVER_TASK_TURN_MAX_SECONDS
    while True:
        # A very short turn can finish in the same read that returned the
        # turn/start response. Consume those already-buffered notifications
        # before waiting for another app-server event.
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            terminal = _app_server_terminal_turn(
                message,
                thread_id=thread_id,
                turn_id=turn_id,
                read_request_id=read_request_id,
            )
            if read_request_id is not None and message.get("id") == read_request_id:
                read_request_id = None
                read_requested_at = None
            if terminal:
                return terminal
        if process.poll() is not None:
            break
        now = monotonic()
        if now >= task_deadline:
            return {
                "turnId": turn_id,
                "status": "interrupted",
                "error": {"message": "task-turn worker exceeded its maximum runtime"},
            }
        request_stale = (
            read_request_id is not None
            and read_requested_at is not None
            and now - read_requested_at >= APP_SERVER_WATCHDOG_STALE_SECONDS
        )
        if now >= next_external_probe_at:
            independently_observed = persisted_thread_turn_state(thread_id)
            next_external_probe_at = monotonic() + APP_SERVER_WATCHDOG_EXTERNAL_PROBE_SECONDS
            if (
                independently_observed
                and independently_observed.get("turnId") == turn_id
                and independently_observed.get("status") in {"completed", "interrupted", "failed"}
            ):
                return {
                    "turnId": turn_id,
                    "status": independently_observed["status"],
                    "error": independently_observed.get("error"),
                }
            if now >= next_live_probe_at and request_stale:
                live_observed = live_thread_turn_states({thread_id}).get(thread_id)
                next_live_probe_at = monotonic() + APP_SERVER_WATCHDOG_LIVE_RETRY_SECONDS
                if (
                    live_observed
                    and live_observed.get("turnId") == turn_id
                    and live_observed.get("status") in {"completed", "interrupted", "failed"}
                ):
                    return {
                        "turnId": turn_id,
                        "status": live_observed["status"],
                        "error": live_observed.get("error"),
                    }
        if now >= next_read_at and (read_request_id is None or request_stale):
            read_request_id = next_request_id
            next_request_id += 1
            read_requested_at = now
            process.stdin.write(
                (
                    json.dumps(
                        {
                            "id": read_request_id,
                            "method": "thread/read",
                            "params": {"threadId": thread_id, "includeTurns": True},
                        }
                    )
                    + "\n"
                ).encode("utf-8")
            )
            process.stdin.flush()
            next_read_at = now + APP_SERVER_WATCHDOG_INTERVAL_SECONDS

        timeout = min(
            APP_SERVER_EVENT_DRAIN_SLICE_SECONDS,
            max(0.0, next_read_at - monotonic()),
        )
        ready = selector.select(timeout)
        if not ready:
            continue
        chunk = os.read(process.stdout.fileno(), 65536)
        if not chunk:
            break
        buffer += chunk
    return None


def _app_server_request_worker(args: argparse.Namespace) -> dict[str, Any]:
    """Create a project-root task without the delegated subagent API."""

    store = ledger(args.ledger)
    pending = {item["intentId"]: item for item in store.pending()}
    intent = pending.get(args.intent_id)
    if not intent:
        raise RuntimeError("intent is not pending")
    prompt = issue_prompt(intent["issueUrl"])
    executable = shutil.which("codex")
    if not executable:
        raise RuntimeError("codex executable is unavailable")
    match = ISSUE_URL.fullmatch(str(intent.get("issueUrl") or ""))
    if match is None:
        raise RuntimeError("intent issue URL is invalid")
    opportunity_key = f"{match.group(1)}#{match.group(2)}"
    process = None
    thread_id = ""
    turn_id = ""
    buffer = b""
    selector = selectors.DefaultSelector()
    try:
        with _app_server_action_session(
            store,
            opportunity_key=opportunity_key,
            argv=[
                executable,
                "app-server",
                "--disable",
                "recommended_plugins",
                "--disable",
                "remote_plugin",
                "--stdio",
            ],
            cwd=GITHUB_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        ) as started_process:
            process = started_process
            if process.stdin is None or process.stdout is None:
                raise RuntimeError("app server pipes are unavailable")
            selector.register(process.stdout, selectors.EVENT_READ)
            process.stdin.write(
                b"".join(
                    (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
                    for item in (
                        {
                            "id": 0,
                            "method": "initialize",
                            "params": {
                                "clientInfo": {"name": "oss-pr-radar", "version": "1.0"},
                                "capabilities": {"experimentalApi": True},
                            },
                        },
                        {
                            "id": 1,
                            "method": "thread/start",
                            "params": {
                                "cwd": str(GITHUB_ROOT.resolve()),
                                "sandbox": "danger-full-access",
                                "approvalPolicy": "never",
                                "threadSource": "appServer",
                            },
                        },
                    )
                )
            )
            process.stdin.flush()
            buffer, message = _read_app_server_response(
                process,
                selector,
                buffer,
                response_id=1,
                timeout=ROOT_THREAD_START_TIMEOUT_SECONDS,
                action="thread/start",
            )
            thread_id = str(((message.get("result") or {}).get("thread") or {}).get("id") or "")
            if not thread_id:
                raise RuntimeError("app server did not create a root task")
            store.bind_creation_client(
                args.intent_id,
                owner=_active_owner(store, args),
                creation_token=args.creation_token,
                client_thread_id=thread_id,
            )
            _managed_bind_legacy_intent(
                store,
                args.ledger,
                args.intent_id,
                worktree_path=args.worktree,
            )
            _require_task_action_clear(store, opportunity_key)
            _write_turn_start_request(
                process,
                thread_id=thread_id,
                cwd=GITHUB_ROOT,
                prompt=prompt,
            )
        buffer, message = _read_app_server_response(
            process,
            selector,
            buffer,
            response_id=2,
            timeout=ROOT_TURN_START_TIMEOUT_SECONDS,
            action="turn/start",
        )
        turn_id = str(((message.get("result") or {}).get("turn") or {}).get("id") or "")
        if not turn_id:
            raise RuntimeError("app server did not start the root task turn")

        deadline = monotonic() + ROOT_TASK_INDEX_WAIT_SECONDS
        while monotonic() < deadline:
            connection = sqlite3.connect(THREAD_DB)
            try:
                row = connection.execute(
                    "SELECT first_user_message FROM threads WHERE id=?", (thread_id,)
                ).fetchone()
            finally:
                connection.close()
            if row and canonical_prompt(str(row[0] or "")) == prompt:
                break
            sleep(0.25)
        else:
            raise RuntimeError("root task was not persisted in the desktop index")

        receipt = commit_receipt(
            argparse.Namespace(
                ledger=args.ledger,
                intent_id=args.intent_id,
                owner=_active_owner(store, args),
                thread_id=thread_id,
                project_id=args.project_id,
                cwd=str(GITHUB_ROOT.resolve()),
                worktree=args.worktree,
                source_repo=args.source_repo,
                title_time=args.title_time,
            )
        )
        _atomic_json(Path(args.receipt), {"ok": True, "turnId": turn_id} | receipt)

        terminal = _wait_for_app_server_terminal_turn(
            process,
            selector,
            buffer,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        if terminal:
            return {
                "ok": True,
                "threadId": thread_id,
                "turnId": turn_id,
                "turnStatus": terminal["status"],
            }
        return {"ok": True, "threadId": thread_id, "turnId": turn_id}
    except Exception as exc:
        receipt_path = Path(args.receipt)
        if not receipt_path.exists():
            _atomic_json(
                receipt_path,
                {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:300]}"},
            )
        raise
    finally:
        selector.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def root_task_create(args: argparse.Namespace) -> dict[str, Any]:
    receipt_root = STATE / "root_task_receipts"
    receipt = receipt_root / f"{args.creation_token}.json"
    launch = receipt_root / f"{args.creation_token}.launch.json"
    receipt.unlink(missing_ok=True)
    launch.unlink(missing_ok=True)
    log = receipt_root / f"{args.creation_token}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as handle:
        worker = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--ledger",
                str(args.ledger),
                "--runtime-root",
                str(args.runtime_root),
                "root-task-worker",
                "--intent-id",
                args.intent_id,
                "--creation-token",
                args.creation_token,
                "--project-id",
                args.project_id,
                "--source-repo",
                args.source_repo,
                "--worktree",
                args.worktree,
                "--title-time",
                args.title_time,
                "--receipt",
                str(receipt),
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    _atomic_json(
        launch,
        {
            "pid": worker.pid,
            "startedAt": iso_z(datetime.now(UTC)),
            "intentId": args.intent_id,
            "creationToken": args.creation_token,
        },
    )
    deadline = monotonic() + ROOT_TASK_RECEIPT_WAIT_SECONDS
    while monotonic() < deadline:
        if receipt.exists():
            result = read_json(receipt, missing={})
            if not result.get("ok"):
                raise RuntimeError(str(result.get("error") or "root task creation failed"))
            return result
        sleep(0.25)
    if receipt.exists():
        result = read_json(receipt, missing={})
        if not result.get("ok"):
            raise RuntimeError(str(result.get("error") or "root task creation failed"))
        return result
    raise RuntimeError("root task creation result is unknown; orphan reconciliation required")


def _codex_decision_prompt(event: dict[str, Any]) -> str:
    issue_url = _issue_url_from_key(str(event.get("candidateKey") or ""))
    return "\n".join(
        (
            "这是 OSS PR Radar 创建的候选决策会话，不是代码实施任务。",
            "",
            f"候选：{issue_url}",
            f"事项：{event['title']}",
            f"当前原因：{event['reason']}",
            f"建议下一步：{event['nextAction']}",
            "",
            "请读取完整 issue、评论、仓库规则和相关 PR，给出简短中文建议，并明确需要用户决定什么。",
            "不要创建子任务、子 Agent 或委派其他会话；只在当前会话内完成这次只读判断。",
            "不要修改代码、公开评论或创建 PR。若涉及公开披露 AI 使用，只准备私下措辞并等待用户确认。",
        )
    )


def _issue_url_from_key(key: str) -> str:
    match = re.fullmatch(
        rf"({GITHUB_ID_SEGMENT.pattern}/{GITHUB_ID_SEGMENT.pattern})#([1-9][0-9]{{0,9}})",
        key,
    )
    if match is None:
        raise RuntimeError("Codex decision candidate key is invalid")
    return f"https://github.com/{match.group(1)}/issues/{match.group(2)}"


def _codex_decision_title(event: dict[str, Any], title_time: str) -> str:
    return compact_title(
        f"[有价值·待决策] {title_time} {event['candidateKey']} {str(event['title']).strip()}"
    )


def _codex_decision_bindings_path() -> Path:
    return STATE / "codex_decision_sessions.json"


def _read_codex_decision_bindings() -> dict[str, Any]:
    value = read_json(
        _codex_decision_bindings_path(),
        missing={"schema": CODEX_DECISION_BINDINGS_SCHEMA, "events": {}},
    )
    if (
        not isinstance(value, dict)
        or value.get("schema") != CODEX_DECISION_BINDINGS_SCHEMA
        or not isinstance(value.get("events"), dict)
    ):
        raise RuntimeError("local Codex decision bindings are invalid")
    return value


def _record_codex_decision_binding(event_id: str, binding: dict[str, Any]) -> None:
    path = _codex_decision_bindings_path()
    lock_path = path.with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        value = _read_codex_decision_bindings()
        events = dict(value["events"])
        events[event_id] = binding
        atomic_write_json(path, {"schema": CODEX_DECISION_BINDINGS_SCHEMA, "events": events})


def _codex_decision_thread(thread_id: str) -> dict[str, Any] | None:
    if not THREAD_DB.is_file():
        return None
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            """SELECT title,archived,first_user_message,cwd,project_id,thread_source
               FROM threads WHERE id=?""",
            (thread_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return None
    return {
        "title": str(row[0] or ""),
        "archived": int(row[1] or 0),
        "prompt": canonical_prompt(str(row[2] or "")),
        "cwd": str(row[3] or ""),
        "projectId": str(row[4]) if row[4] is not None else None,
        "threadSource": str(row[5] or ""),
    }


def _codex_decision_thread_matches(
    thread: dict[str, Any],
    *,
    prompt: str,
    project_id: str,
    require_unarchived: bool,
) -> bool:
    try:
        cwd = Path(str(thread.get("cwd") or "")).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return (
        cwd == GITHUB_ROOT.resolve()
        and thread.get("threadSource") == "appServer"
        and thread.get("projectId") in {None, "", project_id}
        and (not require_unarchived or int(thread.get("archived") or 0) == 0)
        and canonical_prompt(str(thread.get("prompt") or "")) == canonical_prompt(prompt)
    )


def _recover_codex_decision_thread(prompt: str, *, project_id: str) -> str | None:
    if not THREAD_DB.is_file():
        return None
    connection = sqlite3.connect(THREAD_DB)
    try:
        rows = connection.execute(
            """SELECT id,title,archived,first_user_message,cwd,project_id,thread_source
               FROM threads
               WHERE archived=0 AND cwd=? AND first_user_message=?
                 AND thread_source='appServer'
                 AND (project_id IS NULL OR project_id=?)
               ORDER BY updated_at DESC LIMIT 5""",
            (str(GITHUB_ROOT.resolve()), prompt, project_id),
        ).fetchall()
    finally:
        connection.close()
    return next(
        (
            str(row[0])
            for row in rows
            if _codex_decision_thread_matches(
                {
                    "title": str(row[1] or ""),
                    "archived": int(row[2] or 0),
                    "prompt": canonical_prompt(str(row[3] or "")),
                    "cwd": str(row[4] or ""),
                    "projectId": str(row[5]) if row[5] is not None else None,
                    "threadSource": str(row[6] or ""),
                },
                prompt=prompt,
                project_id=project_id,
                require_unarchived=True,
            )
        ),
        None,
    )


def _existing_codex_decision_binding(
    event: dict[str, Any], *, project_id: str
) -> dict[str, Any] | None:
    event_id = str(event["eventId"])
    prompt = _codex_decision_prompt(event)
    prompt_digest = sha256_json(canonical_prompt(prompt))
    stored = (_read_codex_decision_bindings().get("events") or {}).get(event_id)
    if isinstance(stored, dict):
        thread_id = str(stored.get("threadId") or "")
        thread = _codex_decision_thread(thread_id)
        if (
            thread is not None
            and _codex_decision_thread_matches(
                thread,
                prompt=prompt,
                project_id=project_id,
                require_unarchived=False,
            )
            and stored.get("candidateKey") == event.get("candidateKey")
            and stored.get("notificationDigest") == event.get("notificationDigest")
            and stored.get("projectId") == project_id
            and stored.get("promptDigest") == prompt_digest
        ):
            return stored
    recovered = _recover_codex_decision_thread(prompt, project_id=project_id)
    if recovered is None:
        return None
    title_time = datetime.now().astimezone().strftime("%m-%d %H:%M")
    binding = {
        "eventId": event_id,
        "candidateKey": event["candidateKey"],
        "notificationDigest": event["notificationDigest"],
        "threadId": recovered,
        "turnId": "",
        "projectId": project_id,
        "titleTime": title_time,
        "desiredTitle": _codex_decision_title(event, title_time),
        "promptDigest": prompt_digest,
        "createdAt": iso_z(datetime.now(UTC)),
        "recovered": True,
    }
    _record_codex_decision_binding(event_id, binding)
    return binding


def _codex_decision_worker(args: argparse.Namespace) -> dict[str, Any]:
    request = read_json(Path(args.request), missing={})
    event = request.get("event") if isinstance(request, dict) else None
    source_digest = str(request.get("sourceArtifactDigest") or "")
    if not isinstance(event, dict):
        raise RuntimeError("Codex decision worker request is invalid")
    _validate_codex_decision_outbox(
        {
            "schema": "oss-pr-radar.war-room-outbox.v1",
            "channel": "codex",
            "sourceArtifactDigest": source_digest,
            "events": [event],
        }
    )
    if event.get("actionKind") != "USER_DECISION":
        raise RuntimeError("Codex decision worker received a managed task")
    event_id = str(event["eventId"])
    opportunity_key = str(event["candidateKey"])
    title_time = str(request.get("titleTime") or "")
    if not re.fullmatch(r"[0-1][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]", title_time):
        raise RuntimeError("Codex decision title time is invalid")
    prompt = _codex_decision_prompt(event)
    desired_title = _codex_decision_title(event, title_time)
    executable = shutil.which("codex")
    if not executable:
        raise RuntimeError("codex executable is unavailable")
    store = ledger(args.ledger)
    process = None
    thread_id = ""
    turn_id = ""
    buffer = b""
    selector = selectors.DefaultSelector()
    try:
        with _app_server_action_session(
            store,
            opportunity_key=opportunity_key,
            argv=[
                executable,
                "app-server",
                "--disable",
                "recommended_plugins",
                "--disable",
                "remote_plugin",
                "--disable",
                "multi_agent",
                "--disable",
                "multi_agent_v2",
                "--stdio",
            ],
            cwd=GITHUB_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        ) as started_process:
            process = started_process
            if process.stdin is None or process.stdout is None:
                raise RuntimeError("app server pipes are unavailable")
            selector.register(process.stdout, selectors.EVENT_READ)
            process.stdin.write(
                b"".join(
                    (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
                    for item in (
                        {
                            "id": 0,
                            "method": "initialize",
                            "params": {
                                "clientInfo": {"name": "oss-pr-radar", "version": "1.0"},
                                "capabilities": {"experimentalApi": True},
                            },
                        },
                        {
                            "id": 1,
                            "method": "thread/start",
                            "params": {
                                "cwd": str(GITHUB_ROOT.resolve()),
                                "sandbox": "danger-full-access",
                                "approvalPolicy": "never",
                                "threadSource": "appServer",
                            },
                        },
                    )
                )
            )
            process.stdin.flush()
            buffer, message = _read_app_server_response(
                process,
                selector,
                buffer,
                response_id=1,
                timeout=30,
                action="thread/start",
            )
            thread_id = str(((message.get("result") or {}).get("thread") or {}).get("id") or "")
            if not thread_id:
                raise RuntimeError("app server did not create a Codex decision task")
            _require_task_action_clear(store, opportunity_key)
            _write_turn_start_request(
                process,
                thread_id=thread_id,
                cwd=GITHUB_ROOT,
                prompt=prompt,
                delivery_kind="user-decision",
                delivery_token=event_id,
            )
        buffer, message = _read_app_server_response(
            process,
            selector,
            buffer,
            response_id=2,
            timeout=45,
            action="turn/start",
        )
        turn_id = str(((message.get("result") or {}).get("turn") or {}).get("id") or "")
        if not turn_id:
            raise RuntimeError("app server did not start the Codex decision turn")
        deadline = monotonic() + 30
        while monotonic() < deadline:
            thread = _codex_decision_thread(thread_id)
            if thread is not None and _codex_decision_thread_matches(
                thread,
                prompt=prompt,
                project_id=args.project_id,
                require_unarchived=True,
            ):
                break
            sleep(0.25)
        else:
            raise RuntimeError("Codex decision task was not persisted in the desktop index")
        binding = {
            "eventId": event_id,
            "candidateKey": event["candidateKey"],
            "notificationDigest": event["notificationDigest"],
            "threadId": thread_id,
            "turnId": turn_id,
            "projectId": args.project_id,
            "titleTime": title_time,
            "desiredTitle": desired_title,
            "promptDigest": sha256_json(canonical_prompt(prompt)),
            "createdAt": iso_z(datetime.now(UTC)),
        }
        _record_codex_decision_binding(event_id, binding)
        _ensure_desktop_thread_title(thread_id, desired_title)
        _atomic_json(Path(args.receipt), {"ok": True} | binding)
        terminal = _wait_for_app_server_terminal_turn(
            process,
            selector,
            buffer,
            thread_id=thread_id,
            turn_id=turn_id,
        )
        return {"ok": True} | binding | ({"turnStatus": terminal["status"]} if terminal else {})
    except Exception as exc:
        receipt_path = Path(args.receipt)
        if not receipt_path.exists():
            _atomic_json(
                receipt_path,
                {"ok": False, "error": f"{type(exc).__name__}:{str(exc)[:300]}"},
            )
        raise
    finally:
        selector.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def _active_codex_decision_worker(event_id: str) -> dict[str, Any] | None:
    receipt_root = STATE / "codex_decision_receipts"
    launch_path = receipt_root / f"{event_id}.launch.json"
    request_path = receipt_root / f"{event_id}.request.json"
    launch = read_json(launch_path, missing={})
    request = read_json(request_path, missing={})
    event = request.get("event") if isinstance(request, dict) else None
    if (
        not isinstance(launch, dict)
        or launch.get("eventId") != event_id
        or not isinstance(event, dict)
        or event.get("eventId") != event_id
    ):
        return None
    pid = int(launch.get("pid") or 0)
    if not pid or not _pid_is_alive(pid):
        return None
    try:
        command_line = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return None
    if (
        "local_dispatch_bridge.py" not in command_line
        or "codex-decision-worker" not in command_line
        or event_id not in command_line
    ):
        return None
    return {"pid": pid, "startedAt": launch.get("startedAt"), "eventId": event_id}


def _create_codex_decision_task(
    args: argparse.Namespace,
    *,
    event: dict[str, Any],
    source_artifact_digest: str,
) -> dict[str, Any]:
    event_id = str(event["eventId"])
    receipt_root = STATE / "codex_decision_receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)
    request = receipt_root / f"{event_id}.request.json"
    receipt = receipt_root / f"{event_id}.json"
    launch = receipt_root / f"{event_id}.launch.json"
    log = receipt_root / f"{event_id}.log"
    if _active_codex_decision_worker(event_id) is not None:
        raise RuntimeError("Codex decision task creation is already in progress")
    receipt.unlink(missing_ok=True)
    launch.unlink(missing_ok=True)
    atomic_write_json(
        request,
        {
            "sourceArtifactDigest": source_artifact_digest,
            "titleTime": datetime.now().astimezone().strftime("%m-%d %H:%M"),
            "event": event,
        },
    )
    with log.open("ab") as handle:
        worker = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--ledger",
                str(args.ledger),
                "--runtime-root",
                str(args.runtime_root),
                "codex-decision-worker",
                "--project-id",
                args.project_id,
                "--request",
                str(request),
                "--receipt",
                str(receipt),
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    _atomic_json(
        launch,
        {"pid": worker.pid, "startedAt": iso_z(datetime.now(UTC)), "eventId": event_id},
    )
    deadline = monotonic() + 75
    while monotonic() < deadline:
        if receipt.exists():
            result = read_json(receipt, missing={})
            if not result.get("ok"):
                raise RuntimeError(str(result.get("error") or "Codex decision task failed"))
            return result
        sleep(0.25)
    raise RuntimeError("Codex decision task result is unknown; reconciliation required")


def _codex_decision_feedback(
    event: dict[str, Any], binding: dict[str, Any], source_artifact_digest: str
) -> dict[str, Any]:
    delivery_id = sha256_json(
        {
            "eventId": event["eventId"],
            "threadDigest": hashlib.sha256(str(binding["threadId"]).encode()).hexdigest(),
        }
    )
    receipt_id = sha256_json(
        {
            "channel": "codex",
            "eventId": event["eventId"],
            "candidateKey": event["candidateKey"],
            "notificationDigest": event["notificationDigest"],
            "deliveryId": delivery_id,
            "status": "SENT",
        }
    )
    return {
        "eventId": event["eventId"],
        "candidateKey": event["candidateKey"],
        "notificationDigest": event["notificationDigest"],
        "sourceArtifactDigest": source_artifact_digest,
        "canonicalEventDigest": canonical_event_digest(event),
        "status": "SENT",
        "receiptId": receipt_id,
        "deliveryId": delivery_id,
        "analyzed": iso_z(datetime.now(UTC)),
    }


def dispatch_codex_decisions(args: argparse.Namespace) -> dict[str, Any]:
    outbox = fetch_cloud_codex_outbox()
    if outbox is None:
        return {
            "ok": True,
            "created": [],
            "existing": [],
            "deferred": [],
            "warnings": [],
            "errors": [],
            "reason": "codex_outbox_not_published_yet",
        }
    lock_path = STATE / "codex_decision_dispatch.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "ok": True,
                "busy": True,
                "created": [],
                "existing": [],
                "deferred": [
                    {
                        "key": str(event.get("candidateKey") or ""),
                        "reason": "dispatch_already_running",
                    }
                    for event in outbox["events"]
                    if isinstance(event, dict) and event.get("actionKind") == "USER_DECISION"
                ],
                "warnings": [],
                "errors": [],
            }
        return _dispatch_codex_decisions_locked(args, outbox)


def _dispatch_codex_decisions_locked(
    args: argparse.Namespace, outbox: dict[str, Any]
) -> dict[str, Any]:
    source_digest = str(outbox["sourceArtifactDigest"])
    events = [
        event
        for event in outbox["events"]
        if isinstance(event, dict) and event.get("actionKind") == "USER_DECISION"
    ]
    created: list[dict[str, Any]] = []
    existing: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    feedback_updates: dict[str, dict[str, Any]] = {}
    created_count = 0
    for event in events:
        key = str(event["candidateKey"])
        try:
            binding = _existing_codex_decision_binding(event, project_id=args.project_id)
            was_created = False
            if binding is None:
                if _active_codex_decision_worker(str(event["eventId"])) is not None:
                    deferred.append({"key": key, "reason": "creation_in_progress"})
                    continue
                if created_count >= CODEX_DECISION_MAX_PER_CYCLE:
                    deferred.append({"key": key, "reason": "per_cycle_creation_limit"})
                    continue
                binding = _create_codex_decision_task(
                    args,
                    event=event,
                    source_artifact_digest=source_digest,
                )
                created_count += 1
                was_created = True
            thread = _codex_decision_thread(str(binding["threadId"]))
            if thread is None:
                raise RuntimeError("bound Codex decision task is missing")
            if not _codex_decision_thread_matches(
                thread,
                prompt=_codex_decision_prompt(event),
                project_id=args.project_id,
                require_unarchived=False,
            ):
                raise RuntimeError("bound Codex decision task identity is invalid")
            if thread["archived"] == 0:
                _ensure_desktop_thread_title(
                    str(binding["threadId"]),
                    str(
                        binding.get("desiredTitle")
                        or _codex_decision_title(event, binding["titleTime"])
                    ),
                )
            feedback = _codex_decision_feedback(event, binding, source_digest)
            feedback_updates[str(event["eventId"])] = feedback
            try:
                ManagedAdapter(ROOT, args.ledger).record_user_decision_delivery(
                    candidate_key=key,
                    notification_digest=str(event["notificationDigest"]),
                    channel="codex",
                    status="SENT",
                    receipt_id=str(feedback["receiptId"]),
                    source_artifact_digest=source_digest,
                    message_id=str(feedback["deliveryId"]),
                )
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                warnings.append({"key": key, "warning": f"local_ledger:{str(exc)[:200]}"})
            summary = {"key": key, "threadId": binding["threadId"]}
            (created if was_created else existing).append(summary)
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            errors.append({"key": key, "error": f"{type(exc).__name__}:{str(exc)[:300]}"})
    state_changed = False
    publish_attempts = 0
    if feedback_updates:
        try:
            state_changed, publish_attempts = _publish_controller_decision_feedback_updates(
                feedback_updates
            )
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(
                {
                    "key": "controller-feedback",
                    "error": f"{type(exc).__name__}:{str(exc)[:300]}",
                }
            )
    return {
        "ok": not errors,
        "sourceArtifactDigest": source_digest,
        "created": created,
        "existing": existing,
        "deferred": deferred,
        "warnings": warnings,
        "errors": errors,
        "feedbackStateChanged": state_changed,
        "feedbackPublishAttempts": publish_attempts,
    }


def _task_turn_reservation(
    store: RadarLedger,
    *,
    delivery_kind: str,
    thread_id: str,
    delivery_token: str,
) -> dict[str, Any] | None:
    if delivery_kind == "implementation-followup":
        return next(
            (
                item
                for item in store.unresolved_implementation_followups()
                if item.get("threadId") == thread_id and item.get("resultDigest") == delivery_token
            ),
            None,
        )
    if delivery_kind == "pr-followup":
        candidate = next(
            (
                item
                for item in store.unresolved_pr_followups()
                if item.get("thread_id") == thread_id and item.get("wake_digest") == delivery_token
            ),
            None,
        )
        if candidate is None:
            return None
        return candidate | {
            "issueUrl": candidate.get("issue_url"),
            "worktreePath": candidate.get("worktree_path"),
            "reservedAt": candidate.get("created_at"),
        }
    if delivery_kind == "validation-followup":
        candidate = next(
            (
                item
                for item in store.unresolved_validation_followups()
                if item.get("threadId") == thread_id and item.get("resultDigest") == delivery_token
            ),
            None,
        )
        if candidate is None:
            return None
        binding_reader = getattr(store, "validation_followup_delivery_binding", None)
        if callable(binding_reader):
            binding = binding_reader(
                thread_id=thread_id,
                result_digest=delivery_token,
                reservation_digest=str(candidate["reservationDigest"]),
            )
            if binding:
                candidate = candidate | binding
        return candidate
    if delivery_kind == "publication-feedback":
        candidate = next(
            (
                item
                for item in store.unresolved_publication_feedback()
                if item.get("threadId") == thread_id
                and item.get("reservationNonce") == delivery_token
            ),
            None,
        )
        return candidate | {"statusOnly": True} if candidate else None
    if delivery_kind == "recovery":
        return next(
            (
                item
                for item in store.unresolved_recoveries()
                if item.get("threadId") == thread_id
                and (item.get("reservation") or {}).get("recoveryNonce") == delivery_token
            ),
            None,
        )
    raise RuntimeError("unsupported task-turn delivery kind")


def _task_opportunity_key(candidate: dict[str, Any]) -> str:
    issue_url = str(candidate.get("issueUrl") or candidate.get("issue_url") or "")
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        raise RuntimeError("task action has an invalid issue URL")
    return f"{match.group(1)}#{match.group(2)}"


def _require_task_action_clear(store: RadarLedger, opportunity_key: str) -> None:
    if store.active_task_quarantine(opportunity_key) is not None:
        raise PermissionError(f"task action blocked by active quarantine: {opportunity_key}")


def _guarded_task_popen(
    store: RadarLedger,
    *,
    opportunity_key: str,
    argv: list[str],
    cwd: Path,
    **kwargs: Any,
) -> subprocess.Popen[Any]:
    with opportunity_action_guard(ledger_action_guard_root(store.path), opportunity_key):
        _require_task_action_clear(store, opportunity_key)
        return subprocess.Popen(argv, cwd=cwd, **kwargs)


@contextmanager
def _app_server_action_session(
    store: RadarLedger,
    *,
    opportunity_key: str,
    argv: list[str],
    cwd: Path,
    **kwargs: Any,
):
    """Hold the opportunity guard from app-server spawn through turn dispatch."""

    with opportunity_action_guard(ledger_action_guard_root(store.path), opportunity_key):
        _require_task_action_clear(store, opportunity_key)
        yield subprocess.Popen(argv, cwd=cwd, **kwargs)


def _task_turn_start_unlocked(
    store: RadarLedger,
    *,
    opportunity_key: str,
    process: subprocess.Popen[Any],
    thread_id: str,
    cwd: Path,
    prompt: str,
    delivery_kind: str,
    delivery_token: str,
    delivery_attempt_digest: str | None = None,
    validation_binding: dict[str, Any] | None = None,
    validation_candidate: dict[str, Any] | None = None,
) -> None:
    if process.stdin is None:
        raise RuntimeError("app server input is unavailable")
    _require_task_action_clear(store, opportunity_key)
    store.authorize_task_turn_delivery(
        delivery_kind=delivery_kind,
        thread_id=thread_id,
        delivery_token=delivery_token,
        delivery_attempt_digest=delivery_attempt_digest,
        **(
            {
                "reservation_digest": validation_binding["reservationDigest"],
                "snapshot_id": validation_binding["snapshotId"],
                "snapshot_path": validation_binding["snapshotPath"],
                "snapshot_digest": validation_binding["snapshotDigest"],
                "worktree_input_path": validation_binding["worktreeInputPath"],
                "worktree_input_digest": validation_binding["worktreeInputDigest"],
            }
            if delivery_kind == "validation-followup" and validation_binding
            else {}
        ),
    )
    if delivery_kind == "validation-followup":
        if validation_binding is None or validation_candidate is None:
            raise RuntimeError("validation task-turn worktree input binding is unavailable")
        _validation_worktree_input_metadata(
            candidate=validation_candidate,
            reservation_digest=str(validation_binding["reservationDigest"]),
            worktree_input_path=str(validation_binding["worktreeInputPath"]),
            worktree_input_digest=str(validation_binding["worktreeInputDigest"]),
        )
    _write_turn_start_request(
        process,
        thread_id=thread_id,
        cwd=cwd,
        prompt=prompt,
        delivery_kind=delivery_kind,
        delivery_token=delivery_token,
        delivery_attempt_digest=delivery_attempt_digest,
        validation_reservation_digest=(
            str(validation_binding["reservationDigest"])
            if delivery_kind == "validation-followup" and validation_binding
            else None
        ),
    )


def _write_turn_start_request(
    process: subprocess.Popen[Any],
    *,
    thread_id: str,
    cwd: Path,
    prompt: str,
    delivery_kind: str = "",
    delivery_token: str = "",
    delivery_attempt_digest: str | None = None,
    validation_reservation_digest: str | None = None,
) -> None:
    if process.stdin is None:
        raise RuntimeError("app server input is unavailable")
    params = {
        "threadId": thread_id,
        "cwd": str(cwd),
        "input": [{"type": "text", "text": prompt, "text_elements": []}],
        "approvalPolicy": "never",
        "sandboxPolicy": {"type": "dangerFullAccess"},
        "summary": "auto",
    }
    if delivery_kind and delivery_token:
        client_message_id = f"oss-pr-radar:{delivery_kind}:{delivery_token}"
        if (
            delivery_kind == "implementation-followup"
            and delivery_attempt_digest
            and delivery_attempt_digest != delivery_token
        ):
            client_message_id += f":{delivery_attempt_digest}"
        elif delivery_kind == "validation-followup":
            if not validation_reservation_digest:
                raise RuntimeError("validation task turn requires its reservation digest")
            client_message_id += f":{validation_reservation_digest}"
        params["clientUserMessageId"] = client_message_id
    process.stdin.write(
        (
            json.dumps(
                {
                    "id": 2,
                    "method": "turn/start",
                    "params": params,
                },
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    )
    process.stdin.flush()


def _guarded_task_turn_start(
    store: RadarLedger,
    *,
    opportunity_key: str,
    process: subprocess.Popen[Any],
    thread_id: str,
    cwd: Path,
    prompt: str,
    delivery_kind: str,
    delivery_token: str,
    delivery_attempt_digest: str | None = None,
    validation_binding: dict[str, Any] | None = None,
    validation_candidate: dict[str, Any] | None = None,
) -> None:
    with opportunity_action_guard(ledger_action_guard_root(store.path), opportunity_key):
        _task_turn_start_unlocked(
            store,
            opportunity_key=opportunity_key,
            process=process,
            thread_id=thread_id,
            cwd=cwd,
            prompt=prompt,
            delivery_kind=delivery_kind,
            delivery_token=delivery_token,
            delivery_attempt_digest=delivery_attempt_digest,
            validation_binding=validation_binding,
            validation_candidate=validation_candidate,
        )


def _task_turn_prompt(delivery_kind: str, candidate: dict[str, Any]) -> str:
    if delivery_kind == "implementation-followup":
        issue_url = str(candidate.get("issueUrl") or "")
        if not ISSUE_URL.fullmatch(issue_url):
            raise RuntimeError("task-turn delivery has an invalid issue URL")
        return (
            f"{issue_prompt(issue_url)}\n\n"
            "系统续跑：同一问题已经可靠复现并获得实现授权。读取当前任务上下文，"
            "保留现有工作树和复现证据，直接完成最小根因修复、回归测试、独立复核和"
            " Workspace Result Protocol 结构化交接；不要重新创建任务，不要把成功复现"
            "写成无价值结论，也不要执行 GitHub 公开操作。"
            + END_RESULT_TURN_PROMPT
            + PLAIN_LANGUAGE_STATUS_PROMPT
        )
    if delivery_kind == "validation-followup":
        return _validation_followup_prompt(candidate)
    if delivery_kind == "publication-feedback":
        connection = sqlite3.connect(THREAD_DB)
        try:
            row = connection.execute(
                "SELECT rollout_path FROM threads WHERE id=?",
                (candidate["threadId"],),
            ).fetchone()
        finally:
            connection.close()
        return publication_feedback_prompt(
            pr_url=str(candidate.get("prUrl") or ""),
            previous_message=latest_agent_message(row[0] if row else None),
        )
    issue_url = str(candidate.get("issueUrl") or "")
    if not ISSUE_URL.fullmatch(issue_url):
        raise RuntimeError("task-turn delivery has an invalid issue URL")
    if delivery_kind == "pr-followup":
        return _pr_followup_prompt({"issueUrl": issue_url})
    if delivery_kind == "recovery":
        recovery_kind = str(
            candidate.get("recoveryKind")
            or (candidate.get("reservation") or {}).get("recoveryKind")
            or ""
        )
        if recovery_kind == "VALIDATION_FOLLOWUP_RESULT":
            return VALIDATION_RECOVERY_PROMPT
        if recovery_kind == "PR_FOLLOWUP_RESULT":
            return _pr_followup_prompt({"issueUrl": issue_url})
        connection = sqlite3.connect(THREAD_DB)
        try:
            row = connection.execute(
                "SELECT rollout_path FROM threads WHERE id=?",
                (candidate["threadId"],),
            ).fetchone()
        finally:
            connection.close()
        terminal_error = latest_terminal_thread_error(row[0] if row else None)
        prompt = _recovery_turn_prompt(candidate, terminal_error)
        _verify_dispatched_recovery_prompt_binding(candidate, prompt)
        return prompt
    raise RuntimeError("unsupported task-turn delivery kind")


def _bound_legacy_managed_task_project_root(
    candidate: dict[str, Any],
    *,
    raw_thread_cwd: str,
    thread_source: str,
    project_id: str | None,
    worktree: Path,
) -> Path | None:
    """Validate the one historical project root used by managed issue tasks.

    Older managed tasks were created in the Radar project itself before new
    tasks moved to the shared GitHub project.  Accept that exact root only
    when the authenticated task context still binds the issue, task, thread,
    and deterministic managed worktree.  This is deliberately a resume-only
    compatibility check; it does not broaden new-task or receipt creation.
    """

    legacy_root = GITHUB_ROOT / "oss-pr-radar"
    raw_cwd = Path(raw_thread_cwd)
    if (
        not raw_cwd.is_absolute()
        or raw_cwd != legacy_root
        or thread_source != "appServer"
        or project_id not in {None, "", DEFAULT_TASK_PROJECT_ID}
    ):
        return None
    try:
        legacy_fd, opened_legacy_root = open_directory_handle(
            legacy_root,
            label="legacy managed task project root",
        )
    except RuntimeError:
        return None
    else:
        os.close(legacy_fd)
    if opened_legacy_root != legacy_root:
        return None

    issue_url = str(candidate.get("issueUrl") or "")
    issue_match = ISSUE_URL.fullmatch(issue_url)
    if issue_match is None:
        return None
    repo, issue_number = issue_match.groups()
    if candidate.get("key") != f"{repo}#{issue_number}":
        return None
    try:
        context, _updated_at = _verified_shared_task_context(shared_context_path(issue_url))
    except (OSError, RuntimeError, ValueError):
        return None
    intent_id = str(context.get("intentId") or "")
    if not intent_id:
        return None
    expected_worktree = managed_worktree_path(intent_id, repo).resolve()
    expected_context = {
        "schemaVersion": TASK_CONTEXT_SCHEMA,
        "key": candidate["key"],
        "issueUrl": issue_url,
        "threadId": str(candidate.get("threadId") or candidate.get("thread_id") or ""),
        "worktreePath": str(worktree),
        "workspaceMode": "github_project_managed_worktree",
        "taskProjectRoot": str(GITHUB_ROOT.resolve()),
    }
    if expected_worktree != worktree or any(
        context.get(key) != value for key, value in expected_context.items()
    ):
        return None
    return opened_legacy_root


def _validated_task_turn_thread(candidate: dict[str, Any]) -> tuple[Path, str | None]:
    thread_id = str(candidate.get("threadId") or candidate.get("thread_id") or "")
    issue_url = str(candidate.get("issueUrl") or "")
    worktree_value = candidate.get("worktreePath")
    if not thread_id or not worktree_value:
        raise RuntimeError("task-turn delivery lacks its task identity")
    worktree = Path(str(worktree_value)).resolve()
    if not worktree.is_dir() and not candidate.get("statusOnly"):
        raise RuntimeError("task-turn delivery worktree is unavailable")
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        columns = {
            str(item[1]) for item in connection.execute("PRAGMA table_info(threads)").fetchall()
        }
        source_projection = "thread_source" if "thread_source" in columns else "'appServer'"
        project_projection = "project_id" if "project_id" in columns else "NULL"
        row = connection.execute(
            f"SELECT cwd,archived,first_user_message,rollout_path,"
            f"{source_projection} AS thread_source,{project_projection} AS project_id "
            "FROM threads WHERE id=?",
            (thread_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row["archived"] or 0) != 0:
        raise RuntimeError("task-turn delivery target is missing or archived")
    if canonical_prompt(str(row["first_user_message"] or "")) != issue_prompt(issue_url):
        raise RuntimeError("task-turn delivery target prompt mismatch")
    raw_thread_cwd = str(row["cwd"] or "")
    cwd = Path(raw_thread_cwd).resolve()
    if _is_managed_worktree(worktree):
        if cwd != GITHUB_ROOT.resolve():
            legacy_root = _bound_legacy_managed_task_project_root(
                candidate,
                raw_thread_cwd=raw_thread_cwd,
                thread_source=str(row["thread_source"] or ""),
                project_id=(str(row["project_id"]) if row["project_id"] is not None else None),
                worktree=worktree,
            )
            if legacy_root is None or cwd != legacy_root:
                raise RuntimeError("managed task-turn delivery project root mismatch")
    elif cwd != worktree or not _is_within(worktree, WORKTREE_ROOT):
        raise RuntimeError("legacy task-turn delivery worktree mismatch")
    return cwd, row["rollout_path"]


def _commit_task_turn_delivery(
    store: RadarLedger,
    *,
    delivery_kind: str,
    thread_id: str,
    delivery_token: str,
    validation_reservation_digest: str | None = None,
) -> None:
    if delivery_kind == "implementation-followup":
        store.commit_implementation_followup(thread_id=thread_id, result_digest=delivery_token)
    elif delivery_kind == "pr-followup":
        store.commit_pr_followup(thread_id=thread_id, wake_digest=delivery_token)
    elif delivery_kind == "validation-followup":
        store.commit_validation_followup(
            thread_id=thread_id,
            result_digest=delivery_token,
            reservation_digest=validation_reservation_digest,
        )
    elif delivery_kind == "publication-feedback":
        store.commit_publication_feedback(
            thread_id=thread_id,
            reservation_nonce=delivery_token,
        )
    elif delivery_kind == "recovery":
        store.commit_recovery(thread_id=thread_id, nonce=delivery_token)
    else:
        raise RuntimeError("unsupported task-turn delivery kind")


def _app_server_task_error(message: dict[str, Any], *, action: str) -> RuntimeError:
    detail = str(((message.get("error") or {}).get("message") or "")).strip()
    if "already has an active writer" in detail:
        return RuntimeError(f"DESKTOP_ACTIVE_WRITER:{detail[:240]}")
    return RuntimeError(f"APP_SERVER_{action.upper()}_FAILED:{detail[:240] or 'unknown error'}")


def _read_app_server_response(
    process: subprocess.Popen[Any],
    selector: selectors.BaseSelector,
    buffer: bytes,
    *,
    response_id: int,
    timeout: float,
    action: str,
) -> tuple[bytes, dict[str, Any]]:
    if process.stdout is None:
        raise RuntimeError("app server output is unavailable")
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        ready = selector.select(max(0.0, deadline - monotonic()))
        if not ready:
            break
        chunk = os.read(process.stdout.fileno(), 65536)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if message.get("id") != response_id:
                continue
            if message.get("error"):
                raise _app_server_task_error(message, action=action)
            return buffer, message
    raise RuntimeError(f"app server did not complete {action} request")


def _app_server_task_turn_worker(args: argparse.Namespace) -> dict[str, Any]:
    """Resume one existing task and durably receipt the exact new turn."""

    store = ledger(args.ledger)
    candidate = _task_turn_reservation(
        store,
        delivery_kind=args.delivery_kind,
        thread_id=args.thread_id,
        delivery_token=args.delivery_token,
    )
    if candidate is None:
        raise RuntimeError("task-turn delivery reservation is unavailable")
    candidate = candidate | {"threadId": args.thread_id}
    delivery_attempt_digest = (
        str(candidate.get("implementationFollowupAttemptDigest") or args.delivery_token)
        if args.delivery_kind == "implementation-followup"
        else None
    )
    if args.delivery_kind == "implementation-followup" and (
        (getattr(args, "delivery_attempt_digest", None) or args.delivery_token)
        != delivery_attempt_digest
    ):
        raise RuntimeError("implementation task-turn attempt binding mismatch")
    validation_binding: dict[str, Any] | None = None
    if args.delivery_kind == "validation-followup":
        binding_reader = getattr(store, "validation_followup_delivery_binding", None)
        validation_binding = (
            binding_reader(
                thread_id=args.thread_id,
                result_digest=args.delivery_token,
                reservation_digest=str(candidate["reservationDigest"]),
            )
            if callable(binding_reader)
            else None
        )
        if not validation_binding:
            raise RuntimeError("validation task-turn snapshot binding is unavailable")
        for option, key in (
            (args.reservation_digest, "reservationDigest"),
            (args.snapshot_id, "snapshotId"),
            (args.snapshot_path, "snapshotPath"),
            (args.snapshot_digest, "snapshotDigest"),
            (args.worktree_input_path, "worktreeInputPath"),
            (args.worktree_input_digest, "worktreeInputDigest"),
        ):
            if option != validation_binding.get(key):
                raise RuntimeError("validation task-turn snapshot binding mismatch")
        candidate = candidate | validation_binding
        _validation_snapshot_metadata(
            candidate=candidate,
            reservation_digest=str(validation_binding["reservationDigest"]),
            snapshot_id=str(validation_binding["snapshotId"]),
            snapshot_path=str(validation_binding["snapshotPath"]),
            snapshot_digest=str(validation_binding["snapshotDigest"]),
        )
    cwd, _rollout_path = _validated_task_turn_thread(candidate)
    if validation_binding is not None:
        projection = _ensure_validation_worktree_input(
            candidate=candidate,
            reservation_digest=str(validation_binding["reservationDigest"]),
            snapshot_id=str(validation_binding["snapshotId"]),
            snapshot_path=str(validation_binding["snapshotPath"]),
            snapshot_digest=str(validation_binding["snapshotDigest"]),
            worktree_input_path=str(validation_binding["worktreeInputPath"]),
            worktree_input_digest=str(validation_binding["worktreeInputDigest"]),
        )
        if any(
            projection.get(key) != validation_binding.get(key)
            for key in ("worktreeInputPath", "worktreeInputDigest", "resultDigest")
        ):
            raise RuntimeError("validation task-turn worktree input binding mismatch")
        candidate = candidate | projection
    prompt = _task_turn_prompt(args.delivery_kind, candidate)
    executable = shutil.which("codex")
    if not executable:
        raise RuntimeError("codex executable is unavailable")
    opportunity_key = _task_opportunity_key(candidate)
    process = None
    turn_id = ""
    buffer = b""
    selector = selectors.DefaultSelector()
    try:
        with _app_server_action_session(
            store,
            opportunity_key=opportunity_key,
            argv=[
                executable,
                "app-server",
                "--disable",
                "recommended_plugins",
                "--disable",
                "remote_plugin",
                "--stdio",
            ],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        ) as started_process:
            process = started_process
            if process.stdin is None or process.stdout is None:
                raise RuntimeError("app server pipes are unavailable")
            selector.register(process.stdout, selectors.EVENT_READ)
            process.stdin.write(
                b"".join(
                    (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
                    for item in (
                        {
                            "id": 0,
                            "method": "initialize",
                            "params": {
                                "clientInfo": {"name": "oss-pr-radar", "version": "1.0"},
                                "capabilities": {"experimentalApi": True},
                            },
                        },
                        {
                            "id": 1,
                            "method": "thread/resume",
                            "params": {
                                "threadId": args.thread_id,
                                "cwd": str(cwd),
                                "sandbox": "danger-full-access",
                                "approvalPolicy": "never",
                                "excludeTurns": True,
                            },
                        },
                    )
                )
            )
            process.stdin.flush()
            buffer, message = _read_app_server_response(
                process,
                selector,
                buffer,
                response_id=1,
                timeout=30,
                action="resume",
            )
            resumed_thread_id = str(
                ((message.get("result") or {}).get("thread") or {}).get("id") or ""
            )
            if resumed_thread_id != args.thread_id:
                raise RuntimeError("app server resumed the wrong task")
            _task_turn_start_unlocked(
                store,
                opportunity_key=opportunity_key,
                process=process,
                thread_id=args.thread_id,
                cwd=cwd,
                prompt=prompt,
                delivery_kind=args.delivery_kind,
                delivery_token=args.delivery_token,
                delivery_attempt_digest=delivery_attempt_digest,
                validation_binding=validation_binding,
                validation_candidate=candidate,
            )

        buffer, message = _read_app_server_response(
            process,
            selector,
            buffer,
            response_id=2,
            timeout=45,
            action="start",
        )
        turn_id = str(((message.get("result") or {}).get("turn") or {}).get("id") or "")
        if not turn_id:
            raise RuntimeError("app server did not receipt the task turn")
        receipt = {
            "ok": True,
            "threadId": args.thread_id,
            "turnId": turn_id,
            "deliveryKind": args.delivery_kind,
            "deliveryToken": args.delivery_token,
            **(
                {"deliveryAttemptDigest": delivery_attempt_digest}
                if delivery_attempt_digest
                else {}
            ),
            **(
                {"reservationDigest": validation_binding["reservationDigest"]}
                if validation_binding
                else {}
            ),
        }
        if args.delivery_kind != "publication-feedback":
            _commit_task_turn_delivery(
                store,
                delivery_kind=args.delivery_kind,
                thread_id=args.thread_id,
                delivery_token=args.delivery_token,
                validation_reservation_digest=(
                    str(validation_binding["reservationDigest"]) if validation_binding else None
                ),
            )
            _atomic_json(Path(args.receipt), receipt)

        terminal = _wait_for_app_server_terminal_turn(
            process,
            selector,
            buffer,
            thread_id=args.thread_id,
            turn_id=turn_id,
        )
        if args.delivery_kind == "publication-feedback":
            visible = False
            if terminal and terminal["status"] == "completed":
                visibility_deadline = monotonic() + 5
                while monotonic() < visibility_deadline:
                    if publication_feedback_materialized(
                        _rollout_path,
                        str(candidate.get("prUrl") or ""),
                    ):
                        visible = True
                        break
                    sleep(0.1)
            if visible:
                _commit_task_turn_delivery(
                    store,
                    delivery_kind=args.delivery_kind,
                    thread_id=args.thread_id,
                    delivery_token=args.delivery_token,
                )
                terminal_receipt = receipt | {
                    "turnStatus": "completed",
                    "visibleReplyVerified": True,
                }
                _atomic_json(Path(args.receipt), terminal_receipt)
                return terminal_receipt
            store.abandon_publication_feedback(
                thread_id=args.thread_id,
                reservation_nonce=args.delivery_token,
                reason="VISIBLE_STATUS_REPLY_MISSING",
                min_age_minutes=0,
            )
            retry_receipt = receipt | {
                "delivered": False,
                "retryable": True,
                "turnStatus": (terminal or {}).get("status") or "unknown",
                "reason": "VISIBLE_STATUS_REPLY_MISSING",
            }
            _atomic_json(Path(args.receipt), retry_receipt)
            return retry_receipt
        if terminal:
            terminal_receipt = receipt | {"turnStatus": terminal["status"]}
            _atomic_json(Path(args.receipt), terminal_receipt)
            return terminal_receipt
        return receipt
    except Exception as exc:
        receipt_path = Path(args.receipt)
        if not receipt_path.exists():
            _atomic_json(
                receipt_path,
                {
                    "ok": False,
                    "turnStarted": bool(turn_id),
                    "turnId": turn_id or None,
                    "error": f"{type(exc).__name__}:{str(exc)[:300]}",
                    **(
                        {"reservationDigest": args.reservation_digest}
                        if args.delivery_kind == "validation-followup"
                        and getattr(args, "reservation_digest", None)
                        else {}
                    ),
                },
            )
        raise
    finally:
        selector.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def task_turn_worker_entry(args: argparse.Namespace) -> dict[str, Any]:
    """Guarantee a negative receipt even when setup fails before app-server starts."""

    try:
        return _app_server_task_turn_worker(args)
    except Exception as exc:
        receipt = Path(args.receipt)
        if not receipt.exists():
            _atomic_json(
                receipt,
                {
                    "ok": False,
                    "turnStarted": False,
                    "turnId": None,
                    "error": f"{type(exc).__name__}:{str(exc)[:300]}",
                    **(
                        {"reservationDigest": args.reservation_digest}
                        if getattr(args, "delivery_kind", None) == "validation-followup"
                        and getattr(args, "reservation_digest", None)
                        else {}
                    ),
                },
            )
        raise


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


def _task_turn_delivery_identity(
    *,
    delivery_kind: str,
    thread_id: str,
    delivery_token: str,
    delivery_attempt_digest: str | None = None,
    validation_reservation_digest: str | None = None,
) -> dict[str, str]:
    identity = {
        "deliveryKind": delivery_kind,
        "threadId": thread_id,
        "deliveryToken": delivery_token,
    }
    if (
        delivery_kind == "implementation-followup"
        and delivery_attempt_digest
        and delivery_attempt_digest != delivery_token
    ):
        identity["deliveryAttemptDigest"] = delivery_attempt_digest
    elif delivery_kind == "validation-followup":
        if not validation_reservation_digest or not re.fullmatch(
            r"[0-9a-f]{64}", validation_reservation_digest
        ):
            raise RuntimeError("validation task-turn identity requires its reservation digest")
        identity["reservationDigest"] = validation_reservation_digest
    return identity


def _task_turn_delivery_file_key(
    *,
    delivery_kind: str,
    thread_id: str,
    delivery_token: str,
    delivery_attempt_digest: str | None = None,
    validation_reservation_digest: str | None = None,
) -> str:
    return sha256_json(
        _task_turn_delivery_identity(
            delivery_kind=delivery_kind,
            thread_id=thread_id,
            delivery_token=delivery_token,
            delivery_attempt_digest=delivery_attempt_digest,
            validation_reservation_digest=validation_reservation_digest,
        )
    )


def active_task_turn_worker(thread_id: str) -> dict[str, Any] | None:
    """Return the verified local worker that still owns a task turn."""

    receipt_root = STATE / "task_turn_receipts"
    if not receipt_root.is_dir():
        return None
    for launch_path in receipt_root.glob("*.launch.json"):
        launch = read_json(launch_path, missing={})
        if str(launch.get("threadId") or "") != thread_id:
            continue
        pid = int(launch.get("pid") or 0)
        if not pid or not _pid_is_alive(pid):
            continue
        try:
            command_line = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            ).stdout.strip()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            continue
        if (
            "local_dispatch_bridge.py" not in command_line
            or "task-turn-worker" not in command_line
            or thread_id not in command_line
        ):
            continue
        worker = {
            "pid": pid,
            "deliveryKind": launch.get("deliveryKind"),
            "startedAt": launch.get("startedAt"),
        }
        if launch.get("reservationDigest"):
            worker["reservationDigest"] = launch["reservationDigest"]
        return worker
    return active_root_task_worker(thread_id)


def active_root_task_worker(thread_id: str) -> dict[str, Any] | None:
    """Return the verified root-task worker that owns a task's first turn."""

    receipt_root = STATE / "root_task_receipts"
    if not receipt_root.is_dir():
        return None
    for launch_path in receipt_root.glob("*.launch.json"):
        creation_token = launch_path.name.removesuffix(".launch.json")
        launch = read_json(launch_path, missing={})
        receipt = read_json(receipt_root / f"{creation_token}.json", missing={})
        if str(receipt.get("threadId") or "") != thread_id:
            continue
        pid = int(launch.get("pid") or 0)
        if not pid or not _pid_is_alive(pid):
            continue
        try:
            command_line = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                check=True,
                capture_output=True,
                text=True,
                timeout=2,
            ).stdout.strip()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            continue
        if (
            "local_dispatch_bridge.py" not in command_line
            or "root-task-worker" not in command_line
            or creation_token not in command_line
        ):
            continue
        return {
            "pid": pid,
            "deliveryKind": "root-task",
            "startedAt": launch.get("startedAt"),
        }
    return None


def retryable_negative_task_turn_receipt(
    *,
    delivery_kind: str,
    thread_id: str,
    delivery_token: str,
    validation_reservation_digest: str | None = None,
) -> dict[str, Any] | None:
    """Return proof that a failed delivery started no target turn."""

    receipt_key = _task_turn_delivery_file_key(
        delivery_kind=delivery_kind,
        thread_id=thread_id,
        delivery_token=delivery_token,
        validation_reservation_digest=validation_reservation_digest,
    )
    receipt_root = STATE / "task_turn_receipts"
    receipt_path = receipt_root / f"{receipt_key}.json"
    if not receipt_path.is_file():
        return None
    receipt = read_json(receipt_path, missing={})
    if (
        delivery_kind == "validation-followup"
        and receipt.get("reservationDigest") != validation_reservation_digest
    ):
        return None
    if receipt.get("ok") or receipt.get("turnStarted"):
        return None
    if active_task_turn_worker(thread_id) is not None:
        return None
    delivery_error = str(receipt.get("error") or "task-turn delivery failed")[:300]
    if "DESKTOP_ACTIVE_WRITER" in delivery_error:
        return {
            "retryable": True,
            "retryReason": "DESKTOP_ACTIVE_WRITER",
            "deliveryError": delivery_error,
            "desktopHandoffRequired": True,
        }
    return {
        "retryable": True,
        "retryReason": "NEGATIVE_RECEIPT_NO_TURN_STARTED",
        "deliveryError": delivery_error,
    }


def _desktop_task_handoff(
    *, delivery_kind: str, candidate: dict[str, Any], delivery_token: str
) -> dict[str, Any]:
    normalized = dict(candidate)
    issue_url = candidate.get("issueUrl") or candidate.get("issue_url")
    key_match = re.fullmatch(r"([^/]+/[^#]+)#(\d+)", str(candidate.get("key") or ""))
    if not issue_url and key_match:
        issue_url = f"https://github.com/{key_match.group(1)}/issues/{key_match.group(2)}"
    normalized["issueUrl"] = issue_url
    if delivery_kind == "pr-followup":
        normalized |= {
            "threadId": candidate.get("thread_id"),
            "issueUrl": issue_url,
            "worktreePath": candidate.get("worktree_path"),
            "reservedAt": candidate.get("created_at"),
        }
    handoff = {
        "deliveryKind": delivery_kind,
        "threadId": str(normalized.get("threadId") or ""),
        "deliveryToken": delivery_token,
        "prompt": _task_turn_prompt(delivery_kind, normalized),
    }
    attempt_digest = normalized.get("implementationFollowupAttemptDigest")
    if delivery_kind == "implementation-followup" and attempt_digest:
        handoff["deliveryAttemptDigest"] = str(attempt_digest)
    return handoff


def _discard_negative_task_turn_receipt(
    *,
    delivery_kind: str,
    thread_id: str,
    delivery_token: str,
    validation_reservation_digest: str | None = None,
) -> None:
    """Remove a proved-negative receipt after retiring its ledger reservation."""

    receipt_key = _task_turn_delivery_file_key(
        delivery_kind=delivery_kind,
        thread_id=thread_id,
        delivery_token=delivery_token,
        validation_reservation_digest=validation_reservation_digest,
    )
    receipt_root = STATE / "task_turn_receipts"
    (receipt_root / f"{receipt_key}.json").unlink(missing_ok=True)
    (receipt_root / f"{receipt_key}.launch.json").unlink(missing_ok=True)
    (receipt_root / f"{receipt_key}.log").unlink(missing_ok=True)


def _reserved_task_turn_materialized(
    *, delivery_kind: str, candidate: dict[str, Any], delivery_token: str
) -> bool:
    if not THREAD_DB.is_file():
        return False
    handoff = _desktop_task_handoff(
        delivery_kind=delivery_kind,
        candidate=candidate,
        delivery_token=delivery_token,
    )
    thread_id = str(handoff["threadId"])
    reserved_at = str(
        candidate.get("reservedAt")
        or candidate.get("created_at")
        or candidate.get("createdAt")
        or ""
    )
    if not thread_id or not reserved_at:
        return False
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT rollout_path FROM threads WHERE id=?", (thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        return False
    if delivery_kind == "publication-feedback":
        return publication_feedback_materialized(
            row[0],
            str(candidate.get("prUrl") or ""),
        )
    _available, materialized = thread_prompt_materialized_after(
        row[0], reserved_at, str(handoff["prompt"])
    )
    return materialized


def _rearm_negative_followup_deliveries(store: RadarLedger) -> list[dict[str, Any]]:
    """Release reservations whose durable receipt proves that no turn started."""

    rearmed: list[dict[str, Any]] = []
    now = datetime.now(UTC)
    for item in getattr(store, "unresolved_publication_feedback", lambda: [])():
        thread_id = str(item.get("threadId") or "")
        token = str(item.get("reservationNonce") or "")
        if _reserved_task_turn_materialized(
            delivery_kind="publication-feedback",
            candidate=item,
            delivery_token=token,
        ):
            store.commit_publication_feedback(
                thread_id=thread_id,
                reservation_nonce=token,
            )
            _discard_negative_task_turn_receipt(
                delivery_kind="publication-feedback",
                thread_id=thread_id,
                delivery_token=token,
            )
            rearmed.append(
                {
                    "kind": "publication-feedback",
                    "key": item.get("key"),
                    "threadId": thread_id,
                    "reconciledVisibleReply": True,
                }
            )
            continue
        if active_task_turn_worker(thread_id) is not None:
            continue
        receipt_key = _task_turn_delivery_file_key(
            delivery_kind="publication-feedback",
            thread_id=thread_id,
            delivery_token=token,
        )
        receipt_path = STATE / "task_turn_receipts" / f"{receipt_key}.json"
        receipt = read_json(receipt_path, missing={})
        age = now - parse_time(str(item["reservedAt"]))
        proved_incomplete = bool(receipt) and (
            receipt.get("ok") is False or receipt.get("turnStatus") in {"failed", "interrupted"}
        )
        launch_path = STATE / "task_turn_receipts" / f"{receipt_key}.launch.json"
        abandoned_worker = launch_path.exists() and age >= timedelta(minutes=5)
        if age < timedelta(minutes=1) or not (proved_incomplete or abandoned_worker):
            continue
        store.abandon_publication_feedback(
            thread_id=thread_id,
            reservation_nonce=token,
            reason="VISIBLE_STATUS_DELIVERY_INCOMPLETE",
            min_age_minutes=1,
        )
        _discard_negative_task_turn_receipt(
            delivery_kind="publication-feedback",
            thread_id=thread_id,
            delivery_token=token,
        )
        rearmed.append(
            {
                "kind": "publication-feedback",
                "key": item.get("key"),
                "threadId": thread_id,
                "reason": "VISIBLE_STATUS_DELIVERY_INCOMPLETE",
            }
        )

    for item in store.unresolved_pr_followups():
        thread_id = str(item.get("thread_id") or "")
        token = str(item.get("wake_digest") or "")
        if _reserved_task_turn_materialized(
            delivery_kind="pr-followup",
            candidate=item,
            delivery_token=token,
        ):
            store.commit_pr_followup(thread_id=thread_id, wake_digest=token)
            _discard_negative_task_turn_receipt(
                delivery_kind="pr-followup",
                thread_id=thread_id,
                delivery_token=token,
            )
            rearmed.append(
                {
                    "kind": "pr-followup",
                    "key": item.get("opportunity_key") or item.get("key"),
                    "threadId": thread_id,
                    "reconciledDesktopHandoff": True,
                }
            )
            continue
        retry = retryable_negative_task_turn_receipt(
            delivery_kind="pr-followup",
            thread_id=thread_id,
            delivery_token=token,
        )
        if retry and retry.get("desktopHandoffRequired"):
            continue
        if not retry or parse_time(str(item["created_at"])) + timedelta(minutes=1) > now:
            continue
        replacement = store.abandon_pr_followup_delivery(
            thread_id=thread_id,
            wake_digest=token,
            reason="NEGATIVE_RECEIPT_NO_TURN_STARTED",
            min_age_minutes=1,
        )
        _discard_negative_task_turn_receipt(
            delivery_kind="pr-followup",
            thread_id=thread_id,
            delivery_token=token,
        )
        rearmed.append(
            {
                "kind": "pr-followup",
                "key": item.get("opportunity_key") or item.get("key"),
                "threadId": thread_id,
                "replacementWakeDigest": replacement.get("wakeDigest"),
            }
        )

    for item in store.unresolved_validation_followups():
        thread_id = str(item.get("threadId") or "")
        token = str(item.get("resultDigest") or "")
        reservation_digest = str(item.get("reservationDigest") or "")
        if _reserved_task_turn_materialized(
            delivery_kind="validation-followup",
            candidate=item,
            delivery_token=token,
        ):
            commit_kwargs: dict[str, Any] = {
                "thread_id": thread_id,
                "result_digest": token,
            }
            if item.get("reservationDigest"):
                commit_kwargs["reservation_digest"] = str(item["reservationDigest"])
            store.commit_validation_followup(**commit_kwargs)
            _discard_negative_task_turn_receipt(
                delivery_kind="validation-followup",
                thread_id=thread_id,
                delivery_token=token,
                validation_reservation_digest=str(item["reservationDigest"]),
            )
            rearmed.append(
                {
                    "kind": "validation-followup",
                    "key": item.get("key"),
                    "threadId": thread_id,
                    "reconciledDesktopHandoff": True,
                }
            )
            continue
        binding_reader = getattr(store, "validation_followup_delivery_binding", None)
        if callable(binding_reader):
            with opportunity_action_guard(
                ledger_action_guard_root(store.path), str(item.get("key") or "")
            ):
                if active_task_turn_worker(thread_id) is not None:
                    continue
                delivery_started = bool(
                    binding_reader(
                        thread_id=thread_id,
                        result_digest=token,
                        reservation_digest=reservation_digest,
                    )
                )
                if (
                    delivery_started
                    or parse_time(str(item["reservedAt"])) + timedelta(minutes=1) > now
                ):
                    pass
                else:
                    try:
                        store.cancel_validation_followup_reservation(
                            thread_id=thread_id,
                            result_digest=token,
                            reservation_digest=reservation_digest,
                            reason="DELIVERY_NOT_STARTED",
                        )
                    except LedgerError:
                        continue
                    _discard_negative_task_turn_receipt(
                        delivery_kind="validation-followup",
                        thread_id=thread_id,
                        delivery_token=token,
                        validation_reservation_digest=reservation_digest,
                    )
                    rearmed.append(
                        {
                            "kind": "validation-followup",
                            "key": item.get("key"),
                            "threadId": thread_id,
                            "resultDigest": token,
                            "reason": "DELIVERY_NOT_STARTED",
                        }
                    )
                    continue
        retry = retryable_negative_task_turn_receipt(
            delivery_kind="validation-followup",
            thread_id=thread_id,
            delivery_token=token,
            validation_reservation_digest=reservation_digest,
        )
        if retry and retry.get("desktopHandoffRequired"):
            continue
        if not retry or parse_time(str(item["reservedAt"])) + timedelta(minutes=1) > now:
            continue
        store.abandon_validation_followup_delivery(
            thread_id=thread_id,
            result_digest=token,
            reason="NEGATIVE_RECEIPT_NO_TURN_STARTED",
            min_age_minutes=1,
        )
        _discard_negative_task_turn_receipt(
            delivery_kind="validation-followup",
            thread_id=thread_id,
            delivery_token=token,
            validation_reservation_digest=str(item["reservationDigest"]),
        )
        rearmed.append(
            {
                "kind": "validation-followup",
                "key": item.get("key"),
                "threadId": thread_id,
                "resultDigest": token,
            }
        )

    for item in getattr(store, "unresolved_recoveries", lambda: [])():
        thread_id = str(item.get("threadId") or "")
        token = str((item.get("reservation") or {}).get("recoveryNonce") or "")
        if _reserved_task_turn_materialized(
            delivery_kind="recovery",
            candidate=item,
            delivery_token=token,
        ):
            store.commit_recovery(thread_id=thread_id, nonce=token)
            _discard_negative_task_turn_receipt(
                delivery_kind="recovery",
                thread_id=thread_id,
                delivery_token=token,
            )
            rearmed.append(
                {
                    "kind": "recovery",
                    "key": item.get("key"),
                    "threadId": thread_id,
                    "reconciledDesktopHandoff": True,
                }
            )
            continue
        retry = retryable_negative_task_turn_receipt(
            delivery_kind="recovery",
            thread_id=thread_id,
            delivery_token=token,
        )
        if retry and retry.get("desktopHandoffRequired"):
            continue
        if not retry or parse_time(str(item["reservedAt"])) + timedelta(minutes=1) > now:
            continue
        store.abandon_recovery_delivery(
            thread_id=thread_id,
            nonce=token,
            reason="NEGATIVE_RECEIPT_NO_TURN_STARTED",
            min_age_minutes=1,
        )
        _discard_negative_task_turn_receipt(
            delivery_kind="recovery",
            thread_id=thread_id,
            delivery_token=token,
        )
        rearmed.append(
            {
                "kind": "recovery",
                "key": item.get("key"),
                "threadId": thread_id,
                "recoveryNonce": token,
            }
        )
    return rearmed


def _rearm_interrupted_recovery_turns(
    store: RadarLedger,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Permit one fresh recovery when the delivered recovery turn was interrupted."""

    pending = store.sent_recoveries_without_result()
    if not pending:
        return [], []
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        rows = {
            item["threadId"]: connection.execute(
                "SELECT rollout_path FROM threads WHERE id=?", (item["threadId"],)
            ).fetchone()
            for item in pending
        }
    finally:
        connection.close()
    probe_ids = {
        thread_id
        for thread_id, row in rows.items()
        if row is not None
        and latest_thread_turn_state(row["rollout_path"]) is None
        and active_task_turn_worker(thread_id) is None
    }
    live = live_thread_turn_states(probe_ids)
    rearmed: list[dict[str, Any]] = []
    exhausted: list[dict[str, Any]] = []
    for item in pending:
        row = rows.get(item["threadId"])
        state = (
            latest_thread_turn_state(row["rollout_path"]) if row is not None else None
        ) or live.get(item["threadId"])
        if not _is_immediate_recovery(state):
            continue
        if int(item.get("retryCount") or 0) >= 1:
            nonce = str((item.get("reservation") or {}).get("recoveryNonce") or "")
            store.exhaust_recovery(thread_id=item["threadId"], nonce=nonce)
            _discard_negative_task_turn_receipt(
                delivery_kind="recovery",
                thread_id=item["threadId"],
                delivery_token=nonce,
            )
            exhausted.append(
                {
                    "key": item["key"],
                    "threadId": item["threadId"],
                    "reason": "RECOVERY_RETRY_EXHAUSTED",
                }
            )
            continue
        nonce = str((item.get("reservation") or {}).get("recoveryNonce") or "")
        store.abandon_recovery_delivery(
            thread_id=item["threadId"],
            nonce=nonce,
            reason="TERMINAL_RECOVERY_TURN_INTERRUPTED",
            min_age_minutes=0,
        )
        _discard_negative_task_turn_receipt(
            delivery_kind="recovery",
            thread_id=item["threadId"],
            delivery_token=nonce,
        )
        rearmed.append(
            {
                "kind": "recovery",
                "key": item["key"],
                "threadId": item["threadId"],
                "reason": "TERMINAL_RECOVERY_TURN_INTERRUPTED",
            }
        )
    return rearmed, exhausted


def task_turn_deliver(args: argparse.Namespace) -> dict[str, Any]:
    """Start an existing-task turn once, or reconcile its exact receipt."""

    store = ledger(args.ledger)
    candidate = _task_turn_reservation(
        store,
        delivery_kind=args.delivery_kind,
        thread_id=args.thread_id,
        delivery_token=args.delivery_token,
    )
    if candidate is None:
        raise RuntimeError("task-turn delivery reservation is unavailable")
    candidate = candidate | {"threadId": args.thread_id}
    validation_reservation_digest = (
        str(candidate.get("reservationDigest") or "")
        if args.delivery_kind == "validation-followup"
        else None
    )
    delivery_attempt_digest = (
        str(candidate.get("implementationFollowupAttemptDigest") or args.delivery_token)
        if args.delivery_kind == "implementation-followup"
        else None
    )
    receipt_key = _task_turn_delivery_file_key(
        delivery_kind=args.delivery_kind,
        thread_id=args.thread_id,
        delivery_token=args.delivery_token,
        delivery_attempt_digest=delivery_attempt_digest,
        validation_reservation_digest=validation_reservation_digest,
    )
    receipt_root = STATE / "task_turn_receipts"
    receipt = receipt_root / f"{receipt_key}.json"
    launch = receipt_root / f"{receipt_key}.launch.json"
    log = receipt_root / f"{receipt_key}.log"
    receipt_root.mkdir(parents=True, exist_ok=True)

    def desktop_handoff_result(result: dict[str, Any]) -> dict[str, Any] | None:
        if "DESKTOP_ACTIVE_WRITER" not in str(result.get("error") or ""):
            return None
        return {
            "ok": True,
            "pending": True,
            "requiresDesktopHandoff": True,
            "threadId": args.thread_id,
            "deliveryKind": args.delivery_kind,
            "desktopHandoff": _desktop_task_handoff(
                delivery_kind=args.delivery_kind,
                candidate=candidate,
                delivery_token=args.delivery_token,
            ),
        }

    try:
        _cwd, rollout_path = _validated_task_turn_thread(candidate)
        prompt = _task_turn_prompt(args.delivery_kind, candidate)
        if args.delivery_kind == "publication-feedback":
            activity_available = bool(rollout_path and Path(rollout_path).is_file())
            materialized = publication_feedback_materialized(
                rollout_path,
                str(candidate.get("prUrl") or ""),
            )
        else:
            activity_available, materialized = thread_prompt_materialized_after(
                rollout_path,
                str(candidate["reservedAt"]),
                prompt,
            )
    except Exception as exc:
        if not receipt.exists():
            _atomic_json(
                receipt,
                {
                    "ok": False,
                    "turnStarted": False,
                    "turnId": None,
                    "error": f"{type(exc).__name__}:{str(exc)[:300]}",
                    **(
                        {"reservationDigest": validation_reservation_digest}
                        if validation_reservation_digest
                        else {}
                    ),
                },
            )
        raise
    if materialized:
        _commit_task_turn_delivery(
            store,
            delivery_kind=args.delivery_kind,
            thread_id=args.thread_id,
            delivery_token=args.delivery_token,
            validation_reservation_digest=(
                validation_reservation_digest
                if args.delivery_kind == "validation-followup"
                else None
            ),
        )
        return {
            "ok": True,
            "threadId": args.thread_id,
            "deliveryKind": args.delivery_kind,
            "reconciled": True,
            "targetTurnMaterialized": True,
        }

    if receipt.exists():
        result = read_json(receipt, missing={})
        if (
            validation_reservation_digest
            and result.get("reservationDigest") != validation_reservation_digest
        ):
            return {
                "ok": False,
                "pending": True,
                "requiresReconciliation": True,
                "threadId": args.thread_id,
                "deliveryKind": args.delivery_kind,
                "reason": "VALIDATION_RECEIPT_BINDING_MISMATCH",
            }
        if result.get("ok"):
            return result
        desktop_result = desktop_handoff_result(result)
        if desktop_result is not None:
            return desktop_result
        if result.get("turnStarted"):
            return {
                "ok": False,
                "pending": True,
                "requiresReconciliation": True,
                "threadId": args.thread_id,
                "deliveryKind": args.delivery_kind,
                "turnId": result.get("turnId"),
                "reason": "TURN_STARTED_BEFORE_LEDGER_COMMIT",
            }
        receipt.unlink(missing_ok=True)
        launch.unlink(missing_ok=True)

    if launch.exists():
        launch_state = read_json(launch, missing={})
        if (
            validation_reservation_digest
            and launch_state.get("reservationDigest") != validation_reservation_digest
        ):
            return {
                "ok": False,
                "pending": True,
                "requiresReconciliation": True,
                "threadId": args.thread_id,
                "deliveryKind": args.delivery_kind,
                "reason": "VALIDATION_LAUNCH_BINDING_MISMATCH",
            }
        worker_pid = int(launch_state.get("pid") or 0)
        if worker_pid and _pid_is_alive(worker_pid):
            return {
                "ok": True,
                "pending": True,
                "threadId": args.thread_id,
                "deliveryKind": args.delivery_kind,
                "workerPid": worker_pid,
            }
        return {
            "ok": False,
            "pending": True,
            "requiresReconciliation": True,
            "threadId": args.thread_id,
            "deliveryKind": args.delivery_kind,
            "targetTurnMaterialized": materialized,
            "threadActivityAvailable": activity_available,
            "reason": "DELIVERY_WORKER_OUTCOME_UNKNOWN",
        }

    active_worker = active_task_turn_worker(args.thread_id)
    if active_worker is not None:
        return {
            "ok": True,
            "pending": True,
            "threadId": args.thread_id,
            "deliveryKind": args.delivery_kind,
            "reason": "TASK_TURN_WORKER_ACTIVE",
            "worker": active_worker,
        }

    opportunity_key = _task_opportunity_key(candidate)

    validation_binding: dict[str, Any] | None = None

    def validation_delivery_deferred(
        reason: str, exc: ValidationResultChanged | None = None
    ) -> dict[str, Any]:
        return {
            "ok": True,
            "deferred": True,
            "threadId": args.thread_id,
            "deliveryKind": args.delivery_kind,
            "resultDigest": args.delivery_token,
            "reason": reason,
            **(
                {
                    "expectedResultDigest": exc.expected,
                    "observedResultDigest": exc.observed,
                }
                if exc is not None
                else {}
            ),
        }

    try:
        with opportunity_action_guard(ledger_action_guard_root(store.path), opportunity_key):
            _require_task_action_clear(store, opportunity_key)
            if args.delivery_kind == "validation-followup":
                try:
                    reservation_digest = str(candidate["reservationDigest"])
                    if candidate.get("snapshotId"):
                        validation_binding = {
                            "reservationDigest": reservation_digest,
                            "snapshotId": str(candidate["snapshotId"]),
                            "snapshotPath": str(candidate["snapshotPath"]),
                            "snapshotDigest": str(candidate["snapshotDigest"]),
                            "worktreeInputPath": str(candidate["worktreeInputPath"]),
                            "worktreeInputDigest": str(candidate["worktreeInputDigest"]),
                            "resultDigest": args.delivery_token,
                        }
                        _validation_snapshot_metadata(
                            candidate=candidate,
                            reservation_digest=reservation_digest,
                            snapshot_id=validation_binding["snapshotId"],
                            snapshot_path=validation_binding["snapshotPath"],
                            snapshot_digest=validation_binding["snapshotDigest"],
                        )
                    else:
                        snapshot = _ensure_validation_snapshot(
                            candidate, reservation_digest=reservation_digest
                        )
                        validation_binding = {
                            "reservationDigest": reservation_digest,
                            "snapshotId": snapshot["snapshotId"],
                            "snapshotPath": snapshot["snapshotPath"],
                            "snapshotDigest": snapshot["snapshotDigest"],
                            **_validation_worktree_input_binding(
                                candidate=candidate,
                                reservation_digest=reservation_digest,
                                snapshot_digest=str(snapshot["snapshotDigest"]),
                            ),
                            "resultDigest": args.delivery_token,
                        }
                    candidate = candidate | validation_binding
                except ValidationResultChanged as exc:
                    store.cancel_validation_followup_reservation(
                        thread_id=args.thread_id,
                        result_digest=args.delivery_token,
                        reservation_digest=str(candidate["reservationDigest"]),
                        reason="VALIDATION_RESULT_CHANGED_BEFORE_SNAPSHOT",
                    )
                    _discard_negative_task_turn_receipt(
                        delivery_kind="validation-followup",
                        thread_id=args.thread_id,
                        delivery_token=args.delivery_token,
                        validation_reservation_digest=str(candidate["reservationDigest"]),
                    )
                    return validation_delivery_deferred(
                        "VALIDATION_RESULT_CHANGED_BEFORE_SNAPSHOT", exc
                    )
                except (OSError, RuntimeError, ValueError):
                    store.cancel_validation_followup_reservation(
                        thread_id=args.thread_id,
                        result_digest=args.delivery_token,
                        reservation_digest=str(candidate["reservationDigest"]),
                        reason="VALIDATION_SNAPSHOT_INVALID",
                    )
                    _discard_negative_task_turn_receipt(
                        delivery_kind="validation-followup",
                        thread_id=args.thread_id,
                        delivery_token=args.delivery_token,
                        validation_reservation_digest=str(candidate["reservationDigest"]),
                    )
                    return validation_delivery_deferred("VALIDATION_SNAPSHOT_INVALID", None)
            store.authorize_task_turn_delivery(
                delivery_kind=args.delivery_kind,
                thread_id=args.thread_id,
                delivery_token=args.delivery_token,
                delivery_attempt_digest=delivery_attempt_digest,
                **(
                    {
                        "reservation_digest": validation_binding["reservationDigest"],
                        "snapshot_id": validation_binding["snapshotId"],
                        "snapshot_path": validation_binding["snapshotPath"],
                        "snapshot_digest": validation_binding["snapshotDigest"],
                        "worktree_input_path": validation_binding["worktreeInputPath"],
                        "worktree_input_digest": validation_binding["worktreeInputDigest"],
                    }
                    if validation_binding
                    else {}
                ),
            )
            if validation_binding is not None:
                _validation_snapshot_metadata(
                    candidate=candidate,
                    reservation_digest=validation_binding["reservationDigest"],
                    snapshot_id=validation_binding["snapshotId"],
                    snapshot_path=validation_binding["snapshotPath"],
                    snapshot_digest=validation_binding["snapshotDigest"],
                )
            with log.open("ab") as handle:
                worker_argv = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--runtime-root",
                    str(getattr(args, "runtime_root", STATE.parent)),
                    "--ledger",
                    str(args.ledger),
                    "task-turn-worker",
                    "--delivery-kind",
                    args.delivery_kind,
                    "--thread-id",
                    args.thread_id,
                    "--delivery-token",
                    args.delivery_token,
                ]
                if delivery_attempt_digest:
                    worker_argv.extend(["--delivery-attempt-digest", delivery_attempt_digest])
                if validation_binding:
                    worker_argv.extend(
                        [
                            "--reservation-digest",
                            validation_binding["reservationDigest"],
                            "--snapshot-id",
                            validation_binding["snapshotId"],
                            "--snapshot-path",
                            validation_binding["snapshotPath"],
                            "--snapshot-digest",
                            validation_binding["snapshotDigest"],
                            "--worktree-input-path",
                            validation_binding["worktreeInputPath"],
                            "--worktree-input-digest",
                            validation_binding["worktreeInputDigest"],
                        ]
                    )
                worker_argv.extend(
                    [
                        "--receipt",
                        str(receipt),
                    ]
                )
                worker = subprocess.Popen(
                    worker_argv,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
    except Exception as exc:
        if not receipt.exists():
            _atomic_json(
                receipt,
                {
                    "ok": False,
                    "turnStarted": False,
                    "turnId": None,
                    "error": f"{type(exc).__name__}:{str(exc)[:300]}",
                    **(
                        {"reservationDigest": validation_reservation_digest}
                        if validation_reservation_digest
                        else {}
                    ),
                },
            )
        raise
    _atomic_json(
        launch,
        {
            "pid": worker.pid,
            "startedAt": iso_z(datetime.now(UTC)),
            "threadId": args.thread_id,
            "deliveryKind": args.delivery_kind,
            "deliveryToken": args.delivery_token,
            **(
                {"deliveryAttemptDigest": delivery_attempt_digest}
                if delivery_attempt_digest
                else {}
            ),
            **(
                {"reservationDigest": validation_reservation_digest}
                if validation_reservation_digest
                else {}
            ),
        },
    )
    deadline = monotonic() + 60
    while monotonic() < deadline:
        if receipt.exists():
            result = read_json(receipt, missing={})
            if result.get("ok"):
                return result
            desktop_result = desktop_handoff_result(result)
            if desktop_result is not None:
                return desktop_result
            if result.get("turnStarted"):
                return {
                    "ok": False,
                    "pending": True,
                    "requiresReconciliation": True,
                    "threadId": args.thread_id,
                    "deliveryKind": args.delivery_kind,
                    "turnId": result.get("turnId"),
                    "reason": "TURN_STARTED_BEFORE_LEDGER_COMMIT",
                }
            raise RuntimeError(str(result.get("error") or "task-turn delivery failed"))
        sleep(0.25)
    return {
        "ok": True,
        "pending": True,
        "threadId": args.thread_id,
        "deliveryKind": args.delivery_kind,
        "workerPid": worker.pid,
    }


def implementation_followup_deliver(args: argparse.Namespace) -> dict[str, Any]:
    args.delivery_kind = "implementation-followup"
    args.delivery_token = args.result_digest
    return task_turn_deliver(args)


def implementation_followup_reserve(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidate = next(
        (
            item
            for item in store.implementation_followup_candidates()
            if item["threadId"] == args.thread_id and item["resultDigest"] == args.result_digest
        ),
        None,
    )
    if candidate is None:
        raise RuntimeError("implementation follow-up authorization is stale or invalid")
    opportunity_key = str(candidate["key"])
    with opportunity_action_guard(ledger_action_guard_root(Path(args.ledger)), opportunity_key):
        _require_task_action_clear(store, opportunity_key)
        context_path = write_task_context(
            store,
            issue_url=str(candidate["issueUrl"]),
            thread_id=str(candidate["threadId"]),
            cwd=Path(candidate["worktreePath"]),
        )
        context = json.loads(context_path.read_text(encoding="utf-8"))
        if (
            context.get("taskStage") != "IMPLEMENTATION_READY"
            or context.get("probeLevel") != REPRODUCED_VALIDATED
            or context.get("childMayEditFiles") is not True
            or context.get("resultDigest") != args.result_digest
            or not isinstance(context.get("reproductionReceipt"), dict)
        ):
            raise RuntimeError("implementation follow-up context is not authorized")
        return store.reserve_implementation_followup(
            thread_id=args.thread_id,
            result_digest=args.result_digest,
        )


def pr_followup_deliver(args: argparse.Namespace) -> dict[str, Any]:
    args.delivery_kind = "pr-followup"
    args.delivery_token = args.wake_digest
    return task_turn_deliver(args)


def validation_followup_deliver(args: argparse.Namespace) -> dict[str, Any]:
    args.delivery_kind = "validation-followup"
    args.delivery_token = args.result_digest
    return task_turn_deliver(args)


def publication_feedback_deliver(args: argparse.Namespace) -> dict[str, Any]:
    args.delivery_kind = "publication-feedback"
    args.delivery_token = args.reservation_nonce
    return task_turn_deliver(args)


def recovery_deliver(args: argparse.Namespace) -> dict[str, Any]:
    args.delivery_kind = "recovery"
    args.delivery_token = args.recovery_nonce
    return task_turn_deliver(args)


def commit_receipt(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    pending = {item["intentId"]: item for item in store.pending()}
    intent = pending.get(args.intent_id)
    if not intent:
        raise RuntimeError("intent is not pending")
    source = Path(args.source_repo).resolve()
    thread_cwd = Path(args.cwd).resolve()
    worktree = Path(getattr(args, "worktree", None) or args.cwd).resolve()
    if worktree == source or not _worktree_belongs_to_source(worktree, source):
        raise RuntimeError("worktree does not belong to source repository")
    managed = _is_managed_worktree(worktree)
    if managed:
        expected = managed_worktree_path(str(intent["intentId"]), str(intent["repo"]))
        if worktree != expected or thread_cwd != GITHUB_ROOT.resolve():
            raise RuntimeError("managed task project or worktree mismatch")
    elif thread_cwd != worktree or not _is_within(worktree, WORKTREE_ROOT):
        raise RuntimeError("thread cwd is not a Codex worktree")
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        columns = {
            str(item[1]) for item in connection.execute("PRAGMA table_info(threads)").fetchall()
        }
        source_projection = "thread_source" if "thread_source" in columns else "'appServer'"
        row = connection.execute(
            f"SELECT cwd,title,first_user_message,git_origin_url,archived,{source_projection} AS thread_source FROM threads WHERE id=?",
            (args.thread_id,),
        ).fetchone()
    finally:
        connection.close()
    expected_title = lifecycle_title("GO", args.title_time, intent["key"], intent["title"])
    if row is None or int(row["archived"] or 0) != 0:
        raise RuntimeError("thread is missing or archived")
    if str(row["thread_source"] or "") != "appServer":
        raise RuntimeError("thread is not a project-root app-server task")
    if Path(row["cwd"]).resolve() != thread_cwd:
        raise RuntimeError("thread cwd mismatch")
    if canonical_prompt(row["first_user_message"] or "") != issue_prompt(intent["issueUrl"]):
        raise RuntimeError("thread prompt mismatch")
    if (
        not managed
        and normalize_origin(row["git_origin_url"] or "") != str(intent["repo"]).casefold()
    ):
        raise RuntimeError("thread origin mismatch")
    _ensure_desktop_thread_title(args.thread_id, expected_title)
    store.commit_dispatch(
        intent["intentId"],
        owner=_active_owner(store, args),
        thread_id=args.thread_id,
        project_id=args.project_id,
        worktree_path=str(worktree),
        title_time=args.title_time,
    )
    context_path = write_task_context(
        store,
        issue_url=intent["issueUrl"],
        thread_id=args.thread_id,
        cwd=worktree,
    )
    return {
        "ok": True,
        "key": intent["key"],
        "threadId": args.thread_id,
        "workspaceMode": "github_project_managed_worktree" if managed else "codex_worktree",
        "taskContextPath": str(context_path),
    }


def retry_dispatch(args: argparse.Namespace) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", args.reason):
        raise RuntimeError("retry reason must be machine-readable")
    store = ledger(args.ledger)
    dispatches = {
        item["threadId"]: item for item in store.task_context_candidates() if item.get("threadId")
    }
    dispatch = dispatches.get(args.thread_id)
    if dispatch is None:
        raise RuntimeError("retry task context is unavailable")
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT cwd,archived FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row["archived"] or 0) != 1:
        raise RuntimeError("retry requires the old task to be archived first")
    thread_cwd = Path(row["cwd"]).resolve()
    worktree = Path(dispatch["worktreePath"]).resolve()
    managed = _is_managed_worktree(worktree)
    if managed:
        if thread_cwd != GITHUB_ROOT.resolve():
            raise RuntimeError("retry task project root mismatch")
    elif thread_cwd != worktree or not _is_within(worktree, WORKTREE_ROOT):
        raise RuntimeError("retry task cwd is not a Codex worktree")
    if worktree.exists():
        if (worktree / TASK_PRIVATE_DIR / "result.json").exists():
            raise RuntimeError("retry refused because the task already produced a result")
        if command(["git", "status", "--porcelain"], cwd=worktree):
            raise RuntimeError("retry refused because the task worktree is not clean")
    elif int(row["archived"] or 0) != 1:
        raise RuntimeError("retry task worktree is missing before archival")
    if managed:
        shared_context_path(dispatch["issueUrl"]).unlink(missing_ok=True)
        (worktree / TASK_PRIVATE_DIR / "task-context.json").unlink(missing_ok=True)
    value = store.reset_dispatch_for_retry(
        thread_id=args.thread_id,
        reason=args.reason,
    )
    return {"ok": True, "retried": value}


def _thread_created_at(row: sqlite3.Row) -> float:
    created_at_ms = int(row["created_at_ms"] or 0)
    return created_at_ms / 1000 if created_at_ms else float(row["created_at"])


def orphan_list(args: argparse.Namespace) -> dict[str, Any]:
    """Find uniquely matching tasks hidden by asynchronous worktree creation."""

    store = ledger(args.ledger)
    handoffs = store.orphaned_handoffs()
    bound_thread_ids = store.bound_thread_ids()
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """SELECT id,cwd,title,first_user_message,git_origin_url,archived,
                      created_at,created_at_ms
               FROM threads"""
        ).fetchall()
    finally:
        connection.close()

    candidates: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    now = datetime.now().astimezone().timestamp()
    abandon_min_age_minutes = max(
        1,
        int(getattr(args, "min_age_minutes", ORPHAN_ABANDON_MIN_AGE_MINUTES)),
    )
    worktree_root = WORKTREE_ROOT.resolve()
    task_project_root = GITHUB_ROOT.resolve()
    for handoff in handoffs:
        creation_started_at = handoff.get("creationStartedAt")
        started = parse_time(str(creation_started_at or handoff["leaseStartedAt"])).timestamp() - 60
        lease_end = handoff.get("leaseUntil") or handoff.get("expiresAt")
        ended = (
            None
            if handoff["intentStatus"] == "CREATING"
            else parse_time(str(lease_end)).timestamp() + 300
        )
        matches: list[sqlite3.Row] = []
        for row in rows:
            if row["id"] in bound_thread_ids:
                continue
            created = _thread_created_at(row)
            if created < started or (ended is not None and created > ended):
                continue
            if canonical_prompt(row["first_user_message"] or "") != issue_prompt(
                handoff["issueUrl"]
            ):
                continue
            thread_cwd = Path(row["cwd"]).resolve()
            legacy = (
                normalize_origin(row["git_origin_url"] or "") == str(handoff["repo"]).casefold()
                and thread_cwd != worktree_root
                and worktree_root in thread_cwd.parents
            )
            managed = thread_cwd == task_project_root
            if not legacy and not managed:
                continue
            matches.append(row)
        if not matches:
            lease_until = parse_time(str(lease_end)).timestamp()
            if handoff["intentStatus"] == "CREATING" or (
                handoff["intentStatus"] == "LEASED" and lease_until > now
            ):
                value = {
                    "intentId": handoff["intentId"],
                    "key": handoff["key"],
                    "leaseStartedAt": handoff["leaseStartedAt"],
                    "creationStartedAt": creation_started_at,
                    "clientThreadId": handoff.get("clientThreadId"),
                    "creationPending": handoff["intentStatus"] == "CREATING",
                }
                if handoff["intentStatus"] == "CREATING" and creation_started_at:
                    creation_age_minutes = max(
                        0,
                        int((now - parse_time(str(creation_started_at)).timestamp()) // 60),
                    )
                    value["creationAgeMinutes"] = creation_age_minutes
                    value["abandonable"] = creation_age_minutes >= abandon_min_age_minutes
                    if value["abandonable"]:
                        value["abandonNonce"] = sha256_json(
                            {
                                "intentId": handoff["intentId"],
                                "clientThreadId": handoff["clientThreadId"],
                                "creationStartedAt": creation_started_at,
                                "creationToken": handoff.get("creationToken"),
                                "operation": "orphan-creation-abandon-v2",
                            }
                        )
                unmatched.append(value)
            continue
        if len(matches) != 1:
            blocked.append(
                {
                    "intentId": handoff["intentId"],
                    "key": handoff["key"],
                    "reason": "ambiguous_matching_threads",
                    "threadIds": sorted(str(row["id"]) for row in matches),
                }
            )
            continue
        row = matches[0]
        if int(row["archived"] or 0) != 0:
            blocked.append(
                {
                    "intentId": handoff["intentId"],
                    "key": handoff["key"],
                    "reason": "matching_thread_archived",
                    "threadIds": [str(row["id"])],
                }
            )
            continue
        thread_cwd = Path(row["cwd"]).resolve()
        managed = thread_cwd == task_project_root
        worktree = (
            managed_worktree_path(str(handoff["intentId"]), str(handoff["repo"]))
            if managed
            else thread_cwd
        )
        created = _thread_created_at(row)
        title_time = datetime.fromtimestamp(created).astimezone().strftime("%m-%d %H:%M")
        nonce = sha256_json(
            {
                "intentId": handoff["intentId"],
                "threadId": row["id"],
                "threadCwd": str(thread_cwd),
                "worktreePath": str(worktree),
                "leaseStartedAt": handoff["leaseStartedAt"],
                "operation": "orphan-dispatch-reconcile-v1",
            }
        )
        candidates.append(
            handoff
            | {
                "threadId": row["id"],
                "cwd": row["cwd"],
                "worktreePath": str(worktree),
                "workspaceMode": (
                    "github_project_managed_worktree" if managed else "codex_worktree"
                ),
                "currentTitle": row["title"],
                "titleTime": title_time,
                "desiredTitle": lifecycle_title("GO", title_time, handoff["key"], handoff["title"]),
                "orphanNonce": nonce,
            }
        )
    return {
        "ok": not blocked,
        "candidates": candidates,
        "blocked": blocked,
        "unmatched": unmatched,
    }


def duplicate_task_list(args: argparse.Namespace) -> dict[str, Any]:
    """List stale, unbound desktop tasks shadowing a ledger-bound issue task."""

    store = ledger(args.ledger)
    bindings = {
        canonical_prompt(issue_prompt(str(item["issueUrl"]))): item
        for item in store.task_context_candidates()
        if item.get("threadId") and item.get("issueUrl")
    }
    if not bindings or not THREAD_DB.is_file():
        return {"ok": True, "duplicates": []}
    bound_thread_ids = store.bound_thread_ids()
    cutoff = int(
        (
            datetime.now(UTC)
            - timedelta(minutes=max(30, int(getattr(args, "min_age_minutes", 30))))
        ).timestamp()
    )
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """SELECT id,title,first_user_message,archived,created_at,updated_at,
                      thread_source
               FROM threads WHERE cwd=? AND archived=0 AND updated_at<=?""",
            (str(GITHUB_ROOT.resolve()), cutoff),
        ).fetchall()
    finally:
        connection.close()
    duplicates: list[dict[str, Any]] = []
    for row in rows:
        thread_id = str(row["id"])
        if thread_id in bound_thread_ids:
            continue
        if str(row["thread_source"] or "").casefold() == "subagent":
            continue
        binding = bindings.get(canonical_prompt(row["first_user_message"] or ""))
        if binding is None or str(binding["threadId"]) == thread_id:
            continue
        title = str(row["title"] or "")
        if not (title.startswith("<codex_delegation>") or title.startswith("[无价值·重复任务]")):
            continue
        created = datetime.fromtimestamp(int(row["created_at"] or 0), tz=UTC).astimezone()
        desired_title = f"[无价值·重复任务] {created:%m-%d %H:%M} {binding['key']}"
        duplicates.append(
            {
                "threadId": thread_id,
                "canonicalThreadId": str(binding["threadId"]),
                "key": str(binding["key"]),
                "issueUrl": str(binding["issueUrl"]),
                "currentTitle": title,
                "desiredTitle": desired_title,
                "createdAt": int(row["created_at"] or 0),
                "updatedAt": int(row["updated_at"] or 0),
            }
        )
    duplicates.sort(key=lambda item: (item["createdAt"], item["threadId"]))
    return {"ok": True, "duplicates": duplicates}


def duplicate_task_title_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    candidates = duplicate_task_list(args)["duplicates"]
    if not candidates:
        return {"ok": True, "renamed": [], "errors": []}
    results = _set_desktop_thread_titles(candidates)
    connection = sqlite3.connect(THREAD_DB)
    try:
        current = {
            str(row[0]): str(row[1] or "")
            for row in connection.execute(
                f"SELECT id,title FROM threads WHERE id IN ({','.join('?' for _ in candidates)})",
                [item["threadId"] for item in candidates],
            ).fetchall()
        }
    finally:
        connection.close()
    renamed: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for candidate in candidates:
        thread_id = candidate["threadId"]
        if current.get(thread_id) == candidate["desiredTitle"]:
            renamed.append(
                {
                    "threadId": thread_id,
                    "key": candidate["key"],
                    "title": candidate["desiredTitle"],
                }
            )
        else:
            errors.append(
                {
                    "threadId": thread_id,
                    "key": candidate["key"],
                    "error": results.get(thread_id) or "thread title was not applied",
                }
            )
    return {"ok": not errors, "renamed": renamed, "errors": errors}


def duplicate_task_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    """Mark and archive only exact, stale duplicates of a canonical Radar task."""

    titles = duplicate_task_title_reconcile(args)
    errors: list[dict[str, Any]] = list(titles.get("errors") or [])
    renamed_ids = {str(item.get("threadId")) for item in titles.get("renamed") or []}
    candidates = duplicate_task_list(args).get("duplicates") or []
    eligible = [
        candidate
        for candidate in candidates
        if str(candidate.get("currentTitle") or "").startswith("[无价值·重复任务]")
        or str(candidate.get("threadId")) in renamed_ids
    ]
    apply_results = _archive_desktop_threads(eligible)
    archived: list[dict[str, Any]] = []
    for candidate in eligible:
        thread_id = str(candidate["threadId"])
        if apply_results.get(thread_id):
            errors.append(
                {
                    "key": candidate.get("key"),
                    "threadId": thread_id,
                    "error": apply_results[thread_id],
                }
            )
            continue
        archived.append(
            {
                "key": candidate.get("key"),
                "threadId": thread_id,
                "canonicalThreadId": candidate.get("canonicalThreadId"),
            }
        )
    return {
        "ok": not errors,
        "renamed": titles.get("renamed") or [],
        "archived": archived,
        "errors": errors,
    }


def orphan_commit(args: argparse.Namespace) -> dict[str, Any]:
    result = orphan_list(args)
    candidates = {item["intentId"]: item for item in result["candidates"]}
    candidate = candidates.get(args.intent_id)
    if candidate is None or candidate["orphanNonce"] != args.orphan_nonce:
        raise RuntimeError("orphan reconciliation authorization is stale or invalid")
    if candidate["threadId"] != args.thread_id:
        raise RuntimeError("orphan thread mismatch")
    if candidate["desiredTitle"] != args.desired_title:
        raise RuntimeError("orphan desired title mismatch")
    source = Path(args.source_repo).resolve()
    thread_cwd = Path(candidate["cwd"]).resolve()
    cwd = Path(candidate["worktreePath"]).resolve()
    if (
        normalize_origin(command(["git", "remote", "get-url", "origin"], cwd=source))
        != str(candidate["repo"]).casefold()
    ):
        raise RuntimeError("source repository origin mismatch")
    if not _worktree_belongs_to_source(cwd, source):
        raise RuntimeError("orphan worktree does not belong to source repository")
    if candidate["workspaceMode"] == "github_project_managed_worktree":
        if thread_cwd != GITHUB_ROOT.resolve() or not _is_managed_worktree(cwd):
            raise RuntimeError("orphan managed task project mismatch")
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT title,archived,cwd FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[1] or 0) != 0 or Path(row[2]).resolve() != thread_cwd:
        raise RuntimeError("orphan thread binding is invalid")
    _ensure_desktop_thread_title(args.thread_id, args.desired_title)
    store = ledger(args.ledger)
    store.commit_orphan_dispatch(
        args.intent_id,
        thread_id=args.thread_id,
        project_id=args.project_id,
        worktree_path=str(cwd),
        title_time=candidate["titleTime"],
        lease_started_at=candidate["leaseStartedAt"],
    )
    context_path = write_task_context(
        store,
        issue_url=candidate["issueUrl"],
        thread_id=args.thread_id,
        cwd=cwd,
    )
    return {
        "ok": True,
        "key": candidate["key"],
        "threadId": args.thread_id,
        "reconciled": True,
        "taskContextPath": str(context_path),
    }


def orphan_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    """Finish or safely abandon interrupted task creation without model judgment."""

    state = orphan_list(args)
    reconciled: list[dict[str, Any]] = []
    abandoned: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = list(state.get("blocked") or [])
    for candidate in state.get("candidates") or []:
        try:
            source = source_repo(str(candidate["repo"]))
            result = orphan_commit(
                argparse.Namespace(
                    ledger=args.ledger,
                    min_age_minutes=getattr(
                        args, "min_age_minutes", ORPHAN_ABANDON_MIN_AGE_MINUTES
                    ),
                    intent_id=candidate["intentId"],
                    thread_id=candidate["threadId"],
                    project_id=getattr(args, "project_id", DEFAULT_TASK_PROJECT_ID),
                    source_repo=str(source),
                    desired_title=candidate["desiredTitle"],
                    orphan_nonce=candidate["orphanNonce"],
                )
            )
            reconciled.append(result)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            errors.append(
                {
                    "key": candidate.get("key"),
                    "intentId": candidate.get("intentId"),
                    "error": f"{type(exc).__name__}:{str(exc)[:240]}",
                }
            )
    for candidate in state.get("unmatched") or []:
        if not candidate.get("abandonable"):
            continue
        try:
            result = creation_abandon(
                argparse.Namespace(
                    ledger=args.ledger,
                    min_age_minutes=getattr(
                        args, "min_age_minutes", ORPHAN_ABANDON_MIN_AGE_MINUTES
                    ),
                    intent_id=candidate["intentId"],
                    owner=None,
                    client_thread_id=candidate.get("clientThreadId"),
                    abandon_nonce=candidate["abandonNonce"],
                    reason="ASYNC_CREATION_NOT_MATERIALIZED",
                )
            )
            abandoned.append(result)
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(
                {
                    "key": candidate.get("key"),
                    "intentId": candidate.get("intentId"),
                    "error": f"{type(exc).__name__}:{str(exc)[:240]}",
                }
            )
    return {
        "ok": not errors,
        "reconciled": reconciled,
        "abandoned": abandoned,
        "pending": [item for item in state.get("unmatched") or [] if not item.get("abandonable")],
        "errors": errors,
    }


def _task_result_path(candidate: dict[str, Any]) -> Path:
    """Return the lexical result path for display/audit only.

    Do not use this helper for authority reads or writes.  Task result content
    must flow through a validated task private directory descriptor.
    """

    return (
        _lexical_absolute(Path(str(candidate["worktreePath"]))) / TASK_PRIVATE_DIR / "result.json"
    )


_VALIDATION_SNAPSHOT_ID = re.compile(r"^[0-9a-f]{64}$")
_VALIDATION_SNAPSHOT_RELATIVE_PREFIX = "validation-inputs"
_VALIDATION_WORKTREE_INPUT_RELATIVE_PREFIX = f"{TASK_PRIVATE_DIR}/validation-inputs"


class _DirectoryBinding:
    __slots__ = ("path", "fd", "label", "required_mode")

    def __init__(self, path: Path, fd: int, label: str, required_mode: int | None = None) -> None:
        self.path = path
        self.fd = fd
        self.label = label
        self.required_mode = required_mode


def _directory_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _validate_directory_binding(binding: _DirectoryBinding) -> None:
    try:
        path_stat = binding.path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{binding.label} is missing") from exc
    descriptor_stat = os.fstat(binding.fd)
    path_mode = stat.S_IMODE(path_stat.st_mode)
    descriptor_mode = stat.S_IMODE(descriptor_stat.st_mode)
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or not stat.S_ISDIR(path_stat.st_mode)
        or path_stat.st_uid != os.getuid()
        or path_mode & 0o022
        or not stat.S_ISDIR(descriptor_stat.st_mode)
        or descriptor_stat.st_uid != os.getuid()
        or descriptor_mode & 0o022
        or (path_stat.st_dev, path_stat.st_ino) != (descriptor_stat.st_dev, descriptor_stat.st_ino)
    ):
        raise RuntimeError(f"{binding.label} is unsafe")
    if binding.required_mode is not None and (
        path_mode != binding.required_mode or descriptor_mode != binding.required_mode
    ):
        raise RuntimeError(f"{binding.label} is unsafe")


def _validate_directory_bindings(bindings: list[_DirectoryBinding]) -> None:
    for binding in bindings:
        _validate_directory_binding(binding)


def _open_directory_child(
    *,
    parent_fd: int,
    parent_path: Path,
    name: str,
    label: str,
    create: bool = False,
    required_mode: int | None = None,
) -> tuple[int, Path]:
    if name in {"", ".", ".."} or "/" in name:
        raise RuntimeError(f"{label} name is invalid")
    if create:
        try:
            os.mkdir(name, required_mode or 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        source_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    source_mode = stat.S_IMODE(source_stat.st_mode)
    if (
        stat.S_ISLNK(source_stat.st_mode)
        or not stat.S_ISDIR(source_stat.st_mode)
        or source_stat.st_uid != os.getuid()
        or source_mode & 0o022
        or (required_mode is not None and source_mode != required_mode)
    ):
        raise RuntimeError(f"{label} is unsafe")
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise RuntimeError(f"{label} could not be opened safely") from exc
    descriptor_stat = os.fstat(fd)
    descriptor_mode = stat.S_IMODE(descriptor_stat.st_mode)
    if (
        not stat.S_ISDIR(descriptor_stat.st_mode)
        or descriptor_stat.st_uid != os.getuid()
        or descriptor_mode & 0o022
        or (required_mode is not None and descriptor_mode != required_mode)
        or (source_stat.st_dev, source_stat.st_ino)
        != (descriptor_stat.st_dev, descriptor_stat.st_ino)
    ):
        os.close(fd)
        raise RuntimeError(f"{label} is unsafe")
    return fd, parent_path / name


def _open_validation_snapshot_state(*, create: bool) -> tuple[Path, int, Path, int]:
    if STATE.name in {"", ".", ".."} or "/" in STATE.name:
        raise RuntimeError("validation snapshot state directory name is invalid")
    runtime_root = _lexical_absolute(STATE.parent)
    if STATE.name != "state":
        raise RuntimeError("validation snapshot state directory is not bound to runtime root")
    root_fd, root_path = open_directory_handle(
        runtime_root,
        label="validation snapshot runtime root",
    )
    state_fd = -1
    try:
        state_fd, state_path = _open_directory_child(
            parent_fd=root_fd,
            parent_path=root_path,
            name=STATE.name,
            label="validation snapshot state directory",
            create=create,
        )
        return root_path, root_fd, state_path, state_fd
    except Exception:
        if state_fd >= 0:
            os.close(state_fd)
        os.close(root_fd)
        raise


def _require_validation_snapshot_root_binding(
    *,
    runtime_root_path: Path,
    runtime_root_fd: int,
    state_path: Path,
    state_fd: int,
    root_fd: int,
) -> None:
    _validate_directory_bindings(
        [
            _DirectoryBinding(
                runtime_root_path,
                runtime_root_fd,
                "validation snapshot runtime root",
            ),
            _DirectoryBinding(
                state_path,
                state_fd,
                "validation snapshot state directory",
            ),
        ]
    )
    try:
        state_from_root = os.stat(STATE.name, dir_fd=runtime_root_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise RuntimeError("validation snapshot state directory is missing") from exc
    state_descriptor_stat = os.fstat(state_fd)
    if (
        stat.S_ISLNK(state_from_root.st_mode)
        or not stat.S_ISDIR(state_from_root.st_mode)
        or (state_from_root.st_dev, state_from_root.st_ino)
        != (state_descriptor_stat.st_dev, state_descriptor_stat.st_ino)
    ):
        raise RuntimeError("validation snapshot state directory is unsafe")
    try:
        root_stat = os.stat(
            _VALIDATION_SNAPSHOT_RELATIVE_PREFIX,
            dir_fd=state_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("validation snapshot root is missing") from exc
    root_descriptor_stat = os.fstat(root_fd)
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
        or not stat.S_ISDIR(root_descriptor_stat.st_mode)
        or root_descriptor_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_descriptor_stat.st_mode) != 0o700
        or (root_stat.st_dev, root_stat.st_ino)
        != (root_descriptor_stat.st_dev, root_descriptor_stat.st_ino)
    ):
        raise RuntimeError("validation snapshot root is unsafe")


@contextmanager
def _validation_snapshot_root_descriptor(*, create: bool):
    runtime_root_path, runtime_root_fd, state_path, state_fd = _open_validation_snapshot_state(
        create=create
    )
    root_fd = -1
    try:
        if create:
            try:
                os.mkdir(_VALIDATION_SNAPSHOT_RELATIVE_PREFIX, 0o700, dir_fd=state_fd)
            except FileExistsError:
                pass
        try:
            root_stat = os.stat(
                _VALIDATION_SNAPSHOT_RELATIVE_PREFIX,
                dir_fd=state_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("validation snapshot root is missing") from exc
        if (
            stat.S_ISLNK(root_stat.st_mode)
            or not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.getuid()
        ):
            raise RuntimeError("validation snapshot root is unsafe")
        try:
            root_fd = os.open(
                _VALIDATION_SNAPSHOT_RELATIVE_PREFIX,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=state_fd,
            )
        except OSError as exc:
            raise RuntimeError("validation snapshot root could not be opened safely") from exc
        descriptor_stat = os.fstat(root_fd)
        if create and stat.S_IMODE(descriptor_stat.st_mode) != 0o700:
            os.fchmod(root_fd, 0o700)
        _require_validation_snapshot_root_binding(
            runtime_root_path=runtime_root_path,
            runtime_root_fd=runtime_root_fd,
            state_path=state_path,
            state_fd=state_fd,
            root_fd=root_fd,
        )
        try:
            yield root_fd
        except BaseException:
            raise
        else:
            _require_validation_snapshot_root_binding(
                runtime_root_path=runtime_root_path,
                runtime_root_fd=runtime_root_fd,
                state_path=state_path,
                state_fd=state_fd,
                root_fd=root_fd,
            )
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        os.close(state_fd)
        os.close(runtime_root_fd)


def _read_owned_regular_file(
    path: Path,
    *,
    label: str,
    required_mode: int | None = None,
    reject_dangerous_writes: bool = False,
    directory_fd: int | None = None,
    missing_error: type[RuntimeError] = RuntimeError,
) -> bytes:
    """Read one owned regular file through a single no-follow descriptor."""

    try:
        if directory_fd is None:
            path_stat = path.lstat()
        else:
            if path.is_absolute() or len(path.parts) != 1:
                raise RuntimeError(f"{label} path is unsafe")
            path_stat = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise missing_error(f"{label} is missing") from exc
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or not stat.S_ISREG(path_stat.st_mode)
        or path_stat.st_uid != os.getuid()
    ):
        raise RuntimeError(f"{label} permissions are unsafe")
    path_mode = stat.S_IMODE(path_stat.st_mode)
    if required_mode is not None and path_mode != required_mode:
        raise RuntimeError(f"{label} permissions are unsafe")
    if reject_dangerous_writes and path_mode & 0o022:
        raise RuntimeError(f"{label} permissions are unsafe")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise RuntimeError(f"{label} could not be opened safely") from exc
    try:
        descriptor_stat = os.fstat(descriptor)
        if (
            stat.S_ISLNK(descriptor_stat.st_mode)
            or not stat.S_ISREG(descriptor_stat.st_mode)
            or descriptor_stat.st_uid != os.getuid()
        ):
            raise RuntimeError(f"{label} permissions are unsafe")
        descriptor_mode = stat.S_IMODE(descriptor_stat.st_mode)
        if required_mode is not None and descriptor_mode != required_mode:
            raise RuntimeError(f"{label} permissions are unsafe")
        if reject_dangerous_writes and descriptor_mode & 0o022:
            raise RuntimeError(f"{label} permissions are unsafe")
        if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
            path_stat.st_dev,
            path_stat.st_ino,
        ):
            raise RuntimeError(f"{label} changed before it was opened")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_validation_snapshot_raw_from_descriptor(*, snapshot_id: str, root_fd: int) -> bytes:
    return _read_owned_regular_file(
        Path(f"{snapshot_id}.json"),
        label="validation snapshot",
        required_mode=0o400,
        directory_fd=root_fd,
    )


def _read_controlled_validation_result(candidate: dict[str, Any]) -> bytes:
    with _validation_worktree_private_descriptor(candidate) as private_fd:
        return _read_owned_regular_file(
            Path("result.json"),
            label="validation result",
            reject_dangerous_writes=True,
            directory_fd=private_fd,
            missing_error=MissingValidationResult,
        )


def _controlled_validation_result_exists(candidate: dict[str, Any]) -> bool:
    with _validation_worktree_private_descriptor(candidate) as private_fd:
        try:
            os.stat("result.json", dir_fd=private_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True


def _read_authenticated_validation_result(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    """Read and authenticate one queued validation result from one safe fd."""

    raw = _read_controlled_validation_result(candidate)
    expected = str(candidate["resultDigest"])
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationResultChanged(
            expected=expected,
            observed=hashlib.sha256(raw).hexdigest(),
        ) from exc
    if not isinstance(value, dict):
        raise ValidationResultChanged(
            expected=expected,
            observed=hashlib.sha256(raw).hexdigest(),
        )
    try:
        observed = _task_result_digest(value, raw)
    except RuntimeError as exc:
        if "receipt result digest does not match result" not in str(exc):
            raise
        raise ValidationResultChanged(
            expected=expected,
            observed=hashlib.sha256(raw).hexdigest(),
        ) from exc
    if observed != expected:
        raise ValidationResultChanged(expected=expected, observed=observed)
    return value, raw


def _read_authenticated_validation_result_if_present(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any], bytes] | None:
    try:
        return _read_authenticated_validation_result(candidate)
    except MissingValidationResult:
        return None


def _validation_snapshot_bytes_from_descriptor(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    snapshot_id: str,
    snapshot_path: str,
    snapshot_digest: str,
    root_fd: int,
) -> bytes:
    if not _VALIDATION_SNAPSHOT_ID.fullmatch(snapshot_id):
        raise RuntimeError("validation snapshot id is invalid")
    expected_path = f"{_VALIDATION_SNAPSHOT_RELATIVE_PREFIX}/{snapshot_id}.json"
    if snapshot_path != expected_path:
        raise RuntimeError("validation snapshot path is invalid")
    raw = _read_validation_snapshot_raw_from_descriptor(
        snapshot_id=snapshot_id,
        root_fd=root_fd,
    )
    snapshot_hash = hashlib.sha256(raw).hexdigest()
    if snapshot_hash != snapshot_digest:
        raise RuntimeError("validation snapshot digest mismatch")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("validation snapshot JSON is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("validation snapshot JSON is not an object")
    try:
        result_digest = _task_result_digest(value, raw)
    except RuntimeError as exc:
        raise RuntimeError("validation snapshot result digest is invalid") from exc
    if result_digest != candidate["resultDigest"]:
        raise RuntimeError("validation snapshot result digest mismatch")
    if reservation_digest != snapshot_id:
        raise RuntimeError("validation snapshot is not bound to the reservation")
    return raw


def _validation_snapshot_bytes(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    snapshot_id: str,
    snapshot_path: str,
    snapshot_digest: str,
) -> bytes:
    with _validation_snapshot_root_descriptor(create=False) as root_fd:
        return _validation_snapshot_bytes_from_descriptor(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_id=snapshot_id,
            snapshot_path=snapshot_path,
            snapshot_digest=snapshot_digest,
            root_fd=root_fd,
        )


def _validation_snapshot_metadata(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    snapshot_id: str,
    snapshot_path: str,
    snapshot_digest: str,
) -> dict[str, Any]:
    _validation_snapshot_bytes(
        candidate=candidate,
        reservation_digest=reservation_digest,
        snapshot_id=snapshot_id,
        snapshot_path=snapshot_path,
        snapshot_digest=snapshot_digest,
    )
    return {
        "snapshotId": snapshot_id,
        "snapshotPath": snapshot_path,
        "snapshotDigest": snapshot_digest,
        "resultDigest": str(candidate["resultDigest"]),
    }


def _ensure_validation_snapshot(
    candidate: dict[str, Any], *, reservation_digest: str
) -> dict[str, Any]:
    if not _VALIDATION_SNAPSHOT_ID.fullmatch(reservation_digest):
        raise RuntimeError("validation reservation digest is invalid")
    snapshot_id = reservation_digest
    snapshot_path = f"{_VALIDATION_SNAPSHOT_RELATIVE_PREFIX}/{snapshot_id}.json"
    snapshot_name = f"{snapshot_id}.json"
    with _validation_snapshot_root_descriptor(create=True) as root_fd:
        try:
            os.stat(snapshot_name, dir_fd=root_fd, follow_symlinks=False)
            snapshot_exists = True
        except FileNotFoundError:
            snapshot_exists = False
        if snapshot_exists:
            existing_digest = str(candidate.get("snapshotDigest") or "")
            if not existing_digest:
                existing_digest = hashlib.sha256(
                    _read_validation_snapshot_raw_from_descriptor(
                        snapshot_id=snapshot_id,
                        root_fd=root_fd,
                    )
                ).hexdigest()
            _validation_snapshot_bytes_from_descriptor(
                candidate=candidate,
                reservation_digest=reservation_digest,
                snapshot_id=snapshot_id,
                snapshot_path=snapshot_path,
                snapshot_digest=existing_digest,
                root_fd=root_fd,
            )
            snapshot_digest = existing_digest
        else:
            _value, raw = _read_authenticated_validation_result(candidate)
            snapshot_digest = hashlib.sha256(raw).hexdigest()
            temporary_name = f".validation-input-{os.getpid()}-{time.time_ns()}.tmp"
            descriptor = -1
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=root_fd,
                )
                view = memoryview(raw)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                try:
                    os.link(
                        temporary_name,
                        snapshot_name,
                        src_dir_fd=root_fd,
                        dst_dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    pass
                os.fsync(root_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary_name, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
            _validation_snapshot_bytes_from_descriptor(
                candidate=candidate,
                reservation_digest=reservation_digest,
                snapshot_id=snapshot_id,
                snapshot_path=snapshot_path,
                snapshot_digest=snapshot_digest,
                root_fd=root_fd,
            )
    return {
        "snapshotId": snapshot_id,
        "snapshotPath": snapshot_path,
        "snapshotDigest": snapshot_digest,
        "resultDigest": str(candidate["resultDigest"]),
    }


class _ValidationWorktreeDirectory:
    __slots__ = (
        "worktree",
        "worktree_fd",
        "private_dir",
        "private_fd",
        "handles",
        "bindings",
    )

    def __init__(
        self,
        *,
        worktree: Path,
        worktree_fd: int,
        private_dir: Path,
        private_fd: int,
        handles: list[int],
        bindings: list[_DirectoryBinding],
    ) -> None:
        self.worktree = worktree
        self.worktree_fd = worktree_fd
        self.private_dir = private_dir
        self.private_fd = private_fd
        self.handles = handles
        self.bindings = bindings


def _open_managed_validation_worktree_root() -> tuple[
    Path, int, list[int], list[_DirectoryBinding]
]:
    github_fd, github_path = open_directory_handle(GITHUB_ROOT, label="GitHub root")
    handles = [github_fd]
    bindings = [_DirectoryBinding(github_path, github_fd, "GitHub root")]
    try:
        private_fd, private_path = _open_directory_child(
            parent_fd=github_fd,
            parent_path=github_path,
            name=TASK_PRIVATE_DIR,
            label="Radar private root",
            required_mode=0o700,
        )
        handles.append(private_fd)
        bindings.append(_DirectoryBinding(private_path, private_fd, "Radar private root", 0o700))
        worktrees_fd, worktrees_path = _open_directory_child(
            parent_fd=private_fd,
            parent_path=private_path,
            name="worktrees",
            label="managed worktree root",
        )
        handles.append(worktrees_fd)
        bindings.append(_DirectoryBinding(worktrees_path, worktrees_fd, "managed worktree root"))
        return worktrees_path, worktrees_fd, handles, bindings
    except Exception:
        for fd in reversed(handles):
            os.close(fd)
        raise


def _open_legacy_validation_worktree_root() -> tuple[Path, int, list[int], list[_DirectoryBinding]]:
    root_fd, root_path = open_directory_handle(WORKTREE_ROOT, label="Codex worktree root")
    return (
        root_path,
        root_fd,
        [root_fd],
        [_DirectoryBinding(root_path, root_fd, "Codex worktree root")],
    )


def _validation_worktree_trusted_root_openers(
    _candidate: dict[str, Any],
) -> tuple[Callable[[], tuple[Path, int, list[int], list[_DirectoryBinding]]], ...]:
    return (
        _open_managed_validation_worktree_root,
        _open_legacy_validation_worktree_root,
    )


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _relative_worktree_parts(candidate_path: Path, root_path: Path) -> tuple[str, ...] | None:
    try:
        relative = _lexical_absolute(candidate_path).relative_to(_lexical_absolute(root_path))
    except ValueError:
        return None
    if not relative.parts:
        raise RuntimeError("validation worktree cannot be the trusted root")
    parts = tuple(relative.parts)
    if any(part in {"", ".", ".."} or "/" in part for part in parts):
        raise RuntimeError("validation worktree path is unsafe")
    return parts


def _open_validation_worktree_private_dir(
    candidate: dict[str, Any],
) -> _ValidationWorktreeDirectory:
    raw_worktree = str(candidate.get("worktreePath") or "")
    if not raw_worktree:
        raise RuntimeError("validation worktree is unavailable")
    raw_worktree_path = Path(raw_worktree)
    if not raw_worktree_path.is_absolute():
        raise RuntimeError("validation worktree path must be absolute")
    candidate_path = _lexical_absolute(raw_worktree_path)
    root_errors: list[str] = []
    for opener in _validation_worktree_trusted_root_openers(candidate):
        handles: list[int] = []
        try:
            root_path, root_fd, handles, bindings = opener()
        except (OSError, RuntimeError, ValueError) as exc:
            root_errors.append(str(exc)[:160])
            continue
        try:
            parts = _relative_worktree_parts(candidate_path, root_path)
            if parts is None:
                for fd in reversed(handles):
                    os.close(fd)
                continue
            current_fd = root_fd
            current_path = root_path
            current_bindings = list(bindings)
            worktree_fd = -1
            worktree_path = root_path
            for index, part in enumerate(parts):
                label = (
                    "validation worktree"
                    if index == len(parts) - 1
                    else ("validation worktree parent")
                )
                child_fd, child_path = _open_directory_child(
                    parent_fd=current_fd,
                    parent_path=current_path,
                    name=part,
                    label=label,
                )
                handles.append(child_fd)
                current_bindings.append(_DirectoryBinding(child_path, child_fd, label))
                current_fd = child_fd
                current_path = child_path
                worktree_fd = child_fd
                worktree_path = child_path
            private_fd, private_dir = _open_directory_child(
                parent_fd=worktree_fd,
                parent_path=worktree_path,
                name=TASK_PRIVATE_DIR,
                label="validation worktree private directory",
            )
            handles.append(private_fd)
            current_bindings.append(
                _DirectoryBinding(
                    private_dir,
                    private_fd,
                    "validation worktree private directory",
                )
            )
            return _ValidationWorktreeDirectory(
                worktree=worktree_path,
                worktree_fd=worktree_fd,
                private_dir=private_dir,
                private_fd=private_fd,
                handles=handles,
                bindings=current_bindings,
            )
        except Exception:
            for fd in reversed(handles):
                os.close(fd)
            raise
    detail = f": {'; '.join(root_errors)}" if root_errors else ""
    raise RuntimeError(f"validation worktree is outside trusted roots{detail}")


def _require_validation_worktree_private_binding(
    *,
    bindings: list[_DirectoryBinding],
    worktree: Path,
    worktree_fd: int,
    private_dir: Path,
    private_fd: int,
) -> None:
    _validate_directory_bindings(bindings)
    try:
        private_stat = os.stat(
            TASK_PRIVATE_DIR,
            dir_fd=worktree_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("validation worktree private directory is missing") from exc
    private_descriptor_stat = os.fstat(private_fd)
    if (
        stat.S_ISLNK(private_stat.st_mode)
        or not stat.S_ISDIR(private_stat.st_mode)
        or private_stat.st_uid != os.getuid()
        or not stat.S_ISDIR(private_descriptor_stat.st_mode)
        or private_descriptor_stat.st_uid != os.getuid()
        or (private_stat.st_dev, private_stat.st_ino)
        != (private_descriptor_stat.st_dev, private_descriptor_stat.st_ino)
    ):
        raise RuntimeError("validation worktree private directory is unsafe")


@contextmanager
def _task_worktree_private_descriptor(candidate: dict[str, Any]):
    opened = _open_validation_worktree_private_dir(candidate)
    try:
        _require_validation_worktree_private_binding(
            bindings=opened.bindings,
            worktree=opened.worktree,
            worktree_fd=opened.worktree_fd,
            private_dir=opened.private_dir,
            private_fd=opened.private_fd,
        )
        try:
            yield opened
        except BaseException:
            raise
        else:
            _require_validation_worktree_private_binding(
                bindings=opened.bindings,
                worktree=opened.worktree,
                worktree_fd=opened.worktree_fd,
                private_dir=opened.private_dir,
                private_fd=opened.private_fd,
            )
    finally:
        for fd in reversed(opened.handles):
            os.close(fd)


@contextmanager
def _validation_worktree_private_descriptor(candidate: dict[str, Any]):
    with _task_worktree_private_descriptor(candidate) as opened:
        yield opened.private_fd


def _read_task_private_regular_file(
    opened: _ValidationWorktreeDirectory,
    name: str,
    *,
    label: str,
    missing_error: type[RuntimeError] = RuntimeError,
    reject_dangerous_writes: bool = False,
) -> bytes:
    return _read_owned_regular_file(
        Path(name),
        label=label,
        directory_fd=opened.private_fd,
        missing_error=missing_error,
        reject_dangerous_writes=reject_dangerous_writes,
    )


def _read_task_result_bytes_from_private(
    opened: _ValidationWorktreeDirectory,
) -> bytes:
    return _read_task_private_regular_file(
        opened,
        "result.json",
        label="task result",
        missing_error=MissingValidationResult,
        reject_dangerous_writes=True,
    )


def _read_task_context_bytes_from_private(
    opened: _ValidationWorktreeDirectory,
) -> bytes:
    return _read_task_private_regular_file(
        opened,
        "task-context.json",
        label="task context",
    )


def _write_task_result_json_to_private(
    opened: _ValidationWorktreeDirectory,
    value: dict[str, Any],
) -> bytes:
    _require_validation_worktree_private_binding(
        bindings=opened.bindings,
        worktree=opened.worktree,
        worktree_fd=opened.worktree_fd,
        private_dir=opened.private_dir,
        private_fd=opened.private_fd,
    )
    _atomic_private_json(Path("result.json"), value, directory_fd=opened.private_fd)
    _require_validation_worktree_private_binding(
        bindings=opened.bindings,
        worktree=opened.worktree,
        worktree_fd=opened.worktree_fd,
        private_dir=opened.private_dir,
        private_fd=opened.private_fd,
    )
    return _read_task_result_bytes_from_private(opened)


def _read_task_result_bytes_if_present(
    candidate: dict[str, Any],
) -> tuple[Path, bytes] | None:
    with _task_worktree_private_descriptor(candidate) as opened:
        try:
            raw = _read_task_result_bytes_from_private(opened)
        except MissingValidationResult:
            return None
        return opened.private_dir / "result.json", raw


def _require_validation_worktree_input_root_binding(
    *,
    bindings: list[_DirectoryBinding],
    worktree: Path,
    worktree_fd: int,
    private_dir: Path,
    private_fd: int,
    root_fd: int,
) -> None:
    _require_validation_worktree_private_binding(
        bindings=bindings,
        worktree=worktree,
        worktree_fd=worktree_fd,
        private_dir=private_dir,
        private_fd=private_fd,
    )

    directory_name = "validation-inputs"
    try:
        root_stat = os.stat(directory_name, dir_fd=private_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise RuntimeError("validation worktree input directory is missing") from exc
    root_descriptor_stat = os.fstat(root_fd)
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
        or not stat.S_ISDIR(root_descriptor_stat.st_mode)
        or root_descriptor_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_descriptor_stat.st_mode) != 0o700
        or (root_stat.st_dev, root_stat.st_ino)
        != (root_descriptor_stat.st_dev, root_descriptor_stat.st_ino)
    ):
        raise RuntimeError("validation worktree input directory is unsafe")


@contextmanager
def _validation_worktree_input_root_descriptor(candidate: dict[str, Any], *, create: bool):
    opened = _open_validation_worktree_private_dir(candidate)
    root_fd = -1
    directory_name = "validation-inputs"
    try:
        if create:
            try:
                os.mkdir(directory_name, 0o700, dir_fd=opened.private_fd)
            except FileExistsError:
                pass
        try:
            root_fd = os.open(
                directory_name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=opened.private_fd,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("validation worktree input directory is missing") from exc
        except OSError as exc:
            raise RuntimeError(
                "validation worktree input directory could not be opened safely"
            ) from exc
        root_binding = _DirectoryBinding(
            opened.private_dir / directory_name,
            root_fd,
            "validation worktree input directory",
            0o700,
        )
        bindings = [*opened.bindings, root_binding]
        _require_validation_worktree_input_root_binding(
            bindings=bindings,
            worktree=opened.worktree,
            worktree_fd=opened.worktree_fd,
            private_dir=opened.private_dir,
            private_fd=opened.private_fd,
            root_fd=root_fd,
        )
        try:
            yield root_fd
        except BaseException:
            raise
        else:
            _require_validation_worktree_input_root_binding(
                bindings=bindings,
                worktree=opened.worktree,
                worktree_fd=opened.worktree_fd,
                private_dir=opened.private_dir,
                private_fd=opened.private_fd,
                root_fd=root_fd,
            )
    finally:
        if root_fd >= 0:
            os.close(root_fd)
        for fd in reversed(opened.handles):
            os.close(fd)


def _validation_worktree_input_binding(
    *, candidate: dict[str, Any], reservation_digest: str, snapshot_digest: str
) -> dict[str, str]:
    if not _VALIDATION_SNAPSHOT_ID.fullmatch(reservation_digest):
        raise RuntimeError("validation reservation digest is invalid")
    if not snapshot_digest:
        raise RuntimeError("validation snapshot digest is missing")
    return {
        "worktreeInputPath": (
            f"{_VALIDATION_WORKTREE_INPUT_RELATIVE_PREFIX}/{reservation_digest}.json"
        ),
        "worktreeInputDigest": snapshot_digest,
    }


def _validation_worktree_input_bytes_from_descriptor(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    worktree_input_digest: str,
    root_fd: int,
) -> bytes:
    raw = _read_owned_regular_file(
        Path(f"{reservation_digest}.json"),
        label="validation worktree input",
        required_mode=0o400,
        directory_fd=root_fd,
    )
    if hashlib.sha256(raw).hexdigest() != worktree_input_digest:
        raise RuntimeError("validation worktree input digest mismatch")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("validation worktree input JSON is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("validation worktree input JSON is not an object")
    try:
        result_digest = _task_result_digest(value, raw)
    except RuntimeError as exc:
        raise RuntimeError("validation worktree input result digest is invalid") from exc
    if result_digest != candidate["resultDigest"]:
        raise RuntimeError("validation worktree input result digest mismatch")
    return raw


def _validation_worktree_input_bytes(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    worktree_input_path: str,
    worktree_input_digest: str,
) -> bytes:
    if not _VALIDATION_SNAPSHOT_ID.fullmatch(reservation_digest):
        raise RuntimeError("validation reservation digest is invalid")
    expected_path = f"{_VALIDATION_WORKTREE_INPUT_RELATIVE_PREFIX}/{reservation_digest}.json"
    if worktree_input_path != expected_path:
        raise RuntimeError("validation worktree input path is invalid")
    with _validation_worktree_input_root_descriptor(candidate, create=False) as root_fd:
        return _validation_worktree_input_bytes_from_descriptor(
            candidate=candidate,
            reservation_digest=reservation_digest,
            worktree_input_digest=worktree_input_digest,
            root_fd=root_fd,
        )


def _validation_worktree_input_metadata(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    worktree_input_path: str,
    worktree_input_digest: str,
) -> dict[str, str]:
    _validation_worktree_input_bytes(
        candidate=candidate,
        reservation_digest=reservation_digest,
        worktree_input_path=worktree_input_path,
        worktree_input_digest=worktree_input_digest,
    )
    return {
        "worktreeInputPath": worktree_input_path,
        "worktreeInputDigest": worktree_input_digest,
        "resultDigest": str(candidate["resultDigest"]),
    }


def _ensure_validation_worktree_input(
    *,
    candidate: dict[str, Any],
    reservation_digest: str,
    snapshot_id: str,
    snapshot_path: str,
    snapshot_digest: str,
    worktree_input_path: str,
    worktree_input_digest: str,
) -> dict[str, str]:
    raw = _validation_snapshot_bytes(
        candidate=candidate,
        reservation_digest=reservation_digest,
        snapshot_id=snapshot_id,
        snapshot_path=snapshot_path,
        snapshot_digest=snapshot_digest,
    )
    if hashlib.sha256(raw).hexdigest() != worktree_input_digest:
        raise RuntimeError("validation worktree input binding digest mismatch")
    expected = _validation_worktree_input_binding(
        candidate=candidate,
        reservation_digest=reservation_digest,
        snapshot_digest=snapshot_digest,
    )
    if (
        worktree_input_path != expected["worktreeInputPath"]
        or worktree_input_digest != expected["worktreeInputDigest"]
    ):
        raise RuntimeError("validation worktree input binding is invalid")
    destination_name = f"{reservation_digest}.json"
    with _validation_worktree_input_root_descriptor(candidate, create=True) as root_fd:
        try:
            os.stat(destination_name, dir_fd=root_fd, follow_symlinks=False)
            destination_exists = True
        except FileNotFoundError:
            destination_exists = False
        if not destination_exists:
            temporary_name = f".validation-input-{os.getpid()}-{time.time_ns()}.tmp"
            descriptor = -1
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=root_fd,
                )
                view = memoryview(raw)
                while view:
                    view = view[os.write(descriptor, view) :]
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                try:
                    os.link(
                        temporary_name,
                        destination_name,
                        src_dir_fd=root_fd,
                        dst_dir_fd=root_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    pass
                os.fsync(root_fd)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temporary_name, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
        _validation_worktree_input_bytes_from_descriptor(
            candidate=candidate,
            reservation_digest=reservation_digest,
            worktree_input_digest=worktree_input_digest,
            root_fd=root_fd,
        )
    return {
        "worktreeInputPath": worktree_input_path,
        "worktreeInputDigest": worktree_input_digest,
        "resultDigest": str(candidate["resultDigest"]),
    }


def _local_changed_files(worktree: Path) -> list[str]:
    values: set[str] = set()
    for args in (
        ["git", "diff", "--name-only"],
        ["git", "diff", "--cached", "--name-only"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ):
        values.update(line for line in command(args, cwd=worktree).splitlines() if line)
    return sorted(values)


def _validated_changed_files(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("controller commit requires a non-empty changedFiles list")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise RuntimeError("changedFiles entries must be strings")
        path = Path(item)
        if (
            not item.strip()
            or item != path.as_posix()
            or path.is_absolute()
            or ".." in path.parts
            or path.parts[0] == TASK_PRIVATE_DIR
            or "\n" in item
        ):
            raise RuntimeError("changedFiles contains an unsafe path")
        normalized.append(item)
    if len(set(normalized)) != len(normalized):
        raise RuntimeError("changedFiles contains duplicate paths")
    return sorted(normalized)


def _optional_command(args: list[str], *, cwd: Path) -> str | None:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def _switch_controller_branch(worktree: Path, branch: str) -> None:
    current = _optional_command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree)
    if current == branch:
        return
    head = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    existing = _optional_command(
        ["git", "rev-parse", "--verify", f"refs/heads/{branch}"], cwd=worktree
    )
    if existing is None:
        command(["git", "switch", "-c", branch], cwd=worktree)
        return
    if existing != head:
        raise RuntimeError("controller branch already exists at another commit")
    command(["git", "switch", branch], cwd=worktree)


def _commit_args(
    *, context: dict[str, Any], value: dict[str, Any], commit_message: str
) -> list[str]:
    args = ["git", "commit", "-m", commit_message]
    policy = _policy_from_context(context)
    if policy.get("dco") is True or value.get("dcoRequired") is True:
        return ["git", "commit", "--signoff", "-m", commit_message]
    return args


def _require_git_identity(worktree: Path, context: dict[str, Any], value: dict[str, Any]) -> None:
    policy = _policy_from_context(context)
    if policy.get("dco") is not True and value.get("dcoRequired") is not True:
        return
    name = command(["git", "config", "user.name"], cwd=worktree)
    email = command(["git", "config", "user.email"], cwd=worktree)
    if not name or not email:
        raise RuntimeError("DCO sign-off requires configured Git identity")


def _merge_parents(worktree: Path, revision: str = "HEAD") -> list[str]:
    values = command(["git", "rev-list", "--parents", "-n", "1", revision], cwd=worktree).split()
    if not values:
        raise RuntimeError("controller merge commit is unavailable")
    return values[1:]


def _restore_tree_paths(worktree: Path, tree: str, paths: list[str]) -> None:
    for path in paths:
        present = _optional_command(["git", "cat-file", "-e", f"{tree}:{path}"], cwd=worktree)
        if present is not None:
            command(["git", "checkout", tree, "--", path], cwd=worktree)
        else:
            command(["git", "rm", "-f", "--ignore-unmatch", "--", path], cwd=worktree)


def _finalize_controller_merge(
    *,
    candidate: dict[str, Any],
    context: dict[str, Any],
    value: dict[str, Any],
    result_access: _ValidationWorktreeDirectory,
) -> tuple[dict[str, Any], bytes]:
    worktree = result_access.worktree
    changed_files = _validated_changed_files(value.get("changedFiles"))
    branch = str(value.get("branch") or "").strip()
    commit_message = str(value.get("commitMessage") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{2,119}", branch):
        raise RuntimeError("controller merge requires a safe branch name")
    if not public_branch_is_safe(branch):
        raise RuntimeError("controller branch name exposes an AI tool")
    if not commit_message or "\n" in commit_message or len(commit_message) > 120:
        raise RuntimeError("controller merge requires one concise commitMessage")
    if not public_text_is_safe(commit_message, ""):
        raise RuntimeError("controller merge message contains an AI-assistance disclosure")

    followup = context.get("prFollowup")
    evidence = followup.get("evidence") if isinstance(followup, dict) else None
    expected_head = str(followup.get("headSha") or "") if isinstance(followup, dict) else ""
    expected_base = str(evidence.get("baseSha") or "") if isinstance(evidence, dict) else ""
    if (
        not isinstance(evidence, dict)
        or evidence.get("mergeConflict") is not True
        or not re.fullmatch(r"[0-9a-f]{40}", expected_head)
        or not re.fullmatch(r"[0-9a-f]{40}", expected_base)
    ):
        raise RuntimeError("controller merge requires a signed PR conflict snapshot")
    if value.get("mergeBaseSha") != expected_base:
        raise RuntimeError("controller merge base does not match the signed snapshot")

    actual = _local_changed_files(worktree)
    current_head = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    current_branch = _optional_command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree)
    if current_branch != branch:
        if actual:
            raise RuntimeError("controller merge branch drifted with local changes")
        _switch_controller_branch(worktree, branch)
        current_head = command(["git", "rev-parse", "HEAD"], cwd=worktree)

    # Recover idempotently if the merge commit was written before result.json.
    if current_head != expected_head:
        if actual or _merge_parents(worktree) != [expected_head, expected_base]:
            raise RuntimeError("controller merge head does not match the signed PR snapshot")
        if command(["git", "show", "-s", "--format=%s", "HEAD"], cwd=worktree) != commit_message:
            raise RuntimeError("controller merge recovery commit message mismatch")
    else:
        if actual:
            if actual != changed_files:
                raise RuntimeError(
                    "controller merge changedFiles mismatch: "
                    f"expected={changed_files!r} actual={actual!r}"
                )
            command(["git", "add", "--", *changed_files], cwd=worktree)
            resolution_tree = command(["git", "write-tree"], cwd=worktree)
            command(["git", "reset", "--hard", expected_head], cwd=worktree)
        else:
            resolution_source = str(value.get("resolutionSourceCommit") or "")
            if resolution_source != expected_head:
                raise RuntimeError(
                    "clean controller merge handoff requires resolutionSourceCommit at PR head"
                )
            resolution_tree = expected_head

        completed = subprocess.run(
            ["git", "merge", "--no-commit", "--no-ff", expected_base],
            cwd=worktree,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        unmerged = sorted(
            line
            for line in command(
                ["git", "diff", "--name-only", "--diff-filter=U"], cwd=worktree
            ).splitlines()
            if line
        )
        if completed.returncode not in {0, 1} or unmerged != changed_files:
            _optional_command(["git", "merge", "--abort"], cwd=worktree)
            raise RuntimeError(
                "controller merge conflict set mismatch: "
                f"expected={changed_files!r} actual={unmerged!r}"
            )
        _restore_tree_paths(worktree, resolution_tree, changed_files)
        remaining = command(["git", "diff", "--name-only", "--diff-filter=U"], cwd=worktree)
        if remaining:
            _optional_command(["git", "merge", "--abort"], cwd=worktree)
            raise RuntimeError("controller merge left unresolved files")
        _require_git_identity(worktree, context, value)
        command(
            _commit_args(context=context, value=value, commit_message=commit_message), cwd=worktree
        )

    if _merge_parents(worktree) != [expected_head, expected_base]:
        raise RuntimeError("controller merge commit parent binding failed")
    if command(["git", "status", "--porcelain"], cwd=worktree):
        raise RuntimeError("controller merge did not leave a clean worktree")

    finalized = dict(value)
    finalized["commitSha"] = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    finalized["branch"] = command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree)
    finalized["controllerCommitChangedFiles"] = changed_files
    finalized["changedFiles"] = changed_files
    finalized["mergeResolutionFiles"] = changed_files
    finalized["previousCommitSha"] = expected_head
    finalized["mergeBaseSha"] = expected_base
    finalized["handoffMode"] = "controller_merge_complete"
    base_branch = _prepared_base_branch(worktree, context)
    publication = finalized.get("publication")
    if base_branch and isinstance(publication, dict):
        finalized_publication = dict(publication)
        finalized_publication["baseBranch"] = base_branch
        finalized["publication"] = finalized_publication
    if context.get("targetBase") is not None:
        finalized["targetBase"] = validate_target_base(context["targetBase"])
    raw = _write_task_result_json_to_private(result_access, finalized)
    return finalized, raw


def _policy_from_context(context: dict[str, Any]) -> dict[str, Any]:
    live_audit = context.get("liveAudit")
    evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else None
    policy = evidence.get("policy") if isinstance(evidence, dict) else None
    return policy if isinstance(policy, dict) else {}


def _controller_policy_verification(context: dict[str, Any]) -> dict[str, str] | None:
    """Return controller-owned proof that repository policy discovery completed."""
    live_audit = context.get("liveAudit")
    evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else None
    completeness = evidence.get("completeness") if isinstance(evidence, dict) else None
    policy = evidence.get("policy") if isinstance(evidence, dict) else None
    if not isinstance(completeness, dict) or not isinstance(policy, dict):
        return None
    status = str(policy.get("status") or "")
    digest = str(policy.get("digest") or "")
    if (
        completeness.get("repositoryPolicy") != "COMPLETE"
        or status == "UNKNOWN"
        or not status
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        return None
    return {
        "source": "controller_live_audit",
        "capturedAt": str(live_audit.get("capturedAt") or ""),
        "policyDigest": digest,
        "policyStatus": status,
    }


def _prepared_default_branch(worktree: Path) -> str | None:
    """Read the controller-prepared default branch without network access."""

    default_ref = _optional_command(
        ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=worktree,
    )
    prefix = "refs/remotes/origin/"
    if not default_ref or not default_ref.startswith(prefix):
        return None
    branch = default_ref.removeprefix(prefix).strip()
    if not branch or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}", branch):
        raise RuntimeError("prepared default branch is invalid")
    return branch


def _prepared_base_branch(worktree: Path, context: dict[str, Any]) -> str | None:
    """Return the audit-bound target branch, falling back for legacy tasks."""

    if context.get("targetBase") is None:
        return _prepared_default_branch(worktree)
    target = validate_target_base(context["targetBase"])
    command(["git", "cat-file", "-e", f"{target['sha']}^{{commit}}"], cwd=worktree)
    command(
        ["git", "merge-base", "--is-ancestor", target["sha"], "HEAD"],
        cwd=worktree,
    )
    return target["branch"]


def _validation_publication_changed_files(
    *, worktree: Path, context: dict[str, Any], commit_changed_files: list[str]
) -> list[str]:
    followup = context.get("prFollowup")
    if isinstance(followup, dict):
        previous_head = str(followup.get("headSha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", previous_head):
            raise RuntimeError("PR follow-up lacks the signed previous head")
        cumulative = _validated_changed_files(
            [
                line
                for line in command(
                    ["git", "diff", "--name-only", f"{previous_head}..HEAD"], cwd=worktree
                ).splitlines()
                if line
            ]
        )
        # A corrective commit may restore an earlier pending file to its published
        # contents. That file belongs to the commit audit trail but intentionally
        # disappears from the final PR diff.
        if not cumulative:
            raise RuntimeError("PR follow-up leaves no cumulative publication diff")
        return cumulative
    if context.get("stage") != "VALIDATION_PENDING":
        return commit_changed_files
    base_branch = _prepared_base_branch(worktree, context)
    if not base_branch:
        raise RuntimeError("validation continuation lacks a prepared base branch")
    tracking_ref = f"refs/remotes/origin/{base_branch}"
    base = command(["git", "merge-base", "HEAD", tracking_ref], cwd=worktree)
    cumulative = _validated_changed_files(
        [
            line
            for line in command(
                ["git", "diff", "--name-only", f"{base}..HEAD"], cwd=worktree
            ).splitlines()
            if line
        ]
    )
    if not cumulative:
        raise RuntimeError("validation continuation leaves no cumulative publication diff")
    return cumulative


def _prospective_validation_changed_files(*, worktree: Path, context: dict[str, Any]) -> list[str]:
    """Return the cumulative PR diff including the current uncommitted correction."""

    followup = context.get("prFollowup")
    if isinstance(followup, dict):
        base = str(followup.get("headSha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", base):
            raise RuntimeError("PR follow-up lacks the signed previous head")
    else:
        if context.get("stage") != "VALIDATION_PENDING":
            raise RuntimeError("prospective validation diff requires a validation continuation")
        base_branch = _prepared_base_branch(worktree, context)
        if not base_branch:
            raise RuntimeError("validation continuation lacks a prepared base branch")
        base = command(
            ["git", "merge-base", "HEAD", f"refs/remotes/origin/{base_branch}"],
            cwd=worktree,
        )
    tracked = {
        line
        for line in command(["git", "diff", "--name-only", base, "--"], cwd=worktree).splitlines()
        if line
    }
    untracked = {
        line
        for line in command(
            ["git", "ls-files", "--others", "--exclude-standard"], cwd=worktree
        ).splitlines()
        if line
    }
    return _validated_changed_files(sorted(tracked | untracked))


def _stable_patch_id(worktree: Path, commit_sha: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise RuntimeError("controller commit receipt is invalid")
    shown = subprocess.run(
        ["git", "show", "--pretty=format:", "--binary", commit_sha],
        cwd=worktree,
        check=True,
        capture_output=True,
        timeout=30,
    )
    identified = subprocess.run(
        ["git", "patch-id", "--stable"],
        cwd=worktree,
        input=shown.stdout,
        check=True,
        capture_output=True,
        timeout=30,
    )
    parts = identified.stdout.decode("utf-8", errors="strict").split()
    if not parts or not re.fullmatch(r"[0-9a-f]{40}", parts[0]):
        raise RuntimeError("controller commit has no stable patch identity")
    return parts[0]


def _finalize_controller_commit(
    *,
    candidate: dict[str, Any],
    context: dict[str, Any],
    value: dict[str, Any],
    result_access: _ValidationWorktreeDirectory,
    write_if_unchanged: bool = True,
) -> tuple[dict[str, Any], bytes]:
    if value.get("handoffMode") == "controller_merge_required":
        return _finalize_controller_merge(
            candidate=candidate,
            context=context,
            value=value,
            result_access=result_access,
        )
    if value.get("handoffMode") == "controller_commit_complete":
        worktree = result_access.worktree
        declared_commit_files = _validated_changed_files(
            value.get("controllerCommitChangedFiles") or value.get("changedFiles")
        )
        commit_sha = str(value.get("commitSha") or "")
        head_sha = command(["git", "rev-parse", "HEAD"], cwd=worktree)
        actual_commit_files = _validated_changed_files(
            [
                line
                for line in command(
                    ["git", "show", "--pretty=format:", "--name-only", "HEAD"],
                    cwd=worktree,
                ).splitlines()
                if line
            ]
        )
        if commit_sha != head_sha:
            receipt_commit_files = _validated_changed_files(
                [
                    line
                    for line in command(
                        ["git", "show", "--pretty=format:", "--name-only", commit_sha],
                        cwd=worktree,
                    ).splitlines()
                    if line
                ]
            )
            if receipt_commit_files != actual_commit_files or _stable_patch_id(
                worktree, commit_sha
            ) != _stable_patch_id(worktree, head_sha):
                raise RuntimeError("controller commit receipt does not match HEAD")
        is_validation_continuation = context.get("stage") == "VALIDATION_PENDING" or isinstance(
            context.get("prFollowup"), dict
        )
        if is_validation_continuation:
            publication_changed_files = _validation_publication_changed_files(
                worktree=worktree,
                context=context,
                commit_changed_files=actual_commit_files,
            )
            declared_publication_files = _validated_changed_files(value.get("changedFiles"))
            allowed_snapshots = {tuple(actual_commit_files), tuple(publication_changed_files)}
            if (
                tuple(declared_commit_files) not in allowed_snapshots
                or tuple(declared_publication_files) not in allowed_snapshots
            ):
                raise RuntimeError("controller commit receipt does not match validation files")
            commit_changed_files = actual_commit_files
        else:
            if actual_commit_files != declared_commit_files:
                raise RuntimeError("controller commit receipt does not match committed files")
            commit_changed_files = declared_commit_files
            publication_changed_files = _validated_changed_files(value.get("changedFiles"))
            if not set(commit_changed_files).issubset(publication_changed_files):
                raise RuntimeError("controller commit files are missing from publication evidence")
        finalized = dict(value)
        finalized["commitSha"] = head_sha
        finalized["branch"] = command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree)
        finalized["controllerCommitChangedFiles"] = commit_changed_files
        finalized["changedFiles"] = publication_changed_files
        followup = context.get("prFollowup")
        if isinstance(followup, dict):
            previous_commit = str(followup.get("preparedHeadSha") or followup.get("headSha") or "")
            if not re.fullmatch(r"[0-9a-f]{40}", previous_commit):
                raise RuntimeError("controller commit lacks a valid review parent")
            finalized["previousCommitSha"] = previous_commit
        else:
            finalized.pop("previousCommitSha", None)
        base_branch = _prepared_base_branch(worktree, context)
        publication = finalized.get("publication")
        if base_branch and isinstance(publication, dict):
            finalized["publication"] = dict(publication) | {"baseBranch": base_branch}
        if context.get("targetBase") is not None:
            finalized["targetBase"] = validate_target_base(context["targetBase"])
        if write_if_unchanged or finalized != value:
            raw = _write_task_result_json_to_private(result_access, finalized)
        else:
            raw = _read_task_result_bytes_from_private(result_access)
        return finalized, raw
    if value.get("handoffMode") != "controller_commit_required":
        return value, _read_task_result_bytes_from_private(result_access)

    worktree = result_access.worktree
    changed_files = _validated_changed_files(value.get("changedFiles"))
    branch = str(value.get("branch") or "").strip()
    commit_message = str(value.get("commitMessage") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{2,119}", branch):
        raise RuntimeError("controller commit requires a safe branch name")
    if not public_branch_is_safe(branch):
        raise RuntimeError("controller branch name exposes an AI tool")
    if not commit_message or "\n" in commit_message or len(commit_message) > 120:
        raise RuntimeError("controller commit requires one concise commitMessage")
    if not public_text_is_safe(commit_message, ""):
        raise RuntimeError("controller commit message contains an AI-assistance disclosure")

    actual = _local_changed_files(worktree)
    followup = context.get("prFollowup")
    is_validation_continuation = context.get("stage") == "VALIDATION_PENDING" or isinstance(
        followup, dict
    )
    expected_parent = ""
    if isinstance(followup, dict):
        expected_parent = str(followup.get("preparedHeadSha") or followup.get("headSha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", expected_parent):
            raise RuntimeError("controller commit lacks a valid PR follow-up parent")
    if actual:
        commit_changed_files = changed_files
        if actual != changed_files:
            if not is_validation_continuation:
                raise RuntimeError(
                    "controller commit changedFiles mismatch: "
                    f"expected={changed_files!r} actual={actual!r}"
                )
            prospective = _prospective_validation_changed_files(worktree=worktree, context=context)
            if prospective != changed_files:
                raise RuntimeError(
                    "controller commit cumulative changedFiles mismatch: "
                    f"expected={changed_files!r} actual={prospective!r}"
                )
            commit_changed_files = actual
        _switch_controller_branch(worktree, branch)
        if (
            expected_parent
            and command(["git", "rev-parse", "HEAD"], cwd=worktree) != expected_parent
        ):
            raise RuntimeError("controller commit parent drifted from the prepared PR follow-up")
        command(["git", "add", "--", *commit_changed_files], cwd=worktree)
        _require_git_identity(worktree, context, value)
        command(
            _commit_args(context=context, value=value, commit_message=commit_message), cwd=worktree
        )
    else:
        commit_changed_files = changed_files
        # Recover idempotently if the process stopped after the commit but before
        # rewriting result.json.
        _switch_controller_branch(worktree, branch)
        if expected_parent and _merge_parents(worktree) != [expected_parent]:
            raise RuntimeError("controller commit recovery parent does not match the PR follow-up")
        committed = sorted(
            line
            for line in command(
                ["git", "show", "--pretty=format:", "--name-only", "HEAD"], cwd=worktree
            ).splitlines()
            if line
        )
        if committed != changed_files:
            if context.get("stage") == "VALIDATION_PENDING" or isinstance(followup, dict):
                cumulative = _validation_publication_changed_files(
                    worktree=worktree,
                    context=context,
                    commit_changed_files=committed,
                )
                if cumulative != changed_files:
                    raise RuntimeError("controller commit handoff has no matching local changes")
                commit_changed_files = committed
            else:
                raise RuntimeError("controller commit handoff has no matching local changes")

    status = command(["git", "status", "--porcelain"], cwd=worktree)
    if status:
        raise RuntimeError("controller commit did not leave a clean worktree")
    committed = sorted(
        line
        for line in command(
            ["git", "show", "--pretty=format:", "--name-only", "HEAD"], cwd=worktree
        ).splitlines()
        if line
    )
    if committed != commit_changed_files:
        raise RuntimeError("controller commit does not match changedFiles")

    finalized = dict(value)
    finalized["commitSha"] = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    finalized["branch"] = command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree)
    finalized["controllerCommitChangedFiles"] = commit_changed_files
    publication_changed_files = _validation_publication_changed_files(
        worktree=worktree,
        context=context,
        commit_changed_files=commit_changed_files,
    )
    if is_validation_continuation and tuple(changed_files) not in {
        tuple(commit_changed_files),
        tuple(publication_changed_files),
    }:
        raise RuntimeError("controller commit receipt does not match validation files")
    finalized["changedFiles"] = publication_changed_files
    if expected_parent:
        finalized["previousCommitSha"] = expected_parent
    else:
        finalized.pop("previousCommitSha", None)
    finalized["handoffMode"] = "controller_commit_complete"
    base_branch = _prepared_base_branch(worktree, context)
    publication = finalized.get("publication")
    if base_branch and isinstance(publication, dict):
        finalized_publication = dict(publication)
        finalized_publication["baseBranch"] = base_branch
        finalized["publication"] = finalized_publication
    if context.get("targetBase") is not None:
        finalized["targetBase"] = validate_target_base(context["targetBase"])
    raw = _write_task_result_json_to_private(result_access, finalized)
    return finalized, raw


def _publication_block_reason(context: dict[str, Any], value: dict[str, Any]) -> str | None:
    explicit = str(value.get("publicationBlockedReason") or "").strip()
    if explicit in {"AI_DISCLOSURE_REQUIRED", "AI_USE_PROHIBITED"}:
        return explicit
    policy = _policy_from_context(context)
    if policy.get("ai_prohibited") is True:
        return "AI_USE_PROHIBITED"
    if policy.get("ai_disclosure") is True:
        return "AI_DISCLOSURE_REQUIRED"
    return None


def _recover_unbound_pr_followup_preparations(
    store: RadarLedger,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    recovered: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for candidate in store.unbound_pr_followup_preparations():
        try:
            worktree = Path(candidate["worktreePath"]).resolve()
            if not re.fullmatch(r"[0-9a-f]{40}", str(candidate.get("headSha") or "")):
                raise RuntimeError("legacy PR follow-up lacks an immutable published head")
            legacy_context_digest = None
            legacy_wake_digest = None
            context_path = worktree / TASK_PRIVATE_DIR / "task-context.json"
            if context_path.is_file():
                legacy_context = json.loads(context_path.read_text(encoding="utf-8"))
                expected_context = {
                    "key": candidate["key"],
                    "issueUrl": candidate["issueUrl"],
                    "threadId": candidate["threadId"],
                    "worktreePath": str(worktree),
                }
                if not isinstance(legacy_context, dict) or any(
                    legacy_context.get(key) != expected
                    for key, expected in expected_context.items()
                ):
                    raise RuntimeError("legacy PR follow-up context identity is invalid")
                legacy_followup = legacy_context.get("prFollowup")
                legacy_prepared_head = (
                    str(legacy_followup.get("preparedHeadSha"))
                    if isinstance(legacy_followup, dict) and legacy_followup.get("preparedHeadSha")
                    else None
                )
                if (
                    not isinstance(legacy_followup, dict)
                    or legacy_followup.get("prUrl") != candidate["prUrl"]
                    or legacy_context.get("contextDigest")
                    not in _task_context_digest_candidates(legacy_context, legacy_prepared_head)
                ):
                    raise RuntimeError("legacy PR follow-up context digest is invalid")
                legacy_context_digest = str(legacy_context["contextDigest"])
                legacy_wake_digest = str(legacy_followup.get("wakeDigest") or "")
            prepared_head = command(["git", "rev-parse", "HEAD"], cwd=worktree)
            prepared_base = None
            if prepared_head != candidate["headSha"]:
                parents = _merge_parents(worktree)
                subject = command(["git", "show", "-s", "--format=%s", "HEAD"], cwd=worktree)
                if (
                    candidate.get("evidence", {}).get("baseIntegrationRequired") is not True
                    or len(parents) != 2
                    or parents[0] != candidate["headSha"]
                    or subject != "merge: refresh upstream branch for CI validation"
                ):
                    raise RuntimeError("legacy PR follow-up preparation cannot be verified")
                prepared_base = parents[1]
            store.bind_pr_followup_preparation(
                thread_id=candidate["threadId"],
                wake_digest=candidate["wakeDigest"],
                prepared_head_sha=prepared_head,
                prepared_base_sha=prepared_base,
                legacy_context_digest=legacy_context_digest,
                legacy_wake_digest=legacy_wake_digest,
            )
            recovered.append(
                {
                    "key": candidate["key"],
                    "threadId": candidate["threadId"],
                    "preparedHeadSha": prepared_head,
                }
            )
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    return recovered, errors


def sync_task_contexts(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    written: list[dict[str, str]] = []
    refreshed: list[dict[str, str]] = []
    no_go: list[dict[str, str]] = []
    unavailable: list[dict[str, str]] = []
    revalidation_errors: list[dict[str, str]] = []
    superseded = store.reconcile_superseded_pr_followups()
    prepared_recovered, errors = _recover_unbound_pr_followup_preparations(store)
    preparation_error_keys = {item["key"] for item in errors}
    for candidate in store.task_context_candidates():
        if candidate["key"] in preparation_error_keys:
            continue
        try:
            worktree = Path(candidate["worktreePath"]).resolve()
            if not worktree.is_dir():
                if candidate.get("stage") not in PUBLISHED_TASK_STAGES:
                    try:
                        evidence, verdict = _audit_intent(candidate["intent"])
                    except (OSError, RuntimeError, ValueError) as exc:
                        revalidation_errors.append(
                            {
                                "key": candidate["key"],
                                "error": f"{type(exc).__name__}:{str(exc)[:240]}",
                            }
                        )
                    else:
                        if verdict.status == "BLOCK":
                            store.record_stage(
                                candidate["key"],
                                "AUDIT_NO_GO",
                                evidence={
                                    "authorization": verdict.as_dict(),
                                    "evidence": evidence.as_dict(),
                                    "missingWorktreeRevalidation": True,
                                },
                                reason=verdict.reason_code,
                                dedupe_key=(
                                    f"{candidate['intentId']}:{evidence.digest}:"
                                    "missing-worktree-no-go"
                                ),
                            )
                            no_go.append(
                                {
                                    "key": candidate["key"],
                                    "reason": verdict.reason_code,
                                    "source": "missing_worktree_revalidation",
                                }
                            )
                            continue
                unavailable.append(
                    {
                        "key": candidate["key"],
                        "threadId": candidate["threadId"],
                        "worktreePath": str(worktree),
                        "reason": "TASK_WORKTREE_UNAVAILABLE",
                    }
                )
                continue
            current = store.task_context(
                issue_url=candidate["issueUrl"],
                thread_id=candidate["threadId"],
                worktree_path=candidate["worktreePath"],
            )
            if current is None:
                raise RuntimeError("registered task context is unavailable")
            current_audit = current.get("liveAudit")
            if not isinstance(current_audit, dict) or not isinstance(
                current_audit.get("evidence"), dict
            ):
                evidence, verdict = _audit_intent(candidate["intent"])
                if verdict.status != "ALLOW":
                    store.record_stage(
                        candidate["key"],
                        "AUDIT_NO_GO",
                        evidence={
                            "authorization": verdict.as_dict(),
                            "evidence": evidence.as_dict(),
                        },
                        reason=verdict.reason_code,
                        dedupe_key=(
                            f"{candidate['intentId']}:{evidence.digest}:context-refresh-no-go"
                        ),
                    )
                    no_go.append({"key": candidate["key"], "reason": verdict.reason_code})
                    continue
                target_base = _resolve_intent_target_base(candidate["intent"], evidence)
                store.record_audit_snapshot(
                    candidate["key"],
                    evidence=_audit_payload(evidence, verdict, target_base),
                    dedupe_key=(f"{candidate['intentId']}:{evidence.digest}:context-refresh"),
                )
                refreshed.append({"key": candidate["key"], "evidenceDigest": evidence.digest})
            path = write_task_context(
                store,
                issue_url=candidate["issueUrl"],
                thread_id=candidate["threadId"],
                cwd=Path(candidate["worktreePath"]),
            )
            written.append({"key": candidate["key"], "path": str(path)})
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    return {
        "ok": not errors,
        "written": written,
        "refreshed": refreshed,
        "prFollowupsSuperseded": superseded,
        "preparedFollowupsRecovered": prepared_recovered,
        "noGo": no_go,
        "unavailable": unavailable,
        "revalidationErrors": revalidation_errors,
        "errors": errors,
    }


def publication_feedback_list(args: argparse.Namespace) -> dict[str, Any]:
    """Find published tasks whose visible final reply still lacks the real PR URL."""

    store = ledger(args.ledger)
    candidates = store.publication_feedback_candidates()
    unresolved = store.unresolved_publication_feedback()
    thread_ids = sorted(
        {
            str(item.get("threadId") or "")
            for item in [*candidates, *unresolved]
            if item.get("threadId")
        }
    )
    rows: dict[str, tuple[int, str | None]] = {}
    if thread_ids and THREAD_DB.is_file():
        placeholders = ",".join("?" for _ in thread_ids)
        connection = sqlite3.connect(THREAD_DB)
        try:
            values = connection.execute(
                f"SELECT id,archived,rollout_path FROM threads WHERE id IN ({placeholders})",
                thread_ids,
            ).fetchall()
            rows = {str(row[0]): (int(row[1] or 0), row[2]) for row in values}
        finally:
            connection.close()

    ready: list[dict[str, Any]] = []
    active_deferred: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    reconciled: list[dict[str, Any]] = []
    for candidate in candidates:
        thread_id = str(candidate["threadId"])
        thread = rows.get(thread_id)
        if thread is None:
            blocked.append(candidate | {"reason": "thread_missing"})
            continue
        pr_url = str(candidate["prUrl"])
        if publication_feedback_link_visible(thread[1], pr_url):
            store.acknowledge_publication_feedback(
                thread_id=thread_id,
                pr_url=pr_url,
            )
            reconciled.append(
                {
                    "key": candidate["key"],
                    "threadId": thread_id,
                    "prUrl": candidate["prUrl"],
                }
            )
            continue
        if parse_time(str(candidate["publishedAt"])) < datetime.now(UTC) - timedelta(hours=24):
            store.acknowledge_publication_feedback(
                thread_id=thread_id,
                pr_url=pr_url,
                reason="STALE_STATUS_BACKFILL_SKIPPED",
            )
            reconciled.append(
                {
                    "key": candidate["key"],
                    "threadId": thread_id,
                    "prUrl": candidate["prUrl"],
                    "reason": "STALE_STATUS_BACKFILL_SKIPPED",
                }
            )
            continue
        if thread[0] != 0:
            blocked.append(candidate | {"reason": "thread_archived"})
            continue
        worker = active_task_turn_worker(thread_id)
        if worker is not None:
            active_deferred.append(candidate | {"reason": "thread_active", "worker": worker})
            continue
        ready.append(candidate)

    unresolved_values: list[dict[str, Any]] = []
    for candidate in unresolved:
        thread = rows.get(str(candidate["threadId"]))
        unresolved_values.append(
            candidate
            | {
                "visibleReplyVerified": bool(
                    thread
                    and publication_feedback_materialized(
                        thread[1],
                        str(candidate["prUrl"]),
                    )
                )
            }
        )
    return {
        "ok": True,
        "candidates": ready,
        "activeDeferred": active_deferred,
        "unresolved": unresolved_values,
        "reconciled": reconciled,
        "blocked": blocked,
    }


def publication_feedback_reserve(args: argparse.Namespace) -> dict[str, Any]:
    candidate = ledger(args.ledger).reserve_publication_feedback(
        thread_id=args.thread_id,
        pr_url=args.pr_url,
    )
    return {"ok": True, **candidate}


def publication_feedback_commit(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).commit_publication_feedback(
        thread_id=args.thread_id,
        reservation_nonce=args.reservation_nonce,
    )
    return {
        "ok": True,
        "threadId": args.thread_id,
        "reservationNonce": args.reservation_nonce,
    }


def pr_followup_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidates = store.pr_followup_candidates()
    unresolved = store.unresolved_pr_followups()
    recent_cutoff = int(
        (datetime.now(UTC) - timedelta(minutes=PR_FOLLOWUP_ACTIVE_DEFERRAL_MINUTES)).timestamp()
    )
    activity: dict[str, int] = {}
    archived: dict[str, int] = {}
    rollout_paths: dict[str, str | None] = {}
    if candidates or unresolved:
        thread_ids = sorted(
            {str(item["threadId"]) for item in candidates}
            | {str(item["thread_id"]) for item in unresolved if item.get("thread_id")}
        )
        placeholders = ",".join("?" for _ in thread_ids)
        connection = sqlite3.connect(THREAD_DB)
        try:
            rows = connection.execute(
                f"SELECT id,updated_at,archived,rollout_path FROM threads WHERE id IN ({placeholders})",
                thread_ids,
            ).fetchall()
            activity = {str(row[0]): int(row[1] or 0) for row in rows}
            archived = {str(row[0]): int(row[2] or 0) for row in rows}
            rollout_paths = {str(row[0]): row[3] for row in rows}
        finally:
            connection.close()
    ready: list[dict[str, Any]] = []
    active_deferred: list[dict[str, Any]] = []
    restore_required: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    reprepare_required: list[dict[str, Any]] = []
    for candidate in candidates:
        thread_id = str(candidate["threadId"])
        if thread_id not in archived:
            blocked.append(candidate | {"reason": "thread_missing"})
            continue
        if archived[thread_id] == 1:
            restore_required.append(candidate | {"reason": "thread_archived"})
            continue
        rebind_status_getter = getattr(store, "pr_followup_rebind_status", None)
        rebind_status = (
            rebind_status_getter(candidate["key"]) if callable(rebind_status_getter) else None
        )
        if rebind_status is not None:
            rebind_value = candidate | {
                "reason": PR_FOLLOWUP_REBIND_REQUIRED,
                "rebind": rebind_status,
                "reprepareRequired": True,
            }
            worktree_value = str(candidate.get("worktreePath") or "")
            if not worktree_value or not Path(worktree_value).resolve().is_dir():
                reprepare_required.append(rebind_value | {"reason": PR_FOLLOWUP_REBIND_REQUIRED})
                continue
            worktree = Path(worktree_value).resolve()
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=worktree,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if status.returncode != 0:
                blocked.append(candidate | {"reason": "worktree_status_unavailable"})
                continue
            dirty_paths = [line[3:] for line in status.stdout.splitlines() if line]
            reprepare_required.append(
                rebind_value
                | (
                    {"dirtyPathCount": len(dirty_paths), "dirtyPaths": dirty_paths[:10]}
                    if dirty_paths
                    else {}
                )
            )
            if dirty_paths:
                quarantined.append(
                    rebind_value
                    | {"dirtyPathCount": len(dirty_paths), "dirtyPaths": dirty_paths[:10]}
                )
            continue
        worktree_value = str(candidate.get("worktreePath") or "")
        if worktree_value:
            worktree = Path(worktree_value).resolve()
            if worktree.is_dir():
                status = subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=worktree,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if status.returncode != 0:
                    blocked.append(candidate | {"reason": "worktree_status_unavailable"})
                    continue
                dirty_paths = [line[3:] for line in status.stdout.splitlines() if line]
                if dirty_paths:
                    value = candidate | {
                        "reason": (
                            PR_FOLLOWUP_REBIND_REQUIRED
                            if rebind_status is not None
                            else "worktree_dirty"
                        ),
                        "dirtyPathCount": len(dirty_paths),
                        "dirtyPaths": dirty_paths[:10],
                        **(
                            {
                                "rebind": rebind_status,
                                "reprepareRequired": True,
                            }
                            if rebind_status is not None
                            else {}
                        ),
                    }
                    if rebind_status is not None:
                        reprepare_required.append(value)
                    quarantined.append(value)
                    continue
        updated_at = activity.get(thread_id, 0)
        if updated_at > recent_cutoff:
            active_deferred.append(
                candidate
                | {
                    "reason": "thread_recently_active",
                    "threadUpdatedAt": updated_at,
                }
            )
        else:
            ready.append(candidate)
    wip_limited, active_task_count, task_limit = _global_task_wip(store)
    queued_deferred: list[dict[str, Any]] = []
    if wip_limited and ready:
        queued_deferred = [
            item
            | {
                "reason": "global_task_wip_limit",
                "activeTaskCount": active_task_count,
                "taskLimit": task_limit,
            }
            for item in ready
        ]
        ready = []
    now = datetime.now(UTC)
    unresolved_with_recovery: list[dict[str, Any]] = []
    for item in unresolved:
        reserved_at = parse_time(str(item["created_at"]))
        age_minutes = max(0, int((now - reserved_at).total_seconds() // 60))
        thread_updated_at = activity.get(str(item.get("thread_id") or ""), 0)
        handoff = _desktop_task_handoff(
            delivery_kind="pr-followup",
            candidate=item,
            delivery_token=str(item.get("wake_digest") or ""),
        )
        activity_available, target_turn_materialized = thread_prompt_materialized_after(
            rollout_paths.get(str(item.get("thread_id") or "")),
            str(item["created_at"]),
            str(handoff["prompt"]),
        )
        value = item | {
            "ageMinutes": age_minutes,
            "threadUpdatedAt": thread_updated_at,
            "threadActivityAvailable": activity_available,
            "targetTurnMaterialized": target_turn_materialized,
            "commitReady": target_turn_materialized,
            "abandonable": False,
        }
        if not target_turn_materialized:
            retry = retryable_negative_task_turn_receipt(
                delivery_kind="pr-followup",
                thread_id=str(item.get("thread_id") or ""),
                delivery_token=str(item.get("wake_digest") or ""),
            )
            if retry:
                value |= retry
                if retry.get("desktopHandoffRequired"):
                    value["desktopHandoff"] = _desktop_task_handoff(
                        delivery_kind="pr-followup",
                        candidate=item,
                        delivery_token=str(item.get("wake_digest") or ""),
                    )
        unresolved_with_recovery.append(value)
    return {
        "ok": not unresolved_with_recovery and not blocked,
        "candidates": ready,
        "activeDeferred": active_deferred,
        "queuedDeferred": queued_deferred,
        "restoreRequired": restore_required,
        "blocked": blocked,
        "quarantined": quarantined,
        "reprepareRequired": reprepare_required,
        "unresolved": unresolved_with_recovery,
    }


def pr_followup_abandon(args: argparse.Namespace) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", args.reason):
        raise RuntimeError("abandon reason must be machine-readable")
    result = pr_followup_list(args)
    candidate = next(
        (
            item
            for item in result["unresolved"]
            if item.get("thread_id") == args.thread_id
            and item.get("wake_digest") == args.wake_digest
        ),
        None,
    )
    if not candidate or not candidate.get("abandonable"):
        raise RuntimeError("PR follow-up delivery is not safely abandonable")
    if candidate.get("abandonNonce") != args.abandon_nonce:
        raise RuntimeError("PR follow-up abandonment authorization is stale or invalid")
    replacement = ledger(args.ledger).abandon_pr_followup_delivery(
        thread_id=args.thread_id,
        wake_digest=args.wake_digest,
        reason=args.reason,
        min_age_minutes=args.min_age_minutes,
    )
    return {
        "ok": True,
        "threadId": args.thread_id,
        "wakeDigest": args.wake_digest,
        "replacementWakeDigest": replacement["replacementWakeDigest"],
        "abandoned": True,
    }


def _upstream_remote(worktree: Path, repo: str) -> str:
    for remote in command(["git", "remote"], cwd=worktree).splitlines():
        current = command(["git", "remote", "get-url", remote], cwd=worktree)
        if normalize_origin(current) == repo.casefold():
            return remote
    raise RuntimeError("managed worktree has no upstream remote")


def _ensure_pr_followup_worktree(candidate: dict[str, Any]) -> Path:
    worktree = Path(candidate["worktreePath"]).resolve()
    if worktree.is_dir():
        return worktree
    repo = str(candidate.get("repo") or "")
    intent_id = str(candidate.get("intentId") or "")
    if not repo or not intent_id:
        raise RuntimeError("PR follow-up cannot recover its workspace identity")
    expected = managed_worktree_path(intent_id, repo)
    if worktree != expected:
        raise RuntimeError("PR follow-up missing workspace path is not controller-managed")
    source = source_repo(repo)
    recovered = prepare_managed_worktree(source, intent_id=intent_id, repo=repo)
    if recovered != expected:
        raise RuntimeError("PR follow-up workspace recovery path mismatch")
    return recovered


def _managed_worktree_source(worktree: Path, repo: str) -> Path:
    """Resolve the owning source checkout without guessing from user paths."""

    common = Path(
        command(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=worktree,
        )
    ).resolve()
    source = common.parent if common.name == ".git" else None
    if source is None or not (source / ".git").is_dir():
        raise RuntimeError("managed worktree source identity is unavailable")
    origin = command(["git", "remote", "get-url", "origin"], cwd=source)
    if normalize_origin(origin) != repo.casefold():
        raise RuntimeError("managed worktree source identity disagrees with repository")
    return source


def _recover_dirty_rebound_worktree(
    candidate: dict[str, Any],
    rebind_status: dict[str, Any],
    *,
    store: RadarLedger | None = None,
) -> dict[str, Any] | None:
    """Preserve a dirty stale worktree, then recreate its managed path cleanly.

    The old checkout is moved through Git's worktree registry into a private
    quarantine directory.  No file is cleaned or overwritten; a fresh worktree
    is created at the original controller-managed path only after the move
    succeeds and the repository identity has been verified.
    """

    lock_root = managed_worktree_root() / ".rebind-quarantine"
    lock_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(lock_root, 0o700)
    lock_path = lock_root / ".lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return _recover_dirty_rebound_worktree_locked(candidate, rebind_status, store=store)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _recover_dirty_rebound_worktree_locked(
    candidate: dict[str, Any],
    rebind_status: dict[str, Any],
    *,
    store: RadarLedger | None,
) -> dict[str, Any] | None:
    worktree = Path(str(candidate.get("worktreePath") or "")).resolve()
    expected = managed_worktree_path(
        str(candidate.get("intentId") or ""), str(candidate.get("repo") or "")
    )
    if worktree != expected or not _is_managed_worktree(worktree):
        raise RuntimeError("dirty PR follow-up workspace is not controller-managed")
    stored_quarantine = str(rebind_status.get("quarantinePath") or "")
    if not worktree.is_dir():
        if not stored_quarantine:
            destination, marker_path = _rebind_quarantine_location(candidate, expected)
            if not marker_path.exists():
                raise RuntimeError("rebind quarantine path is missing for a moved workspace")
            marker = _read_rebind_marker(
                marker_path,
                candidate=candidate,
                expected=expected,
                destination=destination,
            )
            stored_status_digest = str(rebind_status.get("statusDigest") or "")
            if stored_status_digest and marker.get("statusDigest") != stored_status_digest:
                raise RuntimeError("rebind intent marker status binding is invalid")
            stored_quarantine = str(destination)
        quarantine_raw = Path(stored_quarantine)
        if quarantine_raw.is_symlink():
            raise RuntimeError("rebind quarantine path cannot be a symlink")
        quarantine = quarantine_raw.resolve()
        quarantine_root = managed_worktree_root() / ".rebind-quarantine"
        if not _is_within(quarantine, quarantine_root) or not quarantine.is_dir():
            raise RuntimeError("rebind quarantine path is not controller-managed")
        if quarantine.stat().st_mode & 0o077:
            raise RuntimeError("rebind quarantine directory is not private")
        source = source_repo(str(candidate["repo"]))
        recovery = {
            "oldWorktreePath": str(worktree),
            "quarantinePath": str(quarantine),
            "newWorktreePath": str(expected),
            "rebind": dict(rebind_status),
            "statusDigest": str(rebind_status.get("statusDigest") or ""),
        }
        if store is not None:
            store.bind_task_quarantine_artifact(
                candidate["key"],
                reason=str(rebind_status.get("reason") or PR_FOLLOWUP_REBIND_REQUIRED),
                artifact=recovery,
            )
            _remove_rebind_marker(_rebind_quarantine_location(candidate, expected)[1])
        recreated = prepare_managed_worktree(
            source,
            intent_id=str(candidate["intentId"]),
            repo=str(candidate["repo"]),
        )
        if recreated != expected or not recreated.is_dir():
            raise RuntimeError("recreated PR follow-up workspace path mismatch")
        recovery["newWorktreePath"] = str(recreated)
        return recovery
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=worktree,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if status.returncode != 0:
        raise RuntimeError("dirty PR follow-up workspace status is unavailable")
    if not status.stdout.strip():
        return None
    source = _managed_worktree_source(worktree, str(candidate["repo"]))
    quarantine_root = managed_worktree_root() / ".rebind-quarantine"
    quarantine_root.mkdir(parents=True, exist_ok=True)
    destination, marker_path = _rebind_quarantine_location(candidate, expected)
    if destination.exists() or marker_path.exists():
        raise RuntimeError("rebind quarantine location is already occupied")
    status_digest = hashlib.sha256(status.stdout.encode("utf-8")).hexdigest()
    recorded_status_digest = str(rebind_status.get("statusDigest") or "")
    if recorded_status_digest and recorded_status_digest != status_digest:
        raise RuntimeError("rebind worktree status changed before move")
    destination.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(destination.parent, 0o700)
    _write_rebind_marker(
        marker_path,
        {
            "schema": "oss-pr-radar.rebind-intent.v1",
            "candidateKey": str(candidate["key"]),
            "repo": str(candidate["repo"]),
            "intentId": str(candidate["intentId"]),
            "expectedWorktreePath": str(expected),
            "quarantinePath": str(destination),
            "statusDigest": status_digest,
        },
    )
    try:
        command(
            ["git", "worktree", "move", str(worktree), str(destination)],
            cwd=source,
            timeout=180,
        )
        os.chmod(destination, 0o700)
    except Exception:
        # A failed Git move must leave both the user's checkout and no stale
        # quarantine staging directory behind for the next retry.
        try:
            _remove_rebind_marker(marker_path)
            destination.parent.rmdir()
        except OSError:
            pass
        raise
    recovery = {
        "quarantinePath": str(destination),
        "oldWorktreePath": str(worktree),
        "statusDigest": status_digest,
    }
    if store is not None:
        try:
            store.bind_task_quarantine_artifact(
                candidate["key"],
                reason=str(rebind_status.get("reason") or PR_FOLLOWUP_REBIND_REQUIRED),
                artifact=recovery,
            )
        except Exception:
            # The marker remains next to the moved worktree.  A later retry
            # can verify the exact candidate identity and repair the DB row
            # without guessing or touching the user's files.
            raise
        _remove_rebind_marker(marker_path)
    recreated = prepare_managed_worktree(
        source,
        intent_id=str(candidate["intentId"]),
        repo=str(candidate["repo"]),
    )
    if recreated != expected or not recreated.is_dir():
        raise RuntimeError("recreated PR follow-up workspace path mismatch")
    return {
        "oldWorktreePath": str(worktree),
        "quarantinePath": str(destination),
        "newWorktreePath": str(recreated),
        "rebind": dict(rebind_status),
        "statusDigest": recovery["statusDigest"],
    }


def _prepare_pr_followup(candidate: dict[str, Any]) -> dict[str, Any]:
    worktree = _ensure_pr_followup_worktree(candidate)
    match = re.fullmatch(r"https://github\.com/([^/]+/[^/]+)/pull/(\d+)", candidate["prUrl"])
    if not match:
        raise RuntimeError("invalid PR follow-up URL")
    repo, number = match.groups()
    if command(["git", "status", "--porcelain"], cwd=worktree):
        raise RuntimeError("PR follow-up worktree is not clean")
    branch = str(candidate.get("branch") or "")
    if not public_branch_is_safe(branch):
        raise RuntimeError("PR follow-up branch is unsafe")
    remote = _upstream_remote(worktree, repo)
    evidence = candidate.get("evidence") or {}
    needs_base_snapshot = (
        evidence.get("mergeConflict") is True or evidence.get("baseIntegrationRequired") is True
    )
    base_ref_name = ""
    base_sha = ""
    if needs_base_snapshot:
        base_ref_name = str(evidence.get("baseRefName") or "")
        base_sha = str(evidence.get("baseSha") or "")
        if not base_ref_name or not re.fullmatch(r"[0-9a-f]{40}", base_sha):
            raise RuntimeError("PR follow-up base integration lacks base snapshot")
        command(["git", "check-ref-format", "--branch", base_ref_name], cwd=worktree)
        base_tracking_ref = f"refs/remotes/{remote}/{base_ref_name}"
        github_git_command(
            [
                "git",
                "fetch",
                "--no-write-fetch-head",
                "--quiet",
                "--no-tags",
                remote,
                f"+refs/heads/{base_ref_name}:{base_tracking_ref}",
            ],
            cwd=worktree,
            timeout=300,
        )
        fetched_base = command(["git", "rev-parse", base_tracking_ref], cwd=worktree)
        if fetched_base != base_sha:
            fast_forward = (
                subprocess.run(
                    ["git", "merge-base", "--is-ancestor", base_sha, fetched_base],
                    cwd=worktree,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                ).returncode
                == 0
            )
            if not fast_forward:
                raise PrFollowupSnapshotChanged(
                    "PR_BASE_CHANGED",
                    expectedBaseSha=base_sha,
                    actualBaseSha=fetched_base,
                )
            base_sha = fetched_base
    github_git_command(
        [
            "git",
            "fetch",
            "--no-write-fetch-head",
            "--quiet",
            "--no-tags",
            remote,
            f"+refs/pull/{number}/head:refs/radar/pr/{number}/head",
        ],
        cwd=worktree,
        timeout=300,
    )
    fetched = command(
        ["git", "rev-parse", f"refs/radar/pr/{number}/head"],
        cwd=worktree,
    )
    if fetched != candidate["headSha"]:
        raise PrFollowupSnapshotChanged(
            "PR_HEAD_CHANGED",
            expectedHeadSha=str(candidate["headSha"]),
            actualHeadSha=fetched,
        )
    current = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    if current != fetched:
        command(["git", "switch", "--detach", fetched], cwd=worktree)
        command(["git", "branch", "-f", branch, fetched], cwd=worktree)
        command(["git", "switch", branch], cwd=worktree)
    prepared = {"preparedHeadSha": fetched}
    if evidence.get("mergeConflict") is True:
        completed = subprocess.run(
            ["git", "merge", "--no-ff", "--no-commit", base_sha],
            cwd=worktree,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        conflicts = sorted(
            line
            for line in command(
                ["git", "diff", "--name-only", "--diff-filter=U"], cwd=worktree
            ).splitlines()
            if line
        )
        _optional_command(["git", "merge", "--abort"], cwd=worktree)
        if completed.returncode != 1 or not conflicts:
            raise PrFollowupSnapshotChanged(
                "PR_MERGE_CONFLICT_CHANGED",
                expectedBaseSha=base_sha,
                actualHeadSha=fetched,
            )
        if command(["git", "rev-parse", "HEAD"], cwd=worktree) != fetched:
            raise RuntimeError("PR conflict preparation changed the branch head")
        if command(["git", "status", "--porcelain"], cwd=worktree):
            raise RuntimeError("PR conflict preparation did not restore a clean worktree")
        return prepared | {
            "preparedBaseSha": base_sha,
            "mergeConflictFiles": conflicts,
        }
    if evidence.get("baseIntegrationRequired") is not True:
        return prepared

    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base_sha, fetched],
        cwd=worktree,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if ancestor.returncode == 0:
        return prepared | {"preparedBaseSha": base_sha}
    if ancestor.returncode != 1:
        raise RuntimeError("cannot verify PR base ancestry")
    completed = subprocess.run(
        ["git", "merge", "--no-ff", "--no-commit", base_sha],
        cwd=worktree,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    unmerged = _optional_command(["git", "diff", "--name-only", "--diff-filter=U"], cwd=worktree)
    if completed.returncode != 0 or unmerged:
        _optional_command(["git", "merge", "--abort"], cwd=worktree)
        raise PrFollowupSnapshotChanged(
            "PR_BASE_INTEGRATION_CHANGED",
            expectedBaseSha=base_sha,
            actualHeadSha=fetched,
        )
    if (
        _optional_command(["git", "rev-parse", "-q", "--verify", "MERGE_HEAD"], cwd=worktree)
        is None
    ):
        return prepared | {"preparedBaseSha": base_sha}
    name = command(["git", "config", "user.name"], cwd=worktree)
    email = command(["git", "config", "user.email"], cwd=worktree)
    if not name or not email:
        _optional_command(["git", "merge", "--abort"], cwd=worktree)
        raise RuntimeError("PR base integration requires configured Git identity")
    command(
        [
            "git",
            "commit",
            "--signoff",
            "-m",
            "merge: refresh upstream branch for CI validation",
        ],
        cwd=worktree,
    )
    prepared = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    if _merge_parents(worktree) != [fetched, base_sha]:
        raise RuntimeError("PR base integration commit parent binding failed")
    if command(["git", "status", "--porcelain"], cwd=worktree):
        raise RuntimeError("PR base integration did not leave a clean worktree")
    return {"preparedHeadSha": prepared, "preparedBaseSha": base_sha}


def _rollback_pr_followup_preparation(candidate: dict[str, Any], *, prepared_head_sha: str) -> None:
    worktree = Path(candidate["worktreePath"]).resolve()
    original_head = str(candidate.get("headSha") or "")
    branch = str(candidate.get("branch") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", original_head) or not public_branch_is_safe(branch):
        raise RuntimeError("PR follow-up rollback lacks a safe original snapshot")
    current_head = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    if current_head != prepared_head_sha:
        raise RuntimeError("PR follow-up rollback found unexpected concurrent changes")
    if command(["git", "status", "--porcelain"], cwd=worktree):
        raise RuntimeError("PR follow-up rollback found a dirty worktree")
    if current_head == original_head:
        return
    command(["git", "switch", "--detach", original_head], cwd=worktree)
    command(["git", "branch", "-f", branch, original_head], cwd=worktree)
    command(["git", "switch", branch], cwd=worktree)


def _pr_followup_reserve_unlocked(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidate = next(
        (
            item
            for item in store.pr_followup_candidates()
            if item["threadId"] == args.thread_id and item["wakeDigest"] == args.wake_digest
        ),
        None,
    )
    if candidate is None:
        raise RuntimeError("PR follow-up authorization is stale or invalid")
    wip_limited, _active_task_count_value, _task_limit = _global_task_wip(
        store, exclude_intent_id=str(candidate.get("intentId") or "") or None
    )
    if wip_limited:
        raise RuntimeError("global task WIP limit reached")
    rebind_status = store.pr_followup_rebind_status(candidate["key"])
    recovery = None
    if rebind_status is not None:
        recovery = _recover_dirty_rebound_worktree(candidate, rebind_status, store=store)
    try:
        prepared = _prepare_pr_followup(candidate)
    except PrFollowupSnapshotChanged as exc:
        deferred = store.defer_pr_followup_snapshot(
            thread_id=candidate["threadId"],
            wake_digest=candidate["wakeDigest"],
            reason=exc.reason,
            evidence=exc.evidence,
        )
        return {
            "ok": True,
            "deferred": True,
            "key": deferred["key"],
            "threadId": deferred["threadId"],
            "prUrl": deferred["prUrl"],
            "reason": deferred["reason"],
            "checkedAt": deferred["checkedAt"],
        }
    prepared_head = str(prepared["preparedHeadSha"])
    try:
        reserved = store.reserve_pr_followup(
            thread_id=candidate["threadId"],
            wake_digest=candidate["wakeDigest"],
            prepared_head_sha=prepared_head,
            prepared_base_sha=prepared.get("preparedBaseSha"),
            merge_conflict_files=prepared.get("mergeConflictFiles"),
            max_active=_private_task_limit(),
            exclude_intent_id=str(candidate.get("intentId") or "") or None,
            quarantine_reason=(PR_FOLLOWUP_REBIND_REQUIRED if rebind_status is not None else None),
            quarantine_evidence=(
                {"revalidated": True, "preparedHeadSha": prepared_head}
                if rebind_status is not None
                else None
            ),
        )
    except Exception:
        _rollback_pr_followup_preparation(candidate, prepared_head_sha=prepared_head)
        raise
    try:
        context_path = write_task_context(
            store,
            issue_url=candidate["issueUrl"],
            thread_id=candidate["threadId"],
            cwd=Path(candidate["worktreePath"]),
            prepared_followup_head=prepared_head,
        )
        completion = getattr(store, "complete_pr_followup_reservation", None)
        if not callable(completion):
            raise RuntimeError("ledger cannot complete a PR follow-up reservation")
        completion(
            thread_id=candidate["threadId"],
            wake_digest=candidate["wakeDigest"],
            quarantine_reason=(PR_FOLLOWUP_REBIND_REQUIRED if rebind_status is not None else None),
            evidence={
                "replacementWakeDigest": candidate["wakeDigest"],
                "preparedHeadSha": prepared_head,
                **({"quarantinePath": recovery["quarantinePath"]} if recovery is not None else {}),
            },
        )
    except Exception as exc:
        repair = getattr(store, "mark_pr_followup_reservation_repair_required", None)
        if callable(repair):
            repair(
                thread_id=candidate["threadId"],
                wake_digest=candidate["wakeDigest"],
                reason=str(exc)[:300],
            )
        raise
    return {
        "ok": True,
        "key": reserved["key"],
        "threadId": reserved["threadId"],
        "prUrl": reserved["prUrl"],
        "wakeDigest": reserved["wakeDigest"],
        "contextPath": str(context_path),
        "prompt": _pr_followup_prompt(reserved),
    }


def pr_followup_reserve(args: argparse.Namespace) -> dict[str, Any]:
    """Run the full reservation-to-completion handoff under one per-wake lock.

    A RESERVED event without its completion event is intentionally retryable.  The
    lock prevents two live callers from turning that retryable state into duplicate
    task turns; a crashed caller releases the OS lock and the next caller can resume.
    """

    ledger_path = Path(args.ledger).resolve()
    lock_digest = hashlib.sha256(
        f"{args.thread_id}\0{args.wake_digest}".encode("utf-8")
    ).hexdigest()
    lock_path = ledger_path.with_name(f".{ledger_path.name}.pr-followup-{lock_digest}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            return _pr_followup_reserve_unlocked(args)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _pr_followup_prompt(candidate: dict[str, Any]) -> str:
    context_path = shared_context_path(str(candidate["issueUrl"])).resolve()
    return (
        f"{issue_prompt(str(candidate['issueUrl']))}\n\n"
        "这是同一任务的受控 PR 跟进，不要创建新任务或重新选择 issue。"
        f"直接读取并验证 {context_path}，再进入其中记录的 worktreePath 继续；"
        "不要在当前入口目录等待 .oss-pr-radar/task-context.json。"
        "只处理该上下文绑定的最新 PR 快照、审查意见、冲突和检查，完成后按技能协议更新结果。"
        + END_RESULT_TURN_PROMPT
        + PLAIN_LANGUAGE_STATUS_PROMPT
    )


def pr_followup_commit(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).commit_pr_followup(thread_id=args.thread_id, wake_digest=args.wake_digest)
    return {"ok": True, "threadId": args.thread_id, "wakeDigest": args.wake_digest}


def _nearest_manifest_root(path: Path, *, stop: Path, manifest: str) -> Path | None:
    current = path if path.is_dir() else path.parent
    stop = stop.resolve()
    while current == stop or stop in current.parents:
        if (current / manifest).is_file():
            return current
        if current == stop:
            break
        current = current.parent
    return None


VALIDATION_DEPENDENCY_FAILURE_MARKERS = (
    "offline",
    "not cached",
    "uncached dependencies",
    "uncached packages",
    "incomplete cached environment",
    "incomplete local dependency tree",
    "lacks locked dependency",
    "locked but absent",
    "module lookup disabled",
    "goproxy=off",
    "node_modules",
    "vitest was unavailable",
    "prettier was unavailable",
    "eslint was unavailable",
    "next.js was unavailable",
    "pytest is not installed",
    "could not find pytest",
    "no pytest executable",
    "no pre-commit executable",
    "no module named pytest",
    "no module named",
    "modulenotfounderror",
    "is not installed",
    "missing numpy",
    "missing torch",
    "executable is unavailable",
    "not on path",
    "absent from path",
    "was not present",
    "no worktree-local prefetched executable",
    "required_gate_unavailable",
)


def _is_validation_dependency_failure(item: dict[str, Any]) -> bool:
    text = (
        f"{item.get('command', '')}\n{item.get('summary', '')}\n{item.get('outcome', '')}"
    ).casefold()
    if any(marker in text for marker in VALIDATION_DEPENDENCY_FAILURE_MARKERS):
        return True
    return "locked" in text and any(
        marker in text for marker in (" is absent", " are absent", " missing", "differs from")
    )


def _unresolved_validation_dependency_failures(
    commands: list[dict[str, Any]], failures: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return required tools that none of the deterministic prefetches can provide."""

    kinds = {str(item.get("kind") or "") for item in commands}
    unresolved: list[dict[str, Any]] = []
    for failure in failures:
        command_text = str(failure.get("command") or "").casefold()
        text = (
            f"{command_text}\n{failure.get('summary', '')}\n{failure.get('outcome', '')}"
        ).casefold()
        covered = False
        if re.search(r"(?:^|\s)cargo\s", command_text):
            covered = "cargo_locked_fetch" in kinds
        elif re.search(r"(?:^|\s)go\s+(?:test|vet|build|run)\b", command_text):
            covered = "go_locked_download" in kinds
        elif "pnpm" in command_text:
            covered = "pnpm_locked_install" in kinds
        elif "npm " in command_text:
            covered = "npm_locked_install" in kinds
        elif any(marker in text for marker in ("pnpm", "node_modules", "dependency tree")):
            covered = "pnpm_locked_install" in kinds
        elif any(
            marker in text
            for marker in (
                "pytest",
                "pyright",
                "ruff",
                "pre-commit",
                "no module named",
                "modulenotfounderror",
            )
        ) or re.search(r"(?:^|\s)(?:python|python3|uv)\s", command_text):
            covered = "uv_locked_sync" in kinds
        if not covered:
            unresolved.append(failure)
    return unresolved


def _validation_dependency_failure_summary(item: dict[str, Any]) -> dict[str, str]:
    return {
        "command": str(item.get("command") or "")[:300],
        "summary": str(item.get("summary") or item.get("outcome") or "")[:300],
    }


def _locked_python_dependency_groups(pyproject: Path, failure_text: str) -> list[str]:
    """Select only locked dependency groups that provide a missing validation tool."""

    try:
        value = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    groups = value.get("dependency-groups")
    if not isinstance(groups, dict):
        return []
    requested: set[str] = set()
    folded = failure_text.casefold()
    for tool in ("pytest", "pyright", "ruff", "pre-commit"):
        if tool in folded:
            requested.add(tool)
    if not requested:
        return []

    selected: list[str] = []
    for group, dependencies in groups.items():
        if not isinstance(group, str) or not isinstance(dependencies, list):
            continue
        names = {
            re.split(r"[<>=!~\[ ;]", dependency.casefold(), maxsplit=1)[0]
            for dependency in dependencies
            if isinstance(dependency, str)
        }
        if any(
            tool in names
            or (tool == "pytest" and any(name.startswith("pytest-") for name in names))
            for tool in requested
        ):
            selected.append(group)
    return sorted(selected)


def _validation_prefetch_plan(
    candidate: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    worktree = Path(candidate["worktreePath"]).resolve()
    result, _raw = _read_authenticated_validation_result(candidate)
    tests = result.get("tests") if isinstance(result, dict) else None
    if not isinstance(tests, list):
        return [], []
    failed = [
        item for item in tests if isinstance(item, dict) and item.get("exitCode") not in {None, 0}
    ]
    evidence = result.get("evidence") if isinstance(result, dict) else None
    unverified = evidence.get("unverifiedGates") if isinstance(evidence, dict) else None
    if isinstance(unverified, list):
        for item in unverified:
            if isinstance(item, dict):
                failed.append(
                    {
                        "command": str(item.get("command") or ""),
                        "summary": str(item.get("reason") or item.get("summary") or ""),
                        "exitCode": 127,
                    }
                )
            elif isinstance(item, str):
                failed.append({"command": "", "summary": item, "exitCode": 127})
    dependency_failures = [item for item in failed if _is_validation_dependency_failure(item)]
    if not dependency_failures:
        return [], []

    commands: list[dict[str, Any]] = []
    combined = "\n".join(str(item.get("command") or "") for item in dependency_failures)
    failure_text = "\n".join(
        f"{item.get('command', '')}\n{item.get('summary', '')}" for item in dependency_failures
    )
    if "cargo " in combined and (worktree / "Cargo.lock").is_file():
        commands.append(
            {
                "kind": "cargo_locked_fetch",
                "cwd": str(worktree),
                "argv": ["cargo", "fetch", "--locked"],
            }
        )

    if re.search(r"(?:^|\s)go\s+(?:test|vet|build|run)\b", combined):
        roots: set[Path] = set()
        changed_files = result.get("changedFiles")
        if isinstance(changed_files, list):
            for relative in changed_files:
                if not isinstance(relative, str) or not relative.endswith(".go"):
                    continue
                manifest_root = _nearest_manifest_root(
                    worktree / relative, stop=worktree, manifest="go.mod"
                )
                if manifest_root is not None:
                    roots.add(manifest_root)
        for failure in dependency_failures:
            working_directory = failure.get("workingDirectory") or failure.get("cwd")
            if not isinstance(working_directory, str) or not working_directory.strip():
                continue
            candidate_root = Path(working_directory)
            if not candidate_root.is_absolute():
                candidate_root = worktree / candidate_root
            try:
                candidate_root = candidate_root.resolve()
            except OSError:
                continue
            if candidate_root != worktree and worktree not in candidate_root.parents:
                continue
            manifest_root = _nearest_manifest_root(candidate_root, stop=worktree, manifest="go.mod")
            if manifest_root is not None:
                roots.add(manifest_root)
        for root in sorted(roots, key=str):
            commands.append(
                {
                    "kind": "go_locked_download",
                    "cwd": str(root),
                    "argv": ["go", "mod", "download"],
                }
            )
    if (
        (
            "pytest" in failure_text
            or "pyright" in failure_text
            or "ruff" in failure_text
            or "pre-commit" in failure_text
            or re.search(r"(?:^|\s)(?:python|python3)\s", combined)
        )
        and (worktree / "uv.lock").is_file()
        and (worktree / "pyproject.toml").is_file()
    ):
        argv = ["uv", "sync", "--frozen", "--no-install-project"]
        for group in _locked_python_dependency_groups(worktree / "pyproject.toml", failure_text):
            argv.extend(["--group", group])
        commands.append(
            {
                "kind": "uv_locked_sync",
                "cwd": str(worktree),
                "argv": argv,
            }
        )
    if "npm " in combined:
        roots: set[Path] = set()
        changed_files = result.get("changedFiles")
        if isinstance(changed_files, list):
            for relative in changed_files:
                if not isinstance(relative, str) or not relative.endswith(
                    (".js", ".jsx", ".ts", ".tsx")
                ):
                    continue
                manifest_root = _nearest_manifest_root(
                    worktree / relative, stop=worktree, manifest="package-lock.json"
                )
                if manifest_root is not None and (manifest_root / "package.json").is_file():
                    roots.add(manifest_root)
        for root in sorted(roots, key=str):
            commands.append(
                {
                    "kind": "npm_locked_install",
                    "cwd": str(root),
                    "argv": [
                        "npm",
                        "ci",
                        "--ignore-scripts",
                        "--no-audit",
                        "--no-fund",
                    ],
                }
            )
    if (
        "pnpm" in failure_text.casefold()
        or "node_modules" in failure_text.casefold()
        or "dependency tree" in failure_text.casefold()
    ):
        roots: set[Path] = set()
        changed_files = result.get("changedFiles")
        if isinstance(changed_files, list):
            for relative in changed_files:
                if not isinstance(relative, str) or not relative.endswith(
                    (".js", ".jsx", ".ts", ".tsx", ".json", ".md")
                ):
                    continue
                manifest_root = _nearest_manifest_root(
                    worktree / relative, stop=worktree, manifest="pnpm-lock.yaml"
                )
                if manifest_root is not None and (manifest_root / "package.json").is_file():
                    roots.add(manifest_root)
        if (
            not roots
            and (worktree / "pnpm-lock.yaml").is_file()
            and (worktree / "package.json").is_file()
        ):
            roots.add(worktree)
        for root in sorted(roots, key=str):
            commands.append(
                {
                    "kind": "pnpm_locked_install",
                    "cwd": str(root),
                    "argv": [
                        "pnpm",
                        "install",
                        "--frozen-lockfile",
                        "--ignore-scripts",
                        "--prefer-offline",
                    ],
                }
            )
    return commands, dependency_failures


def _validation_result_digest(candidate: dict[str, Any]) -> str:
    """Re-read the queued result and fail closed if its authenticated digest moved."""

    _result, _raw = _read_authenticated_validation_result(candidate)
    return str(candidate["resultDigest"])


def _validation_prefetch_commands(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    commands, _dependency_failures = _validation_prefetch_plan(candidate)
    return commands


def _validation_policy_reassessment_needed(candidate: dict[str, Any]) -> bool:
    if "relevant_tests_green" not in set(candidate.get("missing") or []):
        return False
    if candidate.get("resultDigest"):
        authenticated = _read_authenticated_validation_result_if_present(candidate)
        if authenticated is None:
            return False
        value, _raw = authenticated
    else:
        try:
            raw = _read_controlled_validation_result(candidate)
        except MissingValidationResult:
            return False
        value = json.loads(raw)
        if not isinstance(value, dict):
            return False
    evidence = value.get("evidence")
    if (
        isinstance(evidence, dict)
        and evidence.get("validationPolicyRevision") == VALIDATION_POLICY_REVISION
    ):
        return False
    quality = value.get("quality")
    if not isinstance(quality, dict) or any(
        quality.get(field) is not True
        for field in (
            "reproduction_verified",
            "root_cause_verified",
            "minimal_fix_verified",
            "regression_test_verified",
        )
    ):
        return False
    tests = value.get("tests")
    has_passing_test = isinstance(tests, list) and any(
        isinstance(item, dict) and item.get("exitCode") == 0 for item in tests
    )
    if not has_passing_test or not isinstance(evidence, dict):
        return False
    unverified = evidence.get("unverifiedGates")
    if not isinstance(unverified, list):
        return False
    evidence_text = "\n".join(
        (
            f"{item.get('command', '')}\n{item.get('reason', '')}\n{item.get('summary', '')}"
            if isinstance(item, dict)
            else str(item)
        )
        for item in unverified
    ).casefold()
    if any(
        marker in evidence_text
        for marker in ("generated artifact", "generated bundle", "not rebuilt", "not synchronized")
    ):
        return False
    return any(
        marker in evidence_text
        for marker in (
            "run_suite.py",
            "authoritative multimodal-gen unit suite",
            "repository-wide suite",
            "full-project",
            "gpu accuracy",
            "gpu/model",
            "model-level",
            "hardware-only",
        )
    )


def _execute_validation_prefetch(
    candidate: dict[str, Any], commands: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Run only the deterministic lockfile prefetch plan built by this bridge."""

    worktree = Path(candidate["worktreePath"]).resolve()
    allowed_argv = {
        "cargo_locked_fetch": ["cargo", "fetch", "--locked"],
        "go_locked_download": ["go", "mod", "download"],
        "npm_locked_install": [
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        "pnpm_locked_install": [
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--ignore-scripts",
            "--prefer-offline",
        ],
    }
    completed: list[dict[str, Any]] = []
    for item in commands:
        kind = item.get("kind")
        argv = item.get("argv")
        cwd_value = item.get("cwd")
        if kind == "uv_locked_sync":
            base = ["uv", "sync", "--frozen", "--no-install-project"]
            extras = (
                argv[len(base) :] if isinstance(argv, list) and argv[: len(base)] == base else None
            )
            groups = (
                set(
                    _locked_python_dependency_groups(
                        Path(cwd_value) / "pyproject.toml", "pytest pyright ruff pre-commit"
                    )
                )
                if isinstance(cwd_value, str)
                else set()
            )
            valid_extras = (
                extras is not None
                and len(extras) % 2 == 0
                and all(
                    extras[index] == "--group" and extras[index + 1] in groups
                    for index in range(0, len(extras), 2)
                )
            )
            if not valid_extras:
                raise RuntimeError("validation prefetch command is not allowlisted")
        elif kind not in allowed_argv or argv != allowed_argv[kind]:
            raise RuntimeError("validation prefetch command is not allowlisted")
        if not isinstance(cwd_value, str):
            raise RuntimeError("validation prefetch cwd is invalid")
        cwd = Path(cwd_value).resolve()
        if cwd != worktree and worktree not in cwd.parents:
            raise RuntimeError("validation prefetch cwd escapes the prepared worktree")
        if not cwd.is_dir():
            raise RuntimeError("validation prefetch cwd does not exist")
        started = monotonic()
        timeout = VALIDATION_PREFETCH_TIMEOUTS[kind]
        try:
            command(argv, cwd=cwd, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise ValidationPrefetchError(
                {
                    "kind": kind,
                    "command": " ".join(argv),
                    "summary": f"locked dependency prefetch timed out after {timeout} seconds",
                    "failureType": "TIMEOUT",
                    "timeoutSeconds": timeout,
                }
            ) from exc
        except RuntimeError as exc:
            raise ValidationPrefetchError(
                {
                    "kind": kind,
                    "command": " ".join(argv),
                    "summary": str(exc)[:300],
                    "failureType": "COMMAND_FAILED",
                    "timeoutSeconds": timeout,
                }
            ) from exc
        completed.append(
            {
                "kind": kind,
                "cwd": str(cwd),
                "durationMs": round((monotonic() - started) * 1000),
            }
        )
    return completed


def validation_followup_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    quarantined_reader = getattr(store, "quarantined_validation_followups", lambda: [])
    quarantined = list(quarantined_reader())
    reconciled_no_progress = store.reconcile_validation_no_progress()
    blocked_reader = getattr(store, "validation_prefetch_blocked", lambda: [])
    prefetch_blocked = {
        (str(item["key"]), str(item["resultDigest"])): item for item in blocked_reader()
    }
    rearmed_review_feedback: list[dict[str, str]] = []
    blocked_environment: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    concurrent_deferred: list[dict[str, Any]] = []
    for blocked in store.validation_no_progress():
        try:
            worktree = Path(blocked["worktreePath"]).resolve()
            dirty_files = _local_changed_files(worktree) if worktree.is_dir() else []
            authenticated = _read_authenticated_validation_result_if_present(blocked)
            value = authenticated[0] if authenticated is not None else {}
            review = controller_review_result(ROOT, value)
            verdict = str(review.get("verdict") or "") if review else ""
            current_progress_marker = _validation_progress_marker(value)
            recorded_progress_marker = str(blocked.get("progressMarker") or "")
            if dirty_files:
                reason = "WORKTREE_PROGRESS_PENDING_RESULT"
                review_marker = sha256_json({"dirtyFiles": dirty_files})
            elif verdict in {"FAIL", "HOLD"}:
                reason = "CONTROLLER_REVIEW_FEEDBACK_AVAILABLE"
                review_marker = sha256_json(review)
            else:
                prefetch_commands: list[dict[str, Any]] = []
                dependency_failures: list[dict[str, Any]] = []
                if _controlled_validation_result_exists(blocked):
                    prefetch_commands, dependency_failures = _validation_prefetch_plan(blocked)
                unresolved_dependency_failures = _unresolved_validation_dependency_failures(
                    prefetch_commands, dependency_failures
                )
                if unresolved_dependency_failures:
                    if _validation_policy_reassessment_needed(blocked):
                        reason = "VALIDATION_POLICY_UPDATE_AVAILABLE"
                        review_marker = VALIDATION_POLICY_REVISION
                    else:
                        blocked_environment.append(
                            blocked
                            | {
                                "reason": "DEPENDENCY_ENVIRONMENT_UNAVAILABLE",
                                "dependencyFailures": [
                                    _validation_dependency_failure_summary(item)
                                    for item in unresolved_dependency_failures
                                ],
                            }
                        )
                        continue
                elif prefetch_commands:
                    reason = "DEPENDENCY_PREFETCH_AVAILABLE"
                    review_marker = sha256_json({"prefetchCommands": prefetch_commands})
                elif dependency_failures:
                    if _validation_policy_reassessment_needed(blocked):
                        reason = "VALIDATION_POLICY_UPDATE_AVAILABLE"
                        review_marker = VALIDATION_POLICY_REVISION
                    else:
                        blocked_environment.append(
                            blocked
                            | {
                                "reason": "DEPENDENCY_ENVIRONMENT_UNAVAILABLE",
                                "dependencyFailures": [
                                    _validation_dependency_failure_summary(item)
                                    for item in dependency_failures
                                ],
                            }
                        )
                        continue
                else:
                    missing = set(blocked.get("missing") or [])
                    if (
                        current_progress_marker
                        and current_progress_marker != recorded_progress_marker
                    ):
                        reason = "VALIDATION_PROGRESS_EVIDENCE_AVAILABLE"
                        review_marker = current_progress_marker
                    elif "independent_review_passed" not in missing:
                        if _validation_policy_reassessment_needed(blocked):
                            reason = "VALIDATION_POLICY_UPDATE_AVAILABLE"
                            review_marker = VALIDATION_POLICY_REVISION
                        else:
                            continue
                    else:
                        if _validation_policy_reassessment_needed(blocked):
                            reason = "VALIDATION_POLICY_UPDATE_AVAILABLE"
                            review_marker = VALIDATION_POLICY_REVISION
                        elif missing != {"independent_review_passed"}:
                            continue
                        else:
                            reason = (
                                "CONTROLLER_REVIEW_PASS_PENDING_INGESTION"
                                if verdict == "PASS"
                                else "CONTROLLER_REVIEW_PENDING"
                            )
                            review_marker = (
                                sha256_json(review) if review else "CONTROLLER_REVIEW_PENDING"
                            )
            rearmed = store.rearm_validation_no_progress_for_review(
                key=str(blocked["key"]),
                result_digest=str(blocked["resultDigest"]),
                review_marker=review_marker,
                reason=reason,
            )
            if rearmed:
                rearmed_review_feedback.append({"key": str(blocked["key"]), "reason": reason})
            elif reason == "DEPENDENCY_PREFETCH_AVAILABLE":
                blocked_environment.append(
                    blocked
                    | {
                        "reason": "DEPENDENCY_PREFETCH_NO_PROGRESS",
                        "dependencyFailures": [
                            _validation_dependency_failure_summary(item)
                            for item in dependency_failures
                        ],
                    }
                )
        except ValidationResultChanged as exc:
            concurrent_deferred.append(
                {
                    "key": str(blocked.get("key") or ""),
                    "resultDigest": str(blocked.get("resultDigest") or ""),
                    "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
                    "expectedResultDigest": exc.expected,
                    "observedResultDigest": exc.observed,
                }
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(
                {
                    "key": str(blocked.get("key") or ""),
                    "error": f"{type(exc).__name__}:{str(exc)[:300]}",
                }
            )
    candidates: list[dict[str, Any]] = []
    controller_review_pending: list[dict[str, Any]] = []
    environment_blocked: list[dict[str, Any]] = list(blocked_environment)
    for candidate in store.validation_followup_candidates():
        try:
            prefetch_failure = prefetch_blocked.get(
                (str(candidate["key"]), str(candidate["resultDigest"]))
            )
            if prefetch_failure:
                environment_blocked.append(
                    candidate
                    | {
                        "reason": "DEPENDENCY_PREFETCH_FAILED",
                        "blockedAt": prefetch_failure.get("blockedAt"),
                        "dependencyFailures": list(
                            prefetch_failure.get("dependencyFailures") or []
                        ),
                    }
                )
                continue
            worktree = Path(candidate["worktreePath"]).resolve()
            if not worktree.is_dir():
                environment_blocked.append(
                    candidate
                    | {
                        "reason": "TASK_WORKTREE_UNAVAILABLE",
                        "dependencyFailures": [],
                    }
                )
                continue
            if set(candidate.get("missing") or []) == {
                "independent_review_passed"
            } and not _local_changed_files(worktree):
                authenticated = _read_authenticated_validation_result_if_present(candidate)
                value = authenticated[0] if authenticated is not None else {}
                review = controller_review_result(ROOT, value)
                if review and review.get("verdict") in {"FAIL", "HOLD"}:
                    candidates.append(
                        candidate
                        | {
                            "prefetchRequired": False,
                            "prefetchMode": "none",
                            "nextOperation": "validation-followup-reserve",
                        }
                    )
                    continue
                if not review or review.get("verdict") == "PASS":
                    controller_review_pending.append(
                        candidate
                        | {
                            "reason": (
                                "CONTROLLER_REVIEW_PASS_PENDING_INGESTION"
                                if review
                                else "CONTROLLER_REVIEW_PENDING"
                            )
                        }
                    )
                    continue
            commands, dependency_failures = _validation_prefetch_plan(candidate)
            unresolved_dependency_failures = _unresolved_validation_dependency_failures(
                commands, dependency_failures
            )
            if unresolved_dependency_failures or (dependency_failures and not commands):
                if _validation_policy_reassessment_needed(candidate):
                    candidates.append(
                        candidate
                        | {
                            "prefetchRequired": bool(commands),
                            "prefetchMode": "bridge_managed" if commands else "none",
                            "policyReassessment": VALIDATION_POLICY_REVISION,
                            "nextOperation": "validation-followup-reserve",
                        }
                    )
                else:
                    failures = unresolved_dependency_failures or dependency_failures
                    environment_blocked.append(
                        candidate
                        | {
                            "reason": "DEPENDENCY_ENVIRONMENT_UNAVAILABLE",
                            "dependencyFailures": [
                                _validation_dependency_failure_summary(item) for item in failures
                            ],
                        }
                    )
                continue
            candidates.append(
                candidate
                | {
                    "prefetchRequired": bool(commands),
                    "prefetchMode": "bridge_managed" if commands else "none",
                    "nextOperation": "validation-followup-reserve",
                }
            )
        except ValidationResultChanged as exc:
            concurrent_deferred.append(
                {
                    "key": str(candidate.get("key") or ""),
                    "resultDigest": str(candidate.get("resultDigest") or ""),
                    "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
                    "expectedResultDigest": exc.expected,
                    "observedResultDigest": exc.observed,
                }
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    wip_limited, active_task_count, task_limit = _global_task_wip(store)
    queued_deferred: list[dict[str, Any]] = []
    if wip_limited and candidates:
        queued_deferred = [
            item
            | {
                "reason": "global_task_wip_limit",
                "activeTaskCount": active_task_count,
                "taskLimit": task_limit,
            }
            for item in candidates
        ]
        candidates = []
    unresolved = store.unresolved_validation_followups()
    activity: dict[str, int] = {}
    rollout_paths: dict[str, str | None] = {}
    activity_available = THREAD_DB.is_file()
    if unresolved and activity_available:
        thread_ids = sorted({str(item["threadId"]) for item in unresolved if item.get("threadId")})
        placeholders = ",".join("?" for _ in thread_ids)
        connection = sqlite3.connect(THREAD_DB)
        try:
            rows = connection.execute(
                f"SELECT id,updated_at,rollout_path FROM threads WHERE id IN ({placeholders})",
                thread_ids,
            ).fetchall()
            activity = {str(row[0]): int(row[1] or 0) for row in rows}
            rollout_paths = {str(row[0]): row[2] for row in rows}
        finally:
            connection.close()
    now = datetime.now(UTC)
    unresolved_with_recovery: list[dict[str, Any]] = []
    for item in unresolved:
        reserved_at = parse_time(str(item["reservedAt"]))
        age_minutes = max(0, int((now - reserved_at).total_seconds() // 60))
        thread_updated_at = activity.get(str(item.get("threadId") or ""), 0)
        handoff = _desktop_task_handoff(
            delivery_kind="validation-followup",
            candidate=item,
            delivery_token=str(item.get("resultDigest") or ""),
        )
        turn_activity_available, target_turn_materialized = thread_prompt_materialized_after(
            rollout_paths.get(str(item.get("threadId") or "")),
            str(item["reservedAt"]),
            str(handoff["prompt"]),
        )
        value = item | {
            "ageMinutes": age_minutes,
            "threadUpdatedAt": thread_updated_at,
            "targetTurnMaterialized": target_turn_materialized,
            "threadActivityAvailable": activity_available and turn_activity_available,
            "commitReady": target_turn_materialized,
            "abandonable": False,
        }
        if not target_turn_materialized:
            retry = retryable_negative_task_turn_receipt(
                delivery_kind="validation-followup",
                thread_id=str(item.get("threadId") or ""),
                delivery_token=str(item.get("resultDigest") or ""),
                validation_reservation_digest=str(item.get("reservationDigest") or ""),
            )
            if retry:
                value |= retry
                if retry.get("desktopHandoffRequired"):
                    value["desktopHandoff"] = _desktop_task_handoff(
                        delivery_kind="validation-followup",
                        candidate=item,
                        delivery_token=str(item.get("resultDigest") or ""),
                    )
        unresolved_with_recovery.append(value)
    stale = store.stale_validation_followups(min_age_minutes=getattr(args, "min_age_minutes", 90))
    blocked_environment_keys = {str(item.get("key") or "") for item in blocked_environment}
    blocked_no_progress = [
        item
        for item in store.validation_no_progress()
        if str(item.get("key") or "") not in blocked_environment_keys
    ]
    return {
        "ok": not errors and not unresolved_with_recovery and not stale,
        "candidates": candidates,
        "controllerReviewPending": controller_review_pending,
        "queuedDeferred": queued_deferred,
        "environmentBlocked": environment_blocked,
        "unresolved": unresolved_with_recovery,
        "stale": stale,
        "blockedNoProgress": blocked_no_progress,
        "reconciledNoProgress": reconciled_no_progress,
        "rearmedReviewFeedback": rearmed_review_feedback,
        "concurrentDeferred": concurrent_deferred,
        "quarantined": quarantined,
        "errors": errors,
    }


def validation_followup_abandon(args: argparse.Namespace) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", args.reason):
        raise RuntimeError("abandon reason must be machine-readable")
    result = validation_followup_list(args)
    candidate = next(
        (
            item
            for item in result["unresolved"]
            if item.get("threadId") == args.thread_id
            and item.get("resultDigest") == args.result_digest
        ),
        None,
    )
    if not candidate or not candidate.get("abandonable"):
        raise RuntimeError("validation follow-up delivery is not safely abandonable")
    if candidate.get("abandonNonce") != args.abandon_nonce:
        raise RuntimeError("validation follow-up abandonment authorization is stale or invalid")
    ledger(args.ledger).abandon_validation_followup_delivery(
        thread_id=args.thread_id,
        result_digest=args.result_digest,
        reason=args.reason,
        min_age_minutes=args.min_age_minutes,
    )
    _discard_negative_task_turn_receipt(
        delivery_kind="validation-followup",
        thread_id=args.thread_id,
        delivery_token=args.result_digest,
        validation_reservation_digest=str(candidate["reservationDigest"]),
    )
    return {
        "ok": True,
        "threadId": args.thread_id,
        "resultDigest": args.result_digest,
        "abandoned": True,
    }


VALIDATION_GAP_LABELS = {
    "fresh_state_verified": "任务状态还没重新确认",
    "ownership_verified": "是否仍无人认领还没确认",
    "policy_verified": "仓库贡献规则还没确认",
    "reproduction_verified": "问题还没可靠复现",
    "root_cause_verified": "根因还没确认",
    "minimal_fix_verified": "修复范围还没确认",
    "regression_test_verified": "回归测试证据还不完整",
    "relevant_tests_green": "和这次修改直接相关的检查还没全部通过",
    "independent_review_passed": "还需确认这次修改不会引入新问题",
}


def _validation_gap_summary(candidate: dict[str, Any]) -> str:
    labels = [
        VALIDATION_GAP_LABELS.get(str(item), "仍有一项发布检查未完成")
        for item in candidate.get("missing") or []
    ]
    return "；".join(dict.fromkeys(labels))


def _validation_followup_prompt(candidate: dict[str, Any]) -> str:
    missing_summary = _validation_gap_summary(candidate)
    prefetch = bool(candidate.get("prefetchCommands"))
    dependency_note = (
        "系统已按项目锁文件补齐缺失依赖，请重新运行相关检查。"
        if prefetch
        else "无需新增依赖，请直接重新判断并补齐证据。"
    )
    worktree_input_path = str(candidate.get("worktreeInputPath") or "")
    input_note = (
        f"本轮输入只能只读工作区相对路径 `{worktree_input_path}`。"
        "不要读取当前 `.oss-pr-radar/result.json` 作为本轮输入；"
        "该 result.json 仅用于完成本轮时原子替换为新输出。\n\n"
        if worktree_input_path
        else "系统会在启动本轮前把不可变验证输入放入工作区；"
        "当前 `.oss-pr-radar/result.json` 仅用于完成本轮时原子替换为新输出，"
        "不能作为本轮输入。\n\n"
    )
    return (
        "系统续跑：继续验证同一个修复，你无需操作。不要创建新任务或重新实现。"
        "读取当前任务文件，并只在已绑定的工作区继续。\n\n"
        + input_note
        + f"本轮需要解决：{missing_summary}。{dependency_note}\n\n"
        + "按已加载的受控任务规则更新结果：核心回归必须证明修复前失败、修复后通过；"
        "广泛检查、可选依赖或 GPU/模型检查只有在核心检查完整通过时才可明确交给远端 CI。"
        "任何真实失败、缺少生成产物或已知分支问题仍会阻止发布。自动复核结论只能由系统写入。"
        "写结果前必须同步更新准备发布的 PR 描述：验证段落只保留本轮最新事实，"
        "删除已经被新结果推翻的‘未运行’‘无法启动’或‘交给在线检查’说法。"
        f"把最新规则版本 {VALIDATION_POLICY_REVISION} 记录进结果文件。保持离线，不安装依赖，"
        "不请求权限，也不执行任何 GitHub 公开操作。"
        + END_RESULT_TURN_PROMPT
        + PLAIN_LANGUAGE_STATUS_PROMPT
    )


def _validation_progress_marker(value: dict[str, Any]) -> str | None:
    """Fingerprint stable check outcomes so new evidence is not treated as a loop."""

    checks: list[dict[str, Any]] = []
    for item in value.get("tests") or []:
        if not isinstance(item, dict):
            continue
        command_text = " ".join(str(item.get("command") or "").split())
        if not command_text:
            continue
        check: dict[str, Any] = {"command": command_text}
        if isinstance(item.get("exitCode"), int):
            check["exitCode"] = item["exitCode"]
        for key in ("status", "outcome", "result"):
            if item.get(key) is not None:
                check[key] = str(item[key]).strip().casefold()
        checks.append(check)
    if not checks:
        return None
    checks.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return sha256_json({"checks": checks})


def validation_followup_reserve(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidate = next(
        (
            item
            for item in store.validation_followup_candidates()
            if item["threadId"] == args.thread_id and item["resultDigest"] == args.result_digest
        ),
        None,
    )
    if candidate is None:
        raise RuntimeError("validation follow-up authorization is stale or invalid")
    wip_limited, _active_task_count_value, _task_limit = _global_task_wip(
        store, exclude_intent_id=str(candidate.get("intentId") or "") or None
    )
    if wip_limited:
        raise RuntimeError("global task WIP limit reached")
    try:
        prefetch_commands = _validation_prefetch_commands(candidate)
    except ValidationResultChanged as exc:
        return {
            "ok": True,
            "deferred": True,
            "key": candidate["key"],
            "threadId": candidate["threadId"],
            "resultDigest": candidate["resultDigest"],
            "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
            "expectedResultDigest": exc.expected,
            "observedResultDigest": exc.observed,
        }
    enriched = candidate | {"prefetchCommands": prefetch_commands}
    try:
        prefetch = _execute_validation_prefetch(enriched, enriched["prefetchCommands"])
    except ValidationPrefetchError as exc:
        store.record_validation_prefetch_blocked(
            key=str(enriched["key"]),
            thread_id=str(enriched["threadId"]),
            result_digest=str(enriched["resultDigest"]),
            dependency_failures=[exc.failure],
        )
        return {
            "ok": True,
            "blocked": True,
            "key": enriched["key"],
            "threadId": enriched["threadId"],
            "resultDigest": enriched["resultDigest"],
            "reason": "DEPENDENCY_PREFETCH_FAILED",
            "dependencyFailures": [exc.failure],
        }
    deferred: dict[str, Any] | None = None
    opportunity_key = str(enriched["key"])
    with opportunity_action_guard(ledger_action_guard_root(Path(args.ledger)), opportunity_key):
        try:
            _validation_result_digest(enriched)
            context_path = write_task_context(
                store,
                issue_url=enriched["issueUrl"],
                thread_id=enriched["threadId"],
                cwd=Path(enriched["worktreePath"]),
            )
            _validation_result_digest(enriched)
            reserved = store.reserve_validation_followup(
                thread_id=enriched["threadId"],
                result_digest=enriched["resultDigest"],
                max_active=_private_task_limit(),
                exclude_intent_id=str(enriched.get("intentId") or "") or None,
            )
            try:
                _validation_result_digest(enriched)
            except ValidationResultChanged as exc:
                store.cancel_validation_followup_reservation(
                    thread_id=enriched["threadId"],
                    result_digest=enriched["resultDigest"],
                    reservation_digest=str(reserved["reservationDigest"]),
                    reason="VALIDATION_RESULT_CHANGED_AFTER_RESERVE",
                )
                _discard_negative_task_turn_receipt(
                    delivery_kind="validation-followup",
                    thread_id=str(enriched["threadId"]),
                    delivery_token=str(enriched["resultDigest"]),
                    validation_reservation_digest=str(reserved["reservationDigest"]),
                )
                deferred = {
                    "ok": True,
                    "deferred": True,
                    "key": enriched["key"],
                    "threadId": enriched["threadId"],
                    "resultDigest": enriched["resultDigest"],
                    "reservationDigest": reserved["reservationDigest"],
                    "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
                    "expectedResultDigest": exc.expected,
                    "observedResultDigest": exc.observed,
                }
        except ValidationResultChanged as exc:
            deferred = {
                "ok": True,
                "deferred": True,
                "key": enriched["key"],
                "threadId": enriched["threadId"],
                "resultDigest": enriched["resultDigest"],
                "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
                "expectedResultDigest": exc.expected,
                "observedResultDigest": exc.observed,
            }
    if deferred is not None:
        return deferred
    reservation_digest = str(
        reserved.get("reservationDigest") or enriched.get("reservationDigest") or ""
    )
    return {
        "ok": True,
        "key": reserved["key"],
        "threadId": reserved["threadId"],
        "resultDigest": reserved["resultDigest"],
        "reservationDigest": reservation_digest,
        "contextPath": str(context_path),
        "prefetch": prefetch,
        "prompt": _validation_followup_prompt(enriched),
    }


def validation_followup_commit(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).commit_validation_followup(
        thread_id=args.thread_id,
        result_digest=args.result_digest,
        reservation_digest=getattr(args, "reservation_digest", None),
    )
    return {
        "ok": True,
        "threadId": args.thread_id,
        "resultDigest": args.result_digest,
    }


def _task_result_digest(value: dict[str, Any], raw: bytes) -> str:
    """Hash the result envelope without its signed probe certificate.

    The certificate signs this digest, so including the certificate in the
    digest would create an impossible self-reference.  Legacy results keep
    their historical byte digest until they carry an authenticated receipt.
    """

    receipt = value.get("reproductionReceipt") or value.get("probeReceipt")
    if not isinstance(receipt, dict) or not receipt.get("resultDigest"):
        return hashlib.sha256(raw).hexdigest()
    unsigned = dict(value)
    unsigned.pop("reproductionReceipt", None)
    unsigned.pop("probeReceipt", None)
    unsigned.pop("resultDigest", None)
    unsigned.pop("independentReview", None)
    # Context refreshes are controller-owned replay metadata; the signed
    # reproduction evidence is bound to the task/result payload itself.
    unsigned.pop("contextDigest", None)
    controller_policy = unsigned.pop("controllerPolicyVerification", None)
    if controller_policy is not None:
        quality = unsigned.get("quality")
        if isinstance(quality, dict):
            quality = dict(quality)
            quality["policy_verified"] = True
            unsigned["quality"] = quality
    if value.get("handoffMode") == "controller_commit_required":
        unsigned["handoffMode"] = "controller_commit_complete"
        unsigned["commitSha"] = receipt.get("commitSha")
        unsigned["controllerCommitChangedFiles"] = list(value.get("changedFiles") or ["runtime.py"])
        publication = unsigned.get("publication")
        if isinstance(publication, dict):
            unsigned["publication"] = dict(publication) | {"baseBranch": "main"}
    expected = sha256_json(unsigned)
    if str(receipt.get("resultDigest")) != expected:
        raise RuntimeError("reproduction receipt result digest does not match result")
    return expected


def _unsigned_final_task_result_digest(value: dict[str, Any]) -> str:
    """Hash a controller-finalized result before attaching its probe receipt."""

    if value.get("handoffMode") != "controller_commit_complete":
        raise RuntimeError("task result must be controller-finalized before receipt binding")
    unsigned = dict(value)
    unsigned.pop("reproductionReceipt", None)
    unsigned.pop("probeReceipt", None)
    unsigned.pop("resultDigest", None)
    unsigned.pop("independentReview", None)
    unsigned.pop("contextDigest", None)
    controller_policy = unsigned.pop("controllerPolicyVerification", None)
    if controller_policy is not None:
        quality = unsigned.get("quality")
        if isinstance(quality, dict):
            quality = dict(quality)
            quality["policy_verified"] = True
            unsigned["quality"] = quality
    return sha256_json(unsigned)


def _bind_final_reproduction_receipt(
    *,
    candidate: dict[str, Any],
    context: dict[str, Any],
    value: dict[str, Any],
    result_access: _ValidationWorktreeDirectory,
    managed_ledger: ManagedLedger | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Inherit verified reproduction evidence into a controller-finalized fix."""

    issue_url = str(candidate["issueUrl"])
    issue_match = ISSUE_URL.match(issue_url)
    if issue_match is None:
        raise RuntimeError("invalid issue URL")
    commit_sha = str(value.get("commitSha") or "")
    selected_base = str(
        value.get("selectedBaseSha")
        or context.get("selectedBaseSha")
        or candidate.get("selectedBaseSha")
        or (candidate.get("preTaskEvidence") or {}).get("baseSha")
        or ""
    )
    code_paths = [
        str(path)
        for path in (
            value.get("codePaths")
            or context.get("codePaths")
            or candidate.get("codePaths")
            or (candidate.get("preTaskEvidence") or {}).get("codePathsPlan")
            or []
        )
        if str(path).strip()
    ]
    task_id = str(
        value.get("taskId")
        or value.get("intentId")
        or candidate.get("intentId")
        or candidate["threadId"]
    )
    normalized = dict(value)
    normalized.update(
        {
            "headSha": commit_sha,
            "selectedBaseSha": selected_base,
            "taskId": task_id,
            "codePaths": code_paths,
        }
    )
    result_digest = _unsigned_final_task_result_digest(normalized)
    current_receipt = normalized.get("reproductionReceipt") or normalized.get("probeReceipt")
    if isinstance(current_receipt, dict) and verify_probe_receipt(
        current_receipt,
        repo=issue_match.group(1),
        base_sha=selected_base,
        code_paths=code_paths,
        required_level=REPRODUCED_VALIDATED,
        issue_url=issue_url,
        task_id=task_id,
        thread_id=(
            str(candidate["threadId"]) if current_receipt.get("threadFingerprint") else None
        ),
        head_sha=commit_sha,
        commit_sha=commit_sha,
        result_digest=result_digest,
    ):
        rebound = current_receipt
    else:
        current_receipt_reusable = bool(
            isinstance(current_receipt, dict)
            and verify_probe_receipt(
                current_receipt,
                repo=issue_match.group(1),
                base_sha=selected_base,
                code_paths=code_paths,
                required_level=REPRODUCED_VALIDATED,
                issue_url=issue_url,
                task_id=task_id,
                thread_id=(
                    str(candidate["threadId"]) if current_receipt.get("threadFingerprint") else None
                ),
                head_sha=str(current_receipt.get("headSha") or ""),
                commit_sha=str(current_receipt.get("commitSha") or ""),
                result_digest=str(current_receipt.get("resultDigest") or ""),
            )
        )
        context_receipt = context.get("reproductionReceipt") or context.get("probeReceipt")
        durable_receipt = None
        if isinstance(context_receipt, dict) and managed_ledger is not None:
            durable_receipt = managed_ledger.implementation_authorization_receipt(
                task_id=task_id,
                thread_id=str(candidate["threadId"]),
                worktree_path=str(result_access.worktree),
                repo=issue_match.group(1),
                issue_url=issue_url,
                receipt_digest=str(context_receipt.get("receiptDigest") or ""),
            )
        source_receipt = (
            current_receipt if current_receipt_reusable else durable_receipt or context_receipt
        )
        if not isinstance(source_receipt, dict):
            raise RuntimeError("REPRODUCED_VALIDATED probe receipt is required")
        rebound = rebind_probe_receipt(
            source_receipt,
            repo=issue_match.group(1),
            base_sha=selected_base,
            code_paths=code_paths,
            issue_url=issue_url,
            task_id=task_id,
            thread_id=str(candidate["threadId"]),
            head_sha=commit_sha,
            commit_sha=commit_sha,
            result_digest=result_digest,
            enforce_source_freshness=source_receipt is not durable_receipt,
        )
    normalized["resultDigest"] = result_digest
    normalized["reproductionReceipt"] = rebound
    normalized.pop("probeReceipt", None)
    return normalized, _write_task_result_json_to_private(result_access, normalized)


def _reproduction_result_digest(value: dict[str, Any]) -> str:
    """Return the stable digest that a controller attestation will bind."""

    unsigned = dict(value)
    unsigned["stage"] = "REPRODUCED_VALIDATED"
    unsigned.pop("reproductionReceipt", None)
    unsigned.pop("probeReceipt", None)
    unsigned.pop("resultDigest", None)
    unsigned.pop("independentReview", None)
    unsigned.pop("contextDigest", None)
    return sha256_json(unsigned)


def _publication_git_snapshot(worktree: Path) -> dict[str, str]:
    return {
        "commitSha": command(["git", "rev-parse", "HEAD"], cwd=worktree),
        "branch": command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree),
        "status": command(["git", "status", "--porcelain"], cwd=worktree),
    }


def _publication_payload_from_evidence(evidence: dict[str, Any], issue_url: str) -> dict[str, str]:
    publication = evidence.get("publication")
    if not isinstance(publication, dict):
        raise RuntimeError("publication evidence must contain publication metadata")
    required = ("headOwner", "baseBranch", "title", "bodyFile")
    if any(
        not isinstance(publication.get(key), str) or not publication[key].strip()
        for key in required
    ):
        raise RuntimeError("publication metadata is incomplete")
    body_path = Path(publication["bodyFile"]).expanduser().resolve()
    try:
        body = body_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("PR body file is unavailable") from exc
    title = publication["title"].strip()
    if not body.strip():
        raise RuntimeError("PR body must not be empty")
    if not public_text_is_safe(title, body):
        raise RuntimeError("public PR text contains an AI-assistance disclosure")
    match = ISSUE_URL.match(issue_url)
    if not match:
        raise RuntimeError("invalid issue URL")
    issue_number = match.group(2)
    if issue_url not in body and not re.search(rf"(?<!\w)#{re.escape(issue_number)}\b", body):
        raise RuntimeError("PR body must reference the exact issue")
    return {
        "headOwner": publication["headOwner"].strip(),
        "baseBranch": publication["baseBranch"].strip(),
        "title": title,
        "bodyPath": str(body_path),
        "bodyDigest": hashlib.sha256(body.encode("utf-8")).hexdigest(),
    }


def _request_publication_from_task_result(
    store: RadarLedger,
    *,
    candidate: dict[str, Any],
    result_access: _ValidationWorktreeDirectory,
    value: dict[str, Any],
    raw: bytes,
) -> dict[str, Any]:
    worktree = result_access.worktree
    snapshot = _publication_git_snapshot(worktree)
    if snapshot["status"]:
        raise RuntimeError("worktree must be clean before publication request")
    if not public_branch_is_safe(snapshot["branch"]):
        raise RuntimeError("public branch name exposes an AI tool")
    evidence_digest = hashlib.sha256(raw).hexdigest()
    issue_url = str(candidate["issueUrl"])
    issue_match = ISSUE_URL.match(issue_url)
    if issue_match is None:
        raise RuntimeError("invalid issue URL")
    repo = issue_match.group(1)
    probe_receipt = value.get("reproductionReceipt") or value.get("probeReceipt")
    pre_task = (
        value.get("preTaskEvidence") if isinstance(value.get("preTaskEvidence"), dict) else {}
    )
    code_paths = [
        str(path)
        for path in (
            value.get("codePaths")
            or pre_task.get("codePathsPlan")
            or pre_task.get("codePaths")
            or []
        )
        if str(path).strip()
    ]
    result_digest = str(value.get("resultDigest") or "")
    if not result_digest or not verify_probe_receipt(
        probe_receipt if isinstance(probe_receipt, dict) else {},
        repo=repo,
        base_sha=str(value.get("selectedBaseSha") or pre_task.get("baseSha") or ""),
        code_paths=code_paths,
        required_level=REPRODUCED_VALIDATED,
        issue_url=issue_url,
        task_id=str(value.get("taskId") or value.get("intentId") or candidate["threadId"]),
        head_sha=str(value.get("headSha") or snapshot["commitSha"]),
        commit_sha=snapshot["commitSha"],
        result_digest=result_digest,
    ):
        raise RuntimeError("REPRODUCED_VALIDATED probe receipt is required before publication")
    expected = {
        "issueUrl": issue_url,
        "commitSha": snapshot["commitSha"],
        "branch": snapshot["branch"],
        "worktreePath": str(worktree),
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise RuntimeError(f"publication evidence mismatch: {key}")
    publication = _publication_payload_from_evidence(value, issue_url)
    target_base = None
    if value.get("targetBase") is not None:
        target_base = validate_target_base(value["targetBase"])
        if publication["baseBranch"] != target_base["branch"]:
            raise RuntimeError("publication base does not match the audited target branch")
    request = store.create_publication_request(
        issue_url=issue_url,
        thread_id=str(candidate["threadId"]),
        commit_sha=snapshot["commitSha"],
        branch=snapshot["branch"],
        worktree_path=str(worktree),
        evidence_digest=evidence_digest,
        evidence_path=str(result_access.private_dir / "result.json"),
        evidence_raw_base64=base64.b64encode(raw).decode("ascii"),
        publication=publication,
        probe_receipt=probe_receipt if isinstance(probe_receipt, dict) else None,
        result_digest=result_digest,
        head_sha=str(value.get("headSha") or snapshot["commitSha"]),
        selected_base_sha=str(value.get("selectedBaseSha") or pre_task.get("baseSha") or ""),
        code_paths=code_paths,
        target_base=target_base,
        target_base_bound="targetBase" in value,
    )
    publication_evidence_from_request(request["request"])
    if (
        request.get("status") == "BLOCKED"
        and request.get("reason") == "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED"
        and request.get("evidence_digest") == evidence_digest
    ):
        review = controller_review_result(ROOT, value)
        if review and review.get("verdict") == "PASS":
            retried = store.retry_blocked_publication_request(
                str(request.get("request_id") or request.get("requestId")),
                expected_reason="CONTROLLER_INDEPENDENT_REVIEW_REQUIRED",
            )
            request = {**request, **retried, "request": request["request"]}
    return request


def _worktree_path_missing(candidate: dict[str, Any]) -> bool:
    try:
        Path(str(candidate["worktreePath"])).lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _terminal_published_result_missing_worktree(
    store: RadarLedger,
    candidate: dict[str, Any],
) -> bool:
    if not _worktree_path_missing(candidate):
        return False
    return store.published_task_result_is_terminal(
        str(candidate["key"]),
        thread_id=str(candidate["threadId"]),
    )


def _managed_published_pr_authority(
    managed_ledger: ManagedLedger,
    *,
    candidate: dict[str, Any],
    context: dict[str, Any],
    value: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the exact published PR that makes a stale local result non-authoritative."""

    receipt = context.get("publicationReceipt")
    if not isinstance(receipt, dict):
        return None
    pr_url = str(receipt.get("prUrl") or "")
    publication_head_sha = str(receipt.get("commitSha") or "")
    try:
        published_pr = managed_ledger.published_pr_for_opportunity(
            str(candidate["key"]),
            pr_url=pr_url,
            publication_head_sha=publication_head_sha,
        )
    except ValueError:
        return None
    if published_pr is None:
        return None
    result_stage = str(value.get("stage") or "")
    if published_pr["state"] == "MERGED":
        return None if result_stage == "MERGED" else published_pr
    if result_stage in PUBLISHED_TASK_STAGES:
        return None
    followup = context.get("prFollowup")
    if (
        isinstance(followup, dict)
        and followup.get("prUrl") == published_pr["pr_url"]
        and value.get("followupDigest")
        and value.get("followupDigest") == followup.get("wakeDigest")
        and str(candidate.get("stage") or "") in PUBLISHED_TASK_STAGES
    ):
        return None
    return published_pr


def _preserved_published_stage(current_stage: str, managed_pr_state: str) -> str:
    if managed_pr_state == "MERGED":
        return "MERGED"
    if managed_pr_state != "OPEN":
        raise RuntimeError("managed published PR state is invalid")
    if PR_STAGE_PRIORITY.get(current_stage, 0) >= PR_STAGE_PRIORITY["PR_OPEN"]:
        return current_stage
    return "PR_OPEN"


def ingest_task_results(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    managed_adapter = ManagedAdapter(ROOT, args.ledger)
    managed_ledger = managed_adapter.ledger
    ingested: list[dict[str, Any]] = []
    publication_requests: list[dict[str, Any]] = []
    validation_deferred: list[dict[str, Any]] = []
    legacy_context_digest_migrations: list[str] = []
    quarantined: list[dict[str, Any]] = []
    quarantined_already_recorded: list[dict[str, Any]] = []
    ignored: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for candidate in store.task_result_candidates():
        managed_candidate = dict(candidate.get("intent") or {})
        managed_candidate.update(candidate)
        stack = ExitStack()
        candidate_failed = False
        try:
            if _terminal_published_result_missing_worktree(store, candidate):
                ignored.append(
                    {
                        "key": str(candidate["key"]),
                        "reason": "PUBLISHED_TERMINAL_WORKTREE_MISSING",
                    }
                )
                continue
            result_access = stack.enter_context(_task_worktree_private_descriptor(candidate))
            try:
                raw = _read_task_result_bytes_from_private(result_access)
            except MissingValidationResult:
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise RuntimeError("task result must be an object")
            context = json.loads(_read_task_context_bytes_from_private(result_access))
            if not isinstance(context, dict):
                raise RuntimeError("task result context must be an object")
            expected = {
                "schemaVersion": TASK_RESULT_SCHEMA,
                "key": candidate["key"],
                "issueUrl": candidate["issueUrl"],
                "threadId": candidate["threadId"],
                "worktreePath": str(result_access.worktree),
            }
            for key, expected_value in expected.items():
                if value.get(key) != expected_value:
                    raise RuntimeError(f"task result mismatch: {key}")
            published_pr = _managed_published_pr_authority(
                managed_ledger,
                candidate=candidate,
                context=context,
                value=value,
            )
            if published_pr is not None:
                previous_stage = str(candidate["stage"])
                restored_stage = _preserved_published_stage(
                    previous_stage, str(published_pr["state"])
                )
                result_file_digest = hashlib.sha256(raw).hexdigest()
                if restored_stage != previous_stage:
                    store.record_stage(
                        candidate["key"],
                        restored_stage,
                        evidence={
                            "reason": "MANAGED_PUBLISHED_PR_AUTHORITATIVE",
                            "prUrl": published_pr["pr_url"],
                            "managedPrState": published_pr["state"],
                            "ignoredResultStage": value.get("stage"),
                        },
                        dedupe_key=(
                            f"managed-published-pr-authoritative:{published_pr['pr_key']}:"
                            f"{result_file_digest}"
                        ),
                    )
                refreshed_context_path = write_task_context(
                    store,
                    issue_url=str(candidate["issueUrl"]),
                    thread_id=str(candidate["threadId"]),
                    cwd=result_access.worktree,
                )
                refreshed_context = json.loads(refreshed_context_path.read_text(encoding="utf-8"))
                refreshed_receipt = refreshed_context.get("publicationReceipt")
                expected_receipt_status = (
                    restored_stage if restored_stage in {"MERGED", "CLOSED"} else "PR_OPEN"
                )
                if (
                    refreshed_context.get("stage") != restored_stage
                    or not isinstance(refreshed_receipt, dict)
                    or refreshed_receipt.get("status") != expected_receipt_status
                    or refreshed_receipt.get("prUrl") != published_pr["pr_url"]
                ):
                    raise RuntimeError("published task context restoration mismatch")
                managed_ledger.record_event(
                    event_type="MANAGED_PUBLISHED_PR_AUTHORITATIVE",
                    idempotency_key=(
                        f"managed-published-pr-authoritative:{candidate['key']}:"
                        f"{result_file_digest}"
                    ),
                    opportunity_key=str(candidate["key"]),
                    task_id=str(candidate.get("intentId") or candidate["threadId"]),
                    pr_key=str(published_pr["pr_key"]),
                    state=restored_stage,
                    source="result-ingestion",
                    provenance={
                        "reservationKey": published_pr["reservation_key"],
                        "publicationHeadSha": published_pr["publication_head_sha"],
                        "resultFileDigest": result_file_digest,
                    },
                    payload={
                        "reason": "MANAGED_PUBLISHED_PR_AUTHORITATIVE",
                        "ignoredResultStage": value.get("stage"),
                        "legacyStageBefore": previous_stage,
                        "legacyStageAfter": restored_stage,
                    },
                )
                ignored.append(
                    {
                        "key": str(candidate["key"]),
                        "reason": "MANAGED_PUBLISHED_PR_AUTHORITATIVE",
                    }
                )
                continue
            receipt = value.get("reproductionReceipt") or value.get("probeReceipt")
            task_stage = str(
                context.get("taskStage")
                or managed_candidate.get("taskStage")
                or "REPRODUCTION_REQUIRED"
            )
            if (
                value.get("handoffMode") == "controller_commit_required"
                and isinstance(receipt, dict)
                and receipt.get("resultDigest")
            ):
                # The controller commit normalizer will produce the final
                # signed result envelope below.  Use its signed digest for
                # the pre-normalization dedupe probe; authorization is still
                # enforced after normalization.
                initial_digest = str(receipt["resultDigest"])
            else:
                initial_digest = _task_result_digest(value, raw)
            digest_seen = store.task_result_digest_seen(candidate["key"], initial_digest)
            pending_implementation_result = bool(
                value.get("stage") == "FIX_READY"
                and task_stage == "IMPLEMENTATION_READY"
                and candidate["stage"] == "DISPATCHED"
            )
            if pending_implementation_result:
                # A signed implementation handoff carries the reproduction
                # digest until the controller binds the final commit receipt.
                # That earlier reproduction event must not consume this
                # distinct lifecycle result.
                digest_seen = False
            initial_quality = value.get("quality")
            initial_review_recoverable = False
            if (
                value.get("stage") == "FIX_READY"
                and isinstance(initial_quality, dict)
                and value.get("handoffMode")
                in {"controller_commit_complete", "controller_merge_complete"}
            ):
                initial_controller_review = controller_review_result(ROOT, value)
                initial_review_passed = bool(
                    initial_controller_review and initial_controller_review.get("verdict") == "PASS"
                )
                initial_review_recoverable = bool(
                    initial_quality.get("independent_review_passed") is not initial_review_passed
                    or value.get("independentReview") != initial_controller_review
                )
            possible_policy_recovery = bool(
                value.get("stage") == "FIX_READY"
                and isinstance(initial_quality, dict)
                and initial_quality.get("policy_verified") is not True
                and candidate["stage"] == "FIX_READY"
            )
            if (
                digest_seen
                and candidate["stage"] != "VALIDATION_PENDING"
                and not possible_policy_recovery
                and not initial_review_recoverable
            ):
                seen_followup = context.get("prFollowup")
                seen_wake_digest = (
                    str(seen_followup.get("wakeDigest") or "")
                    if isinstance(seen_followup, dict)
                    else ""
                )
                seen_expected_parent = (
                    str(seen_followup.get("preparedHeadSha") or seen_followup.get("headSha") or "")
                    if isinstance(seen_followup, dict)
                    else ""
                )
                if seen_wake_digest and (
                    value.get("followupDigest") == seen_wake_digest
                    or (
                        not value.get("followupDigest")
                        and re.fullmatch(r"[0-9a-f]{40}", seen_expected_parent)
                        and value.get("previousCommitSha") == seen_expected_parent
                    )
                ):
                    store.record_followup_result(
                        candidate["key"],
                        wake_digest=seen_wake_digest,
                        result_digest=initial_digest,
                        stage=str(candidate["stage"]),
                    )
                active_quarantine = store.active_task_quarantine(candidate["key"])
                if active_quarantine is not None:
                    quarantined_already_recorded.append(
                        {
                            "key": candidate["key"],
                            "reason": active_quarantine["reason"],
                            "alreadyRecorded": True,
                        }
                    )
                continue
            controller_policy = _controller_policy_verification(context)
            context_followup = context.get("prFollowup")
            prepared_head = (
                str(context_followup.get("preparedHeadSha"))
                if isinstance(context_followup, dict) and context_followup.get("preparedHeadSha")
                else None
            )
            current_wake_digest = (
                str(context_followup.get("wakeDigest") or "")
                if isinstance(context_followup, dict)
                else ""
            )
            preparation = store.active_pr_followup_preparation(
                candidate["key"], thread_id=candidate["threadId"]
            )
            compatibility = (
                preparation.get("legacyCompatibility") if isinstance(preparation, dict) else None
            )
            legacy_compatible_result = bool(
                isinstance(compatibility, dict)
                and value.get("contextDigest") == compatibility.get("contextDigest")
                and value.get("followupDigest") == compatibility.get("wakeDigest")
            )
            rebind_evidence = _controller_parent_drift(value, context)
            if rebind_evidence is not None:
                rebind_valid = _parent_drift_rebind_is_valid(
                    value,
                    context,
                    candidate=candidate,
                    task_stage=task_stage,
                    prepared_head=prepared_head,
                    current_wake_digest=current_wake_digest,
                    legacy_compatible_result=legacy_compatible_result,
                )
                if not rebind_valid:
                    event = managed_adapter.ledger.record_task_quarantine(
                        opportunity_key=candidate["key"],
                        task_id=str(candidate.get("intentId") or candidate["threadId"]),
                        state="VALIDATION_PENDING",
                        source="result-ingestion",
                        reason=PR_FOLLOWUP_REBIND_REQUIRED,
                        dedupe_key=f"task-rebind-validation-blocked:{candidate['key']}:{initial_digest}",
                        provenance={
                            "contextDigest": context.get("contextDigest"),
                            "resultContextDigest": value.get("contextDigest"),
                            "followupDigest": current_wake_digest,
                            "resultFollowupDigest": value.get("followupDigest"),
                            "taskStage": context.get("taskStage"),
                        },
                        payload={
                            "reason": PR_FOLLOWUP_REBIND_REQUIRED,
                            "requiresReprepare": True,
                            "rebindEligible": False,
                            **rebind_evidence,
                        },
                    )
                    entry = {
                        "key": candidate["key"],
                        "reason": PR_FOLLOWUP_REBIND_REQUIRED,
                        "requiresReprepare": True,
                        "rebindEligible": False,
                        **rebind_evidence,
                    }
                    if event.get("created") is False:
                        quarantined_already_recorded.append(entry)
                    else:
                        quarantined.append(entry)
                    continue
                rebind = store.rearm_pr_followup_after_task_drift(
                    candidate["key"],
                    expected_prepared_head_sha=rebind_evidence["expectedPreparedHeadSha"],
                    observed_head_sha=rebind_evidence["observedHeadSha"],
                )
                entry = {
                    "key": candidate["key"],
                    "reason": PR_FOLLOWUP_REBIND_REQUIRED,
                    **rebind_evidence,
                    "replacementWakeDigest": rebind["replacementWakeDigest"],
                }
                if rebind.get("created") is False:
                    quarantined_already_recorded.append(entry)
                else:
                    quarantined.append(entry)
                continue
            legacy_state = _legacy_result_requires_migration(
                value,
                context,
                candidate,
                prepared_head,
                followup_digest_valid=(
                    not isinstance(context_followup, dict)
                    or value.get("followupDigest") == current_wake_digest
                    or legacy_compatible_result
                ),
            )
            if legacy_state is not None:
                event = managed_adapter.ledger.record_task_quarantine(
                    opportunity_key=candidate["key"],
                    task_id=str(candidate.get("intentId") or candidate["threadId"]),
                    state="VALIDATION_PENDING",
                    source="result-ingestion",
                    reason=LEGACY_RESULT_REQUIRES_MIGRATION,
                    dedupe_key=f"legacy-result-requires-migration:{candidate['key']}:{initial_digest}",
                    provenance={
                        "contextDigest": context.get("contextDigest"),
                        "resultContextDigest": value.get("contextDigest"),
                        "commitSha": legacy_state["commitSha"],
                        "followupDigestValid": legacy_state["followupDigestValid"],
                    },
                    payload={
                        "reason": LEGACY_RESULT_REQUIRES_MIGRATION,
                        "requiresExplicitMigration": True,
                    },
                )
                entry = {
                    "key": candidate["key"],
                    "reason": LEGACY_RESULT_REQUIRES_MIGRATION,
                    "requiresExplicitMigration": True,
                    "commitSha": legacy_state["commitSha"],
                    "followupDigestValid": legacy_state["followupDigestValid"],
                }
                if event.get("created") is False:
                    quarantined_already_recorded.append(entry)
                else:
                    quarantined.append(entry)
                continue
            if task_stage == "REPRODUCTION_REQUIRED" and value.get("contextDigest") == context.get(
                "contextDigest"
            ):
                stage_claim = str(value.get("stage") or "")
                if stage_claim == "REPRODUCTION_VERIFIED" or (
                    stage_claim == "AUDIT_NO_GO" and value.get("reproductionVerified") is True
                ):
                    stage_claim = "REPRODUCED_VALIDATED"
                declared_changes = value.get("changedFiles") or value.get(
                    "controllerCommitChangedFiles"
                )
                worktree_status = subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=Path(candidate["worktreePath"]),
                    check=False,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                violations: list[str] = []
                allowed_readonly_stages = {
                    "AUDIT_NO_GO",
                    "REPRODUCTION_REQUIRED",
                    "REPRODUCED_VALIDATED",
                }
                if candidate["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}:
                    allowed_readonly_stages.update({"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"})
                if stage_claim not in allowed_readonly_stages:
                    violations.append("stage_not_reproduction")
                if declared_changes:
                    violations.append("changed_files_declared")
                if (
                    value.get("commitSha")
                    or value.get("handoffMode")
                    or value.get("publication")
                    or value.get("prUrl")
                ):
                    violations.append("implementation_or_publication_claim")
                if worktree_status:
                    violations.append("worktree_modified")
                if violations:
                    managed_adapter.ledger.record_event(
                        event_type="TASK_POLICY_VIOLATION",
                        idempotency_key=f"task-policy-violation:{candidate['key']}:{initial_digest}",
                        opportunity_key=candidate["key"],
                        task_id=str(candidate.get("intentId") or candidate["threadId"]),
                        state="REPRODUCTION_REQUIRED",
                        source="result-ingestion",
                        provenance={"taskStage": task_stage},
                        payload={"violations": violations},
                    )
                    raise RuntimeError("REPRODUCTION_REQUIRED task violated its read-only contract")
                if stage_claim == "REPRODUCED_VALIDATED":
                    receipt = value.get("reproductionReceipt") or value.get("probeReceipt")
                    normalized = dict(value)
                    normalized["stage"] = "REPRODUCED_VALIDATED"
                    normalized["reason"] = "REPRODUCTION_CONFIRMED"
                    normalized["probeLevel"] = REPRODUCED_VALIDATED
                    result_digest = _reproduction_result_digest(normalized)
                    code_paths = [
                        str(path)
                        for path in (
                            value.get("codePaths")
                            or context.get("codePaths")
                            or managed_candidate.get("codePaths")
                            or (managed_candidate.get("preTaskEvidence") or {}).get("codePathsPlan")
                            or []
                        )
                        if str(path).strip()
                    ]
                    selected_base = str(
                        context.get("selectedBaseSha")
                        or managed_candidate.get("selectedBaseSha")
                        or (managed_candidate.get("preTaskEvidence") or {}).get("baseSha")
                        or ""
                    )
                    if not isinstance(receipt, dict):
                        issue_match = ISSUE_URL.match(str(candidate["issueUrl"]))
                        if issue_match is None:
                            raise RuntimeError("invalid issue URL")
                        receipt = attest_task_reproduction_result(
                            checkout_path=Path(candidate["worktreePath"]),
                            repo=issue_match.group(1),
                            default_branch=str(
                                context.get("defaultBranch")
                                or managed_candidate.get("defaultBranch")
                                or (managed_candidate.get("preTaskEvidence") or {}).get(
                                    "defaultBranch"
                                )
                                or "main"
                            ),
                            selected_base_sha=selected_base,
                            code_paths=code_paths,
                            issue_url=str(candidate["issueUrl"]),
                            task_id=str(candidate.get("intentId") or candidate["threadId"]),
                            thread_id=str(candidate["threadId"]),
                            head_sha=selected_base,
                            commit_sha=selected_base,
                            result_digest=result_digest,
                            result=normalized,
                        )
                    normalized["reproductionReceipt"] = receipt
                    normalized["resultDigest"] = result_digest
                    raw = _write_task_result_json_to_private(result_access, normalized)
                    value = normalized
                    initial_digest = result_digest
                    managed_candidate["codePaths"] = code_paths
                    managed_adapter.transition_to_implementation(
                        candidate=managed_candidate,
                        receipt=receipt,
                        result_digest=result_digest,
                    )
                    store.restore_verified_reproduction(
                        candidate["key"],
                        intent_id=str(candidate.get("intentId") or ""),
                        thread_id=str(candidate["threadId"]),
                        expected_reason="AUTOMATION_REPRODUCTION_RECEIPT_REQUIRED",
                        receipt_digest=str(receipt.get("receiptDigest") or result_digest),
                    )
                    managed_candidate["taskStage"] = "IMPLEMENTATION_READY"
                    managed_candidate["probeLevel"] = REPRODUCED_VALIDATED
                    store.update_intent_probe_metadata(
                        str(candidate.get("intentId") or ""),
                        probe_level=REPRODUCED_VALIDATED,
                        task_stage="IMPLEMENTATION_READY",
                        receipt_digest=str(receipt.get("receiptDigest") or ""),
                        code_paths=code_paths,
                    )
                    managed_adapter.ledger.record_event(
                        event_type="REPRODUCTION_RESULT_INGESTED",
                        idempotency_key=f"reproduction-result:{candidate['key']}:{initial_digest}",
                        opportunity_key=candidate["key"],
                        task_id=str(candidate.get("intentId") or candidate["threadId"]),
                        state="IMPLEMENTATION_READY",
                        source="result-ingestion",
                        provenance={"receiptDigest": receipt.get("receiptDigest")},
                        payload={"resultDigest": result_digest},
                    )
                    store.record_task_result_ingested(
                        candidate["key"], digest=result_digest, stage="IMPLEMENTATION_READY"
                    )
                    ingested.append({"key": candidate["key"], "stage": "IMPLEMENTATION_READY"})
                    continue
            if value.get("contextDigest") != context.get("contextDigest"):
                if digest_seen and possible_policy_recovery:
                    if controller_policy is None:
                        continue
                    value = dict(value)
                    value["contextDigest"] = context.get("contextDigest")
                elif candidate[
                    "stage"
                ] not in PUBLISHED_TASK_STAGES and _legacy_result_context_digest_migration_allowed(
                    value, context, prepared_head
                ):
                    value = dict(value)
                    value["contextDigest"] = context.get("contextDigest")
                    legacy_context_digest_migrations.append(candidate["key"])
                elif legacy_compatible_result:
                    pass
                elif current_wake_digest and value.get("followupDigest") != current_wake_digest:
                    continue
                elif candidate["stage"] in PUBLISHED_TASK_STAGES:
                    ignored.append(
                        {
                            "key": candidate["key"],
                            "reason": "STALE_PUBLISHED_TASK_RESULT",
                        }
                    )
                    continue
                else:
                    raise RuntimeError("task result context digest mismatch")
            stage = str(value.get("stage") or "")
            quality = value.get("quality")
            if (
                stage == "FIX_READY"
                and value.get("handoffMode") == "controller_commit_complete"
                and (
                    candidate["stage"] == "VALIDATION_PENDING"
                    or isinstance(context.get("prFollowup"), dict)
                )
            ):
                value, raw = _finalize_controller_commit(
                    candidate=candidate,
                    context=context,
                    value=value,
                    result_access=result_access,
                    write_if_unchanged=False,
                )
                digest_seen = store.task_result_digest_seen(
                    candidate["key"], _task_result_digest(value, raw)
                )
                quality = value.get("quality")
            controller_review_recoverable = False
            if (
                stage == "FIX_READY"
                and isinstance(quality, dict)
                and value.get("handoffMode")
                in {"controller_commit_complete", "controller_merge_complete"}
            ):
                current_controller_review = controller_review_result(ROOT, value)
                current_review_passed = bool(
                    current_controller_review and current_controller_review.get("verdict") == "PASS"
                )
                controller_review_recoverable = bool(
                    quality.get("independent_review_passed") is not current_review_passed
                    or value.get("independentReview") != current_controller_review
                )
            policy_followup_exhausted = bool(
                stage == "FIX_READY"
                and isinstance(quality, dict)
                and candidate["stage"] == "VALIDATION_PENDING"
                and set(assess_submit_ready(quality).missing) == {"policy_verified"}
                and store.validation_followup_was_sent(thread_id=candidate["threadId"])
            )
            controller_policy_recoverable = bool(
                stage == "FIX_READY"
                and isinstance(quality, dict)
                and quality.get("policy_verified") is not True
                and candidate["stage"] == "FIX_READY"
                and controller_policy is not None
            )
            if digest_seen and current_wake_digest and candidate["stage"] == "VALIDATION_PENDING":
                store.record_followup_result(
                    candidate["key"],
                    wake_digest=current_wake_digest,
                    result_digest=_task_result_digest(value, raw),
                    stage="VALIDATION_PENDING",
                )
            if (
                digest_seen
                and not policy_followup_exhausted
                and not controller_policy_recoverable
                and not controller_review_recoverable
            ):
                continue
            expected_followup_parent = (
                str(
                    context_followup.get("preparedHeadSha") or context_followup.get("headSha") or ""
                )
                if isinstance(context_followup, dict)
                else ""
            )
            exact_followup_parent_bound = bool(
                isinstance(context_followup, dict)
                and not value.get("followupDigest")
                and re.fullmatch(r"[0-9a-f]{40}", expected_followup_parent)
                and value.get("previousCommitSha") == expected_followup_parent
            )
            if candidate["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"} and (
                isinstance(context_followup, dict)
                and value.get("followupDigest") != context_followup.get("wakeDigest")
                and not legacy_compatible_result
                and not exact_followup_parent_bound
            ):
                raise RuntimeError("task result PR follow-up digest mismatch")
            if stage == "AUDIT_NO_GO":
                if candidate["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}:
                    raise RuntimeError("an open PR follow-up cannot become AUDIT_NO_GO")
                digest = _task_result_digest(value, raw)
                reason = str(value.get("reason") or "").strip()
                if not reason or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
                    raise RuntimeError("AUDIT_NO_GO requires a machine-readable reason")
                store.record_stage(
                    candidate["key"],
                    "AUDIT_NO_GO",
                    evidence=value.get("evidence")
                    if isinstance(value.get("evidence"), dict)
                    else {},
                    reason=reason,
                    dedupe_key=digest,
                )
                managed_adapter.record_task_result(
                    candidate=managed_candidate, value=value, result_digest=digest
                )
                ingested.append({"key": candidate["key"], "stage": stage, "reason": reason})
            elif stage == "FIX_READY":
                if not isinstance(quality, dict):
                    raise RuntimeError("FIX_READY requires a quality object")
                if quality.get("policy_verified") is not True and controller_policy is not None:
                    value = dict(value)
                    quality = dict(quality)
                    quality["policy_verified"] = True
                    value["quality"] = quality
                    value["controllerPolicyVerification"] = controller_policy
                value, raw = _finalize_controller_commit(
                    candidate=candidate,
                    context=context,
                    value=value,
                    result_access=result_access,
                )
                quality = value.get("quality")
                assert isinstance(quality, dict)
                controller_review = controller_review_result(ROOT, value)
                controller_review_verified = bool(
                    controller_review and controller_review.get("verdict") == "PASS"
                )
                if (
                    quality.get("independent_review_passed") is not controller_review_verified
                    or value.get("independentReview") != controller_review
                ):
                    value = dict(value)
                    quality = dict(quality)
                    quality["independent_review_passed"] = controller_review_verified
                    value["quality"] = quality
                    if controller_review is None:
                        value.pop("independentReview", None)
                    else:
                        value["independentReview"] = controller_review
                    raw = _write_task_result_json_to_private(result_access, value)
                value, raw = _bind_final_reproduction_receipt(
                    candidate=candidate,
                    context=context,
                    value=value,
                    result_access=result_access,
                    managed_ledger=managed_adapter.ledger,
                )
                quality = value.get("quality")
                assert isinstance(quality, dict)
                digest = _task_result_digest(value, raw)
                publication_blocked = _publication_block_reason(context, value)
                assessment = assess_submit_ready(quality)
                if (
                    policy_followup_exhausted
                    and not publication_blocked
                    and set(assessment.missing) == {"policy_verified"}
                ):
                    publication_blocked = "REPOSITORY_POLICY_EVIDENCE_REQUIRED"
                local_policy_only = bool(
                    publication_blocked and set(assessment.missing) == {"policy_verified"}
                )
                if not assessment.ready and not local_policy_only:
                    missing = list(assessment.missing)
                    managed_adapter.record_task_result(
                        candidate=managed_candidate, value=value, result_digest=digest
                    )
                    store.record_validation_deferred(
                        candidate["key"],
                        thread_id=candidate["threadId"],
                        result_digest=digest,
                        missing=missing,
                        progress_marker=_validation_progress_marker(value),
                    )
                    store.record_stage(
                        candidate["key"],
                        "VALIDATION_PENDING",
                        evidence={
                            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
                            "missing": missing,
                            "resultDigest": digest,
                        },
                        dedupe_key=digest,
                    )
                    validation_deferred.append(
                        {
                            "key": candidate["key"],
                            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
                            "missing": missing,
                        }
                    )
                    store.record_task_result_ingested(
                        candidate["key"], digest=digest, stage="VALIDATION_PENDING"
                    )
                    ingested.append(
                        {
                            "key": candidate["key"],
                            "stage": "VALIDATION_PENDING",
                            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
                        }
                    )
                    if current_wake_digest:
                        store.record_followup_result(
                            candidate["key"],
                            wake_digest=current_wake_digest,
                            result_digest=digest,
                            stage="VALIDATION_PENDING",
                        )
                    continue
                if publication_blocked:
                    managed_adapter.record_task_result(
                        candidate=managed_candidate, value=value, result_digest=digest
                    )
                    if candidate["stage"] != "FIX_READY" or controller_policy_recoverable:
                        store.record_stage(
                            candidate["key"],
                            "FIX_READY",
                            evidence=quality | {"publication_blocked_reason": publication_blocked},
                            dedupe_key=digest,
                        )
                    ingested.append(
                        {
                            "key": candidate["key"],
                            "stage": stage,
                            "publicationBlockedReason": publication_blocked,
                        }
                    )
                else:
                    managed_result = managed_adapter.record_task_result(
                        candidate=managed_candidate, value=value, result_digest=digest
                    )
                    if managed_result.get("publicationAllowed") is not True:
                        store.record_stage(
                            candidate["key"],
                            "VALIDATION_PENDING",
                            evidence={
                                "reason": "REPRODUCTION_RECEIPT_REQUIRED",
                                "resultDigest": digest,
                            },
                            dedupe_key=digest,
                        )
                        ingested.append(
                            {
                                "key": candidate["key"],
                                "stage": "REPRODUCTION_REQUIRED",
                                "reason": "REPRODUCTION_RECEIPT_REQUIRED",
                            }
                        )
                        continue
                    if candidate["stage"] != "FIX_READY" or controller_policy_recoverable:
                        store.record_stage(
                            candidate["key"],
                            "FIX_READY",
                            evidence=quality,
                            dedupe_key=digest,
                        )
                    request = _request_publication_from_task_result(
                        store,
                        candidate=candidate,
                        result_access=result_access,
                        value=value,
                        raw=raw,
                    )
                    publication_requests.append(
                        {
                            "key": candidate["key"],
                            "requestId": request.get("request_id") or request.get("requestId"),
                            "status": request.get("status"),
                        }
                    )
                    ingested.append({"key": candidate["key"], "stage": stage})
                store.record_task_result_ingested(
                    candidate["key"], digest=digest, stage="FIX_READY"
                )
                if current_wake_digest:
                    store.record_followup_result(
                        candidate["key"],
                        wake_digest=current_wake_digest,
                        result_digest=digest,
                        stage=stage,
                    )
            elif stage in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}:
                if candidate["stage"] not in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}:
                    raise RuntimeError(
                        "published result is only valid for an existing PR continuation"
                    )
                evidence = value.get("evidence")
                if not isinstance(evidence, dict):
                    raise RuntimeError("published continuation result requires evidence")
                digest = _task_result_digest(value, raw)
                managed_adapter.record_task_result(
                    candidate=managed_candidate, value=value, result_digest=digest
                )
                store.record_task_result_ingested(candidate["key"], digest=digest, stage=stage)
                if current_wake_digest:
                    store.record_followup_result(
                        candidate["key"],
                        wake_digest=current_wake_digest,
                        result_digest=digest,
                        stage=stage,
                    )
                ingested.append({"key": candidate["key"], "stage": stage})
            else:
                raise RuntimeError("unsupported task result stage")
        except (OSError, ValueError, RuntimeError) as exc:
            candidate_failed = True
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
        finally:
            try:
                stack.close()
            except (OSError, ValueError, RuntimeError) as exc:
                if not candidate_failed:
                    errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    result = {
        "ok": not errors,
        "ingested": ingested,
        "publicationRequests": publication_requests,
        "validationDeferred": validation_deferred,
        "errors": errors,
    }
    if quarantined:
        result["quarantined"] = quarantined
    if quarantined_already_recorded:
        result["quarantinedAlreadyRecorded"] = quarantined_already_recorded
    if ignored:
        result["ignored"] = ignored
    if legacy_context_digest_migrations:
        result["legacyContextDigestMigrations"] = legacy_context_digest_migrations
    return result


def ensure_fork_remote(worktree: Path, repo: str, head_owner: str) -> str:
    repository_name = repo.rsplit("/", 1)[1]
    fork_repo = f"{head_owner}/{repository_name}"
    try:
        metadata = json.loads(command(["gh", "api", f"repos/{fork_repo}"], timeout=45))
    except RuntimeError:
        command(["gh", "repo", "fork", repo, "--clone=false"], timeout=180)
        metadata = json.loads(command(["gh", "api", f"repos/{fork_repo}"], timeout=45))
    parent = metadata.get("parent") if isinstance(metadata, dict) else None
    if not isinstance(metadata, dict) or metadata.get("fork") is not True:
        raise RuntimeError("expected publication repository is not a fork")
    if (
        not isinstance(parent, dict)
        or str(parent.get("full_name") or "").casefold() != repo.casefold()
    ):
        raise RuntimeError("existing fork does not belong to the target upstream repository")

    expected_url = f"https://github.com/{fork_repo}.git"
    remotes = command(["git", "remote"], cwd=worktree).splitlines()
    for remote in remotes:
        current = command(["git", "remote", "get-url", remote], cwd=worktree)
        if normalize_origin(current) == fork_repo.casefold():
            return remote
    remote = "radar-fork"
    if remote in remotes:
        remote = f"radar-fork-{head_owner.casefold()}"
    if remote in remotes:
        raise RuntimeError("no safe remote name is available for the publication fork")
    command(["git", "remote", "add", remote, expected_url], cwd=worktree)
    return remote


def _executor(
    operation: str,
    arguments: list[str],
    *,
    ledger_path: Path,
    runtime_root: Path | None = None,
) -> dict[str, Any]:
    if runtime_root is None:
        raise RuntimeError("--runtime-root is required for publication execution")
    binding = bind_runtime(runtime_root)
    executable = binding.script("scripts/publication_executor.py")
    python = runtime_python(runtime_root)
    prefix = ["--runtime-root", str(runtime_root.resolve())]
    completed = subprocess.run(
        [
            str(python),
            str(executable),
            "--ledger",
            str(ledger_path),
            *prefix,
            operation,
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "publication executor failed").strip()
        raise RuntimeError(detail[-500:])
    raw = completed.stdout.strip()
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError("publication executor returned an invalid result")
    return value


def _evidence_from_publication_request(request: dict[str, Any]) -> dict[str, Any]:
    value, _digest = publication_evidence_from_request(request)
    return value


def run_publication_queue(args: argparse.Namespace) -> dict[str, Any]:
    lock_path = Path(args.ledger).with_suffix(".publication.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {
                "ok": True,
                "busy": True,
                "published": [],
                "pending": [],
                "blocked": [],
                "errors": [],
            }
        return _run_publication_queue_unlocked(args)


def _run_publication_queue_unlocked(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    managed_adapter = ManagedAdapter(ROOT, args.ledger)
    published: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for item in store.publication_work_items():
        request_id = str(item["request_id"])
        request = item["request"]
        try:
            external_receipt = item.get("externalPublicationReceipt")
            if isinstance(external_receipt, dict):
                issue_url = str(request["issueUrl"])
                match = ISSUE_URL.match(issue_url)
                publication_kind = str(request.get("publicationKind") or "PR_CREATE")
                external_pr_url = str(external_receipt.get("prUrl") or "")
                if not match or (
                    publication_kind == "PR_UPDATE"
                    and external_pr_url != str(request.get("existingPrUrl") or "")
                ):
                    raise RuntimeError(
                        "external publication receipt has an invalid request binding"
                    )
                reconciled_request = dict(request) | {"requestId": request_id}
                if publication_kind != "PR_UPDATE":
                    reconciled_request["reservationKey"] = f"publication:{request_id}"
                managed_adapter.record_publication_receipt(
                    request=reconciled_request,
                    receipt=external_receipt,
                    receipt_observation=True,
                )
                head_sha = str(
                    external_receipt.get("headSha")
                    or external_receipt.get("remoteSha")
                    or request.get("commitSha")
                    or ""
                )
                store.mark_managed_publication_reconciled(
                    request_id,
                    pr_url=str(external_receipt["prUrl"]),
                    head_sha=head_sha,
                )
                published.append(
                    {
                        "requestId": request_id,
                        "key": request["opportunityKey"],
                        "prUrl": str(external_receipt["prUrl"]),
                        "pushReconciled": True,
                    }
                )
                continue
            if not external_side_effect_allowed(request):
                store.block_publication_request(request_id, "SILENT_EXPLORATION_NOT_PUBLISHABLE")
                blocked.append(
                    {"requestId": request_id, "reason": "SILENT_EXPLORATION_NOT_PUBLISHABLE"}
                )
                continue
            for action in ("push", "create_pr"):
                store.recover_failed_publication_preflight(
                    request_id,
                    action=action,
                    transient_reasons=TRANSIENT_PUBLICATION_AUDIT_REASONS,
                )
            evidence_value = _evidence_from_publication_request(request)
            controller_review = (
                controller_review_result(ROOT, evidence_value)
                if isinstance(evidence_value, dict)
                else None
            )
            if not controller_review or controller_review.get("verdict") != "PASS":
                reason = "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED"
                store.block_publication_request(request_id, reason)
                blocked.append({"requestId": request_id, "reason": reason})
                continue
            ambiguous_push = store.prepare_ambiguous_publication_effect(
                request_id,
                action="push",
            )
            if ambiguous_push and ambiguous_push.get("pending"):
                pending.append(
                    {
                        "requestId": request_id,
                        "reason": "PUBLICATION_EFFECT_STILL_ACTIVE",
                    }
                )
                continue
            recovering_push = ambiguous_push is not None
            permit = ambiguous_push.get("permit") if ambiguous_push else None
            post_push_reconciliation = False
            if permit is None:
                permit = store.prepare_post_push_reconciliation(request_id)
                post_push_reconciliation = permit is not None
            if permit is None:
                broker = broker_publication_request(store, request_id)
                if broker.get("pending"):
                    pending.append(
                        {
                            "requestId": request_id,
                            "reason": (broker.get("audit") or {}).get("reason"),
                        }
                    )
                    continue
                if not broker.get("granted"):
                    audit = broker.get("audit") or {}
                    reason = str(audit.get("reason") or "")
                    terminalized = bool(
                        request.get("publicationKind", "PR_CREATE") == "PR_CREATE"
                        and reason in TERMINAL_PUBLICATION_BLOCK_REASONS
                    )
                    if terminalized:
                        store.record_stage(
                            str(request["opportunityKey"]),
                            "AUDIT_NO_GO",
                            evidence={"publicationAudit": audit},
                            reason=reason,
                            dedupe_key=f"publication-terminal:{request_id}:{reason}",
                        )
                    blocked.append(
                        {
                            "requestId": request_id,
                            "reason": reason,
                            **({"terminalized": True} if terminalized else {}),
                        }
                    )
                    continue
                permit = broker["permit"]
            publication = request["publication"]
            issue_url = str(request["issueUrl"])
            match = ISSUE_URL.match(issue_url)
            if not match:
                raise RuntimeError("publication request contains an invalid issue URL")
            repo = match.group(1)
            if request.get("publicationKind") != "PR_UPDATE":
                reservation = managed_adapter.reserve_publication(
                    request_id=request_id,
                    repo=repo,
                    head_ref=str(request.get("branch") or "") or None,
                    head_sha=str(request.get("commitSha") or "") or None,
                    opportunity_key=str(request.get("opportunityKey") or "") or None,
                    invitation_event_key=str(request.get("invitationEventKey") or "") or None,
                )
                if not reservation.get("allowed"):
                    if reservation.get("absenceRequired"):
                        recovery = managed_adapter.reconcile_publication_absence(
                            reservation_key=reservation["reservationKey"],
                            repo=repo,
                            head_ref=str(request.get("branch") or ""),
                            head_sha=str(request.get("commitSha") or ""),
                            github_client=GitHubAbsenceQueries(GitHubClient()),
                        )
                        if recovery.get("released"):
                            reservation = managed_adapter.reserve_publication(
                                request_id=request_id,
                                repo=repo,
                                head_ref=str(request.get("branch") or "") or None,
                                head_sha=str(request.get("commitSha") or "") or None,
                                opportunity_key=str(request.get("opportunityKey") or "") or None,
                                invitation_event_key=str(request.get("invitationEventKey") or "")
                                or None,
                            )
                        else:
                            reason = str(recovery.get("reason") or "WAITING_EXTERNAL")
                            store.block_publication_request(request_id, reason)
                            blocked.append({"requestId": request_id, "reason": reason})
                            continue
                if not reservation.get("allowed"):
                    reason = str(reservation.get("reason") or "BLOCKED_PRE_TASK")
                    store.block_publication_request(request_id, reason)
                    blocked.append({"requestId": request_id, "reason": reason})
                    continue
                request = dict(request) | {"reservationKey": reservation["reservationKey"]}
                reconciled = managed_adapter.reconcile_publication(
                    reservation_key=reservation["reservationKey"],
                    repo=repo,
                    head_sha=str(request.get("commitSha") or ""),
                )
                if reconciled and reconciled.get("pr_url"):
                    published.append(
                        {
                            "requestId": request_id,
                            "key": request["opportunityKey"],
                            "prUrl": reconciled["pr_url"],
                            "pushReconciled": True,
                        }
                    )
                    continue
            worktree = Path(request["worktreePath"]).resolve()
            head_owner = str(publication["headOwner"])
            common = [
                "--permit-id",
                str(permit["permit_id"]),
                "--issue-url",
                issue_url,
                "--worktree",
                str(worktree),
                "--commit-sha",
                str(request["commitSha"]),
                "--branch",
                str(request["branch"]),
                "--head-owner",
                head_owner,
            ]
            executor_kwargs = {"ledger_path": args.ledger}
            if getattr(args, "runtime_root", None) is not None:
                executor_kwargs["runtime_root"] = args.runtime_root
            push_result = (
                {"reconciled": True}
                if post_push_reconciliation
                else _executor(
                    "push",
                    [*common, "--remote", ensure_fork_remote(worktree, repo, head_owner)],
                    **executor_kwargs,
                )
            )
            if push_result.get("pending"):
                pending.append(
                    {
                        "requestId": request_id,
                        "reason": push_result.get("reason"),
                    }
                )
                continue
            if push_result.get("blocked"):
                blocked.append(
                    {
                        "requestId": request_id,
                        "reason": push_result.get("reason"),
                    }
                )
                continue
            if recovering_push:
                reconciled_permit = store.prepare_post_push_reconciliation(request_id)
                if reconciled_permit is None:
                    raise RuntimeError("reconciled push did not reactivate PR confirmation")
                permit = reconciled_permit
            pr_result = _executor(
                "create-pr",
                [
                    *common,
                    "--repo",
                    repo,
                    "--base",
                    str(publication["baseBranch"]),
                    "--title",
                    str(publication["title"]),
                    "--body-file",
                    str(publication["bodyPath"]),
                ],
                **executor_kwargs,
            )
            if pr_result.get("pending"):
                pending.append(
                    {
                        "requestId": request_id,
                        "reason": pr_result.get("reason"),
                    }
                )
                continue
            if pr_result.get("blocked"):
                blocked.append(
                    {
                        "requestId": request_id,
                        "reason": pr_result.get("reason"),
                    }
                )
                continue
            managed_adapter.record_publication_receipt(
                request=request | {"requestId": request_id},
                receipt=pr_result,
            )
            published.append(
                {
                    "requestId": request_id,
                    "key": request["opportunityKey"],
                    "prUrl": pr_result.get("prUrl"),
                    "pushReconciled": push_result.get("reconciled", False),
                }
            )
        except PermissionError as exc:
            blocked.append(
                {
                    "requestId": request_id,
                    "reason": "ACTIVE_TASK_QUARANTINE",
                    "detail": str(exc)[:240],
                }
            )
            continue
        except (KeyError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"requestId": request_id, "error": str(exc)[:400]})
    return {
        "ok": not errors,
        "published": published,
        "pending": pending,
        "blocked": blocked,
        "errors": errors,
    }


def enqueue_local_receipts(path: Path = LEDGER_PATH) -> dict[str, Any]:
    """Register local result files without recovering worktrees or running Git.

    The fast lane only creates this durable handoff. Full result validation and
    any controller-owned commit reconciliation remain slow-worker operations.
    """

    queue_path = path.parent / "local-receipt-queue.json"
    previous = read_json(queue_path, missing={})
    entries = dict(previous.get("entries") or {}) if isinstance(previous, dict) else {}
    store = RadarLedger(path, read_only=True)
    queued: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    try:
        candidates = store.local_receipt_candidates()
    except sqlite3.OperationalError as exc:
        error_code = getattr(exc, "sqlite_errorcode", None)
        base_error_code = error_code & 0xFF if isinstance(error_code, int) else None
        detail = str(exc).strip().lower()
        is_contention = base_error_code in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        } or detail in {
            "database is busy",
            "database is locked",
            "database table is locked",
            "database schema is locked",
        }
        if is_contention:
            return {
                "ok": True,
                "deferred": True,
                "deferredReason": "LEDGER_BUSY",
                "queued": [],
                "rejected": [],
                "count": len(entries),
                "scope": "local_receipt_registration_only",
            }
        raise
    for candidate in candidates:
        try:
            result = _read_task_result_bytes_if_present(candidate)
            if result is None:
                continue
            result_path, raw = result
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise RuntimeError("task result must be an object")
            for field in ("schemaVersion", "key", "issueUrl", "threadId", "worktreePath"):
                if field not in value:
                    raise RuntimeError(f"task result missing {field}")
            digest = hashlib.sha256(raw).hexdigest()
            item = {
                "key": str(candidate["key"]),
                "path": str(result_path),
                "digest": digest,
                "stage": str(value.get("stage") or ""),
                "queuedAt": iso_z(datetime.now(UTC)),
            }
            existing = entries.get(item["key"])
            if not isinstance(existing, dict) or existing.get("digest") != digest:
                entries[item["key"]] = item
                queued.append(item)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            rejected.append({"key": str(candidate["key"]), "error": str(exc)[:240]})
    atomic_write_json(queue_path, {"schemaVersion": "local_receipt_queue_v1", "entries": entries})
    return {
        "ok": not rejected,
        "queued": queued,
        "rejected": rejected,
        "count": len(entries),
        "scope": "local_receipt_registration_only",
    }


def record_outcome(args: argparse.Namespace) -> dict[str, Any]:
    if args.evidence_file:
        payload = json.loads(Path(args.evidence_file).read_text(encoding="utf-8"))
        evidence = payload.get("quality") if isinstance(payload, dict) else None
        if not isinstance(evidence, dict):
            raise RuntimeError("evidence file must contain a quality object")
    else:
        evidence = json.loads(args.evidence_json) if args.evidence_json else {}
    store = ledger(args.ledger)
    if args.stage == "FIX_READY":
        assessment = assess_submit_ready(evidence)
        if not assessment.ready:
            raise RuntimeError(f"submit-ready evidence missing: {','.join(assessment.missing)}")
    store.record_stage(
        args.key,
        args.stage,
        evidence=evidence,
        reason=args.reason,
        dedupe_key=args.dedupe_key,
    )
    return {"ok": True, "key": args.key, "stage": args.stage}


def submit_publication_request(args: argparse.Namespace) -> dict[str, Any]:
    return request_publication(
        ledger(args.ledger),
        issue_url=args.issue_url,
        thread_id=args.thread_id,
        worktree=Path(args.worktree),
        evidence_path=Path(args.evidence_file),
    )


def publication_check(args: argparse.Namespace) -> dict[str, Any]:
    try:
        permit = ledger(args.ledger).publication_permit(
            issue_url=args.issue_url,
            commit_sha=args.commit_sha,
            branch=args.branch,
        )
    except PermissionError as exc:
        return {
            "ok": False,
            "blocked": "ACTIVE_TASK_QUARANTINE",
            "reason": str(exc)[:240],
            "permitId": None,
            "expiresAt": None,
        }
    return {
        "ok": permit is not None,
        "permitId": permit.get("permit_id") if permit else None,
        "expiresAt": permit.get("expires_at") if permit else None,
    }


def retry_blocked_publication(args: argparse.Namespace) -> dict[str, Any]:
    result = ledger(args.ledger).retry_blocked_publication_request(
        args.request_id,
        expected_reason=args.expected_reason,
    )
    return {"ok": True, **result}


def restore_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    target_thread_id = str(getattr(args, "thread_id", "") or "")
    if target_thread_id:
        bindings = (
            store.restorable_task_bindings()
            if hasattr(store, "restorable_task_bindings")
            else store.restore_candidates()
        )
        bindings = [item for item in bindings if item["threadId"] == target_thread_id]
        if not bindings:
            return {
                "ok": False,
                "restore": [],
                "reconciled": [],
                "blocked": [
                    {
                        "threadId": target_thread_id,
                        "reason": "restore_target_not_authorized",
                    }
                ],
            }
    else:
        bindings = store.restore_candidates()
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    pending: list[dict[str, Any]] = []
    reconciled: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    try:
        for candidate in bindings:
            ledger_archived = (
                candidate.get("lifecycleState", "THREAD_ARCHIVED") == "THREAD_ARCHIVED"
            )
            row = connection.execute(
                "SELECT archived,title FROM threads WHERE id=?",
                (candidate["threadId"],),
            ).fetchone()
            if row is None:
                if ledger_archived or target_thread_id:
                    blocked.append(candidate | {"reason": "thread_missing"})
                continue
            if int(row["archived"] or 0) == 0:
                if ledger_archived:
                    store.commit_restore(
                        thread_id=candidate["threadId"],
                        nonce=candidate["restoreNonce"],
                    )
                    reconciled.append(candidate | {"title": row["title"]})
                continue
            pending.append(
                candidate
                | {
                    "title": row["title"],
                    "reason": (
                        "ledger_archive_pending_restore"
                        if ledger_archived
                        else "desktop_archive_drift"
                    ),
                }
            )
    finally:
        connection.close()
    return {
        "ok": not blocked,
        "restore": pending,
        "reconciled": reconciled,
        "blocked": blocked,
    }


def restore_commit(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    bindings = (
        store.restorable_task_bindings()
        if hasattr(store, "restorable_task_bindings")
        else store.restore_candidates()
    )
    candidates = {item["threadId"]: item for item in bindings}
    candidate = candidates.get(args.thread_id)
    if candidate is None or candidate["restoreNonce"] != args.restore_nonce:
        raise RuntimeError("restore authorization is stale or invalid")
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT archived FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[0] or 0) != 0:
        raise RuntimeError("thread is still archived")
    store.commit_restore(
        thread_id=args.thread_id,
        nonce=args.restore_nonce,
    )
    return {"ok": True, "threadId": args.thread_id}


def cleanup_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    reconciliation_candidates = getattr(store, "cleanup_reconciliation_candidates", None)
    candidates = (
        reconciliation_candidates()
        if callable(reconciliation_candidates)
        else store.cleanup_candidates()
    )
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    pending: list[dict[str, Any]] = []
    try:
        for candidate in candidates:
            row = connection.execute(
                "SELECT archived,title FROM threads WHERE id=?",
                (candidate["threadId"],),
            ).fetchone()
            if row is None:
                continue
            if int(row["archived"] or 0) == 1:
                commit_reconciled = getattr(store, "commit_reconciled_cleanup", None)
                commit = commit_reconciled if callable(commit_reconciled) else store.commit_cleanup
                commit(
                    thread_id=candidate["threadId"],
                    nonce=candidate["cleanupNonce"],
                )
                if candidate.get("worktreePath") and _is_managed_worktree(
                    Path(candidate["worktreePath"])
                ):
                    shared_context_path(candidate["issueUrl"]).unlink(missing_ok=True)
                continue
            if candidate.get("titleSyncedState") not in {None, "AUDIT_NO_GO"}:
                continue
            pending.append(candidate | {"title": row["title"]})
    finally:
        connection.close()
    return {"ok": True, "cleanup": pending}


def cleanup_commit(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidates = {item["threadId"]: item for item in store.cleanup_candidates()}
    candidate = candidates.get(args.thread_id)
    if candidate is None or candidate["cleanupNonce"] != args.cleanup_nonce:
        raise RuntimeError("cleanup authorization is stale or invalid")
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT archived FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[0] or 0) != 1:
        raise RuntimeError("thread is not archived")
    store.commit_cleanup(
        thread_id=args.thread_id,
        nonce=args.cleanup_nonce,
    )
    if candidate.get("worktreePath") and _is_managed_worktree(Path(candidate["worktreePath"])):
        shared_context_path(candidate["issueUrl"]).unlink(missing_ok=True)
    return {"ok": True, "threadId": args.thread_id}


def _apply_desktop_thread_requests(
    items: list[dict[str, Any]],
    *,
    method: str,
    parameter_builder: Callable[[dict[str, Any]], dict[str, Any]],
    operation_label: str,
    timeout_seconds: float = 20.0,
) -> dict[str, str | None]:
    """Apply one supported app-server operation to exact desktop tasks."""

    results = {str(item["threadId"]): "app_server_response_missing" for item in items}
    if not items:
        return results
    executable = shutil.which("codex")
    if not executable:
        return {thread_id: "codex_executable_missing" for thread_id in results}
    process = subprocess.Popen(
        [
            executable,
            "app-server",
            "--disable",
            "recommended_plugins",
            "--disable",
            "remote_plugin",
            "--stdio",
        ],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    request_items = {index: item for index, item in enumerate(items, 1)}
    request_ids = {index: str(item["threadId"]) for index, item in request_items.items()}
    try:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("app server pipes are unavailable")
        requests = [
            {
                "id": 0,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "oss-pr-radar", "version": "1.0"},
                    "capabilities": {"experimentalApi": True},
                },
            },
            *[
                {
                    "id": request_id,
                    "method": method,
                    "params": parameter_builder(request_items[request_id]),
                }
                for request_id in request_ids
            ],
        ]
        process.stdin.write(
            b"".join(
                (json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8")
                for request in requests
            )
        )
        process.stdin.flush()

        pending = {0, *request_ids}
        buffer = b""
        deadline = monotonic() + max(1.0, timeout_seconds)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while pending and monotonic() < deadline:
                ready = selector.select(max(0.0, deadline - monotonic()))
                if not ready:
                    break
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    try:
                        response = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if not isinstance(response, dict):
                        continue
                    response_id = response.get("id")
                    if response_id not in pending:
                        continue
                    pending.remove(response_id)
                    if response_id == 0:
                        if response.get("error"):
                            raise RuntimeError("app server initialization failed")
                        continue
                    thread_id = request_ids[response_id]
                    results[thread_id] = (
                        f"app_server_{operation_label}_failed" if response.get("error") else None
                    )
        if 0 in pending:
            return {thread_id: "app_server_initialization_timeout" for thread_id in results}
        for request_id in pending:
            if request_id in request_ids:
                results[request_ids[request_id]] = f"app_server_{operation_label}_timeout"
        return results
    except (OSError, RuntimeError, ValueError) as exc:
        reason = f"{type(exc).__name__}:{str(exc)[:160]}"
        return {
            thread_id: (current if current is None else reason)
            for thread_id, current in results.items()
        }
    finally:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _archive_desktop_threads(
    candidates: list[dict[str, Any]], *, timeout_seconds: float = 20.0
) -> dict[str, str | None]:
    """Archive exact lifecycle candidates through the supported app-server API."""

    return _apply_desktop_thread_requests(
        candidates,
        method="thread/archive",
        parameter_builder=lambda item: {"threadId": str(item["threadId"])},
        operation_label="archive",
        timeout_seconds=timeout_seconds,
    )


def _unarchive_desktop_threads(
    candidates: list[dict[str, Any]], *, timeout_seconds: float = 20.0
) -> dict[str, str | None]:
    """Unarchive exact valuable lifecycle tasks through the supported app-server API."""

    return _apply_desktop_thread_requests(
        candidates,
        method="thread/unarchive",
        parameter_builder=lambda item: {"threadId": str(item["threadId"])},
        operation_label="unarchive",
        timeout_seconds=timeout_seconds,
    )


def restore_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    state = restore_list(args)
    candidates = list(state.get("restore") or [])
    apply_results = _unarchive_desktop_threads(candidates)
    restored: list[dict[str, Any]] = list(state.get("reconciled") or [])
    errors: list[dict[str, Any]] = list(state.get("blocked") or [])
    for candidate in candidates:
        thread_id = str(candidate["threadId"])
        apply_error = apply_results.get(thread_id)
        try:
            committed = restore_commit(
                argparse.Namespace(
                    ledger=args.ledger,
                    thread_id=thread_id,
                    restore_nonce=candidate["restoreNonce"],
                )
            )
            restored.append({"key": candidate.get("key"), **committed})
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(
                {
                    "key": candidate.get("key"),
                    "threadId": thread_id,
                    "error": apply_error or f"{type(exc).__name__}:{str(exc)[:160]}",
                }
            )
    return {"ok": not errors, "restored": restored, "errors": errors}


def cleanup_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    candidates = cleanup_list(args)["cleanup"]
    eligible: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.get("stage") != "AUDIT_NO_GO" or not str(
            candidate.get("title") or ""
        ).startswith(f"{TITLE_PREFIXES['AUDIT_NO_GO']} "):
            errors.append(
                {
                    "key": candidate.get("key"),
                    "threadId": candidate.get("threadId"),
                    "error": "cleanup_title_not_reconciled",
                }
            )
            continue
        eligible.append(candidate)

    apply_results = _archive_desktop_threads(eligible)
    archived: list[dict[str, Any]] = []
    for candidate in eligible:
        thread_id = str(candidate["threadId"])
        apply_error = apply_results.get(thread_id)
        if apply_error:
            errors.append(
                {
                    "key": candidate["key"],
                    "threadId": thread_id,
                    "error": apply_error,
                }
            )
            continue
        try:
            committed = cleanup_commit(
                argparse.Namespace(
                    ledger=args.ledger,
                    thread_id=thread_id,
                    cleanup_nonce=candidate["cleanupNonce"],
                )
            )
            archived.append({"key": candidate["key"], **committed})
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(
                {
                    "key": candidate["key"],
                    "threadId": thread_id,
                    "error": f"{type(exc).__name__}:{str(exc)[:160]}",
                }
            )
    return {"ok": not errors, "archived": archived, "errors": errors}


def title_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    bindings = store.title_bindings()
    thread_ids = [str(item["threadId"]) for item in bindings]
    current: dict[str, tuple[str, int]] = {}
    if thread_ids:
        connection = sqlite3.connect(THREAD_DB)
        try:
            placeholders = ",".join("?" for _ in thread_ids)
            rows = connection.execute(
                f"SELECT id,title,archived FROM threads WHERE id IN ({placeholders})",
                thread_ids,
            ).fetchall()
            current = {str(row[0]): (str(row[1] or ""), int(row[2] or 0)) for row in rows}
        finally:
            connection.close()
    for binding in bindings:
        title_time = str(binding.get("titleTime") or "")
        actual = current.get(str(binding["threadId"]))
        if not title_time or actual is None or actual[1] != 0:
            continue
        desired = lifecycle_title(
            binding["titleState"], title_time, binding["key"], binding["title"]
        )
        if actual[0] != desired and binding["titleSyncedState"] == binding["titleState"]:
            store.invalidate_title_sync(
                thread_id=binding["threadId"],
                state=binding["titleState"],
                actual_title_digest=hashlib.sha256(actual[0].encode("utf-8")).hexdigest(),
            )
    values = []
    for candidate in store.title_candidates():
        if not candidate.get("titleTime"):
            continue
        actual = current.get(str(candidate["threadId"]))
        if actual is None or actual[1] != 0:
            continue
        values.append(
            candidate
            | {
                "desiredTitle": lifecycle_title(
                    candidate["titleState"],
                    candidate["titleTime"],
                    candidate["key"],
                    candidate["title"],
                )
            }
        )
    return {"ok": True, "titles": values}


def title_commit(args: argparse.Namespace) -> dict[str, Any]:
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT title,archived FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[1] or 0) != 0 or row[0] != args.desired_title:
        raise RuntimeError("thread title was not applied")
    ledger(args.ledger).commit_title(
        thread_id=args.thread_id,
        state=args.title_state,
        nonce=args.title_nonce,
    )
    return {"ok": True, "threadId": args.thread_id, "title": args.desired_title}


def _set_desktop_thread_titles(
    titles: list[dict[str, Any]], *, timeout_seconds: float = 20.0
) -> dict[str, str | None]:
    """Apply lifecycle titles through the supported local app-server protocol."""

    return _apply_desktop_thread_requests(
        titles,
        method="thread/name/set",
        parameter_builder=lambda item: {
            "threadId": str(item["threadId"]),
            "name": str(item["desiredTitle"]),
        },
        operation_label="title_update",
        timeout_seconds=timeout_seconds,
    )


def _ensure_desktop_thread_title(thread_id: str, desired_title: str) -> None:
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT title,archived FROM threads WHERE id=?", (thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[1] or 0) != 0:
        raise RuntimeError("thread is missing or archived")
    if row[0] != desired_title:
        result = _set_desktop_thread_titles(
            [{"threadId": thread_id, "desiredTitle": desired_title}]
        )
        apply_error = result.get(thread_id)
        connection = sqlite3.connect(THREAD_DB)
        try:
            row = connection.execute(
                "SELECT title,archived FROM threads WHERE id=?", (thread_id,)
            ).fetchone()
        finally:
            connection.close()
        if row is None or int(row[1] or 0) != 0 or row[0] != desired_title:
            raise RuntimeError(apply_error or "thread title was not applied")


def title_reconcile(args: argparse.Namespace) -> dict[str, Any]:
    candidates = title_list(args)["titles"]
    if not candidates:
        return {"ok": True, "renamed": [], "errors": []}
    apply_results = _set_desktop_thread_titles(candidates)
    renamed: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for candidate in candidates:
        thread_id = str(candidate["threadId"])
        try:
            committed = title_commit(
                argparse.Namespace(
                    ledger=args.ledger,
                    thread_id=thread_id,
                    title_state=candidate["titleState"],
                    title_nonce=candidate["titleNonce"],
                    desired_title=candidate["desiredTitle"],
                )
            )
            renamed.append({"key": candidate["key"], **committed})
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(
                {
                    "key": candidate["key"],
                    "threadId": thread_id,
                    "error": apply_results.get(thread_id)
                    or f"{type(exc).__name__}:{str(exc)[:160]}",
                }
            )
    return {"ok": not errors, "renamed": renamed, "errors": errors}


def pr_lifecycle_stage(value: dict[str, Any]) -> str:
    if value.get("mergedAt") or str(value.get("state") or "").upper() == "MERGED":
        return "MERGED"
    if str(value.get("state") or "").upper() == "CLOSED":
        return "CLOSED"
    if value.get("isDraft") is True:
        return "PR_OPEN"
    if str(value.get("reviewDecision") or "").upper() == "APPROVED":
        return "MAINTAINER_ACCEPTED"
    checks = [item for item in value.get("statusCheckRollup") or [] if isinstance(item, dict)]
    if checks:
        conclusions = {
            str(item.get("conclusion") or item.get("state") or "").upper() for item in checks
        }
        if conclusions and conclusions <= {"SUCCESS", "NEUTRAL", "SKIPPED"}:
            return "CI_GREEN"
    return "PR_OPEN"


def should_apply_pr_lifecycle_stage(current: str, remote: str, *, is_draft: bool = False) -> bool:
    """Keep local validation/update work authoritative until the PR is terminal."""
    if remote in TERMINAL_PR_STAGES:
        return current != remote
    if current in LOCAL_PR_ACTION_STAGES:
        return False
    if is_draft and remote == "PR_OPEN":
        return current in {"CI_GREEN", "MAINTAINER_ACCEPTED"}
    return PR_STAGE_PRIORITY[remote] > PR_STAGE_PRIORITY.get(current, -1)


def refresh_pull_requests(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    updates = []
    errors = []
    for item in store.tracked_pull_requests():
        try:
            value = json.loads(
                command(
                    [
                        "gh",
                        "pr",
                        "view",
                        item["pr_url"],
                        "--json",
                        "state,isDraft,mergedAt,reviewDecision,statusCheckRollup,url",
                    ],
                    timeout=45,
                )
            )
        except (RuntimeError, json.JSONDecodeError) as exc:
            errors.append({"key": item["key"], "error": str(exc)[:200]})
            continue
        stage = pr_lifecycle_stage(value)
        if should_apply_pr_lifecycle_stage(
            str(item["stage"]), stage, is_draft=value.get("isDraft") is True
        ):
            store.record_stage(
                item["key"],
                stage,
                evidence={"prUrl": item["pr_url"], "remote": value},
                dedupe_key=f"{stage}:{item['pr_url']}",
            )
            updates.append({"key": item["key"], "stage": stage, "prUrl": item["pr_url"]})
    return {"ok": not errors, "updates": updates, "errors": errors}


def recovery_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    quarantined_reader = getattr(store, "quarantined_validation_followups", lambda: [])
    quarantined = list(quarantined_reader())
    unresolved = store.unresolved_recoveries()
    if not THREAD_DB.is_file():
        # A fresh machine may not have a Codex thread database yet.  Recovery
        # cannot be authorized without it, but this must remain a normal
        # fail-closed state rather than crashing the controller.
        blocked = [
            item | {"reason": "THREAD_DB_UNAVAILABLE"}
            for item in store.recovery_candidates(min_age_minutes=0)
        ]
        unresolved_with_recovery = [
            item
            | {
                "reason": "THREAD_DB_UNAVAILABLE",
                "threadActivityAvailable": False,
                "targetTurnMaterialized": False,
                "commitReady": False,
                "abandonable": False,
            }
            for item in unresolved
        ]
        return {
            "ok": not blocked and not unresolved_with_recovery,
            "recoverable": [],
            "activeDeferred": [],
            "queuedDeferred": [],
            "blocked": blocked,
            "unresolved": unresolved_with_recovery,
            "quarantined": quarantined,
        }
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    recoverable: list[dict[str, Any]] = []
    active_deferred: list[dict[str, Any]] = []
    queued_deferred: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    activity_cutoff = int(
        (datetime.now(UTC) - timedelta(minutes=max(30, args.min_age_minutes))).timestamp()
    )
    try:
        candidates = store.recovery_candidates(
            min_age_minutes=0,
            include_exhausted_dispatched=True,
        )
        candidate_thread_ids = {item["threadId"] for item in candidates}
        context_candidates = getattr(store, "task_context_candidates", lambda: [])()
        probe_thread_ids: set[str] = set()
        for thread_id in candidate_thread_ids | {
            str(item.get("threadId") or "") for item in context_candidates
        }:
            if not thread_id:
                continue
            row = connection.execute(
                "SELECT updated_at,rollout_path FROM threads WHERE id=?", (thread_id,)
            ).fetchone()
            if (
                row is not None
                and latest_thread_turn_state(row["rollout_path"]) is None
                and active_task_turn_worker(thread_id) is None
                and (
                    thread_id in candidate_thread_ids
                    or int(row["updated_at"] or 0) > activity_cutoff
                )
            ):
                probe_thread_ids.add(thread_id)
        live_turn_states = live_thread_turn_states(probe_thread_ids)
        for task in context_candidates:
            thread_id = str(task.get("threadId") or "")
            if not thread_id or thread_id in candidate_thread_ids:
                continue
            row = connection.execute(
                "SELECT archived,title,updated_at,rollout_path FROM threads WHERE id=?",
                (thread_id,),
            ).fetchone()
            if (
                row is None
                or int(row["archived"] or 0) == 1
                or int(row["updated_at"] or 0) <= activity_cutoff
                or (
                    latest_thread_turn_state(row["rollout_path"]) or live_turn_states.get(thread_id)
                )
                is not None
            ):
                continue
            active_deferred.append(
                {
                    "key": task["key"],
                    "issueUrl": task["issueUrl"],
                    "threadId": thread_id,
                    "worktreePath": task["worktreePath"],
                    "currentTitle": row["title"],
                    "threadUpdatedAt": row["updated_at"],
                    "reason": "recovery_turn_in_progress",
                }
            )
        for candidate in candidates:
            row = connection.execute(
                "SELECT archived,title,first_user_message,cwd,git_origin_url,updated_at,"
                "rollout_path "
                "FROM threads WHERE id=?",
                (candidate["threadId"],),
            ).fetchone()
            if row is None:
                blocked.append(candidate | {"reason": "thread_missing"})
                continue
            if int(row["archived"] or 0) == 1:
                blocked.append(candidate | {"reason": "thread_archived"})
                continue
            if canonical_prompt(row["first_user_message"] or "") != issue_prompt(
                candidate["issueUrl"]
            ):
                blocked.append(candidate | {"reason": "thread_prompt_mismatch"})
                continue
            expected_repo = candidate["key"].rsplit("#", 1)[0].casefold()
            worktree = Path(candidate["worktreePath"]).resolve()
            thread_cwd = Path(row["cwd"]).resolve()
            managed = _is_managed_worktree(worktree)
            if managed:
                valid_origin = False
                try:
                    valid_origin = (
                        normalize_origin(
                            command(["git", "remote", "get-url", "origin"], cwd=worktree)
                        )
                        == expected_repo
                    )
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    pass
                valid_workspace = thread_cwd == GITHUB_ROOT.resolve() and valid_origin
            else:
                valid_workspace = (
                    thread_cwd == worktree
                    and normalize_origin(row["git_origin_url"] or "") == expected_repo
                )
            if not valid_workspace:
                blocked.append(candidate | {"reason": "thread_origin_mismatch"})
                continue
            turn_state = latest_thread_turn_state(row["rollout_path"]) or live_turn_states.get(
                candidate["threadId"]
            )
            terminal_error = (
                turn_state
                if turn_state and turn_state.get("status") in {"failed", "interrupted"}
                else None
            )
            if candidate.get("recoveryKind") == "DISPATCHED_TASK":
                recovery_prompt = _recovery_turn_prompt(candidate, terminal_error)
                prompt_version, prompt_digest = _dispatched_recovery_prompt_binding(recovery_prompt)
                bound_candidate = bind_dispatched_recovery_prompt(
                    candidate,
                    prompt_version=prompt_version,
                    prompt_digest=prompt_digest,
                )
                if bound_candidate is None:
                    continue
                candidate = bound_candidate
            completed_validation_without_result = False
            if (
                candidate.get("recoveryKind") == "VALIDATION_FOLLOWUP_RESULT"
                and turn_state
                and turn_state.get("status") == "completed"
                and int(row["updated_at"] or 0)
                >= int(parse_time(str(candidate["dispatchedAt"])).timestamp())
            ):
                try:
                    completed_validation_without_result = hashlib.sha256(
                        _read_controlled_validation_result(candidate)
                    ).hexdigest() == str(candidate.get("followupDigest") or "")
                except (OSError, RuntimeError):
                    completed_validation_without_result = False
            immediate_recovery = (
                _is_immediate_recovery(turn_state) or completed_validation_without_result
            )
            turn_worker = (
                active_task_turn_worker(candidate["threadId"]) if immediate_recovery else None
            )
            if turn_worker is not None:
                active_deferred.append(
                    candidate
                    | {
                        "currentTitle": row["title"],
                        "threadUpdatedAt": row["updated_at"],
                        "terminalError": terminal_error,
                        "worker": turn_worker,
                        "reason": "terminal_turn_worker_draining",
                    }
                )
                continue
            if turn_state is None and int(row["updated_at"] or 0) > activity_cutoff:
                active_deferred.append(
                    candidate
                    | {
                        "currentTitle": row["title"],
                        "threadUpdatedAt": row["updated_at"],
                        "reason": "thread_recently_active",
                    }
                )
                continue
            if (
                candidate.get("recoveryKind") == "VALIDATION_FOLLOWUP_RESULT"
                and not immediate_recovery
            ):
                continue
            if int(row["updated_at"] or 0) > activity_cutoff and not immediate_recovery:
                continue
            eligible = candidate | {
                "currentTitle": row["title"],
                "cwd": row["cwd"],
                "threadUpdatedAt": row["updated_at"],
                "terminalError": terminal_error,
                "immediateRecovery": immediate_recovery,
                "completionWithoutResult": completed_validation_without_result,
            }
            if active_deferred or recoverable:
                queued_deferred.append(eligible | {"reason": "serialized_recovery_queue"})
            else:
                recoverable.append(eligible)
    finally:
        connection.close()
    if active_deferred and recoverable:
        queued_deferred = [
            item | {"reason": "serialized_recovery_queue"} for item in recoverable
        ] + queued_deferred
        recoverable = []
    now = datetime.now(UTC)
    unresolved_with_recovery: list[dict[str, Any]] = []
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    try:
        for item in unresolved:
            row = connection.execute(
                "SELECT rollout_path,updated_at FROM threads WHERE id=?",
                (item["threadId"],),
            ).fetchone()
            age_minutes = max(
                0,
                int((now - parse_time(str(item["reservedAt"]))).total_seconds() // 60),
            )
            handoff = _desktop_task_handoff(
                delivery_kind="recovery",
                candidate=item,
                delivery_token=str(item.get("recoveryNonce") or ""),
            )
            activity_available, materialized = thread_prompt_materialized_after(
                row["rollout_path"] if row else None,
                str(item["reservedAt"]),
                str(handoff["prompt"]),
            )
            value = item | {
                "ageMinutes": age_minutes,
                "threadUpdatedAt": int(row["updated_at"] or 0) if row else 0,
                "threadActivityAvailable": activity_available,
                "targetTurnMaterialized": materialized,
                "commitReady": materialized,
                "abandonable": False,
            }
            if not materialized:
                retry = retryable_negative_task_turn_receipt(
                    delivery_kind="recovery",
                    thread_id=str(item.get("threadId") or ""),
                    delivery_token=str(item.get("recoveryNonce") or ""),
                )
                if retry:
                    value |= retry
                    if retry.get("desktopHandoffRequired"):
                        value["desktopHandoff"] = _desktop_task_handoff(
                            delivery_kind="recovery",
                            candidate=item,
                            delivery_token=str(item.get("recoveryNonce") or ""),
                        )
            unresolved_with_recovery.append(value)
    finally:
        connection.close()
    if unresolved:
        queued_deferred = [
            item | {"reason": "recovery_delivery_unresolved"}
            for item in recoverable + queued_deferred
        ]
        recoverable = []
    return {
        "ok": not blocked and not unresolved,
        "recoverable": recoverable,
        "activeDeferred": active_deferred,
        "queuedDeferred": queued_deferred,
        "blocked": blocked,
        "unresolved": unresolved_with_recovery,
        "quarantined": quarantined,
    }


def recovery_reserve(args: argparse.Namespace) -> dict[str, Any]:
    probe = recovery_list(argparse.Namespace(ledger=args.ledger, min_age_minutes=0))
    authorized = {item["threadId"]: item for item in probe["recoverable"]}.get(args.thread_id)
    if (
        not probe["ok"]
        or authorized is None
        or authorized.get("recoveryNonce") != args.recovery_nonce
    ):
        raise RuntimeError("recovery is not the current serialized candidate")
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT rollout_path FROM threads WHERE id=?", (authorized["threadId"],)
        ).fetchone()
    finally:
        connection.close()
    terminal_error = authorized.get("terminalError") or latest_terminal_thread_error(
        row[0] if row else None
    )
    prompt = _recovery_turn_prompt(authorized, terminal_error)
    reserve_kwargs: dict[str, Any] = {
        "thread_id": args.thread_id,
        "nonce": args.recovery_nonce,
    }
    if authorized.get("recoveryKind") == "DISPATCHED_TASK":
        prompt_version, prompt_digest = _dispatched_recovery_prompt_binding(prompt)
        if (
            authorized.get("recoveryPromptVersion") != prompt_version
            or authorized.get("recoveryPromptDigest") != prompt_digest
        ):
            raise RuntimeError("recovery prompt authorization is stale")
        reserve_kwargs.update(
            {
                "recovery_prompt_version": prompt_version,
                "recovery_prompt_digest": prompt_digest,
            }
        )
    candidate = ledger(args.ledger).reserve_recovery(**reserve_kwargs)
    if candidate.get("recoveryKind") == "DISPATCHED_TASK":
        _verify_dispatched_recovery_prompt_binding(candidate, prompt)
    return {
        "ok": True,
        "threadId": candidate["threadId"],
        "prompt": prompt,
        "recoveryNonce": candidate["recoveryNonce"],
        "terminalError": terminal_error,
        **(
            {
                "recoveryPromptVersion": candidate["recoveryPromptVersion"],
                "recoveryPromptDigest": candidate["recoveryPromptDigest"],
                "recoveryChainDigest": candidate["recoveryChainDigest"],
                "rearmedFromExhausted": candidate.get("rearmedFromExhausted"),
            }
            if candidate.get("recoveryKind") == "DISPATCHED_TASK"
            else {}
        ),
    }


def recovery_commit(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).commit_recovery(
        thread_id=args.thread_id,
        nonce=args.recovery_nonce,
    )
    return {"ok": True, "threadId": args.thread_id}


def recovery_abandon(args: argparse.Namespace) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", args.reason):
        raise RuntimeError("abandon reason must be machine-readable")
    probe = recovery_list(
        argparse.Namespace(
            ledger=args.ledger,
            min_age_minutes=0,
            delivery_min_age_minutes=args.min_age_minutes,
        )
    )
    candidate = next(
        (
            item
            for item in probe["unresolved"]
            if item.get("threadId") == args.thread_id
            and item.get("reservation", {}).get("recoveryNonce") == args.recovery_nonce
        ),
        None,
    )
    if not candidate or not candidate.get("abandonable"):
        raise RuntimeError("recovery delivery is not safely abandonable")
    if candidate.get("abandonNonce") != args.abandon_nonce:
        raise RuntimeError("recovery abandonment authorization is stale or invalid")
    ledger(args.ledger).abandon_recovery_delivery(
        thread_id=args.thread_id,
        nonce=args.recovery_nonce,
        reason=args.reason,
        min_age_minutes=args.min_age_minutes,
    )
    return {
        "ok": True,
        "threadId": args.thread_id,
        "recoveryNonce": args.recovery_nonce,
        "abandoned": True,
    }


def task_context(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    deadline = monotonic() + max(0.0, min(float(args.wait_seconds), 300.0))
    reconciliation_attempted = False
    while True:
        value = store.task_context(
            issue_url=args.issue_url,
            thread_id=args.thread_id,
            worktree_path=args.worktree,
        )
        if value is not None:
            return {"ok": True, "task": value, "pendingHandoff": False}
        if not reconciliation_attempted and args.worktree:
            reconciliation_attempted = True
            reconciliation = orphan_list(args)
            matches = [
                item
                for item in reconciliation["candidates"]
                if item["issueUrl"] == args.issue_url
                and Path(item["cwd"]).resolve() == Path(args.worktree).resolve()
                and (not args.thread_id or item["threadId"] == args.thread_id)
            ]
            if len(matches) == 1:
                candidate = matches[0]
                store.commit_orphan_dispatch(
                    candidate["intentId"],
                    thread_id=candidate["threadId"],
                    project_id=f"async-reconciled:{candidate['repo']}",
                    worktree_path=str(Path(candidate["cwd"]).resolve()),
                    title_time=candidate["titleTime"],
                    lease_started_at=candidate["leaseStartedAt"],
                    title_synced_state=None,
                )
                continue
        pending = store.has_live_handoff(issue_url=args.issue_url)
        if not pending or monotonic() >= deadline:
            return {"ok": False, "task": None, "pendingHandoff": pending}
        sleep(0.5)


def _drain_once_unlocked(args: argparse.Namespace) -> dict[str, Any]:
    """Advance at most one user-visible task, terminalizing stale intents on the way."""

    restored = restore_reconcile(argparse.Namespace(ledger=args.ledger))
    if not restored.get("ok"):
        return {
            "ok": False,
            "action": "restore_failed",
            "restored": restored.get("restored") or [],
            "errors": restored.get("errors") or [],
        }
    restored_items = list(restored.get("restored") or [])

    def restore_target(candidate: dict[str, Any]) -> dict[str, Any] | None:
        target = restore_reconcile(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
            )
        )
        restored_items.extend(target.get("restored") or [])
        if target.get("ok"):
            return None
        return {
            "ok": False,
            "action": "restore_failed",
            "restored": restored_items,
            "errors": target.get("errors") or [],
        }

    store = ledger(args.ledger)
    rearmed = _rearm_negative_followup_deliveries(store)
    recovery_rearmed, recovery_exhausted = _rearm_interrupted_recovery_turns(store)
    rearmed.extend(recovery_rearmed)
    account_pause = _codex_usage_limit_pause(store)
    if account_pause:
        return {
            "ok": True,
            "action": "none",
            "held": account_pause["tasks"],
            "accountBlocked": account_pause,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    publication_feedback_state = publication_feedback_list(argparse.Namespace(ledger=args.ledger))
    if publication_feedback_state.get("candidates"):
        candidate = publication_feedback_state["candidates"][0]
        reserved = publication_feedback_reserve(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                pr_url=candidate["prUrl"],
            )
        )
        delivered = publication_feedback_deliver(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                reservation_nonce=reserved["reservationNonce"],
            )
        )
        return {
            "ok": bool(delivered.get("ok")),
            "action": "publication_feedback_dispatched",
            "key": candidate.get("key"),
            "threadId": candidate.get("threadId"),
            "prUrl": candidate.get("prUrl"),
            "delivery": delivered,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    implementation_unresolved = store.unresolved_implementation_followups()
    if implementation_unresolved:
        candidate = implementation_unresolved[0]
        delivered = implementation_followup_deliver(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )
        return {
            "ok": bool(delivered.get("ok")),
            "action": "implementation_followup_dispatched",
            "key": candidate.get("key"),
            "threadId": candidate.get("threadId"),
            "delivery": delivered,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    implementation_candidates = store.implementation_followup_candidates()
    if implementation_candidates:
        candidate = implementation_candidates[0]
        restore_failure = restore_target(candidate)
        if restore_failure:
            return restore_failure
        reserved = implementation_followup_reserve(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )
        delivered = implementation_followup_deliver(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                result_digest=reserved["resultDigest"],
            )
        )
        return {
            "ok": bool(delivered.get("ok")),
            "action": "implementation_followup_dispatched",
            "key": candidate.get("key"),
            "threadId": candidate.get("threadId"),
            "delivery": delivered,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    pr_state = pr_followup_list(argparse.Namespace(ledger=args.ledger))
    deferred_followups: list[dict[str, Any]] = []
    restored_followup_threads: set[str] = set()
    if pr_state.get("restoreRequired"):
        restore_candidate = pr_state["restoreRequired"][0]
        restore_failure = restore_target(restore_candidate)
        if restore_failure:
            return restore_failure
        restored_followup_threads.add(str(restore_candidate["threadId"]))
        pr_state = pr_followup_list(argparse.Namespace(ledger=args.ledger))
    followup_candidates = list(pr_state.get("reprepareRequired") or []) + list(
        pr_state.get("candidates") or []
    )
    for candidate in followup_candidates:
        if str(candidate["threadId"]) not in restored_followup_threads:
            restore_failure = restore_target(candidate)
            if restore_failure:
                return restore_failure
        reserved = pr_followup_reserve(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                wake_digest=candidate["wakeDigest"],
            )
        )
        if reserved.get("deferred"):
            deferred_followups.append(
                {
                    "key": reserved.get("key"),
                    "reason": reserved.get("reason") or "live_snapshot_changed",
                }
            )
            continue
        delivered = pr_followup_deliver(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                wake_digest=candidate["wakeDigest"],
            )
        )
        return {
            "ok": bool(delivered.get("ok")),
            "action": "pr_followup_dispatched",
            "key": candidate.get("key"),
            "threadId": candidate.get("threadId"),
            "delivery": delivered,
            "deferredFollowups": deferred_followups,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    validation_state = validation_followup_list(
        argparse.Namespace(ledger=args.ledger, min_age_minutes=90)
    )
    if validation_state.get("candidates"):
        candidate = validation_state["candidates"][0]
        restore_failure = restore_target(candidate)
        if restore_failure:
            return restore_failure
        try:
            reserved = validation_followup_reserve(
                argparse.Namespace(
                    ledger=args.ledger,
                    thread_id=candidate["threadId"],
                    result_digest=candidate["resultDigest"],
                    prefetch_complete=False,
                )
            )
        except RuntimeError as exc:
            if "global task WIP limit reached" not in str(exc):
                raise
            return {
                "ok": True,
                "action": "none",
                "held": [
                    {
                        "key": candidate.get("key"),
                        "reason": "global_task_wip_limit",
                    }
                ],
                "deferredFollowups": deferred_followups,
                "restored": restored_items,
                "rearmed": rearmed,
                "recoveryRetryExhausted": recovery_exhausted,
            }
        if reserved.get("blocked"):
            return {
                "ok": True,
                "action": "validation_prefetch_blocked",
                "key": candidate.get("key"),
                "threadId": candidate.get("threadId"),
                "dependencyFailures": reserved.get("dependencyFailures") or [],
                "deferredFollowups": deferred_followups,
                "restored": restored_items,
                "rearmed": rearmed,
                "recoveryRetryExhausted": recovery_exhausted,
            }
        if reserved.get("deferred"):
            return {
                "ok": True,
                "action": "validation_followup_deferred",
                "key": candidate.get("key"),
                "threadId": candidate.get("threadId"),
                "reason": reserved.get("reason") or "validation_result_changed",
                "deferredFollowups": deferred_followups,
                "restored": restored_items,
                "rearmed": rearmed,
                "recoveryRetryExhausted": recovery_exhausted,
            }
        delivered = validation_followup_deliver(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )
        if delivered.get("deferred"):
            return {
                "ok": True,
                "action": "validation_followup_deferred",
                "key": candidate.get("key"),
                "threadId": candidate.get("threadId"),
                "reason": delivered.get("reason") or "validation_result_changed",
                "deferredFollowups": deferred_followups,
                "restored": restored_items,
                "rearmed": rearmed,
                "recoveryRetryExhausted": recovery_exhausted,
            }
        return {
            "ok": bool(delivered.get("ok")),
            "action": "validation_followup_dispatched",
            "key": candidate.get("key"),
            "threadId": candidate.get("threadId"),
            "delivery": delivered,
            "deferredFollowups": deferred_followups,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    recovery_state = recovery_list(
        argparse.Namespace(
            ledger=args.ledger,
            min_age_minutes=90,
            delivery_min_age_minutes=5,
        )
    )
    if recovery_state.get("recoverable"):
        candidate = recovery_state["recoverable"][0]
        restore_failure = restore_target(candidate)
        if restore_failure:
            return restore_failure
        recovery_reserve(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                recovery_nonce=candidate["recoveryNonce"],
            )
        )
        delivered = recovery_deliver(
            argparse.Namespace(
                ledger=args.ledger,
                thread_id=candidate["threadId"],
                recovery_nonce=candidate["recoveryNonce"],
            )
        )
        return {
            "ok": bool(delivered.get("ok")),
            "action": "recovery_dispatched",
            "key": candidate.get("key"),
            "threadId": candidate.get("threadId"),
            "delivery": delivered,
            "deferredFollowups": deferred_followups,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    if deferred_followups:
        return {
            "ok": True,
            "action": "none",
            "terminalized": [],
            "held": [
                {
                    "key": item.get("key"),
                    "reason": "higher_priority_followup_refresh_required",
                }
                for item in deferred_followups
            ],
            "deferredFollowups": deferred_followups,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    terminalized: list[dict[str, Any]] = []
    scanner_rechecks: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    owner = str(getattr(args, "owner", None) or "local-event-drain")
    for intent in list_pending(args.ledger).get("pending") or []:
        claim = claim_intent(
            argparse.Namespace(
                ledger=args.ledger,
                runtime_root=args.runtime_root,
                intent_id=intent["intentId"],
                owner=owner,
                lease_minutes=30,
                prepare=True,
                task_project_id=args.project_id,
            )
        )
        if not claim.get("authorized"):
            decision = claim.get("decision") or {}
            if claim.get("recheckRequired"):
                recheck = claim.get("scannerRecheck") or {}
                scanner_rechecks.append(
                    {
                        "key": intent.get("key"),
                        "intentId": intent.get("intentId"),
                        "reason": decision.get("reason_code")
                        or decision.get("reasonCode")
                        or "STATE_DRIFT",
                        "recordedAt": recheck.get("recordedAt"),
                    }
                )
                continue
            if decision.get("status") == "BLOCK":
                terminalized.append(
                    {
                        "key": intent.get("key"),
                        "reason": decision.get("reason_code") or decision.get("reasonCode"),
                    }
                )
                continue
            held.append(
                {
                    "key": intent.get("key"),
                    "reason": claim.get("reason")
                    or decision.get("reason_code")
                    or decision.get("reasonCode"),
                }
            )
            if claim.get("reason") in {"task_wip_limit", "higher_priority_existing_work"}:
                break
            continue
        if claim.get("shadow"):
            terminalized.append({"key": intent.get("key"), "reason": "shadow_observed"})
            continue
        if not claim.get("claimed"):
            held.append({"key": intent.get("key"), "reason": claim.get("reason")})
            continue

        creation = creation_start(
            argparse.Namespace(
                ledger=args.ledger,
                intent_id=intent["intentId"],
                owner=owner,
            )
        )
        created = root_task_create(
            argparse.Namespace(
                ledger=args.ledger,
                runtime_root=args.runtime_root,
                intent_id=intent["intentId"],
                creation_token=creation["creationToken"],
                project_id=args.project_id,
                source_repo=claim["sourceRepoPath"],
                worktree=claim["worktreePath"],
                title_time=claim["titleTime"],
            )
        )
        return {
            "ok": True,
            "action": "issue_task_dispatched",
            "key": intent.get("key"),
            "threadId": created.get("threadId"),
            "turnId": created.get("turnId"),
            "terminalized": terminalized,
            "scannerRechecks": scanner_rechecks,
            "held": held,
            "deferredFollowups": deferred_followups,
            "restored": restored_items,
            "rearmed": rearmed,
            "recoveryRetryExhausted": recovery_exhausted,
        }

    return {
        "ok": True,
        "action": "none",
        "terminalized": terminalized,
        "scannerRechecks": scanner_rechecks,
        "held": held,
        "deferredFollowups": deferred_followups,
        "restored": restored_items,
        "rearmed": rearmed,
        "recoveryRetryExhausted": recovery_exhausted,
    }


def drain_once(args: argparse.Namespace) -> dict[str, Any]:
    """Serialize heartbeat and completion-event dispatch through one drain lock."""

    lock_path = Path(args.ledger).with_suffix(".drain.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"ok": True, "busy": True, "action": "drain_already_running"}
        try:
            return _drain_once_unlocked(args)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return {
                "ok": False,
                "action": "drain_failed",
                "errors": [{"error": f"{type(exc).__name__}:{str(exc)[:400]}"}],
            }


def main() -> int:
    global STATE
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=None)
    parser.add_argument(
        "--runtime-root",
        type=Path,
        default=None,
        help="required for every state-changing or external-action operation",
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("sync")
    subparsers.add_parser("queue-import")
    subparsers.add_parser("publish-terminal-feedback")
    codex_decision_dispatch_parser = subparsers.add_parser("codex-decision-dispatch")
    codex_decision_dispatch_parser.add_argument("--project-id", default=DEFAULT_TASK_PROJECT_ID)
    codex_decision_worker_parser = subparsers.add_parser("codex-decision-worker")
    codex_decision_worker_parser.add_argument("--project-id", required=True)
    codex_decision_worker_parser.add_argument("--request", required=True)
    codex_decision_worker_parser.add_argument("--receipt", required=True)
    subparsers.add_parser("list")
    alerts_parser = subparsers.add_parser("alerts")
    alerts_parser.add_argument("--min-age-minutes", type=int, default=70)
    alerts_parser.add_argument("--notify", action="store_true")
    dispatch_notifications_parser = subparsers.add_parser("dispatch-notifications")
    dispatch_notifications_parser.add_argument("--notify", action="store_true")
    claim = subparsers.add_parser("claim")
    claim.add_argument("--intent-id", required=True)
    claim.add_argument("--owner", required=True)
    claim.add_argument("--lease-minutes", type=int, default=15)
    claim.add_argument("--prepare", action="store_true")
    claim.add_argument("--task-project-id")
    claim_release = subparsers.add_parser("claim-release")
    claim_release.add_argument("--intent-id", required=True)
    claim_release.add_argument("--owner")
    claim_release.add_argument("--reason", required=True)
    reopen_parser = subparsers.add_parser("reopen-false-terminal")
    reopen_parser.add_argument("--key", required=True)
    reopen_parser.add_argument("--expected-reason", required=True)
    reopen_parser.add_argument("--migration-reason", required=True)
    state_drift_reopen_parser = subparsers.add_parser("reopen-state-drift")
    state_drift_reopen_parser.add_argument("--key", required=True)
    state_drift_reopen_parser.add_argument("--intent-id", required=True)
    commit = subparsers.add_parser("commit")
    commit.add_argument("--intent-id", required=True)
    commit.add_argument("--owner")
    commit.add_argument("--thread-id", required=True)
    commit.add_argument("--project-id", required=True)
    commit.add_argument("--cwd", required=True)
    commit.add_argument("--worktree")
    commit.add_argument("--source-repo", required=True)
    commit.add_argument("--title-time", required=True)
    retry_dispatch_parser = subparsers.add_parser("retry-dispatch")
    retry_dispatch_parser.add_argument("--thread-id", required=True)
    retry_dispatch_parser.add_argument("--reason", required=True)
    creation_start_parser = subparsers.add_parser("creation-start")
    creation_start_parser.add_argument("--intent-id", required=True)
    creation_start_parser.add_argument("--owner")
    creation_bind_parser = subparsers.add_parser("creation-bind")
    creation_bind_parser.add_argument("--intent-id", required=True)
    creation_bind_parser.add_argument("--owner")
    creation_bind_parser.add_argument("--creation-token", required=True)
    creation_bind_parser.add_argument("--client-thread-id", required=True)
    creation_cancel_parser = subparsers.add_parser("creation-cancel")
    creation_cancel_parser.add_argument("--intent-id", required=True)
    creation_cancel_parser.add_argument("--owner")
    creation_cancel_parser.add_argument("--creation-token", required=True)
    creation_cancel_parser.add_argument("--reason", required=True)
    creation_abandon_parser = subparsers.add_parser("creation-abandon")
    creation_abandon_parser.add_argument("--intent-id", required=True)
    creation_abandon_parser.add_argument("--owner")
    creation_abandon_parser.add_argument("--client-thread-id")
    creation_abandon_parser.add_argument("--abandon-nonce", required=True)
    creation_abandon_parser.add_argument("--reason", required=True)
    creation_abandon_parser.add_argument(
        "--min-age-minutes", type=int, default=ORPHAN_ABANDON_MIN_AGE_MINUTES
    )
    root_task_create_parser = subparsers.add_parser("root-task-create")
    root_task_create_parser.add_argument("--intent-id", required=True)
    root_task_create_parser.add_argument("--creation-token", required=True)
    root_task_create_parser.add_argument("--project-id", required=True)
    root_task_create_parser.add_argument("--source-repo", required=True)
    root_task_create_parser.add_argument("--worktree", required=True)
    root_task_create_parser.add_argument("--title-time", required=True)
    root_task_worker_parser = subparsers.add_parser("root-task-worker")
    root_task_worker_parser.add_argument("--intent-id", required=True)
    root_task_worker_parser.add_argument("--creation-token", required=True)
    root_task_worker_parser.add_argument("--project-id", required=True)
    root_task_worker_parser.add_argument("--source-repo", required=True)
    root_task_worker_parser.add_argument("--worktree", required=True)
    root_task_worker_parser.add_argument("--title-time", required=True)
    root_task_worker_parser.add_argument("--receipt", required=True)
    orphan_list_parser = subparsers.add_parser("orphan-list")
    orphan_list_parser.add_argument(
        "--min-age-minutes", type=int, default=ORPHAN_ABANDON_MIN_AGE_MINUTES
    )
    orphan_reconcile_parser = subparsers.add_parser("orphan-reconcile")
    orphan_reconcile_parser.add_argument(
        "--min-age-minutes", type=int, default=ORPHAN_ABANDON_MIN_AGE_MINUTES
    )
    orphan_reconcile_parser.add_argument("--project-id", default=DEFAULT_TASK_PROJECT_ID)
    orphan_commit_parser = subparsers.add_parser("orphan-commit")
    orphan_commit_parser.add_argument("--intent-id", required=True)
    orphan_commit_parser.add_argument("--thread-id", required=True)
    orphan_commit_parser.add_argument("--project-id", required=True)
    orphan_commit_parser.add_argument("--source-repo", required=True)
    orphan_commit_parser.add_argument("--desired-title", required=True)
    orphan_commit_parser.add_argument("--orphan-nonce", required=True)
    duplicate_list_parser = subparsers.add_parser("duplicate-task-list")
    duplicate_list_parser.add_argument("--min-age-minutes", type=int, default=30)
    duplicate_title_parser = subparsers.add_parser("duplicate-task-title-reconcile")
    duplicate_title_parser.add_argument("--min-age-minutes", type=int, default=30)
    duplicate_reconcile_parser = subparsers.add_parser("duplicate-task-reconcile")
    duplicate_reconcile_parser.add_argument("--min-age-minutes", type=int, default=30)
    outcome = subparsers.add_parser("outcome")
    outcome.add_argument("--key", required=True)
    outcome.add_argument("--stage", required=True)
    outcome.add_argument("--reason")
    outcome.add_argument("--evidence-json")
    outcome.add_argument("--evidence-file")
    outcome.add_argument("--dedupe-key")
    publication_request = subparsers.add_parser("request-publication")
    publication_request.add_argument("--issue-url", required=True)
    publication_request.add_argument("--thread-id", required=True)
    publication_request.add_argument("--worktree", required=True)
    publication_request.add_argument("--evidence-file", required=True)
    publication_check_parser = subparsers.add_parser("publication-check")
    publication_check_parser.add_argument("--issue-url", required=True)
    publication_check_parser.add_argument("--commit-sha", required=True)
    publication_check_parser.add_argument("--branch", required=True)
    subparsers.add_parser("cleanup-list")
    subparsers.add_parser("cleanup-reconcile")
    subparsers.add_parser("restore-reconcile")
    subparsers.add_parser("context-recover")
    subparsers.add_parser("context-sync")
    subparsers.add_parser("reproduction-probe")
    subparsers.add_parser("publication-feedback-list")
    publication_feedback_reserve_parser = subparsers.add_parser("publication-feedback-reserve")
    publication_feedback_reserve_parser.add_argument("--thread-id", required=True)
    publication_feedback_reserve_parser.add_argument("--pr-url", required=True)
    publication_feedback_deliver_parser = subparsers.add_parser("publication-feedback-deliver")
    publication_feedback_deliver_parser.add_argument("--thread-id", required=True)
    publication_feedback_deliver_parser.add_argument("--reservation-nonce", required=True)
    publication_feedback_commit_parser = subparsers.add_parser("publication-feedback-commit")
    publication_feedback_commit_parser.add_argument("--thread-id", required=True)
    publication_feedback_commit_parser.add_argument("--reservation-nonce", required=True)
    implementation_followup_reserve_parser = subparsers.add_parser(
        "implementation-followup-reserve"
    )
    implementation_followup_reserve_parser.add_argument("--thread-id", required=True)
    implementation_followup_reserve_parser.add_argument("--result-digest", required=True)
    implementation_followup_deliver_parser = subparsers.add_parser(
        "implementation-followup-deliver"
    )
    implementation_followup_deliver_parser.add_argument("--thread-id", required=True)
    implementation_followup_deliver_parser.add_argument("--result-digest", required=True)
    pr_followup_list_parser = subparsers.add_parser("pr-followup-list")
    pr_followup_list_parser.add_argument(
        "--min-age-minutes",
        type=int,
        default=PR_FOLLOWUP_ABANDON_MIN_AGE_MINUTES,
    )
    pr_followup_reserve_parser = subparsers.add_parser("pr-followup-reserve")
    pr_followup_reserve_parser.add_argument("--thread-id", required=True)
    pr_followup_reserve_parser.add_argument("--wake-digest", required=True)
    pr_followup_deliver_parser = subparsers.add_parser("pr-followup-deliver")
    pr_followup_deliver_parser.add_argument("--thread-id", required=True)
    pr_followup_deliver_parser.add_argument("--wake-digest", required=True)
    pr_followup_commit_parser = subparsers.add_parser("pr-followup-commit")
    pr_followup_commit_parser.add_argument("--thread-id", required=True)
    pr_followup_commit_parser.add_argument("--wake-digest", required=True)
    pr_followup_abandon_parser = subparsers.add_parser("pr-followup-abandon")
    pr_followup_abandon_parser.add_argument("--thread-id", required=True)
    pr_followup_abandon_parser.add_argument("--wake-digest", required=True)
    pr_followup_abandon_parser.add_argument("--abandon-nonce", required=True)
    pr_followup_abandon_parser.add_argument("--reason", required=True)
    pr_followup_abandon_parser.add_argument(
        "--min-age-minutes",
        type=int,
        default=PR_FOLLOWUP_ABANDON_MIN_AGE_MINUTES,
    )
    validation_followup_list_parser = subparsers.add_parser("validation-followup-list")
    validation_followup_list_parser.add_argument("--min-age-minutes", type=int, default=90)
    validation_followup_reserve_parser = subparsers.add_parser("validation-followup-reserve")
    validation_followup_reserve_parser.add_argument("--thread-id", required=True)
    validation_followup_reserve_parser.add_argument("--result-digest", required=True)
    validation_followup_reserve_parser.add_argument("--prefetch-complete", action="store_true")
    validation_followup_deliver_parser = subparsers.add_parser("validation-followup-deliver")
    validation_followup_deliver_parser.add_argument("--thread-id", required=True)
    validation_followup_deliver_parser.add_argument("--result-digest", required=True)
    validation_followup_commit_parser = subparsers.add_parser("validation-followup-commit")
    validation_followup_commit_parser.add_argument("--thread-id", required=True)
    validation_followup_commit_parser.add_argument("--result-digest", required=True)
    validation_followup_commit_parser.add_argument("--reservation-digest")
    validation_followup_abandon_parser = subparsers.add_parser("validation-followup-abandon")
    validation_followup_abandon_parser.add_argument("--thread-id", required=True)
    validation_followup_abandon_parser.add_argument("--result-digest", required=True)
    validation_followup_abandon_parser.add_argument("--abandon-nonce", required=True)
    validation_followup_abandon_parser.add_argument("--reason", required=True)
    validation_followup_abandon_parser.add_argument("--min-age-minutes", type=int, default=90)
    subparsers.add_parser("ingest-results")
    subparsers.add_parser("local-receipt-enqueue")
    subparsers.add_parser("independent-review-run")
    subparsers.add_parser("publication-run")
    publication_retry_parser = subparsers.add_parser("publication-retry")
    publication_retry_parser.add_argument("--request-id", required=True)
    publication_retry_parser.add_argument("--expected-reason", required=True)
    subparsers.add_parser("restore-list")
    restore_commit_parser = subparsers.add_parser("restore-commit")
    restore_commit_parser.add_argument("--thread-id", required=True)
    restore_commit_parser.add_argument("--restore-nonce", required=True)
    cleanup_commit_parser = subparsers.add_parser("cleanup-commit")
    cleanup_commit_parser.add_argument("--thread-id", required=True)
    cleanup_commit_parser.add_argument("--cleanup-nonce", required=True)
    subparsers.add_parser("title-list")
    subparsers.add_parser("title-reconcile")
    title_commit_parser = subparsers.add_parser("title-commit")
    title_commit_parser.add_argument("--thread-id", required=True)
    title_commit_parser.add_argument("--title-state", required=True)
    title_commit_parser.add_argument("--title-nonce", required=True)
    title_commit_parser.add_argument("--desired-title", required=True)
    subparsers.add_parser("refresh-prs")
    recovery_list_parser = subparsers.add_parser("recovery-list")
    recovery_list_parser.add_argument("--min-age-minutes", type=int, default=90)
    recovery_list_parser.add_argument("--delivery-min-age-minutes", type=int, default=5)
    recovery_reserve_parser = subparsers.add_parser("recovery-reserve")
    recovery_reserve_parser.add_argument("--thread-id", required=True)
    recovery_reserve_parser.add_argument("--recovery-nonce", required=True)
    recovery_deliver_parser = subparsers.add_parser("recovery-deliver")
    recovery_deliver_parser.add_argument("--thread-id", required=True)
    recovery_deliver_parser.add_argument("--recovery-nonce", required=True)
    recovery_commit_parser = subparsers.add_parser("recovery-commit")
    recovery_commit_parser.add_argument("--thread-id", required=True)
    recovery_commit_parser.add_argument("--recovery-nonce", required=True)
    recovery_abandon_parser = subparsers.add_parser("recovery-abandon")
    recovery_abandon_parser.add_argument("--thread-id", required=True)
    recovery_abandon_parser.add_argument("--recovery-nonce", required=True)
    recovery_abandon_parser.add_argument("--abandon-nonce", required=True)
    recovery_abandon_parser.add_argument("--reason", required=True)
    recovery_abandon_parser.add_argument("--min-age-minutes", type=int, default=5)
    task_turn_worker_parser = subparsers.add_parser("task-turn-worker")
    task_turn_worker_parser.add_argument(
        "--delivery-kind",
        required=True,
        choices=(
            "implementation-followup",
            "pr-followup",
            "validation-followup",
            "publication-feedback",
            "recovery",
        ),
    )
    task_turn_worker_parser.add_argument("--thread-id", required=True)
    task_turn_worker_parser.add_argument("--delivery-token", required=True)
    task_turn_worker_parser.add_argument("--delivery-attempt-digest")
    task_turn_worker_parser.add_argument("--reservation-digest")
    task_turn_worker_parser.add_argument("--snapshot-id")
    task_turn_worker_parser.add_argument("--snapshot-path")
    task_turn_worker_parser.add_argument("--snapshot-digest")
    task_turn_worker_parser.add_argument("--worktree-input-path")
    task_turn_worker_parser.add_argument("--worktree-input-digest")
    task_turn_worker_parser.add_argument("--receipt", required=True)
    task_context_parser = subparsers.add_parser("task-context")
    task_context_parser.add_argument("--issue-url", required=True)
    task_context_parser.add_argument("--thread-id")
    task_context_parser.add_argument("--worktree")
    task_context_parser.add_argument("--wait-seconds", type=float, default=180.0)
    drain_parser = subparsers.add_parser("drain-once")
    drain_parser.add_argument("--project-id", default=DEFAULT_TASK_PROJECT_ID)
    drain_parser.add_argument("--owner", default="local-event-drain")
    metrics = subparsers.add_parser("metrics")
    metrics.add_argument("--days", type=int, default=30)
    for subparser in subparsers.choices.values():
        subparser.add_argument(
            "--runtime-root",
            type=Path,
            default=argparse.SUPPRESS,
            help=argparse.SUPPRESS,
        )
    args = parser.parse_args()
    if args.runtime_root is None:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "--runtime-root is required for every bridge operation",
                }
            )
        )
        return 2
    args.runtime_root = args.runtime_root.resolve()
    STATE = args.runtime_root / "state"
    expected_ledger = runtime_ledger_path(args.runtime_root).resolve()
    if args.ledger is None:
        args.ledger = expected_ledger
    elif args.ledger.resolve() != expected_ledger:
        print(json.dumps({"ok": False, "error": "ledger must be the runtime ledger"}))
        return 2
    try:
        bind_runtime(args.runtime_root)
        require_operational_authorization(args.runtime_root)
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"operational authorization required: {str(exc)[:300]}",
                }
            )
        )
        return 2
    if args.operation == "sync":
        result = sync_queue(args.ledger)
    elif args.operation == "queue-import":
        result = import_signed_queue(args.ledger)
    elif args.operation == "publish-terminal-feedback":
        result = publish_terminal_feedback(args)
    elif args.operation == "codex-decision-dispatch":
        result = dispatch_codex_decisions(args)
    elif args.operation == "codex-decision-worker":
        result = _codex_decision_worker(args)
    elif args.operation == "list":
        result = list_pending(args.ledger)
    elif args.operation == "alerts":
        result = dispatch_alerts(args)
    elif args.operation == "dispatch-notifications":
        result = dispatch_notifications(args)
    elif args.operation == "claim":
        result = claim_intent(args)
    elif args.operation == "claim-release":
        result = release_claim(args)
    elif args.operation == "reopen-false-terminal":
        result = reopen_false_terminal(args)
    elif args.operation == "reopen-state-drift":
        result = reopen_state_drift(args)
    elif args.operation == "commit":
        result = commit_receipt(args)
    elif args.operation == "retry-dispatch":
        result = retry_dispatch(args)
    elif args.operation == "creation-start":
        result = creation_start(args)
    elif args.operation == "creation-bind":
        result = creation_bind(args)
    elif args.operation == "creation-cancel":
        result = creation_cancel(args)
    elif args.operation == "creation-abandon":
        result = creation_abandon(args)
    elif args.operation == "root-task-create":
        result = root_task_create(args)
    elif args.operation == "root-task-worker":
        result = _app_server_request_worker(args)
    elif args.operation == "orphan-list":
        result = orphan_list(args)
    elif args.operation == "orphan-reconcile":
        result = orphan_reconcile(args)
    elif args.operation == "orphan-commit":
        result = orphan_commit(args)
    elif args.operation == "duplicate-task-list":
        result = duplicate_task_list(args)
    elif args.operation == "duplicate-task-title-reconcile":
        result = duplicate_task_title_reconcile(args)
    elif args.operation == "duplicate-task-reconcile":
        result = duplicate_task_reconcile(args)
    elif args.operation == "outcome":
        result = record_outcome(args)
    elif args.operation == "request-publication":
        result = submit_publication_request(args)
    elif args.operation == "publication-check":
        result = publication_check(args)
    elif args.operation == "cleanup-list":
        result = cleanup_list(args)
    elif args.operation == "cleanup-reconcile":
        result = cleanup_reconcile(args)
    elif args.operation == "restore-reconcile":
        result = restore_reconcile(args)
    elif args.operation == "context-recover":
        result = recover_task_contexts(args)
    elif args.operation == "context-sync":
        result = sync_task_contexts(args)
    elif args.operation == "reproduction-probe":
        result = run_reproduction_probes(args)
    elif args.operation == "implementation-followup-reserve":
        result = implementation_followup_reserve(args)
    elif args.operation == "implementation-followup-deliver":
        result = implementation_followup_deliver(args)
    elif args.operation == "publication-feedback-list":
        result = publication_feedback_list(args)
    elif args.operation == "publication-feedback-reserve":
        result = publication_feedback_reserve(args)
    elif args.operation == "publication-feedback-deliver":
        result = publication_feedback_deliver(args)
    elif args.operation == "publication-feedback-commit":
        result = publication_feedback_commit(args)
    elif args.operation == "pr-followup-list":
        result = pr_followup_list(args)
    elif args.operation == "pr-followup-reserve":
        result = pr_followup_reserve(args)
    elif args.operation == "pr-followup-deliver":
        result = pr_followup_deliver(args)
    elif args.operation == "pr-followup-commit":
        result = pr_followup_commit(args)
    elif args.operation == "pr-followup-abandon":
        result = pr_followup_abandon(args)
    elif args.operation == "validation-followup-list":
        result = validation_followup_list(args)
    elif args.operation == "validation-followup-reserve":
        result = validation_followup_reserve(args)
    elif args.operation == "validation-followup-deliver":
        result = validation_followup_deliver(args)
    elif args.operation == "validation-followup-commit":
        result = validation_followup_commit(args)
    elif args.operation == "validation-followup-abandon":
        result = validation_followup_abandon(args)
    elif args.operation == "ingest-results":
        result = ingest_task_results(args)
    elif args.operation == "local-receipt-enqueue":
        result = enqueue_local_receipts(args.ledger)
    elif args.operation == "independent-review-run":
        result = independent_review_run(args)
    elif args.operation == "publication-run":
        result = run_publication_queue(args)
    elif args.operation == "publication-retry":
        result = retry_blocked_publication(args)
    elif args.operation == "restore-list":
        result = restore_list(args)
    elif args.operation == "restore-commit":
        result = restore_commit(args)
    elif args.operation == "cleanup-commit":
        result = cleanup_commit(args)
    elif args.operation == "title-list":
        result = title_list(args)
    elif args.operation == "title-reconcile":
        result = title_reconcile(args)
    elif args.operation == "title-commit":
        result = title_commit(args)
    elif args.operation == "refresh-prs":
        result = refresh_pull_requests(args)
    elif args.operation == "recovery-list":
        result = recovery_list(args)
    elif args.operation == "recovery-reserve":
        result = recovery_reserve(args)
    elif args.operation == "recovery-deliver":
        result = recovery_deliver(args)
    elif args.operation == "recovery-commit":
        result = recovery_commit(args)
    elif args.operation == "recovery-abandon":
        result = recovery_abandon(args)
    elif args.operation == "task-turn-worker":
        result = task_turn_worker_entry(args)
    elif args.operation == "task-context":
        result = task_context(args)
    elif args.operation == "drain-once":
        result = drain_once(args)
    else:
        result = rolling_quality(args.ledger, days=args.days)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
