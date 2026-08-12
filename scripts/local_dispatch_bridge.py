#!/usr/bin/env python3
"""Verify, lease, prepare, and receipt local issue-task dispatches."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic, sleep
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.decision import authorize  # noqa: E402
from oss_pr_radar.dispatch import DispatchSigner, canonical_prompt, verify_queue  # noqa: E402
from oss_pr_radar.evidence import collect_evidence  # noqa: E402
from oss_pr_radar.github_client import GitHubClient  # noqa: E402
from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.metrics import assess_submit_ready, rolling_quality  # noqa: E402
from oss_pr_radar.notifier import FeishuClient, NotificationError, candidate_card  # noqa: E402
from oss_pr_radar.policy import SCANNER_DECISION_REVISION, decision_contract_digest  # noqa: E402
from oss_pr_radar.publication import (  # noqa: E402
    broker_publication_request,
    public_branch_is_safe,
    public_text_is_safe,
    request_publication,
)
from oss_pr_radar.util import (  # noqa: E402
    atomic_write_json,
    iso_z,
    parse_time,
    read_json,
    sha256_json,
)

STATE = ROOT / "state"
LEDGER_PATH = STATE / "radar_ledger.sqlite3"
THREAD_DB = Path.home() / ".codex" / "state_5.sqlite"
GITHUB_ROOT = Path.home() / "Documents" / "github"
WORKTREE_ROOT = Path.home() / ".codex" / "worktrees"
KEYCHAIN_SERVICE = "oss-pr-radar-dispatch"
ISSUE_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
PULL_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$")
DELEGATED_INPUT = re.compile(r"<input>(.*?)</input>", re.DOTALL)
MAX_TITLE_CHARS = 59
TASK_PRIVATE_DIR = ".oss-pr-radar"
TASK_CONTEXT_SCHEMA = "radar-task-context-v1"
TASK_RESULT_SCHEMA = "radar-task-result-v1"
ORPHAN_ABANDON_MIN_AGE_MINUTES = 70
PR_FOLLOWUP_ACTIVE_DEFERRAL_MINUTES = 30
PR_FOLLOWUP_ABANDON_MIN_AGE_MINUTES = 90
CLOUD_PR_FOLLOWUP_MAX_AGE_MINUTES = 150
VALIDATION_PREFETCH_TIMEOUTS = {
    "cargo_locked_fetch": 300,
    "go_locked_download": 300,
    "uv_locked_sync": 900,
    "npm_locked_install": 900,
}
TITLE_PREFIXES = {
    "GO": "[有价值·GO]",
    "AUDIT_NO_GO": "[无价值]",
    "VALIDATION_PENDING": "[有价值·待验证]",
    "FIX_READY": "[有价值·本地修复就绪]",
    "PUBLICATION_REQUEST": "[有价值·存在发布请求]",
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
PUBLISHED_TASK_STAGES = {
    "PR_OPEN",
    "CI_GREEN",
    "MAINTAINER_ACCEPTED",
    "MERGED",
    "CLOSED",
}
IMMEDIATE_RECOVERY_ERROR_CODES = {
    "cyber_policy",
    "internal_error",
    "server_error",
    "system_error",
}
BENIGN_POLICY_RECOVERY_PROMPT = (
    "这是一个普通开源软件的本地 GPU 张量生命周期修复续办，不是网络安全任务。"
    "保留现有工作树和已完成改动，直接完成离线测试、独立复核以及 Workspace Result "
    "Protocol 结构化交接；不要访问网络，不要执行公开操作。"
)
issue_prompt = canonical_prompt


def latest_terminal_thread_error(rollout_path: str | None) -> dict[str, Any] | None:
    """Return the latest turn's terminal error without loading a large rollout."""

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
        if '"task_complete"' not in raw_line and '"turn_context"' not in raw_line:
            continue
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if record.get("type") == "turn_context":
            return None
        payload = record.get("payload") or {}
        if record.get("type") != "event_msg" or payload.get("type") != "task_complete":
            continue
        error = payload.get("error")
        if not isinstance(error, dict):
            return None
        return {
            "code": str(error.get("codex_error_info") or "system_error"),
            "message": str(error.get("message") or "")[:240],
            "turnId": str(payload.get("turn_id") or ""),
        }
    return None


def managed_worktree_root() -> Path:
    return (GITHUB_ROOT / TASK_PRIVATE_DIR / "worktrees").resolve()


def shared_context_root() -> Path:
    return (GITHUB_ROOT / TASK_PRIVATE_DIR / "task-contexts").resolve()


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
    match = ISSUE_URL.match(issue_url)
    if not match:
        raise RuntimeError("invalid issue URL")
    repo, number = match.groups()
    owner, repository = repo.split("/", 1)
    safe = "--".join(
        re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
        for value in (owner, repository, number)
    )
    return shared_context_root() / f"{safe}.json"


def _is_within(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    resolved_root = root.resolve()
    return resolved != resolved_root and resolved_root in resolved.parents


def _is_managed_worktree(path: Path) -> bool:
    return _is_within(path, managed_worktree_root())


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


def prewarm_source_repo(path: Path) -> None:
    """Make the default-branch snapshot locally checkout-ready for Codex."""

    command(
        ["git", "status", "--porcelain=v1", "--untracked-files=no"],
        cwd=path,
        timeout=60,
    )
    default_ref = command(
        ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=path,
        timeout=15,
    )
    quiet_command(
        ["git", "archive", "--format=tar", default_ref],
        cwd=path,
        timeout=600,
    )


def source_repo(repo: str) -> Path:
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
            command(
                ["git", "fetch", "--prune", "--no-tags", "--filter=blob:none", "origin"],
                cwd=path,
                timeout=180,
            )
            resolved = path.resolve()
            prewarm_source_repo(resolved)
            return resolved
    destination = GITHUB_ROOT / repo.rsplit("/", 1)[1]
    if destination.exists():
        destination = GITHUB_ROOT / repo.replace("/", "--")
    clone_target = destination.with_name(f".{destination.name}.radar-clone-{os.getpid()}")
    try:
        command(
            [
                "git",
                "clone",
                "--depth=1",
                "--single-branch",
                "--no-tags",
                "--filter=blob:none",
                f"https://github.com/{repo}.git",
                str(clone_target),
            ],
            timeout=180,
        )
        if destination.exists():
            shutil.rmtree(clone_target, ignore_errors=True)
            return source_repo(repo)
        clone_target.replace(destination)
    except Exception:
        shutil.rmtree(clone_target, ignore_errors=True)
        raise
    resolved = destination.resolve()
    prewarm_source_repo(resolved)
    return resolved


def _worktree_belongs_to_source(worktree: Path, source: Path) -> bool:
    try:
        return git_path(
            "rev-parse", "--path-format=absolute", "--git-common-dir", cwd=worktree
        ) == git_path("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=source)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return False


def prepare_managed_worktree(source: Path, *, intent_id: str, repo: str) -> Path:
    """Create an isolated source checkout inside the broad GitHub project."""

    worktree = managed_worktree_path(intent_id, repo)
    default_ref = command(
        ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
        cwd=source,
        timeout=15,
    )
    if worktree.exists():
        if not _worktree_belongs_to_source(worktree, source):
            raise RuntimeError("managed worktree does not belong to source repository")
        if command(["git", "status", "--porcelain"], cwd=worktree):
            raise RuntimeError("managed worktree is not clean before dispatch")
        command(["git", "switch", "--detach", default_ref], cwd=worktree, timeout=180)
    else:
        worktree.parent.mkdir(parents=True, exist_ok=True)
        try:
            command(
                ["git", "worktree", "add", "--detach", str(worktree), default_ref],
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
    command(["git", "fetch", "origin", "radar-state"], cwd=ROOT)
    raw = command(["git", "show", "FETCH_HEAD:dispatch_queue.json"], cwd=ROOT)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("invalid cloud queue")
    return value


def fetch_cloud_pr_followup() -> dict[str, Any]:
    raw = command(["git", "show", "FETCH_HEAD:pr_followup.json"], cwd=ROOT)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("invalid cloud PR follow-up state")
    digest = str(value.get("digest") or "")
    expected = sha256_json({key: item for key, item in value.items() if key != "digest"})
    if not digest or digest != expected:
        raise RuntimeError("cloud PR follow-up state digest mismatch")
    return value


def ledger(path: Path = LEDGER_PATH) -> RadarLedger:
    return RadarLedger(path)


def _verified_shared_task_context(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("shared task context is not a regular file")
    if path.stat().st_mode & 0o022:
        raise RuntimeError("shared task context is group or world writable")
    raw = path.read_bytes()
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
    if path.resolve() != shared_context_path(issue_url):
        raise RuntimeError("shared task context path does not match issue identity")
    if Path(str(context.get("bootstrapContextPath") or "")).resolve() != path.resolve():
        raise RuntimeError("shared task context bootstrap path is invalid")

    worktree = Path(str(context.get("worktreePath") or "")).resolve()
    if not worktree.is_dir() or not _is_managed_worktree(worktree):
        raise RuntimeError("shared task context worktree is unavailable or unmanaged")
    local_path = worktree / TASK_PRIVATE_DIR / "task-context.json"
    if local_path.is_symlink() or not local_path.is_file():
        raise RuntimeError("worktree task context mirror is missing")
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
        command(["git", "cat-file", "-e", f"{commit_sha}^{{commit}}"], cwd=worktree)
    followup = context.get("prFollowup")
    prepared_head = (
        str(followup.get("preparedHeadSha"))
        if isinstance(followup, dict) and followup.get("preparedHeadSha")
        else None
    )
    digest_payload = {
        "schemaVersion": TASK_CONTEXT_SCHEMA,
        "key": context.get("key"),
        "issueUrl": issue_url,
        "intentId": context.get("intentId"),
        "track": context.get("track"),
        "algorithmEvidence": context.get("algorithmEvidence"),
        "liveAuditDigest": live_audit["evidence"].get("digest"),
        "threadId": context.get("threadId"),
        "worktreePath": context.get("worktreePath"),
    }
    accepted_digests = {
        sha256_json(digest_payload),
        sha256_json(digest_payload | {"prFollowupPreparedHeadSha": prepared_head}),
    }
    if context.get("contextDigest") not in accepted_digests:
        raise RuntimeError("shared task context digest mismatch")
    source_updated_at = iso_z(
        datetime.fromtimestamp(max(path.stat().st_mtime, local_path.stat().st_mtime), tz=UTC)
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

    worktree = Path(str(context.get("worktreePath") or "")).resolve()
    result_path = Path(str(context.get("resultPath") or "")).resolve()
    expected_path = worktree / TASK_PRIVATE_DIR / "result.json"
    if result_path != expected_path:
        raise RuntimeError("shared task context result path is invalid")
    if not result_path.exists():
        return None
    if result_path.is_symlink() or not result_path.is_file():
        raise RuntimeError("published task result is not a regular file")
    if result_path.stat().st_mode & 0o022:
        raise RuntimeError("published task result is group or world writable")

    raw = result_path.read_bytes()
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
    result_digest = hashlib.sha256(raw).hexdigest()
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
    root = shared_context_root()
    if not root.exists():
        return {
            "verified": 0,
            "restored": [],
            "resultReceiptsRestored": 0,
            "errors": [],
        }
    restored: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    result_receipts_restored = 0
    for path in sorted(root.glob("*.json")):
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
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append({"path": str(path), "error": str(exc)[:300]})
    return {
        "verified": len(restored),
        "restored": restored,
        "resultReceiptsRestored": result_receipts_restored,
        "errors": errors,
    }


def recover_task_contexts(args: argparse.Namespace) -> dict[str, Any]:
    result = recover_shared_task_contexts(ledger(args.ledger))
    return {"ok": not result["errors"]} | result


def sync_queue(path: Path = LEDGER_PATH) -> dict[str, Any]:
    queue = fetch_cloud_queue()
    intents = verify_queue(queue, DispatchSigner(signing_key()))
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
            "taskContextRecovery": context_recovery,
            "prFollowup": {"status": "deferred", "reason": "task_context_recovery_failed"},
        }
    stale_terminal = store.reconcile_terminal_intents()
    superseded = store.reconcile_pending(
        {str(item["intentId"]) for item in intents if item.get("intentId")}
    )
    inserted = sum(store.enqueue(item) for item in intents)
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
                followup_import = {
                    "status": "imported",
                    "generatedAt": generated_at,
                    "ageMinutes": age_minutes,
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
        "taskContextRecovery": context_recovery,
        "prFollowup": followup_import,
    }


def publish_terminal_feedback(args: argparse.Namespace) -> dict[str, Any]:
    """Publish local terminal judgments into the integrity-checked cloud state."""

    rows = ledger(args.ledger).terminal_feedback()
    if not rows:
        return {
            "ok": True,
            "published": 0,
            "stateChanged": False,
            "publishAttempts": 0,
            "deferred": [],
            "errors": [],
        }

    github = GitHubClient()
    analyzed = iso_z(datetime.now(UTC))
    published: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    updates: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row["key"])
        try:
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
                deferred.append({"key": key, "reason": "issue_updated_after_local_snapshot"})
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
            errors.append({"key": key, "error": str(exc)[:240]})

    state_changed = False
    publish_attempts = 0
    if updates:
        state_changed, publish_attempts = _publish_controller_feedback_updates(updates)
    return {
        "ok": not errors,
        "published": len(published),
        "stateChanged": state_changed,
        "publishAttempts": publish_attempts,
        "deferred": deferred,
        "errors": errors,
    }


def _publish_controller_feedback_updates(
    updates: dict[str, dict[str, Any]], max_attempts: int = 5
) -> tuple[bool, int]:
    """Merge terminal updates without weakening the state branch stale-write guard."""

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
            cwd=ROOT,
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
                cwd=ROOT,
                timeout=90,
            )
            return True, attempt
        except RuntimeError as exc:
            if "state branch changed since restore" not in str(exc) or attempt == max_attempts:
                raise
            sleep(min(2**attempt, 8))
    raise RuntimeError("controller terminal feedback publish attempts exhausted")


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
    alerts = ledger(args.ledger).pending_alerts(min_age_minutes=args.min_age_minutes)
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
    candidates = store.dispatch_notification_candidates()
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
    }


def _hardware_inventory() -> set[str]:
    return {
        item.strip().casefold()
        for item in os.environ.get("RADAR_HARDWARE", "4090,5090,a100,v100").split(",")
        if item.strip()
    }


def _audit_intent(intent: dict[str, Any]) -> tuple[Any, Any]:
    match = ISSUE_URL.match(str(intent.get("issueUrl") or ""))
    if not match:
        raise RuntimeError("invalid issue URL")
    repo, number = match.groups()
    evidence = collect_evidence(
        GitHubClient(),
        repo,
        int(number),
        current_actor=os.environ.get("GITHUB_ACTOR", "Oxygen56"),
        hardware_inventory=_hardware_inventory(),
    )
    return evidence, authorize(_candidate(intent), evidence)


def _audit_payload(evidence: Any, verdict: Any) -> dict[str, Any]:
    return {
        "authorization": verdict.as_dict(),
        "evidenceDigest": evidence.digest,
        "liveAudit": {
            "capturedAt": iso_z(datetime.now(UTC)),
            "evidence": evidence.as_dict(),
        },
    }


def _private_task_limit() -> int | None:
    raw = os.environ.get("RADAR_MAX_ACTIVE_TASKS", "0").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("RADAR_MAX_ACTIVE_TASKS must be an integer") from exc
    if value < 0 or value > 64:
        raise RuntimeError("RADAR_MAX_ACTIVE_TASKS must be between 0 and 64")
    return value or None


def claim_intent(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    pending = {item["intentId"]: item for item in store.pending()}
    intent = pending.get(args.intent_id)
    if not intent:
        raise RuntimeError("intent is not pending")
    evidence, verdict = _audit_intent(intent)
    if verdict.status == "BLOCK":
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
        return {
            "ok": True,
            "authorized": False,
            "held": True,
            "decision": verdict.as_dict(),
        }
    store.record_stage(
        intent["key"],
        "AUDIT_PASS",
        evidence=_audit_payload(evidence, verdict),
        dedupe_key=f"{intent['intentId']}:{evidence.digest}:live-audit-v1",
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
    max_active = _private_task_limit()
    claimed = store.claim(
        intent["intentId"],
        args.owner,
        lease_minutes=args.lease_minutes,
        max_active=max_active,
    )
    if not claimed:
        wip_limited = (
            max_active is not None
            and store.active_dispatch_count(exclude_intent_id=intent["intentId"]) >= max_active
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
    }
    if args.prepare:
        try:
            path = source_repo(str(intent["repo"]))
            worktree = prepare_managed_worktree(
                path,
                intent_id=str(intent["intentId"]),
                repo=str(intent["repo"]),
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
    live_audit = context.get("liveAudit")
    if not isinstance(live_audit, dict) or not isinstance(live_audit.get("evidence"), dict):
        raise RuntimeError("task context live audit is invalid")
    return sha256_json(
        {
            "schemaVersion": TASK_CONTEXT_SCHEMA,
            "key": context.get("key"),
            "issueUrl": context.get("issueUrl"),
            "intentId": context.get("intentId"),
            "track": context.get("track"),
            "algorithmEvidence": context.get("algorithmEvidence"),
            "liveAuditDigest": live_audit["evidence"].get("digest"),
            "prFollowupPreparedHeadSha": prepared_head,
            "threadId": context.get("threadId"),
            "worktreePath": context.get("worktreePath"),
        }
    )


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
    _exclude_private_task_dir(cwd)
    private_dir = cwd / TASK_PRIVATE_DIR
    private_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    managed = _is_managed_worktree(cwd)
    project_root = GITHUB_ROOT.resolve() if managed else cwd.resolve()
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
    }
    payload["contextDigest"] = _task_context_digest(context, effective_prepared_head)
    path = private_dir / "task-context.json"
    bootstrap_path = None
    if managed:
        bootstrap_path = shared_context_path(issue_url)
        payload["bootstrapContextPath"] = str(bootstrap_path)
    _atomic_json(path, payload)
    if bootstrap_path is not None:
        _atomic_json(bootstrap_path, payload)
    return path


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
    thread_id = ""
    turn_id = ""
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
        ]
        process.stdin.write(
            b"".join((json.dumps(item) + "\n").encode("utf-8") for item in requests)
        )
        process.stdin.flush()
        buffer = b""
        deadline = monotonic() + 30
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while monotonic() < deadline and not thread_id:
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
                    if message.get("id") == 1:
                        thread_id = str(
                            ((message.get("result") or {}).get("thread") or {}).get("id") or ""
                        )
                        break
            if not thread_id:
                raise RuntimeError("app server did not create a root task")
            store.bind_creation_client(
                args.intent_id,
                owner=_active_owner(store, args),
                creation_token=args.creation_token,
                client_thread_id=thread_id,
            )
            process.stdin.write(
                (
                    json.dumps(
                        {
                            "id": 2,
                            "method": "turn/start",
                            "params": {
                                "threadId": thread_id,
                                "cwd": str(GITHUB_ROOT.resolve()),
                                "input": [{"type": "text", "text": prompt, "text_elements": []}],
                                "approvalPolicy": "never",
                                "sandboxPolicy": {"type": "dangerFullAccess"},
                                "summary": "auto",
                            },
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                ).encode("utf-8")
            )
            process.stdin.flush()
            deadline = monotonic() + 45
            while monotonic() < deadline and not turn_id:
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
                    if message.get("id") == 2:
                        turn_id = str(
                            ((message.get("result") or {}).get("turn") or {}).get("id") or ""
                        )
                        break
            if not turn_id:
                raise RuntimeError("app server did not start the root task turn")

            deadline = monotonic() + 30
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

            # Keep the stdio owner alive until the task turn completes.
            while process.poll() is None:
                ready = selector.select(60)
                if not ready:
                    continue
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
                    if (
                        message.get("method") == "turn/completed"
                        and str((message.get("params") or {}).get("threadId") or "") == thread_id
                    ):
                        return {"ok": True, "threadId": thread_id, "turnId": turn_id}
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
        if process.poll() is None:
            process.terminate()


def root_task_create(args: argparse.Namespace) -> dict[str, Any]:
    receipt = STATE / "root_task_receipts" / f"{args.creation_token}.json"
    receipt.unlink(missing_ok=True)
    log = STATE / "root_task_receipts" / f"{args.creation_token}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as handle:
        subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--ledger",
                str(args.ledger),
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
    deadline = monotonic() + 60
    while monotonic() < deadline:
        if receipt.exists():
            result = read_json(receipt, missing={})
            if not result.get("ok"):
                raise RuntimeError(str(result.get("error") or "root task creation failed"))
            return result
        sleep(0.25)
    raise RuntimeError("root task creation result is unknown; orphan reconciliation required")


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


def _task_result_path(candidate: dict[str, Any]) -> Path:
    return Path(candidate["worktreePath"]).resolve() / TASK_PRIVATE_DIR / "result.json"


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
    result_path: Path,
) -> tuple[dict[str, Any], bytes]:
    worktree = Path(candidate["worktreePath"]).resolve()
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
    default_branch = _prepared_default_branch(worktree)
    publication = finalized.get("publication")
    if default_branch and isinstance(publication, dict):
        finalized_publication = dict(publication)
        finalized_publication["baseBranch"] = default_branch
        finalized["publication"] = finalized_publication
    _atomic_json(result_path, finalized)
    return finalized, result_path.read_bytes()


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
        if not set(commit_changed_files).issubset(cumulative):
            raise RuntimeError("PR follow-up commit files are missing from the cumulative diff")
        return cumulative
    if context.get("stage") != "VALIDATION_PENDING":
        return commit_changed_files
    default_branch = _prepared_default_branch(worktree)
    if not default_branch:
        raise RuntimeError("validation continuation lacks a prepared default branch")
    tracking_ref = f"refs/remotes/origin/{default_branch}"
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
    if not set(commit_changed_files).issubset(cumulative):
        raise RuntimeError("validation commit files are missing from the cumulative diff")
    return cumulative


def _finalize_controller_commit(
    *,
    candidate: dict[str, Any],
    context: dict[str, Any],
    value: dict[str, Any],
    result_path: Path,
) -> tuple[dict[str, Any], bytes]:
    if value.get("handoffMode") == "controller_merge_required":
        return _finalize_controller_merge(
            candidate=candidate,
            context=context,
            value=value,
            result_path=result_path,
        )
    if value.get("handoffMode") == "controller_commit_complete":
        worktree = Path(candidate["worktreePath"]).resolve()
        commit_changed_files = _validated_changed_files(
            value.get("controllerCommitChangedFiles") or value.get("changedFiles")
        )
        publication_changed_files = (
            _validation_publication_changed_files(
                worktree=worktree,
                context=context,
                commit_changed_files=commit_changed_files,
            )
            if context.get("stage") == "VALIDATION_PENDING"
            or isinstance(context.get("prFollowup"), dict)
            else _validated_changed_files(value.get("changedFiles"))
        )
        if not set(commit_changed_files).issubset(publication_changed_files):
            raise RuntimeError("controller commit files are missing from publication evidence")
        finalized = dict(value)
        finalized["controllerCommitChangedFiles"] = commit_changed_files
        finalized["changedFiles"] = publication_changed_files
        _atomic_json(result_path, finalized)
        return finalized, result_path.read_bytes()
    if value.get("handoffMode") != "controller_commit_required":
        return value, result_path.read_bytes()

    worktree = Path(candidate["worktreePath"]).resolve()
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
    expected_parent = ""
    if isinstance(followup, dict):
        expected_parent = str(followup.get("preparedHeadSha") or followup.get("headSha") or "")
        if not re.fullmatch(r"[0-9a-f]{40}", expected_parent):
            raise RuntimeError("controller commit lacks a valid PR follow-up parent")
    if actual:
        if actual != changed_files:
            raise RuntimeError(
                "controller commit changedFiles mismatch: "
                f"expected={changed_files!r} actual={actual!r}"
            )
        _switch_controller_branch(worktree, branch)
        if (
            expected_parent
            and command(["git", "rev-parse", "HEAD"], cwd=worktree) != expected_parent
        ):
            raise RuntimeError("controller commit parent drifted from the prepared PR follow-up")
        command(["git", "add", "--", *changed_files], cwd=worktree)
        _require_git_identity(worktree, context, value)
        command(
            _commit_args(context=context, value=value, commit_message=commit_message), cwd=worktree
        )
    else:
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
    if committed != changed_files:
        raise RuntimeError("controller commit does not match changedFiles")

    finalized = dict(value)
    finalized["commitSha"] = command(["git", "rev-parse", "HEAD"], cwd=worktree)
    finalized["branch"] = command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree)
    finalized["controllerCommitChangedFiles"] = changed_files
    finalized["changedFiles"] = _validation_publication_changed_files(
        worktree=worktree,
        context=context,
        commit_changed_files=changed_files,
    )
    finalized["handoffMode"] = "controller_commit_complete"
    default_branch = _prepared_default_branch(worktree)
    publication = finalized.get("publication")
    if default_branch and isinstance(publication, dict):
        finalized_publication = dict(publication)
        finalized_publication["baseBranch"] = default_branch
        finalized["publication"] = finalized_publication
    _atomic_json(result_path, finalized)
    return finalized, result_path.read_bytes()


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
                    != _task_context_digest(legacy_context, legacy_prepared_head)
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
    superseded = store.reconcile_superseded_pr_followups()
    prepared_recovered, errors = _recover_unbound_pr_followup_preparations(store)
    preparation_error_keys = {item["key"] for item in errors}
    for candidate in store.task_context_candidates():
        if candidate["key"] in preparation_error_keys:
            continue
        try:
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
                store.record_audit_snapshot(
                    candidate["key"],
                    evidence=_audit_payload(evidence, verdict),
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
        "errors": errors,
    }


def pr_followup_list(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    candidates = store.pr_followup_candidates()
    unresolved = store.unresolved_pr_followups()
    recent_cutoff = int(
        (datetime.now(UTC) - timedelta(minutes=PR_FOLLOWUP_ACTIVE_DEFERRAL_MINUTES)).timestamp()
    )
    activity: dict[str, int] = {}
    if candidates or unresolved:
        thread_ids = sorted(
            {str(item["threadId"]) for item in candidates}
            | {str(item["thread_id"]) for item in unresolved if item.get("thread_id")}
        )
        placeholders = ",".join("?" for _ in thread_ids)
        connection = sqlite3.connect(THREAD_DB)
        try:
            rows = connection.execute(
                f"SELECT id,updated_at FROM threads WHERE id IN ({placeholders})",
                thread_ids,
            ).fetchall()
            activity = {str(row[0]): int(row[1] or 0) for row in rows}
        finally:
            connection.close()
    ready: list[dict[str, Any]] = []
    active_deferred: list[dict[str, Any]] = []
    for candidate in candidates:
        updated_at = activity.get(str(candidate["threadId"]), 0)
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
    minimum_age_minutes = max(
        1,
        int(
            getattr(
                args,
                "min_age_minutes",
                PR_FOLLOWUP_ABANDON_MIN_AGE_MINUTES,
            )
        ),
    )
    now = datetime.now(UTC)
    unresolved_with_recovery: list[dict[str, Any]] = []
    for item in unresolved:
        reserved_at = parse_time(str(item["created_at"]))
        age_minutes = max(0, int((now - reserved_at).total_seconds() // 60))
        thread_updated_at = activity.get(str(item.get("thread_id") or ""), 0)
        target_turn_materialized = thread_updated_at >= int(reserved_at.timestamp())
        abandonable = age_minutes >= minimum_age_minutes and not target_turn_materialized
        value = item | {
            "ageMinutes": age_minutes,
            "threadUpdatedAt": thread_updated_at,
            "targetTurnMaterialized": target_turn_materialized,
            "abandonable": abandonable,
        }
        if abandonable:
            value["abandonNonce"] = sha256_json(
                {
                    "threadId": item.get("thread_id"),
                    "wakeDigest": item.get("wake_digest"),
                    "reservedAt": item.get("created_at"),
                    "threadUpdatedAt": thread_updated_at,
                    "operation": "pr-followup-delivery-abandon-v1",
                }
            )
        unresolved_with_recovery.append(value)
    return {
        "ok": not unresolved_with_recovery,
        "candidates": ready,
        "activeDeferred": active_deferred,
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


def _prepare_pr_followup(candidate: dict[str, Any]) -> dict[str, Any]:
    worktree = Path(candidate["worktreePath"]).resolve()
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
        command(
            [
                "git",
                "fetch",
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
            if evidence.get("baseIntegrationRequired") is True or not fast_forward:
                raise RuntimeError("PR base changed while preparing follow-up")
            base_sha = fetched_base
    command(
        ["git", "fetch", "--quiet", "--no-tags", remote, f"pull/{number}/head"],
        cwd=worktree,
        timeout=300,
    )
    fetched = command(["git", "rev-parse", "FETCH_HEAD"], cwd=worktree)
    if fetched != candidate["headSha"]:
        raise RuntimeError("PR head changed while preparing follow-up")
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
            raise RuntimeError("PR merge conflict no longer reproduces on the prepared base")
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
        raise RuntimeError("PR base integration is no longer a clean merge")
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


def pr_followup_reserve(args: argparse.Namespace) -> dict[str, Any]:
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
    prepared = _prepare_pr_followup(candidate)
    prepared_head = str(prepared["preparedHeadSha"])
    reserved = store.reserve_pr_followup(
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=prepared_head,
        prepared_base_sha=prepared.get("preparedBaseSha"),
        merge_conflict_files=prepared.get("mergeConflictFiles"),
    )
    context_path = write_task_context(
        store,
        issue_url=candidate["issueUrl"],
        thread_id=candidate["threadId"],
        cwd=Path(candidate["worktreePath"]),
        prepared_followup_head=prepared_head,
    )
    return {
        "ok": True,
        "key": reserved["key"],
        "threadId": reserved["threadId"],
        "prUrl": reserved["prUrl"],
        "wakeDigest": reserved["wakeDigest"],
        "contextPath": str(context_path),
        "prompt": issue_prompt(reserved["issueUrl"]),
    }


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
    "lacks locked dependency",
    "module lookup disabled",
    "goproxy=off",
    "node_modules",
    "vitest was unavailable",
    "prettier was unavailable",
    "eslint was unavailable",
    "next.js was unavailable",
    "pytest is not installed",
    "no module named pytest",
    "no module named",
    "is not installed",
    "missing numpy",
    "missing torch",
    "executable is unavailable",
)


def _validation_prefetch_plan(
    candidate: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    worktree = Path(candidate["worktreePath"]).resolve()
    result_path = worktree / ".oss-pr-radar" / "result.json"
    raw = result_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != candidate["resultDigest"]:
        raise RuntimeError("validation result changed after it was queued")
    result = json.loads(raw)
    tests = result.get("tests") if isinstance(result, dict) else None
    if not isinstance(tests, list):
        return [], []
    failed = [
        item for item in tests if isinstance(item, dict) and item.get("exitCode") not in {None, 0}
    ]
    dependency_failures = [
        item
        for item in failed
        if any(
            marker in f"{item.get('command', '')}\n{item.get('summary', '')}".casefold()
            for marker in VALIDATION_DEPENDENCY_FAILURE_MARKERS
        )
    ]
    if not dependency_failures:
        return [], []

    commands: list[dict[str, Any]] = []
    combined = "\n".join(str(item.get("command") or "") for item in dependency_failures)
    if "cargo " in combined and (worktree / "Cargo.lock").is_file():
        commands.append(
            {
                "kind": "cargo_locked_fetch",
                "cwd": str(worktree),
                "argv": ["cargo", "fetch", "--locked"],
            }
        )

    if "go test" in combined:
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
        for root in sorted(roots, key=str):
            commands.append(
                {
                    "kind": "go_locked_download",
                    "cwd": str(root),
                    "argv": ["go", "mod", "download"],
                }
            )
    if (
        ("pytest" in combined or "python -m" in combined or "python3 -m" in combined)
        and (worktree / "uv.lock").is_file()
        and (worktree / "pyproject.toml").is_file()
    ):
        commands.append(
            {
                "kind": "uv_locked_sync",
                "cwd": str(worktree),
                "argv": ["uv", "sync", "--frozen", "--no-install-project"],
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
    return commands, dependency_failures


def _validation_prefetch_commands(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    commands, _dependency_failures = _validation_prefetch_plan(candidate)
    return commands


def _execute_validation_prefetch(
    candidate: dict[str, Any], commands: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Run only the deterministic lockfile prefetch plan built by this bridge."""

    worktree = Path(candidate["worktreePath"]).resolve()
    allowed_argv = {
        "cargo_locked_fetch": ["cargo", "fetch", "--locked"],
        "go_locked_download": ["go", "mod", "download"],
        "uv_locked_sync": ["uv", "sync", "--frozen", "--no-install-project"],
        "npm_locked_install": [
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
    }
    completed: list[dict[str, Any]] = []
    for item in commands:
        kind = item.get("kind")
        argv = item.get("argv")
        cwd_value = item.get("cwd")
        if kind not in allowed_argv or argv != allowed_argv[kind]:
            raise RuntimeError("validation prefetch command is not allowlisted")
        if not isinstance(cwd_value, str):
            raise RuntimeError("validation prefetch cwd is invalid")
        cwd = Path(cwd_value).resolve()
        if cwd != worktree and worktree not in cwd.parents:
            raise RuntimeError("validation prefetch cwd escapes the prepared worktree")
        if not cwd.is_dir():
            raise RuntimeError("validation prefetch cwd does not exist")
        started = monotonic()
        command(argv, cwd=cwd, timeout=VALIDATION_PREFETCH_TIMEOUTS[kind])
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
    reconciled_no_progress = store.reconcile_validation_no_progress()
    candidates: list[dict[str, Any]] = []
    environment_blocked: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for candidate in store.validation_followup_candidates():
        try:
            commands, dependency_failures = _validation_prefetch_plan(candidate)
            if dependency_failures and not commands:
                environment_blocked.append(
                    candidate
                    | {
                        "reason": "DEPENDENCY_ENVIRONMENT_UNAVAILABLE",
                        "dependencyFailures": [
                            {
                                "command": str(item.get("command") or "")[:300],
                                "summary": str(item.get("summary") or "")[:300],
                            }
                            for item in dependency_failures
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
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    unresolved = store.unresolved_validation_followups()
    minimum_age_minutes = max(1, int(getattr(args, "min_age_minutes", 90)))
    activity: dict[str, int] = {}
    activity_available = THREAD_DB.is_file()
    if unresolved and activity_available:
        thread_ids = sorted({str(item["threadId"]) for item in unresolved if item.get("threadId")})
        placeholders = ",".join("?" for _ in thread_ids)
        connection = sqlite3.connect(THREAD_DB)
        try:
            rows = connection.execute(
                f"SELECT id,updated_at FROM threads WHERE id IN ({placeholders})",
                thread_ids,
            ).fetchall()
            activity = {str(row[0]): int(row[1] or 0) for row in rows}
        finally:
            connection.close()
    now = datetime.now(UTC)
    unresolved_with_recovery: list[dict[str, Any]] = []
    for item in unresolved:
        reserved_at = parse_time(str(item["reservedAt"]))
        age_minutes = max(0, int((now - reserved_at).total_seconds() // 60))
        thread_updated_at = activity.get(str(item.get("threadId") or ""), 0)
        target_turn_materialized = thread_updated_at >= int(reserved_at.timestamp())
        abandonable = (
            activity_available
            and age_minutes >= minimum_age_minutes
            and not target_turn_materialized
        )
        value = item | {
            "ageMinutes": age_minutes,
            "threadUpdatedAt": thread_updated_at,
            "targetTurnMaterialized": target_turn_materialized,
            "threadActivityAvailable": activity_available,
            "abandonable": abandonable,
        }
        if abandonable:
            value["abandonNonce"] = sha256_json(
                {
                    "threadId": item.get("threadId"),
                    "resultDigest": item.get("resultDigest"),
                    "reservedAt": item.get("reservedAt"),
                    "threadUpdatedAt": thread_updated_at,
                    "operation": "validation-followup-delivery-abandon-v1",
                }
            )
        unresolved_with_recovery.append(value)
    stale = store.stale_validation_followups(min_age_minutes=getattr(args, "min_age_minutes", 90))
    blocked_no_progress = store.validation_no_progress()
    return {
        "ok": not errors and not unresolved_with_recovery and not stale,
        "candidates": candidates,
        "environmentBlocked": environment_blocked,
        "unresolved": unresolved_with_recovery,
        "stale": stale,
        "blockedNoProgress": blocked_no_progress,
        "reconciledNoProgress": reconciled_no_progress,
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
    return {
        "ok": True,
        "threadId": args.thread_id,
        "resultDigest": args.result_digest,
        "abandoned": True,
    }


def _validation_followup_prompt(candidate: dict[str, Any]) -> str:
    missing = "、".join(str(item) for item in candidate.get("missing") or [])
    prefetch = bool(candidate.get("prefetchCommands"))
    dependency_note = (
        "控制器已经按锁文件预取缺失依赖；继续保持离线，使用项目虚拟环境或锁文件工具重新运行相关测试。"
        if prefetch
        else "无需新增依赖；直接补齐缺失证据并重新运行相关检查。"
    )
    return (
        "这是同一任务的验证续跑，不要创建新任务或重新实现。重新读取工作树内的 "
        ".oss-pr-radar/task-context.json，并只在其中记录的 worktreePath 继续。\n\n"
        f"当前缺失发布证据：{missing}。{dependency_note}\n\n"
        "必须依据真实运行结果更新 .oss-pr-radar/result.json：补充针对性回归测试；如以测试作为复现证据，"
        "需证明修复前失败、修复后通过。不得刷新 GitHub、不得安装依赖、不得请求权限、不得执行提交、推送、"
        "建 PR 或其他公开动作。若仍无法完成验证，保留对应 quality=false 并写清可复核原因；不得把格式检查"
        "当作功能验证。完成后正常结束，由控制器重新接收结果。"
    )


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
    enriched = candidate | {"prefetchCommands": _validation_prefetch_commands(candidate)}
    prefetch = _execute_validation_prefetch(enriched, enriched["prefetchCommands"])
    context_path = write_task_context(
        store,
        issue_url=enriched["issueUrl"],
        thread_id=enriched["threadId"],
        cwd=Path(enriched["worktreePath"]),
    )
    reserved = store.reserve_validation_followup(
        thread_id=enriched["threadId"], result_digest=enriched["resultDigest"]
    )
    return {
        "ok": True,
        "key": reserved["key"],
        "threadId": reserved["threadId"],
        "resultDigest": reserved["resultDigest"],
        "contextPath": str(context_path),
        "prefetch": prefetch,
        "prompt": _validation_followup_prompt(enriched),
    }


def validation_followup_commit(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).commit_validation_followup(
        thread_id=args.thread_id, result_digest=args.result_digest
    )
    return {
        "ok": True,
        "threadId": args.thread_id,
        "resultDigest": args.result_digest,
    }


def ingest_task_results(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    ingested: list[dict[str, Any]] = []
    publication_requests: list[dict[str, Any]] = []
    validation_deferred: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for candidate in store.task_result_candidates():
        result_path = _task_result_path(candidate)
        if not result_path.exists():
            continue
        try:
            raw = result_path.read_bytes()
            initial_digest = hashlib.sha256(raw).hexdigest()
            digest_seen = store.task_result_digest_seen(candidate["key"], initial_digest)
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise RuntimeError("task result must be an object")
            initial_quality = value.get("quality")
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
            ):
                continue
            context_path = result_path.parent / "task-context.json"
            context = json.loads(context_path.read_text(encoding="utf-8"))
            if not isinstance(context, dict):
                raise RuntimeError("task result context must be an object")
            controller_policy = _controller_policy_verification(context)
            expected = {
                "schemaVersion": TASK_RESULT_SCHEMA,
                "key": candidate["key"],
                "issueUrl": candidate["issueUrl"],
                "threadId": candidate["threadId"],
                "worktreePath": str(Path(candidate["worktreePath"]).resolve()),
            }
            for key, expected_value in expected.items():
                if value.get(key) != expected_value:
                    raise RuntimeError(f"task result mismatch: {key}")
            context_followup = context.get("prFollowup")
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
            if value.get("contextDigest") != context.get("contextDigest"):
                if digest_seen and possible_policy_recovery:
                    if controller_policy is None:
                        continue
                    value = dict(value)
                    value["contextDigest"] = context.get("contextDigest")
                elif legacy_compatible_result:
                    pass
                elif current_wake_digest and value.get("followupDigest") != current_wake_digest:
                    continue
                else:
                    raise RuntimeError("task result context digest mismatch")
            stage = str(value.get("stage") or "")
            quality = value.get("quality")
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
            if digest_seen and not policy_followup_exhausted and not controller_policy_recoverable:
                continue
            if candidate["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"} and (
                isinstance(context_followup, dict)
                and value.get("followupDigest") != context_followup.get("wakeDigest")
                and not legacy_compatible_result
            ):
                raise RuntimeError("task result PR follow-up digest mismatch")
            if stage == "AUDIT_NO_GO":
                if candidate["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}:
                    raise RuntimeError("an open PR follow-up cannot become AUDIT_NO_GO")
                digest = hashlib.sha256(raw).hexdigest()
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
                    result_path=result_path,
                )
                quality = value.get("quality")
                assert isinstance(quality, dict)
                digest = hashlib.sha256(raw).hexdigest()
                publication_blocked = _publication_block_reason(context, value)
                assessment = assess_submit_ready(quality)
                if (
                    policy_followup_exhausted
                    and not publication_blocked
                    and set(assessment.missing) == {"policy_verified"}
                ):
                    publication_blocked = "REPOSITORY_POLICY_EVIDENCE_REQUIRED"
                if candidate["stage"] != "FIX_READY" or controller_policy_recoverable:
                    local_policy_only = bool(
                        publication_blocked and set(assessment.missing) == {"policy_verified"}
                    )
                    if not assessment.ready and not local_policy_only:
                        missing = list(assessment.missing)
                        store.record_validation_deferred(
                            candidate["key"],
                            thread_id=candidate["threadId"],
                            result_digest=digest,
                            missing=missing,
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
                        store.record_task_result_ingested(
                            candidate["key"], digest=digest, stage="VALIDATION_PENDING"
                        )
                        validation_deferred.append(
                            {
                                "key": candidate["key"],
                                "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
                                "missing": missing,
                            }
                        )
                        ingested.append(
                            {
                                "key": candidate["key"],
                                "stage": "VALIDATION_PENDING",
                                "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
                            }
                        )
                        continue
                    store.record_stage(
                        candidate["key"],
                        "FIX_READY",
                        evidence=(
                            quality | {"publication_blocked_reason": publication_blocked}
                            if publication_blocked
                            else quality
                        ),
                        dedupe_key=digest,
                    )
                if publication_blocked:
                    ingested.append(
                        {
                            "key": candidate["key"],
                            "stage": stage,
                            "publicationBlockedReason": publication_blocked,
                        }
                    )
                else:
                    request = request_publication(
                        store,
                        issue_url=candidate["issueUrl"],
                        thread_id=candidate["threadId"],
                        worktree=Path(candidate["worktreePath"]),
                        evidence_path=result_path,
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
            elif stage == "PR_OPEN":
                if candidate["stage"] not in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}:
                    raise RuntimeError("PR_OPEN result is only valid for an existing PR follow-up")
                evidence = value.get("evidence")
                if not isinstance(evidence, dict):
                    raise RuntimeError("PR_OPEN follow-up result requires evidence")
                digest = hashlib.sha256(raw).hexdigest()
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
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    return {
        "ok": not errors,
        "ingested": ingested,
        "publicationRequests": publication_requests,
        "validationDeferred": validation_deferred,
        "errors": errors,
    }


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


def _executor(operation: str, arguments: list[str], *, ledger_path: Path) -> dict[str, Any]:
    raw = command(
        [
            sys.executable,
            str(ROOT / "scripts" / "publication_executor.py"),
            "--ledger",
            str(ledger_path),
            operation,
            *arguments,
        ],
        timeout=420,
    )
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError("publication executor returned an invalid result")
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
    published: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for item in store.publication_work_items():
        request_id = str(item["request_id"])
        request = item["request"]
        try:
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
                    blocked.append(
                        {
                            "requestId": request_id,
                            "reason": (broker.get("audit") or {}).get("reason"),
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
            push_result = (
                {"reconciled": True}
                if post_push_reconciliation
                else _executor(
                    "push",
                    [*common, "--remote", ensure_fork_remote(worktree, repo, head_owner)],
                    ledger_path=args.ledger,
                )
            )
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
                ledger_path=args.ledger,
            )
            published.append(
                {
                    "requestId": request_id,
                    "key": request["opportunityKey"],
                    "prUrl": pr_result.get("prUrl"),
                    "pushReconciled": push_result.get("reconciled", False),
                }
            )
        except (KeyError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append({"requestId": request_id, "error": str(exc)[:400]})
    return {
        "ok": not errors,
        "published": published,
        "pending": pending,
        "blocked": blocked,
        "errors": errors,
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
    permit = ledger(args.ledger).publication_permit(
        issue_url=args.issue_url,
        commit_sha=args.commit_sha,
        branch=args.branch,
    )
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
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    pending: list[dict[str, Any]] = []
    reconciled: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    try:
        for candidate in store.restore_candidates():
            row = connection.execute(
                "SELECT archived,title FROM threads WHERE id=?",
                (candidate["threadId"],),
            ).fetchone()
            if row is None:
                blocked.append(candidate | {"reason": "thread_missing"})
                continue
            if int(row["archived"] or 0) == 0:
                store.commit_restore(
                    thread_id=candidate["threadId"],
                    nonce=candidate["restoreNonce"],
                )
                reconciled.append(candidate | {"title": row["title"]})
                continue
            pending.append(candidate | {"title": row["title"]})
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
    candidates = {item["threadId"]: item for item in store.restore_candidates()}
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
    candidates = store.cleanup_candidates()
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
                store.commit_cleanup(
                    thread_id=candidate["threadId"],
                    nonce=candidate["cleanupNonce"],
                )
                if candidate.get("worktreePath") and _is_managed_worktree(
                    Path(candidate["worktreePath"])
                ):
                    shared_context_path(candidate["issueUrl"]).unlink(missing_ok=True)
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

    results = {str(item["threadId"]): "app_server_response_missing" for item in titles}
    if not titles:
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
    request_ids = {index: str(item["threadId"]) for index, item in enumerate(titles, 1)}
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
            }
        ]
        requests.extend(
            {
                "id": request_id,
                "method": "thread/name/set",
                "params": {
                    "threadId": request_ids[request_id],
                    "name": str(titles[request_id - 1]["desiredTitle"]),
                },
            }
            for request_id in request_ids
        )
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
                        "app_server_title_update_failed" if response.get("error") else None
                    )
        if 0 in pending:
            return {thread_id: "app_server_initialization_timeout" for thread_id in results}
        for request_id in pending:
            if request_id in request_ids:
                results[request_ids[request_id]] = "app_server_title_update_timeout"
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


def should_apply_pr_lifecycle_stage(current: str, remote: str) -> bool:
    """Keep local validation/update work authoritative until the PR is terminal."""
    if remote in TERMINAL_PR_STAGES:
        return current != remote
    if current in LOCAL_PR_ACTION_STAGES:
        return False
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
                        "state,mergedAt,reviewDecision,statusCheckRollup,url",
                    ],
                    timeout=45,
                )
            )
        except (RuntimeError, json.JSONDecodeError) as exc:
            errors.append({"key": item["key"], "error": str(exc)[:200]})
            continue
        stage = pr_lifecycle_stage(value)
        if should_apply_pr_lifecycle_stage(str(item["stage"]), stage):
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
    connection = sqlite3.connect(THREAD_DB)
    connection.row_factory = sqlite3.Row
    recoverable: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    activity_cutoff = int(
        (datetime.now(UTC) - timedelta(minutes=max(30, args.min_age_minutes))).timestamp()
    )
    try:
        for candidate in store.recovery_candidates(min_age_minutes=0):
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
            terminal_error = latest_terminal_thread_error(row["rollout_path"])
            immediate_recovery = bool(
                terminal_error and terminal_error.get("code") in IMMEDIATE_RECOVERY_ERROR_CODES
            )
            if int(row["updated_at"] or 0) > activity_cutoff and not immediate_recovery:
                continue
            recoverable.append(
                candidate
                | {
                    "currentTitle": row["title"],
                    "cwd": row["cwd"],
                    "threadUpdatedAt": row["updated_at"],
                    "terminalError": terminal_error,
                    "immediateRecovery": immediate_recovery,
                }
            )
    finally:
        connection.close()
    return {
        "ok": not blocked and not store.unresolved_recoveries(),
        "recoverable": recoverable,
        "blocked": blocked,
        "unresolved": store.unresolved_recoveries(),
    }


def recovery_reserve(args: argparse.Namespace) -> dict[str, Any]:
    candidate = ledger(args.ledger).reserve_recovery(
        thread_id=args.thread_id,
        nonce=args.recovery_nonce,
    )
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT rollout_path FROM threads WHERE id=?", (candidate["threadId"],)
        ).fetchone()
    finally:
        connection.close()
    terminal_error = latest_terminal_thread_error(row[0] if row else None)
    prompt = issue_prompt(candidate["issueUrl"])
    if terminal_error and terminal_error.get("code") == "cyber_policy":
        prompt = BENIGN_POLICY_RECOVERY_PROMPT
    return {
        "ok": True,
        "threadId": candidate["threadId"],
        "prompt": prompt,
        "recoveryNonce": candidate["recoveryNonce"],
        "terminalError": terminal_error,
    }


def recovery_commit(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).commit_recovery(
        thread_id=args.thread_id,
        nonce=args.recovery_nonce,
    )
    return {"ok": True, "threadId": args.thread_id}


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("sync")
    subparsers.add_parser("publish-terminal-feedback")
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
    subparsers.add_parser("context-recover")
    subparsers.add_parser("context-sync")
    pr_followup_list_parser = subparsers.add_parser("pr-followup-list")
    pr_followup_list_parser.add_argument(
        "--min-age-minutes",
        type=int,
        default=PR_FOLLOWUP_ABANDON_MIN_AGE_MINUTES,
    )
    pr_followup_reserve_parser = subparsers.add_parser("pr-followup-reserve")
    pr_followup_reserve_parser.add_argument("--thread-id", required=True)
    pr_followup_reserve_parser.add_argument("--wake-digest", required=True)
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
    validation_followup_commit_parser = subparsers.add_parser("validation-followup-commit")
    validation_followup_commit_parser.add_argument("--thread-id", required=True)
    validation_followup_commit_parser.add_argument("--result-digest", required=True)
    validation_followup_abandon_parser = subparsers.add_parser("validation-followup-abandon")
    validation_followup_abandon_parser.add_argument("--thread-id", required=True)
    validation_followup_abandon_parser.add_argument("--result-digest", required=True)
    validation_followup_abandon_parser.add_argument("--abandon-nonce", required=True)
    validation_followup_abandon_parser.add_argument("--reason", required=True)
    validation_followup_abandon_parser.add_argument("--min-age-minutes", type=int, default=90)
    subparsers.add_parser("ingest-results")
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
    recovery_reserve_parser = subparsers.add_parser("recovery-reserve")
    recovery_reserve_parser.add_argument("--thread-id", required=True)
    recovery_reserve_parser.add_argument("--recovery-nonce", required=True)
    recovery_commit_parser = subparsers.add_parser("recovery-commit")
    recovery_commit_parser.add_argument("--thread-id", required=True)
    recovery_commit_parser.add_argument("--recovery-nonce", required=True)
    task_context_parser = subparsers.add_parser("task-context")
    task_context_parser.add_argument("--issue-url", required=True)
    task_context_parser.add_argument("--thread-id")
    task_context_parser.add_argument("--worktree")
    task_context_parser.add_argument("--wait-seconds", type=float, default=180.0)
    metrics = subparsers.add_parser("metrics")
    metrics.add_argument("--days", type=int, default=30)
    args = parser.parse_args()
    if args.operation == "sync":
        result = sync_queue(args.ledger)
    elif args.operation == "publish-terminal-feedback":
        result = publish_terminal_feedback(args)
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
    elif args.operation == "orphan-commit":
        result = orphan_commit(args)
    elif args.operation == "duplicate-task-list":
        result = duplicate_task_list(args)
    elif args.operation == "duplicate-task-title-reconcile":
        result = duplicate_task_title_reconcile(args)
    elif args.operation == "outcome":
        result = record_outcome(args)
    elif args.operation == "request-publication":
        result = submit_publication_request(args)
    elif args.operation == "publication-check":
        result = publication_check(args)
    elif args.operation == "cleanup-list":
        result = cleanup_list(args)
    elif args.operation == "context-recover":
        result = recover_task_contexts(args)
    elif args.operation == "context-sync":
        result = sync_task_contexts(args)
    elif args.operation == "pr-followup-list":
        result = pr_followup_list(args)
    elif args.operation == "pr-followup-reserve":
        result = pr_followup_reserve(args)
    elif args.operation == "pr-followup-commit":
        result = pr_followup_commit(args)
    elif args.operation == "pr-followup-abandon":
        result = pr_followup_abandon(args)
    elif args.operation == "validation-followup-list":
        result = validation_followup_list(args)
    elif args.operation == "validation-followup-reserve":
        result = validation_followup_reserve(args)
    elif args.operation == "validation-followup-commit":
        result = validation_followup_commit(args)
    elif args.operation == "validation-followup-abandon":
        result = validation_followup_abandon(args)
    elif args.operation == "ingest-results":
        result = ingest_task_results(args)
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
    elif args.operation == "recovery-commit":
        result = recovery_commit(args)
    elif args.operation == "task-context":
        result = task_context(args)
    else:
        result = rolling_quality(args.ledger, days=args.days)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
