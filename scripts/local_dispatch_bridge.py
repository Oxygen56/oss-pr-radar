#!/usr/bin/env python3
"""Verify, lease, prepare, and receipt local issue-task dispatches."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
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
from oss_pr_radar.publication import (  # noqa: E402
    broker_publication_request,
    public_branch_is_safe,
    public_text_is_safe,
    request_publication,
)
from oss_pr_radar.util import iso_z, parse_time, sha256_json  # noqa: E402

STATE = ROOT / "state"
LEDGER_PATH = STATE / "radar_ledger.sqlite3"
THREAD_DB = Path.home() / ".codex" / "state_5.sqlite"
GITHUB_ROOT = Path.home() / "Documents" / "github"
WORKTREE_ROOT = Path.home() / ".codex" / "worktrees"
KEYCHAIN_SERVICE = "oss-pr-radar-dispatch"
ISSUE_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
DELEGATED_INPUT = re.compile(r"<input>(.*?)</input>", re.DOTALL)
MAX_TITLE_CHARS = 59
TASK_PRIVATE_DIR = ".oss-pr-radar"
TASK_CONTEXT_SCHEMA = "radar-task-context-v1"
TASK_RESULT_SCHEMA = "radar-task-result-v1"
ORPHAN_ABANDON_MIN_AGE_MINUTES = 70
TITLE_PREFIXES = {
    "GO": "[有价值·GO]",
    "AUDIT_NO_GO": "[无价值]",
    "FIX_READY": "[有价值·本地修复就绪]",
    "PUBLICATION_REQUEST": "[有价值·存在发布请求]",
    "PR_OPEN": "[有价值·PR已开]",
    "MERGED": "[有价值·已合并]",
}
PR_STAGE_PRIORITY = {
    "FIX_READY": 0,
    "PR_OPEN": 1,
    "CI_GREEN": 2,
    "MAINTAINER_ACCEPTED": 3,
    "MERGED": 4,
    "CLOSED": 4,
}
issue_prompt = canonical_prompt


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
    for path in GITHUB_ROOT.iterdir():
        if not path.is_dir() or not (path / ".git").exists():
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
        ) == git_path("rev-parse", "--path-format=absolute", "--git-dir", cwd=source)
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
    _exclude_private_task_dir(worktree)
    return worktree.resolve()


def fetch_cloud_queue() -> dict[str, Any]:
    command(["git", "fetch", "origin", "radar-state"], cwd=ROOT)
    raw = command(["git", "show", "FETCH_HEAD:dispatch_queue.json"], cwd=ROOT)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("invalid cloud queue")
    return value


def ledger(path: Path = LEDGER_PATH) -> RadarLedger:
    return RadarLedger(path)


def sync_queue(path: Path = LEDGER_PATH) -> dict[str, Any]:
    queue = fetch_cloud_queue()
    intents = verify_queue(queue, DispatchSigner(signing_key()))
    store = ledger(path)
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
    }


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
    if verdict.status != "ALLOW":
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


def release_claim(args: argparse.Namespace) -> dict[str, Any]:
    released = ledger(args.ledger).release_claim(
        args.intent_id,
        owner=args.owner,
        reason=args.reason,
    )
    if not released:
        raise RuntimeError("claim release authorization is stale or invalid")
    return {"ok": True, "intentId": args.intent_id, "released": True}


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


def write_task_context(store: RadarLedger, *, issue_url: str, thread_id: str, cwd: Path) -> Path:
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
    payload["contextDigest"] = sha256_json(
        {
            "schemaVersion": TASK_CONTEXT_SCHEMA,
            "key": context["key"],
            "issueUrl": context["issueUrl"],
            "intentId": context["intentId"],
            "track": context.get("track"),
            "algorithmEvidence": context.get("algorithmEvidence"),
            "liveAuditDigest": live_audit["evidence"].get("digest"),
            "threadId": context["threadId"],
            "worktreePath": context["worktreePath"],
        }
    )
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
    result = ledger(args.ledger).reserve_creation(args.intent_id, owner=args.owner)
    return {"ok": True} | result


def creation_bind(args: argparse.Namespace) -> dict[str, Any]:
    result = ledger(args.ledger).bind_creation_client(
        args.intent_id,
        owner=args.owner,
        creation_token=args.creation_token,
        client_thread_id=args.client_thread_id,
    )
    return {"ok": True} | result


def creation_cancel(args: argparse.Namespace) -> dict[str, Any]:
    ledger(args.ledger).cancel_creation(
        args.intent_id,
        owner=args.owner,
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
        raise RuntimeError("bound creation is not safely abandonable")
    if candidate.get("abandonNonce") != args.abandon_nonce:
        raise RuntimeError("creation abandonment authorization is stale or invalid")
    if candidate.get("clientThreadId") != args.client_thread_id:
        raise RuntimeError("bound client thread id changed")
    store = ledger(args.ledger)
    handoffs = {item["intentId"]: item for item in store.orphaned_handoffs()}
    handoff = handoffs.get(args.intent_id)
    if not handoff or not handoff.get("creationToken"):
        raise RuntimeError("stored creation authorization is unavailable")
    store.abandon_creation(
        args.intent_id,
        owner=args.owner,
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
        row = connection.execute(
            "SELECT cwd,title,first_user_message,git_origin_url,archived FROM threads WHERE id=?",
            (args.thread_id,),
        ).fetchone()
    finally:
        connection.close()
    expected_title = lifecycle_title("GO", args.title_time, intent["key"], intent["title"])
    if row is None or int(row["archived"] or 0) != 0:
        raise RuntimeError("thread is missing or archived")
    if Path(row["cwd"]).resolve() != thread_cwd:
        raise RuntimeError("thread cwd mismatch")
    if row["title"] != expected_title:
        raise RuntimeError("thread title mismatch")
    if canonical_prompt(row["first_user_message"] or "") != issue_prompt(intent["issueUrl"]):
        raise RuntimeError("thread prompt mismatch")
    if (
        not managed
        and normalize_origin(row["git_origin_url"] or "") != str(intent["repo"]).casefold()
    ):
        raise RuntimeError("thread origin mismatch")
    store.commit_dispatch(
        intent["intentId"],
        owner=args.owner,
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
               FROM threads WHERE archived=0"""
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
                    value["abandonable"] = bool(
                        handoff.get("clientThreadId")
                        and creation_age_minutes >= abandon_min_age_minutes
                    )
                    if value["abandonable"]:
                        value["abandonNonce"] = sha256_json(
                            {
                                "intentId": handoff["intentId"],
                                "clientThreadId": handoff["clientThreadId"],
                                "creationStartedAt": creation_started_at,
                                "creationToken": handoff.get("creationToken"),
                                "operation": "orphan-creation-abandon-v1",
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
    if (
        row is None
        or int(row[1] or 0) != 0
        or row[0] != args.desired_title
        or Path(row[2]).resolve() != thread_cwd
    ):
        raise RuntimeError("orphan thread title was not applied")
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


def _policy_from_context(context: dict[str, Any]) -> dict[str, Any]:
    live_audit = context.get("liveAudit")
    evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else None
    policy = evidence.get("policy") if isinstance(evidence, dict) else None
    return policy if isinstance(policy, dict) else {}


def _finalize_controller_commit(
    *,
    candidate: dict[str, Any],
    context: dict[str, Any],
    value: dict[str, Any],
    result_path: Path,
) -> tuple[dict[str, Any], bytes]:
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
    if actual:
        if actual != changed_files:
            raise RuntimeError(
                "controller commit changedFiles mismatch: "
                f"expected={changed_files!r} actual={actual!r}"
            )
        _switch_controller_branch(worktree, branch)
        command(["git", "add", "--", *changed_files], cwd=worktree)
        commit_args = ["git", "commit", "-m", commit_message]
        policy = _policy_from_context(context)
        if policy.get("dco") is True or value.get("dcoRequired") is True:
            name = command(["git", "config", "user.name"], cwd=worktree)
            email = command(["git", "config", "user.email"], cwd=worktree)
            if not name or not email:
                raise RuntimeError("DCO sign-off requires configured Git identity")
            commit_args.insert(2, "--signoff")
        command(commit_args, cwd=worktree)
    else:
        # Recover idempotently if the process stopped after the commit but before
        # rewriting result.json.
        _switch_controller_branch(worktree, branch)
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
    finalized["changedFiles"] = changed_files
    finalized["handoffMode"] = "controller_commit_complete"
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


def sync_task_contexts(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    written: list[dict[str, str]] = []
    refreshed: list[dict[str, str]] = []
    no_go: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for candidate in store.task_context_candidates():
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
        "noGo": no_go,
        "errors": errors,
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
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise RuntimeError("task result must be an object")
            context_path = result_path.parent / "task-context.json"
            context = json.loads(context_path.read_text(encoding="utf-8"))
            if not isinstance(context, dict) or value.get("contextDigest") != context.get(
                "contextDigest"
            ):
                raise RuntimeError("task result context digest mismatch")
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
            stage = str(value.get("stage") or "")
            if stage == "AUDIT_NO_GO":
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
                quality = value.get("quality")
                if not isinstance(quality, dict):
                    raise RuntimeError("FIX_READY requires a quality object")
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
                if candidate["stage"] != "FIX_READY":
                    assessment = assess_submit_ready(quality)
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
                            "AUDIT_NO_GO",
                            evidence={
                                "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
                                "missing": missing,
                                "resultDigest": digest,
                            },
                            reason="SUBMIT_READY_EVIDENCE_INCOMPLETE",
                            dedupe_key=digest,
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
                                "stage": "AUDIT_NO_GO",
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
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
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
            remote = ensure_fork_remote(worktree, repo, head_owner)
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
            push_result = _executor("push", [*common, "--remote", remote], ledger_path=args.ledger)
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
    values = []
    for candidate in ledger(args.ledger).title_candidates():
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
        current_priority = PR_STAGE_PRIORITY.get(str(item["stage"]), -1)
        if PR_STAGE_PRIORITY[stage] > current_priority:
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
    try:
        for candidate in store.recovery_candidates(min_age_minutes=args.min_age_minutes):
            row = connection.execute(
                "SELECT archived,title,first_user_message,cwd,git_origin_url,updated_at "
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
            recoverable.append(
                candidate
                | {
                    "currentTitle": row["title"],
                    "cwd": row["cwd"],
                    "threadUpdatedAt": row["updated_at"],
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
    return {
        "ok": True,
        "threadId": candidate["threadId"],
        "prompt": issue_prompt(candidate["issueUrl"]),
        "recoveryNonce": candidate["recoveryNonce"],
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
    claim_release.add_argument("--owner", required=True)
    claim_release.add_argument("--reason", required=True)
    commit = subparsers.add_parser("commit")
    commit.add_argument("--intent-id", required=True)
    commit.add_argument("--owner", required=True)
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
    creation_start_parser.add_argument("--owner", required=True)
    creation_bind_parser = subparsers.add_parser("creation-bind")
    creation_bind_parser.add_argument("--intent-id", required=True)
    creation_bind_parser.add_argument("--owner", required=True)
    creation_bind_parser.add_argument("--creation-token", required=True)
    creation_bind_parser.add_argument("--client-thread-id", required=True)
    creation_cancel_parser = subparsers.add_parser("creation-cancel")
    creation_cancel_parser.add_argument("--intent-id", required=True)
    creation_cancel_parser.add_argument("--owner", required=True)
    creation_cancel_parser.add_argument("--creation-token", required=True)
    creation_cancel_parser.add_argument("--reason", required=True)
    creation_abandon_parser = subparsers.add_parser("creation-abandon")
    creation_abandon_parser.add_argument("--intent-id", required=True)
    creation_abandon_parser.add_argument("--owner", required=True)
    creation_abandon_parser.add_argument("--client-thread-id", required=True)
    creation_abandon_parser.add_argument("--abandon-nonce", required=True)
    creation_abandon_parser.add_argument("--reason", required=True)
    creation_abandon_parser.add_argument(
        "--min-age-minutes", type=int, default=ORPHAN_ABANDON_MIN_AGE_MINUTES
    )
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
    subparsers.add_parser("context-sync")
    subparsers.add_parser("ingest-results")
    subparsers.add_parser("publication-run")
    publication_retry_parser = subparsers.add_parser("publication-retry")
    publication_retry_parser.add_argument("--request-id", required=True)
    publication_retry_parser.add_argument("--expected-reason", required=True)
    cleanup_commit_parser = subparsers.add_parser("cleanup-commit")
    cleanup_commit_parser.add_argument("--thread-id", required=True)
    cleanup_commit_parser.add_argument("--cleanup-nonce", required=True)
    subparsers.add_parser("title-list")
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
    elif args.operation == "orphan-list":
        result = orphan_list(args)
    elif args.operation == "orphan-commit":
        result = orphan_commit(args)
    elif args.operation == "outcome":
        result = record_outcome(args)
    elif args.operation == "request-publication":
        result = submit_publication_request(args)
    elif args.operation == "publication-check":
        result = publication_check(args)
    elif args.operation == "cleanup-list":
        result = cleanup_list(args)
    elif args.operation == "context-sync":
        result = sync_task_contexts(args)
    elif args.operation == "ingest-results":
        result = ingest_task_results(args)
    elif args.operation == "publication-run":
        result = run_publication_queue(args)
    elif args.operation == "publication-retry":
        result = retry_blocked_publication(args)
    elif args.operation == "cleanup-commit":
        result = cleanup_commit(args)
    elif args.operation == "title-list":
        result = title_list(args)
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
