#!/usr/bin/env python3
"""Verify, lease, prepare, and receipt local issue-task dispatches."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime
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
from oss_pr_radar.notifier import FeishuClient, NotificationError  # noqa: E402
from oss_pr_radar.publication import broker_publication_request, request_publication  # noqa: E402
from oss_pr_radar.util import parse_time, sha256_json  # noqa: E402

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
            command(["git", "fetch", "--prune", "origin"], cwd=path)
            return path.resolve()
    destination = GITHUB_ROOT / repo.rsplit("/", 1)[1]
    if destination.exists():
        destination = GITHUB_ROOT / repo.replace("/", "--")
    command(
        [
            "git",
            "clone",
            "--filter=blob:none",
            f"https://github.com/{repo}.git",
            str(destination),
        ],
        timeout=900,
    )
    return destination.resolve()


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
                    "title": {"tag": "plain_text", "content": "OSS PR Radar 派发超时"},
                    "template": "red",
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": "\n".join(
                                f"**[{item['key']}]({item['issueUrl']})**："
                                f"等待 {item['pendingAgeMinutes']} 分钟，{item['alertCode']}"
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


def _candidate(intent: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo": intent["repo"],
        "num": intent["issueNumber"],
        "url": intent["issueUrl"],
        "title": intent["title"],
        "category": intent["category"],
        "gate_decision": intent.get("scanGate"),
        "auto_spawn": intent.get("autoSpawn") is True,
        "llm_review": intent.get("llmReview") or {},
    }


def claim_intent(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    pending = {item["intentId"]: item for item in store.pending()}
    intent = pending.get(args.intent_id)
    if not intent:
        raise RuntimeError("intent is not pending")
    match = ISSUE_URL.match(str(intent.get("issueUrl") or ""))
    if not match:
        raise RuntimeError("invalid issue URL")
    repo, number = match.groups()
    inventory = {
        item.strip().casefold()
        for item in os.environ.get("RADAR_HARDWARE", "4090,5090,a100,v100").split(",")
        if item.strip()
    }
    evidence = collect_evidence(
        GitHubClient(),
        repo,
        int(number),
        current_actor=os.environ.get("GITHUB_ACTOR", "Oxygen56"),
        hardware_inventory=inventory,
    )
    verdict = authorize(_candidate(intent), evidence)
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
        evidence={
            "authorization": verdict.as_dict(),
            "evidenceDigest": evidence.digest,
        },
        dedupe_key=f"{intent['intentId']}:{evidence.digest}",
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
    canary = intent.get("mode") == "canary"
    claimed = store.claim(
        intent["intentId"],
        args.owner,
        lease_minutes=args.lease_minutes,
        max_active=1 if canary else None,
    )
    if not claimed:
        wip_limited = (
            canary and store.active_dispatch_count(exclude_intent_id=intent["intentId"]) >= 1
        )
        return {
            "ok": True,
            "authorized": True,
            "claimed": False,
            "reason": "canary_wip_limit" if wip_limited else "lease_unavailable",
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
        path = source_repo(str(intent["repo"]))
        command(["codex", "app", str(path)], timeout=30)
        title_time = datetime.now().astimezone().strftime("%m-%d %H:%M")
        result["sourceRepoPath"] = str(path)
        result["titleTime"] = title_time
        result["desiredTitle"] = lifecycle_title("GO", title_time, intent["key"], intent["title"])
    return result


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
    _exclude_private_task_dir(cwd)
    private_dir = cwd / TASK_PRIVATE_DIR
    private_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_dir, 0o700)
    payload = {
        "schemaVersion": TASK_CONTEXT_SCHEMA,
        **context,
        "resultPath": str((private_dir / "result.json").resolve()),
        "controllerOwnsLifecycle": True,
        "controllerOwnsPublication": True,
        "externalLedgerAccessAllowed": False,
        "planHubRequired": False,
    }
    payload["contextDigest"] = sha256_json(
        {
            "schemaVersion": TASK_CONTEXT_SCHEMA,
            "key": context["key"],
            "issueUrl": context["issueUrl"],
            "intentId": context["intentId"],
            "threadId": context["threadId"],
            "worktreePath": context["worktreePath"],
        }
    )
    path = private_dir / "task-context.json"
    _atomic_json(path, payload)
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


def commit_receipt(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    pending = {item["intentId"]: item for item in store.pending()}
    intent = pending.get(args.intent_id)
    if not intent:
        raise RuntimeError("intent is not pending")
    source = Path(args.source_repo).resolve()
    cwd = Path(args.cwd).resolve()
    if cwd == source or WORKTREE_ROOT.resolve() not in cwd.parents:
        raise RuntimeError("thread cwd is not a Codex worktree")
    if git_path("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=cwd) != git_path(
        "rev-parse", "--path-format=absolute", "--git-dir", cwd=source
    ):
        raise RuntimeError("worktree does not belong to source repository")
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
    if Path(row["cwd"]).resolve() != cwd:
        raise RuntimeError("thread cwd mismatch")
    if row["title"] != expected_title:
        raise RuntimeError("thread title mismatch")
    if canonical_prompt(row["first_user_message"] or "") != issue_prompt(intent["issueUrl"]):
        raise RuntimeError("thread prompt mismatch")
    if normalize_origin(row["git_origin_url"] or "") != str(intent["repo"]).casefold():
        raise RuntimeError("thread origin mismatch")
    store.commit_dispatch(
        intent["intentId"],
        owner=args.owner,
        thread_id=args.thread_id,
        project_id=args.project_id,
        worktree_path=str(cwd),
        title_time=args.title_time,
    )
    context_path = write_task_context(
        store,
        issue_url=intent["issueUrl"],
        thread_id=args.thread_id,
        cwd=cwd,
    )
    return {
        "ok": True,
        "key": intent["key"],
        "threadId": args.thread_id,
        "taskContextPath": str(context_path),
    }


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
    worktree_root = WORKTREE_ROOT.resolve()
    for handoff in handoffs:
        creation_started_at = handoff.get("creationStartedAt")
        started = parse_time(
            str(creation_started_at or handoff["leaseStartedAt"])
        ).timestamp() - 60
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
            if normalize_origin(row["git_origin_url"] or "") != str(handoff["repo"]).casefold():
                continue
            cwd = Path(row["cwd"]).resolve()
            if cwd == worktree_root or worktree_root not in cwd.parents:
                continue
            matches.append(row)
        if not matches:
            lease_until = parse_time(str(lease_end)).timestamp()
            if handoff["intentStatus"] == "CREATING" or (
                handoff["intentStatus"] == "LEASED" and lease_until > now
            ):
                unmatched.append(
                    {
                        "intentId": handoff["intentId"],
                        "key": handoff["key"],
                        "leaseStartedAt": handoff["leaseStartedAt"],
                        "creationStartedAt": creation_started_at,
                        "clientThreadId": handoff.get("clientThreadId"),
                        "creationPending": handoff["intentStatus"] == "CREATING",
                    }
                )
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
        created = _thread_created_at(row)
        title_time = datetime.fromtimestamp(created).astimezone().strftime("%m-%d %H:%M")
        nonce = sha256_json(
            {
                "intentId": handoff["intentId"],
                "threadId": row["id"],
                "leaseStartedAt": handoff["leaseStartedAt"],
                "operation": "orphan-dispatch-reconcile-v1",
            }
        )
        candidates.append(
            handoff
            | {
                "threadId": row["id"],
                "cwd": row["cwd"],
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
    cwd = Path(candidate["cwd"]).resolve()
    if (
        normalize_origin(command(["git", "remote", "get-url", "origin"], cwd=source))
        != str(candidate["repo"]).casefold()
    ):
        raise RuntimeError("source repository origin mismatch")
    if git_path("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=cwd) != git_path(
        "rev-parse", "--path-format=absolute", "--git-dir", cwd=source
    ):
        raise RuntimeError("orphan worktree does not belong to source repository")
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT title,archived FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[1] or 0) != 0 or row[0] != args.desired_title:
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


def sync_task_contexts(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    written: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for candidate in store.task_result_candidates():
        try:
            path = write_task_context(
                store,
                issue_url=candidate["issueUrl"],
                thread_id=candidate["threadId"],
                cwd=Path(candidate["worktreePath"]),
            )
            written.append({"key": candidate["key"], "path": str(path)})
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append({"key": candidate["key"], "error": str(exc)[:300]})
    return {"ok": not errors, "written": written, "errors": errors}


def ingest_task_results(args: argparse.Namespace) -> dict[str, Any]:
    store = ledger(args.ledger)
    ingested: list[dict[str, Any]] = []
    publication_requests: list[dict[str, Any]] = []
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
            digest = hashlib.sha256(raw).hexdigest()
            if stage == "AUDIT_NO_GO":
                reason = str(value.get("reason") or "").strip()
                if not reason or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
                    raise RuntimeError("AUDIT_NO_GO requires a machine-readable reason")
                store.record_stage(
                    candidate["key"],
                    "AUDIT_NO_GO",
                    evidence=value.get("evidence") if isinstance(value.get("evidence"), dict) else {},
                    reason=reason,
                    dedupe_key=digest,
                )
                ingested.append(
                    {"key": candidate["key"], "stage": stage, "reason": reason}
                )
            elif stage == "FIX_READY":
                quality = value.get("quality")
                if not isinstance(quality, dict):
                    raise RuntimeError("FIX_READY requires a quality object")
                if candidate["stage"] != "FIX_READY":
                    assessment = assess_submit_ready(quality)
                    if not assessment.ready:
                        raise RuntimeError(
                            f"submit-ready evidence missing: {','.join(assessment.missing)}"
                        )
                    store.record_stage(
                        candidate["key"],
                        "FIX_READY",
                        evidence=quality,
                        dedupe_key=digest,
                    )
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
    if not isinstance(parent, dict) or str(parent.get("full_name") or "").casefold() != repo.casefold():
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
            push_result = _executor(
                "push", [*common, "--remote", remote], ledger_path=args.ledger
            )
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
                continue
            pending.append(candidate | {"title": row["title"]})
    finally:
        connection.close()
    return {"ok": True, "cleanup": pending}


def cleanup_commit(args: argparse.Namespace) -> dict[str, Any]:
    connection = sqlite3.connect(THREAD_DB)
    try:
        row = connection.execute(
            "SELECT archived FROM threads WHERE id=?", (args.thread_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or int(row[0] or 0) != 1:
        raise RuntimeError("thread is not archived")
    ledger(args.ledger).commit_cleanup(
        thread_id=args.thread_id,
        nonce=args.cleanup_nonce,
    )
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
            if (
                normalize_origin(row["git_origin_url"] or "")
                != candidate["key"].rsplit("#", 1)[0].casefold()
            ):
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
    claim = subparsers.add_parser("claim")
    claim.add_argument("--intent-id", required=True)
    claim.add_argument("--owner", required=True)
    claim.add_argument("--lease-minutes", type=int, default=15)
    claim.add_argument("--prepare", action="store_true")
    commit = subparsers.add_parser("commit")
    commit.add_argument("--intent-id", required=True)
    commit.add_argument("--owner", required=True)
    commit.add_argument("--thread-id", required=True)
    commit.add_argument("--project-id", required=True)
    commit.add_argument("--cwd", required=True)
    commit.add_argument("--source-repo", required=True)
    commit.add_argument("--title-time", required=True)
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
    subparsers.add_parser("orphan-list")
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
    elif args.operation == "claim":
        result = claim_intent(args)
    elif args.operation == "commit":
        result = commit_receipt(args)
    elif args.operation == "creation-start":
        result = creation_start(args)
    elif args.operation == "creation-bind":
        result = creation_bind(args)
    elif args.operation == "creation-cancel":
        result = creation_cancel(args)
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
