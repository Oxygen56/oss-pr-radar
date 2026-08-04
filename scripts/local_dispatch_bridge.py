#!/usr/bin/env python3
"""Verify, lease, prepare, and receipt local issue-task dispatches."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
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
from oss_pr_radar.publication import request_publication  # noqa: E402
from oss_pr_radar.util import sha256_json  # noqa: E402

STATE = ROOT / "state"
LEDGER_PATH = STATE / "radar_ledger.sqlite3"
THREAD_DB = Path.home() / ".codex" / "state_5.sqlite"
GITHUB_ROOT = Path.home() / "Documents" / "github"
WORKTREE_ROOT = Path.home() / ".codex" / "worktrees"
KEYCHAIN_SERVICE = "oss-pr-radar-dispatch"
ISSUE_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
DELEGATED_INPUT = re.compile(r"<input>(.*?)</input>", re.DOTALL)
MAX_TITLE_CHARS = 59
TITLE_PREFIXES = {
    "GO": "[有价值·GO]",
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
    inserted = sum(store.enqueue(item) for item in intents)
    return {
        "ok": True,
        "mode": queue.get("mode"),
        "verified": len(intents),
        "inserted": inserted,
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
    return {"ok": True, "key": intent["key"], "threadId": args.thread_id}


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
    value = ledger(args.ledger).task_context(
        issue_url=args.issue_url,
        thread_id=args.thread_id,
        worktree_path=args.worktree,
    )
    return {"ok": value is not None, "task": value}


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
    elif args.operation == "outcome":
        result = record_outcome(args)
    elif args.operation == "request-publication":
        result = submit_publication_request(args)
    elif args.operation == "publication-check":
        result = publication_check(args)
    elif args.operation == "cleanup-list":
        result = cleanup_list(args)
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
