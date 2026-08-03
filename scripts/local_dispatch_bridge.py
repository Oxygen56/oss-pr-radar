#!/usr/bin/env python3
"""Prepare and verify local Codex issue-task dispatches from the cloud queue."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
STATE = ROOT / "state"
RECEIPTS = STATE / "local_dispatch_receipts.json"
PENDING = STATE / "local_dispatch_pending.json"
THREAD_DB = Path.home() / ".codex" / "state_5.sqlite"
GITHUB_ROOT = Path.home() / "Documents" / "github"
WORKTREE_ROOT = Path.home() / ".codex" / "worktrees"
REPO = "Oxygen56/oss-pr-radar"
ISSUE_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")


def command(args: list[str], cwd: Path | None = None, timeout: int = 300) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            (completed.stderr or completed.stdout or "command failed")[:500]
        )
    return completed.stdout.strip()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def normalize_origin(value: str) -> str:
    normalized = value.strip().removesuffix(".git")
    for prefix in ("https://github.com/", "git@github.com:", "ssh://git@github.com/"):
        if normalized.lower().startswith(prefix):
            return normalized[len(prefix) :].strip("/").casefold()
    return ""


def source_repo(repo: str) -> Path:
    for path in GITHUB_ROOT.iterdir():
        if not path.is_dir() or not (path / ".git").exists():
            continue
        try:
            origin = command(
                ["git", "remote", "get-url", "origin"], cwd=path, timeout=15
            )
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


def cloud_queue() -> dict[str, Any]:
    command(["git", "fetch", "origin", "radar-state"], cwd=ROOT)
    raw = command(["git", "show", "FETCH_HEAD:dispatch_queue.json"], cwd=ROOT)
    value = json.loads(raw)
    if value.get("version") != "dispatch_intents_v1":
        raise RuntimeError("unsupported dispatch queue")
    return value


def live_issue(intent: dict[str, Any]) -> tuple[bool, str]:
    match = ISSUE_URL.match(str(intent.get("issueUrl") or ""))
    if not match:
        return False, "invalid_issue_url"
    repo, number = match.groups()
    raw = command(
        [
            "gh",
            "issue",
            "view",
            number,
            "--repo",
            repo,
            "--json",
            "state,assignees",
        ]
    )
    issue = json.loads(raw)
    if issue.get("state") != "OPEN":
        return False, "issue_not_open"
    if issue.get("assignees"):
        return False, "issue_assigned"
    return True, "live_gate_passed"


def list_pending() -> dict[str, Any]:
    queue = cloud_queue()
    receipts = read_json(RECEIPTS)
    pending: dict[str, Any] = {}
    blocked = []
    for intent in queue.get("intents") or []:
        key = intent.get("key")
        if not key or receipts.get(key, {}).get("intentDigest") == intent.get(
            "intentDigest"
        ):
            continue
        ok, reason = live_issue(intent)
        if not ok:
            blocked.append({"key": key, "reason": reason})
            continue
        path = source_repo(str(intent["repo"]))
        command(["codex", "app", str(path)], timeout=30)
        title_time = datetime.now().astimezone().strftime("%m-%d %H:%M")
        prepared = {
            **intent,
            "sourceRepoPath": str(path),
            "desiredTitle": f"{title_time} {key} {intent['title']}"[:100],
        }
        pending[key] = prepared
    write_json(PENDING, pending)
    return {"ok": True, "pending": list(pending.values()), "blocked": blocked}


def git_path(*args: str, cwd: Path) -> Path:
    return Path(command(["git", *args], cwd=cwd)).resolve()


def commit_receipt(args: argparse.Namespace) -> dict[str, Any]:
    pending = read_json(PENDING)
    intent = pending.get(args.key)
    if not isinstance(intent, dict) or intent.get("intentDigest") != args.intent_digest:
        raise RuntimeError("pending intent mismatch")
    source = Path(intent["sourceRepoPath"]).resolve()
    cwd = Path(args.cwd).resolve()
    if cwd == source or WORKTREE_ROOT.resolve() not in cwd.parents:
        raise RuntimeError("thread cwd is not a Codex worktree")
    if git_path(
        "rev-parse", "--path-format=absolute", "--git-common-dir", cwd=cwd
    ) != git_path("rev-parse", "--path-format=absolute", "--git-dir", cwd=source):
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
    if row is None or int(row["archived"] or 0) != 0:
        raise RuntimeError("thread is missing or archived")
    if Path(row["cwd"]).resolve() != cwd:
        raise RuntimeError("thread cwd mismatch")
    if row["title"] != intent["desiredTitle"]:
        raise RuntimeError("thread title mismatch")
    if (row["first_user_message"] or "").strip() != intent["prompt"].strip():
        raise RuntimeError("thread prompt mismatch")
    if normalize_origin(row["git_origin_url"] or "") != str(intent["repo"]).casefold():
        raise RuntimeError("thread origin mismatch")
    receipts = read_json(RECEIPTS)
    receipts[args.key] = {
        "intentDigest": args.intent_digest,
        "threadId": args.thread_id,
        "projectId": args.project_id,
        "title": intent["desiredTitle"],
        "cwd": str(cwd),
        "committedAt": datetime.now().astimezone().isoformat(),
    }
    write_json(RECEIPTS, receipts)
    pending.pop(args.key, None)
    write_json(PENDING, pending)
    return {"ok": True, "key": args.key, "threadId": args.thread_id}


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("list")
    commit = subparsers.add_parser("commit")
    commit.add_argument("--key", required=True)
    commit.add_argument("--intent-digest", required=True)
    commit.add_argument("--thread-id", required=True)
    commit.add_argument("--project-id", required=True)
    commit.add_argument("--cwd", required=True)
    args = parser.parse_args()
    result = list_pending() if args.operation == "list" else commit_receipt(args)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
