#!/usr/bin/env python3
"""Permit-bound, idempotent Git push and pull-request creation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.publication import (  # noqa: E402
    ISSUE_URL,
    audit_publication_request,
    public_text_is_safe,
)
from oss_pr_radar.util import sha256_json, sha256_text  # noqa: E402


def run(args: list[str], *, cwd: Path, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def normalize_origin(value: str) -> str:
    normalized = value.strip().removesuffix(".git")
    for prefix in ("https://github.com/", "git@github.com:", "ssh://git@github.com/"):
        if normalized.casefold().startswith(prefix):
            return normalized[len(prefix) :].strip("/").casefold()
    return ""


def output(proc: subprocess.CompletedProcess[str]) -> str:
    return (proc.stdout or proc.stderr or "").strip()


def remote_head(worktree: Path, remote: str, branch: str) -> str | None:
    proc = run(
        ["git", "ls-remote", "--heads", remote, f"refs/heads/{branch}"],
        cwd=worktree,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"remote branch lookup failed: {output(proc)[:240]}")
    line = proc.stdout.strip().splitlines()
    return line[0].split()[0] if line else ""


def existing_pr(repo: str, head_owner: str, branch: str) -> dict[str, Any] | None:
    proc = run(
        [
            "gh",
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            f"{head_owner}:{branch}",
            "--state",
            "all",
            "--json",
            "number,url,state,headRefOid,headRefName,headRepositoryOwner",
            "--limit",
            "5",
        ],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pull-request lookup failed: {output(proc)[:240]}")
    try:
        values = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("pull-request lookup returned invalid JSON") from exc
    matches = []
    for value in values if isinstance(values, list) else []:
        owner = (value.get("headRepositoryOwner") or {}).get("login") or ""
        if owner.casefold() == head_owner.casefold() and value.get("headRefName") == branch:
            matches.append(value)
    return next(
        (value for value in matches if str(value.get("state") or "").upper() == "OPEN"),
        matches[0] if matches else None,
    )


def ensure_permit(
    store: RadarLedger,
    *,
    permit_id: str,
    issue_url: str,
    commit_sha: str,
    branch: str,
) -> dict[str, Any]:
    permit = store.publication_permit_by_id(permit_id)
    if not permit:
        raise RuntimeError("publication permit is missing, expired, or consumed")
    if (
        permit["issue_url"] != issue_url
        or permit["commit_sha"] != commit_sha
        or permit["branch"] != branch
    ):
        raise RuntimeError("publication permit binding mismatch")
    audit = audit_publication_request(store, permit["request_id"])
    if audit.status != "ALLOW":
        raise RuntimeError(f"live publication recheck failed: {audit.reason}")
    return permit


def permit_publication(permit: dict[str, Any]) -> dict[str, str]:
    try:
        evidence = json.loads(permit["evidence_json"])
        publication = evidence["publication"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("publication permit payload is invalid") from exc
    required = {"headOwner", "baseBranch", "title", "bodyPath", "bodyDigest"}
    if not isinstance(publication, dict) or not required.issubset(publication):
        raise RuntimeError("publication permit payload is incomplete")
    return {key: str(publication[key]) for key in required}


def begin_effect(
    store: RadarLedger, permit_id: str, action: str, request: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    digest = sha256_json(request)
    effect = store.publication_effect(
        permit_id=permit_id,
        action=action,
        request_digest=digest,
    )
    if not effect.get("created"):
        status = effect["status"]
        if status == "SUCCEEDED":
            return effect, "already_succeeded"
        raise RuntimeError(f"previous {action} attempt requires reconciliation: {status}")
    return effect, "new"


def push(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    worktree = Path(args.worktree).resolve()
    match = ISSUE_URL.match(args.issue_url)
    if not match:
        raise RuntimeError("invalid issue URL")
    upstream_repo = match.group(1)
    permit = ensure_permit(
        store,
        permit_id=args.permit_id,
        issue_url=args.issue_url,
        commit_sha=args.commit_sha,
        branch=args.branch,
    )
    publication = permit_publication(permit)
    if args.head_owner.casefold() != publication["headOwner"].casefold():
        raise RuntimeError("push owner does not match the publication permit")
    expected_fork = f"{publication['headOwner']}/{upstream_repo.rsplit('/', 1)[1]}".casefold()
    remote_url = output(run(["git", "remote", "get-url", args.remote], cwd=worktree))
    if normalize_origin(remote_url) != expected_fork:
        raise RuntimeError("push remote is not the expected user fork")
    request = {
        "issueUrl": args.issue_url,
        "commitSha": args.commit_sha,
        "branch": args.branch,
        "remote": expected_fork,
    }
    current = remote_head(worktree, args.remote, args.branch)
    effect, state = begin_effect(store, args.permit_id, "push", request)
    if state == "already_succeeded":
        return json.loads(effect["result_json"])
    if current == args.commit_sha:
        result = {"ok": True, "reconciled": True, "remoteSha": current}
        store.complete_publication_effect(effect["effect_id"], status="SUCCEEDED", result=result)
        return result
    if current:
        result = {"ok": False, "reason": "REMOTE_BRANCH_CONFLICT", "remoteSha": current}
        store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
        raise RuntimeError("remote branch already points to a different commit")
    proc = run(
        ["git", "push", args.remote, f"{args.commit_sha}:refs/heads/{args.branch}"],
        cwd=worktree,
        timeout=300,
    )
    try:
        reconciled = remote_head(worktree, args.remote, args.branch)
    except RuntimeError as exc:
        result = {"ok": False, "reason": "PUSH_RECONCILIATION_FAILED", "detail": str(exc)[:300]}
        store.complete_publication_effect(
            effect["effect_id"], status="RECONCILE_REQUIRED", result=result
        )
        raise
    if reconciled == args.commit_sha:
        result = {"ok": True, "reconciled": proc.returncode != 0, "remoteSha": reconciled}
        store.complete_publication_effect(effect["effect_id"], status="SUCCEEDED", result=result)
        return result
    result = {"ok": False, "reason": "PUSH_NOT_RECONCILED", "detail": output(proc)[:300]}
    store.complete_publication_effect(
        effect["effect_id"], status="RECONCILE_REQUIRED", result=result
    )
    raise RuntimeError("push result could not be reconciled")


def create_pr(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    worktree = Path(args.worktree).resolve()
    match = ISSUE_URL.match(args.issue_url)
    if not match or match.group(1).casefold() != args.repo.casefold():
        raise RuntimeError("pull-request repository does not match the issue")
    body_path = Path(args.body_file).resolve()
    body = body_path.read_text(encoding="utf-8")
    permit = ensure_permit(
        store,
        permit_id=args.permit_id,
        issue_url=args.issue_url,
        commit_sha=args.commit_sha,
        branch=args.branch,
    )
    publication = permit_publication(permit)
    if args.head_owner.casefold() != publication["headOwner"].casefold():
        raise RuntimeError("PR owner does not match the publication permit")
    if args.base != publication["baseBranch"]:
        raise RuntimeError("PR base does not match the publication permit")
    if args.title != publication["title"]:
        raise RuntimeError("PR title does not match the publication permit")
    if str(body_path) != publication["bodyPath"] or sha256_text(body) != publication["bodyDigest"]:
        raise RuntimeError("PR body does not match the publication permit")
    if not public_text_is_safe(args.title, body):
        raise RuntimeError("public PR text contains an AI-assistance disclosure")
    request = {
        "issueUrl": args.issue_url,
        "commitSha": args.commit_sha,
        "branch": args.branch,
        "repo": args.repo,
        "headOwner": args.head_owner,
        "base": args.base,
        "title": args.title,
        "bodyDigest": sha256_json({"body": body}),
    }
    found = existing_pr(args.repo, args.head_owner, args.branch)
    effect, state = begin_effect(store, args.permit_id, "create_pr", request)
    if state == "already_succeeded":
        return json.loads(effect["result_json"])
    if found and str(found.get("state") or "").upper() != "OPEN":
        result = {"ok": False, "reason": "BRANCH_HAS_CLOSED_OR_MERGED_PR", "pr": found}
        store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
        raise RuntimeError("the branch already has a closed or merged PR")
    if found and found.get("headRefOid") != args.commit_sha:
        result = {"ok": False, "reason": "EXISTING_PR_HEAD_MISMATCH", "pr": found}
        store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
        raise RuntimeError("existing PR head does not match the permitted commit")
    proc = None
    if not found:
        proc = run(
            [
                "gh",
                "pr",
                "create",
                "--repo",
                args.repo,
                "--head",
                f"{args.head_owner}:{args.branch}",
                "--base",
                args.base,
                "--title",
                args.title,
                "--body-file",
                str(Path(args.body_file).resolve()),
            ],
            cwd=worktree,
            timeout=180,
        )
        try:
            found = existing_pr(args.repo, args.head_owner, args.branch)
        except RuntimeError as exc:
            result = {
                "ok": False,
                "reason": "PR_RECONCILIATION_FAILED",
                "detail": str(exc)[:300],
            }
            store.complete_publication_effect(
                effect["effect_id"], status="RECONCILE_REQUIRED", result=result
            )
            raise
    if found and found.get("headRefOid") == args.commit_sha:
        result = {
            "ok": True,
            "reconciled": bool(proc and proc.returncode != 0),
            "prUrl": found["url"],
            "state": found.get("state"),
        }
        store.complete_publication_effect(effect["effect_id"], status="SUCCEEDED", result=result)
        store.consume_publication_permit(args.permit_id, found["url"])
        return result
    result = {
        "ok": False,
        "reason": "PR_CREATION_NOT_RECONCILED",
        "detail": output(proc)[:300] if proc else "not found",
    }
    store.complete_publication_effect(
        effect["effect_id"], status="RECONCILE_REQUIRED", result=result
    )
    raise RuntimeError("PR creation result could not be reconciled")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=ROOT / "state" / "radar_ledger.sqlite3")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("push", "create-pr"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--permit-id", required=True)
        sub.add_argument("--issue-url", required=True)
        sub.add_argument("--worktree", required=True)
        sub.add_argument("--commit-sha", required=True)
        sub.add_argument("--branch", required=True)
        sub.add_argument("--head-owner", default="Oxygen56")
    push_parser = subparsers.choices["push"]
    push_parser.add_argument("--remote", required=True)
    pr_parser = subparsers.choices["create-pr"]
    pr_parser.add_argument("--repo", required=True)
    pr_parser.add_argument("--base", required=True)
    pr_parser.add_argument("--title", required=True)
    pr_parser.add_argument("--body-file", required=True)
    args = parser.parse_args()
    store = RadarLedger(args.ledger)
    result = push(args, store) if args.operation == "push" else create_pr(args, store)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
