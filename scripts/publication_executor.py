#!/usr/bin/env python3
"""Permit-bound, idempotent Git push and pull-request creation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from time import sleep
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.publication import (  # noqa: E402
    ISSUE_URL,
    audit_publication_request,
    public_branch_is_safe,
    public_text_is_safe,
)
from oss_pr_radar.util import sha256_json, sha256_text  # noqa: E402


class PublicationDeferred(RuntimeError):
    pass


class PublicationBlocked(RuntimeError):
    pass


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
    proc = None
    retry_delays = (1.0, 3.0)
    for attempt in range(len(retry_delays) + 1):
        proc = run(
            [
                "gh",
                "api",
                "--method",
                "GET",
                f"repos/{repo}/pulls",
                "-f",
                f"head={head_owner}:{branch}",
                "-f",
                "state=all",
                "-f",
                "per_page=5",
            ],
            cwd=ROOT,
        )
        if proc.returncode == 0:
            break
        if attempt < len(retry_delays):
            sleep(retry_delays[attempt])
    assert proc is not None
    if proc.returncode != 0:
        raise RuntimeError(f"pull-request lookup failed: {output(proc)[:240]}")
    try:
        values = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("pull-request lookup returned invalid JSON") from exc
    matches = []
    for value in values if isinstance(values, list) else []:
        head = value.get("head") or {}
        head_repo = head.get("repo") or {}
        owner = (head_repo.get("owner") or {}).get("login") or (head.get("user") or {}).get(
            "login", ""
        )
        normalized = {
            "number": value.get("number"),
            "url": value.get("html_url"),
            "state": str(value.get("state") or "").upper(),
            "title": str(value.get("title") or ""),
            "body": str(value.get("body") or ""),
            "headRefOid": head.get("sha"),
            "headRefName": head.get("ref"),
            "headRepositoryOwner": {"login": owner},
        }
        if owner.casefold() == head_owner.casefold() and head.get("ref") == branch:
            matches.append(normalized)
    return next(
        (value for value in matches if str(value.get("state") or "").upper() == "OPEN"),
        matches[0] if matches else None,
    )


def wait_for_existing_pr(repo: str, head_owner: str, branch: str) -> dict[str, Any] | None:
    found = existing_pr(repo, head_owner, branch)
    for delay in (1.0, 3.0, 7.0):
        if found:
            break
        sleep(delay)
        found = existing_pr(repo, head_owner, branch)
    return found


def reconcile_pr_metadata(
    *,
    repo: str,
    head_owner: str,
    branch: str,
    found: dict[str, Any],
    commit_sha: str,
    title: str,
    body: str,
    worktree: Path,
) -> tuple[dict[str, Any], bool, bool]:
    """Apply permit-bound metadata and verify the exact open PR reflects it."""

    metadata_known = isinstance(found.get("title"), str) and isinstance(found.get("body"), str)
    if not metadata_known or (found.get("title") == title and found.get("body") == body):
        return found, False, False
    number = found.get("number")
    if not isinstance(number, int) or number <= 0:
        raise RuntimeError("existing pull request number is unavailable")
    proc = run(
        [
            "gh",
            "api",
            "--method",
            "PATCH",
            f"repos/{repo}/pulls/{number}",
            "--raw-field",
            f"title={title}",
            "--raw-field",
            f"body={body}",
        ],
        cwd=worktree,
        timeout=180,
    )
    current = found
    for delay in (0.0, 1.0, 3.0, 7.0):
        if delay:
            sleep(delay)
        current = existing_pr(repo, head_owner, branch) or current
        if (
            current.get("url") == found.get("url")
            and str(current.get("state") or "").upper() == "OPEN"
            and current.get("headRefOid") == commit_sha
            and current.get("title") == title
            and current.get("body") == body
        ):
            return current, True, proc.returncode != 0
    detail = output(proc)[:300]
    suffix = f": {detail}" if detail else ""
    raise RuntimeError(f"pull-request metadata update could not be reconciled{suffix}")


def ensure_permit(
    store: RadarLedger,
    *,
    permit_id: str,
    issue_url: str,
    commit_sha: str,
    branch: str,
    action: str | None = None,
    live_recheck: bool = True,
) -> dict[str, Any]:
    permit = store.publication_permit_by_id(permit_id)
    if not permit and not live_recheck and action:
        permit = store.publication_permit_for_effect(permit_id, action=action)
    if not permit:
        raise RuntimeError("publication permit is missing, expired, or consumed")
    if (
        permit["issue_url"] != issue_url
        or permit["commit_sha"] != commit_sha
        or permit["branch"] != branch
    ):
        raise RuntimeError("publication permit binding mismatch")
    if live_recheck:
        audit = audit_publication_request(store, permit["request_id"])
        if audit.status != "ALLOW":
            raise RuntimeError(f"live publication recheck failed: {audit.reason}")
    return permit


def recheck_new_effect(store: RadarLedger, permit: dict[str, Any], effect_id: str) -> None:
    request = permit_request(store, permit)
    expected_head = None
    if request.get("publicationKind") == "PR_UPDATE" and store.publication_action_succeeded(
        str(permit["request_id"]), action="push"
    ):
        expected_head = str(request.get("commitSha") or "")
    audit = audit_publication_request(
        store,
        permit["request_id"],
        expected_existing_pr_head=expected_head,
    )
    if audit.status == "ALLOW":
        return
    disposition = "DEFER" if audit.status == "DEFER" else "BLOCK"
    store.resolve_publication_preflight(
        effect_id,
        disposition=disposition,
        reason=audit.reason,
    )
    if disposition == "DEFER":
        raise PublicationDeferred(audit.reason)
    raise PublicationBlocked(audit.reason)


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


def permit_request(store: RadarLedger, permit: dict[str, Any]) -> dict[str, Any]:
    row = store.publication_request(str(permit["request_id"]))
    if row is None or not isinstance(row.get("request"), dict):
        raise RuntimeError("publication permit request is unavailable")
    return row["request"]


def begin_effect(
    store: RadarLedger,
    permit_id: str,
    action: str,
    request: dict[str, Any],
    *,
    allow_create: bool,
) -> tuple[dict[str, Any], str]:
    digest = sha256_json(request)
    if allow_create:
        effect = store.publication_effect(
            permit_id=permit_id,
            action=action,
            request_digest=digest,
        )
    else:
        effect = store.publication_effect_by_request(
            permit_id=permit_id,
            action=action,
            request_digest=digest,
        )
        if effect is None:
            raise RuntimeError("inactive permit does not match a recoverable publication effect")
        effect = effect | {"created": False}
    if not effect.get("created"):
        status = effect["status"]
        if status == "SUCCEEDED":
            return effect, "already_succeeded"
        if status == "RECONCILE_REQUIRED":
            return effect, "reconcile_only"
        raise RuntimeError(f"previous {action} attempt requires reconciliation: {status}")
    return effect, "new"


def retryable_pr_creation_failure(effect: dict[str, Any]) -> bool:
    """Return whether an absent PR may be retried after a transient API failure."""

    try:
        result = json.loads(str(effect.get("result_json") or "{}"))
    except json.JSONDecodeError:
        return False
    if not isinstance(result, dict) or result.get("reason") not in {
        "PR_CREATION_NOT_RECONCILED",
        "PR_RECONCILIATION_FAILED",
    }:
        return False
    detail = str(result.get("detail") or "").casefold()
    return any(
        marker in detail
        for marker in (
            "http 502",
            "http 503",
            "http 504",
            "bad gateway",
            "connection reset",
            "connection timed out",
            "no server is currently available",
            "service unavailable",
            "temporarily unavailable",
        )
    )


def push(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    worktree = Path(args.worktree).resolve()
    if not public_branch_is_safe(args.branch):
        raise RuntimeError("public branch name exposes an AI tool")
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
        action="push",
        live_recheck=False,
    )
    publication = permit_publication(permit)
    publication_request = permit_request(store, permit)
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
        "publicationKind": publication_request.get("publicationKind"),
        "existingPrUrl": publication_request.get("existingPrUrl"),
        "previousCommitSha": publication_request.get("previousCommitSha"),
    }
    effect = None
    state = None
    if permit["status"] != "ACTIVE":
        effect, state = begin_effect(store, args.permit_id, "push", request, allow_create=False)
        if state == "already_succeeded":
            return json.loads(effect["result_json"])
    current = remote_head(worktree, args.remote, args.branch)
    if effect is None:
        effect, state = begin_effect(store, args.permit_id, "push", request, allow_create=True)
    if permit["status"] != "ACTIVE" and state != "reconcile_only":
        raise RuntimeError("expired permit cannot authorize a new push attempt")
    if state == "new":
        recheck_new_effect(store, permit, effect["effect_id"])
    if current == args.commit_sha:
        result = {"ok": True, "reconciled": True, "remoteSha": current}
        store.complete_publication_effect(effect["effect_id"], status="SUCCEEDED", result=result)
        return result
    if current and publication_request.get("publicationKind") == "PR_UPDATE":
        previous_commit = str(publication_request.get("previousCommitSha") or "")
        found = existing_pr(upstream_repo, args.head_owner, args.branch)
        if (
            not previous_commit
            or current != previous_commit
            or not found
            or found.get("url") != publication_request.get("existingPrUrl")
            or str(found.get("state") or "").upper() != "OPEN"
            or found.get("headRefOid") != current
        ):
            result = {"ok": False, "reason": "EXISTING_PR_HEAD_DRIFT", "remoteSha": current}
            store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
            store.rearm_pr_followup_after_publication_drift(
                str(permit["request_id"]), reason="EXISTING_PR_HEAD_DRIFT"
            )
            raise RuntimeError("existing PR head changed before branch update")
        run(
            ["git", "fetch", "--quiet", args.remote, f"refs/heads/{args.branch}"],
            cwd=worktree,
            timeout=300,
        )
        ancestry = run(
            ["git", "merge-base", "--is-ancestor", current, args.commit_sha],
            cwd=worktree,
        )
        if ancestry.returncode != 0:
            result = {"ok": False, "reason": "NON_FAST_FORWARD_PR_UPDATE"}
            store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
            store.rearm_pr_followup_after_publication_drift(
                str(permit["request_id"]), reason="NON_FAST_FORWARD_PR_UPDATE"
            )
            raise RuntimeError("PR update is not a fast-forward of the current remote head")
    elif current:
        result = {"ok": False, "reason": "REMOTE_BRANCH_CONFLICT", "remoteSha": current}
        store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
        raise RuntimeError("remote branch already points to a different commit")
    if state == "reconcile_only":
        expected_head = (
            current if publication_request.get("publicationKind") == "PR_UPDATE" else None
        )
        audit = audit_publication_request(
            store,
            permit["request_id"],
            expected_existing_pr_head=expected_head,
        )
        if audit.status != "ALLOW":
            raise RuntimeError(f"live publication retry recheck failed: {audit.reason}")
        permit = store.retry_publication_effect_after_noop(
            effect_id=effect["effect_id"],
            permit_id=args.permit_id,
            evidence={
                "remoteSha": current,
                "expectedPreviousSha": publication_request.get("previousCommitSha"),
                "auditReason": audit.reason,
            },
        )
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
    if not public_branch_is_safe(args.branch):
        raise RuntimeError("public branch name exposes an AI tool")
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
        action="create_pr",
        live_recheck=False,
    )
    publication = permit_publication(permit)
    publication_request = permit_request(store, permit)
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
        "publicationKind": publication_request.get("publicationKind"),
        "existingPrUrl": publication_request.get("existingPrUrl"),
    }
    effect = None
    state = None
    if permit["status"] != "ACTIVE":
        effect, state = begin_effect(
            store, args.permit_id, "create_pr", request, allow_create=False
        )
        if state == "already_succeeded":
            return json.loads(effect["result_json"])
    found = existing_pr(args.repo, args.head_owner, args.branch)
    if effect is None:
        effect, state = begin_effect(store, args.permit_id, "create_pr", request, allow_create=True)
    if permit["status"] != "ACTIVE" and state != "reconcile_only":
        raise RuntimeError("expired permit cannot authorize a new PR attempt")
    if state == "new":
        recheck_new_effect(store, permit, effect["effect_id"])
    if found and str(found.get("state") or "").upper() != "OPEN":
        result = {"ok": False, "reason": "BRANCH_HAS_CLOSED_OR_MERGED_PR", "pr": found}
        store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
        raise RuntimeError("the branch already has a closed or merged PR")
    if publication_request.get("publicationKind") == "PR_UPDATE" and (
        not found
        or found.get("url") != publication_request.get("existingPrUrl")
        or found.get("headRefOid") != args.commit_sha
    ):
        try:
            found = wait_for_existing_pr(args.repo, args.head_owner, args.branch)
        except RuntimeError as exc:
            result = {
                "ok": False,
                "reason": "PR_UPDATE_RECONCILIATION_REQUIRED",
                "detail": str(exc)[:300],
            }
            store.complete_publication_effect(
                effect["effect_id"], status="RECONCILE_REQUIRED", result=result
            )
            raise
        if found.get("url") != publication_request.get("existingPrUrl"):
            result = {"ok": False, "reason": "EXISTING_PR_NOT_FOUND", "pr": found}
            store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
            raise RuntimeError("the exact existing PR is unavailable for update")
    if found and found.get("headRefOid") != args.commit_sha:
        result = {"ok": False, "reason": "EXISTING_PR_HEAD_MISMATCH", "pr": found}
        store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
        raise RuntimeError("existing PR head does not match the permitted commit")
    metadata_updated = False
    metadata_reconciled = False
    if found and publication_request.get("publicationKind") == "PR_UPDATE":
        try:
            found, metadata_updated, metadata_reconciled = reconcile_pr_metadata(
                repo=args.repo,
                head_owner=args.head_owner,
                branch=args.branch,
                found=found,
                commit_sha=args.commit_sha,
                title=args.title,
                body=body,
                worktree=worktree,
            )
        except RuntimeError as exc:
            result = {
                "ok": False,
                "reason": "PR_METADATA_RECONCILIATION_REQUIRED",
                "detail": str(exc)[:300],
            }
            store.complete_publication_effect(
                effect["effect_id"], status="RECONCILE_REQUIRED", result=result
            )
            raise
    retry_create = bool(
        state == "reconcile_only"
        and not found
        and permit["status"] in {"ACTIVE", "EXPIRED"}
        and effect is not None
        and retryable_pr_creation_failure(effect)
    )
    if retry_create:
        audit = audit_publication_request(store, str(permit["request_id"]))
        if audit.status != "ALLOW":
            raise RuntimeError(f"live publication recheck failed: {audit.reason}")
        permit = store.retry_publication_effect_after_noop(
            effect_id=str(effect["effect_id"]),
            permit_id=args.permit_id,
            evidence={
                "exactHeadPrAbsent": True,
                "liveAuditReason": audit.reason,
            },
        )
        state = "retry"
    if state == "reconcile_only" and not found and not retry_create:
        raise RuntimeError("previous PR creation attempt is not visible for the exact head branch")
    proc = None
    if not found and (state == "new" or retry_create):
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
            found = wait_for_existing_pr(args.repo, args.head_owner, args.branch)
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
            "reconciled": bool(proc and proc.returncode != 0) or metadata_reconciled,
            "metadataUpdated": metadata_updated,
            "prUrl": found["url"],
            "state": found.get("state"),
        }
        store.succeed_pull_request_effect(
            effect_id=effect["effect_id"],
            permit_id=args.permit_id,
            pr_url=found["url"],
            result=result,
        )
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
    try:
        result = push(args, store) if args.operation == "push" else create_pr(args, store)
    except PublicationDeferred as exc:
        result = {"ok": True, "pending": True, "reason": str(exc)}
    except PublicationBlocked as exc:
        result = {"ok": True, "blocked": True, "reason": str(exc)}
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
