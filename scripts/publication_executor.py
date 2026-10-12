#!/usr/bin/env python3
"""Permit-bound, idempotent Git push and pull-request creation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from time import sleep
from typing import Any, Callable

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.action_guard import (  # noqa: E402
    ledger_action_guard_root,
    opportunity_action_guard,
)
from oss_pr_radar.ledger import RadarLedger  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.outbound_pause import (  # noqa: E402
    outbound_effect_guard,
)
from oss_pr_radar.publication import (  # noqa: E402
    ISSUE_URL,
    audit_publication_request,
    public_branch_is_safe,
)
from oss_pr_radar.release_binding import bind_runtime, runtime_ledger_path  # noqa: E402
from oss_pr_radar.util import sha256_json, sha256_text  # noqa: E402


class PublicationDeferred(RuntimeError):
    pass


class PublicationBlocked(RuntimeError):
    pass


_OUTBOUND_LOCK_FD: int | None = None


def run(
    args: list[str],
    *,
    cwd: Path,
    timeout: int = 180,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
        pass_fds=(_OUTBOUND_LOCK_FD,) if _OUTBOUND_LOCK_FD is not None else (),
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
    review_state_root: Path | None = None,
    denied_creation_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    permit = store.publication_permit_by_id(permit_id)
    if not permit and not live_recheck and action:
        permit = store.publication_permit_for_effect(permit_id, action=action)
    if not permit and action == "create_pr" and not live_recheck and denied_creation_request:
        # This only finishes a previously proved denial; it grants no new action.
        effect = store.publication_effect_by_request(
            permit_id=permit_id,
            action="create_pr",
            request_digest=sha256_json(denied_creation_request),
        )
        if effect and _recorded_permission_denial(effect, permit_id, denied_creation_request):
            with store.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM publication_permits WHERE permit_id=?",
                    (permit_id,),
                ).fetchone()
            if row is not None and row["status"] in {"ACTIVE", "EXPIRED"}:
                recorded = json.loads(effect["result_json"])
                if row["request_id"] == recorded["evidence"].get("requestId"):
                    permit = dict(row)
    if not permit:
        raise RuntimeError("publication permit is missing, expired, or consumed")
    if (
        permit["issue_url"] != issue_url
        or permit["commit_sha"] != commit_sha
        or permit["branch"] != branch
    ):
        raise RuntimeError("publication permit binding mismatch")
    if live_recheck:
        if review_state_root is None:
            audit = audit_publication_request(store, permit["request_id"])
        else:
            audit = audit_publication_request(
                store,
                permit["request_id"],
                review_state_root=review_state_root,
            )
        if audit.status != "ALLOW":
            raise RuntimeError(f"live publication recheck failed: {audit.reason}")
    return permit


def recheck_new_effect(
    store: RadarLedger,
    permit: dict[str, Any],
    effect_id: str,
    *,
    review_state_root: Path | None = None,
) -> None:
    request = permit_request(store, permit)
    expected_head = None
    if request.get("publicationKind") == "PR_UPDATE" and store.publication_action_succeeded(
        str(permit["request_id"]), action="push"
    ):
        expected_head = str(request.get("commitSha") or "")
    audit_kwargs: dict[str, Any] = {"expected_existing_pr_head": expected_head}
    if review_state_root is not None:
        audit_kwargs["review_state_root"] = review_state_root
    audit = audit_publication_request(store, permit["request_id"], **audit_kwargs)
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
    allow_permission_denial: bool = False,
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
        if allow_permission_denial and _recorded_permission_denial(effect, permit_id, request):
            return effect, "reconcile_denial"
        raise RuntimeError(f"previous {action} attempt requires reconciliation: {status}")
    return effect, "new"


def _pr_creation_permission_denied(detail: str, head_owner: str) -> bool:
    return (
        f"GraphQL: {head_owner} does not have the correct permissions to execute "
        "`CreatePullRequest` (createPullRequest)"
    ).casefold() in detail.casefold()


def _recorded_permission_denial(
    effect: dict[str, Any], permit_id: str, request: dict[str, Any]
) -> bool:
    try:
        result = json.loads(effect.get("result_json") or "{}")
    except (TypeError, ValueError):
        return False
    evidence = result.get("evidence") if isinstance(result, dict) else None
    expected = {
        "schemaVersion": "publication-permission-denial-v1",
        "permitId": permit_id,
        "effectId": effect.get("effect_id"),
        "requestDigest": sha256_json(request),
        **{key: request[key] for key in ("repo", "headOwner", "branch", "base", "commitSha")},
        "exactHeadPrAbsent": True,
        "localHeadSha": request["commitSha"],
        "remoteSha": request["commitSha"],
    }
    return bool(
        effect.get("status") == "FAILED"
        and effect.get("permit_id") == permit_id
        and effect.get("action") == "create_pr"
        and effect.get("request_digest") == sha256_json(request)
        and request.get("publicationKind") == "PR_CREATE"
        and isinstance(evidence, dict)
        and all(evidence.get(key) == value for key, value in expected.items())
        and evidence.get("lookup")
        == {
            "method": "GET",
            "endpoint": f"repos/{request['repo']}/pulls",
            "head": f"{request['headOwner']}:{request['branch']}",
            "state": "all",
            "ok": True,
            "result": [],
        }
        and result.get("evidenceDigest") == sha256_json(evidence)
        and result.get("reason") == "PUBLICATION_PERMISSION_DENIED"
        and result.get("ok") is True
        and result.get("creationAttempted") is True
        and result.get("blocked") is True
        and evidence.get("exactHeadPrAbsent") is True
        and evidence.get("lookup", {}).get("ok") is True
        and isinstance(evidence.get("requestId"), str)
        and bool(evidence["requestId"])
        and evidence.get("forkRepo")
        in {
            f"{request['headOwner']}/{request['repo'].rsplit('/', 1)[1]}",
            _collision_fork_repo(request["repo"], request["headOwner"]),
        }
        and all(
            isinstance(evidence.get(key), str) and bool(evidence[key])
            for key in ("pushEffectId", "pushRequestDigest", "observedAt")
        )
        and isinstance(result.get("detail"), str)
        and _pr_creation_permission_denied(result["detail"], request["headOwner"])
    )


def _finish_pr_creation_permission_denial(
    args: argparse.Namespace,
    store: RadarLedger,
    permit: dict[str, Any],
    effect: dict[str, Any],
    request: dict[str, Any],
    publication_request: dict[str, Any],
    detail: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Contract one exact denied attempt only after fresh, bound negative evidence."""
    lookup = run(
        [
            "gh",
            "api",
            "--method",
            "GET",
            f"repos/{args.repo}/pulls",
            "-f",
            f"head={args.head_owner}:{args.branch}",
            "-f",
            "state=all",
            "-f",
            "per_page=5",
        ],
        cwd=ROOT,
    )
    if lookup.returncode != 0:
        raise RuntimeError("permission-denied PR lookup failed")
    try:
        values = json.loads(lookup.stdout)
    except ValueError as exc:
        raise RuntimeError("permission-denied PR lookup returned invalid JSON") from exc
    if not isinstance(values, list):
        raise RuntimeError("permission-denied PR lookup is not an exact list")
    if values:
        for value in values:
            head = value.get("head") if isinstance(value, dict) else None
            base = value.get("base") if isinstance(value, dict) else None
            head_repo = head.get("repo") if isinstance(head, dict) else None
            owner = head_repo.get("owner") if isinstance(head_repo, dict) else None
            base_repo = base.get("repo") if isinstance(base, dict) else None
            if (
                not isinstance(head, dict)
                or not isinstance(base, dict)
                or not isinstance(owner, dict)
                or owner.get("login") != args.head_owner
                or head.get("ref") != args.branch
                or head.get("sha") != args.commit_sha
                or not isinstance(base_repo, dict)
                or base_repo.get("full_name") != args.repo
                or base.get("ref") != args.base
                or value.get("state") != "open"
                or type(value.get("number")) is not int
                or value["number"] <= 0
                or value.get("html_url") != f"https://github.com/{args.repo}/pull/{value['number']}"
            ):
                raise RuntimeError("permission-denied PR lookup identity or head changed")
        value = values[0]
        return {"url": value["html_url"], "state": "OPEN", "headRefOid": args.commit_sha}, None
    if publication_request.get("publicationKind") != "PR_CREATE":
        raise RuntimeError("permission denial is not a new-publication request")
    current_effect = store.publication_effect_by_request(
        permit_id=args.permit_id, action="create_pr", request_digest=sha256_json(request)
    )
    current_request = store.publication_request(permit["request_id"])
    if (
        current_effect is None
        or current_effect.get("effect_id") != effect["effect_id"]
        or current_effect.get("permit_id") != args.permit_id
        or current_effect.get("action") != "create_pr"
        or current_effect.get("request_digest") != sha256_json(request)
        or current_effect.get("status") not in {"ATTEMPTED", "RECONCILE_REQUIRED", "FAILED"}
        or json.loads(current_effect.get("result_json") or "{}").get("creationAttempted")
        is not True
        or permit_request(store, permit) != publication_request
        or publication_request.get("requestId") != permit["request_id"]
        or current_request is None
        or not (
            current_request["status"] == "GRANTED"
            or (
                current_request["status"] == "BLOCKED"
                and current_request["reason"] == "PUBLICATION_PERMISSION_DENIED"
            )
        )
    ):
        raise RuntimeError("permission-denied publication binding changed")
    worktree = Path(args.worktree).resolve()
    head = run(["git", "rev-parse", "HEAD"], cwd=worktree)
    if head.returncode != 0 or output(head) != args.commit_sha:
        raise RuntimeError("permission-denied local head changed")
    pushes = []
    for fork_repo in (
        f"{args.head_owner}/{args.repo.rsplit('/', 1)[1]}",
        _collision_fork_repo(args.repo, args.head_owner),
    ):
        push_request = {
            **{
                key: request[key]
                for key in ("issueUrl", "commitSha", "branch", "publicationKind", "existingPrUrl")
            },
            "remote": fork_repo.casefold(),
            "previousCommitSha": publication_request.get("previousCommitSha"),
        }
        push = store.publication_effect_by_request(
            permit_id=args.permit_id, action="push", request_digest=sha256_json(push_request)
        )
        if (
            push
            and (
                push.get("effect_id")
                == sha256_text(f"{args.permit_id}|push|{sha256_json(push_request)}")
                and push.get("permit_id") == args.permit_id
                and push.get("action") == "push"
                and push.get("request_digest") == sha256_json(push_request)
                and push.get("status") == "SUCCEEDED"
            )
            and (json.loads(push.get("result_json") or "{}").get("remoteSha") == args.commit_sha)
        ):
            pushes.append((fork_repo, push))
    if len(pushes) != 1:
        raise RuntimeError("permission-denied publication push is not uniquely bound")
    fork_repo, push = pushes[0]
    fork = run(["gh", "api", f"repos/{fork_repo}"], cwd=worktree)
    if fork.returncode != 0 or not _is_exact_target_fork(
        _fork_metadata(fork.stdout), args.repo, fork_repo
    ):
        raise RuntimeError("permission-denied publication fork binding changed")
    if remote_head(worktree, f"https://github.com/{fork_repo}.git", args.branch) != args.commit_sha:
        raise RuntimeError("permission-denied remote head changed")
    if current_request["status"] == "BLOCKED":
        prior = json.loads(current_effect["result_json"])
        with store.connect() as connection:
            event = connection.execute(
                "SELECT payload_json FROM events WHERE event_type='PUBLICATION_BLOCKED' AND dedupe_key=?",
                (f"{permit['request_id']}:PUBLICATION_PERMISSION_DENIED",),
            ).fetchone()
        if (
            not _recorded_permission_denial(current_effect, args.permit_id, request)
            or event is None
            or json.loads(event["payload_json"]).get("auditEvidence") != prior["evidence"]
        ):
            raise RuntimeError("permission-denied terminal evidence changed")
        return None, prior
    evidence = {
        "schemaVersion": "publication-permission-denial-v1",
        "requestId": permit["request_id"],
        "permitId": args.permit_id,
        "effectId": effect["effect_id"],
        "requestDigest": sha256_json(request),
        **{key: request[key] for key in ("repo", "headOwner", "branch", "base", "commitSha")},
        "exactHeadPrAbsent": True,
        "localHeadSha": args.commit_sha,
        "forkRepo": fork_repo,
        "pushEffectId": push["effect_id"],
        "pushRequestDigest": push["request_digest"],
        "remoteSha": args.commit_sha,
        "lookup": {
            "method": "GET",
            "endpoint": f"repos/{args.repo}/pulls",
            "head": f"{args.head_owner}:{args.branch}",
            "state": "all",
            "ok": True,
            "result": [],
        },
        "observedAt": datetime.now(UTC).isoformat(),
    }
    result = {
        "ok": True,
        "blocked": True,
        "reason": "PUBLICATION_PERMISSION_DENIED",
        "creationAttempted": True,
        "detail": detail,
        "evidence": evidence,
        "evidenceDigest": sha256_json(evidence),
    }
    store.complete_publication_effect(effect["effect_id"], status="FAILED", result=result)
    store.block_publication_request(permit["request_id"], result["reason"], evidence=evidence)
    return None, result


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


def transient_github_graphql_failure(detail: str) -> bool:
    lowered = detail.casefold()
    return "graphql" in lowered and any(
        marker in lowered
        for marker in (
            "http 502",
            "http 503",
            "http 504",
            "bad gateway",
            "no server is currently available",
            "service unavailable",
            "temporarily unavailable",
        )
    )


def _publication_opportunity_key(issue_url: str) -> str:
    match = ISSUE_URL.fullmatch(issue_url)
    if match is None:
        raise RuntimeError("invalid issue URL")
    return f"{match.group(1)}#{match.group(2)}"


def _guarded_publication_action(
    args: argparse.Namespace,
    store: RadarLedger,
    action: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    opportunity_key = _publication_opportunity_key(args.issue_url)
    ledger_path = getattr(store, "path", None)
    guard_root = (
        ledger_action_guard_root(Path(ledger_path))
        if ledger_path is not None
        else Path(args.worktree).resolve().parent
    )
    with opportunity_action_guard(guard_root, opportunity_key):
        active_quarantine = getattr(store, "active_task_quarantine", None)
        if active_quarantine is not None and active_quarantine(opportunity_key) is not None:
            raise PermissionError(f"publication blocked by active quarantine: {opportunity_key}")
        return action()


def ensure_fork(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    """Create or validate the exact publication fork while holding the effect lock."""

    return _guarded_publication_action(args, store, lambda: _ensure_fork_unlocked(args, store))


def _collision_fork_repo(upstream_repo: str, head_owner: str) -> str:
    return f"{head_owner}/{upstream_repo.replace('/', '-')}"


def _fork_metadata(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("publication fork lookup returned invalid JSON") from exc


def _is_exact_target_fork(metadata: Any, upstream_repo: str, fork_repo: str) -> bool:
    if not isinstance(metadata, dict) or metadata.get("fork") is not True:
        return False
    parent = metadata.get("parent")
    return (
        str(metadata.get("full_name") or "").casefold() == fork_repo.casefold()
        and isinstance(parent, dict)
        and str(parent.get("full_name") or "").casefold() == upstream_repo.casefold()
    )


def _ensure_fork_unlocked(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    match = ISSUE_URL.match(args.issue_url)
    if not match or match.group(1).casefold() != args.repo.casefold():
        raise RuntimeError("fork repository does not match the issue")
    permit = ensure_permit(
        store,
        permit_id=args.permit_id,
        issue_url=args.issue_url,
        commit_sha=args.commit_sha,
        branch=args.branch,
        review_state_root=getattr(args, "runtime_root", None),
    )
    publication = permit_publication(permit)
    if args.head_owner.casefold() != publication["headOwner"].casefold():
        raise RuntimeError("fork owner does not match the publication permit")

    repository_name = args.repo.rsplit("/", 1)[1]
    fork_repo = f"{args.head_owner}/{repository_name}"
    lookup = run(["gh", "api", f"repos/{fork_repo}"], cwd=Path(args.worktree), timeout=45)
    collision = False
    if lookup.returncode == 0:
        metadata = _fork_metadata(lookup.stdout)
        parent = metadata.get("parent") if isinstance(metadata, dict) else None
        if (
            isinstance(metadata, dict)
            and metadata.get("fork") is True
            and isinstance(parent, dict)
            and str(parent.get("full_name") or "")
            and str(parent.get("full_name") or "").casefold() != args.repo.casefold()
        ):
            collision = True
            fork_repo = _collision_fork_repo(args.repo, args.head_owner)
            lookup = run(["gh", "api", f"repos/{fork_repo}"], cwd=Path(args.worktree), timeout=45)
    created = False
    if lookup.returncode == 0:
        raw = lookup.stdout
    else:
        detail = output(lookup).casefold()
        if "404" not in detail and "not found" not in detail:
            raise RuntimeError(f"publication fork lookup failed: {output(lookup)[:240]}")
        fork_command = ["gh", "repo", "fork", args.repo, "--clone=false"]
        if collision:
            fork_command.extend(["--fork-name", fork_repo.rsplit("/", 1)[1]])
        created_proc = run(
            fork_command,
            cwd=Path(args.worktree),
            timeout=180,
        )
        confirmed = run(["gh", "api", f"repos/{fork_repo}"], cwd=Path(args.worktree), timeout=45)
        for delay in (1.0, 3.0, 7.0):
            if confirmed.returncode == 0:
                break
            sleep(delay)
            confirmed = run(
                ["gh", "api", f"repos/{fork_repo}"],
                cwd=Path(args.worktree),
                timeout=45,
            )
        if confirmed.returncode != 0:
            detail = output(created_proc) or output(confirmed)
            raise RuntimeError(f"publication fork creation could not be reconciled: {detail[:240]}")
        created = True
        raw = confirmed.stdout
    metadata = _fork_metadata(raw)
    parent = metadata.get("parent") if isinstance(metadata, dict) else None
    if not isinstance(metadata, dict) or metadata.get("fork") is not True:
        raise RuntimeError("expected publication repository is not a fork")
    if (
        not isinstance(parent, dict)
        or str(parent.get("full_name") or "").casefold() != args.repo.casefold()
    ):
        raise RuntimeError("existing fork does not belong to the target upstream repository")
    if collision and not _is_exact_target_fork(metadata, args.repo, fork_repo):
        raise RuntimeError("named publication fork does not match the exact target repository")

    worktree = Path(args.worktree).resolve()
    expected_url = f"https://github.com/{fork_repo}.git"
    remotes_proc = run(["git", "remote"], cwd=worktree)
    if remotes_proc.returncode != 0:
        raise RuntimeError(f"publication remote lookup failed: {output(remotes_proc)[:240]}")
    remotes = remotes_proc.stdout.splitlines()
    for remote in remotes:
        current = run(["git", "remote", "get-url", remote], cwd=worktree)
        if current.returncode == 0 and normalize_origin(current.stdout) == fork_repo.casefold():
            return {"ok": True, "remote": remote, "forkRepo": fork_repo, "created": created}
    remote = "radar-fork"
    if remote in remotes:
        remote = f"radar-fork-{args.head_owner.casefold()}"
    if remote in remotes:
        raise RuntimeError("no safe remote name is available for the publication fork")
    added = run(["git", "remote", "add", remote, expected_url], cwd=worktree)
    if added.returncode != 0:
        raise RuntimeError(f"publication remote setup failed: {output(added)[:240]}")
    return {"ok": True, "remote": remote, "forkRepo": fork_repo, "created": created}


def push(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    return _guarded_publication_action(args, store, lambda: _push_unlocked(args, store))


def _push_unlocked(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
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
        review_state_root=getattr(args, "runtime_root", None),
    )
    publication = permit_publication(permit)
    publication_request = permit_request(store, permit)
    if args.head_owner.casefold() != publication["headOwner"].casefold():
        raise RuntimeError("push owner does not match the publication permit")
    expected_fork = f"{publication['headOwner']}/{upstream_repo.rsplit('/', 1)[1]}".casefold()
    remote_url = output(run(["git", "remote", "get-url", args.remote], cwd=worktree))
    actual_fork = normalize_origin(remote_url)
    if actual_fork != expected_fork:
        named_fork = _collision_fork_repo(upstream_repo, publication["headOwner"]).casefold()
        if actual_fork != named_fork:
            raise RuntimeError("push remote is not the expected user fork")
        lookup = run(["gh", "api", f"repos/{named_fork}"], cwd=worktree, timeout=45)
        if lookup.returncode != 0:
            raise RuntimeError(f"publication fork lookup failed: {output(lookup)[:240]}")
        if not _is_exact_target_fork(_fork_metadata(lookup.stdout), upstream_repo, named_fork):
            raise RuntimeError("push fork does not belong to the target upstream repository")
        expected_fork = named_fork
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
        review_state_root = getattr(args, "runtime_root", None)
        if review_state_root is None:
            recheck_new_effect(store, permit, effect["effect_id"])
        else:
            recheck_new_effect(
                store,
                permit,
                effect["effect_id"],
                review_state_root=review_state_root,
            )
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
            [
                "git",
                "fetch",
                "--no-write-fetch-head",
                "--quiet",
                args.remote,
                f"+refs/heads/{args.branch}:refs/radar/publication/{args.branch}",
            ],
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
            review_state_root=getattr(args, "runtime_root", None),
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
    return _guarded_publication_action(args, store, lambda: _create_pr_unlocked(args, store))


def _create_pr_unlocked(args: argparse.Namespace, store: RadarLedger) -> dict[str, Any]:
    worktree = Path(args.worktree).resolve()
    if not public_branch_is_safe(args.branch):
        raise RuntimeError("public branch name exposes an AI tool")
    match = ISSUE_URL.match(args.issue_url)
    if not match or match.group(1).casefold() != args.repo.casefold():
        raise RuntimeError("pull-request repository does not match the issue")
    body_path = Path(args.body_file).resolve()
    body = body_path.read_text(encoding="utf-8")
    request = {
        "issueUrl": args.issue_url,
        "commitSha": args.commit_sha,
        "branch": args.branch,
        "repo": args.repo,
        "headOwner": args.head_owner,
        "base": args.base,
        "title": args.title,
        "bodyDigest": sha256_json({"body": body}),
        "publicationKind": "PR_CREATE",
        "existingPrUrl": None,
    }
    permit = ensure_permit(
        store,
        permit_id=args.permit_id,
        issue_url=args.issue_url,
        commit_sha=args.commit_sha,
        branch=args.branch,
        action="create_pr",
        live_recheck=False,
        review_state_root=getattr(args, "runtime_root", None),
        denied_creation_request=request,
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
    request.update(
        publicationKind=publication_request.get("publicationKind"),
        existingPrUrl=publication_request.get("existingPrUrl"),
    )
    effect = None
    state = None
    if permit["status"] != "ACTIVE":
        effect, state = begin_effect(
            store,
            args.permit_id,
            "create_pr",
            request,
            allow_create=False,
            allow_permission_denial=True,
        )
        if state == "already_succeeded":
            return json.loads(effect["result_json"])
    found = existing_pr(args.repo, args.head_owner, args.branch)
    if effect is None:
        effect, state = begin_effect(
            store,
            args.permit_id,
            "create_pr",
            request,
            allow_create=True,
            allow_permission_denial=True,
        )
    if permit["status"] != "ACTIVE" and state not in {"reconcile_only", "reconcile_denial"}:
        raise RuntimeError("expired permit cannot authorize a new PR attempt")
    if state == "new":
        review_state_root = getattr(args, "runtime_root", None)
        if review_state_root is None:
            recheck_new_effect(store, permit, effect["effect_id"])
        else:
            recheck_new_effect(
                store,
                permit,
                effect["effect_id"],
                review_state_root=review_state_root,
            )
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
    try:
        prior_effect_result = json.loads(str(effect.get("result_json") or "{}"))
    except json.JSONDecodeError:
        prior_effect_result = {}
    creation_attempted = prior_effect_result.get("creationAttempted") is True
    prior_denial = str(
        prior_effect_result.get("creationError") or prior_effect_result.get("detail") or ""
    )
    if (
        state in {"reconcile_only", "reconcile_denial"}
        and not found
        and creation_attempted
        and prior_effect_result.get("reason")
        in {
            "PR_CREATION_NOT_RECONCILED",
            "PR_RECONCILIATION_FAILED",
            "PUBLICATION_PERMISSION_DENIED",
        }
        and _pr_creation_permission_denied(prior_denial, args.head_owner)
    ):
        found, blocked = _finish_pr_creation_permission_denial(
            args, store, permit, effect, request, publication_request, prior_denial
        )
        if blocked is not None:
            return blocked
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
        audit = audit_publication_request(
            store,
            str(permit["request_id"]),
            review_state_root=getattr(args, "runtime_root", None),
        )
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
        if publication_request.get("publicationKind") != "PR_CREATE":
            raise RuntimeError("only a new-publication request may create a PR")
        store.mark_pull_request_creation_attempt(
            effect_id=str(effect["effect_id"]),
            permit_id=args.permit_id,
        )
        creation_attempted = True
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
        if proc.returncode != 0 and transient_github_graphql_failure(output(proc)):
            proc = run(
                [
                    "gh",
                    "api",
                    "--method",
                    "POST",
                    f"repos/{args.repo}/pulls",
                    "--input",
                    "-",
                ],
                cwd=worktree,
                timeout=180,
                input_text=json.dumps(
                    {
                        "title": args.title,
                        "head": f"{args.head_owner}:{args.branch}",
                        "base": args.base,
                        "body": body,
                    }
                ),
            )
        try:
            found = wait_for_existing_pr(args.repo, args.head_owner, args.branch)
        except RuntimeError as exc:
            result = {
                "ok": False,
                "reason": "PR_RECONCILIATION_FAILED",
                "creationAttempted": creation_attempted,
                "detail": str(exc)[:300],
            }
            if _pr_creation_permission_denied(output(proc), args.head_owner):
                result["creationError"] = output(proc)[:300]
            store.complete_publication_effect(
                effect["effect_id"], status="RECONCILE_REQUIRED", result=result
            )
            raise
    if (
        not found
        and proc is not None
        and proc.returncode != 0
        and _pr_creation_permission_denied(output(proc), args.head_owner)
    ):
        detail = output(proc)[:300]
        store.complete_publication_effect(
            effect["effect_id"],
            status="RECONCILE_REQUIRED",
            result={
                "ok": False,
                "reason": "PR_CREATION_NOT_RECONCILED",
                "creationAttempted": creation_attempted,
                "detail": detail,
            },
        )
        found, blocked = _finish_pr_creation_permission_denial(
            args, store, permit, effect, request, publication_request, detail
        )
        if blocked is not None:
            return blocked
    if found and found.get("headRefOid") == args.commit_sha:
        result = {
            "ok": True,
            "created": bool(
                publication_request.get("publicationKind") == "PR_CREATE" and creation_attempted
            ),
            "reconciled": bool(proc and proc.returncode != 0) or metadata_reconciled,
            "metadataUpdated": metadata_updated,
            "prUrl": found["url"],
            "state": found.get("state"),
        }
        if state == "reconcile_denial":
            # The PR was observed, not recreated; retain the denied attempt.
            result["created"] = False
            result["reconciled"] = True
            result["priorPermissionDenial"] = prior_effect_result
            store.complete_publication_effect(
                effect["effect_id"],
                status="RECONCILE_REQUIRED",
                result=prior_effect_result | {"observedPrUrl": found["url"]},
            )
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
        "creationAttempted": creation_attempted,
        "detail": output(proc)[:300] if proc else "not found",
    }
    store.complete_publication_effect(
        effect["effect_id"], status="RECONCILE_REQUIRED", result=result
    )
    raise RuntimeError("PR creation result could not be reconciled")


def main() -> int:
    global _OUTBOUND_LOCK_FD
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=None)
    parser.add_argument("--runtime-root", type=Path, default=None)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("ensure-fork", "push", "create-pr"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--permit-id", required=True)
        sub.add_argument("--issue-url", required=True)
        sub.add_argument("--worktree", required=True)
        sub.add_argument("--commit-sha", required=True)
        sub.add_argument("--branch", required=True)
        sub.add_argument("--head-owner", default="Oxygen56")
    push_parser = subparsers.choices["push"]
    push_parser.add_argument("--remote", required=True)
    fork_parser = subparsers.choices["ensure-fork"]
    fork_parser.add_argument("--repo", required=True)
    pr_parser = subparsers.choices["create-pr"]
    pr_parser.add_argument("--repo", required=True)
    pr_parser.add_argument("--base", required=True)
    pr_parser.add_argument("--title", required=True)
    pr_parser.add_argument("--body-file", required=True)
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
                    "error": "--runtime-root is required for external publication",
                }
            )
        )
        return 2
    args.runtime_root = args.runtime_root.resolve()
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

    def execute() -> dict[str, Any]:
        store = RadarLedger(args.ledger)
        if args.operation == "ensure-fork":
            return ensure_fork(args, store)
        return push(args, store) if args.operation == "push" else create_pr(args, store)

    try:
        with outbound_effect_guard(args.runtime_root, args.ledger) as effect_lock:
            _OUTBOUND_LOCK_FD = effect_lock.fileno()
            try:
                result = execute()
            finally:
                _OUTBOUND_LOCK_FD = None
    except PublicationDeferred as exc:
        result = {"ok": True, "pending": True, "reason": str(exc)}
    except PublicationBlocked as exc:
        result = {"ok": True, "blocked": True, "reason": str(exc)}
    except PermissionError as exc:
        result = {"ok": False, "blocked": True, "reason": str(exc)}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") is True else 2


if __name__ == "__main__":
    raise SystemExit(main())
