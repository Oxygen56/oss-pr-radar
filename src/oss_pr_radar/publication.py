"""One-time publication requests and live, commit-bound authorization."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .decision import authorize
from .evidence import collect_evidence
from .github_client import GitHubClient, GitHubError
from .ledger import LedgerError, RadarLedger
from .metrics import assess_submit_ready
from .util import sha256_text

ISSUE_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
PR_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$")
PUBLIC_AI_DISCLOSURE_RE = re.compile(
    r"\b(?:generated|written|created|assisted)\s+by\s+(?:ai|codex|chatgpt|llm)\b|"
    r"\b(?:ai|codex|chatgpt|llm)[- ]assisted\b|\bai disclosure\b",
    re.I,
)
PUBLIC_TOOL_BRANCH_RE = re.compile(
    r"^(?:codex|chatgpt|claude|gemini|copilot)(?:$|[._/-])|"
    r"(?:^|[._/-])(?:ai|codex|chatgpt|claude|gemini|copilot)[-_]?"
    r"(?:generated|assisted)(?:$|[._/-])",
    re.I,
)


class PublicationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicationAudit:
    status: str
    reason: str
    request_id: str
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def command(args: list[str], *, cwd: Path, timeout: int = 120) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise PublicationError((completed.stderr or completed.stdout)[:800])
    return completed.stdout.strip()


def _normalize_origin(value: str) -> str:
    normalized = value.strip().removesuffix(".git")
    for prefix in ("https://github.com/", "git@github.com:", "ssh://git@github.com/"):
        if normalized.casefold().startswith(prefix):
            return normalized[len(prefix) :].strip("/").casefold()
    return ""


def _git_snapshot(worktree: Path) -> dict[str, Any]:
    return {
        "commitSha": command(["git", "rev-parse", "HEAD"], cwd=worktree),
        "branch": command(["git", "symbolic-ref", "--short", "HEAD"], cwd=worktree),
        "status": command(["git", "status", "--porcelain"], cwd=worktree),
    }


def _evidence_file(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PublicationError("publication evidence is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PublicationError("publication evidence must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def _publication_payload(evidence: dict[str, Any], issue_url: str) -> dict[str, str]:
    value = evidence.get("publication")
    if not isinstance(value, dict):
        raise PublicationError("publication evidence must contain publication metadata")
    required = ("headOwner", "baseBranch", "title", "bodyFile")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
        raise PublicationError("publication metadata is incomplete")
    body_path = Path(value["bodyFile"]).expanduser().resolve()
    try:
        body = body_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PublicationError("PR body file is unavailable") from exc
    title = value["title"].strip()
    if not body.strip():
        raise PublicationError("PR body must not be empty")
    if not public_text_is_safe(title, body):
        raise PublicationError("public PR text contains an AI-assistance disclosure")
    match = ISSUE_URL.match(issue_url)
    if not match:
        raise PublicationError("invalid issue URL")
    issue_number = match.group(2)
    if issue_url not in body and not re.search(rf"(?<!\w)#{re.escape(issue_number)}\b", body):
        raise PublicationError("PR body must reference the exact issue")
    return {
        "headOwner": value["headOwner"].strip(),
        "baseBranch": value["baseBranch"].strip(),
        "title": title,
        "bodyPath": str(body_path),
        "bodyDigest": sha256_text(body),
    }


def request_publication(
    store: RadarLedger,
    *,
    issue_url: str,
    thread_id: str,
    worktree: Path,
    evidence_path: Path,
) -> dict[str, Any]:
    worktree = worktree.resolve()
    evidence_path = evidence_path.resolve()
    snapshot = _git_snapshot(worktree)
    if snapshot["status"]:
        raise PublicationError("worktree must be clean before publication request")
    if not public_branch_is_safe(snapshot["branch"]):
        raise PublicationError("public branch name exposes an AI tool")
    evidence, evidence_digest = _evidence_file(evidence_path)
    expected = {
        "issueUrl": issue_url,
        "commitSha": snapshot["commitSha"],
        "branch": snapshot["branch"],
        "worktreePath": str(worktree),
    }
    for key, value in expected.items():
        if evidence.get(key) != value:
            raise PublicationError(f"publication evidence mismatch: {key}")
    publication = _publication_payload(evidence, issue_url)
    return store.create_publication_request(
        issue_url=issue_url,
        thread_id=thread_id,
        commit_sha=snapshot["commitSha"],
        branch=snapshot["branch"],
        worktree_path=str(worktree),
        evidence_digest=evidence_digest,
        evidence_path=str(evidence_path),
        publication=publication,
    )


def _upstream_remote(worktree: Path, repo: str) -> str:
    remotes = command(["git", "remote"], cwd=worktree).splitlines()
    for remote in remotes:
        url = command(["git", "remote", "get-url", remote], cwd=worktree)
        if _normalize_origin(url) == repo.casefold():
            return remote
    raise PublicationError("worktree has no remote for the upstream repository")


def _changed_files(worktree: Path, repo: str, default_branch: str) -> list[str]:
    remote = _upstream_remote(worktree, repo)
    command(
        ["git", "fetch", "--quiet", remote, default_branch],
        cwd=worktree,
        timeout=300,
    )
    base = command(["git", "merge-base", "HEAD", f"{remote}/{default_branch}"], cwd=worktree)
    value = command(["git", "diff", "--name-only", f"{base}..HEAD"], cwd=worktree)
    return sorted(line for line in value.splitlines() if line)


def _changed_files_since(worktree: Path, previous_commit: str) -> list[str]:
    command(["git", "merge-base", "--is-ancestor", previous_commit, "HEAD"], cwd=worktree)
    value = command(["git", "diff", "--name-only", f"{previous_commit}..HEAD"], cwd=worktree)
    return sorted(line for line in value.splitlines() if line)


def _dco_valid(worktree: Path, repo: str, default_branch: str) -> bool:
    remote = _upstream_remote(worktree, repo)
    base = command(["git", "merge-base", "HEAD", f"{remote}/{default_branch}"], cwd=worktree)
    name = command(["git", "config", "user.name"], cwd=worktree)
    email = command(["git", "config", "user.email"], cwd=worktree)
    if not name or not email:
        return False
    raw = command(["git", "log", "--format=%B%x00", f"{base}..HEAD"], cwd=worktree)
    messages = [message for message in raw.split("\x00") if message.strip()]
    expected = f"Signed-off-by: {name} <{email}>".casefold()
    return bool(messages) and all(expected in message.casefold() for message in messages)


def audit_publication_request(
    store: RadarLedger,
    request_id: str,
    *,
    client: GitHubClient | None = None,
    expected_existing_pr_head: str | None = None,
) -> PublicationAudit:
    row = store.publication_request(request_id)
    if not row:
        raise LedgerError("publication request not found")
    request = row["request"]
    match = ISSUE_URL.match(str(request.get("issueUrl") or ""))
    if not match:
        return PublicationAudit("BLOCK", "INVALID_ISSUE_URL", request_id, {})
    repo, number = match.groups()
    worktree = Path(request["worktreePath"]).resolve()
    try:
        snapshot = _git_snapshot(worktree)
        evidence_file, evidence_digest = _evidence_file(Path(request["evidencePath"]))
    except (OSError, PublicationError) as exc:
        return PublicationAudit(
            "BLOCK", "LOCAL_EVIDENCE_UNAVAILABLE", request_id, {"error": str(exc)[:200]}
        )
    if snapshot["status"]:
        return PublicationAudit("BLOCK", "WORKTREE_DIRTY", request_id, snapshot)
    if not public_branch_is_safe(snapshot["branch"]):
        return PublicationAudit("BLOCK", "PUBLIC_BRANCH_NAME_UNSAFE", request_id, snapshot)
    if snapshot["commitSha"] != request["commitSha"] or snapshot["branch"] != request["branch"]:
        return PublicationAudit("BLOCK", "COMMIT_OR_BRANCH_DRIFT", request_id, snapshot)
    if evidence_digest != request["evidenceDigest"]:
        return PublicationAudit("BLOCK", "EVIDENCE_DIGEST_DRIFT", request_id, {})
    try:
        publication = _publication_payload(evidence_file, request["issueUrl"])
    except PublicationError as exc:
        return PublicationAudit(
            "BLOCK", "PUBLICATION_PAYLOAD_INVALID", request_id, {"error": str(exc)[:200]}
        )
    if publication != request.get("publication"):
        return PublicationAudit("BLOCK", "PUBLICATION_PAYLOAD_DRIFT", request_id, {})
    quality = request.get("quality") or {}
    assessment = assess_submit_ready(quality)
    if not assessment.ready or evidence_file.get("quality") != quality:
        return PublicationAudit(
            "BLOCK", "SUBMIT_READY_EVIDENCE_INCOMPLETE", request_id, assessment.as_dict()
        )
    intent = request.get("intent") or {}
    if not (
        intent.get("autoSubmitAuthorized") is True
        and intent.get("publicSubmissionAllowed") is True
        and intent.get("authorizationSource") == "signed_live_revalidation_required"
        and intent.get("publicationMode") in {"canary", "active"}
    ):
        return PublicationAudit("BLOCK", "PUBLICATION_NOT_AUTHORIZED", request_id, {})

    github = client or GitHubClient()
    evidence = collect_evidence(
        github,
        repo,
        int(number),
        current_actor=os.environ.get("RADAR_GITHUB_ACTOR", "Oxygen56"),
        hardware_inventory={"4090", "5090", "a100", "v100"},
    )
    publication_kind = str(request.get("publicationKind") or "PR_CREATE")
    existing_pr: dict[str, Any] | None = None
    authorization_evidence = evidence
    if publication_kind == "PR_UPDATE":
        existing_url = str(request.get("existingPrUrl") or "")
        previous_commit = str(request.get("previousCommitSha") or "")
        expected_head = expected_existing_pr_head or previous_commit
        pr_match = PR_URL.fullmatch(existing_url)
        if (
            not pr_match
            or pr_match.group(1).casefold() != repo.casefold()
            or not previous_commit
            or expected_head not in {previous_commit, str(request.get("commitSha") or "")}
        ):
            return PublicationAudit("BLOCK", "PR_UPDATE_BINDING_INVALID", request_id, {})
        try:
            existing_pr = github.pull_request(repo, int(pr_match.group(2)))
        except GitHubError as exc:
            return PublicationAudit(
                "DEFER", "EXISTING_PR_UNAVAILABLE", request_id, {"error": str(exc)[:200]}
            )
        head = existing_pr.get("head") or {}
        head_owner = str(((head.get("repo") or {}).get("owner") or {}).get("login") or "")
        if (
            str(existing_pr.get("state") or "").casefold() != "open"
            or str(existing_pr.get("html_url") or "") != existing_url
            or str(head.get("sha") or "") != expected_head
            or str(head.get("ref") or "") != request.get("branch")
            or head_owner.casefold() != publication["headOwner"].casefold()
        ):
            return PublicationAudit(
                "BLOCK",
                "EXISTING_PR_HEAD_DRIFT",
                request_id,
                {"existingPrUrl": existing_url, "expectedCommitSha": expected_head},
            )
        expected_actor = os.environ.get("RADAR_GITHUB_ACTOR", "Oxygen56").casefold()
        assignees = evidence.issue.get("assignees") or []
        assignee_logins = {
            str(item.get("login") or "").casefold()
            for item in assignees
            if isinstance(item, dict) and item.get("login")
        }
        if assignee_logins and assignee_logins != {expected_actor}:
            return PublicationAudit(
                "BLOCK", "ISSUE_ASSIGNED_TO_ANOTHER_CONTRIBUTOR", request_id, {}
            )
        authorization_evidence = replace(
            evidence,
            issue=evidence.issue | {"assignees": []},
            pull_relations=tuple(
                relation
                for relation in evidence.pull_relations
                if relation.get("url") != existing_url
            ),
        )
    elif publication_kind != "PR_CREATE":
        return PublicationAudit("BLOCK", "PUBLICATION_KIND_INVALID", request_id, {})

    candidate = {
        "category": intent.get("category"),
        "gate_decision": intent.get("scanGate"),
        "auto_spawn": intent.get("autoSpawn") is True,
        "llm_review": intent.get("llmReview") or {},
        "track": intent.get("track"),
        "algorithm_evidence": intent.get("algorithmEvidence"),
    }
    verdict = authorize(candidate, authorization_evidence)
    live = {
        "authorization": verdict.as_dict(),
        "evidence": evidence.as_dict(),
        "publication": publication,
        "publicationKind": publication_kind,
        "existingPr": existing_pr,
    }
    if not evidence.complete:
        return PublicationAudit("DEFER", "LIVE_EVIDENCE_INCOMPLETE", request_id, live)
    if verdict.status != "ALLOW":
        return PublicationAudit("BLOCK", verdict.reason_code, request_id, live)
    try:
        metadata = github.repository(repo)
    except GitHubError as exc:
        return PublicationAudit(
            "DEFER",
            "REPOSITORY_METADATA_UNAVAILABLE",
            request_id,
            live | {"error": str(exc)[:200]},
        )
    default_branch = str(metadata.get("default_branch") or "")
    if not default_branch:
        return PublicationAudit("DEFER", "DEFAULT_BRANCH_UNKNOWN", request_id, live)
    if publication["baseBranch"] != default_branch:
        return PublicationAudit("BLOCK", "BASE_BRANCH_MISMATCH", request_id, live)
    expected_actor = os.environ.get("RADAR_GITHUB_ACTOR", "Oxygen56")
    if publication["headOwner"].casefold() != expected_actor.casefold():
        return PublicationAudit("BLOCK", "FORK_OWNER_MISMATCH", request_id, live)
    try:
        changed_files = (
            _changed_files_since(worktree, str(request["previousCommitSha"]))
            if publication_kind == "PR_UPDATE"
            else _changed_files(worktree, repo, default_branch)
        )
    except PublicationError as exc:
        return PublicationAudit(
            "DEFER", "DIFF_REVALIDATION_FAILED", request_id, live | {"error": str(exc)[:200]}
        )
    if not changed_files or changed_files != sorted(evidence_file.get("changedFiles") or []):
        return PublicationAudit(
            "BLOCK",
            "CHANGED_FILES_MISMATCH",
            request_id,
            live | {"changedFiles": changed_files},
        )
    if evidence.policy.get("dco"):
        try:
            dco_valid = _dco_valid(worktree, repo, default_branch)
        except PublicationError as exc:
            return PublicationAudit(
                "DEFER",
                "DCO_REVALIDATION_FAILED",
                request_id,
                live | {"error": str(exc)[:200]},
            )
        if not dco_valid:
            return PublicationAudit("BLOCK", "DCO_SIGNOFF_MISSING", request_id, live)
    return PublicationAudit(
        "ALLOW",
        "LIVE_PUBLICATION_GATES_PASSED",
        request_id,
        live | {"changedFiles": changed_files, "defaultBranch": default_branch},
    )


def broker_publication_request(
    store: RadarLedger,
    request_id: str,
    *,
    client: GitHubClient | None = None,
) -> dict[str, Any]:
    audit = audit_publication_request(store, request_id, client=client)
    if audit.status == "DEFER":
        store.defer_publication_request(request_id, audit.reason)
        return {"ok": True, "granted": False, "pending": True, "audit": audit.as_dict()}
    if audit.status != "ALLOW":
        store.block_publication_request(request_id, audit.reason)
        return {"ok": True, "granted": False, "pending": False, "audit": audit.as_dict()}
    row = store.publication_request(request_id)
    assert row is not None
    request = row["request"]
    permit = store.grant_publication_request(
        request_id,
        issue_url=request["issueUrl"],
        commit_sha=request["commitSha"],
        branch=request["branch"],
        evidence=audit.evidence,
    )
    return {"ok": True, "granted": True, "permit": permit, "audit": audit.as_dict()}


def public_text_is_safe(title: str, body: str) -> bool:
    return not bool(PUBLIC_AI_DISCLOSURE_RE.search(f"{title}\n{body}"))


def public_branch_is_safe(branch: str) -> bool:
    return bool(branch.strip()) and not bool(PUBLIC_TOOL_BRANCH_RE.search(branch))
