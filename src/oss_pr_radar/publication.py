"""One-time publication requests and live, commit-bound authorization."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .decision import authorize
from .evidence import collect_evidence
from .github_client import GitHubClient, GitHubError, is_transient_github_error
from .independent_review import controller_review_passed
from .ledger import LedgerError, RadarLedger
from .metrics import assess_submit_ready
from .opportunity import external_side_effect_allowed
from .repo_probe import REPRODUCED_VALIDATED, verify_probe_receipt
from .target_branch import TargetBranchError, resolve_target_base, validate_target_base
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
CONTROL_ROOT = Path(__file__).parents[2]
MAX_PUBLICATION_EVIDENCE_BYTES = 1024 * 1024
_MAX_PUBLICATION_EVIDENCE_BASE64_BYTES = ((MAX_PUBLICATION_EVIDENCE_BYTES + 2) // 3) * 4
_GITHUB_GIT_RETRY_DELAYS = (0.25, 1.0)


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


def _evidence_field_values(evidence: dict[str, Any]) -> dict[str, Any]:
    pre_task = evidence.get("preTaskEvidence")
    pre_task = pre_task if isinstance(pre_task, dict) else {}
    return {
        "key": evidence.get("key"),
        "issueUrl": evidence.get("issueUrl"),
        "commitSha": evidence.get("commitSha"),
        "branch": evidence.get("branch"),
        "worktreePath": evidence.get("worktreePath"),
        "resultDigest": evidence.get("resultDigest"),
        "headSha": evidence.get("headSha"),
        "selectedBaseSha": evidence.get("selectedBaseSha") or pre_task.get("baseSha"),
        "intentId": evidence.get("intentId") or evidence.get("taskId"),
        "codePaths": sorted(
            {
                str(path)
                for path in (
                    evidence.get("codePaths")
                    or pre_task.get("codePathsPlan")
                    or pre_task.get("codePaths")
                    or []
                )
                if str(path).strip()
            }
        ),
    }


def _bind_publication_evidence_to_request(
    evidence: dict[str, Any], request: dict[str, Any], *, digest: str
) -> None:
    expected_digest = str(request.get("evidenceDigest") or "")
    if not expected_digest:
        raise PublicationError("publication evidence request is missing evidenceDigest")
    if digest != expected_digest:
        raise PublicationError("publication evidence snapshot digest mismatch")
    fields = _evidence_field_values(evidence)
    expected = {
        "key": request.get("opportunityKey"),
        "issueUrl": request.get("issueUrl"),
        "commitSha": request.get("commitSha"),
        "branch": request.get("branch"),
        "worktreePath": request.get("worktreePath"),
        "resultDigest": request.get("resultDigest"),
        "headSha": request.get("headSha"),
        "selectedBaseSha": request.get("selectedBaseSha"),
        "intentId": request.get("intentId"),
    }
    for key, expected_value in expected.items():
        if expected_value is None or expected_value == "":
            continue
        if str(fields.get(key) or "") != str(expected_value):
            raise PublicationError(f"publication evidence request mismatch: {key}")
    request_paths = request.get("codePaths")
    if request_paths is not None:
        expected_paths = sorted({str(path) for path in request_paths if str(path).strip()})
        if fields["codePaths"] != expected_paths:
            raise PublicationError("publication evidence request mismatch: codePaths")


def publication_evidence_from_raw(
    raw: bytes,
    *,
    request: dict[str, Any] | None = None,
    require_bound_digest: bool = False,
    label: str = "publication evidence",
) -> tuple[dict[str, Any], str]:
    if len(raw) > MAX_PUBLICATION_EVIDENCE_BYTES:
        raise PublicationError(f"{label} exceeds the maximum size")
    digest = hashlib.sha256(raw).hexdigest()
    if require_bound_digest and (request is None or not request.get("evidenceDigest")):
        raise PublicationError(f"{label} is missing a bound digest")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicationError(f"{label} is not valid UTF-8") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PublicationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must be an object")
    if request is not None:
        _bind_publication_evidence_to_request(value, request, digest=digest)
    return value, digest


def _evidence_file_with_raw(path: Path) -> tuple[dict[str, Any], str, bytes]:
    raw = path.read_bytes()
    value, digest = publication_evidence_from_raw(raw)
    return value, digest, raw


def _evidence_file(path: Path) -> tuple[dict[str, Any], str]:
    value, digest, _raw = _evidence_file_with_raw(path)
    return value, digest


def publication_evidence_from_request(request: dict[str, Any]) -> tuple[dict[str, Any], str]:
    raw_base64 = request.get("evidenceRawBase64")
    if not isinstance(raw_base64, str) or not raw_base64:
        evidence_path = Path(request["evidencePath"]).expanduser().resolve()
        worktree_path = request.get("worktreePath")
        if worktree_path:
            task_result = (
                Path(str(worktree_path)).expanduser().resolve() / ".oss-pr-radar" / "result.json"
            ).resolve()
            if evidence_path == task_result:
                raise PublicationError("task-result publication evidence requires a bound snapshot")
        value, digest, _raw = _evidence_file_with_raw(evidence_path)
        _bind_publication_evidence_to_request(value, request, digest=digest)
        return value, digest
    if len(raw_base64) > _MAX_PUBLICATION_EVIDENCE_BASE64_BYTES:
        raise PublicationError("publication evidence snapshot exceeds the maximum size")
    try:
        raw = base64.b64decode(raw_base64.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PublicationError("publication evidence snapshot is invalid base64") from exc
    return publication_evidence_from_raw(
        raw,
        request=request,
        require_bound_digest=True,
        label="publication evidence snapshot",
    )


def _evidence_from_request(request: dict[str, Any]) -> tuple[dict[str, Any], str]:
    return publication_evidence_from_request(request)


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
    task_result_path = (worktree / ".oss-pr-radar" / "result.json").resolve()
    if evidence_path == task_result_path:
        raise PublicationError(
            "task-result publication evidence requires a controller-bound snapshot"
        )
    evidence, evidence_digest, evidence_raw = _evidence_file_with_raw(evidence_path)
    issue_match = ISSUE_URL.match(issue_url)
    if issue_match is None:
        raise PublicationError("invalid issue URL")
    repo = issue_match.group(1)
    probe_receipt = evidence.get("reproductionReceipt") or evidence.get("probeReceipt")
    pre_task = (
        evidence.get("preTaskEvidence") if isinstance(evidence.get("preTaskEvidence"), dict) else {}
    )
    code_paths = [
        str(path)
        for path in (
            evidence.get("codePaths")
            or pre_task.get("codePathsPlan")
            or pre_task.get("codePaths")
            or []
        )
        if str(path).strip()
    ]
    result_digest = str(evidence.get("resultDigest") or "")
    if not result_digest or not verify_probe_receipt(
        probe_receipt if isinstance(probe_receipt, dict) else {},
        repo=repo,
        base_sha=str(evidence.get("selectedBaseSha") or pre_task.get("baseSha") or ""),
        code_paths=code_paths,
        required_level=REPRODUCED_VALIDATED,
        issue_url=issue_url,
        task_id=str(evidence.get("taskId") or evidence.get("intentId") or thread_id),
        head_sha=str(evidence.get("headSha") or snapshot["commitSha"]),
        commit_sha=snapshot["commitSha"],
        result_digest=result_digest,
    ):
        raise PublicationError("REPRODUCED_VALIDATED probe receipt is required before publication")
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
    target_base = None
    if evidence.get("targetBase") is not None:
        try:
            target_base = validate_target_base(evidence["targetBase"])
        except TargetBranchError as exc:
            raise PublicationError(str(exc)) from exc
        if publication["baseBranch"] != target_base["branch"]:
            raise PublicationError("publication base does not match the audited target branch")
    request = store.create_publication_request(
        issue_url=issue_url,
        thread_id=thread_id,
        intent_id=(
            str(evidence.get("taskId") or evidence.get("intentId"))
            if evidence.get("taskId") or evidence.get("intentId")
            else None
        ),
        commit_sha=snapshot["commitSha"],
        branch=snapshot["branch"],
        worktree_path=str(worktree),
        evidence_digest=evidence_digest,
        evidence_path=str(evidence_path),
        publication=publication,
        probe_receipt=probe_receipt,
        result_digest=result_digest,
        head_sha=str(evidence.get("headSha") or snapshot["commitSha"]),
        selected_base_sha=str(evidence.get("selectedBaseSha") or pre_task.get("baseSha") or ""),
        code_paths=code_paths,
        target_base=target_base,
        target_base_bound="targetBase" in evidence,
        evidence_raw_base64=base64.b64encode(evidence_raw).decode("ascii"),
    )
    publication_evidence_from_request(request["request"])
    return request


def _upstream_remote(worktree: Path, repo: str) -> str:
    remotes = command(["git", "remote"], cwd=worktree).splitlines()
    for remote in remotes:
        url = command(["git", "remote", "get-url", remote], cwd=worktree)
        if _normalize_origin(url) == repo.casefold():
            return remote
    raise PublicationError("worktree has no remote for the upstream repository")


def _github_git_command(args: list[str], *, cwd: Path, timeout: int) -> str:
    for attempt in range(len(_GITHUB_GIT_RETRY_DELAYS) + 1):
        try:
            return command(args, cwd=cwd, timeout=timeout)
        except (PublicationError, subprocess.TimeoutExpired) as exc:
            if attempt >= len(_GITHUB_GIT_RETRY_DELAYS) or not is_transient_github_error(exc):
                raise
            time.sleep(_GITHUB_GIT_RETRY_DELAYS[attempt])
    raise AssertionError("unreachable")


def _refresh_upstream_branch(worktree: Path, repo: str, default_branch: str) -> str:
    remote = _upstream_remote(worktree, repo)
    ref = f"refs/heads/{default_branch}"
    raw = _github_git_command(
        ["git", "ls-remote", "--exit-code", "--heads", remote, ref],
        cwd=worktree,
        timeout=60,
    )
    fields = raw.split()
    if len(fields) != 2 or fields[1] != ref or not re.fullmatch(r"[0-9a-fA-F]{40,64}", fields[0]):
        raise PublicationError("upstream default branch returned an invalid commit")
    live_sha = fields[0].casefold()
    tracking_ref = f"refs/remotes/{remote}/{default_branch}"
    try:
        local_sha = command(["git", "rev-parse", "--verify", tracking_ref], cwd=worktree)
    except PublicationError:
        local_sha = ""
    if local_sha.casefold() != live_sha:
        _github_git_command(
            [
                "git",
                "fetch",
                "--quiet",
                "--no-tags",
                remote,
                f"+{ref}:{tracking_ref}",
            ],
            cwd=worktree,
            timeout=180,
        )
        refreshed_sha = command(["git", "rev-parse", "--verify", tracking_ref], cwd=worktree)
        if refreshed_sha.casefold() != live_sha:
            raise PublicationError("upstream default branch changed during refresh")
    return remote


def _revalidate_legacy_target_base(
    github: GitHubClient,
    repo: str,
    branch: str,
    expected_sha: str,
) -> str:
    """Recheck the prepared default branch used by a legacy null-target task."""

    if re.fullmatch(r"[0-9a-fA-F]{40}", expected_sha or "") is None:
        raise PublicationError("legacy publication lacks a bound base SHA")
    try:
        observed = github.branch(repo, branch)
    except GitHubError as exc:
        raise PublicationError("legacy publication base branch is unavailable") from exc
    observed_sha = str((observed.get("commit") or {}).get("sha") or "").casefold()
    if re.fullmatch(r"[0-9a-f]{40}", observed_sha) is None:
        raise PublicationError("legacy publication base SHA is invalid")
    if observed_sha == expected_sha.casefold():
        return observed_sha
    try:
        comparison = github.compare(repo, expected_sha, observed_sha)
    except GitHubError as exc:
        raise PublicationError("legacy publication base comparison is unavailable") from exc
    if (
        str(comparison.get("status") or "").casefold() not in {"ahead", "identical"}
        or str((comparison.get("merge_base_commit") or {}).get("sha") or "").casefold()
        != expected_sha.casefold()
    ):
        raise PublicationError("legacy publication base branch drifted")
    return observed_sha


def _changed_files(worktree: Path, repo: str, default_branch: str) -> list[str]:
    remote = _refresh_upstream_branch(worktree, repo, default_branch)
    base = command(["git", "merge-base", "HEAD", f"{remote}/{default_branch}"], cwd=worktree)
    value = command(["git", "diff", "--name-only", f"{base}..HEAD"], cwd=worktree)
    return sorted(line for line in value.splitlines() if line)


def _changed_files_since(worktree: Path, previous_commit: str) -> list[str]:
    command(["git", "merge-base", "--is-ancestor", previous_commit, "HEAD"], cwd=worktree)
    value = command(["git", "diff", "--name-only", f"{previous_commit}..HEAD"], cwd=worktree)
    return sorted(line for line in value.splitlines() if line)


def _changed_files_for_pr_update(
    worktree: Path, previous_commit: str, evidence_file: dict[str, Any]
) -> list[str]:
    if evidence_file.get("handoffMode") != "controller_merge_complete":
        return _changed_files_since(worktree, previous_commit)
    merge_base = str(evidence_file.get("mergeBaseSha") or "")
    resolution_files = evidence_file.get("mergeResolutionFiles")
    controller_changed_files = evidence_file.get("controllerCommitChangedFiles")
    if controller_changed_files is None:
        # Legacy merge receipts used changedFiles for the resolution scope.
        controller_changed_files = evidence_file.get("changedFiles")
    if (
        not re.fullmatch(r"[0-9a-f]{40}", merge_base)
        or not isinstance(resolution_files, list)
        or not resolution_files
        or resolution_files != controller_changed_files
        or any(not isinstance(path, str) or not path for path in resolution_files)
    ):
        raise PublicationError("merge publication evidence is incomplete")
    values = command(["git", "rev-list", "--parents", "-n", "1", "HEAD"], cwd=worktree).split()
    if len(values) != 3 or values[1:] != [previous_commit, merge_base]:
        raise PublicationError("merge publication parent binding failed")
    command(["git", "merge-base", "--is-ancestor", previous_commit, "HEAD"], cwd=worktree)
    command(["git", "merge-base", "--is-ancestor", merge_base, "HEAD"], cwd=worktree)
    return sorted(resolution_files)


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
    review_state_root: Path | None = None,
    review_context: dict[str, Any] | None = None,
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
        evidence_file, evidence_digest = _evidence_from_request(request)
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
    receipt = evidence_file.get("reproductionReceipt") or evidence_file.get("probeReceipt")
    pre_task = evidence_file.get("preTaskEvidence")
    pre_task = pre_task if isinstance(pre_task, dict) else {}
    code_paths = [
        str(path)
        for path in (
            evidence_file.get("codePaths")
            or pre_task.get("codePathsPlan")
            or pre_task.get("codePaths")
            or []
        )
        if str(path).strip()
    ]
    result_digest = str(evidence_file.get("resultDigest") or request.get("resultDigest") or "")
    if not result_digest or not verify_probe_receipt(
        receipt if isinstance(receipt, dict) else {},
        repo=repo,
        base_sha=str(
            evidence_file.get("selectedBaseSha")
            or request.get("selectedBaseSha")
            or pre_task.get("baseSha")
            or ""
        ),
        code_paths=code_paths,
        required_level=REPRODUCED_VALIDATED,
        issue_url=str(request.get("issueUrl") or ""),
        task_id=str(
            request.get("taskId") or request.get("intentId") or request.get("threadId") or ""
        ),
        head_sha=str(
            evidence_file.get("headSha") or request.get("headSha") or request.get("commitSha") or ""
        ),
        commit_sha=str(request.get("commitSha") or ""),
        result_digest=result_digest,
    ):
        return PublicationAudit("BLOCK", "BLOCKED_REPRODUCTION_REQUIRED", request_id, {})
    try:
        publication = _publication_payload(evidence_file, request["issueUrl"])
    except PublicationError as exc:
        return PublicationAudit(
            "BLOCK", "PUBLICATION_PAYLOAD_INVALID", request_id, {"error": str(exc)[:200]}
        )
    if publication != request.get("publication"):
        return PublicationAudit("BLOCK", "PUBLICATION_PAYLOAD_DRIFT", request_id, {})
    if evidence_file.get("targetBase") != request.get("targetBase"):
        return PublicationAudit("BLOCK", "TARGET_BASE_EVIDENCE_DRIFT", request_id, {})
    quality = request.get("quality") or {}
    assessment = assess_submit_ready(quality)
    if not assessment.ready or evidence_file.get("quality") != quality:
        return PublicationAudit(
            "BLOCK", "SUBMIT_READY_EVIDENCE_INCOMPLETE", request_id, assessment.as_dict()
        )
    if review_state_root is None and review_context is None:
        review_passed = controller_review_passed(CONTROL_ROOT, evidence_file)
    elif review_state_root is None:
        review_passed = controller_review_passed(
            CONTROL_ROOT,
            evidence_file,
            review_context=review_context,
        )
    elif review_context is None:
        review_passed = controller_review_passed(
            CONTROL_ROOT,
            evidence_file,
            state_root=review_state_root,
        )
    else:
        review_passed = controller_review_passed(
            CONTROL_ROOT,
            evidence_file,
            state_root=review_state_root,
            review_context=review_context,
        )
    if not review_passed:
        return PublicationAudit("BLOCK", "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED", request_id, {})
    intent = request.get("intent") or {}
    if not external_side_effect_allowed(intent):
        return PublicationAudit("BLOCK", "SILENT_EXPLORATION_NOT_PUBLISHABLE", request_id, {})
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
        if evidence_file.get("handoffMode") == "controller_merge_complete":
            base = existing_pr.get("base") or {}
            base_ref = str(base.get("ref") or "")
            base_repo = str(((base.get("repo") or {}).get("full_name") or repo))
            if not base_ref:
                return PublicationAudit(
                    "DEFER",
                    "EXISTING_PR_BASE_UNAVAILABLE",
                    request_id,
                    {"existingPrUrl": existing_url},
                )
            try:
                live_base = github.branch(base_repo, base_ref)
            except GitHubError as exc:
                return PublicationAudit(
                    "DEFER",
                    "EXISTING_PR_BASE_UNAVAILABLE",
                    request_id,
                    {"existingPrUrl": existing_url, "error": str(exc)[:200]},
                )
            live_base_sha = str((live_base.get("commit") or {}).get("sha") or "")
            if not live_base_sha:
                return PublicationAudit(
                    "DEFER",
                    "EXISTING_PR_BASE_UNAVAILABLE",
                    request_id,
                    {"existingPrUrl": existing_url},
                )
            if live_base_sha != evidence_file.get("mergeBaseSha"):
                return PublicationAudit(
                    "BLOCK",
                    "EXISTING_PR_BASE_DRIFT",
                    request_id,
                    {
                        "existingPrUrl": existing_url,
                        "expectedBaseSha": evidence_file.get("mergeBaseSha"),
                        "observedBaseSha": live_base_sha,
                    },
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
        required_evidence_complete = all(
            value == "COMPLETE"
            for name, value in evidence.completeness.items()
            if name != "relatedPullRequests"
        )
        authorization_evidence = replace(
            evidence,
            complete=required_evidence_complete,
            issue=evidence.issue | {"assignees": []},
            # Duplicate PRs prevent new submissions, but must not freeze a
            # fully bound update to this controller's already-open PR. The
            # direct PR binding above also makes best-effort enrichment of
            # other related PRs optional for this update only.
            pull_relations=(),
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
        "bound_pr_update": publication_kind == "PR_UPDATE",
    }
    verdict = authorize(candidate, authorization_evidence)
    live = {
        "authorization": verdict.as_dict(),
        "evidence": evidence.as_dict(),
        "publication": publication,
        "publicationKind": publication_kind,
        "existingPr": existing_pr,
    }
    if not authorization_evidence.complete:
        return PublicationAudit("DEFER", "LIVE_EVIDENCE_INCOMPLETE", request_id, live)
    if verdict.status == "HOLD":
        return PublicationAudit("DEFER", verdict.reason_code, request_id, live)
    if verdict.status != "ALLOW":
        return PublicationAudit("BLOCK", verdict.reason_code, request_id, live)
    target_base_value = request.get("targetBase")
    live_target_base = None
    if target_base_value is not None:
        try:
            target_base = validate_target_base(target_base_value)
            live_target_base = resolve_target_base(github, repo, evidence.issue)
        except TargetBranchError as exc:
            return PublicationAudit(
                "DEFER", "TARGET_BASE_UNAVAILABLE", request_id, live | {"error": str(exc)[:200]}
            )
        if (
            publication["baseBranch"] != target_base["branch"]
            or live_target_base["branch"] != target_base["branch"]
        ):
            return PublicationAudit("BLOCK", "TARGET_BASE_MISMATCH", request_id, live)
        if live_target_base["sha"] != target_base["sha"]:
            try:
                comparison = github.compare(repo, target_base["sha"], live_target_base["sha"])
            except GitHubError as exc:
                return PublicationAudit(
                    "DEFER",
                    "TARGET_BASE_UNAVAILABLE",
                    request_id,
                    live | {"error": str(exc)[:200]},
                )
            compare_status = str(comparison.get("status") or "").casefold()
            merge_base_sha = str(
                (comparison.get("merge_base_commit") or {}).get("sha") or ""
            ).casefold()
            if compare_status not in {"ahead", "identical"} or merge_base_sha != target_base["sha"]:
                return PublicationAudit("BLOCK", "TARGET_BASE_DRIFT", request_id, live)
        base_branch = target_base["branch"]
        default_branch = live_target_base["defaultBranch"]
    else:
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
        if "targetBase" in request:
            try:
                _revalidate_legacy_target_base(
                    github,
                    repo,
                    default_branch,
                    str(
                        request.get("selectedBaseSha") or evidence_file.get("selectedBaseSha") or ""
                    ),
                )
            except PublicationError as exc:
                return PublicationAudit(
                    "BLOCK", "TARGET_BASE_DRIFT", request_id, live | {"error": str(exc)[:200]}
                )
        base_branch = default_branch
    expected_actor = os.environ.get("RADAR_GITHUB_ACTOR", "Oxygen56")
    if publication["headOwner"].casefold() != expected_actor.casefold():
        return PublicationAudit("BLOCK", "FORK_OWNER_MISMATCH", request_id, live)
    update_changed_files: list[str] = []
    try:
        if publication_kind == "PR_UPDATE":
            update_changed_files = _changed_files_for_pr_update(
                worktree, str(request["previousCommitSha"]), evidence_file
            )
            changed_files = _changed_files(worktree, repo, base_branch)
        else:
            changed_files = _changed_files(worktree, repo, base_branch)
    except PublicationError as exc:
        return PublicationAudit(
            "DEFER", "DIFF_REVALIDATION_FAILED", request_id, live | {"error": str(exc)[:200]}
        )
    if (
        not changed_files
        or (publication_kind == "PR_UPDATE" and not update_changed_files)
        or changed_files != sorted(evidence_file.get("changedFiles") or [])
    ):
        return PublicationAudit(
            "BLOCK",
            "CHANGED_FILES_MISMATCH",
            request_id,
            live
            | {
                "changedFiles": changed_files,
                "updateChangedFiles": update_changed_files,
            },
        )
    if evidence.policy.get("dco"):
        try:
            dco_valid = _dco_valid(worktree, repo, base_branch)
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
        live
        | {
            "changedFiles": changed_files,
            "updateChangedFiles": update_changed_files,
            "defaultBranch": default_branch,
            "targetBase": target_base_value,
            "liveTargetBase": live_target_base,
        },
    )


def broker_publication_request(
    store: RadarLedger,
    request_id: str,
    *,
    client: GitHubClient | None = None,
    review_state_root: Path | None = None,
    review_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    audit = audit_publication_request(
        store,
        request_id,
        client=client,
        review_state_root=review_state_root,
        review_context=review_context,
    )
    if audit.status == "DEFER":
        store.defer_publication_request(request_id, audit.reason, evidence=audit.evidence)
        return {"ok": True, "granted": False, "pending": True, "audit": audit.as_dict()}
    if audit.status != "ALLOW":
        store.block_publication_request(request_id, audit.reason, evidence=audit.evidence)
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
