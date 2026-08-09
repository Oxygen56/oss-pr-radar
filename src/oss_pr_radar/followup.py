"""Stateful responsibility triage for already-open upstream pull requests."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any

from .github_client import GitHubClient, GitHubError
from .util import iso_z, sha256_json

FOLLOWUP_VERSION = "pr_followup_v3"
MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
FAILURE_CONCLUSIONS = {
    "failure",
    "timed_out",
    "cancelled",
    "action_required",
    "startup_failure",
}
TASK_FAILURE_CONCLUSIONS = {"failure", "action_required", "startup_failure"}
AGGREGATE_CHECK_NAMES = {
    "ci success",
    "all checks passed",
    "required checks",
    "build success",
}
LANGUAGE_CHECK_TERMS = {
    ".rs": ("rust", "cargo", "clippy"),
    ".go": ("golang", "go test", "gofmt", "go vet", "golangci"),
    ".py": ("python", "pytest", "ruff", "mypy", "pyright"),
    ".js": ("javascript", "node", "npm", "pnpm", "yarn", "eslint", "jest"),
    ".jsx": ("javascript", "node", "npm", "pnpm", "yarn", "eslint", "jest"),
    ".ts": ("typescript", "node", "npm", "pnpm", "yarn", "eslint", "vitest"),
    ".tsx": ("typescript", "node", "npm", "pnpm", "yarn", "eslint", "vitest"),
    ".java": ("java", "gradle", "maven"),
    ".kt": ("kotlin", "gradle"),
    ".kts": ("kotlin", "gradle"),
    ".c": ("clang", "gcc", "cmake", "meson"),
    ".cc": ("clang", "gcc", "cmake", "meson", "c++"),
    ".cpp": ("clang", "gcc", "cmake", "meson", "c++"),
    ".h": ("clang", "gcc", "cmake", "meson", "c++"),
    ".hpp": ("clang", "gcc", "cmake", "meson", "c++"),
}
GENERIC_CODE_CHECK_NAMES = {
    "build",
    "compile",
    "integration test",
    "integration tests",
    "lint",
    "test",
    "tests",
    "type check",
    "typecheck",
    "unit test",
    "unit tests",
}


def _annotation_evidence(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": value.get("path"),
        "startLine": value.get("start_line"),
        "endLine": value.get("end_line"),
        "level": value.get("annotation_level"),
        "message": str(value.get("message") or "")[:400],
    }


def _normalized_check_name(check: dict[str, Any]) -> str:
    return " ".join(re.sub(r"[^a-z0-9+#.]+", " ", str(check.get("name") or "").casefold()).split())


def _is_aggregate_check(check: dict[str, Any]) -> bool:
    name = _normalized_check_name(check)
    return name in AGGREGATE_CHECK_NAMES or "status check" in name or "all dependent jobs" in name


def _informative_annotation_paths(check: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for item in check.get("_annotations") or []:
        path = str(item.get("path") or "").strip()
        if not path or path == ".github" or path.startswith(".github/workflows/"):
            continue
        paths.add(path)
    return paths


def _check_action_basis(check: dict[str, Any], changed_files: set[str]) -> str | None:
    conclusion = str(check.get("conclusion") or "").casefold()
    if conclusion not in TASK_FAILURE_CONCLUSIONS or _is_aggregate_check(check):
        return None
    annotations = check.get("_annotations") or []
    if any(str(item.get("path") or "") in changed_files for item in annotations):
        return "changed_file_annotation"
    output = check.get("output") or {}
    summary = "\n".join(
        str(output.get(field) or "") for field in ("title", "summary", "text")
    ).casefold()
    if any(path.casefold() in summary for path in changed_files if path):
        return "changed_file_output"

    # GitHub Actions frequently emits only a generic `.github` exit-code
    # annotation for compiler and test failures. Preserve explicit unrelated
    # source annotations, but diagnose unattributed checks that match the
    # language of files changed by this PR.
    if _informative_annotation_paths(check):
        return None
    name = _normalized_check_name(check)
    changed_suffixes = {Path(path).suffix.casefold() for path in changed_files}
    if any(
        term in name for suffix in changed_suffixes for term in LANGUAGE_CHECK_TERMS.get(suffix, ())
    ):
        return "unattributed_language_check"
    if name in GENERIC_CODE_CHECK_NAMES and any(
        suffix in LANGUAGE_CHECK_TERMS for suffix in changed_suffixes
    ):
        return "unattributed_code_check"
    return None


def _actionable_review_threads(
    threads: list[dict[str, Any]], *, author: str, changed_files: set[str]
) -> list[dict[str, Any]]:
    actionable: list[dict[str, Any]] = []
    for thread in threads:
        if thread.get("isResolved") is True or thread.get("isOutdated") is True:
            continue
        comments = (thread.get("comments") or {}).get("nodes") or []
        comments = [item for item in comments if isinstance(item, dict)]
        if not comments:
            continue
        latest = max(
            comments,
            key=lambda item: (str(item.get("createdAt") or ""), str(item.get("url") or "")),
        )
        actor = latest.get("author") or {}
        login = str(actor.get("login") or "")
        association = str(latest.get("authorAssociation") or "").upper()
        author_type = str(actor.get("__typename") or "")
        path = str(thread.get("path") or "")
        if login.casefold() == author.casefold():
            continue
        trusted_reviewer = association in MAINTAINER_ASSOCIATIONS
        review_bot = author_type == "Bot" and path in changed_files
        if not trusted_reviewer and not review_bot:
            continue
        actionable.append(
            {
                "path": path,
                "reviewer": login,
                "association": association,
                "authorType": author_type,
                "createdAt": latest.get("createdAt"),
                "url": latest.get("url"),
                "summary": " ".join(str(latest.get("body") or "").split())[:400],
            }
        )
    return sorted(
        actionable,
        key=lambda item: (
            str(item["path"]),
            str(item["reviewer"]),
            str(item["createdAt"] or ""),
        ),
    )


def _latest_reviews_by_author(reviews: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        login = str((review.get("user") or {}).get("login") or "").casefold()
        if not login:
            continue
        ordering = (
            str(review.get("submitted_at") or ""),
            int(review.get("id") or 0),
        )
        previous = latest.get(login)
        previous_ordering = (
            (
                str(previous.get("submitted_at") or ""),
                int(previous.get("id") or 0),
            )
            if previous
            else ("", 0)
        )
        if previous is None or ordering >= previous_ordering:
            latest[login] = review
    return list(latest.values())


def _repo_from_url(value: str) -> str:
    marker = "https://api.github.com/repos/"
    if value.startswith(marker):
        return value[len(marker) :].split("/issues/", 1)[0]
    return ""


def collect_followup(
    client: GitHubClient,
    *,
    author: str,
    existing: dict[str, Any] | None = None,
    limit: int = 40,
    now: datetime | None = None,
    workers: int = 4,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = monotonic()
    current = (now or datetime.now(UTC)).astimezone(UTC)
    existing_version = str((existing or {}).get("version") or "")
    previous = {
        item.get("key"): item
        for item in (existing or {}).get("items", [])
        if isinstance(item, dict) and item.get("key")
    }
    state_items: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    errors: list[str] = []

    def fetch(
        hit: dict[str, Any],
    ) -> tuple[
        str,
        int,
        dict[str, Any],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]] | None,
        str | None,
        str | None,
    ]:
        repo = _repo_from_url(str(hit.get("repository_url") or ""))
        number = int(hit.get("number") or 0)
        if not repo or not number:
            return repo, number, {}, [], [], [], [], "invalid_pull_reference", None
        try:
            pull = client.pull_request(repo, number)
            base = pull.get("base") or {}
            base_repo = str(((base.get("repo") or {}).get("full_name") or repo))
            base_ref_name = str(base.get("ref") or "")
            if not base_ref_name:
                raise GitHubError("pull request base branch is missing")
            live_base = client.branch(base_repo, base_ref_name)
            live_base_sha = str((live_base.get("commit") or {}).get("sha") or "")
            if not live_base_sha:
                raise GitHubError("pull request live base head is missing")
            pull["_live_base"] = {
                "ref": base_ref_name,
                "repo": base_repo,
                "sha": live_base_sha,
            }
            reviews = client.pull_reviews(repo, number)
            files = client.pull_files(repo, number)
            review_threads: list[dict[str, Any]] | None
            review_thread_error = None
            try:
                review_threads = client.pull_review_threads(repo, number)
            except GitHubError as exc:
                review_threads = None
                review_thread_error = str(exc)[:160]
            head = str((pull.get("head") or {}).get("sha") or "")
            checks = client.check_runs(repo, head) if head else []
            annotation_budget = 8
            for check in checks:
                conclusion = str(check.get("conclusion") or "").casefold()
                name = str(check.get("name") or "").strip().casefold()
                check_id = int(check.get("id") or 0)
                if (
                    conclusion in TASK_FAILURE_CONCLUSIONS
                    and name not in AGGREGATE_CHECK_NAMES
                    and check_id
                    and annotation_budget > 0
                ):
                    annotation_budget -= 1
                    try:
                        check["_annotations"] = client.check_annotations(repo, check_id)
                    except GitHubError as exc:
                        check["_annotations"] = []
                        check["_annotation_error"] = str(exc)[:160]
            return (
                repo,
                number,
                pull,
                reviews,
                checks,
                files,
                review_threads,
                None,
                review_thread_error,
            )
        except GitHubError as exc:
            return repo, number, {}, [], [], [], [], str(exc)[:160], None

    try:
        hits = client.open_pull_requests_by_author(author)[:limit]
    except GitHubError as exc:
        state = {
            "version": FOLLOWUP_VERSION,
            "generatedAt": iso_z(current),
            "items": sorted(previous.values(), key=lambda item: str(item.get("key") or "")),
        }
        state["digest"] = sha256_json(
            {key: value for key, value in state.items() if key != "digest"}
        )
        return state, {
            "scan_ok": False,
            "run_id": f"pr-followup-{int(current.timestamp())}",
            "candidate_details": [],
            "updates": [],
            "errors": [f"open_pull_requests:{str(exc)[:160]}"],
            "workers": 0,
            "duration_seconds": round(monotonic() - started, 3),
        }
    worker_count = max(1, min(int(workers), 6, len(hits) or 1))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        fetched = list(executor.map(fetch, hits))

    for repo, number, pull, reviews, checks, files, review_threads, error, thread_error in fetched:
        if not repo or not number:
            continue
        key = f"{repo}#{number}"
        previous_item = previous.get(key, {})
        if error:
            errors.append(f"{key}:{error}")
            continue
        head = str((pull.get("head") or {}).get("sha") or "")
        base_ref_name = str((pull.get("_live_base") or {}).get("ref") or "")
        base_sha = str((pull.get("_live_base") or {}).get("sha") or "")
        maintainer_changes = [
            review
            for review in _latest_reviews_by_author(reviews)
            if str(review.get("state") or "").upper() == "CHANGES_REQUESTED"
            and str(review.get("author_association") or "").upper() in MAINTAINER_ASSOCIATIONS
        ]
        failing_checks = [
            check
            for check in checks
            if str(check.get("status") or "").lower() == "completed"
            and str(check.get("conclusion") or "").lower() in FAILURE_CONCLUSIONS
        ]
        changed_files = {str(item.get("filename") or "") for item in files if item.get("filename")}
        previous_evidence = previous_item.get("evidence") or {}
        if review_threads is None:
            unresolved_review_threads = previous_evidence.get("unresolvedReviewThreads") or []
            errors.append(f"{key}:review_threads:{thread_error or 'unavailable'}")
        else:
            unresolved_review_threads = _actionable_review_threads(
                review_threads, author=author, changed_files=changed_files
            )
        actionable_checks = []
        for check in failing_checks:
            basis = _check_action_basis(check, changed_files)
            if basis:
                actionable_checks.append(check | {"_action_basis": basis})
        inferred_check_failure = any(
            str(check.get("_action_basis") or "").startswith("unattributed_")
            for check in actionable_checks
        )
        base_integration_required = False
        base_compare_status = None
        base_merge_base_sha = None
        base_compare_error = None
        if inferred_check_failure and head and base_sha:
            try:
                comparison = client.compare(repo, base_sha, head)
                base_compare_status = str(comparison.get("status") or "").casefold() or None
                base_merge_base_sha = (
                    str((comparison.get("merge_base_commit") or {}).get("sha") or "") or None
                )
                base_integration_required = base_compare_status in {"behind", "diverged"} or (
                    bool(base_merge_base_sha) and base_merge_base_sha != base_sha
                )
            except GitHubError as exc:
                base_compare_error = str(exc)[:160]
                # The controller performs an independent ancestry check before
                # preparing a merge. Conservatively request that check instead
                # of letting an unavailable comparison hide a merge-state CI
                # failure.
                base_integration_required = True
        mergeable_state = str(pull.get("mergeable_state") or "").lower()
        previous_conflict = previous_item.get("mergeConflict")
        if previous_conflict is None:
            previous_conflict = "分支存在合并冲突" in previous_item.get("actions", [])
        merge_conflict = (
            bool(previous_conflict)
            if mergeable_state in {"", "unknown"}
            else mergeable_state == "dirty"
        )
        requested_changes = sorted(
            (
                {
                    "reviewer": (item.get("user") or {}).get("login"),
                    "submittedAt": item.get("submitted_at"),
                }
                for item in maintainer_changes
            ),
            key=lambda item: (str(item["reviewer"] or ""), str(item["submittedAt"] or "")),
        )
        failing_check_evidence = sorted(
            (
                {
                    "name": item.get("name"),
                    "conclusion": item.get("conclusion"),
                    "url": item.get("details_url"),
                    "annotations": [
                        _annotation_evidence(annotation)
                        for annotation in (item.get("_annotations") or [])[:20]
                    ],
                }
                for item in failing_checks
            ),
            key=lambda item: (
                str(item["name"] or ""),
                str(item["conclusion"] or ""),
                str(item["url"] or ""),
            ),
        )
        actions: list[str] = []
        if maintainer_changes:
            actions.append("正式 review 要求修改")
        if failing_checks:
            actions.append("CI 检查失败")
        if merge_conflict:
            actions.append("分支存在合并冲突")
        if unresolved_review_threads:
            actions.append("存在未解决审查线程")
        task_actions: list[str] = []
        if maintainer_changes:
            task_actions.append("正式 review 要求修改")
        if actionable_checks:
            task_actions.append("当前分支检查失败")
        if merge_conflict:
            task_actions.append("分支存在合并冲突")
        if unresolved_review_threads:
            task_actions.append("存在未解决审查线程")
        actionable_check_names = sorted(
            str(item.get("name") or "") for item in actionable_checks if item.get("name")
        )
        actionable_check_evidence = sorted(
            (
                {
                    "name": item.get("name"),
                    "url": item.get("details_url"),
                    "basis": item.get("_action_basis"),
                    "annotations": [
                        _annotation_evidence(annotation)
                        for annotation in (item.get("_annotations") or [])[:20]
                    ],
                }
                for item in actionable_checks
            ),
            key=lambda item: (str(item["name"] or ""), str(item["url"] or "")),
        )
        evidence = {
            "headSha": head,
            "baseRefName": base_ref_name,
            "baseSha": base_sha,
            "mergeConflict": merge_conflict,
            "requestedChanges": requested_changes,
            "failingChecks": failing_check_evidence,
            "changedFiles": sorted(changed_files),
            "actionableCheckNames": actionable_check_names,
            "baseIntegrationRequired": base_integration_required,
            "baseCompareStatus": base_compare_status,
            "baseMergeBaseSha": base_merge_base_sha,
            "baseCompareError": base_compare_error,
            "unresolvedReviewThreads": unresolved_review_threads,
        }
        action_evidence = {
            "mergeConflictHead": head if merge_conflict else None,
            "mergeConflictBaseRefName": base_ref_name if merge_conflict else None,
            "mergeConflictBaseSha": base_sha if merge_conflict else None,
            "requestedChanges": requested_changes,
            "failingChecks": failing_check_evidence,
            "unresolvedReviewThreads": unresolved_review_threads,
        }
        digest = sha256_json(action_evidence)
        task_evidence = {
            "mergeConflictHead": head if merge_conflict else None,
            "mergeConflictBaseRefName": base_ref_name if merge_conflict else None,
            "mergeConflictBaseSha": base_sha if merge_conflict else None,
            "requestedChanges": requested_changes,
            "actionableChecks": actionable_check_evidence,
            "baseIntegrationRequired": base_integration_required,
            "baseIntegrationHead": head if base_integration_required else None,
            "baseIntegrationBaseRefName": (base_ref_name if base_integration_required else None),
            "baseIntegrationBaseSha": base_sha if base_integration_required else None,
            "unresolvedReviewThreads": unresolved_review_threads,
        }
        task_digest = sha256_json(task_evidence)
        state_item = {
            "key": key,
            "repo": repo,
            "number": number,
            "url": pull.get("html_url"),
            "title": pull.get("title"),
            "headSha": head,
            "baseRefName": base_ref_name,
            "baseSha": base_sha,
            "actionDigest": digest,
            "actions": actions,
            "taskActions": task_actions,
            "taskActionDigest": task_digest,
            "taskFollowupRequired": bool(task_actions),
            "evidence": evidence,
            "mergeableState": mergeable_state,
            "mergeConflict": merge_conflict,
            "draft": bool(pull.get("draft")),
            "checkedAt": iso_z(current),
        }
        state_items.append(state_item)
        migration_only_change = (
            existing_version != FOLLOWUP_VERSION
            and bool(previous_item)
            and previous_item.get("headSha") == head
            and (
                previous_item.get("taskActions") == task_actions
                or ("taskActions" not in previous_item and previous_item.get("actions") == actions)
            )
        )
        if (
            task_actions
            and previous_item.get("taskActionDigest") != task_digest
            and not migration_only_change
        ):
            updates.append(state_item | {"evidence": evidence})
    state = {
        "version": FOLLOWUP_VERSION,
        "generatedAt": iso_z(current),
        "items": sorted(state_items, key=lambda item: item["key"]),
    }
    state["digest"] = sha256_json({key: value for key, value in state.items() if key != "digest"})
    report = {
        "scan_ok": not errors,
        "run_id": f"pr-followup-{int(current.timestamp())}",
        "candidate_details": [
            {
                "key": item["key"],
                "repo": item["repo"],
                "num": item["number"],
                "url": item["url"],
                "title": item["title"],
                "category": "PR_FOLLOWUP",
                "score": None,
                "auto_spawn": False,
                "notify": True,
                "why": "；".join(item["taskActions"]),
                "test_path": "查看正式 review、分支相关失败检查、审查线程或冲突详情后处理",
                "evidence_digest": item["taskActionDigest"],
            }
            for item in updates
        ],
        "updates": updates,
        "errors": errors,
        "workers": worker_count,
        "duration_seconds": round(monotonic() - started, 3),
    }
    return state, report
