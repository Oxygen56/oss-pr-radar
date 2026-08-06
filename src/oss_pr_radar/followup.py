"""Stateful responsibility triage for already-open upstream pull requests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from .github_client import GitHubClient, GitHubError
from .util import iso_z, sha256_json

FOLLOWUP_VERSION = "pr_followup_v2"
MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
FAILURE_CONCLUSIONS = {
    "failure",
    "timed_out",
    "cancelled",
    "action_required",
    "startup_failure",
}


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
    ) -> tuple[str, int, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str | None]:
        repo = _repo_from_url(str(hit.get("repository_url") or ""))
        number = int(hit.get("number") or 0)
        if not repo or not number:
            return repo, number, {}, [], [], "invalid_pull_reference"
        try:
            pull = client.pull_request(repo, number)
            reviews = client.pull_reviews(repo, number)
            head = str((pull.get("head") or {}).get("sha") or "")
            checks = client.check_runs(repo, head) if head else []
            return repo, number, pull, reviews, checks, None
        except GitHubError as exc:
            return repo, number, {}, [], [], str(exc)[:160]

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

    for repo, number, pull, reviews, checks, error in fetched:
        if not repo or not number:
            continue
        key = f"{repo}#{number}"
        previous_item = previous.get(key, {})
        if error:
            errors.append(f"{key}:{error}")
            continue
        head = str((pull.get("head") or {}).get("sha") or "")
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
        evidence = {
            "headSha": head,
            "mergeConflict": merge_conflict,
            "requestedChanges": requested_changes,
            "failingChecks": failing_check_evidence,
        }
        digest = sha256_json(evidence)
        state_item = {
            "key": key,
            "repo": repo,
            "number": number,
            "url": pull.get("html_url"),
            "title": pull.get("title"),
            "headSha": head,
            "actionDigest": digest,
            "actions": actions,
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
            and previous_item.get("actions") == actions
        )
        if actions and previous_item.get("actionDigest") != digest and not migration_only_change:
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
                "why": "；".join(item["actions"]),
                "test_path": "查看正式 review、失败检查或冲突详情后处理",
                "evidence_digest": item["actionDigest"],
            }
            for item in updates
        ],
        "updates": updates,
        "errors": errors,
        "workers": worker_count,
        "duration_seconds": round(monotonic() - started, 3),
    }
    return state, report
