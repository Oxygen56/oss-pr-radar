"""Stateful responsibility triage for already-open upstream pull requests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .github_client import GitHubClient, GitHubError
from .util import iso_z, sha256_json

FOLLOWUP_VERSION = "pr_followup_v1"
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
) -> tuple[dict[str, Any], dict[str, Any]]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    previous = {
        item.get("key"): item
        for item in (existing or {}).get("items", [])
        if isinstance(item, dict) and item.get("key")
    }
    state_items: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    errors: list[str] = []
    for hit in client.open_pull_requests_by_author(author)[:limit]:
        repo = _repo_from_url(str(hit.get("repository_url") or ""))
        number = int(hit.get("number") or 0)
        if not repo or not number:
            continue
        key = f"{repo}#{number}"
        try:
            pull = client.pull_request(repo, number)
            reviews = client.pull_reviews(repo, number)
            head = str((pull.get("head") or {}).get("sha") or "")
            checks = client.check_runs(repo, head) if head else []
        except GitHubError as exc:
            errors.append(f"{key}:{str(exc)[:160]}")
            continue
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
        actions: list[str] = []
        if maintainer_changes:
            actions.append("正式 review 要求修改")
        if failing_checks:
            actions.append("CI 检查失败")
        if str(pull.get("mergeable_state") or "").lower() == "dirty":
            actions.append("分支存在合并冲突")
        evidence = {
            "headSha": head,
            "mergeableState": pull.get("mergeable_state"),
            "draft": bool(pull.get("draft")),
            "requestedChanges": [
                {
                    "reviewer": (item.get("user") or {}).get("login"),
                    "submittedAt": item.get("submitted_at"),
                }
                for item in maintainer_changes
            ],
            "failingChecks": [
                {
                    "name": item.get("name"),
                    "conclusion": item.get("conclusion"),
                    "url": item.get("details_url"),
                }
                for item in failing_checks
            ],
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
            "checkedAt": iso_z(current),
        }
        state_items.append(state_item)
        if actions and previous.get(key, {}).get("actionDigest") != digest:
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
                "why": "；".join(item["actions"]),
                "test_path": "查看正式 review、失败检查或冲突详情后处理",
                "evidence_digest": item["actionDigest"],
            }
            for item in updates
        ],
        "updates": updates,
        "errors": errors,
    }
    return state, report
