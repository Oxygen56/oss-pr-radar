"""Classify whether pull requests already cover an issue."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from .util import parse_time

WORD_RE = re.compile(r"[a-z][a-z0-9_+-]{2,}", re.I)
STOP = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "this",
    "that",
    "issue",
    "pull",
    "request",
    "fix",
    "fixed",
    "fixes",
    "close",
    "closes",
    "update",
    "add",
}
ACTIVE_EXACT_PR_WINDOW = timedelta(days=30)


@dataclass(frozen=True)
class PullRelation:
    number: int
    url: str
    relation: str
    exact_link: bool
    title_overlap: float
    has_tests: bool
    checks_green: bool | None
    maintainer_approved: bool
    maintainer_owned: bool
    targeted_check_unproven: bool
    current_blocking_review: bool
    draft: bool
    state: str
    merged: bool
    updated_at: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _terms(value: str) -> set[str]:
    return {word.casefold() for word in WORD_RE.findall(value) if word.casefold() not in STOP}


def _overlap(left: str, right: str) -> float:
    lterms, rterms = _terms(left), _terms(right)
    if not lterms or not rterms:
        return 0.0
    return len(lterms & rterms) / len(lterms | rterms)


def _active_exact_pr(updated_at: str, *, now: datetime) -> bool:
    if not updated_at:
        # Missing freshness evidence cannot justify creating a competing PR.
        return True
    try:
        return parse_time(updated_at) >= now - ACTIVE_EXACT_PR_WINDOW
    except (TypeError, ValueError):
        return True


def _review_commit(review: dict[str, Any]) -> str:
    commit = review.get("commit")
    if isinstance(commit, dict):
        return str(commit.get("oid") or commit.get("sha") or "")
    return str(review.get("commit_id") or review.get("commitId") or "")


def _current_blocking_review(pr: dict[str, Any], reviews: list[dict[str, Any]]) -> bool:
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    head_sha = str(head.get("sha") or pr.get("headRefOid") or "")
    for review in reviews:
        review_commit = _review_commit(review)
        if head_sha and review_commit and review_commit != head_sha:
            continue
        state = str(review.get("state") or "").upper()
        body = str(review.get("body") or "")
        if state == "CHANGES_REQUESTED" or re.search(r"\bP[012]\s*:", body, re.I):
            return True
    return False


def _targeted_check_unproven(issue_title: str, checks: list[dict[str, Any]]) -> bool:
    targeted = [
        check for check in checks if _overlap(issue_title, str(check.get("name") or "")) >= 0.18
    ]
    proven = {"success", "neutral", "skipped"}
    return bool(targeted) and any(
        str(check.get("conclusion") or "").casefold() not in proven for check in targeted
    )


def assess_relations(
    *,
    repo: str,
    issue_number: int,
    issue_title: str,
    pull_requests: Iterable[dict[str, Any]],
) -> list[PullRelation]:
    relations: list[PullRelation] = []
    now = datetime.now(UTC)
    issue_targets = (
        rf"(?:#{issue_number}\b|"
        rf"{re.escape(repo)}#{issue_number}\b|"
        rf"https://github\.com/{re.escape(repo)}/issues/{issue_number}\b)"
    )
    coverage_pattern = re.compile(
        rf"\b(?:fixe[sd]?|close[sd]?|resolve[sd]?|address(?:e[sd])?)"
        rf"\s*:?[ ]*{issue_targets}",
        re.I,
    )
    reported_pattern = re.compile(
        rf"\b(?:reported|reproduced|described)\s+in\s*:?[ ]*{issue_targets}",
        re.I,
    )
    reference_pattern = re.compile(issue_targets, re.I)
    for pr in pull_requests:
        body = str(pr.get("body") or "")
        title = str(pr.get("title") or "")
        overlap = _overlap(issue_title, title)
        files = pr.get("files") or []
        has_tests = any(
            re.search(
                r"(?:^|/)(?:test|tests|spec)(?:/|_|\.)",
                str(item.get("filename") or item.get("path") or ""),
                re.I,
            )
            for item in files
            if isinstance(item, dict)
        )
        timeline_event = str(pr.get("_timeline_event") or "").casefold()
        pr_repo = str(pr.get("_repo") or repo).casefold()
        corroborated_report = bool(
            pr_repo == repo.casefold()
            and reported_pattern.search(body)
            and overlap >= 0.4
            and has_tests
        )
        # A cross-reference can be created in either direction. In particular,
        # an issue that cites an older PR as background causes GitHub to emit a
        # cross-reference from that PR. A same-repository "reported in" link is
        # accepted only when matching title semantics and regression tests
        # independently corroborate that the PR covers the report.
        exact = (
            timeline_event == "connected"
            or bool(coverage_pattern.search(body))
            or corroborated_report
        )
        reference_only = not exact and bool(reference_pattern.search(body))
        checks = pr.get("checks")
        checks_green: bool | None = None
        if isinstance(checks, list) and checks:
            conclusions = {
                str(item.get("conclusion") or "").lower()
                for item in checks
                if isinstance(item, dict)
            }
            checks_green = bool(conclusions) and conclusions <= {"success", "neutral", "skipped"}
        check_rows = [item for item in checks or [] if isinstance(item, dict)]
        targeted_check_unproven = _targeted_check_unproven(issue_title, check_rows)
        draft = bool(pr.get("draft") or pr.get("isDraft"))
        state = str(pr.get("state") or "open").upper()
        merged = bool(pr.get("merged_at") or pr.get("mergedAt"))
        reviews = [item for item in pr.get("reviews") or [] if isinstance(item, dict)]
        maintainer_approved = any(
            str(review.get("state") or "").upper() == "APPROVED"
            and str(review.get("author_association") or "").upper()
            in {"OWNER", "MEMBER", "COLLABORATOR"}
            for review in reviews
        )
        current_blocking_review = _current_blocking_review(pr, reviews)
        author_association = str(
            pr.get("author_association") or pr.get("authorAssociation") or ""
        ).upper()
        maintainer_owned = author_association in {"OWNER", "MEMBER", "COLLABORATOR"}
        updated_at = str(pr.get("updated_at") or pr.get("updatedAt") or "")
        if exact and merged:
            relation = "STRONG_MERGED_COVERAGE"
        elif (
            exact
            and state == "OPEN"
            and (_active_exact_pr(updated_at, now=now) or maintainer_approved or maintainer_owned)
            and has_tests
            and not draft
            and not targeted_check_unproven
            and not current_blocking_review
        ):
            relation = "STRONG_EXACT_DUPLICATE"
        elif exact and state == "OPEN":
            relation = "WEAK_OR_PARTIAL_EXACT"
        elif exact:
            relation = "HISTORICAL_CLOSED_EXACT"
        elif reference_only:
            relation = "REFERENCE_ONLY"
        elif state == "OPEN" and overlap >= 0.45:
            relation = "SEMANTIC_OVERLAP"
        else:
            relation = "UNRELATED"
        relations.append(
            PullRelation(
                number=int(pr.get("number") or 0),
                url=str(pr.get("html_url") or pr.get("url") or ""),
                relation=relation,
                exact_link=exact,
                title_overlap=round(overlap, 4),
                has_tests=has_tests,
                checks_green=checks_green,
                maintainer_approved=maintainer_approved,
                maintainer_owned=maintainer_owned,
                targeted_check_unproven=targeted_check_unproven,
                current_blocking_review=current_blocking_review,
                draft=draft,
                state=state,
                merged=merged,
                updated_at=updated_at,
            )
        )
    return relations
