"""Classify whether open pull requests already cover an issue."""

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


def assess_relations(
    *,
    repo: str,
    issue_number: int,
    issue_title: str,
    pull_requests: Iterable[dict[str, Any]],
) -> list[PullRelation]:
    relations: list[PullRelation] = []
    now = datetime.now(UTC)
    exact_patterns = (
        re.compile(
            rf"\b(?:fixe[sd]?|close[sd]?|resolve[sd]?|address(?:e[sd])?|refs?|references?)"
            rf"\s*:?[ ]*#{issue_number}\b",
            re.I,
        ),
        re.compile(rf"https://github\.com/{re.escape(repo)}/issues/{issue_number}\b", re.I),
    )
    for pr in pull_requests:
        body = str(pr.get("body") or "")
        title = str(pr.get("title") or "")
        exact = bool(pr.get("_linked_from_timeline")) or any(
            pattern.search(body) for pattern in exact_patterns
        )
        overlap = _overlap(issue_title, title)
        files = pr.get("files") or []
        has_tests = any(
            re.search(
                r"(?:^|/)(?:test|tests|spec)(?:/|_|\.)", str(item.get("filename") or ""), re.I
            )
            for item in files
            if isinstance(item, dict)
        )
        checks = pr.get("checks")
        checks_green: bool | None = None
        if isinstance(checks, list) and checks:
            conclusions = {
                str(item.get("conclusion") or "").lower()
                for item in checks
                if isinstance(item, dict)
            }
            checks_green = bool(conclusions) and conclusions <= {"success", "neutral", "skipped"}
        draft = bool(pr.get("draft") or pr.get("isDraft"))
        state = str(pr.get("state") or "open").upper()
        merged = bool(pr.get("merged_at") or pr.get("mergedAt"))
        maintainer_approved = any(
            str(review.get("state") or "").upper() == "APPROVED"
            and str(review.get("author_association") or "").upper()
            in {"OWNER", "MEMBER", "COLLABORATOR"}
            for review in pr.get("reviews") or []
            if isinstance(review, dict)
        )
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
        ):
            relation = "STRONG_EXACT_DUPLICATE"
        elif exact and state == "OPEN":
            relation = "WEAK_OR_PARTIAL_EXACT"
        elif exact:
            relation = "HISTORICAL_CLOSED_EXACT"
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
                draft=draft,
                state=state,
                merged=merged,
                updated_at=updated_at,
            )
        )
    return relations
