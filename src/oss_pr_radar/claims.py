"""Evidence-grounded ownership and maintainer-signal extraction."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Iterable

CLAIM_RE = re.compile(
    r"\b(?:"
    r"i(?:['’]?m| am|['’]?ll| will| would|['’]?d)?\s+"
    r"(?:definitely\s+)?(?:like to\s+)?(?:take|claim|work on|investigate|implement|"
    r"prepare|open|submit|send|try|fix|resolve|address|figure (?:this|it) out|"
    r"get (?:this|it) figured out)"
    r"|i can\s+(?:take|claim|work on|investigate|implement|prepare|open|submit|send|try)"
    r"|can (?:you )?assign (?:this|it) to me"
    r"|please assign (?:this|it) to me"
    r"|working on this|already working on this|have (?:a )?(?:patch(?:es)?|fix(?:es)?|prs?)"
    r"|(?:patch(?:es)?|fix(?:es)?|prs?) (?:is |are )?(?:ready|in progress)"
    r"|happy to contribute"
    r"|happy to (?:send|submit|open|prepare|write) "
    r"(?:a |the )?(?:small |focused )?(?:fix|patch|pr|pull request)"
    r"|plan(?:ning)? to (?:work|implement|submit|open)"
    r")\b",
    re.I,
)

CONDITIONAL_CLAIM_RE = re.compile(
    r"\b(?:"
    r"(?:has|have) (?:anyone|somebody) (?:started|taken|claimed|worked on) (?:this|it)"
    r"|is (?:anyone|somebody) (?:working on|taking|claiming) (?:this|it)"
    r"|if (?:no one|nobody|not(?: already)?|this (?:is|has) not) .{0,60}"
    r"(?:i can|i(?:['’]?ll| will| would|['’]?d)) .{0,30}(?:try|take|work|implement|fix)"
    r"|if (?:this|it) (?:is )?(?:still )?(?:available|unclaimed).{0,40}"
    r"(?:i can|i(?:['’]?ll| will| would|['’]?d))"
    r")\b",
    re.I | re.S,
)

CLAIM_RETRACTION_SIMPLE_RE = re.compile(
    r"(?:update:\s*)?(?:"
    r"standing down"
    r"|i(?:['’]?m| am) standing down"
    r"|i(?:['’]?m| am) withdrawing (?:my )?(?:claim|offer)"
    r"|i(?:['’]?m| am) (?:no longer|not) (?:working on|taking|claiming) (?:this|it)"
    r"|i (?:won['’]?t|will not) (?:work on|take|claim) (?:this|it)"
    r")[.!]?",
    re.I,
)

CLAIM_RETRACTION_HANDOFF_RE = re.compile(
    r"(?:update:\s*)?standing down\s*[—-]\s*"
    r"i see (?:pr|pull request)\s*#?\d+"
    r"(?:\s*\(\s*and\s*#?\d+\s*\))?\s+already address(?:es)? this\.\s*"
    r"i(?:['’]?ll| will) defer to (?:those|them)"
    r"[.!]?",
    re.I,
)

CLAIM_RETRACTION_UNCERTAIN_RE = re.compile(
    r"\b(?:for now|temporar(?:y|ily)|until|unless|yet|right now|alone|"
    r"maybe|might|may|perhaps|possibly|consider(?:ing|ed)?|if|whether)\b|\?",
    re.I,
)

MAINTAINER_APPROVAL_RE = re.compile(
    r"\b(?:assigned to you|go ahead|please (?:open|send|submit|work on)|"
    r"feel free to (?:open|send|submit|work on|take)|"
    r"(?:you|@[-\w]+) can (?:take|work on|implement|submit)|"
    r"contributions? welcome|help wanted)\b",
    re.I,
)

ASSIGNMENT_REQUIRED_RE = re.compile(
    r"\b(?:must|need(?:s)? to|required to)\b.{0,45}\b(?:assign(?:ed|ment)?|"
    r"maintainer approval|approval from (?:a )?maintainer)\b|"
    r"\b(?:do not|don['’]?t) (?:open|submit) (?:a )?(?:pr|pull request)\b",
    re.I | re.S,
)


@dataclass(frozen=True)
class ClaimSignal:
    author: str
    created_at: str
    kind: str
    excerpt: str
    association: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _author(comment: dict[str, Any]) -> str:
    raw = comment.get("author") or comment.get("user") or {}
    if isinstance(raw, dict):
        return str(raw.get("login") or raw.get("name") or "")
    return str(raw or "")


def _association(comment: dict[str, Any]) -> str:
    return str(
        comment.get("authorAssociation") or comment.get("author_association") or "NONE"
    ).upper()


def _created(comment: dict[str, Any]) -> str:
    return str(comment.get("createdAt") or comment.get("created_at") or "")


def _body(comment: dict[str, Any]) -> str:
    return str(comment.get("body") or "").strip()


def _created_timestamp(value: str) -> datetime | None:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return timestamp if timestamp.tzinfo is not None else None


def detect_claims(
    comments: Iterable[dict[str, Any]],
    *,
    current_actor: str | None = None,
    issue: dict[str, Any] | None = None,
) -> list[ClaimSignal]:
    actor = (current_actor or "").casefold()
    signals: list[ClaimSignal] = []
    retractions: dict[str, list[datetime]] = {}
    sources = list(comments)
    if issue:
        sources.insert(
            0,
            {
                "body": issue.get("body"),
                "user": issue.get("user") or issue.get("author"),
                "author_association": issue.get("author_association")
                or issue.get("authorAssociation"),
                "created_at": issue.get("created_at") or issue.get("createdAt"),
            },
        )
    for comment in sources:
        author = _author(comment)
        if not author or author.casefold() == actor or author.casefold().endswith("[bot]"):
            continue
        body = _body(comment)
        if not body:
            continue
        retraction_match = None
        if not CLAIM_RETRACTION_UNCERTAIN_RE.search(body):
            retraction_match = CLAIM_RETRACTION_SIMPLE_RE.fullmatch(
                body
            ) or CLAIM_RETRACTION_HANDOFF_RE.fullmatch(body)
        search_start = retraction_match.end() if retraction_match else 0
        kind = ""
        match = CONDITIONAL_CLAIM_RE.search(body, search_start)
        if match:
            kind = "conditional_claim"
        else:
            match = CLAIM_RE.search(body, search_start)
        if match and not kind:
            kind = "active_claim"
        if kind:
            excerpt_start = max(0, match.start() - 80)
            excerpt_end = min(len(body), match.end() + 120)
            signals.append(
                ClaimSignal(
                    author=author,
                    created_at=_created(comment),
                    kind=kind,
                    excerpt=" ".join(body[excerpt_start:excerpt_end].split())[:240],
                    association=_association(comment),
                )
            )
            continue
        if retraction_match:
            created = _created_timestamp(_created(comment))
            if created is not None:
                retractions.setdefault(author.casefold(), []).append(created)
    active: list[ClaimSignal] = []
    for signal in signals:
        created = _created_timestamp(signal.created_at)
        if created is None or not any(
            retracted_at > created for retracted_at in retractions.get(signal.author.casefold(), [])
        ):
            active.append(signal)
    return active


def detect_maintainer_approval(comments: Iterable[dict[str, Any]]) -> list[ClaimSignal]:
    signals: list[ClaimSignal] = []
    for comment in comments:
        association = _association(comment)
        if association not in {"OWNER", "MEMBER", "COLLABORATOR"}:
            continue
        body = _body(comment)
        if MAINTAINER_APPROVAL_RE.search(body):
            signals.append(
                ClaimSignal(
                    author=_author(comment),
                    created_at=_created(comment),
                    kind="maintainer_approval",
                    excerpt=" ".join(body.split())[:240],
                    association=association,
                )
            )
    return signals
