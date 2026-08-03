"""Evidence-grounded ownership and maintainer-signal extraction."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

CLAIM_RE = re.compile(
    r"\b(?:"
    r"i(?:['’]?m| am|['’]?ll| will| would|['’]?d)?\s+"
    r"(?:like to\s+)?(?:take|claim|work on|investigate|implement|prepare|open|submit|send|try)"
    r"|i can\s+(?:take|claim|work on|investigate|implement|prepare|open|submit|send|try)"
    r"|can (?:you )?assign (?:this|it) to me"
    r"|please assign (?:this|it) to me"
    r"|working on this|already working on this|have (?:a )?(?:patch|fix|pr)"
    r"|(?:patch|fix|pr) (?:is )?(?:ready|in progress)"
    r"|happy to contribute|plan(?:ning)? to (?:work|implement|submit|open)"
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


def detect_claims(
    comments: Iterable[dict[str, Any]], *, current_actor: str | None = None
) -> list[ClaimSignal]:
    actor = (current_actor or "").casefold()
    signals: list[ClaimSignal] = []
    for comment in comments:
        author = _author(comment)
        if not author or author.casefold() == actor or author.casefold().endswith("[bot]"):
            continue
        body = _body(comment)
        if not body:
            continue
        kind = ""
        if CONDITIONAL_CLAIM_RE.search(body):
            kind = "conditional_claim"
        elif CLAIM_RE.search(body):
            kind = "active_claim"
        if kind:
            signals.append(
                ClaimSignal(
                    author=author,
                    created_at=_created(comment),
                    kind=kind,
                    excerpt=" ".join(body.split())[:240],
                    association=_association(comment),
                )
            )
    return signals


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
