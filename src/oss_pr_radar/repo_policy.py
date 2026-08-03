"""Repository policy discovery with source hashes and conservative outcomes."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any

from .github_client import GitHubClient, GitHubError
from .util import sha256_json, sha256_text

POLICY_NAMES = {
    "contributing.md",
    "contributing.rst",
    "pull_request_template.md",
    "code_of_conduct.md",
    "security.md",
    "agents.md",
    "cla.md",
    "dco.md",
    "ai_usage_policy.md",
    "ai-usage-policy.md",
    "ai_policy.md",
    "ai-policy.md",
    "ai_disclosure.md",
}
POLICY_PARTS = {
    ".github/pull_request_template/",
    ".github/issue_template/",
    "docs/contributing",
}
AI_DISCLOSURE_RE = re.compile(
    r"(?:generative ai|ai[- ]generated|ai[- ]assisted|ai tools?|"
    r"large language models?|llms?|coding assistants?).{0,160}"
    r"(?:must|required|mandatory|always).{0,100}(?:disclos|declare|identify|"
    r"attribute|label|tag|mention)|"
    r"(?:must|required|mandatory|always).{0,100}(?:disclos|declare|identify|"
    r"attribute|label|tag|mention).{0,160}(?:generative ai|ai[- ]generated|"
    r"ai[- ]assisted|ai tools?|large language models?|llms?|coding assistants?)|"
    r"\bai (?:tool )?used\b|\bai disclosure\b|"
    r"disclos(?:e|ure).{0,60}(?:significant )?ai assistance",
    re.I | re.S,
)
AI_PROHIBITION_RE = re.compile(
    r"(?:do not|don['’]?t|must not)\s+(?:use|rely on)\s+(?:any\s+)?"
    r"(?:generative ai|ai tools?|large language models?|llms?|coding assistants?)|"
    r"(?:do not|don['’]?t|must not)\s+(?:submit|include)\s+(?:any\s+)?"
    r"(?:ai[- ]generated|ai[- ]assisted|llm[- ]generated)\s+"
    r"(?:code|contributions?|pull requests?|prs?)|"
    r"(?:ai[- ]generated|ai[- ]assisted|llm[- ]generated)\s+"
    r"(?:code|contributions?|pull requests?|prs?).{0,60}"
    r"(?:prohibited|not allowed|not accepted)",
    re.I | re.S,
)
ASSIGNMENT_RE = re.compile(
    r"\b(?:must|need(?:s)? to|required to)\b.{0,60}\b(?:assign(?:ed|ment)?|"
    r"maintainer approval|approved by (?:a )?maintainer)\b|"
    r"\b(?:wait for|obtain)\b.{0,35}\b(?:assignment|approval)\b",
    re.I | re.S,
)
NO_UNSOLICITED_RE = re.compile(
    r"\b(?:do not|don['’]?t|must not|no longer|not currently)\b.{0,70}"
    r"\b(?:unsolicited|external)\b.{0,35}\b(?:pull requests?|prs?|contributions?)\b|"
    r"\b(?:unsolicited|external)\b.{0,35}\b(?:pull requests?|prs?|contributions?)\b"
    r".{0,70}\b(?:will be closed|not accepted|are closed)\b|"
    r"\b(?:not accepting|do not accept|will not accept)\b.{0,60}"
    r"\b(?:external )?(?:code contributions?|pull requests?|prs?)\b",
    re.I | re.S,
)
CLA_RE = re.compile(r"\bcontributor license agreement\b|\bCLA\b", re.I)
DCO_RE = re.compile(r"\bdeveloper certificate of origin\b|\bDCO\b|signed-off-by", re.I)


@dataclass(frozen=True)
class PolicyFile:
    path: str
    sha: str
    text_digest: str


@dataclass(frozen=True)
class PolicySnapshot:
    status: str
    digest: str
    files: tuple[PolicyFile, ...]
    ai_disclosure: bool
    ai_prohibited: bool
    assignment_required: bool
    unsolicited_pr_blocked: bool
    cla: bool
    dco: bool
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["files"] = [asdict(item) for item in self.files]
        return value


def _is_policy_path(path: str) -> bool:
    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    return (
        name in POLICY_NAMES
        or any(part in lowered for part in POLICY_PARTS)
        or ("contribut" in lowered and lowered.endswith((".md", ".rst")))
        or ("pull_request_template" in lowered and lowered.endswith(".md"))
    )


def discover_policy(client: GitHubClient, repo: str) -> PolicySnapshot:
    try:
        metadata = client.repository(repo)
        ref = str(metadata.get("default_branch") or "HEAD")
        tree = client.repository_tree(repo, ref)
        entries = sorted(
            (
                item
                for item in tree
                if item.get("type") == "blob"
                and isinstance(item.get("path"), str)
                and _is_policy_path(item["path"])
            ),
            key=lambda item: (len(str(item["path"])), str(item["path"])),
        )[:24]
        files: list[PolicyFile] = []
        texts: list[str] = []
        for entry in entries:
            path = str(entry["path"])
            text = client.file_text(repo, path, ref)[:250_000]
            texts.append(text)
            files.append(
                PolicyFile(
                    path=path,
                    sha=str(entry.get("sha") or ""),
                    text_digest=sha256_text(text),
                )
            )
        combined = "\n\n".join(texts)
        ai = bool(AI_DISCLOSURE_RE.search(combined))
        ai_prohibited = bool(AI_PROHIBITION_RE.search(combined))
        assignment = bool(ASSIGNMENT_RE.search(combined))
        blocked = bool(NO_UNSOLICITED_RE.search(combined))
        status = (
            "CONTRIBUTIONS_CLOSED"
            if blocked
            else "AI_POLICY_REVIEW"
            if ai or ai_prohibited
            else "NORMAL"
        )
        digest = sha256_json(
            {
                "repo": repo,
                "ref": ref,
                "files": [asdict(item) for item in files],
                "flags": [
                    ai,
                    ai_prohibited,
                    assignment,
                    blocked,
                    bool(CLA_RE.search(combined)),
                    bool(DCO_RE.search(combined)),
                ],
            }
        )
        return PolicySnapshot(
            status=status,
            digest=digest,
            files=tuple(files),
            ai_disclosure=ai,
            ai_prohibited=ai_prohibited,
            assignment_required=assignment,
            unsolicited_pr_blocked=blocked,
            cla=bool(CLA_RE.search(combined)),
            dco=bool(DCO_RE.search(combined)),
        )
    except GitHubError as exc:
        return PolicySnapshot(
            status="UNKNOWN",
            digest="",
            files=(),
            ai_disclosure=False,
            ai_prohibited=False,
            assignment_required=False,
            unsolicited_pr_blocked=False,
            cla=False,
            dco=False,
            error=str(exc)[:300],
        )
