"""Repository policy discovery with source hashes and conservative outcomes."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any

from .github_client import GitHubClient, GitHubError
from .util import sha256_json, sha256_text

POLICY_NAMES = {
    "contributing.md",
    "contributing.rst",
    "contributors.md",
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
    "docs/contributing",
}
POLICY_FILE_WORKERS = 6
AI_DISCLOSURE_RE = re.compile(
    r"(?:generative ai|ai[- ]generated|ai[- ]assisted|ai tools?|"
    r"large language models?|llms?|coding assistants?).{0,160}"
    r"(?:must|required|mandatory|always).{0,100}(?:disclos|declare|identify|"
    r"attribute|mention)|"
    r"(?:must|required|mandatory|always).{0,100}(?:disclos|declare|identify|"
    r"attribute|mention).{0,160}(?:generative ai|ai[- ]generated|"
    r"ai[- ]assisted|ai tools?|large language models?|llms?|coding assistants?)|"
    r"(?:generative ai|ai[- ]generated|ai[- ]assisted|ai tools?|"
    r"large language models?|llms?|coding assistants?).{0,180}"
    r"(?:labels?|tags?).{0,60}(?:required|mandatory|must)|"
    r"(?:required|mandatory|must).{0,60}(?:labels?|tags?).{0,180}"
    r"(?:generative ai|ai[- ]generated|ai[- ]assisted|ai tools?|"
    r"large language models?|llms?|coding assistants?)|"
    r"\bai (?:tool )?used\b|\bai disclosure\b|"
    r"disclos(?:e|ure).{0,60}(?:significant )?ai assistance|"
    r"(?:pull requests?|prs?).{0,100}(?:created|generated)\s+by\s+(?:an?\s+)?"
    r"(?:automated|coding|ai)\s+agents?.{0,160}"
    r"(?:add|include|specify|state).{0,80}(?:tool name|from\s+<tool name>)|"
    r"(?:new\s+)?branches?\s+(?:should|must|are required to)\s+use\s+"
    r"(?:the\s+)?[`'\"]?codex/",
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
    r"(?:issue|pull request|pr).{0,180}(?:must|required).{0,120}assign|"
    r"\bwait for assignment\b|"
    r"\bmaintainer\b.{0,80}\bassign\b.{0,100}\bbefore\b.{0,80}"
    r"\b(?:open(?:ing)?|submit(?:ting)?|start(?:ing)?|implement(?:ing)?)\b|"
    r"(?:not assigned|without assignment).{0,180}"
    r"(?:closed automatically|auto(?:matically)?[- ]closed)|"
    r"pull requests?.{0,120}"
    r"(?:invitation only|only (?:from|for) invited|invited contributors?)|"
    r"(?:request|grant).{0,80}contributor access|"
    r"(?:do not|don['’]?t|must not).{0,80}(?:open|submit).{0,40}"
    r"(?:pull request|pr).{0,120}(?:unless|until).{0,80}"
    r"(?:approved|approval|lgtm)|"
    r"(?:only after|must (?:first )?(?:obtain|receive|have)).{0,60}"
    r"(?:lgtm|maintainer approval).{0,100}"
    r"(?:open|submit|start|implement|contribut)|"
    r"\bbefore\b.{0,80}\b(?:open(?:ing)?|submit(?:ting)?|start(?:ing)?|"
    r"implement(?:ing)?)\b.{0,100}\b(?:assignment|maintainer approval|lgtm)\b|"
    r"\b(?:assignment|maintainer approval|lgtm)\b.{0,100}\bbefore\b.{0,80}"
    r"\b(?:open(?:ing)?|submit(?:ting)?|start(?:ing)?|implement(?:ing)?)\b|"
    r"\bfor\s+(?:all\s+)?other\s+issues\b.{0,100}\b(?:please\s+)?"
    r"(?:kindly\s+)?ask\b.{0,60}\bbefore\s+contribut|"
    r"\b(?:ask|check|confirm)\s+(?:with\s+)?(?:the\s+)?maintainers?\b"
    r".{0,80}\bbefore\s+(?:contribut|implement|start)",
    re.I | re.S,
)
NO_UNSOLICITED_RE = re.compile(
    r"\b(?:do not|don['’]?t|must not|no longer|not currently)\b.{0,70}"
    r"\b(?:unsolicited|external)\b.{0,35}\b(?:pull requests?|prs?|contributions?)\b|"
    r"\b(?:unsolicited|external)\b.{0,35}\b(?:pull requests?|prs?|contributions?)\b"
    r".{0,70}\b(?:will be closed|not accepted|are closed)\b|"
    r"\b(?:not accepting|do not accept|will not accept)\b.{0,60}"
    r"\b(?:external )?(?:code contributions?|pull requests?|prs?)\b|"
    r"(?:not|no longer|currently not|not currently)\s+(?:accepting|taking)\s+"
    r"(?:external\s+)?(?:code\s+)?contributions?|"
    r"(?:code\s+)?contributions?\s+(?:are|is)\s+(?:currently\s+)?(?:closed|paused)|"
    r"(?:do not|don['’]?t|won['’]?t|will not)\s+accept\s+"
    r"(?:external\s+)?(?:code\s+)?(?:contributions?|pull requests?|prs?)|"
    r"(?:pull requests?|prs?)\s+(?:from external contributors\s+)?"
    r"(?:are\s+)?not\s+(?:currently\s+)?accepted",
    re.I | re.S,
)
ISSUES_ONLY_RE = re.compile(
    r"\b(?:we\s+)?accept\s+(?:bug reports?|feature requests?|issues?|prompts?)\s*,?\s*"
    r"(?:but\s+)?not\s+(?:external\s+)?(?:pull requests?|prs?|source code|diffs?|patches?)\b|"
    r"\b(?:please\s+)?(?:do not|don['’]?t)\s+open\s+(?:an?\s+)?"
    r"(?:pull request|pr)\b|"
    r"\b(?:please\s+)?(?:do not|don['’]?t)\s+send\s+(?:an?\s+)?diff\s+or\s+"
    r"open\s+(?:an?\s+)?(?:pull request|pr)\b|"
    r"\bshare\s+(?:the\s+)?(?:prompt|intent)\b.{0,100}\bnot\s+"
    r"(?:the\s+)?(?:source code|diff|patch)\b",
    re.I | re.S,
)
CLA_RE = re.compile(r"\bcontributor license agreement\b|\bCLA\b", re.I)
DCO_RE = re.compile(r"\bdeveloper certificate of origin\b|\bDCO\b|signed-off-by", re.I)
NONSTANDARD_AGREEMENT_RE = re.compile(
    r"(?:by\s+(?:submitting|opening)|when\s+you\s+(?:submit|open)|"
    r"contribution agreement).{0,240}"
    r"(?:perpetual|irrevocable).{0,180}(?:transferable|sublicen[sc]able|re-?license)"
    r".{0,220}(?:commercial|proprietary|any terms)|"
    r"grant.{0,120}(?:maintainers?|project).{0,180}"
    r"(?:perpetual|irrevocable).{0,180}(?:transferable|sublicen[sc]able|re-?license)"
    r".{0,220}(?:commercial|proprietary|any terms)",
    re.I | re.S,
)


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
    nonstandard_agreement: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["files"] = [asdict(item) for item in self.files]
        return value


@dataclass(frozen=True)
class PolicyTextClassification:
    ai_disclosure: bool
    ai_prohibited: bool
    assignment_required: bool
    unsolicited_pr_blocked: bool
    cla: bool
    dco: bool
    nonstandard_agreement: bool


def is_policy_path(path: str) -> bool:
    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    return (
        name in POLICY_NAMES
        or any(part in lowered for part in POLICY_PARTS)
        or ("contribut" in lowered and lowered.endswith((".md", ".rst")))
        or ("pull_request_template" in lowered and lowered.endswith(".md"))
    )


def select_policy_entries(tree: list[dict[str, Any]], limit: int = 24) -> list[dict[str, Any]]:
    def priority(item: dict[str, Any]) -> tuple[int, int, str]:
        path = str(item["path"]).casefold()
        name = PurePosixPath(path).name
        if "pull_request_template" in path or name.startswith("ai_") or name.startswith("ai-"):
            rank = 0
        elif "/" not in path and name in {
            "contributing.md",
            "contributing.rst",
            "contributors.md",
            "cla.md",
            "dco.md",
            "license",
            "license.md",
        }:
            rank = 1
        elif name in {"cla.md", "dco.md", "ai_disclosure.md"}:
            rank = 2
        elif name == "agents.md" and "/" not in path:
            rank = 3
        elif name == "agents.md":
            rank = 5
        elif path.startswith("docs/"):
            rank = 6
        else:
            rank = 4
        return rank, len(path), path

    return sorted(
        (
            item
            for item in tree
            if item.get("type") == "blob"
            and isinstance(item.get("path"), str)
            and is_policy_path(item["path"])
        ),
        key=priority,
    )[:limit]


def classify_policy_text(text: str) -> PolicyTextClassification:
    return PolicyTextClassification(
        ai_disclosure=bool(AI_DISCLOSURE_RE.search(text)),
        ai_prohibited=bool(AI_PROHIBITION_RE.search(text)),
        assignment_required=bool(ASSIGNMENT_RE.search(text)),
        unsolicited_pr_blocked=bool(NO_UNSOLICITED_RE.search(text) or ISSUES_ONLY_RE.search(text)),
        cla=bool(CLA_RE.search(text)),
        dco=bool(DCO_RE.search(text)),
        nonstandard_agreement=bool(NONSTANDARD_AGREEMENT_RE.search(text)),
    )


def submission_policy_from_text(text: str, static_rule: str = "normal") -> str:
    flags = classify_policy_text(text)
    has_ai_policy = static_rule == "ai_disclosure_conflict" or (
        flags.ai_disclosure or flags.ai_prohibited
    )
    needs_assignment = static_rule == "needs_assignment" or flags.assignment_required
    contributions_closed = static_rule == "contributions_closed" or flags.unsolicited_pr_blocked
    nonstandard_agreement = (
        static_rule == "nonstandard_contribution_agreement" or flags.nonstandard_agreement
    )
    if contributions_closed:
        return "contributions_closed"
    if nonstandard_agreement:
        return "nonstandard_contribution_agreement"
    if has_ai_policy and needs_assignment:
        return "ai_disclosure_and_assignment"
    if has_ai_policy:
        return "ai_disclosure_conflict"
    if needs_assignment:
        return "needs_assignment"
    if flags.cla or flags.dco:
        return "legal_confirmation"
    return "normal"


def discover_policy(client: GitHubClient, repo: str) -> PolicySnapshot:
    try:
        metadata = client.repository(repo)
        ref = str(metadata.get("default_branch") or "HEAD")
        tree = client.repository_tree(repo, ref)
        entries = select_policy_entries(tree)

        def load_entry(entry: dict[str, Any]) -> tuple[PolicyFile, str]:
            path = str(entry["path"])
            text = client.file_text(repo, path, ref)[:250_000]
            return (
                PolicyFile(path, str(entry.get("sha") or ""), sha256_text(text)),
                text,
            )

        loaded: list[tuple[PolicyFile, str]] = []
        if entries:
            with ThreadPoolExecutor(max_workers=min(POLICY_FILE_WORKERS, len(entries))) as executor:
                loaded = list(executor.map(load_entry, entries))
        files = [item[0] for item in loaded]
        texts = [item[1] for item in loaded]
        combined = "\n\n".join(texts)
        flags = classify_policy_text(combined)
        status = (
            "CONTRIBUTIONS_CLOSED"
            if flags.unsolicited_pr_blocked
            else "LEGAL_POLICY_REVIEW"
            if flags.nonstandard_agreement
            else "AI_POLICY_REVIEW"
            if flags.ai_disclosure or flags.ai_prohibited
            else "NORMAL"
        )
        digest = sha256_json(
            {
                "repo": repo,
                "ref": ref,
                "files": [asdict(item) for item in files],
                "flags": [
                    flags.ai_disclosure,
                    flags.ai_prohibited,
                    flags.assignment_required,
                    flags.unsolicited_pr_blocked,
                    flags.cla,
                    flags.dco,
                    flags.nonstandard_agreement,
                ],
            }
        )
        return PolicySnapshot(
            status=status,
            digest=digest,
            files=tuple(files),
            ai_disclosure=flags.ai_disclosure,
            ai_prohibited=flags.ai_prohibited,
            assignment_required=flags.assignment_required,
            unsolicited_pr_blocked=flags.unsolicited_pr_blocked,
            cla=flags.cla,
            dco=flags.dco,
            nonstandard_agreement=flags.nonstandard_agreement,
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
            nonstandard_agreement=False,
            error=str(exc)[:300],
        )
