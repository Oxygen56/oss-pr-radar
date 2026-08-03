"""Complete, digestible issue evidence used by local authorization."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from .claims import detect_claims, detect_maintainer_approval
from .github_client import GitHubClient, GitHubError
from .relations import assess_relations
from .repo_policy import discover_policy
from .util import sha256_json

HARDWARE_PATTERNS = {
    "h100": re.compile(r"\bH100\b", re.I),
    "h200": re.compile(r"\bH200\b", re.I),
    "b100": re.compile(r"\bB100\b", re.I),
    "b200": re.compile(r"\bB200\b", re.I),
    "b300": re.compile(r"\bB300\b", re.I),
    "multi_node": re.compile(r"\bmulti[- ]node\b|\bRDMA\b|\bInfiniBand\b", re.I),
    "rocm": re.compile(r"\bROCm\b|\bMI(?:250|300|325)\b", re.I),
}


@dataclass(frozen=True)
class EvidenceBundle:
    repo: str
    issue_number: int
    complete: bool
    completeness: dict[str, str]
    issue: dict[str, Any]
    comments: tuple[dict[str, Any], ...]
    timeline: tuple[dict[str, Any], ...]
    claims: tuple[dict[str, Any], ...]
    maintainer_approvals: tuple[dict[str, Any], ...]
    policy: dict[str, Any]
    pull_relations: tuple[dict[str, Any], ...]
    hardware: dict[str, Any]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _hardware(text: str, inventory: set[str]) -> dict[str, Any]:
    required = sorted(name for name, pattern in HARDWARE_PATTERNS.items() if pattern.search(text))
    unavailable = sorted(name for name in required if name not in inventory)
    return {
        "required": required,
        "inventory": sorted(inventory),
        "compatible": not unavailable,
        "unavailable": unavailable,
    }


def collect_evidence(
    client: GitHubClient,
    repo: str,
    issue_number: int,
    *,
    current_actor: str = "Oxygen56",
    hardware_inventory: set[str] | None = None,
) -> EvidenceBundle:
    completeness: dict[str, str] = {}

    def load(name: str, callback: Any, default: Any) -> Any:
        try:
            value = callback()
            completeness[name] = "COMPLETE"
            return value
        except GitHubError as exc:
            completeness[name] = f"ERROR:{str(exc)[:180]}"
            return default

    issue = load("issue", lambda: client.issue(repo, issue_number), {})
    comments = load("comments", lambda: client.comments(repo, issue_number), [])
    timeline = load("timeline", lambda: client.timeline(repo, issue_number), [])
    policy = discover_policy(client, repo)
    completeness["repositoryPolicy"] = "COMPLETE" if policy.status != "UNKNOWN" else f"ERROR:{policy.error or 'unknown'}"
    raw_prs = load(
        "relatedPullRequests",
        lambda: client.related_open_prs(
            repo,
            issue_number,
            issue_title=str(issue.get("title") or ""),
            timeline=timeline,
        ),
        [],
    )
    enriched_prs: list[dict[str, Any]] = []
    for raw in raw_prs:
        number = int(raw.get("number") or 0)
        try:
            detail = client.pull_request(repo, number)
            files = client.pull_files(repo, number)
            reviews = client.pull_reviews(repo, number)
            head = str((detail.get("head") or {}).get("sha") or "")
            checks = client.check_runs(repo, head) if head else []
            enriched_prs.append(
                detail
                | {
                    "files": files,
                    "checks": checks,
                    "reviews": reviews,
                    "_linked_from_timeline": raw.get("_linked_from_timeline") is True,
                }
            )
        except GitHubError:
            enriched_prs.append(raw)
            completeness["relatedPullRequests"] = "PARTIAL"
    relations = assess_relations(
        repo=repo,
        issue_number=issue_number,
        issue_title=str(issue.get("title") or ""),
        pull_requests=enriched_prs,
    )
    claim_signals = detect_claims(comments, current_actor=current_actor)
    approvals = detect_maintainer_approval(comments)
    text = "\n".join(
        [str(issue.get("title") or ""), str(issue.get("body") or "")]
        + [str(item.get("body") or "") for item in comments]
    )
    hardware = _hardware(text, hardware_inventory or {"4090", "5090", "a100", "v100"})
    payload = {
        "repo": repo,
        "issueNumber": issue_number,
        "completeness": completeness,
        "issue": issue,
        "comments": comments,
        "timeline": timeline,
        "claims": [item.as_dict() for item in claim_signals],
        "maintainerApprovals": [item.as_dict() for item in approvals],
        "policy": policy.as_dict(),
        "pullRelations": [item.as_dict() for item in relations],
        "hardware": hardware,
    }
    return EvidenceBundle(
        repo=repo,
        issue_number=issue_number,
        complete=all(value == "COMPLETE" for value in completeness.values()),
        completeness=completeness,
        issue=issue,
        comments=tuple(comments),
        timeline=tuple(timeline),
        claims=tuple(item.as_dict() for item in claim_signals),
        maintainer_approvals=tuple(item.as_dict() for item in approvals),
        policy=policy.as_dict(),
        pull_relations=tuple(item.as_dict() for item in relations),
        hardware=hardware,
        digest=sha256_json(payload),
    )
