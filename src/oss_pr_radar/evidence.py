"""Complete, digestible issue evidence used by local authorization."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from .claims import detect_claims, detect_maintainer_approval
from .github_client import GitHubClient, GitHubError
from .relations import assess_relations
from .repo_policy import PolicySnapshot, discover_policy
from .util import sha256_json

HARDWARE_PATTERNS = {
    "h100": re.compile(r"\bH100\b", re.I),
    "h200": re.compile(r"\bH200\b", re.I),
    "b100": re.compile(r"\bB100\b", re.I),
    "b200": re.compile(r"\bB200\b", re.I),
    "b300": re.compile(r"\bB300\b", re.I),
    "gb10": re.compile(r"\bGB10\b", re.I),
    "gb200": re.compile(r"\bGB200\b", re.I),
    "gb300": re.compile(r"\bGB300\b", re.I),
    "sm121": re.compile(r"\bSM121\b", re.I),
    "dgx_spark": re.compile(r"\bDGX[ -]Spark\b", re.I),
    "multi_node": re.compile(r"\bmulti[- ]node\b|\bRDMA\b|\bInfiniBand\b", re.I),
    "rocm": re.compile(r"\bROCm\b|\bGFX9\d+\b|\bMI(?:250|300|325|350)X?\b", re.I),
    "xpu": re.compile(r"\bXPU\b", re.I),
    "gaudi": re.compile(r"\bGaudi\b|\bHabana\b", re.I),
    "tpu": re.compile(r"\bTPU\b", re.I),
    "ascend": re.compile(r"\bAscend\b|\bCANN\b", re.I),
    "apple_metal": re.compile(r"\bApple Metal\b|\bMPS\b", re.I),
}
DEFAULT_HARDWARE_INVENTORY = frozenset({"4090", "5090", "a100", "v100"})
HARDWARE_SCOPE_EXEMPTION_RE = re.compile(
    r"\bnot\s+(?:rocm|cuda|hardware|gpu|backend)[- ]specific\b|"
    r"\b(?:reproduced|observed)\s+(?:across|on)\s+(?:both|multiple)\s+"
    r"(?:backends?|platforms?|gpu vendors?)\b",
    re.I,
)
HARDWARE_REQUIREMENT_RE = re.compile(
    r"\b(?:requires?|required|must|minimum|at least|exclusively|specific(?:ally)? to|"
    r"only reproduc(?:e|es|ed|ible) on|reproduc(?:e|es|ed|ible) only on)\b",
    re.I,
)
HARDWARE_SENSITIVE_VALIDATION_RE = re.compile(
    r"\b(?:benchmark|throughput|latency|bandwidth|ttft|tokens?/s|ops?|iops|"
    r"gb/s|mb/s|performance|profil(?:e|ing)|nfsiostat|mountstats|"
    r"fragment(?:ed|ation)|kernel)\b",
    re.I,
)
HARDWARE_ENVIRONMENT_SECTION_RE = re.compile(
    r"(?ims)^#{1,6}\s*(?:environment|hardware|system(?: information| info)?|"
    r"reproduction environment)\s*$\n(.*?)(?=^#{1,6}\s|\Z)"
)


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
    default_branch: str = ""
    selected_base_sha: str = ""
    live_base_sha: str = ""
    repo_probe_receipt: dict[str, Any] | None = None
    probe_level: str = "UNVERIFIED"

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["defaultBranch"] = self.default_branch
        value["selectedBaseSha"] = self.selected_base_sha
        value["liveBaseSha"] = self.live_base_sha
        value["evidenceDigest"] = self.digest
        value["repoProbeReceipt"] = self.repo_probe_receipt
        value["probeLevel"] = self.probe_level
        return value


def assess_hardware_requirements(
    title: str,
    labels: str,
    body: str,
    inventory: set[str] | None = None,
) -> dict[str, Any]:
    """Distinguish required hardware from incidental environment mentions."""

    configured_inventory = DEFAULT_HARDWARE_INVENTORY if inventory is None else inventory
    available = {item.casefold() for item in configured_inventory}
    scoped = f"{title}\n{labels}"
    non_specific = bool(HARDWARE_SCOPE_EXEMPTION_RE.search(body[:5000]))
    environment = "\n".join(HARDWARE_ENVIRONMENT_SECTION_RE.findall(body[:12000]))
    hardware_sensitive = bool(HARDWARE_SENSITIVE_VALIDATION_RE.search(f"{title}\n{body[:8000]}"))
    mentioned: set[str] = set()
    required: set[str] = set()

    for name, pattern in HARDWARE_PATTERNS.items():
        if pattern.search(f"{scoped}\n{body}"):
            mentioned.add(name)
        if pattern.search(scoped) and not non_specific:
            required.add(name)
        for match in pattern.finditer(body[:12000]):
            context = body[max(0, match.start() - 90) : min(len(body), match.end() + 90)]
            if HARDWARE_REQUIREMENT_RE.search(context):
                required.add(name)
                break
        if hardware_sensitive and environment and pattern.search(environment) and not non_specific:
            required.add(name)

    required_list = sorted(required)
    unavailable = sorted(name for name in required_list if name not in available)
    return {
        "mentioned": sorted(mentioned),
        "required": required_list,
        "inventory": sorted(available),
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
    policy_snapshot: PolicySnapshot | None = None,
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
    policy = policy_snapshot or discover_policy(client, repo)
    completeness["repositoryPolicy"] = (
        "COMPLETE" if policy.status != "UNKNOWN" else f"ERROR:{policy.error or 'unknown'}"
    )
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
        pr_repo = str(raw.get("_repo") or repo)
        try:
            detail = client.pull_request(pr_repo, number)
            files = client.pull_files(pr_repo, number)
            reviews = client.pull_reviews(pr_repo, number)
            head = str((detail.get("head") or {}).get("sha") or "")
            checks = client.check_runs(pr_repo, head) if head else []
            enriched_prs.append(
                detail
                | {
                    "_repo": pr_repo,
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
    claim_signals = detect_claims(
        comments,
        current_actor=current_actor,
        issue=issue,
    )
    approvals = detect_maintainer_approval(comments)
    labels = ", ".join(
        str(item.get("name") or "") if isinstance(item, dict) else str(item)
        for item in issue.get("labels") or []
    )
    body = "\n".join(
        [str(issue.get("body") or "")] + [str(item.get("body") or "") for item in comments]
    )
    hardware = assess_hardware_requirements(
        str(issue.get("title") or ""),
        labels,
        body,
        hardware_inventory,
    )
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
