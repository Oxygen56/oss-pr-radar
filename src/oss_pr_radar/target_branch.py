"""Resolve the repository branch an issue is actually asking to change."""

from __future__ import annotations

import re
from typing import Any

from .github_client import GitHubClient, GitHubError

BRANCH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,119}")
COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}")

REPOSITORY_BRANCH_RULES: dict[str, dict[str, Any]] = {
    "anomalyco/opencode": {
        "labels": {"2.0": "v2"},
        "guardLabelPattern": r"^\d+(?:\.\d+)*$",
    }
}


class TargetBranchError(RuntimeError):
    pass


def _labels(issue: dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for item in issue.get("labels") or []:
        label = str(item.get("name") or "").strip() if isinstance(item, dict) else str(item).strip()
        if label:
            labels.add(label)
    return labels


def _configured_target(repo: str, issue: dict[str, Any]) -> tuple[str | None, list[str]]:
    rule = REPOSITORY_BRANCH_RULES.get(repo.casefold())
    if not rule:
        return None, []
    labels = _labels(issue)
    mapping = {str(label): str(branch) for label, branch in dict(rule.get("labels") or {}).items()}
    matches = sorted(label for label in labels if label in mapping)
    targets = {mapping[label] for label in matches}
    if len(targets) > 1:
        raise TargetBranchError("issue labels select conflicting target branches")
    if targets:
        return targets.pop(), matches

    guard = str(rule.get("guardLabelPattern") or "")
    guarded = sorted(label for label in labels if guard and re.fullmatch(guard, label))
    if guarded:
        raise TargetBranchError("version label has no configured target branch")
    return None, []


def validate_target_base(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise TargetBranchError("target base is missing")
    branch = str(value.get("branch") or "")
    sha = str(value.get("sha") or "").casefold()
    source = str(value.get("source") or "")
    default_branch = str(value.get("defaultBranch") or "")
    if not BRANCH_RE.fullmatch(branch) or not COMMIT_RE.fullmatch(sha):
        raise TargetBranchError("target base identity is invalid")
    if not source or not BRANCH_RE.fullmatch(default_branch):
        raise TargetBranchError("target base evidence is incomplete")
    result = {
        "branch": branch,
        "sha": sha,
        "source": source,
        "defaultBranch": default_branch,
    }
    label = str(value.get("label") or "")
    if label:
        result["label"] = label
    return result


def resolve_target_base(
    client: GitHubClient,
    repo: str,
    issue: dict[str, Any],
) -> dict[str, str]:
    try:
        metadata = client.repository(repo)
    except GitHubError as exc:
        raise TargetBranchError(f"repository metadata unavailable: {exc}") from exc
    default_branch = str(metadata.get("default_branch") or "")
    if not BRANCH_RE.fullmatch(default_branch):
        raise TargetBranchError("repository default branch is unavailable")

    configured, labels = _configured_target(repo, issue)
    branch = configured or default_branch
    try:
        branch_value = client.branch(repo, branch)
    except GitHubError as exc:
        raise TargetBranchError(f"target branch unavailable: {exc}") from exc
    sha = str((branch_value.get("commit") or {}).get("sha") or "").casefold()
    if not COMMIT_RE.fullmatch(sha):
        raise TargetBranchError("target branch commit is invalid")
    result = {
        "branch": branch,
        "sha": sha,
        "source": "repository_label_rule" if configured else "repository_default",
        "defaultBranch": default_branch,
    }
    if labels:
        result["label"] = labels[0]
    return validate_target_base(result)
