"""Deterministic authorization; semantic models have no positive vote."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from .evidence import EvidenceBundle

SECURITY_RE = re.compile(
    r"\b(?:security vulnerabilit(?:y|ies)|vulnerability disclosure|cve[- :#]?\d*|"
    r"remote code execution|arbitrary code execution|privilege escalation|"
    r"supply chain (?:attack|risk|vulnerability)|credential exfiltration|"
    r"sandbox escape|authentication bypass|command injection|"
    r"indirect prompt injection|unauthorized (?:code )?execution)\b",
    re.I,
)
DESIGN_RE = re.compile(
    r"\b(?:RFC|design proposal|architecture proposal|breaking API|roadmap)\b", re.I
)


@dataclass(frozen=True)
class AuthorizationDecision:
    status: str
    reason_code: str
    checks: dict[str, str]
    evidence_digest: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def authorize(candidate: dict[str, Any], evidence: EvidenceBundle) -> AuthorizationDecision:
    checks = {
        "issueState": "PASS",
        "ownership": "PASS",
        "duplicate": "PASS",
        "design": "PASS",
        "policy": "PASS",
        "hardware": "PASS",
        "evidence": "PASS",
    }

    def decision(status: str, reason: str, check: str | None = None) -> AuthorizationDecision:
        if check:
            checks[check] = status
        return AuthorizationDecision(status, reason, checks, evidence.digest)

    if not evidence.complete:
        checks["evidence"] = "HOLD"
        return decision("HOLD", "EVIDENCE_INCOMPLETE")
    issue = evidence.issue
    if str(issue.get("state") or "").lower() != "open":
        return decision("BLOCK", "ISSUE_NOT_OPEN", "issueState")
    assignees = issue.get("assignees") or []
    if assignees:
        return decision("BLOCK", "ISSUE_ASSIGNED", "ownership")
    if evidence.claims:
        return decision("BLOCK", "ACTIVE_OR_CONDITIONAL_CLAIM", "ownership")
    text = f"{issue.get('title') or ''}\n{issue.get('body') or ''}"
    if SECURITY_RE.search(text):
        return decision("BLOCK", "SECURITY_SENSITIVE")
    policy = evidence.policy
    if policy.get("status") == "CONTRIBUTIONS_CLOSED":
        return decision("BLOCK", "UNSOLICITED_PRS_BLOCKED", "policy")
    if policy.get("nonstandard_agreement"):
        return decision("BLOCK", "NONSTANDARD_CONTRIBUTION_AGREEMENT", "policy")
    if policy.get("ai_prohibited"):
        return decision("BLOCK", "AI_USE_PROHIBITED", "policy")
    if policy.get("ai_disclosure"):
        return decision("HOLD", "AI_DISCLOSURE_REQUIRES_USER", "policy")
    if policy.get("status") == "UNKNOWN":
        return decision("HOLD", "POLICY_UNKNOWN", "policy")
    if policy.get("assignment_required") and not evidence.maintainer_approvals:
        return decision("HOLD", "MAINTAINER_APPROVAL_REQUIRED", "policy")
    relations = {item.get("relation") for item in evidence.pull_relations}
    if relations & {"STRONG_EXACT_DUPLICATE", "STRONG_MERGED_COVERAGE"}:
        return decision("BLOCK", "STRONG_EXISTING_PR", "duplicate")
    if (
        "WEAK_OR_PARTIAL_EXACT" in relations
        and candidate.get("category") != "PR_COMPETITION_OPPORTUNITY"
    ):
        return decision("HOLD", "EXISTING_PR_REQUIRES_COMPETITION_REVIEW", "duplicate")
    if (
        "SEMANTIC_OVERLAP" in relations
        and candidate.get("category") != "PR_COMPETITION_OPPORTUNITY"
    ):
        return decision("HOLD", "SEMANTIC_PR_OVERLAP_REQUIRES_REVIEW", "duplicate")
    if not evidence.hardware.get("compatible"):
        return decision("HOLD", "HARDWARE_UNAVAILABLE", "hardware")
    if candidate.get("track") == "llm_algorithm":
        algorithm = candidate.get("algorithm_evidence")
        if not isinstance(algorithm, dict):
            return decision("BLOCK", "ALGORITHM_EVIDENCE_MISSING", "evidence")
        if (
            algorithm.get("qualified") is not True
            or algorithm.get("operational_only") is not False
            or int(algorithm.get("score") or 0) < 7
            or int(algorithm.get("mechanism_count") or 0) < 1
        ):
            return decision("BLOCK", "ALGORITHM_EVIDENCE_WEAK", "evidence")
    if DESIGN_RE.search(text) and not evidence.maintainer_approvals:
        return decision("HOLD", "DESIGN_APPROVAL_REQUIRED", "design")
    review = candidate.get("llm_review") or {}
    if candidate.get("gate_decision") != "ALLOW_TO_WORK" or candidate.get("auto_spawn") is not True:
        return decision("HOLD", "SCAN_GATE_NOT_AUTHORIZED")
    if review.get("status") != "ok" or review.get("decision") not in {
        "NEW_CLEAN_CANDIDATE",
        "PR_COMPETITION_OPPORTUNITY",
    }:
        return decision("HOLD", "SEMANTIC_REVIEW_NOT_ACTIONABLE")
    if float(review.get("confidence") or 0.0) < 0.65:
        return decision("HOLD", "SEMANTIC_CONFIDENCE_LOW")
    return decision("ALLOW", "LIVE_EVIDENCE_PASSED")
