"""Versioned, outcome-blind maintainer-acceptance policy for radar snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_VERSION = "submit_ready_quality_v1"
SCANNER_DECISION_REVISION = "oss_pr_radar_v29_pre_dispatch_hardening"
DISPATCH_DECISION_REVISION = "signed_intent_v8_durable_creation"
DECISION_CONTRACT_SCHEMA = 5
DECISION_CONTRACT_MANIFEST = {
    "schema": DECISION_CONTRACT_SCHEMA,
    "policyVersion": POLICY_VERSION,
    "scannerDecisionRevision": SCANNER_DECISION_REVISION,
    "dispatchDecisionRevision": DISPATCH_DECISION_REVISION,
    "tiers": ["TIER_A", "BUILD_AND_HOLD", "WATCH", "DROP"],
    "northStar": "rolling_submit_ready_rate",
    "externalMergeCountIsKpi": False,
    "tracks": ["agent_ai_infra", "llm_algorithm"],
    "calibration": {
        "requiredMature": 50,
        "requiredPrecision": 0.80,
        "maxEnrollment": 100,
        "hardGateEscapes": 0,
    },
    "holdout": {
        "requiredMature": 20,
        "requiredPrecision": 0.90,
        "maxEnrollment": 40,
        "hardGateEscapes": 0,
    },
    "releaseStabilityDays": 7,
    "requiredSubmitReadyEvidence": [
        "fresh_state_verified",
        "ownership_verified",
        "policy_verified",
        "reproduction_verified",
        "root_cause_verified",
        "minimal_fix_verified",
        "regression_test_verified",
        "relevant_tests_green",
        "independent_review_passed",
    ],
}
RUNTIME_BUILD_FILES = (
    "scanner.py",
    "policy.py",
    "contracts.py",
    "claims.py",
    "decision.py",
    "dispatch.py",
    "evidence.py",
    "github_client.py",
    "ledger.py",
    "metrics.py",
    "relations.py",
    "repo_policy.py",
    "publication.py",
)


def decision_contract_digest() -> str:
    """Fingerprint versioned decision semantics, excluding transport and UI code."""
    payload = json.dumps(
        DECISION_CONTRACT_MANIFEST,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def runtime_build_digest(
    tools_dir: Path | None = None,
    file_names: tuple[str, ...] = RUNTIME_BUILD_FILES,
) -> str:
    """Fingerprint the exact operational implementation for traceability."""
    root = tools_dir or Path(__file__).resolve().parent
    hasher = hashlib.sha256()
    for name in file_names:
        path = root / name
        hasher.update(path.name.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


@dataclass(frozen=True)
class Prediction:
    tier: str
    reason_code: str


def predict_candidate(
    candidate: dict[str, Any], live_gate: dict[str, Any] | None = None
) -> Prediction:
    """Predict only from frozen scan and optional pre-task live-gate evidence."""
    category = str(candidate.get("category") or "")
    gate = str(candidate.get("gate_decision") or "")
    raw_policy = candidate.get("submission_policy")
    policy = str(raw_policy or "")
    actionability = candidate.get("actionability_evidence") or {}
    raw_assessment = candidate.get("open_pr_assessment")
    assessment = raw_assessment if isinstance(raw_assessment, dict) else {}
    raw_related_assessment = candidate.get("related_issue_assessment")
    related_assessment = raw_related_assessment if isinstance(raw_related_assessment, dict) else {}
    live_checks = (
        live_gate.get("checks")
        if isinstance(live_gate, dict) and isinstance(live_gate.get("checks"), dict)
        else {}
    )
    required_live_checks = ("issueState", "ownership", "duplicate", "design", "policy")
    live_gate_complete = bool(
        isinstance(live_gate, dict)
        and live_gate.get("status") == "PASS"
        and all(live_checks.get(name) == "PASS" for name in required_live_checks)
    )
    labels = " ".join(str(item) for item in candidate.get("labels") or [])
    snapshot_text = (
        " ".join(
            str(candidate.get(field) or "")
            for field in ("title", "risk", "expected_changes", "next_step")
        )
        + " "
        + labels
    )

    if re.search(r"security|vulnerab|安全披露|漏洞|CVE", snapshot_text, re.I):
        return Prediction("DROP", "SECURITY_BLOCKED")
    legacy_normal_policy = raw_policy is None and candidate.get("public_submission_allowed") is True
    private_only = bool(
        category == "LOCAL_FIX_ONLY"
        and gate == "ALLOW_PRIVATE_WORK"
        and policy.startswith("ai_disclosure")
        and candidate.get("public_submission_allowed") is False
    )
    weak_competition = bool(category == "PR_COMPETITION_OPPORTUNITY" and gate == "ALLOW_TO_WORK")
    if (
        policy not in {"normal", "legal_confirmation"}
        and not legacy_normal_policy
        and not private_only
    ):
        return Prediction("DROP", "POLICY_BLOCKED")
    if candidate.get("public_submission_allowed") is not True and not private_only:
        return Prediction("WATCH", "POLICY_BLOCKED")
    if candidate.get("hardware_compatible") is not True:
        return Prediction("WATCH", "HARDWARE_BLOCKED")
    if candidate.get("track") == "llm_algorithm":
        algorithm = candidate.get("algorithm_evidence")
        if not isinstance(algorithm, dict):
            return Prediction("DROP", "ALGORITHM_EVIDENCE_MISSING")
        if (
            algorithm.get("qualified") is not True
            or algorithm.get("operational_only") is not False
            or int(algorithm.get("score") or 0) < 7
            or int(algorithm.get("mechanism_count") or 0) < 1
        ):
            return Prediction("DROP", "ALGORITHM_EVIDENCE_WEAK")
    clean_candidate = bool(category == "NEW_CLEAN_CANDIDATE" and gate == "ALLOW_TO_WORK")
    if not private_only and not clean_candidate and not weak_competition:
        return Prediction("WATCH", "RADAR_GATE_NOT_CLEAN")

    pr_status = str(assessment.get("status") or "")
    if (not assessment or not pr_status) and not live_gate_complete:
        return Prediction("BUILD_AND_HOLD", "OPEN_PR_AUDIT_REQUIRED")

    direct_pr = any(
        bool(item.get("references_issue") or item.get("issue_body_link"))
        for item in assessment.get("prs") or []
        if isinstance(item, dict)
    )
    if pr_status in {
        "direct_open_pr",
        "strong_existing_pr",
        "covered",
        "covered_strong",
        "competition_saturated",
    }:
        return Prediction("DROP", "DUPLICATE")
    if direct_pr and not weak_competition:
        return Prediction("DROP", "DUPLICATE")
    if weak_competition and pr_status != "weak_pr_competition_possible":
        return Prediction("WATCH", "COMPETITION_EVIDENCE_INCOMPLETE")
    if private_only and pr_status == "weak_pr_competition_possible":
        return Prediction("BUILD_AND_HOLD", "WEAK_PR_COMPETITION_PRIVATE_AUDIT")
    if (
        pr_status
        in {
            "keyword_overlap_only",
            "semantic_overlap_requires_review",
            "human_review_required",
            "lookup_failed",
        }
        and not live_gate_complete
    ):
        return Prediction("WATCH", "PR_OVERLAP_REVIEW_REQUIRED")

    related_status = str(related_assessment.get("status") or "")
    if (not related_assessment or not related_status) and not live_gate_complete:
        return Prediction("BUILD_AND_HOLD", "RELATED_ISSUE_AUDIT_REQUIRED")
    if related_status == "potential_overlap":
        return Prediction("WATCH", "RELATED_ISSUE_REVIEW_REQUIRED")
    if related_status and related_status != "none":
        return Prediction("WATCH", "RELATED_ISSUE_AUDIT_FAILED")

    if actionability.get("needs_confirmation") and not actionability.get("maintainer_approved"):
        return Prediction("WATCH", "DESIGN_UNAPPROVED")
    if re.search(
        r"必须(?:先)?(?:得到|获得|等待)?.{0,12}(?:维护者|maintainer).{0,12}(?:确认|批准|approval)|"
        r"(?:requires?|needs?).{0,12}(?:maintainer )?(?:approval|assignment)|"
        r"\b(?:RFC|DEP)\b.{0,20}(?:required|批准|审批|先)|"
        r"(?:设计方向|API 方向).{0,12}(?:未定|待确认|需批准)",
        snapshot_text,
        re.I,
    ) and not actionability.get("maintainer_approved"):
        return Prediction("WATCH", "DESIGN_UNAPPROVED")

    if live_gate is not None:
        if live_gate.get("status") != "PASS":
            return Prediction("WATCH", str(live_gate.get("reasonCode") or "LIVE_GATE_FAILED"))
        if any(
            live_checks.get(name) != "PASS"
            for name in ("issueState", "ownership", "duplicate", "design", "policy")
        ):
            return Prediction("WATCH", "LIVE_GATE_INCOMPLETE")

    if weak_competition:
        return Prediction("BUILD_AND_HOLD", "WEAK_PR_COMPETITION_PRIVATE_AUDIT")

    if private_only:
        return Prediction("BUILD_AND_HOLD", "PRIVATE_ONLY_POLICY")

    repro = int(actionability.get("public_repro_signals") or 0)
    root_cause = actionability.get("root_cause_signal") is True
    maintainer_signal = bool(
        actionability.get("maintainer_approved") or actionability.get("help_wanted")
    )
    if not maintainer_signal and not (root_cause and repro >= 2):
        return Prediction("BUILD_AND_HOLD", "PRIVATE_AUDIT_REQUIRED")
    return Prediction("TIER_A", "FROZEN_EVIDENCE_PASSED")
