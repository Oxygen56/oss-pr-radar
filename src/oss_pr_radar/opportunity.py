"""Deterministic opportunity gates, ranking, capacity, and outcome learning.

This module intentionally has no GitHub, LLM, notification, or task-creation
side effects. It consumes evidence snapshots and returns decisions that callers
must persist and revalidate before doing any external work.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from .util import sha256_json

PRE_TASK_EVIDENCE_SCHEMA = "pre_task_evidence_v1"
CAPACITY_SCHEMA = "opportunity_capacity_v1"
RESULT_CLASSIFICATIONS = (
    "scan_false_positive",
    "state_drift",
    "blocked_pre_task",
    "task_no_go",
    "censored",
)
SEMANTIC_SIGNALS = ("NO_OBJECTION", "FILTER", "RETRY")
MATURE_HORIZONS = (14, 30, 60)


def external_side_effect_allowed(value: dict[str, Any]) -> bool:
    """Keep silent exploration out of every externally visible worker."""

    nested = value.get("intent") if isinstance(value.get("intent"), dict) else {}
    maturity = value.get("maturity") or nested.get("maturity")
    notify = value.get("notify") if "notify" in value else nested.get("notify", True)
    return str(maturity or "").casefold() != "exploration" and notify is not False


def evidence_digest(value: dict[str, Any]) -> str:
    return sha256_json(value)


def classify_scan_outcome(status: str, reason: str = "") -> str:
    """Map a scanner disposition to one and only one managed classification."""

    text = f"{status}:{reason}".casefold()
    if any(marker in text for marker in ("drift", "stale_state", "base_changed", "issue_changed")):
        return "state_drift"
    if any(marker in text for marker in ("policy", "no_go", "not_accepting", "agreement")):
        return "task_no_go"
    if status in {"deferred", "status_update", "lookup_failed", "inspection_budget_deferred"}:
        return "blocked_pre_task"
    if any(
        marker in text
        for marker in ("blocked", "lookup_failed", "fetch_failed", "incomplete", "unknown")
    ):
        return "blocked_pre_task"
    return "scan_false_positive"


def validate_result_classification(value: str) -> str:
    if value not in RESULT_CLASSIFICATIONS:
        raise ValueError(f"invalid opportunity result classification: {value}")
    return value


def normalize_semantic_signal(review: dict[str, Any]) -> dict[str, Any]:
    """Normalize model output as evidence, never as authorization."""

    raw_signal = str(review.get("semanticSignal") or review.get("semantic_signal") or "").upper()
    signal = raw_signal
    explicit_decision = str(review.get("decision") or "").upper()
    decision_signal = {
        "REJECT": "FILTER",
        "WAIT_MAINTAINER": "RETRY",
        "NEW_CLEAN_CANDIDATE": "NO_OBJECTION",
        "PR_COMPETITION_OPPORTUNITY": "NO_OBJECTION",
    }.get(explicit_decision)
    if not signal:
        signal = "RETRY"
    if signal not in SEMANTIC_SIGNALS:
        signal = "RETRY"
    if raw_signal and decision_signal and signal != decision_signal:
        signal = "RETRY"
    try:
        confidence = max(0.0, min(1.0, float(review.get("confidence", 0.0))))
    except (TypeError, ValueError):
        confidence = 0.0
    raw_evidence = review.get("evidence") or review.get("evidence_ids") or []
    if not isinstance(raw_evidence, list):
        raw_evidence = []
    return {
        "semanticSignal": signal,
        "evidence": [str(item)[:500] for item in raw_evidence[:12] if str(item).strip()],
        "confidence": confidence,
    }


def pre_task_gate(
    candidate: dict[str, Any],
    evidence: dict[str, Any],
    *,
    expected: dict[str, Any] | None = None,
    require_semantic: bool = True,
) -> dict[str, Any]:
    """Evaluate the immutable evidence required before creating a task."""

    expected = expected or {}
    reasons: list[str] = []
    issue = evidence.get("issue") if isinstance(evidence.get("issue"), dict) else {}
    policy = evidence.get("policy") if isinstance(evidence.get("policy"), dict) else {}
    duplicate = evidence.get("duplicate") if isinstance(evidence.get("duplicate"), dict) else {}
    base_sha = str(evidence.get("baseSha") or evidence.get("base_sha") or "")
    current_issue_digest = str(evidence.get("issueDigest") or "")
    expected_base = str(expected.get("baseSha") or expected.get("base_sha") or "")
    expected_issue = str(expected.get("issueDigest") or "")
    expected_design = str(expected.get("designDigest") or "")
    expected_assignee = str(expected.get("assigneeDigest") or "")
    state_drift = []
    if expected_base and expected_base != base_sha:
        state_drift.append("base_sha_changed")
    if expected_issue and expected_issue != current_issue_digest:
        state_drift.append("issue_changed")
    for key, label in (
        ("designDigest", "design_changed"),
        ("assigneeDigest", "assignee_changed"),
        ("duplicateDigest", "duplicate_changed"),
    ):
        old = str(expected.get(key) or "")
        new = str(evidence.get(key) or "")
        if old and old != new:
            state_drift.append(label)
    if state_drift:
        reasons.extend(state_drift)

    if str(issue.get("state") or evidence.get("issueState") or "").casefold() != "open":
        reasons.append("issue_not_open")
    if evidence.get("botOnlyRefresh") is True or evidence.get("stale") is True:
        reasons.append("stale_or_bot_refresh")
    if issue.get("assignees") or evidence.get("assignees"):
        reasons.append("issue_assigned")
    if (
        policy.get("status")
        in {
            "UNKNOWN",
            "policy_unknown",
            "AI_POLICY_REVIEW",
            "ai_disclosure_conflict",
            "ai_disclosure_and_assignment",
        }
        or evidence.get("aiDisclosureConflict") is True
    ):
        reasons.append("policy_or_disclosure_uncertain")
    if policy.get("assignment_required") or evidence.get("assignmentRequired") is True:
        if evidence.get("maintainerApproval") is not True and not evidence.get(
            "assignmentEventKey"
        ):
            reasons.append("assignment_required")
    if evidence.get("claUncertain") is True or evidence.get("dcoUncertain") is True:
        reasons.append("legal_policy_uncertain")
    if not base_sha:
        reasons.append("base_sha_missing")
    code_paths = (
        evidence.get("codePaths")
        or evidence.get("code_paths")
        or evidence.get("codePathsPlan")
        or []
    )
    if not isinstance(code_paths, list) or not code_paths:
        reasons.append("no_code_surface")
    if evidence.get("docsOnly") is True or evidence.get("issueOnly") is True:
        reasons.append("docs_or_issue_only")
    if evidence.get("matureRepository") is False:
        reasons.append("repository_not_mature")
    reproduction = evidence.get("reproductionPath")
    if reproduction is None:
        reproduction = evidence.get("reproductionPathPlan")
    validation = evidence.get("validationPath")
    if validation is None:
        validation = evidence.get("validationPathPlan")
    if reproduction is not True or validation is not True:
        reasons.append("reproduction_or_validation_missing")
    duplicate_status = str(duplicate.get("status") or evidence.get("duplicateStatus") or "")
    if duplicate_status in {"covered_strong", "strong", "merged", "competition_saturated"}:
        reasons.append("strong_existing_pr")
    elif duplicate_status in {"lookup_failed", "uncertain"}:
        reasons.append("duplicate_evidence_uncertain")
    if require_semantic:
        semantic = (
            candidate.get("llm_review") if isinstance(candidate.get("llm_review"), dict) else {}
        )
        normalized = normalize_semantic_signal(semantic)
        if normalized["semanticSignal"] != "NO_OBJECTION":
            reasons.append(f"semantic_{normalized['semanticSignal'].casefold()}")
        if normalized["confidence"] < 0.65:
            reasons.append("semantic_confidence_low")

    unique_reasons = list(dict.fromkeys(reasons))
    if state_drift or "stale_or_bot_refresh" in unique_reasons:
        classification = "state_drift"
    elif any(
        reason
        in {
            "policy_or_disclosure_uncertain",
            "legal_policy_uncertain",
            "assignment_required",
            "duplicate_evidence_uncertain",
            "base_sha_missing",
            "reproduction_or_validation_missing",
        }
        for reason in unique_reasons
    ):
        classification = "blocked_pre_task"
    elif any(reason.startswith("semantic_") for reason in unique_reasons):
        classification = "blocked_pre_task"
    elif unique_reasons:
        classification = "task_no_go"
    else:
        classification = None
    return {
        "schema": PRE_TASK_EVIDENCE_SCHEMA,
        "allowed": not unique_reasons,
        "reason": "PRE_TASK_EVIDENCE_PASSED" if not unique_reasons else unique_reasons[0],
        "reasons": unique_reasons,
        "classification": classification,
        "baseSha": base_sha,
        "evidenceDigest": evidence_digest(evidence),
        "expected": {
            "baseSha": expected_base,
            "issueDigest": expected_issue,
            "designDigest": expected_design,
            "assigneeDigest": expected_assignee,
            "duplicateDigest": str(expected.get("duplicateDigest") or ""),
        },
    }


def score_existing_pr(pr: dict[str, Any]) -> dict[str, Any]:
    """Score competing PR strength without treating CI failure as ownership."""

    components = {
        "rootCauseCoverage": 20
        if pr.get("rootCauseCoverage") or pr.get("technical_complete")
        else 0,
        "tests": 18 if int(pr.get("testFiles") or pr.get("test_files") or 0) > 0 else 0,
        "draft": -12 if pr.get("isDraft") or pr.get("is_draft") else 0,
        "activity": 8 if int(pr.get("ageDays") or pr.get("age_days") or 999) < 30 else 0,
        "maintainerRecognition": 12
        if pr.get("maintainerOwned") or pr.get("maintainer_owned") or pr.get("reviewApproved")
        else 0,
        "changeScope": -12
        if int(pr.get("changedFiles") or pr.get("changed_files") or 0) > 18
        else 6,
        "runtimePath": 12 if pr.get("runtimePath") or pr.get("semanticOverlap") else 0,
    }
    score = max(0, min(100, sum(components.values())))
    independent_evidence = {
        "codeChange": bool(
            pr.get("changedFiles") or pr.get("codeChanged") or pr.get("actualCodeChange")
        ),
        "tests": bool(pr.get("testFiles") or pr.get("testEvidence")),
        "maintainerRecognition": components["maintainerRecognition"] > 0,
        "keyPathCoverage": bool(
            pr.get("runtimePath") or pr.get("semanticOverlap") or pr.get("keyPathCoverage")
        ),
    }
    satisfied = sum(independent_evidence.values())
    strong = bool(components["rootCauseCoverage"] > 0 and satisfied >= 2)
    gaps = [name for name, present in independent_evidence.items() if not present]
    return {
        "score": score,
        "strong": strong,
        "components": components,
        "reasons": [name for name, value in components.items() if value > 0],
        "independentEvidence": independent_evidence,
        "gaps": gaps,
        "ciIsDiagnosticOnly": True,
        "ciDoesNotDetermineStrength": True,
    }


def rank_opportunity(
    candidate: dict[str, Any],
    *,
    repository: dict[str, Any] | None = None,
    history: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return an explainable, deterministic high-signal ranking."""

    repository = repository or {}
    history = history or {}
    action = candidate.get("actionability_evidence") or {}
    pr = candidate.get("open_pr_assessment") or {}
    components = {
        "technicalDepth": min(
            20, int(candidate.get("difficultyScore") or candidate.get("score") or 0) * 2
        ),
        "actualImpact": min(
            18, 12 if str(candidate.get("impact") or "").casefold() == "high" else 7
        ),
        "rootCauseClarity": 15
        if action.get("root_cause_signal") or action.get("rootCauseSignal")
        else 4,
        "verifiability": min(
            15,
            int(action.get("public_repro_signals") or 0) * 4
            + (3 if action.get("probe_ready") else 0),
        ),
        "maintainerAdoption": 12
        if action.get("maintainer_approved") or action.get("maintainerApproved")
        else 0,
        "duplicateRisk": -14
        if pr.get("status") in {"weak_pr_competition_possible", "semantic_overlap_requires_review"}
        else 0,
        "narrativeValue": 8 if candidate.get("track") in {"agent_ai_infra", "llm_algorithm"} else 0,
        "repositoryMaturity": min(10, int(repository.get("maturityScore") or 0)),
        "portfolioDiversity": 5
        if history.get("repoCount", 0) < 3 or history.get("topicCount", 0) < 3
        else 0,
    }
    score = sum(components.values())
    reasons = [f"{key}:{value}" for key, value in components.items() if value]
    return {
        "schema": "opportunity_rank_v1",
        "score": score,
        "components": components,
        "reasons": reasons,
        "ciIsNotPrimaryValue": True,
        "mergedCountIsNotPrimaryValue": True,
    }


def allocate_capacity(
    candidates: list[dict[str, Any]], *, capacity: int, seed: str
) -> dict[str, Any]:
    """Allocate fixed 90/10 slots without backfilling weak exploration."""

    capacity = max(0, int(capacity))
    mature_slots = (capacity * 9) // 10
    exploration_slots = capacity - mature_slots

    def stable_key(item: dict[str, Any]) -> str:
        key = f"{seed}|{item.get('repo')}#{item.get('num')}"
        return hashlib.sha256(key.encode()).hexdigest()

    mature = sorted(
        [item for item in candidates if item.get("maturity") != "exploration"],
        key=lambda item: (
            -int((item.get("ranking") or {}).get("score") or item.get("score") or 0),
            stable_key(item),
        ),
    )
    exploration = sorted(
        [item for item in candidates if item.get("maturity") == "exploration"],
        key=stable_key,
    )
    selected_mature = mature[:mature_slots]
    selected_exploration = exploration[:exploration_slots]
    selected_keys = {
        f"{item.get('repo')}#{item.get('num')}" for item in selected_mature + selected_exploration
    }
    return {
        "schema": CAPACITY_SCHEMA,
        "seed": seed,
        "capacity": capacity,
        "slots": {"mature": mature_slots, "exploration": exploration_slots},
        "mature": selected_mature,
        "exploration": selected_exploration,
        "unused": {
            "mature": max(0, mature_slots - len(selected_mature)),
            "exploration": max(0, exploration_slots - len(selected_exploration)),
            "reason": "no_eligible_candidates",
        },
        "selectedKeys": sorted(selected_keys),
    }


def cohort_report(records: list[dict[str, Any]], *, now: datetime) -> dict[str, Any]:
    """Build separate mature funnels and preserve right-censored outcomes."""

    now = now.astimezone(UTC)
    output: dict[str, Any] = {}
    for horizon in MATURE_HORIZONS:
        eligible = []
        for record in records:
            selected_at = record.get("selectedAt") or record.get("observedAt")
            if not selected_at:
                continue
            try:
                due = datetime.fromisoformat(str(selected_at).replace("Z", "+00:00")) + timedelta(
                    days=horizon
                )
            except ValueError:
                continue
            if due > now:
                continue
            label = record.get("outcome")
            if label not in {"success", "failure", "censored"}:
                label = "censored"
            eligible.append(record | {"horizonDays": horizon, "label": label})
        funnel = {
            stage: sum(bool(record.get(stage)) for record in eligible)
            for stage in (
                "selected",
                "task",
                "fix",
                "pr",
                "ci",
                "humanResponse",
                "portfolioOutcome",
            )
        }
        output[str(horizon)] = {
            "eligible": len(eligible),
            "labels": {
                label: sum(item["label"] == label for item in eligible)
                for label in ("success", "failure", "censored")
            },
            "funnel": funnel,
            "records": eligible,
        }
    return output
