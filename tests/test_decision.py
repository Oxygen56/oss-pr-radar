import pytest

from oss_pr_radar.decision import authorize
from oss_pr_radar.evidence import EvidenceBundle


def evidence(body: str) -> EvidenceBundle:
    return EvidenceBundle(
        repo="example/project",
        issue_number=42,
        complete=True,
        completeness={
            "issue": "COMPLETE",
            "comments": "COMPLETE",
            "timeline": "COMPLETE",
            "repositoryPolicy": "COMPLETE",
            "relatedPullRequests": "COMPLETE",
        },
        issue={"state": "open", "title": "Provider model disappears", "body": body},
        comments=(),
        timeline=(),
        claims=(),
        maintainer_approvals=(),
        policy={
            "status": "NORMAL",
            "ai_disclosure": False,
            "ai_prohibited": False,
            "assignment_required": False,
        },
        pull_relations=(),
        hardware={"compatible": True, "required": [], "unavailable": []},
        digest="evidence-digest",
    )


def candidate() -> dict:
    return {
        "track": "agent_ai_infra",
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "llm_review": {
            "status": "ok",
            "decision": "NEW_CLEAN_CANDIDATE",
            "semanticSignal": "NO_OBJECTION",
            "evidence": ["issue_data.issue_body"],
            "confidence": 0.9,
        },
    }


def test_redacted_security_note_does_not_block_normal_bug():
    result = authorize(
        candidate(),
        evidence("Security: API keys and credential values have been removed from this report."),
    )

    assert result.status == "ALLOW"
    assert result.reason_code == "LIVE_EVIDENCE_PASSED"


def test_actual_security_vulnerability_is_blocked():
    result = authorize(
        candidate(),
        evidence("A crafted request triggers remote code execution through command injection."),
    )

    assert result.status == "BLOCK"
    assert result.reason_code == "SECURITY_SENSITIVE"


def test_strong_existing_pr_precedes_contributor_claim():
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{
            **current.__dict__,
            "claims": ({"actor": "contributor", "kind": "active"},),
            "pull_relations": ({"relation": "STRONG_EXACT_DUPLICATE"},),
        }
    )

    result = authorize(candidate(), value)

    assert result.status == "BLOCK"
    assert result.reason_code == "STRONG_EXISTING_PR"
    assert result.checks["duplicate"] == "BLOCK"
    assert result.checks["ownership"] == "PASS"


@pytest.mark.parametrize("blocker", ["targeted_check_unproven", "current_blocking_review"])
def test_competition_candidate_cannot_bypass_unresolved_exact_pr_validation(blocker):
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{
            **current.__dict__,
            "pull_relations": (
                {
                    "relation": "WEAK_OR_PARTIAL_EXACT",
                    "exact_link": True,
                    blocker: True,
                },
            ),
        }
    )
    competition = candidate() | {"category": "PR_COMPETITION_OPPORTUNITY"}

    result = authorize(competition, value)

    assert result.status == "HOLD"
    assert result.reason_code == "EXISTING_PR_VALIDATION_PENDING"
    assert result.checks["duplicate"] == "HOLD"


def test_strong_relation_precedes_a_second_pr_pending_validation():
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{
            **current.__dict__,
            "pull_relations": (
                {"relation": "STRONG_EXACT_DUPLICATE", "exact_link": True},
                {
                    "relation": "WEAK_OR_PARTIAL_EXACT",
                    "exact_link": True,
                    "current_blocking_review": True,
                },
            ),
        }
    )

    result = authorize(candidate(), value)

    assert result.status == "BLOCK"
    assert result.reason_code == "STRONG_EXISTING_PR"


def test_security_label_is_blocked_even_when_issue_text_is_generic():
    current = evidence("Tool output is retained longer than expected.")
    value = EvidenceBundle(
        **{
            **current.__dict__,
            "issue": current.issue | {"labels": [{"name": "security"}, {"name": "secrets"}]},
        }
    )

    result = authorize(candidate(), value)

    assert result.status == "BLOCK"
    assert result.reason_code == "SECURITY_SENSITIVE"


def test_live_gate_rejects_weak_algorithm_snapshot():
    value = candidate()
    value.update(
        {
            "track": "llm_algorithm",
            "algorithm_evidence": {
                "score": 5,
                "mechanism_count": 1,
                "qualified": False,
                "operational_only": True,
            },
        }
    )

    result = authorize(value, evidence("A normal training bug report."))

    assert result.status == "BLOCK"
    assert result.reason_code == "ALGORITHM_EVIDENCE_WEAK"


def test_live_gate_blocks_nonstandard_contribution_agreement():
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{
            **current.__dict__,
            "policy": current.policy
            | {
                "status": "LEGAL_POLICY_REVIEW",
                "nonstandard_agreement": True,
            },
        }
    )

    result = authorize(candidate(), value)

    assert result.status == "BLOCK"
    assert result.reason_code == "NONSTANDARD_CONTRIBUTION_AGREEMENT"


def test_live_gate_allows_ai_disclosure_candidate_for_private_work_only():
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{
            **current.__dict__,
            "policy": current.policy | {"ai_disclosure": True},
        }
    )
    private_candidate = candidate() | {
        "category": "LOCAL_FIX_ONLY",
        "gate_decision": "ALLOW_PRIVATE_WORK",
        "public_submission_allowed": False,
    }

    result = authorize(private_candidate, value)

    assert result.status == "ALLOW"
    assert result.reason_code == "AI_DISCLOSURE_PRIVATE_WORK_ALLOWED"


def test_live_gate_allows_private_disclosure_only_wait():
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{**current.__dict__, "policy": current.policy | {"ai_disclosure": True}}
    )
    private_candidate = candidate() | {
        "category": "LOCAL_FIX_ONLY",
        "gate_decision": "ALLOW_PRIVATE_WORK",
        "auto_spawn": True,
        "public_submission_allowed": False,
        "llm_review": {
            "status": "ok",
            "decision": "WAIT_MAINTAINER",
            "waitReason": "DISCLOSURE_ONLY",
            "semanticSignal": "NO_OBJECTION",
            "confidence": 0.7,
        },
    }

    result = authorize(private_candidate, value)

    assert result.status == "HOLD"
    assert result.reason_code == "SEMANTIC_REVIEW_NOT_ACTIONABLE"


def test_live_gate_holds_private_disclosure_task_waiting_on_design():
    current = evidence("A normal runtime bug report.")
    value = EvidenceBundle(
        **{**current.__dict__, "policy": current.policy | {"ai_disclosure": True}}
    )
    private_candidate = candidate() | {
        "category": "LOCAL_FIX_ONLY",
        "gate_decision": "ALLOW_PRIVATE_WORK",
        "auto_spawn": True,
        "public_submission_allowed": False,
        "llm_review": {
            "status": "ok",
            "decision": "WAIT_MAINTAINER",
            "waitReason": "DESIGN_CONFIRMATION",
            "confidence": 0.7,
        },
    }

    result = authorize(private_candidate, value)

    assert result.status == "HOLD"
    assert result.reason_code == "SEMANTIC_REVIEW_NOT_ACTIONABLE"
