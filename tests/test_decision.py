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
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "llm_review": {
            "status": "ok",
            "decision": "NEW_CLEAN_CANDIDATE",
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
