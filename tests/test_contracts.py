import pytest

from oss_pr_radar.contracts import ContractError, validate_report


def candidate(**updates):
    value = {
        "repo": "a/b",
        "num": 1,
        "url": "https://github.com/a/b/issues/1",
        "title": "Bug",
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "llm_review": {"status": "ok", "decision": "WAIT_MAINTAINER"},
    }
    value.update(updates)
    return value


def test_validation_does_not_mutate_failed_llm_candidate():
    report = {"scan_ok": True, "candidate_details": [candidate(llm_review={"status": "error"})]}
    before = report.copy() | {"candidate_details": [dict(report["candidate_details"][0])]}
    validate_report(report)
    assert report == before


def test_auto_spawn_requires_actionable_review():
    with pytest.raises(ContractError):
        validate_report(
            {
                "scan_ok": True,
                "candidate_details": [candidate(auto_spawn=True, gate_decision="ALLOW_TO_WORK")],
            }
        )


def test_failed_scan_is_rejected():
    with pytest.raises(ContractError):
        validate_report({"scan_ok": False, "scan_error": "incomplete", "candidate_details": []})

