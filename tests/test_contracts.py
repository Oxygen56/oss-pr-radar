import pytest

from oss_pr_radar.contracts import SCAN_SCHEMA, ContractError, contract_digest, validate_report


def candidate(**updates):
    value = {
        "repo": "a/b",
        "num": 1,
        "url": "https://github.com/a/b/issues/1",
        "title": "Bug",
        "track": "agent_ai_infra",
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


def test_v2_report_requires_scan_observability_contract():
    report = {
        "scan_ok": True,
        "schema_version": SCAN_SCHEMA,
        "contract_digest": contract_digest(),
        "run_id": "run-1",
        "snapshot_id": "snapshot-1",
        "tracks": ["agent_ai_infra", "llm_algorithm"],
        "candidate_details": [],
        "timings_seconds": {"collect": 1.0, "total": 2.0},
        "repository_activity": {
            "fixed_scope": ["a/b"],
            "queried": ["a/b"],
            "matched": [],
            "qualified": [],
            "inspected": [],
            "collection_failures": {},
        },
        "deferred_rechecks": {"cooldown_enabled": False},
    }

    validate_report(report, require_v2=True)
    del report["repository_activity"]
    with pytest.raises(ContractError, match="repository_activity"):
        validate_report(report, require_v2=True)
