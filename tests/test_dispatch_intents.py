from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.dispatch import DispatchSigner, SignatureError, verify_queue
from oss_pr_radar.policy import SCANNER_DECISION_REVISION, decision_contract_digest

SCRIPT = Path(__file__).parents[1] / "scripts" / "build_dispatch_intents.py"
SPEC = importlib.util.spec_from_file_location("build_dispatch_intents", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

KEY = "k" * 64
NOW = datetime(2026, 8, 4, tzinfo=UTC)


def candidate(**updates):
    value = {
        "repo": "example/project",
        "num": 42,
        "url": "https://github.com/example/project/issues/42",
        "title": "Runtime bug",
        "category": "NEW_CLEAN_CANDIDATE",
        "score": 9,
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "public_submission_allowed": True,
        "llm_review": {
            "status": "ok",
            "decision": "NEW_CLEAN_CANDIDATE",
            "confidence": 0.91,
            "model": "deepseek-v4-flash",
        },
    }
    value.update(updates)
    return value


def report(*candidates):
    return {
        "scan_ok": True,
        "now": "2026-08-04T00:00:00Z",
        "run_id": "run-1",
        "snapshot_id": "snapshot-1",
        "scanner_version": SCANNER_DECISION_REVISION,
        "candidate_details": list(candidates),
    }


def test_builds_signed_promptless_envelope():
    result = MODULE.build(report(candidate()), signing_key=KEY, now=NOW, source_sha="abc123")
    intent = result["intents"][0]
    assert "prompt" not in intent
    assert intent["sourceSha"] == "abc123"
    assert intent["scannerVersion"] == SCANNER_DECISION_REVISION
    assert intent["decisionContractDigest"] == decision_contract_digest()
    assert len(intent["promptDigest"]) == 64
    assert verify_queue(result, DispatchSigner(KEY), now=NOW) == [intent]


def test_canary_envelope_carries_narrow_publication_authorization():
    result = MODULE.build(
        report(candidate()),
        signing_key=KEY,
        now=NOW,
        mode="canary",
    )
    intent = result["intents"][0]
    assert intent["autoSubmitAuthorized"] is True
    assert intent["publicationMode"] == "canary"
    assert intent["authorizationSource"] == "signed_live_revalidation_required"


def test_human_review_and_llm_failure_are_not_dispatched():
    result = MODULE.build(
        report(
            candidate(gate_decision="HUMAN_REVIEW", auto_spawn=False),
            candidate(llm_review={"status": "error"}, auto_spawn=False),
        ),
        signing_key=KEY,
        now=NOW,
    )
    assert result["intents"] == []


def test_existing_unconsumed_intent_survives_unobserved_scan_until_expiry():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    result = MODULE.build(report(), existing, signing_key=KEY, now=NOW + timedelta(minutes=30))
    assert [item["key"] for item in result["intents"]] == ["example/project#42"]
    assert result["newIntentCount"] == 0


def test_old_scanner_revision_intent_is_revoked_before_issue_recheck():
    signer = DispatchSigner(KEY)
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    stale_intent = dict(existing["intents"][0])
    stale_intent["scannerVersion"] = "oss_pr_radar_v18_previous"
    existing["intents"] = [signer.seal(stale_intent)]
    existing["scannerVersion"] = "oss_pr_radar_v18_previous"
    existing = signer.seal(existing)

    result = MODULE.build(
        report(),
        existing,
        signing_key=KEY,
        now=NOW + timedelta(minutes=10),
    )

    assert result["intents"] == []


def test_stale_scanner_report_cannot_build_dispatch_queue():
    stale = report(candidate())
    stale["scanner_version"] = "oss_pr_radar_v18_previous"
    with pytest.raises(ValueError, match="stale scanner decision revision"):
        MODULE.build(stale, signing_key=KEY, now=NOW)


def test_observed_rejection_revokes_existing_intent():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    result = MODULE.build(
        report(candidate(auto_spawn=False, gate_decision="HUMAN_REVIEW")),
        existing,
        signing_key=KEY,
        now=NOW + timedelta(minutes=10),
    )
    assert result["intents"] == []


def test_scanner_rejection_outcome_revokes_existing_intent():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    rejected = report()
    rejected["issue_outcomes"] = {
        "example/project#42": {
            "status": "rejected",
            "reason": "managed_inference_service_incident",
        }
    }
    result = MODULE.build(
        rejected,
        existing,
        signing_key=KEY,
        now=NOW + timedelta(minutes=10),
    )
    assert result["intents"] == []


def test_deferred_outcome_does_not_revoke_existing_intent():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    deferred = report()
    deferred["issue_outcomes"] = {
        "example/project#42": {
            "status": "deferred",
            "reason": "inspection_budget_deferred",
        }
    }
    result = MODULE.build(
        deferred,
        existing,
        signing_key=KEY,
        now=NOW + timedelta(minutes=10),
    )
    assert [item["key"] for item in result["intents"]] == ["example/project#42"]


def test_tampering_and_expiry_fail_closed():
    result = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    result["intents"][0]["title"] = "tampered"
    with pytest.raises(SignatureError):
        verify_queue(result, DispatchSigner(KEY), now=NOW)

    fresh = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    assert verify_queue(fresh, DispatchSigner(KEY), now=NOW + timedelta(hours=3)) == []
