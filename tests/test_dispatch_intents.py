from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.dispatch import (
    LEGACY_QUEUE_CONTRACTS,
    QUEUE_VERSION,
    SUPERSEDED_SCANNER_DECISION_CONTRACTS,
    DispatchSigner,
    SignatureError,
    canonical_prompt,
    superseded_scanner_revision_queue,
    verify_queue,
)
from oss_pr_radar.policy import SCANNER_DECISION_REVISION, decision_contract_digest
from oss_pr_radar.util import iso_z, sha256_text

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
        "issue_updated": "2026-08-04T00:00:00Z",
        "policy_digest": "policy-digest",
        "track": "agent_ai_infra",
        "category": "NEW_CLEAN_CANDIDATE",
        "score": 9,
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "public_submission_allowed": True,
        "preTaskEvidence": {
            "schema": "pre_task_evidence_v1",
            "baseSha": "base-a",
            "issue": {"state": "open", "assignees": []},
            "codePaths": ["src/runtime.py"],
            "reproductionPath": True,
            "validationPath": True,
        },
        "preTaskGate": {
            "schema": "pre_task_evidence_v1",
            "allowed": True,
            "reason": "PRE_TASK_EVIDENCE_PASSED",
            "evidenceDigest": "evidence-digest",
        },
        "llm_review": {
            "status": "ok",
            "decision": "NEW_CLEAN_CANDIDATE",
            "semanticSignal": "NO_OBJECTION",
            "evidence": ["issue_data.issue_body"],
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
    assert intent["issueUpdatedAt"] == "2026-08-04T00:00:00Z"
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


def test_algorithm_evidence_is_bound_into_dispatch_intent():
    algorithm_evidence = {
        "score": 9,
        "depth": "high",
        "mechanisms": ["post_training_objective", "training_optimization"],
        "mechanism_count": 2,
        "operational_only": False,
        "qualified": True,
    }
    result = MODULE.build(
        report(
            candidate(
                track="llm_algorithm",
                algorithm_evidence=algorithm_evidence,
                actionability_evidence={"public_repro_signals": 2},
            )
        ),
        signing_key=KEY,
        now=NOW,
    )

    intent = result["intents"][0]
    assert intent["track"] == "llm_algorithm"
    assert intent["algorithmEvidence"] == algorithm_evidence


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


def test_strict_deterministic_fallback_is_not_dispatched():
    with pytest.raises(ValueError):
        MODULE.build(
            report(
                candidate(
                    llm_review={
                        "status": "deterministic_fallback",
                        "decision": "NEW_CLEAN_CANDIDATE",
                        "semantic_review_mode": "deterministic_high_confidence_fallback",
                    }
                )
            ),
            signing_key=KEY,
            now=NOW,
        )


def test_ai_disclosure_candidate_is_dispatched_for_private_work_only():
    result = MODULE.build(
        report(
            candidate(
                category="LOCAL_FIX_ONLY",
                gate_decision="ALLOW_PRIVATE_WORK",
                submission_policy="ai_disclosure_conflict",
                public_submission_allowed=False,
            )
        ),
        signing_key=KEY,
        now=NOW,
        mode="canary",
    )
    assert len(result["intents"]) == 1
    assert result["intents"][0]["autoSubmitAuthorized"] is False
    assert result["intents"][0]["submissionPolicy"] == "ai_disclosure_conflict"


def test_ai_disclosure_only_wait_dispatches_private_task():
    result = MODULE.build(
        report(
            candidate(
                category="LOCAL_FIX_ONLY",
                gate_decision="ALLOW_PRIVATE_WORK",
                submission_policy="ai_disclosure_conflict",
                public_submission_allowed=False,
                llm_review={
                    "status": "ok",
                    "decision": "WAIT_MAINTAINER",
                    "wait_reason": "DISCLOSURE_ONLY",
                    "semanticSignal": "NO_OBJECTION",
                    "evidence": ["issue_data.issue_body"],
                    "confidence": 0.7,
                    "model": "deepseek-v4-flash",
                },
            )
        ),
        signing_key=KEY,
        now=NOW,
        mode="canary",
    )
    assert len(result["intents"]) == 1
    assert result["intents"][0]["autoSubmitAuthorized"] is False
    assert result["intents"][0]["llmReview"]["waitReason"] == "DISCLOSURE_ONLY"


def test_ai_disclosure_design_wait_does_not_dispatch_private_task():
    result = MODULE.build(
        report(
            candidate(
                category="WAIT_MAINTAINER",
                gate_decision="HUMAN_REVIEW",
                auto_spawn=False,
                submission_policy="ai_disclosure_conflict",
                public_submission_allowed=False,
                llm_review={
                    "status": "ok",
                    "decision": "WAIT_MAINTAINER",
                    "wait_reason": "DESIGN_CONFIRMATION",
                    "confidence": 0.7,
                    "model": "deepseek-v4-flash",
                },
            )
        ),
        signing_key=KEY,
        now=NOW,
        mode="canary",
    )

    assert result["intents"] == []


def test_existing_unconsumed_intent_survives_unobserved_scan_and_is_renewed():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    result = MODULE.build(report(), existing, signing_key=KEY, now=NOW + timedelta(minutes=30))
    assert [item["key"] for item in result["intents"]] == ["example/project#42"]
    assert result["newIntentCount"] == 0
    assert result["intents"][0]["expiresAt"] > existing["intents"][0]["expiresAt"]


def test_expired_unconsumed_intent_is_renewed_until_live_claim_revalidation():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    result = MODULE.build(report(), existing, signing_key=KEY, now=NOW + timedelta(hours=3))
    assert [item["key"] for item in result["intents"]] == ["example/project#42"]
    assert result["newIntentCount"] == 0
    renewed_expiry = datetime.fromisoformat(
        result["intents"][0]["expiresAt"].replace("Z", "+00:00")
    )
    assert renewed_expiry > NOW + timedelta(hours=3)


def test_seen_recently_and_transient_failures_do_not_withdraw_pending_intent():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    for reason in (
        "seen_recently",
        "issue_fetch_failed",
        "comments_lookup_failed",
        "repo_quality:repo_meta_failed",
    ):
        current = report()
        current["issue_outcomes"] = {"example/project#42": {"status": "rejected", "reason": reason}}
        result = MODULE.build(
            current,
            existing,
            signing_key=KEY,
            now=NOW + timedelta(minutes=30),
        )
        assert [item["key"] for item in result["intents"]] == ["example/project#42"]


def test_retained_intent_respects_current_rollout_mode():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW, mode="canary")
    result = MODULE.build(
        report(),
        existing,
        signing_key=KEY,
        now=NOW + timedelta(minutes=30),
        mode="shadow",
    )
    assert result["intents"][0]["autoSubmitAuthorized"] is False
    assert result["intents"][0]["publicationMode"] == "shadow"


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


def test_current_scanner_revision_and_decision_contract_filter_non_contradictions():
    assert SCANNER_DECISION_REVISION == "oss_pr_radar_v51_bounded_wait_evidence"
    assert decision_contract_digest() != (
        "63d9b5419e4b58f072055513e60148abadfd4bfc9e8ae799e791a761ff3f56a4"
    )


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


def test_controller_terminal_outcome_revokes_existing_intent():
    existing = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    rejected = report()
    rejected["issue_outcomes"] = {
        "example/project#42": {
            "status": "rejected",
            "reason": "controller_terminal",
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


def test_v6_intent_requires_issue_update_watermark():
    signer = DispatchSigner(KEY)
    queue = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    broken = dict(queue["intents"][0])
    broken.pop("issueUpdatedAt")
    queue["intents"] = [signer.seal(broken)]
    queue = signer.seal(queue)

    with pytest.raises(SignatureError, match="issue update watermark"):
        verify_queue(queue, signer, now=NOW)


def test_current_intent_requires_policy_watermark():
    signer = DispatchSigner(KEY)
    queue = MODULE.build(report(candidate()), signing_key=KEY, now=NOW)
    broken = dict(queue["intents"][0])
    broken["policyDigest"] = ""
    queue["intents"] = [signer.seal(broken)]
    queue = signer.seal(queue)

    with pytest.raises(SignatureError, match="policy watermark"):
        verify_queue(queue, signer, now=NOW)


def test_signed_previous_current_format_queue_is_only_superseded_not_dispatchable():
    signer = DispatchSigner(KEY)
    scanner_version = "oss_pr_radar_v50_material_contradictions"
    legacy = SUPERSEDED_SCANNER_DECISION_CONTRACTS[scanner_version]
    issue_url = "https://github.com/example/project/issues/42"
    intent = signer.seal(
        {
            "version": legacy["intentVersion"],
            "intentId": "legacy-intent-v50",
            "key": "example/project#42",
            "repo": "example/project",
            "issueNumber": 42,
            "issueUrl": issue_url,
            "issueUpdatedAt": "2026-08-04T00:00:00Z",
            "policyDigest": "policy-digest",
            "scannerVersion": scanner_version,
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "promptDigest": sha256_text(canonical_prompt(issue_url)),
            "issuedAt": iso_z(NOW),
            "expiresAt": iso_z(NOW + timedelta(hours=2)),
            "status": "PENDING",
        }
    )
    queue = signer.seal(
        {
            "version": QUEUE_VERSION,
            "scannerVersion": scanner_version,
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "intentCount": 1,
            "intents": [intent],
        }
    )

    with pytest.raises(SignatureError, match="stale scanner decision revision"):
        verify_queue(queue, signer, now=NOW)
    stale = superseded_scanner_revision_queue(queue, signer)
    assert stale is not None
    assert stale["status"] == "superseded_scanner_revision"
    assert stale["scannerVersion"] == scanner_version
    assert stale["intentCount"] == 1


def test_signed_v4_queue_remains_readable_during_v7_deployment():
    signer = DispatchSigner(KEY)
    legacy = LEGACY_QUEUE_CONTRACTS["dispatch_intents_v4"]
    issue_url = "https://github.com/example/project/issues/42"
    intent = signer.seal(
        {
            "version": legacy["intentVersion"],
            "intentId": "legacy-intent",
            "key": "example/project#42",
            "repo": "example/project",
            "issueNumber": 42,
            "issueUrl": issue_url,
            "scannerVersion": legacy["scannerVersion"],
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "promptDigest": sha256_text(canonical_prompt(issue_url)),
            "issuedAt": iso_z(NOW),
            "expiresAt": iso_z(NOW + timedelta(hours=2)),
            "status": "PENDING",
        }
    )
    queue = signer.seal(
        {
            "version": "dispatch_intents_v4",
            "scannerVersion": legacy["scannerVersion"],
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "intents": [intent],
        }
    )

    assert verify_queue(queue, signer, now=NOW) == [intent]


def test_signed_v5_queue_remains_readable_during_v7_deployment():
    signer = DispatchSigner(KEY)
    legacy = LEGACY_QUEUE_CONTRACTS["dispatch_intents_v5"]
    issue_url = "https://github.com/example/project/issues/42"
    intent = signer.seal(
        {
            "version": legacy["intentVersion"],
            "intentId": "legacy-intent-v5",
            "key": "example/project#42",
            "repo": "example/project",
            "issueNumber": 42,
            "issueUrl": issue_url,
            "scannerVersion": legacy["scannerVersion"],
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "promptDigest": sha256_text(canonical_prompt(issue_url)),
            "issuedAt": iso_z(NOW),
            "expiresAt": iso_z(NOW + timedelta(hours=2)),
            "status": "PENDING",
        }
    )
    queue = signer.seal(
        {
            "version": "dispatch_intents_v5",
            "scannerVersion": legacy["scannerVersion"],
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "intents": [intent],
        }
    )

    assert verify_queue(queue, signer, now=NOW) == [intent]


def test_signed_v6_queue_remains_readable_during_v7_deployment():
    signer = DispatchSigner(KEY)
    legacy = LEGACY_QUEUE_CONTRACTS["dispatch_intents_v6"]
    issue_url = "https://github.com/example/project/issues/42"
    intent = signer.seal(
        {
            "version": legacy["intentVersion"],
            "intentId": "legacy-intent-v6",
            "key": "example/project#42",
            "repo": "example/project",
            "issueNumber": 42,
            "issueUrl": issue_url,
            "issueUpdatedAt": "2026-08-04T00:00:00Z",
            "policyDigest": "policy-digest",
            "scannerVersion": legacy["scannerVersion"],
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "promptDigest": sha256_text(canonical_prompt(issue_url)),
            "issuedAt": iso_z(NOW),
            "expiresAt": iso_z(NOW + timedelta(hours=2)),
            "status": "PENDING",
        }
    )
    queue = signer.seal(
        {
            "version": "dispatch_intents_v6",
            "scannerVersion": legacy["scannerVersion"],
            "decisionContractDigest": legacy["decisionContractDigest"],
            "contractDigest": legacy["contractDigest"],
            "intents": [intent],
        }
    )

    assert verify_queue(queue, signer, now=NOW) == [intent]
