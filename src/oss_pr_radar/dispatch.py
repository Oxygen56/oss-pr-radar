"""Signed, expiring cloud-to-local dispatch envelopes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from .contracts import contract_digest, validate_report
from .policy import SCANNER_DECISION_REVISION, decision_contract_digest
from .util import canonical_json, iso_z, parse_time, sha256_json, sha256_text

QUEUE_VERSION = "dispatch_intents_v6"
INTENT_VERSION = "dispatch_intent_v6"
LEGACY_QUEUE_CONTRACTS = {
    "dispatch_intents_v4": {
        "intentVersion": "dispatch_intent_v4",
        "scannerVersion": "oss_pr_radar_v27_ci_neutral_competition",
        "decisionContractDigest": (
            "67d712a249b740b0516d2768493b9a74f0b664fc19bea1d73639db20bc3827b2"
        ),
        "contractDigest": ("bb474c033eab57bb01cd4a6bc377966ba8e80c3fd6ea97c5065d161763301ecc"),
    },
    "dispatch_intents_v5": {
        "intentVersion": "dispatch_intent_v5",
        "scannerVersion": "oss_pr_radar_v31_cross_repo_duplicate_gate",
        "decisionContractDigest": (
            "84e6679669c6896f2aa42250f2e60aac4fd537a02f822eb95c8fc4498acbdb2b"
        ),
        "contractDigest": ("1259820e1344ef496d0aa936ae10c40b939621e8d09ce78e64b07f9f65396238"),
    },
}
SKILL = "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)"
ACTIONABLE_DECISIONS = {"NEW_CLEAN_CANDIDATE", "PR_COMPETITION_OPPORTUNITY"}
MAX_INTENT_AGE_DAYS = 14
NON_REVOKING_REJECTION_REASONS = {
    "seen_recently",
    "issue_fetch_failed",
    "comments_lookup_failed",
    "repo_quality:repo_meta_failed",
    "repo_quality:repo_contents_failed",
}


class SignatureError(ValueError):
    pass


def canonical_prompt(issue_url: str) -> str:
    return f"{SKILL}\n{issue_url}"


def _unsigned(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


class DispatchSigner:
    def __init__(self, key: str | bytes):
        raw = key.encode("utf-8") if isinstance(key, str) else key
        if len(raw) < 32:
            raise ValueError("dispatch signing key must contain at least 32 bytes")
        self._key = raw

    def sign(self, value: dict[str, Any]) -> str:
        return hmac.new(
            self._key,
            canonical_json(_unsigned(value)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def seal(self, value: dict[str, Any]) -> dict[str, Any]:
        sealed = dict(_unsigned(value))
        sealed["signature"] = self.sign(sealed)
        return sealed

    def verify(self, value: dict[str, Any]) -> None:
        supplied = str(value.get("signature") or "")
        if not supplied or not hmac.compare_digest(supplied, self.sign(value)):
            raise SignatureError("dispatch signature mismatch")


def _eligible(candidate: dict[str, Any]) -> bool:
    review = candidate.get("llm_review") or {}
    private_disclosure_work = bool(
        candidate.get("gate_decision") == "ALLOW_PRIVATE_WORK"
        and str(candidate.get("submission_policy") or "").startswith("ai_disclosure")
        and candidate.get("public_submission_allowed") is False
    )
    return bool(
        candidate.get("auto_spawn") is True
        and (candidate.get("gate_decision") == "ALLOW_TO_WORK" or private_disclosure_work)
        and review.get("status") == "ok"
        and review.get("decision") in ACTIONABLE_DECISIONS
    )


def rejection_revokes(outcome: dict[str, Any]) -> bool:
    if outcome.get("status") != "rejected":
        return False
    return str(outcome.get("reason") or "") not in NON_REVOKING_REJECTION_REASONS


def build_queue(
    report: dict[str, Any],
    signer: DispatchSigner,
    *,
    existing: dict[str, Any] | None = None,
    now: datetime | None = None,
    ttl_minutes: int = 120,
    mode: str = "shadow",
    source_sha: str = "",
) -> dict[str, Any]:
    validate_report(report)
    scanner_version = str(report.get("scanner_version") or "")
    if scanner_version != SCANNER_DECISION_REVISION:
        raise ValueError("stale scanner decision revision")
    if mode not in {"shadow", "canary", "active"}:
        raise ValueError("unsupported dispatch mode")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    expires = current + timedelta(minutes=max(5, min(ttl_minutes, 360)))
    dispatch_contract_digest = decision_contract_digest()
    observed = {
        f"{item.get('repo')}#{item.get('num')}"
        for item in report.get("candidate_details") or []
        if isinstance(item, dict)
    }
    observed.update(
        key
        for key, outcome in (report.get("issue_outcomes") or {}).items()
        if isinstance(key, str) and isinstance(outcome, dict) and rejection_revokes(outcome)
    )
    retained: dict[str, dict[str, Any]] = {}
    if isinstance(existing, dict) and existing.get("version") == QUEUE_VERSION:
        try:
            signer.verify(existing)
            for item in existing.get("intents") or []:
                if not isinstance(item, dict):
                    continue
                signer.verify(item)
                if (
                    item.get("key") not in observed
                    and item.get("scannerVersion") == scanner_version
                    and item.get("decisionContractDigest") == dispatch_contract_digest
                    and parse_time(str(item["issuedAt"]))
                    > current - timedelta(days=MAX_INTENT_AGE_DAYS)
                    and item.get("status") == "PENDING"
                ):
                    renewed = dict(item)
                    renewed["expiresAt"] = iso_z(expires)
                    renewed["renewedAt"] = iso_z(current)
                    renewed["mode"] = mode
                    renewed["publicationMode"] = mode
                    renewed["autoSubmitAuthorized"] = bool(
                        mode in {"canary", "active"}
                        and renewed.get("publicSubmissionAllowed") is True
                    )
                    retained[str(item["key"])] = signer.seal(renewed)
        except (SignatureError, KeyError, TypeError, ValueError):
            retained = {}

    new_count = 0
    for candidate in report.get("candidate_details") or []:
        key = f"{candidate['repo']}#{candidate['num']}"
        if not _eligible(candidate):
            retained.pop(key, None)
            continue
        issue_url = str(candidate["url"])
        decision_basis = {
            "key": key,
            "issueUpdatedAt": candidate.get("issue_updated"),
            "track": candidate.get("track"),
            "category": candidate.get("category"),
            "gateDecision": candidate.get("gate_decision"),
            "evidenceDigest": candidate.get("evidence_digest")
            or candidate.get("notification_digest")
            or "",
            "policyDigest": candidate.get("policy_digest")
            or report.get("contract_digest")
            or contract_digest(),
            "llmReview": candidate.get("llm_review"),
            "algorithmEvidence": candidate.get("algorithm_evidence"),
        }
        candidate_decision_digest = sha256_json(decision_basis)
        intent_id = sha256_text(
            f"{key}|{report.get('snapshot_id') or report.get('now')}|{candidate_decision_digest}"
        )
        item = {
            "version": INTENT_VERSION,
            "intentId": intent_id,
            "key": key,
            "repo": candidate["repo"],
            "issueNumber": candidate["num"],
            "issueUrl": issue_url,
            "issueUpdatedAt": candidate["issue_updated"],
            "title": candidate["title"],
            "track": candidate.get("track"),
            "category": candidate["category"],
            "score": candidate.get("score"),
            "scanGate": candidate.get("gate_decision"),
            "autoSpawn": candidate.get("auto_spawn") is True,
            "publicSubmissionAllowed": candidate.get("public_submission_allowed") is True,
            "autoSubmitAuthorized": (
                mode in {"canary", "active"} and candidate.get("public_submission_allowed") is True
            ),
            "authorizationSource": "signed_live_revalidation_required",
            "publicationMode": mode,
            "llmReview": {
                key: (candidate.get("llm_review") or {}).get(key)
                for key in ("status", "decision", "confidence", "model")
            },
            "actionabilityEvidence": candidate.get("actionability_evidence") or {},
            "algorithmEvidence": candidate.get("algorithm_evidence"),
            "runId": report.get("run_id") or report.get("now"),
            "sourceSha": source_sha,
            "snapshotId": report.get("snapshot_id") or sha256_json(report),
            "scannerVersion": scanner_version,
            "decisionContractDigest": dispatch_contract_digest,
            "contractDigest": report.get("contract_digest") or contract_digest(),
            "policyDigest": candidate.get("policy_digest") or "",
            "evidenceDigest": candidate.get("evidence_digest") or "",
            "decisionDigest": candidate_decision_digest,
            "promptDigest": sha256_text(canonical_prompt(issue_url)),
            "issuedAt": iso_z(current),
            "expiresAt": iso_z(expires),
            "nonce": secrets.token_hex(16),
            "mode": mode,
            "status": "PENDING",
        }
        retained[key] = signer.seal(item)
        new_count += 1

    queue = {
        "version": QUEUE_VERSION,
        "generatedAt": iso_z(current),
        "runId": report.get("run_id") or report.get("now"),
        "sourceSha": source_sha,
        "scannerVersion": scanner_version,
        "decisionContractDigest": dispatch_contract_digest,
        "contractDigest": report.get("contract_digest") or contract_digest(),
        "mode": mode,
        "intentCount": len(retained),
        "newIntentCount": new_count,
        "intents": sorted(retained.values(), key=lambda item: item["key"]),
    }
    return signer.seal(queue)


def verify_queue(
    queue: dict[str, Any], signer: DispatchSigner, *, now: datetime | None = None
) -> list[dict[str, Any]]:
    version = str(queue.get("version") or "")
    if version == QUEUE_VERSION:
        expected = {
            "intentVersion": INTENT_VERSION,
            "scannerVersion": SCANNER_DECISION_REVISION,
            "decisionContractDigest": decision_contract_digest(),
            "contractDigest": contract_digest(),
        }
    else:
        expected = LEGACY_QUEUE_CONTRACTS.get(version)
    if expected is None:
        raise SignatureError("unsupported dispatch queue")
    if queue.get("contractDigest") != expected["contractDigest"]:
        raise SignatureError("stale dispatch contract")
    if queue.get("scannerVersion") != expected["scannerVersion"]:
        raise SignatureError("stale scanner decision revision")
    if queue.get("decisionContractDigest") != expected["decisionContractDigest"]:
        raise SignatureError("stale dispatch decision revision")
    signer.verify(queue)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    verified: list[dict[str, Any]] = []
    for item in queue.get("intents") or []:
        if not isinstance(item, dict):
            raise SignatureError("invalid dispatch intent")
        signer.verify(item)
        if item.get("version") != expected["intentVersion"]:
            raise SignatureError("unsupported dispatch intent")
        if version == QUEUE_VERSION:
            try:
                parse_time(str(item["issueUpdatedAt"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise SignatureError("dispatch intent issue update watermark is invalid") from exc
            if not item.get("policyDigest"):
                raise SignatureError("dispatch intent policy watermark is invalid")
        if item.get("scannerVersion") != expected["scannerVersion"]:
            raise SignatureError("stale intent scanner revision")
        if item.get("decisionContractDigest") != expected["decisionContractDigest"]:
            raise SignatureError("stale intent decision revision")
        if parse_time(str(item["expiresAt"])) <= current:
            continue
        if item.get("promptDigest") != sha256_text(canonical_prompt(str(item["issueUrl"]))):
            raise SignatureError("prompt digest mismatch")
        verified.append(item)
    return verified
