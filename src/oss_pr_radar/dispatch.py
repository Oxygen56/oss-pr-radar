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

QUEUE_VERSION = "dispatch_intents_v4"
INTENT_VERSION = "dispatch_intent_v4"
SKILL = "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)"
ACTIONABLE_DECISIONS = {"NEW_CLEAN_CANDIDATE", "PR_COMPETITION_OPPORTUNITY"}


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
    return bool(
        candidate.get("auto_spawn") is True
        and candidate.get("gate_decision") == "ALLOW_TO_WORK"
        and review.get("status") == "ok"
        and review.get("decision") in ACTIONABLE_DECISIONS
    )


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
        if isinstance(key, str)
        and isinstance(outcome, dict)
        and outcome.get("status") in {"candidate", "rejected"}
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
                    and parse_time(str(item["expiresAt"])) > current
                    and item.get("status") == "PENDING"
                ):
                    retained[str(item["key"])] = item
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
            "category": candidate.get("category"),
            "gateDecision": candidate.get("gate_decision"),
            "evidenceDigest": candidate.get("evidence_digest")
            or candidate.get("notification_digest")
            or "",
            "policyDigest": candidate.get("policy_digest")
            or report.get("contract_digest")
            or contract_digest(),
            "llmReview": candidate.get("llm_review"),
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
            "title": candidate["title"],
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
    if queue.get("version") != QUEUE_VERSION:
        raise SignatureError("unsupported dispatch queue")
    if queue.get("contractDigest") != contract_digest():
        raise SignatureError("stale dispatch contract")
    if queue.get("scannerVersion") != SCANNER_DECISION_REVISION:
        raise SignatureError("stale scanner decision revision")
    if queue.get("decisionContractDigest") != decision_contract_digest():
        raise SignatureError("stale dispatch decision revision")
    signer.verify(queue)
    current = (now or datetime.now(UTC)).astimezone(UTC)
    verified: list[dict[str, Any]] = []
    for item in queue.get("intents") or []:
        if not isinstance(item, dict):
            raise SignatureError("invalid dispatch intent")
        signer.verify(item)
        if item.get("version") != INTENT_VERSION:
            raise SignatureError("unsupported dispatch intent")
        if item.get("scannerVersion") != SCANNER_DECISION_REVISION:
            raise SignatureError("stale intent scanner revision")
        if item.get("decisionContractDigest") != decision_contract_digest():
            raise SignatureError("stale intent decision revision")
        if parse_time(str(item["expiresAt"])) <= current:
            continue
        if item.get("promptDigest") != sha256_text(canonical_prompt(str(item["issueUrl"]))):
            raise SignatureError("prompt digest mismatch")
        verified.append(item)
    return verified
