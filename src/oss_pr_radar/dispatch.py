"""Signed, expiring cloud-to-local dispatch envelopes."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from .contracts import ACTIONABLE_REVIEW_STATUSES, contract_digest, validate_report
from .opportunity import external_side_effect_allowed
from .policy import SCANNER_DECISION_REVISION, decision_contract_digest
from .util import canonical_json, iso_z, parse_time, sha256_json, sha256_text

QUEUE_VERSION = "dispatch_intents_v7"
INTENT_VERSION = "dispatch_intent_v7"
SUPERSEDED_SCANNER_DECISION_REVISIONS = frozenset(
    {
        "oss_pr_radar_v47_semantic_evidence_only",
        "oss_pr_radar_v48_semantic_evidence_only",
        "oss_pr_radar_v49_payload_bound_evidence_ids",
        "oss_pr_radar_v50_material_contradictions",
        "oss_pr_radar_v51_bounded_wait_evidence",
        "oss_pr_radar_v52_recheck_pr_validation",
    }
)
SUPERSEDED_SCANNER_DECISION_CONTRACTS = {
    "oss_pr_radar_v47_semantic_evidence_only": {
        "intentVersion": INTENT_VERSION,
        "decisionContractDigest": (
            "7a5c2cdcb524e11b2262e10a121fa4be6f3fea3b1685992fce268defd9a51e87"
        ),
        "contractDigest": "a4a72ff173c07ee40bcbb7f0de7aeb3d217b1ef7700aa04f9015806c191b44d9",
    },
    "oss_pr_radar_v48_semantic_evidence_only": {
        "intentVersion": INTENT_VERSION,
        "decisionContractDigest": (
            "15ac0145dc317b96bbc4b7d4d5d0ef171644a06e26e7c2f43a263977fe5a8919"
        ),
        "contractDigest": "a4a72ff173c07ee40bcbb7f0de7aeb3d217b1ef7700aa04f9015806c191b44d9",
    },
    "oss_pr_radar_v49_payload_bound_evidence_ids": {
        "intentVersion": INTENT_VERSION,
        "decisionContractDigest": (
            "63d9b5419e4b58f072055513e60148abadfd4bfc9e8ae799e791a761ff3f56a4"
        ),
        "contractDigest": "a4a72ff173c07ee40bcbb7f0de7aeb3d217b1ef7700aa04f9015806c191b44d9",
    },
    "oss_pr_radar_v50_material_contradictions": {
        "intentVersion": INTENT_VERSION,
        "decisionContractDigest": (
            "22524fef22264e03e24fd139de5a9e4c82a85bebf162081c87ca6ec13aeafa8f"
        ),
        "contractDigest": "a4a72ff173c07ee40bcbb7f0de7aeb3d217b1ef7700aa04f9015806c191b44d9",
    },
    "oss_pr_radar_v51_bounded_wait_evidence": {
        "intentVersion": INTENT_VERSION,
        "decisionContractDigest": (
            "feeb8a88be0effea9330e569fb0f4c62de7e9dbfb0c2729c6a74984dd5ecd6c1"
        ),
        "contractDigest": "0ffabde97bae00693068b61ed03087975ec1c57c989c591a2b43af8aa3ecf505",
    },
    "oss_pr_radar_v52_recheck_pr_validation": {
        "intentVersion": INTENT_VERSION,
        "decisionContractDigest": (
            "bea3254376f7aced8aef5e8a7d060fa881c49ffefdc92fe1a0f5ba16740e04db"
        ),
        "contractDigest": "0ffabde97bae00693068b61ed03087975ec1c57c989c591a2b43af8aa3ecf505",
    },
}
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
    "dispatch_intents_v6": {
        "intentVersion": "dispatch_intent_v6",
        "scannerVersion": "oss_pr_radar_v44_disclosure_tasks_resolve_uncertainty",
        "decisionContractDigest": (
            "3055f8aa2bf39e97c4ac4e981fa468506f59dfa03a5d2f84dfdaf91e2ffed8fc"
        ),
        "contractDigest": ("d203810b30032b5edbfe18113f0805420ab6d1dc77792d3d12c9343355d38fba"),
    },
}
SKILL = "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)"
ISSUE_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
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
        and external_side_effect_allowed(candidate)
        and (candidate.get("gate_decision") == "ALLOW_TO_WORK" or private_disclosure_work)
        and review.get("status") in ACTIONABLE_REVIEW_STATUSES
        and str(review.get("semanticSignal") or review.get("semantic_signal") or "")
        == "NO_OBJECTION"
        and isinstance(candidate.get("preTaskGate") or candidate.get("pre_task_gate"), dict)
        and (candidate.get("preTaskGate") or candidate.get("pre_task_gate")).get("allowed") is True
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
                        and renewed.get("category") != "PR_COMPETITION_OPPORTUNITY"
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
            "submissionPolicy": candidate.get("submission_policy") or "normal",
            "publicSubmissionAllowed": candidate.get("public_submission_allowed") is True,
            "autoSubmitAuthorized": (
                mode in {"canary", "active"}
                and candidate.get("public_submission_allowed") is True
                and candidate.get("category") != "PR_COMPETITION_OPPORTUNITY"
            ),
            "authorizationSource": "signed_live_revalidation_required",
            "publicationMode": mode,
            "llmReview": {
                (
                    "waitReason"
                    if key == "wait_reason"
                    else "semanticSignal"
                    if key == "semanticSignal"
                    else key
                ): (candidate.get("llm_review") or {}).get(key)
                for key in (
                    "status",
                    "decision",
                    "wait_reason",
                    "confidence",
                    "model",
                    "semanticSignal",
                )
            },
            "actionabilityEvidence": candidate.get("actionability_evidence") or {},
            "preTaskEvidence": candidate.get("preTaskEvidence")
            or candidate.get("pre_task_evidence")
            or {},
            "preTaskGate": candidate.get("preTaskGate") or candidate.get("pre_task_gate") or {},
            "defaultBranch": (
                candidate.get("preTaskEvidence") or candidate.get("pre_task_evidence") or {}
            ).get("defaultBranch"),
            "selectedBaseSha": (
                candidate.get("preTaskEvidence") or candidate.get("pre_task_evidence") or {}
            ).get("baseSha"),
            "preTaskEvidenceDigest": (
                candidate.get("preTaskGate") or candidate.get("pre_task_gate") or {}
            ).get("evidenceDigest"),
            "maturity": candidate.get("maturity") or "mature",
            "notify": candidate.get("notify") is not False,
            "probeRequired": True,
            "probeLevel": "PENDING",
            "taskStage": "PREFLIGHT",
            "probeProfile": (
                candidate.get("preTaskEvidence") or candidate.get("pre_task_evidence") or {}
            ).get("probeProfile"),
            "algorithmEvidence": candidate.get("algorithm_evidence"),
            "runId": report.get("run_id") or report.get("now"),
            "sourceSha": source_sha,
            "snapshotId": report.get("snapshot_id") or sha256_json(report),
            "scannerVersion": scanner_version,
            "decisionContractDigest": dispatch_contract_digest,
            "contractDigest": report.get("contract_digest") or contract_digest(),
            "policyDigest": candidate.get("policy_digest") or "",
            "evidenceDigest": candidate.get("evidence_digest")
            or (candidate.get("preTaskGate") or candidate.get("pre_task_gate") or {}).get(
                "evidenceDigest"
            )
            or "",
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
    if queue.get("scannerVersion") != expected["scannerVersion"]:
        raise SignatureError("stale scanner decision revision")
    if queue.get("contractDigest") != expected["contractDigest"]:
        raise SignatureError("stale dispatch contract")
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
        if not external_side_effect_allowed(item):
            raise SignatureError("silent exploration intent cannot be dispatched")
        verified.append(item)
    return verified


def superseded_scanner_revision_queue(
    queue: dict[str, Any], signer: DispatchSigner
) -> dict[str, Any] | None:
    """Authenticate one known-obsolete current-format queue without executing it."""

    if str(queue.get("version") or "") != QUEUE_VERSION:
        return None
    scanner_version = str(queue.get("scannerVersion") or "")
    if scanner_version == SCANNER_DECISION_REVISION:
        return None
    expected = SUPERSEDED_SCANNER_DECISION_CONTRACTS.get(scanner_version)
    if expected is None:
        raise SignatureError("stale scanner decision revision")
    if queue.get("contractDigest") != expected["contractDigest"]:
        raise SignatureError("stale dispatch contract")
    if queue.get("decisionContractDigest") != expected["decisionContractDigest"]:
        raise SignatureError("stale dispatch decision revision")
    signer.verify(queue)
    intents = queue.get("intents")
    if not isinstance(intents, list):
        raise SignatureError("invalid dispatch intents")
    if queue.get("intentCount") != len(intents):
        raise SignatureError("dispatch intent count mismatch")
    intent_count = 0
    for item in intents:
        if not isinstance(item, dict):
            raise SignatureError("invalid dispatch intent")
        signer.verify(item)
        if item.get("version") != expected["intentVersion"]:
            raise SignatureError("unsupported dispatch intent")
        if item.get("scannerVersion") != scanner_version:
            raise SignatureError("stale intent scanner revision")
        if item.get("contractDigest") != expected["contractDigest"]:
            raise SignatureError("stale intent contract")
        if item.get("decisionContractDigest") != expected["decisionContractDigest"]:
            raise SignatureError("stale intent decision revision")
        issue_url = str(item.get("issueUrl") or "")
        match = ISSUE_URL_RE.fullmatch(issue_url)
        if match is None:
            raise SignatureError("dispatch intent issue identity is invalid")
        repo, number = match.groups()
        if item.get("repo") != repo or str(item.get("issueNumber")) != number:
            raise SignatureError("dispatch intent issue identity is invalid")
        if item.get("key") != f"{repo}#{number}":
            raise SignatureError("dispatch intent issue identity is invalid")
        try:
            parse_time(str(item["issueUpdatedAt"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise SignatureError("dispatch intent issue update watermark is invalid") from exc
        if item.get("promptDigest") != sha256_text(canonical_prompt(issue_url)):
            raise SignatureError("prompt digest mismatch")
        if not external_side_effect_allowed(item):
            raise SignatureError("silent exploration intent cannot be dispatched")
        intent_count += 1
    return {
        "status": "superseded_scanner_revision",
        "queueDigest": sha256_json(queue),
        "scannerVersion": scanner_version,
        "decisionContractDigest": expected["decisionContractDigest"],
        "contractDigest": expected["contractDigest"],
        "currentScannerVersion": SCANNER_DECISION_REVISION,
        "intentCount": intent_count,
    }
