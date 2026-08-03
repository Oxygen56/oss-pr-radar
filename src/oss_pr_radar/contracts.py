"""Versioned report and decision contracts for every trust boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .util import sha256_json

SCAN_SCHEMA = "oss-pr-radar.scan.v2"
CANDIDATE_SCHEMA = "oss-pr-radar.candidate.v2"
EVIDENCE_SCHEMA = "oss-pr-radar.evidence.v1"
CONTRACT_REVISION = "trust-core-v3-full-publication-payload"

CONTRACT_MANIFEST = {
    "scanSchema": SCAN_SCHEMA,
    "candidateSchema": CANDIDATE_SCHEMA,
    "evidenceSchema": EVIDENCE_SCHEMA,
    "revision": CONTRACT_REVISION,
    "llmPositiveAuthorization": False,
    "requiredEvidence": [
        "issue",
        "comments",
        "timeline",
        "repositoryPolicy",
        "relatedPullRequests",
    ],
    "dispatchLiveChecks": [
        "issueState",
        "ownership",
        "duplicate",
        "design",
        "policy",
        "hardware",
    ],
    "publicationPermitBinding": [
        "issueUrl",
        "threadId",
        "commitSha",
        "branch",
        "worktreePath",
        "evidenceDigest",
        "headOwner",
        "baseBranch",
        "prTitle",
        "prBodyDigest",
    ],
    "publicationSideEffectsAreIdempotent": True,
}


class ContractError(ValueError):
    pass


def contract_digest() -> str:
    return sha256_json(CONTRACT_MANIFEST)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate_candidate(candidate: dict[str, Any]) -> None:
    _require(isinstance(candidate, dict), "candidate must be an object")
    for key in ("repo", "num", "url", "title", "category", "gate_decision"):
        _require(candidate.get(key) not in (None, ""), f"candidate.{key} is required")
    _require(isinstance(candidate["num"], int), "candidate.num must be an integer")
    _require(
        str(candidate["url"]).startswith("https://github.com/"),
        "candidate.url must be a GitHub URL",
    )
    _require(isinstance(candidate.get("auto_spawn"), bool), "candidate.auto_spawn must be boolean")
    review = candidate.get("llm_review")
    _require(isinstance(review, dict), "candidate.llm_review is required")
    if candidate["auto_spawn"]:
        _require(candidate["gate_decision"] == "ALLOW_TO_WORK", "auto spawn requires ALLOW_TO_WORK")
        _require(review.get("status") == "ok", "auto spawn requires successful LLM review")
        _require(
            review.get("decision") in {"NEW_CLEAN_CANDIDATE", "PR_COMPETITION_OPPORTUNITY"},
            "auto spawn requires an actionable LLM decision",
        )


@dataclass(frozen=True)
class ReportValidation:
    candidate_count: int
    auto_dispatch_count: int
    digest: str


def validate_report(report: dict[str, Any], *, require_v2: bool = False) -> ReportValidation:
    _require(isinstance(report, dict), "report must be an object")
    _require(report.get("scan_ok") is True, f"scan failed: {report.get('scan_error')}")
    if require_v2:
        _require(report.get("schema_version") == SCAN_SCHEMA, "unsupported scan schema")
        _require(report.get("contract_digest") == contract_digest(), "stale decision contract")
        _require(bool(report.get("run_id")), "run_id is required")
        _require(bool(report.get("snapshot_id")), "snapshot_id is required")
    details = report.get("candidate_details")
    _require(isinstance(details, list), "candidate_details must be a list")
    for candidate in details:
        _require("_llm_context" not in candidate, "untrusted LLM context leaked into report")
        validate_candidate(candidate)
    digestable = {key: value for key, value in report.items() if key != "report_digest"}
    digest = sha256_json(digestable)
    if report.get("report_digest"):
        _require(report["report_digest"] == digest, "report digest mismatch")
    return ReportValidation(
        candidate_count=len(details),
        auto_dispatch_count=sum(bool(item.get("auto_spawn")) for item in details),
        digest=digest,
    )
