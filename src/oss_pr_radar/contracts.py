"""Versioned report and decision contracts for every trust boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .util import sha256_json

SCAN_SCHEMA = "oss-pr-radar.scan.v2"
CANDIDATE_SCHEMA = "oss-pr-radar.candidate.v3"
EVIDENCE_SCHEMA = "oss-pr-radar.evidence.v1"
CONTRACT_REVISION = "trust-core-v6-external-state-watermark"

CONTRACT_MANIFEST = {
    "scanSchema": SCAN_SCHEMA,
    "candidateSchema": CANDIDATE_SCHEMA,
    "evidenceSchema": EVIDENCE_SCHEMA,
    "revision": CONTRACT_REVISION,
    "llmPositiveAuthorization": False,
    "tracks": ["agent_ai_infra", "llm_algorithm"],
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
    for key in (
        "repo",
        "num",
        "url",
        "title",
        "issue_updated",
        "policy_digest",
        "category",
        "gate_decision",
    ):
        _require(candidate.get(key) not in (None, ""), f"candidate.{key} is required")
    _require(isinstance(candidate["num"], int), "candidate.num must be an integer")
    _require(
        str(candidate["url"]).startswith("https://github.com/"),
        "candidate.url must be a GitHub URL",
    )
    _require(isinstance(candidate.get("auto_spawn"), bool), "candidate.auto_spawn must be boolean")
    track = str(candidate.get("track") or "")
    _require(track in {"agent_ai_infra", "llm_algorithm"}, "candidate.track is invalid")
    if track == "llm_algorithm":
        algorithm = candidate.get("algorithm_evidence")
        _require(isinstance(algorithm, dict), "algorithm candidate requires algorithm_evidence")
        _require(algorithm.get("qualified") is True, "algorithm evidence must be qualified")
        _require(
            int(algorithm.get("score") or 0) >= 7,
            "algorithm evidence score is below threshold",
        )
        _require(
            int(algorithm.get("mechanism_count") or 0) >= 1,
            "algorithm candidate requires a concrete mechanism",
        )
        _require(
            algorithm.get("operational_only") is False,
            "operational-only work cannot enter the algorithm track",
        )
    review = candidate.get("llm_review")
    _require(isinstance(review, dict), "candidate.llm_review is required")
    if candidate["auto_spawn"]:
        private_disclosure_work = bool(
            candidate.get("gate_decision") == "ALLOW_PRIVATE_WORK"
            and str(candidate.get("submission_policy") or "").startswith("ai_disclosure")
            and candidate.get("public_submission_allowed") is False
        )
        _require(
            candidate["gate_decision"] == "ALLOW_TO_WORK" or private_disclosure_work,
            "auto spawn requires authorized work",
        )
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
        _require(
            report.get("tracks") == ["agent_ai_infra", "llm_algorithm"],
            "scan tracks are incomplete",
        )
        timings = report.get("timings_seconds")
        _require(isinstance(timings, dict), "timings_seconds is required")
        _require(
            all(isinstance(timings.get(key), (int, float)) for key in ("collect", "total")),
            "timings_seconds.collect and total must be numeric",
        )
        activity = report.get("repository_activity")
        _require(isinstance(activity, dict), "repository_activity is required")
        for key in ("fixed_scope", "queried", "matched", "qualified", "inspected"):
            _require(isinstance(activity.get(key), list), f"repository_activity.{key} is required")
        _require(
            isinstance(activity.get("collection_failures"), dict),
            "repository_activity.collection_failures is required",
        )
        rechecks = report.get("deferred_rechecks")
        _require(isinstance(rechecks, dict), "deferred_rechecks is required")
        _require(
            rechecks.get("cooldown_enabled") is False,
            "deferred recheck cooldown must remain disabled",
        )
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
