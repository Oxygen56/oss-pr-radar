"""Compatibility adapter from the existing Radar control plane to Managed Ledger."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .dispatch import DispatchSigner, rejection_revokes, verify_queue
from .github_client import GitHubClient
from .managed_lifecycle import (
    ManagedLedger,
    PublicationAbsenceReconciler,
    export_projection,
    migrate_schema,
    parse_issue_reference,
    pr_key_from_url,
)
from .opportunity import (
    classify_scan_outcome,
    external_side_effect_allowed,
    validate_result_classification,
)
from .release_binding import runtime_ledger_path
from .repo_probe import REPRODUCED_VALIDATED, thread_fingerprint, verify_probe_receipt
from .util import canonical_json, sha256_json

NOTIFICATION_CHANNELS = ("feishu", "codex")
NOTIFICATION_DELIVERY_STATUSES = {"PENDING", "SENT", "FAILED", "RECONCILE_REQUIRED"}
PUBLISHED_RESULT_STAGES = {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}


def _published_result_matches_worktree(
    *, candidate: dict[str, Any], value: dict[str, Any], head_sha: str
) -> bool:
    candidate_path = str(candidate.get("worktreePath") or "")
    value_path = str(value.get("worktreePath") or "")
    if not candidate_path or value_path != candidate_path:
        return False
    worktree = Path(candidate_path)
    try:
        path_stat = worktree.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        return False
    try:
        current_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=worktree,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        status_output = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=worktree,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return current_head == head_sha and not status_output


def _notification_status_by_channel(metadata: dict[str, Any]) -> dict[str, str]:
    """Read channel delivery state, treating the legacy scalar as Feishu-only."""

    raw = metadata.get("notificationStatusByChannel")
    raw = raw if isinstance(raw, dict) else {}
    legacy_feishu = str(metadata.get("notificationStatus") or "PENDING")
    statuses: dict[str, str] = {}
    for channel in NOTIFICATION_CHANNELS:
        status = str(raw.get(channel) or "")
        if status not in NOTIFICATION_DELIVERY_STATUSES:
            status = legacy_feishu if channel == "feishu" else "PENDING"
        if status not in NOTIFICATION_DELIVERY_STATUSES:
            status = "PENDING"
        statuses[channel] = status
    return statuses


class GitHubAbsenceQueries:
    """Exact, read-only GitHub queries used by the slow publication reconciler."""

    def __init__(self, client: GitHubClient | None = None):
        self.client = client or GitHubClient()

    def query_branch(self, repo: str, head_ref: str) -> dict[str, Any]:
        self.client.branch(repo, head_ref)
        return {"exists": True}

    def query_commit(self, repo: str, head_sha: str) -> dict[str, Any]:
        value = self.client.api(f"repos/{repo}/git/commits/{head_sha}")
        if not isinstance(value, dict) or str(value.get("sha") or "") != head_sha:
            raise RuntimeError("GitHub commit response is not bound to requested SHA")
        return {"exists": True}

    def query_pull_request(self, repo: str, head_ref: str, head_sha: str) -> dict[str, Any]:
        owner = repo.split("/", 1)[0]
        value = self.client.api(
            f"repos/{repo}/pulls",
            params={"state": "all", "head": f"{owner}:{head_ref}", "per_page": 100},
        )
        if not isinstance(value, list):
            raise RuntimeError("GitHub pull request response is uncertain")
        matching = [
            item
            for item in value
            if isinstance(item, dict) and item.get("head", {}).get("sha") == head_sha
        ]
        return {"exists": bool(matching), "result": len(matching)}


def default_managed_path(root: Path) -> Path:
    return runtime_ledger_path(root)


def _issue_parts(value: str) -> tuple[str, str, int, str]:
    identity = parse_issue_reference(value)
    return identity["owner"], identity["repo"], identity["issueNumber"], identity["issueUrl"]


def _stage_result_type(stage: str, value: dict[str, Any]) -> str | None:
    explicit = value.get("resultType") or value.get("result_type")
    if explicit:
        return str(explicit)
    if stage == "AUDIT_NO_GO":
        return "task_no_go"
    if str(value.get("blockedReason") or value.get("reason") or "").startswith("BLOCKED"):
        return "blocked_pre_task"
    return None


def _scan_outcome_result_type(outcome: dict[str, Any]) -> str:
    explicit = outcome.get("classification")
    if explicit:
        try:
            return validate_result_classification(str(explicit))
        except ValueError:
            pass
    status = str(outcome.get("status") or "").casefold()
    reason = str(outcome.get("reason") or "").casefold()
    return classify_scan_outcome(status, reason)


def _user_decision_metadata(candidate: dict[str, Any], preflight: dict[str, Any]) -> dict[str, Any]:
    """Return the narrowly authenticated no-task notification state."""

    review = candidate.get("llm_review") or {}
    notification_digest = str(candidate.get("notification_digest") or "")
    review_required = bool(
        candidate.get("category") == "WAIT_MAINTAINER"
        and candidate.get("gate_decision") == "HUMAN_REVIEW"
        and candidate.get("auto_spawn") is False
        and external_side_effect_allowed(candidate)
        and preflight.get("allowed") is True
        and review.get("status") == "ok"
        and review.get("semanticSignal") == "NO_OBJECTION"
        and re.fullmatch(r"[0-9a-f]{64}", notification_digest)
    )
    return {
        "reviewRequired": review_required,
        "gateDecision": "HUMAN_REVIEW" if review_required else "",
        "notificationDigest": notification_digest if review_required else "",
    }


@dataclass
class ManagedAdapter:
    root: Path
    path: Path | None = None

    def __post_init__(self) -> None:
        self.root = self.root.resolve()
        self.path = (self.path or default_managed_path(self.root)).resolve()

    @property
    def ledger(self) -> ManagedLedger:
        return ManagedLedger(self.path, ensure_schema=True)

    def ensure(self) -> dict[str, Any]:
        return migrate_schema(self.path)

    def record_scan_report(self, report: dict[str, Any]) -> dict[str, Any]:
        ledger = self.ledger
        recorded = 0
        candidate_keys: set[str] = set()
        for candidate in report.get("candidate_details") or []:
            if not isinstance(candidate, dict):
                continue
            repo = str(candidate.get("repo") or "")
            number = int(candidate.get("num") or 0)
            issue_url = str(candidate.get("url") or f"https://github.com/{repo}/issues/{number}")
            if not repo or not number:
                continue
            owner, name = repo.split("/", 1)
            key = f"{repo}#{number}"
            candidate_keys.add(key)
            preflight = candidate.get("preTaskGate") or candidate.get("pre_task_gate")
            preflight = preflight if isinstance(preflight, dict) else {}
            decision_metadata = _user_decision_metadata(candidate, preflight)
            existing_metadata: dict[str, Any] = {}
            with ledger._connection() as connection:
                existing = connection.execute(
                    "SELECT metadata_json FROM managed_opportunities WHERE opportunity_key=?",
                    (key,),
                ).fetchone()
            if existing is not None:
                try:
                    parsed = json.loads(existing["metadata_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    parsed = {}
                if isinstance(parsed, dict):
                    existing_metadata = parsed
            notification_status_by_channel = {
                channel: "PENDING" for channel in NOTIFICATION_CHANNELS
            }
            if (
                decision_metadata["reviewRequired"]
                and existing_metadata.get("reviewRequired") is True
                and existing_metadata.get("notificationDigest")
                == decision_metadata["notificationDigest"]
            ):
                notification_status_by_channel = _notification_status_by_channel(existing_metadata)
            notification_status = notification_status_by_channel["feishu"]
            classification = preflight.get("classification")
            opportunity_state = (
                "DECISION_REQUIRED"
                if candidate.get("auto_spawn") or decision_metadata["reviewRequired"]
                else "SYSTEM_PROCESSING"
            )
            if classification == "blocked_pre_task":
                opportunity_state = "WAITING_EXTERNAL"
            elif classification in {"task_no_go", "scan_false_positive", "state_drift"}:
                opportunity_state = "DECISION_REQUIRED"
            ledger.upsert_opportunity(
                opportunity_key=key,
                owner=owner,
                repo=name,
                issue_number=number,
                issue_url=issue_url,
                state=opportunity_state,
                source="scanner",
                provenance={
                    "runId": report.get("run_id"),
                    "scannerVersion": report.get("scanner_version"),
                    "reportDigest": report.get("report_digest") or sha256_json(report),
                },
                observed_at=str(report.get("now") or "") or None,
                metadata={
                    "candidateDigest": candidate.get("evidence_digest"),
                    "title": candidate.get("title"),
                    "preTaskEvidence": candidate.get("preTaskEvidence")
                    or candidate.get("pre_task_evidence")
                    or {},
                    "preTaskGate": preflight,
                    "ranking": candidate.get("ranking") or {},
                    "maturity": candidate.get("maturity") or "mature",
                    "capacityDisposition": candidate.get("capacityDisposition"),
                    **decision_metadata,
                    "notificationStatus": notification_status,
                    "notificationStatusByChannel": notification_status_by_channel,
                    "notified": bool(
                        decision_metadata["reviewRequired"] and notification_status == "SENT"
                    ),
                },
            )
            if isinstance(preflight, dict) and preflight.get("allowed") is not True:
                classification = preflight.get("classification") or classify_scan_outcome(
                    "rejected", str(preflight.get("reason") or "")
                )
                ledger.record_event(
                    event_type="PRE_TASK_GATE_BLOCKED",
                    idempotency_key=f"pre-task:{report.get('run_id') or report.get('now')}:{key}",
                    opportunity_key=key,
                    state=classification,
                    source="scanner",
                    provenance={"evidenceDigest": preflight.get("evidenceDigest")},
                    observed_at=str(report.get("now") or "") or None,
                    payload={
                        "classification": classification,
                        "reason": preflight.get("reason"),
                        "reasons": preflight.get("reasons") or [],
                    },
                )
            ledger.record_event(
                event_type="OPPORTUNITY_SCANNED",
                idempotency_key=f"scan:{report.get('run_id') or report.get('now')}:{key}",
                opportunity_key=key,
                source="scanner",
                provenance={"reportDigest": report.get("report_digest")},
                observed_at=str(report.get("now") or "") or None,
                payload={
                    "autoSpawn": candidate.get("auto_spawn"),
                    "score": candidate.get("score"),
                    "ranking": candidate.get("ranking") or {},
                    "preTaskGate": candidate.get("preTaskGate")
                    or candidate.get("pre_task_gate")
                    or {},
                    "maturity": candidate.get("maturity") or "mature",
                    "capacityDisposition": candidate.get("capacityDisposition"),
                    **decision_metadata,
                },
            )
            if (
                candidate.get("auto_spawn") is True
                and (candidate.get("preTaskGate") or candidate.get("pre_task_gate") or {}).get(
                    "allowed"
                )
                is True
            ):
                ledger.record_event(
                    event_type="OPPORTUNITY_SELECTED",
                    idempotency_key=f"select:{report.get('run_id') or report.get('now')}:{key}",
                    opportunity_key=key,
                    state="DECISION_REQUIRED",
                    source="scanner",
                    provenance={"rankingDigest": sha256_json(candidate.get("ranking") or {})},
                    observed_at=str(report.get("now") or "") or None,
                    payload={"maturity": candidate.get("maturity") or "mature"},
                )
            recorded += 1
        outcomes_recorded = 0
        for key, outcome in (report.get("issue_outcomes") or {}).items():
            if key in candidate_keys or not isinstance(outcome, dict):
                continue
            status = str(outcome.get("status") or "").casefold()
            if status not in {
                "rejected",
                "deferred",
                "status_update",
                "lookup_failed",
                "inspection_budget_deferred",
            }:
                continue
            owner_repo, number_text = str(key).rsplit("#", 1)
            owner, repo = owner_repo.split("/", 1)
            number = int(number_text)
            opportunity_key = f"{owner}/{repo}#{number}"
            task_id = f"scan:{opportunity_key}"
            result_digest = sha256_json({"opportunity": opportunity_key, "outcome": outcome})
            result_type = _scan_outcome_result_type(outcome)
            with ledger._connection() as connection:
                existing = connection.execute(
                    "SELECT state FROM managed_opportunities WHERE opportunity_key=?",
                    (opportunity_key,),
                ).fetchone()
            if existing is not None and not rejection_revokes(outcome):
                ledger.record_event(
                    event_type="SCAN_OUTCOME_DEFERRED_EXISTING_STATE",
                    idempotency_key=(
                        f"defer-existing:{report.get('run_id') or report.get('now')}:"
                        f"{opportunity_key}"
                    ),
                    opportunity_key=opportunity_key,
                    state=str(existing["state"] or ""),
                    source="scanner",
                    provenance={"outcomeDigest": result_digest},
                    observed_at=str(report.get("now") or "") or None,
                    payload={"outcome": outcome},
                )
                outcomes_recorded += 1
                continue
            ledger.upsert_opportunity(
                opportunity_key=opportunity_key,
                owner=owner,
                repo=repo,
                issue_number=number,
                issue_url=f"https://github.com/{owner_repo}/issues/{number}",
                state="WAITING_EXTERNAL" if result_type == "blocked_pre_task" else "SUPERSEDED",
                source="scanner",
                provenance={"runId": report.get("run_id"), "outcomeDigest": result_digest},
                observed_at=str(report.get("now") or "") or None,
            )
            ledger.bind_task(
                task_id=task_id,
                opportunity_key=opportunity_key,
                thread_id=None,
                worktree_path=None,
                source="scanner",
                provenance={"outcomeDigest": result_digest},
                observed_at=str(report.get("now") or "") or None,
            )
            ledger.record_result(
                task_id=task_id,
                result_digest=result_digest,
                worker_state="blocked" if result_type == "blocked_pre_task" else "skipped",
                result_type=result_type,
                waiting_external=result_type == "blocked_pre_task",
                source="scanner",
                provenance={"outcome": outcome},
                observed_at=str(report.get("now") or "") or None,
            )
            outcomes_recorded += 1
        return {"ok": True, "recorded": recorded, "outcomesRecorded": outcomes_recorded}

    def record_user_decision_delivery(
        self,
        *,
        candidate_key: str,
        notification_digest: str,
        channel: str,
        status: str,
        receipt_id: str,
        source_artifact_digest: str,
        reconciliation_required: bool = False,
        message_id: str = "",
        error: str = "",
    ) -> dict[str, Any]:
        """Apply an authenticated USER_DECISION delivery without creating a task."""

        if channel not in NOTIFICATION_CHANNELS:
            raise ValueError("unsupported user decision delivery channel")
        if status not in {"SENT", "FAILED"}:
            raise ValueError("unsupported user decision delivery status")
        if not re.fullmatch(r"[0-9a-f]{64}", notification_digest):
            raise ValueError("user decision notification digest is invalid")
        if not receipt_id or not source_artifact_digest:
            raise ValueError("user decision delivery binding is missing")
        ledger = self.ledger
        connection = ledger._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT metadata_json FROM managed_opportunities WHERE opportunity_key=?",
                (candidate_key,),
            ).fetchone()
            if row is None:
                raise ValueError("user decision opportunity is missing")
            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("user decision opportunity metadata is invalid") from exc
            if not isinstance(metadata, dict) or not all(
                (
                    metadata.get("reviewRequired") is True,
                    metadata.get("gateDecision") == "HUMAN_REVIEW",
                    metadata.get("notificationDigest") == notification_digest,
                )
            ):
                raise ValueError("user decision delivery does not match the managed opportunity")
            notification_status_by_channel = _notification_status_by_channel(metadata)
            prior_status = notification_status_by_channel[channel]
            next_status = (
                "SENT"
                if status == "SENT"
                else "RECONCILE_REQUIRED"
                if reconciliation_required
                else "FAILED"
            )
            if prior_status == "SENT" and next_status != "SENT":
                raise ValueError("sent user decision delivery cannot be downgraded")
            notification_status_by_channel[channel] = next_status
            feishu_status = notification_status_by_channel["feishu"]
            metadata.update(
                {
                    "notificationStatus": feishu_status,
                    "notificationStatusByChannel": notification_status_by_channel,
                    "notified": feishu_status == "SENT",
                }
            )
            if channel == "feishu":
                metadata["deliveryReceiptId"] = receipt_id
            connection.execute(
                "UPDATE managed_opportunities SET metadata_json=? WHERE opportunity_key=?",
                (canonical_json(metadata), candidate_key),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        event = ledger.record_event(
            event_type=(
                "USER_DECISION_NOTIFICATION_SENT"
                if next_status == "SENT"
                else "USER_DECISION_NOTIFICATION_RECONCILE_REQUIRED"
                if next_status == "RECONCILE_REQUIRED"
                else "USER_DECISION_NOTIFICATION_FAILED"
            ),
            idempotency_key=f"user-decision-delivery:{receipt_id}",
            opportunity_key=candidate_key,
            state=next_status,
            source="war_room",
            provenance={
                "channel": channel,
                "sourceArtifactDigest": source_artifact_digest,
            },
            payload={
                "channel": channel,
                "notificationDigest": notification_digest,
                "messageId": message_id if next_status == "SENT" else "",
                "error": error if next_status != "SENT" else "",
            },
        )
        return {"ok": True, "status": next_status, "eventCreated": event["created"]}

    def record_dispatch_queue(self, queue: dict[str, Any]) -> dict[str, Any]:
        ledger = self.ledger
        dispatch_key = os.environ.get("RADAR_DISPATCH_HMAC_KEY")
        queue_verified = False
        if dispatch_key and queue.get("version") and queue.get("signature"):
            verify_queue(queue, DispatchSigner(dispatch_key))
            queue_verified = True
        recorded = 0
        pending_preflight = 0
        for intent in queue.get("intents") or []:
            if not isinstance(intent, dict):
                continue
            key = str(intent.get("key") or "")
            if not key:
                continue
            if not external_side_effect_allowed(intent):
                raise PermissionError("silent exploration intent cannot enter dispatch")
            owner, repo, number, issue_url = _issue_parts(key)
            opportunity_key = f"{owner}/{repo}#{number}"
            ledger.upsert_opportunity(
                opportunity_key=opportunity_key,
                owner=owner,
                repo=repo,
                issue_number=number,
                issue_url=str(intent.get("issueUrl") or issue_url),
                state="PENDING_PREFLIGHT",
                source="dispatch",
                provenance={"queueDigest": sha256_json(queue), "intentId": intent.get("intentId")},
                observed_at=str(intent.get("issuedAt") or "") or None,
                metadata={
                    "decisionDigest": intent.get("decisionDigest"),
                    "preTaskGate": intent.get("preTaskGate") or {},
                    "preTaskEvidence": intent.get("preTaskEvidence") or {},
                },
            )
            if intent.get("autoSpawn") is True:
                gate = ledger.task_creation_gate(
                    repo=f"{owner}/{repo}",
                    invitation_event_key=intent.get("invitationEventKey"),
                    opportunity_key=opportunity_key,
                    pre_task_gate=intent.get("preTaskGate"),
                )
                if not gate["allowed"]:
                    raise PermissionError("managed task creation PR cap reached")
                try:
                    if not queue_verified:
                        raise PermissionError("dispatch queue authentication key is unavailable")
                    ledger.authorize_task_creation(
                        task_id=str(intent.get("intentId") or opportunity_key),
                        opportunity_key=opportunity_key,
                        repo=f"{owner}/{repo}",
                        issue_url=str(intent.get("issueUrl") or issue_url),
                        intent_id=str(intent.get("intentId") or opportunity_key),
                    )
                except PermissionError:
                    # Queue import remains compatible, but no current-key evidence
                    # means a later projection must remain non-actionable.
                    pass
            ledger.record_event(
                event_type="DISPATCH_INTENT_IMPORTED",
                idempotency_key=f"dispatch:{intent.get('intentId') or opportunity_key}:{intent.get('decisionDigest') or ''}",
                opportunity_key=opportunity_key,
                state="PENDING_PREFLIGHT",
                source="dispatch",
                provenance={"queueDigest": sha256_json(queue)},
                observed_at=str(intent.get("issuedAt") or "") or None,
                payload={
                    "status": "PENDING_PREFLIGHT",
                    "intentId": intent.get("intentId"),
                    "mode": queue.get("mode"),
                    "defaultBranch": intent.get("defaultBranch"),
                    "selectedBaseSha": intent.get("selectedBaseSha"),
                    "evidenceDigest": intent.get("preTaskEvidenceDigest")
                    or intent.get("evidenceDigest"),
                },
            )
            recorded += 1
            pending_preflight += 1
        return {"ok": True, "recorded": recorded, "pendingPreflight": pending_preflight}

    def bind_task_after_thread(
        self,
        *,
        intent: dict[str, Any],
        thread_id: str,
        worktree_path: str | None = None,
        state: str | None = None,
        source: str = "dispatch-thread-bind",
    ) -> dict[str, Any]:
        """Bind managed task identity only after the real external thread exists."""

        if not thread_id.strip():
            raise ValueError("actual thread id is required for managed task binding")
        key = str(intent.get("key") or "")
        owner, repo, number, issue_url = _issue_parts(key)
        opportunity_key = f"{owner}/{repo}#{number}"
        requested_stage = state or str(intent.get("taskStage") or "REPRODUCTION_REQUIRED")
        pre_task = (
            intent.get("preTaskEvidence") if isinstance(intent.get("preTaskEvidence"), dict) else {}
        )
        code_paths = [
            str(path)
            for path in (
                intent.get("codePaths")
                or pre_task.get("codePaths")
                or pre_task.get("codePathsPlan")
                or []
            )
            if str(path).strip()
        ]
        selected_base = str(intent.get("selectedBaseSha") or pre_task.get("baseSha") or "")
        default_branch = str(intent.get("defaultBranch") or pre_task.get("defaultBranch") or "main")
        result_digest = str(
            intent.get("resultDigest")
            or intent.get("preTaskEvidenceDigest")
            or sha256_json(
                {
                    "taskId": str(intent.get("intentId") or opportunity_key),
                    "baseSha": selected_base,
                    "codePaths": code_paths,
                }
            )
        )
        requested_receipt = intent.get("reproductionReceipt") or intent.get("probeReceipt")
        expected_opportunity = self.ledger.opportunity_identity(opportunity_key)
        if expected_opportunity is None:
            self.ledger.upsert_opportunity(
                opportunity_key=opportunity_key,
                owner=owner,
                repo=repo,
                issue_number=number,
                issue_url=issue_url,
                state="SYSTEM_PROCESSING",
                source=source,
                provenance={"threadId": thread_id},
                metadata={"selectedBaseSha": selected_base, "codePaths": code_paths},
            )
        else:
            self.ledger.ensure_opportunity_evidence(
                opportunity_key=opportunity_key,
                selected_base_sha=selected_base,
                code_paths=code_paths,
            )
        expected_opportunity = self.ledger.opportunity_identity(opportunity_key)
        if requested_stage == "IMPLEMENTATION_READY" and not (
            isinstance(requested_receipt, dict)
            and verify_probe_receipt(
                requested_receipt,
                repo=(
                    f"{expected_opportunity['owner']}/{expected_opportunity['repo']}"
                    if expected_opportunity
                    else ""
                ),
                base_sha=(
                    expected_opportunity.get("selectedBaseSha") if expected_opportunity else ""
                ),
                code_paths=code_paths,
                required_level=REPRODUCED_VALIDATED,
                issue_url=(expected_opportunity.get("issueUrl") if expected_opportunity else None),
                task_id=str(intent.get("intentId") or opportunity_key),
                thread_id=thread_id,
                head_sha=str(intent.get("headSha") or selected_base),
                commit_sha=str(intent.get("commitSha") or selected_base),
                result_digest=result_digest,
            )
        ):
            requested_stage = "REPRODUCTION_REQUIRED"
        probe_provenance = {
            "repo": f"{owner}/{repo}",
            "issueUrl": issue_url,
            "defaultBranch": default_branch,
            "selectedBaseSha": selected_base,
            "codePaths": code_paths,
            "profileId": intent.get("probeProfile") or pre_task.get("probeProfile"),
            "headSha": str(intent.get("headSha") or selected_base),
            "commitSha": str(intent.get("commitSha") or selected_base),
            "resultDigest": result_digest,
        }
        result = self.ledger.bind_task(
            task_id=str(intent.get("intentId") or opportunity_key),
            opportunity_key=opportunity_key,
            thread_id=thread_id,
            worktree_path=worktree_path,
            state=requested_stage,
            source=source,
            provenance={
                "intentId": intent.get("intentId"),
                "threadBind": True,
                "preTaskEvidenceDigest": intent.get("preTaskEvidenceDigest"),
                "taskStage": requested_stage,
                "probeLevel": str(intent.get("probeLevel") or "UNVERIFIED"),
                "probeReceiptDigest": intent.get("probeReceiptDigest"),
                "probeReceipt": requested_receipt
                if requested_stage == "IMPLEMENTATION_READY"
                else None,
                **probe_provenance,
            },
            observed_at=str(intent.get("issuedAt") or "") or None,
        )
        self.ledger.record_event(
            event_type="TASK_BOUND",
            idempotency_key=f"task-bind:{intent.get('intentId')}:{thread_id}",
            opportunity_key=opportunity_key,
            task_id=str(intent.get("intentId") or opportunity_key),
            state=requested_stage,
            source=source,
            provenance={"threadId": thread_id},
            payload={"threadId": thread_id, "issueUrl": issue_url},
        )
        if requested_stage == "REPRODUCTION_REQUIRED" and selected_base and code_paths:
            self.ledger.queue_reproduction_probe(
                task_id=str(intent.get("intentId") or opportunity_key),
                opportunity_key=opportunity_key,
                repo=f"{owner}/{repo}",
                issue_url=issue_url,
                default_branch=default_branch,
                selected_base_sha=selected_base,
                code_paths=code_paths,
                profile_id=intent.get("probeProfile") or pre_task.get("probeProfile"),
                checkout_path=worktree_path,
                thread_id=thread_id,
                head_sha=probe_provenance["headSha"],
                commit_sha=probe_provenance["commitSha"],
                result_digest=result_digest,
                idempotency_key=f"reproduction:{intent.get('intentId') or opportunity_key}:{selected_base}:{result_digest}",
            )
        return result

    def record_preflight_outcome(
        self,
        *,
        intent: dict[str, Any],
        result_type: str,
        reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist a pre-thread terminal outcome without manufacturing a task."""

        if result_type not in {
            "scan_false_positive",
            "state_drift",
            "blocked_pre_task",
            "task_no_go",
            "censored",
        }:
            raise ValueError("invalid preflight outcome")
        intent_id = str(intent.get("intentId") or "")
        key = str(intent.get("key") or "")
        owner, repo, number, _issue_url = _issue_parts(key)
        opportunity_key = f"{owner}/{repo}#{number}"
        digest = sha256_json(
            {
                "intentId": intent_id,
                "opportunityKey": opportunity_key,
                "resultType": result_type,
                "reason": reason,
                "evidence": evidence or {},
            }
        )
        return self.ledger.record_result(
            task_id=f"preflight:{intent_id or opportunity_key}",
            result_digest=digest,
            worker_state="skipped",
            result_type=result_type,
            waiting_external=result_type == "blocked_pre_task",
            source="live-preflight",
            provenance={"intentId": intent_id, "reason": reason},
            validation={"passed": False, "reason": reason},
        )

    def record_task_result(
        self,
        *,
        candidate: dict[str, Any],
        value: dict[str, Any],
        result_digest: str,
    ) -> dict[str, Any]:
        ledger = self.ledger
        issue_url = str(candidate.get("issueUrl") or value.get("issueUrl") or "")
        owner, repo, number, normalized_url = _issue_parts(issue_url)
        opportunity_key = f"{owner}/{repo}#{number}"
        task_id = str(candidate.get("intentId") or candidate.get("threadId") or opportunity_key)
        thread_id = candidate.get("threadId") or value.get("threadId")
        if not str(thread_id or "").strip():
            bound = ledger.read_task(task_id)
            thread_id = bound.get("thread_id") if bound else None
        if not str(thread_id or "").strip():
            raise RuntimeError("managed result requires an already-created Codex thread")
        existing_opportunity = ledger.opportunity_identity(opportunity_key)
        pre_task = (
            candidate.get("preTaskEvidence")
            if isinstance(candidate.get("preTaskEvidence"), dict)
            else {}
        )
        selected_base = str(candidate.get("selectedBaseSha") or pre_task.get("baseSha") or "")
        code_paths = [
            str(path)
            for path in (
                candidate.get("codePaths")
                or pre_task.get("codePathsPlan")
                or pre_task.get("codePaths")
                or []
            )
            if str(path).strip()
        ]
        stage = str(value.get("stage") or "")
        publication = value.get("publication") if isinstance(value.get("publication"), dict) else {}
        publication_receipt = (
            value.get("publicationReceipt")
            if isinstance(value.get("publicationReceipt"), dict)
            else {}
        )
        pr_url = str(
            value.get("prUrl")
            or publication.get("prUrl")
            or publication_receipt.get("prUrl")
            or ""
        )
        pr_key = pr_key_from_url(pr_url) if pr_url else None
        head_sha = str(value.get("headSha") or value.get("head_sha") or "") or None
        quality = value.get("quality") if isinstance(value.get("quality"), dict) else {}
        validation = (
            value.get("validation") if isinstance(value.get("validation"), dict) else quality
        )
        context_publication_receipt = candidate.get("publicationReceipt")
        published_managed_task = ledger.read_task(task_id)
        if (
            stage in PUBLISHED_RESULT_STAGES
            and published_managed_task is not None
            and published_managed_task.get("readSource") == "managed"
        ):
            if not isinstance(context_publication_receipt, dict):
                raise PermissionError("published task result lacks publication authority")
            commit_sha = str(value.get("commitSha") or value.get("commit_sha") or "")
            task = published_managed_task
            try:
                task_provenance = json.loads(task.get("provenance_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                task_provenance = {}
            durable_receipt = ledger.implementation_authorization_receipt(
                task_id=task_id,
                thread_id=str(thread_id),
                worktree_path=str(candidate.get("worktreePath") or value.get("worktreePath") or ""),
                repo=f"{owner}/{repo}",
                issue_url=normalized_url,
                receipt_digest=str(task_provenance.get("probeReceiptDigest") or ""),
            )
            if publication_receipt or durable_receipt is not None:
                effective_publication_receipt = (
                    publication_receipt or context_publication_receipt
                )
                publication_commit_sha = str(
                    effective_publication_receipt.get("commitSha") or ""
                )
                publication_pr_url = str(effective_publication_receipt.get("prUrl") or "")
                pr_url = str(
                    value.get("prUrl")
                    or publication.get("prUrl")
                    or publication_pr_url
                    or ""
                )
                pr_key = pr_key_from_url(pr_url) if pr_url else None
                bound_pr = (
                    ledger.published_pr_for_opportunity(
                        opportunity_key,
                        pr_url=publication_pr_url,
                        publication_head_sha=publication_commit_sha,
                    )
                    if publication_pr_url and publication_commit_sha
                    else None
                )
                if (
                    existing_opportunity is None
                    or (
                        bool(publication_receipt)
                        and context_publication_receipt != publication_receipt
                    )
                    or publication_pr_url != pr_url
                    or str(publication.get("prUrl") or publication_pr_url)
                    != publication_pr_url
                    or pr_key is None
                    or bound_pr is None
                    or bound_pr.get("pr_key") != pr_key
                    or bound_pr.get("state") != "OPEN"
                    or bound_pr.get("head_sha") != head_sha
                    or not isinstance(durable_receipt, dict)
                    or not re.fullmatch(r"[0-9a-f]{40}", str(head_sha or ""))
                    or commit_sha != head_sha
                    or not _published_result_matches_worktree(
                        candidate=candidate, value=value, head_sha=str(head_sha)
                    )
                ):
                    raise PermissionError("published task result is not bound to the current PR")
                published_validation = dict(validation)
                published_validation.pop("reproductionReceiptAuthenticated", None)
                published_validation.update(
                    {
                        "implementationAuthorizationAuthenticated": True,
                        "publishedContinuationBound": True,
                        "authorizationReceiptDigest": durable_receipt.get("receiptDigest"),
                    }
                )
                managed_result = ledger.record_published_task_result(
                    task_id=task_id,
                    pr_key=pr_key,
                    pr_url=pr_url,
                    publication_commit_sha=publication_commit_sha,
                    head_sha=str(head_sha),
                    commit_sha=commit_sha,
                    result_digest=result_digest,
                    stage=stage,
                    validation=published_validation,
                    provenance={
                        "issueUrl": normalized_url,
                        "stage": stage,
                        "publishedContinuationBound": True,
                        "authorizationReceiptDigest": durable_receipt.get("receiptDigest"),
                    },
                )
                return {
                    "ok": True,
                    "result": managed_result,
                    "reproductionValidated": False,
                    "implementationAuthorized": True,
                    "publicationAllowed": False,
                }
            raise PermissionError("published task result lacks implementation authorization")
        if existing_opportunity is None:
            ledger.upsert_opportunity(
                opportunity_key=opportunity_key,
                owner=owner,
                repo=repo,
                issue_number=number,
                issue_url=normalized_url,
                state="SYSTEM_PROCESSING",
                source="dispatch-result",
                provenance={"taskId": task_id, "source": "managed-result"},
                metadata={"selectedBaseSha": selected_base, "codePaths": code_paths},
            )
        ledger.bind_task(
            task_id=task_id,
            opportunity_key=opportunity_key,
            thread_id=thread_id,
            worktree_path=candidate.get("worktreePath") or value.get("worktreePath"),
            state="REPRODUCTION_REQUIRED",
            source="dispatch-result",
            provenance={
                "resultDigest": result_digest,
                "taskStage": candidate.get("taskStage") or "REPRODUCTION_REQUIRED",
                "probeLevel": candidate.get("probeLevel") or "UNVERIFIED",
                "selectedBaseSha": selected_base,
                "codePaths": code_paths,
                "headSha": str(value.get("headSha") or value.get("head_sha") or "") or None,
                "commitSha": str(value.get("commitSha") or value.get("commit_sha") or "") or None,
            },
        )
        reproduction_receipt = value.get("reproductionReceipt") or value.get("probeReceipt")
        probe_paths = [
            str(path)
            for path in (
                candidate.get("codePaths")
                or (candidate.get("preTaskEvidence") or {}).get("codePathsPlan")
                or (candidate.get("preTaskEvidence") or {}).get("codePaths")
                or []
            )
            if str(path).strip()
        ]
        probe_verified = verify_probe_receipt(
            reproduction_receipt if isinstance(reproduction_receipt, dict) else {},
            repo=f"{owner}/{repo}",
            base_sha=str(
                candidate.get("selectedBaseSha")
                or (candidate.get("preTaskEvidence") or {}).get("baseSha")
                or ""
            ),
            code_paths=probe_paths,
            required_level=REPRODUCED_VALIDATED,
            issue_url=normalized_url,
            task_id=task_id,
            head_sha=head_sha,
            commit_sha=str(value.get("commitSha") or value.get("commit_sha") or "") or None,
            result_digest=result_digest,
        )
        ledger.bind_task(
            task_id=task_id,
            opportunity_key=opportunity_key,
            thread_id=thread_id,
            worktree_path=candidate.get("worktreePath") or value.get("worktreePath"),
            state=(
                "IMPLEMENTATION_READY"
                if candidate.get("taskStage") == "IMPLEMENTATION_READY" and probe_verified
                else "REPRODUCTION_REQUIRED"
            ),
            source="dispatch-result",
            provenance={
                "resultDigest": result_digest,
                "taskStage": candidate.get("taskStage") or "REPRODUCTION_REQUIRED",
                "probeLevel": REPRODUCED_VALIDATED if probe_verified else "UNVERIFIED",
                "selectedBaseSha": selected_base,
                "codePaths": code_paths,
                "headSha": str(value.get("headSha") or value.get("head_sha") or "") or None,
                "commitSha": str(value.get("commitSha") or value.get("commit_sha") or "") or None,
                "probeReceiptDigest": (
                    reproduction_receipt.get("receiptDigest")
                    if isinstance(reproduction_receipt, dict) and probe_verified
                    else None
                ),
                "probeReceipt": reproduction_receipt if probe_verified else None,
            },
        )
        if not probe_verified:
            stage = "REPRODUCTION_REQUIRED"
            validation = dict(validation)
            validation["reproductionRequired"] = True
            validation["reproductionReceiptAuthenticated"] = False
        elif probe_verified:
            validation = dict(validation)
            validation["reproductionReceiptAuthenticated"] = True
        result = ledger.record_result(
            task_id=task_id,
            result_digest=result_digest,
            worker_state=(
                "reproduction_required"
                if not probe_verified
                else str(
                    value.get("workerState")
                    or ("patched" if stage == "FIX_READY" else stage or "queued")
                )
            ),
            result_type=_stage_result_type(stage, value),
            pr_key=pr_key,
            head_sha=head_sha,
            commit_sha=str(value.get("commitSha") or value.get("commit_sha") or "") or None,
            validation=validation,
            prior_head_sha=str(value.get("previousHeadSha") or "") or None,
            new_head_sha=head_sha,
            waiting_external=stage in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"},
            source="dispatch-result",
            provenance={
                "issueUrl": normalized_url,
                "stage": stage,
                "probeLevel": REPRODUCED_VALIDATED if probe_verified else "PATHS_VERIFIED",
            },
        )
        return {
            "ok": True,
            "result": result,
            "reproductionValidated": probe_verified,
            "implementationAuthorized": candidate.get("taskStage") == "IMPLEMENTATION_READY"
            and probe_verified,
            "publicationAllowed": stage == "FIX_READY"
            and candidate.get("taskStage") == "IMPLEMENTATION_READY"
            and probe_verified,
        }

    def transition_to_implementation(
        self, *, candidate: dict[str, Any], receipt: dict[str, Any], result_digest: str
    ) -> dict[str, Any]:
        issue_url = str(candidate.get("issueUrl") or "")
        owner, repo, _number, normalized_url = _issue_parts(issue_url)
        task_id = str(candidate.get("intentId") or candidate.get("threadId") or "")
        paths = [
            str(path)
            for path in (
                candidate.get("codePaths")
                or (candidate.get("preTaskEvidence") or {}).get("codePathsPlan")
                or (candidate.get("preTaskEvidence") or {}).get("codePaths")
                or []
            )
            if str(path).strip()
        ]
        head_sha = str(receipt.get("headSha") or "")
        commit_sha = str(receipt.get("commitSha") or "")
        if not verify_probe_receipt(
            receipt,
            repo=f"{owner}/{repo}",
            base_sha=str(
                candidate.get("selectedBaseSha")
                or (candidate.get("preTaskEvidence") or {}).get("baseSha")
                or ""
            ),
            code_paths=paths,
            issue_url=normalized_url,
            task_id=task_id,
            head_sha=head_sha,
            commit_sha=commit_sha,
            result_digest=result_digest,
        ):
            raise PermissionError("current-key REPRODUCED_VALIDATED receipt is required")
        opportunity_key = f"{owner}/{repo}#{_number}"
        self.ledger.ensure_opportunity_evidence(
            opportunity_key=opportunity_key,
            selected_base_sha=str(
                candidate.get("selectedBaseSha")
                or (candidate.get("preTaskEvidence") or {}).get("baseSha")
                or ""
            ),
            code_paths=paths,
        )
        existing = self.ledger.read_task(task_id) or {}
        thread_id = str(candidate.get("threadId") or existing.get("thread_id") or "")
        if not thread_id:
            raise RuntimeError("managed reproduction transition requires a bound thread")
        self.ledger.bind_task(
            task_id=task_id,
            opportunity_key=opportunity_key,
            thread_id=thread_id,
            worktree_path=candidate.get("worktreePath") or existing.get("worktree_path"),
            state="REPRODUCTION_REQUIRED",
            source="reproduction-result",
            provenance={
                "taskStage": "REPRODUCTION_REQUIRED",
                "probeLevel": "PATHS_VERIFIED",
                "selectedBaseSha": receipt.get("baseSha"),
                "codePaths": paths,
                "headSha": receipt.get("headSha"),
                "commitSha": receipt.get("commitSha"),
                "resultDigest": result_digest,
                "threadFingerprint": thread_fingerprint(thread_id),
            },
        )
        return self.ledger.transition_task_to_implementation(
            task_id=task_id,
            receipt_digest=str(receipt.get("receiptDigest") or result_digest),
            receipt=receipt,
        )

    def record_publication_receipt(
        self,
        *,
        request: dict[str, Any],
        receipt: dict[str, Any],
        receipt_observation: bool = False,
    ) -> dict[str, Any]:
        reservation_key = str(request.get("reservationKey") or "") or None
        if request.get("publicationKind") != "PR_UPDATE" and reservation_key:
            # Keep the established fast rejection for malformed/blocked requests;
            # the atomic ledger method repeats this check under its write lock.
            with self.ledger._connection() as connection:
                reservation = connection.execute(
                    "SELECT state FROM managed_publication_reservations WHERE reservation_key=?",
                    (reservation_key,),
                ).fetchone()
            if reservation is None or reservation["state"] not in {
                "ACTIVE",
                "RECONCILE_REQUIRED",
                "FINALIZED",
            }:
                raise PermissionError("publication reservation is not active")
        pr_url = str(receipt.get("prUrl") or receipt.get("url") or "")
        if not pr_url:
            raise ValueError("publication receipt is missing prUrl")
        pr_key = pr_key_from_url(pr_url)
        owner_repo, number_text = pr_key.rsplit("#", 1)
        owner, repo = owner_repo.split("/", 1)
        head_sha = str(
            receipt.get("headSha") or receipt.get("remoteSha") or request.get("commitSha") or ""
        )
        if not head_sha:
            raise ValueError("publication receipt is missing head SHA")
        issue_url = str(request.get("issueUrl") or "")
        _issue_owner, _issue_repo, _issue_number, normalized_issue_url = _issue_parts(issue_url)
        pre_task = request.get("preTaskEvidence")
        pre_task = pre_task if isinstance(pre_task, dict) else {}
        code_paths = [
            str(path)
            for path in (request.get("codePaths") or pre_task.get("codePaths") or [])
            if str(path).strip()
        ]
        if not verify_probe_receipt(
            request.get("reproductionReceipt") or request.get("probeReceipt") or {},
            repo=f"{_issue_owner}/{_issue_repo}",
            base_sha=str(request.get("selectedBaseSha") or pre_task.get("baseSha") or ""),
            code_paths=code_paths,
            required_level=REPRODUCED_VALIDATED,
            issue_url=normalized_issue_url,
            task_id=str(
                request.get("taskId") or request.get("intentId") or request.get("threadId") or ""
            ),
            head_sha=head_sha,
            commit_sha=str(request.get("commitSha") or ""),
            result_digest=str(request.get("resultDigest") or ""),
        ):
            raise PermissionError("publication receipt requires a current-key reproduction receipt")
        if request.get("publicationKind") != "PR_UPDATE" and not reservation_key:
            raise PermissionError("publication reservation is required before PR creation")
        opportunity_key = f"{_issue_owner}/{_issue_repo}#{_issue_number}"
        row = self.ledger.record_publication_receipt_atomic(
            pr_key=pr_key,
            owner=owner,
            repo=repo,
            number=int(number_text),
            head_sha=head_sha,
            pr_url=pr_url,
            auto_created=request.get("publicationKind") != "PR_UPDATE",
            source_kind="MANAGED_PUBLICATION_RECEIPT",
            source="publication",
            provenance={
                "requestId": request.get("requestId"),
                "receiptDigest": sha256_json(receipt),
            },
            reservation_key=reservation_key,
            opportunity_key=opportunity_key,
            event_idempotency_key=f"publication:{request.get('requestId') or pr_key}:{head_sha}",
            event_provenance={"requestId": request.get("requestId")},
            event_payload={"prUrl": pr_url, "headSha": head_sha},
            receipt_observation=receipt_observation,
        )
        return {"ok": True, "pr": row}

    def reserve_publication(
        self,
        *,
        request_id: str,
        repo: str,
        head_ref: str | None = None,
        head_sha: str | None = None,
        opportunity_key: str | None = None,
        pr_key: str | None = None,
        invitation_event_key: str | None = None,
        lease_seconds: int = 900,
    ) -> dict[str, Any]:
        reservation_key = f"publication:{request_id}"
        result = self.ledger.reserve_publication_slot(
            reservation_key=reservation_key,
            request_id=request_id,
            repo=repo,
            head_ref=head_ref,
            head_sha=head_sha,
            opportunity_key=opportunity_key,
            pr_key=pr_key,
            invitation_event_key=invitation_event_key,
            idempotency_key=reservation_key,
            lease_seconds=lease_seconds,
        )
        if "reservationKey" not in result and result.get("reservation_key"):
            result["reservationKey"] = result["reservation_key"]
        return result

    def reconcile_publication(
        self, *, reservation_key: str, repo: str, head_sha: str
    ) -> dict[str, Any] | None:
        return self.ledger.reconcile_publication_reservation(
            reservation_key=reservation_key,
            repo=repo,
            head_sha=head_sha,
        )

    def reconcile_publication_absence(
        self,
        *,
        reservation_key: str,
        repo: str,
        head_ref: str,
        head_sha: str,
        github_client: Any | None,
        now: str | None = None,
    ) -> dict[str, Any]:
        return PublicationAbsenceReconciler(self.ledger, github_client, now=now).reconcile(
            reservation_key=reservation_key,
            repo=repo,
            head_ref=head_ref,
            head_sha=head_sha,
        )

    def reconcile_pending_absences(self, github_client: Any | None) -> dict[str, Any]:
        connection = self.ledger._connection()
        try:
            rows = connection.execute(
                """SELECT reservation_key,repo,head_ref,head_sha FROM managed_publication_reservations
                   WHERE state IN ('CHECK_ABSENCE_REQUIRED','WAITING_EXTERNAL')"""
            ).fetchall()
        finally:
            connection.close()
        results = []
        for row in rows:
            if not row["head_ref"] or not row["head_sha"]:
                results.append(
                    self.ledger.mark_publication_waiting(
                        reservation_key=row["reservation_key"], reason="HEAD_BINDING_MISSING"
                    )
                )
                continue
            results.append(
                self.reconcile_publication_absence(
                    reservation_key=row["reservation_key"],
                    repo=row["repo"],
                    head_ref=row["head_ref"],
                    head_sha=row["head_sha"],
                    github_client=github_client,
                )
            )
        return {"ok": True, "processed": len(results), "results": results}

    def record_followup(self, state: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
        ledger = self.ledger
        recorded = 0
        for item in state.get("items") or []:
            if not isinstance(item, dict) or not item.get("key"):
                continue
            pr_key = str(item["key"])
            owner_repo, number_text = pr_key.rsplit("#", 1)
            owner, repo = owner_repo.split("/", 1)
            head_sha = str(item.get("headSha") or "")
            if not head_sha:
                continue
            ledger.upsert_pr(
                pr_key=pr_key,
                owner=owner,
                repo=repo,
                number=int(number_text),
                head_sha=head_sha,
                pr_url=str(
                    item.get("url") or f"https://github.com/{owner_repo}/pull/{number_text}"
                ),
                state="OPEN",
                auto_created=False,
                source_kind="FOLLOWUP_OBSERVATION",
                source="github-followup",
                provenance={"runId": report.get("run_id")},
                observed_at=str(item.get("checkedAt") or "") or None,
            )
            evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            checks = evidence.get("failingChecks") or []
            status = str(item.get("ciStatus") or ("FAILED" if checks else "UNKNOWN")).upper()
            ledger.record_ci_run(
                ci_key=f"followup:{pr_key}:{head_sha}",
                pr_key=pr_key,
                head_sha=head_sha,
                status=status,
                checks={"failing": checks, "source": "followup"},
                observed_at=str(item.get("checkedAt") or "") or None,
            )
            for index, change in enumerate(evidence.get("requestedChanges") or []):
                login = str(change.get("reviewer") or "")
                if not login:
                    continue
                ledger.record_maintainer_event(
                    event_key=f"followup:{pr_key}:{head_sha}:review:{index}:{login}",
                    pr_key=pr_key,
                    event_type="REVIEW_CHANGES_REQUESTED",
                    actor_login=login,
                    actor_type=str(change.get("actorType") or "User"),
                    author_association=str(change.get("authorAssociation") or ""),
                    source="github-followup",
                    payload={
                        "targetPrKey": pr_key,
                        "explicit_mechanical_request": change.get(
                            "explicitMechanicalRequest", False
                        ),
                    },
                    observed_at=str(item.get("checkedAt") or "") or None,
                )
            for event in evidence.get("maintainerEvents") or []:
                if not isinstance(event, dict) or not event.get("eventId"):
                    continue
                ledger.record_maintainer_event(
                    event_key=str(event["eventId"]),
                    pr_key=pr_key,
                    opportunity_key=str(event.get("opportunityKey") or pr_key),
                    event_type=str(event.get("eventType") or "").upper(),
                    actor_login=str(event.get("actorLogin") or ""),
                    actor_type=str(event.get("actorType") or ""),
                    author_association=str(event.get("authorAssociation") or "").upper(),
                    source="github-followup",
                    payload={
                        "targetRepo": str(event.get("targetRepo") or owner_repo),
                        "targetPrKey": pr_key,
                        "opportunityKey": str(event.get("opportunityKey") or pr_key),
                        "eventId": str(event["eventId"]),
                    },
                    observed_at=str(item.get("checkedAt") or "") or None,
                )
            current_result = ledger.current_result_for_pr(pr_key)
            if current_result:
                result_digest = str(current_result["result_digest"])
                for event in evidence.get("requestedChanges") or []:
                    login = str(event.get("reviewer") or "")
                    if not login:
                        continue
                    event_key = f"followup:{pr_key}:{head_sha}:review:{list(evidence.get('requestedChanges') or []).index(event)}:{login}"
                    ledger.queue_public_reply(
                        pr_key=pr_key,
                        maintainer_event_key=event_key,
                        result_digest=result_digest,
                        proposed_body="Implemented the requested mechanical change; validation passed.",
                    )
            ledger.record_event(
                event_type="FOLLOWUP_OBSERVED",
                idempotency_key=f"followup:{pr_key}:{head_sha}:{item.get('actionDigest') or item.get('taskActionDigest') or ''}",
                pr_key=pr_key,
                source="github-followup",
                provenance={"runId": report.get("run_id")},
                observed_at=str(item.get("checkedAt") or "") or None,
                payload={"actions": item.get("actions"), "taskActions": item.get("taskActions")},
            )
            recorded += 1
        return {"ok": True, "recorded": recorded}

    def projection(self) -> dict[str, Any]:
        return export_projection(self.path)

    def dispatch_public_replies(
        self,
        sender: Any | None = None,
        *,
        live_revalidator: Any | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Run the controlled reply outbox with an injected external sender."""

        return self.ledger.dispatch_reply_outbox(
            sender, live_revalidator=live_revalidator, limit=limit
        )

    def process_reply_outbox(
        self,
        *,
        sender: Any | None = None,
        receipts: dict[str, dict[str, Any]] | None = None,
        live_revalidator: Any | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Reconcile observed receipts, then dispatch only with an explicit sender."""

        reconciliation = self.ledger.reconcile_reply_outbox(receipts)
        dispatch = self.ledger.dispatch_reply_outbox(
            sender, live_revalidator=live_revalidator, limit=limit
        )
        return {
            "ok": not reconciliation["errors"] and not dispatch["errors"],
            "reconcile": reconciliation,
            "dispatch": dispatch,
        }
