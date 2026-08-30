"""Local authoritative lifecycle ledger with transactional leases and receipts."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import quote

from .action_guard import ledger_action_guard_root, opportunity_action_guard
from .repo_probe import (
    PATHS_VERIFIED,
    REPRODUCED_VALIDATED,
    verify_code_path_tombstone_receipt,
    verify_merge_resolution_scope_receipt,
    verify_probe_receipt,
)
from .task_quarantine import active as active_quarantine
from .task_quarantine import attach_artifact as attach_quarantine_artifact
from .task_quarantine import backfill_from_managed_events, backfill_from_radar_events
from .task_quarantine import clear as clear_quarantine
from .task_quarantine import clear_exact as clear_quarantine_exact
from .task_quarantine import ensure_schema as ensure_quarantine_schema
from .task_quarantine import payload as quarantine_payload
from .task_quarantine import record as record_quarantine
from .task_quarantine import require_clear as require_quarantine_clear
from .util import canonical_json, iso_z, parse_time, sha256_json, sha256_text

STAGES = (
    "DISCOVERED",
    "EVIDENCE_COMPLETE",
    "RANKED",
    "QUALIFIED",
    "LEASED",
    "CREATING",
    "DISPATCHED",
    "AUDIT_PASS",
    "AUDIT_NO_GO",
    "VALIDATION_PENDING",
    "FIX_READY",
    "PR_OPEN",
    "CI_GREEN",
    "MAINTAINER_ACCEPTED",
    "MERGED",
    "CLOSED",
)
TERMINAL_STAGES = {"AUDIT_NO_GO", "MERGED", "CLOSED"}
PUBLISHED_STAGES = {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED", "MERGED", "CLOSED"}
STATE_DRIFT_RECHECK_EVENT = "STATE_DRIFT_RECHECK_REQUIRED"
PR_UPDATE_REARM_REASONS = {"EXISTING_PR_HEAD_DRIFT", "NON_FAST_FORWARD_PR_UPDATE"}
PR_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$")
ISSUE_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
PROBE_RECEIPT_VOLATILE_FIELDS = frozenset({"observedAt", "expiresAt", "receiptDigest", "signature"})


def _live_audit_probe_receipt(audit_payload: dict[str, Any]) -> dict[str, Any] | None:
    live_audit = audit_payload.get("liveAudit")
    evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else None
    if not isinstance(evidence, dict):
        return None
    camel_present = "repoProbeReceipt" in evidence
    snake_present = "repo_probe_receipt" in evidence
    if not camel_present and not snake_present:
        return None
    camel_receipt = evidence.get("repoProbeReceipt")
    snake_receipt = evidence.get("repo_probe_receipt")
    if camel_present and snake_present and camel_receipt != snake_receipt:
        raise LedgerError("live audit repository probe receipts disagree")
    receipt = camel_receipt if camel_present else snake_receipt
    if not isinstance(receipt, dict):
        raise LedgerError("live audit repository probe receipt is invalid")
    return receipt


def _probe_receipt_binding_digest(receipt: dict[str, Any]) -> str:
    return sha256_json(
        {key: value for key, value in receipt.items() if key not in PROBE_RECEIPT_VOLATILE_FIELDS}
    )


def _audited_probe_code_paths(
    payload: dict[str, Any], audit_payload: dict[str, Any], issue_url: str
) -> list[str] | None:
    """Return the exact repository paths authenticated by the live audit.

    Scanner path plans may still contain unresolved basename candidates. Once
    the live repository probe has resolved and authenticated concrete blobs,
    task contexts must not fall back to the broader pre-audit plan.
    """

    receipt = _live_audit_probe_receipt(audit_payload)
    if receipt is None:
        return None
    match = ISSUE_URL_RE.fullmatch(issue_url)
    if match is None:
        raise LedgerError("live audit issue URL is invalid")
    pre_task = payload.get("preTaskEvidence")
    pre_task = pre_task if isinstance(pre_task, dict) else {}
    selected_base = str(payload.get("selectedBaseSha") or pre_task.get("baseSha") or "")
    code_paths = [str(path) for path in (receipt.get("codePaths") or []) if str(path).strip()]
    if not selected_base or not code_paths:
        raise LedgerError("live audit repository probe binding is incomplete")
    if not verify_probe_receipt(
        receipt,
        repo=match.group(1),
        base_sha=selected_base,
        code_paths=code_paths,
        required_level=PATHS_VERIFIED,
        enforce_freshness=False,
    ):
        raise LedgerError("live audit repository probe receipt is not authenticated")
    return code_paths


def _intent_bound_audit_rows(
    connection: sqlite3.Connection, opportunity_key: str, intent_id: str
) -> list[sqlite3.Row]:
    rows = connection.execute(
        """SELECT payload_json,created_at,dedupe_key,id FROM events
           WHERE opportunity_key=?
             AND event_type IN ('AUDIT_PASS','AUDIT_SNAPSHOT')
           ORDER BY id DESC""",
        (opportunity_key,),
    ).fetchall()
    prefix = f"{intent_id}:"
    bound = [row for row in rows if str(row["dedupe_key"] or "").startswith(prefix)]
    if bound:
        return bound
    intent_count = connection.execute(
        "SELECT COUNT(*) FROM intents WHERE opportunity_key=?", (opportunity_key,)
    ).fetchone()[0]
    return list(rows) if int(intent_count) == 1 else []


def bind_dispatched_recovery_prompt(
    candidate: dict[str, Any],
    *,
    prompt_version: str,
    prompt_digest: str,
) -> dict[str, Any] | None:
    """Bind one dispatched-task recovery to the exact prompt that will be sent.

    Legacy exhausted recoveries did not record prompt provenance. A new prompt
    may rearm one of those terminal markers once; an exhaustion carrying the
    same version and digest remains terminal.
    """

    if candidate.get("recoveryKind") != "DISPATCHED_TASK":
        raise LedgerError("prompt binding only applies to dispatched-task recovery")
    version = str(prompt_version).strip()
    digest = str(prompt_digest).strip().lower()
    if not version or len(version) > 160:
        raise LedgerError("recovery prompt version is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise LedgerError("recovery prompt digest is invalid")
    exhausted = list(candidate.get("exhaustedRecoveries") or [])
    if any(
        marker.get("recoveryPromptVersion") is not None
        or marker.get("recoveryPromptDigest") is not None
        for marker in exhausted
    ):
        return None
    rearmed_from = max(
        exhausted,
        key=lambda marker: int(marker.get("eventId") or 0),
        default=None,
    )
    base_nonce = str(candidate.get("recoveryNonce") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", base_nonce):
        raise LedgerError("base recovery nonce is invalid")
    marker_binding = (
        {
            "eventId": int(rearmed_from.get("eventId") or 0),
            "exhaustedNonce": str(rearmed_from.get("exhaustedNonce") or ""),
        }
        if rearmed_from is not None
        else None
    )
    bound = dict(candidate)
    bound.update(
        {
            "baseRecoveryNonce": base_nonce,
            "recoveryPromptVersion": version,
            "recoveryPromptDigest": digest,
            "recoveryChainDigest": sha256_json(
                {
                    "key": candidate.get("key"),
                    "threadId": candidate.get("threadId"),
                    "dispatchedAt": candidate.get("dispatchedAt"),
                    "recoveryKind": candidate.get("recoveryKind"),
                    "followupDigest": candidate.get("followupDigest") or "",
                    "recoveryPromptVersion": version,
                    "recoveryPromptDigest": digest,
                    "rearmedFromExhausted": marker_binding,
                    "chainVersion": "recovery-chain-v1",
                }
            ),
            "recoveryNonce": sha256_json(
                {
                    "baseRecoveryNonce": base_nonce,
                    "recoveryPromptVersion": version,
                    "recoveryPromptDigest": digest,
                    "rearmedFromExhausted": marker_binding,
                    "bindingVersion": "recovery-prompt-binding-v1",
                }
            ),
        }
    )
    if marker_binding is not None:
        bound["rearmedFromExhausted"] = marker_binding
    return bound


def _publication_probe_valid(
    request: dict[str, Any], evidence: dict[str, Any] | None = None
) -> bool:
    """Require a current-key reproduction receipt for every publication layer."""

    merged = dict(request)
    if isinstance(evidence, dict):
        merged.update(evidence)
    issue_url = str(merged.get("issueUrl") or "")
    match = ISSUE_URL_RE.fullmatch(issue_url)
    receipt = merged.get("reproductionReceipt") or merged.get("probeReceipt")
    if match is None or not isinstance(receipt, dict):
        return False
    repo = match.group(1)
    pre_task = merged.get("preTaskEvidence")
    if not isinstance(pre_task, dict):
        pre_task = (merged.get("intent") or {}).get("preTaskEvidence")
    if not isinstance(pre_task, dict):
        pre_task = {}
    base_sha = str(
        merged.get("selectedBaseSha") or pre_task.get("baseSha") or receipt.get("baseSha") or ""
    )
    code_paths = [
        str(path)
        for path in (
            merged.get("codePaths")
            or pre_task.get("codePathsPlan")
            or pre_task.get("codePaths")
            or receipt.get("codePaths")
            or []
        )
        if str(path).strip()
    ]
    commit_sha = str(merged.get("commitSha") or "") or None
    expected_head = str(merged.get("headSha") or commit_sha or "") or None
    result_digest = str(merged.get("resultDigest") or "") or None
    task_id = (
        str(merged.get("taskId") or merged.get("intentId") or merged.get("threadId") or "") or None
    )
    if (
        not base_sha
        or not code_paths
        or not commit_sha
        or not expected_head
        or not result_digest
        or not task_id
    ):
        return False
    return verify_probe_receipt(
        receipt,
        repo=repo,
        base_sha=base_sha,
        code_paths=code_paths,
        required_level=REPRODUCED_VALIDATED,
        issue_url=issue_url,
        task_id=task_id,
        head_sha=expected_head,
        commit_sha=commit_sha,
        result_digest=result_digest,
    )


def _publication_probe_valid_json(raw: str, evidence: dict[str, Any] | None = None) -> bool:
    try:
        request = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return False
    return _publication_probe_valid(request, evidence) if isinstance(request, dict) else False


def _publication_request_without_snapshot(request: dict[str, Any]) -> dict[str, Any]:
    value = dict(request)
    value.pop("evidenceRawBase64", None)
    return value


def _publication_snapshot_present(request: dict[str, Any]) -> bool:
    snapshot = request.get("evidenceRawBase64")
    return isinstance(snapshot, str) and bool(snapshot)


def _publication_has_irreversible_terminal_evidence(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    opportunity_key: str,
) -> bool:
    """Return whether a publication request already crossed its public boundary.

    Repository-probe freshness authorizes a future side effect.  It cannot
    invalidate a side effect that was already durably observed.  Keep this
    check independent of request status so it also repairs databases written
    by the historical freshness migration.
    """

    permit = connection.execute(
        """SELECT 1 FROM publication_permits
           WHERE request_id=? AND status='CONSUMED' LIMIT 1""",
        (request_id,),
    ).fetchone()
    if permit is not None:
        return True
    succeeded_pr = connection.execute(
        """SELECT 1 FROM publication_effects effect
           JOIN publication_permits permit ON permit.permit_id=effect.permit_id
           WHERE permit.request_id=? AND effect.action='create_pr'
             AND effect.status='SUCCEEDED' LIMIT 1""",
        (request_id,),
    ).fetchone()
    if succeeded_pr is not None:
        return True
    published_event = connection.execute(
        """SELECT 1 FROM events event
           JOIN publication_permits permit ON permit.request_id=?
           WHERE event.opportunity_key=? AND event.event_type='PR_OPEN'
             AND (
               json_extract(event.payload_json,'$.permitId')=permit.permit_id
               OR (
                 permit.pr_url IS NOT NULL
                 AND COALESCE(
                   json_extract(event.payload_json,'$.prUrl'),event.dedupe_key
                 )=permit.pr_url
               )
             )
           LIMIT 1""",
        (request_id, opportunity_key),
    ).fetchone()
    if published_event is not None:
        return True

    managed_reservations_exist = connection.execute(
        """SELECT 1 FROM sqlite_master
           WHERE type='table' AND name='managed_publication_reservations'"""
    ).fetchone()
    if managed_reservations_exist is None:
        return False
    finalized = connection.execute(
        """SELECT 1 FROM managed_publication_reservations
           WHERE request_id=? AND state='FINALIZED' LIMIT 1""",
        (request_id,),
    ).fetchone()
    return finalized is not None


def _publication_authorization_is_current_or_terminal(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    opportunity_key: str,
    request_json: str,
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Accept freshness only before an exact request crosses publication."""

    return _publication_has_irreversible_terminal_evidence(
        connection,
        request_id=request_id,
        opportunity_key=opportunity_key,
    ) or _publication_probe_valid_json(request_json, evidence)


RECOVERABLE_CONTEXT_STAGES = {
    "AUDIT_PASS",
    "VALIDATION_PENDING",
    "FIX_READY",
    "PR_OPEN",
    "CI_GREEN",
    "MAINTAINER_ACCEPTED",
    "MERGED",
    "CLOSED",
}
RECOVERABLE_CONTEXT_INTENT_STATUSES = {"DISPATCHED", "COMPLETED"}
RECOVERED_STAGE_RANK = {
    "QUALIFIED": 0,
    "LEASED": 1,
    "CREATING": 2,
    "DISPATCHED": 3,
    "AUDIT_PASS": 4,
    "VALIDATION_PENDING": 5,
    "FIX_READY": 6,
    "PR_OPEN": 7,
    "CI_GREEN": 8,
    "MAINTAINER_ACCEPTED": 9,
    "MERGED": 10,
    "CLOSED": 10,
}
RECOVERED_TITLE_STATE = {
    "AUDIT_NO_GO": "AUDIT_NO_GO",
    "AUDIT_PASS": "GO",
    "VALIDATION_PENDING": "VALIDATION_PENDING",
    "FIX_READY": "FIX_READY",
    "PR_OPEN": "PR_OPEN",
    "CI_GREEN": "PR_OPEN",
    "MAINTAINER_ACCEPTED": "PR_OPEN",
    "MERGED": "MERGED",
    "CLOSED": "PR_OPEN",
}

_EXHAUSTED_DISPATCHED_RECOVERY_PREDICATE = """
    i.status='DISPATCHED'
    AND i.thread_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM events exhausted
      JOIN events recovery
        ON recovery.opportunity_key=exhausted.opportunity_key
       AND recovery.event_type='THREAD_RECOVERY_RESERVED'
       AND recovery.dedupe_key=exhausted.dedupe_key
      WHERE exhausted.opportunity_key=i.opportunity_key
        AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
        AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
        AND recovery.id>(
          SELECT COALESCE(MAX(dispatched.id),0)
          FROM events dispatched
          WHERE dispatched.opportunity_key=i.opportunity_key
            AND dispatched.event_type='DISPATCHED'
            AND dispatched.dedupe_key=i.thread_id
        )
        AND NOT EXISTS (
          SELECT 1
          FROM events later
          WHERE later.opportunity_key=exhausted.opportunity_key
            AND later.id>exhausted.id
            AND (
              later.event_type IN (
                'TASK_RESULT_INGESTED',
                'PUBLISHED_TASK_RESULT_BACKFILLED',
                'PR_FOLLOWUP_RESULT_INGESTED',
                'IMPLEMENTATION_CONTEXT_REPAIRED',
                'AUDIT_PASS',
                'AUDIT_NO_GO',
                'VALIDATION_PENDING',
                'FIX_READY',
                'PR_OPEN',
                'CI_GREEN',
                'MAINTAINER_ACCEPTED',
                'MERGED',
                'CLOSED'
              )
              OR (
                later.event_type='THREAD_RECOVERY_RESERVED'
                AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                AND json_extract(
                      later.payload_json,'$.rearmedFromExhausted.exhaustedNonce'
                    )=exhausted.dedupe_key
              )
              OR (
                later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                AND json_extract(later.payload_json,'$.recoveryNonce')=
                    exhausted.dedupe_key
              )
            )
        )
    )
"""


class LedgerError(RuntimeError):
    pass


_MANAGED_REPLAY_REFRESHED_REQUEST_FIELDS = frozenset(
    {"requestId", "evidenceDigest", "evidenceRawBase64", "probeReceipt"}
)


def _managed_replay_immutable_request(request: dict[str, Any]) -> dict[str, Any]:
    return {
        field: value
        for field, value in request.items()
        if field not in _MANAGED_REPLAY_REFRESHED_REQUEST_FIELDS
    }


def _managed_replay_creation_snapshot(
    connection: sqlite3.Connection,
    *,
    row: sqlite3.Row,
    request: dict[str, Any],
) -> dict[str, Any]:
    """Authenticate the original snapshot from which a stable request ID was derived."""

    event_rows = connection.execute(
        """SELECT * FROM events
           WHERE opportunity_key=? AND event_type='PUBLICATION_REQUESTED'
             AND dedupe_key=?""",
        (row["opportunity_key"], row["request_id"]),
    ).fetchall()
    if len(event_rows) != 1:
        raise LedgerError("managed replay replacement creation event is missing")
    event_row = event_rows[0]
    try:
        original = json.loads(event_row["payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise LedgerError("managed replay replacement creation event is invalid") from exc
    if not isinstance(original, dict):
        raise LedgerError("managed replay replacement creation event is invalid")
    original_evidence_digest = str(original.get("evidenceDigest") or "")
    original_snapshot = original.get("evidenceRawBase64")
    if not isinstance(original_snapshot, str):
        raise LedgerError("managed replay replacement creation snapshot is missing")
    try:
        original_raw = base64.b64decode(original_snapshot.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise LedgerError("managed replay replacement creation snapshot is invalid") from exc
    identity = [
        str(original.get("issueUrl") or ""),
        str(original.get("threadId") or ""),
        str(original.get("commitSha") or ""),
        str(original.get("branch") or ""),
        str(original.get("worktreePath") or ""),
        original_evidence_digest,
        canonical_json(original.get("publication")),
    ]
    if original.get("targetBase") is not None:
        identity.append(canonical_json(original["targetBase"]))
    if (
        event_row["created_at"] != row["created_at"]
        or original.get("requestId") != row["request_id"]
        or sha256_text("|".join(identity)) != row["request_id"]
        or not re.fullmatch(r"[0-9a-f]{64}", original_evidence_digest)
        or hashlib.sha256(original_raw).hexdigest() != original_evidence_digest
        or _managed_replay_immutable_request(original) != _managed_replay_immutable_request(request)
    ):
        raise LedgerError("managed replay replacement creation identity changed")
    return original


def _validate_managed_replay_lineage_authority(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    source_request_id: str,
    source: dict[str, Any],
    lineage: dict[str, Any],
    refreshed_at: str,
) -> None:
    authority_id = lineage.get("authorityEventId")
    continuation_key = str(lineage.get("continuationDedupeKey") or "")
    if (
        not isinstance(authority_id, int)
        or authority_id <= 0
        or not re.fullmatch(r"[0-9a-f]{64}", continuation_key)
    ):
        raise LedgerError("managed replay replacement lineage authority is invalid")
    authority_row = connection.execute(
        "SELECT * FROM events WHERE id=? AND opportunity_key=?",
        (authority_id, opportunity_key),
    ).fetchone()
    continuation_row = connection.execute(
        """SELECT * FROM events
           WHERE opportunity_key=?
             AND event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
             AND dedupe_key=?""",
        (opportunity_key, continuation_key),
    ).fetchone()
    if (
        authority_row is None
        or authority_row["event_type"] != "TASK_RESULT_AUTHORITY_BOUND"
        or continuation_row is None
    ):
        raise LedgerError("managed replay replacement lineage authority is invalid")
    try:
        authority = json.loads(authority_row["payload_json"])
        continuation = json.loads(continuation_row["payload_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise LedgerError("managed replay replacement lineage authority is invalid") from exc
    if not isinstance(authority, dict) or not isinstance(continuation, dict):
        raise LedgerError("managed replay replacement lineage authority is invalid")
    source_result_event_id = authority.get("sourceResultEventId")
    result_row = (
        connection.execute(
            "SELECT * FROM events WHERE id=? AND opportunity_key=?",
            (source_result_event_id, opportunity_key),
        ).fetchone()
        if isinstance(source_result_event_id, int) and source_result_event_id > 0
        else None
    )
    authority_state = {
        field: authority.get(field)
        for field in (
            "taskId",
            "threadId",
            "sourceResultEventId",
            "resultDigest",
            "continuationDedupeKey",
            "tombstoneReceiptDigest",
        )
    }
    tombstone = continuation.get("codePathTombstoneReceipt")
    try:
        refresh_time = parse_time(refreshed_at)
        result_time = parse_time(str(result_row["created_at"] if result_row else ""))
        authority_time = parse_time(str(authority.get("authorityObservedAt") or ""))
        continuation_time = parse_time(str(continuation_row["created_at"]))
    except (TypeError, ValueError) as exc:
        raise LedgerError("managed replay replacement lineage authority is invalid") from exc
    if (
        authority.get("sourcePublicationRequestId") != source_request_id
        or result_row is None
        or result_row["event_type"] != "TASK_RESULT_INGESTED"
        or result_row["dedupe_key"] != source.get("resultDigest")
        or authority.get("continuationDedupeKey") != continuation_key
        or authority.get("taskId") != source.get("intentId")
        or authority.get("threadId") != source.get("threadId")
        or authority.get("resultDigest") != source.get("resultDigest")
        or authority.get("authorityStateDigest") != sha256_json(authority_state)
        or authority.get("authorityObservedAt") != authority_row["created_at"]
        or continuation.get("sourcePublicationRequestId") != source_request_id
        or continuation.get("taskId") != source.get("intentId")
        or continuation.get("threadId") != source.get("threadId")
        or continuation.get("continuationHeadSha") != source.get("commitSha")
        or continuation.get("resultDigest") != source.get("resultDigest")
        or continuation.get("sourceResultEventId") != authority.get("sourceResultEventId")
        or continuation_row["dedupe_key"] != sha256_json(continuation)
        or not isinstance(tombstone, dict)
        or authority.get("tombstoneReceiptDigest") != sha256_json(tombstone)
        or authority_time >= refresh_time
        or continuation_time >= refresh_time
        or not result_time <= continuation_time <= authority_time
    ):
        raise LedgerError("managed replay replacement lineage authority is invalid")


class RadarLedger:
    READ_ONLY_BUSY_TIMEOUT_MS = 1_000

    def __init__(self, path: Path, *, read_only: bool = False):
        self.path = path
        self.read_only = read_only
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()

    def connect(self) -> sqlite3.Connection:
        if self.read_only:
            uri = f"file:{quote(str(self.path.resolve()), safe='/')}?mode=ro"
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=self.READ_ONLY_BUSY_TIMEOUT_MS / 1_000,
                isolation_level=None,
            )
        else:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            f"PRAGMA busy_timeout={self.READ_ONLY_BUSY_TIMEOUT_MS if self.read_only else 30000}"
        )
        if not self.read_only:
            connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS opportunities (
                    key TEXT PRIMARY KEY,
                    repo TEXT NOT NULL,
                    issue_number INTEGER NOT NULL,
                    issue_url TEXT NOT NULL,
                    title TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    snapshot_id TEXT,
                    decision_digest TEXT,
                    terminal_reason TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS intents (
                    intent_id TEXT PRIMARY KEY,
                    opportunity_key TEXT NOT NULL,
                    intent_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_until TEXT,
                    thread_id TEXT,
                    project_id TEXT,
                    worktree_path TEXT,
                    title_time TEXT,
                    title_synced_state TEXT,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(opportunity_key) REFERENCES opportunities(key)
                );
                CREATE INDEX IF NOT EXISTS intents_claimable
                    ON intents(status, expires_at, lease_until);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    opportunity_key TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(opportunity_key, event_type, dedupe_key),
                    FOREIGN KEY(opportunity_key) REFERENCES opportunities(key)
                );
                CREATE TABLE IF NOT EXISTS task_quarantines (
                    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    opportunity_key TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    dedupe_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE','CLEARED')),
                    created_at TEXT NOT NULL,
                    cleared_at TEXT,
                    clear_payload_json TEXT,
                    UNIQUE(opportunity_key, reason, dedupe_key)
                );
                CREATE INDEX IF NOT EXISTS task_quarantines_active_key
                    ON task_quarantines(opportunity_key, status, quarantine_id);
                CREATE TABLE IF NOT EXISTS outcomes (
                    opportunity_key TEXT PRIMARY KEY,
                    selected_at TEXT,
                    submit_ready_at TEXT,
                    external_changed_at TEXT,
                    failure_class TEXT,
                    quality_json TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(opportunity_key) REFERENCES opportunities(key)
                );
                CREATE TABLE IF NOT EXISTS publication_requests (
                    request_id TEXT PRIMARY KEY,
                    opportunity_key TEXT NOT NULL,
                    thread_id TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    worktree_path TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT,
                    permit_id TEXT,
                    request_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(opportunity_key) REFERENCES opportunities(key)
                );
                CREATE TABLE IF NOT EXISTS publication_permits (
                    permit_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    issue_url TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    pr_url TEXT,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES publication_requests(request_id)
                );
                CREATE TABLE IF NOT EXISTS publication_effects (
                    effect_id TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(permit_id, action, request_digest),
                    FOREIGN KEY(permit_id) REFERENCES publication_permits(permit_id)
                );
                CREATE TABLE IF NOT EXISTS pr_followups (
                    opportunity_key TEXT PRIMARY KEY,
                    pr_url TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    task_action_digest TEXT NOT NULL,
                    wake_digest TEXT,
                    actions_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    followup_required INTEGER NOT NULL,
                    checked_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(opportunity_key) REFERENCES opportunities(key)
                );
                """
            )
            backfill_from_radar_events(
                connection, action_guard_root=ledger_action_guard_root(self.path)
            )
            backfill_from_managed_events(
                connection, action_guard_root=ledger_action_guard_root(self.path)
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(intents)")}
            if "title_time" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN title_time TEXT")
            if "title_synced_state" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN title_synced_state TEXT")
            if "creation_token" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN creation_token TEXT")
            if "client_thread_id" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN client_thread_id TEXT")
            if "creation_started_at" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN creation_started_at TEXT")
            now = iso_z(datetime.now(UTC))
            stale_leases = connection.execute(
                """SELECT key FROM opportunities o
                   WHERE o.stage='LEASED'
                     AND NOT EXISTS (
                       SELECT 1 FROM intents i
                       WHERE i.opportunity_key=o.key
                         AND i.status IN ('PENDING','LEASED','CREATING','DISPATCHED','COMPLETED')
                     )"""
            ).fetchall()
            for row in stale_leases:
                connection.execute(
                    """UPDATE opportunities SET stage='AUDIT_PASS',terminal_reason=NULL,
                       updated_at=? WHERE key=?""",
                    (now, row["key"]),
                )
                self._event(
                    connection,
                    row["key"],
                    "LEDGER_STAGE_REPAIRED",
                    "leased_without_active_intent",
                    {"from": "LEASED", "to": "AUDIT_PASS"},
                    now,
                )
            # Historical publication rows predate the authenticated
            # reproduction boundary.  Downgrade only actionable rows; a
            # completed external observation is retained and never replayed.
            legacy_publications = connection.execute(
                "SELECT request_id,request_json,opportunity_key,status FROM publication_requests"
            ).fetchall()
            for row in legacy_publications:
                if _publication_has_irreversible_terminal_evidence(
                    connection,
                    request_id=str(row["request_id"]),
                    opportunity_key=str(row["opportunity_key"]),
                ):
                    connection.execute(
                        """UPDATE publication_requests
                           SET status='CONSUMED',reason=NULL,updated_at=?
                           WHERE request_id=?
                             AND (status<>'CONSUMED' OR reason IS NOT NULL)""",
                        (now, row["request_id"]),
                    )
                    continue
                try:
                    request_payload = json.loads(row["request_json"])
                except (TypeError, json.JSONDecodeError):
                    request_payload = {}
                if _publication_probe_valid(request_payload):
                    continue
                if row["status"] in {"PENDING", "GRANTED", "CONSUMED"}:
                    connection.execute(
                        "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                        ("BLOCKED_REPRODUCTION_REQUIRED", now, row["request_id"]),
                    )
                connection.execute(
                    """UPDATE publication_permits SET status='BLOCKED',updated_at=?
                       WHERE request_id=? AND status IN ('ACTIVE','EXPIRED')""",
                    (now, row["request_id"]),
                )
                connection.execute(
                    """UPDATE publication_effects SET status='BLOCKED',result_json=?,updated_at=?
                       WHERE permit_id IN (SELECT permit_id FROM publication_permits WHERE request_id=?)
                         AND status IN ('ATTEMPTED','RECONCILE_REQUIRED')""",
                    (
                        canonical_json({"ok": False, "reason": "BLOCKED_REPRODUCTION_REQUIRED"}),
                        now,
                        row["request_id"],
                    ),
                )
            drifted_updates = connection.execute(
                """SELECT r.request_id,r.opportunity_key,r.request_json,r.reason
                   FROM publication_requests r
                   JOIN opportunities o ON o.key=r.opportunity_key
                   WHERE r.status='BLOCKED' AND o.stage='FIX_READY'
                     AND r.reason IN ('EXISTING_PR_HEAD_DRIFT','NON_FAST_FORWARD_PR_UPDATE')"""
            ).fetchall()
            for row in drifted_updates:
                self._rearm_followup_for_publication_drift(
                    connection,
                    request_id=row["request_id"],
                    key=row["opportunity_key"],
                    request_json=row["request_json"],
                    reason=row["reason"],
                    now=now,
                )

    @staticmethod
    def _no_go_watermark(connection: sqlite3.Connection, key: str) -> dict[str, str | None] | None:
        terminal = connection.execute(
            """SELECT o.stage,MAX(e.created_at) AS terminal_at
               FROM opportunities o
               LEFT JOIN events e
                 ON e.opportunity_key=o.key AND e.event_type='AUDIT_NO_GO'
               WHERE o.key=?
               GROUP BY o.key,o.stage""",
            (key,),
        ).fetchone()
        if not terminal or terminal["stage"] != "AUDIT_NO_GO" or not terminal["terminal_at"]:
            return None
        audit = connection.execute(
            """SELECT json_extract(
                     payload_json,'$.liveAudit.evidence.issue.updated_at'
                   ) AS issue_updated_at
               FROM events
               WHERE opportunity_key=? AND event_type='AUDIT_PASS'
                 AND created_at<=?
                 AND json_extract(
                   payload_json,'$.liveAudit.evidence.issue.updated_at'
                 ) IS NOT NULL
               ORDER BY created_at DESC LIMIT 1""",
            (key, terminal["terminal_at"]),
        ).fetchone()
        dispatched_intent = connection.execute(
            """SELECT json_extract(payload_json,'$.policyDigest') AS policy_digest
               FROM intents
               WHERE opportunity_key=? AND issued_at<=?
               ORDER BY issued_at DESC LIMIT 1""",
            (key, terminal["terminal_at"]),
        ).fetchone()
        return {
            "terminalAt": str(terminal["terminal_at"]),
            "terminalIssueUpdatedAt": (
                str(audit["issue_updated_at"]) if audit and audit["issue_updated_at"] else None
            ),
            "terminalPolicyDigest": (
                str(dispatched_intent["policy_digest"])
                if dispatched_intent and dispatched_intent["policy_digest"]
                else None
            ),
        }

    @staticmethod
    def _intent_is_stale(
        intent: dict[str, Any], *, issued_at: str, watermark: dict[str, str | None] | None
    ) -> bool:
        if not watermark:
            return False
        terminal_at = str(watermark["terminalAt"])
        terminal_issue_updated = watermark.get("terminalIssueUpdatedAt")
        terminal_policy_digest = watermark.get("terminalPolicyDigest")
        issue_updated = intent.get("issueUpdatedAt")
        issue_unchanged = bool(
            terminal_issue_updated
            and issue_updated
            and parse_time(str(issue_updated)) <= parse_time(str(terminal_issue_updated))
        )
        policy_unchanged = bool(
            not terminal_policy_digest
            or not intent.get("policyDigest")
            or intent.get("policyDigest") == terminal_policy_digest
        )
        return (issue_unchanged and policy_unchanged) or parse_time(issued_at) <= parse_time(
            terminal_at
        )

    def enqueue(self, intent: dict[str, Any]) -> bool:
        now = iso_z(datetime.now(UTC))
        key = str(intent["key"])
        payload = canonical_json(intent)
        with self.transaction() as connection:
            watermark = self._no_go_watermark(connection, key)
            if self._intent_is_stale(
                intent,
                issued_at=str(intent["issuedAt"]),
                watermark=watermark,
            ):
                assert watermark is not None
                self._event(
                    connection,
                    key,
                    "STALE_INTENT_IGNORED",
                    str(intent["intentId"]),
                    {
                        "intentId": intent["intentId"],
                        "issuedAt": intent["issuedAt"],
                        "issueUpdatedAt": intent.get("issueUpdatedAt"),
                        **watermark,
                    },
                    now,
                )
                return False
            existing = connection.execute(
                """SELECT status,expires_at,lease_until,opportunity_key FROM intents
                   WHERE intent_id=?""",
                (intent["intentId"],),
            ).fetchone()
            if existing:
                incoming_expiry = parse_time(str(intent["expiresAt"]))
                renewable = existing["status"] in {
                    "PENDING",
                    "LEASED",
                    "EXPIRED",
                    "SUPERSEDED",
                }
                if renewable and incoming_expiry > datetime.now(UTC):
                    blocking_task = connection.execute(
                        """SELECT intent_id FROM intents
                           WHERE opportunity_key=? AND intent_id<>?
                             AND (
                               (status IN ('PENDING','LEASED') AND expires_at>?)
                               OR status IN ('CREATING','DISPATCHED','COMPLETED')
                             ) LIMIT 1""",
                        (key, intent["intentId"], now),
                    ).fetchone()
                    if blocking_task is not None:
                        connection.execute(
                            """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,
                               lease_until=NULL,updated_at=? WHERE intent_id=?""",
                            (now, intent["intentId"]),
                        )
                        self._event(
                            connection,
                            key,
                            "INTENT_RENEWAL_SUPPRESSED",
                            str(intent["intentId"]),
                            {
                                "intentId": intent["intentId"],
                                "blockingIntentId": blocking_task["intent_id"],
                            },
                            now,
                        )
                        return False
                    lease_active = bool(
                        existing["status"] == "LEASED"
                        and existing["lease_until"]
                        and parse_time(str(existing["lease_until"])) > datetime.now(UTC)
                    )
                    next_status = "LEASED" if lease_active else "PENDING"
                    connection.execute(
                        """UPDATE intents SET status=?,expires_at=?,payload_json=?,
                           lease_owner=CASE WHEN ? THEN lease_owner ELSE NULL END,
                           lease_until=CASE WHEN ? THEN lease_until ELSE NULL END,
                           updated_at=? WHERE intent_id=?""",
                        (
                            next_status,
                            intent["expiresAt"],
                            payload,
                            lease_active,
                            lease_active,
                            now,
                            intent["intentId"],
                        ),
                    )
                return False
            duplicate = connection.execute(
                """SELECT i.intent_id FROM intents i
                   WHERE i.opportunity_key=?
                     AND (
                       (i.status IN ('PENDING','LEASED') AND i.expires_at>?)
                       OR i.status='CREATING'
                       OR i.status IN ('DISPATCHED','COMPLETED')
                       OR (
                         i.status='REJECTED' AND i.intent_digest=?
                         AND NOT EXISTS (
                           SELECT 1 FROM events drift
                            WHERE drift.opportunity_key=i.opportunity_key
                              AND drift.event_type='STATE_DRIFT_RECHECK_REQUIRED'
                              AND json_extract(drift.payload_json,'$.intentId')=i.intent_id
                         )
                       )
                     )
                   LIMIT 1""",
                (key, now, intent.get("decisionDigest") or intent["intentId"]),
            ).fetchone()
            if duplicate:
                return False
            connection.execute(
                """INSERT INTO opportunities
                   (key,repo,issue_number,issue_url,title,stage,first_seen,updated_at,
                    snapshot_id,decision_digest,metadata_json)
                   VALUES (?,?,?,?,?,'QUALIFIED',?,?,?,?,?)
                   ON CONFLICT(key) DO UPDATE SET
                     issue_url=excluded.issue_url,title=excluded.title,
                     updated_at=excluded.updated_at,snapshot_id=excluded.snapshot_id,
                     decision_digest=excluded.decision_digest,
                     stage=CASE
                       WHEN opportunities.stage='AUDIT_NO_GO' THEN 'QUALIFIED'
                       ELSE opportunities.stage
                     END,
                     terminal_reason=CASE
                       WHEN opportunities.stage='AUDIT_NO_GO' THEN NULL
                       ELSE opportunities.terminal_reason
                     END,
                     metadata_json=excluded.metadata_json""",
                (
                    key,
                    intent["repo"],
                    int(intent["issueNumber"]),
                    intent["issueUrl"],
                    intent["title"],
                    now,
                    now,
                    intent.get("snapshotId"),
                    intent.get("decisionDigest"),
                    canonical_json({"mode": intent.get("mode"), "score": intent.get("score")}),
                ),
            )
            connection.execute(
                """INSERT INTO intents
                   (intent_id,opportunity_key,intent_digest,status,issued_at,expires_at,
                    payload_json,updated_at)
                   VALUES (?,?,?,'PENDING',?,?,?,?)""",
                (
                    intent["intentId"],
                    key,
                    intent.get("decisionDigest") or intent["intentId"],
                    intent["issuedAt"],
                    intent["expiresAt"],
                    payload,
                    now,
                ),
            )
            if intent.get("mode") != "shadow":
                connection.execute(
                    """INSERT INTO outcomes
                       (opportunity_key,selected_at,quality_json,updated_at)
                       VALUES (?,?,?,?)
                       ON CONFLICT(opportunity_key) DO UPDATE SET
                         selected_at=COALESCE(outcomes.selected_at,excluded.selected_at),
                         updated_at=excluded.updated_at""",
                    (key, now, "{}", now),
                )
            self._event(connection, key, "QUALIFIED", intent["intentId"], intent, now)
        return True

    def restore_task_context(
        self,
        context: dict[str, Any],
        *,
        source_updated_at: str | None = None,
    ) -> dict[str, Any]:
        """Rebuild durable lifecycle state from a verified controller context mirror."""

        key = str(context.get("key") or "")
        issue_url = str(context.get("issueUrl") or "")
        issue_match = ISSUE_URL_RE.fullmatch(issue_url)
        if not key or issue_match is None:
            raise LedgerError("task context issue identity is invalid")
        repo, issue_number_text = issue_match.groups()
        issue_number = int(issue_number_text)
        if key != f"{repo}#{issue_number}":
            raise LedgerError("task context key does not match issue URL")

        stage = str(context.get("stage") or "")
        intent_status = str(context.get("intentStatus") or "")
        if intent_status not in RECOVERABLE_CONTEXT_INTENT_STATUSES:
            raise LedgerError("task context intent status is not recoverable")
        if stage in {
            "VALIDATION_PENDING",
            "FIX_READY",
            "PR_OPEN",
            "CI_GREEN",
            "MAINTAINER_ACCEPTED",
            "MERGED",
            "CLOSED",
        }:
            intent_status = "COMPLETED"

        intent_id = str(context.get("intentId") or "")
        thread_id = str(context.get("threadId") or "")
        worktree_path = str(context.get("worktreePath") or "")
        context_digest = str(context.get("contextDigest") or "")
        if not all((intent_id, thread_id, worktree_path, context_digest)):
            raise LedgerError("task context lifecycle binding is incomplete")

        live_audit = context.get("liveAudit")
        if not isinstance(live_audit, dict) or not isinstance(live_audit.get("evidence"), dict):
            raise LedgerError("task context live audit is missing")
        evidence = live_audit["evidence"]
        issue = evidence.get("issue")
        if not isinstance(issue, dict):
            raise LedgerError("task context issue snapshot is missing")
        title = str(issue.get("title") or key)
        evidence_digest = str(evidence.get("digest") or context_digest)
        captured_at = str(
            context.get("liveAuditRecordedAt")
            or live_audit.get("capturedAt")
            or source_updated_at
            or iso_z(datetime.now(UTC))
        )
        try:
            parse_time(captured_at)
        except (TypeError, ValueError) as exc:
            raise LedgerError("task context audit timestamp is invalid") from exc
        title_time = str(context.get("titleTime") or "").strip()
        if not re.fullmatch(r"\d{2}-\d{2} \d{2}:\d{2}", title_time):
            title_time = (
                parse_time(captured_at)
                .astimezone(timezone(timedelta(hours=8)))
                .strftime("%m-%d %H:%M")
            )

        if stage not in RECOVERABLE_CONTEXT_STAGES:
            if stage != "DISPATCHED":
                raise LedgerError("task context lifecycle stage is not recoverable")
            current = self.task_context(issue_url=issue_url, thread_id=thread_id)
            immutable_binding = {
                "key": key,
                "intentId": intent_id,
                "threadId": thread_id,
                "worktreePath": str(Path(worktree_path).resolve()),
                "titleTime": title_time,
            }
            if current is None or any(
                current.get(field) != expected for field, expected in immutable_binding.items()
            ):
                raise LedgerError("active task context disagrees with the ledger")
            if context.get("publicationReceipt") is not None:
                raise LedgerError("active task context has an unexpected publication receipt")
            current_stage = str(current.get("stage") or "")
            if current_stage != stage:
                if current_stage == "AUDIT_NO_GO":
                    return {
                        "key": key,
                        "stage": current_stage,
                        "intentRestored": False,
                        "publicationRestored": False,
                        "supersededActiveMirror": True,
                    }
                if current_stage not in RECOVERABLE_CONTEXT_STAGES:
                    raise LedgerError("active task context disagrees with the ledger")
                return {
                    "key": key,
                    "stage": current_stage,
                    "intentRestored": False,
                    "publicationRestored": False,
                    "supersededActiveMirror": True,
                }
            expected_active = {
                "stage": stage,
                "intentStatus": intent_status,
                "liveAudit": live_audit,
                "targetBase": context.get("targetBase"),
            }
            if any(current.get(field) != expected for field, expected in expected_active.items()):
                raise LedgerError("active task context disagrees with the ledger")
            return {
                "key": key,
                "stage": stage,
                "intentRestored": False,
                "publicationRestored": False,
            }

        receipt = context.get("publicationReceipt")
        if receipt is not None and not isinstance(receipt, dict):
            raise LedgerError("task context publication receipt is invalid")
        if stage in PUBLISHED_STAGES:
            if not isinstance(receipt, dict) or not PR_URL_RE.fullmatch(
                str(receipt.get("prUrl") or "")
            ):
                raise LedgerError("published task context is missing a pull request receipt")
        if isinstance(receipt, dict) and receipt.get("prUrl"):
            pr_match = PR_URL_RE.fullmatch(str(receipt.get("prUrl")))
            if pr_match is None:
                raise LedgerError("task context pull request URL is invalid")
            if pr_match.group(1).casefold() != repo.casefold():
                raise LedgerError("task context pull request repository is invalid")
            if not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("commitSha") or "")):
                raise LedgerError("task context publication commit is invalid")
            if not str(receipt.get("branch") or "").strip():
                raise LedgerError("task context publication branch is missing")

        recovered_reproduction_receipt = None
        recovered_receipt_bundle: dict[str, Any] | None = None
        recovered_current_result_bundle: dict[str, str] | None = None
        recovered_context_continuation: dict[str, Any] | None = None
        tombstone_receipt = context.get("codePathTombstoneReceipt")
        if tombstone_receipt is not None:
            reproduction_receipt = context.get("reproductionReceipt")
            followup = context.get("prFollowup")
            context_result_digest = str(context.get("resultDigest") or "")
            context_head_sha = str(context.get("headSha") or "")
            context_commit_sha = str(context.get("commitSha") or "")
            code_paths = [
                str(path) for path in (context.get("codePaths") or []) if str(path).strip()
            ]
            if (
                not isinstance(reproduction_receipt, dict)
                or not isinstance(tombstone_receipt, dict)
                or not isinstance(followup, dict)
                or not code_paths
                or context.get("selectedBaseSha") != reproduction_receipt.get("baseSha")
                or not re.fullmatch(r"[0-9a-f]{64}", context_result_digest)
                or not re.fullmatch(r"[0-9a-f]{40}", context_head_sha)
                or context_commit_sha != context_head_sha
                or context_head_sha != tombstone_receipt.get("preparedHeadSha")
                or not verify_probe_receipt(
                    reproduction_receipt,
                    repo=repo,
                    base_sha=str(reproduction_receipt.get("baseSha") or ""),
                    code_paths=code_paths,
                    required_level=REPRODUCED_VALIDATED,
                    issue_url=issue_url,
                    task_id=intent_id,
                    thread_id=(
                        thread_id if reproduction_receipt.get("threadFingerprint") else None
                    ),
                    head_sha=str(reproduction_receipt.get("headSha") or ""),
                    commit_sha=str(reproduction_receipt.get("commitSha") or ""),
                    result_digest=str(reproduction_receipt.get("resultDigest") or ""),
                    enforce_freshness=False,
                )
                or not verify_code_path_tombstone_receipt(
                    tombstone_receipt,
                    source_receipt_digest=str(reproduction_receipt.get("receiptDigest") or ""),
                    base_sha=str(reproduction_receipt.get("baseSha") or ""),
                    key=key,
                    issue_url=issue_url,
                    intent_id=intent_id,
                    thread_id=thread_id,
                    worktree_path_fingerprint=sha256_text(str(Path(worktree_path).resolve())),
                    pr_url=str(followup.get("prUrl") or ""),
                    wake_digest=str(followup.get("wakeDigest") or ""),
                    action_digest=str(followup.get("actionDigest") or ""),
                    task_action_digest=str(followup.get("taskActionDigest") or ""),
                    checked_at=str(followup.get("checkedAt") or ""),
                    prepared_head_sha=str(followup.get("preparedHeadSha") or ""),
                    code_paths=code_paths,
                )
            ):
                raise LedgerError("task context tombstone authority is invalid")
            recovered_reproduction_receipt = reproduction_receipt
            receipt_digest = str(reproduction_receipt.get("receiptDigest") or "")
            context_receipt_digest = str(context.get("probeReceiptDigest") or "")
            if context_receipt_digest and context_receipt_digest != receipt_digest:
                raise LedgerError("task context tombstone probe receipt digest disagrees")
            recovered_receipt_bundle = {
                "recoveredReproductionReceipt": reproduction_receipt,
                "probeReceiptDigest": receipt_digest,
                "selectedBaseSha": reproduction_receipt.get("baseSha"),
                "codePaths": list(reproduction_receipt.get("codePaths") or []),
            }
            recovered_current_result_bundle = {
                "resultDigest": context_result_digest,
                "headSha": context_head_sha,
                "commitSha": context_commit_sha,
            }
            followup_snapshot = dict(followup)
            followup_snapshot.pop("resultContract", None)
            recovered_context_continuation = {
                "taskId": intent_id,
                "threadId": thread_id,
                "contextDigest": context_digest,
                **recovered_current_result_bundle,
                "followupWakeDigest": followup.get("wakeDigest"),
                "codePathTombstoneReceipt": tombstone_receipt,
                "continuationHeadSha": context_head_sha,
                "prFollowupSnapshot": followup_snapshot,
            }

        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        payload = {
            "intentId": intent_id,
            "key": key,
            "repo": repo,
            "issueNumber": issue_number,
            "issueUrl": issue_url,
            "issueUpdatedAt": issue.get("updated_at"),
            "policyDigest": (
                evidence.get("policy", {}).get("digest")
                if isinstance(evidence.get("policy"), dict)
                else None
            ),
            "title": title,
            "mode": context.get("publicationMode") or "canary",
            "track": context.get("track") or "agent_ai_infra",
            "category": context.get("category"),
            "algorithmEvidence": context.get("algorithmEvidence"),
            "snapshotId": evidence_digest,
            "decisionDigest": context_digest,
            "issuedAt": captured_at,
            "expiresAt": iso_z(now_dt + timedelta(hours=1)),
            "autoSubmitAuthorized": context.get("autoSubmitAuthorized") is True,
            "publicSubmissionAllowed": context.get("publicSubmissionAllowed") is True,
            "authorizationSource": context.get("authorizationSource"),
            "publicationMode": context.get("publicationMode"),
            "taskStage": context.get("taskStage") or "REPRODUCTION_REQUIRED",
            "probeLevel": context.get("probeLevel") or "UNVERIFIED",
            "probeReceiptDigest": context.get("probeReceiptDigest"),
            "selectedBaseSha": context.get("selectedBaseSha"),
            "codePaths": context.get("codePaths") or [],
            "resultDigest": context.get("resultDigest"),
            "headSha": context.get("headSha"),
            "commitSha": context.get("commitSha"),
            "targetBase": context.get("targetBase"),
            "recoveredFromTaskContext": True,
            "titleTime": title_time,
        }
        if recovered_reproduction_receipt is not None:
            payload["recoveredReproductionReceipt"] = recovered_reproduction_receipt
        authority_observed_at = str(source_updated_at or captured_at)
        try:
            authority_observed_time = parse_time(authority_observed_at)
        except (TypeError, ValueError) as exc:
            raise LedgerError("task context source timestamp is invalid") from exc
        continuation_dedupe_key = (
            sha256_json(recovered_context_continuation)
            if recovered_context_continuation is not None
            else None
        )
        tombstone_receipt_digest = (
            sha256_json(tombstone_receipt)
            if recovered_context_continuation is not None and isinstance(tombstone_receipt, dict)
            else None
        )
        context_authority_state = {
            "taskId": intent_id,
            "threadId": thread_id,
            "contextDigest": context_digest,
            "hasContinuation": recovered_context_continuation is not None,
            "continuationDedupeKey": continuation_dedupe_key,
            "probeReceiptDigest": (
                str(recovered_reproduction_receipt.get("receiptDigest") or "")
                if isinstance(recovered_reproduction_receipt, dict)
                else None
            ),
            "tombstoneReceiptDigest": tombstone_receipt_digest,
            "implementationClaimed": bool(recovered_context_continuation)
            or (
                str(context.get("taskStage") or "") == "IMPLEMENTATION_READY"
                and str(context.get("probeLevel") or "") == REPRODUCED_VALIDATED
            ),
        }
        context_authority_state_digest = sha256_json(context_authority_state)
        context_authority_marker = context_authority_state | {
            "authorityObservedAt": authority_observed_at,
            "authorityStateDigest": context_authority_state_digest,
        }
        restored_intent = False
        restored_publication = False
        with self.transaction() as connection:
            existing_intent = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if existing_intent is not None and existing_intent["opportunity_key"] != key:
                raise LedgerError("task context intent is bound to another opportunity")
            latest_authority_row = connection.execute(
                """SELECT id,payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                     AND json_extract(payload_json,'$.taskId')=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, intent_id, thread_id),
            ).fetchone()
            latest_authority: dict[str, Any] | None = None
            if latest_authority_row is not None:
                try:
                    latest_authority = json.loads(latest_authority_row["payload_json"])
                    latest_observed_time = parse_time(
                        str(latest_authority.get("authorityObservedAt") or "")
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise LedgerError("task context authority marker is invalid") from exc
                if authority_observed_time < latest_observed_time:
                    return {
                        "key": key,
                        "stage": stage,
                        "intentRestored": False,
                        "publicationRestored": False,
                        "supersededContextMirror": True,
                    }
                if latest_authority.get("authorityStateDigest") == context_authority_state_digest:
                    watermark_advanced = authority_observed_time > latest_observed_time
                    if watermark_advanced:
                        context_authority_marker["authorityTransition"] = False
                        for field in (
                            "revokedContinuationDedupeKey",
                            "revokedTombstoneReceiptDigest",
                            "revocationObservedAt",
                        ):
                            if latest_authority.get(field):
                                context_authority_marker[field] = latest_authority[field]
                        if recovered_context_continuation is None and (
                            context_authority_marker.get("revokedContinuationDedupeKey")
                            or context_authority_marker.get("revokedTombstoneReceiptDigest")
                        ):
                            context_authority_marker["revocationObservedAt"] = authority_observed_at
                        self._event(
                            connection,
                            key,
                            "TASK_CONTEXT_AUTHORITY_BOUND",
                            sha256_json(context_authority_marker),
                            context_authority_marker,
                            authority_observed_at,
                        )
                    return {
                        "key": key,
                        "stage": stage,
                        "intentRestored": False,
                        "publicationRestored": False,
                        "duplicateContextMirror": True,
                        "authorityWatermarkAdvanced": watermark_advanced,
                    }
                if (
                    authority_observed_time == latest_observed_time
                    and recovered_context_continuation is not None
                ):
                    return {
                        "key": key,
                        "stage": stage,
                        "intentRestored": False,
                        "publicationRestored": False,
                        "supersededContextMirror": True,
                    }

            historical_continuation_rows = connection.execute(
                """SELECT dedupe_key,payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type IN (
                       'TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND',
                       'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                     )
                     AND json_extract(payload_json,'$.taskId')=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id""",
                (key, intent_id, thread_id),
            ).fetchall()
            historical_continuation_refs: set[str] = set()
            historical_tombstone_digests: set[str] = set()
            for historical_row in historical_continuation_rows:
                historical_continuation_refs.add(str(historical_row["dedupe_key"]))
                try:
                    historical_payload = json.loads(historical_row["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("task context continuation history is invalid") from exc
                historical_tombstone = historical_payload.get("codePathTombstoneReceipt")
                if isinstance(historical_tombstone, dict):
                    historical_tombstone_digests.add(sha256_json(historical_tombstone))

            if (
                recovered_context_continuation is not None
                and latest_authority is None
                and historical_continuation_rows
                and (
                    continuation_dedupe_key in historical_continuation_refs
                    or tombstone_receipt_digest in historical_tombstone_digests
                )
            ):
                return {
                    "key": key,
                    "stage": stage,
                    "intentRestored": False,
                    "publicationRestored": False,
                    "supersededContextMirror": True,
                }

            if recovered_context_continuation is not None and latest_authority is not None:
                latest_has_continuation = latest_authority.get("hasContinuation") is True
                latest_continuation_ref = str(latest_authority.get("continuationDedupeKey") or "")
                latest_tombstone_digest = str(latest_authority.get("tombstoneReceiptDigest") or "")
                replayed_after_revocation = not latest_has_continuation and (
                    continuation_dedupe_key in historical_continuation_refs
                    or tombstone_receipt_digest in historical_tombstone_digests
                )
                replayed_superseded_context = (
                    latest_has_continuation
                    and latest_continuation_ref != continuation_dedupe_key
                    and continuation_dedupe_key in historical_continuation_refs
                )
                replayed_superseded_receipt = (
                    latest_has_continuation
                    and latest_tombstone_digest != tombstone_receipt_digest
                    and tombstone_receipt_digest in historical_tombstone_digests
                )
                if (
                    replayed_after_revocation
                    or replayed_superseded_context
                    or replayed_superseded_receipt
                ):
                    return {
                        "key": key,
                        "stage": stage,
                        "intentRestored": False,
                        "publicationRestored": False,
                        "supersededContextMirror": True,
                    }

            if latest_authority is not None:
                for field in (
                    "revokedContinuationDedupeKey",
                    "revokedTombstoneReceiptDigest",
                    "revocationObservedAt",
                ):
                    if latest_authority.get(field):
                        context_authority_marker[field] = latest_authority[field]
            elif (
                recovered_context_continuation is not None
                and historical_continuation_rows
                and continuation_dedupe_key not in historical_continuation_refs
                and tombstone_receipt_digest not in historical_tombstone_digests
            ):
                superseded_legacy_continuation = historical_continuation_rows[-1]
                context_authority_marker["revokedContinuationDedupeKey"] = str(
                    superseded_legacy_continuation["dedupe_key"]
                )
                superseded_legacy_payload = json.loads(
                    superseded_legacy_continuation["payload_json"]
                )
                superseded_legacy_tombstone = superseded_legacy_payload.get(
                    "codePathTombstoneReceipt"
                )
                if isinstance(superseded_legacy_tombstone, dict):
                    context_authority_marker["revokedTombstoneReceiptDigest"] = sha256_json(
                        superseded_legacy_tombstone
                    )
                context_authority_marker["revocationObservedAt"] = authority_observed_at

            if recovered_context_continuation is None:
                revoked_continuation_ref = None
                revoked_tombstone_digest = None
                if latest_authority is not None:
                    revoked_continuation_ref = latest_authority.get(
                        "continuationDedupeKey"
                    ) or latest_authority.get("revokedContinuationDedupeKey")
                    revoked_tombstone_digest = latest_authority.get(
                        "tombstoneReceiptDigest"
                    ) or latest_authority.get("revokedTombstoneReceiptDigest")
                if revoked_continuation_ref is None and historical_continuation_rows:
                    legacy_continuation = historical_continuation_rows[-1]
                    revoked_continuation_ref = str(legacy_continuation["dedupe_key"])
                    legacy_payload = json.loads(legacy_continuation["payload_json"])
                    legacy_tombstone = legacy_payload.get("codePathTombstoneReceipt")
                    if isinstance(legacy_tombstone, dict):
                        revoked_tombstone_digest = sha256_json(legacy_tombstone)
                if revoked_continuation_ref:
                    context_authority_marker["revokedContinuationDedupeKey"] = str(
                        revoked_continuation_ref
                    )
                if revoked_tombstone_digest:
                    context_authority_marker["revokedTombstoneReceiptDigest"] = str(
                        revoked_tombstone_digest
                    )
                if revoked_continuation_ref or revoked_tombstone_digest:
                    context_authority_marker["revocationObservedAt"] = authority_observed_at
            context_authority_marker["authorityTransition"] = True
            restored_intent = existing_intent is None
            existing_opportunity = connection.execute(
                "SELECT stage,first_seen FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if existing_opportunity is None:
                final_stage = stage
                connection.execute(
                    """INSERT INTO opportunities
                       (key,repo,issue_number,issue_url,title,stage,first_seen,updated_at,
                        snapshot_id,decision_digest,terminal_reason,metadata_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)""",
                    (
                        key,
                        repo,
                        issue_number,
                        issue_url,
                        title,
                        final_stage,
                        captured_at,
                        now,
                        evidence_digest,
                        context_digest,
                        canonical_json({"recoveredFromTaskContext": True}),
                    ),
                )
            else:
                current_stage = str(existing_opportunity["stage"])
                if not restored_intent or current_stage in TERMINAL_STAGES:
                    final_stage = current_stage
                elif RECOVERED_STAGE_RANK.get(stage, -1) >= RECOVERED_STAGE_RANK.get(
                    current_stage, -1
                ):
                    final_stage = stage
                else:
                    final_stage = current_stage
                connection.execute(
                    """UPDATE opportunities SET repo=?,issue_number=?,issue_url=?,title=?,
                       stage=?,updated_at=?,snapshot_id=COALESCE(snapshot_id,?),
                       decision_digest=COALESCE(decision_digest,?),
                       metadata_json=? WHERE key=?""",
                    (
                        repo,
                        issue_number,
                        issue_url,
                        title,
                        final_stage,
                        now,
                        evidence_digest,
                        context_digest,
                        canonical_json({"recoveredFromTaskContext": True}),
                        key,
                    ),
                )

            if restored_intent:
                title_state = RECOVERED_TITLE_STATE[final_stage]
                connection.execute(
                    """INSERT INTO intents
                       (intent_id,opportunity_key,intent_digest,status,issued_at,expires_at,
                        lease_owner,lease_until,thread_id,project_id,worktree_path,title_time,
                        title_synced_state,payload_json,updated_at)
                       VALUES (?,?,?,?,?,?,NULL,NULL,?,'github',?,?,?,?,?)""",
                    (
                        intent_id,
                        key,
                        context_digest,
                        intent_status,
                        captured_at,
                        payload["expiresAt"],
                        thread_id,
                        str(Path(worktree_path).resolve()),
                        title_time,
                        title_state,
                        canonical_json(payload),
                        now,
                    ),
                )
            else:
                existing_thread = str(existing_intent["thread_id"] or "")
                existing_worktree = str(existing_intent["worktree_path"] or "")
                if existing_thread and existing_thread != thread_id:
                    raise LedgerError("task context thread binding disagrees with the ledger")
                if (
                    existing_worktree
                    and Path(existing_worktree).resolve() != Path(worktree_path).resolve()
                ):
                    raise LedgerError("task context worktree binding disagrees with the ledger")
                existing_payload = json.loads(existing_intent["payload_json"])
                if not isinstance(existing_payload, dict):
                    raise LedgerError("task context intent payload is invalid")
                payload_changed = False
                if recovered_receipt_bundle is not None:
                    for field, recovered_value in recovered_receipt_bundle.items():
                        if field not in existing_payload or existing_payload[field] is None:
                            existing_payload[field] = recovered_value
                            payload_changed = True
                            continue
                        current_value = existing_payload[field]
                        if field == "codePaths":
                            current_value = (
                                sorted({str(path) for path in current_value if str(path).strip()})
                                if isinstance(current_value, list)
                                else current_value
                            )
                            recovered_value = sorted(
                                {str(path) for path in recovered_value if str(path).strip()}
                            )
                        if current_value != recovered_value:
                            raise LedgerError(
                                f"task context recovered receipt conflicts with intent {field}"
                            )
                elif "recoveredReproductionReceipt" in existing_payload:
                    existing_payload.pop("recoveredReproductionReceipt", None)
                    payload_changed = True
                for field in ("taskStage", "probeLevel"):
                    if existing_payload.get(field) != payload.get(field):
                        existing_payload[field] = payload.get(field)
                        payload_changed = True
                if recovered_current_result_bundle is not None:
                    for field, recovered_value in recovered_current_result_bundle.items():
                        if existing_payload.get(field) != recovered_value:
                            existing_payload[field] = recovered_value
                            payload_changed = True
                title_time_missing = not str(existing_intent["title_time"] or "")
                if payload_changed or title_time_missing:
                    connection.execute(
                        """UPDATE intents SET payload_json=?,
                           title_time=CASE WHEN title_time IS NULL OR title_time=''
                                           THEN ? ELSE title_time END,
                           updated_at=? WHERE intent_id=?""",
                        (canonical_json(existing_payload), title_time, now, intent_id),
                    )
            connection.execute(
                """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,lease_until=NULL,
                   updated_at=? WHERE opportunity_key=? AND intent_id<>?
                     AND status IN ('PENDING','LEASED','CREATING')""",
                (now, key, intent_id),
            )
            connection.execute(
                """INSERT INTO outcomes
                   (opportunity_key,selected_at,submit_ready_at,quality_json,updated_at)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(opportunity_key) DO UPDATE SET
                     selected_at=COALESCE(outcomes.selected_at,excluded.selected_at),
                     submit_ready_at=COALESCE(outcomes.submit_ready_at,excluded.submit_ready_at),
                     updated_at=excluded.updated_at""",
                (
                    key,
                    captured_at,
                    captured_at if final_stage in {"FIX_READY"} | PUBLISHED_STAGES else None,
                    canonical_json({"recoveredFromTaskContext": True}),
                    now,
                ),
            )
            self._event(
                connection,
                key,
                "AUDIT_SNAPSHOT",
                f"recovered:{context_digest}",
                {
                    "liveAudit": live_audit,
                    "targetBase": context.get("targetBase"),
                    "recoveredFromTaskContext": True,
                },
                captured_at,
            )
            if recovered_context_continuation is not None:
                self._event(
                    connection,
                    key,
                    "TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND",
                    str(continuation_dedupe_key),
                    recovered_context_continuation,
                    captured_at,
                )
            self._event(
                connection,
                key,
                "TASK_CONTEXT_AUTHORITY_BOUND",
                sha256_json(context_authority_marker),
                context_authority_marker,
                authority_observed_at,
            )

            if isinstance(receipt, dict) and receipt.get("prUrl"):
                pr_url = str(receipt["prUrl"])
                commit_sha = str(receipt["commitSha"])
                branch = str(receipt["branch"])
                request_id = sha256_text(f"task-context-recovery|{key}|{pr_url}|{commit_sha}")
                permit_id = sha256_text(f"task-context-recovery-permit|{request_id}")
                requested_at = str(receipt.get("requestedAt") or captured_at)
                updated_at = str(receipt.get("updatedAt") or source_updated_at or now)
                for timestamp in (requested_at, updated_at):
                    try:
                        parse_time(timestamp)
                    except (TypeError, ValueError) as exc:
                        raise LedgerError("task context publication timestamp is invalid") from exc
                request = {
                    "requestId": request_id,
                    "opportunityKey": key,
                    "intentId": intent_id,
                    "issueUrl": issue_url,
                    "threadId": thread_id,
                    "commitSha": commit_sha,
                    "branch": branch,
                    "worktreePath": str(Path(worktree_path).resolve()),
                    "evidenceDigest": evidence_digest,
                    "evidencePath": str(context.get("resultPath") or ""),
                    "publication": {},
                    "intent": payload,
                    "publicationKind": "PR_CREATE",
                    "recoveredFromTaskContext": True,
                }
                request["targetBase"] = context.get("targetBase")
                # This path restores an already public PR from its verified
                # controller context.  Probe freshness is a pre-publication
                # authorization constraint, not authority to revoke this
                # irreversible receipt during a later read recovery.
                recovered_terminal = stage in PUBLISHED_STAGES
                existing_publication = connection.execute(
                    """SELECT r.opportunity_key FROM publication_permits p
                       JOIN publication_requests r ON r.request_id=p.request_id
                       WHERE p.pr_url=? AND p.status IN ('CONSUMED','BLOCKED')""",
                    (pr_url,),
                ).fetchone()
                if (
                    existing_publication is not None
                    and existing_publication["opportunity_key"] != key
                ):
                    raise LedgerError("task context pull request is bound to another opportunity")
                restored_publication = existing_publication is None
                if restored_publication:
                    connection.execute(
                        """INSERT INTO publication_requests
                           (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                            evidence_digest,status,reason,permit_id,request_json,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            request_id,
                            key,
                            thread_id,
                            commit_sha,
                            branch,
                            str(Path(worktree_path).resolve()),
                            evidence_digest,
                            "CONSUMED" if recovered_terminal else "BLOCKED",
                            None if recovered_terminal else "BLOCKED_REPRODUCTION_REQUIRED",
                            permit_id if recovered_terminal else None,
                            canonical_json(request),
                            requested_at,
                            updated_at,
                        ),
                    )
                    connection.execute(
                        """INSERT INTO publication_permits
                           (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                            pr_url,evidence_json,created_at,updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            permit_id,
                            request_id,
                            issue_url,
                            commit_sha,
                            branch,
                            "CONSUMED" if recovered_terminal else "BLOCKED",
                            updated_at,
                            pr_url,
                            canonical_json(
                                {
                                    "contextDigest": context_digest,
                                    "recoveredFromTaskContext": True,
                                    "authorizationStatus": "AUTHENTICATED"
                                    if recovered_terminal
                                    else "BLOCKED_REPRODUCTION_REQUIRED",
                                }
                            ),
                            requested_at,
                            updated_at,
                        ),
                    )
                    if recovered_terminal:
                        self._event(
                            connection,
                            key,
                            "PR_OPEN",
                            pr_url,
                            {"permitId": permit_id, "prUrl": pr_url, "recovered": True},
                            updated_at,
                        )

            self._event(
                connection,
                key,
                "TASK_CONTEXT_RECOVERED",
                context_digest,
                {
                    "intentId": intent_id,
                    "threadId": thread_id,
                    "worktreePath": str(Path(worktree_path).resolve()),
                    "stage": final_stage,
                    "publicationRestored": restored_publication,
                },
                now,
            )
        return {
            "key": key,
            "stage": final_stage,
            "intentRestored": restored_intent,
            "publicationRestored": restored_publication,
        }

    def reconcile_terminal_intents(self) -> list[str]:
        """Reject active intents superseded by a later no-go decision."""
        now = iso_z(datetime.now(UTC))
        rejected: list[str] = []
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT i.intent_id,i.opportunity_key,i.issued_at,i.payload_json
                   FROM intents i
                   JOIN opportunities o ON o.key=i.opportunity_key
                   WHERE o.stage='AUDIT_NO_GO'
                     AND i.status IN ('PENDING','LEASED','CREATING','DISPATCHED')"""
            ).fetchall()
            for row in rows:
                intent = json.loads(row["payload_json"])
                watermark = self._no_go_watermark(connection, str(row["opportunity_key"]))
                if not self._intent_is_stale(
                    intent,
                    issued_at=str(row["issued_at"]),
                    watermark=watermark,
                ):
                    continue
                assert watermark is not None
                connection.execute(
                    """UPDATE intents SET status='REJECTED',lease_owner=NULL,
                       lease_until=NULL,updated_at=? WHERE intent_id=?""",
                    (now, row["intent_id"]),
                )
                self._event(
                    connection,
                    str(row["opportunity_key"]),
                    "STALE_INTENT_REJECTED",
                    str(row["intent_id"]),
                    {
                        "intentId": row["intent_id"],
                        "issuedAt": row["issued_at"],
                        "issueUpdatedAt": intent.get("issueUpdatedAt"),
                        **watermark,
                    },
                    now,
                )
                rejected.append(str(row["intent_id"]))
        return rejected

    def reconcile_pending(self, active_intent_ids: set[str]) -> list[str]:
        """Supersede local, uncommitted work that the latest signed queue withdrew."""
        now = iso_z(datetime.now(UTC))
        superseded: list[str] = []
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT intent_id,opportunity_key FROM intents
                   WHERE status IN ('PENDING','LEASED')"""
            ).fetchall()
            for row in rows:
                intent_id = str(row["intent_id"])
                if intent_id in active_intent_ids:
                    continue
                connection.execute(
                    """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,
                       lease_until=NULL,updated_at=? WHERE intent_id=?""",
                    (now, intent_id),
                )
                connection.execute(
                    """UPDATE opportunities SET stage='AUDIT_PASS',terminal_reason=NULL,
                       updated_at=?
                       WHERE key=? AND stage='LEASED'
                         AND NOT EXISTS (
                           SELECT 1 FROM intents
                           WHERE opportunity_key=? AND intent_id<>?
                             AND status IN ('PENDING','LEASED','CREATING','DISPATCHED','COMPLETED')
                         )""",
                    (now, row["opportunity_key"], row["opportunity_key"], intent_id),
                )
                self._event(
                    connection,
                    str(row["opportunity_key"]),
                    "INTENT_SUPERSEDED",
                    intent_id,
                    {"intentId": intent_id, "reason": "absent_from_latest_signed_queue"},
                    now,
                )
                superseded.append(intent_id)
        return superseded

    def supersede_intents_for_scanner_revision(
        self,
        *,
        scanner_version: str,
        decision_contract_digest: str,
        contract_digest: str,
        queue_digest: str,
    ) -> list[str]:
        """Retire only unstarted local work tied to a verified obsolete scanner tuple."""

        if not all((scanner_version, decision_contract_digest, contract_digest, queue_digest)):
            raise LedgerError("stale scanner supersede evidence is incomplete")
        now = iso_z(datetime.now(UTC))
        superseded: list[str] = []
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT intent_id,opportunity_key,payload_json FROM intents
                   WHERE status IN ('PENDING','LEASED')"""
            ).fetchall()
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, json.JSONDecodeError):
                    continue
                if (
                    payload.get("scannerVersion") != scanner_version
                    or payload.get("decisionContractDigest") != decision_contract_digest
                    or payload.get("contractDigest") != contract_digest
                ):
                    continue
                intent_id = str(row["intent_id"])
                key = str(row["opportunity_key"])
                connection.execute(
                    """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,
                       lease_until=NULL,updated_at=? WHERE intent_id=?
                       AND status IN ('PENDING','LEASED')""",
                    (now, intent_id),
                )
                connection.execute(
                    """UPDATE opportunities SET stage='AUDIT_PASS',terminal_reason=NULL,
                       updated_at=?
                       WHERE key=? AND stage='LEASED'
                         AND NOT EXISTS (
                           SELECT 1 FROM intents
                           WHERE opportunity_key=? AND intent_id<>?
                             AND status IN ('PENDING','LEASED','CREATING','DISPATCHED','COMPLETED')
                         )""",
                    (now, key, key, intent_id),
                )
                self._event(
                    connection,
                    key,
                    "INTENT_SUPERSEDED",
                    f"stale-scanner:{scanner_version}:{queue_digest}:{intent_id}",
                    {
                        "intentId": intent_id,
                        "reason": "stale_scanner_decision_revision",
                        "scannerVersion": scanner_version,
                        "decisionContractDigest": decision_contract_digest,
                        "contractDigest": contract_digest,
                        "queueDigest": queue_digest,
                    },
                    now,
                )
                superseded.append(intent_id)
        return superseded

    def supersede_missing_workspace(
        self,
        *,
        key: str,
        intent_id: str,
        worktree_path: str,
        replacement_intent_id: str,
    ) -> bool:
        """Retire a lost private task only when a fresh signed intent replaces it."""

        if not replacement_intent_id or replacement_intent_id == intent_id:
            return False
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT i.status,i.worktree_path,o.stage
                   FROM intents i JOIN opportunities o ON o.key=i.opportunity_key
                   WHERE i.intent_id=? AND i.opportunity_key=?""",
                (intent_id, key),
            ).fetchone()
            if row is None:
                return False
            if row["status"] not in {"DISPATCHED", "COMPLETED"}:
                return False
            if row["stage"] not in {"DISPATCHED", "VALIDATION_PENDING", "FIX_READY"}:
                return False
            if Path(str(row["worktree_path"] or "")).resolve() != Path(worktree_path).resolve():
                raise LedgerError("missing workspace binding disagrees with the ledger")
            if connection.execute(
                "SELECT 1 FROM publication_requests WHERE opportunity_key=? LIMIT 1", (key,)
            ).fetchone():
                return False
            connection.execute(
                """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,
                          lease_until=NULL,updated_at=? WHERE intent_id=?""",
                (now, intent_id),
            )
            connection.execute(
                """UPDATE opportunities SET stage='QUALIFIED',terminal_reason=NULL,
                          updated_at=? WHERE key=?""",
                (now, key),
            )
            self._event(
                connection,
                key,
                "MISSING_WORKSPACE_SUPERSEDED",
                f"{intent_id}:{replacement_intent_id}",
                {
                    "intentId": intent_id,
                    "replacementIntentId": replacement_intent_id,
                    "worktreePath": str(Path(worktree_path).resolve()),
                },
                now,
            )
        return True

    def claim(
        self,
        intent_id: str,
        owner: str,
        *,
        lease_minutes: int = 15,
        max_active: int | None = None,
    ) -> dict[str, Any] | None:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        lease_until = iso_z(now_dt + timedelta(minutes=max(1, min(lease_minutes, 30))))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None or row["status"] not in {"PENDING", "LEASED"}:
                return None
            if parse_time(row["expires_at"]) <= now_dt:
                connection.execute(
                    "UPDATE intents SET status='EXPIRED',updated_at=? WHERE intent_id=?",
                    (now, intent_id),
                )
                return None
            # A live lease is exclusive even when a later controller happens to
            # reuse the same owner label. This prevents overlapping automation
            # runs from both creating a task from one signed intent.
            if row["lease_until"] and parse_time(row["lease_until"]) > now_dt:
                return None
            if max_active is not None:
                active = self._active_task_count(
                    connection,
                    now=now,
                    exclude_intent_id=intent_id,
                )
                if int(active) >= max(0, max_active):
                    return None
            connection.execute(
                """UPDATE intents SET status='LEASED',lease_owner=?,lease_until=?,updated_at=?
                   WHERE intent_id=?""",
                (owner, lease_until, now, intent_id),
            )
            connection.execute(
                "UPDATE opportunities SET stage='LEASED',updated_at=? WHERE key=?",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "LEASED",
                f"{intent_id}:{owner}:{lease_until}",
                {"intentId": intent_id, "owner": owner, "leaseUntil": lease_until},
                now,
            )
            payload = json.loads(row["payload_json"])
            payload["leaseUntil"] = lease_until
            return payload

    def release_claim(self, intent_id: str, *, owner: str, reason: str) -> bool:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT opportunity_key,status,lease_owner,lease_until FROM intents "
                "WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if row is None or row["status"] != "LEASED" or row["lease_owner"] != owner:
                return False
            connection.execute(
                """UPDATE intents SET status='PENDING',lease_owner=NULL,lease_until=NULL,
                   updated_at=? WHERE intent_id=?""",
                (now, intent_id),
            )
            connection.execute(
                """UPDATE opportunities SET stage='AUDIT_PASS',terminal_reason=NULL,
                   updated_at=? WHERE key=?""",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "LEASE_RELEASED",
                f"{intent_id}:{row['lease_until']}",
                {"intentId": intent_id, "owner": owner, "reason": reason},
                now,
            )
            return True

    def update_intent_probe_metadata(
        self,
        intent_id: str,
        *,
        probe_level: str,
        task_stage: str,
        receipt_digest: str,
        code_paths: list[str] | None = None,
    ) -> bool:
        """Persist live probe authorization without changing the intent identity."""

        with self.transaction() as connection:
            row = connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload_json"])
            payload["probeLevel"] = probe_level
            payload["taskStage"] = task_stage
            payload["probeReceiptDigest"] = receipt_digest
            if code_paths is not None:
                normalized_paths = sorted({str(path) for path in code_paths if str(path).strip()})
                payload["codePaths"] = normalized_paths
                pre_task = payload.get("preTaskEvidence")
                if isinstance(pre_task, dict):
                    payload["preTaskEvidence"] = dict(pre_task) | {
                        "codePathsPlan": normalized_paths
                    }
            connection.execute(
                "UPDATE intents SET payload_json=?,updated_at=? WHERE intent_id=?",
                (
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    iso_z(datetime.now(UTC)),
                    intent_id,
                ),
            )
            return True

    def record_live_audit_pass_and_bind_probe(
        self,
        intent_id: str,
        *,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """Atomically persist one live audit and bind its canonical probe receipt."""

        evidence_digest = str(evidence.get("evidenceDigest") or "")
        if not evidence_digest:
            raise LedgerError("live audit evidence digest is missing")
        authorization = evidence.get("authorization")
        if not isinstance(authorization, dict) or authorization.get("status") != "ALLOW":
            raise LedgerError("live audit authorization is not ALLOW")
        authorization_digest = str(
            authorization.get("evidence_digest") or authorization.get("evidenceDigest") or ""
        )
        if authorization_digest != evidence_digest:
            raise LedgerError("live audit authorization digest does not match evidence")
        incoming_receipt = _live_audit_probe_receipt(evidence)
        if incoming_receipt is None:
            raise LedgerError("live audit repository probe receipt is missing")
        if incoming_receipt.get("probeLevel") != PATHS_VERIFIED:
            raise LedgerError("live audit repository probe must be PATHS_VERIFIED")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT i.opportunity_key,i.payload_json,i.status,i.lease_until,
                          o.issue_url,o.stage
                   FROM intents i JOIN opportunities o ON o.key=i.opportunity_key
                   WHERE i.intent_id=?""",
                (intent_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("live audit intent is not registered")
            claimable = row["status"] == "PENDING" or (
                row["status"] == "LEASED"
                and row["lease_until"]
                and parse_time(str(row["lease_until"])) <= datetime.now(UTC)
            )
            if not claimable or row["stage"] not in {"QUALIFIED", "AUDIT_PASS", "LEASED"}:
                raise LedgerError("live audit intent is not claimable")
            payload = json.loads(row["payload_json"])
            issue_url = str(row["issue_url"] or "")
            issue_match = ISSUE_URL_RE.fullmatch(issue_url)
            if issue_match is None:
                raise LedgerError("live audit issue URL is invalid")
            code_paths = _audited_probe_code_paths(payload, evidence, issue_url)
            if not code_paths:
                raise LedgerError("live audit repository probe binding is incomplete")
            pre_task = payload.get("preTaskEvidence")
            pre_task = pre_task if isinstance(pre_task, dict) else {}
            selected_base = str(payload.get("selectedBaseSha") or pre_task.get("baseSha") or "")
            if not verify_probe_receipt(
                incoming_receipt,
                repo=issue_match.group(1),
                base_sha=selected_base,
                code_paths=code_paths,
                required_level=PATHS_VERIFIED,
            ):
                raise LedgerError("live audit repository probe receipt is not fresh")
            binding_digest = _probe_receipt_binding_digest(incoming_receipt)
            dedupe_key = f"{intent_id}:{evidence_digest}:{binding_digest}:live-audit-v2"
            event = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=? AND event_type='AUDIT_PASS' AND dedupe_key=?""",
                (row["opportunity_key"], dedupe_key),
            ).fetchone()
            if event is None:
                connection.execute(
                    """UPDATE opportunities SET stage='AUDIT_PASS',terminal_reason=NULL,
                       updated_at=? WHERE key=?""",
                    (now, row["opportunity_key"]),
                )
                self._event(
                    connection,
                    str(row["opportunity_key"]),
                    "AUDIT_PASS",
                    dedupe_key,
                    evidence,
                    now,
                )
                event = connection.execute(
                    """SELECT id,payload_json FROM events
                       WHERE opportunity_key=? AND event_type='AUDIT_PASS' AND dedupe_key=?""",
                    (row["opportunity_key"], dedupe_key),
                ).fetchone()
            if event is None:
                raise LedgerError("canonical live audit receipt is unavailable")
            canonical_evidence = json.loads(event["payload_json"])
            canonical_receipt = _live_audit_probe_receipt(canonical_evidence)
            if canonical_receipt is None:
                raise LedgerError("canonical live audit repository probe receipt is missing")
            canonical_paths = _audited_probe_code_paths(payload, canonical_evidence, issue_url)
            if (
                not canonical_paths
                or _probe_receipt_binding_digest(canonical_receipt) != binding_digest
            ):
                raise LedgerError("canonical live audit repository probe binding changed")
            probe_level = PATHS_VERIFIED
            task_stage = "REPRODUCTION_REQUIRED"
            payload["probeLevel"] = probe_level
            payload["taskStage"] = task_stage
            payload["probeReceiptDigest"] = str(canonical_receipt.get("receiptDigest") or "")
            normalized_paths = sorted({str(path) for path in canonical_paths if str(path).strip()})
            payload["codePaths"] = normalized_paths
            pre_task = payload.get("preTaskEvidence")
            if isinstance(pre_task, dict):
                payload["preTaskEvidence"] = dict(pre_task) | {"codePathsPlan": normalized_paths}
            connection.execute(
                "UPDATE intents SET payload_json=?,updated_at=? WHERE intent_id=?",
                (
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    now,
                    intent_id,
                ),
            )
            return {
                "dedupeKey": dedupe_key,
                "probeLevel": probe_level,
                "taskStage": task_stage,
                "receiptDigest": payload["probeReceiptDigest"],
                "codePaths": normalized_paths,
            }

    def reconcile_intent_probe_audit_binding(
        self,
        *,
        intent_id: str,
        issue_url: str,
        thread_id: str,
        worktree_path: str,
        expected_base_sha: str,
    ) -> bool:
        """Repair only an exact semantic match to an intent-bound historical audit."""

        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.issue_url,i.thread_id,i.worktree_path,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.intent_id=? AND o.issue_url=? AND i.thread_id=?""",
                (intent_id, issue_url, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("task audit identity is not registered")
            registered_worktree = str(row["worktree_path"] or "")
            if (
                not registered_worktree
                or Path(registered_worktree).resolve() != Path(worktree_path).resolve()
            ):
                raise LedgerError("task audit worktree does not match the result context")
            payload = json.loads(row["payload_json"])
            pre_task = payload.get("preTaskEvidence")
            pre_task = pre_task if isinstance(pre_task, dict) else {}
            selected_base = str(payload.get("selectedBaseSha") or pre_task.get("baseSha") or "")
            if not expected_base_sha or selected_base != expected_base_sha:
                raise LedgerError("task audit selected base does not match the result context")
            expected_digest = str(payload.get("probeReceiptDigest") or "")
            expected_level = str(payload.get("probeLevel") or "UNVERIFIED")
            expected_paths = sorted(
                {str(path) for path in (payload.get("codePaths") or []) if str(path).strip()}
            )
            if not expected_digest:
                return False
            all_rows = connection.execute(
                """SELECT payload_json,dedupe_key,id FROM events
                   WHERE opportunity_key=(
                     SELECT opportunity_key FROM intents WHERE intent_id=?
                   ) AND event_type IN ('AUDIT_PASS','AUDIT_SNAPSHOT')
                   ORDER BY id DESC""",
                (intent_id,),
            ).fetchall()
            for audit_row in all_rows:
                audit_payload = json.loads(audit_row["payload_json"])
                receipt = _live_audit_probe_receipt(audit_payload)
                if receipt is None or str(receipt.get("receiptDigest") or "") != expected_digest:
                    continue
                _audited_probe_code_paths(payload, audit_payload, issue_url)
                return False
            rows = [
                audit_row
                for audit_row in all_rows
                if str(audit_row["dedupe_key"] or "").startswith(f"{intent_id}:")
            ]
            compatible: list[tuple[sqlite3.Row, dict[str, Any], str]] = []
            for audit_row in rows:
                audit_payload = json.loads(audit_row["payload_json"])
                receipt = _live_audit_probe_receipt(audit_payload)
                if receipt is None:
                    continue
                paths = _audited_probe_code_paths(payload, audit_payload, issue_url)
                if (
                    sorted(paths or []) != expected_paths
                    or str(receipt.get("probeLevel") or "UNVERIFIED") != expected_level
                ):
                    continue
                receipt_digest = str(receipt.get("receiptDigest") or "")
                if receipt_digest == expected_digest:
                    return False
                compatible.append((audit_row, receipt, _probe_receipt_binding_digest(receipt)))
            if not compatible:
                raise LedgerError("task audit repository probe receipt digest is unavailable")
            if len({binding for _, _, binding in compatible}) != 1:
                raise LedgerError("task audit repository probe binding is ambiguous")
            canonical_receipt = compatible[0][1]
            payload["probeReceiptDigest"] = str(canonical_receipt["receiptDigest"])
            connection.execute(
                "UPDATE intents SET payload_json=?,updated_at=? WHERE intent_id=?",
                (
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    iso_z(datetime.now(UTC)),
                    intent_id,
                ),
            )
            return True

    def current_lease_owner(self, intent_id: str) -> str:
        """Return the controller that currently owns an active dispatch transaction."""

        with self.connect() as connection:
            row = connection.execute(
                "SELECT status,lease_owner FROM intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
        if row is None:
            raise LedgerError("intent not found")
        if row["status"] not in {"LEASED", "CREATING"} or not row["lease_owner"]:
            raise LedgerError("intent has no active lease owner")
        return str(row["lease_owner"])

    def reserve_creation(self, intent_id: str, *, owner: str) -> dict[str, Any]:
        """Write-ahead a task creation before invoking the desktop side effect."""

        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        token = secrets.token_urlsafe(24)
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise LedgerError("intent not found")
            if row["status"] == "CREATING":
                if row["lease_owner"] != owner or not row["creation_token"]:
                    raise LedgerError("task creation is owned by another controller")
                return {
                    "intentId": intent_id,
                    "creationToken": row["creation_token"],
                    "clientThreadId": row["client_thread_id"],
                    "creationStartedAt": row["creation_started_at"],
                }
            if row["status"] != "LEASED" or row["lease_owner"] != owner:
                raise LedgerError("intent is not leased by this owner")
            if not row["lease_until"] or parse_time(row["lease_until"]) <= now_dt:
                raise LedgerError("dispatch lease expired")
            connection.execute(
                """UPDATE intents SET status='CREATING',creation_token=?,
                   creation_started_at=?,updated_at=? WHERE intent_id=?""",
                (token, now, now, intent_id),
            )
            connection.execute(
                "UPDATE opportunities SET stage='CREATING',updated_at=? WHERE key=?",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "CREATION_RESERVED",
                token,
                {"intentId": intent_id, "owner": owner, "creationToken": token},
                now,
            )
        return {
            "intentId": intent_id,
            "creationToken": token,
            "clientThreadId": None,
            "creationStartedAt": now,
        }

    def bind_creation_client(
        self,
        intent_id: str,
        *,
        owner: str,
        creation_token: str,
        client_thread_id: str,
    ) -> dict[str, Any]:
        """Persist the asynchronous client task id returned by create_thread."""

        if not client_thread_id.strip():
            raise LedgerError("client thread id is required")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None or row["status"] != "CREATING":
                raise LedgerError("task creation is not reserved")
            if row["lease_owner"] != owner or row["creation_token"] != creation_token:
                raise LedgerError("task creation authorization mismatch")
            if row["client_thread_id"] and row["client_thread_id"] != client_thread_id:
                raise LedgerError("task creation is already bound to another client id")
            connection.execute(
                "UPDATE intents SET client_thread_id=?,updated_at=? WHERE intent_id=?",
                (client_thread_id, now, intent_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "CREATION_CLIENT_BOUND",
                client_thread_id,
                {
                    "intentId": intent_id,
                    "creationToken": creation_token,
                    "clientThreadId": client_thread_id,
                },
                now,
            )
        return {
            "intentId": intent_id,
            "creationToken": creation_token,
            "clientThreadId": client_thread_id,
        }

    def cancel_creation(
        self,
        intent_id: str,
        *,
        owner: str,
        creation_token: str,
        reason: str,
    ) -> None:
        """Cancel only a creation call known to have failed without an external id."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None or row["status"] != "CREATING":
                raise LedgerError("task creation is not reserved")
            if row["lease_owner"] != owner or row["creation_token"] != creation_token:
                raise LedgerError("task creation authorization mismatch")
            if row["client_thread_id"]:
                raise LedgerError("bound task creation cannot be cancelled")
            connection.execute(
                """UPDATE intents SET status='PENDING',lease_owner=NULL,lease_until=NULL,
                   creation_token=NULL,creation_started_at=NULL,updated_at=?
                   WHERE intent_id=?""",
                (now, intent_id),
            )
            connection.execute(
                "UPDATE opportunities SET stage='QUALIFIED',updated_at=? WHERE key=?",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "CREATION_CANCELLED",
                creation_token,
                {"intentId": intent_id, "reason": reason},
                now,
            )

    def abandon_creation(
        self,
        intent_id: str,
        *,
        owner: str,
        creation_token: str,
        client_thread_id: str | None,
        reason: str,
        min_age_minutes: int = 70,
    ) -> None:
        """Release a stale creation after the desktop task never materialized."""

        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None or row["status"] != "CREATING":
                raise LedgerError("task creation is not reserved")
            if row["lease_owner"] != owner or row["creation_token"] != creation_token:
                raise LedgerError("task creation authorization mismatch")
            if row["client_thread_id"] != client_thread_id:
                raise LedgerError("creation client thread id changed")
            if row["thread_id"]:
                raise LedgerError("materialized task creation cannot be abandoned")
            if not row["creation_started_at"]:
                raise LedgerError("task creation start time is unavailable")
            minimum_age = timedelta(minutes=max(1, min_age_minutes))
            if parse_time(row["creation_started_at"]) + minimum_age > now_dt:
                raise LedgerError("bound task creation is not old enough to abandon")
            connection.execute(
                """UPDATE intents SET status='SUPERSEDED',lease_owner=NULL,lease_until=NULL,
                   creation_token=NULL,client_thread_id=NULL,creation_started_at=NULL,
                   updated_at=? WHERE intent_id=?""",
                (now, intent_id),
            )
            connection.execute(
                """UPDATE opportunities SET stage='AUDIT_PASS',terminal_reason=NULL,
                   updated_at=? WHERE key=?""",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "CREATION_ABANDONED",
                creation_token,
                {
                    "intentId": intent_id,
                    "clientThreadId": client_thread_id,
                    "reason": reason,
                    "minimumAgeMinutes": max(1, min_age_minutes),
                },
                now,
            )

    def commit_dispatch(
        self,
        intent_id: str,
        *,
        owner: str,
        thread_id: str,
        project_id: str,
        worktree_path: str,
        title_time: str = "",
    ) -> None:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise LedgerError("intent not found")
            if row["status"] == "DISPATCHED" and row["thread_id"] == thread_id:
                return
            if row["status"] not in {"LEASED", "CREATING"} or row["lease_owner"] != owner:
                raise LedgerError("intent is not leased by this owner")
            if row["status"] == "LEASED" and (
                not row["lease_until"] or parse_time(row["lease_until"]) <= now_dt
            ):
                raise LedgerError("dispatch lease expired")
            connection.execute(
                """UPDATE intents SET status='DISPATCHED',thread_id=?,project_id=?,
                   worktree_path=?,title_time=?,title_synced_state='GO',updated_at=?
                   WHERE intent_id=?""",
                (thread_id, project_id, worktree_path, title_time, now, intent_id),
            )
            connection.execute(
                "UPDATE opportunities SET stage='DISPATCHED',updated_at=? WHERE key=?",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "DISPATCHED",
                thread_id,
                {"intentId": intent_id, "threadId": thread_id, "projectId": project_id},
                now,
            )

    def orphaned_handoffs(self) -> list[dict[str, Any]]:
        """Return task handoffs whose Codex thread was created before receipt commit."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.status,i.lease_owner,
                          i.lease_until,i.expires_at,i.payload_json,i.creation_token,
                          i.client_thread_id,i.creation_started_at,
                          l.created_at AS lease_started_at,l.payload_json AS lease_payload
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   JOIN events l ON l.id=(
                     SELECT e.id FROM events e
                     WHERE e.opportunity_key=o.key AND e.event_type='LEASED'
                     ORDER BY e.created_at DESC,e.id DESC LIMIT 1
                   )
                   WHERE i.status IN ('CREATING','LEASED','EXPIRED','SUPERSEDED')
                     AND i.thread_id IS NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM intents newer
                       WHERE newer.opportunity_key=i.opportunity_key
                         AND newer.intent_id<>i.intent_id
                         AND newer.status IN ('PENDING','LEASED','CREATING','DISPATCHED')
                     )
                   ORDER BY l.created_at"""
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            lease_payload = json.loads(row["lease_payload"])
            values.append(
                {
                    "key": row["key"],
                    "issueUrl": row["issue_url"],
                    "title": row["title"],
                    "intentId": row["intent_id"],
                    "intentStatus": row["status"],
                    "leaseOwner": row["lease_owner"] or lease_payload.get("owner"),
                    "leaseStartedAt": row["lease_started_at"],
                    "leaseUntil": row["lease_until"] or lease_payload.get("leaseUntil"),
                    "expiresAt": row["expires_at"],
                    "repo": payload.get("repo"),
                    "creationToken": row["creation_token"],
                    "clientThreadId": row["client_thread_id"],
                    "creationStartedAt": row["creation_started_at"],
                }
            )
        return values

    def bound_thread_ids(self) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT thread_id FROM intents WHERE thread_id IS NOT NULL"
            ).fetchall()
        return {str(row["thread_id"]) for row in rows}

    def commit_orphan_dispatch(
        self,
        intent_id: str,
        *,
        thread_id: str,
        project_id: str,
        worktree_path: str,
        title_time: str,
        lease_started_at: str,
        title_synced_state: str | None = "GO",
    ) -> None:
        """Attach a uniquely matched task after asynchronous creation hid its ID."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise LedgerError("intent not found")
            if row["status"] == "DISPATCHED" and row["thread_id"] == thread_id:
                return
            if row["status"] not in {"CREATING", "LEASED", "EXPIRED", "SUPERSEDED"}:
                raise LedgerError("intent is not eligible for orphan reconciliation")
            if row["thread_id"] is not None:
                raise LedgerError("intent already has a thread")
            newer = connection.execute(
                """SELECT 1 FROM intents WHERE opportunity_key=? AND intent_id<>?
                   AND status IN ('PENDING','LEASED','CREATING','DISPATCHED') LIMIT 1""",
                (row["opportunity_key"], intent_id),
            ).fetchone()
            if newer:
                raise LedgerError("a newer live intent exists")
            lease_event = connection.execute(
                """SELECT created_at FROM events WHERE opportunity_key=?
                   AND event_type='LEASED' ORDER BY created_at DESC,id DESC LIMIT 1""",
                (row["opportunity_key"],),
            ).fetchone()
            if lease_event is None or lease_event["created_at"] != lease_started_at:
                raise LedgerError("lease evidence changed")
            connection.execute(
                """UPDATE intents SET status='DISPATCHED',thread_id=?,project_id=?,
                   worktree_path=?,title_time=?,title_synced_state=?,updated_at=?
                   WHERE intent_id=?""",
                (
                    thread_id,
                    project_id,
                    worktree_path,
                    title_time,
                    title_synced_state,
                    now,
                    intent_id,
                ),
            )
            connection.execute(
                "UPDATE opportunities SET stage='DISPATCHED',updated_at=? WHERE key=?",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "DISPATCHED",
                thread_id,
                {
                    "intentId": intent_id,
                    "threadId": thread_id,
                    "projectId": project_id,
                    "reconciledAsyncCreation": True,
                },
                now,
            )

    def title_bindings(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.title,o.stage,i.thread_id,i.title_time,
                          i.title_synced_state,
                          CASE
                            WHEN o.stage='AUDIT_NO_GO' THEN 'AUDIT_NO_GO'
                            WHEN o.stage='MERGED' THEN 'MERGED'
                            WHEN o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED','CLOSED')
                              THEN 'PR_OPEN'
                            WHEN EXISTS (
                              SELECT 1 FROM publication_requests p
                              WHERE p.opportunity_key=o.key
                                AND p.status IN ('PENDING','GRANTED')
                            ) THEN 'PUBLICATION_REQUEST'
                            WHEN o.stage='VALIDATION_PENDING' THEN 'VALIDATION_PENDING'
                            WHEN o.stage='FIX_READY' THEN 'FIX_READY'
                            ELSE 'GO'
                          END AS desired_state
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL
                     AND i.status IN ('DISPATCHED','COMPLETED','REJECTED')
                     AND COALESCE((
                       SELECT lifecycle.event_type FROM events lifecycle
                       WHERE lifecycle.opportunity_key=o.key
                         AND lifecycle.event_type IN ('THREAD_ARCHIVED','THREAD_RESTORED')
                         AND json_extract(lifecycle.payload_json,'$.threadId')=i.thread_id
                       ORDER BY lifecycle.id DESC LIMIT 1
                     ),'THREAD_RESTORED')<>'THREAD_ARCHIVED'
                   ORDER BY o.updated_at"""
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            values.append(
                {
                    "key": row["key"],
                    "title": row["title"],
                    "threadId": row["thread_id"],
                    "titleTime": row["title_time"],
                    "titleState": row["desired_state"],
                    "titleSyncedState": row["title_synced_state"],
                    "titleNonce": sha256_text(
                        canonical_json(
                            {
                                "key": row["key"],
                                "threadId": row["thread_id"],
                                "title": row["title"],
                                "titleTime": row["title_time"],
                                "titleState": row["desired_state"],
                            }
                        )
                    ),
                }
            )
        return values

    def title_candidates(self) -> list[dict[str, Any]]:
        return [
            item for item in self.title_bindings() if item["titleSyncedState"] != item["titleState"]
        ]

    def invalidate_title_sync(
        self, *, thread_id: str, state: str, actual_title_digest: str
    ) -> bool:
        binding = next(
            (item for item in self.title_bindings() if item["threadId"] == thread_id),
            None,
        )
        if (
            binding is None
            or binding["titleState"] != state
            or binding["titleSyncedState"] != state
        ):
            return False
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            updated = connection.execute(
                """UPDATE intents SET title_synced_state=NULL,updated_at=?
                   WHERE thread_id=? AND title_synced_state=?""",
                (now, thread_id, state),
            ).rowcount
            if updated:
                self._event(
                    connection,
                    binding["key"],
                    "THREAD_TITLE_DRIFTED",
                    f"{thread_id}:{state}:{actual_title_digest}",
                    {
                        "threadId": thread_id,
                        "titleState": state,
                        "actualTitleDigest": actual_title_digest,
                    },
                    now,
                )
        return bool(updated)

    def commit_title(self, *, thread_id: str, state: str, nonce: str) -> None:
        candidates = {item["threadId"]: item for item in self.title_candidates()}
        candidate = candidates.get(thread_id)
        if not candidate or candidate["titleState"] != state or candidate["titleNonce"] != nonce:
            raise LedgerError("title authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            connection.execute(
                """UPDATE intents SET title_synced_state=?,updated_at=?
                   WHERE thread_id=?""",
                (state, now, thread_id),
            )
            self._event(
                connection,
                candidate["key"],
                "THREAD_TITLE_SYNCED",
                f"{thread_id}:{state}",
                {"threadId": thread_id, "titleState": state},
                now,
            )

    def restorable_task_bindings(self) -> list[dict[str, Any]]:
        """Return valuable bindings authorized for targeted desktop restoration."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.title,o.stage,o.updated_at,o.issue_url,
                          i.thread_id,i.worktree_path,i.title_time,
                          lifecycle.id AS lifecycle_event_id,
                          lifecycle.event_type AS lifecycle_state
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   LEFT JOIN events lifecycle ON lifecycle.id=(
                     SELECT lifecycle.id FROM events lifecycle
                     WHERE lifecycle.opportunity_key=o.key
                       AND lifecycle.event_type IN ('THREAD_ARCHIVED','THREAD_RESTORED')
                       AND json_extract(lifecycle.payload_json,'$.threadId')=i.thread_id
                     ORDER BY lifecycle.id DESC LIMIT 1
                   )
                   WHERE o.stage<>'AUDIT_NO_GO'
                     AND i.thread_id IS NOT NULL
                     AND i.status IN ('DISPATCHED','COMPLETED','REJECTED')
                     AND i.rowid=(
                       SELECT MAX(current.rowid) FROM intents current
                       WHERE current.opportunity_key=o.key
                     )
                   ORDER BY o.updated_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "title": row["title"],
                "stage": row["stage"],
                "issueUrl": row["issue_url"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "titleTime": row["title_time"],
                "lifecycleState": row["lifecycle_state"],
                "restoreNonce": sha256_text(
                    f"{row['key']}|{row['thread_id']}|{row['stage']}|"
                    f"{row['updated_at']}|{row['lifecycle_event_id'] or 'physical-drift'}"
                ),
            }
            for row in rows
        ]

    def restore_candidates(self) -> list[dict[str, Any]]:
        """Return tasks the ledger expects to be archived but lifecycle has made valuable."""

        return [
            item
            for item in self.restorable_task_bindings()
            if item["lifecycleState"] == "THREAD_ARCHIVED"
        ]

    def commit_restore(self, *, thread_id: str, nonce: str) -> None:
        candidates = {item["threadId"]: item for item in self.restorable_task_bindings()}
        candidate = candidates.get(thread_id)
        if not candidate or candidate["restoreNonce"] != nonce:
            raise LedgerError("restore authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "THREAD_RESTORED",
                nonce,
                {"threadId": thread_id, "restoreNonce": nonce},
                now,
            )

    def observe_shadow(self, intent_id: str, *, evidence: dict[str, Any]) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT opportunity_key,status FROM intents WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("intent not found")
            if row["status"] == "SHADOW_OBSERVED":
                return
            if row["status"] != "PENDING":
                raise LedgerError("shadow intent is not pending")
            connection.execute(
                "UPDATE intents SET status='SHADOW_OBSERVED',updated_at=? WHERE intent_id=?",
                (now, intent_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "SHADOW_OBSERVED",
                intent_id,
                evidence,
                now,
            )

    def record_stage(
        self,
        key: str,
        stage: str,
        *,
        evidence: dict[str, Any] | None = None,
        reason: str | None = None,
        dedupe_key: str | None = None,
    ) -> None:
        if stage not in STAGES:
            raise ValueError(f"unsupported lifecycle stage: {stage}")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT key,stage FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                raise LedgerError("opportunity not found")
            if (
                dedupe_key
                and connection.execute(
                    """SELECT 1 FROM events
                   WHERE opportunity_key=? AND event_type=? AND dedupe_key=?""",
                    (key, stage, dedupe_key),
                ).fetchone()
            ):
                # A stage receipt is an idempotency boundary, not merely an
                # event de-duplication hint.  Replaying an older result after a
                # later result advanced the lifecycle must not apply the old
                # stage mutation again.
                return
            if row["stage"] in PUBLISHED_STAGES and stage not in PUBLISHED_STAGES:
                event_type = (
                    "POST_PUBLICATION_AUDIT_NO_GO"
                    if stage == "AUDIT_NO_GO"
                    else "POST_PUBLICATION_STAGE_PRESERVED"
                )
                self._event(
                    connection,
                    key,
                    event_type,
                    dedupe_key or f"{event_type}:{stage}:{now}",
                    {
                        "preservedStage": row["stage"],
                        "requestedStage": stage,
                        "reason": reason,
                        "evidence": evidence or {},
                    },
                    now,
                )
                if row["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"} and stage in {
                    "VALIDATION_PENDING",
                    "FIX_READY",
                }:
                    connection.execute(
                        """INSERT INTO outcomes(opportunity_key,selected_at,submit_ready_at,
                           failure_class,quality_json,updated_at)
                           VALUES (?,NULL,?,NULL,?,?)
                           ON CONFLICT(opportunity_key) DO UPDATE SET
                             submit_ready_at=COALESCE(
                               excluded.submit_ready_at,outcomes.submit_ready_at
                             ),
                             quality_json=excluded.quality_json,
                             updated_at=excluded.updated_at""",
                        (
                            key,
                            now if stage == "FIX_READY" else None,
                            canonical_json(evidence or {}),
                            now,
                        ),
                    )
                return
            connection.execute(
                "UPDATE opportunities SET stage=?,terminal_reason=?,updated_at=? WHERE key=?",
                (stage, reason if stage in TERMINAL_STAGES else None, now, key),
            )
            self._event(
                connection,
                key,
                stage,
                dedupe_key or f"{stage}:{now}",
                evidence or {"reason": reason},
                now,
            )
            if stage == "AUDIT_NO_GO":
                connection.execute(
                    "UPDATE intents SET status='REJECTED',updated_at=? WHERE opportunity_key=?",
                    (now, key),
                )
            elif stage in {
                "VALIDATION_PENDING",
                "FIX_READY",
                "PR_OPEN",
                "CI_GREEN",
                "MAINTAINER_ACCEPTED",
                "MERGED",
                "CLOSED",
            }:
                connection.execute(
                    "UPDATE intents SET status='COMPLETED',updated_at=? WHERE opportunity_key=?",
                    (now, key),
                )
            if stage in {"QUALIFIED", "VALIDATION_PENDING", "FIX_READY", "AUDIT_NO_GO"}:
                connection.execute(
                    """INSERT INTO outcomes(opportunity_key,selected_at,submit_ready_at,
                       failure_class,quality_json,updated_at)
                       VALUES (?,?,?,?,?,?)
                       ON CONFLICT(opportunity_key) DO UPDATE SET
                         selected_at=COALESCE(outcomes.selected_at,excluded.selected_at),
                         submit_ready_at=COALESCE(excluded.submit_ready_at,outcomes.submit_ready_at),
                         failure_class=COALESCE(excluded.failure_class,outcomes.failure_class),
                         quality_json=excluded.quality_json,updated_at=excluded.updated_at""",
                    (
                        key,
                        now if stage == "QUALIFIED" else None,
                        now if stage == "FIX_READY" else None,
                        reason if stage == "AUDIT_NO_GO" else None,
                        canonical_json(evidence or {}),
                        now,
                    ),
                )

    def reopen_false_terminal(
        self,
        key: str,
        *,
        expected_reason: str,
        migration_reason: str,
    ) -> None:
        """Reopen a pre-dispatch terminal produced by an obsolete policy gate."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT stage,terminal_reason FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                raise LedgerError("opportunity not found")
            if row["stage"] != "AUDIT_NO_GO" or row["terminal_reason"] != expected_reason:
                raise LedgerError("terminal migration authorization is stale")
            dispatched = connection.execute(
                "SELECT 1 FROM intents WHERE opportunity_key=? AND thread_id IS NOT NULL LIMIT 1",
                (key,),
            ).fetchone()
            if dispatched is not None:
                raise LedgerError("a dispatched task cannot be reopened by policy migration")
            connection.execute(
                "UPDATE opportunities SET stage='QUALIFIED',terminal_reason=NULL,updated_at=? WHERE key=?",
                (now, key),
            )
            connection.execute(
                """UPDATE intents SET status='EXPIRED',lease_owner=NULL,lease_until=NULL,
                   updated_at=? WHERE opportunity_key=? AND status='REJECTED'
                   AND thread_id IS NULL""",
                (now, key),
            )
            self._event(
                connection,
                key,
                "QUALIFIED",
                f"policy-migration:{migration_reason}",
                {
                    "previousReason": expected_reason,
                    "migrationReason": migration_reason,
                },
                now,
            )

    def invalidate_state_drift_intent(
        self,
        key: str,
        *,
        intent_id: str,
        evidence: dict[str, Any] | None = None,
        historical_terminal: bool = False,
    ) -> dict[str, Any]:
        """Invalidate one pre-thread intent and request a fresh scanner decision."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            opportunity = connection.execute(
                "SELECT stage,terminal_reason FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if opportunity is None:
                raise LedgerError("opportunity not found")
            intent = connection.execute(
                """SELECT status,thread_id,payload_json FROM intents
                   WHERE intent_id=? AND opportunity_key=?""",
                (intent_id, key),
            ).fetchone()
            if intent is None:
                raise LedgerError("state drift intent not found")
            if connection.execute(
                """SELECT 1 FROM intents WHERE opportunity_key=? AND (
                       thread_id IS NOT NULL OR client_thread_id IS NOT NULL
                       OR worktree_path IS NOT NULL
                   ) LIMIT 1""",
                (key,),
            ).fetchone():
                raise LedgerError("a thread-bound opportunity cannot be reopened for state drift")
            publication_evidence = connection.execute(
                """SELECT 1 FROM publication_requests WHERE opportunity_key=?
                   UNION ALL SELECT 1 FROM pr_followups WHERE opportunity_key=?
                   UNION ALL SELECT 1 FROM events WHERE opportunity_key=?
                     AND event_type IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED','MERGED','CLOSED')
                   LIMIT 1""",
                (key, key, key),
            ).fetchone()
            if opportunity["stage"] in PUBLISHED_STAGES or publication_evidence:
                raise LedgerError("a published opportunity cannot be reopened for state drift")

            existing_event = connection.execute(
                """SELECT payload_json,created_at FROM events
                   WHERE opportunity_key=? AND event_type=? AND dedupe_key=?""",
                (key, STATE_DRIFT_RECHECK_EVENT, intent_id),
            ).fetchone()
            if existing_event is not None:
                if (
                    opportunity["stage"] != "QUALIFIED"
                    or opportunity["terminal_reason"] is not None
                    or intent["status"] != "REJECTED"
                ):
                    raise LedgerError("state drift recheck has already advanced")
                payload = json.loads(existing_event["payload_json"])
                return {
                    "key": key,
                    "intentId": intent_id,
                    "issueUpdatedAt": payload.get("issueUpdatedAt"),
                    "staleBaseSha": payload.get("staleBaseSha"),
                    "liveBaseSha": payload.get("liveBaseSha"),
                    "evidenceDigest": payload.get("evidenceDigest"),
                    "recordedAt": str(existing_event["created_at"]),
                    "changed": False,
                }

            if historical_terminal:
                if (
                    opportunity["stage"] != "AUDIT_NO_GO"
                    or opportunity["terminal_reason"] != "STATE_DRIFT"
                ):
                    raise LedgerError("historical state drift migration authorization is stale")
                if intent["status"] != "REJECTED":
                    raise LedgerError("historical state drift intent is not rejected")
            elif intent["status"] not in {"PENDING", "LEASED"}:
                raise LedgerError("state drift intent is no longer invalidatable")

            intent_payload = json.loads(intent["payload_json"])
            audit_evidence = evidence if isinstance(evidence, dict) else {}
            if historical_terminal and not audit_evidence:
                terminal_event = connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=? AND event_type='AUDIT_NO_GO'
                       ORDER BY created_at DESC,id DESC LIMIT 1""",
                    (key,),
                ).fetchone()
                if terminal_event is not None:
                    terminal_payload = json.loads(terminal_event["payload_json"])
                    value = terminal_payload.get("evidence")
                    if isinstance(value, dict):
                        audit_evidence = value
            issue = audit_evidence.get("issue")
            issue = issue if isinstance(issue, dict) else {}
            payload = {
                "intentId": intent_id,
                "issueUpdatedAt": audit_evidence.get("issueUpdatedAt")
                or issue.get("updated_at")
                or intent_payload.get("issueUpdatedAt"),
                "staleBaseSha": audit_evidence.get("selectedBaseSha")
                or audit_evidence.get("selected_base_sha")
                or intent_payload.get("selectedBaseSha")
                or (intent_payload.get("preTaskEvidence") or {}).get("baseSha"),
                "liveBaseSha": audit_evidence.get("liveBaseSha")
                or audit_evidence.get("live_base_sha"),
                "evidenceDigest": audit_evidence.get("evidenceDigest")
                or audit_evidence.get("digest"),
                "historicalMigration": historical_terminal,
            }
            connection.execute(
                """UPDATE intents SET status='REJECTED',lease_owner=NULL,lease_until=NULL,
                   creation_token=NULL,client_thread_id=NULL,creation_started_at=NULL,updated_at=?
                   WHERE intent_id=?""",
                (now, intent_id),
            )
            connection.execute(
                """UPDATE opportunities SET stage='QUALIFIED',terminal_reason=NULL,updated_at=?
                   WHERE key=?""",
                (now, key),
            )
            connection.execute(
                """UPDATE outcomes SET failure_class=NULL,updated_at=?
                   WHERE opportunity_key=? AND failure_class='STATE_DRIFT'""",
                (now, key),
            )
            self._event(
                connection,
                key,
                STATE_DRIFT_RECHECK_EVENT,
                intent_id,
                payload,
                now,
            )
            return {
                "key": key,
                "intentId": intent_id,
                "issueUpdatedAt": payload["issueUpdatedAt"],
                "staleBaseSha": payload["staleBaseSha"],
                "liveBaseSha": payload["liveBaseSha"],
                "evidenceDigest": payload["evidenceDigest"],
                "recordedAt": now,
                "changed": True,
            }

    def restore_verified_reproduction(
        self,
        key: str,
        *,
        intent_id: str,
        thread_id: str,
        expected_reason: str,
        receipt_digest: str,
    ) -> bool:
        """Restore a dispatched task after a verified reproduction was misclassified."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            opportunity = connection.execute(
                "SELECT stage,terminal_reason FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if opportunity is None:
                raise LedgerError("opportunity not found")
            if opportunity["stage"] != "AUDIT_NO_GO":
                return False
            if opportunity["terminal_reason"] != expected_reason:
                raise LedgerError("verified reproduction restoration is stale")
            intent = connection.execute(
                """SELECT status,thread_id FROM intents
                   WHERE intent_id=? AND opportunity_key=?""",
                (intent_id, key),
            ).fetchone()
            if intent is None or intent["thread_id"] != thread_id:
                raise LedgerError("verified reproduction task binding changed")
            if intent["status"] != "REJECTED":
                raise LedgerError("verified reproduction task is not terminal")
            connection.execute(
                """UPDATE opportunities SET stage='DISPATCHED',terminal_reason=NULL,updated_at=?
                   WHERE key=?""",
                (now, key),
            )
            connection.execute(
                """UPDATE intents SET status='DISPATCHED',title_synced_state=NULL,updated_at=?
                   WHERE intent_id=?""",
                (now, intent_id),
            )
            connection.execute(
                """UPDATE outcomes SET failure_class=NULL,updated_at=?
                   WHERE opportunity_key=?""",
                (now, key),
            )
            self._event(
                connection,
                key,
                "REPRODUCTION_TERMINAL_REVERSED",
                receipt_digest,
                {
                    "intentId": intent_id,
                    "threadId": thread_id,
                    "previousReason": expected_reason,
                    "receiptDigest": receipt_digest,
                },
                now,
            )
            return True

    def pending(self) -> list[dict[str, Any]]:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT payload_json,status,issued_at,lease_until,client_thread_id,
                          creation_started_at FROM intents
                   WHERE (status IN ('PENDING','LEASED') AND expires_at>?)
                      OR status='CREATING'
                   ORDER BY
                     CASE
                       WHEN json_extract(payload_json,'$.publicSubmissionAllowed')=1
                        AND COALESCE(json_extract(payload_json,'$.submissionPolicy'),'normal')='normal'
                       THEN 0 ELSE 1
                     END,
                     CAST(COALESCE(json_extract(payload_json,'$.score'),0) AS INTEGER) DESC,
                     issued_at""",
                (now,),
            ).fetchall()
        values: list[dict[str, Any]] = []
        for row in rows:
            issued_at = parse_time(row["issued_at"])
            age_minutes = max(0, int((now_dt - issued_at).total_seconds() // 60))
            lease_stale = bool(
                row["status"] == "LEASED"
                and row["lease_until"]
                and parse_time(row["lease_until"]) <= now_dt
            )
            creation_age_minutes = (
                max(
                    0,
                    int((now_dt - parse_time(row["creation_started_at"])).total_seconds() // 60),
                )
                if row["creation_started_at"]
                else None
            )
            values.append(
                json.loads(row["payload_json"])
                | {
                    "ledgerStatus": row["status"],
                    "pendingSince": row["issued_at"],
                    "pendingAgeMinutes": age_minutes,
                    "leaseStale": lease_stale,
                    "clientThreadId": row["client_thread_id"],
                    "creationStartedAt": row["creation_started_at"],
                    "creationAgeMinutes": creation_age_minutes,
                }
            )
        return values

    def terminal_feedback(self) -> list[dict[str, Any]]:
        """Return local terminal judgments eligible for cloud suppression."""

        with self.connect() as connection:
            rows = connection.execute(
                """
                WITH feedback_candidates AS (
                    SELECT o.key, o.repo, o.issue_number, o.issue_url,
                           CASE
                             WHEN o.stage IN ('AUDIT_NO_GO', 'MERGED', 'CLOSED')
                               THEN o.stage
                             ELSE 'AUDIT_NO_GO'
                           END AS feedback_stage,
                           CASE
                             WHEN o.stage IN ('AUDIT_NO_GO', 'MERGED', 'CLOSED')
                               THEN o.terminal_reason
                             ELSE outcomes.failure_class
                           END AS feedback_reason
                      FROM opportunities o
                      LEFT JOIN outcomes ON outcomes.opportunity_key=o.key
                     WHERE o.stage IN ('AUDIT_NO_GO', 'MERGED', 'CLOSED')
                        OR (
                            outcomes.failure_class='WRONG_REPO'
                            AND o.stage NOT IN (
                                'PR_OPEN', 'CI_GREEN', 'MAINTAINER_ACCEPTED', 'MERGED', 'CLOSED'
                            )
                            AND EXISTS (
                                SELECT 1 FROM intents dispatched
                                 WHERE dispatched.opportunity_key=o.key
                                   AND dispatched.thread_id IS NOT NULL
                            )
                            AND EXISTS (
                                SELECT 1 FROM events terminal_event
                                 WHERE terminal_event.opportunity_key=o.key
                                   AND terminal_event.event_type='AUDIT_NO_GO'
                            )
                        )
                ), terminal_candidates AS (
                    SELECT candidate.*,
                           (
                               SELECT MAX(e.created_at)
                                 FROM events e
                                WHERE e.opportunity_key=candidate.key
                                  AND e.event_type=candidate.feedback_stage
                           ) AS terminal_recorded_at
                      FROM feedback_candidates candidate
                )
                SELECT terminal.key, terminal.repo, terminal.issue_number,
                       terminal.issue_url, terminal.feedback_stage AS stage,
                       terminal.feedback_reason AS terminal_reason,
                       (
                           SELECT MAX(i.issued_at)
                             FROM intents i
                            WHERE i.opportunity_key=terminal.key
                       ) AS latest_intent_issued_at,
                       terminal.terminal_recorded_at,
                       (
                           SELECT json_extract(e.payload_json, '$.issueUpdatedAt')
                             FROM events e
                            WHERE e.opportunity_key=terminal.key
                              AND e.event_type=terminal.feedback_stage
                            ORDER BY e.created_at DESC, e.id DESC
                            LIMIT 1
                       ) AS terminal_issue_updated_at,
                       (
                           SELECT e.payload_json
                             FROM events e
                            WHERE e.opportunity_key=terminal.key
                              AND e.event_type IN ('AUDIT_PASS', 'AUDIT_SNAPSHOT')
                              AND e.created_at<=terminal.terminal_recorded_at
                            ORDER BY e.created_at DESC, e.id DESC
                            LIMIT 1
                       ) AS terminal_audit_payload_json,
                       (
                           SELECT e.payload_json
                             FROM events e
                            WHERE e.opportunity_key=terminal.key
                              AND e.event_type=terminal.feedback_stage
                            ORDER BY e.created_at DESC, e.id DESC
                            LIMIT 1
                       ) AS terminal_payload_json
                  FROM terminal_candidates terminal
                 ORDER BY terminal.key
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def scanner_recheck_feedback(self) -> list[dict[str, Any]]:
        """Return active one-shot scanner rechecks emitted by live preflight."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.repo,o.issue_number,o.issue_url,
                          e.payload_json,e.created_at
                     FROM events e
                     JOIN opportunities o ON o.key=e.opportunity_key
                    WHERE e.event_type=? AND o.stage='QUALIFIED'
                      AND e.id=(
                          SELECT MAX(latest.id) FROM events latest
                           WHERE latest.opportunity_key=e.opportunity_key
                             AND latest.event_type=?
                      )
                      AND EXISTS (
                          SELECT 1 FROM intents i
                           WHERE i.opportunity_key=o.key
                             AND i.intent_id=json_extract(e.payload_json,'$.intentId')
                             AND i.status='REJECTED' AND i.thread_id IS NULL
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM intents bound
                           WHERE bound.opportunity_key=o.key AND bound.thread_id IS NOT NULL
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM publication_requests request
                           WHERE request.opportunity_key=o.key
                      )
                    ORDER BY o.key""",
                (STATE_DRIFT_RECHECK_EVENT, STATE_DRIFT_RECHECK_EVENT),
            ).fetchall()
        feedback: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            feedback.append(
                {
                    "key": str(row["key"]),
                    "repo": str(row["repo"]),
                    "issue_number": int(row["issue_number"]),
                    "issue_url": str(row["issue_url"]),
                    "intent_id": str(payload.get("intentId") or ""),
                    "issue_updated_at": payload.get("issueUpdatedAt"),
                    "stale_base_sha": payload.get("staleBaseSha"),
                    "live_base_sha": payload.get("liveBaseSha"),
                    "evidence_digest": payload.get("evidenceDigest"),
                    "recheck_recorded_at": str(row["created_at"]),
                }
            )
        return feedback

    def pending_alerts(self, *, min_age_minutes: int = 70) -> list[dict[str, Any]]:
        threshold = max(60, min(int(min_age_minutes), 24 * 60))
        alerts: list[dict[str, Any]] = []
        for item in self.pending():
            code = None
            if item.get("leaseStale"):
                code = "DISPATCH_LEASE_STALE"
            elif (
                item.get("ledgerStatus") == "CREATING"
                and int(item.get("creationAgeMinutes") or 0) >= threshold
            ):
                code = "TASK_CREATION_PENDING"
            if code:
                alerts.append(item | {"alertCode": code, "thresholdMinutes": threshold})
        return alerts

    def active_dispatch_count(self, *, exclude_intent_id: str | None = None) -> int:
        now = iso_z(datetime.now(UTC))
        query = """SELECT COUNT(*) FROM intents
                   WHERE status IN ('LEASED','CREATING','DISPATCHED')
                     AND (status IN ('CREATING','DISPATCHED') OR lease_until>?)"""
        params: tuple[Any, ...] = (now,)
        if exclude_intent_id:
            query += " AND intent_id<>?"
            params = (now, exclude_intent_id)
        with self.connect() as connection:
            return int(connection.execute(query, params).fetchone()[0])

    @staticmethod
    def _active_task_count(
        connection: sqlite3.Connection,
        *,
        now: str,
        exclude_intent_id: str | None = None,
    ) -> int:
        intent_filter = "" if exclude_intent_id is None else "AND i.intent_id<>?"
        event_filter = (
            ""
            if exclude_intent_id is None
            else """AND NOT EXISTS (
                     SELECT 1 FROM intents excluded
                     WHERE excluded.intent_id=?
                       AND excluded.opportunity_key=r.opportunity_key
                   )"""
        )
        params: list[Any] = [now]
        if exclude_intent_id is not None:
            params.extend([exclude_intent_id, exclude_intent_id, exclude_intent_id])
        return int(
            connection.execute(
                f"""SELECT COUNT(*) FROM (
                     SELECT i.opportunity_key FROM intents i
                     JOIN opportunities o ON o.key=i.opportunity_key
                     WHERE i.status IN ('LEASED','CREATING','DISPATCHED')
                       AND (i.status IN ('CREATING','DISPATCHED') OR i.lease_until>?)
                       {intent_filter}
                       AND NOT ({_EXHAUSTED_DISPATCHED_RECOVERY_PREDICATE})
                     UNION
                     SELECT r.opportunity_key FROM events r
                     WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                       {event_filter}
                       AND NOT EXISTS (
                         SELECT 1 FROM task_quarantines quarantine
                         WHERE quarantine.opportunity_key=r.opportunity_key
                           AND quarantine.status='ACTIVE'
                       )
                       AND EXISTS (
                         SELECT 1 FROM events completed
                         WHERE completed.opportunity_key=r.opportunity_key
                           AND completed.event_type='PR_FOLLOWUP_RESERVATION_REPAIRED'
                           AND completed.dedupe_key=r.dedupe_key
                           AND completed.id>r.id
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events exhausted
                         JOIN events recovery
                           ON recovery.opportunity_key=exhausted.opportunity_key
                          AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                          AND recovery.dedupe_key=exhausted.dedupe_key
                         WHERE exhausted.opportunity_key=r.opportunity_key
                           AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                           AND json_extract(recovery.payload_json,'$.recoveryKind')=
                               'PR_FOLLOWUP_RESULT'
                           AND json_extract(recovery.payload_json,'$.followupDigest')=
                               r.dedupe_key
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events result
                         WHERE result.opportunity_key=r.opportunity_key
                           AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                           AND result.dedupe_key=r.dedupe_key
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events abandoned
                         WHERE abandoned.opportunity_key=r.opportunity_key
                           AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                           AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                           AND abandoned.id>r.id
                       )
                     UNION
                     SELECT r.opportunity_key FROM events r
                     JOIN opportunities o ON o.key=r.opportunity_key
                     WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                       AND o.stage IN (
                         'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                       )
                       {event_filter}
                       AND NOT EXISTS (
                         SELECT 1 FROM task_quarantines quarantine
                         WHERE quarantine.opportunity_key=r.opportunity_key
                           AND quarantine.status='ACTIVE'
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events exhausted
                         JOIN events recovery
                           ON recovery.opportunity_key=exhausted.opportunity_key
                          AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                          AND recovery.dedupe_key=exhausted.dedupe_key
                         WHERE exhausted.opportunity_key=r.opportunity_key
                           AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                           AND json_extract(recovery.payload_json,'$.recoveryKind')=
                               'VALIDATION_FOLLOWUP_RESULT'
                           AND json_extract(recovery.payload_json,'$.followupDigest')=
                               json_extract(r.payload_json,'$.resultDigest')
                       )
                       AND json_extract(r.payload_json,'$.resultDigest')=(
                         SELECT json_extract(d.payload_json,'$.resultDigest')
                         FROM events d
                         WHERE d.opportunity_key=r.opportunity_key
                           AND d.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                         ORDER BY d.id DESC LIMIT 1
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events abandoned
                         WHERE abandoned.opportunity_key=r.opportunity_key
                           AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                           AND json_extract(abandoned.payload_json,'$.resultDigest')=
                               json_extract(r.payload_json,'$.resultDigest')
                           AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                           AND abandoned.id>r.id
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events cancelled
                         WHERE cancelled.opportunity_key=r.opportunity_key
                           AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                           AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                               json_extract(r.payload_json,'$.reservationDigest')
                           AND cancelled.id>r.id
                       )
                   )""",
                params,
            ).fetchone()[0]
        )

    def active_task_count(self, *, exclude_intent_id: str | None = None) -> int:
        """Count durable issue, PR-follow-up, and validation work in flight."""

        with self.connect() as connection:
            return self._active_task_count(
                connection,
                now=iso_z(datetime.now(UTC)),
                exclude_intent_id=exclude_intent_id,
            )

    def exhausted_recovery_blockers(self) -> list[dict[str, Any]]:
        """Return dispatched intents whose latest recovery attempt was exhausted."""

        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.issue_url,o.title,o.stage,
                           i.intent_id,i.status AS intent_status,i.thread_id,i.worktree_path,
                           exhausted.dedupe_key AS reservation_digest,
                           exhausted.payload_json,exhausted.created_at AS exhausted_at,
                           recovery.created_at AS reserved_at
                    FROM opportunities o
                    JOIN intents i ON i.opportunity_key=o.key
                    JOIN events exhausted ON exhausted.opportunity_key=o.key
                      AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                    JOIN events recovery ON recovery.opportunity_key=exhausted.opportunity_key
                      AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                      AND recovery.dedupe_key=exhausted.dedupe_key
                    WHERE {_EXHAUSTED_DISPATCHED_RECOVERY_PREDICATE}
                      AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                      AND recovery.id>(
                        SELECT COALESCE(MAX(dispatched.id),0)
                        FROM events dispatched
                        WHERE dispatched.opportunity_key=i.opportunity_key
                          AND dispatched.event_type='DISPATCHED'
                          AND dispatched.dedupe_key=i.thread_id
                      )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM events later
                        WHERE later.opportunity_key=exhausted.opportunity_key
                          AND later.id>exhausted.id
                          AND (
                            later.event_type IN (
                              'TASK_RESULT_INGESTED',
                              'PUBLISHED_TASK_RESULT_BACKFILLED',
                              'PR_FOLLOWUP_RESULT_INGESTED',
                              'IMPLEMENTATION_CONTEXT_REPAIRED',
                              'AUDIT_PASS',
                              'AUDIT_NO_GO',
                              'VALIDATION_PENDING',
                              'FIX_READY',
                              'PR_OPEN',
                              'CI_GREEN',
                              'MAINTAINER_ACCEPTED',
                              'MERGED',
                              'CLOSED'
                            )
                            OR (
                              later.event_type='THREAD_RECOVERY_RESERVED'
                              AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                              AND json_extract(
                                    later.payload_json,
                                    '$.rearmedFromExhausted.exhaustedNonce'
                                  )=exhausted.dedupe_key
                            )
                            OR (
                              later.event_type=
                                  'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                              AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                              AND json_extract(later.payload_json,'$.recoveryNonce')=
                                  exhausted.dedupe_key
                            )
                            OR (
                              later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                              AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                              AND json_extract(later.payload_json,'$.recoveryNonce')=
                                  exhausted.dedupe_key
                            )
                          )
                      )
                    ORDER BY exhausted.created_at,exhausted.id"""
            ).fetchall()
        blockers: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            blockers.append(
                {
                    "key": row["key"],
                    "issueUrl": row["issue_url"],
                    "title": row["title"],
                    "stage": row["stage"],
                    "intentId": row["intent_id"],
                    "intentStatus": row["intent_status"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "recoveryKind": payload.get("recoveryKind"),
                    "followupDigest": payload.get("followupDigest"),
                    "recoveryNonce": payload.get("recoveryNonce"),
                    "reservationDigest": row["reservation_digest"],
                    "reservedAt": row["reserved_at"],
                    "exhaustedAt": row["exhausted_at"],
                    "blockerCode": "RECOVERY_RETRY_EXHAUSTED",
                    "reason": "RECOVERY_RETRY_EXHAUSTED",
                    "occupiesTaskSlot": False,
                    "retryCount": payload.get("retryCount"),
                    "terminalError": payload.get("terminalError"),
                }
            )
        return blockers

    def recovery_candidates(
        self,
        *,
        min_age_minutes: int = 90,
        include_exhausted_dispatched: bool = False,
    ) -> list[dict[str, Any]]:
        cutoff = iso_z(
            datetime.now(UTC) - timedelta(minutes=max(0, min(int(min_age_minutes), 24 * 60)))
        )
        with self.connect() as connection:
            dispatched_rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,d.created_at AS dispatched_at,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.threadId')=i.thread_id
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events d ON d.opportunity_key=o.key
                     AND d.event_type='DISPATCHED' AND d.dedupe_key=i.thread_id
                   WHERE i.status='DISPATCHED' AND i.thread_id IS NOT NULL
                     AND d.created_at<=?
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND (? OR NOT EXISTS (
                       SELECT 1 FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.opportunity_key=o.key
                         AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                         AND json_extract(recovery.payload_json,'$.recoveryKind')='DISPATCHED_TASK'
                         AND recovery.created_at>=d.created_at
                     ))
                     AND NOT EXISTS (
                       SELECT 1 FROM events advanced
                       WHERE advanced.opportunity_key=o.key
                         AND advanced.id>d.id
                         AND advanced.event_type IN (
                           'TASK_RESULT_INGESTED',
                           'PUBLISHED_TASK_RESULT_BACKFILLED',
                           'PR_FOLLOWUP_RESULT_INGESTED',
                           'IMPLEMENTATION_FOLLOWUP_SENT',
                           'VALIDATION_FOLLOWUP_SENT',
                           'PR_FOLLOWUP_SENT'
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=o.key
                         AND (
                           (e.event_type='THREAD_RECOVERY_RESERVED'
                            AND json_extract(e.payload_json,'$.threadId')=i.thread_id
                            AND e.created_at>=d.created_at
                            AND NOT EXISTS (
                              SELECT 1 FROM events abandoned
                              WHERE abandoned.opportunity_key=e.opportunity_key
                                AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                                AND json_extract(
                                      abandoned.payload_json,'$.reservationDigest'
                                    )=e.dedupe_key
                                AND abandoned.id>e.id
                            ))
                           OR
                           (e.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                            AND json_extract(e.payload_json,'$.threadId')=i.thread_id)
                         )
                     )
                   ORDER BY d.created_at""",
                (cutoff, int(include_exhausted_dispatched)),
            ).fetchall()
            followup_rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,s.created_at AS dispatched_at,
                          s.dedupe_key AS followup_digest,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.threadId')=i.thread_id
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='PR_FOLLOWUP_SENT'
                   WHERE o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND s.created_at<=?
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.opportunity_key=o.key
                         AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'PR_FOLLOWUP_RESULT'
                         AND json_extract(recovery.payload_json,'$.followupDigest')=s.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND result.dedupe_key=s.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events recovery
                         WHERE recovery.opportunity_key=o.key
                           AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                           AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                           AND recovery.created_at>=s.created_at
                           AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=recovery.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(
                                   abandoned.payload_json,'$.reservationDigest'
                                 )=recovery.dedupe_key
                             AND abandoned.id>recovery.id
                         )
                     )
                   ORDER BY s.created_at""",
                (cutoff,),
            ).fetchall()
            validation_rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,s.created_at AS dispatched_at,
                          s.dedupe_key AS followup_digest,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.threadId')=i.thread_id
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                     AND s.dedupe_key=d.dedupe_key
                     AND json_extract(s.payload_json,'$.threadId')=
                         json_extract(d.payload_json,'$.threadId')
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   ) AND s.created_at<=?
                     AND json_extract(d.payload_json,'$.threadId')=i.thread_id
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.opportunity_key=o.key
                         AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'VALIDATION_FOLLOWUP_RESULT'
                         AND json_extract(recovery.payload_json,'$.followupDigest')=s.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type IN (
                           'TASK_RESULT_INGESTED','PUBLISHED_TASK_RESULT_BACKFILLED'
                         )
                         AND result.id>s.id
                         AND json_extract(result.payload_json,'$.threadId')=i.thread_id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events recovery
                         WHERE recovery.opportunity_key=o.key
                           AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                           AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                           AND recovery.created_at>=s.created_at
                           AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=recovery.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(
                                   abandoned.payload_json,'$.reservationDigest'
                                 )=recovery.dedupe_key
                             AND abandoned.id>recovery.id
                         )
                     )
                   ORDER BY s.created_at""",
                (cutoff,),
            ).fetchall()
            implementation_rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,s.created_at AS dispatched_at,
                          s.dedupe_key AS followup_digest,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.threadId')=i.thread_id
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     AND s.id=(
                       SELECT MAX(s2.id) FROM events s2
                       WHERE s2.opportunity_key=o.key
                         AND s2.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     )
                   WHERE i.status='DISPATCHED' AND s.created_at<=?
                     AND i.thread_id=json_extract(s.payload_json,'$.threadId')
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.opportunity_key=o.key
                         AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'IMPLEMENTATION_FOLLOWUP_RESULT'
                         AND json_extract(recovery.payload_json,'$.followupDigest')=s.dedupe_key
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=exhausted.opportunity_key
                             AND rearmed.event_type=
                                 'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND json_extract(rearmed.payload_json,'$.threadId')=i.thread_id
                             AND json_extract(rearmed.payload_json,'$.recoveryNonce')=
                                 exhausted.dedupe_key
                             AND rearmed.id>exhausted.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type='TASK_RESULT_INGESTED'
                         AND result.id>s.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events recovery
                       WHERE recovery.opportunity_key=o.key
                         AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                         AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                         AND recovery.created_at>=s.created_at
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=recovery.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(
                                   abandoned.payload_json,'$.reservationDigest'
                                 )=recovery.dedupe_key
                             AND abandoned.id>recovery.id
                         )
                     )
                   ORDER BY s.created_at""",
                (cutoff,),
            ).fetchall()
            implementation_rearm_rows = connection.execute(
                """SELECT rearmed.id AS rearm_event_id,
                          exhausted.id AS exhausted_event_id,
                          exhausted.opportunity_key AS key,
                          exhausted.dedupe_key AS exhausted_nonce,
                          recovery.payload_json AS recovery_payload_json
                   FROM events rearmed
                   JOIN events exhausted
                     ON exhausted.opportunity_key=rearmed.opportunity_key
                    AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                    AND exhausted.dedupe_key=
                        json_extract(rearmed.payload_json,'$.recoveryNonce')
                   JOIN events recovery
                     ON recovery.opportunity_key=exhausted.opportunity_key
                    AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                    AND recovery.dedupe_key=exhausted.dedupe_key
                   WHERE rearmed.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                   ORDER BY rearmed.id"""
            ).fetchall()
            exhausted_dispatched_rows = (
                connection.execute(
                    """SELECT exhausted.id AS event_id,
                              exhausted.opportunity_key AS key,
                              exhausted.dedupe_key AS exhausted_nonce,
                              exhausted.payload_json AS exhausted_payload_json,
                              recovery.payload_json AS recovery_payload_json,
                              recovery.created_at AS recovery_created_at
                       FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'DISPATCHED_TASK'
                       ORDER BY exhausted.id"""
                ).fetchall()
                if include_exhausted_dispatched
                else []
            )
        implementation_rearms: dict[tuple[str, str, str], dict[str, Any]] = {}
        for rearm_row in implementation_rearm_rows:
            recovery_payload = json.loads(rearm_row["recovery_payload_json"])
            implementation_rearms[
                (
                    str(rearm_row["key"]),
                    str(recovery_payload.get("threadId") or ""),
                    str(recovery_payload.get("followupDigest") or ""),
                )
            ] = {
                "exhaustedNonce": str(rearm_row["exhausted_nonce"]),
                "exhaustedEventId": int(rearm_row["exhausted_event_id"]),
                "rearmEventId": int(rearm_row["rearm_event_id"]),
            }
        exhausted_by_task: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for exhausted_row in exhausted_dispatched_rows:
            recovery_payload = json.loads(exhausted_row["recovery_payload_json"])
            exhausted_payload = json.loads(exhausted_row["exhausted_payload_json"])
            marker = {
                "eventId": int(exhausted_row["event_id"]),
                "exhaustedNonce": str(exhausted_row["exhausted_nonce"]),
                "recoveryCreatedAt": str(exhausted_row["recovery_created_at"]),
                "recoveryPromptVersion": exhausted_payload.get("recoveryPromptVersion")
                or recovery_payload.get("recoveryPromptVersion"),
                "recoveryPromptDigest": exhausted_payload.get("recoveryPromptDigest")
                or recovery_payload.get("recoveryPromptDigest"),
            }
            exhausted_by_task.setdefault(
                (
                    str(exhausted_row["key"]),
                    str(recovery_payload.get("threadId") or ""),
                ),
                [],
            ).append(marker)
        candidates: dict[str, dict[str, Any]] = {}
        for row, recovery_kind in (
            *((row, "DISPATCHED_TASK") for row in dispatched_rows),
            *((row, "PR_FOLLOWUP_RESULT") for row in followup_rows),
            *((row, "VALIDATION_FOLLOWUP_RESULT") for row in validation_rows),
            *((row, "IMPLEMENTATION_FOLLOWUP_RESULT") for row in implementation_rows),
        ):
            thread_id = str(row["thread_id"])
            followup_digest = (
                str(row["followup_digest"])
                if recovery_kind
                in {
                    "PR_FOLLOWUP_RESULT",
                    "VALIDATION_FOLLOWUP_RESULT",
                    "IMPLEMENTATION_FOLLOWUP_RESULT",
                }
                else None
            )
            candidate = {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "intentId": row["intent_id"],
                "threadId": thread_id,
                "worktreePath": row["worktree_path"],
                "dispatchedAt": row["dispatched_at"],
                "recoveryKind": recovery_kind,
                "followupDigest": followup_digest,
                "recoveryNonce": sha256_text(
                    f"{row['key']}|{thread_id}|{row['dispatched_at']}|"
                    f"{recovery_kind}|{followup_digest or ''}|"
                    f"{row['recovery_epoch'] or ''}|recovery-v3"
                ),
            }
            if recovery_kind == "DISPATCHED_TASK" and include_exhausted_dispatched:
                candidate["exhaustedRecoveries"] = [
                    marker
                    for marker in exhausted_by_task.get((str(row["key"]), thread_id), [])
                    if str(marker["recoveryCreatedAt"]) >= str(row["dispatched_at"])
                ]
            if recovery_kind == "IMPLEMENTATION_FOLLOWUP_RESULT":
                marker = implementation_rearms.get(
                    (str(row["key"]), thread_id, str(followup_digest or ""))
                )
                if marker is not None:
                    candidate["rearmedFromExhausted"] = marker
            previous = candidates.get(thread_id)
            if previous is None or candidate["dispatchedAt"] > previous["dispatchedAt"]:
                candidates[thread_id] = candidate
        return sorted(candidates.values(), key=lambda item: item["dispatchedAt"])

    def unresolved_recoveries(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,i.worktree_path,
                          json_extract(r.payload_json,'$.threadId') AS thread_id,
                          r.dedupe_key AS reservation_digest,
                          r.payload_json,r.created_at
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key AND i2.thread_id IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events e
                     WHERE e.opportunity_key=o.key
                       AND e.event_type='THREAD_RECOVERY_SENT'
                       AND e.dedupe_key=r.dedupe_key
                   )
                     AND NOT EXISTS (
                     SELECT 1 FROM events abandoned
                     WHERE abandoned.opportunity_key=o.key
                       AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                       AND json_extract(
                             abandoned.payload_json,'$.reservationDigest'
                           )=r.dedupe_key
                       AND abandoned.id>r.id
                   )
                     AND NOT EXISTS (
                     SELECT 1 FROM events result
                     WHERE result.opportunity_key=o.key
                       AND result.id>r.id
                       AND result.event_type IN (
                         'TASK_RESULT_INGESTED','PR_FOLLOWUP_RESULT_INGESTED'
                       )
                   )
                     AND NOT EXISTS (
                     SELECT 1 FROM events terminal
                     WHERE terminal.opportunity_key=o.key
                       AND terminal.id>r.id
                       AND terminal.event_type IN ('AUDIT_NO_GO','MERGED','CLOSED')
                   )
                   ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "worktreePath": row["worktree_path"],
                "threadId": row["thread_id"],
                "reservationDigest": row["reservation_digest"],
                "reservedAt": row["created_at"],
                "reservation": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def sent_recoveries_without_result(self) -> list[dict[str, Any]]:
        """Return delivered recovery turns that still produced no controller result."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,i.thread_id,r.dedupe_key AS reservation_digest,
                          r.payload_json,s.created_at AS sent_at,
                          (SELECT COUNT(*) FROM events prior
                           JOIN events prior_recovery
                             ON prior_recovery.opportunity_key=prior.opportunity_key
                            AND prior_recovery.event_type='THREAD_RECOVERY_RESERVED'
                            AND prior_recovery.dedupe_key=json_extract(
                                  prior.payload_json,'$.reservationDigest'
                                )
                           WHERE prior.opportunity_key=o.key
                             AND prior.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(prior.payload_json,'$.reason')=
                                 'TERMINAL_RECOVERY_TURN_INTERRUPTED'
                             AND prior.id<r.id
                             AND json_extract(prior_recovery.payload_json,'$.threadId')=
                                 json_extract(r.payload_json,'$.threadId')
                             AND json_extract(prior_recovery.payload_json,'$.recoveryKind')=
                                 json_extract(r.payload_json,'$.recoveryKind')
                             AND COALESCE(
                                   json_extract(
                                     prior_recovery.payload_json,'$.followupDigest'
                                   ),''
                                 )=COALESCE(
                                   json_extract(r.payload_json,'$.followupDigest'),''
                                 )
                             AND (
                               (
                                 json_extract(r.payload_json,'$.recoveryChainDigest')
                                   IS NULL
                                 AND json_extract(
                                       prior_recovery.payload_json,
                                       '$.recoveryChainDigest'
                                     ) IS NULL
                               )
                               OR json_extract(
                                    prior_recovery.payload_json,'$.recoveryChainDigest'
                                  )=json_extract(
                                    r.payload_json,'$.recoveryChainDigest'
                                  )
                             )
                          ) AS retry_count
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key AND i2.thread_id IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='THREAD_RECOVERY_SENT'
                     AND s.dedupe_key=r.dedupe_key
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events abandoned
                     WHERE abandoned.opportunity_key=o.key
                       AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                       AND json_extract(
                             abandoned.payload_json,'$.reservationDigest'
                           )=r.dedupe_key
                       AND abandoned.id>r.id
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.id>s.id
                         AND result.event_type IN (
                           'TASK_RESULT_INGESTED','PR_FOLLOWUP_RESULT_INGESTED'
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events terminal
                       WHERE terminal.opportunity_key=o.key
                         AND terminal.id>r.id
                         AND terminal.event_type IN ('AUDIT_NO_GO','MERGED','CLOSED')
                     )
                   ORDER BY s.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "threadId": row["thread_id"],
                "reservationDigest": row["reservation_digest"],
                "reservation": json.loads(row["payload_json"]),
                "sentAt": row["sent_at"],
                "retryCount": int(row["retry_count"] or 0),
            }
            for row in rows
        ]

    def reserve_recovery(
        self,
        *,
        thread_id: str,
        nonce: str,
        recovery_prompt_version: str | None = None,
        recovery_prompt_digest: str | None = None,
    ) -> dict[str, Any]:
        # The bridge may authorize an immediate one-shot recovery after a
        # terminal desktop error, before the normal stale-task threshold.
        if (recovery_prompt_version is None) != (recovery_prompt_digest is None):
            raise LedgerError("recovery prompt binding is incomplete")
        candidates = {
            item["threadId"]: item
            for item in self.recovery_candidates(
                min_age_minutes=0,
                include_exhausted_dispatched=recovery_prompt_version is not None,
            )
        }
        candidate = candidates.get(thread_id)
        if candidate and recovery_prompt_version is not None:
            candidate = bind_dispatched_recovery_prompt(
                candidate,
                prompt_version=recovery_prompt_version,
                prompt_digest=str(recovery_prompt_digest),
            )
        if not candidate or candidate["recoveryNonce"] != nonce:
            raise LedgerError("recovery authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            require_quarantine_clear(
                connection,
                opportunity_key=str(candidate["key"]),
                operation="recovery delivery reservation",
            )
            if candidate["recoveryKind"] == "IMPLEMENTATION_FOLLOWUP_RESULT":
                eligible = connection.execute(
                    """SELECT s.id
                       FROM events s
                       WHERE s.opportunity_key=?
                         AND s.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND s.dedupe_key=?
                         AND json_extract(s.payload_json,'$.threadId')=?
                         AND s.id=(
                           SELECT MAX(latest.id) FROM events latest
                           WHERE latest.opportunity_key=s.opportunity_key
                             AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=s.opportunity_key
                             AND result.event_type='TASK_RESULT_INGESTED'
                             AND result.id>s.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events exhausted
                           JOIN events prior_recovery
                             ON prior_recovery.opportunity_key=
                                exhausted.opportunity_key
                            AND prior_recovery.event_type='THREAD_RECOVERY_RESERVED'
                            AND prior_recovery.dedupe_key=exhausted.dedupe_key
                           WHERE exhausted.opportunity_key=s.opportunity_key
                             AND exhausted.event_type=
                                 'THREAD_RECOVERY_RETRY_EXHAUSTED'
                             AND json_extract(
                                   prior_recovery.payload_json,'$.threadId'
                                 )=?
                             AND json_extract(
                                   prior_recovery.payload_json,'$.recoveryKind'
                                 )='IMPLEMENTATION_FOLLOWUP_RESULT'
                             AND json_extract(
                                   prior_recovery.payload_json,'$.followupDigest'
                                 )=s.dedupe_key
                             AND NOT EXISTS (
                               SELECT 1 FROM events rearmed
                               WHERE rearmed.opportunity_key=exhausted.opportunity_key
                                 AND rearmed.event_type=
                                     'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                                 AND json_extract(
                                       rearmed.payload_json,'$.threadId'
                                     )=?
                                 AND json_extract(
                                       rearmed.payload_json,'$.recoveryNonce'
                                     )=exhausted.dedupe_key
                                 AND rearmed.id>exhausted.id
                             )
                         )
                       LIMIT 1""",
                    (
                        candidate["key"],
                        candidate.get("followupDigest"),
                        thread_id,
                        thread_id,
                        thread_id,
                    ),
                ).fetchone()
                if eligible is None:
                    raise LedgerError("recovery authorization is stale or invalid")
                epoch_row = connection.execute(
                    """SELECT MAX(abandoned.created_at) AS recovery_epoch
                       FROM events abandoned
                       WHERE abandoned.opportunity_key=?
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.threadId')=?""",
                    (candidate["key"], thread_id),
                ).fetchone()
                current_epoch = str(epoch_row["recovery_epoch"] or "")
                expected_nonce = sha256_text(
                    f"{candidate['key']}|{thread_id}|{candidate['dispatchedAt']}|"
                    f"{candidate['recoveryKind']}|{candidate.get('followupDigest') or ''}|"
                    f"{current_epoch}|recovery-v3"
                )
                if nonce != expected_nonce:
                    raise LedgerError("recovery authorization is stale or invalid")
                lineage = candidate.get("rearmedFromExhausted")
                latest_rearm = connection.execute(
                    """SELECT MAX(rearmed.id) AS rearm_event_id
                       FROM events rearmed
                       JOIN events exhausted
                         ON exhausted.opportunity_key=rearmed.opportunity_key
                        AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                        AND exhausted.dedupe_key=
                            json_extract(rearmed.payload_json,'$.recoveryNonce')
                       JOIN events prior_recovery
                         ON prior_recovery.opportunity_key=exhausted.opportunity_key
                        AND prior_recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND prior_recovery.dedupe_key=exhausted.dedupe_key
                       WHERE rearmed.opportunity_key=?
                         AND rearmed.event_type=
                             'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                         AND json_extract(rearmed.payload_json,'$.threadId')=?
                         AND json_extract(prior_recovery.payload_json,'$.recoveryKind')=
                             'IMPLEMENTATION_FOLLOWUP_RESULT'
                         AND json_extract(prior_recovery.payload_json,'$.followupDigest')=?""",
                    (candidate["key"], thread_id, candidate.get("followupDigest")),
                ).fetchone()
                latest_rearm_id = (
                    int(latest_rearm["rearm_event_id"])
                    if latest_rearm["rearm_event_id"] is not None
                    else None
                )
                if lineage is None and latest_rearm_id is not None:
                    raise LedgerError("recovery authorization is stale or invalid")
                if lineage is not None:
                    if latest_rearm_id != int(lineage.get("rearmEventId") or 0):
                        raise LedgerError("recovery authorization is stale or invalid")
                    exact_rearm = connection.execute(
                        """SELECT 1 FROM events rearmed
                           JOIN events exhausted
                             ON exhausted.opportunity_key=rearmed.opportunity_key
                            AND exhausted.event_type=
                                'THREAD_RECOVERY_RETRY_EXHAUSTED'
                            AND exhausted.dedupe_key=?
                           WHERE rearmed.opportunity_key=?
                             AND rearmed.event_type=
                                 'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND rearmed.id=?
                             AND exhausted.id=?
                             AND json_extract(rearmed.payload_json,'$.threadId')=?
                             AND json_extract(rearmed.payload_json,'$.recoveryNonce')=?
                           LIMIT 1""",
                        (
                            lineage.get("exhaustedNonce"),
                            candidate["key"],
                            lineage.get("rearmEventId"),
                            lineage.get("exhaustedEventId"),
                            thread_id,
                            lineage.get("exhaustedNonce"),
                        ),
                    ).fetchone()
                    if exact_rearm is None:
                        raise LedgerError("recovery authorization is stale or invalid")
            existing = connection.execute(
                """SELECT 1 FROM events reserved WHERE opportunity_key=?
                   AND event_type='THREAD_RECOVERY_RESERVED'
                   AND json_extract(payload_json,'$.threadId')=?
                   AND reserved.created_at>=?
                   AND NOT EXISTS (
                     SELECT 1 FROM events abandoned
                     WHERE abandoned.opportunity_key=reserved.opportunity_key
                       AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                       AND json_extract(
                             abandoned.payload_json,'$.reservationDigest'
                           )=reserved.dedupe_key
                       AND abandoned.id>reserved.id
                   )""",
                (candidate["key"], thread_id, candidate["dispatchedAt"]),
            ).fetchone()
            if existing:
                raise LedgerError("recovery is already reserved")
            changes_before = connection.total_changes
            self._event(
                connection,
                candidate["key"],
                "THREAD_RECOVERY_RESERVED",
                nonce,
                {
                    "threadId": thread_id,
                    "recoveryNonce": nonce,
                    "recoveryKind": candidate["recoveryKind"],
                    "followupDigest": candidate.get("followupDigest"),
                    "recoveryPromptVersion": candidate.get("recoveryPromptVersion"),
                    "recoveryPromptDigest": candidate.get("recoveryPromptDigest"),
                    "recoveryChainDigest": candidate.get("recoveryChainDigest"),
                    "rearmedFromExhausted": candidate.get("rearmedFromExhausted"),
                },
                now,
            )
            if connection.total_changes == changes_before:
                raise LedgerError("recovery authorization is stale or invalid")
        return candidate

    def commit_recovery(self, *, thread_id: str, nonce: str) -> None:
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT r.opportunity_key AS key,r.dedupe_key,r.payload_json
                   FROM opportunities o
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                   WHERE json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.recoveryNonce')=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='THREAD_RECOVERY_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND json_extract(
                               abandoned.payload_json,'$.reservationDigest'
                             )=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (thread_id, nonce),
            ).fetchone()
            if row is None:
                sent = connection.execute(
                    """SELECT 1 FROM events r JOIN events sent
                       ON sent.opportunity_key=r.opportunity_key
                      AND sent.event_type='THREAD_RECOVERY_SENT'
                      AND sent.dedupe_key=r.dedupe_key
                       WHERE r.event_type='THREAD_RECOVERY_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND json_extract(r.payload_json,'$.recoveryNonce')=?
                       LIMIT 1""",
                    (thread_id, nonce),
                ).fetchone()
                if sent:
                    return
                raise LedgerError("recovery reservation not found")
            payload = json.loads(row["payload_json"])
            if payload.get("recoveryNonce") != nonce:
                raise LedgerError("recovery reservation nonce mismatch")
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_SENT",
                row["dedupe_key"],
                {"threadId": thread_id, "recoveryNonce": nonce},
                iso_z(datetime.now(UTC)),
            )

    def abandon_recovery_delivery(
        self,
        *,
        thread_id: str,
        nonce: str,
        reason: str,
        min_age_minutes: int = 5,
    ) -> None:
        """Retire a recovery reservation after proving delivery or result failure."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            allow_sent = reason in {
                "TERMINAL_RECOVERY_TURN_INTERRUPTED",
                "RECOVERY_RETRY_EXHAUSTED",
            }
            row = connection.execute(
                """SELECT r.id,r.opportunity_key AS key,r.dedupe_key,r.created_at
                   FROM events r
                   WHERE r.event_type='THREAD_RECOVERY_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.recoveryNonce')=?
                     AND r.dedupe_key=?
                     AND (? OR NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='THREAD_RECOVERY_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                     ))
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND json_extract(
                               abandoned.payload_json,'$.reservationDigest'
                             )=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (thread_id, nonce, nonce, int(allow_sent)),
            ).fetchone()
            if row is None:
                raise LedgerError("recovery delivery is not abandonable")
            minimum_age = timedelta(minutes=max(0 if allow_sent else 1, min_age_minutes))
            if parse_time(row["created_at"]) + minimum_age > current:
                raise LedgerError("recovery delivery is not old enough to abandon")
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{row['dedupe_key']}|{row['created_at']}"),
                {
                    "threadId": thread_id,
                    "recoveryNonce": nonce,
                    "reservationDigest": row["dedupe_key"],
                    "reservedAt": row["created_at"],
                    "reason": reason,
                    "minimumAgeMinutes": max(0 if allow_sent else 1, min_age_minutes),
                },
                now,
            )

    def exhaust_recovery(
        self,
        *,
        thread_id: str,
        nonce: str,
        terminal_error: dict[str, Any] | None = None,
        retry_count: int | None = None,
    ) -> None:
        """Release a repeatedly interrupted recovery and make the terminal state durable."""

        with self.transaction() as connection:
            row = connection.execute(
                """SELECT r.opportunity_key AS key,r.dedupe_key,r.payload_json,
                          r.created_at
                   FROM events r
                   WHERE r.event_type='THREAD_RECOVERY_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.recoveryNonce')=?
                     AND r.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND json_extract(
                               abandoned.payload_json,'$.reservationDigest'
                             )=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (thread_id, nonce, nonce),
            ).fetchone()
            if row is None:
                raise LedgerError("exhausted recovery reservation not found")
            reservation = json.loads(row["payload_json"])
            now = iso_z(datetime.now(UTC))
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{row['dedupe_key']}|{row['created_at']}"),
                {
                    "threadId": thread_id,
                    "recoveryNonce": nonce,
                    "reservationDigest": row["dedupe_key"],
                    "reservedAt": row["created_at"],
                    "reason": "RECOVERY_RETRY_EXHAUSTED",
                    "minimumAgeMinutes": 0,
                },
                now,
            )
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_RETRY_EXHAUSTED",
                nonce,
                {
                    "threadId": thread_id,
                    "recoveryNonce": nonce,
                    "recoveryKind": reservation.get("recoveryKind"),
                    "followupDigest": reservation.get("followupDigest"),
                    "recoveryPromptVersion": reservation.get("recoveryPromptVersion"),
                    "recoveryPromptDigest": reservation.get("recoveryPromptDigest"),
                    "recoveryChainDigest": reservation.get("recoveryChainDigest"),
                    "rearmedFromExhausted": reservation.get("rearmedFromExhausted"),
                    "retryCount": retry_count,
                    "terminalError": terminal_error,
                },
                now,
            )
            if reservation.get("recoveryKind") == "VALIDATION_FOLLOWUP_RESULT":
                result_digest = str(reservation.get("followupDigest") or "")
                deferred = connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_RESULT_VALIDATION_DEFERRED'
                         AND json_extract(payload_json,'$.resultDigest')=?
                       ORDER BY id DESC LIMIT 1""",
                    (row["key"], result_digest),
                ).fetchone()
                if deferred is not None:
                    deferred_payload = json.loads(deferred["payload_json"])
                    self._event(
                        connection,
                        row["key"],
                        "VALIDATION_FOLLOWUP_NO_PROGRESS",
                        result_digest,
                        {
                            "threadId": thread_id,
                            "resultDigest": result_digest,
                            "previousResultDigest": result_digest,
                            "missing": list(deferred_payload.get("missing") or []),
                            "reason": "RECOVERY_RETRY_EXHAUSTED",
                        },
                        now,
                    )

    def acknowledge_exhausted_recovery(
        self, *, thread_id: str, nonce: str, reason: str
    ) -> dict[str, Any]:
        """Park one reviewed implementation recovery without changing its task result."""

        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
            raise LedgerError("recovery acknowledgement reason must be machine-readable")
        with self.transaction() as connection:
            existing_ack = connection.execute(
                """SELECT ack.payload_json,ack.created_at,o.key,o.issue_url,o.title,o.stage,
                          i.worktree_path
                   FROM events ack
                   JOIN opportunities o ON o.key=ack.opportunity_key
                   JOIN intents i ON i.opportunity_key=ack.opportunity_key
                    AND i.thread_id=?
                   WHERE ack.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                     AND ack.dedupe_key=?
                     AND json_extract(ack.payload_json,'$.threadId')=?
                     AND json_extract(ack.payload_json,'$.recoveryNonce')=?
                   ORDER BY ack.id DESC LIMIT 1""",
                (thread_id, nonce, thread_id, nonce),
            ).fetchone()
            if existing_ack is not None:
                existing_payload = json.loads(existing_ack["payload_json"])
                if existing_payload.get("reason") != reason:
                    raise LedgerError("exhausted recovery was acknowledged with another reason")
                return {
                    "key": existing_ack["key"],
                    "issueUrl": existing_ack["issue_url"],
                    "title": existing_ack["title"],
                    "stage": existing_ack["stage"],
                    "threadId": thread_id,
                    "worktreePath": existing_ack["worktree_path"],
                    "recoveryNonce": nonce,
                    "recoveryKind": existing_payload.get("recoveryKind"),
                    "followupDigest": existing_payload.get("followupDigest"),
                    "reason": reason,
                    "retryCount": existing_payload.get("retryCount"),
                    "terminalError": existing_payload.get("terminalError"),
                    "acknowledgedAt": existing_ack["created_at"],
                    "alreadyAcknowledged": True,
                }
            row = connection.execute(
                """SELECT exhausted.id AS exhausted_id,
                          exhausted.opportunity_key AS key,
                          exhausted.payload_json AS exhausted_payload,
                          recovery.payload_json AS recovery_payload,
                          o.issue_url,o.title,o.stage,i.worktree_path
                   FROM events exhausted
                   JOIN events recovery
                     ON recovery.opportunity_key=exhausted.opportunity_key
                    AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                    AND recovery.dedupe_key=exhausted.dedupe_key
                   JOIN events followup
                     ON followup.opportunity_key=exhausted.opportunity_key
                    AND followup.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                    AND followup.dedupe_key=
                        json_extract(recovery.payload_json,'$.followupDigest')
                   JOIN intents i ON i.opportunity_key=exhausted.opportunity_key
                   JOIN opportunities o ON o.key=exhausted.opportunity_key
                   WHERE exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                     AND exhausted.dedupe_key=?
                     AND json_extract(recovery.payload_json,'$.threadId')=?
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                     AND json_extract(followup.payload_json,'$.threadId')=?
                     AND followup.id=(
                       SELECT MAX(latest.id) FROM events latest
                       WHERE latest.opportunity_key=exhausted.opportunity_key
                         AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     )
                     AND recovery.id>followup.id
                     AND i.thread_id=? AND i.status='DISPATCHED'
                     AND recovery.id>(
                       SELECT COALESCE(MAX(dispatched.id),0)
                       FROM events dispatched
                       WHERE dispatched.opportunity_key=i.opportunity_key
                         AND dispatched.event_type='DISPATCHED'
                         AND dispatched.dedupe_key=i.thread_id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=exhausted.opportunity_key
                         AND later.id>exhausted.id
                         AND (
                           later.event_type IN (
                             'TASK_RESULT_INGESTED',
                             'PUBLISHED_TASK_RESULT_BACKFILLED',
                             'PR_FOLLOWUP_RESULT_INGESTED',
                             'IMPLEMENTATION_CONTEXT_REPAIRED',
                             'AUDIT_PASS',
                             'AUDIT_NO_GO',
                             'VALIDATION_PENDING',
                             'FIX_READY',
                             'PR_OPEN',
                             'CI_GREEN',
                             'MAINTAINER_ACCEPTED',
                             'MERGED',
                             'CLOSED'
                           )
                           OR (
                             later.event_type='THREAD_RECOVERY_RESERVED'
                             AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                             AND json_extract(
                                   later.payload_json,
                                   '$.rearmedFromExhausted.exhaustedNonce'
                                 )=exhausted.dedupe_key
                           )
                           OR (
                             later.event_type=
                                 'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                             AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                             AND json_extract(later.payload_json,'$.recoveryNonce')=
                                 exhausted.dedupe_key
                           )
                           OR (
                             later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                             AND json_extract(later.payload_json,'$.recoveryNonce')=
                                 exhausted.dedupe_key
                           )
                         )
                     )
                   ORDER BY exhausted.id DESC LIMIT 1""",
                (nonce, thread_id, thread_id, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("active exhausted recovery not found")
            exhausted = json.loads(row["exhausted_payload"])
            recovery = json.loads(row["recovery_payload"])
            now = iso_z(datetime.now(UTC))
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED",
                nonce,
                {
                    "threadId": thread_id,
                    "recoveryNonce": nonce,
                    "reason": reason,
                    "recoveryKind": recovery.get("recoveryKind"),
                    "followupDigest": recovery.get("followupDigest"),
                    "retryCount": exhausted.get("retryCount"),
                    "terminalError": exhausted.get("terminalError"),
                    "exhaustedEventId": int(row["exhausted_id"]),
                },
                now,
            )
            return {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "stage": row["stage"],
                "threadId": thread_id,
                "worktreePath": row["worktree_path"],
                "recoveryNonce": nonce,
                "recoveryKind": recovery.get("recoveryKind"),
                "followupDigest": recovery.get("followupDigest"),
                "reason": reason,
                "retryCount": exhausted.get("retryCount"),
                "terminalError": exhausted.get("terminalError"),
                "acknowledgedAt": now,
            }

    def acknowledged_exhausted_recoveries(self) -> list[dict[str, Any]]:
        """Expose reviewed implementation recoveries that remain explicitly parked."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,o.stage,i.intent_id,i.thread_id,
                          i.worktree_path,ack.payload_json,ack.created_at AS acknowledged_at,
                          exhausted.created_at AS exhausted_at
                   FROM events ack
                   JOIN events exhausted
                     ON exhausted.opportunity_key=ack.opportunity_key
                    AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                    AND exhausted.dedupe_key=
                        json_extract(ack.payload_json,'$.recoveryNonce')
                   JOIN events recovery
                     ON recovery.opportunity_key=exhausted.opportunity_key
                    AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                    AND recovery.dedupe_key=exhausted.dedupe_key
                   JOIN events followup
                     ON followup.opportunity_key=exhausted.opportunity_key
                    AND followup.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                    AND followup.dedupe_key=
                        json_extract(recovery.payload_json,'$.followupDigest')
                   JOIN opportunities o ON o.key=ack.opportunity_key
                   JOIN intents i ON i.opportunity_key=ack.opportunity_key
                    AND i.thread_id=json_extract(ack.payload_json,'$.threadId')
                   WHERE ack.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                     AND json_extract(followup.payload_json,'$.threadId')=
                         json_extract(ack.payload_json,'$.threadId')
                     AND followup.id=(
                       SELECT MAX(latest.id) FROM events latest
                       WHERE latest.opportunity_key=ack.opportunity_key
                         AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     )
                     AND recovery.id>followup.id
                     AND NOT EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=ack.opportunity_key
                         AND later.id>ack.id
                         AND (
                           later.event_type IN (
                             'TASK_RESULT_INGESTED',
                             'PUBLISHED_TASK_RESULT_BACKFILLED',
                             'PR_FOLLOWUP_RESULT_INGESTED',
                             'IMPLEMENTATION_CONTEXT_REPAIRED',
                             'AUDIT_PASS',
                             'AUDIT_NO_GO',
                             'VALIDATION_PENDING',
                             'FIX_READY',
                             'PR_OPEN',
                             'CI_GREEN',
                             'MAINTAINER_ACCEPTED',
                             'MERGED',
                             'CLOSED'
                           )
                           OR (
                             later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND json_extract(later.payload_json,'$.threadId')=
                                 json_extract(ack.payload_json,'$.threadId')
                             AND json_extract(later.payload_json,'$.recoveryNonce')=
                                 json_extract(ack.payload_json,'$.recoveryNonce')
                           )
                         )
                     )
                   ORDER BY ack.created_at,ack.id"""
            ).fetchall()
        parked: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            parked.append(
                {
                    "key": row["key"],
                    "issueUrl": row["issue_url"],
                    "title": row["title"],
                    "stage": row["stage"],
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "recoveryNonce": payload.get("recoveryNonce"),
                    "recoveryKind": payload.get("recoveryKind"),
                    "followupDigest": payload.get("followupDigest"),
                    "retryCount": payload.get("retryCount"),
                    "terminalError": payload.get("terminalError"),
                    "reason": payload.get("reason"),
                    "exhaustedAt": row["exhausted_at"],
                    "acknowledgedAt": row["acknowledged_at"],
                    "parked": True,
                    "rearmable": True,
                    "occupiesTaskSlot": False,
                }
            )
        return parked

    def rearm_acknowledged_recovery(
        self, *, thread_id: str, nonce: str, reason: str
    ) -> dict[str, Any]:
        """Explicitly reopen one reviewed, parked implementation recovery."""

        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
            raise LedgerError("recovery rearm reason must be machine-readable")
        with self.transaction() as connection:
            existing_rearm = connection.execute(
                """SELECT rearmed.payload_json,rearmed.created_at,
                          o.key,o.issue_url,o.title,o.stage,i.worktree_path
                   FROM events rearmed
                   JOIN opportunities o ON o.key=rearmed.opportunity_key
                   JOIN intents i ON i.opportunity_key=rearmed.opportunity_key
                    AND i.thread_id=?
                   WHERE rearmed.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                     AND rearmed.dedupe_key=?
                     AND json_extract(rearmed.payload_json,'$.threadId')=?
                     AND json_extract(rearmed.payload_json,'$.recoveryNonce')=?
                   ORDER BY rearmed.id DESC LIMIT 1""",
                (thread_id, nonce, thread_id, nonce),
            ).fetchone()
            if existing_rearm is not None:
                existing_payload = json.loads(existing_rearm["payload_json"])
                if existing_payload.get("reason") != reason:
                    raise LedgerError("parked recovery was rearmed with another reason")
                return {
                    "key": existing_rearm["key"],
                    "issueUrl": existing_rearm["issue_url"],
                    "title": existing_rearm["title"],
                    "stage": existing_rearm["stage"],
                    "threadId": thread_id,
                    "worktreePath": existing_rearm["worktree_path"],
                    "recoveryNonce": nonce,
                    "recoveryKind": existing_payload.get("recoveryKind"),
                    "followupDigest": existing_payload.get("followupDigest"),
                    "reason": reason,
                    "rearmedAt": existing_rearm["created_at"],
                    "alreadyRearmed": True,
                }
            row = connection.execute(
                """SELECT ack.id AS acknowledgement_event_id,
                          exhausted.id AS exhausted_event_id,
                          ack.opportunity_key AS key,ack.payload_json,
                          o.issue_url,o.title,o.stage,i.worktree_path
                   FROM events ack
                   JOIN events exhausted
                     ON exhausted.opportunity_key=ack.opportunity_key
                    AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                    AND exhausted.dedupe_key=?
                   JOIN events recovery
                     ON recovery.opportunity_key=exhausted.opportunity_key
                    AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                    AND recovery.dedupe_key=exhausted.dedupe_key
                   JOIN events followup
                     ON followup.opportunity_key=exhausted.opportunity_key
                    AND followup.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                    AND followup.dedupe_key=
                        json_extract(recovery.payload_json,'$.followupDigest')
                   JOIN opportunities o ON o.key=ack.opportunity_key
                   JOIN intents i ON i.opportunity_key=ack.opportunity_key
                    AND i.thread_id=? AND i.status='DISPATCHED'
                   WHERE ack.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                     AND json_extract(ack.payload_json,'$.threadId')=?
                     AND json_extract(ack.payload_json,'$.recoveryNonce')=?
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                     AND json_extract(followup.payload_json,'$.threadId')=?
                     AND followup.id=(
                       SELECT MAX(latest.id) FROM events latest
                       WHERE latest.opportunity_key=ack.opportunity_key
                         AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     )
                     AND recovery.id>followup.id
                     AND NOT EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=ack.opportunity_key
                         AND later.id>ack.id
                         AND (
                           later.event_type IN (
                             'TASK_RESULT_INGESTED',
                             'PUBLISHED_TASK_RESULT_BACKFILLED',
                             'PR_FOLLOWUP_RESULT_INGESTED',
                             'IMPLEMENTATION_CONTEXT_REPAIRED',
                             'AUDIT_PASS',
                             'AUDIT_NO_GO',
                             'VALIDATION_PENDING',
                             'FIX_READY',
                             'PR_OPEN',
                             'CI_GREEN',
                             'MAINTAINER_ACCEPTED',
                             'MERGED',
                             'CLOSED'
                           )
                           OR (
                             later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND json_extract(later.payload_json,'$.threadId')=?
                             AND json_extract(later.payload_json,'$.recoveryNonce')=?
                           )
                         )
                     )
                   ORDER BY ack.id DESC LIMIT 1""",
                (nonce, thread_id, thread_id, nonce, thread_id, thread_id, nonce),
            ).fetchone()
            if row is None:
                raise LedgerError("parked exhausted recovery not found")
            acknowledged = json.loads(row["payload_json"])
            now = iso_z(datetime.now(UTC))
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED",
                nonce,
                {
                    "threadId": thread_id,
                    "recoveryNonce": nonce,
                    "reason": reason,
                    "recoveryKind": acknowledged.get("recoveryKind"),
                    "followupDigest": acknowledged.get("followupDigest"),
                    "acknowledgementReason": acknowledged.get("reason"),
                    "acknowledgementEventId": int(row["acknowledgement_event_id"]),
                    "exhaustedEventId": int(row["exhausted_event_id"]),
                },
                now,
            )
            return {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "stage": row["stage"],
                "threadId": thread_id,
                "worktreePath": row["worktree_path"],
                "recoveryNonce": nonce,
                "recoveryKind": acknowledged.get("recoveryKind"),
                "followupDigest": acknowledged.get("followupDigest"),
                "reason": reason,
                "rearmedAt": now,
            }

    def record_validation_deferred(
        self,
        key: str,
        *,
        thread_id: str,
        result_digest: str,
        missing: list[str],
        progress_marker: str | None = None,
    ) -> None:
        """Record a substantive result that needs validation, not task recovery."""

        with self.transaction() as connection:
            row = connection.execute(
                """SELECT 1 FROM intents i
                   WHERE i.opportunity_key=? AND i.thread_id=?
                     AND i.status IN ('DISPATCHED','COMPLETED')""",
                (key, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("validation-deferred task is not dispatched")
            payload: dict[str, Any] = {
                "threadId": thread_id,
                "resultDigest": result_digest,
                "missing": missing,
            }
            if progress_marker:
                payload["progressMarker"] = progress_marker
            self._event(
                connection,
                key,
                "TASK_RESULT_VALIDATION_DEFERRED",
                result_digest,
                payload,
                iso_z(datetime.now(UTC)),
            )

            self._mark_validation_no_progress(
                connection,
                key=key,
                thread_id=thread_id,
                result_digest=result_digest,
                missing=missing,
                progress_marker=progress_marker,
            )

    def record_validation_prefetch_blocked(
        self,
        *,
        key: str,
        thread_id: str,
        result_digest: str,
        dependency_failures: list[dict[str, Any]],
    ) -> None:
        """Persist a failed deterministic prefetch so the scheduler does not retry forever."""

        with self.transaction() as connection:
            row = connection.execute(
                """SELECT 1 FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events d ON d.opportunity_key=o.key
                     AND d.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                     AND json_extract(d.payload_json,'$.resultDigest')=?
                   WHERE o.key=? AND i.thread_id=?
                     AND o.stage IN (
                       'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                     )
                   LIMIT 1""",
                (result_digest, key, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("validation prefetch task is not current")
            self._event(
                connection,
                key,
                "VALIDATION_PREFETCH_BLOCKED",
                result_digest,
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "dependencyFailures": dependency_failures,
                },
                iso_z(datetime.now(UTC)),
            )

    def validation_prefetch_blocked(self) -> list[dict[str, Any]]:
        """Return prefetch failures that still apply to the current deferred result."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,b.payload_json,b.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN events b ON b.id=(
                     SELECT MAX(b2.id) FROM events b2
                     WHERE b2.opportunity_key=o.key
                       AND b2.event_type='VALIDATION_PREFETCH_BLOCKED'
                       AND json_extract(b2.payload_json,'$.resultDigest')=
                           json_extract(d.payload_json,'$.resultDigest')
                   )
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )"""
            ).fetchall()
        blocked: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            blocked.append(
                {
                    "key": row["key"],
                    "threadId": payload.get("threadId"),
                    "resultDigest": payload.get("resultDigest"),
                    "dependencyFailures": list(payload.get("dependencyFailures") or []),
                    "blockedAt": row["created_at"],
                }
            )
        return blocked

    @staticmethod
    def _normalized_validation_missing(missing: Any) -> tuple[str, ...]:
        if not isinstance(missing, list):
            return ()
        return tuple(sorted({str(item).strip() for item in missing if str(item).strip()}))

    def _mark_validation_no_progress(
        self,
        connection: sqlite3.Connection,
        *,
        key: str,
        thread_id: str,
        result_digest: str,
        missing: list[str],
        progress_marker: str | None = None,
    ) -> bool:
        """Stop repeat continuations when a completed continuation changed no gap."""

        normalized_missing = self._normalized_validation_missing(missing)
        if not normalized_missing:
            return False
        previous = connection.execute(
            """SELECT d.dedupe_key,d.payload_json
               FROM events d
               WHERE d.opportunity_key=?
                 AND d.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                 AND d.dedupe_key<>?
                 AND EXISTS (
                   SELECT 1 FROM events s
                   WHERE s.opportunity_key=d.opportunity_key
                     AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                     AND s.dedupe_key=d.dedupe_key
                 )
               ORDER BY d.id DESC LIMIT 1""",
            (key, result_digest),
        ).fetchone()
        if previous is None:
            return False
        previous_payload = json.loads(previous["payload_json"])
        if (
            self._normalized_validation_missing(previous_payload.get("missing"))
            != normalized_missing
        ):
            return False
        previous_progress = str(previous_payload.get("progressMarker") or "")
        current_progress = str(progress_marker or "")
        if current_progress and previous_progress != current_progress:
            return False
        self._event(
            connection,
            key,
            "VALIDATION_FOLLOWUP_NO_PROGRESS",
            result_digest,
            {
                "threadId": thread_id,
                "resultDigest": result_digest,
                "previousResultDigest": previous["dedupe_key"],
                "missing": list(normalized_missing),
                "progressMarker": current_progress or None,
                "reason": "UNCHANGED_VALIDATION_GAP",
            },
            iso_z(datetime.now(UTC)),
        )
        return True

    def reconcile_validation_no_progress(self) -> int:
        """Backfill no-progress markers for current validation results."""

        marked = 0
        with self.transaction() as connection:
            exhausted_rows = connection.execute(
                """SELECT o.key,d.payload_json
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND EXISTS (
                       SELECT 1 FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.opportunity_key=o.key
                         AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'VALIDATION_FOLLOWUP_RESULT'
                         AND json_extract(recovery.payload_json,'$.followupDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events n
                       WHERE n.opportunity_key=o.key
                         AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                         AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                     )"""
            ).fetchall()
            for row in exhausted_rows:
                payload = json.loads(row["payload_json"])
                result_digest = str(payload.get("resultDigest") or "")
                self._event(
                    connection,
                    row["key"],
                    "VALIDATION_FOLLOWUP_NO_PROGRESS",
                    result_digest,
                    {
                        "threadId": str(payload.get("threadId") or ""),
                        "resultDigest": result_digest,
                        "previousResultDigest": result_digest,
                        "missing": list(payload.get("missing") or []),
                        "reason": "RECOVERY_RETRY_EXHAUSTED",
                    },
                    iso_z(datetime.now(UTC)),
                )
                marked += 1
            rows = connection.execute(
                """SELECT o.key,d.payload_json
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events n
                       WHERE n.opportunity_key=o.key
                         AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                         AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                     )"""
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"])
                if self._mark_validation_no_progress(
                    connection,
                    key=row["key"],
                    thread_id=str(payload.get("threadId") or ""),
                    result_digest=str(payload.get("resultDigest") or ""),
                    missing=list(payload.get("missing") or []),
                    progress_marker=str(payload.get("progressMarker") or "") or None,
                ):
                    marked += 1
        return marked

    def rearm_validation_no_progress_for_review(
        self,
        *,
        key: str,
        result_digest: str,
        review_marker: str,
        reason: str,
    ) -> bool:
        """Reopen one stalled result only when controller-owned evidence changes."""

        evidence_fingerprint = sha256_text(f"{review_marker}|{reason}")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT n.id,n.payload_json
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN events n ON n.opportunity_key=o.key
                     AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                     AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                   WHERE o.key=?
                     AND json_extract(d.payload_json,'$.resultDigest')=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events active_rearm
                       WHERE active_rearm.opportunity_key=o.key
                         AND active_rearm.event_type=
                             'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                         AND json_extract(active_rearm.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND active_rearm.id>n.id
                     )
                   ORDER BY n.id DESC LIMIT 1""",
                (key, result_digest),
            ).fetchone()
            if row is None:
                return False
            previous = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                   ORDER BY id DESC LIMIT 1""",
                (key,),
            ).fetchone()
            if previous is not None:
                previous_payload = json.loads(previous["payload_json"])
                previous_fingerprint = str(previous_payload.get("evidenceFingerprint") or "")
                if not previous_fingerprint:
                    previous_fingerprint = sha256_text(
                        f"{previous_payload.get('reviewMarker', '')}|"
                        f"{previous_payload.get('reason', '')}"
                    )
                if previous_fingerprint == evidence_fingerprint:
                    return False
            no_progress = json.loads(row["payload_json"])
            thread_id = str(no_progress.get("threadId") or "")
            dedupe_key = sha256_text(f"{row['id']}|{evidence_fingerprint}")
            self._event(
                connection,
                key,
                "VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
                dedupe_key,
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "reviewMarker": review_marker,
                    "reason": reason,
                    "evidenceFingerprint": evidence_fingerprint,
                },
                now,
            )
        return True

    def validation_followup_candidates(self) -> list[dict[str, Any]]:
        """Return validation-pending tasks that have not been resumed for this result."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,i.worktree_path,
                          d.payload_json,d.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND i.thread_id=json_extract(d.payload_json,'$.threadId')
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )
                     AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events r WHERE r.opportunity_key=o.key
                         AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=r.opportunity_key
                             AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.resultDigest')=
                                 json_extract(r.payload_json,'$.resultDigest')
                             AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                             AND abandoned.id>r.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events cancelled
                           WHERE cancelled.opportunity_key=r.opportunity_key
                             AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                             AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                                 json_extract(r.payload_json,'$.reservationDigest')
                             AND cancelled.id>r.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=r.opportunity_key
                             AND rearmed.event_type=
                                 'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                             AND json_extract(rearmed.payload_json,'$.resultDigest')=
                                 json_extract(d.payload_json,'$.resultDigest')
                             AND rearmed.id>r.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events n WHERE n.opportunity_key=o.key
                         AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                         AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=n.opportunity_key
                             AND rearmed.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                             AND json_extract(rearmed.payload_json,'$.resultDigest')=
                                 json_extract(d.payload_json,'$.resultDigest')
                             AND rearmed.id>n.id
                         )
                     )
                   ORDER BY d.created_at"""
            ).fetchall()
        candidates: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            candidates.append(
                {
                    "key": row["key"],
                    "issueUrl": row["issue_url"],
                    "title": row["title"],
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "resultDigest": payload.get("resultDigest"),
                    "missing": list(payload.get("missing") or []),
                    "deferredAt": row["created_at"],
                }
            )
        return candidates

    def validation_no_progress(self) -> list[dict[str, Any]]:
        """Return current validation tasks whose latest continuation made no progress."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.thread_id,i.worktree_path,
                          d.payload_json,n.payload_json AS no_progress_json,n.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN events n ON n.opportunity_key=o.key
                     AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                     AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                   JOIN intents i ON i.opportunity_key=o.key
                     AND i.thread_id=json_extract(d.payload_json,'$.threadId')
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=o.key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND json_extract(cancelled.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND cancelled.id>n.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rearmed
                       WHERE rearmed.opportunity_key=n.opportunity_key
                         AND rearmed.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                         AND json_extract(rearmed.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND rearmed.id>n.id
                     )
                   ORDER BY n.created_at"""
            ).fetchall()
        blocked: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            no_progress = json.loads(row["no_progress_json"])
            blocked.append(
                {
                    "key": row["key"],
                    "issueUrl": row["issue_url"],
                    "title": row["title"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "resultDigest": payload.get("resultDigest"),
                    "previousResultDigest": no_progress.get("previousResultDigest"),
                    "missing": list(no_progress.get("missing") or []),
                    "progressMarker": no_progress.get("progressMarker"),
                    "reason": no_progress.get("reason"),
                    "blockedAt": row["created_at"],
                }
            )
        return blocked

    def quarantined_validation_followups(self) -> list[dict[str, Any]]:
        """Expose validation tasks isolated by an active task quarantine."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.thread_id,i.worktree_path,
                          d.payload_json,q.reason,q.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND i.thread_id=json_extract(d.payload_json,'$.threadId')
                   JOIN task_quarantines q ON q.opportunity_key=o.key
                     AND q.status='ACTIVE'
                     AND q.quarantine_id=(
                       SELECT MAX(latest.quarantine_id)
                       FROM task_quarantines latest
                       WHERE latest.opportunity_key=o.key
                         AND latest.status='ACTIVE'
                     )
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )
                   ORDER BY q.created_at,o.key"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "resultDigest": json.loads(row["payload_json"]).get("resultDigest"),
                "missing": list(json.loads(row["payload_json"]).get("missing") or []),
                "reason": row["reason"],
                "quarantinedAt": row["created_at"],
            }
            for row in rows
        ]

    def validation_followup_was_sent(self, *, thread_id: str) -> bool:
        """Return whether this task already received a validation continuation."""

        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM events
                   WHERE event_type='VALIDATION_FOLLOWUP_SENT'
                     AND json_extract(payload_json,'$.threadId')=?
                   LIMIT 1""",
                (thread_id,),
            ).fetchone()
        return row is not None

    def reserve_validation_followup(
        self,
        *,
        thread_id: str,
        result_digest: str,
        max_active: int | None = None,
        exclude_intent_id: str | None = None,
    ) -> dict[str, Any]:
        candidate = next(
            (
                item
                for item in self.validation_followup_candidates()
                if item["threadId"] == thread_id and item["resultDigest"] == result_digest
            ),
            None,
        )
        if candidate is None:
            raise LedgerError("validation follow-up authorization is stale or invalid")
        if exclude_intent_id is not None and exclude_intent_id != candidate["intentId"]:
            raise LedgerError("validation follow-up WIP exclusion does not match the task")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            require_quarantine_clear(
                connection,
                opportunity_key=str(candidate["key"]),
                operation="validation follow-up reservation",
            )
            if max_active is not None and self._active_task_count(
                connection,
                now=now,
                exclude_intent_id=exclude_intent_id,
            ) >= max(0, max_active):
                raise LedgerError("global task WIP limit reached")
            prior_attempts = int(
                connection.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE opportunity_key=?
                         AND event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND json_extract(payload_json,'$.threadId')=?
                         AND json_extract(payload_json,'$.resultDigest')=?""",
                    (candidate["key"], thread_id, result_digest),
                ).fetchone()[0]
            )
            attempt = prior_attempts + 1
            reservation_digest = sha256_text(
                f"{candidate['key']}|{thread_id}|{result_digest}|attempt:{attempt}"
            )
            self._event(
                connection,
                candidate["key"],
                "VALIDATION_FOLLOWUP_RESERVED",
                reservation_digest,
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "missing": candidate["missing"],
                    "attempt": attempt,
                    "reservationDigest": reservation_digest,
                },
                now,
            )
        return candidate | {"attempt": attempt, "reservationDigest": reservation_digest}

    def commit_validation_followup(
        self,
        *,
        thread_id: str,
        result_digest: str,
        reservation_digest: str | None = None,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.resultDigest')=?
                     AND (? IS NULL OR json_extract(r.payload_json,'$.reservationDigest')=?)
                   WHERE i.thread_id=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                         AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND s.dedupe_key=?
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=r.opportunity_key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND cancelled.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (result_digest, reservation_digest, reservation_digest, thread_id, result_digest),
            ).fetchone()
            if row is None:
                sent = connection.execute(
                    """SELECT 1 FROM events r JOIN events s
                       ON s.opportunity_key=r.opportunity_key
                      AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                      AND s.dedupe_key=?
                       WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.resultDigest')=?
                         AND (? IS NULL OR json_extract(r.payload_json,'$.reservationDigest')=?)
                       LIMIT 1""",
                    (
                        result_digest,
                        thread_id,
                        result_digest,
                        reservation_digest,
                        reservation_digest,
                    ),
                ).fetchone()
                if sent:
                    return
                raise LedgerError(
                    "validation follow-up reservation is missing or already committed"
                )
            self._event(
                connection,
                row["key"],
                "VALIDATION_FOLLOWUP_SENT",
                result_digest,
                {"threadId": thread_id, "resultDigest": result_digest},
                now,
            )

    def unresolved_validation_followups(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,i.worktree_path,r.payload_json,r.created_at,r.dedupe_key
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key AND i2.thread_id IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                       AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                       AND s.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=r.opportunity_key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND cancelled.id>r.id
                     ) ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "worktreePath": row["worktree_path"],
                "threadId": json.loads(row["payload_json"]).get("threadId"),
                "resultDigest": json.loads(row["payload_json"]).get("resultDigest"),
                "reservationDigest": json.loads(row["payload_json"]).get("reservationDigest")
                or row["dedupe_key"],
                "missing": list(json.loads(row["payload_json"]).get("missing") or []),
                "reservedAt": row["created_at"],
            }
            for row in rows
        ]

    def abandon_validation_followup_delivery(
        self,
        *,
        thread_id: str,
        result_digest: str,
        reason: str,
        min_age_minutes: int = 90,
    ) -> None:
        """Retire an old reservation when no target task turn materialized."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT r.id,r.opportunity_key AS key,r.dedupe_key,r.created_at
                   FROM events r
                   WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.resultDigest')=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND sent.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (thread_id, result_digest),
            ).fetchone()
            if row is None:
                raise LedgerError("validation follow-up delivery is not abandonable")
            minimum_age = timedelta(minutes=max(1, min_age_minutes))
            if parse_time(row["created_at"]) + minimum_age > current:
                raise LedgerError("validation follow-up delivery is not old enough to abandon")
            self._event(
                connection,
                row["key"],
                "VALIDATION_FOLLOWUP_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{result_digest}|{row['created_at']}"),
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "reservationDigest": row["dedupe_key"],
                    "reservedAt": row["created_at"],
                    "reason": reason,
                    "minimumAgeMinutes": max(1, min_age_minutes),
                },
                now,
            )

    def cancel_validation_followup_reservation(
        self,
        *,
        thread_id: str,
        result_digest: str,
        reservation_digest: str,
        reason: str,
    ) -> None:
        """Immediately invalidate the latest unstarted validation reservation."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT r.id,r.opportunity_key AS key,r.dedupe_key,r.created_at
                   FROM events r
                   WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.resultDigest')=?
                     AND json_extract(r.payload_json,'$.reservationDigest')=?
                     AND r.id=(
                       SELECT MAX(latest.id) FROM events latest
                       WHERE latest.opportunity_key=r.opportunity_key
                         AND latest.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND sent.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=r.opportunity_key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND cancelled.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events started
                       WHERE started.opportunity_key=r.opportunity_key
                         AND started.event_type='TASK_TURN_DELIVERY_STARTED'
                         AND json_extract(started.payload_json,'$.deliveryKind')='validation-followup'
                         AND json_extract(started.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND started.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (thread_id, result_digest, reservation_digest),
            ).fetchone()
            if row is None:
                raise LedgerError("validation follow-up reservation is not cancellable")
            self._event(
                connection,
                row["key"],
                "VALIDATION_FOLLOWUP_RESERVATION_CANCELLED",
                sha256_text(f"cancelled|{reservation_digest}"),
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "reservationDigest": reservation_digest,
                    "reservedAt": row["created_at"],
                    "reason": reason,
                    "minimumAgeMinutes": 0,
                },
                now,
            )

    def stale_validation_followups(self, *, min_age_minutes: int = 90) -> list[dict[str, Any]]:
        cutoff = iso_z(
            datetime.now(UTC) - timedelta(minutes=max(30, min(int(min_age_minutes), 24 * 60)))
        )
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,d.payload_json,s.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                     AND s.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                     AND json_extract(s.payload_json,'$.threadId')=
                         json_extract(d.payload_json,'$.threadId')
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   ) AND s.created_at<=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type IN (
                           'TASK_RESULT_INGESTED','PUBLISHED_TASK_RESULT_BACKFILLED'
                         )
                         AND result.id>s.id
                         AND json_extract(result.payload_json,'$.threadId')=
                             json_extract(d.payload_json,'$.threadId')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events exhausted
                       JOIN events recovery
                         ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       WHERE exhausted.opportunity_key=o.key
                         AND exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'VALIDATION_FOLLOWUP_RESULT'
                         AND json_extract(recovery.payload_json,'$.followupDigest')=s.dedupe_key
                     )
                   ORDER BY s.created_at""",
                (cutoff,),
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "threadId": json.loads(row["payload_json"]).get("threadId"),
                "resultDigest": json.loads(row["payload_json"]).get("resultDigest"),
                "missing": list(json.loads(row["payload_json"]).get("missing") or []),
                "sentAt": row["created_at"],
            }
            for row in rows
        ]

    def task_context(
        self,
        *,
        issue_url: str,
        thread_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any] | None:
        clauses = ["o.issue_url=?"]
        params: list[Any] = [issue_url]
        if thread_id:
            clauses.append("i.thread_id=?")
            params.append(thread_id)
        if worktree_path and not thread_id:
            raw_worktree = str(worktree_path)
            resolved_worktree = str(Path(worktree_path).resolve())
            if raw_worktree == resolved_worktree:
                clauses.append("i.worktree_path=?")
                params.append(resolved_worktree)
            else:
                clauses.append("i.worktree_path IN (?,?)")
                params.extend((raw_worktree, resolved_worktree))
        if len(clauses) == 1:
            raise ValueError("thread_id or worktree_path is required")
        with self.connect() as connection:
            row = connection.execute(
                f"""SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                           i.worktree_path,i.status,i.payload_json,i.title_time
                    FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                    WHERE {" AND ".join(clauses)}
                    ORDER BY i.updated_at DESC LIMIT 1""",
                tuple(params),
            ).fetchone()
            audit_rows = (
                _intent_bound_audit_rows(connection, row["key"], row["intent_id"])
                if row is not None
                else []
            )
            audit_row = audit_rows[0] if audit_rows else None
            publication_row = (
                connection.execute(
                    """SELECT r.status AS request_status,r.commit_sha,r.branch,
                              r.created_at AS requested_at,r.updated_at AS request_updated_at,
                              p.status AS permit_status,p.pr_url,
                              p.updated_at AS permit_updated_at
                       FROM publication_requests r
                       LEFT JOIN publication_permits p ON p.request_id=r.request_id
                       WHERE r.opportunity_key=?
                       ORDER BY
                         CASE
                           WHEN p.status='CONSUMED' AND p.pr_url IS NOT NULL THEN 1
                           ELSE 0
                         END DESC,
                         CASE
                           WHEN p.status='CONSUMED' AND p.pr_url IS NOT NULL
                             THEN p.updated_at
                           ELSE r.updated_at
                         END DESC,
                         r.updated_at DESC,r.created_at DESC,r.request_id DESC
                       LIMIT 1""",
                    (row["key"],),
                ).fetchone()
                if row is not None
                else None
            )
            followup_row = (
                connection.execute(
                    """SELECT * FROM pr_followups
                       WHERE opportunity_key=?""",
                    (row["key"],),
                ).fetchone()
                if row is not None
                else None
            )
            context_authority_row = (
                connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                         AND json_extract(payload_json,'$.taskId')=?
                         AND json_extract(payload_json,'$.threadId')=?
                       ORDER BY id DESC LIMIT 1""",
                    (row["key"], row["intent_id"], row["thread_id"]),
                ).fetchone()
                if row is not None
                else None
            )
            context_authority_payload: dict[str, Any] | None = None
            context_authority_observed_time: datetime | None = None
            context_revocation_observed_time: datetime | None = None
            active_context_continuation_ref = ""
            active_context_authority_origin_id = 0
            legacy_unmarked_context_authority = False
            if context_authority_row is not None:
                try:
                    context_authority_payload = json.loads(context_authority_row["payload_json"])
                    context_authority_observed_time = parse_time(
                        str(context_authority_payload.get("authorityObservedAt") or "")
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise LedgerError("task context authority marker is invalid") from exc
                marker_state = {
                    field: context_authority_payload.get(field)
                    for field in (
                        "taskId",
                        "threadId",
                        "contextDigest",
                        "hasContinuation",
                        "continuationDedupeKey",
                        "probeReceiptDigest",
                        "tombstoneReceiptDigest",
                        "implementationClaimed",
                    )
                }
                if (
                    marker_state["taskId"] != row["intent_id"]
                    or marker_state["threadId"] != row["thread_id"]
                    or context_authority_payload.get("authorityStateDigest")
                    != sha256_json(marker_state)
                    or not isinstance(context_authority_payload.get("authorityTransition"), bool)
                ):
                    raise LedgerError("task context authority marker is invalid")
                revocation_observed_at = str(
                    context_authority_payload.get("revocationObservedAt") or ""
                )
                if revocation_observed_at:
                    try:
                        context_revocation_observed_time = parse_time(revocation_observed_at)
                    except (TypeError, ValueError) as exc:
                        raise LedgerError("task context authority marker is invalid") from exc
                    if (
                        not (
                            context_authority_payload.get("revokedContinuationDedupeKey")
                            or context_authority_payload.get("revokedTombstoneReceiptDigest")
                        )
                        or context_authority_observed_time is None
                        or context_revocation_observed_time > context_authority_observed_time
                    ):
                        raise LedgerError("task context authority marker is invalid")
                if marker_state["hasContinuation"] is True:
                    active_context_continuation_ref = str(
                        marker_state["continuationDedupeKey"] or ""
                    )
                    if not re.fullmatch(r"[0-9a-f]{64}", active_context_continuation_ref):
                        raise LedgerError("task context authority marker is invalid")
                    authority_origin_row = connection.execute(
                        """SELECT id FROM events
                           WHERE opportunity_key=?
                             AND event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                             AND json_extract(payload_json,'$.taskId')=?
                             AND json_extract(payload_json,'$.threadId')=?
                             AND json_extract(payload_json,'$.authorityStateDigest')=?
                             AND json_extract(payload_json,'$.authorityTransition')=1
                           ORDER BY id DESC LIMIT 1""",
                        (
                            row["key"],
                            row["intent_id"],
                            row["thread_id"],
                            context_authority_payload["authorityStateDigest"],
                        ),
                    ).fetchone()
                    if authority_origin_row is None:
                        raise LedgerError("task context authority marker is invalid")
                    active_context_authority_origin_id = int(authority_origin_row["id"])
            elif row is not None:
                legacy_context_continuation = connection.execute(
                    """SELECT 1 FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
                         AND json_extract(payload_json,'$.taskId')=?
                         AND json_extract(payload_json,'$.threadId')=?
                       LIMIT 1""",
                    (row["key"], row["intent_id"], row["thread_id"]),
                ).fetchone()
                try:
                    legacy_intent_payload = json.loads(row["payload_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("task context intent payload is invalid") from exc
                legacy_unmarked_context_authority = (
                    legacy_context_continuation is not None
                    or legacy_intent_payload.get("recoveredFromTaskContext") is True
                )
            preparation_row = (
                connection.execute(
                    """WITH latest_preparation AS (
                         SELECT id,opportunity_key,dedupe_key,payload_json
                         FROM events
                         WHERE opportunity_key=?
                           AND event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                           AND json_extract(payload_json,'$.threadId')=?
                         ORDER BY id DESC LIMIT 1
                       )
                       SELECT b.payload_json FROM latest_preparation b
                       WHERE NOT (? > b.id)
                         AND NOT EXISTS (
                           SELECT 1 FROM events x
                           WHERE x.opportunity_key=b.opportunity_key
                             AND (
                               (x.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                                AND x.dedupe_key=b.dedupe_key)
                               OR
                               (x.event_type=
                                  'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                                AND json_extract(
                                  x.payload_json,'$.followupWakeDigest'
                                )=b.dedupe_key
                                AND json_extract(x.payload_json,'$.threadId')=
                                    json_extract(b.payload_json,'$.threadId'))
                               OR
                               (x.event_type=
                                  'TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
                               AND json_extract(
                                  x.payload_json,'$.followupWakeDigest'
                                )=b.dedupe_key
                                AND json_extract(x.payload_json,'$.threadId')=
                                    json_extract(b.payload_json,'$.threadId')
                                AND x.dedupe_key=?)
                               OR
                               (x.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                                AND json_extract(x.payload_json,'$.wakeDigest')=
                                    b.dedupe_key
                                AND json_extract(x.payload_json,'$.threadId')=
                                    json_extract(b.payload_json,'$.threadId'))
                             )
                         )""",
                    (
                        row["key"],
                        row["thread_id"],
                        active_context_authority_origin_id,
                        active_context_continuation_ref,
                    ),
                ).fetchone()
                if row is not None
                else None
            )
            latest_task_result_row = (
                connection.execute(
                    """WITH result_candidates AS (
                         SELECT result2.id,result2.opportunity_key,result2.dedupe_key,
                                result2.created_at,
                                (
                                  SELECT MAX(authority.id) FROM events authority
                                  WHERE authority.opportunity_key=result2.opportunity_key
                                    AND authority.event_type='TASK_RESULT_AUTHORITY_BOUND'
                                    AND json_extract(
                                      authority.payload_json,'$.taskId'
                                    )=?
                                    AND json_extract(
                                      authority.payload_json,'$.threadId'
                                    )=?
                                    AND json_extract(
                                      authority.payload_json,'$.sourceResultEventId'
                                    )=result2.id
                                    AND json_extract(
                                      authority.payload_json,'$.resultDigest'
                                    )=result2.dedupe_key
                                ) AS selection_authority_id
                         FROM events result2
                         WHERE result2.opportunity_key=?
                           AND result2.event_type='TASK_RESULT_INGESTED'
                           AND (
                             (
                               json_extract(result2.payload_json,'$.threadId')=?
                               AND COALESCE(
                                 json_extract(result2.payload_json,'$.taskId'),''
                               ) IN ('',?)
                             )
                             OR (
                               COALESCE(
                                 json_extract(result2.payload_json,'$.threadId'),''
                               )=''
                               AND json_extract(result2.payload_json,'$.taskId')=?
                             )
                             OR EXISTS (
                               SELECT 1 FROM events binding
                               WHERE binding.opportunity_key=result2.opportunity_key
                                 AND binding.event_type=
                                   'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                                 AND json_extract(
                                   binding.payload_json,'$.sourceResultEventId'
                                 )=result2.id
                                 AND json_extract(
                                   binding.payload_json,'$.resultDigest'
                                 )=result2.dedupe_key
                                 AND json_extract(binding.payload_json,'$.taskId')=?
                                 AND json_extract(binding.payload_json,'$.threadId')=?
                             )
                           )
                       ), current_result AS (
                         SELECT *,MAX(id,COALESCE(selection_authority_id,0)) AS selection_id
                         FROM result_candidates
                         ORDER BY selection_id DESC,id DESC LIMIT 1
                       )
                       SELECT result.id AS result_id,
                              result.created_at AS result_created_at,
                              continuation.dedupe_key AS continuation_dedupe_key,
                              continuation.payload_json AS continuation_json,
                              authority.id AS selection_authority_id,
                              authority.payload_json AS selection_authority_json
                       FROM current_result result
                       LEFT JOIN events authority
                         ON authority.id=result.selection_authority_id
                       LEFT JOIN events continuation ON continuation.id=(
                         SELECT MAX(continuation2.id) FROM events continuation2
                         WHERE continuation2.opportunity_key=result.opportunity_key
                           AND continuation2.event_type=
                             'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                           AND json_extract(
                             continuation2.payload_json,'$.threadId'
                           )=?
                           AND json_extract(
                             continuation2.payload_json,'$.resultDigest'
                           )=result.dedupe_key
                           AND json_extract(continuation2.payload_json,'$.taskId')=?
                           AND (
                             authority.id IS NULL
                             OR continuation2.dedupe_key=json_extract(
                               authority.payload_json,'$.continuationDedupeKey'
                             )
                           )
                           AND (
                             json_extract(
                               continuation2.payload_json,'$.sourceResultEventId'
                             )=result.id
                             OR (
                               json_type(
                                 continuation2.payload_json,'$.sourceResultEventId'
                               ) IS NULL
                               AND EXISTS (
                                 SELECT 1 FROM events direct_result
                                 WHERE direct_result.id=result.id
                                   AND json_extract(
                                     direct_result.payload_json,'$.threadId'
                                   )=?
                               )
                             )
                           )
                       )
                         AND json_type(
                           continuation.payload_json,'$.codePathTombstoneReceipt'
                         )='object'
                         AND json_type(
                           continuation.payload_json,'$.prFollowupSnapshot'
                         )='object'
                       LIMIT 1""",
                    (
                        row["intent_id"],
                        row["thread_id"],
                        row["key"],
                        row["thread_id"],
                        row["intent_id"],
                        row["intent_id"],
                        row["intent_id"],
                        row["thread_id"],
                        row["thread_id"],
                        row["intent_id"],
                        row["thread_id"],
                    ),
                ).fetchone()
                if row is not None
                else None
            )
            task_result_continuation_authorized = False
            if latest_task_result_row is not None:
                try:
                    result_observed_time = parse_time(
                        str(latest_task_result_row["result_created_at"] or "")
                    )
                except (TypeError, ValueError) as exc:
                    raise LedgerError("task result authority timestamp is invalid") from exc
                if latest_task_result_row["selection_authority_json"] is not None:
                    if latest_task_result_row["continuation_json"] is None:
                        raise LedgerError("task result authority marker is invalid")
                    try:
                        result_continuation = json.loads(
                            latest_task_result_row["continuation_json"]
                        )
                        result_authority = json.loads(
                            latest_task_result_row["selection_authority_json"]
                        )
                        result_authority_observed_time = parse_time(
                            str(result_authority.get("authorityObservedAt") or "")
                        )
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise LedgerError("task result authority marker is invalid") from exc
                    result_authority_state = {
                        field: result_authority.get(field)
                        for field in (
                            "taskId",
                            "threadId",
                            "sourceResultEventId",
                            "resultDigest",
                            "continuationDedupeKey",
                            "tombstoneReceiptDigest",
                        )
                    }
                    continuation_tombstone = result_continuation.get("codePathTombstoneReceipt")
                    if (
                        not isinstance(continuation_tombstone, dict)
                        or result_authority_state["taskId"] != row["intent_id"]
                        or result_authority_state["threadId"] != row["thread_id"]
                        or result_authority_state["sourceResultEventId"]
                        != latest_task_result_row["result_id"]
                        or result_authority_state["resultDigest"]
                        != result_continuation.get("resultDigest")
                        or result_authority_state["continuationDedupeKey"]
                        != latest_task_result_row["continuation_dedupe_key"]
                        or result_authority_state["tombstoneReceiptDigest"]
                        != sha256_json(continuation_tombstone)
                        or result_authority.get("authorityStateDigest")
                        != sha256_json(result_authority_state)
                        or result_authority_observed_time < result_observed_time
                    ):
                        raise LedgerError("task result authority marker is invalid")
                    task_result_continuation_authorized = True
                if latest_task_result_row is not None and (
                    legacy_unmarked_context_authority
                    or (
                        context_revocation_observed_time is not None
                        and result_observed_time <= context_revocation_observed_time
                    )
                ):
                    latest_task_result_row = None
                    task_result_continuation_authorized = False
            task_result_tombstone_row = (
                latest_task_result_row
                if latest_task_result_row is not None
                and latest_task_result_row["continuation_json"] is not None
                and task_result_continuation_authorized
                else None
            )
            task_context_tombstone_row = (
                connection.execute(
                    """SELECT payload_json AS continuation_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
                         AND dedupe_key=?
                         AND json_extract(payload_json,'$.taskId')=?
                         AND json_extract(payload_json,'$.threadId')=?
                         AND json_extract(payload_json,'$.contextDigest')=?
                         AND json_type(
                           payload_json,'$.codePathTombstoneReceipt'
                         )='object'
                         AND json_type(payload_json,'$.prFollowupSnapshot')='object'
                       LIMIT 1""",
                    (
                        row["key"],
                        active_context_continuation_ref,
                        row["intent_id"],
                        row["thread_id"],
                        (
                            context_authority_payload.get("contextDigest")
                            if context_authority_payload is not None
                            else None
                        ),
                    ),
                ).fetchone()
                if row is not None
                and latest_task_result_row is None
                and active_context_continuation_ref
                else None
            )
            tombstone_continuation_row = task_result_tombstone_row or task_context_tombstone_row
            tombstone_authority_history_present = (
                connection.execute(
                    """SELECT 1 FROM events
                       WHERE opportunity_key=?
                         AND event_type IN (
                           'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND',
                           'TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
                         )
                         AND json_extract(payload_json,'$.taskId')=?
                         AND json_extract(payload_json,'$.threadId')=?
                       LIMIT 1""",
                    (row["key"], row["intent_id"], row["thread_id"]),
                ).fetchone()
                is not None
                if row is not None
                else False
            )
            tombstone_authority_missing_from_current_source = (
                tombstone_authority_history_present
                and (
                    (
                        latest_task_result_row is not None
                        and (
                            latest_task_result_row["continuation_json"] is None
                            or not task_result_continuation_authorized
                        )
                    )
                    or (latest_task_result_row is None and not active_context_continuation_ref)
                )
            )
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        audit_payload = json.loads(audit_row["payload_json"]) if audit_row else {}
        audit_policy = ((audit_payload.get("liveAudit") or {}).get("evidence") or {}).get(
            "policy"
        ) or {}
        submission_policy = payload.get("submissionPolicy")
        if not submission_policy and audit_policy.get("ai_disclosure") is True:
            submission_policy = "ai_disclosure_conflict"
        submission_policy = submission_policy or "normal"
        authorization_active = (
            row["status"] in RECOVERABLE_CONTEXT_INTENT_STATUSES and row["stage"] != "AUDIT_NO_GO"
        )
        raw_probe_level = str(payload.get("probeLevel") or "UNVERIFIED")
        raw_task_stage = str(payload.get("taskStage") or "REPRODUCTION_REQUIRED")
        probe_receipt_digest = str(payload.get("probeReceiptDigest") or "")
        verified_probe_receipt = None
        try:
            from .managed_lifecycle import ManagedLedger

            managed_ledger = ManagedLedger(self.path, ensure_schema=True)
            managed_task = managed_ledger.read_task(str(row["intent_id"] or ""))
            managed_provenance = json.loads((managed_task or {}).get("provenance_json") or "{}")
            managed_receipt = managed_provenance.get("probeReceipt")
            if (
                managed_task
                and managed_task.get("state") in {"IMPLEMENTATION_READY", "PORTFOLIO_READY"}
                and isinstance(managed_receipt, dict)
            ):
                verified_probe_receipt = managed_ledger.implementation_authorization_receipt(
                    task_id=str(row["intent_id"] or ""),
                    thread_id=str(row["thread_id"] or ""),
                    worktree_path=str(row["worktree_path"] or ""),
                    repo=str(managed_receipt.get("repo") or ""),
                    issue_url=str(managed_receipt.get("issueUrl") or ""),
                    receipt_digest=str(managed_receipt.get("receiptDigest") or ""),
                )
                if verified_probe_receipt is not None:
                    raw_task_stage = "IMPLEMENTATION_READY"
                    raw_probe_level = "REPRODUCED_VALIDATED"
                    probe_receipt_digest = str(verified_probe_receipt["receiptDigest"])
                    payload["selectedBaseSha"] = verified_probe_receipt["baseSha"]
                    payload["codePaths"] = verified_probe_receipt["codePaths"]
                    payload["resultDigest"] = verified_probe_receipt["resultDigest"]
                    payload["headSha"] = verified_probe_receipt["headSha"]
                    payload["commitSha"] = verified_probe_receipt["commitSha"]
                    current_published = managed_ledger.current_published_result_for_task(
                        str(row["intent_id"] or "")
                    )
                    if current_published is not None:
                        payload["headSha"] = current_published["headSha"]
                        payload["commitSha"] = current_published["commitSha"]
                        payload["resultDigest"] = current_published["resultDigest"]
        except (OSError, RuntimeError, ValueError, sqlite3.Error, json.JSONDecodeError):
            verified_probe_receipt = None
        if tombstone_authority_missing_from_current_source:
            verified_probe_receipt = None
            raw_task_stage = "REPRODUCTION_REQUIRED"
            raw_probe_level = "UNVERIFIED"
        if (
            verified_probe_receipt is None
            and tombstone_continuation_row is not None
            and preparation_row is None
        ):
            recovered_receipt = payload.get("recoveredReproductionReceipt")
            continuation = json.loads(tombstone_continuation_row["continuation_json"])
            tombstone_receipt = continuation.get("codePathTombstoneReceipt")
            followup_snapshot = continuation.get("prFollowupSnapshot")
            followup_wake_digest = str(continuation.get("followupWakeDigest") or "")
            continuation_result_digest = str(continuation.get("resultDigest") or "")
            continuation_head_sha = str(continuation.get("continuationHeadSha") or "")
            context_continuation = continuation.get("contextDigest") is not None
            recovered_paths = [
                str(path) for path in (payload.get("codePaths") or []) if str(path).strip()
            ]
            if (
                isinstance(recovered_receipt, dict)
                and isinstance(tombstone_receipt, dict)
                and isinstance(followup_snapshot, dict)
                and continuation.get("taskId") == row["intent_id"]
                and continuation.get("threadId") == row["thread_id"]
                and re.fullmatch(r"[0-9a-f]{64}", continuation_result_digest)
                and re.fullmatch(r"[0-9a-f]{40}", continuation_head_sha)
                and (
                    not context_continuation
                    or (
                        context_authority_payload is not None
                        and context_authority_payload.get("hasContinuation") is True
                        and active_context_continuation_ref == sha256_json(continuation)
                        and context_authority_payload.get("tombstoneReceiptDigest")
                        == sha256_json(tombstone_receipt)
                        and continuation.get("headSha") == continuation_head_sha
                        and continuation.get("commitSha") == continuation_head_sha
                        and tombstone_receipt.get("preparedHeadSha") == continuation_head_sha
                    )
                )
                and recovered_receipt.get("receiptDigest")
                == tombstone_receipt.get("sourceReceiptDigest")
                and verify_probe_receipt(
                    recovered_receipt,
                    repo=str(row["key"]).split("#", 1)[0],
                    base_sha=str(payload.get("selectedBaseSha") or ""),
                    code_paths=recovered_paths,
                    required_level=REPRODUCED_VALIDATED,
                    issue_url=str(row["issue_url"]),
                    task_id=str(row["intent_id"] or ""),
                    thread_id=(
                        str(row["thread_id"] or "")
                        if recovered_receipt.get("threadFingerprint")
                        else None
                    ),
                    head_sha=str(recovered_receipt.get("headSha") or ""),
                    commit_sha=str(recovered_receipt.get("commitSha") or ""),
                    result_digest=str(recovered_receipt.get("resultDigest") or ""),
                    enforce_freshness=False,
                )
                and verify_code_path_tombstone_receipt(
                    tombstone_receipt,
                    source_receipt_digest=str(recovered_receipt.get("receiptDigest") or ""),
                    base_sha=str(recovered_receipt.get("baseSha") or ""),
                    key=str(row["key"]),
                    issue_url=str(row["issue_url"]),
                    intent_id=str(row["intent_id"] or ""),
                    thread_id=str(row["thread_id"] or ""),
                    worktree_path_fingerprint=sha256_text(
                        str(Path(str(row["worktree_path"] or "")).resolve())
                    ),
                    pr_url=str(followup_snapshot.get("prUrl") or ""),
                    wake_digest=followup_wake_digest,
                    action_digest=str(followup_snapshot.get("actionDigest") or ""),
                    task_action_digest=str(followup_snapshot.get("taskActionDigest") or ""),
                    checked_at=str(followup_snapshot.get("checkedAt") or ""),
                    prepared_head_sha=str(followup_snapshot.get("preparedHeadSha") or ""),
                    code_paths=recovered_paths,
                )
            ):
                verified_probe_receipt = recovered_receipt
                raw_task_stage = "IMPLEMENTATION_READY"
                raw_probe_level = "REPRODUCED_VALIDATED"
                probe_receipt_digest = str(recovered_receipt.get("receiptDigest") or "")
                payload["selectedBaseSha"] = recovered_receipt.get("baseSha")
                payload["codePaths"] = list(recovered_receipt.get("codePaths") or [])
                payload["resultDigest"] = continuation_result_digest
                payload["headSha"] = continuation_head_sha
                payload["commitSha"] = continuation_head_sha
        verified_tombstone_continuation = (
            tombstone_continuation_row is None or preparation_row is not None
        )
        if (
            tombstone_continuation_row is not None
            and preparation_row is None
            and verified_probe_receipt is not None
        ):
            try:
                continuation = json.loads(tombstone_continuation_row["continuation_json"])
            except (TypeError, json.JSONDecodeError):
                continuation = {}
            tombstone_receipt = continuation.get("codePathTombstoneReceipt")
            followup_snapshot = continuation.get("prFollowupSnapshot")
            followup_wake_digest = str(continuation.get("followupWakeDigest") or "")
            continuation_result_digest = str(continuation.get("resultDigest") or "")
            continuation_head_sha = str(continuation.get("continuationHeadSha") or "")
            context_continuation = continuation.get("contextDigest") is not None
            verified_paths = [
                str(path)
                for path in (verified_probe_receipt.get("codePaths") or [])
                if str(path).strip()
            ]
            verified_tombstone_continuation = bool(
                isinstance(tombstone_receipt, dict)
                and isinstance(followup_snapshot, dict)
                and continuation.get("taskId") == row["intent_id"]
                and continuation.get("threadId") == row["thread_id"]
                and continuation_result_digest
                and re.fullmatch(r"[0-9a-f]{40}", continuation_head_sha)
                and (
                    not context_continuation
                    or (
                        context_authority_payload is not None
                        and context_authority_payload.get("hasContinuation") is True
                        and active_context_continuation_ref == sha256_json(continuation)
                        and context_authority_payload.get("tombstoneReceiptDigest")
                        == sha256_json(tombstone_receipt)
                        and re.fullmatch(r"[0-9a-f]{64}", continuation_result_digest)
                        and continuation.get("headSha") == continuation_head_sha
                        and continuation.get("commitSha") == continuation_head_sha
                        and tombstone_receipt.get("preparedHeadSha") == continuation_head_sha
                    )
                )
                and verified_probe_receipt.get("receiptDigest")
                == tombstone_receipt.get("sourceReceiptDigest")
                and followup_snapshot.get("wakeDigest") == followup_wake_digest
                and tombstone_receipt.get("wakeDigest") == followup_wake_digest
                and followup_snapshot.get("preparedHeadSha")
                == tombstone_receipt.get("preparedHeadSha")
                and verify_code_path_tombstone_receipt(
                    tombstone_receipt,
                    source_receipt_digest=str(verified_probe_receipt.get("receiptDigest") or ""),
                    base_sha=str(verified_probe_receipt.get("baseSha") or ""),
                    key=str(row["key"]),
                    issue_url=str(row["issue_url"]),
                    intent_id=str(row["intent_id"] or ""),
                    thread_id=str(row["thread_id"] or ""),
                    worktree_path_fingerprint=sha256_text(
                        str(Path(str(row["worktree_path"] or "")).resolve())
                    ),
                    pr_url=str(followup_snapshot.get("prUrl") or ""),
                    wake_digest=followup_wake_digest,
                    action_digest=str(followup_snapshot.get("actionDigest") or ""),
                    task_action_digest=str(followup_snapshot.get("taskActionDigest") or ""),
                    checked_at=str(followup_snapshot.get("checkedAt") or ""),
                    prepared_head_sha=str(followup_snapshot.get("preparedHeadSha") or ""),
                    code_paths=verified_paths,
                )
            )
        audited_code_paths = None
        if verified_probe_receipt is None:
            selected_base = str(
                payload.get("selectedBaseSha")
                or (payload.get("preTaskEvidence") or {}).get("baseSha")
                or ""
            )
            # Contexts restored from old publication/follow-up records may not
            # have a selected repository base at all.  They cannot carry a
            # base-bound path receipt, so keep their legacy read-only path plan.
            if selected_base:
                audited_code_paths = self.audited_probe_code_paths(
                    intent_id=str(row["intent_id"] or ""),
                    issue_url=str(row["issue_url"]),
                    thread_id=str(row["thread_id"] or ""),
                    worktree_path=str(row["worktree_path"] or ""),
                    expected_base_sha=selected_base,
                    require_receipt_digest_match=False,
                )
        implementation_authorized = (
            authorization_active
            and verified_probe_receipt is not None
            and verified_tombstone_continuation
        )
        task_stage = raw_task_stage if implementation_authorized else "REPRODUCTION_REQUIRED"
        allowed_actions = (
            ["read_issue", "read_repo", "run_reproduction_probe", "write_structured_result"]
            if not implementation_authorized
            else ["read_issue", "read_repo", "edit_files", "run_tests", "write_structured_result"]
        )
        publication_receipt = None
        if publication_row is not None:
            pr_url = publication_row["pr_url"]
            if pr_url:
                receipt_status = row["stage"] if row["stage"] in {"MERGED", "CLOSED"} else "PR_OPEN"
            else:
                receipt_status = (
                    publication_row["permit_status"] or publication_row["request_status"]
                )
            publication_receipt = {
                "status": receipt_status,
                "prUrl": pr_url,
                "commitSha": publication_row["commit_sha"],
                "branch": publication_row["branch"],
                "requestedAt": publication_row["requested_at"],
                "updatedAt": publication_row["permit_updated_at"]
                or publication_row["request_updated_at"],
            }
        pr_followup = None
        code_path_tombstone_receipt = None
        code_path_tombstone_continuation_head = None
        if (
            preparation_row is not None
            or tombstone_continuation_row is not None
            or (followup_row is not None and bool(followup_row["followup_required"]))
        ):
            result_contract = {
                "schemaVersion": "pr-followup-result-contract-v3",
                "requiredWakeDigestField": "followupDigest",
                "allowedStages": ["FIX_READY", "PR_OPEN"],
                "noLocalActionStage": "PR_OPEN",
                "noLocalActionRequiredFields": [
                    "headSha",
                    "commitSha",
                    "prUrl",
                    "evidence.headSha",
                ],
                "noLocalActionHeadBindingField": "prFollowup.preparedHeadSha",
                "noLocalActionPrBindingField": "publicationReceipt.prUrl",
                "mergeConflictHandoffMode": "controller_merge_required",
                "conflictScopeInsufficientReason": "CONFLICT_SCOPE_INSUFFICIENT",
                "requiredResolutionFilesField": "evidence.requiredResolutionFiles",
                "authorizedResolutionFilesField": ("prFollowup.evidence.authorizedResolutionFiles"),
            }
        if followup_row is not None and bool(followup_row["followup_required"]):
            pr_followup = {
                "prUrl": followup_row["pr_url"],
                "headSha": followup_row["head_sha"],
                "actionDigest": followup_row["action_digest"],
                "taskActionDigest": followup_row["task_action_digest"],
                "wakeDigest": followup_row["wake_digest"],
                "actions": json.loads(followup_row["actions_json"]),
                "evidence": json.loads(followup_row["evidence_json"]),
                "checkedAt": followup_row["checked_at"],
                "resultContract": result_contract,
            }
        if preparation_row is not None:
            preparation = json.loads(preparation_row["payload_json"])
            snapshot = preparation.get("snapshot")
            if not isinstance(snapshot, dict):
                raise LedgerError("PR follow-up preparation snapshot is invalid")
            pr_followup = dict(snapshot) | {"resultContract": result_contract}
        elif (
            tombstone_continuation_row is not None
            and implementation_authorized
            and verified_tombstone_continuation
        ):
            continuation = json.loads(tombstone_continuation_row["continuation_json"])
            snapshot = continuation.get("prFollowupSnapshot")
            receipt = continuation.get("codePathTombstoneReceipt")
            continuation_head = str(continuation.get("continuationHeadSha") or "")
            continuation_result_digest = str(continuation.get("resultDigest") or "")
            wake_digest = str(continuation.get("followupWakeDigest") or "")
            receipt_prepared_head = (
                str(receipt.get("preparedHeadSha") or "") if isinstance(receipt, dict) else ""
            )
            if (
                not isinstance(snapshot, dict)
                or not isinstance(receipt, dict)
                or not re.fullmatch(r"[0-9a-f]{64}", wake_digest)
                or snapshot.get("wakeDigest") != wake_digest
                or receipt.get("wakeDigest") != wake_digest
                or snapshot.get("prUrl") != receipt.get("prUrl")
                or snapshot.get("actionDigest") != receipt.get("actionDigest")
                or snapshot.get("taskActionDigest") != receipt.get("taskActionDigest")
                or snapshot.get("checkedAt") != receipt.get("checkedAt")
                or snapshot.get("preparedHeadSha") != receipt_prepared_head
                or not re.fullmatch(r"[0-9a-f]{40}", receipt_prepared_head)
                or not re.fullmatch(r"[0-9a-f]{40}", continuation_head)
                or not continuation_result_digest
            ):
                raise LedgerError("task result tombstone continuation is invalid")
            pr_followup = dict(snapshot) | {
                "preparedHeadSha": receipt_prepared_head,
                "resultContract": result_contract,
            }
            code_path_tombstone_receipt = receipt
            code_path_tombstone_continuation_head = continuation_head
            payload["resultDigest"] = continuation_result_digest
            payload["headSha"] = continuation_head
            payload["commitSha"] = continuation_head
        if isinstance(pr_followup, dict):
            followup_evidence = pr_followup.get("evidence")
            scope_receipt = (
                followup_evidence.get("mergeResolutionScopeReceipt")
                if isinstance(followup_evidence, dict)
                else None
            )
            authorized_resolution_files = (
                followup_evidence.get("authorizedResolutionFiles")
                if isinstance(followup_evidence, dict)
                else None
            )
            if scope_receipt is not None or authorized_resolution_files is not None:
                scope_prepared_head = (
                    str(scope_receipt.get("preparedHeadSha") or "")
                    if isinstance(scope_receipt, dict)
                    else ""
                )
                if (
                    not isinstance(followup_evidence, dict)
                    or not isinstance(scope_receipt, dict)
                    or not isinstance(authorized_resolution_files, list)
                    or not isinstance(followup_evidence.get("mergeConflictFiles"), list)
                    or scope_prepared_head != str(pr_followup.get("headSha") or "")
                    or not verify_merge_resolution_scope_receipt(
                        scope_receipt,
                        key=str(row["key"]),
                        issue_url=str(row["issue_url"]),
                        intent_id=str(row["intent_id"]),
                        thread_id=str(row["thread_id"]),
                        worktree_path_fingerprint=sha256_text(
                            str(Path(str(row["worktree_path"])).resolve())
                        ),
                        pr_url=str(pr_followup.get("prUrl") or ""),
                        current_wake_digest=str(pr_followup.get("wakeDigest") or ""),
                        head_sha=str(pr_followup.get("headSha") or ""),
                        prepared_head_sha=scope_prepared_head,
                        base_sha=str(followup_evidence.get("baseSha") or ""),
                        merge_conflict_files=followup_evidence.get("mergeConflictFiles"),
                        authorized_resolution_files=authorized_resolution_files,
                    )
                ):
                    raise LedgerError("PR follow-up resolution scope receipt is invalid")
        result = {
            "key": row["key"],
            "stage": row["stage"],
            "issueUrl": row["issue_url"],
            "track": payload.get("track") or "agent_ai_infra",
            "category": payload.get("category"),
            "algorithmEvidence": payload.get("algorithmEvidence"),
            "intentId": row["intent_id"],
            "threadId": row["thread_id"],
            "titleTime": row["title_time"],
            "worktreePath": row["worktree_path"],
            "intentStatus": row["status"],
            "probeRequired": payload.get("probeRequired") is True or not payload.get("probeLevel"),
            "probeLevel": raw_probe_level,
            "probeReceiptDigest": probe_receipt_digest or None,
            "reproductionReceipt": (verified_probe_receipt if implementation_authorized else None),
            "probeProfileId": payload.get("probeProfileId"),
            "defaultBranch": payload.get("defaultBranch"),
            "selectedBaseSha": payload.get("selectedBaseSha")
            or (payload.get("preTaskEvidence") or {}).get("baseSha"),
            "codePaths": list(verified_probe_receipt["codePaths"])
            if implementation_authorized
            else audited_code_paths
            or payload.get("codePaths")
            or (payload.get("preTaskEvidence") or {}).get("codePathsPlan"),
            "resultDigest": payload.get("resultDigest"),
            "headSha": payload.get("headSha"),
            "commitSha": payload.get("commitSha"),
            "preTaskEvidence": payload.get("preTaskEvidence"),
            "taskStage": task_stage,
            "allowedActions": allowed_actions,
            "autoSubmitAuthorized": (
                authorization_active and payload.get("autoSubmitAuthorized") is True
            ),
            "publicationMode": payload.get("publicationMode"),
            "submissionPolicy": submission_policy,
            "publicSubmissionAllowed": (
                authorization_active and payload.get("publicSubmissionAllowed") is True
            ),
            "authorizationSource": (
                payload.get("authorizationSource")
                if authorization_active
                else "revoked_terminal_no_go"
            ),
            "liveAudit": audit_payload.get("liveAudit"),
            "targetBase": audit_payload.get("targetBase"),
            "liveAuditRecordedAt": audit_row["created_at"] if audit_row else None,
            "publicationReceipt": publication_receipt,
            "prFollowup": pr_followup,
        }
        if code_path_tombstone_receipt is not None and implementation_authorized:
            result["codePathTombstoneReceipt"] = code_path_tombstone_receipt
            result["codePathTombstoneContinuationHeadSha"] = code_path_tombstone_continuation_head
        return result

    def audited_probe_code_paths(
        self,
        *,
        intent_id: str,
        issue_url: str,
        thread_id: str,
        worktree_path: str,
        expected_base_sha: str,
        require_receipt_digest_match: bool = True,
    ) -> list[str] | None:
        """Read the live-audit path receipt from the controller-owned ledger."""

        with self.connect() as connection:
            row = connection.execute(
                """SELECT o.key,o.issue_url,i.thread_id,i.worktree_path,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.intent_id=? AND o.issue_url=? AND i.thread_id=?""",
                (intent_id, issue_url, thread_id),
            ).fetchone()
            all_audit_rows = (
                connection.execute(
                    """SELECT payload_json,created_at,dedupe_key,id FROM events
                       WHERE opportunity_key=?
                         AND event_type IN ('AUDIT_PASS','AUDIT_SNAPSHOT')
                       ORDER BY id DESC""",
                    (row["key"],),
                ).fetchall()
                if row is not None
                else []
            )
            bound_audit_rows = (
                _intent_bound_audit_rows(connection, row["key"], intent_id)
                if row is not None
                else []
            )
        if row is None:
            raise LedgerError("task audit identity is not registered")
        registered_worktree = str(row["worktree_path"] or "")
        if (
            not registered_worktree
            or Path(registered_worktree).resolve() != Path(worktree_path).resolve()
        ):
            raise LedgerError("task audit worktree does not match the result context")
        payload = json.loads(row["payload_json"])
        pre_task = payload.get("preTaskEvidence")
        pre_task = pre_task if isinstance(pre_task, dict) else {}
        selected_base = str(payload.get("selectedBaseSha") or pre_task.get("baseSha") or "")
        if not expected_base_sha or selected_base != expected_base_sha:
            raise LedgerError("task audit selected base does not match the result context")
        expected_receipt_digest = str(payload.get("probeReceiptDigest") or "")
        candidates = all_audit_rows if expected_receipt_digest else bound_audit_rows
        for audit_row in candidates:
            audit_payload = json.loads(audit_row["payload_json"])
            live_audit = audit_payload.get("liveAudit")
            evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else None
            if not isinstance(evidence, dict):
                continue
            camel_present = "repoProbeReceipt" in evidence
            snake_present = "repo_probe_receipt" in evidence
            if not camel_present and not snake_present:
                continue
            camel_receipt = evidence.get("repoProbeReceipt")
            snake_receipt = evidence.get("repo_probe_receipt")
            receipt = camel_receipt if camel_present else snake_receipt
            receipt_digest = (
                str(receipt.get("receiptDigest") or "") if isinstance(receipt, dict) else ""
            )
            if expected_receipt_digest and receipt_digest != expected_receipt_digest:
                continue
            return _audited_probe_code_paths(payload, audit_payload, issue_url)
        if expected_receipt_digest:
            if require_receipt_digest_match:
                raise LedgerError("task audit repository probe receipt digest is unavailable")
            return None
        for audit_row in all_audit_rows:
            audit_payload = json.loads(audit_row["payload_json"])
            live_audit = audit_payload.get("liveAudit")
            evidence = live_audit.get("evidence") if isinstance(live_audit, dict) else None
            if isinstance(evidence, dict) and (
                "repoProbeReceipt" in evidence or "repo_probe_receipt" in evidence
            ):
                raise LedgerError("repository probe receipt is not bound to the task intent")
        return None

    def task_context_candidates(self) -> list[dict[str, Any]]:
        """Return live, thread-bound tasks whose controller context should stay current."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path,i.status,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND i.status IN ('DISPATCHED','COMPLETED')
                     AND o.stage<>'AUDIT_NO_GO'
                   ORDER BY i.updated_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "stage": row["stage"],
                "issueUrl": row["issue_url"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "intentStatus": row["status"],
                "intent": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def record_implementation_context_repair(
        self,
        *,
        key: str,
        task_id: str,
        thread_id: str,
        worktree_path: str,
        result_digest: str,
        context_digest: str,
    ) -> bool:
        """Append one rearm marker after a denied implementation context is repaired."""

        repair_digest = sha256_text(
            f"{task_id}|{thread_id}|{Path(worktree_path).resolve()}|"
            f"{result_digest}|{context_digest}"
        )
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            binding = connection.execute(
                """SELECT i.worktree_path,t.worktree_path AS managed_worktree_path FROM intents i
                   JOIN managed_tasks t ON t.task_id=i.intent_id
                   WHERE i.intent_id=? AND i.opportunity_key=? AND i.thread_id=?
                     AND i.status='DISPATCHED' AND t.state='IMPLEMENTATION_READY'
                     AND t.thread_id=i.thread_id
                     AND json_extract(t.provenance_json,'$.probeReceipt.resultDigest')=?
                     AND json_extract(t.provenance_json,'$.probeReceipt.receiptDigest')=
                         json_extract(t.provenance_json,'$.probeReceiptDigest')""",
                (task_id, key, thread_id, result_digest),
            ).fetchone()
            reproduction = connection.execute(
                """SELECT 1 FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.stage')='IMPLEMENTATION_READY'""",
                (key, result_digest),
            ).fetchone()
            sent = connection.execute(
                """SELECT id FROM events
                   WHERE opportunity_key=? AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     AND (dedupe_key=? OR json_extract(payload_json,'$.resultDigest')=?)
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, result_digest, result_digest, thread_id),
            ).fetchone()
            if (
                binding is None
                or not binding["worktree_path"]
                or not binding["managed_worktree_path"]
                or Path(str(binding["worktree_path"])).resolve() != Path(worktree_path).resolve()
                or Path(str(binding["managed_worktree_path"])).resolve()
                != Path(worktree_path).resolve()
                or reproduction is None
                or sent is None
            ):
                return False
            if connection.execute(
                """SELECT 1 FROM events
                   WHERE opportunity_key=? AND event_type='IMPLEMENTATION_CONTEXT_REPAIRED'
                     AND dedupe_key=?""",
                (key, repair_digest),
            ).fetchone():
                return False
            self._event(
                connection,
                key,
                "IMPLEMENTATION_CONTEXT_REPAIRED",
                repair_digest,
                {
                    "taskId": task_id,
                    "threadId": thread_id,
                    "worktreePath": str(Path(worktree_path).resolve()),
                    "resultDigest": result_digest,
                    "contextDigest": context_digest,
                    "priorSentEventId": int(sent["id"]),
                },
                now,
            )
        return True

    def implementation_followup_candidates(self) -> list[dict[str, Any]]:
        """Return reproduced tasks that still need their implementation turn."""

        candidates: list[dict[str, Any]] = []
        with self.connect() as connection:
            for task in self.task_context_candidates():
                intent = task.get("intent") or {}
                if (
                    task.get("intentStatus") != "DISPATCHED"
                    or intent.get("taskStage") != "IMPLEMENTATION_READY"
                    or intent.get("probeLevel") != "REPRODUCED_VALIDATED"
                    or not intent.get("probeReceiptDigest")
                ):
                    continue
                reproduction = connection.execute(
                    """SELECT dedupe_key,payload_json,created_at FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_RESULT_INGESTED'
                         AND json_extract(payload_json,'$.stage')='IMPLEMENTATION_READY'
                       ORDER BY id DESC LIMIT 1""",
                    (task["key"],),
                ).fetchone()
                if reproduction is None:
                    continue
                result_digest = str(reproduction["dedupe_key"] or "")
                if not result_digest:
                    continue
                sent = connection.execute(
                    """SELECT id FROM events
                       WHERE opportunity_key=?
                         AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND (dedupe_key=? OR json_extract(payload_json,'$.resultDigest')=?)
                       ORDER BY id DESC LIMIT 1""",
                    (task["key"], result_digest, result_digest),
                ).fetchone()
                reserved = connection.execute(
                    """SELECT id FROM events
                       WHERE opportunity_key=?
                         AND event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                         AND (dedupe_key=? OR json_extract(payload_json,'$.resultDigest')=?)
                       ORDER BY id DESC LIMIT 1""",
                    (task["key"], result_digest, result_digest),
                ).fetchone()
                repair = connection.execute(
                    """SELECT id,dedupe_key FROM events
                       WHERE opportunity_key=?
                         AND event_type='IMPLEMENTATION_CONTEXT_REPAIRED'
                         AND json_extract(payload_json,'$.resultDigest')=?
                         AND json_extract(payload_json,'$.threadId')=?
                       ORDER BY id DESC LIMIT 1""",
                    (task["key"], result_digest, task["threadId"]),
                ).fetchone()
                repair_rearms = (
                    repair is not None
                    and sent is not None
                    and int(repair["id"]) > int(sent["id"])
                    and (reserved is None or int(reserved["id"]) < int(repair["id"]))
                )
                if (sent is None and reserved is None) or repair_rearms:
                    candidates.append(
                        task
                        | {
                            "resultDigest": result_digest,
                            "reproducedAt": reproduction["created_at"],
                            "implementationFollowupAttemptDigest": (
                                str(repair["dedupe_key"])
                                if repair_rearms and repair is not None
                                else result_digest
                            ),
                        }
                    )
        return candidates

    def reserve_implementation_followup(
        self, *, thread_id: str, result_digest: str
    ) -> dict[str, Any]:
        candidate = next(
            (
                item
                for item in self.implementation_followup_candidates()
                if item.get("threadId") == thread_id and item.get("resultDigest") == result_digest
            ),
            None,
        )
        if candidate is None:
            raise LedgerError("implementation follow-up authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        payload = {
            "threadId": thread_id,
            "resultDigest": result_digest,
            "issueUrl": candidate["issueUrl"],
            "worktreePath": candidate["worktreePath"],
            "attemptDigest": candidate["implementationFollowupAttemptDigest"],
        }
        with self.transaction() as connection:
            require_quarantine_clear(
                connection,
                opportunity_key=str(candidate["key"]),
                operation="implementation follow-up reservation",
            )
            self._event(
                connection,
                str(candidate["key"]),
                "IMPLEMENTATION_FOLLOWUP_RESERVED",
                str(candidate["implementationFollowupAttemptDigest"]),
                payload,
                now,
            )
        return candidate | payload | {"reservedAt": now}

    def unresolved_implementation_followups(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT r.opportunity_key,r.dedupe_key,r.payload_json,r.created_at,
                          o.issue_url,i.intent_id,i.thread_id,i.worktree_path
                   FROM events r
                   JOIN opportunities o ON o.key=r.opportunity_key
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                   WHERE r.event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                     AND i.status='DISPATCHED'
                     AND i.thread_id=json_extract(r.payload_json,'$.threadId')
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                     )
                   ORDER BY r.id"""
            ).fetchall()
        return [
            {
                "key": row["opportunity_key"],
                "issueUrl": row["issue_url"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "resultDigest": str(
                    json.loads(row["payload_json"]).get("resultDigest") or row["dedupe_key"]
                ),
                "implementationFollowupAttemptDigest": row["dedupe_key"],
                "reservedAt": row["created_at"],
                "reservation": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def commit_implementation_followup(self, *, thread_id: str, result_digest: str) -> None:
        candidate = next(
            (
                item
                for item in self.unresolved_implementation_followups()
                if item.get("threadId") == thread_id and item.get("resultDigest") == result_digest
            ),
            None,
        )
        if candidate is None:
            raise LedgerError("implementation follow-up reservation is unavailable")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            self._event(
                connection,
                str(candidate["key"]),
                "IMPLEMENTATION_FOLLOWUP_SENT",
                str(candidate["implementationFollowupAttemptDigest"]),
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "attemptDigest": candidate["implementationFollowupAttemptDigest"],
                },
                now,
            )

    def record_audit_snapshot(
        self,
        key: str,
        *,
        evidence: dict[str, Any],
        dedupe_key: str,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            if (
                connection.execute("SELECT 1 FROM opportunities WHERE key=?", (key,)).fetchone()
                is None
            ):
                raise LedgerError("opportunity not found")
            self._event(
                connection,
                key,
                "AUDIT_SNAPSHOT",
                dedupe_key,
                evidence,
                now,
            )

    def dispatch_notification_candidates(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.repo,o.issue_number,o.issue_url,o.title,
                          i.intent_id,i.thread_id,i.title_time,d.created_at AS dispatched_at,
                          json_extract(i.payload_json,'$.maturity') AS maturity,
                          json_extract(i.payload_json,'$.notify') AS notify
                   FROM events d
                   JOIN intents i
                     ON i.intent_id=json_extract(d.payload_json,'$.intentId')
                    AND i.opportunity_key=d.opportunity_key
                    AND i.thread_id=json_extract(d.payload_json,'$.threadId')
                    AND i.thread_id=d.dedupe_key
                   JOIN opportunities o ON o.key=d.opportunity_key
                   WHERE d.event_type='DISPATCHED' AND i.thread_id IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=o.key
                         AND e.event_type IN (
                           'DISPATCH_NOTIFICATION_SENT',
                           'DISPATCH_NOTIFICATION_SUPPRESSED'
                         )
                         AND e.dedupe_key=d.dedupe_key
                     )
                   ORDER BY d.created_at,d.id"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "repo": row["repo"],
                "issueNumber": row["issue_number"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "titleTime": row["title_time"],
                "dispatchedAt": row["dispatched_at"],
                "maturity": row["maturity"] or "mature",
                "notify": row["notify"] != 0,
            }
            for row in rows
        ]

    def commit_dispatch_notification(
        self,
        *,
        intent_id: str,
        thread_id: str,
        idempotency_key: str,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT d.opportunity_key FROM events d
                   JOIN intents i
                     ON i.intent_id=json_extract(d.payload_json,'$.intentId')
                    AND i.opportunity_key=d.opportunity_key
                    AND i.thread_id=json_extract(d.payload_json,'$.threadId')
                    AND i.thread_id=d.dedupe_key
                   WHERE d.event_type='DISPATCHED'
                     AND i.intent_id=? AND i.thread_id=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events suppressed
                       WHERE suppressed.opportunity_key=d.opportunity_key
                         AND suppressed.event_type='DISPATCH_NOTIFICATION_SUPPRESSED'
                         AND suppressed.dedupe_key=d.dedupe_key
                     )""",
                (intent_id, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("dispatch notification task not found")
            self._event(
                connection,
                row["opportunity_key"],
                "DISPATCH_NOTIFICATION_SENT",
                thread_id,
                {"threadId": thread_id, "idempotencyKey": idempotency_key},
                now,
            )

    def suppress_dispatch_notifications_before(
        self,
        *,
        cutoff: str,
        reason: str,
    ) -> list[dict[str, str]]:
        """Audit, without sending, old dispatch notices missed by prior releases."""

        cutoff = iso_z(parse_time(cutoff))
        now = iso_z(datetime.now(UTC))
        suppressed: list[dict[str, str]] = []
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT d.opportunity_key,i.intent_id,i.thread_id,d.created_at
                   FROM events d
                   JOIN intents i
                     ON i.intent_id=json_extract(d.payload_json,'$.intentId')
                    AND i.opportunity_key=d.opportunity_key
                    AND i.thread_id=json_extract(d.payload_json,'$.threadId')
                    AND i.thread_id=d.dedupe_key
                   WHERE d.event_type='DISPATCHED' AND d.created_at<=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=d.opportunity_key
                         AND e.event_type IN (
                           'DISPATCH_NOTIFICATION_SENT',
                           'DISPATCH_NOTIFICATION_SUPPRESSED'
                         )
                         AND e.dedupe_key=d.dedupe_key
                     )
                   ORDER BY d.created_at,d.id""",
                (cutoff,),
            ).fetchall()
            for row in rows:
                self._event(
                    connection,
                    row["opportunity_key"],
                    "DISPATCH_NOTIFICATION_SUPPRESSED",
                    row["thread_id"],
                    {
                        "intentId": row["intent_id"],
                        "threadId": row["thread_id"],
                        "dispatchedAt": row["created_at"],
                        "cutoff": cutoff,
                        "reason": reason,
                    },
                    now,
                )
                suppressed.append(
                    {
                        "key": row["opportunity_key"],
                        "intentId": row["intent_id"],
                        "threadId": row["thread_id"],
                    }
                )
        return suppressed

    def reset_dispatch_for_retry(self, *, thread_id: str, reason: str) -> dict[str, Any]:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT i.intent_id,i.opportunity_key,i.status,i.expires_at,
                          o.stage,o.issue_url,o.title,i.payload_json
                   FROM intents i JOIN opportunities o ON o.key=i.opportunity_key
                   WHERE i.thread_id=?""",
                (thread_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("dispatch retry task not found")
            if row["status"] != "DISPATCHED" or row["stage"] != "DISPATCHED":
                raise LedgerError("only an unresolved dispatched task can be retried")
            if parse_time(row["expires_at"]) <= now_dt:
                raise LedgerError("dispatch intent expired before retry")
            if connection.execute(
                """SELECT 1 FROM publication_requests
                   WHERE opportunity_key=? LIMIT 1""",
                (row["opportunity_key"],),
            ).fetchone():
                raise LedgerError("task with a publication request cannot be retried")
            connection.execute(
                """UPDATE intents SET status='PENDING',lease_owner=NULL,lease_until=NULL,
                          thread_id=NULL,project_id=NULL,worktree_path=NULL,title_time=NULL,
                          title_synced_state=NULL,creation_token=NULL,client_thread_id=NULL,
                          creation_started_at=NULL,updated_at=?
                   WHERE intent_id=?""",
                (now, row["intent_id"]),
            )
            connection.execute(
                """UPDATE opportunities SET stage='QUALIFIED',terminal_reason=NULL,
                          updated_at=? WHERE key=?""",
                (now, row["opportunity_key"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "DISPATCH_RETRY",
                thread_id,
                {"threadId": thread_id, "reason": reason},
                now,
            )
        return {
            "intentId": row["intent_id"],
            "key": row["opportunity_key"],
            "issueUrl": row["issue_url"],
            "title": row["title"],
            "intent": json.loads(row["payload_json"]),
        }

    @staticmethod
    def _task_result_candidates_from_rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [
            {
                "key": row["key"],
                "stage": row["stage"],
                "issueUrl": row["issue_url"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "intentStatus": row["status"],
                "intent": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def task_result_candidates(self) -> list[dict[str, Any]]:
        """Return the broad historical audit set of thread-bound task results."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path,i.status,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines q
                       WHERE q.opportunity_key=o.key AND q.status='ACTIVE'
                     )
                     AND (
                       i.status='DISPATCHED'
                       OR (
                         i.status='REJECTED'
                         AND o.stage='AUDIT_NO_GO'
                         AND o.terminal_reason='AUTOMATION_REPRODUCTION_RECEIPT_REQUIRED'
                       )
                       OR o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                       OR (
                         o.stage IN ('VALIDATION_PENDING','FIX_READY')
                         AND NOT EXISTS (
                           SELECT 1 FROM publication_requests p
                           WHERE p.opportunity_key=o.key
                             AND p.status IN ('PENDING','GRANTED')
                         )
                       )
                     )
                   ORDER BY i.updated_at"""
            ).fetchall()
        return self._task_result_candidates_from_rows(rows)

    def local_receipt_candidates(self) -> list[dict[str, Any]]:
        """Return only tasks that the fast local receipt worker should inspect."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path,i.status,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines q
                       WHERE q.opportunity_key=o.key AND q.status='ACTIVE'
                     )
                     AND (
                       i.status='DISPATCHED'
                       OR (
                         i.status='REJECTED'
                         AND o.stage='AUDIT_NO_GO'
                         AND o.terminal_reason='AUTOMATION_REPRODUCTION_RECEIPT_REQUIRED'
                       )
                       OR (
                         o.stage IN ('VALIDATION_PENDING','FIX_READY')
                         AND NOT EXISTS (
                           SELECT 1 FROM publication_requests p
                           WHERE p.opportunity_key=o.key
                             AND p.status IN ('PENDING','GRANTED')
                         )
                       )
                       OR (
                         o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                         AND EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=o.key
                             AND sent.event_type='PR_FOLLOWUP_SENT'
                             AND NOT EXISTS (
                               SELECT 1 FROM events result
                               WHERE result.opportunity_key=o.key
                                 AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                                 AND result.dedupe_key=sent.dedupe_key
                             )
                             AND NOT EXISTS (
                               SELECT 1 FROM events abandoned
                               WHERE abandoned.opportunity_key=o.key
                                 AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                                 AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                     sent.dedupe_key
                                 AND abandoned.id>sent.id
                             )
                         )
                       )
                     )
                   ORDER BY i.updated_at"""
            ).fetchall()
        return self._task_result_candidates_from_rows(rows)

    def has_live_handoff(self, *, issue_url: str) -> bool:
        now = iso_z(datetime.now(UTC))
        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.issue_url=? AND (
                     i.status='CREATING' OR (
                       i.status='LEASED' AND i.expires_at>? AND i.lease_until>?
                     )
                   )
                   LIMIT 1""",
                (issue_url, now, now),
            ).fetchone()
        return row is not None

    def create_publication_request(
        self,
        *,
        issue_url: str,
        thread_id: str,
        commit_sha: str,
        branch: str,
        worktree_path: str,
        evidence_digest: str,
        evidence_path: str,
        publication: dict[str, str],
        probe_receipt: dict[str, Any] | None = None,
        result_digest: str | None = None,
        head_sha: str | None = None,
        selected_base_sha: str | None = None,
        code_paths: list[str] | None = None,
        target_base: dict[str, str] | None = None,
        target_base_bound: bool = False,
        evidence_raw_base64: str | None = None,
        replacement_of_request_id: str | None = None,
    ) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        request_identity = [
            issue_url,
            thread_id,
            commit_sha,
            branch,
            worktree_path,
            evidence_digest,
            canonical_json(publication),
        ]
        if target_base is not None:
            request_identity.append(canonical_json(target_base))
        request_id = sha256_text("|".join(request_identity))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key,o.stage,i.intent_id,i.status,i.thread_id,i.worktree_path,
                          i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.issue_url=? AND i.thread_id=?
                   ORDER BY i.updated_at DESC LIMIT 1""",
                (issue_url, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("issue is not registered for radar publication")
            previous_publication = connection.execute(
                """SELECT p.pr_url,r.commit_sha,r.branch
                   FROM publication_requests r
                   JOIN publication_permits p ON p.request_id=r.request_id
                   WHERE r.opportunity_key=? AND p.status='CONSUMED'
                     AND p.pr_url IS NOT NULL
                   ORDER BY p.updated_at DESC LIMIT 1""",
                (row["key"],),
            ).fetchone()
            followup = connection.execute(
                """SELECT head_sha,wake_digest FROM pr_followups
                   WHERE opportunity_key=? AND followup_required=1""",
                (row["key"],),
            ).fetchone()
            if row["stage"] != "FIX_READY" and not (
                row["stage"] in {"PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}
                and previous_publication is not None
            ):
                raise LedgerError("opportunity is not submit-ready")
            if row["thread_id"] != thread_id:
                raise LedgerError("publication thread identity mismatch")
            require_quarantine_clear(
                connection, opportunity_key=str(row["key"]), operation="publication request"
            )
            if Path(str(row["worktree_path"] or "")).resolve() != Path(worktree_path).resolve():
                raise LedgerError("publication worktree mismatch")
            payload = json.loads(row["payload_json"])
            if payload.get("autoSubmitAuthorized") is not True:
                raise LedgerError("automatic publication is not authorized")
            if payload.get("publicSubmissionAllowed") is not True:
                raise LedgerError("public submission is not allowed")
            if payload.get("authorizationSource") != "signed_live_revalidation_required":
                raise LedgerError("publication authorization source is invalid")
            if payload.get("publicationMode") not in {"canary", "active"}:
                raise LedgerError("publication mode is not active")
            outcome = connection.execute(
                "SELECT quality_json FROM outcomes WHERE opportunity_key=?",
                (row["key"],),
            ).fetchone()
            quality = json.loads(outcome["quality_json"]) if outcome else {}
            replacement_source = None
            replacement_source_request = None
            if replacement_of_request_id is not None:
                replacement_source = connection.execute(
                    "SELECT * FROM publication_requests WHERE request_id=?",
                    (replacement_of_request_id,),
                ).fetchone()
                if (
                    replacement_source is None
                    or replacement_source["status"] != "BLOCKED"
                    or replacement_source["opportunity_key"] != row["key"]
                    or replacement_source["thread_id"] != thread_id
                ):
                    raise LedgerError(
                        "publication replacement source is not an exact blocked request"
                    )
                try:
                    replacement_source_request = json.loads(replacement_source["request_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("publication replacement source is invalid") from exc
                if not isinstance(replacement_source_request, dict):
                    raise LedgerError("publication replacement source is invalid")
            if previous_publication and previous_publication["branch"] != branch:
                raise LedgerError("PR update must preserve the published branch")
            previous_commit_sha = (
                str(followup["head_sha"])
                if previous_publication and followup and followup["head_sha"]
                else str(previous_publication["commit_sha"])
                if previous_publication
                else None
            )
            request = {
                "requestId": request_id,
                "opportunityKey": row["key"],
                "intentId": row["intent_id"],
                "issueUrl": issue_url,
                "threadId": thread_id,
                "commitSha": commit_sha,
                "branch": branch,
                "worktreePath": str(Path(worktree_path).resolve()),
                "evidenceDigest": evidence_digest,
                "evidencePath": str(Path(evidence_path).resolve()),
                "evidenceRawBase64": evidence_raw_base64,
                "publication": publication,
                "probeReceipt": probe_receipt,
                "resultDigest": result_digest,
                "headSha": head_sha or commit_sha,
                "selectedBaseSha": selected_base_sha,
                "codePaths": sorted(
                    {str(path) for path in (code_paths or []) if str(path).strip()}
                ),
                "quality": quality,
                "intent": payload,
                "publicationKind": "PR_UPDATE" if previous_publication else "PR_CREATE",
            }
            if target_base_bound or target_base is not None:
                request["targetBase"] = target_base
            if previous_publication:
                request.update(
                    {
                        "existingPrUrl": previous_publication["pr_url"],
                        "previousCommitSha": previous_commit_sha,
                        "followupWakeDigest": followup["wake_digest"] if followup else None,
                    }
                )
            if replacement_source_request is not None:
                expected_source = {
                    "opportunityKey": row["key"],
                    "intentId": row["intent_id"],
                    "issueUrl": issue_url,
                    "threadId": thread_id,
                    "commitSha": commit_sha,
                    "branch": branch,
                    "worktreePath": str(Path(worktree_path).resolve()),
                    "evidencePath": str(Path(evidence_path).resolve()),
                    "publication": publication,
                    "resultDigest": result_digest,
                    "headSha": head_sha or commit_sha,
                    "selectedBaseSha": selected_base_sha,
                    "codePaths": sorted(
                        {str(path) for path in (code_paths or []) if str(path).strip()}
                    ),
                    "quality": quality,
                    "publicationKind": "PR_UPDATE",
                    "existingPrUrl": (
                        previous_publication["pr_url"] if previous_publication else None
                    ),
                    "previousCommitSha": (
                        str(previous_publication["commit_sha"]) if previous_publication else None
                    ),
                }
                for field, expected_value in expected_source.items():
                    if replacement_source_request.get(field) != expected_value:
                        raise LedgerError(f"publication replacement source mismatch: {field}")
                if target_base_bound or target_base is not None:
                    if replacement_source_request.get("targetBase") != target_base:
                        raise LedgerError("publication replacement source mismatch: targetBase")
                elif "targetBase" in replacement_source_request:
                    raise LedgerError("publication replacement source mismatch: targetBase")
                if not isinstance(
                    replacement_source_request.get("intent"), dict
                ) or replacement_source_request.get("followupWakeDigest") in {None, ""}:
                    raise LedgerError("publication replacement source update binding is incomplete")
                # Preserve the historical PR-update authority exactly.  In
                # particular, a later and possibly erroneous follow-up row must
                # not silently replace the wake that authorized this commit.
                request = dict(replacement_source_request)
                request.update(
                    {
                        "requestId": request_id,
                        "evidenceDigest": evidence_digest,
                        "evidenceRawBase64": evidence_raw_base64,
                        "probeReceipt": probe_receipt,
                    }
                )
            request_allowed = _publication_probe_valid(request)
            request_status = "PENDING" if request_allowed else "BLOCKED"
            request_reason = None if request_allowed else "BLOCKED_REPRODUCTION_REQUIRED"
            existing = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if existing:
                existing_request = json.loads(existing["request_json"])
                if _publication_snapshot_present(request) and not _publication_snapshot_present(
                    existing_request
                ):
                    if existing["evidence_digest"] != evidence_digest:
                        raise LedgerError("publication request snapshot upgrade digest mismatch")
                    if canonical_json(
                        _publication_request_without_snapshot(existing_request)
                    ) != canonical_json(_publication_request_without_snapshot(request)):
                        raise LedgerError("publication request snapshot upgrade binding mismatch")
                    connection.execute(
                        """UPDATE publication_requests
                           SET request_json=?,updated_at=?
                           WHERE request_id=?""",
                        (canonical_json(request), now, request_id),
                    )
                    self._event(
                        connection,
                        row["key"],
                        "PUBLICATION_REQUEST_SNAPSHOT_UPGRADED",
                        f"{request_id}:{evidence_digest}",
                        {"requestId": request_id, "evidenceDigest": evidence_digest},
                        now,
                    )
                    return {
                        **dict(existing),
                        "request_json": canonical_json(request),
                        "request": request,
                    }
                if (
                    existing["status"] == "BLOCKED"
                    and existing["reason"] == "SUBMIT_READY_EVIDENCE_INCOMPLETE"
                    and existing["evidence_digest"] == evidence_digest
                    and existing_request.get("quality") != quality
                ):
                    connection.execute(
                        """UPDATE publication_requests
                           SET status='PENDING',reason=NULL,request_json=?,updated_at=?
                           WHERE request_id=?""",
                        (canonical_json(request), now, request_id),
                    )
                    self._event(
                        connection,
                        row["key"],
                        "PUBLICATION_REQUEST_REARMED",
                        f"{request_id}:{sha256_json(quality)}",
                        {"requestId": request_id, "reason": "QUALITY_EVIDENCE_REPAIRED"},
                        now,
                    )
                    return {
                        **dict(existing),
                        "status": "PENDING",
                        "reason": None,
                        "request_json": canonical_json(request),
                        "request": request,
                    }
                return dict(existing) | {"request": json.loads(existing["request_json"])}
            connection.execute(
                """INSERT INTO publication_requests
                   (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                    evidence_digest,status,request_json,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    request_id,
                    row["key"],
                    thread_id,
                    commit_sha,
                    branch,
                    request["worktreePath"],
                    evidence_digest,
                    request_status,
                    canonical_json(request),
                    now,
                    now,
                ),
            )
            if request_reason:
                connection.execute(
                    "UPDATE publication_requests SET reason=? WHERE request_id=?",
                    (request_reason, request_id),
                )
            self._event(
                connection,
                row["key"],
                "PUBLICATION_REQUESTED",
                request_id,
                request,
                now,
            )
            return {
                "request_id": request_id,
                "status": request_status,
                "reason": request_reason,
                "request": request,
            }

    def publication_request(self, request_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
        return dict(row) | {"request": json.loads(row["request_json"])} if row else None

    def managed_replay_replacement(self, *, source_request_id: str) -> dict[str, Any] | None:
        """Return the sole request that only refreshed one replay snapshot."""

        refreshed_fields = {
            "requestId",
            "evidenceDigest",
            "evidenceRawBase64",
            "probeReceipt",
        }

        def immutable_request(value: dict[str, Any]) -> dict[str, Any]:
            return {field: item for field, item in value.items() if field not in refreshed_fields}

        def receipt_valid_at(
            receipt: Any,
            *,
            source: dict[str, Any],
            bound_at: str,
        ) -> bool:
            issue_url = str(source.get("issueUrl") or "")
            issue_match = ISSUE_URL_RE.fullmatch(issue_url)
            code_paths = sorted(
                {str(path) for path in (source.get("codePaths") or []) if str(path).strip()}
            )
            if issue_match is None or not code_paths or not isinstance(receipt, dict):
                return False
            try:
                observed_at = parse_time(str(receipt.get("observedAt") or ""))
                snapshot_bound_at = parse_time(bound_at)
                expires_at = parse_time(str(receipt.get("expiresAt") or ""))
            except (TypeError, ValueError):
                return False
            return observed_at <= snapshot_bound_at <= expires_at and verify_probe_receipt(
                receipt,
                repo=issue_match.group(1),
                base_sha=str(source.get("selectedBaseSha") or ""),
                code_paths=code_paths,
                required_level=REPRODUCED_VALIDATED,
                issue_url=issue_url,
                task_id=str(source.get("intentId") or ""),
                thread_id=str(source.get("threadId") or ""),
                head_sha=str(source.get("headSha") or ""),
                commit_sha=str(source.get("commitSha") or ""),
                result_digest=str(source.get("resultDigest") or ""),
                enforce_freshness=False,
            )

        with self.connect() as connection:
            source_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (source_request_id,),
            ).fetchone()
            if source_row is None or source_row["status"] != "BLOCKED":
                raise LedgerError("managed replay replacement source is not blocked")
            try:
                source = json.loads(source_row["request_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError("managed replay replacement source is invalid") from exc
            if not isinstance(source, dict) or source.get("publicationKind") != "PR_UPDATE":
                raise LedgerError("managed replay replacement source is invalid")
            rows = connection.execute(
                """SELECT * FROM publication_requests
                   WHERE opportunity_key=? AND thread_id=? AND commit_sha=?
                     AND branch=? AND worktree_path=? AND request_id<>?
                   ORDER BY created_at,request_id""",
                (
                    source_row["opportunity_key"],
                    source_row["thread_id"],
                    source_row["commit_sha"],
                    source_row["branch"],
                    source_row["worktree_path"],
                    source_request_id,
                ),
            ).fetchall()
            candidates: list[tuple[sqlite3.Row, dict[str, Any]]] = []
            expected = immutable_request(source)
            for row in rows:
                try:
                    request = json.loads(row["request_json"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("managed replay replacement candidate is invalid") from exc
                if not isinstance(request, dict):
                    raise LedgerError("managed replay replacement candidate is invalid")
                if immutable_request(request) == expected:
                    row_bindings = {
                        "requestId": row["request_id"],
                        "opportunityKey": row["opportunity_key"],
                        "threadId": row["thread_id"],
                        "commitSha": row["commit_sha"],
                        "branch": row["branch"],
                        "worktreePath": row["worktree_path"],
                        "evidenceDigest": row["evidence_digest"],
                    }
                    if any(
                        not value or str(request.get(field) or "") != str(value)
                        for field, value in row_bindings.items()
                    ):
                        raise LedgerError("managed replay replacement row binding changed")
                    candidates.append((row, request))
            if len(candidates) > 1:
                raise LedgerError("managed replay has multiple replacement requests")
            if not candidates:
                return None
            row, request = candidates[0]
            original_request = _managed_replay_creation_snapshot(
                connection,
                row=row,
                request=request,
            )
            lineage_rows = connection.execute(
                """SELECT * FROM events
                   WHERE opportunity_key=?
                     AND event_type='MANAGED_REPLAY_REPLACEMENT_REFRESHED'
                     AND json_extract(payload_json,'$.sourceRequestId')=?
                     AND json_extract(payload_json,'$.replacementRequestId')=?
                   ORDER BY id""",
                (row["opportunity_key"], source_request_id, row["request_id"]),
            ).fetchall()
            snapshot_bound_at = str(row["created_at"])
            previous_evidence_digest = None
            if lineage_rows:
                chain_evidence_digest: str | None = None
                chain_receipt: dict[str, Any] | None = None
                for index, lineage_row in enumerate(lineage_rows):
                    try:
                        lineage = json.loads(lineage_row["payload_json"])
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise LedgerError("managed replay replacement lineage is invalid") from exc
                    previous_receipt = (
                        lineage.get("previousProbeReceipt") if isinstance(lineage, dict) else None
                    )
                    new_receipt = (
                        lineage.get("newProbeReceipt") if isinstance(lineage, dict) else None
                    )
                    previous_digest = (
                        str(lineage.get("previousEvidenceDigest") or "")
                        if isinstance(lineage, dict)
                        else ""
                    )
                    new_digest = (
                        str(lineage.get("newEvidenceDigest") or "")
                        if isinstance(lineage, dict)
                        else ""
                    )
                    if (
                        not isinstance(lineage, dict)
                        or lineage.get("policyVersion") != "managed-replay-replacement-refresh-v1"
                        or lineage.get("sourceRequestId") != source_request_id
                        or lineage.get("replacementRequestId") != row["request_id"]
                        or lineage.get("refreshedAt") != lineage_row["created_at"]
                        or lineage.get("previousSnapshotBoundAt") != snapshot_bound_at
                        or parse_time(str(lineage_row["created_at"]))
                        <= parse_time(snapshot_bound_at)
                        or not re.fullmatch(r"[0-9a-f]{64}", previous_digest)
                        or not re.fullmatch(r"[0-9a-f]{64}", new_digest)
                        or previous_digest == new_digest
                        or not isinstance(previous_receipt, dict)
                        or not isinstance(new_receipt, dict)
                        or previous_receipt.get("bindingPurpose") != "implementation-result-v1"
                        or new_receipt.get("bindingPurpose") != "implementation-result-v1"
                        or not previous_receipt.get("derivedFromReceiptDigest")
                        or previous_receipt.get("derivedFromReceiptDigest")
                        != new_receipt.get("derivedFromReceiptDigest")
                        or lineage.get("previousReceiptDigest") != sha256_json(previous_receipt)
                        or lineage.get("newReceiptDigest") != sha256_json(new_receipt)
                        or not receipt_valid_at(
                            previous_receipt,
                            source=source,
                            bound_at=snapshot_bound_at,
                        )
                        or not receipt_valid_at(
                            new_receipt,
                            source=source,
                            bound_at=str(lineage_row["created_at"]),
                        )
                        or (index > 0 and previous_digest != chain_evidence_digest)
                        or (index > 0 and previous_receipt != chain_receipt)
                        or (
                            index == 0 and previous_digest != original_request.get("evidenceDigest")
                        )
                        or (index == 0 and previous_receipt != original_request.get("probeReceipt"))
                    ):
                        raise LedgerError("managed replay replacement lineage is invalid")
                    _validate_managed_replay_lineage_authority(
                        connection,
                        opportunity_key=str(row["opportunity_key"]),
                        source_request_id=source_request_id,
                        source=source,
                        lineage=lineage,
                        refreshed_at=str(lineage_row["created_at"]),
                    )
                    previous_evidence_digest = previous_digest
                    chain_evidence_digest = new_digest
                    chain_receipt = new_receipt
                    snapshot_bound_at = str(lineage_row["created_at"])
                if (
                    chain_evidence_digest != row["evidence_digest"]
                    or request.get("probeReceipt") != chain_receipt
                    # ``updated_at`` also advances when a publication worker
                    # contracts the request to BLOCKED after the signed probe
                    # receipt expires.  The immutable evidence bytes and the
                    # signed refresh chain above bind the snapshot; require the
                    # shared lifecycle clock to be monotonic instead of
                    # mistaking that later status-only write for evidence drift.
                    or parse_time(str(row["updated_at"])) < parse_time(snapshot_bound_at)
                ):
                    raise LedgerError("managed replay replacement lineage is invalid")
            else:
                receipt = request.get("probeReceipt")
                if request != original_request or not receipt_valid_at(
                    receipt,
                    source=source,
                    bound_at=snapshot_bound_at,
                ):
                    raise LedgerError("managed replay replacement receipt is invalid")
            return dict(row) | {
                "request": request,
                "snapshotBoundAt": snapshot_bound_at,
                "previousEvidenceDigest": previous_evidence_digest,
            }

    def refresh_managed_replay_replacement(
        self,
        *,
        source_request_id: str,
        replacement_request_id: str,
        expected_source: dict[str, Any],
        expected_replacement: dict[str, Any],
        new_evidence_digest: str,
        new_evidence_raw_base64: str,
        new_probe_receipt: dict[str, Any],
    ) -> dict[str, Any]:
        """Refresh one exact replay replacement in place without publishing."""

        refreshed_fields = {
            "requestId",
            "evidenceDigest",
            "evidenceRawBase64",
            "probeReceipt",
        }

        def parse_object(raw: Any, error: str) -> dict[str, Any]:
            try:
                value = json.loads(raw)
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError(error) from exc
            if not isinstance(value, dict):
                raise LedgerError(error)
            return value

        def immutable_request(value: dict[str, Any]) -> dict[str, Any]:
            return {field: item for field, item in value.items() if field not in refreshed_fields}

        def evidence_semantics(value: dict[str, Any]) -> dict[str, Any]:
            semantics = dict(value)
            semantics.pop("reproductionReceipt", None)
            semantics.pop("probeReceipt", None)
            return semantics

        with self.transaction() as connection:
            source_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (source_request_id,),
            ).fetchone()
            replacement_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (replacement_request_id,),
            ).fetchone()
            if (
                source_row is None
                or source_row["status"] != "BLOCKED"
                or replacement_row is None
                or source_row["request_id"] == replacement_row["request_id"]
                or replacement_row["permit_id"] is not None
            ):
                raise LedgerError("managed replay replacement refresh source changed")
            source = parse_object(
                source_row["request_json"], "managed replay replacement source is invalid"
            )
            replacement = parse_object(
                replacement_row["request_json"],
                "managed replay replacement request is invalid",
            )
            expected_source_request = expected_source.get("request")
            if not isinstance(expected_source_request, dict):
                raise LedgerError("managed replay replacement source CAS snapshot is invalid")
            for field in source_row.keys():
                if source_row[field] != expected_source.get(field):
                    raise LedgerError("managed replay replacement source CAS row changed")
            if (
                source.get("requestId") != source_request_id
                or source.get("publicationKind") != "PR_UPDATE"
                or source != expected_source_request
                or replacement.get("requestId") != replacement_request_id
                or immutable_request(replacement) != immutable_request(source)
            ):
                raise LedgerError("managed replay replacement semantics changed")

            expected_request = expected_replacement.get("request")
            if not isinstance(expected_request, dict):
                raise LedgerError("managed replay replacement CAS snapshot is invalid")
            for field in replacement_row.keys():
                if replacement_row[field] != expected_replacement.get(field):
                    raise LedgerError("managed replay replacement CAS row changed")
            if replacement != expected_request:
                raise LedgerError("managed replay replacement CAS request changed")
            original_request = _managed_replay_creation_snapshot(
                connection,
                row=replacement_row,
                request=replacement,
            )

            sibling_rows = connection.execute(
                """SELECT request_id,request_json FROM publication_requests
                   WHERE opportunity_key=? AND thread_id=? AND commit_sha=?
                     AND branch=? AND worktree_path=? AND request_id<>?""",
                (
                    source_row["opportunity_key"],
                    source_row["thread_id"],
                    source_row["commit_sha"],
                    source_row["branch"],
                    source_row["worktree_path"],
                    source_request_id,
                ),
            ).fetchall()
            exact_siblings = []
            for sibling in sibling_rows:
                sibling_request = parse_object(
                    sibling["request_json"],
                    "managed replay replacement sibling is invalid",
                )
                if immutable_request(sibling_request) == immutable_request(source):
                    exact_siblings.append(str(sibling["request_id"]))
            if len(exact_siblings) != 1 or exact_siblings[0] != replacement_request_id:
                raise LedgerError("managed replay replacement is not unique")
            local_permit = connection.execute(
                "SELECT 1 FROM publication_permits WHERE request_id=? LIMIT 1",
                (replacement_request_id,),
            ).fetchone()
            local_effect = connection.execute(
                """SELECT 1 FROM publication_effects effect
                   JOIN publication_permits permit ON permit.permit_id=effect.permit_id
                   WHERE permit.request_id=? LIMIT 1""",
                (replacement_request_id,),
            ).fetchone()
            managed_reservation_table = connection.execute(
                """SELECT 1 FROM sqlite_master
                   WHERE type='table' AND name='managed_publication_reservations'"""
            ).fetchone()
            managed_reservation = (
                connection.execute(
                    """SELECT 1 FROM managed_publication_reservations
                       WHERE request_id=? LIMIT 1""",
                    (replacement_request_id,),
                ).fetchone()
                if managed_reservation_table is not None
                else None
            )
            if (
                local_permit is not None
                or local_effect is not None
                or managed_reservation is not None
            ):
                raise LedgerError("managed replay replacement already has a permit")

            source_snapshot = source.get("evidenceRawBase64")
            old_snapshot = replacement.get("evidenceRawBase64")
            if not isinstance(source_snapshot, str) or not isinstance(old_snapshot, str):
                raise LedgerError("managed replay replacement evidence is missing")
            try:
                source_raw = base64.b64decode(source_snapshot.encode("ascii"), validate=True)
                old_raw = base64.b64decode(old_snapshot.encode("ascii"), validate=True)
                new_raw = base64.b64decode(new_evidence_raw_base64.encode("ascii"), validate=True)
                source_evidence = json.loads(source_raw)
                old_evidence = json.loads(old_raw)
                new_evidence = json.loads(new_raw)
            except (ValueError, UnicodeEncodeError, json.JSONDecodeError) as exc:
                raise LedgerError("managed replay replacement evidence is invalid") from exc
            if not all(
                isinstance(item, dict) for item in (source_evidence, old_evidence, new_evidence)
            ):
                raise LedgerError("managed replay replacement evidence is invalid")
            old_receipt = old_evidence.get("reproductionReceipt") or old_evidence.get(
                "probeReceipt"
            )
            new_evidence_receipt = new_evidence.get("reproductionReceipt") or new_evidence.get(
                "probeReceipt"
            )
            if (
                hashlib.sha256(source_raw).hexdigest() != source_row["evidence_digest"]
                or hashlib.sha256(old_raw).hexdigest() != replacement_row["evidence_digest"]
                or hashlib.sha256(new_raw).hexdigest() != new_evidence_digest
                or replacement.get("probeReceipt") != old_receipt
                or new_evidence_receipt != new_probe_receipt
                or evidence_semantics(old_evidence) != evidence_semantics(source_evidence)
                or evidence_semantics(new_evidence) != evidence_semantics(source_evidence)
            ):
                raise LedgerError("managed replay replacement evidence semantics changed")

            issue_url = str(source.get("issueUrl") or "")
            issue_match = ISSUE_URL_RE.fullmatch(issue_url)
            code_paths = sorted(
                {str(path) for path in (source.get("codePaths") or []) if str(path).strip()}
            )
            expected_receipt = {
                "repo": issue_match.group(1) if issue_match is not None else "",
                "base_sha": str(source.get("selectedBaseSha") or ""),
                "code_paths": code_paths,
                "issue_url": issue_url,
                "task_id": str(source.get("intentId") or ""),
                "thread_id": str(source.get("threadId") or ""),
                "head_sha": str(source.get("headSha") or ""),
                "commit_sha": str(source.get("commitSha") or ""),
                "result_digest": str(source.get("resultDigest") or ""),
            }

            def receipt_valid_at(receipt: Any, bound_at: str) -> bool:
                if not isinstance(receipt, dict):
                    return False
                try:
                    observed_at = parse_time(str(receipt.get("observedAt") or ""))
                    snapshot_bound_at = parse_time(bound_at)
                    expires_at = parse_time(str(receipt.get("expiresAt") or ""))
                except (TypeError, ValueError):
                    return False
                return observed_at <= snapshot_bound_at <= expires_at and verify_probe_receipt(
                    receipt,
                    **expected_receipt,
                    required_level=REPRODUCED_VALIDATED,
                    enforce_freshness=False,
                )

            lineage_rows = connection.execute(
                """SELECT * FROM events
                   WHERE opportunity_key=?
                     AND event_type='MANAGED_REPLAY_REPLACEMENT_REFRESHED'
                     AND json_extract(payload_json,'$.sourceRequestId')=?
                     AND json_extract(payload_json,'$.replacementRequestId')=?
                   ORDER BY id""",
                (
                    source_row["opportunity_key"],
                    source_request_id,
                    replacement_request_id,
                ),
            ).fetchall()
            snapshot_bound_at = str(replacement_row["created_at"])
            chain_evidence_digest: str | None = None
            chain_receipt: dict[str, Any] | None = None
            for index, lineage_row in enumerate(lineage_rows):
                lineage = parse_object(
                    lineage_row["payload_json"],
                    "managed replay replacement lineage is invalid",
                )
                previous_receipt = lineage.get("previousProbeReceipt")
                lineage_new_receipt = lineage.get("newProbeReceipt")
                previous_digest = str(lineage.get("previousEvidenceDigest") or "")
                lineage_new_digest = str(lineage.get("newEvidenceDigest") or "")
                if (
                    lineage.get("policyVersion") != "managed-replay-replacement-refresh-v1"
                    or lineage.get("sourceRequestId") != source_request_id
                    or lineage.get("replacementRequestId") != replacement_request_id
                    or lineage.get("refreshedAt") != lineage_row["created_at"]
                    or lineage.get("previousSnapshotBoundAt") != snapshot_bound_at
                    or parse_time(str(lineage_row["created_at"])) <= parse_time(snapshot_bound_at)
                    or not re.fullmatch(r"[0-9a-f]{64}", previous_digest)
                    or not re.fullmatch(r"[0-9a-f]{64}", lineage_new_digest)
                    or previous_digest == lineage_new_digest
                    or not isinstance(previous_receipt, dict)
                    or not isinstance(lineage_new_receipt, dict)
                    or previous_receipt.get("bindingPurpose") != "implementation-result-v1"
                    or lineage_new_receipt.get("bindingPurpose") != "implementation-result-v1"
                    or not previous_receipt.get("derivedFromReceiptDigest")
                    or previous_receipt.get("derivedFromReceiptDigest")
                    != lineage_new_receipt.get("derivedFromReceiptDigest")
                    or lineage.get("previousReceiptDigest") != sha256_json(previous_receipt)
                    or lineage.get("newReceiptDigest") != sha256_json(lineage_new_receipt)
                    or not receipt_valid_at(previous_receipt, snapshot_bound_at)
                    or not receipt_valid_at(
                        lineage_new_receipt,
                        str(lineage_row["created_at"]),
                    )
                    or (index > 0 and previous_digest != chain_evidence_digest)
                    or (index > 0 and previous_receipt != chain_receipt)
                    or (index == 0 and previous_digest != original_request.get("evidenceDigest"))
                    or (index == 0 and previous_receipt != original_request.get("probeReceipt"))
                ):
                    raise LedgerError("managed replay replacement lineage is invalid")
                _validate_managed_replay_lineage_authority(
                    connection,
                    opportunity_key=str(source_row["opportunity_key"]),
                    source_request_id=source_request_id,
                    source=source,
                    lineage=lineage,
                    refreshed_at=str(lineage_row["created_at"]),
                )
                chain_evidence_digest = lineage_new_digest
                chain_receipt = lineage_new_receipt
                snapshot_bound_at = str(lineage_row["created_at"])
            if lineage_rows and (
                chain_evidence_digest != replacement_row["evidence_digest"]
                or chain_receipt != old_receipt
                or parse_time(str(replacement_row["updated_at"])) < parse_time(snapshot_bound_at)
            ):
                raise LedgerError("managed replay replacement lineage is invalid")
            if not lineage_rows and replacement != original_request:
                raise LedgerError("managed replay replacement creation snapshot changed")
            if expected_replacement.get("snapshotBoundAt") != snapshot_bound_at:
                raise LedgerError("managed replay replacement snapshot binding changed")
            try:
                old_observed_at = parse_time(str((old_receipt or {}).get("observedAt") or ""))
                old_expires_at = parse_time(str((old_receipt or {}).get("expiresAt") or ""))
                old_bound_at = parse_time(snapshot_bound_at)
            except (TypeError, ValueError) as exc:
                raise LedgerError("managed replay replacement receipt time is invalid") from exc
            if (
                issue_match is None
                or not code_paths
                or not isinstance(old_receipt, dict)
                or not isinstance(new_probe_receipt, dict)
                or old_receipt.get("bindingPurpose") != "implementation-result-v1"
                or new_probe_receipt.get("bindingPurpose") != "implementation-result-v1"
                or not old_receipt.get("derivedFromReceiptDigest")
                or old_receipt.get("derivedFromReceiptDigest")
                != new_probe_receipt.get("derivedFromReceiptDigest")
                or not old_observed_at <= old_bound_at <= old_expires_at
                or not verify_probe_receipt(
                    old_receipt,
                    **expected_receipt,
                    required_level=REPRODUCED_VALIDATED,
                    enforce_freshness=False,
                )
                or not verify_probe_receipt(
                    new_probe_receipt,
                    **expected_receipt,
                    required_level=REPRODUCED_VALIDATED,
                )
            ):
                raise LedgerError("managed replay replacement receipt is invalid")

            watermark = self._managed_replay_task_result_watermark(
                connection,
                key=str(source_row["opportunity_key"]),
                task_id=str(source["intentId"]),
                thread_id=str(source_row["thread_id"]),
                request_updated_at=str(source_row["updated_at"]),
            )
            authority_id = watermark.get("authorityEventId")
            authority_row = (
                connection.execute(
                    "SELECT * FROM events WHERE id=? AND opportunity_key=?",
                    (authority_id, source_row["opportunity_key"]),
                ).fetchone()
                if authority_id is not None
                else None
            )
            authority = (
                parse_object(
                    authority_row["payload_json"],
                    "managed replay replacement authority is invalid",
                )
                if authority_row is not None
                else {}
            )
            continuation_key = str(watermark.get("continuationDedupeKey") or "")
            continuation_row = connection.execute(
                """SELECT * FROM events
                   WHERE opportunity_key=?
                     AND event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                     AND dedupe_key=?""",
                (source_row["opportunity_key"], continuation_key),
            ).fetchone()
            continuation = (
                parse_object(
                    continuation_row["payload_json"],
                    "managed replay replacement continuation is invalid",
                )
                if continuation_row is not None
                else {}
            )
            authority_state = {
                field: authority.get(field)
                for field in (
                    "taskId",
                    "threadId",
                    "sourceResultEventId",
                    "resultDigest",
                    "continuationDedupeKey",
                    "tombstoneReceiptDigest",
                )
            }
            continuation_tombstone = continuation.get("codePathTombstoneReceipt")
            if (
                authority_row is None
                or authority_row["event_type"] != "TASK_RESULT_AUTHORITY_BOUND"
                or authority.get("sourcePublicationRequestId") != source_request_id
                or authority.get("continuationDedupeKey") != continuation_key
                or authority.get("resultDigest") != source.get("resultDigest")
                or authority.get("authorityStateDigest") != sha256_json(authority_state)
                or continuation.get("sourcePublicationRequestId") != source_request_id
                or continuation.get("continuationHeadSha") != source.get("commitSha")
                or continuation.get("resultDigest") != source.get("resultDigest")
                or not isinstance(continuation_tombstone, dict)
                or authority.get("tombstoneReceiptDigest") != sha256_json(continuation_tombstone)
            ):
                raise LedgerError("managed replay replacement authority is not current")

            if replacement_row["status"] == "PENDING":
                if (
                    replacement_row["reason"] is not None
                    or replacement_row["evidence_digest"] != new_evidence_digest
                    or replacement.get("evidenceDigest") != new_evidence_digest
                    or replacement.get("evidenceRawBase64") != new_evidence_raw_base64
                    or replacement.get("probeReceipt") != new_probe_receipt
                    or (
                        lineage_rows
                        and (
                            chain_evidence_digest != new_evidence_digest
                            or chain_receipt != new_probe_receipt
                            or parse_time(str(replacement_row["updated_at"]))
                            < parse_time(snapshot_bound_at)
                        )
                    )
                ):
                    raise LedgerError("managed replay replacement pending state changed")
                return dict(replacement_row) | {
                    "request": replacement,
                    "refreshed": False,
                }

            if (
                replacement_row["status"] != "BLOCKED"
                or replacement_row["reason"] != "BLOCKED_REPRODUCTION_REQUIRED"
                or replacement_row["evidence_digest"] == new_evidence_digest
            ):
                raise LedgerError("managed replay replacement block state changed")

            refreshed_at = iso_z(datetime.now(UTC))
            try:
                refreshed_time = parse_time(refreshed_at)
                new_observed_at = parse_time(str(new_probe_receipt.get("observedAt") or ""))
                new_expires_at = parse_time(str(new_probe_receipt.get("expiresAt") or ""))
            except (TypeError, ValueError) as exc:
                raise LedgerError("managed replay replacement new receipt time is invalid") from exc
            if (
                refreshed_time <= old_bound_at
                or not new_observed_at <= refreshed_time <= new_expires_at
            ):
                raise LedgerError("managed replay replacement new receipt is not current")
            refreshed_request = dict(replacement)
            refreshed_request.update(
                {
                    "evidenceDigest": new_evidence_digest,
                    "evidenceRawBase64": new_evidence_raw_base64,
                    "probeReceipt": new_probe_receipt,
                }
            )
            updated = connection.execute(
                """UPDATE publication_requests
                   SET evidence_digest=?,request_json=?,status='PENDING',reason=NULL,updated_at=?
                   WHERE request_id=? AND status='BLOCKED'
                     AND reason='BLOCKED_REPRODUCTION_REQUIRED'
                     AND evidence_digest=? AND request_json=? AND updated_at=?""",
                (
                    new_evidence_digest,
                    canonical_json(refreshed_request),
                    refreshed_at,
                    replacement_request_id,
                    replacement_row["evidence_digest"],
                    replacement_row["request_json"],
                    replacement_row["updated_at"],
                ),
            ).rowcount
            if updated != 1:
                raise LedgerError("managed replay replacement refresh CAS lost")
            lineage = {
                "policyVersion": "managed-replay-replacement-refresh-v1",
                "sourceRequestId": source_request_id,
                "replacementRequestId": replacement_request_id,
                "previousEvidenceDigest": replacement_row["evidence_digest"],
                "newEvidenceDigest": new_evidence_digest,
                "previousReceiptDigest": sha256_json(old_receipt),
                "newReceiptDigest": sha256_json(new_probe_receipt),
                "previousProbeReceipt": old_receipt,
                "newProbeReceipt": new_probe_receipt,
                "previousSnapshotBoundAt": snapshot_bound_at,
                "continuationDedupeKey": continuation_key,
                "authorityEventId": int(authority_row["id"]),
                "refreshedAt": refreshed_at,
            }
            lineage_dedupe_key = sha256_text(
                "|".join(
                    (
                        "managed-replay-replacement-refresh-v1",
                        source_request_id,
                        replacement_request_id,
                        str(replacement_row["evidence_digest"]),
                        new_evidence_digest,
                    )
                )
            )
            self._event(
                connection,
                str(source_row["opportunity_key"]),
                "MANAGED_REPLAY_REPLACEMENT_REFRESHED",
                lineage_dedupe_key,
                lineage,
                refreshed_at,
            )
            lineage_row = connection.execute(
                """SELECT * FROM events
                   WHERE opportunity_key=?
                     AND event_type='MANAGED_REPLAY_REPLACEMENT_REFRESHED'
                     AND dedupe_key=?""",
                (source_row["opportunity_key"], lineage_dedupe_key),
            ).fetchone()
            refreshed_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (replacement_request_id,),
            ).fetchone()
            if (
                refreshed_row is None
                or refreshed_row["status"] != "PENDING"
                or refreshed_row["reason"] is not None
                or refreshed_row["evidence_digest"] != new_evidence_digest
                or refreshed_row["request_json"] != canonical_json(refreshed_request)
                or lineage_row is None
                or lineage_row["payload_json"] != canonical_json(lineage)
                or lineage_row["created_at"] != refreshed_at
            ):
                raise LedgerError("managed replay replacement refresh did not persist")
            return dict(refreshed_row) | {
                "request": refreshed_request,
                "refreshed": True,
            }

    def publication_work_items(self) -> list[dict[str, Any]]:
        """Return publication requests that the privileged controller may advance."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT r.*,
                          (SELECT e.result_json FROM publication_effects e
                           JOIN publication_permits permit
                             ON permit.permit_id=e.permit_id
                            AND permit.request_id=r.request_id
                           WHERE e.action='create_pr'
                             AND e.status='SUCCEEDED'
                           ORDER BY e.updated_at DESC LIMIT 1) AS external_receipt_json
                   FROM publication_requests r
                   JOIN opportunities opportunity
                     ON opportunity.key=r.opportunity_key
                   WHERE (
                     NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                         WHERE quarantine.opportunity_key=r.opportunity_key
                           AND quarantine.status='ACTIVE'
                     )
                     AND opportunity.stage IN (
                       'FIX_READY','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                     )
                     AND (r.status IN ('PENDING','GRANTED') OR (
                       r.status='BLOCKED'
                       AND EXISTS (
                         SELECT 1 FROM publication_permits p
                         JOIN publication_effects push ON push.permit_id=p.permit_id
                         JOIN publication_effects confirm ON confirm.permit_id=p.permit_id
                         WHERE p.request_id=r.request_id
                           AND push.action='push' AND push.status='SUCCEEDED'
                           AND confirm.action='create_pr' AND confirm.status='FAILED'
                           AND confirm.result_json LIKE '%\"reason\":\"LIVE_RECHECK_FAILED\"%'
                           AND confirm.result_json LIKE '%\"detail\":\"EXISTING_PR_HEAD_DRIFT\"%'
                       )
                     ))
                   ) OR (
                     r.status='CONSUMED'
                     AND EXISTS (
                       SELECT 1 FROM publication_effects effect
                       JOIN publication_permits permit
                         ON permit.permit_id=effect.permit_id
                        AND permit.request_id=r.request_id
                       WHERE effect.action='create_pr'
                         AND effect.status='SUCCEEDED'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reconciled
                       WHERE reconciled.opportunity_key=r.opportunity_key
                         AND reconciled.event_type='MANAGED_PUBLICATION_RECONCILED'
                         AND reconciled.dedupe_key='managed-publication-reconciled:' || r.request_id
                     )
                   )
                   ORDER BY r.created_at"""
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row) | {"request": json.loads(row["request_json"])}
            raw_receipt = item.pop("external_receipt_json", None)
            if raw_receipt:
                try:
                    receipt = json.loads(raw_receipt)
                except json.JSONDecodeError:
                    receipt = None
                if isinstance(receipt, dict) and receipt.get("prUrl"):
                    item["externalPublicationReceipt"] = receipt
            items.append(item)
        return items

    def mark_managed_publication_reconciled(
        self, request_id: str, *, pr_url: str, head_sha: str
    ) -> None:
        """Record that a durable external PR receipt was attached to managed state."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request is missing")
            self._event(
                connection,
                row["opportunity_key"],
                "MANAGED_PUBLICATION_RECONCILED",
                f"managed-publication-reconciled:{request_id}",
                {"requestId": request_id, "prUrl": pr_url, "headSha": head_sha},
                now,
            )

    def active_task_quarantine(self, key: str) -> dict[str, Any] | None:
        """Return the latest uncleared task-local quarantine, if any."""

        with self.connect() as connection:
            ensure_quarantine_schema(connection)
            row = active_quarantine(connection, opportunity_key=key)
        if row is None:
            return None
        return {
            "reason": str(row["reason"]),
            "payload": quarantine_payload(row),
            "createdAt": row["created_at"],
        }

    def active_task_quarantines(self, key: str) -> list[dict[str, Any]]:
        """Return every active task-local quarantine with a stable payload binding."""

        with self.connect() as connection:
            ensure_quarantine_schema(connection)
            rows = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND status='ACTIVE'
                   ORDER BY quarantine_id""",
                (key,),
            ).fetchall()
        quarantines: list[dict[str, Any]] = []
        for row in rows:
            payload = quarantine_payload(row)
            quarantines.append(
                {
                    "reason": str(row["reason"]),
                    "dedupeKey": str(row["dedupe_key"]),
                    "payload": payload,
                    "payloadDigest": sha256_json(payload),
                    "createdAt": row["created_at"],
                }
            )
        return quarantines

    def single_active_task_quarantine(self, key: str) -> dict[str, Any] | None:
        """Return an active quarantine only when it is the sole task-local gate."""

        with self.connect() as connection:
            ensure_quarantine_schema(connection)
            rows = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND status='ACTIVE'
                   ORDER BY quarantine_id DESC LIMIT 2""",
                (key,),
            ).fetchall()
        if len(rows) != 1:
            return None
        row = rows[0]
        return {
            "reason": str(row["reason"]),
            "dedupeKey": str(row["dedupe_key"]),
            "payload": quarantine_payload(row),
            "createdAt": row["created_at"],
        }

    def clear_task_quarantine_exact(
        self,
        key: str,
        *,
        reason: str,
        dedupe_key: str,
        evidence: dict[str, Any],
    ) -> None:
        """Clear only the exact quarantine row proven by a controller rebind."""

        if not reason or not dedupe_key or not isinstance(evidence, dict):
            raise LedgerError("exact task quarantine clear evidence is incomplete")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            active_rows = connection.execute(
                """SELECT reason,dedupe_key FROM task_quarantines
                   WHERE opportunity_key=? AND status='ACTIVE'
                   ORDER BY quarantine_id""",
                (key,),
            ).fetchall()
            if len(active_rows) != 1 or tuple(active_rows[0]) != (reason, dedupe_key):
                raise LedgerError("exact task quarantine is not the sole active gate")
            cleared = clear_quarantine_exact(
                connection,
                opportunity_key=key,
                reason=reason,
                dedupe_key=dedupe_key,
                evidence=evidence,
                cleared_at=now,
            )
            if cleared != 1:
                raise LedgerError("exact task quarantine was not cleared")
            connection.execute(
                """UPDATE publication_requests
                   SET status='PENDING',reason='TASK_QUARANTINE_CLEARED',updated_at=?
                   WHERE opportunity_key=? AND status='BLOCKED'
                     AND reason='BLOCKED_REPRODUCTION_REQUIRED'""",
                (now, key),
            )
            self._event(
                connection,
                key,
                "TASK_QUARANTINE_CLEARED",
                sha256_text(f"{key}|{reason}|{dedupe_key}|{canonical_json(evidence)}"),
                {"reason": reason, "dedupeKey": dedupe_key, **evidence},
                now,
            )

    def clear_task_quarantines_exact(
        self,
        key: str,
        *,
        gates: list[dict[str, Any]],
        evidence: dict[str, Any],
    ) -> None:
        """Atomically clear one exact, complete snapshot of active quarantine gates."""

        if not isinstance(gates, list) or not gates:
            raise LedgerError("exact task quarantine gate set is empty")
        if not isinstance(evidence, dict) or evidence.get("revalidated") is not True:
            raise LedgerError("exact task quarantine clear evidence is incomplete")

        expected: list[tuple[str, str, str]] = []
        identities: set[tuple[str, str]] = set()
        for gate in gates:
            if not isinstance(gate, dict):
                raise LedgerError("exact task quarantine gate is invalid")
            reason = gate.get("reason")
            dedupe_key = gate.get("dedupeKey")
            payload_digest = gate.get("payloadDigest")
            if (
                not isinstance(reason, str)
                or not reason
                or not isinstance(dedupe_key, str)
                or not dedupe_key
                or not isinstance(payload_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", payload_digest) is None
            ):
                raise LedgerError("exact task quarantine gate is invalid")
            identity = (reason, dedupe_key)
            if identity in identities:
                raise LedgerError("exact task quarantine gate set contains duplicates")
            identities.add(identity)
            expected.append((reason, dedupe_key, payload_digest))

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            ensure_quarantine_schema(connection)
            active_rows = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND status='ACTIVE'
                   ORDER BY quarantine_id""",
                (key,),
            ).fetchall()
            if not active_rows:
                raise LedgerError("exact task quarantine active gate set is empty")
            actual = [
                (
                    str(row["reason"]),
                    str(row["dedupe_key"]),
                    sha256_json(quarantine_payload(row)),
                )
                for row in active_rows
            ]
            if len(actual) != len(expected) or set(actual) != set(expected):
                raise LedgerError("exact task quarantine active gate set changed")

            for reason, dedupe_key, payload_digest in actual:
                cleared = clear_quarantine_exact(
                    connection,
                    opportunity_key=key,
                    reason=reason,
                    dedupe_key=dedupe_key,
                    evidence=evidence,
                    cleared_at=now,
                )
                if cleared != 1:
                    raise LedgerError("exact task quarantine batch was not cleared")
                self._event(
                    connection,
                    key,
                    "TASK_QUARANTINE_CLEARED",
                    sha256_text(
                        f"{key}|{reason}|{dedupe_key}|{payload_digest}|{canonical_json(evidence)}"
                    ),
                    {
                        "reason": reason,
                        "dedupeKey": dedupe_key,
                        "payloadDigest": payload_digest,
                        **evidence,
                    },
                    now,
                )

    def clear_task_quarantine_member_exact(
        self,
        key: str,
        *,
        reason: str,
        dedupe_key: str,
        payload_digest: str,
        evidence: dict[str, Any],
    ) -> None:
        """Clear one exact gate while preserving every unrelated active gate."""

        if (
            not reason
            or not dedupe_key
            or re.fullmatch(r"[0-9a-f]{64}", payload_digest) is None
            or not isinstance(evidence, dict)
            or evidence.get("revalidated") is not True
        ):
            raise LedgerError("exact task quarantine member clear evidence is incomplete")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            ensure_quarantine_schema(connection)
            row = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND reason=? AND dedupe_key=? AND status='ACTIVE'""",
                (key, reason, dedupe_key),
            ).fetchone()
            if row is None or sha256_json(quarantine_payload(row)) != payload_digest:
                raise LedgerError("exact task quarantine member changed")
            cleared = clear_quarantine_exact(
                connection,
                opportunity_key=key,
                reason=reason,
                dedupe_key=dedupe_key,
                evidence=evidence,
                cleared_at=now,
            )
            if cleared != 1:
                raise LedgerError("exact task quarantine member was not cleared")
            if active_quarantine(connection, opportunity_key=key) is None:
                connection.execute(
                    """UPDATE publication_requests
                       SET status='PENDING',reason='TASK_QUARANTINE_CLEARED',updated_at=?
                       WHERE opportunity_key=? AND status='BLOCKED'
                         AND reason='BLOCKED_REPRODUCTION_REQUIRED'""",
                    (now, key),
                )
            self._event(
                connection,
                key,
                "TASK_QUARANTINE_CLEARED",
                sha256_text(
                    f"{key}|{reason}|{dedupe_key}|{payload_digest}|{canonical_json(evidence)}"
                ),
                {
                    "reason": reason,
                    "dedupeKey": dedupe_key,
                    "payloadDigest": payload_digest,
                    **evidence,
                },
                now,
            )

    def supersede_pr_followup_reservation_repair_exact(
        self,
        key: str,
        *,
        task_id: str,
        thread_id: str,
        context_digest: str,
        wake_digest: str,
        replacement_wake_digest: str,
        quarantine_dedupe_key: str,
        quarantine_payload_digest: str,
        context_quarantine_dedupe_key: str,
        context_quarantine_payload_digest: str,
        evidence: dict[str, Any],
    ) -> None:
        """Retire one failed reservation after a newer follow-up supersedes it."""

        hashes = (
            context_digest,
            wake_digest,
            replacement_wake_digest,
            quarantine_payload_digest,
            context_quarantine_payload_digest,
        )
        if (
            not task_id
            or not thread_id
            or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in hashes)
            or wake_digest == replacement_wake_digest
            or not quarantine_dedupe_key
            or not context_quarantine_dedupe_key
            or not isinstance(evidence, dict)
            or evidence.get("revalidated") is not True
        ):
            raise LedgerError("superseded PR follow-up repair evidence is incomplete")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            ensure_quarantine_schema(connection)
            gate = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND reason='PR_FOLLOWUP_REBIND_REQUIRED'
                     AND dedupe_key=? AND status='ACTIVE'""",
                (key, quarantine_dedupe_key),
            ).fetchone()
            if gate is None or sha256_json(quarantine_payload(gate)) != quarantine_payload_digest:
                raise LedgerError("superseded PR follow-up quarantine changed")
            context_gate = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND reason='SHARED_CONTEXT_INVALID'
                     AND dedupe_key=? AND status='ACTIVE'""",
                (key, context_quarantine_dedupe_key),
            ).fetchone()
            if (
                context_gate is None
                or sha256_json(quarantine_payload(context_gate))
                != context_quarantine_payload_digest
            ):
                raise LedgerError("superseded PR follow-up context quarantine changed")
            gate_payload = quarantine_payload(gate)
            if (
                gate_payload.get("threadId") != thread_id
                or gate_payload.get("wakeDigest") != wake_digest
                or gate_payload.get("reservationPending") is not True
            ):
                raise LedgerError("superseded PR follow-up quarantine binding is invalid")
            current = connection.execute(
                """SELECT pr_url,head_sha,wake_digest,checked_at FROM pr_followups
                   WHERE opportunity_key=? AND followup_required=1""",
                (key,),
            ).fetchone()
            if current is None or current["wake_digest"] != replacement_wake_digest:
                raise LedgerError("replacement PR follow-up changed")
            reserved = connection.execute(
                """SELECT id,created_at,payload_json FROM events
                   WHERE opportunity_key=? AND event_type='PR_FOLLOWUP_RESERVED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, wake_digest, thread_id),
            ).fetchone()
            preparation = connection.execute(
                """SELECT id,payload_json FROM events
                   WHERE opportunity_key=? AND event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, wake_digest, thread_id),
            ).fetchone()
            repair = connection.execute(
                """SELECT id FROM events
                   WHERE opportunity_key=?
                     AND event_type='PR_FOLLOWUP_RESERVATION_REPAIR_REQUIRED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, wake_digest, thread_id),
            ).fetchone()
            if (
                reserved is None
                or preparation is None
                or repair is None
                or int(preparation["id"]) < int(reserved["id"])
                or int(repair["id"]) < int(reserved["id"])
            ):
                raise LedgerError("superseded PR follow-up reservation proof is incomplete")
            try:
                reserved_payload = json.loads(reserved["payload_json"])
                preparation_payload = json.loads(preparation["payload_json"])
                preparation_snapshot = preparation_payload.get("snapshot")
                prepared_checked_at = parse_time(str(preparation_snapshot.get("checkedAt") or ""))
                replacement_checked_at = parse_time(str(current["checked_at"] or ""))
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LedgerError(
                    "superseded PR follow-up reservation snapshot is invalid"
                ) from exc
            prepared_pr_url = str(preparation_snapshot.get("prUrl") or "")
            prepared_head_sha = str(preparation_snapshot.get("preparedHeadSha") or "")
            if (
                not isinstance(reserved_payload, dict)
                or not isinstance(preparation_payload, dict)
                or not isinstance(preparation_snapshot, dict)
                or reserved_payload.get("threadId") != thread_id
                or reserved_payload.get("prUrl") != prepared_pr_url
                or preparation_payload.get("threadId") != thread_id
                or preparation_snapshot.get("wakeDigest") != wake_digest
                or not PR_URL_RE.fullmatch(prepared_pr_url)
                or re.fullmatch(r"[0-9a-f]{40}", prepared_head_sha) is None
                or current["pr_url"] != prepared_pr_url
                or current["head_sha"] != prepared_head_sha
                or replacement_checked_at <= prepared_checked_at
            ):
                raise LedgerError("replacement PR follow-up changed")
            terminal = connection.execute(
                """SELECT 1 FROM events
                   WHERE opportunity_key=? AND id>?
                     AND (
                       (event_type IN ('PR_FOLLOWUP_SENT','PR_FOLLOWUP_RESULT_INGESTED',
                                       'PR_FOLLOWUP_RESERVATION_REPAIRED')
                        AND dedupe_key=?)
                       OR
                       (event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                        AND json_extract(payload_json,'$.wakeDigest')=?)
                     ) LIMIT 1""",
                (key, reserved["id"], wake_digest, wake_digest),
            ).fetchone()
            if terminal is not None:
                raise LedgerError("superseded PR follow-up reservation is already terminal")
            authority_row = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=? AND event_type='TASK_CONTEXT_AUTHORITY_BOUND'
                     AND json_extract(payload_json,'$.taskId')=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, task_id, thread_id),
            ).fetchone()
            if authority_row is None:
                raise LedgerError("superseded PR follow-up context authority is missing")
            try:
                authority = json.loads(authority_row["payload_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError("superseded PR follow-up context authority is invalid") from exc
            authority_state = {
                field: authority.get(field)
                for field in (
                    "taskId",
                    "threadId",
                    "contextDigest",
                    "hasContinuation",
                    "continuationDedupeKey",
                    "probeReceiptDigest",
                    "tombstoneReceiptDigest",
                    "implementationClaimed",
                )
            }
            continuation_ref = str(authority_state["continuationDedupeKey"] or "")
            tombstone_digest = str(authority_state["tombstoneReceiptDigest"] or "")
            if (
                authority_state["taskId"] != task_id
                or authority_state["threadId"] != thread_id
                or authority_state["contextDigest"] != context_digest
                or authority_state["hasContinuation"] is not True
                or re.fullmatch(r"[0-9a-f]{64}", continuation_ref) is None
                or re.fullmatch(r"[0-9a-f]{64}", tombstone_digest) is None
                or authority.get("authorityStateDigest") != sha256_json(authority_state)
            ):
                raise LedgerError("superseded PR follow-up context authority is invalid")
            continuation_row = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.taskId')=?
                     AND json_extract(payload_json,'$.threadId')=?
                     AND json_extract(payload_json,'$.contextDigest')=?
                     AND json_extract(payload_json,'$.followupWakeDigest')=?
                   LIMIT 1""",
                (key, continuation_ref, task_id, thread_id, context_digest, wake_digest),
            ).fetchone()
            if continuation_row is None:
                raise LedgerError("superseded PR follow-up continuation is missing")
            continuation = json.loads(continuation_row["payload_json"])
            continuation_tombstone = continuation.get("codePathTombstoneReceipt")
            if (
                not isinstance(continuation_tombstone, dict)
                or sha256_json(continuation_tombstone) != tombstone_digest
            ):
                raise LedgerError("superseded PR follow-up continuation is invalid")
            cleared = clear_quarantine_exact(
                connection,
                opportunity_key=key,
                reason="PR_FOLLOWUP_REBIND_REQUIRED",
                dedupe_key=quarantine_dedupe_key,
                evidence=evidence,
                cleared_at=now,
            )
            if cleared != 1:
                raise LedgerError("superseded PR follow-up quarantine was not cleared")
            self._event(
                connection,
                key,
                "TASK_QUARANTINE_CLEARED",
                sha256_text(
                    f"{key}|PR_FOLLOWUP_REBIND_REQUIRED|{quarantine_dedupe_key}|"
                    f"{quarantine_payload_digest}|{canonical_json(evidence)}"
                ),
                {
                    "reason": "PR_FOLLOWUP_REBIND_REQUIRED",
                    "dedupeKey": quarantine_dedupe_key,
                    "payloadDigest": quarantine_payload_digest,
                    **evidence,
                },
                now,
            )
            context_cleared = clear_quarantine_exact(
                connection,
                opportunity_key=key,
                reason="SHARED_CONTEXT_INVALID",
                dedupe_key=context_quarantine_dedupe_key,
                evidence=evidence,
                cleared_at=now,
            )
            if context_cleared != 1:
                raise LedgerError("superseded PR follow-up context quarantine was not cleared")
            self._event(
                connection,
                key,
                "TASK_QUARANTINE_CLEARED",
                sha256_text(
                    f"{key}|SHARED_CONTEXT_INVALID|{context_quarantine_dedupe_key}|"
                    f"{context_quarantine_payload_digest}|{canonical_json(evidence)}"
                ),
                {
                    "reason": "SHARED_CONTEXT_INVALID",
                    "dedupeKey": context_quarantine_dedupe_key,
                    "payloadDigest": context_quarantine_payload_digest,
                    **evidence,
                },
                now,
            )
            if active_quarantine(connection, opportunity_key=key) is None:
                connection.execute(
                    """UPDATE publication_requests
                       SET status='PENDING',reason='TASK_QUARANTINE_CLEARED',updated_at=?
                       WHERE opportunity_key=? AND status='BLOCKED'
                         AND reason='BLOCKED_REPRODUCTION_REQUIRED'""",
                    (now, key),
                )
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{wake_digest}|{reserved['created_at']}"),
                {
                    "threadId": thread_id,
                    "wakeDigest": wake_digest,
                    "reservedAt": reserved["created_at"],
                    "reason": "SUPERSEDED_BY_NEWER_FOLLOWUP",
                    "replacementWakeDigest": replacement_wake_digest,
                    "recoveredFromTaskContext": True,
                },
                now,
            )
            revoked_state = {
                "taskId": task_id,
                "threadId": thread_id,
                "contextDigest": context_digest,
                "hasContinuation": False,
                "continuationDedupeKey": None,
                "probeReceiptDigest": authority_state["probeReceiptDigest"],
                "tombstoneReceiptDigest": None,
                "implementationClaimed": False,
            }
            revoked_marker = revoked_state | {
                "authorityObservedAt": now,
                "authorityStateDigest": sha256_json(revoked_state),
                "authorityTransition": True,
                "revokedContinuationDedupeKey": continuation_ref,
                "revokedTombstoneReceiptDigest": tombstone_digest,
                "revocationObservedAt": now,
                "replacementWakeDigest": replacement_wake_digest,
            }
            self._event(
                connection,
                key,
                "TASK_CONTEXT_AUTHORITY_BOUND",
                sha256_json(revoked_marker),
                revoked_marker,
                now,
            )

    def record_shared_context_quarantine(
        self,
        *,
        key: str,
        reason: str,
        dedupe_key: str,
        payload: dict[str, Any],
        created_at: str,
    ) -> dict[str, Any]:
        with opportunity_action_guard(ledger_action_guard_root(self.path), key):
            return self._record_shared_context_quarantine(
                key=key,
                reason=reason,
                dedupe_key=dedupe_key,
                payload=payload,
                created_at=created_at,
            )

    def _record_shared_context_quarantine(
        self,
        *,
        key: str,
        reason: str,
        dedupe_key: str,
        payload: dict[str, Any],
        created_at: str,
    ) -> dict[str, Any]:
        """Persist a context quarantine and audit event in one transaction."""

        with self.transaction() as connection:
            ensure_quarantine_schema(connection)
            rows = connection.execute(
                """SELECT dedupe_key,status FROM task_quarantines
                   WHERE opportunity_key=? AND reason=?
                     AND (dedupe_key=? OR dedupe_key LIKE ? OR dedupe_key LIKE ?)""",
                (key, reason, dedupe_key, f"{dedupe_key}|reobserved", f"{dedupe_key}|generation=%"),
            ).fetchall()
            active = next((row for row in rows if row["status"] == "ACTIVE"), None)
            if active is not None:
                effective_key = str(active["dedupe_key"])
            else:
                generation = 0
                for row in rows:
                    value = str(row["dedupe_key"])
                    if value == dedupe_key:
                        generation = max(generation, 1)
                    elif value == f"{dedupe_key}|reobserved":
                        generation = max(generation, 2)
                    elif value.startswith(f"{dedupe_key}|generation="):
                        try:
                            generation = max(generation, int(value.rsplit("=", 1)[1]))
                        except ValueError as exc:
                            raise LedgerError("task quarantine generation is invalid") from exc
                effective_key = (
                    dedupe_key if generation == 0 else f"{dedupe_key}|generation={generation + 1}"
                )
            row = record_quarantine(
                connection,
                opportunity_key=key,
                reason=reason,
                dedupe_key=effective_key,
                payload=payload,
                created_at=created_at,
            )
            # A recovery ledger can intentionally be empty. The quarantine
            # row remains the authoritative audit/gate in that case; an event
            # is added when the corresponding opportunity exists so the
            # legacy event stream stays useful without violating its FK.
            if (
                connection.execute("SELECT 1 FROM opportunities WHERE key=?", (key,)).fetchone()
                is not None
            ):
                self._event(
                    connection,
                    key,
                    "SHARED_TASK_CONTEXT_QUARANTINED",
                    effective_key,
                    {"reason": reason, **payload},
                    created_at,
                )
            return {"created": bool(row.get("created")), "dedupeKey": effective_key}

    def clear_task_quarantine(self, key: str, *, reason: str, evidence: dict[str, Any]) -> None:
        """Clear a task quarantine only after a fresh controller rebind succeeds."""

        if not reason or not isinstance(evidence, dict):
            raise LedgerError("task quarantine clear evidence is incomplete")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            cleared = clear_quarantine(
                connection,
                opportunity_key=key,
                reason=reason,
                evidence=evidence,
                cleared_at=now,
            )
            if cleared == 0:
                return
            # A quarantine blocks existing requests before the result is
            # ingested.  Revalidation deliberately reopens them as PENDING;
            # any prior GRANTED authorization must be reacquired.
            connection.execute(
                """UPDATE publication_requests
                   SET status='PENDING',reason='TASK_QUARANTINE_CLEARED',updated_at=?
                   WHERE opportunity_key=? AND status='BLOCKED'
                     AND reason='BLOCKED_REPRODUCTION_REQUIRED'""",
                (now, key),
            )
            self._event(
                connection,
                key,
                "TASK_QUARANTINE_CLEARED",
                sha256_text(f"{key}|{reason}|{canonical_json(evidence)}"),
                {"reason": reason, **evidence},
                now,
            )

    def bind_task_quarantine_artifact(
        self, key: str, *, reason: str, artifact: dict[str, Any]
    ) -> None:
        """Persist a recovery directory binding in the shared quarantine row."""

        with self.transaction() as connection:
            attach_quarantine_artifact(
                connection,
                opportunity_key=key,
                reason=reason,
                artifact=artifact,
            )

    def defer_publication_request(
        self,
        request_id: str,
        reason: str,
        *,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request not found")
            connection.execute(
                """UPDATE publication_requests SET status='PENDING',reason=?,updated_at=?
                   WHERE request_id=? AND status='PENDING'""",
                (reason, now, request_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "PUBLICATION_DEFERRED",
                f"{request_id}:{reason}:{sha256_json(evidence or {})}",
                {
                    "requestId": request_id,
                    "reason": reason,
                    "auditEvidence": evidence or {},
                },
                now,
            )

    def block_publication_request(
        self,
        request_id: str,
        reason: str,
        *,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key,request_json,status
                   FROM publication_requests WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request not found")
            if _publication_has_irreversible_terminal_evidence(
                connection,
                request_id=request_id,
                opportunity_key=str(row["opportunity_key"]),
            ):
                connection.execute(
                    """UPDATE publication_requests
                       SET status='CONSUMED',reason=NULL,updated_at=?
                       WHERE request_id=?
                         AND (status<>'CONSUMED' OR reason IS NOT NULL)""",
                    (now, request_id),
                )
                self._event(
                    connection,
                    row["opportunity_key"],
                    "PUBLICATION_BLOCK_IGNORED_TERMINAL",
                    f"{request_id}:{reason}",
                    {
                        "requestId": request_id,
                        "reason": reason,
                        "auditEvidence": evidence or {},
                    },
                    now,
                )
                return
            connection.execute(
                """UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=?
                   WHERE request_id=?""",
                (reason, now, request_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "PUBLICATION_BLOCKED",
                f"{request_id}:{reason}",
                {
                    "requestId": request_id,
                    "reason": reason,
                    "auditEvidence": evidence or {},
                },
                now,
            )
            # Blocking is a safe contraction.  Do not let its optional PR
            # update rearm reactivate work while the task is quarantined.
            if active_quarantine(connection, opportunity_key=str(row["opportunity_key"])) is None:
                self._rearm_followup_for_publication_drift(
                    connection,
                    request_id=request_id,
                    key=row["opportunity_key"],
                    request_json=row["request_json"],
                    reason=reason,
                    now=now,
                )

    def rearm_pr_followup_after_publication_drift(self, request_id: str, *, reason: str) -> None:
        if reason not in PR_UPDATE_REARM_REASONS:
            raise ValueError("unsupported PR update rearm reason")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key,request_json FROM publication_requests
                   WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request not found")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                operation="publication follow-up rearm",
            )
            connection.execute(
                """UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=?
                   WHERE request_id=?""",
                (reason, now, request_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "PUBLICATION_BLOCKED",
                f"{request_id}:{reason}",
                {"requestId": request_id, "reason": reason},
                now,
            )
            if not self._rearm_followup_for_publication_drift(
                connection,
                request_id=request_id,
                key=row["opportunity_key"],
                request_json=row["request_json"],
                reason=reason,
                now=now,
            ):
                raise LedgerError("publication request is not an existing PR update")

    def rearm_pr_followup_after_task_drift(
        self,
        key: str,
        *,
        expected_prepared_head_sha: str,
        observed_head_sha: str,
        reason: str = "PR_FOLLOWUP_REBIND_REQUIRED",
    ) -> dict[str, Any]:
        """Rebind one stale follow-up while holding its opportunity guard."""

        with opportunity_action_guard(ledger_action_guard_root(self.path), key):
            return self._rearm_pr_followup_after_task_drift_unlocked(
                key,
                expected_prepared_head_sha=expected_prepared_head_sha,
                observed_head_sha=observed_head_sha,
                reason=reason,
            )

    def _rearm_pr_followup_after_task_drift_unlocked(
        self,
        key: str,
        *,
        expected_prepared_head_sha: str,
        observed_head_sha: str,
        reason: str = "PR_FOLLOWUP_REBIND_REQUIRED",
    ) -> dict[str, Any]:
        """Rebind one stale prepared follow-up without changing the PR parent."""

        if not re.fullmatch(r"[0-9a-f]{40}", expected_prepared_head_sha):
            raise LedgerError("PR follow-up expected prepared head is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", observed_head_sha):
            raise LedgerError("PR follow-up observed head is invalid")
        if not reason or len(reason) > 120:
            raise LedgerError("PR follow-up rebind reason is invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT wake_digest,followup_required FROM pr_followups WHERE opportunity_key=?",
                (key,),
            ).fetchone()
            if row is None or int(row["followup_required"] or 0) != 1:
                raise LedgerError("PR follow-up is not rebindable")
            previous_wake = str(row["wake_digest"] or "")
            existing = connection.execute(
                """SELECT payload_json,dedupe_key FROM events
                   WHERE opportunity_key=? AND event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                   ORDER BY id DESC LIMIT 1""",
                (key,),
            ).fetchone()
            if existing is not None:
                payload = json.loads(existing["payload_json"])
                if (
                    payload.get("expectedPreparedHeadSha") == expected_prepared_head_sha
                    and payload.get("observedHeadSha") == observed_head_sha
                    and payload.get("replacementWakeDigest") == previous_wake
                ):
                    return {
                        "key": key,
                        "previousWakeDigest": str(payload["previousWakeDigest"]),
                        "replacementWakeDigest": previous_wake,
                        "created": False,
                    }
            replacement_wake = sha256_json(
                {
                    "operation": "pr-followup-rebind-v1",
                    "previousWakeDigest": previous_wake,
                    "expectedPreparedHeadSha": expected_prepared_head_sha,
                    "observedHeadSha": observed_head_sha,
                    "reason": reason,
                }
            )
            payload = {
                "previousWakeDigest": previous_wake,
                "replacementWakeDigest": replacement_wake,
                "expectedPreparedHeadSha": expected_prepared_head_sha,
                "observedHeadSha": observed_head_sha,
                "reason": reason,
            }
            record_quarantine(
                connection,
                opportunity_key=key,
                reason=reason,
                dedupe_key=sha256_text(canonical_json(payload)),
                payload=payload,
                created_at=now,
            )
            connection.execute(
                """UPDATE pr_followups SET wake_digest=?,updated_at=?
                   WHERE opportunity_key=? AND wake_digest=? AND followup_required=1""",
                (replacement_wake, now, key, previous_wake),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                raise LedgerError("PR follow-up changed during rebind")
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_REBIND_REQUIRED",
                replacement_wake,
                payload,
                now,
            )
        return {
            "key": key,
            "previousWakeDigest": previous_wake,
            "replacementWakeDigest": replacement_wake,
            "created": True,
        }

    def _rearm_followup_for_publication_drift(
        self,
        connection: sqlite3.Connection,
        *,
        request_id: str,
        key: str,
        request_json: str,
        reason: str,
        now: str,
    ) -> bool:
        if reason not in PR_UPDATE_REARM_REASONS:
            return False
        try:
            request = json.loads(request_json)
        except json.JSONDecodeError:
            return False
        if request.get("publicationKind") != "PR_UPDATE":
            return False
        connection.execute(
            """UPDATE publication_permits SET status='EXPIRED',updated_at=?
               WHERE request_id=? AND status='ACTIVE'""",
            (now, request_id),
        )
        connection.execute(
            """UPDATE opportunities SET stage='PR_OPEN',terminal_reason=NULL,updated_at=?
               WHERE key=? AND stage='FIX_READY'""",
            (now, key),
        )
        connection.execute(
            """UPDATE pr_followups SET followup_required=0,updated_at=?
               WHERE opportunity_key=?""",
            (now, key),
        )
        active_reservations = connection.execute(
            """SELECT r.dedupe_key FROM events r
               WHERE r.opportunity_key=?
                 AND r.event_type='PR_FOLLOWUP_RESERVED'
                 AND NOT EXISTS (
                   SELECT 1 FROM events finished
                   WHERE finished.opportunity_key=r.opportunity_key
                     AND finished.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                     AND finished.dedupe_key=r.dedupe_key
                 )""",
            (key,),
        ).fetchall()
        for reservation in active_reservations:
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESULT_INGESTED",
                reservation["dedupe_key"],
                {"requestId": request_id, "stage": "REARMED"},
                now,
            )
        self._event(
            connection,
            key,
            "PR_FOLLOWUP_REARM_REQUIRED",
            request_id,
            {"requestId": request_id, "reason": reason},
            now,
        )
        return True

    def retry_blocked_publication_request(
        self, request_id: str, *, expected_reason: str
    ) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT opportunity_key,status,reason FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request not found")
            if row["status"] != "BLOCKED":
                raise LedgerError("publication request is not blocked")
            if row["reason"] != expected_reason:
                raise LedgerError("publication block reason changed")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                operation="publication request retry",
            )
            connection.execute(
                """UPDATE publication_requests SET status='PENDING',reason=NULL,updated_at=?
                   WHERE request_id=?""",
                (now, request_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "PUBLICATION_RETRY_REQUESTED",
                f"{request_id}:{expected_reason}:{now}",
                {"requestId": request_id, "previousReason": expected_reason},
                now,
            )
        return {"requestId": request_id, "status": "PENDING"}

    def grant_publication_request(
        self,
        request_id: str,
        *,
        issue_url: str,
        commit_sha: str,
        branch: str,
        evidence: dict[str, Any],
        ttl_minutes: int = 10,
    ) -> dict[str, Any]:
        current = datetime.now(UTC)
        now = iso_z(current)
        expires_at = iso_z(current + timedelta(minutes=max(1, min(ttl_minutes, 15))))
        with self.transaction() as connection:
            request = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if request is None or request["status"] not in {"PENDING", "GRANTED"}:
                raise LedgerError("publication request is not grantable")
            require_quarantine_clear(
                connection,
                opportunity_key=str(request["opportunity_key"]),
                operation="publication grant",
            )
            request_payload = json.loads(request["request_json"])
            if not _publication_probe_valid(request_payload, evidence):
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", now, request_id),
                )
                connection.commit()
                raise LedgerError("current-key REPRODUCED_VALIDATED receipt is required")
            existing = connection.execute(
                "SELECT * FROM publication_permits WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if (
                existing
                and existing["status"] == "ACTIVE"
                and parse_time(existing["expires_at"]) > current
            ):
                return dict(existing)
            if existing:
                unresolved = connection.execute(
                    """SELECT COUNT(*) FROM publication_effects
                       WHERE permit_id=? AND status<>'SUCCEEDED'""",
                    (existing["permit_id"],),
                ).fetchone()[0]
                if unresolved:
                    raise LedgerError("publication effect requires reconciliation")
                permit_id = existing["permit_id"]
                connection.execute(
                    """UPDATE publication_permits SET status='ACTIVE',expires_at=?,
                       evidence_json=?,updated_at=? WHERE permit_id=?""",
                    (expires_at, canonical_json(evidence), now, permit_id),
                )
            else:
                permit_id = secrets.token_hex(24)
                connection.execute(
                    """INSERT INTO publication_permits
                       (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                        evidence_json,created_at,updated_at)
                       VALUES (?,?,?,?,?,'ACTIVE',?,?,?,?)""",
                    (
                        permit_id,
                        request_id,
                        issue_url,
                        commit_sha,
                        branch,
                        expires_at,
                        canonical_json(evidence),
                        now,
                        now,
                    ),
                )
            connection.execute(
                """UPDATE publication_requests SET status='GRANTED',reason=NULL,
                   permit_id=?,updated_at=? WHERE request_id=?""",
                (permit_id, now, request_id),
            )
            self._event(
                connection,
                request["opportunity_key"],
                "PUBLICATION_AUTHORIZED",
                f"{permit_id}:{expires_at}",
                {"requestId": request_id, "permitId": permit_id, "expiresAt": expires_at},
                now,
            )
            return {
                "permit_id": permit_id,
                "request_id": request_id,
                "issue_url": issue_url,
                "commit_sha": commit_sha,
                "branch": branch,
                "status": "ACTIVE",
                "expires_at": expires_at,
            }

    def publication_permit(
        self, *, issue_url: str, commit_sha: str, branch: str
    ) -> dict[str, Any] | None:
        current = datetime.now(UTC)
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT * FROM publication_permits
                   WHERE issue_url=? AND commit_sha=? AND branch=?
                   ORDER BY created_at DESC LIMIT 1""",
                (issue_url, commit_sha, branch),
            ).fetchone()
            if row is None:
                return None
            request_row = connection.execute(
                "SELECT opportunity_key,request_json FROM publication_requests WHERE request_id=?",
                (row["request_id"],),
            ).fetchone()
            if request_row is not None:
                require_quarantine_clear(
                    connection,
                    opportunity_key=str(request_row["opportunity_key"]),
                    operation="publication permit",
                )
            if request_row is None or not _publication_authorization_is_current_or_terminal(
                connection,
                request_id=str(row["request_id"]),
                opportunity_key=str(request_row["opportunity_key"]),
                request_json=str(request_row["request_json"]),
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (iso_z(current), row["permit_id"]),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", iso_z(current), row["request_id"]),
                )
                return None
            if row["status"] == "ACTIVE" and parse_time(row["expires_at"]) <= current:
                connection.execute(
                    "UPDATE publication_permits SET status='EXPIRED',updated_at=? WHERE permit_id=?",
                    (iso_z(current), row["permit_id"]),
                )
                return None
            return dict(row) if row["status"] == "ACTIVE" else None

    def publication_permit_by_id(self, permit_id: str) -> dict[str, Any] | None:
        current = datetime.now(UTC)
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if row is None:
                return None
            request_row = connection.execute(
                "SELECT opportunity_key,request_json FROM publication_requests WHERE request_id=?",
                (row["request_id"],),
            ).fetchone()
            if request_row is not None:
                require_quarantine_clear(
                    connection,
                    opportunity_key=str(request_row["opportunity_key"]),
                    operation="publication permit",
                )
            if request_row is None or not _publication_authorization_is_current_or_terminal(
                connection,
                request_id=str(row["request_id"]),
                opportunity_key=str(request_row["opportunity_key"]),
                request_json=str(request_row["request_json"]),
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (iso_z(current), permit_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", iso_z(current), row["request_id"]),
                )
                return None
            if row["status"] == "ACTIVE" and parse_time(row["expires_at"]) <= current:
                connection.execute(
                    "UPDATE publication_permits SET status='EXPIRED',updated_at=? WHERE permit_id=?",
                    (iso_z(current), permit_id),
                )
                return None
            return dict(row) if row["status"] == "ACTIVE" else None

    def publication_permit_for_effect(
        self, permit_id: str, *, action: str
    ) -> dict[str, Any] | None:
        """Return a non-active permit only for an existing recoverable effect."""
        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            permit = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if permit is None:
                return None
            request_row = connection.execute(
                "SELECT opportunity_key,request_json FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request_row is not None:
                require_quarantine_clear(
                    connection,
                    opportunity_key=str(request_row["opportunity_key"]),
                    operation="publication effect permit",
                )
            if request_row is None or not _publication_authorization_is_current_or_terminal(
                connection,
                request_id=str(permit["request_id"]),
                opportunity_key=str(request_row["opportunity_key"]),
                request_json=str(request_row["request_json"]),
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (now, permit_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", now, permit["request_id"]),
                )
                return None
            if permit["status"] == "ACTIVE" and parse_time(permit["expires_at"]) <= current:
                connection.execute(
                    "UPDATE publication_permits SET status='EXPIRED',updated_at=? WHERE permit_id=?",
                    (now, permit_id),
                )
                permit = connection.execute(
                    "SELECT * FROM publication_permits WHERE permit_id=?", (permit_id,)
                ).fetchone()
            if permit["status"] not in {"ACTIVE", "EXPIRED", "CONSUMED"}:
                return None
            effect = connection.execute(
                """SELECT status FROM publication_effects
                   WHERE permit_id=? AND action=?
                     AND status IN ('RECONCILE_REQUIRED','SUCCEEDED')
                   ORDER BY updated_at DESC LIMIT 1""",
                (permit_id, action),
            ).fetchone()
            if effect is None:
                return None
            if permit["status"] == "CONSUMED" and effect["status"] != "SUCCEEDED":
                return None
            return dict(permit)

    def publication_effect_by_request(
        self, *, permit_id: str, action: str, request_digest: str
    ) -> dict[str, Any] | None:
        effect_id = sha256_text(f"{permit_id}|{action}|{request_digest}")
        with self.connect() as connection:
            authorization = connection.execute(
                """SELECT p.request_id,r.opportunity_key,r.request_json
                   FROM publication_permits p
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE p.permit_id=?""",
                (permit_id,),
            ).fetchone()
            if authorization is None or not _publication_authorization_is_current_or_terminal(
                connection,
                request_id=str(authorization["request_id"]),
                opportunity_key=str(authorization["opportunity_key"]),
                request_json=str(authorization["request_json"]),
            ):
                return None
            row = connection.execute(
                "SELECT * FROM publication_effects WHERE effect_id=?", (effect_id,)
            ).fetchone()
        return dict(row) if row else None

    def publication_effect(
        self,
        *,
        permit_id: str,
        action: str,
        request_digest: str,
    ) -> dict[str, Any]:
        effect_id = sha256_text(f"{permit_id}|{action}|{request_digest}")
        now = iso_z(datetime.now(UTC))
        blocked = False
        with self.transaction() as connection:
            authorization = connection.execute(
                """SELECT p.request_id,r.opportunity_key,r.request_json
                   FROM publication_permits p
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE p.permit_id=?""",
                (permit_id,),
            ).fetchone()
            terminal = bool(
                authorization is not None
                and _publication_has_irreversible_terminal_evidence(
                    connection,
                    request_id=str(authorization["request_id"]),
                    opportunity_key=str(authorization["opportunity_key"]),
                )
            )
            existing = connection.execute(
                "SELECT * FROM publication_effects WHERE effect_id=?", (effect_id,)
            ).fetchone()
            if terminal:
                if existing is not None:
                    return dict(existing) | {"created": False}
                raise LedgerError("publication effect cannot be created after terminal publication")
            if authorization is None or not _publication_probe_valid_json(
                authorization["request_json"]
            ):
                if authorization is not None:
                    connection.execute(
                        "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                        (now, permit_id),
                    )
                    connection.execute(
                        "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                        ("BLOCKED_REPRODUCTION_REQUIRED", now, authorization["request_id"]),
                    )
                blocked = True
            else:
                request = connection.execute(
                    "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
                    (authorization["request_id"],),
                ).fetchone()
                if request is None:
                    blocked = True
                else:
                    require_quarantine_clear(
                        connection,
                        opportunity_key=str(request["opportunity_key"]),
                        operation="publication effect",
                    )
            if not blocked:
                if existing:
                    return dict(existing) | {"created": False}
                connection.execute(
                    """INSERT INTO publication_effects
                       (effect_id,permit_id,action,request_digest,status,result_json,
                        created_at,updated_at)
                       VALUES (?,?,?,?,'ATTEMPTED','{}',?,?)""",
                    (effect_id, permit_id, action, request_digest, now, now),
                )
                return {
                    "effect_id": effect_id,
                    "permit_id": permit_id,
                    "action": action,
                    "request_digest": request_digest,
                    "status": "ATTEMPTED",
                    "result_json": "{}",
                    "created": True,
                }
        if blocked:
            raise LedgerError("publication effect blocked: authenticated reproduction is required")
        raise LedgerError("publication effect could not be created")

    def resolve_publication_preflight(
        self,
        effect_id: str,
        *,
        disposition: str,
        reason: str,
    ) -> None:
        """Resolve a live recheck before any external publication action ran."""

        if disposition not in {"DEFER", "BLOCK"}:
            raise LedgerError("invalid publication preflight disposition")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT e.*,p.request_id,r.opportunity_key
                   FROM publication_effects e
                   JOIN publication_permits p ON p.permit_id=e.permit_id
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE e.effect_id=?""",
                (effect_id,),
            ).fetchone()
            if row is None or row["status"] != "ATTEMPTED":
                raise LedgerError("publication preflight effect is not active")
            connection.execute(
                "DELETE FROM publication_effects WHERE effect_id=?",
                (effect_id,),
            )
            connection.execute(
                """UPDATE publication_permits SET status='EXPIRED',updated_at=?
                   WHERE permit_id=? AND status='ACTIVE'""",
                (now, row["permit_id"]),
            )
            request_status = "PENDING" if disposition == "DEFER" else "BLOCKED"
            connection.execute(
                """UPDATE publication_requests SET status=?,reason=?,updated_at=?
                   WHERE request_id=?""",
                (request_status, reason, now, row["request_id"]),
            )
            self._event(
                connection,
                row["opportunity_key"],
                f"PUBLICATION_PREFLIGHT_{disposition}",
                f"{effect_id}:{reason}",
                {
                    "requestId": row["request_id"],
                    "effectId": effect_id,
                    "action": row["action"],
                    "reason": reason,
                },
                now,
            )

    def recover_failed_publication_preflight(
        self,
        request_id: str,
        *,
        action: str,
        transient_reasons: set[str],
    ) -> bool:
        """Repair legacy live-recheck deferrals that were recorded as failures."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT e.*,p.request_id,r.opportunity_key
                   FROM publication_effects e
                   JOIN publication_permits p ON p.permit_id=e.permit_id
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE p.request_id=? AND e.action=? AND e.status='FAILED'
                   ORDER BY e.updated_at DESC LIMIT 1""",
                (request_id, action),
            ).fetchone()
            if row is None:
                return False
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                operation="publication preflight recovery",
            )
            try:
                failure = json.loads(row["result_json"])
            except json.JSONDecodeError:
                return False
            detail = str(failure.get("detail") or "")
            if failure.get("reason") != "LIVE_RECHECK_FAILED" or detail not in transient_reasons:
                return False
            connection.execute(
                "DELETE FROM publication_effects WHERE effect_id=?",
                (row["effect_id"],),
            )
            connection.execute(
                """UPDATE publication_permits SET status='EXPIRED',updated_at=?
                   WHERE permit_id=?""",
                (now, row["permit_id"]),
            )
            connection.execute(
                """UPDATE publication_requests SET status='PENDING',reason=?,updated_at=?
                   WHERE request_id=?""",
                (detail, now, request_id),
            )
            self._event(
                connection,
                row["opportunity_key"],
                "PUBLICATION_PREFLIGHT_RECOVERED",
                row["effect_id"],
                {
                    "requestId": request_id,
                    "effectId": row["effect_id"],
                    "action": action,
                    "reason": detail,
                },
                now,
            )
            return True

    def prepare_ambiguous_publication_effect(
        self,
        request_id: str,
        *,
        action: str,
        min_age_minutes: int = 5,
    ) -> dict[str, Any] | None:
        """Expose an interrupted effect only after its writer has gone stale."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT p.*,e.effect_id,e.action AS effect_action,
                          e.status AS effect_status,e.created_at AS effect_created_at,
                          e.updated_at AS effect_updated_at,
                          e.result_json AS effect_result_json
                   FROM publication_permits p
                   JOIN publication_effects e ON e.permit_id=p.permit_id
                   WHERE p.request_id=? AND e.action=?
                     AND e.status IN ('ATTEMPTED','RECONCILE_REQUIRED')
                   ORDER BY e.updated_at DESC LIMIT 1""",
                (request_id, action),
            ).fetchone()
            if row is None:
                return None
            request_row = connection.execute(
                "SELECT opportunity_key,request_json FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if request_row is None:
                return None
            if request_row is None or not _publication_probe_valid_json(
                request_row["request_json"]
            ):
                connection.execute(
                    "UPDATE publication_effects SET status='BLOCKED',result_json=?,updated_at=? WHERE effect_id=?",
                    (
                        canonical_json({"ok": False, "reason": "BLOCKED_REPRODUCTION_REQUIRED"}),
                        now,
                        row["effect_id"],
                    ),
                )
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (now, row["permit_id"]),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", now, request_id),
                )
                return None
            require_quarantine_clear(
                connection,
                opportunity_key=str(request_row["opportunity_key"]),
                operation="ambiguous publication effect recovery",
            )
            age = current - parse_time(row["effect_updated_at"])
            if row["effect_status"] == "ATTEMPTED" and age < timedelta(
                minutes=max(1, min_age_minutes)
            ):
                return {
                    "pending": True,
                    "action": action,
                    "effectId": row["effect_id"],
                    "ageMinutes": max(0, int(age.total_seconds() // 60)),
                }
            if row["effect_status"] == "ATTEMPTED":
                connection.execute(
                    """UPDATE publication_effects
                       SET status='RECONCILE_REQUIRED',result_json=?,updated_at=?
                       WHERE effect_id=? AND status='ATTEMPTED'""",
                    (
                        canonical_json(
                            {
                                "ok": False,
                                "reason": "INTERRUPTED_EFFECT_STALE",
                                "previousResult": json.loads(row["effect_result_json"]),
                            }
                        ),
                        now,
                        row["effect_id"],
                    ),
                )
                self._event(
                    connection,
                    connection.execute(
                        "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
                        (request_id,),
                    ).fetchone()["opportunity_key"],
                    "PUBLICATION_EFFECT_RECONCILIATION_REQUIRED",
                    row["effect_id"],
                    {
                        "requestId": request_id,
                        "effectId": row["effect_id"],
                        "action": action,
                    },
                    now,
                )
            permit = {key: row[key] for key in row.keys() if not key.startswith("effect_")}
            return {
                "pending": False,
                "action": action,
                "effectId": row["effect_id"],
                "permit": permit,
            }

    def retry_publication_effect_after_noop(
        self,
        *,
        effect_id: str,
        permit_id: str,
        evidence: dict[str, Any],
        ttl_minutes: int = 10,
    ) -> dict[str, Any]:
        """Reauthorize an exact idempotent effect after live state proves no effect."""

        current = datetime.now(UTC)
        now = iso_z(current)
        expires_at = iso_z(current + timedelta(minutes=max(1, min(ttl_minutes, 15))))
        with self.transaction() as connection:
            effect = connection.execute(
                "SELECT * FROM publication_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            permit = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?",
                (permit_id,),
            ).fetchone()
            if effect is None or permit is None or effect["permit_id"] != permit_id:
                raise LedgerError("publication retry binding mismatch")
            request_row = connection.execute(
                "SELECT opportunity_key,request_json FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request_row is None:
                raise LedgerError("publication request is missing")
            require_quarantine_clear(
                connection,
                opportunity_key=str(request_row["opportunity_key"]),
                operation="publication effect retry",
            )
            if request_row is None or not _publication_probe_valid_json(
                request_row["request_json"], evidence
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (now, permit_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", now, permit["request_id"]),
                )
                connection.commit()
                raise LedgerError(
                    "publication retry blocked: authenticated reproduction is required"
                )
            if effect["status"] != "RECONCILE_REQUIRED":
                raise LedgerError("publication effect is not awaiting reconciliation")
            if effect["action"] not in {"push", "create_pr"}:
                raise LedgerError("publication effect is not safely retryable")
            if permit["status"] not in {"ACTIVE", "EXPIRED"}:
                raise LedgerError("publication permit is not retryable")
            connection.execute(
                """UPDATE publication_permits
                   SET status='ACTIVE',expires_at=?,updated_at=? WHERE permit_id=?""",
                (expires_at, now, permit_id),
            )
            connection.execute(
                """UPDATE publication_effects
                   SET status='ATTEMPTED',result_json=?,updated_at=? WHERE effect_id=?""",
                (
                    canonical_json(
                        {
                            "ok": False,
                            "reason": "RETRY_AFTER_CONFIRMED_NO_EFFECT",
                            "evidence": evidence,
                        }
                    ),
                    now,
                    effect_id,
                ),
            )
            connection.execute(
                """UPDATE publication_requests
                   SET status='GRANTED',reason='RETRY_AFTER_CONFIRMED_NO_EFFECT',updated_at=?
                   WHERE request_id=?""",
                (now, permit["request_id"]),
            )
            self._event(
                connection,
                connection.execute(
                    "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
                    (permit["request_id"],),
                ).fetchone()["opportunity_key"],
                "PUBLICATION_EFFECT_RETRY_AUTHORIZED",
                sha256_json({"effectId": effect_id, "authorizedAt": now}),
                {"effectId": effect_id, "permitId": permit_id, "evidence": evidence},
                now,
            )
            refreshed = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?",
                (permit_id,),
            ).fetchone()
        return dict(refreshed)

    def publication_action_succeeded(self, request_id: str, *, action: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM publication_permits p
                   JOIN publication_effects e ON e.permit_id=p.permit_id
                   WHERE p.request_id=? AND e.action=? AND e.status='SUCCEEDED'
                   LIMIT 1""",
                (request_id, action),
            ).fetchone()
        return row is not None

    def prepare_post_push_reconciliation(self, request_id: str) -> dict[str, Any] | None:
        """Resume exact-PR confirmation after its branch update already succeeded."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            request_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if request_row is None or request_row["status"] == "CONSUMED":
                return None
            require_quarantine_clear(
                connection,
                opportunity_key=str(request_row["opportunity_key"]),
                operation="post-push publication reconciliation",
            )
            try:
                request = json.loads(request_row["request_json"])
            except json.JSONDecodeError:
                return None
            publication_kind = request.get("publicationKind")
            if publication_kind not in {"PR_CREATE", "PR_UPDATE"}:
                return None
            permit = connection.execute(
                """SELECT * FROM publication_permits WHERE request_id=?
                   ORDER BY updated_at DESC LIMIT 1""",
                (request_id,),
            ).fetchone()
            if permit is None:
                return None
            pushed = connection.execute(
                """SELECT 1 FROM publication_effects
                   WHERE permit_id=? AND action='push' AND status='SUCCEEDED'
                   LIMIT 1""",
                (permit["permit_id"],),
            ).fetchone()
            if pushed is None:
                return None
            confirmation = connection.execute(
                """SELECT * FROM publication_effects
                   WHERE permit_id=? AND action='create_pr'
                   ORDER BY updated_at DESC LIMIT 1""",
                (permit["permit_id"],),
            ).fetchone()
            if publication_kind == "PR_CREATE" and (
                confirmation is None or confirmation["status"] != "RECONCILE_REQUIRED"
            ):
                return None
            if confirmation is not None and confirmation["status"] == "FAILED":
                try:
                    failure = json.loads(confirmation["result_json"])
                except json.JSONDecodeError:
                    return None
                if not (
                    failure.get("reason") == "LIVE_RECHECK_FAILED"
                    and failure.get("detail") == "EXISTING_PR_HEAD_DRIFT"
                ):
                    return None
                connection.execute(
                    """UPDATE publication_effects SET status='RECONCILE_REQUIRED',updated_at=?
                       WHERE effect_id=?""",
                    (now, confirmation["effect_id"]),
                )
            elif confirmation is not None and confirmation["status"] not in {
                "ATTEMPTED",
                "RECONCILE_REQUIRED",
            }:
                return None
            if confirmation is not None and confirmation["status"] == "ATTEMPTED":
                connection.execute(
                    """UPDATE publication_effects SET status='RECONCILE_REQUIRED',updated_at=?
                       WHERE effect_id=?""",
                    (now, confirmation["effect_id"]),
                )
            if confirmation is None or publication_kind == "PR_CREATE":
                expires_at = iso_z(current + timedelta(minutes=10))
                connection.execute(
                    """UPDATE publication_permits SET status='ACTIVE',expires_at=?,updated_at=?
                       WHERE permit_id=?""",
                    (expires_at, now, permit["permit_id"]),
                )
            connection.execute(
                """UPDATE publication_requests SET status='GRANTED',reason=?,updated_at=?
                   WHERE request_id=?""",
                ("POST_PUSH_RECONCILIATION", now, request_id),
            )
            self._event(
                connection,
                request_row["opportunity_key"],
                "POST_PUSH_RECONCILIATION",
                request_id,
                {"requestId": request_id},
                now,
            )
            refreshed = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?",
                (permit["permit_id"],),
            ).fetchone()
        return dict(refreshed) if refreshed else None

    def tracked_pull_requests(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT * FROM (
                     SELECT o.key,o.repo,o.issue_url,o.stage,p.pr_url,p.permit_id,
                            p.updated_at,r.commit_sha,r.branch,i.thread_id,i.worktree_path,
                            ROW_NUMBER() OVER (
                              PARTITION BY p.pr_url ORDER BY p.updated_at DESC
                            ) AS latest_rank
                     FROM opportunities o
                     JOIN intents i ON i.intent_id=(
                       SELECT i2.intent_id FROM intents i2
                       WHERE i2.opportunity_key=o.key
                         AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                       ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                     )
                     JOIN publication_requests r ON r.opportunity_key=o.key
                     JOIN publication_permits p ON p.request_id=r.request_id
                     WHERE p.pr_url IS NOT NULL AND (
                       p.status='CONSUMED' OR
                       (p.status='BLOCKED' AND r.reason='BLOCKED_REPRODUCTION_REQUIRED'
                        AND json_extract(r.request_json,'$.recoveredFromTaskContext')=1)
                     )
                       AND o.stage NOT IN ('MERGED','CLOSED')
                   ) WHERE latest_rank=1 ORDER BY updated_at"""
            ).fetchall()
        return [
            {key: value for key, value in dict(row).items() if key != "latest_rank"} for row in rows
        ]

    def import_pr_followups(self, state: dict[str, Any]) -> dict[str, int]:
        if state.get("version") != "pr_followup_v3" or not isinstance(state.get("items"), list):
            raise LedgerError("unsupported PR follow-up state")
        now = iso_z(datetime.now(UTC))
        inserted = 0
        updated = 0
        matched = 0
        stale_head_suppressed = 0
        with self.transaction() as connection:
            tracked = {
                str(row["pr_url"]): {
                    "key": str(row["opportunity_key"]),
                    "commitSha": str(row["commit_sha"]),
                    "consumedAt": str(row["consumed_at"]),
                }
                for row in connection.execute(
                    """SELECT pr_url,opportunity_key,commit_sha,consumed_at FROM (
                         SELECT p.pr_url,r.opportunity_key,r.commit_sha,
                                p.updated_at AS consumed_at,
                                ROW_NUMBER() OVER (
                                  PARTITION BY p.pr_url
                                  ORDER BY p.updated_at DESC,r.updated_at DESC,
                                           r.created_at DESC,r.request_id DESC
                                ) AS latest_rank
                         FROM publication_requests r
                         JOIN publication_permits p ON p.request_id=r.request_id
                         WHERE p.pr_url IS NOT NULL AND (
                           p.status='CONSUMED' OR
                           (p.status='BLOCKED' AND r.reason='BLOCKED_REPRODUCTION_REQUIRED'
                            AND json_extract(r.request_json,'$.recoveredFromTaskContext')=1)
                         )
                       ) WHERE latest_rank=1"""
                ).fetchall()
            }
            for item in state["items"]:
                if not isinstance(item, dict):
                    continue
                pr_url = str(item.get("url") or "")
                binding = tracked.get(pr_url)
                if not binding or not PR_URL_RE.fullmatch(pr_url):
                    continue
                key = binding["key"]
                matched += 1
                head_sha = str(item.get("headSha") or "")
                action_digest = str(item.get("actionDigest") or "")
                task_digest = str(item.get("taskActionDigest") or "")
                checked_at = str(item.get("checkedAt") or state.get("generatedAt") or now)
                if not head_sha or not action_digest or not task_digest:
                    raise LedgerError("PR follow-up item is incomplete")
                actions = item.get("taskActions") or []
                evidence = item.get("evidence") or {}
                if not isinstance(actions, list) or not isinstance(evidence, dict):
                    raise LedgerError("PR follow-up evidence is invalid")
                try:
                    checked_time = parse_time(checked_at)
                    consumed_time = parse_time(binding["consumedAt"])
                except (TypeError, ValueError) as exc:
                    raise LedgerError("PR follow-up timestamps are invalid") from exc
                if head_sha != binding["commitSha"] and checked_time <= consumed_time:
                    retired = connection.execute(
                        """UPDATE pr_followups
                           SET followup_required=0,wake_digest=NULL,updated_at=?
                           WHERE opportunity_key=?
                             AND (followup_required<>0 OR wake_digest IS NOT NULL)""",
                        (now, key),
                    )
                    updated += retired.rowcount
                    stale_head_suppressed += 1
                    self._event(
                        connection,
                        key,
                        "PR_FOLLOWUP_STALE_HEAD_SUPPRESSED",
                        sha256_text(
                            f"{pr_url}|{head_sha}|{binding['commitSha']}|{binding['consumedAt']}"
                        ),
                        {
                            "prUrl": pr_url,
                            "staleHeadSha": head_sha,
                            "currentCommitSha": binding["commitSha"],
                            "checkedAt": checked_at,
                            "consumedAt": binding["consumedAt"],
                        },
                        now,
                    )
                    continue
                required = item.get("taskFollowupRequired") is True
                previous = connection.execute(
                    "SELECT * FROM pr_followups WHERE opportunity_key=?", (key,)
                ).fetchone()
                preserved_resolution_scope = False
                if required and previous is not None:
                    authorized_wake_completed = connection.execute(
                        """SELECT 1 FROM events
                           WHERE opportunity_key=?
                             AND event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND dedupe_key=? LIMIT 1""",
                        (key, str(previous["wake_digest"] or "")),
                    ).fetchone()
                    authorized_wake_reserved = connection.execute(
                        """SELECT 1 FROM events
                           WHERE opportunity_key=?
                             AND event_type='PR_FOLLOWUP_RESERVED'
                             AND dedupe_key=? LIMIT 1""",
                        (key, str(previous["wake_digest"] or "")),
                    ).fetchone()
                    previous_evidence = json.loads(previous["evidence_json"])
                    previous_receipt = (
                        previous_evidence.get("mergeResolutionScopeReceipt")
                        if isinstance(previous_evidence, dict)
                        else None
                    )
                    previous_authorized = (
                        previous_evidence.get("authorizedResolutionFiles")
                        if isinstance(previous_evidence, dict)
                        else None
                    )
                    incoming_conflicts = evidence.get("mergeConflictFiles")
                    previous_conflicts = (
                        previous_evidence.get("mergeConflictFiles")
                        if isinstance(previous_evidence, dict)
                        else None
                    )
                    conflicts = (
                        previous_conflicts
                        if evidence.get("mergeConflict") is True
                        and "mergeConflictFiles" not in evidence
                        else incoming_conflicts
                    )
                    identity = connection.execute(
                        """SELECT o.issue_url,i.intent_id,i.thread_id,i.worktree_path
                           FROM opportunities o JOIN intents i ON i.intent_id=(
                             SELECT i2.intent_id FROM intents i2
                             WHERE i2.opportunity_key=o.key
                               AND i2.thread_id IS NOT NULL
                               AND i2.worktree_path IS NOT NULL
                             ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                           )
                           WHERE o.key=?""",
                        (key,),
                    ).fetchone()
                    if (
                        isinstance(previous_evidence, dict)
                        and isinstance(previous_receipt, dict)
                        and isinstance(previous_authorized, list)
                        and isinstance(conflicts, list)
                        and identity is not None
                        and authorized_wake_completed is None
                        and (
                            authorized_wake_reserved is None
                            or previous["task_action_digest"] == task_digest
                        )
                        and previous["pr_url"] == pr_url
                        and previous["head_sha"] == head_sha
                        and previous_evidence.get("baseSha") == evidence.get("baseSha")
                        and previous_evidence.get("mergeConflictFiles") == conflicts
                        and verify_merge_resolution_scope_receipt(
                            previous_receipt,
                            key=key,
                            issue_url=str(identity["issue_url"]),
                            intent_id=str(identity["intent_id"]),
                            thread_id=str(identity["thread_id"]),
                            worktree_path_fingerprint=sha256_text(
                                str(Path(str(identity["worktree_path"])).resolve())
                            ),
                            pr_url=pr_url,
                            current_wake_digest=str(previous["wake_digest"] or ""),
                            head_sha=head_sha,
                            prepared_head_sha=str(previous_receipt.get("preparedHeadSha") or ""),
                            base_sha=str(evidence.get("baseSha") or ""),
                            merge_conflict_files=conflicts,
                            authorized_resolution_files=previous_authorized,
                        )
                    ):
                        evidence = dict(evidence) | {
                            "mergeConflictFiles": list(conflicts),
                            "authorizedResolutionFiles": list(previous_authorized),
                            "mergeResolutionScopeReceipt": previous_receipt,
                            "resolutionScopeSourceWakeDigest": previous_evidence.get(
                                "resolutionScopeSourceWakeDigest"
                            ),
                            "resolutionScopeRequestResultDigest": previous_evidence.get(
                                "resolutionScopeRequestResultDigest"
                            ),
                        }
                        preserved_resolution_scope = True
                deferred = connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='PR_FOLLOWUP_SNAPSHOT_DEFERRED'
                       ORDER BY id DESC LIMIT 1""",
                    (key,),
                ).fetchone()
                deferred_checked_at = None
                if deferred is not None:
                    deferred_payload = json.loads(deferred["payload_json"])
                    deferred_checked_at = str(deferred_payload.get("checkedAt") or "")
                suppress_deferred_snapshot = bool(
                    required
                    and deferred_checked_at
                    and checked_time <= parse_time(deferred_checked_at)
                )
                if suppress_deferred_snapshot:
                    required = False
                if required and preserved_resolution_scope:
                    wake_digest = previous["wake_digest"]
                elif required and (
                    previous is None
                    or not bool(previous["followup_required"])
                    or previous["task_action_digest"] != task_digest
                ):
                    wake_digest = sha256_text(
                        f"{key}|{pr_url}|{head_sha}|{task_digest}|{checked_at}|"
                        f"{str(previous['wake_digest'] or '') if previous else ''}"
                    )
                elif required and previous is not None:
                    wake_digest = previous["wake_digest"]
                else:
                    wake_digest = None
                connection.execute(
                    """INSERT INTO pr_followups
                       (opportunity_key,pr_url,head_sha,action_digest,task_action_digest,
                        wake_digest,actions_json,evidence_json,followup_required,checked_at,
                        updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(opportunity_key) DO UPDATE SET
                         pr_url=excluded.pr_url,head_sha=excluded.head_sha,
                         action_digest=excluded.action_digest,
                         task_action_digest=excluded.task_action_digest,
                         wake_digest=excluded.wake_digest,actions_json=excluded.actions_json,
                         evidence_json=excluded.evidence_json,
                         followup_required=excluded.followup_required,
                         checked_at=excluded.checked_at,updated_at=excluded.updated_at""",
                    (
                        key,
                        pr_url,
                        head_sha,
                        action_digest,
                        task_digest,
                        wake_digest,
                        canonical_json(actions),
                        canonical_json(evidence),
                        int(required),
                        checked_at,
                        now,
                    ),
                )
                inserted += int(previous is None)
                updated += int(previous is not None)
        return {
            "matched": matched,
            "inserted": inserted,
            "updated": updated,
            "staleHeadSuppressed": stale_head_suppressed,
        }

    def suspend_pr_followups(self, *, source_generated_at: str, reason: str) -> list[str]:
        """Stop task wakes when their verified cloud snapshot is too old."""

        if not source_generated_at or not reason:
            raise LedgerError("PR follow-up suspension evidence is incomplete")
        parse_time(source_generated_at)
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT opportunity_key FROM pr_followups
                   WHERE followup_required=1
                   ORDER BY opportunity_key"""
            ).fetchall()
            keys = [str(row["opportunity_key"]) for row in rows]
            if not keys:
                return []
            connection.execute(
                """UPDATE pr_followups
                   SET followup_required=0,updated_at=?
                   WHERE followup_required=1""",
                (now,),
            )
            for key in keys:
                self._event(
                    connection,
                    key,
                    "PR_FOLLOWUP_SOURCE_STALE",
                    sha256_text(f"{source_generated_at}|{reason}"),
                    {
                        "sourceGeneratedAt": source_generated_at,
                        "reason": reason,
                    },
                    now,
                )
        return keys

    @staticmethod
    def _pr_followup_candidate_rows(
        connection: sqlite3.Connection,
        *,
        thread_id: str | None = None,
        wake_digest: str | None = None,
    ) -> list[sqlite3.Row]:
        filters: list[str] = []
        params: list[str] = []
        if thread_id is not None:
            filters.append("AND i.thread_id=?")
            params.append(thread_id)
        if wake_digest is not None:
            filters.append("AND f.wake_digest=?")
            params.append(wake_digest)
        extra_filters = "\n                     ".join(filters)
        query = f"""SELECT f.*,o.key,o.repo,o.issue_url,o.stage,i.intent_id,
                          i.thread_id,i.worktree_path,
                          r.branch
                   FROM pr_followups f
                   JOIN opportunities o ON o.key=f.opportunity_key
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN publication_requests r ON r.opportunity_key=o.key
                   JOIN publication_permits p ON p.request_id=r.request_id
                   WHERE f.followup_required=1 AND f.wake_digest IS NOT NULL
                     AND o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND p.pr_url=f.pr_url AND (
                       p.status='CONSUMED' OR
                       (p.status='BLOCKED' AND r.reason='BLOCKED_REPRODUCTION_REQUIRED'
                        AND json_extract(r.request_json,'$.recoveredFromTaskContext')=1)
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM publication_requests update_request
                       WHERE update_request.opportunity_key=o.key
                         AND update_request.status IN ('PENDING','GRANTED','BLOCKED')
                         AND json_extract(
                           update_request.request_json,'$.publicationKind'
                         )='PR_UPDATE'
                         AND update_request.commit_sha<>f.head_sha
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                         AND (
                           quarantine.reason<>'PR_FOLLOWUP_REBIND_REQUIRED'
                           OR (
                             COALESCE(
                               json_extract(
                                 quarantine.payload_json,'$.replacementWakeDigest'
                               ),
                               ''
                             )<>f.wake_digest
                             AND NOT (
                               COALESCE(
                                 json_extract(
                                   quarantine.payload_json,'$.reservationPending'
                                 ),
                                 0
                               )=1
                               AND COALESCE(
                                 json_extract(quarantine.payload_json,'$.wakeDigest'),
                                 ''
                               )=f.wake_digest
                             )
                           )
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events e WHERE e.opportunity_key=o.key
                         AND e.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND e.dedupe_key=f.wake_digest
                     )
                       AND NOT EXISTS (
                       SELECT 1 FROM events active
                       WHERE active.opportunity_key=o.key
                         AND active.event_type='PR_FOLLOWUP_RESERVED'
                         AND EXISTS (
                           SELECT 1 FROM events completed
                           WHERE completed.opportunity_key=active.opportunity_key
                             AND completed.event_type='PR_FOLLOWUP_RESERVATION_REPAIRED'
                             AND completed.dedupe_key=active.dedupe_key
                             AND completed.id>active.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events rebound
                           WHERE rebound.opportunity_key=active.opportunity_key
                             AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                             AND rebound.id>active.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events finished
                           WHERE finished.opportunity_key=active.opportunity_key
                             AND finished.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND finished.dedupe_key=active.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=active.opportunity_key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 active.dedupe_key
                             AND abandoned.id>active.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events repair
                             WHERE repair.opportunity_key=active.opportunity_key
                               AND repair.event_type='PR_FOLLOWUP_RESERVATION_REPAIR_REQUIRED'
                             AND repair.dedupe_key=active.dedupe_key
                             AND repair.id>active.id
                             AND NOT EXISTS (
                               SELECT 1 FROM events repaired
                               WHERE repaired.opportunity_key=repair.opportunity_key
                                 AND repaired.event_type='PR_FOLLOWUP_RESERVATION_REPAIRED'
                                 AND repaired.dedupe_key=repair.dedupe_key
                                 AND repaired.id>repair.id
                               )
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='PR_FOLLOWUP_SENT'
                         AND sent.dedupe_key=f.wake_digest
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events pending
                       WHERE pending.opportunity_key=o.key
                         AND pending.event_type='PR_FOLLOWUP_RESERVED'
                         AND pending.dedupe_key<>f.wake_digest
                         AND NOT EXISTS (
                           SELECT 1 FROM events completed
                           WHERE completed.opportunity_key=pending.opportunity_key
                             AND completed.event_type='PR_FOLLOWUP_RESERVATION_REPAIRED'
                             AND completed.dedupe_key=pending.dedupe_key
                             AND completed.id>pending.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events finished
                           WHERE finished.opportunity_key=pending.opportunity_key
                             AND finished.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND finished.dedupe_key=pending.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=pending.opportunity_key
                             AND sent.event_type='PR_FOLLOWUP_SENT'
                             AND sent.dedupe_key=pending.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=pending.opportunity_key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 pending.dedupe_key
                             AND abandoned.id>pending.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events rebound
                           WHERE rebound.opportunity_key=pending.opportunity_key
                             AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                             AND rebound.id>pending.id
                         )
                     )
                     {extra_filters}
                   ORDER BY f.checked_at,r.updated_at DESC"""
        return list(connection.execute(query, tuple(params)).fetchall())

    @staticmethod
    def _materialize_pr_followup_candidates(
        rows: Iterable[sqlite3.Row],
    ) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for row in rows:
            key = str(row["key"])
            unique.setdefault(
                key,
                {
                    "key": key,
                    "repo": row["repo"],
                    "issueUrl": row["issue_url"],
                    "prUrl": row["pr_url"],
                    "headSha": row["head_sha"],
                    "actionDigest": row["action_digest"],
                    "taskActionDigest": row["task_action_digest"],
                    "wakeDigest": row["wake_digest"],
                    "actions": json.loads(row["actions_json"]),
                    "evidence": json.loads(row["evidence_json"]),
                    "checkedAt": row["checked_at"],
                    "threadId": row["thread_id"],
                    "intentId": row["intent_id"],
                    "worktreePath": row["worktree_path"],
                    "branch": row["branch"],
                },
            )
        return list(unique.values())

    def pr_followup_candidates(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = self._pr_followup_candidate_rows(connection)
        return self._materialize_pr_followup_candidates(rows)

    def pr_followup_rebind_status(self, key: str) -> dict[str, Any] | None:
        """Return the latest task-local rebind signal, if one exists."""

        with self.connect() as connection:
            ensure_quarantine_schema(connection)
            backfill_from_managed_events(
                connection, action_guard_root=ledger_action_guard_root(self.path)
            )
            quarantine = connection.execute(
                """SELECT * FROM task_quarantines
                   WHERE opportunity_key=? AND reason='PR_FOLLOWUP_REBIND_REQUIRED'
                   ORDER BY quarantine_id DESC LIMIT 1""",
                (key,),
            ).fetchone()
            if quarantine is not None:
                if quarantine["status"] == "ACTIVE":
                    return quarantine_payload(dict(quarantine)) | {
                        "createdAt": quarantine["created_at"]
                    }
                return None
            row = connection.execute(
                """SELECT payload_json,created_at FROM events
                   WHERE opportunity_key=? AND event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                   ORDER BY id DESC LIMIT 1""",
                (key,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        if not isinstance(payload, dict):
            raise LedgerError("PR follow-up rebind payload is invalid")
        return payload | {"createdAt": row["created_at"]}

    @staticmethod
    def _pr_followup_snapshot(
        candidate: dict[str, Any], *, prepared_head_sha: str
    ) -> dict[str, Any]:
        return {
            "prUrl": candidate["prUrl"],
            "headSha": candidate["headSha"],
            "preparedHeadSha": prepared_head_sha,
            "actionDigest": candidate["actionDigest"],
            "taskActionDigest": candidate["taskActionDigest"],
            "wakeDigest": candidate["wakeDigest"],
            "actions": candidate["actions"],
            "evidence": candidate["evidence"],
            "checkedAt": candidate["checkedAt"],
        }

    def historical_pr_followup_preparation(
        self,
        *,
        key: str,
        task_id: str,
        thread_id: str,
        wake_digest: str,
    ) -> dict[str, Any] | None:
        """Return one exact immutable preparation, including completed wakes."""

        if (
            not key
            or not task_id
            or not thread_id
            or re.fullmatch(r"[0-9a-f]{64}", wake_digest) is None
        ):
            raise ValueError("historical PR follow-up preparation identity is invalid")
        with self.connect() as connection:
            row = connection.execute(
                """SELECT e.payload_json,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path
                   FROM events e
                   JOIN opportunities o ON o.key=e.opportunity_key
                   JOIN intents i ON i.opportunity_key=e.opportunity_key
                    AND i.intent_id=? AND i.thread_id=?
                   WHERE e.opportunity_key=?
                     AND e.event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                     AND e.dedupe_key=?
                     AND json_extract(e.payload_json,'$.threadId')=?""",
                (task_id, thread_id, key, wake_digest, thread_id),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise LedgerError("historical PR follow-up preparation is invalid") from exc
        snapshot = payload.get("snapshot") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or payload.get("threadId") != thread_id
            or not isinstance(snapshot, dict)
            or snapshot.get("wakeDigest") != wake_digest
        ):
            raise LedgerError("historical PR follow-up preparation is invalid")
        return {
            "key": key,
            "issueUrl": row["issue_url"],
            "intentId": row["intent_id"],
            "threadId": row["thread_id"],
            "worktreePath": row["worktree_path"],
            "wakeDigest": wake_digest,
            "snapshot": snapshot,
        }

    def reserve_pr_followup(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        prepared_head_sha: str | None = None,
        prepared_base_sha: str | None = None,
        merge_conflict_files: list[str] | None = None,
        max_active: int | None = None,
        exclude_intent_id: str | None = None,
        quarantine_reason: str | None = None,
        quarantine_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if prepared_head_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", prepared_head_sha):
            raise LedgerError("PR follow-up prepared head is invalid")
        with self.transaction() as connection:
            candidates = self._materialize_pr_followup_candidates(
                self._pr_followup_candidate_rows(
                    connection, thread_id=thread_id, wake_digest=wake_digest
                )
            )
            candidate = next(iter(candidates), None)
            if candidate is None:
                raise LedgerError("PR follow-up authorization is stale or invalid")
            if exclude_intent_id is not None and exclude_intent_id != candidate["intentId"]:
                raise LedgerError("PR follow-up WIP exclusion does not match the task")
            snapshot_candidate = candidate
            if prepared_base_sha is not None:
                if not re.fullmatch(r"[0-9a-f]{40}", prepared_base_sha):
                    raise LedgerError("PR follow-up prepared base is invalid")
                evidence = dict(candidate["evidence"])
                original_base_sha = str(evidence.get("baseSha") or "")
                accepts_fast_forwarded_base = (
                    evidence.get("mergeConflict") is True
                    or evidence.get("baseIntegrationRequired") is True
                )
                if not accepts_fast_forwarded_base:
                    if prepared_base_sha != original_base_sha:
                        raise LedgerError("PR follow-up prepared base changed unexpectedly")
                elif prepared_base_sha != original_base_sha:
                    evidence["baseAdvancedFromSha"] = original_base_sha
                    evidence["baseSha"] = prepared_base_sha
                if merge_conflict_files is not None:
                    normalized = sorted(set(merge_conflict_files))
                    if not normalized or any(
                        not isinstance(path, str)
                        or not path
                        or Path(path).is_absolute()
                        or ".." in Path(path).parts
                        for path in normalized
                    ):
                        raise LedgerError("PR follow-up conflict files are invalid")
                    evidence["mergeConflictFiles"] = normalized
                snapshot_candidate = candidate | {"evidence": evidence}
            elif merge_conflict_files is not None:
                raise LedgerError("PR follow-up conflict files lack a prepared base")
            snapshot_evidence = snapshot_candidate.get("evidence")
            scope_receipt = (
                snapshot_evidence.get("mergeResolutionScopeReceipt")
                if isinstance(snapshot_evidence, dict)
                else None
            )
            authorized_resolution_files = (
                snapshot_evidence.get("authorizedResolutionFiles")
                if isinstance(snapshot_evidence, dict)
                else None
            )
            if scope_receipt is not None or authorized_resolution_files is not None:
                if (
                    prepared_head_sha is None
                    or not isinstance(snapshot_evidence, dict)
                    or not isinstance(scope_receipt, dict)
                    or not isinstance(authorized_resolution_files, list)
                    or not isinstance(snapshot_evidence.get("mergeConflictFiles"), list)
                    or not verify_merge_resolution_scope_receipt(
                        scope_receipt,
                        key=str(candidate["key"]),
                        issue_url=str(candidate["issueUrl"]),
                        intent_id=str(candidate["intentId"]),
                        thread_id=str(candidate["threadId"]),
                        worktree_path_fingerprint=sha256_text(
                            str(Path(str(candidate["worktreePath"])).resolve())
                        ),
                        pr_url=str(candidate["prUrl"]),
                        current_wake_digest=str(candidate["wakeDigest"]),
                        head_sha=str(candidate["headSha"]),
                        prepared_head_sha=prepared_head_sha,
                        base_sha=str(snapshot_evidence.get("baseSha") or ""),
                        merge_conflict_files=snapshot_evidence.get("mergeConflictFiles"),
                        authorized_resolution_files=authorized_resolution_files,
                    )
                ):
                    raise LedgerError("PR follow-up resolution scope authorization is stale")
            if quarantine_reason is None:
                require_quarantine_clear(
                    connection,
                    opportunity_key=str(candidate["key"]),
                    operation="PR follow-up reservation",
                )
            else:
                if quarantine_reason != "PR_FOLLOWUP_REBIND_REQUIRED":
                    raise LedgerError("PR follow-up quarantine revalidation reason is invalid")
                if active_quarantine(connection, opportunity_key=str(candidate["key"])) is None:
                    raise LedgerError("PR follow-up quarantine is not active for revalidation")
            existing = connection.execute(
                """SELECT 1 FROM events reserved
                   WHERE reserved.opportunity_key=?
                     AND reserved.event_type='PR_FOLLOWUP_RESERVED'
                     AND reserved.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events finished
                       WHERE finished.opportunity_key=reserved.opportunity_key
                         AND finished.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND finished.dedupe_key=reserved.dedupe_key
                     )""",
                (candidate["key"], wake_digest),
            ).fetchone()
            if existing:
                return snapshot_candidate
            if max_active is not None and self._active_task_count(
                connection,
                now=iso_z(datetime.now(UTC)),
                exclude_intent_id=exclude_intent_id,
            ) >= max(0, max_active):
                raise LedgerError("global task WIP limit reached")
            self._event(
                connection,
                candidate["key"],
                "PR_FOLLOWUP_RESERVED",
                wake_digest,
                {"threadId": thread_id, "prUrl": candidate["prUrl"]},
                iso_z(datetime.now(UTC)),
            )
            if prepared_head_sha is not None:
                self._event(
                    connection,
                    candidate["key"],
                    "PR_FOLLOWUP_PREPARATION_BOUND",
                    wake_digest,
                    {
                        "threadId": thread_id,
                        "snapshot": self._pr_followup_snapshot(
                            snapshot_candidate, prepared_head_sha=prepared_head_sha
                        ),
                    },
                    iso_z(datetime.now(UTC)),
                )
        return snapshot_candidate

    def mark_pr_followup_reservation_repair_required(
        self, *, thread_id: str, wake_digest: str, reason: str
    ) -> None:
        """Record a reservation repair while holding its opportunity guard."""

        with self.connect() as connection:
            row = connection.execute(
                """SELECT opportunity_key FROM events
                   WHERE event_type='PR_FOLLOWUP_RESERVED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (wake_digest, thread_id),
            ).fetchone()
        if row is None:
            raise LedgerError("PR follow-up reservation is unavailable for repair")
        key = str(row["opportunity_key"])
        with opportunity_action_guard(ledger_action_guard_root(self.path), key):
            self._mark_pr_followup_reservation_repair_required_unlocked(
                thread_id=thread_id, wake_digest=wake_digest, reason=reason
            )

    def _mark_pr_followup_reservation_repair_required_unlocked(
        self, *, thread_id: str, wake_digest: str, reason: str
    ) -> None:
        """Make a failed post-reservation handoff immediately retryable.

        The original reservation remains an immutable fact.  This event is the
        compensating state that lets the same wake digest be retried without
        creating a second reservation or releasing an unverified task.
        """

        if not reason:
            raise LedgerError("PR follow-up repair reason is required")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key FROM events
                   WHERE event_type='PR_FOLLOWUP_RESERVED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (wake_digest, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("PR follow-up reservation is unavailable for repair")
            record_quarantine(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                reason="PR_FOLLOWUP_REBIND_REQUIRED",
                dedupe_key=sha256_text(f"{row['opportunity_key']}|{wake_digest}|{reason}"),
                payload={
                    "threadId": thread_id,
                    "wakeDigest": wake_digest,
                    "reason": reason,
                    "reservationPending": True,
                },
                created_at=now,
            )
            self._event(
                connection,
                row["opportunity_key"],
                "PR_FOLLOWUP_RESERVATION_REPAIR_REQUIRED",
                wake_digest,
                {"threadId": thread_id, "wakeDigest": wake_digest, "reason": reason},
                now,
            )

    def complete_pr_followup_reservation(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        quarantine_reason: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        """Commit the filesystem handoff and quarantine clear as one DB step."""

        now = iso_z(datetime.now(UTC))
        evidence = dict(evidence or {})
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key FROM events
                   WHERE event_type='PR_FOLLOWUP_RESERVED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (wake_digest, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("PR follow-up reservation is missing")
            key = str(row["opportunity_key"])
            preparation = connection.execute(
                """SELECT 1 FROM events
                   WHERE opportunity_key=?
                     AND event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                     AND dedupe_key=?
                   LIMIT 1""",
                (key, wake_digest),
            ).fetchone()
            if preparation is None:
                raise LedgerError("PR follow-up preparation is not bound")
            if quarantine_reason:
                if quarantine_reason != "PR_FOLLOWUP_REBIND_REQUIRED":
                    raise LedgerError("PR follow-up quarantine clear reason is invalid")
                cleared = clear_quarantine(
                    connection,
                    opportunity_key=key,
                    reason=quarantine_reason,
                    evidence={"revalidated": True, **evidence},
                    cleared_at=now,
                )
                if cleared:
                    connection.execute(
                        """UPDATE publication_requests
                           SET status='PENDING',reason='TASK_QUARANTINE_CLEARED',updated_at=?
                           WHERE opportunity_key=? AND status='BLOCKED'
                             AND reason='BLOCKED_REPRODUCTION_REQUIRED'""",
                        (now, key),
                    )
                    self._event(
                        connection,
                        key,
                        "TASK_QUARANTINE_CLEARED",
                        sha256_text(f"{key}|{quarantine_reason}|{canonical_json(evidence)}"),
                        {"reason": quarantine_reason, **evidence},
                        now,
                    )
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESERVATION_REPAIRED",
                wake_digest,
                {"threadId": thread_id, "wakeDigest": wake_digest, **evidence},
                now,
            )

    def defer_pr_followup_snapshot(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        candidate = next(
            (
                item
                for item in self.pr_followup_candidates()
                if item["threadId"] == thread_id and item["wakeDigest"] == wake_digest
            ),
            None,
        )
        if candidate is None:
            raise LedgerError("PR follow-up deferral authorization is stale or invalid")
        if not reason:
            raise LedgerError("PR follow-up deferral reason is required")
        now = iso_z(datetime.now(UTC))
        payload = {
            "threadId": thread_id,
            "prUrl": candidate["prUrl"],
            "wakeDigest": wake_digest,
            "checkedAt": candidate["checkedAt"],
            "reason": reason,
            "evidence": evidence or {},
        }
        with self.transaction() as connection:
            updated = connection.execute(
                """UPDATE pr_followups
                   SET followup_required=0,wake_digest=NULL,updated_at=?
                   WHERE opportunity_key=? AND wake_digest=? AND followup_required=1""",
                (now, candidate["key"], wake_digest),
            )
            if updated.rowcount != 1:
                raise LedgerError("PR follow-up deferral authorization changed")
            self._event(
                connection,
                candidate["key"],
                "PR_FOLLOWUP_SNAPSHOT_DEFERRED",
                wake_digest,
                payload,
                now,
            )
        return candidate | payload

    def unbound_pr_followup_preparations(self) -> list[dict[str, Any]]:
        """Return sent follow-ups created before prepared snapshots were durable."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT f.*,o.key,o.issue_url,r.dedupe_key AS reserved_wake_digest,
                          json_extract(r.payload_json,'$.threadId') AS reserved_thread_id,
                          json_extract(r.payload_json,'$.prUrl') AS reserved_pr_url,
                          i.worktree_path,
                          (
                            SELECT request.commit_sha
                            FROM publication_requests request
                            JOIN publication_permits permit
                              ON permit.request_id=request.request_id
                            WHERE request.opportunity_key=o.key
                              AND permit.status='CONSUMED'
                              AND permit.pr_url=json_extract(r.payload_json,'$.prUrl')
                            ORDER BY permit.updated_at DESC LIMIT 1
                          ) AS published_head_sha
                   FROM events r
                   JOIN opportunities o ON o.key=r.opportunity_key
                   JOIN pr_followups f ON f.opportunity_key=o.key
                     AND f.pr_url=json_extract(r.payload_json,'$.prUrl')
                   JOIN intents i ON i.opportunity_key=o.key
                     AND i.thread_id=json_extract(r.payload_json,'$.threadId')
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND NOT EXISTS (
                       SELECT 1 FROM events b WHERE b.opportunity_key=o.key
                         AND b.event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                         AND b.dedupe_key=r.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events x WHERE x.opportunity_key=o.key
                         AND x.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND x.dedupe_key=r.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=o.key
                         AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rebound
                       WHERE rebound.opportunity_key=r.opportunity_key
                         AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                         AND rebound.id>r.id
                     )
                   ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "prUrl": row["reserved_pr_url"],
                "headSha": row["published_head_sha"],
                "wakeDigest": row["reserved_wake_digest"],
                "currentWakeDigest": row["wake_digest"],
                "actionDigest": row["action_digest"],
                "taskActionDigest": row["task_action_digest"],
                "actions": json.loads(row["actions_json"]),
                "evidence": json.loads(row["evidence_json"]),
                "checkedAt": row["checked_at"],
                "threadId": row["reserved_thread_id"],
                "worktreePath": row["worktree_path"],
            }
            for row in rows
        ]

    def bind_pr_followup_preparation(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        prepared_head_sha: str,
        prepared_base_sha: str | None = None,
        legacy_context_digest: str | None = None,
        legacy_wake_digest: str | None = None,
    ) -> dict[str, Any]:
        candidate = next(
            (
                item
                for item in self.unbound_pr_followup_preparations()
                if item["threadId"] == thread_id and item["wakeDigest"] == wake_digest
            ),
            None,
        )
        if candidate is None:
            raise LedgerError("PR follow-up preparation binding is stale or invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", prepared_head_sha):
            raise LedgerError("PR follow-up prepared head is invalid")
        if legacy_context_digest is not None and not re.fullmatch(
            r"[0-9a-f]{64}", legacy_context_digest
        ):
            raise LedgerError("legacy PR follow-up context digest is invalid")
        if legacy_wake_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", legacy_wake_digest):
            raise LedgerError("legacy PR follow-up wake digest is invalid")
        if (legacy_context_digest is None) != (legacy_wake_digest is None):
            raise LedgerError("legacy PR follow-up compatibility is incomplete")
        evidence = dict(candidate["evidence"])
        if prepared_base_sha is not None:
            if not re.fullmatch(r"[0-9a-f]{40}", prepared_base_sha):
                raise LedgerError("PR follow-up prepared base is invalid")
            if evidence.get("baseIntegrationRequired") is not True:
                raise LedgerError("PR follow-up prepared base is unexpected")
            evidence["baseSha"] = prepared_base_sha
        snapshot = self._pr_followup_snapshot(
            candidate | {"evidence": evidence}, prepared_head_sha=prepared_head_sha
        )
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "PR_FOLLOWUP_PREPARATION_BOUND",
                wake_digest,
                {
                    "threadId": thread_id,
                    "snapshot": snapshot,
                    "legacyRecovered": True,
                    "legacyCompatibility": (
                        {
                            "contextDigest": legacy_context_digest,
                            "wakeDigest": legacy_wake_digest,
                        }
                        if legacy_context_digest is not None
                        else None
                    ),
                },
                iso_z(datetime.now(UTC)),
            )
        return candidate | {"preparedHeadSha": prepared_head_sha}

    def active_pr_followup_preparation(
        self, key: str, *, thread_id: str | None = None
    ) -> dict[str, Any] | None:
        clauses = [
            "b.opportunity_key=?",
            "b.event_type='PR_FOLLOWUP_PREPARATION_BOUND'",
            "NOT EXISTS (SELECT 1 FROM events x WHERE "
            "x.opportunity_key=b.opportunity_key "
            "AND x.event_type='PR_FOLLOWUP_RESULT_INGESTED' "
            "AND x.dedupe_key=b.dedupe_key)",
            "NOT EXISTS (SELECT 1 FROM events abandoned WHERE "
            "abandoned.opportunity_key=b.opportunity_key "
            "AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED' "
            "AND json_extract(abandoned.payload_json,'$.wakeDigest')=b.dedupe_key "
            "AND abandoned.id>b.id)",
            "NOT EXISTS (SELECT 1 FROM events rebound WHERE "
            "rebound.opportunity_key=b.opportunity_key "
            "AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED' "
            "AND rebound.id>b.id)",
        ]
        params: list[Any] = [key]
        if thread_id is not None:
            clauses.append("json_extract(b.payload_json,'$.threadId')=?")
            params.append(thread_id)
        with self.connect() as connection:
            row = connection.execute(
                f"""SELECT b.payload_json FROM events b
                    WHERE {" AND ".join(clauses)}
                    ORDER BY b.id DESC LIMIT 1""",
                tuple(params),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        snapshot = payload.get("snapshot")
        if not isinstance(snapshot, dict):
            raise LedgerError("PR follow-up preparation snapshot is invalid")
        compatibility = payload.get("legacyCompatibility")
        return {
            "threadId": payload.get("threadId"),
            "snapshot": snapshot,
            "legacyCompatibility": compatibility if isinstance(compatibility, dict) else None,
        }

    def reconcile_superseded_pr_followups(self) -> list[dict[str, str]]:
        """Close legacy reservations that a later ingested follow-up superseded."""

        now = iso_z(datetime.now(UTC))
        reconciled: list[dict[str, str]] = []
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT r.opportunity_key AS key,r.dedupe_key AS wake_digest,
                          (SELECT later.dedupe_key FROM events later
                           WHERE later.opportunity_key=r.opportunity_key
                             AND later.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND later.id>r.id
                           ORDER BY later.id DESC LIMIT 1) AS superseded_by
                   FROM events r
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND NOT EXISTS (
                       SELECT 1 FROM events same
                       WHERE same.opportunity_key=r.opportunity_key
                         AND same.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND same.dedupe_key=r.dedupe_key
                     )
                     AND EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=r.opportunity_key
                         AND later.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND later.id>r.id
                     )
                   ORDER BY r.id"""
            ).fetchall()
            for row in rows:
                self._event(
                    connection,
                    row["key"],
                    "PR_FOLLOWUP_RESULT_INGESTED",
                    row["wake_digest"],
                    {"stage": "SUPERSEDED", "supersededBy": row["superseded_by"]},
                    now,
                )
                reconciled.append(
                    {
                        "key": row["key"],
                        "wakeDigest": row["wake_digest"],
                        "supersededBy": row["superseded_by"],
                    }
                )
        return reconciled

    def commit_pr_followup(self, *, thread_id: str, wake_digest: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT r.opportunity_key AS key,
                          json_extract(r.payload_json,'$.prUrl') AS pr_url
                   FROM events r
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND r.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events s WHERE s.opportunity_key=r.opportunity_key
                         AND s.event_type='PR_FOLLOWUP_SENT'
                         AND s.dedupe_key=r.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rebound
                       WHERE rebound.opportunity_key=r.opportunity_key
                         AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                         AND rebound.id>r.id
                     )""",
                (thread_id, wake_digest),
            ).fetchone()
            if row is None:
                sent = connection.execute(
                    """SELECT 1 FROM events r JOIN events s
                       ON s.opportunity_key=r.opportunity_key
                      AND s.event_type='PR_FOLLOWUP_SENT'
                      AND s.dedupe_key=r.dedupe_key
                       WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND r.dedupe_key=?
                       LIMIT 1""",
                    (thread_id, wake_digest),
                ).fetchone()
                if sent:
                    return
                raise LedgerError("PR follow-up reservation is missing or already committed")
            self._event(
                connection,
                row["key"],
                "PR_FOLLOWUP_SENT",
                wake_digest,
                {"threadId": thread_id, "prUrl": row["pr_url"]},
                now,
            )

    def abandon_pr_followup_delivery(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        reason: str,
        min_age_minutes: int = 90,
    ) -> dict[str, str]:
        """Retire an old reservation when no target task turn materialized."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT r.id,r.opportunity_key AS key,r.created_at
                   FROM events r
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND r.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='PR_FOLLOWUP_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events finished
                       WHERE finished.opportunity_key=r.opportunity_key
                         AND finished.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND finished.dedupe_key=r.dedupe_key
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC LIMIT 1""",
                (thread_id, wake_digest),
            ).fetchone()
            if row is None:
                raise LedgerError("PR follow-up delivery is not abandonable")
            minimum_age = timedelta(minutes=max(1, min_age_minutes))
            if parse_time(row["created_at"]) + minimum_age > current:
                raise LedgerError("PR follow-up delivery is not old enough to abandon")
            self._event(
                connection,
                row["key"],
                "PR_FOLLOWUP_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{wake_digest}|{row['created_at']}"),
                {
                    "threadId": thread_id,
                    "wakeDigest": wake_digest,
                    "reservedAt": row["created_at"],
                    "reason": reason,
                    "minimumAgeMinutes": max(1, min_age_minutes),
                },
                now,
            )
            replacement_wake_digest = sha256_json(
                {
                    "previousWakeDigest": wake_digest,
                    "reservedAt": row["created_at"],
                    "abandonedAt": now,
                    "operation": "pr-followup-delivery-retry-v1",
                }
            )
            connection.execute(
                """UPDATE pr_followups SET wake_digest=?,updated_at=?
                   WHERE opportunity_key=? AND wake_digest=? AND followup_required=1""",
                (replacement_wake_digest, now, row["key"], wake_digest),
            )
            return {"replacementWakeDigest": replacement_wake_digest}

    def unresolved_pr_followups(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT r.opportunity_key AS key,o.issue_url,i.worktree_path,
                          r.dedupe_key AS wake_digest,
                          r.payload_json,r.created_at
                   FROM events r
                   JOIN opportunities o ON o.key=r.opportunity_key
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key AND i2.thread_id IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND NOT EXISTS (
                     SELECT 1 FROM events s WHERE s.opportunity_key=r.opportunity_key
                       AND s.event_type='PR_FOLLOWUP_SENT'
                       AND s.dedupe_key=r.dedupe_key
                   )
                     AND NOT EXISTS (
                     SELECT 1 FROM events abandoned
                     WHERE abandoned.opportunity_key=r.opportunity_key
                       AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                       AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                       AND abandoned.id>r.id
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rebound
                       WHERE rebound.opportunity_key=r.opportunity_key
                         AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                         AND rebound.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events repair
                       WHERE repair.opportunity_key=r.opportunity_key
                         AND repair.event_type='PR_FOLLOWUP_RESERVATION_REPAIR_REQUIRED'
                         AND repair.dedupe_key=r.dedupe_key
                         AND repair.id>r.id
                         AND NOT EXISTS (
                           SELECT 1 FROM events repaired
                           WHERE repaired.opportunity_key=repair.opportunity_key
                             AND repaired.event_type='PR_FOLLOWUP_RESERVATION_REPAIRED'
                             AND repaired.dedupe_key=repair.dedupe_key
                             AND repaired.id>repair.id
                         )
                     ) ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issue_url": row["issue_url"],
                "worktree_path": row["worktree_path"],
                "thread_id": json.loads(row["payload_json"]).get("threadId"),
                "pr_url": json.loads(row["payload_json"]).get("prUrl"),
                "wake_digest": row["wake_digest"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def active_pr_followup(self, key: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT * FROM pr_followups
                   WHERE opportunity_key=? AND followup_required=1""",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return dict(row) | {
            "actions": json.loads(row["actions_json"]),
            "evidence": json.loads(row["evidence_json"]),
        }

    def task_result_digest_seen(self, key: str, digest: str) -> bool:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM events WHERE opportunity_key=? AND dedupe_key=?
                   AND event_type='TASK_RESULT_INGESTED' LIMIT 1""",
                (key, digest),
            ).fetchone()
        return row is not None

    def published_task_result_is_terminal(self, key: str, *, thread_id: str) -> bool:
        """Return whether a missing historical worktree no longer needs local ingestion."""

        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id=?
                       AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   WHERE o.key=?
                     AND i.status='COMPLETED'
                     AND o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED','MERGED','CLOSED')
                     AND EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type='TASK_RESULT_INGESTED'
                     )
                     AND (
                       EXISTS (
                         SELECT 1 FROM events opened
                         WHERE opened.opportunity_key=o.key
                           AND opened.event_type='PR_OPEN'
                       )
                       OR EXISTS (
                         SELECT 1 FROM publication_requests request
                         JOIN publication_permits permit ON permit.request_id=request.request_id
                         WHERE request.opportunity_key=o.key
                           AND permit.pr_url IS NOT NULL
                       )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM publication_requests request
                       WHERE request.opportunity_key=o.key
                         AND request.status IN ('PENDING','GRANTED')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='PR_FOLLOWUP_SENT'
                         AND NOT EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=o.key
                             AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND result.dedupe_key=sent.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 sent.dedupe_key
                             AND abandoned.id>sent.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='PR_FOLLOWUP_RESERVED'
                         AND NOT EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=o.key
                             AND sent.event_type='PR_FOLLOWUP_SENT'
                             AND sent.dedupe_key=reserved.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=o.key
                             AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND result.dedupe_key=reserved.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 reserved.dedupe_key
                             AND abandoned.id>reserved.id
                         )
                       )
                   LIMIT 1""",
                (thread_id, key),
            ).fetchone()
            if row is None:
                return False
            unresolved_validation = connection.execute(
                """SELECT 1
                   FROM events marker
                   WHERE marker.opportunity_key=?
                     AND marker.event_type IN (
                       'VALIDATION_FOLLOWUP_RESERVED',
                       'VALIDATION_FOLLOWUP_SENT'
                     )
                     AND json_extract(marker.payload_json,'$.threadId')=?
                     AND json_extract(marker.payload_json,'$.resultDigest') IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=marker.opportunity_key
                         AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND sent.dedupe_key=
                             json_extract(marker.payload_json,'$.resultDigest')
                         AND json_extract(sent.payload_json,'$.threadId')=
                             json_extract(marker.payload_json,'$.threadId')
                         AND sent.id>=CASE
                           WHEN marker.event_type='VALIDATION_FOLLOWUP_SENT'
                           THEN marker.id ELSE marker.id+1 END
                         AND EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=sent.opportunity_key
                             AND result.event_type='TASK_RESULT_INGESTED'
                             AND result.id>sent.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=marker.opportunity_key
                         AND cancelled.event_type=
                             'VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(marker.payload_json,'$.reservationDigest')
                         AND cancelled.id>marker.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=marker.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(marker.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.threadId')=
                             json_extract(marker.payload_json,'$.threadId')
                         AND (
                           marker.event_type='VALIDATION_FOLLOWUP_SENT'
                           OR json_extract(abandoned.payload_json,'$.reservedAt')=
                              marker.created_at
                         )
                         AND abandoned.id>marker.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events no_progress
                       WHERE no_progress.opportunity_key=marker.opportunity_key
                         AND no_progress.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                         AND no_progress.dedupe_key=
                             json_extract(marker.payload_json,'$.resultDigest')
                         AND json_extract(no_progress.payload_json,'$.threadId')=
                             json_extract(marker.payload_json,'$.threadId')
                         AND no_progress.id>marker.id
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=no_progress.opportunity_key
                             AND rearmed.event_type=
                                 'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                             AND json_extract(rearmed.payload_json,'$.resultDigest')=
                                 json_extract(marker.payload_json,'$.resultDigest')
                             AND json_extract(rearmed.payload_json,'$.threadId')=
                                 json_extract(marker.payload_json,'$.threadId')
                             AND rearmed.id>no_progress.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rearmed
                       WHERE rearmed.opportunity_key=marker.opportunity_key
                         AND rearmed.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                         AND json_extract(rearmed.payload_json,'$.resultDigest')=
                             json_extract(marker.payload_json,'$.resultDigest')
                         AND json_extract(rearmed.payload_json,'$.threadId')=
                             json_extract(marker.payload_json,'$.threadId')
                         AND rearmed.id>marker.id
                     )
                   LIMIT 1""",
                (key, thread_id),
            ).fetchone()
        return unresolved_validation is None

    def record_followup_result(
        self, key: str, *, wake_digest: str, result_digest: str, stage: str
    ) -> None:
        with self.transaction() as connection:
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESULT_INGESTED",
                wake_digest,
                {"resultDigest": result_digest, "stage": stage},
                iso_z(datetime.now(UTC)),
            )

    def authorize_pr_followup_resolution_scope(
        self,
        key: str,
        *,
        source_wake_digest: str,
        result_digest: str,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist one signed merge-resolution scope and rearm its follow-up."""

        if (
            not re.fullmatch(r"[0-9a-f]{64}", source_wake_digest)
            or not re.fullmatch(r"[0-9a-f]{64}", result_digest)
            or not isinstance(receipt, dict)
        ):
            raise LedgerError("PR follow-up resolution scope binding is invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            existing = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='PR_FOLLOWUP_RESOLUTION_SCOPE_AUTHORIZED'
                     AND dedupe_key=?""",
                (key, result_digest),
            ).fetchone()
            if existing is not None:
                payload = json.loads(existing["payload_json"])
                if not isinstance(payload, dict):
                    raise LedgerError("PR follow-up resolution scope event is invalid")
                return payload | {"created": False}

            row = connection.execute(
                """SELECT f.*,o.issue_url,i.intent_id,i.thread_id,i.worktree_path
                   FROM pr_followups f
                   JOIN opportunities o ON o.key=f.opportunity_key
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=f.opportunity_key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   WHERE f.opportunity_key=?""",
                (key,),
            ).fetchone()
            if row is None or row["wake_digest"] != source_wake_digest:
                raise LedgerError("PR follow-up resolution scope source wake is stale")
            evidence = json.loads(row["evidence_json"])
            if not isinstance(evidence, dict):
                raise LedgerError("PR follow-up resolution scope evidence is invalid")
            source_row = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC LIMIT 1""",
                (key, source_wake_digest, row["thread_id"]),
            ).fetchone()
            try:
                source_payload = (
                    json.loads(source_row["payload_json"]) if source_row is not None else None
                )
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError(
                    "PR follow-up resolution scope source snapshot is invalid"
                ) from exc
            source_snapshot = (
                source_payload.get("snapshot") if isinstance(source_payload, dict) else None
            )
            source_evidence = (
                source_snapshot.get("evidence") if isinstance(source_snapshot, dict) else None
            )
            conflicts = (
                source_evidence.get("mergeConflictFiles")
                if isinstance(source_evidence, dict)
                else None
            )
            source_base = (
                str(source_evidence.get("baseSha") or "")
                if isinstance(source_evidence, dict)
                else ""
            )
            authorized = receipt.get("authorizedResolutionFiles")
            replacement_wake = str(receipt.get("authorizedWakeDigest") or "")
            prepared_head = str(receipt.get("preparedHeadSha") or "")
            if (
                receipt.get("sourceWakeDigest") != source_wake_digest
                or receipt.get("requestResultDigest") != result_digest
                or not isinstance(source_snapshot, dict)
                or not isinstance(source_evidence, dict)
                or source_snapshot.get("wakeDigest") != source_wake_digest
                or source_snapshot.get("prUrl") != row["pr_url"]
                or source_snapshot.get("headSha") != row["head_sha"]
                or source_snapshot.get("preparedHeadSha") != prepared_head
                or source_snapshot.get("preparedHeadSha") != source_snapshot.get("headSha")
                or not str(source_snapshot.get("actionDigest") or "")
                or not str(source_snapshot.get("checkedAt") or "")
                or source_snapshot.get("taskActionDigest") != row["task_action_digest"]
                or source_evidence.get("mergeConflict") is not True
                or evidence.get("mergeConflict") is not True
                or str(evidence.get("baseSha") or "") != source_base
                or not isinstance(conflicts, list)
                or not isinstance(authorized, list)
                or not verify_merge_resolution_scope_receipt(
                    receipt,
                    key=key,
                    issue_url=str(row["issue_url"]),
                    intent_id=str(row["intent_id"]),
                    thread_id=str(row["thread_id"]),
                    worktree_path_fingerprint=sha256_text(
                        str(Path(str(row["worktree_path"])).resolve())
                    ),
                    pr_url=str(row["pr_url"]),
                    current_wake_digest=replacement_wake,
                    head_sha=str(row["head_sha"]),
                    prepared_head_sha=prepared_head,
                    base_sha=source_base,
                    merge_conflict_files=conflicts,
                    authorized_resolution_files=authorized,
                )
            ):
                raise LedgerError("PR follow-up resolution scope receipt is invalid")
            updated_evidence = dict(evidence)
            updated_evidence["mergeConflictFiles"] = list(conflicts)
            updated_evidence["authorizedResolutionFiles"] = list(authorized)
            updated_evidence["mergeResolutionScopeReceipt"] = receipt
            updated_evidence["resolutionScopeSourceWakeDigest"] = source_wake_digest
            updated_evidence["resolutionScopeRequestResultDigest"] = result_digest
            connection.execute(
                """UPDATE pr_followups
                   SET wake_digest=?,evidence_json=?,followup_required=1,updated_at=?
                   WHERE opportunity_key=? AND wake_digest=?""",
                (
                    replacement_wake,
                    canonical_json(updated_evidence),
                    now,
                    key,
                    source_wake_digest,
                ),
            )
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESULT_INGESTED",
                source_wake_digest,
                {"resultDigest": result_digest, "stage": "PR_OPEN"},
                now,
            )
            payload = {
                "sourceWakeDigest": source_wake_digest,
                "replacementWakeDigest": replacement_wake,
                "resultDigest": result_digest,
                "authorizedResolutionFiles": list(authorized),
                "receipt": receipt,
            }
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESOLUTION_SCOPE_AUTHORIZED",
                result_digest,
                payload,
                now,
            )
        return payload | {"created": True}

    def record_task_result_ingested(
        self,
        key: str,
        *,
        digest: str,
        stage: str,
        task_id: str | None = None,
        thread_id: str | None = None,
        followup_wake_digest: str | None = None,
        code_path_tombstone_receipt: dict[str, Any] | None = None,
        continuation_head_sha: str | None = None,
        pr_followup_snapshot: dict[str, Any] | None = None,
    ) -> None:
        tombstone_binding = (
            followup_wake_digest,
            code_path_tombstone_receipt,
            continuation_head_sha,
            pr_followup_snapshot,
        )
        if any(value is not None for value in tombstone_binding):
            if (
                not task_id
                or not thread_id
                or not re.fullmatch(r"[0-9a-f]{64}", str(followup_wake_digest or ""))
                or not isinstance(code_path_tombstone_receipt, dict)
                or not code_path_tombstone_receipt
                or not isinstance(pr_followup_snapshot, dict)
                or not pr_followup_snapshot
                or code_path_tombstone_receipt.get("wakeDigest") != followup_wake_digest
                or pr_followup_snapshot.get("wakeDigest") != followup_wake_digest
                or pr_followup_snapshot.get("prUrl") != code_path_tombstone_receipt.get("prUrl")
                or pr_followup_snapshot.get("actionDigest")
                != code_path_tombstone_receipt.get("actionDigest")
                or pr_followup_snapshot.get("taskActionDigest")
                != code_path_tombstone_receipt.get("taskActionDigest")
                or pr_followup_snapshot.get("checkedAt")
                != code_path_tombstone_receipt.get("checkedAt")
                or pr_followup_snapshot.get("preparedHeadSha")
                != code_path_tombstone_receipt.get("preparedHeadSha")
                or not re.fullmatch(r"[0-9a-f]{40}", str(continuation_head_sha or ""))
            ):
                raise ValueError("task result tombstone continuation is invalid")
        with self.transaction() as connection:
            recorded_at = iso_z(datetime.now(UTC))
            existing_result_row = connection.execute(
                """SELECT id FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                     AND dedupe_key=?""",
                (key, digest),
            ).fetchone()
            payload = {"stage": stage, "resultDigest": digest}
            if task_id:
                payload["taskId"] = task_id
            if thread_id:
                payload["threadId"] = thread_id
            if followup_wake_digest is not None:
                payload["followupWakeDigest"] = followup_wake_digest
                payload["codePathTombstoneReceipt"] = code_path_tombstone_receipt
                payload["continuationHeadSha"] = continuation_head_sha
            self._event(
                connection,
                key,
                "TASK_RESULT_INGESTED",
                digest,
                payload,
                recorded_at,
            )
            if followup_wake_digest is not None:
                exact_intent = connection.execute(
                    """SELECT 1 FROM intents
                       WHERE opportunity_key=? AND intent_id=? AND thread_id=?""",
                    (key, task_id, thread_id),
                ).fetchone()
                result_row = connection.execute(
                    """SELECT id,payload_json FROM events
                       WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                         AND dedupe_key=?""",
                    (key, digest),
                ).fetchone()
                if exact_intent is None or result_row is None:
                    raise ValueError("task result tombstone continuation identity is invalid")
                result_payload = json.loads(result_row["payload_json"])
                if not isinstance(result_payload, dict):
                    raise ValueError("task result tombstone continuation identity is invalid")
                existing_task_id = str(result_payload.get("taskId") or "")
                existing_thread_id = str(result_payload.get("threadId") or "")
                if (
                    (existing_task_id and existing_task_id != task_id)
                    or (existing_thread_id and existing_thread_id != thread_id)
                    or result_payload.get("resultDigest") != digest
                ):
                    raise ValueError("task result tombstone continuation identity is invalid")
                continuation_payload = {
                    "sourceResultEventId": int(result_row["id"]),
                    "taskId": task_id,
                    "threadId": thread_id,
                    "stage": stage,
                    "resultDigest": digest,
                    "followupWakeDigest": followup_wake_digest,
                    "codePathTombstoneReceipt": code_path_tombstone_receipt,
                    "continuationHeadSha": continuation_head_sha,
                    "prFollowupSnapshot": pr_followup_snapshot,
                }
                continuation_dedupe_key = sha256_json(continuation_payload)
                existing_continuation_row = connection.execute(
                    """SELECT id FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                         AND dedupe_key=?""",
                    (key, continuation_dedupe_key),
                ).fetchone()
                self._event(
                    connection,
                    key,
                    "TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND",
                    continuation_dedupe_key,
                    continuation_payload,
                    recorded_at,
                )
                if existing_result_row is None and existing_continuation_row is None:
                    result_authority_state = {
                        "taskId": task_id,
                        "threadId": thread_id,
                        "sourceResultEventId": int(result_row["id"]),
                        "resultDigest": digest,
                        "continuationDedupeKey": continuation_dedupe_key,
                        "tombstoneReceiptDigest": sha256_json(code_path_tombstone_receipt),
                    }
                    result_authority_marker = result_authority_state | {
                        "authorityObservedAt": recorded_at,
                        "authorityStateDigest": sha256_json(result_authority_state),
                    }
                    self._event(
                        connection,
                        key,
                        "TASK_RESULT_AUTHORITY_BOUND",
                        sha256_json(result_authority_marker),
                        result_authority_marker,
                        recorded_at,
                    )

    @staticmethod
    def _managed_replay_task_result_watermark(
        connection: sqlite3.Connection,
        *,
        key: str,
        task_id: str,
        thread_id: str,
        request_updated_at: str,
    ) -> dict[str, Any]:
        selected = connection.execute(
            """WITH candidates AS (
                 SELECT result.*,(
                   SELECT MAX(authority.id) FROM events authority
                   WHERE authority.opportunity_key=result.opportunity_key
                     AND authority.event_type='TASK_RESULT_AUTHORITY_BOUND'
                     AND json_extract(authority.payload_json,'$.taskId')=?
                     AND json_extract(authority.payload_json,'$.threadId')=?
                     AND json_extract(authority.payload_json,'$.sourceResultEventId')=
                         result.id
                     AND json_extract(authority.payload_json,'$.resultDigest')=
                         result.dedupe_key
                 ) AS selection_authority_id
                 FROM events result
                 WHERE result.opportunity_key=?
                   AND result.event_type='TASK_RESULT_INGESTED'
                   AND (
                     (
                       json_extract(result.payload_json,'$.threadId')=?
                       AND COALESCE(json_extract(result.payload_json,'$.taskId'),'')
                           IN ('',?)
                     )
                     OR (
                       COALESCE(json_extract(result.payload_json,'$.threadId'),'')=''
                       AND json_extract(result.payload_json,'$.taskId')=?
                     )
                     OR EXISTS (
                       SELECT 1 FROM events binding
                       WHERE binding.opportunity_key=result.opportunity_key
                         AND binding.event_type=
                             'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                         AND json_extract(binding.payload_json,'$.sourceResultEventId')=
                             result.id
                         AND json_extract(binding.payload_json,'$.resultDigest')=
                             result.dedupe_key
                         AND json_extract(binding.payload_json,'$.taskId')=?
                         AND json_extract(binding.payload_json,'$.threadId')=?
                     )
                   )
               )
               SELECT candidates.*,
                      MAX(
                        candidates.id,COALESCE(candidates.selection_authority_id,0)
                      ) AS selection_id,
                      authority.payload_json AS selection_authority_json
               FROM candidates
               LEFT JOIN events authority
                 ON authority.id=candidates.selection_authority_id
               ORDER BY selection_id DESC,candidates.id DESC LIMIT 1""",
            (
                task_id,
                thread_id,
                key,
                thread_id,
                task_id,
                task_id,
                task_id,
                thread_id,
            ),
        ).fetchone()
        latest_related = connection.execute(
            """SELECT MAX(id) FROM events
               WHERE opportunity_key=?
                 AND event_type IN (
                   'TASK_RESULT_INGESTED',
                   'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND',
                   'TASK_RESULT_AUTHORITY_BOUND'
                 )
                 AND (
                   json_extract(payload_json,'$.taskId')=?
                   OR json_extract(payload_json,'$.threadId')=?
                 )""",
            (key, task_id, thread_id),
        ).fetchone()[0]
        authority_payload: dict[str, Any] = {}
        if selected is not None and selected["selection_authority_json"] is not None:
            try:
                authority_payload = json.loads(selected["selection_authority_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError("managed replay selection authority is invalid") from exc
            if not isinstance(authority_payload, dict):
                raise LedgerError("managed replay selection authority is invalid")
        return {
            "requestUpdatedAt": request_updated_at,
            "selectionId": int(selected["selection_id"]) if selected is not None else None,
            "resultEventId": int(selected["id"]) if selected is not None else None,
            "authorityEventId": (
                int(selected["selection_authority_id"])
                if selected is not None and selected["selection_authority_id"] is not None
                else None
            ),
            "continuationDedupeKey": authority_payload.get("continuationDedupeKey"),
            "latestRelatedEventId": int(latest_related) if latest_related is not None else None,
        }

    def managed_replay_task_result_watermark(self, *, request_id: str) -> dict[str, Any]:
        """Capture the exact result projection before replay mutates local state."""

        with self.connect() as connection:
            request_row = connection.execute(
                """SELECT opportunity_key,thread_id,request_json,status,updated_at
                   FROM publication_requests WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if request_row is None or request_row["status"] != "BLOCKED":
                raise LedgerError("managed replay source request is not blocked")
            try:
                request = json.loads(request_row["request_json"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError("managed replay source request is invalid") from exc
            if (
                not isinstance(request, dict)
                or request.get("requestId") != request_id
                or request.get("publicationKind") != "PR_UPDATE"
                or request.get("opportunityKey") != request_row["opportunity_key"]
                or request.get("threadId") != request_row["thread_id"]
                or not request.get("intentId")
            ):
                raise LedgerError("managed replay source request is invalid")
            return self._managed_replay_task_result_watermark(
                connection,
                key=str(request_row["opportunity_key"]),
                task_id=str(request["intentId"]),
                thread_id=str(request_row["thread_id"]),
                request_updated_at=str(request_row["updated_at"]),
            )

    def bind_managed_replay_task_result_continuation(
        self,
        *,
        request_id: str,
        durable_receipt: dict[str, Any],
        managed_result_key: str,
        managed_validation_digest: str,
        expected_watermark: dict[str, Any],
    ) -> dict[str, Any]:
        """Reassert one historical tombstone continuation for an exact replay.

        This is deliberately narrower than generic result ingestion.  It never
        rewrites a result or an earlier authority event.  A transaction verifies
        the blocked PR-update snapshot, the durable managed authorization, the
        historical result triple, and the currently selected triple before it
        appends one continuation and its matching authority marker.
        """

        def parse_object(raw: Any, error: str) -> dict[str, Any]:
            try:
                value = json.loads(raw)
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError(error) from exc
            if not isinstance(value, dict):
                raise LedgerError(error)
            return value

        with self.transaction() as connection:
            request_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if request_row is None or request_row["status"] != "BLOCKED":
                raise LedgerError("managed replay source request is not blocked")
            request = parse_object(
                request_row["request_json"], "managed replay source request is invalid"
            )
            row_bindings = {
                "requestId": request_row["request_id"],
                "opportunityKey": request_row["opportunity_key"],
                "threadId": request_row["thread_id"],
                "commitSha": request_row["commit_sha"],
                "branch": request_row["branch"],
                "worktreePath": request_row["worktree_path"],
                "evidenceDigest": request_row["evidence_digest"],
            }
            if any(
                not expected or str(request.get(field) or "") != str(expected)
                for field, expected in row_bindings.items()
            ):
                raise LedgerError("managed replay source request row binding changed")
            if request.get("publicationKind") != "PR_UPDATE":
                raise LedgerError("managed replay source is not a PR update")

            key = str(request.get("opportunityKey") or "")
            task_id = str(request.get("intentId") or "")
            thread_id = str(request.get("threadId") or "")
            issue_url = str(request.get("issueUrl") or "")
            worktree_path = str(request.get("worktreePath") or "")
            result_digest = str(request.get("resultDigest") or "")
            source_wake_digest = str(request.get("followupWakeDigest") or "")
            previous_commit = str(request.get("previousCommitSha") or "")
            desired_commit = str(request.get("commitSha") or "")
            selected_base_sha = str(request.get("selectedBaseSha") or "")
            existing_pr_url = str(request.get("existingPrUrl") or "")
            code_paths = sorted(
                {str(path) for path in (request.get("codePaths") or []) if str(path).strip()}
            )
            issue_match = ISSUE_URL_RE.fullmatch(issue_url)
            pr_match = PR_URL_RE.fullmatch(existing_pr_url)
            if (
                not key
                or not task_id
                or not thread_id
                or not worktree_path
                or issue_match is None
                or key != f"{issue_match.group(1)}#{issue_match.group(2)}"
                or pr_match is None
                or pr_match.group(1) != issue_match.group(1)
                or re.fullmatch(r"[0-9a-f]{64}", result_digest) is None
                or re.fullmatch(r"[0-9a-f]{64}", source_wake_digest) is None
                or re.fullmatch(r"[0-9a-f]{40}", previous_commit) is None
                or re.fullmatch(r"[0-9a-f]{40}", desired_commit) is None
                or previous_commit == desired_commit
                or re.fullmatch(r"[0-9a-f]{40}", selected_base_sha) is None
                or not code_paths
            ):
                raise LedgerError("managed replay source identity is invalid")
            if Path(worktree_path).resolve() != Path(str(request_row["worktree_path"])).resolve():
                raise LedgerError("managed replay source worktree changed")
            if not isinstance(expected_watermark, dict) or expected_watermark != (
                self._managed_replay_task_result_watermark(
                    connection,
                    key=key,
                    task_id=task_id,
                    thread_id=thread_id,
                    request_updated_at=str(request_row["updated_at"]),
                )
            ):
                raise LedgerError("managed replay task result projection changed")

            snapshot_base64 = request.get("evidenceRawBase64")
            if not isinstance(snapshot_base64, str) or not snapshot_base64:
                raise LedgerError("managed replay source evidence is missing")
            try:
                evidence_raw = base64.b64decode(snapshot_base64.encode("ascii"), validate=True)
                evidence = json.loads(evidence_raw)
            except (ValueError, UnicodeEncodeError, json.JSONDecodeError) as exc:
                raise LedgerError("managed replay source evidence is invalid") from exc
            if (
                not isinstance(evidence, dict)
                or hashlib.sha256(evidence_raw).hexdigest() != request_row["evidence_digest"]
                or evidence.get("resultDigest") != result_digest
                or (evidence.get("taskId") or evidence.get("intentId")) != task_id
                or evidence.get("threadId") != thread_id
                or evidence.get("commitSha") != desired_commit
                or evidence.get("previousCommitSha") != previous_commit
                or evidence.get("worktreePath") != worktree_path
            ):
                raise LedgerError("managed replay source evidence binding changed")
            historical_tombstone = evidence.get("codePathTombstoneReceipt")
            if not isinstance(historical_tombstone, dict) or not historical_tombstone:
                raise LedgerError("managed replay source tombstone is missing")

            intent_row = connection.execute(
                """SELECT worktree_path FROM intents
                   WHERE opportunity_key=? AND intent_id=? AND thread_id=?""",
                (key, task_id, thread_id),
            ).fetchone()
            if (
                intent_row is None
                or Path(str(intent_row["worktree_path"] or "")).resolve()
                != Path(worktree_path).resolve()
            ):
                raise LedgerError("managed replay intent binding changed")

            managed_task = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if (
                managed_task is None
                or managed_task["opportunity_key"] != key
                or managed_task["thread_id"] != thread_id
                or Path(str(managed_task["worktree_path"] or "")).resolve()
                != Path(worktree_path).resolve()
                or managed_task["state"] not in {"IMPLEMENTATION_READY", "PORTFOLIO_READY"}
            ):
                raise LedgerError("managed replay durable task binding changed")
            managed_provenance = parse_object(
                managed_task["provenance_json"], "managed replay durable receipt is invalid"
            )
            if (
                not isinstance(durable_receipt, dict)
                or managed_provenance.get("probeReceipt") != durable_receipt
                or managed_provenance.get("probeReceiptDigest")
                != durable_receipt.get("receiptDigest")
            ):
                raise LedgerError("managed replay durable receipt binding changed")
            durable_paths = sorted(
                {
                    str(path)
                    for path in (durable_receipt.get("codePaths") or [])
                    if str(path).strip()
                }
            )
            if (
                durable_paths != code_paths
                or durable_receipt.get("baseSha") != selected_base_sha
                or not verify_probe_receipt(
                    durable_receipt,
                    repo=issue_match.group(1),
                    base_sha=selected_base_sha,
                    code_paths=code_paths,
                    required_level=REPRODUCED_VALIDATED,
                    issue_url=issue_url,
                    task_id=task_id,
                    thread_id=thread_id,
                    head_sha=str(durable_receipt.get("headSha") or ""),
                    commit_sha=str(durable_receipt.get("commitSha") or ""),
                    result_digest=str(durable_receipt.get("resultDigest") or ""),
                    enforce_freshness=False,
                )
            ):
                raise LedgerError("managed replay durable receipt is invalid")

            managed_result = connection.execute(
                "SELECT * FROM managed_results WHERE result_key=?",
                (managed_result_key,),
            ).fetchone()
            if managed_result is None:
                raise LedgerError("managed replay result disappeared")
            expected_pr_key = f"{pr_match.group(1)}#{int(pr_match.group(2))}"
            expected_managed_result_key = (
                f"{task_id}|{expected_pr_key}|{desired_commit}|{result_digest}"
            )
            validation_json = str(managed_result["validation_json"] or "")
            validation = parse_object(
                validation_json, "managed replay result validation is invalid"
            )
            if (
                hashlib.sha256(validation_json.encode("utf-8")).hexdigest()
                != managed_validation_digest
                or managed_result_key != expected_managed_result_key
                or managed_result["task_id"] != task_id
                or managed_result["pr_key"] != expected_pr_key
                or managed_result["head_sha"] != desired_commit
                or managed_result["commit_sha"] != desired_commit
                or managed_result["result_digest"] != result_digest
                or managed_result["worker_state"] != "patched"
                or int(managed_result["is_current"] or 0) != 1
                or validation.get("passed") is not True
                or not validation.get("evidence")
            ):
                raise LedgerError("managed replay result validation changed")

            def load_bundle(
                result_row: sqlite3.Row | dict[str, Any],
                *,
                continuation_dedupe_key: str | None = None,
                original_only: bool = False,
                authority_id: int | None = None,
            ) -> dict[str, Any]:
                result_payload = parse_object(
                    result_row["payload_json"], "managed replay result event is invalid"
                )
                continuation_clauses = [
                    "opportunity_key=?",
                    "event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'",
                    "json_extract(payload_json,'$.sourceResultEventId')=?",
                    "json_extract(payload_json,'$.resultDigest')=?",
                    "json_extract(payload_json,'$.taskId')=?",
                    "json_extract(payload_json,'$.threadId')=?",
                ]
                continuation_params: list[Any] = [
                    key,
                    int(result_row["id"]),
                    result_row["dedupe_key"],
                    task_id,
                    thread_id,
                ]
                if continuation_dedupe_key is not None:
                    continuation_clauses.append("dedupe_key=?")
                    continuation_params.append(continuation_dedupe_key)
                if original_only:
                    continuation_clauses.append(
                        "json_type(payload_json,'$.sourcePublicationRequestId') IS NULL"
                    )
                if authority_id is None:
                    continuation_clauses.append(
                        """EXISTS (
                          SELECT 1 FROM events AS authority
                          WHERE authority.opportunity_key=events.opportunity_key
                            AND authority.event_type='TASK_RESULT_AUTHORITY_BOUND'
                            AND json_extract(authority.payload_json,'$.taskId')=?
                            AND json_extract(authority.payload_json,'$.threadId')=?
                            AND json_extract(authority.payload_json,'$.sourceResultEventId')=?
                            AND json_extract(
                                  authority.payload_json,'$.continuationDedupeKey'
                                )=events.dedupe_key
                        )"""
                    )
                    continuation_params.extend((task_id, thread_id, int(result_row["id"])))
                continuation_row = connection.execute(
                    f"""SELECT * FROM events WHERE {" AND ".join(continuation_clauses)}
                        ORDER BY id DESC LIMIT 1""",
                    tuple(continuation_params),
                ).fetchone()
                if continuation_row is None:
                    raise LedgerError("managed replay continuation is missing")
                continuation = parse_object(
                    continuation_row["payload_json"],
                    "managed replay continuation is invalid",
                )
                if continuation_row["dedupe_key"] != sha256_json(continuation):
                    raise LedgerError("managed replay continuation digest is invalid")

                if authority_id is None:
                    authority_row = connection.execute(
                        """SELECT * FROM events
                           WHERE opportunity_key=?
                             AND event_type='TASK_RESULT_AUTHORITY_BOUND'
                             AND json_extract(payload_json,'$.taskId')=?
                             AND json_extract(payload_json,'$.threadId')=?
                             AND json_extract(payload_json,'$.sourceResultEventId')=?
                             AND json_extract(payload_json,'$.continuationDedupeKey')=?
                           ORDER BY id DESC LIMIT 1""",
                        (
                            key,
                            task_id,
                            thread_id,
                            int(result_row["id"]),
                            continuation_row["dedupe_key"],
                        ),
                    ).fetchone()
                else:
                    authority_row = connection.execute(
                        "SELECT * FROM events WHERE id=? AND opportunity_key=?",
                        (authority_id, key),
                    ).fetchone()
                if (
                    authority_row is None
                    or authority_row["event_type"] != "TASK_RESULT_AUTHORITY_BOUND"
                ):
                    raise LedgerError("managed replay result authority is missing")
                authority = parse_object(
                    authority_row["payload_json"], "managed replay result authority is invalid"
                )
                authority_state = {
                    field: authority.get(field)
                    for field in (
                        "taskId",
                        "threadId",
                        "sourceResultEventId",
                        "resultDigest",
                        "continuationDedupeKey",
                        "tombstoneReceiptDigest",
                    )
                }
                tombstone = continuation.get("codePathTombstoneReceipt")
                snapshot = continuation.get("prFollowupSnapshot")
                try:
                    result_time = parse_time(str(result_row["created_at"] or ""))
                    continuation_time = parse_time(str(continuation_row["created_at"] or ""))
                    authority_time = parse_time(str(authority.get("authorityObservedAt") or ""))
                    authority_event_time = parse_time(str(authority_row["created_at"] or ""))
                except (TypeError, ValueError) as exc:
                    raise LedgerError("managed replay authority timestamp is invalid") from exc
                if (
                    result_row["event_type"] != "TASK_RESULT_INGESTED"
                    or result_payload.get("taskId") != task_id
                    or result_payload.get("threadId") != thread_id
                    or result_payload.get("resultDigest") != result_row["dedupe_key"]
                    or continuation.get("sourceResultEventId") != int(result_row["id"])
                    or continuation.get("taskId") != task_id
                    or continuation.get("threadId") != thread_id
                    or continuation.get("resultDigest") != result_row["dedupe_key"]
                    or continuation.get("stage") != result_payload.get("stage")
                    or continuation.get("followupWakeDigest")
                    != result_payload.get("followupWakeDigest")
                    or continuation.get("continuationHeadSha")
                    != result_payload.get("continuationHeadSha")
                    or continuation.get("codePathTombstoneReceipt")
                    != result_payload.get("codePathTombstoneReceipt")
                    or not isinstance(tombstone, dict)
                    or not isinstance(snapshot, dict)
                    or snapshot.get("wakeDigest") != continuation.get("followupWakeDigest")
                    or snapshot.get("prUrl") != tombstone.get("prUrl")
                    or snapshot.get("actionDigest") != tombstone.get("actionDigest")
                    or snapshot.get("taskActionDigest") != tombstone.get("taskActionDigest")
                    or snapshot.get("checkedAt") != tombstone.get("checkedAt")
                    or snapshot.get("preparedHeadSha") != tombstone.get("preparedHeadSha")
                    or authority_state["taskId"] != task_id
                    or authority_state["threadId"] != thread_id
                    or authority_state["sourceResultEventId"] != int(result_row["id"])
                    or authority_state["resultDigest"] != result_row["dedupe_key"]
                    or authority_state["continuationDedupeKey"] != continuation_row["dedupe_key"]
                    or authority_state["tombstoneReceiptDigest"] != sha256_json(tombstone)
                    or authority.get("authorityStateDigest") != sha256_json(authority_state)
                    or not result_time <= continuation_time <= authority_time
                    or authority_time != authority_event_time
                    or not verify_code_path_tombstone_receipt(
                        tombstone,
                        source_receipt_digest=str(durable_receipt.get("receiptDigest") or ""),
                        base_sha=selected_base_sha,
                        key=key,
                        issue_url=issue_url,
                        intent_id=task_id,
                        thread_id=thread_id,
                        worktree_path_fingerprint=sha256_text(str(Path(worktree_path).resolve())),
                        pr_url=str(snapshot.get("prUrl") or ""),
                        wake_digest=str(continuation.get("followupWakeDigest") or ""),
                        action_digest=str(snapshot.get("actionDigest") or ""),
                        task_action_digest=str(snapshot.get("taskActionDigest") or ""),
                        checked_at=str(snapshot.get("checkedAt") or ""),
                        prepared_head_sha=str(snapshot.get("preparedHeadSha") or ""),
                        code_paths=code_paths,
                    )
                ):
                    raise LedgerError("managed replay result authority is invalid")
                return {
                    "resultRow": result_row,
                    "result": result_payload,
                    "continuationRow": continuation_row,
                    "continuation": continuation,
                    "authorityRow": authority_row,
                    "authority": authority,
                }

            source_result_row = connection.execute(
                """SELECT * FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                     AND dedupe_key=?""",
                (key, result_digest),
            ).fetchone()
            if source_result_row is None:
                raise LedgerError("managed replay historical result is missing")
            source_bundle = load_bundle(source_result_row, original_only=True)
            source_continuation = source_bundle["continuation"]
            source_snapshot = source_continuation["prFollowupSnapshot"]
            if (
                source_continuation.get("followupWakeDigest") != source_wake_digest
                or source_continuation.get("continuationHeadSha") != desired_commit
                or source_continuation.get("codePathTombstoneReceipt") != historical_tombstone
                or source_snapshot.get("prUrl") != existing_pr_url
                or source_snapshot.get("preparedHeadSha") != previous_commit
            ):
                raise LedgerError("managed replay historical continuation changed")

            def selected_result() -> dict[str, Any] | None:
                selection = self._managed_replay_task_result_watermark(
                    connection,
                    key=key,
                    task_id=task_id,
                    thread_id=thread_id,
                    request_updated_at=str(request_row["updated_at"]),
                )
                result_event_id = selection.get("resultEventId")
                if result_event_id is None:
                    return None
                selected_row = connection.execute(
                    "SELECT * FROM events WHERE id=? AND opportunity_key=?",
                    (result_event_id, key),
                ).fetchone()
                if selected_row is None:
                    raise LedgerError("managed replay selected result disappeared")
                return dict(selected_row) | {
                    "selection_authority_id": selection.get("authorityEventId"),
                    "selection_id": selection.get("selectionId"),
                }

            replay_authority_rows = connection.execute(
                """SELECT * FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_AUTHORITY_BOUND'
                     AND json_extract(payload_json,'$.sourcePublicationRequestId')=?
                   ORDER BY id DESC""",
                (key, request_id),
            ).fetchall()
            current_result_row = selected_result()
            if current_result_row is None:
                raise LedgerError("managed replay current result is missing")

            if replay_authority_rows:
                if len(replay_authority_rows) != 1:
                    raise LedgerError("managed replay continuation was bound more than once")
                replay_authority_row = replay_authority_rows[0]
                replay_authority = parse_object(
                    replay_authority_row["payload_json"],
                    "managed replay continuation authority is invalid",
                )
                replay_continuation_key = str(replay_authority.get("continuationDedupeKey") or "")
                previous_continuation_key = str(
                    replay_authority.get("previousContinuationDedupeKey") or ""
                )
                if (
                    int(current_result_row["id"]) != int(source_result_row["id"])
                    or int(current_result_row["selection_authority_id"] or 0)
                    != int(replay_authority_row["id"])
                    or replay_authority.get("sourcePublicationRequestId") != request_id
                    or not re.fullmatch(r"[0-9a-f]{64}", previous_continuation_key)
                ):
                    raise LedgerError("managed replay continuation authority is stale")
                replay_bundle = load_bundle(
                    source_result_row,
                    continuation_dedupe_key=replay_continuation_key,
                    authority_id=int(replay_authority_row["id"]),
                )
                previous_row = connection.execute(
                    """SELECT * FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                         AND dedupe_key=?""",
                    (key, previous_continuation_key),
                ).fetchone()
                if previous_row is None:
                    raise LedgerError("managed replay previous continuation disappeared")
                previous_result_row = connection.execute(
                    "SELECT * FROM events WHERE id=?",
                    (
                        parse_object(
                            previous_row["payload_json"],
                            "managed replay previous continuation is invalid",
                        ).get("sourceResultEventId"),
                    ),
                ).fetchone()
                if previous_result_row is None:
                    raise LedgerError("managed replay previous result disappeared")
                previous_bundle = load_bundle(
                    previous_result_row,
                    continuation_dedupe_key=previous_continuation_key,
                )
                expected_continuation = dict(source_continuation) | {
                    "continuationHeadSha": desired_commit,
                    "previousContinuationDedupeKey": previous_continuation_key,
                    "sourcePublicationRequestId": request_id,
                }
                if (
                    previous_bundle["continuation"].get("continuationHeadSha") != previous_commit
                    or replay_bundle["continuation"] != expected_continuation
                    or replay_authority.get("previousContinuationDedupeKey")
                    != previous_continuation_key
                ):
                    raise LedgerError("managed replay continuation authority changed")
                return {
                    "created": False,
                    "alreadyCurrent": True,
                    "continuationDedupeKey": replay_continuation_key,
                    "previousContinuationDedupeKey": previous_continuation_key,
                }

            current_bundle = load_bundle(
                current_result_row,
                authority_id=int(current_result_row["selection_authority_id"] or 0),
            )
            if (
                int(current_result_row["id"]) == int(source_result_row["id"])
                and current_bundle["continuationRow"]["dedupe_key"]
                == source_bundle["continuationRow"]["dedupe_key"]
            ):
                return {
                    "created": False,
                    "alreadyCurrent": True,
                    "continuationDedupeKey": source_bundle["continuationRow"]["dedupe_key"],
                    "previousContinuationDedupeKey": None,
                }
            if (
                current_bundle["continuation"].get("continuationHeadSha") != previous_commit
                or current_bundle["continuation"].get("sourcePublicationRequestId") is not None
            ):
                raise LedgerError("managed replay current continuation changed")

            previous_continuation_key = str(current_bundle["continuationRow"]["dedupe_key"])
            rebound_continuation = dict(source_continuation) | {
                "continuationHeadSha": desired_commit,
                "previousContinuationDedupeKey": previous_continuation_key,
                "sourcePublicationRequestId": request_id,
            }
            rebound_continuation_key = sha256_json(rebound_continuation)
            recorded_at = iso_z(datetime.now(UTC))
            self._event(
                connection,
                key,
                "TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND",
                rebound_continuation_key,
                rebound_continuation,
                recorded_at,
            )
            authority_state = {
                "taskId": task_id,
                "threadId": thread_id,
                "sourceResultEventId": int(source_result_row["id"]),
                "resultDigest": result_digest,
                "continuationDedupeKey": rebound_continuation_key,
                "tombstoneReceiptDigest": sha256_json(historical_tombstone),
            }
            rebound_authority = authority_state | {
                "authorityObservedAt": recorded_at,
                "authorityStateDigest": sha256_json(authority_state),
                "previousContinuationDedupeKey": previous_continuation_key,
                "sourcePublicationRequestId": request_id,
            }
            authority_dedupe_key = sha256_text(
                "|".join(
                    (
                        "managed-result-replay-authority-v1",
                        request_id,
                        str(source_result_row["id"]),
                        rebound_continuation_key,
                        previous_continuation_key,
                    )
                )
            )
            self._event(
                connection,
                key,
                "TASK_RESULT_AUTHORITY_BOUND",
                authority_dedupe_key,
                rebound_authority,
                recorded_at,
            )
            rebound_authority_row = connection.execute(
                """SELECT id FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_AUTHORITY_BOUND'
                     AND dedupe_key=? AND payload_json=?""",
                (key, authority_dedupe_key, canonical_json(rebound_authority)),
            ).fetchone()
            rebound_continuation_row = connection.execute(
                """SELECT id FROM events
                   WHERE opportunity_key=?
                     AND event_type='TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                     AND dedupe_key=? AND payload_json=?""",
                (key, rebound_continuation_key, canonical_json(rebound_continuation)),
            ).fetchone()
            selected_after = selected_result()
            if (
                rebound_authority_row is None
                or rebound_continuation_row is None
                or selected_after is None
                or int(selected_after["id"]) != int(source_result_row["id"])
                or int(selected_after["selection_authority_id"] or 0)
                != int(rebound_authority_row["id"])
            ):
                raise LedgerError("managed replay continuation CAS did not commit exactly")
            return {
                "created": True,
                "alreadyCurrent": True,
                "continuationDedupeKey": rebound_continuation_key,
                "previousContinuationDedupeKey": previous_continuation_key,
            }

    def published_task_result_backfill_seen(self, key: str, *, digest: str) -> bool:
        """Return whether the legacy controller recorded a published-result backfill."""

        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM events
                   WHERE opportunity_key=?
                     AND event_type='PUBLISHED_TASK_RESULT_BACKFILLED'
                     AND dedupe_key=?
                   LIMIT 1""",
                (key, digest),
            ).fetchone()
        return row is not None

    def record_published_task_result_backfilled(
        self,
        key: str,
        *,
        task_id: str,
        thread_id: str,
        digest: str,
        stage: str,
        pr_url: str,
        head_sha: str,
    ) -> None:
        """Append the legacy-side completion marker for an atomic managed backfill."""

        with self.transaction() as connection:
            self._event(
                connection,
                key,
                "PUBLISHED_TASK_RESULT_BACKFILLED",
                digest,
                {
                    "taskId": task_id,
                    "threadId": thread_id,
                    "resultDigest": digest,
                    "stage": stage,
                    "prUrl": pr_url,
                    "headSha": head_sha,
                },
                iso_z(datetime.now(UTC)),
            )

    def complete_publication_effect(
        self, effect_id: str, *, status: str, result: dict[str, Any]
    ) -> None:
        if status not in {"SUCCEEDED", "RECONCILE_REQUIRED", "FAILED"}:
            raise ValueError("invalid publication effect status")
        with self.transaction() as connection:
            request = connection.execute(
                """SELECT r.opportunity_key
                   FROM publication_effects e
                   JOIN publication_permits p ON p.permit_id=e.permit_id
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE e.effect_id=?""",
                (effect_id,),
            ).fetchone()
            if request is not None:
                require_quarantine_clear(
                    connection,
                    opportunity_key=str(request["opportunity_key"]),
                    operation="publication effect completion",
                )
            connection.execute(
                """UPDATE publication_effects SET status=?,result_json=?,updated_at=?
                   WHERE effect_id=?""",
                (
                    status,
                    canonical_json(result),
                    iso_z(datetime.now(UTC)),
                    effect_id,
                ),
            )

    def _retire_pr_followup_snapshot_after_publication(
        self,
        connection: sqlite3.Connection,
        *,
        request: sqlite3.Row,
        pr_url: str,
        now: str,
    ) -> None:
        payload = json.loads(request["request_json"])
        if payload.get("publicationKind") != "PR_UPDATE":
            return
        previous = connection.execute(
            "SELECT head_sha FROM pr_followups WHERE opportunity_key=? AND pr_url=?",
            (request["opportunity_key"], pr_url),
        ).fetchone()
        if previous is None:
            return
        connection.execute(
            """UPDATE pr_followups
               SET followup_required=0,wake_digest=NULL,updated_at=?
               WHERE opportunity_key=? AND pr_url=?""",
            (now, request["opportunity_key"], pr_url),
        )
        self._event(
            connection,
            request["opportunity_key"],
            "PR_FOLLOWUP_SNAPSHOT_SUPERSEDED",
            str(request["request_id"]),
            {
                "requestId": request["request_id"],
                "prUrl": pr_url,
                "previousCommitSha": payload.get("previousCommitSha") or previous["head_sha"],
                "commitSha": request["commit_sha"],
            },
            now,
        )

    def consume_publication_permit(self, permit_id: str, pr_url: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            permit = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if permit is None or permit["status"] != "ACTIVE":
                raise LedgerError("publication permit is not active")
            request_row = connection.execute(
                "SELECT opportunity_key,request_json FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request_row is None or not _publication_probe_valid_json(
                request_row["request_json"]
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (now, permit_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    ("BLOCKED_REPRODUCTION_REQUIRED", now, permit["request_id"]),
                )
                connection.commit()
                raise LedgerError(
                    "publication receipt blocked: authenticated reproduction is required"
                )
            require_quarantine_clear(
                connection,
                opportunity_key=str(request_row["opportunity_key"]),
                operation="publication permit consumption",
            )
            connection.execute(
                """UPDATE publication_permits SET status='CONSUMED',pr_url=?,updated_at=?
                   WHERE permit_id=?""",
                (pr_url, now, permit_id),
            )
            connection.execute(
                """UPDATE publication_requests SET status='CONSUMED',reason=NULL,updated_at=?
                   WHERE request_id=?""",
                (now, permit["request_id"]),
            )
            request = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request:
                connection.execute(
                    "UPDATE opportunities SET stage='PR_OPEN',updated_at=? WHERE key=?",
                    (now, request["opportunity_key"]),
                )
                connection.execute(
                    "UPDATE intents SET status='COMPLETED',updated_at=? WHERE opportunity_key=?",
                    (now, request["opportunity_key"]),
                )
                self._event(
                    connection,
                    request["opportunity_key"],
                    "PR_OPEN",
                    pr_url,
                    {"permitId": permit_id, "prUrl": pr_url},
                    now,
                )
                self._retire_pr_followup_snapshot_after_publication(
                    connection, request=request, pr_url=pr_url, now=now
                )

    def publication_feedback_candidates(self) -> list[dict[str, Any]]:
        """Return published tasks whose visible task reply does not yet reflect the PR."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,i.thread_id,i.worktree_path,
                          COALESCE(
                            json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                          ) AS pr_url,opened.created_at AS published_at
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events opened ON opened.id=(
                     SELECT MAX(e.id) FROM events e
                     WHERE e.opportunity_key=o.key AND e.event_type='PR_OPEN'
                   )
                   WHERE o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=COALESCE(
                           json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                         AND json_extract(reserved.payload_json,'$.prUrl')=COALESCE(
                           json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                             AND abandoned.dedupe_key=reserved.dedupe_key
                         )
                     )
                   ORDER BY opened.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "prUrl": row["pr_url"],
                "publishedAt": row["published_at"],
            }
            for row in rows
        ]

    def unresolved_publication_feedback(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,i.thread_id,i.worktree_path,
                          json_extract(reserved.payload_json,'$.prUrl') AS pr_url,
                          reserved.dedupe_key AS reservation_nonce,
                          reserved.created_at AS reserved_at
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id IS NOT NULL AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events reserved ON reserved.opportunity_key=o.key
                     AND reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events sent
                     WHERE sent.opportunity_key=o.key
                       AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                       AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=o.key
                         AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                         AND abandoned.dedupe_key=reserved.dedupe_key
                   )
                   ORDER BY reserved.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "prUrl": row["pr_url"],
                "reservationNonce": row["reservation_nonce"],
                "reservedAt": row["reserved_at"],
            }
            for row in rows
        ]

    def reserve_publication_feedback(self, *, thread_id: str, pr_url: str) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        nonce = sha256_text(f"{thread_id}|{pr_url}|{now}|{secrets.token_hex(16)}")
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key,o.issue_url,i.thread_id,i.worktree_path,
                          opened.created_at AS published_at
                   FROM opportunities o
                   JOIN intents i ON i.intent_id=(
                     SELECT i2.intent_id FROM intents i2
                     WHERE i2.opportunity_key=o.key
                       AND i2.thread_id=? AND i2.worktree_path IS NOT NULL
                     ORDER BY i2.updated_at DESC,i2.intent_id DESC LIMIT 1
                   )
                   JOIN events opened ON opened.id=(
                     SELECT MAX(e.id) FROM events e
                     WHERE e.opportunity_key=o.key AND e.event_type='PR_OPEN'
                       AND COALESCE(json_extract(e.payload_json,'$.prUrl'),e.dedupe_key)=?
                   )
                   WHERE o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=?
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                         AND json_extract(reserved.payload_json,'$.prUrl')=?
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                             AND abandoned.dedupe_key=reserved.dedupe_key
                         )
                     )""",
                (thread_id, pr_url, pr_url, pr_url),
            ).fetchone()
            if row is None:
                raise LedgerError("publication feedback is stale or already reserved")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["key"]),
                operation="publication feedback reservation",
            )
            self._event(
                connection,
                row["key"],
                "THREAD_PUBLICATION_STATUS_RESERVED",
                nonce,
                {"threadId": thread_id, "prUrl": pr_url, "reservationNonce": nonce},
                now,
            )
        return {
            "key": row["key"],
            "issueUrl": row["issue_url"],
            "threadId": row["thread_id"],
            "worktreePath": row["worktree_path"],
            "prUrl": pr_url,
            "publishedAt": row["published_at"],
            "reservationNonce": nonce,
            "reservedAt": now,
        }

    def commit_publication_feedback(self, *, thread_id: str, reservation_nonce: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT reserved.opportunity_key,
                          json_extract(reserved.payload_json,'$.prUrl') AS pr_url
                   FROM events reserved
                   JOIN intents i ON i.opportunity_key=reserved.opportunity_key
                     AND i.thread_id=?
                   WHERE reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                     AND reserved.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=reserved.opportunity_key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=reserved.opportunity_key
                         AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                         AND abandoned.dedupe_key=reserved.dedupe_key
                     )
                   LIMIT 1""",
                (thread_id, reservation_nonce),
            ).fetchone()
            if row is None:
                sent = connection.execute(
                    """SELECT 1 FROM events reserved JOIN events sent
                       ON sent.opportunity_key=reserved.opportunity_key
                      AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                      AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                       WHERE reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                         AND json_extract(reserved.payload_json,'$.threadId')=?
                         AND reserved.dedupe_key=?
                       LIMIT 1""",
                    (thread_id, reservation_nonce),
                ).fetchone()
                if sent:
                    return
                raise LedgerError("publication feedback reservation is unavailable")
            self._event(
                connection,
                row["opportunity_key"],
                "THREAD_PUBLICATION_STATUS_SENT",
                row["pr_url"],
                {
                    "threadId": thread_id,
                    "prUrl": row["pr_url"],
                    "reservationNonce": reservation_nonce,
                },
                now,
            )

    def abandon_publication_feedback(
        self,
        *,
        thread_id: str,
        reservation_nonce: str,
        reason: str,
        min_age_minutes: int = 1,
    ) -> None:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT reserved.opportunity_key,reserved.created_at
                   FROM events reserved
                   JOIN intents i ON i.opportunity_key=reserved.opportunity_key
                     AND i.thread_id=?
                   WHERE reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                     AND reserved.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=reserved.opportunity_key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=reserved.opportunity_key
                         AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                         AND abandoned.dedupe_key=reserved.dedupe_key
                     )
                   LIMIT 1""",
                (thread_id, reservation_nonce),
            ).fetchone()
            if row is None:
                raise LedgerError("publication feedback reservation is unavailable")
            if parse_time(str(row["created_at"])) + timedelta(minutes=min_age_minutes) > now_dt:
                raise LedgerError("publication feedback reservation is too recent to abandon")
            self._event(
                connection,
                row["opportunity_key"],
                "THREAD_PUBLICATION_STATUS_ABANDONED",
                reservation_nonce,
                {
                    "threadId": thread_id,
                    "reservationNonce": reservation_nonce,
                    "reason": reason,
                },
                now,
            )

    def acknowledge_publication_feedback(
        self,
        *,
        thread_id: str,
        pr_url: str,
        reason: str | None = None,
    ) -> None:
        """Record that the existing final task reply already contains the exact PR URL."""
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opened.opportunity_key
                   FROM events opened
                   JOIN intents i ON i.opportunity_key=opened.opportunity_key
                     AND i.thread_id=?
                   WHERE opened.event_type='PR_OPEN'
                     AND COALESCE(
                       json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                     )=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=opened.opportunity_key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=opened.dedupe_key
                     )
                   LIMIT 1""",
                (thread_id, pr_url),
            ).fetchone()
            if row is None:
                return
            self._event(
                connection,
                row["opportunity_key"],
                "THREAD_PUBLICATION_STATUS_SENT",
                pr_url,
                {
                    "threadId": thread_id,
                    "prUrl": pr_url,
                    "reconciledExistingReply": reason is None,
                    "reason": reason,
                },
                now,
            )

    def succeed_pull_request_effect(
        self,
        *,
        effect_id: str,
        permit_id: str,
        pr_url: str,
        result: dict[str, Any],
    ) -> None:
        """Atomically reconcile a PR effect and consume its narrowly bound permit."""
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            effect = connection.execute(
                "SELECT * FROM publication_effects WHERE effect_id=?", (effect_id,)
            ).fetchone()
            permit = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if effect is None or permit is None:
                raise LedgerError("publication effect or permit not found")
            if effect["permit_id"] != permit_id or effect["action"] != "create_pr":
                raise LedgerError("publication effect binding mismatch")
            if effect["status"] not in {"ATTEMPTED", "RECONCILE_REQUIRED"}:
                raise LedgerError("pull-request effect is not finalizable")
            if permit["status"] not in {"ACTIVE", "EXPIRED"}:
                raise LedgerError("publication permit is not consumable")
            if permit["status"] == "EXPIRED" and effect["status"] != "RECONCILE_REQUIRED":
                raise LedgerError("expired permit can only reconcile an ambiguous effect")
            request = connection.execute(
                "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request is None:
                raise LedgerError("publication request is missing")
            require_quarantine_clear(
                connection,
                opportunity_key=str(request["opportunity_key"]),
                operation="pull-request effect completion",
            )
            connection.execute(
                """UPDATE publication_effects SET status='SUCCEEDED',result_json=?,updated_at=?
                   WHERE effect_id=?""",
                (canonical_json(result), now, effect_id),
            )
            connection.execute(
                """UPDATE publication_permits SET status='CONSUMED',pr_url=?,updated_at=?
                   WHERE permit_id=?""",
                (pr_url, now, permit_id),
            )
            connection.execute(
                """UPDATE publication_requests SET status='CONSUMED',reason=NULL,updated_at=?
                   WHERE request_id=?""",
                (now, permit["request_id"]),
            )
            request = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request:
                connection.execute(
                    "UPDATE opportunities SET stage='PR_OPEN',updated_at=? WHERE key=?",
                    (now, request["opportunity_key"]),
                )
                connection.execute(
                    "UPDATE intents SET status='COMPLETED',updated_at=? WHERE opportunity_key=?",
                    (now, request["opportunity_key"]),
                )
                self._event(
                    connection,
                    request["opportunity_key"],
                    "PR_OPEN",
                    pr_url,
                    {"permitId": permit_id, "prUrl": pr_url},
                    now,
                )
                self._retire_pr_followup_snapshot_after_publication(
                    connection, request=request, pr_url=pr_url, now=now
                )

    def _cleanup_candidates(self, *, require_title_sync: bool) -> list[dict[str, Any]]:
        title_clause = "AND i.title_synced_state='AUDIT_NO_GO'" if require_title_sync else ""
        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.stage,o.updated_at,o.issue_url,i.thread_id,i.worktree_path,
                          i.title_synced_state
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.stage='AUDIT_NO_GO' AND i.thread_id IS NOT NULL
                     {title_clause}
                     AND COALESCE((
                       SELECT lifecycle.event_type FROM events lifecycle
                       WHERE lifecycle.opportunity_key=o.key
                         AND lifecycle.event_type IN ('THREAD_ARCHIVED','THREAD_RESTORED')
                         AND json_extract(lifecycle.payload_json,'$.threadId')=i.thread_id
                       ORDER BY lifecycle.id DESC LIMIT 1
                     ),'THREAD_RESTORED')<>'THREAD_ARCHIVED'
                   ORDER BY o.updated_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "stage": row["stage"],
                "titleSyncedState": row["title_synced_state"],
                "cleanupNonce": sha256_text(
                    f"{row['key']}|{row['thread_id']}|{row['stage']}|{row['updated_at']}"
                ),
            }
            for row in rows
        ]

    def cleanup_candidates(self) -> list[dict[str, Any]]:
        return self._cleanup_candidates(require_title_sync=True)

    def cleanup_reconciliation_candidates(self) -> list[dict[str, Any]]:
        """Include no-go tasks whose desktop thread was archived before title sync."""

        return self._cleanup_candidates(require_title_sync=False)

    def commit_cleanup(self, *, thread_id: str, nonce: str) -> None:
        candidates = {item["threadId"]: item for item in self.cleanup_candidates()}
        candidate = candidates.get(thread_id)
        if not candidate or candidate["cleanupNonce"] != nonce:
            raise LedgerError("cleanup authorization is stale or invalid")
        self._commit_cleanup_candidate(candidate, nonce=nonce)

    def commit_reconciled_cleanup(self, *, thread_id: str, nonce: str) -> None:
        candidates = {item["threadId"]: item for item in self.cleanup_reconciliation_candidates()}
        candidate = candidates.get(thread_id)
        if not candidate or candidate["cleanupNonce"] != nonce:
            raise LedgerError("cleanup reconciliation authorization is stale or invalid")
        self._commit_cleanup_candidate(candidate, nonce=nonce)

    def _commit_cleanup_candidate(self, candidate: dict[str, Any], *, nonce: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "THREAD_ARCHIVED",
                nonce,
                {"threadId": candidate["threadId"], "cleanupNonce": nonce},
                now,
            )

    def authorize_task_turn_delivery(
        self,
        *,
        delivery_kind: str,
        thread_id: str,
        delivery_token: str,
        delivery_attempt_digest: str | None = None,
        reservation_digest: str | None = None,
        snapshot_id: str | None = None,
        snapshot_path: str | None = None,
        snapshot_digest: str | None = None,
        worktree_input_path: str | None = None,
        worktree_input_digest: str | None = None,
    ) -> dict[str, Any]:
        """Atomically bind a reserved turn to the current quarantine-free state."""

        selectors = {
            "implementation-followup": (
                "IMPLEMENTATION_FOLLOWUP_RESERVED",
                "json_extract(payload_json,'$.threadId')=? AND dedupe_key=?",
            ),
            "pr-followup": (
                "PR_FOLLOWUP_RESERVED",
                "json_extract(payload_json,'$.threadId')=? AND dedupe_key=?",
            ),
            "validation-followup": (
                "VALIDATION_FOLLOWUP_RESERVED",
                "json_extract(payload_json,'$.threadId')=? "
                "AND json_extract(payload_json,'$.resultDigest')=?",
            ),
            "recovery": (
                "THREAD_RECOVERY_RESERVED",
                "json_extract(payload_json,'$.threadId')=? AND dedupe_key=?",
            ),
            "publication-feedback": (
                "THREAD_PUBLICATION_STATUS_RESERVED",
                "json_extract(payload_json,'$.threadId')=? AND dedupe_key=?",
            ),
        }
        selector = selectors.get(delivery_kind)
        if selector is None:
            raise LedgerError("unsupported task-turn delivery kind")
        now = iso_z(datetime.now(UTC))
        idempotency_key = f"task-turn-start:{delivery_kind}:{thread_id}:{delivery_token}"
        if delivery_kind == "implementation-followup":
            if not delivery_attempt_digest:
                delivery_attempt_digest = delivery_token
            idempotency_key += f":{delivery_attempt_digest}"
        elif delivery_kind == "validation-followup":
            required = (
                reservation_digest,
                snapshot_id,
                snapshot_path,
                snapshot_digest,
                worktree_input_path,
                worktree_input_digest,
            )
            if not all(isinstance(value, str) and value for value in required):
                raise LedgerError("validation task-turn delivery requires its snapshot binding")
            expected_worktree_input_path = (
                f".oss-pr-radar/validation-inputs/{reservation_digest}.json"
            )
            if (
                snapshot_id != reservation_digest
                or worktree_input_path != expected_worktree_input_path
                or worktree_input_digest != snapshot_digest
            ):
                raise LedgerError("validation task-turn worktree input binding is invalid")
            idempotency_key += f":{reservation_digest}"
        with self.transaction() as connection:
            if delivery_kind == "implementation-followup":
                row = connection.execute(
                    """SELECT r.opportunity_key,r.payload_json,r.dedupe_key
                       FROM events r
                       WHERE r.event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND (r.dedupe_key=? OR json_extract(r.payload_json,'$.resultDigest')=?)
                         AND NOT EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=r.opportunity_key
                             AND sent.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                             AND sent.dedupe_key=r.dedupe_key
                         )
                       ORDER BY r.id DESC LIMIT 1""",
                    (thread_id, delivery_token, delivery_token),
                ).fetchone()
                if row is not None and row["dedupe_key"] != delivery_attempt_digest:
                    raise LedgerError("implementation task-turn attempt binding mismatch")
            elif delivery_kind == "validation-followup":
                row = connection.execute(
                    """SELECT r.id,r.opportunity_key,r.payload_json
                       FROM events r
                       WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND json_extract(r.payload_json,'$.resultDigest')=?
                         AND json_extract(r.payload_json,'$.reservationDigest')=?
                         AND r.id=(
                           SELECT MAX(latest.id) FROM events latest
                           WHERE latest.opportunity_key=r.opportunity_key
                             AND latest.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=r.opportunity_key
                             AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                             AND sent.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events cancelled
                           WHERE cancelled.opportunity_key=r.opportunity_key
                             AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                             AND json_extract(cancelled.payload_json,'$.reservationDigest')=?
                             AND cancelled.id>r.id
                         )
                       ORDER BY r.id DESC LIMIT 1""",
                    (thread_id, delivery_token, reservation_digest, reservation_digest),
                ).fetchone()
            else:
                event_type, predicate = selector
                row = connection.execute(
                    f"""SELECT opportunity_key,payload_json FROM events
                        WHERE event_type=? AND {predicate}
                        ORDER BY id DESC LIMIT 1""",
                    (event_type, thread_id, delivery_token),
                ).fetchone()
            if row is None:
                raise LedgerError("task-turn delivery reservation is unavailable")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                operation="task-turn delivery start",
            )
            binding = {
                "deliveryKind": delivery_kind,
                "threadId": thread_id,
                "deliveryToken": delivery_token,
            }
            if delivery_kind == "implementation-followup":
                binding["deliveryAttemptDigest"] = delivery_attempt_digest
            elif delivery_kind == "validation-followup":
                binding.update(
                    {
                        "reservationDigest": reservation_digest,
                        "snapshotId": snapshot_id,
                        "snapshotPath": snapshot_path,
                        "snapshotDigest": snapshot_digest,
                        "worktreeInputPath": worktree_input_path,
                        "worktreeInputDigest": worktree_input_digest,
                        "resultDigest": delivery_token,
                    }
                )
            existing = connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_TURN_DELIVERY_STARTED'
                     AND dedupe_key=?""",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                payload = json.loads(existing["payload_json"])
                if any(payload.get(key) != value for key, value in binding.items()):
                    raise LedgerError("task-turn delivery binding mismatch")
                return {
                    "opportunityKey": str(row["opportunity_key"]),
                    **binding,
                }
            self._event(
                connection,
                str(row["opportunity_key"]),
                "TASK_TURN_DELIVERY_STARTED",
                idempotency_key,
                binding,
                now,
            )
            return {
                "opportunityKey": str(row["opportunity_key"]),
                **binding,
            }

    def validation_followup_delivery_binding(
        self,
        *,
        thread_id: str,
        result_digest: str,
        reservation_digest: str,
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_TURN_DELIVERY_STARTED'
                     AND json_extract(payload_json,'$.deliveryKind')='validation-followup'
                     AND json_extract(payload_json,'$.threadId')=?
                     AND json_extract(payload_json,'$.resultDigest')=?
                     AND json_extract(payload_json,'$.reservationDigest')=?
                   ORDER BY id DESC LIMIT 1""",
                (thread_id, result_digest, reservation_digest),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        return {
            key: payload.get(key)
            for key in (
                "reservationDigest",
                "snapshotId",
                "snapshotPath",
                "snapshotDigest",
                "worktreeInputPath",
                "worktreeInputDigest",
                "resultDigest",
            )
        }

    def _event(
        self,
        connection: sqlite3.Connection,
        key: str,
        event_type: str,
        dedupe_key: str,
        payload: dict[str, Any],
        created_at: str,
    ) -> None:
        connection.execute(
            """INSERT OR IGNORE INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?)""",
            (key, event_type, dedupe_key, canonical_json(payload), created_at),
        )
