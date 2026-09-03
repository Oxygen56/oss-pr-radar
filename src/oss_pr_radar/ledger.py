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
PR_UPDATE_REARM_REASONS = {
    "EXISTING_PR_BASE_DRIFT",
    "EXISTING_PR_HEAD_DRIFT",
    "NON_FAST_FORWARD_PR_UPDATE",
}
PR_FOLLOWUP_REARM_BARRIER_EVENT = "PR_FOLLOWUP_REARM_OBSERVATION_BARRIER"
MANAGED_REPLAY_REPLACEMENT_CREATED_EVENT = "MANAGED_REPLAY_REPLACEMENT_CREATED"
PR_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$")
ISSUE_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")
PROBE_RECEIPT_VOLATILE_FIELDS = frozenset({"observedAt", "expiresAt", "receiptDigest", "signature"})
# Publication may only be authorized for an intent that is still part of the
# live task lifecycle.  Historical/superseded intents remain in the ledger for
# auditability, but must never receive a new grant or recovery action.
_PUBLICATION_ACTIVE_INTENT_STATUSES = frozenset(
    {"PENDING", "LEASED", "CREATING", "DISPATCHED", "COMPLETED"}
)
# These events use a result/wake digest as their historical dedupe key.  A
# digest is not an immutable task identity: two intent generations for one
# issue can legitimately produce the same digest.  Keep the old key for
# compatibility, but reject a conflicting identity instead of silently
# dropping the newer event through INSERT OR IGNORE.
_IDENTITY_GUARDED_EVENT_TYPES = frozenset(
    {
        "TASK_RESULT_INGESTED",
        "PUBLISHED_TASK_RESULT_BACKFILLED",
        "TASK_RESULT_VALIDATION_DEFERRED",
        "VALIDATION_PREFETCH_BLOCKED",
        "VALIDATION_FOLLOWUP_NO_PROGRESS",
        "VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
        "VALIDATION_FOLLOWUP_RESERVED",
        "VALIDATION_FOLLOWUP_RESERVATION_CANCELLED",
        "VALIDATION_FOLLOWUP_DELIVERY_ABANDONED",
        "PR_FOLLOWUP_RESULT_INGESTED",
        "PR_FOLLOWUP_RESERVED",
        "PR_FOLLOWUP_PREPARATION_BOUND",
        "PR_FOLLOWUP_SENT",
        "PR_FOLLOWUP_DELIVERY_ABANDONED",
        "VALIDATION_FOLLOWUP_SENT",
    }
)


def _resolve_exact_intent_binding(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    intent_id: str | None = None,
    thread_id: str | None = None,
    worktree_path: str | None = None,
) -> sqlite3.Row | None:
    """Resolve one task binding without guessing from the newest intent.

    A single opportunity can have several historical intents.  Lifecycle
    records must therefore carry an exact identity (or be left unresolved),
    rather than silently borrowing whichever intent was updated most recently.
    When no intent id is available we only accept a unique thread/worktree
    match; ambiguity is deliberately fail-closed.
    """

    key = str(opportunity_key or "")
    requested_intent = str(intent_id or "")
    requested_thread = str(thread_id or "")
    requested_worktree = str(worktree_path or "")
    if not key:
        return None
    path_values: tuple[str, ...] = ()
    if requested_worktree:
        try:
            resolved = str(Path(requested_worktree).resolve())
        except (OSError, RuntimeError):
            resolved = requested_worktree
        path_values = tuple(dict.fromkeys((requested_worktree, resolved)))
    if requested_intent:
        # An explicit intent id is already a globally unique binding within
        # an opportunity.  Thread/worktree are optional corroborating fields;
        # when supplied they must agree, but their absence must not make the
        # resolver silently fall back to a different historical intent.
        clauses = ["opportunity_key=?", "intent_id=?"]
        params: list[str] = [key, requested_intent]
        if requested_thread:
            clauses.append("thread_id=?")
            params.append(requested_thread)
        if path_values:
            placeholders = ",".join("?" for _ in path_values)
            clauses.append(f"worktree_path IN ({placeholders})")
            params.extend(path_values)
        rows = connection.execute(
            f"SELECT * FROM intents WHERE {' AND '.join(clauses)} "
            "ORDER BY updated_at DESC,intent_id DESC",
            tuple(params),
        ).fetchall()
        if len(rows) != 1:
            return None
        row = rows[0]
        # A pre-dispatch lifecycle event may be authorized by its immutable
        # intent id before the app-server has materialized a thread/worktree.
        # If the caller supplied either corroborating field, the SQL selector
        # above already required it to match; otherwise retain the incomplete
        # row and let callers that need a runnable task enforce completeness.
        if requested_thread and row["thread_id"] is None:
            return None
        if requested_worktree and row["worktree_path"] is None:
            return None
        return row

    # Without an explicit immutable id, a thread and a concrete worktree are
    # both required and must identify exactly one historical intent.
    if not requested_thread:
        return None
    clauses = ["opportunity_key=?", "thread_id IS NOT NULL", "thread_id=?"]
    params = [key, requested_thread]
    if path_values:
        placeholders = ",".join("?" for _ in path_values)
        clauses.append(f"worktree_path IN ({placeholders})")
        params.extend(path_values)
    else:
        clauses.append("worktree_path IS NOT NULL")
    rows = connection.execute(
        f"SELECT * FROM intents WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC,intent_id DESC",
        tuple(params),
    ).fetchall()
    return rows[0] if len(rows) == 1 else None


def _pr_followup_binding_columns_present(connection: sqlite3.Connection) -> bool:
    """Return whether this connection sees the additive follow-up binding schema."""

    columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(pr_followups)")}
    return {"intent_id", "thread_id", "worktree_path"}.issubset(columns)


def _intent_event_binding_clause(intent_alias: str, event_alias: str) -> str:
    """Build a fail-closed SQL predicate for an intent/event identity pair.

    Lifecycle events created before identity fields were added contain only a
    thread id (or, occasionally, no binding at all).  Such legacy events are
    usable only when that thread maps to one and only one intent/worktree.
    New events carry ``intentId`` and can be matched exactly.  Invalid JSON is
    never interpreted as a legacy empty payload.
    """

    payload = f"{event_alias}.payload_json"
    valid_payload = f"json_valid({payload})=1"
    json_object = f"CASE WHEN {valid_payload} THEN {payload} ELSE '{{}}' END"
    thread_expr = f"json_extract({json_object},'$.threadId')"
    intent_id_expr = f"json_extract({json_object},'$.intentId')"
    task_expr = f"json_extract({json_object},'$.taskId')"
    intent_expr = f"COALESCE({intent_id_expr},{task_expr})"
    worktree_expr = f"json_extract({json_object},'$.worktreePath')"
    intent_id_type = f"json_type({json_object},'$.intentId')"
    task_id_type = f"json_type({json_object},'$.taskId')"
    thread_type = f"json_type({json_object},'$.threadId')"
    worktree_type = f"json_type({json_object},'$.worktreePath')"
    # Keep SQL's permissive SQLite coercions from disagreeing with the
    # Python resolver.  A present identity field is either a non-empty JSON
    # string or an explicit null; numbers, arrays, objects, and empty strings
    # are malformed and must never participate in a binding comparison.
    identity_shape = f"""
        AND (
          {intent_id_type} IS NULL OR {intent_id_type}='null'
          OR ({intent_id_type}='text' AND {intent_id_expr}<>'')
        )
        AND (
          {task_id_type} IS NULL OR {task_id_type}='null'
          OR ({task_id_type}='text' AND {task_expr}<>'')
        )
        AND (
          {thread_type} IS NULL OR {thread_type}='null'
          OR ({thread_type}='text' AND {thread_expr}<>'')
        )
        AND (
          {worktree_type} IS NULL OR {worktree_type}='null'
          OR ({worktree_type}='text' AND {worktree_expr}<>'')
        )
    """
    # Keep the explicit-id branch authoritative.  The fallback branch is
    # deliberately unique on the exact legacy identity available in the
    # payload; if two historical intents share it, no row is returned.
    return f"""
        {valid_payload}
        {identity_shape}
        AND NOT (
          COALESCE({intent_id_type}='text',0)
          AND COALESCE({task_id_type}='text',0)
          AND COALESCE({intent_id_expr}<>{task_expr},0)
        )
        AND {intent_alias}.thread_id IS NOT NULL
        AND {intent_alias}.worktree_path IS NOT NULL
        AND (
          -- An explicit immutable id is authoritative.  Older result and
          -- recovery payloads may carry only taskId/intentId, so absent
          -- thread/worktree fields are accepted and corroborated only when
          -- they are actually present.
          (
            {intent_expr} IS NOT NULL
            AND {intent_alias}.intent_id={intent_expr}
            AND ({thread_expr} IS NULL OR {intent_alias}.thread_id={thread_expr})
            AND ({worktree_expr} IS NULL OR {intent_alias}.worktree_path={worktree_expr})
          )
          OR (
            -- Legacy events without an immutable id must still provide a
            -- thread and resolve uniquely; ambiguous history fails closed.
            {intent_expr} IS NULL
            AND {thread_expr} IS NOT NULL
            AND {intent_alias}.thread_id={thread_expr}
            AND (
              (
                {worktree_expr} IS NOT NULL
                AND {intent_alias}.worktree_path={worktree_expr}
                AND NOT EXISTS (
                  SELECT 1 FROM intents other
                  WHERE other.opportunity_key={intent_alias}.opportunity_key
                    AND other.intent_id<>{intent_alias}.intent_id
                    AND other.thread_id={intent_alias}.thread_id
                    AND other.worktree_path={intent_alias}.worktree_path
                )
              )
              OR (
                {worktree_expr} IS NULL
                AND NOT EXISTS (
                  SELECT 1 FROM intents other
                  WHERE other.opportunity_key={intent_alias}.opportunity_key
                    AND other.intent_id<>{intent_alias}.intent_id
                    AND other.thread_id={intent_alias}.thread_id
                    AND other.worktree_path IS NOT NULL
                )
              )
            )
          )
        )
    """


def _legacy_unique_unbound_event_clause(intent_alias: str, event_alias: str) -> str:
    """Match an old event with no identity only for a singleton task.

    A few pre-identity result events contain just a digest/stage.  They can
    safely retire an implementation recovery only when the opportunity has
    exactly one intent with a complete binding.  This compatibility predicate
    is intentionally separate from ``_intent_event_binding_clause`` so that
    validation and publication paths remain fail-closed for unbound results.
    """

    payload = f"{event_alias}.payload_json"
    valid_payload = f"json_valid({payload})=1"
    return f"""
        {valid_payload}
        AND json_extract(CASE WHEN {valid_payload} THEN {payload} ELSE '{{}}' END,'$.intentId') IS NULL
        AND json_extract(CASE WHEN {valid_payload} THEN {payload} ELSE '{{}}' END,'$.taskId') IS NULL
        AND json_extract(CASE WHEN {valid_payload} THEN {payload} ELSE '{{}}' END,'$.threadId') IS NULL
        AND json_extract(CASE WHEN {valid_payload} THEN {payload} ELSE '{{}}' END,'$.worktreePath') IS NULL
        AND NOT EXISTS (
          SELECT 1 FROM intents other
          WHERE other.opportunity_key={intent_alias}.opportunity_key
            AND other.intent_id<>{intent_alias}.intent_id
            AND other.thread_id IS NOT NULL
            AND other.worktree_path IS NOT NULL
        )
    """


def _resolved_path_equal(left: str, right: str) -> bool:
    """Compare worktree paths while tolerating the legacy relative spelling."""

    if left == right:
        return True
    try:
        return Path(left).resolve() == Path(right).resolve()
    except (OSError, RuntimeError):
        return False


def _implementation_followup_event_matches_identity(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    row: sqlite3.Row,
    candidate: dict[str, Any],
    result_digest: str,
    attempt_digest: str | None = None,
) -> bool:
    """Validate one implementation event against its immutable task binding."""

    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    binding = _resolve_event_intent_binding(
        connection,
        opportunity_key=opportunity_key,
        payload=payload,
    )
    expected_intent = str(candidate.get("intentId") or candidate.get("intent_id") or "")
    expected_thread = str(candidate.get("threadId") or candidate.get("thread_id") or "")
    expected_worktree = str(candidate.get("worktreePath") or candidate.get("worktree_path") or "")
    if (
        binding is None
        or not expected_intent
        or not expected_thread
        or not expected_worktree
        or str(binding["intent_id"] or "") != expected_intent
        or str(binding["thread_id"] or "") != expected_thread
        or binding["worktree_path"] is None
        or not _resolved_path_equal(str(binding["worktree_path"]), expected_worktree)
    ):
        return False
    if payload.get("resultDigest") is not None and payload.get("resultDigest") != result_digest:
        return False
    if payload.get("issueUrl") is not None and payload.get("issueUrl") != candidate.get("issueUrl"):
        return False
    if attempt_digest is not None:
        if str(row["dedupe_key"] or "") != attempt_digest:
            return False
        if (
            payload.get("attemptDigest") is not None
            and payload.get("attemptDigest") != attempt_digest
        ):
            return False
    return True


def _resolve_event_intent_binding(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    payload: Any,
) -> sqlite3.Row | None:
    """Resolve an event payload to one immutable intent, or fail closed.

    Current implementation/continuation events carry ``intentId`` (older
    result events use the equivalent ``taskId``), plus optional thread and
    worktree fields.  Legacy rows may omit those fields; they are accepted
    only when the available identity selects exactly one intent.  A payload
    with malformed types or conflicting aliases is never guessed.
    """

    if not isinstance(payload, dict):
        return None
    identity_values: list[str] = []
    for field in ("intentId", "taskId"):
        if field not in payload or payload[field] is None:
            continue
        value = payload[field]
        if not isinstance(value, str) or not value:
            return None
        identity_values.append(value)
    if identity_values and any(value != identity_values[0] for value in identity_values[1:]):
        return None
    explicit_id = identity_values[0] if identity_values else None

    supplied_thread: str | None = None
    if "threadId" in payload and payload["threadId"] is not None:
        value = payload["threadId"]
        if not isinstance(value, str) or not value:
            return None
        supplied_thread = value
    supplied_worktree: str | None = None
    if "worktreePath" in payload and payload["worktreePath"] is not None:
        value = payload["worktreePath"]
        if not isinstance(value, str) or not value:
            return None
        supplied_worktree = value

    if explicit_id is not None:
        row = connection.execute(
            "SELECT * FROM intents WHERE opportunity_key=? AND intent_id=?",
            (opportunity_key, explicit_id),
        ).fetchone()
        if row is None or row["thread_id"] is None or row["worktree_path"] is None:
            return None
        if supplied_thread is not None and row["thread_id"] != supplied_thread:
            return None
        if supplied_worktree is not None and not _resolved_path_equal(
            str(row["worktree_path"]), supplied_worktree
        ):
            return None
        return row

    rows = connection.execute(
        """SELECT * FROM intents
           WHERE opportunity_key=? AND thread_id IS NOT NULL AND worktree_path IS NOT NULL""",
        (opportunity_key,),
    ).fetchall()
    matches: list[sqlite3.Row] = []
    for row in rows:
        if supplied_thread is not None and row["thread_id"] != supplied_thread:
            continue
        if supplied_worktree is not None and not _resolved_path_equal(
            str(row["worktree_path"]), supplied_worktree
        ):
            continue
        matches.append(row)
    return matches[0] if len(matches) == 1 else None


def _event_identity_projection(payload: Any) -> tuple[str | None, str | None, str | None]:
    """Extract the comparable identity fields from an event payload.

    ``intentId`` and the legacy ``taskId`` are aliases for the same immutable
    task id.  ``None`` means that a legacy payload did not carry that field;
    malformed present values are rejected so SQLite cannot coerce them into a
    false match.  Worktree paths are compared with the same resolver used by
    the rest of the ledger to tolerate the old relative spelling.
    """

    if not isinstance(payload, dict):
        raise LedgerError("event binding payload is invalid")
    task_ids: list[str] = []
    for field in ("intentId", "taskId"):
        if field not in payload or payload[field] is None:
            continue
        value = payload[field]
        if not isinstance(value, str) or not value:
            raise LedgerError("event binding payload is invalid")
        task_ids.append(value)
    if task_ids and any(value != task_ids[0] for value in task_ids[1:]):
        raise LedgerError("event binding payload identity mismatch")
    thread_id: str | None = None
    if "threadId" in payload and payload["threadId"] is not None:
        value = payload["threadId"]
        if not isinstance(value, str) or not value:
            raise LedgerError("event binding payload is invalid")
        thread_id = value
    worktree_path: str | None = None
    if "worktreePath" in payload and payload["worktreePath"] is not None:
        value = payload["worktreePath"]
        if not isinstance(value, str) or not value:
            raise LedgerError("event binding payload is invalid")
        worktree_path = value
    return (task_ids[0] if task_ids else None, thread_id, worktree_path)


def _event_identity_conflicts(existing_payload: Any, incoming_payload: Any) -> bool:
    """Return whether two same-key task events identify different tasks.

    Missing identity fields are retained as a compatibility path for legacy
    rows.  Whenever both rows provide a field, however, disagreement is a
    hard conflict; silently ignoring the incoming row would make a newer
    intent look completed by an older event.
    """

    existing = _event_identity_projection(existing_payload)
    incoming = _event_identity_projection(incoming_payload)
    existing_task, existing_thread, existing_worktree = existing
    incoming_task, incoming_thread, incoming_worktree = incoming
    if existing_task is not None and incoming_task is not None:
        if existing_task != incoming_task:
            return True
    if existing_thread is not None and incoming_thread is not None:
        if existing_thread != incoming_thread:
            return True
    if existing_worktree is not None and incoming_worktree is not None:
        if not _resolved_path_equal(existing_worktree, incoming_worktree):
            return True
    return False


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
    bound: list[sqlite3.Row] = []
    legacy_unbound: list[sqlite3.Row] = []
    for row in rows:
        dedupe_bound = str(row["dedupe_key"] or "").startswith(prefix)
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            has_explicit_identity = any(
                payload.get(field) not in (None, "")
                for field in ("intentId", "taskId", "threadId", "worktreePath")
            )
            if has_explicit_identity:
                # A digest/prefix is only a hint once an event carries an
                # identity payload. Resolve it against the exact intent and
                # reject malformed or foreign rows even when their dedupe key
                # happens to use this generation's prefix.
                binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=opportunity_key,
                    payload=payload,
                )
                if binding is None or str(binding["intent_id"] or "") != str(intent_id):
                    continue
                bound.append(row)
                continue
            legacy_unbound.append(row)
        if dedupe_bound:
            # Legacy snapshots had no identity fields; their canonical writer
            # encoded the generation in the dedupe prefix.
            bound.append(row)
    if bound:
        return bound
    intent_count = connection.execute(
        "SELECT COUNT(*) FROM intents WHERE opportunity_key=?", (opportunity_key,)
    ).fetchone()[0]
    return legacy_unbound if int(intent_count) == 1 else []


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


def _publication_ambiguous_effect_boundary(
    connection: sqlite3.Connection,
    *,
    request_id: str,
) -> dict[str, Any] | None:
    """Return an effect whose external outcome must be reconciled before revocation.

    ``ATTEMPTED`` is written before the executor performs its last live
    preflight. A concurrent audit therefore cannot tell whether the executor
    is still in that preflight or has already crossed into the external call.
    ``RECONCILE_REQUIRED`` and a durable ``creationAttempted`` marker are even
    stronger ambiguity boundaries. In all three cases, preserving the exact
    request and permit until the effect reconciles is safer than creating an
    orphan public result that the ledger can no longer consume.
    """

    rows = connection.execute(
        """SELECT effect.effect_id,effect.action,effect.status,effect.result_json,
                  effect.updated_at
           FROM publication_effects effect
           JOIN publication_permits permit ON permit.permit_id=effect.permit_id
           WHERE permit.request_id=?
           ORDER BY CASE WHEN effect.action='create_pr' THEN 0 ELSE 1 END,
                    effect.updated_at DESC""",
        (request_id,),
    ).fetchall()
    for row in rows:
        try:
            result = json.loads(str(row["result_json"] or "{}"))
        except json.JSONDecodeError:
            result = {}
        creation_attempted = bool(
            isinstance(result, dict) and result.get("creationAttempted") is True
        )
        if row["status"] not in {"ATTEMPTED", "RECONCILE_REQUIRED"} and not creation_attempted:
            continue
        return {
            "effectId": str(row["effect_id"]),
            "action": str(row["action"]),
            "status": str(row["status"]),
            "creationAttempted": creation_attempted,
            "updatedAt": str(row["updated_at"]),
        }
    return None


def _revoke_private_publication_authorizations(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    publication_rows: list[sqlite3.Row],
    reason: str,
    now: str,
    record_event: Any,
) -> None:
    """Revoke unpublished requests without crossing a durable public boundary."""

    for publication in publication_rows:
        request_id = str(publication["request_id"])
        request_status = str(publication["status"])
        if request_status not in {"PENDING", "GRANTED"}:
            continue
        if _publication_has_irreversible_terminal_evidence(
            connection,
            request_id=request_id,
            opportunity_key=opportunity_key,
        ) or _publication_ambiguous_effect_boundary(
            connection,
            request_id=request_id,
        ):
            continue
        permit = connection.execute(
            """SELECT permit_id,status FROM publication_permits
               WHERE request_id=?""",
            (request_id,),
        ).fetchone()
        connection.execute(
            """UPDATE publication_requests
               SET status='BLOCKED',reason=?,updated_at=?
               WHERE request_id=? AND status IN ('PENDING','GRANTED')""",
            (reason, now, request_id),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            continue
        if permit is not None and permit["status"] != "CONSUMED":
            connection.execute(
                """UPDATE publication_permits SET status='BLOCKED',updated_at=?
                   WHERE permit_id=? AND status<>'CONSUMED'""",
                (now, permit["permit_id"]),
            )
        record_event(
            connection,
            opportunity_key,
            "PUBLICATION_AUTHORIZATION_REVOKED",
            f"{request_id}:{reason}",
            {
                "requestId": request_id,
                "reason": reason,
                "previousRequestStatus": request_status,
                "permitId": permit["permit_id"] if permit is not None else None,
                "previousPermitStatus": permit["status"] if permit is not None else None,
            },
            now,
        )


def _publication_authorization_is_current_or_terminal(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    opportunity_key: str,
    request_json: str,
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Accept freshness only before an exact request crosses publication."""

    if _publication_has_irreversible_terminal_evidence(
        connection,
        request_id=request_id,
        opportunity_key=opportunity_key,
    ):
        return True
    if not _publication_request_intent_is_active(
        connection,
        request_id=request_id,
        opportunity_key=opportunity_key,
        request_json=request_json,
    ):
        return False
    return _publication_probe_valid_json(request_json, evidence)


def _resolve_publication_request_binding(
    connection: sqlite3.Connection,
    request: sqlite3.Row,
) -> tuple[sqlite3.Row, dict[str, Any]]:
    """Resolve the immutable intent behind one publication request.

    Publication tables predate the explicit intent column, so the request
    JSON and the denormalized thread/worktree columns are both checked.  A
    malformed or disagreeing identity is rejected instead of allowing a
    request for one historical intent to complete another intent on the same
    opportunity.
    """

    try:
        payload = json.loads(str(request["request_json"] or "{}"))
    except (TypeError, json.JSONDecodeError) as exc:
        raise LedgerError("publication request identity is invalid") from exc
    if not isinstance(payload, dict):
        raise LedgerError("publication request identity is invalid")

    def optional_text(field: str) -> str | None:
        value = payload.get(field)
        if value in (None, ""):
            return None
        if not isinstance(value, str) or not value.strip():
            raise LedgerError(f"publication request {field} identity is invalid")
        return value

    intent_value = optional_text("intentId")
    task_value = optional_text("taskId")
    if intent_value and task_value and intent_value != task_value:
        raise LedgerError("publication request intent identity disagrees")
    intent_id = intent_value or task_value
    payload_thread = optional_text("threadId")
    payload_worktree = optional_text("worktreePath")
    row_thread = str(request["thread_id"] or "") or None
    row_worktree = str(request["worktree_path"] or "") or None
    if payload_thread and row_thread and payload_thread != row_thread:
        raise LedgerError("publication request thread identity disagrees")
    if (
        payload_worktree
        and row_worktree
        and not _resolved_path_equal(payload_worktree, row_worktree)
    ):
        raise LedgerError("publication request worktree identity disagrees")
    thread_id = payload_thread or row_thread
    worktree_path = payload_worktree or row_worktree
    binding = _resolve_exact_intent_binding(
        connection,
        opportunity_key=str(request["opportunity_key"]),
        intent_id=intent_id,
        thread_id=thread_id,
        worktree_path=worktree_path,
    )
    if binding is None:
        raise LedgerError("publication request intent binding is stale or ambiguous")
    return binding, payload


def _publication_request_intent_is_active(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    opportunity_key: str,
    request_json: str | None = None,
    request_row: sqlite3.Row | None = None,
) -> bool:
    """Return whether a request still belongs to an active task generation.

    Publication requests historically had no intent foreign key, so the
    immutable identity in ``request_json`` (plus the denormalized columns) is
    resolved before checking the intent status.  A legacy request with no
    identity can only use the compatibility fallback when this opportunity has
    exactly one intent; once generations coexist, ambiguity fails closed.
    """

    row = request_row
    if row is None:
        row = connection.execute(
            "SELECT * FROM publication_requests WHERE request_id=? AND opportunity_key=?",
            (request_id, opportunity_key),
        ).fetchone()
    if row is None:
        return False
    raw = request_json if request_json is not None else row["request_json"]
    try:
        payload = json.loads(str(raw or "{}"))
    except (TypeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    explicit_identity = any(
        payload.get(field) not in (None, "")
        for field in ("intentId", "taskId", "threadId", "worktreePath")
    )
    try:
        binding, _ = _resolve_publication_request_binding(connection, row)
    except LedgerError:
        binding = None
    if binding is not None:
        return str(binding["status"] or "") in _PUBLICATION_ACTIVE_INTENT_STATUSES
    if explicit_identity:
        return False

    # Compatibility for pre-intent publication rows.  Do not guess from the
    # newest row: a singleton opportunity is the only unambiguous legacy case.
    intents = connection.execute(
        "SELECT status FROM intents WHERE opportunity_key=?",
        (opportunity_key,),
    ).fetchall()
    if not intents:
        # Some pre-intent databases retain a publication row before the
        # intent table was backfilled.  Preserve that single-generation
        # compatibility case; as soon as any intent exists, ambiguity is
        # fail-closed below.
        return str(row["status"] or "") in {"PENDING", "GRANTED"}
    return len(intents) == 1 and str(intents[0]["status"] or "") in (
        _PUBLICATION_ACTIVE_INTENT_STATUSES
    )


def _reopen_active_publication_requests_after_quarantine_clear(
    connection: sqlite3.Connection,
    *,
    opportunity_key: str,
    now: str,
) -> None:
    """Reopen only current-generation requests after a quarantine is cleared."""

    rows = connection.execute(
        """SELECT * FROM publication_requests
           WHERE opportunity_key=? AND status='BLOCKED'
             AND reason='BLOCKED_REPRODUCTION_REQUIRED'""",
        (opportunity_key,),
    ).fetchall()
    for row in rows:
        if _publication_request_intent_is_active(
            connection,
            request_id=str(row["request_id"]),
            opportunity_key=opportunity_key,
            request_row=row,
        ):
            connection.execute(
                """UPDATE publication_requests
                   SET status='PENDING',reason='TASK_QUARANTINE_CLEARED',updated_at=?
                   WHERE request_id=? AND status='BLOCKED'""",
                (now, row["request_id"]),
            )


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

_EXHAUSTED_DISPATCHED_RECOVERY_PREDICATE = f"""
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
        AND {_intent_event_binding_clause("i", "exhausted")}
        AND {_intent_event_binding_clause("i", "recovery")}
        AND json_extract(
              CASE WHEN json_valid(recovery.payload_json)=1
                   THEN recovery.payload_json ELSE '{{}}' END,
              '$.threadId'
            )=i.thread_id
        AND recovery.id>(
          SELECT COALESCE(MAX(dispatched.id),0)
          FROM events dispatched
          WHERE dispatched.opportunity_key=i.opportunity_key
            AND dispatched.event_type='DISPATCHED'
            AND dispatched.dedupe_key=i.thread_id
            AND {_intent_event_binding_clause("i", "dispatched")}
        )
        AND NOT EXISTS (
          SELECT 1
          FROM events later
          WHERE later.opportunity_key=exhausted.opportunity_key
            AND later.id>exhausted.id
            AND {_intent_event_binding_clause("i", "later")}
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
                AND json_extract(
                      CASE WHEN json_valid(later.payload_json)=1
                           THEN later.payload_json ELSE '{{}}' END,
                      '$.threadId'
                    )=i.thread_id
                AND json_extract(
                      CASE WHEN json_valid(later.payload_json)=1
                           THEN later.payload_json ELSE '{{}}' END,
                      '$.rearmedFromExhausted.exhaustedNonce'
                    )=exhausted.dedupe_key
              )
              OR (
                later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                AND json_extract(
                      CASE WHEN json_valid(later.payload_json)=1
                           THEN later.payload_json ELSE '{{}}' END,
                      '$.threadId'
                    )=i.thread_id
                AND json_extract(
                      CASE WHEN json_valid(later.payload_json)=1
                           THEN later.payload_json ELSE '{{}}' END,
                      '$.recoveryNonce'
                    )=
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


def _managed_replay_receipt_valid_at(
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
    return (
        receipt.get("bindingPurpose") == "implementation-result-v1"
        and bool(receipt.get("derivedFromReceiptDigest"))
        and observed_at <= snapshot_bound_at <= expires_at
        and verify_probe_receipt(
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
    )


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

    def _backfill_pr_followup_bindings(self, connection: sqlite3.Connection) -> None:
        """Backfill follow-up task identity from an exact durable source.

        Older ledgers keyed follow-ups only by opportunity.  A consumed
        publication request (or, for legacy rows, its reservation event) is the
        only safe source for the task/thread/worktree binding.  Ambiguous rows
        remain unbound and are intentionally hidden by candidate queries until
        a later exact observation repairs them.
        """

        rows = connection.execute(
            """SELECT * FROM pr_followups
               WHERE intent_id IS NULL OR thread_id IS NULL OR worktree_path IS NULL"""
        ).fetchall()
        for followup in rows:
            key = str(followup["opportunity_key"])
            binding: sqlite3.Row | None = None
            publication = connection.execute(
                """SELECT r.thread_id,r.worktree_path,r.request_json
                   FROM publication_requests r
                   JOIN publication_permits p ON p.request_id=r.request_id
                   WHERE r.opportunity_key=? AND p.pr_url=?
                     AND (
                       p.status='CONSUMED'
                       OR (
                         p.status='BLOCKED'
                         AND r.reason='BLOCKED_REPRODUCTION_REQUIRED'
                         AND json_valid(r.request_json)=1
                         AND json_extract(r.request_json,'$.recoveredFromTaskContext')=1
                       )
                     )
                   ORDER BY p.updated_at DESC,r.updated_at DESC,
                            r.created_at DESC,r.request_id DESC LIMIT 1""",
                (key, followup["pr_url"]),
            ).fetchone()
            if publication is not None:
                try:
                    request_payload = json.loads(str(publication["request_json"] or "{}"))
                except (TypeError, json.JSONDecodeError):
                    request_payload = {}
                if not isinstance(request_payload, dict):
                    request_payload = {}
                binding = _resolve_exact_intent_binding(
                    connection,
                    opportunity_key=key,
                    intent_id=str(request_payload.get("intentId") or "") or None,
                    thread_id=str(publication["thread_id"] or "") or None,
                    worktree_path=str(publication["worktree_path"] or "") or None,
                )
            if binding is None and followup["wake_digest"]:
                event_rows = connection.execute(
                    """SELECT event_type,payload_json FROM events
                       WHERE opportunity_key=? AND dedupe_key=?
                         AND event_type IN (
                           'PR_FOLLOWUP_PREPARATION_BOUND','PR_FOLLOWUP_RESERVED'
                         )
                       ORDER BY CASE event_type
                                  WHEN 'PR_FOLLOWUP_PREPARATION_BOUND' THEN 0 ELSE 1
                                END,id DESC""",
                    (key, followup["wake_digest"]),
                ).fetchall()
                for event in event_rows:
                    try:
                        payload = json.loads(str(event["payload_json"] or "{}"))
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(payload, dict):
                        continue
                    binding = _resolve_exact_intent_binding(
                        connection,
                        opportunity_key=key,
                        intent_id=str(payload.get("intentId") or "") or None,
                        thread_id=str(payload.get("threadId") or "") or None,
                        worktree_path=str(payload.get("worktreePath") or "") or None,
                    )
                    if binding is not None:
                        break
            if binding is None:
                continue
            existing_identity = (
                followup["intent_id"],
                followup["thread_id"],
                followup["worktree_path"],
            )
            resolved_identity = (
                str(binding["intent_id"]),
                str(binding["thread_id"]),
                str(binding["worktree_path"]),
            )
            if any(
                current is not None and str(current) != expected
                for current, expected in zip(existing_identity, resolved_identity, strict=True)
            ):
                # A partially populated row that disagrees with its source is
                # not repaired by inference; candidate selection will fail
                # closed and a fresh exact import can replace it safely.
                continue
            connection.execute(
                """UPDATE pr_followups
                   SET intent_id=?,thread_id=?,worktree_path=?
                   WHERE opportunity_key=?""",
                (*resolved_identity, key),
            )

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
                    intent_id TEXT,
                    thread_id TEXT,
                    worktree_path TEXT,
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
            followup_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(pr_followups)")
            }
            for name in ("intent_id", "thread_id", "worktree_path"):
                if name not in followup_columns:
                    connection.execute(f"ALTER TABLE pr_followups ADD COLUMN {name} TEXT")
            # Create this only after the additive columns exist.  Placing the
            # index in the CREATE-TABLE script makes opening a pre-fix ledger
            # fail before the migration can add those columns.
            connection.execute(
                """CREATE INDEX IF NOT EXISTS pr_followups_binding
                   ON pr_followups(opportunity_key,intent_id,thread_id,wake_digest)"""
            )
            self._backfill_pr_followup_bindings(connection)
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
                   JOIN pr_followups f ON f.opportunity_key=r.opportunity_key
                   JOIN intents i ON i.intent_id=json_extract(
                     CASE WHEN json_valid(r.request_json) THEN r.request_json ELSE '{}' END,
                     '$.intentId'
                   )
                   WHERE r.status='BLOCKED'
                     AND o.stage IN ('FIX_READY','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND r.reason IN (
                       'EXISTING_PR_BASE_DRIFT',
                       'EXISTING_PR_HEAD_DRIFT',
                       'NON_FAST_FORWARD_PR_UPDATE'
                     )
                     AND json_valid(r.request_json)=1
                     AND json_extract(
                       CASE WHEN json_valid(r.request_json) THEN r.request_json ELSE '{}' END,
                       '$.publicationKind'
                     )='PR_UPDATE'
                     AND json_extract(
                       CASE WHEN json_valid(r.request_json) THEN r.request_json ELSE '{}' END,
                       '$.existingPrUrl'
                     )=f.pr_url
                     AND json_extract(
                       CASE WHEN json_valid(r.request_json) THEN r.request_json ELSE '{}' END,
                       '$.previousCommitSha'
                     ) IS NOT NULL
                     AND (
                       r.reason='EXISTING_PR_HEAD_DRIFT'
                       OR json_extract(
                         CASE
                           WHEN json_valid(r.request_json) THEN r.request_json ELSE '{}'
                         END,
                         '$.previousCommitSha'
                       )=f.head_sha
                     )
                     AND i.opportunity_key=r.opportunity_key
                     AND i.thread_id=r.thread_id
                     AND i.worktree_path=r.worktree_path
                     AND i.status IN ('DISPATCHED','COMPLETED')
                     AND (
                       json_extract(r.request_json,'$.intentId')=i.intent_id
                       OR (
                         json_extract(r.request_json,'$.intentId') IS NULL
                         AND NOT EXISTS (
                           SELECT 1 FROM intents other
                           WHERE other.opportunity_key=i.opportunity_key
                             AND other.intent_id<>i.intent_id
                             AND other.thread_id=i.thread_id
                             AND other.worktree_path=i.worktree_path
                         )
                       )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events barrier
                       WHERE barrier.opportunity_key=r.opportunity_key
                         AND barrier.event_type='PR_FOLLOWUP_REARM_OBSERVATION_BARRIER'
                         AND barrier.dedupe_key=r.request_id
                     )
                     AND EXISTS (
                       SELECT 1 FROM events blocked
                       WHERE blocked.opportunity_key=r.opportunity_key
                         AND blocked.event_type='PUBLICATION_BLOCKED'
                         AND blocked.dedupe_key=r.request_id || ':' || r.reason
                         AND json_extract(blocked.payload_json,'$.requestId')=r.request_id
                         AND json_extract(blocked.payload_json,'$.reason')=r.reason
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=r.opportunity_key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM publication_requests newer
                       WHERE newer.opportunity_key=r.opportunity_key
                         AND (
                           newer.created_at>r.created_at
                           OR (
                             newer.created_at=r.created_at
                             AND newer.request_id>r.request_id
                           )
                         )
                     )
                     AND EXISTS (
                       SELECT 1 FROM publication_requests published
                       JOIN publication_permits permit
                         ON permit.request_id=published.request_id
                       WHERE published.opportunity_key=r.opportunity_key
                         AND permit.status='CONSUMED'
                         AND permit.pr_url=f.pr_url
                     )"""
            ).fetchall()
            for row in drifted_updates:
                if _publication_has_irreversible_terminal_evidence(
                    connection,
                    request_id=str(row["request_id"]),
                    opportunity_key=str(row["opportunity_key"]),
                ):
                    continue
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
            current = self.task_context(
                issue_url=issue_url,
                thread_id=thread_id,
                intent_id=intent_id,
                worktree_path=worktree_path,
            )
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
                """SELECT o.issue_url,i.opportunity_key,i.thread_id,i.worktree_path,i.payload_json
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
            # A matching receipt digest is not sufficient to identify the
            # task generation. Restrict the canonical lookup to audit rows
            # proven to belong to this exact intent first.
            bound_rows = _intent_bound_audit_rows(
                connection,
                str(row["opportunity_key"]),
                intent_id,
            )
            for audit_row in bound_rows:
                audit_payload = json.loads(audit_row["payload_json"])
                receipt = _live_audit_probe_receipt(audit_payload)
                if receipt is None or str(receipt.get("receiptDigest") or "") != expected_digest:
                    continue
                _audited_probe_code_paths(payload, audit_payload, issue_url)
                return False
            compatible: list[tuple[sqlite3.Row, dict[str, Any], str]] = []
            for audit_row in bound_rows:
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
                f"""SELECT o.key,o.title,o.stage,i.intent_id,i.thread_id,i.worktree_path,i.title_time,
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
                     AND i.rowid=(
                       SELECT MAX(current.rowid) FROM intents current
                       WHERE current.opportunity_key=o.key
                     )
                     AND COALESCE((
                       SELECT lifecycle.event_type FROM events lifecycle
                       WHERE lifecycle.opportunity_key=o.key
                         AND lifecycle.event_type IN ('THREAD_ARCHIVED','THREAD_RESTORED')
                         AND {_intent_event_binding_clause("i", "lifecycle")}
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
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "titleTime": row["title_time"],
                    "titleState": row["desired_state"],
                    "titleSyncedState": row["title_synced_state"],
                    "titleNonce": sha256_text(
                        canonical_json(
                            {
                                "key": row["key"],
                                "intentId": row["intent_id"],
                                "threadId": row["thread_id"],
                                "worktreePath": row["worktree_path"],
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
        bindings = [item for item in self.title_bindings() if item["threadId"] == thread_id]
        binding = bindings[0] if len(bindings) == 1 else None
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
                   WHERE intent_id=? AND thread_id=? AND title_synced_state=?""",
                (now, binding["intentId"], thread_id, state),
            ).rowcount
            if updated:
                self._event(
                    connection,
                    binding["key"],
                    "THREAD_TITLE_DRIFTED",
                    f"{thread_id}:{state}:{actual_title_digest}",
                    {
                        "intentId": binding["intentId"],
                        "threadId": thread_id,
                        "worktreePath": binding.get("worktreePath"),
                        "titleState": state,
                        "actualTitleDigest": actual_title_digest,
                    },
                    now,
                )
        return bool(updated)

    def commit_title(
        self,
        *,
        thread_id: str,
        state: str,
        nonce: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        candidates = [item for item in self.title_candidates() if item["threadId"] == thread_id]
        if intent_id:
            candidates = [item for item in candidates if item.get("intentId") == intent_id]
        if worktree_path:
            candidates = [
                item
                for item in candidates
                if item.get("worktreePath")
                and _resolved_path_equal(str(item["worktreePath"]), str(worktree_path))
            ]
        candidate = candidates[0] if len(candidates) == 1 else None
        if not candidate or candidate["titleState"] != state or candidate["titleNonce"] != nonce:
            raise LedgerError("title authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            connection.execute(
                """UPDATE intents SET title_synced_state=?,updated_at=?
                   WHERE intent_id=? AND thread_id=?""",
                (state, now, candidate["intentId"], thread_id),
            )
            self._event(
                connection,
                candidate["key"],
                "THREAD_TITLE_SYNCED",
                f"{thread_id}:{state}",
                {
                    "intentId": candidate["intentId"],
                    "threadId": thread_id,
                    "worktreePath": candidate.get("worktreePath"),
                    "titleState": state,
                },
                now,
            )

    def restorable_task_bindings(self) -> list[dict[str, Any]]:
        """Return valuable bindings authorized for targeted desktop restoration."""

        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.title,o.stage,o.updated_at,o.issue_url,
                          i.intent_id,i.thread_id,i.worktree_path,i.title_time,
                          lifecycle.id AS lifecycle_event_id,
                          lifecycle.event_type AS lifecycle_state
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   LEFT JOIN events lifecycle ON lifecycle.id=(
                     SELECT lifecycle.id FROM events lifecycle
                     WHERE lifecycle.opportunity_key=o.key
                       AND lifecycle.event_type IN ('THREAD_ARCHIVED','THREAD_RESTORED')
                       AND {_intent_event_binding_clause("i", "lifecycle")}
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
                "intentId": row["intent_id"],
                "issueUrl": row["issue_url"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "titleTime": row["title_time"],
                "lifecycleState": row["lifecycle_state"],
                "restoreNonce": sha256_text(
                    f"{row['key']}|{row['intent_id']}|{row['thread_id']}|"
                    f"{row['worktree_path']}|{row['stage']}|{row['updated_at']}|"
                    f"{row['lifecycle_event_id'] or 'physical-drift'}"
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

    def commit_restore(
        self,
        *,
        thread_id: str,
        nonce: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        candidates = [
            item for item in self.restorable_task_bindings() if item["threadId"] == thread_id
        ]
        if intent_id:
            candidates = [item for item in candidates if item.get("intentId") == intent_id]
        if worktree_path:
            candidates = [
                item
                for item in candidates
                if item.get("worktreePath")
                and _resolved_path_equal(str(item["worktreePath"]), str(worktree_path))
            ]
        candidate = candidates[0] if len(candidates) == 1 else None
        if not candidate or candidate["restoreNonce"] != nonce:
            raise LedgerError("restore authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "THREAD_RESTORED",
                nonce,
                {
                    "intentId": candidate.get("intentId"),
                    "threadId": thread_id,
                    "worktreePath": candidate.get("worktreePath"),
                    "restoreNonce": nonce,
                },
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
        intent_id: str | None = None,
        thread_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        if stage not in STAGES:
            raise ValueError(f"unsupported lifecycle stage: {stage}")
        # Lifecycle stages are global per opportunity, but their side effects
        # belong to one immutable task intent.  Do not infer that intent from
        # recency: explicit identity is resolved exactly, while legacy calls
        # are accepted only when there is at most one historical intent.
        intent_id = str(intent_id or "") or None
        thread_id = str(thread_id or "") or None
        worktree_path = str(worktree_path or "") or None
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT key,stage FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                raise LedgerError("opportunity not found")
            binding_row: sqlite3.Row | None = None
            if intent_id or thread_id or worktree_path:
                binding_row = _resolve_exact_intent_binding(
                    connection,
                    opportunity_key=key,
                    intent_id=intent_id,
                    thread_id=thread_id,
                    worktree_path=worktree_path,
                )
                if binding_row is None:
                    raise LedgerError("stage identity is stale or ambiguous")
            else:
                intent_rows = connection.execute(
                    "SELECT * FROM intents WHERE opportunity_key=? "
                    "ORDER BY updated_at DESC,intent_id DESC",
                    (key,),
                ).fetchall()
                if len(intent_rows) > 1:
                    raise LedgerError("stage identity is required for multiple intents")
                # Keep the legacy event shape for a sole unbound caller.  The
                # caller may still opt into an exact identity; absence of an
                # identity is safe here because there is no competing intent.

            # The opportunity stage is a projection for the current intent.
            # A delayed result from an older generation may still be useful
            # evidence, but it must never move that projection backwards (or
            # close a replacement task).  Keep a durable diagnostic event and
            # leave all lifecycle state untouched when the explicit binding is
            # no longer the newest intent for this opportunity.
            if binding_row is not None:
                current_row = connection.execute(
                    """SELECT intent_id FROM intents
                       WHERE opportunity_key=?
                       ORDER BY rowid DESC LIMIT 1""",
                    (key,),
                ).fetchone()
                repeated_issue_no_go = False
                if stage == "AUDIT_NO_GO" and reason:
                    repeated_issue_no_go = (
                        connection.execute(
                            """SELECT 1 FROM events
                               WHERE opportunity_key=? AND event_type='AUDIT_NO_GO'
                                 AND json_extract(payload_json,'$.reason')=?
                               LIMIT 1""",
                            (key, reason),
                        ).fetchone()
                        is not None
                    )
                if (
                    current_row is not None
                    and str(current_row["intent_id"]) != str(binding_row["intent_id"])
                    and not repeated_issue_no_go
                ):
                    stale_payload = {
                        "requestedStage": stage,
                        "reason": reason,
                        "sourceDedupeKey": dedupe_key,
                        "intentId": str(binding_row["intent_id"]),
                        "threadId": binding_row["thread_id"],
                        "worktreePath": binding_row["worktree_path"],
                        "currentIntentId": str(current_row["intent_id"]),
                    }
                    self._event(
                        connection,
                        key,
                        "STALE_STAGE_IGNORED",
                        sha256_json(
                            {
                                "sourceDedupeKey": dedupe_key,
                                **stale_payload,
                                "stage": stage,
                            }
                        ),
                        stale_payload,
                        now,
                    )
                    return

            def event_payload(payload: dict[str, Any] | None = None) -> dict[str, Any]:
                value = dict(payload or {})
                if binding_row is None:
                    return value
                identity = {
                    "intentId": str(binding_row["intent_id"]),
                    "threadId": (
                        str(binding_row["thread_id"])
                        if binding_row["thread_id"] is not None
                        else None
                    ),
                    "worktreePath": (
                        str(binding_row["worktree_path"])
                        if binding_row["worktree_path"] is not None
                        else None
                    ),
                }
                for field, expected in identity.items():
                    supplied = value.get(field)
                    if supplied is None:
                        continue
                    agrees = (
                        _resolved_path_equal(str(supplied), expected)
                        if field == "worktreePath"
                        else str(supplied) == expected
                    )
                    if not agrees:
                        raise LedgerError(f"stage evidence {field} does not match intent binding")
                value.update(identity)
                return value

            stage_evidence = event_payload(evidence or {"reason": reason})
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
            publication_rows: list[sqlite3.Row] = []
            irreversible_publication = None
            ambiguous_publication = None
            if stage == "AUDIT_NO_GO":
                publication_rows = connection.execute(
                    """SELECT request_id,status,permit_id,thread_id,worktree_path,request_json
                       FROM publication_requests
                       WHERE opportunity_key=? ORDER BY created_at""",
                    (key,),
                ).fetchall()
                if binding_row is not None:
                    matched_publications: list[sqlite3.Row] = []
                    for publication in publication_rows:
                        try:
                            request_payload = json.loads(publication["request_json"] or "{}")
                        except (TypeError, json.JSONDecodeError):
                            continue
                        if not isinstance(request_payload, dict):
                            continue
                        request_intent = request_payload.get("intentId") or request_payload.get(
                            "taskId"
                        )
                        request_thread = request_payload.get("threadId") or publication["thread_id"]
                        request_worktree = (
                            request_payload.get("worktreePath") or publication["worktree_path"]
                        )
                        if request_intent and str(request_intent) != str(binding_row["intent_id"]):
                            continue
                        if request_thread and str(request_thread) != str(binding_row["thread_id"]):
                            continue
                        if request_worktree and not _resolved_path_equal(
                            str(request_worktree), str(binding_row["worktree_path"])
                        ):
                            continue
                        # Legacy requests with no identity cannot be safely
                        # revoked by a task-bound stage event.
                        if not request_intent and not request_thread and not request_worktree:
                            continue
                        matched_publications.append(publication)
                    publication_rows = matched_publications
                irreversible_publication = next(
                    (
                        publication
                        for publication in publication_rows
                        if _publication_has_irreversible_terminal_evidence(
                            connection,
                            request_id=str(publication["request_id"]),
                            opportunity_key=key,
                        )
                    ),
                    None,
                )
                ambiguous_publication = next(
                    (
                        {
                            "requestId": str(publication["request_id"]),
                            "effect": boundary,
                        }
                        for publication in publication_rows
                        if (
                            boundary := _publication_ambiguous_effect_boundary(
                                connection,
                                request_id=str(publication["request_id"]),
                            )
                        )
                        is not None
                    ),
                    None,
                )
                _revoke_private_publication_authorizations(
                    connection,
                    opportunity_key=key,
                    publication_rows=publication_rows,
                    reason=reason or "AUDIT_NO_GO",
                    now=now,
                    record_event=self._event,
                )
            if stage == "AUDIT_NO_GO" and irreversible_publication is not None:
                # A delayed live audit may discover a no-go only after an
                # external publication receipt was durably observed.  The
                # receipt is authoritative: keep the useful lifecycle and
                # record the late audit without pretending the PR vanished.
                self._event(
                    connection,
                    key,
                    "POST_PUBLICATION_AUDIT_NO_GO",
                    dedupe_key or f"POST_PUBLICATION_AUDIT_NO_GO:{now}",
                    {
                        "preservedStage": row["stage"],
                        "reason": reason,
                        "evidence": stage_evidence,
                        "publicationRequestId": irreversible_publication["request_id"],
                        "publicationBoundary": "IRREVERSIBLE_RECEIPT",
                        **event_payload(),
                    },
                    now,
                )
                return
            if stage == "AUDIT_NO_GO" and ambiguous_publication is not None:
                # The executor may already be inside an external push/PR call.
                # Keep the exact authorization consumable until that effect is
                # reconciled, and retain this audit as a durable deferred gate.
                # Replaying the no-go after a confirmed no-effect will then
                # revoke normally; a successful PR will instead establish the
                # authoritative public boundary.
                effect = ambiguous_publication["effect"]
                self._event(
                    connection,
                    key,
                    "PUBLICATION_AUDIT_NO_GO_DEFERRED",
                    dedupe_key or f"PUBLICATION_AUDIT_NO_GO_DEFERRED:{now}",
                    {
                        "preservedStage": row["stage"],
                        "reason": reason,
                        "evidence": stage_evidence,
                        "publicationRequestId": ambiguous_publication["requestId"],
                        "publicationBoundary": "IN_FLIGHT_OR_UNCERTAIN",
                        "effectId": effect["effectId"],
                        "effectAction": effect["action"],
                        "effectStatus": effect["status"],
                        "creationAttempted": effect["creationAttempted"],
                        **event_payload(),
                    },
                    now,
                )
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
                        "evidence": stage_evidence,
                        **event_payload(),
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
                stage_evidence,
                now,
            )
            if binding_row is not None:
                if stage == "AUDIT_NO_GO":
                    connection.execute(
                        "UPDATE intents SET status='REJECTED',updated_at=? WHERE intent_id=?",
                        (now, binding_row["intent_id"]),
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
                        "UPDATE intents SET status='COMPLETED',updated_at=? WHERE intent_id=?",
                        (now, binding_row["intent_id"]),
                    )
            elif stage == "AUDIT_NO_GO":
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
            else f"""AND NOT EXISTS (
                     SELECT 1 FROM intents excluded
                     WHERE excluded.intent_id=?
                       AND excluded.opportunity_key=r.opportunity_key
                       AND ({_intent_event_binding_clause("excluded", "r")})
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
                     JOIN intents i ON i.opportunity_key=r.opportunity_key
                       AND {_intent_event_binding_clause("i", "r")}
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
                           AND {_intent_event_binding_clause("i", "completed")}
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
                           AND {_intent_event_binding_clause("i", "exhausted")}
                           AND {_intent_event_binding_clause("i", "recovery")}
                           AND json_extract(
                                 CASE WHEN json_valid(recovery.payload_json)=1
                                      THEN recovery.payload_json ELSE '{{}}' END,
                                 '$.recoveryKind'
                               )=
                               'PR_FOLLOWUP_RESULT'
                           AND json_extract(
                                 CASE WHEN json_valid(recovery.payload_json)=1
                                      THEN recovery.payload_json ELSE '{{}}' END,
                                 '$.followupDigest'
                               )=
                               r.dedupe_key
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events result
                         WHERE result.opportunity_key=r.opportunity_key
                           AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                           AND result.dedupe_key=r.dedupe_key
                           AND {_intent_event_binding_clause("i", "result")}
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events abandoned
                         WHERE abandoned.opportunity_key=r.opportunity_key
                           AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                           AND {_intent_event_binding_clause("i", "abandoned")}
                           AND json_extract(
                                 CASE WHEN json_valid(abandoned.payload_json)=1
                                      THEN abandoned.payload_json ELSE '{{}}' END,
                                 '$.wakeDigest'
                               )=r.dedupe_key
                           AND abandoned.id>r.id
                       )
                     UNION
                     SELECT r.opportunity_key FROM events r
                     JOIN opportunities o ON o.key=r.opportunity_key
                     JOIN intents i ON i.opportunity_key=r.opportunity_key
                       AND {_intent_event_binding_clause("i", "r")}
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
                           AND {_intent_event_binding_clause("i", "exhausted")}
                           AND {_intent_event_binding_clause("i", "recovery")}
                           AND json_extract(
                                 CASE WHEN json_valid(recovery.payload_json)=1
                                      THEN recovery.payload_json ELSE '{{}}' END,
                                 '$.recoveryKind'
                               )=
                               'VALIDATION_FOLLOWUP_RESULT'
                           AND json_extract(
                                 CASE WHEN json_valid(recovery.payload_json)=1
                                      THEN recovery.payload_json ELSE '{{}}' END,
                                 '$.followupDigest'
                               )=json_extract(
                                 CASE WHEN json_valid(r.payload_json)=1
                                      THEN r.payload_json ELSE '{{}}' END,
                                 '$.resultDigest'
                               )
                       )
                       AND json_extract(
                             CASE WHEN json_valid(r.payload_json)=1
                                  THEN r.payload_json ELSE '{{}}' END,
                             '$.resultDigest'
                           )=(
                         SELECT json_extract(
                                  CASE WHEN json_valid(d.payload_json)=1
                                       THEN d.payload_json ELSE '{{}}' END,
                                  '$.resultDigest'
                                )
                         FROM events d
                         WHERE d.opportunity_key=r.opportunity_key
                           AND d.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                         ORDER BY d.id DESC LIMIT 1
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events abandoned
                         WHERE abandoned.opportunity_key=r.opportunity_key
                           AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                           AND {_intent_event_binding_clause("i", "abandoned")}
                           AND json_extract(
                                 CASE WHEN json_valid(abandoned.payload_json)=1
                                      THEN abandoned.payload_json ELSE '{{}}' END,
                                 '$.resultDigest'
                               )=json_extract(
                                 CASE WHEN json_valid(r.payload_json)=1
                                      THEN r.payload_json ELSE '{{}}' END,
                                 '$.resultDigest'
                               )
                           AND json_extract(
                                 CASE WHEN json_valid(abandoned.payload_json)=1
                                      THEN abandoned.payload_json ELSE '{{}}' END,
                                 '$.reservedAt'
                               )=r.created_at
                           AND abandoned.id>r.id
                       )
                       AND NOT EXISTS (
                         SELECT 1 FROM events cancelled
                         WHERE cancelled.opportunity_key=r.opportunity_key
                           AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                           AND {_intent_event_binding_clause("i", "cancelled")}
                           AND json_extract(
                                 CASE WHEN json_valid(cancelled.payload_json)=1
                                      THEN cancelled.payload_json ELSE '{{}}' END,
                                 '$.reservationDigest'
                               )=json_extract(
                                 CASE WHEN json_valid(r.payload_json)=1
                                      THEN r.payload_json ELSE '{{}}' END,
                                 '$.reservationDigest'
                               )
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
                    WHERE i.status='DISPATCHED'
                      AND i.thread_id IS NOT NULL
                      AND {_intent_event_binding_clause("i", "exhausted")}
                      AND {_intent_event_binding_clause("i", "recovery")}
                      AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                      AND recovery.id>(
                        SELECT COALESCE(MAX(dispatched.id),0)
                        FROM events dispatched
                        WHERE dispatched.opportunity_key=i.opportunity_key
                          AND dispatched.event_type='DISPATCHED'
                          AND dispatched.dedupe_key=i.thread_id
                          AND {_intent_event_binding_clause("i", "dispatched")}
                      )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM events later
                        WHERE later.opportunity_key=exhausted.opportunity_key
                          AND later.id>exhausted.id
                          AND {_intent_event_binding_clause("i", "later")}
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
                              AND json_extract(
                                    CASE WHEN json_valid(later.payload_json)=1
                                         THEN later.payload_json ELSE '{{}}' END,
                                    '$.threadId'
                                  )=i.thread_id
                              AND json_extract(
                                    CASE WHEN json_valid(later.payload_json)=1
                                         THEN later.payload_json ELSE '{{}}' END,
                                    '$.rearmedFromExhausted.exhaustedNonce'
                                  )=exhausted.dedupe_key
                            )
                            OR (
                              later.event_type=
                                  'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                              AND json_extract(
                                    CASE WHEN json_valid(later.payload_json)=1
                                         THEN later.payload_json ELSE '{{}}' END,
                                    '$.threadId'
                                  )=i.thread_id
                              AND json_extract(
                                    CASE WHEN json_valid(later.payload_json)=1
                                         THEN later.payload_json ELSE '{{}}' END,
                                    '$.recoveryNonce'
                                  )=
                                  exhausted.dedupe_key
                            )
                            OR (
                              later.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                              AND json_extract(
                                    CASE WHEN json_valid(later.payload_json)=1
                                         THEN later.payload_json ELSE '{{}}' END,
                                    '$.threadId'
                                  )=i.thread_id
                              AND json_extract(
                                    CASE WHEN json_valid(later.payload_json)=1
                                         THEN later.payload_json ELSE '{{}}' END,
                                    '$.recoveryNonce'
                                  )=
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
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,d.created_at AS dispatched_at,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events d ON d.opportunity_key=o.key
                     AND d.event_type='DISPATCHED' AND d.dedupe_key=i.thread_id
                     AND {_intent_event_binding_clause("i", "d")}
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
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
                         AND json_extract(
                               CASE WHEN json_valid(recovery.payload_json)=1
                                    THEN recovery.payload_json ELSE '{{}}' END,
                               '$.recoveryKind'
                             )='DISPATCHED_TASK'
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
                         AND {_intent_event_binding_clause("i", "advanced")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events malformed_advanced
                       WHERE malformed_advanced.opportunity_key=o.key
                         AND malformed_advanced.id>d.id
                         AND malformed_advanced.event_type IN (
                           'TASK_RESULT_INGESTED',
                           'PUBLISHED_TASK_RESULT_BACKFILLED',
                           'PR_FOLLOWUP_RESULT_INGESTED',
                           'IMPLEMENTATION_FOLLOWUP_SENT',
                           'VALIDATION_FOLLOWUP_SENT',
                           'PR_FOLLOWUP_SENT'
                         )
                         AND json_valid(malformed_advanced.payload_json)<>1
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=o.key
                         AND (
                           (e.event_type='THREAD_RECOVERY_RESERVED'
                            AND {_intent_event_binding_clause("i", "e")}
                            AND e.created_at>=d.created_at
                            AND NOT EXISTS (
                              SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=e.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                             AND json_extract(
                                   abandoned.payload_json,'$.reservationDigest'
                                 )=e.dedupe_key
                                AND abandoned.id>e.id
                            ))
                           OR
                           (e.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                            AND {_intent_event_binding_clause("i", "e")})
                         )
                     )
                   ORDER BY d.created_at""",
                (cutoff, int(include_exhausted_dispatched)),
            ).fetchall()
            followup_rows = connection.execute(
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,s.created_at AS dispatched_at,
                          s.dedupe_key AS followup_digest,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='PR_FOLLOWUP_SENT'
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "s")}
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
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
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
                         AND {_intent_event_binding_clause("i", "result")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events recovery
                         WHERE recovery.opportunity_key=o.key
                           AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                           AND {_intent_event_binding_clause("i", "recovery")}
                           AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                           AND recovery.created_at>=s.created_at
                           AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=recovery.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
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
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,s.created_at AS dispatched_at,
                          s.dedupe_key AS followup_digest,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                          ) AS recovery_epoch
                   FROM opportunities o
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
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   ) AND s.created_at<=?
                     AND json_extract(d.payload_json,'$.threadId')=i.thread_id
                     AND {_intent_event_binding_clause("i", "s")}
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
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
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
                         AND {_intent_event_binding_clause("i", "result")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events recovery
                         WHERE recovery.opportunity_key=o.key
                           AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                           AND {_intent_event_binding_clause("i", "recovery")}
                           AND json_extract(recovery.payload_json,'$.threadId')=i.thread_id
                           AND recovery.created_at>=s.created_at
                           AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=recovery.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
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
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,s.created_at AS dispatched_at,
                          s.dedupe_key AS followup_digest,
                          (SELECT MAX(abandoned.created_at) FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                          ) AS recovery_epoch
                   FROM opportunities o
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "s")}
                   WHERE i.status='DISPATCHED' AND s.created_at<=?
                     AND i.thread_id=json_extract(
                           CASE WHEN json_valid(s.payload_json)=1
                                THEN s.payload_json ELSE '{{}}' END,
                           '$.threadId'
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
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
                         AND json_extract(
                               CASE WHEN json_valid(recovery.payload_json)=1
                                    THEN recovery.payload_json ELSE '{{}}' END,
                               '$.threadId'
                             )=i.thread_id
                         AND json_extract(
                               CASE WHEN json_valid(recovery.payload_json)=1
                                    THEN recovery.payload_json ELSE '{{}}' END,
                               '$.recoveryKind'
                             )=
                             'IMPLEMENTATION_FOLLOWUP_RESULT'
                         AND json_extract(
                               CASE WHEN json_valid(recovery.payload_json)=1
                                    THEN recovery.payload_json ELSE '{{}}' END,
                               '$.followupDigest'
                             )=s.dedupe_key
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=exhausted.opportunity_key
                             AND rearmed.event_type=
                                 'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND {_intent_event_binding_clause("i", "rearmed")}
                             AND json_extract(
                                   CASE WHEN json_valid(rearmed.payload_json)=1
                                        THEN rearmed.payload_json ELSE '{{}}' END,
                                   '$.threadId'
                                 )=i.thread_id
                             AND json_extract(
                                   CASE WHEN json_valid(rearmed.payload_json)=1
                                        THEN rearmed.payload_json ELSE '{{}}' END,
                                   '$.recoveryNonce'
                                 )=
                                 exhausted.dedupe_key
                             AND rearmed.id>exhausted.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type='TASK_RESULT_INGESTED'
                         AND result.id>s.id
                         AND (
                           {_intent_event_binding_clause("i", "result")}
                           OR {_legacy_unique_unbound_event_clause("i", "result")}
                         )
                       )
                     AND NOT EXISTS (
                       SELECT 1 FROM events recovery
                       WHERE recovery.opportunity_key=o.key
                         AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                         AND {_intent_event_binding_clause("i", "recovery")}
                         AND json_extract(
                               CASE WHEN json_valid(recovery.payload_json)=1
                                    THEN recovery.payload_json ELSE '{{}}' END,
                               '$.threadId'
                             )=i.thread_id
                         AND recovery.created_at>=s.created_at
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=recovery.opportunity_key
                             AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                             AND json_extract(
                                   CASE WHEN json_valid(abandoned.payload_json)=1
                                        THEN abandoned.payload_json ELSE '{{}}' END,
                                   '$.reservationDigest'
                                 )=recovery.dedupe_key
                             AND abandoned.id>recovery.id
                         )
                     )
                   ORDER BY s.created_at""",
                (cutoff,),
            ).fetchall()
            implementation_rearm_rows = connection.execute(
                f"""SELECT rearmed.id AS rearm_event_id,
                          exhausted.id AS exhausted_event_id,
                          exhausted.opportunity_key AS key,
                          exhausted.dedupe_key AS exhausted_nonce,
                          recovery.payload_json AS recovery_payload_json,
                          i.intent_id,i.thread_id,i.worktree_path
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
                   JOIN intents i ON i.opportunity_key=exhausted.opportunity_key
                   WHERE rearmed.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                     AND {_intent_event_binding_clause("i", "rearmed")}
                     AND {_intent_event_binding_clause("i", "exhausted")}
                     AND {_intent_event_binding_clause("i", "recovery")}
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                   ORDER BY rearmed.id"""
            ).fetchall()
            exhausted_dispatched_rows = (
                connection.execute(
                    f"""SELECT exhausted.id AS event_id,
                              exhausted.opportunity_key AS key,
                              exhausted.dedupe_key AS exhausted_nonce,
                              exhausted.payload_json AS exhausted_payload_json,
                              recovery.payload_json AS recovery_payload_json,
                              recovery.created_at AS recovery_created_at,
                              i.intent_id,i.thread_id,i.worktree_path
                       FROM events exhausted
                       JOIN events recovery
                        ON recovery.opportunity_key=exhausted.opportunity_key
                        AND recovery.event_type='THREAD_RECOVERY_RESERVED'
                        AND recovery.dedupe_key=exhausted.dedupe_key
                       JOIN intents i ON i.opportunity_key=exhausted.opportunity_key
                       WHERE exhausted.event_type='THREAD_RECOVERY_RETRY_EXHAUSTED'
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'DISPATCHED_TASK'
                       ORDER BY exhausted.id"""
                ).fetchall()
                if include_exhausted_dispatched
                else []
            )
        implementation_rearms: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for rearm_row in implementation_rearm_rows:
            recovery_payload = json.loads(rearm_row["recovery_payload_json"])
            implementation_rearms[
                (
                    str(rearm_row["key"]),
                    str(rearm_row["intent_id"] or recovery_payload.get("intentId") or ""),
                    str(rearm_row["thread_id"] or recovery_payload.get("threadId") or ""),
                    str(rearm_row["worktree_path"] or recovery_payload.get("worktreePath") or ""),
                    str(recovery_payload.get("followupDigest") or ""),
                )
            ] = {
                "exhaustedNonce": str(rearm_row["exhausted_nonce"]),
                "exhaustedEventId": int(rearm_row["exhausted_event_id"]),
                "rearmEventId": int(rearm_row["rearm_event_id"]),
            }
        exhausted_by_task: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
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
                    str(exhausted_row["intent_id"] or recovery_payload.get("intentId") or ""),
                    str(exhausted_row["thread_id"] or recovery_payload.get("threadId") or ""),
                    str(
                        exhausted_row["worktree_path"] or recovery_payload.get("worktreePath") or ""
                    ),
                ),
                [],
            ).append(marker)
        candidates: dict[tuple[str, str, str], dict[str, Any]] = {}
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
                    for marker in exhausted_by_task.get(
                        (
                            str(row["key"]),
                            str(row["intent_id"]),
                            thread_id,
                            str(row["worktree_path"] or ""),
                        ),
                        [],
                    )
                    if str(marker["recoveryCreatedAt"]) >= str(row["dispatched_at"])
                ]
            if recovery_kind == "IMPLEMENTATION_FOLLOWUP_RESULT":
                marker = implementation_rearms.get(
                    (
                        str(row["key"]),
                        str(row["intent_id"]),
                        thread_id,
                        str(row["worktree_path"] or ""),
                        str(followup_digest or ""),
                    )
                )
                if marker is not None:
                    candidate["rearmedFromExhausted"] = marker
            candidate_identity = (
                str(row["intent_id"]),
                thread_id,
                str(row["worktree_path"] or ""),
            )
            previous = candidates.get(candidate_identity)
            if previous is None or candidate["dispatchedAt"] > previous["dispatchedAt"]:
                candidates[candidate_identity] = candidate
        return sorted(candidates.values(), key=lambda item: item["dispatchedAt"])

    def unresolved_recoveries(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.issue_url,i.intent_id,i.thread_id,i.worktree_path,
                          json_extract(r.payload_json,'$.threadId') AS thread_id,
                          r.dedupe_key AS reservation_digest,
                          r.payload_json,r.created_at
                   FROM opportunities o
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events e
                     WHERE e.opportunity_key=o.key
                       AND e.event_type='THREAD_RECOVERY_SENT'
                       AND e.dedupe_key=r.dedupe_key
                       AND {_intent_event_binding_clause("i", "e")}
                   )
                     AND NOT EXISTS (
                     SELECT 1 FROM events abandoned
                     WHERE abandoned.opportunity_key=o.key
                       AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                       AND {_intent_event_binding_clause("i", "abandoned")}
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
                       AND {_intent_event_binding_clause("i", "result")}
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
                "intentId": row["intent_id"],
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
                f"""SELECT o.key,i.intent_id,i.thread_id,i.worktree_path,
                          r.dedupe_key AS reservation_digest,
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
                             AND {_intent_event_binding_clause("i", "prior_recovery")}
                             AND (
                               {_intent_event_binding_clause("i", "prior")}
                               OR {_legacy_unique_unbound_event_clause("i", "prior")}
                             )
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
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='THREAD_RECOVERY_SENT'
                     AND s.dedupe_key=r.dedupe_key
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "r")}
                     AND (
                       {_intent_event_binding_clause("i", "s")}
                       OR {_legacy_unique_unbound_event_clause("i", "s")}
                     )
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events abandoned
                     WHERE abandoned.opportunity_key=o.key
                       AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                       AND {_intent_event_binding_clause("i", "abandoned")}
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
                         AND {_intent_event_binding_clause("i", "result")}
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
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        # The bridge may authorize an immediate one-shot recovery after a
        # terminal desktop error, before the normal stale-task threshold.
        if (recovery_prompt_version is None) != (recovery_prompt_digest is None):
            raise LedgerError("recovery prompt binding is incomplete")
        raw_candidates = [
            item
            for item in self.recovery_candidates(
                min_age_minutes=0,
                include_exhausted_dispatched=recovery_prompt_version is not None,
            )
            if item["threadId"] == thread_id
            and (not intent_id or str(item.get("intentId") or "") == str(intent_id))
            and (
                not worktree_path
                or (
                    item.get("worktreePath")
                    and _resolved_path_equal(str(item["worktreePath"]), str(worktree_path))
                )
            )
        ]
        candidates: list[dict[str, Any]] = []
        for item in raw_candidates:
            candidate = item
            if recovery_prompt_version is not None:
                candidate = bind_dispatched_recovery_prompt(
                    item,
                    prompt_version=recovery_prompt_version,
                    prompt_digest=str(recovery_prompt_digest),
                )
            if candidate is not None and candidate["recoveryNonce"] == nonce:
                candidates.append(candidate)
        if len(candidates) != 1:
            raise LedgerError("recovery authorization is stale or invalid")
        candidate = candidates[0]
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            require_quarantine_clear(
                connection,
                opportunity_key=str(candidate["key"]),
                operation="recovery delivery reservation",
            )
            if candidate["recoveryKind"] == "IMPLEMENTATION_FOLLOWUP_RESULT":
                eligible = connection.execute(
                    f"""SELECT s.id
                       FROM events s
                       JOIN intents i ON i.opportunity_key=s.opportunity_key
                         AND i.intent_id=?
                       WHERE s.opportunity_key=?
                         AND s.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND s.dedupe_key=?
                         AND json_extract(s.payload_json,'$.threadId')=?
                         AND {_intent_event_binding_clause("i", "s")}
                         AND s.id=(
                           SELECT MAX(latest.id) FROM events latest
                           WHERE latest.opportunity_key=s.opportunity_key
                             AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                             AND {_intent_event_binding_clause("i", "latest")}
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=s.opportunity_key
                             AND result.event_type='TASK_RESULT_INGESTED'
                             AND result.id>s.id
                             AND (
                               {_intent_event_binding_clause("i", "result")}
                               OR {_legacy_unique_unbound_event_clause("i", "result")}
                             )
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
                            AND {_intent_event_binding_clause("i", "prior_recovery")}
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
                                 AND {_intent_event_binding_clause("i", "rearmed")}
                                 AND json_extract(
                                       rearmed.payload_json,'$.recoveryNonce'
                                     )=exhausted.dedupe_key
                                 AND rearmed.id>exhausted.id
                             )
                         )
                       LIMIT 1""",
                    (
                        candidate["intentId"],
                        candidate["key"],
                        candidate.get("followupDigest"),
                        thread_id,
                    ),
                ).fetchone()
                if eligible is None:
                    raise LedgerError("recovery authorization is stale or invalid")
                epoch_row = connection.execute(
                    f"""SELECT MAX(abandoned.created_at) AS recovery_epoch
                       FROM events abandoned
                       JOIN intents i ON i.opportunity_key=abandoned.opportunity_key
                         AND i.intent_id=?
                       WHERE abandoned.opportunity_key=?
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}""",
                    (candidate["intentId"], candidate["key"]),
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
                    f"""SELECT MAX(rearmed.id) AS rearm_event_id
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
                       JOIN intents i
                         ON i.opportunity_key=rearmed.opportunity_key
                        AND i.intent_id=?
                       WHERE rearmed.opportunity_key=?
                         AND rearmed.event_type=
                             'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                         AND {_intent_event_binding_clause("i", "rearmed")}
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "prior_recovery")}
                         AND json_extract(rearmed.payload_json,'$.threadId')=?
                         AND json_extract(prior_recovery.payload_json,'$.recoveryKind')=
                             'IMPLEMENTATION_FOLLOWUP_RESULT'
                         AND json_extract(prior_recovery.payload_json,'$.followupDigest')=?""",
                    (
                        candidate["intentId"],
                        candidate["key"],
                        thread_id,
                        candidate.get("followupDigest"),
                    ),
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
                        f"""SELECT 1 FROM events rearmed
                           JOIN events exhausted
                             ON exhausted.opportunity_key=rearmed.opportunity_key
                            AND exhausted.event_type=
                                'THREAD_RECOVERY_RETRY_EXHAUSTED'
                            AND exhausted.dedupe_key=?
                           JOIN intents i
                             ON i.opportunity_key=rearmed.opportunity_key
                            AND i.intent_id=?
                           WHERE rearmed.opportunity_key=?
                             AND rearmed.event_type=
                                 'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                             AND {_intent_event_binding_clause("i", "rearmed")}
                             AND {_intent_event_binding_clause("i", "exhausted")}
                             AND rearmed.id=?
                             AND exhausted.id=?
                             AND json_extract(rearmed.payload_json,'$.threadId')=?
                             AND json_extract(rearmed.payload_json,'$.recoveryNonce')=?
                           LIMIT 1""",
                        (
                            lineage.get("exhaustedNonce"),
                            candidate["intentId"],
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
                f"""SELECT 1 FROM events reserved
                   JOIN intents i ON i.opportunity_key=reserved.opportunity_key
                     AND i.intent_id=?
                   WHERE reserved.opportunity_key=?
                   AND reserved.event_type='THREAD_RECOVERY_RESERVED'
                   AND json_extract(reserved.payload_json,'$.threadId')=?
                   AND reserved.created_at>=?
                   AND {_intent_event_binding_clause("i", "reserved")}
                   AND NOT EXISTS (
                     SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=reserved.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                       AND json_extract(
                             abandoned.payload_json,'$.reservationDigest'
                           )=reserved.dedupe_key
                       AND abandoned.id>reserved.id
                   )""",
                (candidate["intentId"], candidate["key"], thread_id, candidate["dispatchedAt"]),
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
                    "intentId": candidate["intentId"],
                    "threadId": thread_id,
                    "worktreePath": candidate["worktreePath"],
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

    def commit_recovery(
        self,
        *,
        thread_id: str,
        nonce: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        with self.transaction() as connection:
            reservation_identity_clause = ""
            reservation_params: list[Any] = [thread_id, nonce]
            if intent_id:
                reservation_identity_clause = " AND i.intent_id=?"
                reservation_params.append(str(intent_id))
            rows = connection.execute(
                f"""SELECT r.opportunity_key AS key,r.dedupe_key,r.payload_json,
                          i.intent_id,i.thread_id,i.worktree_path
                   FROM opportunities o
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.recoveryNonce')=?
                     {reservation_identity_clause}
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='THREAD_RECOVERY_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(
                               abandoned.payload_json,'$.reservationDigest'
                             )=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC""",
                tuple(reservation_params),
            ).fetchall()
            if worktree_path:
                rows = [
                    candidate_row
                    for candidate_row in rows
                    if candidate_row["worktree_path"]
                    and _resolved_path_equal(
                        str(candidate_row["worktree_path"]), str(worktree_path)
                    )
                ]
            if len(rows) > 1:
                raise LedgerError("recovery reservation is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                sent_identity_clause = ""
                sent_params: list[Any] = [thread_id, nonce]
                if intent_id:
                    sent_identity_clause = " AND i.intent_id=?"
                    sent_params.append(str(intent_id))
                sent_rows = connection.execute(
                    f"""SELECT r.opportunity_key AS key,r.payload_json,
                              i.intent_id,i.thread_id,i.worktree_path
                       FROM events r
                       JOIN events sent
                       ON sent.opportunity_key=r.opportunity_key
                      AND sent.event_type='THREAD_RECOVERY_SENT'
                      AND sent.dedupe_key=r.dedupe_key
                       JOIN intents i ON i.opportunity_key=r.opportunity_key
                         AND {_intent_event_binding_clause("i", "r")}
                         AND {_intent_event_binding_clause("i", "sent")}
                       WHERE r.event_type='THREAD_RECOVERY_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND json_extract(r.payload_json,'$.recoveryNonce')=?
                         {sent_identity_clause}
                       ORDER BY sent.id DESC""",
                    tuple(sent_params),
                ).fetchall()
                if worktree_path:
                    sent_rows = [
                        candidate_row
                        for candidate_row in sent_rows
                        if candidate_row["worktree_path"]
                        and _resolved_path_equal(
                            str(candidate_row["worktree_path"]), str(worktree_path)
                        )
                    ]
                if len(sent_rows) > 1:
                    raise LedgerError("recovery reservation is ambiguous")
                if sent_rows:
                    return
                raise LedgerError("recovery reservation not found")
            payload = json.loads(row["payload_json"])
            if payload.get("recoveryNonce") != nonce:
                raise LedgerError("recovery reservation nonce mismatch")
            changes_before = connection.total_changes
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_SENT",
                row["dedupe_key"],
                {
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "recoveryNonce": nonce,
                },
                iso_z(datetime.now(UTC)),
            )
            if connection.total_changes == changes_before:
                raise LedgerError("recovery sent event binding collides with another task")

    def abandon_recovery_delivery(
        self,
        *,
        thread_id: str,
        nonce: str,
        reason: str,
        min_age_minutes: int = 5,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Retire a recovery reservation after proving delivery or result failure."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            allow_sent = reason in {
                "TERMINAL_RECOVERY_TURN_INTERRUPTED",
                "RECOVERY_RETRY_EXHAUSTED",
            }
            identity_clause = ""
            reservation_params: list[Any] = [thread_id, nonce, nonce, int(allow_sent)]
            if intent_id:
                identity_clause = " AND i.intent_id=?"
                reservation_params.append(str(intent_id))
            rows = connection.execute(
                f"""SELECT r.id,r.opportunity_key AS key,r.dedupe_key,r.created_at,
                          r.payload_json,i.intent_id,i.thread_id,i.worktree_path
                   FROM events r
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE r.event_type='THREAD_RECOVERY_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.recoveryNonce')=?
                     AND r.dedupe_key=?
                     {identity_clause}
                     AND (? OR NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='THREAD_RECOVERY_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                         AND {_intent_event_binding_clause("i", "sent")}
                     ))
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(
                               abandoned.payload_json,'$.reservationDigest'
                             )=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC""",
                tuple(reservation_params),
            ).fetchall()
            if worktree_path:
                rows = [
                    candidate_row
                    for candidate_row in rows
                    if candidate_row["worktree_path"]
                    and _resolved_path_equal(
                        str(candidate_row["worktree_path"]), str(worktree_path)
                    )
                ]
            if len(rows) > 1:
                raise LedgerError("recovery delivery is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                raise LedgerError("recovery delivery is not abandonable")
            minimum_age = timedelta(minutes=max(0 if allow_sent else 1, min_age_minutes))
            if parse_time(row["created_at"]) + minimum_age > current:
                raise LedgerError("recovery delivery is not old enough to abandon")
            changes_before = connection.total_changes
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{row['dedupe_key']}|{row['created_at']}"),
                {
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "recoveryNonce": nonce,
                    "reservationDigest": row["dedupe_key"],
                    "reservedAt": row["created_at"],
                    "reason": reason,
                    "minimumAgeMinutes": max(0 if allow_sent else 1, min_age_minutes),
                },
                now,
            )
            if connection.total_changes == changes_before:
                raise LedgerError("recovery abandonment binding collides with another task")

    def exhaust_recovery(
        self,
        *,
        thread_id: str,
        nonce: str,
        terminal_error: dict[str, Any] | None = None,
        retry_count: int | None = None,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Release a repeatedly interrupted recovery and make the terminal state durable."""

        with self.transaction() as connection:
            identity_clause = ""
            reservation_params: list[Any] = [thread_id, nonce, nonce]
            if intent_id:
                identity_clause = " AND i.intent_id=?"
                reservation_params.append(str(intent_id))
            rows = connection.execute(
                f"""SELECT r.opportunity_key AS key,r.dedupe_key,r.payload_json,
                          r.created_at,i.intent_id,i.thread_id,i.worktree_path
                   FROM events r
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE r.event_type='THREAD_RECOVERY_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND json_extract(r.payload_json,'$.recoveryNonce')=?
                     AND r.dedupe_key=?
                     {identity_clause}
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(
                               abandoned.payload_json,'$.reservationDigest'
                             )=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC""",
                tuple(reservation_params),
            ).fetchall()
            if worktree_path:
                rows = [
                    candidate_row
                    for candidate_row in rows
                    if candidate_row["worktree_path"]
                    and _resolved_path_equal(
                        str(candidate_row["worktree_path"]), str(worktree_path)
                    )
                ]
            if len(rows) > 1:
                raise LedgerError("exhausted recovery reservation is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                raise LedgerError("exhausted recovery reservation not found")
            reservation = json.loads(row["payload_json"])
            now = iso_z(datetime.now(UTC))
            changes_before = connection.total_changes
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_DELIVERY_ABANDONED",
                sha256_text(f"{thread_id}|{row['dedupe_key']}|{row['created_at']}"),
                {
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "recoveryNonce": nonce,
                    "reservationDigest": row["dedupe_key"],
                    "reservedAt": row["created_at"],
                    "reason": "RECOVERY_RETRY_EXHAUSTED",
                    "minimumAgeMinutes": 0,
                },
                now,
            )
            if connection.total_changes == changes_before:
                raise LedgerError("recovery exhaustion abandonment collides with another task")
            changes_before = connection.total_changes
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_RETRY_EXHAUSTED",
                nonce,
                {
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
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
            if connection.total_changes == changes_before:
                raise LedgerError("recovery exhaustion marker collides with another task")
            if reservation.get("recoveryKind") == "VALIDATION_FOLLOWUP_RESULT":
                result_digest = str(reservation.get("followupDigest") or "")
                deferred_rows = connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='TASK_RESULT_VALIDATION_DEFERRED'
                         AND json_extract(payload_json,'$.resultDigest')=?
                       ORDER BY id DESC""",
                    (row["key"], result_digest),
                ).fetchall()
                deferred_payload = None
                for deferred_row in deferred_rows:
                    try:
                        candidate_payload = json.loads(deferred_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    bound = _resolve_event_intent_binding(
                        connection,
                        opportunity_key=str(row["key"]),
                        payload=candidate_payload,
                    )
                    if bound is not None and str(bound["intent_id"]) == str(row["intent_id"]):
                        deferred_payload = candidate_payload
                        break
                if deferred_payload is not None:
                    self._event(
                        connection,
                        row["key"],
                        "VALIDATION_FOLLOWUP_NO_PROGRESS",
                        result_digest,
                        {
                            "intentId": row["intent_id"],
                            "threadId": thread_id,
                            "worktreePath": row["worktree_path"],
                            "resultDigest": result_digest,
                            "previousResultDigest": result_digest,
                            "missing": list(deferred_payload.get("missing") or []),
                            "reason": "RECOVERY_RETRY_EXHAUSTED",
                        },
                        now,
                    )

    def acknowledge_exhausted_recovery(
        self,
        *,
        thread_id: str,
        nonce: str,
        reason: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        """Park one reviewed implementation recovery without changing its task result."""

        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
            raise LedgerError("recovery acknowledgement reason must be machine-readable")
        with self.transaction() as connection:
            existing_ack_rows = connection.execute(
                f"""SELECT ack.payload_json,ack.created_at,o.key,o.issue_url,o.title,o.stage,
                          i.intent_id,i.thread_id,i.worktree_path
                   FROM events ack
                   JOIN opportunities o ON o.key=ack.opportunity_key
                   JOIN intents i ON i.opportunity_key=ack.opportunity_key
                    AND {_intent_event_binding_clause("i", "ack")}
                   WHERE ack.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                     AND ack.dedupe_key=?
                     AND json_extract(ack.payload_json,'$.threadId')=?
                     AND json_extract(ack.payload_json,'$.recoveryNonce')=?
                   ORDER BY ack.id DESC""",
                (nonce, thread_id, nonce),
            ).fetchall()
            existing_ack = None
            for ack_row in existing_ack_rows:
                if intent_id and ack_row["intent_id"] != intent_id:
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(ack_row["worktree_path"] or ""), str(worktree_path)
                ):
                    continue
                if existing_ack is not None:
                    # The same nonce must never resolve to two task bindings.
                    raise LedgerError("exhausted recovery acknowledgement is ambiguous")
                existing_ack = ack_row
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
            row_rows = connection.execute(
                f"""SELECT exhausted.id AS exhausted_id,
                          exhausted.opportunity_key AS key,
                          exhausted.payload_json AS exhausted_payload,
                          recovery.payload_json AS recovery_payload,
                          followup.payload_json AS followup_payload,
                          o.issue_url,o.title,o.stage,i.intent_id,i.thread_id,i.worktree_path
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
                    AND {_intent_event_binding_clause("i", "exhausted")}
                    AND {_intent_event_binding_clause("i", "recovery")}
                    AND {_intent_event_binding_clause("i", "followup")}
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
                         AND {_intent_event_binding_clause("i", "latest")}
                     )
                     AND recovery.id>followup.id
                     AND i.thread_id=? AND i.status='DISPATCHED'
                     AND recovery.id>(
                       SELECT COALESCE(MAX(dispatched.id),0)
                       FROM events dispatched
                       WHERE dispatched.opportunity_key=i.opportunity_key
                          AND dispatched.event_type='DISPATCHED'
                          AND dispatched.dedupe_key=i.thread_id
                          AND {_intent_event_binding_clause("i", "dispatched")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=exhausted.opportunity_key
                         AND later.id>exhausted.id
                         AND {_intent_event_binding_clause("i", "later")}
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
                   ORDER BY exhausted.id DESC""",
                (nonce, thread_id, thread_id, thread_id),
            ).fetchall()
            matching_rows = []
            for candidate_row in row_rows:
                if intent_id and candidate_row["intent_id"] != intent_id:
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(candidate_row["worktree_path"] or ""), str(worktree_path)
                ):
                    continue
                matching_rows.append(candidate_row)
            if len(matching_rows) != 1:
                raise LedgerError("active exhausted recovery not found")
            row = matching_rows[0]
            exhausted = json.loads(row["exhausted_payload"])
            recovery = json.loads(row["recovery_payload"])
            now = iso_z(datetime.now(UTC))
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED",
                nonce,
                {
                    "intentId": recovery.get("intentId"),
                    "threadId": thread_id,
                    "worktreePath": recovery.get("worktreePath"),
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
                f"""SELECT o.key,o.issue_url,o.title,o.stage,i.intent_id,i.thread_id,
                          i.worktree_path,i.status AS intent_status,
                          ack.payload_json,ack.created_at AS acknowledged_at,
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
                    AND {_intent_event_binding_clause("i", "ack")}
                    AND {_intent_event_binding_clause("i", "exhausted")}
                    AND {_intent_event_binding_clause("i", "recovery")}
                    AND {_intent_event_binding_clause("i", "followup")}
                   WHERE ack.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                     AND json_valid(ack.payload_json)=1
                     AND json_valid(exhausted.payload_json)=1
                     AND json_valid(recovery.payload_json)=1
                     AND json_valid(followup.payload_json)=1
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                     AND json_extract(followup.payload_json,'$.threadId')=
                         json_extract(ack.payload_json,'$.threadId')
                     AND followup.id=(
                       SELECT MAX(latest.id) FROM events latest
                       WHERE latest.opportunity_key=ack.opportunity_key
                         AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND {_intent_event_binding_clause("i", "latest")}
                     )
                     AND recovery.id>followup.id
                     AND NOT EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=ack.opportunity_key
                         AND later.id>ack.id
                         AND {_intent_event_binding_clause("i", "later")}
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
                             AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                             AND json_extract(later.payload_json,'$.recoveryNonce')=
                                 exhausted.dedupe_key
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
                    "rearmable": row["intent_status"] == "DISPATCHED",
                    "occupiesTaskSlot": False,
                }
            )
        return parked

    def rearm_acknowledged_recovery(
        self,
        *,
        thread_id: str,
        nonce: str,
        reason: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        """Explicitly reopen one reviewed, parked implementation recovery.

        A recovery nonce is scoped to the exact task intent.  Historical
        intents may share an issue or even a Codex thread, so every lifecycle
        event in this query is matched through the durable intent binding.
        A parked recovery is rearmable only while its original intent remains
        the active dispatched intent.  A later rollover marks the old intent
        superseded; reopening it here would create a successful-looking event
        that can never be scheduled (and could race the replacement task), so
        that case fails closed.
        """

        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
            raise LedgerError("recovery rearm reason must be machine-readable")
        with self.transaction() as connection:
            existing_rows = connection.execute(
                f"""SELECT rearmed.payload_json,rearmed.created_at,
                          o.key,o.issue_url,o.title,o.stage,
                          i.intent_id,i.status AS intent_status,i.thread_id,i.worktree_path
                   FROM events rearmed
                   JOIN opportunities o ON o.key=rearmed.opportunity_key
                   JOIN intents i ON i.opportunity_key=rearmed.opportunity_key
                   WHERE rearmed.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED'
                     AND rearmed.dedupe_key=?
                     AND json_valid(rearmed.payload_json)=1
                     AND json_extract(rearmed.payload_json,'$.threadId')=?
                     AND json_extract(rearmed.payload_json,'$.recoveryNonce')=?
                     AND {_intent_event_binding_clause("i", "rearmed")}
                   ORDER BY rearmed.id DESC""",
                (nonce, thread_id, nonce),
            ).fetchall()
            existing_matches = []
            for existing_row in existing_rows:
                if intent_id and str(existing_row["intent_id"]) != str(intent_id):
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(existing_row["worktree_path"] or ""), str(worktree_path)
                ):
                    continue
                existing_matches.append(existing_row)
            if len(existing_matches) > 1:
                raise LedgerError("parked recovery rearm is ambiguous")
            if existing_matches:
                existing_rearm = existing_matches[0]
                if existing_rearm["intent_status"] != "DISPATCHED":
                    raise LedgerError("parked recovery intent is no longer active")
                existing_payload = json.loads(existing_rearm["payload_json"])
                if existing_payload.get("reason") != reason:
                    raise LedgerError("parked recovery was rearmed with another reason")
                return {
                    "key": existing_rearm["key"],
                    "issueUrl": existing_rearm["issue_url"],
                    "title": existing_rearm["title"],
                    "stage": existing_rearm["stage"],
                    "intentId": existing_rearm["intent_id"],
                    "threadId": existing_rearm["thread_id"],
                    "worktreePath": existing_rearm["worktree_path"],
                    "recoveryNonce": nonce,
                    "recoveryKind": existing_payload.get("recoveryKind"),
                    "followupDigest": existing_payload.get("followupDigest"),
                    "reason": reason,
                    "rearmedAt": existing_rearm["created_at"],
                    "alreadyRearmed": True,
                }
            row_rows = connection.execute(
                f"""SELECT ack.id AS acknowledgement_event_id,
                          exhausted.id AS exhausted_event_id,
                          ack.opportunity_key AS key,ack.payload_json,
                          o.issue_url,o.title,o.stage,
                          i.intent_id,i.status AS intent_status,i.thread_id,i.worktree_path
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
                   WHERE ack.event_type=
                         'THREAD_RECOVERY_RETRY_EXHAUSTED_ACKNOWLEDGED'
                     AND json_valid(ack.payload_json)=1
                     AND json_valid(exhausted.payload_json)=1
                     AND json_valid(recovery.payload_json)=1
                     AND json_valid(followup.payload_json)=1
                     AND json_extract(ack.payload_json,'$.threadId')=?
                     AND json_extract(ack.payload_json,'$.recoveryNonce')=?
                     AND json_extract(recovery.payload_json,'$.recoveryKind')=
                         'IMPLEMENTATION_FOLLOWUP_RESULT'
                     AND json_extract(followup.payload_json,'$.threadId')=?
                     AND {_intent_event_binding_clause("i", "ack")}
                     AND {_intent_event_binding_clause("i", "exhausted")}
                     AND {_intent_event_binding_clause("i", "recovery")}
                     AND {_intent_event_binding_clause("i", "followup")}
                     AND followup.id=(
                       SELECT MAX(latest.id) FROM events latest
                       WHERE latest.opportunity_key=ack.opportunity_key
                         AND latest.event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND {_intent_event_binding_clause("i", "latest")}
                     )
                     AND recovery.id>followup.id
                     AND NOT EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=ack.opportunity_key
                         AND later.id>ack.id
                         AND {_intent_event_binding_clause("i", "later")}
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
                             AND json_extract(later.payload_json,'$.threadId')=i.thread_id
                             AND json_extract(later.payload_json,'$.recoveryNonce')=
                                 exhausted.dedupe_key
                           )
                         )
                     )
                   ORDER BY ack.id DESC""",
                (nonce, thread_id, nonce, thread_id),
            ).fetchall()
            matching_rows = []
            for candidate_row in row_rows:
                if intent_id and str(candidate_row["intent_id"]) != str(intent_id):
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(candidate_row["worktree_path"] or ""), str(worktree_path)
                ):
                    continue
                matching_rows.append(candidate_row)
            if len(matching_rows) != 1:
                raise LedgerError("parked exhausted recovery not found")
            row = matching_rows[0]
            if row["intent_status"] != "DISPATCHED":
                raise LedgerError("parked recovery intent is no longer active")
            acknowledged = json.loads(row["payload_json"])
            now = iso_z(datetime.now(UTC))
            self._event(
                connection,
                row["key"],
                "THREAD_RECOVERY_RETRY_EXHAUSTED_REARMED",
                nonce,
                {
                    # Persist the resolved ledger identity even when the
                    # acknowledgement came from a legacy payload without an
                    # explicit intent id.
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
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
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Record a substantive result that needs validation, not task recovery."""

        with self.transaction() as connection:
            binding = _resolve_exact_intent_binding(
                connection,
                opportunity_key=key,
                intent_id=intent_id,
                thread_id=thread_id,
                worktree_path=worktree_path,
            )
            if binding is None or binding["status"] not in {"DISPATCHED", "COMPLETED"}:
                raise LedgerError("validation-deferred task is not dispatched")
            payload: dict[str, Any] = {
                "intentId": str(binding["intent_id"]),
                "threadId": thread_id,
                "worktreePath": str(binding["worktree_path"]),
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
                intent_id=str(binding["intent_id"]),
                worktree_path=str(binding["worktree_path"]),
            )

    def record_validation_prefetch_blocked(
        self,
        *,
        key: str,
        thread_id: str,
        result_digest: str,
        dependency_failures: list[dict[str, Any]],
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Persist a failed deterministic prefetch so the scheduler does not retry forever."""

        with self.transaction() as connection:
            binding = _resolve_exact_intent_binding(
                connection,
                opportunity_key=key,
                intent_id=intent_id,
                thread_id=thread_id,
                worktree_path=worktree_path,
            )
            latest = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   ORDER BY id DESC LIMIT 1""",
                (key,),
            ).fetchone()
            deferred_payload: dict[str, Any] | None = None
            if latest is not None:
                try:
                    parsed = json.loads(latest["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    parsed = None
                if isinstance(parsed, dict):
                    deferred_binding = _resolve_event_intent_binding(
                        connection, opportunity_key=key, payload=parsed
                    )
                    if (
                        deferred_binding is not None
                        and binding is not None
                        and deferred_binding["intent_id"] == binding["intent_id"]
                        and parsed.get("threadId") == thread_id
                        and parsed.get("resultDigest") == result_digest
                    ):
                        deferred_payload = parsed
            stage = connection.execute(
                "SELECT stage FROM opportunities WHERE key=?", (key,)
            ).fetchone()
            if (
                binding is None
                or binding["status"] not in {"DISPATCHED", "COMPLETED"}
                or stage is None
                or stage["stage"]
                not in {"VALIDATION_PENDING", "PR_OPEN", "CI_GREEN", "MAINTAINER_ACCEPTED"}
                or deferred_payload is None
            ):
                raise LedgerError("validation prefetch task is not current")
            self._event(
                connection,
                key,
                "VALIDATION_PREFETCH_BLOCKED",
                result_digest,
                {
                    "intentId": str(binding["intent_id"]),
                    "threadId": thread_id,
                    "worktreePath": str(binding["worktree_path"]),
                    "resultDigest": result_digest,
                    "dependencyFailures": dependency_failures,
                },
                iso_z(datetime.now(UTC)),
            )

    def validation_prefetch_blocked(self) -> list[dict[str, Any]]:
        """Return prefetch failures that still apply to the current deferred result."""

        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,i.intent_id,i.thread_id,i.worktree_path,
                          b.payload_json,b.created_at
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                     AND i.status IN ('DISPATCHED','COMPLETED')
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                       AND {_intent_event_binding_clause("i", "d2")}
                   )
                   JOIN events b ON b.id=(
                     SELECT MAX(b2.id) FROM events b2
                     WHERE b2.opportunity_key=o.key
                       AND b2.event_type='VALIDATION_PREFETCH_BLOCKED'
                       AND {_intent_event_binding_clause("i", "b2")}
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
                    "intentId": row["intent_id"],
                    "threadId": row["thread_id"] or payload.get("threadId"),
                    "worktreePath": row["worktree_path"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> bool:
        """Stop repeat continuations when a completed continuation changed no gap."""

        normalized_missing = self._normalized_validation_missing(missing)
        if not normalized_missing:
            return False
        current_binding = _resolve_exact_intent_binding(
            connection,
            opportunity_key=key,
            intent_id=intent_id,
            thread_id=thread_id,
            worktree_path=worktree_path,
        )
        if current_binding is None:
            return False
        previous_rows = connection.execute(
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
               ORDER BY d.id DESC""",
            (key, result_digest),
        ).fetchall()
        previous = None
        previous_payload: dict[str, Any] | None = None
        for previous_row in previous_rows:
            try:
                parsed_previous = json.loads(previous_row["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(parsed_previous, dict):
                continue
            previous_binding = _resolve_event_intent_binding(
                connection, opportunity_key=key, payload=parsed_previous
            )
            if (
                previous_binding is not None
                and previous_binding["intent_id"] == current_binding["intent_id"]
            ):
                previous = previous_row
                previous_payload = parsed_previous
                break
        if previous is None or previous_payload is None:
            return False
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
                "intentId": str(current_binding["intent_id"]),
                "threadId": thread_id,
                "worktreePath": str(current_binding["worktree_path"]),
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
                f"""SELECT o.key,i.intent_id,i.thread_id,i.worktree_path,d.payload_json
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
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
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
                         AND json_extract(recovery.payload_json,'$.recoveryKind')=
                             'VALIDATION_FOLLOWUP_RESULT'
                         AND json_extract(recovery.payload_json,'$.followupDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events n
                       WHERE n.opportunity_key=o.key
                         AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                         AND {_intent_event_binding_clause("i", "n")}
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
                        "intentId": row["intent_id"],
                        "threadId": row["thread_id"] or str(payload.get("threadId") or ""),
                        "worktreePath": row["worktree_path"],
                        "resultDigest": result_digest,
                        "previousResultDigest": result_digest,
                        "missing": list(payload.get("missing") or []),
                        "reason": "RECOVERY_RETRY_EXHAUSTED",
                    },
                    iso_z(datetime.now(UTC)),
                )
                marked += 1
            rows = connection.execute(
                f"""SELECT o.key,i.intent_id,i.thread_id,i.worktree_path,d.payload_json
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
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
                         AND {_intent_event_binding_clause("i", "n")}
                         AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                     )"""
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"])
                if self._mark_validation_no_progress(
                    connection,
                    key=row["key"],
                    thread_id=row["thread_id"] or str(payload.get("threadId") or ""),
                    result_digest=str(payload.get("resultDigest") or ""),
                    missing=list(payload.get("missing") or []),
                    progress_marker=str(payload.get("progressMarker") or "") or None,
                    intent_id=row["intent_id"],
                    worktree_path=row["worktree_path"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> bool:
        """Reopen one stalled result only when controller-owned evidence changes."""

        evidence_fingerprint = sha256_text(f"{review_marker}|{reason}")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT n.id,n.payload_json,i.intent_id,i.thread_id,i.worktree_path
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
                   JOIN events n ON n.opportunity_key=o.key
                     AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                     AND {_intent_event_binding_clause("i", "n")}
                     AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                   WHERE o.key=?
                     AND json_extract(d.payload_json,'$.resultDigest')=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events active_rearm
                         WHERE active_rearm.opportunity_key=o.key
                           AND active_rearm.event_type=
                               'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                         AND {_intent_event_binding_clause("i", "active_rearm")}
                         AND json_extract(active_rearm.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND active_rearm.id>n.id
                     )
                   ORDER BY n.id DESC""",
                (key, result_digest),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if row["intent_id"] == intent_id]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            row = rows[0] if len(rows) == 1 else None
            if row is None:
                return False
            previous_rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                   ORDER BY id DESC""",
                (key,),
            ).fetchall()
            previous_payload: dict[str, Any] | None = None
            for previous in previous_rows:
                try:
                    parsed_previous = json.loads(previous["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(parsed_previous, dict):
                    continue
                previous_binding = _resolve_event_intent_binding(
                    connection, opportunity_key=key, payload=parsed_previous
                )
                if (
                    previous_binding is not None
                    and previous_binding["intent_id"] == row["intent_id"]
                ):
                    previous_payload = parsed_previous
                    break
            if previous_payload is not None:
                previous_fingerprint = str(previous_payload.get("evidenceFingerprint") or "")
                if not previous_fingerprint:
                    previous_fingerprint = sha256_text(
                        f"{previous_payload.get('reviewMarker', '')}|"
                        f"{previous_payload.get('reason', '')}"
                    )
                if previous_fingerprint == evidence_fingerprint:
                    return False
            no_progress = json.loads(row["payload_json"])
            thread_id = str(row["thread_id"] or no_progress.get("threadId") or "")
            dedupe_key = sha256_text(f"{row['id']}|{evidence_fingerprint}")
            self._event(
                connection,
                key,
                "VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
                dedupe_key,
                {
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
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
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,i.worktree_path,
                          d.payload_json,d.created_at
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                       AND {_intent_event_binding_clause("i", "d2")}
                   )
                   WHERE o.stage IN (
                     'VALIDATION_PENDING','PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED'
                   )
                     AND i.status IN ('DISPATCHED','COMPLETED')
                     AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM task_quarantines quarantine
                       WHERE quarantine.opportunity_key=o.key
                         AND quarantine.status='ACTIVE'
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events r WHERE r.opportunity_key=o.key
                         AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND {_intent_event_binding_clause("i", "r")}
                         AND json_extract(r.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=r.opportunity_key
                             AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                             AND {_intent_event_binding_clause("i", "abandoned")}
                             AND json_extract(abandoned.payload_json,'$.resultDigest')=
                                 json_extract(r.payload_json,'$.resultDigest')
                             AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                             AND abandoned.id>r.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events cancelled
                           WHERE cancelled.opportunity_key=r.opportunity_key
                             AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                             AND {_intent_event_binding_clause("i", "cancelled")}
                             AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                                 json_extract(r.payload_json,'$.reservationDigest')
                             AND cancelled.id>r.id
                         )
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=r.opportunity_key
                             AND rearmed.event_type=
                                 'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                             AND {_intent_event_binding_clause("i", "rearmed")}
                             AND json_extract(rearmed.payload_json,'$.resultDigest')=
                                 json_extract(d.payload_json,'$.resultDigest')
                             AND rearmed.id>r.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events n WHERE n.opportunity_key=o.key
                         AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                         AND {_intent_event_binding_clause("i", "n")}
                         AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
                         AND NOT EXISTS (
                           SELECT 1 FROM events rearmed
                           WHERE rearmed.opportunity_key=n.opportunity_key
                             AND rearmed.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                             AND {_intent_event_binding_clause("i", "rearmed")}
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
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,i.worktree_path,
                          d.payload_json,n.payload_json AS no_progress_json,n.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
                   JOIN events n ON n.opportunity_key=o.key
                     AND n.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS'
                     AND {_intent_event_binding_clause("i", "n")}
                     AND n.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
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
                         AND {_intent_event_binding_clause("i", "cancelled")}
                         AND json_extract(cancelled.payload_json,'$.resultDigest')=
                             json_extract(d.payload_json,'$.resultDigest')
                         AND cancelled.id>n.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rearmed
                       WHERE rearmed.opportunity_key=n.opportunity_key
                         AND rearmed.event_type='VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                         AND {_intent_event_binding_clause("i", "rearmed")}
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
                    "intentId": row["intent_id"],
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
                f"""SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,i.worktree_path,
                          d.payload_json,q.reason,q.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
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
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "resultDigest": json.loads(row["payload_json"]).get("resultDigest"),
                "missing": list(json.loads(row["payload_json"]).get("missing") or []),
                "reason": row["reason"],
                "quarantinedAt": row["created_at"],
            }
            for row in rows
        ]

    def validation_followup_was_sent(
        self,
        *,
        thread_id: str,
        key: str | None = None,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> bool:
        """Return whether this task already received a validation continuation."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT opportunity_key,payload_json FROM events
                   WHERE event_type='VALIDATION_FOLLOWUP_SENT'
                     AND json_extract(payload_json,'$.threadId')=?
                   ORDER BY id DESC""",
                (thread_id,),
            ).fetchall()
            if key is None:
                return bool(rows)
            for row in rows:
                if row["opportunity_key"] != key:
                    continue
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                binding = _resolve_event_intent_binding(
                    connection, opportunity_key=key, payload=payload
                )
                if binding is None:
                    continue
                if intent_id and binding["intent_id"] != intent_id:
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(binding["worktree_path"]), str(worktree_path)
                ):
                    continue
                return True
        return False

    def reserve_validation_followup(
        self,
        *,
        thread_id: str,
        result_digest: str,
        max_active: int | None = None,
        exclude_intent_id: str | None = None,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        candidates = [
            item
            for item in self.validation_followup_candidates()
            if item["threadId"] == thread_id and item["resultDigest"] == result_digest
        ]
        if intent_id:
            candidates = [item for item in candidates if item.get("intentId") == intent_id]
        if worktree_path:
            candidates = [
                item
                for item in candidates
                if item.get("worktreePath")
                and _resolved_path_equal(str(item["worktreePath"]), str(worktree_path))
            ]
        candidate = candidates[0] if len(candidates) == 1 else None
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
            prior_rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(payload_json,'$.threadId')=?
                     AND json_extract(payload_json,'$.resultDigest')=?""",
                (candidate["key"], thread_id, result_digest),
            ).fetchall()
            prior_attempts = 0
            for prior_row in prior_rows:
                try:
                    prior_payload = json.loads(prior_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                prior_binding = _resolve_event_intent_binding(
                    connection, opportunity_key=str(candidate["key"]), payload=prior_payload
                )
                if (
                    prior_binding is not None
                    and prior_binding["intent_id"] == candidate["intentId"]
                ):
                    prior_attempts += 1
            attempt = prior_attempts + 1
            reservation_digest = sha256_text(
                f"{candidate['key']}|{candidate['intentId']}|{thread_id}|"
                f"{candidate['worktreePath']}|{result_digest}|attempt:{attempt}"
            )
            self._event(
                connection,
                candidate["key"],
                "VALIDATION_FOLLOWUP_RESERVED",
                reservation_digest,
                {
                    "intentId": candidate["intentId"],
                    "threadId": thread_id,
                    "worktreePath": candidate["worktreePath"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT o.key,r.payload_json,r.id FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND {_intent_event_binding_clause("i", "r")}
                     AND json_extract(r.payload_json,'$.resultDigest')=?
                     AND (? IS NULL OR json_extract(r.payload_json,'$.reservationDigest')=?)
                   WHERE i.thread_id=?
                     AND i.status IN ('DISPATCHED','COMPLETED')
                     AND NOT EXISTS (
                       SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                         AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND {_intent_event_binding_clause("i", "s")}
                         AND s.dedupe_key=?
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=r.opportunity_key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND {_intent_event_binding_clause("i", "cancelled")}
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND cancelled.id>r.id
                     )
                   ORDER BY r.id DESC""",
                (result_digest, reservation_digest, reservation_digest, thread_id, result_digest),
            ).fetchall()
            filtered_rows: list[sqlite3.Row] = []
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                if intent_id and payload.get("intentId") != intent_id:
                    continue
                if worktree_path and not payload.get("worktreePath"):
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(payload.get("worktreePath")), str(worktree_path)
                ):
                    continue
                filtered_rows.append(row)
            row = filtered_rows[0] if len(filtered_rows) == 1 else None
            if row is None:
                sent_rows = connection.execute(
                    f"""SELECT r.payload_json,s.payload_json AS sent_payload FROM events r
                       JOIN intents i ON i.opportunity_key=r.opportunity_key
                        AND i.thread_id=?
                        AND i.status IN ('DISPATCHED','COMPLETED')
                        AND {_intent_event_binding_clause("i", "r")}
                       JOIN events s ON s.opportunity_key=r.opportunity_key
                        AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                        AND {_intent_event_binding_clause("i", "s")}
                        AND s.dedupe_key=?
                       WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=i.thread_id
                         AND json_extract(r.payload_json,'$.resultDigest')=?
                         AND (? IS NULL OR json_extract(r.payload_json,'$.reservationDigest')=?)
                       ORDER BY r.id DESC""",
                    (
                        thread_id,
                        result_digest,
                        result_digest,
                        reservation_digest,
                        reservation_digest,
                    ),
                ).fetchall()
                sent = False
                for sent_row in sent_rows:
                    try:
                        sent_payload = json.loads(sent_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if intent_id and sent_payload.get("intentId") != intent_id:
                        continue
                    if worktree_path and not sent_payload.get("worktreePath"):
                        continue
                    if worktree_path and not _resolved_path_equal(
                        str(sent_payload.get("worktreePath")), str(worktree_path)
                    ):
                        continue
                    sent = True
                    break
                if sent:
                    return
                raise LedgerError(
                    "validation follow-up reservation is missing or already committed"
                )
            reservation_payload = json.loads(row["payload_json"] or "{}")
            self._event(
                connection,
                row["key"],
                "VALIDATION_FOLLOWUP_SENT",
                result_digest,
                {
                    "intentId": reservation_payload.get("intentId"),
                    "threadId": thread_id,
                    "worktreePath": reservation_payload.get("worktreePath"),
                    "resultDigest": result_digest,
                },
                now,
            )

    def unresolved_validation_followups(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.issue_url,i.intent_id,i.thread_id,i.worktree_path,
                          r.payload_json,r.created_at,r.dedupe_key
                   FROM opportunities o
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "r")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                       AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                       AND {_intent_event_binding_clause("i", "s")}
                       AND s.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=r.opportunity_key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND {_intent_event_binding_clause("i", "cancelled")}
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND cancelled.id>r.id
                     ) ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "intentId": row["intent_id"],
                "worktreePath": row["worktree_path"],
                "threadId": row["thread_id"] or json.loads(row["payload_json"]).get("threadId"),
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Retire an old reservation when no target task turn materialized."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT r.id,r.opportunity_key AS key,r.dedupe_key,r.created_at,
                          i.intent_id,i.worktree_path
                   FROM events r
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND i.thread_id=?
                     AND i.status IN ('DISPATCHED','COMPLETED')
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=i.thread_id
                     AND json_extract(r.payload_json,'$.resultDigest')=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND {_intent_event_binding_clause("i", "sent")}
                         AND sent.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC""",
                (thread_id, result_digest),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if row["intent_id"] == intent_id]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            row = rows[0] if len(rows) == 1 else None
            if row is None:
                raise LedgerError("validation follow-up delivery is not abandonable")
            minimum_age = timedelta(minutes=max(1, min_age_minutes))
            if parse_time(row["created_at"]) + minimum_age > current:
                raise LedgerError("validation follow-up delivery is not old enough to abandon")
            self._event(
                connection,
                row["key"],
                "VALIDATION_FOLLOWUP_DELIVERY_ABANDONED",
                sha256_text(
                    f"{row['key']}|{row['intent_id']}|{thread_id}|{result_digest}|"
                    f"{row['created_at']}"
                ),
                {
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Immediately invalidate the latest unstarted validation reservation."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT r.id,r.opportunity_key AS key,r.dedupe_key,r.created_at,
                          i.intent_id,i.worktree_path
                   FROM events r
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND i.thread_id=?
                     AND i.status IN ('DISPATCHED','COMPLETED')
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=i.thread_id
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
                         AND {_intent_event_binding_clause("i", "sent")}
                         AND sent.dedupe_key=json_extract(r.payload_json,'$.resultDigest')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(abandoned.payload_json,'$.resultDigest')=
                             json_extract(r.payload_json,'$.resultDigest')
                         AND json_extract(abandoned.payload_json,'$.reservedAt')=r.created_at
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=r.opportunity_key
                         AND cancelled.event_type='VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND {_intent_event_binding_clause("i", "cancelled")}
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND cancelled.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events started
                       WHERE started.opportunity_key=r.opportunity_key
                         AND started.event_type='TASK_TURN_DELIVERY_STARTED'
                         AND {_intent_event_binding_clause("i", "started")}
                         AND json_extract(started.payload_json,'$.deliveryKind')='validation-followup'
                         AND json_extract(started.payload_json,'$.reservationDigest')=
                             json_extract(r.payload_json,'$.reservationDigest')
                         AND started.id>r.id
                     )
                   ORDER BY r.id DESC""",
                (thread_id, result_digest, reservation_digest),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if row["intent_id"] == intent_id]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            row = rows[0] if len(rows) == 1 else None
            if row is None:
                raise LedgerError("validation follow-up reservation is not cancellable")
            self._event(
                connection,
                row["key"],
                "VALIDATION_FOLLOWUP_RESERVATION_CANCELLED",
                sha256_text(f"cancelled|{reservation_digest}"),
                {
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
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
                f"""SELECT o.key,o.issue_url,i.intent_id,i.thread_id,i.worktree_path,
                          d.payload_json,s.created_at
                   FROM opportunities o
                   JOIN events d ON d.id=(
                     SELECT MAX(d2.id) FROM events d2
                     WHERE d2.opportunity_key=o.key
                       AND d2.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                   )
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "d")}
                     AND i.status IN ('DISPATCHED','COMPLETED')
                   JOIN events s ON s.opportunity_key=o.key
                     AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                     AND {_intent_event_binding_clause("i", "s")}
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
                         AND {_intent_event_binding_clause("i", "result")}
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
                         AND {_intent_event_binding_clause("i", "exhausted")}
                         AND {_intent_event_binding_clause("i", "recovery")}
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
                "intentId": row["intent_id"],
                "threadId": row["thread_id"] or json.loads(row["payload_json"]).get("threadId"),
                "worktreePath": row["worktree_path"],
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
        intent_id: str | None = None,
    ) -> dict[str, Any] | None:
        clauses = ["o.issue_url=?"]
        params: list[Any] = [issue_url]
        if intent_id:
            clauses.append("i.intent_id=?")
            params.append(intent_id)
        if thread_id:
            clauses.append("i.thread_id=?")
            params.append(thread_id)
        if worktree_path:
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
            rows = connection.execute(
                f"""SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                           i.worktree_path,i.status,i.payload_json,i.title_time
                    FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                    WHERE {" AND ".join(clauses)}
                    ORDER BY i.updated_at DESC,i.intent_id DESC""",
                tuple(params),
            ).fetchall()
            # A thread or worktree can be reused by a later intent.  Without
            # an explicit intent id, project only a uniquely provable binding;
            # selecting the newest row would silently cross-wire lifecycle
            # results after a rollover.
            row = rows[0] if len(rows) == 1 else None
            audit_rows = (
                _intent_bound_audit_rows(connection, row["key"], row["intent_id"])
                if row is not None
                else []
            )
            audit_row = audit_rows[0] if audit_rows else None
            publication_worktree_values: tuple[str, ...] = ()
            if row is not None and row["worktree_path"]:
                raw_publication_worktree = str(row["worktree_path"])
                try:
                    resolved_publication_worktree = str(Path(raw_publication_worktree).resolve())
                except (OSError, RuntimeError):
                    resolved_publication_worktree = raw_publication_worktree
                publication_worktree_values = tuple(
                    dict.fromkeys((raw_publication_worktree, resolved_publication_worktree))
                )
            # ``taskId`` is the legacy spelling of the immutable intent id in
            # a few pre-v5 publication snapshots.  Resolve both aliases from
            # one guarded JSON object and reject a payload that carries two
            # disagreeing ids; otherwise a request for an older generation
            # could be projected onto the newer task merely because its SQL
            # row happens to share the same thread/worktree.
            request_json_object = (
                "CASE WHEN json_valid(r.request_json)=1 THEN r.request_json ELSE '{}' END"
            )
            request_intent_expr = f"json_extract({request_json_object},'$.intentId')"
            request_task_expr = f"json_extract({request_json_object},'$.taskId')"
            request_identity_expr = f"COALESCE({request_intent_expr},{request_task_expr})"
            publication_row = (
                connection.execute(
                    f"""SELECT r.status AS request_status,r.commit_sha,r.branch,
                              r.created_at AS requested_at,r.updated_at AS request_updated_at,
                              p.status AS permit_status,p.pr_url,
                              p.updated_at AS permit_updated_at
                       FROM publication_requests r
                       LEFT JOIN publication_permits p ON p.request_id=r.request_id
                       WHERE r.opportunity_key=?
                         AND r.thread_id=?
                         AND r.worktree_path IN (
                           {",".join("?" for _ in publication_worktree_values) or "NULL"}
                         )
                         AND json_valid(r.request_json)=1
                         AND (
                           json_extract(r.request_json,'$.threadId') IS NULL
                           OR json_extract(r.request_json,'$.threadId')=r.thread_id
                         )
                         AND (
                           json_extract(r.request_json,'$.worktreePath') IS NULL
                           OR json_extract(r.request_json,'$.worktreePath') IN (
                             {",".join("?" for _ in publication_worktree_values) or "NULL"}
                           )
                         )
                         AND (
                           (
                             {request_identity_expr}=?
                             AND (
                               json_type({request_json_object},'$.intentId') IS NULL
                               OR json_type({request_json_object},'$.intentId')='null'
                               OR (
                                 json_type({request_json_object},'$.intentId')='text'
                                 AND {request_intent_expr}<>''
                               )
                             )
                             AND (
                               json_type({request_json_object},'$.taskId') IS NULL
                               OR json_type({request_json_object},'$.taskId')='null'
                               OR (
                                 json_type({request_json_object},'$.taskId')='text'
                                 AND {request_task_expr}<>''
                               )
                             )
                             AND NOT (
                               COALESCE(
                                 json_type({request_json_object},'$.intentId')='text',
                                 0
                               )
                               AND COALESCE(
                                 json_type({request_json_object},'$.taskId')='text',
                                 0
                               )
                               AND COALESCE(
                                 {request_intent_expr}<>{request_task_expr},
                                 0
                               )
                             )
                           )
                           OR (
                             {request_intent_expr} IS NULL
                             AND {request_task_expr} IS NULL
                             AND NOT EXISTS (
                               SELECT 1 FROM intents other
                               WHERE other.opportunity_key=r.opportunity_key
                                 AND other.thread_id=r.thread_id
                                 AND other.worktree_path IN (
                                   {",".join("?" for _ in publication_worktree_values) or "NULL"}
                                 )
                                 AND other.intent_id<>?
                             )
                           )
                         )
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
                    (
                        row["key"],
                        row["thread_id"],
                        *publication_worktree_values,
                        *publication_worktree_values,
                        row["intent_id"],
                        *publication_worktree_values,
                        row["intent_id"],
                    ),
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
            followup_binding_schema_present = _pr_followup_binding_columns_present(connection)
            if followup_row is not None and not followup_binding_schema_present:
                # A read-only view of an old ledger must not project an
                # opportunity-wide wake into an arbitrary historical task.
                followup_row = None
            elif followup_row is not None:
                # A follow-up observation belongs to one immutable task
                # identity.  Partial/NULL bindings are ambiguous (especially
                # after an opportunity rollover) and must never be projected
                # into an arbitrary historical task.  The additive migration
                # backfills legacy rows only when it can prove one exact
                # identity; everything else fails closed until a fresh exact
                # observation repairs it.
                if any(
                    followup_row[field] is None
                    for field in ("intent_id", "thread_id", "worktree_path")
                ) or (
                    followup_row["intent_id"] != row["intent_id"]
                    or followup_row["thread_id"] != row["thread_id"]
                    or followup_row["worktree_path"] != row["worktree_path"]
                ):
                    followup_row = None
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
                    f"""WITH current_intent AS (
                         SELECT * FROM intents
                          WHERE opportunity_key=? AND intent_id=?
                       ), latest_preparation AS (
                         SELECT e.id,e.opportunity_key,e.dedupe_key,e.payload_json
                         FROM events e
                         JOIN current_intent ci
                           ON ci.opportunity_key=e.opportunity_key
                         WHERE e.opportunity_key=?
                           AND e.event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                           AND {_intent_event_binding_clause("ci", "e")}
                         ORDER BY e.id DESC LIMIT 1
                       )
                       SELECT b.payload_json FROM latest_preparation b
                       CROSS JOIN current_intent ci
                       WHERE NOT (? > b.id)
                         AND NOT EXISTS (
                           SELECT 1 FROM events x
                           WHERE x.opportunity_key=b.opportunity_key
                             AND (
                               (x.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                                AND x.dedupe_key=b.dedupe_key
                                AND {_intent_event_binding_clause("ci", "x")})
                               OR
                               (x.event_type=
                                  'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND'
                                AND json_extract(
                                  x.payload_json,'$.followupWakeDigest'
                                )=b.dedupe_key
                                AND json_extract(x.payload_json,'$.threadId')=
                                    json_extract(b.payload_json,'$.threadId')
                                AND {_intent_event_binding_clause("ci", "x")})
                               OR
                               (x.event_type=
                                  'TASK_CONTEXT_TOMBSTONE_CONTINUATION_BOUND'
                               AND json_extract(
                                  x.payload_json,'$.followupWakeDigest'
                                )=b.dedupe_key
                                AND json_extract(x.payload_json,'$.threadId')=
                                    json_extract(b.payload_json,'$.threadId')
                                AND x.dedupe_key=?
                                AND {_intent_event_binding_clause("ci", "x")})
                               OR
                               (x.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                                AND json_extract(x.payload_json,'$.wakeDigest')=
                                    b.dedupe_key
                                AND json_extract(x.payload_json,'$.threadId')=
                                    json_extract(b.payload_json,'$.threadId')
                                AND {_intent_event_binding_clause("ci", "x")})
                             )
                         )""",
                    (
                        row["key"],
                        row["intent_id"],
                        row["key"],
                        active_context_authority_origin_id,
                        active_context_continuation_ref,
                    ),
                ).fetchone()
                if row is not None
                else None
            )
            latest_task_result_row = (
                connection.execute(
                    f"""WITH current_intent AS (
                         SELECT * FROM intents
                          WHERE opportunity_key=? AND intent_id=?
                       ), result_candidates AS (
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
                         CROSS JOIN current_intent ci
                         WHERE result2.opportunity_key=?
                           AND result2.event_type='TASK_RESULT_INGESTED'
                           AND (
                             ({_intent_event_binding_clause("ci", "result2")})
                             OR (
                               json_valid(result2.payload_json)=1
                               AND json_extract(result2.payload_json,'$.intentId') IS NULL
                               AND json_extract(result2.payload_json,'$.taskId') IS NULL
                               AND EXISTS (
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
                                   AND {_intent_event_binding_clause("ci", "binding")}
                               )
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
                       CROSS JOIN current_intent ci
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
                           AND {_intent_event_binding_clause("ci", "continuation2")}
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
                        row["key"],
                        row["intent_id"],
                        row["intent_id"],
                        row["thread_id"],
                        row["key"],
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
        if audit_payload.get("missingWorktreeRevalidation") is True:
            result["missingWorktreeRevalidation"] = True
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
        # A receipt digest is content identity, not task identity: two intent
        # generations can legitimately produce the same digest. Never let a
        # matching digest from another generation authorize this task's paths.
        candidates = bound_audit_rows
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
                     AND json_extract(
                           CASE WHEN json_valid(t.provenance_json)=1
                                THEN t.provenance_json ELSE '{}' END,
                           '$.probeReceipt.resultDigest'
                         )=?
                     AND json_extract(
                           CASE WHEN json_valid(t.provenance_json)=1
                                THEN t.provenance_json ELSE '{}' END,
                           '$.probeReceipt.receiptDigest'
                         )=
                         json_extract(
                           CASE WHEN json_valid(t.provenance_json)=1
                                THEN t.provenance_json ELSE '{}' END,
                           '$.probeReceiptDigest'
                         )""",
                (task_id, key, thread_id, result_digest),
            ).fetchone()
            reproduction = None
            for result_row in connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                     AND dedupe_key=?
                   ORDER BY id DESC""",
                (key, result_digest),
            ).fetchall():
                try:
                    result_payload = json.loads(result_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(result_payload, dict) or result_payload.get("stage") != (
                    "IMPLEMENTATION_READY"
                ):
                    continue
                if result_payload.get("resultDigest") not in {None, result_digest}:
                    continue
                result_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=result_payload,
                )
                if (
                    result_binding is not None
                    and str(result_binding["intent_id"]) == task_id
                    and str(result_binding["thread_id"] or "") == thread_id
                    and result_binding["worktree_path"] is not None
                    and _resolved_path_equal(str(result_binding["worktree_path"]), worktree_path)
                ):
                    reproduction = result_row
                    break
            sent = None
            for sent_row in connection.execute(
                """SELECT id,dedupe_key,payload_json FROM events
                   WHERE opportunity_key=? AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     AND (
                       dedupe_key=?
                       OR json_extract(
                            CASE WHEN json_valid(payload_json)=1
                                 THEN payload_json ELSE '{}' END,
                            '$.resultDigest'
                          )=?
                     )
                   ORDER BY id DESC""",
                (key, result_digest, result_digest),
            ).fetchall():
                if _implementation_followup_event_matches_identity(
                    connection,
                    opportunity_key=key,
                    row=sent_row,
                    candidate={
                        "intentId": task_id,
                        "threadId": thread_id,
                        "worktreePath": worktree_path,
                    },
                    result_digest=result_digest,
                ):
                    sent = sent_row
                    break
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
        tasks = self.task_context_candidates()
        with self.connect() as connection:
            for task in tasks:
                intent = task.get("intent") or {}
                if (
                    task.get("intentStatus") != "DISPATCHED"
                    or intent.get("taskStage") != "IMPLEMENTATION_READY"
                    or intent.get("probeLevel") != "REPRODUCED_VALIDATED"
                    or not intent.get("probeReceiptDigest")
                ):
                    continue
                reproduction = None
                for result_row in connection.execute(
                    """SELECT id,dedupe_key,payload_json,created_at FROM events
                       WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                       ORDER BY id DESC""",
                    (task["key"],),
                ).fetchall():
                    try:
                        result_payload = json.loads(result_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if (
                        not isinstance(result_payload, dict)
                        or result_payload.get("stage") != "IMPLEMENTATION_READY"
                    ):
                        continue
                    bound = _resolve_event_intent_binding(
                        connection,
                        opportunity_key=str(task["key"]),
                        payload=result_payload,
                    )
                    if bound is None or str(bound["intent_id"]) != str(task["intentId"]):
                        continue
                    if bound["thread_id"] != task["threadId"] or not _resolved_path_equal(
                        str(bound["worktree_path"]), str(task["worktreePath"])
                    ):
                        continue
                    reproduction = result_row
                    break
                if reproduction is None:
                    continue
                result_digest = str(reproduction["dedupe_key"] or "")
                if not result_digest:
                    continue
                sent = None
                for sent_row in connection.execute(
                    """SELECT id,dedupe_key,payload_json FROM events
                       WHERE opportunity_key=? AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                       ORDER BY id DESC""",
                    (task["key"],),
                ).fetchall():
                    try:
                        sent_payload = json.loads(sent_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(sent_payload, dict):
                        continue
                    if not (
                        str(sent_row["dedupe_key"] or "") == result_digest
                        or sent_payload.get("resultDigest") == result_digest
                    ):
                        continue
                    bound = _resolve_event_intent_binding(
                        connection,
                        opportunity_key=str(task["key"]),
                        payload=sent_payload,
                    )
                    if bound is None or str(bound["intent_id"]) != str(task["intentId"]):
                        continue
                    sent = sent_row
                    break
                reserved = None
                for reserved_row in connection.execute(
                    """SELECT id,dedupe_key,payload_json FROM events
                       WHERE opportunity_key=? AND event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                       ORDER BY id DESC""",
                    (task["key"],),
                ).fetchall():
                    try:
                        reserved_payload = json.loads(reserved_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(reserved_payload, dict):
                        continue
                    if not (
                        str(reserved_row["dedupe_key"] or "") == result_digest
                        or reserved_payload.get("resultDigest") == result_digest
                    ):
                        continue
                    bound = _resolve_event_intent_binding(
                        connection,
                        opportunity_key=str(task["key"]),
                        payload=reserved_payload,
                    )
                    if bound is None or str(bound["intent_id"]) != str(task["intentId"]):
                        continue
                    reserved = reserved_row
                    break
                repair = None
                for repair_row in connection.execute(
                    """SELECT id,dedupe_key,payload_json FROM events
                       WHERE opportunity_key=? AND event_type='IMPLEMENTATION_CONTEXT_REPAIRED'
                       ORDER BY id DESC""",
                    (task["key"],),
                ).fetchall():
                    try:
                        repair_payload = json.loads(repair_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if not isinstance(repair_payload, dict):
                        continue
                    if repair_payload.get("resultDigest") != result_digest:
                        continue
                    bound = _resolve_event_intent_binding(
                        connection,
                        opportunity_key=str(task["key"]),
                        payload=repair_payload,
                    )
                    if bound is None or str(bound["intent_id"]) != str(task["intentId"]):
                        continue
                    repair = repair_row
                    break
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
        self,
        *,
        thread_id: str,
        result_digest: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        if intent_id is not None and (not isinstance(intent_id, str) or not intent_id):
            raise LedgerError("implementation follow-up intent binding is invalid")
        if worktree_path is not None and (not isinstance(worktree_path, str) or not worktree_path):
            raise LedgerError("implementation follow-up worktree binding is invalid")
        candidates = [
            item
            for item in self.implementation_followup_candidates()
            if item.get("threadId") == thread_id and item.get("resultDigest") == result_digest
        ]
        if intent_id is not None:
            candidates = [item for item in candidates if item.get("intentId") == intent_id]
        if worktree_path is not None:
            candidates = [
                item
                for item in candidates
                if item.get("worktreePath")
                and _resolved_path_equal(str(item["worktreePath"]), worktree_path)
            ]
        if len(candidates) != 1:
            raise LedgerError("implementation follow-up authorization is stale or invalid")
        candidate = candidates[0]
        now = iso_z(datetime.now(UTC))
        payload = {
            "intentId": candidate["intentId"],
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
            attempt_digest = str(candidate["implementationFollowupAttemptDigest"])
            existing = connection.execute(
                """SELECT id,created_at,payload_json,dedupe_key FROM events
                   WHERE opportunity_key=?
                     AND event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                     AND dedupe_key=?""",
                (str(candidate["key"]), attempt_digest),
            ).fetchone()
            if existing is not None:
                if _implementation_followup_event_matches_identity(
                    connection,
                    opportunity_key=str(candidate["key"]),
                    row=existing,
                    candidate=candidate,
                    result_digest=result_digest,
                    attempt_digest=attempt_digest,
                ):
                    return candidate | payload | {"reservedAt": existing["created_at"]}
                raise LedgerError(
                    "implementation follow-up reservation is stale or invalid: "
                    "dedupe key is bound to another intent"
                )
            self._event(
                connection,
                str(candidate["key"]),
                "IMPLEMENTATION_FOLLOWUP_RESERVED",
                attempt_digest,
                payload,
                now,
            )
        return candidate | payload | {"reservedAt": now}

    def unresolved_implementation_followups(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT r.id,r.opportunity_key,r.dedupe_key,r.payload_json,r.created_at,
                          o.issue_url
                   FROM events r
                   JOIN opportunities o ON o.key=r.opportunity_key
                   WHERE r.event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                   ORDER BY r.id"""
            ).fetchall()
            unresolved: list[dict[str, Any]] = []
            for row in rows:
                try:
                    reservation = json.loads(row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(reservation, dict):
                    continue
                binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=str(row["opportunity_key"]),
                    payload=reservation,
                )
                if binding is None or binding["status"] != "DISPATCHED":
                    continue
                sent = False
                for sent_row in connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                         AND dedupe_key=?
                       ORDER BY id DESC""",
                    (row["opportunity_key"], row["dedupe_key"]),
                ).fetchall():
                    try:
                        sent_payload = json.loads(sent_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        continue
                    sent_binding = _resolve_event_intent_binding(
                        connection,
                        opportunity_key=str(row["opportunity_key"]),
                        payload=sent_payload,
                    )
                    if sent_binding is not None and str(sent_binding["intent_id"]) == str(
                        binding["intent_id"]
                    ):
                        sent = True
                        break
                if sent:
                    continue
                unresolved.append(
                    {
                        "key": row["opportunity_key"],
                        "issueUrl": row["issue_url"],
                        "intentId": binding["intent_id"],
                        "threadId": binding["thread_id"],
                        "worktreePath": binding["worktree_path"],
                        "resultDigest": str(reservation.get("resultDigest") or row["dedupe_key"]),
                        "implementationFollowupAttemptDigest": row["dedupe_key"],
                        "reservedAt": row["created_at"],
                        "reservation": reservation,
                    }
                )
        return unresolved

    def commit_implementation_followup(
        self,
        *,
        thread_id: str,
        result_digest: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        if intent_id is not None and (not isinstance(intent_id, str) or not intent_id):
            raise LedgerError("implementation follow-up intent binding is invalid")
        if worktree_path is not None and (not isinstance(worktree_path, str) or not worktree_path):
            raise LedgerError("implementation follow-up worktree binding is invalid")
        candidates = [
            item
            for item in self.unresolved_implementation_followups()
            if item.get("threadId") == thread_id and item.get("resultDigest") == result_digest
        ]
        if intent_id is not None:
            candidates = [item for item in candidates if item.get("intentId") == intent_id]
        if worktree_path is not None:
            candidates = [
                item
                for item in candidates
                if item.get("worktreePath")
                and _resolved_path_equal(str(item["worktreePath"]), worktree_path)
            ]
        if len(candidates) != 1:
            raise LedgerError("implementation follow-up reservation is unavailable")
        candidate = candidates[0]
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            attempt_digest = str(candidate["implementationFollowupAttemptDigest"])
            existing = connection.execute(
                """SELECT id,created_at,payload_json,dedupe_key FROM events
                   WHERE opportunity_key=?
                     AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'
                     AND dedupe_key=?""",
                (str(candidate["key"]), attempt_digest),
            ).fetchone()
            if existing is not None:
                if _implementation_followup_event_matches_identity(
                    connection,
                    opportunity_key=str(candidate["key"]),
                    row=existing,
                    candidate=candidate,
                    result_digest=result_digest,
                    attempt_digest=attempt_digest,
                ):
                    return
                raise LedgerError(
                    "implementation follow-up reservation is unavailable: "
                    "dedupe key is bound to another intent"
                )
            self._event(
                connection,
                str(candidate["key"]),
                "IMPLEMENTATION_FOLLOWUP_SENT",
                attempt_digest,
                {
                    "intentId": candidate["intentId"],
                    "threadId": thread_id,
                    "worktreePath": candidate["worktreePath"],
                    "resultDigest": result_digest,
                    "attemptDigest": attempt_digest,
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

    def reset_dispatch_for_retry(
        self,
        *,
        thread_id: str,
        reason: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT i.intent_id,i.opportunity_key,i.status,i.expires_at,
                          i.worktree_path,o.stage,o.issue_url,o.title,i.payload_json
                   FROM intents i JOIN opportunities o ON o.key=i.opportunity_key
                   WHERE i.thread_id=?""",
                (thread_id,),
            ).fetchall()
            if len(rows) > 1 and (not intent_id or not worktree_path):
                raise LedgerError("dispatch retry task identity is ambiguous")
            if intent_id:
                rows = [row for row in rows if str(row["intent_id"]) == str(intent_id)]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            if len(rows) > 1:
                raise LedgerError("dispatch retry task identity is ambiguous")
            row = rows[0] if rows else None
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

    @staticmethod
    def _task_result_candidate_query(*, latest_only: bool) -> str:
        latest_clause = ""
        if latest_only:
            latest_clause = (
                "AND i.rowid=("
                "SELECT MAX(current.rowid) FROM intents current "
                "WHERE current.opportunity_key=o.key"
                ")"
            )
        return f"""SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path,i.status,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     {latest_clause}
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

    def task_result_candidates(self) -> list[dict[str, Any]]:
        """Return the broad historical audit set of thread-bound task results.

        This intentionally includes older intents so independent review can
        inspect retained historical worktrees.  Operational ingestion uses
        :meth:`task_result_candidates_for_ingestion`, which projects only the
        current intent and applies the identity gate after reading the result.
        """

        with self.connect() as connection:
            rows = connection.execute(
                self._task_result_candidate_query(latest_only=False)
            ).fetchall()
        return self._task_result_candidates_from_rows(rows)

    def task_result_candidates_for_ingestion(self) -> list[dict[str, Any]]:
        """Return only the current, structurally bound task-result candidates."""

        with self.connect() as connection:
            rows = connection.execute(
                self._task_result_candidate_query(latest_only=True)
            ).fetchall()
        return self._task_result_candidates_from_rows(rows)

    def task_result_binding_gate(
        self,
        candidate: dict[str, Any],
        value: Any,
    ) -> bool:
        """Verify a result envelope belongs to one exact candidate intent.

        ``taskId``/``intentId`` are optional for legacy result files.  When
        omitted, the candidate's key/thread/worktree tuple must identify one
        and only one intent in the ledger.  Any malformed or conflicting
        identity is rejected instead of being guessed from the newest row.
        """

        if not isinstance(candidate, dict) or not isinstance(value, dict):
            return False
        key = str(candidate.get("key") or "")
        intent_id = str(candidate.get("intentId") or "")
        thread_id = str(candidate.get("threadId") or "")
        worktree_path = str(candidate.get("worktreePath") or "")
        issue_url = str(candidate.get("issueUrl") or "")
        if not all((key, intent_id, thread_id, worktree_path, issue_url)):
            return False
        if (
            value.get("key") != key
            or value.get("issueUrl") != issue_url
            or value.get("threadId") != thread_id
            or not isinstance(value.get("worktreePath"), str)
            or not _resolved_path_equal(worktree_path, str(value["worktreePath"]))
        ):
            return False
        explicit_values: list[str] = []
        for field in ("taskId", "intentId"):
            if field not in value or value[field] is None:
                continue
            if not isinstance(value[field], str) or not value[field]:
                return False
            explicit_values.append(value[field])
        if explicit_values and any(item != explicit_values[0] for item in explicit_values[1:]):
            return False
        if explicit_values and explicit_values[0] != intent_id:
            return False
        with self.connect() as connection:
            binding = _resolve_exact_intent_binding(
                connection,
                opportunity_key=key,
                intent_id=intent_id,
                thread_id=thread_id,
                worktree_path=worktree_path,
            )
            if binding is None:
                return False
            if explicit_values:
                return True
            # A legacy envelope without an immutable id is safe only when no
            # other historical intent shares this exact task identity.
            rows = connection.execute(
                """SELECT intent_id,worktree_path FROM intents
                   WHERE opportunity_key=? AND thread_id=? AND worktree_path IS NOT NULL""",
                (key, thread_id),
            ).fetchall()
            matching = [
                row
                for row in rows
                if _resolved_path_equal(str(row["worktree_path"]), worktree_path)
            ]
            return len(matching) == 1 and str(matching[0]["intent_id"]) == intent_id

    def local_receipt_candidates(self) -> list[dict[str, Any]]:
        """Return only tasks that the fast local receipt worker should inspect."""

        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path,i.status,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND i.rowid=(
                       SELECT MAX(current.rowid) FROM intents current
                       WHERE current.opportunity_key=o.key
                     )
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
                             AND {_intent_event_binding_clause("i", "sent")}
                             AND NOT EXISTS (
                               SELECT 1 FROM events result
                               WHERE result.opportunity_key=o.key
                                 AND (
                                   (
                                     result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                                     AND result.dedupe_key=sent.dedupe_key
                                   )
                                   OR (
                                     result.event_type='PUBLISHED_TASK_RESULT_BACKFILLED'
                                     AND json_extract(result.payload_json,'$.stage') IN (
                                       'PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED','MERGED'
                                     )
                                   )
                                 )
                                 AND result.id>sent.id
                                 AND {_intent_event_binding_clause("i", "result")}
                             )
                             AND NOT EXISTS (
                               SELECT 1 FROM events abandoned
                               WHERE abandoned.opportunity_key=o.key
                                 AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                                 AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                     sent.dedupe_key
                                 AND abandoned.id>sent.id
                                 AND {_intent_event_binding_clause("i", "abandoned")}
                             )
                         )
                       )
                       OR (
                         o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                         AND EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=o.key
                             AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                             AND json_extract(sent.payload_json,'$.threadId')=i.thread_id
                             AND {_intent_event_binding_clause("i", "sent")}
                             AND NOT EXISTS (
                               SELECT 1 FROM events result
                               WHERE result.opportunity_key=sent.opportunity_key
                                 AND result.event_type IN (
                                   'TASK_RESULT_INGESTED',
                                   'PUBLISHED_TASK_RESULT_BACKFILLED'
                                 )
                                 AND result.id>sent.id
                                 AND (
                                   (
                                     {_intent_event_binding_clause("i", "result")}
                                     AND json_extract(result.payload_json,'$.threadId')=
                                         i.thread_id
                                   )
                                   OR (
                                     result.event_type='TASK_RESULT_INGESTED'
                                     AND json_valid(result.payload_json)=1
                                     AND COALESCE(
                                       json_extract(result.payload_json,'$.threadId'),''
                                     )=''
                                     AND json_extract(result.payload_json,'$.intentId') IS NULL
                                     AND json_extract(result.payload_json,'$.taskId') IS NULL
                                     AND json_extract(result.payload_json,'$.worktreePath') IS NULL
                                     AND EXISTS (
                                       SELECT 1 FROM events deferred
                                       WHERE deferred.opportunity_key=
                                             sent.opportunity_key
                                         AND deferred.event_type=
                                             'TASK_RESULT_VALIDATION_DEFERRED'
                                         AND deferred.dedupe_key=result.dedupe_key
                                         AND deferred.id>sent.id
                                         AND deferred.id<=result.id
                                         AND json_extract(
                                           deferred.payload_json,'$.threadId'
                                         )=i.thread_id
                                         AND {_intent_event_binding_clause("i", "deferred")}
                                     )
                                   )
                                 )
                             )
                             AND NOT EXISTS (
                               SELECT 1 FROM events cancelled
                               WHERE cancelled.opportunity_key=sent.opportunity_key
                                 AND cancelled.event_type=
                                     'VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                                 AND json_extract(cancelled.payload_json,'$.resultDigest')=
                                     sent.dedupe_key
                                 AND json_extract(cancelled.payload_json,'$.threadId')=
                                     i.thread_id
                                 AND cancelled.id>sent.id
                                 AND {_intent_event_binding_clause("i", "cancelled")}
                             )
                             AND NOT EXISTS (
                               SELECT 1 FROM events abandoned
                               WHERE abandoned.opportunity_key=sent.opportunity_key
                                 AND abandoned.event_type=
                                     'VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                                 AND json_extract(abandoned.payload_json,'$.resultDigest')=
                                     sent.dedupe_key
                                 AND json_extract(abandoned.payload_json,'$.threadId')=
                                     i.thread_id
                                 AND abandoned.id>sent.id
                                 AND {_intent_event_binding_clause("i", "abandoned")}
                             )
                             AND NOT EXISTS (
                               SELECT 1 FROM events no_progress
                               WHERE no_progress.opportunity_key=sent.opportunity_key
                                 AND no_progress.event_type=
                                     'VALIDATION_FOLLOWUP_NO_PROGRESS'
                                 AND no_progress.dedupe_key=sent.dedupe_key
                                 AND json_extract(no_progress.payload_json,'$.threadId')=
                                     i.thread_id
                                 AND {_intent_event_binding_clause("i", "no_progress")}
                                 AND NOT EXISTS (
                                   SELECT 1 FROM events rearmed
                                   WHERE rearmed.opportunity_key=sent.opportunity_key
                                     AND rearmed.event_type=
                                         'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                                     AND json_extract(
                                       rearmed.payload_json,'$.resultDigest'
                                     )=sent.dedupe_key
                                     AND json_extract(
                                       rearmed.payload_json,'$.threadId'
                                     )=i.thread_id
                                     AND rearmed.id>no_progress.id
                                     AND {_intent_event_binding_clause("i", "rearmed")}
                                 )
                             )
                             AND NOT EXISTS (
                               SELECT 1 FROM events rearmed
                               WHERE rearmed.opportunity_key=sent.opportunity_key
                                 AND rearmed.event_type=
                                     'VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED'
                                 AND json_extract(rearmed.payload_json,'$.resultDigest')=
                                     sent.dedupe_key
                                 AND json_extract(rearmed.payload_json,'$.threadId')=
                                     i.thread_id
                                 AND rearmed.id>sent.id
                                 AND {_intent_event_binding_clause("i", "rearmed")}
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
        intent_id: str | None = None,
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
        if not isinstance(thread_id, str) or not thread_id:
            raise LedgerError("publication thread identity is invalid")
        if intent_id is not None and (not isinstance(intent_id, str) or not intent_id):
            raise LedgerError("publication intent identity is invalid")
        with self.transaction() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,i.intent_id,i.status,i.thread_id,i.worktree_path,
                          i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.issue_url=? AND i.thread_id=?
                   ORDER BY i.updated_at DESC,i.intent_id DESC""",
                (issue_url, thread_id),
            ).fetchall()
            matches = [
                candidate
                for candidate in rows
                if (intent_id is None or str(candidate["intent_id"]) == intent_id)
                and candidate["worktree_path"] is not None
                and _resolved_path_equal(str(candidate["worktree_path"]), str(worktree_path))
            ]
            if len(matches) != 1:
                raise LedgerError("publication task binding is stale or ambiguous")
            row = matches[0]
            if str(row["status"] or "") not in _PUBLICATION_ACTIVE_INTENT_STATUSES:
                raise LedgerError("publication task intent is inactive")
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
            if replacement_of_request_id is not None:
                replacement_created_payload = {
                    "policyVersion": "managed-replay-replacement-created-v1",
                    "sourceRequestId": replacement_of_request_id,
                    "replacementRequestId": request_id,
                    "immutableRequestDigest": sha256_json(
                        _managed_replay_immutable_request(request)
                    ),
                    "replacementCreatedAt": now,
                    "recordedAt": now,
                }
                self._event(
                    connection,
                    row["key"],
                    MANAGED_REPLAY_REPLACEMENT_CREATED_EVENT,
                    replacement_of_request_id,
                    replacement_created_payload,
                    now,
                )
                replacement_created = connection.execute(
                    """SELECT payload_json,created_at FROM events
                       WHERE opportunity_key=? AND event_type=? AND dedupe_key=?""",
                    (
                        row["key"],
                        MANAGED_REPLAY_REPLACEMENT_CREATED_EVENT,
                        replacement_of_request_id,
                    ),
                ).fetchone()
                if (
                    replacement_created is None
                    or replacement_created["payload_json"]
                    != canonical_json(replacement_created_payload)
                    or replacement_created["created_at"] != now
                ):
                    raise LedgerError("managed replay replacement lineage conflicts")
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
                        or not _managed_replay_receipt_valid_at(
                            previous_receipt,
                            source=source,
                            bound_at=snapshot_bound_at,
                        )
                        or not _managed_replay_receipt_valid_at(
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
                if request != original_request or not _managed_replay_receipt_valid_at(
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
                worktree_path=str(source_row["worktree_path"] or "") or None,
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
            eligible_rows: list[sqlite3.Row] = []
            for row in rows:
                terminal = _publication_has_irreversible_terminal_evidence(
                    connection,
                    request_id=str(row["request_id"]),
                    opportunity_key=str(row["opportunity_key"]),
                )
                if terminal or _publication_request_intent_is_active(
                    connection,
                    request_id=str(row["request_id"]),
                    opportunity_key=str(row["opportunity_key"]),
                    request_row=row,
                ):
                    eligible_rows.append(row)
            rows = eligible_rows
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
            _reopen_active_publication_requests_after_quarantine_clear(
                connection,
                opportunity_key=key,
                now=now,
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
                _reopen_active_publication_requests_after_quarantine_clear(
                    connection,
                    opportunity_key=key,
                    now=now,
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
            _reopen_active_publication_requests_after_quarantine_clear(
                connection,
                opportunity_key=key,
                now=now,
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
        previous_commit = str(request.get("previousCommitSha") or "")
        # New requests carry intentId; legacy PR_UPDATE requests may omit it,
        # but still have to prove the complete thread/worktree identity.  The
        # resolver below accepts the legacy form only when that tuple maps to
        # one intent, and otherwise fails closed.
        intent_id = str(request.get("intentId") or "")
        thread_id = str(request.get("threadId") or "")
        worktree_path = str(request.get("worktreePath") or "")
        if (
            re.fullmatch(r"[0-9a-f]{40}", previous_commit) is None
            or not thread_id
            or not worktree_path
        ):
            return False
        existing_barrier = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key=? AND event_type=? AND dedupe_key=?""",
            (key, PR_FOLLOWUP_REARM_BARRIER_EVENT, request_id),
        ).fetchone()
        if existing_barrier is not None:
            try:
                barrier_payload = json.loads(existing_barrier["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            return bool(
                isinstance(barrier_payload, dict)
                and barrier_payload.get("requestId") == request_id
                and barrier_payload.get("reason") == reason
                and barrier_payload.get("rearmAfter")
            )
        followup = connection.execute(
            """SELECT pr_url,head_sha,wake_digest,checked_at FROM pr_followups
               WHERE opportunity_key=?""",
            (key,),
        ).fetchone()
        if followup is None or request.get("existingPrUrl") != followup["pr_url"]:
            return False
        if reason != "EXISTING_PR_HEAD_DRIFT" and previous_commit != followup["head_sha"]:
            return False
        request_row = connection.execute(
            """SELECT thread_id,worktree_path,status,reason FROM publication_requests
               WHERE request_id=? AND opportunity_key=?""",
            (request_id, key),
        ).fetchone()
        # A rollover may leave a newer intent for the same opportunity.  The
        # blocked PR_UPDATE request already carries the immutable task
        # identity, so validate that exact tuple instead of borrowing the
        # opportunity's latest intent.
        bound_intent = _resolve_exact_intent_binding(
            connection,
            opportunity_key=key,
            intent_id=intent_id or None,
            thread_id=thread_id,
            worktree_path=worktree_path,
        )
        newer_request = connection.execute(
            """SELECT 1 FROM publication_requests newer
               JOIN publication_requests current
                 ON current.request_id=? AND current.opportunity_key=newer.opportunity_key
               WHERE newer.created_at>current.created_at
                  OR (
                    newer.created_at=current.created_at
                    AND newer.request_id>current.request_id
                  )
               LIMIT 1""",
            (request_id,),
        ).fetchone()
        published = connection.execute(
            """SELECT 1 FROM publication_requests published
               JOIN publication_permits permit ON permit.request_id=published.request_id
               WHERE published.opportunity_key=?
                 AND permit.status='CONSUMED'
                 AND permit.pr_url=?
               LIMIT 1""",
            (key, followup["pr_url"]),
        ).fetchone()
        if (
            request_row is None
            or request_row["status"] != "BLOCKED"
            or request_row["reason"] != reason
            or request_row["thread_id"] != thread_id
            or request_row["worktree_path"] != worktree_path
            or bound_intent is None
            or bound_intent["status"] not in {"DISPATCHED", "COMPLETED"}
            or newer_request is not None
            or published is None
            or _publication_has_irreversible_terminal_evidence(
                connection,
                request_id=request_id,
                opportunity_key=key,
            )
        ):
            return False
        blocked = connection.execute(
            """SELECT 1 FROM events
               WHERE opportunity_key=? AND event_type='PUBLICATION_BLOCKED'
                 AND dedupe_key=?
                 AND json_extract(payload_json,'$.requestId')=?
                 AND json_extract(payload_json,'$.reason')=?""",
            (key, f"{request_id}:{reason}", request_id, reason),
        ).fetchone()
        if blocked is None or active_quarantine(connection, opportunity_key=key) is not None:
            return False
        try:
            rearm_after = iso_z(max(parse_time(now), parse_time(followup["checked_at"])))
        except (TypeError, ValueError):
            return False
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
            """SELECT r.id,r.dedupe_key,r.payload_json FROM events r
               WHERE r.opportunity_key=?
                 AND r.event_type='PR_FOLLOWUP_RESERVED'""",
            (key,),
        ).fetchall()
        for reservation in active_reservations:
            try:
                reservation_payload = json.loads(reservation["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError("PR follow-up reservation identity is invalid") from exc
            reservation_binding = _resolve_event_intent_binding(
                connection, opportunity_key=key, payload=reservation_payload
            )
            if (
                reservation_binding is None
                or str(reservation_binding["intent_id"]) != str(bound_intent["intent_id"])
                or str(reservation_binding["thread_id"]) != str(bound_intent["thread_id"])
                or not _resolved_path_equal(
                    str(reservation_binding["worktree_path"]),
                    str(bound_intent["worktree_path"]),
                )
            ):
                continue
            finished_rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='PR_FOLLOWUP_RESULT_INGESTED'
                     AND dedupe_key=?
                     AND id>?""",
                (key, reservation["dedupe_key"], reservation["id"]),
            ).fetchall()
            if finished_rows:
                finished_bindings = [
                    _resolve_event_intent_binding(
                        connection,
                        opportunity_key=key,
                        payload=json.loads(row["payload_json"] or "{}"),
                    )
                    for row in finished_rows
                ]
                if any(
                    binding is not None
                    and str(binding["intent_id"]) == str(bound_intent["intent_id"])
                    and str(binding["thread_id"]) == str(bound_intent["thread_id"])
                    and _resolved_path_equal(
                        str(binding["worktree_path"]), str(bound_intent["worktree_path"])
                    )
                    for binding in finished_bindings
                ):
                    continue
                # A same-key result for another intent is a hard collision;
                # do not silently mark this reservation complete.
                raise LedgerError("PR follow-up result binding mismatch")
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESULT_INGESTED",
                reservation["dedupe_key"],
                {
                    "requestId": request_id,
                    "stage": "REARMED",
                    "intentId": str(bound_intent["intent_id"]),
                    "threadId": str(bound_intent["thread_id"]),
                    "worktreePath": str(bound_intent["worktree_path"]),
                },
                now,
            )
        self._event(
            connection,
            key,
            "PR_FOLLOWUP_REARM_REQUIRED",
            request_id,
            {
                "requestId": request_id,
                "reason": reason,
                "previousWakeDigest": followup["wake_digest"],
                "sourceCheckedAt": followup["checked_at"],
                "rearmAfter": rearm_after,
            },
            now,
        )
        self._event(
            connection,
            key,
            PR_FOLLOWUP_REARM_BARRIER_EVENT,
            request_id,
            {
                "requestId": request_id,
                "reason": reason,
                "previousWakeDigest": followup["wake_digest"],
                "sourceCheckedAt": followup["checked_at"],
                "rearmAfter": rearm_after,
            },
            now,
        )
        return True

    def retry_blocked_publication_request(
        self, request_id: str, *, expected_reason: str
    ) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request not found")
            if row["status"] != "BLOCKED":
                raise LedgerError("publication request is not blocked")
            if row["reason"] != expected_reason:
                raise LedgerError("publication block reason changed")
            if not _publication_request_intent_is_active(
                connection,
                request_id=request_id,
                opportunity_key=str(row["opportunity_key"]),
                request_row=row,
            ):
                raise LedgerError("publication request intent is inactive")
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
            if not _publication_request_intent_is_active(
                connection,
                request_id=request_id,
                opportunity_key=str(request["opportunity_key"]),
                request_row=request,
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? "
                    "WHERE request_id=? AND status<>'CONSUMED'",
                    (now, request_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? "
                    "WHERE request_id=?",
                    ("BLOCKED_TASK_INTENT_INACTIVE", now, request_id),
                )
                connection.commit()
                raise LedgerError("publication request intent is inactive")
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
                "SELECT * FROM publication_requests WHERE request_id=?",
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
            intent_active = bool(
                authorization is not None
                and _publication_request_intent_is_active(
                    connection,
                    request_id=str(authorization["request_id"]),
                    opportunity_key=str(authorization["opportunity_key"]),
                    request_json=str(authorization["request_json"]),
                )
            )
            if (
                authorization is None
                or not intent_active
                or not _publication_probe_valid_json(authorization["request_json"])
            ):
                if authorization is not None:
                    reason = (
                        "BLOCKED_TASK_INTENT_INACTIVE"
                        if not intent_active
                        else "BLOCKED_REPRODUCTION_REQUIRED"
                    )
                    connection.execute(
                        "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                        (now, permit_id),
                    )
                    connection.execute(
                        "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                        (reason, now, authorization["request_id"]),
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
            raise LedgerError(
                "publication effect blocked: task intent is inactive"
                if authorization is not None and not intent_active
                else "publication effect blocked: authenticated reproduction is required"
            )
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
        self._resume_deferred_publication_no_go(effect_id)

    def _resume_deferred_publication_no_go(self, effect_id: str) -> None:
        """Reapply an audit once the exact ambiguous effect is no longer live."""

        with self.connect() as connection:
            row = connection.execute(
                """SELECT opportunity_key,dedupe_key,payload_json
                   FROM events
                   WHERE event_type='PUBLICATION_AUDIT_NO_GO_DEFERRED'
                     AND json_extract(payload_json,'$.effectId')=?
                   ORDER BY id DESC LIMIT 1""",
                (effect_id,),
            ).fetchone()
        if row is None:
            return
        try:
            payload = json.loads(str(row["payload_json"] or "{}"))
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        reason = str(payload.get("reason") or "AUDIT_NO_GO")
        evidence = payload.get("evidence")
        self.record_stage(
            str(row["opportunity_key"]),
            "AUDIT_NO_GO",
            evidence=evidence if isinstance(evidence, dict) else {},
            reason=reason,
            dedupe_key=str(row["dedupe_key"]),
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
            request_row = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if request_row is None or not _publication_request_intent_is_active(
                connection,
                request_id=request_id,
                opportunity_key=str(row["opportunity_key"]),
                request_row=request_row,
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? "
                    "WHERE permit_id=? AND status<>'CONSUMED'",
                    (now, row["permit_id"]),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? "
                    "WHERE request_id=? AND status<>'CONSUMED'",
                    ("BLOCKED_TASK_INTENT_INACTIVE", now, request_id),
                )
                return False
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
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if request_row is None:
                return None
            intent_active = _publication_request_intent_is_active(
                connection,
                request_id=request_id,
                opportunity_key=str(request_row["opportunity_key"]),
                request_row=request_row,
            )
            probe_valid = _publication_probe_valid_json(request_row["request_json"])
            if not intent_active or not probe_valid:
                reason = (
                    "BLOCKED_TASK_INTENT_INACTIVE"
                    if not intent_active
                    else "BLOCKED_REPRODUCTION_REQUIRED"
                )
                connection.execute(
                    "UPDATE publication_effects SET status='BLOCKED',result_json=?,updated_at=? WHERE effect_id=?",
                    (
                        canonical_json({"ok": False, "reason": reason}),
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
                    (reason, now, request_id),
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
                "SELECT * FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request_row is None:
                raise LedgerError("publication request is missing")
            require_quarantine_clear(
                connection,
                opportunity_key=str(request_row["opportunity_key"]),
                operation="publication effect retry",
            )
            intent_active = _publication_request_intent_is_active(
                connection,
                request_id=str(permit["request_id"]),
                opportunity_key=str(request_row["opportunity_key"]),
                request_row=request_row,
            )
            probe_valid = _publication_probe_valid_json(request_row["request_json"], evidence)
            if not intent_active or not probe_valid:
                reason = (
                    "BLOCKED_TASK_INTENT_INACTIVE"
                    if not intent_active
                    else "BLOCKED_REPRODUCTION_REQUIRED"
                )
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? WHERE permit_id=?",
                    (now, permit_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? WHERE request_id=?",
                    (reason, now, permit["request_id"]),
                )
                connection.commit()
                raise LedgerError(
                    "publication retry blocked: task intent is inactive"
                    if not intent_active
                    else "publication retry blocked: authenticated reproduction is required"
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
            if not _publication_request_intent_is_active(
                connection,
                request_id=request_id,
                opportunity_key=str(request_row["opportunity_key"]),
                request_row=request_row,
            ):
                connection.execute(
                    "UPDATE publication_permits SET status='BLOCKED',updated_at=? "
                    "WHERE request_id=? AND status<>'CONSUMED'",
                    (now, request_id),
                )
                connection.execute(
                    "UPDATE publication_requests SET status='BLOCKED',reason=?,updated_at=? "
                    "WHERE request_id=? AND status<>'CONSUMED'",
                    ("BLOCKED_TASK_INTENT_INACTIVE", now, request_id),
                )
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
                            p.updated_at,r.commit_sha,r.branch,
                            i.intent_id,i.thread_id,i.worktree_path,
                            ROW_NUMBER() OVER (
                              PARTITION BY p.pr_url ORDER BY p.updated_at DESC
                            ) AS latest_rank
                     FROM opportunities o
                     JOIN publication_requests r ON r.opportunity_key=o.key
                     JOIN publication_permits p ON p.request_id=r.request_id
                     JOIN intents i ON i.opportunity_key=o.key
                       AND i.thread_id=r.thread_id
                       AND i.worktree_path=r.worktree_path
                       AND (
                         (
                           json_valid(r.request_json)=1
                           AND json_extract(r.request_json,'$.intentId') IS NOT NULL
                           AND i.intent_id=json_extract(r.request_json,'$.intentId')
                         )
                         OR (
                           json_valid(r.request_json)=1
                           AND json_extract(r.request_json,'$.intentId') IS NULL
                           AND NOT EXISTS (
                             SELECT 1 FROM intents other
                             WHERE other.opportunity_key=i.opportunity_key
                               AND other.thread_id=i.thread_id
                               AND other.worktree_path=i.worktree_path
                               AND other.intent_id<>i.intent_id
                           )
                         )
                       )
                     WHERE p.pr_url IS NOT NULL AND (
                       p.status='CONSUMED' OR
                       (p.status='BLOCKED' AND r.reason='BLOCKED_REPRODUCTION_REQUIRED'
                        AND json_valid(r.request_json)=1
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
            tracked: dict[str, dict[str, Any]] = {}
            tracked_rows = connection.execute(
                """SELECT pr_url,opportunity_key,commit_sha,consumed_at,
                          thread_id,worktree_path,request_json
                   FROM (
                     SELECT p.pr_url,r.opportunity_key,r.commit_sha,
                            p.updated_at AS consumed_at,r.thread_id,
                            r.worktree_path,r.request_json,
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
                        AND json_valid(r.request_json)=1
                        AND json_extract(r.request_json,'$.recoveredFromTaskContext')=1)
                     )
                   ) WHERE latest_rank=1"""
            ).fetchall()
            for row in tracked_rows:
                try:
                    request_payload = json.loads(str(row["request_json"] or "{}"))
                except (TypeError, json.JSONDecodeError):
                    request_payload = {}
                if not isinstance(request_payload, dict):
                    request_payload = {}
                exact_intent = _resolve_exact_intent_binding(
                    connection,
                    opportunity_key=str(row["opportunity_key"]),
                    intent_id=str(request_payload.get("intentId") or "") or None,
                    thread_id=str(row["thread_id"] or "") or None,
                    worktree_path=str(row["worktree_path"] or "") or None,
                )
                tracked[str(row["pr_url"])] = {
                    "key": str(row["opportunity_key"]),
                    "commitSha": str(row["commit_sha"]),
                    "consumedAt": str(row["consumed_at"]),
                    "intentId": str(exact_intent["intent_id"]) if exact_intent else None,
                    "threadId": str(exact_intent["thread_id"]) if exact_intent else None,
                    "worktreePath": str(exact_intent["worktree_path"]) if exact_intent else None,
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
                previous = connection.execute(
                    "SELECT * FROM pr_followups WHERE opportunity_key=?", (key,)
                ).fetchone()
                if previous is not None:
                    try:
                        previous_checked_time = parse_time(previous["checked_at"])
                    except (TypeError, ValueError) as exc:
                        raise LedgerError("stored PR follow-up timestamp is invalid") from exc
                    if checked_time < previous_checked_time:
                        continue
                incoming_identity = (
                    binding.get("intentId"),
                    binding.get("threadId"),
                    binding.get("worktreePath"),
                )
                previous_identity = (
                    previous["intent_id"] if previous is not None else None,
                    previous["thread_id"] if previous is not None else None,
                    previous["worktree_path"] if previous is not None else None,
                )

                def previous_event_is_bound(
                    event_type: str,
                    dedupe_key: str,
                    *,
                    _previous=previous,
                    _previous_identity=previous_identity,
                    _key=key,
                ) -> bool:
                    """Match a prior wake event to the exact stored intent.

                    Wake digests are content-derived and therefore not task
                    identities.  Looking them up by opportunity alone lets a
                    replay from an older intent generation close the newer
                    generation's follow-up.  Resolve the event payload first
                    and require the binding columns on ``previous`` to agree.
                    An incomplete legacy row is deliberately treated as
                    unresolved instead of guessed from recency.
                    """

                    if _previous is None or not all(_previous_identity):
                        return False
                    rows = connection.execute(
                        """SELECT payload_json FROM events
                           WHERE opportunity_key=? AND event_type=?
                             AND dedupe_key=?""",
                        (_key, event_type, dedupe_key),
                    ).fetchall()
                    for event_row in rows:
                        try:
                            event_payload = json.loads(event_row["payload_json"] or "{}")
                        except (TypeError, json.JSONDecodeError):
                            continue
                        event_binding = _resolve_event_intent_binding(
                            connection,
                            opportunity_key=_key,
                            payload=event_payload,
                        )
                        if (
                            event_binding is not None
                            and str(event_binding["intent_id"] or "") == str(_previous_identity[0])
                            and str(event_binding["thread_id"] or "") == str(_previous_identity[1])
                            and event_binding["worktree_path"] is not None
                            and _resolved_path_equal(
                                str(event_binding["worktree_path"]),
                                str(_previous_identity[2]),
                            )
                        ):
                            return True
                    return False

                previous_wake_active = False
                if previous is not None and previous["wake_digest"]:
                    previous_wake_active = not previous_event_is_bound(
                        "PR_FOLLOWUP_RESULT_INGESTED", str(previous["wake_digest"])
                    )
                if previous_wake_active and all(previous_identity):
                    # Keep an in-flight wake attached to the task that created
                    # it even if a later publication request introduces a new
                    # intent for the same opportunity.
                    followup_identity = previous_identity
                elif all(incoming_identity):
                    followup_identity = incoming_identity
                elif all(previous_identity):
                    followup_identity = previous_identity
                else:
                    followup_identity = (None, None, None)
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
                rearm_barrier = connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=? AND event_type=?
                       ORDER BY id DESC LIMIT 1""",
                    (key, PR_FOLLOWUP_REARM_BARRIER_EVENT),
                ).fetchone()
                rearm_after = None
                if rearm_barrier is not None:
                    try:
                        rearm_payload = json.loads(rearm_barrier["payload_json"])
                        rearm_after = parse_time(str(rearm_payload.get("rearmAfter") or ""))
                    except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise LedgerError("PR follow-up rearm barrier is invalid") from exc
                if rearm_after is not None and checked_time <= rearm_after:
                    if previous is not None and parse_time(previous["checked_at"]) > rearm_after:
                        continue
                    required = False
                preserved_resolution_scope = False
                if required and previous is not None:
                    authorized_wake_completed = (
                        object()
                        if previous_event_is_bound(
                            "PR_FOLLOWUP_RESULT_INGESTED", str(previous["wake_digest"] or "")
                        )
                        else None
                    )
                    authorized_wake_reserved = (
                        object()
                        if previous_event_is_bound(
                            "PR_FOLLOWUP_RESERVED", str(previous["wake_digest"] or "")
                        )
                        else None
                    )
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
                    identity = None
                    if all(followup_identity):
                        identity = connection.execute(
                            """SELECT o.issue_url,i.intent_id,i.thread_id,i.worktree_path
                               FROM opportunities o JOIN intents i
                                 ON i.opportunity_key=o.key
                                AND i.intent_id=?
                                AND i.thread_id=?
                                AND i.worktree_path=?
                               WHERE o.key=?""",
                            (*followup_identity, key),
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
                        updated_at,intent_id,thread_id,worktree_path)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(opportunity_key) DO UPDATE SET
                         pr_url=excluded.pr_url,head_sha=excluded.head_sha,
                         action_digest=excluded.action_digest,
                         task_action_digest=excluded.task_action_digest,
                         wake_digest=excluded.wake_digest,actions_json=excluded.actions_json,
                         evidence_json=excluded.evidence_json,
                         followup_required=excluded.followup_required,
                         checked_at=excluded.checked_at,updated_at=excluded.updated_at,
                         intent_id=excluded.intent_id,thread_id=excluded.thread_id,
                         worktree_path=excluded.worktree_path""",
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
                        followup_identity[0],
                        followup_identity[1],
                        followup_identity[2],
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
    def _pr_update_rearm_allows_followup(
        connection: sqlite3.Connection,
        *,
        request_row: sqlite3.Row,
        followup_pr_url: str,
        followup_checked_at: str,
    ) -> bool:
        if (
            request_row["status"] != "BLOCKED"
            or request_row["reason"] not in PR_UPDATE_REARM_REASONS
        ):
            return False
        try:
            request = json.loads(request_row["request_json"])
        except (TypeError, json.JSONDecodeError):
            return False
        if (
            not isinstance(request, dict)
            or request.get("requestId") != request_row["request_id"]
            or request.get("publicationKind") != "PR_UPDATE"
            or request.get("existingPrUrl") != followup_pr_url
        ):
            return False
        event_rows = connection.execute(
            """SELECT event_type,payload_json FROM events
               WHERE opportunity_key=? AND dedupe_key=?
                 AND event_type IN (
                   'PR_FOLLOWUP_REARM_REQUIRED',
                   'PR_FOLLOWUP_REARM_OBSERVATION_BARRIER'
                 )""",
            (request_row["opportunity_key"], request_row["request_id"]),
        ).fetchall()
        if len(event_rows) != 2:
            return False
        payloads: dict[str, dict[str, Any]] = {}
        for event_row in event_rows:
            try:
                payload = json.loads(event_row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            if not isinstance(payload, dict):
                return False
            payloads[str(event_row["event_type"])] = payload
        rearm = payloads.get("PR_FOLLOWUP_REARM_REQUIRED")
        barrier = payloads.get(PR_FOLLOWUP_REARM_BARRIER_EVENT)
        if (
            rearm is None
            or barrier is None
            or rearm.get("requestId") != request_row["request_id"]
            or barrier.get("requestId") != request_row["request_id"]
            or rearm.get("reason") != request_row["reason"]
            or barrier.get("reason") != request_row["reason"]
            or rearm.get("rearmAfter") != barrier.get("rearmAfter")
        ):
            return False
        try:
            return parse_time(followup_checked_at) > parse_time(
                str(barrier.get("rearmAfter") or "")
            )
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _managed_replay_source_allows_followup(
        connection: sqlite3.Connection,
        *,
        source_row: sqlite3.Row,
        source_request: dict[str, Any],
        followup_pr_url: str,
        followup_checked_at: str,
    ) -> bool:
        if source_row["status"] != "BLOCKED":
            return False
        lineage_rows = connection.execute(
            """SELECT * FROM events
               WHERE opportunity_key=?
                 AND event_type IN (
                   'MANAGED_REPLAY_REPLACEMENT_CREATED',
                   'MANAGED_REPLAY_REPLACEMENT_REFRESHED'
                 )
                 AND (
                   dedupe_key=?
                   OR json_extract(
                     CASE WHEN json_valid(payload_json) THEN payload_json ELSE '{}' END,
                     '$.sourceRequestId'
                   )=?
                 )
               ORDER BY id""",
            (
                source_row["opportunity_key"],
                source_row["request_id"],
                source_row["request_id"],
            ),
        ).fetchall()
        if not lineage_rows:
            return False
        parsed_lineage: list[tuple[sqlite3.Row, dict[str, Any]]] = []
        replacement_ids: set[str] = set()
        for lineage_row in lineage_rows:
            try:
                lineage = json.loads(lineage_row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                return False
            if not isinstance(lineage, dict):
                return False
            replacement_id = str(lineage.get("replacementRequestId") or "")
            if lineage.get("sourceRequestId") != source_row["request_id"] or not re.fullmatch(
                r"[0-9a-f]{64}", replacement_id
            ):
                return False
            if lineage_row["event_type"] == MANAGED_REPLAY_REPLACEMENT_CREATED_EVENT:
                if (
                    lineage_row["dedupe_key"] != source_row["request_id"]
                    or lineage.get("policyVersion") != "managed-replay-replacement-created-v1"
                    or lineage.get("replacementCreatedAt") != lineage_row["created_at"]
                    or lineage.get("recordedAt") != lineage_row["created_at"]
                    or not re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(lineage.get("immutableRequestDigest") or ""),
                    )
                ):
                    return False
            elif (
                lineage.get("policyVersion") != "managed-replay-replacement-refresh-v1"
                or lineage.get("refreshedAt") != lineage_row["created_at"]
            ):
                return False
            replacement_ids.add(replacement_id)
            parsed_lineage.append((lineage_row, lineage))
        if len(replacement_ids) != 1:
            return False
        replacement_id = replacement_ids.pop()
        replacement_row = connection.execute(
            "SELECT * FROM publication_requests WHERE request_id=?",
            (replacement_id,),
        ).fetchone()
        if (
            replacement_row is None
            or replacement_row["opportunity_key"] != source_row["opportunity_key"]
            or replacement_row["thread_id"] != source_row["thread_id"]
            or replacement_row["commit_sha"] != source_row["commit_sha"]
            or replacement_row["branch"] != source_row["branch"]
            or replacement_row["worktree_path"] != source_row["worktree_path"]
            or replacement_row["status"] != "BLOCKED"
            or replacement_row["reason"] not in PR_UPDATE_REARM_REASONS
        ):
            return False
        try:
            replacement_request = json.loads(replacement_row["request_json"])
        except (TypeError, json.JSONDecodeError):
            return False
        try:
            replacement_created_time = parse_time(str(replacement_row["created_at"]))
            source_created_time = parse_time(str(source_row["created_at"]))
        except (TypeError, ValueError):
            return False
        if (
            not isinstance(replacement_request, dict)
            or source_request.get("publicationKind") != "PR_UPDATE"
            or replacement_request.get("publicationKind") != "PR_UPDATE"
            or source_request.get("existingPrUrl") != followup_pr_url
            or replacement_request.get("existingPrUrl") != followup_pr_url
            or _managed_replay_immutable_request(source_request)
            != _managed_replay_immutable_request(replacement_request)
            or replacement_created_time <= source_created_time
        ):
            return False
        for row, request in (
            (source_row, source_request),
            (replacement_row, replacement_request),
        ):
            bindings = {
                "requestId": row["request_id"],
                "opportunityKey": row["opportunity_key"],
                "threadId": row["thread_id"],
                "commitSha": row["commit_sha"],
                "branch": row["branch"],
                "worktreePath": row["worktree_path"],
                "evidenceDigest": row["evidence_digest"],
            }
            if any(request.get(field) != value for field, value in bindings.items()):
                return False
        try:
            source_original = _managed_replay_creation_snapshot(
                connection,
                row=source_row,
                request=source_request,
            )
            replacement_original = _managed_replay_creation_snapshot(
                connection,
                row=replacement_row,
                request=replacement_request,
            )
        except LedgerError:
            return False
        if (
            source_original != source_request
            or not _managed_replay_receipt_valid_at(
                source_original.get("probeReceipt"),
                source=source_request,
                bound_at=str(source_row["created_at"]),
            )
            or not _managed_replay_receipt_valid_at(
                replacement_original.get("probeReceipt"),
                source=source_request,
                bound_at=str(replacement_row["created_at"]),
            )
        ):
            return False
        created_lineage = [
            (row, lineage)
            for row, lineage in parsed_lineage
            if row["event_type"] == MANAGED_REPLAY_REPLACEMENT_CREATED_EVENT
        ]
        refresh_lineage = [
            (row, lineage)
            for row, lineage in parsed_lineage
            if row["event_type"] == "MANAGED_REPLAY_REPLACEMENT_REFRESHED"
        ]
        if created_lineage:
            if (
                len(created_lineage) != 1
                or created_lineage[0][1].get("replacementCreatedAt")
                != replacement_row["created_at"]
                or created_lineage[0][1].get("immutableRequestDigest")
                != sha256_json(_managed_replay_immutable_request(replacement_request))
            ):
                return False
        elif not refresh_lineage:
            return False

        snapshot_bound_at = str(replacement_row["created_at"])
        evidence_digest = str(replacement_original.get("evidenceDigest") or "")
        probe_receipt = replacement_original.get("probeReceipt")
        for lineage_row, lineage in refresh_lineage:
            previous_receipt = lineage.get("previousProbeReceipt")
            new_receipt = lineage.get("newProbeReceipt")
            previous_digest = str(lineage.get("previousEvidenceDigest") or "")
            new_digest = str(lineage.get("newEvidenceDigest") or "")
            try:
                lineage_time = parse_time(str(lineage_row["created_at"]))
                previous_bound_time = parse_time(snapshot_bound_at)
            except (TypeError, ValueError):
                return False
            if (
                lineage_time <= previous_bound_time
                or lineage.get("previousSnapshotBoundAt") != snapshot_bound_at
                or previous_digest != evidence_digest
                or previous_receipt != probe_receipt
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
                or not _managed_replay_receipt_valid_at(
                    previous_receipt,
                    source=source_request,
                    bound_at=snapshot_bound_at,
                )
                or not _managed_replay_receipt_valid_at(
                    new_receipt,
                    source=source_request,
                    bound_at=str(lineage_row["created_at"]),
                )
            ):
                return False
            try:
                _validate_managed_replay_lineage_authority(
                    connection,
                    opportunity_key=str(source_row["opportunity_key"]),
                    source_request_id=str(source_row["request_id"]),
                    source=source_request,
                    lineage=lineage,
                    refreshed_at=str(lineage_row["created_at"]),
                )
            except LedgerError:
                return False
            snapshot_bound_at = str(lineage_row["created_at"])
            evidence_digest = new_digest
            probe_receipt = new_receipt
        if refresh_lineage:
            try:
                replacement_updated_time = parse_time(str(replacement_row["updated_at"]))
                final_snapshot_time = parse_time(snapshot_bound_at)
            except (TypeError, ValueError):
                return False
            if (
                replacement_row["evidence_digest"] != evidence_digest
                or replacement_request.get("probeReceipt") != probe_receipt
                or replacement_updated_time < final_snapshot_time
            ):
                return False
        elif replacement_request != replacement_original:
            return False
        return RadarLedger._pr_update_rearm_allows_followup(
            connection,
            request_row=replacement_row,
            followup_pr_url=followup_pr_url,
            followup_checked_at=followup_checked_at,
        )

    @staticmethod
    def _pr_followup_has_blocking_update(
        connection: sqlite3.Connection,
        *,
        opportunity_key: str,
        followup_head_sha: str,
        followup_pr_url: str,
        followup_checked_at: str,
    ) -> bool:
        rows = connection.execute(
            """SELECT * FROM publication_requests
               WHERE opportunity_key=?
                 AND status IN ('PENDING','GRANTED','BLOCKED')""",
            (opportunity_key,),
        ).fetchall()
        for row in rows:
            try:
                request = json.loads(row["request_json"])
            except (TypeError, json.JSONDecodeError):
                if row["commit_sha"] != followup_head_sha:
                    return True
                continue
            if not isinstance(request, dict):
                if row["commit_sha"] != followup_head_sha:
                    return True
                continue
            if request.get("publicationKind") != "PR_UPDATE":
                continue
            if row["commit_sha"] == followup_head_sha:
                continue
            if RadarLedger._pr_update_rearm_allows_followup(
                connection,
                request_row=row,
                followup_pr_url=followup_pr_url,
                followup_checked_at=followup_checked_at,
            ):
                continue
            if RadarLedger._managed_replay_source_allows_followup(
                connection,
                source_row=row,
                source_request=request,
                followup_pr_url=followup_pr_url,
                followup_checked_at=followup_checked_at,
            ):
                continue
            return True
        return False

    @staticmethod
    def _pr_followup_candidate_rows(
        connection: sqlite3.Connection,
        *,
        thread_id: str | None = None,
        wake_digest: str | None = None,
    ) -> list[sqlite3.Row]:
        if not _pr_followup_binding_columns_present(connection):
            # Read-only observers may open a pre-migration ledger.  Do not
            # resurrect the old latest-intent heuristic; wait for the writable
            # initializer to add and backfill the binding columns.
            return []
        filters: list[str] = []
        params: list[str] = []
        if thread_id is not None:
            filters.append("AND i.thread_id=?")
            params.append(thread_id)
        if wake_digest is not None:
            filters.append("AND f.wake_digest=?")
            params.append(wake_digest)
        extra_filters = "\n                     ".join(filters)
        query = f"""SELECT f.*,o.key,o.repo,o.issue_url,o.stage,
                          i.intent_id AS bound_intent_id,
                          i.thread_id AS bound_thread_id,
                          i.worktree_path AS bound_worktree_path,
                          r.branch
                   FROM pr_followups f
                   JOIN opportunities o ON o.key=f.opportunity_key
                   JOIN publication_requests r ON r.opportunity_key=o.key
                   JOIN publication_permits p ON p.request_id=r.request_id
                   JOIN intents i ON i.opportunity_key=o.key
                     AND (
                       (
                         f.intent_id IS NOT NULL
                         AND i.intent_id=f.intent_id
                         AND i.thread_id=f.thread_id
                         AND i.worktree_path=f.worktree_path
                         AND r.thread_id=f.thread_id
                         AND r.worktree_path=f.worktree_path
                       )
                       OR (
                         f.intent_id IS NULL
                         AND (f.thread_id IS NULL OR i.thread_id=f.thread_id)
                         AND (f.worktree_path IS NULL OR i.worktree_path=f.worktree_path)
                         AND i.thread_id=r.thread_id
                         AND i.worktree_path=r.worktree_path
                         AND (
                           (
                             json_valid(r.request_json)=1
                             AND json_extract(r.request_json,'$.intentId') IS NOT NULL
                             AND i.intent_id=json_extract(r.request_json,'$.intentId')
                           )
                           OR (
                             json_valid(r.request_json)=1
                             AND json_extract(r.request_json,'$.intentId') IS NULL
                             AND NOT EXISTS (
                               SELECT 1 FROM intents other
                               WHERE other.opportunity_key=i.opportunity_key
                                 AND other.thread_id=i.thread_id
                                 AND other.worktree_path=i.worktree_path
                                 AND other.intent_id<>i.intent_id
                             )
                           )
                         )
                       )
                     )
                   WHERE f.followup_required=1 AND f.wake_digest IS NOT NULL
                     AND o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND p.pr_url=f.pr_url AND (
                       p.status='CONSUMED' OR
                       (p.status='BLOCKED' AND r.reason='BLOCKED_REPRODUCTION_REQUIRED'
                        AND json_valid(r.request_json)=1
                        AND json_extract(r.request_json,'$.recoveredFromTaskContext')=1)
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
        rows = list(connection.execute(query, tuple(params)).fetchall())
        blocked: dict[str, bool] = {}
        eligible: list[sqlite3.Row] = []
        for row in rows:
            key = str(row["key"])
            if key not in blocked:
                blocked[key] = RadarLedger._pr_followup_has_blocking_update(
                    connection,
                    opportunity_key=key,
                    followup_head_sha=str(row["head_sha"]),
                    followup_pr_url=str(row["pr_url"]),
                    followup_checked_at=str(row["checked_at"]),
                )
            if not blocked[key]:
                eligible.append(row)
        return eligible

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
                    "threadId": row["bound_thread_id"],
                    "intentId": row["bound_intent_id"],
                    "worktreePath": row["bound_worktree_path"],
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
                {
                    "intentId": candidate["intentId"],
                    "threadId": thread_id,
                    "worktreePath": candidate["worktreePath"],
                    "prUrl": candidate["prUrl"],
                },
                iso_z(datetime.now(UTC)),
            )
            if prepared_head_sha is not None:
                self._event(
                    connection,
                    candidate["key"],
                    "PR_FOLLOWUP_PREPARATION_BOUND",
                    wake_digest,
                    {
                        "intentId": candidate["intentId"],
                        "threadId": thread_id,
                        "worktreePath": candidate["worktreePath"],
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
            if not _pr_followup_binding_columns_present(connection):
                return []
            rows = connection.execute(
                """SELECT f.*,o.key,o.issue_url,r.dedupe_key AS reserved_wake_digest,
                          json_extract(r.payload_json,'$.threadId') AS reserved_thread_id,
                          json_extract(r.payload_json,'$.prUrl') AS reserved_pr_url,
                          i.intent_id AS bound_intent_id,
                          i.worktree_path AS bound_worktree_path,
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
                     AND (
                       (
                         json_extract(r.payload_json,'$.intentId') IS NOT NULL
                         AND i.intent_id=json_extract(r.payload_json,'$.intentId')
                       )
                       OR (
                         json_extract(r.payload_json,'$.intentId') IS NULL
                         AND f.intent_id=i.intent_id
                       )
                     )
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
                "intentId": row["bound_intent_id"],
                "worktreePath": row["bound_worktree_path"],
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
                """SELECT r.id,r.opportunity_key AS key,r.dedupe_key AS wake_digest,
                          r.payload_json
                   FROM events r
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND EXISTS (
                       SELECT 1 FROM events later
                       WHERE later.opportunity_key=r.opportunity_key
                         AND later.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND later.id>r.id
                     )
                   ORDER BY r.id"""
            ).fetchall()
            for row in rows:
                try:
                    reservation_payload = json.loads(row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("PR follow-up reservation identity is invalid") from exc
                reservation_binding = _resolve_event_intent_binding(
                    connection, opportunity_key=row["key"], payload=reservation_payload
                )
                if reservation_binding is None:
                    # Legacy unbound rows are only reconcilable when the
                    # opportunity has one unambiguous complete intent.
                    continue
                existing_same = connection.execute(
                    """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND dedupe_key=?""",
                    (row["key"], row["wake_digest"]),
                ).fetchall()
                if existing_same:
                    existing_bindings = []
                    for existing_row in existing_same:
                        try:
                            existing_payload = json.loads(existing_row["payload_json"] or "{}")
                        except (TypeError, json.JSONDecodeError) as exc:
                            raise LedgerError("PR follow-up result identity is invalid") from exc
                        existing_bindings.append(
                            _resolve_event_intent_binding(
                                connection,
                                opportunity_key=row["key"],
                                payload=existing_payload,
                            )
                        )
                    if not any(
                        binding is not None
                        and str(binding["intent_id"]) == str(reservation_binding["intent_id"])
                        and str(binding["thread_id"]) == str(reservation_binding["thread_id"])
                        and _resolved_path_equal(
                            str(binding["worktree_path"]),
                            str(reservation_binding["worktree_path"]),
                        )
                        for binding in existing_bindings
                    ):
                        raise LedgerError("PR follow-up result binding mismatch")
                    continue
                later_rows = connection.execute(
                    """SELECT id,dedupe_key,payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND id>? ORDER BY id DESC""",
                    (row["key"], row["id"]),
                ).fetchall()
                matching_later = None
                for later in later_rows:
                    try:
                        later_payload = json.loads(later["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError) as exc:
                        raise LedgerError("PR follow-up result identity is invalid") from exc
                    later_binding = _resolve_event_intent_binding(
                        connection, opportunity_key=row["key"], payload=later_payload
                    )
                    if (
                        later_binding is not None
                        and str(later_binding["intent_id"]) == str(reservation_binding["intent_id"])
                        and str(later_binding["thread_id"]) == str(reservation_binding["thread_id"])
                        and _resolved_path_equal(
                            str(later_binding["worktree_path"]),
                            str(reservation_binding["worktree_path"]),
                        )
                    ):
                        matching_later = later
                        break
                if matching_later is None:
                    continue
                self._event(
                    connection,
                    row["key"],
                    "PR_FOLLOWUP_RESULT_INGESTED",
                    row["wake_digest"],
                    {
                        "stage": "SUPERSEDED",
                        "supersededBy": matching_later["dedupe_key"],
                        "intentId": str(reservation_binding["intent_id"]),
                        "threadId": str(reservation_binding["thread_id"]),
                        "worktreePath": str(reservation_binding["worktree_path"]),
                    },
                    now,
                )
                reconciled.append(
                    {
                        "key": row["key"],
                        "wakeDigest": row["wake_digest"],
                        "supersededBy": matching_later["dedupe_key"],
                    }
                )
        return reconciled

    def commit_pr_followup(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT r.opportunity_key AS key,r.payload_json,
                          i.intent_id,i.worktree_path
                   FROM events r
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND r.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events s
                       WHERE s.opportunity_key=r.opportunity_key
                         AND s.event_type='PR_FOLLOWUP_SENT'
                         AND s.dedupe_key=r.dedupe_key
                         AND {_intent_event_binding_clause("i", "s")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events rebound
                       WHERE rebound.opportunity_key=r.opportunity_key
                         AND rebound.event_type='PR_FOLLOWUP_REBIND_REQUIRED'
                         AND {_intent_event_binding_clause("i", "rebound")}
                         AND rebound.id>r.id
                     )
                   ORDER BY r.id DESC""",
                (thread_id, wake_digest),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if str(row["intent_id"] or "") == str(intent_id)]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            if len(rows) > 1:
                raise LedgerError("PR follow-up reservation is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                sent_rows = connection.execute(
                    f"""SELECT r.payload_json,s.payload_json AS sent_payload,
                              i.intent_id,i.worktree_path
                       FROM events r
                       JOIN events s
                         ON s.opportunity_key=r.opportunity_key
                        AND s.event_type='PR_FOLLOWUP_SENT'
                        AND s.dedupe_key=r.dedupe_key
                       JOIN intents i ON i.opportunity_key=r.opportunity_key
                         AND {_intent_event_binding_clause("i", "r")}
                       WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND r.dedupe_key=?
                         AND {_intent_event_binding_clause("i", "s")}
                       ORDER BY s.id DESC""",
                    (thread_id, wake_digest),
                ).fetchall()
                if intent_id:
                    sent_rows = [
                        row for row in sent_rows if str(row["intent_id"] or "") == str(intent_id)
                    ]
                if worktree_path:
                    sent_rows = [
                        row
                        for row in sent_rows
                        if row["worktree_path"]
                        and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                    ]
                if len(sent_rows) > 1:
                    raise LedgerError("PR follow-up reservation is ambiguous")
                if sent_rows:
                    return
                raise LedgerError("PR follow-up reservation is missing or already committed")
            reservation_payload = json.loads(row["payload_json"] or "{}")
            self._event(
                connection,
                row["key"],
                "PR_FOLLOWUP_SENT",
                wake_digest,
                {
                    "intentId": reservation_payload.get("intentId") or row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": reservation_payload.get("worktreePath") or row["worktree_path"],
                    "prUrl": reservation_payload.get("prUrl"),
                },
                now,
            )

    def abandon_pr_followup_delivery(
        self,
        *,
        thread_id: str,
        wake_digest: str,
        reason: str,
        min_age_minutes: int = 90,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, str]:
        """Retire an old reservation when no target task turn materialized."""

        current = datetime.now(UTC)
        now = iso_z(current)
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT r.id,r.opportunity_key AS key,r.created_at,
                          r.payload_json,i.intent_id,i.worktree_path
                   FROM events r
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND {_intent_event_binding_clause("i", "r")}
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.threadId')=?
                     AND r.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=r.opportunity_key
                         AND sent.event_type='PR_FOLLOWUP_SENT'
                         AND sent.dedupe_key=r.dedupe_key
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events finished
                       WHERE finished.opportunity_key=r.opportunity_key
                         AND finished.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND finished.dedupe_key=r.dedupe_key
                         AND {_intent_event_binding_clause("i", "finished")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=r.opportunity_key
                         AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {_intent_event_binding_clause("i", "abandoned")}
                         AND json_extract(abandoned.payload_json,'$.wakeDigest')=r.dedupe_key
                         AND abandoned.id>r.id
                     )
                   ORDER BY r.id DESC""",
                (thread_id, wake_digest),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if str(row["intent_id"] or "") == str(intent_id)]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            if len(rows) > 1:
                raise LedgerError("PR follow-up delivery is ambiguous")
            row = rows[0] if rows else None
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
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "wakeDigest": wake_digest,
                    "worktreePath": row["worktree_path"],
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
            if not _pr_followup_binding_columns_present(connection):
                return []
            rows = connection.execute(
                """SELECT r.opportunity_key AS key,o.issue_url,
                          i.intent_id AS bound_intent_id,
                          i.thread_id AS bound_thread_id,
                          i.worktree_path AS bound_worktree_path,
                          r.dedupe_key AS wake_digest,
                          r.payload_json,r.created_at
                   FROM events r
                   JOIN opportunities o ON o.key=r.opportunity_key
                   JOIN pr_followups f ON f.opportunity_key=r.opportunity_key
                     AND f.pr_url=json_extract(r.payload_json,'$.prUrl')
                   JOIN intents i ON i.opportunity_key=r.opportunity_key
                     AND i.thread_id=json_extract(r.payload_json,'$.threadId')
                     AND (
                       (
                         json_extract(r.payload_json,'$.intentId') IS NOT NULL
                         AND i.intent_id=json_extract(r.payload_json,'$.intentId')
                       )
                       OR (
                         json_extract(r.payload_json,'$.intentId') IS NULL
                         AND f.intent_id=i.intent_id
                       )
                     )
                   WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                     AND NOT EXISTS (
                     SELECT 1 FROM events s WHERE s.opportunity_key=r.opportunity_key
                       AND s.event_type='PR_FOLLOWUP_SENT'
                       AND s.dedupe_key=r.dedupe_key
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=r.opportunity_key
                         AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND result.dedupe_key=r.dedupe_key
                         AND result.id>r.id
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
                "worktree_path": row["bound_worktree_path"],
                "thread_id": json.loads(row["payload_json"]).get("threadId"),
                "intent_id": row["bound_intent_id"],
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

    def task_result_digest_seen(
        self,
        key: str,
        digest: str,
        *,
        intent_id: str | None = None,
        thread_id: str | None = None,
        worktree_path: str | None = None,
    ) -> bool:
        """Check one result digest without crossing immutable task bindings.

        The historical API keyed only by opportunity and digest.  That is
        insufficient after an intent rollover because two task generations
        may legitimately produce the same digest.  Callers with a binding get
        an exact match; an unbound call retains compatibility only for a
        singleton opportunity and otherwise fails closed.
        """

        requested_intent = str(intent_id or "") or None
        requested_thread = str(thread_id or "") or None
        requested_worktree = str(worktree_path or "") or None
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=? AND dedupe_key=?
                     AND event_type='TASK_RESULT_INGESTED'
                   ORDER BY id DESC""",
                (key, digest),
            ).fetchall()
            if not rows:
                return False
            intent_rows = connection.execute(
                """SELECT intent_id,thread_id,worktree_path FROM intents
                   WHERE opportunity_key=? ORDER BY rowid DESC""",
                (key,),
            ).fetchall()
            if requested_intent is None and requested_thread is None and requested_worktree is None:
                # A legacy caller cannot attribute an event across multiple
                # intent generations.  Requiring a singleton preserves old
                # behavior while preventing an old digest from suppressing a
                # replacement task.
                return len(intent_rows) == 1
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=payload,
                )
                if binding is None:
                    # Pre-identity ledgers may have one intent row without a
                    # materialized thread/worktree.  Preserve the historical
                    # singleton read path, but never use it when another
                    # intent exists or an explicit event id disagrees.
                    if len(intent_rows) == 1:
                        singleton_id = str(intent_rows[0]["intent_id"] or "")
                        payload_id = payload.get("intentId") or payload.get("taskId")
                        if payload_id and str(payload_id) != singleton_id:
                            continue
                        if requested_intent is not None and requested_intent != singleton_id:
                            continue
                        return True
                    continue
                if requested_intent is not None and str(binding["intent_id"]) != requested_intent:
                    continue
                if (
                    requested_thread is not None
                    and str(binding["thread_id"] or "") != requested_thread
                ):
                    continue
                if requested_worktree is not None and (
                    binding["worktree_path"] is None
                    or not _resolved_path_equal(str(binding["worktree_path"]), requested_worktree)
                ):
                    continue
                return True
        return False

    def published_task_result_is_terminal(
        self,
        key: str,
        *,
        thread_id: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> bool:
        """Return whether a missing historical worktree no longer needs local ingestion."""

        with self.connect() as connection:
            binding = _resolve_exact_intent_binding(
                connection,
                opportunity_key=key,
                intent_id=intent_id,
                thread_id=thread_id,
                worktree_path=worktree_path,
            )
            if binding is None:
                return False
            bound_intent_id = str(binding["intent_id"])
            bound_thread_id = str(binding["thread_id"] or "")
            bound_worktree_path = str(binding["worktree_path"] or "")
            result_binding = (
                f"({_intent_event_binding_clause('i', 'result')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'result')})"
            )
            # PR follow-up lifecycle rows share a wake digest across intent
            # generations.  Every relation below therefore carries the same
            # immutable intent/thread/worktree binding as the task result;
            # an old generation's sent/result/abandoned row must not close a
            # replacement task's follow-up.
            followup_sent_binding = (
                f"({_intent_event_binding_clause('i', 'sent')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'sent')})"
            )
            followup_result_binding = (
                f"({_intent_event_binding_clause('i', 'result')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'result')})"
            )
            followup_abandoned_binding = (
                f"({_intent_event_binding_clause('i', 'abandoned')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'abandoned')})"
            )
            followup_reserved_binding = (
                f"({_intent_event_binding_clause('i', 'reserved')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'reserved')})"
            )
            row = connection.execute(
                f"""SELECT 1
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                     AND i.intent_id=?
                     AND i.thread_id=?
                     AND i.worktree_path=?
                   WHERE o.key=?
                     AND i.status='COMPLETED'
                     AND o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED','MERGED','CLOSED')
                     AND EXISTS (
                       SELECT 1 FROM events result
                       WHERE result.opportunity_key=o.key
                         AND result.event_type='TASK_RESULT_INGESTED'
                         AND {result_binding}
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
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='PR_FOLLOWUP_SENT'
                         AND {followup_sent_binding}
                         AND NOT EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=o.key
                             AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND {followup_result_binding}
                             AND result.dedupe_key=sent.dedupe_key
                           )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND {followup_abandoned_binding}
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 sent.dedupe_key
                             AND abandoned.id>sent.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='PR_FOLLOWUP_RESERVED'
                         AND {followup_reserved_binding}
                         AND NOT EXISTS (
                           SELECT 1 FROM events sent
                           WHERE sent.opportunity_key=o.key
                             AND sent.event_type='PR_FOLLOWUP_SENT'
                             AND {followup_sent_binding}
                             AND sent.dedupe_key=reserved.dedupe_key
                           )
                         AND NOT EXISTS (
                           SELECT 1 FROM events result
                           WHERE result.opportunity_key=o.key
                             AND result.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND {followup_result_binding}
                             AND result.dedupe_key=reserved.dedupe_key
                           )
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=o.key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND {followup_abandoned_binding}
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 reserved.dedupe_key
                             AND abandoned.id>reserved.id
                         )
                       )
                   LIMIT 1""",
                (bound_intent_id, bound_thread_id, bound_worktree_path, key),
            ).fetchone()
            if row is None:
                return False

            def binding_matches(candidate: sqlite3.Row | None) -> bool:
                """Check one resolved row against the selected task binding."""

                return bool(
                    candidate is not None
                    and str(candidate["intent_id"] or "") == bound_intent_id
                    and str(candidate["thread_id"] or "") == bound_thread_id
                    and candidate["worktree_path"] is not None
                    and _resolved_path_equal(str(candidate["worktree_path"]), bound_worktree_path)
                )

            # The lifecycle stage is projected per opportunity, but the
            # evidence that makes a missing worktree terminal is per intent.
            # Re-resolve PR_OPEN and publication rows in Python so a foreign
            # intent cannot satisfy (or block) this task through an
            # opportunity-wide SQL EXISTS/NOT EXISTS.
            opened_for_binding = False
            opened_rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=? AND event_type='PR_OPEN'
                   ORDER BY id""",
                (key,),
            ).fetchall()
            for opened_row in opened_rows:
                try:
                    opened_payload = json.loads(opened_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                opened_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=opened_payload,
                )
                if binding_matches(opened_binding):
                    opened_for_binding = True
                    break

            publication_for_binding = False
            pending_for_binding = False
            publication_rows = connection.execute(
                """SELECT request.*,permit.pr_url AS _terminal_permit_pr_url
                   FROM publication_requests request
                   LEFT JOIN publication_permits permit
                     ON permit.request_id=request.request_id
                   WHERE request.opportunity_key=?""",
                (key,),
            ).fetchall()
            for publication_row in publication_rows:
                try:
                    publication_binding, _ = _resolve_publication_request_binding(
                        connection, publication_row
                    )
                except LedgerError:
                    # A malformed/ambiguous publication row is unsafe to
                    # classify while deciding terminality; fail closed rather
                    # than letting either intent inherit it by recency.
                    return False
                if not binding_matches(publication_binding):
                    continue
                if publication_row["_terminal_permit_pr_url"] is not None:
                    publication_for_binding = True
                if publication_row["status"] in {"PENDING", "GRANTED"}:
                    pending_for_binding = True

            if not (opened_for_binding or publication_for_binding) or pending_for_binding:
                return False
            marker_binding = (
                f"({_intent_event_binding_clause('i', 'marker')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'marker')})"
            )
            sent_binding = (
                f"({_intent_event_binding_clause('i', 'sent')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'sent')})"
            )
            result_binding_for_sent = (
                f"({_intent_event_binding_clause('i', 'result')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'result')})"
            )
            cancelled_binding = (
                f"({_intent_event_binding_clause('i', 'cancelled')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'cancelled')})"
            )
            abandoned_binding = (
                f"({_intent_event_binding_clause('i', 'abandoned')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'abandoned')})"
            )
            no_progress_binding = (
                f"({_intent_event_binding_clause('i', 'no_progress')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'no_progress')})"
            )
            rearmed_binding = (
                f"({_intent_event_binding_clause('i', 'rearmed')} OR "
                f"{_legacy_unique_unbound_event_clause('i', 'rearmed')})"
            )
            unresolved_validation = connection.execute(
                f"""SELECT 1
                   FROM events marker
                   JOIN intents i ON i.opportunity_key=marker.opportunity_key
                     AND i.intent_id=?
                     AND i.thread_id=?
                     AND i.worktree_path=?
                   WHERE marker.opportunity_key=?
                     AND {marker_binding}
                     AND marker.event_type IN (
                       'VALIDATION_FOLLOWUP_RESERVED',
                       'VALIDATION_FOLLOWUP_SENT'
                     )
                     AND json_extract(marker.payload_json,'$.threadId')=i.thread_id
                     AND json_extract(marker.payload_json,'$.resultDigest') IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=marker.opportunity_key
                         AND sent.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND {sent_binding}
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
                             AND {result_binding_for_sent}
                             AND result.id>sent.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events cancelled
                       WHERE cancelled.opportunity_key=marker.opportunity_key
                         AND cancelled.event_type=
                             'VALIDATION_FOLLOWUP_RESERVATION_CANCELLED'
                         AND {cancelled_binding}
                         AND json_extract(cancelled.payload_json,'$.reservationDigest')=
                             json_extract(marker.payload_json,'$.reservationDigest')
                         AND cancelled.id>marker.id
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=marker.opportunity_key
                         AND abandoned.event_type='VALIDATION_FOLLOWUP_DELIVERY_ABANDONED'
                         AND {abandoned_binding}
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
                         AND {no_progress_binding}
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
                             AND {rearmed_binding}
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
                         AND {rearmed_binding}
                         AND json_extract(rearmed.payload_json,'$.resultDigest')=
                             json_extract(marker.payload_json,'$.resultDigest')
                         AND json_extract(rearmed.payload_json,'$.threadId')=
                             json_extract(marker.payload_json,'$.threadId')
                         AND rearmed.id>marker.id
                     )
                   LIMIT 1""",
                (bound_intent_id, bound_thread_id, bound_worktree_path, key),
            ).fetchone()
        return unresolved_validation is None

    def record_followup_result(
        self,
        key: str,
        *,
        wake_digest: str,
        result_digest: str,
        stage: str,
        intent_id: str | None = None,
        thread_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Record a PR follow-up result against one immutable task identity.

        Older callers did not pass identity fields.  In that compatibility
        path we recover them from the exact sent event (or the bound follow-up
        row) and only fill them when one intent can be proven.  Ambiguous
        rollover history is deliberately left unacknowledged rather than
        allowing a result to suppress another task's recovery.
        """

        with self.transaction() as connection:
            identity_supplied = any(
                value is not None and str(value) for value in (intent_id, thread_id, worktree_path)
            )
            binding = (
                _resolve_exact_intent_binding(
                    connection,
                    opportunity_key=key,
                    intent_id=intent_id,
                    thread_id=thread_id,
                    worktree_path=worktree_path,
                )
                if identity_supplied
                else None
            )
            if identity_supplied and binding is None:
                # An explicit identity is authoritative.  Falling back to a
                # sent event or follow-up row here could silently attach the
                # result to a newer task after an intent rollover.
                raise LedgerError("PR follow-up result binding is invalid")
            source_rows = connection.execute(
                """SELECT payload_json FROM events
                       WHERE opportunity_key=?
                         AND event_type='PR_FOLLOWUP_SENT'
                         AND dedupe_key=?
                       ORDER BY id DESC""",
                (key, wake_digest),
            ).fetchall()
            source_bindings: list[sqlite3.Row] = []
            for source_row in source_rows:
                try:
                    source_payload = json.loads(source_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                source_binding = _resolve_event_intent_binding(
                    connection, opportunity_key=key, payload=source_payload
                )
                if source_binding is not None and all(
                    str(existing["intent_id"]) != str(source_binding["intent_id"])
                    for existing in source_bindings
                ):
                    source_bindings.append(source_binding)
            if identity_supplied and source_rows:
                if (
                    binding is None
                    or not source_bindings
                    or not any(
                        str(source["intent_id"]) == str(binding["intent_id"])
                        and str(source["thread_id"]) == str(binding["thread_id"])
                        and _resolved_path_equal(
                            str(source["worktree_path"]), str(binding["worktree_path"])
                        )
                        for source in source_bindings
                    )
                ):
                    raise LedgerError("PR follow-up result binding conflicts with its source")
            if binding is None:
                if len(source_bindings) == 1:
                    binding = source_bindings[0]
                elif len(source_bindings) > 1:
                    raise LedgerError("PR follow-up result binding is ambiguous")
            if binding is None:
                followup_rows = connection.execute(
                    """SELECT intent_id,thread_id,worktree_path
                       FROM pr_followups
                       WHERE opportunity_key=? AND wake_digest=?""",
                    (key, wake_digest),
                ).fetchall()
                followup_bindings: list[sqlite3.Row] = []
                for followup_row in followup_rows:
                    followup_binding = _resolve_exact_intent_binding(
                        connection,
                        opportunity_key=key,
                        intent_id=followup_row["intent_id"],
                        thread_id=followup_row["thread_id"],
                        worktree_path=followup_row["worktree_path"],
                    )
                    if followup_binding is not None and all(
                        str(existing["intent_id"]) != str(followup_binding["intent_id"])
                        for existing in followup_bindings
                    ):
                        followup_bindings.append(followup_binding)
                if len(followup_bindings) == 1:
                    binding = followup_bindings[0]
                elif len(followup_bindings) > 1:
                    raise LedgerError("PR follow-up result binding is ambiguous")
            if binding is None and not (intent_id or thread_id or worktree_path):
                unique_rows = connection.execute(
                    """SELECT * FROM intents
                       WHERE opportunity_key=?
                         AND thread_id IS NOT NULL
                         AND worktree_path IS NOT NULL""",
                    (key,),
                ).fetchall()
                if len(unique_rows) == 1:
                    binding = unique_rows[0]
            payload: dict[str, Any] = {
                "resultDigest": result_digest,
                "stage": stage,
            }
            if binding is not None:
                payload.update(
                    {
                        "intentId": str(binding["intent_id"]),
                        "threadId": str(binding["thread_id"]),
                        "worktreePath": str(binding["worktree_path"]),
                    }
                )
            self._event(
                connection,
                key,
                "PR_FOLLOWUP_RESULT_INGESTED",
                wake_digest,
                payload,
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
            if not _pr_followup_binding_columns_present(connection):
                raise LedgerError("PR follow-up binding schema migration is required")
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
                """SELECT f.*,o.issue_url,
                          i.intent_id AS bound_intent_id,
                          i.thread_id AS bound_thread_id,
                          i.worktree_path AS bound_worktree_path
                   FROM pr_followups f
                   JOIN opportunities o ON o.key=f.opportunity_key
                   JOIN intents i ON i.opportunity_key=f.opportunity_key
                     AND i.intent_id=f.intent_id
                     AND i.thread_id=f.thread_id
                     AND i.worktree_path=f.worktree_path
                   WHERE f.opportunity_key=?
                     AND f.intent_id IS NOT NULL
                     AND f.thread_id IS NOT NULL
                     AND f.worktree_path IS NOT NULL""",
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
                (key, source_wake_digest, row["bound_thread_id"]),
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
                    intent_id=str(row["bound_intent_id"]),
                    thread_id=str(row["bound_thread_id"]),
                    worktree_path_fingerprint=sha256_text(
                        str(Path(str(row["bound_worktree_path"])).resolve())
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
                {
                    "resultDigest": result_digest,
                    "stage": "PR_OPEN",
                    "intentId": str(row["bound_intent_id"]),
                    "threadId": str(row["bound_thread_id"]),
                    "worktreePath": str(row["bound_worktree_path"]),
                },
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
                """SELECT id,payload_json FROM events
                   WHERE opportunity_key=? AND event_type='TASK_RESULT_INGESTED'
                     AND dedupe_key=?""",
                (key, digest),
            ).fetchone()
            intent_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM intents WHERE opportunity_key=?", (key,)
                ).fetchone()[0]
            )
            if intent_count > 1 and not task_id and not thread_id:
                raise LedgerError("task result identity is required for multiple intents")
            if existing_result_row is not None and intent_count > 1:
                try:
                    existing_payload = json.loads(existing_result_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("task result dedupe binding is invalid") from exc
                if not isinstance(existing_payload, dict):
                    raise LedgerError("task result dedupe binding is invalid")
                existing_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=existing_payload,
                )
                incoming_payload: dict[str, Any] = {
                    "taskId": task_id,
                    "threadId": thread_id,
                }
                incoming_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=incoming_payload,
                )
                # INSERT OR IGNORE would otherwise keep an old, partially
                # attributed row and silently make the replacement result
                # look already consumed.  Reuse is safe only when both rows
                # resolve to the same immutable intent.
                if existing_binding is None or incoming_binding is None:
                    raise LedgerError("task result dedupe binding is ambiguous")
                if existing_binding["intent_id"] != incoming_binding["intent_id"]:
                    raise LedgerError("event dedupe binding mismatch")
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
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        result_payload = (
            "CASE WHEN json_valid(result.payload_json)=1 THEN result.payload_json ELSE '{}' END"
        )
        result_task_id = f"NULLIF(json_extract({result_payload},'$.taskId'),'')"
        result_intent_id = f"NULLIF(json_extract({result_payload},'$.intentId'),'')"
        result_identity = f"COALESCE({result_task_id},{result_intent_id})"
        result_thread_id = f"json_extract({result_payload},'$.threadId')"
        result_worktree_path = f"json_extract({result_payload},'$.worktreePath')"
        result_identity_shape = (
            f"NOT ({result_task_id} IS NOT NULL AND {result_intent_id} IS NOT NULL "
            f"AND {result_task_id}<>{result_intent_id})"
        )
        worktree_values: tuple[str, ...] = ()
        if worktree_path:
            raw_worktree = str(worktree_path)
            try:
                resolved_worktree = str(Path(raw_worktree).resolve())
            except (OSError, RuntimeError):
                resolved_worktree = raw_worktree
            worktree_values = tuple(dict.fromkeys((raw_worktree, resolved_worktree)))
        result_worktree_gate = ""
        result_worktree_params: tuple[str, ...] = ()
        if worktree_values:
            placeholders = ",".join("?" for _ in worktree_values)
            result_worktree_gate = (
                f"AND ({result_worktree_path} IS NULL "
                f"OR {result_worktree_path} IN ({placeholders}))"
            )
            result_worktree_params = worktree_values
            legacy_result_uniqueness = (
                f"({result_worktree_path} IS NOT NULL AND NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=result.opportunity_key "
                "AND other.intent_id<>? AND other.thread_id=? "
                f"AND other.worktree_path IN ({placeholders})"
                f")) OR ({result_worktree_path} IS NULL AND NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=result.opportunity_key "
                "AND other.intent_id<>? AND other.thread_id=?"
                "))"
            )
            legacy_result_uniqueness_params = (
                task_id,
                thread_id,
                *worktree_values,
                task_id,
                thread_id,
            )
        else:
            legacy_result_uniqueness = (
                f"{result_worktree_path} IS NULL AND NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=result.opportunity_key "
                "AND other.intent_id<>? AND other.thread_id=?"
                "))"
            )
            legacy_result_uniqueness_params = (task_id, thread_id)
        selected = connection.execute(
            f"""WITH candidates AS (
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
                   AND {result_identity_shape}
                   {result_worktree_gate}
                   AND (
                     (
                       {result_thread_id}=?
                       AND (
                         {result_identity}=?
                         OR (
                           {result_identity} IS NULL
                           AND ({legacy_result_uniqueness})
                         )
                       )
                     )
                     OR (
                       COALESCE({result_thread_id},'')=''
                       AND {result_identity}=?
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
                *result_worktree_params,
                thread_id,
                task_id,
                *legacy_result_uniqueness_params,
                task_id,
                task_id,
                thread_id,
            ),
        ).fetchone()
        related_payload = (
            "CASE WHEN json_valid(related.payload_json)=1 THEN related.payload_json ELSE '{}' END"
        )
        related_task_id = f"NULLIF(json_extract({related_payload},'$.taskId'),'')"
        related_intent_id = f"NULLIF(json_extract({related_payload},'$.intentId'),'')"
        related_identity = f"COALESCE({related_task_id},{related_intent_id})"
        related_thread_id = f"json_extract({related_payload},'$.threadId')"
        related_worktree_path = f"json_extract({related_payload},'$.worktreePath')"
        related_identity_shape = (
            f"NOT ({related_task_id} IS NOT NULL AND {related_intent_id} IS NOT NULL "
            f"AND {related_task_id}<>{related_intent_id})"
        )
        related_worktree_gate = ""
        if worktree_values:
            placeholders = ",".join("?" for _ in worktree_values)
            related_worktree_gate = (
                f"AND ({related_worktree_path} IS NULL "
                f"OR {related_worktree_path} IN ({placeholders}))"
            )
            related_legacy_uniqueness = (
                f"({related_worktree_path} IS NOT NULL AND NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=related.opportunity_key "
                "AND other.intent_id<>? AND other.thread_id=? "
                f"AND other.worktree_path IN ({placeholders})"
                f")) OR ({related_worktree_path} IS NULL AND NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=related.opportunity_key "
                "AND other.intent_id<>? AND other.thread_id=?"
                "))"
            )
            related_legacy_uniqueness_params = (
                task_id,
                thread_id,
                *worktree_values,
                task_id,
                thread_id,
            )
        else:
            related_legacy_uniqueness = (
                f"{related_worktree_path} IS NULL AND NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=related.opportunity_key "
                "AND other.intent_id<>? AND other.thread_id=?"
                "))"
            )
            related_legacy_uniqueness_params = (task_id, thread_id)
        latest_related = connection.execute(
            f"""SELECT MAX(related.id) FROM events related
               WHERE opportunity_key=?
                 AND related.event_type IN (
                   'TASK_RESULT_INGESTED',
                   'TASK_RESULT_TOMBSTONE_CONTINUATION_BOUND',
                   'TASK_RESULT_AUTHORITY_BOUND'
                 )
                 AND {related_identity_shape}
                 {related_worktree_gate}
                 AND (
                   (
                     {related_identity}=?
                     AND ({related_thread_id} IS NULL OR {related_thread_id}=?)
                   )
                   OR (
                     {related_identity} IS NULL
                     AND {related_thread_id}=?
                     AND ({related_legacy_uniqueness})
                   )
                 )""",
            (
                key,
                *result_worktree_params,
                task_id,
                thread_id,
                thread_id,
                *related_legacy_uniqueness_params,
            ),
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
                worktree_path=str(request.get("worktreePath") or "") or None,
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
                    worktree_path=worktree_path,
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
                    worktree_path=worktree_path,
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

    def published_task_result_backfill_seen(
        self,
        key: str,
        *,
        digest: str,
        intent_id: str | None = None,
        thread_id: str | None = None,
        worktree_path: str | None = None,
    ) -> bool:
        """Check a published-result backfill without crossing task bindings."""

        requested_intent = str(intent_id or "") or None
        requested_thread = str(thread_id or "") or None
        requested_worktree = str(worktree_path or "") or None
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='PUBLISHED_TASK_RESULT_BACKFILLED'
                     AND dedupe_key=?
                   ORDER BY id DESC""",
                (key, digest),
            ).fetchall()
            if not rows:
                return False
            if requested_intent is None and requested_thread is None and requested_worktree is None:
                intent_count = connection.execute(
                    "SELECT COUNT(*) FROM intents WHERE opportunity_key=?", (key,)
                ).fetchone()[0]
                return int(intent_count) == 1
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=payload,
                )
                if binding is None:
                    continue
                if requested_intent is not None and str(binding["intent_id"]) != requested_intent:
                    continue
                if (
                    requested_thread is not None
                    and str(binding["thread_id"] or "") != requested_thread
                ):
                    continue
                if requested_worktree is not None and (
                    binding["worktree_path"] is None
                    or not _resolved_path_equal(str(binding["worktree_path"]), requested_worktree)
                ):
                    continue
                return True
        return False

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
            existing = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=?
                     AND event_type='PUBLISHED_TASK_RESULT_BACKFILLED'
                     AND dedupe_key=?""",
                (key, digest),
            ).fetchone()
            intent_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM intents WHERE opportunity_key=?", (key,)
                ).fetchone()[0]
            )
            if existing is not None and intent_count > 1:
                try:
                    existing_payload = json.loads(existing["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("published result dedupe binding is invalid") from exc
                if not isinstance(existing_payload, dict):
                    raise LedgerError("published result dedupe binding is invalid")
                existing_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload=existing_payload,
                )
                incoming_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=key,
                    payload={"taskId": task_id, "threadId": thread_id},
                )
                if existing_binding is None or incoming_binding is None:
                    raise LedgerError("published result dedupe binding is ambiguous")
                if existing_binding["intent_id"] != incoming_binding["intent_id"]:
                    raise LedgerError("event dedupe binding mismatch")
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
        if status != "RECONCILE_REQUIRED":
            self._resume_deferred_publication_no_go(effect_id)

    def mark_pull_request_creation_attempt(self, *, effect_id: str, permit_id: str) -> None:
        """Persist the boundary immediately before a real PR-create call."""

        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT e.status,e.action,e.result_json,r.opportunity_key,
                          json_extract(r.request_json,'$.publicationKind') AS publication_kind
                   FROM publication_effects e
                   JOIN publication_permits p ON p.permit_id=e.permit_id
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE e.effect_id=? AND e.permit_id=?""",
                (effect_id, permit_id),
            ).fetchone()
            if row is None or row["action"] != "create_pr":
                raise LedgerError("pull-request creation effect is unavailable")
            if row["status"] not in {"ATTEMPTED", "RECONCILE_REQUIRED"}:
                raise LedgerError("pull-request creation effect is not attemptable")
            if row["publication_kind"] != "PR_CREATE":
                raise LedgerError("pull-request creation attempt is not a new publication")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                operation="pull-request creation attempt",
            )
            prior = json.loads(row["result_json"] or "{}")
            prior["creationAttempted"] = True
            connection.execute(
                """UPDATE publication_effects SET result_json=?,updated_at=?
                   WHERE effect_id=?""",
                (canonical_json(prior), now, effect_id),
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
                "SELECT * FROM publication_requests WHERE request_id=?",
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
            request_binding, _ = _resolve_publication_request_binding(connection, request_row)
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
                    "UPDATE intents SET status='COMPLETED',updated_at=? WHERE intent_id=?",
                    (now, request_binding["intent_id"]),
                )
                self._event(
                    connection,
                    request["opportunity_key"],
                    "PR_OPEN",
                    pr_url,
                    {
                        "permitId": permit_id,
                        "prUrl": pr_url,
                        "intentId": request_binding["intent_id"],
                        "threadId": request_binding["thread_id"],
                        "worktreePath": request_binding["worktree_path"],
                    },
                    now,
                )
                self._retire_pr_followup_snapshot_after_publication(
                    connection, request=request, pr_url=pr_url, now=now
                )

    def publication_feedback_candidates(self) -> list[dict[str, Any]]:
        """Return published tasks whose visible task reply does not yet reflect the PR."""

        binding_clause = f"""
            (
              {_intent_event_binding_clause("i", "opened")}
              OR (
                json_valid(opened.payload_json)=1
                AND json_extract(opened.payload_json,'$.intentId') IS NULL
                AND json_extract(opened.payload_json,'$.threadId') IS NULL
                AND json_extract(opened.payload_json,'$.worktreePath') IS NULL
                AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                AND NOT EXISTS (
                  SELECT 1 FROM intents other
                  WHERE other.opportunity_key=o.key
                    AND other.intent_id<>i.intent_id
                    AND other.thread_id IS NOT NULL
                    AND other.worktree_path IS NOT NULL
                )
              )
            )
        """
        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.issue_url,i.intent_id,i.thread_id,i.worktree_path,
                          COALESCE(
                            json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                          ) AS pr_url,opened.created_at AS published_at
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events opened ON opened.opportunity_key=o.key
                     AND opened.event_type='PR_OPEN'
                     AND {binding_clause}
                   WHERE o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND NOT EXISTS (
                       SELECT 1 FROM events newer
                       WHERE newer.opportunity_key=o.key
                         AND newer.event_type='PR_OPEN'
                         AND COALESCE(
                           json_extract(newer.payload_json,'$.prUrl'),newer.dedupe_key
                         )=COALESCE(
                           json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                         )
                         AND newer.id>opened.id
                         AND (
                           {_intent_event_binding_clause("i", "newer")}
                           OR (
                             json_valid(newer.payload_json)=1
                             AND json_extract(newer.payload_json,'$.intentId') IS NULL
                             AND json_extract(newer.payload_json,'$.threadId') IS NULL
                             AND json_extract(newer.payload_json,'$.worktreePath') IS NULL
                             AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                             AND NOT EXISTS (
                               SELECT 1 FROM intents other
                               WHERE other.opportunity_key=o.key
                                 AND other.intent_id<>i.intent_id
                                 AND other.thread_id IS NOT NULL
                                 AND other.worktree_path IS NOT NULL
                             )
                           )
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=COALESCE(
                           json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                         )
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                         AND json_extract(reserved.payload_json,'$.prUrl')=COALESCE(
                           json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                         )
                         AND {_intent_event_binding_clause("i", "reserved")}
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                             WHERE abandoned.opportunity_key=o.key
                               AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                               AND abandoned.dedupe_key=reserved.dedupe_key
                               AND {_intent_event_binding_clause("i", "abandoned")}
                         )
                     )
                   ORDER BY opened.created_at"""
            ).fetchall()
        # A PR URL can only be delivered after one immutable task owns it.
        # If legacy/manual history claims the same URL for multiple intents,
        # suppress all candidates instead of arbitrarily choosing one thread.
        conflict_urls = {
            str(pr_url)
            for pr_url in {str(row["pr_url"]) for row in rows}
            if len({str(row["intent_id"]) for row in rows if str(row["pr_url"]) == pr_url}) > 1
        }
        if conflict_urls:
            rows = [row for row in rows if str(row["pr_url"]) not in conflict_urls]
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "prUrl": row["pr_url"],
                "publishedAt": row["published_at"],
            }
            for row in rows
        ]

    def controller_publication_notice_candidates(self) -> list[dict[str, Any]]:
        """Return newly-created PRs not yet shown by the controller heartbeat."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,
                          json_extract(opened.payload_json,'$.prUrl') AS pr_url,
                          opened.created_at AS published_at
                   FROM opportunities o
                   JOIN events opened ON opened.id=(
                     SELECT MAX(e.id) FROM events e
                     WHERE e.opportunity_key=o.key AND e.event_type='PR_OPEN'
                   )
                   WHERE json_extract(opened.payload_json,'$.prUrl') IS NOT NULL
                     AND EXISTS (
                       SELECT 1 FROM publication_requests request
                       JOIN publication_permits permit
                         ON permit.request_id=request.request_id
                       JOIN publication_effects effect
                         ON effect.permit_id=permit.permit_id
                       WHERE request.opportunity_key=o.key
                         AND permit.pr_url=json_extract(opened.payload_json,'$.prUrl')
                         AND json_extract(request.request_json,'$.publicationKind')='PR_CREATE'
                         AND effect.action='create_pr'
                         AND effect.status='SUCCEEDED'
                         AND json_extract(effect.result_json,'$.created')=1
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='CONTROLLER_PUBLICATION_NOTICE_SENT'
                         AND sent.dedupe_key=json_extract(opened.payload_json,'$.prUrl')
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='CONTROLLER_PUBLICATION_NOTICE_RESERVED'
                         AND json_extract(reserved.payload_json,'$.prUrl')=
                             json_extract(opened.payload_json,'$.prUrl')
                     )
                   ORDER BY opened.created_at,opened.id"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "prUrl": row["pr_url"],
                "publishedAt": row["published_at"],
            }
            for row in rows
        ]

    def unresolved_controller_publication_notices(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,
                          json_extract(reserved.payload_json,'$.prUrl') AS pr_url,
                          json_extract(reserved.payload_json,'$.publishedAt') AS published_at,
                          reserved.dedupe_key AS reservation_nonce,
                          reserved.created_at AS reserved_at
                   FROM events reserved
                   JOIN opportunities o ON o.key=reserved.opportunity_key
                   WHERE reserved.event_type='CONTROLLER_PUBLICATION_NOTICE_RESERVED'
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=reserved.opportunity_key
                         AND sent.event_type='CONTROLLER_PUBLICATION_NOTICE_SENT'
                         AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                     )
                   ORDER BY reserved.created_at,reserved.id"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "prUrl": row["pr_url"],
                "publishedAt": row["published_at"],
                "reservationNonce": row["reservation_nonce"],
                "reservedAt": row["reserved_at"],
            }
            for row in rows
        ]

    def reserve_controller_publication_notice(self, *, pr_url: str) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        nonce = sha256_text(f"controller-publication-notice|{pr_url}|{now}")
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key,o.issue_url,opened.created_at AS published_at
                   FROM opportunities o
                   JOIN events opened ON opened.opportunity_key=o.key
                    AND opened.event_type='PR_OPEN'
                    AND json_extract(opened.payload_json,'$.prUrl')=?
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events sent
                     WHERE sent.opportunity_key=o.key
                       AND sent.event_type='CONTROLLER_PUBLICATION_NOTICE_SENT'
                       AND sent.dedupe_key=?
                   )
                     AND EXISTS (
                       SELECT 1 FROM publication_requests request
                       JOIN publication_permits permit
                         ON permit.request_id=request.request_id
                       JOIN publication_effects effect
                         ON effect.permit_id=permit.permit_id
                       WHERE request.opportunity_key=o.key
                         AND permit.pr_url=?
                         AND json_extract(request.request_json,'$.publicationKind')='PR_CREATE'
                         AND effect.action='create_pr'
                         AND effect.status='SUCCEEDED'
                         AND json_extract(effect.result_json,'$.created')=1
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='CONTROLLER_PUBLICATION_NOTICE_RESERVED'
                         AND json_extract(reserved.payload_json,'$.prUrl')=?
                   )
                   ORDER BY opened.id DESC LIMIT 1""",
                (pr_url, pr_url, pr_url, pr_url),
            ).fetchone()
            if row is None:
                raise LedgerError("controller publication notice is stale or already reserved")
            self._event(
                connection,
                row["key"],
                "CONTROLLER_PUBLICATION_NOTICE_RESERVED",
                nonce,
                {"prUrl": pr_url, "publishedAt": row["published_at"]},
                now,
            )
        return {
            "key": row["key"],
            "issueUrl": row["issue_url"],
            "prUrl": pr_url,
            "publishedAt": row["published_at"],
            "reservationNonce": nonce,
            "reservedAt": now,
        }

    def commit_controller_publication_notice(self, *, reservation_nonce: str, pr_url: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key FROM events
                   WHERE event_type='CONTROLLER_PUBLICATION_NOTICE_RESERVED'
                     AND dedupe_key=?
                     AND json_extract(payload_json,'$.prUrl')=?
                   LIMIT 1""",
                (reservation_nonce, pr_url),
            ).fetchone()
            if row is None:
                raise LedgerError("controller publication notice reservation is unavailable")
            existing = connection.execute(
                """SELECT 1 FROM events
                   WHERE opportunity_key=?
                     AND event_type='CONTROLLER_PUBLICATION_NOTICE_SENT'
                     AND dedupe_key=? LIMIT 1""",
                (row["opportunity_key"], pr_url),
            ).fetchone()
            if existing is not None:
                return
            self._event(
                connection,
                row["opportunity_key"],
                "CONTROLLER_PUBLICATION_NOTICE_SENT",
                pr_url,
                {"prUrl": pr_url, "reservationNonce": reservation_nonce},
                now,
            )

    def unresolved_publication_feedback(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.issue_url,i.intent_id,i.thread_id,i.worktree_path,
                          json_extract(reserved.payload_json,'$.prUrl') AS pr_url,
                          reserved.dedupe_key AS reservation_nonce,
                          reserved.created_at AS reserved_at
                   FROM opportunities o
                   JOIN events reserved ON reserved.opportunity_key=o.key
                     AND reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {_intent_event_binding_clause("i", "reserved")}
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events sent
                     WHERE sent.opportunity_key=o.key
                       AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                       AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                       AND {_intent_event_binding_clause("i", "sent")}
                   )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=o.key
                         AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                         AND abandoned.dedupe_key=reserved.dedupe_key
                         AND {_intent_event_binding_clause("i", "abandoned")}
                   )
                   ORDER BY reserved.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "prUrl": row["pr_url"],
                "reservationNonce": row["reservation_nonce"],
                "reservedAt": row["reserved_at"],
            }
            for row in rows
        ]

    def reserve_publication_feedback(
        self,
        *,
        thread_id: str,
        pr_url: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        nonce = sha256_text(f"{thread_id}|{pr_url}|{now}|{secrets.token_hex(16)}")
        intent_join = ["i.thread_id=?", "i.worktree_path IS NOT NULL"]
        intent_params: list[str] = [thread_id]
        if intent_id:
            intent_join.append("i.intent_id=?")
            intent_params.append(str(intent_id))
        elif not worktree_path:
            # A legacy caller supplies only a thread.  Accept it only when
            # that thread identifies one complete intent for this opportunity.
            intent_join.append(
                "NOT EXISTS ("
                "SELECT 1 FROM intents other "
                "WHERE other.opportunity_key=o.key "
                "AND other.intent_id<>i.intent_id "
                "AND other.thread_id=? "
                "AND other.worktree_path IS NOT NULL)"
            )
            intent_params.append(thread_id)
        # Select an opened event that is itself attributable to the selected
        # intent.  Looking up the latest URL match without this predicate lets
        # a later intent's PR_OPEN hide (or be mistaken for) the caller's
        # publication.
        opened_binding = (
            f"({_intent_event_binding_clause('i', 'e')} OR "
            f"{_legacy_unique_unbound_event_clause('i', 'e')})"
        )
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT o.key,o.issue_url,i.intent_id,i.thread_id,i.worktree_path,
                          opened.created_at AS published_at
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                     AND {" AND ".join(intent_join)}
                   JOIN events opened ON opened.id=(
                     SELECT MAX(e.id) FROM events e
                     WHERE e.opportunity_key=o.key AND e.event_type='PR_OPEN'
                       AND COALESCE(
                         json_extract(
                           CASE WHEN json_valid(e.payload_json)=1
                                THEN e.payload_json ELSE '{{}}' END,
                           '$.prUrl'
                         ),
                         e.dedupe_key
                       )=?
                       AND {opened_binding}
                   )
                   WHERE o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED')
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=o.key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=?
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                         AND json_extract(reserved.payload_json,'$.prUrl')=?
                         AND {_intent_event_binding_clause("i", "reserved")}
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                             WHERE abandoned.opportunity_key=o.key
                               AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                               AND abandoned.dedupe_key=reserved.dedupe_key
                               AND {_intent_event_binding_clause("i", "abandoned")}
                         )
                     )""",
                tuple(intent_params) + (pr_url, pr_url, pr_url),
            ).fetchall()
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            if len(rows) > 1:
                raise LedgerError("publication feedback identity is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                raise LedgerError("publication feedback is stale or already reserved")

            # This is the compare-and-swap guard for duplicate PR URLs.  The
            # reservation transaction is BEGIN IMMEDIATE, so the complete
            # claim set is observed atomically with the event we append.  If
            # any same-URL PR_OPEN cannot be resolved to the selected intent,
            # or resolves to another intent generation, fail closed instead of
            # sending a status reply to the wrong task.
            claim_rows = connection.execute(
                """SELECT payload_json,dedupe_key
                   FROM events
                   WHERE opportunity_key=?
                     AND event_type='PR_OPEN'
                     AND COALESCE(
                       json_extract(
                         CASE WHEN json_valid(payload_json)=1
                              THEN payload_json ELSE '{}'
                         END,
                         '$.prUrl'
                       ),
                       dedupe_key
                     )=?""",
                (str(row["key"]), pr_url),
            ).fetchall()
            claim_intents: set[str] = set()
            for claim in claim_rows:
                try:
                    claim_payload = json.loads(claim["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("publication feedback identity is ambiguous") from exc
                claim_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=str(row["key"]),
                    payload=claim_payload,
                )
                if claim_binding is None:
                    raise LedgerError("publication feedback identity is ambiguous")
                claim_intents.add(str(claim_binding["intent_id"]))
            if claim_intents != {str(row["intent_id"])}:
                raise LedgerError("publication feedback identity is ambiguous")
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
                {
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
                    "prUrl": pr_url,
                    "reservationNonce": nonce,
                },
                now,
            )
        return {
            "key": row["key"],
            "issueUrl": row["issue_url"],
            "intentId": row["intent_id"],
            "threadId": row["thread_id"],
            "worktreePath": row["worktree_path"],
            "prUrl": pr_url,
            "publishedAt": row["published_at"],
            "reservationNonce": nonce,
            "reservedAt": now,
        }

    def commit_publication_feedback(
        self,
        *,
        thread_id: str,
        reservation_nonce: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT reserved.opportunity_key,i.intent_id,i.worktree_path,
                          json_extract(reserved.payload_json,'$.prUrl') AS pr_url
                   FROM events reserved
                   JOIN intents i ON i.opportunity_key=reserved.opportunity_key
                     AND {_intent_event_binding_clause("i", "reserved")}
                   WHERE reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                     AND json_extract(reserved.payload_json,'$.threadId')=?
                     AND reserved.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=reserved.opportunity_key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=reserved.opportunity_key
                         AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                         AND abandoned.dedupe_key=reserved.dedupe_key
                         AND {_intent_event_binding_clause("i", "abandoned")}
                     )
                   ORDER BY reserved.id DESC""",
                (thread_id, reservation_nonce),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if str(row["intent_id"] or "") == str(intent_id)]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            if len(rows) > 1:
                raise LedgerError("publication feedback reservation is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                sent_rows = connection.execute(
                    f"""SELECT i.intent_id,i.worktree_path
                       FROM events reserved
                       JOIN events sent
                       ON sent.opportunity_key=reserved.opportunity_key
                      AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                      AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                       JOIN intents i ON i.opportunity_key=reserved.opportunity_key
                        AND {_intent_event_binding_clause("i", "reserved")}
                        AND {_intent_event_binding_clause("i", "sent")}
                       WHERE reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                         AND json_extract(reserved.payload_json,'$.threadId')=?
                         AND reserved.dedupe_key=?
                       ORDER BY sent.id DESC""",
                    (thread_id, reservation_nonce),
                ).fetchall()
                if intent_id:
                    sent_rows = [
                        value
                        for value in sent_rows
                        if str(value["intent_id"] or "") == str(intent_id)
                    ]
                if worktree_path:
                    sent_rows = [
                        value
                        for value in sent_rows
                        if value["worktree_path"]
                        and _resolved_path_equal(str(value["worktree_path"]), str(worktree_path))
                    ]
                if len(sent_rows) > 1:
                    raise LedgerError("publication feedback reservation is ambiguous")
                if sent_rows:
                    return
                raise LedgerError("publication feedback reservation is unavailable")
            self._event(
                connection,
                row["opportunity_key"],
                "THREAD_PUBLICATION_STATUS_SENT",
                row["pr_url"],
                {
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT reserved.opportunity_key,i.intent_id,i.worktree_path,reserved.created_at
                   FROM events reserved
                   JOIN intents i ON i.opportunity_key=reserved.opportunity_key
                     AND {_intent_event_binding_clause("i", "reserved")}
                   WHERE reserved.event_type='THREAD_PUBLICATION_STATUS_RESERVED'
                     AND json_extract(reserved.payload_json,'$.threadId')=?
                     AND reserved.dedupe_key=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=reserved.opportunity_key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=json_extract(reserved.payload_json,'$.prUrl')
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events abandoned
                       WHERE abandoned.opportunity_key=reserved.opportunity_key
                         AND abandoned.event_type='THREAD_PUBLICATION_STATUS_ABANDONED'
                         AND abandoned.dedupe_key=reserved.dedupe_key
                         AND {_intent_event_binding_clause("i", "abandoned")}
                     )
                   ORDER BY reserved.id DESC""",
                (thread_id, reservation_nonce),
            ).fetchall()
            if intent_id:
                rows = [row for row in rows if str(row["intent_id"] or "") == str(intent_id)]
            if worktree_path:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"]
                    and _resolved_path_equal(str(row["worktree_path"]), str(worktree_path))
                ]
            if len(rows) > 1:
                raise LedgerError("publication feedback reservation is ambiguous")
            row = rows[0] if rows else None
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
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        """Record that the existing final task reply already contains the exact PR URL."""
        if not isinstance(thread_id, str) or not thread_id:
            raise LedgerError("publication feedback thread identity is invalid")
        if intent_id is not None and (not isinstance(intent_id, str) or not intent_id):
            raise LedgerError("publication feedback intent identity is invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            rows = connection.execute(
                f"""SELECT opened.opportunity_key
                          ,i.intent_id,i.thread_id,i.worktree_path
                   FROM events opened
                   JOIN intents i ON i.opportunity_key=opened.opportunity_key
                     AND (
                       {_intent_event_binding_clause("i", "opened")}
                       OR (
                         i.thread_id=? AND i.worktree_path IS NOT NULL
                         AND json_valid(opened.payload_json)=1
                         AND json_extract(opened.payload_json,'$.intentId') IS NULL
                         AND json_extract(opened.payload_json,'$.threadId') IS NULL
                         AND json_extract(opened.payload_json,'$.worktreePath') IS NULL
                         AND NOT EXISTS (
                           SELECT 1 FROM intents other
                           WHERE other.opportunity_key=opened.opportunity_key
                             AND other.intent_id<>i.intent_id
                             AND other.thread_id=i.thread_id
                             AND other.worktree_path IS NOT NULL
                         )
                       )
                     )
                   WHERE opened.event_type='PR_OPEN'
                     AND (
                       json_extract(
                         CASE WHEN json_valid(opened.payload_json)
                              THEN opened.payload_json ELSE '{{}}' END,
                         '$.threadId'
                       )=?
                       OR json_extract(
                         CASE WHEN json_valid(opened.payload_json)
                              THEN opened.payload_json ELSE '{{}}' END,
                         '$.threadId'
                       ) IS NULL
                     )
                     AND COALESCE(
                       json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                     )=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events sent
                       WHERE sent.opportunity_key=opened.opportunity_key
                         AND sent.event_type='THREAD_PUBLICATION_STATUS_SENT'
                         AND sent.dedupe_key=COALESCE(
                           json_extract(opened.payload_json,'$.prUrl'),opened.dedupe_key
                         )
                         AND {_intent_event_binding_clause("i", "sent")}
                     )
                   ORDER BY opened.id DESC""",
                (thread_id, thread_id, pr_url),
            ).fetchall()
            if intent_id is not None:
                rows = [row for row in rows if str(row["intent_id"] or "") == intent_id]
            if worktree_path is not None:
                rows = [
                    row
                    for row in rows
                    if row["worktree_path"] is not None
                    and _resolved_path_equal(str(row["worktree_path"]), worktree_path)
                ]
            if len(rows) > 1:
                raise LedgerError("publication feedback binding is ambiguous")
            row = rows[0] if rows else None
            if row is None:
                return
            self._event(
                connection,
                row["opportunity_key"],
                "THREAD_PUBLICATION_STATUS_SENT",
                pr_url,
                {
                    "intentId": row["intent_id"],
                    "threadId": thread_id,
                    "worktreePath": row["worktree_path"],
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
                "SELECT * FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
            if request is None:
                raise LedgerError("publication request is missing")
            request_binding, _ = _resolve_publication_request_binding(connection, request)
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
                    "UPDATE intents SET status='COMPLETED',updated_at=? WHERE intent_id=?",
                    (now, request_binding["intent_id"]),
                )
                self._event(
                    connection,
                    request["opportunity_key"],
                    "PR_OPEN",
                    pr_url,
                    {
                        "permitId": permit_id,
                        "prUrl": pr_url,
                        "intentId": request_binding["intent_id"],
                        "threadId": request_binding["thread_id"],
                        "worktreePath": request_binding["worktree_path"],
                    },
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
                          i.intent_id,i.title_synced_state
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.stage='AUDIT_NO_GO' AND i.thread_id IS NOT NULL
                     AND i.rowid=(
                       SELECT MAX(current.rowid) FROM intents current
                       WHERE current.opportunity_key=o.key
                     )
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
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "stage": row["stage"],
                "titleSyncedState": row["title_synced_state"],
                "cleanupNonce": sha256_text(
                    f"{row['key']}|{row['intent_id']}|{row['thread_id']}|"
                    f"{row['worktree_path']}|{row['stage']}|{row['updated_at']}"
                ),
            }
            for row in rows
        ]

    def cleanup_candidates(self) -> list[dict[str, Any]]:
        return self._cleanup_candidates(require_title_sync=True)

    def cleanup_reconciliation_candidates(self) -> list[dict[str, Any]]:
        """Include no-go tasks whose desktop thread was archived before title sync."""

        return self._cleanup_candidates(require_title_sync=False)

    def commit_cleanup(
        self,
        *,
        thread_id: str,
        nonce: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        candidates = [
            item
            for item in self.cleanup_candidates()
            if item["threadId"] == thread_id
            and item["cleanupNonce"] == nonce
            and (intent_id is None or item.get("intentId") == intent_id)
            and (
                worktree_path is None
                or _resolved_path_equal(str(item.get("worktreePath") or ""), worktree_path)
            )
        ]
        candidate = candidates[0] if len(candidates) == 1 else None
        if candidate is None:
            raise LedgerError("cleanup authorization is stale or invalid")
        self._commit_cleanup_candidate(candidate, nonce=nonce)

    def commit_reconciled_cleanup(
        self,
        *,
        thread_id: str,
        nonce: str,
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> None:
        candidates = [
            item
            for item in self.cleanup_reconciliation_candidates()
            if item["threadId"] == thread_id
            and item["cleanupNonce"] == nonce
            and (intent_id is None or item.get("intentId") == intent_id)
            and (
                worktree_path is None
                or _resolved_path_equal(str(item.get("worktreePath") or ""), worktree_path)
            )
        ]
        candidate = candidates[0] if len(candidates) == 1 else None
        if candidate is None:
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
                {
                    "intentId": candidate.get("intentId"),
                    "threadId": candidate["threadId"],
                    "worktreePath": candidate.get("worktreePath"),
                    "cleanupNonce": nonce,
                },
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any]:
        """Atomically bind a reserved turn to the current quarantine-free state."""

        # The bridge carries the immutable task identity whenever it is
        # available.  Keep both arguments optional for legacy callers and
        # normalize them once for the fail-closed checks below.
        intent_id = str(intent_id) if intent_id else None
        worktree_path = str(worktree_path) if worktree_path else None

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
        if intent_id:
            idempotency_key += f":intent:{intent_id}"
        if worktree_path:
            idempotency_key += f":worktree:{sha256_text(worktree_path)}"
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

        def select_bound_row(
            connection: sqlite3.Connection,
            rows: list[sqlite3.Row],
            *,
            ambiguity_message: str,
            eligible=None,
        ) -> tuple[sqlite3.Row, sqlite3.Row] | None:
            """Resolve every candidate before choosing a task reservation.

            The previous newest-first lookup let a replacement task hide an
            older valid reservation whenever they shared a thread or digest.
            Resolve all rows to immutable identities first; only rows that
            collapse to one exact identity may be selected.
            """

            resolved: list[tuple[sqlite3.Row, sqlite3.Row]] = []
            for candidate_row in rows:
                try:
                    payload = json.loads(candidate_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                binding_row = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=str(candidate_row["opportunity_key"]),
                    payload=payload,
                )
                if binding_row is None:
                    continue
                if str(binding_row["thread_id"] or "") != thread_id:
                    continue
                if intent_id and str(binding_row["intent_id"] or "") != intent_id:
                    continue
                if worktree_path and not _resolved_path_equal(
                    str(binding_row["worktree_path"] or ""), worktree_path
                ):
                    continue
                if eligible is not None and not eligible(candidate_row, binding_row):
                    continue
                resolved.append((candidate_row, binding_row))
            if not resolved:
                return None
            identities = {
                (
                    str(binding["intent_id"]),
                    str(binding["thread_id"]),
                    str(binding["worktree_path"]),
                )
                for _row, binding in resolved
            }
            if len(identities) > 1:
                raise LedgerError(ambiguity_message)
            return resolved[0]

        def bound_event_exists(
            connection: sqlite3.Connection,
            *,
            opportunity_key: str,
            event_type: str,
            binding: sqlite3.Row,
            dedupe_key: str | None = None,
            after_id: int | None = None,
            payload_field: str | None = None,
            payload_value: str | None = None,
        ) -> bool:
            """Check a lifecycle event only after resolving its identity."""

            clauses = ["opportunity_key=?", "event_type=?"]
            params: list[Any] = [opportunity_key, event_type]
            if dedupe_key is not None:
                clauses.append("dedupe_key=?")
                params.append(dedupe_key)
            if after_id is not None:
                clauses.append("id>?")
                params.append(after_id)
            rows = connection.execute(
                f"SELECT id,payload_json FROM events WHERE {' AND '.join(clauses)} ORDER BY id DESC",
                tuple(params),
            ).fetchall()
            for event_row in rows:
                try:
                    payload = json.loads(event_row["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                if payload_field is not None and payload.get(payload_field) != payload_value:
                    continue
                event_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=opportunity_key,
                    payload=payload,
                )
                if event_binding is None:
                    continue
                if str(event_binding["intent_id"]) != str(binding["intent_id"]):
                    continue
                if str(event_binding["thread_id"]) != str(binding["thread_id"]):
                    continue
                if not _resolved_path_equal(
                    str(event_binding["worktree_path"]), str(binding["worktree_path"])
                ):
                    continue
                return True
            return False

        with self.transaction() as connection:
            if delivery_kind == "implementation-followup":
                rows = connection.execute(
                    """SELECT r.id,r.opportunity_key,r.payload_json,r.dedupe_key
                       FROM events r
                       WHERE r.event_type='IMPLEMENTATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND (r.dedupe_key=? OR json_extract(r.payload_json,'$.resultDigest')=?)
                       ORDER BY r.id DESC""",
                    (thread_id, delivery_token, delivery_token),
                ).fetchall()
                rows = [
                    candidate_row
                    for candidate_row in rows
                    if candidate_row["dedupe_key"] == delivery_attempt_digest
                ]
                selected = select_bound_row(
                    connection,
                    rows,
                    ambiguity_message="task-turn delivery reservation is ambiguous",
                    eligible=lambda candidate_row, binding: (
                        not bound_event_exists(
                            connection,
                            opportunity_key=str(candidate_row["opportunity_key"]),
                            event_type="IMPLEMENTATION_FOLLOWUP_SENT",
                            binding=binding,
                            dedupe_key=str(candidate_row["dedupe_key"]),
                        )
                    ),
                )
                row, resolved_binding = selected if selected is not None else (None, None)
            elif delivery_kind == "validation-followup":
                rows = connection.execute(
                    """SELECT r.id,r.opportunity_key,r.payload_json,r.dedupe_key
                       FROM events r
                       WHERE r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                         AND json_extract(r.payload_json,'$.threadId')=?
                         AND json_extract(r.payload_json,'$.resultDigest')=?
                         AND json_extract(r.payload_json,'$.reservationDigest')=?
                       ORDER BY r.id DESC""",
                    (thread_id, delivery_token, reservation_digest),
                ).fetchall()
                selected = select_bound_row(
                    connection,
                    rows,
                    ambiguity_message="task-turn delivery reservation is ambiguous",
                    eligible=lambda candidate_row, binding: (
                        not bound_event_exists(
                            connection,
                            opportunity_key=str(candidate_row["opportunity_key"]),
                            event_type="VALIDATION_FOLLOWUP_SENT",
                            binding=binding,
                            dedupe_key=delivery_token,
                        )
                        and not bound_event_exists(
                            connection,
                            opportunity_key=str(candidate_row["opportunity_key"]),
                            event_type="VALIDATION_FOLLOWUP_RESERVATION_CANCELLED",
                            binding=binding,
                            after_id=int(candidate_row["id"]),
                            payload_field="reservationDigest",
                            payload_value=reservation_digest,
                        )
                    ),
                )
                row, resolved_binding = selected if selected is not None else (None, None)
            else:
                event_type, predicate = selector
                rows = connection.execute(
                    f"""SELECT id,opportunity_key,payload_json,dedupe_key FROM events
                        WHERE event_type=? AND {predicate}
                        ORDER BY id DESC""",
                    (event_type, thread_id, delivery_token),
                ).fetchall()
                sent_type = {
                    "pr-followup": "PR_FOLLOWUP_SENT",
                    "recovery": "THREAD_RECOVERY_SENT",
                    "publication-feedback": "THREAD_PUBLICATION_STATUS_SENT",
                }.get(delivery_kind)

                def sent_dedupe(candidate_row: sqlite3.Row) -> str | None:
                    if delivery_kind != "publication-feedback":
                        return str(candidate_row["dedupe_key"])
                    try:
                        payload = json.loads(candidate_row["payload_json"] or "{}")
                    except (TypeError, json.JSONDecodeError):
                        return None
                    value = payload.get("prUrl") if isinstance(payload, dict) else None
                    return str(value) if value else None

                selected = select_bound_row(
                    connection,
                    rows,
                    ambiguity_message="task-turn delivery reservation is ambiguous",
                    eligible=(
                        lambda candidate_row, binding: (
                            not bound_event_exists(
                                connection,
                                opportunity_key=str(candidate_row["opportunity_key"]),
                                event_type=str(sent_type),
                                binding=binding,
                                dedupe_key=sent_dedupe(candidate_row),
                            )
                            if sent_type
                            else True
                        )
                    ),
                )
                row, resolved_binding = selected if selected is not None else (None, None)
            if row is None:
                raise LedgerError("task-turn delivery reservation is unavailable")

            # Resolve the reservation payload to one immutable intent before
            # starting a user-visible turn.  Without this check, a historical
            # event sharing a thread/token could silently bind to whichever
            # row happened to be newest.  Legacy payloads remain usable only
            # when the resolver can prove a unique thread/worktree binding.
            try:
                reservation_payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError) as exc:
                raise LedgerError("task-turn delivery reservation binding is invalid") from exc
            if resolved_binding is None:
                resolved_binding = _resolve_event_intent_binding(
                    connection,
                    opportunity_key=str(row["opportunity_key"]),
                    payload=reservation_payload,
                )
            if resolved_binding is None:
                raise LedgerError("task-turn delivery reservation binding is ambiguous")
            if str(resolved_binding["thread_id"] or "") != str(thread_id):
                raise LedgerError("task-turn delivery thread binding mismatch")
            if intent_id and str(resolved_binding["intent_id"] or "") != intent_id:
                raise LedgerError("task-turn delivery intent binding mismatch")
            if worktree_path and not _resolved_path_equal(
                str(resolved_binding["worktree_path"] or ""), worktree_path
            ):
                raise LedgerError("task-turn delivery worktree binding mismatch")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"]),
                operation="task-turn delivery start",
            )
            binding = {
                "deliveryKind": delivery_kind,
                "threadId": thread_id,
                "deliveryToken": delivery_token,
                # Persist the resolver's result even when a legacy caller did
                # not supply identity explicitly.  This prevents a later
                # rollover from inheriting an old idempotency record.
                "intentId": str(resolved_binding["intent_id"]),
                "worktreePath": str(resolved_binding["worktree_path"]),
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
                if any(
                    key not in {"intentId", "worktreePath"} and payload.get(key) != value
                    for key, value in binding.items()
                ) or any(
                    key in payload and payload.get(key) != value
                    for key, value in binding.items()
                    if key in {"intentId", "worktreePath"}
                ):
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
        intent_id: str | None = None,
        worktree_path: str | None = None,
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT payload_json FROM events
                   WHERE event_type='TASK_TURN_DELIVERY_STARTED'
                     AND json_extract(payload_json,'$.deliveryKind')='validation-followup'
                     AND json_extract(payload_json,'$.threadId')=?
                     AND json_extract(payload_json,'$.resultDigest')=?
                     AND json_extract(payload_json,'$.reservationDigest')=?
                   ORDER BY id DESC""",
                (thread_id, result_digest, reservation_digest),
            ).fetchall()
        matches: list[sqlite3.Row] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            if intent_id and str(payload.get("intentId") or "") != str(intent_id):
                continue
            if worktree_path and not payload.get("worktreePath"):
                continue
            if worktree_path and not _resolved_path_equal(
                str(payload.get("worktreePath")), str(worktree_path)
            ):
                continue
            matches.append(row)
        if len(matches) != 1:
            return None
        payload = json.loads(matches[0]["payload_json"])
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
        if event_type in _IDENTITY_GUARDED_EVENT_TYPES:
            existing = connection.execute(
                """SELECT payload_json FROM events
                   WHERE opportunity_key=? AND event_type=? AND dedupe_key=?""",
                (key, event_type, dedupe_key),
            ).fetchone()
            if existing is not None:
                try:
                    existing_payload = json.loads(existing["payload_json"] or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise LedgerError("event binding payload is invalid") from exc
                if _event_identity_conflicts(existing_payload, payload):
                    raise LedgerError("event dedupe binding mismatch")
        connection.execute(
            """INSERT OR IGNORE INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?)""",
            (key, event_type, dedupe_key, canonical_json(payload), created_at),
        )
