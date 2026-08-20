"""Safe, replayable persistence for the managed lifecycle across workflow runs."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from .managed_lifecycle import (
    MANAGED_SCHEMA_VERSION,
    ManagedLedger,
    _attestation_authenticated,
    _attestation_structure_valid,
    canonical_opportunity_identity,
    public_reply_policy_digest,
    render_reply_template,
    schema_digest,
    verify_validation_certificate_history,
)
from .managed_lifecycle import (
    _certificate_structure_valid as _certificate_shape,
)
from .managed_security import (
    sensitive_identity,
    sign_current,
    stable_fingerprint,
    verify_current,
    verify_current_or_previous,
)
from .repo_probe import thread_fingerprint, verify_probe_receipt
from .util import canonical_json

SNAPSHOT_SCHEMA_VERSION = "managed_lifecycle_snapshot_v6"
LEGACY_SNAPSHOT_SCHEMA_VERSION = "managed_lifecycle_snapshot_v5"
LEGACY_MANAGED_SCHEMA_VERSION = 7
LEGACY_MANAGED_SCHEMA_V7_DIGEST = "10ed2d89cd0357806d3e62f3ef140f42c2c234b9cb4b82ed406ce24983153a0e"
LEGACY_V7_ROW_KEYS = frozenset(
    {
        "opportunities",
        "tasks",
        "prs",
        "results",
        "events",
        "maintainerEvents",
        "ciRuns",
        "outcomes",
        "replies",
        "deliveries",
        "reservations",
        "absenceAttestations",
        "attestationNonceConsumptions",
        "reproductionProbes",
        "reproductionAttemptEvents",
    }
)
CURRENT_ROW_KEYS = frozenset(LEGACY_V7_ROW_KEYS | {"taskQuarantines"})
SNAPSHOT_AUTH_CONTEXT = "managed-snapshot-v1"
_FORBIDDEN_KEYS = {
    "threadid",
    "thread_id",
    "worktreepath",
    "worktree_path",
    "absolutepath",
    "absolute_path",
    "artifactpath",
    "artifact_path",
    "originalpath",
    "original_path",
    "private_text",
    "token",
    "secret",
    "password",
    "api_key",
}


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _safe_digest(value: object) -> str:
    return _digest(value)


def _task_probe_metadata(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _opportunity_probe_metadata(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    evidence = parsed.get("preTaskEvidence")
    if not isinstance(evidence, dict):
        evidence = {}
    paths = (
        parsed.get("codePaths") or evidence.get("codePaths") or evidence.get("codePathsPlan") or []
    )
    return {
        "selectedBaseSha": parsed.get("selectedBaseSha")
        or parsed.get("baseSha")
        or evidence.get("selectedBaseSha")
        or evidence.get("baseSha"),
        "codePaths": [str(path) for path in paths if str(path).strip()]
        if isinstance(paths, list)
        else [],
    }


def _opportunity_display_metadata(metadata_raw: str, provenance_raw: str) -> dict[str, Any]:
    """Preserve only safe fields that affect the user projection."""

    def parse(raw: str) -> dict[str, Any]:
        try:
            value = json.loads(raw or "{}")
        except (TypeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    metadata = parse(metadata_raw)
    provenance = parse(provenance_raw)
    title = metadata.get("title") or provenance.get("title")
    result: dict[str, Any] = {}
    if isinstance(title, str) and title.strip():
        normalized_title = title.strip()
        if not (
            normalized_title.startswith(("/", "\\"))
            or "/Users/" in normalized_title
            or "\\Users\\" in normalized_title
            or "sk-" in normalized_title
        ):
            result["displayTitle"] = normalized_title[:500]
    origin_kind = metadata.get("originKind") or provenance.get("originKind")
    if isinstance(origin_kind, str) and origin_kind.strip():
        result["originKind"] = origin_kind
    return result


def _validate_snapshot_opportunity(row: dict[str, Any]) -> bool:
    canonical_opportunity_identity(
        opportunity_key=row["opportunityKey"],
        owner=row["owner"],
        repo=row["repo"],
        issue_number=row["issueNumber"],
        issue_url=row["issueUrl"],
    )
    return True


def _origin_observation_digest(raw: str) -> str:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and set(parsed) == {"snapshotDigest"}:
        return str(parsed["snapshotDigest"])
    return _safe_digest(raw)


def _safe_idempotency(value: str) -> str:
    """Expose a raw key only when it cannot carry local identity or paths."""

    return stable_fingerprint(value) if sensitive_identity(value) else value


_SAFE_QUARANTINE_DIGEST_FIELDS = {
    "wakeDigest",
    "replacementWakeDigest",
    "followupDigest",
    "resultDigest",
    "reservationDigest",
    "deliveryToken",
}
_SAFE_QUARANTINE_BOOL_FIELDS = {"reservationPending"}
_QUARANTINE_EVENT_TYPES = {
    "LEGACY_RESULT_REQUIRES_MIGRATION",
    "PUBLISHED_TASK_WORKTREE_MISSING",
    "PR_FOLLOWUP_REBIND_REQUIRED",
    "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID",
    "SHARED_CONTEXT_LAYOUT_CONFLICT",
    "TASK_QUARANTINE_CLEARED",
}
_QUARANTINE_ROW_KEYS = frozenset(
    {
        "opportunityKey",
        "reason",
        "dedupeFingerprint",
        "payload",
        "status",
        "createdAt",
        "clearedAt",
        "clearPayloadDigest",
    }
)
_QUARANTINE_PAYLOAD_KEYS = frozenset(
    {"payloadDigest"} | _SAFE_QUARANTINE_DIGEST_FIELDS | _SAFE_QUARANTINE_BOOL_FIELDS
)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _quarantine_dedupe_fingerprint(value: str) -> str:
    if value.startswith("snapshot:") and _is_sha256(value.removeprefix("snapshot:")):
        return value.removeprefix("snapshot:")
    return stable_fingerprint(value)


def _validate_canonical_quarantine_payload(payload: object) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not _is_sha256(payload.get("payloadDigest")):
        return None
    if not set(payload) <= _QUARANTINE_PAYLOAD_KEYS:
        return None
    canonical = {"payloadDigest": payload["payloadDigest"]}
    for key in sorted(_SAFE_QUARANTINE_DIGEST_FIELDS):
        value = payload.get(key)
        if value is not None:
            if not _is_sha256(value):
                return None
            canonical[key] = value
    for key in sorted(_SAFE_QUARANTINE_BOOL_FIELDS):
        value = payload.get(key)
        if value is not None:
            if not isinstance(value, bool):
                return None
            canonical[key] = value
    return canonical


def _validate_timestamp(value: object, *, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"managed snapshot quarantine {field} time is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise ValueError(f"managed snapshot quarantine {field} time is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"managed snapshot quarantine {field} time is missing timezone")


def _safe_quarantine_payload(raw: str, *, dedupe_key: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    if dedupe_key.startswith("snapshot:"):
        canonical = _validate_canonical_quarantine_payload(parsed)
        if canonical is not None:
            return canonical
    safe: dict[str, Any] = {"payloadDigest": _safe_digest(raw or "{}")}
    for key in sorted(_SAFE_QUARANTINE_DIGEST_FIELDS):
        value = parsed.get(key)
        if _is_sha256(value):
            safe[key] = value
    for key in sorted(_SAFE_QUARANTINE_BOOL_FIELDS):
        value = parsed.get(key)
        if isinstance(value, bool):
            safe[key] = value
    return safe


def _safe_quarantine_clear_payload_digest(raw: str | None, *, dedupe_key: str) -> str | None:
    if raw is None:
        return None
    if dedupe_key.startswith("snapshot:"):
        try:
            parsed = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            parsed = None
        if (
            isinstance(parsed, dict)
            and frozenset(parsed) == {"clearPayloadDigest"}
            and _is_sha256(parsed.get("clearPayloadDigest"))
        ):
            return parsed["clearPayloadDigest"]
    return _safe_digest(raw)


def _snapshot_quarantine_event_identity(row: dict[str, Any]) -> tuple[str, str]:
    key = str(row["idempotencyKey"])
    fingerprint = str(row.get("idempotencyFingerprint") or stable_fingerprint(key))
    match = re.fullmatch(r"task-quarantine:snapshot:([0-9a-f]{64})", key)
    if match is not None:
        expected = stable_fingerprint(key)
        if fingerprint != expected:
            raise ValueError("managed snapshot quarantine audit event identity is invalid")
        return key, fingerprint
    canonical_key = f"task-quarantine:snapshot:{fingerprint}"
    return canonical_key, stable_fingerprint(canonical_key)


def _snapshot_event_identity(row: dict[str, Any]) -> tuple[str, str]:
    if row["eventType"] in _QUARANTINE_EVENT_TYPES:
        return _snapshot_quarantine_event_identity(row)
    key = _safe_idempotency(str(row["idempotencyKey"]))
    return key, str(row.get("idempotencyFingerprint") or stable_fingerprint(key))


def _snapshot_event_payload_digest(row: sqlite3.Row) -> str:
    if row["event_type"] in _QUARANTINE_EVENT_TYPES:
        return _safe_digest("{}")
    return _safe_digest(row["payload_json"])


def _validate_snapshot_quarantine(row: dict[str, Any]) -> None:
    if not isinstance(row, dict):
        raise ValueError("managed snapshot quarantine row is invalid")
    if frozenset(row) != _QUARANTINE_ROW_KEYS:
        raise ValueError("managed snapshot quarantine row shape is invalid")
    match = re.fullmatch(r"([^/\s#]+)/([^/\s#]+)#([1-9][0-9]*)", str(row["opportunityKey"]))
    if match is None:
        raise ValueError("managed snapshot quarantine opportunity key is invalid")
    owner, repo, number = match.groups()
    _validate_snapshot_opportunity(
        {
            "opportunityKey": row["opportunityKey"],
            "owner": owner,
            "repo": repo,
            "issueNumber": int(number),
            "issueUrl": f"https://github.com/{owner}/{repo}/issues/{number}",
        }
    )
    reason = row.get("reason")
    if not isinstance(reason, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", reason):
        raise ValueError("managed snapshot quarantine reason is invalid")
    if not _is_sha256(row.get("dedupeFingerprint")):
        raise ValueError("managed snapshot quarantine dedupe fingerprint is invalid")
    status = row.get("status")
    if status not in {"ACTIVE", "CLEARED"}:
        raise ValueError("managed snapshot quarantine status is invalid")
    _validate_timestamp(row.get("createdAt"), field="created")
    if status == "ACTIVE":
        if row.get("clearedAt") is not None or row.get("clearPayloadDigest") is not None:
            raise ValueError("managed snapshot active quarantine clear fields are invalid")
    else:
        _validate_timestamp(row.get("clearedAt"), field="clear")
        if not _is_sha256(row.get("clearPayloadDigest")):
            raise ValueError("managed snapshot quarantine clear payload is invalid")
    payload = row.get("payload")
    if not isinstance(payload, dict) or not _is_sha256(payload.get("payloadDigest")):
        raise ValueError("managed snapshot quarantine payload is invalid")
    if not set(payload) <= _QUARANTINE_PAYLOAD_KEYS:
        raise ValueError("managed snapshot quarantine payload contains unsupported fields")
    for key in _SAFE_QUARANTINE_DIGEST_FIELDS:
        if key in payload and not _is_sha256(payload[key]):
            raise ValueError("managed snapshot quarantine digest field is invalid")
    for key in _SAFE_QUARANTINE_BOOL_FIELDS:
        if key in payload and not isinstance(payload[key], bool):
            raise ValueError("managed snapshot quarantine bool field is invalid")


def _safe_validation(raw: str, *, result_key: str, result_digest: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = {}
    certificate = value.get("certificate") if isinstance(value, dict) else None
    if not isinstance(certificate, dict) and isinstance(value, dict):
        evidence = value.get("evidence")
        certificate = evidence.get("certificate") if isinstance(evidence, dict) else None
    if not isinstance(certificate, dict):
        return {"certificate": None, "authenticationStatus": "UNAUTHENTICATED"}
    return {
        "certificate": certificate,
        "authenticationStatus": "AUTHENTICATED"
        if verify_validation_certificate_history(certificate)
        else "UNAUTHENTICATED",
    }


def _snapshot_rows(path: Path) -> dict[str, list[dict[str, Any]]]:
    ledger = ManagedLedger(path, ensure_schema=True)
    connection = ledger._connection()
    try:
        opportunities = [
            {
                "opportunityKey": row["opportunity_key"],
                "owner": row["owner"],
                "repo": row["repo"],
                "issueNumber": row["issue_number"],
                "issueUrl": row["issue_url"],
                "selectedBaseSha": _opportunity_probe_metadata(row["metadata_json"]).get(
                    "selectedBaseSha"
                ),
                "codePaths": _opportunity_probe_metadata(row["metadata_json"]).get("codePaths", []),
                "state": row["state"],
                "source": row["source"],
                "observedAt": row["observed_at"],
                "provenanceDigest": _safe_digest(row["provenance_json"]),
                "metadataDigest": _safe_digest(row["metadata_json"]),
                **_opportunity_display_metadata(row["metadata_json"], row["provenance_json"]),
            }
            for row in connection.execute(
                "SELECT * FROM managed_opportunities ORDER BY opportunity_key"
            ).fetchall()
            if _validate_snapshot_opportunity(
                {
                    "opportunityKey": row["opportunity_key"],
                    "owner": row["owner"],
                    "repo": row["repo"],
                    "issueNumber": row["issue_number"],
                    "issueUrl": row["issue_url"],
                }
            )
        ]
        tasks = [
            {
                "taskId": row["task_id"],
                "opportunityKey": row["opportunity_key"],
                "threadFingerprint": thread_fingerprint(row["thread_id"])
                if row["thread_id"]
                else None,
                "state": row["state"],
                "source": row["source"],
                "observedAt": row["observed_at"],
                "provenanceDigest": _safe_digest(row["provenance_json"]),
                "taskStage": _task_probe_metadata(row["provenance_json"]).get("taskStage"),
                "probeLevel": _task_probe_metadata(row["provenance_json"]).get("probeLevel"),
                "probeReceiptDigest": _task_probe_metadata(row["provenance_json"]).get(
                    "probeReceiptDigest"
                ),
                "probeReceipt": _task_probe_metadata(row["provenance_json"]).get("probeReceipt"),
                "selectedBaseSha": _task_probe_metadata(row["provenance_json"]).get(
                    "selectedBaseSha"
                ),
                "codePaths": _task_probe_metadata(row["provenance_json"]).get("codePaths") or [],
                "headSha": _task_probe_metadata(row["provenance_json"]).get("headSha"),
                "commitSha": _task_probe_metadata(row["provenance_json"]).get("commitSha"),
                "resultDigest": _task_probe_metadata(row["provenance_json"]).get("resultDigest"),
            }
            for row in connection.execute("SELECT * FROM managed_tasks ORDER BY task_id").fetchall()
        ]
        prs = [
            {
                "prKey": row["pr_key"],
                "owner": row["owner"],
                "repo": row["repo"],
                "number": row["number"],
                "headSha": row["head_sha"],
                "prUrl": row["pr_url"],
                "state": row["state"],
                "autoCreated": bool(row["auto_created"]),
                "maintainerResponse": bool(row["maintainer_response"]),
                "sourceKind": row["source_kind"],
                "originKind": row["origin_kind"],
                "originObservationDigest": _origin_observation_digest(
                    row["origin_observation_json"]
                ),
                "originHeadSha": row["origin_head_sha"],
                "originPrUrl": row["origin_pr_url"],
                "source": row["source"],
                "latestSource": row["latest_source"],
                "observedAt": row["observed_at"],
            }
            for row in connection.execute("SELECT * FROM managed_prs ORDER BY pr_key").fetchall()
        ]
        results = [
            {
                "resultKey": row["result_key"],
                "taskId": row["task_id"],
                "prKey": row["pr_key"],
                "headSha": row["head_sha"],
                "resultDigest": row["result_digest"],
                "resultType": row["result_type"],
                "workerState": row["worker_state"],
                "commitSha": row["commit_sha"],
                "validationCertificate": _safe_validation(
                    row["validation_json"],
                    result_key=row["result_key"],
                    result_digest=row["result_digest"],
                )["certificate"],
                "authenticationStatus": _safe_validation(
                    row["validation_json"],
                    result_key=row["result_key"],
                    result_digest=row["result_digest"],
                )["authenticationStatus"],
                "source": row["source"],
                "observedAt": row["observed_at"],
                "isCurrent": bool(row["is_current"]),
                "supersededBy": row["superseded_by"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_results ORDER BY result_key"
            ).fetchall()
        ]
        events = []
        for row in connection.execute(
            "SELECT * FROM managed_lifecycle_events ORDER BY event_id"
        ).fetchall():
            idempotency_key, idempotency_fingerprint = _snapshot_event_identity(
                {
                    "eventType": row["event_type"],
                    "idempotencyKey": row["idempotency_key"],
                    "idempotencyFingerprint": row["idempotency_fingerprint"],
                }
            )
            events.append(
                {
                    "opportunityKey": row["opportunity_key"],
                    "taskId": row["task_id"],
                    "prKey": row["pr_key"],
                    "eventType": row["event_type"],
                    "state": row["state"],
                    "idempotencyKey": idempotency_key,
                    "idempotencyFingerprint": idempotency_fingerprint,
                    "source": row["source"],
                    "observedAt": row["observed_at"],
                    "payloadDigest": _snapshot_event_payload_digest(row),
                }
            )
        maintainer_events = [
            {
                "eventKey": row["event_key"],
                "prKey": row["pr_key"],
                "eventType": row["event_type"],
                "actorLogin": row["actor_login"],
                "actorType": row["actor_type"],
                "authorAssociation": row["author_association"],
                "isMaintainer": bool(row["is_maintainer"]),
                "observedAt": row["observed_at"],
                "payload": {
                    key: json.loads(row["payload_json"]).get(key)
                    for key in (
                        "targetRepo",
                        "targetPrKey",
                        "opportunityKey",
                        "explicit_mechanical_request",
                    )
                    if key in json.loads(row["payload_json"])
                },
            }
            for row in connection.execute(
                "SELECT * FROM managed_maintainer_events ORDER BY event_key"
            ).fetchall()
        ]
        ci_runs = [
            {
                "ciKey": row["ci_key"],
                "prKey": row["pr_key"],
                "headSha": row["head_sha"],
                "status": row["status"],
                "observedAt": row["observed_at"],
                "source": row["source"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_ci_runs ORDER BY ci_key"
            ).fetchall()
        ]
        outcomes = [
            {
                "opportunityKey": row["opportunity_key"],
                "prKey": row["pr_key"],
                "horizonDays": row["horizon_days"],
                "label": row["label"],
                "observedAt": row["observed_at"],
                "source": row["source"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_external_outcomes ORDER BY pr_key,horizon_days"
            ).fetchall()
        ]
        replies = [
            {
                "replyKey": row["reply_key"],
                "prKey": row["pr_key"],
                "maintainerEventKey": row["maintainer_event_key"],
                "resultDigest": row["result_digest"],
                "mode": row["mode"],
                "templateId": row["template_id"],
                "templateParams": json.loads(row["template_params_json"]),
                "bodyDigest": row["body_digest"] or _safe_digest(row["body"]),
                "policyDigest": row["policy_digest"],
                "reason": row["reason"],
                "createdAt": row["created_at"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_public_replies ORDER BY reply_key"
            ).fetchall()
        ]
        deliveries = [
            {
                "replyKey": row["reply_key"],
                "state": row["state"],
                "externalId": row["external_id"],
                "receiptDigest": row["receipt_digest"],
                "error": row["error"],
                "updatedAt": row["updated_at"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_reply_deliveries ORDER BY reply_key"
            ).fetchall()
        ]
        reservations = [
            {
                "reservationKey": row["reservation_key"],
                "requestId": row["request_id"],
                "repo": row["repo"],
                "headRef": row["head_ref"],
                "opportunityKey": row["opportunity_key"],
                "prKey": row["pr_key"],
                "headSha": row["head_sha"],
                "invitationEventKey": row["invitation_event_key"],
                "state": row["state"],
                "idempotencyKey": row["idempotency_key"],
                "leaseUntil": row["lease_until"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_publication_reservations ORDER BY reservation_key"
            ).fetchall()
        ]
        attestations = [
            {
                "schema": "absence_attestation_v1",
                "attestationId": row["attestation_id"],
                "reservationKey": row["reservation_key"],
                "repo": row["repo"],
                "headRef": row["head_ref"],
                "headSha": row["head_sha"],
                "queries": json.loads(row["query_json"]),
                "localEffect": json.loads(row["local_effect_json"]),
                "observedAt": row["observed_at"],
                "policy": row["policy_version"],
                "nonce": row["nonce"],
                "contentDigest": row["content_digest"],
                "signerKeyId": row["signer_key_id"],
                "signature": row["signature"],
                "authenticationStatus": row["authentication_status"],
                "createdAt": row["created_at"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_publication_absence_attestations ORDER BY attestation_id"
            ).fetchall()
        ]
        consumptions = [
            {
                "consumptionId": row["consumption_id"],
                "attestationId": row["attestation_id"],
                "nonce": row["nonce"],
                "reservationKey": row["reservation_key"],
                "contentDigest": row["content_digest"],
                "consumedAt": row["consumed_at"],
            }
            for row in connection.execute(
                "SELECT * FROM attestation_nonce_consumptions ORDER BY consumption_id"
            ).fetchall()
        ]
        task_quarantines = [
            {
                "opportunityKey": row["opportunity_key"],
                "reason": row["reason"],
                "dedupeFingerprint": _quarantine_dedupe_fingerprint(row["dedupe_key"]),
                "payload": _safe_quarantine_payload(
                    row["payload_json"], dedupe_key=row["dedupe_key"]
                ),
                "status": row["status"],
                "createdAt": row["created_at"],
                "clearedAt": row["cleared_at"],
                "clearPayloadDigest": _safe_quarantine_clear_payload_digest(
                    row["clear_payload_json"], dedupe_key=row["dedupe_key"]
                ),
            }
            for row in connection.execute(
                "SELECT * FROM task_quarantines ORDER BY quarantine_id"
            ).fetchall()
        ]
        reproduction_probes = [
            {
                "probeKey": row["probe_key"],
                "taskId": row["task_id"],
                "opportunityKey": row["opportunity_key"],
                "repo": row["repo"],
                "issueUrl": row["issue_url"],
                "threadFingerprint": thread_fingerprint(row["thread_id"])
                if row["thread_id"]
                else None,
                "defaultBranch": row["default_branch"],
                "selectedBaseSha": row["selected_base_sha"],
                "codePaths": json.loads(row["code_paths_json"]),
                "profileId": row["profile_id"],
                "headSha": row["head_sha"],
                "commitSha": row["commit_sha"],
                "resultDigest": row["result_digest"],
                "state": row["state"],
                "receipt": json.loads(row["receipt_json"] or "{}"),
                "error": row["error"],
                "idempotencyKey": _safe_idempotency(row["idempotency_key"]),
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
                "workerNonce": row["worker_nonce"],
                "attemptId": row["attempt_id"],
                "startedAt": row["started_at"],
                "leaseExpiresAt": row["lease_expires_at"],
                "attemptCount": row["attempt_count"],
            }
            for row in connection.execute(
                "SELECT * FROM managed_reproduction_probes ORDER BY probe_key"
            ).fetchall()
        ]
        reproduction_attempt_events = [
            {
                "attemptId": row["attempt_id"],
                "sequence": row["sequence"],
                "probeKey": row["probe_key"],
                "event": row["event"],
                "observedAt": row["observed_at"],
                "payload": json.loads(row["payload_json"] or "{}"),
            }
            for row in connection.execute(
                "SELECT * FROM managed_reproduction_attempt_events ORDER BY attempt_id,sequence"
            ).fetchall()
        ]
        return {
            "opportunities": opportunities,
            "tasks": tasks,
            "prs": prs,
            "results": results,
            "events": events,
            "maintainerEvents": maintainer_events,
            "ciRuns": ci_runs,
            "outcomes": outcomes,
            "replies": replies,
            "deliveries": deliveries,
            "reservations": reservations,
            "absenceAttestations": attestations,
            "attestationNonceConsumptions": consumptions,
            "taskQuarantines": task_quarantines,
            "reproductionProbes": reproduction_probes,
            "reproductionAttemptEvents": reproduction_attempt_events,
        }
    finally:
        connection.close()


def build_snapshot(path: Path) -> dict[str, Any]:
    rows = _snapshot_rows(path)
    snapshot = {
        "snapshotSchema": SNAPSHOT_SCHEMA_VERSION,
        "managedSchemaVersion": MANAGED_SCHEMA_VERSION,
        "managedSchemaDigest": schema_digest(),
        "rows": rows,
        "contentDigest": _digest(rows),
    }
    auth = sign_current(snapshot, context=SNAPSHOT_AUTH_CONTEXT)
    if not auth["keyId"] or not auth["signature"]:
        raise PermissionError("managed snapshot signing key is unavailable")
    snapshot["keyId"] = auth["keyId"]
    snapshot["rootSignature"] = sign_current(
        {**snapshot, "keyId": auth["keyId"]}, context=SNAPSHOT_AUTH_CONTEXT
    )["signature"]
    return snapshot


def _snapshot_authenticated(snapshot: dict[str, Any], *, current_only: bool = True) -> bool:
    key_id = snapshot.get("keyId")
    signature = snapshot.get("rootSignature")
    if not key_id or not signature:
        return False
    payload = {key: value for key, value in snapshot.items() if key != "rootSignature"}
    verifier = verify_current if current_only else verify_current_or_previous
    return verifier(
        payload,
        context=SNAPSHOT_AUTH_CONTEXT,
        key_id=key_id,
        signature=signature,
    )


def _is_legacy_v7_snapshot(snapshot: dict[str, Any]) -> bool:
    return (
        snapshot.get("snapshotSchema") == LEGACY_SNAPSHOT_SCHEMA_VERSION
        and snapshot.get("managedSchemaVersion") == LEGACY_MANAGED_SCHEMA_VERSION
        and snapshot.get("managedSchemaDigest") == LEGACY_MANAGED_SCHEMA_V7_DIGEST
    )


def _snapshot_rows_for_current(snapshot: dict[str, Any]) -> dict[str, Any]:
    rows = snapshot.get("rows")
    if not isinstance(rows, dict):
        raise ValueError("managed snapshot rows are invalid")
    if _is_legacy_v7_snapshot(snapshot):
        if frozenset(rows) != LEGACY_V7_ROW_KEYS:
            raise ValueError("legacy v7 managed snapshot row shape is invalid")
        return {**rows, "taskQuarantines": []}
    if frozenset(rows) != CURRENT_ROW_KEYS:
        raise ValueError("managed snapshot row shape is invalid")
    return rows


def _walk(value: object, *, key: str = "") -> None:
    lowered = key.casefold().replace("-", "_")
    if lowered in _FORBIDDEN_KEYS:
        raise ValueError(f"managed snapshot contains forbidden field: {key}")
    if isinstance(value, dict):
        for child_key, child in value.items():
            _walk(child, key=str(child_key))
    elif isinstance(value, list):
        for child in value:
            _walk(child, key=key)
    elif isinstance(value, str):
        if value.startswith(("/", "file://", "\\\\")):
            raise ValueError("managed snapshot contains an absolute path")


def validate_snapshot(
    snapshot: dict[str, Any],
    *,
    current_only: bool = True,
    allow_legacy: bool = False,
) -> None:
    legacy_v7 = _is_legacy_v7_snapshot(snapshot)
    if legacy_v7 and not allow_legacy:
        raise ValueError("legacy managed snapshot is not allowed in this path")
    if snapshot.get("snapshotSchema") != SNAPSHOT_SCHEMA_VERSION and not legacy_v7:
        raise ValueError("unsupported managed snapshot schema")
    if not _snapshot_authenticated(snapshot, current_only=current_only):
        raise ValueError("managed snapshot root authentication failed")
    if legacy_v7:
        if "taskQuarantines" in snapshot.get("rows", {}):
            raise ValueError("legacy v7 managed snapshot row shape is invalid")
    elif snapshot.get("managedSchemaVersion") != MANAGED_SCHEMA_VERSION:
        raise ValueError("managed snapshot schema version mismatch")
    if not legacy_v7 and snapshot.get("managedSchemaDigest") != schema_digest():
        raise ValueError("managed snapshot schema digest mismatch")
    rows = _snapshot_rows_for_current(snapshot)
    if not isinstance(rows, dict) or snapshot.get("contentDigest") != _digest(rows):
        if not legacy_v7:
            raise ValueError("managed snapshot content digest mismatch")
        legacy_rows = snapshot.get("rows")
        if not isinstance(legacy_rows, dict) or snapshot.get("contentDigest") != _digest(
            legacy_rows
        ):
            raise ValueError("managed snapshot content digest mismatch")
    for opportunity in rows.get("opportunities", []):
        _validate_snapshot_opportunity(opportunity)
    for result in rows.get("results", []):
        certificate = result.get("validationCertificate")
        if certificate is None:
            if result.get("authenticationStatus") != "UNAUTHENTICATED":
                raise ValueError("managed snapshot unauthenticated result status is invalid")
        else:
            if (
                not isinstance(certificate, dict)
                or not _certificate_shape(certificate)
                or not certificate.get("keyId")
                or not certificate.get("signature")
                or not verify_validation_certificate_history(certificate)
                or result.get("authenticationStatus") != "AUTHENTICATED"
            ):
                raise ValueError("managed snapshot validation certificate authentication failed")
            if certificate.get("resultKey") != result.get("resultKey") or certificate.get(
                "resultDigest"
            ) != result.get("resultDigest"):
                raise ValueError("validation certificate is not bound to its result")
    for reply in rows.get("replies", []):
        if not isinstance(reply.get("templateParams"), dict) or not isinstance(
            reply.get("bodyDigest"), str
        ):
            raise ValueError("managed snapshot contains an invalid reply certificate")
    if not legacy_v7:
        if "taskQuarantines" not in rows:
            raise ValueError("managed snapshot quarantine rows are missing")
        quarantine_keys: set[tuple[str, str, str]] = set()
        for quarantine in rows.get("taskQuarantines", []):
            _validate_snapshot_quarantine(quarantine)
            quarantine_key = (
                quarantine["opportunityKey"],
                quarantine["reason"],
                quarantine["dedupeFingerprint"],
            )
            if quarantine_key in quarantine_keys:
                raise ValueError("managed snapshot duplicate quarantine row")
            quarantine_keys.add(quarantine_key)
    for event in rows.get("events", []):
        fingerprint = event.get("idempotencyFingerprint")
        key = str(event.get("idempotencyKey"))
        if not isinstance(fingerprint, str) or fingerprint not in {
            key,
            stable_fingerprint(key),
        }:
            raise ValueError("managed snapshot contains an invalid idempotency fingerprint")
    for attestation in rows.get("absenceAttestations", []):
        if not isinstance(attestation, dict):
            raise ValueError("managed snapshot contains an unauthenticated absence attestation")
        status = attestation.get("authenticationStatus")
        if status == "AUTHENTICATED" and (
            not _attestation_structure_valid(attestation)
            or not attestation.get("signerKeyId")
            or not attestation.get("signature")
            or not _attestation_authenticated(attestation)
        ):
            raise ValueError("managed snapshot absence attestation signature mismatch")
        if status == "LEGACY_REAUTH_REQUIRED" and not isinstance(
            attestation.get("contentDigest"), str
        ):
            raise ValueError("managed snapshot legacy attestation digest is invalid")
        if status not in {"AUTHENTICATED", "LEGACY_REAUTH_REQUIRED"}:
            raise ValueError("managed snapshot absence attestation authorization status invalid")
    attestation_by_id = {
        row.get("attestationId"): row for row in rows.get("absenceAttestations", [])
    }
    consumed_attestation_ids: set[str] = set()
    for consumption in rows.get("attestationNonceConsumptions", []):
        attestation = attestation_by_id.get(consumption.get("attestationId"))
        if (
            not isinstance(consumption, dict)
            or not isinstance(attestation, dict)
            or consumption.get("nonce") != attestation.get("nonce")
            or consumption.get("reservationKey") != attestation.get("reservationKey")
            or consumption.get("contentDigest") != attestation.get("contentDigest")
            or consumption.get("attestationId") in consumed_attestation_ids
        ):
            raise ValueError("managed snapshot nonce consumption binding mismatch")
        consumed_attestation_ids.add(consumption["attestationId"])
    _walk(snapshot)
    serialized = canonical_json(snapshot)
    for name, value in os.environ.items():
        if (
            value
            and len(value) >= 8
            and any(
                marker in name.casefold() for marker in ("token", "secret", "password", "api_key")
            )
        ):
            if value in serialized:
                raise ValueError(f"managed snapshot contains environment secret: {name}")
    if any(
        re.search(pattern, serialized)
        for pattern in (
            r"ghp_[A-Za-z0-9]{20,}",
            r"github_pat_[A-Za-z0-9_]{20,}",
            r"Bearer [A-Za-z0-9._~-]{20,}",
            r"sk-[A-Za-z0-9]{20,}",
        )
    ):
        raise ValueError("managed snapshot contains a token-like value")


def encode_snapshot(snapshot: dict[str, Any]) -> bytes:
    validate_snapshot(snapshot, current_only=True, allow_legacy=False)
    raw = canonical_json(snapshot).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


def decode_snapshot(
    raw: bytes,
    *,
    current_only: bool = True,
    allow_legacy: bool = False,
) -> dict[str, Any]:
    try:
        snapshot = json.loads(gzip.decompress(raw).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("managed snapshot is not valid compressed JSON") from exc
    if not isinstance(snapshot, dict):
        raise ValueError("managed snapshot must be an object")
    validate_snapshot(snapshot, current_only=current_only, allow_legacy=allow_legacy)
    return snapshot


def inspect_snapshot(snapshot_path: Path) -> dict[str, Any]:
    """Decode historical evidence without allowing any database write."""

    if not snapshot_path.exists():
        raise FileNotFoundError(snapshot_path)
    return decode_snapshot(snapshot_path.read_bytes(), current_only=False, allow_legacy=True)


def export_snapshot(database: Path, output: Path) -> dict[str, Any]:
    raw = encode_snapshot(build_snapshot(database))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(output)
    return {"ok": True, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _insert_snapshot(connection: sqlite3.Connection, rows: dict[str, list[dict[str, Any]]]) -> None:
    opportunity_rows = {row["opportunityKey"]: row for row in rows["opportunities"]}
    for row in rows["opportunities"]:
        _validate_snapshot_opportunity(row)
    for row in rows.get("reproductionProbes", []):
        opportunity = opportunity_rows.get(row["opportunityKey"])
        if opportunity is None:
            raise ValueError("snapshot probe opportunity is missing")
        identity = canonical_opportunity_identity(
            opportunity_key=opportunity["opportunityKey"],
            owner=opportunity["owner"],
            repo=opportunity["repo"],
            issue_number=opportunity["issueNumber"],
            issue_url=opportunity["issueUrl"],
        )
        if (
            row["repo"] != f"{identity['owner']}/{identity['repo']}"
            or row["issueUrl"] != identity["issueUrl"]
        ):
            raise ValueError("snapshot probe identity does not match opportunity")
    # Lifecycle events are append-only.  A restore may replay an event already
    # present in the target, but a different event under the same idempotency
    # key is corruption and must abort before any managed row is replaced.
    for row in rows["events"]:
        _, fingerprint = _snapshot_event_identity(row)
        existing = connection.execute(
            """SELECT opportunity_key,task_id,pr_key,event_type,state,source,observed_at
               FROM managed_lifecycle_events WHERE idempotency_fingerprint=?""",
            (fingerprint,),
        ).fetchone()
        if existing and any(
            existing[key] != row[field]
            for key, field in (
                ("opportunity_key", "opportunityKey"),
                ("task_id", "taskId"),
                ("pr_key", "prKey"),
                ("event_type", "eventType"),
                ("state", "state"),
                ("source", "source"),
                ("observed_at", "observedAt"),
            )
        ):
            raise ValueError(
                f"managed snapshot event conflicts with idempotency key {row['idempotencyKey']}"
            )
    for trigger in (
        "managed_events_no_update",
        "managed_events_no_delete",
        "managed_absence_attestations_no_update",
        "managed_absence_attestations_no_delete",
        "attestation_nonce_consumptions_no_update",
        "attestation_nonce_consumptions_no_delete",
    ):
        connection.execute(f'DROP TRIGGER IF EXISTS "{trigger}"')
    for table in (
        "managed_public_replies",
        "managed_reply_deliveries",
        "managed_external_outcomes",
        "managed_ci_runs",
        "managed_maintainer_events",
        "managed_publication_reservations",
        "managed_publication_absence_attestations",
        "attestation_nonce_consumptions",
        "managed_reproduction_probes",
        "managed_reproduction_attempt_events",
        "managed_results",
        "managed_prs",
        "managed_tasks",
        "managed_opportunities",
        "managed_lifecycle_events",
    ):
        connection.execute(f'DELETE FROM "{table}"')
    for row in rows.get("taskQuarantines", []):
        _validate_snapshot_quarantine(row)
        dedupe_key = f"snapshot:{row['dedupeFingerprint']}"
        payload_json = canonical_json(row["payload"])
        clear_payload = (
            canonical_json({"clearPayloadDigest": row["clearPayloadDigest"]})
            if row.get("clearPayloadDigest")
            else None
        )
        existing = connection.execute(
            """SELECT status FROM task_quarantines
               WHERE opportunity_key=? AND reason=? AND dedupe_key=?""",
            (row["opportunityKey"], row["reason"], dedupe_key),
        ).fetchone()
        if existing is None:
            connection.execute(
                """INSERT INTO task_quarantines
                   (opportunity_key,reason,dedupe_key,payload_json,status,created_at,cleared_at,clear_payload_json)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    row["opportunityKey"],
                    row["reason"],
                    dedupe_key,
                    payload_json,
                    row["status"],
                    row["createdAt"],
                    row.get("clearedAt"),
                    clear_payload,
                ),
            )
        elif row["status"] == "ACTIVE" and existing["status"] == "CLEARED":
            connection.execute(
                """UPDATE task_quarantines
                   SET payload_json=?, status='ACTIVE', created_at=?, cleared_at=NULL, clear_payload_json=NULL
                   WHERE opportunity_key=? AND reason=? AND dedupe_key=? AND status='CLEARED'""",
                (
                    payload_json,
                    row["createdAt"],
                    row["opportunityKey"],
                    row["reason"],
                    dedupe_key,
                ),
            )
    for row in rows["opportunities"]:
        connection.execute(
            """INSERT INTO managed_opportunities
               (opportunity_key,owner,repo,issue_number,issue_url,state,source,provenance_json,observed_at,metadata_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                row["opportunityKey"],
                row["owner"],
                row["repo"],
                row["issueNumber"],
                row["issueUrl"],
                row["state"],
                row["source"],
                "{}",
                row["observedAt"],
                canonical_json(
                    {
                        "selectedBaseSha": row.get("selectedBaseSha"),
                        "codePaths": row.get("codePaths") or [],
                        **({"title": row["displayTitle"]} if row.get("displayTitle") else {}),
                        **({"originKind": row["originKind"]} if row.get("originKind") else {}),
                    }
                ),
            ),
        )
    for row in rows["tasks"]:
        receipt = row.get("probeReceipt")
        opportunity = connection.execute(
            "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
            (row["opportunityKey"],),
        ).fetchone()
        expected_repo = ""
        expected_issue_url = ""
        expected_base = ""
        opportunity_metadata: dict[str, Any] = {}
        if opportunity is not None:
            expected_repo = f"{opportunity['owner']}/{opportunity['repo']}"
            expected_issue_url = opportunity["issue_url"]
            try:
                opportunity_metadata = json.loads(opportunity["metadata_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                opportunity_metadata = {}
            expected_evidence = opportunity_metadata.get("preTaskEvidence")
            if not isinstance(expected_evidence, dict):
                expected_evidence = {}
            expected_base = str(
                opportunity_metadata.get("selectedBaseSha")
                or opportunity_metadata.get("baseSha")
                or expected_evidence.get("selectedBaseSha")
                or expected_evidence.get("baseSha")
                or ""
            )
        expected_paths = opportunity_metadata.get("codePaths") or row.get("codePaths") or []
        authorized_task = (
            row.get("taskStage") == "IMPLEMENTATION_READY"
            and row.get("probeLevel") == "REPRODUCED_VALIDATED"
            and bool(row.get("probeReceiptDigest"))
            and isinstance(receipt, dict)
            and receipt.get("receiptDigest") == row.get("probeReceiptDigest")
            and verify_probe_receipt(
                receipt,
                repo=expected_repo,
                base_sha=expected_base,
                code_paths=[str(path) for path in expected_paths],
                required_level="REPRODUCED_VALIDATED",
                issue_url=expected_issue_url,
                task_id=row["taskId"],
                thread_fingerprint_value=row.get("threadFingerprint"),
                head_sha=row.get("headSha") or receipt.get("headSha"),
                commit_sha=row.get("commitSha") or receipt.get("commitSha"),
                result_digest=row.get("resultDigest") or receipt.get("resultDigest"),
            )
        )
        task_state = row["state"] if authorized_task else "REPRODUCTION_REQUIRED"
        task_provenance = {
            "taskStage": row.get("taskStage") if authorized_task else "REPRODUCTION_REQUIRED",
            "probeLevel": row.get("probeLevel") if authorized_task else "UNVERIFIED",
            "probeReceiptDigest": row.get("probeReceiptDigest") if authorized_task else None,
            "probeReceipt": receipt if authorized_task else None,
            "selectedBaseSha": row.get("selectedBaseSha") if authorized_task else None,
            "codePaths": row.get("codePaths") if authorized_task else [],
            "headSha": row.get("headSha") if authorized_task else None,
            "commitSha": row.get("commitSha") if authorized_task else None,
            "resultDigest": row.get("resultDigest") if authorized_task else None,
            "threadFingerprint": row.get("threadFingerprint") if authorized_task else None,
            "snapshotRestored": True,
        }
        connection.execute(
            """INSERT INTO managed_tasks
               (task_id,opportunity_key,thread_id,worktree_path,state,source,provenance_json,observed_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                row["taskId"],
                row["opportunityKey"],
                None,
                None,
                task_state,
                row["source"],
                canonical_json(task_provenance),
                row["observedAt"],
            ),
        )
    for row in rows.get("reproductionProbes", []):
        receipt = row.get("receipt") if isinstance(row.get("receipt"), dict) else {}
        receipt_current = bool(
            receipt
            and verify_probe_receipt(
                receipt,
                repo=row["repo"],
                base_sha=row["selectedBaseSha"],
                code_paths=list(row.get("codePaths") or []),
                required_level="REPRODUCED_VALIDATED",
                issue_url=row["issueUrl"],
                task_id=row["taskId"],
                thread_fingerprint_value=row.get("threadFingerprint"),
                head_sha=row["headSha"],
                commit_sha=row["commitSha"],
                result_digest=row["resultDigest"],
            )
        )
        restored_state = row.get("state")
        if restored_state == "RUNNING" or (restored_state == "SUCCEEDED" and not receipt_current):
            restored_state = "WAITING_EXTERNAL"
        connection.execute(
            """INSERT INTO managed_reproduction_probes
               (probe_key,task_id,opportunity_key,repo,issue_url,thread_id,default_branch,selected_base_sha,
                code_paths_json,profile_id,checkout_path,head_sha,commit_sha,result_digest,state,
                receipt_json,error,idempotency_key,created_at,updated_at,worker_nonce,attempt_id,
                started_at,lease_expires_at,attempt_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,?)""",
            (
                row["probeKey"],
                row["taskId"],
                row["opportunityKey"],
                row["repo"],
                row["issueUrl"],
                None,
                row["defaultBranch"],
                row["selectedBaseSha"],
                canonical_json(row.get("codePaths") or []),
                row.get("profileId"),
                None,
                row["headSha"],
                row["commitSha"],
                row["resultDigest"],
                restored_state,
                canonical_json(receipt),
                row.get("error"),
                row.get("idempotencyKey") or row["probeKey"],
                row["createdAt"],
                row["updatedAt"],
                int(row.get("attemptCount") or 0),
            ),
        )
    for row in rows.get("reproductionAttemptEvents", []):
        connection.execute(
            """INSERT INTO managed_reproduction_attempt_events
               (attempt_id,sequence,probe_key,event,observed_at,payload_json)
               VALUES (?,?,?,?,?,?)""",
            (
                row["attemptId"],
                int(row["sequence"]),
                row["probeKey"],
                row["event"],
                row["observedAt"],
                canonical_json(row.get("payload") or {}),
            ),
        )
    for row in rows["prs"]:
        connection.execute(
            """INSERT INTO managed_prs
               (pr_key,owner,repo,number,head_sha,pr_url,state,auto_created,maintainer_response,
               source_kind,source,provenance_json,observed_at,metadata_json,origin_kind,
                origin_observation_json,origin_head_sha,origin_pr_url,latest_source)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["prKey"],
                row["owner"],
                row["repo"],
                row["number"],
                row["headSha"],
                row["prUrl"],
                row["state"],
                int(row["autoCreated"]),
                int(row["maintainerResponse"]),
                row["sourceKind"],
                row["source"],
                "{}",
                row["observedAt"],
                "{}",
                row.get("originKind") or row["sourceKind"],
                canonical_json({"snapshotDigest": row.get("originObservationDigest", "")}),
                row.get("originHeadSha"),
                row.get("originPrUrl"),
                row.get("latestSource") or row["source"],
            ),
        )
    for row in rows["results"]:
        connection.execute(
            """INSERT INTO managed_results
               (result_key,task_id,pr_key,head_sha,result_digest,result_type,worker_state,commit_sha,validation_json,source,provenance_json,observed_at,is_current,superseded_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["resultKey"],
                row["taskId"],
                row["prKey"],
                row["headSha"],
                row["resultDigest"],
                row["resultType"],
                row["workerState"],
                row["commitSha"],
                canonical_json(
                    {
                        "passed": row["validationCertificate"].get("passed") is True
                        if isinstance(row["validationCertificate"], dict)
                        else False,
                        "certificate": row["validationCertificate"],
                        "authenticationStatus": row.get("authenticationStatus"),
                        "evidence": {"certificate": row["validationCertificate"]}
                        if isinstance(row["validationCertificate"], dict)
                        else {},
                    }
                ),
                row["source"],
                "{}",
                row["observedAt"],
                int(row["isCurrent"]),
                row["supersededBy"],
            ),
        )
    for row in rows["events"]:
        event_idempotency_key, fingerprint = _snapshot_event_identity(row)
        connection.execute(
            """INSERT INTO managed_lifecycle_events
               (opportunity_key,task_id,pr_key,event_type,state,idempotency_key,source,
                idempotency_fingerprint,provenance_json,observed_at,payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["opportunityKey"],
                row["taskId"],
                row["prKey"],
                row["eventType"],
                row["state"],
                event_idempotency_key,
                row["source"],
                fingerprint,
                "{}",
                row["observedAt"],
                "{}",
            ),
        )
    for row in rows["maintainerEvents"]:
        connection.execute(
            """INSERT INTO managed_maintainer_events
               (event_key,pr_key,event_type,actor_login,actor_type,author_association,is_maintainer,observed_at,source,payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                row["eventKey"],
                row["prKey"],
                row["eventType"],
                row["actorLogin"],
                row["actorType"],
                row["authorAssociation"],
                int(row["isMaintainer"]),
                row["observedAt"],
                "snapshot",
                canonical_json(row["payload"]),
            ),
        )
    for row in rows["ciRuns"]:
        connection.execute(
            """INSERT INTO managed_ci_runs
               (ci_key,pr_key,head_sha,status,checks_json,observed_at,source,provenance_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                row["ciKey"],
                row["prKey"],
                row["headSha"],
                row["status"],
                "{}",
                row["observedAt"],
                row["source"],
                "{}",
            ),
        )
    for row in rows["outcomes"]:
        connection.execute(
            """INSERT INTO managed_external_outcomes
               (opportunity_key,pr_key,horizon_days,label,observed_at,source,provenance_json)
               VALUES (?,?,?,?,?,?,?)""",
            (
                row["opportunityKey"],
                row["prKey"],
                row["horizonDays"],
                row["label"],
                row["observedAt"],
                row["source"],
                "{}",
            ),
        )
    for row in rows["replies"]:
        connection.execute(
            """INSERT INTO managed_public_replies
               (reply_key,pr_key,maintainer_event_key,result_digest,mode,body,reason,created_at,
                template_id,template_params_json,body_digest,policy_digest)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["replyKey"],
                row["prKey"],
                row["maintainerEventKey"],
                row["resultDigest"],
                row["mode"]
                if row["policyDigest"] == public_reply_policy_digest()
                and render_reply_template(row["templateId"], row["templateParams"])
                and _safe_digest(render_reply_template(row["templateId"], row["templateParams"]))
                == row["bodyDigest"]
                and row["policyDigest"]
                else "DRAFT",
                render_reply_template(row["templateId"], row["templateParams"]) or "",
                row["reason"],
                row["createdAt"],
                row["templateId"],
                canonical_json(row["templateParams"]),
                row["bodyDigest"],
                row["policyDigest"],
            ),
        )
    for row in rows["deliveries"]:
        reply_mode = connection.execute(
            "SELECT mode FROM managed_public_replies WHERE reply_key=?", (row["replyKey"],)
        ).fetchone()
        restorable = bool(reply_mode and reply_mode["mode"] == "AUTO_REPLY_ALLOWED")
        connection.execute(
            """INSERT INTO managed_reply_deliveries
               (reply_key,state,external_id,receipt_digest,error,updated_at)
               VALUES (?,?,?,?,?,?)""",
            (
                row["replyKey"],
                row["state"]
                if restorable and row["state"] in {"QUEUED", "SENDING", "SENT", "BLOCKED", "FAILED"}
                else "BLOCKED",
                row["externalId"],
                row["receiptDigest"],
                row["error"] or (None if restorable else "RESTORED_REPLY_NOT_AUTHORIZED"),
                row["updatedAt"],
            ),
        )
    for row in rows["reservations"]:
        connection.execute(
            """INSERT INTO managed_publication_reservations
               (reservation_key,request_id,repo,head_ref,opportunity_key,pr_key,head_sha,invitation_event_key,
                state,idempotency_key,lease_until,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["reservationKey"],
                row["requestId"],
                row["repo"],
                row.get("headRef"),
                row["opportunityKey"],
                row["prKey"],
                row["headSha"],
                row["invitationEventKey"],
                row["state"],
                row["idempotencyKey"],
                row["leaseUntil"],
                row["createdAt"],
                row["updatedAt"],
            ),
        )
    for row in rows.get("absenceAttestations", []):
        existing = connection.execute(
            "SELECT * FROM managed_publication_absence_attestations WHERE attestation_id=?",
            (row["attestationId"],),
        ).fetchone()
        if existing and (
            existing["content_digest"] != row["contentDigest"]
            or existing["signature"] != row["signature"]
        ):
            raise ValueError("managed snapshot conflicts with an absence attestation")
        connection.execute(
            """INSERT INTO managed_publication_absence_attestations
               (attestation_id,reservation_key,repo,head_ref,head_sha,query_json,local_effect_json,
                observed_at,policy_version,nonce,content_digest,signer_key_id,signature,
                authentication_status,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["attestationId"],
                row["reservationKey"],
                row["repo"],
                row["headRef"],
                row["headSha"],
                canonical_json(row["queries"]),
                canonical_json(row["localEffect"]),
                row["observedAt"],
                row["policy"],
                row["nonce"],
                row["contentDigest"],
                row["signerKeyId"],
                row["signature"],
                row["authenticationStatus"],
                row["createdAt"],
            ),
        )
    for row in rows.get("attestationNonceConsumptions", []):
        existing = connection.execute(
            """SELECT * FROM attestation_nonce_consumptions
               WHERE attestation_id=? AND nonce=? AND reservation_key=? AND content_digest=?""",
            (
                row["attestationId"],
                row["nonce"],
                row["reservationKey"],
                row["contentDigest"],
            ),
        ).fetchone()
        if existing:
            continue
        connection.execute(
            """INSERT INTO attestation_nonce_consumptions
               (attestation_id,nonce,reservation_key,content_digest,consumed_at)
               VALUES (?,?,?,?,?)""",
            (
                row["attestationId"],
                row["nonce"],
                row["reservationKey"],
                row["contentDigest"],
                row["consumedAt"],
            ),
        )
    connection.execute(
        """CREATE TRIGGER managed_events_no_update
           BEFORE UPDATE ON managed_lifecycle_events
           BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER managed_events_no_delete
           BEFORE DELETE ON managed_lifecycle_events
           BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER managed_absence_attestations_no_update
           BEFORE UPDATE ON managed_publication_absence_attestations
           BEGIN SELECT RAISE(ABORT, 'absence attestations are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER managed_absence_attestations_no_delete
           BEFORE DELETE ON managed_publication_absence_attestations
           BEGIN SELECT RAISE(ABORT, 'absence attestations are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER attestation_nonce_consumptions_no_update
           BEFORE UPDATE ON attestation_nonce_consumptions
           BEGIN SELECT RAISE(ABORT, 'nonce consumptions are append-only'); END"""
    )
    connection.execute(
        """CREATE TRIGGER attestation_nonce_consumptions_no_delete
           BEFORE DELETE ON attestation_nonce_consumptions
           BEGIN SELECT RAISE(ABORT, 'nonce consumptions are append-only'); END"""
    )


def import_snapshot(
    database: Path, snapshot_path: Path, *, allow_missing: bool = False
) -> dict[str, Any]:
    if not snapshot_path.exists():
        if allow_missing:
            return {"ok": True, "skipped": True, "reason": "snapshot_missing"}
        raise FileNotFoundError(snapshot_path)
    # Live restore is intentionally current-key-only.  Historical verification
    # is available through inspect_snapshot and cannot write a database.
    snapshot = decode_snapshot(snapshot_path.read_bytes(), current_only=True, allow_legacy=True)
    ledger = ManagedLedger(database, ensure_schema=True)
    connection = ledger._connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        _insert_snapshot(connection, _snapshot_rows_for_current(snapshot))
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
    return {"ok": True, "skipped": False, "contentDigest": snapshot["contentDigest"]}
