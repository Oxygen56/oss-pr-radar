"""Managed OSS contribution lifecycle tables and deterministic ledger rules.

The existing Radar tables remain readable and writable by their established
callers. Managed tables are additive, versioned, and are only created by an
explicit migration on a database copy.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .action_guard import ledger_action_guard_root, opportunity_action_guard
from .managed_security import (
    current_signing_key_id,
    sign_current,
    stable_fingerprint,
    verify_current,
    verify_current_or_previous,
)
from .task_quarantine import active as active_quarantine
from .task_quarantine import attach_artifact as attach_quarantine_artifact
from .task_quarantine import backfill_from_managed_events
from .task_quarantine import clear as clear_quarantine
from .task_quarantine import payload as quarantine_payload
from .task_quarantine import record as record_quarantine
from .task_quarantine import require_clear as require_quarantine_clear
from .util import canonical_json, iso_z

MANAGED_SCHEMA_VERSION = 8
KNOWN_MANAGED_SCHEMA_V7_DIGESTS = frozenset(
    {
        "10ed2d89cd0357806d3e62f3ef140f42c2c234b9cb4b82ed406ce24983153a0e",
        "02ea3f38a042c2c48ad61089777d9cf0817190f413270b74010e64a5a860e360",
    }
)
MANAGED_TABLES = (
    "managed_public_replies",
    "managed_reply_deliveries",
    "managed_publication_reservations",
    "managed_publication_absence_attestations",
    "attestation_nonce_consumptions",
    "managed_external_outcomes",
    "managed_ci_runs",
    "managed_maintainer_events",
    "managed_lifecycle_events",
    "managed_results",
    "managed_prs",
    "managed_tasks",
    "managed_reproduction_probes",
    "managed_reproduction_attempt_events",
    "managed_opportunities",
    "managed_schema_migrations",
)
RESULT_TYPES = (
    "scan_false_positive",
    "state_drift",
    "blocked_pre_task",
    "task_no_go",
    "censored",
)
MATURE_HORIZONS = (14, 30, 60)
ABSENCE_ATTESTATION_POLICY = "absence-attestation-v1"
ABSENCE_ATTESTATION_MAX_AGE_SECONDS = 900
MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
OPEN_PR_CAP = 5
REPRODUCTION_PROBE_LEASE_SECONDS = 300
REPRODUCTION_PROBE_MAX_ATTEMPTS = 3
REPRODUCTION_RETRY_EXHAUSTED_ERROR = "RETRY_EXHAUSTED"
PROJECTION_BUCKETS = (
    "DECISION_REQUIRED",
    "SYSTEM_PROCESSING",
    "WAITING_EXTERNAL",
    "PORTFOLIO_READY",
)
PR_STATES = frozenset({"OPEN", "CLOSED", "MERGED"})
_PR_URL_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)(?:/.*)?$")
_OPPORTUNITY_KEY_RE = re.compile(r"^([^/\s#]+)/([^/\s#]+)#([1-9][0-9]*)$")
_ISSUE_URL_RE = re.compile(r"^https://github\.com/([^/\s]+)/([^/\s]+)/issues/([1-9][0-9]*)$")
_UNCERTAIN_REPLY_FLAGS = (
    "semantic_uncertainty",
    "legal_uncertainty",
    "security_uncertainty",
    "disclosure_uncertainty",
    "policy_uncertainty",
)
VALIDATION_CERTIFICATE_SCHEMA = "validation_evidence_certificate_v1"
TASK_CREATION_AUTHORIZATION_SCHEMA = "task_creation_authorization_v1"
PUBLIC_REPLY_POLICY_VERSION = "public_reply_policy_v1"
REPLY_TEMPLATE_ID = "mechanical_change_v1"
_REPLY_TEMPLATES = {
    "standard": "Implemented the requested mechanical change; validation passed.",
    "short": "Fixed as requested.",
}


def _utc(value: str | None = None) -> str:
    return value or iso_z(datetime.now(UTC))


def _json(value: object) -> str:
    return canonical_json(value)


def _digest(value: object) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def pr_key_from_url(pr_url: str) -> str:
    match = _PR_URL_RE.match(pr_url.rstrip("/"))
    if not match:
        raise ValueError(f"unsupported GitHub pull request URL: {pr_url}")
    return f"{match.group(1)}/{match.group(2)}#{int(match.group(3))}"


def is_maintainer_actor(
    *,
    actor_type: str | None,
    actor_login: str | None,
    author_association: str | None,
    verified_permission: bool = False,
) -> bool:
    """Apply the maintainer rule without trusting worker or model claims."""

    if (actor_type or "").casefold() != "user":
        return False
    login = (actor_login or "").casefold()
    if not login or login.endswith("[bot]") or "[bot]" in login:
        return False
    association = (author_association or "").upper()
    del verified_permission
    return association in MAINTAINER_ASSOCIATIONS


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _parse_rfc3339_utc(value: object) -> datetime:
    """Parse a lease timestamp strictly; naive timestamps are malformed."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("lease timestamp is missing")
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ):
        raise ValueError("lease timestamp is not RFC3339")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("lease timestamp has no timezone")
    return parsed.astimezone(UTC)


def parse_issue_reference(value: str) -> dict[str, Any]:
    """Parse one canonical GitHub issue key or URL."""

    if not isinstance(value, str):
        raise ValueError("issue reference must be text")
    key_match = _OPPORTUNITY_KEY_RE.fullmatch(value)
    if key_match:
        owner, repo, number = key_match.groups()
    else:
        url_match = _ISSUE_URL_RE.fullmatch(value)
        if not url_match:
            raise ValueError("issue reference is not canonical")
        owner, repo, number = url_match.groups()
    number_int = int(number)
    return {
        "owner": owner,
        "repo": repo,
        "issueNumber": number_int,
        "opportunityKey": f"{owner}/{repo}#{number_int}",
        "issueUrl": f"https://github.com/{owner}/{repo}/issues/{number_int}",
    }


def canonical_opportunity_identity(
    *, opportunity_key: str, owner: str, repo: str, issue_number: int, issue_url: str
) -> dict[str, Any]:
    """Validate every stored issue identity component as one immutable tuple."""

    parsed_key = parse_issue_reference(opportunity_key)
    parsed_url = parse_issue_reference(issue_url)
    if (
        parsed_key != parsed_url
        or owner != parsed_key["owner"]
        or repo != parsed_key["repo"]
        or int(issue_number) != parsed_key["issueNumber"]
    ):
        raise ValueError("opportunity issue identity is inconsistent")
    return parsed_key


def canonical_opportunity_key(value: str) -> str:
    """Return the storage key for either an issue key or its canonical URL."""

    return str(parse_issue_reference(value)["opportunityKey"])


def _valid_validation(validation: dict[str, Any] | None) -> bool:
    if not isinstance(validation, dict) or validation.get("passed") is not True:
        return False
    evidence = validation.get("evidence")
    if not evidence:
        return False
    certificate = validation.get("certificate")
    if not isinstance(certificate, dict):
        certificate = evidence.get("certificate") if isinstance(evidence, dict) else None
    if isinstance(certificate, dict):
        return certificate.get("passed") is True and _valid_validation_certificate(certificate)
    return bool(validation.get("evidence"))


def _sanitize_check_id(value: object) -> str | None:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        return None
    cleaned = re.sub(r"[^A-Za-z0-9_.:/-]+", "_", value)[:120]
    return cleaned or None


def _certificate_structure_valid(certificate: dict[str, Any]) -> bool:
    if certificate.get("schema") != VALIDATION_CERTIFICATE_SCHEMA:
        return False
    content_digest = certificate.get("contentDigest")
    unsigned = {
        key: value
        for key, value in certificate.items()
        if key not in {"contentDigest", "keyId", "signature"}
    }
    if not isinstance(content_digest, str) or content_digest != _digest(unsigned):
        return False
    return bool(
        isinstance(certificate.get("passed"), bool)
        and isinstance(certificate.get("checkIds"), list)
        and certificate.get("checkCount") == len(certificate["checkIds"])
        and isinstance(certificate.get("resultKey"), str)
        and isinstance(certificate.get("resultDigest"), str)
        and isinstance(certificate.get("policyDigest"), str)
    )


def validation_certificate(
    validation: dict[str, Any] | None,
    *,
    result_key: str,
    result_digest: str,
    source_event_key: str | None = None,
    commit_sha: str | None = None,
    head_sha: str | None = None,
    ci_status: str = "UNKNOWN",
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Create a replayable certificate without carrying private evidence text."""

    raw = validation if isinstance(validation, dict) else {}
    existing = raw.get("certificate")
    if not isinstance(existing, dict):
        evidence_value = raw.get("evidence")
        existing = evidence_value.get("certificate") if isinstance(evidence_value, dict) else None
    evidence = raw.get("evidence")
    evidence_items = evidence if isinstance(evidence, list) else []
    check_ids: list[str] = []
    for item in evidence_items:
        candidate = item
        if isinstance(item, dict):
            candidate = (
                item.get("checkId") or item.get("check_id") or item.get("name") or item.get("id")
            )
        check_id = _sanitize_check_id(candidate)
        if check_id and check_id not in check_ids:
            check_ids.append(check_id)
    if (
        isinstance(existing, dict)
        and _certificate_structure_valid(existing)
        and commit_sha is None
        and head_sha is None
        and ci_status == "UNKNOWN"
        and observed_at is None
    ):
        return existing
    if isinstance(existing, dict) and _certificate_structure_valid(existing):
        check_ids = list(existing.get("checkIds") or [])
        evidence_count = int(existing.get("evidenceCount") or 0)
    else:
        evidence_count = len(evidence_items)
    certificate = {
        "schema": VALIDATION_CERTIFICATE_SCHEMA,
        "passed": raw.get("passed") is True,
        "checkIds": sorted(check_ids),
        "checkCount": len(check_ids),
        "evidenceCount": evidence_count,
        "sourceEventKey": source_event_key or str(raw.get("sourceEventKey") or result_key),
        "resultKey": result_key,
        "resultDigest": result_digest,
        "commitSha": commit_sha or (existing or {}).get("commitSha"),
        "headSha": head_sha or (existing or {}).get("headSha"),
        "ciStatus": ci_status or (existing or {}).get("ciStatus") or "UNKNOWN",
        "observedAt": _utc(observed_at),
        "policyDigest": public_reply_policy_digest(),
    }
    certificate["contentDigest"] = _digest(certificate)
    auth = sign_current(certificate, context="evidence-cert-v1")
    if not auth["keyId"] or not auth["signature"]:
        raise PermissionError("validation certificate signing key is unavailable")
    certificate["keyId"] = auth["keyId"]
    certificate["signature"] = sign_current(certificate, context="evidence-cert-v1")["signature"]
    return certificate


def _certificate_signature_valid(certificate: dict[str, Any], *, current_only: bool) -> bool:
    verifier = verify_current if current_only else verify_current_or_previous
    return _certificate_structure_valid(certificate) and verifier(
        {key: value for key, value in certificate.items() if key != "signature"},
        context="evidence-cert-v1",
        key_id=certificate.get("keyId"),
        signature=certificate.get("signature"),
    )


def verify_validation_certificate_current(certificate: dict[str, Any]) -> bool:
    """Verify evidence that is about to authorize a live state transition."""

    return _certificate_signature_valid(certificate, current_only=True)


def verify_validation_certificate_history(certificate: dict[str, Any]) -> bool:
    """Verify historical evidence for snapshot/history display only."""

    return _certificate_signature_valid(certificate, current_only=False)


def verify_validation_certificate(certificate: dict[str, Any]) -> bool:
    return verify_validation_certificate_current(certificate)


def task_creation_authorization(
    *, task_id: str, opportunity_key: str, repo: str, issue_url: str, intent_id: str
) -> dict[str, Any]:
    """Issue a current-key authorization bound to one managed task identity."""

    canonical_key = canonical_opportunity_key(opportunity_key)
    parsed_url = parse_issue_reference(issue_url)
    if parsed_url["opportunityKey"] != canonical_key or repo != (
        f"{parsed_url['owner']}/{parsed_url['repo']}"
    ):
        raise ValueError("task creation authorization identity is inconsistent")
    payload = {
        "schema": TASK_CREATION_AUTHORIZATION_SCHEMA,
        "taskId": task_id,
        "opportunityKey": canonical_key,
        "repo": f"{parsed_url['owner']}/{parsed_url['repo']}",
        "issueUrl": parsed_url["issueUrl"],
        "intentId": intent_id,
    }
    auth = sign_current(payload, context="task-creation-v1")
    if not auth["keyId"] or not auth["signature"]:
        raise PermissionError("task creation authorization key is unavailable")
    return payload | {"keyId": auth["keyId"], "signature": auth["signature"]}


def verify_task_creation_authorization(
    value: dict[str, Any],
    *,
    task_id: str,
    opportunity_key: str,
    repo: str,
    issue_url: str,
) -> bool:
    if not isinstance(value, dict) or value.get("schema") != TASK_CREATION_AUTHORIZATION_SCHEMA:
        return False
    try:
        expected_key = canonical_opportunity_key(opportunity_key)
        parsed_url = parse_issue_reference(issue_url)
    except (TypeError, ValueError):
        return False
    if parsed_url["opportunityKey"] != expected_key:
        return False
    payload = {
        key: value.get(key)
        for key in ("schema", "taskId", "opportunityKey", "repo", "issueUrl", "intentId")
    }
    if (
        payload["taskId"] != task_id
        or payload["opportunityKey"] != expected_key
        or payload["repo"] != f"{parsed_url['owner']}/{parsed_url['repo']}"
        or payload["issueUrl"] != parsed_url["issueUrl"]
        or not isinstance(payload["intentId"], str)
        or not payload["intentId"]
    ):
        return False
    return verify_current(
        payload,
        context="task-creation-v1",
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    )


def _valid_validation_certificate(certificate: dict[str, Any]) -> bool:
    return verify_validation_certificate_current(certificate)


def public_reply_policy_digest() -> str:
    return _digest(
        {
            "version": PUBLIC_REPLY_POLICY_VERSION,
            "allowedTemplate": REPLY_TEMPLATE_ID,
            "requires": [
                "maintainer_event",
                "patched_result",
                "validation_certificate",
                "passed_ci",
            ],
        }
    )


def _reply_template(body: str) -> tuple[str, dict[str, str]] | None:
    for style, rendered in _REPLY_TEMPLATES.items():
        if body == rendered:
            return REPLY_TEMPLATE_ID, {"style": style}
    return None


def render_reply_template(template_id: str, params: dict[str, Any]) -> str | None:
    if template_id != REPLY_TEMPLATE_ID:
        return None
    style = params.get("style")
    return _REPLY_TEMPLATES.get(style) if isinstance(style, str) else None


def json_payload(value: str) -> dict[str, Any]:
    parsed = json.loads(value)
    return parsed if isinstance(parsed, dict) else {}


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS managed_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    migration_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_opportunities (
    opportunity_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    repo TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    issue_url TEXT NOT NULL,
    state TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_tasks (
    task_id TEXT PRIMARY KEY,
    opportunity_key TEXT NOT NULL,
    thread_id TEXT,
    worktree_path TEXT,
    state TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(opportunity_key, task_id)
);
CREATE TABLE IF NOT EXISTS managed_reproduction_probes (
    probe_key TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    opportunity_key TEXT NOT NULL,
    repo TEXT NOT NULL,
    issue_url TEXT NOT NULL,
    thread_id TEXT,
    default_branch TEXT NOT NULL,
    selected_base_sha TEXT NOT NULL,
    code_paths_json TEXT NOT NULL,
    profile_id TEXT,
    checkout_path TEXT,
    head_sha TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PENDING','RUNNING','SUCCEEDED','WAITING_EXTERNAL')),
    receipt_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    worker_nonce TEXT,
    attempt_id TEXT,
    started_at TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS managed_reproduction_attempt_events (
    attempt_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    probe_key TEXT NOT NULL,
    event TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(attempt_id, sequence)
);
CREATE TABLE IF NOT EXISTS managed_prs (
    pr_key TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    repo TEXT NOT NULL,
    number INTEGER NOT NULL,
    head_sha TEXT,
    pr_url TEXT NOT NULL,
    state TEXT NOT NULL,
    auto_created INTEGER NOT NULL DEFAULT 0,
    maintainer_response INTEGER NOT NULL DEFAULT 0,
    source_kind TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    origin_kind TEXT NOT NULL DEFAULT 'MANAGED',
    origin_observation_json TEXT NOT NULL DEFAULT '{}',
    origin_head_sha TEXT,
    origin_pr_url TEXT,
    latest_source TEXT NOT NULL DEFAULT '',
    UNIQUE(owner, repo, number)
);
CREATE TABLE IF NOT EXISTS managed_results (
    result_key TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    pr_key TEXT,
    head_sha TEXT,
    result_digest TEXT NOT NULL,
    result_type TEXT CHECK(result_type IN
      ('scan_false_positive','state_drift','blocked_pre_task','task_no_go','censored')
      OR result_type IS NULL),
    worker_state TEXT NOT NULL,
    commit_sha TEXT,
    validation_json TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    is_current INTEGER NOT NULL DEFAULT 1,
    superseded_by TEXT,
    UNIQUE(task_id, pr_key, head_sha, result_digest)
);
CREATE TABLE IF NOT EXISTS managed_lifecycle_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    opportunity_key TEXT,
    task_id TEXT,
    pr_key TEXT,
    event_type TEXT NOT NULL,
    state TEXT,
    idempotency_key TEXT NOT NULL UNIQUE,
    idempotency_fingerprint TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
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
CREATE TABLE IF NOT EXISTS managed_maintainer_events (
    event_key TEXT PRIMARY KEY,
    pr_key TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_login TEXT,
    actor_type TEXT,
    author_association TEXT,
    is_maintainer INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_ci_runs (
    ci_key TEXT PRIMARY KEY,
    pr_key TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','PASSED','FAILED','CANCELLED','UNKNOWN')),
    checks_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    UNIQUE(pr_key, head_sha, ci_key)
);
CREATE TABLE IF NOT EXISTS managed_external_outcomes (
    outcome_id INTEGER PRIMARY KEY AUTOINCREMENT,
    opportunity_key TEXT,
    pr_key TEXT,
    horizon_days INTEGER NOT NULL CHECK(horizon_days IN (14,30,60)),
    label TEXT NOT NULL CHECK(label IN ('success','failure','censored','pending')),
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    UNIQUE(pr_key, horizon_days)
);
CREATE TABLE IF NOT EXISTS managed_public_replies (
    reply_key TEXT PRIMARY KEY,
    pr_key TEXT NOT NULL,
    maintainer_event_key TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('DRAFT','AUTO_REPLY_ALLOWED','DECISION_REQUIRED')),
    body TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    template_id TEXT NOT NULL DEFAULT 'opaque_body_v1',
    template_params_json TEXT NOT NULL DEFAULT '{}',
    body_digest TEXT NOT NULL DEFAULT '',
    policy_digest TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS managed_reply_deliveries (
    reply_key TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('QUEUED','SENDING','SENT','FAILED','BLOCKED')),
    external_id TEXT,
    receipt_digest TEXT,
    error TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_publication_reservations (
    reservation_key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    repo TEXT NOT NULL,
    head_ref TEXT,
    opportunity_key TEXT,
    pr_key TEXT,
    head_sha TEXT,
    invitation_event_key TEXT,
    state TEXT NOT NULL CHECK(state IN ('ACTIVE','BLOCKED','FINALIZED','EXPIRED','CHECK_ABSENCE_REQUIRED','WAITING_EXTERNAL','RELEASED','RECONCILE_REQUIRED')),
    idempotency_key TEXT NOT NULL UNIQUE,
    lease_until TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS managed_publication_absence_attestations (
    attestation_id TEXT PRIMARY KEY,
    reservation_key TEXT NOT NULL,
    repo TEXT NOT NULL,
    head_ref TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    query_json TEXT NOT NULL,
    local_effect_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    nonce TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    signer_key_id TEXT,
    signature TEXT,
    authentication_status TEXT NOT NULL DEFAULT 'AUTHENTICATED',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attestation_nonce_consumptions (
    consumption_id INTEGER PRIMARY KEY AUTOINCREMENT,
    attestation_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    reservation_key TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    UNIQUE(attestation_id, nonce, reservation_key, content_digest)
);
CREATE TRIGGER IF NOT EXISTS managed_events_no_update
BEFORE UPDATE ON managed_lifecycle_events
BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS managed_events_no_delete
BEFORE DELETE ON managed_lifecycle_events
BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS managed_absence_attestations_no_update
BEFORE UPDATE ON managed_publication_absence_attestations
BEGIN SELECT RAISE(ABORT, 'absence attestations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS managed_absence_attestations_no_delete
BEFORE DELETE ON managed_publication_absence_attestations
BEGIN SELECT RAISE(ABORT, 'absence attestations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS attestation_nonce_consumptions_no_update
BEFORE UPDATE ON attestation_nonce_consumptions
BEGIN SELECT RAISE(ABORT, 'nonce consumptions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS attestation_nonce_consumptions_no_delete
BEFORE DELETE ON attestation_nonce_consumptions
BEGIN SELECT RAISE(ABORT, 'nonce consumptions are append-only'); END;
"""


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def schema_digest() -> str:
    return hashlib.sha256(SCHEMA_SQL.encode("utf-8")).hexdigest()


def _attestation_unsigned(attestation: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in attestation.items()
        if key not in {"contentDigest", "signerKeyId", "signature"}
    }


def _attestation_structure_valid(attestation: dict[str, Any]) -> bool:
    content_digest = attestation.get("contentDigest")
    return isinstance(content_digest, str) and content_digest == _digest(
        _attestation_unsigned(attestation)
    )


def _attestation_authenticated(attestation: dict[str, Any]) -> bool:
    """Verify an attestation for history/snapshot inspection."""

    if not _attestation_structure_valid(attestation):
        return False
    signer_key_id = attestation.get("signerKeyId")
    signature = attestation.get("signature")
    if not signer_key_id or not signature:
        return False
    return verify_current_or_previous(
        {
            **_attestation_unsigned(attestation),
            "contentDigest": attestation["contentDigest"],
            "signerKeyId": signer_key_id,
        },
        context="absence-attestation-v1",
        key_id=signer_key_id,
        signature=signature,
    )


def _attestation_authenticated_current(attestation: dict[str, Any]) -> bool:
    """Verify an attestation that is about to release a reservation."""

    if not _attestation_structure_valid(attestation):
        return False
    signer_key_id = attestation.get("signerKeyId")
    signature = attestation.get("signature")
    if not signer_key_id or not signature:
        return False
    return verify_current(
        {
            **_attestation_unsigned(attestation),
            "contentDigest": attestation["contentDigest"],
            "signerKeyId": signer_key_id,
        },
        context="absence-attestation-v1",
        key_id=signer_key_id,
        signature=signature,
    )


def _read_schema_migration_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    try:
        rows = connection.execute(
            "SELECT version,applied_at,migration_digest FROM managed_schema_migrations ORDER BY version"
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    current_digest = schema_digest()
    for row in rows:
        version = int(row["version"])
        if version > MANAGED_SCHEMA_VERSION:
            raise ValueError(f"unknown managed schema version: {version}")
        if version == 7 and row["migration_digest"] not in KNOWN_MANAGED_SCHEMA_V7_DIGESTS:
            raise ValueError("managed schema v7 digest mismatch")
        if version == MANAGED_SCHEMA_VERSION and row["migration_digest"] != current_digest:
            raise ValueError("managed schema current digest mismatch")
    return rows


def migrate_schema(
    path: Path,
    *,
    target_version: int = MANAGED_SCHEMA_VERSION,
    _allow_v6_upgrade: bool = False,
) -> dict[str, Any]:
    """Apply additive managed schema migrations to an explicitly chosen DB."""

    if target_version != MANAGED_SCHEMA_VERSION:
        raise ValueError(f"unsupported managed schema target: {target_version}")
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(path)
    try:
        existing_version = 0
        rows = _read_schema_migration_rows(connection)
        existing_version = int(rows[-1]["version"]) if rows else 0
        if existing_version == 6 and not _allow_v6_upgrade:
            raise ValueError("managed schema v6 requires migrate_v6_to_current")
        connection.executescript(SCHEMA_SQL)
        backfill_from_managed_events(connection, action_guard_root=ledger_action_guard_root(path))
        connection.execute("BEGIN IMMEDIATE")
        result_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(managed_results)").fetchall()
        }
        result_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='managed_results'"
            ).fetchone()[0]
            or ""
        )
        if "result_type TEXT NOT NULL" in result_sql:
            connection.execute("ALTER TABLE managed_results RENAME TO managed_results_v7")
            connection.execute(
                """CREATE TABLE managed_results (
                    result_key TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    pr_key TEXT,
                    head_sha TEXT,
                    result_digest TEXT NOT NULL,
                    result_type TEXT CHECK(result_type IN
                      ('scan_false_positive','state_drift','blocked_pre_task','task_no_go','censored')
                      OR result_type IS NULL),
                    worker_state TEXT NOT NULL,
                    commit_sha TEXT,
                    validation_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    is_current INTEGER NOT NULL DEFAULT 1,
                    superseded_by TEXT,
                    UNIQUE(task_id, pr_key, head_sha, result_digest)
                )"""
            )
            connection.execute(
                """INSERT INTO managed_results
                   SELECT result_key,task_id,pr_key,head_sha,result_digest,result_type,
                          worker_state,commit_sha,validation_json,source,provenance_json,
                          observed_at,is_current,superseded_by
                   FROM managed_results_v7"""
            )
            connection.execute("DROP TABLE managed_results_v7")
            result_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(managed_results)").fetchall()
            }
        if "is_current" not in result_columns:
            connection.execute(
                "ALTER TABLE managed_results ADD COLUMN is_current INTEGER NOT NULL DEFAULT 1"
            )
        if "superseded_by" not in result_columns:
            connection.execute("ALTER TABLE managed_results ADD COLUMN superseded_by TEXT")
        event_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(managed_lifecycle_events)").fetchall()
        }
        if "idempotency_fingerprint" not in event_columns:
            connection.execute("DROP TRIGGER IF EXISTS managed_events_no_update")
            connection.execute(
                "ALTER TABLE managed_lifecycle_events ADD COLUMN idempotency_fingerprint TEXT"
            )
            for event in connection.execute(
                "SELECT event_id,idempotency_key FROM managed_lifecycle_events"
            ).fetchall():
                connection.execute(
                    "UPDATE managed_lifecycle_events SET idempotency_fingerprint=? WHERE event_id=?",
                    (stable_fingerprint(event["idempotency_key"]), event["event_id"]),
                )
            connection.execute(
                "CREATE TRIGGER IF NOT EXISTS managed_events_no_update BEFORE UPDATE ON managed_lifecycle_events BEGIN SELECT RAISE(ABORT, 'managed lifecycle events are append-only'); END"
            )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS managed_events_fingerprint_unique ON managed_lifecycle_events(idempotency_fingerprint)"
        )
        reservation_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='managed_publication_reservations'"
        ).fetchone()[0]
        if "CHECK_ABSENCE_REQUIRED" not in (reservation_sql or ""):
            connection.execute(
                "ALTER TABLE managed_publication_reservations RENAME TO managed_publication_reservations_v4"
            )
            connection.execute(
                """CREATE TABLE managed_publication_reservations (
                    reservation_key TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    repo TEXT NOT NULL,
                    head_ref TEXT,
                    opportunity_key TEXT,
                    pr_key TEXT,
                    head_sha TEXT,
                    invitation_event_key TEXT,
                    state TEXT NOT NULL CHECK(state IN ('ACTIVE','BLOCKED','FINALIZED','EXPIRED','CHECK_ABSENCE_REQUIRED','WAITING_EXTERNAL','RELEASED','RECONCILE_REQUIRED')),
                    idempotency_key TEXT NOT NULL UNIQUE,
                    lease_until TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """INSERT INTO managed_publication_reservations
                   (reservation_key,request_id,repo,head_ref,opportunity_key,pr_key,head_sha,
                    invitation_event_key,state,idempotency_key,lease_until,created_at,updated_at)
                   SELECT reservation_key,request_id,repo,NULL,opportunity_key,pr_key,head_sha,
                          invitation_event_key,state,idempotency_key,lease_until,created_at,updated_at
                   FROM managed_publication_reservations_v4"""
            )
            connection.execute("DROP TABLE managed_publication_reservations_v4")
        reservation_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(managed_publication_reservations)"
            ).fetchall()
        }
        if "head_ref" not in reservation_columns:
            connection.execute(
                "ALTER TABLE managed_publication_reservations ADD COLUMN head_ref TEXT"
            )
        attestation_indexes = connection.execute(
            "PRAGMA index_list(managed_publication_absence_attestations)"
        ).fetchall()
        has_reservation_unique = False
        for index in attestation_indexes:
            if not index[2]:
                continue
            columns = [
                str(item[2])
                for item in connection.execute(f'PRAGMA index_info("{index[1]}")').fetchall()
            ]
            if columns == ["reservation_key"]:
                has_reservation_unique = True
                break
        if has_reservation_unique:
            connection.execute("DROP TRIGGER IF EXISTS managed_absence_attestations_no_update")
            connection.execute("DROP TRIGGER IF EXISTS managed_absence_attestations_no_delete")
            connection.execute(
                "ALTER TABLE managed_publication_absence_attestations RENAME TO managed_publication_absence_attestations_v6"
            )
            connection.execute(
                """CREATE TABLE managed_publication_absence_attestations (
                    attestation_id TEXT PRIMARY KEY,
                    reservation_key TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    head_ref TEXT NOT NULL,
                    head_sha TEXT NOT NULL,
                    query_json TEXT NOT NULL,
                    local_effect_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    signer_key_id TEXT,
                    signature TEXT,
                    authentication_status TEXT NOT NULL DEFAULT 'AUTHENTICATED',
                    created_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                """INSERT INTO managed_publication_absence_attestations
                   (attestation_id,reservation_key,repo,head_ref,head_sha,query_json,local_effect_json,
                    observed_at,policy_version,nonce,content_digest,signer_key_id,signature,
                    authentication_status,created_at)
                   SELECT attestation_id,reservation_key,repo,head_ref,head_sha,query_json,local_effect_json,
                    observed_at,policy_version,nonce,content_digest,signer_key_id,signature,
                    'AUTHENTICATED',created_at
                   FROM managed_publication_absence_attestations_v6"""
            )
            connection.execute("DROP TABLE managed_publication_absence_attestations_v6")
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
        attestation_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(managed_publication_absence_attestations)"
            ).fetchall()
        }
        if "authentication_status" not in attestation_columns:
            connection.execute(
                "ALTER TABLE managed_publication_absence_attestations ADD COLUMN authentication_status TEXT NOT NULL DEFAULT 'AUTHENTICATED'"
            )
            connection.execute(
                """CREATE TRIGGER managed_absence_attestations_no_delete
                   BEFORE DELETE ON managed_publication_absence_attestations
                   BEGIN SELECT RAISE(ABORT, 'absence attestations are append-only'); END"""
            )
        for table, columns in {
            "managed_prs": {
                "origin_kind": "TEXT NOT NULL DEFAULT 'MANAGED'",
                "origin_observation_json": "TEXT NOT NULL DEFAULT '{}'",
                "origin_head_sha": "TEXT",
                "origin_pr_url": "TEXT",
                "latest_source": "TEXT NOT NULL DEFAULT ''",
            },
            "managed_public_replies": {
                "template_id": "TEXT NOT NULL DEFAULT 'opaque_body_v1'",
                "template_params_json": "TEXT NOT NULL DEFAULT '{}'",
                "body_digest": "TEXT NOT NULL DEFAULT ''",
                "policy_digest": "TEXT NOT NULL DEFAULT ''",
            },
        }.items():
            present = {
                str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for name, ddl in columns.items():
                if name not in present:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
        probe_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(managed_reproduction_probes)"
            ).fetchall()
        }
        for name, ddl in {
            "thread_id": "TEXT",
            "worker_nonce": "TEXT",
            "attempt_id": "TEXT",
            "started_at": "TEXT",
            "lease_expires_at": "TEXT",
            "attempt_count": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if name not in probe_columns:
                connection.execute(
                    f"ALTER TABLE managed_reproduction_probes ADD COLUMN {name} {ddl}"
                )
        connection.execute(
            """UPDATE managed_prs SET origin_kind=CASE WHEN source_kind='EXISTING_OPEN_PR'
               THEN 'EXISTING_OPEN_PR' ELSE COALESCE(NULLIF(origin_kind,''),source_kind) END,
            origin_observation_json=CASE WHEN origin_observation_json='{}'
               THEN provenance_json ELSE origin_observation_json END,
               origin_head_sha=CASE WHEN origin_head_sha IS NULL AND source_kind='EXISTING_OPEN_PR'
               THEN head_sha ELSE origin_head_sha END,
               origin_pr_url=CASE WHEN origin_pr_url IS NULL AND source_kind='EXISTING_OPEN_PR'
               THEN pr_url ELSE origin_pr_url END,
               latest_source=CASE WHEN latest_source='' THEN source ELSE latest_source END"""
        )
        for reply in connection.execute(
            "SELECT reply_key,body FROM managed_public_replies WHERE body_digest=''"
        ).fetchall():
            connection.execute(
                "UPDATE managed_public_replies SET body_digest=?,policy_digest=? WHERE reply_key=?",
                (_digest(reply["body"]), public_reply_policy_digest(), reply["reply_key"]),
            )
        row = connection.execute(
            "SELECT version FROM managed_schema_migrations WHERE version=?",
            (MANAGED_SCHEMA_VERSION,),
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO managed_schema_migrations(version,applied_at,migration_digest) VALUES (?,?,?)",
                (MANAGED_SCHEMA_VERSION, _utc(), schema_digest()),
            )
            applied = True
        else:
            applied = False
        connection.commit()
        return {
            "ok": True,
            "version": MANAGED_SCHEMA_VERSION,
            "applied": applied,
            "migrationDigest": schema_digest(),
            "tables": list(MANAGED_TABLES),
        }
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def migrate_v6_to_current(
    source: Path,
    target: Path,
    *,
    snapshot_output: Path | None = None,
) -> dict[str, Any]:
    """Atomically reauthorize a v6 database on a copy with explicit downgrade."""

    if source.resolve() == target.resolve():
        raise ValueError("v6 migration target must differ from source")
    if schema_status(source)["current"] != 6:
        raise ValueError("source database must be managed schema v6")
    if not current_signing_key_id():
        raise PermissionError("v6 migration requires the current signing key")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        copy_database(source, temporary)
        migrate_schema(temporary, _allow_v6_upgrade=True)
        connection = connect(temporary)
        try:
            connection.execute("BEGIN IMMEDIATE")
            result_rows = connection.execute(
                "SELECT result_key,validation_json FROM managed_results"
            ).fetchall()
            for row in result_rows:
                try:
                    validation = json.loads(row["validation_json"])
                except json.JSONDecodeError:
                    validation = {}
                connection.execute(
                    "UPDATE managed_results SET validation_json=? WHERE result_key=?",
                    (
                        _json(
                            {
                                "passed": False,
                                "certificate": None,
                                "authenticationStatus": "UNAUTHENTICATED",
                                "authorizationState": "LEGACY_REAUTH_REQUIRED",
                                "legacyValidationDigest": _digest(validation),
                            }
                        ),
                        row["result_key"],
                    ),
                )
            connection.execute(
                "UPDATE managed_public_replies SET mode='DRAFT',reason='LEGACY_REAUTH_REQUIRED'"
            )
            connection.execute(
                "UPDATE managed_reply_deliveries SET state='BLOCKED',error='LEGACY_REAUTH_REQUIRED'"
            )
            connection.execute("DROP TRIGGER IF EXISTS managed_absence_attestations_no_update")
            connection.execute("DROP TRIGGER IF EXISTS managed_absence_attestations_no_delete")
            connection.execute(
                """UPDATE managed_publication_absence_attestations
                   SET authentication_status='LEGACY_REAUTH_REQUIRED',signer_key_id=NULL,signature=NULL"""
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
                "UPDATE managed_publication_reservations SET state='CHECK_ABSENCE_REQUIRED' WHERE state<>'BLOCKED'"
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        migrated = ManagedLedger(temporary)
        migrated.record_event(
            event_type="MANAGED_SCHEMA_MIGRATED",
            idempotency_key=f"managed-schema:v6-to-v{MANAGED_SCHEMA_VERSION}",
            state="LEGACY_REAUTH_REQUIRED",
            source="managed-migration",
            provenance={
                "fromVersion": 6,
                "toVersion": MANAGED_SCHEMA_VERSION,
                "authorization": "reauth_required",
            },
            payload={
                "certificates": "UNAUTHENTICATED",
                "absenceAttestations": "LEGACY_REAUTH_REQUIRED",
            },
        )
        from .managed_snapshot import export_snapshot

        output = snapshot_output or target.with_name("managed_lifecycle.snapshot.json.gz")
        snapshot_result = export_snapshot(temporary, output)
        os.replace(temporary, target)
        temporary = Path()
        return {
            "ok": True,
            "fromVersion": 6,
            "toVersion": MANAGED_SCHEMA_VERSION,
            "target": str(target),
            "snapshot": snapshot_result,
            "authorization": "LEGACY_REAUTH_REQUIRED",
        }
    finally:
        if temporary and temporary != Path() and temporary.exists():
            temporary.unlink()


def migrate_v6_to_v7(
    source: Path,
    target: Path,
    *,
    snapshot_output: Path | None = None,
) -> dict[str, Any]:
    """Compatibility entrypoint: migrate v6 to the current managed schema."""

    return migrate_v6_to_current(source, target, snapshot_output=snapshot_output)


def rollback_schema(path: Path, *, target_version: int = 0) -> dict[str, Any]:
    """Remove only managed objects, leaving legacy and publication tables intact."""

    if target_version != 0:
        raise ValueError("only rollback to version 0 is supported")
    connection = connect(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        for table in MANAGED_TABLES:
            connection.execute(f'DROP TABLE IF EXISTS "{table}"')
        connection.execute("DROP TRIGGER IF EXISTS managed_events_no_update")
        connection.execute("DROP TRIGGER IF EXISTS managed_events_no_delete")
        connection.execute("COMMIT")
        return {"ok": True, "version": 0, "dropped": list(MANAGED_TABLES)}
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()


def copy_database(source: Path, target: Path) -> None:
    """Copy a closed SQLite DB without writing to the source."""

    if source.resolve() == target.resolve():
        raise ValueError("migration source and target must be different")
    target.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.execute("PRAGMA query_only=ON")
        target_connection.execute("PRAGMA journal_mode=WAL")
        source_connection.backup(target_connection)
    finally:
        target_connection.close()
        source_connection.close()


def _append_probe_attempt_event(
    connection: sqlite3.Connection,
    *,
    attempt_id: str,
    probe_key: str,
    event: str,
    observed_at: str,
    payload: dict[str, Any] | None = None,
) -> None:
    prior = connection.execute(
        "SELECT COALESCE(MAX(sequence), -1) FROM managed_reproduction_attempt_events WHERE attempt_id=?",
        (attempt_id,),
    ).fetchone()[0]
    connection.execute(
        """INSERT INTO managed_reproduction_attempt_events
           (attempt_id,sequence,probe_key,event,observed_at,payload_json)
           VALUES (?,?,?,?,?,?)""",
        (attempt_id, int(prior) + 1, probe_key, event, observed_at, _json(payload or {})),
    )


def legacy_content_snapshot(path: Path) -> dict[str, Any]:
    """Return row counts and canonical digests for every non-managed table."""

    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        tables = [
            str(row[0])
            for row in connection.execute(
                """SELECT name FROM sqlite_master WHERE type='table'
                   AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'managed_%'
                   AND name NOT IN ('attestation_nonce_consumptions','task_quarantines')
                   ORDER BY name"""
            ).fetchall()
        ]
        snapshot: dict[str, Any] = {}
        for table in tables:
            rows = [dict(row) for row in connection.execute(f' SELECT * FROM "{table}"').fetchall()]
            rows.sort(key=lambda row: _json(row))
            snapshot[table] = {"rowCount": len(rows), "contentDigest": _digest(rows)}
        return {"tables": snapshot, "overallDigest": _digest(snapshot)}
    finally:
        connection.close()


def _row_json(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


@dataclass
class ManagedLedger:
    path: Path
    ensure_schema: bool = False

    def __post_init__(self) -> None:
        if self.ensure_schema:
            migrate_schema(self.path)

    def _connection(self) -> sqlite3.Connection:
        return connect(self.path)

    def record_event(
        self,
        *,
        event_type: str,
        idempotency_key: str,
        opportunity_key: str | None = None,
        task_id: str | None = None,
        pr_key: str | None = None,
        state: str | None = None,
        source: str = "managed",
        provenance: dict[str, Any] | None = None,
        observed_at: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        opportunity_key = canonical_opportunity_key(opportunity_key) if opportunity_key else None
        fingerprint = stable_fingerprint(idempotency_key)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM managed_lifecycle_events WHERE idempotency_fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if existing:
                connection.execute("COMMIT")
                return dict(existing) | {"created": False}
            connection.execute(
                """INSERT INTO managed_lifecycle_events
                   (opportunity_key,task_id,pr_key,event_type,state,idempotency_key,source,
                    idempotency_fingerprint,provenance_json,observed_at,payload_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    opportunity_key,
                    task_id,
                    pr_key,
                    event_type,
                    state,
                    idempotency_key,
                    source,
                    fingerprint,
                    _json(provenance or {}),
                    _utc(observed_at),
                    _json(payload or {}),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_lifecycle_events WHERE idempotency_fingerprint=?",
                (fingerprint,),
            ).fetchone()
            connection.commit()
            return dict(row) | {"created": True}
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def record_task_quarantine(
        self,
        *,
        opportunity_key: str,
        reason: str,
        dedupe_key: str,
        task_id: str | None = None,
        state: str = "VALIDATION_PENDING",
        source: str = "managed",
        provenance: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        """Record a blocking quarantine under its opportunity action guard."""

        opportunity_key = canonical_opportunity_key(opportunity_key)
        with opportunity_action_guard(ledger_action_guard_root(self.path), opportunity_key):
            return self._record_task_quarantine_unlocked(
                opportunity_key=opportunity_key,
                reason=reason,
                dedupe_key=dedupe_key,
                task_id=task_id,
                state=state,
                source=source,
                provenance=provenance,
                payload=payload,
                observed_at=observed_at,
            )

    def _record_task_quarantine_unlocked(
        self,
        *,
        opportunity_key: str,
        reason: str,
        dedupe_key: str,
        task_id: str | None = None,
        state: str = "VALIDATION_PENDING",
        source: str = "managed",
        provenance: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        """Record the publication-blocking fact and its managed audit atomically."""

        opportunity_key = canonical_opportunity_key(opportunity_key)
        observed_at = _utc(observed_at)
        event_idempotency_key = f"task-quarantine:{reason}:{dedupe_key}"
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            quarantine = record_quarantine(
                connection,
                opportunity_key=opportunity_key,
                reason=reason,
                dedupe_key=dedupe_key,
                payload=payload or {},
                created_at=observed_at,
            )
            if quarantine["created"]:
                fingerprint = stable_fingerprint(event_idempotency_key)
                connection.execute(
                    """INSERT OR IGNORE INTO managed_lifecycle_events
                       (opportunity_key,task_id,event_type,state,idempotency_key,
                        idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        opportunity_key,
                        task_id,
                        reason,
                        state,
                        event_idempotency_key,
                        fingerprint,
                        source,
                        _json(provenance or {}),
                        observed_at,
                        _json(payload or {}),
                    ),
                )
            connection.commit()
            return quarantine
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def active_task_quarantine(self, opportunity_key: str) -> dict[str, Any] | None:
        connection = self._connection()
        try:
            row = active_quarantine(connection, opportunity_key=opportunity_key)
            if row is None:
                return None
            return {
                "reason": row["reason"],
                "payload": quarantine_payload(row),
                "createdAt": row["created_at"],
            }
        finally:
            connection.close()

    def clear_task_quarantine(
        self,
        opportunity_key: str,
        *,
        reason: str,
        evidence: dict[str, Any],
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        """Clear the same authoritative row and append its managed audit atomically."""

        observed_at = _utc(observed_at)
        event_idempotency_key = (
            f"task-quarantine-cleared:{opportunity_key}:{reason}:{canonical_json(evidence)}"
        )
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cleared = clear_quarantine(
                connection,
                opportunity_key=canonical_opportunity_key(opportunity_key),
                reason=reason,
                evidence=evidence,
                cleared_at=observed_at,
            )
            if cleared:
                fingerprint = stable_fingerprint(event_idempotency_key)
                connection.execute(
                    """INSERT OR IGNORE INTO managed_lifecycle_events
                       (opportunity_key,event_type,state,idempotency_key,
                        idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        canonical_opportunity_key(opportunity_key),
                        "TASK_QUARANTINE_CLEARED",
                        "READY",
                        event_idempotency_key,
                        fingerprint,
                        "managed",
                        _json({"reason": reason}),
                        observed_at,
                        _json({"reason": reason, **evidence}),
                    ),
                )
            connection.commit()
            return {"cleared": cleared}
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def bind_task_quarantine_artifact(
        self, opportunity_key: str, *, reason: str, artifact: dict[str, Any]
    ) -> None:
        """Persist a recovery directory binding in the shared quarantine row."""

        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            attach_quarantine_artifact(
                connection,
                opportunity_key=canonical_opportunity_key(opportunity_key),
                reason=reason,
                artifact=artifact,
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def upsert_opportunity(
        self,
        *,
        opportunity_key: str,
        owner: str,
        repo: str,
        issue_number: int,
        issue_url: str,
        state: str,
        source: str,
        provenance: dict[str, Any],
        observed_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        identity = canonical_opportunity_identity(
            opportunity_key=opportunity_key,
            owner=owner,
            repo=repo,
            issue_number=issue_number,
            issue_url=issue_url,
        )
        canonical_key = identity["opportunityKey"]
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (canonical_key,),
            ).fetchone()
            if existing is not None:
                canonical_opportunity_identity(
                    opportunity_key=identity["opportunityKey"],
                    owner=existing["owner"],
                    repo=existing["repo"],
                    issue_number=existing["issue_number"],
                    issue_url=existing["issue_url"],
                )
            connection.execute(
                """INSERT INTO managed_opportunities
                   (opportunity_key,owner,repo,issue_number,issue_url,state,source,
                    provenance_json,observed_at,metadata_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(opportunity_key) DO UPDATE SET
                     state=excluded.state,provenance_json=excluded.provenance_json,
                     observed_at=excluded.observed_at,metadata_json=excluded.metadata_json""",
                (
                    canonical_key,
                    identity["owner"],
                    identity["repo"],
                    identity["issueNumber"],
                    identity["issueUrl"],
                    state,
                    source,
                    _json(provenance),
                    _utc(observed_at),
                    _json(metadata or {}),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (canonical_key,),
            ).fetchone()
            if row is None:
                raise RuntimeError("managed opportunity upsert did not return a row")
            connection.execute("COMMIT")
            return dict(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def opportunity_identity(self, opportunity_key: str) -> dict[str, Any] | None:
        """Return immutable issue identity and base evidence for a managed opportunity."""

        try:
            canonical_key = canonical_opportunity_key(opportunity_key)
        except (TypeError, ValueError):
            return None
        connection = self._connection()
        try:
            row = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (canonical_key,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None
        try:
            canonical_opportunity_identity(
                opportunity_key=canonical_key,
                owner=row["owner"],
                repo=row["repo"],
                issue_number=row["issue_number"],
                issue_url=row["issue_url"],
            )
        except (TypeError, ValueError):
            return None
        try:
            provenance = json.loads(row["provenance_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            provenance = {}
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            metadata = {}
        evidence = metadata.get("preTaskEvidence") if isinstance(metadata, dict) else {}
        if not isinstance(evidence, dict):
            evidence = {}
        selected_base = (
            metadata.get("selectedBaseSha")
            or metadata.get("baseSha")
            or evidence.get("selectedBaseSha")
            or evidence.get("baseSha")
            or provenance.get("selectedBaseSha")
            or provenance.get("baseSha")
        )
        opportunity_paths = metadata.get("codePaths") if isinstance(metadata, dict) else []
        if not isinstance(opportunity_paths, list):
            opportunity_paths = []
        return {
            "opportunityKey": canonical_key,
            "owner": row["owner"],
            "repo": row["repo"],
            "issueNumber": int(row["issue_number"]),
            "issueUrl": row["issue_url"],
            "selectedBaseSha": str(selected_base or ""),
            "codePaths": [str(path) for path in opportunity_paths if str(path).strip()],
        }

    def ensure_opportunity_evidence(
        self, *, opportunity_key: str, selected_base_sha: str, code_paths: list[str]
    ) -> dict[str, Any]:
        """Record missing pre-task evidence without changing an established identity."""

        if not selected_base_sha or not code_paths:
            raise ValueError("opportunity evidence is incomplete")
        opportunity_key = canonical_opportunity_key(opportunity_key)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (opportunity_key,),
            ).fetchone()
            if row is None:
                raise ValueError("managed opportunity is missing")
            canonical_opportunity_identity(
                opportunity_key=opportunity_key,
                owner=row["owner"],
                repo=row["repo"],
                issue_number=row["issue_number"],
                issue_url=row["issue_url"],
            )
            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                metadata = {}
            if not isinstance(metadata, dict):
                metadata = {}
            existing_base = str(metadata.get("selectedBaseSha") or metadata.get("baseSha") or "")
            existing_paths = metadata.get("codePaths") or []
            if existing_base and existing_base != selected_base_sha:
                raise ValueError("opportunity base evidence is immutable")
            if existing_paths and sorted(str(path) for path in existing_paths) != sorted(
                str(path) for path in code_paths
            ):
                raise ValueError("opportunity code path evidence is immutable")
            metadata["selectedBaseSha"] = existing_base or selected_base_sha
            metadata["codePaths"] = existing_paths or sorted({str(path) for path in code_paths})
            connection.execute(
                "UPDATE managed_opportunities SET metadata_json=? WHERE opportunity_key=?",
                (_json(metadata), opportunity_key),
            )
            updated = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (opportunity_key,),
            ).fetchone()
            connection.commit()
            return dict(updated)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def bind_task(
        self,
        *,
        task_id: str,
        opportunity_key: str,
        thread_id: str | None,
        worktree_path: str | None,
        state: str = "SYSTEM_PROCESSING",
        source: str = "managed",
        provenance: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        opportunity_key = canonical_opportunity_key(opportunity_key)
        connection = self._connection()
        provenance = dict(provenance or {})
        expected_opportunity = self.opportunity_identity(opportunity_key)
        if state == "IMPLEMENTATION_READY":
            from .repo_probe import REPRODUCED_VALIDATED, verify_probe_receipt

            candidate_receipt = provenance.get("probeReceipt")
            expected_paths = expected_opportunity.get("codePaths") if expected_opportunity else []
            expected_paths = (
                [str(path) for path in expected_paths if str(path).strip()]
                if isinstance(expected_paths, list)
                else []
            )
            if not isinstance(candidate_receipt, dict) or not verify_probe_receipt(
                candidate_receipt,
                repo=(
                    f"{expected_opportunity['owner']}/{expected_opportunity['repo']}"
                    if expected_opportunity
                    else ""
                ),
                base_sha=(
                    expected_opportunity.get("selectedBaseSha") if expected_opportunity else ""
                ),
                code_paths=expected_paths,
                required_level=REPRODUCED_VALIDATED,
                issue_url=(expected_opportunity.get("issueUrl") if expected_opportunity else None),
                task_id=task_id,
                thread_id=thread_id,
                thread_fingerprint_value=provenance.get("threadFingerprint"),
                head_sha=provenance.get("headSha"),
                commit_sha=provenance.get("commitSha"),
                result_digest=provenance.get("resultDigest"),
            ):
                state = "REPRODUCTION_REQUIRED"
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if existing and (
                existing["opportunity_key"] != opportunity_key
                or (existing["thread_id"] and thread_id and existing["thread_id"] != thread_id)
                or (
                    existing["worktree_path"]
                    and worktree_path
                    and existing["worktree_path"] != worktree_path
                )
            ):
                raise ValueError("task identity is immutable")
            if existing and existing["state"] == "IMPLEMENTATION_READY":
                # A legacy result rebind must never roll back the managed
                # lifecycle fact established by a current-key receipt.
                state = "IMPLEMENTATION_READY"
                try:
                    existing_provenance = json.loads(existing["provenance_json"] or "{}")
                except json.JSONDecodeError:
                    existing_provenance = {}
                provenance = existing_provenance | provenance
                provenance.update(
                    {
                        "taskStage": "IMPLEMENTATION_READY",
                        "probeLevel": "REPRODUCED_VALIDATED",
                        "probeReceiptDigest": existing_provenance.get("probeReceiptDigest"),
                        "probeReceipt": existing_provenance.get("probeReceipt"),
                    }
                )
                established_receipt = existing_provenance.get("probeReceipt")
                if isinstance(established_receipt, dict):
                    provenance.update(
                        {
                            "selectedBaseSha": established_receipt.get("baseSha"),
                            "codePaths": list(established_receipt.get("codePaths") or []),
                            "headSha": established_receipt.get("headSha"),
                            "commitSha": established_receipt.get("commitSha"),
                            "resultDigest": established_receipt.get("resultDigest"),
                        }
                    )
            connection.execute(
                """INSERT INTO managed_tasks
                   (task_id,opportunity_key,thread_id,worktree_path,state,source,
                    provenance_json,observed_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(task_id) DO UPDATE SET thread_id=COALESCE(excluded.thread_id,managed_tasks.thread_id),
                     worktree_path=COALESCE(excluded.worktree_path,managed_tasks.worktree_path),
                     state=excluded.state,
                     source=excluded.source,provenance_json=excluded.provenance_json,
                     observed_at=excluded.observed_at""",
                (
                    task_id,
                    opportunity_key,
                    thread_id,
                    worktree_path,
                    state,
                    source,
                    _json(provenance),
                    _utc(observed_at),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.record_event(
            event_type="TASK_BOUND",
            idempotency_key=f"task-bound:{task_id}",
            opportunity_key=opportunity_key,
            task_id=task_id,
            state=state,
            source=source,
            provenance=provenance,
            observed_at=observed_at,
            payload={"thread_id": thread_id, "worktree_path": worktree_path},
        )
        return dict(row)

    def current_reproduction_receipt(
        self,
        *,
        task_id: str,
        receipt_digest: str | None,
        repo: str,
        issue_url: str,
        selected_base_sha: str,
        code_paths: list[str],
        head_sha: str | None = None,
        commit_sha: str | None = None,
        result_digest: str | None = None,
        checkout_path: Path | None = None,
        policy_digest: str | None = None,
    ) -> dict[str, Any] | None:
        """Return only a complete, current-key receipt recorded by the managed ledger."""

        from .repo_probe import REPRODUCED_VALIDATED, validate_checkout_paths, verify_probe_receipt

        if not receipt_digest:
            return None
        connection = self._connection()
        try:
            rows = connection.execute(
                """SELECT receipt_json FROM managed_reproduction_probes
                   WHERE task_id=? AND state='SUCCEEDED' ORDER BY updated_at DESC""",
                (task_id,),
            ).fetchall()
            task_row = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            opportunity_row = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=(SELECT opportunity_key FROM managed_tasks WHERE task_id=?)",
                (task_id,),
            ).fetchone()
        finally:
            connection.close()
        if task_row is None or opportunity_row is None:
            return None
        if (
            repo != f"{opportunity_row['owner']}/{opportunity_row['repo']}"
            or issue_url != opportunity_row["issue_url"]
        ):
            return None
        expected_opportunity = self.opportunity_identity(task_row["opportunity_key"])
        if not expected_opportunity or not expected_opportunity.get("selectedBaseSha"):
            return None
        if selected_base_sha != expected_opportunity["selectedBaseSha"]:
            return None
        try:
            task_provenance = json.loads(task_row["provenance_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            return None
        expected_paths = expected_opportunity.get("codePaths")
        if not isinstance(expected_paths, list) or not expected_paths:
            return None
        if sorted(str(path) for path in expected_paths) != sorted(code_paths):
            return None
        expected_thread_id = task_row["thread_id"]
        expected_thread_fingerprint = task_provenance.get("threadFingerprint")
        candidate_receipts: list[dict[str, Any]] = []
        task_receipt = task_provenance.get("probeReceipt")
        if isinstance(task_receipt, dict):
            candidate_receipts.append(task_receipt)
        for row in rows:
            try:
                receipt = json.loads(row["receipt_json"] or "{}")
            except json.JSONDecodeError:
                continue
            candidate_receipts.append(receipt)
        for receipt in candidate_receipts:
            if not isinstance(receipt, dict) or receipt.get("receiptDigest") != receipt_digest:
                continue
            if not verify_probe_receipt(
                receipt,
                repo=repo,
                base_sha=selected_base_sha,
                code_paths=[str(path) for path in expected_paths],
                required_level=REPRODUCED_VALIDATED,
                issue_url=issue_url,
                task_id=task_id,
                thread_id=expected_thread_id,
                thread_fingerprint_value=expected_thread_fingerprint,
                head_sha=head_sha,
                commit_sha=commit_sha,
                result_digest=result_digest,
                policy_digest=policy_digest,
            ):
                return None
            if checkout_path is not None:
                try:
                    current_bindings = validate_checkout_paths(checkout_path, code_paths)
                except Exception:
                    return None
                if current_bindings != receipt.get("codePathBindings"):
                    return None
            return receipt
        return None

    def implementation_authorization_receipt(
        self,
        *,
        task_id: str,
        thread_id: str,
        worktree_path: str,
        repo: str,
        issue_url: str,
        receipt_digest: str | None = None,
        checkout_path: Path | None = None,
    ) -> dict[str, Any] | None:
        """Verify the signed receipt behind an established implementation transition.

        Receipt freshness is a transition-time constraint. Once the managed task has
        durably reached ``IMPLEMENTATION_READY``, replaying its controller context
        must validate the immutable task binding and signature without depending on
        mutable opportunity metadata or the receipt's one-hour transport lifetime.
        """

        from .repo_probe import (
            REPRODUCED_VALIDATED,
            validate_checkout_paths,
            verify_probe_receipt,
        )

        connection = self._connection()
        try:
            task_row = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            opportunity_row = (
                connection.execute(
                    "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                    (task_row["opportunity_key"],),
                ).fetchone()
                if task_row is not None
                else None
            )
        finally:
            connection.close()
        if (
            task_row is None
            or opportunity_row is None
            or task_row["state"] != "IMPLEMENTATION_READY"
        ):
            return None
        if not task_row["thread_id"] or task_row["thread_id"] != thread_id:
            return None
        if not task_row["worktree_path"]:
            return None
        if Path(str(task_row["worktree_path"])).resolve() != Path(worktree_path).resolve():
            return None
        try:
            identity = canonical_opportunity_identity(
                opportunity_key=task_row["opportunity_key"],
                owner=opportunity_row["owner"],
                repo=opportunity_row["repo"],
                issue_number=opportunity_row["issue_number"],
                issue_url=opportunity_row["issue_url"],
            )
            provenance = json.loads(task_row["provenance_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(provenance, dict):
            return None
        if repo != f"{identity['owner']}/{identity['repo']}" or issue_url != identity["issueUrl"]:
            return None
        receipt = provenance.get("probeReceipt")
        if not isinstance(receipt, dict):
            return None
        stored_digest = str(provenance.get("probeReceiptDigest") or "")
        candidate_digest = str(receipt.get("receiptDigest") or "")
        if not stored_digest or candidate_digest != stored_digest:
            return None
        if receipt_digest is not None and receipt_digest != stored_digest:
            return None
        selected_base_sha = str(receipt.get("baseSha") or "")
        code_paths = [str(path) for path in (receipt.get("codePaths") or []) if str(path).strip()]
        head_sha = str(receipt.get("headSha") or "")
        commit_sha = str(receipt.get("commitSha") or "")
        result_digest = str(receipt.get("resultDigest") or "")
        if not all((selected_base_sha, code_paths, head_sha, commit_sha, result_digest)):
            return None
        if not verify_probe_receipt(
            receipt,
            repo=repo,
            base_sha=selected_base_sha,
            code_paths=code_paths,
            required_level=REPRODUCED_VALIDATED,
            issue_url=issue_url,
            task_id=task_id,
            thread_id=thread_id,
            thread_fingerprint_value=str(provenance.get("threadFingerprint") or "") or None,
            head_sha=head_sha,
            commit_sha=commit_sha,
            result_digest=result_digest,
            enforce_freshness=False,
        ):
            return None
        if checkout_path is not None:
            try:
                current_bindings = validate_checkout_paths(checkout_path, code_paths)
            except Exception:
                return None
            if current_bindings != receipt.get("codePathBindings"):
                return None
        return receipt

    def upsert_pr(
        self,
        *,
        pr_key: str,
        owner: str,
        repo: str,
        number: int,
        head_sha: str | None,
        pr_url: str,
        state: str,
        auto_created: bool,
        invitation_event_key: str | None = None,
        reservation_key: str | None = None,
        source_kind: str = "MANAGED",
        source: str = "managed",
        provenance: dict[str, Any] | None = None,
        observed_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        expected_key = f"{owner}/{repo}#{number}"
        if pr_key != expected_key:
            raise ValueError("PR key must be owner/repo#number")
        if state not in PR_STATES:
            raise ValueError(f"unsupported managed PR state: {state}")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM managed_prs WHERE pr_key=?", (pr_key,)
            ).fetchone()
            if reservation_key:
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
                if reservation["state"] == "FINALIZED" and existing is None:
                    raise PermissionError("finalized reservation has no recorded PR")
            if existing and existing["origin_kind"] == "EXISTING_OPEN_PR":
                auto_created = False
            auto_creation = (
                auto_created
                and state == "OPEN"
                and (existing is None or not existing["auto_created"])
            )
            if auto_creation and (existing is None or not existing["auto_created"]):
                gate = self._repo_pr_gate(
                    f"{owner}/{repo}",
                    invitation_event_key,
                    target_pr_key=pr_key,
                    exclude_reservation_key=reservation_key,
                )
                if not gate["allowed"]:
                    raise PermissionError("repository open unanswered automatic PR cap reached")
            connection.execute(
                """INSERT INTO managed_prs
                   (pr_key,owner,repo,number,head_sha,pr_url,state,auto_created,
                    maintainer_response,source_kind,source,provenance_json,observed_at,metadata_json,
                    origin_kind,origin_observation_json,origin_head_sha,origin_pr_url,latest_source)
                   VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(pr_key) DO UPDATE SET head_sha=excluded.head_sha,
                     pr_url=excluded.pr_url,state=excluded.state,
                     auto_created=CASE WHEN managed_prs.auto_created=1 THEN 1 ELSE excluded.auto_created END,
                     source_kind=managed_prs.source_kind,source=excluded.source,
                     provenance_json=excluded.provenance_json,observed_at=excluded.observed_at,
                     metadata_json=excluded.metadata_json,
                     origin_kind=managed_prs.origin_kind,
                     origin_observation_json=managed_prs.origin_observation_json,
                     origin_head_sha=managed_prs.origin_head_sha,
                     origin_pr_url=managed_prs.origin_pr_url,
                     latest_source=excluded.source""",
                (
                    pr_key,
                    owner,
                    repo,
                    number,
                    head_sha,
                    pr_url,
                    state,
                    int(auto_created),
                    source_kind,
                    source,
                    _json(provenance or {}),
                    _utc(observed_at),
                    _json(metadata or {}),
                    source_kind,
                    _json(provenance or {}),
                    head_sha if source_kind == "EXISTING_OPEN_PR" else None,
                    pr_url if source_kind == "EXISTING_OPEN_PR" else None,
                    source,
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_prs WHERE pr_key=?", (pr_key,)
            ).fetchone()
            connection.commit()
            return dict(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def transition_task_to_implementation(
        self,
        *,
        task_id: str,
        receipt_digest: str,
        receipt: dict[str, Any] | None = None,
        source: str = "controller",
    ) -> dict[str, Any]:
        """Make the reproduction-to-implementation transition explicit and auditable."""

        if not receipt_digest:
            raise ValueError("authenticated reproduction receipt is required")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None:
                raise ValueError("managed task is not bound")
            if row["state"] == "IMPLEMENTATION_READY":
                connection.commit()
                return dict(row)
            if row["state"] != "REPRODUCTION_REQUIRED":
                raise ValueError("task is not waiting for authenticated reproduction")
            provenance = json.loads(row["provenance_json"] or "{}")
            candidate_receipt = receipt or provenance.get("probeReceipt")
            if (
                not isinstance(candidate_receipt, dict)
                or candidate_receipt.get("receiptDigest") != receipt_digest
            ):
                raise PermissionError("complete signed reproduction receipt is required")
            opportunity = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (row["opportunity_key"],),
            ).fetchone()
            if opportunity is None:
                raise PermissionError("managed opportunity identity is required")
            expected = self.opportunity_identity(row["opportunity_key"])
            expected_paths = expected.get("codePaths") if expected else []
            expected_head = str(provenance.get("headSha") or "")
            expected_commit = str(provenance.get("commitSha") or "")
            expected_result = str(provenance.get("resultDigest") or "")
            if (
                not isinstance(expected_paths, list)
                or not expected
                or not expected.get("selectedBaseSha")
                or not expected_head
                or not expected_commit
                or not expected_result
            ):
                raise PermissionError("managed opportunity evidence is incomplete")
            from .repo_probe import REPRODUCED_VALIDATED, verify_probe_receipt

            if not verify_probe_receipt(
                candidate_receipt,
                repo=f"{expected['owner']}/{expected['repo']}",
                base_sha=expected["selectedBaseSha"],
                code_paths=[str(path) for path in expected_paths],
                required_level=REPRODUCED_VALIDATED,
                issue_url=expected["issueUrl"],
                task_id=task_id,
                thread_id=row["thread_id"],
                thread_fingerprint_value=provenance.get("threadFingerprint"),
                head_sha=expected_head,
                commit_sha=expected_commit,
                result_digest=expected_result,
            ):
                raise PermissionError("current-key reproduction receipt verification failed")
            now = _utc(None)
            provenance.update(
                {
                    "taskStage": "IMPLEMENTATION_READY",
                    "probeLevel": "REPRODUCED_VALIDATED",
                    "probeReceiptDigest": receipt_digest,
                    "probeReceipt": candidate_receipt,
                    "selectedBaseSha": candidate_receipt["baseSha"],
                    "codePaths": list(candidate_receipt["codePaths"]),
                    "headSha": candidate_receipt["headSha"],
                    "commitSha": candidate_receipt["commitSha"],
                    "resultDigest": candidate_receipt["resultDigest"],
                }
            )
            connection.execute(
                """UPDATE managed_tasks SET state=?,source=?,observed_at=?,provenance_json=?
                   WHERE task_id=?""",
                ("IMPLEMENTATION_READY", source, now, _json(provenance), task_id),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.record_event(
            event_type="REPRODUCTION_VALIDATED",
            idempotency_key=f"reproduction-transition:{task_id}:{receipt_digest}",
            task_id=task_id,
            state="IMPLEMENTATION_READY",
            source=source,
            provenance={"receiptDigest": receipt_digest},
            payload={"receiptDigest": receipt_digest},
        )
        return self.read_task(task_id) or {}

    def record_result(
        self,
        *,
        task_id: str,
        result_digest: str,
        worker_state: str,
        result_type: str | None = None,
        pr_key: str | None = None,
        head_sha: str | None = None,
        commit_sha: str | None = None,
        validation: dict[str, Any] | None = None,
        prior_head_sha: str | None = None,
        new_head_sha: str | None = None,
        waiting_external: bool = False,
        source: str = "managed",
        provenance: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        if result_type is not None and result_type not in RESULT_TYPES:
            raise ValueError(f"unknown result type: {result_type}")
        result_key = f"{task_id}|{pr_key or ''}|{head_sha or ''}|{result_digest}"
        # A patched lifecycle result is a managed result even when it is not
        # one of the five terminal outcome classifications.  Other worker
        # observations remain event-only status updates.
        if result_type is None and worker_state != "patched":
            if worker_state == "reproduction_required":
                state = "REPRODUCTION_REQUIRED"
            elif worker_state == "patched":
                state = "PORTFOLIO_READY"
            elif worker_state == "needs_human":
                state = "DECISION_REQUIRED"
            elif worker_state == "skipped" or waiting_external:
                state = "WAITING_EXTERNAL" if waiting_external else "SUPERSEDED"
            else:
                state = "SYSTEM_PROCESSING"
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing_task = connection.execute(
                    "SELECT state FROM managed_tasks WHERE task_id=?", (task_id,)
                ).fetchone()
                if (
                    existing_task
                    and existing_task["state"]
                    in {
                        "IMPLEMENTATION_READY",
                        "PORTFOLIO_READY",
                    }
                    and state in {"REPRODUCTION_REQUIRED", "SYSTEM_PROCESSING"}
                ):
                    state = existing_task["state"]
                connection.execute(
                    "UPDATE managed_tasks SET state=? WHERE task_id=?", (state, task_id)
                )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
            event = self.record_event(
                event_type="PATCHED" if worker_state == "patched" else "TASK_STATUS_OBSERVED",
                idempotency_key=f"worker-status:{result_key}",
                task_id=task_id,
                pr_key=pr_key,
                state=state,
                source=source,
                provenance=provenance,
                observed_at=observed_at,
                payload={"worker_state": worker_state},
            )
            return {
                "resultKey": result_key,
                "worker_state": worker_state,
                "result_type": None,
                "state": state,
                "advanced": False,
                "created": event["created"],
            }
        persisted_validation = dict(validation or {})
        if persisted_validation.get("passed") is True:
            persisted_validation.setdefault(
                "certificate",
                validation_certificate(
                    persisted_validation,
                    result_key=result_key,
                    result_digest=result_digest,
                    source_event_key=str((provenance or {}).get("eventKey") or result_key),
                    commit_sha=commit_sha,
                    head_sha=head_sha,
                    observed_at=observed_at,
                ),
            )
        validation_ok = _valid_validation(persisted_validation)
        patched = worker_state.casefold() == "patched"
        has_new_head = bool(new_head_sha) and new_head_sha != prior_head_sha
        patch_advanced = patched and bool(commit_sha) and validation_ok and has_new_head
        if worker_state == "needs_human":
            state = "DECISION_REQUIRED"
        elif worker_state == "skipped":
            state = "WAITING_EXTERNAL" if waiting_external else "SUPERSEDED"
        elif patch_advanced:
            state = "PORTFOLIO_READY"
        elif waiting_external:
            state = "WAITING_EXTERNAL"
        else:
            state = "SYSTEM_PROCESSING"
        event_type = "PATCHED" if patch_advanced else "TASK_RESULT_RECORDED"
        if patched and not patch_advanced:
            event_type = "PATCH_REJECTED_MISSING_EVIDENCE"
        connection = self._connection()
        superseded: list[dict[str, Any]] = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM managed_results WHERE result_key=?", (result_key,)
            ).fetchone()
            if existing:
                connection.commit()
                self.record_event(
                    event_type=event_type,
                    idempotency_key=f"result:{result_key}",
                    task_id=task_id,
                    pr_key=pr_key,
                    state=state,
                    source=source,
                    provenance=provenance,
                    observed_at=observed_at,
                    payload={"worker_state": worker_state, "replayed": True},
                )
                return dict(existing) | {
                    "created": False,
                    "state": state,
                    "advanced": patch_advanced,
                }
            current_rows = connection.execute(
                """SELECT result_key,result_type,result_digest FROM managed_results
                   WHERE task_id=? AND pr_key IS ? AND head_sha IS ? AND is_current=1""",
                (task_id, pr_key, head_sha),
            ).fetchall()
            superseded = [dict(item) for item in current_rows if item["result_key"] != result_key]
            for old in superseded:
                connection.execute(
                    """UPDATE managed_results SET is_current=0,superseded_by=?
                       WHERE result_key=?""",
                    (result_key, old["result_key"]),
                )
            connection.execute(
                """INSERT INTO managed_results
                   (result_key,task_id,pr_key,head_sha,result_digest,result_type,worker_state,
                    commit_sha,validation_json,source,provenance_json,observed_at,is_current,superseded_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                (
                    result_key,
                    task_id,
                    pr_key,
                    head_sha,
                    result_digest,
                    result_type,
                    worker_state,
                    commit_sha,
                    _json(persisted_validation),
                    source,
                    _json(provenance or {}),
                    _utc(observed_at),
                    1,
                ),
            )
            existing_task = connection.execute(
                "SELECT state FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if (
                existing_task
                and existing_task["state"]
                in {
                    "IMPLEMENTATION_READY",
                    "PORTFOLIO_READY",
                }
                and state in {"REPRODUCTION_REQUIRED", "SYSTEM_PROCESSING"}
            ):
                state = existing_task["state"]
            connection.execute("UPDATE managed_tasks SET state=? WHERE task_id=?", (state, task_id))
            row = connection.execute(
                "SELECT * FROM managed_results WHERE result_key=?", (result_key,)
            ).fetchone()
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.record_event(
            event_type=event_type,
            idempotency_key=f"result:{result_key}",
            task_id=task_id,
            pr_key=pr_key,
            state=state,
            source=source,
            provenance=provenance,
            observed_at=observed_at,
            payload={
                "worker_state": worker_state,
                "commit_sha": commit_sha,
                "new_head_sha": new_head_sha,
                "advanced": patch_advanced,
            },
        )
        for old in superseded:
            self.record_event(
                event_type="RESULT_CLASSIFICATION_SUPERSEDED",
                idempotency_key=f"result-superseded:{old['result_key']}:{result_key}",
                task_id=task_id,
                pr_key=pr_key,
                state="SUPERSEDED",
                source=source,
                provenance=provenance,
                observed_at=observed_at,
                payload={"oldResultKey": old["result_key"], "newResultKey": result_key},
            )
        return dict(row) | {"created": True, "state": state, "advanced": patch_advanced}

    def record_maintainer_event(
        self,
        *,
        event_key: str,
        pr_key: str,
        event_type: str,
        actor_login: str | None,
        actor_type: str | None,
        author_association: str | None,
        opportunity_key: str | None = None,
        verified_permission: bool = False,
        source: str = "github",
        payload: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        maintainer = is_maintainer_actor(
            actor_type=actor_type,
            actor_login=actor_login,
            author_association=author_association,
            verified_permission=verified_permission,
        )
        event_payload = dict(payload or {})
        event_payload.setdefault("targetPrKey", pr_key)
        owner_repo = pr_key.split("#", 1)[0]
        if event_payload.get("targetRepo") not in {None, owner_repo}:
            raise ValueError("maintainer event repository binding mismatch")
        event_payload["targetRepo"] = owner_repo
        if opportunity_key is not None:
            event_payload["opportunityKey"] = opportunity_key
        if event_type.upper() in {"INVITATION", "ASSIGNMENT"} and not (
            event_payload.get("targetPrKey") == pr_key
        ):
            raise ValueError("invitation or assignment requires the current PR binding")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM managed_maintainer_events WHERE event_key=?", (event_key,)
            ).fetchone()
            if existing:
                if existing["pr_key"] != pr_key:
                    raise ValueError("maintainer event idempotency key is bound to another PR")
                connection.commit()
                return dict(existing) | {"created": False}
            connection.execute(
                """INSERT INTO managed_maintainer_events
                   (event_key,pr_key,event_type,actor_login,actor_type,author_association,
                    is_maintainer,observed_at,source,payload_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_key,
                    pr_key,
                    event_type,
                    actor_login,
                    actor_type,
                    author_association,
                    int(maintainer),
                    _utc(observed_at),
                    source,
                    _json(event_payload),
                ),
            )
            if maintainer:
                connection.execute(
                    "UPDATE managed_prs SET maintainer_response=1 WHERE pr_key=?", (pr_key,)
                )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        event = self.record_event(
            event_type="MAINTAINER_EVENT",
            idempotency_key=f"maintainer:{event_key}",
            pr_key=pr_key,
            state="MAINTAINER_RESPONSE" if maintainer else "EXTERNAL_EVENT",
            source=source,
            provenance={"actor_type": actor_type, "author_association": author_association},
            observed_at=observed_at,
            payload={"event_key": event_key, "is_maintainer": maintainer},
        )
        return {"eventKey": event_key, "isMaintainer": maintainer, "created": True, "event": event}

    def record_ci_run(
        self,
        *,
        ci_key: str,
        pr_key: str,
        head_sha: str,
        status: str,
        checks: dict[str, Any] | None = None,
        source: str = "github",
        provenance: dict[str, Any] | None = None,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        normalized_status = status.upper()
        if normalized_status not in {
            "QUEUED",
            "RUNNING",
            "PASSED",
            "FAILED",
            "CANCELLED",
            "UNKNOWN",
        }:
            raise ValueError("invalid CI status")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO managed_ci_runs
                   (ci_key,pr_key,head_sha,status,checks_json,observed_at,source,provenance_json)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(ci_key) DO UPDATE SET status=excluded.status,
                     checks_json=excluded.checks_json,observed_at=excluded.observed_at,
                     source=excluded.source,provenance_json=excluded.provenance_json""",
                (
                    ci_key,
                    pr_key,
                    head_sha,
                    normalized_status,
                    _json(checks or {}),
                    _utc(observed_at),
                    source,
                    _json(provenance or {}),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_ci_runs WHERE ci_key=?", (ci_key,)
            ).fetchone()
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self._refresh_result_certificate(
            pr_key=pr_key,
            head_sha=head_sha,
            ci_status=normalized_status,
            observed_at=observed_at,
        )
        self.record_event(
            event_type="CI_RESULT_OBSERVED",
            idempotency_key=f"ci:{ci_key}:{head_sha}:{normalized_status}:{_digest(checks or {})}",
            pr_key=pr_key,
            state=f"CI_{normalized_status}",
            source=source,
            provenance=provenance,
            observed_at=observed_at,
            payload={"ciKey": ci_key, "headSha": head_sha, "checks": checks or {}},
        )
        return dict(row)

    def queue_reproduction_probe(
        self,
        *,
        task_id: str,
        opportunity_key: str,
        repo: str,
        issue_url: str,
        default_branch: str,
        selected_base_sha: str,
        code_paths: list[str],
        profile_id: str | None,
        checkout_path: str | None,
        thread_id: str | None = None,
        head_sha: str,
        commit_sha: str,
        result_digest: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Persist a controller-owned reproduction request for the slow worker."""

        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                task_id,
                opportunity_key,
                repo,
                issue_url,
                default_branch,
                selected_base_sha,
                head_sha,
                commit_sha,
                result_digest,
                idempotency_key,
            )
        ):
            raise ValueError("reproduction probe identity is incomplete")
        opportunity_key = canonical_opportunity_key(opportunity_key)
        normalized_paths = sorted({str(path) for path in code_paths if str(path).strip()})
        if not normalized_paths or any(
            not path or path.startswith(("/", "\\")) or ".." in Path(path).parts
            for path in normalized_paths
        ):
            raise ValueError("reproduction probe code paths are invalid")
        now = _utc(None)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            task_identity = connection.execute(
                "SELECT opportunity_key,thread_id FROM managed_tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if task_identity is None or task_identity["opportunity_key"] != opportunity_key:
                raise ValueError("reproduction probe task/opportunity binding is invalid")
            opportunity = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (opportunity_key,),
            ).fetchone()
            if opportunity is None:
                raise ValueError("reproduction probe opportunity is missing")
            try:
                opportunity_identity = canonical_opportunity_identity(
                    opportunity_key=opportunity_key,
                    owner=opportunity["owner"],
                    repo=opportunity["repo"],
                    issue_number=opportunity["issue_number"],
                    issue_url=opportunity["issue_url"],
                )
            except (TypeError, ValueError) as exc:
                raise ValueError("reproduction probe opportunity identity is invalid") from exc
            try:
                opportunity_metadata = json.loads(opportunity["metadata_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                opportunity_metadata = {}
            try:
                opportunity_provenance = json.loads(opportunity["provenance_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                opportunity_provenance = {}
            expected_evidence = opportunity_metadata.get("preTaskEvidence")
            if not isinstance(expected_evidence, dict):
                expected_evidence = {}
            expected_base = str(
                opportunity_metadata.get("selectedBaseSha")
                or opportunity_metadata.get("baseSha")
                or expected_evidence.get("selectedBaseSha")
                or expected_evidence.get("baseSha")
                or opportunity_provenance.get("selectedBaseSha")
                or opportunity_provenance.get("baseSha")
                or ""
            )
            expected_paths = (
                opportunity_metadata.get("codePaths")
                or opportunity_provenance.get("codePaths")
                or []
            )
            if (
                repo != f"{opportunity_identity['owner']}/{opportunity_identity['repo']}"
                or issue_url != opportunity_identity["issueUrl"]
                or selected_base_sha != expected_base
                or sorted(normalized_paths) != sorted(str(path) for path in expected_paths)
            ):
                raise ValueError("reproduction probe evidence is not bound to its opportunity")
            task_row = connection.execute(
                "SELECT thread_id FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            effective_thread_id = thread_id or (task_row["thread_id"] if task_row else None)
            connection.execute(
                """INSERT INTO managed_reproduction_probes
                   (probe_key,task_id,opportunity_key,repo,issue_url,thread_id,default_branch,
                    selected_base_sha,code_paths_json,profile_id,checkout_path,head_sha,
                    commit_sha,result_digest,state,receipt_json,error,idempotency_key,created_at,updated_at,
                    worker_nonce,attempt_id,started_at,lease_expires_at,attempt_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'PENDING','{}',NULL,?,?,?,NULL,NULL,NULL,NULL,0)
                   ON CONFLICT(idempotency_key) DO UPDATE SET updated_at=excluded.updated_at""",
                (
                    stable_fingerprint(idempotency_key),
                    task_id,
                    opportunity_key,
                    repo,
                    issue_url,
                    effective_thread_id,
                    default_branch,
                    selected_base_sha,
                    _json(normalized_paths),
                    profile_id,
                    checkout_path,
                    head_sha,
                    commit_sha,
                    result_digest,
                    idempotency_key,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_reproduction_probes WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.record_event(
            event_type="REPRODUCTION_PROBE_QUEUED",
            idempotency_key=f"probe-queued:{idempotency_key}",
            opportunity_key=opportunity_key,
            task_id=task_id,
            state="REPRODUCTION_REQUIRED",
            source="controller",
            provenance={"probeKey": row["probe_key"]},
            payload={"profileId": profile_id, "selectedBaseSha": selected_base_sha},
        )
        return dict(row)

    def claim_reproduction_probe(
        self,
        *,
        worker_nonce: str,
        lease_seconds: int = REPRODUCTION_PROBE_LEASE_SECONDS,
    ) -> dict[str, Any] | None:
        """Claim one probe with a durable, single-attempt lease."""

        if not worker_nonce:
            raise ValueError("worker nonce is required")
        now = datetime.now(UTC)
        now_text = iso_z(now)
        expires = iso_z(now + timedelta(seconds=max(1, lease_seconds)))
        attempt_id = secrets.token_urlsafe(18)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            exhausted = connection.execute(
                """SELECT * FROM managed_reproduction_probes
                   WHERE state='RUNNING' AND attempt_count >= ?
                   ORDER BY probe_key""",
                (REPRODUCTION_PROBE_MAX_ATTEMPTS,),
            ).fetchall()
            for stranded in exhausted:
                try:
                    lease_status = (
                        "expired"
                        if _parse_rfc3339_utc(stranded["lease_expires_at"]) <= now
                        else "future"
                    )
                except ValueError:
                    lease_status = "malformed"
                original_error = stranded["error"]
                exhaustion_key = (
                    f"reproduction-retry-exhausted:{stranded['probe_key']}:{stranded['attempt_id'] or 'none'}:"
                    f"{stranded['attempt_count']}"
                )
                connection.execute(
                    """UPDATE managed_reproduction_probes
                       SET state='WAITING_EXTERNAL',worker_nonce=NULL,attempt_id=NULL,
                           started_at=NULL,lease_expires_at=NULL,error=COALESCE(error,?),updated_at=?
                       WHERE probe_key=? AND state='RUNNING' AND attempt_count >= ?""",
                    (
                        REPRODUCTION_RETRY_EXHAUSTED_ERROR,
                        now_text,
                        stranded["probe_key"],
                        REPRODUCTION_PROBE_MAX_ATTEMPTS,
                    ),
                )
                connection.execute(
                    """INSERT OR IGNORE INTO managed_lifecycle_events
                       (opportunity_key,task_id,pr_key,event_type,state,idempotency_key,source,
                        idempotency_fingerprint,provenance_json,observed_at,payload_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        stranded["opportunity_key"],
                        stranded["task_id"],
                        None,
                        "REPRODUCTION_RETRY_EXHAUSTED",
                        "WAITING_EXTERNAL",
                        exhaustion_key,
                        "managed-reproduction-worker",
                        stable_fingerprint(exhaustion_key),
                        _json(
                            {
                                "probeKey": stranded["probe_key"],
                                "attemptCount": stranded["attempt_count"],
                            }
                        ),
                        now_text,
                        _json(
                            {
                                "leaseStatus": lease_status,
                                "originalError": original_error,
                                "attemptId": stranded["attempt_id"],
                            }
                        ),
                    ),
                )
                if stranded["attempt_id"]:
                    _append_probe_attempt_event(
                        connection,
                        attempt_id=stranded["attempt_id"],
                        probe_key=stranded["probe_key"],
                        event="RETRY_EXHAUSTED",
                        observed_at=now_text,
                        payload={"leaseStatus": lease_status, "externalEffectCount": 0},
                    )
            candidates = connection.execute(
                """SELECT * FROM managed_reproduction_probes
                   WHERE state IN ('PENDING','WAITING_EXTERNAL','RUNNING')
                     AND attempt_count < ?
                   ORDER BY updated_at,probe_key""",
                (REPRODUCTION_PROBE_MAX_ATTEMPTS,),
            ).fetchall()
            row = None
            malformed_lease = False
            for candidate in candidates:
                if candidate["state"] in {"PENDING", "WAITING_EXTERNAL"}:
                    row = candidate
                    break
                try:
                    expired = _parse_rfc3339_utc(candidate["lease_expires_at"]) <= now
                except ValueError:
                    expired = True
                    malformed_lease = True
                if expired:
                    row = candidate
                    break
            if row is None:
                connection.commit()
                return None
            prior_attempt_id = row["attempt_id"]
            connection.execute(
                """UPDATE managed_reproduction_probes
                   SET state='RUNNING',worker_nonce=?,attempt_id=?,started_at=?,
                       lease_expires_at=?,attempt_count=attempt_count+1,updated_at=?,error=?
                   WHERE probe_key=?""",
                (
                    worker_nonce,
                    attempt_id,
                    now_text,
                    expires,
                    now_text,
                    "MALFORMED_LEASE_RECOVERED" if malformed_lease else None,
                    row["probe_key"],
                ),
            )
            if malformed_lease:
                recovery_key = (
                    f"lease-recovered:{row['probe_key']}:{prior_attempt_id or 'none'}:{attempt_id}"
                )
                fingerprint = stable_fingerprint(recovery_key)
                connection.execute(
                    """INSERT OR IGNORE INTO managed_lifecycle_events
                       (opportunity_key,task_id,pr_key,event_type,state,idempotency_key,source,
                        idempotency_fingerprint,provenance_json,observed_at,payload_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        row["opportunity_key"],
                        row["task_id"],
                        None,
                        "MALFORMED_LEASE_RECOVERED",
                        "RUNNING",
                        recovery_key,
                        "managed-reproduction-worker",
                        fingerprint,
                        _json({"priorAttemptId": prior_attempt_id}),
                        now_text,
                        _json({"probeKey": row["probe_key"], "newAttemptId": attempt_id}),
                    ),
                )
            if prior_attempt_id:
                _append_probe_attempt_event(
                    connection,
                    attempt_id=prior_attempt_id,
                    probe_key=row["probe_key"],
                    event="LEASE_EXPIRED_RECOVERED",
                    observed_at=now_text,
                    payload={"newAttemptId": attempt_id},
                )
            _append_probe_attempt_event(
                connection,
                attempt_id=attempt_id,
                probe_key=row["probe_key"],
                event="ATTEMPT_STARTED",
                observed_at=now_text,
                payload={"workerNonce": worker_nonce, "externalEffectCount": 0},
            )
            claimed = connection.execute(
                "SELECT * FROM managed_reproduction_probes WHERE probe_key=?",
                (row["probe_key"],),
            ).fetchone()
            connection.commit()
            return dict(claimed) if claimed else None
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def fail_reproduction_probe(
        self, *, probe_key: str, attempt_id: str, error: str
    ) -> dict[str, Any]:
        """Persist a failure only for the currently owning attempt."""

        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """UPDATE managed_reproduction_probes
                   SET state='WAITING_EXTERNAL',error=?,receipt_json='{}',
                       worker_nonce=NULL,attempt_id=NULL,started_at=NULL,lease_expires_at=NULL,updated_at=?
                   WHERE probe_key=? AND state='RUNNING' AND attempt_id=?""",
                (error[:240], _utc(None), probe_key, attempt_id),
            ).rowcount
            if not changed:
                connection.rollback()
                raise RuntimeError("stale reproduction probe attempt")
            _append_probe_attempt_event(
                connection,
                attempt_id=attempt_id,
                probe_key=probe_key,
                event="ATTEMPT_FAILED",
                observed_at=_utc(None),
                payload={"externalEffectCount": 0, "error": error[:240]},
            )
            row = connection.execute(
                "SELECT * FROM managed_reproduction_probes WHERE probe_key=?", (probe_key,)
            ).fetchone()
            connection.commit()
            return dict(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def complete_reproduction_probe(
        self, *, probe_key: str, attempt_id: str, receipt: dict[str, Any]
    ) -> dict[str, Any]:
        """Atomically record a validated receipt and advance its managed task."""

        from .repo_probe import REPRODUCED_VALIDATED, verify_probe_receipt

        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM managed_reproduction_probes WHERE probe_key=?", (probe_key,)
            ).fetchone()
            if row is None:
                raise ValueError("reproduction probe is unknown")
            if row["state"] == "SUCCEEDED":
                if row["receipt_json"] == _json(receipt):
                    connection.commit()
                    return dict(row)
                raise RuntimeError("reproduction probe already completed with another receipt")
            if row["state"] != "RUNNING" or row["attempt_id"] != attempt_id:
                raise RuntimeError("stale reproduction probe attempt")
            paths = json.loads(row["code_paths_json"])
            if not verify_probe_receipt(
                receipt,
                repo=row["repo"],
                base_sha=row["selected_base_sha"],
                code_paths=paths,
                required_level=REPRODUCED_VALIDATED,
                issue_url=row["issue_url"],
                task_id=row["task_id"],
                thread_id=row["thread_id"],
                attempt_id=attempt_id,
                head_sha=row["head_sha"],
                commit_sha=row["commit_sha"],
                result_digest=row["result_digest"],
            ):
                raise PermissionError("probe receipt is not current-key authenticated")
            task = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (row["task_id"],)
            ).fetchone()
            if task is None:
                raise ValueError("managed task is not bound")
            opportunity = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (row["opportunity_key"],),
            ).fetchone()
            if opportunity is None:
                raise PermissionError("managed opportunity identity is required")
            try:
                expected_identity = canonical_opportunity_identity(
                    opportunity_key=row["opportunity_key"],
                    owner=opportunity["owner"],
                    repo=opportunity["repo"],
                    issue_number=opportunity["issue_number"],
                    issue_url=opportunity["issue_url"],
                )
            except (TypeError, ValueError) as exc:
                raise PermissionError("managed opportunity identity is invalid") from exc
            if (
                row["repo"] != f"{expected_identity['owner']}/{expected_identity['repo']}"
                or row["issue_url"] != expected_identity["issueUrl"]
            ):
                raise PermissionError("probe identity does not match its opportunity")
            provenance = json.loads(task["provenance_json"] or "{}")
            provenance.update(
                {
                    "taskStage": "IMPLEMENTATION_READY",
                    "probeLevel": REPRODUCED_VALIDATED,
                    "probeReceiptDigest": receipt["receiptDigest"],
                    "probeReceipt": receipt,
                    "selectedBaseSha": receipt["baseSha"],
                    "codePaths": list(receipt["codePaths"]),
                    "headSha": receipt["headSha"],
                    "commitSha": receipt["commitSha"],
                    "resultDigest": receipt["resultDigest"],
                }
            )
            connection.execute(
                """UPDATE managed_tasks SET state='IMPLEMENTATION_READY',source=?,observed_at=?,provenance_json=?
                   WHERE task_id=? AND state IN ('REPRODUCTION_REQUIRED','IMPLEMENTATION_READY')""",
                ("slow-reproduction-worker", _utc(None), _json(provenance), row["task_id"]),
            )
            connection.execute(
                """UPDATE managed_reproduction_probes
                   SET state='SUCCEEDED',receipt_json=?,error=NULL,worker_nonce=NULL,attempt_id=NULL,
                       started_at=NULL,lease_expires_at=NULL,updated_at=?
                   WHERE probe_key=? AND state='RUNNING' AND attempt_id=?""",
                (_json(receipt), _utc(None), probe_key, attempt_id),
            )
            _append_probe_attempt_event(
                connection,
                attempt_id=attempt_id,
                probe_key=probe_key,
                event="ATTEMPT_FINISHED",
                observed_at=_utc(None),
                payload={"externalEffectCount": 0, "cleanup": "completed"},
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.record_event(
            event_type="REPRODUCTION_VALIDATED",
            idempotency_key=f"reproduction-probe:{probe_key}:{receipt['receiptDigest']}",
            task_id=row["task_id"],
            state="IMPLEMENTATION_READY",
            source="slow-reproduction-worker",
            provenance={"receiptDigest": receipt["receiptDigest"]},
        )
        return self.read_task(row["task_id"]) or {}

    def run_pending_reproduction_probes(
        self, *, limit: int = 10, worker_nonce: str | None = None
    ) -> dict[str, Any]:
        """Run queued probes through durable claim/complete/fail transitions."""

        from .repo_probe import run_reproduction_probe

        worker_nonce = worker_nonce or secrets.token_urlsafe(18)
        processed: list[dict[str, Any]] = []
        for _ in range(max(1, min(limit, 100))):
            row = self.claim_reproduction_probe(worker_nonce=worker_nonce)
            if row is None:
                break
            probe_key = row["probe_key"]
            attempt_id = row["attempt_id"]
            if not row["profile_id"] or not row["checkout_path"]:
                error = (
                    "TRUSTED_PROBE_PROFILE_UNAVAILABLE"
                    if not row["profile_id"]
                    else "CHECKOUT_UNAVAILABLE"
                )
                finished = self.fail_reproduction_probe(
                    probe_key=probe_key, attempt_id=attempt_id, error=error
                )
                processed.append(
                    {"probeKey": probe_key, "state": finished["state"], "reason": error}
                )
                continue
            receipt: dict[str, Any] = {}
            try:
                receipt = run_reproduction_probe(
                    checkout_path=Path(row["checkout_path"]),
                    repo=row["repo"],
                    default_branch=row["default_branch"],
                    selected_base_sha=row["selected_base_sha"],
                    code_paths=json.loads(row["code_paths_json"]),
                    profile_id=row["profile_id"],
                    issue_url=row["issue_url"],
                    task_id=row["task_id"],
                    head_sha=row["head_sha"],
                    commit_sha=row["commit_sha"],
                    result_digest=row["result_digest"],
                    thread_id=row["thread_id"],
                    attempt_id=attempt_id,
                )
                finished = self.complete_reproduction_probe(
                    probe_key=probe_key, attempt_id=attempt_id, receipt=receipt
                )
                processed.append({"probeKey": probe_key, "state": "SUCCEEDED", "error": None})
            except Exception as exc:
                error = f"{type(exc).__name__}:{str(exc)[:240]}"
                try:
                    finished = self.fail_reproduction_probe(
                        probe_key=probe_key, attempt_id=attempt_id, error=error
                    )
                    processed.append(
                        {"probeKey": probe_key, "state": finished["state"], "error": error}
                    )
                except RuntimeError:
                    processed.append(
                        {"probeKey": probe_key, "state": "STALE_ATTEMPT", "error": error}
                    )
        return {
            "ok": True,
            "processed": processed,
            "count": len(processed),
            "workerNonce": worker_nonce,
        }

    def _refresh_result_certificate(
        self,
        *,
        pr_key: str,
        head_sha: str,
        ci_status: str,
        observed_at: str | None = None,
    ) -> dict[str, Any] | None:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                """SELECT * FROM managed_results WHERE pr_key=? AND head_sha=? AND is_current=1
                   ORDER BY observed_at DESC,result_key DESC LIMIT 1""",
                (pr_key, head_sha),
            ).fetchone()
            if result is None:
                connection.commit()
                return None
            validation = json_payload(result["validation_json"])
            if validation.get("passed") is not True:
                connection.commit()
                return dict(result)
            certificate = validation_certificate(
                validation,
                result_key=result["result_key"],
                result_digest=result["result_digest"],
                commit_sha=result["commit_sha"],
                head_sha=head_sha,
                ci_status=ci_status,
                observed_at=observed_at,
            )
            validation["certificate"] = certificate
            connection.execute(
                "UPDATE managed_results SET validation_json=? WHERE result_key=?",
                (_json(validation), result["result_key"]),
            )
            if (
                result["worker_state"].casefold() == "patched"
                and result["commit_sha"]
                and _valid_validation(validation)
                and ci_status == "PASSED"
            ):
                connection.execute(
                    "UPDATE managed_tasks SET state='PORTFOLIO_READY' WHERE task_id=?",
                    (result["task_id"],),
                )
            updated = connection.execute(
                "SELECT * FROM managed_results WHERE result_key=?", (result["result_key"],)
            ).fetchone()
            connection.commit()
            return dict(updated)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def current_result_for_pr(self, pr_key: str) -> dict[str, Any] | None:
        connection = self._connection()
        try:
            row = connection.execute(
                """SELECT * FROM managed_results
                   WHERE pr_key=? AND is_current=1
                   ORDER BY observed_at DESC,result_key DESC LIMIT 1""",
                (pr_key,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def _invitation_exemption(
        self,
        event_key: str | None,
        *,
        target_repo: str,
        target_pr_key: str | None = None,
        target_opportunity_key: str | None = None,
    ) -> bool:
        if not event_key:
            return False
        connection = self._connection()
        try:
            row = connection.execute(
                """SELECT is_maintainer,pr_key,payload_json FROM managed_maintainer_events
                   WHERE event_key=? AND event_type IN ('INVITATION','ASSIGNMENT')""",
                (event_key,),
            ).fetchone()
            if not row or not row["is_maintainer"]:
                return False
            if target_pr_key is None and target_opportunity_key is None:
                return False
            payload = json_payload(row["payload_json"])
            if payload.get("targetRepo") != target_repo:
                return False
            if target_pr_key is not None and payload.get("targetPrKey") != target_pr_key:
                return False
            if (
                target_opportunity_key is not None
                and payload.get("opportunityKey") != target_opportunity_key
            ):
                return False
            return True
        finally:
            connection.close()

    def open_unanswered_auto_pr_count(self, repo: str) -> int:
        connection = self._connection()
        try:
            return int(
                connection.execute(
                    """SELECT COUNT(*) FROM managed_prs
                       WHERE (repo=? OR owner || '/' || repo=?) AND state='OPEN'
                         AND auto_created=1 AND maintainer_response=0""",
                    (repo, repo),
                ).fetchone()[0]
            )
        finally:
            connection.close()

    def _active_publication_reservation_count(
        self, connection: sqlite3.Connection, repo: str, *, exclude_key: str | None = None, now: str
    ) -> int:
        return int(
            connection.execute(
                """SELECT COUNT(*) FROM managed_publication_reservations
                   WHERE repo=? AND state='ACTIVE' AND lease_until>?
                     AND (? IS NULL OR reservation_key<>?)""",
                (repo, now, exclude_key, exclude_key),
            ).fetchone()[0]
        )

    def reserve_publication_slot(
        self,
        *,
        reservation_key: str,
        request_id: str,
        repo: str,
        head_ref: str | None = None,
        head_sha: str | None = None,
        idempotency_key: str,
        opportunity_key: str | None = None,
        pr_key: str | None = None,
        invitation_event_key: str | None = None,
        lease_seconds: int = 900,
        now: str | None = None,
    ) -> dict[str, Any]:
        current = _parse_time(_utc(now))
        observed = _utc(now)
        lease_until = (
            (current + timedelta(seconds=max(30, min(lease_seconds, 3600))))
            .isoformat()
            .replace("+00:00", "Z")
        )
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if opportunity_key:
                require_quarantine_clear(
                    connection,
                    opportunity_key=opportunity_key,
                    operation="managed publication reservation",
                )
            else:
                quarantined = connection.execute(
                    """SELECT opportunity_key FROM task_quarantines
                       WHERE opportunity_key LIKE ? AND status='ACTIVE'
                       ORDER BY quarantine_id DESC LIMIT 1""",
                    (f"{repo}#%",),
                ).fetchone()
                if quarantined is not None:
                    raise PermissionError(
                        "managed publication reservation blocked by active task quarantine: "
                        f"{quarantined['opportunity_key']}"
                    )
            existing = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE request_id=? OR reservation_key=?",
                (request_id, reservation_key),
            ).fetchone()
            if existing:
                if head_ref and existing["head_ref"] and existing["head_ref"] != head_ref:
                    raise ValueError("publication reservation head ref binding mismatch")
                if head_sha and existing["head_sha"] and existing["head_sha"] != head_sha:
                    raise ValueError("publication reservation head SHA binding mismatch")
                if existing["state"] == "ACTIVE" and _parse_time(existing["lease_until"]) > current:
                    connection.commit()
                    return dict(existing) | {"allowed": True, "replayed": True}
                if existing["state"] == "FINALIZED":
                    connection.commit()
                    return dict(existing) | {"allowed": True, "replayed": True}
                if existing["state"] in {"EXPIRED", "CHECK_ABSENCE_REQUIRED"}:
                    connection.execute(
                        "UPDATE managed_publication_reservations SET state='CHECK_ABSENCE_REQUIRED',updated_at=? WHERE reservation_key=?",
                        (observed, existing["reservation_key"]),
                    )
                    connection.commit()
                    return dict(existing) | {
                        "state": "CHECK_ABSENCE_REQUIRED",
                        "allowed": False,
                        "absenceRequired": True,
                        "reconcileRequired": True,
                        "reason": "WAITING_EXTERNAL",
                    }
                if existing["state"] == "WAITING_EXTERNAL":
                    connection.commit()
                    return dict(existing) | {
                        "allowed": False,
                        "absenceRequired": True,
                        "reason": "WAITING_EXTERNAL",
                    }
                if existing["state"] == "RELEASED":
                    connection.execute(
                        "UPDATE managed_publication_reservations SET state='ACTIVE',lease_until=?,updated_at=? WHERE reservation_key=?",
                        (lease_until, observed, existing["reservation_key"]),
                    )
                    connection.commit()
                    return dict(existing) | {
                        "state": "ACTIVE",
                        "lease_until": lease_until,
                        "allowed": True,
                        "replayed": True,
                    }
            active_prs = int(
                connection.execute(
                    """SELECT COUNT(*) FROM managed_prs
                       WHERE (repo=? OR owner || '/' || repo=?) AND state='OPEN'
                         AND auto_created=1 AND maintainer_response=0""",
                    (repo, repo),
                ).fetchone()[0]
            )
            active_reservations = self._active_publication_reservation_count(
                connection, repo, now=observed
            )
            invitation = self._invitation_exemption(
                invitation_event_key,
                target_repo=repo,
                target_pr_key=pr_key,
                target_opportunity_key=opportunity_key,
            )
            allowed = invitation or active_prs + active_reservations < OPEN_PR_CAP
            state = "ACTIVE" if allowed else "BLOCKED"
            connection.execute(
                """INSERT INTO managed_publication_reservations
                   (reservation_key,request_id,repo,head_ref,opportunity_key,pr_key,head_sha,invitation_event_key,
                    state,idempotency_key,lease_until,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    reservation_key,
                    request_id,
                    repo,
                    head_ref,
                    opportunity_key,
                    pr_key,
                    head_sha,
                    invitation_event_key,
                    state,
                    idempotency_key,
                    lease_until,
                    observed,
                    observed,
                ),
            )
            connection.commit()
            return {
                "reservationKey": reservation_key,
                "requestId": request_id,
                "repo": repo,
                "state": state,
                "allowed": allowed,
                "reason": "VERIFIED_MAINTAINER_INVITATION"
                if invitation
                else ("PUBLICATION_CAPACITY" if allowed else "BLOCKED_PRE_TASK"),
                "activePrs": active_prs,
                "activeReservations": active_reservations,
                "limit": OPEN_PR_CAP,
                "leaseUntil": lease_until,
            }
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def finalize_publication_reservation(
        self,
        *,
        reservation_key: str,
        pr_key: str,
        head_sha: str,
        now: str | None = None,
        connection: sqlite3.Connection | None = None,
        receipt_observation: bool = False,
    ) -> dict[str, Any]:
        observed = _utc(now)
        owns_connection = connection is None
        connection = connection or self._connection()
        try:
            if owns_connection:
                connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            if row is None:
                raise ValueError("publication reservation is missing")
            if not receipt_observation:
                require_quarantine_clear(
                    connection,
                    opportunity_key=str(row["opportunity_key"] or pr_key),
                    operation="managed publication finalize",
                )
            if pr_key.split("#", 1)[0] != row["repo"]:
                raise ValueError("publication receipt repository does not match reservation")
            if row["state"] == "FINALIZED":
                if owns_connection:
                    connection.commit()
                return dict(row) | {"created": False}
            if row["state"] not in {"ACTIVE", "RECONCILE_REQUIRED"}:
                raise PermissionError("publication reservation is not finalizable")
            connection.execute(
                """UPDATE managed_publication_reservations
                   SET state='FINALIZED',pr_key=?,head_sha=?,updated_at=?
                   WHERE reservation_key=?""",
                (pr_key, head_sha, observed, reservation_key),
            )
            row = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            if owns_connection:
                connection.commit()
            return dict(row) | {"created": True}
        except Exception:
            if owns_connection and connection.in_transaction:
                connection.rollback()
            raise
        finally:
            if owns_connection:
                connection.close()

    def record_publication_receipt_atomic(
        self,
        *,
        pr_key: str,
        owner: str,
        repo: str,
        number: int,
        head_sha: str,
        pr_url: str,
        auto_created: bool,
        source_kind: str,
        source: str,
        provenance: dict[str, Any] | None = None,
        reservation_key: str | None = None,
        invitation_event_key: str | None = None,
        opportunity_key: str | None = None,
        event_idempotency_key: str,
        event_provenance: dict[str, Any] | None = None,
        event_payload: dict[str, Any] | None = None,
        now: str | None = None,
        receipt_observation: bool = False,
    ) -> dict[str, Any]:
        """Persist a publication receipt and its lifecycle transition atomically.

        This is deliberately one transaction: the quarantine gate is evaluated
        while holding the same write lock that inserts the PR row, finalizes the
        reservation, and records the receipt event.
        """

        expected_key = f"{owner}/{repo}#{number}"
        if pr_key != expected_key:
            raise ValueError("PR key must be owner/repo#number")
        if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
            raise ValueError("publication receipt head SHA is invalid")
        observed = _utc(now)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            reservation = None
            gate_key = opportunity_key
            if reservation_key:
                reservation = connection.execute(
                    "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                    (reservation_key,),
                ).fetchone()
                if reservation is None or reservation["state"] not in {
                    "ACTIVE",
                    "RECONCILE_REQUIRED",
                    "FINALIZED",
                }:
                    raise PermissionError("publication reservation is not active")
                gate_key = str(reservation["opportunity_key"] or gate_key or "")
                if reservation["state"] == "FINALIZED":
                    existing_finalized = connection.execute(
                        "SELECT * FROM managed_prs WHERE pr_key=?", (pr_key,)
                    ).fetchone()
                    if existing_finalized is None:
                        raise PermissionError("finalized reservation has no recorded PR")
            if gate_key and not receipt_observation:
                require_quarantine_clear(
                    connection,
                    opportunity_key=gate_key,
                    operation="managed publication receipt",
                )

            existing = connection.execute(
                "SELECT * FROM managed_prs WHERE pr_key=?", (pr_key,)
            ).fetchone()
            if existing and existing["origin_kind"] == "EXISTING_OPEN_PR":
                auto_created = False
            auto_creation = auto_created and (existing is None or not existing["auto_created"])
            if auto_creation and not receipt_observation:
                invitation_allowed = False
                if invitation_event_key:
                    invitation = connection.execute(
                        """SELECT is_maintainer,payload_json
                           FROM managed_maintainer_events
                           WHERE event_key=? AND event_type IN ('INVITATION','ASSIGNMENT')""",
                        (invitation_event_key,),
                    ).fetchone()
                    if invitation and invitation["is_maintainer"]:
                        invitation_payload = json_payload(invitation["payload_json"])
                        invitation_allowed = (
                            invitation_payload.get("targetRepo") == f"{owner}/{repo}"
                        )
                if not invitation_allowed:
                    open_count = int(
                        connection.execute(
                            """SELECT COUNT(*) FROM managed_prs
                               WHERE (repo=? OR owner || '/' || repo=?)
                                 AND state='OPEN' AND auto_created=1 AND maintainer_response=0""",
                            (f"{owner}/{repo}", f"{owner}/{repo}"),
                        ).fetchone()[0]
                    )
                    active_count = self._active_publication_reservation_count(
                        connection,
                        f"{owner}/{repo}",
                        exclude_key=reservation_key,
                        now=observed,
                    )
                    if open_count + active_count >= OPEN_PR_CAP:
                        raise PermissionError("repository open unanswered automatic PR cap reached")

            connection.execute(
                """INSERT INTO managed_prs
                   (pr_key,owner,repo,number,head_sha,pr_url,state,auto_created,
                    maintainer_response,source_kind,source,provenance_json,observed_at,metadata_json,
                    origin_kind,origin_observation_json,origin_head_sha,origin_pr_url,latest_source)
                   VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(pr_key) DO UPDATE SET head_sha=excluded.head_sha,
                     pr_url=excluded.pr_url,state=excluded.state,
                     auto_created=CASE WHEN managed_prs.auto_created=1 THEN 1 ELSE excluded.auto_created END,
                     source_kind=managed_prs.source_kind,source=excluded.source,
                     provenance_json=excluded.provenance_json,observed_at=excluded.observed_at,
                     metadata_json=excluded.metadata_json,
                     origin_kind=managed_prs.origin_kind,
                     origin_observation_json=managed_prs.origin_observation_json,
                     origin_head_sha=managed_prs.origin_head_sha,
                     origin_pr_url=managed_prs.origin_pr_url,
                     latest_source=excluded.source""",
                (
                    pr_key,
                    owner,
                    repo,
                    number,
                    head_sha,
                    pr_url,
                    "OPEN",
                    int(auto_created),
                    source_kind,
                    source,
                    _json(provenance or {}),
                    observed,
                    _json({}),
                    source_kind,
                    _json(provenance or {}),
                    None,
                    None,
                    source,
                ),
            )

            if reservation_key:
                self.finalize_publication_reservation(
                    reservation_key=reservation_key,
                    pr_key=pr_key,
                    head_sha=head_sha,
                    now=observed,
                    connection=connection,
                    receipt_observation=receipt_observation,
                )

            fingerprint = stable_fingerprint(event_idempotency_key)
            connection.execute(
                """INSERT OR IGNORE INTO managed_lifecycle_events
                   (opportunity_key,task_id,pr_key,event_type,state,idempotency_key,source,
                    idempotency_fingerprint,provenance_json,observed_at,payload_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    canonical_opportunity_key(opportunity_key) if opportunity_key else None,
                    None,
                    pr_key,
                    "PUBLICATION_RECEIPT_OBSERVED",
                    None,
                    event_idempotency_key,
                    source,
                    fingerprint,
                    _json(event_provenance or {}),
                    observed,
                    _json(event_payload or {}),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_prs WHERE pr_key=?", (pr_key,)
            ).fetchone()
            connection.commit()
            return dict(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def reconcile_publication_reservation(
        self,
        *,
        reservation_key: str,
        repo: str,
        head_sha: str,
        now: str | None = None,
    ) -> dict[str, Any] | None:
        """Recover a receipt written before a reservation finalize was interrupted."""

        connection = self._connection()
        try:
            reservation = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            if reservation is None:
                return None
            if reservation["state"] == "FINALIZED":
                if not reservation["pr_key"]:
                    return None
                pr = connection.execute(
                    "SELECT * FROM managed_prs WHERE pr_key=?", (reservation["pr_key"],)
                ).fetchone()
                return (
                    dict(pr) | {"reservation": dict(reservation), "reconciled": True}
                    if pr
                    else None
                )
            if reservation["state"] not in {"ACTIVE", "RECONCILE_REQUIRED"}:
                return None
            candidates = connection.execute(
                """SELECT * FROM managed_prs
                   WHERE owner || '/' || repo=? AND state='OPEN' AND auto_created=1
                     AND head_sha=? AND source_kind='MANAGED_PUBLICATION_RECEIPT'
                   ORDER BY pr_key""",
                (repo, head_sha),
            ).fetchall()
            if len(candidates) != 1:
                return None
            pr = dict(candidates[0])
        finally:
            connection.close()
        finalized = self.finalize_publication_reservation(
            reservation_key=reservation_key,
            pr_key=pr["pr_key"],
            head_sha=head_sha,
            now=now,
        )
        self.record_event(
            event_type="PUBLICATION_RECEIPT_RECONCILED",
            idempotency_key=f"publication-reconciled:{reservation_key}:{pr['pr_key']}:{head_sha}",
            pr_key=pr["pr_key"],
            source="publication-reconcile",
            payload={"reservationKey": reservation_key, "headSha": head_sha},
            observed_at=now,
        )
        return pr | {"reservation": finalized, "reconciled": True}

    def publication_effect_absence(
        self, *, reservation_key: str, repo: str, head_sha: str
    ) -> dict[str, Any]:
        """Read the local publication effect ledger without treating missing tables as absence."""

        connection = self._connection()
        try:
            reservation = connection.execute(
                "SELECT request_id,repo,head_sha FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            if reservation is None or reservation["repo"] != repo:
                return {
                    "ok": False,
                    "exists": None,
                    "endpoint": "local:managed_publication_reservations",
                }
            try:
                rows = connection.execute(
                    """SELECT e.effect_id,e.status FROM publication_effects e
                       JOIN publication_permits p ON p.permit_id=e.permit_id
                       WHERE p.request_id=? AND p.commit_sha=?""",
                    (reservation["request_id"], head_sha),
                ).fetchall()
            except sqlite3.OperationalError:
                return {"ok": False, "exists": None, "endpoint": "local:publication_effects"}
            return {
                "ok": True,
                "exists": bool(rows),
                "endpoint": "local:publication_effects",
                "result": [{"effectId": row["effect_id"], "status": row["status"]} for row in rows],
            }
        finally:
            connection.close()

    def create_absence_attestation(
        self,
        *,
        reservation_key: str,
        repo: str,
        head_ref: str,
        head_sha: str,
        queries: list[dict[str, Any]],
        local_effect: dict[str, Any],
        observed_at: str | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        observed = _utc(observed_at)
        connection = self._connection()
        try:
            reservation = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            if reservation is None:
                raise ValueError("publication reservation is missing")
            if (
                reservation["repo"] != repo
                or (reservation["head_ref"] and reservation["head_ref"] != head_ref)
                or (reservation["head_sha"] and reservation["head_sha"] != head_sha)
            ):
                raise ValueError("absence attestation reservation binding mismatch")
        finally:
            connection.close()
        base = {
            "schema": "absence_attestation_v1",
            "attestationId": f"absence:{reservation_key}:{secrets.token_hex(16)}",
            "reservationKey": reservation_key,
            "repo": repo,
            "headRef": head_ref,
            "headSha": head_sha,
            "queries": queries,
            "localEffect": local_effect,
            "observedAt": observed,
            "policy": ABSENCE_ATTESTATION_POLICY,
            "nonce": nonce or secrets.token_hex(16),
            "authenticationStatus": "AUTHENTICATED",
            "createdAt": observed,
        }
        base["contentDigest"] = _digest(base)
        auth = sign_current(
            {**base, "contentDigest": base["contentDigest"]}, context="absence-attestation-v1"
        )
        if not auth["keyId"] or not auth["signature"]:
            raise PermissionError("absence attestation signing key is unavailable")
        attestation = base | {
            "signerKeyId": auth["keyId"],
            "signature": None,
        }
        if auth["keyId"]:
            attestation["signature"] = sign_current(
                {**base, "contentDigest": base["contentDigest"], "signerKeyId": auth["keyId"]},
                context="absence-attestation-v1",
            )["signature"]
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO managed_publication_absence_attestations
                   (attestation_id,reservation_key,repo,head_ref,head_sha,query_json,local_effect_json,
                    observed_at,policy_version,nonce,content_digest,signer_key_id,signature,
                    authentication_status,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    base["attestationId"],
                    reservation_key,
                    repo,
                    head_ref,
                    head_sha,
                    _json(queries),
                    _json(local_effect),
                    observed,
                    ABSENCE_ATTESTATION_POLICY,
                    base["nonce"],
                    base["contentDigest"],
                    attestation["signerKeyId"],
                    attestation["signature"],
                    "AUTHENTICATED",
                    observed,
                ),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return attestation

    def apply_absence_attestation(
        self,
        attestation: dict[str, Any],
        *,
        now: str | None = None,
        max_age_seconds: int = ABSENCE_ATTESTATION_MAX_AGE_SECONDS,
    ) -> dict[str, Any]:
        observed = _parse_time(_utc(now))
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if not _attestation_authenticated_current(attestation):
                raise PermissionError("absence attestation signature is invalid or unavailable")
            if attestation.get("authenticationStatus") != "AUTHENTICATED":
                raise PermissionError("absence attestation requires reauthentication")
            try:
                attestation_time = _parse_time(str(attestation["observedAt"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise PermissionError("absence attestation timestamp is invalid") from exc
            age = (observed - attestation_time).total_seconds()
            if age < 0 or age > max_age_seconds:
                raise PermissionError("absence attestation is stale")
            attestation_id = str(attestation.get("attestationId") or "")
            if not attestation_id:
                raise PermissionError("absence attestation id is missing")
            stored_attestation = connection.execute(
                "SELECT * FROM managed_publication_absence_attestations WHERE attestation_id=?",
                (attestation_id,),
            ).fetchone()
            if stored_attestation is None or stored_attestation[
                "content_digest"
            ] != attestation.get("contentDigest"):
                raise PermissionError("absence attestation is not recorded")
            reservation = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (attestation.get("reservationKey"),),
            ).fetchone()
            if reservation is None:
                raise PermissionError("absence attestation reservation is missing")
            if (
                reservation["repo"] != attestation.get("repo")
                or (
                    reservation["head_ref"]
                    and reservation["head_ref"] != attestation.get("headRef")
                )
                or (
                    reservation["head_sha"]
                    and reservation["head_sha"] != attestation.get("headSha")
                )
            ):
                raise PermissionError("absence attestation head binding mismatch")
            if reservation["state"] in {"RELEASED", "FINALIZED"}:
                connection.commit()
                return dict(reservation) | {
                    "released": False,
                    "reason": "REPLAY_REJECTED",
                }
            already_consumed = connection.execute(
                """SELECT 1 FROM attestation_nonce_consumptions
                   WHERE attestation_id=? OR (nonce=? AND reservation_key=?)
                   LIMIT 1""",
                (attestation_id, attestation.get("nonce"), attestation.get("reservationKey")),
            ).fetchone()
            if already_consumed:
                connection.commit()
                return dict(reservation) | {
                    "released": False,
                    "reason": "REPLAY_REJECTED",
                }
            queries = attestation.get("queries")
            local_effect = attestation.get("localEffect")
            repo = str(attestation.get("repo") or "")
            head_ref = str(attestation.get("headRef") or "")
            head_sha = str(attestation.get("headSha") or "")
            owner = repo.split("/", 1)[0] if "/" in repo else ""
            expected_endpoints = {
                f"repos/{repo}/branches/{head_ref}",
                f"repos/{repo}/git/commits/{head_sha}",
                f"repos/{repo}/pulls?head={owner}:{head_ref}&state=all",
            }
            if (
                not isinstance(queries, list)
                or {item.get("endpoint") for item in queries if isinstance(item, dict)}
                != expected_endpoints
            ):
                raise PermissionError("absence attestation query binding mismatch")
            if len(queries) != 3 or not all(isinstance(item, dict) for item in queries):
                raise PermissionError("absence attestation query shape mismatch")
            connection.execute(
                """INSERT INTO attestation_nonce_consumptions
                   (attestation_id,nonce,reservation_key,content_digest,consumed_at)
                   VALUES (?,?,?,?,?)""",
                (
                    attestation_id,
                    attestation["nonce"],
                    attestation["reservationKey"],
                    attestation["contentDigest"],
                    _utc(now),
                ),
            )
            local_exists = (
                local_effect.get("exists") is True if isinstance(local_effect, dict) else False
            )
            if (
                not isinstance(queries, list)
                or not isinstance(local_effect, dict)
                or any(item.get("ok") is not True for item in queries if isinstance(item, dict))
                or any(
                    item.get("exists") is not False for item in queries if isinstance(item, dict)
                )
                or local_effect.get("ok") is not True
                or local_effect.get("exists") is not False
            ):
                state = (
                    "RECONCILE_REQUIRED"
                    if any(
                        isinstance(item, dict) and item.get("exists") is True
                        for item in queries or []
                    )
                    or local_exists
                    else "WAITING_EXTERNAL"
                )
                connection.execute(
                    "UPDATE managed_publication_reservations SET state=?,updated_at=? WHERE reservation_key=?",
                    (state, _utc(now), attestation["reservationKey"]),
                )
                connection.commit()
                return dict(reservation) | {"state": state, "released": False}
            connection.execute(
                "UPDATE managed_publication_reservations SET state='RELEASED',updated_at=? WHERE reservation_key=?",
                (_utc(now), attestation["reservationKey"]),
            )
            connection.commit()
            return {
                "reservationKey": attestation["reservationKey"],
                "state": "RELEASED",
                "released": True,
            }
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def mark_publication_waiting(
        self,
        *,
        reservation_key: str,
        state: str = "WAITING_EXTERNAL",
        reason: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        if state not in {"WAITING_EXTERNAL", "RECONCILE_REQUIRED"}:
            raise ValueError("invalid publication recovery state")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            if row is None:
                raise ValueError("publication reservation is missing")
            require_quarantine_clear(
                connection,
                opportunity_key=str(row["opportunity_key"] or ""),
                operation="publication waiting transition",
            )
            connection.execute(
                "UPDATE managed_publication_reservations SET state=?,updated_at=? WHERE reservation_key=?",
                (state, _utc(now), reservation_key),
            )
            row = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
            connection.commit()
            return dict(row) | ({"reason": reason} if reason else {})
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def expire_publication_reservations(self, *, now: str | None = None) -> int:
        observed = _utc(now)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """UPDATE managed_publication_reservations SET state='CHECK_ABSENCE_REQUIRED',updated_at=?
                   WHERE state='ACTIVE' AND lease_until<=?""",
                (observed, observed),
            )
            connection.commit()
            return int(cursor.rowcount)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _repo_pr_gate(
        self,
        repo: str,
        invitation_event_key: str | None,
        *,
        target_pr_key: str | None = None,
        target_opportunity_key: str | None = None,
        exclude_reservation_key: str | None = None,
    ) -> dict[str, Any]:
        if self._invitation_exemption(
            invitation_event_key,
            target_repo=repo,
            target_pr_key=target_pr_key,
            target_opportunity_key=target_opportunity_key,
        ):
            return {
                "allowed": True,
                "reason": "VERIFIED_MAINTAINER_INVITATION",
                "count": self.open_unanswered_auto_pr_count(repo),
            }
        count = self.open_unanswered_auto_pr_count(repo)
        connection = self._connection()
        try:
            count += self._active_publication_reservation_count(
                connection,
                repo,
                exclude_key=exclude_reservation_key,
                now=_utc(),
            )
        finally:
            connection.close()
        return {
            "allowed": count < OPEN_PR_CAP,
            "reason": "OPEN_PR_CAPACITY" if count < OPEN_PR_CAP else "OPEN_PR_CAP_REACHED",
            "count": count,
            "limit": OPEN_PR_CAP,
        }

    def task_creation_gate(
        self,
        *,
        repo: str,
        invitation_event_key: str | None = None,
        opportunity_key: str | None = None,
        pre_task_gate: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if pre_task_gate is not None and pre_task_gate.get("allowed") is not True:
            return {
                "allowed": False,
                "reason": pre_task_gate.get("reason") or "PRE_TASK_EVIDENCE_REQUIRED",
                "classification": pre_task_gate.get("classification") or "blocked_pre_task",
            }
        return self._repo_pr_gate(
            repo, invitation_event_key, target_opportunity_key=opportunity_key
        )

    def authorize_task_creation(
        self,
        *,
        task_id: str,
        opportunity_key: str,
        repo: str,
        issue_url: str,
        intent_id: str,
    ) -> dict[str, Any]:
        """Persist the only lifecycle evidence that can authorize an action."""

        canonical_key = canonical_opportunity_key(opportunity_key)
        authorization = task_creation_authorization(
            task_id=task_id,
            opportunity_key=opportunity_key,
            repo=repo,
            issue_url=issue_url,
            intent_id=intent_id,
        )
        return self.record_event(
            event_type="TASK_CREATION_AUTHORIZED",
            idempotency_key=f"task-creation-authorized:{task_id}:{intent_id}",
            opportunity_key=canonical_key,
            task_id=task_id,
            state="AUTHORIZED",
            source="managed-lifecycle",
            provenance={"authorizationKeyId": authorization["keyId"]},
            payload={"authorization": authorization},
        )

    def publication_gate(
        self,
        *,
        repo: str,
        invitation_event_key: str | None = None,
        pr_key: str | None = None,
    ) -> dict[str, Any]:
        return self._repo_pr_gate(repo, invitation_event_key, target_pr_key=pr_key)

    def prepare_public_reply(
        self,
        *,
        pr_key: str,
        maintainer_event_key: str,
        result_digest: str,
        proposed_body: str,
        completed: bool,
        objective_validation: bool,
        uncertainty: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        connection = self._connection()
        try:
            event = connection.execute(
                "SELECT * FROM managed_maintainer_events WHERE event_key=? AND pr_key=?",
                (maintainer_event_key, pr_key),
            ).fetchone()
            if not event:
                raise ValueError("maintainer event is required")
            event_payload = json_payload(event["payload_json"])
            result = connection.execute(
                """SELECT r.*,p.head_sha AS pr_head_sha
                   FROM managed_results r JOIN managed_prs p ON p.pr_key=r.pr_key
                   WHERE r.pr_key=? AND r.result_digest=? AND r.is_current=1
                   ORDER BY r.observed_at DESC LIMIT 1""",
                (pr_key, result_digest),
            ).fetchone()
            ci = None
            if result and result["head_sha"]:
                ci = connection.execute(
                    """SELECT status FROM managed_ci_runs
                       WHERE pr_key=? AND head_sha=? AND status='PASSED'
                       ORDER BY observed_at DESC LIMIT 1""",
                    (pr_key, result["head_sha"]),
                ).fetchone()
            task_evidence = bool(
                result
                and result["worker_state"].casefold() == "patched"
                and result["commit_sha"]
                and _valid_validation(json_payload(result["validation_json"]))
                and result["head_sha"] == result["pr_head_sha"]
                and ci
            )
            if task_evidence:
                stored_validation = json_payload(result["validation_json"])
                certificate = stored_validation.get("certificate")
                if not isinstance(certificate, dict):
                    evidence = stored_validation.get("evidence")
                    certificate = (
                        evidence.get("certificate") if isinstance(evidence, dict) else None
                    )
                task_evidence = bool(
                    isinstance(certificate, dict)
                    and certificate.get("resultKey") == result["result_key"]
                    and certificate.get("resultDigest") == result["result_digest"]
                )
            flags = event_payload.get("uncertainty")
            if not isinstance(flags, dict):
                flags = {}
            allowed = bool(
                event["is_maintainer"]
                and event_payload.get("explicit_mechanical_request") is True
                and task_evidence
                and not any(flags.get(flag, False) for flag in _UNCERTAIN_REPLY_FLAGS)
            )
            template = _reply_template(proposed_body)
            allowed = allowed and template is not None
            del completed, objective_validation, uncertainty
            mode = "AUTO_REPLY_ALLOWED" if allowed else "DRAFT"
            reason = (
                "verified mechanical request"
                if allowed
                else "DECISION_REQUIRED: evidence closure required"
            )
            reply_key = f"{pr_key}|{maintainer_event_key}|{result_digest}"
            existing = connection.execute(
                "SELECT * FROM managed_public_replies WHERE reply_key=?", (reply_key,)
            ).fetchone()
            if existing:
                if existing["mode"] == "DRAFT" and mode == "AUTO_REPLY_ALLOWED":
                    connection.execute(
                        """UPDATE managed_public_replies
                           SET mode='AUTO_REPLY_ALLOWED',body=?,reason=?,template_id=?
                               ,template_params_json=?,body_digest=?,policy_digest=?
                           WHERE reply_key=?""",
                        (
                            proposed_body,
                            reason,
                            template[0],
                            _json(template[1]),
                            _digest(proposed_body),
                            public_reply_policy_digest(),
                            reply_key,
                        ),
                    )
                    existing = connection.execute(
                        "SELECT * FROM managed_public_replies WHERE reply_key=?", (reply_key,)
                    ).fetchone()
                elif existing["mode"] == "AUTO_REPLY_ALLOWED" and mode != "AUTO_REPLY_ALLOWED":
                    connection.execute(
                        "UPDATE managed_public_replies SET mode='DRAFT',reason=? WHERE reply_key=?",
                        (reason, reply_key),
                    )
                    existing = connection.execute(
                        "SELECT * FROM managed_public_replies WHERE reply_key=?", (reply_key,)
                    ).fetchone()
                return dict(existing) | {"created": False}
            connection.execute(
                """INSERT OR IGNORE INTO managed_public_replies
                   (reply_key,pr_key,maintainer_event_key,result_digest,mode,body,reason,created_at,
                    template_id,template_params_json,body_digest,policy_digest)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    reply_key,
                    pr_key,
                    maintainer_event_key,
                    result_digest,
                    mode,
                    proposed_body,
                    reason,
                    _utc(),
                    template[0] if template else "opaque_body_v1",
                    _json(template[1] if template else {}),
                    _digest(proposed_body),
                    public_reply_policy_digest(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_public_replies WHERE reply_key=?", (reply_key,)
            ).fetchone()
            return dict(row) | {"created": True}
        finally:
            connection.close()

    def queue_public_reply(
        self,
        *,
        pr_key: str,
        maintainer_event_key: str,
        result_digest: str,
        proposed_body: str,
    ) -> dict[str, Any]:
        """Prepare a reply and queue only a deterministically authorized one."""

        prepared = self.prepare_public_reply(
            pr_key=pr_key,
            maintainer_event_key=maintainer_event_key,
            result_digest=result_digest,
            proposed_body=proposed_body,
            completed=False,
            objective_validation=False,
        )
        if prepared["mode"] != "AUTO_REPLY_ALLOWED":
            return prepared | {"queued": False}
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT OR IGNORE INTO managed_reply_deliveries
                   (reply_key,state,updated_at) VALUES (?, 'QUEUED', ?)""",
                (prepared["reply_key"], _utc()),
            )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return prepared | {"queued": True}

    def dispatch_reply_outbox(
        self,
        sender: Any | None,
        *,
        live_revalidator: Any | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Send only revalidated queued replies; sender is injected for tests."""

        if sender is None:
            return {
                "attempted": 0,
                "sent": 0,
                "blocked": 0,
                "errors": [],
                "skipped": "sender_not_configured",
            }
        attempted = sent = blocked = 0
        errors: list[dict[str, str]] = []
        while attempted < limit:
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """SELECT d.reply_key,r.* FROM managed_reply_deliveries d
                       JOIN managed_public_replies r ON r.reply_key=d.reply_key
                       WHERE d.state='QUEUED' ORDER BY d.updated_at,d.reply_key LIMIT 1"""
                ).fetchone()
                if row is None:
                    connection.commit()
                    break
                connection.execute(
                    "UPDATE managed_reply_deliveries SET state='SENDING',updated_at=? WHERE reply_key=?",
                    (_utc(), row["reply_key"]),
                )
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
            attempted += 1
            revalidated = self.prepare_public_reply(
                pr_key=row["pr_key"],
                maintainer_event_key=row["maintainer_event_key"],
                result_digest=row["result_digest"],
                proposed_body=row["body"],
                completed=False,
                objective_validation=False,
            )
            body_integrity = bool(
                revalidated["mode"] == "AUTO_REPLY_ALLOWED"
                and revalidated.get("policy_digest") == public_reply_policy_digest()
                and revalidated.get("body_digest") == _digest(revalidated.get("body") or "")
                and (
                    revalidated.get("template_id") == "opaque_body_v1"
                    or render_reply_template(
                        revalidated.get("template_id") or "",
                        json_payload(revalidated.get("template_params_json") or "{}"),
                    )
                    == revalidated.get("body")
                )
            )
            if not body_integrity:
                connection = self._connection()
                try:
                    connection.execute(
                        "UPDATE managed_reply_deliveries SET state='BLOCKED',error=?,updated_at=? WHERE reply_key=?",
                        (
                            "DECISION_REQUIRED: reply evidence or policy changed",
                            _utc(),
                            row["reply_key"],
                        ),
                    )
                    connection.execute(
                        "UPDATE managed_public_replies SET mode='DRAFT',reason=? WHERE reply_key=?",
                        ("DECISION_REQUIRED: reply evidence or policy changed", row["reply_key"]),
                    )
                    connection.commit()
                finally:
                    connection.close()
                blocked += 1
                continue
            if live_revalidator is None:
                connection = self._connection()
                try:
                    connection.execute(
                        "UPDATE managed_reply_deliveries SET state='BLOCKED',error=?,updated_at=? WHERE reply_key=?",
                        (
                            "DECISION_REQUIRED: live revalidation unavailable",
                            _utc(),
                            row["reply_key"],
                        ),
                    )
                    connection.commit()
                finally:
                    connection.close()
                blocked += 1
                continue
            evidence_connection = self._connection()
            try:
                live_row = evidence_connection.execute(
                    """SELECT r.head_sha,p.head_sha AS pr_head_sha,e.event_key,
                       (SELECT status FROM managed_ci_runs WHERE pr_key=r.pr_key AND head_sha=r.head_sha
                        ORDER BY observed_at DESC LIMIT 1) AS ci_status
                       FROM managed_results r JOIN managed_prs p ON p.pr_key=r.pr_key
                       JOIN managed_maintainer_events e ON e.event_key=?
                       WHERE r.pr_key=? AND r.result_digest=? AND r.is_current=1
                       ORDER BY r.observed_at DESC LIMIT 1""",
                    (row["maintainer_event_key"], row["pr_key"], row["result_digest"]),
                ).fetchone()
            finally:
                evidence_connection.close()
            if live_row is None:
                live_ok = False
                live_payload = {}
            else:
                live_payload = live_revalidator(
                    pr_key=row["pr_key"],
                    head_sha=live_row["head_sha"],
                    maintainer_event_key=live_row["event_key"],
                    result_digest=row["result_digest"],
                )
                live_ok = bool(
                    isinstance(live_payload, dict)
                    and live_payload.get("headSha") == live_row["head_sha"]
                    and live_payload.get("ciStatus") == "PASSED"
                    and live_payload.get("maintainerEventKey") == live_row["event_key"]
                    and live_payload.get("resultDigest") == row["result_digest"]
                    and live_payload.get("certificateVerified") is True
                )
            if not live_ok:
                connection = self._connection()
                try:
                    connection.execute(
                        "UPDATE managed_reply_deliveries SET state='BLOCKED',error=?,updated_at=? WHERE reply_key=?",
                        ("DECISION_REQUIRED: live evidence changed", _utc(), row["reply_key"]),
                    )
                    connection.commit()
                finally:
                    connection.close()
                blocked += 1
                continue
            try:
                receipt = sender(
                    pr_key=row["pr_key"],
                    body=row["body"],
                    reply_key=row["reply_key"],
                )
                receipt = receipt if isinstance(receipt, dict) else {"receipt": receipt}
            except Exception as exc:
                connection = self._connection()
                try:
                    connection.execute(
                        "UPDATE managed_reply_deliveries SET state='FAILED',error=?,updated_at=? WHERE reply_key=?",
                        (str(exc)[:400], _utc(), row["reply_key"]),
                    )
                    connection.commit()
                finally:
                    connection.close()
                errors.append({"replyKey": row["reply_key"], "error": str(exc)[:400]})
                continue
            connection = self._connection()
            try:
                connection.execute(
                    """UPDATE managed_reply_deliveries
                       SET state='SENT',external_id=?,receipt_digest=?,error=NULL,updated_at=?
                       WHERE reply_key=?""",
                    (
                        str(receipt.get("id") or receipt.get("externalId") or "") or None,
                        _digest(receipt),
                        _utc(),
                        row["reply_key"],
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            sent += 1
        return {"attempted": attempted, "sent": sent, "blocked": blocked, "errors": errors}

    def reconcile_reply_delivery(
        self,
        *,
        reply_key: str,
        external_id: str,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        connection = self._connection()
        try:
            current = connection.execute(
                "SELECT * FROM managed_public_replies WHERE reply_key=?", (reply_key,)
            ).fetchone()
            if current is None:
                raise ValueError("reply is missing")
            revalidated = self.prepare_public_reply(
                pr_key=current["pr_key"],
                maintainer_event_key=current["maintainer_event_key"],
                result_digest=current["result_digest"],
                proposed_body=current["body"],
                completed=False,
                objective_validation=False,
            )
            if revalidated["mode"] != "AUTO_REPLY_ALLOWED":
                raise PermissionError("reply evidence is no longer authorized")
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT d.*,r.pr_key,r.maintainer_event_key,r.result_digest,r.body,r.body_digest,
                   r.template_id,r.template_params_json,r.policy_digest,r.mode
                   FROM managed_reply_deliveries d JOIN managed_public_replies r
                   ON r.reply_key=d.reply_key WHERE d.reply_key=?""",
                (reply_key,),
            ).fetchone()
            if row is None:
                raise ValueError("reply delivery is missing")
            if (
                row["mode"] != "AUTO_REPLY_ALLOWED"
                or row["policy_digest"] != public_reply_policy_digest()
            ):
                raise PermissionError("reply evidence is no longer authorized")
            if row["body_digest"] != _digest(row["body"]):
                raise PermissionError("reply body digest mismatch")
            rendered = render_reply_template(
                row["template_id"], json_payload(row["template_params_json"])
            )
            if row["template_id"] != "opaque_body_v1" and rendered != row["body"]:
                raise PermissionError("reply template digest mismatch")
            connection.execute(
                """UPDATE managed_reply_deliveries
                   SET state='SENT',external_id=?,receipt_digest=?,error=NULL,updated_at=?
                   WHERE reply_key=?""",
                (external_id, _digest(receipt), _utc(), reply_key),
            )
            result = connection.execute(
                "SELECT * FROM managed_reply_deliveries WHERE reply_key=?", (reply_key,)
            ).fetchone()
            connection.commit()
            return dict(result)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def reconcile_reply_outbox(
        self, receipts: dict[str, dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        """Reconcile only receipts already observed; never invent an external send."""

        reconciled = blocked = 0
        errors: list[dict[str, str]] = []
        for reply_key, receipt in (receipts or {}).items():
            try:
                self.reconcile_reply_delivery(
                    reply_key=reply_key,
                    external_id=str(receipt.get("id") or receipt.get("externalId") or ""),
                    receipt=receipt,
                )
                reconciled += 1
            except Exception as exc:
                blocked += 1
                errors.append({"replyKey": reply_key, "error": str(exc)[:400]})
        return {"reconciled": reconciled, "blocked": blocked, "errors": errors}

    def record_external_outcome(
        self,
        *,
        pr_key: str,
        horizon_days: int,
        label: str,
        opportunity_key: str | None = None,
        source: str = "external",
        provenance: dict[str, Any] | None = None,
        observed_at: str | None = None,
        _system_generated: bool = False,
    ) -> dict[str, Any]:
        if horizon_days not in MATURE_HORIZONS:
            raise ValueError("external outcome horizon must be 14, 30, or 60 days")
        if label not in {"success", "failure", "censored", "pending"}:
            raise ValueError("invalid external outcome label")
        if label == "censored" and not _system_generated:
            raise PermissionError("censored outcomes are generated only after a mature horizon")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO managed_external_outcomes
                   (opportunity_key,pr_key,horizon_days,label,observed_at,source,provenance_json)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(pr_key,horizon_days) DO UPDATE SET label=excluded.label,
                     observed_at=excluded.observed_at,source=excluded.source,
                     provenance_json=excluded.provenance_json""",
                (
                    opportunity_key,
                    pr_key,
                    horizon_days,
                    label,
                    _utc(observed_at),
                    source,
                    _json(provenance or {}),
                ),
            )
            row = connection.execute(
                """SELECT * FROM managed_external_outcomes
                   WHERE pr_key=? AND horizon_days=?""",
                (pr_key, horizon_days),
            ).fetchone()
            connection.commit()
            return dict(row)
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def generate_censored_outcomes(self, *, now: str | None = None) -> int:
        at = _parse_time(_utc(now))
        connection = self._connection()
        try:
            candidates = connection.execute(
                "SELECT pr_key,observed_at FROM managed_prs ORDER BY pr_key"
            ).fetchall()
            existing = {
                (row["pr_key"], row["horizon_days"])
                for row in connection.execute(
                    "SELECT pr_key,horizon_days FROM managed_external_outcomes"
                ).fetchall()
            }
        finally:
            connection.close()
        generated = 0
        for pr in candidates:
            started = _parse_time(pr["observed_at"])
            for horizon in MATURE_HORIZONS:
                if (pr["pr_key"], horizon) in existing:
                    continue
                if at >= started + timedelta(days=horizon):
                    self.record_external_outcome(
                        pr_key=pr["pr_key"],
                        horizon_days=horizon,
                        label="censored",
                        source="managed:maturity-clock",
                        observed_at=now,
                        _system_generated=True,
                    )
                    generated += 1
        return generated

    def mature_cohort(
        self,
        *,
        horizon_days: int,
        now: str | None = None,
    ) -> list[dict[str, Any]]:
        if horizon_days not in MATURE_HORIZONS:
            raise ValueError("external outcome horizon must be 14, 30, or 60 days")
        self.generate_censored_outcomes(now=now)
        at = _parse_time(_utc(now))
        connection = self._connection()
        try:
            prs = connection.execute(
                "SELECT pr_key,observed_at FROM managed_prs ORDER BY pr_key"
            ).fetchall()
            outcomes = {
                row["pr_key"]: row["label"]
                for row in connection.execute(
                    """SELECT pr_key,label FROM managed_external_outcomes
                       WHERE horizon_days=?""",
                    (horizon_days,),
                ).fetchall()
            }
            result = []
            for pr in prs:
                label = outcomes.get(pr["pr_key"])
                if label is None:
                    mature_at = _parse_time(pr["observed_at"]) + timedelta(days=horizon_days)
                    label = "censored" if at >= mature_at else "pending"
                result.append({"prKey": pr["pr_key"], "horizonDays": horizon_days, "label": label})
            return result
        finally:
            connection.close()

    def cohort_learning_report(self, *, now: str | None = None) -> dict[str, Any]:
        """Return selected-to-outcome funnels for mature 14/30/60 day cohorts."""

        from .opportunity import cohort_report

        at = _parse_time(_utc(now))
        connection = self._connection()
        try:
            records: dict[str, dict[str, Any]] = {}
            for row in connection.execute(
                """SELECT opportunity_key,task_id,pr_key,event_type,state,observed_at,payload_json
                   FROM managed_lifecycle_events ORDER BY event_id"""
            ).fetchall():
                key = row["opportunity_key"] or row["pr_key"] or row["task_id"]
                if not key:
                    continue
                item = records.setdefault(
                    str(key),
                    {
                        "key": str(key),
                        "prKey": None,
                        "selectedAt": None,
                        "selected": False,
                        "task": False,
                        "fix": False,
                        "pr": False,
                        "ci": False,
                        "humanResponse": False,
                        "portfolioOutcome": False,
                    },
                )
                event_type = str(row["event_type"] or "")
                payload = json_payload(row["payload_json"])
                if row["pr_key"]:
                    item["prKey"] = str(row["pr_key"])
                if event_type in {"OPPORTUNITY_SELECTED", "DISPATCH_INTENT_IMPORTED"}:
                    item["selected"] = True
                    item["selectedAt"] = item["selectedAt"] or row["observed_at"]
                if event_type == "TASK_BOUND":
                    item["task"] = True
                if event_type == "PATCHED":
                    item["fix"] = True
                if event_type == "PUBLICATION_RECEIPT_OBSERVED":
                    item["pr"] = True
                if event_type == "MAINTAINER_EVENT_OBSERVED" and payload.get("isMaintainer"):
                    item["humanResponse"] = True
                if row["state"] == "PORTFOLIO_READY":
                    item["portfolioOutcome"] = True
            for row in connection.execute(
                "SELECT pr_key,horizon_days,label FROM managed_external_outcomes"
            ).fetchall():
                for item in records.values():
                    if item.get("pr") and item.get("prKey") == row["pr_key"]:
                        item["outcome"] = row["label"]
            return {
                "schema": "managed_opportunity_learning_v1",
                "observedAt": iso_z(at),
                "cohorts": cohort_report(list(records.values()), now=at),
            }
        finally:
            connection.close()

    def projection(self) -> dict[str, Any]:
        """Return a read-only War Room view; no lifecycle state is written."""

        connection = self._connection()
        try:
            tasks = connection.execute(
                """SELECT t.*, p.pr_url,p.pr_key,p.head_sha,p.state AS pr_state,
                          p.maintainer_response,p.auto_created
                   FROM managed_tasks t LEFT JOIN managed_prs p
                     ON p.pr_key=(SELECT r.pr_key FROM managed_results r
                                  WHERE r.task_id=t.task_id ORDER BY r.observed_at DESC LIMIT 1)
                   ORDER BY t.task_id"""
            ).fetchall()
            result_rows = {
                row["task_id"]: row
                for row in connection.execute(
                    """SELECT r.* FROM managed_results r
                       WHERE r.observed_at=(SELECT MAX(r2.observed_at) FROM managed_results r2
                                            WHERE r2.task_id=r.task_id)"""
                ).fetchall()
            }
            ci_rows = {
                (row["pr_key"], row["head_sha"]): row
                for row in connection.execute(
                    """SELECT c.* FROM managed_ci_runs c
                       WHERE c.observed_at=(SELECT MAX(c2.observed_at) FROM managed_ci_runs c2
                                            WHERE c2.pr_key=c.pr_key AND c2.head_sha=c.head_sha)"""
                ).fetchall()
            }
            items: list[dict[str, Any]] = []
            for task in tasks:
                result = result_rows.get(task["task_id"])
                ci = ci_rows.get((task["pr_key"], task["head_sha"]))
                ci_status = ci["status"] if ci else None
                state = task["state"]
                if state == "DECISION_REQUIRED" or (
                    result and result["worker_state"] == "needs_human"
                ):
                    bucket = "DECISION_REQUIRED"
                elif (
                    state == "PORTFOLIO_READY"
                    and (
                        (
                            result
                            and result["commit_sha"]
                            and _valid_validation(json_payload(result["validation_json"]))
                        )
                        or not result
                    )
                    and ci_status == "PASSED"
                ):
                    bucket = "PORTFOLIO_READY"
                elif (
                    state == "WAITING_EXTERNAL"
                    or ci_status in {"QUEUED", "RUNNING"}
                    or (task["pr_state"] == "OPEN" and not task["maintainer_response"])
                ):
                    bucket = "WAITING_EXTERNAL"
                else:
                    bucket = "SYSTEM_PROCESSING"
                items.append(
                    {
                        "bucket": bucket,
                        "taskId": task["task_id"],
                        "opportunityKey": task["opportunity_key"],
                        "internal": {
                            "taskState": state,
                            "workerState": result["worker_state"] if result else None,
                            "resultType": result["result_type"] if result else None,
                            "commitSha": result["commit_sha"] if result else None,
                            "ciStatus": ci_status,
                            "prKey": task["pr_key"],
                            "headSha": task["head_sha"],
                        },
                    }
                )
            task_pr_keys = {
                item["internal"]["prKey"] for item in items if item["internal"]["prKey"]
            }
            for pr in connection.execute("SELECT * FROM managed_prs ORDER BY pr_key").fetchall():
                if pr["pr_key"] in task_pr_keys:
                    continue
                bucket = (
                    "WAITING_EXTERNAL"
                    if pr["state"] == "OPEN" and not pr["maintainer_response"]
                    else "SYSTEM_PROCESSING"
                )
                items.append(
                    {
                        "bucket": bucket,
                        "prKey": pr["pr_key"],
                        "opportunityKey": None,
                        "internal": {
                            "taskState": None,
                            "workerState": None,
                            "resultType": None,
                            "commitSha": None,
                            "prKey": pr["pr_key"],
                            "headSha": pr["head_sha"],
                            "sourceKind": pr["source_kind"],
                        },
                    }
                )
            buckets = {bucket: [] for bucket in PROJECTION_BUCKETS}
            for item in items:
                buckets[item["bucket"]].append(item)
            return {"buckets": buckets, "items": items}
        finally:
            connection.close()

    def war_room_projection(self, *, source_commit: str | None = None) -> dict[str, Any]:
        """Return the versioned managed-user artifact used by new War Room views."""

        from .war_room_projection import build_projection

        return build_projection(self.path, source_commit=source_commit)

    def read_opportunity(self, opportunity_key: str) -> dict[str, Any] | None:
        try:
            canonical_key = canonical_opportunity_key(opportunity_key)
        except (TypeError, ValueError):
            canonical_key = opportunity_key
        connection = self._connection()
        try:
            row = connection.execute(
                "SELECT * FROM managed_opportunities WHERE opportunity_key=?",
                (canonical_key,),
            ).fetchone()
            if row:
                return dict(row) | {"readSource": "managed"}
            legacy = connection.execute(
                "SELECT * FROM opportunities WHERE key=?", (opportunity_key,)
            ).fetchone()
            if legacy:
                return dict(legacy) | {"readSource": "legacy"}
            return None
        finally:
            connection.close()

    def read_task(self, task_id: str) -> dict[str, Any] | None:
        connection = self._connection()
        try:
            row = connection.execute(
                "SELECT * FROM managed_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if row:
                return dict(row) | {"readSource": "managed"}
            legacy = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (task_id,)
            ).fetchone()
            return dict(legacy) | {"readSource": "legacy"} if legacy else None
        finally:
            connection.close()

    def legacy_tables_snapshot(self) -> dict[str, Any]:
        connection = self._connection()
        try:
            result: dict[str, Any] = {}
            for table, key in (
                ("opportunities", "key"),
                ("publication_requests", "request_id"),
                ("publication_effects", "effect_id"),
            ):
                rows = connection.execute(f'SELECT * FROM "{table}" ORDER BY "{key}"').fetchall()
                result[table] = [dict(row) for row in rows]
            return result
        finally:
            connection.close()


class PublicationAbsenceReconciler:
    """Slow-worker reconciler that produces signed absence attestations."""

    def __init__(self, ledger: ManagedLedger, github_client: Any, *, now: str | None = None):
        self.ledger = ledger
        self.github_client = github_client
        self.now = now

    @staticmethod
    def _query(client: Any, method_name: str, endpoint: str, *args: Any) -> dict[str, Any]:
        method = getattr(client, method_name)
        try:
            value = method(*args)
        except Exception as exc:
            message = str(exc).casefold()
            if "404" in message or "not found" in message:
                return {"endpoint": endpoint, "ok": True, "exists": False, "result": "not_found"}
            raise RuntimeError(f"external query failed: {endpoint}") from exc
        if isinstance(value, dict) and "exists" in value:
            exists = value["exists"]
            result = value.get("result")
        else:
            exists = value is not None and value != []
            result = (
                value if isinstance(value, (str, int, bool)) else ("present" if exists else "empty")
            )
        if not isinstance(exists, bool):
            raise RuntimeError(f"external query is uncertain: {endpoint}")
        return {"endpoint": endpoint, "ok": True, "exists": exists, "result": result}

    def reconcile(
        self,
        *,
        reservation_key: str,
        repo: str,
        head_ref: str,
        head_sha: str,
    ) -> dict[str, Any]:
        connection = self.ledger._connection()
        try:
            reservation = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation_key,),
            ).fetchone()
        finally:
            connection.close()
        if reservation is None:
            raise ValueError("publication reservation is missing")
        if (
            reservation["repo"] != repo
            or (reservation["head_ref"] and reservation["head_ref"] != head_ref)
            or (reservation["head_sha"] and reservation["head_sha"] != head_sha)
        ):
            return self.ledger.mark_publication_waiting(
                reservation_key=reservation_key, state="WAITING_EXTERNAL", now=self.now
            ) | {"released": False, "reason": "RESERVATION_BINDING_MISMATCH"}
        if self.github_client is None:
            return self.ledger.mark_publication_waiting(
                reservation_key=reservation_key, state="WAITING_EXTERNAL", now=self.now
            ) | {"released": False, "reason": "GITHUB_CLIENT_UNAVAILABLE"}
        try:
            owner, name = repo.split("/", 1)
            queries = [
                self._query(
                    self.github_client,
                    "query_branch",
                    f"repos/{repo}/branches/{head_ref}",
                    repo,
                    head_ref,
                ),
                self._query(
                    self.github_client,
                    "query_commit",
                    f"repos/{repo}/git/commits/{head_sha}",
                    repo,
                    head_sha,
                ),
                self._query(
                    self.github_client,
                    "query_pull_request",
                    f"repos/{repo}/pulls?head={owner}:{head_ref}&state=all",
                    repo,
                    head_ref,
                    head_sha,
                ),
            ]
            del owner, name
            local_effect = self.ledger.publication_effect_absence(
                reservation_key=reservation_key, repo=repo, head_sha=head_sha
            )
        except Exception:
            return self.ledger.mark_publication_waiting(
                reservation_key=reservation_key, state="WAITING_EXTERNAL", now=self.now
            ) | {"released": False, "reason": "EXTERNAL_QUERY_UNCERTAIN"}
        attestation = self.ledger.create_absence_attestation(
            reservation_key=reservation_key,
            repo=repo,
            head_ref=head_ref,
            head_sha=head_sha,
            queries=queries,
            local_effect=local_effect,
            observed_at=self.now,
        )
        try:
            return self.ledger.apply_absence_attestation(attestation, now=self.now)
        except PermissionError:
            return self.ledger.mark_publication_waiting(
                reservation_key=reservation_key, state="WAITING_EXTERNAL", now=self.now
            ) | {"released": False, "reason": "ATTESTATION_NOT_AUTHENTICATED"}


def schema_status(path: Path) -> dict[str, Any]:
    connection = connect(path)
    try:
        rows = _read_schema_migration_rows(connection)
        return {
            "versions": [dict(row) for row in rows],
            "current": rows[-1]["version"] if rows else 0,
        }
    finally:
        connection.close()


def migrate_copy(source: Path, target: Path) -> dict[str, Any]:
    copy_database(source, target)
    before = ManagedLedger(target).legacy_tables_snapshot()
    migration = migrate_schema(target)
    after = ManagedLedger(target).legacy_tables_snapshot()
    return {
        "source": str(source),
        "target": str(target),
        "migration": migration,
        "legacyBeforeDigest": _digest(before),
        "legacyAfterDigest": _digest(after),
        "legacyUnchanged": before == after,
        "schema": schema_status(target),
    }


def summarize_open_prs(path: Path) -> dict[str, Any]:
    ledger = ManagedLedger(path)
    connection = ledger._connection()
    try:
        try:
            rows = connection.execute(
                """SELECT pr_key,pr_url,head_sha,state,source_kind FROM managed_prs
                   WHERE state='OPEN' ORDER BY pr_key"""
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        observations = [
            {
                "prKey": row["pr_key"],
                "url": row["pr_url"],
                "headSha": row["head_sha"],
                "state": row["state"],
                "sourceKind": row["source_kind"],
            }
            for row in rows
        ]
        return {
            "count": len(observations),
            "observations": observations,
            "digest": _digest(observations),
        }
    finally:
        connection.close()


def import_open_pr_observations(
    path: Path,
    observations: list[dict[str, Any]],
    *,
    observed_at: str | None = None,
    source: str = "github_snapshot",
) -> dict[str, Any]:
    """Import existing open PRs as observations without mutating legacy tables."""

    ledger = ManagedLedger(path, ensure_schema=True)
    before_legacy = ledger.legacy_tables_snapshot()
    before = summarize_open_prs(path)
    imported = 0
    for observation in observations:
        pr_url = str(observation.get("url") or observation.get("prUrl") or "")
        pr_key = str(observation.get("prKey") or pr_key_from_url(pr_url))
        owner_repo, number_text = pr_key.rsplit("#", 1)
        owner, repo = owner_repo.split("/", 1)
        number = int(number_text)
        row_observed_at = observed_at
        if row_observed_at is None:
            with ledger._connection() as connection:
                existing = connection.execute(
                    "SELECT head_sha,observed_at FROM managed_prs WHERE pr_key=?",
                    (pr_key,),
                ).fetchone()
            if existing is not None and existing["head_sha"] == observation.get("headSha"):
                row_observed_at = existing["observed_at"]
        row = ledger.upsert_pr(
            pr_key=pr_key,
            owner=owner,
            repo=repo,
            number=number,
            head_sha=observation.get("headSha"),
            pr_url=pr_url or f"https://github.com/{owner}/{repo}/pull/{number}",
            state=str(observation.get("state") or "OPEN"),
            auto_created=False,
            source_kind="EXISTING_OPEN_PR",
            source=source,
            provenance={"import": source},
            observed_at=row_observed_at,
            metadata={"observation": True},
        )
        ledger.record_event(
            event_type="EXISTING_OPEN_PR_OBSERVED",
            idempotency_key=f"existing-open-pr:{pr_key}:{row['head_sha'] or ''}",
            pr_key=pr_key,
            source=source,
            provenance={"import": source},
            observed_at=observed_at,
            payload={"sourceKind": "EXISTING_OPEN_PR"},
        )
        imported += 1
    after_legacy = ledger.legacy_tables_snapshot()
    after = summarize_open_prs(path)
    return {
        "imported": imported,
        "before": before,
        "after": after,
        "legacyBeforeDigest": _digest(before_legacy),
        "legacyAfterDigest": _digest(after_legacy),
        "legacyUnchanged": before_legacy == after_legacy,
        "zeroLegacyMutation": before_legacy == after_legacy,
    }


def reconcile_managed_pr_states(
    path: Path,
    observations: list[dict[str, Any]],
    *,
    observed_at: str | None = None,
    source: str = "github-authoritative-reconciliation",
    require_all_managed: bool = True,
) -> dict[str, Any]:
    """Reconcile every managed PR from exact read-only API evidence.

    A missing PR is never interpreted as closed.  Every managed key must have
    one explicit OPEN/CLOSED/MERGED observation, and the evidence must bind the
    state, URL, head SHA and response digest before any row is updated.
    """

    ledger = ManagedLedger(path, ensure_schema=True)
    normalized: dict[str, dict[str, Any]] = {}
    for observation in observations:
        pr_url = str(observation.get("url") or observation.get("prUrl") or "")
        pr_key = str(observation.get("prKey") or pr_key_from_url(pr_url))
        state = str(observation.get("state") or "")
        if state not in PR_STATES:
            raise ValueError("authoritative PR observation must have OPEN, CLOSED, or MERGED state")
        if pr_key in normalized:
            raise ValueError(f"duplicate authoritative PR observation: {pr_key}")
        evidence = observation.get("apiEvidence")
        if not isinstance(evidence, dict) or evidence.get("authoritativeReadOnly") is not True:
            raise ValueError(f"authoritative API evidence is required for {pr_key}")
        if evidence.get("state") != state or evidence.get("url") != pr_url:
            raise ValueError(f"authoritative API evidence does not bind {pr_key}")
        if not isinstance(evidence.get("endpoint"), str) or not evidence["endpoint"]:
            raise ValueError(f"authoritative API endpoint is missing for {pr_key}")
        if not isinstance(evidence.get("responseDigest"), str) or not evidence["responseDigest"]:
            raise ValueError(f"authoritative API response digest is missing for {pr_key}")
        if not isinstance(evidence.get("fetchedAt"), str) or not evidence["fetchedAt"]:
            raise ValueError(f"authoritative API fetch time is missing for {pr_key}")
        if evidence.get("headSha") != observation.get("headSha"):
            raise ValueError(f"authoritative API head SHA does not bind {pr_key}")
        normalized[pr_key] = dict(observation)

    connection = ledger._connection()
    try:
        existing = {
            str(row["pr_key"]): row
            for row in connection.execute("SELECT * FROM managed_prs ORDER BY pr_key").fetchall()
        }
    finally:
        connection.close()
    missing = sorted(set(existing) - set(normalized))
    unexpected = sorted(set(normalized) - set(existing))
    if require_all_managed and (missing or unexpected):
        if missing:
            raise ValueError(f"authoritative PR reconciliation is incomplete: {missing[0]}")
        raise ValueError(f"authoritative PR reconciliation has an unexpected PR: {unexpected[0]}")

    before = summarize_managed_prs(path)
    for pr_key, observation in sorted(normalized.items()):
        pr_url = str(observation.get("url") or observation.get("prUrl") or "")
        owner_repo, number_text = pr_key.rsplit("#", 1)
        owner, repo = owner_repo.split("/", 1)
        number = int(number_text)
        state = str(observation["state"])
        evidence = dict(observation["apiEvidence"])
        row = ledger.upsert_pr(
            pr_key=pr_key,
            owner=owner,
            repo=repo,
            number=number,
            head_sha=observation.get("headSha"),
            pr_url=pr_url,
            state=state,
            auto_created=False,
            source_kind=(
                str(existing[pr_key]["source_kind"]) if pr_key in existing else "EXISTING_OPEN_PR"
            ),
            source=source,
            provenance={"reconciliation": "authoritative_read_only_api"},
            observed_at=observed_at or evidence["fetchedAt"],
            metadata={"authoritative": True, "responseDigest": evidence["responseDigest"]},
        )
        ledger.record_event(
            event_type="MANAGED_PR_STATE_RECONCILED",
            idempotency_key=(f"managed-pr-state:{pr_key}:{state}:{evidence['responseDigest']}"),
            pr_key=pr_key,
            state=state,
            source=source,
            provenance={"authoritative": True, "endpoint": evidence["endpoint"]},
            observed_at=evidence["fetchedAt"],
            payload={"state": state, "headSha": row["head_sha"], "apiEvidence": evidence},
        )
    after = summarize_managed_prs(path)
    by_key = {item["pr_key"]: item for item in after["observations"]}
    head_mismatches = [
        key
        for key, observation in normalized.items()
        if by_key.get(key, {}).get("head_sha") != observation.get("headSha")
    ]
    return {
        "authoritative": True,
        "total": after["count"],
        "stateCounts": after["stateCounts"],
        "liveOpenKeys": sorted(key for key, item in normalized.items() if item["state"] == "OPEN"),
        "missingManagedKeys": missing,
        "unexpectedManagedKeys": unexpected,
        "duplicateObservationKeys": [],
        "headMismatches": sorted(head_mismatches),
        "before": before,
        "after": after,
        "allManagedKeysObserved": not missing,
    }


def summarize_managed_prs(path: Path) -> dict[str, Any]:
    ledger = ManagedLedger(path)
    connection = ledger._connection()
    try:
        rows = connection.execute(
            "SELECT pr_key,pr_url,head_sha,state,source_kind FROM managed_prs ORDER BY pr_key"
        ).fetchall()
        observations = [dict(row) for row in rows]
    finally:
        connection.close()
    counts = {state: sum(item["state"] == state for item in observations) for state in PR_STATES}
    return {
        "count": len(observations),
        "stateCounts": counts,
        "observations": observations,
        "digest": _digest(observations),
    }


def export_projection(path: Path) -> dict[str, Any]:
    return ManagedLedger(path).projection()


def export_war_room_projection(path: Path, *, source_commit: str | None = None) -> dict[str, Any]:
    """Export the versioned user artifact without changing the legacy projection API."""

    from .war_room_projection import export_projection as export_user_projection

    return export_user_projection(path, source_commit=source_commit)
