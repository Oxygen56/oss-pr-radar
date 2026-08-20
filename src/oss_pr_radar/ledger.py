"""Local authoritative lifecycle ledger with transactional leases and receipts."""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .repo_probe import REPRODUCED_VALIDATED, verify_probe_receipt
from .task_quarantine import active as active_quarantine
from .task_quarantine import attach_artifact as attach_quarantine_artifact
from .task_quarantine import backfill_from_managed_events, backfill_from_radar_events
from .task_quarantine import clear as clear_quarantine
from .task_quarantine import ensure_schema as ensure_quarantine_schema
from .task_quarantine import payload as quarantine_payload
from .task_quarantine import record as record_quarantine
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
PR_UPDATE_REARM_REASONS = {"EXISTING_PR_HEAD_DRIFT", "NON_FAST_FORWARD_PR_UPDATE"}
PR_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/(\d+)$")
ISSUE_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/issues/(\d+)$")


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


class LedgerError(RuntimeError):
    pass


class RadarLedger:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
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
            backfill_from_radar_events(connection)
            backfill_from_managed_events(connection)
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
                """SELECT intent_id FROM intents
                   WHERE opportunity_key=?
                     AND (
                       (status IN ('PENDING','LEASED') AND expires_at>?)
                       OR status='CREATING'
                       OR status IN ('DISPATCHED','COMPLETED')
                       OR (status='REJECTED' AND intent_digest=?)
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
            "targetBase": context.get("targetBase"),
            "recoveredFromTaskContext": True,
            "titleTime": title_time,
        }
        restored_intent = False
        restored_publication = False
        with self.transaction() as connection:
            existing_intent = connection.execute(
                "SELECT * FROM intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if existing_intent is not None and existing_intent["opportunity_key"] != key:
                raise LedgerError("task context intent is bound to another opportunity")
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
                if not str(existing_intent["title_time"] or ""):
                    connection.execute(
                        "UPDATE intents SET title_time=?,updated_at=? WHERE intent_id=?",
                        (title_time, now, intent_id),
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
                recovered_authorized = _publication_probe_valid(request)
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
                            "CONSUMED" if recovered_authorized else "BLOCKED",
                            None if recovered_authorized else "BLOCKED_REPRODUCTION_REQUIRED",
                            permit_id if recovered_authorized else None,
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
                            "CONSUMED" if recovered_authorized else "BLOCKED",
                            updated_at,
                            pr_url,
                            canonical_json(
                                {
                                    "contextDigest": context_digest,
                                    "recoveredFromTaskContext": True,
                                    "authorizationStatus": "AUTHENTICATED"
                                    if recovered_authorized
                                    else "BLOCKED_REPRODUCTION_REQUIRED",
                                }
                            ),
                            requested_at,
                            updated_at,
                        ),
                    )
                    if recovered_authorized:
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
        self, intent_id: str, *, probe_level: str, task_stage: str, receipt_digest: str
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
            if stage == "AUDIT_NO_GO" and row["stage"] in PUBLISHED_STAGES:
                self._event(
                    connection,
                    key,
                    "POST_PUBLICATION_AUDIT_NO_GO",
                    dedupe_key or f"POST_PUBLICATION_AUDIT_NO_GO:{now}",
                    {
                        "preservedStage": row["stage"],
                        "reason": reason,
                        "evidence": evidence or {},
                    },
                    now,
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
                SELECT o.key, o.repo, o.issue_number, o.issue_url, o.stage,
                       o.terminal_reason,
                       MAX(i.issued_at) AS latest_intent_issued_at,
                       (
                           SELECT MAX(e.created_at)
                             FROM events e
                            WHERE e.opportunity_key=o.key
                              AND e.event_type=o.stage
                       ) AS terminal_recorded_at,
                       (
                           SELECT json_extract(e.payload_json, '$.issueUpdatedAt')
                             FROM events e
                            WHERE e.opportunity_key=o.key
                              AND e.event_type=o.stage
                            ORDER BY e.created_at DESC, e.id DESC
                            LIMIT 1
                       ) AS terminal_issue_updated_at
                  FROM opportunities o
                  LEFT JOIN intents i ON i.opportunity_key=o.key
                 WHERE o.stage IN ('AUDIT_NO_GO', 'MERGED', 'CLOSED')
                 GROUP BY o.key, o.repo, o.issue_number, o.issue_url, o.stage,
                          o.terminal_reason
                 ORDER BY o.key
                """
            ).fetchall()
        return [dict(row) for row in rows]

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
        intent_filter = "" if exclude_intent_id is None else "AND intent_id<>?"
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
                     SELECT opportunity_key FROM intents
                     WHERE status IN ('LEASED','CREATING','DISPATCHED')
                       AND (status IN ('CREATING','DISPATCHED') OR lease_until>?)
                       {intent_filter}
                     UNION
                     SELECT r.opportunity_key FROM events r
                     WHERE r.event_type='PR_FOLLOWUP_RESERVED'
                       {event_filter}
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
                       AND o.stage='VALIDATION_PENDING'
                       {event_filter}
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

    def recovery_candidates(self, *, min_age_minutes: int = 90) -> list[dict[str, Any]]:
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
                (cutoff,),
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
                   WHERE o.stage='VALIDATION_PENDING' AND s.created_at<=?
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
        candidates: dict[str, dict[str, Any]] = {}
        for row, recovery_kind in (
            *((row, "DISPATCHED_TASK") for row in dispatched_rows),
            *((row, "PR_FOLLOWUP_RESULT") for row in followup_rows),
            *((row, "VALIDATION_FOLLOWUP_RESULT") for row in validation_rows),
        ):
            thread_id = str(row["thread_id"])
            followup_digest = (
                str(row["followup_digest"])
                if recovery_kind in {"PR_FOLLOWUP_RESULT", "VALIDATION_FOLLOWUP_RESULT"}
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
                           WHERE prior.opportunity_key=o.key
                             AND prior.event_type='THREAD_RECOVERY_DELIVERY_ABANDONED'
                             AND json_extract(prior.payload_json,'$.reason')=
                                 'TERMINAL_RECOVERY_TURN_INTERRUPTED'
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

    def reserve_recovery(self, *, thread_id: str, nonce: str) -> dict[str, Any]:
        # The bridge may authorize an immediate one-shot recovery after a
        # terminal desktop error, before the normal stale-task threshold.
        candidates = {
            item["threadId"]: item for item in self.recovery_candidates(min_age_minutes=0)
        }
        candidate = candidates.get(thread_id)
        if not candidate or candidate["recoveryNonce"] != nonce:
            raise LedgerError("recovery authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
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
                },
                now,
            )
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
                (thread_id, nonce, int(allow_sent)),
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

    def exhaust_recovery(self, *, thread_id: str, nonce: str) -> None:
        """Release a repeatedly interrupted recovery and make the terminal state durable."""

        self.abandon_recovery_delivery(
            thread_id=thread_id,
            nonce=nonce,
            reason="RECOVERY_RETRY_EXHAUSTED",
            min_age_minutes=0,
        )
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key AS key,payload_json FROM events
                   WHERE event_type='THREAD_RECOVERY_RESERVED'
                     AND json_extract(payload_json,'$.threadId')=?
                     AND json_extract(payload_json,'$.recoveryNonce')=?
                   ORDER BY id DESC LIMIT 1""",
                (thread_id, nonce),
            ).fetchone()
            if row is None:
                raise LedgerError("exhausted recovery reservation not found")
            reservation = json.loads(row["payload_json"])
            now = iso_z(datetime.now(UTC))
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
                     AND o.stage='VALIDATION_PENDING'
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
                   WHERE o.stage='VALIDATION_PENDING'"""
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
                   WHERE o.stage='VALIDATION_PENDING'
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
                   WHERE o.stage='VALIDATION_PENDING'
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
                """SELECT n.id
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
            dedupe_key = sha256_text(f"{row['id']}|{evidence_fingerprint}")
            self._event(
                connection,
                key,
                "VALIDATION_FOLLOWUP_NO_PROGRESS_REARMED",
                dedupe_key,
                {
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
                   WHERE o.stage='VALIDATION_PENDING'
                     AND i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
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
                   WHERE o.stage='VALIDATION_PENDING'
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

    def commit_validation_followup(self, *, thread_id: str, result_digest: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND json_extract(r.payload_json,'$.resultDigest')=?
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
                   ORDER BY r.id DESC LIMIT 1""",
                (result_digest, thread_id, result_digest),
            ).fetchone()
            if row is None:
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
                """SELECT o.key,o.issue_url,i.worktree_path,r.payload_json,r.created_at
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
                     ) ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "worktreePath": row["worktree_path"],
                "threadId": json.loads(row["payload_json"]).get("threadId"),
                "resultDigest": json.loads(row["payload_json"]).get("resultDigest"),
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
                   WHERE o.stage='VALIDATION_PENDING' AND s.created_at<=?
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
            audit_row = (
                connection.execute(
                    """SELECT payload_json,created_at FROM events
                       WHERE opportunity_key=?
                         AND event_type IN ('AUDIT_PASS','AUDIT_SNAPSHOT')
                       ORDER BY id DESC LIMIT 1""",
                    (row["key"],),
                ).fetchone()
                if row is not None
                else None
            )
            publication_row = (
                connection.execute(
                    """SELECT r.status AS request_status,r.commit_sha,r.branch,
                              r.created_at AS requested_at,r.updated_at AS request_updated_at,
                              p.status AS permit_status,p.pr_url,
                              p.updated_at AS permit_updated_at
                       FROM publication_requests r
                       LEFT JOIN publication_permits p ON p.request_id=r.request_id
                       WHERE r.opportunity_key=?
                       ORDER BY r.updated_at DESC LIMIT 1""",
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
            preparation_row = (
                connection.execute(
                    """SELECT b.payload_json FROM events b
                       WHERE b.opportunity_key=?
                         AND b.event_type='PR_FOLLOWUP_PREPARATION_BOUND'
                         AND json_extract(b.payload_json,'$.threadId')=?
                         AND NOT EXISTS (
                           SELECT 1 FROM events x
                           WHERE x.opportunity_key=b.opportunity_key
                             AND x.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                             AND x.dedupe_key=b.dedupe_key
                         )
                       ORDER BY b.id DESC LIMIT 1""",
                    (row["key"], row["thread_id"]),
                ).fetchone()
                if row is not None
                else None
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
        authorization_active = row["status"] != "REJECTED" and row["stage"] != "AUDIT_NO_GO"
        raw_probe_level = str(payload.get("probeLevel") or "UNVERIFIED")
        raw_task_stage = str(payload.get("taskStage") or "REPRODUCTION_REQUIRED")
        probe_receipt_digest = str(payload.get("probeReceiptDigest") or "")
        implementation_authorized = (
            raw_task_stage == "IMPLEMENTATION_READY"
            and raw_probe_level == "REPRODUCED_VALIDATED"
            and bool(probe_receipt_digest)
        )
        verified_probe_receipt = None
        if implementation_authorized:
            try:
                from .managed_lifecycle import ManagedLedger

                issue_path = issue_url.removeprefix("https://github.com/").split("/issues/", 1)[0]
                expected_paths = [
                    str(path)
                    for path in (
                        payload.get("codePaths")
                        or (payload.get("preTaskEvidence") or {}).get("codePathsPlan")
                        or []
                    )
                    if str(path).strip()
                ]
                verified_probe_receipt = ManagedLedger(
                    self.path, ensure_schema=True
                ).current_reproduction_receipt(
                    task_id=str(row["intent_id"] or ""),
                    receipt_digest=probe_receipt_digest,
                    repo=issue_path,
                    issue_url=issue_url,
                    selected_base_sha=str(
                        payload.get("selectedBaseSha")
                        or (payload.get("preTaskEvidence") or {}).get("baseSha")
                        or ""
                    ),
                    code_paths=expected_paths,
                    head_sha=str(payload.get("headSha") or ""),
                    commit_sha=str(payload.get("commitSha") or ""),
                    result_digest=str(payload.get("resultDigest") or ""),
                    policy_digest=str(
                        payload.get("policyDigest")
                        or (payload.get("preTaskEvidence") or {}).get("policyDigest")
                        or ""
                    )
                    or None,
                )
            except (OSError, RuntimeError, ValueError, sqlite3.Error):
                verified_probe_receipt = None
        implementation_authorized = verified_probe_receipt is not None
        if not implementation_authorized:
            # A legacy payload may retain an older result digest after the
            # managed task has already recorded the authoritative receipt.
            # Re-read the complete receipt from managed provenance, never from
            # a digest-only field, and use its bound identity for the context.
            try:
                from .managed_lifecycle import ManagedLedger

                managed_task = ManagedLedger(self.path, ensure_schema=True).read_task(
                    str(row["intent_id"] or "")
                )
                managed_provenance = json.loads((managed_task or {}).get("provenance_json") or "{}")
                managed_receipt = managed_provenance.get("probeReceipt")
                if (
                    managed_task
                    and managed_task.get("state") == "IMPLEMENTATION_READY"
                    and isinstance(managed_receipt, dict)
                ):
                    verified_probe_receipt = ManagedLedger(
                        self.path, ensure_schema=True
                    ).current_reproduction_receipt(
                        task_id=str(row["intent_id"] or ""),
                        receipt_digest=str(managed_receipt.get("receiptDigest") or ""),
                        repo=str(managed_receipt.get("repo") or ""),
                        issue_url=str(managed_receipt.get("issueUrl") or ""),
                        selected_base_sha=str(managed_receipt.get("baseSha") or ""),
                        code_paths=list(managed_receipt.get("codePaths") or []),
                        head_sha=str(managed_receipt.get("headSha") or ""),
                        commit_sha=str(managed_receipt.get("commitSha") or ""),
                        result_digest=str(managed_receipt.get("resultDigest") or ""),
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
            except (OSError, RuntimeError, ValueError, sqlite3.Error, json.JSONDecodeError):
                verified_probe_receipt = None
        task_stage = raw_task_stage if implementation_authorized else "REPRODUCTION_REQUIRED"
        implementation_authorized = verified_probe_receipt is not None
        allowed_actions = (
            ["read_issue", "read_repo", "run_reproduction_probe", "write_structured_result"]
            if not implementation_authorized
            else ["read_issue", "read_repo", "edit_files", "run_tests", "write_structured_result"]
        )
        publication_receipt = None
        if publication_row is not None:
            pr_url = publication_row["pr_url"]
            receipt_status = (
                "PR_OPEN"
                if pr_url
                else publication_row["permit_status"] or publication_row["request_status"]
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
        if preparation_row is not None or (
            followup_row is not None and bool(followup_row["followup_required"])
        ):
            result_contract = {
                "requiredWakeDigestField": "followupDigest",
                "allowedStages": ["FIX_READY", "PR_OPEN"],
                "noLocalActionStage": "PR_OPEN",
                "mergeConflictHandoffMode": "controller_merge_required",
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
        return {
            "key": row["key"],
            "stage": row["stage"],
            "issueUrl": row["issue_url"],
            "track": payload.get("track") or "agent_ai_infra",
            "algorithmEvidence": payload.get("algorithmEvidence"),
            "intentId": row["intent_id"],
            "threadId": row["thread_id"],
            "titleTime": row["title_time"],
            "worktreePath": row["worktree_path"],
            "intentStatus": row["status"],
            "probeRequired": payload.get("probeRequired") is True or not payload.get("probeLevel"),
            "probeLevel": raw_probe_level,
            "probeReceiptDigest": probe_receipt_digest or None,
            "reproductionReceipt": verified_probe_receipt,
            "probeProfileId": payload.get("probeProfileId"),
            "defaultBranch": payload.get("defaultBranch"),
            "selectedBaseSha": payload.get("selectedBaseSha")
            or (payload.get("preTaskEvidence") or {}).get("baseSha"),
            "codePaths": payload.get("codePaths")
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
                          i.thread_id,i.title_time,i.updated_at,
                          json_extract(i.payload_json,'$.maturity') AS maturity,
                          json_extract(i.payload_json,'$.notify') AS notify
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.status='DISPATCHED' AND i.thread_id IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=o.key
                         AND e.event_type='DISPATCH_NOTIFICATION_SENT'
                         AND e.dedupe_key=i.thread_id
                     )
                   ORDER BY i.updated_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "repo": row["repo"],
                "issueNumber": row["issue_number"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "threadId": row["thread_id"],
                "titleTime": row["title_time"],
                "maturity": row["maturity"] or "mature",
                "notify": row["notify"] != 0,
            }
            for row in rows
        ]

    def commit_dispatch_notification(
        self,
        *,
        thread_id: str,
        idempotency_key: str,
    ) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key FROM intents
                   WHERE thread_id=? AND status='DISPATCHED'""",
                (thread_id,),
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

    def task_result_candidates(self) -> list[dict[str, Any]]:
        """Return thread-bound tasks whose private workspace result can be ingested."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,o.issue_url,i.intent_id,i.thread_id,
                          i.worktree_path,i.status,i.payload_json
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND i.worktree_path IS NOT NULL
                     AND (
                       i.status='DISPATCHED'
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
            if row["stage"] != "FIX_READY":
                raise LedgerError("opportunity is not submit-ready")
            if row["thread_id"] != thread_id:
                raise LedgerError("publication thread identity mismatch")
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
            request_allowed = _publication_probe_valid(request)
            request_status = "PENDING" if request_allowed else "BLOCKED"
            request_reason = None if request_allowed else "BLOCKED_REPRODUCTION_REQUIRED"
            existing = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if existing:
                existing_request = json.loads(existing["request_json"])
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

    def publication_work_items(self) -> list[dict[str, Any]]:
        """Return publication requests that the privileged controller may advance."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT r.* FROM publication_requests r
                   WHERE NOT EXISTS (
                     SELECT 1 FROM task_quarantines quarantine
                     WHERE quarantine.opportunity_key=r.opportunity_key
                       AND quarantine.status='ACTIVE'
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
                   ORDER BY r.created_at"""
            ).fetchall()
        return [dict(row) | {"request": json.loads(row["request_json"])} for row in rows]

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

    def defer_publication_request(self, request_id: str, reason: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            connection.execute(
                """UPDATE publication_requests SET status='PENDING',reason=?,updated_at=?
                   WHERE request_id=? AND status='PENDING'""",
                (reason, now, request_id),
            )

    def block_publication_request(self, request_id: str, reason: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT opportunity_key,request_json
                   FROM publication_requests WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if row is None:
                raise LedgerError("publication request not found")
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
                "SELECT request_json FROM publication_requests WHERE request_id=?",
                (row["request_id"],),
            ).fetchone()
            if request_row is None or not _publication_probe_valid_json(
                request_row["request_json"]
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
                "SELECT request_json FROM publication_requests WHERE request_id=?",
                (row["request_id"],),
            ).fetchone()
            if request_row is None or not _publication_probe_valid_json(
                request_row["request_json"]
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
                "SELECT request_json FROM publication_requests WHERE request_id=?",
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
                """SELECT r.request_json FROM publication_permits p
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE p.permit_id=?""",
                (permit_id,),
            ).fetchone()
            if authorization is None or not _publication_probe_valid_json(
                authorization["request_json"]
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
                """SELECT p.request_id,r.request_json FROM publication_permits p
                   JOIN publication_requests r ON r.request_id=p.request_id
                   WHERE p.permit_id=?""",
                (permit_id,),
            ).fetchone()
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
            if not blocked:
                existing = connection.execute(
                    "SELECT * FROM publication_effects WHERE effect_id=?", (effect_id,)
                ).fetchone()
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
                "SELECT request_json FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
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
                "SELECT request_json FROM publication_requests WHERE request_id=?",
                (permit["request_id"],),
            ).fetchone()
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
                if required and (
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

    def pr_followup_candidates(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT f.*,o.key,o.repo,o.issue_url,o.stage,i.intent_id,
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
                       SELECT 1 FROM events e WHERE e.opportunity_key=o.key
                         AND e.event_type='PR_FOLLOWUP_RESULT_INGESTED'
                         AND e.dedupe_key=f.wake_digest
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events reserved
                       WHERE reserved.opportunity_key=o.key
                         AND reserved.event_type='PR_FOLLOWUP_RESERVED'
                         AND reserved.dedupe_key=f.wake_digest
                         AND NOT EXISTS (
                           SELECT 1 FROM events abandoned
                           WHERE abandoned.opportunity_key=reserved.opportunity_key
                             AND abandoned.event_type='PR_FOLLOWUP_DELIVERY_ABANDONED'
                             AND json_extract(abandoned.payload_json,'$.wakeDigest')=
                                 reserved.dedupe_key
                             AND abandoned.id>reserved.id
                         )
                     )
                     AND NOT EXISTS (
                       SELECT 1 FROM events active
                       WHERE active.opportunity_key=o.key
                         AND active.event_type='PR_FOLLOWUP_RESERVED'
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
                     )
                   ORDER BY f.checked_at,r.updated_at DESC"""
            ).fetchall()
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

    def pr_followup_rebind_status(self, key: str) -> dict[str, Any] | None:
        """Return the latest task-local rebind signal, if one exists."""

        with self.connect() as connection:
            ensure_quarantine_schema(connection)
            backfill_from_managed_events(connection)
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
            raise LedgerError("PR follow-up authorization is stale or invalid")
        if exclude_intent_id is not None and exclude_intent_id != candidate["intentId"]:
            raise LedgerError("PR follow-up WIP exclusion does not match the task")
        if prepared_head_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", prepared_head_sha):
            raise LedgerError("PR follow-up prepared head is invalid")
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
        with self.transaction() as connection:
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

    def record_task_result_ingested(self, key: str, *, digest: str, stage: str) -> None:
        with self.transaction() as connection:
            self._event(
                connection,
                key,
                "TASK_RESULT_INGESTED",
                digest,
                {"stage": stage},
                iso_z(datetime.now(UTC)),
            )

    def complete_publication_effect(
        self, effect_id: str, *, status: str, result: dict[str, Any]
    ) -> None:
        if status not in {"SUCCEEDED", "RECONCILE_REQUIRED", "FAILED"}:
            raise ValueError("invalid publication effect status")
        with self.transaction() as connection:
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
                "SELECT request_json FROM publication_requests WHERE request_id=?",
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
