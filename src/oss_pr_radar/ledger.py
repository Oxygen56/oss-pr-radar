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

from .util import canonical_json, iso_z, parse_time, sha256_text

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
            title_time = parse_time(captured_at).astimezone(
                timezone(timedelta(hours=8))
            ).strftime("%m-%d %H:%M")

        if stage not in RECOVERABLE_CONTEXT_STAGES:
            if stage != "DISPATCHED":
                raise LedgerError("task context lifecycle stage is not recoverable")
            current = self.task_context(issue_url=issue_url, thread_id=thread_id)
            expected_binding = {
                "key": key,
                "stage": stage,
                "intentId": intent_id,
                "threadId": thread_id,
                "worktreePath": str(Path(worktree_path).resolve()),
                "intentStatus": intent_status,
                "titleTime": title_time,
                "liveAudit": live_audit,
            }
            if current is None or any(
                current.get(field) != expected
                for field, expected in expected_binding.items()
            ):
                raise LedgerError("active task context disagrees with the ledger")
            if context.get("publicationReceipt") is not None:
                raise LedgerError("active task context has an unexpected publication receipt")
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
                {"liveAudit": live_audit, "recoveredFromTaskContext": True},
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
                existing_publication = connection.execute(
                    """SELECT r.opportunity_key FROM publication_permits p
                       JOIN publication_requests r ON r.request_id=p.request_id
                       WHERE p.pr_url=? AND p.status='CONSUMED'""",
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
                           VALUES (?,?,?,?,?,?,?,'CONSUMED',NULL,?,?,?,?)""",
                        (
                            request_id,
                            key,
                            thread_id,
                            commit_sha,
                            branch,
                            str(Path(worktree_path).resolve()),
                            evidence_digest,
                            permit_id,
                            canonical_json(request),
                            requested_at,
                            updated_at,
                        ),
                    )
                    connection.execute(
                        """INSERT INTO publication_permits
                           (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,
                            pr_url,evidence_json,created_at,updated_at)
                           VALUES (?,?,?,?,?,'CONSUMED',?,?,?,?,?)""",
                        (
                            permit_id,
                            request_id,
                            issue_url,
                            commit_sha,
                            branch,
                            updated_at,
                            pr_url,
                            canonical_json(
                                {
                                    "contextDigest": context_digest,
                                    "recoveredFromTaskContext": True,
                                }
                            ),
                            requested_at,
                            updated_at,
                        ),
                    )
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
                active = connection.execute(
                    """SELECT COUNT(*) FROM intents
                       WHERE status IN ('LEASED','CREATING','DISPATCHED')
                         AND intent_id<>?
                         AND (status IN ('CREATING','DISPATCHED') OR lease_until>?)""",
                    (intent_id, now),
                ).fetchone()[0]
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
        client_thread_id: str,
        reason: str,
        min_age_minutes: int = 70,
    ) -> None:
        """Release a bound async creation after the desktop task never materialized."""

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
                raise LedgerError("bound client thread id changed")
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
            item
            for item in self.title_bindings()
            if item["titleSyncedState"] != item["titleState"]
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

    def restore_candidates(self) -> list[dict[str, Any]]:
        """Return current tasks whose archived UI state no longer matches lifecycle."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.title,o.stage,o.updated_at,o.issue_url,
                          i.thread_id,i.worktree_path,i.title_time,
                          archived.id AS archived_event_id
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   JOIN events archived ON archived.id=(
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
                     AND archived.event_type='THREAD_ARCHIVED'
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
                "restoreNonce": sha256_text(
                    f"{row['key']}|{row['thread_id']}|{row['stage']}|"
                    f"{row['updated_at']}|{row['archived_event_id']}"
                ),
            }
            for row in rows
        ]

    def commit_restore(self, *, thread_id: str, nonce: str) -> None:
        candidates = {item["threadId"]: item for item in self.restore_candidates()}
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

    def pending(self) -> list[dict[str, Any]]:
        now_dt = datetime.now(UTC)
        now = iso_z(now_dt)
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT payload_json,status,issued_at,lease_until,client_thread_id,
                          creation_started_at FROM intents
                   WHERE (status IN ('PENDING','LEASED') AND expires_at>?)
                      OR status='CREATING'
                   ORDER BY issued_at""",
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

    def recovery_candidates(self, *, min_age_minutes: int = 90) -> list[dict[str, Any]]:
        cutoff = iso_z(
            datetime.now(UTC) - timedelta(minutes=max(30, min(int(min_age_minutes), 24 * 60)))
        )
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.intent_id,i.thread_id,
                          i.worktree_path,d.created_at AS dispatched_at
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events d ON d.opportunity_key=o.key
                     AND d.event_type='DISPATCHED' AND d.dedupe_key=i.thread_id
                   WHERE i.status='DISPATCHED' AND i.thread_id IS NOT NULL
                     AND d.created_at<=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=o.key
                         AND (
                           (e.event_type='THREAD_RECOVERY_RESERVED'
                            AND e.dedupe_key=i.thread_id)
                           OR
                           (e.event_type='TASK_RESULT_VALIDATION_DEFERRED'
                            AND json_extract(e.payload_json,'$.threadId')=i.thread_id)
                         )
                     )
                   ORDER BY d.created_at""",
                (cutoff,),
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "title": row["title"],
                "intentId": row["intent_id"],
                "threadId": row["thread_id"],
                "worktreePath": row["worktree_path"],
                "dispatchedAt": row["dispatched_at"],
                "recoveryNonce": sha256_text(
                    f"{row['key']}|{row['thread_id']}|{row['dispatched_at']}|recovery-v1"
                ),
            }
            for row in rows
        ]

    def unresolved_recoveries(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,i.thread_id,r.payload_json,r.created_at
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                     AND r.dedupe_key=i.thread_id
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events e
                     WHERE e.opportunity_key=o.key
                       AND e.event_type='THREAD_RECOVERY_SENT'
                   )
                   ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "issueUrl": row["issue_url"],
                "threadId": row["thread_id"],
                "reservedAt": row["created_at"],
                "reservation": json.loads(row["payload_json"]),
            }
            for row in rows
        ]

    def reserve_recovery(self, *, thread_id: str, nonce: str) -> dict[str, Any]:
        candidates = {item["threadId"]: item for item in self.recovery_candidates()}
        candidate = candidates.get(thread_id)
        if not candidate or candidate["recoveryNonce"] != nonce:
            raise LedgerError("recovery authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            existing = connection.execute(
                """SELECT 1 FROM events WHERE opportunity_key=?
                   AND event_type='THREAD_RECOVERY_RESERVED' AND dedupe_key=?""",
                (candidate["key"], thread_id),
            ).fetchone()
            if existing:
                raise LedgerError("recovery is already reserved")
            self._event(
                connection,
                candidate["key"],
                "THREAD_RECOVERY_RESERVED",
                thread_id,
                {"threadId": thread_id, "recoveryNonce": nonce},
                now,
            )
        return candidate

    def commit_recovery(self, *, thread_id: str, nonce: str) -> None:
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key,r.payload_json
                   FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='THREAD_RECOVERY_RESERVED'
                     AND r.dedupe_key=i.thread_id
                   WHERE i.thread_id=?""",
                (thread_id,),
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
                thread_id,
                {"threadId": thread_id, "recoveryNonce": nonce},
                iso_z(datetime.now(UTC)),
            )

    def record_validation_deferred(
        self,
        key: str,
        *,
        thread_id: str,
        result_digest: str,
        missing: list[str],
    ) -> None:
        """Record a substantive result that needs validation, not task recovery."""

        with self.transaction() as connection:
            row = connection.execute(
                """SELECT 1 FROM intents i
                   JOIN opportunities o ON o.key=i.opportunity_key
                   WHERE i.opportunity_key=? AND i.thread_id=?
                     AND (i.status='DISPATCHED'
                          OR (i.status='COMPLETED' AND o.stage='VALIDATION_PENDING'))""",
                (key, thread_id),
            ).fetchone()
            if row is None:
                raise LedgerError("validation-deferred task is not dispatched")
            self._event(
                connection,
                key,
                "TASK_RESULT_VALIDATION_DEFERRED",
                result_digest,
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "missing": missing,
                },
                iso_z(datetime.now(UTC)),
            )

    def validation_followup_candidates(self) -> list[dict[str, Any]]:
        """Return validation-pending tasks that have not been resumed for this result."""

        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.issue_url,o.title,i.thread_id,i.worktree_path,
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
                         AND r.dedupe_key=json_extract(d.payload_json,'$.resultDigest')
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
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "resultDigest": payload.get("resultDigest"),
                    "missing": list(payload.get("missing") or []),
                    "deferredAt": row["created_at"],
                }
            )
        return candidates

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

    def reserve_validation_followup(self, *, thread_id: str, result_digest: str) -> dict[str, Any]:
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
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "VALIDATION_FOLLOWUP_RESERVED",
                result_digest,
                {
                    "threadId": thread_id,
                    "resultDigest": result_digest,
                    "missing": candidate["missing"],
                },
                iso_z(datetime.now(UTC)),
            )
        return candidate

    def commit_validation_followup(self, *, thread_id: str, result_digest: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                     AND r.dedupe_key=?
                   WHERE i.thread_id=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                         AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                         AND s.dedupe_key=?
                     )""",
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
                """SELECT o.key,r.payload_json,r.created_at
                   FROM opportunities o
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='VALIDATION_FOLLOWUP_RESERVED'
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                       AND s.event_type='VALIDATION_FOLLOWUP_SENT'
                       AND s.dedupe_key=r.dedupe_key
                   ) ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "threadId": json.loads(row["payload_json"]).get("threadId"),
                "resultDigest": json.loads(row["payload_json"]).get("resultDigest"),
                "missing": list(json.loads(row["payload_json"]).get("missing") or []),
                "reservedAt": row["created_at"],
            }
            for row in rows
        ]

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
        if worktree_path:
            clauses.append("i.worktree_path=?")
            params.append(str(Path(worktree_path).resolve()))
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
                       WHERE opportunity_key=? AND followup_required=1""",
                    (row["key"],),
                ).fetchone()
                if row is not None
                else None
            )
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        audit_payload = json.loads(audit_row["payload_json"]) if audit_row else {}
        authorization_active = row["status"] != "REJECTED" and row["stage"] != "AUDIT_NO_GO"
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
        if followup_row is not None:
            pr_followup = {
                "prUrl": followup_row["pr_url"],
                "headSha": followup_row["head_sha"],
                "actionDigest": followup_row["action_digest"],
                "taskActionDigest": followup_row["task_action_digest"],
                "wakeDigest": followup_row["wake_digest"],
                "actions": json.loads(followup_row["actions_json"]),
                "evidence": json.loads(followup_row["evidence_json"]),
                "checkedAt": followup_row["checked_at"],
                "resultContract": {
                    "requiredWakeDigestField": "followupDigest",
                    "allowedStages": ["FIX_READY", "PR_OPEN"],
                    "noLocalActionStage": "PR_OPEN",
                    "mergeConflictHandoffMode": "controller_merge_required",
                },
            }
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
            "autoSubmitAuthorized": (
                authorization_active and payload.get("autoSubmitAuthorized") is True
            ),
            "publicationMode": payload.get("publicationMode"),
            "publicSubmissionAllowed": (
                authorization_active and payload.get("publicSubmissionAllowed") is True
            ),
            "authorizationSource": (
                payload.get("authorizationSource")
                if authorization_active
                else "revoked_terminal_no_go"
            ),
            "liveAudit": audit_payload.get("liveAudit"),
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
                          i.thread_id,i.title_time,i.updated_at
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
                             AND p.status IN ('PENDING','GRANTED','CONSUMED')
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
    ) -> dict[str, Any]:
        now = iso_z(datetime.now(UTC))
        request_id = sha256_text(
            "|".join(
                (
                    issue_url,
                    thread_id,
                    commit_sha,
                    branch,
                    worktree_path,
                    evidence_digest,
                    canonical_json(publication),
                )
            )
        )
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
                "quality": quality,
                "intent": payload,
                "publicationKind": "PR_UPDATE" if previous_publication else "PR_CREATE",
            }
            if previous_publication:
                request.update(
                    {
                        "existingPrUrl": previous_publication["pr_url"],
                        "previousCommitSha": previous_commit_sha,
                        "followupWakeDigest": followup["wake_digest"] if followup else None,
                    }
                )
            existing = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if existing:
                return dict(existing) | {"request": json.loads(existing["request_json"])}
            connection.execute(
                """INSERT INTO publication_requests
                   (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                    evidence_digest,status,request_json,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,'PENDING',?,?,?)""",
                (
                    request_id,
                    row["key"],
                    thread_id,
                    commit_sha,
                    branch,
                    request["worktreePath"],
                    evidence_digest,
                    canonical_json(request),
                    now,
                    now,
                ),
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
                "status": "PENDING",
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
                   WHERE r.status IN ('PENDING','GRANTED') OR (
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
                   )
                   ORDER BY r.created_at"""
            ).fetchall()
        return [dict(row) | {"request": json.loads(row["request_json"])} for row in rows]

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
        with self.transaction() as connection:
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
            if request.get("publicationKind") != "PR_UPDATE":
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
            if confirmation is None:
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
                     WHERE p.status='CONSUMED' AND p.pr_url IS NOT NULL
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
        with self.transaction() as connection:
            tracked = {
                str(row["pr_url"]): str(row["opportunity_key"])
                for row in connection.execute(
                    """SELECT DISTINCT p.pr_url,r.opportunity_key
                       FROM publication_requests r
                       JOIN publication_permits p ON p.request_id=r.request_id
                       WHERE p.status='CONSUMED' AND p.pr_url IS NOT NULL"""
                ).fetchall()
            }
            for item in state["items"]:
                if not isinstance(item, dict):
                    continue
                pr_url = str(item.get("url") or "")
                key = tracked.get(pr_url)
                if not key or not PR_URL_RE.fullmatch(pr_url):
                    continue
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
                required = item.get("taskFollowupRequired") is True
                previous = connection.execute(
                    "SELECT * FROM pr_followups WHERE opportunity_key=?", (key,)
                ).fetchone()
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
        return {"matched": matched, "inserted": inserted, "updated": updated}

    def pr_followup_candidates(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT f.*,o.key,o.issue_url,o.stage,i.thread_id,i.worktree_path,
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
                     AND p.status='CONSUMED' AND p.pr_url=f.pr_url
                     AND NOT EXISTS (
                       SELECT 1 FROM events e WHERE e.opportunity_key=o.key
                         AND e.event_type IN (
                           'PR_FOLLOWUP_RESERVED','PR_FOLLOWUP_RESULT_INGESTED'
                         )
                         AND e.dedupe_key=f.wake_digest
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
                    "issueUrl": row["issue_url"],
                    "prUrl": row["pr_url"],
                    "headSha": row["head_sha"],
                    "wakeDigest": row["wake_digest"],
                    "actions": json.loads(row["actions_json"]),
                    "evidence": json.loads(row["evidence_json"]),
                    "checkedAt": row["checked_at"],
                    "threadId": row["thread_id"],
                    "worktreePath": row["worktree_path"],
                    "branch": row["branch"],
                },
            )
        return list(unique.values())

    def reserve_pr_followup(self, *, thread_id: str, wake_digest: str) -> dict[str, Any]:
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
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "PR_FOLLOWUP_RESERVED",
                wake_digest,
                {"threadId": thread_id, "prUrl": candidate["prUrl"]},
                iso_z(datetime.now(UTC)),
            )
        return candidate

    def commit_pr_followup(self, *, thread_id: str, wake_digest: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT o.key,f.pr_url FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   JOIN pr_followups f ON f.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='PR_FOLLOWUP_RESERVED'
                     AND r.dedupe_key=f.wake_digest
                   WHERE i.thread_id=? AND f.wake_digest=?
                     AND NOT EXISTS (
                       SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                         AND s.event_type='PR_FOLLOWUP_SENT'
                         AND s.dedupe_key=f.wake_digest
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

    def unresolved_pr_followups(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,f.pr_url,f.wake_digest,r.payload_json,r.created_at
                   FROM opportunities o
                   JOIN pr_followups f ON f.opportunity_key=o.key
                   JOIN events r ON r.opportunity_key=o.key
                     AND r.event_type='PR_FOLLOWUP_RESERVED'
                     AND r.dedupe_key=f.wake_digest
                   WHERE NOT EXISTS (
                     SELECT 1 FROM events s WHERE s.opportunity_key=o.key
                       AND s.event_type='PR_FOLLOWUP_SENT'
                       AND s.dedupe_key=f.wake_digest
                   ) ORDER BY r.created_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "thread_id": json.loads(row["payload_json"]).get("threadId"),
                "pr_url": row["pr_url"],
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

    def consume_publication_permit(self, permit_id: str, pr_url: str) -> None:
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            permit = connection.execute(
                "SELECT * FROM publication_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()
            if permit is None or permit["status"] != "ACTIVE":
                raise LedgerError("publication permit is not active")
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
                "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
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
                "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
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

    def cleanup_candidates(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,o.updated_at,o.issue_url,i.thread_id,i.worktree_path
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.stage='AUDIT_NO_GO' AND i.thread_id IS NOT NULL
                     AND i.title_synced_state='AUDIT_NO_GO'
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
                "cleanupNonce": sha256_text(
                    f"{row['key']}|{row['thread_id']}|{row['stage']}|{row['updated_at']}"
                ),
            }
            for row in rows
        ]

    def commit_cleanup(self, *, thread_id: str, nonce: str) -> None:
        candidates = {item["threadId"]: item for item in self.cleanup_candidates()}
        candidate = candidates.get(thread_id)
        if not candidate or candidate["cleanupNonce"] != nonce:
            raise LedgerError("cleanup authorization is stale or invalid")
        now = iso_z(datetime.now(UTC))
        with self.transaction() as connection:
            self._event(
                connection,
                candidate["key"],
                "THREAD_ARCHIVED",
                nonce,
                {"threadId": thread_id, "cleanupNonce": nonce},
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
