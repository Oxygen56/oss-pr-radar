"""Local authoritative lifecycle ledger with transactional leases and receipts."""

from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from .util import canonical_json, iso_z, parse_time, sha256_text

STAGES = (
    "DISCOVERED",
    "EVIDENCE_COMPLETE",
    "RANKED",
    "QUALIFIED",
    "LEASED",
    "DISPATCHED",
    "AUDIT_PASS",
    "AUDIT_NO_GO",
    "FIX_READY",
    "PR_OPEN",
    "CI_GREEN",
    "MAINTAINER_ACCEPTED",
    "MERGED",
    "CLOSED",
)
TERMINAL_STAGES = {"AUDIT_NO_GO", "MERGED", "CLOSED"}


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
                """
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(intents)")}
            if "title_time" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN title_time TEXT")
            if "title_synced_state" not in columns:
                connection.execute("ALTER TABLE intents ADD COLUMN title_synced_state TEXT")

    def enqueue(self, intent: dict[str, Any]) -> bool:
        now = iso_z(datetime.now(UTC))
        key = str(intent["key"])
        payload = canonical_json(intent)
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT status FROM intents WHERE intent_id=?", (intent["intentId"],)
            ).fetchone()
            if existing:
                return False
            duplicate = connection.execute(
                """SELECT intent_id FROM intents
                   WHERE opportunity_key=?
                     AND (
                       (status IN ('PENDING','LEASED') AND expires_at>?)
                       OR status IN ('DISPATCHED','COMPLETED')
                     )
                   LIMIT 1""",
                (key, now),
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
                       WHERE status IN ('LEASED','DISPATCHED')
                         AND intent_id<>?
                         AND (status='DISPATCHED' OR lease_until>?)""",
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
            if row["status"] != "LEASED" or row["lease_owner"] != owner:
                raise LedgerError("intent is not leased by this owner")
            if not row["lease_until"] or parse_time(row["lease_until"]) <= now_dt:
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

    def title_candidates(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.title,o.stage,o.updated_at,i.thread_id,i.title_time,
                          i.title_synced_state,
                          CASE
                            WHEN o.stage='MERGED' THEN 'MERGED'
                            WHEN o.stage IN ('PR_OPEN','CI_GREEN','MAINTAINER_ACCEPTED','CLOSED')
                              THEN 'PR_OPEN'
                            WHEN EXISTS (
                              SELECT 1 FROM publication_requests p
                              WHERE p.opportunity_key=o.key
                                AND p.status IN ('PENDING','GRANTED')
                            ) THEN 'PUBLICATION_REQUEST'
                            WHEN o.stage='FIX_READY' THEN 'FIX_READY'
                            ELSE 'GO'
                          END AS desired_state
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE i.thread_id IS NOT NULL AND o.stage<>'AUDIT_NO_GO'
                     AND i.status IN ('DISPATCHED','COMPLETED')
                   ORDER BY o.updated_at"""
            ).fetchall()
        values = []
        for row in rows:
            if row["title_synced_state"] == row["desired_state"]:
                continue
            values.append(
                {
                    "key": row["key"],
                    "title": row["title"],
                    "threadId": row["thread_id"],
                    "titleTime": row["title_time"],
                    "titleState": row["desired_state"],
                    "titleNonce": sha256_text(
                        f"{row['key']}|{row['thread_id']}|{row['desired_state']}|{row['updated_at']}"
                    ),
                }
            )
        return values

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
            row = connection.execute("SELECT key FROM opportunities WHERE key=?", (key,)).fetchone()
            if row is None:
                raise LedgerError("opportunity not found")
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
            if stage in {"QUALIFIED", "FIX_READY", "AUDIT_NO_GO"}:
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
                """SELECT payload_json,status,issued_at,lease_until FROM intents
                   WHERE status IN ('PENDING','LEASED') AND expires_at>?
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
            values.append(
                json.loads(row["payload_json"])
                | {
                    "ledgerStatus": row["status"],
                    "pendingSince": row["issued_at"],
                    "pendingAgeMinutes": age_minutes,
                    "leaseStale": lease_stale,
                }
            )
        return values

    def pending_alerts(self, *, min_age_minutes: int = 70) -> list[dict[str, Any]]:
        threshold = max(60, min(int(min_age_minutes), 24 * 60))
        alerts: list[dict[str, Any]] = []
        for item in self.pending():
            code = None
            if item.get("leaseStale"):
                code = "DISPATCH_LEASE_STALE"
            elif int(item.get("pendingAgeMinutes") or 0) >= threshold:
                code = "DISPATCH_PENDING_OVER_ONE_CYCLE"
            if code:
                alerts.append(item | {"alertCode": code, "thresholdMinutes": threshold})
        return alerts

    def active_dispatch_count(self, *, exclude_intent_id: str | None = None) -> int:
        now = iso_z(datetime.now(UTC))
        query = """SELECT COUNT(*) FROM intents
                   WHERE status IN ('LEASED','DISPATCHED')
                     AND (status='DISPATCHED' OR lease_until>?)"""
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
                         AND e.event_type='THREAD_RECOVERY_RESERVED'
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
                   AND event_type='THREAD_RECOVERY_RESERVED'""",
                (candidate["key"],),
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
                           i.worktree_path,i.status,i.payload_json
                    FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                    WHERE {" AND ".join(clauses)}
                    ORDER BY i.updated_at DESC LIMIT 1""",
                tuple(params),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        return {
            "key": row["key"],
            "stage": row["stage"],
            "issueUrl": row["issue_url"],
            "intentId": row["intent_id"],
            "threadId": row["thread_id"],
            "worktreePath": row["worktree_path"],
            "intentStatus": row["status"],
            "autoSubmitAuthorized": payload.get("autoSubmitAuthorized") is True,
            "publicationMode": payload.get("publicationMode"),
            "publicSubmissionAllowed": payload.get("publicSubmissionAllowed") is True,
            "authorizationSource": payload.get("authorizationSource"),
        }

    def has_live_handoff(self, *, issue_url: str) -> bool:
        now = iso_z(datetime.now(UTC))
        with self.connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM opportunities o
                   JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.issue_url=? AND i.status='LEASED'
                     AND i.expires_at>? AND i.lease_until>?
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
            }
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
                "SELECT opportunity_key FROM publication_requests WHERE request_id=?",
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

    def tracked_pull_requests(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT o.key,o.stage,p.pr_url,p.permit_id,p.updated_at
                   FROM opportunities o
                   JOIN publication_requests r ON r.opportunity_key=o.key
                   JOIN publication_permits p ON p.request_id=r.request_id
                   WHERE p.status='CONSUMED' AND p.pr_url IS NOT NULL
                     AND o.stage NOT IN ('MERGED','CLOSED')
                   ORDER BY p.updated_at"""
            ).fetchall()
        return [dict(row) for row in rows]

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
                """UPDATE publication_requests SET status='CONSUMED',updated_at=?
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
                """UPDATE publication_requests SET status='CONSUMED',updated_at=?
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
                """SELECT o.key,o.stage,o.updated_at,i.thread_id
                   FROM opportunities o JOIN intents i ON i.opportunity_key=o.key
                   WHERE o.stage='AUDIT_NO_GO' AND i.thread_id IS NOT NULL
                     AND NOT EXISTS (
                       SELECT 1 FROM events e
                       WHERE e.opportunity_key=o.key AND e.event_type='THREAD_ARCHIVED'
                     )
                   ORDER BY o.updated_at"""
            ).fetchall()
        return [
            {
                "key": row["key"],
                "threadId": row["thread_id"],
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
                thread_id,
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
