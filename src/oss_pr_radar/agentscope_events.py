"""Durable, conditional GitHub event lane for the AgentScope contributor worker.

The lane deliberately contains no model invocation.  Polling, deduplication,
leases, queue import and wake delivery are durable so a process crash can only
delay work; it cannot duplicate a task.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

from .util import canonical_json

REPO = "agentscope-ai/agentscope"
EVENT_VERSION = "agentscope_event_v1"


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


@dataclass(frozen=True)
class PollResult:
    status: str
    events: tuple[dict[str, Any], ...] = ()
    pages: int = 0
    next_since: str | None = None
    etag: str | None = None
    last_modified: str | None = None


class GitHubIssuePoller:
    """Poll issue updates with ETag, since, pagination and an overlap window."""

    def __init__(
        self,
        state_path: Path,
        *,
        repo: str = REPO,
        transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], Any]] | None = None,
        overlap_seconds: int = 120,
        per_page: int = 100,
    ) -> None:
        self.state_path = Path(state_path)
        self.repo = repo
        self.auth_required = transport is None
        self.transport = transport or self._http_transport
        self.overlap_seconds = max(0, overlap_seconds)
        self.per_page = max(1, min(per_page, 100))

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}

    def _save(self, value: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.state_path)

    @staticmethod
    def _http_transport(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], Any]:
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8"))
                return response.status, dict(response.headers.items()), body
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return 304, dict(exc.headers.items()), None
            raise

    def poll(self, *, now: datetime | None = None) -> PollResult:
        state = self._load()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        previous = _parse_time(str(state.get("watermark") or ""))
        if previous is None:
            status, response_headers, payload = self.transport(
                f"https://api.github.com/repos/{self.repo}/issues?state=all&sort=updated&direction=desc&per_page={self.per_page}&page=1",
                self._headers(state, conditional=False, require_auth=self.auth_required),
            )
            if status != 200 or not isinstance(payload, list):
                raise RuntimeError(f"GitHub issues baseline failed: HTTP {status}")
            latest = max((_parse_time(str(item.get("updated_at") or "")) for item in payload if isinstance(item, dict)), default=None)
            watermark = (latest or current).isoformat().replace("+00:00", "Z")
            self._save({"schemaVersion": "agentscope_poll_v1", "watermark": watermark,
                        "gateEtag": response_headers.get("ETag"),
                        "gateLastModified": response_headers.get("Last-Modified"),
                        "updatedAt": current.isoformat().replace("+00:00", "Z")})
            return PollResult("baseline", pages=1, next_since=watermark,
                              etag=response_headers.get("ETag"), last_modified=response_headers.get("Last-Modified"))
        since = previous - timedelta(seconds=self.overlap_seconds) if previous else None
        gate_status, gate_headers, _gate_payload = self.transport(
            f"https://api.github.com/repos/{self.repo}/issues?state=all&sort=updated&direction=desc&per_page={self.per_page}&page=1",
            self._headers(state, conditional=True, require_auth=self.auth_required),
        )
        if gate_status == 304:
            return PollResult("not_modified", pages=1, etag=state.get("gateEtag"), last_modified=state.get("gateLastModified"))
        if gate_status != 200:
            raise RuntimeError(f"GitHub issues gate failed: HTTP {gate_status}")
        events: list[dict[str, Any]] = []
        page = 1
        max_updated = previous
        final_headers: dict[str, str] = {"ETag": gate_headers.get("ETag", ""), "Last-Modified": gate_headers.get("Last-Modified", "")}
        while True:
            query = f"?state=all&sort=updated&direction=asc&per_page={self.per_page}&page={page}"
            if since:
                query += "&since=" + since.isoformat().replace("+00:00", "Z")
            status, response_headers, payload = self.transport(
                f"https://api.github.com/repos/{self.repo}/issues{query}", self._headers(state, conditional=False, require_auth=self.auth_required)
            )
            final_headers.update(response_headers)
            if status == 304:
                return PollResult("not_modified", pages=page - 1, etag=state.get("etag"))
            if status != 200 or not isinstance(payload, list):
                raise RuntimeError(f"GitHub issues request failed: HTTP {status}")
            for item in payload:
                if not isinstance(item, dict):
                    continue
                updated = _parse_time(str(item.get("updated_at") or ""))
                if updated and (max_updated is None or updated > max_updated):
                    max_updated = updated
                if not self._is_relevant(item):
                    continue
                event = {
                    "version": EVENT_VERSION,
                    "repo": self.repo,
                    "number": item.get("number"),
                    "kind": "issue_update" if not item.get("pull_request") else "pr_update",
                    "updatedAt": item.get("updated_at"),
                    "issue": item,
                }
                event["eventId"] = f"github:{self.repo}:{item.get('number')}:{event['kind']}:{item.get('updated_at')}"
                events.append(event)
            if len(payload) < self.per_page:
                break
            page += 1
        watermark = (max_updated or current).isoformat().replace("+00:00", "Z")
        self._save({
            "schemaVersion": "agentscope_poll_v1",
            "watermark": watermark,
            "gateEtag": final_headers.get("ETag") or state.get("gateEtag"),
            "gateLastModified": final_headers.get("Last-Modified") or state.get("gateLastModified"),
            "updatedAt": current.isoformat().replace("+00:00", "Z"),
        })
        return PollResult("ok", tuple(events), page, watermark,
                          final_headers.get("ETag") or state.get("gateEtag"),
                          final_headers.get("Last-Modified") or state.get("gateLastModified"))

    @staticmethod
    def _headers(state: dict[str, Any], *, conditional: bool, require_auth: bool) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            try:
                token = subprocess.run(["gh", "auth", "token"], check=True, capture_output=True, text=True, timeout=3).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                token = ""
        if not token and require_auth:
            raise RuntimeError("GitHub authentication unavailable; refusing anonymous polling")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if conditional and state.get("gateEtag"):
            headers["If-None-Match"] = str(state["gateEtag"])
        if conditional and state.get("gateLastModified"):
            headers["If-Modified-Since"] = str(state["gateLastModified"])
        return headers

    @staticmethod
    def _is_relevant(item: dict[str, Any]) -> bool:
        title = str(item.get("title") or "").lower()
        body = str(item.get("body") or "").lower()
        labels = {str(label.get("name") or "").lower() for label in item.get("labels") or [] if isinstance(label, dict)}
        if item.get("pull_request"):
            author = str((item.get("user") or {}).get("login") or "").lower()
            return author == "oxygen56" or any(token in title for token in ("ci", "review", "conflict"))
        if any(token in title or token in body for token in ("documentation", "docs:", "dependency", "bump ")):
            return False
        return bool({"bug", "feature", "enhancement", "help wanted", "good first issue", "code"} & labels) or any(
            token in title or token in body for token in ("bug", "error", "crash", "exception", "regression", "implement")
        )


class EventLane:
    """SQLite event inbox with one writer, leases, priority and wake receipts."""

    def __init__(self, path: Path, *, lease_seconds: int = 120, ttl_seconds: int = 86400) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lease_seconds = max(1, lease_seconds)
        self.ttl_seconds = max(1, ttl_seconds)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS event_lane_events (
                    event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL, created_at REAL NOT NULL,
                    delivered_at REAL
                );
                CREATE TABLE IF NOT EXISTS event_lane_state (
                    key TEXT PRIMARY KEY, value_json TEXT NOT NULL
                );
            """)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    @contextmanager
    def writer(self) -> Iterable[sqlite3.Connection]:
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def append(self, event: dict[str, Any], *, priority: int = 0, now: float | None = None) -> bool:
        event_id = str(event.get("eventId") or _digest(event))
        payload = dict(event)
        payload["eventId"] = event_id
        with self.writer() as db:
            result = db.execute(
                "INSERT OR IGNORE INTO event_lane_events(event_id,payload_json,priority,created_at) VALUES(?,?,?,?)",
                (event_id, json.dumps(payload, sort_keys=True), int(priority), time.time() if now is None else now),
            )
            return result.rowcount == 1

    def append_many(self, events: Iterable[dict[str, Any]], *, priority: int = 0) -> int:
        return sum(self.append(event, priority=priority) for event in events)

    def append_or_handoff(
        self, event: dict[str, Any], *, priority: int = 0, handoff_path: Path | None = None
    ) -> str:
        """Persist to the ledger, or persist a handoff when another writer owns it."""
        try:
            return "ledger" if self.append(event, priority=priority) else "duplicate"
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or handoff_path is None:
                raise
            handoff_path.parent.mkdir(parents=True, exist_ok=True)
            with handoff_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"priority": priority, "event": event}, sort_keys=True) + "\n")
            return "handoff"

    def drain_handoff(self, handoff_path: Path) -> int:
        """Import a handoff exactly once; malformed lines remain for inspection."""
        try:
            lines = handoff_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return 0
        imported = 0
        remaining: list[str] = []
        for line in lines:
            try:
                value = json.loads(line)
                event = value["event"]
                priority = int(value.get("priority") or 0)
                self.append(event, priority=priority)
                imported += 1
            except (KeyError, TypeError, ValueError, json.JSONDecodeError, sqlite3.OperationalError):
                remaining.append(line)
        if remaining:
            handoff_path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
        else:
            handoff_path.unlink(missing_ok=True)
        return imported

    def claim(self, *, limit: int = 3, now: float | None = None) -> list[dict[str, Any]]:
        current = time.time() if now is None else now
        with self.writer() as db:
            rows = db.execute(
                "SELECT * FROM event_lane_events WHERE (status='pending' OR (status='leased' AND lease_until<=?)) "
                "ORDER BY priority DESC, created_at ASC LIMIT ?", (current, limit)
            ).fetchall()
            result = []
            until = current + self.lease_seconds
            for row in rows:
                db.execute("UPDATE event_lane_events SET status='leased',attempts=attempts+1,lease_until=? WHERE event_id=?", (until, row["event_id"]))
                item = json.loads(row["payload_json"])
                item["attempts"] = row["attempts"] + 1
                result.append(item)
            return result

    def ack(self, event_id: str) -> None:
        with self.writer() as db:
            db.execute("UPDATE event_lane_events SET status='delivered',delivered_at=?,lease_until=NULL WHERE event_id=?", (time.time(), event_id))

    def pending(self) -> int:
        with self.connect() as db:
            return int(db.execute("SELECT count(*) FROM event_lane_events WHERE status IN ('pending','leased')").fetchone()[0])

    def import_queue(self, queue: dict[str, Any], *, wake: Callable[[dict[str, Any]], Any] | None = None) -> dict[str, int]:
        """Import intents and PR follow-up records, then wake each unique task once."""
        imported = 0
        task_ids: set[str] = set()
        for key in ("intents", "prFollowups", "followups", "slowWorkRequests"):
            values = queue.get(key) or []
            if isinstance(values, dict):
                values = [values]
            for value in values:
                if not isinstance(value, dict):
                    continue
                task_id = str(value.get("taskId") or value.get("intentId") or value.get("threadId") or _digest(value))
                event = {"version": EVENT_VERSION, "kind": key, "taskId": task_id, "payload": value,
                         "eventId": f"queue:{_digest({key: key, 'taskId': task_id, 'payload': value})}"}
                if self.append(event, priority=100 if key != "intents" else 50):
                    imported += 1
                    task_ids.add(task_id)
        if wake:
            for task_id in sorted(task_ids):
                wake({"taskId": task_id, "reason": "queue_import"})
        return {"imported": imported, "woken": len(task_ids)}

    def expire_claims(self, *, now: float | None = None) -> int:
        current = time.time() if now is None else now
        with self.writer() as db:
            result = db.execute("UPDATE event_lane_events SET status='watch_only' WHERE status='pending' AND created_at<? AND json_extract(payload_json,'$.designWait')=1", (current - self.ttl_seconds,))
            return result.rowcount


def dispatch_once(
    lane: EventLane,
    deliver: Callable[[dict[str, Any]], Any],
    *,
    limit: int = 3,
    now: float | None = None,
) -> dict[str, int]:
    """Drain exactly once per event; failed delivery remains retryable."""
    claimed = lane.claim(limit=limit, now=now)
    delivered = 0
    for event in claimed:
        try:
            deliver(event)
        except Exception:
            continue
        lane.ack(str(event["eventId"]))
        delivered += 1
    return {"claimed": len(claimed), "delivered": delivered, "pending": lane.pending()}
