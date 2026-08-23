"""Durable, conditional GitHub event lane for the AgentScope contributor worker.

The lane deliberately contains no model invocation.  Polling, deduplication,
leases, queue import and wake delivery are durable so a process crash can only
delay work; it cannot duplicate a task.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import uuid
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
        details_transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], Any]] | None = None,
        overlap_seconds: int = 120,
        per_page: int = 100,
    ) -> None:
        self.state_path = Path(state_path)
        self.repo = repo
        self.auth_required = transport is None
        self.transport = transport or self._http_transport
        self.details_transport = details_transport or self.transport
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
            active_prs = [
                dict(item)
                for item in payload
                if isinstance(item, dict)
                and item.get("pull_request")
                and str((item.get("user") or {}).get("login") or "").casefold() == "oxygen56"
                and str(item.get("state") or "open").casefold() == "open"
            ]
            watermark = (latest or current).isoformat().replace("+00:00", "Z")
            self._save({"schemaVersion": "agentscope_poll_v1", "watermark": watermark,
                        "gateEtag": response_headers.get("ETag"),
                        "gateLastModified": response_headers.get("Last-Modified"),
                        "activePullRequests": active_prs,
                        "updatedAt": current.isoformat().replace("+00:00", "Z")})
            return PollResult("baseline", pages=1, next_since=watermark,
                              etag=response_headers.get("ETag"), last_modified=response_headers.get("Last-Modified"))
        since = previous - timedelta(seconds=self.overlap_seconds) if previous else None
        gate_status, gate_headers, _gate_payload = self.transport(
            f"https://api.github.com/repos/{self.repo}/issues?state=all&sort=updated&direction=desc&per_page={self.per_page}&page=1",
            self._headers(state, conditional=True, require_auth=self.auth_required),
        )
        if gate_status == 304:
            cached = [item for item in state.get("activePullRequests") or [] if isinstance(item, dict)]
            events = self._active_pull_events(cached, state)
            self._save(state)
            return PollResult(
                "ok" if events else "not_modified",
                tuple(events),
                pages=1,
                etag=state.get("gateEtag"),
                last_modified=state.get("gateLastModified"),
            )
        if gate_status != 200:
            raise RuntimeError(f"GitHub issues gate failed: HTTP {gate_status}")
        events: list[dict[str, Any]] = []
        active_cache = {
            f"{self.repo}#{item.get('number')}": dict(item)
            for item in state.get("activePullRequests") or []
            if isinstance(item, dict) and item.get("number") is not None
        }
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
            if status == 304:
                return PollResult("not_modified", pages=page - 1, etag=state.get("etag"))
            if status != 200 or not isinstance(payload, list):
                raise RuntimeError(f"GitHub issues request failed: HTTP {status}")
            for item in payload:
                if not isinstance(item, dict):
                    continue
                if (
                    item.get("pull_request")
                    and str((item.get("user") or {}).get("login") or "").casefold() == "oxygen56"
                    and str(item.get("state") or "open").casefold() == "open"
                ):
                    active_cache[f"{self.repo}#{item.get('number')}"] = dict(item)
                elif item.get("pull_request"):
                    active_cache.pop(f"{self.repo}#{item.get('number')}", None)
                item = self._enrich_pull_request(item, state)
                if item is None:
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
                if item.get("pull_request"):
                    event["prDetails"] = item.get("agentscopeDetails") or {}
                detail_suffix = (
                    f":{_digest(item.get('agentscopeDetails'))[:16]}"
                    if item.get("agentscopeDetails")
                    else ""
                )
                event["eventId"] = (
                    f"github:{self.repo}:{item.get('number')}:{event['kind']}:{item.get('updated_at')}"
                    f"{detail_suffix}"
                )
                events.append(event)
            if len(payload) < self.per_page:
                break
            page += 1
        watermark = (max_updated or current).isoformat().replace("+00:00", "Z")
        state.update({
            "schemaVersion": "agentscope_poll_v1",
            "watermark": watermark,
            "gateEtag": final_headers.get("ETag") or state.get("gateEtag"),
            "gateLastModified": final_headers.get("Last-Modified") or state.get("gateLastModified"),
            "updatedAt": current.isoformat().replace("+00:00", "Z"),
            "activePullRequests": list(active_cache.values()),
        })
        self._save(state)
        return PollResult("ok", tuple(events), page, watermark,
                          final_headers.get("ETag") or state.get("gateEtag"),
                          final_headers.get("Last-Modified") or state.get("gateLastModified"))

    def _active_pull_events(
        self, cached: list[dict[str, Any]], state: dict[str, Any]
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for original in cached:
            item = self._enrich_pull_request(dict(original), state)
            if item is None:
                continue
            if not self._is_relevant(item):
                continue
            number = item.get("number")
            kind = "pr_update"
            details = item.get("agentscopeDetails") or {}
            suffix = f":{_digest(details)[:16]}" if details else ""
            events.append(
                {
                    "version": EVENT_VERSION,
                    "repo": self.repo,
                    "number": number,
                    "kind": kind,
                    "updatedAt": item.get("updated_at"),
                    "issue": item,
                    "prDetails": details,
                    "eventId": f"github:{self.repo}:{number}:{kind}:{item.get('updated_at')}{suffix}",
                }
            )
        return events

    def _enrich_pull_request(self, item: dict[str, Any], state: dict[str, Any]) -> dict[str, Any] | None:
        """Fetch review/comment/check state for active Oxygen56 PRs incrementally."""
        if not item.get("pull_request"):
            return item
        author = str((item.get("user") or {}).get("login") or "").casefold()
        if author != "oxygen56" or str(item.get("state") or "open").casefold() != "open":
            return item
        number = item.get("number")
        if number is None:
            return item
        snapshot_key = f"{self.repo}#{number}"
        previous = (state.get("completePrSnapshots") or {}).get(snapshot_key)
        headers = self._headers(state, conditional=False, require_auth=self.auth_required)
        base = f"https://api.github.com/repos/{self.repo}"
        details: dict[str, Any] = {}
        requests = (
            ("pull", f"{base}/pulls/{number}"),
            ("reviews", f"{base}/pulls/{number}/reviews?per_page=100&page=1"),
            ("comments", f"{base}/issues/{number}/comments?per_page=100&page=1"),
        )
        complete = True
        for key, url in requests:
            try:
                status, _response_headers, body = self.details_transport(url, headers)
            except (OSError, RuntimeError, urllib.error.URLError):
                complete = False
                continue
            if status == 200:
                details[key] = body
            else:
                complete = False
        if isinstance(details.get("pull"), dict):
            for key in ("mergeable_state", "mergeable", "rebaseable", "comments", "review_comments"):
                if key in details["pull"]:
                    item[key] = details["pull"][key]
            head_sha = str((details["pull"].get("head") or {}).get("sha") or "")
            if head_sha:
                try:
                    status, _response_headers, body = self.details_transport(
                        f"{base}/commits/{head_sha}/check-runs?per_page=100&page=1", headers
                    )
                except (OSError, RuntimeError, urllib.error.URLError):
                    status, body = 0, None
                if status == 200:
                    details["checks"] = body
                else:
                    complete = False
            else:
                complete = False
        else:
            complete = False
        if not complete or not all(key in details for key in ("pull", "reviews", "comments", "checks")):
            return dict(previous) if isinstance(previous, dict) else None
        item["agentscopeDetails"] = details
        state.setdefault("completePrSnapshots", {})[snapshot_key] = dict(item)
        return item

    def full_reconcile(self, *, now: datetime | None = None) -> PollResult:
        """Run a non-conditional, all-pages reconciliation for missed updates."""
        state = self._load()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        events: list[dict[str, Any]] = []
        active_prs: list[dict[str, Any]] = []
        fingerprints = state.get("fullFingerprints") if isinstance(state.get("fullFingerprints"), dict) else {}
        next_fingerprints: dict[str, str] = {}
        page = 1
        max_updated = _parse_time(str(state.get("watermark") or ""))
        while True:
            query = f"?state=all&sort=updated&direction=asc&per_page={self.per_page}&page={page}"
            status, _headers, payload = self.transport(
                f"https://api.github.com/repos/{self.repo}/issues{query}",
                self._headers(state, conditional=False, require_auth=self.auth_required),
            )
            if status != 200 or not isinstance(payload, list):
                raise RuntimeError(f"GitHub full reconciliation failed: HTTP {status}")
            for original in payload:
                if not isinstance(original, dict):
                    continue
                if (
                    original.get("pull_request")
                    and str((original.get("user") or {}).get("login") or "").casefold() == "oxygen56"
                    and str(original.get("state") or "open").casefold() == "open"
                ):
                    active_prs.append(dict(original))
                item = self._enrich_pull_request(dict(original), state)
                updated = _parse_time(str(original.get("updated_at") or ""))
                if updated and (max_updated is None or updated > max_updated):
                    max_updated = updated
                if item is None or not self._is_relevant(item):
                    continue
                details = item.get("agentscopeDetails") or {}
                kind = "pr_update" if item.get("pull_request") else "issue_update"
                item_key = f"{self.repo}#{item.get('number')}"
                fingerprint = _digest({
                    "updatedAt": item.get("updated_at"), "state": item.get("state"),
                    "title": item.get("title"), "body": item.get("body"),
                    "details": details,
                })
                next_fingerprints[item_key] = fingerprint
                if not fingerprints:
                    continue
                if fingerprints.get(item_key) == fingerprint:
                    continue
                suffix = f":{_digest(details)[:16]}" if details else ""
                events.append({
                    "version": EVENT_VERSION, "repo": self.repo, "number": item.get("number"),
                    "kind": kind, "updatedAt": item.get("updated_at"), "issue": item,
                    "prDetails": details,
                    "eventId": f"github:{self.repo}:{item.get('number')}:{kind}:{item.get('updated_at')}{suffix}",
                })
            if len(payload) < self.per_page:
                break
            page += 1
        watermark = (max_updated or current).isoformat().replace("+00:00", "Z")
        state.update({
            "schemaVersion": "agentscope_poll_v1", "watermark": watermark,
            "updatedAt": current.isoformat().replace("+00:00", "Z"),
            "activePullRequests": active_prs,
            "fullFingerprints": next_fingerprints,
        })
        self._save(state)
        return PollResult("full_reconcile", tuple(events), page, watermark,
                          state.get("gateEtag"), state.get("gateLastModified"))

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
            try:
                stored = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", "gh:github.com", "-w"], check=True, capture_output=True, text=True, timeout=3).stdout.strip()
                if stored.startswith("go-keyring-base64:"):
                    token = base64.b64decode(stored.split(":", 1)[1]).decode("utf-8")
            except (OSError, ValueError, base64.binascii.Error, subprocess.SubprocessError):
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
            state = str(item.get("state") or "open").lower()
            merge_state = str(item.get("mergeable_state") or "").lower()
            try:
                comments = int(item.get("comments") or 0)
            except (TypeError, ValueError):
                comments = 0
            try:
                review_comments = int(item.get("review_comments") or 0)
            except (TypeError, ValueError):
                review_comments = 0
            return author == "oxygen56" or (
                state == "open"
                and (
                    any(token in title for token in ("ci", "review", "conflict"))
                    or comments > 0
                    or review_comments > 0
                    or merge_state in {"dirty", "blocked", "unknown"}
                )
            )
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
                    delivered_at REAL, lease_owner TEXT, lease_token TEXT
                );
                CREATE TABLE IF NOT EXISTS event_lane_state (
                    key TEXT PRIMARY KEY, value_json TEXT NOT NULL
                );
            CREATE TABLE IF NOT EXISTS event_lane_threads (
                    event_key TEXT PRIMARY KEY, thread_id TEXT NOT NULL,
                    turn_id TEXT, status TEXT NOT NULL, receipt_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS event_lane_turns (
                    event_id TEXT PRIMARY KEY, event_key TEXT NOT NULL,
                    thread_id TEXT NOT NULL DEFAULT '',
                    client_user_message_id TEXT NOT NULL,
                    turn_id TEXT, status TEXT NOT NULL DEFAULT 'reserved',
                    receipt_json TEXT NOT NULL DEFAULT '{}', created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS event_lane_turns_key
                    ON event_lane_turns(event_key, created_at);
                CREATE TABLE IF NOT EXISTS event_lane_public_work (
                    event_key TEXT PRIMARY KEY, status TEXT NOT NULL,
                    watch_until REAL, source TEXT NOT NULL DEFAULT 'event-lane',
                    updated_at REAL NOT NULL
                );
            """)
            columns = {str(row[1]) for row in db.execute("PRAGMA table_info(event_lane_events)")}
            if "lease_owner" not in columns:
                db.execute("ALTER TABLE event_lane_events ADD COLUMN lease_owner TEXT")
            if "lease_token" not in columns:
                db.execute("ALTER TABLE event_lane_events ADD COLUMN lease_token TEXT")

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
        if not payload.get("eventKey"):
            target = payload.get("targetKey") or payload.get("key")
            if not target and payload.get("repo") and payload.get("number") is not None:
                target = f"{payload['repo']}#{payload['number']}"
            if target:
                payload["eventKey"] = str(target)
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
            lock_path = handoff_path.with_suffix(handoff_path.suffix + ".lock")
            with lock_path.open("a+", encoding="utf-8") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                with handoff_path.open("a", encoding="utf-8") as stream:
                    stream.write(
                        json.dumps({"priority": priority, "event": event}, sort_keys=True) + "\n"
                    )
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return "handoff"

    def drain_handoff(self, handoff_path: Path) -> int:
        """Import a handoff exactly once; malformed lines remain for inspection."""
        lock_path = handoff_path.with_suffix(handoff_path.suffix + ".lock")
        with lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                handoff_path.replace(handoff_path.with_suffix(handoff_path.suffix + ".draining"))
            except FileNotFoundError:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                return 0
            draining = handoff_path.with_suffix(handoff_path.suffix + ".draining")
            try:
                lines = draining.read_text(encoding="utf-8").splitlines()
            except (FileNotFoundError, OSError):
                lines = []
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
                temporary = handoff_path.with_suffix(handoff_path.suffix + ".tmp")
                temporary.write_text("\n".join(remaining) + "\n", encoding="utf-8")
                os.replace(temporary, handoff_path)
            else:
                handoff_path.unlink(missing_ok=True)
            draining.unlink(missing_ok=True)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return imported

    def claim(
        self, *, limit: int = 3, owner: str = "event-lane", now: float | None = None
    ) -> list[dict[str, Any]]:
        current = time.time() if now is None else now
        with self.writer() as db:
            rows = db.execute(
                "SELECT * FROM event_lane_events WHERE (status='pending' OR (status='leased' AND lease_until<=?)) "
                "ORDER BY priority DESC, created_at ASC LIMIT ?", (current, limit)
            ).fetchall()
            result = []
            until = current + self.lease_seconds
            for row in rows:
                token = uuid.uuid4().hex
                db.execute(
                    "UPDATE event_lane_events SET status='leased',attempts=attempts+1,lease_until=?,"
                    "lease_owner=?,lease_token=? WHERE event_id=?",
                    (until, str(owner), token, row["event_id"]),
                )
                item = json.loads(row["payload_json"])
                item["attempts"] = row["attempts"] + 1
                item["leaseOwner"] = str(owner)
                item["leaseToken"] = token
                result.append(item)
            return result

    def ack(self, event_id: str, *, lease_token: str, owner: str = "event-lane") -> bool:
        with self.writer() as db:
            result = db.execute(
                "UPDATE event_lane_events SET status='delivered',delivered_at=?,lease_until=NULL,"
                "lease_owner=NULL,lease_token=NULL WHERE event_id=? AND status='leased' "
                "AND lease_owner=? AND lease_token=?",
                (time.time(), event_id, str(owner), str(lease_token)),
            )
            return result.rowcount == 1

    def pending(self) -> int:
        with self.connect() as db:
            return int(db.execute("SELECT count(*) FROM event_lane_events WHERE status IN ('pending','leased')").fetchone()[0])

    def handler_thread(self, event_key: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM event_lane_threads WHERE event_key=?", (event_key,)).fetchone()
        return dict(row) if row else None

    def handler_turn(self, event_id: str) -> dict[str, Any] | None:
        """Return the durable turn reservation for one event, if any."""
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM event_lane_turns WHERE event_id=?", (str(event_id),)
            ).fetchone()
        return dict(row) if row else None

    def reserve_handler_turn(
        self, event_key: str, event_id: str, client_user_message_id: str
    ) -> dict[str, Any]:
        """Reserve one independent turn idempotently before spawning a worker."""
        with self.writer() as db:
            row = db.execute(
                "SELECT * FROM event_lane_turns WHERE event_id=?", (str(event_id),)
            ).fetchone()
            if row:
                return dict(row)
            db.execute(
                "INSERT INTO event_lane_turns(event_id,event_key,client_user_message_id,created_at) "
                "VALUES(?,?,?,?)",
                (str(event_id), str(event_key), str(client_user_message_id), time.time()),
            )
            row = db.execute(
                "SELECT * FROM event_lane_turns WHERE event_id=?", (str(event_id),)
            ).fetchone()
        assert row is not None
        return dict(row)

    def bind_handler_turn(
        self,
        event_key: str,
        event_id: str,
        thread_id: str,
        turn_id: str,
        receipt: dict[str, Any],
        *,
        status: str = "started",
    ) -> None:
        """Bind a real thread/turn receipt without changing another event's turn."""
        with self.writer() as db:
            db.execute(
                "UPDATE event_lane_turns SET event_key=?,thread_id=?,turn_id=?,status=?,receipt_json=? "
                "WHERE event_id=?",
                (
                    str(event_key),
                    str(thread_id),
                    str(turn_id),
                    str(status),
                    json.dumps(receipt, sort_keys=True),
                    str(event_id),
                ),
            )
            db.execute(
                "INSERT INTO event_lane_threads(event_key,thread_id,turn_id,status,receipt_json) "
                "VALUES(?,?,?,?,?) ON CONFLICT(event_key) DO UPDATE SET "
                "thread_id=excluded.thread_id,turn_id=excluded.turn_id,status=excluded.status,"
                "receipt_json=excluded.receipt_json",
                (
                    str(event_key),
                    str(thread_id),
                    str(turn_id),
                    str(status),
                    json.dumps(receipt, sort_keys=True),
                ),
            )

    def bind_handler_thread(self, event_key: str, thread_id: str, turn_id: str, receipt: dict[str, Any], *, status: str = "started") -> None:
        with self.writer() as db:
            db.execute("INSERT INTO event_lane_threads(event_key,thread_id,turn_id,status,receipt_json) VALUES(?,?,?,?,?) ON CONFLICT(event_key) DO UPDATE SET thread_id=excluded.thread_id,turn_id=excluded.turn_id,status=excluded.status,receipt_json=excluded.receipt_json", (event_key, thread_id, turn_id, status, json.dumps(receipt, sort_keys=True)))

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
                target_key = str(value.get("key") or value.get("opportunityKey") or value.get("opportunity_key") or "")
                event = {"version": EVENT_VERSION, "kind": key, "taskId": task_id,
                         "targetKey": target_key, "repo": value.get("repo"), "payload": value,
                         "eventId": f"queue:{_digest({key: key, 'taskId': task_id, 'payload': value})}"}
                if value.get("designWait") or value.get("design_wait"):
                    event["designWait"] = True
                if value.get("priority") is not None:
                    event["priority"] = value.get("priority")
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
            rows = db.execute(
                "SELECT event_id,payload_json FROM event_lane_events WHERE status='pending' "
                "AND json_extract(payload_json,'$.designWait')=1 AND "
                "(created_at<? OR (json_extract(payload_json,'$.designWaitUntil') IS NOT NULL "
                "AND json_extract(payload_json,'$.designWaitUntil')<=?))",
                (current - self.ttl_seconds, current),
            ).fetchall()
            for row in rows:
                db.execute("UPDATE event_lane_events SET status='watch_only' WHERE event_id=?", (row["event_id"],))
                payload = json.loads(row["payload_json"])
                event_key = str(payload.get("eventKey") or payload.get("targetKey") or "")
                if not event_key and payload.get("repo") and payload.get("number") is not None:
                    event_key = f"{payload['repo']}#{payload['number']}"
                if event_key:
                    db.execute(
                        "UPDATE event_lane_threads SET status='watch_only' WHERE event_key=?",
                        (event_key,),
                    )
                    db.execute(
                        "UPDATE event_lane_public_work SET status='watch_only',updated_at=? WHERE event_key=?",
                        (current, event_key),
                    )
            return len(rows)

    def mark_design_wait(self, event_id: str) -> bool:
        """Persist the machine-readable 24h design wait state."""
        with self.writer() as db:
            row = db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?", (str(event_id),)
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload_json"])
            payload["designWait"] = True
            db.execute(
                "UPDATE event_lane_events SET payload_json=? WHERE event_id=?",
                (json.dumps(payload, sort_keys=True), str(event_id)),
            )
            event_key = str(payload.get("eventKey") or payload.get("targetKey") or "")
            if event_key:
                db.execute(
                    "INSERT INTO event_lane_public_work(event_key,status,watch_until,updated_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(event_key) DO UPDATE SET status='design_wait',updated_at=excluded.updated_at",
                    (event_key, "design_wait", time.time() + self.ttl_seconds, time.time()),
                )
            return True

    def active_work_keys(self) -> set[str]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT event_key FROM event_lane_threads WHERE status IN ('reserved','started')"
            ).fetchall()
            public = db.execute(
                "SELECT event_key FROM event_lane_public_work WHERE status IN ('active','design_wait') "
                "AND (watch_until IS NULL OR watch_until>?)", (time.time(),)
            ).fetchall()
        return {str(row["event_key"]) for row in rows + public if row["event_key"]}

    def public_status(self, event_key: str) -> str | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT status FROM event_lane_public_work WHERE event_key=?", (str(event_key),)
            ).fetchone()
        return str(row["status"]) if row else None

    def register_public_work(self, event_key: str, *, status: str = "active", watch_until: float | None = None, source: str = "event-lane") -> None:
        with self.writer() as db:
            db.execute(
                "INSERT INTO event_lane_public_work(event_key,status,watch_until,source,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(event_key) DO UPDATE SET status=excluded.status,watch_until=excluded.watch_until,"
                "source=excluded.source,updated_at=excluded.updated_at",
                (str(event_key), str(status), watch_until, str(source), time.time()),
            )

    def clear_public_work(self, event_key: str) -> None:
        with self.writer() as db:
            db.execute("DELETE FROM event_lane_public_work WHERE event_key=?", (str(event_key),))

    def state_value(self, key: str) -> Any:
        with self.connect() as db:
            row = db.execute("SELECT value_json FROM event_lane_state WHERE key=?", (str(key),)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["value_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def set_state_value(self, key: str, value: Any) -> None:
        with self.writer() as db:
            db.execute(
                "INSERT INTO event_lane_state(key,value_json) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
                (str(key), json.dumps(value, sort_keys=True)),
            )


def dispatch_once(
    lane: EventLane,
    deliver: Callable[[dict[str, Any]], Any],
    *,
    limit: int = 3,
    owner: str = "event-lane",
    now: float | None = None,
) -> dict[str, int]:
    """Drain exactly once per event; failed delivery remains retryable."""
    claimed = lane.claim(limit=limit, owner=owner, now=now)
    delivered = 0
    for event in claimed:
        try:
            deliver(event)
        except Exception:
            continue
        if lane.ack(
            str(event["eventId"]),
            lease_token=str(event.get("leaseToken") or ""),
            owner=owner,
        ):
            delivered += 1
    return {"claimed": len(claimed), "delivered": delivered, "pending": lane.pending()}
