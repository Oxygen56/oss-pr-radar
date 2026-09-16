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
import re
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
EXTERNAL_RESOLUTION_REASONS = frozenset(
    {"issue_closed", "issue_assigned_external", "external_claim_comment"}
)
_NEGATED_EXTERNAL_CLAIM_RE = re.compile(
    r"\b(?:i|we)\b.{0,20}\b(?:can't|cannot|can not|won['’]?t|will not|would not|do not|don't|never)\b",
    re.IGNORECASE | re.DOTALL,
)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _valid_machine_outcome_receipt(receipt: dict[str, Any], event_id: str, event_key: str) -> bool:
    """Validate the private outcome shape without importing the worker."""

    # A valid payload inside a failed/interrupted bridge wrapper is not a
    # completed result.  Keep the recovery gate conservative so it can retry
    # that stale turn instead of silently treating it as settled.
    if str(receipt.get("turnStatus") or "") != "completed":
        return False
    outcome = receipt.get("outcome")
    if not isinstance(outcome, dict) or outcome.get("error"):
        return False
    if (
        outcome.get("schemaVersion") != "agentscope_event_outcome_v1"
        or str(outcome.get("eventId") or "") != str(event_id)
        or str(outcome.get("publicKey") or "") != str(event_key)
    ):
        return False
    state = str(outcome.get("state") or "")
    if state not in {"no_action", "claimed_or_pr", "design_wait"}:
        return False
    expected = {"schemaVersion", "eventId", "publicKey", "state"}
    if state == "design_wait":
        expected.update({"waitStartedAt", "waitUntil"})
    if set(outcome) != expected:
        return False
    if state == "design_wait":
        started = _parse_time(str(outcome.get("waitStartedAt") or ""))
        until = _parse_time(str(outcome.get("waitUntil") or ""))
        if started is None or until is None or until < started:
            return False
        if until - started > timedelta(hours=24):
            return False
    return True


def _event_bridge_process_alive(value: object) -> bool:
    """Return true only for a live detached event bridge worker."""
    try:
        pid = int(value)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except OSError:
        return False
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        # On platforms without ps, preserve a demonstrably live process.
        return True
    command = result.stdout if result.returncode == 0 else ""
    return "local_dispatch_bridge.py" in command and "-event-worker" in command


_RECEIPT_HISTORY_LIMIT = 8
_RECEIPT_HISTORY_ITEM_MAX_BYTES = 8192
_RECOVERY_RETRY_TERMINAL_REASONS = frozenset(
    {
        "handler_turn_timeout",
        "handler_reservation_timeout_retry",
        "handler_start_exception",
        "handler_start_retryable",
        "handler_start_failed",
        "central_task_thread_receipt_mismatch",
        "outcome_recovery_attempts_exhausted",
    }
)


def _receipt_object(value: object) -> dict[str, Any]:
    """Decode a persisted turn receipt without letting corrupt JSON escape."""
    if isinstance(value, dict):
        return dict(value)
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


def advance_model_fallback(
    event: dict[str, Any],
    *,
    model: str,
    candidates: tuple[str, ...],
    error: object,
    now: float | None = None,
) -> tuple[dict[str, Any], str]:
    """Record one actual failed model and select the next unused candidate."""
    ordered = tuple(str(item).strip() for item in candidates if str(item).strip())
    selected = str(model).strip()
    if not ordered or len(set(ordered)) != len(ordered) or not selected:
        raise ValueError("invalid transient model fallback candidates")
    current = time.time() if now is None else float(now)
    updated = dict(event)
    prior = updated.get("modelFallback")
    prior = dict(prior) if isinstance(prior, dict) else {}
    history = prior.get("history")
    history = [dict(item) for item in history if isinstance(item, dict)] if isinstance(history, list) else []
    attempted = [str(item.get("model") or "") for item in history]
    if selected not in attempted:
        history.append(
            {
                "model": selected,
                "failedAt": datetime.fromtimestamp(current, UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "error": str(error)[:500],
            }
        )
    history = history[-(len(ordered) + 1) :]
    attempted_set = {
        str(item.get("model") or "") for item in history if isinstance(item, dict)
    }
    next_index = next(
        (index for index, candidate in enumerate(ordered) if candidate not in attempted_set),
        len(ordered),
    )
    state = "exhausted" if next_index >= len(ordered) else "pending"
    updated["modelFallback"] = {
        "schemaVersion": "oss_pr_radar_event_model_fallback_v1",
        "candidates": list(ordered),
        "nextIndex": next_index,
        "history": history,
        "state": state,
    }
    return updated, state


def _receipt_has_live_bridge(receipt: dict[str, Any]) -> bool:
    """Fail closed when any known bridge PID is still a live event worker."""
    for field in ("workerPid", "pid", "processId", "launchPid"):
        if receipt.get(field) and _event_bridge_process_alive(receipt.get(field)):
            return True
    return False


def _bounded_receipt_history(receipt: dict[str, Any], *, captured_at: float) -> list[dict[str, Any]]:
    """Keep a small immutable trail when a recovery turn is retried."""
    prior = receipt.get("receiptHistory")
    history: list[dict[str, Any]] = []
    if isinstance(prior, list):
        for item in prior[-_RECEIPT_HISTORY_LIMIT :]:
            if not isinstance(item, dict):
                continue
            try:
                item_encoded = json.dumps(item, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                item_encoded = "{}"
            if len(item_encoded.encode("utf-8")) > _RECEIPT_HISTORY_ITEM_MAX_BYTES:
                item = {
                    "truncated": True,
                    "sha256": hashlib.sha256(item_encoded.encode("utf-8")).hexdigest(),
                }
            history.append(item)
    snapshot = {key: value for key, value in receipt.items() if key != "receiptHistory"}
    try:
        encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        encoded = "{}"
        snapshot = {"truncated": True}
    if len(encoded.encode("utf-8")) > _RECEIPT_HISTORY_ITEM_MAX_BYTES:
        snapshot = {
            "truncated": True,
            "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        }
    captured = datetime.fromtimestamp(captured_at, UTC).isoformat().replace("+00:00", "Z")
    return (history + [{"capturedAt": captured, "receipt": snapshot}])[-_RECEIPT_HISTORY_LIMIT:]


def _merge_receipt_history(
    existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    """Carry retry history through the bridge's replacement receipt."""
    merged = dict(incoming)
    existing_history = existing.get("receiptHistory")
    incoming_history = merged.get("receiptHistory")
    if isinstance(existing_history, list):
        combined = [item for item in existing_history if isinstance(item, dict)]
        if isinstance(incoming_history, list):
            combined.extend(item for item in incoming_history if isinstance(item, dict))
        # Reconciliation can bind the same terminal file twice (first as
        # completed, then as needs_reconcile).  De-duplicate identical history
        # entries so that bounded storage retains distinct attempts.
        unique: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in combined:
            try:
                marker = json.dumps(item, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                marker = repr(item)
            if marker in seen:
                continue
            seen.add(marker)
            unique.append(item)
        merged["receiptHistory"] = unique[-_RECEIPT_HISTORY_LIMIT:]
    return merged


def _stable_records(
    value: Any, keys: tuple[str, ...], sort_keys: tuple[str, ...]
) -> list[dict[str, Any]]:
    rows = value if isinstance(value, list) else []
    projected = [{key: row.get(key) for key in keys} for row in rows if isinstance(row, dict)]
    return sorted(projected, key=lambda row: tuple(str(row.get(key) or "") for key in sort_keys))


def _github_material_projection(event: dict[str, Any]) -> dict[str, Any]:
    """Keep only stable PR review/comment/check material in event identity."""
    details = event.get("prDetails") if isinstance(event.get("prDetails"), dict) else {}
    if not details:
        issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
        details = (
            issue.get("agentscopeDetails")
            if isinstance(issue.get("agentscopeDetails"), dict)
            else {}
        )
    if not details:
        return {}
    pull = details.get("pull") if isinstance(details.get("pull"), dict) else {}
    # GitHub computes mergeability asynchronously, so unknown/clean and the
    # companion booleans can flap without any actionable PR change.  Keep the
    # full values in the payload, but project only an explicit conflict into
    # wake identity.
    pull_keys = (
        "state",
        "draft",
        "updated_at",
        "comments",
        "review_comments",
    )
    pull_projection = {key: pull.get(key) for key in pull_keys} if pull else {}
    if pull:
        pull_projection["merge_conflict"] = (
            str(pull.get("mergeable_state") or "").casefold() == "dirty"
        )
        head = pull.get("head") if isinstance(pull.get("head"), dict) else {}
        pull_projection["head"] = {
            "sha": head.get("sha"),
            "ref": head.get("ref"),
            "user": {
                "login": str(
                    ((head.get("user") if isinstance(head.get("user"), dict) else {}) or {}).get(
                        "login"
                    )
                    or ""
                )
            },
        }
    reviews = _stable_records(
        details.get("reviews"),
        ("id", "state", "submitted_at", "commit_id", "body", "updated_at"),
        ("id", "updated_at", "submitted_at"),
    )
    comments = _stable_records(
        details.get("comments"),
        ("id", "created_at", "updated_at", "body", "user"),
        ("id", "updated_at", "created_at"),
    )
    comments = [
        {
            **{key: value for key, value in row.items() if key != "user"},
            "user": {
                "login": str(
                    ((row.get("user") if isinstance(row.get("user"), dict) else {}) or {}).get(
                        "login"
                    )
                    or ""
                )
            },
        }
        for row in comments
    ]
    checks = details.get("checks") if isinstance(details.get("checks"), dict) else {}
    check_runs = _stable_records(
        checks.get("check_runs"),
        ("id", "name", "head_sha", "status", "conclusion", "started_at", "completed_at", "app"),
        ("id", "name"),
    )
    check_runs = [
        {
            **{key: value for key, value in row.items() if key != "app"},
            "app": {
                "slug": str(
                    ((row.get("app") if isinstance(row.get("app"), dict) else {}) or {}).get("slug")
                    or ""
                )
            },
        }
        for row in check_runs
    ]
    material = {
        "pull": pull_projection,
        "reviews": reviews,
        "comments": comments,
        "checks": check_runs,
    }
    return material if any(material.values()) else {}


def _github_material_digest(event: dict[str, Any]) -> str:
    material = _github_material_projection(event)
    return _digest(material) if material else ""


PASSING_CHECK_CONCLUSIONS = {"success", "neutral", "skipped"}
ISSUE_STARVATION_SECONDS = 5 * 60
AGED_ISSUE_PRIORITY = 210
RECOVERY_PRIORITY = 300

# Poll health is intentionally a small, bounded journal in the existing poll
# state file. Three consecutive failures expose a sustained outage while one
# transient network error remains recoverable.
POLL_HEALTH_SCHEMA = "event_poll_health_v1"
POLL_FAILURE_WINDOW_SECONDS = 15 * 60
POLL_FAILURE_WINDOW_MAX_ATTEMPTS = 20
POLL_DEGRADED_CONSECUTIVE_FAILURES = 3
POLL_DEGRADED_MIN_WINDOW_ATTEMPTS = 3
POLL_DEGRADED_FAILURE_RATE = 0.5
POLL_DETAIL_INCOMPLETE_ERROR = "GitHub PR detail refresh incomplete"


def _github_check_wake_projection(check_runs: Any) -> dict[str, Any]:
    """Collapse noisy CI progress into actionable wake phases."""

    rows = [
        row for row in (check_runs if isinstance(check_runs, list) else []) if isinstance(row, dict)
    ]
    if not rows:
        return {"phase": "no_checks"}
    failures = [
        {
            "id": row.get("id"),
            "name": row.get("name"),
            "head_sha": row.get("head_sha"),
            "conclusion": row.get("conclusion"),
        }
        for row in rows
        if row.get("conclusion")
        and str(row.get("conclusion") or "").casefold() not in PASSING_CHECK_CONCLUSIONS
    ]
    if failures:
        return {
            "phase": "failure",
            "failures": sorted(
                failures,
                key=lambda row: (str(row.get("id") or ""), str(row.get("name") or "")),
            ),
        }
    if all(
        str(row.get("status") or "").casefold() == "completed"
        and str(row.get("conclusion") or "").casefold() in PASSING_CHECK_CONCLUSIONS
        for row in rows
    ):
        return {"phase": "success"}
    return {"phase": "active"}


def _github_wake_projection(event: dict[str, Any]) -> dict[str, Any]:
    """Keep full payload evidence while reducing only the dispatch identity."""

    material = _github_material_projection(event)
    if not material or str(event.get("kind") or "") != "pr_update":
        return material
    return {
        **material,
        "checks": _github_check_wake_projection(material.get("checks")),
    }


def _github_wake_digest(event: dict[str, Any]) -> str:
    material = _github_wake_projection(event)
    return _digest(material) if material else ""


def github_event_effective_time(event: dict[str, Any]) -> datetime | None:
    """Return the latest stable time represented by a GitHub event."""
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    values = [event.get("updatedAt"), issue.get("updated_at")]
    material = _github_material_projection(event)
    pull = material.get("pull") if isinstance(material.get("pull"), dict) else {}
    values.append(pull.get("updated_at"))
    for row in material.get("reviews") or []:
        values.extend((row.get("updated_at"), row.get("submitted_at")))
    for row in material.get("comments") or []:
        values.extend((row.get("updated_at"), row.get("created_at")))
    for row in material.get("checks") or []:
        values.extend((row.get("completed_at"), row.get("started_at")))
    parsed = [_parse_time(str(value)) for value in values if value]
    parsed = [value for value in parsed if value is not None]
    return max(parsed) if parsed else None


def _github_event_id(event: dict[str, Any]) -> str:
    base = f"github:{event.get('repo')}:{event.get('number')}:{event.get('kind')}:{event.get('updatedAt')}"
    wake_digest = _github_wake_digest(event)
    return f"{base}:{wake_digest}" if wake_digest else base


def _github_event_identity(event: dict[str, Any]) -> tuple[str, str, str, str, str] | None:
    """Return stable GitHub identity fields, including material revision."""
    if not str(event.get("eventId") or "").startswith("github:") and not event.get("repo"):
        return None
    repo = str(event.get("repo") or "")
    number = str(event.get("number") or "")
    kind = str(event.get("kind") or "")
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    updated = str(event.get("updatedAt") or issue.get("updated_at") or "")
    if not repo or not number or not kind or not updated:
        return None
    return repo, number, kind, updated, _github_wake_digest(event)


@dataclass(frozen=True)
class PollResult:
    status: str
    events: tuple[dict[str, Any], ...] = ()
    pages: int = 0
    next_since: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    error: str | None = None


class GitHubIssuePoller:
    """Poll issue updates with ETag, since, pagination and an overlap window."""

    def __init__(
        self,
        state_path: Path,
        *,
        repo: str = REPO,
        transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], Any]] | None = None,
        details_transport: Callable[[str, dict[str, str]], tuple[int, dict[str, str], Any]]
        | None = None,
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
        self._incomplete_details = False

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

    @staticmethod
    def _stamp(value: datetime) -> str:
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _error_text(exc: BaseException | str) -> str:
        if isinstance(exc, BaseException):
            message = str(exc).strip()
            text = f"{type(exc).__name__}:{message}" if message else type(exc).__name__
        else:
            text = str(exc)
        return text[:400]

    @staticmethod
    def _recoverable_poll_error(exc: BaseException) -> bool:
        if isinstance(exc, urllib.error.HTTPError):
            return exc.code in {408, 429} or 500 <= exc.code <= 599
        if isinstance(exc, (OSError, TimeoutError, urllib.error.URLError)):
            return True
        if isinstance(exc, RuntimeError):
            match = re.search(r"\bHTTP (\d{3})\b", str(exc))
            if match:
                status = int(match.group(1))
                return status in {408, 429} or 500 <= status <= 599
        return False

    def _record_poll_health(
        self,
        *,
        now: datetime,
        success: bool,
        error: BaseException | str | None = None,
    ) -> None:
        """Persist poll liveness without changing the event watermark."""
        current = now.astimezone(UTC)
        state = self._load()
        raw_window = state.get("failureWindow")
        window: list[dict[str, Any]] = []
        if isinstance(raw_window, list):
            for entry in raw_window:
                if not isinstance(entry, dict) or not isinstance(entry.get("ok"), bool):
                    continue
                at = _parse_time(str(entry.get("at") or ""))
                if at is None or at > current:
                    continue
                if (current - at).total_seconds() <= POLL_FAILURE_WINDOW_SECONDS:
                    window.append({"at": self._stamp(at), "ok": bool(entry["ok"])})
        window.append({"at": self._stamp(current), "ok": bool(success)})
        window = window[-POLL_FAILURE_WINDOW_MAX_ATTEMPTS:]
        attempts = len(window)
        failures = sum(1 for entry in window if not entry["ok"])
        rate = round(failures / attempts, 3) if attempts else 0.0
        try:
            prior_consecutive = max(0, int(state.get("consecutiveFailures") or 0))
        except (TypeError, ValueError):
            prior_consecutive = 0
        consecutive = 0 if success else prior_consecutive + 1
        degraded = not success and (
            consecutive >= POLL_DEGRADED_CONSECUTIVE_FAILURES
            or (
                attempts >= POLL_DEGRADED_MIN_WINDOW_ATTEMPTS and rate >= POLL_DEGRADED_FAILURE_RATE
            )
        )
        stamp = self._stamp(current)
        state.setdefault("schemaVersion", "agentscope_poll_v1")
        state["pollHealthSchema"] = POLL_HEALTH_SCHEMA
        state["lastAttemptAt"] = stamp
        state["failureWindow"] = window
        state["failureWindowAttempts"] = attempts
        state["failureWindowFailures"] = failures
        state["failureRate"] = rate
        state["consecutiveFailures"] = consecutive
        if success:
            state["lastSuccessAt"] = stamp
            state["lastError"] = None
            state["pollHealthStatus"] = "healthy"
        else:
            state["lastFailureAt"] = stamp
            state["lastError"] = self._error_text(error or "poll failed")
            state["pollHealthStatus"] = "degraded" if degraded else "recovering"
        self._save(state)

    def poll(self, *, now: datetime | None = None) -> PollResult:
        """Poll once and persist health even when GitHub is unavailable."""
        current = (now or datetime.now(UTC)).astimezone(UTC)
        try:
            result = self._poll_once(now=current)
        except Exception as exc:  # noqa: BLE001 - polling is an isolation boundary
            error = self._error_text(exc)
            self._record_poll_health(now=current, success=False, error=error)
            if not self._recoverable_poll_error(exc):
                raise
            state = self._load()
            return PollResult(
                "degraded",
                pages=0,
                next_since=str(state.get("watermark") or "") or None,
                error=error,
            )
        if result.status == "degraded" or self._incomplete_details:
            error = result.error or POLL_DETAIL_INCOMPLETE_ERROR
            self._record_poll_health(now=current, success=False, error=error)
            return PollResult(
                "degraded",
                (),
                pages=result.pages,
                next_since=result.next_since,
                etag=result.etag,
                last_modified=result.last_modified,
                error=error,
            )
        self._record_poll_health(now=current, success=True)
        return result

    def _poll_once(self, *, now: datetime | None = None) -> PollResult:
        self._incomplete_details = False
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
            latest = max(
                (
                    _parse_time(str(item.get("updated_at") or ""))
                    for item in payload
                    if isinstance(item, dict)
                ),
                default=None,
            )
            active_prs = [
                dict(item)
                for item in payload
                if isinstance(item, dict)
                and item.get("pull_request")
                and str((item.get("user") or {}).get("login") or "").casefold() == "oxygen56"
                and str(item.get("state") or "open").casefold() == "open"
            ]
            watermark = (latest or current).isoformat().replace("+00:00", "Z")
            self._save(
                {
                    "schemaVersion": "agentscope_poll_v1",
                    "watermark": watermark,
                    "gateEtag": response_headers.get("ETag"),
                    "gateLastModified": response_headers.get("Last-Modified"),
                    "activePullRequests": active_prs,
                    "updatedAt": current.isoformat().replace("+00:00", "Z"),
                }
            )
            return PollResult(
                "baseline",
                pages=1,
                next_since=watermark,
                etag=response_headers.get("ETag"),
                last_modified=response_headers.get("Last-Modified"),
            )
        since = previous - timedelta(seconds=self.overlap_seconds) if previous else None
        gate_status, gate_headers, _gate_payload = self.transport(
            f"https://api.github.com/repos/{self.repo}/issues?state=all&sort=updated&direction=desc&per_page={self.per_page}&page=1",
            self._headers(state, conditional=True, require_auth=self.auth_required),
        )
        if gate_status == 304:
            cached = [
                item for item in state.get("activePullRequests") or [] if isinstance(item, dict)
            ]
            events = self._active_pull_events(cached, state)
            if self._incomplete_details:
                return PollResult(
                    "degraded",
                    pages=1,
                    next_since=str(state.get("watermark") or "") or None,
                    etag=state.get("gateEtag"),
                    last_modified=state.get("gateLastModified"),
                    error=POLL_DETAIL_INCOMPLETE_ERROR,
                )
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
        final_headers: dict[str, str] = {
            "ETag": gate_headers.get("ETag", ""),
            "Last-Modified": gate_headers.get("Last-Modified", ""),
        }
        while True:
            query = f"?state=all&sort=updated&direction=asc&per_page={self.per_page}&page={page}"
            if since:
                query += "&since=" + since.isoformat().replace("+00:00", "Z")
            status, response_headers, payload = self.transport(
                f"https://api.github.com/repos/{self.repo}/issues{query}",
                self._headers(state, conditional=False, require_auth=self.auth_required),
            )
            if status == 304:
                if self._incomplete_details:
                    return PollResult(
                        "degraded",
                        pages=page - 1,
                        next_since=str(state.get("watermark") or "") or None,
                        etag=state.get("gateEtag"),
                        last_modified=state.get("gateLastModified"),
                        error=POLL_DETAIL_INCOMPLETE_ERROR,
                    )
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
                event["eventId"] = _github_event_id(event)
                events.append(event)
            if len(payload) < self.per_page:
                break
            page += 1
        if self._incomplete_details:
            return PollResult(
                "degraded",
                pages=page,
                next_since=str(state.get("watermark") or "") or None,
                etag=state.get("gateEtag"),
                last_modified=state.get("gateLastModified"),
                error=POLL_DETAIL_INCOMPLETE_ERROR,
            )
        watermark = (max_updated or current).isoformat().replace("+00:00", "Z")
        state.update(
            {
                "schemaVersion": "agentscope_poll_v1",
                "watermark": watermark,
                "gateEtag": final_headers.get("ETag") or state.get("gateEtag"),
                "gateLastModified": final_headers.get("Last-Modified")
                or state.get("gateLastModified"),
                "updatedAt": current.isoformat().replace("+00:00", "Z"),
                "activePullRequests": list(active_cache.values()),
            }
        )
        self._save(state)
        return PollResult(
            "ok",
            tuple(events),
            page,
            watermark,
            final_headers.get("ETag") or state.get("gateEtag"),
            final_headers.get("Last-Modified") or state.get("gateLastModified"),
        )

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
            events.append(
                {
                    "version": EVENT_VERSION,
                    "repo": self.repo,
                    "number": number,
                    "kind": kind,
                    "updatedAt": item.get("updated_at"),
                    "issue": item,
                    "prDetails": details,
                    "eventId": _github_event_id(
                        {
                            "repo": self.repo,
                            "number": number,
                            "kind": kind,
                            "updatedAt": item.get("updated_at"),
                            "prDetails": details,
                        }
                    ),
                }
            )
        return events

    def _enrich_pull_request(
        self, item: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any] | None:
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
            except Exception as exc:  # noqa: BLE001 - classify transport failures below
                if not self._recoverable_poll_error(exc):
                    raise
                complete = False
                continue
            if status == 200:
                details[key] = body
            elif status == 0 or status in {408, 429} or status >= 500:
                complete = False
            else:
                raise RuntimeError(f"GitHub PR detail failed: HTTP {status}")
        if isinstance(details.get("pull"), dict):
            for key in (
                "mergeable_state",
                "mergeable",
                "rebaseable",
                "comments",
                "review_comments",
            ):
                if key in details["pull"]:
                    item[key] = details["pull"][key]
            head_sha = str((details["pull"].get("head") or {}).get("sha") or "")
            if head_sha:
                try:
                    status, _response_headers, body = self.details_transport(
                        f"{base}/commits/{head_sha}/check-runs?per_page=100&page=1", headers
                    )
                except Exception as exc:  # noqa: BLE001 - classify transport failures below
                    if not self._recoverable_poll_error(exc):
                        raise
                    status, body = 0, None
                if status == 200:
                    details["checks"] = body
                elif status == 0 or status in {408, 429} or status >= 500:
                    complete = False
                else:
                    raise RuntimeError(f"GitHub check-runs failed: HTTP {status}")
            else:
                complete = False
        else:
            complete = False
        if not complete or not all(
            key in details for key in ("pull", "reviews", "comments", "checks")
        ):
            self._incomplete_details = True
            return dict(previous) if isinstance(previous, dict) else None
        item["agentscopeDetails"] = details
        state.setdefault("completePrSnapshots", {})[snapshot_key] = dict(item)
        return item

    def full_reconcile(self, *, now: datetime | None = None) -> PollResult:
        """Run reconciliation and persist health without advancing on failure."""
        current = (now or datetime.now(UTC)).astimezone(UTC)
        try:
            result = self._full_reconcile_once(now=current)
        except Exception as exc:  # noqa: BLE001 - reconciliation is an isolation boundary
            error = self._error_text(exc)
            self._record_poll_health(now=current, success=False, error=error)
            if not self._recoverable_poll_error(exc):
                raise
            state = self._load()
            return PollResult(
                "degraded",
                pages=0,
                next_since=str(state.get("watermark") or "") or None,
                error=error,
            )
        if result.status == "degraded" or self._incomplete_details:
            error = result.error or POLL_DETAIL_INCOMPLETE_ERROR
            self._record_poll_health(now=current, success=False, error=error)
            return PollResult(
                "degraded",
                (),
                pages=result.pages,
                next_since=result.next_since,
                etag=result.etag,
                last_modified=result.last_modified,
                error=error,
            )
        self._record_poll_health(now=current, success=True)
        return result

    def _full_reconcile_once(self, *, now: datetime | None = None) -> PollResult:
        """Run a non-conditional, all-pages reconciliation for missed updates."""
        self._incomplete_details = False
        state = self._load()
        current = (now or datetime.now(UTC)).astimezone(UTC)
        events: list[dict[str, Any]] = []
        active_prs: list[dict[str, Any]] = []
        fingerprints = (
            state.get("fullFingerprints") if isinstance(state.get("fullFingerprints"), dict) else {}
        )
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
                    and str((original.get("user") or {}).get("login") or "").casefold()
                    == "oxygen56"
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
                fingerprint = _digest(
                    {
                        "updatedAt": item.get("updated_at"),
                        "state": item.get("state"),
                        "title": item.get("title"),
                        "body": item.get("body"),
                        "material": _github_material_projection(
                            {
                                "repo": self.repo,
                                "number": item.get("number"),
                                "kind": kind,
                                "updatedAt": item.get("updated_at"),
                                "prDetails": details,
                            }
                        ),
                    }
                )
                next_fingerprints[item_key] = fingerprint
                if not fingerprints:
                    continue
                if fingerprints.get(item_key) == fingerprint:
                    continue
                event = {
                    "version": EVENT_VERSION,
                    "repo": self.repo,
                    "number": item.get("number"),
                    "kind": kind,
                    "updatedAt": item.get("updated_at"),
                    "issue": item,
                    "prDetails": details,
                }
                event["eventId"] = _github_event_id(event)
                events.append(event)
            if len(payload) < self.per_page:
                break
            page += 1
        if self._incomplete_details:
            return PollResult(
                "degraded",
                pages=page,
                next_since=str(state.get("watermark") or "") or None,
                error=POLL_DETAIL_INCOMPLETE_ERROR,
            )
        watermark = (max_updated or current).isoformat().replace("+00:00", "Z")
        state.update(
            {
                "schemaVersion": "agentscope_poll_v1",
                "watermark": watermark,
                "updatedAt": current.isoformat().replace("+00:00", "Z"),
                "activePullRequests": active_prs,
                "fullFingerprints": next_fingerprints,
            }
        )
        self._save(state)
        return PollResult(
            "full_reconcile",
            tuple(events),
            page,
            watermark,
            state.get("gateEtag"),
            state.get("gateLastModified"),
        )

    @staticmethod
    def _headers(state: dict[str, Any], *, conditional: bool, require_auth: bool) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not token:
            try:
                token = subprocess.run(
                    ["gh", "auth", "token"], check=True, capture_output=True, text=True, timeout=3
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                token = ""
        if not token and require_auth:
            try:
                stored = subprocess.run(
                    ["/usr/bin/security", "find-generic-password", "-s", "gh:github.com", "-w"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=3,
                ).stdout.strip()
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
        labels = {
            str(label.get("name") or "").lower()
            for label in item.get("labels") or []
            if isinstance(label, dict)
        }
        if item.get("pull_request"):
            author = str((item.get("user") or {}).get("login") or "").lower()
            # Only Oxygen56's own PRs are event sources.  Other authors' PRs
            # may be inspected during eligibility checks, but never wake the
            # event lane merely because they have comments or conflicts.
            return author == "oxygen56"
        if any(
            token in title or token in body
            for token in ("documentation", "docs:", "dependency", "bump ")
        ):
            return False
        return bool(
            {"bug", "feature", "enhancement", "help wanted", "good first issue", "code"} & labels
        ) or any(
            token in title or token in body
            for token in ("bug", "error", "crash", "exception", "regression", "implement")
        )


class EventLane:
    """SQLite event inbox with one writer, leases, priority and wake receipts."""

    def __init__(
        self,
        path: Path,
        *,
        lease_seconds: int = 120,
        ttl_seconds: int = 86400,
        max_attempts: int = 3,
        turn_timeout_seconds: int = 900,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lease_seconds = max(1, lease_seconds)
        self.ttl_seconds = max(1, ttl_seconds)
        # A broken bridge must not turn one event into an immortal lease.  A
        # terminal reconciliation record is safer than repeatedly waking a
        # second task from the same stale event.
        self.max_attempts = max(1, max_attempts)
        self.turn_timeout_seconds = max(1, turn_timeout_seconds)
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

    def _coalesce_pending_pr_updates(
        self,
        db: sqlite3.Connection,
        *,
        current: float,
        event_key: str | None = None,
        keep_event_id: str | None = None,
    ) -> int:
        query = (
            "SELECT e.rowid AS queue_rowid,e.event_id,e.payload_json,e.created_at "
            "FROM event_lane_events e "
            "WHERE json_extract(e.payload_json,'$.kind')='pr_update'"
        )
        params: list[object] = []
        if event_key:
            query += " AND json_extract(e.payload_json,'$.eventKey')=?"
            params.append(str(event_key))
        rows = db.execute(query, params).fetchall()
        groups: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            key = str(payload.get("eventKey") or "")
            if key:
                groups.setdefault(key, []).append(row)
        coalesced = 0
        for key_rows in groups.values():
            if len(key_rows) <= 1:
                continue
            keep = next(
                (row for row in key_rows if str(row["event_id"]) == str(keep_event_id or "")),
                max(key_rows, key=lambda row: int(row["queue_rowid"])),
            )
            for row in key_rows:
                if row["event_id"] == keep["event_id"]:
                    continue
                payload = json.loads(row["payload_json"])
                payload["terminalReason"] = "superseded_by_newer_pr_snapshot"
                payload["supersededByEventId"] = str(keep["event_id"])
                result = db.execute(
                    "UPDATE event_lane_events SET status='coalesced',payload_json=?,"
                    "delivered_at=?,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                    "WHERE event_id=? AND status='pending' AND NOT EXISTS "
                    "(SELECT 1 FROM event_lane_turns t WHERE t.event_id=event_lane_events.event_id)",
                    (
                        json.dumps(payload, sort_keys=True),
                        current,
                        str(row["event_id"]),
                    ),
                )
                coalesced += result.rowcount
        return coalesced

    def coalesce_pending_pr_updates(self, *, now: float | None = None) -> int:
        """Keep only the newest unstarted snapshot for each pull request."""

        current = time.time() if now is None else now
        with self.writer() as db:
            return self._coalesce_pending_pr_updates(db, current=current)

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
        identity = _github_event_identity(payload)
        current = time.time() if now is None else now
        with self.writer() as db:
            if (
                identity is not None
                and payload.get("kind") == "pr_update"
                and payload.get("eventKey")
            ):
                latest = db.execute(
                    "SELECT rowid AS queue_rowid,event_id,payload_json,status "
                    "FROM event_lane_events "
                    "WHERE json_extract(payload_json,'$.kind')='pr_update' "
                    "AND json_extract(payload_json,'$.eventKey')=? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (str(payload["eventKey"]),),
                ).fetchone()
                generation = 1
                if latest is not None:
                    try:
                        existing = json.loads(latest["payload_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        existing = {}
                    try:
                        latest_generation = max(0, int(existing.get("wakeGeneration") or 0))
                    except (TypeError, ValueError):
                        latest_generation = 0
                    if _github_event_identity(existing) == identity:
                        payload["eventId"] = str(latest["event_id"])
                        if latest_generation:
                            payload["wakeGeneration"] = latest_generation
                        if latest["status"] == "pending":
                            updated = db.execute(
                                "UPDATE event_lane_events SET payload_json=?,priority=? "
                                "WHERE event_id=? AND status='pending' AND NOT EXISTS "
                                "(SELECT 1 FROM event_lane_turns t "
                                "WHERE t.event_id=event_lane_events.event_id)",
                                (
                                    json.dumps(payload, sort_keys=True),
                                    int(priority),
                                    str(latest["event_id"]),
                                ),
                            )
                            if updated.rowcount:
                                self._coalesce_pending_pr_updates(
                                    db,
                                    current=current,
                                    event_key=str(payload["eventKey"]),
                                    keep_event_id=str(latest["event_id"]),
                                )
                        return False
                    generation = latest_generation + 1
                event_id = f"{event_id}:g{generation}"
                payload["eventId"] = event_id
                payload["wakeGeneration"] = generation
            elif identity is not None:
                for row in db.execute(
                    "SELECT event_id,payload_json,status FROM event_lane_events "
                    "WHERE event_id LIKE 'github:%'"
                ):
                    try:
                        existing = json.loads(row["payload_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if _github_event_identity(existing) == identity:
                        if row["status"] == "pending":
                            payload["eventId"] = str(row["event_id"])
                            updated = db.execute(
                                "UPDATE event_lane_events SET payload_json=?,priority=? "
                                "WHERE event_id=? AND status='pending' AND NOT EXISTS "
                                "(SELECT 1 FROM event_lane_turns t "
                                "WHERE t.event_id=event_lane_events.event_id)",
                                (
                                    json.dumps(payload, sort_keys=True),
                                    int(priority),
                                    str(row["event_id"]),
                                ),
                            )
                            if updated.rowcount and payload.get("kind") == "pr_update":
                                self._coalesce_pending_pr_updates(
                                    db,
                                    current=current,
                                    event_key=str(payload.get("eventKey") or ""),
                                    keep_event_id=str(row["event_id"]),
                                )
                        return False
            result = db.execute(
                "INSERT OR IGNORE INTO event_lane_events(event_id,payload_json,priority,created_at) VALUES(?,?,?,?)",
                (event_id, json.dumps(payload, sort_keys=True), int(priority), current),
            )
            if result.rowcount == 1 and payload.get("kind") == "pr_update":
                self._coalesce_pending_pr_updates(
                    db,
                    current=current,
                    event_key=str(payload.get("eventKey") or ""),
                    keep_event_id=event_id,
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
                except (
                    KeyError,
                    TypeError,
                    ValueError,
                    json.JSONDecodeError,
                    sqlite3.OperationalError,
                ):
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
                "SELECT * FROM event_lane_events WHERE attempts<? AND "
                "(status='pending' OR (status='leased' AND lease_until<=?)) AND "
                "(json_extract(payload_json,'$.retryNotBefore') IS NULL OR "
                "CAST(json_extract(payload_json,'$.retryNotBefore') AS REAL)<=?) "
                "ORDER BY CASE "
                "WHEN json_extract(payload_json,'$.kind')='outcome_reconcile' THEN ? "
                "WHEN priority<=10 AND ?-created_at>=? THEN ? "
                "ELSE priority END DESC, created_at ASC LIMIT ?",
                (
                    self.max_attempts,
                    current,
                    current,
                    RECOVERY_PRIORITY,
                    current,
                    ISSUE_STARVATION_SECONDS,
                    AGED_ISSUE_PRIORITY,
                    limit,
                ),
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

    def defer_event(
        self, event_id: str, *, lease_token: str | None = None, owner: str = "event-lane"
    ) -> bool:
        """Return a leased event to pending when its sole executor is busy."""
        with self.writer() as db:
            query = (
                "UPDATE event_lane_events SET status='pending',lease_until=NULL,"
                "lease_owner=NULL,lease_token=NULL WHERE event_id=? AND status='leased'"
            )
            params: list[object] = [str(event_id)]
            if lease_token:
                query += " AND lease_owner=? AND lease_token=?"
                params.extend([str(owner), str(lease_token)])
            return db.execute(query, params).rowcount == 1

    def defer_prestart_authorization_gap(
        self,
        event_id: str,
        *,
        lease_token: str,
        owner: str = "event-lane",
    ) -> bool:
        """Refund a leased attempt stopped by the authorization gate.

        This is intentionally narrower than ``defer_event``: the caller must
        still own the exact lease and the handler may only have an empty local
        reservation.  Removing that reservation and refunding the attempt in
        one transaction prevents a pre-turn infrastructure gap from becoming
        either a duplicate Codex turn or a manufactured reconciliation item.
        """
        token = str(lease_token or "")
        if not token:
            return False
        with self.writer() as db:
            result = db.execute(
                "UPDATE event_lane_events SET status='pending',"
                "attempts=attempts-1,"
                "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                "WHERE event_id=? AND status='leased' AND attempts>0 "
                "AND lease_owner=? AND lease_token=? "
                "AND EXISTS (SELECT 1 FROM event_lane_turns WHERE "
                "event_lane_turns.event_id=event_lane_events.event_id "
                "AND status='reserved' AND thread_id='' "
                "AND (turn_id IS NULL OR turn_id=''))",
                (str(event_id), str(owner), token),
            )
            if result.rowcount != 1:
                return False
            removed = db.execute(
                "DELETE FROM event_lane_turns WHERE event_id=? AND status='reserved' "
                "AND thread_id='' AND (turn_id IS NULL OR turn_id='')",
                (str(event_id),),
            )
            if removed.rowcount != 1:
                raise RuntimeError("prestart authorization reservation changed")
            return True

    def record_transient_model_failure(
        self,
        event_id: str,
        *,
        model: str,
        candidates: tuple[str, ...],
        error: object,
        lease_token: str | None = None,
        owner: str = "event-lane",
        retry_not_before: float | None = None,
    ) -> str:
        """Advance one durable model fallback chain without refunding an attempt.

        The event-lane attempt is deliberately retained: a capacity failure is
        a real model attempt, not an infrastructure pre-start refund.  This
        makes the finite candidate list the authority and prevents a stale
        receipt from resetting an event into an unbounded retry loop.
        """
        ordered = tuple(str(item).strip() for item in candidates if str(item).strip())
        selected = str(model).strip()
        if not ordered or len(set(ordered)) != len(ordered) or not selected:
            raise ValueError("invalid transient model fallback candidates")
        current = time.time()
        with self.writer() as db:
            row = db.execute(
                "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            if row is None or str(row["status"] or "") not in {
                "leased",
                "delivered",
                "needs_reconcile",
            }:
                return "conflict"
            if lease_token and (
                str(row["status"] or "") != "leased"
                or db.execute(
                    "SELECT 1 FROM event_lane_events WHERE event_id=? AND lease_owner=? AND lease_token=?",
                    (str(event_id), str(owner), str(lease_token)),
                ).fetchone()
                is None
            ):
                return "conflict"
            try:
                event = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                event = {"eventId": str(event_id)}
            if not isinstance(event, dict):
                event = {"eventId": str(event_id)}
            prior_fallback = event.get("modelFallback")
            legacy_reset = bool(
                selected not in ordered
                and not (
                    isinstance(prior_fallback, dict)
                    and prior_fallback.get("schemaVersion")
                    == "oss_pr_radar_event_model_fallback_v1"
                )
            )
            event, fallback_state = advance_model_fallback(
                event,
                model=selected,
                candidates=ordered,
                error=error,
                now=current,
            )
            fallback = event["modelFallback"]
            if legacy_reset:
                try:
                    generation = int(event.get("recoveryGeneration") or 0)
                except (TypeError, ValueError, OverflowError):
                    generation = 0
                event["recoveryGeneration"] = generation + 1
                event["legacyModelFallbackMigration"] = {
                    "schemaVersion": "oss_pr_radar_legacy_model_fallback_migration_v1",
                    "previousModel": selected,
                    "previousAttempts": int(row["attempts"] or 0),
                }
            exhausted = fallback_state == "exhausted"
            if exhausted:
                event["terminalReason"] = "model_capacity_retries_exhausted"
                event.pop("retryNotBefore", None)
                status = "needs_reconcile"
            else:
                event.pop("terminalReason", None)
                if retry_not_before is not None:
                    event["retryNotBefore"] = float(retry_not_before)
                status = "pending"
            result = db.execute(
                "UPDATE event_lane_events SET status=?,attempts=?,payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=?",
                (
                    status,
                    0 if legacy_reset and not exhausted else int(row["attempts"] or 0),
                    json.dumps(event, sort_keys=True),
                    current if exhausted else None,
                    str(event_id),
                ),
            )
            if result.rowcount != 1:
                return "conflict"
            turn = db.execute(
                "SELECT event_key,turn_id,receipt_json FROM event_lane_turns WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            if turn is not None:
                receipt = _receipt_object(turn["receipt_json"])
                receipt.update(
                    {
                        "model": selected,
                        "terminalError": str(error)[:500],
                        "modelFallback": fallback,
                    }
                )
                if exhausted:
                    receipt["terminalReason"] = "model_capacity_retries_exhausted"
                receipt_json = json.dumps(receipt, sort_keys=True)
                db.execute(
                    "UPDATE event_lane_turns SET status='needs_reconcile',receipt_json=? WHERE event_id=?",
                    (receipt_json, str(event_id)),
                )
                if str(turn["turn_id"] or ""):
                    db.execute(
                        "UPDATE event_lane_threads SET status='needs_reconcile',receipt_json=? "
                        "WHERE event_key=? AND turn_id=?",
                        (receipt_json, str(turn["event_key"]), str(turn["turn_id"])),
                    )
            return "exhausted" if exhausted else "retry"

    def try_reserve_handler_turn_if_idle(
        self,
        event_key: str,
        event_id: str,
        client_user_message_id: str,
        *,
        lease_token: str,
        owner: str = "event-lane",
        recovery_retry: bool = False,
    ) -> dict[str, Any]:
        """Atomically reserve the central task or refund a busy claim.

        A recovery event may retry after a terminal but invalid bridge receipt.
        In that narrow case an old bound turn is reset only after proving that
        no detached bridge process is still alive; ordinary events retain the
        strict turn-conflict behavior.
        """
        token = str(lease_token or "")
        if not token:
            return {"status": "conflict", "reason": "lease_token_missing"}
        with self.writer() as db:
            event_row = db.execute(
                "SELECT status,attempts,lease_owner,lease_token FROM event_lane_events "
                "WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            if (
                event_row is None
                or str(event_row["status"]) != "leased"
                or int(event_row["attempts"] or 0) <= 0
                or str(event_row["lease_owner"] or "") != str(owner)
                or str(event_row["lease_token"] or "") != token
            ):
                return {"status": "conflict", "reason": "lease_mismatch"}
            turn = db.execute(
                "SELECT * FROM event_lane_turns WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            resettable = bool(
                turn is not None
                and str(turn["status"] or "") == "needs_reconcile"
                and not str(turn["thread_id"] or "")
                and not str(turn["turn_id"] or "")
            )
            recovery_resettable = False
            recovery_live_process = False
            if turn is not None and not resettable and recovery_retry:
                receipt = _receipt_object(turn["receipt_json"])
                terminal_status = str(receipt.get("turnStatus") or "")
                terminal_reason = str(receipt.get("terminalReason") or "")
                has_terminal_marker = terminal_status in {
                    "completed",
                    "failed",
                    "interrupted",
                } or terminal_reason in _RECOVERY_RETRY_TERMINAL_REASONS
                # A valid outcome must never be overwritten by a retry.  The
                # worker normally catches this earlier, but keeping the check
                # at the atomic SQL boundary protects against stale callers.
                invalid_outcome = not _valid_machine_outcome_receipt(
                    receipt, str(event_id), str(event_key)
                )
                recovery_resettable = (
                    str(turn["status"] or "") == "needs_reconcile"
                    and has_terminal_marker
                    and invalid_outcome
                    and not _receipt_has_live_bridge(receipt)
                )
                recovery_live_process = (
                    str(turn["status"] or "") == "needs_reconcile"
                    and has_terminal_marker
                    and invalid_outcome
                    and not recovery_resettable
                )
            if turn is not None and not (resettable or recovery_resettable):
                if recovery_live_process:
                    refunded = db.execute(
                        "UPDATE event_lane_events SET status='pending',attempts=attempts-1,"
                        "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                        "WHERE event_id=? AND status='leased' AND attempts>0 "
                        "AND lease_owner=? AND lease_token=?",
                        (str(event_id), str(owner), token),
                    )
                    if refunded.rowcount != 1:
                        raise RuntimeError("live recovery claim changed during atomic refund")
                    return {
                        "status": "busy",
                        "activeEventId": str(event_id),
                        "reason": "recovery_process_active",
                    }
                return {"status": "conflict", "reason": "turn_conflict"}
            active = db.execute(
                "SELECT event_id FROM event_lane_turns WHERE event_id<>? "
                "AND status IN ('reserved','started') LIMIT 1",
                (str(event_id),),
            ).fetchone()
            if active is not None:
                refunded = db.execute(
                    "UPDATE event_lane_events SET status='pending',attempts=attempts-1,"
                    "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                    "WHERE event_id=? AND status='leased' AND attempts>0 "
                    "AND lease_owner=? AND lease_token=?",
                    (str(event_id), str(owner), token),
                )
                if refunded.rowcount != 1:
                    raise RuntimeError("busy claim changed during atomic refund")
                return {
                    "status": "busy",
                    "activeEventId": str(active["event_id"]),
                }
            current = time.time()
            if resettable or recovery_resettable:
                old_receipt = _receipt_object(turn["receipt_json"])
                reset_receipt = (
                    {
                        "receiptHistory": _bounded_receipt_history(
                            old_receipt, captured_at=current
                        ),
                        "retryOfTurnId": str(turn["turn_id"] or ""),
                        "retryPreparedAt": datetime.fromtimestamp(current, UTC)
                        .isoformat()
                        .replace("+00:00", "Z"),
                    }
                    if recovery_resettable
                    else {}
                )
                reset_query = (
                    "UPDATE event_lane_turns SET event_key=?,client_user_message_id=?,"
                    "thread_id='',turn_id=NULL,status='reserved',receipt_json=?,created_at=? "
                    "WHERE event_id=? AND status='needs_reconcile'"
                )
                reset_params: tuple[object, ...] = (
                    str(event_key),
                    str(client_user_message_id),
                    json.dumps(reset_receipt, sort_keys=True),
                    current,
                    str(event_id),
                )
                if not recovery_resettable:
                    reset_query += " AND thread_id='' AND (turn_id IS NULL OR turn_id='')"
                changed = db.execute(reset_query, reset_params)
                if changed.rowcount != 1:
                    raise RuntimeError("handler turn changed during atomic reservation")
            else:
                db.execute(
                    "INSERT INTO event_lane_turns(event_id,event_key,client_user_message_id,created_at) "
                    "VALUES(?,?,?,?)",
                    (
                        str(event_id),
                        str(event_key),
                        str(client_user_message_id),
                        current,
                    ),
                )
            reserved = db.execute(
                "SELECT * FROM event_lane_turns WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            if reserved is None or str(reserved["status"] or "") != "reserved":
                raise RuntimeError("handler turn reservation was not persisted")
            return {"status": "reserved", "turn": dict(reserved)}

    def pending(self) -> int:
        with self.connect() as db:
            return int(
                db.execute(
                    "SELECT count(*) FROM event_lane_events WHERE status IN ('pending','leased')"
                ).fetchone()[0]
            )

    def expire_handler_turns(
        self, *, now: float | None = None, timeout_seconds: int | None = None
    ) -> int:
        """Terminalize stale bridge turns so they cannot hold the lane forever."""
        current = time.time() if now is None else now
        timeout = self.turn_timeout_seconds if timeout_seconds is None else max(1, timeout_seconds)
        with self.writer() as db:
            rows = db.execute(
                "SELECT event_id,event_key,status,receipt_json FROM event_lane_turns "
                "WHERE status IN ('reserved','started') AND created_at<=?",
                (current - timeout,),
            ).fetchall()
            expired = 0
            for row in rows:
                try:
                    receipt = json.loads(row["receipt_json"] or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    receipt = {}
                pid = (
                    receipt.get("workerPid")
                    or receipt.get("pid")
                    or receipt.get("processId")
                    or receipt.get("launchPid")
                )
                if pid and _event_bridge_process_alive(pid):
                    continue
                expired += 1
                retry_reservation = (
                    str(row["status"]) == "reserved" and receipt.get("turnStarted") is not True
                )
                receipt["terminalReason"] = (
                    "handler_reservation_timeout_retry"
                    if retry_reservation
                    else "handler_turn_timeout"
                )
                receipt_json = json.dumps(receipt, sort_keys=True)
                db.execute(
                    "UPDATE event_lane_turns SET status='needs_reconcile',receipt_json=? "
                    "WHERE event_id=? AND status IN ('reserved','started')",
                    (receipt_json, row["event_id"]),
                )
                db.execute(
                    "UPDATE event_lane_threads SET status='needs_reconcile',receipt_json=? "
                    "WHERE event_key=? AND status IN ('reserved','started')",
                    (receipt_json, row["event_key"]),
                )
                event_row = db.execute(
                    "SELECT status,attempts,payload_json FROM event_lane_events WHERE event_id=?",
                    (row["event_id"],),
                ).fetchone()
                if event_row:
                    event_status = str(event_row["status"] or "")
                    # A settlement/closeout may have won the writer lock
                    # before this stale turn was examined.  Never resurrect
                    # an already terminal event from that old turn.
                    if event_status not in {"pending", "leased", "delivered"}:
                        continue
                    try:
                        payload = json.loads(event_row["payload_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        # A corrupt payload cannot be safely retried or
                        # interpreted as a recovery chain.  Leave the turn
                        # reconciliable, make the lease terminal, and avoid
                        # crashing the whole poller.
                        db.execute(
                            "UPDATE event_lane_events SET status='needs_reconcile',"
                            "delivered_at=?,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                            "WHERE event_id=? AND status IN ('pending','leased','delivered')",
                            (current, row["event_id"]),
                        )
                        continue
                    payload["terminalReason"] = receipt["terminalReason"]
                    is_recovery = payload.get("kind") == "outcome_reconcile"
                    # A detached recovery turn is acknowledged before its
                    # result arrives, so the event is often already
                    # ``delivered`` when the turn timeout is observed.  Put
                    # that recovery back into the bounded retry state instead
                    # of leaving a delivered+needs_reconcile pair that can
                    # never be claimed again.
                    if is_recovery and event_status == "delivered":
                        attempts = int(event_row["attempts"] or 0)
                        exhausted = attempts >= self.max_attempts
                        if exhausted:
                            payload["terminalReason"] = "outcome_recovery_attempts_exhausted"
                            payload["recoveryExhausted"] = True
                            payload["recoveryAttempts"] = attempts
                        db.execute(
                            "UPDATE event_lane_events SET status=?,payload_json=?,"
                            "delivered_at=?,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                            "WHERE event_id=? AND status='delivered'",
                            (
                                "needs_reconcile" if exhausted else "pending",
                                json.dumps(payload, sort_keys=True),
                                current if exhausted else None,
                                row["event_id"],
                            ),
                        )
                    elif retry_reservation:
                        db.execute(
                            "UPDATE event_lane_events SET status='pending',payload_json=?,"
                            "delivered_at=NULL,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                            "WHERE event_id=? AND status IN ('pending','leased')",
                            (json.dumps(payload, sort_keys=True), row["event_id"]),
                        )
                    else:
                        db.execute(
                            "UPDATE event_lane_events SET status='needs_reconcile',payload_json=?,"
                            "delivered_at=?,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                            "WHERE event_id=? AND status IN ('pending','leased')",
                            (json.dumps(payload, sort_keys=True), current, row["event_id"]),
                        )
            return expired

    def terminalize_github_events_before(
        self, boundary: datetime, *, now: float | None = None
    ) -> list[dict[str, str]]:
        """Audit and terminalize pre-bootstrap GitHub events without delivery.

        This is intentionally limited to the first bootstrap boundary. Queue
        imports and events without a trustworthy GitHub update timestamp are
        left eligible for normal dispatch.
        """
        boundary = boundary.astimezone(UTC)
        current = time.time() if now is None else now
        terminalized: list[dict[str, str]] = []
        with self.writer() as db:
            rows = db.execute(
                "SELECT event_id,payload_json FROM event_lane_events "
                "WHERE status IN ('pending','leased')"
            ).fetchall()
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                event_id = str(payload.get("eventId") or row["event_id"])
                if not event_id.startswith("github:"):
                    continue
                updated = github_event_effective_time(payload)
                if updated is None or updated > boundary:
                    continue
                db.execute(
                    "UPDATE event_lane_events SET status='baseline',delivered_at=?,"
                    "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=?",
                    (current, row["event_id"]),
                )
                terminalized.append(
                    {"eventId": event_id, "updatedAt": updated.isoformat().replace("+00:00", "Z")}
                )
        return terminalized

    def record_baseline_event(
        self, event: dict[str, Any], *, now: float | None = None
    ) -> dict[str, str]:
        """Persist a fetched pre-bootstrap GitHub event as terminal baseline."""
        event_id = str(event.get("eventId") or _digest(event))
        payload = dict(event)
        payload["eventId"] = event_id
        current = time.time() if now is None else now
        updated = github_event_effective_time(payload)
        if updated is None:
            raise ValueError("baseline GitHub event has no valid updatedAt")
        with self.writer() as db:
            row = db.execute(
                "SELECT status FROM event_lane_events WHERE event_id=?", (event_id,)
            ).fetchone()
            identity = _github_event_identity(payload)
            if row is None and identity is not None:
                for candidate in db.execute(
                    "SELECT event_id,payload_json,status FROM event_lane_events WHERE event_id LIKE 'github:%'"
                ):
                    try:
                        existing = json.loads(candidate["payload_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if _github_event_identity(existing) == identity:
                        event_id = str(candidate["event_id"])
                        row = candidate
                        break
            if row is None:
                db.execute(
                    "INSERT INTO event_lane_events(event_id,payload_json,status,created_at,delivered_at) "
                    "VALUES(?,?, 'baseline', ?, ?)",
                    (event_id, json.dumps(payload, sort_keys=True), current, current),
                )
            elif str(row["status"]) in {"pending", "leased"}:
                db.execute(
                    "UPDATE event_lane_events SET status='baseline',delivered_at=?,lease_until=NULL,"
                    "lease_owner=NULL,lease_token=NULL WHERE event_id=?",
                    (current, event_id),
                )
        return {"eventId": event_id, "updatedAt": updated.isoformat().replace("+00:00", "Z")}

    def handler_thread(self, event_key: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM event_lane_threads WHERE event_key=?", (event_key,)
            ).fetchone()
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
                if str(row["status"]) == "needs_reconcile":
                    db.execute(
                        "UPDATE event_lane_turns SET event_key=?,client_user_message_id=?,"
                        "thread_id='',turn_id=NULL,status='reserved',receipt_json='{}',created_at=? "
                        "WHERE event_id=? AND status='needs_reconcile'",
                        (
                            str(event_key),
                            str(client_user_message_id),
                            time.time(),
                            str(event_id),
                        ),
                    )
                    row = db.execute(
                        "SELECT * FROM event_lane_turns WHERE event_id=?",
                        (str(event_id),),
                    ).fetchone()
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

    def release_handler_reservation(
        self,
        event_id: str,
        receipt: dict[str, Any],
        *,
        reason: str,
    ) -> bool:
        """Release a turn that failed before a real Codex turn was received."""
        value = dict(receipt)
        value["terminalReason"] = str(reason)
        with self.writer() as db:
            existing = db.execute(
                "SELECT receipt_json FROM event_lane_turns WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            existing_receipt = _receipt_object(existing["receipt_json"]) if existing else {}
            value = _merge_receipt_history(existing_receipt, value)
            result = db.execute(
                "UPDATE event_lane_turns SET status='needs_reconcile',receipt_json=? "
                "WHERE event_id=? AND status='reserved'",
                (json.dumps(value, sort_keys=True), str(event_id)),
            )
            return result.rowcount == 1

    def active_handler_turn(self, event_key: str) -> dict[str, Any] | None:
        """Return the one currently running turn for an event key, if any."""
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM event_lane_turns WHERE event_key=? "
                "AND status IN ('reserved','started') ORDER BY created_at DESC LIMIT 1",
                (str(event_key),),
            ).fetchone()
        return dict(row) if row else None

    def active_handler_thread(self, thread_id: str) -> dict[str, Any] | None:
        """Return the one currently running turn for a central thread."""
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM event_lane_turns WHERE thread_id=? "
                "AND status IN ('reserved','started') ORDER BY created_at DESC LIMIT 1",
                (str(thread_id),),
            ).fetchone()
        return dict(row) if row else None

    def terminalize_event(
        self, event_id: str, *, status: str = "needs_reconcile", reason: str = ""
    ) -> bool:
        """Stop a deterministic failure without manufacturing a success receipt."""
        if status not in {"needs_reconcile", "coalesced", "watch_only", "baseline"}:
            raise ValueError("invalid event terminal status")
        with self.writer() as db:
            row = db.execute(
                "SELECT payload_json FROM event_lane_events WHERE event_id=?", (str(event_id),)
            ).fetchone()
            if row is None:
                return False
            payload = json.loads(row["payload_json"])
            if reason:
                payload["terminalReason"] = str(reason)
            db.execute(
                "UPDATE event_lane_events SET status=?,payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=? "
                "AND status IN ('pending','leased')",
                (status, json.dumps(payload, sort_keys=True), time.time(), str(event_id)),
            )
            return db.total_changes > 0

    def settle_exhausted_recovery_no_action(
        self,
        recovery_event_id: str,
        *,
        root_event_id: str,
        event_key: str,
        reason: str,
        evidence: dict[str, Any],
        now: float | None = None,
        watch_seconds: int = 24 * 60 * 60,
    ) -> dict[str, Any]:
        """Move a demonstrably superseded recovery chain to watch-only.

        Exhaustion is a terminal *infrastructure* state, not a successful
        outcome.  We only close the recovery row when the stable lineage and a
        small, allow-listed GitHub observation prove that another actor has
        taken over (or the issue is closed).  The original event and public
        tracking record remain watchable so a later GitHub update can wake the
        lane again; no public action or synthetic success receipt is created.
        """

        if not isinstance(reason, str) or reason not in EXTERNAL_RESOLUTION_REASONS:
            return {"status": "invalid", "settled": False}
        if (
            isinstance(watch_seconds, bool)
            or not isinstance(watch_seconds, int)
            or not 0 < watch_seconds <= 7 * 24 * 60 * 60
        ):
            return {"status": "invalid", "settled": False}
        recovery_id = str(recovery_event_id or "")
        root_id = str(root_event_id or "")
        key = str(event_key or "")
        if not recovery_id or not root_id or not key:
            return {"status": "invalid", "settled": False}
        if not isinstance(evidence, dict):
            return {"status": "invalid", "settled": False}
        if evidence.get("kind") != reason:
            return {"status": "invalid", "settled": False}
        required = {
            "issue_closed": {"repo", "number", "issueState"},
            "issue_assigned_external": {"repo", "number", "issueState", "assignee"},
            "external_claim_comment": {
                "repo",
                "number",
                "issueState",
                "commentId",
                "author",
                "createdAt",
                "excerpt",
            },
        }[reason]
        if any(not str(evidence.get(field) or "") for field in required):
            return {"status": "invalid", "settled": False}
        if str(evidence.get("repo")) != REPO:
            return {"status": "invalid", "settled": False}
        evidence_number = str(evidence.get("number") or "")
        if not re.fullmatch(r"[1-9][0-9]*", evidence_number):
            return {"status": "invalid", "settled": False}
        key_prefix, key_separator, key_number = key.rpartition("#")
        if (
            key_separator != "#"
            or key_prefix != REPO
            or re.fullmatch(r"[1-9][0-9]*", key_number) is None
            or key_number != evidence_number
        ):
            return {"status": "invalid", "settled": False}
        if reason == "issue_closed" and str(evidence.get("issueState")).casefold() != "closed":
            return {"status": "invalid", "settled": False}
        if reason != "issue_closed" and str(evidence.get("issueState")).casefold() != "open":
            return {"status": "invalid", "settled": False}
        if (
            reason == "issue_assigned_external"
            and str(evidence.get("assignee") or "").casefold() == "oxygen56"
        ):
            return {"status": "invalid", "settled": False}
        if reason == "external_claim_comment" and (
            _parse_time(str(evidence["createdAt"])) is None
            or str(evidence.get("claimKind") or "") not in {"active_claim", "conditional_claim"}
            or str(evidence.get("author") or "").casefold().endswith("[bot]")
            or str(evidence.get("author") or "").casefold() == "oxygen56"
        ):
            return {"status": "invalid", "settled": False}
        try:
            current = time.time() if now is None else float(now)
        except (TypeError, ValueError, OverflowError):
            return {"status": "invalid", "settled": False}
        if not (current == current and abs(current) != float("inf")):
            return {"status": "invalid", "settled": False}
        bounded_watch_seconds = watch_seconds
        try:
            resolved_at = datetime.fromtimestamp(current, UTC).isoformat().replace("+00:00", "Z")
            watch_until = (
                datetime.fromtimestamp(current + bounded_watch_seconds, UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except (OverflowError, OSError, ValueError):
            return {"status": "invalid", "settled": False}
        marker = {
            "schemaVersion": "agentscope_event_recovery_resolution_v1",
            "state": "watch_only",
            "reason": str(reason),
            "resolvedAt": resolved_at,
            "watchUntil": watch_until,
            "evidence": {
                str(name)[:80]: str(value)[:400]
                for name, value in evidence.items()
                if str(name) and value is not None
            },
        }

        def parse_object(raw: object) -> dict[str, Any]:
            try:
                value = json.loads(str(raw or "{}"))
            except (TypeError, ValueError, json.JSONDecodeError):
                return {}
            return value if isinstance(value, dict) else {}

        def live_process(receipt: dict[str, Any]) -> bool:
            pid = (
                receipt.get("workerPid")
                or receipt.get("pid")
                or receipt.get("processId")
                or receipt.get("launchPid")
            )
            return bool(pid and _event_bridge_process_alive(pid))

        expected_recovery = (
            "outcome-reconcile:agentscope:" + hashlib.sha256(root_id.encode("utf-8")).hexdigest()
        )
        with self.writer() as db:
            recovery = db.execute(
                "SELECT status,attempts,payload_json,created_at FROM event_lane_events WHERE event_id=?",
                (recovery_id,),
            ).fetchone()
            root = db.execute(
                "SELECT status,payload_json,created_at FROM event_lane_events WHERE event_id=?",
                (root_id,),
            ).fetchone()
            recovery_turn = db.execute(
                "SELECT event_key,thread_id,turn_id,status,receipt_json,created_at "
                "FROM event_lane_turns WHERE event_id=?",
                (recovery_id,),
            ).fetchone()
            root_turn = db.execute(
                "SELECT event_key,thread_id,turn_id,status,receipt_json,created_at "
                "FROM event_lane_turns WHERE event_id=?",
                (root_id,),
            ).fetchone()
            if recovery is None or root is None:
                return {"status": "missing", "settled": False}
            recovery_payload = parse_object(recovery["payload_json"])
            root_payload = parse_object(root["payload_json"])
            key_prefix, key_separator, key_number = key.rpartition("#")
            root_kind = str(root_payload.get("kind") or "")
            lineage_shape_valid = (
                key_separator == "#"
                and key_prefix == REPO
                and re.fullmatch(r"[1-9][0-9]*", key_number) is not None
                and recovery_id == expected_recovery
                and root_id.startswith("github:")
                and "outcome-reconcile:" not in root_id
                and root_id.startswith(f"github:{REPO}:{key_number}:{root_kind}:")
                and str(root_payload.get("eventId") or "") == root_id
                and str(root_payload.get("repo") or "") == REPO
                and str(root_payload.get("number") or "") == key_number
                and str(root_payload.get("eventKey") or "") == key
                and root_kind in {"issue_update", "pr_update"}
                and str(recovery_payload.get("eventId") or "") == recovery_id
                and recovery_payload.get("kind") == "outcome_reconcile"
                and str(recovery_payload.get("eventKey") or "") == key
                and str(recovery_payload.get("rootEventId") or "") == root_id
                and str(recovery_payload.get("eventIdSource") or "") == root_id
                and isinstance(recovery_payload.get("payload"), dict)
                and str(recovery_payload["payload"].get("eventId") or "") == root_id
                and str(recovery_payload["payload"].get("rootEventId") or "") == root_id
                and str(recovery_payload["payload"].get("publicKey") or "") == key
            )
            if not lineage_shape_valid:
                return {"status": "not_eligible", "settled": False}
            already_done = (
                str(recovery["status"] or "") == "coalesced"
                and str(root["status"] or "") in {"watch_only", "coalesced"}
                and (recovery_turn is None or str(recovery_turn["status"] or "") == "superseded")
                and (
                    root_turn is None
                    or str(root_turn["status"] or "") in {"watch_only", "superseded"}
                )
            )
            if already_done:
                return {"status": "already_applied", "settled": False}
            recovery_receipt = (
                parse_object(recovery_turn["receipt_json"]) if recovery_turn is not None else {}
            )
            root_receipt = parse_object(root_turn["receipt_json"]) if root_turn is not None else {}
            try:
                recovery_attempts = int(recovery["attempts"] or 0)
            except (TypeError, ValueError, OverflowError):
                return {"status": "not_eligible", "settled": False}
            recovery_exhausted = recovery_attempts >= self.max_attempts
            if (
                str(root_payload.get("number") or "") != str(evidence.get("number") or "")
                or str(root["status"] or "") not in {"delivered", "needs_reconcile"}
                or str(recovery["status"] or "") not in {"needs_reconcile", "delivered"}
                or not recovery_exhausted
                or recovery_turn is None
                or root_turn is None
                or str(recovery_turn["event_key"] or "") != key
                or str(root_turn["event_key"] or "") != key
                or str(recovery_turn["status"] or "") != "needs_reconcile"
                or str(root_turn["status"] or "") != "needs_reconcile"
                or (reason != "issue_closed" and root_kind != "issue_update")
            ):
                return {"status": "not_eligible", "settled": False}
            root_time = _parse_time(str(root_payload.get("updatedAt") or ""))
            if root_time is None and isinstance(root_payload.get("issue"), dict):
                root_time = _parse_time(str(root_payload["issue"].get("updated_at") or ""))
            evidence_time = _parse_time(str(evidence.get("createdAt") or ""))
            if (
                reason == "external_claim_comment"
                and root_time is not None
                and (evidence_time is None or evidence_time < root_time)
            ):
                return {"status": "not_eligible", "settled": False}
            try:
                chain_created_at = max(
                    float(recovery["created_at"] or 0),
                    float(root["created_at"] or 0),
                    float(recovery_turn["created_at"] or 0),
                    float(root_turn["created_at"] or 0),
                )
            except (TypeError, ValueError, OverflowError):
                return {"status": "not_eligible", "settled": False}
            # A later recovery/result for the same public key owns the latest
            # observation.  Do not hide it while settling an older exhausted
            # chain; let the newer chain finish normally.
            newer_rows = db.execute(
                "SELECT e.event_id,e.status,e.created_at,t.status AS turn_status,t.receipt_json "
                "FROM event_lane_events e LEFT JOIN event_lane_turns t USING(event_id) "
                "WHERE json_valid(e.payload_json) "
                "AND json_extract(e.payload_json,'$.eventKey')=? "
                "AND json_extract(e.payload_json,'$.kind')='outcome_reconcile' "
                "AND e.event_id NOT IN (?,?) AND e.created_at>?",
                (key, root_id, recovery_id, chain_created_at),
            ).fetchall()
            for newer in newer_rows:
                newer_status = str(newer["status"] or "")
                newer_turn_status = str(newer["turn_status"] or "")
                if newer_status in {"pending", "leased", "delivered", "needs_reconcile"}:
                    if (
                        newer_status in {"pending", "leased"}
                        or newer_turn_status in {"reserved", "started"}
                        or _valid_machine_outcome_receipt(
                            parse_object(newer["receipt_json"]), str(newer["event_id"]), key
                        )
                    ):
                        return {"status": "newer_recovery", "settled": False}
            newer_valid_turn = db.execute(
                "SELECT event_id,receipt_json FROM event_lane_turns "
                "WHERE event_key=? AND created_at>? AND event_id NOT IN (?,?)",
                (key, chain_created_at, root_id, recovery_id),
            ).fetchall()
            for newer_turn in newer_valid_turn:
                if _valid_machine_outcome_receipt(
                    parse_object(newer_turn["receipt_json"]), str(newer_turn["event_id"]), key
                ):
                    return {"status": "newer_turn", "settled": False}
            if live_process(recovery_receipt) or live_process(root_receipt):
                return {"status": "active_turn", "settled": False}

            def invalid_terminal_receipt(receipt: dict[str, Any], event_id: str) -> bool:
                status = str(receipt.get("turnStatus") or "")
                if status not in {"completed", "failed", "interrupted"}:
                    return False
                # A completed/failed wrapper is eligible only when its
                # machine outcome is genuinely missing or invalid.  Never
                # overwrite a valid outcome with an operator watch marker.
                return not _valid_machine_outcome_receipt(receipt, event_id, key)

            if not invalid_terminal_receipt(recovery_receipt, recovery_id):
                return {"status": "terminal_receipt_missing", "settled": False}
            if not invalid_terminal_receipt(root_receipt, root_id):
                return {"status": "terminal_receipt_missing", "settled": False}
            if reason == "external_claim_comment":
                author_type = str(
                    evidence.get("authorType") or evidence.get("userType") or ""
                ).casefold()
                excerpt = str(evidence.get("excerpt") or "")
                if author_type == "bot" or _NEGATED_EXTERNAL_CLAIM_RE.search(excerpt):
                    return {"status": "invalid", "settled": False}
            active = db.execute(
                "SELECT event_id FROM event_lane_turns WHERE event_key=? "
                "AND status IN ('reserved','started') AND event_id NOT IN (?,?) LIMIT 1",
                (key, root_id, recovery_id),
            ).fetchone()
            if active is not None:
                return {"status": "active_turn", "settled": False}

            recovery_payload["terminalReason"] = "exhausted_recovery_settled_watch_only"
            recovery_payload["operatorResolution"] = marker
            root_payload["terminalReason"] = "external_claim_watch_only"
            root_payload["operatorResolution"] = marker
            recovery_receipt["operatorResolution"] = marker
            recovery_receipt["terminalReason"] = "exhausted_recovery_settled_watch_only"
            root_receipt["operatorResolution"] = marker
            root_receipt["terminalReason"] = "external_claim_watch_only"
            changed_recovery = db.execute(
                "UPDATE event_lane_events SET status='coalesced',payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=? "
                "AND status IN ('needs_reconcile','delivered')",
                (json.dumps(recovery_payload, sort_keys=True), current, recovery_id),
            )
            changed_root = db.execute(
                "UPDATE event_lane_events SET status='watch_only',payload_json=?,delivered_at=?,"
                "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=? "
                "AND status IN ('delivered','needs_reconcile')",
                (json.dumps(root_payload, sort_keys=True), current, root_id),
            )
            if changed_recovery.rowcount != 1 or changed_root.rowcount != 1:
                raise RuntimeError("exhausted recovery changed during watch-only settlement")
            db.execute(
                "UPDATE event_lane_turns SET status='superseded',receipt_json=? "
                "WHERE event_id=? AND status='needs_reconcile'",
                (json.dumps(recovery_receipt, sort_keys=True), recovery_id),
            )
            db.execute(
                "UPDATE event_lane_turns SET status='watch_only',receipt_json=? "
                "WHERE event_id=? AND status='needs_reconcile'",
                (json.dumps(root_receipt, sort_keys=True), root_id),
            )
            db.execute(
                "UPDATE event_lane_threads SET status='watch_only',receipt_json=? "
                "WHERE event_key=? AND status='needs_reconcile' AND "
                "((thread_id=? AND turn_id=?) OR (thread_id=? AND turn_id=?))",
                (
                    json.dumps(root_receipt, sort_keys=True),
                    key,
                    str(recovery_turn["thread_id"] or ""),
                    str(recovery_turn["turn_id"] or ""),
                    str(root_turn["thread_id"] or ""),
                    str(root_turn["turn_id"] or ""),
                ),
            )
            newer_turn = db.execute(
                "SELECT 1 FROM event_lane_turns WHERE event_key=? AND created_at>? "
                "AND event_id NOT IN (?,?) LIMIT 1",
                (
                    key,
                    max(
                        float(recovery_turn["created_at"] or 0), float(root_turn["created_at"] or 0)
                    ),
                    root_id,
                    recovery_id,
                ),
            ).fetchone()
            public = db.execute(
                "SELECT status,source FROM event_lane_public_work WHERE event_key=?",
                (key,),
            ).fetchone()
            if (
                public is not None
                and str(public["source"] or "") == "outcome-invalid"
                and str(public["status"] or "") in {"active", "design_wait"}
                and newer_turn is None
            ):
                db.execute(
                    "UPDATE event_lane_public_work SET status='watch_only',watch_until=?,"
                    "source='external-claim',updated_at=? WHERE event_key=? "
                    "AND source='outcome-invalid' AND status IN ('active','design_wait')",
                    (current + bounded_watch_seconds, current, key),
                )
            return {
                "status": "applied",
                "settled": True,
                "reason": str(reason),
                "state": "watch_only",
            }

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
            existing = db.execute(
                "SELECT receipt_json FROM event_lane_turns WHERE event_id=?",
                (str(event_id),),
            ).fetchone()
            existing_receipt = _receipt_object(existing["receipt_json"]) if existing else {}
            incoming_receipt = _merge_receipt_history(existing_receipt, dict(receipt))
            db.execute(
                "UPDATE event_lane_turns SET event_key=?,thread_id=?,turn_id=?,status=?,receipt_json=? "
                "WHERE event_id=?",
                (
                    str(event_key),
                    str(thread_id),
                    str(turn_id),
                    str(status),
                    json.dumps(incoming_receipt, sort_keys=True),
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
                    json.dumps(incoming_receipt, sort_keys=True),
                ),
            )

    def bind_handler_thread(
        self,
        event_key: str,
        thread_id: str,
        turn_id: str,
        receipt: dict[str, Any],
        *,
        status: str = "started",
    ) -> None:
        with self.writer() as db:
            db.execute(
                "INSERT INTO event_lane_threads(event_key,thread_id,turn_id,status,receipt_json) VALUES(?,?,?,?,?) ON CONFLICT(event_key) DO UPDATE SET thread_id=excluded.thread_id,turn_id=excluded.turn_id,status=excluded.status,receipt_json=excluded.receipt_json",
                (event_key, thread_id, turn_id, status, json.dumps(receipt, sort_keys=True)),
            )

    def import_queue(
        self, queue: dict[str, Any], *, wake: Callable[[dict[str, Any]], Any] | None = None
    ) -> dict[str, int]:
        """Import intents and PR follow-up records, then wake each unique task once."""
        imported = 0
        task_ids: set[str] = set()
        current = time.time()
        for key in ("intents", "prFollowups", "followups", "slowWorkRequests"):
            values = queue.get(key) or []
            if isinstance(values, dict):
                values = [values]
            for value in values:
                if not isinstance(value, dict):
                    continue
                status = str(value.get("ledgerStatus") or value.get("status") or "").upper()
                if status in {"EXPIRED", "SUPERSEDED", "REJECTED", "CLOSED"}:
                    continue
                expires = value.get("expiresAt") or value.get("expires_at")
                if expires:
                    try:
                        if _parse_time(str(expires)).timestamp() <= current:  # type: ignore[union-attr]
                            continue
                    except (AttributeError, TypeError, ValueError):
                        # A malformed expiry must not become an authorization
                        # to wake work; leave it for controller reconciliation.
                        continue
                lease_until = value.get("leaseUntil") or value.get("lease_until")
                if status == "LEASED" and lease_until:
                    try:
                        if _parse_time(str(lease_until)).timestamp() <= current:  # type: ignore[union-attr]
                            continue
                    except (AttributeError, TypeError, ValueError):
                        continue
                task_id = str(
                    value.get("taskId")
                    or value.get("intentId")
                    or value.get("threadId")
                    or _digest(value)
                )
                target_key = str(
                    value.get("key")
                    or value.get("opportunityKey")
                    or value.get("opportunity_key")
                    or ""
                )
                event = {
                    "version": EVENT_VERSION,
                    "kind": key,
                    "taskId": task_id,
                    "targetKey": target_key,
                    "repo": value.get("repo"),
                    "payload": value,
                    "eventId": f"queue:{_digest({'kind': key, 'taskId': task_id})}",
                }
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

    def retire_queue_events(self, *, now: float | None = None) -> int:
        """Retire queue mirrors from older releases without executing them."""
        current = time.time() if now is None else now
        retired = 0
        with self.writer() as db:
            rows = db.execute(
                "SELECT event_id,payload_json FROM event_lane_events "
                "WHERE status IN ('pending','leased') AND event_id LIKE 'queue:%'"
            ).fetchall()
            for row in rows:
                try:
                    payload = json.loads(row["payload_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if payload.get("kind") not in {
                    "intents",
                    "prFollowups",
                    "followups",
                    "slowWorkRequests",
                }:
                    continue
                payload["terminalReason"] = "retired_shared_queue_mirror"
                db.execute(
                    "UPDATE event_lane_events SET status='coalesced',payload_json=?,delivered_at=?,"
                    "lease_until=NULL,lease_owner=NULL,lease_token=NULL WHERE event_id=?",
                    (json.dumps(payload, sort_keys=True), current, row["event_id"]),
                )
                retired += 1
        return retired

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
                db.execute(
                    "UPDATE event_lane_events SET status='watch_only' WHERE event_id=?",
                    (row["event_id"],),
                )
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
            # Expired bridge leases are not a reason to create another task.
            # Keep a durable reconciliation marker after bounded retries.
            exhausted = db.execute(
                "SELECT event_id,payload_json FROM event_lane_events "
                "WHERE attempts>=? AND (status='pending' OR "
                "(status='leased' AND lease_until<=?))",
                (self.max_attempts, current),
            ).fetchall()
            for row in exhausted:
                payload = json.loads(row["payload_json"])
                payload["terminalReason"] = "lease_attempts_exhausted"
                db.execute(
                    "UPDATE event_lane_events SET status='needs_reconcile',payload_json=?,"
                    "delivered_at=?,lease_until=NULL,lease_owner=NULL,lease_token=NULL "
                    "WHERE event_id=?",
                    (json.dumps(payload, sort_keys=True), current, row["event_id"]),
                )
            return len(rows) + len(exhausted)

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
            wait_until = payload.get("designWaitUntil")
            if not wait_until:
                outcome = payload.get("outcome") if isinstance(payload.get("outcome"), dict) else {}
                wait_until = outcome.get("waitUntil")
            try:
                watch_until = datetime.fromisoformat(
                    str(wait_until).replace("Z", "+00:00")
                ).timestamp()
            except (TypeError, ValueError):
                watch_until = time.time() + self.ttl_seconds
            payload["designWaitUntil"] = (
                datetime.fromtimestamp(watch_until, UTC).isoformat().replace("+00:00", "Z")
            )
            db.execute(
                "UPDATE event_lane_events SET payload_json=? WHERE event_id=?",
                (json.dumps(payload, sort_keys=True), str(event_id)),
            )
            event_key = str(payload.get("eventKey") or payload.get("targetKey") or "")
            if event_key:
                db.execute(
                    "INSERT INTO event_lane_public_work(event_key,status,watch_until,updated_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(event_key) DO UPDATE SET status='design_wait',watch_until=excluded.watch_until,updated_at=excluded.updated_at",
                    (event_key, "design_wait", watch_until, time.time()),
                )
                db.execute(
                    "UPDATE event_lane_threads SET status='design_wait' WHERE event_key=? "
                    "AND status IN ('reserved','started')",
                    (event_key,),
                )
            return True

    def active_work_keys(self) -> set[str]:
        current = time.time()
        with self.writer() as db:
            db.execute(
                "UPDATE event_lane_public_work SET status='watch_only',updated_at=? "
                "WHERE status='design_wait' AND watch_until IS NOT NULL AND watch_until<=?",
                (current, current),
            )
            rows = db.execute(
                "SELECT event_key FROM event_lane_threads WHERE status IN ('reserved','started')"
            ).fetchall()
            public = db.execute(
                "SELECT event_key FROM event_lane_public_work WHERE status IN ('active','design_wait') "
                "AND (status='active' OR (watch_until IS NOT NULL AND watch_until>?))",
                (current,),
            ).fetchall()
        return {str(row["event_key"]) for row in rows + public if row["event_key"]}

    def public_status(self, event_key: str) -> str | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT status FROM event_lane_public_work WHERE event_key=?", (str(event_key),)
            ).fetchone()
        return str(row["status"]) if row else None

    def register_public_work(
        self,
        event_key: str,
        *,
        status: str = "active",
        watch_until: float | None = None,
        source: str = "event-lane",
    ) -> None:
        if status == "design_wait" and watch_until is None:
            watch_until = time.time() + self.ttl_seconds
        if status == "design_wait" and watch_until is not None and watch_until <= time.time():
            status = "watch_only"
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
            row = db.execute(
                "SELECT value_json FROM event_lane_state WHERE key=?", (str(key),)
            ).fetchone()
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
