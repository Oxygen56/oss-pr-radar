"""Append-only receipts for scheduled automation command invocations.

The receipt log deliberately sits beside, but does not replace, the domain
ledgers.  It reconciles the process boundary: a scheduler invocation starts,
the command exits, a final JSON result is (or is not) produced, and the result
summarises any external effects it can prove.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .release_binding import open_directory_handle, validate_runtime_layout
from .util import atomic_write_json, canonical_json, iso_z, parse_time, sha256_json, utc_now

AUTOMATION_RUN_RECEIPT_SCHEMA = "oss-pr-radar.automation-run-receipt.v1"
AUTOMATION_RUN_AUDIT_SCHEMA = "oss-pr-radar.automation-run-audit.v1"
AUTOMATION_RUN_RECEIPT_FILE = "automation-runs.ndjson"
AUTOMATION_AUDIT_REPORT_PREFIX = "automation-audit-"
STARTED = "STARTED"
COMPLETED = "COMPLETED"

# Only scheduler-owned, non-secret metadata is copied from the environment.
# Arbitrary environment capture would turn an audit record into a credential
# leak, so callers must add new trigger fields here deliberately.
TRIGGER_ENV_KEYS = (
    "RADAR_AUTOMATION_ID",
    "RADAR_AUTOMATION_ROLE",
    "RADAR_INVOCATION_ID",
    "RADAR_TRIGGER_ID",
    "RADAR_SCHEDULED_AT",
)


def automation_run_receipt_path(runtime_root: Path) -> Path:
    """Return the receipt path without creating or modifying runtime state."""

    return Path(runtime_root).absolute() / "state" / AUTOMATION_RUN_RECEIPT_FILE


def argv_digest(argv: Sequence[str]) -> str:
    """Hash command arguments without persisting their potentially sensitive text."""

    return sha256_json([str(value) for value in argv])


def start_automation_run(
    runtime_root: Path,
    *,
    automation_id: str,
    role: str,
    argv: Sequence[str],
    release_id: str | None = None,
    environment: Mapping[str, str] | None = None,
    run_id: str | None = None,
    started_at: str | None = None,
) -> dict[str, Any]:
    """Append and return one immutable ``STARTED`` invocation record."""

    env = os.environ if environment is None else environment
    trigger_environment: dict[str, str] = {}
    for key in TRIGGER_ENV_KEYS:
        value = env.get(key)
        if isinstance(value, str) and value.strip():
            # Scheduler metadata is diagnostic only; keep the receipt bounded
            # even if a caller supplies an unexpectedly large environment
            # value.
            trigger_environment[key] = value.strip()[:256]
    run_id = run_id or secrets.token_hex(16)
    started_at = started_at or iso_z(utc_now())
    # The command entry point is the authority for its identity.  Environment
    # variables are merely an optional scheduler envelope and must never be
    # allowed to relabel a run (a manually launched process can set them).
    resolved_automation_id = automation_id
    resolved_role = role
    trigger_identity_mismatch = any(
        trigger_environment.get(key) not in {None, expected}
        for key, expected in (
            ("RADAR_AUTOMATION_ID", automation_id),
            ("RADAR_AUTOMATION_ROLE", role),
        )
    )
    invocation_id = trigger_environment.get("RADAR_INVOCATION_ID", run_id)
    record = {
        "schema": AUTOMATION_RUN_RECEIPT_SCHEMA,
        "recordType": STARTED,
        "runId": run_id,
        "automationId": resolved_automation_id,
        "role": resolved_role,
        "invocationId": invocation_id,
        "triggerId": trigger_environment.get("RADAR_TRIGGER_ID"),
        "scheduledAt": trigger_environment.get("RADAR_SCHEDULED_AT"),
        # A timestamp by itself cannot distinguish a scheduler trigger from a
        # manually supplied value.  Require both scheduler identifiers for the
        # stronger "present" classification; the raw envelope is retained
        # only for diagnostics.
        "triggerEvidencePresent": bool(
            trigger_environment.get("RADAR_TRIGGER_ID")
            and trigger_environment.get("RADAR_SCHEDULED_AT")
        ),
        "triggerMetadataPresent": bool(trigger_environment),
        "triggerIdentityMismatch": trigger_identity_mismatch,
        "triggerEnvironment": trigger_environment,
        "releaseId": release_id,
        "argvDigest": argv_digest(argv),
        "argvCount": len(argv),
        "runtimeRootDigest": sha256_json(str(Path(runtime_root).absolute())),
        "startedAt": started_at,
        "recordedAt": started_at,
    }
    return _append_sealed_record(runtime_root, record)


def complete_automation_run(
    runtime_root: Path,
    started: Mapping[str, Any],
    *,
    exit_code: int,
    final_json: Mapping[str, Any] | None = None,
    final_json_text: str | None = None,
    release_id: str | None = None,
    error: str | None = None,
    blocked_reason: str | None = None,
    external_effects: Mapping[str, Any] | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Append and return the terminal receipt for one started invocation.

    ``final_json_text`` should be the exact text written to stdout, including
    its trailing newline.  This makes ``finalJsonSha256`` directly comparable
    with captured command output.  When only ``final_json`` is supplied the
    canonical JSON encoding is hashed instead.
    """

    _validate_started_record(started)
    final_value: Mapping[str, Any] | None = final_json
    final_payload: bytes | None = None
    if final_json_text is not None:
        try:
            parsed = json.loads(final_json_text)
        except json.JSONDecodeError as exc:
            raise ValueError("final JSON text is invalid") from exc
        if not isinstance(parsed, dict):
            raise ValueError("final JSON text must contain an object")
        if final_value is not None and sha256_json(parsed) != sha256_json(final_value):
            raise ValueError("final JSON text does not match the supplied result")
        final_value = parsed
        final_payload = final_json_text.encode("utf-8")
    elif final_value is not None:
        final_payload = canonical_json(final_value).encode("utf-8")

    completed_at = completed_at or iso_z(utc_now())
    final_ok: bool | None = None
    if final_value is not None and isinstance(final_value.get("ok"), bool):
        final_ok = bool(final_value["ok"])
    record = {
        "schema": AUTOMATION_RUN_RECEIPT_SCHEMA,
        "recordType": COMPLETED,
        "runId": started["runId"],
        "automationId": started["automationId"],
        "role": started["role"],
        "invocationId": started["invocationId"],
        "triggerId": started.get("triggerId"),
        "scheduledAt": started.get("scheduledAt"),
        "triggerEvidencePresent": started.get("triggerEvidencePresent") is True,
        "triggerMetadataPresent": started.get("triggerMetadataPresent") is True,
        "releaseId": release_id if release_id is not None else started.get("releaseId"),
        "argvDigest": started["argvDigest"],
        "runtimeRootDigest": started["runtimeRootDigest"],
        "startedAt": started["startedAt"],
        "completedAt": completed_at,
        "recordedAt": completed_at,
        "exitCode": int(exit_code),
        "finalJsonPresent": final_payload is not None,
        "finalJsonSha256": (
            hashlib.sha256(final_payload).hexdigest() if final_payload is not None else None
        ),
        "finalJsonOk": final_ok,
        "error": _bounded_text(error),
        "blockedReason": _bounded_text(blocked_reason),
        "externalEffects": dict(external_effects or {}),
        "startedRecordDigest": started["recordDigest"],
    }
    return _append_sealed_record(runtime_root, record)


def load_automation_run_receipts(
    runtime_root: Path,
    *,
    path: Path | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read the append-only log without modifying it.

    Parse and authentication failures are returned as audit issues instead of
    hiding otherwise valid records.
    """

    path = path or automation_run_receipt_path(runtime_root)
    payload, read_issue = _read_receipt_payload(runtime_root, path)
    if read_issue is not None:
        return [], [read_issue]
    assert payload is not None
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        return [], [
            {
                "code": "RECEIPT_LOG_UNREADABLE",
                "path": str(path),
                "error": f"{type(exc).__name__}:{str(exc)[:200]}",
            }
        ]

    records: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            issues.append({"code": "EMPTY_RECEIPT_LINE", "line": line_number})
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            issues.append(
                {
                    "code": "INVALID_RECEIPT_JSON",
                    "line": line_number,
                    "error": str(exc)[:200],
                }
            )
            continue
        if not isinstance(value, dict):
            issues.append({"code": "INVALID_RECEIPT_RECORD", "line": line_number})
            continue
        value["_line"] = line_number
        records.append(value)
    return records, issues


def audit_automation_runs(
    records: Sequence[Mapping[str, Any]],
    *,
    source_issues: Sequence[Mapping[str, Any]] = (),
    automation_id: str | None = None,
    window_start: str | None = None,
    window_end: str | None = None,
    expected_interval_minutes: float | None = None,
    grace_minutes: float = 10,
    checked_at: str | None = None,
    expected_runtime_root_digest: str | None = None,
) -> dict[str, Any]:
    """Reconcile start/end pairs, schedule windows, and exit/JSON agreement."""

    if expected_interval_minutes is not None and expected_interval_minutes <= 0:
        raise ValueError("expected interval must be positive")
    if grace_minutes < 0:
        raise ValueError("grace minutes must be non-negative")
    start_boundary = parse_time(window_start) if window_start else None
    end_boundary = parse_time(window_end) if window_end else None
    if start_boundary and end_boundary and end_boundary < start_boundary:
        raise ValueError("audit window end precedes its start")
    if (start_boundary or end_boundary) and expected_interval_minutes is None:
        raise ValueError("an audit window requires an expected interval")

    issues = [dict(item) for item in source_issues]
    selected: list[Mapping[str, Any]] = []
    for record in records:
        if automation_id is not None and record.get("automationId") != automation_id:
            continue
        if not _record_in_window(record, start_boundary=start_boundary, end_boundary=end_boundary):
            continue
        selected.append(record)
        issues.extend(_record_integrity_issues(record))
        if (
            expected_runtime_root_digest is not None
            and record.get("runtimeRootDigest") != expected_runtime_root_digest
        ):
            issues.append(_issue("RUNTIME_ROOT_MISMATCH", record))
    if not selected:
        issues.append(
            {
                "code": "NO_AUTOMATION_RUNS",
                "automationId": automation_id,
            }
        )

    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in selected:
        run_id = record.get("runId")
        if not isinstance(run_id, str) or not run_id:
            issues.append(_issue("MISSING_RUN_ID", record))
            continue
        grouped[run_id].append(record)

    complete_runs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for run_id, run_records in sorted(grouped.items()):
        starts = [item for item in run_records if item.get("recordType") == STARTED]
        completions = [item for item in run_records if item.get("recordType") == COMPLETED]
        if len(starts) != 1:
            issues.append(
                {
                    "code": "MISSING_STARTED" if not starts else "DUPLICATE_STARTED",
                    "runId": run_id,
                    "count": len(starts),
                }
            )
        if len(completions) != 1:
            issues.append(
                {
                    "code": "MISSING_COMPLETED" if not completions else "DUPLICATE_COMPLETED",
                    "runId": run_id,
                    "count": len(completions),
                }
            )
        if len(starts) == 1 and len(completions) == 1:
            start, completion = starts[0], completions[0]
            complete_runs.append((start, completion))
            issues.extend(_pair_issues(start, completion))

    starts = [
        item
        for item in selected
        if item.get("recordType") == STARTED and isinstance(item.get("runId"), str)
    ]
    issues.extend(_duplicate_invocation_issues(starts))
    issues.extend(_duplicate_schedule_issues(starts))
    scheduled_starts = [item for item in starts if _valid_scheduled_at(item.get("scheduledAt"))]
    scheduler_missing = [
        item.get("runId")
        for item in starts
        if item.get("triggerEvidencePresent") is not True
        or not _valid_scheduled_at(item.get("scheduledAt"))
    ]
    if expected_interval_minutes is not None and scheduled_starts:
        issues.extend(
            _schedule_gap_issues(
                scheduled_starts,
                start_boundary=start_boundary,
                end_boundary=end_boundary,
                interval=timedelta(minutes=expected_interval_minutes),
                grace=timedelta(minutes=grace_minutes),
            )
        )

    identity_mismatch = [
        item.get("runId") for item in starts if item.get("triggerIdentityMismatch") is True
    ]
    if starts and not scheduler_missing:
        scheduler_evidence = "present"
    elif scheduler_missing and len(scheduler_missing) < len(starts):
        scheduler_evidence = "partial"
    else:
        scheduler_evidence = "missing"
    warnings: list[dict[str, Any]] = []
    if scheduler_missing:
        warnings.append(
            {
                "code": "SCHEDULER_EVIDENCE_MISSING",
                "runIds": scheduler_missing,
            }
        )
    if identity_mismatch:
        issues.extend(
            {
                "code": "TRIGGER_IDENTITY_MISMATCH",
                "runId": run_id,
            }
            for run_id in identity_mismatch
        )
    if expected_interval_minutes is not None and scheduler_missing:
        warnings.append(
            {
                "code": "SCHEDULE_GAP_CHECK_DEGRADED",
                "reason": "gap detection uses only receipts with scheduler scheduledAt metadata",
            }
        )

    failed_runs = []
    for _start, completion in complete_runs:
        exit_code = completion.get("exitCode")
        final_ok = completion.get("finalJsonOk")
        if exit_code != 0 or final_ok is not True:
            failed_runs.append(
                {
                    "runId": completion.get("runId"),
                    "exitCode": exit_code,
                    "finalJsonOk": final_ok,
                    "blockedReason": completion.get("blockedReason"),
                    "error": completion.get("error"),
                }
            )

    if failed_runs:
        run_status = "failed"
    elif not selected or issues:
        run_status = "unknown"
    else:
        run_status = "healthy"

    return {
        "schema": AUTOMATION_RUN_AUDIT_SCHEMA,
        "ok": not issues and not failed_runs,
        "receiptIntegrityOk": not issues,
        "executionOk": not failed_runs,
        "checkedAt": checked_at or iso_z(utc_now()),
        "automationId": automation_id,
        "schedulerEvidence": scheduler_evidence,
        "schedulerEvidenceMissingRunIds": scheduler_missing,
        "schedulerEvidenceMismatchedRunIds": identity_mismatch,
        "window": {
            "start": window_start,
            "end": window_end,
            "expectedIntervalMinutes": expected_interval_minutes,
            "graceMinutes": grace_minutes,
        },
        "counts": {
            "records": len(selected),
            "runs": len(grouped),
            "started": len(starts),
            "completed": sum(item.get("recordType") == COMPLETED for item in selected),
            "closed": len(complete_runs),
            "issues": len(issues),
            "failedRuns": len(failed_runs),
        },
        "warnings": warnings,
        "runStatus": run_status,
        "failedRuns": failed_runs,
        "issues": issues,
    }


def write_automation_audit_report(
    runtime_root: Path,
    *,
    automation_id: str,
    path: Path | None = None,
    expected_interval_minutes: float | None = None,
    grace_minutes: float = 10,
) -> tuple[Path, dict[str, Any]]:
    """Refresh a small local audit report after a command terminal receipt.

    The report is derived only from the append-only receipt log and is safe to
    regenerate.  It is intentionally separate from the command's final JSON,
    so a later audit cannot retroactively change what the scheduler observed.
    """

    records, source_issues = load_automation_run_receipts(runtime_root)
    audit = audit_automation_runs(
        records,
        source_issues=source_issues,
        automation_id=automation_id,
        expected_interval_minutes=expected_interval_minutes,
        grace_minutes=grace_minutes,
        expected_runtime_root_digest=sha256_json(str(Path(runtime_root).absolute())),
    )
    if path is None:
        _root, _releases, state = validate_runtime_layout(runtime_root, create_state=True)
        safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", automation_id).strip("-") or "automation"
        path = state / (f"{AUTOMATION_AUDIT_REPORT_PREFIX}{safe_id}.json")
    atomic_write_json(path, audit)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # The JSON is still useful on filesystems that do not support chmod;
        # callers retain the command receipt as the authoritative record.
        pass
    return path, audit


def _record_in_window(
    record: Mapping[str, Any],
    *,
    start_boundary: datetime | None,
    end_boundary: datetime | None,
) -> bool:
    """Filter records for a requested audit window without dropping malformed rows."""

    if start_boundary is None and end_boundary is None:
        return True
    raw = record.get("scheduledAt") or record.get("startedAt")
    try:
        observed = parse_time(str(raw))
    except (TypeError, ValueError):
        # Keep malformed records visible so integrity checks report them.
        return True
    if start_boundary is not None and observed < start_boundary:
        return False
    if end_boundary is not None and observed > end_boundary:
        return False
    return True


def _valid_scheduled_at(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parse_time(value)
    except (TypeError, ValueError):
        return False
    return True


def _read_receipt_payload(
    runtime_root: Path, path: Path
) -> tuple[bytes | None, dict[str, Any] | None]:
    """Read the receipt while sharing the writer's lock and refusing symlinks."""

    path = Path(path).absolute()
    parent_fd = -1
    descriptor = -1
    try:
        try:
            parent_fd, _canonical_parent = open_directory_handle(
                path.parent,
                label="automation run receipt parent",
                required_mode=None,
            )
        except RuntimeError as exc:
            if not path.parent.exists():
                return None, {"code": "RECEIPT_LOG_MISSING", "path": str(path)}
            return None, {
                "code": "RECEIPT_LOG_UNREADABLE",
                "path": str(path),
                "error": str(exc)[:200],
            }
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return None, {"code": "RECEIPT_LOG_MISSING", "path": str(path)}
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            return None, {"code": "RECEIPT_LOG_UNSAFE", "path": str(path)}
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            return None, {
                "code": "RECEIPT_LOG_UNSAFE",
                "path": str(path),
                "error": "receipt log must have mode 600",
            }
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        try:
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks), None
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as exc:
        return None, {
            "code": "RECEIPT_LOG_UNREADABLE",
            "path": str(path),
            "error": f"{type(exc).__name__}:{str(exc)[:200]}",
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _append_sealed_record(runtime_root: Path, record: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(record)
    sealed["recordDigest"] = sha256_json(record)
    _append_record(runtime_root, sealed)
    return sealed


def _append_record(runtime_root: Path, record: Mapping[str, Any]) -> None:
    _root, _releases, state = validate_runtime_layout(runtime_root, create_state=True)
    directory_fd, _canonical_state = open_directory_handle(
        state,
        label="automation run receipt state",
        required_mode=0o700,
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(AUTOMATION_RUN_RECEIPT_FILE, flags, 0o600, dir_fd=directory_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise RuntimeError("automation run receipt log is unsafe")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            os.fchmod(descriptor, 0o600)
        payload = (canonical_json(record) + "\n").encode("utf-8")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
            os.fsync(directory_fd)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _validate_started_record(started: Mapping[str, Any]) -> None:
    required = (
        "runId",
        "automationId",
        "role",
        "invocationId",
        "argvDigest",
        "runtimeRootDigest",
        "startedAt",
        "recordDigest",
    )
    if started.get("schema") != AUTOMATION_RUN_RECEIPT_SCHEMA:
        raise ValueError("started automation receipt schema is invalid")
    if started.get("recordType") != STARTED:
        raise ValueError("automation completion requires a STARTED receipt")
    if any(not isinstance(started.get(key), str) or not started.get(key) for key in required):
        raise ValueError("started automation receipt is incomplete")
    expected = sha256_json(
        {key: value for key, value in started.items() if key not in {"recordDigest", "_line"}}
    )
    if expected != started["recordDigest"]:
        raise ValueError("started automation receipt digest is invalid")


def _bounded_text(value: str | None, *, limit: int = 600) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value[:limit] if value else None


def _record_integrity_issues(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if record.get("schema") != AUTOMATION_RUN_RECEIPT_SCHEMA:
        issues.append(_issue("INVALID_RECEIPT_SCHEMA", record))
    digest = record.get("recordDigest")
    unsigned = {key: value for key, value in record.items() if key not in {"recordDigest", "_line"}}
    if not isinstance(digest, str) or digest != sha256_json(unsigned):
        issues.append(_issue("RECEIPT_DIGEST_MISMATCH", record))
    if record.get("recordType") not in {STARTED, COMPLETED}:
        issues.append(_issue("INVALID_RECORD_TYPE", record))
    return issues


def _pair_issues(started: Mapping[str, Any], completed: Mapping[str, Any]) -> list[dict[str, Any]]:
    run_id = str(started.get("runId") or completed.get("runId") or "")
    issues: list[dict[str, Any]] = []
    if completed.get("startedRecordDigest") != started.get("recordDigest"):
        issues.append({"code": "START_COMPLETION_LINK_MISMATCH", "runId": run_id})
    for key in (
        "automationId",
        "role",
        "invocationId",
        "triggerId",
        "scheduledAt",
        "triggerEvidencePresent",
        "triggerMetadataPresent",
        "argvDigest",
        "runtimeRootDigest",
        "startedAt",
        "releaseId",
    ):
        if started.get(key) != completed.get(key):
            issues.append(
                {"code": "START_COMPLETION_FIELD_MISMATCH", "runId": run_id, "field": key}
            )
    try:
        if parse_time(str(completed["completedAt"])) < parse_time(str(started["startedAt"])):
            issues.append({"code": "COMPLETION_PRECEDES_START", "runId": run_id})
    except (KeyError, TypeError, ValueError):
        issues.append({"code": "INVALID_RUN_TIMESTAMP", "runId": run_id})

    exit_code = completed.get("exitCode")
    present = completed.get("finalJsonPresent")
    final_ok = completed.get("finalJsonOk")
    digest = completed.get("finalJsonSha256")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        issues.append({"code": "MISSING_EXIT_CODE", "runId": run_id})
    if not isinstance(present, bool):
        issues.append({"code": "INVALID_FINAL_JSON_PRESENCE", "runId": run_id})
    elif present:
        if not isinstance(digest, str) or len(digest) != 64:
            issues.append({"code": "MISSING_FINAL_JSON_DIGEST", "runId": run_id})
        if not isinstance(final_ok, bool):
            issues.append({"code": "MISSING_FINAL_JSON_OK", "runId": run_id})
    else:
        issues.append({"code": "MISSING_FINAL_JSON", "runId": run_id})
        if digest is not None or final_ok is not None:
            issues.append({"code": "ABSENT_FINAL_JSON_HAS_RESULT", "runId": run_id})

    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        if exit_code == 0 and (present is not True or final_ok is not True):
            issues.append({"code": "EXIT_FINAL_JSON_MISMATCH", "runId": run_id})
        elif exit_code != 0 and final_ok is True:
            issues.append({"code": "EXIT_FINAL_JSON_MISMATCH", "runId": run_id})
    effects = completed.get("externalEffects")
    if not isinstance(effects, dict):
        issues.append({"code": "MISSING_EXTERNAL_EFFECT_SUMMARY", "runId": run_id})
    elif effects.get("summaryAvailable") is not True:
        issues.append({"code": "EXTERNAL_EFFECTS_UNCERTAIN", "runId": run_id})
    return issues


def _duplicate_invocation_issues(starts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    for record in starts:
        automation_id = record.get("automationId")
        invocation_id = record.get("invocationId")
        run_id = record.get("runId")
        if all(
            isinstance(value, str) and value for value in (automation_id, invocation_id, run_id)
        ):
            grouped[(str(automation_id), str(invocation_id))].add(str(run_id))
    return [
        {
            "code": "DUPLICATE_INVOCATION",
            "automationId": key[0],
            "invocationId": key[1],
            "runIds": sorted(run_ids),
        }
        for key, run_ids in sorted(grouped.items())
        if len(run_ids) > 1
    ]


def _duplicate_schedule_issues(starts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, datetime], set[str]] = defaultdict(set)
    for record in starts:
        automation_id = record.get("automationId")
        scheduled_at = record.get("scheduledAt")
        run_id = record.get("runId")
        if not all(
            isinstance(value, str) and value for value in (automation_id, scheduled_at, run_id)
        ):
            continue
        try:
            normalized = parse_time(str(scheduled_at))
        except (TypeError, ValueError):
            continue
        grouped[(str(automation_id), normalized)].add(str(run_id))
    return [
        {
            "code": "DUPLICATE_SCHEDULED_WINDOW",
            "automationId": key[0],
            "scheduledAt": iso_z(key[1]),
            "runIds": sorted(run_ids),
        }
        for key, run_ids in sorted(grouped.items())
        if len(run_ids) > 1
    ]


def _schedule_gap_issues(
    starts: Sequence[Mapping[str, Any]],
    *,
    start_boundary: datetime | None,
    end_boundary: datetime | None,
    interval: timedelta,
    grace: timedelta,
) -> list[dict[str, Any]]:
    timestamps: list[tuple[datetime, Mapping[str, Any]]] = []
    issues: list[dict[str, Any]] = []
    for record in starts:
        # A command start is not evidence that the scheduler fired.  Never
        # use startedAt to fill a scheduled slot; doing so makes a manual
        # fallback run hide a missed natural trigger.
        raw = record.get("scheduledAt")
        if not raw:
            continue
        try:
            timestamps.append((parse_time(str(raw)), record))
        except (TypeError, ValueError):
            issues.append(_issue("INVALID_SCHEDULE_TIMESTAMP", record))
    timestamps.sort(key=lambda item: item[0])

    if start_boundary is not None or end_boundary is not None:
        if start_boundary is None:
            start_boundary = timestamps[0][0] if timestamps else end_boundary
        if end_boundary is None:
            end_boundary = timestamps[-1][0] if timestamps else start_boundary
        assert start_boundary is not None and end_boundary is not None
        slot = start_boundary
        while slot <= end_boundary:
            matches = [record for observed, record in timestamps if abs(observed - slot) <= grace]
            if not matches:
                issues.append(
                    {
                        "code": "MISSED_RUN_WINDOW",
                        "scheduledAt": iso_z(slot),
                        "graceMinutes": grace.total_seconds() / 60,
                    }
                )
            slot += interval
        return issues

    for (previous, _), (current, _) in zip(timestamps, timestamps[1:], strict=False):
        gap = current - previous
        if gap > interval + grace:
            # Count only slots that are still outside the current run's
            # tolerance window.  This avoids understating a long gap (for
            # example, 00:00 -> 02:11 with a 60-minute interval has two
            # missing slots, not one).
            missing = 0
            slot = previous + interval
            while slot <= current - grace:
                missing += 1
                slot += interval
            issues.append(
                {
                    "code": "MISSED_RUN_WINDOW",
                    "after": iso_z(previous),
                    "before": iso_z(current),
                    "estimatedMissing": max(1, missing),
                }
            )
    return issues


def _issue(code: str, record: Mapping[str, Any]) -> dict[str, Any]:
    issue: dict[str, Any] = {"code": code}
    if isinstance(record.get("runId"), str):
        issue["runId"] = record["runId"]
    if isinstance(record.get("_line"), int):
        issue["line"] = record["_line"]
    return issue
