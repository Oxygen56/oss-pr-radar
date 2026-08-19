"""Read-only deployment acceptance checks for the Stage 7 layout."""

from __future__ import annotations

import hashlib
import json
import plistlib
import re
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .automation_contracts import build_contracts
from .automation_snapshot import (
    AUTOMATION_SNAPSHOT_SCHEMA,
    derive_automation_snapshot,
)
from .launch_config import parse_launchctl_config
from .local_publication import worker_specs
from .managed_lifecycle import MANAGED_SCHEMA_VERSION, MANAGED_TABLES
from .managed_security import current_signing_key_available, sign_current, verify_current
from .operational_auth import (
    issue_operational_authorization as _issue_operational_authorization,
)
from .operational_auth import (
    stable_evidence_digest,
    verify_operational_authorization,
    verify_staged_worker_receipt,
    worker_spec_digest,
)
from .pr_projection import ledger_projection
from .release_binding import bind_runtime, runtime_ledger_path, runtime_root_digest
from .runtime import REQUIRED_WORKERS, disk_snapshot, pending_publication_effects, read_json
from .runtime_audit import LEGACY_LABELS, WORKER_LABELS, collect_snapshot, launchctl_print
from .stage6_rehearsal import redact_public, stable_sqlite_copy, validate_detached_report_envelope
from .stage6_verification import validate_verification_manifest
from .util import sha256_json

WORKER_MAX_AGE = {
    "fast": timedelta(minutes=2),
    "slow": timedelta(minutes=5),
    "queue-importer": timedelta(minutes=15),
}
MAX_EVIDENCE_AGE = timedelta(hours=24)
MAX_AUTOMATION_AGE = timedelta(minutes=10)


def _utc_datetime(value: object, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(UTC)


def _ledger_check(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"present": False, "integrity": "MISSING", "managedCounts": {}}
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        version = connection.execute(
            "SELECT COALESCE(MAX(version), 0) FROM managed_schema_migrations"
        ).fetchone()[0]
        counts = {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in MANAGED_TABLES
        }
        pr_states = {
            state: int(
                connection.execute(
                    "SELECT COUNT(*) FROM managed_prs WHERE state=?", (state,)
                ).fetchone()[0]
            )
            for state in ("OPEN", "CLOSED", "MERGED")
        }
        return {
            "present": True,
            "integrity": integrity,
            "managedSchema": int(version),
            "managedCounts": counts,
            "managedPrStateCounts": pr_states,
        }
    except sqlite3.Error as exc:
        return {"present": True, "integrity": "ERROR", "error": str(exc)[:200]}
    finally:
        connection.close()


def _stage6_pr_invariant(report: Path) -> dict[str, Any]:
    try:
        value = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Stage 6 report is unreadable") from exc
    invariant = value.get("prInvariant") if isinstance(value, dict) else None
    required = {
        "totalRecords",
        "currentOpen",
        "closedOrMerged",
        "allManagedKeysObserved",
        "liveOpenCount",
        "missing",
        "unexpected",
        "duplicates",
        "headMismatches",
        "managedPrProjectionDigest",
    }
    if not isinstance(invariant, dict) or set(invariant) != required:
        raise ValueError("Stage 6 report PR invariant is incomplete")
    if any(
        not isinstance(invariant[key], int)
        for key in ("totalRecords", "currentOpen", "closedOrMerged", "liveOpenCount")
    ):
        raise ValueError("Stage 6 report PR invariant counts are invalid")
    if invariant["allManagedKeysObserved"] is not True or any(
        invariant[key] for key in ("missing", "unexpected", "duplicates", "headMismatches")
    ):
        raise ValueError("Stage 6 report PR invariant is not clean")
    if not isinstance(invariant["managedPrProjectionDigest"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", invariant["managedPrProjectionDigest"]
    ):
        raise ValueError("Stage 6 report PR projection digest is invalid")
    code_head = value.get("codeHead")
    validate_verification_manifest(value.get("verification"), code_head)
    return invariant


def _baseline_matches_ledger(baseline: dict[str, Any], evidence: dict[str, Any]) -> bool:
    counts = (
        evidence.get("managedCounts") if isinstance(evidence.get("managedCounts"), dict) else {}
    )
    states = (
        evidence.get("managedPrStateCounts")
        if isinstance(evidence.get("managedPrStateCounts"), dict)
        else {}
    )
    return (
        baseline.get("totalRecords") == counts.get("managed_prs")
        and baseline.get("currentOpen") == states.get("OPEN")
        and baseline.get("closedOrMerged") == states.get("CLOSED", 0) + states.get("MERGED", 0)
        and baseline.get("liveOpenCount") == states.get("OPEN")
        and baseline.get("managedPrProjectionDigest") == evidence.get("managedPrProjectionDigest")
    )


def shareable_acceptance_report(value: dict[str, Any]) -> dict[str, Any]:
    """Return a path/token-redacted report suitable for sharing externally."""

    return redact_public(value)


def _freshness(state: dict[str, Any], worker: str) -> dict[str, Any]:
    field = "queueImportSuccessAt" if worker == "queue-importer" else "lastSuccessAt"
    workers = state.get("workers") if isinstance(state.get("workers"), dict) else {}
    worker_state = workers.get(worker) if isinstance(workers, dict) else {}
    worker_state = worker_state if isinstance(worker_state, dict) else {}
    value = worker_state.get(field)
    if not isinstance(value, str):
        return {"lastSuccessAt": value, "fresh": False}
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return {"lastSuccessAt": value, "fresh": False}
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return {"lastSuccessAt": value, "fresh": False}
    parsed = parsed.astimezone(UTC)
    now = datetime.now(UTC)
    age = now - parsed
    return {
        "lastSuccessAt": value,
        "fresh": age >= timedelta(0) and age <= WORKER_MAX_AGE[worker],
        "maxAgeSeconds": int(WORKER_MAX_AGE[worker].total_seconds()),
    }


def _stable_ledger_observation(path: Path, *, max_attempts: int = 3) -> dict[str, Any]:
    """Read one normalized SQLite backup for counts, digest, and effects."""

    if not path.is_file():
        return {
            "evidence": {"present": False, "integrity": "MISSING", "managedCounts": {}},
            "sha256": None,
            "pendingEffects": -1,
        }
    with tempfile.TemporaryDirectory(prefix="oss-pr-radar-stage7-ledger-") as directory:
        snapshot = Path(directory) / "ledger.sqlite3"
        copy = stable_sqlite_copy(
            path,
            snapshot,
            quiesce_token="stage7-acceptance-read",
            max_attempts=max_attempts,
        )
        raw = snapshot.read_bytes()
        evidence = _ledger_check(snapshot)
        projection = ledger_projection(snapshot)
        evidence["managedPrProjectionDigest"] = projection["digest"]
        return {
            "evidence": evidence,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "pendingEffects": pending_publication_effects(snapshot),
            "copy": copy,
        }


def _actual_plist(home: Path, label: str) -> dict[str, Any]:
    path = home / "Library" / "LaunchAgents" / f"{label}.plist"
    if path.is_symlink():
        return {"path": str(path), "present": False}
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException):
        return {"path": str(path), "present": False}
    if not isinstance(value, dict):
        return {"path": str(path), "present": False}
    return {
        "path": str(path),
        "present": True,
        "ProgramArguments": value.get("ProgramArguments"),
        "WorkingDirectory": value.get("WorkingDirectory"),
    }


def _loaded(output: str) -> bool:
    lowered = output.casefold()
    return bool(output.strip()) and not any(
        marker in lowered for marker in ("could not find", "service not found", "no such process")
    )


_launch_config = parse_launchctl_config


def _verify_bound_evidence(
    value: Any, *, schema: str, context: str, runtime_root: Path, release_id: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise ValueError("strict acceptance evidence schema is invalid")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned, context=context, key_id=value.get("keyId"), signature=value.get("signature")
    ):
        raise ValueError("strict acceptance evidence authentication failed")
    if value.get("runtimeRootDigest") != runtime_root_digest(runtime_root):
        raise ValueError("strict acceptance evidence runtime binding mismatch")
    if value.get("releaseId") != release_id:
        raise ValueError("strict acceptance evidence release binding mismatch")
    observed = _utc_datetime(value.get("observedAt"), field="strict acceptance evidence time")
    now = datetime.now(UTC)
    if now - observed > MAX_EVIDENCE_AGE or observed > now + timedelta(minutes=5):
        raise ValueError("strict acceptance evidence is stale")
    return unsigned


def build_managed_counts_evidence(
    runtime_root: Path,
    report: Path,
    envelope: Path,
    *,
    code_head: str,
) -> dict[str, Any]:
    """Generate counts only from a fully validated Stage 6 envelope and ledger."""

    validate_detached_report_envelope(report, envelope, code_head=code_head)
    stage6_invariant = _stage6_pr_invariant(report)
    binding = bind_runtime(runtime_root)
    if binding.release.get("commit") != code_head:
        raise ValueError("counts evidence HEAD does not match the active release")
    ledger = runtime_ledger_path(runtime_root)
    observation = _stable_ledger_observation(ledger)
    evidence = observation["evidence"]
    if evidence.get("integrity") != "ok" or evidence.get("managedSchema") != MANAGED_SCHEMA_VERSION:
        raise ValueError("counts evidence requires a current managed ledger")
    envelope_value = json.loads(envelope.read_text(encoding="utf-8"))
    unsigned = {
        "schema": "oss-pr-radar.stage7-counts-evidence.v1",
        "generator": "stage6-envelope-verified",
        "runtimeRootDigest": runtime_root_digest(runtime_root),
        "releaseId": binding.release_id,
        "releaseHead": code_head,
        "observedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "managedCounts": evidence["managedCounts"],
        "ledgerSha256": observation["sha256"],
        "ledgerSnapshot": "sqlite-backup-wal-safe-v1",
        "ledgerGeneration": observation.get("copy", {})
        .get("attempts", [{}])[-1]
        .get("after", {})
        .get("generation"),
        "managedPrProjectionDigest": evidence["managedPrProjectionDigest"],
        "sourceEnvelopeSha256": hashlib.sha256(envelope.read_bytes()).hexdigest(),
        "sourceReportSha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "sourceArtifactDigest": sha256_json(envelope_value["artifactManifest"]),
        "stage6ExpectedPrInvariant": stage6_invariant,
        "sourceEnvelopePath": str(envelope.resolve()),
        "sourceReportPath": str(report.resolve()),
    }
    auth = sign_current(unsigned, context="stage7-counts-evidence-v1")
    if not auth.get("keyId") or not auth.get("signature"):
        raise PermissionError("current signing key is unavailable")
    return {**unsigned, **auth}


def check(
    runtime_root: Path,
    *,
    home: Path | None = None,
    strict: bool = True,
    launchctl_runner: Any | None = None,
    expected_managed_counts: dict[str, int] | None = None,
    managed_counts_evidence: Path | dict[str, Any] | None = None,
    automation_snapshot: Path | dict[str, Any] | None = None,
    require_workers_loaded: bool = True,
) -> dict[str, Any]:
    """Check a release-bound runtime without performing any external action."""

    runtime_root = runtime_root.resolve()
    binding = bind_runtime(runtime_root)
    home = home or Path.home()
    specs = worker_specs(binding.code_root, home=home, runtime_root=runtime_root)
    contracts = build_contracts(runtime_root, home=home)
    expected_workers = {spec["Label"]: spec for spec in specs}
    contract_workers = contracts["workers"]
    contract_match = set(expected_workers) == set(contract_workers) and all(
        expected_workers[label]["ProgramArguments"] == contract_workers[label]["command"]
        and expected_workers[label]["WorkingDirectory"] == contract_workers[label]["workdir"]
        for label in expected_workers
    )
    release_path = str(binding.code_root)
    runtime_path = str(runtime_root)
    ledger = runtime_ledger_path(runtime_root)
    pointer = runtime_root / "state" / "current-ledger"
    pointer_target_ok = pointer.is_symlink() and (
        pointer.resolve().parent == (runtime_root / "state" / "ledger-releases").resolve()
        and pointer.resolve().is_file()
    )
    pointer_ok = pointer_target_ok or (not strict and not pointer.exists())
    try:
        ledger_observation = _stable_ledger_observation(ledger)
    except (OSError, RuntimeError):
        ledger_observation = {
            "evidence": {"present": True, "integrity": "ERROR", "managedCounts": {}},
            "sha256": None,
            "pendingEffects": -1,
        }
    ledger_evidence = ledger_observation["evidence"]
    ledger_sha = ledger_observation.get("sha256")
    pending_effects = ledger_observation.get("pendingEffects", -1)
    ledger_schema_ok = (
        ledger_evidence.get("present") is True
        and ledger_evidence.get("integrity") == "ok"
        and ledger_evidence.get("managedSchema") == MANAGED_SCHEMA_VERSION
    )
    if not strict and ledger_evidence.get("integrity") == "MISSING":
        ledger_schema_ok = True
    exact_counts = None if strict else expected_managed_counts
    counts_evidence_ok = not strict
    stage6_baseline: dict[str, Any] | None = None
    if strict:
        if managed_counts_evidence is None:
            counts_evidence_ok = False
        else:
            raw = (
                json.loads(managed_counts_evidence.read_text(encoding="utf-8"))
                if isinstance(managed_counts_evidence, Path)
                else managed_counts_evidence
            )
            try:
                bound = _verify_bound_evidence(
                    raw,
                    schema="oss-pr-radar.stage7-counts-evidence.v1",
                    context="stage7-counts-evidence-v1",
                    runtime_root=runtime_root,
                    release_id=binding.release_id,
                )
                exact_counts = bound.get("managedCounts")
                stage6_baseline = bound.get("stage6ExpectedPrInvariant")
                counts_evidence_ok = (
                    isinstance(exact_counts, dict)
                    and isinstance(stage6_baseline, dict)
                    and bound.get("generator") == "stage6-envelope-verified"
                    and bound.get("releaseHead") == binding.release.get("commit")
                    and bound.get("ledgerSha256") == ledger_sha
                    and bound.get("ledgerSnapshot") == "sqlite-backup-wal-safe-v1"
                    and isinstance(bound.get("ledgerGeneration"), str)
                    and isinstance(bound.get("sourceEnvelopeSha256"), str)
                    and isinstance(bound.get("sourceReportSha256"), str)
                    and isinstance(bound.get("sourceArtifactDigest"), str)
                    and bound.get("managedCounts") == ledger_evidence.get("managedCounts")
                    and bound.get("managedPrProjectionDigest")
                    == ledger_evidence.get("managedPrProjectionDigest")
                )
                source_envelope = Path(str(bound.get("sourceEnvelopePath")))
                source_report = Path(str(bound.get("sourceReportPath")))
                if counts_evidence_ok:
                    try:
                        validate_detached_report_envelope(
                            source_report,
                            source_envelope,
                            code_head=str(binding.release.get("commit")),
                        )
                        source_value = json.loads(source_envelope.read_text(encoding="utf-8"))
                        counts_evidence_ok = (
                            bound.get("sourceEnvelopeSha256")
                            == hashlib.sha256(source_envelope.read_bytes()).hexdigest()
                            and bound.get("sourceReportSha256")
                            == hashlib.sha256(source_report.read_bytes()).hexdigest()
                            and bound.get("sourceArtifactDigest")
                            == sha256_json(source_value["artifactManifest"])
                            and stage6_baseline == _stage6_pr_invariant(source_report)
                            and _baseline_matches_ledger(stage6_baseline, ledger_evidence)
                        )
                    except (OSError, ValueError, json.JSONDecodeError):
                        counts_evidence_ok = False
            except (OSError, json.JSONDecodeError, ValueError):
                counts_evidence_ok = False
    expected_ok = (
        not strict
        and (exact_counts is None or ledger_evidence.get("managedCounts") == exact_counts)
    ) or (
        strict
        and isinstance(stage6_baseline, dict)
        and _baseline_matches_ledger(stage6_baseline, ledger_evidence)
    )
    automation_evidence_ok = not strict
    actual_automation = None
    if strict:
        if automation_snapshot is not None:
            try:
                raw = (
                    json.loads(automation_snapshot.read_text(encoding="utf-8"))
                    if isinstance(automation_snapshot, Path)
                    else automation_snapshot
                )
                actual_automation = _verify_bound_evidence(
                    raw,
                    schema=AUTOMATION_SNAPSHOT_SCHEMA,
                    context="stage7-automation-snapshot-v1",
                    runtime_root=runtime_root,
                    release_id=binding.release_id,
                )
                observed = _utc_datetime(
                    actual_automation.get("observedAt"), field="automation snapshot time"
                )
                files = actual_automation.get("sourceFiles")
                automation_evidence_ok = (
                    datetime.now(UTC) - observed <= MAX_AUTOMATION_AGE
                    and observed <= datetime.now(UTC) + timedelta(minutes=1)
                    and isinstance(files, list)
                    and len(files) == 2
                )
                source_paths: dict[str, Path] = {}
                source_resolved: set[str] = set()
                for item in files if isinstance(files, list) else []:
                    if not isinstance(item, dict) or set(item) != {
                        "role",
                        "path",
                        "bytes",
                        "sha256",
                        "mtimeNs",
                    }:
                        automation_evidence_ok = False
                        continue
                    path = Path(str(item.get("path")))
                    if (
                        not path.is_absolute()
                        or not path.is_file()
                        or path.is_symlink()
                        or item.get("bytes") != path.stat().st_size
                        or item.get("sha256") != hashlib.sha256(path.read_bytes()).hexdigest()
                        or item.get("mtimeNs") != path.stat().st_mtime_ns
                    ):
                        automation_evidence_ok = False
                    resolved = str(path.resolve())
                    if resolved in source_resolved:
                        automation_evidence_ok = False
                    source_resolved.add(resolved)
                    role = str(item.get("role"))
                    if role in source_paths or role not in {"heartbeat", "dailyWarRoom"}:
                        automation_evidence_ok = False
                    source_paths[role] = path
                if set(source_paths) != {"heartbeat", "dailyWarRoom"}:
                    automation_evidence_ok = False
                if automation_evidence_ok:
                    derived = derive_automation_snapshot(
                        runtime_root,
                        source_paths["heartbeat"],
                        source_paths["dailyWarRoom"],
                        home=home,
                        observed_at=str(actual_automation["observedAt"]),
                    )
                    for key in (
                        "schema",
                        "generator",
                        "runtimeRootDigest",
                        "releaseId",
                        "releaseHead",
                        "releaseManifestSha256",
                        "observedAt",
                        "sourceFiles",
                        "heartbeat",
                        "dailyWarRoom",
                        "workers",
                    ):
                        if actual_automation.get(key) != derived.get(key):
                            automation_evidence_ok = False
            except (OSError, json.JSONDecodeError, ValueError):
                automation_evidence_ok = False
    runtime_state = read_json(runtime_root / "state" / "runtime-health.json", {})
    runtime_state = runtime_state if isinstance(runtime_state, dict) else {}
    launch_outputs: dict[str, str] = {}

    def read_launchctl(label: str) -> str:
        output = launchctl_runner(label) if launchctl_runner is not None else launchctl_print(label)
        launch_outputs[label] = output
        return output

    snapshot: dict[str, Any] | None = None
    launch_error = None
    if strict:
        try:
            snapshot = collect_snapshot(runtime_root, launchctl_runner=read_launchctl)
            for legacy_label in LEGACY_LABELS:
                read_launchctl(legacy_label)
        except Exception as exc:
            launch_error = f"{type(exc).__name__}:{str(exc)[:240]}"
    actual_configs = {
        label: _actual_plist(home, label)
        if strict
        else {
            "path": None,
            "present": True,
            "ProgramArguments": spec["ProgramArguments"],
            "WorkingDirectory": spec["WorkingDirectory"],
        }
        for label, spec in expected_workers.items()
    }
    worker_reports = []
    actual_loaded_arguments: list[str] = []
    for worker in REQUIRED_WORKERS:
        label = WORKER_LABELS[worker]
        expected = expected_workers[label]
        actual = actual_configs[label]
        actual_args = actual.get("ProgramArguments")
        actual_workdir = actual.get("WorkingDirectory")
        launch_actual = (
            _launch_config(launch_outputs.get(label, ""))
            if strict
            else {
                "ProgramArguments": actual_args,
                "WorkingDirectory": actual_workdir,
            }
        )
        loaded = _loaded(launch_outputs.get(label, "")) if strict else False
        launch_config_match = not strict or (
            not loaded
            or (
                launch_actual.get("ProgramArguments") == actual_args
                and launch_actual.get("WorkingDirectory") == actual_workdir
            )
        )
        actual_match = (
            actual.get("present") is True
            and actual_args == expected["ProgramArguments"]
            and actual_workdir == expected["WorkingDirectory"]
        )
        if strict and loaded and isinstance(launch_actual.get("ProgramArguments"), list):
            actual_loaded_arguments.extend(
                str(value) for value in launch_actual["ProgramArguments"]
            )
        evidence = (snapshot or {}).get("workerProcesses", {}).get(worker, {})
        evidence = evidence if isinstance(evidence, dict) else {}
        launch = evidence.get("launchctl") if isinstance(evidence.get("launchctl"), dict) else {}
        process = evidence.get("process") if isinstance(evidence.get("process"), dict) else {}
        pid = launch.get("pid") if snapshot else None
        worker_reports.append(
            {
                "worker": worker,
                "label": label,
                "command": actual_args,
                "workdir": actual_workdir,
                "expectedCommand": expected["ProgramArguments"],
                "expectedWorkdir": expected["WorkingDirectory"],
                "actualConfigMatch": actual_match,
                "launchConfigMatch": launch_config_match,
                "releaseBound": isinstance(actual_args, list)
                and any(release_path in str(arg) for arg in actual_args),
                "runtimeBound": isinstance(actual_args, list)
                and runtime_path in [str(arg) for arg in actual_args],
                "loaded": loaded if strict else None,
                "pid": pid,
                "lastExitCode": launch.get("lastExitCode") if snapshot else None,
                "processAlive": process.get("alive") if snapshot else None,
                "processVersionMatched": process.get("versionMatched") if snapshot else None,
                "processWorkingDirectoryMatched": process.get("workingDirectoryMatched")
                if snapshot
                else None,
                "freshness": _freshness(runtime_state, worker),
            }
        )
    staged_receipt_valid = True
    if strict and not require_workers_loaded:
        staged_receipt_valid = verify_staged_worker_receipt(
            runtime_root,
            specs=specs,
            worker_reports=worker_reports,
            home=home,
        )
    worker_ok = all(
        item["actualConfigMatch"]
        and item["launchConfigMatch"]
        and item["releaseBound"]
        and item["runtimeBound"]
        and (
            not strict
            or (
                (item["loaded"] if require_workers_loaded else not item["loaded"])
                and (
                    not require_workers_loaded
                    or (
                        item["lastExitCode"] == 0
                        and item["freshness"]["fresh"]
                        and (
                            item["pid"] is None
                            or (
                                item["processAlive"] is True
                                and item["processVersionMatched"] is True
                                and item["processWorkingDirectoryMatched"] is True
                            )
                        )
                    )
                )
            )
        )
        for item in worker_reports
    )
    old_monolithic = any(_loaded(launch_outputs.get(label, "")) for label in LEGACY_LABELS) or any(
        argument
        in {
            f"{runtime_path}/scripts/local_publication_agent.py",
            f"{runtime_path}/scripts/local_publication_worker.py",
            f"{runtime_path}/scripts/local_dispatch_bridge.py",
        }
        for argument in actual_loaded_arguments
    )
    disk = disk_snapshot(runtime_root)
    deployment = (
        runtime_state.get("deployment") if isinstance(runtime_state.get("deployment"), dict) else {}
    )
    identity_ok = (
        deployment.get("releaseVersion") == binding.release_id
        and deployment.get("policyDigest") == binding.release.get("policyDigest")
        and deployment.get("manifestVerified") is True
        and deployment.get("deploymentDirty") is not True
    )
    pending_ok = pending_effects == 0
    disk_ok = disk.get("level") != "stop"
    runtime_git = runtime_root / ".git"
    code_git = binding.code_root / ".git"
    shared_git = (
        runtime_git.exists() and code_git.exists() and runtime_git.resolve() == code_git.resolve()
    )
    no_runtime_code_drift = all(
        not str(argument).startswith(runtime_path + "/scripts")
        for argument in actual_loaded_arguments
    )
    operational_authorization_valid = False
    operational_authorization_evidence_match = False
    if strict and require_workers_loaded:
        try:
            authorization = verify_operational_authorization(runtime_root)
            operational_authorization_evidence_match = True
            for evidence, field in (
                (managed_counts_evidence, "managedCountsEvidenceSha256"),
                (automation_snapshot, "automationSnapshotSha256"),
            ):
                if isinstance(evidence, Path) and authorization.get(
                    field
                ) != stable_evidence_digest(evidence):
                    operational_authorization_evidence_match = False
            operational_authorization_valid = operational_authorization_evidence_match
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
            operational_authorization_valid = False
    return {
        "schema": "oss-pr-radar.stage7-acceptance.v3",
        "ok": (
            contract_match
            and not old_monolithic
            and pointer_ok
            and ledger_schema_ok
            and expected_ok
            and (not strict or counts_evidence_ok)
            and (not strict or automation_evidence_ok)
            and worker_ok
            and (not strict or require_workers_loaded or staged_receipt_valid)
            and no_runtime_code_drift
            and not shared_git
            and (not strict or launch_error is None)
            and (not strict or disk_ok)
            and (not strict or (pending_ok and pending_effects == 0))
            and (not strict or identity_ok)
            and (not strict or current_signing_key_available())
            and (not strict or not require_workers_loaded or operational_authorization_valid)
        ),
        "release": {
            "path": release_path,
            "releaseId": binding.release_id,
            "manifestSha256": binding.release.get("manifestSha256"),
            "policyDigest": binding.release.get("policyDigest"),
        },
        "workers": worker_reports,
        "workerSpecDigest": worker_spec_digest(specs),
        "automationContractsMatch": contract_match,
        "actualAutomationEvidence": {
            "present": actual_automation is not None,
            "valid": automation_evidence_ok,
        },
        "ledger": {
            "pointer": str(pointer),
            "pointerValid": pointer_target_ok,
            "path": str(ledger),
            **ledger_evidence,
        },
        "noRuntimeCodeDrift": no_runtime_code_drift,
        "noSharedGitWrites": not shared_git,
        "disk": disk,
        "diskStopThresholdOk": disk_ok,
        "pendingPublicationEffects": pending_effects,
        "pendingPublicationEffectsValid": pending_ok,
        "pendingPublicationEffectsClear": pending_effects == 0,
        "managedCountsEvidenceValid": counts_evidence_ok,
        "runtimeReleasePolicyIdentityMatch": identity_ok,
        "signingCapabilityAvailable": current_signing_key_available(),
        "dangerousBridgeReachable": old_monolithic,
        "oldMonolithicWorkerReachable": old_monolithic,
        "launchctlError": launch_error,
        "strict": strict,
        "strictMode": "final"
        if strict and require_workers_loaded
        else ("preflight" if strict else "development"),
        "operationalAuthorizationValid": operational_authorization_valid,
        "stagedWorkerReceiptValid": staged_receipt_valid,
        "operationalAuthorizationEvidenceMatch": operational_authorization_evidence_match,
        "fakeSmoke": not strict,
    }


def issue_operational_authorization(
    runtime_root: Path,
    *,
    managed_counts_evidence: Path,
    automation_snapshot: Path,
    home: Path | None = None,
    launchctl_runner: Any | None = None,
) -> dict[str, Any]:
    """Issue authorization only after the strict unloaded-worker preflight."""

    def stable_json(path: Path) -> tuple[dict[str, Any], str]:
        digest = stable_evidence_digest(path)
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("operational evidence must be an object")
        if digest != stable_evidence_digest(path):
            raise RuntimeError("operational evidence changed after validation")
        return value, digest

    counts_value, counts_digest = stable_json(managed_counts_evidence)
    automation_value, automation_digest = stable_json(automation_snapshot)

    preflight = check(
        runtime_root,
        home=home,
        strict=True,
        launchctl_runner=launchctl_runner,
        managed_counts_evidence=counts_value,
        automation_snapshot=automation_value,
        require_workers_loaded=False,
    )
    if preflight.get("stagedWorkerReceiptValid") is not True:
        raise RuntimeError("operational authorization requires a valid staged worker receipt")
    return _issue_operational_authorization(
        runtime_root,
        preflight=preflight,
        managed_counts_evidence=managed_counts_evidence,
        automation_snapshot=automation_snapshot,
        managed_counts_evidence_sha256=counts_digest,
        automation_snapshot_sha256=automation_digest,
    )
