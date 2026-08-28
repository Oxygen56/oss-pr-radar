#!/usr/bin/env python3
"""Versioned compact Stage 6 rehearsal using explicit copies and a fake sender.

The script never writes to a source or external service.  Its input live-state
file must contain one exact API-backed observation per managed PR key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.legacy_migration import (  # noqa: E402
    compact_recursive_managed_history_copy,
    import_legacy_history,
)
from oss_pr_radar.live_pr_snapshot import (  # noqa: E402
    prepare_managed_ledger,
    validate_snapshot_binding,
)
from oss_pr_radar.managed_lifecycle import reconcile_managed_pr_states  # noqa: E402
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot  # noqa: E402
from oss_pr_radar.pr_projection import ledger_projection, projection_summary  # noqa: E402
from oss_pr_radar.release_binding import (  # noqa: E402
    require_stable_code_identity,
    resolve_code_identity,
)
from oss_pr_radar.stage6_rehearsal import (  # noqa: E402
    artifact_manifest,
    public_safe_scan,
    require_free_space,
    resolve_observation_time,
    secure_atomic_json,
    secure_permissions,
    secure_sqlite_target,
    source_generation,
    stable_sqlite_copy,
    validate_detached_report_envelope,
    write_detached_report_envelope,
)
from oss_pr_radar.stage6_verification import validate_verification_manifest  # noqa: E402
from oss_pr_radar.war_room_projection import build_projection  # noqa: E402


def _verify_final_code_identity(initial_identity):
    return require_stable_code_identity(ROOT, initial_identity)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _observations(path: Path) -> list[dict]:
    value = json.loads(path.read_text(encoding="utf-8"))
    items = value.get("observations", value) if isinstance(value, dict) else value
    if not isinstance(items, list):
        raise ValueError("live state input must be an observation list")
    return items


def _counts(path: Path) -> dict[str, int]:
    with sqlite3.connect(path) as connection:
        return {
            "managedPrs": int(connection.execute("SELECT COUNT(*) FROM managed_prs").fetchone()[0]),
            "managedOpportunities": int(
                connection.execute("SELECT COUNT(*) FROM managed_opportunities").fetchone()[0]
            ),
            "managedHistoryEvents": int(
                connection.execute("SELECT COUNT(*) FROM managed_lifecycle_events").fetchone()[0]
            ),
        }


def _run_attempt(
    source_backup: Path,
    migrated: Path,
    legacy: Path,
    reports: Path,
    followup: Path,
    live_snapshot: dict,
    live_states: list[dict],
    observed_at: str,
    source_copy_attempts: int,
) -> dict:
    stable_sqlite_copy(
        source_backup,
        migrated,
        quiesce_token="stage6-compact-copy",
        max_attempts=source_copy_attempts,
    )
    history_compaction = compact_recursive_managed_history_copy(
        migrated,
        source=source_backup,
        observed_at=observed_at,
    )
    prepared = prepare_managed_ledger(
        migrated,
        production_ledger=source_backup,
        war_room_db=legacy,
        reports_dir=reports,
        followup=followup,
        observed_at=observed_at,
    )
    if prepared["keySetDigest"] != live_snapshot.get("keySetDigest"):
        raise ValueError("live-state key set does not match the pre-migration managed key set")
    reconcile = reconcile_managed_pr_states(migrated, live_states, observed_at=observed_at)
    live_projection = projection_summary(live_states)
    managed_projection = ledger_projection(migrated)
    if managed_projection["digest"] != live_projection["digest"]:
        raise ValueError("migrated PR projection does not match live snapshot identity")
    replay_legacy = import_legacy_history(
        migrated,
        production_ledger=source_backup,
        war_room_db=legacy,
        reports_dir=reports,
    )
    replay_reconcile = reconcile_managed_pr_states(migrated, live_states, observed_at=observed_at)
    migrated_projection = build_projection(migrated)
    public_snapshot = migrated.with_name(".stage6-snapshot.json.gz")
    restore = migrated.with_name("fresh-restore.sqlite3")
    if restore.exists():
        restore.unlink()
    secure_sqlite_target(restore)
    snapshot_result = export_snapshot(migrated, public_snapshot)
    import_snapshot(restore, public_snapshot)
    first_restore_projection = build_projection(restore)
    import_snapshot(restore, public_snapshot)
    replay_restore_projection = build_projection(restore)
    public_snapshot.unlink(missing_ok=True)
    return {
        "historyCompaction": history_compaction,
        "legacy": prepared["legacy"],
        "preMigration": prepared,
        "reconciliation": reconcile,
        "replay": {
            "legacyManagedHistoryEvents": replay_legacy["managedHistoryEvents"],
            "reconciliationStateCounts": replay_reconcile["after"]["stateCounts"],
            "managedCountsAfterReplay": _counts(migrated),
            "reconcileHeadMismatches": replay_reconcile["headMismatches"],
            "reconcileUnexpected": replay_reconcile["unexpectedManagedKeys"],
        },
        "counts": _counts(migrated),
        "prProjection": managed_projection,
        "livePrProjection": live_projection,
        "projectionDigest": migrated_projection["artifactDigest"],
        "restoreProjectionDigest": first_restore_projection["artifactDigest"],
        "restoreReplayProjectionDigest": replay_restore_projection["artifactDigest"],
        "snapshotContentDigest": snapshot_result["sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--legacy-db", type=Path, required=True)
    parser.add_argument("--legacy-reports", type=Path, required=True)
    parser.add_argument("--followup", type=Path, required=True)
    parser.add_argument("--live-states", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--code-head", required=True)
    parser.add_argument("--verification-manifest", type=Path, required=True)
    parser.add_argument("--observed-at")
    parser.add_argument("--source-copy-attempts", type=int, default=5)
    parser.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args()
    initial_identity = resolve_code_identity(ROOT)
    actual_head = initial_identity.commit
    if args.code_head != actual_head:
        raise ValueError("--code-head must match the current worktree HEAD")
    root = args.artifact_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    secure_permissions(root)
    projected = (
        sum(path.stat().st_size for path in (args.source, args.legacy_db) if path.exists()) * 4
        + 10 * 1024 * 1024
    )
    space = require_free_space(root, projected)
    source_backup = root / "source-ledger.sqlite3"
    migrated = root / "migrated.sqlite3"
    live_snapshot = json.loads(args.live_states.read_text(encoding="utf-8"))
    validate_snapshot_binding(
        live_snapshot,
        source=args.source,
        legacy_db=args.legacy_db,
        legacy_reports=args.legacy_reports,
        followup=args.followup,
    )
    live_states = _observations(args.live_states)
    observed_at = resolve_observation_time(live_snapshot, explicit=args.observed_at)
    verification = {}
    if args.verification_manifest:
        verification = json.loads(args.verification_manifest.read_text(encoding="utf-8"))
        verification = validate_verification_manifest(verification, args.code_head)
    attempts = []
    final = None
    for attempt in range(1, args.max_attempts + 1):
        before = source_generation(args.source)
        if before != live_snapshot["sourceGeneration"]:
            raise RuntimeError("live-state snapshot source generation is stale")
        copy = stable_sqlite_copy(args.source, source_backup, quiesce_token="stage6-source-quiesce")
        result = _run_attempt(
            source_backup,
            migrated,
            args.legacy_db,
            args.legacy_reports,
            args.followup,
            live_snapshot,
            live_states,
            observed_at=observed_at,
            source_copy_attempts=args.source_copy_attempts,
        )
        after = source_generation(args.source)
        validate_snapshot_binding(
            live_snapshot,
            source=args.source,
            legacy_db=args.legacy_db,
            legacy_reports=args.legacy_reports,
            followup=args.followup,
        )
        stable = before == after == live_snapshot["sourceGeneration"]
        attempts.append(
            {"attempt": attempt, "copy": copy, "before": before, "after": after, "stable": stable}
        )
        if stable:
            final = result
            break
    if final is None:
        raise RuntimeError("source generation did not stabilize before migration replace")
    _verify_final_code_identity(initial_identity)
    reconciliation = final["reconciliation"]
    report = {
        "schema": "oss-pr-radar.stage6.report.v2",
        "codeHead": args.code_head,
        "verification": verification,
        "sourceGenerationStable": True,
        "observationTime": observed_at,
        "observationTimeSource": "live_snapshot"
        if live_snapshot.get("generatedAt")
        else "explicit_or_runtime_now",
        "attempts": attempts,
        "disk": space,
        "sourceBackup": {"bytes": source_backup.stat().st_size, "sha256": _sha(source_backup)},
        "liveStateBinding": {
            "sourceGeneration": live_snapshot["sourceGeneration"],
            "inputDigests": live_snapshot["inputDigests"],
            "keySetDigest": live_snapshot["keySetDigest"],
        },
        "migration": final,
        "prInvariant": {
            "totalRecords": reconciliation["after"]["count"],
            "currentOpen": reconciliation["after"]["stateCounts"]["OPEN"],
            "closedOrMerged": reconciliation["after"]["stateCounts"]["CLOSED"]
            + reconciliation["after"]["stateCounts"]["MERGED"],
            "allManagedKeysObserved": reconciliation["allManagedKeysObserved"],
            "liveOpenCount": len(reconciliation["liveOpenKeys"]),
            "missing": reconciliation["missingManagedKeys"],
            "unexpected": reconciliation["unexpectedManagedKeys"],
            "duplicates": reconciliation["duplicateObservationKeys"],
            "headMismatches": reconciliation["headMismatches"],
            "managedPrProjectionDigest": final["prProjection"]["digest"],
        },
        "externalSideEffects": {
            "githubWrites": 0,
            "feishuSends": 0,
            "codexTaskMutations": 0,
            "fakeSender": True,
        },
        "artifactClassification": {"restrictedRecoveryFilesExcluded": True},
    }
    envelope_path = root / "stage6-public-envelope.json"
    envelope_path.unlink(missing_ok=True)
    manifest = artifact_manifest(
        root, exclude_names={"stage6-public-summary.json", envelope_path.name}
    )
    report["publicSafeScanBeforeReport"] = manifest["publicSafeScan"]
    report["fileInventory"] = manifest["files"]
    report["detachedEnvelope"] = {
        "path": envelope_path.name,
        "classification": "PUBLIC_SAFE",
        "binds": "report bytes and exact code HEAD",
    }
    report_path = root / "stage6-public-summary.json"
    secure_atomic_json(report_path, report)
    envelope_inventory = artifact_manifest(root, exclude_names={envelope_path.name})
    write_detached_report_envelope(
        report_path,
        envelope_path,
        code_head=args.code_head,
        inventory=envelope_inventory,
    )
    secure_permissions(root)
    if not public_safe_scan(root)["publicSafe"]:
        raise RuntimeError("public-safe Stage 6 report failed its post-write scan")
    validate_detached_report_envelope(report_path, envelope_path, code_head=args.code_head)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
