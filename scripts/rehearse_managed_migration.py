#!/usr/bin/env python3
"""Read-only production SQLite/WAL rehearsal into an integration-only copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.managed_adapter import ManagedAdapter  # noqa: E402
from oss_pr_radar.managed_lifecycle import (  # noqa: E402
    copy_database,
    import_open_pr_observations,
    legacy_content_snapshot,
    migrate_schema,
    rollback_schema,
    schema_status,
)
from oss_pr_radar.util import atomic_write_json, canonical_json  # noqa: E402


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def receipt_snapshot(root: Path) -> dict[str, object]:
    files: list[dict[str, object]] = []
    state = root / "state"
    if state.is_dir():
        candidates = [
            path
            for path in state.rglob("*")
            if path.is_file()
            and (
                path.name == "local_dispatch_receipts.json"
                or path.parent.name
                in {"receipt", "receipts", "root_task_receipts", "task_turn_receipts"}
            )
        ]
        for path in sorted(candidates):
            files.append(
                {
                    "relativePath": str(path.relative_to(root)),
                    "size": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )
    return {
        "count": len(files),
        "contentDigest": hashlib.sha256(canonical_json(files).encode("utf-8")).hexdigest(),
        "files": files,
    }


def _open_pr_observations(state_path: Path) -> list[dict[str, object]]:
    if not state_path.is_file():
        return []
    state = json.loads(state_path.read_text(encoding="utf-8"))
    observations = []
    for item in state.get("items", []) if isinstance(state, dict) else []:
        if not isinstance(item, dict) or not item.get("url") or not item.get("headSha"):
            continue
        observations.append(
            {
                "url": str(item["url"]),
                "headSha": str(item["headSha"]),
                "state": "OPEN",
            }
        )
    return observations


def _pr_summary(observations: list[dict[str, object]]) -> dict[str, object]:
    stable = sorted(
        ({"url": item.get("url"), "headSha": item.get("headSha")} for item in observations),
        key=lambda item: (str(item["url"]), str(item["headSha"])),
    )
    return {
        "count": len(stable),
        "urlHeadDigest": hashlib.sha256(canonical_json(stable).encode("utf-8")).hexdigest(),
    }


def _managed_counts(path: Path) -> dict[str, int]:
    connection = sqlite3.connect(path)
    try:
        return {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in (
                "managed_prs",
                "managed_lifecycle_events",
                "managed_ci_runs",
                "managed_maintainer_events",
            )
        }
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("/Users/oxygen/Documents/github/oss-pr-radar/state/radar_ledger.sqlite3"),
    )
    parser.add_argument(
        "--source-root", type=Path, default=Path("/Users/oxygen/Documents/github/oss-pr-radar")
    )
    parser.add_argument("--followup", type=Path)
    parser.add_argument(
        "--copy", type=Path, default=ROOT / ".artifacts" / "radar_ledger.rehearsal.sqlite3"
    )
    parser.add_argument(
        "--report", type=Path, default=ROOT / "reports" / "managed-migration-rehearsal.json"
    )
    args = parser.parse_args()
    source = args.source.resolve()
    source_root = args.source_root.resolve()
    followup_path = (args.followup or source_root / "state" / "pr_followup.json").resolve()
    target = args.copy.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target == source:
        raise SystemExit("rehearsal copy must be outside the production source")
    if target.exists():
        target.unlink()
    copy_database(source, target)
    before_legacy = legacy_content_snapshot(source)
    before_receipts = receipt_snapshot(source_root)
    source_journal = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    target_connection = sqlite3.connect(target)
    try:
        source_journal_mode = str(source_journal.execute("PRAGMA journal_mode").fetchone()[0])
        target_journal_mode_before = str(
            target_connection.execute("PRAGMA journal_mode").fetchone()[0]
        )
    finally:
        source_journal.close()
        target_connection.close()
    migration = migrate_schema(target)
    after_migration_legacy = legacy_content_snapshot(target)
    observations = _open_pr_observations(followup_path)
    managed_before_import = _managed_counts(target)
    import_result = import_open_pr_observations(
        target, observations, source="war-room-readonly-snapshot"
    )
    managed_after_import = _managed_counts(target)
    adapter = ManagedAdapter(ROOT, target)
    followup_state = (
        json.loads(followup_path.read_text(encoding="utf-8"))
        if followup_path.is_file()
        else {"items": []}
    )
    managed_followup = adapter.record_followup(
        followup_state, {"run_id": "managed-migration-rehearsal"}
    )
    managed_before_replay = _managed_counts(target)
    projection = adapter.ledger.war_room_projection()
    replay_import = import_open_pr_observations(
        target, observations, source="war-room-readonly-snapshot"
    )
    after_import_legacy = legacy_content_snapshot(target)
    managed_after_replay = _managed_counts(target)
    rollback = rollback_schema(target)
    after_rollback_legacy = legacy_content_snapshot(target)
    report = {
        "schema": {
            "migration": migration,
            "rollback": rollback,
            "afterRollback": schema_status(target),
            "sourceJournalMode": source_journal_mode,
            "targetJournalModeBefore": target_journal_mode_before,
        },
        "legacy": {
            "before": before_legacy,
            "afterMigrationUnchanged": before_legacy == after_migration_legacy,
            "afterImportUnchanged": before_legacy == after_import_legacy,
            "afterRollbackUnchanged": before_legacy == after_rollback_legacy,
        },
        "receipts": {
            "before": {
                "count": before_receipts["count"],
                "contentDigest": before_receipts["contentDigest"],
                "files": before_receipts["files"],
            },
            "sourceUnchanged": receipt_snapshot(source_root) == before_receipts,
        },
        "openPrImport": {
            "beforeAfter": _pr_summary(observations),
            "import": {
                key: value for key, value in import_result.items() if key not in {"before", "after"}
            },
            "replay": {
                key: value for key, value in replay_import.items() if key not in {"before", "after"}
            },
            "managedCountsBeforeImport": managed_before_import,
            "managedCountsAfterImport": managed_after_import,
            "managedCountsBeforeReplay": managed_before_replay,
            "managedCountsAfterReplay": managed_after_replay,
            "replayNoGrowth": managed_before_replay == managed_after_replay,
        },
        "managedFollowup": managed_followup,
        "projectionBucketCounts": {key: len(value) for key, value in projection["buckets"].items()},
        "source": "read_only_sqlite_backup_and_local_war_room_snapshot",
        "secretsIncluded": False,
        "target": str(target),
    }
    atomic_write_json(args.report, report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
