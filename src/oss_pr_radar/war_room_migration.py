"""Explicit-copy migration and rollback helpers for the War Room cutover."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .managed_lifecycle import (
    MANAGED_TABLES,
    copy_database,
    legacy_content_snapshot,
    migrate_schema,
    schema_status,
    summarize_open_prs,
)
from .managed_security import sign_current, verify_current, verify_current_or_previous
from .util import sha256_json
from .war_room_projection import export_projection

ROLLBACK_CONTEXT = "managed-snapshot-v1"
ROLLBACK_CONSUMPTION_SCHEMA = "oss-pr-radar.war-room-rollback-consumption.v1"


def _rollback_nonce_path(target: Path) -> Path:
    return target.with_name(f".{target.name}.war-room-rollback-consumptions.json")


def _rollback_lock_path(target: Path) -> Path:
    return target.with_name(f".{target.name}.war-room-rollback-consumptions.lock")


def _durable_json_replace(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _consume_rollback_nonce(manifest: dict[str, Any]) -> Path:
    target = Path(str(manifest["target"])).resolve()
    consumption_path = Path(str(manifest["rollbackConsumptionPath"])).resolve()
    expected_path = _rollback_nonce_path(target)
    if consumption_path != expected_path:
        raise RuntimeError("rollback consumption path is not bound to target")
    nonce = str(manifest.get("rollbackNonce") or "")
    digest = str(manifest.get("manifestDigest") or "")
    if not nonce or not digest:
        raise RuntimeError("rollback manifest nonce binding is missing")
    lock_path = _rollback_lock_path(target)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            if consumption_path.exists():
                try:
                    ledger = json.loads(consumption_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise RuntimeError("rollback consumption ledger is invalid") from exc
                if not isinstance(ledger, dict) or ledger.get("schema") != ROLLBACK_CONSUMPTION_SCHEMA:
                    raise RuntimeError("rollback consumption ledger schema is invalid")
                records = ledger.get("records")
                if not isinstance(records, list):
                    raise RuntimeError("rollback consumption ledger records are invalid")
                for record in records:
                    if not isinstance(record, dict):
                        raise RuntimeError("rollback consumption ledger record is invalid")
                    unsigned = {
                        key: value for key, value in record.items() if key not in {"keyId", "signature"}
                    }
                    if not verify_current_or_previous(
                        unsigned,
                        context="war-room-rollback-v1",
                        key_id=record.get("keyId"),
                        signature=record.get("signature"),
                    ):
                        raise RuntimeError("rollback consumption ledger authentication failed")
                    if record.get("manifestDigest") == digest or record.get("rollbackNonce") == nonce:
                        raise RuntimeError("rollback manifest nonce has already been consumed")
            else:
                records = []
            unsigned = {
                "schema": ROLLBACK_CONSUMPTION_SCHEMA,
                "manifestDigest": digest,
                "rollbackNonce": nonce,
                "target": str(target),
                "consumedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
            auth = sign_current(unsigned, context="war-room-rollback-v1")
            if not auth["keyId"] or not auth["signature"]:
                raise PermissionError("rollback consumption signing key is unavailable")
            record = unsigned | {"keyId": auth["keyId"], "signature": auth["signature"]}
            _durable_json_replace(
                consumption_path,
                {"schema": ROLLBACK_CONSUMPTION_SCHEMA, "records": [*records, record]},
            )
            return consumption_path
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _managed_snapshot(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        tables: dict[str, list[dict[str, Any]]] = {}
        for table in MANAGED_TABLES:
            try:
                tables[table] = [
                    dict(row)
                    for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                ]
            except sqlite3.OperationalError:
                tables[table] = []
        return {"tables": tables, "digest": sha256_json(tables)}
    finally:
        connection.close()


def _sign_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    unsigned = {key: value for key, value in manifest.items() if key not in {"manifestDigest", "keyId", "signature"}}
    digest = sha256_json(unsigned)
    auth = sign_current(
        {**unsigned, "manifestDigest": digest},
        context=ROLLBACK_CONTEXT,
    )
    if not auth["keyId"] or not auth["signature"]:
        raise PermissionError("rollback manifest signing key is unavailable")
    signature = sign_current(
        {**unsigned, "manifestDigest": digest, "keyId": auth["keyId"]},
        context=ROLLBACK_CONTEXT,
    )["signature"]
    return {**unsigned, "manifestDigest": digest, "keyId": auth["keyId"], "signature": signature}


def _verify_manifest(manifest: dict[str, Any]) -> None:
    unsigned = {key: value for key, value in manifest.items() if key not in {"manifestDigest", "keyId", "signature"}}
    digest = sha256_json(unsigned)
    if manifest.get("manifestDigest") != digest:
        raise RuntimeError("rollback manifest content digest mismatch")
    if not verify_current(
        {**unsigned, "manifestDigest": digest, "keyId": manifest.get("keyId")},
        context=ROLLBACK_CONTEXT,
        key_id=manifest.get("keyId"),
        signature=manifest.get("signature"),
    ):
        raise RuntimeError("rollback manifest authentication failed")


def _pr_history_snapshot(path: Path) -> dict[str, Any]:
    """Digest every managed PR row, including closed history."""

    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        try:
            rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM managed_prs ORDER BY pr_key"
                ).fetchall()
            ]
        except sqlite3.OperationalError:
            rows = []
        return {"count": len(rows), "digest": sha256_json(rows)}
    finally:
        connection.close()


def prepare_copy(source: Path, target: Path, *, source_commit: str = "") -> dict[str, Any]:
    """Migrate only a newly created target copy; the source is opened read-only."""

    source = source.resolve()
    target = target.resolve()
    if source == target:
        raise ValueError("migration requires an explicit different target copy")
    if not source.is_file():
        raise FileNotFoundError(source)
    rollback_backup = target.with_name(f".{target.name}.war-room-pre-migration")
    if rollback_backup.exists():
        raise FileExistsError(f"rollback backup already exists: {rollback_backup}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        copy_database(source, temporary)
        legacy_before = legacy_content_snapshot(temporary)
        prs_before = summarize_open_prs(temporary)
        pr_history_before = _pr_history_snapshot(temporary)
        managed_schema_before = schema_status(temporary)["current"]
        copy_database(temporary, rollback_backup)
        backup_digest = _file_digest(rollback_backup)
        migration = migrate_schema(temporary)
        legacy_after = legacy_content_snapshot(temporary)
        prs_after = summarize_open_prs(temporary)
        pr_history_after = _pr_history_snapshot(temporary)
        if (
            legacy_before != legacy_after
            or prs_before != prs_after
            or pr_history_before != pr_history_after
        ):
            raise RuntimeError("copy migration changed legacy data or existing open PR history")
        artifact = export_projection(temporary, source_commit=source_commit)
        before_snapshot = _managed_snapshot(rollback_backup)
        after_snapshot = _managed_snapshot(temporary)
        rollback_manifest = {
            "schema": "oss-pr-radar.war-room-rollback.v1",
            "target": str(target),
            "rollbackConsumptionPath": str(_rollback_nonce_path(target)),
            "rollbackNonce": hashlib.sha256(os.urandom(32)).hexdigest(),
            "legacyContentDigest": legacy_before["overallDigest"],
            "existingOpenPrDigest": prs_before["digest"],
            "existingPrHistoryDigest": pr_history_before["digest"],
            "rollbackBackup": str(rollback_backup),
            "managedSchemaBefore": managed_schema_before,
            "managedSchemaAfter": migration["version"],
            "backupContentDigest": backup_digest,
            "managedSnapshotBeforeDigest": before_snapshot["digest"],
            "managedSnapshotAfterDigest": after_snapshot["digest"],
            "projectionDigest": artifact["artifactDigest"],
        }
        rollback_manifest = _sign_manifest(rollback_manifest)
        os.replace(temporary, target)
        temporary = Path()
        return {
            "ok": True,
            "source": str(source),
            "target": str(target),
            "sideEffects": "target_copy_only",
            "migration": migration,
            "legacyUnchanged": True,
            "existingOpenPrPreserved": True,
            "projectionDigest": artifact["artifactDigest"],
            "rollbackManifest": rollback_manifest,
        }
    finally:
        if temporary != Path() and temporary.exists():
            temporary.unlink()
        if temporary != Path() and rollback_backup.exists():
            rollback_backup.unlink()


def rollback_copy(target: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Rollback only the explicitly named copy after verifying its manifest."""

    target = target.resolve()
    if manifest.get("schema") != "oss-pr-radar.war-room-rollback.v1":
        raise ValueError("invalid War Room rollback manifest")
    _verify_manifest(manifest)
    if Path(str(manifest.get("target"))).resolve() != target:
        raise ValueError("rollback target does not match manifest")
    if legacy_content_snapshot(target)["overallDigest"] != manifest.get("legacyContentDigest"):
        raise RuntimeError("legacy content changed after migration; rollback is unsafe")
    if _pr_history_snapshot(target)["digest"] != manifest.get("existingPrHistoryDigest"):
        raise RuntimeError("existing PR history changed after migration; rollback is unsafe")
    backup = Path(str(manifest.get("rollbackBackup"))).resolve()
    if backup == target or not backup.is_file():
        raise FileNotFoundError(backup)
    if _file_digest(backup) != manifest.get("backupContentDigest"):
        raise RuntimeError("rollback backup content digest mismatch")
    # Consume before any restore attempt. A crash after this point is
    # fail-closed: the manifest is spent and must be re-issued.
    _consume_rollback_nonce(manifest)
    if _managed_snapshot(target)["digest"] != manifest.get("managedSnapshotAfterDigest"):
        raise RuntimeError("rollback target managed snapshot changed; restore is unsafe")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.rollback.", dir=target.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        copy_database(backup, temporary)
        if _file_digest(temporary) != manifest.get("backupContentDigest"):
            raise RuntimeError("rollback temporary backup digest mismatch")
        if _managed_snapshot(temporary)["digest"] != manifest.get("managedSnapshotBeforeDigest"):
            raise RuntimeError("rollback backup managed snapshot mismatch")
        restored_projection = export_projection(temporary)
        if not restored_projection.get("artifactDigest"):
            raise RuntimeError("rollback projection verification failed")
        os.replace(temporary, target)
        temporary = Path()
        restored = {
            "target": str(target),
            "rollbackManifestDigest": sha256_json(manifest),
            "legacyPreserved": legacy_content_snapshot(target)["overallDigest"]
            == manifest["legacyContentDigest"],
            "existingPrHistoryPreserved": _pr_history_snapshot(target)["digest"]
            == manifest["existingPrHistoryDigest"],
            "schema": schema_status(target),
            "rollbackBackupRetained": str(backup),
        }
        if not restored["legacyPreserved"] or not restored["existingPrHistoryPreserved"]:
            raise RuntimeError("rollback restore verification failed")
        return restored
    finally:
        if temporary != Path() and temporary.exists():
            temporary.unlink()
