from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest

from oss_pr_radar.stage6_rehearsal import (
    PUBLIC_SAFE,
    RESTRICTED_RECOVERY,
    QuiescenceError,
    artifact_manifest,
    public_safe_scan,
    require_free_space,
    resolve_observation_time,
    secure_atomic_json,
    secure_permissions,
    secure_sqlite_target,
    stable_sqlite_copy,
    validate_detached_report_envelope,
    write_detached_report_envelope,
)
from oss_pr_radar.util import iso_z, utc_now


def _source(path):
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE data (value TEXT NOT NULL)")
    connection.execute("INSERT INTO data(value) VALUES ('one')")
    connection.commit()
    connection.close()


def test_stable_copy_requires_proof_and_preserves_target_on_source_change(tmp_path):
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "target.sqlite3"
    _source(source)
    with pytest.raises(QuiescenceError, match="quiesce token"):
        stable_sqlite_copy(source, target)

    changed = False

    def writer(_attempt, path):
        nonlocal changed
        if changed:
            return
        connection = sqlite3.connect(path)
        connection.execute("INSERT INTO data(value) VALUES ('concurrent')")
        connection.commit()
        connection.close()
        changed = True

    result = stable_sqlite_copy(source, target, quiesce_token="stage6-test", generation_hook=writer)
    assert result["ok"] is True
    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT COUNT(*) FROM data").fetchone()[0] == 2

    failed_target = tmp_path / "failed.sqlite3"

    def always_writer(_attempt, path):
        connection = sqlite3.connect(path)
        connection.execute("INSERT INTO data(value) VALUES ('never-stable')")
        connection.commit()
        connection.close()

    with pytest.raises(QuiescenceError, match="did not stabilize"):
        stable_sqlite_copy(source, failed_target, quiesce_token="stage6-test", max_attempts=2, generation_hook=always_writer)
    assert not failed_target.exists()
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT COUNT(*) FROM data").fetchone()[0] == 4


def test_public_manifest_excludes_restricted_recovery_from_safety_claim(tmp_path):
    secure_atomic_json(
        tmp_path / "summary.json",
        {"worktreePath": "/Users/oxygen/private", "api_key": "sk-secret-value"},
    )
    (tmp_path / "live-open-prs.raw.json").write_text(
        json.dumps({"Authorization": "Bearer raw-secret-value"}), encoding="utf-8"
    )
    (tmp_path / "recovery.sqlite3").write_bytes(b"raw recovery bytes")
    secure_permissions(tmp_path)
    manifest = artifact_manifest(tmp_path)
    assert manifest["publicSafeScan"]["publicSafe"] is True
    assert any(item["classification"] == PUBLIC_SAFE for item in manifest["files"])
    assert any(item["classification"] == RESTRICTED_RECOVERY for item in manifest["files"])
    assert public_safe_scan(tmp_path)["violations"] == []
    assert oct(tmp_path.stat().st_mode & 0o777) == "0o700"
    assert all(oct(path.stat().st_mode & 0o777) == "0o600" for path in tmp_path.iterdir())


def test_free_space_guard_fails_before_reserve_is_crossed(tmp_path):
    with pytest.raises(OSError, match="insufficient free space"):
        require_free_space(tmp_path, projected_bytes=100, minimum_bytes=10**20)


def test_sqlite_restore_target_is_private_at_creation(tmp_path):
    target = tmp_path / "fresh-restore.sqlite3"
    secure_sqlite_target(target)
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_observation_time_is_strict_current_and_snapshot_bound():
    current = iso_z(utc_now())
    assert resolve_observation_time({"generatedAt": current}) == current
    assert resolve_observation_time({"generatedAt": current}, explicit=current) == current
    with pytest.raises(ValueError, match="match"):
        resolve_observation_time({"generatedAt": current}, explicit=iso_z(utc_now()))
    with pytest.raises(ValueError, match="strict UTC"):
        resolve_observation_time({}, explicit=current.replace("Z", "+00:00"))
    with pytest.raises(ValueError, match="too old"):
        resolve_observation_time({}, explicit=iso_z(utc_now() - timedelta(days=2)))
    with pytest.raises(ValueError, match="future"):
        resolve_observation_time({}, explicit=iso_z(utc_now() + timedelta(hours=1)))


def test_detached_report_envelope_binds_report_bytes_and_head(tmp_path):
    report = tmp_path / "stage6-public-summary.json"
    envelope = tmp_path / "stage6-public-envelope.json"
    secure_atomic_json(report, {"codeHead": "a" * 40, "status": "ok"})
    write_detached_report_envelope(report, envelope, code_head="a" * 40, inventory=artifact_manifest(tmp_path, exclude_names={envelope.name}))
    validate_detached_report_envelope(report, envelope, code_head="a" * 40)
    report.write_text(report.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="report bytes"):
        validate_detached_report_envelope(report, envelope, code_head="a" * 40)


def test_compact_fixture_envelope_covers_exact_current_tree(tmp_path):
    fixture = tmp_path / "stage7-fixture"
    fixture.mkdir()
    secure_permissions(fixture)
    report = fixture / "public-report.json"
    envelope = fixture / "public-envelope.json"
    secure_atomic_json(report, {"schema": "fixture", "codeHead": "b" * 40, "status": "ok"})
    inventory = artifact_manifest(fixture, exclude_names={envelope.name})
    write_detached_report_envelope(report, envelope, code_head="b" * 40, inventory=inventory)
    validate_detached_report_envelope(report, envelope, code_head="b" * 40)

    secure_atomic_json(fixture / "unlisted.json", {"value": "new"})
    with pytest.raises(ValueError, match="filesystem"):
        validate_detached_report_envelope(report, envelope, code_head="b" * 40)


def test_detached_envelope_rejects_unbound_inventory_fields(tmp_path):
    report = tmp_path / "report.json"
    envelope = tmp_path / "envelope.json"
    secure_atomic_json(report, {"status": "ok"})
    inventory = artifact_manifest(tmp_path, exclude_names={envelope.name})
    write_detached_report_envelope(report, envelope, code_head="c" * 40, inventory=inventory)
    payload = json.loads(envelope.read_text(encoding="utf-8"))
    payload["artifactManifest"]["files"][0]["mode"] = "0o644"
    secure_atomic_json(envelope, payload)
    with pytest.raises(ValueError, match="mode"):
        validate_detached_report_envelope(report, envelope, code_head="c" * 40)
