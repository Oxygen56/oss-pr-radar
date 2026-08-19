from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oss_pr_radar.live_pr_snapshot import (
    build_live_snapshot,
    input_digests,
    validate_snapshot_binding,
    write_live_snapshot,
)
from oss_pr_radar.stage6_rehearsal import QuiescenceError, source_generation


def _legacy_db(path: Path, *, wal: bool = False) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    if wal:
        connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        "CREATE TABLE opportunities (key TEXT PRIMARY KEY, issue_url TEXT, stage TEXT, updated_at TEXT)"
    )
    connection.execute("CREATE TABLE publication_requests (request_id TEXT PRIMARY KEY)")
    connection.execute("CREATE TABLE publication_effects (effect_id TEXT PRIMARY KEY)")
    connection.execute(
        "INSERT INTO opportunities VALUES (?, ?, ?, ?)",
        ("owner/repo#1", "https://github.com/owner/repo/issues/1", "OPEN", "2026-08-19T00:00:00Z"),
    )
    connection.commit()
    return connection


def _inputs(
    tmp_path: Path, *, wal: bool = False
) -> tuple[Path, Path, Path, sqlite3.Connection | None]:
    source = tmp_path / "source.sqlite3"
    source_connection = _legacy_db(source)
    legacy_db = tmp_path / "legacy-war-room.sqlite3"
    legacy_connection = _legacy_db(legacy_db, wal=wal)
    reports = tmp_path / "legacy-reports"
    reports.mkdir()
    (reports / "latest.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
    followup = tmp_path / "followup.json"
    followup.write_text(
        json.dumps(
            {
                "items": [
                    {"url": "https://github.com/owner/repo/pull/1", "headSha": "head-1"},
                    {"url": "https://github.com/owner/repo/pull/2", "headSha": "head-2"},
                    {"url": "https://github.com/owner/repo/pull/3", "headSha": "head-3"},
                ]
            }
        ),
        encoding="utf-8",
    )
    source_connection.close()
    return source, legacy_db, reports, legacy_connection


class _FakeGitHub:
    def __init__(self, responses: dict[int, dict], failure: int | None = None, on_first=None):
        self.responses = responses
        self.failure = failure
        self.on_first = on_first
        self.calls = 0

    def pull_request(self, _repo: str, number: int) -> dict:
        self.calls += 1
        if self.calls == 1 and self.on_first is not None:
            self.on_first()
        if number == self.failure:
            raise RuntimeError("simulated GitHub read failure")
        return self.responses[number]


def _responses() -> dict[int, dict]:
    return {
        1: {
            "number": 1,
            "html_url": "https://github.com/owner/repo/pull/1",
            "state": "open",
            "merged_at": None,
            "head": {"sha": "api-head-1"},
            "title": "open",
        },
        2: {
            "number": 2,
            "html_url": "https://github.com/owner/repo/pull/2",
            "state": "closed",
            "merged_at": None,
            "head": {"sha": "api-head-2"},
            "title": "closed",
        },
        3: {
            "number": 3,
            "html_url": "https://github.com/owner/repo/pull/3",
            "state": "closed",
            "merged_at": "2026-08-19T01:00:00Z",
            "head": {"sha": "api-head-3"},
            "title": "merged",
        },
    }


def test_live_snapshot_uses_stable_two_level_copy_and_maps_all_states(tmp_path):
    source, legacy_db, reports, _ = _inputs(tmp_path)
    snapshot = build_live_snapshot(
        source,
        legacy_db=legacy_db,
        legacy_reports=reports,
        followup=tmp_path / "followup.json",
        quiesce_token="test-writer-stopped",
        client=_FakeGitHub(_responses()),
        workers=1,
    )
    assert snapshot["managedKeys"] == ["owner/repo#1", "owner/repo#2", "owner/repo#3"]
    assert [item["state"] for item in snapshot["observations"]] == ["OPEN", "CLOSED", "MERGED"]
    assert all(item["apiEvidence"]["authoritativeReadOnly"] for item in snapshot["observations"])
    assert all(item["apiEvidence"]["responseDigest"] for item in snapshot["observations"])
    assert snapshot["sourceGeneration"] == source_generation(source)
    assert snapshot["inputDigests"]["legacyDb"]["sourceGeneration"] == source_generation(legacy_db)
    output = tmp_path / "live-states.json"
    write_live_snapshot(output, snapshot)
    assert output.stat().st_mode & 0o777 == 0o600
    assert "https://github.com/owner/repo/pull/1" in output.read_text(encoding="utf-8")
    assert not list(tmp_path.glob(".live-states.json.*.tmp"))


def test_live_snapshot_api_failure_preserves_existing_output(tmp_path):
    source, legacy_db, reports, _ = _inputs(tmp_path)
    output = tmp_path / "live-states.json"
    output.write_text("previous", encoding="utf-8")
    with pytest.raises(RuntimeError, match="simulated GitHub read failure"):
        snapshot = build_live_snapshot(
            source,
            legacy_db=legacy_db,
            legacy_reports=reports,
            followup=tmp_path / "followup.json",
            quiesce_token="test-writer-stopped",
            client=_FakeGitHub(_responses(), failure=2),
            workers=1,
            max_attempts=1,
        )
        write_live_snapshot(output, snapshot)
    assert output.read_text(encoding="utf-8") == "previous"


def test_live_snapshot_validator_failure_preserves_output_and_temp_free(tmp_path):
    output = tmp_path / "live-states.json"
    output.write_text("previous", encoding="utf-8")
    calls = 0

    def validator(_value: dict) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("invalid serialized snapshot")

    with pytest.raises(ValueError, match="invalid serialized snapshot"):
        write_live_snapshot(
            output, {"url": "https://github.com/owner/repo/pull/1"}, validator=validator
        )
    assert calls == 2
    assert output.read_text(encoding="utf-8") == "previous"
    assert not list(tmp_path.glob(".live-states.json.*.tmp"))


def test_live_snapshot_rejects_pull_url_prefix_bypass(tmp_path):
    source, legacy_db, reports, _ = _inputs(tmp_path)
    responses = _responses()
    responses[1] = {**responses[1], "html_url": "https://github.com/owner/repo/pull/1evil"}
    with pytest.raises(ValueError, match="invalid html_url"):
        build_live_snapshot(
            source,
            legacy_db=legacy_db,
            legacy_reports=reports,
            followup=tmp_path / "followup.json",
            quiesce_token="test-writer-stopped",
            client=_FakeGitHub(responses),
            workers=1,
            max_attempts=1,
        )


def test_live_snapshot_aborts_when_source_changes_during_api_reads(tmp_path):
    source, legacy_db, reports, _ = _inputs(tmp_path)

    def mutate_source() -> None:
        with sqlite3.connect(source) as connection:
            connection.execute("UPDATE opportunities SET stage='CHANGED' WHERE key='owner/repo#1'")

    with pytest.raises(QuiescenceError, match="did not stabilize"):
        build_live_snapshot(
            source,
            legacy_db=legacy_db,
            legacy_reports=reports,
            followup=tmp_path / "followup.json",
            quiesce_token="test-writer-stopped",
            client=_FakeGitHub(_responses(), on_first=mutate_source),
            workers=1,
            max_attempts=1,
        )


def test_legacy_db_binding_tracks_wal_logical_changes(tmp_path):
    source, legacy_db, reports, connection = _inputs(tmp_path, wal=True)
    assert connection is not None
    try:
        before = input_digests(legacy_db, reports, tmp_path / "followup.json")
        connection.execute(
            "INSERT INTO opportunities VALUES (?, ?, ?, ?)",
            (
                "owner/repo#9",
                "https://github.com/owner/repo/issues/9",
                "NEW",
                "2026-08-19T00:01:00Z",
            ),
        )
        connection.commit()
        after = input_digests(legacy_db, reports, tmp_path / "followup.json")
        assert before["legacyDb"]["sourceGeneration"] != after["legacyDb"]["sourceGeneration"]
        assert source_generation(legacy_db)["tableCounts"]["opportunities"] == 2
    finally:
        connection.close()


def test_live_snapshot_rejects_stale_future_naive_and_tampered_evidence(tmp_path):
    source, legacy_db, reports, _ = _inputs(tmp_path)
    snapshot = build_live_snapshot(
        source,
        legacy_db=legacy_db,
        legacy_reports=reports,
        followup=tmp_path / "followup.json",
        quiesce_token="test-writer-stopped",
        client=_FakeGitHub(_responses()),
        workers=1,
    )
    kwargs = {
        "source": source,
        "legacy_db": legacy_db,
        "legacy_reports": reports,
        "followup": tmp_path / "followup.json",
    }
    old = deepcopy(snapshot)
    old_time = (datetime.now(UTC) - timedelta(minutes=31)).isoformat().replace("+00:00", "Z")
    old["generatedAt"] = old_time
    with pytest.raises(ValueError, match="too old"):
        validate_snapshot_binding(old, **kwargs)

    future = deepcopy(snapshot)
    future["generatedAt"] = (
        (datetime.now(UTC) + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    )
    with pytest.raises(ValueError, match="future"):
        validate_snapshot_binding(future, **kwargs)

    naive = deepcopy(snapshot)
    naive["observations"][0]["apiEvidence"]["fetchedAt"] = datetime.now().isoformat()
    with pytest.raises(ValueError, match="UTC"):
        validate_snapshot_binding(naive, **kwargs)

    tampered = deepcopy(snapshot)
    tampered["observations"][0]["apiEvidence"]["headSha"] = "wrong"
    with pytest.raises(ValueError, match="does not match"):
        validate_snapshot_binding(tampered, **kwargs)
