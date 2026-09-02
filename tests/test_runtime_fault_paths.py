from __future__ import annotations

import errno
import sqlite3
import time

import pytest
from test_ledger import insert_publication_preflight, intent

from oss_pr_radar.ledger import LedgerError, RadarLedger
from oss_pr_radar.local_publication import queue_import_once
from oss_pr_radar.runtime import (
    exclusive_lock,
    pending_publication_effects,
    record_cycle,
    rotate_log,
)
from oss_pr_radar.runtime_audit import audit_snapshot
from oss_pr_radar.util import sha256_text


def test_sqlite_interrupted_transaction_rolls_back_before_restart(tmp_path):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    store.enqueue(intent())

    with pytest.raises(sqlite3.OperationalError, match="interrupted"):
        with store.transaction() as connection:
            connection.execute("UPDATE opportunities SET title='uncommitted' WHERE key='a/b#1'")
            raise sqlite3.OperationalError("interrupted")

    restarted = RadarLedger(database)
    with restarted.connect() as connection:
        title = connection.execute("SELECT title FROM opportunities WHERE key='a/b#1'").fetchone()[
            0
        ]
    assert title == "Bug"
    replay = audit_snapshot(
        {
            "state": {},
            "release": {"valid": False},
            "sqliteInterrupted": True,
            "disk": {"level": "ok"},
            "logBytes": 0,
        }
    )
    assert "SQLITE_INTERRUPTED" in replay["faults"]


def test_creating_and_attempted_effects_are_retained_and_idempotent(tmp_path):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    store.enqueue(intent())
    assert store.claim("intent-1", "controller")
    reserved = store.reserve_creation("intent-1", owner="controller")
    restarted = RadarLedger(database)
    replayed = restarted.reserve_creation("intent-1", owner="controller")
    assert replayed["creationToken"] == reserved["creationToken"]

    insert_publication_preflight(restarted, effect_status="ATTEMPTED")
    assert pending_publication_effects(database) == 1
    effect_id = sha256_text("permit-1|push|digest")
    with restarted.connect() as connection:
        connection.execute(
            "UPDATE publication_effects SET effect_id=? WHERE effect_id='effect-1'",
            (effect_id,),
        )
    with pytest.raises(LedgerError, match="authenticated reproduction is required"):
        restarted.publication_effect(permit_id="permit-1", action="push", request_digest="digest")
    assert restarted.publication_request("request-1")["status"] == "BLOCKED"


def test_enospc_write_is_a_stop_condition(tmp_path, monkeypatch):
    def no_space(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr("oss_pr_radar.runtime._atomic_write", no_space)
    with pytest.raises(OSError) as raised:
        record_cycle(
            tmp_path,
            worker="fast",
            ok=True,
            exit_code=0,
            started_at=time.time(),
        )
    assert raised.value.errno == errno.ENOSPC
    replay = audit_snapshot(
        {
            "state": {},
            "release": {"valid": False},
            "lastErrno": "ENOSPC",
            "disk": {"level": "stop"},
            "logBytes": 0,
        }
    )
    assert {"ENOSPC", "DISK_STOP_THRESHOLD"} <= set(replay["faults"])


def test_log_rotation_handles_exact_limit_and_keeps_bounded_history(tmp_path):
    path = tmp_path / "operations.ndjson"
    path.write_bytes(b"x" * 10)
    rotate_log(path, max_bytes=10, backups=2)
    assert not path.exists()
    assert path.with_name("operations.ndjson.1").read_bytes() == b"x" * 10


def test_queue_importer_lock_prevents_duplicate_import(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot",
        lambda _root: {
            "level": "ok",
            "freeBytes": 100 * 1024**3,
            "usedFraction": 0.5,
        },
    )
    calls = []
    with exclusive_lock(tmp_path / "state" / "queue-import.lock"):
        result = queue_import_once(
            tmp_path,
            runner=lambda *_args: calls.append(True) or {"ok": True},
        )
    assert result["busy"] is True
    assert calls == []
