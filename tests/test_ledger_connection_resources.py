from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from oss_pr_radar import ledger
from oss_pr_radar.ledger import RadarLedger


@pytest.fixture
def resource_database(tmp_path: Path) -> Path:
    path = tmp_path / "connection-resources.sqlite3"
    store = RadarLedger(path)
    with store.connect() as connection:
        connection.execute("CREATE TABLE connection_resource_probe(value INTEGER NOT NULL)")
        connection.execute("INSERT INTO connection_resource_probe VALUES (0)")
    return path


def assert_closed(connection: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


@pytest.mark.parametrize("read_only", [False, True])
def test_connection_context_releases_the_actual_connection(resource_database, read_only):
    store = RadarLedger(resource_database, read_only=read_only)

    with store.connect() as connection:
        assert connection.execute("SELECT value FROM connection_resource_probe").fetchone()[0] == 0

    assert_closed(connection)


def test_explicit_begin_commits_and_releases_the_connection(resource_database):
    store = RadarLedger(resource_database)

    with store.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO connection_resource_probe VALUES (1)")

    assert_closed(connection)
    with store.connect() as verification:
        values = verification.execute(
            "SELECT value FROM connection_resource_probe ORDER BY value"
        ).fetchall()
    assert [row[0] for row in values] == [0, 1]


def test_explicit_begin_rolls_back_on_error_and_releases_the_connection(resource_database):
    store = RadarLedger(resource_database)

    with pytest.raises(ValueError, match="transaction interrupted"):
        with store.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO connection_resource_probe VALUES (1)")
            raise ValueError("transaction interrupted")

    assert_closed(connection)
    with store.connect() as verification:
        values = verification.execute(
            "SELECT value FROM connection_resource_probe ORDER BY value"
        ).fetchall()
    assert [row[0] for row in values] == [0]


@pytest.mark.parametrize("read_only", [False, True])
def test_configuration_failure_releases_the_connection(resource_database, monkeypatch, read_only):
    store = RadarLedger(resource_database, read_only=read_only)
    real_connect = sqlite3.connect
    real_execute = ledger._ClosingLedgerConnection.execute
    opened = []

    def capture_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    def fail_configuration(connection, sql, *args, **kwargs):
        if sql == "PRAGMA foreign_keys=ON":
            raise sqlite3.OperationalError("connection configuration failed")
        return real_execute(connection, sql, *args, **kwargs)

    monkeypatch.setattr(ledger.sqlite3, "connect", capture_connect)
    monkeypatch.setattr(ledger._ClosingLedgerConnection, "execute", fail_configuration)

    with pytest.raises(sqlite3.OperationalError, match="connection configuration failed"):
        store.connect()

    assert len(opened) == 1
    assert_closed(opened[0])


@pytest.mark.parametrize("read_only", [False, True])
def test_repeated_reads_do_not_exhaust_file_descriptors_without_gc(resource_database, read_only):
    # The real incident exhausted descriptors while collecting many follow-up
    # rows. Keep this resource limit isolated from pytest and host workers.
    script = """
import gc
import json
import resource
import sys
from pathlib import Path

from oss_pr_radar.ledger import RadarLedger

store = RadarLedger(Path(sys.argv[1]), read_only=sys.argv[2] == "true")
_, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))
gc.disable()
for completed in range(2_000):
    with store.connect() as connection:
        assert connection.execute("SELECT value FROM connection_resource_probe").fetchone()[0] == 0
print(json.dumps({
    "completed": completed + 1,
    "readOnly": store.read_only,
    "gcEnabled": gc.isenabled(),
    "descriptorLimit": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
}))
"""
    source_root = Path(__file__).resolve().parents[1] / "src"
    result = subprocess.run(
        [sys.executable, "-c", script, str(resource_database), str(read_only).lower()],
        env={**os.environ, "PYTHONPATH": str(source_root)},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "completed": 2_000,
        "readOnly": read_only,
        "gcEnabled": False,
        "descriptorLimit": 256,
    }
