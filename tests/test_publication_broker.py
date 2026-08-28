from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "publication_broker.py"
SPEC = importlib.util.spec_from_file_location("publication_broker", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize(
    ("broker_result", "expected_exit"),
    [
        ({"ok": True, "granted": False, "pending": False}, 0),
        ({"ok": "true", "granted": True}, 2),
    ],
)
def test_broker_uses_runtime_ledger_and_durable_review_state(
    monkeypatch, tmp_path, broker_result, expected_exit
):
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    ledger_path = runtime_root / "state" / "radar_ledger.sqlite3"
    captured = {}
    monkeypatch.setattr(MODULE, "runtime_ledger_path", lambda _root: ledger_path)
    monkeypatch.setattr(
        MODULE,
        "bind_runtime",
        lambda root, *, code_root: captured.update(binding=(root, code_root)),
    )
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda root: captured.update(authorization=root),
    )
    monkeypatch.setattr(MODULE, "RadarLedger", lambda path: ("ledger", path))

    def broker(store, request_id, *, review_state_root):
        captured.update(
            store=store,
            request_id=request_id,
            review_state_root=review_state_root,
        )
        return broker_result

    monkeypatch.setattr(MODULE, "broker_publication_request", broker)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--runtime-root", str(runtime_root), "--request-id", "request-1"],
    )

    assert MODULE.main() == expected_exit
    assert captured["store"] == ("ledger", ledger_path)
    assert captured["request_id"] == "request-1"
    assert captured["review_state_root"] == runtime_root
    assert captured["authorization"] == runtime_root


def test_broker_rejects_a_non_runtime_ledger(monkeypatch, tmp_path):
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    expected_ledger = runtime_root / "state" / "radar_ledger.sqlite3"
    monkeypatch.setattr(MODULE, "runtime_ledger_path", lambda _root: expected_ledger)
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args, **_kwargs: pytest.fail("an unbound ledger must never reach the broker"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--runtime-root",
            str(runtime_root),
            "--ledger",
            str(tmp_path / "wrong.sqlite3"),
            "--request-id",
            "request-1",
        ],
    )

    assert MODULE.main() == 2
