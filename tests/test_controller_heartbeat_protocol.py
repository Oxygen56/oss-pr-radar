from __future__ import annotations

from pathlib import Path

PROTOCOL = (
    Path(__file__).parents[1] / "docs" / "controller-heartbeat.md"
).read_text(encoding="utf-8")


def test_controller_protocol_uses_transactional_title_reconciliation():
    assert "title-reconcile" in PROTOCOL
    assert "Never use" in PROTOCOL
    assert "`set_thread_title` or manual `title-commit`" in PROTOCOL
    assert "do not call `set_thread_title`" in PROTOCOL
    assert "do not call `title-commit` manually" in PROTOCOL


def test_controller_protocol_keeps_fixed_point_queues_explicit():
    for operation in (
        "orphan-list",
        "pr-followup-list",
        "validation-followup-list",
        "restore-list",
        "title-list",
        "cleanup-list",
    ):
        assert operation in PROTOCOL


def test_controller_protocol_requires_structured_no_code_followup_result():
    assert "prose alone is not a" in PROTOCOL
    assert "completed handoff" in PROTOCOL
    assert "exact follow-up digest" in PROTOCOL


def test_controller_protocol_preserves_long_running_command_sessions():
    assert "text(JSON.stringify(result))" in PROTOCOL
    assert "poll that exact ID" in PROTOCOL
    assert "with `write_stdin`" in PROTOCOL
    assert "Empty output accompanied by a session ID means still running" in PROTOCOL
