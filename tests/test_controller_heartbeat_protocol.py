from __future__ import annotations

from pathlib import Path

PROTOCOL = (Path(__file__).parents[1] / "docs" / "controller-heartbeat.md").read_text(
    encoding="utf-8"
)


def test_controller_protocol_requires_visible_complete_read():
    assert "must return this file's full content" in PROTOCOL
    assert "output. Never redirect it" in PROTOCOL
    assert "Never redirect it to `/dev/null`" in PROTOCOL


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


def test_controller_protocol_recovers_terminal_desktop_errors_once():
    assert "immediateRecovery=true" in PROTOCOL
    assert "canonical recovery" in PROTOCOL
    assert "never improvise a retry or send a second recovery" in PROTOCOL


def test_controller_protocol_does_not_interrupt_active_pr_followups():
    assert "activeDeferred" in PROTOCOL
    assert "must not be reserved, resent" in PROTOCOL


def test_controller_protocol_preserves_prepared_pr_followup_snapshot():
    assert "ledger-bound prepared commit" in PROTOCOL
    assert "immutable follow-up snapshot" in PROTOCOL
    assert "verifiable controller merge" in PROTOCOL


def test_controller_protocol_delegates_validation_prefetch_to_bridge():
    assert "The bridge itself computes" in PROTOCOL
    assert "lockfile-scoped dependency prefetch" in PROTOCOL
    assert "must never inspect or execute dependency commands" in PROTOCOL
    assert "A failed prefetch leaves the candidate unreserved" in PROTOCOL
