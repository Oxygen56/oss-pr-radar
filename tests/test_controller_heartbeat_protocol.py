from __future__ import annotations

from pathlib import Path

PROTOCOL = (Path(__file__).parents[1] / "docs" / "controller-heartbeat.md").read_text(
    encoding="utf-8"
)


def test_controller_protocol_has_one_deterministic_entrypoint():
    assert ".venv/bin/python scripts/controller_cycle.py" in PROTOCOL
    assert "only hourly orchestration entry point" in PROTOCOL
    assert "Do not\nrepeat individual lifecycle operations" in PROTOCOL


def test_controller_protocol_keeps_task_and_publication_boundaries():
    assert "controller, not an issue implementation task" in PROTOCOL
    assert "automatic public publication stays blocked" in PROTOCOL
    assert "publicationReceipt.prUrl" in PROTOCOL


def test_controller_protocol_serializes_and_prioritizes_dispatch():
    assert "drains at most one user-visible action" in PROTOCOL
    assert "existing PR follow-up, validation continuation, recovery, then new issue" in PROTOCOL
    assert "controller_already_running" in PROTOCOL
    assert "drain_already_running" in PROTOCOL


def test_controller_protocol_uses_event_driven_completion():
    assert "Normal throughput is\nevent-driven" in PROTOCOL
    assert "immediately calls the same" in PROTOCOL
    assert "does not poll or" in PROTOCOL


def test_controller_protocol_isolates_deepseek_harness():
    assert "DeepSeek Harness has its own automation" in PROTOCOL
    assert "task capacity, state, and metrics" in PROTOCOL


def test_controller_protocol_reports_final_truth_only():
    assert "Use only the final JSON as the run result" in PROTOCOL
    assert "finalBlockers" in PROTOCOL
    assert "failures" in PROTOCOL
    assert "Do not paste logs" in PROTOCOL


def test_controller_protocol_keeps_heartbeat_summary_plain():
    assert "运行正常；当前没有需要你处理的事情。" in PROTOCOL
    assert "Never\n  expose queue counts" in PROTOCOL
    assert "已开始处理" in PROTOCOL
    assert "已继续检查现有 PR" in PROTOCOL
    assert "你无需操作" in PROTOCOL
