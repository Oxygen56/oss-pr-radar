from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from oss_pr_radar import scanner
from oss_pr_radar.dispatch import DispatchSigner, build_queue
from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.opportunity import (
    allocate_capacity,
    classify_scan_outcome,
    cohort_report,
    pre_task_gate,
    score_existing_pr,
    validate_result_classification,
)
from oss_pr_radar.policy import SCANNER_DECISION_REVISION
from oss_pr_radar.scope import scope_digest, scope_entries


def candidate(**updates):
    value = {
        "repo": "mature/project",
        "num": 7,
        "llm_review": {
            "semanticSignal": "NO_OBJECTION",
            "confidence": 0.9,
        },
    }
    value.update(updates)
    return value


def evidence(**updates):
    value = {
        "schema": "pre_task_evidence_v1",
        "issue": {"state": "open", "assignees": []},
        "baseSha": "base-a",
        "policy": {"status": "normal"},
        "codePaths": ["src/runtime.py"],
        "reproductionPath": True,
        "validationPath": True,
        "matureRepository": True,
        "duplicate": {"status": "none"},
        "duplicateStatus": "none",
    }
    value.update(updates)
    return value


def test_pre_task_gate_requires_live_open_issue_and_pinned_base():
    passed = pre_task_gate(candidate(), evidence())
    assert passed["allowed"] is True
    assert passed["classification"] is None
    assert len(passed["evidenceDigest"]) == 64

    closed = pre_task_gate(candidate(), evidence(issue={"state": "closed", "assignees": []}))
    assert closed["allowed"] is False
    assert closed["classification"] == "task_no_go"

    assigned = pre_task_gate(
        candidate(), evidence(issue={"state": "open", "assignees": ["maintainer"]})
    )
    assert "issue_assigned" in assigned["reasons"]
    assert assigned["allowed"] is False

    drifted = pre_task_gate(candidate(), evidence(), expected={"baseSha": "base-b"})
    assert drifted["classification"] == "state_drift"
    assert "base_sha_changed" in drifted["reasons"]

    missing_recheck = pre_task_gate(
        candidate(), evidence(), expected={"baseSha": "base-a", "issueDigest": "issue-a"}
    )
    assert missing_recheck["classification"] == "state_drift"
    assert "issue_changed" in missing_recheck["reasons"]

    deterministic_pass = pre_task_gate(candidate(llm_review={}), evidence(), require_semantic=False)
    assert deterministic_pass["allowed"] is True
    semantic_retry = pre_task_gate(candidate(llm_review={}), evidence())
    assert semantic_retry["classification"] == "blocked_pre_task"
    assert "semantic_retry" in semantic_retry["reasons"]


def test_policy_duplicate_and_code_surface_fail_closed():
    assignment = pre_task_gate(
        candidate(),
        evidence(policy={"status": "normal", "assignment_required": True}),
    )
    assert assignment["classification"] == "blocked_pre_task"
    assert "assignment_required" in assignment["reasons"]

    disclosure = pre_task_gate(
        candidate(),
        evidence(aiDisclosureConflict=True, policy={"status": "ai_disclosure_conflict"}),
    )
    assert disclosure["allowed"] is False
    assert disclosure["classification"] == "blocked_pre_task"

    docs = pre_task_gate(candidate(), evidence(codePaths=[], docsOnly=True))
    assert docs["classification"] == "task_no_go"
    assert "no_code_surface" in docs["reasons"]

    strong = pre_task_gate(
        candidate(),
        evidence(duplicate={"status": "covered_strong"}, duplicateStatus="covered_strong"),
    )
    assert strong["classification"] == "task_no_go"
    assert "strong_existing_pr" in strong["reasons"]


def test_ci_failure_does_not_erase_strong_pr_evidence():
    result = score_existing_pr(
        {
            "state": "OPEN",
            "technical_complete": True,
            "rootCauseCoverage": True,
            "testFiles": 3,
            "maintainerOwned": True,
            "ageDays": 4,
            "isDraft": False,
            "changedFiles": 4,
            "ciStatus": "FAILED",
        }
    )
    assert result["strong"] is True
    assert result["ciIsDiagnosticOnly"] is True
    assert result["components"]["maintainerRecognition"] > 0


def test_capacity_is_stable_and_never_backfills_exploration():
    mature = [
        {"repo": "mature/project", "num": index, "maturity": "mature", "score": index}
        for index in range(3)
    ]
    exploration = [
        {"repo": "explore/project", "num": index, "maturity": "exploration"} for index in range(4)
    ]
    first = allocate_capacity(mature + exploration, capacity=10, seed="run-1")
    second = allocate_capacity(mature + exploration, capacity=10, seed="run-1")
    assert first["selectedKeys"] == second["selectedKeys"]
    assert len(first["mature"]) == 3
    assert len(first["exploration"]) == 1
    assert first["unused"]["mature"] == 6


def test_learning_cohort_keeps_censored_separate_from_success_and_failure():
    now = datetime(2026, 8, 19, tzinfo=UTC)
    report = cohort_report(
        [
            {
                "key": "a",
                "selectedAt": "2026-06-01T00:00:00Z",
                "selected": True,
                "task": True,
                "outcome": "success",
            },
            {
                "key": "b",
                "selectedAt": "2026-06-01T00:00:00Z",
                "selected": True,
                "task": True,
                "outcome": "failure",
            },
            {"key": "c", "selectedAt": "2026-06-01T00:00:00Z", "selected": True, "task": True},
        ],
        now=now,
    )
    assert report["14"]["labels"] == {"success": 1, "failure": 1, "censored": 1}
    assert report["30"]["labels"]["censored"] == 1
    assert report["60"]["labels"]["censored"] == 1


def test_classifications_are_exclusive_and_scope_is_deduplicated():
    assert classify_scan_outcome("deferred", "policy_unknown") == "task_no_go"
    assert classify_scan_outcome("deferred", "lookup_failed") == "blocked_pre_task"
    assert classify_scan_outcome("rejected", "unrelated") == "scan_false_positive"
    assert validate_result_classification("state_drift") == "state_drift"
    entries = scope_entries()
    assert len({entry["repo"] for entry in entries}) == len(entries)
    assert scope_digest()


def test_scan_to_task_gate_only_creates_task_for_passed_candidate(tmp_path: Path):
    database = tmp_path / "radar.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    adapter.ensure()
    passed_gate = pre_task_gate(candidate(), evidence())
    blocked_gate = pre_task_gate(
        candidate(repo="mature/project", num=8),
        evidence(issue={"state": "closed", "assignees": []}),
    )
    common = {
        "url": "https://github.com/mature/project/issues/7",
        "title": "Runtime state is lost",
        "issue_updated": "2026-08-19T00:00:00Z",
        "policy_digest": "policy",
        "track": "agent_ai_infra",
        "score": 12,
        "public_submission_allowed": True,
        "llm_review": {
            "status": "ok",
            "semanticSignal": "NO_OBJECTION",
            "evidence": ["issue_data.issue_body"],
            "confidence": 0.9,
        },
    }
    high = {
        **common,
        "repo": "mature/project",
        "num": 7,
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "preTaskEvidence": evidence(),
        "preTaskGate": passed_gate,
    }
    low = {
        **common,
        "repo": "mature/project",
        "num": 8,
        "url": "https://github.com/mature/project/issues/8",
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "preTaskEvidence": evidence(issue={"state": "closed", "assignees": []}),
        "preTaskGate": blocked_gate,
    }
    report = {
        "scan_ok": True,
        "run_id": "scan-phase3",
        "snapshot_id": "snapshot-phase3",
        "scanner_version": SCANNER_DECISION_REVISION,
        "candidate_details": [high, low],
        "issue_outcomes": {},
    }
    adapter.record_scan_report(report)
    queue = build_queue(
        report,
        DispatchSigner("k" * 64),
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    assert [item["key"] for item in queue["intents"]] == ["mature/project#7"]
    adapter.record_dispatch_queue(queue)
    projection = adapter.projection()
    assert projection["items"] == []
    adapter.bind_task_after_thread(
        intent=queue["intents"][0], thread_id="thread-7", worktree_path=str(tmp_path / "w7")
    )
    projection = adapter.projection()
    assert [item["taskId"] for item in projection["items"]] == [queue["intents"][0]["intentId"]]
    assert projection["items"][0]["bucket"] == "SYSTEM_PROCESSING"


def test_radar_run_to_dispatch_rechecks_gate_before_task_creation(tmp_path: Path, monkeypatch):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    report_path = tmp_path / "scan.json"
    base = {
        "title": "Streaming runtime loses tool-call state",
        "issue_updated": "2026-08-19T00:00:00Z",
        "policy_digest": "policy",
        "track": "agent_ai_infra",
        "score": 12,
        "submission_policy": "normal",
        "public_submission_allowed": True,
        "llm_review": {
            "status": "ok",
            "semanticSignal": "NO_OBJECTION",
            "confidence": 0.9,
            "evidence": ["issue_data.issue_body"],
        },
    }
    high_evidence = evidence()
    high = {
        **base,
        "repo": "mature/project",
        "num": 7,
        "url": "https://github.com/mature/project/issues/7",
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "preTaskEvidence": high_evidence,
        "preTaskGate": pre_task_gate({}, high_evidence, require_semantic=False),
    }
    low_evidence = evidence(issue={"state": "closed", "assignees": []})
    low = {
        **base,
        "repo": "mature/project",
        "num": 8,
        "url": "https://github.com/mature/project/issues/8",
        "category": "WAIT_MAINTAINER",
        "gate_decision": "HUMAN_REVIEW",
        "auto_spawn": False,
        "preTaskEvidence": low_evidence,
        "preTaskGate": pre_task_gate({}, low_evidence, require_semantic=False),
    }

    class IdentityEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            for item in candidates:
                item["llm_review"] = base["llm_review"]
            return candidates

    radar = scanner.Radar(
        datetime(2026, 8, 19, tzinfo=UTC),
        2,
        tmp_path / "seen.json",
        "",
        dry_run=True,
        notify=False,
        managed_ledger_path=database,
        repo_cache_path=tmp_path / "repo-cache.json",
        controller_feedback_path=tmp_path / "feedback.json",
        notification_outbox_path=tmp_path / "outbox.json",
    )
    monkeypatch.setattr(radar, "collect_items", lambda: {"mature/project#7": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([high, low], 1, 2))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", IdentityEvaluator)

    radar.run(report_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    queue = build_queue(
        report,
        DispatchSigner("k" * 64),
        now=datetime(2026, 8, 19, tzinfo=UTC),
    )
    assert [item["key"] for item in queue["intents"]] == ["mature/project#7"]
    with ManagedAdapter(tmp_path, database).ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0] == 0
    ManagedAdapter(tmp_path, database).record_dispatch_queue(queue)
    with ManagedAdapter(tmp_path, database).ledger._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0] == 0
