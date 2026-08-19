from __future__ import annotations

import subprocess
from datetime import UTC, datetime

import pytest
from test_ledger import legal_publication_probe

from oss_pr_radar import scanner
from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES
from oss_pr_radar.scanner import Radar

pytestmark = pytest.mark.usefixtures("current_signing_key")


def test_slow_worker_runs_queued_reproduction_and_keeps_missing_profile_external(tmp_path):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    adapter = ManagedAdapter(tmp_path, database)
    worktree, base_sha, head_sha, _branch, _receipt, result_digest, _evidence = (
        legal_publication_probe(tmp_path, task_id="slow-real")
    )
    checkout = tmp_path / "slow-probe-checkout"
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(checkout), base_sha],
        cwd=worktree,
        check=True,
        capture_output=True,
    )
    profile_id = "test-slow-real-profile"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "schemaVersion": "trusted-probe-profile-v1",
        "version": 1,
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    try:
        intent = {
            "intentId": "slow-real",
            "key": "a/b#1",
            "issueUrl": "https://github.com/a/b/issues/1",
            "selectedBaseSha": base_sha,
            "defaultBranch": "main",
            "codePaths": ["runtime.py"],
            "probeProfile": profile_id,
            "headSha": head_sha,
            "commitSha": head_sha,
            "resultDigest": result_digest,
        }
        adapter.bind_task_after_thread(
            intent=intent,
            thread_id="thread-slow-real",
            worktree_path=str(checkout),
        )
        processed = adapter.ledger.run_pending_reproduction_probes()
        assert processed["processed"][0]["state"] == "SUCCEEDED"
        assert adapter.ledger.read_task("slow-real")["state"] == "IMPLEMENTATION_READY"

        adapter.bind_task_after_thread(
            intent={
                **intent,
                "intentId": "slow-no-profile",
                "probeProfile": None,
            },
            thread_id="thread-slow-no-profile",
            worktree_path=str(checkout),
        )
        waiting = adapter.ledger.run_pending_reproduction_probes()
        assert waiting["processed"][-1]["state"] == "WAITING_EXTERNAL"
        assert adapter.ledger.read_task("slow-no-profile")["state"] == "REPRODUCTION_REQUIRED"
    finally:
        TRUSTED_PROBE_PROFILES.pop(profile_id, None)
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(checkout)],
            cwd=worktree,
            check=False,
            capture_output=True,
        )


def test_scanner_entrypoint_writes_managed_opportunity(tmp_path, monkeypatch):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    seen_path = tmp_path / "seen.json"
    candidate = {
        "repo": "owner/repo",
        "num": 7,
        "title": "Streaming tool-call chunks lose their id",
        "url": "https://github.com/owner/repo/issues/7",
        "score": 9,
        "category": "NEW_CLEAN_CANDIDATE",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "labels": ["bug"],
        "issue_updated": "2026-08-19T00:00:00Z",
        "submission_policy": "normal",
        "public_submission_allowed": True,
        "actionability_evidence": {"public_repro_signals": 1},
        "open_pr_assessment": {"status": "none"},
        "related_issue_assessment": {"status": "none"},
    }

    class IdentityEvaluator:
        @classmethod
        def from_environment(cls, _path):
            return cls()

        def evaluate_candidates(self, candidates):
            return candidates

    radar = Radar(
        datetime(2026, 8, 19, tzinfo=UTC),
        2,
        seen_path,
        "",
        dry_run=True,
        notify=False,
        managed_ledger_path=database,
        repo_cache_path=tmp_path / "repo-cache.json",
        controller_feedback_path=tmp_path / "feedback.json",
        notification_outbox_path=tmp_path / "outbox.json",
    )
    monkeypatch.setattr(radar, "collect_items", lambda: {"owner/repo#7": {}})
    monkeypatch.setattr(radar, "shortlist", lambda _items: ([candidate], 1, 1))
    monkeypatch.setattr(scanner, "DeepSeekEvaluator", IdentityEvaluator)

    result = radar.run(tmp_path / "latest_scan.json")

    assert result["managed_ledger"] == {"ok": True, "recorded": 1, "outcomesRecorded": 0}
    with ManagedLedger(database)._connection() as connection:
        row = connection.execute(
            "SELECT opportunity_key,source FROM managed_opportunities"
        ).fetchone()
    assert dict(row) == {"opportunity_key": "owner/repo#7", "source": "scanner"}


def test_real_control_plane_adapter_path_reaches_all_projection_buckets(tmp_path):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    report = {
        "run_id": "scan-e2e",
        "now": "2026-08-19T00:00:00Z",
        "scanner_version": "scanner-e2e",
        "report_digest": "scan-digest",
        "candidate_details": [
            {
                "repo": "owner/repo",
                "num": number,
                "url": f"https://github.com/owner/repo/issues/{number}",
                "auto_spawn": True,
            }
            for number in range(1, 5)
        ],
    }
    assert adapter.record_scan_report(report)["recorded"] == 4
    queue = {
        "mode": "shadow",
        "intents": [
            {
                "intentId": f"task-{number}",
                "key": f"owner/repo#{number}",
                "issueUrl": f"https://github.com/owner/repo/issues/{number}",
                "issuedAt": "2026-08-19T00:01:00Z",
                "decisionDigest": f"decision-{number}",
            }
            for number in range(1, 5)
        ],
    }
    assert adapter.record_dispatch_queue(queue)["recorded"] == 4
    intents = {item["intentId"]: item for item in queue["intents"]}
    worktree, base_sha, head_sha, branch, probe_receipt, result_digest, evidence_path = (
        legal_publication_probe(
            tmp_path,
            owner_repo="owner/repo",
            issue_number=4,
            task_id="task-4",
        )
    )
    intents["task-4"].update(
        {
            "taskStage": "IMPLEMENTATION_READY",
            "probeLevel": "REPRODUCED_VALIDATED",
            "selectedBaseSha": base_sha,
            "codePaths": ["runtime.py"],
            "headSha": head_sha,
            "commitSha": head_sha,
            "resultDigest": result_digest,
            "probeReceiptDigest": probe_receipt["receiptDigest"],
            "reproductionReceipt": probe_receipt,
        }
    )
    fixtures = {}
    for number in range(1, 4):
        fixtures[number] = legal_publication_probe(
            tmp_path,
            owner_repo="owner/repo",
            issue_number=number,
            task_id=f"task-{number}",
        )
        _worktree, selected_base, _head, _branch, _receipt, _digest, _evidence = fixtures[number]
        intents[f"task-{number}"].update(
            {
                "taskStage": "IMPLEMENTATION_READY",
                "probeLevel": "REPRODUCED_VALIDATED",
                "selectedBaseSha": selected_base,
                "codePaths": ["runtime.py"],
                "headSha": _head,
                "commitSha": _head,
                "resultDigest": _digest,
                "probeReceiptDigest": _receipt["receiptDigest"],
                "reproductionReceipt": _receipt,
            }
        )
    for number in range(1, 5):
        adapter.bind_task_after_thread(
            intent=intents[f"task-{number}"],
            thread_id=f"thread-{number}",
            worktree_path=str(tmp_path / f"worktree-{number}"),
        )
    _worktree, base_1, head_1, _branch, receipt_1, digest_1, _evidence = fixtures[1]
    adapter.record_task_result(
        candidate=intents["task-1"],
        value={
            "stage": "DECISION_REQUIRED",
            "workerState": "needs_human",
            "selectedBaseSha": base_1,
            "headSha": head_1,
            "commitSha": head_1,
            "codePaths": ["runtime.py"],
            "reproductionReceipt": receipt_1,
            "resultDigest": digest_1,
        },
        result_digest=digest_1,
    )
    _worktree, base_2, head_2, _branch, receipt_2, digest_2, _evidence = fixtures[2]
    adapter.record_task_result(
        candidate=intents["task-2"],
        value={
            "stage": "queued",
            "workerState": "queued",
            "selectedBaseSha": base_2,
            "headSha": head_2,
            "commitSha": head_2,
            "codePaths": ["runtime.py"],
            "reproductionReceipt": receipt_2,
            "resultDigest": digest_2,
        },
        result_digest=digest_2,
    )
    _worktree, base_3, head_3, _branch, receipt_3, digest_3, _evidence = fixtures[3]
    adapter.record_task_result(
        candidate=intents["task-3"],
        value={
            "stage": "PR_OPEN",
            "selectedBaseSha": base_3,
            "headSha": head_3,
            "commitSha": head_3,
            "codePaths": ["runtime.py"],
            "reproductionReceipt": receipt_3,
            "resultDigest": digest_3,
        },
        result_digest=digest_3,
    )
    adapter.record_task_result(
        candidate=intents["task-4"],
        value={
            "stage": "FIX_READY",
            "taskId": "task-4",
            "taskStage": "IMPLEMENTATION_READY",
            "probeRequired": True,
            "probeLevel": "REPRODUCED_VALIDATED",
            "selectedBaseSha": base_sha,
            "headSha": head_sha,
            "commitSha": head_sha,
            "codePaths": ["runtime.py"],
            "preTaskEvidence": {"baseSha": base_sha, "codePathsPlan": ["runtime.py"]},
            "reproductionReceipt": probe_receipt,
            "resultDigest": result_digest,
            "previousHeadSha": "old-head",
            "publication": {"prUrl": "https://github.com/owner/repo/pull/4"},
            "quality": {"passed": True, "evidence": ["pytest-e2e"]},
        },
        result_digest=result_digest,
    )
    reservation = adapter.reserve_publication(
        request_id="request-4", repo="owner/repo", opportunity_key="owner/repo#4"
    )
    assert reservation["allowed"]
    adapter.record_publication_receipt(
        request={
            "requestId": "request-4",
            "issueUrl": "https://github.com/owner/repo/issues/4",
            "taskId": "task-4",
            "commitSha": head_sha,
            "publicationKind": "PR_CREATE",
            "reservationKey": reservation["reservationKey"],
            "selectedBaseSha": base_sha,
            "headSha": head_sha,
            "codePaths": ["runtime.py"],
            "preTaskEvidence": {"baseSha": base_sha, "codePathsPlan": ["runtime.py"]},
            "resultDigest": result_digest,
            "reproductionReceipt": probe_receipt,
        },
        receipt={"prUrl": "https://github.com/owner/repo/pull/4", "headSha": head_sha},
    )
    adapter.record_followup(
        {
            "items": [
                {
                    "key": "owner/repo#4",
                    "url": "https://github.com/owner/repo/pull/4",
                    "headSha": head_sha,
                    "ciStatus": "PASSED",
                    "checkedAt": "2026-08-19T00:05:00Z",
                    "evidence": {"failingChecks": [], "requestedChanges": []},
                    "actions": [],
                    "taskActions": [],
                }
            ]
        },
        {"run_id": "followup-e2e"},
    )
    projection = adapter.projection()
    assert all(projection["buckets"][bucket] for bucket in projection["buckets"])
    assert {item["bucket"] for item in projection["items"]} == {
        "DECISION_REQUIRED",
        "SYSTEM_PROCESSING",
        "WAITING_EXTERNAL",
        "PORTFOLIO_READY",
    }
    with ManagedLedger(database)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_opportunities").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM managed_results").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM managed_lifecycle_events").fetchone()[0] >= 8
        )
        assert connection.execute("SELECT COUNT(*) FROM managed_ci_runs").fetchone()[0] == 1


def test_managed_write_failure_is_visible_and_replayable(tmp_path, monkeypatch):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    report = {
        "run_id": "scan-replay",
        "now": "2026-08-19T00:00:00Z",
        "candidate_details": [{"repo": "owner/repo", "num": 1}],
    }
    original = ManagedLedger.record_event
    calls = {"count": 0}

    def fail_once(self, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("managed write unavailable")
        return original(self, **kwargs)

    monkeypatch.setattr(ManagedLedger, "record_event", fail_once)
    with pytest.raises(RuntimeError, match="managed write unavailable"):
        adapter.record_scan_report(report)
    assert adapter.record_scan_report(report)["recorded"] == 1


def test_scan_rejected_and_deferred_outcomes_become_mutually_exclusive_results(tmp_path):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    result = adapter.record_scan_report(
        {
            "run_id": "scan-outcomes",
            "now": "2026-08-19T00:00:00Z",
            "candidate_details": [],
            "issue_outcomes": {
                "owner/repo#1": {"status": "rejected", "reason": "score_low"},
                "owner/repo#2": {"status": "deferred", "reason": "issue_fetch_failed"},
            },
        }
    )
    assert result["outcomesRecorded"] == 2
    with ManagedLedger(database)._connection() as connection:
        rows = connection.execute(
            "SELECT result_type,is_current FROM managed_results ORDER BY task_id"
        ).fetchall()
        assert [dict(row) for row in rows] == [
            {"result_type": "scan_false_positive", "is_current": 1},
            {"result_type": "blocked_pre_task", "is_current": 1},
        ]


def test_publication_receipt_replays_finalize_without_second_external_effect(tmp_path, monkeypatch):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    reservation = adapter.reserve_publication(
        request_id="request-reconcile", repo="owner/repo", opportunity_key="owner/repo#9"
    )
    worktree, base_sha, head_sha, _branch, probe_receipt, result_digest, evidence_path = (
        legal_publication_probe(
            tmp_path,
            owner_repo="owner/repo",
            issue_number=9,
            task_id="request-reconcile",
        )
    )
    original = ManagedLedger.finalize_publication_reservation
    calls = {"count": 0}

    def fail_finalize_once(self, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("finalize interrupted")
        return original(self, **kwargs)

    monkeypatch.setattr(ManagedLedger, "finalize_publication_reservation", fail_finalize_once)
    request = {
        "requestId": "request-reconcile",
        "issueUrl": "https://github.com/owner/repo/issues/9",
        "publicationKind": "PR_CREATE",
        "reservationKey": reservation["reservationKey"],
        "taskId": "request-reconcile",
        "commitSha": head_sha,
        "headSha": head_sha,
        "selectedBaseSha": base_sha,
        "codePaths": ["runtime.py"],
        "preTaskEvidence": {"baseSha": base_sha, "codePathsPlan": ["runtime.py"]},
        "resultDigest": result_digest,
        "reproductionReceipt": probe_receipt,
        "evidencePath": str(evidence_path),
    }
    receipt = {"prUrl": "https://github.com/owner/repo/pull/9", "headSha": head_sha}
    with pytest.raises(RuntimeError, match="finalize interrupted"):
        adapter.record_publication_receipt(request=request, receipt=receipt)
    replay = adapter.record_publication_receipt(request=request, receipt=receipt)

    assert replay["ok"] is True
    assert calls["count"] == 2
    with ManagedLedger(database)._connection() as connection:
        assert (
            connection.execute(
                "SELECT state FROM managed_publication_reservations WHERE reservation_key=?",
                (reservation["reservationKey"],),
            ).fetchone()[0]
            == "FINALIZED"
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_prs WHERE pr_key='owner/repo#9'"
            ).fetchone()[0]
            == 1
        )


def test_blocked_publication_reservation_cannot_import_receipt(tmp_path):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    for number in range(1, 6):
        adapter.ledger.upsert_pr(
            pr_key=f"owner/repo#{number}",
            owner="owner",
            repo="repo",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=True,
        )
    reservation = adapter.reserve_publication(request_id="blocked", repo="owner/repo")
    assert reservation["allowed"] is False
    with pytest.raises(PermissionError, match="reservation is not active"):
        adapter.record_publication_receipt(
            request={
                "requestId": "blocked",
                "publicationKind": "PR_CREATE",
                "reservationKey": reservation["reservationKey"],
                "commitSha": "commit-6",
            },
            receipt={"prUrl": "https://github.com/owner/repo/pull/6", "headSha": "head-6"},
        )
    with ManagedLedger(database)._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_prs WHERE pr_key='owner/repo#6'"
            ).fetchone()[0]
            == 0
        )


def test_followup_reply_path_calls_prepare_and_defaults_to_draft(tmp_path):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    adapter.ledger.upsert_pr(
        pr_key="owner/repo#10",
        owner="owner",
        repo="repo",
        number=10,
        head_sha="head-10",
        pr_url="https://github.com/owner/repo/pull/10",
        state="OPEN",
        auto_created=True,
    )
    adapter.ledger.bind_task(
        task_id="task-10", opportunity_key="owner/repo#10", thread_id=None, worktree_path=None
    )
    adapter.ledger.record_result(
        task_id="task-10",
        result_digest="result-10",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#10",
        head_sha="head-10",
        commit_sha="commit-10",
        validation={"passed": True, "evidence": ["test"]},
        prior_head_sha="old-head",
        new_head_sha="head-10",
    )
    adapter.ledger.record_ci_run(
        ci_key="ci-10", pr_key="owner/repo#10", head_sha="head-10", status="PASSED"
    )
    adapter.record_followup(
        {
            "items": [
                {
                    "key": "owner/repo#10",
                    "url": "https://github.com/owner/repo/pull/10",
                    "headSha": "head-10",
                    "ciStatus": "PASSED",
                    "checkedAt": "2026-08-19T00:05:00Z",
                    "evidence": {
                        "failingChecks": [],
                        "requestedChanges": [
                            {
                                "reviewer": "owner-user",
                                "actorType": "User",
                                "authorAssociation": "OWNER",
                            }
                        ],
                    },
                }
            ]
        },
        {"run_id": "followup-reply"},
    )
    with ManagedLedger(database)._connection() as connection:
        reply = connection.execute(
            "SELECT mode FROM managed_public_replies WHERE pr_key='owner/repo#10'"
        ).fetchone()
    assert reply["mode"] == "DRAFT"


def test_followup_importer_records_bound_invitation_and_assignment_events(tmp_path):
    database = tmp_path / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(tmp_path, database)
    for number in range(1, 6):
        adapter.ledger.upsert_pr(
            pr_key=f"owner/repo#{number}",
            owner="owner",
            repo="repo",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=True,
        )
    state = {
        "items": [
            {
                "key": "owner/repo#7",
                "url": "https://github.com/owner/repo/pull/7",
                "headSha": "head-7",
                "checkedAt": "2026-08-19T00:05:00Z",
                "evidence": {
                    "failingChecks": [],
                    "requestedChanges": [],
                    "maintainerEvents": [
                        {
                            "eventId": "github:invite-7",
                            "eventType": "INVITATION",
                            "actorLogin": "owner-user",
                            "actorType": "User",
                            "authorAssociation": "OWNER",
                            "targetRepo": "owner/repo",
                            "targetPrKey": "owner/repo#7",
                            "opportunityKey": "owner/repo#7",
                        },
                        {
                            "eventId": "github:assign-7",
                            "eventType": "ASSIGNMENT",
                            "actorLogin": "member-user",
                            "actorType": "User",
                            "authorAssociation": "MEMBER",
                            "targetRepo": "owner/repo",
                            "targetPrKey": "owner/repo#7",
                            "opportunityKey": "owner/repo#7",
                        },
                    ],
                },
            }
        ]
    }
    adapter.record_followup(state, {"run_id": "followup-events"})
    with ManagedLedger(database)._connection() as connection:
        rows = connection.execute(
            """SELECT event_key,event_type,is_maintainer FROM managed_maintainer_events
               ORDER BY event_key"""
        ).fetchall()
    assert [dict(row) for row in rows] == [
        {"event_key": "github:assign-7", "event_type": "ASSIGNMENT", "is_maintainer": 1},
        {"event_key": "github:invite-7", "event_type": "INVITATION", "is_maintainer": 1},
    ]
    assert adapter.ledger.publication_gate(
        repo="owner/repo", invitation_event_key="github:invite-7", pr_key="owner/repo#7"
    )["allowed"]
    assert not adapter.ledger.publication_gate(
        repo="owner/repo", invitation_event_key="github:invite-7", pr_key="owner/repo#8"
    )["allowed"]
