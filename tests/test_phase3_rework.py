from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from oss_pr_radar.contracts import contract_digest
from oss_pr_radar.decision import AuthorizationDecision
from oss_pr_radar.dispatch import DispatchSigner, build_queue
from oss_pr_radar.evidence import EvidenceBundle
from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.outbox import (
    OUTBOX_VERSION,
    build_outbox,
    external_outbox_event_allowed,
    external_outbox_event_reason,
)
from oss_pr_radar.policy import SCANNER_DECISION_REVISION
from oss_pr_radar.repo_probe import (
    PATHS_VERIFIED,
    REPRODUCED_VALIDATED,
    TRUSTED_PROBE_PROFILES,
    run_repo_probe,
    run_reproduction_probe,
    verify_probe_receipt,
)
from oss_pr_radar.util import iso_z, sha256_json

ROOT = Path(__file__).parents[1]
BRIDGE_PATH = ROOT / "scripts" / "local_dispatch_bridge.py"
BRIDGE_SPEC = importlib.util.spec_from_file_location("phase3_bridge", BRIDGE_PATH)
BRIDGE = importlib.util.module_from_spec(BRIDGE_SPEC)
assert BRIDGE_SPEC and BRIDGE_SPEC.loader
BRIDGE_SPEC.loader.exec_module(BRIDGE)

SEND_PATH = ROOT / "scripts" / "send_notification_outbox.py"
SEND_SPEC = importlib.util.spec_from_file_location("phase3_sender", SEND_PATH)
SENDER = importlib.util.module_from_spec(SEND_SPEC)
assert SEND_SPEC and SEND_SPEC.loader
SEND_SPEC.loader.exec_module(SENDER)


KEY = "k" * 64
NOW = datetime.now(UTC) + timedelta(hours=1)


def evidence_bundle() -> EvidenceBundle:
    return EvidenceBundle(
        repo="owner/repo",
        issue_number=7,
        complete=True,
        completeness={
            "issue": "COMPLETE",
            "comments": "COMPLETE",
            "timeline": "COMPLETE",
            "repositoryPolicy": "COMPLETE",
            "relatedPullRequests": "COMPLETE",
        },
        issue={"state": "open", "title": "Runtime bug", "body": "reproduce"},
        comments=(),
        timeline=(),
        claims=(),
        maintainer_approvals=(),
        policy={
            "status": "NORMAL",
            "ai_disclosure": False,
            "ai_prohibited": False,
            "assignment_required": False,
        },
        pull_relations=(),
        hardware={"compatible": True, "required": [], "unavailable": []},
        digest="live-evidence",
    )


class FakeGitHub:
    def __init__(self, sha: str, paths: list[str] | None = None):
        self.sha = sha
        self.paths = ["src/runtime.py"] if paths is None else paths
        self.calls: list[tuple[str, str]] = []

    def repository(self, repo: str):
        self.calls.append(("repository", repo))
        return {"default_branch": "main"}

    def branch(self, repo: str, branch: str):
        self.calls.append(("branch", f"{repo}:{branch}"))
        return {"commit": {"sha": self.sha}}

    def repository_tree(self, repo: str, ref: str):
        self.calls.append(("tree", f"{repo}:{ref}"))
        return [{"path": path, "type": "blob"} for path in self.paths]


def test_repo_probe_verifies_an_exact_blob_path(monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)

    receipt = run_repo_probe(
        FakeGitHub("base-a", paths=["src/pkg/runtime.py"]),
        repo="owner/repo",
        default_branch="main",
        selected_base_sha="base-a",
        code_paths=["src/pkg/runtime.py"],
    )

    assert receipt["probeLevel"] == PATHS_VERIFIED
    assert receipt["codePathsVerified"] is True


def test_repo_probe_does_not_verify_a_directory_from_its_blob_children(monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)

    receipt = run_repo_probe(
        FakeGitHub("base-a", paths=["src/pkg/runtime.py"]),
        repo="owner/repo",
        default_branch="main",
        selected_base_sha="base-a",
        code_paths=["src/pkg"],
    )

    assert receipt["probeLevel"] == "UNVERIFIED"
    assert receipt["codePathsVerified"] is False


def intent(*, base_sha: str = "base-a", maturity: str = "mature") -> dict:
    return {
        "intentId": "intent-7",
        "key": "owner/repo#7",
        "repo": "owner/repo",
        "issueNumber": 7,
        "issueUrl": "https://github.com/owner/repo/issues/7",
        "title": "Runtime bug",
        "mode": "canary",
        "category": "NEW_CLEAN_CANDIDATE",
        "scanGate": "ALLOW_TO_WORK",
        "autoSpawn": True,
        "publicSubmissionAllowed": True,
        "llmReview": {
            "status": "ok",
            "semanticSignal": "NO_OBJECTION",
            "evidence": ["issue_data.issue_body"],
            "confidence": 0.9,
        },
        "issuedAt": iso_z(NOW),
        "expiresAt": iso_z(NOW + timedelta(hours=1)),
        "defaultBranch": "main",
        "selectedBaseSha": base_sha,
        "preTaskEvidenceDigest": "preflight-digest",
        "preTaskEvidence": {
            "issue": {"state": "open", "assignees": []},
            "policy": {"status": "NORMAL"},
            "baseSha": base_sha,
            "defaultBranch": "main",
            "codePathsPlan": ["src/runtime.py"],
        },
        "maturity": maturity,
        "notify": maturity != "exploration",
    }


def allow_verdict():
    return AuthorizationDecision("ALLOW", "ALLOW", {}, "live-evidence")


def test_all_notification_kinds_and_sender_skip_exploration(tmp_path, monkeypatch):
    candidate = {
        "repo": "owner/repo",
        "num": 7,
        "url": "https://github.com/owner/repo/issues/7",
        "title": "Exploration",
        "auto_spawn": True,
        "maturity": "exploration",
        "notify": True,
    }
    report = {"run_id": "explore", "candidate_details": [candidate]}
    assert build_outbox(report, now=NOW, kind="immediate")["events"] == []
    assert build_outbox(report, now=NOW, kind="review")["events"] == []
    assert build_outbox(report, now=NOW, kind="watch")["events"] == []

    outbox = {
        "version": OUTBOX_VERSION,
        "generatedAt": iso_z(NOW),
        "candidateStateIndex": {},
        "events": [
            {
                "eventId": "explore-event",
                "idempotencyKey": "explore-event",
                "status": "PENDING",
                "attempts": 0,
                "createdAt": iso_z(NOW),
                "kind": "watch",
                "candidateKeys": ["owner/repo#7"],
                "candidateStates": [
                    {"key": "owner/repo#7", "maturity": "exploration", "notify": True}
                ],
                "card": {},
            }
        ],
    }
    outbox["events"][0]["candidateStates"][0].update(
        {"stateId": "state-7", "kind": "watch", "notify": True}
    )
    outbox["digest"] = sha256_json({key: value for key, value in outbox.items() if key != "digest"})
    source = tmp_path / "outbox.json"
    result = tmp_path / "receipt.json"
    source.write_text(json.dumps(outbox), encoding="utf-8")
    calls = []

    class NeverSender:
        def __init__(self, *_args):
            pass

        def send_card(self, *_args, **_kwargs):
            calls.append(True)
            raise AssertionError("silent exploration reached Feishu")

    monkeypatch.setattr(SENDER, "FeishuClient", NeverSender)
    monkeypatch.setenv("FEISHU_APP_ID", "id")
    monkeypatch.setenv("FEISHU_APP_SECRET", "secret")
    monkeypatch.setenv("FEISHU_CHAT_ID", "chat")
    monkeypatch.setattr(sys, "argv", ["send_notification_outbox.py", str(source), str(result)])
    assert SENDER.main() == 0
    saved = json.loads(result.read_text(encoding="utf-8"))
    assert saved["events"][0]["status"] == "SKIPPED_SILENT"
    assert calls == []


def test_queue_import_is_pending_preflight_and_does_not_create_managed_task(tmp_path, monkeypatch):
    candidate = {
        "repo": "owner/repo",
        "num": 7,
        "url": "https://github.com/owner/repo/issues/7",
        "title": "Runtime bug",
        "issue_updated": iso_z(NOW),
        "policy_digest": "policy",
        "track": "agent_ai_infra",
        "category": "NEW_CLEAN_CANDIDATE",
        "score": 9,
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "public_submission_allowed": True,
        "preTaskEvidence": {
            "baseSha": "base-a",
            "defaultBranch": "main",
            "codePathsPlan": ["src/runtime.py"],
        },
        "preTaskGate": {"allowed": True, "evidenceDigest": "digest"},
        "llm_review": {
            "status": "ok",
            "semanticSignal": "NO_OBJECTION",
            "evidence": ["issue_data.issue_body"],
            "confidence": 0.9,
        },
    }
    report = {
        "scan_ok": True,
        "now": iso_z(NOW),
        "run_id": "run-1",
        "snapshot_id": "snapshot-1",
        "scanner_version": SCANNER_DECISION_REVISION,
        "contract_digest": contract_digest(),
        "candidate_details": [candidate],
    }
    queue = build_queue(report, DispatchSigner(KEY), now=NOW, mode="shadow")
    database = tmp_path / "radar.sqlite3"
    monkeypatch.setattr(BRIDGE, "fetch_cloud_queue", lambda: queue)
    monkeypatch.setattr(BRIDGE, "signing_key", lambda: KEY)
    imported = BRIDGE.import_signed_queue(database)
    assert imported["verified"] == 1
    with ManagedLedger(database)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0] == 0
        state = connection.execute(
            "SELECT state FROM managed_opportunities WHERE opportunity_key='owner/repo#7'"
        ).fetchone()[0]
    assert state == "PENDING_PREFLIGHT"


def test_live_base_drift_is_recorded_and_never_creates_task(tmp_path, monkeypatch):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    queued = intent(base_sha="old-base")
    store.enqueue(queued)
    client = FakeGitHub("new-base")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    monkeypatch.setattr(BRIDGE, "GitHubClient", lambda: client)
    monkeypatch.setattr(BRIDGE, "collect_evidence", lambda *_args, **_kwargs: evidence_bundle())
    monkeypatch.setattr(BRIDGE, "authorize", lambda *_args, **_kwargs: allow_verdict())

    result = BRIDGE.claim_intent(
        SimpleNamespace(
            ledger=database,
            intent_id=queued["intentId"],
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )
    assert result["authorized"] is False
    assert result["decision"]["reason_code"] == "STATE_DRIFT"
    assert result["recheckRequired"] is True
    assert result["scannerRecheck"]["staleBaseSha"] == "old-base"
    assert result["scannerRecheck"]["liveBaseSha"] == "new-base"
    with ManagedLedger(database)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT result_type FROM managed_results WHERE result_type='state_drift'"
            ).fetchone()[0]
            == "state_drift"
        )
    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage,terminal_reason FROM opportunities WHERE key='owner/repo#7'"
        ).fetchone()
        intent_status = connection.execute(
            "SELECT status FROM intents WHERE intent_id='intent-7'"
        ).fetchone()["status"]
        no_go_count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='AUDIT_NO_GO'"
        ).fetchone()[0]
    assert dict(opportunity) == {"stage": "QUALIFIED", "terminal_reason": None}
    assert intent_status == "REJECTED"
    assert no_go_count == 0
    assert store.terminal_feedback() == []
    assert store.scanner_recheck_feedback()[0]["intent_id"] == "intent-7"
    assert ("branch", "owner/repo:main") in client.calls


def test_live_issue_state_is_rechecked_before_probe_can_authorize(tmp_path, monkeypatch):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    queued = intent()
    store.enqueue(queued)
    client = FakeGitHub("base-a")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    monkeypatch.setattr(BRIDGE, "GitHubClient", lambda: client)
    monkeypatch.setattr(
        BRIDGE,
        "collect_evidence",
        lambda *_args, **_kwargs: replace(
            evidence_bundle(), issue={"state": "closed", "assignees": []}
        ),
    )
    result = BRIDGE.claim_intent(
        SimpleNamespace(
            ledger=database,
            intent_id=queued["intentId"],
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )
    assert result["authorized"] is False
    assert result["decision"]["reason_code"] == "ISSUE_NOT_OPEN"
    assert any(call[0] == "tree" for call in client.calls)


def test_probe_receipt_is_required_before_fake_thread_bind(tmp_path, monkeypatch):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    queued = intent()
    store.enqueue(queued)
    client = FakeGitHub("base-a", paths=[])
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    monkeypatch.setattr(BRIDGE, "GitHubClient", lambda: client)
    monkeypatch.setattr(BRIDGE, "collect_evidence", lambda *_args, **_kwargs: evidence_bundle())
    monkeypatch.setattr(BRIDGE, "authorize", lambda *_args, **_kwargs: allow_verdict())

    held = BRIDGE.claim_intent(
        SimpleNamespace(
            ledger=database,
            intent_id=queued["intentId"],
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )
    assert held["authorized"] is False
    assert held["decision"]["reason_code"] == "REPO_PATHS_UNRESOLVED"


def test_passed_probe_claim_then_actual_bind_creates_one_task(tmp_path, monkeypatch):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    queued = intent(base_sha="a" * 40)
    store.enqueue(queued)
    client = FakeGitHub("a" * 40)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    monkeypatch.setattr(BRIDGE, "GitHubClient", lambda: client)
    monkeypatch.setattr(BRIDGE, "collect_evidence", lambda *_args, **_kwargs: evidence_bundle())
    monkeypatch.setattr(BRIDGE, "authorize", lambda *_args, **_kwargs: allow_verdict())
    claimed = BRIDGE.claim_intent(
        SimpleNamespace(
            ledger=database,
            intent_id=queued["intentId"],
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )
    assert claimed["claimed"] is True
    assert claimed["probeLevel"] == PATHS_VERIFIED
    assert claimed["taskStage"] == "REPRODUCTION_REQUIRED"
    started = BRIDGE.creation_start(
        SimpleNamespace(ledger=database, intent_id=queued["intentId"], owner="controller")
    )
    bound = BRIDGE.creation_bind(
        SimpleNamespace(
            ledger=database,
            intent_id=queued["intentId"],
            owner="controller",
            creation_token=started["creationToken"],
            client_thread_id="thread-real-1",
        )
    )
    assert bound["clientThreadId"] == "thread-real-1"
    with ManagedLedger(database)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_tasks").fetchone()[0] == 1
        assert (
            connection.execute("SELECT thread_id FROM managed_tasks").fetchone()[0]
            == "thread-real-1"
        )
        assert (
            connection.execute("SELECT state FROM managed_tasks").fetchone()[0]
            == "REPRODUCTION_REQUIRED"
        )


def test_probe_levels_and_current_only_authorization(monkeypatch, tmp_path):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    client = FakeGitHub("base-a")
    paths = run_repo_probe(
        client,
        repo="owner/repo",
        default_branch="main",
        selected_base_sha="base-a",
        code_paths=["src/runtime.py"],
    )
    assert paths["probeLevel"] == PATHS_VERIFIED
    raw_command_calls = []
    raw_command_receipt = run_repo_probe(
        client,
        repo="owner/repo",
        default_branch="main",
        selected_base_sha="base-a",
        code_paths=["src/runtime.py"],
        reproduction_command=["sh", "-c", "touch SHOULD_NOT_RUN"],
        validation_command=["python3", "-c", "raise SystemExit(1)"],
        command_runner=lambda command, _cwd: raw_command_calls.append(command) or True,
    )
    assert raw_command_calls == []
    assert raw_command_receipt["probeLevel"] == PATHS_VERIFIED
    assert verify_probe_receipt(
        paths,
        repo="owner/repo",
        base_sha="base-a",
        code_paths=["src/runtime.py"],
        required_level=PATHS_VERIFIED,
    )
    assert not verify_probe_receipt(
        paths,
        repo="owner/repo",
        base_sha="base-a",
        code_paths=["src/runtime.py"],
        required_level=REPRODUCED_VALIDATED,
    )
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init"], cwd=checkout, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Probe Test"], cwd=checkout, check=True)
    subprocess.run(["git", "config", "user.email", "probe@example.com"], cwd=checkout, check=True)
    (checkout / "probe_target.py").write_text("assert 2 + 2 == 4\n", encoding="utf-8")
    subprocess.run(["git", "add", "probe_target.py"], cwd=checkout, check=True)
    subprocess.run(["git", "commit", "-m", "probe"], cwd=checkout, check=True, capture_output=True)
    selected_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True
    ).stdout.strip()
    monkeypatch.setitem(
        TRUSTED_PROBE_PROFILES,
        "test-real-checkout",
        {
            "reproductionArgv": ["python3", "probe_target.py"],
            "validationArgv": ["python3", "probe_target.py"],
        },
    )
    full = run_reproduction_probe(
        checkout_path=checkout,
        repo="owner/repo",
        default_branch="main",
        selected_base_sha=selected_sha,
        code_paths=["probe_target.py"],
        profile_id="test-real-checkout",
        issue_url="https://github.com/owner/repo/issues/7",
        task_id="task-7",
        thread_id="thread-7",
        head_sha=selected_sha,
        commit_sha=selected_sha,
        result_digest="probe-result",
    )
    assert full["probeLevel"] == REPRODUCED_VALIDATED
    assert verify_probe_receipt(
        full,
        repo="owner/repo",
        base_sha=selected_sha,
        code_paths=["probe_target.py"],
        issue_url="https://github.com/owner/repo/issues/7",
        task_id="task-7",
        thread_id="thread-7",
        head_sha=selected_sha,
        commit_sha=selected_sha,
        result_digest="probe-result",
    )

    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "p" * 64)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "previous-only")
    previous_receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo="owner/repo",
        default_branch="main",
        selected_base_sha=selected_sha,
        code_paths=["probe_target.py"],
        profile_id="test-real-checkout",
        issue_url="https://github.com/owner/repo/issues/7",
        task_id="task-7",
        head_sha=selected_sha,
        commit_sha=selected_sha,
        result_digest="probe-result",
    )
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "current")
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS", "p" * 64)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_PREVIOUS_ID", "previous-only")
    assert not verify_probe_receipt(
        previous_receipt,
        repo="owner/repo",
        base_sha=selected_sha,
        code_paths=["probe_target.py"],
        issue_url="https://github.com/owner/repo/issues/7",
        task_id="task-7",
        head_sha=selected_sha,
        commit_sha=selected_sha,
        result_digest="probe-result",
    )
    monkeypatch.delenv("RADAR_DISPATCH_HMAC_KEY")
    assert not verify_probe_receipt(
        full,
        repo="owner/repo",
        base_sha=selected_sha,
        code_paths=["probe_target.py"],
        issue_url="https://github.com/owner/repo/issues/7",
        task_id="task-7",
        head_sha=selected_sha,
        commit_sha=selected_sha,
        result_digest="probe-result",
    )


def test_reproduction_receipt_is_required_for_fix_ready_and_then_allows_publication(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", KEY)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(["git", "init"], cwd=checkout, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Probe Test"], cwd=checkout, check=True)
    subprocess.run(["git", "config", "user.email", "probe@example.com"], cwd=checkout, check=True)
    (checkout / "probe_target.py").write_text("assert 2 + 2 == 4\n", encoding="utf-8")
    subprocess.run(["git", "add", "probe_target.py"], cwd=checkout, check=True)
    subprocess.run(["git", "commit", "-m", "probe"], cwd=checkout, check=True, capture_output=True)
    selected_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True
    ).stdout.strip()
    monkeypatch.setitem(
        TRUSTED_PROBE_PROFILES,
        "test-adapter-real",
        {
            "reproductionArgv": ["python3", "probe_target.py"],
            "validationArgv": ["python3", "probe_target.py"],
        },
    )
    receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo="owner/repo",
        default_branch="main",
        selected_base_sha=selected_sha,
        code_paths=["probe_target.py"],
        profile_id="test-adapter-real",
        issue_url="https://github.com/owner/repo/issues/7",
        task_id="intent-7",
        thread_id="thread-7",
        head_sha="head-a",
        commit_sha="commit-a",
        result_digest="result-with-paths-only",
    )
    database = tmp_path / "radar.sqlite3"
    adapter = ManagedAdapter(tmp_path, database)
    candidate = {
        "intentId": "intent-7",
        "threadId": "thread-7",
        "issueUrl": "https://github.com/owner/repo/issues/7",
        "selectedBaseSha": selected_sha,
        "probeRequired": True,
        "preTaskEvidence": {"baseSha": selected_sha, "codePathsPlan": ["probe_target.py"]},
    }
    blocked = adapter.record_task_result(
        candidate=candidate,
        value={
            "stage": "FIX_READY",
            "commitSha": "commit-a",
            "headSha": "head-a",
            "previousHeadSha": "base-a",
            "validation": {"passed": True, "evidence": ["unit-test"]},
            "probeReceipt": {"probeLevel": PATHS_VERIFIED},
        },
        result_digest="result-with-paths-only",
    )
    assert blocked["publicationAllowed"] is False

    adapter.transition_to_implementation(
        candidate=candidate,
        receipt=receipt,
        result_digest="result-with-paths-only",
    )
    implementation_candidate = candidate | {
        "taskStage": "IMPLEMENTATION_READY",
        "probeLevel": REPRODUCED_VALIDATED,
    }
    allowed = adapter.record_task_result(
        candidate=implementation_candidate,
        value={
            "stage": "FIX_READY",
            "commitSha": "commit-a",
            "headSha": "head-a",
            "previousHeadSha": "base-a",
            "validation": {"passed": True, "evidence": ["unit-test"]},
            "reproductionReceipt": receipt,
        },
        result_digest="result-with-paths-only",
    )
    assert allowed["reproductionValidated"] is True
    assert allowed["publicationAllowed"] is True


def test_outbox_sender_rejects_old_and_malformed_events():
    old = {"eventId": "old"}
    malformed = {
        "kind": "immediate",
        "candidateKeys": ["owner/repo#7"],
        "candidateStates": [
            {
                "key": "other/repo#7",
                "stateId": "x",
                "kind": "immediate",
                "maturity": "mature",
                "notify": True,
            }
        ],
    }
    assert external_outbox_event_allowed(old) is False
    assert external_outbox_event_reason(old).startswith("REVALIDATION_REQUIRED:")
    assert external_outbox_event_allowed(malformed) is False
    assert external_outbox_event_reason(malformed).endswith("CANDIDATE_KEY_MISMATCH")


def test_thread_bind_failure_is_recorded_for_reconciliation(tmp_path, monkeypatch):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    queued = intent()
    store.enqueue(queued)
    assert store.claim(queued["intentId"], "controller", lease_minutes=15)
    started = BRIDGE.creation_start(
        SimpleNamespace(ledger=database, intent_id=queued["intentId"], owner="controller")
    )

    def fail_bind(*_args, **_kwargs):
        raise RuntimeError("managed bind interrupted")

    monkeypatch.setattr(
        "oss_pr_radar.managed_adapter.ManagedAdapter.bind_task_after_thread", fail_bind
    )
    try:
        BRIDGE.creation_bind(
            SimpleNamespace(
                ledger=database,
                intent_id=queued["intentId"],
                owner="controller",
                creation_token=started["creationToken"],
                client_thread_id="thread-orphaned",
            )
        )
    except RuntimeError as exc:
        assert "managed bind interrupted" in str(exc)
    else:
        raise AssertionError("bind failure must be visible")
    with ManagedLedger(database)._connection() as connection:
        event = connection.execute(
            "SELECT payload_json FROM managed_lifecycle_events WHERE event_type='TASK_BIND_RECONCILIATION_REQUIRED'"
        ).fetchone()
    assert event is not None
    assert "managed bind interrupted" in event["payload_json"]


def test_thread_bind_forwards_complete_opportunity_evidence_and_worktree(tmp_path, monkeypatch):
    database = tmp_path / "radar.sqlite3"
    store = RadarLedger(database)
    queued = intent(base_sha="selected-base")
    store.enqueue(queued)
    assert store.claim(queued["intentId"], "controller", lease_minutes=15)
    started = BRIDGE.creation_start(
        SimpleNamespace(ledger=database, intent_id=queued["intentId"], owner="controller")
    )
    store.bind_creation_client(
        queued["intentId"],
        owner="controller",
        creation_token=started["creationToken"],
        client_thread_id="thread-created",
    )
    captured = {}

    def capture_bind(_adapter, *, intent, thread_id, worktree_path):
        captured.update(
            intent=intent,
            thread_id=thread_id,
            worktree_path=worktree_path,
        )
        return {}

    monkeypatch.setattr(
        "oss_pr_radar.managed_adapter.ManagedAdapter.bind_task_after_thread", capture_bind
    )
    BRIDGE._managed_bind_legacy_intent(
        store,
        database,
        queued["intentId"],
        worktree_path="/tmp/owner--repo--7",
    )

    assert captured["thread_id"] == "thread-created"
    assert captured["worktree_path"] == "/tmp/owner--repo--7"
    assert captured["intent"]["selectedBaseSha"] == "selected-base"
    assert captured["intent"]["preTaskEvidence"]["codePathsPlan"] == ["src/runtime.py"]


def test_semantic_contradiction_fails_closed_before_dispatch(tmp_path, monkeypatch):
    from oss_pr_radar.llm import DeepSeekEvaluator

    evaluator = DeepSeekEvaluator(KEY, "model", "https://example.invalid", tmp_path / "cache.json")
    monkeypatch.setattr(
        evaluator,
        "_request",
        lambda _payload: {
            "decision": "NEW_CLEAN_CANDIDATE",
            "semanticSignal": "FILTER",
            "score": 10,
            "confidence": 0.99,
            "evidence_ids": ["issue_data.issue_body"],
            "contradictions": ["the issue is already fixed"],
        },
    )
    candidate = {
        "repo": "owner/repo",
        "num": 7,
        "title": "Runtime bug",
        "track": "agent_ai_infra",
        "gate_decision": "ALLOW_TO_WORK",
        "auto_spawn": True,
        "actionability_evidence": {},
        "open_pr_assessment": {"status": "none"},
        "related_issue_assessment": {"status": "none"},
    }
    result = evaluator.evaluate_candidates([candidate])[0]
    assert result["llm_review"]["semanticSignal"] == "RETRY"
    assert result["gate_decision"] == "RETRY_REQUIRED"
    assert result["auto_spawn"] is False
