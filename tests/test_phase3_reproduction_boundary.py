from __future__ import annotations

import gzip
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_local_dispatch_bridge import registered_store
from test_phase3_rework import BRIDGE, FakeGitHub
from test_publication import prepared_request

from oss_pr_radar import repo_probe
from oss_pr_radar.ledger import LedgerError
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_lifecycle import ManagedLedger, _parse_rfc3339_utc
from oss_pr_radar.managed_security import sign_current
from oss_pr_radar.managed_snapshot import (
    SNAPSHOT_AUTH_CONTEXT,
    export_snapshot,
    import_snapshot,
)
from oss_pr_radar.managed_snapshot import (
    _digest as snapshot_digest,
)
from oss_pr_radar.repo_probe import (
    PATHS_VERIFIED,
    REPRODUCED_VALIDATED,
    TRUSTED_PROBE_PROFILES,
    run_repo_probe,
    run_reproduction_probe,
    verify_probe_receipt,
)
from oss_pr_radar.util import iso_z

pytestmark = pytest.mark.usefixtures("current_signing_key")


def real_checkout(tmp_path):
    checkout = tmp_path / "pinned-checkout"
    checkout.mkdir()
    for args in (
        ["git", "init"],
        ["git", "config", "user.name", "Probe Test"],
        ["git", "config", "user.email", "probe@example.com"],
    ):
        subprocess.run(args, cwd=checkout, check=True, capture_output=True)
    (checkout / "target.py").write_text("assert 2 + 2 == 4\n", encoding="utf-8")
    subprocess.run(["git", "add", "target.py"], cwd=checkout, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "probe"], cwd=checkout, check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True
    ).stdout.strip()
    return checkout, sha


def test_missing_probe_contract_is_reproduction_required(tmp_path):
    database = tmp_path / "managed.sqlite3"
    adapter = ManagedAdapter(tmp_path, database)
    result = adapter.record_task_result(
        candidate={
            "intentId": "task-legacy",
            "threadId": "thread-legacy",
            "issueUrl": "https://github.com/owner/repo/issues/1",
            "selectedBaseSha": "base",
        },
        value={
            "stage": "FIX_READY",
            "commitSha": "commit",
            "headSha": "head",
            "validation": {"passed": True, "evidence": ["forged-pass"]},
        },
        result_digest="legacy-result",
    )
    assert result["reproductionValidated"] is False
    assert result["implementationAuthorized"] is False
    assert result["publicationAllowed"] is False
    task = ManagedLedger(database).read_task("task-legacy")
    assert task and task["state"] == "REPRODUCTION_REQUIRED"


def test_task_context_forged_implementation_digest_stays_read_only(tmp_path):
    store, worktree = registered_store(tmp_path)
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update(
            {
                "taskStage": "IMPLEMENTATION_READY",
                "probeLevel": REPRODUCED_VALIDATED,
                "probeReceiptDigest": "forged-digest-only",
                "selectedBaseSha": "base-sha",
                "codePaths": ["target.py"],
                "headSha": "head-sha",
                "commitSha": "commit-sha",
                "resultDigest": "result-sha",
            }
        )
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )
    context_path = BRIDGE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["taskStage"] == "REPRODUCTION_REQUIRED"
    assert context["childMayEditFiles"] is False
    assert context["allowedActions"] == [
        "read_issue",
        "read_repo",
        "run_reproduction_probe",
        "write_structured_result",
    ]


def test_print_profile_and_issue_command_cannot_become_full_receipt(monkeypatch, tmp_path):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "k" * 64)
    path_only = run_repo_probe(
        FakeGitHub("base"),
        repo="owner/repo",
        default_branch="main",
        selected_base_sha="base",
        code_paths=["src/runtime.py"],
        reproduction_command=["python3", "-c", "print('passed')"],
        validation_command=["python3", "-c", "print('passed')"],
    )
    assert path_only["probeLevel"] == PATHS_VERIFIED
    checkout, sha = real_checkout(tmp_path)
    monkeypatch.setitem(
        TRUSTED_PROBE_PROFILES,
        "untrusted-print-profile",
        {
            "reproductionArgv": ["python3", "-c", "print('passed')"],
            "validationArgv": ["python3", "target.py"],
        },
    )
    receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo="owner/repo",
        default_branch="main",
        selected_base_sha=sha,
        code_paths=["target.py"],
        profile_id="untrusted-print-profile",
        issue_url="https://github.com/owner/repo/issues/1",
        task_id="task-1",
        head_sha="head-1",
        commit_sha="commit-1",
        result_digest="result-1",
    )
    assert receipt["probeLevel"] == PATHS_VERIFIED
    assert not verify_probe_receipt(
        receipt,
        repo="owner/repo",
        base_sha=sha,
        code_paths=["target.py"],
        required_level=REPRODUCED_VALIDATED,
        issue_url="https://github.com/owner/repo/issues/1",
        task_id="task-1",
        head_sha="head-1",
        commit_sha="commit-1",
        result_digest="result-1",
    )


def test_legacy_request_and_effect_are_blocked_without_external_replay(tmp_path):
    store, request, _ = prepared_request(tmp_path)
    row = store.publication_request(request["request_id"])
    payload = row["request"]
    payload.pop("probeReceipt", None)
    payload.pop("resultDigest", None)
    now = iso_z(datetime.now(UTC) + timedelta(minutes=10))
    permit_id = "legacy-permit"
    with store.connect() as connection:
        connection.execute(
            "UPDATE publication_requests SET status='GRANTED',request_json=?,permit_id=? WHERE request_id=?",
            (json.dumps(payload), permit_id, request["request_id"]),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,evidence_json,created_at,updated_at)
               VALUES (?,?,?,?,?,'ACTIVE',?,?,?,?)""",
            (
                permit_id,
                request["request_id"],
                row["request"]["issueUrl"],
                row["commit_sha"],
                row["branch"],
                now,
                "{}",
                now,
                now,
            ),
        )
    with pytest.raises(LedgerError, match="reproduction"):
        store.publication_effect(permit_id=permit_id, action="push", request_digest="legacy")
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT status,reason FROM publication_requests WHERE request_id=?",
                (request["request_id"],),
            ).fetchone()["reason"]
            == "BLOCKED_REPRODUCTION_REQUIRED"
        )
        assert (
            connection.execute(
                "SELECT status FROM publication_permits WHERE permit_id=?", (permit_id,)
            ).fetchone()["status"]
            == "BLOCKED"
        )


def _real_probe(
    checkout: Path,
    sha: str,
    *,
    task_id: str = "probe-task",
    result_digest: str = "probe-result",
    code_paths: list[str] | None = None,
):
    profile_id = f"test-real-{task_id}"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "schemaVersion": "trusted-probe-profile-v1",
        "version": 1,
        "reproductionArgv": ["python3", "target.py"],
        "validationArgv": ["python3", "target.py"],
    }
    try:
        return run_reproduction_probe(
            checkout_path=checkout,
            repo="owner/repo",
            default_branch="main",
            selected_base_sha=sha,
            code_paths=code_paths or ["target.py"],
            profile_id=profile_id,
            issue_url="https://github.com/owner/repo/issues/1",
            task_id=task_id,
            head_sha=sha,
            commit_sha=sha,
            result_digest=result_digest,
        )
    finally:
        TRUSTED_PROBE_PROFILES.pop(profile_id, None)


def test_symlink_nested_symlink_and_toctou_never_authorize_probe(monkeypatch, tmp_path):
    checkout, sha = real_checkout(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (checkout / "escape.py").symlink_to(outside)
    symlink_receipt = _real_probe(
        checkout, sha, task_id="symlink", code_paths=["target.py", "escape.py"]
    )
    assert symlink_receipt["probeLevel"] == "UNVERIFIED"
    assert not verify_probe_receipt(
        symlink_receipt,
        repo="owner/repo",
        base_sha=sha,
        code_paths=["target.py", "escape.py"],
        required_level=REPRODUCED_VALIDATED,
        issue_url="https://github.com/owner/repo/issues/1",
        task_id="symlink",
        head_sha=sha,
        commit_sha=sha,
        result_digest="probe-result",
    )
    (checkout / "escape.py").unlink()
    (checkout / "nested").mkdir()
    (checkout / "nested" / "link").symlink_to(outside)
    nested = _real_probe(
        checkout,
        sha,
        task_id="nested",
        result_digest="nested-result",
        code_paths=["target.py", "nested/link"],
    )
    assert nested["probeLevel"] == "UNVERIFIED"
    (checkout / "nested" / "link").unlink()
    (checkout / "nested").rmdir()

    original_runner = repo_probe._run_profile_command

    def mutate_before_execution(command, cwd, code_paths=None, **kwargs):
        # The source worktree may be replaced after archive creation; the
        # worker must continue only against the immutable Git snapshot.
        (checkout / "target.py").unlink()
        (checkout / "target.py").symlink_to(outside)
        return original_runner(command, cwd, code_paths, **kwargs)

    monkeypatch.setattr(repo_probe, "_run_profile_command", mutate_before_execution)
    raced = _real_probe(checkout, sha, task_id="toctou", result_digest="toctou-result")
    assert raced["probeLevel"] == REPRODUCED_VALIDATED
    assert verify_probe_receipt(
        raced,
        repo="owner/repo",
        base_sha=sha,
        code_paths=["target.py"],
        required_level=REPRODUCED_VALIDATED,
        issue_url="https://github.com/owner/repo/issues/1",
        task_id="toctou",
        head_sha=sha,
        commit_sha=sha,
        result_digest="toctou-result",
    )


def test_missing_sandbox_backend_never_calls_injected_runner(monkeypatch, tmp_path):
    checkout, sha = real_checkout(tmp_path)
    calls = []
    monkeypatch.setattr(repo_probe.shutil, "which", lambda name: None)
    profile_id = "test-no-sandbox"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "target.py"],
        "validationArgv": ["python3", "target.py"],
    }
    try:
        receipt = run_reproduction_probe(
            checkout_path=checkout,
            repo="owner/repo",
            default_branch="main",
            selected_base_sha=sha,
            code_paths=["target.py"],
            profile_id=profile_id,
            issue_url="https://github.com/owner/repo/issues/1",
            task_id="no-sandbox",
            head_sha=sha,
            commit_sha=sha,
            result_digest="no-sandbox-result",
            command_runner=lambda *_args: calls.append(True) or 0,
            _test_only_command_runner=True,
        )
    finally:
        TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    assert calls == []
    assert receipt["reason"] == "SANDBOX_BACKEND_UNAVAILABLE"
    assert receipt["probeLevel"] == "UNVERIFIED"


def test_real_probe_sandbox_denies_host_secret_write_and_network(tmp_path):
    if sys.platform != "darwin" or not shutil.which("sandbox-exec"):
        pytest.skip("macOS sandbox backend is required for this behavior test")
    checkout, sha = real_checkout(tmp_path)
    unrelated_host_file = Path("/private/tmp/oss-pr-radar-host-read-test")
    unrelated_tmp_file = Path("/private/tmp/oss-pr-radar-host-read-test-2")
    host_write_file = Path("/private/tmp/oss-pr-radar-host-write-sentinel")
    unrelated_host_file.write_text("host-only", encoding="utf-8")
    unrelated_tmp_file.write_text("host-only-2", encoding="utf-8")
    host_write_file.unlink(missing_ok=True)
    script = checkout / "tests" / "security_probe.py"
    script.parent.mkdir()
    script.write_text(
        f"""from pathlib import Path
import socket

read_denied = False
try:
    Path({str(unrelated_tmp_file)!r}).read_text()
except PermissionError:
    read_denied = True

tmp_read_denied = False
try:
    Path({str(unrelated_host_file)!r}).read_text()
except PermissionError:
    tmp_read_denied = True

write_denied = False
host_write = Path({str(host_write_file)!r})
try:
    host_write.write_text('must-not-write')
except PermissionError:
    write_denied = True

network_denied = False
try:
    socket.create_connection(('1.1.1.1', 80), timeout=1)
except PermissionError:
    network_denied = True
except OSError:
    pass

raise SystemExit(0 if read_denied and tmp_read_denied and write_denied and network_denied else 7)
""",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "add", "tests/security_probe.py"], cwd=checkout, check=True, capture_output=True
    )
    subprocess.run(
        ["git", "commit", "-m", "security probe"], cwd=checkout, check=True, capture_output=True
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True
    ).stdout.strip()
    profile_id = "security-probe-test"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "schemaVersion": "trusted-probe-profile-v1",
        "version": 1,
        "requiresExistingTestPath": True,
        "reproductionArgv": ["python3", "{existingTestPath}"],
        "validationArgv": ["python3", "{existingTestPath}"],
    }
    attempt_id = "sandbox-security-attempt"
    before = set(Path("/private/tmp").glob(f"oss-pr-radar-probe-attempt-{attempt_id}-*"))
    try:
        receipt = run_reproduction_probe(
            checkout_path=checkout,
            repo="owner/repo",
            default_branch="main",
            selected_base_sha=sha,
            code_paths=["tests/security_probe.py"],
            profile_id=profile_id,
            issue_url="https://github.com/owner/repo/issues/1",
            task_id="sandbox-security",
            head_sha=sha,
            commit_sha=sha,
            result_digest="sandbox-security-result",
            attempt_id=attempt_id,
        )
    finally:
        TRUSTED_PROBE_PROFILES.pop(profile_id, None)
        unrelated_host_file.unlink(missing_ok=True)
        unrelated_tmp_file.unlink(missing_ok=True)
        host_write_file.unlink(missing_ok=True)
    assert receipt["probeLevel"] == REPRODUCED_VALIDATED, receipt
    assert receipt["attemptJournal"]["externalEffectCount"] == 0
    assert set(Path("/private/tmp").glob(f"oss-pr-radar-probe-attempt-{attempt_id}-*")) == before


def test_git_archive_rejects_committed_symlink_object(tmp_path):
    checkout, _sha = real_checkout(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("raise SystemExit(0)\n", encoding="utf-8")
    (checkout / "link.py").symlink_to(outside)
    subprocess.run(["git", "add", "link.py"], cwd=checkout, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "symlink"], cwd=checkout, check=True, capture_output=True
    )
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True
    ).stdout.strip()
    receipt = _real_probe(checkout, sha, task_id="archive-symlink", code_paths=["link.py"])
    assert receipt["reason"] == "ARCHIVE_OBJECT_UNSAFE"
    assert receipt["probeLevel"] == "UNVERIFIED"


def test_probe_crash_after_command_leaves_no_attempt_sandbox_and_reclaims(tmp_path):
    checkout, sha = real_checkout(tmp_path)
    database = tmp_path / "crash.sqlite3"
    ledger = ManagedLedger(database, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": sha, "codePaths": ["target.py"]},
    )
    ledger.bind_task(
        task_id="crash-task",
        opportunity_key="owner/repo#1",
        thread_id="thread-crash",
        worktree_path=str(checkout),
    )
    ledger.queue_reproduction_probe(
        task_id="crash-task",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/1",
        default_branch="main",
        selected_base_sha=sha,
        code_paths=["target.py"],
        profile_id=None,
        checkout_path=str(checkout),
        head_sha=sha,
        commit_sha=sha,
        result_digest="crash-result",
        idempotency_key="crash-intent",
    )
    claimed = ledger.claim_reproduction_probe(worker_nonce="crash-worker")
    assert claimed
    profile_id = "crash-test-profile"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "schemaVersion": "trusted-probe-profile-v1",
        "version": 1,
        "reproductionArgv": ["python3", "target.py"],
        "validationArgv": ["python3", "target.py"],
    }
    seen_cwd = []
    before = set(Path("/private/tmp").glob(f"oss-pr-radar-probe-attempt-{claimed['attempt_id']}-*"))
    try:
        with pytest.raises(KeyboardInterrupt):
            run_reproduction_probe(
                checkout_path=checkout,
                repo="owner/repo",
                default_branch="main",
                selected_base_sha=sha,
                code_paths=["target.py"],
                profile_id=profile_id,
                issue_url="https://github.com/owner/repo/issues/1",
                task_id="crash-task",
                head_sha=sha,
                commit_sha=sha,
                result_digest="crash-result",
                attempt_id=claimed["attempt_id"],
                command_runner=lambda _command, cwd: (
                    seen_cwd.append(cwd) or (_ for _ in ()).throw(KeyboardInterrupt())
                ),
                _test_only_command_runner=True,
            )
    finally:
        TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    assert seen_cwd and seen_cwd[0] != checkout and not seen_cwd[0].exists()
    assert (
        set(Path("/private/tmp").glob(f"oss-pr-radar-probe-attempt-{claimed['attempt_id']}-*"))
        == before
    )
    with ledger._connection() as connection:
        events = connection.execute(
            "SELECT event FROM managed_reproduction_attempt_events WHERE attempt_id=?",
            (claimed["attempt_id"],),
        ).fetchall()
        connection.execute(
            "UPDATE managed_reproduction_probes SET lease_expires_at='2000-01-01T00:00:00Z' WHERE probe_key=?",
            (claimed["probe_key"],),
        )
    assert [row["event"] for row in events] == ["ATTEMPT_STARTED"]
    retry = ledger.claim_reproduction_probe(worker_nonce="crash-retry")
    assert retry and retry["attempt_id"] != claimed["attempt_id"]


def test_probe_lease_claim_reclaim_stale_and_max_attempts(tmp_path):
    checkout, sha = real_checkout(tmp_path)
    database = tmp_path / "managed.sqlite3"
    ledger = ManagedLedger(database, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": sha, "codePaths": ["target.py"]},
    )
    ledger.bind_task(
        task_id="lease-task",
        opportunity_key="owner/repo#1",
        thread_id="thread-lease",
        worktree_path=str(checkout),
    )
    ledger.queue_reproduction_probe(
        task_id="lease-task",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/1",
        default_branch="main",
        selected_base_sha=sha,
        code_paths=["target.py"],
        profile_id=None,
        checkout_path=str(checkout),
        head_sha=sha,
        commit_sha=sha,
        result_digest="lease-result",
        idempotency_key="lease-intent",
    )
    first = ledger.claim_reproduction_probe(worker_nonce="worker-a", lease_seconds=60)
    assert first and first["attempt_count"] == 1
    assert ledger.claim_reproduction_probe(worker_nonce="worker-b") is None
    with ledger._connection() as connection:
        connection.execute(
            "UPDATE managed_reproduction_probes SET lease_expires_at='2000-01-01T00:00:00Z' WHERE probe_key=?",
            (first["probe_key"],),
        )
    second = ledger.claim_reproduction_probe(worker_nonce="worker-b")
    assert second and second["attempt_id"] != first["attempt_id"]
    with pytest.raises(RuntimeError, match="stale"):
        ledger.fail_reproduction_probe(
            probe_key=first["probe_key"], attempt_id=first["attempt_id"], error="stale-worker"
        )
    ledger.fail_reproduction_probe(
        probe_key=second["probe_key"], attempt_id=second["attempt_id"], error="retry-1"
    )
    claimed = ledger.claim_reproduction_probe(worker_nonce="worker-c")
    assert claimed
    ledger.fail_reproduction_probe(
        probe_key=claimed["probe_key"], attempt_id=claimed["attempt_id"], error="retry-2"
    )
    assert ledger.claim_reproduction_probe(worker_nonce="worker-final") is None
    with ledger._connection() as connection:
        row = connection.execute(
            "SELECT state,attempt_count,worker_nonce,attempt_id,lease_expires_at FROM managed_reproduction_probes"
        ).fetchone()
    assert dict(row) == {
        "state": "WAITING_EXTERNAL",
        "attempt_count": 3,
        "worker_nonce": None,
        "attempt_id": None,
        "lease_expires_at": None,
    }


@pytest.mark.parametrize(
    "lease_value",
    [None, "2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z"],
    ids=["missing", "expired", "future-stranded"],
)
def test_exhausted_running_probe_is_terminalized_before_candidate_filter(tmp_path, lease_value):
    checkout, sha = real_checkout(tmp_path)
    ledger = ManagedLedger(tmp_path / "exhausted.sqlite3", ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": sha, "codePaths": ["target.py"]},
    )
    ledger.bind_task(
        task_id="exhausted-task",
        opportunity_key="owner/repo#1",
        thread_id="exhausted-thread",
        worktree_path=str(checkout),
    )
    ledger.queue_reproduction_probe(
        task_id="exhausted-task",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/1",
        default_branch="main",
        selected_base_sha=sha,
        code_paths=["target.py"],
        profile_id=None,
        checkout_path=str(checkout),
        head_sha=sha,
        commit_sha=sha,
        result_digest="exhausted-result",
        idempotency_key="exhausted-intent",
    )
    for worker in ("exhausted-a", "exhausted-b", "exhausted-c"):
        claimed = ledger.claim_reproduction_probe(worker_nonce=worker)
        assert claimed
        if worker != "exhausted-c":
            ledger.fail_reproduction_probe(
                probe_key=claimed["probe_key"],
                attempt_id=claimed["attempt_id"],
                error="worker-failed",
            )
    with ledger._connection() as connection:
        connection.execute(
            "UPDATE managed_reproduction_probes SET lease_expires_at=?,error=? WHERE probe_key=?",
            (lease_value, "preserve-this-error", claimed["probe_key"]),
        )

    assert ledger.claim_reproduction_probe(worker_nonce="must-not-retry") is None
    with ledger._connection() as connection:
        row = connection.execute(
            "SELECT state,error,worker_nonce,attempt_id,started_at,lease_expires_at,attempt_count "
            "FROM managed_reproduction_probes WHERE probe_key=?",
            (claimed["probe_key"],),
        ).fetchone()
        events = connection.execute(
            "SELECT event_type FROM managed_lifecycle_events "
            "WHERE event_type='REPRODUCTION_RETRY_EXHAUSTED'"
        ).fetchall()
    assert dict(row) == {
        "state": "WAITING_EXTERNAL",
        "error": "preserve-this-error",
        "worker_nonce": None,
        "attempt_id": None,
        "started_at": None,
        "lease_expires_at": None,
        "attempt_count": 3,
    }
    assert len(events) == 1
    assert ledger.claim_reproduction_probe(worker_nonce="second-must-not-retry") is None
    with ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events "
                "WHERE event_type='REPRODUCTION_RETRY_EXHAUSTED'"
            ).fetchone()[0]
            == 1
        )


def test_opportunity_identity_is_canonical_and_immutable(tmp_path):
    ledger = ManagedLedger(tmp_path / "canonical.sqlite3", ensure_schema=True)
    with pytest.raises(ValueError, match="identity"):
        ledger.upsert_opportunity(
            opportunity_key="owner/repo#7",
            owner="owner",
            repo="repo",
            issue_number=8,
            issue_url="https://github.com/owner/repo/issues/7",
            state="SYSTEM_PROCESSING",
            source="test",
            provenance={},
            metadata={},
        )
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#7",
        owner="owner",
        repo="repo",
        issue_number=7,
        issue_url="https://github.com/owner/repo/issues/7",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={},
    )
    with ledger._connection() as connection:
        connection.execute(
            "UPDATE managed_opportunities SET issue_number=8 WHERE opportunity_key='owner/repo#7'"
        )
    assert ledger.opportunity_identity("owner/repo#7") is None


def test_url_opportunity_key_uses_canonical_storage_and_event_identity(tmp_path):
    ledger = ManagedLedger(tmp_path / "url-key.sqlite3", ensure_schema=True)
    issue_url = "https://github.com/owner/repo/issues/7"
    first = ledger.upsert_opportunity(
        opportunity_key=issue_url,
        owner="owner",
        repo="repo",
        issue_number=7,
        issue_url=issue_url,
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={},
    )
    second = ledger.upsert_opportunity(
        opportunity_key="owner/repo#7",
        owner="owner",
        repo="repo",
        issue_number=7,
        issue_url=issue_url,
        state="DECISION_REQUIRED",
        source="test",
        provenance={},
        metadata={},
    )
    assert first["opportunity_key"] == "owner/repo#7"
    assert second["opportunity_key"] == "owner/repo#7"
    assert ledger.opportunity_identity(issue_url)["opportunityKey"] == "owner/repo#7"
    assert ledger.read_opportunity(issue_url)["opportunity_key"] == "owner/repo#7"
    with ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_opportunities WHERE opportunity_key='owner/repo#7'"
            ).fetchone()[0]
            == 1
        )
    event = ledger.record_event(
        event_type="URL_IDENTITY_TEST",
        idempotency_key="url-identity-event",
        opportunity_key=issue_url,
        source="test",
    )
    replay = ledger.record_event(
        event_type="URL_IDENTITY_TEST",
        idempotency_key="url-identity-event",
        opportunity_key="owner/repo#7",
        source="test",
    )
    assert event["created"] is True
    assert replay["created"] is False
    assert event["opportunity_key"] == "owner/repo#7"


def test_upsert_post_insert_failure_rolls_back_row_and_event(tmp_path, monkeypatch):
    ledger = ManagedLedger(tmp_path / "upsert-atomic.sqlite3", ensure_schema=True)
    real_connection = ledger._connection()

    class FailAfterInsert:
        inserted = False

        @property
        def in_transaction(self):
            return real_connection.in_transaction

        def execute(self, sql, parameters=()):
            if self.inserted and sql.lstrip().startswith("SELECT * FROM managed_opportunities"):
                raise RuntimeError("injected post-insert failure")
            cursor = real_connection.execute(sql, parameters)
            if sql.lstrip().startswith("INSERT INTO managed_opportunities"):
                self.inserted = True
            return cursor

        def rollback(self):
            return real_connection.rollback()

        def close(self):
            return real_connection.close()

    injected = FailAfterInsert()
    monkeypatch.setattr(ledger, "_connection", lambda: injected)
    with pytest.raises(RuntimeError, match="post-insert"):
        ledger.upsert_opportunity(
            opportunity_key="https://github.com/owner/repo/issues/7",
            owner="owner",
            repo="repo",
            issue_number=7,
            issue_url="https://github.com/owner/repo/issues/7",
            state="SYSTEM_PROCESSING",
            source="test",
            provenance={},
            metadata={},
        )
    monkeypatch.undo()
    with ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_opportunities WHERE opportunity_key='owner/repo#7'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE opportunity_key='owner/repo#7'"
            ).fetchone()[0]
            == 0
        )


def test_snapshot_cannot_reauthorize_inconsistent_opportunity_identity(tmp_path):
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "target.sqlite3"
    source_ledger = ManagedLedger(source, ensure_schema=True)
    source_ledger.upsert_opportunity(
        opportunity_key="owner/repo#7",
        owner="owner",
        repo="repo",
        issue_number=7,
        issue_url="https://github.com/owner/repo/issues/7",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={},
    )
    target_ledger = ManagedLedger(target, ensure_schema=True)
    target_ledger.upsert_opportunity(
        opportunity_key="sentinel/repo#1",
        owner="sentinel",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/sentinel/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={},
    )
    snapshot_path = tmp_path / "identity.snapshot.gz"
    export_snapshot(source, snapshot_path)
    snapshot = json.loads(gzip.decompress(snapshot_path.read_bytes()))
    snapshot["rows"]["opportunities"][0]["issueNumber"] = 8
    snapshot["contentDigest"] = snapshot_digest(snapshot["rows"])
    signed_payload = {key: value for key, value in snapshot.items() if key != "rootSignature"}
    auth = sign_current(signed_payload, context=SNAPSHOT_AUTH_CONTEXT)
    snapshot["keyId"] = auth["keyId"]
    snapshot["rootSignature"] = sign_current(
        {**signed_payload, "keyId": auth["keyId"]}, context=SNAPSHOT_AUTH_CONTEXT
    )["signature"]
    snapshot_path.write_bytes(gzip.compress(json.dumps(snapshot, sort_keys=True).encode("utf-8")))
    with pytest.raises(ValueError, match="identity"):
        import_snapshot(target, snapshot_path)
    with target_ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_opportunities WHERE opportunity_key='sentinel/repo#1'"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_opportunities WHERE opportunity_key='owner/repo#7'"
            ).fetchone()[0]
            == 0
        )


def test_lease_rfc3339_boundaries_and_malformed_recovery(tmp_path):
    exact = _parse_rfc3339_utc("2026-08-19T00:00:00Z")
    assert exact == _parse_rfc3339_utc("2026-08-19T08:00:00+08:00")
    assert exact <= exact
    assert _parse_rfc3339_utc("2099-08-19T00:00:00+00:00") > exact
    for malformed in (
        None,
        "",
        "2026-08-19 00:00:00+00:00",
        "2026-08-19T00:00:00",
        "2026-08-19T00:00:00+0000",
    ):
        with pytest.raises(ValueError):
            _parse_rfc3339_utc(malformed)

    checkout, sha = real_checkout(tmp_path)
    database = tmp_path / "malformed-lease.sqlite3"
    ledger = ManagedLedger(database, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": sha, "codePaths": ["target.py"]},
    )
    ledger.bind_task(
        task_id="malformed-lease-task",
        opportunity_key="owner/repo#1",
        thread_id="thread-malformed",
        worktree_path=str(checkout),
    )
    ledger.queue_reproduction_probe(
        task_id="malformed-lease-task",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/1",
        default_branch="main",
        selected_base_sha=sha,
        code_paths=["target.py"],
        profile_id=None,
        checkout_path=str(checkout),
        head_sha=sha,
        commit_sha=sha,
        result_digest="malformed-lease-result",
        idempotency_key="malformed-lease-intent",
    )
    first = ledger.claim_reproduction_probe(worker_nonce="malformed-worker-a")
    assert first
    with ledger._connection() as connection:
        connection.execute(
            "UPDATE managed_reproduction_probes SET lease_expires_at=NULL WHERE probe_key=?",
            (first["probe_key"],),
        )
    recovered = ledger.claim_reproduction_probe(worker_nonce="malformed-worker-b")
    assert recovered and recovered["attempt_id"] != first["attempt_id"]
    with ledger._connection() as connection:
        event = connection.execute(
            "SELECT event_type,payload_json FROM managed_lifecycle_events "
            "WHERE event_type='MALFORMED_LEASE_RECOVERED'"
        ).fetchone()
    assert event and event["event_type"] == "MALFORMED_LEASE_RECOVERED"


def test_probe_queue_rejects_receipt_identity_not_derived_from_opportunity(tmp_path):
    checkout, sha = real_checkout(tmp_path)
    ledger = ManagedLedger(tmp_path / "identity.sqlite3", ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": sha, "codePaths": ["target.py"]},
    )
    ledger.bind_task(
        task_id="identity-task",
        opportunity_key="owner/repo#1",
        thread_id="thread-identity",
        worktree_path=str(checkout),
    )
    with pytest.raises(ValueError, match="bound to its opportunity"):
        ledger.queue_reproduction_probe(
            task_id="identity-task",
            opportunity_key="owner/repo#1",
            repo="other/repo",
            issue_url="https://github.com/other/repo/issues/1",
            default_branch="main",
            selected_base_sha="wrong-base",
            code_paths=["other.py"],
            profile_id=None,
            checkout_path=str(checkout),
            head_sha=sha,
            commit_sha=sha,
            result_digest="identity-result",
            idempotency_key="identity-intent",
        )


def test_running_probe_snapshot_restores_as_retryable_without_lock(tmp_path):
    checkout, sha = real_checkout(tmp_path)
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "target.sqlite3"
    ledger = ManagedLedger(source, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": sha, "codePaths": ["target.py"]},
    )
    ledger.bind_task(
        task_id="snapshot-task",
        opportunity_key="owner/repo#1",
        thread_id="thread",
        worktree_path=str(checkout),
    )
    ledger.queue_reproduction_probe(
        task_id="snapshot-task",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/1",
        default_branch="main",
        selected_base_sha=sha,
        code_paths=["target.py"],
        profile_id=None,
        checkout_path=str(checkout),
        head_sha=sha,
        commit_sha=sha,
        result_digest="snapshot-result",
        idempotency_key="snapshot-intent",
    )
    claimed = ledger.claim_reproduction_probe(worker_nonce="crashed-worker")
    assert claimed and claimed["state"] == "RUNNING"
    snapshot = tmp_path / "state.snapshot.gz"
    export_snapshot(source, snapshot)
    import_snapshot(target, snapshot)
    with ManagedLedger(target, ensure_schema=True)._connection() as connection:
        row = connection.execute(
            "SELECT state,attempt_count,worker_nonce,attempt_id,lease_expires_at FROM managed_reproduction_probes"
        ).fetchone()
    assert dict(row) == {
        "state": "WAITING_EXTERNAL",
        "attempt_count": 1,
        "worker_nonce": None,
        "attempt_id": None,
        "lease_expires_at": None,
    }
