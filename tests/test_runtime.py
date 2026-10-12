from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import time
from pathlib import Path

import pytest

from oss_pr_radar.runtime import (
    REQUIRED_WORKERS,
    DiskThresholds,
    RuntimeLockBusy,
    disk_restart_safe,
    disk_snapshot,
    evaluate_health,
    exclusive_lock,
    pending_publication_effects,
    record_cycle,
    rotate_log,
)
from oss_pr_radar.util import canonical_json, sha256_json, sha256_text


def _permission_denial_ledger(tmp_path, mutation=None):
    path = tmp_path / "publication.sqlite3"
    commit = "a" * 40
    snapshot = {
        "requestId": "request-1",
        "opportunityKey": "a/b#1",
        "threadId": "thread-1",
        "worktreePath": "/worktree",
        "evidenceDigest": "c" * 64,
        "issueUrl": "https://github.com/a/b/issues/1",
        "commitSha": commit,
        "branch": "fix-boundary",
        "publicationKind": "PR_CREATE",
        "publication": {"headOwner": "Oxygen56", "baseBranch": "main"},
    }
    push_digest = sha256_json(
        {
            "issueUrl": snapshot["issueUrl"],
            "commitSha": commit,
            "branch": snapshot["branch"],
            "remote": "oxygen56/b",
            "publicationKind": "PR_CREATE",
            "existingPrUrl": None,
            "previousCommitSha": None,
        }
    )
    request_digest = sha256_json({"originalCreateRequest": "retained"})
    effect = {
        "effect_id": sha256_text(f"permit-1|create_pr|{request_digest}"),
        "permit_id": "permit-1",
        "action": "create_pr",
        "request_digest": request_digest,
        "status": "FAILED",
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:02:00Z",
    }
    push = {
        "effect_id": sha256_text(f"permit-1|push|{push_digest}"),
        "permit_id": "permit-1",
        "action": "push",
        "request_digest": push_digest,
        "status": "SUCCEEDED",
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:00:20Z",
    }
    evidence = {
        "schemaVersion": "publication-permission-denial-v1",
        "requestId": "request-1",
        "permitId": "permit-1",
        "effectId": effect["effect_id"],
        "requestDigest": request_digest,
        "repo": "a/b",
        "headOwner": "Oxygen56",
        "branch": snapshot["branch"],
        "base": "main",
        "commitSha": commit,
        "exactHeadPrAbsent": True,
        "localHeadSha": commit,
        "forkRepo": "Oxygen56/b",
        "pushEffectId": push["effect_id"],
        "pushRequestDigest": push_digest,
        "remoteSha": commit,
        "lookup": {
            "method": "GET",
            "endpoint": "repos/a/b/pulls",
            "head": "Oxygen56:fix-boundary",
            "state": "all",
            "ok": True,
            "result": [],
        },
        "observedAt": "2020-01-01T00:01:00Z",
    }
    result = {
        "ok": True,
        "blocked": True,
        "reason": "PUBLICATION_PERMISSION_DENIED",
        "creationAttempted": True,
        "detail": "pull request create failed: GraphQL: Oxygen56 does not have the correct "
        "permissions to execute `CreatePullRequest` (createPullRequest)",
        "evidence": evidence,
    }
    request = {
        "request_id": "request-1",
        "opportunity_key": "a/b#1",
        "thread_id": "thread-1",
        "worktree_path": "/worktree",
        "evidence_digest": "c" * 64,
        "permit_id": "permit-1",
        "status": "BLOCKED",
        "reason": "PUBLICATION_PERMISSION_DENIED",
        "commit_sha": commit,
        "branch": snapshot["branch"],
    }
    permit = {
        "permit_id": "permit-1",
        "request_id": "request-1",
        "issue_url": snapshot["issueUrl"],
        "commit_sha": commit,
        "branch": snapshot["branch"],
    }
    rows = {
        "effect": effect,
        "push": push,
        "evidence": evidence,
        "result": result,
        "request": request,
        "permit": permit,
        "snapshot": snapshot,
        "event_present": True,
        "event_matches": True,
        "push_result": {"ok": True, "remoteSha": commit},
    }
    if mutation:
        mutation(rows)
    result["evidenceDigest"] = sha256_json(evidence)
    effect["result_json"] = canonical_json(result)
    push["result_json"] = canonical_json(rows["push_result"])
    request["request_json"] = canonical_json(snapshot)
    event = {
        "opportunity_key": "a/b#1",
        "event_type": "PUBLICATION_BLOCKED",
        "dedupe_key": "request-1:PUBLICATION_PERMISSION_DENIED",
        "payload_json": canonical_json(
            {
                "requestId": "request-1",
                "reason": "PUBLICATION_PERMISSION_DENIED",
                "auditEvidence": evidence if rows["event_matches"] else {},
            }
        ),
        "created_at": "2020-01-01T00:02:01Z",
    }
    with sqlite3.connect(path) as connection:
        for table, values in [
            ("publication_effects", effect),
            ("publication_permits", permit),
            ("publication_requests", request),
            ("events", event),
        ]:
            connection.execute(
                f"CREATE TABLE {table} ({','.join(f'{key} TEXT' for key in values)})"
            )
            if table != "events" or rows["event_present"]:
                connection.execute(
                    f"INSERT INTO {table} VALUES ({','.join('?' for _ in values)})",
                    tuple(values.values()),
                )
        connection.execute(
            f"INSERT INTO publication_effects VALUES ({','.join('?' for _ in push)})",
            tuple(push[key] for key in effect),
        )
    return path


def test_pending_effects_retains_resolved_denial_history_without_new_age_gate(tmp_path):
    path = _permission_denial_ledger(tmp_path)
    before = path.read_bytes()
    assert pending_publication_effects(path) == 0
    assert path.read_bytes() == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT status FROM publication_effects").fetchall() == [
            ("FAILED",),
            ("SUCCEEDED",),
        ]
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("effect", "status", "RECONCILE_REQUIRED"),
        ("effect", "action", "push"),
        ("effect", "effect_id", "wrong-effect"),
        ("effect", "request_digest", "f" * 64),
        ("effect", "permit_id", "another-permit"),
        ("request", "status", "GRANTED"),
        ("request", "reason", "BLOCKED_REPRODUCTION_REQUIRED"),
        ("request", "permit_id", "another-permit"),
        ("snapshot", "requestId", "another-request"),
        ("snapshot", "publicationKind", "PR_UPDATE"),
        ("snapshot", "worktreePath", "/other-worktree"),
        ("snapshot", "threadId", "other-thread"),
        ("snapshot", "evidenceDigest", "d" * 64),
        ("result", "creationAttempted", 1),
        ("result", "blocked", 1),
        ("result", "detail", "GraphQL: permission denied"),
        ("evidence", "schemaVersion", "unknown"),
        ("evidence", "requestId", "another-request"),
        ("evidence", "permitId", "another-permit"),
        ("evidence", "effectId", "another-effect"),
        ("evidence", "requestDigest", "f" * 64),
        ("evidence", "repo", "other/repo"),
        ("evidence", "headOwner", "another-owner"),
        ("evidence", "branch", "another-branch"),
        ("evidence", "base", "another-base"),
        ("evidence", "commitSha", "b" * 40),
        ("evidence", "localHeadSha", "b" * 40),
        ("evidence", "remoteSha", "b" * 40),
        ("evidence", "exactHeadPrAbsent", 1),
        ("evidence", "forkRepo", "another-owner/b"),
        ("evidence", "pushEffectId", "another-effect"),
        ("evidence", "pushRequestDigest", "f" * 64),
        ("evidence", "observedAt", "2019-12-31T23:00:00Z"),
        ("evidence", "observedAt", "2020-01-01T00:03:00Z"),
        ("evidence", "observedAt", "2020-01-01T00:01:00"),
        ("push_result", "remoteSha", "b" * 40),
        ("push_result", "ok", 1),
        ("push", "action", "create_pr"),
        ("push", "request_digest", "f" * 64),
    ],
)
def test_pending_effects_does_not_hide_unproven_or_misbound_denials(
    tmp_path, section, field, value
):
    path = _permission_denial_ledger(tmp_path, lambda rows: rows[section].update({field: value}))
    assert pending_publication_effects(path) == 1


@pytest.mark.parametrize("missing", ["event", "event_proof", "query", "query_ok", "query_result"])
def test_pending_effects_requires_exact_negative_query_and_block_event(tmp_path, missing):
    def mutate(rows):
        if missing == "event":
            rows["event_present"] = False
        elif missing == "event_proof":
            rows["event_matches"] = False
        elif missing == "query":
            rows["evidence"]["lookup"]["head"] = "another-owner:fix-boundary"
        elif missing == "query_ok":
            rows["evidence"]["lookup"]["ok"] = 1
        else:
            rows["evidence"]["lookup"]["result"] = {}

    assert pending_publication_effects(_permission_denial_ledger(tmp_path, mutate)) == 1


def test_pending_effects_keeps_unknown_failed_and_orphan_effects(tmp_path):
    path = tmp_path / "unknown.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE publication_effects (status TEXT)")
        connection.executemany(
            "INSERT INTO publication_effects VALUES (?)",
            [("FAILED",), ("RECONCILE_REQUIRED",), ("ATTEMPTED",), ("SUCCEEDED",)],
        )
    assert pending_publication_effects(path) == 3


def _iso(epoch: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def healthy_state(now: float) -> dict:
    return {
        "lastSuccessAt": _iso(now - 10),
        "queueImportSuccessAt": _iso(now - 100),
        "consecutiveFailures": 0,
        "lastExitCode": 0,
        "pendingPublicationEffects": 0,
        "manifestVerified": True,
        "deploymentDirty": False,
        "releaseVersion": "release-a",
        "policyDigest": "policy-a",
    }


def test_health_rejects_stale_success_and_consecutive_failures():
    now = time.time()
    state = healthy_state(now) | {
        "lastSuccessAt": _iso(now - 121),
        "consecutiveFailures": 3,
        "lastExitCode": 1,
    }

    result = evaluate_health(
        state,
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
    )

    assert result["healthy"] is False
    assert {
        "RECENT_SUCCESS_MISSING_OR_STALE",
        "CONSECUTIVE_FAILURES",
        "LAST_EXIT_NONZERO",
    } <= set(result["issues"])


def test_health_keeps_noncapacity_queue_log_and_policy_boundaries():
    now = time.time()
    state = healthy_state(now) | {
        "queueImportSuccessAt": _iso(now - 901),
        "pendingPublicationEffects": 1,
        "deploymentDirty": True,
    }
    result = evaluate_health(
        state,
        now=now,
        expected_release="release-b",
        expected_policy_digest="policy-b",
        disk={"level": "stop", "freeBytes": 1},
        log_bytes=51 * 1024 * 1024,
    )

    assert result["healthy"] is False
    assert {
        "QUEUE_IMPORT_STALE",
        "PUBLICATION_EFFECT_REQUIRES_RECONCILIATION",
        "RELEASE_VERSION_MISMATCH",
        "POLICY_DIGEST_CHANGED",
        "DIRTY_OR_UNVERIFIED_DEPLOYMENT",
        "LOG_LIMIT_EXCEEDED",
    } <= set(result["issues"])


def test_low_disk_capacity_is_measured_without_marking_workers_unhealthy():
    now = time.time()

    result = evaluate_health(
        healthy_state(now),
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
        disk={"level": "warning", "freeBytes": 50 * 1024 * 1024 * 1024},
    )

    assert result["healthy"] is True
    assert result["issues"] == []
    assert result["warnings"] == []
    assert result["disk"]["freeBytes"] == 50 * 1024 * 1024 * 1024


def test_health_does_not_fail_on_a_historical_disk_capacity_episode():
    now = time.time()
    gate = {
        "ok": False,
        "blocked": True,
        "reason": "DISK_STOP_THRESHOLD",
        "active": True,
        "gateActive": True,
    }

    result = evaluate_health(
        healthy_state(now),
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
        disk={"level": "warning", "freeBytes": 50 * 1024**3, "usedFraction": 0.93},
        disk_pressure_gate=gate,
    )

    assert result["healthy"] is True
    assert result["issues"] == []
    assert result["warnings"] == []
    assert result["diskPressureGate"] == gate


def test_lock_is_non_blocking_and_restart_safe(tmp_path: Path):
    lock_path = tmp_path / "state" / "controller.lock"
    with exclusive_lock(lock_path):
        with pytest.raises(RuntimeLockBusy):
            with exclusive_lock(lock_path):
                pass
    with exclusive_lock(lock_path):
        pass


def test_cycle_state_and_operation_log_are_durable(tmp_path: Path):
    record_cycle(
        tmp_path,
        worker="fast",
        ok=False,
        exit_code=1,
        started_at=time.time() - 2,
        error_code="SQLITE_INTERRUPT",
        release_version="release-a",
        policy_digest="policy-a",
    )
    record_cycle(
        tmp_path,
        worker="fast",
        ok=True,
        exit_code=0,
        started_at=time.time() - 1,
    )
    state = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    operations = (tmp_path / "state" / "runtime-operations" / "operations.ndjson").read_text()
    assert state["workers"]["fast"]["consecutiveFailures"] == 0
    assert state["workers"]["fast"]["lastExitCode"] == 0
    assert state["workers"]["fast"]["lastSuccessAt"]
    assert "lastExitCode" not in state
    assert "consecutiveFailures" not in state
    assert operations.count("\n") == 2
    assert "SQLITE_INTERRUPT" in operations


def _record_cycle_process(root: str, worker: str) -> None:
    record_cycle(
        Path(root),
        worker=worker,
        ok=True,
        exit_code=0,
        started_at=time.time(),
    )


def test_runtime_health_keeps_worker_state_and_aggregate_atomic(tmp_path: Path):
    processes = [
        multiprocessing.Process(target=_record_cycle_process, args=(str(tmp_path), worker))
        for worker in REQUIRED_WORKERS
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    state = json.loads((tmp_path / "state" / "runtime-health.json").read_text())
    assert set(state["workers"]) == set(REQUIRED_WORKERS)
    assert "worker" not in state
    assert "lastExitCode" not in state
    assert state["workers"]["fast"]["lastExitCode"] == 0
    assert state["workers"]["slow"]["lastExitCode"] == 0
    assert state["workers"]["queue-importer"]["lastExitCode"] == 0


def test_required_worker_failure_cannot_be_hidden_by_successful_worker():
    now = time.time()
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - 10),
                "lastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update({"lastExitCode": 1, "consecutiveFailures": 1})

    result = evaluate_health(
        state,
        now=now,
        expected_release="release-a",
        expected_policy_digest="policy-a",
    )

    assert result["healthy"] is False
    assert result["workers"]["fast"]["healthy"] is True
    assert result["workers"]["slow"]["healthy"] is False
    assert "slow:LAST_EXIT_NONZERO" in result["issues"]


def test_health_does_not_mark_live_slow_cycle_stale_before_inflight_deadline(monkeypatch):
    now = time.time()
    monkeypatch.setattr(
        "oss_pr_radar.runtime.pid_probe",
        lambda pid, expected_fragment=None: {
            "pid": pid,
            "alive": pid == os.getpid(),
            "versionMatched": expected_fragment == "slow_publication_worker.py",
        },
    )
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - (600 if worker == "slow" else 10)),
                "queueImportSuccessAt": _iso(now - 100),
                "lastExitCode": 0,
                "queueLastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update(
        {
            "inFlight": True,
            "attemptStartedAt": _iso(now - 300),
            "workerPid": os.getpid(),
            "workerPidAlive": True,
        }
    )

    result = evaluate_health(
        state, now=now, expected_release="release-a", expected_policy_digest="policy-a"
    )

    assert result["healthy"] is True
    assert result["workers"]["slow"]["inFlight"] is True
    assert result["workers"]["slow"]["workerPidAlive"] is True
    assert "slow:RECENT_SUCCESS_MISSING_OR_STALE" not in result["issues"]


@pytest.mark.parametrize(
    ("worker_pid_alive", "attempt_age", "issue", "command_matches", "observed_alive"),
    [
        (False, 300, "INFLIGHT_PID_NOT_ALIVE", True, False),
        (True, 1801, "INFLIGHT_TIMEOUT", True, True),
        (True, 300, "INFLIGHT_PID_NOT_ALIVE", False, False),
    ],
)
def test_health_rejects_dead_or_overdue_slow_cycle(
    monkeypatch, worker_pid_alive, attempt_age, issue, command_matches, observed_alive
):
    now = time.time()
    monkeypatch.setattr(
        "oss_pr_radar.runtime.pid_probe",
        lambda pid, expected_fragment=None: {
            "pid": pid,
            "alive": pid == os.getpid(),
            "versionMatched": command_matches and expected_fragment == "slow_publication_worker.py",
        },
    )
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - 600),
                "lastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update(
        {
            "inFlight": True,
            "attemptStartedAt": _iso(now - attempt_age),
            "workerPid": os.getpid(),
            "workerPidAlive": worker_pid_alive,
        }
    )

    result = evaluate_health(
        state, now=now, expected_release="release-a", expected_policy_digest="policy-a"
    )

    assert result["healthy"] is False
    assert f"slow:{issue}" in result["issues"]
    assert result["workers"]["slow"]["workerPidAlive"] is observed_alive


def test_health_rejects_nonexistent_recorded_slow_pid():
    now = time.time()
    state = {
        "workers": {
            worker: {
                "lastSuccessAt": _iso(now - (600 if worker == "slow" else 10)),
                "queueImportSuccessAt": _iso(now - 100),
                "lastExitCode": 0,
                "queueLastExitCode": 0,
                "consecutiveFailures": 0,
            }
            for worker in REQUIRED_WORKERS
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }
    state["workers"]["slow"].update(
        {
            "inFlight": True,
            "attemptStartedAt": _iso(now - 300),
            "workerPid": 1_000_000_000,
            "workerPidAlive": True,
        }
    )

    result = evaluate_health(
        state, now=now, expected_release="release-a", expected_policy_digest="policy-a"
    )

    assert result["healthy"] is False
    assert "slow:INFLIGHT_PID_NOT_ALIVE" in result["issues"]
    assert result["workers"]["slow"]["workerPidAlive"] is False


def test_log_rotation_keeps_bounded_history(tmp_path: Path):
    path = tmp_path / "agent.log"
    path.write_bytes(b"x" * 10)
    path.with_name("agent.log.1").write_bytes(b"old")

    rotate_log(path, max_bytes=5, backups=2)

    assert not path.exists()
    assert path.with_name("agent.log.1").read_bytes() == b"x" * 10
    assert path.with_name("agent.log.2").read_bytes() == b"old"


def test_disk_snapshot_reports_actual_bytes_with_capacity_limits_disabled(
    monkeypatch, tmp_path: Path
):
    class Usage:
        total = 100
        used = 96
        free = 4

    monkeypatch.setattr("oss_pr_radar.runtime.shutil.disk_usage", lambda _path: Usage())
    result = disk_snapshot(
        tmp_path,
        DiskThresholds(
            warning_free_bytes=20,
            stop_free_bytes=5,
            warning_used_fraction=0.8,
            stop_used_fraction=0.95,
        ),
    )

    assert result["level"] == "unrestricted"
    assert result["capacityLimitsEnabled"] is False
    assert result["path"] == str(tmp_path)
    assert result["totalBytes"] == 100
    assert result["freeBytes"] == 4
    assert result["usedFraction"] == 0.96
    assert not any(
        name in result
        for name in (
            "warningFreeBytes",
            "stopFreeBytes",
            "stopUsedFraction",
            "restartFreeBytes",
            "restartUsedFraction",
        )
    )


def test_disk_snapshot_keeps_the_actual_unrounded_fraction(monkeypatch, tmp_path: Path):
    class Usage:
        total = 10_000_000
        used = 9_400_004
        free = 599_996

    monkeypatch.setattr("oss_pr_radar.runtime.shutil.disk_usage", lambda _path: Usage())

    result = disk_snapshot(tmp_path)

    assert result["usedFraction"] > 0.94
    assert result["usedFraction"] != 0.94
    assert result["level"] == "unrestricted"
    assert result["capacityLimitsEnabled"] is False


@pytest.mark.parametrize(
    "snapshot",
    [
        {"level": "stop", "freeBytes": 0, "usedFraction": 1.0},
        {"level": "warning", "freeBytes": 24 * 1024**3, "usedFraction": 0.940001},
        {"level": "unrestricted", "freeBytes": 1, "usedFraction": 0.99},
    ],
)
def test_disk_restart_compatibility_helper_no_longer_imposes_capacity_rules(snapshot):
    assert disk_restart_safe(snapshot) is True
