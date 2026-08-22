from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from test_deploy_local_runtime import make_repositories
from test_ledger import insert_publication_preflight
from test_runtime import healthy_state

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.runtime_audit import (
    active_release_evidence,
    audit_snapshot,
    collect_snapshot,
    parse_launchctl_output,
)


def healthy_worker_processes():
    return {
        worker: {
            "label": {
                "fast": "com.oss-pr-radar.local-publication",
                "slow": "com.oss-pr-radar.local-publication-slow",
                "queue-importer": "com.oss-pr-radar.queue-importer",
            }[worker],
            "launchctl": {"pid": 1, "lastExitCode": 0},
            "process": {
                "alive": True,
                "versionMatched": True,
                "releaseIdentityMatched": True,
                "workingDirectoryMatched": True,
            },
            "stalePidConflict": False,
        }
        for worker in ("fast", "slow", "queue-importer")
    }


def short_lived_worker_processes():
    return {
        worker: {
            "label": {
                "fast": "com.oss-pr-radar.local-publication",
                "slow": "com.oss-pr-radar.local-publication-slow",
                "queue-importer": "com.oss-pr-radar.queue-importer",
            }[worker],
            "launchctl": {"pid": None, "lastExitCode": 0},
            "process": {
                "alive": False,
                "versionMatched": False,
                "releaseIdentityMatched": False,
                "workingDirectoryMatched": False,
            },
            "stalePidConflict": False,
        }
        for worker in ("fast", "slow", "queue-importer")
    }


def healthy_nested_state(now: float) -> dict:
    last_success = datetime.fromtimestamp(now - 10, UTC).isoformat().replace("+00:00", "Z")
    return {
        "workers": {
            worker: {
                "healthy": True,
                **(
                    {"queueLastExitCode": 0, "queueImportSuccessAt": last_success}
                    if worker == "queue-importer"
                    else {"lastExitCode": 0, "lastSuccessAt": last_success}
                ),
                "consecutiveFailures": 0,
            }
            for worker in ("fast", "slow", "queue-importer")
        },
        "deployment": {
            "pendingPublicationEffects": 0,
            "manifestVerified": True,
            "deploymentDirty": False,
            "releaseVersion": "release-a",
            "policyDigest": "policy-a",
        },
    }


def test_launchctl_parser_keeps_pid_and_last_exit_code():
    parsed = parse_launchctl_output("state = running\npid = 123\nlast exit code = 1\n")
    assert parsed == {"pid": 123, "lastExitCode": 1, "state": "running"}


def test_audit_reports_pid_dash_with_nonzero_launchctl_exit():
    result = audit_snapshot(
        {
            "state": {},
            "release": {"valid": True, "releaseId": "release-a", "policyDigest": "policy-a"},
            "process": {"pid": None, "alive": False, "versionMatched": False},
            "launchctl": {"pid": None, "lastExitCode": 1, "state": "loaded"},
            "disk": {"level": "stop"},
            "logBytes": 0,
        }
    )
    assert "LAUNCHCTL_LAST_EXIT_NONZERO" in result["faults"]


def test_collect_snapshot_reads_pid_and_version_from_fast_worker(tmp_path, monkeypatch):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "runtime-health.json").write_text(
        '{"workers":{"fast":{"pid":123,"pidAlive":true,"processVersionMatched":true}}}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "oss_pr_radar.runtime_audit.active_release_evidence",
        lambda _root: {
            "valid": True,
            "releaseId": "release-a",
            "policyDigest": "policy-a",
        },
    )
    monkeypatch.setattr("oss_pr_radar.runtime_audit.disk_snapshot", lambda _root: {"level": "ok"})
    monkeypatch.setattr(
        "oss_pr_radar.runtime_audit.process_probe",
        lambda _pid, **_kwargs: {
            "pid": 123,
            "alive": True,
            "versionMatched": True,
            "releaseIdentityMatched": True,
            "workingDirectoryMatched": True,
        },
    )
    from oss_pr_radar.runtime_audit import collect_snapshot

    snapshot = collect_snapshot(
        tmp_path,
        launchctl_runner=lambda _label: "state = running\npid = 123\nlast exit code = 0\n",
    )
    assert snapshot["process"] == {
        "pid": 123,
        "alive": True,
        "versionMatched": True,
    }


def test_collect_snapshot_uses_real_pids_and_detects_stale_runtime_pid(tmp_path):
    source, target = make_repositories(tmp_path)
    import importlib.util

    script = Path(__file__).parents[1] / "scripts" / "deploy_local_runtime.py"
    spec = importlib.util.spec_from_file_location("deploy_runtime_probe", script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.deploy(source, target)
    release = active_release_evidence(target)
    assert release["valid"] is True

    workers = {}
    processes = {}
    for worker in ("fast", "slow", "queue-importer"):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(5)", release["path"]],
            cwd=target,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes[worker] = process
        workers[worker] = {
            "pid": process.pid + 100000,
            "lastSuccessAt": "2999-01-01T00:00:00Z",
            "lastExitCode": 0,
            "consecutiveFailures": 0,
        }
    (target / "state").mkdir(exist_ok=True)
    (target / "state" / "runtime-health.json").write_text(
        json.dumps({"workers": workers, "deployment": {"manifestVerified": True}}),
        encoding="utf-8",
    )

    labels = {
        "fast": "com.oss-pr-radar.local-publication",
        "slow": "com.oss-pr-radar.local-publication-slow",
        "queue-importer": "com.oss-pr-radar.queue-importer",
    }

    def fake_launchctl(label: str) -> str:
        worker = next(name for name, value in labels.items() if value == label)
        return f"state = running\npid = {processes[worker].pid}\nlast exit code = 0\n"

    try:
        snapshot = collect_snapshot(target, launchctl_runner=fake_launchctl)
        for worker in labels:
            process = snapshot["workerProcesses"][worker]["process"]
            assert process["alive"] is True
            assert process["workingDirectoryMatched"] is True
            assert process["releaseIdentityMatched"] is True
        assert snapshot["workerProcesses"]["fast"]["stalePidConflict"] is True
        result = audit_snapshot(snapshot)
        assert result["ok"] is False
        assert "STALE_PID_CONFLICT" in result["faults"]
    finally:
        for process in processes.values():
            process.terminate()
            process.wait(timeout=5)


def test_collect_snapshot_replays_real_journal_sqlite_effect_and_disk_evidence(tmp_path):
    source, target = make_repositories(tmp_path)
    import importlib.util

    script = Path(__file__).parents[1] / "scripts" / "deploy_local_runtime.py"
    spec = importlib.util.spec_from_file_location("deploy_runtime_faults", script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    module.deploy(source, target)
    state = target / "state"
    state.mkdir(exist_ok=True)
    database = state / "radar_ledger.sqlite3"
    store = RadarLedger(database)
    insert_publication_preflight(store, effect_status="ATTEMPTED")
    operations = state / "runtime-operations"
    operations.mkdir()
    (operations / "operations.ndjson").write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "operationId": "clone-1",
                        "worker": "slow",
                        "operation": "slow-cycle",
                        "status": "started",
                        "errorCode": "CLONE_TIMEOUT",
                    }
                ),
                json.dumps(
                    {
                        "operationId": "disk-1",
                        "worker": "slow",
                        "operation": "slow-cycle",
                        "status": "failure",
                        "errorCode": "ENOSPC",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (state / "slow-worker-backoff.json").write_text(
        '{"inFlight":true,"retryAfter":9999999999}\n', encoding="utf-8"
    )
    (state / "runtime-journal.json").write_text(
        '{"state":"CREATING","inFlight":true,"operation":"publication"}\n',
        encoding="utf-8",
    )
    (state / "sqlite-interrupted.json").write_text('{"interrupted":true}\n', encoding="utf-8")

    snapshot = collect_snapshot(
        target,
        launchctl_runner=lambda _label: "state = loaded\nlast exit code = 1\n",
    )

    assert any(item["errorCode"] == "CLONE_TIMEOUT" for item in snapshot["operations"])
    assert snapshot["journal"]["state"] == "CREATING"
    assert snapshot["journal"]["processCrashed"] is True
    assert snapshot["publicationEffect"]["status"] == "ATTEMPTED"
    assert snapshot["publicationEffect"]["processCrashed"] is True
    assert snapshot["sqliteInterrupted"] is True
    assert snapshot["lastErrno"] == "ENOSPC"
    assert "isolatedRefs" in snapshot["fetchHead"]
    result = audit_snapshot(snapshot)
    assert {
        "CLONE_OR_FETCH_TIMEOUT",
        "CREATING_PUBLICATION_EFFECT_AFTER_CRASH",
        "JOURNAL_AFTER_CRASH",
        "SQLITE_INTERRUPTED",
        "ENOSPC",
    } <= set(result["faults"])


def test_fault_replay_covers_runtime_failure_matrix():
    now = time.time()
    snapshot = {
        "state": healthy_state(now)
        | {"lastExitCode": 1, "lastErrorCode": "SQLITE_INTERRUPT", "deploymentDirty": True},
        "process": {"pid": 123, "alive": True, "versionMatched": True},
        "launchctl": {"lastExitCode": 1},
        "release": {
            "valid": True,
            "releaseId": "release-b",
            "policyDigest": "policy-b",
        },
        "disk": {"level": "stop"},
        "logBytes": 60 * 1024 * 1024,
        "operations": [{"errorCode": "CLONE_TIMEOUT"}],
        "fetchHead": {"cleared": True},
        "locks": {"importerControllerConcurrent": True},
        "journal": {"state": "BEGIN", "processCrashed": True},
        "publicationEffect": {"status": "CREATING", "processCrashed": True},
        "sqliteInterrupted": True,
        "lastErrno": "ENOSPC",
    }

    result = audit_snapshot(snapshot, now=now)

    assert result["ok"] is False
    assert {
        "PID_ALIVE_WITH_NONZERO_EXIT",
        "CLONE_OR_FETCH_TIMEOUT",
        "SHARED_FETCH_HEAD_CLEARED_OR_USED",
        "CONCURRENT_IMPORTER_CONTROLLER",
        "JOURNAL_AFTER_CRASH",
        "CREATING_PUBLICATION_EFFECT_AFTER_CRASH",
        "SQLITE_INTERRUPTED",
        "ENOSPC",
        "DISK_STOP_THRESHOLD",
        "LOG_LIMIT_EXCEEDED",
        "DIRTY_OR_UNVERIFIED_DEPLOYMENT",
        "POLICY_DIGEST_CHANGED",
    } <= set(result["faults"])


def test_fault_replay_is_clean_for_verified_healthy_runtime():
    now = time.time()
    result = audit_snapshot(
        {
            "state": healthy_state(now),
            "disk": {"level": "ok"},
            "logBytes": 1024,
            "release": {
                "valid": True,
                "releaseId": "release-a",
                "policyDigest": "policy-a",
            },
            "workerProcesses": healthy_worker_processes(),
        },
        now=now,
    )

    assert result["ok"] is True
    assert result["faults"] == []


def test_fault_replay_accepts_successful_short_lived_workers_without_pid():
    now = time.time()
    result = audit_snapshot(
        {
            "state": healthy_nested_state(now),
            "disk": {"level": "ok"},
            "logBytes": 1024,
            "release": {
                "valid": True,
                "releaseId": "release-a",
                "policyDigest": "policy-a",
            },
            "workerProcesses": short_lived_worker_processes(),
        },
        now=now,
    )

    assert result["ok"] is True
    assert result["faults"] == []


def test_runtime_audit_rejects_tampered_active_release(tmp_path):
    source, target = make_repositories(tmp_path)
    import importlib.util

    script = Path(__file__).parents[1] / "scripts" / "deploy_local_runtime.py"
    spec = importlib.util.spec_from_file_location("deploy_for_audit", script)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    result = module.deploy(source, target)

    assert active_release_evidence(target)["valid"] is True
    release = Path(result["releasePath"])
    (release / "scripts" / "runner.py").write_text("tampered\n", encoding="utf-8")

    evidence = active_release_evidence(target)
    assert evidence["valid"] is False
    assert "changed" in evidence["error"]
