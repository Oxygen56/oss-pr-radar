from __future__ import annotations

import hashlib
import json
import plistlib
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import oss_pr_radar.operational_auth as operational_auth_module
import oss_pr_radar.stage7_cutover as cutover_module
import scripts.deploy_local_runtime as deploy_local_runtime
import scripts.install_local_publication_workers as workers_module
import scripts.stage7_evidence as stage7_evidence_script
from oss_pr_radar.automation_contracts import build_contracts
from oss_pr_radar.automation_snapshot import (
    _prompt_digest,
    build_automation_snapshot,
    canonical_prompt,
)
from oss_pr_radar.daily_war_room import run_daily_cycle
from oss_pr_radar.local_publication import slow_advance_once, worker_specs
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.managed_security import sign_current
from oss_pr_radar.operational_auth import (
    authorization_path,
    consume_worker_staging_authorization,
    finalize_operational_authorization,
    issue_worker_staging_authorization,
    reset_expired_worker_staging,
    staged_worker_receipt_path,
    verify_operational_authorization,
    worker_spec_digest,
)
from oss_pr_radar.pr_projection import projection_summary
from oss_pr_radar.release_binding import runtime_root_digest
from oss_pr_radar.stage6_verification import build_verification_manifest
from oss_pr_radar.stage7_acceptance import (
    _activated_worker_execution_ok,
    _managed_counts_append_only,
    build_managed_counts_evidence,
    check,
    issue_operational_authorization,
    shareable_acceptance_report,
)
from oss_pr_radar.stage7_cutover import (
    activate,
    bootstrap,
    prepare,
    restore_git_preservation,
    rollback,
    status,
)
from oss_pr_radar.util import iso_z, utc_now


def _runtime(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    release = runtime / "releases" / "stage7-test"
    release.mkdir(parents=True)
    payload = {
        "schemaVersion": "oss_pr_radar_release_v1",
        "commit": "a" * 40,
        "capabilities": ["durable-independent-review-state-v1"],
        "files": [],
        "policyDigest": hashlib.sha256(b"[]").hexdigest(),
    }
    payload["manifestSha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    payload["releaseId"] = release.name
    (release / "release-manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    (runtime / "current-release").symlink_to(release)
    (runtime / "state").mkdir()
    return runtime


def _verification(head: str) -> dict:
    definitions = build_verification_manifest(head)["definitions"]["commands"]
    return build_verification_manifest(
        head,
        results={
            item["id"]: {"status": "passed", "exitCode": 0, "outputDigest": "a" * 64}
            for item in definitions
        },
    )


def test_prompt_digest_accepts_only_codex_terminal_lf_removal(tmp_path):
    runtime = tmp_path / "runtime"
    command = ["python", "controller_cycle.py"]
    expected = canonical_prompt("heartbeat", runtime, command)
    digest = hashlib.sha256(expected.encode("utf-8")).hexdigest()

    assert (
        _prompt_digest(
            expected.removesuffix("\n"),
            role="heartbeat",
            runtime_root=runtime,
            release_command=command,
        )
        == digest
    )
    assert (
        _prompt_digest(
            expected,
            role="heartbeat",
            runtime_root=runtime,
            release_command=command,
        )
        == digest
    )

    invalid = [
        expected.removesuffix("\n") + " ",
        expected[:-2],
        expected + "\n",
        expected.removesuffix("\n") + "\r\n",
        expected.replace("execute only", "execute the only", 1),
    ]
    for prompt in invalid:
        with pytest.raises(ValueError, match="canonical template"):
            _prompt_digest(
                prompt,
                role="heartbeat",
                runtime_root=runtime,
                release_command=command,
            )


@pytest.mark.parametrize(
    ("role", "command"),
    [
        ("heartbeat", ["python", "controller_cycle.py"]),
        ("dailyWarRoom", ["python", "daily_war_room_cycle.py", "--send"]),
    ],
)
def test_canonical_prompt_forbids_extra_final_output(tmp_path, role, command):
    prompt = canonical_prompt(role, tmp_path / "runtime", command)

    assert "whether success or failure" in prompt
    assert "only the required plain sentence and nothing else" in prompt
    assert "do not add extra text" in prompt
    assert "UI directives" in prompt
    assert "inbox markup including ::inbox-item" in prompt
    assert "headers, Markdown, labels, or wrappers" in prompt


def test_daily_prompt_replays_same_idempotent_command_after_lost_result(tmp_path):
    prompt = canonical_prompt(
        "dailyWarRoom", tmp_path / "runtime", ["python", "daily_war_room_cycle.py", "--send"]
    )

    assert "context compaction or a missing tool result" in prompt
    assert "never reply from uncertainty" in prompt
    assert "execute the identical release-command once more" in prompt
    assert "durable delivery deduplication" in prompt


def test_staged_receipt_rejects_observations_older_than_freshness_window():
    observed_at = iso_z(utc_now() - timedelta(minutes=11))
    digest = "a" * 64
    labels = [
        "com.oss-pr-radar.local-publication",
        "com.oss-pr-radar.local-publication-slow",
        "com.oss-pr-radar.queue-importer",
    ]
    specs = [{"Label": label} for label in labels]
    records = [
        {
            "label": label,
            "observedAt": observed_at,
            "loaded": False,
            "pid": None,
            "specDigest": digest,
            "plistPath": f"/tmp/{label}.plist",
            "plistSha256": "b" * 64,
            "mode": "0o600",
            "ownerUid": operational_auth_module.os.getuid(),
            "regular": True,
            "symlink": False,
        }
        for label in labels
    ]

    with pytest.raises(RuntimeError, match="staged worker observation is stale"):
        operational_auth_module._validate_worker_records(records, specs=specs, spec_digest=digest)


def test_final_ledger_append_only_guard_preserves_exact_pr_invariants():
    counts = {"managed_lifecycle_events": 10, "managed_prs": 40, "managed_tasks": 2}
    states = {"OPEN": 29, "CLOSED": 8, "MERGED": 3}
    assert _managed_counts_append_only(
        counts,
        {**counts, "managed_lifecycle_events": 11},
        expected_pr_states=states,
        current_pr_states=states,
    )
    assert not _managed_counts_append_only(
        counts,
        {**counts, "managed_lifecycle_events": 9},
        expected_pr_states=states,
        current_pr_states=states,
    )
    assert not _managed_counts_append_only(
        counts,
        counts,
        expected_pr_states=states,
        current_pr_states={**states, "OPEN": 28},
    )


def test_stage7_acceptance_accepts_running_worker_without_last_exit_code():
    running = {
        "pid": 123,
        "lastExitCode": None,
        "processAlive": True,
        "processVersionMatched": True,
        "processWorkingDirectoryMatched": True,
        "freshness": {"fresh": False},
    }
    assert _activated_worker_execution_ok(running) is True

    assert (
        _activated_worker_execution_ok(
            {
                **running,
                "lastExitCode": 1,
            }
        )
        is False
    )

    assert (
        _activated_worker_execution_ok(
            {
                "pid": None,
                "lastExitCode": 0,
                "processAlive": False,
                "processVersionMatched": False,
                "processWorkingDirectoryMatched": False,
                "freshness": {"fresh": True},
            }
        )
        is True
    )


def _source(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ledger = ManagedLedger(path, ensure_schema=True)
    connection = ledger._connection()
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS values_table (value TEXT NOT NULL)")
        connection.execute("INSERT INTO values_table(value) VALUES (?)", (value,))
    finally:
        connection.close()


def _git_repo(path: Path) -> None:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Stage7 Test"], cwd=path, check=True)
    (path / "tracked.bin").write_bytes(b"before\x00binary")
    subprocess.run(["git", "add", "tracked.bin"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=path, check=True)
    (path / "tracked.bin").write_bytes(b"after\x00binary")
    (path / "untracked.bin").write_bytes(b"untracked\x00bytes")
    (path / "untracked.bin").chmod(0o640)
    (path / "z-untracked.bin").write_bytes(b"second\x00untracked")
    (path / "z-untracked.bin").chmod(0o600)


def _clean_git_repo(path: Path) -> None:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Stage7 Test"], cwd=path, check=True)
    (path / "tracked.txt").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=path, check=True)


def _ignore_runtime_artifacts(path: Path) -> None:
    releases = path / "releases" / "example"
    releases.mkdir(parents=True)
    (releases / "release-manifest.json").write_text("{}\n", encoding="utf-8")
    (path / "current-release").symlink_to(releases)
    raw = subprocess.check_output(
        ["git", "rev-parse", "--git-path", "info/exclude"], cwd=path, text=True
    ).strip()
    exclude = Path(raw)
    if not exclude.is_absolute():
        exclude = path / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    exclude.write_text("/current-release\n/releases/\n", encoding="utf-8")


def _bootstrap(runtime: Path, legacy: Path, tmp_path: Path) -> None:
    now = utc_now()
    expires = iso_z(now + timedelta(minutes=5))
    now = iso_z(now)
    unsigned = {
        "schema": "oss-pr-radar.stage7-stop-evidence.v1",
        "runtimeRootDigest": runtime_root_digest(runtime),
        "releaseId": "stage7-test",
        "observedAt": now,
        "expiresAt": expires,
        "allStopped": True,
        "workers": {
            worker: {"loaded": False, "pidAlive": False}
            for worker in ("fast", "slow", "queue-importer")
        },
        "legacy": {
            label: {"loaded": False}
            for label in (
                "com.oss-pr-radar.local-publication-agent",
                "com.oss-pr-radar.local-publication-worker",
                "com.oss-pr-radar.local-dispatch-bridge",
                "com.oss-pr-radar.local-publication-legacy",
            )
        },
    }
    auth = sign_current(unsigned, context="stage7-stop-evidence-v1")
    evidence = tmp_path / "stopped.json"
    evidence.write_text(json.dumps({**unsigned, **auth}), encoding="utf-8")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(cutover_module, "launchctl_print", lambda _label: "service not found")
        patch.setattr(cutover_module, "collect_snapshot", lambda _runtime: {})
        bootstrap(
            runtime,
            legacy,
            quiesce_token="writer-stopped",
            service_stopped_evidence=evidence,
        )


def _signed_staging_fixture(tmp_path: Path) -> tuple[Path, Path, list[dict[str, object]], Path]:
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "staging-negative")
    _bootstrap(runtime, source, tmp_path)
    prepared = prepare(runtime, source, quiesce_token="writer-stopped")
    activate(runtime, Path(prepared["manifestPath"]))
    home = tmp_path / "home"
    current = operational_auth_module._current_ledger_identity(runtime)
    release_id = "stage7-test"
    now = iso_z(utc_now())
    counts_unsigned = {
        "schema": "oss-pr-radar.stage7-counts-evidence.v1",
        "runtimeRootDigest": runtime_root_digest(runtime),
        "releaseId": release_id,
        "releaseHead": "a" * 40,
        "observedAt": now,
        "ledgerGeneration": current["generation"],
        "ledgerSha256": current["sha256"],
        "managedPrProjectionDigest": current["managedPrProjectionDigest"],
    }
    counts_path = tmp_path / "counts.json"
    counts_path.write_text(
        json.dumps(
            {
                **counts_unsigned,
                **sign_current(counts_unsigned, context="stage7-counts-evidence-v1"),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    counts_path.chmod(0o600)
    specs_value = worker_specs(
        runtime / "releases" / "stage7-test", home=home, runtime_root=runtime
    )
    issue_worker_staging_authorization(
        runtime,
        managed_counts_evidence=counts_path,
        home=home,
    )
    staging_token = json.loads(
        operational_auth_module.worker_staging_authorization_path(runtime).read_text(
            encoding="utf-8"
        )
    )
    assert "automationSnapshotPath" not in staging_token
    assert "automationSnapshotSha256" not in staging_token
    return (
        runtime,
        home,
        specs_value,
        operational_auth_module.worker_staging_authorization_path(runtime),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "expired",
        "signature",
        "tampered-field",
        "runtime-root",
        "release-id",
        "release-head",
        "release-manifest",
        "ledger-pointer",
        "ledger-generation",
        "ledger-hash",
        "counts-digest",
        "worker-spec",
        "replay",
    ],
)
def test_staging_authorization_rejects_bound_tamper_before_any_stage_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "staging-negative-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime, home, specs_value, token_path = _signed_staging_fixture(tmp_path)
    token = json.loads(token_path.read_text(encoding="utf-8"))
    resign = mutation not in {"signature", "tampered-field"}
    changes: dict[str, object] = {
        "expired": {"expiresAt": iso_z(utc_now() - timedelta(seconds=1))},
        "runtime-root": {"runtimeRootDigest": "f" * 64},
        "release-id": {"releaseId": "wrong-release"},
        "release-head": {"releaseHead": "b" * 40},
        "release-manifest": {"releaseManifestSha256": "c" * 64},
        "ledger-pointer": {"ledgerTarget": "ledger-releases/other.sqlite3"},
        "ledger-generation": {"ledgerGeneration": "stale-generation"},
        "ledger-hash": {"ledgerSha256": "d" * 64},
        "counts-digest": {"managedCountsEvidenceSha256": "e" * 64},
        "worker-spec": {"workerSpecDigest": "g" * 64},
        "replay": {"state": "CONSUMED"},
    }
    if mutation in changes:
        token.update(changes[mutation])
    elif mutation == "signature":
        token["signature"] = "invalid-signature"
    else:
        token["unexpected"] = "tamper"
    if resign:
        unsigned = {key: value for key, value in token.items() if key not in {"keyId", "signature"}}
        token = {
            **unsigned,
            **sign_current(unsigned, context="stage7-worker-staging-authorization-v1"),
        }
    token_path.write_text(json.dumps(token) + "\n", encoding="utf-8")
    token_path.chmod(0o600)

    with pytest.raises(RuntimeError):
        operational_auth_module.require_worker_staging_authorization(
            runtime, specs=specs_value, home=home
        )
    assert not (home / "Library" / "LaunchAgents").exists()
    assert not operational_auth_module.staged_worker_receipt_path(runtime).exists()


def _consume_signed_staging_fixture(
    runtime: Path, home: Path, specs: list[dict[str, object]]
) -> dict[str, object]:
    launch_dir = (home / "Library" / "LaunchAgents").resolve()
    launch_dir.mkdir(parents=True)
    spec_digest = worker_spec_digest(specs)
    records: list[dict[str, object]] = []
    for spec in specs:
        label = str(spec["Label"])
        path = launch_dir / f"{label}.plist"
        path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML, sort_keys=True))
        path.chmod(0o600)
        records.append(
            {
                "worker": label,
                "label": label,
                "plistPath": str(path),
                "plistSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": "0o600",
                "ownerUid": operational_auth_module.os.getuid(),
                "regular": True,
                "symlink": False,
                "loaded": False,
                "pid": None,
                "specDigest": spec_digest,
                "observedAt": iso_z(utc_now()),
            }
        )
    return consume_worker_staging_authorization(
        runtime,
        specs=specs,
        worker_records=records,
    )


def test_expired_worker_staging_reset_preserves_bound_plists_and_allows_reissue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "staging-reset-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime, home, specs, token_path = _signed_staging_fixture(tmp_path)
    token = json.loads(token_path.read_text(encoding="utf-8"))
    counts_path = Path(str(token["managedCountsEvidencePath"]))
    receipt = _consume_signed_staging_fixture(runtime, home, specs)
    expires = datetime.fromisoformat(str(receipt["stagingExpiresAt"]).replace("Z", "+00:00"))

    result = reset_expired_worker_staging(
        runtime,
        home=home,
        launchctl_runner=lambda _label: "Could not find service",
        now=expires + timedelta(seconds=1),
    )

    assert result["ok"] is True
    assert result["reset"] is True
    assert result["workersUnloaded"] is True
    assert result["pendingPublicationEffects"] == 0
    assert result["removed"] == [
        "worker-staging-authorization.json",
        "staged-worker-receipt.json",
    ]
    assert not token_path.exists()
    assert not staged_worker_receipt_path(runtime).exists()
    assert all(
        (home / "Library" / "LaunchAgents" / f"{spec['Label']}.plist").is_file() for spec in specs
    )
    renewed = issue_worker_staging_authorization(
        runtime,
        managed_counts_evidence=counts_path,
        home=home,
    )
    assert renewed["state"] == "ACTIVE"


def test_expired_worker_staging_reset_is_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "staging-reset-block-key" * 3)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime, home, _specs, token_path = _signed_staging_fixture(tmp_path)
    token = json.loads(token_path.read_text(encoding="utf-8"))
    expires = datetime.fromisoformat(str(token["expiresAt"]).replace("Z", "+00:00"))

    with pytest.raises(RuntimeError, match="refuses unexpired"):
        reset_expired_worker_staging(
            runtime,
            home=home,
            launchctl_runner=lambda _label: "service not found",
            now=datetime.fromisoformat(str(token["issuedAt"]).replace("Z", "+00:00"))
            + timedelta(seconds=1),
        )
    assert token_path.exists()

    with pytest.raises(RuntimeError, match="requires unloaded worker"):
        reset_expired_worker_staging(
            runtime,
            home=home,
            launchctl_runner=lambda label: (
                "state = waiting" if label.endswith("local-publication") else "service not found"
            ),
            now=expires + timedelta(seconds=1),
        )
    assert token_path.exists()

    import oss_pr_radar.runtime as runtime_module

    monkeypatch.setattr(runtime_module, "pending_publication_effects", lambda _path: 1)
    with pytest.raises(RuntimeError, match="zero pending publication effects"):
        reset_expired_worker_staging(
            runtime,
            home=home,
            launchctl_runner=lambda _label: "service not found",
            now=expires + timedelta(seconds=1),
        )
    assert token_path.exists()


def test_expired_worker_staging_reset_rejects_staged_plist_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "staging-reset-drift-key" * 3)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime, home, specs, token_path = _signed_staging_fixture(tmp_path)
    receipt = _consume_signed_staging_fixture(runtime, home, specs)
    expires = datetime.fromisoformat(str(receipt["stagingExpiresAt"]).replace("Z", "+00:00"))
    drifted = home / "Library" / "LaunchAgents" / f"{specs[0]['Label']}.plist"
    drifted.write_bytes(drifted.read_bytes() + b"\n")

    with pytest.raises(RuntimeError, match="plist binding mismatch"):
        reset_expired_worker_staging(
            runtime,
            home=home,
            launchctl_runner=lambda _label: "service not found",
            now=expires + timedelta(seconds=1),
        )
    assert token_path.exists()
    assert staged_worker_receipt_path(runtime).exists()


def test_expired_worker_staging_reset_clears_only_staged_operational_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "staging-reset-staged-key" * 3)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime, home, specs, token_path = _signed_staging_fixture(tmp_path)
    receipt = _consume_signed_staging_fixture(runtime, home, specs)
    _, binding = operational_auth_module.active_release(runtime)
    ledger = operational_auth_module._current_ledger_identity(runtime)
    issued = utc_now()
    auth_unsigned = {
        "schema": operational_auth_module.OPERATIONAL_AUTH_SCHEMA,
        "state": "STAGED",
        "runtimeRootDigest": runtime_root_digest(runtime),
        "releaseId": binding["releaseId"],
        "releaseHead": binding["commit"],
        "releaseManifestSha256": binding["manifestSha256"],
        "ledgerTarget": ledger["target"],
        "ledgerGeneration": ledger["generation"],
        "ledgerSha256AtIssue": ledger["sha256"],
        "managedPrProjectionDigest": ledger["managedPrProjectionDigest"],
        "managedCountsEvidenceSha256": receipt["managedCountsEvidenceSha256"],
        "automationSnapshotSha256": "a" * 64,
        "issuedAt": iso_z(issued),
        "workerConfigDigest": worker_spec_digest(specs),
        "stagedWorkerReceiptSha256": operational_auth_module.stable_evidence_digest(
            staged_worker_receipt_path(runtime)
        ),
        "stagingNonce": receipt["stagingNonce"],
        "workerPlistBindings": [
            {
                key: item[key]
                for key in (
                    "label",
                    "plistPath",
                    "plistSha256",
                    "mode",
                    "ownerUid",
                    "regular",
                    "symlink",
                )
            }
            for item in receipt["workers"]
        ],
    }
    auth_path = authorization_path(runtime)
    auth_path.write_text(
        json.dumps(
            {
                **auth_unsigned,
                **sign_current(
                    auth_unsigned, context=operational_auth_module.OPERATIONAL_AUTH_CONTEXT
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    auth_path.chmod(0o600)

    result = reset_expired_worker_staging(
        runtime,
        home=home,
        launchctl_runner=lambda _label: "service not found",
        now=issued + timedelta(minutes=11),
    )

    assert result["removed"] == [
        "operational-authorization.json",
        "worker-staging-authorization.json",
        "staged-worker-receipt.json",
    ]
    assert not auth_path.exists()
    assert not token_path.exists()
    assert not staged_worker_receipt_path(runtime).exists()


def test_expired_worker_staging_reset_never_clears_active_operational_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "staging-reset-active-key" * 3)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime, home, _specs, _token_path = _signed_staging_fixture(tmp_path)
    unsigned = {"schema": operational_auth_module.OPERATIONAL_AUTH_SCHEMA, "state": "ACTIVE"}
    auth_path = authorization_path(runtime)
    auth_path.write_text(
        json.dumps(
            {
                **unsigned,
                **sign_current(unsigned, context=operational_auth_module.OPERATIONAL_AUTH_CONTEXT),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    auth_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="refuses ACTIVE"):
        reset_expired_worker_staging(
            runtime,
            home=home,
            launchctl_runner=lambda _label: "service not found",
            now=utc_now() + timedelta(hours=1),
        )
    assert auth_path.exists()


def test_stage7_evidence_exposes_expired_worker_staging_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = tmp_path / "runtime"
    observed: dict[str, object] = {}

    def reset(root: Path, *, home: Path | None = None) -> dict[str, object]:
        observed.update({"root": root, "home": home})
        return {"ok": True, "reset": True}

    monkeypatch.setattr(stage7_evidence_script, "reset_expired_worker_staging", reset)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "stage7_evidence.py",
            "reset-expired-worker-staging",
            "--runtime-root",
            str(runtime),
            "--home",
            str(tmp_path / "home"),
        ],
    )

    assert stage7_evidence_script.main() == 0
    assert observed == {"root": runtime, "home": tmp_path / "home"}
    assert json.loads(capsys.readouterr().out)["reset"] is True


def test_stage7_prepare_activate_and_rollback_only_moves_pointer(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-key" * 5)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "one")
    _bootstrap(runtime, source, tmp_path)
    observed_at = iso_z(utc_now())
    first = prepare(runtime, source, quiesce_token="writer-stopped", observed_at=observed_at)
    assert first["manifest"]["nonce"]
    assert first["manifest"]["fileInventory"]
    assert first["manifest"]["observationTime"] == observed_at
    activate(runtime, Path(first["manifestPath"]))
    first_target = (runtime / "state" / "current-ledger").resolve()
    before = first_target.read_bytes()
    assert check(runtime, home=tmp_path / "home", strict=False)["ok"] is True
    _source(source, "two")
    second = prepare(runtime, source, quiesce_token="writer-stopped")
    activate(runtime, Path(second["manifestPath"]))
    second_target = (runtime / "state" / "current-ledger").resolve()
    ManagedLedger(second_target, ensure_schema=True).record_event(
        event_type="POST_ACTIVATE_WRITE", idempotency_key="post-activate-write"
    )
    assert second_target != first_target
    rollback(runtime, Path(second["manifestPath"]))
    assert (runtime / "state" / "current-ledger").resolve() == first_target
    assert first_target.read_bytes() == before
    assert second_target.is_file()
    assert status(runtime)["pointer"]["target"] == str(first_target.relative_to(runtime / "state"))


def test_stage7_bootstrap_rollback_consumes_nonce_once(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-bootstrap-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "bootstrap")
    _bootstrap(runtime, source, tmp_path)
    prepared = prepare(runtime, source, quiesce_token="writer-stopped")
    activate(runtime, Path(prepared["manifestPath"]))
    activated_copy = tmp_path / "activated-copy.json"
    shutil.copy2(prepared["manifestPath"], activated_copy)
    assert prepared["manifest"]["previousTarget"].startswith("ledger-releases/bootstrap-")
    rollback(runtime, Path(prepared["manifestPath"]))
    assert (runtime / "state" / "current-ledger").resolve().name.startswith("bootstrap-")
    with pytest.raises(RuntimeError, match="nonce has already been consumed"):
        rollback(runtime, activated_copy)


def test_stage7_preserves_git_bytes_modes_and_source(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-git-key" * 5)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "one")
    _bootstrap(runtime, source, tmp_path)
    source_before = source.read_bytes()
    repo = tmp_path / "production-repo"
    _git_repo(repo)
    _ignore_runtime_artifacts(repo)
    status_before = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo, text=True
    )
    result = prepare(runtime, source, quiesce_token="writer-stopped", production_repo=repo)
    preservation = result["manifest"]["gitPreservation"]
    archive = Path(preservation["archivePath"])
    metadata = json.loads((archive / "archive-manifest.json").read_text())
    assert (archive / "tracked.patch").read_bytes()
    assert metadata["untrackedFiles"][0]["mode"] == "0o640"
    assert {item["path"] for item in preservation["untrackedFiles"]} == {
        "untracked.bin",
        "z-untracked.bin",
    }
    assert source.read_bytes() == source_before
    assert (
        subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo, text=True
        )
        == status_before
    )
    assert all((item["mode"] == "0o600") for item in result["manifest"]["fileInventory"])
    restored = restore_git_preservation(Path(result["manifestPath"]), repo, mode="rehearse")
    assert restored["ok"] is True
    assert restored["phase"] == "VERIFIED"
    subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "clean", "-fd"], cwd=repo, check=True, capture_output=True)
    applied = restore_git_preservation(Path(result["manifestPath"]), repo, mode="apply")
    assert applied["ok"] is True
    assert (repo / "untracked.bin").stat().st_mode & 0o777 == 0o640
    assert (repo / "z-untracked.bin").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("with_untracked", [False, True])
def test_stage7_rehearses_empty_tracked_patch(tmp_path, monkeypatch, with_untracked):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-empty-patch-key" * 5)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "empty-patch")
    _bootstrap(runtime, source, tmp_path)
    repo = tmp_path / "production-repo"
    _clean_git_repo(repo)
    if with_untracked:
        (repo / "user-note.txt").write_bytes(b"preserve me\x00\n")
        (repo / "user-note.txt").chmod(0o640)
    status_before = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo, text=True
    )
    result = prepare(runtime, source, quiesce_token="writer-stopped", production_repo=repo)
    archive = Path(result["manifest"]["gitPreservation"]["archivePath"])
    assert (archive / "tracked.patch").read_bytes() == b""
    assert result["manifest"]["gitPreservation"]["trackedPatch"]["bytes"] == 0

    rehearsed = restore_git_preservation(Path(result["manifestPath"]), repo, mode="rehearse")
    assert rehearsed["ok"] is True
    assert rehearsed["status"] == status_before

    if with_untracked:
        (repo / "user-note.txt").unlink()
        applied = restore_git_preservation(Path(result["manifestPath"]), repo, mode="apply")
        assert applied["ok"] is True
        assert (repo / "user-note.txt").read_bytes() == b"preserve me\x00\n"
        assert (repo / "user-note.txt").stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize("mutation", ["missing", "metadata"])
def test_stage7_empty_tracked_patch_tamper_fails_closed(tmp_path, monkeypatch, mutation):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-empty-patch-tamper-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "empty-patch-tamper")
    _bootstrap(runtime, source, tmp_path)
    repo = tmp_path / "production-repo"
    _clean_git_repo(repo)
    result = prepare(runtime, source, quiesce_token="writer-stopped", production_repo=repo)
    archive = Path(result["manifest"]["gitPreservation"]["archivePath"])
    patch = archive / "tracked.patch"
    if mutation == "missing":
        patch.unlink()
    else:
        archive_manifest = archive / "archive-manifest.json"
        value = json.loads(archive_manifest.read_text(encoding="utf-8"))
        value["trackedPatch"]["bytes"] = 1
        archive_manifest.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        archive_manifest.chmod(0o600)
    with pytest.raises(RuntimeError, match="inventory|missing|changed"):
        restore_git_preservation(Path(result["manifestPath"]), repo, mode="rehearse")


def test_stage7_rejects_tampered_preservation_before_activate(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-inventory-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "one")
    _bootstrap(runtime, source, tmp_path)
    repo = tmp_path / "production-repo"
    _git_repo(repo)
    result = prepare(runtime, source, quiesce_token="writer-stopped", production_repo=repo)
    archive = Path(result["manifest"]["gitPreservation"]["archivePath"])
    (archive / "tracked.patch").write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="inventory"):
        activate(runtime, Path(result["manifestPath"]))


def test_stage7_restore_apply_rolls_back_after_tracked_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-restore-fail-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "one")
    _bootstrap(runtime, source, tmp_path)
    repo = tmp_path / "production-repo"
    _git_repo(repo)
    result = prepare(runtime, source, quiesce_token="writer-stopped", production_repo=repo)
    subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "clean", "-fd"], cwd=repo, check=True, capture_output=True)
    original = cutover_module._apply_preservation_to_repo

    def fail_after_target(repo_path, manifest, journal):
        value = original(repo_path, manifest, journal)
        if repo_path.resolve() == repo.resolve():
            raise RuntimeError("injected tracked apply failure")
        return value

    monkeypatch.setattr(cutover_module, "_apply_preservation_to_repo", fail_after_target)
    with pytest.raises(RuntimeError, match="injected tracked apply failure"):
        restore_git_preservation(Path(result["manifestPath"]), repo, mode="apply")
    assert (
        subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo, text=True
        )
        == ""
    )
    assert not (repo / "untracked.bin").exists()
    assert not (repo / "z-untracked.bin").exists()
    assert not list(repo.rglob("*.restore.*.tmp"))
    assert not list(repo.parent.glob(f".{repo.name}.oss-pr-radar-restore.json"))


def test_stage7_restore_apply_rolls_back_after_untracked_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-restore-untracked-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "one")
    _bootstrap(runtime, source, tmp_path)
    repo = tmp_path / "production-repo"
    _git_repo(repo)
    result = prepare(runtime, source, quiesce_token="writer-stopped", production_repo=repo)
    subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "clean", "-fd"], cwd=repo, check=True, capture_output=True)
    original_private = cutover_module._private_bytes
    counter = {"writes": 0}

    def fail_second_untracked(path, payload):
        original_private(path, payload)
        if ".restore." in path.name:
            counter["writes"] += 1
            if counter["writes"] == 4:
                raise RuntimeError("injected untracked failure")

    monkeypatch.setattr(cutover_module, "_private_bytes", fail_second_untracked)
    with pytest.raises(RuntimeError, match="injected untracked failure"):
        restore_git_preservation(Path(result["manifestPath"]), repo, mode="apply")
    assert (
        subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo, text=True
        )
        == ""
    )
    assert not (repo / "untracked.bin").exists()
    assert not (repo / "z-untracked.bin").exists()
    assert not list(repo.rglob("*.restore.*.tmp"))
    assert not list(repo.parent.glob(f".{repo.name}.oss-pr-radar-restore.json"))
    assert (repo / "tracked.bin").read_bytes() == b"before\x00binary"


def test_stage7_signed_stop_evidence_is_rechecked_for_toctou(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-toctou-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "one")
    monkeypatch.setattr(
        cutover_module,
        "_live_services_stopped",
        lambda _root: (_ for _ in ()).throw(RuntimeError("service restarted")),
    )
    with pytest.raises(RuntimeError, match="service restarted"):
        _bootstrap(runtime, source, tmp_path)


def test_stage7_strict_acceptance_uses_actual_plists_launchd_and_signed_inputs(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "stage7-strict-key" * 4)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "stage7-current")
    # This test exercises release/worker evidence, not host capacity.  Keep
    # the shared disk gate deterministic even when the CI host is near its
    # hard threshold while the temporary fixture is being built.
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot",
        lambda _root: {"level": "ok", "freeBytes": 100 * 1024**3},
    )
    runtime = _runtime(tmp_path)
    source = tmp_path / "source.sqlite3"
    _source(source, "strict")
    _bootstrap(runtime, source, tmp_path)
    prepared = prepare(runtime, source, quiesce_token="writer-stopped")
    activate(runtime, Path(prepared["manifestPath"]))
    deploy_local_runtime.activate_release(runtime, "stage7-test")
    home = tmp_path / "home"
    contracts = build_contracts(runtime, home=home)
    launch_dir = home / "Library" / "LaunchAgents"
    now = iso_z(utc_now())
    health_path = runtime / "state" / "runtime-health.json"
    state = json.loads(health_path.read_text(encoding="utf-8"))
    state["workers"] = {
        "fast": {"lastSuccessAt": now, "lastExitCode": 0},
        "slow": {"lastSuccessAt": now, "lastExitCode": 0},
        "queue-importer": {"queueImportSuccessAt": now, "queueLastExitCode": 0},
    }
    health_path.write_text(json.dumps(state), encoding="utf-8")
    retry_at = utc_now().timestamp() + 300
    (runtime / "state" / "slow-worker-backoff.json").write_text(
        json.dumps(
            {
                "schemaVersion": "slow_backoff_v1",
                "failureCount": 1,
                "nextAttemptAt": retry_at,
                "retryAfter": retry_at,
                "inFlight": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    def must_not_run_slow(_root: Path, _operation: str):
        raise AssertionError("persisted backoff should not run slow work")

    slow_result = slow_advance_once(runtime, runner=must_not_run_slow)
    assert slow_result["reason"] == "PERSISTED_BACKOFF"
    assert json.loads(health_path.read_text(encoding="utf-8"))["workers"]["slow"] == {
        "lastSuccessAt": now,
        "lastExitCode": 0,
    }
    report_dir = tmp_path / "stage6"
    report_dir.mkdir()
    report = report_dir / "report.json"
    envelope = report_dir / "envelope.json"
    report.write_text(
        json.dumps(
            {
                "codeHead": "a" * 40,
                "verification": _verification("a" * 40),
                "prInvariant": {
                    "totalRecords": 0,
                    "currentOpen": 0,
                    "closedOrMerged": 0,
                    "allManagedKeysObserved": True,
                    "liveOpenCount": 0,
                    "missing": [],
                    "unexpected": [],
                    "duplicates": [],
                    "headMismatches": [],
                    "managedPrProjectionDigest": projection_summary([])["digest"],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    report.chmod(0o600)
    from oss_pr_radar.stage6_rehearsal import artifact_manifest, write_detached_report_envelope

    inventory = artifact_manifest(report_dir, exclude_names={envelope.name})
    write_detached_report_envelope(report, envelope, code_head="a" * 40, inventory=inventory)
    counts = build_managed_counts_evidence(runtime, report, envelope, code_head="a" * 40)
    heartbeat_toml = tmp_path / "heartbeat.automation.toml"
    daily_toml = tmp_path / "daily.automation.toml"

    def write_automation(path, role):
        spec = contracts[role]
        timestamp = int(utc_now().timestamp() * 1000)
        lines = [
            "version = 1",
            f"name = {json.dumps(spec['name'])}",
            f"id = {json.dumps(spec['id'])}",
            f"kind = {json.dumps(spec['kind'])}",
            f"status = {json.dumps(spec['status'])}",
            f"rrule = {json.dumps(spec['rrule'])}",
            f"created_at = {timestamp}",
            f"updated_at = {timestamp}",
        ]
        lines.append(f"target_thread_id = {json.dumps(spec['targetThreadId'])}")
        lines.append(
            f"prompt = {json.dumps(canonical_prompt(role, runtime, spec['releaseCommand']))}"
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    write_automation(heartbeat_toml, "heartbeat")
    write_automation(daily_toml, "dailyWarRoom")
    outputs = {}
    for label, spec in contracts["workers"].items():
        args = "\n".join(f"  {arg}" for arg in spec["command"])
        outputs[label] = (
            f"state = waiting\nprogram = {spec['command'][0]}\narguments = {{\n{args}\n}}\nworking directory = {spec['workdir']}\nlast exit code = 0\n"
        )

    def launchctl(label: str) -> str:
        return outputs.get(label, "Could not find service")

    monkeypatch.setattr(
        "oss_pr_radar.stage7_acceptance.disk_snapshot",
        lambda _root: {"level": "ok", "freeBytes": 64 * 1024**3},
    )
    counts_path = tmp_path / "managed-counts.json"
    automation_path = tmp_path / "automation-snapshot.json"
    counts_path.write_text(json.dumps(counts, sort_keys=True) + "\n", encoding="utf-8")
    specs_value = worker_specs(
        runtime / "releases" / "stage7-test", home=home, runtime_root=runtime
    )
    issue_worker_staging_authorization(
        runtime,
        managed_counts_evidence=counts_path,
        home=home,
    )
    assert not launch_dir.exists()
    monkeypatch.setattr(
        workers_module,
        "launchctl",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 1, "", ""),
    )
    workers_module.stage_workers(
        specs_value, home=home, domain=f"gui/{operational_auth_module.os.getuid()}"
    )
    assert sorted(path.name for path in launch_dir.glob("*.plist")) == sorted(
        f"{spec['Label']}.plist" for spec in specs_value
    )
    automation = build_automation_snapshot(
        runtime,
        heartbeat_toml,
        daily_toml,
        home=home,
        observed_at=now,
    )
    assert automation["schema"] == "oss-pr-radar.stage7-automation-snapshot.v3"
    assert automation["generator"] == "stage7-automation-toml-v3"
    assert automation["dailyWarRoom"]["kind"] == "heartbeat"
    assert automation["heartbeat"]["targetThreadId"] == "019f71c3-4f26-7030-b126-25f8cfbac4c4"
    assert automation["dailyWarRoom"]["targetThreadId"] == ("01a03bf2-e310-7f63-8db6-a9ec0a39f4aa")
    assert automation["dailyWarRoom"]["targetThreadId"] != automation["heartbeat"]["targetThreadId"]
    assert {
        "model",
        "reasoningEffort",
        "executionEnvironment",
        "cwds",
        "target",
    }.isdisjoint(automation["dailyWarRoom"])
    automation_unsigned = {
        key: value for key, value in automation.items() if key not in {"keyId", "signature"}
    }
    auth = {key: value for key, value in automation.items() if key in {"keyId", "signature"}}
    automation_path.write_text(
        json.dumps({**automation_unsigned, **auth}, sort_keys=True) + "\n", encoding="utf-8"
    )
    staged_records = []
    for spec in specs_value:
        label = str(spec["Label"])
        plist = (launch_dir / f"{label}.plist").resolve()
        staged_records.append(
            {
                "worker": label,
                "label": label,
                "plistPath": str(plist),
                "plistSha256": hashlib.sha256(plist.read_bytes()).hexdigest(),
                "mode": "0o600",
                "ownerUid": plist.stat().st_uid,
                "regular": True,
                "symlink": False,
                "loaded": False,
                "pid": None,
                "specDigest": worker_spec_digest(specs_value),
                "observedAt": iso_z(utc_now()),
            }
        )
    first_receipt = consume_worker_staging_authorization(
        runtime, specs=specs_value, worker_records=staged_records
    )
    receipt_value = json.loads(staged_worker_receipt_path(runtime).read_text(encoding="utf-8"))
    assert "automationSnapshotPath" not in receipt_value
    assert "automationSnapshotSha256" not in receipt_value
    receipt_path = staged_worker_receipt_path(runtime)
    receipt_bytes = receipt_path.read_bytes()
    receipt_stat = receipt_path.stat()
    second_receipt = consume_worker_staging_authorization(
        runtime, specs=specs_value, worker_records=staged_records
    )
    assert second_receipt == first_receipt
    assert (
        hashlib.sha256(receipt_bytes).hexdigest()
        == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    )
    assert receipt_path.stat().st_mtime_ns == receipt_stat.st_mtime_ns
    preflight = check(
        runtime,
        home=home,
        launchctl_runner=lambda _label: "Could not find service",
        managed_counts_evidence=counts,
        automation_snapshot={**automation_unsigned, **auth},
        require_workers_loaded=False,
    )
    assert preflight["ok"] is True
    assert preflight["stagedWorkerReceiptValid"] is True
    assert preflight["runtimeReleasePolicyIdentityMatch"] is True
    issue_operational_authorization(
        runtime,
        managed_counts_evidence=counts_path,
        automation_snapshot=automation_path,
        home=home,
        launchctl_runner=lambda _label: "Could not find service",
    )
    assert staged_worker_receipt_path(runtime).exists()
    receipt_before_finalize = staged_worker_receipt_path(runtime).read_bytes()
    with monkeypatch.context() as context:
        context.setattr(
            operational_auth_module,
            "_remove_private_and_fsync",
            lambda _path: (_ for _ in ()).throw(OSError("receipt fsync failure")),
        )
        with pytest.raises(OSError, match="receipt fsync failure"):
            finalize_operational_authorization(runtime)
    assert staged_worker_receipt_path(runtime).read_bytes() == receipt_before_finalize
    assert json.loads(authorization_path(runtime).read_text())["state"] == "STAGED"
    with monkeypatch.context() as context:
        context.setattr(
            operational_auth_module,
            "_write_private_commit_point",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("active write failure")),
        )
        with pytest.raises(OSError, match="active write failure"):
            finalize_operational_authorization(runtime)
    assert not staged_worker_receipt_path(runtime).exists()
    assert json.loads(authorization_path(runtime).read_text())["state"] == "STAGED"
    staged_worker_receipt_path(runtime).write_bytes(receipt_before_finalize)
    staged_worker_receipt_path(runtime).chmod(0o600)

    def assert_staged_receipt_drift_rejected() -> None:
        assert (
            check(
                runtime,
                home=home,
                launchctl_runner=lambda _label: "Could not find service",
                managed_counts_evidence=counts_path,
                automation_snapshot=automation_path,
                require_workers_loaded=False,
            )["ok"]
            is False
        )

    activation_plist = launch_dir / "com.oss-pr-radar.local-publication.plist"
    activation_bytes = activation_plist.read_bytes()
    activation_plist.chmod(0o644)
    assert_staged_receipt_drift_rejected()
    activation_plist.chmod(0o600)
    current_uid = operational_auth_module.os.getuid()
    with monkeypatch.context() as context:
        context.setattr(operational_auth_module.os, "getuid", lambda: current_uid + 1)
        assert_staged_receipt_drift_rejected()
    activation_plist.unlink()
    activation_plist.symlink_to(launch_dir / "com.oss-pr-radar.local-publication-slow.plist")
    assert_staged_receipt_drift_rejected()
    activation_plist.unlink()
    activation_plist.write_bytes(activation_bytes)
    activation_plist.chmod(0o600)
    activation_plist.unlink()
    activation_plist.mkdir()
    assert_staged_receipt_drift_rejected()
    activation_plist.rmdir()
    activation_plist.write_bytes(activation_bytes)
    activation_plist.chmod(0o600)

    with pytest.raises(RuntimeError, match="not been activated"):
        verify_operational_authorization(runtime)
    activation_plist.write_bytes(activation_bytes + b"drift")
    with pytest.raises(RuntimeError, match="worker binding"):
        verify_operational_authorization(runtime, require_staged_receipt=True)
    activation_plist.write_bytes(activation_bytes)
    finalize_operational_authorization(runtime)
    assert not staged_worker_receipt_path(runtime).exists()
    result = check(
        runtime,
        home=home,
        launchctl_runner=launchctl,
        managed_counts_evidence=counts_path,
        automation_snapshot=automation_path,
    )
    assert result["ok"] is True
    assert result["operationalAuthorizationValid"] is True
    assert result["operationalAuthorizationEvidenceMatch"] is True

    # Worker health/lifecycle bookkeeping may append after activation, but
    # the Stage 6 PR projection and all PR state counts remain immutable.
    ManagedLedger(
        (runtime / "state" / "current-ledger").resolve(), ensure_schema=True
    ).record_event(event_type="WORKER_HEALTH_APPEND", idempotency_key="worker-health-append")
    appended = check(
        runtime,
        home=home,
        launchctl_runner=launchctl,
        managed_counts_evidence=counts_path,
        automation_snapshot=automation_path,
    )
    assert appended["ok"] is True
    assert appended["managedCountsEvidenceValid"] is True

    drift_plist = launch_dir / "com.oss-pr-radar.local-publication.plist"
    drift_bytes = drift_plist.read_bytes()
    drift_plist.write_bytes(drift_bytes + b"\n")
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts_path,
            automation_snapshot=automation_path,
        )["ok"]
        is False
    )
    drift_plist.write_bytes(drift_bytes)
    heartbeat_text = heartbeat_toml.read_text(encoding="utf-8")
    heartbeat_toml.write_text(heartbeat_text + "command = []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported or missing fields"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    heartbeat_toml.write_text(heartbeat_text, encoding="utf-8")
    daily_text = daily_toml.read_text(encoding="utf-8")
    daily_toml.write_text(
        daily_text.replace('kind = "heartbeat"', 'kind = "cron"'), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="dailyWarRoom automation kind"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    daily_toml.write_text(daily_text, encoding="utf-8")
    daily_toml.write_text(
        daily_text.replace(
            'target_thread_id = "01a03bf2-e310-7f63-8db6-a9ec0a39f4aa"',
            'target_thread_id = "wrong-thread"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dailyWarRoom target thread"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    daily_toml.write_text(daily_text, encoding="utf-8")
    heartbeat_toml.write_text(
        heartbeat_text.replace(
            'target_thread_id = "019f71c3-4f26-7030-b126-25f8cfbac4c4"',
            'target_thread_id = "01a03bf2-e310-7f63-8db6-a9ec0a39f4aa"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="heartbeat target thread"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    heartbeat_toml.write_text(heartbeat_text, encoding="utf-8")
    daily_toml.write_text(
        daily_text.replace(
            'target_thread_id = "01a03bf2-e310-7f63-8db6-a9ec0a39f4aa"',
            'target_thread_id = "019f71c3-4f26-7030-b126-25f8cfbac4c4"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dailyWarRoom target thread"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    daily_toml.write_text(daily_text, encoding="utf-8")
    daily_toml.write_text(daily_text + 'model = "gpt-5.5"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported or missing fields"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    daily_toml.write_text(daily_text, encoding="utf-8")
    daily_prompt = canonical_prompt(
        "dailyWarRoom", runtime, contracts["dailyWarRoom"]["releaseCommand"]
    )
    no_send_prompt = canonical_prompt(
        "dailyWarRoom", runtime, contracts["dailyWarRoom"]["releaseCommand"][:-1]
    )
    daily_toml.write_text(
        daily_text.replace(json.dumps(daily_prompt), json.dumps(no_send_prompt)), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="canonical template"):
        build_automation_snapshot(runtime, heartbeat_toml, daily_toml, home=home, observed_at=now)
    daily_toml.write_text(daily_text, encoding="utf-8")
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )
    stale_unsigned = {**automation_unsigned, "observedAt": iso_z(utc_now() - timedelta(minutes=11))}
    stale_auth = sign_current(stale_unsigned, context="stage7-automation-snapshot-v1")
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**stale_unsigned, **stale_auth},
        )["ok"]
        is False
    )
    outputs["com.oss-pr-radar.local-publication"] = outputs[
        "com.oss-pr-radar.local-publication"
    ].replace("working directory = ", "working directory = /poisoned-runtime/")
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )
    outputs["com.oss-pr-radar.local-publication-legacy"] = "state = waiting\n"
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )

    bad_dir = tmp_path / "bad-stage6"
    bad_dir.mkdir()
    bad_report = bad_dir / "report.json"
    bad_envelope = bad_dir / "envelope.json"
    bad_report.write_text(
        json.dumps(
            {
                "codeHead": "a" * 40,
                "verification": _verification("a" * 40),
                "prInvariant": {
                    "totalRecords": 999,
                    "currentOpen": 999,
                    "closedOrMerged": 0,
                    "allManagedKeysObserved": True,
                    "liveOpenCount": 999,
                    "missing": [],
                    "unexpected": [],
                    "duplicates": [],
                    "headMismatches": [],
                    "managedPrProjectionDigest": projection_summary([])["digest"],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    bad_report.chmod(0o600)
    bad_inventory = artifact_manifest(bad_dir, exclude_names={bad_envelope.name})
    write_detached_report_envelope(
        bad_report, bad_envelope, code_head="a" * 40, inventory=bad_inventory
    )
    bad_counts = build_managed_counts_evidence(
        runtime, bad_report, bad_envelope, code_head="a" * 40
    )
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=bad_counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )

    identity_dir = tmp_path / "identity-stage6"
    identity_dir.mkdir()
    identity_report = identity_dir / "report.json"
    identity_envelope = identity_dir / "envelope.json"
    identity_report.write_text(
        json.dumps(
            {
                "codeHead": "a" * 40,
                "verification": _verification("a" * 40),
                "prInvariant": {
                    "totalRecords": 0,
                    "currentOpen": 0,
                    "closedOrMerged": 0,
                    "allManagedKeysObserved": True,
                    "liveOpenCount": 0,
                    "missing": [],
                    "unexpected": [],
                    "duplicates": [],
                    "headMismatches": [],
                    "managedPrProjectionDigest": "b" * 64,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    identity_report.chmod(0o600)
    identity_inventory = artifact_manifest(identity_dir, exclude_names={identity_envelope.name})
    write_detached_report_envelope(
        identity_report, identity_envelope, code_head="a" * 40, inventory=identity_inventory
    )
    identity_counts = build_managed_counts_evidence(
        runtime, identity_report, identity_envelope, code_head="a" * 40
    )
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=identity_counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )

    def write_health(timestamp: str, exit_code: object = 0) -> None:
        state["workers"] = {
            worker: {
                "lastSuccessAt": timestamp,
                "queueImportSuccessAt": timestamp,
                "lastExitCode": exit_code,
            }
            for worker in ("fast", "slow", "queue-importer")
        }
        (runtime / "state" / "runtime-health.json").write_text(json.dumps(state), encoding="utf-8")

    write_health(iso_z(utc_now() - timedelta(minutes=3)))
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )
    write_health(iso_z(utc_now() + timedelta(minutes=1)))
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )
    write_health(datetime.now().isoformat())
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )
    write_health(now, None)
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )
    assert verify_operational_authorization(runtime, now=utc_now() + timedelta(days=365))
    authorization_path(runtime).unlink()
    assert (
        check(
            runtime,
            home=home,
            launchctl_runner=launchctl,
            managed_counts_evidence=counts,
            automation_snapshot={**automation_unsigned, **auth},
        )["ok"]
        is False
    )


def test_private_authorization_commit_point_survives_directory_fsync_failure(tmp_path, monkeypatch):
    target = tmp_path / "state" / "authorization.json"
    original_fsync = operational_auth_module.os.fsync
    calls = 0

    def fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(operational_auth_module.os, "fsync", fsync)
    operational_auth_module._write_private_commit_point(target, {"state": "ACTIVE"})
    assert json.loads(target.read_text()) == {"state": "ACTIVE"}
    assert target.stat().st_mode & 0o777 == 0o600
    assert not list(target.parent.glob(".*.tmp"))


def test_stage7_acceptance_and_contracts_bind_to_one_release(tmp_path):
    runtime = _runtime(tmp_path)
    acceptance = check(runtime, home=tmp_path / "home", strict=False)
    assert acceptance["ok"] is True
    assert acceptance["release"]["releaseId"] == "stage7-test"
    contracts = build_contracts(runtime)
    assert contracts["schema"] == "oss-pr-radar.automation-command-contracts.v2"
    assert contracts["release"]["releaseId"] == "stage7-test"
    order = contracts["cutoverOrder"]
    assert len(order) == len(set(order))
    assert order.index("automationActivation") < order.index("automationSnapshot")
    assert order.index("activate") < order.index("managedCountsEvidence")
    assert order.index("managedCountsEvidence") < order.index("issueWorkerStagingAuthorization")
    assert order.index("issueWorkerStagingAuthorization") < order.index("stageWorkerConfigs")
    assert order.index("stageWorkerConfigs") < order.index("automationSnapshot")
    assert order.index("managedCountsEvidence") < order.index("strictPreflight")
    assert order.index("strictPreflight") < order.index("activateWorkers")
    assert order.index("activateWorkers") < order.index("strictFinalAcceptance")
    for section_name in ("stage6", "stage7"):
        section = contracts[section_name]
        for name, spec in section.items():
            for dependency in spec.get("requires", []):
                assert dependency in order
                assert order.index(dependency) < order.index(name)
    assert "snapshotManagedPrStates" not in contracts["stage6"]
    assert contracts["stage7"]["automationActivation"]["requires"] == ["stageWorkerConfigs"]
    assert contracts["stage7"]["strictFinalAcceptance"]["requires"] == ["activateWorkers"]
    plan = contracts["cutoverPlan"]
    assert [item["id"] for item in plan] == order
    assert len({item["contractRef"] for item in plan}) == len(plan)
    for index, item in enumerate(plan):
        assert item["requires"] == order[:index]
        assert ("command" in item) ^ ("action" in item)
        section_name, contract_name = (
            item["contractRef"].split(".", 1)
            if "." in item["contractRef"]
            else (None, item["contractRef"])
        )
        implementation = (
            contracts["deployment"]
            if section_name is None
            else contracts[section_name][contract_name]
        )
        assert item.get("command", implementation.get("command")) == implementation.get("command")
        assert item.get("action", implementation.get("action")) == implementation.get("action")
    assert "--live-states" not in contracts["stage7"]["prepare"]["command"]
    install_command = contracts["stage7"]["stageWorkerConfigs"]["command"]
    assert install_command[1].endswith("/scripts/install_local_publication_workers.py")
    assert install_command[-3:] == ["--runtime-root", str(runtime.resolve()), "--stage"]
    staging_command = contracts["stage7"]["issueWorkerStagingAuthorization"]["command"]
    assert "worker-staging-authorization" in staging_command
    assert staging_command[-2:] == ["--managed-counts-evidence", "<managed-counts-evidence>"]
    assert "--automation-snapshot" not in staging_command
    activate_command = contracts["stage7"]["activateWorkers"]["command"]
    assert activate_command[-3:] == ["--runtime-root", str(runtime.resolve()), "--activate"]
    assert contracts["heartbeat"]["releaseCommand"][1].endswith("/scripts/controller_cycle.py")
    assert contracts["heartbeat"]["kind"] == "heartbeat"
    assert contracts["dailyWarRoom"]["kind"] == "heartbeat"
    assert contracts["heartbeat"]["targetThreadId"] == ("019f71c3-4f26-7030-b126-25f8cfbac4c4")
    assert contracts["dailyWarRoom"]["targetThreadId"] == ("01a03bf2-e310-7f63-8db6-a9ec0a39f4aa")
    assert contracts["dailyWarRoom"]["targetThreadId"] != contracts["heartbeat"]["targetThreadId"]
    assert contracts["dailyWarRoom"]["rrule"] == ("FREQ=DAILY;BYHOUR=9;BYMINUTE=0;BYSECOND=0")
    assert {
        "model",
        "reasoningEffort",
        "executionEnvironment",
        "cwds",
        "target",
    }.isdisjoint(contracts["dailyWarRoom"])
    assert contracts["dailyWarRoom"]["releaseCommand"][1].endswith(
        "/scripts/daily_war_room_cycle.py"
    )
    assert contracts["dailyWarRoom"]["releaseCommand"][-1] == "--send"
    heartbeat_prompt = canonical_prompt(
        "heartbeat", runtime, contracts["heartbeat"]["releaseCommand"]
    )
    assert (
        "desktopHandoff.prompt unchanged exactly once to desktopHandoff.threadId"
        in heartbeat_prompt
    )
    assert heartbeat_prompt.count("desktopHandoff.prompt") == 1
    assert "运行正常；当前没有需要你处理的事情。" in heartbeat_prompt
    assert "已开始或继续处理；你无需操作。" in heartbeat_prompt
    assert "never show JSON, paths, logs, prompts, or internal fields" in heartbeat_prompt
    assert "even when command exit is nonzero or final JSON ok=false" in heartbeat_prompt
    assert "execute the identical release-command once more" in heartbeat_prompt
    assert "safely joins the already-running controller" in heartbeat_prompt
    assert heartbeat_prompt.index("if it contains desktopHandoff") < heartbeat_prompt.index(
        "if the command fails or final JSON ok=false"
    )
    assert "when there is no desktopHandoff" in heartbeat_prompt
    daily_prompt = canonical_prompt(
        "dailyWarRoom", runtime, contracts["dailyWarRoom"]["releaseCommand"]
    )
    assert "检查已完成；当前没有需要你处理的事情。" in daily_prompt
    assert "--send" in daily_prompt
    assert daily_prompt.index("if the command fails or final JSON ok=false") < daily_prompt.index(
        "only when it succeeds"
    )
    public = shareable_acceptance_report(acceptance)
    public_text = json.dumps(public, ensure_ascii=False)
    assert "/private/" not in public_text
    assert str(tmp_path) not in public_text
    (runtime / "scripts").mkdir()
    (runtime / "scripts" / "local_dispatch_bridge.py").write_text("poison\n", encoding="utf-8")
    assert check(runtime, home=tmp_path / "home", strict=False)["ok"] is True


def test_automation_commands_follow_current_release_pointer(tmp_path):
    runtime = _runtime(tmp_path)
    contracts = build_contracts(runtime)
    stable = str(runtime.resolve() / "current-release")
    active = str((runtime / "current-release").resolve())

    heartbeat = contracts["heartbeat"]
    daily = contracts["dailyWarRoom"]
    assert heartbeat["releaseCommand"][1] == f"{stable}/scripts/controller_cycle.py"
    assert heartbeat["releaseCommand"][-1] == stable
    assert daily["releaseCommand"][1] == f"{stable}/scripts/daily_war_room_cycle.py"
    assert active not in heartbeat["releaseCommand"][1]
    assert active not in daily["releaseCommand"][1]
    for spec in (heartbeat, daily):
        assert spec["releaseBinding"] == {
            "kind": "active-release-pointer",
            "path": stable,
            "releaseId": contracts["release"]["releaseId"],
            "manifestSha256": contracts["release"]["manifestSha256"],
        }


def test_stage7_prepare_cli_rejects_live_states(tmp_path):
    script = Path(__file__).parents[1] / "scripts" / "stage7_cutover.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "prepare",
            "--runtime-root",
            str(tmp_path / "runtime"),
            "--source",
            str(tmp_path / "source.sqlite3"),
            "--quiesce-token",
            "writer-stopped",
            "--live-states",
            str(tmp_path / "live-states.json"),
        ],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "unrecognized arguments: --live-states" in result.stderr


@pytest.mark.parametrize(
    "script_name",
    [
        "controller_cycle.py",
        "daily_war_room_cycle.py",
        "slow_publication_worker.py",
        "queue_importer.py",
    ],
)
def test_deployed_action_clis_have_no_auth_bypass_option(script_name):
    script = Path(__file__).parents[1] / "scripts" / script_name
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    help_text = result.stdout + result.stderr
    assert "--skip-auth" not in help_text
    assert "--allow-unreleased-code" not in help_text


def test_daily_cycle_does_not_resend_unchanged_actionable_item(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "daily-stage7-key" * 4)
    ledger_path = tmp_path / "runtime" / "state" / "radar_ledger.sqlite3"
    ledger_path.parent.mkdir(parents=True)
    ledger = ManagedLedger(ledger_path, ensure_schema=True)
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="DECISION_REQUIRED",
        source="test",
        provenance={"title": "候选一"},
        metadata={"title": "候选一", "preTaskGate": {"allowed": True}},
    )
    ledger.bind_task(
        task_id="task-1", opportunity_key="owner/repo#1", thread_id="t1", worktree_path=None
    )
    ledger.authorize_task_creation(
        task_id="task-1",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url="https://github.com/owner/repo/issues/1",
        intent_id="task-1",
    )
    runtime = ledger_path.parents[1]
    first = run_daily_cycle(runtime)
    assert first["ok"] is True
    assert first["newActionableCount"] == 1
    sent = run_daily_cycle(runtime, send=True, sender=lambda _event: "message-1")
    assert sent["ok"] is True
    assert sent["sent"] == 1

    def duplicate_sender(_event):
        raise AssertionError("an identical replay must not resend a delivered event")

    replayed = run_daily_cycle(runtime, send=True, sender=duplicate_sender)
    assert replayed["ok"] is True
    assert replayed["newActionableCount"] == 0
    assert replayed["sent"] == 0
    assert replayed["failed"] == 0
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#2",
        owner="owner",
        repo="repo",
        issue_number=2,
        issue_url="https://github.com/owner/repo/issues/2",
        state="DECISION_REQUIRED",
        source="test",
        provenance={"title": "未授权"},
        metadata={"title": "未授权", "preTaskGate": {"allowed": False}},
    )
    rerun = run_daily_cycle(runtime)
    assert rerun["ok"] is True
    assert rerun["newActionableCount"] == 0
    assert rerun["artifactDigest"] != sent["artifactDigest"]

    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="DECISION_REQUIRED",
        source="test",
        provenance={"title": "候选一更新"},
        metadata={"title": "候选一更新", "preTaskGate": {"allowed": True}},
    )

    def failing_sender(_event):
        raise RuntimeError("send failed")

    failed = run_daily_cycle(runtime, send=True, sender=failing_sender)
    assert failed["ok"] is False
    assert failed["failed"] == 1
