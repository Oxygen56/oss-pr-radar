from __future__ import annotations

import gzip
import importlib.util
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from test_ledger import legal_publication_probe
from test_managed_round7_security import legacy_v7_snapshot, write_snapshot

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_lifecycle import MANAGED_SCHEMA_VERSION, ManagedLedger, schema_status
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot

pytestmark = pytest.mark.usefixtures("current_signing_key")

SCRIPT = Path(__file__).parents[1] / "scripts" / "state_branch.py"
SPEC = importlib.util.spec_from_file_location("state_branch", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_state_writer_children_inherit_the_outbound_lock_descriptor(monkeypatch, tmp_path):
    captured = {}

    def fake_run(*_args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    MODULE._OUTBOUND_LOCK_FD = 41
    try:
        MODULE.git("status", cwd=tmp_path)
    finally:
        MODULE._OUTBOUND_LOCK_FD = None

    assert captured["pass_fds"] == (41,)


def initialized_repo(tmp_path):
    origin = tmp_path / "origin.git"
    root = tmp_path / "root"
    git("init", "--bare", str(origin), cwd=tmp_path)
    git("init", str(root), cwd=tmp_path)
    git("remote", "add", "origin", str(origin), cwd=root)
    (root / "state").mkdir()
    (root / "state" / "seen.json").write_text("{}\n", encoding="utf-8")
    return root, origin


def publish_raw_state(root: Path, branch: str, available: dict[str, Path]) -> None:
    manifest = MODULE.build_manifest(
        root,
        available,
        allow_legacy_managed_snapshot=True,
    )
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    index = root / ".git" / f"test-{branch}.index"
    env = {**os.environ, "GIT_INDEX_FILE": str(index)}
    subprocess.run(["git", "read-tree", "--empty"], cwd=root, check=True, env=env)
    for remote_name, source in available.items():
        blob = subprocess.run(
            ["git", "hash-object", "-w", str(source)],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo", "100644", blob, remote_name],
            cwd=root,
            check=True,
            env=env,
        )
    manifest_path = root / ".git" / f"{branch}.manifest"
    manifest_path.write_bytes(manifest_bytes)
    manifest_blob = subprocess.run(
        ["git", "hash-object", "-w", str(manifest_path)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        [
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            "100644",
            manifest_blob,
            MODULE.MANIFEST,
        ],
        cwd=root,
        check=True,
        env=env,
    )
    tree = subprocess.run(
        ["git", "write-tree"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()
    commit = subprocess.run(
        [
            "git",
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit-tree",
            tree,
            "-m",
            "legacy state",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "push", "--force", "origin", f"{commit}:refs/heads/{branch}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("operation", ["publish", "migrate"])
def test_state_branch_cli_blocks_writes_while_outbound_pause_is_active(
    monkeypatch, tmp_path, operation
):
    @contextmanager
    def blocked_guard(_root, _ledger):
        raise PermissionError("GITHUB_OUTBOUND_PAUSED")
        yield

    monkeypatch.setattr(MODULE, "outbound_effect_guard", blocked_guard)
    monkeypatch.setattr(
        MODULE,
        "publish",
        lambda *_args, **_kwargs: pytest.fail("paused state branch must not push"),
    )
    monkeypatch.setattr(
        MODULE,
        "migrate",
        lambda *_args, **_kwargs: pytest.fail("paused state migration must not push"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            "state_branch.py",
            operation,
            "--root",
            str(tmp_path),
        ],
    )

    with pytest.raises(PermissionError, match="GITHUB_OUTBOUND_PAUSED"):
        MODULE.main()


def test_publish_and_restore_verify_manifest(tmp_path):
    root, origin = initialized_repo(tmp_path)
    codex_outbox = root / "state" / "war_room_codex_outbox.json"
    codex_outbox.write_text(
        '{"schema": "oss-pr-radar.war-room-outbox.v1", "events": []}\n',
        encoding="utf-8",
    )
    MODULE.publish(root, "radar-state")
    restored = tmp_path / "restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    assert json.loads((restored / "state" / "seen.json").read_text()) == {}
    assert (
        json.loads((restored / "state" / "war_room_codex_outbox.json").read_text())["schema"]
        == "oss-pr-radar.war-room-outbox.v1"
    )
    assert (restored / "state" / "base_sha.txt").read_text().strip()


def test_controller_feedback_uses_an_independent_integrity_branch(tmp_path):
    root, origin = initialized_repo(tmp_path)
    feedback = root / "state" / "controller_terminal_feedback.json"
    feedback.write_text('{"a/b#1": {"status": "controller_terminal"}}\n', encoding="utf-8")
    decision_feedback = root / "state" / "controller_decision_feedback.json"
    decision_feedback.write_text(
        '{"schema": "oss-pr-radar.codex-decision-feedback.v1", "events": {}}\n',
        encoding="utf-8",
    )
    MODULE.publish(
        root,
        "radar-controller-feedback",
        files=MODULE.CONTROLLER_FEEDBACK_FILES,
        manifest_name=MODULE.CONTROLLER_FEEDBACK_MANIFEST,
        base_sha_path=MODULE.CONTROLLER_FEEDBACK_BASE_SHA,
        manifest_version=MODULE.CONTROLLER_FEEDBACK_MANIFEST_VERSION,
    )

    restored = tmp_path / "restored-feedback"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(
        restored,
        "radar-controller-feedback",
        files=MODULE.CONTROLLER_FEEDBACK_FILES,
        manifest_name=MODULE.CONTROLLER_FEEDBACK_MANIFEST,
        base_sha_path=MODULE.CONTROLLER_FEEDBACK_BASE_SHA,
        manifest_version=MODULE.CONTROLLER_FEEDBACK_MANIFEST_VERSION,
    )

    assert json.loads((restored / "state" / "controller_terminal_feedback.json").read_text()) == {
        "a/b#1": {"status": "controller_terminal"}
    }
    assert (
        json.loads((restored / "state" / "controller_decision_feedback.json").read_text())["schema"]
        == "oss-pr-radar.codex-decision-feedback.v1"
    )
    assert not (restored / "state" / "seen.json").exists()


def test_publish_fetches_existing_state_through_authenticated_root(tmp_path, monkeypatch):
    root, _origin = initialized_repo(tmp_path)
    MODULE.publish(root, "radar-state")
    MODULE.restore(root, "radar-state")
    (root / "state" / "seen.json").write_text('{"next": true}\n', encoding="utf-8")

    original_git = MODULE.git

    def guarded_git(*args, cwd=None, check=True, env=None):
        if args[:2] == ("fetch", "origin") and cwd != root:
            raise AssertionError("remote fetch escaped the authenticated checkout")
        return original_git(*args, cwd=cwd, check=check, env=env)

    monkeypatch.setattr(MODULE, "git", guarded_git)
    MODULE.publish(root, "radar-state")
    monkeypatch.setattr(MODULE, "git", original_git)

    restored = tmp_path / "restored-authenticated"
    git("clone", str(root.parent / "origin.git"), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    assert json.loads((restored / "state" / "seen.json").read_text()) == {"next": True}


def test_restore_rejects_file_changed_without_manifest_update(tmp_path):
    root, origin = initialized_repo(tmp_path)
    MODULE.publish(root, "radar-state")
    attacker = tmp_path / "attacker"
    git("clone", "--branch", "radar-state", str(origin), str(attacker), cwd=tmp_path)
    (attacker / "seen.json").write_text('{"tampered": true}\n', encoding="utf-8")
    git("add", "seen.json", cwd=attacker)
    git(
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "tamper",
        cwd=attacker,
    )
    git("push", "origin", "radar-state", cwd=attacker)
    restored = tmp_path / "restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        MODULE.restore(restored, "radar-state")


def test_restore_uses_private_ref_when_shared_fetch_head_is_cleared(tmp_path, monkeypatch):
    root, origin = initialized_repo(tmp_path)
    MODULE.publish(root, "radar-state")
    restored = tmp_path / "restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    original_git = MODULE.git

    def clearing_git(*args, cwd=None, check=True, env=None):
        result = original_git(*args, cwd=cwd, check=check, env=env)
        if args and args[0] == "fetch" and cwd is not None:
            (cwd / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
        return result

    monkeypatch.setattr(MODULE, "git", clearing_git)
    MODULE.restore(restored, "radar-state")

    assert json.loads((restored / "state" / "seen.json").read_text()) == {}
    assert subprocess.run(
        ["git", "rev-parse", MODULE.isolated_state_ref("radar-state")],
        cwd=restored,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_concurrent_restores_use_independent_explicit_refs(tmp_path):
    root, origin = initialized_repo(tmp_path)
    MODULE.publish(root, "radar-state")
    restored_roots = []
    for index in range(2):
        restored = tmp_path / f"restored-{index}"
        git("clone", str(origin), str(restored), cwd=tmp_path)
        restored_roots.append(restored)

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda path: MODULE.restore(path, "radar-state"), restored_roots))

    for restored in restored_roots:
        assert json.loads((restored / "state" / "seen.json").read_text()) == {}
        assert not (restored / ".git" / "FETCH_HEAD").exists()


def test_migrate_adds_manifest_without_rewriting_legacy_state(tmp_path):
    root, origin = initialized_repo(tmp_path)
    git("checkout", "--orphan", "radar-state", cwd=root)
    (root / "seen.json").write_text('{"legacy": true}\n', encoding="utf-8")
    git("add", "seen.json", cwd=root)
    git(
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "legacy state",
        cwd=root,
    )
    git("push", "origin", "radar-state", cwd=root)

    MODULE.migrate(root, "radar-state")
    restored = tmp_path / "restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    assert json.loads((restored / "state" / "seen.json").read_text()) == {"legacy": True}


def test_migrate_repairs_manifest_after_legacy_writer_updates_state(tmp_path):
    root, origin = initialized_repo(tmp_path)
    MODULE.publish(root, "radar-state")
    legacy_writer = tmp_path / "legacy-writer"
    git(
        "clone",
        "--branch",
        "radar-state",
        str(origin),
        str(legacy_writer),
        cwd=tmp_path,
    )
    (legacy_writer / "seen.json").write_text(
        '{"updated_by_legacy_writer": true}\n', encoding="utf-8"
    )
    git("add", "seen.json", cwd=legacy_writer)
    git(
        "-c",
        "user.name=test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "legacy writer update",
        cwd=legacy_writer,
    )
    git("push", "origin", "radar-state", cwd=legacy_writer)

    MODULE.migrate(root, "radar-state")
    restored = tmp_path / "restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    assert json.loads((restored / "state" / "seen.json").read_text()) == {
        "updated_by_legacy_writer": True
    }


def test_managed_snapshot_persists_lifecycle_cap_and_idempotency_across_workspaces(tmp_path):
    root, origin = initialized_repo(tmp_path)
    database = root / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(root, database)
    adapter.record_scan_report(
        {
            "run_id": "run-1",
            "now": "2026-08-19T00:00:00Z",
            "candidate_details": [{"repo": "owner/repo", "num": 1}],
        }
    )
    adapter.ledger.bind_task(
        task_id="task-1",
        opportunity_key="owner/repo#1",
        thread_id="codex-thread-private",
        worktree_path="/Users/oxygen/private-worktree",
    )
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
    reservation = adapter.reserve_publication(
        request_id="run1-reservation", repo="other/repo", opportunity_key="other/repo#1"
    )
    assert reservation["allowed"] is True
    snapshot = root / "state" / "managed_lifecycle.snapshot.json.gz"
    export_snapshot(database, snapshot)
    compressed = snapshot.read_bytes()
    public_text = gzip.decompress(compressed).decode("utf-8")
    assert '\\"/' not in public_text
    assert "/tmp/" not in public_text
    assert "codex-thread-private" not in public_text
    assert "threadFingerprint" in public_text
    assert "worktree" not in public_text.casefold()
    assert "ghp_" not in public_text
    assert import_snapshot(database, snapshot)["ok"] is True

    MODULE.publish(root, "radar-state")
    restored = tmp_path / "run-2"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    restored_database = restored / "state" / "radar_ledger.sqlite3"
    RadarLedger(restored_database)
    import_snapshot(restored_database, restored / "state" / "managed_lifecycle.snapshot.json.gz")
    restored_ledger = ManagedLedger(restored_database)

    assert restored_ledger.open_unanswered_auto_pr_count("owner/repo") == 5
    assert restored_ledger.publication_gate(repo="owner/repo")["allowed"] is False
    with restored_ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT state FROM managed_publication_reservations WHERE request_id='run1-reservation'"
            ).fetchone()[0]
            == "ACTIVE"
        )
    with restored_ledger._connection() as connection:
        event_count = connection.execute(
            "SELECT COUNT(*) FROM managed_lifecycle_events"
        ).fetchone()[0]
    adapter_restored = ManagedAdapter(restored, restored_database)
    adapter_restored.record_scan_report(
        {
            "run_id": "run-1",
            "now": "2026-08-19T00:00:00Z",
            "candidate_details": [{"repo": "owner/repo", "num": 1}],
        }
    )
    with restored_ledger._connection() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM managed_lifecycle_events").fetchone()[0]
            == event_count
        )
    assert set(restored_ledger.projection()["buckets"]) == {
        "DECISION_REQUIRED",
        "SYSTEM_PROCESSING",
        "WAITING_EXTERNAL",
        "PORTFOLIO_READY",
    }


def test_state_restore_accepts_exact_legacy_v7_snapshot_but_publish_rejects_it(tmp_path):
    root, origin = initialized_repo(tmp_path)
    database = root / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(root, database)
    adapter.record_scan_report(
        {
            "run_id": "legacy-v7",
            "now": "2026-08-19T00:00:00Z",
            "candidate_details": [{"repo": "owner/repo", "num": 1}],
        }
    )
    legacy = legacy_v7_snapshot(database)
    snapshot = root / "state" / "managed_lifecycle.snapshot.json.gz"
    write_snapshot(snapshot, legacy)
    with pytest.raises(RuntimeError, match="legacy managed snapshot"):
        MODULE.publish(root, "radar-state")

    publish_raw_state(root, "radar-state", {"managed_lifecycle.snapshot.json.gz": snapshot})
    restored = tmp_path / "legacy-restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    restored_database = restored / "state" / "radar_ledger.sqlite3"
    RadarLedger(restored_database)
    import_snapshot(restored_database, restored / "state" / "managed_lifecycle.snapshot.json.gz")
    assert schema_status(restored_database)["current"] == MANAGED_SCHEMA_VERSION


def test_managed_snapshot_restore_is_atomic_on_corruption(tmp_path):
    root, _origin = initialized_repo(tmp_path)
    database = root / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(root, database)
    adapter.record_scan_report(
        {
            "run_id": "safe",
            "now": "2026-08-19T00:00:00Z",
            "candidate_details": [{"repo": "owner/repo", "num": 1}],
        }
    )
    snapshot = root / "state" / "managed_lifecycle.snapshot.json.gz"
    export_snapshot(database, snapshot)
    snapshot.write_bytes(snapshot.read_bytes()[:-1] + b"x")
    with pytest.raises(ValueError):
        import_snapshot(database, snapshot)
    with ManagedLedger(database)._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_opportunities").fetchone()[0] == 1


def test_script_level_fix_ready_reply_snapshot_replays_into_fresh_workspace(tmp_path):
    root, origin = initialized_repo(tmp_path)
    database = root / "state" / "radar_ledger.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(root, database)
    adapter.record_scan_report(
        {
            "run_id": "script-run-1",
            "now": "2026-08-19T00:00:00Z",
            "candidate_details": [{"repo": "owner/repo", "num": 1}],
        }
    )
    adapter.ledger.bind_task(
        task_id="task-script-1",
        opportunity_key="owner/repo#1",
        thread_id="task-script-1",
        worktree_path="/private/worktree/should-not-export",
        state="REPRODUCTION_REQUIRED",
    )
    _worktree, _base_sha, _head_sha, _branch, probe_receipt, _digest, _evidence = (
        legal_publication_probe(
            tmp_path,
            owner_repo="owner/repo",
            issue_number=1,
            task_id="task-script-1",
        )
    )
    adapter.ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url="https://github.com/owner/repo/issues/1",
        state="SYSTEM_PROCESSING",
        source="test-legal-fixture",
        provenance={"fixture": True},
        metadata={"selectedBaseSha": probe_receipt["baseSha"], "codePaths": ["runtime.py"]},
    )
    adapter.ledger.bind_task(
        task_id="task-script-1",
        opportunity_key="owner/repo#1",
        thread_id="task-script-1",
        worktree_path="/private/worktree/should-not-export",
        state="REPRODUCTION_REQUIRED",
        provenance={
            "codePaths": ["runtime.py"],
            "selectedBaseSha": probe_receipt["baseSha"],
            "headSha": probe_receipt["headSha"],
            "commitSha": probe_receipt["commitSha"],
            "resultDigest": probe_receipt["resultDigest"],
        },
    )
    adapter.ledger.transition_task_to_implementation(
        task_id="task-script-1",
        receipt_digest=probe_receipt["receiptDigest"],
        receipt=probe_receipt,
    )
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
    adapter.ledger.record_result(
        task_id="task-script-1",
        result_digest="result-script-1",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#1",
        head_sha="head-1",
        commit_sha="commit-1",
        validation={"passed": True, "evidence": [{"checkId": "pytest.unit"}]},
        prior_head_sha="old-head",
        new_head_sha="head-1",
        provenance={"eventKey": "result-event-script-1"},
    )
    adapter.ledger.record_ci_run(
        ci_key="ci-script-1", pr_key="owner/repo#1", head_sha="head-1", status="PASSED"
    )
    adapter.ledger.record_maintainer_event(
        event_key="maintainer-script-1",
        pr_key="owner/repo#1",
        event_type="COMMENT",
        actor_login="owner",
        actor_type="User",
        author_association="OWNER",
        payload={"targetPrKey": "owner/repo#1", "explicit_mechanical_request": True},
    )
    queued = adapter.ledger.queue_public_reply(
        pr_key="owner/repo#1",
        maintainer_event_key="maintainer-script-1",
        result_digest="result-script-1",
        proposed_body="Implemented the requested mechanical change; validation passed.",
    )
    assert queued["mode"] == "AUTO_REPLY_ALLOWED"
    assert queued["queued"] is True

    snapshot = root / "state" / "managed_lifecycle.snapshot.json.gz"
    python = sys.executable
    export_script = Path(__file__).parents[1] / "scripts" / "export_managed_snapshot.py"
    process_script = Path(__file__).parents[1] / "scripts" / "process_managed_replies.py"
    import_script = Path(__file__).parents[1] / "scripts" / "import_managed_snapshot.py"
    projection_script = Path(__file__).parents[1] / "scripts" / "export_managed_projection.py"
    subprocess.run(
        [python, str(export_script), "--ledger", str(database), "--output", str(snapshot)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    public_text = gzip.decompress(snapshot.read_bytes()).decode("utf-8")
    assert "Implemented the requested mechanical change" not in public_text
    assert "private-thread" not in public_text
    assert "/private/worktree" not in public_text
    MODULE.publish(root, "radar-state")

    run2 = tmp_path / "run-2-script"
    git("clone", str(origin), str(run2), cwd=tmp_path)
    MODULE.restore(run2, "radar-state")
    run2_db = run2 / "state" / "radar_ledger.sqlite3"
    RadarLedger(run2_db)
    import_result = subprocess.run(
        [
            python,
            str(import_script),
            "--ledger",
            str(run2_db),
            "--snapshot",
            str(run2 / "state" / "managed_lifecycle.snapshot.json.gz"),
        ],
        cwd=run2,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            python,
            str(import_script),
            "--ledger",
            str(run2_db),
            "--snapshot",
            str(run2 / "state" / "managed_lifecycle.snapshot.json.gz"),
        ],
        cwd=run2,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [python, str(process_script), "--ledger", str(run2_db)],
        cwd=run2,
        check=True,
        capture_output=True,
        text=True,
    )
    projection = json.loads(
        subprocess.run(
            [python, str(projection_script), "--db-copy", str(run2_db)],
            cwd=run2,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    assert any(
        item["taskId"] == "task-script-1" for item in projection["buckets"]["PORTFOLIO_READY"]
    )
    with ManagedLedger(run2_db)._connection() as connection:
        reply = connection.execute(
            "SELECT * FROM managed_public_replies WHERE reply_key=?",
            ("owner/repo#1|maintainer-script-1|result-script-1",),
        ).fetchone()
        delivery = connection.execute(
            "SELECT state FROM managed_reply_deliveries WHERE reply_key=?",
            ("owner/repo#1|maintainer-script-1|result-script-1",),
        ).fetchone()
        assert reply["mode"] == "AUTO_REPLY_ALLOWED"
        assert reply["body_digest"] == queued["body_digest"]
        assert reply["template_id"] == queued["template_id"]
        assert delivery["state"] == "QUEUED"
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_reply_deliveries WHERE reply_key=?",
                (reply["reply_key"],),
            ).fetchone()[0]
            == 1
        )
    assert json.loads(import_result.stdout)["ok"] is True
