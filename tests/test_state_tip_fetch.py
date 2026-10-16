from __future__ import annotations

import hashlib
import json
import os
import subprocess

import pytest
import test_local_dispatch_bridge as native_fixture
import test_state_branch as state_fixture

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_adapter import ManagedAdapter
from oss_pr_radar.managed_snapshot import export_snapshot, import_snapshot

pytestmark = pytest.mark.usefixtures("current_signing_key")
state_branch = state_fixture.MODULE
bridge = native_fixture.MODULE


def _git(root, *args, check=True):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=check)


def _state_history(tmp_path):
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(tmp_path, "init", "--bare", str(origin))
    _git(seed, "init")
    _git(seed, "branch", "-M", "radar-state")
    _git(seed, "config", "user.name", "Radar Test")
    _git(seed, "config", "user.email", "radar@example.test")
    _git(seed, "remote", "add", "origin", origin.as_uri())
    queue = native_fixture._signed_dispatch_queue(intent_id="tip-only", key="owner/repo#1")
    outbox = native_fixture._codex_decision_outbox()
    (seed / "dispatch_queue.json").write_text(json.dumps(queue))
    (seed / "war_room_codex_outbox.json").write_text(json.dumps(outbox))
    (seed / "seen.json").write_text('{"current":true}\n')
    database = tmp_path / "snapshot.sqlite3"
    RadarLedger(database)
    adapter = ManagedAdapter(seed, database)
    adapter.ledger.upsert_pr(
        pr_key="owner/repo#1",
        owner="owner",
        repo="repo",
        number=1,
        head_sha="1" * 40,
        pr_url="https://github.com/owner/repo/pull/1",
        state="OPEN",
        auto_created=True,
    )
    snapshot = seed / "managed_lifecycle.snapshot.json.gz"
    export_snapshot(database, snapshot)
    files = {
        name: seed / name
        for name in (
            "dispatch_queue.json",
            "war_room_codex_outbox.json",
            "seen.json",
            snapshot.name,
        )
    }
    manifest = state_branch.build_manifest(seed, files)
    (seed / state_branch.MANIFEST).write_text(json.dumps(manifest))
    _git(seed, "add", ".")
    _git(seed, "commit", "-m", "current authenticated state")
    retired = seed / "retired-run-payload.bin"
    retired.write_bytes(os.urandom(1024 * 1024))
    old_blob = _git(seed, "hash-object", str(retired)).stdout.strip()
    _git(seed, "add", retired.name)
    _git(seed, "commit", "-m", "retired large run")
    _git(seed, "tag", "retired-state-tag")
    retired.unlink()
    _git(seed, "add", "-u")
    _git(seed, "commit", "-m", "remove retired run from current tree")
    tip = _git(seed, "rev-parse", "HEAD").stdout.strip()
    _git(seed, "push", "origin", "radar-state", "--tags")
    return origin, seed, tip, old_blob, queue, outbox, snapshot.read_bytes()


def _empty_client(tmp_path, origin):
    root = tmp_path / "client"
    root.mkdir()
    _git(root, "init")
    _git(root, "branch", "-M", "main")
    _git(root, "config", "user.name", "Radar Test")
    _git(root, "config", "user.email", "radar@example.test")
    (root / "source.py").write_text("VALUE = 1\n")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "independent program checkout")
    _git(root, "tag", "local-source-tag")
    _git(root, "remote", "add", "origin", origin.as_uri())
    (root / ".git/FETCH_HEAD").write_bytes(b"existing-fetch-head-must-survive\n")
    return root


@pytest.mark.parametrize("operation", ["queue", "outbox", "state-ref"])
def test_state_consumers_fetch_only_current_tip_and_keep_checkout_identity(
    monkeypatch, tmp_path, operation
):
    origin, _seed, tip, old_blob, queue, outbox, snapshot = _state_history(tmp_path)
    root = _empty_client(tmp_path, origin)
    before_head = _git(root, "rev-parse", "HEAD").stdout
    before_fetch_head = (root / ".git/FETCH_HEAD").read_bytes()
    before_tags = _git(root, "tag", "--list").stdout
    monkeypatch.setattr(bridge, "ROOT", root)
    (tmp_path / "private-runtime").mkdir(mode=0o700)
    monkeypatch.setattr(bridge, "STATE", tmp_path / "private-runtime/state")
    if operation == "queue":
        assert bridge.fetch_cloud_queue() == queue
        ref = "refs/radar/import/radar-state"
    elif operation == "outbox":
        assert bridge.fetch_cloud_codex_outbox() == outbox
        ref = "refs/radar/import/radar-state"
    else:
        ref, result = state_branch.fetch_state_ref(root, "radar-state")
        assert result.returncode == 0
    assert _git(root, "rev-parse", ref).stdout.strip() == tip
    observed = subprocess.check_output(
        ["git", "show", f"{ref}:managed_lifecycle.snapshot.json.gz"], cwd=root
    )
    assert hashlib.sha256(observed).digest() == hashlib.sha256(snapshot).digest()
    state_branch._validate_state_file("managed_lifecycle.snapshot.json.gz", observed)
    assert _git(root, "--no-lazy-fetch", "cat-file", "-e", old_blob, check=False).returncode != 0
    assert _git(root, "rev-list", "--count", ref).stdout.strip() == "1"
    assert _git(root, "rev-parse", "HEAD").stdout == before_head
    assert (root / ".git/FETCH_HEAD").read_bytes() == before_fetch_head
    assert _git(root, "tag", "--list").stdout == before_tags


def test_tip_only_restore_authenticates_snapshot_and_publishes_child_of_exact_tip(tmp_path):
    origin, _seed, tip, old_blob, _queue, _outbox, snapshot = _state_history(tmp_path)
    root = _empty_client(tmp_path, origin)
    state_branch.restore(root, "radar-state")
    assert (root / state_branch.BASE_SHA).read_text() == tip
    restored_snapshot = root / state_branch.FILES["managed_lifecycle.snapshot.json.gz"]
    assert restored_snapshot.read_bytes() == snapshot
    database = root / "state/new-ledger.sqlite3"
    RadarLedger(database)
    assert import_snapshot(database, restored_snapshot)["ok"] is True
    assert ManagedAdapter(root, database).ledger.open_unanswered_auto_pr_count("owner/repo") == 1
    assert _git(root, "--no-lazy-fetch", "cat-file", "-e", old_blob, check=False).returncode != 0
    head_before = _git(root, "rev-parse", "HEAD").stdout
    fetch_before = (root / ".git/FETCH_HEAD").read_bytes()
    (root / "state/seen.json").write_text('{"new":true}\n')
    state_branch.publish(root, "radar-state")
    # This is an independent bare-remote readback, not a production post-push GET.
    child = _git(origin, "rev-parse", "refs/heads/radar-state").stdout.strip()
    assert child != tip
    assert _git(origin, "show", "-s", "--format=%P", child).stdout.strip() == tip
    assert json.loads(_git(origin, "show", f"{child}:seen.json").stdout) == {"new": True}
    assert _git(root, "rev-parse", "HEAD").stdout == head_before
    assert (root / ".git/FETCH_HEAD").read_bytes() == fetch_before


@pytest.mark.parametrize("race", ["stale-base", "push-lease"])
def test_tip_only_state_publish_still_rejects_remote_changes(monkeypatch, tmp_path, race):
    origin, seed, tip, _old_blob, _queue, _outbox, _snapshot = _state_history(tmp_path)
    root = _empty_client(tmp_path, origin)
    state_branch.restore(root, "radar-state")

    def advance_remote():
        (seed / "seen.json").write_text('{"other-writer":true}\n')
        _git(seed, "add", "seen.json")
        _git(seed, "commit", "-m", "another real writer")
        _git(seed, "push", "origin", "radar-state")
        return _git(seed, "rev-parse", "HEAD").stdout.strip()

    if race == "stale-base":
        actual = advance_remote()
        with pytest.raises(RuntimeError, match="state branch changed since restore"):
            state_branch.publish(root, "radar-state")
    else:
        original_git = state_branch.git
        raced = []

        def concurrent_git(*args, **kwargs):
            if args[0] == "push":
                assert args[1] == f"--force-with-lease=refs/heads/radar-state:{tip}"
                raced.append(advance_remote())
            return original_git(*args, **kwargs)

        monkeypatch.setattr(state_branch, "git", concurrent_git)
        with pytest.raises(subprocess.CalledProcessError) as failure:
            state_branch.publish(root, "radar-state")
        assert "stale info" in failure.value.stderr
        actual = raced[0]
    assert _git(origin, "rev-parse", "refs/heads/radar-state").stdout.strip() == actual
