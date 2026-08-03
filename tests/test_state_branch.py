from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "state_branch.py"
SPEC = importlib.util.spec_from_file_location("state_branch", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def initialized_repo(tmp_path):
    origin = tmp_path / "origin.git"
    root = tmp_path / "root"
    git("init", "--bare", str(origin), cwd=tmp_path)
    git("init", str(root), cwd=tmp_path)
    git("remote", "add", "origin", str(origin), cwd=root)
    (root / "state").mkdir()
    (root / "state" / "seen.json").write_text("{}\n", encoding="utf-8")
    return root, origin


def test_publish_and_restore_verify_manifest(tmp_path):
    root, origin = initialized_repo(tmp_path)
    MODULE.publish(root, "radar-state")
    restored = tmp_path / "restored"
    git("clone", str(origin), str(restored), cwd=tmp_path)
    MODULE.restore(restored, "radar-state")
    assert json.loads((restored / "state" / "seen.json").read_text()) == {}
    assert (restored / "state" / "base_sha.txt").read_text().strip()


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
