from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.stage7_cutover import prepare, restore_git_preservation

SCRIPT = Path(__file__).parents[1] / "scripts" / "deploy_local_runtime.py"
SPEC = importlib.util.spec_from_file_location("deploy_local_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def git(path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def make_repositories(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    git(source, "init")
    git(target, "init")
    (source / "scripts").mkdir()
    (source / "scripts" / "runner.py").write_text("VERSION = 2\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source",
    )
    return source, target


def test_deploy_creates_immutable_release_and_preserves_runtime_state(tmp_path):
    source, target = make_repositories(tmp_path)
    (target / "state").mkdir()
    ledger = target / "state" / "radar_ledger.sqlite3"
    ledger.write_bytes(b"durable-ledger")
    (target / "user-note.txt").write_text("keep\n", encoding="utf-8")

    result = MODULE.deploy(source, target)

    assert result["ok"] is True
    release = Path(result["releasePath"])
    assert release.is_dir()
    assert (release / "scripts" / "runner.py").read_text(encoding="utf-8") == "VERSION = 2\n"
    assert ledger.read_bytes() == b"durable-ledger"
    assert (target / "current-release").resolve() == release
    manifest = json.loads((release / MODULE.MANIFEST).read_text(encoding="utf-8"))
    assert manifest["commit"] == result["commit"]
    assert manifest["manifestSha256"] == result["manifestSha256"]
    assert MODULE.verify_release(release)["releaseId"] == result["releaseId"]


def test_deploy_ignores_runtime_artifacts_and_preserves_private_exclude(tmp_path):
    source, target = make_repositories(tmp_path)
    (target / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    git(target, "add", "tracked.txt")
    git(
        target,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "target",
    )
    exclude = Path(
        subprocess.run(
            ["git", "rev-parse", "--git-path", "info/exclude"],
            cwd=target,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    if not exclude.is_absolute():
        exclude = target / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    exclude.write_text("# keep this local rule\n*.local\n", encoding="utf-8")
    tracked_before = (target / "tracked.txt").read_bytes()

    MODULE.deploy(source, target)
    MODULE.deploy(source, target)

    assert (target / "tracked.txt").read_bytes() == tracked_before
    assert subprocess.run(
        ["git", "diff", "--exit-code"], cwd=target, check=False
    ).returncode == 0
    assert subprocess.run(
        ["git", "diff", "--cached", "--exit-code"], cwd=target, check=False
    ).returncode == 0
    assert subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=target,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""
    private_rules = exclude.read_text(encoding="utf-8")
    assert "# keep this local rule\n*.local\n" in private_rules
    for pattern in MODULE.LOCAL_RUNTIME_IGNORE_PATTERNS:
        assert private_rules.splitlines().count(pattern) == 1
        assert pattern in (Path(__file__).parents[1] / ".gitignore").read_text(encoding="utf-8")
    assert "!/state/.gitkeep" in (Path(__file__).parents[1] / ".gitignore").read_text(
        encoding="utf-8"
    )
    assert subprocess.run(
        ["git", "check-ignore", "-q", "current-release"], cwd=target, check=False
    ).returncode == 0
    assert subprocess.run(
        ["git", "check-ignore", "-q", "releases/example"], cwd=target, check=False
    ).returncode == 0


def test_deploy_preserves_existing_target_dirt_and_stage7_rehearses_only_that_dirt(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "deploy-stage7-key" * 5)
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY_ID", "deploy-stage7-current")
    source_repo, target = make_repositories(tmp_path)
    (target / "tracked.txt").write_text("before\n", encoding="utf-8")
    git(target, "add", "tracked.txt")
    git(
        target,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "target",
    )

    (target / "tracked.txt").write_text("changed\n", encoding="utf-8")
    (target / "user-note.txt").write_text("keep this\n", encoding="utf-8")
    status_before = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=target,
        text=True,
    )
    MODULE.deploy(source_repo, target)
    assert subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=target,
        text=True,
    ) == status_before
    state = target / "state"
    versions = state / "ledger-releases"
    versions.mkdir(parents=True)
    legacy = tmp_path / "legacy.sqlite3"
    ManagedLedger(legacy, ensure_schema=True)._connection().close()
    shutil.copy2(legacy, versions / "legacy.sqlite3")
    (state / "current-ledger").symlink_to(Path("ledger-releases") / "legacy.sqlite3")
    private_exclude = Path(
        subprocess.run(
            ["git", "rev-parse", "--git-path", "info/exclude"],
            cwd=target,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    if not private_exclude.is_absolute():
        private_exclude = target / private_exclude
    private_exclude.parent.mkdir(parents=True, exist_ok=True)
    private_rules = private_exclude.read_text(encoding="utf-8")
    for pattern in MODULE.LOCAL_RUNTIME_IGNORE_PATTERNS:
        assert private_rules.splitlines().count(pattern) == 1

    managed_source = tmp_path / "managed.sqlite3"
    ManagedLedger(managed_source, ensure_schema=True)._connection().close()
    result = prepare(
        target,
        managed_source,
        quiesce_token="writer-stopped",
        production_repo=target,
    )
    preservation = result["manifest"]["gitPreservation"]
    assert subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=target,
        text=True,
    ) == status_before
    assert {item["path"] for item in preservation["untrackedFiles"]} == {"user-note.txt"}
    rehearsed = restore_git_preservation(Path(result["manifestPath"]), target, mode="rehearse")
    assert rehearsed["ok"] is True


def test_dirty_source_is_rejected_before_any_release_is_created(tmp_path):
    source, target = make_repositories(tmp_path)
    exclude = Path(
        subprocess.run(
            ["git", "rev-parse", "--git-path", "info/exclude"],
            cwd=target,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    if not exclude.is_absolute():
        exclude = target / exclude
    exclude_before = exclude.read_bytes() if exclude.exists() else None
    (source / "scripts" / "runner.py").write_text("DIRTY = True\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="dirty source"):
        MODULE.deploy(source, target)
    assert not (target / MODULE.RELEASES).exists()
    assert (exclude.read_bytes() if exclude.exists() else None) == exclude_before


def test_existing_release_is_verified_and_corruption_blocks_activation(tmp_path):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    release = Path(first["releasePath"])
    (release / "scripts" / "runner.py").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="(?:size|digest) changed"):
        MODULE.deploy(source, target)
