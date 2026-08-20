from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from oss_pr_radar import release_binding as release_binding_module
from oss_pr_radar import runtime as runtime_module
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.release_binding import active_release
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


def test_deploy_records_release_identity_without_overwriting_worker_health(tmp_path):
    source, target = make_repositories(tmp_path)
    state = target / "state" / "runtime-health.json"
    state.parent.mkdir(parents=True)
    workers = {"fast": {"lastSuccessAt": "old"}, "slow": {"lastExitCode": 1}}
    state.write_text(
        json.dumps(
            {
                "workers": workers,
                "deployment": {
                    "releaseVersion": "old-release",
                    "policyDigest": "old-policy",
                    "manifestVerified": True,
                    "deploymentDirty": False,
                },
            }
        ),
        encoding="utf-8",
    )
    state.chmod(0o600)

    result = MODULE.deploy(source, target)

    value = json.loads(state.read_text(encoding="utf-8"))
    manifest = json.loads((Path(result["releasePath"]) / MODULE.MANIFEST).read_text())
    assert value["workers"] == workers
    assert value["deployment"] == {
        "releaseVersion": result["releaseId"],
        "policyDigest": manifest["policyDigest"],
        "manifestVerified": True,
        "deploymentDirty": False,
    }


def test_deploy_secures_existing_runtime_directories_and_private_files(tmp_path):
    source, target = make_repositories(tmp_path)
    (target / "releases").mkdir()
    (target / "state").mkdir()
    (target / "releases").chmod(0o755)
    (target / "state").chmod(0o755)

    result = MODULE.deploy(source, target)

    assert (target / "releases").stat().st_mode & 0o777 == 0o700
    assert (target / "state").stat().st_mode & 0o777 == 0o700
    assert (target / "state" / "runtime-health.json").stat().st_mode & 0o777 == 0o600
    assert (target / "state" / "runtime-health.lock").stat().st_mode & 0o777 == 0o600
    assert MODULE.verify_release(Path(result["releasePath"]))["releaseId"] == result["releaseId"]


def test_release_activation_write_failure_restores_pointer_and_health(tmp_path, monkeypatch):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    state_path = target / "state" / "runtime-health.json"
    before_state = state_path.read_bytes()
    original = runtime_module._atomic_write

    def fail_health(path, value, **kwargs):
        if path == state_path:
            raise OSError("injected health write failure")
        return original(path, value, **kwargs)

    monkeypatch.setattr(runtime_module, "_atomic_write", fail_health)
    with pytest.raises(OSError, match="injected health write failure"):
        MODULE.activate_release(target, first["releaseId"])

    assert (target / "current-release").resolve().name == second["releaseId"]
    assert state_path.read_bytes() == before_state
    assert not runtime_module.release_activation_journal_path(target).exists()


def test_interrupted_release_activation_recovers_to_previous_pair(tmp_path):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    state_path = target / "state" / "runtime-health.json"
    old_state = state_path.read_bytes()
    first_manifest = MODULE.verify_release(target / MODULE.RELEASES / first["releaseId"])
    journal = {
        "schema": "oss-pr-radar.release-activation.v1",
        "oldTarget": str((target / MODULE.RELEASES / second["releaseId"]).resolve()),
        "newTarget": str((target / MODULE.RELEASES / first["releaseId"]).resolve()),
        "oldStateBytes": __import__("base64").b64encode(old_state).decode("ascii"),
        "oldStateMode": state_path.stat().st_mode & 0o777,
        "newDeployment": {
            "releaseVersion": first["releaseId"],
            "policyDigest": first_manifest["policyDigest"],
            "manifestVerified": True,
            "deploymentDirty": False,
        },
        "phase": "pointer-active",
    }
    runtime_module._atomic_write(runtime_module.release_activation_journal_path(target), journal)
    runtime_module._atomic_pointer_write(
        target / MODULE.RELEASE_POINTER, target / MODULE.RELEASES / first["releaseId"]
    )

    assert runtime_module.recover_release_activation(target) == "rolled_back"
    assert (target / MODULE.RELEASE_POINTER).resolve().name == second["releaseId"]
    assert state_path.read_bytes() == old_state
    assert not runtime_module.release_activation_journal_path(target).exists()


def test_release_activation_waits_for_runtime_lock(tmp_path):
    source, target = make_repositories(tmp_path)
    result = MODULE.deploy(source, target)
    finished = threading.Event()

    def activate_again():
        MODULE.activate_release(target, result["releaseId"])
        finished.set()

    with runtime_module.exclusive_lock(runtime_module.runtime_state_lock_path(target)):
        thread = threading.Thread(target=activate_again)
        thread.start()
        time.sleep(0.05)
        assert not finished.is_set()
    thread.join(timeout=5)
    assert finished.is_set()


def test_deploy_rejects_symlinked_releases_root_without_writing_outside(tmp_path):
    source, target = make_repositories(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_bytes(b"keep")
    (target / "releases").symlink_to(outside, target_is_directory=True)
    before = marker.read_bytes()

    with pytest.raises(RuntimeError, match="runtime releases"):
        MODULE.deploy(source, target)

    assert marker.read_bytes() == before
    assert not (target / "current-release").exists()
    assert not (target / "state").exists()


def test_activate_rejects_symlinked_release_directory_and_preserves_state(tmp_path):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    outside = tmp_path / "outside-release"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_bytes(b"keep")
    release = target / MODULE.RELEASES / first["releaseId"]
    release.rename(release.with_name("release-real"))
    release.symlink_to(outside, target_is_directory=True)
    pointer_before = (target / MODULE.RELEASE_POINTER).resolve()
    health_before = (target / "state" / "runtime-health.json").read_bytes()

    with pytest.raises(RuntimeError, match="release"):
        MODULE.activate_release(target, first["releaseId"])

    assert (target / MODULE.RELEASE_POINTER).resolve() == pointer_before
    assert (target / "state" / "runtime-health.json").read_bytes() == health_before
    assert marker.read_bytes() == b"keep"


def test_deploy_rejects_symlinked_state_without_external_write(tmp_path):
    source, target = make_repositories(tmp_path)
    outside = tmp_path / "outside-state"
    outside.mkdir()
    marker = outside / "runtime-health.json"
    marker.write_bytes(b"keep")
    (target / "state").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="runtime state"):
        MODULE.deploy(source, target)

    assert marker.read_bytes() == b"keep"
    assert not (target / MODULE.RELEASES).exists()
    assert not (target / MODULE.RELEASE_POINTER).exists()


def test_active_release_rejects_external_current_release_pointer(tmp_path):
    source, target = make_repositories(tmp_path)
    MODULE.deploy(source, target)
    outside = tmp_path / "outside-release"
    outside.mkdir()
    pointer = target / MODULE.RELEASE_POINTER
    pointer.unlink()
    pointer.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="escapes"):
        active_release(target)


def test_release_activation_rechecks_target_before_pointer_replace(tmp_path, monkeypatch):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    MODULE.activate_release(target, first["releaseId"])
    second_path = target / MODULE.RELEASES / second["releaseId"]
    outside = tmp_path / "outside-release"
    outside.mkdir()
    original = runtime_module._atomic_pointer_write
    swapped = False

    def replace_release(pointer, release, **kwargs):
        nonlocal swapped
        if pointer.name == MODULE.RELEASE_POINTER and not swapped:
            swapped = True
            second_path.rename(second_path.with_name("release-raced"))
            second_path.symlink_to(outside, target_is_directory=True)
            return original(pointer, release, **kwargs)

    monkeypatch.setattr(runtime_module, "_atomic_pointer_write", replace_release)
    with pytest.raises(RuntimeError, match="unsafe|changed|real directory|escapes releases"):
        MODULE.activate_release(target, second["releaseId"])

    assert (target / MODULE.RELEASE_POINTER).resolve().name == first["releaseId"]


def test_release_activation_rejects_same_name_release_replacement_and_rolls_back(
    tmp_path, monkeypatch
):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    MODULE.activate_release(target, first["releaseId"])
    release = target / MODULE.RELEASES / second["releaseId"]
    manifest = MODULE.verify_release(release)
    original = runtime_module._atomic_pointer_write
    swapped = False

    def replace_with_same_name(pointer, destination, **kwargs):
        nonlocal swapped
        if pointer.name == MODULE.RELEASE_POINTER and not swapped:
            swapped = True
            release.rename(release.with_name("release-replaced"))
            release.mkdir()
        return original(pointer, destination, **kwargs)

    monkeypatch.setattr(runtime_module, "_atomic_pointer_write", replace_with_same_name)
    with pytest.raises(RuntimeError, match="release"):
        runtime_module.activate_release_pointer(target, release, manifest)

    assert (target / MODULE.RELEASE_POINTER).resolve().name == first["releaseId"]
    assert not runtime_module.release_activation_journal_path(target).exists()


def test_runtime_root_replacement_rolls_back_through_held_descriptors(tmp_path, monkeypatch):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    state_path = target / "state" / "runtime-health.json"
    old_state = state_path.read_bytes()
    outside = tmp_path / "outside-runtime"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_bytes(b"keep")
    real_target = target.with_name("target-real")
    original = runtime_module._atomic_write_bytes
    swapped = False

    def replace_root(path, payload, *, mode, **kwargs):
        nonlocal swapped
        if path.name == runtime_module.RELEASE_ACTIVATION_JOURNAL and not swapped:
            swapped = True
            target.rename(real_target)
            target.symlink_to(outside, target_is_directory=True)
        return original(path, payload, mode=mode, **kwargs)

    monkeypatch.setattr(runtime_module, "_atomic_write_bytes", replace_root)
    with pytest.raises(RuntimeError, match="runtime root|runtime state|release"):
        MODULE.activate_release(target, first["releaseId"])

    assert marker.read_bytes() == b"keep"
    pointer_target = os.readlink(real_target / MODULE.RELEASE_POINTER)
    assert (
        Path(pointer_target).resolve()
        == (real_target / MODULE.RELEASES / second["releaseId"]).resolve()
    )
    assert (real_target / MODULE.RELEASE_POINTER).resolve() == (
        real_target / MODULE.RELEASES / second["releaseId"]
    ).resolve()
    assert (real_target / "state" / "runtime-health.json").read_bytes() == old_state
    assert not (real_target / "state" / runtime_module.RELEASE_ACTIVATION_JOURNAL).exists()


def test_directory_fd_path_resolution_uses_macos_bytes_buffer(tmp_path, monkeypatch):
    if not hasattr(release_binding_module.fcntl, "F_GETPATH"):
        pytest.skip("macOS F_GETPATH is unavailable")
    descriptor = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    original = release_binding_module.fcntl.fcntl
    seen: list[object] = []

    def checked_fcntl(fd, command, argument):
        seen.append(argument)
        return original(fd, command, argument)

    monkeypatch.setattr(release_binding_module.fcntl, "fcntl", checked_fcntl)
    try:
        assert (
            release_binding_module._path_from_directory_fd(descriptor, label="test directory")
            == tmp_path
        )
    finally:
        os.close(descriptor)
    assert seen and all(isinstance(argument, bytes) for argument in seen)


def test_atomic_pointer_write_closes_owned_directory_on_validation_errors(tmp_path, monkeypatch):
    parent = tmp_path / "runtime"
    parent.mkdir()
    pointer = parent / MODULE.RELEASE_POINTER
    opened: list[int] = []
    original = runtime_module.open_directory_handle

    def track_open(*args, **kwargs):
        descriptor, canonical = original(*args, **kwargs)
        opened.append(descriptor)
        return descriptor, canonical

    monkeypatch.setattr(runtime_module, "open_directory_handle", track_open)
    for _ in range(20):
        with pytest.raises(FileNotFoundError):
            runtime_module._atomic_pointer_write(pointer, parent / "missing-release")

    leaked = []
    for descriptor in opened:
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        leaked.append(descriptor)
        os.close(descriptor)
    assert leaked == []


def test_activation_holds_state_directory_fd_when_state_is_replaced(tmp_path, monkeypatch):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    state = target / "state"
    outside = tmp_path / "outside-state"
    outside.mkdir()
    marker = outside / runtime_module.RELEASE_ACTIVATION_JOURNAL
    marker.write_bytes(b"keep")
    original = runtime_module._atomic_write_bytes
    swapped = False

    def replace_state(path, payload, *, mode, **kwargs):
        nonlocal swapped
        if path.name == runtime_module.RELEASE_ACTIVATION_JOURNAL and not swapped:
            swapped = True
            state.rename(target / "state-raced")
            state.symlink_to(outside, target_is_directory=True)
        return original(path, payload, mode=mode, **kwargs)

    monkeypatch.setattr(runtime_module, "_atomic_write_bytes", replace_state)
    with pytest.raises(RuntimeError, match="runtime state|release"):
        MODULE.activate_release(target, first["releaseId"])

    assert marker.read_bytes() == b"keep"
    assert (target / MODULE.RELEASE_POINTER).resolve().name == second["releaseId"]


def test_activation_rejects_health_symlink_at_fd_open_without_external_read(tmp_path, monkeypatch):
    source, target = make_repositories(tmp_path)
    first = MODULE.deploy(source, target)
    (source / "scripts" / "runner.py").write_text("VERSION = 3\n", encoding="utf-8")
    git(source, "add", "scripts/runner.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "source-v3",
    )
    second = MODULE.deploy(source, target)
    health = target / "state" / "runtime-health.json"
    outside = tmp_path / "outside-health.json"
    outside.write_bytes(b"external-health")
    before = outside.read_bytes()
    original_open = runtime_module.os.open
    swapped = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None, **kwargs):
        nonlocal swapped
        if path == runtime_module.RUNTIME_STATE and dir_fd is not None and not swapped:
            swapped = True
            health.unlink()
            health.symlink_to(outside)
        return original_open(path, flags, mode, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(runtime_module.os, "open", racing_open)
    with pytest.raises(OSError):
        MODULE.activate_release(target, first["releaseId"])

    assert outside.read_bytes() == before
    assert (target / MODULE.RELEASE_POINTER).resolve().name == second["releaseId"]


def test_activation_normalizes_macos_var_alias(tmp_path):
    private_var = Path("/private/var")
    public_var = Path("/var")
    if not private_var.is_dir() or public_var.resolve() != private_var:
        pytest.skip("macOS /var alias is unavailable")
    source, target = make_repositories(tmp_path)
    result = MODULE.deploy(source, target)
    relative = target.relative_to(private_var)
    alias_target = public_var / relative

    MODULE.activate_release(alias_target, result["releaseId"])

    assert (target / MODULE.RELEASE_POINTER).resolve().name == result["releaseId"]


def test_runtime_root_replacement_during_fd_identity_resolution_has_no_external_write(
    tmp_path, monkeypatch
):
    if not hasattr(release_binding_module.fcntl, "F_GETPATH"):
        pytest.skip("descriptor path identity test requires macOS F_GETPATH")
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_bytes(b"keep")
    original_fcntl = release_binding_module.fcntl.fcntl
    swapped = False

    def racing_fcntl(descriptor, command, argument):
        nonlocal swapped
        if command == release_binding_module.fcntl.F_GETPATH and not swapped:
            swapped = True
            real_root = runtime_root.with_name("runtime-real")
            runtime_root.rename(real_root)
            runtime_root.symlink_to(outside, target_is_directory=True)
        return original_fcntl(descriptor, command, argument)

    monkeypatch.setattr(release_binding_module.fcntl, "fcntl", racing_fcntl)
    with pytest.raises(RuntimeError, match="runtime root changed during validation"):
        release_binding_module.validate_runtime_layout(
            runtime_root, create_releases=True, create_state=True
        )

    assert marker.read_bytes() == b"keep"
    assert not (outside / "state").exists()
    assert not (outside / "releases").exists()


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
    assert subprocess.run(["git", "diff", "--exit-code"], cwd=target, check=False).returncode == 0
    assert (
        subprocess.run(
            ["git", "diff", "--cached", "--exit-code"], cwd=target, check=False
        ).returncode
        == 0
    )
    assert (
        subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=target,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        == ""
    )
    private_rules = exclude.read_text(encoding="utf-8")
    assert "# keep this local rule\n*.local\n" in private_rules
    for pattern in MODULE.LOCAL_RUNTIME_IGNORE_PATTERNS:
        assert private_rules.splitlines().count(pattern) == 1
        assert pattern in (Path(__file__).parents[1] / ".gitignore").read_text(encoding="utf-8")
    assert "!/state/.gitkeep" in (Path(__file__).parents[1] / ".gitignore").read_text(
        encoding="utf-8"
    )
    assert (
        subprocess.run(
            ["git", "check-ignore", "-q", "current-release"], cwd=target, check=False
        ).returncode
        == 0
    )
    assert (
        subprocess.run(
            ["git", "check-ignore", "-q", "releases/example"], cwd=target, check=False
        ).returncode
        == 0
    )


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
    assert (
        subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=target,
            text=True,
        )
        == status_before
    )
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
    assert (
        subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=target,
            text=True,
        )
        == status_before
    )
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
