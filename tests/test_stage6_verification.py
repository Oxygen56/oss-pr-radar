from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import oss_pr_radar.release_binding as release_binding_module
from oss_pr_radar.release_binding import resolve_code_identity
from oss_pr_radar.stage6_verification import (
    VERSIONED_DEFINITIONS,
    build_verification_manifest,
    validate_verification_manifest,
)
from oss_pr_radar.util import sha256_json

HEAD = "0a4e99b78b376e03e02699b7b6e3fe5cede41bf5"


def _passed_results() -> dict[str, dict[str, object]]:
    return {
        item["id"]: {"status": "passed", "exitCode": 0, "outputDigest": "a" * 64}
        for item in build_verification_manifest(HEAD)["definitions"]["commands"]
    }


def test_verification_manifest_is_bound_to_versioned_definitions_and_head():
    manifest = build_verification_manifest(HEAD, results=_passed_results())
    assert validate_verification_manifest(manifest, HEAD)["definitionDigest"] == manifest["definitionDigest"]

    forged = json.loads(json.dumps(manifest))
    forged["definitions"]["faultTests"].append("forged-fault")
    with pytest.raises(ValueError, match="versioned checks"):
        validate_verification_manifest(forged, HEAD)

    with pytest.raises(ValueError, match="different commit"):
        validate_verification_manifest(manifest, "f" * 40)

    forged_result = json.loads(json.dumps(manifest))
    forged_result["results"]["not-a-defined-check"] = "passed"
    with pytest.raises(ValueError, match="command results are incomplete"):
        validate_verification_manifest(forged_result, HEAD)

    forged_result = json.loads(json.dumps(manifest))
    forged_result["results"]["full-pytest"] = "0 passed"
    with pytest.raises(ValueError, match="result is not canonical"):
        validate_verification_manifest(forged_result, HEAD)

    non_canonical = json.loads(json.dumps(manifest))
    non_canonical["results"]["full-pytest"] = {"status": "passed", "exitCode": 0, "outputDigest": "bad"}
    non_canonical["manifestDigest"] = sha256_json(
        {key: value for key, value in non_canonical.items() if key != "manifestDigest"}
    )
    with pytest.raises(ValueError, match="result digest"):
        validate_verification_manifest(non_canonical, HEAD)

    for invalid in (
        {},
        {**_passed_results(), "extra": {"status": "passed", "exitCode": 0, "outputDigest": "a" * 64}},
        {**_passed_results(), "full-pytest": {"status": "failed", "exitCode": 1, "outputDigest": "a" * 64}},
        {**_passed_results(), "full-pytest": {"status": "skipped", "exitCode": 0, "outputDigest": "a" * 64}},
        {**_passed_results(), "full-pytest": {"status": "passed", "exitCode": 1, "outputDigest": "a" * 64}},
        {**_passed_results(), "full-pytest": {"status": "passed", "exitCode": 0, "outputDigest": "short"}},
    ):
        invalid_manifest = build_verification_manifest(HEAD, results=invalid)
        with pytest.raises(ValueError):
            validate_verification_manifest(invalid_manifest, HEAD)


def test_versioned_yaml_check_executes_all_hidden_workflows():
    command = next(
        item["command"]
        for item in build_verification_manifest(HEAD)["definitions"]["commands"]
        if item["id"] == "yaml"
    )
    root = Path(__file__).parents[1]
    result = subprocess.run(
        shlex.split(command),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        ".github/workflows/ci.yml",
        ".github/workflows/health.yml",
        ".github/workflows/radar.yml",
    ]


def test_stage6_manifest_requires_bound_results_or_run(tmp_path):
    script = Path(__file__).parents[1] / "scripts" / "stage6_manifest.py"
    artifact_root = tmp_path / "artifact"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--artifact-root",
            str(artifact_root),
            "--verification-out",
            str(tmp_path / "verification" / "verification-manifest.json"),
        ],
        cwd=script.parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "provide exactly one of --results or --run" in result.stderr
    assert not artifact_root.exists()


def test_stage6_manifest_results_output_is_directly_consumable(tmp_path):
    root = Path(__file__).parents[1]
    clean_root = tmp_path / "clean-candidate"
    shutil.copytree(
        root,
        clean_root,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__"),
    )
    subprocess.run(["git", "init", "-q"], cwd=clean_root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=clean_root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=clean_root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=clean_root, check=True)
    subprocess.run(["git", "commit", "-qm", "clean candidate"], cwd=clean_root, check=True)
    script = clean_root / "scripts" / "stage6_manifest.py"
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(_passed_results()), encoding="utf-8")
    artifact_root = tmp_path / "rehearsal-report"
    verification_path = tmp_path / "verification-root" / "verification-manifest.json"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--artifact-root",
            str(artifact_root),
            "--verification-out",
            str(verification_path),
            "--results",
            str(results_path),
        ],
        cwd=clean_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    persisted = json.loads(verification_path.read_text(encoding="utf-8"))
    actual_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=clean_root, text=True).strip()
    assert validate_verification_manifest(persisted, actual_head)["codeHead"] == actual_head
    assert verification_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(result.stdout)["verificationOut"] == str(verification_path.resolve())

    forged_results = json.loads(results_path.read_text(encoding="utf-8"))
    forged_results["extra"] = {"status": "passed", "exitCode": 0, "outputDigest": "a" * 64}
    results_path.write_text(json.dumps(forged_results), encoding="utf-8")
    failed_root = tmp_path / "failed-report"
    failed_verification = tmp_path / "failed-verification" / "verification-manifest.json"
    failed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--artifact-root",
            str(failed_root),
            "--verification-out",
            str(failed_verification),
            "--results",
            str(results_path),
        ],
        cwd=clean_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert not failed_root.exists()
    assert not failed_verification.exists()
    results_path.write_text(json.dumps(_passed_results()), encoding="utf-8")

    target = tmp_path / "production"
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
    (target / "parent.txt").write_text("parent\n", encoding="utf-8")
    subprocess.run(["git", "add", "parent.txt"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "parent"], cwd=target, check=True)
    parent_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    (target / "dirty-parent.txt").write_text("dirty\n", encoding="utf-8")
    deploy = subprocess.run(
        [sys.executable, str(clean_root / "scripts" / "deploy_local_runtime.py"), "--source", str(clean_root), "--target", str(target)],
        cwd=clean_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert deploy.returncode == 0, deploy.stderr
    release = (target / "current-release").resolve()
    identity_command = next(
        item["command"] for item in VERSIONED_DEFINITIONS["commands"] if item["id"] == "code-integrity"
    )
    command_env = os.environ.copy()
    command_env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{command_env.get('PATH', '')}"
    identity_run = subprocess.run(
        shlex.split(identity_command),
        cwd=release,
        env=command_env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert identity_run.returncode == 0, identity_run.stderr
    release_manifest = json.loads((release / "release-manifest.json").read_text(encoding="utf-8"))
    identity_value = json.loads(identity_run.stdout)
    assert identity_value["commit"] == release_manifest["commit"]
    assert identity_value["commit"] != parent_head
    release_verification = tmp_path / "release-verification" / "verification-manifest.json"
    release_report = tmp_path / "release-report"
    release_run = subprocess.run(
        [
            sys.executable,
            str(release / "scripts" / "stage6_manifest.py"),
            "--artifact-root",
            str(release_report),
            "--verification-out",
            str(release_verification),
            "--results",
            str(results_path),
        ],
        cwd=target,
        check=False,
        capture_output=True,
        text=True,
    )
    assert release_run.returncode == 0, release_run.stderr
    release_value = json.loads(release_verification.read_text(encoding="utf-8"))
    assert release_value["codeHead"] == release_manifest["commit"]
    assert release_value["codeHead"] != parent_head


def test_stage6_manifest_rejects_clean_head_change_before_writing(tmp_path, monkeypatch):
    source = Path(__file__).parents[1]
    clean_root = tmp_path / "changing-candidate"
    shutil.copytree(
        source,
        clean_root,
        ignore=shutil.ignore_patterns(".git", ".venv", ".pytest_cache", "__pycache__"),
    )
    subprocess.run(["git", "init", "-q"], cwd=clean_root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=clean_root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=clean_root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=clean_root, check=True)
    subprocess.run(["git", "commit", "-qm", "clean candidate"], cwd=clean_root, check=True)
    module_spec = importlib.util.spec_from_file_location("stage6_manifest_change_test", clean_root / "scripts" / "stage6_manifest.py")
    assert module_spec and module_spec.loader
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    module.ROOT = clean_root
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(_passed_results()), encoding="utf-8")
    verification_path = tmp_path / "verification" / "manifest.json"
    artifact_root = tmp_path / "report"
    original_resolve = module.resolve_code_identity
    calls = 0

    def resolve_with_head_change(root: Path):
        nonlocal calls
        calls += 1
        if calls == 2:
            (clean_root / "during-run.txt").write_text("changed\n", encoding="utf-8")
            subprocess.run(["git", "add", "during-run.txt"], cwd=clean_root, check=True)
            subprocess.run(["git", "commit", "-qm", "during run"], cwd=clean_root, check=True)
        return original_resolve(root)

    monkeypatch.setattr(module, "resolve_code_identity", resolve_with_head_change)
    monkeypatch.setattr(release_binding_module, "resolve_code_identity", resolve_with_head_change)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(clean_root / "scripts" / "stage6_manifest.py"),
            "--artifact-root",
            str(artifact_root),
            "--verification-out",
            str(verification_path),
            "--results",
            str(results_path),
        ],
    )
    with pytest.raises(RuntimeError, match="code identity changed"):
        module.main()
    assert calls == 2
    assert not artifact_root.exists()
    assert not verification_path.exists()


def _write_release(root: Path, commit: str) -> Path:
    release = root / "releases" / "candidate"
    script = release / "scripts" / "runner.py"
    script.parent.mkdir(parents=True)
    script.write_text("VERSION = 1\n", encoding="utf-8")
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    files = [{"path": "scripts/runner.py", "bytes": script.stat().st_size, "sha256": digest}]
    def canonical(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload = {
        "schemaVersion": "oss-pr-radar_release_v1",
        "commit": commit,
        "files": files,
        "policyDigest": hashlib.sha256(canonical([{"path": "scripts/runner.py", "sha256": digest}])).hexdigest(),
    }
    manifest_sha = hashlib.sha256(canonical(payload)).hexdigest()
    payload["manifestSha256"] = manifest_sha
    payload["releaseId"] = f"{commit[:12]}-{manifest_sha[:12]}"
    release = release.rename(release.parent / payload["releaseId"])
    (release / "release-manifest.json").write_text(json.dumps(payload), encoding="utf-8")
    return release


def test_code_identity_uses_release_manifest_not_dirty_parent_git(tmp_path):
    parent = tmp_path / "production-repo"
    parent.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=parent, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=parent, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=parent, check=True)
    (parent / "parent.txt").write_text("parent\n", encoding="utf-8")
    subprocess.run(["git", "add", "parent.txt"], cwd=parent, check=True)
    subprocess.run(["git", "commit", "-qm", "parent"], cwd=parent, check=True)
    (parent / "dirty-parent.txt").write_text("dirty\n", encoding="utf-8")
    release = _write_release(parent, "b" * 40)
    identity = resolve_code_identity(release)
    assert identity.kind == "release"
    assert identity.commit == "b" * 40
    (release / "scripts" / "runner.py").write_text("POISONED\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="release file (size|digest) changed"):
        resolve_code_identity(release)
    (release / "scripts" / "runner.py").write_text("VERSION = 1\n", encoding="utf-8")
    manifest_path = release / "release-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["commit"] = "c" * 40
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(RuntimeError, match="manifest digest mismatch"):
        resolve_code_identity(release)


def test_compact_final_identity_guard_rejects_release_change_before_report(tmp_path):
    source = Path(__file__).parents[1]
    release = _write_release(tmp_path, "d" * 40)
    module_spec = importlib.util.spec_from_file_location("stage6_compact_guard_test", source / "scripts" / "stage6_compact_rehearsal.py")
    assert module_spec and module_spec.loader
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    module.ROOT = release
    initial = resolve_code_identity(release)
    (release / "scripts" / "runner.py").write_text("CHANGED\n", encoding="utf-8")
    report = tmp_path / "public-summary.json"
    with pytest.raises(RuntimeError, match="release file (size|digest) changed"):
        module._verify_final_code_identity(initial)
    assert not report.exists()


def test_code_identity_rejects_nested_or_dirty_development_root(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    (root / "tracked.txt").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "root"], cwd=root, check=True)
    nested = root / "src"
    nested.mkdir()
    with pytest.raises(RuntimeError, match="exact Git top-level"):
        resolve_code_identity(nested)
    (root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="must be clean"):
        resolve_code_identity(root)
