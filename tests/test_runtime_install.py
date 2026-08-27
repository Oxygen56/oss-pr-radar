from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from oss_pr_radar.controller import controller_cycle
from oss_pr_radar.local_publication import worker_specs
from oss_pr_radar.runtime import pid_probe
from oss_pr_radar.runtime_audit import active_release_evidence

DEPLOY_SCRIPT = Path(__file__).parents[1] / "scripts" / "deploy_local_runtime.py"
SPEC = importlib.util.spec_from_file_location("deploy_runtime_install", DEPLOY_SCRIPT)
assert SPEC and SPEC.loader
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)


def git(path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def repositories(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    target = tmp_path / "runtime"
    source.mkdir()
    target.mkdir()
    git(source, "init")
    git(target, "init")
    (source / "scripts").mkdir()
    (source / "scripts" / "worker.py").write_text("VERSION = 1\n", encoding="utf-8")
    git(source, "add", "scripts/worker.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "release-1",
    )
    return source, target


def test_workers_use_active_immutable_release_and_runtime_root(tmp_path):
    source, target = repositories(tmp_path)
    result = DEPLOY.deploy(source, target)
    release = Path(result["releasePath"])

    specs = worker_specs(release, home=tmp_path / "home", runtime_root=target)

    assert active_release_evidence(target)["releaseId"] == result["releaseId"]
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(2)", str(release)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        probe = pid_probe(process.pid, expected_fragment=str(release))
        assert probe["alive"] is True
        assert probe["versionMatched"] is True
    finally:
        process.terminate()
        process.wait(timeout=5)
    for spec in specs:
        arguments = spec["ProgramArguments"]
        assert any(str(release) in argument for argument in arguments)
        assert str(target) in arguments
        assert spec["WorkingDirectory"] == str(target.resolve())
        assert ["--root", str(target.resolve())] in [
            arguments[index : index + 2] for index in range(len(arguments) - 1)
        ]


def test_activate_rollback_preserves_ledger_receipt_queue_and_rejects_corruption(tmp_path):
    source, target = repositories(tmp_path)
    first = DEPLOY.deploy(source, target)
    release_one = Path(first["releasePath"])
    state = target / "state"
    state.mkdir(exist_ok=True)
    ledger = state / "radar_ledger.sqlite3"
    receipt = state / "task-turn-receipt.json"
    queue = state / "local-receipt-queue.json"
    ledger.write_bytes(b"ledger-before-rollback")
    receipt.write_text('{"status":"PR_OPEN"}\n', encoding="utf-8")
    queue.write_text('{"entries":{"one":"kept"}}\n', encoding="utf-8")
    before = {path: path.read_bytes() for path in (ledger, receipt, queue)}

    (source / "scripts" / "worker.py").write_text("VERSION = 2\n", encoding="utf-8")
    git(source, "add", "scripts/worker.py")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "release-2",
    )
    second = DEPLOY.deploy(source, target)
    release_two = Path(second["releasePath"])
    assert release_two != release_one

    DEPLOY.activate_release(target, str(first["releaseId"]))
    assert (target / "current-release").resolve() == release_one
    assert {path: path.read_bytes() for path in before} == before

    (release_two / "scripts" / "worker.py").write_text("corrupt\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="(?:size|digest) changed"):
        DEPLOY.activate_release(target, str(second["releaseId"]))
    assert (target / "current-release").resolve() == release_one


def test_controller_never_resolves_executables_from_poisoned_runtime_scripts(tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_DISPATCH_HMAC_KEY", "controller-stage7-key" * 4)
    source, target = repositories(tmp_path)
    for name in (
        "local_dispatch_bridge.py",
        "install_local_publication_workers.py",
        "check_workflow_health.py",
        "event_lane_health.py",
    ):
        (source / "scripts" / name).write_text("# test release executable\n", encoding="utf-8")
    git(source, "add", "scripts")
    git(
        source,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "release-scripts",
    )
    result = DEPLOY.deploy(source, target)
    release = Path(result["releasePath"])
    (target / "scripts").mkdir()
    (target / "scripts" / "local_dispatch_bridge.py").write_text("raise SystemExit('poison')\n")
    calls = []

    def runner(_root, stage, argv, _allowed, _timeout):
        calls.append((stage, list(argv)))
        if stage in {"workflowHealth", "finalWorkflowHealth"}:
            return {
                "operationalHealthy": True,
                "githubNaturalScheduleHealthy": True,
                "effectiveScan": {"recentActive": False},
            }
        if stage == "drain":
            return {"ok": True, "action": "none"}
        if stage == "finalQueue":
            return {"ok": True, "pending": []}
        if stage == "quality":
            return {"ok": True}
        return {"ok": True}

    monkeypatch.setattr(
        "oss_pr_radar.controller.require_operational_authorization", lambda _root: {}
    )
    controller_cycle(target, code_root=release, runner=runner, notify=False)
    executable_args = [
        argument for _stage, argv in calls for argument in argv if argument.endswith(".py")
    ]
    assert executable_args
    assert all(str(release) in argument for argument in executable_args)
    assert all(str(target / "scripts") not in argument for argument in executable_args)
