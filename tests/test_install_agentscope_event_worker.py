from __future__ import annotations

import importlib.util
import json
import plistlib
import shutil
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "install_agentscope_event_worker.py"
SPEC = importlib.util.spec_from_file_location("install_agentscope_event_worker", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_launchagent_path_resolves_codex_runtime(tmp_path, monkeypatch):
    codex_dir = tmp_path / "ChatGPT.app" / "Contents" / "Resources"
    codex_dir.mkdir(parents=True)
    (codex_dir / "codex").touch(mode=0o755)
    monkeypatch.setattr(MODULE, "SERVICE_PATH", str(codex_dir))

    code_root = tmp_path / "release"
    (code_root / "scripts").mkdir(parents=True)
    (code_root / "release-manifest.json").write_text("{}\n", encoding="utf-8")
    (code_root / "scripts" / "agentscope_event_worker.py").write_text(
        "# event worker\n", encoding="utf-8"
    )
    runtime_root = tmp_path / "runtime"
    runtime_python = runtime_root / ".venv" / "bin" / "python"
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("#!/bin/sh\n", encoding="utf-8")

    value = MODULE.spec(runtime_root, code_root=code_root, home=tmp_path / "home")
    environment = value["EnvironmentVariables"]
    launch_path = str(environment["PATH"])

    assert launch_path == str(codex_dir)
    assert shutil.which("codex", path=launch_path) == str(codex_dir / "codex")
    assert value["ProgramArguments"][0] == str(runtime_python)


def test_install_does_not_kill_run_at_load_worker(tmp_path, monkeypatch):
    runtime_root = tmp_path / "runtime"
    runtime_python = runtime_root / ".venv" / "bin" / "python"
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("#!/bin/sh\n", encoding="utf-8")
    code_root = tmp_path / "release"
    (code_root / "scripts").mkdir(parents=True)
    (code_root / "release-manifest.json").write_text("{}\n", encoding="utf-8")
    (code_root / "scripts" / "agentscope_event_worker.py").write_text(
        "# event worker\n", encoding="utf-8"
    )
    calls = []
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda argv, **kwargs: calls.append((argv, kwargs)),
    )

    MODULE.install(
        runtime_root,
        code_root=code_root,
        home=tmp_path / "home",
    )

    commands = [argv[1] for argv, _kwargs in calls]
    assert commands == ["bootout", "bootstrap"]


def test_stage_cli_writes_without_loading(tmp_path, monkeypatch, capsys):
    calls = []

    def fake_install(runtime_root, *, code_root, manifest_sha256=None, load=True):
        calls.append(
            {
                "runtimeRoot": runtime_root,
                "codeRoot": code_root,
                "manifestSha256": manifest_sha256,
                "load": load,
            }
        )
        return {"ok": True, "loaded": load}

    monkeypatch.setattr(MODULE, "install", fake_install)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--runtime-root",
            str(tmp_path / "runtime"),
            "--code-root",
            str(tmp_path / "release"),
            "--manifest-sha256",
            "a" * 64,
            "--stage",
        ],
    )

    assert MODULE.main() == 0
    assert calls == [
        {
            "runtimeRoot": tmp_path / "runtime",
            "codeRoot": tmp_path / "release",
            "manifestSha256": "a" * 64,
            "load": False,
        }
    ]
    assert json.loads(capsys.readouterr().out)["loaded"] is False


def test_staged_install_verifies_plist_without_launchctl(tmp_path, monkeypatch):
    runtime_root = tmp_path / "runtime"
    runtime_python = runtime_root / ".venv" / "bin" / "python"
    runtime_python.parent.mkdir(parents=True)
    runtime_python.write_text("#!/bin/sh\n", encoding="utf-8")
    code_root = tmp_path / "release"
    (code_root / "scripts").mkdir(parents=True)
    (code_root / "release-manifest.json").write_text("{}\n", encoding="utf-8")
    (code_root / "scripts" / "agentscope_event_worker.py").write_text(
        "# event worker\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("launchctl must not run while staging"),
    )

    result = MODULE.install(
        runtime_root,
        code_root=code_root,
        home=tmp_path / "home",
        load=False,
    )

    path = Path(result["plist"])
    assert result["loaded"] is False
    assert path.stat().st_mode & 0o777 == 0o600
    assert plistlib.loads(path.read_bytes()) == result["spec"]
    assert result["spec"]["ProgramArguments"][0] == str(runtime_python)


def test_spec_rejects_missing_runtime_python(tmp_path):
    code_root = tmp_path / "release"
    (code_root / "scripts").mkdir(parents=True)
    (code_root / "release-manifest.json").write_text("{}\n", encoding="utf-8")
    (code_root / "scripts" / "agentscope_event_worker.py").write_text(
        "# event worker\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="runtime Python interpreter is unavailable"):
        MODULE.spec(tmp_path / "runtime", code_root=code_root, home=tmp_path / "home")
