from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

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

    value = MODULE.spec(tmp_path / "runtime", code_root=code_root, home=tmp_path / "home")
    environment = value["EnvironmentVariables"]
    launch_path = str(environment["PATH"])

    assert launch_path == str(codex_dir)
    assert shutil.which("codex", path=launch_path) == str(codex_dir / "codex")
