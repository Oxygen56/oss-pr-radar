from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "deploy_local_runtime.py"
SPEC = importlib.util.spec_from_file_location("deploy_local_runtime", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def git(path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def test_deploy_preserves_runtime_state_and_only_removes_manifest_files(tmp_path):
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    git(source, "init")
    git(target, "init")
    (source / "scripts").mkdir()
    (source / "scripts" / "runner.py").write_text("VERSION = 2\n", encoding="utf-8")
    (source / "state").mkdir()
    (source / "state" / ".gitkeep").write_text("", encoding="utf-8")
    git(source, "add", "scripts/runner.py", "state/.gitkeep")

    (target / "state").mkdir()
    ledger = target / "state" / "radar_ledger.sqlite3"
    ledger.write_bytes(b"durable-ledger")
    (target / "obsolete.py").write_text("old\n", encoding="utf-8")
    (target / "user-note.txt").write_text("keep\n", encoding="utf-8")
    (target / MODULE.MANIFEST).write_text(
        json.dumps({"version": "runtime_manifest_v1", "files": ["obsolete.py"]}),
        encoding="utf-8",
    )

    result = MODULE.deploy(source, target)

    assert result["ok"] is True
    assert (target / "scripts" / "runner.py").read_text(encoding="utf-8") == "VERSION = 2\n"
    assert ledger.read_bytes() == b"durable-ledger"
    assert not (target / "obsolete.py").exists()
    assert (target / "user-note.txt").read_text(encoding="utf-8") == "keep\n"
    manifest = json.loads((target / MODULE.MANIFEST).read_text(encoding="utf-8"))
    assert manifest["files"] == ["scripts/runner.py"]
