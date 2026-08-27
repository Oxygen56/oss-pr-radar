from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from oss_pr_radar import repo_probe


def _git(checkout: Path, *args: str, input: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(checkout), *args],
        check=True,
        capture_output=True,
        input=input,
    )


def _checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _git(checkout, "init", "--quiet")
    _git(checkout, "config", "user.name", "Index Contract Test")
    _git(checkout, "config", "user.email", "index-contract@example.com")
    (checkout / "src" / "plugins").mkdir(parents=True)
    (checkout / "src" / "frontends").mkdir(parents=True)
    (checkout / "src" / "plugins" / "keep.py").write_text("keep = True\n", encoding="utf-8")
    (checkout / "src" / "frontends" / "target.py").write_text(
        "target = True\n", encoding="utf-8"
    )
    _git(checkout, "add", ".")
    _git(checkout, "commit", "--quiet", "-m", "initial")
    return checkout


def test_indexable_paths_accept_normal_worktree_without_staging(tmp_path: Path) -> None:
    checkout = _checkout(tmp_path)
    target = checkout / "src" / "frontends" / "target.py"
    target.write_text("target = False\n", encoding="utf-8")

    bindings = repo_probe.validate_indexable_checkout_paths(
        checkout, ["src/frontends/target.py"]
    )

    assert set(bindings) == {"src/frontends/target.py"}
    _git(checkout, "diff", "--cached", "--quiet")


def test_indexable_paths_reject_materialized_file_outside_sparse_checkout(
    tmp_path: Path,
) -> None:
    checkout = _checkout(tmp_path)
    _git(checkout, "sparse-checkout", "init", "--cone")
    _git(checkout, "sparse-checkout", "set", "src/plugins")
    target = checkout / "src" / "frontends" / "target.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_git(checkout, "show", "HEAD:src/frontends/target.py").stdout)

    # Filesystem-only validation reproduces the old false positive.
    assert set(repo_probe.validate_checkout_paths(checkout, ["src/frontends/target.py"])) == {
        "src/frontends/target.py"
    }
    with pytest.raises(repo_probe.ProbeUnavailable, match="CODE_PATH_OUTSIDE_SPARSE_CHECKOUT"):
        repo_probe.validate_indexable_checkout_paths(checkout, ["src/frontends/target.py"])

    _git(checkout, "diff", "--cached", "--quiet")
