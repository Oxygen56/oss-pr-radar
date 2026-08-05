from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "publication_executor.py"
SPEC = importlib.util.spec_from_file_location("publication_executor", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class ReconcileStore:
    def __init__(self, *, effect_status="RECONCILE_REQUIRED"):
        self.succeeded = []
        self.effect_status = effect_status

    def publication_effect(self, **_kwargs):
        return {
            "created": False,
            "effect_id": "effect-1",
            "status": self.effect_status,
            "result_json": json.dumps(
                {"ok": True, "prUrl": "https://github.com/example/project/pull/2"}
            ),
        }

    def publication_effect_by_request(self, **kwargs):
        return self.publication_effect(**kwargs)

    def succeed_pull_request_effect(self, **kwargs):
        self.succeeded.append(kwargs)


def pr_args(tmp_path: Path) -> SimpleNamespace:
    body = tmp_path / "body.md"
    body.write_text("Fixes #1\n", encoding="utf-8")
    return SimpleNamespace(
        issue_url="https://github.com/example/project/issues/1",
        repo="example/project",
        worktree=str(tmp_path),
        body_file=str(body),
        permit_id="permit-1",
        commit_sha="a" * 40,
        branch="fix-one",
        head_owner="Oxygen56",
        base="main",
        title="fix: one",
    )


def configure_permit(monkeypatch, args):
    monkeypatch.setattr(MODULE, "ensure_permit", lambda *_args, **_kwargs: {"status": "EXPIRED"})
    monkeypatch.setattr(
        MODULE,
        "permit_publication",
        lambda _permit: {
            "headOwner": args.head_owner,
            "baseBranch": args.base,
            "title": args.title,
            "bodyPath": str(Path(args.body_file).resolve()),
            "bodyDigest": MODULE.sha256_text(Path(args.body_file).read_text(encoding="utf-8")),
        },
    )


def test_create_pr_reconciles_previous_ambiguous_attempt_without_recreating(monkeypatch, tmp_path):
    args = pr_args(tmp_path)
    store = ReconcileStore()
    configure_permit(monkeypatch, args)
    monkeypatch.setattr(
        MODULE,
        "existing_pr",
        lambda *_args: {
            "url": "https://github.com/example/project/pull/2",
            "state": "OPEN",
            "headRefOid": args.commit_sha,
        },
    )
    monkeypatch.setattr(
        MODULE,
        "run",
        lambda *_args, **_kwargs: pytest.fail("reconciliation must not create another PR"),
    )

    result = MODULE.create_pr(args, store)

    assert result["ok"] is True
    assert result["reconciled"] is False
    assert store.succeeded == [
        {
            "effect_id": "effect-1",
            "permit_id": "permit-1",
            "pr_url": "https://github.com/example/project/pull/2",
            "result": result,
        }
    ]


def test_create_pr_keeps_ambiguous_attempt_when_remote_result_is_still_missing(
    monkeypatch, tmp_path
):
    args = pr_args(tmp_path)
    store = ReconcileStore()
    configure_permit(monkeypatch, args)
    monkeypatch.setattr(MODULE, "existing_pr", lambda *_args: None)
    monkeypatch.setattr(
        MODULE,
        "run",
        lambda *_args, **_kwargs: pytest.fail("reconciliation must not create another PR"),
    )

    with pytest.raises(RuntimeError, match="not visible"):
        MODULE.create_pr(args, store)

    assert store.succeeded == []


def test_create_pr_replays_consumed_success_without_remote_lookup(monkeypatch, tmp_path):
    args = pr_args(tmp_path)
    store = ReconcileStore(effect_status="SUCCEEDED")
    monkeypatch.setattr(MODULE, "ensure_permit", lambda *_args, **_kwargs: {"status": "CONSUMED"})
    monkeypatch.setattr(
        MODULE,
        "permit_publication",
        lambda _permit: {
            "headOwner": args.head_owner,
            "baseBranch": args.base,
            "title": args.title,
            "bodyPath": str(Path(args.body_file).resolve()),
            "bodyDigest": MODULE.sha256_text(Path(args.body_file).read_text(encoding="utf-8")),
        },
    )
    monkeypatch.setattr(
        MODULE,
        "existing_pr",
        lambda *_args: pytest.fail("completed effects must replay without a remote lookup"),
    )

    result = MODULE.create_pr(args, store)

    assert result == {"ok": True, "prUrl": "https://github.com/example/project/pull/2"}
    assert store.succeeded == []


def test_create_pr_rejects_tool_identity_in_public_branch(tmp_path):
    args = pr_args(tmp_path)
    args.branch = "codex/fix-one"

    with pytest.raises(RuntimeError, match="branch name exposes"):
        MODULE.create_pr(args, ReconcileStore())


def test_existing_pr_uses_exact_rest_head_filter(monkeypatch):
    calls = []

    def fake_run(args, **_kwargs):
        calls.append(args)
        payload = [
            {
                "number": 2,
                "html_url": "https://github.com/example/project/pull/2",
                "state": "open",
                "head": {
                    "ref": "fix-one",
                    "sha": "a" * 40,
                    "repo": {"owner": {"login": "Oxygen56"}},
                },
            }
        ]
        return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    found = MODULE.existing_pr("example/project", "Oxygen56", "fix-one")

    assert found["url"] == "https://github.com/example/project/pull/2"
    assert calls[0][:4] == ["gh", "api", "--method", "GET"]
    assert "head=Oxygen56:fix-one" in calls[0]


def test_wait_for_existing_pr_retries_eventual_visibility(monkeypatch):
    expected = {"url": "https://github.com/example/project/pull/2"}
    results = iter([None, None, expected])
    delays = []
    monkeypatch.setattr(MODULE, "existing_pr", lambda *_args: next(results))
    monkeypatch.setattr(MODULE, "sleep", delays.append)

    found = MODULE.wait_for_existing_pr("example/project", "Oxygen56", "fix-one")

    assert found == expected
    assert delays == [1.0, 3.0]
