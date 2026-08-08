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


class ActiveStore:
    def __init__(self):
        self.completed = []
        self.succeeded = []
        self.rearmed = []

    def publication_effect(self, **_kwargs):
        return {
            "created": True,
            "effect_id": "effect-1",
            "status": "ATTEMPTED",
            "result_json": "{}",
        }

    def complete_publication_effect(self, effect_id, *, status, result):
        self.completed.append((effect_id, status, result))

    def succeed_pull_request_effect(self, **kwargs):
        self.succeeded.append(kwargs)

    def rearm_pr_followup_after_publication_drift(self, request_id, *, reason):
        self.rearmed.append((request_id, reason))


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
    monkeypatch.setattr(
        MODULE,
        "permit_request",
        lambda *_args: {"publicationKind": "PR_CREATE"},
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
        "permit_request",
        lambda *_args: {"publicationKind": "PR_CREATE"},
    )
    monkeypatch.setattr(
        MODULE,
        "existing_pr",
        lambda *_args: pytest.fail("completed effects must replay without a remote lookup"),
    )

    result = MODULE.create_pr(args, store)

    assert result == {"ok": True, "prUrl": "https://github.com/example/project/pull/2"}
    assert store.succeeded == []


def test_create_pr_update_reuses_exact_existing_pr_without_creating_another(
    monkeypatch, tmp_path
):
    args = pr_args(tmp_path)
    store = ActiveStore()
    configure_permit(monkeypatch, args)
    monkeypatch.setattr(
        MODULE,
        "ensure_permit",
        lambda *_args, **_kwargs: {"status": "ACTIVE", "request_id": "request-1"},
    )
    monkeypatch.setattr(
        MODULE,
        "permit_request",
        lambda *_args: {
            "publicationKind": "PR_UPDATE",
            "existingPrUrl": "https://github.com/example/project/pull/2",
        },
    )
    monkeypatch.setattr(MODULE, "recheck_new_effect", lambda *_args: None)
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
        lambda *_args, **_kwargs: pytest.fail("an existing PR update must not create another PR"),
    )

    result = MODULE.create_pr(args, store)

    assert result["ok"] is True
    assert result["prUrl"] == "https://github.com/example/project/pull/2"
    assert store.succeeded[0]["pr_url"] == result["prUrl"]


def test_push_allows_only_fast_forward_update_of_exact_existing_pr(monkeypatch, tmp_path):
    args = pr_args(tmp_path)
    args.remote = "radar-fork"
    args.commit_sha = "b" * 40
    previous_head = "a" * 40
    store = ActiveStore()
    monkeypatch.setattr(
        MODULE,
        "ensure_permit",
        lambda *_args, **_kwargs: {"status": "ACTIVE", "request_id": "request-1"},
    )
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
        "permit_request",
        lambda *_args: {
            "publicationKind": "PR_UPDATE",
            "existingPrUrl": "https://github.com/example/project/pull/2",
            "previousCommitSha": previous_head,
        },
    )
    monkeypatch.setattr(MODULE, "recheck_new_effect", lambda *_args: None)
    monkeypatch.setattr(
        MODULE,
        "existing_pr",
        lambda *_args: {
            "url": "https://github.com/example/project/pull/2",
            "state": "OPEN",
            "headRefOid": previous_head,
        },
    )
    remote_heads = iter([previous_head, args.commit_sha])
    monkeypatch.setattr(MODULE, "remote_head", lambda *_args: next(remote_heads))
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[:4] == ["git", "remote", "get-url", args.remote]:
            return subprocess.CompletedProcess(command, 0, "git@github.com:Oxygen56/project.git\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    result = MODULE.push(args, store)

    assert result == {"ok": True, "reconciled": False, "remoteSha": args.commit_sha}
    assert ["git", "merge-base", "--is-ancestor", previous_head, args.commit_sha] in calls
    assert [
        "git",
        "push",
        args.remote,
        f"{args.commit_sha}:refs/heads/{args.branch}",
    ] in calls


def test_push_rearms_original_task_when_existing_pr_head_drifted(monkeypatch, tmp_path):
    args = pr_args(tmp_path)
    args.remote = "radar-fork"
    args.commit_sha = "c" * 40
    permitted_previous = "a" * 40
    live_previous = "b" * 40
    store = ActiveStore()
    monkeypatch.setattr(
        MODULE,
        "ensure_permit",
        lambda *_args, **_kwargs: {"status": "ACTIVE", "request_id": "request-1"},
    )
    monkeypatch.setattr(
        MODULE,
        "permit_publication",
        lambda _permit: {"headOwner": args.head_owner},
    )
    monkeypatch.setattr(
        MODULE,
        "permit_request",
        lambda *_args: {
            "publicationKind": "PR_UPDATE",
            "existingPrUrl": "https://github.com/example/project/pull/2",
            "previousCommitSha": permitted_previous,
        },
    )
    monkeypatch.setattr(MODULE, "recheck_new_effect", lambda *_args: None)
    monkeypatch.setattr(MODULE, "remote_head", lambda *_args: live_previous)
    monkeypatch.setattr(
        MODULE,
        "existing_pr",
        lambda *_args: {
            "url": "https://github.com/example/project/pull/2",
            "state": "OPEN",
            "headRefOid": live_previous,
        },
    )

    def fake_run(command, **_kwargs):
        if command[:4] == ["git", "remote", "get-url", args.remote]:
            return subprocess.CompletedProcess(command, 0, "git@github.com:Oxygen56/project.git\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    with pytest.raises(RuntimeError, match="head changed"):
        MODULE.push(args, store)

    assert store.rearmed == [("request-1", "EXISTING_PR_HEAD_DRIFT")]
    assert store.completed[0][1] == "FAILED"


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
