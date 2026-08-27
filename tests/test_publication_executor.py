from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "publication_executor.py"
SPEC = importlib.util.spec_from_file_location("publication_executor", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class ReconcileStore:
    def __init__(self, *, effect_status="RECONCILE_REQUIRED", effect_result=None):
        self.succeeded = []
        self.completed = []
        self.retried = []
        self.effect_status = effect_status
        self.effect_result = effect_result or {
            "ok": True,
            "prUrl": "https://github.com/example/project/pull/2",
        }

    def publication_effect(self, **_kwargs):
        return {
            "created": False,
            "effect_id": "effect-1",
            "status": self.effect_status,
            "result_json": json.dumps(self.effect_result),
        }

    def publication_effect_by_request(self, **kwargs):
        return self.publication_effect(**kwargs)

    def succeed_pull_request_effect(self, **kwargs):
        self.succeeded.append(kwargs)

    def complete_publication_effect(self, effect_id, *, status, result):
        self.completed.append((effect_id, status, result))

    def retry_publication_effect_after_noop(self, *, effect_id, permit_id, evidence):
        self.retried.append((effect_id, permit_id, evidence))
        return {"status": "ACTIVE", "request_id": "request-1"}


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

    def publication_action_succeeded(self, _request_id, *, action):
        return action == "push"


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


def test_create_pr_retries_transient_503_after_exact_head_is_still_absent(monkeypatch, tmp_path):
    args = pr_args(tmp_path)
    store = ReconcileStore(
        effect_result={
            "ok": False,
            "reason": "PR_CREATION_NOT_RECONCILED",
            "detail": "HTTP 503: No server is currently available",
        }
    )
    configure_permit(monkeypatch, args)
    monkeypatch.setattr(
        MODULE,
        "ensure_permit",
        lambda *_args, **_kwargs: {"status": "ACTIVE", "request_id": "request-1"},
    )
    monkeypatch.setattr(
        MODULE,
        "audit_publication_request",
        lambda *_args, **_kwargs: SimpleNamespace(
            status="ALLOW", reason="LIVE_PUBLICATION_GATES_PASSED"
        ),
    )
    found = iter(
        [
            None,
            {
                "url": "https://github.com/example/project/pull/2",
                "state": "OPEN",
                "headRefOid": args.commit_sha,
            },
        ]
    )
    monkeypatch.setattr(MODULE, "existing_pr", lambda *_args: next(found))
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    result = MODULE.create_pr(args, store)

    assert result["ok"] is True
    assert result["prUrl"] == "https://github.com/example/project/pull/2"
    assert len(calls) == 1
    assert calls[0][:3] == ["gh", "pr", "create"]
    assert store.retried == [
        (
            "effect-1",
            "permit-1",
            {
                "exactHeadPrAbsent": True,
                "liveAuditReason": "LIVE_PUBLICATION_GATES_PASSED",
            },
        )
    ]


def test_create_pr_does_not_retry_when_live_state_no_longer_allows_publication(
    monkeypatch, tmp_path
):
    args = pr_args(tmp_path)
    store = ReconcileStore(
        effect_result={
            "ok": False,
            "reason": "PR_CREATION_NOT_RECONCILED",
            "detail": "HTTP 503: No server is currently available",
        }
    )
    configure_permit(monkeypatch, args)
    monkeypatch.setattr(
        MODULE,
        "ensure_permit",
        lambda *_args, **_kwargs: {"status": "EXPIRED", "request_id": "request-1"},
    )
    monkeypatch.setattr(MODULE, "existing_pr", lambda *_args: None)
    monkeypatch.setattr(
        MODULE,
        "audit_publication_request",
        lambda *_args, **_kwargs: SimpleNamespace(status="DEFER", reason="ISSUE_CHANGED"),
    )
    monkeypatch.setattr(
        MODULE,
        "run",
        lambda *_args, **_kwargs: pytest.fail("an inactive permit cannot retry publication"),
    )

    with pytest.raises(RuntimeError, match="live publication recheck failed: ISSUE_CHANGED"):
        MODULE.create_pr(args, store)
    assert store.retried == []


def test_create_pr_falls_back_to_rest_when_gh_graphql_is_temporarily_unavailable(
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
    monkeypatch.setattr(MODULE, "recheck_new_effect", lambda *_args: None)
    found = iter(
        [
            None,
            {
                "url": "https://github.com/example/project/pull/2",
                "state": "OPEN",
                "headRefOid": args.commit_sha,
            },
        ]
    )
    monkeypatch.setattr(MODULE, "existing_pr", lambda *_args: next(found))
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[:3] == ["gh", "pr", "create"]:
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "HTTP 503: No server is currently available (https://api.github.com/graphql)",
            )
        return subprocess.CompletedProcess(command, 0, '{"html_url":"ignored"}', "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    result = MODULE.create_pr(args, store)

    assert result["prUrl"] == "https://github.com/example/project/pull/2"
    assert calls[0][0][:3] == ["gh", "pr", "create"]
    assert calls[1][0] == [
        "gh",
        "api",
        "--method",
        "POST",
        "repos/example/project/pulls",
        "--input",
        "-",
    ]
    assert json.loads(calls[1][1]["input_text"]) == {
        "title": args.title,
        "head": "Oxygen56:fix-one",
        "base": "main",
        "body": "Fixes #1\n",
    }


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


def test_create_pr_update_reuses_exact_existing_pr_without_creating_another(monkeypatch, tmp_path):
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


def test_create_pr_update_reconciles_permit_bound_title_and_body(monkeypatch, tmp_path):
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
    body = Path(args.body_file).read_text(encoding="utf-8")
    stale = {
        "number": 2,
        "url": "https://github.com/example/project/pull/2",
        "state": "OPEN",
        "headRefOid": args.commit_sha,
        "title": "fix: stale title",
        "body": "Checks could not run.\n",
    }
    current = {**stale, "title": args.title, "body": body}
    results = iter([stale, current])
    monkeypatch.setattr(MODULE, "existing_pr", lambda *_args: next(results))
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    result = MODULE.create_pr(args, store)

    assert result["ok"] is True
    assert result["metadataUpdated"] is True
    assert result["reconciled"] is False
    assert len(calls) == 1
    assert calls[0][:5] == [
        "gh",
        "api",
        "--method",
        "PATCH",
        "repos/example/project/pulls/2",
    ]
    assert f"title={args.title}" in calls[0]
    assert f"body={body}" in calls[0]
    assert "pr" not in calls[0]


def test_post_push_recheck_accepts_the_permitted_target_head(monkeypatch):
    store = ActiveStore()
    captured = {}
    monkeypatch.setattr(
        MODULE,
        "permit_request",
        lambda *_args: {"publicationKind": "PR_UPDATE", "commitSha": "b" * 40},
    )

    def audit(_store, request_id, *, expected_existing_pr_head=None):
        captured.update(
            request_id=request_id,
            expected_existing_pr_head=expected_existing_pr_head,
        )
        return SimpleNamespace(status="ALLOW", reason="LIVE_PUBLICATION_GATES_PASSED")

    monkeypatch.setattr(MODULE, "audit_publication_request", audit)

    MODULE.recheck_new_effect(store, {"request_id": "request-1"}, "effect-1")

    assert captured == {
        "request_id": "request-1",
        "expected_existing_pr_head": "b" * 40,
    }


def test_live_recheck_deferral_is_retryable_before_external_action(monkeypatch):
    class Store(ActiveStore):
        def __init__(self):
            super().__init__()
            self.resolved = []

        def resolve_publication_preflight(self, effect_id, *, disposition, reason):
            self.resolved.append((effect_id, disposition, reason))

    store = Store()
    monkeypatch.setattr(
        MODULE,
        "permit_request",
        lambda *_args: {"publicationKind": "PR_CREATE"},
    )
    monkeypatch.setattr(
        MODULE,
        "audit_publication_request",
        lambda *_args, **_kwargs: SimpleNamespace(
            status="DEFER", reason="LIVE_EVIDENCE_INCOMPLETE"
        ),
    )

    with pytest.raises(MODULE.PublicationDeferred, match="LIVE_EVIDENCE_INCOMPLETE"):
        MODULE.recheck_new_effect(store, {"request_id": "request-1"}, "effect-1")

    assert store.resolved == [("effect-1", "DEFER", "LIVE_EVIDENCE_INCOMPLETE")]
    assert store.completed == []


def test_live_recheck_block_is_recorded_before_external_action(monkeypatch):
    class Store(ActiveStore):
        def __init__(self):
            super().__init__()
            self.resolved = []

        def resolve_publication_preflight(self, effect_id, *, disposition, reason):
            self.resolved.append((effect_id, disposition, reason))

    store = Store()
    monkeypatch.setattr(
        MODULE,
        "permit_request",
        lambda *_args: {"publicationKind": "PR_CREATE"},
    )
    monkeypatch.setattr(
        MODULE,
        "audit_publication_request",
        lambda *_args, **_kwargs: SimpleNamespace(
            status="BLOCK", reason="ISSUE_ASSIGNED_TO_ANOTHER_CONTRIBUTOR"
        ),
    )

    with pytest.raises(
        MODULE.PublicationBlocked,
        match="ISSUE_ASSIGNED_TO_ANOTHER_CONTRIBUTOR",
    ):
        MODULE.recheck_new_effect(store, {"request_id": "request-1"}, "effect-1")

    assert store.resolved == [("effect-1", "BLOCK", "ISSUE_ASSIGNED_TO_ANOTHER_CONTRIBUTOR")]
    assert store.completed == []


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
            return subprocess.CompletedProcess(
                command, 0, "git@github.com:Oxygen56/project.git\n", ""
            )
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


def test_push_retries_stale_ambiguous_effect_after_remote_noop_proof(monkeypatch, tmp_path):
    args = pr_args(tmp_path)
    args.remote = "radar-fork"
    args.commit_sha = "b" * 40
    previous_head = "a" * 40

    class Store(ReconcileStore):
        def __init__(self):
            super().__init__()
            self.completed = []
            self.retried = []

        def complete_publication_effect(self, effect_id, *, status, result):
            self.completed.append((effect_id, status, result))

        def retry_publication_effect_after_noop(self, **kwargs):
            self.retried.append(kwargs)
            return {"status": "ACTIVE", "request_id": "request-1"}

    store = Store()
    monkeypatch.setattr(
        MODULE,
        "ensure_permit",
        lambda *_args, **_kwargs: {"status": "EXPIRED", "request_id": "request-1"},
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
            "previousCommitSha": previous_head,
        },
    )
    monkeypatch.setattr(
        MODULE,
        "audit_publication_request",
        lambda *_args, **_kwargs: SimpleNamespace(
            status="ALLOW", reason="LIVE_PUBLICATION_GATES_PASSED"
        ),
    )
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
            return subprocess.CompletedProcess(
                command, 0, "git@github.com:Oxygen56/project.git\n", ""
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE, "run", fake_run)

    result = MODULE.push(args, store)

    assert result["remoteSha"] == args.commit_sha
    assert store.retried[0]["effect_id"] == "effect-1"
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
            return subprocess.CompletedProcess(
                command, 0, "git@github.com:Oxygen56/project.git\n", ""
            )
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
                "title": "fix: one",
                "body": "Fixes #1\n",
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
    assert found["title"] == "fix: one"
    assert found["body"] == "Fixes #1\n"
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


def test_publication_cli_rejects_missing_authorization_before_external_write(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("missing authorization")),
    )
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("git/gh must not run before authorization"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            "publication_executor.py",
            "push",
            "--runtime-root",
            str(tmp_path),
            "--permit-id",
            "permit-1",
            "--issue-url",
            "https://github.com/example/project/issues/1",
            "--worktree",
            str(tmp_path),
            "--commit-sha",
            "a" * 40,
            "--branch",
            "fix-one",
            "--remote",
            "origin",
        ],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "authorization" in result["error"]


def test_authorized_publication_cli_reaches_operation_without_external_process(
    monkeypatch, tmp_path, capsys
):
    calls = []
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        MODULE, "require_operational_authorization", lambda root: calls.append(root)
    )
    monkeypatch.setattr(MODULE, "RadarLedger", lambda _path: object())
    @contextmanager
    def effect_guard(_root, _path):
        yield SimpleNamespace(fileno=lambda: 0)

    monkeypatch.setattr(MODULE, "outbound_effect_guard", effect_guard)
    monkeypatch.setattr(MODULE, "push", lambda _args, _store: {"ok": True, "pushed": True})
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            "publication_executor.py",
            "push",
            "--runtime-root",
            str(tmp_path),
            "--permit-id",
            "permit-1",
            "--issue-url",
            "https://github.com/example/project/issues/1",
            "--worktree",
            str(tmp_path),
            "--commit-sha",
            "a" * 40,
            "--branch",
            "fix-one",
            "--remote",
            "origin",
        ],
    )

    assert MODULE.main() == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "pushed": True}
    assert calls == [tmp_path.resolve()]


def test_authorized_publication_cli_still_blocks_when_outbound_pause_is_active(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(MODULE, "require_operational_authorization", lambda _root: None)
    @contextmanager
    def effect_guard(_root, _path):
        raise PermissionError("GITHUB_OUTBOUND_PAUSED")
        yield

    monkeypatch.setattr(MODULE, "outbound_effect_guard", effect_guard)
    monkeypatch.setattr(
        MODULE,
        "RadarLedger",
        lambda _path: pytest.fail("paused executor must stop before opening publication state"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            "publication_executor.py",
            "push",
            "--runtime-root",
            str(tmp_path),
            "--permit-id",
            "permit-1",
            "--issue-url",
            "https://github.com/example/project/issues/1",
            "--worktree",
            str(tmp_path),
            "--commit-sha",
            "a" * 40,
            "--branch",
            "fix-one",
            "--remote",
            "origin",
        ],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result == {"ok": False, "blocked": True, "reason": "GITHUB_OUTBOUND_PAUSED"}


def test_external_commands_inherit_the_outbound_lock_descriptor(monkeypatch, tmp_path):
    captured = {}

    def fake_run(*_args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess([], 0, stdout="", stderr="")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    MODULE._OUTBOUND_LOCK_FD = 37
    try:
        MODULE.run(["git", "status"], cwd=tmp_path)
    finally:
        MODULE._OUTBOUND_LOCK_FD = None

    assert captured["pass_fds"] == (37,)


def test_ensure_fork_does_not_turn_a_transient_lookup_failure_into_a_write(
    monkeypatch, tmp_path
):
    calls = []
    monkeypatch.setattr(MODULE, "ensure_permit", lambda *_args, **_kwargs: {"id": "permit"})
    monkeypatch.setattr(
        MODULE,
        "permit_publication",
        lambda _permit: {"headOwner": "Oxygen56"},
    )

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 1, stdout="", stderr="HTTP 503")

    monkeypatch.setattr(MODULE, "run", fake_run)
    args = SimpleNamespace(
        permit_id="permit-1",
        issue_url="https://github.com/example/project/issues/1",
        commit_sha="a" * 40,
        branch="fix-one",
        head_owner="Oxygen56",
        repo="example/project",
        worktree=str(tmp_path),
    )

    with pytest.raises(RuntimeError, match="fork lookup failed"):
        MODULE._ensure_fork_unlocked(args, object())

    assert all(call[:3] != ["gh", "repo", "fork"] for call in calls)


def test_ensure_fork_creates_once_and_returns_a_validated_remote(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(MODULE, "ensure_permit", lambda *_args, **_kwargs: {"id": "permit"})
    monkeypatch.setattr(
        MODULE,
        "permit_publication",
        lambda _permit: {"headOwner": "Oxygen56"},
    )
    fork = {
        "fork": True,
        "parent": {"full_name": "example/project"},
    }

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        if arguments[:2] == ["gh", "api"]:
            api_calls = sum(call[:2] == ["gh", "api"] for call in calls)
            if api_calls == 1:
                return subprocess.CompletedProcess(arguments, 1, stdout="", stderr="HTTP 404")
            return subprocess.CompletedProcess(
                arguments, 0, stdout=json.dumps(fork), stderr=""
            )
        if arguments[:3] == ["gh", "repo", "fork"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")
        if arguments == ["git", "remote"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="origin\n", stderr="")
        if arguments[:3] == ["git", "remote", "get-url"]:
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout="https://github.com/example/project.git\n",
                stderr="",
            )
        if arguments[:3] == ["git", "remote", "add"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr(MODULE, "run", fake_run)
    args = SimpleNamespace(
        permit_id="permit-1",
        issue_url="https://github.com/example/project/issues/1",
        commit_sha="a" * 40,
        branch="fix-one",
        head_owner="Oxygen56",
        repo="example/project",
        worktree=str(tmp_path),
    )

    result = MODULE._ensure_fork_unlocked(args, object())

    assert result == {
        "ok": True,
        "remote": "radar-fork",
        "forkRepo": "Oxygen56/project",
        "created": True,
    }
    assert sum(call[:3] == ["gh", "repo", "fork"] for call in calls) == 1


def test_publication_cli_rejects_wrong_release_binding_before_external_process(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(
        MODULE,
        "bind_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("release mismatch")),
    )
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("git/gh must not run for an invalid release"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        [
            "publication_executor.py",
            "push",
            "--runtime-root",
            str(tmp_path),
            "--permit-id",
            "permit-1",
            "--issue-url",
            "https://github.com/example/project/issues/1",
            "--worktree",
            str(tmp_path),
            "--commit-sha",
            "a" * 40,
            "--branch",
            "fix-one",
            "--remote",
            "origin",
        ],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "authorization" in result["error"]


def test_publication_executor_help_has_no_auth_bypass_option():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "skip-auth" not in completed.stdout
    assert "allow-unreleased-code" not in completed.stdout


def test_publication_guard_blocks_active_quarantine_before_action(tmp_path):
    args = pr_args(tmp_path)

    class GuardedStore:
        path = tmp_path / "ledger.sqlite3"

        @staticmethod
        def active_task_quarantine(_key):
            return {"reason": "ACTIVE_TASK_QUARANTINE"}

    called = []
    with pytest.raises(PermissionError, match="active quarantine"):
        MODULE._guarded_publication_action(args, GuardedStore(), lambda: called.append(True))
    assert called == []


def test_publication_guard_linearizes_quarantine_before_callback(tmp_path):
    args = pr_args(tmp_path)
    from oss_pr_radar.action_guard import ledger_action_guard_root, opportunity_action_guard

    class GuardedStore:
        path = tmp_path / "ledger.sqlite3"

        def __init__(self):
            self.active = False

        def active_task_quarantine(self, _key):
            return {"reason": "ACTIVE_TASK_QUARANTINE"} if self.active else None

    store = GuardedStore()
    key = MODULE._publication_opportunity_key(args.issue_url)
    started = threading.Event()
    finished = threading.Event()

    def activate():
        started.set()
        with opportunity_action_guard(ledger_action_guard_root(store.path), key):
            store.active = True
        finished.set()

    with opportunity_action_guard(ledger_action_guard_root(store.path), key):
        thread = threading.Thread(target=activate)
        thread.start()
        assert started.wait(2)
        assert not finished.is_set()
    thread.join(timeout=2)
    assert finished.is_set()

    called = []
    with pytest.raises(PermissionError, match="active quarantine"):
        MODULE._guarded_publication_action(args, store, lambda: called.append(True))
    assert called == []


def test_publication_action_guard_holds_through_irreversible_callback(tmp_path):
    args = pr_args(tmp_path)
    from oss_pr_radar.action_guard import ledger_action_guard_root, opportunity_action_guard

    class GuardedStore:
        path = tmp_path / "ledger.sqlite3"

        def __init__(self):
            self.active = False

        def active_task_quarantine(self, _key):
            return {"reason": "ACTIVE_TASK_QUARANTINE"} if self.active else None

    store = GuardedStore()
    key = MODULE._publication_opportunity_key(args.issue_url)
    quarantine_started = threading.Event()
    quarantine_finished = threading.Event()
    quarantine_errors = []

    def activate():
        quarantine_started.set()
        try:
            with opportunity_action_guard(ledger_action_guard_root(store.path), key):
                store.active = True
        except BaseException as exc:
            quarantine_errors.append(exc)
        finally:
            quarantine_finished.set()

    activation = threading.Thread(target=activate)

    def irreversible_action():
        activation.start()
        assert quarantine_started.wait(2)
        assert not quarantine_finished.is_set()
        return {"ok": True, "irreversible": True}

    result = MODULE._guarded_publication_action(args, store, irreversible_action)
    activation.join(timeout=2)
    assert result == {"ok": True, "irreversible": True}
    assert not activation.is_alive()
    assert quarantine_errors == []
    assert quarantine_finished.is_set()
    assert store.active is True
