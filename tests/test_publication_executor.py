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
