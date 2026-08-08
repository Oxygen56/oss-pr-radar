import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from oss_pr_radar import publication
from oss_pr_radar.ledger import LedgerError, RadarLedger
from oss_pr_radar.metrics import QUALITY_FIELDS
from oss_pr_radar.publication import (
    broker_publication_request,
    public_branch_is_safe,
    public_text_is_safe,
    request_publication,
)
from oss_pr_radar.util import iso_z


def git(*args, cwd):
    result = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def dispatch_intent(worktree):
    now = datetime.now(UTC)
    return {
        "intentId": "intent-1",
        "key": "example/project#7",
        "repo": "example/project",
        "issueNumber": 7,
        "issueUrl": "https://github.com/example/project/issues/7",
        "title": "Streaming tool arguments disappear",
        "category": "NEW_CLEAN_CANDIDATE",
        "mode": "canary",
        "publicationMode": "canary",
        "score": 9,
        "snapshotId": "snapshot",
        "decisionDigest": "decision",
        "scanGate": "ALLOW_TO_WORK",
        "autoSpawn": True,
        "publicSubmissionAllowed": True,
        "autoSubmitAuthorized": True,
        "authorizationSource": "signed_live_revalidation_required",
        "llmReview": {
            "status": "ok",
            "decision": "NEW_CLEAN_CANDIDATE",
            "confidence": 0.91,
            "model": "test",
        },
        "issuedAt": iso_z(now),
        "expiresAt": iso_z(now + timedelta(hours=1)),
        "worktree": str(worktree),
    }


def prepared_request(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    git("init", cwd=worktree)
    git("config", "user.name", "Tester", cwd=worktree)
    git("config", "user.email", "tester@example.com", cwd=worktree)
    (worktree / "file.txt").write_text("fixed\n", encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "Fix streaming", cwd=worktree)
    branch = git("symbolic-ref", "--short", "HEAD", cwd=worktree)
    commit = git("rev-parse", "HEAD", cwd=worktree)

    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(dispatch_intent(worktree))
    store.claim("intent-1", "worker")
    store.commit_dispatch(
        "intent-1",
        owner="worker",
        thread_id="thread-1",
        project_id="project-1",
        worktree_path=str(worktree),
    )
    quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("example/project#7", "FIX_READY", evidence=quality)
    body_path = tmp_path / "pr-body.md"
    body_path.write_text("Fixes #7\n\nAdds a regression test.\n", encoding="utf-8")
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(
        json.dumps(
            {
                "issueUrl": "https://github.com/example/project/issues/7",
                "commitSha": commit,
                "branch": branch,
                "worktreePath": str(worktree),
                "changedFiles": ["file.txt"],
                "quality": quality,
                "tests": [{"command": "pytest", "exitCode": 0}],
                "publication": {
                    "headOwner": "Oxygen56",
                    "baseBranch": "main",
                    "title": "Fix streaming tool arguments",
                    "bodyFile": str(body_path),
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    request = request_publication(
        store,
        issue_url="https://github.com/example/project/issues/7",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=evidence_path,
    )
    return store, request, evidence_path


def test_blocked_publication_can_be_reingested_after_evidence_is_corrected(tmp_path):
    store, request, _evidence_path = prepared_request(tmp_path)
    store.block_publication_request(request["request_id"], "BASE_BRANCH_MISMATCH")

    candidates = store.task_result_candidates()

    assert [candidate["key"] for candidate in candidates] == ["example/project#7"]


def test_blocked_publication_retry_requires_the_observed_reason(tmp_path):
    store, request, _evidence_path = prepared_request(tmp_path)
    store.block_publication_request(request["request_id"], "STRONG_EXISTING_PR")

    retried = store.retry_blocked_publication_request(
        request["request_id"], expected_reason="STRONG_EXISTING_PR"
    )

    assert retried["status"] == "PENDING"
    assert store.publication_request(request["request_id"])["status"] == "PENDING"
    assert store.task_result_candidates() == []


class Client:
    def issue(self, repo, number):
        return {
            "state": "open",
            "title": "Streaming tool arguments disappear",
            "body": "Tool call arguments are lost while streaming.",
            "assignees": [],
        }

    def comments(self, repo, number):
        return []

    def timeline(self, repo, number):
        return []

    def repository(self, repo):
        return {"default_branch": "main"}

    def repository_tree(self, repo, ref):
        return []

    def related_open_prs(self, repo, number, **kwargs):
        return []


def test_broker_grants_commit_bound_permit(monkeypatch, tmp_path):
    store, request, _ = prepared_request(tmp_path)
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])
    result = broker_publication_request(store, request["request_id"], client=Client())
    assert result["granted"] is True
    permit = result["permit"]
    assert store.publication_permit(
        issue_url="https://github.com/example/project/issues/7",
        commit_sha=permit["commit_sha"],
        branch=permit["branch"],
    )


def test_followup_publication_is_bound_to_existing_pr_and_previous_head(tmp_path):
    store, request, evidence_path = prepared_request(tmp_path)
    first = store.publication_request(request["request_id"])
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url=first["request"]["issueUrl"],
        commit_sha=first["commit_sha"],
        branch=first["branch"],
        evidence={"publication": first["request"]["publication"]},
    )
    store.consume_publication_permit(permit["permit_id"], "https://github.com/example/project/pull/8")
    worktree = tmp_path / "worktree"
    (worktree / "file.txt").write_text("fixed again\n", encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "Refine streaming fix", cwd=worktree)
    current = git("rev-parse", "HEAD", cwd=worktree)
    quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("example/project#7", "FIX_READY", evidence=quality)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["commitSha"] = current
    evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")

    update = request_publication(
        store,
        issue_url="https://github.com/example/project/issues/7",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=evidence_path,
    )

    payload = update["request"]
    assert payload["publicationKind"] == "PR_UPDATE"
    assert payload["existingPrUrl"] == "https://github.com/example/project/pull/8"
    assert payload["previousCommitSha"] == first["commit_sha"]


def test_broker_allows_fast_forward_update_of_its_exact_existing_pr(monkeypatch, tmp_path):
    store, request, evidence_path = prepared_request(tmp_path)
    first = store.publication_request(request["request_id"])
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url=first["request"]["issueUrl"],
        commit_sha=first["commit_sha"],
        branch=first["branch"],
        evidence={"publication": first["request"]["publication"]},
    )
    pr_url = "https://github.com/example/project/pull/8"
    store.consume_publication_permit(permit["permit_id"], pr_url)
    worktree = tmp_path / "worktree"
    (worktree / "file.txt").write_text("fixed again\n", encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "Refine streaming fix", cwd=worktree)
    current = git("rev-parse", "HEAD", cwd=worktree)
    quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("example/project#7", "FIX_READY", evidence=quality)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["commitSha"] = current
    evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    update = request_publication(
        store,
        issue_url="https://github.com/example/project/issues/7",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=evidence_path,
    )

    class UpdateClient(Client):
        def related_open_prs(self, repo, number, **kwargs):
            return [{"number": 8, "_repo": repo}]

        def pull_request(self, repo, number):
            return {
                "number": 8,
                "state": "open",
                "html_url": pr_url,
                "title": "Fix streaming tool arguments",
                "body": "Fixes #7",
                "updated_at": "2026-08-09T00:00:00Z",
                "head": {
                    "sha": first["commit_sha"],
                    "ref": first["branch"],
                    "repo": {"owner": {"login": "Oxygen56"}},
                },
            }

        def pull_files(self, repo, number):
            return [{"filename": "file.txt"}]

        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return []

    monkeypatch.setattr(publication, "_changed_files_since", lambda *args: ["file.txt"])
    result = broker_publication_request(store, update["request_id"], client=UpdateClient())

    assert result["granted"] is True
    assert result["audit"]["evidence"]["publicationKind"] == "PR_UPDATE"


def test_evidence_digest_drift_blocks_publication(monkeypatch, tmp_path):
    store, request, evidence_path = prepared_request(tmp_path)
    evidence_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])
    result = broker_publication_request(store, request["request_id"], client=Client())
    assert result["granted"] is False
    assert result["audit"]["reason"] == "EVIDENCE_DIGEST_DRIFT"


def test_pr_body_drift_blocks_publication(monkeypatch, tmp_path):
    store, request, evidence_path = prepared_request(tmp_path)
    body_path = json.loads(evidence_path.read_text(encoding="utf-8"))["publication"]["bodyFile"]
    publication.Path(body_path).write_text("Fixes #7\n\nDifferent body.\n", encoding="utf-8")
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])
    result = broker_publication_request(store, request["request_id"], client=Client())
    assert result["granted"] is False
    assert result["audit"]["reason"] == "PUBLICATION_PAYLOAD_DRIFT"


def test_public_text_only_rejects_explicit_assistance_disclosure():
    assert public_text_is_safe("Fix AI agent streaming", "Fixes #7") is True
    assert public_text_is_safe("Fix streaming", "Generated by Codex") is False


def test_public_branch_rejects_tool_identity_without_blocking_ai_domain_names():
    assert public_branch_is_safe("fix/ai-agent-streaming") is True
    assert public_branch_is_safe("fix/mcp-oauth-shared-storage") is True
    assert public_branch_is_safe("fix/gemini-tool-calls") is True
    assert public_branch_is_safe("codex/fix-streaming") is False
    assert public_branch_is_safe("fix/ai-generated-patch") is False


def test_expired_permit_can_only_finalize_ambiguous_pr_effect(tmp_path):
    store, request, _ = prepared_request(tmp_path)
    row = store.publication_request(request["request_id"])
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url="https://github.com/example/project/issues/7",
        commit_sha=row["commit_sha"],
        branch=row["branch"],
        evidence={"publication": {}},
    )
    effect = store.publication_effect(
        permit_id=permit["permit_id"],
        action="create_pr",
        request_digest="request-digest",
    )
    store.complete_publication_effect(
        effect["effect_id"],
        status="RECONCILE_REQUIRED",
        result={"ok": False, "reason": "PR_CREATION_NOT_RECONCILED"},
    )
    with store.transaction() as connection:
        connection.execute(
            "UPDATE publication_permits SET status='EXPIRED' WHERE permit_id=?",
            (permit["permit_id"],),
        )

    reconciliable = store.publication_permit_for_effect(permit["permit_id"], action="create_pr")
    assert reconciliable["status"] == "EXPIRED"

    result = {
        "ok": True,
        "prUrl": "https://github.com/example/project/pull/8",
        "state": "OPEN",
    }
    store.succeed_pull_request_effect(
        effect_id=effect["effect_id"],
        permit_id=permit["permit_id"],
        pr_url=result["prUrl"],
        result=result,
    )

    with store.connect() as connection:
        permit_row = connection.execute(
            "SELECT status,pr_url FROM publication_permits WHERE permit_id=?",
            (permit["permit_id"],),
        ).fetchone()
        effect_row = connection.execute(
            "SELECT status FROM publication_effects WHERE effect_id=?",
            (effect["effect_id"],),
        ).fetchone()
        opportunity = connection.execute(
            "SELECT stage FROM opportunities WHERE key='example/project#7'"
        ).fetchone()
        intent = connection.execute(
            "SELECT status FROM intents WHERE intent_id='intent-1'"
        ).fetchone()
    assert dict(permit_row) == {"status": "CONSUMED", "pr_url": result["prUrl"]}
    assert effect_row["status"] == "SUCCEEDED"
    assert opportunity["stage"] == "PR_OPEN"
    assert intent["status"] == "COMPLETED"
    replay_permit = store.publication_permit_for_effect(permit["permit_id"], action="create_pr")
    replay_effect = store.publication_effect_by_request(
        permit_id=permit["permit_id"],
        action="create_pr",
        request_digest="request-digest",
    )
    assert replay_permit["status"] == "CONSUMED"
    assert replay_effect["status"] == "SUCCEEDED"


def test_expired_permit_cannot_finalize_new_pr_effect(tmp_path):
    store, request, _ = prepared_request(tmp_path)
    row = store.publication_request(request["request_id"])
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url="https://github.com/example/project/issues/7",
        commit_sha=row["commit_sha"],
        branch=row["branch"],
        evidence={"publication": {}},
    )
    effect = store.publication_effect(
        permit_id=permit["permit_id"],
        action="create_pr",
        request_digest="request-digest",
    )
    with store.transaction() as connection:
        connection.execute(
            "UPDATE publication_permits SET status='EXPIRED' WHERE permit_id=?",
            (permit["permit_id"],),
        )

    assert store.publication_permit_for_effect(permit["permit_id"], action="create_pr") is None
    with pytest.raises(LedgerError, match="expired permit"):
        store.succeed_pull_request_effect(
            effect_id=effect["effect_id"],
            permit_id=permit["permit_id"],
            pr_url="https://github.com/example/project/pull/8",
            result={"ok": True},
        )
