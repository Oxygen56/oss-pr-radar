import json
import subprocess
from datetime import UTC, datetime, timedelta

from oss_pr_radar import publication
from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.metrics import QUALITY_FIELDS
from oss_pr_radar.publication import (
    broker_publication_request,
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
