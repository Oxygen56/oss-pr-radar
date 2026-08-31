import base64
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from oss_pr_radar import publication
from oss_pr_radar.github_client import GitHubError
from oss_pr_radar.independent_review import REVIEW_SCHEMA, _receipt_path, _source_digest
from oss_pr_radar.ledger import LedgerError, RadarLedger
from oss_pr_radar.metrics import QUALITY_FIELDS
from oss_pr_radar.publication import (
    broker_publication_request,
    public_branch_is_safe,
    public_text_is_safe,
    request_publication,
)
from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES, run_reproduction_probe
from oss_pr_radar.util import iso_z

pytestmark = pytest.mark.usefixtures("current_signing_key")


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
            "semanticSignal": "NO_OBJECTION",
            "evidence": ["issue_data.issue_body"],
            "confidence": 0.91,
            "model": "test",
        },
        "issuedAt": iso_z(now),
        "expiresAt": iso_z(now + timedelta(hours=1)),
        "worktree": str(worktree),
    }


def prepared_request(tmp_path):
    publication.CONTROL_ROOT = tmp_path
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    git("init", cwd=worktree)
    git("config", "user.name", "Tester", cwd=worktree)
    git("config", "user.email", "tester@example.com", cwd=worktree)
    git("commit", "--allow-empty", "-m", "chore: baseline", cwd=worktree)
    (worktree / "file.txt").write_text('assert "fixed" == "fixed"\n', encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "Fix streaming", cwd=worktree)
    branch = git("symbolic-ref", "--short", "HEAD", cwd=worktree)
    commit = git("rev-parse", "HEAD", cwd=worktree)
    TRUSTED_PROBE_PROFILES["test-publication-real"] = {
        "reproductionArgv": ["python3", "file.txt"],
        "validationArgv": ["python3", "file.txt"],
    }
    result_digest = "publication-result-digest"
    reproduction_receipt = run_reproduction_probe(
        checkout_path=worktree,
        repo="example/project",
        default_branch="main",
        selected_base_sha=commit,
        code_paths=["file.txt"],
        profile_id="test-publication-real",
        issue_url="https://github.com/example/project/issues/7",
        task_id="intent-1",
        thread_id="thread-1",
        head_sha=commit,
        commit_sha=commit,
        result_digest=result_digest,
    )

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
                "key": "example/project#7",
                "issueUrl": "https://github.com/example/project/issues/7",
                "commitSha": commit,
                "branch": branch,
                "worktreePath": str(worktree),
                "changedFiles": ["file.txt"],
                "quality": quality,
                "probeRequired": True,
                "probeLevel": "REPRODUCED_VALIDATED",
                "selectedBaseSha": commit,
                "headSha": commit,
                "resultDigest": result_digest,
                "taskId": "intent-1",
                "codePaths": ["file.txt"],
                "reproductionReceipt": reproduction_receipt,
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
    evidence_value = json.loads(evidence_path.read_text(encoding="utf-8"))
    source_digest = _source_digest(evidence_value)
    review = {
        "schemaVersion": REVIEW_SCHEMA,
        "reviewedAt": iso_z(datetime.now(UTC)),
        "commitSha": commit,
        "baseRevision": commit,
        "sourceDigest": source_digest,
        "reviewMode": "codex_exec_ephemeral_read_only",
        "verdict": "PASS",
        "summary": "Explicit fixture review passed.",
        "findings": [],
        "blockingEvidence": [],
        "evidence": ["file.txt", "pytest"],
    }
    review_path = _receipt_path(
        tmp_path,
        key="example/project#7",
        commit_sha=commit,
        source_digest=source_digest,
    )
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(
        json.dumps(
            {
                "schemaVersion": REVIEW_SCHEMA,
                "key": "example/project#7",
                "commitSha": commit,
                "sourceDigest": source_digest,
                "review": review,
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
    assert request["request"]["evidenceRawBase64"]
    return store, request, evidence_path


def refresh_reproduction_evidence(evidence, *, worktree, tmp_path, commit_sha):
    probe_checkout = tmp_path / "probe-checkout"
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(probe_checkout), evidence["selectedBaseSha"]],
        cwd=worktree,
        check=True,
        capture_output=True,
    )
    result_digest = f"result-{commit_sha}"
    evidence.update(
        {
            "commitSha": commit_sha,
            "headSha": commit_sha,
            "resultDigest": result_digest,
            "reproductionReceipt": run_reproduction_probe(
                checkout_path=probe_checkout,
                repo="example/project",
                default_branch="main",
                selected_base_sha=evidence["selectedBaseSha"],
                code_paths=["file.txt"],
                profile_id="test-publication-real",
                issue_url="https://github.com/example/project/issues/7",
                task_id="intent-1",
                thread_id="thread-1",
                head_sha=commit_sha,
                commit_sha=commit_sha,
                result_digest=result_digest,
            ),
        }
    )
    return evidence


def write_explicit_review_receipt(evidence, *, tmp_path):
    """Issue a fresh private review artifact for the exact evidence snapshot."""

    source_digest = _source_digest(evidence)
    commit_sha = str(evidence["commitSha"])
    review = {
        "schemaVersion": REVIEW_SCHEMA,
        "key": evidence["key"],
        "reviewedAt": iso_z(datetime.now(UTC)),
        "commitSha": commit_sha,
        "baseRevision": str(evidence.get("selectedBaseSha") or commit_sha),
        "sourceDigest": source_digest,
        "reviewMode": "codex_exec_ephemeral_read_only",
        "verdict": "PASS",
        "summary": "Explicit fixture review passed.",
        "findings": [],
        "blockingEvidence": [],
        "evidence": ["file.txt", "pytest"],
    }
    path = _receipt_path(
        tmp_path,
        key=str(evidence["key"]),
        commit_sha=commit_sha,
        source_digest=source_digest,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schemaVersion": REVIEW_SCHEMA,
                "key": evidence["key"],
                "commitSha": commit_sha,
                "sourceDigest": source_digest,
                "review": review,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_up_to_date_upstream_branch_skips_fetch(monkeypatch, tmp_path):
    calls = []
    sha = "a" * 40

    def command(args, *, cwd, timeout=120):
        calls.append((args, cwd, timeout))
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            return f"{sha}\trefs/heads/main"
        if args[:3] == ["git", "rev-parse", "--verify"]:
            return sha
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)

    remote = publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    assert remote == "origin"
    assert not any(args[:2] == ["git", "fetch"] for args, _cwd, _timeout in calls)


def test_changed_upstream_branch_fetches_exact_tracking_ref(monkeypatch, tmp_path):
    calls = []
    old_sha = "a" * 40
    live_sha = "b" * 40
    fetched = False

    def command(args, *, cwd, timeout=120):
        nonlocal fetched
        calls.append((args, cwd, timeout))
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            return f"{live_sha}\trefs/heads/main"
        if args[:2] == ["git", "fetch"]:
            fetched = True
            return ""
        if args[:3] == ["git", "rev-parse", "--verify"]:
            return live_sha if fetched else old_sha
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)

    publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    fetch = next(args for args, _cwd, _timeout in calls if args[:2] == ["git", "fetch"])
    assert fetch == [
        "git",
        "fetch",
        "--quiet",
        "--no-tags",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
    ]


def test_refresh_upstream_branch_retries_transient_ls_remote_errors(monkeypatch, tmp_path):
    sha = "a" * 40
    ls_remote_calls = 0
    sleeps = []

    def command(args, *, cwd, timeout=120):
        nonlocal ls_remote_calls
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            ls_remote_calls += 1
            if ls_remote_calls < 3:
                raise publication.PublicationError("unexpected EOF while reading")
            return f"{sha}\trefs/heads/main"
        if args[:3] == ["git", "rev-parse", "--verify"]:
            return sha
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)
    monkeypatch.setattr(publication.time, "sleep", sleeps.append)

    publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    assert ls_remote_calls == 3
    assert sleeps == [0.25, 1.0]


def test_refresh_upstream_branch_retries_transient_fetch_error(monkeypatch, tmp_path):
    old_sha = "a" * 40
    live_sha = "b" * 40
    fetch_calls = 0
    sleeps = []

    def command(args, *, cwd, timeout=120):
        nonlocal fetch_calls
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            return f"{live_sha}\trefs/heads/main"
        if args[:2] == ["git", "fetch"]:
            fetch_calls += 1
            if fetch_calls == 1:
                raise publication.PublicationError(
                    "curl 56 Recv failure: Operation timed out\n"
                    "fatal: expected flush after ref listing"
                )
            return ""
        if args[:3] == ["git", "rev-parse", "--verify"]:
            return live_sha if fetch_calls >= 2 else old_sha
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)
    monkeypatch.setattr(publication.time, "sleep", sleeps.append)

    publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    assert fetch_calls == 2
    assert sleeps == [0.25]


def test_refresh_upstream_branch_retries_subprocess_timeout(monkeypatch, tmp_path):
    sha = "a" * 40
    ls_remote_calls = 0
    sleeps = []

    def command(args, *, cwd, timeout=120):
        nonlocal ls_remote_calls
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            ls_remote_calls += 1
            if ls_remote_calls == 1:
                raise subprocess.TimeoutExpired(args, timeout)
            return f"{sha}\trefs/heads/main"
        if args[:3] == ["git", "rev-parse", "--verify"]:
            return sha
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)
    monkeypatch.setattr(publication.time, "sleep", sleeps.append)

    publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    assert ls_remote_calls == 2
    assert sleeps == [0.25]


def test_refresh_upstream_branch_does_not_retry_hard_error(monkeypatch, tmp_path):
    ls_remote_calls = 0
    sleeps = []

    def command(args, *, cwd, timeout=120):
        nonlocal ls_remote_calls
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            ls_remote_calls += 1
            raise publication.PublicationError("fatal: repository not found")
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)
    monkeypatch.setattr(publication.time, "sleep", sleeps.append)

    with pytest.raises(publication.PublicationError, match="repository not found"):
        publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    assert ls_remote_calls == 1
    assert sleeps == []


def test_refresh_upstream_branch_stops_after_two_transient_retries(monkeypatch, tmp_path):
    ls_remote_calls = 0
    sleeps = []

    def command(args, *, cwd, timeout=120):
        nonlocal ls_remote_calls
        if args == ["git", "remote"]:
            return "origin"
        if args[:3] == ["git", "remote", "get-url"]:
            return "https://github.com/example/project.git"
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            ls_remote_calls += 1
            raise publication.PublicationError("unexpected EOF while reading")
        raise AssertionError(args)

    monkeypatch.setattr(publication, "command", command)
    monkeypatch.setattr(publication.time, "sleep", sleeps.append)

    with pytest.raises(publication.PublicationError, match="unexpected EOF"):
        publication._refresh_upstream_branch(tmp_path, "example/project", "main")

    assert ls_remote_calls == 3
    assert sleeps == [0.25, 1.0]


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


def test_legacy_null_target_revalidation_allows_forward_only_and_rejects_fork():
    class BranchClient:
        def __init__(self, status, merge_base):
            self.status = status
            self.merge_base = merge_base

        def branch(self, repo, branch):
            return {"commit": {"sha": "b" * 40}}

        def compare(self, repo, base, head):
            return {
                "status": self.status,
                "merge_base_commit": {"sha": self.merge_base},
            }

    assert (
        publication._revalidate_legacy_target_base(
            BranchClient("ahead", "a" * 40),
            "example/project",
            "main",
            "a" * 40,
        )
        == "b" * 40
    )
    with pytest.raises(publication.PublicationError, match="drifted"):
        publication._revalidate_legacy_target_base(
            BranchClient("behind", "c" * 40),
            "example/project",
            "main",
            "a" * 40,
        )


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


def test_broker_reads_private_review_from_durable_runtime_state(monkeypatch, tmp_path):
    store, request, _ = prepared_request(tmp_path)
    source_review_root = tmp_path / "state" / "independent_reviews"
    durable_runtime = tmp_path / "runtime"
    durable_review_root = durable_runtime / "state" / "independent_reviews"
    durable_review_root.parent.mkdir(parents=True)
    source_review_root.rename(durable_review_root)
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])

    result = broker_publication_request(
        store,
        request["request_id"],
        client=Client(),
        review_state_root=durable_runtime,
    )

    assert result["granted"] is True
    assert result["audit"]["reason"] == "LIVE_PUBLICATION_GATES_PASSED"


def test_broker_forwards_historical_review_context(monkeypatch, tmp_path):
    store, request, _ = prepared_request(tmp_path)
    durable_runtime = tmp_path / "runtime"
    review_context = {"prFollowup": {"wakeDigest": "historical-wake"}}
    observed = {}

    def review_passed(root, value, *, state_root=None, review_context=None):
        observed.update(
            {
                "root": root,
                "value": value,
                "stateRoot": state_root,
                "reviewContext": review_context,
            }
        )
        return True

    monkeypatch.setattr(publication, "controller_review_passed", review_passed)
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])

    result = broker_publication_request(
        store,
        request["request_id"],
        client=Client(),
        review_state_root=durable_runtime,
        review_context=review_context,
    )

    assert result["granted"] is True
    assert observed["stateRoot"] == durable_runtime
    assert observed["reviewContext"] is review_context


def test_bound_evidence_snapshot_prevents_evidence_path_reread(monkeypatch, tmp_path):
    store, request, evidence_path = prepared_request(tmp_path)
    evidence_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])

    result = broker_publication_request(store, request["request_id"], client=Client())

    assert result["granted"] is True
    assert result["audit"]["reason"] == "LIVE_PUBLICATION_GATES_PASSED"


def test_bound_evidence_snapshot_blocks_request_field_replacement(tmp_path):
    store, request, _evidence_path = prepared_request(tmp_path)
    payload = dict(request["request"])
    payload["resultDigest"] = "replacement-digest"
    with store.connect() as connection:
        connection.execute(
            "UPDATE publication_requests SET request_json=? WHERE request_id=?",
            (json.dumps(payload, sort_keys=True), request["request_id"]),
        )

    audit = publication.audit_publication_request(store, request["request_id"], client=Client())

    assert audit.status == "BLOCK"
    assert audit.reason == "LOCAL_EVIDENCE_UNAVAILABLE"
    assert "resultDigest" in audit.evidence["error"]


@pytest.mark.parametrize(
    ("raw_base64", "error"),
    [
        ("not base64!!", "base64"),
        (base64.b64encode(b"\xff").decode("ascii"), "UTF-8"),
        (base64.b64encode(b"[]").decode("ascii"), "object"),
    ],
)
def test_publication_evidence_snapshot_rejects_invalid_encoding(tmp_path, raw_base64, error):
    _store, request, _evidence_path = prepared_request(tmp_path)
    payload = dict(request["request"])
    payload["evidenceRawBase64"] = raw_base64

    with pytest.raises(publication.PublicationError, match=error):
        publication.publication_evidence_from_request(payload)


def test_publication_evidence_snapshot_rejects_oversize_payload(tmp_path):
    _store, request, _evidence_path = prepared_request(tmp_path)
    payload = dict(request["request"])
    raw = b" " * (publication.MAX_PUBLICATION_EVIDENCE_BYTES + 1)
    payload["evidenceRawBase64"] = base64.b64encode(raw).decode("ascii")
    payload["evidenceDigest"] = hashlib.sha256(raw).hexdigest()

    with pytest.raises(publication.PublicationError, match="maximum size"):
        publication.publication_evidence_from_request(payload)


def test_legacy_task_result_evidence_requires_snapshot_even_through_symlink(tmp_path):
    worktree = tmp_path / "worktree"
    outside = tmp_path / "outside-private"
    worktree.mkdir()
    outside.mkdir()
    (worktree / ".oss-pr-radar").symlink_to(outside, target_is_directory=True)
    evidence = outside / "result.json"
    evidence.write_text("{}", encoding="utf-8")
    request = {
        "worktreePath": str(worktree),
        "evidencePath": str(evidence.resolve()),
        "evidenceDigest": hashlib.sha256(b"{}").hexdigest(),
    }

    with pytest.raises(publication.PublicationError, match="bound snapshot"):
        publication.publication_evidence_from_request(request)


def test_broker_blocks_legacy_request_without_private_review(monkeypatch, tmp_path):
    store, request, _ = prepared_request(tmp_path)
    monkeypatch.setattr(publication, "controller_review_passed", lambda _root, _value: False)
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])

    result = broker_publication_request(store, request["request_id"], client=Client())

    assert result["granted"] is False
    assert result["audit"]["reason"] == "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED"
    assert store.publication_request(request["request_id"])["status"] == "BLOCKED"


def test_broker_still_blocks_a_new_pr_when_a_strong_competitor_exists(tmp_path):
    store, request, _ = prepared_request(tmp_path)

    class CompetitionClient(Client):
        def related_open_prs(self, repo, number, **kwargs):
            return [{"number": 9, "_repo": repo}]

        def pull_request(self, repo, number):
            return {
                "number": number,
                "state": "open",
                "html_url": f"https://github.com/{repo}/pull/{number}",
                "title": "Fix streaming tool arguments",
                "body": "Fixes #7",
                "draft": False,
                "updated_at": "2026-08-09T01:00:00Z",
                "head": {"sha": "competing-head"},
            }

        def pull_files(self, repo, number):
            return [{"filename": "tests/test_streaming.py"}]

        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return [{"conclusion": "success"}]

    result = broker_publication_request(store, request["request_id"], client=CompetitionClient())

    assert result["granted"] is False
    assert result["pending"] is False
    assert result["audit"]["reason"] == "STRONG_EXISTING_PR"


def test_broker_defers_unresolved_exact_pr_validation_and_recovers(monkeypatch, tmp_path):
    store, request, _ = prepared_request(tmp_path)
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])

    class PendingCompetitionClient(Client):
        def related_open_prs(self, repo, number, **kwargs):
            return [{"number": 9, "_repo": repo}]

        def pull_request(self, repo, number):
            return {
                "number": number,
                "state": "open",
                "html_url": f"https://github.com/{repo}/pull/{number}",
                "title": "Fix streaming tool arguments",
                "body": "Fixes #7",
                "draft": False,
                "updated_at": "2026-08-09T01:00:00Z",
                "head": {"sha": "competing-head"},
            }

        def pull_files(self, repo, number):
            return [{"filename": "tests/test_streaming.py"}]

        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return [{"name": "Streaming tool arguments", "conclusion": None}]

    deferred = broker_publication_request(
        store,
        request["request_id"],
        client=PendingCompetitionClient(),
    )

    assert deferred["granted"] is False
    assert deferred["pending"] is True
    assert deferred["audit"]["reason"] == "EXISTING_PR_VALIDATION_PENDING"
    assert store.publication_request(request["request_id"])["status"] == "PENDING"
    with store.connect() as connection:
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE event_type='PUBLICATION_DEFERRED' ORDER BY id DESC LIMIT 1"""
        ).fetchone()
    payload = json.loads(event["payload_json"])
    relations = payload["auditEvidence"]["evidence"]["pull_relations"]
    assert relations[0]["url"] == "https://github.com/example/project/pull/9"
    assert relations[0]["targeted_check_unproven"] is True

    recovered = broker_publication_request(store, request["request_id"], client=Client())

    assert recovered["granted"] is True, recovered


@pytest.mark.parametrize("completion", ["direct", "effect"])
def test_followup_publication_is_bound_to_existing_pr_and_previous_head(tmp_path, completion):
    store, request, evidence_path = prepared_request(tmp_path)
    first = store.publication_request(request["request_id"])
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url=first["request"]["issueUrl"],
        commit_sha=first["commit_sha"],
        branch=first["branch"],
        evidence={"publication": first["request"]["publication"]},
    )
    store.consume_publication_permit(
        permit["permit_id"], "https://github.com/example/project/pull/8"
    )
    checked_at = iso_z(datetime.now(UTC))
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": checked_at,
            "items": [
                {
                    "url": "https://github.com/example/project/pull/8",
                    "headSha": first["commit_sha"],
                    "actionDigest": "old-action",
                    "taskActionDigest": "old-task-action",
                    "checkedAt": checked_at,
                    "taskActions": ["old head check failed"],
                    "taskFollowupRequired": True,
                    "evidence": {"actionableCheckNames": ["Old check"]},
                }
            ],
        }
    )
    assert store.pr_followup_candidates()
    worktree = tmp_path / "worktree"
    (worktree / "file.txt").write_text("fixed again\n", encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "Refine streaming fix", cwd=worktree)
    current = git("rev-parse", "HEAD", cwd=worktree)
    quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("example/project#7", "FIX_READY", evidence=quality)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    refresh_reproduction_evidence(
        evidence, worktree=worktree, tmp_path=tmp_path, commit_sha=current
    )
    evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    write_explicit_review_receipt(evidence, tmp_path=tmp_path)

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

    update_permit = store.grant_publication_request(
        update["request_id"],
        issue_url=payload["issueUrl"],
        commit_sha=payload["commitSha"],
        branch=payload["branch"],
        evidence={"publication": payload["publication"]},
    )
    if completion == "direct":
        store.consume_publication_permit(
            update_permit["permit_id"], "https://github.com/example/project/pull/8"
        )
    else:
        effect = store.publication_effect(
            permit_id=update_permit["permit_id"],
            action="create_pr",
            request_digest="confirm-update",
        )
        store.succeed_pull_request_effect(
            effect_id=effect["effect_id"],
            permit_id=update_permit["permit_id"],
            pr_url="https://github.com/example/project/pull/8",
            result={
                "ok": True,
                "prUrl": "https://github.com/example/project/pull/8",
            },
        )

    assert store.pr_followup_candidates() == []
    with store.connect() as connection:
        followup = connection.execute(
            """SELECT followup_required,wake_digest FROM pr_followups
               WHERE opportunity_key='example/project#7'"""
        ).fetchone()
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='example/project#7'
                 AND event_type='PR_FOLLOWUP_SNAPSHOT_SUPERSEDED'"""
        ).fetchone()
    assert dict(followup) == {"followup_required": 0, "wake_digest": None}
    assert json.loads(event["payload_json"])["commitSha"] == current


def test_broker_allows_bound_update_despite_a_competing_pr(monkeypatch, tmp_path):
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
    recovered_intent = dict(first["request"]["intent"])
    for field in ("category", "scanGate", "autoSpawn", "llmReview"):
        recovered_intent.pop(field, None)
    recovered_intent["recoveredFromTaskContext"] = True
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE opportunity_key='example/project#7'",
            (json.dumps(recovered_intent, sort_keys=True),),
        )
    worktree = tmp_path / "worktree"
    (worktree / "second.txt").write_text("follow-up fix\n", encoding="utf-8")
    git("add", "second.txt", cwd=worktree)
    git("commit", "-m", "Refine streaming fix", cwd=worktree)
    current = git("rev-parse", "HEAD", cwd=worktree)
    quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("example/project#7", "FIX_READY", evidence=quality)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    refresh_reproduction_evidence(
        evidence, worktree=worktree, tmp_path=tmp_path, commit_sha=current
    )
    evidence["changedFiles"] = ["file.txt", "second.txt"]
    evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    write_explicit_review_receipt(evidence, tmp_path=tmp_path)
    update = request_publication(
        store,
        issue_url="https://github.com/example/project/issues/7",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=evidence_path,
    )

    class UpdateClient(Client):
        def comments(self, repo, number):
            return [
                {
                    "body": "I'd like to work on this. I'll add regression coverage.",
                    "user": {"login": "argszero"},
                    "author_association": "NONE",
                    "created_at": "2026-08-26T02:36:59Z",
                },
                {
                    "body": (
                        "Standing down — I see PR #8 already addresses this. I'll defer to those."
                    ),
                    "user": {"login": "argszero"},
                    "author_association": "NONE",
                    "created_at": "2026-08-26T10:53:24Z",
                },
            ]

        def related_open_prs(self, repo, number, **kwargs):
            return [
                {"number": 8, "_repo": repo},
                {"number": 9, "_repo": repo},
            ]

        def pull_request(self, repo, number):
            if number == 9:
                return {
                    "number": 9,
                    "state": "open",
                    "html_url": "https://github.com/example/project/pull/9",
                    "title": "Fix streaming tool arguments",
                    "body": "Fixes #7",
                    "draft": False,
                    "updated_at": "2026-08-09T01:00:00Z",
                    "head": {"sha": "competing-head"},
                }
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

    monkeypatch.setattr(publication, "_changed_files_since", lambda *args: ["second.txt"])
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt", "second.txt"])
    result = broker_publication_request(store, update["request_id"], client=UpdateClient())

    assert result["granted"] is True
    assert result["audit"]["evidence"]["changedFiles"] == ["file.txt", "second.txt"]
    assert result["audit"]["evidence"]["updateChangedFiles"] == ["second.txt"]
    assert update["request"]["intent"]["recoveredFromTaskContext"] is True
    assert "scanGate" not in update["request"]["intent"]
    assert result["audit"]["evidence"]["publicationKind"] == "PR_UPDATE"
    relations = result["audit"]["evidence"]["evidence"]["pull_relations"]
    assert any(relation["url"].endswith("/pull/9") for relation in relations)

    push = store.publication_effect(
        permit_id=result["permit"]["permit_id"],
        action="push",
        request_digest="push-request",
    )
    store.complete_publication_effect(
        push["effect_id"],
        status="SUCCEEDED",
        result={"ok": True, "remoteSha": current},
    )

    class PushedClient(UpdateClient):
        def pull_request(self, repo, number):
            value = super().pull_request(repo, number)
            value["head"]["sha"] = current
            return value

    post_push = publication.audit_publication_request(
        store,
        update["request_id"],
        client=PushedClient(),
        expected_existing_pr_head=current,
    )
    assert post_push.status == "ALLOW"


def test_broker_allows_bound_update_when_related_pr_enrichment_is_partial(monkeypatch, tmp_path):
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
    refresh_reproduction_evidence(
        evidence, worktree=worktree, tmp_path=tmp_path, commit_sha=current
    )
    evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    write_explicit_review_receipt(evidence, tmp_path=tmp_path)
    update = request_publication(
        store,
        issue_url="https://github.com/example/project/issues/7",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=evidence_path,
    )

    class PartialRelationsClient(Client):
        def related_open_prs(self, repo, number, **kwargs):
            raise GitHubError("related PR checks are temporarily unavailable")

        def pull_request(self, repo, number):
            return {
                "number": number,
                "state": "open",
                "html_url": pr_url,
                "head": {
                    "sha": first["commit_sha"],
                    "ref": first["branch"],
                    "repo": {"owner": {"login": "Oxygen56"}},
                },
            }

    monkeypatch.setattr(publication, "_changed_files_since", lambda *args: ["file.txt"])
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])
    result = broker_publication_request(
        store, update["request_id"], client=PartialRelationsClient()
    )

    assert result["granted"] is True
    assert (
        result["audit"]["evidence"]["evidence"]["completeness"]["relatedPullRequests"]
        == "ERROR:related PR checks are temporarily unavailable"
    )


def test_merge_update_files_are_bound_to_exact_two_parent_commit(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    git("init", cwd=worktree)
    git("config", "user.name", "Tester", cwd=worktree)
    git("config", "user.email", "tester@example.com", cwd=worktree)
    source = worktree / "runtime.py"
    source.write_text("value = 'original'\n", encoding="utf-8")
    git("add", "runtime.py", cwd=worktree)
    git("commit", "-m", "chore: baseline", cwd=worktree)
    git("branch", "-M", "main", cwd=worktree)
    git("switch", "-c", "fix/runtime", cwd=worktree)
    source.write_text("value = 'pull-request'\n", encoding="utf-8")
    git("add", "runtime.py", cwd=worktree)
    git("commit", "-m", "fix: runtime", cwd=worktree)
    previous_head = git("rev-parse", "HEAD", cwd=worktree)
    git("switch", "main", cwd=worktree)
    source.write_text("value = 'upstream'\n", encoding="utf-8")
    git("add", "runtime.py", cwd=worktree)
    git("commit", "-m", "refactor: runtime", cwd=worktree)
    base_sha = git("rev-parse", "HEAD", cwd=worktree)
    git("switch", "fix/runtime", cwd=worktree)
    subprocess.run(
        ["git", "merge", "--no-commit", "--no-ff", base_sha],
        cwd=worktree,
        check=False,
        capture_output=True,
        text=True,
    )
    source.write_text("value = 'pull-request'\n", encoding="utf-8")
    git("add", "runtime.py", cwd=worktree)
    git("commit", "-m", "merge: refresh runtime branch", cwd=worktree)
    evidence = {
        "handoffMode": "controller_merge_complete",
        "mergeBaseSha": base_sha,
        "mergeResolutionFiles": ["runtime.py"],
        "controllerCommitChangedFiles": ["runtime.py"],
        "changedFiles": ["runtime.py"],
    }

    assert publication._changed_files_for_pr_update(worktree, previous_head, evidence) == [
        "runtime.py"
    ]
    with pytest.raises(publication.PublicationError, match="parent binding"):
        publication._changed_files_for_pr_update(
            worktree,
            previous_head,
            evidence | {"mergeBaseSha": "a" * 40},
        )
    with pytest.raises(publication.PublicationError, match="evidence is incomplete"):
        publication._changed_files_for_pr_update(
            worktree,
            previous_head,
            evidence | {"mergeResolutionFiles": ["forged.py"]},
        )


@pytest.mark.parametrize("live_branch_matches", [True, False])
def test_merge_update_uses_live_repository_base_not_pr_snapshot(
    tmp_path, live_branch_matches, monkeypatch
):
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
    previous_head = first["commit_sha"]
    git("switch", "-c", "upstream-base", f"{previous_head}^", cwd=worktree)
    (worktree / "file.txt").write_text("upstream\n", encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "refactor: update file", cwd=worktree)
    base_sha = git("rev-parse", "HEAD", cwd=worktree)
    git("switch", first["branch"], cwd=worktree)
    merge = subprocess.run(
        ["git", "merge", "--no-commit", "--no-ff", base_sha],
        cwd=worktree,
        check=False,
        capture_output=True,
        text=True,
    )
    assert merge.returncode == 1
    (worktree / "file.txt").write_text('assert "fixed" == "fixed"\n', encoding="utf-8")
    git("add", "file.txt", cwd=worktree)
    git("commit", "-m", "merge: refresh branch", cwd=worktree)
    current = git("rev-parse", "HEAD", cwd=worktree)
    quality = {field: True for field in QUALITY_FIELDS}
    store.record_stage("example/project#7", "FIX_READY", evidence=quality)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    refresh_reproduction_evidence(
        evidence, worktree=worktree, tmp_path=tmp_path, commit_sha=current
    )
    evidence.update(
        {
            "handoffMode": "controller_merge_complete",
            "previousCommitSha": previous_head,
            "mergeBaseSha": base_sha,
            "mergeResolutionFiles": ["file.txt"],
            "controllerCommitChangedFiles": ["file.txt"],
            "changedFiles": ["feature.py", "file.txt"],
        }
    )
    evidence_path.write_text(json.dumps(evidence, sort_keys=True), encoding="utf-8")
    exclude = worktree / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "\n.oss-pr-radar/\n", encoding="utf-8")
    private = worktree / ".oss-pr-radar"
    private.mkdir(exist_ok=True)
    (private / "task-context.json").write_text(
        json.dumps(
            {
                "prFollowup": {
                    "headSha": previous_head,
                    "evidence": {
                        "mergeConflict": True,
                        "baseSha": base_sha,
                        "mergeConflictFiles": ["file.txt"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    write_explicit_review_receipt(evidence, tmp_path=tmp_path)
    update = request_publication(
        store,
        issue_url="https://github.com/example/project/issues/7",
        thread_id="thread-1",
        worktree=worktree,
        evidence_path=evidence_path,
    )

    class AdvancedBaseClient(Client):
        def related_open_prs(self, repo, number, **kwargs):
            return [{"number": 8, "_repo": repo}]

        def pull_request(self, repo, number):
            return {
                "number": 8,
                "state": "open",
                "html_url": pr_url,
                "head": {
                    "sha": previous_head,
                    "ref": first["branch"],
                    "repo": {"owner": {"login": "Oxygen56"}},
                },
                "base": {
                    "sha": "d" * 40,
                    "ref": "main",
                    "repo": {"full_name": "example/project"},
                },
            }

        def branch(self, repo, branch):
            assert (repo, branch) == ("example/project", "main")
            return {"commit": {"sha": base_sha if live_branch_matches else "a" * 40}}

        def pull_files(self, repo, number):
            return [{"filename": "file.txt"}]

        def pull_reviews(self, repo, number):
            return []

        def check_runs(self, repo, ref):
            return []

    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["feature.py", "file.txt"])
    result = broker_publication_request(store, update["request_id"], client=AdvancedBaseClient())

    assert result["granted"] is live_branch_matches
    if live_branch_matches:
        assert result["audit"]["reason"] == "LIVE_PUBLICATION_GATES_PASSED"
        assert result["audit"]["evidence"]["changedFiles"] == ["feature.py", "file.txt"]
        assert result["audit"]["evidence"]["updateChangedFiles"] == ["file.txt"]
    else:
        assert result["audit"]["reason"] == "EXISTING_PR_BASE_DRIFT"


def test_evidence_snapshot_digest_drift_blocks_publication(monkeypatch, tmp_path):
    store, request, _evidence_path = prepared_request(tmp_path)
    payload = dict(request["request"])
    payload["evidenceRawBase64"] = base64.b64encode(b"{}").decode("ascii")
    with store.connect() as connection:
        connection.execute(
            "UPDATE publication_requests SET request_json=? WHERE request_id=?",
            (json.dumps(payload, sort_keys=True), request["request_id"]),
        )
    monkeypatch.setattr(publication, "_changed_files", lambda *args: ["file.txt"])

    result = broker_publication_request(store, request["request_id"], client=Client())
    assert result["granted"] is False
    assert result["audit"]["reason"] == "LOCAL_EVIDENCE_UNAVAILABLE"
    assert "digest" in result["audit"]["evidence"]["error"]


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
    legacy_event_payload = {"permitId": permit["permit_id"], "prUrl": result["prUrl"]}
    store.record_stage(
        "example/project#7",
        "PR_OPEN",
        evidence=legacy_event_payload,
        dedupe_key=result["prUrl"],
    )
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
        legacy_event = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='example/project#7'
                 AND event_type='PR_OPEN' AND dedupe_key=?""",
            (result["prUrl"],),
        ).fetchone()
    assert dict(permit_row) == {"status": "CONSUMED", "pr_url": result["prUrl"]}
    assert effect_row["status"] == "SUCCEEDED"
    assert opportunity["stage"] == "PR_OPEN"
    assert intent["status"] == "COMPLETED"
    assert json.loads(legacy_event["payload_json"]) == legacy_event_payload
    assert store.controller_publication_notice_candidates() == []
    assert store.publication_feedback_candidates()[0]["prUrl"] == result["prUrl"]
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
