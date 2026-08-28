import fcntl
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import oss_pr_radar.independent_review as module
from oss_pr_radar.metrics import QUALITY_FIELDS


def git(repo: Path, *args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def prepared_task(tmp_path: Path):
    control = tmp_path / "control"
    schema = control / "schemas" / "independent_review.schema.json"
    schema.parent.mkdir(parents=True)
    schema.write_text("{}", encoding="utf-8")

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    git(worktree, "init", "-b", "main")
    git(worktree, "config", "user.name", "Test User")
    git(worktree, "config", "user.email", "test@example.com")
    (worktree / ".gitignore").write_text(".oss-pr-radar/\n", encoding="utf-8")
    (worktree / "service.py").write_text("def value():\n    return 1\n", encoding="utf-8")
    git(worktree, "add", ".gitignore", "service.py")
    git(worktree, "commit", "-m", "base")
    base = git(worktree, "rev-parse", "HEAD")
    git(worktree, "switch", "-c", "fix/1")
    (worktree / "service.py").write_text("def value():\n    return 2\n", encoding="utf-8")
    git(worktree, "add", "service.py")
    git(worktree, "commit", "-m", "fix: return correct value")
    head = git(worktree, "rev-parse", "HEAD")

    private = worktree / ".oss-pr-radar"
    private.mkdir()
    result = {
        "schemaVersion": "radar-task-result-v1",
        "key": "owner/repo#1",
        "issueUrl": "https://github.com/owner/repo/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "stage": "FIX_READY",
        "handoffMode": "controller_commit_complete",
        "commitSha": head,
        "changedFiles": ["service.py"],
        "quality": {field: field != "independent_review_passed" for field in QUALITY_FIELDS},
        "evidence": {"summary": "focused regression passed"},
        "publication": {"baseBranch": "main"},
    }
    result_path = private / "result.json"
    result_path.write_text(json.dumps(result), encoding="utf-8")
    candidate = {
        "key": result["key"],
        "stage": "VALIDATION_PENDING",
        "issueUrl": result["issueUrl"],
        "threadId": result["threadId"],
        "worktreePath": str(worktree.resolve()),
    }
    return control, worktree, result_path, candidate, base, head


def test_review_once_binds_pass_to_exact_commit(tmp_path, monkeypatch):
    control, worktree, result_path, candidate, base, head = prepared_task(tmp_path)

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())
    seen = {}

    def reviewer(cwd, schema, prompt, timeout):
        seen.update(cwd=cwd, schema=schema, prompt=prompt, timeout=timeout)
        return {
            "verdict": "PASS",
            "summary": "The committed diff is narrowly scoped and correct.",
            "findings": [],
            "evidence": ["service.py is the complete committed diff"],
        }

    outcome = module.review_once(control, control / "ledger.sqlite3", reviewer=reviewer)
    value = json.loads(result_path.read_text(encoding="utf-8"))

    assert outcome["updated"] == [
        {
            "key": "owner/repo#1",
            "verdict": "PASS",
            "commitSha": head,
            "findingCount": 0,
        }
    ]
    assert value["quality"]["independent_review_passed"] is False
    assert "independentReview" not in value
    sidecar = json.loads(
        (worktree / ".oss-pr-radar" / "independent-review.json").read_text(encoding="utf-8")
    )
    assert sidecar["commitSha"] == head
    assert sidecar["baseRevision"] == base
    assert sidecar["reviewMode"] == "codex_exec_ephemeral_read_only"
    assert module.controller_review_passed(control, value) is True
    assert f"{base}..{head}" in seen["prompt"]
    assert seen["cwd"] == worktree


def test_review_receipt_survives_controller_result_receipt_rebinding(tmp_path, monkeypatch):
    control, _worktree, result_path, candidate, _base, head = prepared_task(tmp_path)

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())
    module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: {
            "verdict": "PASS",
            "summary": "The exact committed diff has no blocking finding.",
            "findings": [],
            "evidence": ["The implementation and regression test are narrowly scoped."],
        },
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    review = module.controller_review_result(control, value)
    assert review is not None

    value["quality"]["independent_review_passed"] = True
    value["independentReview"] = review
    value["resultDigest"] = "a" * 64
    value["contextDigest"] = "b" * 64
    value["controllerPolicyVerification"] = {"verifiedAt": "2026-08-21T00:00:00Z"}
    value["reproductionReceipt"] = {
        "commitSha": head,
        "resultDigest": "a" * 64,
        "receiptDigest": "c" * 64,
    }

    assert module.controller_review_passed(control, value) is True


def test_review_once_does_not_repeat_unchanged_hold(tmp_path, monkeypatch):
    control, _worktree, _result_path, candidate, _base, _head = prepared_task(tmp_path)

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    first = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: {
            "verdict": "HOLD",
            "summary": "The local evidence does not identify the lifecycle owner.",
            "findings": [],
            "evidence": ["The ownership contract is absent from the checkout."],
        },
    )
    assert first["updated"][0]["verdict"] == "HOLD"

    def reviewer(*_args):
        raise AssertionError("unchanged HOLD must wait for task evidence to change")

    outcome = module.review_once(control, control / "ledger.sqlite3", reviewer=reviewer)

    assert outcome["ok"] is True
    assert outcome["updated"] == []
    assert outcome["skipped"] == [{"key": "owner/repo#1", "reason": "REVIEW_HOLD_ALREADY_APPLIED"}]


def test_review_receipt_is_reused_across_code_releases(tmp_path, monkeypatch):
    release_a, _worktree, result_path, candidate, _base, head = prepared_task(tmp_path)
    release_b = tmp_path / "release-b"
    schema_b = release_b / "schemas" / "independent_review.schema.json"
    schema_b.parent.mkdir(parents=True)
    schema_b.write_text("{}", encoding="utf-8")
    state_root = tmp_path / "runtime"

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())
    first = module.review_once(
        release_a,
        release_a / "ledger.sqlite3",
        state_root=state_root,
        reviewer=lambda *_args: {
            "verdict": "PASS",
            "summary": "The exact committed diff has no blocking finding.",
            "findings": [],
            "evidence": ["The implementation and regression test are narrowly scoped."],
        },
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))

    assert first["updated"][0]["commitSha"] == head
    assert module.controller_review_passed(release_b, value, state_root=state_root) is True

    second = module.review_once(
        release_b,
        release_b / "ledger.sqlite3",
        state_root=state_root,
        reviewer=lambda *_args: (_ for _ in ()).throw(
            AssertionError("the durable receipt must be reused by the next code release")
        ),
    )

    assert second["ok"] is True
    assert second["updated"] == []
    assert second["skipped"] == [{"key": "owner/repo#1", "reason": "REVIEW_PASS_ALREADY_APPLIED"}]
    assert list((state_root / "state" / "independent_reviews").glob("*.json"))
    assert not (release_a / "state" / "independent_reviews").exists()
    assert not (release_b / "state" / "independent_reviews").exists()


def test_review_failures_and_cursor_are_shared_across_code_releases(tmp_path, monkeypatch):
    release_a, _worktree, result_path, candidate, _base, _head = prepared_task(tmp_path)
    release_b = tmp_path / "release-b"
    schema_b = release_b / "schemas" / "independent_review.schema.json"
    schema_b.parent.mkdir(parents=True)
    schema_b.write_text("{}", encoding="utf-8")
    state_root = tmp_path / "runtime"

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    def failing_reviewer(*_args):
        raise RuntimeError("review transport failed")

    first = module.review_once(
        release_a,
        release_a / "ledger.sqlite3",
        state_root=state_root,
        reviewer=failing_reviewer,
    )
    second = module.review_once(
        release_b,
        release_b / "ledger.sqlite3",
        state_root=state_root,
        reviewer=failing_reviewer,
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    cursor = json.loads(
        (state_root / "state" / "independent_review_cursor.json").read_text(encoding="utf-8")
    )

    assert first["errors"][0]["key"] == "owner/repo#1"
    assert second["errors"][0]["key"] == "owner/repo#1"
    assert cursor["key"] == "owner/repo#1"
    assert cursor["attempts"] == 2
    assert (
        module._review_failure_attempts(
            state_root,
            candidate=candidate,
            source_digest=module._source_digest(value),
            commit_sha=str(value["commitSha"]),
        )
        == 2
    )
    assert not (release_a / "state" / "independent_review_cursor.json").exists()
    assert not (release_b / "state" / "independent_review_cursor.json").exists()


def test_review_lock_is_shared_across_code_releases(tmp_path):
    release_a, _worktree, _result_path, _candidate, _base, _head = prepared_task(tmp_path)
    release_b = tmp_path / "release-b"
    schema_b = release_b / "schemas" / "independent_review.schema.json"
    schema_b.parent.mkdir(parents=True)
    schema_b.write_text("{}", encoding="utf-8")
    state_root = tmp_path / "runtime"
    lock_path = state_root / "state" / "independent_review.lock"
    lock_path.parent.mkdir(parents=True)

    with lock_path.open("a+", encoding="utf-8") as held_lock:
        module.fcntl.flock(held_lock.fileno(), module.fcntl.LOCK_EX | module.fcntl.LOCK_NB)
        outcome = module.review_once(
            release_b,
            release_b / "ledger.sqlite3",
            state_root=state_root,
            reviewer=lambda *_args: (_ for _ in ()).throw(
                AssertionError("a shared lock must prevent a second review")
            ),
        )

    assert outcome == {"ok": True, "busy": True, "updated": [], "skipped": []}
    assert lock_path.is_file()
    assert not (release_a / "state" / "independent_review.lock").exists()
    assert not (release_b / "state" / "independent_review.lock").exists()


def test_migrate_legacy_review_receipts_selects_latest_valid_identity(tmp_path):
    runtime_root = tmp_path / "runtime"
    key = "owner/repo#1"
    commit_sha = "a" * 40
    source_digest = "b" * 64

    def write_receipt(release: str, *, reviewed_at: str, verdict: str) -> Path:
        state_root = runtime_root / "releases" / release
        path = module._receipt_path(
            state_root,
            key=key,
            commit_sha=commit_sha,
            source_digest=source_digest,
        )
        path.parent.mkdir(parents=True)
        review = {
            "schemaVersion": "independent-review-v1",
            "reviewedAt": reviewed_at,
            "commitSha": commit_sha,
            "baseRevision": "c" * 40,
            "sourceDigest": source_digest,
            "reviewMode": "codex_exec_ephemeral_read_only",
            "verdict": verdict,
            "summary": f"The {release} review is structurally valid.",
            "findings": [],
            "evidence": [f"receipt from {release}"],
        }
        path.write_text(
            json.dumps(
                {
                    "schemaVersion": "independent-review-v1",
                    "key": key,
                    "commitSha": commit_sha,
                    "sourceDigest": source_digest,
                    "review": review,
                }
            ),
            encoding="utf-8",
        )
        return path

    older = write_receipt("release-a", reviewed_at="2026-08-27T00:00:00Z", verdict="PASS")
    latest = write_receipt("release-b", reviewed_at="2026-08-28T00:00:00Z", verdict="HOLD")
    invalid = older.parent / "wrong-name.json"
    invalid.write_text(older.read_text(encoding="utf-8"), encoding="utf-8")

    first = module.migrate_legacy_review_state(runtime_root)
    target = runtime_root / "state" / "independent_reviews" / latest.name
    migrated = json.loads(target.read_text(encoding="utf-8"))

    assert first == {
        "receiptsScanned": 3,
        "receiptsInvalid": 1,
        "receiptsMigrated": 1,
        "failuresScanned": 0,
        "failuresInvalid": 0,
        "failuresMigrated": 0,
        "cursorsScanned": 0,
        "cursorsInvalid": 0,
        "cursorsMigrated": 0,
    }
    assert migrated["review"]["reviewedAt"] == "2026-08-28T00:00:00Z"
    assert migrated["review"]["verdict"] == "HOLD"

    second = module.migrate_legacy_review_state(runtime_root)

    assert second["receiptsMigrated"] == 0
    assert json.loads(target.read_text(encoding="utf-8")) == migrated


def test_migrate_legacy_failures_and_cursor_accumulates_once_under_durable_lock(tmp_path):
    runtime_root = tmp_path / "runtime"
    key = "owner/repo#1"
    commit_sha = "a" * 40
    source_digest = "b" * 64

    for release, attempts, failed_at, error in (
        ("release-a", 3, "2026-08-27T00:00:00Z", "RuntimeError:older failure"),
        ("release-b", 1, "2026-08-28T00:00:00Z", "RuntimeError:latest failure"),
    ):
        state_root = runtime_root / "releases" / release
        failure_path = module._review_failure_path(
            state_root,
            candidate={"key": key},
            source_digest=source_digest,
            commit_sha=commit_sha,
        )
        failure_path.parent.mkdir(parents=True)
        failure_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "independent-review-failure-v1",
                    "key": key,
                    "sourceDigest": source_digest,
                    "commitSha": commit_sha,
                    "attempts": attempts,
                    "failedAt": failed_at,
                    "error": error,
                }
            ),
            encoding="utf-8",
        )
        (state_root / "state" / "independent_review.lock").write_text(
            "legacy lock must not migrate",
            encoding="utf-8",
        )

    cursor_a = runtime_root / "releases" / "release-a" / "state"
    (cursor_a / "independent_review_cursor.json").write_text(
        json.dumps(
            {
                "schemaVersion": "independent-review-cursor-v1",
                "key": key,
                "sourceDigest": source_digest,
                "commitSha": commit_sha,
                "attempts": 3,
                "failedAt": "2026-08-27T00:00:00Z",
                "error": "RuntimeError:older failure",
            }
        ),
        encoding="utf-8",
    )
    cursor_b = runtime_root / "releases" / "release-b" / "state"
    (cursor_b / "independent_review_cursor.json").write_text(
        json.dumps(
            {
                "schemaVersion": "independent-review-cursor-v1",
                "key": "owner/repo#2",
                "sourceDigest": "d" * 64,
                "commitSha": "e" * 40,
                "attempts": 0,
                "advancedAt": "2026-08-28T00:01:00Z",
                "reason": "RESULT_CHANGED_DURING_REVIEW",
            }
        ),
        encoding="utf-8",
    )

    first = module.migrate_legacy_review_state(runtime_root)
    target_failure = module._review_failure_path(
        runtime_root,
        candidate={"key": key},
        source_digest=source_digest,
        commit_sha=commit_sha,
    )
    migrated_failure = json.loads(target_failure.read_text(encoding="utf-8"))
    migrated_cursor = json.loads(
        (runtime_root / "state" / "independent_review_cursor.json").read_text(encoding="utf-8")
    )

    assert first["failuresScanned"] == 2
    assert first["failuresInvalid"] == 0
    assert first["failuresMigrated"] == 1
    assert first["cursorsScanned"] == 2
    assert first["cursorsInvalid"] == 0
    assert first["cursorsMigrated"] == 1
    assert migrated_failure["attempts"] == 4
    assert migrated_failure["legacyAttemptsImported"] == 4
    assert migrated_failure["failedAt"] == "2026-08-28T00:00:00Z"
    assert migrated_failure["error"] == "RuntimeError:latest failure"
    assert migrated_cursor["key"] == "owner/repo#2"
    assert migrated_cursor["reason"] == "RESULT_CHANGED_DURING_REVIEW"
    durable_lock = runtime_root / "state" / "independent_review.lock"
    assert durable_lock.is_file()
    assert durable_lock.read_text(encoding="utf-8") == ""

    second = module.migrate_legacy_review_state(runtime_root)

    assert second["failuresMigrated"] == 0
    assert second["cursorsMigrated"] == 0

    module._record_review_failure(
        runtime_root,
        candidate={"key": key},
        source_digest=source_digest,
        commit_sha=commit_sha,
        error=RuntimeError("durable failure"),
    )
    after_durable_attempt = json.loads(target_failure.read_text(encoding="utf-8"))
    assert after_durable_attempt["attempts"] == 5
    assert after_durable_attempt["legacyAttemptsImported"] == 4

    third = module.migrate_legacy_review_state(runtime_root)

    assert third["failuresMigrated"] == 0
    assert json.loads(target_failure.read_text(encoding="utf-8"))["attempts"] == 5

    rollback_failure = module._review_failure_path(
        runtime_root / "releases" / "release-b",
        candidate={"key": key},
        source_digest=source_digest,
        commit_sha=commit_sha,
    )
    rollback_value = json.loads(rollback_failure.read_text(encoding="utf-8"))
    rollback_value |= {
        "attempts": 2,
        "failedAt": "2026-08-29T00:00:00Z",
        "error": "RuntimeError:rollback failure",
    }
    rollback_failure.write_text(json.dumps(rollback_value), encoding="utf-8")

    fourth = module.migrate_legacy_review_state(runtime_root)
    after_rollback = json.loads(target_failure.read_text(encoding="utf-8"))

    assert fourth["failuresMigrated"] == 1
    assert after_rollback["attempts"] == 6
    assert after_rollback["legacyAttemptsImported"] == 5
    assert after_rollback["error"] == "RuntimeError:rollback failure"


def test_migrate_legacy_review_state_refuses_concurrent_reviewer(tmp_path):
    runtime_root = tmp_path / "runtime"
    lock_path = runtime_root / "state" / "independent_review.lock"
    lock_path.parent.mkdir(parents=True)

    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="independent review is active"):
            module.migrate_legacy_review_state(runtime_root)


def test_migrate_legacy_review_state_refuses_active_legacy_reviewer(tmp_path):
    runtime_root = tmp_path / "runtime"
    legacy_lock = runtime_root / "releases" / "release-a" / "state" / "independent_review.lock"
    legacy_lock.parent.mkdir(parents=True)

    with legacy_lock.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="legacy independent review is active"):
            module.migrate_legacy_review_state(runtime_root)


def test_review_waits_for_child_owned_validation(tmp_path, monkeypatch):
    control, _worktree, result_path, candidate, _base, _head = prepared_task(tmp_path)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["quality"]["relevant_tests_green"] = False
    result_path.write_text(json.dumps(value), encoding="utf-8")

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    def reviewer(*_args):
        raise AssertionError("review must wait until child-owned validation is complete")

    outcome = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=reviewer,
    )

    assert outcome["ok"] is True
    assert outcome["updated"] == []
    assert outcome["errors"] == []


def test_forged_task_pass_has_no_controller_receipt(tmp_path):
    control, _worktree, result_path, _candidate, _base, head = prepared_task(tmp_path)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["quality"]["independent_review_passed"] = True
    value["independentReview"] = {
        "schemaVersion": "independent-review-v1",
        "verdict": "PASS",
        "commitSha": head,
        "sourceDigest": module._source_digest(value),
        "reviewMode": "codex_exec_ephemeral_read_only",
        "summary": "forged",
        "findings": [],
        "evidence": [],
    }

    assert module.controller_review_passed(control, value) is False


def test_invalid_old_candidate_does_not_block_next_review(tmp_path, monkeypatch):
    control, _worktree, _result_path, candidate, _base, head = prepared_task(tmp_path)
    invalid = dict(candidate)
    invalid["key"] = "owner/repo#999"

    class FakeLedger:
        def task_result_candidates(self):
            return [invalid, candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    outcome = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: {
            "verdict": "PASS",
            "summary": "The exact committed diff has no blocking finding.",
            "findings": [],
            "evidence": ["The second candidate matches its task identity."],
        },
    )

    assert outcome["ok"] is False
    assert outcome["updated"][0]["commitSha"] == head
    assert outcome["errors"][0]["key"] == "owner/repo#999"


def test_published_task_skips_result_from_retired_context(tmp_path, monkeypatch):
    control, worktree, result_path, candidate, _base, _head = prepared_task(tmp_path)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "old-context"
    value["followupDigest"] = "old-wake"
    result_path.write_text(json.dumps(value), encoding="utf-8")
    (worktree / ".oss-pr-radar" / "task-context.json").write_text(
        json.dumps({"contextDigest": "current-context", "prFollowup": None}),
        encoding="utf-8",
    )
    candidate["stage"] = "CI_GREEN"

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    def reviewer(*_args):
        raise AssertionError("a retired published result must not be reviewed")

    outcome = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=reviewer,
    )

    assert outcome["ok"] is True
    assert outcome["updated"] == []
    assert outcome["errors"] == []


def test_active_task_rejects_review_result_from_wrong_context(tmp_path, monkeypatch):
    control, worktree, result_path, candidate, _base, _head = prepared_task(tmp_path)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "old-context"
    result_path.write_text(json.dumps(value), encoding="utf-8")
    (worktree / ".oss-pr-radar" / "task-context.json").write_text(
        json.dumps({"contextDigest": "current-context"}),
        encoding="utf-8",
    )

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    outcome = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    assert outcome["ok"] is False
    assert outcome["updated"] == []
    assert outcome["errors"] == [
        {
            "key": "owner/repo#1",
            "error": "RuntimeError:independent review task result context digest mismatch",
        }
    ]


def test_review_discards_changed_result_and_rotates_to_next_candidate(tmp_path, monkeypatch):
    control, worktree_one, result_path, candidate_one, _base, _head = prepared_task(
        tmp_path / "one"
    )
    (
        _control_two,
        worktree_two,
        result_two,
        candidate_two,
        _base_two,
        head_two,
    ) = prepared_task(tmp_path / "two")
    second_value = json.loads(result_two.read_text(encoding="utf-8"))
    second_value.update(
        {
            "key": "owner/repo#2",
            "issueUrl": "https://github.com/owner/repo/issues/2",
            "threadId": "thread-2",
        }
    )
    result_two.write_text(json.dumps(second_value), encoding="utf-8")
    candidate_two.update(
        {
            "key": second_value["key"],
            "issueUrl": second_value["issueUrl"],
            "threadId": second_value["threadId"],
        }
    )

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate_one, candidate_two]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    def changing_reviewer(cwd, *_args):
        assert cwd == worktree_one
        latest = json.loads(result_path.read_text(encoding="utf-8"))
        latest["evidence"]["summary"] = "validation evidence changed during review"
        result_path.write_text(json.dumps(latest), encoding="utf-8")
        return {
            "verdict": "PASS",
            "summary": "The stale snapshot looked correct.",
            "findings": [],
            "evidence": ["This verdict must be discarded."],
        }

    outcome = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=changing_reviewer,
    )
    latest = json.loads(result_path.read_text(encoding="utf-8"))
    cursor = json.loads(
        (control / "state" / "independent_review_cursor.json").read_text(encoding="utf-8")
    )

    assert outcome["updated"] == []
    assert outcome["skipped"] == [{"key": "owner/repo#1", "reason": "RESULT_CHANGED_DURING_REVIEW"}]
    assert module.controller_review_passed(control, latest) is False
    assert cursor["key"] == "owner/repo#1"
    assert cursor["attempts"] == 0
    assert cursor["reason"] == "RESULT_CHANGED_DURING_REVIEW"

    observed = []

    def passing_reviewer(cwd, *_args):
        observed.append(cwd)
        return {
            "verdict": "PASS",
            "summary": "The next candidate has no blocking finding.",
            "findings": [],
            "evidence": ["The changed candidate did not monopolize the queue."],
        }

    second = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=passing_reviewer,
    )

    assert observed == [worktree_two]
    assert second["updated"][0]["key"] == "owner/repo#2"
    assert second["updated"][0]["commitSha"] == head_two


def test_reviewer_failure_rotates_to_next_candidate(tmp_path, monkeypatch):
    control, worktree_one, _result_one, candidate_one, _base_one, _head_one = prepared_task(
        tmp_path / "one"
    )
    (
        _control_two,
        worktree_two,
        result_two,
        candidate_two,
        _base_two,
        head_two,
    ) = prepared_task(tmp_path / "two")
    second_value = json.loads(result_two.read_text(encoding="utf-8"))
    second_value.update(
        {
            "key": "owner/repo#2",
            "issueUrl": "https://github.com/owner/repo/issues/2",
            "threadId": "thread-2",
        }
    )
    result_two.write_text(json.dumps(second_value), encoding="utf-8")
    candidate_two.update(
        {
            "key": second_value["key"],
            "issueUrl": second_value["issueUrl"],
            "threadId": second_value["threadId"],
        }
    )

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate_one, candidate_two]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    first = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: (_ for _ in ()).throw(RuntimeError("review transport failed")),
    )
    assert first["updated"] == []
    assert first["errors"][0]["key"] == "owner/repo#1"
    cursor = json.loads(
        (control / "state" / "independent_review_cursor.json").read_text(encoding="utf-8")
    )
    assert cursor["key"] == "owner/repo#1"
    observed = []

    def reviewer(cwd, *_args):
        observed.append(cwd)
        return {
            "verdict": "PASS",
            "summary": "The next candidate has no blocking finding.",
            "findings": [],
            "evidence": ["The failed candidate did not block the queue."],
        }

    second = module.review_once(control, control / "ledger.sqlite3", reviewer=reviewer)

    assert observed == [worktree_two]
    assert second["updated"][0]["key"] == "owner/repo#2"
    assert second["updated"][0]["commitSha"] == head_two
    assert worktree_one.is_dir()


def test_review_retry_stops_after_three_failures_for_the_same_result(tmp_path, monkeypatch):
    control, _worktree, _result_path, candidate, _base, head = prepared_task(tmp_path)

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())
    attempts = 0

    def failing_reviewer(*_args):
        nonlocal attempts
        attempts += 1
        raise RuntimeError("review transport failed")

    for expected in (1, 2, 3):
        outcome = module.review_once(
            control,
            control / "ledger.sqlite3",
            reviewer=failing_reviewer,
        )
        assert outcome["errors"][0]["key"] == "owner/repo#1"
        cursor = json.loads(
            (control / "state" / "independent_review_cursor.json").read_text(encoding="utf-8")
        )
        assert cursor["attempts"] == expected

    exhausted = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: (_ for _ in ()).throw(
            AssertionError("an exhausted unchanged result must not run again")
        ),
    )

    assert attempts == 3
    assert exhausted["errors"] == []
    assert len(exhausted["retryExhausted"]) == 1
    assert exhausted["retryExhausted"][0] == {
        "key": "owner/repo#1",
        "reason": "INDEPENDENT_REVIEW_RETRY_EXHAUSTED",
        "attempts": 3,
        "sourceDigest": exhausted["retryExhausted"][0]["sourceDigest"],
        "commitSha": head,
    }


def test_review_retry_counts_survive_alternating_candidate_failures(tmp_path, monkeypatch):
    control, _worktree_one, result_one, candidate_one, _base_one, _head_one = prepared_task(
        tmp_path / "one"
    )
    _control_two, _worktree_two, result_two, candidate_two, _base_two, _head_two = prepared_task(
        tmp_path / "two"
    )
    second_value = json.loads(result_two.read_text(encoding="utf-8"))
    second_value.update(
        {
            "key": "owner/repo#2",
            "issueUrl": "https://github.com/owner/repo/issues/2",
            "threadId": "thread-2",
        }
    )
    result_two.write_text(json.dumps(second_value), encoding="utf-8")
    candidate_two.update(
        {
            "key": second_value["key"],
            "issueUrl": second_value["issueUrl"],
            "threadId": second_value["threadId"],
        }
    )

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate_one, candidate_two]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())

    def failing_reviewer(*_args):
        raise RuntimeError("review transport failed")

    for _ in range(6):
        module.review_once(control, control / "ledger.sqlite3", reviewer=failing_reviewer)

    first_value = json.loads(result_one.read_text(encoding="utf-8"))
    first_attempts = module._review_failure_attempts(
        control,
        candidate=candidate_one,
        source_digest=module._source_digest(first_value),
        commit_sha=str(first_value["commitSha"]),
    )
    second_attempts = module._review_failure_attempts(
        control,
        candidate=candidate_two,
        source_digest=module._source_digest(second_value),
        commit_sha=str(second_value["commitSha"]),
    )

    assert first_attempts == 3
    assert second_attempts == 3
    exhausted = module.review_once(
        control,
        control / "ledger.sqlite3",
        reviewer=lambda *_args: (_ for _ in ()).throw(
            AssertionError("both unchanged results are exhausted")
        ),
    )
    assert {item["key"] for item in exhausted["retryExhausted"]} == {
        "owner/repo#1",
        "owner/repo#2",
    }


def test_review_followup_is_bound_to_new_commit_only(tmp_path, monkeypatch):
    control, worktree, result_path, candidate, _base, previous_head = prepared_task(tmp_path)
    (worktree / "service.py").write_text("def value():\n    return 3\n", encoding="utf-8")
    git(worktree, "add", "service.py")
    git(worktree, "commit", "-m", "fix: address review feedback")
    head = git(worktree, "rev-parse", "HEAD")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value.update(
        {
            "commitSha": head,
            "previousCommitSha": previous_head,
            "controllerCommitChangedFiles": ["service.py"],
        }
    )
    result_path.write_text(json.dumps(value), encoding="utf-8")
    candidate["stage"] = "PR_OPEN"

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())
    observed = {}

    def reviewer(_cwd, _schema, prompt, _timeout):
        observed["prompt"] = prompt
        return {
            "verdict": "PASS",
            "summary": "The follow-up commit addresses the requested behavior.",
            "findings": [],
            "evidence": ["The exact follow-up commit changes service.py."],
        }

    outcome = module.review_once(control, control / "ledger.sqlite3", reviewer=reviewer)
    latest = json.loads(result_path.read_text(encoding="utf-8"))

    assert outcome["updated"][0]["commitSha"] == head
    assert f"{previous_head}..{head}" in observed["prompt"]
    assert module.controller_review_passed(control, latest) is True


def test_review_supports_controller_merge_resolution(tmp_path, monkeypatch):
    control, worktree, result_path, candidate, _base, previous_head = prepared_task(tmp_path)
    git(worktree, "switch", "main")
    (worktree / "service.py").write_text("def value():\n    return 4\n", encoding="utf-8")
    git(worktree, "add", "service.py")
    git(worktree, "commit", "-m", "refactor: update upstream value")
    merge_base = git(worktree, "rev-parse", "HEAD")
    git(worktree, "switch", "fix/1")
    completed = subprocess.run(
        ["git", "merge", "--no-commit", "--no-ff", "main"],
        cwd=worktree,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    (worktree / "service.py").write_text("def value():\n    return 5\n", encoding="utf-8")
    git(worktree, "add", "service.py")
    git(worktree, "commit", "-m", "merge: resolve service value")
    head = git(worktree, "rev-parse", "HEAD")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value.update(
        {
            "commitSha": head,
            "handoffMode": "controller_merge_complete",
            "previousCommitSha": previous_head,
            "mergeBaseSha": merge_base,
            "controllerCommitChangedFiles": ["service.py"],
            "mergeResolutionFiles": ["service.py"],
        }
    )
    result_path.write_text(json.dumps(value), encoding="utf-8")
    candidate["stage"] = "PR_OPEN"

    class FakeLedger:
        def task_result_candidates(self):
            return [candidate]

    monkeypatch.setattr(module, "RadarLedger", lambda _path: FakeLedger())
    observed = {}

    def reviewer(_cwd, _schema, prompt, _timeout):
        observed["prompt"] = prompt
        return {
            "verdict": "PASS",
            "summary": "The conflict resolution preserves both intended behaviors.",
            "findings": [],
            "evidence": ["The resolution was compared with both merge parents."],
        }

    outcome = module.review_once(control, control / "ledger.sqlite3", reviewer=reviewer)

    assert outcome["updated"][0]["commitSha"] == head
    assert previous_head in observed["prompt"]
    assert merge_base in observed["prompt"]
    assert "merge resolution" in observed["prompt"]


def test_pass_with_blocking_finding_is_normalized_to_fail():
    review = module._normalized_review(
        {
            "verdict": "PASS",
            "summary": "A blocking regression remains.",
            "findings": [
                {
                    "severity": "P2",
                    "file": "service.py",
                    "line": 2,
                    "message": "The fallback path still returns the stale value.",
                }
            ],
            "evidence": ["Read the fallback branch."],
        }
    )

    assert review["verdict"] == "FAIL"


def test_codex_runner_is_ephemeral_and_read_only(tmp_path, monkeypatch):
    schema = tmp_path / "schemas" / "independent_review.schema.json"
    schema.parent.mkdir(parents=True)
    schema.write_text("{}", encoding="utf-8")
    worktree = tmp_path / "repo"
    worktree.mkdir()
    observed = {}

    monkeypatch.setattr(module.shutil, "which", lambda _name: "/opt/bin/codex")
    monkeypatch.setenv("FEISHU_APP_SECRET", "must-not-reach-reviewer")

    def run(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        output = Path(argv[argv.index("--output-last-message") + 1])
        output.write_text(
            json.dumps(
                {
                    "verdict": "PASS",
                    "summary": "No blocking findings.",
                    "findings": [],
                    "evidence": [],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module.subprocess, "run", run)
    result = module.codex_review_runner(worktree, schema, "review prompt", 321)

    assert result["verdict"] == "PASS"
    assert "--ephemeral" in observed["argv"]
    assert observed["argv"][observed["argv"].index("--sandbox") + 1] == "read-only"
    assert "--ignore-user-config" in observed["argv"]
    assert observed["argv"][observed["argv"].index("--disable") + 1] == "plugins"
    assert "--skip-git-repo-check" in observed["argv"]
    assert "project_doc_max_bytes=0" in observed["argv"]
    assert observed["argv"][observed["argv"].index("--add-dir") + 1] == str(worktree)
    assert observed["argv"][observed["argv"].index("--cd") + 1] != str(worktree)
    assert observed["kwargs"]["cwd"] != worktree
    assert "FEISHU_APP_SECRET" not in observed["kwargs"]["env"]
    assert "--output-schema" in observed["argv"]
    assert observed["kwargs"]["timeout"] == 321
