from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from oss_pr_radar.ledger import RadarLedger
from oss_pr_radar.managed_lifecycle import (
    ManagedLedger,
    PublicationAbsenceReconciler,
    copy_database,
    export_projection,
    import_open_pr_observations,
    is_maintainer_actor,
    legacy_content_snapshot,
    migrate_schema,
    pr_key_from_url,
    rollback_schema,
    summarize_open_prs,
)

pytestmark = pytest.mark.usefixtures("current_signing_key")


def new_ledger(tmp_path):
    database = tmp_path / "ledger.sqlite3"
    RadarLedger(database)
    return database, ManagedLedger(database, ensure_schema=True)


def test_result_semantics_require_new_head_and_validation(tmp_path):
    _, ledger = new_ledger(tmp_path)
    ledger.bind_task(
        task_id="task-1",
        opportunity_key="owner/repo#1",
        thread_id="thread-1",
        worktree_path="/tmp/task-1",
    )
    queued = ledger.record_result(task_id="task-1", result_digest="queued", worker_state="queued")
    assert queued["state"] == "SYSTEM_PROCESSING"
    needs_human = ledger.record_result(
        task_id="task-1", result_digest="human", worker_state="needs_human"
    )
    assert needs_human["state"] == "DECISION_REQUIRED"
    skipped = ledger.record_result(
        task_id="task-1", result_digest="skip", worker_state="skipped", waiting_external=True
    )
    assert skipped["state"] == "WAITING_EXTERNAL"
    rejected = ledger.record_result(
        task_id="task-1",
        result_digest="bad-patch",
        worker_state="patched",
        commit_sha="commit-1",
        validation={"passed": True, "evidence": []},
        prior_head_sha="head-1",
        new_head_sha="head-2",
    )
    assert rejected["advanced"] is False
    accepted = ledger.record_result(
        task_id="task-1",
        result_digest="good-patch",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#1",
        head_sha="head-2",
        commit_sha="commit-1",
        validation={"passed": True, "evidence": ["pytest:1"]},
        prior_head_sha="head-1",
        new_head_sha="head-2",
    )
    assert accepted["state"] == "PORTFOLIO_READY"
    assert accepted["advanced"] is True
    replay = ledger.record_result(
        task_id="task-1",
        result_digest="good-patch",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#1",
        head_sha="head-2",
        commit_sha="commit-1",
        validation={"passed": True, "evidence": ["pytest:1"]},
        prior_head_sha="head-1",
        new_head_sha="head-2",
    )
    assert replay["created"] is False
    reclassified = ledger.record_result(
        task_id="task-1",
        result_digest="reclassified",
        worker_state="needs_human",
        result_type="task_no_go",
        pr_key="owner/repo#1",
        head_sha="head-2",
    )
    assert reclassified["created"] is True
    with ledger._connection() as connection:
        current = connection.execute(
            "SELECT result_type,is_current FROM managed_results WHERE task_id=? AND pr_key=? AND head_sha=? ORDER BY result_digest",
            ("task-1", "owner/repo#1", "head-2"),
        ).fetchall()
        assert [row["is_current"] for row in current].count(1) == 1
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE event_type='RESULT_CLASSIFICATION_SUPERSEDED'"
            ).fetchone()[0]
            == 1
        )


def test_maintainer_qualification_and_public_reply_policy(tmp_path):
    _, ledger = new_ledger(tmp_path)
    ledger.upsert_pr(
        pr_key="owner/repo#1",
        owner="owner",
        repo="repo",
        number=1,
        head_sha="head-1",
        pr_url="https://github.com/owner/repo/pull/1",
        state="OPEN",
        auto_created=True,
    )
    assert is_maintainer_actor(actor_type="User", actor_login="octocat", author_association="OWNER")
    assert not is_maintainer_actor(
        actor_type="Bot", actor_login="octocat[bot]", author_association="OWNER"
    )
    assert not is_maintainer_actor(
        actor_type="User", actor_login="ordinary", author_association="NONE"
    )
    assert not is_maintainer_actor(
        actor_type="User",
        actor_login="ordinary",
        author_association="NONE",
        verified_permission=True,
    )
    ledger.bind_task(
        task_id="task-1",
        opportunity_key="owner/repo#1",
        thread_id="thread-1",
        worktree_path="/tmp/task-1",
    )
    ledger.record_result(
        task_id="task-1",
        result_digest="reply-result",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#1",
        head_sha="head-1",
        commit_sha="commit-1",
        validation={"passed": True, "evidence": ["objective-test"]},
        prior_head_sha="old-head",
        new_head_sha="head-1",
    )
    ledger.record_ci_run(
        ci_key="reply-ci",
        pr_key="owner/repo#1",
        head_sha="head-1",
        status="PASSED",
    )
    event = ledger.record_maintainer_event(
        event_key="event-1",
        pr_key="owner/repo#1",
        event_type="COMMENT",
        actor_login="octocat",
        actor_type="User",
        author_association="OWNER",
        payload={"explicit_mechanical_request": True, "targetPrKey": "owner/repo#1"},
    )
    assert event["isMaintainer"] is True
    allowed = ledger.prepare_public_reply(
        pr_key="owner/repo#1",
        maintainer_event_key="event-1",
        result_digest="reply-result",
        proposed_body="Fixed as requested.",
        completed=False,
        objective_validation=False,
    )
    assert allowed["mode"] == "AUTO_REPLY_ALLOWED"
    assert (
        ledger.prepare_public_reply(
            pr_key="owner/repo#1",
            maintainer_event_key="event-1",
            result_digest="reply-result",
            proposed_body="Fixed as requested.",
            completed=True,
            objective_validation=True,
        )["created"]
        is False
    )
    blocked = ledger.prepare_public_reply(
        pr_key="owner/repo#1",
        maintainer_event_key="event-1",
        result_digest="missing-result",
        proposed_body="Please review.",
        completed=False,
        objective_validation=False,
        uncertainty={"policy_uncertainty": True},
    )
    assert blocked["mode"] == "DRAFT"


def test_reply_outbox_revalidates_and_is_idempotent(tmp_path):
    _, ledger = new_ledger(tmp_path)
    ledger.upsert_pr(
        pr_key="owner/repo#2",
        owner="owner",
        repo="repo",
        number=2,
        head_sha="head-2",
        pr_url="https://github.com/owner/repo/pull/2",
        state="OPEN",
        auto_created=True,
    )
    ledger.record_maintainer_event(
        event_key="mechanical-2",
        pr_key="owner/repo#2",
        event_type="COMMENT",
        actor_login="maintainer",
        actor_type="User",
        author_association="MEMBER",
        payload={"targetPrKey": "owner/repo#2", "explicit_mechanical_request": True},
    )
    draft = ledger.prepare_public_reply(
        pr_key="owner/repo#2",
        maintainer_event_key="mechanical-2",
        result_digest="later",
        proposed_body="Please review.",
        completed=True,
        objective_validation=True,
    )
    assert draft["mode"] == "DRAFT"

    ledger.bind_task(
        task_id="task-2", opportunity_key="owner/repo#2", thread_id=None, worktree_path=None
    )
    ledger.record_result(
        task_id="task-2",
        result_digest="later",
        worker_state="patched",
        result_type="state_drift",
        pr_key="owner/repo#2",
        head_sha="head-2",
        commit_sha="commit-2",
        validation={"passed": True, "evidence": ["test"]},
        prior_head_sha="old-head",
        new_head_sha="head-2",
    )
    ledger.record_ci_run(ci_key="ci-2", pr_key="owner/repo#2", head_sha="head-2", status="PASSED")
    allowed = ledger.queue_public_reply(
        pr_key="owner/repo#2",
        maintainer_event_key="mechanical-2",
        result_digest="later",
        proposed_body="Implemented the requested mechanical change; validation passed.",
    )
    assert allowed["mode"] == "AUTO_REPLY_ALLOWED"
    sent = []

    def fake_sender(**payload):
        sent.append(payload)
        return {"id": "comment-2"}

    def live_revalidator(**payload):
        return {
            "headSha": payload["head_sha"],
            "ciStatus": "PASSED",
            "maintainerEventKey": payload["maintainer_event_key"],
            "resultDigest": payload["result_digest"],
            "certificateVerified": True,
        }

    assert ledger.dispatch_reply_outbox(fake_sender, live_revalidator=live_revalidator) == {
        "attempted": 1,
        "sent": 1,
        "blocked": 0,
        "errors": [],
    }
    assert (
        ledger.dispatch_reply_outbox(fake_sender, live_revalidator=live_revalidator)["attempted"]
        == 0
    )
    assert sent[0]["reply_key"] == "owner/repo#2|mechanical-2|later"
    with ledger._connection() as connection:
        assert (
            connection.execute(
                "SELECT state FROM managed_reply_deliveries WHERE reply_key=?",
                (sent[0]["reply_key"],),
            ).fetchone()[0]
            == "SENT"
        )


def test_repo_cap_has_two_gates_and_verified_invitation_exemption(tmp_path):
    _, ledger = new_ledger(tmp_path)
    for number in range(1, 6):
        ledger.upsert_pr(
            pr_key=f"owner/repo#{number}",
            owner="owner",
            repo="repo",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=True,
        )
    assert ledger.open_unanswered_auto_pr_count("repo") == 5
    assert ledger.task_creation_gate(repo="repo")["allowed"] is False
    assert ledger.publication_gate(repo="repo")["allowed"] is False
    with pytest.raises(PermissionError):
        ledger.upsert_pr(
            pr_key="owner/repo#6",
            owner="owner",
            repo="repo",
            number=6,
            head_sha="head-6",
            pr_url="https://github.com/owner/repo/pull/6",
            state="OPEN",
            auto_created=True,
        )
    invitation = ledger.record_maintainer_event(
        event_key="invite-7",
        pr_key="owner/repo#7",
        event_type="INVITATION",
        actor_login="owner",
        actor_type="User",
        author_association="OWNER",
        opportunity_key="owner/repo#7",
        payload={"targetPrKey": "owner/repo#7", "opportunityKey": "owner/repo#7"},
    )
    assert invitation["isMaintainer"] is True
    assert ledger.task_creation_gate(
        repo="owner/repo", invitation_event_key="invite-7", opportunity_key="owner/repo#7"
    )["allowed"]
    assert not ledger.publication_gate(
        repo="owner/repo", invitation_event_key="invite-7", pr_key="owner/repo#6"
    )["allowed"]
    ledger.record_maintainer_event(
        event_key="invite-6",
        pr_key="owner/repo#6",
        event_type="INVITATION",
        actor_login="owner",
        actor_type="User",
        author_association="OWNER",
        payload={"targetPrKey": "owner/repo#6"},
    )
    ledger.upsert_pr(
        pr_key="owner/repo#6",
        owner="owner",
        repo="repo",
        number=6,
        head_sha="head-6",
        pr_url="https://github.com/owner/repo/pull/6",
        state="OPEN",
        auto_created=True,
        invitation_event_key="invite-6",
    )


def test_existing_observation_cannot_become_sixth_automatic_pr(tmp_path):
    _, ledger = new_ledger(tmp_path)
    for number in range(1, 6):
        ledger.upsert_pr(
            pr_key=f"owner/repo#{number}",
            owner="owner",
            repo="repo",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=True,
        )
    ledger.upsert_pr(
        pr_key="owner/repo#6",
        owner="owner",
        repo="repo",
        number=6,
        head_sha="observed-head-6",
        pr_url="https://github.com/owner/repo/pull/6",
        state="OPEN",
        auto_created=False,
        source_kind="EXISTING_OPEN_PR",
    )
    row = ledger.upsert_pr(
        pr_key="owner/repo#6",
        owner="owner",
        repo="repo",
        number=6,
        head_sha="new-head-6",
        pr_url="https://github.com/owner/repo/pull/6",
        state="OPEN",
        auto_created=True,
    )
    assert row["auto_created"] == 0


def test_publication_reservation_serializes_fifth_and_sixth_slots(tmp_path):
    _, ledger = new_ledger(tmp_path)
    for number in range(1, 5):
        ledger.upsert_pr(
            pr_key=f"owner/repo#{number}",
            owner="owner",
            repo="repo",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=True,
        )

    def reserve(number):
        return ledger.reserve_publication_slot(
            reservation_key=f"publication:req-{number}",
            request_id=f"req-{number}",
            repo="owner/repo",
            idempotency_key=f"publication:req-{number}",
            now="2026-08-19T00:00:00Z",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reserve, (5, 6)))
    assert sum(bool(result["allowed"]) for result in results) == 1
    assert sum(result["reason"] == "BLOCKED_PRE_TASK" for result in results) == 1


def test_publication_reservation_lease_requires_reconciliation_after_timeout(tmp_path):
    _, ledger = new_ledger(tmp_path)
    reserved = ledger.reserve_publication_slot(
        reservation_key="publication:req-1",
        request_id="req-1",
        repo="owner/repo",
        idempotency_key="publication:req-1",
        head_ref="feature/req-1",
        head_sha="head-1",
        lease_seconds=30,
        now="2026-08-19T00:00:00Z",
    )
    assert reserved["allowed"] is True
    assert ledger.expire_publication_reservations(now="2026-08-19T00:01:00Z") == 1
    retry = ledger.reserve_publication_slot(
        reservation_key="publication:req-1",
        request_id="req-1",
        repo="owner/repo",
        idempotency_key="publication:req-1",
        head_ref="feature/req-1",
        head_sha="head-1",
        now="2026-08-19T00:01:01Z",
    )
    assert retry["reconcileRequired"] is True

    class FakeGithub:
        def query_branch(self, repo, head_ref):
            return {"exists": False}

        def query_commit(self, repo, head_sha):
            return {"exists": False}

        def query_pull_request(self, repo, head_ref, head_sha):
            return {"exists": False}

    absent = PublicationAbsenceReconciler(
        ledger, FakeGithub(), now="2026-08-19T00:01:03Z"
    ).reconcile(
        reservation_key="publication:req-1",
        repo="owner/repo",
        head_ref="feature/req-1",
        head_sha="head-1",
    )
    assert absent["released"] is True
    retryable = ledger.reserve_publication_slot(
        reservation_key="publication:req-1",
        request_id="req-1",
        repo="owner/repo",
        idempotency_key="publication:req-1",
        head_ref="feature/req-1",
        head_sha="head-1",
        now="2026-08-19T00:01:04Z",
    )
    assert retryable["allowed"] is True
    finalized = ledger.finalize_publication_reservation(
        reservation_key="publication:req-1",
        pr_key="owner/repo#1",
        head_sha="head-1",
        now="2026-08-19T00:01:05Z",
    )
    assert finalized["state"] == "FINALIZED"


def test_sqlite_backup_migration_and_rollback_preserve_legacy_digest(tmp_path):
    source = tmp_path / "source.sqlite3"
    target = tmp_path / "copy.sqlite3"
    RadarLedger(source)
    before = legacy_content_snapshot(source)
    copy_database(source, target)
    with sqlite3.connect(source) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert legacy_content_snapshot(target) == before
    migrate_schema(target)
    assert legacy_content_snapshot(target) == before
    rollback_schema(target)
    assert legacy_content_snapshot(target) == before


def test_mature_cohort_right_censors_and_projection_has_four_buckets(tmp_path):
    _, ledger = new_ledger(tmp_path)
    for number in range(1, 5):
        ledger.upsert_pr(
            pr_key=f"owner/repo#{number}",
            owner="owner",
            repo="repo",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/owner/repo/pull/{number}",
            state="OPEN",
            auto_created=True,
            observed_at="2026-01-01T00:00:00Z",
        )
    ledger.bind_task(
        task_id="decision", opportunity_key="owner/repo#10", thread_id=None, worktree_path=None
    )
    ledger.record_result(task_id="decision", result_digest="d", worker_state="needs_human")
    ledger.bind_task(
        task_id="processing", opportunity_key="owner/repo#11", thread_id=None, worktree_path=None
    )
    ledger.record_result(task_id="processing", result_digest="p", worker_state="queued")
    ledger.bind_task(
        task_id="waiting", opportunity_key="owner/repo#12", thread_id=None, worktree_path=None
    )
    ledger.record_result(
        task_id="waiting", result_digest="w", worker_state="skipped", waiting_external=True
    )
    ledger.bind_task(
        task_id="ready", opportunity_key="owner/repo#13", thread_id=None, worktree_path=None
    )
    ledger.record_result(
        task_id="ready",
        result_digest="r",
        worker_state="patched",
        result_type="state_drift",
        head_sha="head-4",
        commit_sha="commit-4",
        validation={"passed": True, "evidence": ["test"]},
        prior_head_sha="old",
        new_head_sha="head-4",
    )
    ledger.record_ci_run(
        ci_key="ci-4",
        pr_key="owner/repo#4",
        head_sha="head-4",
        status="passed",
        checks={"pytest": "passed"},
    )
    projection = export_projection(ledger.path)
    assert set(projection["buckets"]) == {
        "DECISION_REQUIRED",
        "SYSTEM_PROCESSING",
        "WAITING_EXTERNAL",
        "PORTFOLIO_READY",
    }
    assert all(item["internal"] for item in projection["items"])
    censored = ledger.mature_cohort(horizon_days=14, now="2026-02-01T00:00:00Z")
    assert censored[0]["label"] == "censored"
    with pytest.raises(PermissionError):
        ledger.record_external_outcome(pr_key="owner/repo#1", horizon_days=14, label="censored")
    ledger.record_external_outcome(
        pr_key="owner/repo#1", horizon_days=14, label="success", observed_at="2026-01-20T00:00:00Z"
    )
    assert (
        ledger.mature_cohort(horizon_days=14, now="2026-02-01T00:00:00Z")[0]["label"] == "success"
    )


def test_existing_open_pr_import_is_idempotent_and_does_not_mutate_legacy(tmp_path):
    database, ledger = new_ledger(tmp_path)
    legacy_before = ledger.legacy_tables_snapshot()
    observations = [
        {
            "url": f"https://github.com/owner/repo/pull/{number}",
            "headSha": f"sha-{number}",
        }
        for number in range(1, 109)
    ]
    result = import_open_pr_observations(database, observations, observed_at="2026-01-01T00:00:00Z")
    assert result["before"]["count"] == 0
    assert result["after"]["count"] == 108
    assert result["zeroLegacyMutation"] is True
    assert ledger.legacy_tables_snapshot() == legacy_before
    assert summarize_open_prs(database)["count"] == 108
    with ledger._connection() as connection:
        first_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("managed_prs", "managed_lifecycle_events")
        }
    assert pr_key_from_url("https://github.com/owner/repo/pull/1") == "owner/repo#1"
    replay = import_open_pr_observations(database, observations, observed_at="2026-01-01T00:00:00Z")
    assert replay["after"]["count"] == 108
    with ledger._connection() as connection:
        replay_counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("managed_prs", "managed_lifecycle_events")
        }
    assert replay_counts == first_counts
