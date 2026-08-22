from __future__ import annotations

import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from oss_pr_radar.contracts import contract_digest
from oss_pr_radar.dispatch import (
    INTENT_VERSION,
    QUEUE_VERSION,
    SUPERSEDED_SCANNER_DECISION_CONTRACTS,
)
from oss_pr_radar.dispatch import (
    canonical_prompt as dispatch_canonical_prompt,
)
from oss_pr_radar.independent_review import REVIEW_SCHEMA, _receipt_path, _source_digest
from oss_pr_radar.ledger import LedgerError, RadarLedger
from oss_pr_radar.local_publication import slow_advance_once
from oss_pr_radar.managed_lifecycle import ManagedLedger
from oss_pr_radar.metrics import QUALITY_FIELDS
from oss_pr_radar.policy import SCANNER_DECISION_REVISION, decision_contract_digest
from oss_pr_radar.util import iso_z, parse_time, sha256_json, sha256_text

pytestmark = pytest.mark.usefixtures("current_signing_key")

SCRIPT = Path(__file__).parents[1] / "scripts" / "local_dispatch_bridge.py"
HOST_SHARED_CONTEXT_ROOT = Path("/Users/oxygen/Documents/github/.oss-pr-radar/task-contexts")
SPEC = importlib.util.spec_from_file_location("local_dispatch_bridge", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

V47_SUPERSEDED_REVISION = "oss_pr_radar_v47_semantic_evidence_only"
V48_SUPERSEDED_REVISION = "oss_pr_radar_v48_semantic_evidence_only"
V49_SUPERSEDED_REVISION = "oss_pr_radar_v49_payload_bound_evidence_ids"


@pytest.fixture(autouse=True)
def hermetic_bridge_shared_root(monkeypatch, tmp_path):
    """Keep the dynamically loaded bridge module out of the host shared root."""

    github_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", github_root)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    private_root = github_root / MODULE.TASK_PRIVATE_DIR
    private_root.mkdir(parents=True, exist_ok=True)
    private_root.chmod(0o700)


def _signed_dispatch_queue(
    *,
    scanner_version: str = SCANNER_DECISION_REVISION,
    intent_id: str = "intent-1",
    key: str = "owner/repo#1",
    include_intent: bool = True,
    queue_overrides: dict | None = None,
    intent_overrides: dict | None = None,
) -> dict:
    signer = MODULE.DispatchSigner(os.environ["RADAR_DISPATCH_HMAC_KEY"])
    owner_repo, number_text = key.split("#", 1)
    number = int(number_text)
    issue_url = f"https://github.com/{owner_repo}/issues/{number}"
    stale_contract = SUPERSEDED_SCANNER_DECISION_CONTRACTS.get(scanner_version)
    decision_digest = (
        stale_contract["decisionContractDigest"] if stale_contract else decision_contract_digest()
    )
    dispatch_contract = stale_contract["contractDigest"] if stale_contract else contract_digest()
    intents = []
    if include_intent:
        intent = {
            "version": INTENT_VERSION,
            "intentId": intent_id,
            "key": key,
            "repo": owner_repo,
            "issueNumber": number,
            "issueUrl": issue_url,
            "title": "Useful bug",
            "issuedAt": "2026-08-21T00:00:00Z",
            "expiresAt": "2026-08-28T00:00:00Z",
            "issueUpdatedAt": "2026-08-21T00:00:00Z",
            "policyDigest": "policy-digest",
            "scannerVersion": scanner_version,
            "decisionContractDigest": decision_digest,
            "contractDigest": dispatch_contract,
            "decisionDigest": f"decision-{intent_id}",
            "promptDigest": sha256_text(dispatch_canonical_prompt(issue_url)),
            "autoSpawn": True,
            "notify": True,
            "preTaskGate": {"allowed": True},
            "preTaskEvidence": {"schema": "pre_task_evidence_v1"},
        }
        if intent_overrides:
            intent.update(intent_overrides)
        intents.append(signer.seal(intent))
    queue = {
        "version": QUEUE_VERSION,
        "mode": "shadow",
        "issuedAt": "2026-08-21T00:00:00Z",
        "scannerVersion": scanner_version,
        "decisionContractDigest": decision_digest,
        "contractDigest": dispatch_contract,
        "intentCount": len(intents),
        "intents": intents,
    }
    if queue_overrides:
        queue.update(queue_overrides)
    return signer.seal(queue)


def test_resolve_repo_code_paths_expands_unique_basenames_and_drops_identifiers():
    class Client:
        def repository_tree(self, repo, ref):
            assert repo == "vllm-project/vllm"
            assert ref == "base-sha"
            return [
                {
                    "type": "blob",
                    "path": "vllm/v1/spec_decode/draft_model/qwen3_dflash.py",
                },
                {"type": "blob", "path": "tests/test_other.py"},
                {"type": "tree", "path": "vllm/v1"},
            ]

    assert MODULE._resolve_repo_code_paths(
        Client(),
        repo="vllm-project/vllm",
        ref="base-sha",
        code_paths=["`qwen3_dflash.py`", "Qwen3_5ForConditionalGeneration"],
    ) == ["vllm/v1/spec_decode/draft_model/qwen3_dflash.py"]


def test_resolve_repo_code_paths_keeps_unique_suffixes_only():
    class Client:
        def repository_tree(self, _repo, _ref):
            return [
                {"type": "blob", "path": "src/providers/openai/client.py"},
                {"type": "blob", "path": "src/providers/anthropic/client.py"},
                {"type": "blob", "path": "tests/unit/client.py"},
            ]

    assert MODULE._resolve_repo_code_paths(
        Client(),
        repo="owner/repo",
        ref="base-sha",
        code_paths=["providers/openai/client.py", "client.py"],
    ) == ["src/providers/openai/client.py"]


def _superseded_scanner_revision() -> str:
    return V47_SUPERSEDED_REVISION


def _enqueue_signed_intent(
    store: RadarLedger,
    *,
    scanner_version: str,
    intent_id: str,
    key: str,
) -> dict:
    intent = _signed_dispatch_queue(
        scanner_version=scanner_version,
        intent_id=intent_id,
        key=key,
    )["intents"][0]
    assert store.enqueue(intent) is True
    return intent


def _intent_statuses(path: Path) -> dict[str, str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[0]): str(row[1])
            for row in connection.execute("SELECT intent_id,status FROM intents")
        }


def _managed_event_count(path: Path, event_type: str) -> int:
    if not path.exists():
        return 0
    with sqlite3.connect(path) as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='managed_lifecycle_events'"
        ).fetchone()
        if table is None:
            return 0
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM managed_lifecycle_events WHERE event_type=?",
                (event_type,),
            ).fetchone()[0]
        )


def test_import_signed_queue_retires_known_superseded_queue_and_unstarted_local_intents(
    monkeypatch, tmp_path
):
    db = tmp_path / "ledger.sqlite3"
    stale_revision = _superseded_scanner_revision()
    store = RadarLedger(db)
    _enqueue_signed_intent(
        store,
        scanner_version=stale_revision,
        intent_id="old-pending",
        key="old/repo#1",
    )
    _enqueue_signed_intent(
        store,
        scanner_version=stale_revision,
        intent_id="old-leased",
        key="old/repo#2",
    )
    assert store.claim("old-leased", "tester") is not None
    _enqueue_signed_intent(
        store,
        scanner_version=SCANNER_DECISION_REVISION,
        intent_id="current-pending",
        key="new/repo#1",
    )
    _enqueue_signed_intent(
        store,
        scanner_version=stale_revision,
        intent_id="old-creating",
        key="old/repo#3",
    )
    assert store.claim("old-creating", "tester") is not None
    store.reserve_creation("old-creating", owner="tester")
    _enqueue_signed_intent(
        store,
        scanner_version=stale_revision,
        intent_id="old-dispatched",
        key="old/repo#4",
    )
    assert store.claim("old-dispatched", "tester") is not None
    store.commit_dispatch(
        "old-dispatched",
        owner="tester",
        thread_id="thread-old-dispatched",
        project_id="github",
        worktree_path=str(tmp_path / "old-dispatched"),
    )
    _enqueue_signed_intent(
        store,
        scanner_version=stale_revision,
        intent_id="old-completed",
        key="old/repo#5",
    )
    store.record_stage("old/repo#5", "FIX_READY", evidence={"result": "done"})
    remote = _signed_dispatch_queue(scanner_version=stale_revision, include_intent=False)
    monkeypatch.setattr(MODULE, "fetch_cloud_queue", lambda: remote)

    result = MODULE.import_signed_queue(db)

    assert result["ok"] is True
    assert result["staleQueueRejected"] == 1
    assert result["verified"] == 0
    assert result["inserted"] == 0
    assert set(result["staleLocalIntentsSuperseded"]) == {"old-pending", "old-leased"}
    assert result["superseded"] == 2
    assert _intent_statuses(db) == {
        "old-pending": "SUPERSEDED",
        "old-leased": "SUPERSEDED",
        "current-pending": "PENDING",
        "old-creating": "CREATING",
        "old-dispatched": "DISPATCHED",
        "old-completed": "COMPLETED",
    }
    assert _managed_event_count(db, "DISPATCH_QUEUE_REJECTED") == 1

    again = MODULE.import_signed_queue(db)

    assert again["ok"] is True
    assert again["staleQueueRejected"] == 1
    assert again["auditEventCreated"] is False
    assert again["staleLocalIntentsSuperseded"] == []
    assert _managed_event_count(db, "DISPATCH_QUEUE_REJECTED") == 1


@pytest.mark.parametrize(
    ("stale_revision", "suffix"),
    [
        (V48_SUPERSEDED_REVISION, "48"),
        (V49_SUPERSEDED_REVISION, "49"),
    ],
)
def test_import_signed_queue_retires_superseded_exact_tuple_without_importing(
    monkeypatch, tmp_path, stale_revision, suffix
):
    db = tmp_path / "ledger.sqlite3"
    store = RadarLedger(db)
    _enqueue_signed_intent(
        store,
        scanner_version=stale_revision,
        intent_id=f"v{suffix}-pending",
        key=f"old/repo#{suffix}",
    )
    remote = _signed_dispatch_queue(
        scanner_version=stale_revision,
        intent_id=f"remote-v{suffix}",
        key=f"remote/repo#{suffix}",
    )
    monkeypatch.setattr(MODULE, "fetch_cloud_queue", lambda: remote)

    result = MODULE.import_signed_queue(db)

    assert result["ok"] is True
    assert result["staleQueueRejected"] == 1
    assert result["verified"] == 0
    assert result["inserted"] == 0
    assert result["staleQueue"]["scannerVersion"] == stale_revision
    assert result["staleQueue"]["intentCount"] == 1
    assert result["staleLocalIntentsSuperseded"] == [f"v{suffix}-pending"]
    assert _intent_statuses(db) == {f"v{suffix}-pending": "SUPERSEDED"}
    assert _managed_event_count(db, "DISPATCH_QUEUE_REJECTED") == 1


def test_sync_queue_superseded_revision_runs_independent_maintenance(monkeypatch, tmp_path):
    db = tmp_path / "ledger.sqlite3"
    store = RadarLedger(db)
    _enqueue_signed_intent(
        store,
        scanner_version=SCANNER_DECISION_REVISION,
        intent_id="current-pending",
        key="new/repo#1",
    )
    stale_revision = _superseded_scanner_revision()
    remote = _signed_dispatch_queue(scanner_version=stale_revision, include_intent=False)
    monkeypatch.setattr(MODULE, "fetch_cloud_queue", lambda: remote)
    recovery_calls = []

    def recover(store_arg):
        recovery_calls.append(store_arg.path)
        return {
            "verified": 1,
            "restored": [],
            "resultReceiptsRestored": 0,
            "unavailable": [],
            "quarantined": [],
            "errors": [],
        }

    monkeypatch.setattr(MODULE, "recover_shared_task_contexts", recover)
    monkeypatch.setattr(
        MODULE,
        "fetch_cloud_pr_followup",
        lambda: {
            "version": "pr_followup_v3",
            "generatedAt": iso_z(datetime.now(UTC)),
            "items": [],
        },
    )

    result = MODULE.sync_queue(db)

    assert result["ok"] is True
    assert result["staleQueueRejected"] == 1
    assert result["verified"] == 0
    assert result["inserted"] == 0
    assert result["superseded"] == 0
    assert recovery_calls == [db]
    assert result["taskContextRecovery"]["verified"] == 1
    assert result["prFollowup"]["status"] == "imported"
    assert _intent_statuses(db) == {"current-pending": "PENDING"}


def test_import_signed_queue_imports_current_revision(monkeypatch, tmp_path):
    db = tmp_path / "ledger.sqlite3"
    queue = _signed_dispatch_queue(
        scanner_version=SCANNER_DECISION_REVISION,
        intent_id="current-intent",
        key="current/repo#1",
    )
    monkeypatch.setattr(MODULE, "fetch_cloud_queue", lambda: queue)

    result = MODULE.import_signed_queue(db)

    assert result["ok"] is True
    assert result["verified"] == 1
    assert result["inserted"] == 1
    assert result.get("staleQueueRejected", 0) == 0
    assert _intent_statuses(db) == {"current-intent": "PENDING"}


@pytest.mark.parametrize(
    ("queue_factory", "message"),
    [
        (
            lambda stale: (
                _signed_dispatch_queue(
                    scanner_version=stale,
                    include_intent=False,
                    queue_overrides={"mode": "active"},
                )
                | {"mode": "tampered"}
            ),
            "dispatch signature mismatch",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=False,
                queue_overrides={"decisionContractDigest": "bad-decision"},
            ),
            "stale dispatch decision revision",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=False,
                queue_overrides={"contractDigest": "bad-contract"},
            ),
            "stale dispatch contract",
        ),
        (
            lambda _stale: _signed_dispatch_queue(
                scanner_version="oss_pr_radar_v99_future",
                include_intent=False,
            ),
            "stale scanner decision revision",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                intent_overrides={"scannerVersion": SCANNER_DECISION_REVISION},
            ),
            "stale intent scanner revision",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                intent_overrides={"decisionContractDigest": "bad-intent-decision"},
            ),
            "stale intent decision revision",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                intent_overrides={"contractDigest": "bad-intent-contract"},
            ),
            "stale intent contract",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                intent_overrides={"promptDigest": "bad-prompt"},
            ),
            "prompt digest mismatch",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                intent_overrides={"maturity": "exploration"},
            ),
            "silent exploration intent cannot be dispatched",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                intent_overrides={"key": "owner/repo#999"},
            ),
            "dispatch intent issue identity is invalid",
        ),
        (
            lambda stale: _signed_dispatch_queue(
                scanner_version=stale,
                include_intent=True,
                queue_overrides={"intentCount": 2},
            ),
            "dispatch intent count mismatch",
        ),
    ],
)
@pytest.mark.parametrize(
    "stale_revision",
    [
        V47_SUPERSEDED_REVISION,
        V48_SUPERSEDED_REVISION,
        V49_SUPERSEDED_REVISION,
    ],
)
def test_superseded_queue_fail_closed_without_writes(
    monkeypatch, tmp_path, queue_factory, message, stale_revision
):
    db = tmp_path / "ledger.sqlite3"
    queue = queue_factory(stale_revision)
    monkeypatch.setattr(MODULE, "fetch_cloud_queue", lambda: queue)

    with pytest.raises(MODULE.SignatureError, match=re.escape(message)):
        MODULE.import_signed_queue(db)

    assert not db.exists() or _managed_event_count(db, "DISPATCH_QUEUE_REJECTED") == 0


def _finalize_controller_commit_for_test(
    *,
    candidate: dict,
    context: dict,
    value: dict,
    result_path: Path | None = None,
    write_if_unchanged: bool = True,
):
    worktree = Path(candidate["worktreePath"]).resolve()
    trusted_roots = [
        (MODULE.GITHUB_ROOT / MODULE.TASK_PRIVATE_DIR / "worktrees").resolve(),
        MODULE.WORKTREE_ROOT.resolve(),
    ]
    if not any(
        root.exists() and (worktree == root or root in worktree.parents) for root in trusted_roots
    ):
        MODULE.WORKTREE_ROOT = worktree.parent
    MODULE._exclude_private_task_dir(worktree)
    private = worktree / MODULE.TASK_PRIVATE_DIR
    private.mkdir(mode=0o700, exist_ok=True)
    private.chmod(0o700)
    private_result = private / "result.json"
    if (
        not private_result.exists()
        or json.loads(private_result.read_text(encoding="utf-8")) != value
    ):
        private_result.write_text(json.dumps(value), encoding="utf-8")
    with MODULE._task_worktree_private_descriptor(candidate) as result_access:
        finalized, raw = MODULE._finalize_controller_commit(
            candidate=candidate,
            context=context,
            value=value,
            result_access=result_access,
            write_if_unchanged=write_if_unchanged,
        )
    if result_path is not None and result_path.resolve() != private_result.resolve():
        result_path.write_text(json.dumps(finalized), encoding="utf-8")
    return finalized, raw


def test_orphan_reconcile_commits_unique_matches_and_abandons_proven_misses(monkeypatch):
    monkeypatch.setattr(
        MODULE,
        "orphan_list",
        lambda _args: {
            "ok": True,
            "candidates": [
                {
                    "intentId": "intent-1",
                    "threadId": "thread-1",
                    "key": "a/b#1",
                    "repo": "a/b",
                    "desiredTitle": "[有价值] a/b#1",
                    "orphanNonce": "orphan-1",
                }
            ],
            "unmatched": [
                {
                    "intentId": "intent-2",
                    "key": "a/b#2",
                    "clientThreadId": None,
                    "abandonable": True,
                    "abandonNonce": "abandon-2",
                }
            ],
            "blocked": [],
        },
    )
    monkeypatch.setattr(MODULE, "source_repo", lambda _repo: Path("/tmp/a-b"))
    monkeypatch.setattr(
        MODULE,
        "orphan_commit",
        lambda args: {"ok": True, "intentId": args.intent_id, "threadId": args.thread_id},
    )
    monkeypatch.setattr(
        MODULE,
        "creation_abandon",
        lambda args: {"ok": True, "intentId": args.intent_id, "abandoned": True},
    )

    result = MODULE.orphan_reconcile(
        SimpleNamespace(ledger=Path("/tmp/ledger"), min_age_minutes=70, project_id="github")
    )

    assert result["ok"] is True
    assert result["reconciled"][0]["threadId"] == "thread-1"
    assert result["abandoned"][0]["intentId"] == "intent-2"


def test_duplicate_task_reconcile_archives_only_exact_renamed_duplicates(monkeypatch):
    candidate = {
        "threadId": "duplicate-1",
        "canonicalThreadId": "canonical-1",
        "key": "a/b#1",
        "currentTitle": "<codex_delegation>",
    }
    monkeypatch.setattr(
        MODULE,
        "duplicate_task_title_reconcile",
        lambda _args: {
            "ok": True,
            "renamed": [
                {
                    "threadId": "duplicate-1",
                    "key": "a/b#1",
                    "title": "[无价值·重复任务] a/b#1",
                }
            ],
            "errors": [],
        },
    )
    monkeypatch.setattr(
        MODULE,
        "duplicate_task_list",
        lambda _args: {"ok": True, "duplicates": [candidate]},
    )
    monkeypatch.setattr(
        MODULE,
        "_archive_desktop_threads",
        lambda items: {item["threadId"]: None for item in items},
    )

    result = MODULE.duplicate_task_reconcile(SimpleNamespace())

    assert result["ok"] is True
    assert result["archived"] == [
        {
            "key": "a/b#1",
            "threadId": "duplicate-1",
            "canonicalThreadId": "canonical-1",
        }
    ]


def test_event_drain_creates_exactly_one_new_issue_task(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: {"candidates": [], "restoreRequired": [], "unresolved": []},
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_list",
        lambda _args: {"candidates": [], "unresolved": []},
    )
    monkeypatch.setattr(
        MODULE,
        "recovery_list",
        lambda _args: {"recoverable": [], "unresolved": []},
    )
    monkeypatch.setattr(
        MODULE,
        "list_pending",
        lambda _path: {
            "pending": [
                {
                    "intentId": "intent-1",
                    "key": "a/b#1",
                }
            ]
        },
    )

    def claim(args):
        calls.append(("claim", args.intent_id))
        return {
            "authorized": True,
            "claimed": True,
            "sourceRepoPath": "/tmp/source",
            "worktreePath": "/tmp/worktree",
            "titleTime": "08-15 12:00",
        }

    monkeypatch.setattr(MODULE, "claim_intent", claim)
    monkeypatch.setattr(
        MODULE,
        "creation_start",
        lambda args: calls.append(("creation", args.intent_id)) or {"creationToken": "token-1"},
    )
    monkeypatch.setattr(
        MODULE,
        "root_task_create",
        lambda args: (
            calls.append(("create", args.creation_token, args.runtime_root))
            or {"threadId": "thread-1", "turnId": "turn-1"}
        ),
    )

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            runtime_root=tmp_path,
            project_id="github-project",
            owner="event-drain",
        )
    )

    assert result["action"] == "issue_task_dispatched"
    assert result["threadId"] == "thread-1"
    assert calls == [
        ("claim", "intent-1"),
        ("creation", "intent-1"),
        ("create", "token-1", tmp_path),
    ]


def test_event_drain_pauses_when_active_task_hit_codex_usage_limit(monkeypatch, tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "turn_id": "turn-usage-limit",
                    "error": {
                        "codex_error_info": "usage_limit_exceeded",
                        "message": (
                            "You've hit your usage limit. Visit settings or try again "
                            "at Aug 27th, 2026 11:08 PM."
                        ),
                    },
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads ("
            "id TEXT, archived INTEGER, title TEXT, updated_at INTEGER, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?)",
            ("thread-1", 0, "[有价值] a/b#1", 123, str(rollout)),
        )

    class Store:
        def active_task_count(self, **_kwargs):
            return 5

        def task_context_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "intentStatus": "DISPATCHED",
                    "threadId": "thread-1",
                }
            ]

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(MODULE, "_rearm_negative_followup_deliveries", lambda _store: [])
    monkeypatch.setattr(MODULE, "_rearm_interrupted_recovery_turns", lambda _store: ([], []))
    monkeypatch.setattr(MODULE, "live_thread_turn_states", lambda _thread_ids: {})
    monkeypatch.setattr(
        MODULE,
        "publication_feedback_list",
        lambda _args: pytest.fail("account usage pause should stop before dispatch probes"),
    )

    result = MODULE._drain_once_unlocked(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            runtime_root=tmp_path,
            project_id="github-project",
            owner="event-drain",
        )
    )

    assert result["ok"] is True
    assert result["action"] == "none"
    assert result["accountBlocked"]["reason"] == "codex_usage_limit_exceeded"
    assert result["accountBlocked"]["resumeAfter"] == "Aug 27th, 2026 11:08 PM"
    assert result["held"] == [
        {
            "key": "a/b#1",
            "threadId": "thread-1",
            "reason": "codex_usage_limit_exceeded",
            "resumeAfter": "Aug 27th, 2026 11:08 PM",
            "turnId": "turn-usage-limit",
            "threadUpdatedAt": 123,
            "currentTitle": "[有价值] a/b#1",
        }
    ]


def test_root_task_create_passes_runtime_root_to_worker(monkeypatch, tmp_path):
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    monkeypatch.setattr(MODULE, "STATE", tmp_path)
    captured = {}

    class FakeWorker:
        pid = 123

    def fake_popen(argv, **_kwargs):
        captured["argv"] = argv
        receipt = Path(argv[argv.index("--receipt") + 1])
        receipt.write_text(
            json.dumps({"ok": True, "threadId": "thread-1", "turnId": "turn-1"}),
            encoding="utf-8",
        )
        return FakeWorker()

    monkeypatch.setattr(MODULE.subprocess, "Popen", fake_popen)

    result = MODULE.root_task_create(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            runtime_root=runtime_root,
            intent_id="intent-1",
            creation_token="token-1",
            project_id="github-project",
            source_repo="/tmp/source",
            worktree="/tmp/worktree",
            title_time="08-21 11:35",
        )
    )

    argv = captured["argv"]
    assert argv[argv.index("--runtime-root") + 1] == str(runtime_root)
    assert result["threadId"] == "thread-1"


def test_resolve_repo_code_paths_uses_symbol_search_for_method_anchors():
    class Client:
        @staticmethod
        def repository_tree(_repo, _ref):
            return [
                {"type": "blob", "path": "src/agentscope/model/_base.py"},
                {"type": "blob", "path": "tests/model_count_tokens_test.py"},
            ]

        @staticmethod
        def api(_endpoint, *, params):
            assert params["q"] == "count_tokens repo:agentscope-ai/agentscope"
            return {
                "items": [
                    {"path": "tests/model_count_tokens_test.py"},
                    {"path": "src/agentscope/model/_base.py"},
                ]
            }

    assert MODULE._resolve_repo_code_paths(
        Client(),
        repo="agentscope-ai/agentscope",
        ref="abc123",
        code_paths=["ChatModelBase.count_tokens"],
    ) == ["src/agentscope/model/_base.py"]


def test_event_drain_lock_suppresses_overlapping_trigger(tmp_path):
    ledger_path = tmp_path / "ledger.sqlite3"
    lock_path = ledger_path.with_suffix(".drain.lock")
    lock_path.touch()
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = MODULE.drain_once(
            SimpleNamespace(
                ledger=ledger_path,
                project_id="github-project",
                owner="event-drain",
            )
        )

    assert result == {"ok": True, "busy": True, "action": "drain_already_running"}


def test_event_drain_holds_new_issue_when_pr_snapshot_needs_refresh(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: {
            "candidates": [{"threadId": "old-thread", "wakeDigest": "old-wake", "key": "a/b#1"}]
        },
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_reserve",
        lambda _args: {"ok": True, "deferred": True, "key": "a/b#1"},
    )
    monkeypatch.setattr(MODULE, "validation_followup_list", lambda _args: {"candidates": []})
    monkeypatch.setattr(MODULE, "recovery_list", lambda _args: {"recoverable": []})
    monkeypatch.setattr(
        MODULE,
        "list_pending",
        lambda _path: pytest.fail("new issues must wait for the higher-priority PR refresh"),
    )

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3", project_id="github", owner="event-drain"
        )
    )

    assert result["action"] == "none"
    assert result["deferredFollowups"] == [{"key": "a/b#1", "reason": "live_snapshot_changed"}]
    assert result["held"] == [
        {"key": "a/b#1", "reason": "higher_priority_followup_refresh_required"}
    ]


def test_event_drain_restores_an_archived_pr_task_before_followup(monkeypatch, tmp_path):
    restored = []

    def restore(args):
        thread_id = getattr(args, "thread_id", None)
        if thread_id:
            restored.append(thread_id)
        return {"ok": True, "restored": [], "errors": []}

    followup_calls = 0

    def followups(_args):
        nonlocal followup_calls
        followup_calls += 1
        candidate = {
            "key": "a/b#1",
            "threadId": "thread-1",
            "wakeDigest": "wake-1",
        }
        if followup_calls == 1:
            return {
                "candidates": [],
                "restoreRequired": [candidate],
                "unresolved": [],
            }
        return {
            "candidates": [candidate],
            "restoreRequired": [],
            "unresolved": [],
        }

    monkeypatch.setattr(MODULE, "restore_reconcile", restore)
    monkeypatch.setattr(MODULE, "pr_followup_list", followups)
    monkeypatch.setattr(
        MODULE,
        "pr_followup_reserve",
        lambda _args: {"ok": True, "deferred": False},
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_deliver",
        lambda _args: {"ok": True, "threadId": "thread-1"},
    )

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            project_id="github-project",
            owner="event-drain",
        )
    )

    assert result["action"] == "pr_followup_dispatched"
    assert restored == ["thread-1"]


def test_event_drain_treats_validation_wip_race_as_a_normal_deferral(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: {"candidates": [], "restoreRequired": [], "unresolved": []},
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_list",
        lambda _args: {
            "candidates": [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "result-digest",
                }
            ]
        },
    )

    def reserve(_args):
        raise RuntimeError("global task WIP limit reached")

    monkeypatch.setattr(MODULE, "validation_followup_reserve", reserve)

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            project_id="github-project",
            owner="event-drain",
        )
    )

    assert result["ok"] is True
    assert result["action"] == "none"
    assert result["held"] == [{"key": "a/b#1", "reason": "global_task_wip_limit"}]


def test_event_drain_terminalizes_validation_prefetch_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: {"candidates": [], "restoreRequired": [], "unresolved": []},
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_list",
        lambda _args: {
            "candidates": [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "result-digest",
                }
            ]
        },
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_reserve",
        lambda _args: {
            "ok": True,
            "blocked": True,
            "dependencyFailures": [{"failureType": "TIMEOUT"}],
        },
    )

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            project_id="github-project",
            owner="event-drain",
        )
    )

    assert result["ok"] is True
    assert result["action"] == "validation_prefetch_blocked"
    assert result["dependencyFailures"] == [{"failureType": "TIMEOUT"}]


def test_event_drain_does_not_deliver_a_deferred_validation_followup(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: {"candidates": [], "restoreRequired": [], "unresolved": []},
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_list",
        lambda _args: {
            "candidates": [{"key": "a/b#1", "threadId": "thread-1", "resultDigest": "old-digest"}]
        },
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_reserve",
        lambda _args: {
            "ok": True,
            "deferred": True,
            "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
        },
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_deliver",
        lambda _args: pytest.fail("a deferred validation result must not be delivered"),
    )

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            project_id="github-project",
            owner="event-drain",
        )
    )

    assert result["ok"] is True
    assert result["action"] == "validation_followup_deferred"
    assert result["reason"] == "VALIDATION_RESULT_CHANGED_AFTER_QUEUE"


@pytest.fixture(autouse=True)
def disable_live_thread_watchdog(monkeypatch, tmp_path):
    thread_db = tmp_path / "default-codex-db" / "threads.sqlite3"
    thread_db.parent.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads ("
            "id TEXT, title TEXT, archived INTEGER, updated_at INTEGER, "
            "rollout_path TEXT, first_user_message TEXT, cwd TEXT, git_origin_url TEXT)"
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "live_thread_turn_states", lambda _thread_ids: {})
    monkeypatch.setattr(MODULE, "active_task_turn_worker", lambda _thread_id: None)


def run_git(path: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def registered_store(tmp_path: Path, worktree: Path | None = None) -> tuple[RadarLedger, Path]:
    worktree = worktree or tmp_path / "worktree"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    (worktree / ".git" / "info" / "exclude").write_text(".oss-pr-radar/\n", encoding="utf-8")
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
            "autoSubmitAuthorized": True,
            "publicSubmissionAllowed": True,
            "authorizationSource": "signed_live_revalidation_required",
            "publicationMode": "canary",
        }
    )
    store.claim("intent-1", "controller")
    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-1",
        project_id="github",
        worktree_path=str(worktree),
        title_time="08-05 16:00",
    )
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "authorization": {"status": "ALLOW"},
            "evidenceDigest": "live-evidence",
            "liveAudit": {
                "capturedAt": iso_z(now),
                "evidence": {"digest": "live-evidence", "issue": {"state": "open"}},
            },
        },
        dedupe_key="test-live-evidence",
    )
    return store, worktree


def test_verified_reproduction_alias_advances_to_implementation(tmp_path):
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    base_sha = run_git(worktree, "rev-parse", "HEAD")

    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update(
            {
                "defaultBranch": "main",
                "selectedBaseSha": base_sha,
                "codePaths": ["`runtime_symbol`"],
                "preTaskEvidence": {
                    "defaultBranch": "main",
                    "baseSha": base_sha,
                    "codePathsPlan": ["`runtime_symbol`"],
                },
                "probeRequired": True,
                "probeLevel": "PATHS_VERIFIED",
                "taskStage": "REPRODUCTION_REQUIRED",
            }
        )
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )

    managed = ManagedLedger(store.path, ensure_schema=True)
    managed.upsert_opportunity(
        opportunity_key="a/b#1",
        owner="a",
        repo="b",
        issue_number=1,
        issue_url="https://github.com/a/b/issues/1",
        state="SYSTEM_PROCESSING",
        source="test-legal-fixture",
        provenance={"fixture": True},
        metadata={"selectedBaseSha": base_sha, "codePaths": ["runtime.py"]},
    )
    managed.bind_task(
        task_id="intent-1",
        opportunity_key="a/b#1",
        thread_id="thread-1",
        worktree_path=str(worktree),
        state="REPRODUCTION_REQUIRED",
        provenance={
            "selectedBaseSha": base_sha,
            "codePaths": ["`runtime_symbol`"],
        },
    )
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": MODULE.TASK_RESULT_SCHEMA,
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "AUTOMATION_REPRODUCTION_RECEIPT_REQUIRED",
                "reproductionVerified": True,
                "codePaths": ["runtime.py"],
                "evidence": {
                    "summary": "The pinned runtime path reproduces the reported boundary."
                },
                "tests": [
                    {
                        "command": "python3 runtime.py",
                        "exitCode": 0,
                        "summary": "Reproduction check passed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    store.record_stage(
        "a/b#1",
        "AUDIT_NO_GO",
        reason="AUTOMATION_REPRODUCTION_RECEIPT_REQUIRED",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=store.path))

    assert result["ok"] is True, result
    assert result["ingested"] == [{"key": "a/b#1", "stage": "IMPLEMENTATION_READY"}]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["stage"] == "REPRODUCED_VALIDATED"
    assert finalized["reason"] == "REPRODUCTION_CONFIRMED"
    assert finalized["reproductionReceipt"]["profileId"] == "task-result-evidence-v1"
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
    assert payload["taskStage"] == "IMPLEMENTATION_READY"
    assert payload["probeLevel"] == "REPRODUCED_VALIDATED"
    assert managed.read_task("intent-1")["state"] == "IMPLEMENTATION_READY"
    with store.connect() as connection:
        opportunity = connection.execute(
            "SELECT stage,terminal_reason FROM opportunities WHERE key='a/b#1'"
        ).fetchone()
        intent = connection.execute(
            "SELECT status,title_synced_state FROM intents WHERE intent_id='intent-1'"
        ).fetchone()
    assert tuple(opportunity) == ("DISPATCHED", None)
    assert tuple(intent) == ("DISPATCHED", None)

    implementation = store.implementation_followup_candidates()
    assert len(implementation) == 1
    assert implementation[0]["threadId"] == "thread-1"
    result_digest = implementation[0]["resultDigest"]
    reserved = store.reserve_implementation_followup(
        thread_id="thread-1", result_digest=result_digest
    )
    prompt = MODULE._task_turn_prompt("implementation-followup", reserved)
    assert dispatch_canonical_prompt("https://github.com/a/b/issues/1") in prompt
    assert "直接完成最小根因修复" in prompt
    authorization = store.authorize_task_turn_delivery(
        delivery_kind="implementation-followup",
        thread_id="thread-1",
        delivery_token=result_digest,
    )
    assert authorization["opportunityKey"] == "a/b#1"
    store.commit_implementation_followup(
        thread_id="thread-1", result_digest=result_digest
    )
    assert store.implementation_followup_candidates() == []
    assert store.unresolved_implementation_followups() == []


def bind_validation_runtime(monkeypatch, root: Path) -> Path:
    monkeypatch.setattr(MODULE, "ROOT", root)
    state = root / "state"
    monkeypatch.setattr(MODULE, "STATE", state)
    return state


def _write_explicit_controller_review(root: Path, value: dict[str, object]) -> dict[str, object]:
    """Create the private review artifact used by legal controller fixtures."""

    commit_sha = str(value["commitSha"])
    source_digest = _source_digest(value)
    review: dict[str, object] = {
        "schemaVersion": REVIEW_SCHEMA,
        "key": value["key"],
        "reviewedAt": iso_z(datetime.now(UTC)),
        "commitSha": commit_sha,
        "baseRevision": str(value.get("selectedBaseSha") or commit_sha),
        "sourceDigest": source_digest,
        "reviewMode": "codex_exec_ephemeral_read_only",
        "verdict": "PASS",
        "summary": "Explicit fixture review passed.",
        "findings": [],
        "blockingEvidence": [],
        "evidence": ["runtime.py", "pytest"],
    }
    path = _receipt_path(
        root,
        key=str(value["key"]),
        commit_sha=commit_sha,
        source_digest=source_digest,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schemaVersion": REVIEW_SCHEMA,
                "key": value["key"],
                "commitSha": commit_sha,
                "sourceDigest": source_digest,
                "review": review,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return review


def test_compact_title_matches_desktop_limit():
    value = "08-04 02:16 repo/project#42 " + "x" * 100
    result = MODULE.compact_title(value)
    assert len(result) == 59
    assert result.endswith("…")


def test_lifecycle_title_keeps_timestamp_and_value_prefix():
    result = MODULE.lifecycle_title(
        "FIX_READY", "08-04 05:25", "repo/project#42", "Runtime correctness"
    )
    assert result.startswith("[有价值·准备提交] 08-04 05:25 repo/project#42")
    assert len(result) <= 59


def test_validation_pending_title_remains_visibly_valuable():
    result = MODULE.lifecycle_title(
        "VALIDATION_PENDING", "08-09 05:25", "repo/project#42", "Runtime correctness"
    )
    assert result.startswith("[有价值·检查中] 08-09 05:25 repo/project#42")


def test_no_go_title_is_visibly_marked_before_archive():
    result = MODULE.lifecycle_title(
        "AUDIT_NO_GO", "08-04 18:47", "repo/project#42", "Duplicate work"
    )
    assert result.startswith("[无价值] 08-04 18:47 repo/project#42")


def test_title_list_detects_desktop_title_drift(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "PR_OPEN", evidence={})
    pending = store.title_candidates()[0]
    store.commit_title(
        thread_id="thread-1",
        state="PR_OPEN",
        nonce=pending["titleNonce"],
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, title TEXT, archived INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", "<codex_delegation>...", 0),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    result = MODULE.title_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert len(result["titles"]) == 1
    assert result["titles"][0]["threadId"] == "thread-1"
    assert result["titles"][0]["desiredTitle"].startswith("[有价值·PR已开] 08-05 16:00 a/b#1")
    with store.connect() as connection:
        drift = connection.execute(
            "SELECT payload_json FROM events WHERE event_type='THREAD_TITLE_DRIFTED'"
        ).fetchone()
    assert drift is not None
    assert "<codex_delegation>" not in drift["payload_json"]


def test_title_reconcile_applies_and_receipts_desktop_title(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "PR_OPEN", evidence={})
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, title TEXT, archived INTEGER)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", "<codex_delegation>...", 0),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    def apply_titles(candidates):
        with sqlite3.connect(thread_db) as connection:
            for candidate in candidates:
                connection.execute(
                    "UPDATE threads SET title=? WHERE id=?",
                    (candidate["desiredTitle"], candidate["threadId"]),
                )
        return {str(candidate["threadId"]): None for candidate in candidates}

    monkeypatch.setattr(MODULE, "_set_desktop_thread_titles", apply_titles)

    result = MODULE.title_reconcile(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["errors"] == []
    assert result["renamed"][0]["threadId"] == "thread-1"
    assert MODULE.title_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")) == {
        "ok": True,
        "titles": [],
    }


def test_title_list_ignores_archived_desktop_tasks(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, title TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", "old", 1))
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    assert MODULE.title_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")) == {
        "ok": True,
        "titles": [],
    }


def test_canonical_prompt_unwraps_delegation():
    prompt = "[$gh-issue-pr](/tmp/SKILL.md)\nhttps://github.com/a/b/issues/1"
    wrapped = f"<codex_delegation><source_thread_id>x</source_thread_id><input>{prompt}</input></codex_delegation>"
    assert MODULE.canonical_prompt(wrapped) == prompt


def test_terminal_feedback_is_published_only_for_unchanged_issues(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = bind_validation_runtime(monkeypatch, tmp_path)
    state.mkdir()
    feedback_path = state / "controller_terminal_feedback.json"
    calls = []

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2020-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(
        MODULE,
        "command",
        lambda args, **_kwargs: calls.append(args) or "",
    )

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    saved = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert result["published"] == 1
    assert result["stateChanged"] is True
    assert result["publishAttempts"] == 1
    assert saved["a/b#1"]["status"] == "controller_terminal"
    assert saved["a/b#1"]["terminal_reason"] == "ALREADY_FIXED"
    assert [call[2] for call in calls] == ["restore", "publish"]
    assert all("controller-feedback" in call for call in calls)


def test_terminal_feedback_reloads_and_merges_after_concurrent_publish(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = bind_validation_runtime(monkeypatch, tmp_path)
    state.mkdir()
    feedback_path = state / "controller_terminal_feedback.json"
    calls = []
    delays = []
    restore_count = 0
    publish_count = 0

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2020-01-01T00:00:00Z", "state": "open"}

    def concurrent_command(args, **_kwargs):
        nonlocal restore_count, publish_count
        calls.append(args)
        if args[2] == "restore":
            restore_count += 1
            if restore_count >= 2:
                feedback_path.write_text(
                    json.dumps(
                        {
                            "x/y#2": {
                                "status": "controller_terminal",
                                "terminal_reason": "CONCURRENT_RESULT",
                            }
                        }
                    ),
                    encoding="utf-8",
                )
        elif args[2] == "publish":
            publish_count += 1
            if publish_count <= 4:
                raise RuntimeError("state branch changed since restore")
        return ""

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", concurrent_command)
    monkeypatch.setattr(MODULE, "sleep", delays.append)

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    saved = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert result["published"] == 1
    assert result["stateChanged"] is True
    assert result["publishAttempts"] == 5
    assert set(saved) == {"a/b#1", "x/y#2"}
    assert [call[2] for call in calls] == ["restore", "publish"] * 5
    assert delays == [2, 4, 8, 8]


def test_terminal_feedback_does_not_republish_unchanged_state(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = bind_validation_runtime(monkeypatch, tmp_path)
    state.mkdir()
    feedback_path = state / "controller_terminal_feedback.json"
    feedback_path.write_text(
        json.dumps(
            {
                "a/b#1": {
                    "analyzed": "2020-01-01T00:00:00Z",
                    "status": "controller_terminal",
                    "controller_stage": "AUDIT_NO_GO",
                    "terminal_reason": "ALREADY_FIXED",
                    "issue_updated": "2020-01-01T00:00:00Z",
                    "scanner_version": MODULE.SCANNER_DECISION_REVISION,
                    "decision_contract_digest": MODULE.decision_contract_digest(),
                }
            }
        ),
        encoding="utf-8",
    )
    calls = []

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2020-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", lambda args, **_kwargs: calls.append(args) or "")

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    saved = json.loads(feedback_path.read_text(encoding="utf-8"))
    assert result["published"] == 1
    assert result["stateChanged"] is False
    assert result["publishAttempts"] == 1
    assert saved["a/b#1"]["analyzed"] == "2020-01-01T00:00:00Z"
    assert [call[2] for call in calls] == ["restore"]


def test_terminal_feedback_defers_when_issue_changed_after_dispatch(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = bind_validation_runtime(monkeypatch, tmp_path)
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2099-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", lambda *_args, **_kwargs: "")

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["published"] == 0
    assert result["deferred"] == [{"key": "a/b#1", "reason": "issue_updated_after_local_snapshot"}]
    assert not (state / "controller_terminal_feedback.json").exists()


def test_terminal_feedback_treats_transient_github_failure_as_deferred(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            raise RuntimeError("gh: Gateway Time-out (HTTP 504)")

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["errors"] == []
    assert result["deferred"] == [{"key": "a/b#1", "reason": "github_temporarily_unavailable"}]
    assert result["warnings"] == [{"key": "a/b#1", "warning": "gh: Gateway Time-out (HTTP 504)"}]


def test_terminal_feedback_treats_plain_github_eof_as_deferred(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            raise RuntimeError('Get "https://api.github.com/repos/a/b/issues/1": EOF')

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["errors"] == []
    assert result["deferred"] == [{"key": "a/b#1", "reason": "github_temporarily_unavailable"}]


def test_terminal_feedback_keeps_nontransient_github_failure_fatal(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="ALREADY_FIXED")
    state = tmp_path / "state"
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            raise RuntimeError("gh: Resource not accessible by integration (HTTP 403)")

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is False
    assert result["deferred"] == []
    assert result["warnings"] == []
    assert result["errors"] == [
        {
            "key": "a/b#1",
            "error": "gh: Resource not accessible by integration (HTTP 403)",
        }
    ]


def test_terminal_feedback_uses_latest_terminal_recheck_time(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="INITIAL_NO_GO")
    with store.connect() as connection:
        connection.execute(
            "UPDATE intents SET issued_at='2020-01-01T00:00:00Z' WHERE opportunity_key='a/b#1'"
        )
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="UNCHANGED_AFTER_RECHECK")
    state = tmp_path / "state"
    state.mkdir()

    class GitHub:
        def issue(self, _repo, _number):
            return {"updated_at": "2021-01-01T00:00:00Z", "state": "open"}

    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "GitHubClient", GitHub)
    monkeypatch.setattr(MODULE, "command", lambda *_args, **_kwargs: "")

    result = MODULE.publish_terminal_feedback(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["published"] == 1
    assert result["deferred"] == []


def test_pr_lifecycle_prefers_merge_review_and_green_checks():
    assert MODULE.pr_lifecycle_stage({"state": "MERGED"}) == "MERGED"
    assert (
        MODULE.pr_lifecycle_stage({"state": "OPEN", "reviewDecision": "APPROVED"})
        == "MAINTAINER_ACCEPTED"
    )
    assert (
        MODULE.pr_lifecycle_stage(
            {
                "state": "OPEN",
                "statusCheckRollup": [
                    {"conclusion": "SUCCESS"},
                    {"conclusion": "SKIPPED"},
                ],
            }
        )
        == "CI_GREEN"
    )


@pytest.mark.parametrize("current", ["VALIDATION_PENDING", "FIX_READY"])
def test_remote_open_state_does_not_replace_local_pr_action_stage(current):
    assert MODULE.should_apply_pr_lifecycle_stage(current, "PR_OPEN") is False
    assert MODULE.should_apply_pr_lifecycle_stage(current, "CI_GREEN") is False
    assert MODULE.should_apply_pr_lifecycle_stage(current, "MAINTAINER_ACCEPTED") is False


@pytest.mark.parametrize("current", ["VALIDATION_PENDING", "FIX_READY"])
@pytest.mark.parametrize("remote", ["MERGED", "CLOSED"])
def test_remote_terminal_state_replaces_local_pr_action_stage(current, remote):
    assert MODULE.should_apply_pr_lifecycle_stage(current, remote) is True


def test_remote_pr_lifecycle_only_advances_published_stage():
    assert MODULE.should_apply_pr_lifecycle_stage("PR_OPEN", "CI_GREEN") is True
    assert MODULE.should_apply_pr_lifecycle_stage("CI_GREEN", "MAINTAINER_ACCEPTED") is True
    assert MODULE.should_apply_pr_lifecycle_stage("MAINTAINER_ACCEPTED", "PR_OPEN") is False


def test_refresh_pull_requests_preserves_local_validation_stage(monkeypatch, tmp_path):
    recorded = []

    class Store:
        def tracked_pull_requests(self):
            return [
                {
                    "key": "a/b#1",
                    "pr_url": "https://github.com/a/b/pull/9",
                    "stage": "VALIDATION_PENDING",
                }
            ]

        def record_stage(self, *args, **kwargs):
            recorded.append((args, kwargs))

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE,
        "command",
        lambda *_args, **_kwargs: json.dumps({"state": "OPEN", "statusCheckRollup": []}),
    )

    result = MODULE.refresh_pull_requests(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {"ok": True, "updates": [], "errors": []}
    assert recorded == []


def test_task_context_waits_for_live_handoff_receipt(monkeypatch, tmp_path):
    expected = {"threadId": "thread-1", "worktreePath": str(tmp_path)}

    class Store:
        calls = 0

        def task_context(self, **_kwargs):
            self.calls += 1
            return expected if self.calls == 2 else None

        def has_live_handoff(self, **_kwargs):
            return True

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "orphan_list",
        lambda _args: {"ok": True, "candidates": [], "blocked": [], "unmatched": []},
    )
    monkeypatch.setattr(MODULE, "sleep", lambda _seconds: None)

    result = MODULE.task_context(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            issue_url="https://github.com/a/b/issues/1",
            thread_id=None,
            worktree=str(tmp_path),
            wait_seconds=1,
        )
    )

    assert result == {"ok": True, "task": expected, "pendingHandoff": False}


def test_workspace_task_context_is_private_and_git_ignored(tmp_path):
    store, worktree = registered_store(tmp_path)

    path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["schemaVersion"] == "radar-task-context-v1"
    assert value["threadId"] == "thread-1"
    assert value["titleTime"] == "08-05 16:00"
    assert value["externalLedgerAccessAllowed"] is False
    assert value["planHubRequired"] is False
    assert value["networkPolicy"] == "controller_snapshot_only"
    assert value["childMayRequestApproval"] is False
    assert value["childMayWriteGitMetadata"] is False
    assert value["controllerOwnsCommit"] is True
    assert value["liveAudit"]["evidence"]["digest"] == "live-evidence"
    assert run_git(worktree, "status", "--porcelain") == ""

    store.record_stage("a/b#1", "FIX_READY", evidence={})
    refreshed = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )
    assert refreshed["stage"] == "FIX_READY"
    assert refreshed["contextDigest"] == value["contextDigest"]

    request = store.create_publication_request(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        commit_sha="a" * 40,
        branch="fix-runtime",
        worktree_path=str(worktree),
        evidence_digest="evidence",
        evidence_path=str(worktree / ".oss-pr-radar" / "result.json"),
        publication={
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: runtime",
            "bodyPath": str(worktree / ".oss-pr-radar" / "pr-body.md"),
        },
    )
    with pytest.raises(LedgerError, match="publication request is not grantable"):
        store.grant_publication_request(
            request["request_id"],
            issue_url="https://github.com/a/b/issues/1",
            commit_sha="a" * 40,
            branch="fix-runtime",
            evidence={},
        )
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "FIX_READY"
    )
    assert store.task_context_candidates()[0]["threadId"] == "thread-1"


def test_managed_workspace_context_is_mirrored_for_github_project_bootstrap(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path, worktree=worktree)

    path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    local = json.loads(path.read_text(encoding="utf-8"))
    bootstrap_path = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    bootstrap = json.loads(bootstrap_path.read_text(encoding="utf-8"))
    assert local == bootstrap
    assert local["workspaceMode"] == "github_project_managed_worktree"
    assert local["taskProjectRoot"] == str(project_root.resolve())
    assert local["bootstrapContextPath"] == str(bootstrap_path)
    assert local["worktreePath"] == str(worktree.resolve())


def test_shared_context_recovery_rebuilds_a_lost_local_ledger(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 1
    assert result["errors"] == []
    assert result["restored"][0]["stage"] == "FIX_READY"
    context = recovered.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context is not None
    assert context["intentStatus"] == "COMPLETED"
    assert context["stage"] == "FIX_READY"
    assert re.fullmatch(r"\d{2}-\d{2} \d{2}:\d{2}", context["titleTime"])


def test_shared_context_recovery_verifies_an_existing_dispatched_task(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    verified = MODULE.recover_shared_task_contexts(store)

    assert verified["verified"] == 1
    assert verified["errors"] == []
    assert verified["restored"] == [
        {
            "key": "a/b#1",
            "stage": "DISPATCHED",
            "intentRestored": False,
            "publicationRestored": False,
            "resultReceiptRestored": False,
        }
    ]


def _context_digest_fixture(tmp_path, *, stage="DISPATCHED"):
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, worktree = registered_store(tmp_path, worktree=worktree)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "README.md").write_text("fixture\n", encoding="utf-8")
    run_git(worktree, "add", "README.md")
    run_git(worktree, "commit", "-m", "chore: context fixture")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    if stage != "DISPATCHED":
        store.record_stage("a/b#1", stage, evidence={})
    local_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    return (
        store,
        worktree,
        local_path,
        MODULE.shared_context_path("https://github.com/a/b/issues/1"),
    )


def _rewrite_context_mirrors(local_path, shared_path, value):
    MODULE._atomic_json(local_path, value)
    MODULE._atomic_json(shared_path, value)


def test_task_context_digest_binds_target_base_and_prepared_head():
    context = {
        "schemaVersion": MODULE.TASK_CONTEXT_SCHEMA,
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "intentId": "intent-1",
        "track": "agent_ai_infra",
        "algorithmEvidence": None,
        "liveAudit": {"evidence": {"digest": "evidence"}},
        "threadId": "thread-1",
        "worktreePath": "/tmp/worktree",
        "targetBase": {
            "branch": "main",
            "sha": "a" * 40,
            "source": "repository_default",
            "defaultBranch": "main",
        },
    }
    prepared = "a" * 40
    canonical = MODULE._task_context_digest(context, prepared)
    assert canonical == sha256_json(MODULE._task_context_digest_payload(context, prepared))
    assert canonical != MODULE._task_context_digest(
        context | {"targetBase": {**context["targetBase"], "sha": "b" * 40}}, prepared
    )
    assert canonical != sha256_json(
        MODULE._task_context_digest_payload(context, prepared, include_target_base=False)
    )


def test_published_non_null_target_cannot_use_legacy_context_digest(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path / "worktrees")
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    _store, worktree, local_path, _shared_path = _context_digest_fixture(
        tmp_path / "fixture", stage="PR_OPEN"
    )
    context = json.loads(local_path.read_text(encoding="utf-8"))
    context["stage"] = "PR_OPEN"
    context["publicationReceipt"] = {
        "prUrl": "https://github.com/a/b/pull/2",
        "commitSha": run_git(worktree, "rev-parse", "HEAD"),
    }
    context["targetBase"] = {
        "branch": "main",
        "sha": run_git(worktree, "rev-parse", "HEAD"),
        "source": "repository_default",
        "defaultBranch": "main",
    }
    assert MODULE._legacy_task_context_digest_allowed(context) is False
    candidates = MODULE._task_context_digest_candidates(context, None)
    legacy_digest = sha256_json(
        MODULE._task_context_digest_payload(context, None, include_target_base=False)
    )
    assert candidates
    assert legacy_digest not in candidates


def test_legacy_implementation_result_requires_explicit_migration(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path / "worktrees")
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    store, worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    context = json.loads(local_path.read_text(encoding="utf-8"))
    context["taskStage"] = None
    context["probeLevel"] = None
    context["contextDigest"] = MODULE._task_context_digest(context, None)
    _rewrite_context_mirrors(local_path, shared_path, context)
    candidate = store.task_result_candidates()[0]
    value = {
        "schemaVersion": MODULE.TASK_RESULT_SCHEMA,
        "contextDigest": context["contextDigest"],
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "stage": "FIX_READY",
        "commitSha": run_git(worktree, "rev-parse", "HEAD"),
        "changedFiles": ["README.md"],
    }
    classified = MODULE._legacy_result_requires_migration(
        value,
        context,
        candidate,
        None,
        followup_digest_valid=True,
    )
    assert classified == {
        "legacyDigest": "false",
        "commitSha": value["commitSha"],
        "followupDigestValid": "true",
    }
    context["targetBase"] = {
        "branch": "main",
        "sha": value["commitSha"],
        "source": "repository_default",
        "defaultBranch": "main",
    }
    context["contextDigest"] = MODULE._task_context_digest(context, None)
    legacy_value = dict(value)
    legacy_value["contextDigest"] = sha256_json(
        MODULE._task_context_digest_payload(context, None, include_target_base=False)
    )
    assert (
        MODULE._legacy_result_requires_migration(
            legacy_value,
            context,
            candidate,
            None,
            followup_digest_valid=True,
        )
        is None
    )


def test_ingestion_quarantines_legacy_implementation_result_without_side_effect(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path / "worktrees")
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    store, worktree, result_path = _controller_commit_result(tmp_path)
    context_path = result_path.parent / "task-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["taskStage"] = None
    context["probeLevel"] = None
    context["contextDigest"] = MODULE._task_context_digest(context, None)
    _rewrite_context_mirrors(
        context_path,
        MODULE.shared_context_path(context["issueUrl"]),
        context,
    )
    now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        for request_id, status in (("pending-1", "PENDING"), ("granted-1", "GRANTED")):
            connection.execute(
                """INSERT INTO publication_requests
                   (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                    evidence_digest,status,request_json,created_at,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    request_id,
                    "a/b#1",
                    "thread-1",
                    "a" * 40,
                    "fix/runtime",
                    str(worktree),
                    "evidence",
                    status,
                    json.dumps({"opportunityKey": "a/b#1"}),
                    now,
                    now,
                ),
            )
    original = result_path.read_bytes()

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True, result.get("errors")
    assert result["errors"] == []
    assert result["publicationRequests"] == []
    assert result["quarantined"][0]["reason"] == MODULE.LEGACY_RESULT_REQUIRES_MIGRATION
    assert store.publication_work_items() == []
    assert (
        store.active_task_quarantine("a/b#1")["reason"] == MODULE.LEGACY_RESULT_REQUIRES_MIGRATION
    )
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM task_quarantines WHERE opportunity_key=? AND status='ACTIVE'",
                ("a/b#1",),
            ).fetchone()[0]
            == 1
        )
    assert result_path.read_bytes() == original
    from oss_pr_radar.managed_lifecycle import ManagedLedger

    with ManagedLedger(tmp_path / "ledger.sqlite3", ensure_schema=True)._connection() as connection:
        event = connection.execute(
            """SELECT event_type FROM managed_lifecycle_events
               WHERE opportunity_key='a/b#1' AND event_type=?""",
            (MODULE.LEGACY_RESULT_REQUIRES_MIGRATION,),
        ).fetchone()
    assert event[0] == MODULE.LEGACY_RESULT_REQUIRES_MIGRATION

    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert repeated["ok"] is True, repeated.get("errors")
    assert repeated.get("quarantined", []) == []
    assert "quarantinedAlreadyRecorded" not in repeated
    assert repeated["ingested"] == []

    with pytest.raises(ValueError):
        store.clear_task_quarantine(
            "a/b#1",
            reason=MODULE.LEGACY_RESULT_REQUIRES_MIGRATION,
            evidence={"migrationId": "not-revalidated"},
        )
    store.clear_task_quarantine(
        "a/b#1",
        reason=MODULE.LEGACY_RESULT_REQUIRES_MIGRATION,
        evidence={"revalidated": True, "migrationId": "m-1"},
    )
    assert store.active_task_quarantine("a/b#1") is None
    assert {item["request_id"] for item in store.publication_work_items()} == {
        "pending-1",
        "granted-1",
    }


def test_shared_context_recovery_accepts_target_bound_context_without_errors(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["targetBase"] = {
        "branch": "main",
        "sha": run_git(_worktree, "rev-parse", "HEAD"),
        "source": "repository_default",
        "defaultBranch": "main",
    }
    value["contextDigest"] = sha256_json(
        MODULE._task_context_digest_payload(value, None, include_prepared_head=False)
    )
    _rewrite_context_mirrors(local_path, shared_path, value)
    with store.transaction() as connection:
        store._event(
            connection,
            "a/b#1",
            "AUDIT_SNAPSHOT",
            "target-bound-fixture",
            {"liveAudit": value["liveAudit"], "targetBase": value["targetBase"]},
            value["liveAudit"].get("capturedAt"),
        )

    recovered = MODULE.recover_shared_task_contexts(store)

    assert recovered["verified"] == 1, json.dumps(recovered, indent=2, default=str)
    assert recovered["errors"] == []


def test_shared_context_recovery_rejects_target_base_tampering(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["targetBase"] = {
        "branch": "main",
        "sha": run_git(_worktree, "rev-parse", "HEAD"),
        "source": "repository_default",
        "defaultBranch": "main",
    }
    value["contextDigest"] = MODULE._task_context_digest(value, None)
    _rewrite_context_mirrors(local_path, shared_path, value)
    tampered = dict(value, targetBase={**value["targetBase"], "sha": "b" * 40})
    MODULE._atomic_json(shared_path, tampered)

    recovered = MODULE.recover_shared_task_contexts(store)

    assert recovered["verified"] == 0
    assert recovered["errors"] == []
    assert recovered["quarantined"][0]["reason"] == "SHARED_CONTEXT_DIGEST_MISMATCH"


def test_shared_context_digest_quarantine_is_private_and_idempotent(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "f" * 64
    MODULE._atomic_json(shared_path, value)
    request_now = iso_z(datetime.now(UTC))
    with store.transaction() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "request-context-quarantine",
                "a/b#1",
                "thread-1",
                "a" * 40,
                "fix/runtime",
                str(_worktree),
                "evidence",
                "PENDING",
                json.dumps({"opportunityKey": "a/b#1"}),
                request_now,
                request_now,
            ),
        )

    first = MODULE.recover_shared_task_contexts(store)
    artifact_path = Path(first["quarantined"][0]["artifactPath"])
    artifact_bytes = artifact_path.read_bytes()
    artifact_mtime = artifact_path.stat().st_mtime_ns
    second = MODULE.recover_shared_task_contexts(store)

    assert first["errors"] == []
    assert first["quarantined"][0]["new"] is True
    assert second["errors"] == []
    assert second["quarantined"][0]["new"] is False
    assert artifact_path.read_bytes() == artifact_bytes
    assert artifact_path.stat().st_mtime_ns == artifact_mtime
    assert store.publication_work_items() == []
    artifact = json.loads(Path(first["quarantined"][0]["artifactPath"]).read_text())
    assert artifact["originalBytesSha256"] == first["quarantined"][0]["originalBytesSha256"]
    assert base64.b64decode(artifact["originalBytesBase64"]) == shared_path.read_bytes()
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM task_quarantines WHERE opportunity_key='a/b#1'"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE opportunity_key='a/b#1' "
                "AND event_type='SHARED_TASK_CONTEXT_QUARANTINED'"
            ).fetchone()[0]
            == 1
        )


def test_shared_context_bootstrap_path_is_quarantined_separately(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["bootstrapContextPath"] = str(tmp_path / "other-context.json")
    MODULE._atomic_json(local_path, value)
    MODULE._atomic_json(shared_path, value)

    recovered = MODULE.recover_shared_task_contexts(store)

    assert recovered["verified"] == 0
    assert recovered["errors"] == []
    assert recovered["quarantined"][0]["reason"] == "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID"


def test_shared_context_quarantine_artifact_identity_includes_reason(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    reasons = iter(["SHARED_CONTEXT_DIGEST_MISMATCH", "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID"])
    monkeypatch.setattr(MODULE, "_shared_context_quarantine_reason", lambda _exc: next(reasons))
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "f" * 64
    MODULE._atomic_json(shared_path, value)

    first = MODULE.recover_shared_task_contexts(store)
    second = MODULE.recover_shared_task_contexts(store)

    first_path = Path(first["quarantined"][0]["artifactPath"])
    second_path = Path(second["quarantined"][0]["artifactPath"])
    assert first_path != second_path
    assert len(first_path.name) == len("q-" + "0" * 64 + ".json")
    assert len(second_path.name) == len("q-" + "0" * 64 + ".json")
    assert json.loads(first_path.read_text())["reason"] == "SHARED_CONTEXT_DIGEST_MISMATCH"
    assert json.loads(second_path.read_text())["reason"] == "SHARED_CONTEXT_BOOTSTRAP_PATH_INVALID"
    assert first_path.exists()
    assert second_path.exists()


def test_shared_context_quarantine_reactivates_each_cleared_generation(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "f" * 64
    MODULE._atomic_json(shared_path, value)

    first = MODULE.recover_shared_task_contexts(store)
    store.clear_task_quarantine(
        "a/b#1", reason="SHARED_CONTEXT_DIGEST_MISMATCH", evidence={"revalidated": True}
    )
    second = MODULE.recover_shared_task_contexts(store)
    store.clear_task_quarantine(
        "a/b#1", reason="SHARED_CONTEXT_DIGEST_MISMATCH", evidence={"revalidated": True}
    )
    third = MODULE.recover_shared_task_contexts(store)

    assert [
        item["new"]
        for item in (first["quarantined"] + second["quarantined"] + third["quarantined"])
    ] == [True, True, True]
    assert store.active_task_quarantine("a/b#1") is not None
    with store.connect() as connection:
        rows = connection.execute(
            "SELECT dedupe_key,status FROM task_quarantines "
            "WHERE opportunity_key='a/b#1' AND reason='SHARED_CONTEXT_DIGEST_MISMATCH' "
            "ORDER BY quarantine_id"
        ).fetchall()
    assert [row["status"] for row in rows] == ["CLEARED", "CLEARED", "ACTIVE"]
    assert rows[0]["dedupe_key"] != rows[1]["dedupe_key"] != rows[2]["dedupe_key"]


def test_shared_context_quarantine_artifact_tamper_is_global_fail_closed(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "f" * 64
    MODULE._atomic_json(shared_path, value)
    first = MODULE.recover_shared_task_contexts(store)
    artifact = Path(first["quarantined"][0]["artifactPath"])
    original = artifact.read_bytes()
    artifact.write_bytes(original.replace(b"shared-context-quarantine-v1", b"tampered-context-v1"))
    artifact.chmod(0o600)

    second = MODULE.recover_shared_task_contexts(store)

    assert second["quarantined"] == []
    assert "quarantine persistence failed" in second["errors"][0]["error"]
    assert artifact.read_bytes() != original


def test_shared_context_quarantine_artifact_mode_tamper_is_global_fail_closed(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "f" * 64
    MODULE._atomic_json(shared_path, value)
    first = MODULE.recover_shared_task_contexts(store)
    artifact = Path(first["quarantined"][0]["artifactPath"])
    artifact.chmod(0o644)

    second = MODULE.recover_shared_task_contexts(store)

    assert second["quarantined"] == []
    assert "quarantine persistence failed" in second["errors"][0]["error"]


@pytest.mark.parametrize("layout", ["root-symlink", "root-mode", "lock-symlink"])
def test_shared_context_quarantine_path_hijack_fails_closed(monkeypatch, tmp_path, layout):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    private_root = project_root / MODULE.TASK_PRIVATE_DIR
    private_root.mkdir(parents=True, exist_ok=True)
    private_root.chmod(0o700)
    shared_root = MODULE.shared_context_root()
    shared_root.mkdir(parents=True)
    shared_root.chmod(0o700)
    invalid = shared_root / "a--b--1.json"
    invalid.write_text(
        json.dumps({"issueUrl": "https://github.com/a/b/issues/1", "key": "a/b#1"}),
        encoding="utf-8",
    )
    invalid.chmod(0o600)
    quarantine_root = MODULE.shared_context_quarantine_root()
    external = tmp_path / "external"
    external.mkdir()
    if layout == "root-symlink":
        external.chmod(0o700)
        quarantine_root.parent.mkdir(parents=True, exist_ok=True)
        quarantine_root.symlink_to(external, target_is_directory=True)
    else:
        quarantine_root.mkdir(parents=True)
        quarantine_root.chmod(0o750 if layout == "root-mode" else 0o700)
        if layout == "lock-symlink":
            (external / "lock-target").touch()
            (quarantine_root / ".context-quarantine.lock").symlink_to(external / "lock-target")

    recovered = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "ledger.sqlite3"))

    assert recovered["quarantined"] == []
    assert "quarantine persistence failed" in recovered["errors"][0]["error"]
    assert list(external.iterdir()) == (
        [external / "lock-target"] if layout == "lock-symlink" else []
    )


def test_shared_context_quarantine_rejects_ancestor_private_root_symlink(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    external = tmp_path / "external"
    project_root.mkdir(exist_ok=True)
    external.mkdir(exist_ok=True)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    shutil.rmtree(project_root / MODULE.TASK_PRIVATE_DIR)
    (project_root / MODULE.TASK_PRIVATE_DIR).symlink_to(external, target_is_directory=True)

    with pytest.raises((OSError, RuntimeError), match="symlink|private|directory"):
        MODULE._open_shared_context_quarantine_directory(create=True)

    assert list(external.iterdir()) == []


def test_shared_context_quarantine_rejects_ancestor_replacement_after_safe_open(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    project_root.mkdir(exist_ok=True)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    private_root = project_root / MODULE.TASK_PRIVATE_DIR
    private_root.mkdir(mode=0o700, exist_ok=True)
    private_root.chmod(0o700)
    quarantine = private_root / "context-quarantine"
    quarantine.mkdir(mode=0o700)
    quarantine.chmod(0o700)
    external = tmp_path / "external"
    external.mkdir(mode=0o700)

    _fd, _path, handles = MODULE._open_shared_context_quarantine_directory(create=False)
    try:
        private_root.rename(tmp_path / "private-original")
        private_root.symlink_to(external, target_is_directory=True)
        with pytest.raises((OSError, RuntimeError), match="symlink|private|directory"):
            MODULE._ensure_context_quarantine_artifact(
                MODULE.shared_context_quarantine_root() / ("q-" + "a" * 64 + ".json"),
                key="a/b#1",
                issue_url="https://github.com/a/b/issues/1",
                reason="SHARED_CONTEXT_INVALID",
                source_path=tmp_path / "context.json",
                raw=b"{}",
                source_digest="a" * 64,
                source_mode=0o600,
                error="test",
            )
    finally:
        for handle in reversed(handles):
            os.close(handle)
    assert list(external.iterdir()) == []


def test_shared_context_quarantine_concurrent_observation_has_one_artifact(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value["contextDigest"] = "f" * 64
    MODULE._atomic_json(shared_path, value)
    results = []

    def recover():
        results.append(MODULE.recover_shared_task_contexts(store))

    threads = [threading.Thread(target=recover) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(results) == 2
    assert [result["errors"] for result in results] == [[], []]
    paths = {result["quarantined"][0]["artifactPath"] for result in results}
    assert len(paths) == 1
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM task_quarantines WHERE opportunity_key='a/b#1'"
            ).fetchone()[0]
            == 1
        )


def test_shared_context_unknown_filename_fails_without_quarantine_write(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    private_root = project_root / MODULE.TASK_PRIVATE_DIR
    private_root.mkdir(parents=True, exist_ok=True)
    private_root.chmod(0o700)
    root = MODULE.shared_context_root()
    root.mkdir(parents=True)
    root.chmod(0o700)
    path = root / "untrusted.json"
    path.write_bytes(b"not-json")
    path.chmod(0o600)

    recovered = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "ledger.sqlite3"))

    assert recovered["quarantined"] == []
    assert recovered["errors"][0]["error"].endswith("identity is unavailable for quarantine")
    assert not MODULE.shared_context_quarantine_root().exists()


def _shared_context_inventory(root: Path) -> str:
    entries = []
    if root.exists():
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(root))
            stat_result = path.lstat()
            if path.is_symlink():
                entries.append((relative, "symlink", os.readlink(path)))
            elif path.is_file():
                entries.append(
                    (
                        relative,
                        "file",
                        stat_result.st_mode & 0o777,
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                    )
                )
            else:
                entries.append((relative, "directory", stat_result.st_mode & 0o777))
    return sha256_json(entries)


def test_shared_context_recovery_is_hermetic_against_host_inventory(monkeypatch, tmp_path):
    host_contexts = HOST_SHARED_CONTEXT_ROOT
    before = _shared_context_inventory(host_contexts)
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    root = MODULE.shared_context_root()
    root.mkdir(parents=True)
    root.chmod(0o700)
    invalid = root / "a--b--1.json"
    invalid.write_text(
        json.dumps({"issueUrl": "https://github.com/a/b/issues/1", "key": "a/b#1"}),
        encoding="utf-8",
    )
    invalid.chmod(0o600)

    recovered = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "ledger.sqlite3"))

    assert recovered["errors"] == []
    assert recovered["quarantined"][0]["new"] is True
    assert _shared_context_inventory(host_contexts) == before


def test_published_legacy_context_without_target_base_is_accepted(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    _store, _worktree, local_path, shared_path = _context_digest_fixture(
        tmp_path / "fixture", stage="PR_OPEN"
    )
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value.pop("targetBase")
    value["publicationReceipt"] = {
        "status": "PR_OPEN",
        "prUrl": "https://github.com/a/b/pull/9",
        "commitSha": run_git(_worktree, "rev-parse", "HEAD"),
    }
    value["contextDigest"] = sha256_json(
        MODULE._task_context_digest_payload(
            value,
            None,
            include_target_base=False,
            include_prepared_head=False,
        )
    )
    _rewrite_context_mirrors(local_path, shared_path, value)

    verified, _updated = MODULE._verified_shared_task_context(shared_path)

    assert verified["stage"] == "PR_OPEN"


def test_active_legacy_context_without_target_base_fails_closed(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    _store, _worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    value = json.loads(local_path.read_text(encoding="utf-8"))
    value.pop("targetBase")
    value["contextDigest"] = sha256_json(
        MODULE._task_context_digest_payload(
            value,
            None,
            include_target_base=False,
            include_prepared_head=False,
        )
    )
    _rewrite_context_mirrors(local_path, shared_path, value)

    with pytest.raises(RuntimeError, match="shared task context digest mismatch"):
        MODULE._verified_shared_task_context(shared_path)


def test_shared_context_recovery_ignores_context_removed_by_cleanup(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    original_verify = MODULE._verified_shared_task_context

    def remove_before_verify(path):
        path.unlink()
        return original_verify(path)

    monkeypatch.setattr(MODULE, "_verified_shared_task_context", remove_before_verify)

    recovered = MODULE.recover_shared_task_contexts(store)

    assert recovered["verified"] == 0
    assert recovered["restored"] == []
    assert recovered["errors"] == []


def test_shared_context_recovery_does_not_block_on_a_missing_historical_worktree(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    shutil.rmtree(worktree)

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 0
    assert result["restored"] == []
    assert result["errors"] == []
    assert result["unavailable"] == [
        {
            "path": str(MODULE.shared_context_path("https://github.com/a/b/issues/1")),
            "key": "a/b#1",
            "issueUrl": "https://github.com/a/b/issues/1",
            "intentId": "intent-1",
            "stage": "DISPATCHED",
            "threadId": "thread-1",
            "worktreePath": str(worktree.resolve()),
            "published": False,
            "reason": "TASK_WORKTREE_UNAVAILABLE",
        }
    ]


def test_shared_context_recovery_defers_and_repairs_a_missing_worktree_mirror(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    local_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    local_path.unlink()

    recovered = MODULE.recover_shared_task_contexts(store)

    assert recovered["verified"] == 0
    assert recovered["errors"] == []
    assert recovered["unavailable"][0]["reason"] == "TASK_CONTEXT_MIRROR_UNAVAILABLE"

    synced = MODULE.sync_task_contexts(
        SimpleNamespace(ledger=tmp_path / "original" / "ledger.sqlite3")
    )

    assert synced["ok"] is True
    assert local_path.is_file()
    assert json.loads(local_path.read_text(encoding="utf-8")) == json.loads(
        MODULE.shared_context_path("https://github.com/a/b/issues/1").read_text(encoding="utf-8")
    )


def test_v2_shared_context_path_bounds_identity_segments_and_issue_number():
    url = "https://github.com/" + "o" * 39 + "/" + "r" * 100 + "/issues/9999999999"
    path = MODULE.shared_context_path(url)
    relative = path.relative_to(MODULE.shared_context_root())
    assert relative.parts[0] == "v2"
    assert all(len(part.encode("utf-8")) <= 255 for part in relative.parts)
    assert MODULE._shared_context_path_identity(path) == (
        "o" * 39,
        "r" * 100,
        "9999999999",
    )

    with pytest.raises(RuntimeError):
        MODULE.shared_context_path("https://github.com/" + "o" * 40 + "/repo/issues/1")
    with pytest.raises(RuntimeError):
        MODULE.shared_context_path("https://github.com/owner/" + "r" * 101 + "/issues/1")
    with pytest.raises(RuntimeError):
        MODULE.shared_context_path("https://github.com/owner/repo/issues/10000000000")


def test_legacy_and_v2_shared_context_duplicates_prefer_v2_or_fail_on_bytes_conflict(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    context_root = MODULE.shared_context_root()
    context_root.mkdir(parents=True, mode=0o700)
    os.chmod(context_root, 0o700)
    url = "https://github.com/a/b/issues/1"
    canonical = MODULE.shared_context_path(url)
    canonical.parent.mkdir(parents=True, mode=0o700)
    os.chmod(canonical.parent, 0o700)
    os.chmod(canonical.parent.parent, 0o700)
    os.chmod(canonical.parent.parent.parent, 0o700)
    legacy = context_root / MODULE._legacy_shared_context_filename(url)
    canonical.write_bytes(b"same")
    legacy.write_bytes(b"same")
    os.chmod(canonical, 0o600)
    os.chmod(legacy, 0o600)
    selected, errors = MODULE._deduplicate_shared_context_paths([legacy, canonical])
    assert selected == [canonical]
    assert errors == []

    legacy.write_bytes(b"different")
    selected, errors = MODULE._deduplicate_shared_context_paths([legacy, canonical])
    assert selected == []
    assert len(errors) == 2
    assert all(isinstance(error, MODULE._SharedContextValidationError) for error in errors)
    assert {error.source_path for error in errors} == {legacy, canonical}


def test_shared_context_unknown_root_entry_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    context_root = MODULE.shared_context_root()
    context_root.mkdir(parents=True, mode=0o700)
    os.chmod(context_root, 0o700)
    (context_root / "unexpected").symlink_to(tmp_path / "outside")
    result = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "ledger.sqlite3"))
    assert result["verified"] == 0
    assert result["errors"]
    assert "unexpected shared context root entry" in result["errors"][0]["error"]


def test_shared_context_recovery_deduplicates_trusted_legacy_and_v2_contexts(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, worktree, local_path, canonical = _context_digest_fixture(tmp_path / "fixture")
    legacy = MODULE.shared_context_root() / MODULE._legacy_shared_context_filename(
        "https://github.com/a/b/issues/1"
    )
    value = json.loads(canonical.read_text(encoding="utf-8"))
    legacy_value = value | {"bootstrapContextPath": str(legacy)}
    legacy.write_text(json.dumps(legacy_value), encoding="utf-8")
    os.chmod(legacy, 0o600)

    try:
        MODULE._verified_shared_task_context(canonical)
    except Exception as exc:
        raise AssertionError(f"canonical verification failed: {type(exc).__name__}: {exc}") from exc
    listed = MODULE._list_shared_context_paths()
    selected, dedup_errors = MODULE._deduplicate_shared_context_paths(listed)
    assert canonical in listed, {
        "root": str(MODULE.shared_context_root()),
        "listed": [str(p) for p in listed],
    }
    assert selected == [canonical], {"selected": [str(p) for p in selected], "errors": dedup_errors}

    recovered = MODULE.recover_shared_task_contexts(store)
    assert recovered["errors"] == []
    assert recovered["verified"] == 1, json.dumps(recovered, indent=2, default=str)
    assert len(recovered["restored"]) == 1
    assert recovered["restored"][0]["key"] == "a/b#1"

    legacy.write_text(json.dumps(legacy_value | {"threadId": "other"}), encoding="utf-8")
    os.chmod(legacy, 0o600)
    conflicted = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "conflict.sqlite3"))
    assert conflicted["verified"] == 0
    assert conflicted["errors"] == []
    assert [item["reason"] for item in conflicted["quarantined"]] == [
        "SHARED_CONTEXT_LAYOUT_CONFLICT",
        "SHARED_CONTEXT_LAYOUT_CONFLICT",
    ]
    assert [item["new"] for item in conflicted["quarantined"]] == [True, True]

    repeated = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "conflict.sqlite3"))
    assert repeated["errors"] == []
    assert [item["new"] for item in repeated["quarantined"]] == [False, False]


def test_shared_context_layout_conflict_without_bindable_identity_fails_closed(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    context_root = MODULE.shared_context_root()
    context_root.mkdir(parents=True, mode=0o700)
    os.chmod(context_root, 0o700)
    url = "https://github.com/a/b/issues/1"
    canonical = MODULE.shared_context_path(url)
    canonical.parent.mkdir(parents=True, mode=0o700)
    os.chmod(canonical.parent, 0o700)
    os.chmod(canonical.parent.parent, 0o700)
    os.chmod(canonical.parent.parent.parent, 0o700)
    legacy = context_root / MODULE._legacy_shared_context_filename(url)
    canonical.write_text(
        json.dumps({"issueUrl": "https://github.com/x/y/issues/2", "key": "x/y#2"}),
        encoding="utf-8",
    )
    legacy.write_text(
        json.dumps({"issueUrl": "https://github.com/x/y/issues/3", "key": "x/y#3"}),
        encoding="utf-8",
    )
    os.chmod(canonical, 0o600)
    os.chmod(legacy, 0o600)

    result = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "ledger.sqlite3"))

    assert result["verified"] == 0
    assert result["quarantined"] == []
    assert len(result["errors"]) == 2
    assert all("identity is unavailable" in item["error"] for item in result["errors"])


def test_shared_context_layout_conflict_quarantine_persistence_failure_blocks_controller(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    _store, _worktree, _local_path, canonical = _context_digest_fixture(tmp_path / "fixture")
    legacy = MODULE.shared_context_root() / MODULE._legacy_shared_context_filename(
        "https://github.com/a/b/issues/1"
    )
    value = json.loads(canonical.read_text(encoding="utf-8"))
    legacy.write_text(json.dumps(value | {"threadId": "other"}), encoding="utf-8")
    os.chmod(legacy, 0o600)

    def fail_record(*_args, **_kwargs):
        raise sqlite3.Error("simulated persistence failure")

    monkeypatch.setattr(RadarLedger, "_record_shared_context_quarantine", fail_record)

    result = MODULE.recover_shared_task_contexts(RadarLedger(tmp_path / "ledger.sqlite3"))

    assert result["verified"] == 0
    assert result["quarantined"] == []
    assert len(result["errors"]) == 2
    assert all("quarantine persistence failed" in item["error"] for item in result["errors"])


def test_fresh_signed_intent_can_replace_a_task_whose_workspace_was_lost(tmp_path):
    store, worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "FIX_READY", evidence={})

    replaced = store.supersede_missing_workspace(
        key="a/b#1",
        intent_id="intent-1",
        worktree_path=str(worktree),
        replacement_intent_id="intent-2",
    )
    now = datetime.now(UTC)
    inserted = store.enqueue(
        {
            "intentId": "intent-2",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot-2",
            "decisionDigest": "decision-2",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )

    assert replaced is True
    assert inserted is True
    assert [item["intentId"] for item in store.pending()] == ["intent-2"]


def test_shared_context_recovery_accepts_a_superseded_dispatched_mirror(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    verified = MODULE.recover_shared_task_contexts(store)

    assert verified["verified"] == 1
    assert verified["errors"] == []
    assert verified["restored"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "intentRestored": False,
            "publicationRestored": False,
            "supersededActiveMirror": True,
            "resultReceiptRestored": False,
        }
    ]


def test_shared_context_recovery_accepts_a_terminal_no_go_over_dispatched_mirror(
    monkeypatch, tmp_path
):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    store.record_stage("a/b#1", "AUDIT_NO_GO", evidence={}, reason="DUPLICATE")

    verified = MODULE.recover_shared_task_contexts(store)

    assert verified["verified"] == 1
    assert verified["errors"] == []
    assert verified["restored"] == [
        {
            "key": "a/b#1",
            "stage": "AUDIT_NO_GO",
            "intentRestored": False,
            "publicationRestored": False,
            "supersededActiveMirror": True,
            "resultReceiptRestored": False,
        }
    ]


def test_shared_context_recovery_does_not_rebuild_a_dispatched_task(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 0
    assert result["restored"] == []
    assert result["errors"] == []
    assert result["quarantined"][0]["reason"] == "SHARED_CONTEXT_INVALID"


def test_shared_context_recovery_fails_closed_when_mirrors_disagree(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    value = json.loads(context_path.read_text(encoding="utf-8"))
    value["stage"] = "FIX_READY"
    MODULE._atomic_json(context_path, value)

    recovered = RadarLedger(tmp_path / "recovered.sqlite3")
    result = MODULE.recover_shared_task_contexts(recovered)

    assert result["verified"] == 0
    assert result["restored"] == []
    assert result["errors"] == []
    assert result["quarantined"][0]["reason"] == "SHARED_CONTEXT_INVALID"


def test_shared_context_recovery_marks_clean_published_result_as_consumed(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.managed_worktree_path("intent-1", "a/b")
    store, _ = registered_store(tmp_path / "original", worktree=worktree)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: add runtime boundary")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    source.write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update(
            {
                "taskStage": "IMPLEMENTATION_READY",
                "probeLevel": "REPRODUCED_VALIDATED",
                "selectedBaseSha": base_sha,
                "codePaths": ["runtime.py"],
            }
        )
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "FIX_READY",
                "handoffMode": "controller_commit_complete",
                "branch": run_git(worktree, "symbolic-ref", "--short", "HEAD"),
                "controllerCommitChangedFiles": ["runtime.py"],
                "taskStage": "IMPLEMENTATION_READY",
                "taskId": "intent-1",
                "probeRequired": True,
                "probeLevel": "REPRODUCED_VALIDATED",
                "selectedBaseSha": base_sha,
                "headSha": head_sha,
                "commitSha": head_sha,
                "codePaths": ["runtime.py"],
                "preTaskEvidence": {
                    "defaultBranch": "main",
                    "baseSha": base_sha,
                    "codePathsPlan": ["runtime.py"],
                },
                "changedFiles": ["runtime.py"],
                "quality": {key: True for key in QUALITY_FIELDS},
                "independentReview": {
                    "verdict": "PASS",
                    "summary": "test controller receipt",
                },
                "publication": {
                    "headOwner": "Oxygen56",
                    "baseBranch": "main",
                    "title": "fix: runtime",
                    "bodyFile": str(worktree / ".oss-pr-radar" / "pr-body.md"),
                },
            }
        ),
        encoding="utf-8",
    )
    result_value = json.loads(result_path.read_text(encoding="utf-8"))
    _sign_reproduction_certificate(
        result_value,
        result_path=result_path,
        base_sha=base_sha,
        head_sha=head_sha,
        commit_sha=head_sha,
        store=store,
    )
    request = store.create_publication_request(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        commit_sha=head_sha,
        branch="fix-runtime",
        worktree_path=str(worktree),
        evidence_digest="evidence",
        evidence_path=str(result_path),
        publication={
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "fix: runtime",
            "bodyPath": str(worktree / ".oss-pr-radar" / "pr-body.md"),
        },
        probe_receipt=result_value["reproductionReceipt"],
        result_digest=result_value["resultDigest"],
        head_sha=head_sha,
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
    )
    permit = store.grant_publication_request(
        request["request_id"],
        issue_url="https://github.com/a/b/issues/1",
        commit_sha=head_sha,
        branch="fix-runtime",
        evidence={},
    )
    store.consume_publication_permit(permit["permit_id"], "https://github.com/a/b/pull/2")
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    recovered_path = tmp_path / "recovered.sqlite3"
    recovered = RadarLedger(recovered_path)
    recovery = MODULE.recover_shared_task_contexts(recovered)
    recovered_value = json.loads(result_path.read_text(encoding="utf-8"))
    monkeypatch.setattr(
        MODULE,
        "controller_review_result",
        lambda *_args: recovered_value["independentReview"],
    )
    ingestion = MODULE.ingest_task_results(SimpleNamespace(ledger=recovered_path))

    assert recovery["resultReceiptsRestored"] == 1
    assert recovery["restored"][0]["resultReceiptRestored"] is True
    assert ingestion["ok"] is True, ingestion["errors"]
    assert ingestion["ingested"] == []
    assert ingestion["publicationRequests"] == []
    with recovered.connect() as connection:
        followup_results = connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='PR_FOLLOWUP_RESULT_INGESTED'"
        ).fetchone()[0]
    assert followup_results == 0


def test_clean_pr_followup_result_restores_its_wake_receipt(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    (worktree / ".git" / "info" / "exclude").write_text(".oss-pr-radar/\n", encoding="utf-8")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    MODULE._exclude_private_task_dir(worktree)
    private = worktree / ".oss-pr-radar"
    private.mkdir()
    result_path = private / "result.json"
    context = {
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "resultPath": str(result_path),
        "contextDigest": "context",
        "stage": "PR_OPEN",
        "publicationReceipt": {
            "prUrl": "https://github.com/a/b/pull/2",
            "commitSha": head_sha,
        },
        "prFollowup": {"wakeDigest": "wake"},
    }
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": "context",
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "followupDigest": "wake",
                "evidence": {"reviewed": True},
            }
        ),
        encoding="utf-8",
    )

    recovered = MODULE._recoverable_published_result(context)

    assert recovered is not None
    assert recovered["stage"] == "PR_OPEN"
    assert recovered["wakeDigest"] == "wake"

    context["contextDigest"] = "new-context"
    context["prFollowup"] = {"wakeDigest": "new-wake"}
    assert MODULE._recoverable_published_result(context) is None

    stale_fix = json.loads(result_path.read_text(encoding="utf-8"))
    stale_fix["stage"] = "FIX_READY"
    stale_fix.pop("followupDigest")
    result_path.write_text(json.dumps(stale_fix), encoding="utf-8")
    recovered_fix = MODULE._recoverable_published_result(context)
    assert recovered_fix is not None
    assert recovered_fix["stage"] == "FIX_READY"


def test_context_recovery_ignores_already_ingested_result_from_older_context(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    private = worktree / ".oss-pr-radar"
    private.mkdir()
    result_path = private / "result.json"
    context = {
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "resultPath": str(result_path),
        "contextDigest": "new-context",
        "stage": "PR_OPEN",
        "publicationReceipt": {
            "prUrl": "https://github.com/a/b/pull/2",
            "commitSha": head_sha,
        },
    }
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": "old-context",
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "followupDigest": "old-wake",
            }
        ),
        encoding="utf-8",
    )
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "category": "NEW_CLEAN_CANDIDATE",
            "scanGate": "ALLOW_TO_WORK",
            "autoSpawn": True,
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    digest = hashlib.sha256(result_path.read_bytes()).hexdigest()
    store.record_task_result_ingested("a/b#1", digest=digest, stage="PR_OPEN")

    assert MODULE._recoverable_published_result(context, store=store) is None


def test_prepare_managed_worktree_is_isolated_under_github_project(monkeypatch, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    run_git(source, "init")
    run_git(source, "config", "user.name", "Test Contributor")
    run_git(source, "config", "user.email", "test@example.com")
    (source / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(source, "add", "runtime.py")
    run_git(source, "commit", "-m", "baseline")
    run_git(source, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)

    worktree = MODULE.prepare_managed_worktree(
        source,
        intent_id="intent-1",
        repo="a/b",
    )

    assert MODULE._is_managed_worktree(worktree) is True
    assert (worktree / "runtime.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert MODULE._worktree_belongs_to_source(worktree, source) is True
    assert run_git(worktree, "status", "--porcelain") == ""


def test_worktree_membership_uses_common_repository_for_linked_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    run_git(source, "init")
    run_git(source, "config", "user.name", "Test Contributor")
    run_git(source, "config", "user.email", "test@example.com")
    (source / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(source, "add", "runtime.py")
    run_git(source, "commit", "-m", "baseline")
    linked = tmp_path / "linked"
    run_git(source, "worktree", "add", "--detach", str(linked), "HEAD")

    assert MODULE._worktree_belongs_to_source(source, linked) is True


def test_commit_receipt_binds_github_project_thread_to_managed_worktree(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    source.mkdir()
    run_git(source, "init")
    run_git(source, "config", "user.name", "Test Contributor")
    run_git(source, "config", "user.email", "test@example.com")
    (source / "runtime.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(source, "add", "runtime.py")
    run_git(source, "commit", "-m", "baseline")
    run_git(source, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    worktree = MODULE.prepare_managed_worktree(
        source,
        intent_id="intent-1",
        repo="a/b",
    )
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
            "autoSubmitAuthorized": True,
            "publicSubmissionAllowed": True,
            "authorizationSource": "signed_live_revalidation_required",
            "publicationMode": "canary",
        }
    )
    store.claim("intent-1", "controller")
    store.record_audit_snapshot(
        "a/b#1",
        evidence={
            "authorization": {"status": "ALLOW"},
            "evidenceDigest": "live-evidence",
            "liveAudit": {
                "capturedAt": iso_z(now),
                "evidence": {"digest": "live-evidence", "issue": {"state": "open"}},
            },
        },
        dedupe_key="live-evidence",
    )
    title_time = "08-08 16:20"
    title = MODULE.lifecycle_title("GO", title_time, "a/b#1", "Runtime bug")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?)",
            (
                "thread-1",
                str(project_root),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                None,
                0,
            ),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    def apply_titles(candidates):
        assert candidates[0]["desiredTitle"] == title
        with sqlite3.connect(thread_db) as connection:
            connection.execute(
                "UPDATE threads SET title=? WHERE id=?",
                (candidates[0]["desiredTitle"], candidates[0]["threadId"]),
            )
        return {"thread-1": None}

    monkeypatch.setattr(MODULE, "_set_desktop_thread_titles", apply_titles)

    result = MODULE.commit_receipt(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            thread_id="thread-1",
            project_id="github-project",
            cwd=str(project_root),
            worktree=str(worktree),
            source_repo=str(source),
            title_time=title_time,
        )
    )

    assert result["workspaceMode"] == "github_project_managed_worktree"
    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context is not None
    assert context["worktreePath"] == str(worktree)
    assert MODULE.shared_context_path("https://github.com/a/b/issues/1").exists()


def test_private_task_dispatch_is_not_limited_by_publication_canary(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)

    def candidate_intent(number: int):
        return {
            "intentId": f"intent-{number}",
            "key": f"a/b#{number}",
            "repo": "a/b",
            "issueNumber": number,
            "issueUrl": f"https://github.com/a/b/issues/{number}",
            "title": f"Runtime bug {number}",
            "mode": "canary",
            "category": "NEW_CLEAN_CANDIDATE",
            "scanGate": "ALLOW_TO_WORK",
            "autoSpawn": True,
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": f"decision-{number}",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }

    store.enqueue(candidate_intent(1))
    store.enqueue(candidate_intent(2))
    store.record_stage(
        "a/b#2",
        "AUDIT_PASS",
        evidence={"evidenceDigest": "evidence-2"},
        dedupe_key="intent-2:evidence-2",
    )
    store.claim("intent-1", "controller")
    store.commit_dispatch(
        "intent-1",
        owner="controller",
        thread_id="thread-1",
        project_id="github",
        worktree_path="/tmp/worktree-1",
    )

    evidence = SimpleNamespace(
        digest="evidence-2",
        as_dict=lambda: {
            "digest": "evidence-2",
            "complete": True,
            "repo": "a/b",
            "issue": {"labels": []},
        },
    )
    verdict = SimpleNamespace(
        status="ALLOW",
        reason_code="ALLOW",
        as_dict=lambda: {"status": "ALLOW", "reasonCode": "ALLOW"},
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))
    monkeypatch.setattr(
        MODULE,
        "resolve_target_base",
        lambda _client, _repo, _issue: {
            "branch": "main",
            "sha": "a" * 40,
            "source": "repository_default",
            "defaultBranch": "main",
        },
    )
    monkeypatch.setenv("RADAR_MAX_ACTIVE_TASKS", "0")

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-2",
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )

    assert result["claimed"] is True
    with store.connect() as connection:
        audit = connection.execute(
            """SELECT payload_json FROM events
               WHERE opportunity_key='a/b#2' AND event_type='AUDIT_PASS'
               ORDER BY id DESC LIMIT 1"""
        ).fetchone()
    assert json.loads(audit["payload_json"])["liveAudit"]["evidence"]["digest"] == ("evidence-2")


def test_private_task_dispatch_defaults_to_five_active_tasks(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    for number in range(1, 7):
        store.enqueue(
            {
                "intentId": f"intent-{number}",
                "key": f"a/b#{number}",
                "repo": "a/b",
                "issueNumber": number,
                "issueUrl": f"https://github.com/a/b/issues/{number}",
                "title": f"Runtime bug {number}",
                "mode": "canary",
                "category": "NEW_CLEAN_CANDIDATE",
                "scanGate": "ALLOW_TO_WORK",
                "autoSpawn": True,
                "score": 9,
                "snapshotId": "snapshot",
                "decisionDigest": f"decision-{number}",
                "issuedAt": iso_z(now),
                "expiresAt": iso_z(now + timedelta(hours=1)),
            }
        )
    for number in range(1, 6):
        store.claim(f"intent-{number}", "controller")
        store.commit_dispatch(
            f"intent-{number}",
            owner="controller",
            thread_id=f"thread-{number}",
            project_id="github",
            worktree_path=f"/tmp/worktree-{number}",
        )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "_audit_intent",
        lambda _intent: pytest.fail("WIP-limited tasks must not run a live audit"),
    )
    monkeypatch.delenv("RADAR_MAX_ACTIVE_TASKS", raising=False)

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-6",
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )

    assert result["authorized"] is False
    assert result["auditDeferred"] is True
    assert result["held"] is True
    assert result["claimed"] is False
    assert result["reason"] == "task_wip_limit"


def test_independent_review_runs_while_issue_task_lifecycle_is_active(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    schema_path = tmp_path / "schemas" / "independent_review.schema.json"
    schema_path.parent.mkdir(parents=True)
    schema_path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        MODULE,
        "review_once",
        lambda *_args, **_kwargs: {"ok": True, "updated": ["a/b#1"]},
    )

    result = MODULE.independent_review_run(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {"ok": True, "updated": ["a/b#1"]}


def test_independent_review_missing_schema_is_nonfatal(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)

    result = MODULE.independent_review_run(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {
        "ok": True,
        "unavailable": True,
        "reason": "independent_review_schema_unavailable",
        "updated": [],
        "skipped": [],
        "errors": [],
    }


def test_new_issue_priority_includes_pending_independent_review(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: {
            "candidates": [],
            "restoreRequired": [],
            "unresolved": [],
        },
    )
    monkeypatch.setattr(
        MODULE,
        "validation_followup_list",
        lambda _args: {
            "candidates": [],
            "controllerReviewPending": [{"key": "a/b#1"}],
            "unresolved": [],
        },
    )
    monkeypatch.setattr(
        MODULE,
        "recovery_list",
        lambda _args: {"recoverable": [], "unresolved": []},
    )

    result = MODULE._higher_priority_existing_work(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"),
        intent_key="a/b#2",
    )

    assert result == [{"kind": "independent_review", "key": "a/b#1"}]


def test_new_issue_claim_defers_to_existing_validation_work(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-new",
            "key": "a/b#2",
            "repo": "a/b",
            "issueNumber": 2,
            "issueUrl": "https://github.com/a/b/issues/2",
            "title": "New runtime bug",
            "mode": "canary",
            "category": "NEW_CLEAN_CANDIDATE",
            "scanGate": "ALLOW_TO_WORK",
            "autoSpawn": True,
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision-new",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "_higher_priority_existing_work",
        lambda _args, *, intent_key: [{"kind": "validation_followup", "key": "a/b#1"}],
    )
    monkeypatch.setattr(
        MODULE,
        "_audit_intent",
        lambda _intent: pytest.fail("new issue must not be audited ahead of validation"),
    )

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-new",
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )

    assert result == {
        "ok": True,
        "authorized": False,
        "auditDeferred": True,
        "held": True,
        "claimed": False,
        "reason": "higher_priority_existing_work",
        "priorityWork": [{"kind": "validation_followup", "key": "a/b#1"}],
    }
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_claim_hold_does_not_terminalize_candidate(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    store.enqueue(
        intent := {
            "intentId": "intent-hold",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(datetime.now(UTC)),
            "expiresAt": iso_z(datetime.now(UTC) + timedelta(hours=1)),
        }
    )
    evidence = SimpleNamespace(digest="evidence", as_dict=lambda: {"digest": "evidence"})
    verdict = SimpleNamespace(
        status="HOLD",
        reason_code="MAINTAINER_REVIEW_PENDING",
        as_dict=lambda: {
            "status": "HOLD",
            "reasonCode": "MAINTAINER_REVIEW_PENDING",
        },
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id=intent["intentId"],
            owner="controller",
            lease_minutes=15,
            prepare=False,
        )
    )

    assert result["authorized"] is False
    assert result["held"] is True
    assert store.pending()[0]["ledgerStatus"] == "PENDING"
    with store.connect() as connection:
        stage = connection.execute("SELECT stage FROM opportunities WHERE key='a/b#1'").fetchone()[
            "stage"
        ]
    assert stage == "QUALIFIED"


def test_dispatch_notification_receipt_is_per_created_thread(tmp_path):
    store, _worktree = registered_store(tmp_path)

    assert [item["threadId"] for item in store.dispatch_notification_candidates()] == ["thread-1"]
    store.commit_dispatch_notification(thread_id="thread-1", idempotency_key="notification-1")
    assert store.dispatch_notification_candidates() == []


def test_prepare_failure_releases_claim(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    evidence = SimpleNamespace(
        digest="evidence",
        as_dict=lambda: {
            "digest": "evidence",
            "complete": True,
            "repo": "a/b",
            "issue": {"labels": []},
        },
    )
    verdict = SimpleNamespace(
        status="ALLOW",
        reason_code="ALLOW",
        as_dict=lambda: {"status": "ALLOW", "reasonCode": "ALLOW"},
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))
    monkeypatch.setattr(
        MODULE,
        "resolve_target_base",
        lambda _client, _repo, _issue: {
            "branch": "main",
            "sha": "a" * 40,
            "source": "repository_default",
            "defaultBranch": "main",
        },
    )
    monkeypatch.setattr(
        MODULE,
        "source_repo",
        lambda _repo, **_kwargs: (_ for _ in ()).throw(RuntimeError("clone timeout")),
    )

    with pytest.raises(RuntimeError, match="clone timeout"):
        MODULE.claim_intent(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                intent_id="intent-1",
                owner="controller",
                lease_minutes=15,
                prepare=True,
            )
        )

    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_prepare_claim_returns_single_project_root_and_isolated_worktree(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    evidence = SimpleNamespace(
        digest="evidence",
        as_dict=lambda: {
            "digest": "evidence",
            "complete": True,
            "repo": "a/b",
            "issue": {"labels": []},
        },
    )
    verdict = SimpleNamespace(
        status="ALLOW",
        reason_code="ALLOW",
        as_dict=lambda: {"status": "ALLOW", "reasonCode": "ALLOW"},
    )
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))
    monkeypatch.setattr(
        MODULE,
        "resolve_target_base",
        lambda _client, _repo, _issue: {
            "branch": "main",
            "sha": "a" * 40,
            "source": "repository_default",
            "defaultBranch": "main",
        },
    )
    monkeypatch.setattr(MODULE, "source_repo", lambda _repo, **_kwargs: source)
    monkeypatch.setattr(MODULE, "prepare_managed_worktree", lambda *_args, **_kwargs: worktree)

    result = MODULE.claim_intent(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            lease_minutes=15,
            prepare=True,
            task_project_id="github-project",
        )
    )

    assert result["sourceRepoPath"] == str(source)
    assert result["taskProjectPath"] == str(project_root.resolve())
    assert result["worktreePath"] == str(worktree)
    assert result["leaseOwner"] == "controller"
    assert result["createThreadRequest"] == {
        "prompt": (
            "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)\n"
            "https://github.com/a/b/issues/1"
        ),
        "target": {
            "type": "project",
            "projectId": "github-project",
            "environment": {"type": "local"},
        },
    }
    assert "projectId" not in result["createThreadRequest"]


def test_creation_start_infers_active_lease_owner(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    assert store.claim("intent-1", "controller") is not None
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.creation_start(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner=None,
        )
    )

    assert result["ok"] is True
    assert result["intentId"] == "intent-1"
    assert result["creationToken"]
    assert store.current_lease_owner("intent-1") == "controller"


def test_creation_start_does_not_override_explicit_wrong_owner(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    assert store.claim("intent-1", "controller") is not None
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    with pytest.raises(LedgerError, match="not leased by this owner"):
        MODULE.creation_start(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                intent_id="intent-1",
                owner="mistyped-controller",
            )
        )


def test_claim_release_returns_unstarted_lease_to_pending(monkeypatch, tmp_path):
    store = RadarLedger(tmp_path / "ledger.sqlite3")
    now = datetime.now(UTC)
    store.enqueue(
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "repo": "a/b",
            "issueNumber": 1,
            "issueUrl": "https://github.com/a/b/issues/1",
            "title": "Runtime bug",
            "mode": "canary",
            "score": 9,
            "snapshotId": "snapshot",
            "decisionDigest": "decision",
            "issuedAt": iso_z(now),
            "expiresAt": iso_z(now + timedelta(hours=1)),
        }
    )
    store.claim("intent-1", "controller")
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.release_claim(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner=None,
            reason="CONTROLLER_DID_NOT_START_CREATION",
        )
    )

    assert result == {"ok": True, "intentId": "intent-1", "released": True}
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_new_repo_clone_is_shallow_and_atomic(monkeypatch, tmp_path):
    commands = []
    prewarmed = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        clone_target = Path(args[-1])
        clone_target.mkdir(parents=True)
        (clone_target / ".git").mkdir()
        return ""

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "prewarm_source_repo", prewarmed.append)

    path = MODULE.source_repo("example/large-repo")

    clone = commands[0][0]
    assert clone[:2] == ["git", "clone"]
    assert "--depth=1" in clone
    assert "--single-branch" in clone
    assert "--no-tags" in clone
    assert commands[0][2] == 180
    assert path == (tmp_path / "large-repo").resolve()
    assert prewarmed == [path]
    assert not list(tmp_path.glob(".large-repo.radar-clone-*"))


def test_existing_repo_fetches_and_prewarms_default_snapshot(monkeypatch, tmp_path):
    repo = tmp_path / "large-repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    commands = []
    prewarmed = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        if args == ["git", "remote", "get-url", "origin"]:
            return "https://github.com/example/large-repo.git"
        if args == [
            "git",
            "symbolic-ref",
            "--quiet",
            "refs/remotes/origin/HEAD",
        ]:
            return "refs/remotes/origin/main"
        return ""

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "prewarm_source_repo", prewarmed.append)

    path = MODULE.source_repo("example/large-repo")

    assert commands[2][0] == [
        "git",
        "fetch",
        "--no-write-fetch-head",
        "--no-tags",
        "--filter=blob:none",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
    ]
    assert commands[2][2] == 180
    assert prewarmed == [path]


def test_default_branch_fetch_rejects_non_origin_symbolic_ref(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE,
        "command",
        lambda *_args, **_kwargs: "refs/remotes/upstream/main",
    )

    with pytest.raises(RuntimeError, match="does not target an origin branch"):
        MODULE.fetch_default_branch(tmp_path)


def test_existing_repo_ignores_linked_worktree_candidates(monkeypatch, tmp_path):
    linked = tmp_path / "a-linked"
    linked.mkdir()
    (linked / ".git").write_text("gitdir: /tmp/common/worktrees/a-linked\n")
    repo = tmp_path / "b-main"
    repo.mkdir()
    (repo / ".git").mkdir()
    commands = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        if args == ["git", "remote", "get-url", "origin"]:
            assert cwd == repo
            return "https://github.com/example/large-repo.git"
        if args == [
            "git",
            "symbolic-ref",
            "--quiet",
            "refs/remotes/origin/HEAD",
        ]:
            return "refs/remotes/origin/main"
        return ""

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "prewarm_source_repo", lambda _path: None)

    path = MODULE.source_repo("example/large-repo")

    assert path == repo.resolve()
    assert all(cwd != linked for _args, cwd, _timeout, _stdin in commands)


def test_prewarm_source_repo_refreshes_index_and_hydrates_only_default_snapshot(
    monkeypatch, tmp_path
):
    commands = []
    quiet_commands = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        commands.append((args, cwd, timeout, stdin))
        if args[:3] == ["git", "symbolic-ref", "--quiet"]:
            return "refs/remotes/origin/main"
        return ""

    def fake_quiet_command(args, *, cwd, timeout=300):
        quiet_commands.append((args, cwd, timeout))

    monkeypatch.setattr(MODULE, "command", fake_command)
    monkeypatch.setattr(MODULE, "quiet_command", fake_quiet_command)

    MODULE.prewarm_source_repo(tmp_path)

    assert commands[0][0] == [
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    ]
    assert quiet_commands == [
        (
            [
                "git",
                "archive",
                "--format=tar",
                "refs/remotes/origin/main",
            ],
            tmp_path,
            600,
        )
    ]


def test_retry_dispatch_requires_archived_clean_resultless_task(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", str(worktree), 1))
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.retry_dispatch(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            reason="INVALID_EXECUTION_ENVIRONMENT",
        )
    )

    assert result["retried"]["intentId"] == "intent-1"
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_retry_dispatch_accepts_worktree_removed_by_archival(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", str(worktree), 1))
    shutil.rmtree(worktree)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.retry_dispatch(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            reason="INVALID_EXECUTION_ENVIRONMENT",
        )
    )

    assert result["retried"]["intentId"] == "intent-1"
    assert store.pending()[0]["ledgerStatus"] == "PENDING"


def test_recovery_accepts_github_project_thread_with_managed_worktree(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(project_root),
                None,
                1,
                None,
            ),
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["blocked"] == []
    assert result["recoverable"][0]["threadId"] == "thread-1"


def test_pr_followup_list_defers_recently_active_threads(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        connection.executemany(
            "INSERT INTO threads VALUES (?,?,?,?)",
            [
                ("thread-active", int(datetime.now(UTC).timestamp()), 0, None),
                (
                    "thread-idle",
                    int((datetime.now(UTC) - timedelta(hours=2)).timestamp()),
                    0,
                    None,
                ),
            ],
        )

    class Store:
        def pr_followup_candidates(self):
            return [
                {"key": "a/b#1", "threadId": "thread-active"},
                {"key": "a/b#2", "threadId": "thread-idle"},
            ]

        def unresolved_pr_followups(self):
            return []

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert [item["threadId"] for item in result["candidates"]] == ["thread-idle"]
    assert [item["threadId"] for item in result["activeDeferred"]] == ["thread-active"]
    assert result["activeDeferred"][0]["reason"] == "thread_recently_active"


def test_pr_followup_list_defers_ready_candidates_at_global_wip_limit(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?)",
            (
                "thread-idle",
                int((datetime.now(UTC) - timedelta(hours=2)).timestamp()),
                0,
                None,
            ),
        )

    class Store:
        def pr_followup_candidates(self):
            return [{"key": "a/b#1", "threadId": "thread-idle"}]

        def unresolved_pr_followups(self):
            return []

        def active_task_count(self, **_kwargs):
            return 1

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setenv("RADAR_MAX_ACTIVE_TASKS", "1")

    result = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["candidates"] == []
    assert result["queuedDeferred"] == [
        {
            "key": "a/b#1",
            "threadId": "thread-idle",
            "reason": "global_task_wip_limit",
            "activeTaskCount": 1,
            "taskLimit": 1,
        }
    ]


def test_pr_followup_list_requires_archived_task_restoration(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?)",
            ("thread-1", int(datetime.now(UTC).timestamp()), 1, None),
        )

    class Store:
        def pr_followup_candidates(self):
            return [{"key": "a/b#1", "threadId": "thread-1"}]

        def unresolved_pr_followups(self):
            return []

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["candidates"] == []
    assert result["restoreRequired"] == [
        {"key": "a/b#1", "threadId": "thread-1", "reason": "thread_archived"}
    ]
    assert result["blocked"] == []


def test_pr_followup_list_isolates_dirty_worktree_and_keeps_next_candidate(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    dirty = tmp_path / "dirty"
    clean = tmp_path / "clean"
    for worktree in (dirty, clean):
        worktree.mkdir()
        run_git(worktree, "init")
        run_git(worktree, "config", "user.name", "Radar Test")
        run_git(worktree, "config", "user.email", "radar-test@example.invalid")
        (worktree / "tracked.txt").write_text("base\n", encoding="utf-8")
        run_git(worktree, "add", "tracked.txt")
        run_git(worktree, "commit", "-m", "baseline")
    (dirty / "tracked.txt").write_text("changed\n", encoding="utf-8")
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        old = int((datetime.now(UTC) - timedelta(hours=2)).timestamp())
        connection.executemany(
            "INSERT INTO threads VALUES (?,?,?,?)",
            [("thread-dirty", old, 0, None), ("thread-clean", old, 0, None)],
        )

    class Store:
        def pr_followup_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-dirty",
                    "worktreePath": str(dirty),
                },
                {
                    "key": "a/b#2",
                    "threadId": "thread-clean",
                    "worktreePath": str(clean),
                },
            ]

        def unresolved_pr_followups(self):
            return []

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert [item["key"] for item in result["candidates"]] == ["a/b#2"]
    assert result["blocked"] == []
    assert result["quarantined"][0]["key"] == "a/b#1"
    assert result["quarantined"][0]["reason"] == "worktree_dirty"
    assert result["quarantined"][0]["dirtyPaths"] == ["tracked.txt"]


def test_pr_followup_list_reports_rebind_for_dirty_worktree(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    run_git(dirty, "init")
    run_git(dirty, "config", "user.name", "Radar Test")
    run_git(dirty, "config", "user.email", "radar-test@example.invalid")
    (dirty / "tracked.txt").write_text("base\n", encoding="utf-8")
    run_git(dirty, "add", "tracked.txt")
    run_git(dirty, "commit", "-m", "baseline")
    (dirty / "tracked.txt").write_text("changed\n", encoding="utf-8")
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        old = int((datetime.now(UTC) - timedelta(hours=2)).timestamp())
        connection.execute("INSERT INTO threads VALUES (?,?,?,?)", ("thread-dirty", old, 0, None))

    class Store:
        def pr_followup_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-dirty",
                    "worktreePath": str(dirty),
                }
            ]

        def pr_followup_rebind_status(self, _key):
            return {
                "expectedPreparedHeadSha": "a" * 40,
                "observedHeadSha": "b" * 40,
                "replacementWakeDigest": "c" * 64,
            }

        def unresolved_pr_followups(self):
            return []

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["candidates"] == []
    assert result["quarantined"][0]["reason"] == MODULE.PR_FOLLOWUP_REBIND_REQUIRED
    assert result["quarantined"][0]["reprepareRequired"] is True
    assert result["quarantined"][0]["dirtyPaths"] == ["tracked.txt"]

    (dirty / "tracked.txt").write_text("base\n", encoding="utf-8")
    recovered = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert recovered["candidates"] == []
    assert [item["key"] for item in recovered["reprepareRequired"]] == ["a/b#1"]
    assert recovered["quarantined"] == []


def test_parent_drift_rebind_rejects_forged_result_before_ledger_mutation(monkeypatch, tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["taskStage"] = "IMPLEMENTATION_READY"
    candidate = store.pr_followup_candidates()[0]
    monkeypatch.setattr(MODULE, "_controller_policy_verification", lambda _context: {})
    value = {
        "key": candidate["key"],
        "stage": "FIX_READY",
        "handoffMode": "controller_commit_required",
        "contextDigest": "forged-context-digest",
        "followupDigest": context["prFollowup"]["wakeDigest"],
    }

    assert (
        MODULE._parent_drift_rebind_is_valid(
            value,
            context,
            candidate=candidate,
            task_stage="IMPLEMENTATION_READY",
            prepared_head=context["prFollowup"].get("preparedHeadSha"),
            current_wake_digest=context["prFollowup"]["wakeDigest"],
            legacy_compatible_result=False,
        )
        is False
    )
    assert store.pr_followup_rebind_status(candidate["key"]) is None


def test_dirty_rebound_worktree_is_preserved_and_recreated_clean(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    run_git(source, "init")
    run_git(source, "config", "user.name", "Radar Test")
    run_git(source, "config", "user.email", "radar@example.invalid")
    (source / "tracked.txt").write_text("base\n", encoding="utf-8")
    run_git(source, "add", "tracked.txt")
    run_git(source, "commit", "-m", "baseline")
    head = run_git(source, "rev-parse", "HEAD")
    run_git(source, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(source, "update-ref", "refs/remotes/origin/main", head)
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    expected = MODULE.managed_worktree_path("intent-1", "a/b")
    expected.parent.mkdir(parents=True, exist_ok=True)
    run_git(source, "worktree", "add", "--detach", str(expected), head)
    (expected / "tracked.txt").write_text("user change\n", encoding="utf-8")
    (expected / "user-note.txt").write_text("keep me\n", encoding="utf-8")

    recovery = MODULE._recover_dirty_rebound_worktree(
        {
            "key": "a/b#1",
            "repo": "a/b",
            "intentId": "intent-1",
            "worktreePath": str(expected),
        },
        {"replacementWakeDigest": "w" * 64},
    )

    assert recovery is not None
    quarantined = Path(recovery["quarantinePath"])
    assert (quarantined / "tracked.txt").read_text(encoding="utf-8") == "user change\n"
    assert (quarantined / "user-note.txt").read_text(encoding="utf-8") == "keep me\n"
    assert run_git(expected, "status", "--porcelain") == ""


def test_dirty_rebound_worktree_move_failure_keeps_user_checkout_recoverable(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    run_git(source, "init")
    run_git(source, "config", "user.name", "Radar Test")
    run_git(source, "config", "user.email", "radar@example.invalid")
    (source / "tracked.txt").write_text("base\n", encoding="utf-8")
    run_git(source, "add", "tracked.txt")
    run_git(source, "commit", "-m", "baseline")
    head = run_git(source, "rev-parse", "HEAD")
    run_git(source, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(source, "update-ref", "refs/remotes/origin/main", head)
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    expected = MODULE.managed_worktree_path("intent-1", "a/b")
    expected.parent.mkdir(parents=True, exist_ok=True)
    run_git(source, "worktree", "add", "--detach", str(expected), head)
    (expected / "tracked.txt").write_text("user change\n", encoding="utf-8")
    (expected / "user-note.txt").write_text("keep me\n", encoding="utf-8")
    original_command = MODULE.command

    def fail_move(args, **kwargs):
        if list(args[:3]) == ["git", "worktree", "move"]:
            raise RuntimeError("injected worktree move failure")
        return original_command(args, **kwargs)

    monkeypatch.setattr(MODULE, "command", fail_move)
    with pytest.raises(RuntimeError, match="injected worktree move failure"):
        MODULE._recover_dirty_rebound_worktree(
            {
                "key": "a/b#1",
                "repo": "a/b",
                "intentId": "intent-1",
                "worktreePath": str(expected),
            },
            {"replacementWakeDigest": "w" * 64},
        )

    assert expected.exists()
    assert (expected / "tracked.txt").read_text(encoding="utf-8") == "user change\n"
    assert (expected / "user-note.txt").read_text(encoding="utf-8") == "keep me\n"
    quarantine_root = MODULE.managed_worktree_root() / ".rebind-quarantine"
    assert not quarantine_root.exists() or {item.name for item in quarantine_root.iterdir()} <= {
        ".lock"
    }


def test_dirty_rebound_recreate_failure_persists_quarantine_for_retry(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "source_repo", lambda _repo: source)
    run_git(source, "init")
    run_git(source, "config", "user.name", "Radar Test")
    run_git(source, "config", "user.email", "radar@example.invalid")
    (source / "tracked.txt").write_text("base\n", encoding="utf-8")
    run_git(source, "add", "tracked.txt")
    run_git(source, "commit", "-m", "baseline")
    head = run_git(source, "rev-parse", "HEAD")
    run_git(source, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(source, "update-ref", "refs/remotes/origin/main", head)
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    expected = MODULE.managed_worktree_path("intent-1", "a/b")
    expected.parent.mkdir(parents=True, exist_ok=True)
    run_git(source, "worktree", "add", "--detach", str(expected), head)
    (expected / "tracked.txt").write_text("user change\n", encoding="utf-8")
    (expected / "user-note.txt").write_text("keep me\n", encoding="utf-8")

    bound: dict[str, str] = {}

    class Store:
        def bind_task_quarantine_artifact(self, _key, *, reason, artifact):
            assert reason == MODULE.PR_FOLLOWUP_REBIND_REQUIRED
            bound.update(artifact)

    original_prepare = MODULE.prepare_managed_worktree
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected recreate failure")
        return original_prepare(*args, **kwargs)

    monkeypatch.setattr(MODULE, "prepare_managed_worktree", fail_once)
    candidate = {
        "key": "a/b#1",
        "repo": "a/b",
        "intentId": "intent-1",
        "worktreePath": str(expected),
    }
    status = {"reason": MODULE.PR_FOLLOWUP_REBIND_REQUIRED, "replacementWakeDigest": "w" * 64}

    with pytest.raises(RuntimeError, match="injected recreate failure"):
        MODULE._recover_dirty_rebound_worktree(candidate, status, store=Store())
    assert not expected.exists()
    assert Path(bound["quarantinePath"]).is_dir()
    assert (Path(bound["quarantinePath"]) / "user-note.txt").read_text() == "keep me\n"

    retry_status = status | {"quarantinePath": bound["quarantinePath"]}
    recovery = MODULE._recover_dirty_rebound_worktree(candidate, retry_status, store=Store())
    assert recovery["quarantinePath"] == bound["quarantinePath"]
    assert expected.is_dir()
    assert run_git(expected, "status", "--porcelain") == ""
    assert (Path(bound["quarantinePath"]) / "tracked.txt").read_text() == "user change\n"


def test_dirty_rebound_db_bind_failure_leaves_marker_for_exact_retry(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "source_repo", lambda _repo: source)
    run_git(source, "init")
    run_git(source, "config", "user.name", "Radar Test")
    run_git(source, "config", "user.email", "radar@example.invalid")
    (source / "tracked.txt").write_text("base\n", encoding="utf-8")
    run_git(source, "add", "tracked.txt")
    run_git(source, "commit", "-m", "baseline")
    head = run_git(source, "rev-parse", "HEAD")
    run_git(source, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(source, "update-ref", "refs/remotes/origin/main", head)
    run_git(source, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    expected = MODULE.managed_worktree_path("intent-1", "a/b")
    expected.parent.mkdir(parents=True, exist_ok=True)
    run_git(source, "worktree", "add", "--detach", str(expected), head)
    (expected / "tracked.txt").write_text("user change\n", encoding="utf-8")
    note = expected / "user-note.txt"
    note.write_text("keep me\n", encoding="utf-8")
    note.chmod(0o640)

    class Store:
        def __init__(self):
            self.attempts = 0

        def bind_task_quarantine_artifact(self, _key, *, reason, artifact):
            assert reason == MODULE.PR_FOLLOWUP_REBIND_REQUIRED
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("injected database bind failure")
            self.artifact = dict(artifact)

    store = Store()
    candidate = {
        "key": "a/b#1",
        "repo": "a/b",
        "intentId": "intent-1",
        "worktreePath": str(expected),
    }
    status = {"reason": MODULE.PR_FOLLOWUP_REBIND_REQUIRED}
    with pytest.raises(OSError, match="database bind failure"):
        MODULE._recover_dirty_rebound_worktree(candidate, status, store=store)
    assert not expected.exists()
    marker = next(
        (project_root / MODULE.TASK_PRIVATE_DIR / "worktrees" / ".rebind-quarantine").rglob(
            "rebind-intent.json"
        )
    )
    assert marker.stat().st_mode & 0o777 == 0o600
    quarantined = Path(json.loads(marker.read_text(encoding="utf-8"))["quarantinePath"])
    assert (quarantined / "tracked.txt").read_text(encoding="utf-8") == "user change\n"
    assert (quarantined / "user-note.txt").stat().st_mode & 0o777 == 0o640

    recovery = MODULE._recover_dirty_rebound_worktree(candidate, status, store=store)
    assert recovery["quarantinePath"] == str(quarantined)
    assert expected.is_dir()
    assert run_git(expected, "status", "--porcelain") == ""
    assert store.attempts == 2


def test_pr_followup_clean_rebind_clears_gate_and_reopens_request(monkeypatch, tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.rearm_pr_followup_after_task_drift(
        candidate["key"], expected_prepared_head_sha="a" * 40, observed_head_sha="b" * 40
    )
    candidate = store.pr_followup_candidates()[0]
    context_path = tmp_path / "task-context.json"
    monkeypatch.setattr(MODULE, "_recover_dirty_rebound_worktree", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        MODULE, "_prepare_pr_followup", lambda _candidate: {"preparedHeadSha": "c" * 40}
    )
    monkeypatch.setattr(MODULE, "write_task_context", lambda *_args, **_kwargs: context_path)

    result = MODULE.pr_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            wake_digest=candidate["wakeDigest"],
        )
    )

    assert result["ok"] is True
    assert store.active_task_quarantine(candidate["key"]) is None
    assert store.pr_followup_candidates() == []


@pytest.mark.parametrize(
    ("failure_point", "repair_fails"),
    [
        ("context", False),
        ("completion", False),
        ("context", True),
        ("completion", True),
    ],
)
def test_pr_followup_reserve_failure_is_retryable_without_stuck_gate(
    monkeypatch, tmp_path, failure_point, repair_fails
):
    store, _worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.rearm_pr_followup_after_task_drift(
        candidate["key"], expected_prepared_head_sha="a" * 40, observed_head_sha="b" * 40
    )
    candidate = store.pr_followup_candidates()[0]
    monkeypatch.setattr(MODULE, "_recover_dirty_rebound_worktree", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        MODULE, "_prepare_pr_followup", lambda _candidate: {"preparedHeadSha": "c" * 40}
    )
    context_path = tmp_path / "task-context.json"
    original_complete = RadarLedger.complete_pr_followup_reservation
    original_repair = RadarLedger.mark_pr_followup_reservation_repair_required
    calls = {"context": 0, "completion": 0}

    def write(*args, **kwargs):
        calls["context"] += 1
        if failure_point == "context" and calls["context"] == 1:
            raise OSError("injected context write failure")
        return context_path

    def complete(self, *args, **kwargs):
        calls["completion"] += 1
        if failure_point == "completion" and calls["completion"] == 1:
            raise OSError("injected quarantine clear failure")
        return original_complete(self, *args, **kwargs)

    monkeypatch.setattr(MODULE, "write_task_context", write)
    monkeypatch.setattr(RadarLedger, "complete_pr_followup_reservation", complete)

    def repair(self, *args, **kwargs):
        calls.setdefault("repair", 0)
        calls["repair"] += 1
        if repair_fails and calls["repair"] == 1:
            raise OSError("injected repair write failure")
        return original_repair(self, *args, **kwargs)

    monkeypatch.setattr(RadarLedger, "mark_pr_followup_reservation_repair_required", repair)
    first = SimpleNamespace(
        ledger=tmp_path / "ledger.sqlite3",
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
    )
    with pytest.raises(OSError):
        MODULE.pr_followup_reserve(first)
    assert store.pr_followup_candidates()
    assert store.active_task_quarantine(candidate["key"]) is not None
    assert store.active_task_count() == 0

    result = MODULE.pr_followup_reserve(first)
    assert result["ok"] is True
    assert store.active_task_quarantine(candidate["key"]) is None
    assert store.pr_followup_candidates() == []
    assert calls["context"] >= 1
    if failure_point == "completion":
        assert calls["completion"] >= 2
    if repair_fails:
        assert calls["repair"] == 1

    # A second completion is a harmless retry and cannot create a second
    # reservation or completion event.
    store.complete_pr_followup_reservation(
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
        quarantine_reason=MODULE.PR_FOLLOWUP_REBIND_REQUIRED,
    )
    with store.connect() as connection:
        counts = connection.execute(
            """SELECT event_type,COUNT(*) AS count FROM events
               WHERE opportunity_key=? AND dedupe_key=?
                 AND event_type IN ('PR_FOLLOWUP_RESERVED',
                                    'PR_FOLLOWUP_RESERVATION_REPAIRED')
               GROUP BY event_type""",
            (candidate["key"], candidate["wakeDigest"]),
        ).fetchall()
    assert {row["event_type"]: row["count"] for row in counts} == {
        "PR_FOLLOWUP_RESERVED": 1,
        "PR_FOLLOWUP_RESERVATION_REPAIRED": 1,
    }


def test_pr_followup_reserve_serializes_concurrent_retries(monkeypatch, tmp_path):
    store, _worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.rearm_pr_followup_after_task_drift(
        candidate["key"], expected_prepared_head_sha="a" * 40, observed_head_sha="b" * 40
    )
    candidate = store.pr_followup_candidates()[0]
    monkeypatch.setattr(MODULE, "_recover_dirty_rebound_worktree", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        MODULE, "_prepare_pr_followup", lambda _candidate: {"preparedHeadSha": "c" * 40}
    )
    context_path = tmp_path / "task-context.json"
    first_write_started = threading.Event()
    release_first_write = threading.Event()
    calls = {"write": 0}

    def write(*_args, **_kwargs):
        calls["write"] += 1
        if calls["write"] == 1:
            first_write_started.set()
            assert release_first_write.wait(5)
        return context_path

    monkeypatch.setattr(MODULE, "write_task_context", write)
    args = SimpleNamespace(
        ledger=tmp_path / "ledger.sqlite3",
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
    )
    results = []

    def run():
        try:
            results.append(("ok", MODULE.pr_followup_reserve(args)))
        except Exception as exc:  # noqa: BLE001 - assert the losing caller is stale
            results.append(("error", str(exc)))

    first = threading.Thread(target=run)
    second = threading.Thread(target=run)
    first.start()
    assert first_write_started.wait(5)
    second.start()
    time.sleep(0.05)
    release_first_write.set()
    first.join(5)
    second.join(5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert [kind for kind, _value in results].count("ok") == 1
    assert [kind for kind, _value in results].count("error") == 1
    assert calls["write"] == 1
    with store.connect() as connection:
        counts = connection.execute(
            """SELECT event_type,COUNT(*) AS count FROM events
               WHERE opportunity_key=? AND dedupe_key=?
                 AND event_type IN ('PR_FOLLOWUP_RESERVED',
                                    'PR_FOLLOWUP_RESERVATION_REPAIRED')
               GROUP BY event_type""",
            (candidate["key"], candidate["wakeDigest"]),
        ).fetchall()
    assert {row["event_type"]: row["count"] for row in counts} == {
        "PR_FOLLOWUP_RESERVED": 1,
        "PR_FOLLOWUP_RESERVATION_REPAIRED": 1,
    }


def test_pr_followup_reserve_clears_rebind_gate_after_reprepare(monkeypatch, tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    original = store.pr_followup_candidates()[0]
    rebound = store.rearm_pr_followup_after_task_drift(
        original["key"], expected_prepared_head_sha="a" * 40, observed_head_sha="b" * 40
    )
    candidate = store.pr_followup_candidates()[0]
    assert candidate["wakeDigest"] == rebound["replacementWakeDigest"]
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?)",
            (
                candidate["threadId"],
                int((datetime.now(UTC) - timedelta(hours=2)).timestamp()),
                0,
                None,
            ),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    listed = MODULE.pr_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert [item["key"] for item in listed["reprepareRequired"]] == [candidate["key"]]
    recovery_calls = []
    monkeypatch.setattr(
        MODULE,
        "_recover_dirty_rebound_worktree",
        lambda _candidate, status, **_kwargs: (
            recovery_calls.append(status) or {"quarantinePath": str(tmp_path / "quarantine")}
        ),
    )
    monkeypatch.setattr(
        MODULE, "_prepare_pr_followup", lambda _candidate: {"preparedHeadSha": "c" * 40}
    )

    result = MODULE.pr_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            wake_digest=candidate["wakeDigest"],
        )
    )

    assert result["ok"] is True
    assert recovery_calls and recovery_calls[0]["replacementWakeDigest"] == candidate["wakeDigest"]
    assert store.active_task_quarantine(candidate["key"]) is None


def test_pr_followup_never_abandons_an_unreceipted_delivery(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    reserved_at = iso_z(now - timedelta(hours=2))
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?)",
            ("thread-1", int((now - timedelta(hours=3)).timestamp()), 0, None),
        )

    class Store:
        def pr_followup_candidates(self):
            return []

        def unresolved_pr_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "thread_id": "thread-1",
                    "pr_url": "https://github.com/a/b/pull/2",
                    "wake_digest": "a" * 64,
                    "created_at": reserved_at,
                }
            ]

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    args = SimpleNamespace(
        ledger=tmp_path / "ledger.sqlite3",
        min_age_minutes=90,
    )
    probe = MODULE.pr_followup_list(args)
    unresolved = probe["unresolved"][0]

    assert unresolved["abandonable"] is False
    assert unresolved["commitReady"] is False
    assert "abandonNonce" not in unresolved
    with pytest.raises(RuntimeError, match="not safely abandonable"):
        MODULE.pr_followup_abandon(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id="thread-1",
                wake_digest="a" * 64,
                abandon_nonce="unused",
                reason="TARGET_TURN_NOT_MATERIALIZED",
                min_age_minutes=90,
            )
        )


def test_pr_followup_keeps_unknown_delivery_when_target_thread_updated(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    reserved_at = now - timedelta(hours=2)
    issue_url = "https://github.com/a/b/issues/1"
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "timestamp": iso_z(reserved_at + timedelta(minutes=1)),
                "type": "event_msg",
                "payload": {
                    "type": "user_message",
                    "message": MODULE._pr_followup_prompt({"issueUrl": issue_url}),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, updated_at INTEGER, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?)",
            (
                "thread-1",
                int((now - timedelta(minutes=30)).timestamp()),
                0,
                str(rollout),
            ),
        )

    class Store:
        def pr_followup_candidates(self):
            return []

        def unresolved_pr_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "thread_id": "thread-1",
                    "pr_url": "https://github.com/a/b/pull/2",
                    "wake_digest": "a" * 64,
                    "created_at": iso_z(reserved_at),
                }
            ]

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.pr_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["unresolved"][0]["targetTurnMaterialized"] is True
    assert result["unresolved"][0]["commitReady"] is True
    assert result["unresolved"][0]["abandonable"] is False


def test_recovery_skips_a_recently_active_thread(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(project_root),
                None,
                int(datetime.now(UTC).timestamp()),
                None,
            ),
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["blocked"] == []
    assert result["recoverable"] == []


def test_recovery_immediately_surfaces_a_recent_terminal_desktop_error(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    run_git(worktree, "init")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        "\n".join(
            [
                json.dumps({"type": "turn_context", "payload": {"turn_id": "turn-1"}}),
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "turn_id": "turn-1",
                            "error": {
                                "codex_error_info": "cyber_policy",
                                "message": "try rephrasing",
                            },
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(project_root),
                None,
                int(datetime.now(UTC).timestamp()),
                str(rollout),
            ),
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["blocked"] == []
    assert result["recoverable"][0]["immediateRecovery"] is True
    assert result["recoverable"][0]["terminalError"]["code"] == "cyber_policy"


def test_recovery_immediately_resumes_an_interrupted_validation_followup(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest",
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(worktree),
                "https://github.com/a/b.git",
                int(datetime.now(UTC).timestamp()),
                None,
            ),
        )

    interrupted = {
        "status": "interrupted",
        "code": "turn_interrupted",
        "message": "interrupted",
        "turnId": "turn-validation",
    }
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "latest_thread_turn_state",
        lambda _rollout_path: interrupted,
    )
    monkeypatch.setattr(
        MODULE,
        "active_task_turn_worker",
        lambda thread_id: (
            {"pid": 123, "deliveryKind": "validation-followup"} if thread_id == "thread-1" else None
        ),
    )

    draining = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert draining["recoverable"] == []
    assert draining["activeDeferred"][0]["reason"] == "terminal_turn_worker_draining"

    monkeypatch.setattr(MODULE, "active_task_turn_worker", lambda _thread_id: None)

    listed = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert listed["activeDeferred"] == []
    assert listed["recoverable"][0]["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert listed["recoverable"][0]["immediateRecovery"] is True
    assert listed["recoverable"][0]["terminalError"] == interrupted

    reserved = MODULE.recovery_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            recovery_nonce=listed["recoverable"][0]["recoveryNonce"],
        )
    )

    assert reserved["terminalError"] == interrupted
    assert reserved["prompt"] == MODULE.VALIDATION_RECOVERY_PROMPT


def test_recovery_resumes_completed_validation_turn_without_a_new_result(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text("{}\n", encoding="utf-8")
    result_digest = hashlib.sha256(result_path.read_bytes()).hexdigest()
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=result_digest,
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest=result_digest)
    store.commit_validation_followup(thread_id="thread-1", result_digest=result_digest)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                0,
                "task",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                str(worktree),
                "https://github.com/a/b.git",
                int(datetime.now(UTC).timestamp()),
                None,
            ),
        )

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "latest_thread_turn_state",
        lambda _rollout_path: {
            "status": "completed",
            "code": None,
            "message": "",
            "turnId": "turn-validation",
        },
    )
    monkeypatch.setattr(MODULE, "active_task_turn_worker", lambda _thread_id: None)

    listed = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert listed["activeDeferred"] == []
    assert listed["recoverable"][0]["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert listed["recoverable"][0]["immediateRecovery"] is True
    assert listed["recoverable"][0]["completionWithoutResult"] is True


def test_interrupted_recovery_turn_is_rearmed_once(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?)", ("thread-1", None))
    calls = []

    class Store:
        def sent_recoveries_without_result(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "reservation": {"recoveryNonce": "nonce-1"},
                    "retryCount": 0,
                }
            ]

        def abandon_recovery_delivery(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(
        MODULE,
        "live_thread_turn_states",
        lambda _ids: {
            "thread-1": {
                "turnId": "turn-1",
                "status": "interrupted",
                "code": "turn_interrupted",
                "message": "interrupted",
            }
        },
    )
    monkeypatch.setattr(MODULE, "_discard_negative_task_turn_receipt", lambda **_kwargs: None)

    rearmed, exhausted = MODULE._rearm_interrupted_recovery_turns(Store())

    assert exhausted == []
    assert rearmed[0]["reason"] == "TERMINAL_RECOVERY_TURN_INTERRUPTED"
    assert calls == [
        {
            "thread_id": "thread-1",
            "nonce": "nonce-1",
            "reason": "TERMINAL_RECOVERY_TURN_INTERRUPTED",
            "min_age_minutes": 0,
        }
    ]


def test_interrupted_recovery_turn_stops_after_one_rearm(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?)", ("thread-1", None))

    exhausted_calls = []

    class Store:
        def sent_recoveries_without_result(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "reservation": {"recoveryNonce": "nonce-2"},
                    "retryCount": 1,
                }
            ]

        def exhaust_recovery(self, **kwargs):
            exhausted_calls.append(kwargs)

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(
        MODULE,
        "live_thread_turn_states",
        lambda _ids: {
            "thread-1": {
                "turnId": "turn-2",
                "status": "interrupted",
                "code": "turn_interrupted",
                "message": "interrupted",
            }
        },
    )
    monkeypatch.setattr(MODULE, "_discard_negative_task_turn_receipt", lambda **_kwargs: None)

    rearmed, exhausted = MODULE._rearm_interrupted_recovery_turns(Store())

    assert rearmed == []
    assert exhausted[0]["reason"] == "RECOVERY_RETRY_EXHAUSTED"
    assert exhausted_calls == [{"thread_id": "thread-1", "nonce": "nonce-2"}]


def test_new_validation_followup_is_not_blocked_by_prior_sent_recovery(tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "VALIDATION_PENDING")

    first_digest = "result-digest-1"
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=first_digest,
        missing=["relevant_tests_green"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest=first_digest)
    store.commit_validation_followup(thread_id="thread-1", result_digest=first_digest)
    first_recovery = store.recovery_candidates(min_age_minutes=0)[0]
    store.reserve_recovery(thread_id="thread-1", nonce=first_recovery["recoveryNonce"])
    store.commit_recovery(thread_id="thread-1", nonce=first_recovery["recoveryNonce"])

    second_digest = "result-digest-2"
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=["independent_review_passed"],
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest=second_digest)
    store.commit_validation_followup(thread_id="thread-1", result_digest=second_digest)

    second_recovery = store.recovery_candidates(min_age_minutes=0)[0]

    assert second_recovery["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert second_recovery["followupDigest"] == second_digest
    assert second_recovery["recoveryNonce"] != first_recovery["recoveryNonce"]
    store.reserve_recovery(thread_id="thread-1", nonce=second_recovery["recoveryNonce"])
    reservation = store.unresolved_recoveries()[0]["reservation"]
    assert reservation["recoveryKind"] == "VALIDATION_FOLLOWUP_RESULT"
    assert reservation["followupDigest"] == second_digest


def test_validation_continuation_excludes_its_own_intent_from_wip(monkeypatch, tmp_path):
    observed = {}
    candidate = {
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "intentId": "intent-1",
        "worktreePath": str(tmp_path / "worktree"),
        "resultDigest": "result-digest",
        "missing": ["relevant_tests_green"],
    }

    class Store:
        def active_task_count(self, *, exclude_intent_id=None):
            observed["excludeIntentId"] = exclude_intent_id
            return 0

        def validation_followup_candidates(self):
            return [candidate]

        def reserve_validation_followup(self, **_kwargs):
            return candidate

    monkeypatch.setenv("RADAR_MAX_ACTIVE_TASKS", "1")
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "_validation_prefetch_commands", lambda _candidate: [])
    monkeypatch.setattr(
        MODULE,
        "_validation_result_digest",
        lambda _candidate: candidate["resultDigest"],
    )
    monkeypatch.setattr(
        MODULE, "_execute_validation_prefetch", lambda _candidate, _commands: {"ok": True}
    )
    monkeypatch.setattr(
        MODULE,
        "write_task_context",
        lambda *_args, **_kwargs: tmp_path / "worktree" / ".oss-pr-radar/task-context.json",
    )

    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest="result-digest",
        )
    )

    assert reserved["ok"] is True
    assert observed["excludeIntentId"] == "intent-1"
    assert "核心回归必须证明修复前失败、修复后通过" in reserved["prompt"]
    assert "自动复核结论只能由系统写入" in reserved["prompt"]
    assert "验证段落只保留本轮最新事实" in reserved["prompt"]
    assert "删除已经被新结果推翻" in reserved["prompt"]
    assert "provider/all-extras" not in reserved["prompt"]
    assert "independent_review_passed" not in reserved["prompt"]


def test_recovery_delivery_preserves_validation_followup_prompt():
    prompt = MODULE._task_turn_prompt(
        "recovery",
        {
            "issueUrl": "https://github.com/a/b/issues/1",
            "threadId": "thread-1",
            "reservation": {"recoveryKind": "VALIDATION_FOLLOWUP_RESULT"},
        },
    )

    assert prompt == MODULE.VALIDATION_RECOVERY_PROMPT
    assert "正在处理，暂未创建 PR" in prompt
    assert "修改已完成，正在创建 PR" in prompt
    assert "不要等待或轮询系统复核、发布" in prompt
    assert "只有在本轮结束后才能继续" in prompt


def test_validation_followup_prompt_translates_internal_gaps_for_the_user():
    reservation_digest = "a" * 64
    worktree_input_path = f".oss-pr-radar/validation-inputs/{reservation_digest}.json"
    prompt = MODULE._validation_followup_prompt(
        {
            "missing": ["relevant_tests_green", "independent_review_passed"],
            "prefetchCommands": [],
            "worktreeInputPath": worktree_input_path,
        }
    )

    assert "和这次修改直接相关的检查还没全部通过" in prompt
    assert "还需确认这次修改不会引入新问题" in prompt
    assert MODULE.VALIDATION_POLICY_REVISION in prompt
    assert "第一句按真实状态选择" in prompt
    assert "固定使用‘这次在修’‘当前状态’‘下一步’" in prompt
    assert "一句不超过三十个汉字的大白话" in prompt
    assert "不能复述 issue 标题" in prompt
    assert "只有拿到准确链接后才能写" in prompt
    assert "不能只写‘继续处理’" in prompt
    assert "等待维护者启动完整检查" in prompt
    assert "发现一处可能引发错误执行的风险，正在修正" in prompt
    assert "项目的在线检查会继续完成" in prompt
    assert "不要罗列测试名称、测试数量、工具名称或构建产物" in prompt
    assert "整轮默认不发送中间进度" in prompt
    assert "不要直播排查步骤、猜测、尝试过的方案" in prompt
    assert "最终回复只回答五件事" in prompt
    assert "不重复播报未变状态" in prompt
    assert "不要在用户可见回复中提技能名" in prompt
    assert "不得描述成代码测试失败" in prompt
    assert "你无需操作" in prompt
    assert "不要等待或轮询系统复核、发布" in prompt
    assert "写完有效结果后立即给出最终回复并结束本轮" in prompt
    assert "relevant_tests_green" not in prompt
    assert "independent_review_passed" not in prompt
    assert f"`{worktree_input_path}`" in prompt
    assert "本轮输入只能只读工作区相对路径" in prompt
    assert "不要读取当前 `.oss-pr-radar/result.json` 作为本轮输入" in prompt
    assert "原子替换为新输出" in prompt
    assert str(MODULE.STATE) not in prompt


def test_pr_followup_prompt_ends_before_controller_work_can_continue():
    prompt = MODULE._pr_followup_prompt({"issueUrl": "https://github.com/a/b/issues/1"})

    assert "不要等待或轮询系统复核、发布" in prompt
    assert "只有在本轮结束后才能继续" in prompt


def test_recovery_serializes_multiple_terminal_failures(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    thread_db = tmp_path / "threads.sqlite3"
    candidates = []
    rows = []
    for index in (1, 2):
        repo = f"repo{index}"
        worktree = project_root / ".oss-pr-radar" / "worktrees" / f"task-{index}" / repo
        worktree.mkdir(parents=True)
        run_git(worktree, "init")
        run_git(worktree, "remote", "add", "origin", f"https://github.com/a/{repo}.git")
        rollout = tmp_path / f"rollout-{index}.jsonl"
        rollout.write_text(
            json.dumps(
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "task_complete",
                        "turn_id": f"turn-{index}",
                        "error": {
                            "codex_error_info": "other",
                            "message": "unexpected status 403 Forbidden",
                        },
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        issue_url = f"https://github.com/a/{repo}/issues/{index}"
        candidates.append(
            {
                "key": f"a/{repo}#{index}",
                "issueUrl": issue_url,
                "threadId": f"thread-{index}",
                "worktreePath": str(worktree),
            }
        )
        rows.append(
            (
                f"thread-{index}",
                0,
                "task",
                MODULE.issue_prompt(issue_url),
                str(project_root),
                None,
                int(datetime.now(UTC).timestamp()),
                str(rollout),
            )
        )
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.executemany("INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)", rows)

    unresolved = []

    class Store:
        def recovery_candidates(self, **_kwargs):
            return candidates

        def task_context_candidates(self):
            return []

        def unresolved_recoveries(self):
            return list(unresolved)

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert [item["threadId"] for item in result["recoverable"]] == ["thread-1"]
    assert [item["threadId"] for item in result["queuedDeferred"]] == ["thread-2"]

    unresolved.append(
        {
            "key": "a/other#3",
            "threadId": "thread-other",
            "reservedAt": iso_z(datetime.now(UTC)),
        }
    )
    blocked_by_unknown_delivery = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert blocked_by_unknown_delivery["recoverable"] == []
    assert [item["threadId"] for item in blocked_by_unknown_delivery["queuedDeferred"]] == [
        "thread-1",
        "thread-2",
    ]
    assert {item["reason"] for item in blocked_by_unknown_delivery["queuedDeferred"]} == {
        "recovery_delivery_unresolved"
    }


def test_active_turn_defers_all_terminal_recoveries(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    active_worktree = project_root / ".oss-pr-radar" / "worktrees" / "active" / "active"
    failed_worktree = project_root / ".oss-pr-radar" / "worktrees" / "failed" / "failed"
    for worktree, repo in ((active_worktree, "active"), (failed_worktree, "failed")):
        worktree.mkdir(parents=True)
        run_git(worktree, "init")
        run_git(worktree, "remote", "add", "origin", f"https://github.com/a/{repo}.git")
    active_rollout = tmp_path / "active.jsonl"
    active_rollout.write_text(
        json.dumps({"type": "turn_context", "payload": {"turn_id": "turn-active"}}) + "\n",
        encoding="utf-8",
    )
    failed_rollout = tmp_path / "failed.jsonl"
    failed_rollout.write_text(
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "turn_id": "turn-failed",
                    "error": {"codex_error_info": "unauthorized", "message": "logged out"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    now = int(datetime.now(UTC).timestamp())
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, archived INTEGER, title TEXT, first_user_message TEXT,
                cwd TEXT, git_origin_url TEXT, updated_at INTEGER, rollout_path TEXT
            )"""
        )
        connection.executemany(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            [
                (
                    "thread-active",
                    0,
                    "active",
                    MODULE.issue_prompt("https://github.com/a/active/issues/1"),
                    str(project_root),
                    None,
                    now,
                    str(active_rollout),
                ),
                (
                    "thread-failed",
                    0,
                    "failed",
                    MODULE.issue_prompt("https://github.com/a/failed/issues/2"),
                    str(project_root),
                    None,
                    now,
                    str(failed_rollout),
                ),
            ],
        )

    class Store:
        def recovery_candidates(self, **_kwargs):
            return [
                {
                    "key": "a/failed#2",
                    "issueUrl": "https://github.com/a/failed/issues/2",
                    "threadId": "thread-failed",
                    "worktreePath": str(failed_worktree),
                }
            ]

        def task_context_candidates(self):
            return [
                {
                    "key": "a/active#1",
                    "issueUrl": "https://github.com/a/active/issues/1",
                    "threadId": "thread-active",
                    "worktreePath": str(active_worktree),
                }
            ]

        def unresolved_recoveries(self):
            return []

    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    result = MODULE.recovery_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )

    assert result["recoverable"] == []
    assert [item["threadId"] for item in result["activeDeferred"]] == ["thread-active"]
    assert [item["threadId"] for item in result["queuedDeferred"]] == ["thread-failed"]


def test_latest_terminal_error_ignores_a_failure_before_a_new_turn(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "task_complete",
                            "error": {"codex_error_info": "internal_error"},
                        },
                    }
                ),
                json.dumps({"type": "turn_context", "payload": {"turn_id": "turn-2"}}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert MODULE.latest_terminal_thread_error(str(rollout)) is None


def test_thread_turn_materialization_is_bounded_by_reservation_time(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    reserved_at = datetime.now(UTC)
    rollout.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": iso_z(reserved_at - timedelta(minutes=1)),
                        "type": "turn_context",
                        "payload": {"turn_id": "turn-old"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": iso_z(reserved_at + timedelta(seconds=1)),
                        "type": "turn_context",
                        "payload": {"turn_id": "turn-new"},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert MODULE.thread_turn_materialized_after(str(rollout), iso_z(reserved_at)) == (True, True)
    assert MODULE.thread_turn_materialized_after(
        str(tmp_path / "missing.jsonl"), iso_z(reserved_at)
    ) == (False, False)


def test_app_server_terminal_turn_accepts_completion_notification():
    result = MODULE._app_server_terminal_turn(
        {
            "method": "turn/completed",
            "params": {
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "status": "failed", "error": {"message": "x"}},
            },
        },
        thread_id="thread-1",
        turn_id="turn-1",
    )

    assert result == {
        "turnId": "turn-1",
        "status": "failed",
        "error": {"message": "x"},
    }


def test_app_server_terminal_turn_accepts_thread_read_watchdog_response():
    result = MODULE._app_server_terminal_turn(
        {
            "id": 7,
            "result": {
                "thread": {
                    "id": "thread-1",
                    "turns": [
                        {"id": "turn-old", "status": "completed"},
                        {"id": "turn-1", "status": "interrupted"},
                    ],
                }
            },
        },
        thread_id="thread-1",
        turn_id="turn-1",
        read_request_id=7,
    )

    assert result == {"turnId": "turn-1", "status": "interrupted", "error": None}


def test_app_server_terminal_turn_ignores_in_progress_or_unrelated_turns():
    assert (
        MODULE._app_server_terminal_turn(
            {
                "id": 7,
                "result": {
                    "thread": {
                        "id": "thread-1",
                        "turns": [{"id": "turn-1", "status": "inProgress"}],
                    }
                },
            },
            thread_id="thread-1",
            turn_id="turn-1",
            read_request_id=7,
        )
        is None
    )
    assert (
        MODULE._app_server_terminal_turn(
            {
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-2",
                    "turn": {"id": "turn-1", "status": "completed"},
                },
            },
            thread_id="thread-1",
            turn_id="turn-1",
        )
        is None
    )


def test_app_server_watchdog_consumes_buffered_terminal_before_select():
    class FakeStdin:
        @staticmethod
        def write(_value: bytes) -> None:
            raise AssertionError("a terminal turn must not trigger another request")

        @staticmethod
        def flush() -> None:
            return None

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 123

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = FakeStdout()

        @staticmethod
        def poll():
            return None

    class NeverSelect:
        @staticmethod
        def select(_timeout):
            raise AssertionError("a buffered terminal event must be consumed immediately")

    buffered = (
        b'{"method":"turn/completed","params":{"threadId":"thread-1",'
        b'"turn":{"id":"turn-1","status":"interrupted"}}}\n'
    )

    result = MODULE._wait_for_app_server_terminal_turn(
        FakeProcess(),
        NeverSelect(),
        buffered,
        thread_id="thread-1",
        turn_id="turn-1",
    )

    assert result == {"turnId": "turn-1", "status": "interrupted", "error": None}


def test_validation_progress_marker_tracks_check_outcomes_not_wording():
    first = MODULE._validation_progress_marker(
        {
            "tests": [
                {"command": "pnpm  test", "exitCode": 1, "summary": "first wording"},
                {"command": "pnpm lint", "exitCode": 0},
            ]
        }
    )
    rewritten = MODULE._validation_progress_marker(
        {
            "tests": [
                {"command": "pnpm lint", "exitCode": 0},
                {"command": "pnpm test", "exitCode": 1, "summary": "new wording"},
            ]
        }
    )
    fixed = MODULE._validation_progress_marker(
        {
            "tests": [
                {"command": "pnpm test", "exitCode": 0},
                {"command": "pnpm lint", "exitCode": 0},
            ]
        }
    )

    assert first == rewritten
    assert fixed != first


def test_app_server_watchdog_polls_on_wall_clock_despite_continuous_events(monkeypatch):
    class FakeStdin:
        def __init__(self):
            self.writes: list[bytes] = []

        def write(self, value: bytes) -> None:
            self.writes.append(value)

        def flush(self) -> None:
            return None

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 123

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = FakeStdout()

        @staticmethod
        def poll():
            return None

    class AlwaysReadySelector:
        @staticmethod
        def select(_timeout):
            return [(object(), None)]

    times = iter([0.0, 1.0, 1.0, 5.0, 5.0])
    chunks = iter(
        [
            b'{"method":"turn/started","params":{}}\n',
            (
                b'{"id":3,"result":{"thread":{"id":"thread-1","turns":'
                b'[{"id":"turn-1","status":"interrupted"}]}}}\n'
            ),
        ]
    )
    monkeypatch.setattr(MODULE, "monotonic", lambda: next(times, 5.0))
    monkeypatch.setattr(MODULE.os, "read", lambda _fd, _size: next(chunks))
    process = FakeProcess()

    result = MODULE._wait_for_app_server_terminal_turn(
        process,
        AlwaysReadySelector(),
        b"",
        thread_id="thread-1",
        turn_id="turn-1",
    )

    assert result == {"turnId": "turn-1", "status": "interrupted", "error": None}
    assert json.loads(process.stdin.writes[0]) == {
        "id": 3,
        "method": "thread/read",
        "params": {"threadId": "thread-1", "includeTurns": True},
    }


def test_app_server_watchdog_uses_persisted_terminal_probe_when_read_stalls(monkeypatch):
    class FakeStdin:
        def __init__(self):
            self.writes: list[bytes] = []

        def write(self, value: bytes) -> None:
            self.writes.append(value)

        def flush(self) -> None:
            return None

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 123

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = FakeStdout()

        @staticmethod
        def poll():
            return None

    class NeverReadySelector:
        @staticmethod
        def select(_timeout):
            return []

    class StepClock:
        def __init__(self):
            self.value = -1.0

        def __call__(self):
            self.value += 1.0
            return self.value

    monkeypatch.setattr(MODULE, "monotonic", StepClock())
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_STALE_SECONDS", 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_EXTERNAL_PROBE_SECONDS", 2.0)
    monkeypatch.setattr(
        MODULE,
        "persisted_thread_turn_state",
        lambda thread_id: (
            {
                "turnId": "turn-1",
                "status": "interrupted",
                "code": "turn_interrupted",
                "message": "interrupted",
            }
            if thread_id == "thread-1"
            else None
        ),
    )
    process = FakeProcess()

    result = MODULE._wait_for_app_server_terminal_turn(
        process,
        NeverReadySelector(),
        b"",
        thread_id="thread-1",
        turn_id="turn-1",
    )

    assert result == {"turnId": "turn-1", "status": "interrupted", "error": None}
    assert json.loads(process.stdin.writes[0])["method"] == "thread/read"


def test_app_server_watchdog_times_out_without_opening_second_app_server(monkeypatch):
    class FakeStdin:
        def __init__(self):
            self.writes: list[bytes] = []

        def write(self, value: bytes) -> None:
            self.writes.append(value)

        def flush(self) -> None:
            return None

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 123

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = FakeStdout()

        @staticmethod
        def poll():
            return None

    class NeverReadySelector:
        @staticmethod
        def select(_timeout):
            return []

    class StepClock:
        def __init__(self):
            self.value = -1.0

        def __call__(self):
            self.value += 1.0
            return self.value

    monkeypatch.setattr(MODULE, "monotonic", StepClock())
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_STALE_SECONDS", 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_EXTERNAL_PROBE_SECONDS", 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_TASK_TURN_MAX_SECONDS", 2.0)
    monkeypatch.setattr(MODULE, "persisted_thread_turn_state", lambda _thread_id: None)
    monkeypatch.setattr(
        MODULE,
        "live_thread_turn_states",
        lambda _thread_ids: (_ for _ in ()).throw(
            AssertionError("active task watchdog must not open a second app-server")
        ),
    )
    process = FakeProcess()

    result = MODULE._wait_for_app_server_terminal_turn(
        process,
        NeverReadySelector(),
        b"",
        thread_id="thread-1",
        turn_id="turn-1",
    )

    assert result == {
        "turnId": "turn-1",
        "status": "interrupted",
        "error": {"message": "task-turn worker exceeded its maximum runtime"},
    }


def test_app_server_watchdog_reconciles_persisted_terminal_view(monkeypatch):
    class FakeStdin:
        def __init__(self):
            self.writes: list[bytes] = []

        def write(self, value: bytes) -> None:
            self.writes.append(value)

        def flush(self) -> None:
            return None

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 123

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = FakeStdout()

        @staticmethod
        def poll():
            return None

    class AlwaysReadySelector:
        @staticmethod
        def select(_timeout):
            return [(object(), None)]

    monkeypatch.setattr(MODULE, "monotonic", lambda: 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_STALE_SECONDS", 15.0)
    monkeypatch.setattr(MODULE, "APP_SERVER_WATCHDOG_EXTERNAL_PROBE_SECONDS", 0.0)
    monkeypatch.setattr(
        MODULE,
        "persisted_thread_turn_state",
        lambda _thread_id: {
            "turnId": "turn-1",
            "status": "interrupted",
            "code": "turn_interrupted",
            "message": "interrupted",
        },
    )
    process = FakeProcess()

    result = MODULE._wait_for_app_server_terminal_turn(
        process,
        AlwaysReadySelector(),
        b"",
        thread_id="thread-1",
        turn_id="turn-1",
    )

    assert result == {"turnId": "turn-1", "status": "interrupted", "error": None}
    assert process.stdin.writes == []


def test_active_root_task_worker_owns_the_first_turn(monkeypatch, tmp_path):
    receipt_root = tmp_path / "root_task_receipts"
    receipt_root.mkdir()
    creation_token = "root-token"
    (receipt_root / f"{creation_token}.launch.json").write_text(
        json.dumps({"pid": 123, "startedAt": "2026-08-13T17:00:00Z"}),
        encoding="utf-8",
    )
    (receipt_root / f"{creation_token}.json").write_text(
        json.dumps({"ok": True, "threadId": "thread-1"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "STATE", tmp_path)
    monkeypatch.setattr(MODULE, "_pid_is_alive", lambda _pid: True)
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout=(
                "python scripts/local_dispatch_bridge.py root-task-worker "
                f"--creation-token {creation_token}"
            )
        ),
    )

    assert MODULE.active_root_task_worker("thread-1") == {
        "pid": 123,
        "deliveryKind": "root-task",
        "startedAt": "2026-08-13T17:00:00Z",
    }
    assert MODULE.active_root_task_worker("thread-2") is None


def test_task_turn_delivery_reconciles_a_materialized_turn_without_resending(monkeypatch, tmp_path):
    issue_url = "https://github.com/a/b/issues/1"
    reserved_at = datetime.now(UTC) - timedelta(minutes=5)
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "intent" / "b"
    worktree.mkdir(parents=True)
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "timestamp": iso_z(reserved_at + timedelta(seconds=1)),
                "type": "event_msg",
                "payload": {
                    "type": "user_message",
                    "message": MODULE._pr_followup_prompt({"issueUrl": issue_url}),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER, "
            "first_user_message TEXT, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?)",
            ("thread-1", str(project_root), 0, MODULE.issue_prompt(issue_url), str(rollout)),
        )

    class Store:
        committed = None

        def unresolved_pr_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "issue_url": issue_url,
                    "worktree_path": str(worktree),
                    "thread_id": "thread-1",
                    "pr_url": "https://github.com/a/b/pull/2",
                    "wake_digest": "a" * 64,
                    "created_at": iso_z(reserved_at),
                }
            ]

        def commit_pr_followup(self, **kwargs):
            self.committed = kwargs

    store = Store()
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    bind_validation_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    rollout.write_text(
        json.dumps(
            {
                "timestamp": iso_z(reserved_at + timedelta(seconds=1)),
                "type": "event_msg",
                "payload": {
                    "type": "user_message",
                    "message": MODULE._pr_followup_prompt({"issueUrl": issue_url}),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("a materialized turn must not be resent"),
    )

    result = MODULE.task_turn_deliver(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            delivery_kind="pr-followup",
            delivery_token="a" * 64,
            thread_id="thread-1",
        )
    )

    assert result["reconciled"] is True
    assert store.committed == {"thread_id": "thread-1", "wake_digest": "a" * 64}


def test_task_turn_delivery_never_restarts_a_live_worker(monkeypatch, tmp_path):
    issue_url = "https://github.com/a/b/issues/1"
    reserved_at = datetime.now(UTC) - timedelta(minutes=5)
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "intent" / "b"
    worktree.mkdir(parents=True)
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text("", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER, "
            "first_user_message TEXT, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?)",
            ("thread-1", str(project_root), 0, MODULE.issue_prompt(issue_url), str(rollout)),
        )

    class Store:
        def unresolved_pr_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "issue_url": issue_url,
                    "worktree_path": str(worktree),
                    "thread_id": "thread-1",
                    "pr_url": "https://github.com/a/b/pull/2",
                    "wake_digest": "a" * 64,
                    "created_at": iso_z(reserved_at),
                }
            ]

    state = tmp_path / "state"
    receipt_key = MODULE.sha256_json(
        {
            "deliveryKind": "pr-followup",
            "threadId": "thread-1",
            "deliveryToken": "a" * 64,
        }
    )
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    (receipt_root / f"{receipt_key}.launch.json").write_text(
        json.dumps({"pid": os.getpid()}), encoding="utf-8"
    )
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("a live delivery worker must not be duplicated"),
    )

    result = MODULE.task_turn_deliver(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            delivery_kind="pr-followup",
            delivery_token="a" * 64,
            thread_id="thread-1",
        )
    )

    assert result["pending"] is True
    assert result["workerPid"] == os.getpid()


def test_task_turn_delivery_rechecks_quarantine_before_starting_worker(monkeypatch, tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
    )
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text("", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER, "
            "first_user_message TEXT, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?)",
            (
                candidate["threadId"],
                str(worktree),
                0,
                MODULE.issue_prompt(candidate["issueUrl"]),
                str(rollout),
            ),
        )

    activation_started = threading.Event()
    activation_finished = threading.Event()
    activation_errors = []

    def activate_quarantine():
        activation_started.set()
        try:
            store.record_shared_context_quarantine(
                key=candidate["key"],
                reason="SHARED_CONTEXT_INVALID",
                dedupe_key="race-quarantine",
                payload={"source": "delivery-race"},
                created_at=iso_z(datetime.now(UTC)),
            )
        except BaseException as exc:
            activation_errors.append(exc)
        finally:
            activation_finished.set()

    with MODULE.opportunity_action_guard(
        MODULE.ledger_action_guard_root(store.path), candidate["key"]
    ):
        activation = threading.Thread(target=activate_quarantine)
        activation.start()
        assert activation_started.wait(2)
        assert not activation_finished.is_set()

    activation.join(timeout=2)
    assert not activation.is_alive()
    assert activation_errors == []
    assert activation_finished.is_set()

    popen_calls = []
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    bind_validation_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("a quarantined task must not start a worker"),
    )

    with pytest.raises(PermissionError, match="blocked by active quarantine"):
        MODULE.task_turn_deliver(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                delivery_kind="pr-followup",
                delivery_token=candidate["wakeDigest"],
                thread_id=candidate["threadId"],
            )
        )

    assert popen_calls == []
    assert store.active_task_quarantine(candidate["key"]) is not None

    store.clear_task_quarantine(
        candidate["key"],
        reason="SHARED_CONTEXT_INVALID",
        evidence={"revalidated": True},
    )
    authorized = store.authorize_task_turn_delivery(
        delivery_kind="pr-followup",
        thread_id=candidate["threadId"],
        delivery_token=candidate["wakeDigest"],
    )
    assert authorized["deliveryToken"] == candidate["wakeDigest"]


def test_task_spawn_is_blocked_when_quarantine_wins_the_guard(monkeypatch, tmp_path):
    store, _worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    key = candidate["key"]
    store.reserve_pr_followup(
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
    )
    release = threading.Event()
    ready = threading.Event()
    activation_errors = []
    spawn_errors = []
    popen_calls = []

    def activate():
        try:
            with MODULE.opportunity_action_guard(MODULE.ledger_action_guard_root(store.path), key):
                store._record_shared_context_quarantine(
                    key=key,
                    reason="SHARED_CONTEXT_INVALID",
                    dedupe_key="activation-first",
                    payload={"source": "race"},
                    created_at=iso_z(datetime.now(UTC)),
                )
                ready.set()
                assert release.wait(2)
        except BaseException as exc:
            activation_errors.append(exc)

    def spawn():
        try:
            MODULE._guarded_task_popen(
                store,
                opportunity_key=key,
                argv=[sys.executable, "-c", "pass"],
                cwd=tmp_path,
            )
        except BaseException as exc:
            spawn_errors.append(exc)

    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *args, **kwargs: popen_calls.append((args, kwargs)),
    )
    activation = threading.Thread(target=activate)
    activation.start()
    assert ready.wait(2)
    worker = threading.Thread(target=spawn)
    worker.start()
    time.sleep(0.05)
    assert popen_calls == []
    release.set()
    activation.join(timeout=2)
    worker.join(timeout=2)
    assert activation_errors == []
    assert isinstance(spawn_errors[0], PermissionError)
    assert popen_calls == []
    assert store.active_task_quarantine(key) is not None


def test_app_server_action_guard_holds_through_turn_start_before_quarantine(monkeypatch, tmp_path):
    store, _worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    key = candidate["key"]
    store.reserve_pr_followup(
        thread_id=candidate["threadId"],
        wake_digest=candidate["wakeDigest"],
    )

    class FakeStdin:
        def __init__(self):
            self.writes = []
            self.flushes = 0

        def write(self, value):
            self.writes.append(value)

        def flush(self):
            self.flushes += 1

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()

    process = FakeProcess()
    monkeypatch.setattr(MODULE.subprocess, "Popen", lambda *_args, **_kwargs: process)
    quarantine_started = threading.Event()
    quarantine_finished = threading.Event()
    quarantine_errors = []

    def activate_quarantine():
        quarantine_started.set()
        try:
            store.record_shared_context_quarantine(
                key=key,
                reason="SHARED_CONTEXT_INVALID",
                dedupe_key="app-server-action-first",
                payload={"source": "app-server-race"},
                created_at=iso_z(datetime.now(UTC)),
            )
        except BaseException as exc:
            quarantine_errors.append(exc)
        finally:
            quarantine_finished.set()

    activation = threading.Thread(target=activate_quarantine)
    with MODULE._app_server_action_session(
        store,
        opportunity_key=key,
        argv=["codex", "app-server", "--stdio"],
        cwd=tmp_path,
    ) as started_process:
        assert started_process is process
        activation.start()
        assert quarantine_started.wait(2)
        assert not quarantine_finished.is_set()
        process.stdin.write(b"initialize\nthread/resume\n")
        process.stdin.flush()
        MODULE._task_turn_start_unlocked(
            store,
            opportunity_key=key,
            process=process,
            thread_id=candidate["threadId"],
            cwd=tmp_path,
            prompt="continue",
            delivery_kind="pr-followup",
            delivery_token=candidate["wakeDigest"],
        )
        assert process.stdin.flushes == 2
        assert b"turn/start" in process.stdin.writes[-1]
        assert not quarantine_finished.is_set()

    activation.join(timeout=2)
    assert not activation.is_alive()
    assert quarantine_errors == []
    assert quarantine_finished.is_set()
    assert store.active_task_quarantine(key) is not None


def test_task_turn_preflight_failure_writes_a_negative_receipt(monkeypatch, tmp_path):
    issue_url = "https://github.com/a/b/issues/1"
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "intent" / "b"
    worktree.mkdir(parents=True)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER, "
            "first_user_message TEXT, rollout_path TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?)",
            ("thread-1", str(project_root), 1, MODULE.issue_prompt(issue_url), None),
        )

    reservation_digest = "b" * 64

    class Store:
        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": issue_url,
                    "worktreePath": str(worktree),
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "reservationDigest": reservation_digest,
                    "missing": ["relevant_tests_green"],
                    "reservedAt": iso_z(datetime.now(UTC) - timedelta(minutes=2)),
                }
            ]

    state = tmp_path / "state"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    with pytest.raises(RuntimeError, match="target is missing or archived"):
        MODULE.task_turn_deliver(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                delivery_kind="validation-followup",
                delivery_token="a" * 64,
                thread_id="thread-1",
            )
        )

    receipt_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="a" * 64,
        validation_reservation_digest=reservation_digest,
    )
    receipt = json.loads(
        (state / "task_turn_receipts" / f"{receipt_key}.json").read_text(encoding="utf-8")
    )
    assert receipt == {
        "ok": False,
        "turnStarted": False,
        "turnId": None,
        "error": "RuntimeError:task-turn delivery target is missing or archived",
        "reservationDigest": reservation_digest,
    }


def test_task_turn_worker_setup_failure_writes_a_negative_receipt(monkeypatch, tmp_path):
    receipt = tmp_path / "receipt.json"
    monkeypatch.setattr(
        MODULE,
        "_app_server_task_turn_worker",
        lambda _args: (_ for _ in ()).throw(RuntimeError("setup failed")),
    )

    with pytest.raises(RuntimeError, match="setup failed"):
        MODULE.task_turn_worker_entry(SimpleNamespace(receipt=str(receipt)))

    value = json.loads(receipt.read_text(encoding="utf-8"))
    assert value == {
        "ok": False,
        "turnStarted": False,
        "turnId": None,
        "error": "RuntimeError:setup failed",
    }


def test_app_server_active_writer_error_is_machine_classified():
    error = MODULE._app_server_task_error(
        {
            "error": {
                "message": "thread thread-1 already has an active writer",
            }
        },
        action="resume",
    )

    assert str(error).startswith("DESKTOP_ACTIVE_WRITER:")


def test_exact_prompt_reconciliation_ignores_unrelated_user_turn(tmp_path):
    reserved_at = datetime.now(UTC) - timedelta(minutes=5)
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "timestamp": iso_z(reserved_at + timedelta(seconds=1)),
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "看不懂，什么意思"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    available, materialized = MODULE.thread_prompt_materialized_after(
        str(rollout), iso_z(reserved_at), "系统续跑：继续验证同一个修复。"
    )

    assert available is True
    assert materialized is False


def test_negative_task_turn_receipt_is_retryable_after_worker_exit(monkeypatch, tmp_path):
    state = tmp_path / "state"
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    delivery_token = "a" * 64
    reservation_digest = "b" * 64
    receipt_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token=delivery_token,
        validation_reservation_digest=reservation_digest,
    )
    (receipt_root / f"{receipt_key}.json").write_text(
        json.dumps(
            {
                "ok": False,
                "turnStarted": False,
                "turnId": None,
                "error": "RuntimeError:app server could not resume the task",
                "reservationDigest": reservation_digest,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "STATE", state)

    result = MODULE.retryable_negative_task_turn_receipt(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token=delivery_token,
        validation_reservation_digest=reservation_digest,
    )

    assert result == {
        "retryable": True,
        "retryReason": "NEGATIVE_RECEIPT_NO_TURN_STARTED",
        "deliveryError": "RuntimeError:app server could not resume the task",
    }


def test_recovery_reserve_rephrases_a_benign_policy_false_positive(monkeypatch, tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "task_complete",
                    "error": {"codex_error_info": "cyber_policy"},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, rollout_path TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?)", ("thread-1", str(rollout)))

    class Store:
        def reserve_recovery(self, **_kwargs):
            return {
                "threadId": "thread-1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "recoveryNonce": "nonce",
            }

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE,
        "recovery_list",
        lambda _args: {
            "ok": True,
            "recoverable": [{"threadId": "thread-1", "recoveryNonce": "nonce"}],
        },
    )

    result = MODULE.recovery_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            recovery_nonce="nonce",
        )
    )

    assert result["prompt"] == MODULE.BENIGN_POLICY_RECOVERY_PROMPT
    assert result["terminalError"]["code"] == "cyber_policy"


def test_cleanup_commit_removes_managed_bootstrap_context(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    worktree.mkdir(parents=True)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    bootstrap = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text("{}\n", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER)")
        connection.execute("INSERT INTO threads VALUES (?,?)", ("thread-1", 1))

    class Store:
        committed = False

        def cleanup_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": str(worktree),
                    "cleanupNonce": "nonce",
                }
            ]

        def commit_cleanup(self, **_kwargs):
            self.committed = True

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    MODULE.cleanup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            cleanup_nonce="nonce",
        )
    )

    assert store.committed is True
    assert not bootstrap.exists()


def test_cleanup_list_reconciles_already_archived_no_go_before_title_sync(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    worktree = project_root / ".oss-pr-radar" / "worktrees" / "task" / "b"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    store, _ = registered_store(tmp_path / "store", worktree=worktree)
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    bootstrap_path = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    assert context_path.exists()
    assert bootstrap_path.exists()
    store.record_stage("a/b#1", "AUDIT_NO_GO", reason="STRONG_EXISTING_PR")
    assert store.title_candidates()[0]["titleState"] == "AUDIT_NO_GO"
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)", ("thread-1", 1, "old useful title")
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    result = MODULE.cleanup_list(SimpleNamespace(ledger=store.path))

    assert result == {"ok": True, "cleanup": []}
    assert store.cleanup_candidates() == []
    assert store.cleanup_reconciliation_candidates() == []
    assert not bootstrap_path.exists()


def test_cleanup_reconcile_archives_reconciled_no_go_task(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "AUDIT_NO_GO", evidence={})
    title = store.title_candidates()[0]
    desired_title = MODULE.lifecycle_title(
        title["titleState"], title["titleTime"], title["key"], title["title"]
    )
    store.commit_title(
        thread_id="thread-1",
        state=title["titleState"],
        nonce=title["titleNonce"],
    )
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", 0, desired_title))
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    def archive(candidates):
        with sqlite3.connect(thread_db) as connection:
            for candidate in candidates:
                connection.execute(
                    "UPDATE threads SET archived=1 WHERE id=?", (candidate["threadId"],)
                )
        return {str(candidate["threadId"]): None for candidate in candidates}

    monkeypatch.setattr(MODULE, "_archive_desktop_threads", archive)

    result = MODULE.cleanup_reconcile(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {
        "ok": True,
        "archived": [{"key": "a/b#1", "ok": True, "threadId": "thread-1"}],
        "errors": [],
    }
    assert store.cleanup_candidates() == []


def test_restore_list_and_commit_require_actual_unarchive(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", 1, "[无价值] task"))

    class Store:
        committed = False

        def restore_candidates(self):
            if self.committed:
                return []
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": "/tmp/worktree",
                    "restoreNonce": "nonce",
                }
            ]

        def commit_restore(self, **_kwargs):
            self.committed = True

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    pending = MODULE.restore_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert pending["restore"][0]["threadId"] == "thread-1"
    assert store.committed is False

    with sqlite3.connect(thread_db) as connection:
        connection.execute("UPDATE threads SET archived=0 WHERE id='thread-1'")
    result = MODULE.restore_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            restore_nonce="nonce",
        )
    )

    assert result["ok"] is True
    assert store.committed is True


def test_restore_list_reconciles_already_unarchived_task(monkeypatch, tmp_path):
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute("INSERT INTO threads VALUES (?,?,?)", ("thread-1", 0, "task"))

    class Store:
        committed = False

        def restore_candidates(self):
            if self.committed:
                return []
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "restoreNonce": "nonce",
                }
            ]

        def commit_restore(self, **_kwargs):
            self.committed = True

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    result = MODULE.restore_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["restore"] == []
    assert result["reconciled"][0]["threadId"] == "thread-1"
    assert store.committed is True


def test_restore_list_does_not_bulk_restore_desktop_archive_drift(monkeypatch, tmp_path):
    registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", 1, "[有价值] task"),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    result = MODULE.restore_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {"ok": True, "restore": [], "reconciled": [], "blocked": []}


def test_restore_reconcile_repairs_targeted_desktop_archive_drift(monkeypatch, tmp_path):
    store, _worktree = registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", 1, "[有价值] task"),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    def unarchive(candidates):
        with sqlite3.connect(thread_db) as connection:
            for candidate in candidates:
                connection.execute(
                    "UPDATE threads SET archived=0 WHERE id=?",
                    (candidate["threadId"],),
                )
        return {str(candidate["threadId"]): None for candidate in candidates}

    monkeypatch.setattr(MODULE, "_unarchive_desktop_threads", unarchive)

    result = MODULE.restore_reconcile(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", thread_id="thread-1")
    )

    assert result["ok"] is True
    assert result["restored"][0]["threadId"] == "thread-1"
    assert result["restored"][0]["key"] == "a/b#1"
    with sqlite3.connect(thread_db) as connection:
        assert (
            connection.execute("SELECT archived FROM threads WHERE id='thread-1'").fetchone()[0]
            == 0
        )
    with store.connect() as connection:
        restored = connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='THREAD_RESTORED'"
        ).fetchone()[0]
    assert restored == 1


def test_restore_reconcile_trusts_verified_postcondition_over_transport_error(
    monkeypatch, tmp_path
):
    store, _worktree = registered_store(tmp_path)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, archived INTEGER, title TEXT)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", 1, "[有价值] task"),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    def partially_successful_unarchive(candidates):
        with sqlite3.connect(thread_db) as connection:
            connection.execute(
                "UPDATE threads SET archived=0 WHERE id=?",
                (candidates[0]["threadId"],),
            )
        return {"thread-1": "app_server_unarchive_failed"}

    monkeypatch.setattr(MODULE, "_unarchive_desktop_threads", partially_successful_unarchive)

    result = MODULE.restore_reconcile(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", thread_id="thread-1")
    )

    assert result["ok"] is True
    assert result["errors"] == []
    assert result["restored"][0]["threadId"] == "thread-1"
    with store.connect() as connection:
        restored = connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='THREAD_RESTORED'"
        ).fetchone()[0]
    assert restored == 1


def test_controller_ingests_workspace_no_go_without_child_ledger_access(tmp_path):
    store, worktree = registered_store(tmp_path)
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "STRONG_EXISTING_PR",
                "evidence": {"existingPr": "https://github.com/a/b/pull/2"},
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True, result["errors"]
    assert result["ingested"] == [
        {"key": "a/b#1", "stage": "AUDIT_NO_GO", "reason": "STRONG_EXISTING_PR"}
    ]
    task = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert task is not None
    assert task["stage"] == "AUDIT_NO_GO"
    assert task["autoSubmitAuthorized"] is False


def test_ingestion_ignores_stale_result_after_published_context_moves_on(tmp_path):
    store, worktree = registered_store(tmp_path)
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    old_context = json.loads(context_path.read_text(encoding="utf-8"))
    result_path = Path(old_context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": old_context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "evidence": {"reviewed": True},
            }
        ),
        encoding="utf-8",
    )
    store.record_stage(
        "a/b#1",
        "CI_GREEN",
        evidence={"prUrl": "https://github.com/a/b/pull/2"},
    )
    current_context = dict(old_context)
    current_context["contextDigest"] = "current-published-context"
    context_path.write_text(json.dumps(current_context), encoding="utf-8")
    assert current_context.get("prFollowup") is None

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == []
    assert result["ignored"] == [{"key": "a/b#1", "reason": "STALE_PUBLISHED_TASK_RESULT"}]
    assert result["errors"] == []


def test_ingestion_still_rejects_context_mismatch_for_active_task(tmp_path):
    store, worktree = registered_store(tmp_path)
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    Path(context["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": "wrong-context",
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "STRONG_EXISTING_PR",
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is False
    assert result.get("ignored", []) == []
    assert result["errors"] == [{"key": "a/b#1", "error": "task result context digest mismatch"}]


def test_ingestion_rejects_legacy_result_for_non_null_target_base(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    store, worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    context = json.loads(local_path.read_text(encoding="utf-8"))
    context["targetBase"] = {
        "branch": "main",
        "sha": run_git(worktree, "rev-parse", "HEAD"),
        "source": "repository_default",
        "defaultBranch": "main",
    }
    context["contextDigest"] = MODULE._task_context_digest(context, None)
    _rewrite_context_mirrors(local_path, shared_path, context)
    result_path = Path(context["resultPath"])
    legacy_digest = sha256_json(
        MODULE._task_context_digest_payload(
            context,
            None,
            include_target_base=False,
        )
    )
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": legacy_digest,
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )
    original_result_bytes = result_path.read_bytes()

    ledger_path = tmp_path / "fixture" / "ledger.sqlite3"
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=ledger_path))

    assert first["ok"] is False
    assert first["ingested"] == []
    assert first.get("legacyContextDigestMigrations", []) == []
    assert first["errors"] == [{"key": "a/b#1", "error": "task result context digest mismatch"}]
    assert result_path.read_bytes() == original_result_bytes
    assert json.loads(result_path.read_text(encoding="utf-8"))["contextDigest"] == legacy_digest


def test_ingestion_migrates_exact_legacy_result_for_explicit_null_target_base(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    store, worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    context = json.loads(local_path.read_text(encoding="utf-8"))
    context["targetBase"] = None
    context["contextDigest"] = MODULE._task_context_digest(context, None)
    _rewrite_context_mirrors(local_path, shared_path, context)
    result_path = Path(context["resultPath"])
    legacy_digest = sha256_json(
        MODULE._task_context_digest_payload(
            context,
            None,
            include_target_base=False,
        )
    )
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": legacy_digest,
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(
        SimpleNamespace(ledger=tmp_path / "fixture" / "ledger.sqlite3")
    )

    assert result["ok"] is True, result["errors"]
    assert result["legacyContextDigestMigrations"] == ["a/b#1"]


def test_legacy_result_migration_accepts_missing_target_base_field(monkeypatch, tmp_path):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    store, worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    context = json.loads(local_path.read_text(encoding="utf-8"))
    context.pop("targetBase")
    context["contextDigest"] = sha256_json(
        MODULE._task_context_digest_payload(
            context,
            None,
            include_target_base=False,
        )
    )
    _rewrite_context_mirrors(local_path, shared_path, context)
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(
        SimpleNamespace(ledger=tmp_path / "fixture" / "ledger.sqlite3")
    )

    assert result["ok"] is True, result["errors"]
    assert result["errors"] == []
    assert result.get("legacyContextDigestMigrations", []) == []


@pytest.mark.parametrize("mutation", ["target", "result", "identity"])
def test_legacy_result_digest_migration_rejects_tampering(monkeypatch, tmp_path, mutation):
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    store, worktree, local_path, shared_path = _context_digest_fixture(tmp_path / "fixture")
    context = json.loads(local_path.read_text(encoding="utf-8"))
    context["targetBase"] = {
        "branch": "main",
        "sha": run_git(worktree, "rev-parse", "HEAD"),
        "source": "repository_default",
        "defaultBranch": "main",
    }
    context["contextDigest"] = MODULE._task_context_digest(context, None)
    _rewrite_context_mirrors(local_path, shared_path, context)
    result_path = Path(context["resultPath"])
    legacy_digest = sha256_json(
        MODULE._task_context_digest_payload(
            context,
            None,
            include_target_base=False,
        )
    )
    if mutation == "target":
        context["targetBase"] = {**context["targetBase"], "sha": "b" * 40}
        _rewrite_context_mirrors(local_path, shared_path, context)
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": legacy_digest if mutation == "target" else "f" * 64,
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "other-thread" if mutation == "identity" else "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(
        SimpleNamespace(ledger=tmp_path / "fixture" / "ledger.sqlite3")
    )

    assert result["ok"] is False
    expected_error = (
        "task result mismatch: threadId"
        if mutation == "identity"
        else "task result context digest mismatch"
    )
    assert result["errors"] == [{"key": "a/b#1", "error": expected_error}]


def test_legacy_result_migration_does_not_change_signed_result_digest(tmp_path):
    _store, _worktree, result_path = _controller_commit_result(tmp_path)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    raw = result_path.read_bytes()
    assert isinstance(value.get("reproductionReceipt"), dict)
    expected = value["resultDigest"]

    migrated = dict(value, contextDigest="target-bound-context")

    assert MODULE._task_result_digest(migrated, raw) == expected


def _published_followup_store(
    tmp_path: Path,
) -> tuple[RadarLedger, Path, str, str]:
    MODULE.ROOT = tmp_path
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(worktree, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(
        worktree,
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    )
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    pr_url = "https://github.com/a/b/pull/9"
    now = iso_z(datetime.now(UTC))
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO publication_requests
               (request_id,opportunity_key,thread_id,commit_sha,branch,worktree_path,
                evidence_digest,status,request_json,created_at,updated_at)
               VALUES ('request-1','a/b#1','thread-1',?,'fix/1-runtime',?,
                       'evidence','CONSUMED','{}',?,?)""",
            (head_sha, str(worktree), now, now),
        )
        connection.execute(
            """INSERT INTO publication_permits
               (permit_id,request_id,issue_url,commit_sha,branch,status,expires_at,pr_url,
                evidence_json,created_at,updated_at)
               VALUES ('permit-1','request-1','https://github.com/a/b/issues/1',?,
                       'fix/1-runtime','CONSUMED',?,?, '{}',?,?)""",
            (head_sha, iso_z(datetime.now(UTC) + timedelta(hours=1)), pr_url, now, now),
        )
    store.record_stage("a/b#1", "PR_OPEN", evidence={"prUrl": pr_url})
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": now,
            "items": [
                {
                    "url": pr_url,
                    "headSha": head_sha,
                    "actionDigest": "action",
                    "taskActionDigest": "task-action",
                    "taskFollowupRequired": True,
                    "taskActions": ["当前分支检查失败"],
                    "evidence": {"actionableCheckNames": ["Ruff"]},
                    "checkedAt": now,
                }
            ],
        }
    )
    return store, worktree, head_sha, pr_url


def test_ingestion_accepts_current_ci_green_continuation_result(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    store.record_stage("a/b#1", "CI_GREEN", evidence={"checks": "green"})
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    Path(context["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "CI_GREEN",
                "followupDigest": context["prFollowup"]["wakeDigest"],
                "evidence": {"verified": True},
            }
        ),
        encoding="utf-8",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True, result["errors"]
    assert result["ingested"] == [{"key": "a/b#1", "stage": "CI_GREEN"}]


def test_ingestion_skips_published_terminal_missing_worktree_after_result_ingested(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    store.record_stage("a/b#1", "CI_GREEN", evidence={"checks": "green"})
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "CI_GREEN",
                "followupDigest": context["prFollowup"]["wakeDigest"],
                "evidence": {"verified": True},
            }
        ),
        encoding="utf-8",
    )
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert first["ok"] is True, first["errors"]
    assert first["ingested"] == [{"key": "a/b#1", "stage": "CI_GREEN"}]

    shutil.rmtree(worktree)

    second = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    third = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    for result in (second, third):
        assert result["ok"] is True, result.get("errors")
        assert result["errors"] == []
        assert result["ingested"] == []
        assert result["ignored"] == [
            {
                "key": "a/b#1",
                "reason": "PUBLISHED_TERMINAL_WORKTREE_MISSING",
            }
        ]


def test_ingestion_reports_published_missing_worktree_with_unfinished_validation_followup(
    tmp_path,
):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    store.record_task_result_ingested("a/b#1", digest="published-result", stage="CI_GREEN")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="validation-result",
        missing=["independent_review_passed"],
    )
    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"resultDigest": "validation-result"},
        dedupe_key="validation:unfinished",
    )
    store.reserve_validation_followup(thread_id="thread-1", result_digest="validation-result")
    store.record_stage(
        "a/b#1",
        "CI_GREEN",
        evidence={"prUrl": "https://github.com/a/b/pull/9"},
        dedupe_key="ci-green:unfinished-validation",
    )
    shutil.rmtree(worktree)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is False
    assert result["ingested"] == []
    assert result.get("ignored", []) == []
    assert result["errors"][0]["key"] == "a/b#1"
    assert "worktree is missing" in result["errors"][0]["error"]


def test_ingestion_reports_unpublished_missing_worktree(tmp_path):
    _store, worktree, _result_path = _controller_commit_result(tmp_path)
    shutil.rmtree(worktree)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is False
    assert result["ingested"] == []
    assert result["errors"][0]["key"] == "a/b#1"
    assert "worktree is missing" in result["errors"][0]["error"]


def test_ingestion_reports_unfinished_followup_missing_worktree(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    store.record_task_result_ingested("a/b#1", digest="result", stage="PR_OPEN")
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    shutil.rmtree(worktree)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is False
    assert result["ingested"] == []
    assert result["errors"][0]["key"] == "a/b#1"
    assert "worktree is missing" in result["errors"][0]["error"]


def test_pr_followup_reserve_refreshes_context_and_routes_to_shared_context(monkeypatch, tmp_path):
    store, worktree, _head_sha, pr_url = _published_followup_store(tmp_path)
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    candidate = store.pr_followup_candidates()[0]
    prepared = []

    def prepare(value):
        prepared.append(value)
        return {"preparedHeadSha": "b" * 40}

    monkeypatch.setattr(MODULE, "_prepare_pr_followup", prepare)

    result = MODULE.pr_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            wake_digest=candidate["wakeDigest"],
        )
    )

    assert prepared == [candidate]
    assert result["prUrl"] == pr_url
    assert result["prompt"].splitlines()[:2] == [
        "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)",
        "https://github.com/a/b/issues/1",
    ]
    assert str(MODULE.shared_context_path("https://github.com/a/b/issues/1")) in result["prompt"]
    assert "不要在当前入口目录等待 .oss-pr-radar/task-context.json" in result["prompt"]
    context = json.loads(Path(result["contextPath"]).read_text(encoding="utf-8"))
    assert context["prFollowup"]["wakeDigest"] == candidate["wakeDigest"]
    assert context["prFollowup"]["preparedHeadSha"] == "b" * 40
    assert context["publicationReceipt"]["prUrl"] == pr_url
    refreshed = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )
    assert refreshed["prFollowup"]["preparedHeadSha"] == "b" * 40
    assert refreshed["contextDigest"] == context["contextDigest"]
    assert store.pr_followup_candidates() == []


def test_pr_followup_reserve_rolls_back_unrecorded_preparation(monkeypatch, tmp_path):
    _store, worktree, original_head, _pr_url = _published_followup_store(tmp_path)
    candidate_store = RadarLedger(tmp_path / "ledger.sqlite3")
    candidate = candidate_store.pr_followup_candidates()[0]

    def prepare(_value):
        (worktree / "prepared.py").write_text("prepared = True\n", encoding="utf-8")
        run_git(worktree, "add", "prepared.py")
        run_git(worktree, "commit", "-m", "merge: prepare updated base")
        return {"preparedHeadSha": run_git(worktree, "rev-parse", "HEAD")}

    def fail_reservation(_self, **_kwargs):
        raise RuntimeError("simulated ledger failure")

    monkeypatch.setattr(MODULE, "_prepare_pr_followup", prepare)
    monkeypatch.setattr(RadarLedger, "reserve_pr_followup", fail_reservation)

    with pytest.raises(RuntimeError, match="simulated ledger failure"):
        MODULE.pr_followup_reserve(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id="thread-1",
                wake_digest=candidate["wakeDigest"],
            )
        )

    assert run_git(worktree, "rev-parse", "HEAD") == original_head
    assert run_git(worktree, "symbolic-ref", "--short", "HEAD") == "fix/1-runtime"
    assert run_git(worktree, "status", "--porcelain") == ""


def test_pr_followup_commit_cannot_self_attest_independent_review(monkeypatch, tmp_path):
    store, worktree, previous_head, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=previous_head,
    )
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
        prepared_followup_head=previous_head,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    body_path = worktree / ".oss-pr-radar" / "pr-body.md"
    body_path.write_text("Fixes #1\n\nCorrect the runtime boundary.\n", encoding="utf-8")
    quality = {field: True for field in QUALITY_FIELDS}
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "FIX_READY",
                "followupDigest": candidate["wakeDigest"],
                "handoffMode": "controller_commit_required",
                "commitSha": None,
                "branch": run_git(worktree, "symbolic-ref", "--short", "HEAD"),
                "commitMessage": "fix: address runtime review",
                "changedFiles": ["runtime.py"],
                "tests": [{"command": "pytest tests/runtime", "exitCode": 0}],
                "quality": quality,
                "publication": {
                    "headOwner": "Oxygen56",
                    "baseBranch": "main",
                    "title": "fix: address runtime review",
                    "bodyFile": str(body_path.resolve()),
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "controller_review_result", lambda _root, _value: None)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    finalized = json.loads(result_path.read_text(encoding="utf-8"))

    assert result["ok"] is False
    assert result["errors"] == [
        {
            "key": "a/b#1",
            "error": "REPRODUCTION_REQUIRED task violated its read-only contract",
        }
    ]
    assert result["publicationRequests"] == []
    assert result["validationDeferred"] == []
    assert finalized["quality"]["independent_review_passed"] is True
    assert "previousCommitSha" not in finalized
    assert run_git(worktree, "status", "--porcelain") == "M runtime.py"
    assert store.publication_work_items() == []

    reviewed = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert reviewed["publicationRequests"] == []
    assert reviewed["errors"] == result["errors"]


def test_pr_followup_reserve_defers_changed_snapshot_until_fresh_import(monkeypatch, tmp_path):
    store, _worktree, _head_sha, pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]

    def changed_snapshot(_candidate):
        raise MODULE.PrFollowupSnapshotChanged(
            "PR_BASE_CHANGED",
            expectedBaseSha="a" * 40,
            actualBaseSha="b" * 40,
        )

    monkeypatch.setattr(MODULE, "_prepare_pr_followup", changed_snapshot)

    result = MODULE.pr_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            wake_digest=candidate["wakeDigest"],
        )
    )

    assert result["ok"] is True
    assert result["deferred"] is True
    assert result["reason"] == "PR_BASE_CHANGED"
    assert store.pr_followup_candidates() == []

    def import_snapshot(checked_at):
        return store.import_pr_followups(
            {
                "version": "pr_followup_v3",
                "generatedAt": checked_at,
                "items": [
                    {
                        "url": pr_url,
                        "headSha": candidate["headSha"],
                        "actionDigest": candidate["actionDigest"],
                        "taskActionDigest": candidate["taskActionDigest"],
                        "taskFollowupRequired": True,
                        "taskActions": candidate["actions"],
                        "evidence": candidate["evidence"],
                        "checkedAt": checked_at,
                    }
                ],
            }
        )

    import_snapshot(candidate["checkedAt"])
    assert store.pr_followup_candidates() == []

    fresh_checked_at = iso_z(parse_time(candidate["checkedAt"]) + timedelta(minutes=1))
    import_snapshot(fresh_checked_at)
    fresh = store.pr_followup_candidates()
    assert len(fresh) == 1
    assert fresh[0]["checkedAt"] == fresh_checked_at
    assert fresh[0]["wakeDigest"] != candidate["wakeDigest"]


def test_pr_followup_reserve_binds_controller_verified_conflict_files(tmp_path):
    store, worktree, head_sha, pr_url = _published_followup_store(tmp_path)
    now = iso_z(datetime.now(UTC))
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": now,
            "items": [
                {
                    "url": pr_url,
                    "headSha": head_sha,
                    "actionDigest": "conflict-action",
                    "taskActionDigest": "conflict-task-action",
                    "taskFollowupRequired": True,
                    "taskActions": ["分支存在合并冲突"],
                    "evidence": {
                        "mergeConflict": True,
                        "baseRefName": "main",
                        "baseSha": "a" * 40,
                        "mergeConflictPreparationVersion": "conflict_files_v1",
                    },
                    "checkedAt": now,
                }
            ],
        }
    )
    candidate = store.pr_followup_candidates()[0]

    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=head_sha,
        prepared_base_sha="b" * 40,
        merge_conflict_files=["src/two.py", "src/one.py"],
    )
    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert context["prFollowup"]["preparedHeadSha"] == head_sha
    assert context["prFollowup"]["evidence"]["baseAdvancedFromSha"] == "a" * 40
    assert context["prFollowup"]["evidence"]["baseSha"] == "b" * 40
    assert context["prFollowup"]["evidence"]["mergeConflictFiles"] == [
        "src/one.py",
        "src/two.py",
    ]
    assert worktree.is_dir()
    assert store.unresolved_pr_followups()


def test_pr_followup_reserve_binds_fast_forwarded_integration_base(tmp_path):
    store, _worktree, head_sha, pr_url = _published_followup_store(tmp_path)
    now = iso_z(datetime.now(UTC))
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": now,
            "items": [
                {
                    "url": pr_url,
                    "headSha": head_sha,
                    "actionDigest": "base-action",
                    "taskActionDigest": "base-task-action",
                    "taskFollowupRequired": True,
                    "taskActions": ["当前分支需要更新项目主分支"],
                    "evidence": {
                        "mergeConflict": False,
                        "baseIntegrationRequired": True,
                        "baseRefName": "main",
                        "baseSha": "a" * 40,
                    },
                    "checkedAt": now,
                }
            ],
        }
    )
    candidate = store.pr_followup_candidates()[0]

    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=head_sha,
        prepared_base_sha="b" * 40,
    )
    context = store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")

    assert context["prFollowup"]["evidence"]["baseAdvancedFromSha"] == "a" * 40
    assert context["prFollowup"]["evidence"]["baseSha"] == "b" * 40


def test_context_sync_recovers_legacy_prepared_followup_binding(tmp_path):
    store, worktree, previous_head, _pr_url = _published_followup_store(tmp_path)
    run_git(worktree, "switch", "main")
    (worktree / "base.py").write_text("base = True\n", encoding="utf-8")
    run_git(worktree, "add", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    prepared_base = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    run_git(worktree, "merge", "--no-ff", "--no-commit", prepared_base)
    run_git(worktree, "commit", "-m", "merge: refresh upstream branch for CI validation")
    prepared_head = run_git(worktree, "rev-parse", "HEAD")
    with store.connect() as connection:
        row = connection.execute(
            "SELECT evidence_json FROM pr_followups WHERE opportunity_key='a/b#1'"
        ).fetchone()
        evidence = json.loads(row["evidence_json"])
        evidence.update({"baseIntegrationRequired": True, "baseSha": "f" * 40})
        connection.execute(
            "UPDATE pr_followups SET evidence_json=? WHERE opportunity_key='a/b#1'",
            (json.dumps(evidence),),
        )
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    next_checked_at = iso_z(datetime.now(UTC) + timedelta(minutes=1))
    store.import_pr_followups(
        {
            "version": "pr_followup_v3",
            "generatedAt": next_checked_at,
            "items": [
                {
                    "url": "https://github.com/a/b/pull/9",
                    "headSha": previous_head,
                    "actionDigest": "new-action",
                    "taskActionDigest": "new-task-action",
                    "taskFollowupRequired": True,
                    "taskActions": ["存在未解决审查线程"],
                    "evidence": {
                        "baseIntegrationRequired": True,
                        "baseSha": "f" * 40,
                    },
                    "checkedAt": next_checked_at,
                }
            ],
        }
    )
    legacy_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
    assert "preparedHeadSha" not in legacy["prFollowup"]
    assert legacy["prFollowup"]["wakeDigest"] != candidate["wakeDigest"]
    Path(legacy["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": legacy["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "PR_OPEN",
                "followupDigest": legacy["prFollowup"]["wakeDigest"],
                "evidence": {"verified": True},
            }
        ),
        encoding="utf-8",
    )

    recovered, errors = MODULE._recover_unbound_pr_followup_preparations(store)
    refreshed_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    refreshed = json.loads(refreshed_path.read_text(encoding="utf-8"))

    assert errors == []
    assert recovered[0]["preparedHeadSha"] == prepared_head
    assert refreshed["prFollowup"]["headSha"] == previous_head
    assert refreshed["prFollowup"]["preparedHeadSha"] == prepared_head
    assert refreshed["prFollowup"]["evidence"]["baseSha"] == prepared_base
    assert refreshed["contextDigest"] != legacy["contextDigest"]
    assert refreshed["prFollowup"]["wakeDigest"] == candidate["wakeDigest"]
    preparation = store.active_pr_followup_preparation("a/b#1", thread_id="thread-1")
    assert preparation["legacyCompatibility"] == {
        "contextDigest": legacy["contextDigest"],
        "wakeDigest": legacy["prFollowup"]["wakeDigest"],
    }
    assert store.pr_followup_candidates() == []

    ingested = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert ingested["ok"] is True
    assert ingested["ingested"] == [{"key": "a/b#1", "stage": "PR_OPEN"}]
    assert store.active_pr_followup_preparation("a/b#1", thread_id="thread-1") is None
    assert store.pr_followup_candidates()[0]["wakeDigest"] == legacy["prFollowup"]["wakeDigest"]


def test_context_sync_closes_legacy_reservation_superseded_by_later_result(tmp_path):
    store, worktree, head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=head_sha,
    )
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.record_followup_result(
        "a/b#1",
        wake_digest="f" * 64,
        result_digest="later-result",
        stage="PR_OPEN",
    )

    synced = MODULE.sync_task_contexts(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert synced["ok"] is True
    assert synced["prFollowupsSuperseded"] == [
        {
            "key": "a/b#1",
            "wakeDigest": candidate["wakeDigest"],
            "supersededBy": "f" * 64,
        }
    ]
    assert store.active_pr_followup_preparation("a/b#1", thread_id="thread-1") is None
    assert (worktree / ".oss-pr-radar" / "task-context.json").is_file()


@pytest.mark.parametrize("reason", ["STRONG_EXISTING_PR", "ACTIVE_OR_CONDITIONAL_CLAIM"])
def test_context_sync_terminalizes_obsolete_task_with_missing_worktree(
    monkeypatch, tmp_path, reason
):
    store, worktree = registered_store(tmp_path)
    store.record_stage("a/b#1", "FIX_READY", evidence={})
    shutil.rmtree(worktree)
    evidence = SimpleNamespace(digest="live-evidence", as_dict=lambda: {"complete": True})
    verdict = SimpleNamespace(
        status="BLOCK",
        reason_code=reason,
        as_dict=lambda: {"status": "BLOCK", "reason_code": reason},
    )
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))

    synced = MODULE.sync_task_contexts(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert synced["ok"] is True
    assert synced["unavailable"] == []
    assert synced["revalidationErrors"] == []
    assert synced["noGo"] == [
        {
            "key": "a/b#1",
            "reason": reason,
            "source": "missing_worktree_revalidation",
        }
    ]
    context = store.task_context(
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
    )
    assert context is not None
    assert context["stage"] == "AUDIT_NO_GO"


def test_context_sync_keeps_missing_worktree_for_nonterminal_hold(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    shutil.rmtree(worktree)
    evidence = SimpleNamespace(digest="live-evidence", as_dict=lambda: {"complete": False})
    verdict = SimpleNamespace(
        status="HOLD",
        reason_code="EVIDENCE_INCOMPLETE",
        as_dict=lambda: {"status": "HOLD", "reason_code": "EVIDENCE_INCOMPLETE"},
    )
    monkeypatch.setattr(MODULE, "_audit_intent", lambda _intent: (evidence, verdict))

    synced = MODULE.sync_task_contexts(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert synced["ok"] is True
    assert synced["noGo"] == []
    assert synced["unavailable"][0]["key"] == "a/b#1"
    assert synced["revalidationErrors"] == []


def test_context_sync_keeps_missing_worktree_when_live_revalidation_fails(monkeypatch, tmp_path):
    store, worktree = registered_store(tmp_path)
    shutil.rmtree(worktree)

    def fail_revalidation(_intent):
        raise RuntimeError("GitHub unavailable")

    monkeypatch.setattr(MODULE, "_audit_intent", fail_revalidation)

    synced = MODULE.sync_task_contexts(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert synced["ok"] is True
    assert synced["errors"] == []
    assert synced["unavailable"][0]["reason"] == "TASK_WORKTREE_UNAVAILABLE"
    assert synced["revalidationErrors"] == [
        {"key": "a/b#1", "error": "RuntimeError:GitHub unavailable"}
    ]


def test_ingest_skips_consumed_result_after_followup_context_refresh(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    original_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    original = json.loads(original_path.read_text(encoding="utf-8"))
    result_path = Path(original["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": original["contextDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "FIX_READY",
            }
        ),
        encoding="utf-8",
    )
    digest = hashlib.sha256(result_path.read_bytes()).hexdigest()
    store.record_task_result_ingested("a/b#1", digest=digest, stage="FIX_READY")
    refreshed_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
        prepared_followup_head="b" * 40,
    )
    refreshed = json.loads(refreshed_path.read_text(encoding="utf-8"))
    assert refreshed["contextDigest"] != original["contextDigest"]

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == []
    assert result["publicationRequests"] == []
    assert result["errors"] == []


def test_ingest_skips_blocked_fix_after_context_refresh(tmp_path):
    store, _worktree, result_path = _controller_commit_result(tmp_path)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    request_id = first["publicationRequests"][0]["requestId"]
    store.block_publication_request(request_id, "SUBMIT_READY_EVIDENCE_INCOMPLETE")
    context_path = result_path.parent / "task-context.json"
    refreshed = json.loads(context_path.read_text(encoding="utf-8"))
    refreshed["contextDigest"] = "refreshed-context"
    context_path.write_text(json.dumps(refreshed), encoding="utf-8")

    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert repeated["ok"] is True
    assert repeated["ingested"] == []
    assert repeated["publicationRequests"] == []
    assert repeated["errors"] == []


def test_prepare_pr_followup_accepts_fast_forwarded_base(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    remote = tmp_path / "remote.git"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    baseline = run_git(worktree, "rev-parse", "HEAD")
    run_git(remote.parent, "init", "--bare", str(remote))
    run_git(worktree, "remote", "add", "origin", str(remote))
    run_git(worktree, "push", "origin", f"{baseline}:refs/heads/main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    source.write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    live_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", "HEAD:refs/heads/fix/1-runtime")
    run_git(remote, "update-ref", "refs/pull/9/head", live_head)
    run_git(worktree, "switch", "--detach", baseline)
    source.write_text("value = 3\n", encoding="utf-8")
    (worktree / "base.py").write_text("base = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    live_base = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", f"{live_base}:refs/heads/main")
    run_git(worktree, "update-ref", "refs/remotes/origin/main", baseline)
    run_git(worktree, "switch", "--detach", baseline)
    run_git(worktree, "branch", "-f", "fix/1-runtime", baseline)
    monkeypatch.setattr(MODULE, "_upstream_remote", lambda *_args: "origin")

    prepared = MODULE._prepare_pr_followup(
        {
            "prUrl": "https://github.com/a/b/pull/9",
            "worktreePath": str(worktree),
            "branch": "fix/1-runtime",
            "headSha": live_head,
            "evidence": {
                "mergeConflict": True,
                "baseRefName": "main",
                "baseSha": baseline,
            },
        }
    )

    assert prepared == {
        "preparedHeadSha": live_head,
        "preparedBaseSha": live_base,
        "mergeConflictFiles": ["runtime.py"],
    }
    assert run_git(worktree, "rev-parse", "HEAD") == live_head
    assert run_git(worktree, "branch", "--show-current") == "fix/1-runtime"
    assert run_git(worktree, "rev-parse", "refs/remotes/origin/main") == live_base
    assert run_git(worktree, "status", "--porcelain") == ""


def test_pr_followup_recreates_a_missing_controller_workspace(monkeypatch, tmp_path):
    project_root = tmp_path / "github"
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)
    expected = MODULE.managed_worktree_path("intent-1", "a/b")
    source = tmp_path / "source"
    source.mkdir()
    calls = []

    monkeypatch.setattr(
        MODULE, "source_repo", lambda repo: calls.append(("source", repo)) or source
    )

    def prepare(source_path, *, intent_id, repo):
        calls.append(("prepare", source_path, intent_id, repo))
        expected.mkdir(parents=True)
        return expected

    monkeypatch.setattr(MODULE, "prepare_managed_worktree", prepare)

    recovered = MODULE._ensure_pr_followup_worktree(
        {
            "worktreePath": str(expected),
            "repo": "a/b",
            "intentId": "intent-1",
        }
    )

    assert recovered == expected
    assert calls == [
        ("source", "a/b"),
        ("prepare", source, "intent-1", "a/b"),
    ]


def test_prepare_conflicted_pr_followup_requires_signed_base_snapshot(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    monkeypatch.setattr(MODULE, "_upstream_remote", lambda *_args: "origin")

    with pytest.raises(RuntimeError, match="lacks base snapshot"):
        MODULE._prepare_pr_followup(
            {
                "prUrl": "https://github.com/a/b/pull/9",
                "worktreePath": str(worktree),
                "branch": "fix/1-runtime",
                "headSha": "a" * 40,
                "evidence": {"mergeConflict": True},
            }
        )


def test_prepare_pr_followup_refreshes_fast_forwarded_base_before_integration(
    monkeypatch, tmp_path
):
    worktree = tmp_path / "worktree"
    remote = tmp_path / "remote.git"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    baseline = run_git(worktree, "rev-parse", "HEAD")
    run_git(remote.parent, "init", "--bare", str(remote))
    run_git(worktree, "remote", "add", "origin", str(remote))
    run_git(worktree, "push", "origin", f"{baseline}:refs/heads/main")

    run_git(worktree, "switch", "-c", "fix/1-runtime")
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    live_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", "HEAD:refs/heads/fix/1-runtime")
    run_git(remote, "update-ref", "refs/pull/9/head", live_head)

    run_git(worktree, "switch", "--detach", baseline)
    (worktree / "base.py").write_text("base = 2\n", encoding="utf-8")
    run_git(worktree, "add", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    live_base = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "push", "origin", f"{live_base}:refs/heads/main")
    run_git(worktree, "switch", "fix/1-runtime")
    monkeypatch.setattr(MODULE, "_upstream_remote", lambda *_args: "origin")

    preparation = MODULE._prepare_pr_followup(
        {
            "prUrl": "https://github.com/a/b/pull/9",
            "worktreePath": str(worktree),
            "branch": "fix/1-runtime",
            "headSha": live_head,
            "evidence": {
                "mergeConflict": False,
                "baseIntegrationRequired": True,
                "baseRefName": "main",
                "baseSha": baseline,
            },
        }
    )

    prepared = preparation["preparedHeadSha"]
    assert preparation["preparedBaseSha"] == live_base
    assert prepared == run_git(worktree, "rev-parse", "HEAD")
    assert prepared != live_head
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        live_head,
        live_base,
    ]
    assert "Signed-off-by: Test Contributor <test@example.com>" in run_git(
        worktree, "show", "-s", "--format=%B", "HEAD"
    )
    assert run_git(worktree, "status", "--porcelain") == ""


def test_controller_ingests_followup_fix_as_update_to_exact_existing_pr(tmp_path):
    store, worktree, previous_head, pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: preserve runtime boundary")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update(
            {
                "defaultBranch": "main",
                "selectedBaseSha": base_sha,
                "preTaskEvidence": {
                    "defaultBranch": "main",
                    "baseSha": base_sha,
                    "codePathsPlan": ["runtime.py"],
                },
                "codePaths": ["runtime.py"],
                "probeRequired": True,
                "probeLevel": "REPRODUCED_VALIDATED",
                "taskStage": "IMPLEMENTATION_READY",
            }
        )
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    body_path = worktree / ".oss-pr-radar" / "pr-body.md"
    body_path.write_text("Fixes #1\n\nCorrect the runtime boundary.\n", encoding="utf-8")
    result_path = Path(context["resultPath"])
    result_path.write_text(
        json.dumps(
            {
                "schemaVersion": "radar-task-result-v1",
                "contextDigest": context["contextDigest"],
                "followupDigest": candidate["wakeDigest"],
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-1",
                "worktreePath": str(worktree.resolve()),
                "stage": "FIX_READY",
                "handoffMode": "controller_commit_complete",
                "commitSha": head_sha,
                "branch": run_git(worktree, "symbolic-ref", "--short", "HEAD"),
                "controllerCommitChangedFiles": ["runtime.py"],
                "commitMessage": "fix: preserve runtime boundary",
                "changedFiles": ["runtime.py"],
                "headSha": head_sha,
                "previousCommitSha": previous_head,
                "selectedBaseSha": base_sha,
                "taskId": "intent-1",
                "codePaths": ["runtime.py"],
                "preTaskEvidence": {
                    "defaultBranch": "main",
                    "baseSha": base_sha,
                    "codePathsPlan": ["runtime.py"],
                },
                "probeRequired": True,
                "probeLevel": "REPRODUCED_VALIDATED",
                "tests": [{"command": "pytest tests/runtime", "exitCode": 0}],
                "quality": {field: True for field in QUALITY_FIELDS},
                "publication": {
                    "headOwner": "Oxygen56",
                    "baseBranch": "main",
                    "title": "fix: preserve runtime boundary",
                    "bodyFile": str(body_path.resolve()),
                },
            }
        ),
        encoding="utf-8",
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    candidate_record = next(
        item
        for item in store.task_result_candidates()
        if item["key"] == "a/b#1" and item["threadId"] == "thread-1"
    )
    value, _raw = _finalize_controller_commit_for_test(
        candidate=candidate_record,
        context=context,
        value=value,
        result_path=result_path,
    )
    value["independentReview"] = MODULE.controller_review_result(MODULE.ROOT, value)
    _sign_reproduction_certificate(
        value,
        result_path=result_path,
        base_sha=base_sha,
        head_sha=head_sha,
        commit_sha=head_sha,
        store=store,
    )
    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True, result["errors"]
    assert result["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(result["publicationRequests"]) == 1
    request = store.publication_work_items()[0]["request"]
    assert request["publicationKind"] == "PR_UPDATE"
    assert request["existingPrUrl"] == pr_url
    assert request["previousCommitSha"] == previous_head
    assert request["commitSha"] == run_git(worktree, "rev-parse", "HEAD")
    assert request["commitSha"] != previous_head
    assert store.task_result_digest_seen(
        "a/b#1", MODULE._task_result_digest(value, result_path.read_bytes())
    )


def test_followup_commit_preserves_prepared_base_integration_diff(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    baseline = run_git(worktree, "rev-parse", "HEAD")

    run_git(worktree, "switch", "-c", "fix/1-runtime")
    (worktree / "feature.py").write_text("feature = True\n", encoding="utf-8")
    run_git(worktree, "add", "feature.py")
    run_git(worktree, "commit", "-m", "fix: feature")
    previous_head = run_git(worktree, "rev-parse", "HEAD")

    run_git(worktree, "switch", "main")
    (worktree / "base.py").write_text("base = 2\n", encoding="utf-8")
    run_git(worktree, "add", "base.py")
    run_git(worktree, "commit", "-m", "chore: advance base")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    run_git(worktree, "merge", "--no-ff", "--no-commit", base_sha)
    run_git(worktree, "commit", "--signoff", "-m", "merge: refresh upstream branch")
    prepared_head = run_git(worktree, "rev-parse", "HEAD")

    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    result_path = tmp_path / "result.json"
    value = {
        "handoffMode": "controller_commit_required",
        "commitSha": None,
        "branch": "fix/1-runtime",
        "commitMessage": "fix: adapt runtime to current base",
        "changedFiles": ["runtime.py"],
        "publication": {"baseBranch": "main"},
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")

    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context={
            "stage": "PR_OPEN",
            "prFollowup": {
                "headSha": previous_head,
                "preparedHeadSha": prepared_head,
                "evidence": {
                    "baseIntegrationRequired": True,
                    "baseSha": base_sha,
                },
            },
        },
        value=value,
        result_path=result_path,
    )

    assert finalized["controllerCommitChangedFiles"] == ["runtime.py"]
    assert finalized["changedFiles"] == ["base.py", "runtime.py"]
    assert finalized["previousCommitSha"] == prepared_head
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        prepared_head
    ]
    assert run_git(worktree, "merge-base", baseline, "HEAD") == baseline


def _controller_commit_result(
    tmp_path: Path,
    *,
    policy_verified: bool = True,
    controller_policy_complete: bool = False,
    missing_quality: tuple[str, ...] = (),
    publication_blocked_reason: str | None = None,
    dco_required: bool = False,
    base_branch: str = "main",
    authenticated: bool = True,
) -> tuple[RadarLedger, Path, Path]:
    from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES, run_reproduction_probe

    MODULE.ROOT = tmp_path
    store, worktree = registered_store(tmp_path)
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 1\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "remote", "add", "origin", "https://github.com/a/b.git")
    run_git(worktree, "update-ref", "refs/remotes/origin/main", "HEAD")
    run_git(
        worktree,
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    )
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    source.write_text("value = 2\nassert value == 2\n", encoding="utf-8")
    run_git(worktree, "switch", "-c", "fix/1-runtime-boundary")
    run_git(worktree, "add", "runtime.py")
    commit_message = "fix: preserve runtime boundary"
    if dco_required:
        commit_message += "\n\nSigned-off-by: Test Contributor <test@example.com>"
    run_git(worktree, "commit", "-m", commit_message)
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    probe_checkout = tmp_path / "probe-checkout"
    run_git(worktree, "worktree", "add", "--detach", str(probe_checkout), base_sha)
    profile_id = "test-local-controller-real"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    probe = run_reproduction_probe(
        checkout_path=probe_checkout,
        repo="a/b",
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
        profile_id=profile_id,
        issue_url="https://github.com/a/b/issues/1",
        task_id="intent-1",
        thread_id="thread-1",
        head_sha=head_sha,
        commit_sha=head_sha,
        result_digest="pending-result-digest",
    )
    TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    run_git(worktree, "worktree", "remove", "--force", str(probe_checkout))
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update(
            {
                "defaultBranch": "main",
                "selectedBaseSha": base_sha,
                "preTaskEvidence": {
                    "defaultBranch": "main",
                    "baseSha": base_sha,
                    "codePathsPlan": ["runtime.py"],
                },
                "codePaths": ["runtime.py"],
                "probeRequired": True,
                "probeLevel": "REPRODUCED_VALIDATED",
                "taskStage": "IMPLEMENTATION_READY",
                "probeReceiptDigest": probe["receiptDigest"],
                "resultDigest": "pending-result-digest",
                "headSha": head_sha,
                "commitSha": head_sha,
            }
        )
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )
    if controller_policy_complete:
        store.record_audit_snapshot(
            "a/b#1",
            evidence={
                "authorization": {"status": "ALLOW"},
                "evidenceDigest": "c" * 64,
                "liveAudit": {
                    "capturedAt": iso_z(datetime.now(UTC)),
                    "evidence": {
                        "digest": "c" * 64,
                        "repo": "a/b",
                        "issue": {"number": 1, "state": "open"},
                        "completeness": {"repositoryPolicy": "COMPLETE"},
                        "policy": {
                            "status": "NORMAL",
                            "digest": "d" * 64,
                            "ai_disclosure": False,
                            "ai_prohibited": False,
                        },
                    },
                },
            },
            dedupe_key="controller-policy-complete",
        )
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    body_path = worktree / ".oss-pr-radar" / "pr-body.md"
    body_path.write_text("Fixes #1\n\nCorrect the runtime boundary.\n", encoding="utf-8")
    result_path = Path(context["resultPath"])
    quality = {field: True for field in QUALITY_FIELDS}
    quality["policy_verified"] = policy_verified
    for field in missing_quality:
        quality[field] = False
    result = {
        "schemaVersion": "radar-task-result-v1",
        "contextDigest": context["contextDigest"],
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "stage": "FIX_READY",
        "handoffMode": "controller_commit_complete",
        "commitSha": head_sha,
        "branch": "fix/1-runtime-boundary",
        "controllerCommitChangedFiles": ["runtime.py"],
        "commitMessage": "fix: preserve runtime boundary",
        "changedFiles": ["runtime.py"],
        "headSha": head_sha,
        "selectedBaseSha": base_sha,
        "taskId": "intent-1",
        "codePaths": ["runtime.py"],
        "preTaskEvidence": {
            "defaultBranch": "main",
            "baseSha": base_sha,
            "codePathsPlan": ["runtime.py"],
        },
        "probeRequired": True,
        "probeLevel": "REPRODUCED_VALIDATED",
        "reproductionReceipt": probe,
        "tests": [{"command": "pytest tests/runtime", "exitCode": 0}],
        "quality": quality,
        "independentReview": {
            "verdict": "PASS",
            "summary": "test controller receipt",
        },
        "dcoRequired": dco_required,
        "publication": {
            "headOwner": "Oxygen56",
            "baseBranch": base_branch,
            "title": "fix: preserve runtime boundary",
            "bodyFile": str(body_path.resolve()),
        },
    }
    if publication_blocked_reason:
        result["publicationBlockedReason"] = publication_blocked_reason
    if quality.get("independent_review_passed") is not True:
        result.pop("independentReview", None)
    if controller_policy_complete:
        result["controllerPolicyVerification"] = {
            "source": "controller_live_audit",
            "capturedAt": iso_z(datetime.now(UTC)),
            "policyDigest": "d" * 64,
            "policyStatus": "NORMAL",
        }
    signed_result = dict(result)
    signed_result["handoffMode"] = "controller_commit_complete"
    signed_result["publication"] = dict(result["publication"]) | {"baseBranch": "main"}
    if controller_policy_complete:
        signed_quality = dict(signed_result["quality"])
        signed_quality["policy_verified"] = True
        signed_result["quality"] = signed_quality
        signed_result.pop("controllerPolicyVerification", None)
    signed_result.pop("contextDigest", None)
    unsigned_digest = sha256_json(signed_result)
    result["resultDigest"] = unsigned_digest
    probe["resultDigest"] = unsigned_digest
    # Re-sign after binding the actual immutable result digest.
    from oss_pr_radar.repo_probe import run_reproduction_probe

    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    # The first probe was executed against the fixed base.  Recreate the
    # signed certificate with the final result binding through the same real
    # profile and checkout, then remove the temporary profile.
    probe_checkout = tmp_path / "probe-checkout-final"
    run_git(worktree, "worktree", "add", "--detach", str(probe_checkout), base_sha)
    probe = run_reproduction_probe(
        checkout_path=probe_checkout,
        repo="a/b",
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
        profile_id=profile_id,
        issue_url="https://github.com/a/b/issues/1",
        task_id="intent-1",
        thread_id="thread-1",
        head_sha=head_sha,
        commit_sha=head_sha,
        result_digest=unsigned_digest,
    )
    TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    run_git(worktree, "worktree", "remove", "--force", str(probe_checkout))
    result["reproductionReceipt"] = probe
    managed = ManagedLedger(store.path, ensure_schema=True)
    managed.upsert_opportunity(
        opportunity_key="a/b#1",
        owner="a",
        repo="b",
        issue_number=1,
        issue_url="https://github.com/a/b/issues/1",
        state="SYSTEM_PROCESSING",
        source="test-legal-fixture",
        provenance={"fixture": True},
        metadata={"selectedBaseSha": base_sha, "codePaths": ["runtime.py"]},
    )
    managed.bind_task(
        task_id="intent-1",
        opportunity_key="a/b#1",
        thread_id="thread-1",
        worktree_path=str(worktree),
        state="REPRODUCTION_REQUIRED",
        provenance={
            "codePaths": ["runtime.py"],
            "selectedBaseSha": probe["baseSha"],
            "headSha": probe["headSha"],
            "commitSha": probe["commitSha"],
            "resultDigest": probe["resultDigest"],
        },
    )
    managed.transition_task_to_implementation(
        task_id="intent-1",
        receipt_digest=probe["receiptDigest"],
        receipt=probe,
    )
    # Bind the actual current-key receipt before materializing the final task
    # context.  This keeps legal fixtures editable without weakening the
    # missing/unauthenticated-probe downgrade.
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update(
            {
                "probeReceiptDigest": probe["receiptDigest"],
                "resultDigest": unsigned_digest,
                "headSha": head_sha,
                "commitSha": head_sha,
                "taskStage": "IMPLEMENTATION_READY",
                "probeLevel": "REPRODUCED_VALIDATED",
            }
        )
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )
    context = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )
    result["contextDigest"] = context["contextDigest"]
    result["handoffMode"] = "controller_commit_required"
    result["commitSha"] = None
    result.pop("controllerCommitChangedFiles", None)
    if not authenticated:
        result.pop("reproductionReceipt", None)
        result.pop("resultDigest", None)
    result_path.write_text(json.dumps(result), encoding="utf-8")
    if authenticated:
        candidate_record = next(
            item
            for item in store.task_result_candidates()
            if item["key"] == "a/b#1" and item["threadId"] == "thread-1"
        )
        context = json.loads((result_path.parent / "task-context.json").read_text(encoding="utf-8"))
        result, _raw = _finalize_controller_commit_for_test(
            candidate=candidate_record,
            context=context,
            value=result,
            result_path=result_path,
        )
        if controller_policy_complete:
            result_quality = dict(result.get("quality") or {})
            result_quality["policy_verified"] = True
            result["quality"] = result_quality
            result_path.write_text(json.dumps(result), encoding="utf-8")
        _sign_reproduction_certificate(
            result,
            result_path=result_path,
            base_sha=base_sha,
            head_sha=head_sha,
            commit_sha=head_sha,
            store=store,
        )
        if quality.get("independent_review_passed") is True:
            review_value = dict(result)
            review_quality = dict(review_value.get("quality") or {})
            if controller_policy_complete:
                review_quality["policy_verified"] = True
            review_value["quality"] = review_quality
            _write_explicit_controller_review(tmp_path, review_value)
    return store, worktree, result_path


def _refresh_reproduction_certificate(result_path: Path) -> str:
    """Re-sign a legal fixture after its controller-owned result fields change."""

    from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES, run_reproduction_probe

    value = json.loads(result_path.read_text(encoding="utf-8"))
    existing = dict(value["reproductionReceipt"])
    unsigned = dict(value)
    unsigned.pop("reproductionReceipt", None)
    unsigned.pop("probeReceipt", None)
    unsigned.pop("resultDigest", None)
    unsigned.pop("independentReview", None)
    unsigned.pop("contextDigest", None)
    policy_certificate = unsigned.pop("controllerPolicyVerification", None)
    quality = unsigned.get("quality")
    if isinstance(quality, dict):
        quality = dict(quality)
        if policy_certificate is not None:
            quality["policy_verified"] = True
        unsigned["quality"] = quality
    if value.get("handoffMode") == "controller_commit_required":
        unsigned["handoffMode"] = "controller_commit_complete"
        unsigned["commitSha"] = existing.get("commitSha")
        unsigned["branch"] = existing.get("headRef") or value.get(
            "branch", "fix/1-runtime-boundary"
        )
        unsigned["controllerCommitChangedFiles"] = list(value.get("changedFiles") or ["runtime.py"])
        publication = unsigned.get("publication")
        if isinstance(publication, dict):
            unsigned["publication"] = dict(publication) | {"baseBranch": "main"}
    digest = sha256_json(unsigned)
    worktree = Path(value["worktreePath"]).resolve()
    checkout = worktree.parent / ".probe-refresh"
    profile_id = "test-local-controller-refresh"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    run_git(worktree, "worktree", "add", "--detach", str(checkout), existing["baseSha"])
    receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo=existing["repo"],
        default_branch=existing["defaultBranch"],
        selected_base_sha=existing["baseSha"],
        code_paths=list(existing["codePaths"]),
        profile_id=profile_id,
        issue_url=existing["issueUrl"],
        task_id=existing["taskId"],
        head_sha=existing.get("headSha"),
        commit_sha=existing.get("commitSha"),
        result_digest=digest,
    )
    TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    run_git(worktree, "worktree", "remove", "--force", str(checkout))
    value["resultDigest"] = digest
    value["reproductionReceipt"] = receipt
    # Keep the controller context bound to the newly issued receipt.  Follow-up
    # fixtures intentionally rebuild this binding instead of relying on a
    # global test bypass.
    store = RadarLedger(worktree.parent / "ledger.sqlite3")
    store.update_intent_probe_metadata(
        str(value.get("taskId") or "intent-1"),
        probe_level="REPRODUCED_VALIDATED",
        task_stage="IMPLEMENTATION_READY",
        receipt_digest=str(receipt.get("receiptDigest") or ""),
    )
    context_path = MODULE.write_task_context(
        store,
        issue_url=str(value["issueUrl"]),
        thread_id=str(value["threadId"]),
        cwd=worktree,
    )
    value["contextDigest"] = json.loads(context_path.read_text(encoding="utf-8"))["contextDigest"]
    quality = value.get("quality")
    review = value.get("independentReview")
    if (
        isinstance(quality, dict)
        and quality.get("independent_review_passed") is True
        and isinstance(review, dict)
        and review.get("verdict") == "PASS"
    ):
        value["independentReview"] = _write_explicit_controller_review(MODULE.ROOT, value)
    result_path.write_text(json.dumps(value), encoding="utf-8")
    return digest


def _sign_reproduction_certificate(
    value: dict,
    *,
    result_path: Path,
    base_sha: str,
    head_sha: str,
    commit_sha: str,
    store: RadarLedger | None = None,
) -> str:
    from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES, run_reproduction_probe

    unsigned = dict(value)
    unsigned.pop("reproductionReceipt", None)
    unsigned.pop("probeReceipt", None)
    unsigned.pop("resultDigest", None)
    unsigned.pop("independentReview", None)
    unsigned.pop("contextDigest", None)
    policy_certificate = unsigned.pop("controllerPolicyVerification", None)
    quality = unsigned.get("quality")
    if isinstance(quality, dict) and policy_certificate is not None:
        quality = dict(quality)
        quality["policy_verified"] = True
        unsigned["quality"] = quality
    digest = sha256_json(unsigned)
    worktree = Path(value["worktreePath"]).resolve()
    checkout = worktree.parent / ".probe-new"
    profile_id = "test-local-controller-new"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    run_git(worktree, "worktree", "add", "--detach", str(checkout), base_sha)
    receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo="a/b",
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
        profile_id=profile_id,
        issue_url="https://github.com/a/b/issues/1",
        task_id="intent-1",
        thread_id=str(value.get("threadId") or "thread-1"),
        head_sha=head_sha,
        commit_sha=commit_sha,
        result_digest=digest,
    )
    TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    run_git(worktree, "worktree", "remove", "--force", str(checkout))
    value["resultDigest"] = digest
    value["reproductionReceipt"] = receipt
    if store is not None:
        store.update_intent_probe_metadata(
            str(value.get("taskId") or "intent-1"),
            probe_level="REPRODUCED_VALIDATED",
            task_stage="IMPLEMENTATION_READY",
            receipt_digest=str(receipt.get("receiptDigest") or ""),
        )
        managed = ManagedLedger(store.path, ensure_schema=True)
        task_id = str(value.get("taskId") or "intent-1")
        opportunity_key = str(value.get("key") or "a/b#1")
        owner_repo, issue_number = opportunity_key.rsplit("#", 1)
        owner, repo = owner_repo.split("/", 1)
        managed.upsert_opportunity(
            opportunity_key=opportunity_key,
            owner=owner,
            repo=repo,
            issue_number=int(issue_number),
            issue_url=str(value["issueUrl"]),
            state="SYSTEM_PROCESSING",
            source="test-legal-fixture",
            provenance={"fixture": True},
            metadata={"selectedBaseSha": base_sha, "codePaths": ["runtime.py"]},
        )
        managed.bind_task(
            task_id=task_id,
            opportunity_key=str(value.get("key") or "a/b#1"),
            thread_id=str(value.get("threadId") or "thread-1"),
            worktree_path=str(worktree),
            state="REPRODUCTION_REQUIRED",
            provenance={
                "codePaths": list(receipt.get("codePaths") or ["runtime.py"]),
                "selectedBaseSha": receipt.get("baseSha"),
                "headSha": receipt.get("headSha"),
                "commitSha": receipt.get("commitSha"),
                "resultDigest": receipt.get("resultDigest"),
            },
        )
        managed.transition_task_to_implementation(
            task_id=task_id,
            receipt_digest=str(receipt.get("receiptDigest") or ""),
            receipt=receipt,
        )
        context_path = MODULE.write_task_context(
            store,
            issue_url=str(value["issueUrl"]),
            thread_id=str(value["threadId"]),
            cwd=worktree,
        )
        value["contextDigest"] = json.loads(context_path.read_text(encoding="utf-8"))[
            "contextDigest"
        ]
        if (
            isinstance(value.get("quality"), dict)
            and value["quality"].get("independent_review_passed") is True
        ):
            value["independentReview"] = _write_explicit_controller_review(MODULE.ROOT, value)
    result_path.write_text(json.dumps(value), encoding="utf-8")
    return digest


def _legal_queue_publication_fixture(tmp_path: Path, *, request_id: str = "request-1") -> dict:
    """Build a real local commit plus a current-key reproduction receipt."""

    from oss_pr_radar.repo_probe import TRUSTED_PROBE_PROFILES, run_reproduction_probe

    MODULE.ROOT = tmp_path
    worktree = tmp_path / f"worktree-{request_id}"
    worktree.mkdir()
    run_git(worktree, "init")
    (worktree / ".git" / "info" / "exclude").write_text(".oss-pr-radar/\n", encoding="utf-8")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    (worktree / "runtime.py").write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime boundary")
    head_sha = run_git(worktree, "rev-parse", "HEAD")
    base_sha = head_sha
    private_dir = worktree / ".oss-pr-radar"
    private_dir.mkdir()
    result_path = private_dir / "result.json"
    body_path = private_dir / "body.md"
    body_path.write_text("Fixes #1\n\nFix the runtime boundary.\n", encoding="utf-8")
    issue_url = "https://github.com/a/b/issues/1"
    value = {
        "schemaVersion": "radar-task-result-v1",
        "key": "a/b#1",
        "issueUrl": issue_url,
        "threadId": request_id,
        "taskId": request_id,
        "worktreePath": str(worktree.resolve()),
        "stage": "FIX_READY",
        "taskStage": "IMPLEMENTATION_READY",
        "probeRequired": True,
        "probeLevel": "REPRODUCED_VALIDATED",
        "selectedBaseSha": base_sha,
        "headSha": head_sha,
        "commitSha": head_sha,
        "branch": "fix-runtime",
        "codePaths": ["runtime.py"],
        "preTaskEvidence": {
            "defaultBranch": "main",
            "baseSha": base_sha,
            "codePathsPlan": ["runtime.py"],
        },
        "quality": {field: True for field in QUALITY_FIELDS},
        "independentReview": {
            "verdict": "PASS",
            "summary": "test controller receipt",
        },
    }
    profile_id = f"test-queue-{request_id}"
    checkout = worktree.parent / f"probe-{request_id}"
    TRUSTED_PROBE_PROFILES[profile_id] = {
        "reproductionArgv": ["python3", "runtime.py"],
        "validationArgv": ["python3", "runtime.py"],
    }
    run_git(worktree, "worktree", "add", "--detach", str(checkout), base_sha)
    unsigned = dict(value)
    digest = sha256_json(unsigned)
    receipt = run_reproduction_probe(
        checkout_path=checkout,
        repo="a/b",
        default_branch="main",
        selected_base_sha=base_sha,
        code_paths=["runtime.py"],
        profile_id=profile_id,
        issue_url=issue_url,
        task_id=request_id,
        head_sha=head_sha,
        commit_sha=head_sha,
        result_digest=digest,
    )
    TRUSTED_PROBE_PROFILES.pop(profile_id, None)
    run_git(worktree, "worktree", "remove", "--force", str(checkout))
    value["resultDigest"] = digest
    value["reproductionReceipt"] = receipt
    value["independentReview"] = _write_explicit_controller_review(tmp_path, value)
    result_path.write_text(json.dumps(value), encoding="utf-8")
    raw = result_path.read_bytes()
    evidence_digest = hashlib.sha256(raw).hexdigest()
    return {
        "worktree": worktree,
        "resultPath": result_path,
        "headSha": head_sha,
        "request": {
            "requestId": request_id,
            "opportunityKey": "a/b#1",
            "issueUrl": issue_url,
            "taskId": request_id,
            "commitSha": head_sha,
            "headSha": head_sha,
            "selectedBaseSha": base_sha,
            "branch": "fix-runtime",
            "worktreePath": str(worktree),
            "evidencePath": str(result_path),
            "evidenceDigest": evidence_digest,
            "evidenceRawBase64": base64.b64encode(raw).decode("ascii"),
            "resultDigest": digest,
            "probeRequired": True,
            "probeLevel": "REPRODUCED_VALIDATED",
            "taskStage": "IMPLEMENTATION_READY",
            "codePaths": ["runtime.py"],
            "preTaskEvidence": value["preTaskEvidence"],
            "reproductionReceipt": receipt,
            "publication": {
                "headOwner": "Oxygen56",
                "baseBranch": "main",
                "title": "fix: runtime",
                "bodyPath": str(body_path),
            },
        },
    }


def test_implementation_context_survives_missing_opportunity_code_paths(tmp_path):
    store, worktree, _result_path = _controller_commit_result(tmp_path)
    with store.connect() as connection:
        connection.execute(
            "UPDATE managed_opportunities SET metadata_json='{}' WHERE opportunity_key='a/b#1'"
        )

    context = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )

    assert context["taskStage"] == "IMPLEMENTATION_READY"
    assert context["childMayEditFiles"] is True
    assert context["codePaths"] == ["runtime.py"]
    assert context["reproductionReceipt"]["receiptDigest"] == context["probeReceiptDigest"]


def test_implementation_context_survives_expired_transition_receipt(
    monkeypatch, tmp_path
):
    import oss_pr_radar.repo_probe as repo_probe

    store, worktree, _result_path = _controller_commit_result(tmp_path)
    managed = ManagedLedger(store.path, ensure_schema=True)
    provenance = json.loads(managed.read_task("intent-1")["provenance_json"])
    receipt = provenance["probeReceipt"]
    real_datetime = datetime

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(UTC) + timedelta(hours=2)

    monkeypatch.setattr(repo_probe, "datetime", FutureDateTime)
    assert not repo_probe.verify_probe_receipt(
        receipt,
        repo="a/b",
        base_sha=receipt["baseSha"],
        code_paths=list(receipt["codePaths"]),
        issue_url=receipt["issueUrl"],
        task_id="intent-1",
        thread_id="thread-1",
        head_sha=receipt["headSha"],
        commit_sha=receipt["commitSha"],
        result_digest=receipt["resultDigest"],
    )

    context = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )

    assert context["taskStage"] == "IMPLEMENTATION_READY"
    assert context["childMayEditFiles"] is True
    assert context["resultDigest"] == receipt["resultDigest"]


def test_repaired_implementation_context_rearms_same_result_once(tmp_path):
    store, worktree, _result_path = _controller_commit_result(tmp_path)
    managed = ManagedLedger(store.path, ensure_schema=True)
    provenance = json.loads(managed.read_task("intent-1")["provenance_json"])
    result_digest = str(provenance["probeReceipt"]["resultDigest"])
    store.record_task_result_ingested(
        "a/b#1", digest=result_digest, stage="IMPLEMENTATION_READY"
    )
    initial = store.implementation_followup_candidates()[0]
    store.reserve_implementation_followup(
        thread_id="thread-1", result_digest=result_digest
    )
    store.commit_implementation_followup(
        thread_id="thread-1", result_digest=result_digest
    )
    assert initial["implementationFollowupAttemptDigest"] == result_digest

    context_path = worktree / ".oss-pr-radar" / "task-context.json"
    denied_context = json.loads(context_path.read_text(encoding="utf-8"))
    denied_context.update(
        {
            "taskStage": "REPRODUCTION_REQUIRED",
            "probeLevel": "UNVERIFIED",
            "allowedActions": [
                "read_issue",
                "read_repo",
                "run_reproduction_probe",
                "write_structured_result",
            ],
            "taskMode": "reproduction_only",
            "childMayEditFiles": False,
        }
    )
    context_path.write_text(json.dumps(denied_context), encoding="utf-8")

    repaired = json.loads(
        MODULE.write_task_context(
            store,
            issue_url="https://github.com/a/b/issues/1",
            thread_id="thread-1",
            cwd=worktree,
        ).read_text(encoding="utf-8")
    )
    assert repaired["taskStage"] == "IMPLEMENTATION_READY"
    candidates = store.implementation_followup_candidates()
    assert len(candidates) == 1
    assert candidates[0]["resultDigest"] == result_digest
    attempt_digest = candidates[0]["implementationFollowupAttemptDigest"]
    assert attempt_digest != result_digest

    reserved = store.reserve_implementation_followup(
        thread_id="thread-1", result_digest=result_digest
    )
    assert reserved["implementationFollowupAttemptDigest"] == attempt_digest
    authorization = store.authorize_task_turn_delivery(
        delivery_kind="implementation-followup",
        thread_id="thread-1",
        delivery_token=result_digest,
        delivery_attempt_digest=attempt_digest,
    )
    assert authorization["deliveryAttemptDigest"] == attempt_digest
    store.commit_implementation_followup(
        thread_id="thread-1", result_digest=result_digest
    )
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )

    assert store.implementation_followup_candidates() == []
    with store.connect() as connection:
        repaired_count = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key='a/b#1'
                 AND event_type='IMPLEMENTATION_CONTEXT_REPAIRED'"""
        ).fetchone()[0]
        sent_count = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE opportunity_key='a/b#1'
                 AND event_type='IMPLEMENTATION_FOLLOWUP_SENT'"""
        ).fetchone()[0]
    assert repaired_count == 1
    assert sent_count == 2


def test_controller_normalizes_child_base_to_prepared_default_branch(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        base_branch="release-1.12.0",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["publication"]["baseBranch"] == "main"
    with store.connect() as connection:
        request = connection.execute(
            "SELECT request_json FROM publication_requests WHERE opportunity_key='a/b#1'"
        ).fetchone()
    assert json.loads(request["request_json"])["publication"]["baseBranch"] == "main"


def test_controller_commits_validated_child_patch_and_requests_publication(tmp_path):
    store, worktree, result_path = _controller_commit_result(tmp_path)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(result["publicationRequests"]) == 1
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert finalized["commitSha"] == run_git(worktree, "rev-parse", "HEAD")
    assert finalized["branch"] == "fix/1-runtime-boundary"
    assert run_git(worktree, "status", "--porcelain") == ""
    assert run_git(worktree, "show", "--pretty=format:", "--name-only", "HEAD") == "runtime.py"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "FIX_READY"
    )


def test_child_cannot_self_attest_independent_review(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(tmp_path, authenticated=False)
    monkeypatch.setattr(MODULE, "controller_review_result", lambda _root, _value: None)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["publicationRequests"] == []
    assert result["validationDeferred"] == [
        {
            "key": "a/b#1",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
            "missing": ["independent_review_passed"],
        }
    ]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["quality"]["independent_review_passed"] is False
    assert finalized["reproductionReceipt"]["bindingPurpose"] == "implementation-result-v1"
    assert finalized["reproductionReceipt"]["commitSha"] == finalized["commitSha"]
    assert finalized["reproductionReceipt"]["resultDigest"] == finalized["resultDigest"]
    assert store.publication_work_items() == []

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert listed["candidates"] == []
    assert listed["controllerReviewPending"][0]["reason"] == "CONTROLLER_REVIEW_PENDING"


def test_final_receipt_rebind_uses_current_valid_receipt_when_context_source_is_unavailable(
    tmp_path,
):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("independent_review_passed",),
    )
    candidate = store.task_result_candidates()[0]
    value = json.loads(result_path.read_text(encoding="utf-8"))
    original_digest = value["resultDigest"]
    value["quality"]["independent_review_passed"] = True
    value["independentReview"] = {
        "schemaVersion": "independent-review-v1",
        "verdict": "PASS",
        "summary": "The exact committed diff has no blocking finding.",
    }
    context = json.loads((result_path.parent / "task-context.json").read_text(encoding="utf-8"))
    context.pop("reproductionReceipt", None)
    context.pop("probeReceipt", None)

    with MODULE._task_worktree_private_descriptor(candidate) as result_access:
        finalized, _raw = MODULE._bind_final_reproduction_receipt(
            candidate=candidate,
            context=context,
            value=value,
            result_access=result_access,
        )

    assert finalized["resultDigest"] != original_digest
    assert finalized["reproductionReceipt"]["resultDigest"] == finalized["resultDigest"]
    assert finalized["reproductionReceipt"]["derivedFromReceiptDigest"]


def test_failed_controller_review_remains_an_actionable_followup(monkeypatch, tmp_path):
    _store, _worktree, result_path = _controller_commit_result(tmp_path, authenticated=False)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["tests"] = [
        {
            "command": "pnpm test",
            "exitCode": 127,
            "summary": "node_modules unavailable in the locked environment",
        }
    ]
    result_path.write_text(json.dumps(value), encoding="utf-8")
    review = {
        "verdict": "FAIL",
        "summary": "The integration path still forwards the stale payload.",
        "findings": [
            {
                "severity": "P1",
                "file": "runtime.py",
                "line": 1,
                "message": "The caller ignores the mutation.",
            }
        ],
        "evidence": ["The unchanged integration path bypasses the helper output."],
    }
    monkeypatch.setattr(MODULE, "controller_review_result", lambda _root, _value: review)

    ingested = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert ingested["validationDeferred"][0]["missing"] == ["independent_review_passed"]
    assert listed["controllerReviewPending"] == []
    assert listed["candidates"][0]["missing"] == ["independent_review_passed"]
    assert listed["environmentBlocked"] == []


def test_existing_fix_ready_result_accepts_later_controller_review(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(tmp_path)
    candidate = store.task_result_candidates()[0]
    context = json.loads((result_path.parent / "task-context.json").read_text(encoding="utf-8"))
    value = json.loads(result_path.read_text(encoding="utf-8"))
    finalized, _raw = _finalize_controller_commit_for_test(
        candidate=candidate,
        context=context,
        value=value,
        result_path=result_path,
    )
    finalized["quality"]["independent_review_passed"] = True
    controller_review = {
        "verdict": "PASS",
        "summary": "The exact committed change has no blocking finding.",
    }
    finalized["independentReview"] = controller_review
    result_path.write_text(json.dumps(finalized), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)
    store.record_stage("a/b#1", "FIX_READY", evidence=finalized["quality"])
    store.record_task_result_ingested("a/b#1", digest="previous-result", stage="FIX_READY")
    monkeypatch.setattr(MODULE, "controller_review_result", lambda _root, _value: controller_review)

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert len(result["publicationRequests"]) == 1
    assert json.loads(result_path.read_text(encoding="utf-8"))["independentReview"] == (
        controller_review
    )


def test_controller_policy_snapshot_satisfies_child_policy_quality(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
        controller_policy_complete=True,
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert len(result["publicationRequests"]) == 1
    assert result["validationDeferred"] == []
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["quality"]["policy_verified"] is True
    assert finalized["controllerPolicyVerification"] == {
        "source": "controller_live_audit",
        "capturedAt": finalized["controllerPolicyVerification"]["capturedAt"],
        "policyDigest": "d" * 64,
        "policyStatus": "NORMAL",
    }
    assert finalized["controllerPolicyVerification"]["capturedAt"]


def test_controller_policy_snapshot_recovers_an_existing_blocked_fix(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
        controller_policy_complete=True,
    )
    controller_verification = MODULE._controller_policy_verification
    monkeypatch.setattr(MODULE, "_controller_policy_verification", lambda _context: None)
    legacy_value = json.loads(result_path.read_text(encoding="utf-8"))
    legacy_value["quality"]["policy_verified"] = False
    legacy_value.pop("controllerPolicyVerification", None)
    result_path.write_text(json.dumps(legacy_value), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)

    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )["candidates"][0]
    MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
        )
    )
    blocked = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    monkeypatch.setattr(MODULE, "_controller_policy_verification", controller_verification)
    recovered_value = json.loads(result_path.read_text(encoding="utf-8"))
    recovered_context = json.loads(
        (result_path.parent / "task-context.json").read_text(encoding="utf-8")
    )
    recovered_value["quality"]["policy_verified"] = True
    recovered_value["controllerPolicyVerification"] = controller_verification(recovered_context)
    result_path.write_text(json.dumps(recovered_value), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)
    store.record_stage("a/b#1", "FIX_READY", evidence=recovered_value["quality"])
    MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=_worktree,
    )

    recovered = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first["validationDeferred"][0]["missing"] == ["policy_verified"]
    assert "publicationBlockedReason" in blocked["ingested"][0], blocked
    assert blocked["ingested"][0]["publicationBlockedReason"] == (
        "REPOSITORY_POLICY_EVIDENCE_REQUIRED"
    ), blocked
    assert len(recovered["publicationRequests"]) == 1
    assert recovered["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert json.loads(result_path.read_text(encoding="utf-8"))["quality"]["policy_verified"] is True
    request_id = recovered["publicationRequests"][0]["requestId"]
    request = store.publication_request(request_id)
    assert request is not None
    assert request["request"]["quality"]["policy_verified"] is True


def test_validation_followup_list_defers_ready_candidates_at_global_wip_limit(
    monkeypatch, tmp_path
):
    store, _worktree, _result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
    )
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert first["validationDeferred"][0]["missing"] == ["policy_verified"]
    monkeypatch.setattr(store, "active_task_count", lambda **_kwargs: 1)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setenv("RADAR_MAX_ACTIVE_TASKS", "1")

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["candidates"] == []
    assert len(listed["queuedDeferred"]) == 1
    assert listed["queuedDeferred"][0]["reason"] == "global_task_wip_limit"
    assert listed["queuedDeferred"][0]["activeTaskCount"] == 1
    assert listed["queuedDeferred"][0]["taskLimit"] == 1


def test_repaired_quality_rearms_same_blocked_publication_request(tmp_path):
    store, worktree, result_path = _controller_commit_result(tmp_path)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    request_id = first["publicationRequests"][0]["requestId"]
    request = store.publication_request(request_id)
    assert request is not None
    stale_quality = dict(request["request"]["quality"])
    stale_quality["policy_verified"] = False
    stale_request = dict(request["request"])
    stale_request["quality"] = stale_quality
    with store.connect() as connection:
        connection.execute(
            """UPDATE outcomes SET quality_json=? WHERE opportunity_key='a/b#1'""",
            (json.dumps(stale_quality),),
        )
        connection.execute(
            """UPDATE publication_requests
               SET status='BLOCKED',reason='SUBMIT_READY_EVIDENCE_INCOMPLETE',request_json=?
               WHERE request_id=?""",
            (json.dumps(stale_request), request_id),
        )
    store.record_stage(
        "a/b#1",
        "FIX_READY",
        evidence=request["request"]["quality"],
        dedupe_key="quality-repaired",
    )

    candidate = store.task_result_candidates()[0]
    value = json.loads(result_path.read_text(encoding="utf-8"))
    raw = result_path.read_bytes()
    with MODULE._task_worktree_private_descriptor(candidate) as result_access:
        repaired = MODULE._request_publication_from_task_result(
            store,
            candidate=candidate,
            result_access=result_access,
            value=value,
            raw=raw,
        )

    assert repaired["request_id"] == request_id
    assert repaired["status"] == "PENDING"
    assert repaired["request"]["quality"]["policy_verified"] is True
    assert store.publication_request(request_id)["reason"] is None


def test_completed_controller_review_rearms_same_blocked_publication_request(tmp_path):
    store, _worktree, result_path = _controller_commit_result(tmp_path)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    request_id = first["publicationRequests"][0]["requestId"]
    with store.connect() as connection:
        connection.execute(
            """UPDATE publication_requests
               SET status='BLOCKED',reason='CONTROLLER_INDEPENDENT_REVIEW_REQUIRED'
               WHERE request_id=?""",
            (request_id,),
        )

    candidate = store.task_result_candidates()[0]
    value = json.loads(result_path.read_text(encoding="utf-8"))
    raw = result_path.read_bytes()
    with MODULE._task_worktree_private_descriptor(candidate) as result_access:
        repaired = MODULE._request_publication_from_task_result(
            store,
            candidate=candidate,
            result_access=result_access,
            value=value,
            raw=raw,
        )

    assert repaired["request_id"] == request_id
    assert repaired["status"] == "PENDING"
    assert store.publication_request(request_id)["reason"] is None


def test_existing_policy_block_with_refreshed_context_stays_idempotent(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )["candidates"][0]
    MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
        )
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = result_path.parent / "task-context.json"
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["contextDigest"] = "refreshed-context"
    context_path.write_text(json.dumps(context), encoding="utf-8")

    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert repeated == {
        "ok": True,
        "ingested": [],
        "publicationRequests": [],
        "validationDeferred": [],
        "errors": [],
    }


def test_controller_creates_two_parent_commit_for_conflicted_pr_followup(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 'original'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    source.write_text("value = 'pull-request'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: preserve runtime")
    previous_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "main")
    source.write_text("value = 'upstream'\n", encoding="utf-8")
    (worktree / "base.py").write_text("base = True\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py", "base.py")
    run_git(worktree, "commit", "-m", "refactor: update runtime")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")

    result_path = tmp_path / "result.json"
    value = {
        "handoffMode": "controller_merge_required",
        "commitSha": None,
        "branch": "fix/1-runtime",
        "commitMessage": "merge: refresh runtime branch",
        "changedFiles": ["runtime.py"],
        "mergeBaseSha": base_sha,
        "resolutionSourceCommit": previous_head,
        "publication": {"baseBranch": "main"},
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")
    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context={
            "prFollowup": {
                "headSha": previous_head,
                "evidence": {
                    "mergeConflict": True,
                    "baseRefName": "main",
                    "baseSha": base_sha,
                },
            }
        },
        value=value,
        result_path=result_path,
    )

    assert finalized["handoffMode"] == "controller_merge_complete"
    assert finalized["mergeResolutionFiles"] == ["runtime.py"]
    assert finalized["controllerCommitChangedFiles"] == ["runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py"]
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        previous_head,
        base_sha,
    ]
    assert source.read_text(encoding="utf-8") == "value = 'pull-request'\n"
    assert run_git(worktree, "status", "--porcelain") == ""


def test_controller_merge_rejects_incomplete_conflict_file_set(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    for name in ("one.py", "two.py"):
        (worktree / name).write_text("value = 'original'\n", encoding="utf-8")
    run_git(worktree, "add", "one.py", "two.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    for name in ("one.py", "two.py"):
        (worktree / name).write_text("value = 'pull-request'\n", encoding="utf-8")
    run_git(worktree, "add", "one.py", "two.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    previous_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "main")
    for name in ("one.py", "two.py"):
        (worktree / name).write_text("value = 'upstream'\n", encoding="utf-8")
    run_git(worktree, "add", "one.py", "two.py")
    run_git(worktree, "commit", "-m", "refactor: runtime")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    value = {
        "handoffMode": "controller_merge_required",
        "branch": "fix/1-runtime",
        "commitMessage": "merge: refresh runtime branch",
        "changedFiles": ["one.py"],
        "mergeBaseSha": base_sha,
        "resolutionSourceCommit": previous_head,
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(RuntimeError, match="conflict set mismatch"):
        _finalize_controller_commit_for_test(
            candidate={"worktreePath": str(worktree)},
            context={
                "prFollowup": {
                    "headSha": previous_head,
                    "evidence": {"mergeConflict": True, "baseSha": base_sha},
                }
            },
            value=value,
            result_path=result_path,
        )

    assert run_git(worktree, "rev-parse", "HEAD") == previous_head
    assert run_git(worktree, "status", "--porcelain") == ""


def test_controller_merge_preserves_child_prepared_resolution(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    run_git(worktree, "init")
    run_git(worktree, "config", "user.name", "Test Contributor")
    run_git(worktree, "config", "user.email", "test@example.com")
    source = worktree / "runtime.py"
    source.write_text("value = 'original'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "chore: baseline")
    run_git(worktree, "branch", "-M", "main")
    run_git(worktree, "switch", "-c", "fix/1-runtime")
    source.write_text("value = 'pull-request'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "fix: runtime")
    previous_head = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "main")
    source.write_text("value = 'upstream'\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "-m", "refactor: runtime")
    base_sha = run_git(worktree, "rev-parse", "HEAD")
    run_git(worktree, "switch", "fix/1-runtime")
    source.write_text("value = 'combined-resolution'\n", encoding="utf-8")
    value = {
        "handoffMode": "controller_merge_required",
        "branch": "fix/1-runtime",
        "commitMessage": "merge: refresh runtime branch",
        "changedFiles": ["runtime.py"],
        "mergeBaseSha": base_sha,
    }
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(value), encoding="utf-8")

    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context={
            "prFollowup": {
                "headSha": previous_head,
                "evidence": {"mergeConflict": True, "baseSha": base_sha},
            }
        },
        value=value,
        result_path=result_path,
    )

    assert source.read_text(encoding="utf-8") == "value = 'combined-resolution'\n"
    assert finalized["previousCommitSha"] == previous_head
    assert finalized["mergeBaseSha"] == base_sha
    assert run_git(worktree, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [
        previous_head,
        base_sha,
    ]


def test_controller_keeps_ai_disclosure_fix_local_and_signs_dco(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
        publication_blocked_reason="AI_DISCLOSURE_REQUIRED",
        dco_required=True,
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["publicationRequests"] == []
    assert result["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "FIX_READY",
            "publicationBlockedReason": "AI_DISCLOSURE_REQUIRED",
        }
    ]
    assert "Signed-off-by: Test Contributor <test@example.com>" in run_git(
        worktree, "show", "-s", "--format=%B", "HEAD"
    )
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert store.publication_work_items() == []


def test_controller_stops_policy_only_validation_after_one_followup(tmp_path):
    store, _worktree, _result_path = _controller_commit_result(
        tmp_path,
        policy_verified=False,
    )

    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert first["validationDeferred"][0]["missing"] == ["policy_verified"]
    candidate = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )["candidates"][0]
    MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=candidate["resultDigest"],
        )
    )

    reconciled = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert reconciled["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "FIX_READY",
            "publicationBlockedReason": "REPOSITORY_POLICY_EVIDENCE_REQUIRED",
        }
    ]
    assert reconciled["publicationRequests"] == []
    assert (
        MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))[
            "candidates"
        ]
        == []
    )


def test_controller_defers_blocked_local_fix_with_incomplete_validation(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
        publication_blocked_reason="AI_DISCLOSURE_REQUIRED",
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["validationDeferred"] == [
        {
            "key": "a/b#1",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
            "missing": ["regression_test_verified", "relevant_tests_green"],
        }
    ]
    assert result["publicationRequests"] == []
    assert result["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
        }
    ]
    with store.connect() as connection:
        event = connection.execute(
            """SELECT payload_json FROM events
               WHERE event_type='TASK_RESULT_VALIDATION_DEFERRED'"""
        ).fetchone()
    assert json.loads(event["payload_json"])["missing"] == [
        "regression_test_verified",
        "relevant_tests_green",
    ]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "VALIDATION_PENDING"
    )
    assert store.task_result_candidates()[0]["stage"] == "VALIDATION_PENDING"
    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert repeated["ingested"] == []

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert listed["ok"] is True
    assert listed["unresolved"] == []
    assert listed["stale"] == []
    assert listed["errors"] == []
    assert listed["candidates"][0]["threadId"] == "thread-1"
    assert listed["candidates"][0]["missing"] == [
        "regression_test_verified",
        "relevant_tests_green",
    ]
    assert listed["candidates"][0]["prefetchRequired"] is False
    assert listed["candidates"][0]["prefetchMode"] == "none"
    assert listed["candidates"][0]["nextOperation"] == "validation-followup-reserve"
    assert "prefetchCommands" not in listed["candidates"][0]

    digest = listed["candidates"][0]["resultDigest"]
    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
            prefetch_complete=False,
        )
    )
    assert reserved["ok"] is True
    assert "回归测试证据还不完整" in reserved["prompt"]
    assert "和这次修改直接相关的检查还没全部通过" in reserved["prompt"]
    assert "regression_test_verified" not in reserved["prompt"]
    assert "relevant_tests_green" not in reserved["prompt"]
    assert (
        MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))[
            "unresolved"
        ][0]["resultDigest"]
        == digest
    )

    MODULE.validation_followup_commit(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
        )
    )
    final_list = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )
    assert final_list["candidates"] == []
    assert final_list["unresolved"] == []
    assert final_list["stale"] == []

    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_SENT'""",
            (iso_z(datetime.now(UTC) - timedelta(hours=3)),),
        )
    stalled = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )
    assert stalled["ok"] is False
    assert stalled["stale"][0]["threadId"] == "thread-1"


def test_validation_followup_reserve_rejects_result_changed_after_reservation(
    monkeypatch, tmp_path
):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    assert MODULE._task_result_path(candidate) == result_path
    original_reserve = RadarLedger.reserve_validation_followup
    mutation_started = threading.Event()
    mutation_finished = threading.Event()
    attempt_files: list[Path] = []
    state = bind_validation_runtime(monkeypatch, tmp_path)

    def mutate_result_after_reservation():
        assert mutation_started.wait(2)
        value = json.loads(result_path.read_text(encoding="utf-8"))
        value["tests"] = [{"command": "pytest changed after queue", "exitCode": 0}]
        result_path.write_text(json.dumps(value), encoding="utf-8")
        mutation_finished.set()

    writer = threading.Thread(target=mutate_result_after_reservation)

    def reserve_and_race(instance, **kwargs):
        reserved = original_reserve(instance, **kwargs)
        receipt_root = state / "task_turn_receipts"
        receipt_root.mkdir(parents=True, exist_ok=True)
        receipt_key = MODULE._task_turn_delivery_file_key(
            delivery_kind="validation-followup",
            thread_id=candidate["threadId"],
            delivery_token=candidate["resultDigest"],
            validation_reservation_digest=reserved["reservationDigest"],
        )
        attempt_files.extend(
            [
                receipt_root / f"{receipt_key}.json",
                receipt_root / f"{receipt_key}.launch.json",
                receipt_root / f"{receipt_key}.log",
            ]
        )
        attempt_files[0].write_text(
            json.dumps(
                {
                    "ok": False,
                    "turnStarted": False,
                    "reservationDigest": reserved["reservationDigest"],
                }
            ),
            encoding="utf-8",
        )
        attempt_files[1].write_text(json.dumps({"pid": 0}), encoding="utf-8")
        attempt_files[2].write_text("cancelled attempt", encoding="utf-8")
        writer.start()
        mutation_started.set()
        assert mutation_finished.wait(2)
        writer.join(timeout=2)
        return reserved

    monkeypatch.setattr(RadarLedger, "reserve_validation_followup", reserve_and_race)
    result = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )

    assert result.get("deferred") is True, result
    assert result["reason"] == "VALIDATION_RESULT_CHANGED_AFTER_QUEUE"
    assert store.unresolved_validation_followups() == []
    assert store.active_task_count() == 0
    assert attempt_files
    assert all(not path.exists() for path in attempt_files)
    with store.connect() as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM events WHERE event_type='VALIDATION_FOLLOWUP_SENT'"
            ).fetchone()
            is None
        )
    with pytest.raises(RuntimeError, match="task-turn delivery reservation is unavailable"):
        MODULE.validation_followup_deliver(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )


def test_validation_followup_delivery_rechecks_result_before_starting_worker(monkeypatch, tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    assert reserved["ok"] is True

    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text("", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads ("
            "id TEXT, cwd TEXT, archived INTEGER, first_user_message TEXT, "
            "rollout_path TEXT, git_origin_url TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?)",
            (
                candidate["threadId"],
                str(worktree),
                0,
                MODULE.issue_prompt(candidate["issueUrl"]),
                str(rollout),
                "https://github.com/a/b.git",
            ),
        )

    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["tests"] = [{"command": "pytest changed before delivery", "exitCode": 0}]
    result_path.write_text(json.dumps(value), encoding="utf-8")

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    bind_validation_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "a changed validation result must not start a worker"
        ),
    )

    result = MODULE.validation_followup_deliver(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
        )
    )

    assert result["deferred"] is True
    assert result["reason"] == "VALIDATION_RESULT_CHANGED_BEFORE_SNAPSHOT"
    assert store.unresolved_validation_followups() == []
    assert store.active_task_count() == 0
    assert rollout.read_text(encoding="utf-8") == ""
    assert list((tmp_path / "state" / "task_turn_receipts").glob("*.launch.json")) == []


class _FakeTaskTurnStdin:
    def __init__(self):
        self.writes: list[bytes] = []

    def write(self, value: bytes) -> None:
        self.writes.append(value)

    def flush(self) -> None:
        return None


class _FakeTaskTurnProcess:
    def __init__(self):
        self.stdin = _FakeTaskTurnStdin()
        self.stdout = object()

    @staticmethod
    def poll():
        return 0


class _FakeTaskTurnSelector:
    def register(self, *_args, **_kwargs) -> None:
        return None

    def close(self) -> None:
        return None


def _bound_validation_worker_fixture(monkeypatch, tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path, missing_quality=("relevant_tests_green",)
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    candidate = next(
        item
        for item in store.unresolved_validation_followups()
        if item["reservationDigest"] == reserved["reservationDigest"]
    )
    bind_validation_runtime(monkeypatch, tmp_path)
    thread_db = tmp_path / "validation-threads.sqlite3"
    rollout = tmp_path / "validation-rollout.jsonl"
    rollout.write_text("", encoding="utf-8")
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads ("
            "id TEXT, cwd TEXT, archived INTEGER, first_user_message TEXT, "
            "rollout_path TEXT, git_origin_url TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?)",
            (
                candidate["threadId"],
                str(worktree),
                0,
                MODULE.issue_prompt(candidate["issueUrl"]),
                str(rollout),
                "https://github.com/a/b.git",
            ),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    original_live_bytes = result_path.read_bytes()
    reservation_digest = str(candidate["reservationDigest"])
    snapshot = MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)
    binding = {
        "reservationDigest": reservation_digest,
        "snapshotId": str(snapshot["snapshotId"]),
        "snapshotPath": str(snapshot["snapshotPath"]),
        "snapshotDigest": str(snapshot["snapshotDigest"]),
        **MODULE._validation_worktree_input_binding(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_digest=str(snapshot["snapshotDigest"]),
        ),
        "resultDigest": str(candidate["resultDigest"]),
    }
    store.authorize_task_turn_delivery(
        delivery_kind="validation-followup",
        thread_id=str(candidate["threadId"]),
        delivery_token=str(candidate["resultDigest"]),
        reservation_digest=reservation_digest,
        snapshot_id=binding["snapshotId"],
        snapshot_path=binding["snapshotPath"],
        snapshot_digest=binding["snapshotDigest"],
        worktree_input_path=binding["worktreeInputPath"],
        worktree_input_digest=binding["worktreeInputDigest"],
    )
    args = SimpleNamespace(
        ledger=tmp_path / "ledger.sqlite3",
        delivery_kind="validation-followup",
        thread_id=str(candidate["threadId"]),
        delivery_token=str(candidate["resultDigest"]),
        reservation_digest=reservation_digest,
        snapshot_id=binding["snapshotId"],
        snapshot_path=binding["snapshotPath"],
        snapshot_digest=binding["snapshotDigest"],
        worktree_input_path=binding["worktreeInputPath"],
        worktree_input_digest=binding["worktreeInputDigest"],
        receipt=str(tmp_path / "task-turn-receipt.json"),
    )
    return (
        store,
        candidate | binding,
        worktree,
        result_path,
        original_live_bytes,
        binding,
        args,
    )


def _task_turn_messages(process: _FakeTaskTurnProcess) -> list[dict[str, object]]:
    return [
        json.loads(line) for write in process.stdin.writes for line in write.splitlines() if line
    ]


def test_validation_attempt_scopes_delivery_files_and_client_id_but_not_worker_lock(
    monkeypatch, tmp_path
):
    (
        store,
        candidate,
        worktree,
        _result_path,
        _original_live_bytes,
        first_binding,
        _args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)
    result_digest = str(candidate["resultDigest"])
    first_reservation = str(first_binding["reservationDigest"])
    state = MODULE.STATE
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True, exist_ok=True)

    first_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id=str(candidate["threadId"]),
        delivery_token=result_digest,
        validation_reservation_digest=first_reservation,
    )
    first_paths = [
        receipt_root / f"{first_key}.json",
        receipt_root / f"{first_key}.launch.json",
        receipt_root / f"{first_key}.log",
    ]
    first_paths[0].write_text(
        json.dumps(
            {
                "ok": False,
                "turnStarted": False,
                "reservationDigest": first_reservation,
            }
        ),
        encoding="utf-8",
    )
    first_paths[1].write_text(
        json.dumps({"pid": 0, "reservationDigest": first_reservation}),
        encoding="utf-8",
    )
    first_paths[2].write_text("attempt one", encoding="utf-8")

    with store.connect() as connection:
        connection.execute(
            """UPDATE events SET created_at=?
               WHERE event_type='VALIDATION_FOLLOWUP_RESERVED'
                 AND dedupe_key=?""",
            (
                iso_z(datetime.now(UTC) - timedelta(minutes=2)),
                first_reservation,
            ),
        )
    store.abandon_validation_followup_delivery(
        thread_id=str(candidate["threadId"]),
        result_digest=result_digest,
        reason="TARGET_TURN_OUTCOME_UNKNOWN",
        min_age_minutes=1,
    )
    MODULE._discard_negative_task_turn_receipt(
        delivery_kind="validation-followup",
        thread_id=str(candidate["threadId"]),
        delivery_token=result_digest,
        validation_reservation_digest=first_reservation,
    )
    assert all(not path.exists() for path in first_paths)

    second = store.reserve_validation_followup(
        thread_id=str(candidate["threadId"]), result_digest=result_digest
    )
    second_reservation = str(second["reservationDigest"])
    assert second_reservation != first_reservation
    second_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id=str(candidate["threadId"]),
        delivery_token=result_digest,
        validation_reservation_digest=second_reservation,
    )
    assert second_key != first_key

    for path, content in zip(
        first_paths,
        (
            json.dumps(
                {
                    "ok": False,
                    "turnStarted": False,
                    "reservationDigest": first_reservation,
                }
            ),
            json.dumps({"pid": 0, "reservationDigest": first_reservation}),
            "orphaned attempt one",
        ),
        strict=True,
    ):
        path.write_text(content, encoding="utf-8")
    assert (
        MODULE.retryable_negative_task_turn_receipt(
            delivery_kind="validation-followup",
            thread_id=str(candidate["threadId"]),
            delivery_token=result_digest,
            validation_reservation_digest=second_reservation,
        )
        is None
    )
    MODULE._discard_negative_task_turn_receipt(
        delivery_kind="validation-followup",
        thread_id=str(candidate["threadId"]),
        delivery_token=result_digest,
        validation_reservation_digest=second_reservation,
    )
    assert all(path.exists() for path in first_paths)

    active_worker = {
        "pid": 123,
        "deliveryKind": "validation-followup",
        "reservationDigest": first_reservation,
    }
    monkeypatch.setattr(
        MODULE,
        "active_task_turn_worker",
        lambda thread_id: active_worker if thread_id == str(candidate["threadId"]) else None,
    )
    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "a second attempt must not bypass the thread-global worker lock"
        ),
    )
    blocked = MODULE.task_turn_deliver(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            delivery_kind="validation-followup",
            delivery_token=result_digest,
            thread_id=str(candidate["threadId"]),
        )
    )
    assert blocked["pending"] is True
    assert blocked["reason"] == "TASK_TURN_WORKER_ACTIVE"
    assert blocked["worker"]["reservationDigest"] == first_reservation

    first_process = _FakeTaskTurnProcess()
    second_process = _FakeTaskTurnProcess()
    for process, reservation in (
        (first_process, first_reservation),
        (second_process, second_reservation),
    ):
        MODULE._write_turn_start_request(
            process,
            thread_id=str(candidate["threadId"]),
            cwd=worktree,
            prompt="continue validation",
            delivery_kind="validation-followup",
            delivery_token=result_digest,
            validation_reservation_digest=reservation,
        )
    first_id = _task_turn_messages(first_process)[0]["params"]["clientUserMessageId"]
    second_id = _task_turn_messages(second_process)[0]["params"]["clientUserMessageId"]
    assert first_id != second_id
    assert str(first_id).endswith(first_reservation)
    assert str(second_id).endswith(second_reservation)


def test_validation_worker_projects_snapshot_and_sends_exact_local_input_prompt(
    monkeypatch, tmp_path
):
    (
        store,
        candidate,
        worktree,
        result_path,
        original_live_bytes,
        binding,
        args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)
    changed = json.loads(result_path.read_text(encoding="utf-8"))
    changed["tests"] = [{"command": "changed after binding", "exitCode": 0}]
    result_path.write_text(json.dumps(changed), encoding="utf-8")
    process = _FakeTaskTurnProcess()

    @contextmanager
    def action_session(*_args, **_kwargs):
        yield process

    def read_response(_process, _selector, buffer, *, response_id, **_kwargs):
        if response_id == 1:
            return buffer, {"result": {"thread": {"id": candidate["threadId"]}}}
        return buffer, {"result": {"turn": {"id": "turn-1"}}}

    monkeypatch.setattr(MODULE, "_app_server_action_session", action_session)
    monkeypatch.setattr(MODULE.selectors, "DefaultSelector", _FakeTaskTurnSelector)
    monkeypatch.setattr(MODULE, "_read_app_server_response", read_response)
    monkeypatch.setattr(
        MODULE,
        "_wait_for_app_server_terminal_turn",
        lambda *_args, **_kwargs: {"turnId": "turn-1", "status": "completed"},
    )
    monkeypatch.setattr(MODULE.shutil, "which", lambda _name: "/usr/bin/codex")

    result = MODULE._app_server_task_turn_worker(args)

    projection = worktree / binding["worktreeInputPath"]
    assert projection.read_bytes() == original_live_bytes
    assert projection.read_bytes() != result_path.read_bytes()
    assert stat.S_IMODE(projection.stat().st_mode) == 0o400
    assert stat.S_IMODE(projection.parent.stat().st_mode) == 0o700
    turns = [item for item in _task_turn_messages(process) if item.get("method") == "turn/start"]
    assert len(turns) == 1
    prompt = turns[0]["params"]["input"][0]["text"]
    assert f"`{binding['worktreeInputPath']}`" in prompt
    assert "不要读取当前 `.oss-pr-radar/result.json` 作为本轮输入" in prompt
    assert str(MODULE.STATE) not in prompt
    assert result["ok"] is True
    assert store.unresolved_validation_followups() == []


@pytest.mark.parametrize("mutation", ["missing", "tampered", "symlink"])
def test_validation_worker_rejects_projection_changed_before_turn_start(
    monkeypatch, tmp_path, mutation
):
    (
        store,
        candidate,
        worktree,
        _result_path,
        _original_live_bytes,
        binding,
        args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)
    process = _FakeTaskTurnProcess()
    original_prompt = MODULE._task_turn_prompt

    def prompt_then_change(delivery_kind, prompt_candidate):
        prompt = original_prompt(delivery_kind, prompt_candidate)
        projection = worktree / binding["worktreeInputPath"]
        if mutation == "missing":
            projection.unlink()
        elif mutation == "tampered":
            projection.chmod(0o600)
            projection.write_text('{"resultDigest":"changed"}', encoding="utf-8")
            projection.chmod(0o400)
        else:
            target = tmp_path / "validation-input-target.json"
            target.write_bytes(projection.read_bytes())
            projection.unlink()
            projection.symlink_to(target)
        return prompt

    @contextmanager
    def action_session(*_args, **_kwargs):
        yield process

    def read_response(_process, _selector, buffer, *, response_id, **_kwargs):
        assert response_id == 1
        return buffer, {"result": {"thread": {"id": candidate["threadId"]}}}

    monkeypatch.setattr(MODULE, "_task_turn_prompt", prompt_then_change)
    monkeypatch.setattr(MODULE, "_app_server_action_session", action_session)
    monkeypatch.setattr(MODULE.selectors, "DefaultSelector", _FakeTaskTurnSelector)
    monkeypatch.setattr(MODULE, "_read_app_server_response", read_response)
    monkeypatch.setattr(MODULE.shutil, "which", lambda _name: "/usr/bin/codex")

    with pytest.raises(RuntimeError):
        MODULE._app_server_task_turn_worker(args)

    assert all(item.get("method") != "turn/start" for item in _task_turn_messages(process))
    assert (
        store.unresolved_validation_followups()[0]["reservationDigest"]
        == binding["reservationDigest"]
    )


def test_validation_worker_popen_retry_restores_projection_from_state_snapshot(
    monkeypatch, tmp_path
):
    (
        _store,
        _candidate,
        worktree,
        result_path,
        original_live_bytes,
        binding,
        args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)

    @contextmanager
    def failed_action_session(*_args, **_kwargs):
        raise RuntimeError("popen failed")
        yield

    monkeypatch.setattr(MODULE, "_app_server_action_session", failed_action_session)
    monkeypatch.setattr(MODULE.selectors, "DefaultSelector", _FakeTaskTurnSelector)
    monkeypatch.setattr(MODULE.shutil, "which", lambda _name: "/usr/bin/codex")

    with pytest.raises(RuntimeError, match="popen failed"):
        MODULE._app_server_task_turn_worker(args)
    projection = worktree / binding["worktreeInputPath"]
    assert projection.read_bytes() == original_live_bytes

    projection.unlink()
    changed = json.loads(result_path.read_text(encoding="utf-8"))
    changed["tests"] = [{"command": "changed before retry", "exitCode": 0}]
    result_path.write_text(json.dumps(changed), encoding="utf-8")
    monkeypatch.setattr(
        MODULE,
        "_task_result_path",
        lambda _candidate: pytest.fail("snapshot-backed retry must not read live result.json"),
    )

    with pytest.raises(RuntimeError, match="popen failed"):
        MODULE._app_server_task_turn_worker(args)
    assert projection.read_bytes() == original_live_bytes
    assert stat.S_IMODE(projection.stat().st_mode) == 0o400


def test_validation_worktree_input_path_cannot_escape_worktree(monkeypatch, tmp_path):
    (
        _store,
        candidate,
        _worktree,
        _result_path,
        _original_live_bytes,
        binding,
        _args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="validation worktree input binding is invalid"):
        MODULE._ensure_validation_worktree_input(
            candidate=candidate,
            reservation_digest=binding["reservationDigest"],
            snapshot_id=binding["snapshotId"],
            snapshot_path=binding["snapshotPath"],
            snapshot_digest=binding["snapshotDigest"],
            worktree_input_path=".oss-pr-radar/validation-inputs/../../result.json",
            worktree_input_digest=binding["worktreeInputDigest"],
        )
    assert not (tmp_path / "result.json").exists()


def _replace_validation_private_dir_after_binding(
    *,
    worktree: Path,
    replacement_private: Path,
    replacement_kind: str,
) -> Path:
    private_dir = worktree / MODULE.TASK_PRIVATE_DIR
    original_private = worktree / f"{MODULE.TASK_PRIVATE_DIR}.original"
    private_dir.rename(original_private)
    if replacement_kind == "symlink":
        private_dir.symlink_to(replacement_private, target_is_directory=True)
    else:
        replacement_private.rename(private_dir)
    return original_private


def _replace_validation_worktree_parent_after_binding(
    *,
    parent: Path,
    replacement_parent: Path,
    replacement_kind: str,
) -> Path:
    original_parent = parent.with_name(f"{parent.name}.original")
    parent.rename(original_parent)
    if replacement_kind == "symlink":
        parent.symlink_to(replacement_parent, target_is_directory=True)
    else:
        replacement_parent.rename(parent)
    return original_parent


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_worktree_input_read_fails_if_private_parent_is_replaced(
    monkeypatch, tmp_path, replacement_kind
):
    (
        _store,
        candidate,
        worktree,
        _result_path,
        original_live_bytes,
        binding,
        _args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)
    MODULE._ensure_validation_worktree_input(
        candidate=candidate,
        reservation_digest=binding["reservationDigest"],
        snapshot_id=binding["snapshotId"],
        snapshot_path=binding["snapshotPath"],
        snapshot_digest=binding["snapshotDigest"],
        worktree_input_path=binding["worktreeInputPath"],
        worktree_input_digest=binding["worktreeInputDigest"],
    )
    replacement_private = tmp_path / f"read-{replacement_kind}-private"
    replacement_root = replacement_private / "validation-inputs"
    replacement_root.mkdir(parents=True)
    replacement_root.chmod(0o700)
    replacement_file = replacement_root / f"{binding['reservationDigest']}.json"
    replacement_file.write_bytes(original_live_bytes)
    replacement_file.chmod(0o400)
    original_require = MODULE._require_validation_worktree_input_root_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_private_dir_after_binding(
                worktree=worktree,
                replacement_private=replacement_private,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(
        MODULE, "_require_validation_worktree_input_root_binding", require_then_swap
    )

    with pytest.raises(RuntimeError, match="private directory is unsafe"):
        MODULE._validation_worktree_input_bytes(
            candidate=candidate,
            reservation_digest=binding["reservationDigest"],
            worktree_input_path=binding["worktreeInputPath"],
            worktree_input_digest=binding["worktreeInputDigest"],
        )
    assert swapped is True
    visible_replacement_file = (
        worktree / MODULE.TASK_PRIVATE_DIR / "validation-inputs" / replacement_file.name
        if replacement_kind == "different-inode"
        else replacement_file
    )
    assert visible_replacement_file.read_bytes() == original_live_bytes


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_worktree_input_write_fails_if_private_parent_is_replaced(
    monkeypatch, tmp_path, replacement_kind
):
    (
        _store,
        candidate,
        worktree,
        _result_path,
        _original_live_bytes,
        binding,
        _args,
    ) = _bound_validation_worker_fixture(monkeypatch, tmp_path)
    replacement_private = tmp_path / f"write-{replacement_kind}-private"
    replacement_root = replacement_private / "validation-inputs"
    replacement_root.mkdir(parents=True)
    replacement_root.chmod(0o700)
    original_require = MODULE._require_validation_worktree_input_root_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_private_dir_after_binding(
                worktree=worktree,
                replacement_private=replacement_private,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(
        MODULE, "_require_validation_worktree_input_root_binding", require_then_swap
    )

    with pytest.raises(RuntimeError, match="private directory is unsafe"):
        MODULE._ensure_validation_worktree_input(
            candidate=candidate,
            reservation_digest=binding["reservationDigest"],
            snapshot_id=binding["snapshotId"],
            snapshot_path=binding["snapshotPath"],
            snapshot_digest=binding["snapshotDigest"],
            worktree_input_path=binding["worktreeInputPath"],
            worktree_input_digest=binding["worktreeInputDigest"],
        )
    assert swapped is True
    visible_replacement_root = (
        worktree / MODULE.TASK_PRIVATE_DIR / "validation-inputs"
        if replacement_kind == "different-inode"
        else replacement_root
    )
    assert list(visible_replacement_root.iterdir()) == []


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_worktree_input_write_fails_if_worktree_parent_is_replaced(
    monkeypatch, tmp_path, replacement_kind
):
    parent = tmp_path / "projection-original-parent"
    worktree = parent / "worktree"
    result_path = worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    bind_validation_runtime(monkeypatch, tmp_path)
    reservation_digest = "9" * 64
    snapshot = MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)
    binding = {
        "reservationDigest": reservation_digest,
        **snapshot,
        **MODULE._validation_worktree_input_binding(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_digest=str(snapshot["snapshotDigest"]),
        ),
    }
    replacement_parent = tmp_path / f"projection-parent-{replacement_kind}"
    replacement_worktree = replacement_parent / worktree.name
    replacement_private = replacement_worktree / MODULE.TASK_PRIVATE_DIR
    replacement_private.mkdir(parents=True)
    replacement_root = replacement_private / "validation-inputs"
    replacement_root.mkdir(mode=0o700)
    original_require = MODULE._require_validation_worktree_input_root_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_worktree_parent_after_binding(
                parent=parent,
                replacement_parent=replacement_parent,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(
        MODULE, "_require_validation_worktree_input_root_binding", require_then_swap
    )

    with pytest.raises(RuntimeError, match="validation worktree parent is unsafe"):
        MODULE._ensure_validation_worktree_input(
            candidate=candidate,
            reservation_digest=binding["reservationDigest"],
            snapshot_id=binding["snapshotId"],
            snapshot_path=binding["snapshotPath"],
            snapshot_digest=binding["snapshotDigest"],
            worktree_input_path=binding["worktreeInputPath"],
            worktree_input_digest=binding["worktreeInputDigest"],
        )
    assert swapped is True
    visible_replacement_root = (
        parent / worktree.name / MODULE.TASK_PRIVATE_DIR / "validation-inputs"
        if replacement_kind == "different-inode"
        else replacement_root
    )
    assert list(visible_replacement_root.iterdir()) == []


def test_validation_snapshot_is_immutable_across_bind_and_popen_retry(monkeypatch, tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path, missing_quality=("relevant_tests_green",)
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    reservation_digest = reserved["reservationDigest"]
    original_live_bytes = result_path.read_bytes()
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text("", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads ("
            "id TEXT, cwd TEXT, archived INTEGER, first_user_message TEXT, "
            "rollout_path TEXT, git_origin_url TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?)",
            (
                candidate["threadId"],
                str(worktree),
                0,
                MODULE.issue_prompt(candidate["issueUrl"]),
                str(rollout),
                "https://github.com/a/b.git",
            ),
        )

    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    bind_validation_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)

    def fail_popen(*_args, **_kwargs):
        raise RuntimeError("popen failed")

    monkeypatch.setattr(MODULE.subprocess, "Popen", fail_popen)

    original_snapshot = MODULE._ensure_validation_snapshot
    mutate_before_bind = {"done": False}

    def snapshot_then_mutate(candidate_value, *, reservation_digest):
        snapshot = original_snapshot(candidate_value, reservation_digest=reservation_digest)
        if not mutate_before_bind["done"]:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            value["tests"] = [{"command": "changed after snapshot", "exitCode": 0}]
            result_path.write_text(json.dumps(value), encoding="utf-8")
            mutate_before_bind["done"] = True
        return snapshot

    monkeypatch.setattr(MODULE, "_ensure_validation_snapshot", snapshot_then_mutate)
    with pytest.raises(RuntimeError, match="popen failed"):
        MODULE.validation_followup_deliver(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )

    snapshot_path = tmp_path / "state" / "validation-inputs" / f"{reservation_digest}.json"
    assert snapshot_path.read_bytes() == original_live_bytes
    assert stat.S_IMODE(snapshot_path.stat().st_mode) == 0o400
    binding = store.validation_followup_delivery_binding(
        thread_id=candidate["threadId"],
        result_digest=candidate["resultDigest"],
        reservation_digest=reservation_digest,
    )
    assert binding is not None
    assert binding["snapshotPath"] == f"validation-inputs/{reservation_digest}.json"
    assert binding["worktreeInputPath"] == (
        f".oss-pr-radar/validation-inputs/{reservation_digest}.json"
    )
    assert binding["worktreeInputDigest"] == binding["snapshotDigest"]
    assert store.unresolved_validation_followups()[0]["reservationDigest"] == reservation_digest

    monkeypatch.setattr(
        MODULE,
        "_task_result_path",
        lambda _candidate: pytest.fail("retry must not read live result.json"),
    )
    with pytest.raises(RuntimeError, match="popen failed"):
        MODULE.validation_followup_deliver(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )
    assert (
        store.validation_followup_delivery_binding(
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
            reservation_digest=reservation_digest,
        )
        == binding
    )


def test_validation_snapshot_tamper_does_not_start_or_cancel_bound_turn(monkeypatch, tmp_path):
    store, worktree, _result_path = _controller_commit_result(
        tmp_path, missing_quality=("relevant_tests_green",)
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id=candidate["threadId"],
            result_digest=candidate["resultDigest"],
            prefetch_complete=False,
        )
    )
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text("", encoding="utf-8")
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT, cwd TEXT, archived INTEGER, "
            "first_user_message TEXT, rollout_path TEXT, git_origin_url TEXT)"
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?)",
            (
                candidate["threadId"],
                str(worktree),
                0,
                MODULE.issue_prompt(candidate["issueUrl"]),
                str(rollout),
                "https://github.com/a/b.git",
            ),
        )
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path)
    bind_validation_runtime(monkeypatch, tmp_path)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("tampered snapshot must not start a worker"),
    )

    original_authorize = store.authorize_task_turn_delivery

    def authorize_then_tamper(**kwargs):
        result = original_authorize(**kwargs)
        snapshot = MODULE.STATE / kwargs["snapshot_path"]
        snapshot.chmod(0o600)
        return result

    monkeypatch.setattr(store, "authorize_task_turn_delivery", authorize_then_tamper)
    with pytest.raises(RuntimeError, match="validation snapshot permissions are unsafe"):
        MODULE.validation_followup_deliver(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id=candidate["threadId"],
                result_digest=candidate["resultDigest"],
            )
        )
    assert (
        store.unresolved_validation_followups()[0]["reservationDigest"]
        == reserved["reservationDigest"]
    )


def test_validation_snapshot_same_reservation_converges_to_one_file(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    bind_validation_runtime(monkeypatch, tmp_path)
    reservation_digest = "a" * 64

    with ThreadPoolExecutor(max_workers=4) as executor:
        bindings = list(
            executor.map(
                lambda _index: MODULE._ensure_validation_snapshot(
                    candidate, reservation_digest=reservation_digest
                ),
                range(4),
            )
        )

    assert {item["snapshotId"] for item in bindings} == {reservation_digest}
    assert len(list((tmp_path / "state" / "validation-inputs").glob("*.json"))) == 1


def test_validation_snapshot_rejects_missing_path_mode_and_digest(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    bind_validation_runtime(monkeypatch, tmp_path)
    reservation_digest = "b" * 64
    binding = MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)
    snapshot = tmp_path / "state" / "validation-inputs" / f"{reservation_digest}.json"

    with pytest.raises(RuntimeError, match="validation snapshot path is invalid"):
        MODULE._validation_snapshot_metadata(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_id=reservation_digest,
            snapshot_path="validation-inputs/../result.json",
            snapshot_digest=binding["snapshotDigest"],
        )

    snapshot.unlink()
    with pytest.raises(RuntimeError, match="validation snapshot is missing"):
        MODULE._validation_snapshot_metadata(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_id=reservation_digest,
            snapshot_path=binding["snapshotPath"],
            snapshot_digest=binding["snapshotDigest"],
        )

    MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)
    snapshot.chmod(0o600)
    with pytest.raises(RuntimeError, match="validation snapshot permissions are unsafe"):
        MODULE._validation_snapshot_metadata(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_id=reservation_digest,
            snapshot_path=binding["snapshotPath"],
            snapshot_digest=binding["snapshotDigest"],
        )

    snapshot.chmod(0o400)
    with pytest.raises(RuntimeError, match="validation snapshot digest mismatch"):
        MODULE._validation_snapshot_metadata(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_id=reservation_digest,
            snapshot_path=binding["snapshotPath"],
            snapshot_digest="c" * 64,
        )


def test_validation_snapshot_symlink_is_rejected_before_target_read(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    bind_validation_runtime(monkeypatch, tmp_path)
    reservation_digest = "d" * 64
    MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)
    snapshot = tmp_path / "state" / "validation-inputs" / f"{reservation_digest}.json"
    target = tmp_path / "target.json"
    target.write_bytes(snapshot.read_bytes())
    snapshot.unlink()
    snapshot.symlink_to(target)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _path: pytest.fail("validation snapshot must not read through a symlink"),
    )

    with pytest.raises(RuntimeError, match="validation snapshot permissions are unsafe"):
        MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)


def test_validation_live_result_chain_never_follows_a_symlink(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    private = worktree / ".oss-pr-radar"
    private.mkdir(parents=True)
    target = tmp_path / "outside-result.json"
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    target.write_bytes(raw)
    result_path = private / "result.json"
    result_path.symlink_to(target)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
        "missing": ["relevant_tests_green"],
    }
    bind_validation_runtime(monkeypatch, tmp_path)

    operations = (
        lambda: MODULE._validation_prefetch_plan(candidate),
        lambda: MODULE._validation_result_digest(candidate),
        lambda: MODULE._validation_policy_reassessment_needed(candidate),
        lambda: MODULE._ensure_validation_snapshot(candidate, reservation_digest="e" * 64),
    )
    for operation in operations:
        with pytest.raises(RuntimeError, match="validation result permissions are unsafe"):
            operation()
    assert target.read_bytes() == raw
    assert list((tmp_path / "state").rglob("*.json")) == []


def test_validation_live_result_rejects_dangerous_mode_and_wrong_owner(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }

    result_path.chmod(0o666)
    with pytest.raises(RuntimeError, match="validation result permissions are unsafe"):
        MODULE._validation_result_digest(candidate)

    result_path.chmod(0o644)
    original_stat = MODULE.os.stat

    def wrong_owner_stat(path, *args, **kwargs):
        value = original_stat(path, *args, **kwargs)
        if path == Path("result.json") and kwargs.get("dir_fd") is not None:
            fields = list(value)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(MODULE.os, "stat", wrong_owner_stat)
    with pytest.raises(RuntimeError, match="validation result permissions are unsafe"):
        MODULE._validation_result_digest(candidate)


def test_validation_live_result_detects_inode_swap_between_lstat_and_open(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    original_stat = MODULE.os.stat
    swapped = False

    def swapping_stat(path, *args, **kwargs):
        nonlocal swapped
        value = original_stat(path, *args, **kwargs)
        if path == Path("result.json") and kwargs.get("dir_fd") is not None and not swapped:
            replacement = result_path.with_suffix(".replacement")
            replacement.write_bytes(raw)
            replacement.chmod(0o644)
            os.replace(replacement, result_path)
            swapped = True
        return value

    monkeypatch.setattr(MODULE.os, "stat", swapping_stat)
    with pytest.raises(RuntimeError, match="validation result changed before it was opened"):
        MODULE._validation_result_digest(candidate)
    assert swapped is True


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_live_result_read_fails_if_private_parent_is_replaced(
    monkeypatch, tmp_path, replacement_kind
):
    worktree = tmp_path / "worktree"
    private = worktree / MODULE.TASK_PRIVATE_DIR
    private.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    (private / "result.json").write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    replacement_private = tmp_path / f"live-{replacement_kind}-private"
    replacement_private.mkdir()
    outside_result = replacement_private / "result.json"
    outside_result.write_bytes(b'{"outside": true}\n')
    original_require = MODULE._require_validation_worktree_private_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_private_dir_after_binding(
                worktree=worktree,
                replacement_private=replacement_private,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(MODULE, "_require_validation_worktree_private_binding", require_then_swap)

    with pytest.raises(RuntimeError, match="private directory is unsafe"):
        MODULE._validation_result_digest(candidate)
    assert swapped is True
    visible_outside_result = (
        worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
        if replacement_kind == "different-inode"
        else outside_result
    )
    assert visible_outside_result.read_bytes() == b'{"outside": true}\n'


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_live_result_read_fails_if_worktree_parent_is_replaced(
    monkeypatch, tmp_path, replacement_kind
):
    parent = tmp_path / "live-parent"
    worktree = parent / "worktree"
    private = worktree / MODULE.TASK_PRIVATE_DIR
    private.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    (private / "result.json").write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    replacement_parent = tmp_path / f"live-parent-{replacement_kind}"
    replacement_worktree = replacement_parent / worktree.name
    replacement_private = replacement_worktree / MODULE.TASK_PRIVATE_DIR
    replacement_private.mkdir(parents=True)
    outside_result = replacement_private / "result.json"
    outside_result.write_bytes(b'{"outside": true}\n')
    original_require = MODULE._require_validation_worktree_private_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_worktree_parent_after_binding(
                parent=parent,
                replacement_parent=replacement_parent,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(MODULE, "_require_validation_worktree_private_binding", require_then_swap)

    with pytest.raises(RuntimeError, match="validation worktree parent is unsafe"):
        MODULE._validation_result_digest(candidate)
    assert swapped is True
    visible_outside_result = (
        parent / worktree.name / MODULE.TASK_PRIVATE_DIR / "result.json"
        if replacement_kind == "different-inode"
        else outside_result
    )
    assert visible_outside_result.read_bytes() == b'{"outside": true}\n'


@pytest.mark.parametrize("operation", ["ingest", "enqueue"])
def test_task_result_candidate_rejects_private_symlink_without_external_read(tmp_path, operation):
    _store, worktree, _result_path = _controller_commit_result(tmp_path)
    private = worktree / MODULE.TASK_PRIVATE_DIR
    original_private = worktree / f"{MODULE.TASK_PRIVATE_DIR}.original"
    outside_private = tmp_path / "outside-private"
    outside_private.mkdir()
    outside_result = outside_private / "result.json"
    outside_result.write_text("{not-json-from-outside", encoding="utf-8")
    private.rename(original_private)
    private.symlink_to(outside_private, target_is_directory=True)

    if operation == "ingest":
        result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
        rejected = result["errors"]
    else:
        result = MODULE.enqueue_local_receipts(tmp_path / "ledger.sqlite3")
        rejected = result["rejected"]

    assert result["ok"] is False
    assert rejected and rejected[0]["key"] == "a/b#1"
    assert "not-json-from-outside" not in rejected[0]["error"]
    assert outside_result.read_text(encoding="utf-8") == "{not-json-from-outside"


@pytest.mark.parametrize("operation", ["ingest", "enqueue"])
@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_task_result_candidate_rejects_private_parent_replaced_after_binding(
    monkeypatch, tmp_path, replacement_kind, operation
):
    _store, worktree, _result_path = _controller_commit_result(tmp_path)
    replacement_private = tmp_path / f"task-result-{replacement_kind}-private"
    replacement_private.mkdir()
    outside_result = replacement_private / "result.json"
    outside_result.write_text('{"outside": true}\n', encoding="utf-8")
    original_require = MODULE._require_validation_worktree_private_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_private_dir_after_binding(
                worktree=worktree,
                replacement_private=replacement_private,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(MODULE, "_require_validation_worktree_private_binding", require_then_swap)

    if operation == "ingest":
        result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
        rejected = result["errors"]
    else:
        result = MODULE.enqueue_local_receipts(tmp_path / "ledger.sqlite3")
        rejected = result["rejected"]

    assert swapped is True
    assert result["ok"] is False
    assert rejected and rejected[0]["key"] == "a/b#1"
    visible_outside_result = (
        worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
        if replacement_kind == "different-inode"
        else outside_result
    )
    assert visible_outside_result.read_bytes() == b'{"outside": true}\n'


@pytest.mark.parametrize("operation", ["ingest", "enqueue"])
def test_task_result_candidate_skips_missing_result_in_safe_private_dir(tmp_path, operation):
    _store, _worktree, result_path = _controller_commit_result(tmp_path)
    result_path.unlink()

    if operation == "ingest":
        result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
        assert result["ok"] is True
        assert result["ingested"] == []
        assert result["errors"] == []
    else:
        result = MODULE.enqueue_local_receipts(tmp_path / "ledger.sqlite3")
        assert result["ok"] is True
        assert result["queued"] == []
        assert result["rejected"] == []


def test_fast_receipt_skips_plain_published_history_with_missing_worktree(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.record_followup_result(
        "a/b#1",
        wake_digest=candidate["wakeDigest"],
        result_digest="already-ingested",
        stage="PR_OPEN",
    )
    shutil.rmtree(worktree)

    result = MODULE.enqueue_local_receipts(tmp_path / "ledger.sqlite3")

    assert result["ok"] is True
    assert result["queued"] == []
    assert result["rejected"] == []


def test_fast_receipt_reports_unfinished_pr_followup_with_missing_worktree(tmp_path):
    store, worktree, _head_sha, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    store.commit_pr_followup(thread_id="thread-1", wake_digest=candidate["wakeDigest"])
    shutil.rmtree(worktree)

    result = MODULE.enqueue_local_receipts(tmp_path / "ledger.sqlite3")

    assert result["ok"] is False
    assert result["queued"] == []
    assert result["rejected"][0]["key"] == "a/b#1"
    assert "worktree is missing" in result["rejected"][0]["error"]


def test_fast_receipt_reports_unfinished_validation_followup_with_missing_worktree(tmp_path):
    store, worktree, _result_path = _controller_commit_result(tmp_path)
    value = json.loads(_result_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(_result_path.read_bytes()).hexdigest()
    store.record_stage(
        "a/b#1",
        "VALIDATION_PENDING",
        evidence={"reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE"},
        dedupe_key=digest,
    )
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green"],
    )
    store.record_task_result_ingested("a/b#1", digest=digest, stage="VALIDATION_PENDING")
    store.reserve_validation_followup(thread_id="thread-1", result_digest=digest)
    store.commit_validation_followup(thread_id="thread-1", result_digest=digest)
    assert value["key"] == "a/b#1"
    shutil.rmtree(worktree)

    result = MODULE.enqueue_local_receipts(tmp_path / "ledger.sqlite3")

    assert result["ok"] is False
    assert result["queued"] == []
    assert result["rejected"][0]["key"] == "a/b#1"
    assert "worktree is missing" in result["rejected"][0]["error"]


def test_validation_result_absence_requires_existing_safe_private_dir(tmp_path):
    worktree = tmp_path / "missing-private" / "worktree"
    worktree.mkdir(parents=True)
    candidate = {"worktreePath": str(worktree), "resultDigest": "a" * 64}

    with pytest.raises(RuntimeError, match="validation worktree private directory is missing"):
        MODULE._read_authenticated_validation_result_if_present(candidate)

    private = worktree / MODULE.TASK_PRIVATE_DIR
    private.mkdir(mode=0o700)
    assert MODULE._read_authenticated_validation_result_if_present(candidate) is None


def test_validation_worktree_path_must_be_absolute():
    candidate = {"worktreePath": "relative-worktree", "resultDigest": "a" * 64}

    with pytest.raises(RuntimeError, match="validation worktree path must be absolute"):
        MODULE._read_authenticated_validation_result_if_present(candidate)


def test_validation_worktree_outside_trusted_roots_fails_closed(monkeypatch, tmp_path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    outside = tmp_path / "outside" / "worktree"
    (outside / MODULE.TASK_PRIVATE_DIR).mkdir(parents=True)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", trusted)
    candidate = {"worktreePath": str(outside), "resultDigest": "a" * 64}

    with pytest.raises(RuntimeError, match="outside trusted roots"):
        MODULE._read_authenticated_validation_result_if_present(candidate)


def _replace_validation_snapshot_parent_after_binding(
    *, state: Path, replacement: Path, parent: str, replacement_kind: str
) -> None:
    if parent == "state":
        original = state.with_name(f"{state.name}.original")
        state.rename(original)
        if replacement_kind == "symlink":
            state.symlink_to(replacement, target_is_directory=True)
        else:
            replacement.rename(state)
        return

    root = state / "validation-inputs"
    original = state / "validation-inputs.original"
    root.rename(original)
    if replacement_kind == "symlink":
        root.symlink_to(replacement, target_is_directory=True)
    else:
        replacement.rename(root)


@pytest.mark.parametrize("parent", ["state", "root"])
@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_snapshot_read_fails_if_parent_is_replaced(
    monkeypatch, tmp_path, parent, replacement_kind
):
    worktree = tmp_path / "worktree"
    result_path = worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    state = bind_validation_runtime(monkeypatch, tmp_path)
    reservation_digest = "7" * 64
    binding = MODULE._ensure_validation_snapshot(candidate, reservation_digest=reservation_digest)

    replacement = tmp_path / f"snapshot-read-{parent}-{replacement_kind}"
    replacement_root = replacement / "validation-inputs" if parent == "state" else replacement
    replacement_root.mkdir(parents=True)
    replacement_root.chmod(0o700)
    outside_snapshot = replacement_root / f"{reservation_digest}.json"
    outside_snapshot.write_bytes(b'{"outside": true}\n')
    outside_snapshot.chmod(0o400)
    original_require = MODULE._require_validation_snapshot_root_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_snapshot_parent_after_binding(
                state=state,
                replacement=replacement,
                parent=parent,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(MODULE, "_require_validation_snapshot_root_binding", require_then_swap)

    expected_error = (
        "validation snapshot state directory is unsafe"
        if parent == "state"
        else "validation snapshot root is unsafe"
    )
    with pytest.raises(RuntimeError, match=expected_error):
        MODULE._validation_snapshot_metadata(
            candidate=candidate,
            reservation_digest=reservation_digest,
            snapshot_id=binding["snapshotId"],
            snapshot_path=binding["snapshotPath"],
            snapshot_digest=binding["snapshotDigest"],
        )
    assert swapped is True
    visible_outside_snapshot = (
        state / "validation-inputs" / outside_snapshot.name
        if replacement_kind == "different-inode"
        else outside_snapshot
    )
    assert visible_outside_snapshot.read_bytes() == b'{"outside": true}\n'


@pytest.mark.parametrize("parent", ["state", "root"])
@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_snapshot_write_fails_if_parent_is_replaced(
    monkeypatch, tmp_path, parent, replacement_kind
):
    worktree = tmp_path / "worktree"
    result_path = worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    state = bind_validation_runtime(monkeypatch, tmp_path)
    state.mkdir()
    (state / "validation-inputs").mkdir(mode=0o700)
    replacement = tmp_path / f"snapshot-write-{parent}-{replacement_kind}"
    replacement_root = replacement / "validation-inputs" if parent == "state" else replacement
    replacement_root.mkdir(parents=True)
    replacement_root.chmod(0o700)
    original_require = MODULE._require_validation_snapshot_root_binding
    swapped = False

    def require_then_swap(**kwargs):
        nonlocal swapped
        original_require(**kwargs)
        if not swapped:
            _replace_validation_snapshot_parent_after_binding(
                state=state,
                replacement=replacement,
                parent=parent,
                replacement_kind=replacement_kind,
            )
            swapped = True

    monkeypatch.setattr(MODULE, "_require_validation_snapshot_root_binding", require_then_swap)

    expected_error = (
        "validation snapshot state directory is unsafe"
        if parent == "state"
        else "validation snapshot root is unsafe"
    )
    with pytest.raises(RuntimeError, match=expected_error):
        MODULE._ensure_validation_snapshot(candidate, reservation_digest="8" * 64)
    assert swapped is True
    visible_replacement_root = (
        state / "validation-inputs" if replacement_kind == "different-inode" else replacement_root
    )
    assert list(visible_replacement_root.iterdir()) == []


def test_validation_snapshot_root_symlink_is_rejected(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / ".oss-pr-radar" / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    state = bind_validation_runtime(monkeypatch, tmp_path)
    state.mkdir()
    outside = tmp_path / "outside-snapshots"
    outside.mkdir()
    (state / "validation-inputs").symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeError, match="validation snapshot root is unsafe"):
        MODULE._ensure_validation_snapshot(candidate, reservation_digest="f" * 64)
    assert list(outside.iterdir()) == []


def test_validation_snapshot_state_parent_must_match_root(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    result_path = worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(MODULE, "ROOT", runtime)
    detached_state = tmp_path / "detached-state"
    monkeypatch.setattr(MODULE, "STATE", detached_state)

    with pytest.raises(RuntimeError, match="not bound to ROOT"):
        MODULE._ensure_validation_snapshot(candidate, reservation_digest="1" * 64)
    assert not detached_state.exists()


@pytest.mark.parametrize("replacement_kind", ["symlink", "different-inode"])
def test_validation_snapshot_create_fails_if_runtime_root_is_replaced(
    monkeypatch, tmp_path, replacement_kind
):
    worktree = tmp_path / "worktree"
    result_path = worktree / MODULE.TASK_PRIVATE_DIR / "result.json"
    result_path.parent.mkdir(parents=True)
    raw = b'{"tests": [{"command": "focused", "exitCode": 0}]}\n'
    result_path.write_bytes(raw)
    candidate = {
        "worktreePath": str(worktree),
        "resultDigest": hashlib.sha256(raw).hexdigest(),
    }
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(MODULE, "ROOT", runtime)
    monkeypatch.setattr(MODULE, "STATE", runtime / "state")
    replacement = tmp_path / f"runtime-replacement-{replacement_kind}"
    replacement.mkdir()
    original_child = MODULE._open_directory_child
    swapped = False

    def open_child_then_swap(**kwargs):
        nonlocal swapped
        if kwargs.get("label") == "validation snapshot state directory" and not swapped:
            original_runtime = runtime.with_name("runtime.original")
            runtime.rename(original_runtime)
            if replacement_kind == "symlink":
                runtime.symlink_to(replacement, target_is_directory=True)
            else:
                replacement.rename(runtime)
            swapped = True
        return original_child(**kwargs)

    monkeypatch.setattr(MODULE, "_open_directory_child", open_child_then_swap)

    with pytest.raises(RuntimeError, match="validation snapshot runtime root is unsafe"):
        MODULE._ensure_validation_snapshot(candidate, reservation_digest="2" * 64)
    assert swapped is True
    visible_replacement_root = runtime if replacement_kind == "different-inode" else replacement
    assert not (visible_replacement_root / "state").exists()


def test_validation_followup_list_reconciles_and_reports_unchanged_gap(tmp_path):
    store, worktree = registered_store(tmp_path)
    (worktree / MODULE.TASK_PRIVATE_DIR).mkdir(mode=0o700)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest="result-digest-1",
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.reserve_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    store.commit_validation_followup(thread_id="thread-1", result_digest="result-digest-1")
    with store.connect() as connection:
        connection.execute(
            """INSERT INTO events
               (opportunity_key,event_type,dedupe_key,payload_json,created_at)
               VALUES (?,?,?,?,?)""",
            (
                "a/b#1",
                "TASK_RESULT_VALIDATION_DEFERRED",
                "result-digest-2",
                json.dumps(
                    {
                        "threadId": "thread-1",
                        "resultDigest": "result-digest-2",
                        "missing": ["relevant_tests_green"],
                    }
                ),
                iso_z(datetime.now(UTC)),
            ),
        )

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["ok"] is True
    assert listed["candidates"] == []
    assert listed["unresolved"] == []
    assert listed["stale"] == []
    assert listed["errors"] == []
    assert listed["reconciledNoProgress"] == 1
    assert listed["blockedNoProgress"][0]["key"] == "a/b#1"
    assert listed["blockedNoProgress"][0]["resultDigest"] == "result-digest-2"
    assert listed["blockedNoProgress"][0]["previousResultDigest"] == "result-digest-1"
    assert listed["blockedNoProgress"][0]["missing"] == ["relevant_tests_green"]


def test_new_controller_review_feedback_rearms_a_stalled_validation(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green", "independent_review_passed"),
    )
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    first_digest = first["validationDeferred"][0]
    candidate = store.validation_followup_candidates()[0]
    store.reserve_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    store.commit_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["independentReview"] = {"verdict": "FAIL", "summary": "integration path is stale"}
    value["tests"] = [{"command": "pytest tests/runtime", "exitCode": 1}]
    result_path.write_text(json.dumps(value), encoding="utf-8")
    second_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=["relevant_tests_green", "independent_review_passed"],
    )
    review = {"verdict": "FAIL", "summary": "integration path is stale"}
    monkeypatch.setattr(MODULE, "controller_review_result", lambda _root, _value: dict(review))

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first_digest["missing"] == ["relevant_tests_green", "independent_review_passed"]
    assert listed["rearmedReviewFeedback"] == [
        {"key": "a/b#1", "reason": "CONTROLLER_REVIEW_FEEDBACK_AVAILABLE"}
    ]
    assert listed["blockedNoProgress"] == []
    assert listed["candidates"][0]["resultDigest"] == second_digest

    store.reserve_validation_followup(thread_id="thread-1", result_digest=second_digest)
    store.commit_validation_followup(thread_id="thread-1", result_digest=second_digest)
    value["evidence"] = {"summary": "the same validation gap remains"}
    result_path.write_text(json.dumps(value), encoding="utf-8")
    third_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=third_digest,
        missing=["relevant_tests_green", "independent_review_passed"],
    )

    unchanged = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert unchanged["rearmedReviewFeedback"] == []
    assert unchanged["blockedNoProgress"][0]["resultDigest"] == third_digest

    review["summary"] = "the integration path and async fallback are both stale"
    changed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert changed["rearmedReviewFeedback"] == [
        {"key": "a/b#1", "reason": "CONTROLLER_REVIEW_FEEDBACK_AVAILABLE"}
    ]
    assert changed["candidates"][0]["resultDigest"] == third_digest


def test_dirty_worktree_rearms_a_stalled_validation_result(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    store.reserve_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    store.commit_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["evidence"] = {"summary": "the continuation started but was interrupted"}
    result_path.write_text(json.dumps(value), encoding="utf-8")
    second_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=["relevant_tests_green"],
    )
    (worktree / "runtime.py").write_text("value = 3\n", encoding="utf-8")

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["rearmedReviewFeedback"] == [
        {"key": "a/b#1", "reason": "WORKTREE_PROGRESS_PENDING_RESULT"}
    ]
    assert listed["blockedNoProgress"] == []
    assert listed["candidates"][0]["resultDigest"] == second_digest


def test_new_check_outcome_rearms_a_stalled_validation_result(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["tests"] = [{"command": "pnpm test", "exitCode": 1}]
    result_path.write_text(json.dumps(value), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    store.reserve_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    store.commit_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])

    value["evidence"] = {"summary": "the same gap remains"}
    result_path.write_text(json.dumps(value), encoding="utf-8")
    second_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=["relevant_tests_green"],
    )

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first["validationDeferred"][0]["missing"] == ["relevant_tests_green"]
    assert listed["rearmedReviewFeedback"] == [
        {"key": "a/b#1", "reason": "VALIDATION_PROGRESS_EVIDENCE_AVAILABLE"}
    ]
    assert listed["blockedNoProgress"] == []
    assert listed["candidates"][0]["resultDigest"] == second_digest


def test_available_dependency_prefetch_rearms_a_stalled_validation(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    store.reserve_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    store.commit_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["evidence"] = {"summary": "locked validation dependency is absent"}
    result_path.write_text(json.dumps(value), encoding="utf-8")
    second_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=list(candidate["missing"]),
    )
    monkeypatch.setattr(MODULE, "_local_changed_files", lambda _worktree: [])
    monkeypatch.setattr(
        MODULE,
        "_validation_prefetch_plan",
        lambda _candidate: (
            [
                {
                    "kind": "npm_locked_install",
                    "cwd": str(tmp_path),
                    "argv": [
                        "npm",
                        "ci",
                        "--ignore-scripts",
                        "--no-audit",
                        "--no-fund",
                    ],
                }
            ],
            [],
        ),
    )

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["rearmedReviewFeedback"] == [
        {"key": "a/b#1", "reason": "DEPENDENCY_PREFETCH_AVAILABLE"}
    ]
    assert listed["blockedNoProgress"] == []
    assert listed["candidates"][0]["prefetchRequired"] is True


def test_locked_but_absent_node_dependency_builds_npm_prefetch_plan(tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / "package.json").write_text("{}\n", encoding="utf-8")
    (worktree / "package-lock.json").write_text("{}\n", encoding="utf-8")
    private = worktree / ".oss-pr-radar"
    private.mkdir()
    result = {
        "changedFiles": ["open-sse/utils/stream.ts"],
        "tests": [
            {
                "command": "npm run lint:json",
                "exitCode": 2,
                "summary": "eslint-config-next 16.3.0 is locked but absent",
            }
        ],
    }
    raw = json.dumps(result).encode()
    (private / "result.json").write_bytes(raw)

    commands, failures = MODULE._validation_prefetch_plan(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert len(failures) == 1
    assert commands == [
        {
            "kind": "npm_locked_install",
            "cwd": str(worktree.resolve()),
            "argv": ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        }
    ]


def test_unlocked_unverified_gate_is_classified_as_environment_blocked(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    store.reserve_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    store.commit_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["evidence"] = {
        "unverifiedGates": [
            {
                "command": "cd docs && mint broken-links",
                "reason": "mint is not on PATH and no worktree-local prefetched executable exists",
            }
        ]
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")
    second_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=list(candidate["missing"]),
    )
    monkeypatch.setattr(MODULE, "_local_changed_files", lambda _worktree: [])

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["blockedNoProgress"] == []
    assert listed["rearmedReviewFeedback"] == []
    assert listed["environmentBlocked"][0]["key"] == "a/b#1"
    assert listed["environmentBlocked"][0]["reason"] == ("DEPENDENCY_ENVIRONMENT_UNAVAILABLE")


def test_string_unverified_dependency_gate_is_environment_blocked(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    candidate = store.validation_followup_candidates()[0]
    store.reserve_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    store.commit_validation_followup(thread_id="thread-1", result_digest=candidate["resultDigest"])
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["evidence"] = {
        "unverifiedGates": [
            "pre-commit and Ruff are absent from PATH in the locked validation environment"
        ]
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")
    second_digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=second_digest,
        missing=list(candidate["missing"]),
    )
    monkeypatch.setattr(MODULE, "_local_changed_files", lambda _worktree: [])

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["blockedNoProgress"] == []
    assert listed["rearmedReviewFeedback"] == []
    assert listed["environmentBlocked"][0]["key"] == "a/b#1"
    assert listed["environmentBlocked"][0]["reason"] == ("DEPENDENCY_ENVIRONMENT_UNAVAILABLE")


def test_mixed_prefetchable_and_unavailable_gates_stop_without_followup(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green", "independent_review_passed"),
    )
    (worktree / "go.mod").write_text("module example.test/runtime\n", encoding="utf-8")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["changedFiles"] = ["service.go"]
    value["tests"] = [
        {
            "command": "GOPROXY=off go vet ./...",
            "exitCode": 1,
            "outcome": "blocked_by_uncached_dependencies",
        },
        {
            "command": "golangci-lint version",
            "exitCode": 127,
            "outcome": "required_gate_unavailable_after_locked_prefetch",
        },
    ]
    raw = json.dumps(value).encode()
    result_path.write_bytes(raw)
    digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green", "independent_review_passed"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["candidates"] == []
    assert listed["rearmedReviewFeedback"] == []
    assert listed["environmentBlocked"][0]["reason"] == ("DEPENDENCY_ENVIRONMENT_UNAVAILABLE")
    assert listed["environmentBlocked"][0]["dependencyFailures"] == [
        {
            "command": "golangci-lint version",
            "summary": "required_gate_unavailable_after_locked_prefetch",
        }
    ]


def test_string_unverified_gate_with_lockfile_builds_prefetch_plan(tmp_path):
    worktree = tmp_path / "worktree"
    private = worktree / ".oss-pr-radar"
    private.mkdir(parents=True)
    (worktree / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (worktree / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    result = {
        "changedFiles": ["src/runtime.py"],
        "tests": [],
        "evidence": {
            "unverifiedGates": [
                "uv run pytest requires 54 uncached packages in the locked environment"
            ]
        },
    }
    raw = json.dumps(result).encode()
    (private / "result.json").write_bytes(raw)

    commands, failures = MODULE._validation_prefetch_plan(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert len(failures) == 1
    assert commands == [
        {
            "kind": "uv_locked_sync",
            "cwd": str(worktree.resolve()),
            "argv": ["uv", "sync", "--frozen", "--no-install-project"],
        }
    ]


def test_validation_followup_never_abandons_an_unreceipted_delivery(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    reserved_at = iso_z(now - timedelta(hours=2))
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, updated_at INTEGER, rollout_path TEXT)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", int((now - timedelta(hours=3)).timestamp()), None),
        )

    reservation_digest = "b" * 64

    class Store:
        def reconcile_validation_no_progress(self):
            return 0

        def validation_followup_candidates(self):
            return []

        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "reservationDigest": reservation_digest,
                    "missing": ["relevant_tests_green"],
                    "reservedAt": reserved_at,
                }
            ]

        def stale_validation_followups(self, **_kwargs):
            return []

        def validation_no_progress(self):
            return []

    store = Store()
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    args = SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    unresolved = MODULE.validation_followup_list(args)["unresolved"][0]

    assert unresolved["abandonable"] is False
    assert unresolved["commitReady"] is False
    assert "retryable" not in unresolved
    assert "abandonNonce" not in unresolved
    with pytest.raises(RuntimeError, match="not safely abandonable"):
        MODULE.validation_followup_abandon(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id="thread-1",
                result_digest="a" * 64,
                abandon_nonce="unused",
                reason="TARGET_TURN_NOT_MATERIALIZED",
                min_age_minutes=90,
            )
        )


def test_validation_followup_exposes_active_writer_as_desktop_handoff(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    reserved_at = iso_z(now - timedelta(hours=2))
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute("CREATE TABLE threads (id TEXT, updated_at INTEGER, rollout_path TEXT)")
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?)",
            ("thread-1", int((now - timedelta(hours=3)).timestamp()), None),
        )

    reservation_digest = "b" * 64

    class Store:
        def reconcile_validation_no_progress(self):
            return 0

        def validation_followup_candidates(self):
            return []

        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "reservationDigest": reservation_digest,
                    "missing": ["independent_review_passed"],
                    "reservedAt": reserved_at,
                }
            ]

        def stale_validation_followups(self, **_kwargs):
            return []

        def validation_no_progress(self):
            return []

    state = tmp_path / "state"
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    receipt_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="a" * 64,
        validation_reservation_digest=reservation_digest,
    )
    (receipt_root / f"{receipt_key}.json").write_text(
        json.dumps(
            {
                "ok": False,
                "turnStarted": False,
                "turnId": None,
                "error": (
                    "RuntimeError:DESKTOP_ACTIVE_WRITER:"
                    "thread thread-1 already has an active writer"
                ),
                "reservationDigest": reservation_digest,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())

    unresolved = MODULE.validation_followup_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=90)
    )["unresolved"][0]

    assert unresolved["retryable"] is True
    assert unresolved["retryReason"] == "DESKTOP_ACTIVE_WRITER"
    assert unresolved["desktopHandoffRequired"] is True
    assert unresolved["desktopHandoff"]["threadId"] == "thread-1"
    assert "系统续跑" in unresolved["desktopHandoff"]["prompt"]
    assert "independent_review_passed" not in unresolved["desktopHandoff"]["prompt"]
    assert unresolved["commitReady"] is False
    assert unresolved["abandonable"] is False


def test_negative_validation_receipt_rearms_the_same_result(monkeypatch, tmp_path):
    reserved_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    calls = []
    reservation_digest = "b" * 64

    class Store:
        def unresolved_pr_followups(self):
            return []

        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "reservationDigest": reservation_digest,
                    "reservedAt": reserved_at,
                }
            ]

        def abandon_validation_followup_delivery(self, **kwargs):
            calls.append(kwargs)

    state = tmp_path / "state"
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    receipt_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="a" * 64,
        validation_reservation_digest=reservation_digest,
    )
    receipt = receipt_root / f"{receipt_key}.json"
    launch = receipt_root / f"{receipt_key}.launch.json"
    log = receipt_root / f"{receipt_key}.log"
    receipt.write_text(
        json.dumps(
            {
                "ok": False,
                "turnStarted": False,
                "error": "resume failed",
                "reservationDigest": reservation_digest,
            }
        ),
        encoding="utf-8",
    )
    launch.write_text(json.dumps({"pid": 0}), encoding="utf-8")
    log.write_text("old attempt", encoding="utf-8")
    monkeypatch.setattr(MODULE, "STATE", state)

    rearmed = MODULE._rearm_negative_followup_deliveries(Store())

    assert rearmed == [
        {
            "kind": "validation-followup",
            "key": "a/b#1",
            "threadId": "thread-1",
            "resultDigest": "a" * 64,
        }
    ]
    assert calls == [
        {
            "thread_id": "thread-1",
            "result_digest": "a" * 64,
            "reason": "NEGATIVE_RECEIPT_NO_TURN_STARTED",
            "min_age_minutes": 1,
        }
    ]
    assert not receipt.exists()
    assert not launch.exists()
    assert not log.exists()


def test_active_writer_receipt_waits_for_desktop_handoff_instead_of_rearming(monkeypatch, tmp_path):
    reserved_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    calls = []
    reservation_digest = "b" * 64

    class Store:
        def unresolved_pr_followups(self):
            return []

        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "reservationDigest": reservation_digest,
                    "reservedAt": reserved_at,
                }
            ]

        def abandon_validation_followup_delivery(self, **kwargs):
            calls.append(kwargs)

    state = tmp_path / "state"
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    receipt_key = MODULE._task_turn_delivery_file_key(
        delivery_kind="validation-followup",
        thread_id="thread-1",
        delivery_token="a" * 64,
        validation_reservation_digest=reservation_digest,
    )
    receipt = receipt_root / f"{receipt_key}.json"
    receipt.write_text(
        json.dumps(
            {
                "ok": False,
                "turnStarted": False,
                "error": "RuntimeError:DESKTOP_ACTIVE_WRITER:active writer",
                "reservationDigest": reservation_digest,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "STATE", state)
    monkeypatch.setattr(MODULE, "THREAD_DB", tmp_path / "missing.sqlite3")

    assert MODULE._rearm_negative_followup_deliveries(Store()) == []
    assert calls == []
    assert receipt.exists()


def test_materialized_desktop_handoff_is_committed_without_resending(monkeypatch, tmp_path):
    committed = []
    reservation_digest = "b" * 64

    class Store:
        def unresolved_pr_followups(self):
            return []

        def unresolved_validation_followups(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "resultDigest": "a" * 64,
                    "reservationDigest": reservation_digest,
                    "reservedAt": "2026-08-17T00:00:00Z",
                }
            ]

        def commit_validation_followup(self, **kwargs):
            committed.append(kwargs)

    monkeypatch.setattr(MODULE, "STATE", tmp_path / "state")
    monkeypatch.setattr(MODULE, "_reserved_task_turn_materialized", lambda *args, **kwargs: True)

    reconciled = MODULE._rearm_negative_followup_deliveries(Store())

    assert committed == [
        {
            "thread_id": "thread-1",
            "result_digest": "a" * 64,
            "reservation_digest": reservation_digest,
        }
    ]
    assert reconciled == [
        {
            "kind": "validation-followup",
            "key": "a/b#1",
            "threadId": "thread-1",
            "reconciledDesktopHandoff": True,
        }
    ]


def test_html_escaped_delegated_prompt_is_recognized_as_materialized(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    prompt = "PR 已创建：<准确链接>"
    rollout.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-17T00:01:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "<codex_delegation><input>"
                                "PR 已创建：&lt;准确链接&gt;"
                                "</input></codex_delegation>"
                            ),
                        }
                    ],
                },
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    assert MODULE.thread_prompt_materialized_after(
        str(rollout), "2026-08-17T00:00:00Z", prompt
    ) == (True, True)


def test_negative_recovery_receipt_rearms_the_same_task(monkeypatch, tmp_path):
    reserved_at = iso_z(datetime.now(UTC) - timedelta(minutes=2))
    calls = []

    class Store:
        def unresolved_pr_followups(self):
            return []

        def unresolved_validation_followups(self):
            return []

        def unresolved_recoveries(self):
            return [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "reservedAt": reserved_at,
                    "reservation": {"recoveryNonce": "nonce-1"},
                }
            ]

        def abandon_recovery_delivery(self, **kwargs):
            calls.append(kwargs)

    state = tmp_path / "state"
    receipt_root = state / "task_turn_receipts"
    receipt_root.mkdir(parents=True)
    receipt_key = MODULE.sha256_json(
        {
            "deliveryKind": "recovery",
            "threadId": "thread-1",
            "deliveryToken": "nonce-1",
        }
    )
    receipt = receipt_root / f"{receipt_key}.json"
    receipt.write_text(
        json.dumps({"ok": False, "turnStarted": False, "error": "resume failed"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "STATE", state)

    rearmed = MODULE._rearm_negative_followup_deliveries(Store())

    assert rearmed == [
        {
            "kind": "recovery",
            "key": "a/b#1",
            "threadId": "thread-1",
            "recoveryNonce": "nonce-1",
        }
    ]
    assert calls == [
        {
            "thread_id": "thread-1",
            "nonce": "nonce-1",
            "reason": "NEGATIVE_RECEIPT_NO_TURN_STARTED",
            "min_age_minutes": 1,
        }
    ]
    assert not receipt.exists()


def test_controller_defers_unvalidated_publishable_fix_without_agent_failure(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=(
            "regression_test_verified",
            "relevant_tests_green",
            "independent_review_passed",
        ),
    )

    result = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
        }
    ]
    assert result["publicationRequests"] == []
    assert result["validationDeferred"] == [
        {
            "key": "a/b#1",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
            "missing": [
                "regression_test_verified",
                "relevant_tests_green",
                "independent_review_passed",
            ],
        }
    ]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["handoffMode"] == "controller_commit_complete"
    assert finalized["commitSha"] == run_git(worktree, "rev-parse", "HEAD")
    assert store.publication_work_items() == []
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "VALIDATION_PENDING"
    )
    assert store.task_result_candidates()[0]["stage"] == "VALIDATION_PENDING"
    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert repeated["ingested"] == []

    completed = json.loads(result_path.read_text(encoding="utf-8"))
    for field in (
        "regression_test_verified",
        "relevant_tests_green",
        "independent_review_passed",
    ):
        completed["quality"][field] = True
    completed["independentReview"] = {
        "verdict": "PASS",
        "summary": "test controller receipt",
    }
    result_path.write_text(json.dumps(completed), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)

    advanced = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert advanced["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(advanced["publicationRequests"]) == 1
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "FIX_READY"
    )


def test_managed_result_failure_remains_replayable_before_legacy_ingest_marker(
    tmp_path, monkeypatch
):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=(
            "regression_test_verified",
            "relevant_tests_green",
            "independent_review_passed",
        ),
    )
    original = MODULE.ManagedAdapter.record_task_result
    calls = {"count": 0}

    def fail_once(self, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("managed ledger unavailable")
        return original(self, **kwargs)

    monkeypatch.setattr(MODULE.ManagedAdapter, "record_task_result", fail_once)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first["ok"] is False, first
    assert first["errors"] == [{"key": "a/b#1", "error": "managed ledger unavailable"}]
    result_digest = hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert not store.task_result_digest_seen("a/b#1", result_digest)
    replay = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert replay["ok"] is True
    assert replay["ingested"] == [
        {
            "key": "a/b#1",
            "stage": "VALIDATION_PENDING",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
        }
    ]


def test_complete_fix_ready_requires_managed_write_before_legacy_stage(tmp_path, monkeypatch):
    store, _worktree, _result_path = _controller_commit_result(tmp_path)
    original = MODULE.ManagedAdapter.record_task_result

    def fail_once(self, **kwargs):
        monkeypatch.setattr(MODULE.ManagedAdapter, "record_task_result", original)
        raise RuntimeError("managed result unavailable")

    monkeypatch.setattr(MODULE.ManagedAdapter, "record_task_result", fail_once)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first["ok"] is False
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        != "FIX_READY"
    )


def test_fix_ready_replays_legacy_projection_after_managed_success(tmp_path, monkeypatch):
    store, _worktree, _result_path = _controller_commit_result(tmp_path)
    original = MODULE.RadarLedger.record_stage
    calls = {"count": 0}

    def fail_legacy_once(self, *args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("legacy projection unavailable")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(MODULE.RadarLedger, "record_stage", fail_legacy_once)
    first = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert first["ok"] is False, first
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        != "FIX_READY"
    )
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_results").fetchone()[0] == 1

    replay = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert replay["ok"] is True
    assert (
        store.task_context(issue_url="https://github.com/a/b/issues/1", thread_id="thread-1")[
            "stage"
        ]
        == "FIX_READY"
    )
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_results").fetchone()[0] == 1


def test_validation_followup_uses_cumulative_files_for_first_publication(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )

    deferred = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert deferred["validationDeferred"]
    original_head = run_git(worktree, "rev-parse", "HEAD")

    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    assert context["stage"] == "VALIDATION_PENDING"
    (worktree / "test_runtime.py").write_text(
        "def test_runtime():\n    assert True\n", encoding="utf-8"
    )
    run_git(worktree, "add", "test_runtime.py")
    run_git(worktree, "commit", "-m", "test: cover runtime boundary")
    followup_head = run_git(worktree, "rev-parse", "HEAD")
    followup = json.loads(result_path.read_text(encoding="utf-8"))
    followup.update(
        {
            "contextDigest": context["contextDigest"],
            "handoffMode": "controller_commit_complete",
            "commitSha": followup_head,
            "headSha": followup_head,
            "controllerCommitChangedFiles": ["test_runtime.py"],
            "commitMessage": "test: cover runtime boundary",
            "changedFiles": ["runtime.py", "test_runtime.py"],
            "quality": {field: True for field in QUALITY_FIELDS},
        }
    )
    followup.pop("controllerCommitChangedFiles", None)
    followup["controllerCommitChangedFiles"] = ["test_runtime.py"]
    followup["reproductionReceipt"]["headSha"] = followup_head
    followup["reproductionReceipt"]["commitSha"] = followup_head
    result_path.write_text(json.dumps(followup), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)

    advanced = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert advanced["ok"] is True
    assert advanced["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    assert len(advanced["publicationRequests"]) == 1
    assert run_git(worktree, "rev-parse", "HEAD") != original_head
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["controllerCommitChangedFiles"] == ["test_runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py", "test_runtime.py"]

    finalized_after_sync, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context | {"stage": "PR_OPEN"},
        value=finalized,
        result_path=result_path,
    )
    assert finalized_after_sync["changedFiles"] == ["runtime.py", "test_runtime.py"]
    assert run_git(worktree, "show", "--pretty=format:", "--name-only", "HEAD") == (
        "test_runtime.py"
    )


def test_validation_followup_accepts_cumulative_files_with_local_correction(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    (worktree / "test_runtime.py").write_text(
        "def test_runtime():\n    assert True\n", encoding="utf-8"
    )
    run_git(worktree, "add", "test_runtime.py")
    run_git(worktree, "commit", "-m", "test: cover runtime boundary")
    followup_head = run_git(worktree, "rev-parse", "HEAD")
    followup = json.loads(result_path.read_text(encoding="utf-8"))
    followup.update(
        {
            "contextDigest": context["contextDigest"],
            "handoffMode": "controller_commit_complete",
            "commitSha": followup_head,
            "headSha": followup_head,
            "controllerCommitChangedFiles": ["test_runtime.py"],
            "commitMessage": "test: cover runtime boundary",
            "changedFiles": ["runtime.py", "test_runtime.py"],
            "quality": {field: True for field in QUALITY_FIELDS},
        }
    )
    followup.pop("controllerCommitChangedFiles", None)
    followup["controllerCommitChangedFiles"] = ["test_runtime.py"]
    followup["reproductionReceipt"]["headSha"] = followup_head
    followup["reproductionReceipt"]["commitSha"] = followup_head
    result_path.write_text(json.dumps(followup), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)

    advanced = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert advanced["ok"] is True
    assert advanced["ingested"] == [{"key": "a/b#1", "stage": "FIX_READY"}]
    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    assert finalized["controllerCommitChangedFiles"] == ["test_runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py", "test_runtime.py"]


def test_validation_followup_normalizes_existing_complete_handoff(tmp_path, monkeypatch):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    (worktree / "test_runtime.py").write_text(
        "def test_runtime():\n    assert True\n", encoding="utf-8"
    )
    run_git(worktree, "add", "test_runtime.py")
    run_git(worktree, "commit", "-m", "test: cover runtime boundary")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value.update(
        {
            "handoffMode": "controller_commit_complete",
            "commitSha": run_git(worktree, "rev-parse", "HEAD"),
            "changedFiles": ["test_runtime.py"],
        }
    )
    value.pop("controllerCommitChangedFiles", None)
    result_path.write_text(json.dumps(value), encoding="utf-8")

    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=value,
        result_path=result_path,
    )

    assert finalized["controllerCommitChangedFiles"] == ["test_runtime.py"]
    assert finalized["changedFiles"] == ["runtime.py", "test_runtime.py"]

    def unexpected_write(*_args, **_kwargs):
        raise AssertionError("an already normalized handoff must not be rewritten")

    monkeypatch.setattr(MODULE, "_atomic_json", unexpected_write)
    repeated, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=finalized,
        result_path=result_path,
        write_if_unchanged=False,
    )
    assert repeated == finalized


def test_validation_followup_allows_a_revision_to_remove_rejected_files(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))

    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    (worktree / "replacement.py").write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py", "replacement.py")
    run_git(worktree, "commit", "-m", "fix: narrow runtime correction")

    value = json.loads(result_path.read_text(encoding="utf-8"))
    value.update(
        {
            "contextDigest": context["contextDigest"],
            "handoffMode": "controller_commit_complete",
            "commitSha": run_git(worktree, "rev-parse", "HEAD"),
            "changedFiles": ["replacement.py"],
            "controllerCommitChangedFiles": ["replacement.py"],
        }
    )

    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=value,
        result_path=result_path,
    )

    assert finalized["controllerCommitChangedFiles"] == ["replacement.py", "runtime.py"]
    assert finalized["changedFiles"] == ["replacement.py"]


def test_validation_followup_recovers_a_committed_cumulative_file_handoff(tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))

    (worktree / "runtime.py").write_text("value = 1\n", encoding="utf-8")
    (worktree / "replacement.py").write_text("value = 2\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py", "replacement.py")
    run_git(worktree, "commit", "-m", "fix: narrow runtime correction")

    value = json.loads(result_path.read_text(encoding="utf-8"))
    value.update(
        {
            "contextDigest": context["contextDigest"],
            "handoffMode": "controller_commit_required",
            "commitSha": None,
            "changedFiles": ["replacement.py"],
        }
    )
    value.pop("controllerCommitChangedFiles", None)

    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=value,
        result_path=result_path,
    )

    assert finalized["handoffMode"] == "controller_commit_complete"
    assert finalized["controllerCommitChangedFiles"] == ["replacement.py", "runtime.py"]
    assert finalized["changedFiles"] == ["replacement.py"]


def test_controller_accepts_equivalent_rebased_commit_receipt(tmp_path):
    _store, worktree, result_path = _controller_commit_result(tmp_path)
    context = json.loads(
        (worktree / ".oss-pr-radar" / "task-context.json").read_text(encoding="utf-8")
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=value,
        result_path=result_path,
    )
    receipt_commit = finalized["commitSha"]

    run_git(worktree, "commit", "--amend", "-m", "fix: preserve rebased runtime boundary")
    rebased_commit = run_git(worktree, "rev-parse", "HEAD")
    assert rebased_commit != receipt_commit

    normalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=finalized,
        result_path=result_path,
    )

    assert normalized["commitSha"] == rebased_commit
    assert normalized["controllerCommitChangedFiles"] == ["runtime.py"]
    assert normalized["changedFiles"] == ["runtime.py"]


def test_controller_rejects_changed_commit_behind_an_old_receipt(tmp_path):
    _store, worktree, result_path = _controller_commit_result(tmp_path)
    context = json.loads(
        (worktree / ".oss-pr-radar" / "task-context.json").read_text(encoding="utf-8")
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    finalized, _raw = _finalize_controller_commit_for_test(
        candidate={"worktreePath": str(worktree)},
        context=context,
        value=value,
        result_path=result_path,
    )

    (worktree / "runtime.py").write_text("value = 3\n", encoding="utf-8")
    run_git(worktree, "add", "runtime.py")
    run_git(worktree, "commit", "--amend", "-m", "fix: change runtime behavior")

    with pytest.raises(RuntimeError, match="controller commit receipt does not match HEAD"):
        _finalize_controller_commit_for_test(
            candidate={"worktreePath": str(worktree)},
            context=context,
            value=finalized,
            result_path=result_path,
        )


def test_ingestion_recovers_seen_complete_pr_followup_parent(tmp_path, monkeypatch):
    store, worktree, previous_head, _pr_url = _published_followup_store(tmp_path)
    candidate = store.pr_followup_candidates()[0]
    store.reserve_pr_followup(
        thread_id="thread-1",
        wake_digest=candidate["wakeDigest"],
        prepared_head_sha=previous_head,
    )
    store.complete_pr_followup_reservation(
        thread_id="thread-1", wake_digest=candidate["wakeDigest"]
    )
    with store.connect() as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM intents WHERE intent_id='intent-1'"
            ).fetchone()[0]
        )
        payload.update({"taskStage": "IMPLEMENTATION_READY", "probeLevel": "REPRODUCED_VALIDATED"})
        connection.execute(
            "UPDATE intents SET payload_json=? WHERE intent_id='intent-1'",
            (json.dumps(payload, sort_keys=True),),
        )
    context_path = MODULE.write_task_context(
        store,
        issue_url="https://github.com/a/b/issues/1",
        thread_id="thread-1",
        cwd=worktree,
        prepared_followup_head=previous_head,
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    (worktree / "test_runtime.py").write_text(
        "def test_runtime():\n    assert True\n", encoding="utf-8"
    )
    run_git(worktree, "add", "test_runtime.py")
    run_git(worktree, "commit", "-m", "test: cover runtime follow-up")
    result = {
        "schemaVersion": "radar-task-result-v1",
        "contextDigest": context["contextDigest"],
        "key": "a/b#1",
        "issueUrl": "https://github.com/a/b/issues/1",
        "threadId": "thread-1",
        "worktreePath": str(worktree.resolve()),
        "stage": "FIX_READY",
        "handoffMode": "controller_commit_complete",
        "commitSha": run_git(worktree, "rev-parse", "HEAD"),
        "branch": run_git(worktree, "symbolic-ref", "--short", "HEAD"),
        "taskId": "intent-1",
        "probeRequired": True,
        "probeLevel": "REPRODUCED_VALIDATED",
        "selectedBaseSha": previous_head,
        "headSha": run_git(worktree, "rev-parse", "HEAD"),
        "codePaths": ["runtime.py"],
        "preTaskEvidence": {
            "defaultBranch": "main",
            "baseSha": previous_head,
            "codePathsPlan": ["runtime.py"],
        },
        "changedFiles": ["test_runtime.py"],
        "controllerCommitChangedFiles": ["test_runtime.py"],
        "tests": [{"command": "pytest test_runtime.py", "exitCode": 0}],
        "quality": {field: field != "independent_review_passed" for field in QUALITY_FIELDS},
        "publication": {
            "headOwner": "Oxygen56",
            "baseBranch": "main",
            "title": "test: cover runtime follow-up",
            "bodyFile": str((worktree / ".oss-pr-radar" / "pr-body.md").resolve()),
        },
    }
    result_path = Path(context["resultPath"])
    (worktree / ".oss-pr-radar" / "pr-body.md").write_text(
        "Fixes #1\n\nCover the runtime follow-up.\n", encoding="utf-8"
    )
    result_path.write_text(json.dumps(result), encoding="utf-8")
    result_value = json.loads(result_path.read_text(encoding="utf-8"))
    candidate_record = next(
        item
        for item in store.task_result_candidates()
        if item["key"] == "a/b#1" and item["threadId"] == "thread-1"
    )
    result_value, _raw = _finalize_controller_commit_for_test(
        candidate=candidate_record,
        context=context,
        value=result_value,
        result_path=result_path,
    )
    _sign_reproduction_certificate(
        result_value,
        result_path=result_path,
        base_sha=previous_head,
        head_sha=result_value["commitSha"],
        commit_sha=result_value["commitSha"],
        store=store,
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence=result["quality"])
    store.record_task_result_ingested(
        "a/b#1",
        digest=hashlib.sha256(result_path.read_bytes()).hexdigest(),
        stage="VALIDATION_PENDING",
    )

    outcome = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    finalized = json.loads(result_path.read_text(encoding="utf-8"))

    assert outcome["ok"] is True, outcome["errors"]
    assert outcome["errors"] == []
    assert outcome["validationDeferred"] == [
        {
            "key": "a/b#1",
            "reason": "SUBMIT_READY_EVIDENCE_INCOMPLETE",
            "missing": ["independent_review_passed"],
        }
    ]
    assert finalized["previousCommitSha"] == previous_head
    assert finalized["controllerCommitChangedFiles"] == ["test_runtime.py"]
    assert store.active_task_count() == 0

    with store.connect() as connection:
        connection.execute(
            "DELETE FROM events WHERE opportunity_key='a/b#1' "
            "AND event_type='PR_FOLLOWUP_RESULT_INGESTED'"
        )
    assert store.active_task_count() == 1
    monkeypatch.setattr(MODULE, "controller_review_result", lambda *_args: None)

    repeated = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert repeated["ingested"] == []
    assert store.active_task_count() == 0


def test_validation_prefetch_plan_is_lockfile_scoped(tmp_path):
    worktree = tmp_path / "worktree"
    result_dir = worktree / ".oss-pr-radar"
    go_module = worktree / "gateway"
    ui_root = worktree / "ui"
    result_dir.mkdir(parents=True)
    go_module.mkdir()
    ui_root.mkdir()
    (worktree / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
    (worktree / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (worktree / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    (go_module / "go.mod").write_text("module example.com/gateway\n", encoding="utf-8")
    (go_module / "router.go").write_text("package gateway\n", encoding="utf-8")
    (ui_root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (ui_root / "package.json").write_text("{}\n", encoding="utf-8")
    (ui_root / "app.tsx").write_text("export default 1;\n", encoding="utf-8")
    result = {
        "changedFiles": ["gateway/router.go", "ui/app.tsx"],
        "tests": [
            {
                "command": "CARGO_NET_OFFLINE=true cargo test -p router",
                "exitCode": 101,
                "summary": "offline cache lacks locked dependency",
            },
            {
                "command": "GOPROXY=off go test ./...",
                "exitCode": 1,
                "summary": "module lookup disabled by GOPROXY=off",
            },
            {
                "command": "npm run test",
                "exitCode": 127,
                "summary": "Vitest was unavailable because node_modules is absent",
            },
            {
                "command": "python3 -m pytest tests/test_router.py",
                "exitCode": 1,
                "summary": "pytest is not installed in the prepared environment",
            },
        ],
    }
    raw = json.dumps(result).encode()
    result_path = result_dir / "result.json"
    result_path.write_bytes(raw)

    commands = MODULE._validation_prefetch_commands(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert commands == [
        {
            "kind": "cargo_locked_fetch",
            "cwd": str(worktree.resolve()),
            "argv": ["cargo", "fetch", "--locked"],
        },
        {
            "kind": "go_locked_download",
            "cwd": str(go_module.resolve()),
            "argv": ["go", "mod", "download"],
        },
        {
            "kind": "uv_locked_sync",
            "cwd": str(worktree.resolve()),
            "argv": ["uv", "sync", "--frozen", "--no-install-project"],
        },
        {
            "kind": "npm_locked_install",
            "cwd": str(ui_root.resolve()),
            "argv": [
                "npm",
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
        },
    ]


def test_validation_followup_changed_result_is_retryable_not_an_error(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(tmp_path)
    value = json.loads(result_path.read_text(encoding="utf-8"))
    raw = result_path.read_bytes()
    expected_digest = MODULE._task_result_digest(value, raw)
    store.record_stage("a/b#1", "VALIDATION_PENDING")
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=expected_digest,
        missing=["relevant_tests_green", "independent_review_passed"],
    )

    value["evidence"] = {"summary": "controller was still writing the result"}
    result_path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(MODULE, "controller_review_result", lambda *_args: None)

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["ok"] is True, listed
    assert listed["errors"] == []
    assert listed["candidates"] == []
    assert listed["concurrentDeferred"] == [
        {
            "key": "a/b#1",
            "resultDigest": expected_digest,
            "reason": "VALIDATION_RESULT_CHANGED_AFTER_QUEUE",
            "expectedResultDigest": expected_digest,
            "observedResultDigest": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        }
    ]


def test_validation_prefetch_recognizes_go_vet_and_python_tool_environment_gaps(tmp_path):
    worktree = tmp_path / "worktree"
    result_dir = worktree / ".oss-pr-radar"
    result_dir.mkdir(parents=True)
    (worktree / "go.mod").write_text("module example.com/runtime\n", encoding="utf-8")
    (worktree / "go.sum").write_text("", encoding="utf-8")
    (worktree / "runtime.go").write_text("package runtime\n", encoding="utf-8")
    (worktree / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (worktree / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    result = {
        "changedFiles": ["runtime.go", "runtime.py"],
        "tests": [
            {
                "command": "GOPROXY=off go vet ./...",
                "exitCode": 1,
                "summary": "blocked by uncached dependencies",
            },
            {
                "command": "pyright",
                "exitCode": 1,
                "summary": "full check used an incomplete cached environment",
            },
        ],
    }
    raw = json.dumps(result).encode()
    (result_dir / "result.json").write_bytes(raw)

    commands = MODULE._validation_prefetch_commands(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert [item["kind"] for item in commands] == ["go_locked_download", "uv_locked_sync"]


def test_validation_prefetch_supports_pnpm_and_go_failure_working_directory(tmp_path):
    worktree = tmp_path / "worktree"
    result_dir = worktree / ".oss-pr-radar"
    go_module = worktree / "packages" / "sdk-go"
    source_dir = worktree / "packages" / "extension"
    result_dir.mkdir(parents=True)
    go_module.mkdir(parents=True)
    source_dir.mkdir(parents=True)
    (worktree / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    (worktree / "package.json").write_text("{}\n", encoding="utf-8")
    (go_module / "go.mod").write_text("module example.com/sdk\n", encoding="utf-8")
    (source_dir / "runtime.ts").write_text("export const value = 1;\n", encoding="utf-8")
    result = {
        "changedFiles": ["packages/extension/runtime.ts"],
        "tests": [
            {
                "command": "GOPROXY=off go test ./...",
                "workingDirectory": "packages/sdk-go",
                "exitCode": 1,
                "summary": "module lookup disabled by GOPROXY=off",
            }
        ],
        "evidence": {
            "unverifiedGates": [
                "The pnpm checks were unavailable because node_modules has an incomplete dependency tree."
            ]
        },
    }
    raw = json.dumps(result).encode()
    (result_dir / "result.json").write_bytes(raw)

    commands = MODULE._validation_prefetch_commands(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert [item["kind"] for item in commands] == [
        "go_locked_download",
        "pnpm_locked_install",
    ]
    assert commands[0]["cwd"] == str(go_module.resolve())
    assert commands[1]["argv"] == [
        "pnpm",
        "install",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--prefer-offline",
    ]


def test_validation_prefetch_includes_locked_group_that_provides_missing_pytest(tmp_path):
    worktree = tmp_path / "worktree"
    result_dir = worktree / ".oss-pr-radar"
    result_dir.mkdir(parents=True)
    (worktree / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (worktree / "pyproject.toml").write_text(
        """
[project]
name = "x"
[dependency-groups]
test = ["pytest>=8", "pytest-asyncio>=0.25"]
docs = ["mkdocs>=1"]
""".strip(),
        encoding="utf-8",
    )
    result = {
        "changedFiles": ["runtime.py"],
        "tests": [
            {
                "command": ".venv/bin/python run_tests.py -t test_runtime.py",
                "exitCode": 1,
                "summary": "The repository runner could not find pytest.",
            }
        ],
    }
    raw = json.dumps(result).encode()
    (result_dir / "result.json").write_bytes(raw)

    commands = MODULE._validation_prefetch_commands(
        {
            "worktreePath": str(worktree),
            "resultDigest": hashlib.sha256(raw).hexdigest(),
        }
    )

    assert commands == [
        {
            "kind": "uv_locked_sync",
            "cwd": str(worktree.resolve()),
            "argv": [
                "uv",
                "sync",
                "--frozen",
                "--no-install-project",
                "--group",
                "test",
            ],
        }
    ]


def test_validation_followup_blocks_missing_python_dependencies_without_lockfile(
    tmp_path,
):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["tests"] = [
        {
            "command": "python3 -m pytest test_runtime.py",
            "exitCode": 1,
            "summary": "The prepared worktree has no pytest executable.",
        }
    ]
    raw = json.dumps(value).encode()
    result_path.write_bytes(raw)
    digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert listed["candidates"] == []
    assert listed["environmentBlocked"][0]["key"] == "a/b#1"
    assert listed["environmentBlocked"][0]["reason"] == "DEPENDENCY_ENVIRONMENT_UNAVAILABLE"


def test_validation_followup_reassesses_ci_delegation_once(tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green", "independent_review_passed"),
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["evidence"] = {
        "unverifiedGates": [
            {
                "command": "pre-commit run --files runtime.py",
                "reason": "pre-commit is not installed in the prepared environment",
            },
            "The repository-wide GPU/model suite can run only in remote CI.",
        ]
    }
    result_path.write_text(json.dumps(value), encoding="utf-8")
    _refresh_reproduction_certificate(result_path)

    ingested = MODULE.ingest_task_results(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))
    assert ingested["validationDeferred"]

    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert [item["key"] for item in listed["candidates"]] == ["a/b#1"]
    assert listed["candidates"][0]["policyReassessment"] == (MODULE.VALIDATION_POLICY_REVISION)
    assert listed["environmentBlocked"] == []

    finalized = json.loads(result_path.read_text(encoding="utf-8"))
    finalized.setdefault("evidence", {})["validationPolicyRevision"] = (
        MODULE.VALIDATION_POLICY_REVISION
    )
    result_path.write_text(json.dumps(finalized), encoding="utf-8")
    assert (
        MODULE._validation_policy_reassessment_needed(
            {
                "worktreePath": str(Path(finalized["worktreePath"])),
                "missing": ["relevant_tests_green"],
            }
        )
        is False
    )


def test_validation_prefetch_execution_enforces_command_and_worktree_boundaries(
    monkeypatch, tmp_path
):
    worktree = tmp_path / "worktree"
    package = worktree / "ui"
    package.mkdir(parents=True)
    calls = []

    def fake_command(args, cwd=None, timeout=300, stdin=None):
        calls.append((args, cwd, timeout, stdin))
        return ""

    monkeypatch.setattr(MODULE, "command", fake_command)
    candidate = {"worktreePath": str(worktree)}
    commands = [
        {
            "kind": "npm_locked_install",
            "cwd": str(package),
            "argv": [
                "npm",
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
        }
    ]

    completed = MODULE._execute_validation_prefetch(candidate, commands)

    assert calls == [
        (
            commands[0]["argv"],
            package.resolve(),
            MODULE.VALIDATION_PREFETCH_TIMEOUTS["npm_locked_install"],
            None,
        )
    ]
    assert completed[0]["kind"] == "npm_locked_install"
    assert completed[0]["cwd"] == str(package.resolve())

    with pytest.raises(RuntimeError, match="not allowlisted"):
        MODULE._execute_validation_prefetch(
            candidate,
            [
                {
                    "kind": "npm_locked_install",
                    "cwd": str(package),
                    "argv": ["npm", "install"],
                }
            ],
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(RuntimeError, match="escapes"):
        MODULE._execute_validation_prefetch(
            candidate,
            [
                {
                    "kind": "cargo_locked_fetch",
                    "cwd": str(outside),
                    "argv": ["cargo", "fetch", "--locked"],
                }
            ],
        )


def test_validation_prefetch_timeout_has_structured_failure(monkeypatch, tmp_path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    command = {
        "kind": "npm_locked_install",
        "cwd": str(worktree),
        "argv": ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    }

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(command["argv"], 600)

    monkeypatch.setattr(MODULE, "command", timeout)

    with pytest.raises(MODULE.ValidationPrefetchError) as raised:
        MODULE._execute_validation_prefetch(
            {"worktreePath": str(worktree)},
            [command],
        )

    assert raised.value.failure["failureType"] == "TIMEOUT"
    assert raised.value.failure["timeoutSeconds"] == 600


def test_validation_followup_reserve_runs_prefetch_inside_bridge(monkeypatch, tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("regression_test_verified", "relevant_tests_green"),
    )
    ui_root = worktree / "ui"
    ui_root.mkdir()
    (ui_root / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (ui_root / "package.json").write_text("{}\n", encoding="utf-8")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["changedFiles"] = ["runtime.py", "ui/app.tsx"]
    value["tests"] = [
        {
            "command": "npm run test",
            "exitCode": 127,
            "summary": "Vitest was unavailable because node_modules is absent",
        }
    ]
    raw = json.dumps(value).encode()
    result_path.write_bytes(raw)
    digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["regression_test_verified", "relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})
    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))[
        "candidates"
    ][0]
    assert listed["prefetchRequired"] is True
    assert listed["prefetchMode"] == "bridge_managed"
    assert "prefetchCommands" not in listed
    executed = []

    def fake_execute(candidate, commands):
        executed.extend(commands)
        return [{"kind": commands[0]["kind"], "cwd": commands[0]["cwd"], "durationMs": 1}]

    monkeypatch.setattr(MODULE, "_execute_validation_prefetch", fake_execute)

    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
            prefetch_complete=False,
        )
    )

    assert [item["kind"] for item in executed] == ["npm_locked_install"]
    assert reserved["prefetch"][0]["kind"] == "npm_locked_install"
    assert "系统已按项目锁文件补齐缺失依赖" in reserved["prompt"]


def test_validation_followup_prefetch_failure_is_blocked_without_delivery(monkeypatch, tmp_path):
    store, worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    (worktree / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (worktree / "package.json").write_text("{}\n", encoding="utf-8")
    value = json.loads(result_path.read_text(encoding="utf-8"))
    value["changedFiles"] = ["runtime.ts"]
    value["tests"] = [
        {
            "command": "npm run test",
            "exitCode": 127,
            "summary": "node_modules is absent",
        }
    ]
    raw = json.dumps(value).encode()
    result_path.write_bytes(raw)
    digest = _refresh_reproduction_certificate(result_path)
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})
    failure = {
        "kind": "npm_locked_install",
        "command": "npm ci --ignore-scripts --no-audit --no-fund",
        "summary": "locked dependency prefetch timed out after 600 seconds",
        "failureType": "TIMEOUT",
        "timeoutSeconds": 600,
    }
    monkeypatch.setattr(
        MODULE,
        "_execute_validation_prefetch",
        lambda *_args: (_ for _ in ()).throw(MODULE.ValidationPrefetchError(failure)),
    )

    reserved = MODULE.validation_followup_reserve(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            thread_id="thread-1",
            result_digest=digest,
            prefetch_complete=False,
        )
    )
    listed = MODULE.validation_followup_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert reserved["blocked"] is True
    assert listed["candidates"] == []
    assert listed["environmentBlocked"][0]["reason"] == "DEPENDENCY_PREFETCH_FAILED"
    assert listed["environmentBlocked"][0]["dependencyFailures"] == [failure]
    assert store.unresolved_validation_followups() == []


def test_validation_prefetch_failure_does_not_reserve_followup(monkeypatch, tmp_path):
    store, _worktree, result_path = _controller_commit_result(
        tmp_path,
        missing_quality=("relevant_tests_green",),
    )
    digest = json.loads(result_path.read_text(encoding="utf-8"))["reproductionReceipt"][
        "resultDigest"
    ]
    store.record_validation_deferred(
        "a/b#1",
        thread_id="thread-1",
        result_digest=digest,
        missing=["relevant_tests_green"],
    )
    store.record_stage("a/b#1", "VALIDATION_PENDING", evidence={})

    def fail_prefetch(candidate, commands):
        raise RuntimeError("prefetch failed")

    monkeypatch.setattr(MODULE, "_execute_validation_prefetch", fail_prefetch)

    with pytest.raises(RuntimeError, match="prefetch failed"):
        MODULE.validation_followup_reserve(
            SimpleNamespace(
                ledger=tmp_path / "ledger.sqlite3",
                thread_id="thread-1",
                result_digest=digest,
                prefetch_complete=True,
            )
        )

    assert store.validation_followup_candidates()[0]["resultDigest"] == digest
    assert store.unresolved_validation_followups() == []


def test_privileged_controller_runs_granted_publication_queue(monkeypatch, tmp_path):
    fixture = _legal_queue_publication_fixture(tmp_path)
    request = fixture["request"]

    class Store:
        def publication_work_items(self):
            return [
                {
                    "request_id": "request-1",
                    "request": request,
                }
            ]

        def recover_failed_publication_preflight(self, *_args, **_kwargs):
            return False

        def prepare_ambiguous_publication_effect(self, _request_id, *, action):
            assert action == "push"
            return None

        def prepare_post_push_reconciliation(self, _request_id):
            return None

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args: {"granted": True, "permit": {"permit_id": "permit-1"}},
    )
    monkeypatch.setattr(MODULE, "ensure_fork_remote", lambda *_args: "radar-fork")
    calls = []

    def executor(operation, arguments, *, ledger_path):
        calls.append((operation, arguments, ledger_path))
        if operation == "push":
            return {"ok": True, "reconciled": False}
        return {"ok": True, "prUrl": "https://github.com/a/b/pull/2"}

    monkeypatch.setattr(MODULE, "_executor", executor)
    ledger_path = tmp_path / "ledger.sqlite3"

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=ledger_path))

    assert result["ok"] is True
    assert result["published"][0]["prUrl"] == "https://github.com/a/b/pull/2"
    assert [call[0] for call in calls] == ["push", "create-pr"]
    assert all(call[2] == ledger_path for call in calls)


def test_publication_queue_requires_bound_snapshot_for_task_result(monkeypatch, tmp_path):
    fixture = _legal_queue_publication_fixture(tmp_path)
    live_task_result_request = dict(fixture["request"])
    live_task_result_request.pop("evidenceRawBase64")

    class Store:
        request = live_task_result_request

        def publication_work_items(self):
            return [
                {
                    "request_id": "request-1",
                    "request": self.request,
                }
            ]

        def recover_failed_publication_preflight(self, *_args, **_kwargs):
            return False

        def prepare_ambiguous_publication_effect(self, *_args, **_kwargs):
            return None

        def prepare_post_push_reconciliation(self, *_args, **_kwargs):
            return None

    store = Store()
    controller_calls = []
    broker_calls = []
    executor_calls = []

    def controller_review(_root, _value):
        controller_calls.append(True)
        return {"verdict": "PASS"}

    def broker(*_args, **_kwargs):
        broker_calls.append(True)
        return {"granted": False, "audit": {"reason": "MIGRATED_REQUEST_REVIEWED"}}

    def executor(*_args, **_kwargs):
        executor_calls.append(True)
        pytest.fail("task-result request without a snapshot must not publish")

    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "controller_review_result", controller_review)
    monkeypatch.setattr(MODULE, "broker_publication_request", broker)
    monkeypatch.setattr(MODULE, "_executor", executor)

    missing_snapshot = MODULE.run_publication_queue(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3")
    )

    assert missing_snapshot["published"] == []
    assert missing_snapshot["blocked"] == []
    assert missing_snapshot["errors"] == [
        {
            "requestId": "request-1",
            "error": "task-result publication evidence requires a bound snapshot",
        }
    ]
    assert controller_calls == []
    assert broker_calls == []
    assert executor_calls == []

    store.request = fixture["request"]
    migrated = MODULE.run_publication_queue(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert migrated["errors"] == []
    assert migrated["blocked"] == [
        {"requestId": "request-1", "reason": "MIGRATED_REQUEST_REVIEWED"}
    ]
    assert controller_calls == [True]
    assert broker_calls == [True]
    assert executor_calls == []


def test_publication_queue_blocks_legacy_request_without_private_review(monkeypatch, tmp_path):
    evidence_path = tmp_path / "legacy-result.json"
    raw = json.dumps({"quality": {"independent_review_passed": True}}).encode("utf-8")
    evidence_path.write_bytes(raw)
    recorded = []

    class Store:
        def publication_work_items(self):
            return [
                {
                    "request_id": "request-1",
                    "request": {
                        "evidencePath": str(evidence_path),
                        "evidenceDigest": hashlib.sha256(raw).hexdigest(),
                    },
                }
            ]

        def recover_failed_publication_preflight(self, *_args, **_kwargs):
            return False

        def block_publication_request(self, request_id, reason):
            recorded.append((request_id, reason))

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "controller_review_result", lambda _root, _value: None)
    monkeypatch.setattr(
        MODULE,
        "_executor",
        lambda *_args, **_kwargs: pytest.fail("unreviewed request must not execute"),
    )

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["published"] == []
    assert result["blocked"] == [
        {"requestId": "request-1", "reason": "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED"}
    ]
    assert recorded == [("request-1", "CONTROLLER_INDEPENDENT_REVIEW_REQUIRED")]


def test_publication_cap_blocks_before_push_or_create_pr(monkeypatch, tmp_path):
    ledger_path = tmp_path / "ledger.sqlite3"
    managed = ManagedLedger(ledger_path, ensure_schema=True)
    for number in range(1, 6):
        managed.upsert_pr(
            pr_key=f"a/b#{number}",
            owner="a",
            repo="b",
            number=number,
            head_sha=f"head-{number}",
            pr_url=f"https://github.com/a/b/pull/{number}",
            state="OPEN",
            auto_created=True,
        )
    evidence_path = tmp_path / "result.json"
    evidence = {
        "key": "a/b#6",
        "issueUrl": "https://github.com/a/b/issues/6",
        "commitSha": "a" * 40,
        "branch": "fix-6",
        "worktreePath": str(tmp_path),
        "quality": {"independent_review_passed": True},
    }
    raw = json.dumps(evidence, sort_keys=True).encode("utf-8")
    evidence_path.write_bytes(raw)
    blocked = []

    class Store:
        def publication_work_items(self):
            return [
                {
                    "request_id": "request-6",
                    "request": {
                        "requestId": "request-6",
                        "opportunityKey": "a/b#6",
                        "issueUrl": "https://github.com/a/b/issues/6",
                        "commitSha": "a" * 40,
                        "branch": "fix-6",
                        "worktreePath": str(tmp_path),
                        "evidencePath": str(evidence_path),
                        "evidenceDigest": hashlib.sha256(raw).hexdigest(),
                        "publication": {
                            "headOwner": "Oxygen56",
                            "baseBranch": "main",
                            "title": "fix: six",
                            "bodyPath": str(tmp_path / "body.md"),
                        },
                    },
                }
            ]

        def recover_failed_publication_preflight(self, *_args, **_kwargs):
            return False

        def prepare_ambiguous_publication_effect(self, *_args, **_kwargs):
            return None

        def prepare_post_push_reconciliation(self, *_args, **_kwargs):
            return None

        def block_publication_request(self, request_id, reason):
            blocked.append((request_id, reason))

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "controller_review_result", lambda *_args: {"verdict": "PASS"})
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args: {"granted": True, "permit": {"permit_id": "permit-6"}},
    )
    monkeypatch.setattr(
        MODULE,
        "_executor",
        lambda *_args, **_kwargs: pytest.fail("cap must block before external publication"),
    )

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=ledger_path))

    assert result["published"] == []
    assert result["blocked"] == [{"requestId": "request-6", "reason": "BLOCKED_PRE_TASK"}]
    assert blocked == [("request-6", "BLOCKED_PRE_TASK")]


def test_publication_finalize_failure_reconciles_without_second_create_pr(monkeypatch, tmp_path):
    ledger_path = tmp_path / "ledger.sqlite3"
    managed = ManagedLedger(ledger_path, ensure_schema=True)
    fixture = _legal_queue_publication_fixture(tmp_path, request_id="request-reconcile-queue")
    request = fixture["request"]
    calls = []

    class Store:
        def __init__(self):
            self.external_receipt = None
            self.reconciled = False

        def publication_work_items(self):
            item = {"request_id": "request-reconcile-queue", "request": request}
            if self.external_receipt is not None and not self.reconciled:
                item["externalPublicationReceipt"] = self.external_receipt
            return [item]

        def recover_failed_publication_preflight(self, *_args, **_kwargs):
            return False

        def prepare_ambiguous_publication_effect(self, *_args, **_kwargs):
            return None

        def prepare_post_push_reconciliation(self, *_args, **_kwargs):
            return None

        def mark_managed_publication_reconciled(self, request_id, *, pr_url, head_sha):
            assert request_id == "request-reconcile-queue"
            assert pr_url == self.external_receipt["prUrl"]
            assert head_sha == request["commitSha"]
            self.reconciled = True

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "controller_review_result", lambda *_args: {"verdict": "PASS"})
    monkeypatch.setattr(MODULE, "ensure_fork_remote", lambda *_args: "radar-fork")
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args: {"granted": True, "permit": {"permit_id": "permit-reconcile"}},
    )

    def executor(operation, _arguments, *, ledger_path):
        calls.append(operation)
        if operation == "push":
            return {"ok": True}
        result = {
            "ok": True,
            "prUrl": "https://github.com/a/b/pull/1",
            "headSha": request["commitSha"],
        }
        store.external_receipt = dict(result)
        return result

    monkeypatch.setattr(MODULE, "_executor", executor)
    original_finalize = ManagedLedger.finalize_publication_reservation
    failed = {"value": False}

    def fail_finalize_once(self, **kwargs):
        if not failed["value"]:
            failed["value"] = True
            raise RuntimeError("finalize interrupted")
        return original_finalize(self, **kwargs)

    monkeypatch.setattr(ManagedLedger, "finalize_publication_reservation", fail_finalize_once)
    first = MODULE.run_publication_queue(SimpleNamespace(ledger=ledger_path))
    with managed._connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM managed_prs").fetchone()[0] == 0
        from oss_pr_radar.task_quarantine import record

        record(
            connection,
            opportunity_key="a/b#1",
            reason="ACTIVE_TASK_QUARANTINE",
            dedupe_key="receipt-after-external-effect",
            payload={"test": True},
            created_at="2026-08-20T00:00:00Z",
        )
    # The reconciliation is internal accounting for an already successful
    # create_pr effect.  It must remain completable even when the repository
    # cap is full; no second executor action is allowed.
    for number in range(2, 7):
        managed.upsert_pr(
            pr_key=f"a/b#{number}",
            owner="a",
            repo="b",
            number=number,
            head_sha="c" * 40,
            pr_url=f"https://github.com/a/b/pull/{number}",
            state="OPEN",
            auto_created=False,
        )
    with managed._connection() as connection:
        connection.execute("UPDATE managed_prs SET auto_created=1 WHERE owner='a' AND repo='b'")
    second = MODULE.run_publication_queue(SimpleNamespace(ledger=ledger_path))

    assert first["published"] == []
    assert first["errors"] == [
        {"requestId": "request-reconcile-queue", "error": "finalize interrupted"}
    ]
    assert second["published"] == [
        {
            "requestId": "request-reconcile-queue",
            "key": "a/b#1",
            "prUrl": "https://github.com/a/b/pull/1",
            "pushReconciled": True,
        }
    ]
    assert calls == ["push", "create-pr"]


def test_publication_queue_reconciles_interrupted_push_before_pr_confirmation(
    monkeypatch, tmp_path
):
    fixture = _legal_queue_publication_fixture(tmp_path)
    request = fixture["request"]

    class Store:
        def publication_work_items(self):
            return [
                {
                    "request_id": "request-1",
                    "request": request,
                }
            ]

        def recover_failed_publication_preflight(self, *_args, **_kwargs):
            return False

        def prepare_ambiguous_publication_effect(self, _request_id, *, action):
            assert action == "push"
            return {"pending": False, "permit": {"permit_id": "permit-1"}}

        def prepare_post_push_reconciliation(self, _request_id):
            return {"permit_id": "permit-1"}

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "ensure_fork_remote", lambda *_args: "radar-fork")
    monkeypatch.setattr(
        MODULE,
        "broker_publication_request",
        lambda *_args: pytest.fail("reconciliation must not request a new permit first"),
    )
    calls = []

    def executor(operation, arguments, *, ledger_path):
        calls.append(operation)
        if operation == "push":
            return {"ok": True, "reconciled": True}
        return {"ok": True, "prUrl": "https://github.com/a/b/pull/2"}

    monkeypatch.setattr(MODULE, "_executor", executor)

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert calls == ["push", "create-pr"]


def test_publication_queue_returns_immediately_when_another_executor_holds_lock(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        MODULE.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(BlockingIOError()),
    )

    result = MODULE.run_publication_queue(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {
        "ok": True,
        "busy": True,
        "published": [],
        "pending": [],
        "blocked": [],
        "errors": [],
    }


def test_publication_executor_failure_reports_the_useful_tail(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE,
        "bind_runtime",
        lambda _root: SimpleNamespace(script=lambda _name: Path("publication_executor.py")),
    )
    monkeypatch.setattr(MODULE, "runtime_python", lambda _root: Path(sys.executable))
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["python"],
            1,
            "",
            "Traceback\n" + "x" * 700 + "\nRuntimeError: exact publication failure",
        ),
    )

    with pytest.raises(RuntimeError, match="exact publication failure"):
        MODULE._executor(
            "push",
            [],
            ledger_path=tmp_path / "ledger.sqlite3",
            runtime_root=tmp_path,
        )


def test_bridge_operation_requires_runtime_root_before_dispatch(monkeypatch, capsys):
    monkeypatch.setattr(
        MODULE,
        "run_publication_queue",
        lambda _args: pytest.fail("publication must be gated before dispatch"),
    )
    monkeypatch.setattr(MODULE.sys, "argv", ["local_dispatch_bridge.py", "publication-run"])

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "runtime-root" in result["error"]


def test_fresh_subprocess_bridge_uses_private_home_without_host_root_access(tmp_path):
    home = tmp_path / "home"
    for path in (
        home,
        home / ".config",
        home / ".local" / "share",
        home / ".local" / "state",
        home / ".cache",
        home / ".codex",
    ):
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "CODEX_HOME": str(home / ".codex"),
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        }
    )
    before = _shared_context_inventory(HOST_SHARED_CONTEXT_ROOT)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, runpy; ns=runpy.run_path(%r); "
                "print(json.dumps({'githubRoot': str(ns['GITHUB_ROOT']), "
                "'sharedRoot': str(ns['GITHUB_ROOT'] / ns['TASK_PRIVATE_DIR'] / 'task-contexts')}))"
            )
            % str(SCRIPT),
        ],
        cwd=Path(__file__).parents[1],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    assert json.loads(probe.stdout) == {
        "githubRoot": str(home / "Documents" / "github"),
        "sharedRoot": str(
            home / "Documents" / "github" / MODULE.TASK_PRIVATE_DIR / "task-contexts"
        ),
    }
    assert not (home / "Documents" / "github" / MODULE.TASK_PRIVATE_DIR).exists()
    assert _shared_context_inventory(HOST_SHARED_CONTEXT_ROOT) == before


def test_every_bridge_operation_requires_authorization_before_dispatch(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("missing authorization")),
    )
    monkeypatch.setattr(
        MODULE,
        "list_pending",
        lambda _path: pytest.fail("even read-like CLI operations must be gated"),
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["local_dispatch_bridge.py", "list", "--runtime-root", str(tmp_path)],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "authorization" in result["error"]


def test_bridge_rejects_wrong_release_binding_before_authorization(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        MODULE,
        "bind_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("release mismatch")),
    )
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda *_args: pytest.fail("authorization must not run for an invalid release"),
    )
    monkeypatch.setattr(MODULE, "list_pending", lambda _path: pytest.fail("must fail closed"))
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["local_dispatch_bridge.py", "list", "--runtime-root", str(tmp_path)],
    )

    assert MODULE.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "operational authorization" in result["error"]


def test_authorized_publication_run_reaches_dispatch(monkeypatch, tmp_path, capsys):
    calls = []
    monkeypatch.setattr(MODULE, "bind_runtime", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        MODULE,
        "require_operational_authorization",
        lambda root: calls.append(root),
    )
    monkeypatch.setattr(MODULE, "run_publication_queue", lambda _args: {"ok": True})
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["local_dispatch_bridge.py", "publication-run", "--runtime-root", str(tmp_path)],
    )

    assert MODULE.main() == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True}
    assert calls == [tmp_path.resolve()]


def test_reproduction_probe_entrypoint_uses_existing_managed_schema(tmp_path):
    database = tmp_path / "managed.sqlite3"
    ManagedLedger(database, ensure_schema=True)

    result = MODULE.run_reproduction_probes(SimpleNamespace(ledger=database))

    assert result["ok"] is True
    assert result["count"] == 0
    assert result["processed"] == []


def test_reproduction_probe_entrypoint_persists_missing_profile_failure(tmp_path):
    database = tmp_path / "managed.sqlite3"
    ledger = ManagedLedger(database, ensure_schema=True)
    issue_url = "https://github.com/owner/repo/issues/1"
    ledger.upsert_opportunity(
        opportunity_key="owner/repo#1",
        owner="owner",
        repo="repo",
        issue_number=1,
        issue_url=issue_url,
        state="SYSTEM_PROCESSING",
        source="test",
        provenance={},
        metadata={"selectedBaseSha": "a" * 40, "codePaths": ["src/main.py"]},
    )
    ledger.bind_task(
        task_id="probe-task",
        opportunity_key="owner/repo#1",
        thread_id="thread-1",
        worktree_path=None,
        state="REPRODUCTION_REQUIRED",
    )
    ledger.queue_reproduction_probe(
        task_id="probe-task",
        opportunity_key="owner/repo#1",
        repo="owner/repo",
        issue_url=issue_url,
        default_branch="main",
        selected_base_sha="a" * 40,
        code_paths=["src/main.py"],
        profile_id=None,
        checkout_path=None,
        thread_id="thread-1",
        head_sha="b" * 40,
        commit_sha="b" * 40,
        result_digest="result-digest",
        idempotency_key="probe-intent",
    )

    result = MODULE.run_reproduction_probes(SimpleNamespace(ledger=database))

    assert result["ok"] is True
    assert result["count"] >= 1
    assert all(
        item["state"] == "WAITING_EXTERNAL"
        and item["reason"] == "TRUSTED_PROBE_PROFILE_UNAVAILABLE"
        for item in result["processed"]
    )
    with ledger._connection() as connection:
        row = connection.execute("SELECT state, error FROM managed_reproduction_probes").fetchone()
    assert row["state"] == "WAITING_EXTERNAL"
    assert row["error"] == "TRUSTED_PROBE_PROFILE_UNAVAILABLE"


def test_slow_cycle_quarantine_excludes_bad_result_and_continues_normal_task(monkeypatch, tmp_path):
    """Exercise recovery, ingestion, and the slow cycle with two real tasks."""

    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", tmp_path / "github")
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", tmp_path / "worktrees")
    ledger_path = tmp_path / "state" / "radar_ledger.sqlite3"
    ledger_path.parent.mkdir(parents=True)
    store = RadarLedger(ledger_path)
    now = datetime.now(UTC)

    def add_task(intent_id: str, key: str, issue_url: str, thread_id: str) -> Path:
        worktree = tmp_path / "github" / MODULE.TASK_PRIVATE_DIR / "worktrees" / intent_id
        worktree.mkdir(parents=True)
        run_git(worktree, "init")
        run_git(
            worktree,
            "remote",
            "add",
            "origin",
            f"https://github.com/{key.split('#', 1)[0]}.git",
        )
        (worktree / ".git" / "info" / "exclude").write_text(".oss-pr-radar/\n", encoding="utf-8")
        store.enqueue(
            {
                "intentId": intent_id,
                "key": key,
                "repo": key.split("#", 1)[0],
                "issueNumber": int(key.rsplit("#", 1)[1]),
                "issueUrl": issue_url,
                "title": "Runtime task",
                "mode": "canary",
                "score": 9,
                "snapshotId": "snapshot",
                "decisionDigest": "decision",
                "issuedAt": iso_z(now),
                "expiresAt": iso_z(now + timedelta(hours=1)),
                "autoSubmitAuthorized": True,
                "publicSubmissionAllowed": True,
                "authorizationSource": "signed_live_revalidation_required",
                "publicationMode": "canary",
            }
        )
        store.claim(intent_id, "controller")
        store.commit_dispatch(
            intent_id,
            owner="controller",
            thread_id=thread_id,
            project_id="github",
            worktree_path=str(worktree),
            title_time="08-20 16:03",
        )
        store.record_audit_snapshot(
            key,
            evidence={
                "authorization": {"status": "ALLOW"},
                "evidenceDigest": f"{intent_id}-evidence",
                "liveAudit": {
                    "capturedAt": iso_z(now),
                    "evidence": {"digest": f"{intent_id}-evidence", "issue": {"state": "open"}},
                },
            },
            dedupe_key=f"{intent_id}-audit",
        )
        MODULE.write_task_context(
            store,
            issue_url=issue_url,
            thread_id=thread_id,
            cwd=worktree,
        )
        return worktree

    add_task("intent-bad", "a/b#1", "https://github.com/a/b/issues/1", "thread-bad")
    normal_worktree = add_task(
        "intent-normal", "c/d#2", "https://github.com/c/d/issues/2", "thread-normal"
    )
    bad_context_path = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    bad_context = json.loads(bad_context_path.read_text(encoding="utf-8"))
    bad_context["contextDigest"] = "f" * 64
    MODULE._atomic_json(bad_context_path, bad_context)
    Path(bad_context["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": MODULE.TASK_RESULT_SCHEMA,
                "contextDigest": "f" * 64,
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-bad",
                "worktreePath": str(
                    (
                        tmp_path / "github" / MODULE.TASK_PRIVATE_DIR / "worktrees" / "intent-bad"
                    ).resolve()
                ),
                "stage": "FIX_READY",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )
    normal_context_path = MODULE.shared_context_path("https://github.com/c/d/issues/2")
    normal_context = json.loads(normal_context_path.read_text(encoding="utf-8"))
    Path(normal_context["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": MODULE.TASK_RESULT_SCHEMA,
                "contextDigest": normal_context["contextDigest"],
                "key": "c/d#2",
                "issueUrl": "https://github.com/c/d/issues/2",
                "threadId": "thread-normal",
                "worktreePath": str(normal_worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )
    ManagedLedger(ledger_path, ensure_schema=True)
    assert {item["key"] for item in store.task_result_candidates()} == {"a/b#1", "c/d#2"}
    calls: list[str] = []
    observed: dict[str, object] = {}

    def runner(root: Path, operation: str) -> dict[str, object]:
        calls.append(operation)
        args = SimpleNamespace(ledger=ledger_path)
        if operation == "context-recover":
            value = MODULE.recover_task_contexts(args)
            observed["candidateAfterRecovery"] = store.task_result_candidates()
            return value
        if operation == "ingest-results":
            observed[operation] = MODULE.ingest_task_results(args)
            return observed[operation]
        if operation == "reproduction-probe":
            return MODULE.run_reproduction_probes(args)
        if operation == "publication-run":
            return MODULE.run_publication_queue(args)
        if operation == "publication-feedback-list":
            return MODULE.publication_feedback_list(args)
        return {
            "ok": True,
            "updated": [],
            "renamed": [],
            "archived": [],
            "published": [],
            "pending": [],
            "blocked": [],
            "errors": [],
        }

    result = slow_advance_once(tmp_path, runner=runner)

    assert result["ok"] is True, result
    assert {"context-recover", "ingest-results", "reproduction-probe"} <= set(calls)
    assert result["publicationRequests"] == []
    assert result["published"] == []
    assert any(item["key"] == "a/b#1" for item in result["contextsQuarantined"])
    assert any(item["key"] == "c/d#2" for item in result["resultsIngested"]), {
        "result": result,
        "observed": observed,
    }
    assert store.active_task_quarantine("a/b#1") is not None
    assert store.publication_work_items() == []


def test_real_slow_worker_subprocess_quarantines_history_without_publication(monkeypatch, tmp_path):
    """Run the deployed slow CLI and real bridge subprocess in an isolated home."""

    import plistlib

    import oss_pr_radar.operational_auth as operational_auth
    import scripts.deploy_local_runtime as deploy_local_runtime
    from oss_pr_radar.local_publication import worker_specs
    from oss_pr_radar.managed_security import sign_current
    from oss_pr_radar.operational_auth import (
        consume_worker_staging_authorization,
        finalize_operational_authorization,
        issue_operational_authorization,
        issue_worker_staging_authorization,
        worker_spec_digest,
    )
    from oss_pr_radar.release_binding import verify_release

    home = tmp_path / "home"
    runtime = tmp_path / "runtime"
    github_root = home / "Documents" / "github"
    worktree_root = github_root / MODULE.TASK_PRIVATE_DIR / "worktrees"
    home.mkdir(parents=True, exist_ok=True)
    runtime.mkdir(mode=0o700)
    runtime.chmod(0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    for directory in (
        home / ".config",
        home / ".local" / "share",
        home / ".local" / "state",
        home / ".cache",
        home / ".codex",
    ):
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    monkeypatch.setattr(MODULE, "ROOT", runtime)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", github_root)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", home / ".codex" / "worktrees")
    github_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    github_root.chmod(0o700)
    private_root = github_root / MODULE.TASK_PRIVATE_DIR
    private_root.mkdir(mode=0o700, exist_ok=True)
    private_root.chmod(0o700)
    worktree_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    worktree_root.chmod(0o700)
    ledger_path = runtime / "state" / "ledger-releases" / "managed.sqlite3"
    ledger_path.parent.mkdir(parents=True, mode=0o700)
    ledger_path.parent.chmod(0o700)
    (runtime / "releases").mkdir(mode=0o700)
    (runtime / "releases").chmod(0o700)
    store = RadarLedger(ledger_path)
    ManagedLedger(ledger_path, ensure_schema=True)

    # Build a real immutable release in the temporary runtime.  The child
    # bridge is loaded from this release and therefore exercises the same
    # release binding and operational authorization checks as deployment.
    release_build = runtime / "releases" / ".release-build"
    release_build.mkdir(mode=0o700)
    release_build.chmod(0o700)
    shutil.copytree(
        SCRIPT.parents[1] / "src" / "oss_pr_radar", release_build / "src" / "oss_pr_radar"
    )
    release_bridge = release_build / "scripts" / "local_dispatch_bridge.py"
    release_bridge.parent.mkdir(mode=0o700)
    shutil.copy2(SCRIPT, release_bridge)
    os.chmod(release_bridge, 0o600)
    release_files = {
        path.relative_to(release_build)
        for path in release_build.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    release_manifest = deploy_local_runtime.build_manifest(release_build, release_files, "a" * 40)
    (release_build / "release-manifest.json").write_bytes(
        (json.dumps(release_manifest, sort_keys=True, indent=2) + "\n").encode()
    )
    os.chmod(release_build / "release-manifest.json", 0o600)
    verify_release(release_build, require_directory_identity=False)
    release = runtime / "releases" / str(release_manifest["releaseId"])
    release_build.rename(release)
    os.chmod(release, 0o700)
    (runtime / "current-release").symlink_to(release)

    (runtime / "state" / "current-ledger").symlink_to(Path("ledger-releases") / "managed.sqlite3")
    now = datetime.now(UTC)

    def add_task(intent_id: str, key: str, issue_url: str, thread_id: str) -> Path:
        worktree = worktree_root / intent_id
        worktree.mkdir(parents=True)
        run_git(worktree, "init")
        run_git(
            worktree,
            "remote",
            "add",
            "origin",
            f"https://github.com/{key.split('#', 1)[0]}.git",
        )
        store.enqueue(
            {
                "intentId": intent_id,
                "key": key,
                "repo": key.split("#", 1)[0],
                "issueNumber": int(key.rsplit("#", 1)[1]),
                "issueUrl": issue_url,
                "title": "Runtime task",
                "mode": "canary",
                "score": 9,
                "snapshotId": "snapshot",
                "decisionDigest": "decision",
                "issuedAt": iso_z(now),
                "expiresAt": iso_z(now + timedelta(hours=1)),
                "autoSubmitAuthorized": True,
                "publicSubmissionAllowed": True,
                "authorizationSource": "signed_live_revalidation_required",
                "publicationMode": "canary",
            }
        )
        store.claim(intent_id, "controller")
        store.commit_dispatch(
            intent_id,
            owner="controller",
            thread_id=thread_id,
            project_id="github",
            worktree_path=str(worktree),
            title_time="08-20 16:03",
        )
        store.record_audit_snapshot(
            key,
            evidence={
                "authorization": {"status": "ALLOW"},
                "evidenceDigest": f"{intent_id}-evidence",
                "liveAudit": {
                    "capturedAt": iso_z(now),
                    "evidence": {"digest": f"{intent_id}-evidence", "issue": {"state": "open"}},
                },
            },
            dedupe_key=f"{intent_id}-audit",
        )
        MODULE.write_task_context(store, issue_url=issue_url, thread_id=thread_id, cwd=worktree)
        return worktree

    add_task("intent-bad", "a/b#1", "https://github.com/a/b/issues/1", "thread-bad")
    normal_worktree = add_task(
        "intent-normal", "c/d#2", "https://github.com/c/d/issues/2", "thread-normal"
    )
    bad_context_path = MODULE.shared_context_path("https://github.com/a/b/issues/1")
    bad_context = json.loads(bad_context_path.read_text(encoding="utf-8"))
    bad_context["contextDigest"] = "f" * 64
    MODULE._atomic_json(bad_context_path, bad_context)
    Path(bad_context["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": MODULE.TASK_RESULT_SCHEMA,
                "contextDigest": "f" * 64,
                "key": "a/b#1",
                "issueUrl": "https://github.com/a/b/issues/1",
                "threadId": "thread-bad",
                "worktreePath": str((worktree_root / "intent-bad").resolve()),
                "stage": "FIX_READY",
            }
        ),
        encoding="utf-8",
    )
    normal_context_path = MODULE.shared_context_path("https://github.com/c/d/issues/2")
    normal_context = json.loads(normal_context_path.read_text(encoding="utf-8"))
    Path(normal_context["resultPath"]).write_text(
        json.dumps(
            {
                "schemaVersion": MODULE.TASK_RESULT_SCHEMA,
                "contextDigest": normal_context["contextDigest"],
                "key": "c/d#2",
                "issueUrl": "https://github.com/c/d/issues/2",
                "threadId": "thread-normal",
                "worktreePath": str(normal_worktree.resolve()),
                "stage": "AUDIT_NO_GO",
                "reason": "EVIDENCE_INCOMPLETE",
            }
        ),
        encoding="utf-8",
    )
    thread_db = home / ".codex" / "state_5.sqlite"
    connection = sqlite3.connect(thread_db)
    try:
        connection.execute(
            "CREATE TABLE threads ("
            "id TEXT PRIMARY KEY, title TEXT, archived INTEGER NOT NULL, "
            "updated_at INTEGER NOT NULL, rollout_path TEXT, first_user_message TEXT, "
            "cwd TEXT, git_origin_url TEXT)"
        )
        connection.commit()
    finally:
        connection.close()

    # Create the real stage receipt and long-lived operational authorization;
    # no authentication or runtime-binding function is replaced in the child.
    counts_path = tmp_path / "managed-counts.json"
    current = operational_auth._current_ledger_identity(runtime)
    counts_unsigned = {
        "schema": "oss-pr-radar.stage7-counts-evidence.v1",
        "runtimeRootDigest": operational_auth.runtime_root_digest(runtime),
        "releaseId": str(release_manifest["releaseId"]),
        "releaseHead": "a" * 40,
        "observedAt": iso_z(datetime.now(UTC)),
        "ledgerGeneration": current["generation"],
        "ledgerSha256": current["sha256"],
        "managedPrProjectionDigest": current["managedPrProjectionDigest"],
    }
    counts_path.write_text(
        json.dumps(
            {
                **counts_unsigned,
                **sign_current(counts_unsigned, context="stage7-counts-evidence-v1"),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(counts_path, 0o600)
    specs = worker_specs(release, home=home, runtime_root=runtime)
    issue_worker_staging_authorization(runtime, managed_counts_evidence=counts_path, home=home)
    launch_agents = home / "Library" / "LaunchAgents"
    launch_agents.mkdir(parents=True, mode=0o700)
    worker_records = []
    for spec in specs:
        plist_path = launch_agents / f"{spec['Label']}.plist"
        plist_path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML, sort_keys=True))
        os.chmod(plist_path, 0o600)
        worker_records.append(
            {
                "label": spec["Label"],
                "observedAt": iso_z(datetime.now(UTC)),
                "loaded": False,
                "pid": None,
                "specDigest": worker_spec_digest(specs),
                "plistPath": str(plist_path),
                "plistSha256": hashlib.sha256(plist_path.read_bytes()).hexdigest(),
                "mode": "0o600",
                "ownerUid": os.getuid(),
                "regular": True,
                "symlink": False,
            }
        )
    consume_worker_staging_authorization(runtime, specs=specs, worker_records=worker_records)
    automation_path = tmp_path / "automation-snapshot.json"
    automation_path.write_text('{"schema":"isolated-automation-snapshot"}\n', encoding="utf-8")
    os.chmod(automation_path, 0o600)
    preflight = {
        "ok": True,
        "strictMode": "preflight",
        "managedCountsEvidenceValid": True,
        "stagedWorkerReceiptValid": True,
        "actualAutomationEvidence": {"valid": True},
        "pendingPublicationEffectsValid": True,
        "diskStopThresholdOk": True,
        "runtimeReleasePolicyIdentityMatch": True,
        "noRuntimeCodeDrift": True,
        "noSharedGitWrites": True,
        "dangerousBridgeReachable": False,
        "oldMonolithicWorkerReachable": False,
        "workerSpecDigest": worker_spec_digest(specs),
        "ledger": current,
        "workers": [
            {
                "label": spec["Label"],
                "actualConfigMatch": True,
                "launchConfigMatch": True,
                "loaded": False,
            }
            for spec in specs
        ],
    }
    issue_operational_authorization(
        runtime,
        preflight=preflight,
        managed_counts_evidence=counts_path,
        automation_snapshot=automation_path,
    )
    finalize_operational_authorization(runtime)
    operational_auth.require_operational_authorization(runtime)

    sitecustomize = tmp_path / "sitecustomize.py"
    sitecustomize.write_text(
        """import json, os, subprocess, sys
from pathlib import Path
import oss_pr_radar.local_publication as _publication
from oss_pr_radar.release_binding import runtime_ledger_path
_bridge = Path(os.environ['RADAR_TEST_BRIDGE'])
def _real_bridge(root, operation, **kwargs):
    completed = subprocess.run(
        [sys.executable, str(_bridge), '--runtime-root', str(root),
         '--ledger', str(runtime_ledger_path(root)), operation],
        capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        Path(os.environ['RADAR_BRIDGE_ERROR']).write_text(
            completed.stderr or completed.stdout, encoding='utf-8'
        )
        raise RuntimeError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout)
_publication.run_bridge = _real_bridge
_original_slow = _publication.slow_advance_once
def _slow(root, **kwargs):
    return _original_slow(root, runner=_real_bridge)
_publication.slow_advance_once = _slow
""",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["RADAR_TEST_BRIDGE"] = str(release / "scripts" / "local_dispatch_bridge.py")
    env["RADAR_BRIDGE_ERROR"] = str(tmp_path / "bridge-error.txt")
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path), str(SCRIPT.parents[1] / "src"), str(SCRIPT.parents[1])]
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT.parents[1] / "scripts" / "local_publication_agent.py"),
            "--root",
            str(runtime),
            "--mode",
            "slow",
            "--json",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    bridge_error = (
        (tmp_path / "bridge-error.txt").read_text(encoding="utf-8")
        if (tmp_path / "bridge-error.txt").exists()
        else ""
    )
    assert completed.returncode == 0, bridge_error or completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    assert result["ok"] is True, result
    assert any(item["key"] == "a/b#1" for item in result["contextsQuarantined"])
    assert any(item["key"] == "c/d#2" for item in result["resultsIngested"]), json.dumps(
        result, ensure_ascii=False, indent=2
    )
    assert result["publicationRequests"] == []
    assert result["published"] == []
    assert result["slowWorkerDiagnostic"]["contextRecovery"]["errors"] == 0
    assert result["slowWorkerDiagnostic"]["contextRecovery"]["quarantined"] >= 1


def test_bridge_help_has_no_auth_bypass_option():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "skip-auth" not in completed.stdout
    assert "allow-unreleased-code" not in completed.stdout


def test_task_context_self_reconciles_exact_async_handoff(monkeypatch, tmp_path):
    issue_url = "https://github.com/a/b/issues/1"
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    class Store:
        reconciled = False
        commit_args = None

        def task_context(self, **_kwargs):
            if self.reconciled:
                return {"threadId": "thread-1", "worktreePath": str(worktree)}
            return None

        def commit_orphan_dispatch(self, intent_id, **kwargs):
            self.reconciled = True
            self.commit_args = (intent_id, kwargs)

        def has_live_handoff(self, **_kwargs):
            return True

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(
        MODULE,
        "orphan_list",
        lambda _args: {
            "ok": True,
            "blocked": [],
            "unmatched": [],
            "candidates": [
                {
                    "intentId": "intent-1",
                    "threadId": "thread-1",
                    "issueUrl": issue_url,
                    "repo": "a/b",
                    "cwd": str(worktree),
                    "titleTime": "08-04 18:47",
                    "leaseStartedAt": "2026-08-04T10:47:08Z",
                }
            ],
        },
    )

    result = MODULE.task_context(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            issue_url=issue_url,
            thread_id=None,
            worktree=str(worktree),
            wait_seconds=1,
        )
    )

    assert result["ok"] is True
    assert store.commit_args[0] == "intent-1"
    assert store.commit_args[1]["title_synced_state"] is None


def test_orphan_list_recovers_unique_async_worktree_task(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    cwd = worktree_root / "abcd" / "repo"
    cwd.mkdir(parents=True)
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                str(cwd),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                "https://github.com/a/b.git",
                0,
                int(now.timestamp()),
                int(now.timestamp() * 1000),
            ),
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "LEASED",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(minutes=1)),
                    "leaseUntil": iso_z(now + timedelta(minutes=29)),
                    "expiresAt": iso_z(now + timedelta(hours=1)),
                    "repo": "a/b",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["ok"] is True
    assert result["blocked"] == []
    assert result["candidates"][0]["threadId"] == "thread-1"
    assert result["candidates"][0]["desiredTitle"].startswith("[有价值·处理中]")


def test_duplicate_task_list_only_returns_stale_unbound_raw_tasks(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    project_root = tmp_path / "github"
    project_root.mkdir(exist_ok=True)
    thread_db = tmp_path / "threads.sqlite3"
    prompt = MODULE.issue_prompt("https://github.com/a/b/issues/1")
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                archived INTEGER, created_at INTEGER, updated_at INTEGER,
                thread_source TEXT
            )"""
        )
        rows = [
            ("canonical", str(project_root), "[有价值]", prompt, 0, -300, -60, "app"),
            ("duplicate", str(project_root), "<codex_delegation>raw", prompt, 0, -240, -60, "app"),
            ("recent", str(project_root), "<codex_delegation>raw", prompt, 0, -20, -5, "app"),
            ("archived", str(project_root), "<codex_delegation>raw", prompt, 1, -240, -60, "app"),
            (
                "helper",
                str(project_root),
                "<codex_delegation>raw",
                prompt,
                0,
                -240,
                -60,
                "subagent",
            ),
        ]
        for row in rows:
            connection.execute(
                "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
                row[:5]
                + (
                    int((now + timedelta(minutes=row[5])).timestamp()),
                    int((now + timedelta(minutes=row[6])).timestamp()),
                    row[7],
                ),
            )

    class Store:
        def task_context_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "canonical",
                }
            ]

        def bound_thread_ids(self):
            return {"canonical"}

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)

    result = MODULE.duplicate_task_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=30)
    )

    assert [item["threadId"] for item in result["duplicates"]] == ["duplicate"]
    assert result["duplicates"][0]["canonicalThreadId"] == "canonical"
    assert result["duplicates"][0]["desiredTitle"].startswith("[无价值·重复任务]")

    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "UPDATE threads SET title=? WHERE id=?",
            (result["duplicates"][0]["desiredTitle"], "duplicate"),
        )
    after_rename = MODULE.duplicate_task_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=30)
    )
    assert [item["threadId"] for item in after_rename["duplicates"]] == ["duplicate"]


def test_orphan_list_recovers_thread_created_in_github_project(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    project_root = tmp_path / "github"
    project_root.mkdir(exist_ok=True)
    thread_db = tmp_path / "threads.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-1",
                str(project_root),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                None,
                0,
                int(now.timestamp()),
                int(now.timestamp() * 1000),
            ),
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(minutes=1)),
                    "leaseUntil": iso_z(now + timedelta(minutes=29)),
                    "expiresAt": iso_z(now + timedelta(hours=1)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(minutes=1)),
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "GITHUB_ROOT", project_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    candidate = result["candidates"][0]
    assert candidate["threadId"] == "thread-1"
    assert candidate["workspaceMode"] == "github_project_managed_worktree"
    assert candidate["cwd"] == str(project_root)
    assert candidate["worktreePath"] == str(MODULE.managed_worktree_path("intent-1", "a/b"))


def test_orphan_list_does_not_report_expired_lease_as_active(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "LEASED",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(minutes=31)),
                    "leaseUntil": iso_z(now - timedelta(minutes=1)),
                    "expiresAt": iso_z(now + timedelta(hours=1)),
                    "repo": "a/b",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result == {"ok": True, "candidates": [], "blocked": [], "unmatched": []}


def test_orphan_list_keeps_bound_async_creation_after_lease_expiry(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["candidates"] == []
    unmatched = result["unmatched"][0]
    expected = {
        "intentId": "intent-1",
        "key": "a/b#1",
        "leaseStartedAt": iso_z(now - timedelta(hours=2)),
        "creationStartedAt": iso_z(now - timedelta(hours=2)),
        "clientThreadId": "client-1",
        "creationPending": True,
        "abandonable": True,
    }
    assert {key: unmatched[key] for key in expected} == expected
    assert unmatched["creationAgeMinutes"] >= 119
    assert unmatched["abandonNonce"]


def test_creation_abandon_requires_a_stale_unmatched_bound_request(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        abandoned = None

        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

        def abandon_creation(self, intent_id, **kwargs):
            self.abandoned = (intent_id, kwargs)

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)
    probe = MODULE.orphan_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=70)
    )
    nonce = probe["unmatched"][0]["abandonNonce"]

    result = MODULE.creation_abandon(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            client_thread_id="client-1",
            abandon_nonce=nonce,
            reason="ASYNC_CREATION_NOT_MATERIALIZED",
            min_age_minutes=70,
        )
    )

    assert result["abandoned"] is True
    assert store.abandoned == (
        "intent-1",
        {
            "owner": "controller",
            "creation_token": "token-1",
            "client_thread_id": "client-1",
            "reason": "ASYNC_CREATION_NOT_MATERIALIZED",
            "min_age_minutes": 70,
        },
    )


def test_creation_abandon_accepts_a_stale_unbound_request(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    worktree_root.mkdir()
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )

    class Store:
        abandoned = None

        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": None,
                }
            ]

        def bound_thread_ids(self):
            return set()

        def abandon_creation(self, intent_id, **kwargs):
            self.abandoned = (intent_id, kwargs)

    store = Store()
    monkeypatch.setattr(MODULE, "ledger", lambda _path: store)
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)
    probe = MODULE.orphan_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=70)
    )
    candidate = probe["unmatched"][0]

    result = MODULE.creation_abandon(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            intent_id="intent-1",
            owner="controller",
            client_thread_id=None,
            abandon_nonce=candidate["abandonNonce"],
            reason="CREATION_NOT_MATERIALIZED",
            min_age_minutes=70,
        )
    )

    assert result["abandoned"] is True
    assert store.abandoned[1]["client_thread_id"] is None


def test_orphan_list_blocks_archived_matching_thread(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    cwd = worktree_root / "late" / "repo"
    cwd.mkdir(parents=True)
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-archived",
                str(cwd),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                "https://github.com/a/b.git",
                1,
                int(now.timestamp()),
                int(now.timestamp() * 1000),
            ),
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": None,
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(
        SimpleNamespace(ledger=tmp_path / "ledger.sqlite3", min_age_minutes=70)
    )

    assert result["unmatched"] == []
    assert result["blocked"] == [
        {
            "intentId": "intent-1",
            "key": "a/b#1",
            "reason": "matching_thread_archived",
            "threadIds": ["thread-archived"],
        }
    ]


def test_orphan_list_matches_late_thread_for_creating_intent(monkeypatch, tmp_path):
    now = datetime.now(UTC)
    thread_db = tmp_path / "threads.sqlite3"
    worktree_root = tmp_path / "worktrees"
    cwd = worktree_root / "late" / "repo"
    cwd.mkdir(parents=True)
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            """CREATE TABLE threads (
                id TEXT, cwd TEXT, title TEXT, first_user_message TEXT,
                git_origin_url TEXT, archived INTEGER, created_at INTEGER,
                created_at_ms INTEGER
            )"""
        )
        connection.execute(
            "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
            (
                "thread-late",
                str(cwd),
                "automatic title",
                MODULE.issue_prompt("https://github.com/a/b/issues/1"),
                "https://github.com/a/b.git",
                0,
                int(now.timestamp()),
                int(now.timestamp() * 1000),
            ),
        )

    class Store:
        def orphaned_handoffs(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "title": "Runtime bug",
                    "intentId": "intent-1",
                    "intentStatus": "CREATING",
                    "leaseOwner": "controller",
                    "leaseStartedAt": iso_z(now - timedelta(hours=2)),
                    "leaseUntil": iso_z(now - timedelta(hours=1)),
                    "expiresAt": iso_z(now - timedelta(minutes=30)),
                    "repo": "a/b",
                    "creationStartedAt": iso_z(now - timedelta(hours=2)),
                    "creationToken": "token-1",
                    "clientThreadId": "client-1",
                }
            ]

        def bound_thread_ids(self):
            return set()

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)
    monkeypatch.setattr(MODULE, "WORKTREE_ROOT", worktree_root)

    result = MODULE.orphan_list(SimpleNamespace(ledger=tmp_path / "ledger.sqlite3"))

    assert result["blocked"] == []
    assert result["unmatched"] == []
    assert result["candidates"][0]["threadId"] == "thread-late"


def test_publication_feedback_prompt_reuses_plain_problem_and_requires_exact_reply(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "agent_message",
                    "message": (
                        "修改已完成，正在创建 PR。\n\n"
                        "这次在修：会把逐条命令合并，导致执行失败。\n"
                        "当前状态：本地检查已通过。"
                    ),
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    pr_url = "https://github.com/a/b/pull/9"

    previous = MODULE.latest_agent_message(str(rollout))
    prompt = MODULE.publication_feedback_prompt(pr_url=pr_url, previous_message=previous)

    assert "这次修复：会把逐条命令合并，导致执行失败。" in prompt
    assert f"PR 已创建：{pr_url}" in prompt
    assert MODULE.publication_feedback_materialized(str(rollout), pr_url) is False
    with rollout.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n"
            + json.dumps(
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "agent_message",
                        "message": f"PR 已创建：{pr_url}\n\n你无需操作。",
                    },
                },
                ensure_ascii=False,
            )
        )
    assert MODULE.publication_feedback_materialized(str(rollout), pr_url) is True


def test_publication_feedback_list_reconciles_an_existing_visible_reply(monkeypatch, tmp_path):
    pr_url = "https://github.com/a/b/pull/9"
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(
        json.dumps(
            {
                "type": "event_msg",
                "payload": {
                    "type": "agent_message",
                    "message": f"PR 已创建：{pr_url}\n\n你无需操作。",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    thread_db = tmp_path / "state.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute("INSERT INTO threads VALUES ('thread-1',0,?)", (str(rollout),))
    acknowledgements = []

    class Store:
        def publication_feedback_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": "/tmp/worktree",
                    "prUrl": pr_url,
                    "publishedAt": "2026-08-17T00:00:00Z",
                }
            ]

        def unresolved_publication_feedback(self):
            return []

        def acknowledge_publication_feedback(self, **kwargs):
            acknowledgements.append(kwargs)

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    result = MODULE.publication_feedback_list(SimpleNamespace(ledger=tmp_path / "ledger"))

    assert result["candidates"] == []
    assert result["reconciled"][0]["prUrl"] == pr_url
    assert acknowledgements == [{"thread_id": "thread-1", "pr_url": pr_url}]


def test_publication_feedback_list_reconciles_stale_archived_history(monkeypatch, tmp_path):
    pr_url = "https://github.com/a/b/pull/9"
    thread_db = tmp_path / "state.sqlite3"
    with sqlite3.connect(thread_db) as connection:
        connection.execute(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, archived INTEGER, rollout_path TEXT)"
        )
        connection.execute("INSERT INTO threads VALUES ('thread-1',1,NULL)")
    acknowledgements = []

    class Store:
        def publication_feedback_candidates(self):
            return [
                {
                    "key": "a/b#1",
                    "issueUrl": "https://github.com/a/b/issues/1",
                    "threadId": "thread-1",
                    "worktreePath": "/tmp/worktree",
                    "prUrl": pr_url,
                    "publishedAt": iso_z(datetime.now(UTC) - timedelta(days=2)),
                }
            ]

        def unresolved_publication_feedback(self):
            return []

        def acknowledge_publication_feedback(self, **kwargs):
            acknowledgements.append(kwargs)

    monkeypatch.setattr(MODULE, "ledger", lambda _path: Store())
    monkeypatch.setattr(MODULE, "THREAD_DB", thread_db)

    result = MODULE.publication_feedback_list(SimpleNamespace(ledger=tmp_path / "ledger"))

    assert result["blocked"] == []
    assert result["reconciled"] == [
        {
            "key": "a/b#1",
            "threadId": "thread-1",
            "prUrl": pr_url,
            "reason": "STALE_STATUS_BACKFILL_SKIPPED",
        }
    ]
    assert acknowledgements == [
        {
            "thread_id": "thread-1",
            "pr_url": pr_url,
            "reason": "STALE_STATUS_BACKFILL_SKIPPED",
        }
    ]


def test_event_drain_prioritizes_visible_publication_feedback(monkeypatch, tmp_path):
    monkeypatch.setattr(
        MODULE, "restore_reconcile", lambda _args: {"ok": True, "restored": [], "errors": []}
    )
    monkeypatch.setattr(MODULE, "ledger", lambda _path: object())
    monkeypatch.setattr(MODULE, "_rearm_negative_followup_deliveries", lambda _store: [])
    monkeypatch.setattr(MODULE, "_rearm_interrupted_recovery_turns", lambda _store: ([], []))
    monkeypatch.setattr(
        MODULE,
        "publication_feedback_list",
        lambda _args: {
            "candidates": [
                {
                    "key": "a/b#1",
                    "threadId": "thread-1",
                    "prUrl": "https://github.com/a/b/pull/9",
                }
            ]
        },
    )
    monkeypatch.setattr(
        MODULE,
        "publication_feedback_reserve",
        lambda _args: {"ok": True, "reservationNonce": "nonce-1"},
    )
    monkeypatch.setattr(
        MODULE,
        "publication_feedback_deliver",
        lambda _args: {"ok": True, "visibleReplyVerified": True},
    )
    monkeypatch.setattr(
        MODULE,
        "pr_followup_list",
        lambda _args: pytest.fail("PR work must wait until the visible link is synced"),
    )

    result = MODULE.drain_once(
        SimpleNamespace(
            ledger=tmp_path / "ledger.sqlite3",
            project_id="github",
            owner="event-drain",
        )
    )

    assert result["action"] == "publication_feedback_dispatched"
    assert result["prUrl"] == "https://github.com/a/b/pull/9"


def test_guarded_task_popen_blocks_active_quarantine_before_process_start(tmp_path):
    class GuardedStore:
        path = tmp_path / "ledger.sqlite3"

        @staticmethod
        def active_task_quarantine(_key):
            return {"reason": "ACTIVE_TASK_QUARANTINE"}

    with pytest.raises(PermissionError, match="active quarantine"):
        MODULE._guarded_task_popen(
            GuardedStore(),
            opportunity_key="example/project#1",
            argv=[sys.executable, "-c", "raise SystemExit(1)"],
            cwd=tmp_path,
        )
