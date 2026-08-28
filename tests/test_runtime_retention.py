from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from oss_pr_radar import runtime_retention
from oss_pr_radar.local_publication import fast_advance_once
from oss_pr_radar.runtime_retention import (
    RetentionError,
    apply_runtime_retention,
    maybe_reclaim_runtime_storage,
    plan_runtime_retention,
    restore_runtime_archive,
)


def _stage6_run(
    root: Path,
    name: str,
    *,
    mtime: float,
    payload: bytes = b"x" * 20_000,
    complete: bool = True,
) -> Path:
    run = root / "reports" / "stage6" / name
    run.mkdir(parents=True)
    (run / "stage6-public-envelope.json").write_text("{}\n", encoding="utf-8")
    if complete:
        (run / "stage6-public-summary.json").write_text("{}\n", encoding="utf-8")
    (run / "source-ledger.sqlite3").write_bytes(payload)
    for path in [*run.rglob("*"), run]:
        os.utime(path, (mtime, mtime), follow_symlinks=False)
    return run


def test_plan_protects_active_recent_latest_referenced_and_incomplete(monkeypatch, tmp_path):
    now = time.time()
    old = now - 3 * 24 * 60 * 60
    _stage6_run(tmp_path, "deadbeef-20260819T000000Z", mtime=old)
    _stage6_run(tmp_path, "abc12345-20260820T000000Z", mtime=old + 1)
    _stage6_run(tmp_path, "feedface-20260820T010000Z", mtime=old + 2)
    _stage6_run(tmp_path, "badc0ffe-20260820T020000Z", mtime=old + 3, complete=False)
    _stage6_run(tmp_path, "cafeaffe-20260828T000000Z", mtime=now - 60)
    _stage6_run(tmp_path, "decafbad-20260821T000000Z", mtime=old + 4)
    stage7 = tmp_path / "reports" / "stage7"
    stage7.mkdir()
    (stage7 / "current.json").write_text(
        json.dumps(
            {
                "source": str(
                    tmp_path
                    / "reports"
                    / "stage6"
                    / "feedface-20260820T010000Z"
                    / "stage6-public-envelope.json"
                )
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": True, "releaseId": "abc12345-release"},
    )

    plan = plan_runtime_retention(
        tmp_path,
        now=now,
        min_age_seconds=24 * 60 * 60,
        keep_latest=1,
    )

    assert {item["name"] for item in plan["candidates"]} == {
        "deadbeef-20260819T000000Z",
        "decafbad-20260821T000000Z",
    }
    protected = {item["name"]: set(item["reasons"]) for item in plan["protected"]}
    assert "active_release" in protected["abc12345-20260820T000000Z"]
    assert "active_evidence_reference" in protected["feedface-20260820T010000Z"]
    assert "incomplete_stage6_output" in protected["badc0ffe-20260820T020000Z"]
    assert "too_recent" in protected["cafeaffe-20260828T000000Z"]
    assert "newest_runs" in protected["cafeaffe-20260828T000000Z"]
    # The second-newest eligible run remains eligible because keep_latest=1.
    assert "decafbad-20260821T000000Z" not in {item["name"] for item in plan["protected"]}


def test_plan_does_not_pin_expired_historical_stage7_reference(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 8 * 24 * 60 * 60,
    )
    stage7 = tmp_path / "reports" / "stage7"
    stage7.mkdir()
    old_report = stage7 / "historical.json"
    old_report.write_text(json.dumps({"source": str(run)}), encoding="utf-8")
    os.utime(old_report, (now - 8 * 24 * 60 * 60, now - 8 * 24 * 60 * 60))
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )

    plan = plan_runtime_retention(
        tmp_path,
        now=now,
        min_age_seconds=24 * 60 * 60,
        keep_latest=0,
    )

    assert {item["name"] for item in plan["candidates"]} == {run.name}


def test_plan_fails_closed_when_stage7_root_is_replaced_by_symlink(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
    )
    stage7 = tmp_path / "reports" / "stage7"
    stage7.mkdir()
    stage7.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    stage7.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )

    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)

    assert plan["candidates"] == []
    assert "managed" not in str(run)


def test_apply_archives_verifies_removes_and_can_restore(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
        payload=b"repeatable" * 100_000,
    )
    expected = (run / "source-ledger.sqlite3").read_bytes()
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(
        tmp_path,
        now=now,
        min_age_seconds=1,
        keep_latest=0,
    )

    result = apply_runtime_retention(
        tmp_path, plan=plan, now=now, keep_latest=0, min_age_seconds=1, max_candidates=1
    )

    assert result["ok"] is True
    assert result["operations"][0]["status"] == "archived_and_removed"
    assert result["freedBytes"] > 0
    assert not run.exists()
    archive = tmp_path / result["operations"][0]["archive"]
    assert archive.is_file()
    state = json.loads((tmp_path / "state" / "runtime-retention.json").read_text())
    assert state["operations"][-1]["freedBytes"] == result["freedBytes"]

    restored = restore_runtime_archive(tmp_path, archive)

    assert restored == {"ok": True, "restored": "reports/stage6/deadbeef-20260819T000000Z"}
    assert (run / "source-ledger.sqlite3").read_bytes() == expected


def test_apply_keeps_source_if_it_changes_during_archive(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
        payload=b"repeatable" * 20_000,
    )
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)
    from oss_pr_radar import runtime_retention

    original = runtime_retention._archive_inventory

    def mutate_after_archive(archive: Path, candidate_name: str):
        inventory = original(archive, candidate_name)
        (run / "late-write.txt").write_text("changed", encoding="utf-8")
        return inventory

    monkeypatch.setattr(runtime_retention, "_archive_inventory", mutate_after_archive)

    result = apply_runtime_retention(
        tmp_path, plan=plan, now=now, keep_latest=0, min_age_seconds=1, max_candidates=1
    )

    assert result["operations"][0]["status"] == "kept_source_changed"
    assert run.is_dir()
    assert list((tmp_path / "reports" / "stage6-archives").glob("*.tar.gz")) == []


def test_apply_preserves_verified_archive_if_source_removal_reports_failure(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
        payload=b"repeatable" * 100_000,
    )
    monkeypatch.setattr(
        runtime_retention,
        "active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)
    real_rmtree = runtime_retention.shutil.rmtree

    def remove_then_report_failure(path, *args, **kwargs):
        real_rmtree(path, *args, **kwargs)
        raise OSError("post-delete reporting failure")

    monkeypatch.setattr(runtime_retention.shutil, "rmtree", remove_then_report_failure)

    result = apply_runtime_retention(
        tmp_path, plan=plan, now=now, keep_latest=0, min_age_seconds=1, max_candidates=1
    )

    operation = result["operations"][0]
    assert operation["status"] == "failed_closed"
    assert not run.exists()
    assert (tmp_path / operation["archive"]).is_file()


def test_prune_keeps_archive_when_inventory_digest_or_source_reference_is_untrusted(
    monkeypatch, tmp_path
):
    now = time.time()
    _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
        payload=b"repeatable" * 100_000,
    )
    monkeypatch.setattr(
        runtime_retention,
        "active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)
    created = apply_runtime_retention(
        tmp_path,
        plan=plan,
        now=now,
        min_age_seconds=1,
        keep_latest=0,
        max_candidates=1,
    )
    archive = tmp_path / created["operations"][0]["archive"]
    old = now - 8 * 24 * 60 * 60
    os.utime(archive, (old, old))
    stage7 = tmp_path / "reports" / "stage7"
    stage7.mkdir()
    (stage7 / "source-reference.json").write_text(
        json.dumps({"source": "reports/stage6/deadbeef-20260819T000000Z"}),
        encoding="utf-8",
    )

    result = apply_runtime_retention(
        tmp_path,
        plan={"candidates": []},
        now=now,
        min_age_seconds=1,
        keep_latest=0,
        max_candidates=0,
        archive_min_age_seconds=7 * 24 * 60 * 60,
        archive_keep_latest=0,
        max_archives=20,
    )

    assert archive.exists()
    assert any(item["status"] == "kept_evidence_reference" for item in result["operations"])

    (stage7 / "source-reference.json").unlink()
    state_path = tmp_path / "state" / "runtime-retention.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    for entry in state["operations"]:
        if isinstance(entry, dict) and isinstance(entry.get("operations"), list):
            for operation in entry["operations"]:
                if operation.get("status") == "archived_and_removed":
                    operation["inventorySha256"] = "0" * 64
    state_path.write_text(json.dumps(state), encoding="utf-8")

    result = apply_runtime_retention(
        tmp_path,
        plan={"candidates": []},
        now=now,
        min_age_seconds=1,
        keep_latest=0,
        max_candidates=0,
        archive_min_age_seconds=7 * 24 * 60 * 60,
        archive_keep_latest=0,
        max_archives=20,
    )
    assert archive.exists()
    assert any(item["status"] == "kept_unverified" for item in result["operations"])


def test_pressure_reclaim_fails_closed_when_state_root_is_symlink(monkeypatch, tmp_path):
    state = tmp_path / "state"
    outside = tmp_path / "outside"
    outside.mkdir()
    state.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(
        runtime_retention,
        "require_operational_authorization",
        lambda _root: {"state": "ACTIVE"},
    )

    result = maybe_reclaim_runtime_storage(tmp_path, disk={"level": "stop"})

    assert result["ok"] is False
    assert result["reason"] == "retention_failed_closed"
    assert list(outside.iterdir()) == []


def test_restore_rejects_symlinked_stage6_root(monkeypatch, tmp_path):
    now = time.time()
    _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
        payload=b"repeatable" * 100_000,
    )
    monkeypatch.setattr(
        runtime_retention,
        "active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)
    created = apply_runtime_retention(
        tmp_path, plan=plan, now=now, keep_latest=0, min_age_seconds=1, max_candidates=1
    )
    archive = tmp_path / created["operations"][0]["archive"]
    stage6 = tmp_path / "reports" / "stage6"
    stage6.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    stage6.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RetentionError):
        restore_runtime_archive(tmp_path, archive)
    assert list(outside.iterdir()) == []


def test_apply_rechecks_plan_when_release_becomes_active(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
    )
    release = {"valid": False}
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: release,
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)
    release.update({"valid": True, "releaseId": "deadbeef-live"})

    result = apply_runtime_retention(
        tmp_path, plan=plan, now=now, keep_latest=0, min_age_seconds=1, max_candidates=1
    )

    assert result["operations"] == [
        {"path": "reports/stage6/deadbeef-20260819T000000Z", "status": "skipped_stale_plan"}
    ]
    assert run.is_dir()


def test_apply_fails_closed_on_symlink_inside_candidate(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
    )
    (run / "link").symlink_to(tmp_path / "outside")
    os.utime(run, (now - 3 * 24 * 60 * 60, now - 3 * 24 * 60 * 60))
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)

    result = apply_runtime_retention(
        tmp_path, plan=plan, now=now, keep_latest=0, min_age_seconds=1, max_candidates=1
    )

    assert result["ok"] is False
    assert result["operations"][0]["status"] == "failed_closed"
    assert run.is_dir()


def test_pressure_reclaim_is_noop_without_pressure(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
    )
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )

    result = maybe_reclaim_runtime_storage(tmp_path, disk={"level": "ok"}, now=now)

    assert result["attempted"] is False
    assert result["reason"] == "disk_not_under_pressure"
    assert run.is_dir()


def test_pressure_reclaim_requires_fresh_operational_authorization(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
    )
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.require_operational_authorization",
        lambda _root: (_ for _ in ()).throw(RuntimeError("authorization expired")),
    )

    result = maybe_reclaim_runtime_storage(tmp_path, disk={"level": "stop"}, now=now)

    assert result["attempted"] is False
    assert result["ok"] is False
    assert result["reason"] == "operational_authorization_required"
    assert run.is_dir()


def test_apply_prunes_only_verified_old_managed_archives(monkeypatch, tmp_path):
    now = time.time()
    run = _stage6_run(
        tmp_path,
        "deadbeef-20260819T000000Z",
        mtime=now - 3 * 24 * 60 * 60,
        payload=b"repeatable" * 100_000,
    )
    monkeypatch.setattr(
        "oss_pr_radar.runtime_retention.active_release_evidence",
        lambda _root: {"valid": False},
    )
    plan = plan_runtime_retention(tmp_path, now=now, min_age_seconds=1, keep_latest=0)
    created = apply_runtime_retention(
        tmp_path,
        plan=plan,
        now=now,
        min_age_seconds=1,
        keep_latest=0,
        max_candidates=1,
        archive_min_age_seconds=7 * 24 * 60 * 60,
        archive_keep_latest=3,
        max_archives=20,
    )
    archive = tmp_path / created["operations"][0]["archive"]
    old = now - 8 * 24 * 60 * 60
    os.utime(archive, (old, old))
    unmanaged = tmp_path / "reports" / "stage6-archives" / "unmanaged.tar.gz"
    unmanaged.write_bytes(b"not a managed archive")
    os.utime(unmanaged, (old, old))

    result = apply_runtime_retention(
        tmp_path,
        plan={"candidates": []},
        now=now,
        min_age_seconds=1,
        keep_latest=0,
        max_candidates=0,
        archive_min_age_seconds=7 * 24 * 60 * 60,
        archive_keep_latest=0,
        max_archives=20,
    )

    assert any(item["status"] == "archive_pruned" for item in result["operations"])
    assert not archive.exists()
    assert unmanaged.exists()
    assert not run.exists()


def test_fast_worker_rechecks_disk_after_retention(monkeypatch, tmp_path):
    snapshots = iter([{"level": "stop"}, {"level": "ok"}])
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.disk_snapshot", lambda _root: next(snapshots)
    )
    monkeypatch.setattr(
        "oss_pr_radar.local_publication.maybe_reclaim_runtime_storage",
        lambda _root, *, disk: {
            "attempted": True,
            "ok": True,
            "freedBytes": 123,
            "beforeDisk": disk,
        },
    )
    calls: list[str] = []

    def runner(_root: Path, operation: str):
        calls.append(operation)
        return {"ok": True, "queued": [], "errors": []}

    result = fast_advance_once(tmp_path, runner=runner)

    assert result["ok"] is True
    assert result["storageMaintenance"]["freedBytes"] == 123
    assert calls == ["local-receipt-enqueue"]
