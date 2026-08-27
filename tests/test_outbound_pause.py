from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

import oss_pr_radar.outbound_pause as module
from oss_pr_radar.util import iso_z


def test_outbound_effect_lock_is_distinct_from_publication_queue_lock(tmp_path):
    ledger = tmp_path / "radar_ledger.sqlite3"

    assert module.outbound_effect_lock_path(ledger).name == "radar_ledger.outbound.lock"
    assert module.outbound_effect_lock_path(ledger) != ledger.with_suffix(".publication.lock")


def test_expired_pause_remains_active_until_explicit_resume(monkeypatch, tmp_path):
    release = tmp_path / "releases" / "release-1"
    release.mkdir(parents=True)
    state = tmp_path / "state"
    state.mkdir()
    path = state / module.OUTBOUND_PAUSE_FILENAME
    path.write_text(
        json.dumps(
            {
                "schemaVersion": module.OUTBOUND_PAUSE_SCHEMA,
                "paused": True,
                "reason": "MAINTENANCE",
                "createdAt": iso_z(datetime.now(UTC) - timedelta(hours=2)),
                "expiresAt": iso_z(datetime.now(UTC) - timedelta(hours=1)),
                "releaseId": "release-1",
                "releasePath": str(release),
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    monkeypatch.setattr(
        module,
        "active_release",
        lambda _root: (release, {"releaseId": "release-1"}),
    )

    pause = module.active_outbound_pause(tmp_path)

    assert pause is not None
    assert pause["expired"] is True
    with pytest.raises(PermissionError, match="GITHUB_OUTBOUND_PAUSED_EXPIRED"):
        module.require_outbound_effects_allowed(tmp_path)
