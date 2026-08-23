from __future__ import annotations

from pathlib import Path

import oss_pr_radar.release_binding as binding


def test_inactive_event_release_is_pinned_without_consulting_current_pointer(tmp_path, monkeypatch):
    releases = tmp_path / "releases"
    releases.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    old = releases / "old-release"
    event = releases / "event-release"
    old.mkdir(mode=0o700)
    event.mkdir(mode=0o700)
    monkeypatch.setattr(
        binding,
        "verify_release",
        lambda path: {"releaseId": path.name, "commit": "a" * 40, "manifestSha256": "event"},
    )
    monkeypatch.setattr(
        binding,
        "active_release",
        lambda _root: (_ for _ in ()).throw(AssertionError("current-release must not be consulted")),
    )
    result = binding.bind_verified_release(tmp_path, event)
    assert result.code_root == Path(event)
    assert result.release["releaseId"] == "event-release"
