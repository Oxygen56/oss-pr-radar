from __future__ import annotations

import hashlib
import os
from copy import deepcopy
from pathlib import Path

import pytest

from oss_pr_radar.operational_auth import _verify_worker_plist_bindings

_CORE_LABELS = (
    "com.oss-pr-radar.local-publication",
    "com.oss-pr-radar.local-publication-slow",
    "com.oss-pr-radar.queue-importer",
)


def _bindings(root: Path, count: int) -> list[dict[str, object]]:
    result = []
    for index in range(count):
        path = root / f"worker-{index}.plist"
        path.write_bytes(f"worker-{index}\n".encode())
        path.chmod(0o600)
        result.append(
            {
                "label": (
                    _CORE_LABELS[index]
                    if index < len(_CORE_LABELS)
                    else f"com.oss-pr-radar.future-worker-{index}"
                ),
                "plistPath": str(path),
                "plistSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": "0o600",
                "ownerUid": os.getuid(),
                "regular": True,
                "symlink": False,
            }
        )
    return result


@pytest.mark.parametrize("count", [3, 4, 7])
def test_worker_plist_bindings_accept_core_and_future_complete_sets(
    tmp_path: Path, count: int
) -> None:
    assert _verify_worker_plist_bindings(_bindings(tmp_path, count)) is True


@pytest.mark.parametrize("missing_label", _CORE_LABELS)
def test_worker_plist_bindings_reject_sets_missing_a_core_worker(
    tmp_path: Path, missing_label: str
) -> None:
    bindings = [item for item in _bindings(tmp_path, 4) if item["label"] != missing_label]
    assert _verify_worker_plist_bindings(bindings) is False


def test_worker_plist_bindings_reject_arbitrary_single_worker(tmp_path: Path) -> None:
    binding = _bindings(tmp_path, 4)[-1]
    assert _verify_worker_plist_bindings([binding]) is False


def test_worker_plist_bindings_reject_empty_duplicate_and_malformed_sets(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path, 3)
    assert _verify_worker_plist_bindings([]) is False

    duplicate_label = deepcopy(bindings)
    duplicate_label[1]["label"] = duplicate_label[0]["label"]
    assert _verify_worker_plist_bindings(duplicate_label) is False

    duplicate_path = deepcopy(bindings)
    duplicate_path[1]["plistPath"] = duplicate_path[0]["plistPath"]
    duplicate_path[1]["plistSha256"] = duplicate_path[0]["plistSha256"]
    assert _verify_worker_plist_bindings(duplicate_path) is False

    missing_field = deepcopy(bindings)
    del missing_field[0]["plistSha256"]
    assert _verify_worker_plist_bindings(missing_field) is False

    bad_digest = deepcopy(bindings)
    bad_digest[0]["plistSha256"] = "not-a-digest"
    assert _verify_worker_plist_bindings(bad_digest) is False
