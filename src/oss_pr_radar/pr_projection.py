"""Canonical, non-public PR identity projection used by migration gates."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .util import sha256_json


def _key_parts(key: str) -> tuple[str, str, int]:
    owner_repo, number_text = key.rsplit("#", 1)
    owner, repo = owner_repo.split("/", 1)
    number = int(number_text)
    if not owner or not repo or number < 1 or str(number) != number_text:
        raise ValueError(f"invalid managed PR key: {key}")
    return owner, repo, number


def canonical_pr_projection(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        key = str(record.get("prKey") or record.get("pr_key") or "")
        if not key or key in seen:
            raise ValueError(f"duplicate or missing managed PR key: {key}")
        seen.add(key)
        owner = record.get("owner")
        repo = record.get("repo")
        number = record.get("number")
        if owner is None or repo is None or number is None:
            owner, repo, number = _key_parts(key)
        else:
            number = int(number)
        expected_key = f"{owner}/{repo}#{number}"
        if expected_key != key:
            raise ValueError(f"managed PR identity does not match key: {key}")
        state = record.get("state")
        if state not in {"OPEN", "CLOSED", "MERGED"}:
            raise ValueError(f"invalid managed PR state: {key}")
        projected.append(
            {
                "owner": str(owner),
                "repo": str(repo),
                "number": number,
                "state": state,
                "prUrl": record.get("prUrl", record.get("url")) or None,
                "headSha": record.get("headSha", record.get("head_sha")) or None,
            }
        )
    return sorted(projected, key=lambda item: (item["owner"], item["repo"], item["number"]))


def projection_digest(records: Iterable[dict[str, Any]]) -> str:
    return sha256_json(canonical_pr_projection(records))


def projection_summary(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    projected = canonical_pr_projection(records)
    return {
        "count": len(projected),
        "stateCounts": {
            state: sum(item["state"] == state for item in projected)
            for state in ("OPEN", "CLOSED", "MERGED")
        },
        "digest": sha256_json(projected),
    }


def ledger_projection(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT pr_key,owner,repo,number,state,pr_url,head_sha FROM managed_prs ORDER BY pr_key"
        ).fetchall()
        return projection_summary(
            {
                "pr_key": row["pr_key"],
                "owner": row["owner"],
                "repo": row["repo"],
                "number": row["number"],
                "state": row["state"],
                "prUrl": row["pr_url"],
                "headSha": row["head_sha"],
            }
            for row in rows
        )
    finally:
        connection.close()
