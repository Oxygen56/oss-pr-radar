"""Authoritative live PR snapshots for the Stage 6 migration boundary."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .github_client import GitHubClient
from .legacy_migration import import_legacy_history
from .managed_lifecycle import import_open_pr_observations, migrate_schema
from .pr_projection import projection_summary
from .stage6_rehearsal import (
    QuiescenceError,
    source_generation,
    stable_sqlite_copy,
)
from .util import canonical_json, iso_z, utc_now

LIVE_PR_SNAPSHOT_SCHEMA = "oss-pr-radar.stage6.live-pr-states.v1"
MAX_WORKERS = 16
MAX_SNAPSHOT_AGE = timedelta(minutes=30)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _reports_digest(path: Path) -> dict[str, Any]:
    if not path.is_dir():
        raise ValueError("legacy reports directory is missing")
    files = []
    for item in sorted(path.iterdir(), key=lambda candidate: candidate.name):
        if not item.is_file():
            continue
        files.append(
            {
                "name": item.name,
                "bytes": item.stat().st_size,
                "sha256": _sha256_file(item),
            }
        )
    return {"files": files, "sha256": _sha256_bytes(canonical_json(files).encode("utf-8"))}


def input_digests(legacy_db: Path, legacy_reports: Path, followup: Path) -> dict[str, Any]:
    """Digest every non-source input consumed by the shared pre-migration."""

    if not legacy_db.is_file():
        raise ValueError("legacy War Room database is missing")
    if not followup.is_file():
        raise ValueError("follow-up snapshot is missing")
    return {
        # The main SQLite file is not the complete logical input while WAL is
        # active.  source_generation() reads a consistent SQLite backup and
        # therefore binds the rows consumed by the migration, not just the
        # primary file bytes.
        "legacyDb": {"sourceGeneration": source_generation(legacy_db)},
        "legacyReports": _reports_digest(legacy_reports),
        "followup": {"bytes": followup.stat().st_size, "sha256": _sha256_file(followup)},
    }


def input_binding(
    source: Path,
    legacy_db: Path,
    legacy_reports: Path,
    followup: Path,
) -> dict[str, Any]:
    return {
        "sourceGeneration": source_generation(source),
        "inputDigests": input_digests(legacy_db, legacy_reports, followup),
    }


def _followup_items(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError("follow-up snapshot must contain an items list")
    items = []
    for item in value["items"]:
        if not isinstance(item, dict):
            raise ValueError("follow-up snapshot contains an invalid item")
        if item.get("url") and item.get("headSha"):
            items.append({"url": str(item["url"]), "headSha": str(item["headSha"]), "state": "OPEN"})
    return items


def read_managed_pr_keys(path: Path) -> list[str]:
    """Read and validate the exact managed PR key set from a private copy."""

    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        try:
            rows = connection.execute(
                "SELECT pr_key, owner, repo, number FROM managed_prs ORDER BY pr_key"
            ).fetchall()
        except sqlite3.OperationalError as exc:
            raise ValueError("pre-migration copy has no managed_prs table") from exc
    finally:
        connection.close()
    keys: list[str] = []
    for row in rows:
        key = str(row["pr_key"] or "")
        expected = f"{row['owner']}/{row['repo']}#{int(row['number'])}"
        if not key or key != expected:
            raise ValueError("managed_prs contains an invalid PR key")
        if key in keys:
            raise ValueError(f"managed_prs contains a duplicate PR key: {key}")
        keys.append(key)
    return keys


def key_set_digest(keys: list[str]) -> str:
    return _sha256_bytes(canonical_json(sorted(keys)).encode("utf-8"))


def _fresh_utc(value: object, *, field: str, now: datetime) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"live-state {field} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"live-state {field} timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"live-state {field} timestamp must be UTC")
    parsed = parsed.astimezone(UTC)
    if parsed > now:
        raise ValueError(f"live-state {field} timestamp is in the future")
    if now - parsed > MAX_SNAPSHOT_AGE:
        raise ValueError(f"live-state {field} timestamp is too old")
    return parsed


def prepare_managed_ledger(
    target: Path,
    *,
    production_ledger: Path,
    war_room_db: Path,
    reports_dir: Path,
    followup: Path,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """The one pre-migration path shared by Stage 6 and live-state capture."""

    migrate_schema(target)
    legacy = import_legacy_history(
        target,
        production_ledger=production_ledger,
        war_room_db=war_room_db,
        reports_dir=reports_dir,
    )
    items = _followup_items(followup)
    import_open_pr_observations(
        target,
        items,
        source="FOLLOWUP_OBSERVATION",
        observed_at=observed_at,
    )
    keys = read_managed_pr_keys(target)
    return {
        "legacy": legacy,
        "followupObservationCount": len(items),
        "managedKeys": keys,
        "keySetDigest": key_set_digest(keys),
    }


def _state_from_response(response: dict[str, Any], *, key: str) -> tuple[str, str, str]:
    expected_url = _expected_pr_url(key)
    owner_repo, number_text = key.rsplit("#", 1)
    number = int(number_text)
    url = response.get("html_url")
    if url != expected_url:
        raise ValueError(f"GitHub PR response has an invalid html_url for {key}")
    number_value = response.get("number")
    if number_value != number:
        raise ValueError(f"GitHub PR response number does not match {key}")
    head = response.get("head")
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(head_sha, str) or not head_sha:
        raise ValueError(f"GitHub PR response has no head.sha for {key}")
    merged_at = response.get("merged_at")
    if merged_at is not None:
        if not isinstance(merged_at, str) or not merged_at:
            raise ValueError(f"GitHub PR response has an invalid merged_at for {key}")
        state = "MERGED"
    elif response.get("state") == "open":
        state = "OPEN"
    elif response.get("state") == "closed":
        state = "CLOSED"
    else:
        raise ValueError(f"GitHub PR response has an unsupported state for {key}")
    return state, url, head_sha


def _expected_pr_url(key: str) -> str:
    owner_repo, number_text = key.rsplit("#", 1)
    try:
        number = int(number_text)
    except ValueError as exc:
        raise ValueError(f"live-state observation key is invalid for {key}") from exc
    if not owner_repo or number < 1 or str(number) != number_text:
        raise ValueError(f"live-state observation key is invalid for {key}")
    return f"https://github.com/{owner_repo}/pull/{number}"


def _fetch_observation(client: GitHubClient, key: str) -> dict[str, Any]:
    owner_repo, number_text = key.rsplit("#", 1)
    number = int(number_text)
    endpoint = f"repos/{owner_repo}/pulls/{number}"
    response = client.pull_request(owner_repo, number)
    if not isinstance(response, dict):
        raise ValueError(f"GitHub PR response is not an object for {key}")
    state, url, head_sha = _state_from_response(response, key=key)
    fetched_at = iso_z(utc_now())
    evidence = {
        "authoritativeReadOnly": True,
        "state": state,
        "url": url,
        "headSha": head_sha,
        "endpoint": endpoint,
        "responseDigest": _sha256_bytes(canonical_json(response).encode("utf-8")),
        "fetchedAt": fetched_at,
    }
    return {
        "prKey": key,
        "state": state,
        "url": url,
        "headSha": head_sha,
        "apiEvidence": evidence,
    }


def fetch_observations(client: GitHubClient, keys: list[str], *, workers: int) -> list[dict[str, Any]]:
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="live-pr") as executor:
        # map preserves the exact managed key order while propagating any one failure.
        return list(executor.map(lambda key: _fetch_observation(client, key), keys))


def build_live_snapshot(
    source: Path,
    *,
    legacy_db: Path,
    legacy_reports: Path,
    followup: Path,
    quiesce_token: str,
    client: GitHubClient | None = None,
    workers: int = 4,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Build a complete live snapshot without writing an output file."""

    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    source = source.resolve()
    legacy_db = legacy_db.resolve()
    legacy_reports = legacy_reports.resolve()
    followup = followup.resolve()
    github = client or GitHubClient()
    last_error: Exception | None = None
    for _attempt in range(1, max_attempts + 1):
        before = input_binding(source, legacy_db, legacy_reports, followup)
        try:
            with tempfile.TemporaryDirectory(prefix=".live-pr-state-", dir=source.parent) as directory:
                source_backup = Path(directory) / "source-backup.sqlite3"
                target = Path(directory) / "migrated.sqlite3"
                stable_sqlite_copy(
                    source,
                    source_backup,
                    quiesce_token=quiesce_token,
                    max_attempts=1,
                )
                # Migration must consume the exact stable backup whose
                # generation was captured above.  Keeping a second explicit
                # copy also mirrors Stage 6's source_backup -> migrated path.
                stable_sqlite_copy(
                    source_backup,
                    target,
                    quiesce_token="live-pr-migration-copy",
                    max_attempts=1,
                )
                prepared = prepare_managed_ledger(
                    target,
                    production_ledger=source_backup,
                    war_room_db=legacy_db,
                    reports_dir=legacy_reports,
                    followup=followup,
                )
                observations = fetch_observations(
                    github,
                    prepared["managedKeys"],
                    workers=workers,
                )
                after = input_binding(source, legacy_db, legacy_reports, followup)
                if before != after:
                    last_error = QuiescenceError("live-state inputs changed during API observation")
                    continue
                generated_at = iso_z(utc_now())
                return {
                    "schema": LIVE_PR_SNAPSHOT_SCHEMA,
                    "generatedAt": generated_at,
                    "sourceGeneration": before["sourceGeneration"],
                    "inputDigests": before["inputDigests"],
                    "managedKeys": prepared["managedKeys"],
                    "keySetDigest": prepared["keySetDigest"],
                    "prProjection": projection_summary(observations),
                    "preMigration": {
                        "managedPrCount": len(prepared["managedKeys"]),
                        "followupObservationCount": prepared["followupObservationCount"],
                        "legacyHistory": prepared["legacy"],
                    },
                    "observations": observations,
                }
        except QuiescenceError as exc:
            last_error = exc
            continue
    raise QuiescenceError(
        f"live-state inputs did not stabilize after {max_attempts} attempts"
    ) from last_error


def validate_snapshot_binding(
    snapshot: dict[str, Any],
    *,
    source: Path,
    legacy_db: Path,
    legacy_reports: Path,
    followup: Path,
) -> None:
    if snapshot.get("schema") != LIVE_PR_SNAPSHOT_SCHEMA:
        raise ValueError("live-state snapshot schema is unsupported")
    now = datetime.now(UTC)
    generated_at = _fresh_utc(snapshot.get("generatedAt"), field="generatedAt", now=now)
    binding = input_binding(source.resolve(), legacy_db.resolve(), legacy_reports.resolve(), followup.resolve())
    if snapshot.get("sourceGeneration") != binding["sourceGeneration"]:
        raise ValueError("live-state snapshot source generation does not match inputs")
    if snapshot.get("inputDigests") != binding["inputDigests"]:
        raise ValueError("live-state snapshot input digests do not match inputs")
    keys = snapshot.get("managedKeys")
    observations = snapshot.get("observations")
    if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
        raise ValueError("live-state managed key set is invalid")
    if len(set(keys)) != len(keys) or keys != sorted(keys):
        raise ValueError("live-state managed key set is duplicate or unordered")
    if snapshot.get("keySetDigest") != key_set_digest(keys):
        raise ValueError("live-state key-set digest is invalid")
    if not isinstance(observations, list) or len(observations) != len(keys):
        raise ValueError("live-state observations are incomplete")
    observed_keys = [item.get("prKey") for item in observations if isinstance(item, dict)]
    if observed_keys != keys:
        raise ValueError("live-state observations do not exactly match managed keys")
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("live-state observation is invalid")
        key = observation.get("prKey")
        if not isinstance(key, str) or "#" not in key:
            raise ValueError("live-state observation key is invalid")
        evidence = observation.get("apiEvidence")
        if not isinstance(evidence, dict) or evidence.get("authoritativeReadOnly") is not True:
            raise ValueError(f"live-state API evidence is missing for {key}")
        owner_repo, number_text = key.rsplit("#", 1)
        expected_url = _expected_pr_url(key)
        state = observation.get("state")
        url = observation.get("url")
        head_sha = observation.get("headSha")
        if state not in {"OPEN", "CLOSED", "MERGED"} or url != expected_url or not isinstance(head_sha, str) or not head_sha:
            raise ValueError(f"live-state observation fields are invalid for {key}")
        if evidence.get("state") != state or evidence.get("url") != url or evidence.get("headSha") != head_sha:
            raise ValueError(f"live-state API evidence does not match observation for {key}")
        if evidence.get("endpoint") != f"repos/{owner_repo}/pulls/{int(number_text)}":
            raise ValueError(f"live-state endpoint does not match observation for {key}")
        digest = evidence.get("responseDigest")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"live-state response digest is invalid for {key}")
        fetched_at = _fresh_utc(evidence.get("fetchedAt"), field=f"fetchedAt for {key}", now=now)
        if fetched_at > generated_at:
            raise ValueError(f"live-state fetchedAt is after generatedAt for {key}")
    if snapshot.get("prProjection") != projection_summary(observations):
        raise ValueError("live-state PR projection digest does not match observations")


def write_live_snapshot(
    path: Path,
    value: dict[str, Any],
    *,
    validator: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Write only a complete snapshot, atomically and privately."""

    raw = (canonical_json(value) + "\n").encode("utf-8")
    if validator is not None:
        validator(json.loads(raw.decode("utf-8")))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        temporary.chmod(0o600)
        temporary.write_bytes(raw)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        if validator is not None:
            validator(json.loads(temporary.read_text(encoding="utf-8")))
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
