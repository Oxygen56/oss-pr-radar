"""Signed, append-only transport of controller-observed public PR admissions.

This is not a database checkpoint or a publication command. Only a finalized
reservation with matching durable GitHub create-PR evidence can leave the
controller. Import admits that already-public PR without replacing cloud state.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .managed_lifecycle import ManagedLedger
from .managed_security import (
    sign_current,
    stable_fingerprint,
    verify_current,
    verify_current_or_previous,
)
from .util import canonical_json, sha256_json

SCHEMA = "oss-pr-radar.publication-feedback.v1"
CONTEXT = "publication-feedback-v1"
FILENAME = "controller_publication_feedback.json"
SOURCE = "controller-publication-feedback"
_KEY = re.compile(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#([1-9][0-9]*)")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FIELDS = {
    "publicationId",
    "issueKey",
    "issueUrl",
    "prKey",
    "prUrl",
    "headSha",
    "publishedAt",
    "proofDigest",
}


def _entry(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("publication feedback has unexpected fields")
    if any(not isinstance(item, str) for item in value.values()):
        raise ValueError("publication feedback fields must be strings")
    pr, issue = _KEY.fullmatch(value["prKey"]), _KEY.fullmatch(value["issueKey"])
    if not pr or not issue or pr.groups()[:2] != issue.groups()[:2]:
        raise ValueError("publication feedback repository binding mismatch")
    owner, repo, number = pr.groups()
    if (
        value["prUrl"] != f"https://github.com/{owner}/{repo}/pull/{number}"
        or value["issueUrl"] != f"https://github.com/{owner}/{repo}/issues/{issue.group(3)}"
        or not _SHA.fullmatch(value["headSha"])
        or not _DIGEST.fullmatch(value["publicationId"])
        or not _DIGEST.fullmatch(value["proofDigest"])
    ):
        raise ValueError("publication feedback public identity is invalid")
    try:
        published = datetime.fromisoformat(value["publishedAt"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("publication feedback timestamp is invalid") from exc
    if published.tzinfo != UTC or published > datetime.now(UTC):
        raise ValueError("publication feedback timestamp is invalid")
    return dict(value)


def validate_feedback(value: Any, *, historical: bool = False) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != {"schema", "entries", "keyId", "signature"}:
        raise ValueError("publication feedback envelope is invalid")
    if value["schema"] != SCHEMA or not isinstance(value["entries"], dict):
        raise ValueError("publication feedback schema is invalid")
    payload = {"schema": SCHEMA, "entries": value["entries"]}
    verify = verify_current_or_previous if historical else verify_current
    if not verify(payload, context=CONTEXT, key_id=value["keyId"], signature=value["signature"]):
        raise ValueError("publication feedback signature is invalid")
    result = {}
    for publication_id, raw in value["entries"].items():
        entry = _entry(raw)
        if publication_id != entry["publicationId"]:
            raise ValueError("publication feedback identifier mismatch")
        result[publication_id] = entry
    return result


def signed_feedback(entries: dict[str, dict[str, str]]) -> dict[str, Any]:
    for publication_id, raw in entries.items():
        if _entry(raw)["publicationId"] != publication_id:
            raise ValueError("publication feedback identifier mismatch")
    payload = {"schema": SCHEMA, "entries": dict(sorted(entries.items()))}
    signature = sign_current(payload, context=CONTEXT)
    if not signature["signature"]:
        raise PermissionError("publication feedback signing key unavailable")
    return payload | signature


def build_feedback(database: Path) -> dict[str, Any]:
    """Read one SQLite snapshot; never migrate or write the production ledger."""

    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    entries = {}
    try:
        connection.execute("BEGIN")
        for reservation in connection.execute(
            "SELECT * FROM managed_publication_reservations WHERE state='FINALIZED' ORDER BY reservation_key"
        ).fetchall():
            # A cloud checkpoint may seed a new controller. Imported admissions
            # are already transported evidence, never a local publication source.
            if re.fullmatch(r"publication-feedback:[0-9a-f]{64}", reservation["reservation_key"]):
                if reservation["request_id"] != reservation["reservation_key"]:
                    raise ValueError("imported publication admission binding is invalid")
                continue
            pr = connection.execute(
                "SELECT * FROM managed_prs WHERE pr_key=?", (reservation["pr_key"],)
            ).fetchone()
            request = connection.execute(
                "SELECT * FROM publication_requests WHERE request_id=?",
                (reservation["request_id"],),
            ).fetchone()
            permit = connection.execute(
                "SELECT * FROM publication_permits WHERE request_id=?", (reservation["request_id"],)
            ).fetchone()
            if (
                pr is None
                or request is None
                or permit is None
                or pr["origin_kind"] != "MANAGED_PUBLICATION_RECEIPT"
                or request["status"] != "CONSUMED"
                or permit["status"] != "CONSUMED"
                or request["opportunity_key"] != reservation["opportunity_key"]
                or request["commit_sha"] != reservation["head_sha"]
                or permit["commit_sha"] != reservation["head_sha"]
                or request["branch"] != reservation["head_ref"]
                or permit["branch"] != reservation["head_ref"]
                or permit["pr_url"] != pr["pr_url"]
                or reservation["repo"] != f"{pr['owner']}/{pr['repo']}"
                or pr["pr_key"] != f"{pr['owner']}/{pr['repo']}#{pr['number']}"
            ):
                raise ValueError("finalized publication admission has mismatched durable bindings")
            events = connection.execute(
                """SELECT * FROM managed_lifecycle_events WHERE opportunity_key=? AND pr_key=?
                   AND event_type='PUBLICATION_RECEIPT_OBSERVED' ORDER BY event_id""",
                (reservation["opportunity_key"], pr["pr_key"]),
            ).fetchall()
            events = [
                event
                for event in events
                if event["idempotency_key"]
                == f"publication:{reservation['request_id']}:{reservation['head_sha']}"
                and json.loads(event["provenance_json"]).get("requestId")
                == reservation["request_id"]
                and json.loads(event["payload_json"]).get(
                    "reservationKey", reservation["reservation_key"]
                )
                == reservation["reservation_key"]
                and all(
                    json.loads(event["payload_json"]).get(field) == expected
                    for field, expected in (
                        ("prUrl", pr["pr_url"]),
                        ("headSha", reservation["head_sha"]),
                    )
                )
            ]
            effects = connection.execute(
                "SELECT * FROM publication_effects WHERE permit_id=? AND action='create_pr' AND status='SUCCEEDED' ORDER BY created_at,effect_id",
                (permit["permit_id"],),
            ).fetchall()
            effects = [
                effect
                for effect in effects
                if json.loads(effect["result_json"]).get("ok") is True
                and json.loads(effect["result_json"]).get("prUrl") == pr["pr_url"]
            ]
            if not events or not effects:
                raise ValueError(
                    "finalized publication admission lacks matching successful GitHub evidence"
                )
            event, effect = events[0], effects[0]
            publication_id = stable_fingerprint(reservation["reservation_key"])
            entry = {
                "publicationId": publication_id,
                "issueKey": reservation["opportunity_key"],
                "issueUrl": permit["issue_url"],
                "prKey": pr["pr_key"],
                "prUrl": pr["pr_url"],
                "headSha": reservation["head_sha"],
                "publishedAt": event["observed_at"],
                "proofDigest": sha256_json(
                    {"reservation": dict(reservation), "event": dict(event), "effect": dict(effect)}
                ),
            }
            entries[publication_id] = _entry(entry)
    finally:
        connection.close()
    return signed_feedback(entries)


def merge_feedback(previous: dict[str, Any] | None, incoming: dict[str, Any]) -> dict[str, Any]:
    entries = validate_feedback(previous, historical=True) if previous is not None else {}
    for publication_id, entry in validate_feedback(incoming).items():
        if publication_id in entries and entries[publication_id] != entry:
            raise ValueError("publication feedback conflicts with an existing admission")
        entries[publication_id] = entry
    return signed_feedback(entries)


def apply_feedback(database: Path, value: dict[str, Any]) -> dict[str, Any]:
    """Admit public identities atomically; never overwrite existing observations."""

    entries = validate_feedback(value)
    ledger = ManagedLedger(database, ensure_schema=True)
    added = duplicates = 0
    connection = ledger._connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        for publication_id, entry in sorted(entries.items()):
            owner, repo, number = _KEY.fullmatch(entry["prKey"]).groups()
            identity = f"publication-feedback:{publication_id}"
            receipt_identity = f"{identity}:{sha256_json(entry)}"
            fingerprint = stable_fingerprint(receipt_identity)
            payload = {
                "prUrl": entry["prUrl"],
                "headSha": entry["headSha"],
                "reservationKey": identity,
                "publicationFeedback": entry,
            }
            existing_event = connection.execute(
                "SELECT * FROM managed_lifecycle_events WHERE idempotency_fingerprint=?",
                (fingerprint,),
            ).fetchone()
            if existing_event and (
                existing_event["event_type"] != "PUBLICATION_RECEIPT_OBSERVED"
                or existing_event["opportunity_key"] != entry["issueKey"]
                or existing_event["pr_key"] != entry["prKey"]
                or existing_event["source"] != SOURCE
                or existing_event["observed_at"] != entry["publishedAt"]
                or json.loads(existing_event["payload_json"]) not in ({}, payload)
            ):
                raise ValueError("publication feedback conflicts with a recorded receipt")
            existing = connection.execute(
                "SELECT * FROM managed_prs WHERE pr_key=?", (entry["prKey"],)
            ).fetchone()
            if existing and (
                existing["owner"],
                existing["repo"],
                existing["number"],
                existing["pr_url"],
            ) != (owner, repo, int(number), entry["prUrl"]):
                raise ValueError("publication feedback conflicts with an existing PR identity")
            reservation = connection.execute(
                "SELECT * FROM managed_publication_reservations WHERE reservation_key=?",
                (identity,),
            ).fetchone()
            if reservation and (
                reservation["state"],
                reservation["request_id"],
                reservation["repo"],
                reservation["opportunity_key"],
                reservation["pr_key"],
                reservation["head_sha"],
                reservation["idempotency_key"],
                reservation["created_at"],
            ) != (
                "FINALIZED",
                identity,
                f"{owner}/{repo}",
                entry["issueKey"],
                entry["prKey"],
                entry["headSha"],
                receipt_identity,
                entry["publishedAt"],
            ):
                raise ValueError("publication feedback conflicts with an existing reservation")
            if existing_event and (existing is None or reservation is None):
                raise ValueError("recorded publication feedback is missing its admission")
            if existing is None:
                provenance = canonical_json(
                    {"publicationId": publication_id, "proofDigest": entry["proofDigest"]}
                )
                connection.execute(
                    """INSERT INTO managed_prs (pr_key,owner,repo,number,head_sha,pr_url,state,
                       auto_created,maintainer_response,source_kind,source,provenance_json,observed_at,
                       metadata_json,origin_kind,origin_observation_json,latest_source)
                       VALUES (?,?,?,?,?,?,'OPEN',1,0,'MANAGED_PUBLICATION_RECEIPT',?,?,?,'{}',
                       'MANAGED_PUBLICATION_RECEIPT',?,?)""",
                    (
                        entry["prKey"],
                        owner,
                        repo,
                        int(number),
                        entry["headSha"],
                        entry["prUrl"],
                        SOURCE,
                        provenance,
                        entry["publishedAt"],
                        provenance,
                        SOURCE,
                    ),
                )
                added += 1
            connection.execute(
                """INSERT OR IGNORE INTO managed_publication_reservations
                   (reservation_key,request_id,repo,opportunity_key,pr_key,head_sha,state,
                   idempotency_key,lease_until,created_at,updated_at) VALUES (?,?,?,?,?,?,'FINALIZED',?,?,?,?)""",
                (
                    identity,
                    identity,
                    f"{owner}/{repo}",
                    entry["issueKey"],
                    entry["prKey"],
                    entry["headSha"],
                    receipt_identity,
                    entry["publishedAt"],
                    entry["publishedAt"],
                    entry["publishedAt"],
                ),
            )
            connection.execute(
                """INSERT OR IGNORE INTO managed_lifecycle_events (opportunity_key,pr_key,event_type,
                   idempotency_key,idempotency_fingerprint,source,provenance_json,observed_at,payload_json)
                   VALUES (?,?,'PUBLICATION_RECEIPT_OBSERVED',?,?,?,'{}',?,?)""",
                (
                    entry["issueKey"],
                    entry["prKey"],
                    receipt_identity,
                    fingerprint,
                    SOURCE,
                    entry["publishedAt"],
                    canonical_json(payload),
                ),
            )
            duplicates += bool(existing_event)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return {"ok": True, "admissions": len(entries), "added": added, "duplicates": duplicates}
