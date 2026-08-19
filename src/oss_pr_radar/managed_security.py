"""Non-persistent signing and redacted identity primitives for managed state."""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
from typing import Any

from .util import canonical_json

DISPATCH_SIGNING_KEY_ENV = "RADAR_DISPATCH_HMAC_KEY"
PREVIOUS_SIGNING_KEY_ENV = "RADAR_DISPATCH_HMAC_KEY_PREVIOUS"
CURRENT_KEY_ID_ENV = "RADAR_DISPATCH_HMAC_KEY_ID"
PREVIOUS_KEY_ID_ENV = "RADAR_DISPATCH_HMAC_KEY_PREVIOUS_ID"
CONTEXTS = {
    "evidence-cert-v1": "evidence-cert-v1",
    "absence-attestation-v1": "absence-attestation-v1",
    "managed-snapshot-v1": "managed-snapshot-v1",
    "repo-probe-v1": "repo-probe-v1",
    "task-creation-v1": "task-creation-v1",
    "war-room-rollback-v1": "war-room-rollback-v1",
    "war-room-copy-v1": "war-room-copy-v1",
    "war-room-delivery-v1": "war-room-delivery-v1",
    "stage7-cutover-v1": "stage7-cutover-v1",
    "stage7-stop-evidence-v1": "stage7-stop-evidence-v1",
    "stage7-automation-snapshot-v1": "stage7-automation-snapshot-v1",
    "stage7-counts-evidence-v1": "stage7-counts-evidence-v1",
    "stage7-operational-authorization-v1": "stage7-operational-authorization-v1",
    "stage7-worker-staging-authorization-v1": "stage7-worker-staging-authorization-v1",
    "stage7-staged-worker-receipt-v1": "stage7-staged-worker-receipt-v1",
}
KEYCHAIN_SERVICE = "oss-pr-radar-dispatch"


def _keychain_current_key() -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        completed = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def current_signing_key_available() -> bool:
    return _current_key() is not None


def _current_value() -> str | None:
    return os.environ.get(DISPATCH_SIGNING_KEY_ENV) or _keychain_current_key()


def _configured_keys() -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    current = _current_value()
    previous = os.environ.get(PREVIOUS_SIGNING_KEY_ENV)
    if current:
        result[os.environ.get(CURRENT_KEY_ID_ENV, "dispatch-current")] = current.encode()
    if previous:
        result[os.environ.get(PREVIOUS_KEY_ID_ENV, "dispatch-previous")] = previous.encode()
    return result


def _current_key() -> tuple[str, bytes] | None:
    """Return only the active signing key; the previous key is verify-only."""

    current = _current_value()
    if not current:
        return None
    return (
        os.environ.get(CURRENT_KEY_ID_ENV, "dispatch-current"),
        current.encode(),
    )


def current_signing_key_id() -> str | None:
    current = _current_key()
    return current[0] if current else None


def signing_key_ids() -> tuple[str, ...]:
    """Return configured IDs for verification, including the previous key."""

    return tuple(_configured_keys())


def derive_key(key_id: str, context: str) -> bytes | None:
    master = _configured_keys().get(key_id)
    if master is None or context not in CONTEXTS:
        return None
    return hmac.new(master, CONTEXTS[context].encode(), hashlib.sha256).digest()


def sign_current(payload: dict[str, Any], *, context: str) -> dict[str, Any]:
    """Sign with the current key only; never fall back to the previous key."""

    current = _current_key()
    if current is None or context not in CONTEXTS:
        return {"keyId": None, "signature": None}
    key_id, master = current
    derived = hmac.new(master, CONTEXTS[context].encode(), hashlib.sha256).digest()
    return {
        "keyId": key_id,
        "signature": hmac.new(
            derived, canonical_json(payload).encode(), hashlib.sha256
        ).hexdigest(),
    }


def verify_current_or_previous(
    payload: dict[str, Any], *, context: str, key_id: str | None, signature: str | None
) -> bool:
    """Verify historical signatures with either configured current or previous key."""

    if not key_id or not signature:
        return False
    derived = derive_key(key_id, context)
    if derived is None:
        return False
    expected = hmac.new(derived, canonical_json(payload).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_current(
    payload: dict[str, Any], *, context: str, key_id: str | None, signature: str | None
) -> bool:
    """Verify a newly-authorizing object with the active key only.

    Historical verification intentionally remains separate from this API.  A
    previous key may explain old evidence, but it must never authorize a new
    task, publication, or probe result.
    """

    current = _current_key()
    if current is None or not key_id or not signature or context not in CONTEXTS:
        return False
    current_id, master = current
    if key_id != current_id:
        return False
    derived = hmac.new(master, CONTEXTS[context].encode(), hashlib.sha256).digest()
    expected = hmac.new(derived, canonical_json(payload).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def stable_fingerprint(value: str) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def sensitive_identity(value: str) -> bool:
    lowered = value.casefold()
    return any(marker in lowered for marker in ("thread", "worktree", "file:", "/", "\\"))
