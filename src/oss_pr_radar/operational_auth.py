"""The signed operational authorization required by deployed Radar actions."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import plistlib
import re
import sqlite3
import stat
import tempfile
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .managed_security import sign_current, verify_current
from .pr_projection import ledger_projection
from .release_binding import active_release, runtime_root_digest
from .stage6_rehearsal import source_generation, stable_sqlite_copy
from .util import canonical_json, iso_z, sha256_json

OPERATIONAL_AUTH_SCHEMA = "oss-pr-radar.stage7-operational-authorization.v1"
OPERATIONAL_AUTH_CONTEXT = "stage7-operational-authorization-v1"
OPERATIONAL_AUTH_FILENAME = "operational-authorization.json"
WORKER_STAGING_AUTH_SCHEMA = "oss-pr-radar.stage7-worker-staging-authorization.v1"
WORKER_STAGING_AUTH_CONTEXT = "stage7-worker-staging-authorization-v1"
WORKER_STAGING_AUTH_FILENAME = "worker-staging-authorization.json"
STAGED_WORKER_RECEIPT_SCHEMA = "oss-pr-radar.stage7-staged-worker-receipt.v1"
STAGED_WORKER_RECEIPT_CONTEXT = "stage7-staged-worker-receipt-v1"
STAGED_WORKER_RECEIPT_FILENAME = "staged-worker-receipt.json"
WORKER_STAGING_LOCK_FILENAME = ".worker-staging.lock"
WORKER_STAGING_AUTH_TTL = timedelta(minutes=5)
WORKER_STAGING_MAX_EVIDENCE_AGE = timedelta(minutes=10)


def authorization_path(runtime_root: Path) -> Path:
    return runtime_root.resolve() / "state" / OPERATIONAL_AUTH_FILENAME


def worker_staging_authorization_path(runtime_root: Path) -> Path:
    return runtime_root.resolve() / "state" / WORKER_STAGING_AUTH_FILENAME


def staged_worker_receipt_path(runtime_root: Path) -> Path:
    return runtime_root.resolve() / "state" / STAGED_WORKER_RECEIPT_FILENAME


def worker_staging_lock_path(runtime_root: Path) -> Path:
    return runtime_root.resolve() / "state" / WORKER_STAGING_LOCK_FILENAME


class _WorkerStagingLock:
    def __init__(self, runtime_root: Path) -> None:
        self.path = worker_staging_lock_path(runtime_root)
        self.handle: Any | None = None

    def __enter__(self) -> "_WorkerStagingLock":
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        self.handle = self.path.open("a+b")
        os.chmod(self.path, 0o600)
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        assert self.handle is not None
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()


def worker_staging_transaction_lock(runtime_root: Path) -> _WorkerStagingLock:
    """Return the process-exclusive lock covering the complete stage transaction."""

    return _WorkerStagingLock(runtime_root)


def _write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        payload = (canonical_json(value) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_private_commit_point(path: Path, value: dict[str, Any]) -> None:
    """Atomically publish a private record without failing after visibility.

    The caller uses this only for the final authorization transition.  Before
    ``os.replace`` every failure is recoverable and is raised.  Once replace
    succeeds, the authorization is visible and must not be followed by a
    rollback path; a directory fsync failure is therefore intentionally
    contained after the commit point.
    """

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    replaced = False
    try:
        payload = (canonical_json(value) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        replaced = True
        try:
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            # The signed ACTIVE record is already visible.  Do not turn this
            # into an exception that would make the worker caller roll back.
            pass
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if not replaced:
            temporary.unlink(missing_ok=True)


def _remove_private_and_fsync(path: Path) -> None:
    """Remove one verified private record and durably publish that removal."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"private record is not a regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeError(f"private record permissions are unsafe: {path}")
    path.unlink()
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def revoke_operational_authorization(runtime_root: Path) -> None:
    with _WorkerStagingLock(runtime_root):
        for path in (
            authorization_path(runtime_root),
            worker_staging_authorization_path(runtime_root),
            staged_worker_receipt_path(runtime_root),
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                continue
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def _revoke_worker_staging_authorization_unlocked(runtime_root: Path) -> None:
    path = worker_staging_authorization_path(runtime_root)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def revoke_worker_staging_authorization(runtime_root: Path) -> None:
    """Revoke only the staging permit; the receipt remains for activation proof."""

    with _WorkerStagingLock(runtime_root):
        _revoke_worker_staging_authorization_unlocked(runtime_root)


def stable_evidence_digest(path: Path) -> str:
    """Hash one regular evidence file only if it stays unchanged while read."""

    if path.is_symlink() or not path.is_file():
        raise RuntimeError("operational evidence must be a regular file")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise RuntimeError("operational evidence changed while being read")
    return hashlib.sha256(raw).hexdigest()


def worker_spec_digest(specs: list[dict[str, Any]]) -> str:
    """Digest only the immutable worker identity and launch configuration."""

    normalized = [
        {
            "Label": str(spec["Label"]),
            "ProgramArguments": [str(item) for item in spec["ProgramArguments"]],
            "WorkingDirectory": str(spec["WorkingDirectory"]),
        }
        for spec in specs
    ]
    return sha256_json(sorted(normalized, key=lambda item: item["Label"]))


def _current_ledger_identity(runtime_root: Path) -> dict[str, Any]:
    """Read a stable identity for the currently pointed-to managed ledger."""

    runtime_root = runtime_root.resolve()
    state = runtime_root / "state"
    pointer = state / "current-ledger"
    releases = (state / "ledger-releases").resolve()
    if not pointer.is_symlink():
        raise RuntimeError("worker staging authorization requires current-ledger")
    target = pointer.resolve()
    if target.parent != releases or not target.is_file():
        raise RuntimeError("worker staging authorization ledger pointer is invalid")
    with tempfile.TemporaryDirectory(prefix="oss-pr-radar-staging-ledger-") as directory:
        snapshot = Path(directory) / "ledger.sqlite3"
        copy = stable_sqlite_copy(
            target,
            snapshot,
            quiesce_token="stage7-worker-staging-authorization-read",
        )
        raw = snapshot.read_bytes()
        generation = copy["attempts"][-1]["after"]["generation"]
        projection = ledger_projection(snapshot)
        connection = sqlite3.connect(f"file:{snapshot.resolve()}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            connection.close()
        if integrity != "ok":
            raise RuntimeError("worker staging authorization ledger is not integral")
        return {
            "target": str(target.relative_to(state)),
            "generation": generation,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "managedPrProjectionDigest": projection["digest"],
            "sourceGeneration": source_generation(target),
        }


def _read_bound_evidence(
    path: Path,
    *,
    schema: str,
    context: str,
    runtime_root: Path,
    release_id: str,
) -> tuple[dict[str, Any], str]:
    digest = stable_evidence_digest(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("worker staging evidence is invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RuntimeError("worker staging evidence schema is invalid")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned,
        context=context,
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    ):
        raise RuntimeError("worker staging evidence authentication failed")
    if value.get("runtimeRootDigest") != runtime_root_digest(runtime_root):
        raise RuntimeError("worker staging evidence runtime binding mismatch")
    if value.get("releaseId") != release_id:
        raise RuntimeError("worker staging evidence release binding mismatch")
    try:
        observed = datetime.fromisoformat(str(value["observedAt"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("worker staging evidence timestamp is invalid") from exc
    now = datetime.now(UTC)
    if (
        observed.tzinfo is None
        or observed > now
        or now - observed > WORKER_STAGING_MAX_EVIDENCE_AGE
    ):
        raise RuntimeError("worker staging evidence is stale")
    if digest != stable_evidence_digest(path):
        raise RuntimeError("worker staging evidence changed while being read")
    return value, digest


def _require_worker_staging_authorization_unlocked(
    runtime_root: Path,
    *,
    specs: list[dict[str, Any]],
    home: Path | None = None,
) -> dict[str, Any]:
    """Validate the short-lived, stage-only permit before any plist write."""

    runtime_root = runtime_root.resolve()
    if authorization_path(runtime_root).exists() or authorization_path(runtime_root).is_symlink():
        raise RuntimeError("worker staging is refused while full operational authorization exists")
    path = worker_staging_authorization_path(runtime_root)
    receipt = staged_worker_receipt_path(runtime_root)
    if receipt.exists() or receipt.is_symlink():
        raise RuntimeError("worker staging authorization has already been consumed")
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("worker staging authorization is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("worker staging authorization is invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != WORKER_STAGING_AUTH_SCHEMA:
        raise RuntimeError("worker staging authorization schema is invalid")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned,
        context=WORKER_STAGING_AUTH_CONTEXT,
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    ):
        raise RuntimeError("worker staging authorization authentication failed")
    if value.get("scope") != "stage_worker_configs" or value.get("state") != "ACTIVE":
        raise RuntimeError("worker staging authorization scope or state is invalid")
    release_path, binding = active_release(runtime_root)
    if (
        value.get("runtimeRootDigest") != runtime_root_digest(runtime_root)
        or value.get("releaseId") != binding.get("releaseId")
        or value.get("releaseHead") != binding.get("commit")
        or value.get("releaseManifestSha256") != binding.get("manifestSha256")
    ):
        raise RuntimeError("worker staging authorization release binding mismatch")
    try:
        issued = datetime.fromisoformat(str(value["issuedAt"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(value["expiresAt"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("worker staging authorization timestamps are invalid") from exc
    now = datetime.now(UTC)
    if issued.tzinfo is None or expires.tzinfo is None or issued > now or now >= expires:
        raise RuntimeError("worker staging authorization is expired or not yet valid")
    if expires - issued > WORKER_STAGING_AUTH_TTL:
        raise RuntimeError("worker staging authorization lifetime is too long")
    current = _current_ledger_identity(runtime_root)
    if any(
        value.get(key) != current[current_key]
        for key, current_key in (
            ("ledgerTarget", "target"),
            ("ledgerGeneration", "generation"),
            ("ledgerSha256", "sha256"),
            ("managedPrProjectionDigest", "managedPrProjectionDigest"),
        )
    ):
        raise RuntimeError("worker staging authorization ledger binding mismatch")
    if value.get("workerSpecDigest") != worker_spec_digest(specs):
        raise RuntimeError("worker staging authorization worker spec mismatch")
    counts_path = Path(str(value.get("managedCountsEvidencePath")))
    counts, counts_digest = _read_bound_evidence(
        counts_path,
        schema="oss-pr-radar.stage7-counts-evidence.v1",
        context="stage7-counts-evidence-v1",
        runtime_root=runtime_root,
        release_id=str(binding["releaseId"]),
    )
    if value.get("managedCountsEvidenceSha256") != counts_digest:
        raise RuntimeError("worker staging authorization counts digest mismatch")
    if counts.get("releaseHead") not in {None, value.get("releaseHead")}:
        raise RuntimeError("worker staging authorization counts HEAD mismatch")
    return value


def require_worker_staging_authorization(
    runtime_root: Path,
    *,
    specs: list[dict[str, Any]],
    home: Path | None = None,
    _lock_held: bool = False,
) -> dict[str, Any]:
    if _lock_held:
        return _require_worker_staging_authorization_unlocked(runtime_root, specs=specs, home=home)
    with _WorkerStagingLock(runtime_root):
        return _require_worker_staging_authorization_unlocked(runtime_root, specs=specs, home=home)


def _issue_worker_staging_authorization_unlocked(
    runtime_root: Path,
    *,
    managed_counts_evidence: Path,
    home: Path | None = None,
) -> dict[str, Any]:
    """Issue the least-privilege permit used only to stage unloaded plists."""

    runtime_root = runtime_root.resolve()
    path = worker_staging_authorization_path(runtime_root)
    receipt = staged_worker_receipt_path(runtime_root)
    if (
        path.exists()
        or path.is_symlink()
        or receipt.exists()
        or receipt.is_symlink()
        or authorization_path(runtime_root).exists()
        or authorization_path(runtime_root).is_symlink()
    ):
        raise RuntimeError("worker staging authorization already exists")
    release_path, binding = active_release(runtime_root)
    counts, counts_digest = _read_bound_evidence(
        managed_counts_evidence,
        schema="oss-pr-radar.stage7-counts-evidence.v1",
        context="stage7-counts-evidence-v1",
        runtime_root=runtime_root,
        release_id=str(binding["releaseId"]),
    )
    current = _current_ledger_identity(runtime_root)
    if any(
        counts.get(key) != current[current_key]
        for key, current_key in (
            ("ledgerGeneration", "generation"),
            ("ledgerSha256", "sha256"),
            ("managedPrProjectionDigest", "managedPrProjectionDigest"),
        )
    ):
        raise RuntimeError("managed-counts evidence does not match current ledger")
    from .local_publication import worker_specs

    specs = worker_specs(release_path, home=home or Path.home(), runtime_root=runtime_root)
    issued = datetime.now(UTC)
    unsigned = {
        "schema": WORKER_STAGING_AUTH_SCHEMA,
        "scope": "stage_worker_configs",
        "state": "ACTIVE",
        "runtimeRootDigest": runtime_root_digest(runtime_root),
        "releaseId": str(binding["releaseId"]),
        "releaseHead": str(binding["commit"]),
        "releaseManifestSha256": binding.get("manifestSha256"),
        "ledgerTarget": current["target"],
        "ledgerGeneration": current["generation"],
        "ledgerSha256": current["sha256"],
        "managedPrProjectionDigest": current["managedPrProjectionDigest"],
        "managedCountsEvidencePath": str(managed_counts_evidence.resolve()),
        "managedCountsEvidenceSha256": counts_digest,
        "workerSpecDigest": worker_spec_digest(specs),
        "issuedAt": iso_z(issued),
        "expiresAt": iso_z(issued + WORKER_STAGING_AUTH_TTL),
        "nonce": hashlib.sha256(os.urandom(32)).hexdigest(),
    }
    signed = sign_current(unsigned, context=WORKER_STAGING_AUTH_CONTEXT)
    if not signed.get("keyId") or not signed.get("signature"):
        raise PermissionError("current signing key is unavailable")
    value = {**unsigned, **signed}
    _write_private(path, value)
    return value


def issue_worker_staging_authorization(
    runtime_root: Path,
    *,
    managed_counts_evidence: Path,
    home: Path | None = None,
) -> dict[str, Any]:
    with _WorkerStagingLock(runtime_root):
        return _issue_worker_staging_authorization_unlocked(
            runtime_root,
            managed_counts_evidence=managed_counts_evidence,
            home=home,
        )


def _validate_worker_records(
    records: list[dict[str, Any]], *, specs: list[dict[str, Any]], spec_digest: str
) -> list[dict[str, Any]]:
    expected = {str(spec["Label"]) for spec in specs}
    normalized = sorted(records, key=lambda item: str(item.get("label")))
    if [str(item.get("label")) for item in normalized] != sorted(expected):
        raise RuntimeError("staged worker receipt labels are not exact")
    for item in normalized:
        observed = datetime.fromisoformat(str(item["observedAt"]).replace("Z", "+00:00"))
        if (
            observed.tzinfo is None
            or observed > datetime.now(UTC)
            or datetime.now(UTC) - observed > timedelta(minutes=10)
        ):
            raise RuntimeError("staged worker observation is stale")
        if (
            item.get("loaded") is not False
            or item.get("pid") is not None
            or item.get("specDigest") != spec_digest
            or not isinstance(item.get("plistPath"), str)
            or not Path(str(item["plistPath"])).is_absolute()
            or item.get("plistSha256") is None
            or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("plistSha256")))
            or item.get("mode") != "0o600"
            or item.get("ownerUid") != os.getuid()
            or item.get("regular") is not True
            or item.get("symlink") is not False
        ):
            raise RuntimeError("staged worker receipt data is invalid")
    return normalized


def _read_staged_receipt(runtime_root: Path) -> dict[str, Any]:
    path = staged_worker_receipt_path(runtime_root)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("staged worker receipt is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != STAGED_WORKER_RECEIPT_SCHEMA
        or value.get("scope") != "stage_worker_configs"
        or value.get("state") != "CONSUMED"
    ):
        raise RuntimeError("staged worker receipt schema is invalid")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned,
        context=STAGED_WORKER_RECEIPT_CONTEXT,
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    ):
        raise RuntimeError("staged worker receipt authentication failed")
    return value


def _read_json_signed_staging(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("staging authorization is missing or unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if (
        not isinstance(value, dict)
        or value.get("schema") != WORKER_STAGING_AUTH_SCHEMA
        or value.get("state") not in {"ACTIVE", "CONSUMED"}
        or not verify_current(
            unsigned,
            context=WORKER_STAGING_AUTH_CONTEXT,
            key_id=value.get("keyId"),
            signature=value.get("signature"),
        )
    ):
        raise RuntimeError("staging authorization authentication failed")
    return value


def _receipt_matches_files(value: dict[str, Any], *, specs: list[dict[str, Any]]) -> bool:
    records = value.get("workers")
    if not isinstance(records, list):
        return False
    try:
        normalized = _validate_worker_records(
            records, specs=specs, spec_digest=str(value["workerSpecDigest"])
        )
    except (KeyError, TypeError, ValueError, RuntimeError):
        return False
    for item in normalized:
        path = Path(str(item["plistPath"]))
        try:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or hashlib.sha256(path.read_bytes()).hexdigest() != item["plistSha256"]
            ):
                return False
        except OSError:
            return False
    return True


def consume_worker_staging_authorization(
    runtime_root: Path,
    *,
    specs: list[dict[str, Any]],
    worker_records: list[dict[str, Any]],
    _lock_held: bool = False,
) -> dict[str, Any]:
    """Consume a stage permit once; retries return the same verified receipt."""

    with nullcontext() if _lock_held else _WorkerStagingLock(runtime_root):
        receipt_path = staged_worker_receipt_path(runtime_root)
        if receipt_path.exists() or receipt_path.is_symlink():
            value = _read_staged_receipt(runtime_root)
            if value.get("workerSpecDigest") != worker_spec_digest(
                specs
            ) or not _receipt_matches_files(value, specs=specs):
                raise RuntimeError("existing staged receipt conflicts with current worker files")
            staging_path = worker_staging_authorization_path(runtime_root)
            staging = _read_json_signed_staging(staging_path)
            if staging.get("state") == "ACTIVE":
                original_digest = stable_evidence_digest(staging_path)
                if value.get("authorizationDigest") != original_digest:
                    raise RuntimeError("staged receipt does not bind the active staging nonce")
                consumed = {
                    key: item
                    for key, item in staging.items()
                    if key not in {"keyId", "signature", "state", "consumedAt", "receiptSha256"}
                }
                consumed.update(
                    {
                        "state": "CONSUMED",
                        "initialAuthorizationDigest": original_digest,
                        "consumedAt": iso_z(datetime.now(UTC)),
                        "receiptSha256": stable_evidence_digest(receipt_path),
                    }
                )
                signed = sign_current(consumed, context=WORKER_STAGING_AUTH_CONTEXT)
                _write_private(staging_path, {**consumed, **signed})
            return value
        auth = _require_worker_staging_authorization_unlocked(runtime_root, specs=specs)
        records = _validate_worker_records(
            worker_records, specs=specs, spec_digest=str(auth["workerSpecDigest"])
        )
        auth_digest = stable_evidence_digest(worker_staging_authorization_path(runtime_root))
        receipt_unsigned = {
            "schema": STAGED_WORKER_RECEIPT_SCHEMA,
            "scope": "stage_worker_configs",
            "state": "CONSUMED",
            "runtimeRootDigest": auth["runtimeRootDigest"],
            "releaseId": auth["releaseId"],
            "releaseHead": auth["releaseHead"],
            "releaseManifestSha256": auth["releaseManifestSha256"],
            "ledgerTarget": auth["ledgerTarget"],
            "ledgerGeneration": auth["ledgerGeneration"],
            "ledgerSha256": auth["ledgerSha256"],
            "managedPrProjectionDigest": auth["managedPrProjectionDigest"],
            "workerSpecDigest": auth["workerSpecDigest"],
            "stagingNonce": auth["nonce"],
            "stagingIssuedAt": auth["issuedAt"],
            "stagingExpiresAt": auth["expiresAt"],
            "managedCountsEvidencePath": auth["managedCountsEvidencePath"],
            "managedCountsEvidenceSha256": auth["managedCountsEvidenceSha256"],
            "authorizationDigest": auth_digest,
            "stagedAt": iso_z(datetime.now(UTC)),
            "workers": records,
        }
        signed = sign_current(receipt_unsigned, context=STAGED_WORKER_RECEIPT_CONTEXT)
        receipt = {**receipt_unsigned, **signed}
        _write_private(receipt_path, receipt)
        consumed_unsigned = {
            key: value
            for key, value in auth.items()
            if key not in {"keyId", "signature", "state", "consumedAt", "receiptSha256"}
        }
        consumed_unsigned.update(
            {
                "state": "CONSUMED",
                "initialAuthorizationDigest": auth_digest,
                "consumedAt": iso_z(datetime.now(UTC)),
                "receiptSha256": stable_evidence_digest(receipt_path),
            }
        )
        consumed_signed = sign_current(consumed_unsigned, context=WORKER_STAGING_AUTH_CONTEXT)
        _write_private(
            worker_staging_authorization_path(runtime_root),
            {**consumed_unsigned, **consumed_signed},
        )
        return receipt


def verify_staged_worker_receipt(
    runtime_root: Path,
    *,
    specs: list[dict[str, Any]],
    worker_reports: list[dict[str, Any]],
    home: Path | None = None,
) -> bool:
    """Validate consumed stage proof against actual plist bytes and reports."""

    try:
        value = _read_staged_receipt(runtime_root)
        binding = active_release(runtime_root)[1]
        current = _current_ledger_identity(runtime_root)
        if any(
            value.get(key) != expected
            for key, expected in (
                ("runtimeRootDigest", runtime_root_digest(runtime_root)),
                ("releaseId", binding.get("releaseId")),
                ("releaseHead", binding.get("commit")),
                ("releaseManifestSha256", binding.get("manifestSha256")),
                ("ledgerTarget", current["target"]),
                ("ledgerGeneration", current["generation"]),
                ("ledgerSha256", current["sha256"]),
                ("managedPrProjectionDigest", current["managedPrProjectionDigest"]),
            )
        ):
            return False
        if value.get("workerSpecDigest") != worker_spec_digest(specs):
            return False
        staging_path = worker_staging_authorization_path(runtime_root)
        staging = _read_json_signed_staging(staging_path)
        for receipt_key, staging_key in (
            ("stagingNonce", "nonce"),
            ("stagingIssuedAt", "issuedAt"),
            ("stagingExpiresAt", "expiresAt"),
            ("managedCountsEvidencePath", "managedCountsEvidencePath"),
            ("managedCountsEvidenceSha256", "managedCountsEvidenceSha256"),
        ):
            if value.get(receipt_key) != staging.get(staging_key):
                return False
        if value.get("authorizationDigest") != staging.get("initialAuthorizationDigest"):
            return False
        if (
            stable_evidence_digest(Path(str(value["managedCountsEvidencePath"])))
            != value["managedCountsEvidenceSha256"]
        ):
            return False
        records = value.get("workers")
        reports = {str(item.get("label")): item for item in worker_reports}
        if not isinstance(records, list) or len(records) != len(specs):
            return False
        _validate_worker_records(records, specs=specs, spec_digest=worker_spec_digest(specs))
        expected_labels = {str(spec["Label"]) for spec in specs}
        if {str(item.get("label")) for item in records} != expected_labels:
            return False
        base = home or Path.home()
        for item in records:
            label = str(item["label"])
            report = reports.get(label)
            plist = base.resolve() / "Library" / "LaunchAgents" / f"{label}.plist"
            if (
                report is None
                or report.get("loaded") is not False
                or report.get("actualConfigMatch") is not True
                or item.get("loaded") is not False
                or item.get("plistPath") != str(plist)
                or item.get("ownerUid") != os.getuid()
                or item.get("regular") is not True
                or item.get("symlink") is not False
                or item.get("mode") != "0o600"
                or plist.is_symlink()
                or not plist.is_file()
                or oct(plist.stat().st_mode & 0o777) != "0o600"
                or item.get("plistSha256") != hashlib.sha256(plist.read_bytes()).hexdigest()
            ):
                return False
        if not _receipt_matches_files(value, specs=specs):
            return False
        return True
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, json.JSONDecodeError):
        return False


def _preflight_requirements(preflight: dict[str, Any]) -> None:
    if preflight.get("ok") is not True or preflight.get("strictMode") != "preflight":
        raise RuntimeError("operational authorization requires a successful strict preflight")
    required = {
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
    }
    for key, expected in required.items():
        actual = preflight.get(key)
        if isinstance(expected, dict):
            if not isinstance(actual, dict) or any(actual.get(k) != v for k, v in expected.items()):
                raise RuntimeError(f"operational authorization preflight failed: {key}")
        elif actual != expected:
            raise RuntimeError(f"operational authorization preflight failed: {key}")
    workers = preflight.get("workers")
    if not isinstance(workers, list) or len(workers) != 3:
        raise RuntimeError("operational authorization requires three staged workers")
    if any(
        item.get("actualConfigMatch") is not True
        or item.get("launchConfigMatch") is not True
        or item.get("loaded") is not False
        for item in workers
        if isinstance(item, dict)
    ) or any(not isinstance(item, dict) for item in workers):
        raise RuntimeError("operational authorization requires unloaded release-bound workers")


def _issue_operational_authorization_unlocked(
    runtime_root: Path,
    *,
    preflight: dict[str, Any],
    managed_counts_evidence: Path,
    automation_snapshot: Path,
    managed_counts_evidence_sha256: str | None = None,
    automation_snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    """Sign the only authorization that allows deployed business actions."""

    _preflight_requirements(preflight)
    runtime_root = runtime_root.resolve()
    _, manifest = active_release(runtime_root)
    pointer = runtime_root / "state" / "current-ledger"
    if (
        not pointer.is_symlink()
        or pointer.resolve().parent != (runtime_root / "state" / "ledger-releases").resolve()
    ):
        raise RuntimeError("operational authorization requires an active managed ledger")
    receipt_path = staged_worker_receipt_path(runtime_root)
    receipt = _read_staged_receipt(runtime_root)
    if not _receipt_matches_files(
        receipt, specs=[{"Label": str(item.get("label"))} for item in receipt.get("workers", [])]
    ):
        raise RuntimeError("operational authorization requires an intact staged receipt")
    receipt_digest = stable_evidence_digest(receipt_path)
    worker_bindings = [
        {
            key: item[key]
            for key in (
                "label",
                "plistPath",
                "plistSha256",
                "mode",
                "ownerUid",
                "regular",
                "symlink",
            )
        }
        for item in receipt["workers"]
    ]
    ledger_info = preflight.get("ledger") if isinstance(preflight.get("ledger"), dict) else {}
    issued = datetime.now(UTC)
    unsigned = {
        "schema": OPERATIONAL_AUTH_SCHEMA,
        "state": "STAGED",
        "runtimeRootDigest": runtime_root_digest(runtime_root),
        "releaseId": str(manifest["releaseId"]),
        "releaseHead": str(manifest["commit"]),
        "releaseManifestSha256": manifest.get("manifestSha256"),
        "ledgerTarget": str(pointer.resolve().relative_to(runtime_root / "state")),
        "ledgerGeneration": ledger_info.get("generation"),
        "ledgerSha256AtIssue": ledger_info.get("sha256"),
        "managedPrProjectionDigest": ledger_info.get("managedPrProjectionDigest"),
        "managedCountsEvidenceSha256": managed_counts_evidence_sha256
        or stable_evidence_digest(managed_counts_evidence),
        "automationSnapshotSha256": automation_snapshot_sha256
        or stable_evidence_digest(automation_snapshot),
        "issuedAt": iso_z(issued),
        "workerConfigDigest": preflight.get("workerSpecDigest")
        or sha256_json(preflight.get("workers")),
        "stagedWorkerReceiptSha256": receipt_digest,
        "stagingNonce": receipt.get("stagingNonce"),
        "workerPlistBindings": worker_bindings,
    }
    auth = sign_current(unsigned, context=OPERATIONAL_AUTH_CONTEXT)
    if not auth.get("keyId") or not auth.get("signature"):
        raise PermissionError("current signing key is unavailable")
    value = {**unsigned, **auth}
    _revoke_worker_staging_authorization_unlocked(runtime_root)
    _write_private(authorization_path(runtime_root), value)
    return value


def issue_operational_authorization(
    runtime_root: Path,
    *,
    preflight: dict[str, Any],
    managed_counts_evidence: Path,
    automation_snapshot: Path,
    managed_counts_evidence_sha256: str | None = None,
    automation_snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    """Sign the only authorization that allows deployed business actions."""

    with _WorkerStagingLock(runtime_root):
        return _issue_operational_authorization_unlocked(
            runtime_root,
            preflight=preflight,
            managed_counts_evidence=managed_counts_evidence,
            automation_snapshot=automation_snapshot,
            managed_counts_evidence_sha256=managed_counts_evidence_sha256,
            automation_snapshot_sha256=automation_snapshot_sha256,
        )


def _verify_worker_plist_bindings(bindings: object) -> bool:
    if not isinstance(bindings, list) or len(bindings) != 3:
        return False
    labels: set[str] = set()
    for item in bindings:
        if not isinstance(item, dict) or item.get("label") in labels:
            return False
        labels.add(str(item.get("label")))
        path = Path(str(item.get("plistPath")))
        try:
            metadata = path.lstat()
            if (
                not path.is_absolute()
                or stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != item.get("ownerUid")
                or item.get("regular") is not True
                or item.get("symlink") is not False
                or item.get("mode") != "0o600"
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or hashlib.sha256(path.read_bytes()).hexdigest() != item.get("plistSha256")
            ):
                return False
        except (OSError, ValueError):
            return False
    return True


def verify_operational_authorization(
    runtime_root: Path, *, now: datetime | None = None, require_staged_receipt: bool = False
) -> dict[str, Any]:
    runtime_root = runtime_root.resolve()
    path = authorization_path(runtime_root)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("operational authorization is missing or not a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("operational authorization is missing or invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != OPERATIONAL_AUTH_SCHEMA:
        raise RuntimeError("operational authorization schema is invalid")
    if value.get("state") not in {"STAGED", "ACTIVE"}:
        raise RuntimeError("operational authorization state is invalid")
    if value.get("state") == "STAGED" and not require_staged_receipt:
        raise RuntimeError("operational authorization has not been activated")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned,
        context=OPERATIONAL_AUTH_CONTEXT,
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    ):
        raise RuntimeError("operational authorization authentication failed")
    if path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("operational authorization permissions are unsafe")
    _, manifest = active_release(runtime_root)
    if (
        value.get("runtimeRootDigest") != runtime_root_digest(runtime_root)
        or value.get("releaseId") != manifest.get("releaseId")
        or value.get("releaseHead") != manifest.get("commit")
        or value.get("releaseManifestSha256") != manifest.get("manifestSha256")
    ):
        raise RuntimeError("operational authorization release binding mismatch")
    pointer = runtime_root / "state" / "current-ledger"
    if (
        not pointer.is_symlink()
        or pointer.resolve().parent != (runtime_root / "state" / "ledger-releases").resolve()
    ):
        raise RuntimeError("operational authorization ledger pointer is invalid")
    if value.get("ledgerTarget") != str(pointer.resolve().relative_to(runtime_root / "state")):
        raise RuntimeError("operational authorization ledger binding mismatch")
    try:
        issued = datetime.fromisoformat(str(value["issuedAt"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("operational authorization timestamps are invalid") from exc
    current = now or datetime.now(UTC)
    if issued.tzinfo is None or issued > current:
        raise RuntimeError("operational authorization is not yet valid")
    bindings = value.get("workerPlistBindings")
    receipt = staged_worker_receipt_path(runtime_root)
    if not isinstance(
        value.get("stagedWorkerReceiptSha256"), str
    ) or not _verify_worker_plist_bindings(bindings):
        raise RuntimeError("operational authorization worker binding is invalid")
    if require_staged_receipt or value.get("state") == "STAGED":
        if (
            receipt.is_symlink()
            or not receipt.is_file()
            or stable_evidence_digest(receipt) != value.get("stagedWorkerReceiptSha256")
        ):
            raise RuntimeError("operational authorization staged receipt is missing or changed")
    return value


def require_operational_authorization(
    runtime_root: Path, *, require_staged_receipt: bool = False
) -> dict[str, Any]:
    return verify_operational_authorization(
        runtime_root, require_staged_receipt=require_staged_receipt
    )


def finalize_operational_authorization(runtime_root: Path) -> dict[str, Any]:
    """Promote staged full auth at one final, fail-closed commit point."""

    with _WorkerStagingLock(runtime_root):
        value = verify_operational_authorization(runtime_root, require_staged_receipt=True)
        unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
        unsigned.update({"state": "ACTIVE", "activationCompletedAt": iso_z(datetime.now(UTC))})
        signed = sign_current(unsigned, context=OPERATIONAL_AUTH_CONTEXT)
        if not signed.get("keyId") or not signed.get("signature"):
            raise PermissionError("current signing key is unavailable")
        # Remove the proof first.  Until the ACTIVE record is atomically
        # visible, only an unusable STAGED authorization can remain.
        _remove_private_and_fsync(staged_worker_receipt_path(runtime_root))
        _write_private_commit_point(authorization_path(runtime_root), {**unsigned, **signed})
        return {**unsigned, **signed}


def _reset_timestamp(value: object, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"worker staging reset timestamp is invalid: {field}") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(f"worker staging reset timestamp has no UTC offset: {field}")
    return parsed.astimezone(UTC)


def _reset_bound_counts_evidence(
    path_value: object,
    *,
    expected_digest: object,
    runtime_root: Path,
    binding: dict[str, Any],
    ledger: dict[str, Any],
    now: datetime,
) -> datetime:
    path = Path(str(path_value))
    digest = stable_evidence_digest(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("worker staging reset counts evidence is invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != (
        "oss-pr-radar.stage7-counts-evidence.v1"
    ):
        raise RuntimeError("worker staging reset counts evidence schema is invalid")
    unsigned = {key: item for key, item in value.items() if key not in {"keyId", "signature"}}
    if not verify_current(
        unsigned,
        context="stage7-counts-evidence-v1",
        key_id=value.get("keyId"),
        signature=value.get("signature"),
    ):
        raise RuntimeError("worker staging reset counts evidence authentication failed")
    if (
        digest != expected_digest
        or digest != stable_evidence_digest(path)
        or value.get("runtimeRootDigest") != runtime_root_digest(runtime_root)
        or value.get("releaseId") != binding.get("releaseId")
        or value.get("releaseHead") not in {None, binding.get("commit")}
        or value.get("ledgerGeneration") != ledger.get("generation")
        or value.get("ledgerSha256") != ledger.get("sha256")
        or value.get("managedPrProjectionDigest") != ledger.get("managedPrProjectionDigest")
    ):
        raise RuntimeError("worker staging reset counts evidence binding mismatch")
    observed = _reset_timestamp(value.get("observedAt"), field="counts.observedAt")
    if observed > now:
        raise RuntimeError("worker staging reset counts evidence is from the future")
    return observed


def _validate_reset_worker_plists(
    specs: list[dict[str, Any]],
    *,
    home: Path,
    receipt: dict[str, Any] | None,
    now: datetime,
) -> bool:
    launch_dir = home.resolve() / "Library" / "LaunchAgents"
    expected = {str(spec["Label"]): spec for spec in specs}
    paths = {label: launch_dir / f"{label}.plist" for label in expected}
    present = [path.exists() or path.is_symlink() for path in paths.values()]
    if any(present) and not all(present):
        raise RuntimeError("worker staging reset refuses partial worker plist state")
    if all(present):
        for label, path in paths.items():
            try:
                metadata = path.lstat()
                actual = plistlib.loads(path.read_bytes())
            except (OSError, plistlib.InvalidFileException) as exc:
                raise RuntimeError("worker staging reset worker plist is unreadable") from exc
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or actual != expected[label]
            ):
                raise RuntimeError("worker staging reset worker plist binding mismatch")
    if receipt is None:
        return all(present)
    if not all(present):
        raise RuntimeError("worker staging reset receipt requires three staged plists")
    records = receipt.get("workers")
    if not isinstance(records, list) or len(records) != len(expected):
        raise RuntimeError("worker staging reset receipt worker set is invalid")
    by_label = {str(item.get("label")): item for item in records if isinstance(item, dict)}
    if set(by_label) != set(expected) or len(by_label) != len(records):
        raise RuntimeError("worker staging reset receipt worker labels are invalid")
    spec_digest = worker_spec_digest(specs)
    for label, item in by_label.items():
        path = paths[label]
        observed = _reset_timestamp(item.get("observedAt"), field=f"{label}.observedAt")
        if observed > now:
            raise RuntimeError("worker staging reset worker observation is from the future")
        if (
            item.get("loaded") is not False
            or item.get("pid") is not None
            or item.get("specDigest") != spec_digest
            or item.get("plistPath") != str(path)
            or item.get("plistSha256") != hashlib.sha256(path.read_bytes()).hexdigest()
            or item.get("mode") != "0o600"
            or item.get("ownerUid") != os.getuid()
            or item.get("regular") is not True
            or item.get("symlink") is not False
        ):
            raise RuntimeError("worker staging reset receipt plist binding mismatch")
    return True


def reset_expired_worker_staging(
    runtime_root: Path,
    *,
    home: Path | None = None,
    launchctl_runner: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Clear only expired, release-bound staging state while workers are stopped.

    Every observable intermediate state remains fail-closed: a STAGED full
    authorization is removed first, and the receipt that blocks a fresh stage
    is removed last.  The staging lock serializes this reset with stage,
    authorization issue, and activation commit operations.
    """

    runtime_root = runtime_root.resolve()
    base = (home or Path.home()).resolve()
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None:
        raise RuntimeError("worker staging reset time must include a UTC offset")
    current_time = current_time.astimezone(UTC)
    with _WorkerStagingLock(runtime_root):
        release_path, binding = active_release(runtime_root)
        ledger = _current_ledger_identity(runtime_root)
        from .local_publication import worker_specs
        from .release_binding import runtime_ledger_path
        from .runtime import pending_publication_effects
        from .runtime_audit import WORKER_LABELS, launchctl_print

        specs = worker_specs(release_path, home=base, runtime_root=runtime_root)
        expected_spec_digest = worker_spec_digest(specs)
        runner = launchctl_runner or launchctl_print
        unloaded_markers = ("could not find", "service not found", "no such process")
        for worker in ("fast", "slow", "queue-importer"):
            label = WORKER_LABELS[worker]
            output = runner(label)
            if not isinstance(output, str) or not any(
                marker in output.casefold() for marker in unloaded_markers
            ):
                raise RuntimeError(f"worker staging reset requires unloaded worker: {worker}")
        pending = pending_publication_effects(runtime_ledger_path(runtime_root))
        if pending != 0:
            raise RuntimeError("worker staging reset requires zero pending publication effects")

        auth_path = authorization_path(runtime_root)
        staging_path = worker_staging_authorization_path(runtime_root)
        receipt_path = staged_worker_receipt_path(runtime_root)
        auth: dict[str, Any] | None = None
        staging: dict[str, Any] | None = None
        receipt: dict[str, Any] | None = None
        stale_reasons: list[str] = []

        if auth_path.exists() or auth_path.is_symlink():
            if (
                auth_path.is_symlink()
                or not auth_path.is_file()
                or stat.S_IMODE(auth_path.stat().st_mode) != 0o600
            ):
                raise RuntimeError("worker staging reset operational authorization is unsafe")
            try:
                auth = json.loads(auth_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "worker staging reset operational authorization is invalid"
                ) from exc
            if not isinstance(auth, dict) or auth.get("schema") != OPERATIONAL_AUTH_SCHEMA:
                raise RuntimeError(
                    "worker staging reset operational authorization schema is invalid"
                )
            unsigned = {
                key: item for key, item in auth.items() if key not in {"keyId", "signature"}
            }
            if not verify_current(
                unsigned,
                context=OPERATIONAL_AUTH_CONTEXT,
                key_id=auth.get("keyId"),
                signature=auth.get("signature"),
            ):
                raise RuntimeError(
                    "worker staging reset operational authorization authentication failed"
                )
            if auth.get("state") == "ACTIVE":
                raise RuntimeError("worker staging reset refuses ACTIVE operational authorization")
            if auth.get("state") != "STAGED":
                raise RuntimeError(
                    "worker staging reset operational authorization state is invalid"
                )
            if (
                auth.get("runtimeRootDigest") != runtime_root_digest(runtime_root)
                or auth.get("releaseId") != binding.get("releaseId")
                or auth.get("releaseHead") != binding.get("commit")
                or auth.get("releaseManifestSha256") != binding.get("manifestSha256")
                or auth.get("ledgerTarget") != ledger.get("target")
                or auth.get("ledgerGeneration") != ledger.get("generation")
                or auth.get("ledgerSha256AtIssue") != ledger.get("sha256")
                or auth.get("managedPrProjectionDigest") != ledger.get("managedPrProjectionDigest")
                or auth.get("workerConfigDigest") != expected_spec_digest
            ):
                raise RuntimeError(
                    "worker staging reset operational authorization binding mismatch"
                )
            bindings = auth.get("workerPlistBindings")
            if not _verify_worker_plist_bindings(bindings):
                raise RuntimeError(
                    "worker staging reset operational authorization plist binding mismatch"
                )
            expected_paths = {
                label: str(base / "Library" / "LaunchAgents" / f"{label}.plist")
                for label in (str(spec["Label"]) for spec in specs)
            }
            if (
                not isinstance(bindings, list)
                or {
                    str(item.get("label")): str(item.get("plistPath"))
                    for item in bindings
                    if isinstance(item, dict)
                }
                != expected_paths
            ):
                raise RuntimeError(
                    "worker staging reset operational authorization worker set mismatch"
                )
            issued = _reset_timestamp(auth.get("issuedAt"), field="authorization.issuedAt")
            if issued > current_time:
                raise RuntimeError("worker staging reset authorization is from the future")
            if current_time - issued > WORKER_STAGING_MAX_EVIDENCE_AGE:
                stale_reasons.append("operational_authorization_stale")

        if staging_path.exists() or staging_path.is_symlink():
            staging = _read_json_signed_staging(staging_path)
            issued = _reset_timestamp(staging.get("issuedAt"), field="staging.issuedAt")
            expires = _reset_timestamp(staging.get("expiresAt"), field="staging.expiresAt")
            if (
                issued > current_time
                or expires <= issued
                or expires - issued > WORKER_STAGING_AUTH_TTL
            ):
                raise RuntimeError("worker staging reset authorization timestamps are invalid")
            if (
                staging.get("runtimeRootDigest") != runtime_root_digest(runtime_root)
                or staging.get("releaseId") != binding.get("releaseId")
                or staging.get("releaseHead") != binding.get("commit")
                or staging.get("releaseManifestSha256") != binding.get("manifestSha256")
                or staging.get("ledgerTarget") != ledger.get("target")
                or staging.get("ledgerGeneration") != ledger.get("generation")
                or staging.get("ledgerSha256") != ledger.get("sha256")
                or staging.get("managedPrProjectionDigest")
                != ledger.get("managedPrProjectionDigest")
                or staging.get("workerSpecDigest") != expected_spec_digest
            ):
                raise RuntimeError("worker staging reset authorization binding mismatch")
            counts_observed = _reset_bound_counts_evidence(
                staging.get("managedCountsEvidencePath"),
                expected_digest=staging.get("managedCountsEvidenceSha256"),
                runtime_root=runtime_root,
                binding=binding,
                ledger=ledger,
                now=current_time,
            )
            if expires <= current_time:
                stale_reasons.append("worker_staging_authorization_expired")
            if current_time - counts_observed > WORKER_STAGING_MAX_EVIDENCE_AGE:
                stale_reasons.append("managed_counts_evidence_stale")

        if receipt_path.exists() or receipt_path.is_symlink():
            receipt = _read_staged_receipt(runtime_root)
            if (
                receipt.get("runtimeRootDigest") != runtime_root_digest(runtime_root)
                or receipt.get("releaseId") != binding.get("releaseId")
                or receipt.get("releaseHead") != binding.get("commit")
                or receipt.get("releaseManifestSha256") != binding.get("manifestSha256")
                or receipt.get("ledgerTarget") != ledger.get("target")
                or receipt.get("ledgerGeneration") != ledger.get("generation")
                or receipt.get("ledgerSha256") != ledger.get("sha256")
                or receipt.get("managedPrProjectionDigest")
                != ledger.get("managedPrProjectionDigest")
                or receipt.get("workerSpecDigest") != expected_spec_digest
            ):
                raise RuntimeError("worker staging reset receipt binding mismatch")
            staged_at = _reset_timestamp(receipt.get("stagedAt"), field="receipt.stagedAt")
            expires = _reset_timestamp(
                receipt.get("stagingExpiresAt"), field="receipt.stagingExpiresAt"
            )
            if staged_at > current_time:
                raise RuntimeError("worker staging reset receipt is from the future")
            counts_observed = _reset_bound_counts_evidence(
                receipt.get("managedCountsEvidencePath"),
                expected_digest=receipt.get("managedCountsEvidenceSha256"),
                runtime_root=runtime_root,
                binding=binding,
                ledger=ledger,
                now=current_time,
            )
            if expires <= current_time:
                stale_reasons.append("staged_worker_receipt_expired")
            if current_time - staged_at > WORKER_STAGING_MAX_EVIDENCE_AGE:
                stale_reasons.append("staged_worker_receipt_stale")
            if current_time - counts_observed > WORKER_STAGING_MAX_EVIDENCE_AGE:
                stale_reasons.append("managed_counts_evidence_stale")

        staged_plists = _validate_reset_worker_plists(
            specs, home=base, receipt=receipt, now=current_time
        )
        if auth is not None and receipt is None:
            raise RuntimeError("worker staging reset STAGED authorization has no receipt")
        if staging is not None and staging.get("state") == "CONSUMED" and receipt is None:
            raise RuntimeError("worker staging reset consumed authorization has no receipt")
        if receipt is not None and staging is not None:
            for receipt_key, staging_key in (
                ("stagingNonce", "nonce"),
                ("stagingIssuedAt", "issuedAt"),
                ("stagingExpiresAt", "expiresAt"),
                ("managedCountsEvidencePath", "managedCountsEvidencePath"),
                ("managedCountsEvidenceSha256", "managedCountsEvidenceSha256"),
            ):
                if receipt.get(receipt_key) != staging.get(staging_key):
                    raise RuntimeError("worker staging reset receipt authorization mismatch")
            receipt_digest = stable_evidence_digest(receipt_path)
            if staging.get("state") == "CONSUMED":
                if (
                    receipt.get("authorizationDigest") != staging.get("initialAuthorizationDigest")
                    or staging.get("receiptSha256") != receipt_digest
                ):
                    raise RuntimeError("worker staging reset consumed proof mismatch")
            elif receipt.get("authorizationDigest") != stable_evidence_digest(staging_path):
                raise RuntimeError("worker staging reset active proof mismatch")
        if (
            auth is not None
            and receipt is not None
            and (
                auth.get("stagedWorkerReceiptSha256") != stable_evidence_digest(receipt_path)
                or auth.get("stagingNonce") != receipt.get("stagingNonce")
            )
        ):
            raise RuntimeError("worker staging reset operational receipt mismatch")

        existing = [
            path
            for path in (auth_path, staging_path, receipt_path)
            if path.exists() or path.is_symlink()
        ]
        if not existing:
            return {
                "ok": True,
                "reset": False,
                "alreadyClear": True,
                "releaseId": binding.get("releaseId"),
                "ledgerTarget": ledger.get("target"),
                "stagedPlists": staged_plists,
                "workersUnloaded": True,
                "pendingPublicationEffects": pending,
            }
        if not stale_reasons:
            raise RuntimeError("worker staging reset refuses unexpired staging state")

        removed: list[str] = []
        # Removing STAGED full auth first makes activation impossible.  The
        # receipt remains the new-stage blocker until the final commit step.
        for path in (auth_path, staging_path, receipt_path):
            if path.exists() or path.is_symlink():
                _remove_private_and_fsync(path)
                removed.append(path.name)
        return {
            "ok": True,
            "reset": True,
            "alreadyClear": False,
            "releaseId": binding.get("releaseId"),
            "ledgerTarget": ledger.get("target"),
            "stagedPlists": staged_plists,
            "workersUnloaded": True,
            "pendingPublicationEffects": pending,
            "removed": removed,
            "staleReasons": sorted(set(stale_reasons)),
        }
