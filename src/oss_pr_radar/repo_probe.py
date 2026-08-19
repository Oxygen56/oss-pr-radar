"""Bounded, signed repository and local probe evidence for task creation."""

from __future__ import annotations

import hashlib
import io
import os
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .github_client import GitHubClient, GitHubError
from .managed_security import sign_current, verify_current
from .util import iso_z, parse_time, sha256_json

PROBE_SCHEMA = "repo_probe_receipt_v1"
PROBE_CONTEXT = "repo-probe-v1"
MAX_PROBE_SECONDS = 30
PATHS_VERIFIED = "PATHS_VERIFIED"
REPRODUCED_VALIDATED = "REPRODUCED_VALIDATED"
PROBE_LEVELS = {PATHS_VERIFIED, REPRODUCED_VALIDATED}
SAFE_PROBE_HEADS = {"python", "python3", "pytest", "uv", "go", "cargo"}


def thread_fingerprint(thread_id: str) -> str:
    return hashlib.sha256(thread_id.encode("utf-8")).hexdigest()


class ProbeUnavailable(RuntimeError):
    """The probe cannot be run under the currently available isolation policy."""


def _checkout_root(checkout: Path) -> Path:
    """Return a non-symlink checkout root, rejecting unsafe filesystem objects."""

    checkout = Path(checkout)
    try:
        root_stat = os.lstat(checkout)
    except OSError as exc:
        raise ProbeUnavailable("CHECKOUT_UNAVAILABLE") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise ProbeUnavailable("CHECKOUT_ROOT_UNSAFE")
    try:
        resolved = checkout.resolve(strict=True)
    except OSError as exc:
        raise ProbeUnavailable("CHECKOUT_UNAVAILABLE") from exc
    return resolved


def validate_checkout_paths(checkout: Path, code_paths: list[str]) -> dict[str, str]:
    """Validate and digest repository paths without following symlink components.

    The policy is deliberately narrow: every path must be a regular, single-link
    file below the pinned checkout.  The returned digest binds the normalized
    relative path and its resolved filesystem identity/content without exposing
    the local absolute path in a public receipt.
    """

    root = _checkout_root(checkout)
    bindings: dict[str, str] = {}
    for raw_path in sorted({str(path) for path in code_paths if str(path).strip()}):
        path = Path(raw_path)
        if (
            not raw_path
            or path.is_absolute()
            or raw_path.replace("\\", "/") != raw_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ProbeUnavailable("CODE_PATH_UNSAFE")
        current = root
        for index, component in enumerate(path.parts):
            current = current / component
            try:
                item = os.lstat(current)
            except OSError as exc:
                raise ProbeUnavailable("CODE_PATH_MISSING") from exc
            if stat.S_ISLNK(item.st_mode):
                raise ProbeUnavailable("CODE_PATH_SYMLINK")
            if index < len(path.parts) - 1 and not stat.S_ISDIR(item.st_mode):
                raise ProbeUnavailable("CODE_PATH_PARENT_UNSAFE")
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
            raise ProbeUnavailable("CODE_PATH_FILE_UNSAFE")
        try:
            resolved = current.resolve(strict=True)
            resolved.relative_to(root)
            content = current.read_bytes()
        except (OSError, ValueError) as exc:
            raise ProbeUnavailable("CODE_PATH_UNSAFE") from exc
        bindings[path.as_posix()] = sha256_json(
            {"relativePath": path.as_posix(), "contentSha256": hashlib.sha256(content).hexdigest()}
        )
    if not bindings:
        raise ProbeUnavailable("CODE_PATHS_REQUIRED")
    return bindings

# Profiles are code-owned.  A profile must name real repository test selectors
# and may never contain shell syntax or an inline print/eval program.
TRUSTED_PROBE_PROFILES: dict[str, dict[str, Any]] = {
    "python-pytest-existing-test-path-v1": {
        "schemaVersion": "trusted-probe-profile-v1",
        "version": 1,
        "language": "python",
        "requiresExistingTestPath": True,
        "reproductionArgv": ["python3", "-m", "pytest", "{existingTestPath}", "-q"],
        "validationArgv": ["python3", "-m", "pytest", "{existingTestPath}", "-q"],
    }
}
TRUSTED_REPO_PROFILES: dict[str, str] = {}


def register_trusted_repo_profile(repo: str, profile_id: str) -> None:
    """Register a code-owned profile selector for one canonical repository."""

    if not isinstance(repo, str) or "/" not in repo or profile_id not in TRUSTED_PROBE_PROFILES:
        raise ValueError("trusted repository profile is invalid")
    TRUSTED_REPO_PROFILES[repo.casefold()] = profile_id


def select_probe_profile(repo: str, checkout_path: Path, code_paths: list[str]) -> str | None:
    selected = TRUSTED_REPO_PROFILES.get(repo.casefold())
    if selected:
        return selected
    try:
        bindings = validate_checkout_paths(checkout_path, code_paths)
    except ProbeUnavailable:
        return None
    for profile_id, profile in TRUSTED_PROBE_PROFILES.items():
        if profile.get("requiresExistingTestPath") and any(
            path in bindings
            and (Path(path).name.startswith("test") or Path(path).parts[:1] == ("tests",))
            for path in code_paths
        ):
            return profile_id
    return None


def _safe_command(command: Any) -> list[str] | None:
    if not isinstance(command, list) or not command or len(command) > 20:
        return None
    values = [str(item) for item in command]
    if values[0] not in SAFE_PROBE_HEADS:
        return None
    if "-c" in values or "--command" in values:
        return None
    if any(
        any(token in value for token in ("$", "`", ";", "&&", "||", ">", "<", "\n", "\r"))
        for value in values
    ):
        return None
    return values


def _profile_command(profile: dict[str, Any], label: str, checkout: Path, code_paths: list[str]) -> list[str] | None:
    command = _safe_command(profile.get(f"{label}Argv"))
    if command is None:
        return None
    try:
        bindings = validate_checkout_paths(checkout, code_paths)
    except ProbeUnavailable:
        return None
    existing = next(
        (
            path
            for path in code_paths
            if path in bindings
            and (Path(path).name.startswith("test") or Path(path).parts[:1] == ("tests",))
        ),
        None,
    )
    if profile.get("requiresExistingTestPath") and existing is None:
        return None
    resolved: list[str] = []
    for value in command:
        if value == "{existingTestPath}":
            if existing is None:
                return None
            resolved.append(existing)
        else:
            resolved.append(value)
    return resolved


def _signed_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    auth = sign_current(payload, context=PROBE_CONTEXT)
    return payload | {"keyId": auth["keyId"], "signature": auth["signature"]}


def verify_probe_receipt(
    receipt: dict[str, Any], *, repo: str, base_sha: str, code_paths: list[str],
    required_level: str = REPRODUCED_VALIDATED, issue_url: str | None = None,
    task_id: str | None = None, thread_id: str | None = None,
    thread_fingerprint_value: str | None = None, attempt_id: str | None = None,
    head_sha: str | None = None,
    commit_sha: str | None = None, result_digest: str | None = None,
    policy_digest: str | None = None,
    max_age_seconds: int = 3600,
) -> bool:
    if not isinstance(receipt, dict):
        return False
    if receipt.get("schema") != PROBE_SCHEMA:
        return False
    if receipt.get("repo") != repo or receipt.get("baseSha") != base_sha:
        return False
    if required_level == REPRODUCED_VALIDATED and receipt.get("checkoutSha") != base_sha:
        return False
    if issue_url is not None and receipt.get("issueUrl") != issue_url:
        return False
    for field, expected in (
        ("taskId", task_id),
        ("attemptId", attempt_id),
        ("headSha", head_sha),
        ("commitSha", commit_sha),
        ("resultDigest", result_digest),
    ):
        if expected is not None and receipt.get(field) != expected:
            return False
    if thread_id is not None and receipt.get("threadFingerprint") != thread_fingerprint(thread_id):
        return False
    if (
        thread_fingerprint_value is not None
        and receipt.get("threadFingerprint") != thread_fingerprint_value
    ):
        return False
    if sorted(receipt.get("codePaths") or []) != sorted(code_paths):
        return False
    if policy_digest is not None and receipt.get("policyDigest") != policy_digest:
        return False
    if required_level not in PROBE_LEVELS:
        return False
    level = receipt.get("probeLevel")
    if level not in PROBE_LEVELS:
        return False
    if level == REPRODUCED_VALIDATED and required_level == PATHS_VERIFIED:
        pass
    elif level != required_level:
        return False
    if receipt.get("status") != level or receipt.get("codePathsVerified") is not True:
        return False
    bindings = receipt.get("codePathBindings")
    if level == REPRODUCED_VALIDATED and (
        not isinstance(bindings, dict)
        or set(bindings) != set(code_paths)
        or not all(isinstance(value, str) and value for value in bindings.values())
    ):
        return False
    if level == REPRODUCED_VALIDATED and not isinstance(receipt.get("policyDigest"), str):
        return False
    if level == REPRODUCED_VALIDATED:
        if not isinstance(receipt.get("checkoutSnapshotDigest"), str):
            return False
        journal = receipt.get("attemptJournal")
        if (
            not isinstance(journal, dict)
            or journal.get("externalEffectCount") != 0
            or journal.get("network") != "denied"
            or journal.get("hostWrites") != "denied"
            or "ATTEMPT_CLEANUP_FINISHED" not in (journal.get("events") or [])
        ):
            return False
    try:
        observed_at = parse_time(str(receipt.get("observedAt") or ""))
        expires_at = parse_time(str(receipt.get("expiresAt") or ""))
    except (TypeError, ValueError):
        return False
    now = datetime.now(UTC)
    if observed_at > now + timedelta(minutes=5) or expires_at < now:
        return False
    if (now - observed_at).total_seconds() > max(1, max_age_seconds):
        return False
    if level == REPRODUCED_VALIDATED and not (
        receipt.get("reproductionVerified") is True
        and receipt.get("validationVerified") is True
    ):
        return False
    payload = {
        key: value
        for key, value in receipt.items()
        if key not in {"keyId", "signature", "receiptDigest"}
    }
    if receipt.get("receiptDigest") != sha256_json(payload):
        return False
    signed_payload = {key: value for key, value in receipt.items() if key not in {"keyId", "signature"}}
    return bool(receipt.get("keyId")) and bool(receipt.get("signature")) and verify_current(
        signed_payload,
        context=PROBE_CONTEXT,
        key_id=str(receipt.get("keyId")),
        signature=str(receipt.get("signature")),
    )


def run_repo_probe(
    client: GitHubClient,
    *,
    repo: str,
    default_branch: str,
    selected_base_sha: str,
    code_paths: list[str],
    probe_profile: str | None = None,
    reproduction_command: Any = None,
    validation_command: Any = None,
    command_runner: Callable[[list[str], Path], bool] | None = None,
) -> dict[str, Any]:
    """Verify only repository paths; full reproduction requires a checkout."""

    payload: dict[str, Any] = {
        "schema": PROBE_SCHEMA,
        "repo": repo,
        "defaultBranch": default_branch,
        "baseSha": selected_base_sha,
        "codePaths": sorted({str(path) for path in code_paths if str(path).strip()}),
        "probeLevel": "UNVERIFIED",
        "codePathsVerified": False,
        "reproductionVerified": False,
        "validationVerified": False,
        "commandStatuses": {},
        "observedAt": iso_z(datetime.now(UTC)),
        "expiresAt": iso_z(datetime.now(UTC) + timedelta(minutes=30)),
    }
    try:
        repository = client.repository(repo)
        branch = client.branch(repo, default_branch)
        actual_default = str(repository.get("default_branch") or "")
        actual_sha = str((branch.get("commit") or {}).get("sha") or "")
        payload["actualDefaultBranch"] = actual_default
        payload["actualBaseSha"] = actual_sha
        if actual_default != default_branch or actual_sha != selected_base_sha:
            payload["reason"] = "STATE_DRIFT"
            return _signed_receipt(payload)
        tree = client.repository_tree(repo, selected_base_sha)
        tree_paths = {str(item.get("path") or "") for item in tree if isinstance(item, dict)}
        payload["codePathsVerified"] = bool(payload["codePaths"]) and all(
            path in tree_paths or any(item.startswith(f"{path}/") for item in tree_paths)
            for path in payload["codePaths"]
        )
    except (GitHubError, OSError, RuntimeError) as exc:
        payload["reason"] = f"REPOSITORY_PROBE_UNAVAILABLE:{type(exc).__name__}"
        return _signed_receipt(payload)

    payload["probeLevel"] = PATHS_VERIFIED if payload["codePathsVerified"] else "UNVERIFIED"
    payload["status"] = payload["probeLevel"]
    payload["commandStatuses"] = {"reproduction": "NOT_RUN", "validation": "NOT_RUN"}
    payload["reason"] = "REPRODUCTION_REQUIRED"
    payload["receiptDigest"] = sha256_json(payload)
    return _signed_receipt(payload)


def _normalized_archive_paths(code_paths: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw in sorted({str(path) for path in code_paths if str(path).strip()}):
        path = PurePosixPath(raw)
        if (
            not raw
            or path.is_absolute()
            or "\\" in raw
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ProbeUnavailable("CODE_PATH_UNSAFE")
        normalized.append(path.as_posix())
    if not normalized:
        raise ProbeUnavailable("CODE_PATHS_REQUIRED")
    return normalized


def _materialize_git_snapshot(
    checkout_path: Path,
    selected_base_sha: str,
    code_paths: list[str],
    destination: Path,
) -> tuple[str, dict[str, str], str]:
    """Materialize only Git objects into a private, immutable probe snapshot."""

    checkout = Path(checkout_path)
    try:
        root_stat = os.lstat(checkout)
    except OSError as exc:
        raise ProbeUnavailable("CHECKOUT_UNAVAILABLE") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise ProbeUnavailable("CHECKOUT_ROOT_UNSAFE")
    paths = _normalized_archive_paths(code_paths)
    try:
        identity = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", f"{selected_base_sha}^{{commit}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=MAX_PROBE_SECONDS,
        )
        if identity.returncode != 0 or identity.stdout.strip() != selected_base_sha:
            raise ProbeUnavailable("CHECKOUT_SHA_UNAVAILABLE")
        archived = subprocess.run(
            ["git", "-C", str(checkout), "archive", "--format=tar", selected_base_sha, "--", *paths],
            check=False,
            capture_output=True,
            timeout=MAX_PROBE_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeUnavailable("GIT_ARCHIVE_UNAVAILABLE") from exc
    if archived.returncode != 0:
        raise ProbeUnavailable("GIT_ARCHIVE_UNAVAILABLE")

    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    bindings: dict[str, str] = {}
    requested = set(paths)
    try:
        with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as stream:
            for member in stream:
                member_path = PurePosixPath(member.name)
                if (
                    member.name.startswith("/")
                    or "\\" in member.name
                    or any(part in {"", ".", ".."} for part in member_path.parts)
                ):
                    raise ProbeUnavailable("ARCHIVE_PATH_UNSAFE")
                if member.issym() or member.islnk() or not (member.isdir() or member.isreg()):
                    raise ProbeUnavailable("ARCHIVE_OBJECT_UNSAFE")
                target = destination.joinpath(*member_path.parts)
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = stream.extractfile(member)
                if source is None:
                    raise ProbeUnavailable("ARCHIVE_FILE_UNREADABLE")
                content = source.read()
                with open(target, "xb") as output:
                    output.write(content)
                os.chmod(target, 0o444)
                normalized = member_path.as_posix()
                if normalized in requested:
                    bindings[normalized] = sha256_json(
                        {"relativePath": normalized, "contentSha256": hashlib.sha256(content).hexdigest()}
                    )
        if set(bindings) != requested:
            raise ProbeUnavailable("CODE_PATH_MISSING_FROM_ARCHIVE")
    except (OSError, tarfile.TarError) as exc:
        raise ProbeUnavailable("ARCHIVE_EXTRACTION_FAILED") from exc
    snapshot_digest = sha256_json({"checkoutSha": selected_base_sha, "codePathBindings": bindings})
    for directory in sorted(destination.rglob("*"), reverse=True):
        if directory.is_dir():
            os.chmod(directory, 0o555)
    return selected_base_sha, bindings, snapshot_digest


def run_reproduction_probe(
    *,
    checkout_path: Path,
    repo: str,
    default_branch: str,
    selected_base_sha: str,
    code_paths: list[str],
    profile_id: str | None,
    issue_url: str,
    task_id: str,
    head_sha: str,
    commit_sha: str,
    result_digest: str,
    command_runner: Callable[[list[str], Path], int] | None = None,
    thread_id: str | None = None,
    attempt_id: str | None = None,
    _test_only_command_runner: bool = False,
) -> dict[str, Any]:
    """Run a trusted profile in an immutable Git-object snapshot.

    The supplied checkout is used only as a Git object database.  Repository
    files are never opened from its worktree; commands receive a private,
    read-only archive extracted for this attempt.
    """

    now = datetime.now(UTC)
    if command_runner is not None and not _test_only_command_runner:
        raise ProbeUnavailable("COMMAND_RUNNER_NOT_ALLOWED")
    attempt_id = attempt_id or secrets.token_urlsafe(12)
    payload: dict[str, Any] = {
        "schema": PROBE_SCHEMA,
        "repo": repo,
        "defaultBranch": default_branch,
        "baseSha": selected_base_sha,
        "issueUrl": issue_url,
        "taskId": task_id,
        "attemptId": attempt_id,
        "headSha": head_sha,
        "commitSha": commit_sha,
        "resultDigest": result_digest,
        "codePaths": sorted({str(path) for path in code_paths if str(path).strip()}),
        "probeLevel": "UNVERIFIED",
        "status": "UNVERIFIED",
        "codePathsVerified": False,
        "reproductionVerified": False,
        "validationVerified": False,
        "commandStatuses": {},
        "profileId": profile_id,
        "observedAt": iso_z(now),
        "expiresAt": iso_z(now + timedelta(minutes=30)),
        "attemptJournal": {
            "effectToken": sha256_json({"attemptId": attempt_id, "effects": 0}),
            "externalEffectCount": 0,
            "network": "denied",
            "hostWrites": "denied",
            "events": ["ATTEMPT_STARTED"],
        },
    }
    if thread_id is not None:
        payload["threadFingerprint"] = thread_fingerprint(thread_id)

    try:
        with tempfile.TemporaryDirectory(
            prefix=f"oss-pr-radar-probe-attempt-{attempt_id}-", dir="/private/tmp"
        ) as attempt_root:
            snapshot = Path(attempt_root) / "snapshot"
            scratch = Path(attempt_root) / "scratch"
            scratch.mkdir(mode=0o700)
            try:
                checkout_sha, bindings, snapshot_digest = _materialize_git_snapshot(
                    checkout_path, selected_base_sha, payload["codePaths"], snapshot
                )
                payload["checkoutSha"] = checkout_sha
                payload["codePathBindings"] = bindings
                payload["checkoutSnapshotDigest"] = snapshot_digest
                payload["codePathsVerified"] = True
                payload["attemptJournal"]["events"].append("SNAPSHOT_READY")
            except ProbeUnavailable as exc:
                payload["reason"] = str(exc)

            profile_id = profile_id or (
                select_probe_profile(repo, snapshot, payload["codePaths"])
                if payload["codePathsVerified"]
                else None
            )
            profile = TRUSTED_PROBE_PROFILES.get(profile_id or "")
            if not isinstance(profile, dict):
                payload["reason"] = payload.get("reason") or "TRUSTED_PROBE_PROFILE_UNAVAILABLE"
            else:
                payload["profileId"] = profile_id
                payload["profileVersion"] = profile.get("version")
                payload["policyDigest"] = sha256_json(
                    {
                        "schema": PROBE_SCHEMA,
                        "profileId": profile_id,
                        "profileVersion": profile.get("version"),
                        "sandbox": "macos-sandbox-exec-v2-deny-default",
                        "network": "disabled",
                        "hostWrites": "denied",
                        "snapshot": "git-archive-regular-files-v1",
                    }
                )
                if not payload["codePathsVerified"]:
                    pass
                elif not shutil.which("sandbox-exec") or sys.platform != "darwin":
                    payload["reason"] = "SANDBOX_BACKEND_UNAVAILABLE"
                    payload["commandStatuses"] = {
                        "reproduction": "NOT_RUN_SANDBOX_UNAVAILABLE",
                        "validation": "NOT_RUN_SANDBOX_UNAVAILABLE",
                    }
                else:
                    for label in ("reproduction", "validation"):
                        command = _profile_command(profile, label, snapshot, payload["codePaths"])
                        if command is None:
                            payload["commandStatuses"][label] = "PROFILE_INVALID"
                            continue
                        try:
                            validate_checkout_paths(snapshot, payload["codePaths"])
                            exit_code = int(
                                _run_profile_command(
                                    command, snapshot, payload["codePaths"], scratch_dir=scratch
                                )
                                if command_runner is None
                                else command_runner(command, snapshot)
                            )
                        except (OSError, RuntimeError, subprocess.SubprocessError, ProbeUnavailable):
                            exit_code = 125
                        payload["commandStatuses"][label] = {"exitCode": exit_code}
                        payload["attemptJournal"]["events"].append(f"{label.upper()}_FINISHED")
                        if label == "reproduction":
                            payload["reproductionVerified"] = exit_code == 0
                        else:
                            payload["validationVerified"] = exit_code == 0
                    try:
                        final_bindings = validate_checkout_paths(snapshot, payload["codePaths"])
                    except ProbeUnavailable:
                        final_bindings = None
                    if final_bindings != payload.get("codePathBindings"):
                        payload["reproductionVerified"] = False
                        payload["validationVerified"] = False
                        payload["reason"] = "SNAPSHOT_CHANGED_DURING_PROBE"
                    if payload["reproductionVerified"] and payload["validationVerified"]:
                        payload["probeLevel"] = REPRODUCED_VALIDATED
                        payload["status"] = REPRODUCED_VALIDATED
                    else:
                        payload["probeLevel"] = PATHS_VERIFIED
                        payload["status"] = PATHS_VERIFIED
                        if payload.get("reason") != "SNAPSHOT_CHANGED_DURING_PROBE":
                            payload["reason"] = "REPRODUCTION_COMMAND_FAILED"
            payload["attemptJournal"]["events"].append("ATTEMPT_CLEANUP_FINISHED")
    except Exception as exc:
        payload["reason"] = f"PROBE_FAILED:{type(exc).__name__}"
        payload["attemptJournal"]["events"].append("ATTEMPT_FAILED")
    payload["receiptDigest"] = sha256_json(payload)
    return _signed_receipt(payload)


def _run_profile_command(
    command: list[str],
    cwd: Path,
    code_paths: list[str] | None = None,
    *,
    scratch_dir: Path | None = None,
) -> int:
    def limit_resources() -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (MAX_PROBE_SECONDS, MAX_PROBE_SECONDS))
            resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
            if hasattr(resource, "RLIMIT_AS"):
                resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        except (OSError, ValueError):
            # The wall-clock timeout and temporary HOME remain enforced on
            # platforms that do not expose every resource limit.
            return

    executable = shutil.which("sandbox-exec")
    if not executable or sys.platform != "darwin":
        raise ProbeUnavailable("SANDBOX_BACKEND_UNAVAILABLE")
    if code_paths is not None:
        validate_checkout_paths(cwd, code_paths)
    scratch = scratch_dir or Path(
        tempfile.mkdtemp(prefix="oss-pr-radar-probe-scratch-", dir="/private/tmp")
    )
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    home = scratch / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    controlled_path = "/opt/homebrew/bin:/usr/bin:/bin"
    executable_path = shutil.which(command[0], path=controlled_path)
    if not executable_path:
        raise ProbeUnavailable("PROBE_EXECUTABLE_UNAVAILABLE")

    launcher_path = Path(executable_path)
    resolved_executable = launcher_path.resolve(strict=True)
    runtime_roots: list[Path] = []
    runtime_files: list[Path] = []
    framework = next(
        (parent for parent in (resolved_executable, *resolved_executable.parents) if parent.name == "Python.framework"),
        None,
    )
    if framework is not None:
        runtime_roots.append(framework)
        runtime_roots.append(framework.parent.parent)
        runtime_files.append(Path("/usr/lib/libSystem.B.dylib"))
        version = next(
            (parent.name for parent in resolved_executable.parents if parent.parent.name == "Versions"),
            None,
        )
        homebrew = next(
            (parent for parent in resolved_executable.parents if parent.name == "homebrew"),
            None,
        )
        if version and homebrew is not None:
            runtime_roots.append(homebrew / "lib" / f"python{version}")
            formula_root = next(
                (parent for parent in resolved_executable.parents if parent.parent.name == "Cellar"),
                None,
            )
            if formula_root is not None:
                runtime_roots.append(formula_root)
            runtime_roots.append(homebrew / "opt" / f"python@{version}")
    elif resolved_executable.parent == Path("/usr/bin"):
        # Keep the system interpreter supported only with its known system
        # runtime roots.  Unknown runtimes fail closed below.
        runtime_roots.extend((Path("/usr/lib"), Path("/System/Library"), Path("/Library/Frameworks")))
    else:
        raise ProbeUnavailable("RUNTIME_ALLOWLIST_UNAVAILABLE")
    runtime_roots = [root for root in runtime_roots if root.is_dir()]
    runtime_files = [path for path in runtime_files if path.is_file()]
    if framework is not None and framework not in runtime_roots:
        raise ProbeUnavailable("RUNTIME_ALLOWLIST_UNAVAILABLE")

    def sandbox_path(path: str) -> str:
        return path.replace("\\", "\\\\").replace('"', '\\"')
    rules = [
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow ipc-posix-shm)",
        "(deny network*)",
    ]
    rules.extend(
        f'(allow file-read* (subpath "{sandbox_path(str(root))}"))'
        for root in runtime_roots
    )
    # Seatbelt resolves every directory component before opening the executable
    # and temporary roots.  Permit only those directory entries as literals;
    # this is metadata/traversal access, not recursive host-file access.
    literal_paths: set[str] = {"/", "/private", "/private/tmp", "/dev"}
    for root in (*runtime_roots, *runtime_files, launcher_path, resolved_executable, cwd, scratch):
        literal_paths.update(str(parent) for parent in Path(root).parents)
        literal_paths.add(str(root))
    literal_paths.update({"/dev/null", "/dev/urandom", "/dev/random"})
    rules.extend(
        f'(allow file-read* (literal "{sandbox_path(path)}"))'
        for path in sorted(literal_paths)
    )
    rules.append(f'(allow process-exec (literal "{sandbox_path(str(resolved_executable))}"))')
    rules.append(f'(allow file-read* (subpath "{sandbox_path(str(cwd))}"))')
    rules.append(f'(allow file-write* (subpath "{sandbox_path(str(scratch))}"))')
    rules.append(f'(allow file-read* (subpath "{sandbox_path(str(scratch))}"))')
    argv = [executable, "-p", "".join(rules), str(resolved_executable), *command[1:]]
    path_value = controlled_path
    completed = subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=MAX_PROBE_SECONDS,
        shell=False,
        start_new_session=True,
        preexec_fn=limit_resources,
        env={
            "PATH": path_value,
            "HOME": str(home),
            "TMPDIR": str(scratch),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "RADAR_PROBE_NETWORK": "disabled",
        },
    )
    return completed.returncode


def _run_safe_command(command: list[str], cwd: Path) -> bool:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=MAX_PROBE_SECONDS,
            env={"PATH": os.environ.get("PATH", "")},
        )
        return completed.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
