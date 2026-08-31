"""Build signed evidence from the actual Stage 7 automation TOML files."""

from __future__ import annotations

import hashlib
import plistlib
import re
import shlex
import tomllib
from datetime import datetime
from pathlib import Path
from typing import Any

from .automation_contracts import (
    AUTOMATION_PROMPT_POLICY,
    DAILY_WAR_ROOM_NAME,
    HEARTBEAT_NAME,
    build_contracts,
)
from .local_publication import worker_specs
from .managed_security import sign_current
from .release_binding import bind_runtime, runtime_root_digest
from .util import iso_z, utc_now

AUTOMATION_SNAPSHOT_SCHEMA = "oss-pr-radar.stage7-automation-snapshot.v3"
AUTOMATION_SNAPSHOT_CONTEXT = "stage7-automation-snapshot-v1"
AUTOMATION_SNAPSHOT_GENERATOR = "stage7-automation-toml-v3"
AUTOMATION_PROMPT_TEMPLATE = "oss-pr-radar.prompt-template.v1"
_SECRET_LIKE = re.compile(r"(?:sk-|secret|token|hmac)[A-Za-z0-9_:=/.-]{12,}", re.IGNORECASE)


def _file_metadata(path: Path, *, role: str) -> tuple[bytes, dict[str, Any]]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"automation TOML is symlinked: {path}")
    try:
        before = path.stat()
    except OSError as exc:
        raise ValueError(f"automation TOML is missing: {path}") from exc
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"automation TOML is missing or symlinked: {path}")
    raw = path.read_bytes()
    after = path.stat()
    if (
        before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise RuntimeError(f"automation TOML changed while being read: {path}")
    return raw, {
        "role": role,
        "path": str(resolved),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "mtimeNs": after.st_mtime_ns,
    }


def _automation_section(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"automation TOML is invalid: {path}") from exc
    section = value.get("automation", value)
    if not isinstance(section, dict):
        raise ValueError(f"automation TOML section is invalid: {path}")
    return section


def _prompt_digest(
    prompt: object,
    *,
    role: str,
    runtime_root: Path,
    release_command: list[str],
) -> str:
    expected = canonical_prompt(role, runtime_root, release_command)
    accepted = {expected}
    if expected.endswith("\n"):
        accepted.add(expected.removesuffix("\n"))
    if not isinstance(prompt, str) or prompt not in accepted:
        raise ValueError(f"{role} automation prompt does not match the canonical template")
    if "\x00" in prompt or len(prompt.encode("utf-8")) > 32 * 1024:
        raise ValueError("automation prompt is invalid")
    lowered = prompt.casefold()
    forbidden = (
        str((runtime_root / "scripts").resolve()).casefold(),
        "local_publication_agent.py",
        "local_publication_worker.py",
        "local_dispatch_bridge.py",
        "current-ledger",
        "radar_ledger.sqlite3",
        "old-war-room",
        "/war-room/",
    )
    if any(item in lowered for item in forbidden) or _SECRET_LIKE.search(prompt):
        raise ValueError("automation prompt contains a forbidden runtime or secret reference")
    return hashlib.sha256(expected.encode("utf-8")).hexdigest()


def canonical_prompt(role: str, runtime_root: Path, release_command: list[str]) -> str:
    """Return the only prompt accepted for a release-bound automation."""

    if role not in {"heartbeat", "dailyWarRoom"}:
        raise ValueError("unknown automation role")
    command_text = shlex.join(release_command)
    final_reply_contract = (
        "every final reply, whether success or failure, must contain only the required "
        "plain sentence and nothing else; do not add extra text, UI directives, inbox markup "
        "including ::inbox-item, headers, Markdown, labels, or wrappers; "
    )
    if role == "heartbeat":
        action = (
            "execute only the release-command exactly as written, including its first interpreter token; never drop the interpreter or substitute a different path; it may take several minutes; inspect its final JSON; "
            "if context compaction or a missing tool result happens after the command starts, never reply from uncertainty and execute the identical release-command once more, which safely joins the already-running controller, then inspect that final JSON; "
            "if it contains desktopHandoff, send desktopHandoff.prompt unchanged exactly once to desktopHandoff.threadId even when command exit is nonzero or final JSON ok=false, because this handoff is the prescribed recovery action; "
            "only after that message-tool send succeeds reply '已开始或继续处理；你无需操作。'; "
            "when there is no desktopHandoff, if the command fails or final JSON ok=false, reply with one plain-Chinese sentence naming only the real user-visible blocker; "
            "when there is no desktopHandoff, it succeeds, and final JSON contains newPullRequest.prUrl, validate that value is an https://github.com/<owner>/<repo>/pull/<number> URL and reply with exactly two plain-text lines: first '新 PR 已创建：<newPullRequest.prUrl>' with the placeholder replaced by that exact URL, then '你无需操作。'; "
            "when there is no desktopHandoff, it succeeds, and there is no newPullRequest, reply exactly '运行正常；当前没有需要你处理的事情。'; "
            f"{final_reply_contract}"
            "never show JSON, paths, logs, prompts, or internal fields."
        )
    else:
        action = (
            "execute only the release-command exactly as written, including its first interpreter token; never drop the interpreter or substitute a different path; the command must include --send and is the only daily action; "
            "if context compaction or a missing tool result happens after the command starts, never reply from uncertainty and execute the identical release-command once more, which safely replays the daily cycle through its durable delivery deduplication, then inspect that final JSON; "
            "check command exit and final JSON ok; if the command fails or final JSON ok=false, reply with one plain-Chinese sentence naming only the real user-visible blocker; "
            "only when it succeeds, reply exactly '检查已完成；当前没有需要你处理的事情。'; "
            f"{final_reply_contract}"
            "never show JSON, paths, logs, prompts, or internal fields."
        )
    return (
        f"{AUTOMATION_PROMPT_TEMPLATE}\n"
        f"role={role}\n"
        f"runtime-root={runtime_root.resolve()}\n"
        f"release-command={command_text}\n"
        f"{action}\n"
    )


def _automation_entry(
    section: dict[str, Any], *, role: str, expected: dict[str, Any], runtime_root: Path
) -> dict[str, Any]:
    prompt_value = section.get("prompt")
    if isinstance(prompt_value, dict):
        prompt_value = prompt_value.get("text")
    now_ms = int(utc_now().timestamp() * 1000)
    for timestamp_key in ("created_at", "updated_at"):
        timestamp = section.get(timestamp_key)
        if not isinstance(timestamp, int) or timestamp <= 0 or timestamp > now_ms + 10 * 60 * 1000:
            raise ValueError(f"{role} automation {timestamp_key} is invalid")
    if section["updated_at"] < section["created_at"]:
        raise ValueError(f"{role} automation timestamps are not monotonic")
    required = {
        "version": section.get("version"),
        "name": section.get("name"),
        "id": section.get("id"),
        "kind": section.get("kind"),
        "status": section.get("status"),
        "rrule": section.get("rrule"),
    }
    if any(value is None for value in required.values()):
        raise ValueError(f"{role} automation TOML is missing required fields")
    if required["version"] != 1 or required["name"] != (
        HEARTBEAT_NAME if role == "heartbeat" else DAILY_WAR_ROOM_NAME
    ):
        raise ValueError(f"{role} automation version or name does not match the contract")
    for key in ("id", "kind", "status", "rrule"):
        if str(required[key]) != str(expected[key]):
            raise ValueError(f"{role} automation {key} does not match the contract")
    allowed = {
        "version",
        "name",
        "id",
        "kind",
        "status",
        "rrule",
        "created_at",
        "updated_at",
        "prompt",
    }
    allowed.add("target_thread_id")
    if section.get("target_thread_id") != expected.get("targetThreadId"):
        raise ValueError(f"{role} target thread does not match the contract")
    if set(section) != allowed:
        raise ValueError(f"{role} TOML has unsupported or missing fields")
    release_command = list(expected["releaseCommand"])
    prompt_digest = _prompt_digest(
        prompt_value,
        role=role,
        runtime_root=runtime_root,
        release_command=release_command,
    )
    return {
        "id": str(required["id"]),
        "kind": str(required["kind"]),
        "status": str(required["status"]),
        "rrule": str(required["rrule"]),
        "version": 1,
        "name": required["name"],
        "createdAt": section["created_at"],
        "updatedAt": section["updated_at"],
        "targetThreadId": str(expected["targetThreadId"]),
        "releaseCommand": release_command,
        # Keep the concrete release identity in the signed snapshot while the
        # command itself follows the stable current-release pointer.
        "releaseBinding": expected.get("releaseBinding"),
        "runtimeRoot": str(runtime_root.resolve()),
        "promptTemplate": AUTOMATION_PROMPT_TEMPLATE,
        "promptDigest": prompt_digest,
        "promptPolicy": AUTOMATION_PROMPT_POLICY,
    }


def _actual_workers(runtime_root: Path, home: Path, contracts: dict[str, Any]) -> dict[str, Any]:
    specs = worker_specs(
        Path(contracts["release"]["codeRoot"]), home=home, runtime_root=runtime_root
    )
    result: dict[str, Any] = {}
    for spec in specs:
        label = str(spec["Label"])
        path = home / "Library" / "LaunchAgents" / f"{label}.plist"
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"worker LaunchAgent plist is missing or symlinked: {path}")
        value = plistlib.loads(path.read_bytes())
        arguments = value.get("ProgramArguments") if isinstance(value, dict) else None
        workdir = value.get("WorkingDirectory") if isinstance(value, dict) else None
        if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
            raise ValueError(f"worker LaunchAgent command is invalid: {label}")
        if not isinstance(workdir, str):
            raise ValueError(f"worker LaunchAgent cwd is invalid: {label}")
        result[label] = {
            "command": list(arguments),
            "workdir": workdir,
            "status": "configured",
        }
    return result


def derive_automation_snapshot(
    runtime_root: Path,
    heartbeat_toml: Path,
    daily_toml: Path,
    *,
    home: Path | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Parse actual TOML/plists and derive, but do not sign, snapshot content."""

    runtime_root = runtime_root.resolve()
    binding = bind_runtime(runtime_root)
    home = (home or Path.home()).resolve()
    if heartbeat_toml.resolve() == daily_toml.resolve():
        raise ValueError("heartbeat and daily automation TOML paths must be distinct")
    heartbeat_raw, heartbeat_file = _file_metadata(heartbeat_toml, role="heartbeat")
    daily_raw, daily_file = _file_metadata(daily_toml, role="dailyWarRoom")
    contracts = build_contracts(runtime_root, home=home)
    heartbeat = _automation_entry(
        _automation_section(heartbeat_raw, heartbeat_toml),
        role="heartbeat",
        expected=contracts["heartbeat"],
        runtime_root=runtime_root,
    )
    daily = _automation_entry(
        _automation_section(daily_raw, daily_toml),
        role="dailyWarRoom",
        expected=contracts["dailyWarRoom"],
        runtime_root=runtime_root,
    )
    selected = observed_at or iso_z(utc_now())
    parsed = datetime.fromisoformat(selected.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("automation snapshot observed_at must include a timezone")
    return {
        "schema": AUTOMATION_SNAPSHOT_SCHEMA,
        "generator": AUTOMATION_SNAPSHOT_GENERATOR,
        "runtimeRootDigest": runtime_root_digest(runtime_root),
        "releaseId": binding.release_id,
        "releaseHead": binding.release.get("commit"),
        "releaseManifestSha256": binding.release.get("manifestSha256"),
        "observedAt": iso_z(parsed),
        "sourceFiles": [heartbeat_file, daily_file],
        "heartbeat": heartbeat,
        "dailyWarRoom": daily,
        "workers": _actual_workers(runtime_root, home, contracts),
    }


def build_automation_snapshot(
    runtime_root: Path,
    heartbeat_toml: Path,
    daily_toml: Path,
    *,
    home: Path | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    unsigned = derive_automation_snapshot(
        runtime_root,
        heartbeat_toml,
        daily_toml,
        home=home,
        observed_at=observed_at,
    )
    auth = sign_current(unsigned, context=AUTOMATION_SNAPSHOT_CONTEXT)
    if not auth.get("keyId") or not auth.get("signature"):
        raise PermissionError("current signing key is unavailable")
    return {**unsigned, **auth}
