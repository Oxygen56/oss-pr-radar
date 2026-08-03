#!/usr/bin/env python3
"""Provision one dispatch HMAC key to macOS Keychain and GitHub Actions."""

from __future__ import annotations

import argparse
import getpass
import secrets
import subprocess
import sys

KEYCHAIN_SERVICE = "oss-pr-radar-dispatch"
SECRET_NAME = "RADAR_DISPATCH_HMAC_KEY"


def run(args: list[str], *, stdin: str | None = None, check: bool = True) -> str:
    completed = subprocess.run(
        args,
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout)[:500])
    return completed.stdout.strip()


def existing_key() -> str | None:
    if sys.platform != "darwin":
        return None
    completed = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def store_keychain(value: str) -> None:
    if sys.platform != "darwin":
        raise RuntimeError("local key storage currently requires macOS Keychain")
    run(
        [
            "security",
            "add-generic-password",
            "-U",
            "-a",
            getpass.getuser(),
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            value,
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="Oxygen56/oss-pr-radar")
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--mode", choices=("shadow", "canary", "active"), default="shadow")
    args = parser.parse_args()

    value = None if args.rotate else existing_key()
    created = value is None
    if value is None:
        value = secrets.token_urlsafe(48)
        store_keychain(value)
    run(["gh", "secret", "set", SECRET_NAME, "--repo", args.repo], stdin=value)
    run(
        [
            "gh",
            "variable",
            "set",
            "RADAR_DISPATCH_MODE",
            "--repo",
            args.repo,
            "--body",
            args.mode,
        ]
    )
    print(
        f"dispatch signing configured: repo={args.repo}, mode={args.mode}, "
        f"local_key={'created' if created else 'reused'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
