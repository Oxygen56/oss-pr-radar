#!/usr/bin/env python3
"""Create a versioned, relative-path Stage 6 evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.release_binding import (  # noqa: E402
    require_stable_code_identity,
    resolve_code_identity,
)
from oss_pr_radar.stage6_rehearsal import (  # noqa: E402
    artifact_manifest,
    public_safe_scan,
    secure_atomic_json,
    secure_atomic_private_json,
    secure_permissions,
    validate_detached_report_envelope,
    write_detached_report_envelope,
)
from oss_pr_radar.stage6_verification import (  # noqa: E402
    VERSIONED_DEFINITIONS,
    build_verification_manifest,
    validate_verification_manifest,
)


def _head() -> str:
    return resolve_code_identity(ROOT).commit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--verification-out", type=Path, required=True)
    parser.add_argument("--code-head", default=None)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--commands", type=Path)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if bool(args.results) == args.run:
        raise ValueError("provide exactly one of --results or --run")
    initial_identity = resolve_code_identity(ROOT)
    current_head = initial_identity.commit
    code_head = args.code_head or current_head
    if code_head != current_head:
        raise ValueError("--code-head must match the current code identity")
    results = {}
    command_environment = os.environ.copy()
    interpreter_bin = str(Path(sys.executable).parent)
    command_environment["PATH"] = f"{interpreter_bin}{os.pathsep}{command_environment.get('PATH', '')}"
    if args.results:
        results = json.loads(args.results.read_text(encoding="utf-8"))
    elif args.run:
        for item in VERSIONED_DEFINITIONS["commands"]:
            completed = subprocess.run(
                item["command"],
                cwd=ROOT,
                shell=True,
                check=False,
                capture_output=True,
                text=True,
                env=command_environment,
            )
            output = (completed.stdout + completed.stderr).encode("utf-8")
            results[item["id"]] = {
                "status": "passed" if completed.returncode == 0 else "failed",
                "exitCode": completed.returncode,
                "outputDigest": hashlib.sha256(output).hexdigest(),
            }
    require_stable_code_identity(ROOT, initial_identity)
    commands = None
    if args.commands:
        commands = json.loads(args.commands.read_text(encoding="utf-8"))
    verification = build_verification_manifest(code_head, results=results)
    if commands is not None and commands != verification["definitions"]["commands"]:
        raise ValueError("commands must match the versioned verification definitions")
    verification = validate_verification_manifest(verification, code_head)
    root = args.artifact_root.resolve()
    verification_path = args.verification_out.resolve()
    if verification_path == root or verification_path.parent == root or root in verification_path.parents or verification_path.parent in root.parents:
        raise ValueError("verification output must use a separate root from the Stage 6 artifact root")
    secure_atomic_private_json(verification_path, verification)
    persisted_verification = json.loads(verification_path.read_text(encoding="utf-8"))
    validate_verification_manifest(persisted_verification, code_head)
    root.mkdir(parents=True, exist_ok=True)
    secure_permissions(root)
    envelope_path = root / "stage6-public-envelope.json"
    envelope_path.unlink(missing_ok=True)
    manifest = artifact_manifest(root, exclude_names={"stage6-public-summary.json", envelope_path.name})
    report = {
        "schema": "oss-pr-radar.stage6.report.v2",
        "codeHead": code_head,
        "verification": verification,
        "artifactManifest": manifest,
        "detachedEnvelope": {
            "path": envelope_path.name,
            "classification": "PUBLIC_SAFE",
            "binds": "report bytes and exact code HEAD",
        },
    }
    report_path = root / "stage6-public-summary.json"
    secure_atomic_json(report_path, report)
    envelope_inventory = artifact_manifest(root, exclude_names={envelope_path.name})
    write_detached_report_envelope(
        report_path,
        envelope_path,
        code_head=code_head,
        inventory=envelope_inventory,
    )
    secure_permissions(root)
    validate_detached_report_envelope(report_path, envelope_path, code_head=code_head)
    print(json.dumps({"ok": True, "publicSafe": public_safe_scan(root)["publicSafe"], "fileCount": len(envelope_inventory["files"]), "verificationOut": str(verification_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
