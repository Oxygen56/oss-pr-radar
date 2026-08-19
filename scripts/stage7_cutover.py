#!/usr/bin/env python3
"""Prepare, activate, inspect, or roll back the local Stage 7 ledger pointer."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.stage7_cutover import (  # noqa: E402
    activate,
    bootstrap,
    build_stop_evidence,
    prepare,
    restore_git_preservation,
    rollback,
    status,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="phase", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--runtime-root", type=Path, required=True)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--quiesce-token", required=True)
    p.add_argument("--production-repo", type=Path)
    p.add_argument("--observed-at")
    p.add_argument("--max-attempts", type=int, default=3)
    p = sub.add_parser("stop-evidence")
    p.add_argument("--runtime-root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("bootstrap")
    p.add_argument("--runtime-root", type=Path, required=True)
    p.add_argument("--legacy-source", type=Path, required=True)
    p.add_argument("--service-stopped-evidence", type=Path, required=True)
    p.add_argument("--quiesce-token", required=True)
    p.add_argument("--max-attempts", type=int, default=3)
    for name in ("activate", "rollback"):
        command = sub.add_parser(name)
        command.add_argument("--runtime-root", type=Path, required=True)
        command.add_argument("--manifest", type=Path, required=True)
    restore = sub.add_parser("restore")
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--repo", type=Path, required=True)
    restore.add_argument("--mode", choices=("rehearse", "apply"), required=True)
    s = sub.add_parser("status")
    s.add_argument("--runtime-root", type=Path, required=True)
    args = parser.parse_args()
    if args.phase == "stop-evidence":
        value = build_stop_evidence(args.runtime_root)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(args.out, 0o600)
    elif args.phase == "bootstrap":
        value = bootstrap(
            args.runtime_root,
            args.legacy_source,
            quiesce_token=args.quiesce_token,
            service_stopped_evidence=args.service_stopped_evidence,
            max_attempts=args.max_attempts,
        )
    elif args.phase == "prepare":
        value = prepare(
            args.runtime_root,
            args.source,
            quiesce_token=args.quiesce_token,
            production_repo=args.production_repo,
            max_attempts=args.max_attempts,
            observed_at=args.observed_at,
        )
    elif args.phase == "activate":
        value = activate(args.runtime_root, args.manifest)
    elif args.phase == "rollback":
        value = rollback(args.runtime_root, args.manifest)
    elif args.phase == "restore":
        value = restore_git_preservation(args.manifest, args.repo, mode=args.mode)
    else:
        value = status(args.runtime_root)
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
