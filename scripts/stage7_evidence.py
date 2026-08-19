#!/usr/bin/env python3
"""Generate authenticated Stage 7 evidence from explicit local inputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.automation_snapshot import build_automation_snapshot  # noqa: E402
from oss_pr_radar.operational_auth import (  # noqa: E402
    authorization_path,
    issue_worker_staging_authorization,
)
from oss_pr_radar.runtime import write_json  # noqa: E402
from oss_pr_radar.stage7_acceptance import (  # noqa: E402
    build_managed_counts_evidence,
    issue_operational_authorization,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="kind", required=True)
    automation = sub.add_parser("automation-snapshot")
    automation.add_argument("--runtime-root", type=Path, required=True)
    automation.add_argument("--heartbeat-toml", type=Path, required=True)
    automation.add_argument("--daily-toml", type=Path, required=True)
    automation.add_argument("--home", type=Path)
    automation.add_argument("--observed-at")
    automation.add_argument("--out", type=Path, required=True)
    counts = sub.add_parser("managed-counts")
    counts.add_argument("--runtime-root", type=Path, required=True)
    counts.add_argument("--report", type=Path, required=True)
    counts.add_argument("--envelope", type=Path, required=True)
    counts.add_argument("--code-head", required=True)
    counts.add_argument("--out", type=Path, required=True)
    authorization = sub.add_parser("operational-authorization")
    authorization.add_argument("--runtime-root", type=Path, required=True)
    authorization.add_argument("--managed-counts-evidence", type=Path, required=True)
    authorization.add_argument("--automation-snapshot", type=Path, required=True)
    authorization.add_argument("--home", type=Path)
    staging = sub.add_parser("worker-staging-authorization")
    staging.add_argument("--runtime-root", type=Path, required=True)
    staging.add_argument("--managed-counts-evidence", type=Path, required=True)
    staging.add_argument("--home", type=Path)
    args = parser.parse_args()
    if args.kind == "automation-snapshot":
        value = build_automation_snapshot(
            args.runtime_root,
            args.heartbeat_toml,
            args.daily_toml,
            home=args.home,
            observed_at=args.observed_at,
        )
        write_json(args.out, value)
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    elif args.kind == "managed-counts":
        value = build_managed_counts_evidence(
            args.runtime_root,
            args.report,
            args.envelope,
            code_head=args.code_head,
        )
        write_json(args.out, value)
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    elif args.kind == "worker-staging-authorization":
        value = issue_worker_staging_authorization(
            args.runtime_root,
            managed_counts_evidence=args.managed_counts_evidence,
            home=args.home,
        )
        print(json.dumps({
            "ok": True,
            "schema": value["schema"],
            "scope": value["scope"],
            "path": str(args.runtime_root.resolve() / "state" / "worker-staging-authorization.json"),
            "expiresAt": value["expiresAt"],
        }, ensure_ascii=False, sort_keys=True))
    else:
        value = issue_operational_authorization(
            args.runtime_root,
            managed_counts_evidence=args.managed_counts_evidence,
            automation_snapshot=args.automation_snapshot,
            home=args.home,
        )
        print(json.dumps({
            "ok": True,
            "schema": value["schema"],
            "path": str(authorization_path(args.runtime_root)),
            "releaseId": value["releaseId"],
            "ledgerTarget": value["ledgerTarget"],
        }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
