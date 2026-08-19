#!/usr/bin/env python3
"""Create the read-only live PR state input required by Stage 6."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.github_client import GitHubClient  # noqa: E402
from oss_pr_radar.live_pr_snapshot import (  # noqa: E402
    build_live_snapshot,
    validate_snapshot_binding,
    write_live_snapshot,
)
from oss_pr_radar.util import canonical_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True, help="legacy production ledger")
    parser.add_argument("--legacy-db", type=Path, required=True, help="legacy War Room database")
    parser.add_argument("--legacy-reports", type=Path, required=True)
    parser.add_argument("--followup", type=Path, required=True)
    parser.add_argument("--quiesce-token", required=True)
    parser.add_argument("--out", "--output", dest="output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args()
    value = build_live_snapshot(
        args.source,
        legacy_db=args.legacy_db,
        legacy_reports=args.legacy_reports,
        followup=args.followup,
        quiesce_token=args.quiesce_token,
        client=GitHubClient(),
        workers=args.workers,
        max_attempts=args.max_attempts,
    )
    # Do not publish even a fully fetched snapshot until its final evidence,
    # freshness, URL/key-set, and input bindings have been checked together.
    validate_snapshot_binding(
        value,
        source=args.source,
        legacy_db=args.legacy_db,
        legacy_reports=args.legacy_reports,
        followup=args.followup,
    )
    # Validate the exact bytes that are about to be replaced, not only the
    # in-memory object returned by the API collector.
    serialized = (canonical_json(value) + "\n").encode("utf-8")
    serialized_value = json.loads(serialized.decode("utf-8"))
    validate_snapshot_binding(
        serialized_value,
        source=args.source,
        legacy_db=args.legacy_db,
        legacy_reports=args.legacy_reports,
        followup=args.followup,
    )
    write_live_snapshot(
        args.output,
        value,
        validator=lambda candidate: validate_snapshot_binding(
            candidate,
            source=args.source,
            legacy_db=args.legacy_db,
            legacy_reports=args.legacy_reports,
            followup=args.followup,
        ),
    )
    written_value = json.loads(args.output.read_text(encoding="utf-8"))
    validate_snapshot_binding(
        written_value,
        source=args.source,
        legacy_db=args.legacy_db,
        legacy_reports=args.legacy_reports,
        followup=args.followup,
    )
    print(
        json.dumps(
            {
                "ok": True,
                "schema": value["schema"],
                "out": str(args.output),
                "managedPrCount": len(value["managedKeys"]),
                "keySetDigest": value["keySetDigest"],
                "sourceGenerationDigest": value["sourceGeneration"]["generation"],
                "generatedAt": value["generatedAt"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
