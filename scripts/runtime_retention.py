#!/usr/bin/env python3
"""Plan, apply, or restore bounded Radar runtime retention."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.runtime import exclusive_lock  # noqa: E402
from oss_pr_radar.runtime_retention import (  # noqa: E402
    DEFAULT_ARCHIVE_KEEP_LATEST,
    DEFAULT_ARCHIVE_MIN_AGE_SECONDS,
    DEFAULT_KEEP_LATEST,
    DEFAULT_MAX_ARCHIVES,
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MIN_AGE_SECONDS,
    RETENTION_LOCK,
    apply_runtime_retention,
    plan_runtime_retention,
    restore_runtime_archive,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true")
    action.add_argument("--restore", type=Path)
    parser.add_argument(
        "--min-age-hours",
        type=float,
        default=DEFAULT_MIN_AGE_SECONDS / 3600,
    )
    parser.add_argument("--keep-latest", type=int, default=DEFAULT_KEEP_LATEST)
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument(
        "--archive-min-age-hours",
        type=float,
        default=DEFAULT_ARCHIVE_MIN_AGE_SECONDS / 3600,
    )
    parser.add_argument("--archive-keep-latest", type=int, default=DEFAULT_ARCHIVE_KEEP_LATEST)
    parser.add_argument("--max-archives", type=int, default=DEFAULT_MAX_ARCHIVES)
    args = parser.parse_args()
    min_age_seconds = int(args.min_age_hours * 3600)
    archive_min_age_seconds = int(args.archive_min_age_hours * 3600)
    try:
        if args.apply or args.restore:
            require_operational_authorization(args.root)
        if args.restore:
            with exclusive_lock(args.root / "state" / RETENTION_LOCK, blocking=False):
                result = restore_runtime_archive(args.root, args.restore)
        elif args.apply:
            with exclusive_lock(args.root / "state" / RETENTION_LOCK, blocking=False):
                plan = plan_runtime_retention(
                    args.root,
                    min_age_seconds=min_age_seconds,
                    keep_latest=args.keep_latest,
                    max_candidates=args.max_candidates,
                    archive_min_age_seconds=archive_min_age_seconds,
                    archive_keep_latest=args.archive_keep_latest,
                    max_archives=args.max_archives,
                )
                result = apply_runtime_retention(
                    args.root,
                    plan=plan,
                    min_age_seconds=min_age_seconds,
                    keep_latest=args.keep_latest,
                    max_candidates=args.max_candidates,
                    archive_min_age_seconds=archive_min_age_seconds,
                    archive_keep_latest=args.archive_keep_latest,
                    max_archives=args.max_archives,
                )
        else:
            result = plan_runtime_retention(
                args.root,
                min_age_seconds=min_age_seconds,
                keep_latest=args.keep_latest,
                max_candidates=args.max_candidates,
                archive_min_age_seconds=archive_min_age_seconds,
                archive_keep_latest=args.archive_keep_latest,
                max_archives=args.max_archives,
            )
    except (OSError, RuntimeError, ValueError) as exc:
        result = {
            "ok": False,
            "blocked": "runtime retention failed closed",
            "error": f"{type(exc).__name__}:{str(exc)[:400]}",
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
