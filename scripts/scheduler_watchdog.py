#!/usr/bin/env python3
"""Run the independent hourly-slot GitHub Actions fallback watchdog."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.local_publication import worker_log_paths  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.release_binding import bind_runtime  # noqa: E402
from oss_pr_radar.runtime import (  # noqa: E402
    disk_pressure_gate,
    record_cycle,
    rotate_log,
)
from oss_pr_radar.scheduler_watchdog import (  # noqa: E402
    WATCHDOG_LABEL,
    WATCHDOG_WORKER,
    watchdog_cycle,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--repo", default="Oxygen56/oss-pr-radar")
    parser.add_argument("--workflow", default="radar.yml")
    parser.add_argument("--ref", default="main")
    parser.add_argument("--slot-minute", type=int, default=17)
    parser.add_argument("--grace-minutes", type=int, default=13)
    parser.add_argument("--window-hours", type=float, default=2.0)
    args = parser.parse_args()
    started = time.time()
    try:
        binding = bind_runtime(args.root)
        require_operational_authorization(args.root)
    except (OSError, RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "blocked": "operational authorization required",
                    "error": str(exc)[:400],
                }
            )
        )
        return 1

    stdout_path, stderr_path = worker_log_paths(WATCHDOG_LABEL, home=Path.home())
    rotate_log(stdout_path)
    rotate_log(stderr_path)
    gate = disk_pressure_gate(args.root, worker=WATCHDOG_WORKER)
    if gate.get("allowed") is not True:
        result = {
            "ok": True,
            "action": "disk_gate_blocked",
            "diskPressureGate": gate,
        }
    else:
        try:
            result = watchdog_cycle(
                args.root,
                repo=args.repo,
                workflow=args.workflow,
                ref=args.ref,
                window_hours=args.window_hours,
                slot_minute=args.slot_minute,
                grace_minutes=args.grace_minutes,
            )
        except PermissionError as exc:
            # A release-bound publication pause is an intentional gate.  Do
            # not consume the slot; the next five-minute cycle may retry after
            # the authorized resume.
            result = {"ok": True, "action": "publication_paused", "blocked": str(exc)[:200]}
        except Exception as exc:
            result = {
                "ok": False,
                "action": "failed",
                "error": f"{type(exc).__name__}:{str(exc)[:400]}",
            }

    record_cycle(
        args.root,
        worker=WATCHDOG_WORKER,
        ok=result.get("ok") is True,
        exit_code=0 if result.get("ok") is True else 1,
        started_at=started,
        error_code=None if result.get("ok") is True else str(result.get("action") or "FAILED"),
        release_version=binding.release_id,
        policy_digest=str(binding.release.get("policyDigest") or ""),
        watchdogAction=result.get("action"),
        watchdogSlotAt=result.get("slotAt"),
        watchdogFallbackKey=result.get("fallbackKey"),
        githubNaturalScheduleHealthy=result.get("githubNaturalScheduleHealthy"),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
