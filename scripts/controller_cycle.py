#!/usr/bin/env python3
"""Run one deterministic OSS PR Radar desktop controller cycle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.automation_run_receipt import (  # noqa: E402
    complete_automation_run,
    start_automation_run,
    write_automation_audit_report,
)
from oss_pr_radar.controller import (  # noqa: E402
    DEFAULT_PROJECT_ID,
    compact_controller_result,
    run_locked_controller_cycle,
)
from oss_pr_radar.release_binding import bind_runtime  # noqa: E402
from oss_pr_radar.util import iso_z, utc_now  # noqa: E402

AUTOMATION_ID = "oss-pr-radar"
AUTOMATION_ROLE = "controller-heartbeat"
MAX_FAILURE_LABELS = 8
MAX_FAILURE_SECTION_CHARS = 240


def _error_result(blocked: str, exc: BaseException) -> dict[str, object]:
    return {
        "ok": False,
        "checkedAt": iso_z(utc_now()),
        "blocked": blocked,
        "error": f"{type(exc).__name__}:{str(exc)[:400]}",
    }


def _bounded_failure_labels(
    values: object,
    *,
    include_queue: bool,
) -> list[str]:
    if not isinstance(values, list):
        return []
    labels: list[str] = []
    characters = 0
    for item in values:
        if isinstance(item, dict):
            stage = str(item.get("stage") or "").strip()
            queue = str(item.get("queue") or "").strip()
            label = f"{stage}:{queue}" if include_queue and stage and queue else stage
        elif isinstance(item, str):
            label = item.strip()
        else:
            continue
        label = label[:80]
        if not label or label in labels:
            continue
        added = len(label) + (1 if labels else 0)
        if len(labels) >= MAX_FAILURE_LABELS or characters + added > MAX_FAILURE_SECTION_CHARS:
            break
        labels.append(label)
        characters += added
    return labels


def _controller_failure_summary(result: dict[str, object]) -> str | None:
    parts: list[str] = []
    blockers = result.get("finalBlockers")
    failures = result.get("failures")
    blocker_labels = _bounded_failure_labels(blockers, include_queue=True)
    failure_labels = _bounded_failure_labels(failures, include_queue=False)
    if isinstance(blockers, list) and blockers:
        suffix = ": " + ",".join(blocker_labels) if blocker_labels else ""
        parts.append("controller final blockers" + suffix)
    if isinstance(failures, list) and failures:
        suffix = ": " + ",".join(failure_labels) if failure_labels else ""
        parts.append("controller stage failures" + suffix)
    return "; ".join(parts) or None


def _external_effects(
    result: dict[str, object] | None, *, startup_effects_known: bool = False
) -> dict[str, object]:
    """Keep a bounded, non-sensitive summary of effects visible in final JSON."""

    if result is None:
        return {"summaryAvailable": False}
    stages = result.get("stages")
    if not isinstance(stages, dict):
        # Startup authorization/release blockers occur before any effectful
        # stage; an unexpected error is intentionally marked unknown.
        return {
            "summaryAvailable": startup_effects_known,
            "unknown": not startup_effects_known,
        }
    publication = stages.get("publication")
    publication = publication if isinstance(publication, dict) else {}
    published = []
    for item in publication.get("published") or []:
        if not isinstance(item, dict):
            continue
        compact = {
            key: item[key]
            for key in ("key", "requestId", "prUrl", "commitSha")
            if item.get(key) is not None
        }
        if compact:
            published.append(compact)
    notifications = stages.get("dispatchNotifications")
    notifications = notifications if isinstance(notifications, dict) else {}
    alerts = stages.get("alerts")
    alerts = alerts if isinstance(alerts, dict) else {}
    notified = [
        {
            key: item[key]
            for key in ("key", "threadId")
            if isinstance(item, dict) and item.get(key) is not None
        }
        for item in (notifications.get("notified") or [])
        if isinstance(item, dict)
    ]
    drain = stages.get("drain")
    drain = drain if isinstance(drain, dict) else {}
    return {
        "summaryAvailable": True,
        "github": {"publishedCount": len(published), "published": published[:50]},
        "feishu": {
            "notifiedCount": len(notified),
            "notified": notified[:50],
            "alertsNotified": bool(alerts.get("notified")),
        },
        "codex": {
            "drainAction": drain.get("action"),
            "drainKey": drain.get("key"),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--code-root",
        type=Path,
        default=ROOT,
        help="explicit release code root; it must equal --root/current-release",
    )
    parser.add_argument("--project-id", default=DEFAULT_PROJECT_ID)
    parser.add_argument("--no-notify", action="store_true")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args(argv)
    invocation_argv = [sys.argv[0], *(sys.argv[1:] if argv is None else argv)]
    initial_binding = None
    try:
        initial_binding = bind_runtime(args.root, code_root=args.code_root)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        # The controller performs its authoritative binding after taking its
        # lock.  This best-effort early read only pins the receipt identity;
        # startup blockers are still reported by the real controller path.
        pass
    started = start_automation_run(
        args.root,
        automation_id=AUTOMATION_ID,
        role=AUTOMATION_ROLE,
        argv=invocation_argv,
        release_id=initial_binding.release_id if initial_binding is not None else None,
    )
    result: dict[str, object] | None = None
    final_text: str | None = None
    exit_code = 1
    error: str | None = None
    blocked_reason: str | None = None
    startup_effects_known = False
    try:
        result = run_locked_controller_cycle(
            args.root,
            code_root=args.code_root,
            notify=not args.no_notify,
            project_id=args.project_id,
            wait_existing=True,
            report_on_complete=True,
            automation_run_id=str(started["runId"]),
        )
        report_path = args.root.resolve() / "reports" / "latest_controller_cycle.json"
        output = result if args.full else compact_controller_result(result, report_path=report_path)
        output = {**output, "automationRunId": started["runId"]}
        output_text = json.dumps(output, ensure_ascii=False) + "\n"
        try:
            sys.stdout.write(output_text)
            sys.stdout.flush()
        except BaseException as exc:
            final_text = None
            error = f"{type(exc).__name__}:{str(exc)[:400]}"
            blocked_reason = "final JSON delivery failed"
            raise
        final_text = output_text
        exit_code = 0 if result.get("ok") is True else 1
        blocked_reason = str(result.get("blocked") or "") or None
        error = str(result.get("error") or "") or None
        if exit_code != 0 and not blocked_reason:
            blocked_reason = _controller_failure_summary(result)
        startup_effects_known = bool(result.get("blocked")) and not result.get("stages")
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 1
        error = str(exc)
        blocked_reason = "controller command exited"
        result = _error_result(blocked_reason, exc)
        output = {**result, "automationRunId": started["runId"]}
        output_text = json.dumps(output, ensure_ascii=False) + "\n"
        try:
            sys.stdout.write(output_text)
            sys.stdout.flush()
        except BaseException as exc:
            final_text = None
            error = f"{type(exc).__name__}:{str(exc)[:400]}"
            blocked_reason = "final JSON delivery failed"
            raise
        final_text = output_text
    except Exception as exc:  # pragma: no cover - exercised through entrypoint tests
        if blocked_reason == "final JSON delivery failed":
            # Do not attempt a second payload after a partial/broken stdout
            # write; the receipt must record the delivery failure as-is.
            raise
        exit_code = 1
        error = f"{type(exc).__name__}:{str(exc)[:400]}"
        blocked_reason = "controller command failed"
        result = _error_result(blocked_reason, exc)
        output = {**result, "automationRunId": started["runId"]}
        output_text = json.dumps(output, ensure_ascii=False) + "\n"
        try:
            sys.stdout.write(output_text)
            sys.stdout.flush()
        except BaseException as exc:
            final_text = None
            error = f"{type(exc).__name__}:{str(exc)[:400]}"
            blocked_reason = "final JSON delivery failed"
            raise
        final_text = output_text
    finally:
        bound_release_id = (
            result.get("boundReleaseId")
            if isinstance(result, dict) and isinstance(result.get("boundReleaseId"), str)
            else None
        )
        complete_automation_run(
            args.root,
            started,
            exit_code=exit_code,
            final_json_text=final_text,
            release_id=bound_release_id,
            error=error,
            blocked_reason=blocked_reason,
            external_effects=_external_effects(result, startup_effects_known=startup_effects_known),
        )
        try:
            write_automation_audit_report(
                args.root,
                automation_id=AUTOMATION_ID,
                expected_interval_minutes=60,
            )
        except (OSError, RuntimeError, ValueError):
            # Keep the terminal receipt authoritative if disk pressure or a
            # transient read race prevents refreshing the derived view.
            pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
