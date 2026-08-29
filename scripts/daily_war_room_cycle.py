#!/usr/bin/env python3
"""Run one deterministic daily War Room cycle from an explicit runtime root."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.automation_run_receipt import (  # noqa: E402
    complete_automation_run,
    start_automation_run,
    write_automation_audit_report,
)
from oss_pr_radar.daily_war_room import run_daily_cycle  # noqa: E402
from oss_pr_radar.notifier import FeishuClient  # noqa: E402
from oss_pr_radar.operational_auth import require_operational_authorization  # noqa: E402
from oss_pr_radar.release_binding import bind_runtime  # noqa: E402
from oss_pr_radar.util import iso_z, utc_now  # noqa: E402

AUTOMATION_ID = "daily-github-open-pr-status-review"
AUTOMATION_ROLE = "daily-war-room"


def _error_result(blocked: str, exc: BaseException) -> dict[str, object]:
    return {
        "ok": False,
        "checkedAt": iso_z(utc_now()),
        "blocked": blocked,
        "error": f"{type(exc).__name__}:{str(exc)[:400]}",
    }


def _external_effects(
    result: dict[str, object] | None, *, send: bool, startup_effects_known: bool = False
) -> dict[str, object]:
    if result is None:
        return {"summaryAvailable": False}
    if "sendRequested" in result:
        return {
            "summaryAvailable": True,
            "feishu": {
                "sendRequested": bool(result.get("sendRequested")),
                "sent": int(result.get("sent") or 0),
                "failed": int(result.get("failed") or 0),
            },
            "cycleId": result.get("cycleId"),
        }
    # Authorization and credential checks happen before the sender is built,
    # so a structured startup blocker is known to have made no external call.
    if startup_effects_known:
        return {
            "summaryAvailable": True,
            "feishu": {"sendRequested": send, "sent": 0, "failed": 0},
        }
    return {"summaryAvailable": False, "unknown": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--send", action="store_true")
    args = parser.parse_args(argv)
    invocation_argv = [sys.argv[0], *(sys.argv[1:] if argv is None else argv)]
    initial_binding = None
    try:
        initial_binding = bind_runtime(args.runtime_root, code_root=ROOT)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        pass
    started = start_automation_run(
        args.runtime_root,
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
    binding = initial_binding
    cycle_entered = False
    try:
        if binding is None:
            binding = bind_runtime(args.runtime_root, code_root=ROOT)
        try:
            require_operational_authorization(args.runtime_root)
        except RuntimeError as exc:
            blocked_reason = "operational authorization required"
            error = f"{type(exc).__name__}:{str(exc)[:400]}"
            result = _error_result(blocked_reason, exc)
            startup_effects_known = True
        else:
            sender = None
            if args.send:
                app_id = os.environ.get("FEISHU_APP_ID")
                app_secret = os.environ.get("FEISHU_APP_SECRET")
                chat_id = os.environ.get("FEISHU_CHAT_ID")
                if not app_id or not app_secret or not chat_id:
                    raise RuntimeError("authenticated Feishu credentials are required for --send")
                client = FeishuClient(app_id, app_secret, chat_id)

                def sender(event: dict) -> str:
                    response = client.send_card(
                        event["card"], idempotency_key=event["idempotencyKey"]
                    )
                    return str((response.get("data") or {}).get("message_id") or "")

            cycle_entered = True
            result = run_daily_cycle(
                args.runtime_root,
                ledger=args.ledger,
                send=args.send,
                sender=sender,
                automation_run_id=str(started["runId"]),
            )
            result["release"] = {
                "releaseId": binding.release_id,
                "path": str(binding.code_root),
                "manifestSha256": binding.release.get("manifestSha256"),
            }
    except SystemExit as exc:
        blocked_reason = blocked_reason or "daily War Room cycle exited"
        error = str(exc)
        result = _error_result(blocked_reason, exc)
        startup_effects_known = not cycle_entered
    except RuntimeError as exc:
        blocked_reason = blocked_reason or "daily War Room cycle blocked"
        error = f"{type(exc).__name__}:{str(exc)[:400]}"
        result = _error_result(blocked_reason, exc)
        startup_effects_known = not cycle_entered
    except Exception as exc:  # pragma: no cover - exercised through entrypoint tests
        blocked_reason = "daily War Room cycle failed"
        error = f"{type(exc).__name__}:{str(exc)[:400]}"
        result = _error_result(blocked_reason, exc)
        startup_effects_known = not cycle_entered

    try:
        if result is not None:
            result = {**result, "automationRunId": started["runId"]}
            output_text = json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n"
            try:
                sys.stdout.write(output_text)
                sys.stdout.flush()
            except BaseException as exc:
                # The bytes may have been only partially delivered (for
                # example, a closed pipe), so do not attest to a final JSON
                # payload we cannot prove was emitted.
                final_text = None
                error = f"{type(exc).__name__}:{str(exc)[:400]}"
                blocked_reason = "final JSON delivery failed"
                raise
            final_text = output_text
            exit_code = 0 if result.get("ok") is True else 1
            blocked_reason = blocked_reason or str(result.get("blocked") or "") or None
            error = error or str(result.get("error") or "") or None
            if exit_code != 0 and not blocked_reason:
                if result.get("failed"):
                    blocked_reason = "daily Feishu delivery failures"
                else:
                    blocked_reason = "daily War Room cycle returned not ok"
        return exit_code
    finally:
        complete_automation_run(
            args.runtime_root,
            started,
            exit_code=exit_code,
            final_json_text=final_text,
            release_id=binding.release_id if binding is not None else None,
            error=error,
            blocked_reason=blocked_reason,
            external_effects=_external_effects(
                result,
                send=args.send,
                startup_effects_known=startup_effects_known,
            ),
        )
        try:
            write_automation_audit_report(
                args.runtime_root,
                automation_id=AUTOMATION_ID,
                expected_interval_minutes=24 * 60,
            )
        except (OSError, RuntimeError, ValueError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
