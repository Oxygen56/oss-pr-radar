"""Fast local collection and publication for completed Radar tasks."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

LAUNCH_AGENT_LABEL = "com.oss-pr-radar.local-publication"
SERVICE_PATH = (
    "/Applications/ChatGPT.app/Contents/Resources:"
    "/Applications/Codex.app/Contents/Resources:"
    "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:"
    "/usr/sbin:/sbin:/Library/Apple/usr/bin"
)
SENSITIVE_ENVIRONMENT_KEYS = {
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "FEISHU_APP_ID",
    "FEISHU_APP_SECRET",
    "MODEL_API_KEY",
    "OPENAI_API_KEY",
}


def _python(root: Path) -> Path:
    candidate = root / ".venv" / "bin" / "python"
    return candidate if candidate.exists() else Path(sys.executable)


def run_bridge(root: Path, operation: str, *, timeout: int = 900) -> dict[str, Any]:
    completed = subprocess.run(
        [str(_python(root)), str(root / "scripts" / "local_dispatch_bridge.py"), operation],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr or completed.stdout or "local bridge failed"
        raise RuntimeError(f"{operation}: {detail[:800]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{operation}: local bridge returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{operation}: local bridge returned a non-object")
    return value


def retryable_delivery_pending(root: Path, *, min_age_seconds: int = 60) -> bool:
    """Detect a durable no-turn receipt that is old enough to re-arm."""

    receipt_root = root / "state" / "task_turn_receipts"
    now = time.time()
    for path in receipt_root.glob("*.json"):
        if path.name.endswith(".launch.json"):
            continue
        try:
            if now - path.stat().st_mtime < min_age_seconds:
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if value.get("ok") is False and value.get("turnStarted") is False:
            return True
        if value.get("turnStatus") in {"failed", "interrupted"}:
            return True
    return False


def advance_once(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]] = run_bridge,
) -> dict[str, Any]:
    root = root.resolve()
    recovery = runner(root, "context-recover")
    recovery_errors = list(recovery.get("errors") or [])
    recovery_unavailable = list(recovery.get("unavailable") or [])
    public_unavailable = recovery_unavailable[:5]
    if recovery.get("ok") is False or recovery_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": [],
            "publicationRequests": [],
            "validationDeferred": [],
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": recovery_errors
            or [{"error": "task context recovery failed before result ingestion"}],
        }
    ingestion = runner(root, "ingest-results")
    ingestion_errors = list(ingestion.get("errors") or [])
    if ingestion.get("ok") is False or ingestion_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": list(ingestion.get("ingested") or []),
            "publicationRequests": list(ingestion.get("publicationRequests") or []),
            "validationDeferred": list(ingestion.get("validationDeferred") or []),
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": ingestion_errors
            or [{"error": "task result ingestion failed before publication"}],
        }
    independent_review = runner(root, "independent-review-run")
    review_errors = list(independent_review.get("errors") or [])
    review_updated = bool(independent_review.get("updated"))
    if (independent_review.get("ok") is False or review_errors) and not review_updated:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": list(ingestion.get("ingested") or []),
            "publicationRequests": list(ingestion.get("publicationRequests") or []),
            "validationDeferred": list(ingestion.get("validationDeferred") or []),
            "independentReview": independent_review,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": review_errors or [{"error": "independent review failed before publication"}],
        }
    post_review_ingestion = (
        runner(root, "ingest-results")
        if review_updated
        else {"ok": True, "ingested": [], "publicationRequests": [], "validationDeferred": []}
    )
    post_review_errors = list(post_review_ingestion.get("errors") or [])
    if post_review_ingestion.get("ok") is False or post_review_errors:
        return {
            "ok": False,
            "activity": True,
            "resultsIngested": [
                *list(ingestion.get("ingested") or []),
                *list(post_review_ingestion.get("ingested") or []),
            ],
            "publicationRequests": [
                *list(ingestion.get("publicationRequests") or []),
                *list(post_review_ingestion.get("publicationRequests") or []),
            ],
            "validationDeferred": [
                *list(ingestion.get("validationDeferred") or []),
                *list(post_review_ingestion.get("validationDeferred") or []),
            ],
            "independentReview": independent_review,
            "published": [],
            "contextsSynced": [],
            "pending": [],
            "blocked": [],
            "contextsUnavailable": public_unavailable,
            "contextsUnavailableCount": len(recovery_unavailable),
            "errors": post_review_errors
            or [{"error": "task result ingestion failed after independent review"}],
        }
    ingested = [
        *list(ingestion.get("ingested") or []),
        *list(post_review_ingestion.get("ingested") or []),
    ]
    title_reconciliation = runner(root, "title-reconcile")
    cleanup_reconciliation = runner(root, "cleanup-reconcile")
    publication = runner(root, "publication-run")
    published = list(publication.get("published") or [])
    context_sync = (
        runner(root, "context-sync") if published else {"ok": True, "written": [], "errors": []}
    )

    errors = [
        *review_errors,
        *list(title_reconciliation.get("errors") or []),
        *list(cleanup_reconciliation.get("errors") or []),
        *list(publication.get("errors") or []),
        *list(context_sync.get("errors") or []),
    ]
    requests = [
        *list(ingestion.get("publicationRequests") or []),
        *list(post_review_ingestion.get("publicationRequests") or []),
    ]
    validation_deferred = [
        *list(ingestion.get("validationDeferred") or []),
        *list(post_review_ingestion.get("validationDeferred") or []),
    ]
    blocked = list(publication.get("blocked") or [])
    pending = list(publication.get("pending") or [])
    renamed = list(title_reconciliation.get("renamed") or [])
    archived = list(cleanup_reconciliation.get("archived") or [])
    drain = {"ok": True, "action": "not_triggered"}
    terminal_feedback = {"ok": True, "published": 0, "errors": []}
    lifecycle_healthy = bool(
        not errors
        and title_reconciliation.get("ok") is not False
        and cleanup_reconciliation.get("ok") is not False
        and publication.get("ok") is not False
        and context_sync.get("ok") is not False
    )
    recovery = (
        runner(root, "recovery-list") if lifecycle_healthy else {"ok": False, "recoverable": []}
    )
    recoverable = list(recovery.get("recoverable") or []) if recovery.get("ok") else []
    should_drain = bool(
        ingested
        or validation_deferred
        or archived
        or published
        or recoverable
        or retryable_delivery_pending(root)
    )
    if should_drain and lifecycle_healthy:
        drain = runner(root, "drain-once")
        errors.extend(list(drain.get("errors") or []))
        if drain.get("terminalized"):
            terminal_feedback = runner(root, "publish-terminal-feedback")
            errors.extend(list(terminal_feedback.get("errors") or []))
    drain_activity = bool(
        drain.get("action")
        and drain.get("action") not in {"none", "not_triggered", "drain_already_running"}
    )
    activity = bool(
        ingested
        or requests
        or renamed
        or archived
        or published
        or blocked
        or errors
        or drain_activity
    )
    return {
        "ok": not errors
        and title_reconciliation.get("ok") is not False
        and cleanup_reconciliation.get("ok") is not False
        and publication.get("ok") is not False
        and context_sync.get("ok") is not False
        and drain.get("ok") is not False
        and terminal_feedback.get("ok") is not False,
        "activity": activity,
        "resultsIngested": ingested,
        "publicationRequests": requests,
        "validationDeferred": validation_deferred,
        "independentReview": independent_review,
        "titlesRenamed": renamed,
        "threadsArchived": archived,
        "published": published,
        "contextsSynced": list(context_sync.get("written") or []),
        "recoverable": recoverable,
        "drain": drain,
        "terminalFeedback": terminal_feedback,
        "pending": pending,
        "blocked": blocked,
        "contextsUnavailable": public_unavailable,
        "contextsUnavailableCount": len(recovery_unavailable),
        "errors": errors,
    }


def launch_agent_spec(root: Path, *, interval_seconds: int, home: Path) -> dict[str, Any]:
    root = root.resolve()
    interval = max(15, min(int(interval_seconds), 300))
    log_dir = home / "Library" / "Logs" / "oss-pr-radar"
    return {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [
            "/usr/bin/env",
            "-i",
            f"HOME={home}",
            f"USER={home.name}",
            f"LOGNAME={home.name}",
            "LANG=en_US.UTF-8",
            f"PATH={SERVICE_PATH}",
            str(_python(root)),
            str(root / "scripts" / "local_publication_agent.py"),
            "--root",
            str(root),
        ],
        "WorkingDirectory": str(root),
        "RunAtLoad": True,
        "StartInterval": interval,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "StandardOutPath": str(log_dir / "publication-agent.log"),
        "StandardErrorPath": str(log_dir / "publication-agent.error.log"),
    }


def write_launch_agent(path: Path, spec: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(spec, fmt=plistlib.FMT_XML, sort_keys=True))


def main() -> int:
    for key in SENSITIVE_ENVIRONMENT_KEYS:
        os.environ.pop(key, None)
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[2])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = advance_once(args.root)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        result = {"ok": False, "activity": True, "errors": [{"error": str(exc)[:800]}]}
    if args.json or result.get("activity") or not result.get("ok"):
        print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
