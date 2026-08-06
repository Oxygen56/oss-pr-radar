"""Fast local collection and publication for completed Radar tasks."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

LAUNCH_AGENT_LABEL = "com.oss-pr-radar.local-publication"
SERVICE_PATH = (
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


def advance_once(
    root: Path,
    *,
    runner: Callable[[Path, str], dict[str, Any]] = run_bridge,
) -> dict[str, Any]:
    root = root.resolve()
    ingestion = runner(root, "ingest-results")
    publication = runner(root, "publication-run")
    published = list(publication.get("published") or [])
    context_sync = (
        runner(root, "context-sync") if published else {"ok": True, "written": [], "errors": []}
    )

    errors = [
        *list(ingestion.get("errors") or []),
        *list(publication.get("errors") or []),
        *list(context_sync.get("errors") or []),
    ]
    ingested = list(ingestion.get("ingested") or [])
    requests = list(ingestion.get("publicationRequests") or [])
    blocked = list(publication.get("blocked") or [])
    pending = list(publication.get("pending") or [])
    activity = bool(ingested or requests or published or blocked or errors)
    return {
        "ok": not errors
        and ingestion.get("ok") is not False
        and publication.get("ok") is not False
        and context_sync.get("ok") is not False,
        "activity": activity,
        "resultsIngested": ingested,
        "publicationRequests": requests,
        "published": published,
        "contextsSynced": list(context_sync.get("written") or []),
        "pending": pending,
        "blocked": blocked,
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
