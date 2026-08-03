#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.dispatch import DispatchSigner, build_queue  # noqa: E402
from oss_pr_radar.util import sha256_json  # noqa: E402


def digest(value: Any) -> str:
    return sha256_json(value)


def build(
    report: dict[str, Any],
    existing: dict[str, Any] | None = None,
    *,
    signing_key: str,
    mode: str = "shadow",
    now: datetime | None = None,
    source_sha: str = "",
) -> dict[str, Any]:
    return build_queue(
        report,
        DispatchSigner(signing_key),
        existing=existing,
        now=now or datetime.now(UTC),
        mode=mode,
        source_sha=source_sha,
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--queue", type=Path)
    parser.add_argument("--mode", choices=("shadow", "canary", "active"))
    parser.add_argument("--ttl-minutes", type=int, default=120)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    existing = None
    if args.queue and args.queue.exists():
        existing = json.loads(args.queue.read_text(encoding="utf-8"))
    signing_key = os.environ.get("RADAR_DISPATCH_HMAC_KEY")
    if not signing_key:
        raise SystemExit("RADAR_DISPATCH_HMAC_KEY is required")
    intents = build_queue(
        report,
        DispatchSigner(signing_key),
        existing=existing,
        ttl_minutes=args.ttl_minutes,
        mode=args.mode or os.environ.get("RADAR_DISPATCH_MODE", "shadow"),
        source_sha=os.environ.get("GITHUB_SHA", ""),
    )
    write_json(args.output, intents)
    if args.queue:
        write_json(args.queue, intents)
    print(
        json.dumps(
            {
                "dispatch_mode": intents["mode"],
                "dispatch_intents": len(intents["intents"]),
                "new_dispatch_intents": intents["newIntentCount"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
