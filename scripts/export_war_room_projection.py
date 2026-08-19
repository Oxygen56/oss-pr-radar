#!/usr/bin/env python3
"""Export the one versioned War Room artifact and optional channel views."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oss_pr_radar.war_room_messages import build_outbox, validate_outboxes  # noqa: E402
from oss_pr_radar.war_room_projection import export_projection, write_views  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger-copy", type=Path, required=True)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--views", type=Path)
    parser.add_argument("--feishu-outbox", type=Path)
    parser.add_argument("--codex-outbox", type=Path)
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args()
    artifact = export_projection(args.ledger_copy, args.artifact, source_commit=args.source_commit)
    if args.views:
        write_views(artifact, args.views)
    outboxes = {
        "feishu": build_outbox(artifact, channel="feishu"),
        "codex": build_outbox(artifact, channel="codex"),
    }
    validate_outboxes(artifact, outboxes)
    if args.feishu_outbox:
        from oss_pr_radar.util import atomic_write_json

        atomic_write_json(args.feishu_outbox, outboxes["feishu"])
    if args.codex_outbox:
        from oss_pr_radar.util import atomic_write_json

        atomic_write_json(args.codex_outbox, outboxes["codex"])
    result = {
        "artifact": artifact,
        "outboxes": outboxes,
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
