#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SKILL = "[$gh-issue-pr](/Users/oxygen/.codex/skills/gh-issue-pr/SKILL.md)"


def digest(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def build(
    report: dict[str, Any], existing: dict[str, Any] | None = None
) -> dict[str, Any]:
    now = datetime.now(UTC)
    queued = {
        item.get("key"): item
        for item in (existing or {}).get("intents", [])
        if isinstance(item, dict) and item.get("key")
    }
    intents = []
    for candidate in report.get("candidate_details") or []:
        review = candidate.get("llm_review") or {}
        if not (
            candidate.get("auto_spawn") is True
            and candidate.get("gate_decision") == "ALLOW_TO_WORK"
            and review.get("status") == "ok"
            and review.get("decision")
            in {"NEW_CLEAN_CANDIDATE", "PR_COMPETITION_OPPORTUNITY"}
        ):
            continue
        url = str(candidate["url"])
        item = {
            "key": f"{candidate['repo']}#{candidate['num']}",
            "repo": candidate["repo"],
            "issueNumber": candidate["num"],
            "issueUrl": url,
            "title": candidate["title"],
            "category": candidate["category"],
            "score": candidate["score"],
            "prompt": f"{SKILL}\n{url}",
            "scannerVersion": report.get("scanner_version"),
        }
        item["intentDigest"] = digest(item)
        previous = queued.get(item["key"])
        item["queuedAt"] = (
            previous.get("queuedAt")
            if isinstance(previous, dict)
            and previous.get("intentDigest") == item["intentDigest"]
            else now.isoformat().replace("+00:00", "Z")
        )
        intents.append(item)
        queued[item["key"]] = item
    return {
        "version": "dispatch_intents_v1",
        "generatedAt": now.isoformat().replace("+00:00", "Z"),
        "scanNow": report.get("now"),
        "intents": sorted(queued.values(), key=lambda item: item["key"]),
        "newIntentCount": len(intents),
    }


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
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    existing = None
    if args.queue and args.queue.exists():
        existing = json.loads(args.queue.read_text(encoding="utf-8"))
    intents = build(report, existing)
    write_json(args.output, intents)
    if args.queue:
        write_json(args.queue, intents)
    print(
        json.dumps(
            {
                "dispatch_intents": len(intents["intents"]),
                "new_dispatch_intents": intents["newIntentCount"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
