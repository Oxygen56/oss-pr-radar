"""Watch held opportunities for maintainer, ownership, PR, and policy changes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any

from .evidence import collect_evidence
from .github_client import GitHubClient
from .repo_policy import discover_policy
from .util import iso_z, parse_time, sha256_json

WATCHLIST_VERSION = "opportunity_watchlist_v1"


def build_watchlist(
    report: dict[str, Any],
    existing: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
    ttl_days: int = 14,
) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    retained: dict[str, dict[str, Any]] = {}
    if isinstance(existing, dict) and existing.get("version") == WATCHLIST_VERSION:
        for item in existing.get("items") or []:
            if not isinstance(item, dict):
                continue
            try:
                if parse_time(str(item["expiresAt"])) > current:
                    retained[str(item["key"])] = item
            except (KeyError, TypeError, ValueError):
                continue
    for candidate in report.get("candidate_details") or []:
        if not isinstance(candidate, dict):
            continue
        key = f"{candidate.get('repo')}#{candidate.get('num')}"
        queued = bool(
            candidate.get("auto_spawn") is True
            and candidate.get("gate_decision") == "ALLOW_TO_WORK"
        )
        held = bool(
            candidate.get("category")
            in {
                "WAIT_MAINTAINER",
                "PR_COMPETITION_OPPORTUNITY",
            }
            or candidate.get("gate_decision") == "HUMAN_REVIEW"
        )
        if not queued and not held:
            retained.pop(key, None)
            continue
        previous = retained.get(key) or {}
        retained[key] = {
            "key": key,
            "repo": candidate["repo"],
            "issueNumber": candidate["num"],
            "issueUrl": candidate["url"],
            "issueTitle": candidate["title"],
            "issueUpdated": candidate.get("issue_updated") or "",
            "category": candidate.get("category"),
            "gateDecision": candidate.get("gate_decision"),
            "status": "QUEUED" if queued else "WATCHING",
            "reason": candidate.get("next_step") or candidate.get("risk") or "",
            "evidenceDigest": candidate.get("evidence_digest") or "",
            "policyDigest": candidate.get("policy_digest") or "",
            "createdAt": previous.get("createdAt") or iso_z(current),
            "lastCheckedAt": previous.get("lastCheckedAt"),
            "expiresAt": iso_z(current + timedelta(days=max(1, ttl_days))),
        }
    value = {
        "version": WATCHLIST_VERSION,
        "generatedAt": iso_z(current),
        "items": sorted(retained.values(), key=lambda item: item["key"]),
    }
    value["digest"] = sha256_json({key: item for key, item in value.items() if key != "digest"})
    return value


def recheck_watchlist(
    watchlist: dict[str, Any],
    client: GitHubClient,
    *,
    limit: int = 20,
    current_actor: str = "Oxygen56",
    hardware_inventory: set[str] | None = None,
    now: datetime | None = None,
    workers: int = 3,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = monotonic()
    if watchlist.get("version") != WATCHLIST_VERSION:
        raise ValueError("unsupported opportunity watchlist")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    items = [item for item in watchlist.get("items") or [] if isinstance(item, dict)]
    items.sort(key=lambda item: str(item.get("lastCheckedAt") or ""))
    updates: list[dict[str, Any]] = []
    pending_rechecks: dict[str, Any] = {}
    selected = items[: max(0, limit)]
    worker_count = max(1, min(int(workers), 4, len(selected) or 1))
    repos = sorted({str(item["repo"]) for item in selected})
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        policies = dict(
            zip(
                repos,
                executor.map(lambda repo: discover_policy(client, repo), repos),
                strict=True,
            )
        )

    def inspect(
        item: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
        evidence = collect_evidence(
            client,
            str(item["repo"]),
            int(item["issueNumber"]),
            current_actor=current_actor,
            hardware_inventory=hardware_inventory,
            policy_snapshot=policies[str(item["repo"])],
        )
        previous_status = str(item.get("status") or "WATCHING")
        new_status = previous_status if previous_status in {"QUEUED", "WATCHING"} else "WATCHING"
        reason = "NO_ACTIONABLE_CHANGE"
        if not evidence.complete:
            new_status = "DATA_HOLD"
            reason = "EVIDENCE_INCOMPLETE"
        elif str(evidence.issue.get("state") or "").lower() != "open":
            new_status = "CLOSED"
            reason = "ISSUE_NOT_OPEN"
        elif evidence.issue.get("assignees") or evidence.claims:
            new_status = "COVERED"
            reason = "OWNERSHIP_CHANGED"
        elif any(
            relation.get("relation") in {"STRONG_EXACT_DUPLICATE", "STRONG_MERGED_COVERAGE"}
            for relation in evidence.pull_relations
        ):
            new_status = "COVERED"
            reason = "STRONG_PR_APPEARED"
        elif item.get("latestPolicyDigest") and evidence.policy.get("digest") != item.get(
            "latestPolicyDigest"
        ):
            new_status = "POLICY_CHANGED"
            reason = "POLICY_REVALIDATION_REQUIRED"
        elif evidence.maintainer_approvals:
            new_status = "RESCAN_REQUIRED"
            reason = "MAINTAINER_GREEN_LIGHT"
        item["status"] = new_status
        item["lastCheckedAt"] = iso_z(current)
        item["latestEvidenceDigest"] = evidence.digest
        item["latestPolicyDigest"] = evidence.policy.get("digest")
        if new_status != previous_status or new_status in {
            "RESCAN_REQUIRED",
            "POLICY_CHANGED",
        }:
            update = {
                **item,
                "previousStatus": previous_status,
                "reasonCode": reason,
                "evidence": evidence.as_dict(),
            }
        else:
            update = None
        queued_state_changed = previous_status == "QUEUED" and new_status != "QUEUED"
        pending = (
            {
                "issueTitle": item["issueTitle"],
                "issueUrl": item["issueUrl"],
                "issueUpdated": evidence.issue.get("updated_at") or "",
                "reasonCode": reason,
            }
            if new_status in {"RESCAN_REQUIRED", "POLICY_CHANGED"} or queued_state_changed
            else None
        )
        return item, update, pending

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        inspected = list(executor.map(inspect, selected))
    for item, update, pending in inspected:
        if update:
            updates.append(update)
        if pending:
            pending_rechecks[item["key"]] = pending
    watchlist["generatedAt"] = iso_z(current)
    watchlist["digest"] = sha256_json(
        {key: value for key, value in watchlist.items() if key != "digest"}
    )
    result = {
        "scan_ok": True,
        "run_id": f"watch-{int(current.timestamp())}",
        "candidate_details": [
            {
                "key": item["key"],
                "repo": item["repo"],
                "num": item["issueNumber"],
                "url": item["issueUrl"],
                "title": item["issueTitle"],
                "category": "WAIT_MAINTAINER",
                "score": None,
                "auto_spawn": False,
                "why": item["reasonCode"],
                "test_path": "重新运行完整扫描和贡献规则检查",
                "evidence_digest": item["latestEvidenceDigest"],
            }
            for item in updates
        ],
        "updates": updates,
        "pending_rechecks": pending_rechecks,
        "workers": worker_count,
        "duration_seconds": round(monotonic() - started, 3),
    }
    return watchlist, result
