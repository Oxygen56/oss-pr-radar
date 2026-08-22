"""Deterministic managed-user projection for the War Room.

The projection is deliberately a pure read of the managed Ledger.  Feishu,
Codex, and any local dashboard must consume this artifact rather than making
their own lifecycle decisions.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .managed_lifecycle import MANAGED_SCHEMA_VERSION, verify_task_creation_authorization
from .util import atomic_write_json, sha256_json

PROJECTION_SCHEMA = "oss-pr-radar.war-room-projection.v1"
VIEW_SCHEMA = "oss-pr-radar.war-room-views.v1"
PROJECTION_BUCKETS = (
    "DECISION_REQUIRED",
    "SYSTEM_PROCESSING",
    "WAITING_EXTERNAL",
    "PORTFOLIO_READY",
)
EVIDENCE_LEVELS = ("待补充", "有记录", "已核实", "外部记录")
ACTION_KINDS = ("NONE", "MANAGED_TASK", "USER_DECISION")
NOTIFICATION_STATUSES = ("NONE", "PENDING", "SENT", "FAILED", "RECONCILE_REQUIRED")


class ProjectionError(ValueError):
    """Raised when a War Room artifact violates its public contract."""


def _json(value: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _plain_title(*values: Any) -> str:
    for value in values:
        candidate = _text(value)
        if any("\u4e00" <= char <= "\u9fff" for char in candidate):
            return candidate
    return ""


def _gate_passed(
    connection: sqlite3.Connection,
    opportunity: sqlite3.Row | None,
    task: sqlite3.Row | None,
) -> bool:
    """Authorize only a current-key lifecycle event bound to the task and issue."""

    if opportunity is None or task is None:
        return False
    repo = f"{opportunity['owner']}/{opportunity['repo']}"
    rows = connection.execute(
        """SELECT payload_json FROM managed_lifecycle_events
           WHERE event_type='TASK_CREATION_AUTHORIZED'
             AND task_id=? AND opportunity_key=?
           ORDER BY observed_at DESC, event_id DESC""",
        (task["task_id"], opportunity["opportunity_key"]),
    ).fetchall()
    for row in rows:
        payload = _json(row["payload_json"])
        authorization = payload.get("authorization")
        if verify_task_creation_authorization(
            authorization,
            task_id=str(task["task_id"]),
            opportunity_key=str(opportunity["opportunity_key"]),
            repo=repo,
            issue_url=str(opportunity["issue_url"]),
        ):
            return True
    return False


def _latest_rows(
    connection: sqlite3.Connection,
) -> tuple[dict[str, sqlite3.Row], dict[tuple[str, str], sqlite3.Row]]:
    tasks = {
        row["task_id"]: row
        for row in connection.execute("SELECT * FROM managed_tasks ORDER BY task_id").fetchall()
    }
    results = {
        row["task_id"]: row
        for row in connection.execute(
            """SELECT * FROM (
                 SELECT r.*, ROW_NUMBER() OVER (
                   PARTITION BY r.task_id ORDER BY r.observed_at DESC, r.result_key DESC
                 ) AS rn
                 FROM managed_results r
               ) WHERE rn=1"""
        ).fetchall()
    }
    ci = {
        (row["pr_key"], row["head_sha"]): row
        for row in connection.execute(
            """SELECT * FROM (
                 SELECT c.*, ROW_NUMBER() OVER (
                   PARTITION BY c.pr_key, c.head_sha
                   ORDER BY c.observed_at DESC, c.ci_key DESC
                 ) AS rn
                 FROM managed_ci_runs c
               ) WHERE rn=1"""
        ).fetchall()
    }
    return {task_id: (tasks[task_id], results.get(task_id)) for task_id in tasks}, ci


def _display_fields(
    *,
    bucket: str,
    opportunity: sqlite3.Row | None,
    task: sqlite3.Row | None,
    result: sqlite3.Row | None,
    ci: sqlite3.Row | None,
    existing_pr: bool = False,
) -> dict[str, str]:
    metadata = _json(opportunity["metadata_json"]) if opportunity is not None else {}
    provenance = _json(opportunity["provenance_json"]) if opportunity is not None else {}
    title = _plain_title(metadata.get("title"), provenance.get("title"))
    if not title and opportunity is not None:
        title = f"处理 {opportunity['owner']}/{opportunity['repo']} 的第 {opportunity['issue_number']} 号问题"
    if not title:
        title = "跟进已有的开源贡献"
    if bucket == "DECISION_REQUIRED":
        reason = "需要你确认下一步，当前记录不足以安全继续。"
        next_action = "请确认是否继续，以及需要补充的要求。"
    elif bucket == "WAITING_EXTERNAL":
        reason = "正在等待外部检查或维护者反馈。"
        next_action = "等待外部结果；有新反馈后再继续。"
    elif bucket == "PORTFOLIO_READY":
        reason = "已有托管任务、验证结果和外部检查记录。"
        next_action = "请查看交付物并决定是否继续后续处理。"
    else:
        reason = "托管任务正在处理，暂时没有需要你决定的事项。"
        next_action = "等待任务产生下一条可核实记录。"
    if existing_pr:
        reason = "这是已有的开放贡献记录，保留原始来源并等待外部反馈。"
        next_action = "等待维护者反馈；不会自动关闭或删除该记录。"
    if result is not None and result["worker_state"] == "needs_human":
        reason = "任务已暂停，等待你确认处理方向。"
        next_action = "请确认处理方向后再继续。"
    if bucket == "PORTFOLIO_READY" and ci is None:
        reason = "任务已有交付记录，但外部检查结果尚未齐全。"
        next_action = "等待外部检查完成。"
    if task is None:
        evidence = "外部记录" if existing_pr else "待补充"
    elif bucket == "PORTFOLIO_READY":
        evidence = "已核实"
    else:
        evidence = "有记录"
    return {
        "title": title,
        "reason": reason,
        "evidenceLevel": evidence,
        "nextAction": next_action,
    }


def _bucket(
    *,
    state: str,
    task: sqlite3.Row | None,
    result: sqlite3.Row | None,
    ci: sqlite3.Row | None,
    pr: sqlite3.Row | None,
    gate_passed: bool,
) -> str:
    worker_state = str(result["worker_state"] if result else "")
    ci_status = str(ci["status"] if ci else "")
    if state == "DECISION_REQUIRED" or worker_state == "needs_human":
        return "DECISION_REQUIRED"
    if (
        gate_passed
        and state == "PORTFOLIO_READY"
        and result is not None
        and result["commit_sha"]
        and _json(result["validation_json"]).get("passed") is True
        and ci_status == "PASSED"
    ):
        return "PORTFOLIO_READY"
    if (
        state == "WAITING_EXTERNAL"
        or ci_status in {"QUEUED", "RUNNING"}
        or (pr is not None and pr["state"] == "OPEN" and not pr["maintainer_response"])
    ):
        return "WAITING_EXTERNAL"
    return "SYSTEM_PROCESSING"


def _item(
    *,
    connection: sqlite3.Connection,
    opportunity: sqlite3.Row | None,
    task: sqlite3.Row | None,
    result: sqlite3.Row | None,
    ci: sqlite3.Row | None,
    pr: sqlite3.Row | None,
) -> dict[str, Any]:
    gate_passed = _gate_passed(connection, opportunity, task)
    state = str(task["state"] if task is not None else opportunity["state"] if opportunity else "")
    bucket = _bucket(state=state, task=task, result=result, ci=ci, pr=pr, gate_passed=gate_passed)
    display = _display_fields(
        bucket=bucket,
        opportunity=opportunity,
        task=task,
        result=result,
        ci=ci,
        existing_pr=bool(pr is not None and pr["origin_kind"] == "EXISTING_OPEN_PR"),
    )
    key = str(opportunity["opportunity_key"] if opportunity else pr["pr_key"])
    actionable = bool(task is not None and gate_passed)
    metadata = _json(opportunity["metadata_json"] if opportunity else "{}")
    notification_digest = str(metadata.get("notificationDigest") or "")
    notification_status = str(metadata.get("notificationStatus") or "PENDING")
    review_required = bool(
        task is None
        and opportunity is not None
        and opportunity["source"] == "scanner"
        and state == "DECISION_REQUIRED"
        and metadata.get("reviewRequired") is True
        and metadata.get("gateDecision") == "HUMAN_REVIEW"
        and re.fullmatch(r"[0-9a-f]{64}", notification_digest)
        and notification_status in NOTIFICATION_STATUSES[1:]
    )
    action_kind = "MANAGED_TASK" if actionable else "USER_DECISION" if review_required else "NONE"
    if not review_required:
        notification_digest = ""
        notification_status = "NONE"
    notified = bool(review_required and notification_status == "SENT")
    return {
        "candidateKey": key,
        "bucket": bucket,
        **display,
        "actionable": actionable,
        "reviewRequired": review_required,
        "actionKind": action_kind,
        "notificationDigest": notification_digest or None,
        "notificationStatus": notification_status,
        "notified": notified,
        "taskId": task["task_id"] if task is not None else None,
        "creationGatePassed": gate_passed,
        "originKind": pr["origin_kind"] if pr is not None else "MANAGED_CANDIDATE",
        "originPrUrl": pr["origin_pr_url"] if pr is not None else None,
    }


def _observed_at(connection: sqlite3.Connection) -> str:
    values: list[str] = []
    for table, column in (
        ("managed_opportunities", "observed_at"),
        ("managed_tasks", "observed_at"),
        ("managed_results", "observed_at"),
        ("managed_prs", "observed_at"),
        ("managed_ci_runs", "observed_at"),
    ):
        values.extend(
            str(row[0])
            for row in connection.execute(f"SELECT {column} FROM {table}").fetchall()
            if row[0]
        )
    return max(values) if values else "1970-01-01T00:00:00Z"


def build_projection(path: Path, *, source_commit: str | None = None) -> dict[str, Any]:
    """Build the single versioned artifact consumed by every War Room view."""

    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        opportunities = {
            row["opportunity_key"]: row
            for row in connection.execute(
                "SELECT * FROM managed_opportunities ORDER BY opportunity_key"
            ).fetchall()
        }
        task_pairs, ci_rows = _latest_rows(connection)
        prs = {
            row["pr_key"]: row
            for row in connection.execute("SELECT * FROM managed_prs ORDER BY pr_key").fetchall()
        }
        by_opportunity: dict[str, list[sqlite3.Row]] = {}
        for task, _result in task_pairs.values():
            by_opportunity.setdefault(str(task["opportunity_key"]), []).append(task)
        items: list[dict[str, Any]] = []
        for key, opportunity in opportunities.items():
            tasks = sorted(
                by_opportunity.get(key, []),
                key=lambda row: (str(row["observed_at"]), str(row["task_id"])),
            )
            task = tasks[-1] if tasks else None
            result = task_pairs.get(task["task_id"], (None, None))[1] if task else None
            pr_key = str(result["pr_key"]) if result is not None and result["pr_key"] else None
            pr = prs.get(pr_key) if pr_key else None
            ci = ci_rows.get((pr_key, str(result["head_sha"]))) if result and pr_key else None
            items.append(
                _item(
                    connection=connection,
                    opportunity=opportunity,
                    task=task,
                    result=result,
                    ci=ci,
                    pr=pr,
                )
            )
        for pr_key, pr in prs.items():
            linked = connection.execute(
                "SELECT 1 FROM managed_results WHERE pr_key=? LIMIT 1", (pr_key,)
            ).fetchone()
            if linked is not None:
                continue
            items.append(
                _item(
                    connection=connection,
                    opportunity=None,
                    task=None,
                    result=None,
                    ci=None,
                    pr=pr,
                )
            )
        items.sort(key=lambda item: str(item["candidateKey"]))
        buckets = {bucket: [] for bucket in PROJECTION_BUCKETS}
        for item in items:
            buckets[str(item["bucket"])].append(item)
        artifact: dict[str, Any] = {
            "schema": PROJECTION_SCHEMA,
            "schemaVersion": 1,
            "artifactType": "managed_user_projection",
            "source": {
                "ledgerSchemaVersion": MANAGED_SCHEMA_VERSION,
                "sourceCommit": source_commit or "",
            },
            "observedAt": _observed_at(connection),
            "buckets": buckets,
            "items": items,
        }
        artifact["artifactDigest"] = sha256_json(artifact)
        validate_projection(artifact)
        return artifact
    finally:
        connection.close()


def validate_projection(value: dict[str, Any]) -> None:
    if not isinstance(value, dict) or value.get("schema") != PROJECTION_SCHEMA:
        raise ProjectionError("invalid War Room projection schema")
    if value.get("schemaVersion") != 1 or value.get("artifactType") != "managed_user_projection":
        raise ProjectionError("invalid War Room projection version")
    if set(value.get("buckets") or {}) != set(PROJECTION_BUCKETS):
        raise ProjectionError("projection buckets are not exhaustive")
    items = value.get("items")
    if not isinstance(items, list) or len({item.get("candidateKey") for item in items}) != len(
        items
    ):
        raise ProjectionError("projection candidates are not unique")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or item.get("bucket") not in PROJECTION_BUCKETS:
            raise ProjectionError("candidate bucket is invalid")
        if (
            not isinstance(item.get("actionable"), bool)
            or not isinstance(item.get("reviewRequired"), bool)
            or not isinstance(item.get("notified"), bool)
        ):
            raise ProjectionError("candidate action flags are invalid")
        if (
            item.get("actionKind") not in ACTION_KINDS
            or item.get("notificationStatus") not in NOTIFICATION_STATUSES
        ):
            raise ProjectionError("candidate notification state is invalid")
        digest = item.get("notificationDigest")
        if digest is not None and not (
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ProjectionError("candidate notification digest is invalid")
        if item["candidateKey"] in seen:
            raise ProjectionError("candidate appears more than once")
        seen.add(item["candidateKey"])
        if item.get("evidenceLevel") not in EVIDENCE_LEVELS:
            raise ProjectionError("candidate evidence level is invalid")
        if not all(
            isinstance(item.get(key), str) and item[key].strip()
            for key in ("title", "reason", "nextAction")
        ):
            raise ProjectionError("candidate display fields must be plain text")
        if not any("\u4e00" <= char <= "\u9fff" for char in item["title"]):
            raise ProjectionError("candidate title must be Simplified Chinese")
        if item["actionKind"] == "MANAGED_TASK":
            if (
                item.get("actionable") is not True
                or item.get("reviewRequired") is not False
                or item.get("creationGatePassed") is not True
                or not item.get("taskId")
                or item.get("notificationDigest") is not None
                or item.get("notificationStatus") != "NONE"
                or item.get("notified") is not False
            ):
                raise ProjectionError("managed task action binding is invalid")
        elif item["actionKind"] == "USER_DECISION":
            if (
                item.get("actionable") is not False
                or item.get("reviewRequired") is not True
                or item.get("creationGatePassed") is not False
                or item.get("taskId") is not None
                or item.get("bucket") != "DECISION_REQUIRED"
                or item.get("notificationDigest") is None
                or item.get("notificationStatus") == "NONE"
                or item.get("notified") != (item.get("notificationStatus") == "SENT")
            ):
                raise ProjectionError("user decision action binding is invalid")
        elif any(
            (
                item.get("actionable") is not False,
                item.get("reviewRequired") is not False,
                item.get("creationGatePassed") is not False,
                item.get("notified") is not False,
                item.get("notificationDigest") is not None,
                item.get("notificationStatus") != "NONE",
            )
        ):
            raise ProjectionError("non-actionable candidate has notification authority")
    flattened: list[dict[str, Any]] = []
    for bucket in PROJECTION_BUCKETS:
        bucket_items = value["buckets"].get(bucket)
        if not isinstance(bucket_items, list):
            raise ProjectionError("bucket contents are not lists")
        if any(item.get("bucket") != bucket for item in bucket_items):
            raise ProjectionError("candidate appears in the wrong bucket")
        flattened.extend(bucket_items)
    if len(flattened) != len(items):
        raise ProjectionError("candidate appears in more than one bucket")
    # The item view is globally sorted, while the bucket view is intentionally
    # grouped by lifecycle bucket. Compare identities after normalizing order.
    if [
        item["candidateKey"] for item in sorted(flattened, key=lambda item: item["candidateKey"])
    ] != [item["candidateKey"] for item in sorted(items, key=lambda item: item["candidateKey"])]:
        raise ProjectionError("bucket view differs from item view")
    digestable = {key: item for key, item in value.items() if key != "artifactDigest"}
    if value.get("artifactDigest") != sha256_json(digestable):
        raise ProjectionError("projection digest mismatch")


def export_projection(
    path: Path, output: Path | None = None, *, source_commit: str | None = None
) -> dict[str, Any]:
    artifact = build_projection(path, source_commit=source_commit)
    if output is not None:
        atomic_write_json(output, artifact)
    return artifact


def build_views(artifact: dict[str, Any]) -> dict[str, Any]:
    """Render Feishu and Codex views without re-evaluating lifecycle state."""

    validate_projection(artifact)
    actionable = [
        item for item in artifact["items"] if item["actionable"] or item["reviewRequired"]
    ]
    views: dict[str, Any] = {
        "schema": VIEW_SCHEMA,
        "sourceArtifactDigest": artifact["artifactDigest"],
        "feishu": {"sourceArtifactDigest": artifact["artifactDigest"], "items": actionable},
        "codex": {"sourceArtifactDigest": artifact["artifactDigest"], "items": actionable},
    }
    validate_views(views)
    return views


def validate_views(value: dict[str, Any]) -> None:
    if value.get("schema") != VIEW_SCHEMA:
        raise ProjectionError("invalid War Room view schema")
    digest = value.get("sourceArtifactDigest")
    feishu = value.get("feishu") or {}
    codex = value.get("codex") or {}
    if feishu.get("sourceArtifactDigest") != digest or codex.get("sourceArtifactDigest") != digest:
        raise ProjectionError("Feishu and Codex views must share one artifact")
    left = [item.get("candidateKey") for item in feishu.get("items") or []]
    right = [item.get("candidateKey") for item in codex.get("items") or []]
    if left != right:
        raise ProjectionError("Feishu and Codex actionable views differ")
    if any(
        item.get("actionable") is not True and item.get("reviewRequired") is not True
        for item in feishu.get("items") or []
    ):
        raise ProjectionError("unauthorized item entered a channel view")


def write_views(artifact: dict[str, Any], output: Path) -> dict[str, Any]:
    views = build_views(artifact)
    atomic_write_json(output, views)
    return views
