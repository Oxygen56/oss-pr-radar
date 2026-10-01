"""Controllable quality metrics for the opportunity-to-submit-ready loop."""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .util import iso_z

QUALITY_FIELDS = (
    "fresh_state_verified",
    "ownership_verified",
    "policy_verified",
    "reproduction_verified",
    "root_cause_verified",
    "minimal_fix_verified",
    "regression_test_verified",
    "relevant_tests_green",
    "independent_review_passed",
)

# These are failures that fresh discovery or the live pre-dispatch gate should
# have caught before a user-visible task consumed the single implementation slot.
# Older controller versions used lowercase PREEXISTING_* values while current
# versions persist machine-readable uppercase authorization reasons.
FILTER_MISS_CLASSES = frozenset(
    {
        "ACTIVE_OR_CONDITIONAL_CLAIM",
        "ALREADY_FIXED",
        "DESIGN_APPROVAL_REQUIRED",
        "DESIGN_UNAPPROVED",
        "DUPLICATE",
        "EXISTING_PR_REQUIRES_COMPETITION_REVIEW",
        "ISSUE_ASSIGNED",
        "ISSUE_NOT_OPEN",
        "MAINTAINER_APPROVAL_REQUIRED",
        "OWNERSHIP",
        "PREEXISTING_CLAIM",
        "PREEXISTING_DUPLICATE",
        "PREEXISTING_POLICY_BLOCK",
        "SEMANTIC_PR_OVERLAP_REQUIRES_REVIEW",
        "STRONG_EXISTING_PR",
        "UNSOLICITED_PRS_BLOCKED",
    }
)


def canonical_failure_class(value: Any) -> str:
    return str(value or "").strip().replace("-", "_").upper()


@dataclass(frozen=True)
class SubmitReadyAssessment:
    ready: bool
    missing: tuple[str, ...]
    evidence: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


VALIDATION_DEPENDENCY_FAILURE_MARKERS = (
    "offline",
    "not cached",
    "uncached dependencies",
    "uncached packages",
    "incomplete cached environment",
    "incomplete local dependency tree",
    "lacks locked dependency",
    "locked but absent",
    "module lookup disabled",
    "goproxy=off",
    "node_modules",
    "vitest was unavailable",
    "prettier was unavailable",
    "eslint was unavailable",
    "next.js was unavailable",
    "pytest is not installed",
    "could not find pytest",
    "no pytest executable",
    "no pre-commit executable",
    "no module named pytest",
    "no module named",
    "modulenotfounderror",
    "is not installed",
    "missing numpy",
    "missing torch",
    "executable is unavailable",
    "not on path",
    "absent from path",
    "was not present",
    "no worktree-local prefetched executable",
    "required_gate_unavailable",
)


def is_validation_dependency_failure(item: dict[str, Any]) -> bool:
    text = (
        f"{item.get('command', '')}\n{item.get('summary', '')}\n{item.get('outcome', '')}\n{item.get('result', '')}"
    ).casefold()
    if any(marker in text for marker in VALIDATION_DEPENDENCY_FAILURE_MARKERS):
        return True
    return "locked" in text and any(
        marker in text for marker in (" is absent", " are absent", " missing", "differs from")
    )


def _is_before_fix_check(item: dict[str, Any], text: str) -> bool:
    phase = str(item.get("phase") or "").casefold().replace("-", "_").replace(" ", "_")
    return phase in {
        "before_fix",
        "pre_fix",
        "before_patch",
        "pre_patch",
        "baseline",
        "reproduction",
    } or bool(re.search(r"\b(?:before|pre)[ _-](?:the[ _-])?(?:fix|patch)\b", text, re.IGNORECASE))


def unresolved_current_test_failures(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Find explicit current check failures, retaining legitimate before-fix evidence.

    Historical result files may omit tests or describe them without exit codes.
    This only contradicts a green claim with an explicit failed/unavailable run;
    a later successful run of the same command and working directory resolves it.
    """

    tests = result.get("tests")
    if not isinstance(tests, list):
        return []
    pending: dict[tuple[str, str], dict[str, Any]] = {}
    for index, item in enumerate(tests):
        if not isinstance(item, dict):
            continue
        text = "\n".join(
            str(item.get(field) or "") for field in ("command", "summary", "outcome", "result")
        )
        if _is_before_fix_check(item, text):
            continue
        command = str(item.get("command") or "").strip()
        cwd = str(item.get("workingDirectory") or item.get("cwd") or "").strip()
        key = (command or f"<unnamed-check-{index}>", cwd)
        code = item.get("exitCode")
        if code == 0:
            pending.pop(key, None)
        elif code is not None or is_validation_dependency_failure(item):
            pending[key] = item
    return list(pending.values())


def environment_stub_checks_without_real_validation(result: dict[str, Any]) -> bool:
    """Reject SDK import stand-ins as the only behavioral validation evidence."""

    tests = result.get("tests")
    if not isinstance(tests, list):
        return False
    environment_stubs = False
    real_validation = False
    for item in tests:
        if not isinstance(item, dict):
            continue
        text = "\n".join(
            str(item.get(field) or "") for field in ("command", "summary", "outcome", "result")
        )
        command = str(item.get("command") or "")
        project_test = bool(
            re.search(r"(?:^|\s)(?:\S*/)?pytest\b|\s-m\s+(?:pytest|unittest)\b", command)
        )
        if (
            re.search(
                r"\bin[ -]process\s+stubs?\b.*\bmissing\b.*\bsdk\b.*\bimports?\b",
                text,
                re.IGNORECASE | re.DOTALL,
            )
            and not project_test
        ):
            environment_stubs = True
        elif item.get("exitCode") == 0 and not _is_before_fix_check(item, text):
            if not re.search(
                r"\b(?:ast\.parse|py_compile|compileall|ruff|mypy|pyright|black|isort|"
                r"eslint|prettier|lint|format|typecheck)\b|"
                r"\bgit\s+diff\b.*--check\b|--version\b|"
                r"\bpython(?:\d+(?:\.\d+)*)?\s+-V\b|"
                r"\b(?:sys\.version(?:_info)?|platform\.python_version|ensurepip)\b|"
                r"\b(?:pip\d*|uv(?:\s+pip)?|poetry|npm|pnpm|yarn)\s+(?:install|sync|check)\b|"
                r"(?:^|\s)(?:\S+\s+-m\s+venv|virtualenv)\b",
                command,
                re.IGNORECASE,
            ):
                real_validation = True
    return environment_stubs and not real_validation


def assess_submit_ready(
    evidence: dict[str, Any], *, task_result: dict[str, Any] | None = None
) -> SubmitReadyAssessment:
    effective = dict(evidence)
    if task_result is not None and (
        unresolved_current_test_failures(task_result)
        or environment_stub_checks_without_real_validation(task_result)
    ):
        effective["relevant_tests_green"] = False
    missing = tuple(field for field in QUALITY_FIELDS if effective.get(field) is not True)
    return SubmitReadyAssessment(not missing, missing, effective)


def rolling_quality(path: Path, *, days: int = 30) -> dict[str, Any]:
    cutoff = iso_z(datetime.now(UTC) - timedelta(days=max(1, days)))
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """SELECT selected_at,submit_ready_at,failure_class,quality_json
               FROM outcomes WHERE selected_at>=?""",
            (cutoff,),
        ).fetchall()
        hard_escapes = connection.execute(
            """SELECT COUNT(*) FROM events
               WHERE created_at>=? AND event_type='HARD_GATE_ESCAPE'""",
            (cutoff,),
        ).fetchone()[0]
    finally:
        connection.close()
    selected = len(rows)
    submit_ready = sum(bool(row["submit_ready_at"]) for row in rows)
    failure_counts = Counter(
        canonical_failure_class(row["failure_class"])
        for row in rows
        if canonical_failure_class(row["failure_class"])
    )
    filter_misses = sum(failure_counts[name] for name in FILTER_MISS_CLASSES)
    return {
        "windowDays": days,
        "selected": selected,
        "submitReady": submit_ready,
        "submitReadyRate": round(submit_ready / selected, 4) if selected else None,
        "filterMisses": filter_misses,
        "filterMissRate": round(filter_misses / selected, 4) if selected else None,
        "hardGateEscapes": int(hard_escapes),
        "failureClassCounts": dict(sorted(failure_counts.items())),
        "qualityEvidence": [json.loads(row["quality_json"]) for row in rows],
    }
